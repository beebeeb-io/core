//! Format detection by magic bytes (spec §5.1, A2). The extension never
//! takes part: `detect` has no name parameter.

/// The archive formats Beebeeb opens.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ArchiveFormat {
    Zip,
    Tar,
    /// A tar inside gzip (`.tgz`, `.tar.gz`).
    TarGzip,
    /// One gzip-compressed file (`.gz`).
    Gzip,
}

impl ArchiveFormat {
    /// The binding string: `"zip" | "tar" | "tgz" | "gz"`.
    pub const fn as_str(self) -> &'static str {
        match self {
            ArchiveFormat::Zip => "zip",
            ArchiveFormat::Tar => "tar",
            ArchiveFormat::TarGzip => "tgz",
            ArchiveFormat::Gzip => "gz",
        }
    }
}

/// Archive formats recognised and refused by name (R2: 7z and rar are out).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ForeignFormat {
    Rar,
    SevenZip,
    Xz,
    Zstd,
    Bzip2,
}

impl ForeignFormat {
    /// The name the refusal shows (`refuse_foreign`'s `{format}`).
    pub const fn display_name(self) -> &'static str {
        match self {
            ForeignFormat::Rar => "RAR",
            ForeignFormat::SevenZip => "7z",
            ForeignFormat::Xz => "xz",
            ForeignFormat::Zstd => "Zstandard",
            ForeignFormat::Bzip2 => "bzip2",
        }
    }

    /// The binding string.
    pub const fn as_str(self) -> &'static str {
        match self {
            ForeignFormat::Rar => "rar",
            ForeignFormat::SevenZip => "7z",
            ForeignFormat::Xz => "xz",
            ForeignFormat::Zstd => "zstd",
            ForeignFormat::Bzip2 => "bzip2",
        }
    }
}

/// What the first bytes (and, for programs, the tail) say a file is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Detection {
    Archive(ArchiveFormat),
    /// A gzip stream: inflate its first 512 bytes and ask
    /// [`detect_gzip_inner`] whether it holds a tar.
    GzipNeedsInflatedHead,
    Foreign(ForeignFormat),
    /// An `MZ` program with a zip end record at its tail.
    SelfExtracting,
    NotAnArchive,
}

const ZIP_LOCAL: [u8; 4] = [0x50, 0x4B, 0x03, 0x04];
const ZIP_END: [u8; 4] = [0x50, 0x4B, 0x05, 0x06];
/// The first part of a spanned zip starts with the data-descriptor
/// signature; the zip reader refuses it as `Spanned`.
const ZIP_SPANNED: [u8; 4] = [0x50, 0x4B, 0x07, 0x08];
const GZIP: [u8; 3] = [0x1F, 0x8B, 0x08];

const FOREIGN: [(&[u8], ForeignFormat); 5] = [
    (b"Rar!\x1A\x07", ForeignFormat::Rar),
    (b"7z\xBC\xAF\x27\x1C", ForeignFormat::SevenZip),
    (b"\xFD7zXZ\x00", ForeignFormat::Xz),
    (b"\x28\xB5\x2F\xFD", ForeignFormat::Zstd),
    (b"BZh", ForeignFormat::Bzip2),
];

/// Detect a file's format from its first bytes (`head`, up to 512) and its
/// last bytes (`tail`, up to [`super::limits::ZIP_TAIL_WINDOW`]). `len` is
/// the whole file's length.
///
/// A zip is recognised by its first signature; whether its end record and
/// central directory agree is the zip reader's check, so a zip whose end
/// is missing is refused as damaged or truncated, never "not an archive".
pub fn detect(head: &[u8], tail: &[u8], len: u64) -> Detection {
    if head.starts_with(&ZIP_LOCAL) || head.starts_with(&ZIP_END) || head.starts_with(&ZIP_SPANNED) {
        return Detection::Archive(ArchiveFormat::Zip);
    }
    if head.starts_with(&GZIP) {
        return Detection::GzipNeedsInflatedHead;
    }
    if is_tar_header(head) {
        return Detection::Archive(ArchiveFormat::Tar);
    }
    if let Some((_, format)) = FOREIGN.iter().find(|(magic, _)| head.starts_with(magic)) {
        return Detection::Foreign(*format);
    }
    if head.starts_with(b"MZ") && has_zip_end_record(tail, len) {
        return Detection::SelfExtracting;
    }
    Detection::NotAnArchive
}

/// A gzip stream holds a tar when its first 512 inflated bytes are a tar
/// header with a valid checksum; otherwise it is one compressed file.
pub fn detect_gzip_inner(inflated_head: &[u8]) -> ArchiveFormat {
    if is_tar_header(inflated_head) {
        ArchiveFormat::TarGzip
    } else {
        ArchiveFormat::Gzip
    }
}

/// A 512-byte tar header whose checksum field matches its bytes (the field
/// itself counted as spaces), with a name. `ustar` at 257 is not required:
/// v7 headers are recognised by the checksum alone.
pub(crate) fn is_tar_header(block: &[u8]) -> bool {
    let Some(block) = block.get(..512) else {
        return false;
    };
    if block[0] == 0 {
        return false;
    }
    let Some(stored) = parse_octal(&block[148..156]) else {
        return false;
    };
    let (unsigned, signed) = header_sums(block);
    stored == unsigned || i64::try_from(stored).is_ok_and(|s| s == signed)
}

/// The unsigned and signed byte sums of a header, its checksum field
/// counted as eight spaces (old tars summed signed chars).
pub(crate) fn header_sums(block: &[u8]) -> (u64, i64) {
    let mut unsigned = 0u64;
    let mut signed = 0i64;
    for (i, &b) in block.iter().take(512).enumerate() {
        let b = if (148..156).contains(&i) { b' ' } else { b };
        unsigned += u64::from(b);
        signed += i64::from(b as i8);
    }
    (unsigned, signed)
}

/// An octal field: optional leading spaces, digits, then NUL or space.
/// Empty or non-octal is `None`.
pub(crate) fn parse_octal(field: &[u8]) -> Option<u64> {
    let text = field
        .iter()
        .skip_while(|&&b| b == b' ')
        .take_while(|&&b| b != 0 && b != b' ');
    let mut value: u64 = 0;
    let mut digits = 0;
    for &b in text {
        if !(b'0'..=b'7').contains(&b) {
            return None;
        }
        value = value.checked_mul(8)?.checked_add(u64::from(b - b'0'))?;
        digits += 1;
    }
    (digits > 0).then_some(value)
}

/// Whether the tail holds a zip end record whose comment runs exactly to
/// the end of the file.
fn has_zip_end_record(tail: &[u8], len: u64) -> bool {
    let tail_start = len.saturating_sub(tail.len() as u64);
    (0..tail.len().saturating_sub(21)).rev().any(|i| {
        tail[i..].starts_with(&ZIP_END) && {
            let comment = u64::from(u16::from_le_bytes([tail[i + 20], tail[i + 21]]));
            tail_start + i as u64 + 22 + comment == len
        }
    })
}
