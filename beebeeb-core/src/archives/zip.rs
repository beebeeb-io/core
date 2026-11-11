//! Zip, read sans-I/O from its end (spec §5.1, A4).
//!
//! Listing reads the tail (the end record and the ZIP64 records), then the
//! central directory, and nothing else. The central directory is
//! authoritative: a local header that disagrees with it makes that entry
//! corrupt, and entries whose bytes overlap each other or the central
//! directory refuse the archive. Entry data is decoded push-style (stored,
//! deflate; ZipCrypto and WinZip AES), so a reader can stop for bytes at
//! any point and go on exactly where it was.

use std::collections::BTreeSet;

use zeroize::Zeroizing;

use super::inflate::Inflater;
use super::limits::{
    BOMB_RATIO, BOMB_RATIO_FLOOR_BYTES, MAX_CENTRAL_DIRECTORY_BYTES, MAX_ENTRIES, PIECE_BYTES, PULL_AHEAD_BYTES,
    ZIP_TAIL_WINDOW,
};
use super::listing::{ListingBuilder, Locator};
use super::model::{ArchiveEntry, ArchiveRefusal, ArchiveTime, EntryCipher, EntryKind, SkipReason};
use super::names::{RawName, decode_name, display_name, entry_path};
use super::platform::ArchivePlatform;
use super::session::PieceStep;
use super::source::{ByteRange, ByteSource, Miss, read_exact_at};
use super::tar::Halt;
use super::winzip_aes::{self, AUTH_CODE_LEN, AesDecryptor};
use super::zipcrypto::{self, ZipCryptoKeys};

const SIG_LOCAL: [u8; 4] = [0x50, 0x4B, 0x03, 0x04];
const SIG_CENTRAL: [u8; 4] = [0x50, 0x4B, 0x01, 0x02];
const SIG_END: [u8; 4] = [0x50, 0x4B, 0x05, 0x06];
const SIG_ZIP64_END: [u8; 4] = [0x50, 0x4B, 0x06, 0x06];
const SIG_ZIP64_LOCATOR: [u8; 4] = [0x50, 0x4B, 0x06, 0x07];

const FLAG_ENCRYPTED: u16 = 1 << 0;
const FLAG_DATA_DESCRIPTOR: u16 = 1 << 3;
const FLAG_STRONG_ENCRYPTION: u16 = 1 << 6;
const FLAG_UTF8: u16 = 1 << 11;
const FLAG_CD_ENCRYPTED: u16 = 1 << 13;

/// A ZipCrypto entry proves a password only when its CRC-32 covers at
/// least this much data: CRC-32 is one-to-one on four bytes, so a wrong
/// key's garbage then matches by chance about once in 2^32 entries. With
/// less data the CRC can only be matched by a few values, and with none
/// it matches anything; the one check byte (1 in 256) is all that is left.
const ZIPCRYPTO_PROOF_BYTES: u64 = 4;

const METHOD_STORED: u16 = 0;
const METHOD_DEFLATE: u16 = 8;
const METHOD_AES: u16 = 99;

fn u16_at(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

fn u64_at(b: &[u8], at: usize) -> u64 {
    let mut le = [0u8; 8];
    le.copy_from_slice(&b[at..at + 8]);
    u64::from_le_bytes(le)
}

fn damaged() -> Halt {
    Halt::Refused(ArchiveRefusal::Damaged)
}

/// Where a zip entry's bytes are and how they are encoded, from its
/// central directory record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ZipLocator {
    pub header_offset: u64,
    /// The next entry's local header, or the central directory: this
    /// entry's data may not reach it.
    pub limit: u64,
    pub raw_name: Vec<u8>,
    pub method: u16,
    /// The compression under the encryption (AES records it separately).
    pub data_method: u16,
    pub flags: u16,
    pub crc32: u32,
    pub compressed_size: u64,
    pub uncompressed_size: u64,
    pub cipher: EntryCipher,
    pub dos_time: u16,
}

// ------------------------------------------------------------- listing

struct EndRecord {
    entries: u64,
    cd_size: u64,
    cd_offset: u64,
    /// Where the central directory must end: the ZIP64 end record, or the
    /// end record.
    cd_must_end_at: u64,
}

enum ListState {
    Tail,
    Zip64 {
        locator_at: u64,
        record_at: u64,
        classic: (u64, u64, u64),
        tail_start: u64,
        tail: Vec<u8>,
    },
    Central {
        end: EndRecord,
        tail_start: u64,
        tail: Vec<u8>,
    },
}

pub(crate) struct ZipLister {
    state: ListState,
    spanned_head: bool,
}

impl ZipLister {
    pub(crate) fn new(head: &[u8]) -> Self {
        Self {
            state: ListState::Tail,
            spanned_head: head.starts_with(&[0x50, 0x4B, 0x07, 0x08]),
        }
    }

    /// Advance the listing. `Ok(true)` once every entry is in `builder`.
    pub(crate) fn step<S: ByteSource + ?Sized>(
        &mut self,
        source: &mut S,
        platform: ArchivePlatform,
        builder: &mut ListingBuilder,
    ) -> Result<bool, Halt> {
        if self.spanned_head {
            return Err(Halt::Refused(ArchiveRefusal::Spanned));
        }
        let len = source.len();
        match &self.state {
            ListState::Tail => {
                source.release_before(len.saturating_sub(ZIP_TAIL_WINDOW));
                let tail_start = len.saturating_sub(ZIP_TAIL_WINDOW);
                let tail = read_exact_at(source, ByteRange::new(tail_start, len))?;
                self.state = end_record(tail_start, tail, len)?;
                Ok(false)
            }
            ListState::Zip64 {
                locator_at,
                record_at,
                classic,
                tail_start,
                tail,
            } => {
                let record_end = record_at.checked_add(56).ok_or_else(damaged)?;
                let record = slice_or_read(source, *tail_start, tail, ByteRange::new(*record_at, record_end))?;
                if record[..4] != SIG_ZIP64_END {
                    return Err(damaged());
                }
                let (disk, disk_cd) = (u32_at(&record, 16), u32_at(&record, 20));
                let (on_disk, entries) = (u64_at(&record, 24), u64_at(&record, 32));
                if disk != 0 || disk_cd != 0 || on_disk != entries {
                    return Err(Halt::Refused(ArchiveRefusal::Spanned));
                }
                // A ZIP64 field is used only where the classic one is
                // saturated; otherwise both must agree.
                let pick = |classic: u64, max: u64, zip64: u64| if classic == max { zip64 } else { classic };
                let end = EndRecord {
                    entries: pick(classic.0, 0xFFFF, entries),
                    cd_size: pick(classic.1, 0xFFFF_FFFF, u64_at(&record, 40)),
                    cd_offset: pick(classic.2, 0xFFFF_FFFF, u64_at(&record, 48)),
                    cd_must_end_at: *record_at,
                };
                if *locator_at < record_end {
                    return Err(damaged());
                }
                let next = ListState::Central {
                    end,
                    tail_start: *tail_start,
                    tail: tail.clone(),
                };
                self.state = next;
                Ok(false)
            }
            ListState::Central { end, tail_start, tail } => {
                check_end_record(end)?;
                let cd = ByteRange::new(end.cd_offset, end.cd_offset + end.cd_size);
                let bytes = slice_or_read(source, *tail_start, tail, cd)?;
                parse_central_directory(&bytes, end, platform, builder)?;
                source.release_before(len);
                Ok(true)
            }
        }
    }
}

/// `range` from the tail already read, or from the source.
fn slice_or_read<S: ByteSource + ?Sized>(
    source: &mut S,
    tail_start: u64,
    tail: &[u8],
    range: ByteRange,
) -> Result<Vec<u8>, Halt> {
    let tail_end = tail_start + tail.len() as u64;
    if range.start >= tail_start && range.end <= tail_end {
        let from = (range.start - tail_start) as usize;
        return Ok(tail[from..from + range.len() as usize].to_vec());
    }
    Ok(read_exact_at(source, range)?)
}

/// Find the end record: the last signature whose comment runs exactly to
/// the end of the file.
fn end_record(tail_start: u64, tail: Vec<u8>, len: u64) -> Result<ListState, Halt> {
    let found = (0..tail.len().saturating_sub(21)).rev().find(|&i| {
        tail[i..].starts_with(&SIG_END) && tail_start + i as u64 + 22 + u64::from(u16_at(&tail, i + 20)) == len
    });
    let Some(at) = found else {
        return Err(Halt::Refused(missing_end_record(&tail)));
    };
    let e = &tail[at..];
    let (disk, disk_cd, on_disk, entries) = (u16_at(e, 4), u16_at(e, 6), u16_at(e, 8), u16_at(e, 10));
    let (cd_size, cd_offset) = (u32_at(e, 12), u32_at(e, 16));
    let end_at = tail_start + at as u64;
    // The ZIP64 locator sits right before the end record.
    if at >= 20 && tail[at - 20..].starts_with(&SIG_ZIP64_LOCATOR) {
        let l = &tail[at - 20..at];
        if u32_at(l, 4) != 0 || u32_at(l, 16) > 1 {
            return Err(Halt::Refused(ArchiveRefusal::Spanned));
        }
        return Ok(ListState::Zip64 {
            locator_at: end_at - 20,
            record_at: u64_at(l, 8),
            classic: (u64::from(entries), u64::from(cd_size), u64::from(cd_offset)),
            tail_start,
            tail,
        });
    }
    if disk != 0 || disk_cd != 0 || on_disk != entries {
        return Err(Halt::Refused(ArchiveRefusal::Spanned));
    }
    let end = EndRecord {
        entries: u64::from(entries),
        cd_size: u64::from(cd_size),
        cd_offset: u64::from(cd_offset),
        cd_must_end_at: end_at,
    };
    Ok(ListState::Central { end, tail_start, tail })
}

/// No end record: a file cut inside its central directory ends in an
/// incomplete central record (truncated); anything else is damaged.
fn missing_end_record(tail: &[u8]) -> ArchiveRefusal {
    let last = (0..tail.len().saturating_sub(3))
        .rev()
        .find(|&i| tail[i..].starts_with(&SIG_CENTRAL));
    match last {
        Some(i) if tail.len() - i < 46 => ArchiveRefusal::Truncated,
        Some(i) => {
            let r = &tail[i..];
            let record = 46 + usize::from(u16_at(r, 28)) + usize::from(u16_at(r, 30)) + usize::from(u16_at(r, 32));
            if record > r.len() {
                ArchiveRefusal::Truncated
            } else {
                ArchiveRefusal::Damaged
            }
        }
        None => ArchiveRefusal::Damaged,
    }
}

/// The checks the end record allows before the central directory is read.
fn check_end_record(end: &EndRecord) -> Result<(), Halt> {
    if end.entries > MAX_ENTRIES as u64 || end.cd_size > MAX_CENTRAL_DIRECTORY_BYTES {
        return Err(Halt::Refused(ArchiveRefusal::TooMany));
    }
    // Each central record is at least 46 bytes, and the directory ends
    // exactly where the end records begin (no prepended data: offset 0).
    if end.entries.saturating_mul(46) > end.cd_size
        || end.cd_offset.checked_add(end.cd_size) != Some(end.cd_must_end_at)
    {
        return Err(damaged());
    }
    Ok(())
}

struct Central<'a> {
    made_by: u16,
    flags: u16,
    method: u16,
    dos_time: u16,
    dos_date: u16,
    crc32: u32,
    compressed: u64,
    uncompressed: u64,
    disk: u32,
    external: u32,
    header_offset: u64,
    name: &'a [u8],
    extra: &'a [u8],
}

fn parse_central_directory(
    cd: &[u8],
    end: &EndRecord,
    platform: ArchivePlatform,
    builder: &mut ListingBuilder,
) -> Result<(), Halt> {
    let mut records = Vec::with_capacity(end.entries as usize);
    let mut pos = 0usize;
    for _ in 0..end.entries {
        let r = cd.get(pos..pos + 46).ok_or_else(damaged)?;
        if r[..4] != SIG_CENTRAL {
            return Err(damaged());
        }
        let (n, m, k) = (
            usize::from(u16_at(r, 28)),
            usize::from(u16_at(r, 30)),
            usize::from(u16_at(r, 32)),
        );
        let name = cd.get(pos + 46..pos + 46 + n).ok_or_else(damaged)?;
        let extra = cd.get(pos + 46 + n..pos + 46 + n + m).ok_or_else(damaged)?;
        cd.get(pos + 46 + n + m..pos + 46 + n + m + k).ok_or_else(damaged)?;
        let mut record = Central {
            made_by: u16_at(r, 4),
            flags: u16_at(r, 8),
            method: u16_at(r, 10),
            dos_time: u16_at(r, 12),
            dos_date: u16_at(r, 14),
            crc32: u32_at(r, 16),
            compressed: u64::from(u32_at(r, 20)),
            uncompressed: u64::from(u32_at(r, 24)),
            disk: u32::from(u16_at(r, 34)),
            external: u32_at(r, 38),
            header_offset: u64::from(u32_at(r, 42)),
            name,
            extra,
        };
        apply_zip64(&mut record)?;
        if record.flags & (FLAG_STRONG_ENCRYPTION | FLAG_CD_ENCRYPTED) != 0 {
            return Err(Halt::Refused(ArchiveRefusal::StrongEncryption));
        }
        if record.disk != 0 {
            return Err(Halt::Refused(ArchiveRefusal::Spanned));
        }
        records.push(record);
        pos += 46 + n + m + k;
    }
    if pos != cd.len() {
        return Err(damaged());
    }
    let limits = span_limits(&records, end.cd_offset)?;
    for (record, limit) in records.iter().zip(limits) {
        let (entry, locator) = zip_entry(record, limit, platform);
        builder.push(entry, locator).map_err(Halt::Refused)?;
    }
    Ok(())
}

/// Replace saturated sizes and offsets with the ZIP64 extra field's.
fn apply_zip64(r: &mut Central<'_>) -> Result<(), Halt> {
    let Some(data) = extra_field(r.extra, 0x0001) else {
        return if r.uncompressed == 0xFFFF_FFFF || r.compressed == 0xFFFF_FFFF || r.header_offset == 0xFFFF_FFFF {
            Err(damaged())
        } else {
            Ok(())
        };
    };
    let mut at = 0usize;
    let mut next = |len: usize| -> Result<&[u8], Halt> {
        let field = data.get(at..at + len).ok_or_else(damaged)?;
        at += len;
        Ok(field)
    };
    if r.uncompressed == 0xFFFF_FFFF {
        r.uncompressed = u64_at(next(8)?, 0);
    }
    if r.compressed == 0xFFFF_FFFF {
        r.compressed = u64_at(next(8)?, 0);
    }
    if r.header_offset == 0xFFFF_FFFF {
        r.header_offset = u64_at(next(8)?, 0);
    }
    if r.disk == 0xFFFF {
        r.disk = u32_at(next(4)?, 0);
    }
    Ok(())
}

/// The data of the first extra field with this id.
fn extra_field(mut extra: &[u8], id: u16) -> Option<&[u8]> {
    while extra.len() >= 4 {
        let (field_id, len) = (u16_at(extra, 0), usize::from(u16_at(extra, 2)));
        let data = extra.get(4..4 + len)?;
        if field_id == id {
            return Some(data);
        }
        extra = &extra[4 + len..];
    }
    None
}

/// Each entry's `[local header, lowest possible data end)` must not
/// overlap another's or the central directory (overlapped-file bombs).
/// Returns, per entry, the offset its data may not reach.
fn span_limits(records: &[Central<'_>], cd_start: u64) -> Result<Vec<u64>, Halt> {
    let mut starts = BTreeSet::new();
    let mut spans = Vec::with_capacity(records.len());
    for r in records {
        let end = r
            .header_offset
            .checked_add(30 + r.name.len() as u64)
            .and_then(|e| e.checked_add(r.compressed))
            .ok_or_else(damaged)?;
        if end > cd_start || !starts.insert(r.header_offset) {
            return Err(Halt::Refused(ArchiveRefusal::Bomb));
        }
        spans.push((r.header_offset, end));
    }
    let mut sorted = spans.clone();
    sorted.sort_unstable();
    if sorted.windows(2).any(|w| w[0].1 > w[1].0) {
        return Err(Halt::Refused(ArchiveRefusal::Bomb));
    }
    Ok(spans
        .iter()
        .map(|(start, _)| starts.range(start + 1..).next().copied().unwrap_or(cd_start))
        .collect())
}

fn method_name(method: u16) -> String {
    match method {
        1 => "Shrink".into(),
        2..=5 => "Reduce".into(),
        6 => "Implode".into(),
        9 => "Deflate64".into(),
        12 => "bzip2".into(),
        14 => "LZMA".into(),
        93 => "Zstandard".into(),
        95 => "xz".into(),
        98 => "PPMd".into(),
        other => format!("method {other}"),
    }
}

fn zip_entry(r: &Central<'_>, limit: u64, platform: ArchivePlatform) -> (ArchiveEntry, Locator) {
    let unicode_path = extra_field(r.extra, 0x7075)
        .filter(|d| d.len() >= 5 && d[0] == 1)
        .map(|d| (u32_at(d, 1), &d[5..]));
    let decoded = decode_name(RawName::Zip {
        raw: r.name,
        utf8_flag: r.flags & FLAG_UTF8 != 0,
        unicode_path,
    });
    let path = entry_path(&decoded);
    // Unix modes, when a Unix host made the entry.
    let mode = if r.made_by >> 8 == 3 { r.external >> 16 } else { 0 };
    let kind = match mode & 0o170_000 {
        0o120_000 => EntryKind::Symlink,
        0o040_000 => EntryKind::Folder,
        0o020_000 | 0o060_000 | 0o010_000 | 0o140_000 => EntryKind::Device,
        _ if decoded.ends_with('/') || decoded.ends_with('\\') => EntryKind::Folder,
        _ if r.made_by >> 8 == 0 && r.external & 0x10 != 0 => EntryKind::Folder,
        _ => EntryKind::File,
    };
    let aes = extra_field(r.extra, 0x9901).filter(|d| d.len() >= 7 && &d[2..4] == b"AE");
    let (cipher, data_method) = match (r.flags & FLAG_ENCRYPTED != 0, r.method, aes) {
        (false, method, _) => (EntryCipher::None, Some(method)),
        (true, METHOD_AES, Some(d)) => {
            let bits = match d[4] {
                1 => 128,
                2 => 192,
                3 => 256,
                _ => 0,
            };
            (
                EntryCipher::Aes { bits, ae: d[0] },
                (bits != 0 && (d[0] == 1 || d[0] == 2)).then(|| u16_at(d, 5)),
            )
        }
        (true, METHOD_AES, None) => (EntryCipher::Aes { bits: 0, ae: 0 }, None),
        (true, method, _) => (EntryCipher::ZipCrypto, Some(method)),
    };
    let skip = match (&path, kind) {
        (Err(reason), _) => Some(reason.clone()),
        (Ok(_), EntryKind::Symlink) => Some(SkipReason::Link),
        (Ok(_), EntryKind::Device) => Some(SkipReason::Device),
        (Ok(_), EntryKind::Folder) => None,
        (Ok(_), _) => match data_method {
            None => Some(SkipReason::Unsupported("Unknown encryption".into())),
            Some(METHOD_STORED | METHOD_DEFLATE) if r.uncompressed > platform.max_entry_bytes() => {
                Some(SkipReason::TooLarge)
            }
            Some(METHOD_STORED | METHOD_DEFLATE)
                if r.uncompressed > BOMB_RATIO_FLOOR_BYTES && r.uncompressed / BOMB_RATIO > r.compressed =>
            {
                Some(SkipReason::Bomb)
            }
            Some(METHOD_STORED | METHOD_DEFLATE) => None,
            Some(other) => Some(SkipReason::Method(method_name(other))),
        },
    };
    let locator = match (kind, &skip, data_method) {
        (EntryKind::File, None, Some(data_method)) => Locator::Zip(Box::new(ZipLocator {
            header_offset: r.header_offset,
            limit,
            raw_name: r.name.to_vec(),
            method: r.method,
            data_method,
            flags: r.flags,
            crc32: r.crc32,
            compressed_size: r.compressed,
            uncompressed_size: r.uncompressed,
            cipher,
            dos_time: r.dos_time,
        })),
        _ => Locator::None,
    };
    let entry = ArchiveEntry {
        index: 0,
        display_path: display_name(&decoded),
        path: path.ok(),
        kind,
        size: if kind == EntryKind::Folder { 0 } else { r.uncompressed },
        compressed_size: r.compressed,
        cipher,
        modified: modified(r),
        skip,
    };
    (entry, locator)
}

/// The extended timestamp (0x5455) or NTFS (0x000A) time, else the
/// zone-less DOS time.
fn modified(r: &Central<'_>) -> Option<ArchiveTime> {
    if let Some(d) = extra_field(r.extra, 0x5455)
        && d.len() >= 5
        && d[0] & 1 != 0
    {
        return Some(ArchiveTime::Utc {
            unix_ms: i64::from(u32_at(d, 1) as i32) * 1000,
        });
    }
    if let Some(d) = extra_field(r.extra, 0x000A) {
        let mut attrs = d.get(4..)?;
        while attrs.len() >= 4 {
            let (tag, size) = (u16_at(attrs, 0), usize::from(u16_at(attrs, 2)));
            if tag == 1 && size >= 24 && attrs.len() >= 4 + 8 {
                // 100 ns ticks since 1601-01-01.
                let ticks = u64_at(attrs, 4) as i64;
                return Some(ArchiveTime::Utc {
                    unix_ms: ticks / 10_000 - 11_644_473_600_000,
                });
            }
            attrs = attrs.get(4 + size..)?;
        }
    }
    let (t, d) = (r.dos_time, r.dos_date);
    let (month, day) = (((d >> 5) & 0x0F) as u8, (d & 0x1F) as u8);
    if month == 0 || month > 12 || day == 0 {
        return None;
    }
    Some(ArchiveTime::Local {
        year: 1980 + (d >> 9),
        month,
        day,
        hour: (t >> 11) as u8,
        minute: ((t >> 5) & 0x3F) as u8,
        second: ((t & 0x1F) * 2) as u8,
    })
}

// ------------------------------------------------------------- entries

enum Decryption {
    None,
    Zip(ZipCryptoKeys),
    Aes(Box<AesDecryptor>),
}

enum DecState {
    Local,
    CryptoHeader { data_start: u64 },
    Body(Box<Body>),
    Done,
}

struct Body {
    crypto: Decryption,
    inflater: Option<Inflater>,
    /// Compressed bytes still to read: `[pos, end)`.
    pos: u64,
    end: u64,
    /// Decrypted compressed bytes not yet decoded.
    buf: Zeroizing<Vec<u8>>,
    buf_pos: usize,
    produced: u64,
    crc: flate2::Crc,
    stream_end: bool,
}

/// One zip entry's decoder.
pub(crate) struct ZipDecoder {
    loc: ZipLocator,
    /// The password's encodings to try, in order
    /// ([`super::password::ArchivePassword::candidates`]).
    passwords: Vec<Zeroizing<Vec<u8>>>,
    /// Which of `passwords` opened the cipher.
    opened_with: Option<usize>,
    state: DecState,
}

impl ZipDecoder {
    pub(crate) fn new(loc: ZipLocator, passwords: Vec<Zeroizing<Vec<u8>>>) -> Self {
        Self {
            loc,
            passwords,
            opened_with: None,
            state: DecState::Local,
        }
    }

    /// Which password encoding opened the cipher (an index into the
    /// candidates it was made with); `None` for a plain entry or before
    /// the cipher is open.
    pub(crate) fn opened_with(&self) -> Option<usize> {
        self.opened_with
    }

    /// Whether this entry passing its own check proves the password: an
    /// AES entry (its authentication code), or a ZipCrypto entry whose CRC
    /// covers at least `ZIPCRYPTO_PROOF_BYTES`. A shorter ZipCrypto entry
    /// is guarded by its one check byte and little else.
    pub(crate) fn proves_password(&self) -> bool {
        match self.loc.cipher {
            EntryCipher::None => false,
            EntryCipher::ZipCrypto => self.loc.uncompressed_size >= ZIPCRYPTO_PROOF_BYTES,
            EntryCipher::Aes { .. } => true,
        }
    }

    pub(crate) fn next_piece<S: ByteSource + ?Sized>(&mut self, source: &mut S) -> PieceStep {
        let step = self.advance(source);
        let step = match step {
            Ok(step) => step,
            Err(Miss::Need(range)) => return PieceStep::NeedBytes(range),
            Err(Miss::Io(e)) => return PieceStep::Io(e),
            Err(Miss::Truncated) => PieceStep::Corrupt,
        };
        if !matches!(step, PieceStep::Data(_)) {
            self.state = DecState::Done;
            self.passwords.clear();
        }
        step
    }

    fn advance<S: ByteSource + ?Sized>(&mut self, source: &mut S) -> Result<PieceStep, Miss> {
        if let Some(step) = self.open(source)? {
            return Ok(step);
        }
        match &mut self.state {
            DecState::Body(body) => body.next(source, &self.loc),
            _ => Ok(PieceStep::Corrupt),
        }
    }

    /// Read the local header and open the cipher. `Ok(None)` once the
    /// body can be read; `Ok(Some(step))` when the entry ends first
    /// (corrupt, wrong password).
    pub(crate) fn open<S: ByteSource + ?Sized>(&mut self, source: &mut S) -> Result<Option<PieceStep>, Miss> {
        loop {
            match &mut self.state {
                DecState::Body(_) => return Ok(None),
                DecState::Done => return Ok(Some(PieceStep::Verified)),
                DecState::Local => {
                    let at = self.loc.header_offset;
                    let fixed = read_exact_at(source, ByteRange::new(at, at + 30))?;
                    let (n, m) = (u64::from(u16_at(&fixed, 26)), u64::from(u16_at(&fixed, 28)));
                    let names = read_exact_at(source, ByteRange::new(at + 30, at + 30 + n))?;
                    if !self.local_agrees(&fixed, &names) {
                        return Ok(Some(PieceStep::Corrupt));
                    }
                    let data_start = at + 30 + n + m;
                    match data_start.checked_add(self.loc.compressed_size) {
                        Some(end) if end <= self.loc.limit => {}
                        _ => return Ok(Some(PieceStep::Corrupt)),
                    }
                    self.state = DecState::CryptoHeader { data_start };
                }
                DecState::CryptoHeader { data_start } => {
                    let data_start = *data_start;
                    match self.open_crypto(source, data_start)? {
                        Ok(body) => self.state = DecState::Body(Box::new(body)),
                        Err(step) => return Ok(Some(step)),
                    }
                }
            }
        }
    }

    fn local_agrees(&self, fixed: &[u8], name: &[u8]) -> bool {
        let loc = &self.loc;
        if fixed[..4] != SIG_LOCAL
            || name != loc.raw_name.as_slice()
            || u16_at(fixed, 8) != loc.method
            || (u16_at(fixed, 6) & FLAG_ENCRYPTED) != (loc.flags & FLAG_ENCRYPTED)
        {
            return false;
        }
        if u16_at(fixed, 6) & FLAG_DATA_DESCRIPTOR == 0 {
            let (crc, compressed, size) = (u32_at(fixed, 14), u32_at(fixed, 18), u32_at(fixed, 22));
            let saturated = compressed == 0xFFFF_FFFF || size == 0xFFFF_FFFF;
            if crc != loc.crc32
                || (!saturated
                    && (u64::from(compressed) != loc.compressed_size || u64::from(size) != loc.uncompressed_size))
            {
                return false;
            }
        }
        true
    }

    /// Read the encryption header and open the cipher. The outer error is
    /// a miss; the inner one is the step to answer (wrong password,
    /// corrupt).
    fn open_crypto<S: ByteSource + ?Sized>(
        &mut self,
        source: &mut S,
        data_start: u64,
    ) -> Result<Result<Body, PieceStep>, Miss> {
        let loc = &self.loc;
        let data_end = data_start + loc.compressed_size;
        let (crypto, pos, end) = match loc.cipher {
            EntryCipher::None => (Decryption::None, data_start, data_end),
            EntryCipher::ZipCrypto => {
                if loc.compressed_size < 12 {
                    return Ok(Err(PieceStep::Corrupt));
                }
                let header = read_exact_at(source, ByteRange::new(data_start, data_start + 12))?;
                let mut fixed = [0u8; 12];
                fixed.copy_from_slice(&header);
                let check = if loc.flags & FLAG_DATA_DESCRIPTOR != 0 {
                    (loc.dos_time >> 8) as u8
                } else {
                    (loc.crc32 >> 24) as u8
                };
                match self
                    .passwords
                    .iter()
                    .enumerate()
                    .find_map(|(i, p)| zipcrypto::open_header(p, &fixed, check).map(|keys| (i, keys)))
                {
                    Some((i, keys)) => {
                        self.opened_with = Some(i);
                        (Decryption::Zip(keys), data_start + 12, data_end)
                    }
                    None => return Ok(Err(PieceStep::WrongPassword)),
                }
            }
            EntryCipher::Aes { bits, .. } => {
                let Some(salt_len) = winzip_aes::salt_len(bits) else {
                    return Ok(Err(PieceStep::Corrupt));
                };
                let overhead = (salt_len + 2 + AUTH_CODE_LEN) as u64;
                if loc.compressed_size < overhead {
                    return Ok(Err(PieceStep::Corrupt));
                }
                let head = read_exact_at(source, ByteRange::new(data_start, data_start + salt_len as u64 + 2))?;
                let verifier = [head[salt_len], head[salt_len + 1]];
                let salt = &head[..salt_len];
                match self
                    .passwords
                    .iter()
                    .enumerate()
                    .find_map(|(i, p)| winzip_aes::open(p, bits, salt, verifier).map(|aes| (i, aes)))
                {
                    Some((i, aes)) => {
                        self.opened_with = Some(i);
                        (
                            Decryption::Aes(Box::new(aes)),
                            data_start + salt_len as u64 + 2,
                            data_end - AUTH_CODE_LEN as u64,
                        )
                    }
                    None => return Ok(Err(PieceStep::WrongPassword)),
                }
            }
        };
        Ok(Ok(Body {
            crypto,
            inflater: (loc.data_method == METHOD_DEFLATE).then(Inflater::new),
            pos,
            end,
            buf: Zeroizing::new(Vec::new()),
            buf_pos: 0,
            produced: 0,
            crc: flate2::Crc::new(),
            stream_end: false,
        }))
    }
}

impl Body {
    /// Read and decrypt the next window of compressed bytes.
    fn refill<S: ByteSource + ?Sized>(&mut self, source: &mut S) -> Result<(), Miss> {
        let window_end = self.pos.saturating_add(PULL_AHEAD_BYTES).min(self.end);
        let mut window = Zeroizing::new(read_exact_at(source, ByteRange::new(self.pos, window_end))?);
        match &mut self.crypto {
            Decryption::None => {}
            Decryption::Zip(keys) => keys.decrypt(&mut window),
            Decryption::Aes(aes) => aes.decrypt(&mut window),
        }
        self.pos = window_end;
        // Keep what the decoder has not taken yet, then the new window.
        let mut buf = Zeroizing::new(Vec::with_capacity(self.buf.len() - self.buf_pos + window.len()));
        buf.extend_from_slice(&self.buf[self.buf_pos..]);
        buf.extend_from_slice(&window);
        self.buf = buf;
        self.buf_pos = 0;
        source.release_before(self.pos);
        Ok(())
    }

    fn next<S: ByteSource + ?Sized>(&mut self, source: &mut S, loc: &ZipLocator) -> Result<PieceStep, Miss> {
        let declared = loc.uncompressed_size;
        loop {
            let unread = &self.buf[self.buf_pos..];
            let finished_decoding =
                self.stream_end || (self.inflater.is_none() && unread.is_empty() && self.pos == self.end);
            if finished_decoding {
                if !unread.is_empty() || self.pos < self.end {
                    // Bytes after the deflate stream's end: still read, so
                    // the authentication code covers all of them.
                    self.buf_pos = self.buf.len();
                    if self.pos < self.end {
                        self.refill(source)?;
                    }
                    continue;
                }
                return self.finish(source, loc);
            }
            // At most one byte past the declared size, so a lie is seen.
            let room = (declared - self.produced.min(declared))
                .saturating_add(1)
                .min(PIECE_BYTES as u64) as usize;
            let mut out = Vec::new();
            let consumed = match &mut self.inflater {
                Some(inflater) => {
                    let Ok(pushed) = inflater.push(unread, &mut out, room) else {
                        return Ok(PieceStep::Corrupt);
                    };
                    self.stream_end = pushed.stream_end;
                    pushed.consumed
                }
                None => {
                    let n = unread.len().min(room);
                    out.extend_from_slice(&unread[..n]);
                    n
                }
            };
            self.buf_pos += consumed;
            self.produced += out.len() as u64;
            if self.produced > declared {
                return Ok(PieceStep::Skipped(SkipReason::Bomb));
            }
            if !out.is_empty() {
                self.crc.update(&out);
                return Ok(PieceStep::Data(out));
            }
            if self.stream_end || consumed > 0 {
                continue;
            }
            if self.pos == self.end {
                // The deflate stream wants bytes the entry does not have.
                return Ok(PieceStep::Corrupt);
            }
            self.refill(source)?;
        }
    }

    fn finish<S: ByteSource + ?Sized>(&mut self, source: &mut S, loc: &ZipLocator) -> Result<PieceStep, Miss> {
        if self.produced != loc.uncompressed_size {
            return Ok(PieceStep::Corrupt);
        }
        let check_crc = !matches!(loc.cipher, EntryCipher::Aes { ae: 2, .. });
        if let Decryption::Aes(_) = self.crypto {
            let stored = read_exact_at(source, ByteRange::new(self.end, self.end + AUTH_CODE_LEN as u64))?;
            let Decryption::Aes(aes) = std::mem::replace(&mut self.crypto, Decryption::None) else {
                return Ok(PieceStep::Corrupt);
            };
            if !aes.verify(&stored) {
                return Ok(PieceStep::Corrupt);
            }
        }
        if check_crc && self.crc.sum() != loc.crc32 {
            return Ok(PieceStep::Corrupt);
        }
        Ok(PieceStep::Verified)
    }
}
