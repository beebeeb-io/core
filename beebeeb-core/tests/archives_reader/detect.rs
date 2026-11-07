//! Detection by magic bytes, never the extension (spec §5.1, A2).

use beebeeb_core::archives::{ArchiveFormat, Detection, ForeignFormat, detect, detect_gzip_inner};

/// A 512-byte tar header for `name` with the given magic, checksum filled in.
fn tar_header(name: &str, ustar: bool) -> Vec<u8> {
    let mut h = vec![0u8; 512];
    h[..name.len()].copy_from_slice(name.as_bytes());
    h[100..108].copy_from_slice(b"0000644\0");
    h[108..116].copy_from_slice(b"0000000\0");
    h[116..124].copy_from_slice(b"0000000\0");
    h[124..136].copy_from_slice(b"00000000005\0");
    h[136..148].copy_from_slice(b"00000000000\0");
    h[156] = b'0';
    if ustar {
        h[257..263].copy_from_slice(b"ustar\0");
        h[263..265].copy_from_slice(b"00");
    }
    h[148..156].copy_from_slice(b"        ");
    let sum: u32 = h.iter().map(|&b| u32::from(b)).sum();
    h[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    h
}

fn zip_end_record(cd_offset: u32, cd_size: u32, entries: u16) -> Vec<u8> {
    let mut e = vec![0x50, 0x4B, 0x05, 0x06, 0, 0, 0, 0];
    e.extend_from_slice(&entries.to_le_bytes());
    e.extend_from_slice(&entries.to_le_bytes());
    e.extend_from_slice(&cd_size.to_le_bytes());
    e.extend_from_slice(&cd_offset.to_le_bytes());
    e.extend_from_slice(&0u16.to_le_bytes());
    e
}

fn head_tail(bytes: &[u8]) -> (&[u8], &[u8], u64) {
    let head = &bytes[..bytes.len().min(512)];
    let tail_start = bytes.len().saturating_sub(65_633);
    (head, &bytes[tail_start..], bytes.len() as u64)
}

fn detected(bytes: &[u8]) -> Detection {
    let (head, tail, len) = head_tail(bytes);
    detect(head, tail, len)
}

#[test]
fn detect_zip_local_header() {
    let mut bytes = vec![0x50, 0x4B, 0x03, 0x04];
    bytes.extend_from_slice(&[0u8; 60]);
    bytes.extend_from_slice(&zip_end_record(64, 0, 0));
    assert_eq!(detected(&bytes), Detection::Archive(ArchiveFormat::Zip));
}

#[test]
fn detect_empty_zip() {
    let bytes = zip_end_record(0, 0, 0);
    assert_eq!(detected(&bytes), Detection::Archive(ArchiveFormat::Zip));
}

#[test]
fn detect_gzip_then_inner_tar_is_tgz() {
    let bytes = [0x1F, 0x8B, 0x08, 0, 0, 0, 0, 0, 0, 0x03];
    assert_eq!(detected(&bytes), Detection::GzipNeedsInflatedHead);
    assert_eq!(detect_gzip_inner(&tar_header("a.txt", true)), ArchiveFormat::TarGzip);
}

#[test]
fn detect_gzip_then_text_is_gz() {
    let bytes = [0x1F, 0x8B, 0x08, 0, 0, 0, 0, 0, 0, 0x03];
    assert_eq!(detected(&bytes), Detection::GzipNeedsInflatedHead);
    assert_eq!(detect_gzip_inner(b"just some notes\n"), ArchiveFormat::Gzip);
    let mut long_text = b"hello ".repeat(200);
    long_text.truncate(512);
    assert_eq!(detect_gzip_inner(&long_text), ArchiveFormat::Gzip);
}

#[test]
fn detect_ustar() {
    let mut bytes = tar_header("a.txt", true);
    bytes.extend_from_slice(&[0u8; 1536]);
    assert_eq!(detected(&bytes), Detection::Archive(ArchiveFormat::Tar));
}

#[test]
fn detect_v7_tar_by_checksum() {
    let mut bytes = tar_header("old.txt", false);
    bytes.extend_from_slice(&[0u8; 1536]);
    assert_eq!(detected(&bytes), Detection::Archive(ArchiveFormat::Tar));
}

#[test]
fn detect_bad_checksum_is_not_tar() {
    let mut bytes = tar_header("a.txt", true);
    bytes[0] = b'b'; // the stored checksum no longer matches
    bytes.extend_from_slice(&[0u8; 1536]);
    assert_eq!(detected(&bytes), Detection::NotAnArchive);
    // An all-zero block is never a tar header either.
    assert_eq!(detected(&[0u8; 2048]), Detection::NotAnArchive);
}

#[test]
fn detect_sfx_prefix() {
    let mut bytes = b"MZ".to_vec();
    bytes.extend_from_slice(&[0x90u8; 4000]);
    let local_at = bytes.len() as u32;
    bytes.extend_from_slice(&[0x50, 0x4B, 0x03, 0x04]);
    bytes.extend_from_slice(&[0u8; 60]);
    let cd_at = bytes.len() as u32;
    bytes.extend_from_slice(&zip_end_record(cd_at, 0, 0));
    assert!(local_at > 0);
    assert_eq!(detected(&bytes), Detection::SelfExtracting);
    // An `MZ` program with no zip end record is just not an archive.
    let plain_program = [b"MZ".as_slice(), &[0x90u8; 4000]].concat();
    assert_eq!(detected(&plain_program), Detection::NotAnArchive);
}

#[test]
fn detect_foreign_by_name() {
    let rows: [(&[u8], ForeignFormat); 5] = [
        (b"Rar!\x1A\x07\x01\x00", ForeignFormat::Rar),
        (b"7z\xBC\xAF\x27\x1C\x00\x04", ForeignFormat::SevenZip),
        (b"\xFD7zXZ\x00\x00\x04", ForeignFormat::Xz),
        (b"\x28\xB5\x2F\xFD\x24\x00", ForeignFormat::Zstd),
        (b"BZh91AY&SY", ForeignFormat::Bzip2),
    ];
    for (magic, format) in rows {
        let mut bytes = magic.to_vec();
        bytes.extend_from_slice(&[0u8; 100]);
        assert_eq!(detected(&bytes), Detection::Foreign(format), "{format:?}");
    }
}

#[test]
fn detect_zip_named_tar_reads_as_zip() {
    // `detect` takes bytes only: no name can reach it. A zip uploaded as
    // `backup.tar` and a tar uploaded as `photos.zip` read as what they are.
    let mut zip_bytes = vec![0x50, 0x4B, 0x03, 0x04];
    zip_bytes.extend_from_slice(&[0u8; 60]);
    zip_bytes.extend_from_slice(&zip_end_record(64, 0, 0));
    assert_eq!(detected(&zip_bytes), Detection::Archive(ArchiveFormat::Zip));
    let mut tar_bytes = tar_header("photo.jpg", true);
    tar_bytes.extend_from_slice(&[0u8; 1536]);
    assert_eq!(detected(&tar_bytes), Detection::Archive(ArchiveFormat::Tar));
}

#[test]
fn detect_unknown_is_not_an_archive() {
    assert_eq!(detected(b"%PDF-1.7\n%..."), Detection::NotAnArchive);
    assert_eq!(detected(b""), Detection::NotAnArchive);
    assert_eq!(detected(b"PK"), Detection::NotAnArchive);
}
