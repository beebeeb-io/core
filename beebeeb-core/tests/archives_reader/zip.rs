//! The zip reader: listing from the end, hostile central directories,
//! entry streams, and resumability (spec §5.1, §6.2, A4).

use beebeeb_core::archives::{
    ArchiveFormat, ArchivePassword, ArchivePlatform, ArchiveRefusal, ArchiveSession, ArchiveTime, ByteSource,
    EntryCipher, EntryKind, PieceStep, SessionStep, SkipReason, SourceError,
};
use zip::CompressionMethod::{Deflated, Stored};

use crate::support::{
    Blocking, Chaos, Lock, RawZip, RawZipEntry, Recording, drive, list, read_entry, read_entry_with, zip9, zip9_read,
};

fn listed(bytes: Vec<u8>) -> ArchiveSession<Blocking> {
    let mut session = ArchiveSession::open(Blocking(bytes), ArchivePlatform::Native);
    assert_eq!(drive(&mut session, |_, r| panic!("{r:?}")), SessionStep::Listed);
    session
}

#[test]
fn zip_lists_stored_and_deflate() {
    let text = b"the quick brown fox ".repeat(500);
    let bytes = zip9(&[
        ("a.txt", Stored, None, b"hello"),
        ("dir/", Stored, None, b""),
        ("dir/b.txt", Deflated, None, &text),
    ]);
    let mut session = listed(bytes);
    let listing = session.listing().unwrap().clone();
    assert_eq!(listing.format, ArchiveFormat::Zip);
    let rows: Vec<_> = listing
        .entries
        .iter()
        .map(|e| (e.display_path.as_str(), e.kind, e.size))
        .collect();
    assert_eq!(
        rows,
        vec![
            ("a.txt", EntryKind::File, 5),
            ("dir", EntryKind::Folder, 0),
            ("dir/b.txt", EntryKind::File, 10_000)
        ]
    );
    assert!(listing.entries[2].compressed_size < 10_000);
    assert_eq!(read_entry(&mut session, 0), (b"hello".to_vec(), PieceStep::Verified));
    assert_eq!(read_entry(&mut session, 2), (text, PieceStep::Verified));
}

#[test]
fn zip_lists_zip64() {
    let mut zip = RawZip::of(vec![
        RawZipEntry::stored("big-one.bin", b"zip64 sized"),
        RawZipEntry::deflated("two.txt", b"two"),
    ]);
    zip.zip64 = true;
    let mut session = listed(zip.build());
    let sizes: Vec<_> = session
        .listing()
        .unwrap()
        .entries
        .iter()
        .map(|e| (e.display_path.clone(), e.size))
        .collect();
    assert_eq!(sizes, vec![("big-one.bin".to_string(), 11), ("two.txt".to_string(), 3)]);
    assert_eq!(read_entry(&mut session, 1), (b"two".to_vec(), PieceStep::Verified));
}

#[test]
fn zip_empty_archive() {
    let listing = list(RawZip::default().build()).unwrap();
    assert_eq!(listing.format, ArchiveFormat::Zip);
    assert!(listing.entries.is_empty());
}

#[test]
fn zip_eocd_found_behind_comment() {
    let mut zip = RawZip::of(vec![RawZipEntry::stored("a.txt", b"a")]);
    // A comment holding a fake end-record signature with a wrong length.
    zip.comment = [b"see PK\x05\x06".as_slice(), &[0u8; 14], &[0xFF, 0x00], &[b'c'; 900]].concat();
    let listing = list(zip.build()).unwrap();
    assert_eq!(listing.entries.len(), 1);
}

#[test]
fn zip_listing_demands_only_tail_and_cd() {
    let big = vec![0u8; 100 * 1024 * 1024];
    let mut entries = vec![RawZipEntry::stored("huge.bin", &big)];
    for i in 0..50 {
        entries.push(RawZipEntry::stored(&format!("small-{i}.txt"), b"s"));
    }
    let bytes = RawZip::of(entries).build();
    let mut session = ArchiveSession::open(Recording::new(bytes), ArchivePlatform::Native);
    assert_eq!(drive(&mut session, |_, r| panic!("{r:?}")), SessionStep::Listed);
    let cd_size: u64 = (46 + 8) + 50 * (46 + 12);
    let read = session.source_mut().bytes_read();
    assert!(read < 512 + 65_633 + cd_size + 4096, "listing read {read} bytes");
}

#[test]
fn zip_truncated_cd_is_truncated() {
    let bytes = RawZip::of(
        (0..20)
            .map(|i| RawZipEntry::stored(&format!("f{i}.txt"), b"x"))
            .collect(),
    )
    .build();
    // Cut inside the central directory (the end record is the last 22 bytes).
    let cut = bytes.len() - 22 - 30;
    assert_eq!(list(bytes[..cut].to_vec()), Err(ArchiveRefusal::Truncated));
}

#[test]
fn zip_missing_eocd_is_damaged() {
    let mut bytes = RawZip::of(vec![RawZipEntry::stored("a.txt", b"a")]).build();
    let at = bytes.len() - 22;
    bytes[at..at + 4].copy_from_slice(b"XXXX");
    assert_eq!(list(bytes), Err(ArchiveRefusal::Damaged));
    // A central directory that does not end where the end record begins.
    let mut lying = RawZip::of(vec![RawZipEntry::stored("a.txt", b"a")]);
    lying.cd_size_override = Some(10);
    assert_eq!(list(lying.build()), Err(ArchiveRefusal::Damaged));
}

#[test]
fn zip_sfx_prefix_refused() {
    let mut sfx = RawZip::of(vec![RawZipEntry::stored("a.txt", b"a")]);
    sfx.prefix = [b"MZ".as_slice(), &[0x90; 3000]].concat();
    assert_eq!(list(sfx.build()), Err(ArchiveRefusal::SelfExtracting));
}

#[test]
fn zip_spanned_refused() {
    let mut spanned = RawZip::of(vec![RawZipEntry::stored("a.txt", b"a")]);
    spanned.disk = 1;
    assert_eq!(list(spanned.build()), Err(ArchiveRefusal::Spanned));
    // The first part of a split archive starts with the spanning marker.
    let mut first_part = b"PK\x07\x08".to_vec();
    first_part.extend_from_slice(&RawZip::of(vec![RawZipEntry::stored("a.txt", b"a")]).build());
    assert_eq!(list(first_part), Err(ArchiveRefusal::Spanned));
}

#[test]
fn zip_strong_encryption_refused() {
    let mut entry = RawZipEntry::stored("secret.bin", b"x");
    entry.flags = 1 | (1 << 6);
    assert_eq!(
        list(RawZip::of(vec![entry]).build()),
        Err(ArchiveRefusal::StrongEncryption)
    );
}

#[test]
fn zip_local_header_disagrees_entry_is_corrupt() {
    let mut renamed = RawZipEntry::stored("shown.txt", b"payload");
    renamed.local_name = Some(b"hidden.txt".to_vec());
    let mut remethod = RawZipEntry::stored("other.txt", b"payload");
    remethod.local_method = Some(8);
    let mut session = listed(RawZip::of(vec![renamed, remethod, RawZipEntry::stored("ok.txt", b"ok")]).build());
    assert_eq!(read_entry(&mut session, 0), (Vec::new(), PieceStep::Corrupt));
    assert_eq!(read_entry(&mut session, 1), (Vec::new(), PieceStep::Corrupt));
    assert_eq!(read_entry(&mut session, 2), (b"ok".to_vec(), PieceStep::Verified));
}

#[test]
fn zip_overlapping_entries_refused() {
    let mut twin = RawZipEntry::stored("twin.txt", b"payload");
    twin.header_offset = Some(0);
    let bytes = RawZip::of(vec![RawZipEntry::stored("first.txt", b"payload"), twin]).build();
    assert_eq!(list(bytes), Err(ArchiveRefusal::Bomb));
    // An entry whose data would run into the central directory.
    let mut long = RawZipEntry::stored("long.txt", b"short");
    long.compressed = Some(5_000);
    assert_eq!(list(RawZip::of(vec![long]).build()), Err(ArchiveRefusal::Bomb));
}

#[test]
fn zip_lying_size_entry_cut_as_bomb() {
    let real = vec![b'A'; 1024 * 1024];
    let mut liar = RawZipEntry::deflated("small.txt", &real);
    liar.uncompressed = 100;
    let mut session = listed(RawZip::of(vec![liar]).build());
    let (out, end) = read_entry(&mut session, 0);
    assert_eq!(end, PieceStep::Skipped(SkipReason::Bomb));
    assert!(out.len() <= 101, "{} bytes passed the declared 100", out.len());
}

#[test]
fn zip_ratio_bomb_skipped() {
    let gib = 1024 * 1024 * 1024u64;
    let mut bomb = RawZipEntry::stored("bomb.bin", &vec![0u8; 1024 * 1024]);
    bomb.method = 8;
    bomb.uncompressed = 2 * gib;
    let mut edge = RawZipEntry::stored("edge.bin", &vec![0u8; 1024 * 1024]);
    edge.method = 8;
    edge.uncompressed = gib; // 1,024:1, but not over 1 GiB
    let listing = list(RawZip::of(vec![bomb, edge]).build()).unwrap();
    assert_eq!(listing.entries[0].skip, Some(SkipReason::Bomb));
    assert_eq!(listing.entries[1].skip, None);
}

#[test]
fn zip_symlink_entry_skipped() {
    let mut link = RawZipEntry::stored("link", b"/etc/passwd");
    link.made_by = 3 << 8 | 30;
    link.external = 0o120_777 << 16;
    let mut regular = RawZipEntry::stored("file", b"x");
    regular.made_by = 3 << 8 | 30;
    regular.external = 0o100_644 << 16;
    let listing = list(RawZip::of(vec![link, regular]).build()).unwrap();
    assert_eq!(
        (listing.entries[0].kind, listing.entries[0].skip.clone()),
        (EntryKind::Symlink, Some(SkipReason::Link))
    );
    assert_eq!(
        (listing.entries[1].kind, listing.entries[1].skip.clone()),
        (EntryKind::File, None)
    );
}

#[test]
fn zip_unsupported_method_skipped() {
    let mut bzip2 = RawZipEntry::stored("data.bz", b"BZh9...");
    bzip2.method = 12;
    let listing = list(RawZip::of(vec![bzip2]).build()).unwrap();
    assert_eq!(listing.entries[0].skip, Some(SkipReason::Method("bzip2".into())));
}

#[test]
fn zip_entry_count_over_cap_refused() {
    let mut zip = RawZip::of(vec![RawZipEntry::stored("a.txt", b"a")]);
    zip.zip64 = true;
    zip.entries_override = Some(100_001);
    assert_eq!(list(zip.build()), Err(ArchiveRefusal::TooMany));
}

#[test]
fn zip_cd_over_32_mib_refused() {
    let mut zip = RawZip::of(vec![RawZipEntry::stored("a.txt", b"a")]);
    zip.zip64 = true;
    zip.cd_size_override = Some(32 * 1024 * 1024 + 1);
    assert_eq!(list(zip.build()), Err(ArchiveRefusal::TooMany));
}

#[test]
fn zip_crc_mismatch_is_corrupt() {
    let mut wrong = RawZipEntry::deflated("wrong.txt", b"some text that is stored with a wrong checksum");
    wrong.crc ^= 0xDEAD_BEEF;
    let mut session = listed(RawZip::of(vec![wrong]).build());
    let (out, end) = read_entry(&mut session, 0);
    assert_eq!(end, PieceStep::Corrupt);
    // The bytes were handed out unverified; Corrupt means none may be kept.
    assert_eq!(out, b"some text that is stored with a wrong checksum");
}

/// A source that never holds anything: every read is `Pending`.
struct Unanswered(u64);

impl ByteSource for Unanswered {
    fn len(&self) -> u64 {
        self.0
    }

    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<usize, SourceError> {
        Err(SourceError::Pending(beebeeb_core::archives::ByteRange::new(
            offset,
            offset + buf.len() as u64,
        )))
    }
}

#[test]
fn zip_parse_restarts_capped_at_8() {
    let mut session = ArchiveSession::open(Unanswered(4096), ArchivePlatform::Browser);
    let mut demands = 0;
    let end = loop {
        match session.step() {
            SessionStep::NeedBytes(_) => demands += 1,
            other => break other,
        }
        assert!(demands < 100, "the session kept asking");
    };
    assert_eq!(end, SessionStep::Refused(ArchiveRefusal::Damaged));
    assert_eq!(demands, 9, "one demand and eight repeats");
}

#[test]
fn zip_dos_time_is_local_and_ut_extra_is_utc() {
    let dos = RawZipEntry::stored("dos.txt", b"d");
    let mut ut = RawZipEntry::stored("ut.txt", b"u");
    ut.cd_extra = [0x55, 0x54, 5, 0, 1].to_vec();
    ut.cd_extra.extend_from_slice(&1_700_000_000u32.to_le_bytes());
    let listing = list(RawZip::of(vec![dos, ut]).build()).unwrap();
    assert_eq!(
        listing.entries[0].modified,
        Some(ArchiveTime::Local {
            year: 2024,
            month: 3,
            day: 15,
            hour: 12,
            minute: 34,
            second: 56
        })
    );
    assert_eq!(
        listing.entries[1].modified,
        Some(ArchiveTime::Utc {
            unix_ms: 1_700_000_000_000
        })
    );
}

#[test]
fn resumable_pull_matches_one_shot() {
    // ~300 KiB that compresses to several 64 KiB windows.
    let data: Vec<u8> = (0..300_000u32)
        .map(|i| ((i * 7919) % 253) as u8 ^ (i >> 9) as u8)
        .collect();
    let password = "correct horse";
    let cases: [(&str, zip::CompressionMethod, Lock<'_>); 4] = [
        ("stored", Stored, None),
        ("deflate", Deflated, None),
        ("aes-256 deflate", Deflated, Some((password, true))),
        ("zipcrypto deflate", Deflated, Some((password, false))),
    ];
    for (label, method, protection) in cases {
        let bytes = zip9(&[("data.bin", method, protection, &data)]);
        let reference = zip9_read(&bytes, 0, protection.map(|(p, _)| p));
        assert_eq!(reference, data, "{label}: zip 9's own read");
        let cipher = list(bytes.clone()).unwrap().entries[0].cipher;
        assert_eq!(cipher != EntryCipher::None, protection.is_some(), "{label}");
        for seed in 1..=8u64 {
            let mut session = ArchiveSession::open(Chaos::new(bytes.clone(), seed), ArchivePlatform::Browser);
            assert_eq!(
                drive(&mut session, |s, r| s.grant(r)),
                SessionStep::Listed,
                "{label} seed {seed}"
            );
            let pw = protection.map(|(p, _)| ArchivePassword::new(p.to_string()));
            let (out, end) = read_entry_with(&mut session, 0, pw.as_ref(), |s, r| s.grant(r));
            assert_eq!(end, PieceStep::Verified, "{label} seed {seed}");
            assert!(out == reference, "{label} seed {seed}: different bytes");
            assert!(
                session.source_mut().pendings > 0,
                "{label} seed {seed}: no miss happened"
            );
        }
    }
}

/// A ZIP64 locator that names a record offset near u64::MAX is damaged,
/// never an overflow (review finding).
#[test]
fn zip64_locator_offset_near_the_end_of_u64_is_damaged() {
    let mut zip = RawZip::of(vec![RawZipEntry::stored("a.txt", b"a")]);
    zip.zip64 = true;
    let mut bytes = zip.build();
    let locator = bytes.len() - 22 - 20;
    assert_eq!(&bytes[locator..locator + 4], b"PK\x06\x07");
    bytes[locator + 8..locator + 16].copy_from_slice(&(u64::MAX - 15).to_le_bytes());
    assert_eq!(list(bytes), Err(ArchiveRefusal::Damaged));
}
