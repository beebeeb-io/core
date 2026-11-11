//! Tar, tgz and gz listing and entry streams.

use beebeeb_core::archives::{
    ArchiveFormat, ArchivePlatform, ArchiveRefusal, ArchiveSession, ArchiveTime, EntryKind, PieceStep, SkipReason,
};

use crate::support::{
    Blocking, Recording, TarBuilder, drive, gzip, gzip_named, gzip_zeros_member, list, list_chaos, list_on, octal,
    read_entry, seal_checksum, tar_header,
};

fn sample_tar() -> Vec<u8> {
    TarBuilder::default()
        .file("a.txt", b"hello")
        .folder("dir/")
        .file("dir/b.txt", b"abc")
        .finish()
}

fn paths(listing: &beebeeb_core::archives::ArchiveListing) -> Vec<(String, EntryKind, u64)> {
    listing
        .entries
        .iter()
        .map(|e| (e.display_path.clone(), e.kind, e.size))
        .collect()
}

#[test]
fn tar_lists_ustar() {
    let listing = list(sample_tar()).unwrap();
    assert_eq!(listing.format, ArchiveFormat::Tar);
    assert!(listing.complete);
    assert_eq!(
        paths(&listing),
        vec![
            ("a.txt".into(), EntryKind::File, 5),
            ("dir".into(), EntryKind::Folder, 0),
            ("dir/b.txt".into(), EntryKind::File, 3)
        ]
    );
    assert_eq!(
        (listing.totals.files, listing.totals.folders, listing.totals.bytes),
        (2, 1, 8)
    );
    assert!(matches!(listing.entries[0].modified, Some(ArchiveTime::Utc { .. })));
    assert_eq!(
        listing.entries[2].path.as_ref().unwrap().components,
        vec!["dir", "b.txt"]
    );
}

#[test]
fn tar_lists_v7() {
    let listing = list(TarBuilder::v7().file("old.txt", b"v7 data").finish()).unwrap();
    assert_eq!(paths(&listing), vec![("old.txt".into(), EntryKind::File, 7)]);
}

#[test]
fn tar_bad_checksum_is_damaged() {
    let mut tar = sample_tar();
    // The second header starts after a.txt's header and one data block.
    tar[1024] ^= 0x01;
    assert_eq!(list(tar), Err(ArchiveRefusal::Damaged));
}

#[test]
fn tar_pax_size_and_path() {
    let long = format!("{}/name.txt", "deep".repeat(40));
    let tar = TarBuilder::default()
        .pax(&[("path", &long), ("size", "7"), ("mtime", "1700000000.25")])
        .raw(&tar_header(b"short", b'0', &octal(0, 12), true))
        .data(b"seven!!")
        .file("next.txt", b"n")
        .finish();
    let listing = list(tar).unwrap();
    assert_eq!(paths(&listing)[1], (long, EntryKind::File, 7));
    assert_eq!(
        listing.entries[1].modified,
        Some(ArchiveTime::Utc {
            unix_ms: 1_700_000_000_250
        })
    );
    assert_eq!(paths(&listing)[2], ("next.txt".into(), EntryKind::File, 1));
}

#[test]
fn tar_gnu_long_name() {
    let long = format!("gnu/{}.txt", "x".repeat(200));
    let tar = TarBuilder::default()
        .gnu_long(&long)
        .file("truncated-name", b"data")
        .finish();
    let listing = list(tar).unwrap();
    assert_eq!(
        paths(&listing),
        vec![("gnu".into(), EntryKind::Folder, 0), (long, EntryKind::File, 4)]
    );
}

#[test]
fn tar_base256_size() {
    let mut size = [0u8; 12];
    size[0] = 0x80;
    size[11] = 5;
    let tar = TarBuilder::default()
        .raw(&tar_header(b"binary-size.bin", b'0', &size, true))
        .data(b"12345")
        .file("after.txt", b"ok")
        .finish();
    let listing = list(tar).unwrap();
    assert_eq!(
        paths(&listing),
        vec![
            ("binary-size.bin".into(), EntryKind::File, 5),
            ("after.txt".into(), EntryKind::File, 2)
        ]
    );
}

#[test]
fn tar_link_and_device_entries_skipped() {
    let rows = [
        (b'1', EntryKind::HardLink, SkipReason::Link),
        (b'2', EntryKind::Symlink, SkipReason::Link),
        (b'3', EntryKind::Device, SkipReason::Device),
        (b'4', EntryKind::Device, SkipReason::Device),
        (b'6', EntryKind::Device, SkipReason::Device),
    ];
    for (typeflag, kind, skip) in rows {
        let tar = TarBuilder::default()
            .entry("special", typeflag, b"")
            .file("plain.txt", b"p")
            .finish();
        let listing = list(tar).unwrap();
        assert_eq!(listing.entries[0].kind, kind, "typeflag {}", typeflag as char);
        assert_eq!(listing.entries[0].skip, Some(skip), "typeflag {}", typeflag as char);
        assert_eq!(listing.entries[1].skip, None);
        assert_eq!(listing.totals.skipped, 1);
    }
}

#[test]
fn tar_sparse_unsupported() {
    let listing = list(TarBuilder::default().entry("sparse.img", b'S', b"").finish()).unwrap();
    assert_eq!(
        listing.entries[0].skip,
        Some(SkipReason::Unsupported("Sparse file".into()))
    );
}

#[test]
fn tar_pax_header_over_1_mib_refused() {
    let tar = TarBuilder::default()
        .raw(&tar_header(b"./PaxHeaders/x", b'x', &octal(1024 * 1024 + 1, 12), true))
        .raw(&vec![0u8; 1024 * 1024 + 512])
        .finish();
    assert_eq!(list(tar), Err(ArchiveRefusal::Damaged));
    // Exactly 1 MiB is a valid (if odd) pax header.
    let body_len = 1024 * 1024;
    let filler = "a".repeat(body_len - 20);
    let tar = TarBuilder::default()
        .pax(&[("comment", &filler)])
        .file("x", b"")
        .finish();
    assert!(list(tar).is_ok());
}

#[test]
fn tar_truncated_is_truncated() {
    let tar = TarBuilder::default()
        .file("a.txt", &[7u8; 2000])
        .file("b.txt", b"b")
        .finish();
    // Cut inside a.txt's data, and inside b.txt's header.
    assert_eq!(list(tar[..1500].to_vec()), Err(ArchiveRefusal::Truncated));
    assert_eq!(list(tar[..2560 + 100].to_vec()), Err(ArchiveRefusal::Truncated));
}

#[test]
fn tar_header_hopping_reads_only_header_ranges() {
    let big = vec![0x5Au8; 8 * 1024 * 1024];
    let tar = TarBuilder::default()
        .file("one.bin", &big)
        .file("two.bin", &big)
        .file("three.bin", &big)
        .finish();
    let mut session = ArchiveSession::open(Recording::new(tar), ArchivePlatform::Native);
    let step = drive(&mut session, |_, range| panic!("asked for {range:?}"));
    assert_eq!(step, beebeeb_core::archives::SessionStep::Listed);
    assert_eq!(session.listing().unwrap().entries.len(), 3);
    let read = session.source_mut().bytes_read();
    assert!(read < 4096, "listing read {read} bytes");
}

#[test]
fn tar_entry_count_over_cap_refused() {
    let mut over = TarBuilder::default();
    for i in 0..100_000 {
        over.file(&format!("f{i}"), b"");
    }
    let at_cap = over.clone_bytes_with_end();
    over.file("one-too-many", b"");
    assert_eq!(list(over.finish()), Err(ArchiveRefusal::TooMany));
    assert_eq!(list(at_cap).unwrap().entries.len(), 100_000);
}

#[test]
fn tgz_detected_by_inner_header() {
    let tgz = gzip(&sample_tar());
    let len = tgz.len() as u64;
    let listing = list(tgz).unwrap();
    assert_eq!(listing.format, ArchiveFormat::TarGzip);
    assert!(listing.complete);
    assert_eq!(paths(&listing).len(), 3);
    // The whole stream is compressed: its size is the compressed total.
    assert_eq!(listing.totals.compressed_bytes, len);
}

#[test]
fn gz_single_file_listing() {
    let listing = list(gzip_named("notes.txt", b"hello world")).unwrap();
    assert_eq!(listing.format, ArchiveFormat::Gzip);
    assert!(listing.complete);
    assert_eq!(paths(&listing), vec![("notes.txt".into(), EntryKind::File, 11)]);
    assert_eq!(
        listing.entries[0].modified,
        Some(ArchiveTime::Utc {
            unix_ms: 1_700_000_000_000
        })
    );
}

#[test]
fn gz_multi_member() {
    let bytes = [gzip(b"hello "), gzip(b"world")].concat();
    let mut session = ArchiveSession::open(Blocking(bytes), ArchivePlatform::Native);
    assert_eq!(
        drive(&mut session, |_, r| panic!("{r:?}")),
        beebeeb_core::archives::SessionStep::Listed
    );
    assert_eq!(session.listing().unwrap().entries[0].size, 11);
    assert_eq!(
        read_entry(&mut session, 0),
        (b"hello world".to_vec(), PieceStep::Verified)
    );
}

#[test]
fn gz_truncated_is_truncated() {
    let bytes = gzip_named("notes.txt", &[b'z'; 5000]);
    assert_eq!(list(bytes[..bytes.len() - 4].to_vec()), Err(ArchiveRefusal::Truncated));
    assert_eq!(list(bytes[..12].to_vec()), Err(ArchiveRefusal::Truncated));
}

#[test]
fn tgz_scan_limit_marks_incomplete() {
    // The mobile app scans 256 MiB of a tgz; this one holds 300 MiB, as
    // three gzip members: the headers before the big entry, its zeros, and
    // the rest.
    let big_len = 300u64 * 1024 * 1024;
    let mut head = TarBuilder::default();
    head.file("first.txt", b"first")
        .raw(&tar_header(b"big.bin", b'0', &octal(big_len, 12), true));
    let tgz = [
        gzip(&head.finish_without_end()),
        gzip_zeros_member(big_len),
        gzip(&TarBuilder::default().file("after.txt", b"after").finish()),
    ]
    .concat();
    let listing = list_on(tgz.clone(), ArchivePlatform::MobileApp).unwrap();
    assert!(!listing.complete);
    let names: Vec<_> = listing.entries.iter().map(|e| e.display_path.as_str()).collect();
    assert_eq!(names, vec!["first.txt", "big.bin"]);
    // Below the limit the same builder lists everything (the fixture is a
    // valid tgz, so the cut above is the limit's).
    let small = [
        gzip(&head.finish_without_end_again(5)),
        gzip_zeros_member(512), // 5 data bytes and their padding
        gzip(&TarBuilder::default().file("after.txt", b"after").finish()),
    ]
    .concat();
    let complete = list_on(small, ArchivePlatform::MobileApp).unwrap();
    assert!(complete.complete);
    assert_eq!(complete.entries.len(), 3);
}

#[test]
fn tar_entry_stream_verified() {
    let mut session = ArchiveSession::open(Blocking(sample_tar()), ArchivePlatform::Native);
    drive(&mut session, |_, r| panic!("{r:?}"));
    assert_eq!(read_entry(&mut session, 2), (b"abc".to_vec(), PieceStep::Verified));
    assert_eq!(read_entry(&mut session, 0), (b"hello".to_vec(), PieceStep::Verified));
    // The same entry inside gzip, and a 200 KiB entry in pieces.
    let big: Vec<u8> = (0..200 * 1024).map(|i| (i % 251) as u8).collect();
    let tgz = gzip(
        &TarBuilder::default()
            .file("a.txt", b"hello")
            .file("big.bin", &big)
            .finish(),
    );
    let mut session = ArchiveSession::open(Blocking(tgz), ArchivePlatform::Native);
    drive(&mut session, |_, r| panic!("{r:?}"));
    assert_eq!(read_entry(&mut session, 1), (big, PieceStep::Verified));
}

#[test]
fn chaos_source_tar_listing_equal() {
    let long = format!("{}/x.txt", "p".repeat(150));
    let mut builder = TarBuilder::default();
    builder
        .pax(&[("path", &long)])
        .file("ignored", b"pax")
        .gnu_long(&"g".repeat(300))
        .file("t", b"gnu");
    for i in 0..40 {
        builder.file(&format!("dir{}/f{i}.bin", i % 3), &vec![i as u8; 700 * i]);
    }
    let tar = builder.finish();
    for bytes in [tar.clone(), gzip(&tar)] {
        let expected = list(bytes.clone()).unwrap();
        let (chaotic, pendings) = list_chaos(bytes, 7);
        assert!(pendings > 0, "the chaos source never said Pending");
        assert_eq!(chaotic.unwrap(), expected);
    }
}

trait FinishExt {
    fn finish_without_end(&mut self) -> Vec<u8>;
    fn finish_without_end_again(&mut self, big_len: u64) -> Vec<u8>;
    fn clone_bytes_with_end(&mut self) -> Vec<u8>;
}

impl FinishExt for TarBuilder {
    fn finish_without_end(&mut self) -> Vec<u8> {
        let mut bytes = self.finish();
        bytes.truncate(bytes.len() - 1024);
        bytes
    }

    fn finish_without_end_again(&mut self, big_len: u64) -> Vec<u8> {
        let mut head = TarBuilder::default();
        head.file("first.txt", b"first")
            .raw(&tar_header(b"big.bin", b'0', &octal(big_len, 12), true));
        head.finish_without_end()
    }

    fn clone_bytes_with_end(&mut self) -> Vec<u8> {
        let bytes = self.finish();
        self.raw(&bytes[..bytes.len() - 1024]);
        bytes
    }
}

/// A GNU base-256 mtime of 2^62 seconds fits an i64 but not as
/// milliseconds: the entry lists with no time, and nothing overflows
/// (review finding).
#[test]
fn tar_huge_base256_mtime_lists_without_a_time() {
    let mut h = tar_header(b"old.txt", b'0', &octal(2, 12), true);
    h[136..148].copy_from_slice(&[0x80, 0, 0, 0, 0x40, 0, 0, 0, 0, 0, 0, 0]);
    seal_checksum(&mut h);
    let mut tar = TarBuilder::default();
    tar.raw(&h).raw(&{
        let mut block = [0u8; 512];
        block[..2].copy_from_slice(b"ok");
        block
    });
    let listing = list(tar.finish()).expect("lists");
    assert_eq!(listing.entries[0].display_path, "old.txt");
    assert_eq!(listing.entries[0].modified, None);
}
