use std::io::{Cursor, Read};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use beebeeb_core::CoreError;
use beebeeb_core::chunk_stream::ExpectedChunkFormat;
use beebeeb_core::encrypt::encrypt_chunk_raw;
use beebeeb_core::kdf::{MasterKey, derive_file_key};
use beebeeb_core::zip::{ZipEntry, ZipProgress, stream_folder_zip};

fn test_master_key() -> MasterKey {
    MasterKey::from_bytes([1u8; 32])
}

/// Helper: encrypt plaintext chunks for a given file_id, returning the encrypted blobs.
fn encrypt_chunks(master_key: &MasterKey, file_id: &str, chunks: &[&[u8]]) -> Vec<Vec<u8>> {
    let file_key = derive_file_key(master_key, file_id.as_bytes());
    chunks
        .iter()
        .map(|chunk| encrypt_chunk_raw(&file_key, chunk).unwrap())
        .collect()
}

#[test]
fn single_file_roundtrip() {
    let mk = test_master_key();
    let plaintext = b"hello beebeeb zip";
    let file_id = "file-001";
    let encrypted_chunks = encrypt_chunks(&mk, file_id, &[plaintext.as_slice()]);

    let entries = vec![ZipEntry {
        path: "greeting.txt".to_string(),
        file_id: file_id.to_string(),
        chunk_count: 1,
        size_bytes: plaintext.len() as u64,
        chunk_format: ExpectedChunkFormat::Unrecorded,
    }];

    let cancel = AtomicBool::new(false);
    let mut buf = Vec::new();

    let chunks_clone = encrypted_chunks.clone();
    let mut fetch = |_fid: &str, idx: u32| -> Result<Vec<u8>, CoreError> { Ok(chunks_clone[idx as usize].clone()) };

    let mk2 = test_master_key();
    stream_folder_zip(&mk2, &entries, &mut fetch, Cursor::new(&mut buf), &|_| {}, &cancel).unwrap();

    // Verify the zip contents
    let reader = Cursor::new(&buf);
    let mut archive = zip::ZipArchive::new(reader).unwrap();
    assert_eq!(archive.len(), 1);

    let mut file = archive.by_name("greeting.txt").unwrap();
    let mut contents = Vec::new();
    file.read_to_end(&mut contents).unwrap();
    assert_eq!(contents, plaintext);
}

#[test]
fn multi_file_with_nested_paths() {
    let mk = test_master_key();

    let file_a_content = b"file A content";
    let file_b_content = b"file B in subfolder";
    let file_c_content = b"deeply nested file C";

    let enc_a = encrypt_chunks(&mk, "file-a", &[file_a_content.as_slice()]);
    let enc_b = encrypt_chunks(&mk, "file-b", &[file_b_content.as_slice()]);
    let enc_c = encrypt_chunks(&mk, "file-c", &[file_c_content.as_slice()]);

    let entries = vec![
        ZipEntry {
            path: "root.txt".to_string(),
            file_id: "file-a".to_string(),
            chunk_count: 1,
            size_bytes: file_a_content.len() as u64,
            chunk_format: ExpectedChunkFormat::Unrecorded,
        },
        ZipEntry {
            path: "docs/readme.txt".to_string(),
            file_id: "file-b".to_string(),
            chunk_count: 1,
            size_bytes: file_b_content.len() as u64,
            chunk_format: ExpectedChunkFormat::Unrecorded,
        },
        ZipEntry {
            path: "docs/deep/nested.txt".to_string(),
            file_id: "file-c".to_string(),
            chunk_count: 1,
            size_bytes: file_c_content.len() as u64,
            chunk_format: ExpectedChunkFormat::Unrecorded,
        },
    ];

    let all_chunks: std::collections::HashMap<String, Vec<Vec<u8>>> = [
        ("file-a".to_string(), enc_a),
        ("file-b".to_string(), enc_b),
        ("file-c".to_string(), enc_c),
    ]
    .into_iter()
    .collect();

    let mut buf = Vec::new();
    let cancel = AtomicBool::new(false);

    let mut fetch = |fid: &str, idx: u32| -> Result<Vec<u8>, CoreError> { Ok(all_chunks[fid][idx as usize].clone()) };

    let mk2 = test_master_key();
    stream_folder_zip(&mk2, &entries, &mut fetch, Cursor::new(&mut buf), &|_| {}, &cancel).unwrap();

    let reader = Cursor::new(&buf);
    let mut archive = zip::ZipArchive::new(reader).unwrap();
    assert_eq!(archive.len(), 3);

    let mut read_entry = |name: &str| -> Vec<u8> {
        let mut file = archive.by_name(name).unwrap();
        let mut contents = Vec::new();
        file.read_to_end(&mut contents).unwrap();
        contents
    };

    assert_eq!(read_entry("root.txt"), file_a_content);
    assert_eq!(read_entry("docs/readme.txt"), file_b_content);
    assert_eq!(read_entry("docs/deep/nested.txt"), file_c_content);
}

#[test]
fn cancellation_returns_cancelled() {
    let mk = test_master_key();
    let plaintext = b"data";
    let enc = encrypt_chunks(&mk, "file-x", &[plaintext.as_slice()]);

    let entries = vec![ZipEntry {
        path: "file.txt".to_string(),
        file_id: "file-x".to_string(),
        chunk_count: 1,
        size_bytes: plaintext.len() as u64,
        chunk_format: ExpectedChunkFormat::Unrecorded,
    }];

    let cancel = AtomicBool::new(true); // cancelled before start
    let mut buf = Vec::new();

    let mut fetch = |_fid: &str, idx: u32| -> Result<Vec<u8>, CoreError> { Ok(enc[idx as usize].clone()) };

    let mk2 = test_master_key();
    let result = stream_folder_zip(&mk2, &entries, &mut fetch, Cursor::new(&mut buf), &|_| {}, &cancel);

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(matches!(err, CoreError::Cancelled), "expected Cancelled, got: {err:?}");
}

#[test]
fn cancellation_mid_chunks() {
    let mk = test_master_key();
    let chunk_data = b"chunk content here";
    let enc = encrypt_chunks(
        &mk,
        "file-mid",
        &[chunk_data.as_slice(), chunk_data.as_slice(), chunk_data.as_slice()],
    );

    let entries = vec![ZipEntry {
        path: "big.bin".to_string(),
        file_id: "file-mid".to_string(),
        chunk_count: 3,
        size_bytes: (chunk_data.len() * 3) as u64,
        chunk_format: ExpectedChunkFormat::Unrecorded,
    }];

    let cancel = AtomicBool::new(false);
    let mut buf = Vec::new();
    let fetch_count = Mutex::new(0u32);

    let mut fetch = |_fid: &str, idx: u32| -> Result<Vec<u8>, CoreError> {
        let mut count = fetch_count.lock().unwrap();
        *count += 1;
        if *count >= 2 {
            cancel.store(true, Ordering::Relaxed);
        }
        Ok(enc[idx as usize].clone())
    };

    let mk2 = test_master_key();
    let result = stream_folder_zip(&mk2, &entries, &mut fetch, Cursor::new(&mut buf), &|_| {}, &cancel);

    assert!(matches!(result, Err(CoreError::Cancelled)));
}

#[test]
fn progress_callback_fires() {
    let mk = test_master_key();
    let chunk1 = b"first chunk";
    let chunk2 = b"second chunk";
    let enc = encrypt_chunks(&mk, "file-prog", &[chunk1.as_slice(), chunk2.as_slice()]);

    let entries = vec![ZipEntry {
        path: "progress.txt".to_string(),
        file_id: "file-prog".to_string(),
        chunk_count: 2,
        size_bytes: (chunk1.len() + chunk2.len()) as u64,
        chunk_format: ExpectedChunkFormat::Unrecorded,
    }];

    let cancel = AtomicBool::new(false);
    let mut buf = Vec::new();
    let progress_reports: Mutex<Vec<(u64, u64, usize, String)>> = Mutex::new(Vec::new());

    let mut fetch = |_fid: &str, idx: u32| -> Result<Vec<u8>, CoreError> { Ok(enc[idx as usize].clone()) };

    let mk2 = test_master_key();
    stream_folder_zip(
        &mk2,
        &entries,
        &mut fetch,
        Cursor::new(&mut buf),
        &|p: &ZipProgress| {
            progress_reports
                .lock()
                .unwrap()
                .push((p.bytes_done, p.bytes_total, p.file_index, p.current_file.clone()));
        },
        &cancel,
    )
    .unwrap();

    let reports = progress_reports.lock().unwrap();
    assert_eq!(reports.len(), 2, "should fire once per chunk");

    // All reports should reference file_index 0 (only one file)
    for r in reports.iter() {
        assert_eq!(r.2, 0);
        assert_eq!(r.3, "progress.txt");
    }

    // bytes_done should be monotonically increasing
    assert!(reports[1].0 > reports[0].0);

    // bytes_total should be consistent
    assert_eq!(reports[0].1, reports[1].1);
}

#[test]
fn empty_file_produces_valid_zip_entry() {
    let mk = test_master_key();
    let enc = encrypt_chunks(&mk, "file-empty", &[b"".as_slice()]);

    let entries = vec![ZipEntry {
        path: "empty.txt".to_string(),
        file_id: "file-empty".to_string(),
        chunk_count: 1,
        size_bytes: 0,
        chunk_format: ExpectedChunkFormat::Unrecorded,
    }];

    let cancel = AtomicBool::new(false);
    let mut buf = Vec::new();

    let mut fetch = |_fid: &str, idx: u32| -> Result<Vec<u8>, CoreError> { Ok(enc[idx as usize].clone()) };

    let mk2 = test_master_key();
    stream_folder_zip(&mk2, &entries, &mut fetch, Cursor::new(&mut buf), &|_| {}, &cancel).unwrap();

    let reader = Cursor::new(&buf);
    let mut archive = zip::ZipArchive::new(reader).unwrap();
    assert_eq!(archive.len(), 1);

    let mut file = archive.by_name("empty.txt").unwrap();
    let mut contents = Vec::new();
    file.read_to_end(&mut contents).unwrap();
    assert!(contents.is_empty(), "empty file should have empty content");
}

/// Deterministic bytes that do not compress (xorshift64*), so a DEFLATE stream has to store them.
fn incompressible(len: usize, seed: u64) -> Vec<u8> {
    let mut state = seed;
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        out.extend_from_slice(&state.wrapping_mul(0x2545_F491_4F6C_DD1D).to_le_bytes());
    }
    out.truncate(len);
    out
}

/// The entries of [`mixed_payloads_roundtrip`]: several chunks per file, incompressible and compressible, an empty
/// file, nested paths. LD-0144: zip 9 reuses its DEFLATE compressor across entries, which the six other tests, with
/// payloads of a few bytes, cannot show. Core's writer has one compression level, so this does not cover a switch
/// between levels (where that cache is reset).
fn mixed_payloads() -> Vec<(&'static str, Vec<Vec<u8>>)> {
    let text: Vec<u8> = b"the quick brown fox jumps over the lazy dog\n"
        .iter()
        .copied()
        .cycle()
        .take(64 * 1024)
        .collect();
    vec![
        (
            "a/random.bin",
            vec![
                incompressible(64 * 1024, 1),
                incompressible(64 * 1024, 2),
                incompressible(5_000, 3),
            ],
        ),
        ("a/text.txt", vec![text.clone(), text.clone()]),
        ("empty.bin", vec![Vec::new()]),
        ("b/c/random2.bin", vec![incompressible(200 * 1024, 4)]),
        ("b/after-incompressible.txt", vec![text]),
    ]
}

#[test]
fn mixed_payloads_roundtrip() {
    let mk = test_master_key();
    let files = mixed_payloads();

    let mut entries = Vec::new();
    let mut chunks = std::collections::HashMap::new();
    for (i, (path, parts)) in files.iter().enumerate() {
        let file_id = format!("mixed-{i}");
        let refs: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
        chunks.insert(file_id.clone(), encrypt_chunks(&mk, &file_id, &refs));
        entries.push(ZipEntry {
            path: (*path).to_string(),
            file_id,
            chunk_count: parts.len() as u32,
            size_bytes: parts.iter().map(|p| p.len() as u64).sum(),
            chunk_format: ExpectedChunkFormat::Unrecorded,
        });
    }

    let mut buf = Vec::new();
    let cancel = AtomicBool::new(false);
    let mut fetch = |fid: &str, idx: u32| -> Result<Vec<u8>, CoreError> { Ok(chunks[fid][idx as usize].clone()) };
    stream_folder_zip(&mk, &entries, &mut fetch, Cursor::new(&mut buf), &|_| {}, &cancel).unwrap();

    let mut archive = zip::ZipArchive::new(Cursor::new(&buf)).unwrap();
    assert_eq!(archive.len(), files.len());
    for (path, parts) in &files {
        let want: Vec<u8> = parts.concat();
        let mut file = archive.by_name(path).unwrap();
        assert_eq!(file.size(), want.len() as u64, "{path}: declared size");
        assert!(!file.is_dir(), "{path}: a file, not a directory");
        let mut got = Vec::new();
        // The reader checks the entry's CRC-32 when it reaches the end, so a corrupt stream fails here.
        file.read_to_end(&mut got).unwrap();
        assert!(got == want, "{path}: {} bytes read, {} written", got.len(), want.len());
    }
}

// ---------------------------------------------------------------------------------------------------------------
// LD-0146: large entries, an unfinished archive, duplicate names, progress units.
// ---------------------------------------------------------------------------------------------------------------

/// The only place these tests build a `ZipEntry`, so a new field is one edit.
fn entry_for(path: &str, file_id: &str, chunk_count: u32, size_bytes: u64) -> ZipEntry {
    ZipEntry {
        path: path.to_string(),
        file_id: file_id.to_string(),
        chunk_count,
        size_bytes,
        chunk_format: ExpectedChunkFormat::Unrecorded,
    }
}

/// A source of encrypted chunks, `file_id` -> frames, for [`stream_folder_zip`]'s `fetch_chunk`.
type Source = std::collections::HashMap<String, Vec<Vec<u8>>>;

fn fetch_from(source: &Source) -> impl FnMut(&str, u32) -> Result<Vec<u8>, CoreError> + '_ {
    move |fid, idx| Ok(source[fid][idx as usize].clone())
}

/// A text payload that is the same on every run and has no zip signature in it.
fn text_chunk(label: &str, len: usize) -> Vec<u8> {
    format!("{label} line of text\n")
        .into_bytes()
        .into_iter()
        .cycle()
        .take(len)
        .collect()
}

/// Item 1: an entry past the 4 GiB ZIP64 threshold. The source is one 64 MiB frame of zeros that the mock reader
/// serves 65 times (a v1 frame carries no position, so the decryptor takes the same frame again); DEFLATE shrinks
/// the zeros, so the 4 GiB archive is a few MiB in memory and nothing large touches the disk.
///
/// It decrypts 4 GiB. On aarch64 `aes` 0.8 and `polyval` use their software backends (their ARMv8 backends need
/// `--cfg aes_armv8` / `--cfg polyval_armv8`, which nothing in this repo sets), so there it takes minutes: run it with
/// `cargo test -p beebeeb-core --test zip_tests -- --ignored`. On x86_64 (CI, the Legion) it runs with the suite.
#[test]
#[cfg_attr(
    target_arch = "aarch64",
    ignore = "decrypts 4 GiB with software AES-GCM on aarch64 (minutes); run with --ignored"
)]
fn entry_above_4_gib_completes_as_zip64() {
    const CHUNK: usize = 64 * 1024 * 1024;
    const CHUNKS: u32 = 65;
    let mk = test_master_key();
    let frame = encrypt_chunks(&mk, "big-file", &[vec![0u8; CHUNK].as_slice()]).remove(0);
    let size = CHUNK as u64 * u64::from(CHUNKS);
    assert!(size > u64::from(u32::MAX), "the fixture must pass the ZIP64 threshold");

    let entries = vec![entry_for("big.bin", "big-file", CHUNKS, size)];
    let mut fetch = |_: &str, _: u32| -> Result<Vec<u8>, CoreError> { Ok(frame.clone()) };
    let mut buf = Vec::new();
    let result = stream_folder_zip(
        &mk,
        &entries,
        &mut fetch,
        Cursor::new(&mut buf),
        &|_| {},
        &AtomicBool::new(false),
    );
    assert!(result.is_ok(), "a 4 GiB entry must complete, got: {result:?}");

    let mut archive = zip::ZipArchive::new(Cursor::new(&buf)).unwrap();
    assert_eq!(archive.len(), 1);
    let mut file = archive.by_index(0).unwrap();
    assert_eq!(file.size(), size, "declared size");
    // The reader checks the CRC-32 when it reaches the end of the entry.
    let read = std::io::copy(&mut file, &mut std::io::sink()).unwrap();
    assert_eq!(read, size, "bytes read back");
}

/// The `version needed to extract` of a five-byte entry whose `size_bytes` says `declared`: 45 is ZIP64, 20 is the
/// plain layout every reader opens.
fn version_needed_when_declared(declared: u64) -> u16 {
    let mk = test_master_key();
    let mut source = Source::new();
    source.insert("tiny".into(), encrypt_chunks(&mk, "tiny", &[b"tiny!".as_slice()]));
    let entries = vec![entry_for("tiny.bin", "tiny", 1, declared)];
    let mut fetch = fetch_from(&source);
    let mut buf = Vec::new();
    stream_folder_zip(
        &mk,
        &entries,
        &mut fetch,
        Cursor::new(&mut buf),
        &|_| {},
        &AtomicBool::new(false),
    )
    .unwrap();
    let mut archive = zip::ZipArchive::new(Cursor::new(&buf)).unwrap();
    let file = archive.by_index(0).unwrap();
    file.version_needed()
}

/// Item 1, fast: the layout follows the entry's declared size. From 3 GiB it is ZIP64 (the 1 GiB below `u32::MAX`
/// is the margin for DEFLATE growth and a size that is only the server's word); below it nothing changes, so the
/// archives of everyday folders stay readable by every tool.
#[test]
fn zip64_is_chosen_from_three_gib_declared() {
    const THREE_GIB: u64 = 3 << 30;
    assert_eq!(version_needed_when_declared(0), 20, "an empty declaration");
    assert_eq!(version_needed_when_declared(THREE_GIB - 1), 20, "just below 3 GiB");
    assert_eq!(version_needed_when_declared(THREE_GIB), 45, "3 GiB");
    assert_eq!(version_needed_when_declared(u64::from(u32::MAX) + 1), 45, "4 GiB");
}

/// What a reader must refuse: output that stopped before the archive was finished.
fn assert_unfinished(buf: &[u8], what: &str) {
    assert!(
        !buf.is_empty(),
        "{what}: the fixture wrote nothing, so it proves nothing"
    );
    assert!(
        zip::ZipArchive::new(Cursor::new(buf)).is_err(),
        "{what}: a reader accepts the {}-byte output as a complete archive",
        buf.len()
    );
    for (record, signature) in [
        ("end of central directory", b"PK\x05\x06"),
        ("central directory header", b"PK\x01\x02"),
    ] {
        assert!(
            !buf.windows(4).any(|w| w == signature),
            "{what}: the output holds a {record} record"
        );
    }
}

/// Two entries: `first.txt` (one chunk of 4,000 bytes) and `second.txt` (three chunks of 3,000), each declaring the
/// size in `declared`.
fn two_entries_declared(declared: [u64; 2]) -> (MasterKey, Vec<ZipEntry>, Source) {
    let mk = test_master_key();
    let first = text_chunk("first", 4_000);
    let parts: Vec<Vec<u8>> = (0..3).map(|i| text_chunk(&format!("second {i}"), 3_000)).collect();
    let part_refs: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
    let mut source = Source::new();
    source.insert("f1".into(), encrypt_chunks(&mk, "f1", &[first.as_slice()]));
    source.insert("f2".into(), encrypt_chunks(&mk, "f2", &part_refs));
    let entries = vec![
        entry_for("first.txt", "f1", 1, declared[0]),
        entry_for("second.txt", "f2", 3, declared[1]),
    ];
    (mk, entries, source)
}

fn two_entries() -> (MasterKey, Vec<ZipEntry>, Source) {
    two_entries_declared([4_000, 9_000])
}

/// Item 2: cancelled in the middle of an entry.
#[test]
fn cancel_mid_entry_leaves_no_readable_archive() {
    let (mk, entries, source) = two_entries();
    let cancel = AtomicBool::new(false);
    let mut inner = fetch_from(&source);
    let mut fetched = 0;
    let mut fetch = |fid: &str, idx: u32| {
        fetched += 1;
        if fetched == 3 {
            cancel.store(true, Ordering::Relaxed); // the second chunk of `second.txt`
        }
        inner(fid, idx)
    };
    let mut buf = Vec::new();
    let result = stream_folder_zip(&mk, &entries, &mut fetch, Cursor::new(&mut buf), &|_| {}, &cancel);
    assert!(matches!(result, Err(CoreError::Cancelled)), "got {result:?}");
    assert_unfinished(&buf, "cancel mid-entry");
}

/// Item 2: cancelled between two entries, after the first one was complete.
#[test]
fn cancel_between_entries_leaves_no_readable_archive() {
    let (mk, entries, source) = two_entries();
    let cancel = AtomicBool::new(false);
    let mut fetch = fetch_from(&source);
    let mut buf = Vec::new();
    let on_progress = |p: &ZipProgress| {
        if p.file_index == 0 {
            cancel.store(true, Ordering::Relaxed);
        }
    };
    let result = stream_folder_zip(&mk, &entries, &mut fetch, Cursor::new(&mut buf), &on_progress, &cancel);
    assert!(matches!(result, Err(CoreError::Cancelled)), "got {result:?}");
    assert_unfinished(&buf, "cancel between entries");
}

/// Item 2: the download of a chunk fails.
#[test]
fn fetch_error_leaves_no_readable_archive() {
    let (mk, entries, source) = two_entries();
    let mut inner = fetch_from(&source);
    let mut fetch = |fid: &str, idx: u32| {
        if fid == "f2" && idx == 1 {
            return Err(CoreError::Io("connection reset".into()));
        }
        inner(fid, idx)
    };
    let mut buf = Vec::new();
    let result = stream_folder_zip(
        &mk,
        &entries,
        &mut fetch,
        Cursor::new(&mut buf),
        &|_| {},
        &AtomicBool::new(false),
    );
    assert!(matches!(result, Err(CoreError::Io(_))), "got {result:?}");
    assert_unfinished(&buf, "fetch error");
}

/// Item 2: a chunk that does not authenticate.
#[test]
fn corrupt_chunk_leaves_no_readable_archive() {
    let (mk, entries, mut source) = two_entries();
    let frame = &mut source.get_mut("f2").unwrap()[1];
    let last = frame.len() - 1;
    frame[last] ^= 0x01;
    let mut fetch = fetch_from(&source);
    let mut buf = Vec::new();
    let result = stream_folder_zip(
        &mk,
        &entries,
        &mut fetch,
        Cursor::new(&mut buf),
        &|_| {},
        &AtomicBool::new(false),
    );
    assert!(result.is_err(), "a corrupt chunk must fail the archive");
    assert_unfinished(&buf, "corrupt chunk");
}

/// Item 2: a panic in the caller's callback unwinds through the writer, which must not finish the archive either.
#[test]
fn panic_in_progress_callback_leaves_no_readable_archive() {
    let (mk, entries, source) = two_entries();
    let mut fetch = fetch_from(&source);
    let mut buf = Vec::new();
    let on_progress = |p: &ZipProgress| {
        if p.file_index == 1 {
            panic!("progress callback failed");
        }
    };
    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = stream_folder_zip(
            &mk,
            &entries,
            &mut fetch,
            Cursor::new(&mut buf),
            &on_progress,
            &AtomicBool::new(false),
        );
    }));
    assert!(unwound.is_err(), "the fixture must panic");
    assert_unfinished(&buf, "panic in the progress callback");
}

/// Item 4 relies on this: a zero-chunk entry never reaches a finished archive (`ChunkDecryptor::finish` errors when
/// no frame was pushed), so the progress total is only ever corrected from an entry's last chunk.
#[test]
fn zero_chunk_entry_fails_the_archive() {
    let (mk, mut entries, source) = two_entries();
    entries.push(entry_for("none.bin", "f1", 0, 28));
    let mut fetch = fetch_from(&source);
    let mut buf = Vec::new();
    let result = stream_folder_zip(
        &mk,
        &entries,
        &mut fetch,
        Cursor::new(&mut buf),
        &|_| {},
        &AtomicBool::new(false),
    );
    assert!(
        result.is_err(),
        "a zero-chunk entry must fail the archive, got {result:?}"
    );
    assert_unfinished(&buf, "zero-chunk entry");
}

/// The names of the archive made from entries at `paths`, in order; every entry reads the same one-chunk file.
fn archive_names(paths: &[&str]) -> Vec<String> {
    let mk = test_master_key();
    let mut source = Source::new();
    source.insert("same".into(), encrypt_chunks(&mk, "same", &[b"same bytes".as_slice()]));
    let entries: Vec<ZipEntry> = paths.iter().map(|p| entry_for(p, "same", 1, 10)).collect();
    let mut fetch = fetch_from(&source);
    let mut buf = Vec::new();
    stream_folder_zip(
        &mk,
        &entries,
        &mut fetch,
        Cursor::new(&mut buf),
        &|_| {},
        &AtomicBool::new(false),
    )
    .unwrap();
    let archive = zip::ZipArchive::new(Cursor::new(&buf)).unwrap();
    archive.file_names().map(|name| name.unwrap().into_owned()).collect()
}

/// Item 3: two entries with the same decrypted path both land; the second is renamed like the cli renames a
/// duplicate (`scan (2).pdf`), and each name keeps its own bytes.
#[test]
fn duplicate_names_are_renamed_and_both_land() {
    let mk = test_master_key();
    let (a, b) = (text_chunk("copy A", 500), text_chunk("copy B", 700));
    let mut source = Source::new();
    source.insert("fa".into(), encrypt_chunks(&mk, "fa", &[a.as_slice()]));
    source.insert("fb".into(), encrypt_chunks(&mk, "fb", &[b.as_slice()]));
    let entries = vec![
        entry_for("docs/scan.pdf", "fa", 1, 500),
        entry_for("docs/scan.pdf", "fb", 1, 700),
    ];
    let mut fetch = fetch_from(&source);
    let mut buf = Vec::new();
    stream_folder_zip(
        &mk,
        &entries,
        &mut fetch,
        Cursor::new(&mut buf),
        &|_| {},
        &AtomicBool::new(false),
    )
    .expect("a duplicate name must not abort the archive");

    let mut archive = zip::ZipArchive::new(Cursor::new(&buf)).unwrap();
    assert_eq!(archive.len(), 2);
    for (name, want) in [("docs/scan.pdf", &a), ("docs/scan (2).pdf", &b)] {
        let mut got = Vec::new();
        archive.by_name(name).unwrap().read_to_end(&mut got).unwrap();
        assert!(&got == want, "{name}: wrong bytes");
    }
}

/// Item 3: the rules around the rename. Names compare as a case- and normalisation-insensitive drive would show
/// them (macOS and Windows extract that way); a name an entry already has is never taken by a rename; the suffix
/// goes before the extension of the last path component only; a leading dot is not an extension.
#[test]
fn duplicate_name_rules() {
    let names = archive_names(&[
        "docs/scan.pdf",
        "docs/scan.pdf", // (3): "docs/scan (2).pdf" is another entry's own name
        "docs/scan (2).pdf",
        "DOCS/Scan.PDF", // the same file on a case-insensitive drive
        "v1.2/README",   // a dot in the folder is not an extension
        "v1.2/README",
        ".env",
        ".env",
        "caf\u{e9}.txt",
        "cafe\u{301}.txt", // the same name, decomposed
    ]);
    assert_eq!(
        names,
        [
            "docs/scan.pdf",
            "docs/scan (3).pdf",
            "docs/scan (2).pdf",
            "DOCS/Scan (4).PDF",
            "v1.2/README",
            "v1.2/README (2)",
            ".env",
            ".env (2)",
            "caf\u{e9}.txt",
            "cafe\u{301} (2).txt",
        ]
    );
}

/// Item 4: the last progress event is 100% and none is above it, whichever unit the uploader declared `size_bytes` in.
/// The server accepts either (`complete.rs`): the web declares the plaintext size, the cli the encrypted one
/// (plaintext + 28 bytes per chunk). Here `first.txt` has 1 chunk and `second.txt` 3, so 4,028 and 9,084 encrypted.
#[test]
fn progress_ends_at_exactly_the_total() {
    for (convention, declared) in [
        ("plaintext sizes (web)", [4_000, 9_000]),
        ("encrypted sizes (cli)", [4_028, 9_084]),
        ("web file, then cli file", [4_000, 9_084]),
        ("cli file, then web file", [4_028, 9_000]),
    ] {
        let (mk, entries, source) = two_entries_declared(declared);
        let mut fetch = fetch_from(&source);
        let mut buf = Vec::new();
        let events: Mutex<Vec<(u64, u64)>> = Mutex::new(Vec::new());
        let on_progress = |p: &ZipProgress| events.lock().unwrap().push((p.bytes_done, p.bytes_total));
        stream_folder_zip(
            &mk,
            &entries,
            &mut fetch,
            Cursor::new(&mut buf),
            &on_progress,
            &AtomicBool::new(false),
        )
        .unwrap();

        let events = events.into_inner().unwrap();
        assert_eq!(events.len(), 4, "{convention}: one event per chunk");
        assert!(
            events.iter().all(|(done, total)| done <= total),
            "{convention}: an event is above 100%: {events:?}"
        );
        assert!(
            events.windows(2).all(|w| w[0].0 < w[1].0),
            "{convention}: bytes_done does not grow: {events:?}"
        );
        assert_eq!(
            events.last(),
            Some(&(13_000, 13_000)),
            "{convention}: events {events:?}"
        );
    }
}
