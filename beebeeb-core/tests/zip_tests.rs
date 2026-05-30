use std::io::{Cursor, Read};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use beebeeb_core::CoreError;
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
        },
        ZipEntry {
            path: "docs/readme.txt".to_string(),
            file_id: "file-b".to_string(),
            chunk_count: 1,
            size_bytes: file_b_content.len() as u64,
        },
        ZipEntry {
            path: "docs/deep/nested.txt".to_string(),
            file_id: "file-c".to_string(),
            chunk_count: 1,
            size_bytes: file_c_content.len() as u64,
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
