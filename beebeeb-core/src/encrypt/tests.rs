#![allow(deprecated)]
use super::*;
use crate::chunk_stream::ExpectedChunkFormat::{Unrecorded, V2};
use crate::kdf::{derive_file_key, derive_master_key};

fn test_file_key() -> FileKey {
    let mk = derive_master_key("test-password", b"test-salt-16bytes").unwrap();
    derive_file_key(&mk, b"test-file-id")
}

#[test]
fn protected_metadata_fields_are_all_or_nothing_and_canonical() {
    let base = r#"{"name":"a.txt","chunk_format":2"#;
    for suffix in [
        r#","version_id":"000000000000000000000000"}"#,
        r#","version_counter":1}"#,
        r#","version_id":"00000000000000000000000A","version_counter":1}"#,
        r#","version_id":"000000000000000000000000","version_counter":0}"#,
        r#","version_id":"000000000000000000000000","version_counter":9007199254740992}"#,
    ] {
        assert!(
            parse_name_metadata(&format!("{base}{suffix}")).is_err(),
            "accepted hostile metadata: {suffix}"
        );
    }
}

#[test]
fn protected_metadata_accepts_the_largest_exact_counter() {
    let metadata = parse_name_metadata(
        r#"{"name":"a.txt","chunk_format":2,"version_id":"000102030405060708090a0b","version_counter":9007199254740991}"#,
    )
    .unwrap();
    assert_eq!(
        metadata.version.unwrap().counter,
        crate::chunk_stream::MAX_VERSION_COUNTER
    );
}

#[test]
fn roundtrip_encrypt_decrypt_chunk() {
    let key = test_file_key();
    let plaintext = b"hello, beebeeb!";

    let blob = encrypt_chunk(&key, plaintext).unwrap();
    assert_eq!(blob.cipher_suite, CipherSuite::V1Aes256Gcm);
    assert_eq!(blob.nonce.len(), 12);
    assert_ne!(&blob.ciphertext[..plaintext.len()], plaintext.as_slice());

    let decrypted = decrypt_chunk(&key, &blob).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn wrong_key_fails_decryption() {
    let key = test_file_key();
    let blob = encrypt_chunk(&key, b"secret").unwrap();

    let mk = derive_master_key("different-password", b"different-salt-16").unwrap();
    let wrong_key = derive_file_key(&mk, b"wrong-file");
    assert!(decrypt_chunk(&wrong_key, &blob).is_err());
}

#[test]
fn tampered_ciphertext_fails() {
    let key = test_file_key();
    let mut blob = encrypt_chunk(&key, b"important data").unwrap();

    if let Some(byte) = blob.ciphertext.first_mut() {
        *byte ^= 0xFF;
    }

    assert!(decrypt_chunk(&key, &blob).is_err());
}

#[test]
fn tampered_nonce_fails() {
    let key = test_file_key();
    let mut blob = encrypt_chunk(&key, b"important data").unwrap();

    if let Some(byte) = blob.nonce.first_mut() {
        *byte ^= 0xFF;
    }

    assert!(decrypt_chunk(&key, &blob).is_err());
}

#[test]
fn invalid_nonce_length_fails() {
    let key = test_file_key();
    let blob = EncryptedBlob {
        cipher_suite: CipherSuite::V1Aes256Gcm,
        nonce: vec![0u8; 8], // wrong length
        ciphertext: vec![0u8; 32],
    };
    assert!(decrypt_chunk(&key, &blob).is_err());
}

#[test]
fn empty_plaintext_roundtrip() {
    let key = test_file_key();
    let blob = encrypt_chunk(&key, b"").unwrap();
    let decrypted = decrypt_chunk(&key, &blob).unwrap();
    assert!(decrypted.is_empty());
}

#[test]
fn roundtrip_metadata() {
    let key = test_file_key();
    let filename = "photos/vacation/IMG_2024.jpg";

    let blob = encrypt_metadata(&key, filename).unwrap();
    let recovered = decrypt_metadata(&key, &blob).unwrap();
    assert_eq!(recovered, filename);
}

#[test]
fn metadata_wrong_key_fails() {
    let key = test_file_key();
    let blob = encrypt_metadata(&key, "secret.txt").unwrap();

    let mk = derive_master_key("other", b"other-salt-16byte").unwrap();
    let wrong_key = derive_file_key(&mk, b"wrong");
    assert!(decrypt_metadata(&wrong_key, &blob).is_err());
}

#[test]
fn unique_nonces_per_encryption() {
    let key = test_file_key();
    let blob1 = encrypt_chunk(&key, b"same").unwrap();
    let blob2 = encrypt_chunk(&key, b"same").unwrap();
    assert_ne!(blob1.nonce, blob2.nonce);
}

#[test]
fn decrypt_chunks_to_file_roundtrip() {
    let key = test_file_key();
    let chunk1 = b"hello, ";
    let chunk2 = b"beebeeb!";

    let blob1 = encrypt_chunk(&key, chunk1).unwrap();
    let blob2 = encrypt_chunk(&key, chunk2).unwrap();

    let chunks = vec![(blob1.nonce, blob1.ciphertext), (blob2.nonce, blob2.ciphertext)];

    let dir = std::env::temp_dir();
    let path = dir.join("beebeeb_test_decrypt_chunks.bin");
    let path_str = path.to_str().unwrap();

    let total = decrypt_chunks_to_file(&key, "test-file-id", Unrecorded, chunks, path_str).unwrap();
    assert_eq!(total, (chunk1.len() + chunk2.len()) as u64);

    let written = std::fs::read(&path).unwrap();
    assert_eq!(written, b"hello, beebeeb!");

    std::fs::remove_file(&path).ok();
}

#[test]
fn decrypt_chunks_to_file_empty_is_rejected() {
    // Task 1908 (justified behaviour change): this used to return Ok(0) and
    // write an empty file. No real file has zero frames — even an empty file
    // is one 28-byte frame in v1 and v2 — so a zero-frame list is a server
    // that withheld every chunk: total truncation. It must be an error, and
    // no output may appear.
    let key = test_file_key();

    let dir = std::env::temp_dir();
    let path = dir.join("beebeeb_test_decrypt_empty.bin");
    let path_str = path.to_str().unwrap();
    std::fs::remove_file(&path).ok();

    let err = decrypt_chunks_to_file(&key, "test-file-id", Unrecorded, vec![], path_str).unwrap_err();
    assert!(matches!(err, CoreError::Decryption));
    assert!(!path.exists(), "no output may appear for a zero-frame file");
}

#[test]
fn decrypt_chunks_to_file_leaves_no_partial_file_on_midstream_failure() {
    // Mirror of decrypt_contiguous_leaves_no_partial_file_on_midstream_failure:
    // chunk 1 decrypts fine, chunk 2's GCM tag is corrupt. The function must
    // fail AND leave no partial plaintext at output_path AND no .tmp artifact.
    let key = test_file_key();
    let blob1 = encrypt_chunk(&key, b"AAAAAAAA").unwrap();
    let mut blob2 = encrypt_chunk(&key, b"BBBBBBBB").unwrap();
    // Corrupt the GCM tag of the second chunk (flip the last ciphertext byte).
    let last = blob2.ciphertext.len() - 1;
    blob2.ciphertext[last] ^= 0xFF;
    let chunks = vec![(blob1.nonce, blob1.ciphertext), (blob2.nonce, blob2.ciphertext)];

    let path = std::env::temp_dir().join("beebeeb_test_chunks_partial_cleanup.bin");
    let tmp = std::path::PathBuf::from(format!("{}.tmp", path.to_str().unwrap()));
    // Ensure stale artifacts from a prior run do not mask the assertion.
    std::fs::remove_file(&path).ok();
    std::fs::remove_file(&tmp).ok();

    let err = decrypt_chunks_to_file(&key, "test-file-id", Unrecorded, chunks, path.to_str().unwrap()).unwrap_err();
    assert!(matches!(err, CoreError::Decryption));
    assert!(
        !path.exists(),
        "no partial plaintext file may remain at output_path after a failed decrypt"
    );
    assert!(!tmp.exists(), "no .tmp artifact may remain after a failed decrypt");
}

#[test]
fn decrypt_chunks_to_file_wrong_key_fails() {
    let key = test_file_key();
    let blob = encrypt_chunk(&key, b"secret data").unwrap();
    let chunks = vec![(blob.nonce, blob.ciphertext)];

    let mk = derive_master_key("different-password", b"different-salt-16").unwrap();
    let wrong_key = derive_file_key(&mk, b"wrong-file");

    let dir = std::env::temp_dir();
    let path = dir.join("beebeeb_test_decrypt_wrong_key.bin");
    let path_str = path.to_str().unwrap();

    assert!(decrypt_chunks_to_file(&wrong_key, "test-file-id", Unrecorded, chunks, path_str).is_err());

    std::fs::remove_file(&path).ok();
}

#[test]
fn large_plaintext_roundtrip() {
    let key = test_file_key();
    let plaintext = vec![0x42u8; 1024 * 1024]; // 1 MiB
    let blob = encrypt_chunk(&key, &plaintext).unwrap();
    let decrypted = decrypt_chunk(&key, &blob).unwrap();
    assert_eq!(decrypted, plaintext);
}

fn pack_chunk(blob: &EncryptedBlob) -> Vec<u8> {
    let mut out = Vec::with_capacity(blob.nonce.len() + blob.ciphertext.len());
    out.extend_from_slice(&blob.nonce);
    out.extend_from_slice(&blob.ciphertext);
    out
}

#[test]
fn decrypt_contiguous_roundtrip_two_uniform_chunks() {
    let key = test_file_key();
    let chunk_size: u64 = 8;
    let p1 = b"AAAAAAAA";
    let p2 = b"BBBBBBBB";
    let blob1 = encrypt_chunk(&key, p1).unwrap();
    let blob2 = encrypt_chunk(&key, p2).unwrap();
    let mut body = pack_chunk(&blob1);
    body.extend(pack_chunk(&blob2));

    let path = std::env::temp_dir().join("beebeeb_test_contig_uniform.bin");
    let total = decrypt_contiguous_to_file(
        &key,
        "test-file-id",
        Unrecorded,
        &body,
        chunk_size,
        path.to_str().unwrap(),
    )
    .unwrap();
    assert_eq!(total, 16);

    let written = std::fs::read(&path).unwrap();
    assert_eq!(written, b"AAAAAAAABBBBBBBB");
    std::fs::remove_file(&path).ok();
}

#[test]
fn decrypt_contiguous_roundtrip_with_remainder() {
    let key = test_file_key();
    let chunk_size: u64 = 8;
    let p1 = b"AAAAAAAA"; // full chunk
    let p2 = b"BBB"; // short final chunk
    let blob1 = encrypt_chunk(&key, p1).unwrap();
    let blob2 = encrypt_chunk(&key, p2).unwrap();
    let mut body = pack_chunk(&blob1);
    body.extend(pack_chunk(&blob2));

    let path = std::env::temp_dir().join("beebeeb_test_contig_remainder.bin");
    let total = decrypt_contiguous_to_file(
        &key,
        "test-file-id",
        Unrecorded,
        &body,
        chunk_size,
        path.to_str().unwrap(),
    )
    .unwrap();
    assert_eq!(total, 11);

    let written = std::fs::read(&path).unwrap();
    assert_eq!(written, b"AAAAAAAABBB");
    std::fs::remove_file(&path).ok();
}

#[test]
fn decrypt_contiguous_empty_body_is_rejected() {
    // Task 1908 (justified behaviour change, same reasoning as
    // decrypt_chunks_to_file_empty_is_rejected): an empty body is never a
    // valid encrypted file, so it is total truncation, not an empty file.
    let key = test_file_key();
    let path = std::env::temp_dir().join("beebeeb_test_contig_empty.bin");
    std::fs::remove_file(&path).ok();
    let err = decrypt_contiguous_to_file(&key, "test-file-id", Unrecorded, &[], 8, path.to_str().unwrap()).unwrap_err();
    assert!(matches!(err, CoreError::Decryption));
    assert!(!path.exists(), "no output may appear for an empty body");
}

/// v2 frames for `data` split into `cs`-byte chunks, via the shared encryptor.
fn v2_body(file_id: &str, data: &[u8], cs: u64) -> (crate::kdf::MasterKey, Vec<Vec<u8>>) {
    use crate::chunk_stream::{ChunkEncryptor, ChunkFormat};
    let mk = derive_master_key("test-password", b"test-salt-16bytes").unwrap();
    let mut enc = ChunkEncryptor::for_push_with_chunk_size(&mk, file_id, data.len() as u64, cs)
        .unwrap()
        .with_format(ChunkFormat::V2)
        .unwrap();
    let frames: Vec<Vec<u8>> = data
        .chunks(cs as usize)
        .map(|c| enc.push_chunk(c).unwrap().data)
        .collect();
    enc.finish().unwrap();
    (mk, frames)
}

#[test]
fn decrypt_contiguous_v2_roundtrip_and_swap_rejected() {
    let data = b"AAAAAAAABBBBBBBBCCC";
    let (mk, frames) = v2_body("contig-v2", data, 8);
    let key = derive_file_key(&mk, b"contig-v2");
    let path = std::env::temp_dir().join("beebeeb_test_contig_v2.bin");

    let total = decrypt_contiguous_to_file(&key, "contig-v2", V2, &frames.concat(), 8, path.to_str().unwrap()).unwrap();
    assert_eq!(total, data.len() as u64);
    assert_eq!(std::fs::read(&path).unwrap(), data);
    std::fs::remove_file(&path).ok();

    // Equal-size chunks 0 and 1 swapped: must fail, and leave no output.
    let swapped = [frames[1].clone(), frames[0].clone(), frames[2].clone()].concat();
    let err = decrypt_contiguous_to_file(&key, "contig-v2", V2, &swapped, 8, path.to_str().unwrap()).unwrap_err();
    assert!(matches!(err, CoreError::Decryption));
    assert!(!path.exists());

    // Last chunk withheld: truncation must fail.
    let truncated = [frames[0].clone(), frames[1].clone()].concat();
    let err = decrypt_contiguous_to_file(&key, "contig-v2", V2, &truncated, 8, path.to_str().unwrap()).unwrap_err();
    assert!(matches!(err, CoreError::Decryption));
    assert!(!path.exists());
}

#[test]
fn decrypt_chunks_to_file_v2_roundtrip_and_drop_rejected() {
    let data = b"AAAAAAAABBBBBBBBCCCCCCCC";
    let (mk, frames) = v2_body("pairs-v2", data, 8);
    let key = derive_file_key(&mk, b"pairs-v2");
    let pairs = |fs: &[Vec<u8>]| -> Vec<(Vec<u8>, Vec<u8>)> {
        fs.iter()
            .map(|f| (f[..NONCE_LEN].to_vec(), f[NONCE_LEN..].to_vec()))
            .collect()
    };
    let path = std::env::temp_dir().join("beebeeb_test_pairs_v2.bin");

    let total = decrypt_chunks_to_file(&key, "pairs-v2", V2, pairs(&frames), path.to_str().unwrap()).unwrap();
    assert_eq!(total, data.len() as u64);
    std::fs::remove_file(&path).ok();

    // Middle chunk dropped: must fail.
    let dropped = [frames[0].clone(), frames[2].clone()];
    let err = decrypt_chunks_to_file(&key, "pairs-v2", V2, pairs(&dropped), path.to_str().unwrap()).unwrap_err();
    assert!(matches!(err, CoreError::Decryption));
    assert!(!path.exists());
}

#[test]
fn decrypt_contiguous_zero_chunk_size_rejected() {
    let key = test_file_key();
    let body = vec![0u8; NONCE_LEN + 16];
    let path = std::env::temp_dir().join("beebeeb_test_contig_zero.bin");
    let err =
        decrypt_contiguous_to_file(&key, "test-file-id", Unrecorded, &body, 0, path.to_str().unwrap()).unwrap_err();
    match err {
        CoreError::InvalidInput(_) => {}
        other => panic!("expected InvalidInput, got {other:?}"),
    }
    // Empty file may exist on err; clean up if so.
    std::fs::remove_file(&path).ok();
}

#[test]
fn decrypt_contiguous_wrong_key_fails() {
    let key = test_file_key();
    let wrong_key = derive_file_key(
        &derive_master_key("different-password", b"test-salt-16bytes").unwrap(),
        b"test-file-id",
    );
    let blob = encrypt_chunk(&key, b"secrets").unwrap();
    let body = pack_chunk(&blob);
    let path = std::env::temp_dir().join("beebeeb_test_contig_wrong_key.bin");
    let err = decrypt_contiguous_to_file(&wrong_key, "test-file-id", Unrecorded, &body, 7, path.to_str().unwrap())
        .unwrap_err();
    assert!(matches!(err, CoreError::Decryption));
    std::fs::remove_file(&path).ok();
}

#[test]
fn decrypt_contiguous_truncated_body_rejected() {
    let key = test_file_key();
    // Body shorter than NONCE_LEN + TAG_LEN — cannot even attempt decrypt.
    let body = vec![0u8; NONCE_LEN + 8]; // 8 bytes < 16 byte tag
    let path = std::env::temp_dir().join("beebeeb_test_contig_truncated.bin");
    let err =
        decrypt_contiguous_to_file(&key, "test-file-id", Unrecorded, &body, 64, path.to_str().unwrap()).unwrap_err();
    assert!(matches!(err, CoreError::Decryption));
    std::fs::remove_file(&path).ok();
}

#[test]
fn decrypt_contiguous_leaves_no_partial_file_on_midstream_failure() {
    // R2: chunk 1 decrypts fine, chunk 2's tag is corrupt. The function must
    // fail AND leave no partial plaintext at output_path — otherwise an
    // existence-based cache would serve the truncated first chunk as a
    // "complete" decrypt on every subsequent open.
    let key = test_file_key();
    let chunk_size: u64 = 8;
    let blob1 = encrypt_chunk(&key, b"AAAAAAAA").unwrap();
    let blob2 = encrypt_chunk(&key, b"BBBBBBBB").unwrap();
    let mut body = pack_chunk(&blob1);
    let mut second = pack_chunk(&blob2);
    // Corrupt the GCM tag of the second chunk (flip the last byte).
    let last = second.len() - 1;
    second[last] ^= 0xFF;
    body.extend(second);

    let path = std::env::temp_dir().join("beebeeb_test_contig_partial_cleanup.bin");
    // Ensure a stale file from a prior run does not mask the assertion.
    std::fs::remove_file(&path).ok();

    let err = decrypt_contiguous_to_file(
        &key,
        "test-file-id",
        Unrecorded,
        &body,
        chunk_size,
        path.to_str().unwrap(),
    )
    .unwrap_err();
    assert!(matches!(err, CoreError::Decryption));
    assert!(
        !path.exists(),
        "no partial plaintext file may remain at output_path after a failed decrypt"
    );
    // No .tmp artifact may survive either.
    let tmp = std::env::temp_dir().join("beebeeb_test_contig_partial_cleanup.bin.tmp");
    assert!(!tmp.exists(), "no .tmp artifact may remain after a failed decrypt");
}

#[test]
fn decrypt_contiguous_atomic_no_partial_visible_at_final_path() {
    // R2: on a wrong key the very first chunk fails. The final output path
    // must never have been created (atomic .tmp + rename means the final
    // path only appears on full success).
    let key = test_file_key();
    let wrong_key = derive_file_key(
        &derive_master_key("different-password", b"test-salt-16bytes").unwrap(),
        b"test-file-id",
    );
    let blob = encrypt_chunk(&key, b"secrets!").unwrap();
    let body = pack_chunk(&blob);
    let path = std::env::temp_dir().join("beebeeb_test_contig_atomic_firstfail.bin");
    std::fs::remove_file(&path).ok();

    let err = decrypt_contiguous_to_file(&wrong_key, "test-file-id", Unrecorded, &body, 8, path.to_str().unwrap())
        .unwrap_err();
    assert!(matches!(err, CoreError::Decryption));
    assert!(
        !path.exists(),
        "final output path must not exist after a first-chunk failure"
    );
}

// ── decrypt_names batch primitive (task 0806) ───────────────────────────

#[test]
fn decrypt_names_batch_matches_single_byte_for_byte() {
    let master = derive_master_key("batch-test-pw", b"batch-salt-16byte").unwrap();
    // N names encrypted under the string-UUID form (web/mobile/server form).
    let owned: Vec<(uuid::Uuid, String)> = (0..50)
        .map(|i| {
            let id = uuid::Uuid::new_v4();
            let enc = encrypt_name(&master, &id.to_string(), &format!("file_{i}.txt"), Some("text/plain")).unwrap();
            (id, enc)
        })
        .collect();
    let items: Vec<(uuid::Uuid, &str)> = owned.iter().map(|(id, e)| (*id, e.as_str())).collect();

    let batch = decrypt_names(&master, &items);
    assert_eq!(batch.len(), owned.len());
    for (i, ((id, enc), res)) in owned.iter().zip(&batch).enumerate() {
        let single = decrypt_name_with_mime(&master, &id.to_string(), enc).unwrap();
        let got = res.as_ref().expect("batch item should decrypt");
        assert_eq!(
            *got, single,
            "item {i}: batch must match single decrypt_name_with_mime byte-for-byte"
        );
        assert_eq!(got.0, format!("file_{i}.txt"));
        assert_eq!(got.1.as_deref(), Some("text/plain"));
    }
}

#[test]
fn decrypt_names_isolates_partial_failure() {
    let master = derive_master_key("pw-partial", b"salt-16-bytes-ok").unwrap();
    let good_id = uuid::Uuid::new_v4();
    let good = encrypt_name(&master, &good_id.to_string(), "good.pdf", Some("application/pdf")).unwrap();
    // Valid blob but encrypted under a DIFFERENT master key → GCM tag fails.
    let other = derive_master_key("other-pw", b"other-salt-16byt").unwrap();
    let wrong_id = uuid::Uuid::new_v4();
    let wrong = encrypt_name(&other, &wrong_id.to_string(), "secret.txt", None).unwrap();
    let bad_id = uuid::Uuid::new_v4();

    let items: Vec<(uuid::Uuid, &str)> = vec![
        (good_id, good.as_str()),
        (bad_id, "{ not a valid blob"), // garbage → parse fails
        (wrong_id, wrong.as_str()),
    ];
    let res = decrypt_names(&master, &items);
    assert_eq!(res.len(), 3);
    assert_eq!(res[0].as_ref().unwrap().0, "good.pdf", "good item decrypts");
    assert!(res[1].is_err(), "garbage blob → Err for that item only");
    assert!(res[2].is_err(), "wrong-key blob → Err (GCM tag), batch not failed");
}

#[test]
fn decrypt_names_empty_input() {
    let master = derive_master_key("pw-empty", b"salt-16-bytes-ok").unwrap();
    assert!(decrypt_names(&master, &[]).is_empty());
}

#[test]
fn decrypt_names_handles_legacy_binary_uuid_form() {
    // A file keyed under the legacy binary-UUID form (CLI/desktop origin) must
    // still decrypt — via the second derivation attempt.
    let master = derive_master_key("pw-bin", b"salt-16-bytes-ok").unwrap();
    let id = uuid::Uuid::new_v4();
    let bin_key = derive_file_key(&master, id.as_bytes());
    let plaintext = serde_json::json!({"name": "legacy.bin", "mime_type": "application/octet-stream"}).to_string();
    let blob = encrypt_metadata(&bin_key, &plaintext).unwrap();
    let enc = serde_json::to_string(&blob).unwrap();

    let res = decrypt_names(&master, &[(id, enc.as_str())]);
    let (name, mime) = res[0]
        .as_ref()
        .expect("binary-form name should decrypt via 2nd attempt");
    assert_eq!(name, "legacy.bin");
    assert_eq!(mime.as_deref(), Some("application/octet-stream"));
}

/// Regression test (found 2026-07-01): `decrypt_one_name` used to
/// re-implement a NARROWER parser than `decrypt_name_with_mime` — only the
/// native `EncryptedBlob` direct-deserialize path, no plaintext fast-path,
/// no legacy web base64 `{nonce,ciphertext}` format. `decrypt_one_name` now
/// delegates to `decrypt_name_with_mime` so the two paths can never drift.
#[test]
fn decrypt_names_batch_handles_web_base64_format() {
    let master = derive_master_key("pw-web-format", b"salt-16-bytes-ok").unwrap();
    let id = uuid::Uuid::new_v4();
    // Web derives the file key from the UUID STRING bytes (the common case).
    let key = derive_file_key(&master, id.to_string().as_bytes());
    let plaintext = serde_json::json!({"name": "web-upload.png", "mime_type": "image/png"}).to_string();
    let blob = encrypt_metadata(&key, &plaintext).unwrap();
    // Legacy web wire format: base64 {"nonce":"...","ciphertext":"..."} — NO
    // `cipher_suite` field, unlike the native `EncryptedBlob` JSON shape.
    let web_enc = crate::metadata_wire::serialize_encrypted_metadata(&blob.nonce, &blob.ciphertext);

    // Sanity: the single-item path already handles this format correctly.
    let single = decrypt_name_with_mime(&master, &id.to_string(), &web_enc).unwrap();
    assert_eq!(single, ("web-upload.png".to_string(), Some("image/png".to_string())));

    // The batch path must match it byte-for-byte, not silently fail.
    let res = decrypt_names(&master, &[(id, web_enc.as_str())]);
    let got = res[0].as_ref().expect("batch must decrypt the web base64 blob format");
    assert_eq!(*got, single);
}

/// Companion regression test: a bare (non-JSON) legacy plaintext filename
/// must also survive the batch path — the same gap this fix closes.
#[test]
fn decrypt_names_batch_handles_plaintext_fast_path() {
    let master = derive_master_key("pw-plaintext", b"salt-16-bytes-ok").unwrap();
    let id = uuid::Uuid::new_v4();
    let res = decrypt_names(&master, &[(id, "legacy-plain-name.txt")]);
    let (name, mime) = res[0]
        .as_ref()
        .expect("bare plaintext name must pass through the batch path");
    assert_eq!(name, "legacy-plain-name.txt");
    assert_eq!(*mime, None);
}

// ── decrypt_name: multi-format / multi-key consolidation (the SINGLE
//    source of truth shared by CLI / desktop / mobile / web). ──────────────

use crate::kdf::MasterKey;

/// A fixed UUID file id used across the name-decryption format tests.
const NAME_FID: &str = "3e15382b-1111-2222-3333-444455556666";

fn name_master_key() -> MasterKey {
    derive_master_key("test-password", b"test-salt-16bytes").unwrap()
}

/// Encode the plaintext into the **web base64** `{nonce, ciphertext}` blob
/// shape that older web builds produced (base64 strings, no `cipher_suite`).
/// Mirrors `repos/web/src/lib/crypto.ts` legacy serializer.
fn web_base64_blob(file_key: &FileKey, plaintext: &str) -> String {
    use base64::Engine as _;
    let blob = encrypt_metadata(file_key, plaintext).unwrap();
    let b64 = base64::engine::general_purpose::STANDARD;
    serde_json::json!({
        "nonce": b64.encode(&blob.nonce),
        "ciphertext": b64.encode(&blob.ciphertext),
    })
    .to_string()
}

/// Format 1: a bare (non-JSON) plaintext name passes straight through. This
/// is how server-created folders / pre-encryption rows are stored.
#[test]
fn decrypt_name_plaintext_passthrough() {
    let mk = name_master_key();
    assert_eq!(decrypt_name(&mk, NAME_FID, "Documents").unwrap(), "Documents");
    let (n, mime) = decrypt_name_with_mime(&mk, NAME_FID, "Documents").unwrap();
    assert_eq!(n, "Documents");
    assert_eq!(mime, None);
}

/// Format 2 + string-UUID key: the canonical CLI/core path —
/// `encrypt_name` produces a native EncryptedBlob with the `{name,mime}`
/// envelope; `decrypt_name` round-trips it.
#[test]
fn decrypt_name_native_blob_string_uuid_roundtrip() {
    let mk = name_master_key();
    let enc = encrypt_name(&mk, NAME_FID, "report.pdf", Some("application/pdf")).unwrap();
    assert_eq!(decrypt_name(&mk, NAME_FID, &enc).unwrap(), "report.pdf");
    let (name, mime) = decrypt_name_with_mime(&mk, NAME_FID, &enc).unwrap();
    assert_eq!(name, "report.pdf");
    assert_eq!(mime.as_deref(), Some("application/pdf"));
}

/// Format 3 + string-UUID key: the **web app base64 blob** — the format
/// that was failing for web-app-created files before this consolidation.
/// The web client derives the file key from the UUID *string* bytes, so the
/// string-UUID derivation must match.
#[test]
fn decrypt_name_web_base64_blob_string_uuid() {
    let mk = name_master_key();
    let fk = derive_file_key(&mk, NAME_FID.as_bytes());
    // Web encrypts the `{name,mime_type}` JSON envelope, base64-wrapped.
    let envelope = serde_json::json!({"name": "vacation.jpg", "mime_type": "image/jpeg"}).to_string();
    let blob = web_base64_blob(&fk, &envelope);
    assert!(!blob.contains("cipher_suite"), "web blob has no cipher_suite field");

    assert_eq!(decrypt_name(&mk, NAME_FID, &blob).unwrap(), "vacation.jpg");
    let (name, mime) = decrypt_name_with_mime(&mk, NAME_FID, &blob).unwrap();
    assert_eq!(name, "vacation.jpg");
    assert_eq!(mime.as_deref(), Some("image/jpeg"));
}

/// Format 3 web base64 blob carrying a **bare filename** plaintext (the
/// oldest web shape, pre-`{name,mime}` envelope) — returned as-is, no MIME.
#[test]
fn decrypt_name_web_base64_blob_bare_filename() {
    let mk = name_master_key();
    let fk = derive_file_key(&mk, NAME_FID.as_bytes());
    let blob = web_base64_blob(&fk, "legacy-name.txt");
    assert_eq!(decrypt_name(&mk, NAME_FID, &blob).unwrap(), "legacy-name.txt");
    let (_, mime) = decrypt_name_with_mime(&mk, NAME_FID, &blob).unwrap();
    assert_eq!(mime, None);
}

/// Native blob encrypted under the **binary-UUID** key (legacy pre-`bb
/// repair` CLI file): `decrypt_name` must fall back to the binary derivation.
#[test]
fn decrypt_name_native_blob_binary_uuid_fallback() {
    let mk = name_master_key();
    let uuid: uuid::Uuid = NAME_FID.parse().unwrap();
    let fk = derive_file_key(&mk, uuid.as_bytes());
    let envelope = serde_json::json!({"name": "old.doc", "mime_type": null}).to_string();
    let blob = encrypt_metadata(&fk, &envelope).unwrap();
    let blob_json = serde_json::to_string(&blob).unwrap();
    assert_eq!(decrypt_name(&mk, NAME_FID, &blob_json).unwrap(), "old.doc");
}

/// Web base64 blob encrypted under the **binary-UUID** key — both legacy
/// dimensions at once (web shape + binary derivation).
#[test]
fn decrypt_name_web_base64_blob_binary_uuid_fallback() {
    let mk = name_master_key();
    let uuid: uuid::Uuid = NAME_FID.parse().unwrap();
    let fk = derive_file_key(&mk, uuid.as_bytes());
    let blob = web_base64_blob(&fk, "binary-key.png");
    assert_eq!(decrypt_name(&mk, NAME_FID, &blob).unwrap(), "binary-key.png");
}

/// A wrong master key fails cleanly with `Decryption` after trying every
/// (key, format) combination — no panic, no partial result.
#[test]
fn decrypt_name_wrong_key_fails() {
    let mk = name_master_key();
    let enc = encrypt_name(&mk, NAME_FID, "secret.txt", None).unwrap();
    let wrong = derive_master_key("other-password", b"other-salt-16byte").unwrap();
    assert!(matches!(
        decrypt_name(&wrong, NAME_FID, &enc),
        Err(CoreError::Decryption)
    ));
}

/// A non-UUID file id still decrypts via the string-UUID key (binary
/// derivation is simply skipped when the id won't parse as a UUID).
#[test]
fn decrypt_name_non_uuid_file_id_uses_string_key() {
    let mk = name_master_key();
    let fid = "not-a-uuid-just-a-string";
    let enc = encrypt_name(&mk, fid, "named.bin", None).unwrap();
    assert_eq!(decrypt_name(&mk, fid, &enc).unwrap(), "named.bin");
}

/// `decrypt_name_with_key` (the known-file-key entry point used by
/// file-request uploads) handles both the native and web base64 blobs.
#[test]
fn decrypt_name_with_key_handles_both_blob_formats() {
    let mk = name_master_key();
    let fk = derive_file_key(&mk, NAME_FID.as_bytes());

    let native = encrypt_name(&mk, NAME_FID, "via-key.pdf", Some("application/pdf")).unwrap();
    assert_eq!(decrypt_name_with_key(&fk, &native).as_deref(), Some("via-key.pdf"));

    let web = web_base64_blob(&fk, &serde_json::json!({"name": "web-via-key.txt"}).to_string());
    assert_eq!(decrypt_name_with_key(&fk, &web).as_deref(), Some("web-via-key.txt"));

    // Plaintext fast path also works on the known-key entry point.
    assert_eq!(decrypt_name_with_key(&fk, "Inbox").as_deref(), Some("Inbox"));
}

// ── Task 1908: chunk format recorded in the encrypted name metadata ──────

/// Decrypt the raw metadata plaintext of a native-blob `name_encrypted`.
fn metadata_plaintext(mk: &MasterKey, file_id: &str, name_encrypted: &str) -> String {
    let fk = derive_file_key(mk, file_id.as_bytes());
    decrypt_envelope_plaintext(&fk, name_encrypted).unwrap()
}

/// Seal an arbitrary metadata plaintext as a native `name_encrypted`.
fn seal_metadata(mk: &MasterKey, file_id: &str, plaintext: &str) -> String {
    let fk = derive_file_key(mk, file_id.as_bytes());
    serde_json::to_string(&encrypt_metadata(&fk, plaintext).unwrap()).unwrap()
}

#[test]
fn name_metadata_records_v2_and_reads_it_back() {
    let mk = name_master_key();
    let ne = encrypt_name_with_chunk_format(&mk, NAME_FID, "a.pdf", Some("application/pdf"), V2).unwrap();
    let meta = decrypt_name_metadata(&mk, NAME_FID, &ne).unwrap();
    assert_eq!(meta.name, "a.pdf");
    assert_eq!(meta.mime_type.as_deref(), Some("application/pdf"));
    assert_eq!(meta.chunk_format, V2);
    // The existing readers still see the same name/MIME.
    assert_eq!(decrypt_name(&mk, NAME_FID, &ne).unwrap(), "a.pdf");
    // Known-key reader (share recipients) agrees.
    let fk = derive_file_key(&mk, NAME_FID.as_bytes());
    assert_eq!(decrypt_name_metadata_with_key(&fk, &ne).unwrap().chunk_format, V2);
}

#[test]
fn encrypt_name_writes_no_chunk_format_field() {
    // Unrecorded = byte-for-byte the pre-1908 plaintext shape, so every
    // existing reader and every pre-1908 client sees what it always saw.
    let mk = name_master_key();
    let ne = encrypt_name(&mk, NAME_FID, "b.txt", None).unwrap();
    assert_eq!(
        metadata_plaintext(&mk, NAME_FID, &ne),
        r#"{"mime_type":null,"name":"b.txt"}"#
    );
    assert_eq!(
        decrypt_name_metadata(&mk, NAME_FID, &ne).unwrap().chunk_format,
        Unrecorded
    );
    let ne2 = encrypt_name_with_chunk_format(&mk, NAME_FID, "b.txt", None, Unrecorded).unwrap();
    assert_eq!(
        metadata_plaintext(&mk, NAME_FID, &ne2),
        r#"{"mime_type":null,"name":"b.txt"}"#
    );
    let ne3 = encrypt_name_with_chunk_format(&mk, NAME_FID, "b.txt", None, V2).unwrap();
    assert_eq!(
        metadata_plaintext(&mk, NAME_FID, &ne3),
        r#"{"chunk_format":2,"mime_type":null,"name":"b.txt"}"#
    );
}

#[test]
fn name_metadata_legacy_shapes_are_unrecorded() {
    let mk = name_master_key();
    // Plaintext legacy name.
    let meta = decrypt_name_metadata(&mk, NAME_FID, "Inbox").unwrap();
    assert_eq!((meta.name.as_str(), meta.chunk_format), ("Inbox", Unrecorded));
    // Bare-filename plaintext inside an envelope.
    let ne = seal_metadata(&mk, NAME_FID, "old-name.txt");
    let meta = decrypt_name_metadata(&mk, NAME_FID, &ne).unwrap();
    assert_eq!((meta.name.as_str(), meta.chunk_format), ("old-name.txt", Unrecorded));
}

#[test]
fn name_metadata_unknown_chunk_format_is_an_error_not_detection() {
    let mk = name_master_key();
    for bad in [
        r#"{"name":"x","chunk_format":1}"#,
        r#"{"name":"x","chunk_format":0}"#,
        r#"{"name":"x","chunk_format":3}"#,
        r#"{"name":"x","chunk_format":"2"}"#,
        r#"{"name":"x","chunk_format":null}"#,
    ] {
        let ne = seal_metadata(&mk, NAME_FID, bad);
        assert!(decrypt_name_metadata(&mk, NAME_FID, &ne).is_err(), "{bad}");
    }
    let ne = encrypt_name_with_chunk_format(&mk, NAME_FID, "x", None, V2).unwrap();
    assert_eq!(decrypt_name_metadata(&mk, NAME_FID, &ne).unwrap().chunk_format, V2);
}

#[test]
fn name_metadata_wrong_key_fails() {
    let mk = name_master_key();
    let ne = encrypt_name_with_chunk_format(&mk, NAME_FID, "a", None, V2).unwrap();
    let other = derive_master_key("other-password", b"test-salt-16bytes").unwrap();
    assert!(decrypt_name_metadata(&other, NAME_FID, &ne).is_err());
}
