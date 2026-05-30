//! Cross-client test vectors for encrypted metadata format.
//!
//! These vectors define the canonical wire format that ALL Beebeeb clients
//! (CLI, web, mobile) must produce and consume. Any change to encryption
//! output that breaks these vectors is a cross-client compatibility bug.

use beebeeb_core::encrypt::{
    decrypt_chunk, decrypt_chunk_raw, decrypt_metadata, encrypt_chunk, encrypt_chunk_raw,
    encrypt_metadata,
};
use beebeeb_core::kdf::{derive_file_key, MasterKey};
use beebeeb_types::{CipherSuite, EncryptedBlob};

/// A known master key for deterministic test vectors.
const TEST_MASTER_KEY: [u8; 32] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12,
    0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
];

const TEST_FILE_ID: &str = "550e8400-e29b-41d4-a716-446655440000";

#[test]
fn canonical_blob_has_cipher_suite() {
    let mk = MasterKey::from_bytes(TEST_MASTER_KEY);
    let fk = derive_file_key(&mk, TEST_FILE_ID.as_bytes());
    let blob = encrypt_metadata(&fk, "test.pdf").unwrap();

    assert_eq!(blob.cipher_suite, CipherSuite::V1Aes256Gcm);
    assert_eq!(blob.nonce.len(), 12);
    assert!(!blob.ciphertext.is_empty());
}

#[test]
fn canonical_blob_serializes_with_cipher_suite() {
    let mk = MasterKey::from_bytes(TEST_MASTER_KEY);
    let fk = derive_file_key(&mk, TEST_FILE_ID.as_bytes());
    let blob = encrypt_metadata(&fk, "report.pdf").unwrap();

    let json = serde_json::to_string(&blob).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

    // Must have cipher_suite field
    assert_eq!(parsed["cipher_suite"], "V1Aes256Gcm");
    // nonce must be a byte array, not base64 string
    assert!(parsed["nonce"].is_array());
    // ciphertext must be a byte array, not base64 string
    assert!(parsed["ciphertext"].is_array());
}

#[test]
fn key_derivation_uses_string_uuid() {
    let mk = MasterKey::from_bytes(TEST_MASTER_KEY);
    let fk = derive_file_key(&mk, TEST_FILE_ID.as_bytes());

    // Key should be deterministic
    let mk2 = MasterKey::from_bytes(TEST_MASTER_KEY);
    let fk2 = derive_file_key(&mk2, TEST_FILE_ID.as_bytes());
    assert_eq!(fk.as_bytes(), fk2.as_bytes());

    // String UUID and binary UUID should produce DIFFERENT keys.
    // The string form "550e8400-..." is 36 bytes; the binary form is 16 bytes.
    // This verifies clients must agree on using the string representation.
    let uuid_binary: [u8; 16] = [0x55, 0x0e, 0x84, 0x00, 0xe2, 0x9b, 0x41, 0xd4, 0xa7, 0x16, 0x44, 0x66, 0x55, 0x44, 0x00, 0x00];
    let mk3 = MasterKey::from_bytes(TEST_MASTER_KEY);
    let fk_binary = derive_file_key(&mk3, &uuid_binary);
    assert_ne!(fk.as_bytes(), fk_binary.as_bytes());
}

#[test]
fn roundtrip_metadata_encryption() {
    let mk = MasterKey::from_bytes(TEST_MASTER_KEY);
    let fk = derive_file_key(&mk, TEST_FILE_ID.as_bytes());

    let plaintext = "my-secret-filename.pdf";
    let blob = encrypt_metadata(&fk, plaintext).unwrap();
    let decrypted = decrypt_metadata(&fk, &blob).unwrap();

    assert_eq!(decrypted, plaintext);
}

#[test]
fn roundtrip_chunk_encryption() {
    let mk = MasterKey::from_bytes(TEST_MASTER_KEY);
    let fk = derive_file_key(&mk, TEST_FILE_ID.as_bytes());

    let plaintext = b"Hello, encrypted world! This is chunk data.";
    let blob = encrypt_chunk(&fk, plaintext).unwrap();
    let decrypted = decrypt_chunk(&fk, &blob).unwrap();

    assert_eq!(decrypted, plaintext);
}

#[test]
fn legacy_base64_format_rejected_by_canonical_deserialization() {
    let mk = MasterKey::from_bytes(TEST_MASTER_KEY);
    let fk = derive_file_key(&mk, TEST_FILE_ID.as_bytes());

    // First encrypt canonically (verify our key works)
    let _blob = encrypt_metadata(&fk, "legacy-test.txt").unwrap();

    // Simulate a legacy format where nonce and ciphertext are base64 strings
    // instead of byte arrays. This is what a misconfigured web client might produce.
    let legacy_json = serde_json::json!({
        "cipher_suite": "V1Aes256Gcm",
        "nonce": "AAAAAAAAAAAAAAAA",       // base64 string instead of byte array
        "ciphertext": "BBBBBBBBBBBBBBB",   // base64 string instead of byte array
    });
    let legacy_str = serde_json::to_string(&legacy_json).unwrap();

    // The canonical EncryptedBlob deserialization must reject this
    let result = serde_json::from_str::<EncryptedBlob>(&legacy_str);
    assert!(
        result.is_err() || {
            // Or if it somehow parses, the data should be wrong and decryption fails
            let parsed = result.unwrap();
            decrypt_metadata(&fk, &parsed).is_err()
        },
        "legacy base64-string format must not silently round-trip through canonical EncryptedBlob"
    );
}

#[test]
fn nonce_uniqueness() {
    let mk = MasterKey::from_bytes(TEST_MASTER_KEY);
    let fk = derive_file_key(&mk, TEST_FILE_ID.as_bytes());

    let blob1 = encrypt_metadata(&fk, "same-name.txt").unwrap();

    let mk2 = MasterKey::from_bytes(TEST_MASTER_KEY);
    let fk2 = derive_file_key(&mk2, TEST_FILE_ID.as_bytes());
    let blob2 = encrypt_metadata(&fk2, "same-name.txt").unwrap();

    // Same plaintext must produce different ciphertext (random nonce)
    assert_ne!(blob1.nonce, blob2.nonce);
    assert_ne!(blob1.ciphertext, blob2.ciphertext);
}

#[test]
fn canonical_json_roundtrip_preserves_data() {
    let mk = MasterKey::from_bytes(TEST_MASTER_KEY);
    let fk = derive_file_key(&mk, TEST_FILE_ID.as_bytes());

    let blob = encrypt_metadata(&fk, "wire-format-test.txt").unwrap();

    // Serialize to JSON (the wire format)
    let json = serde_json::to_string(&blob).unwrap();

    // Deserialize from JSON (what the receiving client does)
    let recovered: EncryptedBlob = serde_json::from_str(&json).unwrap();

    assert_eq!(recovered.cipher_suite, blob.cipher_suite);
    assert_eq!(recovered.nonce, blob.nonce);
    assert_eq!(recovered.ciphertext, blob.ciphertext);

    // The recovered blob must still decrypt correctly
    let mk2 = MasterKey::from_bytes(TEST_MASTER_KEY);
    let fk2 = derive_file_key(&mk2, TEST_FILE_ID.as_bytes());
    let decrypted = decrypt_metadata(&fk2, &recovered).unwrap();
    assert_eq!(decrypted, "wire-format-test.txt");
}

#[test]
fn ciphertext_length_matches_plaintext_plus_tag() {
    let mk = MasterKey::from_bytes(TEST_MASTER_KEY);
    let fk = derive_file_key(&mk, TEST_FILE_ID.as_bytes());

    // AES-256-GCM appends a 16-byte auth tag
    let plaintext = "exactly-this-text";
    let blob = encrypt_metadata(&fk, plaintext).unwrap();

    assert_eq!(
        blob.ciphertext.len(),
        plaintext.len() + 16,
        "ciphertext must be plaintext length + 16 bytes GCM auth tag"
    );
}

#[test]
fn empty_plaintext_roundtrip() {
    let mk = MasterKey::from_bytes(TEST_MASTER_KEY);
    let fk = derive_file_key(&mk, TEST_FILE_ID.as_bytes());

    // Empty filename is a valid edge case (e.g. root directory metadata)
    let blob = encrypt_metadata(&fk, "").unwrap();
    let decrypted = decrypt_metadata(&fk, &blob).unwrap();
    assert_eq!(decrypted, "");

    // Ciphertext should still be 16 bytes (just the GCM tag)
    assert_eq!(blob.ciphertext.len(), 16);
}

#[test]
fn unicode_filename_roundtrip() {
    let mk = MasterKey::from_bytes(TEST_MASTER_KEY);
    let fk = derive_file_key(&mk, TEST_FILE_ID.as_bytes());

    let filenames = [
        "Dokumente/Steuererkl\u{00e4}rung 2025.pdf",
        "\u{1f4c4} notes.txt",  // emoji in filename
        "\u{4f60}\u{597d}\u{4e16}\u{754c}.txt",  // Chinese characters
        "path/with spaces/and-dashes/file.tar.gz",
    ];

    for name in &filenames {
        let blob = encrypt_metadata(&fk, name).unwrap();
        let mk2 = MasterKey::from_bytes(TEST_MASTER_KEY);
        let fk2 = derive_file_key(&mk2, TEST_FILE_ID.as_bytes());
        let decrypted = decrypt_metadata(&fk2, &blob).unwrap();
        assert_eq!(&decrypted, *name, "unicode roundtrip failed for: {name:?}");
    }
}

#[test]
fn raw_chunk_roundtrip() {
    let mk = MasterKey::from_bytes(TEST_MASTER_KEY);
    let fk = derive_file_key(&mk, TEST_FILE_ID.as_bytes());
    let plaintext = b"Hello, raw binary chunk!";
    let raw = encrypt_chunk_raw(&fk, plaintext).unwrap();
    // Raw format: 12 bytes nonce + ciphertext (plaintext + 16 tag)
    assert_eq!(raw.len(), 12 + plaintext.len() + 16);
    let decrypted = decrypt_chunk_raw(&fk, &raw).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn is_media_classification() {
    assert!(beebeeb_core::media::is_media(Some("image/jpeg")));
    assert!(beebeeb_core::media::is_media(Some("video/mp4")));
    assert!(!beebeeb_core::media::is_media(Some("audio/mpeg")));
    assert!(!beebeeb_core::media::is_media(Some("application/pdf")));
    assert!(!beebeeb_core::media::is_media(None));
}

#[test]
fn previewable_types() {
    assert!(beebeeb_core::media::is_previewable(Some("image/jpeg")));
    assert!(beebeeb_core::media::is_previewable(Some("audio/mpeg")));
    assert!(beebeeb_core::media::is_previewable(Some("video/mp4")));
    assert!(beebeeb_core::media::is_previewable(Some("text/plain")));
    assert!(beebeeb_core::media::is_previewable(Some("application/pdf")));
    assert!(!beebeeb_core::media::is_previewable(Some("application/zip")));
    assert!(!beebeeb_core::media::is_previewable(None));
}

#[test]
fn previewable_extensions() {
    assert!(beebeeb_core::media::is_previewable_by_extension("photo.jpg"));
    assert!(beebeeb_core::media::is_previewable_by_extension("song.mp3"));
    assert!(beebeeb_core::media::is_previewable_by_extension("code.py"));
    assert!(beebeeb_core::media::is_previewable_by_extension("readme.md"));
    assert!(!beebeeb_core::media::is_previewable_by_extension("archive.zip"));
    assert!(!beebeeb_core::media::is_previewable_by_extension("noext"));
}

#[test]
fn guess_mime_covers_common_types() {
    assert_eq!(beebeeb_core::media::guess_mime_type("photo.jpg"), Some("image/jpeg"));
    assert_eq!(beebeeb_core::media::guess_mime_type("video.mp4"), Some("video/mp4"));
    assert_eq!(beebeeb_core::media::guess_mime_type("song.flac"), Some("audio/flac"));
    assert_eq!(beebeeb_core::media::guess_mime_type("doc.pdf"), Some("application/pdf"));
    assert_eq!(beebeeb_core::media::guess_mime_type("unknown.xyz"), None);
}

// ---------------------------------------------------------------------------
// Chunk planning cross-client vectors
// ---------------------------------------------------------------------------

#[test]
fn plan_chunks_small_file_mobile() {
    let plan = beebeeb_types::plan_chunks(10_000_000, beebeeb_types::ChunkProfile::Mobile);
    assert_eq!(plan.chunk_size_bytes, 4 * 1024 * 1024); // 4 MiB for files <= 64 MiB
    assert_eq!(plan.chunk_count, 3); // ceil(10_000_000 / 4_194_304)
}

#[test]
fn plan_chunks_large_file_desktop() {
    // N=32 ladder: 2e9 bytes (~1.86 GiB) → base_chunk_size = 64 MiB (Desktop
    // cap 128 MiB doesn't bind here).
    let plan = beebeeb_types::plan_chunks(2_000_000_000, beebeeb_types::ChunkProfile::Desktop);
    assert_eq!(plan.chunk_size_bytes, 64 * 1024 * 1024);
}

#[test]
fn plan_chunks_empty_file() {
    let plan = beebeeb_types::plan_chunks(0, beebeeb_types::ChunkProfile::Web);
    assert_eq!(plan.chunk_count, 1); // empty files still produce one chunk
}

#[test]
fn plan_chunks_web_capped() {
    // 5 GiB file: N=32 base_chunk_size = 256 MiB; Web caps at 32 MiB.
    let plan = beebeeb_types::plan_chunks(5 * 1024 * 1024 * 1024, beebeeb_types::ChunkProfile::Web);
    assert_eq!(plan.chunk_size_bytes, 32 * 1024 * 1024);

    // 200 GiB file: base 256 MiB; Web caps at 32 MiB.
    let plan = beebeeb_types::plan_chunks(200 * 1024 * 1024 * 1024, beebeeb_types::ChunkProfile::Web);
    assert_eq!(plan.chunk_size_bytes, 32 * 1024 * 1024);
}

#[test]
fn plan_chunks_mobile_capped() {
    // 200 GiB file: base 256 MiB; Mobile caps at 32 MiB.
    let plan = beebeeb_types::plan_chunks(200 * 1024 * 1024 * 1024, beebeeb_types::ChunkProfile::Mobile);
    assert_eq!(plan.chunk_size_bytes, 32 * 1024 * 1024);
}
