//! Cross-platform test vector validation.
//!
//! These tests load `test-vectors/vectors.json` and verify that every
//! deterministic crypto operation in beebeeb-core produces the exact expected
//! output. The same JSON file must be used by every platform implementation
//! (WASM, UniFFI/Swift, UniFFI/Kotlin, CLI) to guarantee interoperability.
//!
//! If any test here fails after a code change, it means the change broke
//! cross-platform compatibility and existing user data may become unreadable.

use beebeeb_core::encrypt::{decrypt_chunk, decrypt_metadata, encrypt_metadata};
use beebeeb_core::file_request::{derive_request_wrap_key, open_request_upload, unwrap_request_private};
use beebeeb_core::kdf::{FileKey, MasterKey, derive_file_key, derive_master_key, derive_shared_folder_index_key};
use beebeeb_core::opaque::{
    OpaqueEnvelope, compute_recovery_check, derive_share_key, derive_x25519_private, derive_x25519_public,
    x25519_shared_secret,
};
use beebeeb_core::recovery::recover_from_phrase;
use beebeeb_types::{CipherSuite, EncryptedBlob};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn load_vectors() -> Vec<serde_json::Value> {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../test-vectors/vectors.json");
    let contents = std::fs::read_to_string(path).expect("test-vectors/vectors.json must exist");
    let root: serde_json::Value = serde_json::from_str(&contents).unwrap();
    root["vectors"].as_array().unwrap().clone()
}

fn get_vector(vectors: &[serde_json::Value], name: &str) -> serde_json::Value {
    vectors
        .iter()
        .find(|v| v["name"].as_str() == Some(name))
        .unwrap_or_else(|| panic!("vector '{name}' not found in vectors.json"))
        .clone()
}

fn decode_hex(v: &serde_json::Value, field: &str) -> Vec<u8> {
    hex::decode(v[field].as_str().unwrap_or_else(|| panic!("field '{field}' missing")))
        .unwrap_or_else(|_| panic!("field '{field}' is not valid hex"))
}

fn bytes32(v: &serde_json::Value, field: &str) -> [u8; 32] {
    let b = decode_hex(v, field);
    b.try_into()
        .unwrap_or_else(|v: Vec<u8>| panic!("field '{field}' must be 32 bytes, got {}", v.len()))
}

// ---------------------------------------------------------------------------
// 0. A shared folder's key id (task 2133)
// ---------------------------------------------------------------------------

#[test]
fn vector_folder_key_id() {
    let vectors = load_vectors();
    let v = get_vector(&vectors, "folder_key_id");
    assert_eq!(v["info"].as_str(), Some("beebeeb/folder-key-id/v1"));
    assert_eq!(v["salt"].as_str(), Some("none"));
    let key = bytes32(&v, "folder_key_hex");
    assert_eq!(
        beebeeb_core::folder_key::folder_key_id(&key),
        bytes32(&v, "expected_key_id_hex")
    );
}

// ---------------------------------------------------------------------------
// 1. Master key derivation from password (Argon2id)
// ---------------------------------------------------------------------------

#[test]
fn vector_master_key_from_password() {
    let vectors = load_vectors();
    let v = get_vector(&vectors, "master_key_from_password");

    let password = v["password"].as_str().unwrap();
    let salt = decode_hex(&v, "salt_hex");
    let expected = bytes32(&v, "expected_master_key_hex");

    let mk = derive_master_key(password, &salt).unwrap();
    assert_eq!(
        mk.to_bytes(),
        expected,
        "master_key_from_password: derived key does not match vector"
    );
}

// ---------------------------------------------------------------------------
// 2. File key derivation (HKDF-SHA256)
// ---------------------------------------------------------------------------

#[test]
fn vector_file_key_derivation() {
    let vectors = load_vectors();
    let v = get_vector(&vectors, "file_key_derivation");

    let mk = MasterKey::from_bytes(bytes32(&v, "master_key_hex"));
    let file_id = decode_hex(&v, "file_id_hex");
    let expected = bytes32(&v, "expected_file_key_hex");

    let fk = derive_file_key(&mk, &file_id);
    assert_eq!(
        *fk.as_bytes(),
        expected,
        "file_key_derivation: derived file key does not match vector"
    );
}

// ---------------------------------------------------------------------------
// 3. Chunk decryption (decrypt-only — nonce was random at generation time)
// ---------------------------------------------------------------------------

#[test]
fn vector_chunk_decrypt() {
    let vectors = load_vectors();
    let v = get_vector(&vectors, "chunk_encrypt_decrypt");

    let file_key = FileKey::from_bytes(bytes32(&v, "file_key_hex"));
    let nonce = decode_hex(&v, "nonce_hex");
    let ciphertext = decode_hex(&v, "ciphertext_hex");
    let expected_plaintext = decode_hex(&v, "plaintext_hex");

    let blob = EncryptedBlob {
        cipher_suite: CipherSuite::V1Aes256Gcm,
        nonce,
        ciphertext,
    };

    let decrypted = decrypt_chunk(&file_key, &blob).unwrap();
    assert_eq!(
        decrypted, expected_plaintext,
        "chunk_encrypt_decrypt: decrypted plaintext does not match vector"
    );
}

// ---------------------------------------------------------------------------
// 4. X25519 identity keypair derivation
// ---------------------------------------------------------------------------

#[test]
fn vector_x25519_identity_keypair() {
    let vectors = load_vectors();
    let v = get_vector(&vectors, "x25519_identity_keypair");

    let mk = MasterKey::from_bytes(bytes32(&v, "master_key_hex"));
    let expected_private = bytes32(&v, "expected_x25519_private_hex");
    let expected_public = bytes32(&v, "expected_x25519_public_hex");

    let private = derive_x25519_private(&mk);
    let public = derive_x25519_public(&private);

    assert_eq!(
        *private, expected_private,
        "x25519_identity_keypair: private key does not match vector"
    );
    assert_eq!(
        public, expected_public,
        "x25519_identity_keypair: public key does not match vector"
    );
}

// ---------------------------------------------------------------------------
// 5. X25519 share key exchange
// ---------------------------------------------------------------------------

#[test]
fn vector_x25519_share_key_exchange() {
    let vectors = load_vectors();
    let v = get_vector(&vectors, "x25519_share_key_exchange");

    let mk_a = MasterKey::from_bytes(bytes32(&v, "alice_master_key_hex"));
    let mk_b = MasterKey::from_bytes(bytes32(&v, "bob_master_key_hex"));
    let expected_shared_secret = bytes32(&v, "expected_shared_secret_hex");
    let expected_share_key = bytes32(&v, "expected_share_key_hex");
    let file_id = decode_hex(&v, "file_id_hex");

    let priv_a = derive_x25519_private(&mk_a);
    let pub_a = derive_x25519_public(&priv_a);
    let priv_b = derive_x25519_private(&mk_b);
    let pub_b = derive_x25519_public(&priv_b);

    // Verify public keys match the vector
    assert_eq!(
        hex::encode(pub_a),
        v["alice_x25519_public_hex"].as_str().unwrap(),
        "x25519_share_key_exchange: alice public key mismatch"
    );
    assert_eq!(
        hex::encode(pub_b),
        v["bob_x25519_public_hex"].as_str().unwrap(),
        "x25519_share_key_exchange: bob public key mismatch"
    );

    // Shared secret must be identical from both sides
    let shared_ab = x25519_shared_secret(&priv_a, &pub_b).unwrap();
    let shared_ba = x25519_shared_secret(&priv_b, &pub_a).unwrap();
    assert_eq!(*shared_ab, *shared_ba, "x25519 DH must be commutative");
    assert_eq!(
        *shared_ab, expected_shared_secret,
        "x25519_share_key_exchange: shared secret does not match vector"
    );

    // Share key derivation
    let share_key = derive_share_key(&shared_ab, &file_id);
    assert_eq!(
        *share_key, expected_share_key,
        "x25519_share_key_exchange: share key does not match vector"
    );
}

// ---------------------------------------------------------------------------
// 5b. Share-key derivation — additional file_id variants (task 0708)
// ---------------------------------------------------------------------------
// Locks `derive_share_key` against drift with more pinned (file_id ->
// share_key) pairs, reusing the shared secret from `x25519_share_key_exchange`.
// The expected keys were computed with the canonical HKDF-SHA256, salt
// `b"beebeeb-share"` (see opaque::derive_share_key). ANY change to the share-key
// derivation — including "normalizing" the salt — breaks these. DO NOT update
// the expected hex to make a failing test pass: a failure here means a real
// derivation change that would break every existing share. The salt is immutable.
#[test]
fn vector_share_key_additional_file_ids() {
    let vectors = load_vectors();
    let v = get_vector(&vectors, "x25519_share_key_exchange");
    let shared_secret = bytes32(&v, "expected_shared_secret_hex");

    // (file_id ASCII, expected derive_share_key hex). UUID-string file_ids match
    // real usage; first/last cover the all-zero and all-f extremes.
    let cases: [(&str, &str); 3] = [
        (
            "00000000-0000-0000-0000-000000000001",
            "7230e7bf70dd6a3c3591534c8289931c0cba04bb57a16953bc24735fa98a6ce7",
        ),
        (
            "11111111-2222-3333-4444-555555555555",
            "ac0388e7fbc5b17db53120e4486b433c21308bc64c64c492c0a40cac6c8e9199",
        ),
        (
            "ffffffff-ffff-ffff-ffff-ffffffffffff",
            "64d0cdbc2dacab3fa89f0f5e2fb3c1b29924ffb42985b3376acf86869e462d15",
        ),
    ];
    for (file_id, expected_hex) in cases {
        let got = derive_share_key(&shared_secret, file_id.as_bytes());
        assert_eq!(
            hex::encode(*got),
            expected_hex,
            "derive_share_key drift for file_id {file_id} — share-key derivation changed (salt must be immutable)"
        );
    }
}

// ---------------------------------------------------------------------------
// 6. Recovery check
// ---------------------------------------------------------------------------

#[test]
fn vector_recovery_check() {
    let vectors = load_vectors();
    let v = get_vector(&vectors, "recovery_check");

    let mk = MasterKey::from_bytes(bytes32(&v, "master_key_hex"));
    let expected = bytes32(&v, "expected_recovery_check_hex");

    let rc = compute_recovery_check(&mk);
    assert_eq!(*rc, expected, "recovery_check: computed value does not match vector");
}

// ---------------------------------------------------------------------------
// 7. Envelope serialization
// ---------------------------------------------------------------------------

#[test]
fn vector_envelope_serialization() {
    let vectors = load_vectors();
    let v = get_vector(&vectors, "envelope_serialization");

    let mk_bytes = bytes32(&v, "master_key_hex");
    let x_priv = bytes32(&v, "x25519_private_hex");
    let rc = bytes32(&v, "recovery_check_hex");
    let expected = decode_hex(&v, "expected_envelope_hex");

    let envelope = OpaqueEnvelope {
        master_key: mk_bytes,
        x25519_private: x_priv,
        recovery_check: rc,
    };

    let serialized = envelope.to_bytes();
    assert_eq!(
        serialized.to_vec(),
        expected,
        "envelope_serialization: serialized bytes do not match vector"
    );

    // Also verify deserialization roundtrip
    let deserialized = OpaqueEnvelope::from_bytes(&serialized);
    assert_eq!(deserialized.master_key, mk_bytes);
    assert_eq!(deserialized.x25519_private, x_priv);
    assert_eq!(deserialized.recovery_check, rc);
}

// ---------------------------------------------------------------------------
// 8. Recovery phrase roundtrip (BIP39 mnemonic -> Argon2id -> master key)
// ---------------------------------------------------------------------------

#[test]
fn vector_recovery_phrase_roundtrip() {
    let vectors = load_vectors();
    let v = get_vector(&vectors, "recovery_phrase_roundtrip");

    let mnemonic = v["mnemonic"].as_str().unwrap();
    let expected = bytes32(&v, "expected_master_key_hex");

    let mk = recover_from_phrase(mnemonic).unwrap();
    assert_eq!(
        mk.to_bytes(),
        expected,
        "recovery_phrase_roundtrip: recovered key does not match vector"
    );
}

// ---------------------------------------------------------------------------
// 9. Metadata (filename) decrypt vector
// ---------------------------------------------------------------------------

#[test]
fn vector_metadata_decrypt() {
    let vectors = load_vectors();
    let v = get_vector(&vectors, "metadata_encrypt_decrypt");

    let file_key = FileKey::from_bytes(bytes32(&v, "file_key_hex"));
    let nonce = decode_hex(&v, "nonce_hex");
    let ciphertext = decode_hex(&v, "ciphertext_hex");
    let expected_metadata = v["metadata"].as_str().unwrap();

    let blob = EncryptedBlob {
        cipher_suite: CipherSuite::V1Aes256Gcm,
        nonce,
        ciphertext,
    };

    let decrypted = decrypt_metadata(&file_key, &blob).unwrap();
    assert_eq!(
        decrypted, expected_metadata,
        "metadata_encrypt_decrypt: decrypted metadata does not match vector"
    );
}

// ---------------------------------------------------------------------------
// 10. Chunk encrypt->decrypt roundtrip (verifies random-nonce path)
// ---------------------------------------------------------------------------

#[test]
fn vector_chunk_encrypt_decrypt_roundtrip() {
    let vectors = load_vectors();
    let v = get_vector(&vectors, "chunk_encrypt_decrypt");

    let file_key = FileKey::from_bytes(bytes32(&v, "file_key_hex"));
    let expected_plaintext = decode_hex(&v, "plaintext_hex");

    // Encrypt with a fresh random nonce, then decrypt — must match original
    let blob = beebeeb_core::encrypt::encrypt_chunk(&file_key, &expected_plaintext).unwrap();
    let decrypted = decrypt_chunk(&file_key, &blob).unwrap();
    assert_eq!(
        decrypted, expected_plaintext,
        "chunk roundtrip: encrypt->decrypt must reproduce the original plaintext"
    );
}

// ---------------------------------------------------------------------------
// 11. Metadata encrypt->decrypt roundtrip with various filenames
// ---------------------------------------------------------------------------

#[test]
fn vector_metadata_encrypt_decrypt_roundtrip_unicode() {
    let vectors = load_vectors();
    let v = get_vector(&vectors, "metadata_encrypt_decrypt");

    let file_key = FileKey::from_bytes(bytes32(&v, "file_key_hex"));

    // Test with a range of filenames that must work across all platforms
    let filenames = [
        "photos/vacation/IMG_2024.jpg",
        "documents/tax-return-2025.pdf",
        "",
        "a",
        &"x".repeat(4096),
        "Dokumente/Steuererklaerung 2025.pdf",
        "folder/file with spaces.txt",
    ];

    for name in &filenames {
        let blob = encrypt_metadata(&file_key, name).unwrap();
        let recovered = decrypt_metadata(&file_key, &blob).unwrap();
        assert_eq!(&recovered, *name, "metadata roundtrip failed for filename: {name:?}");
    }
}

// ---------------------------------------------------------------------------
// 12. Key derivation chain — full pipeline from password to file key
// ---------------------------------------------------------------------------

#[test]
fn vector_full_key_chain() {
    let vectors = load_vectors();
    let pw_vec = get_vector(&vectors, "master_key_from_password");
    let fk_vec = get_vector(&vectors, "file_key_derivation");

    // Derive master key from password
    let password = pw_vec["password"].as_str().unwrap();
    let salt = decode_hex(&pw_vec, "salt_hex");
    let mk = derive_master_key(password, &salt).unwrap();

    // Derive file key using the same master key and file ID from the vector
    let file_id = decode_hex(&fk_vec, "file_id_hex");
    let expected_fk = bytes32(&fk_vec, "expected_file_key_hex");
    let fk = derive_file_key(&mk, &file_id);

    assert_eq!(
        *fk.as_bytes(),
        expected_fk,
        "full_key_chain: password -> master key -> file key chain must produce expected file key"
    );
}

// ---------------------------------------------------------------------------
// 13. Envelope -> master key -> file key -> decrypt chain
// ---------------------------------------------------------------------------

#[test]
fn vector_envelope_to_decrypt_chain() {
    let vectors = load_vectors();
    let env_vec = get_vector(&vectors, "envelope_serialization");
    let fk_vec = get_vector(&vectors, "file_key_derivation");
    let chunk_vec = get_vector(&vectors, "chunk_encrypt_decrypt");

    // Deserialize the envelope
    let envelope_bytes = decode_hex(&env_vec, "expected_envelope_hex");
    let envelope_arr: [u8; 96] = envelope_bytes.try_into().unwrap();
    let envelope = OpaqueEnvelope::from_bytes(&envelope_arr);

    // Extract master key from envelope
    let mk = MasterKey::from_bytes(envelope.master_key);

    // Derive file key
    let file_id = decode_hex(&fk_vec, "file_id_hex");
    let fk = derive_file_key(&mk, &file_id);
    assert_eq!(
        *fk.as_bytes(),
        bytes32(&fk_vec, "expected_file_key_hex"),
        "envelope chain: file key mismatch"
    );

    // Decrypt the chunk from the vector
    let nonce = decode_hex(&chunk_vec, "nonce_hex");
    let ciphertext = decode_hex(&chunk_vec, "ciphertext_hex");
    let expected_plaintext = decode_hex(&chunk_vec, "plaintext_hex");

    let blob = EncryptedBlob {
        cipher_suite: CipherSuite::V1Aes256Gcm,
        nonce,
        ciphertext,
    };
    let decrypted = decrypt_chunk(&fk, &blob).unwrap();
    assert_eq!(
        decrypted, expected_plaintext,
        "envelope chain: decrypted chunk does not match expected plaintext"
    );
}

// ---------------------------------------------------------------------------
// 14. Recovery phrase -> master key -> file key -> decrypt chain
// ---------------------------------------------------------------------------

#[test]
fn vector_recovery_phrase_full_chain() {
    let vectors = load_vectors();
    let rp_vec = get_vector(&vectors, "recovery_phrase_roundtrip");

    let mnemonic = rp_vec["mnemonic"].as_str().unwrap();
    let expected_mk = bytes32(&rp_vec, "expected_master_key_hex");

    // Recover master key
    let mk = recover_from_phrase(mnemonic).unwrap();
    assert_eq!(mk.to_bytes(), expected_mk);

    // Derive a file key and verify encrypt->decrypt roundtrip with it
    let file_id = b"cross-platform-test-file-001";
    let fk = derive_file_key(&mk, file_id);

    let plaintext = b"This data was encrypted with a recovery-phrase-derived key.";
    let blob = beebeeb_core::encrypt::encrypt_chunk(&fk, plaintext).unwrap();
    let decrypted = decrypt_chunk(&fk, &blob).unwrap();
    assert_eq!(decrypted, plaintext);
}

// ---------------------------------------------------------------------------
// 15. Share key can encrypt/decrypt (proves sharing pipeline works end-to-end)
// ---------------------------------------------------------------------------

#[test]
fn vector_share_key_encrypts_and_decrypts() {
    let vectors = load_vectors();
    let v = get_vector(&vectors, "x25519_share_key_exchange");

    let share_key_bytes = bytes32(&v, "expected_share_key_hex");
    let share_fk = FileKey::from_bytes(share_key_bytes);

    let plaintext = b"Shared document content visible to both Alice and Bob.";
    let blob = beebeeb_core::encrypt::encrypt_chunk(&share_fk, plaintext).unwrap();
    let decrypted = decrypt_chunk(&share_fk, &blob).unwrap();
    assert_eq!(
        decrypted, plaintext,
        "share_key: a share key must be usable as a file encryption key"
    );
}

// ---------------------------------------------------------------------------
// 16. File request seal/open (sealed-box / ECIES per request)
// ---------------------------------------------------------------------------

#[test]
fn vector_file_request_seal_open() {
    let vectors = load_vectors();
    let v = get_vector(&vectors, "file_request_seal_open");

    let mk = MasterKey::from_bytes(bytes32(&v, "master_key_hex"));
    let request_id = decode_hex(&v, "request_id_hex");
    let expected_wrap_key = bytes32(&v, "expected_wrap_key_hex");
    let r_priv = bytes32(&v, "r_priv_hex");
    let expected_r_pub = bytes32(&v, "r_pub_hex");
    let file_id = decode_hex(&v, "file_id_hex");
    let expected_content_key = bytes32(&v, "content_key_hex");
    let e_pub = bytes32(&v, "e_pub_hex");
    let wrapped_key = decode_hex(&v, "wrapped_key_hex");
    let wrapped_private = decode_hex(&v, "wrapped_private_hex");
    let wrap_nonce = decode_hex(&v, "wrap_nonce_hex");

    // 1. The private-wrap key is deterministic and must match the vector.
    let wrap_key = derive_request_wrap_key(&mk, &request_id);
    assert_eq!(
        *wrap_key, expected_wrap_key,
        "file_request_seal_open: wrap key does not match vector"
    );

    // 2. The request public key must match the one derived from r_priv.
    let r_pub = derive_x25519_public(&r_priv);
    assert_eq!(
        r_pub, expected_r_pub,
        "file_request_seal_open: r_pub does not match vector"
    );

    // 3. Unwrapping the stored wrapped private key must recover r_priv exactly.
    let recovered_priv = unwrap_request_private(&mk, &request_id, &wrapped_private, &wrap_nonce).unwrap();
    assert_eq!(
        *recovered_priv, r_priv,
        "file_request_seal_open: unwrapped private key does not match vector"
    );

    // 4. The critical interop path: a content key sealed on one platform must
    //    open to the original bytes on any other platform.
    let opened = open_request_upload(&r_priv, &e_pub, &file_id, &wrapped_key).unwrap();
    assert_eq!(
        *opened, expected_content_key,
        "file_request_seal_open: opened content key does not match vector"
    );
}

// ---------------------------------------------------------------------------
// 18. Share-key wrap (audit item K3) — pins the wire format web's
//     wrapKeyForShare/unwrapKeyFromShare (repos/web/src/lib/crypto.ts)
//     independently implements: nonce(12) || AES-256-GCM ciphertext (32-byte
//     key + 16-byte tag) = 60 bytes, no AAD, raw 32-byte key (no KDF).
// ---------------------------------------------------------------------------

#[test]
fn vector_share_key_wrap_decrypt() {
    let vectors = load_vectors();
    let v = get_vector(&vectors, "share_key_wrap");

    let wrap_key = FileKey::from_bytes(bytes32(&v, "wrap_key_hex"));
    let nonce = decode_hex(&v, "nonce_hex");
    let ciphertext = decode_hex(&v, "ciphertext_hex");
    let expected_key_to_wrap = decode_hex(&v, "key_to_wrap_hex");

    assert_eq!(
        nonce.len() + ciphertext.len(),
        60,
        "share_key_wrap: nonce(12) || ciphertext(48) must total 60 bytes (the K3 wire format)"
    );

    let blob = EncryptedBlob {
        cipher_suite: CipherSuite::V1Aes256Gcm,
        nonce,
        ciphertext,
    };

    let decrypted = decrypt_chunk(&wrap_key, &blob).unwrap();
    assert_eq!(
        decrypted, expected_key_to_wrap,
        "share_key_wrap: decrypted key does not match vector — this is the interop contract \
         web's unwrapKeyFromShare must also satisfy against this exact ciphertext"
    );
}

#[test]
fn vector_share_key_wrap_encrypt_roundtrip() {
    let vectors = load_vectors();
    let v = get_vector(&vectors, "share_key_wrap");

    let wrap_key = FileKey::from_bytes(bytes32(&v, "wrap_key_hex"));
    let expected_key_to_wrap = decode_hex(&v, "key_to_wrap_hex");

    // Encrypt with a fresh random nonce, then decrypt — must reproduce the
    // original 32-byte key. Mirrors what web's wrapKeyForShare ->
    // unwrapKeyFromShare round trip must also do.
    let blob = beebeeb_core::encrypt::encrypt_chunk(&wrap_key, &expected_key_to_wrap).unwrap();
    let decrypted = decrypt_chunk(&wrap_key, &blob).unwrap();
    assert_eq!(
        decrypted, expected_key_to_wrap,
        "share_key_wrap roundtrip: encrypt->decrypt must reproduce the original key"
    );
}

// ---------------------------------------------------------------------------
// 19. Thumbnail encryption (audit item K3) — pins the wire format web's
//     thumbnail.ts (encryptThumbnailBlob / fetchAndDecryptThumbnail /
//     fetchAndDecryptLargeThumbnail) independently implements: nonce(12) ||
//     AES-256-GCM ciphertext, no AAD, over arbitrary-length plaintext.
// ---------------------------------------------------------------------------

#[test]
fn vector_thumbnail_encrypt_decrypt() {
    let vectors = load_vectors();
    let v = get_vector(&vectors, "thumbnail_encrypt");

    let file_key = FileKey::from_bytes(bytes32(&v, "file_key_hex"));
    let nonce = decode_hex(&v, "nonce_hex");
    let ciphertext = decode_hex(&v, "ciphertext_hex");
    let expected_plaintext = decode_hex(&v, "plaintext_hex");

    let blob = EncryptedBlob {
        cipher_suite: CipherSuite::V1Aes256Gcm,
        nonce,
        ciphertext,
    };

    let decrypted = decrypt_chunk(&file_key, &blob).unwrap();
    assert_eq!(
        decrypted, expected_plaintext,
        "thumbnail_encrypt: decrypted plaintext does not match vector — this is the interop \
         contract web's thumbnail decrypt path must also satisfy against this exact ciphertext"
    );
}

#[test]
fn vector_thumbnail_encrypt_roundtrip() {
    let vectors = load_vectors();
    let v = get_vector(&vectors, "thumbnail_encrypt");

    let file_key = FileKey::from_bytes(bytes32(&v, "file_key_hex"));
    let expected_plaintext = decode_hex(&v, "plaintext_hex");

    let blob = beebeeb_core::encrypt::encrypt_chunk(&file_key, &expected_plaintext).unwrap();
    let decrypted = decrypt_chunk(&file_key, &blob).unwrap();
    assert_eq!(
        decrypted, expected_plaintext,
        "thumbnail_encrypt roundtrip: encrypt->decrypt must reproduce the original plaintext"
    );
}

// ---------------------------------------------------------------------------
// 19b. Shared-folder search-index key (version 8, task 2237) — the reader
//      path every client implements must reproduce the published buckets.
// ---------------------------------------------------------------------------

#[test]
fn shared_folder_index_key_vector_is_reproducible() {
    let vectors = load_vectors();
    let v = get_vector(&vectors, "shared_folder_index_key");

    let folder_key = FileKey::from_bytes(bytes32(&v, "folder_key_hex"));
    let buckets = v["buckets"].as_array().expect("buckets array");
    assert_eq!(buckets.len(), 3, "vector must pin buckets 0, 7 and 63");

    for entry in buckets {
        let bucket = entry["bucket"].as_u64().expect("bucket") as u32;
        let expected = entry["expected_hex"].as_str().expect("expected_hex");
        let got = hex::encode(derive_shared_folder_index_key(&folder_key, bucket).as_bytes());
        assert_eq!(got, expected, "shared_folder_index_key diverged for bucket {bucket}");
    }
}

// ---------------------------------------------------------------------------
// 20. Version guard — fail loudly if vectors.json format changes unexpectedly
// ---------------------------------------------------------------------------

#[test]
fn vector_file_version_check() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../test-vectors/vectors.json");
    let contents = std::fs::read_to_string(path).unwrap();
    let root: serde_json::Value = serde_json::from_str(&contents).unwrap();

    let version = root["version"]
        .as_u64()
        .expect("vectors.json must have a 'version' field");
    assert_eq!(
        version, 11,
        "vectors.json version mismatch — expected 11, got {version}. \
         Update this test if you intentionally bumped the version."
    );

    let vectors = root["vectors"].as_array().unwrap();
    let names: Vec<&str> = vectors.iter().map(|v| v["name"].as_str().unwrap()).collect();

    // Every expected vector must be present
    let required = [
        "master_key_from_password",
        "file_key_derivation",
        "chunk_encrypt_decrypt",
        "x25519_identity_keypair",
        "x25519_share_key_exchange",
        "recovery_check",
        "envelope_serialization",
        "recovery_phrase_roundtrip",
        "metadata_encrypt_decrypt",
        "file_request_seal_open",
        "share_key_wrap",
        "thumbnail_encrypt",
        // Version 5 (task 1943): chunk format v2 + v2 name metadata.
        "chunk_v2_stream",
        "chunk_v2_single_frame",
        "metadata_v2_name",
        // Version 6 (task 1958): the name writer under a given per-file key.
        "metadata_v2_name_filekey",
        "metadata_v1_name_filekey",
        // Version 7 (task 2133): a shared folder's key id.
        "folder_key_id",
        // Version 8 (task 2237): a shared folder's search-index bucket key.
        "shared_folder_index_key",
        // Version 9 (task 2237b): the public folder-link key combiner.
        "combine_folder_link_key",
        "key_wrap_v1",
        "folder_link_passphrase",
        "folder_link_passphrase_nfd",
        "folder_custody_v1",
        "link_owner_key_v1",
        "link_owner_token_v1",
        "folder_child_file_v1",
        "folder_child_folder_v1",
        "owner_wrapped_file_key",
        "owner_wrapped_folder_key",
        "folder_wrapped_file_key",
    ];
    for name in &required {
        assert!(names.contains(name), "vectors.json is missing required vector '{name}'");
    }
}

// Owner/shared-folder custody: consume independent known answers, then check
// shipped fresh-nonce writers against those same published keys.
#[test]
fn vector_owner_wrapped_file_key() {
    let v = get_vector(&load_vectors(), "owner_wrapped_file_key");
    check_owner_key_vector(&v, "file_id", "child_key_hex");
}

#[test]
fn vector_owner_wrapped_folder_key() {
    let v = get_vector(&load_vectors(), "owner_wrapped_folder_key");
    check_owner_key_vector(&v, "folder_id", "folder_key_hex");
}

fn check_owner_key_vector(v: &serde_json::Value, id_field: &str, key_field: &str) {
    use beebeeb_core::owned_keys::{unwrap_owner_key, wrap_key_to_owner};

    let master = MasterKey::from_bytes(bytes32(v, "master_key_hex"));
    let id = v[id_field].as_str().unwrap();
    let expected = bytes32(v, key_field);
    let frame = decode_hex(v, "expected_frame_hex");
    assert_eq!(&frame[..12], decode_hex(v, "nonce_hex"));
    assert_eq!(unwrap_owner_key(&master, id, &frame).unwrap().as_bytes(), &expected);
    let shipped = wrap_key_to_owner(&master, id, &FileKey::from_bytes(expected)).unwrap();
    assert_eq!(shipped.len(), frame.len());
    assert_eq!(unwrap_owner_key(&master, id, &shipped).unwrap().as_bytes(), &expected);
}

#[test]
fn vector_folder_wrapped_file_key() {
    use beebeeb_core::owned_keys::{unwrap_child_key, wrap_child_key};

    let v = get_vector(&load_vectors(), "folder_wrapped_file_key");
    let folder = FileKey::from_bytes(bytes32(&v, "folder_key_hex"));
    let expected = bytes32(&v, "child_key_hex");
    let frame = decode_hex(&v, "expected_frame_hex");
    assert_eq!(&frame[..12], decode_hex(&v, "nonce_hex"));
    assert_eq!(unwrap_child_key(&folder, &frame).unwrap().as_bytes(), &expected);
    let shipped = wrap_child_key(&folder, &FileKey::from_bytes(expected)).unwrap();
    assert_eq!(shipped.len(), frame.len());
    assert_eq!(unwrap_child_key(&folder, &shipped).unwrap().as_bytes(), &expected);
}

// ---------------------------------------------------------------------------
// 21. Chunk format v2 (version 5, task 1943) — what every client's v2 READ
//     path must do with these bytes, through the public reader only.
// ---------------------------------------------------------------------------

use beebeeb_core::chunk_stream::{ChunkDecryptor, ChunkFormat, ExpectedChunkFormat, chunk_aad_v2, open_chunk};

/// A v2 vector's frames, decrypted in order by the streaming reader under the
/// V2 pin, equal its plaintext, and the stream finishes (last frame seen). Each
/// frame also opens on its own at its index (random access), its published AAD
/// is the documented layout, and it does NOT open as a v1 frame.
fn check_chunk_v2(name: &str) {
    let vectors = load_vectors();
    let v = get_vector(&vectors, name);
    let mk = MasterKey::from_bytes(bytes32(&v, "master_key_hex"));
    let file_id = v["file_id"].as_str().unwrap();
    let file_key = derive_file_key(&mk, file_id.as_bytes());
    assert_eq!(
        hex::encode(file_key.as_bytes()),
        v["file_key_hex"].as_str().unwrap(),
        "{name}: file key"
    );
    let version_id: [u8; 12] = decode_hex(&v, "version_id_hex").try_into().unwrap();
    let frames = v["frames"].as_array().unwrap();
    assert_eq!(frames.len() as u64, v["chunk_count"].as_u64().unwrap());

    let mut dec = ChunkDecryptor::for_push(&mk, file_id, ExpectedChunkFormat::V2);
    let mut plaintext = Vec::new();
    let mut wire = Vec::new();
    for f in frames {
        let frame = decode_hex(f, "frame_hex");
        let index = f["index"].as_u64().unwrap() as u32;
        let is_last = f["is_last"].as_bool().unwrap();
        assert_eq!(
            hex::encode(chunk_aad_v2(file_id.as_bytes(), &version_id, index, is_last)),
            f["aad_hex"].as_str().unwrap(),
            "{name}: AAD of frame {index}"
        );
        let opened = open_chunk(&file_key, file_id, &version_id, index, is_last, ChunkFormat::V2, &frame).unwrap();
        assert_eq!(
            opened,
            decode_hex(f, "plaintext_hex"),
            "{name}: frame {index} (random access)"
        );
        assert!(
            open_chunk(
                &file_key,
                file_id,
                &version_id,
                index,
                is_last,
                ChunkFormat::V1Legacy,
                &frame
            )
            .is_err(),
            "{name}: a v2 frame must not open as v1"
        );
        plaintext.extend(dec.push_frame(&frame).unwrap().data);
        wire.extend(frame);
    }
    dec.finish().expect("the stream ends with its last frame");
    assert_eq!(
        detected_format(&mk, file_id, &decode_hex(&frames[0], "frame_hex")),
        Some(ChunkFormat::V2)
    );
    assert_eq!(plaintext, decode_hex(&v, "plaintext_hex"), "{name}: plaintext");
    assert_eq!(
        hex::encode(&wire),
        v["wire_hex"].as_str().unwrap(),
        "{name}: wire = frames back to back"
    );
}

/// The format a fresh reader detects for these frames when the metadata records
/// nothing (`Unrecorded`): v2, from frame 0.
fn detected_format(mk: &MasterKey, file_id: &str, frame0: &[u8]) -> Option<ChunkFormat> {
    let mut dec = ChunkDecryptor::for_push(mk, file_id, ExpectedChunkFormat::Unrecorded);
    dec.push_frame(frame0).unwrap();
    dec.format()
}

#[test]
fn vector_chunk_v2_stream_decrypt() {
    check_chunk_v2("chunk_v2_stream");
    // A multi-frame v2 file without its last frame is rejected (truncation).
    let vectors = load_vectors();
    let v = get_vector(&vectors, "chunk_v2_stream");
    let mk = MasterKey::from_bytes(bytes32(&v, "master_key_hex"));
    let frames = v["frames"].as_array().unwrap();
    assert!(frames.len() > 2, "the stream vector must have more than two frames");
    let mut dec = ChunkDecryptor::for_push(&mk, v["file_id"].as_str().unwrap(), ExpectedChunkFormat::V2);
    for f in &frames[..frames.len() - 1] {
        dec.push_frame(&decode_hex(f, "frame_hex")).unwrap();
    }
    assert!(
        dec.finish().is_err(),
        "a v2 stream without its last frame must not finish"
    );
}

#[test]
fn vector_chunk_v2_single_frame_decrypt() {
    check_chunk_v2("chunk_v2_single_frame");
}

#[test]
fn vector_metadata_v2_name_decrypt() {
    let vectors = load_vectors();
    let v = get_vector(&vectors, "metadata_v2_name");
    let mk = MasterKey::from_bytes(bytes32(&v, "master_key_hex"));
    let meta = beebeeb_core::encrypt::decrypt_file_metadata(
        &mk,
        v["file_id"].as_str().unwrap(),
        v["name_encrypted"].as_str().unwrap(),
    )
    .unwrap();
    assert_eq!(meta.name, v["expected_name"].as_str().unwrap());
    assert_eq!(meta.mime_type.as_deref(), v["expected_mime_type"].as_str());
    assert_eq!(meta.chunk_format, ExpectedChunkFormat::V2);
    assert_eq!(v["expected_chunk_format"].as_u64(), Some(2));
    // Sealed under the name subkey: the raw file key alone does not open it.
    let file_key = derive_file_key(&mk, v["file_id"].as_str().unwrap().as_bytes());
    let blob: beebeeb_types::EncryptedBlob = serde_json::from_str(v["name_encrypted"].as_str().unwrap()).unwrap();
    assert!(
        decrypt_metadata(&file_key, &blob).is_err(),
        "a v2 name must not open under the raw file key"
    );
    assert_eq!(hex::encode(&blob.nonce), v["nonce_hex"].as_str().unwrap());
}

// ---------------------------------------------------------------------------
// 22. The rename writer under a given per-file key (version 6, task 1958) —
//     what every client's rename reader must read back, public API only.
// ---------------------------------------------------------------------------

fn file_key_of(v: &serde_json::Value) -> beebeeb_core::kdf::FileKey {
    let bytes: [u8; 32] = hex::decode(v["file_key_hex"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    beebeeb_core::kdf::FileKey::from_bytes(bytes)
}

#[test]
fn vector_metadata_name_filekey_reads_back_with_its_pin() {
    let vectors = load_vectors();
    for (name, pin) in [
        ("metadata_v2_name_filekey", ExpectedChunkFormat::V2),
        ("metadata_v1_name_filekey", ExpectedChunkFormat::Unrecorded),
    ] {
        let v = get_vector(&vectors, name);
        let fk = file_key_of(&v);
        let meta = beebeeb_core::encrypt::decrypt_file_metadata_with_key(&fk, v["name_encrypted"].as_str().unwrap())
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(meta.name, v["expected_name"].as_str().unwrap(), "{name}");
        assert_eq!(meta.mime_type.as_deref(), v["expected_mime_type"].as_str(), "{name}");
        assert_eq!(meta.chunk_format, pin, "{name}");
        assert_eq!(
            u64::from(pin.as_u8()),
            v["expected_chunk_format"].as_u64().unwrap(),
            "{name}"
        );
    }
}

#[test]
fn vector_metadata_v2_name_filekey_is_not_under_the_raw_key_and_v1_is() {
    let vectors = load_vectors();
    let raw_opens = |name: &str| {
        let v = get_vector(&vectors, name);
        let blob: beebeeb_types::EncryptedBlob = serde_json::from_str(v["name_encrypted"].as_str().unwrap()).unwrap();
        beebeeb_core::encrypt::decrypt_metadata(&file_key_of(&v), &blob).is_ok()
    };
    assert!(
        !raw_opens("metadata_v2_name_filekey"),
        "a v2-pinned name is subkey-sealed"
    );
    assert!(
        raw_opens("metadata_v1_name_filekey"),
        "an unpinned name is legacy raw-key sealed"
    );
}

/// The SHIPPED name writers against the published name vectors (task 1958
/// round 2, I-1). A shipped writer draws a fresh nonce, so its bytes cannot
/// equal a vector's; what can be compared is everything else. With each vector's
/// own inputs, `encrypt_name_with_chunk_format` (master key, 1943) and
/// `encrypt_name_for` (given key, 1958) must seal under the SAME key as the
/// vector (raw file key or name subkey: each opens both blobs or neither) to the
/// SAME plaintext, at the same length. A wrong key choice, a dropped pin or a
/// different envelope in the shipped path is red here, not only in unit tests.
#[test]
fn vector_names_are_what_the_shipped_writers_seal() {
    let vectors = load_vectors();
    let cases: [(&str, bool); 3] = [
        ("metadata_v2_name", true),
        ("metadata_v2_name_filekey", false),
        ("metadata_v1_name_filekey", false),
    ];
    for (name, master_key_writer) in cases {
        let v = get_vector(&vectors, name);
        let filename = v["expected_name"].as_str().unwrap();
        let mime = v["expected_mime_type"].as_str();
        let pin = ExpectedChunkFormat::from_u8(v["expected_chunk_format"].as_u64().unwrap() as u8).unwrap();
        let file_key = file_key_of(&v);
        let shipped = if master_key_writer {
            let mk = MasterKey::from_bytes(bytes32(&v, "master_key_hex"));
            beebeeb_core::encrypt::encrypt_name_with_chunk_format(
                &mk,
                v["file_id"].as_str().unwrap(),
                filename,
                mime,
                pin,
            )
        } else {
            beebeeb_core::encrypt::encrypt_name_for(&file_key, filename, mime, pin)
        }
        .unwrap_or_else(|e| panic!("{name}: {e}"));
        let shipped: EncryptedBlob = serde_json::from_str(&shipped).unwrap();
        let published: EncryptedBlob = serde_json::from_str(v["name_encrypted"].as_str().unwrap()).unwrap();
        assert_eq!(
            shipped.ciphertext.len(),
            published.ciphertext.len(),
            "{name}: envelope length"
        );
        let name_key = FileKey::from_bytes(bytes32(&v, "name_key_hex"));
        let mut opened = 0;
        for (label, key) in [("raw file key", &file_key), ("name subkey", &name_key)] {
            let want = decrypt_metadata(key, &published).ok();
            let got = decrypt_metadata(key, &shipped).ok();
            assert_eq!(
                got, want,
                "{name}: the shipped writer and the vector differ under the {label}"
            );
            opened += usize::from(want.is_some());
        }
        assert_eq!(opened, 1, "{name}: the vector opens under exactly one key");
    }
}
