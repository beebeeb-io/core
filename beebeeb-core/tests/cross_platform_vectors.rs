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
use beebeeb_core::kdf::{FileKey, MasterKey, derive_file_key, derive_master_key};
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
        private, expected_private,
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
    let shared_ab = x25519_shared_secret(&priv_a, &pub_b);
    let shared_ba = x25519_shared_secret(&priv_b, &pub_a);
    assert_eq!(shared_ab, shared_ba, "x25519 DH must be commutative");
    assert_eq!(
        shared_ab, expected_shared_secret,
        "x25519_share_key_exchange: shared secret does not match vector"
    );

    // Share key derivation
    let share_key = derive_share_key(&shared_ab, &file_id);
    assert_eq!(
        share_key, expected_share_key,
        "x25519_share_key_exchange: share key does not match vector"
    );
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
    assert_eq!(rc, expected, "recovery_check: computed value does not match vector");
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
// 16. Version guard — fail loudly if vectors.json format changes unexpectedly
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
        version, 2,
        "vectors.json version mismatch — expected 2, got {version}. \
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
    ];
    for name in &required {
        assert!(names.contains(name), "vectors.json is missing required vector '{name}'");
    }
}
