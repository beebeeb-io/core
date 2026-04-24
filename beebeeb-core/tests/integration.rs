//! Integration tests for beebeeb-core: end-to-end encryption roundtrips,
//! recovery phrase flows, and key derivation edge cases.

use beebeeb_core::encrypt::{decrypt_chunk, decrypt_metadata, encrypt_chunk, encrypt_metadata};
use beebeeb_core::kdf::{derive_file_key, derive_master_key};
use beebeeb_core::recovery::{generate_recovery_phrase, recover_from_phrase};

// ---------------------------------------------------------------------------
// E2EE roundtrip: recovery phrase -> master key -> file key -> encrypt -> decrypt
// ---------------------------------------------------------------------------

#[test]
fn full_e2ee_roundtrip_single_chunk() {
    let (_phrase, master_key) = generate_recovery_phrase().unwrap();

    let file_id = b"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
    let file_key = derive_file_key(&master_key, file_id);

    let plaintext = b"This is a confidential document.";
    let blob = encrypt_chunk(&file_key, plaintext).unwrap();
    let decrypted = decrypt_chunk(&file_key, &blob).unwrap();

    assert_eq!(decrypted, plaintext, "decrypted data must match original plaintext");
}

#[test]
fn full_e2ee_roundtrip_multiple_chunks() {
    let (_phrase, master_key) = generate_recovery_phrase().unwrap();

    let file_id = b"file-multi-chunk-test";
    let file_key = derive_file_key(&master_key, file_id);

    // Simulate a 3-chunk file (like a ~3 MiB upload split into 1 MiB chunks)
    let chunks: Vec<Vec<u8>> = vec![
        vec![0xAA; 1024 * 1024], // 1 MiB
        vec![0xBB; 1024 * 1024], // 1 MiB
        vec![0xCC; 512 * 1024],  // 512 KiB (last chunk smaller)
    ];

    let encrypted: Vec<_> = chunks
        .iter()
        .map(|chunk| encrypt_chunk(&file_key, chunk).unwrap())
        .collect();

    // Decrypt and verify each chunk
    for (i, (blob, original)) in encrypted.iter().zip(chunks.iter()).enumerate() {
        let decrypted = decrypt_chunk(&file_key, blob).unwrap();
        assert_eq!(
            decrypted, *original,
            "chunk {i} must decrypt to its original plaintext"
        );
    }
}

// ---------------------------------------------------------------------------
// Metadata (filename) encryption roundtrip
// ---------------------------------------------------------------------------

#[test]
fn metadata_encrypt_decrypt_roundtrip() {
    let (_phrase, master_key) = generate_recovery_phrase().unwrap();
    let file_key = derive_file_key(&master_key, b"file-for-metadata-test");

    let filenames = [
        "photos/vacation/IMG_2024.jpg",
        "documents/tax-return-2025.pdf",
        "",                   // empty filename
        "a",                  // single char
        "emoji-in-name.txt",  // ASCII-only is fine
        &"x".repeat(4096),   // long filename
    ];

    for filename in &filenames {
        let blob = encrypt_metadata(&file_key, filename).unwrap();
        let recovered = decrypt_metadata(&file_key, &blob).unwrap();
        assert_eq!(&recovered, *filename, "metadata roundtrip failed for: {filename:?}");
    }
}

// ---------------------------------------------------------------------------
// Different file IDs produce different ciphertexts for same plaintext
// ---------------------------------------------------------------------------

#[test]
fn different_file_ids_produce_different_ciphertexts() {
    let (_phrase, master_key) = generate_recovery_phrase().unwrap();

    let plaintext = b"identical content in two files";

    let key_a = derive_file_key(&master_key, b"file-A");
    let key_b = derive_file_key(&master_key, b"file-B");

    let blob_a = encrypt_chunk(&key_a, plaintext).unwrap();
    let blob_b = encrypt_chunk(&key_b, plaintext).unwrap();

    // Different keys must produce different ciphertexts (with overwhelming probability,
    // since the keys are different AND the nonces are random).
    assert_ne!(
        blob_a.ciphertext, blob_b.ciphertext,
        "same plaintext encrypted under different file keys must produce different ciphertext"
    );

    // But each still decrypts correctly with its own key
    assert_eq!(decrypt_chunk(&key_a, &blob_a).unwrap(), plaintext);
    assert_eq!(decrypt_chunk(&key_b, &blob_b).unwrap(), plaintext);
}

// ---------------------------------------------------------------------------
// Wrong key fails to decrypt
// ---------------------------------------------------------------------------

#[test]
fn wrong_key_fails_to_decrypt_chunk() {
    let (_phrase, master_key) = generate_recovery_phrase().unwrap();

    let correct_key = derive_file_key(&master_key, b"correct-file");
    let wrong_key = derive_file_key(&master_key, b"wrong-file");

    let blob = encrypt_chunk(&correct_key, b"secret data").unwrap();

    let result = decrypt_chunk(&wrong_key, &blob);
    assert!(result.is_err(), "decryption with wrong key must fail");
}

#[test]
fn wrong_master_key_fails_to_decrypt() {
    let (_phrase_a, mk_a) = generate_recovery_phrase().unwrap();
    let (_phrase_b, mk_b) = generate_recovery_phrase().unwrap();

    let file_id = b"shared-file-id";
    let key_a = derive_file_key(&mk_a, file_id);
    let key_b = derive_file_key(&mk_b, file_id);

    let blob = encrypt_chunk(&key_a, b"user A's private data").unwrap();

    let result = decrypt_chunk(&key_b, &blob);
    assert!(
        result.is_err(),
        "decryption with a file key derived from a different master key must fail"
    );
}

#[test]
fn wrong_key_fails_to_decrypt_metadata() {
    let (_phrase, master_key) = generate_recovery_phrase().unwrap();

    let correct_key = derive_file_key(&master_key, b"correct");
    let wrong_key = derive_file_key(&master_key, b"wrong");

    let blob = encrypt_metadata(&correct_key, "secret-filename.pdf").unwrap();
    let result = decrypt_metadata(&wrong_key, &blob);
    assert!(result.is_err(), "metadata decryption with wrong key must fail");
}

// ---------------------------------------------------------------------------
// Recovery phrase roundtrip: generate -> recover -> same master key
// ---------------------------------------------------------------------------

#[test]
fn recovery_phrase_roundtrip_produces_same_master_key() {
    let (phrase, original_key) = generate_recovery_phrase().unwrap();

    // Recover the master key from the phrase
    let recovered_key = recover_from_phrase(&phrase).unwrap();

    assert_eq!(
        original_key.to_bytes(),
        recovered_key.to_bytes(),
        "recovered master key must match the original"
    );
}

#[test]
fn recovery_phrase_roundtrip_full_e2ee() {
    // Generate a recovery phrase and encrypt some data
    let (phrase, original_key) = generate_recovery_phrase().unwrap();

    let file_id = b"important-file";
    let file_key = derive_file_key(&original_key, file_id);
    let blob = encrypt_chunk(&file_key, b"critical user data").unwrap();

    // Simulate account recovery: user enters their phrase on a new device
    let recovered_key = recover_from_phrase(&phrase).unwrap();
    let recovered_file_key = derive_file_key(&recovered_key, file_id);
    let decrypted = decrypt_chunk(&recovered_file_key, &blob).unwrap();

    assert_eq!(
        decrypted,
        b"critical user data",
        "data encrypted before recovery must be decryptable after recovery"
    );
}

#[test]
fn different_recovery_phrases_produce_different_keys() {
    let (phrase_a, key_a) = generate_recovery_phrase().unwrap();
    let (phrase_b, key_b) = generate_recovery_phrase().unwrap();

    assert_ne!(phrase_a, phrase_b, "two generated phrases should differ");
    assert_ne!(
        key_a.to_bytes(),
        key_b.to_bytes(),
        "different phrases must produce different master keys"
    );
}

#[test]
fn invalid_recovery_phrase_is_rejected() {
    let result = recover_from_phrase("this is not a valid bip39 recovery phrase string");
    assert!(result.is_err(), "invalid phrase must be rejected");
}

// ---------------------------------------------------------------------------
// Password-derived master key: determinism
// ---------------------------------------------------------------------------

#[test]
fn password_derived_key_is_deterministic() {
    let password = "correct horse battery staple";
    let salt = b"salt-of-16-bytes!";

    let mk1 = derive_master_key(password, salt).unwrap();
    let mk2 = derive_master_key(password, salt).unwrap();

    assert_eq!(mk1.to_bytes(), mk2.to_bytes());
}

#[test]
fn password_derived_key_encrypts_and_decrypts() {
    let mk = derive_master_key("my-strong-password", b"unique-salt-16bytes").unwrap();
    let file_key = derive_file_key(&mk, b"file-001");

    let plaintext = b"encrypted with password-derived key";
    let blob = encrypt_chunk(&file_key, plaintext).unwrap();
    let decrypted = decrypt_chunk(&file_key, &blob).unwrap();

    assert_eq!(decrypted, plaintext);
}
