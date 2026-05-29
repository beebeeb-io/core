use beebeeb_core::encrypt::{decrypt_chunk, decrypt_metadata, encrypt_chunk, encrypt_metadata};
use beebeeb_core::file_request::{
    derive_request_wrap_key, open_request_upload, seal_to_request, unwrap_request_private, wrap_request_private,
};
use beebeeb_core::kdf::{derive_file_key, derive_master_key};
use beebeeb_core::opaque::{
    OpaqueEnvelope, compute_recovery_check, derive_share_key, derive_x25519_private, derive_x25519_public,
    x25519_shared_secret,
};
use beebeeb_core::recovery::{generate_recovery_phrase, recover_from_phrase};
use serde_json::{Value, json};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn main() {
    let mut vectors: Vec<Value> = Vec::new();

    // Vector 1: Master key derivation from password
    let password = "correct-horse-battery-staple";
    let salt = b"beebeeb-test-salt-16b";
    let mk = derive_master_key(password, salt).unwrap();
    vectors.push(json!({
        "name": "master_key_from_password",
        "password": password,
        "salt_hex": hex(salt),
        "expected_master_key_hex": hex(&mk.to_bytes()),
    }));

    // Vector 2: File key derivation
    let file_id = b"550e8400-e29b-41d4-a716-446655440000";
    let fk = derive_file_key(&mk, file_id);
    vectors.push(json!({
        "name": "file_key_derivation",
        "master_key_hex": hex(&mk.to_bytes()),
        "file_id_hex": hex(file_id),
        "expected_file_key_hex": hex(fk.as_bytes()),
    }));

    // Vector 3: Chunk encryption (fixed nonce for reproducibility)
    let plaintext = b"Hello, Beebeeb! This is a test.";
    let encrypted = encrypt_chunk(&fk, plaintext).unwrap();
    let nonce_hex = hex(&encrypted.nonce);
    let ciphertext_hex = hex(&encrypted.ciphertext);
    let decrypted = decrypt_chunk(&fk, &encrypted).unwrap();
    assert_eq!(&decrypted, plaintext);
    vectors.push(json!({
        "name": "chunk_encrypt_decrypt",
        "file_key_hex": hex(fk.as_bytes()),
        "plaintext_hex": hex(plaintext),
        "nonce_hex": nonce_hex,
        "ciphertext_hex": ciphertext_hex,
        "note": "nonce is random — use this vector for decrypt-only testing. To verify encrypt, check that decrypt(encrypt(plaintext)) == plaintext."
    }));

    // Vector 4: X25519 keypair derivation
    let x_priv = derive_x25519_private(&mk);
    let x_pub = derive_x25519_public(&x_priv);
    vectors.push(json!({
        "name": "x25519_identity_keypair",
        "master_key_hex": hex(&mk.to_bytes()),
        "expected_x25519_private_hex": hex(&*x_priv),
        "expected_x25519_public_hex": hex(&x_pub),
    }));

    // Vector 5: X25519 shared secret + share key
    let password_b = "bob-secure-password-2026";
    let mk_b = derive_master_key(password_b, salt).unwrap();
    let priv_b = derive_x25519_private(&mk_b);
    let pub_b = derive_x25519_public(&priv_b);
    let shared_ab = x25519_shared_secret(&x_priv, &pub_b).unwrap();
    let shared_ba = x25519_shared_secret(&priv_b, &x_pub).unwrap();
    assert_eq!(*shared_ab, *shared_ba);
    let share_key = derive_share_key(&shared_ab, file_id);
    vectors.push(json!({
        "name": "x25519_share_key_exchange",
        "alice_master_key_hex": hex(&mk.to_bytes()),
        "bob_master_key_hex": hex(&mk_b.to_bytes()),
        "alice_x25519_public_hex": hex(&x_pub),
        "bob_x25519_public_hex": hex(&pub_b),
        "expected_shared_secret_hex": hex(&*shared_ab),
        "file_id_hex": hex(file_id),
        "expected_share_key_hex": hex(&*share_key),
    }));

    // Vector 6: Recovery check
    let rc = compute_recovery_check(&mk);
    vectors.push(json!({
        "name": "recovery_check",
        "master_key_hex": hex(&mk.to_bytes()),
        "expected_recovery_check_hex": hex(&*rc),
    }));

    // Vector 7: Envelope round-trip
    let mk_bytes = mk.to_bytes();
    let envelope = OpaqueEnvelope {
        master_key: mk_bytes,
        x25519_private: *x_priv,
        recovery_check: *rc,
    };
    let envelope_bytes = envelope.to_bytes();
    vectors.push(json!({
        "name": "envelope_serialization",
        "master_key_hex": hex(&mk.to_bytes()),
        "x25519_private_hex": hex(&*x_priv),
        "recovery_check_hex": hex(&*rc),
        "expected_envelope_hex": hex(&envelope_bytes),
    }));

    // Vector 8: Recovery phrase
    let (phrase, recovered_mk) = generate_recovery_phrase().unwrap();
    let re_recovered = recover_from_phrase(&phrase).unwrap();
    assert_eq!(&recovered_mk.to_bytes(), &re_recovered.to_bytes());
    vectors.push(json!({
        "name": "recovery_phrase_roundtrip",
        "mnemonic": phrase,
        "expected_master_key_hex": hex(&recovered_mk.to_bytes()),
        "note": "mnemonic is random — use this to verify recover_from_phrase(phrase) produces the expected key."
    }));

    // Vector 9: Metadata (filename) encryption — uses the same file key as chunk encryption
    let metadata = "photos/vacation/2025-summer/IMG_0042.jpg";
    let encrypted_meta = encrypt_metadata(&fk, metadata).unwrap();
    let meta_nonce_hex = hex(&encrypted_meta.nonce);
    let meta_ciphertext_hex = hex(&encrypted_meta.ciphertext);
    let decrypted_meta = decrypt_metadata(&fk, &encrypted_meta).unwrap();
    assert_eq!(&decrypted_meta, metadata);
    vectors.push(json!({
        "name": "metadata_encrypt_decrypt",
        "file_key_hex": hex(fk.as_bytes()),
        "metadata": metadata,
        "nonce_hex": meta_nonce_hex,
        "ciphertext_hex": meta_ciphertext_hex,
        "note": "nonce is random — use this vector for decrypt-only testing. To verify encrypt, check that decrypt(encrypt(metadata)) == metadata."
    }));

    // Vector 10: File request seal/open (sealed-box / ECIES per request)
    // wrap_key is deterministic; e_pub / wrapped_key / wrapped_private use random
    // ephemeral keys + nonces, so they are for open/unwrap (decrypt-only) testing.
    let request_id = b"req-550e8400-e29b-41d4-a716-446655440099";
    let fr_wrap_key = derive_request_wrap_key(&mk, request_id);
    // Fixed request keypair so r_priv / r_pub are stable in the vector.
    let r_priv = [0x11u8; 32];
    let r_pub = derive_x25519_public(&r_priv);
    let (wrapped_private, wrap_nonce) = wrap_request_private(&mk, request_id, &r_priv).unwrap();
    let r_priv_check = unwrap_request_private(&mk, request_id, &wrapped_private, &wrap_nonce).unwrap();
    assert_eq!(*r_priv_check, r_priv);
    let fr_file_id = b"file-request-uploaded-file-001";
    let content_key = [0x42u8; 32];
    let sealed = seal_to_request(&r_pub, fr_file_id, &content_key).unwrap();
    let opened = open_request_upload(&r_priv, &sealed.e_pub, fr_file_id, &sealed.wrapped_key).unwrap();
    assert_eq!(*opened, content_key);
    vectors.push(json!({
        "name": "file_request_seal_open",
        "master_key_hex": hex(&mk.to_bytes()),
        "request_id_hex": hex(request_id),
        "expected_wrap_key_hex": hex(&*fr_wrap_key),
        "r_priv_hex": hex(&r_priv),
        "r_pub_hex": hex(&r_pub),
        "file_id_hex": hex(fr_file_id),
        "content_key_hex": hex(&content_key),
        "e_pub_hex": hex(&sealed.e_pub),
        "wrapped_key_hex": hex(&sealed.wrapped_key),
        "wrapped_private_hex": hex(&wrapped_private),
        "wrap_nonce_hex": hex(&wrap_nonce),
        "note": "wrap_key is deterministic. e_pub/wrapped_key (random ephemeral+nonce) verify open_request_upload(r_priv,e_pub,file_id,wrapped_key)==content_key; wrapped_private/wrap_nonce (random nonce) verify unwrap_request_private==r_priv."
    }));

    let output = json!({
        "version": 3,
        "generated_by": "beebeeb-core test vector generator",
        "vectors": vectors,
    });

    println!("{}", serde_json::to_string_pretty(&output).unwrap());
}
