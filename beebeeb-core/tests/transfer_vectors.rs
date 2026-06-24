//! Cross-binding test vectors + round-trip for the Constellation transfer channel.
//!
//! These exercise the EXACT functions the WASM (web) and UniFFI (Swift/Kotlin)
//! bindings wrap — `beebeeb_core::transfer::*` and `beebeeb_core::blob::*`. The
//! fixed `(shared_secret, session_id) -> transfer_key / sas_bytes` vector below
//! is the salt-mismatch guard: WASM and Swift can each assert byte-identical
//! derivation against these constants, so a binding that accidentally routed
//! through the salt-less `hash::derive_sas_bytes` (salt = None) instead of the
//! salted `transfer::derive_sas` (salt = session_id) would fail here.

use beebeeb_core::transfer::{
    decrypt_transfer, derive_sas, derive_shared_secret, derive_transfer_key, encrypt_transfer, generate_keypair,
    sas_to_words,
};

// A fixed (shared_secret, session_id) pin. These are NOT a real ECDH output —
// they are arbitrary fixed bytes chosen so every binding can reproduce the same
// HKDF expansion. If you change the salt/info of the transfer derivation, these
// constants change and this test fails (intended tripwire).
const FIXED_SHARED: [u8; 32] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
    0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
];
const FIXED_SESSION_ID: [u8; 16] = [
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
];

// HKDF-SHA256(ikm = FIXED_SHARED, salt = FIXED_SESSION_ID, info = "beebeeb-transfer-v1")
const EXPECTED_TRANSFER_KEY_HEX: &str = "47e363480624b26317cc25882f5274a1464cf44ac7658c792cbae33c0c0a62d1";
// HKDF-SHA256(ikm = FIXED_SHARED, salt = FIXED_SESSION_ID, info = "beebeeb-sas-v1") truncated to 4 bytes
const EXPECTED_SAS_HEX: &str = "8ef0155a";

#[test]
fn transfer_key_matches_fixed_vector() {
    let tk = derive_transfer_key(&FIXED_SHARED, &FIXED_SESSION_ID);
    assert_eq!(
        hex::encode(tk),
        EXPECTED_TRANSFER_KEY_HEX,
        "transfer key derivation drifted — WASM/Swift bindings will no longer agree. \
         Most likely a salt mismatch (salt MUST be session_id, info MUST be beebeeb-transfer-v1)."
    );
}

#[test]
fn sas_bytes_match_fixed_vector() {
    let sas = derive_sas(&FIXED_SHARED, &FIXED_SESSION_ID);
    assert_eq!(
        hex::encode(sas),
        EXPECTED_SAS_HEX,
        "SAS derivation drifted — cross-binding SAS words would mismatch. \
         salt MUST be session_id, info MUST be beebeeb-sas-v1 (NOT the salt-less hash::derive_sas_bytes)."
    );
}

#[test]
fn salted_sas_differs_from_saltless_hkdf() {
    // The transfer SAS is salted with session_id; the legacy salt-less helper
    // (hash::derive_sas_bytes, salt = None) is a DIFFERENT derivation. If a
    // binding wrapped the wrong one, the bytes would silently differ across
    // clients. Assert they are not equal so the distinction is load-bearing.
    let salted = derive_sas(&FIXED_SHARED, &FIXED_SESSION_ID);
    let saltless = beebeeb_core::hash::derive_sas_bytes(&FIXED_SHARED, b"beebeeb-sas-v1", 4);
    assert_ne!(
        salted.to_vec(),
        saltless,
        "salted transfer SAS must NOT equal the salt-less hash::derive_sas_bytes output"
    );
}

#[test]
fn full_transfer_roundtrip_both_sides_agree() {
    // Two ephemeral keypairs (sender + receiver), ECDH both directions, then
    // both derive the same transfer key from the shared secret + a shared
    // session id, encrypt on one side and decrypt on the other.
    let session_id = FIXED_SESSION_ID;

    let sender = generate_keypair();
    let receiver = generate_keypair();
    let sender_pub = sender.public;
    let receiver_pub = receiver.public;

    let sender_shared = derive_shared_secret(sender.secret, &receiver_pub);
    let receiver_shared = derive_shared_secret(receiver.secret, &sender_pub);
    assert_eq!(sender_shared, receiver_shared, "ECDH shared secret must match both ways");

    let sender_key = derive_transfer_key(&sender_shared, &session_id);
    let receiver_key = derive_transfer_key(&receiver_shared, &session_id);
    assert_eq!(sender_key, receiver_key, "derived transfer key must match both sides");

    // Payload round-trip: sender encrypts, receiver decrypts.
    let payload = b"constellation transfer payload \x00\xff with binary bytes";
    let blob = encrypt_transfer(&sender_key, payload).unwrap();
    let recovered = decrypt_transfer(&receiver_key, &blob).unwrap();
    assert_eq!(&recovered[..], &payload[..]);

    // Filename round-trip (UTF-8 with accents) over the same channel.
    let filename = "Steuererkl\u{00e4}rung 2025.pdf";
    let fn_blob = encrypt_transfer(&sender_key, filename.as_bytes()).unwrap();
    let fn_recovered = decrypt_transfer(&receiver_key, &fn_blob).unwrap();
    assert_eq!(String::from_utf8(fn_recovered).unwrap(), filename);
}

#[test]
fn sas_agrees_both_sides_and_detects_mitm() {
    let session_id = FIXED_SESSION_ID;

    let sender = generate_keypair();
    let receiver = generate_keypair();
    let sender_pub = sender.public;
    let receiver_pub = receiver.public;

    let sender_shared = derive_shared_secret(sender.secret, &receiver_pub);
    let receiver_shared = derive_shared_secret(receiver.secret, &sender_pub);

    let sender_sas = derive_sas(&sender_shared, &session_id);
    let receiver_sas = derive_sas(&receiver_shared, &session_id);
    assert_eq!(sender_sas, receiver_sas, "honest channel: both sides derive the same SAS");
    assert_eq!(
        sas_to_words(&sender_sas),
        sas_to_words(&receiver_sas),
        "SAS words must match on both screens for an honest channel"
    );

    // MITM: an active attacker substitutes their own key, so the receiver ends
    // up with a DIFFERENT shared secret. The SAS words must diverge.
    let mitm = generate_keypair();
    let mitm_pub = mitm.public;
    let receiver2 = generate_keypair();
    let receiver2_pub = receiver2.public;
    // Receiver ECDHs against the MITM key instead of the real sender key.
    let receiver_under_mitm = derive_shared_secret(receiver2.secret, &mitm_pub);
    let mitm_sas = derive_sas(&receiver_under_mitm, &session_id);
    // The honest sender's SAS (sender_shared) must not match the tampered one.
    // (Equality here would be a ~1-in-2^32 fluke; assert inequality.)
    let _ = receiver2_pub; // silence unused on some toolchains
    assert_ne!(
        sender_sas, mitm_sas,
        "a substituted (MITM) key must produce a different SAS"
    );
}
