//! Move 2 — the metadata envelope (spec §16.2).
//!
//! Cases live in `test-vectors/consolidation/envelope.json`. The reader accepts
//! every stored form (base64, numeric arrays, the optional `cipher_suite`, the
//! mobile short `n`/`c` keys); the writer is core's frozen canonical form, so a
//! decoded envelope re-encodes byte for byte to `serialize_encrypted_metadata`.

use beebeeb_core::CoreError;
use beebeeb_core::metadata_wire::{MetadataEnvelope, serialize_encrypted_metadata};
use beebeeb_types::CipherSuite;
use serde_json::Value;

pub const CONCEPT: &str = "envelope";

fn hex_bytes(value: &Value, key: &str) -> Vec<u8> {
    let encoded = value[key]
        .as_str()
        .unwrap_or_else(|| panic!("{key} must be a hex string, got {}", value[key]));
    hex::decode(encoded).unwrap_or_else(|e| panic!("{key} is not hex: {e}"))
}

fn cipher_suite(value: &Value, case_id: &str) -> Option<CipherSuite> {
    match &value["cipher_suite"] {
        Value::Null => None,
        Value::String(name) if name == "V1Aes256Gcm" => Some(CipherSuite::V1Aes256Gcm),
        other => panic!("{case_id}: unexpected cipher_suite {other}"),
    }
}

#[test]
fn envelope_cases_match_core() {
    let cases = super::cases(CONCEPT);
    assert!(cases.len() >= 5, "move 2's named cases are all present");

    let (mut decoded, mut encoded, mut rejected) = (0, 0, 0);
    for case in &cases {
        let case_id = case["id"].as_str().expect("case id");
        match case["kind"].as_str().expect("case kind") {
            "decode" => {
                decoded += 1;
                let payload = case["payload"].as_str().expect("payload string");
                let envelope = MetadataEnvelope::decode(payload)
                    .unwrap_or_else(|e| panic!("{case_id}: expected a decode, got {e}"));
                let expected = &case["expected"];
                assert_eq!(
                    envelope.cipher_suite,
                    cipher_suite(expected, case_id),
                    "{case_id}: cipher_suite"
                );
                assert_eq!(envelope.nonce, hex_bytes(expected, "nonce_hex"), "{case_id}: nonce");
                assert_eq!(
                    envelope.ciphertext,
                    hex_bytes(expected, "ciphertext_hex"),
                    "{case_id}: ciphertext"
                );
                // The canonical writer is unchanged: re-encoding drops any suite
                // and matches the frozen writer's bytes exactly.
                assert_eq!(
                    envelope.encode(),
                    serialize_encrypted_metadata(&envelope.nonce, &envelope.ciphertext),
                    "{case_id}: the writer must stay byte-identical"
                );
            }
            "decode-error" => {
                rejected += 1;
                let payload = case["payload"].as_str().expect("payload string");
                let err = MetadataEnvelope::decode(payload).expect_err("this case must be rejected");
                assert!(
                    matches!(err, CoreError::InvalidInput(_)),
                    "{case_id}: expected InvalidInput, got {err:?}"
                );
            }
            "encode" => {
                encoded += 1;
                let envelope = MetadataEnvelope {
                    cipher_suite: cipher_suite(case, case_id),
                    nonce: hex_bytes(case, "nonce_hex"),
                    ciphertext: hex_bytes(case, "ciphertext_hex"),
                };
                let canonical = envelope.encode();
                assert_eq!(
                    canonical,
                    case["expected_canonical"].as_str().expect("expected_canonical"),
                    "{case_id}: canonical bytes"
                );
                assert_eq!(
                    canonical,
                    serialize_encrypted_metadata(&envelope.nonce, &envelope.ciphertext),
                    "{case_id}: the writer must stay byte-identical"
                );
                let roundtrip = MetadataEnvelope::decode(&canonical).expect("canonical output parses");
                assert_eq!(
                    (roundtrip.nonce, roundtrip.ciphertext),
                    (envelope.nonce.clone(), envelope.ciphertext.clone()),
                    "{case_id}: roundtrip"
                );
                assert_eq!(
                    roundtrip.cipher_suite, None,
                    "{case_id}: the canonical form carries no suite"
                );
            }
            other => panic!("{case_id}: unknown case kind `{other}`"),
        }
    }

    assert!(
        decoded >= 5 && encoded >= 1 && rejected >= 3,
        "decoded {decoded}, encoded {encoded}, rejected {rejected}"
    );
}
