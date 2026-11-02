//! Move 2 — the JSON metadata envelope, both directions (web W-P3-2).
//!
//! The decoder accepts every stored form core accepts (base64 strings, legacy
//! numeric arrays, the mobile short `n`/`c` keys, an absent/`null`/named
//! `cipher_suite`); the encoder is core's frozen canonical writer, so the bytes
//! this returns are the bytes core and every other client write.

use beebeeb_core::metadata_wire::MetadataEnvelope;
use serde::Serialize;
use wasm_bindgen::prelude::*;

/// Serialize a nonce + ciphertext pair into the canonical wire format.
///
/// Returns `{"ciphertext":"<base64>","nonce":"<base64>"}` — byte-identical to
/// `beebeeb_core::metadata_wire::serialize_encrypted_metadata`. Never emits a
/// `cipher_suite`: the writer is frozen.
#[wasm_bindgen(js_name = encodeMetadataEnvelope)]
pub fn encode_metadata_envelope(nonce: &[u8], ciphertext: &[u8]) -> String {
    beebeeb_core::metadata_wire::serialize_encrypted_metadata(nonce, ciphertext)
}

/// The decoded envelope as JS sees it.
///
/// `nonce` and `ciphertext` are byte arrays (`Uint8Array.from(...)` in the
/// client); `cipher_suite` is `"V1Aes256Gcm"` when the payload named it and
/// `null` when it did not (which means "assume V1", exactly as core reads it).
#[derive(Serialize)]
struct EnvelopeJs {
    cipher_suite: Option<beebeeb_types::CipherSuite>,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
}

/// Decode any accepted stored form of the metadata envelope.
///
/// Throws an `Error` whose message starts with `invalid input:` — the core
/// error's own text — for invalid JSON, a missing/non-byte field, an unknown
/// cipher suite, or a `null` field. Fields core does not know are ignored.
#[wasm_bindgen(js_name = decodeMetadataEnvelope)]
pub fn decode_metadata_envelope(payload: &str) -> Result<JsValue, JsError> {
    let envelope = MetadataEnvelope::decode(payload).map_err(|e| JsError::new(&e.to_string()))?;
    // `serialize_missing_as_null` keeps `cipher_suite: null` an explicit null in
    // the JS object (serde_wasm_bindgen would otherwise drop the key), so a
    // caller can distinguish "no suite named" from a typo.
    let serializer = serde_wasm_bindgen::Serializer::new().serialize_missing_as_null(true);
    Ok(EnvelopeJs {
        cipher_suite: envelope.cipher_suite,
        nonce: envelope.nonce,
        ciphertext: envelope.ciphertext,
    }
    .serialize(&serializer)?)
}
