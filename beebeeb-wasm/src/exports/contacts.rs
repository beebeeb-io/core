//! Contact safety numbers (relayed-key pinning design, D1/D2) for the web
//! client, so it shows the same number as the apps (core #74 crypto review,
//! P2-7). No rule lives here: the format is `beebeeb_core::contact_keys`,
//! proved by `test-vectors/safety_number.json`. Web must use `normalizeEmail`
//! and never its own `String.prototype.trim`, which strips other characters.
use beebeeb_core::contact_keys;
use wasm_bindgen::prelude::*;

/// The 60-digit safety number two contacts compare (12 groups of 5, joined).
/// Each email is normalised by core first; keys are the contacts' 32-byte
/// X25519 public keys. The same on both sides whatever the argument order.
#[wasm_bindgen(js_name = safetyNumber)]
pub fn safety_number(
    email_a: &str,
    public_key_a: &[u8],
    email_b: &str,
    public_key_b: &[u8],
) -> Result<String, JsError> {
    let key = |bytes: &[u8]| -> Result<[u8; 32], JsError> {
        bytes
            .try_into()
            .map_err(|_| JsError::new("public key must be 32 bytes"))
    };
    contact_keys::safety_number(email_a, &key(public_key_a)?, email_b, &key(public_key_b)?)
        .map_err(|e| JsError::new(&e.to_string()))
}

/// An account email in the server's stored form (Rust `str::trim`, then
/// Unicode lower case). Use it for every email that names a contact or a pin.
#[wasm_bindgen(js_name = normalizeEmail)]
pub fn normalize_email(raw: &str) -> String {
    contact_keys::normalize_email(raw)
}
