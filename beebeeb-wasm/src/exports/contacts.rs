//! Core's email normalisation for the web client. No rule lives here: the form
//! is `beebeeb_core::contact_keys::normalize_email`. Web must use `normalizeEmail`
//! and never its own `String.prototype.trim`, which strips other characters. The
//! safety number a share shows is `shareSafetyNumber`.
use beebeeb_core::contact_keys;
use wasm_bindgen::prelude::*;

/// An account email in the server's stored form (Rust `str::trim`, then
/// Unicode lower case). Use it for every email that names a contact or a pin.
#[wasm_bindgen(js_name = normalizeEmail)]
pub fn normalize_email(raw: &str) -> String {
    contact_keys::normalize_email(raw)
}
