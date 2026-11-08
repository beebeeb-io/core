//! The share safety number for web (`beebeeb_core::share_flow::safety`). Thin; public keys only.
//! Errors throw a `JsError` whose message is the core code (`invalid_input`).
use beebeeb_core::share_flow::safety;
use serde_json::json;
use wasm_bindgen::prelude::*;

use super::auth_flow::to_js;

/// `{ digits: "60 digits", peerFingerprint: "<SHA-256 of the peer key, hex>" }`.
#[wasm_bindgen(js_name = shareSafetyNumber)]
pub fn share_safety_number(
    own_user_id: &str,
    own_public_key: &[u8],
    peer_user_id: &str,
    peer_public_key: &[u8],
) -> Result<JsValue, JsError> {
    let n = safety::safety_number(own_user_id, own_public_key, peer_user_id, peer_public_key)
        .map_err(|e| JsError::new(e.code()))?;
    to_js(
        &json!({ "digits": n.digits, "peerFingerprint": n.peer_fingerprint.iter().map(|b| format!("{b:02x}")).collect::<String>() }),
    )
}
