//! The share safety number for web (`beebeeb_core::share_flow::safety`). Thin; public keys only.
//! Errors throw a `JsError` whose message is the core code (`invalid_input`).
use beebeeb_core::kdf::MasterKey;
use beebeeb_core::share_flow::{ShareFlowError, safety};
use serde_json::json;
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

use super::auth_flow::to_js;

/// `shareSafetyNumber(masterKey, ownUserId, peerUserId, peerPublicKey)` →
/// `{ digits: "60 digits", peerFingerprint: "<SHA-256 of the peer key, hex>" }`. The own sharing
/// key is derived from the master key in core; `peerPublicKey` is the key the share was sealed to.
#[wasm_bindgen(js_name = shareSafetyNumber)]
pub fn share_safety_number(
    master_key: &[u8],
    own_user_id: &str,
    peer_user_id: &str,
    peer_public_key: &[u8],
) -> Result<JsValue, JsError> {
    let bytes: Zeroizing<[u8; 32]> = Zeroizing::new(
        master_key
            .try_into()
            .map_err(|_| JsError::new(ShareFlowError::InvalidInput("key length").code()))?,
    );
    let master = MasterKey::from_bytes(*bytes);
    let n = safety::safety_number(&master, own_user_id, peer_user_id, peer_public_key)
        .map_err(|e| JsError::new(e.code()))?;
    to_js(
        &json!({ "digits": n.digits, "peerFingerprint": n.peer_fingerprint.iter().map(|b| format!("{b:02x}")).collect::<String>() }),
    )
}
