//! Passkey vault exports (B15) for web. Web keeps its TS implementation for now (switching is a later web task); the
//! vectors prove both give the same bytes. `navigator.credentials` stays in web; these take its options out and its
//! response and PRF output back in. Steps speak JSON (the core `passkey::ceremony` types).

use super::*;
use beebeeb_core::passkey::{self, ceremony};

fn wrap_inner(prf_output: &[u8], master_key: &[u8]) -> Result<Vec<u8>, String> {
    let prf = passkey::PrfOutput::from_slice(prf_output).map_err(|e| e.to_string())?;
    let mk_bytes = zeroize::Zeroizing::new(
        <[u8; 32]>::try_from(master_key).map_err(|_| "master_key must be exactly 32 bytes".to_string())?,
    );
    let mk = kdf::MasterKey::from_bytes(*mk_bytes);
    passkey::wrap_vault_key(&prf, &mk).map_err(|e| e.to_string())
}

fn unwrap_inner(prf_output: &[u8], blob: &[u8]) -> Result<Vec<u8>, String> {
    let prf = passkey::PrfOutput::from_slice(prf_output).map_err(|e| e.to_string())?;
    let mk = passkey::unwrap_vault_key(&prf, blob).map_err(|e| e.to_string())?;
    Ok(mk.to_bytes().to_vec())
}

fn json_step(
    answer_json: &str,
    step: impl Fn(&serde_json::Value) -> Result<serde_json::Value, ceremony::PasskeyError>,
) -> Result<String, String> {
    let answer: serde_json::Value =
        serde_json::from_str(answer_json).map_err(|_| "passkey: malformed JSON".to_string())?;
    step(&answer).map(|v| v.to_string()).map_err(|e| e.code().to_string())
}

/// The PRF eval input web passes as `prf.eval.first`.
#[wasm_bindgen(js_name = passkeyPrfEvalInput)]
pub fn passkey_prf_eval_input() -> Vec<u8> {
    passkey::prf_eval_input().to_vec()
}

/// Wrap the vault key under a PRF output: the escrow blob (`nonce || ct || tag`).
#[wasm_bindgen(js_name = passkeyWrapVaultKey)]
pub fn passkey_wrap_vault_key(prf_output: &[u8], master_key: &[u8]) -> Result<Vec<u8>, JsError> {
    wrap_inner(prf_output, master_key).map_err(|e| JsError::new(&e))
}

/// Open an escrow blob with a PRF output. Returns the 32-byte vault key (the WASM boundary's raw-key convention).
#[wasm_bindgen(js_name = passkeyUnwrapVaultKey)]
pub fn passkey_unwrap_vault_key(prf_output: &[u8], blob: &[u8]) -> Result<Vec<u8>, JsError> {
    unwrap_inner(prf_output, blob).map_err(|e| JsError::new(&e))
}

/// `register-start`'s answer → `RegistrationStart` JSON.
#[wasm_bindgen(js_name = passkeyParseRegistrationStart)]
pub fn passkey_parse_registration_start(answer_json: &str) -> Result<String, JsError> {
    json_step(answer_json, |a| {
        ceremony::parse_registration_start(a).map(|s| serde_json::to_value(s).unwrap_or_default())
    })
    .map_err(|e| JsError::new(&e))
}

/// `login-start`'s answer → `AssertionStart` JSON.
#[wasm_bindgen(js_name = passkeyParseAssertionStart)]
pub fn passkey_parse_assertion_start(answer_json: &str) -> Result<String, JsError> {
    json_step(answer_json, |a| {
        ceremony::parse_assertion_start(a).map(|s| serde_json::to_value(s).unwrap_or_default())
    })
    .map_err(|e| JsError::new(&e))
}

/// The `vault-key-escrow` body for a credential id and a blob.
#[wasm_bindgen(js_name = passkeyEscrowBody)]
pub fn passkey_escrow_body(credential_id: &[u8], blob: &[u8]) -> String {
    ceremony::escrow_body(credential_id, blob).to_string()
}

#[cfg(test)]
mod passkey_export_tests {
    use super::*;

    #[test]
    fn passkey_wasm_roundtrip_and_steps() {
        let blob = wrap_inner(&[1u8; 32], &[7u8; 32]).unwrap();
        assert_eq!(unwrap_inner(&[1u8; 32], &blob).unwrap(), vec![7u8; 32]);
        assert!(unwrap_inner(&[2u8; 32], &blob).is_err());
        assert!(wrap_inner(&[1u8; 31], &[7u8; 32]).is_err());
        let ok = json_step(
            r#"{"publicKey":{"challenge":"AAAA","rpId":"beebeeb.io"},"auth_state":"s","user_id":"u"}"#,
            |a| ceremony::parse_assertion_start(a).map(|s| serde_json::to_value(s).unwrap()),
        )
        .unwrap();
        assert!(ok.contains("\"rp_id\":\"beebeeb.io\""));
        assert_eq!(
            json_step("{}", |a| ceremony::parse_assertion_start(a)
                .map(|s| serde_json::to_value(s).unwrap())),
            Err("passkey_malformed".to_string())
        );
    }
}
