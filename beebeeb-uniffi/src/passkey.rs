//! Passkey vault exports (B15): the core primitive and the ceremony steps for mobile. The platform call
//! (ASAuthorization / Credential Manager) stays in the app: it takes the options out of a step and hands the
//! response and the PRF output back in. Steps speak JSON (the core `passkey::ceremony` types); the vault key only
//! ever crosses as a [`MasterKeyHandle`], never as bytes.

use super::*;
use beebeeb_core::passkey::{self, ceremony};

fn json_err(_: serde_json::Error) -> CryptoError {
    CryptoError::InvalidInput {
        detail: "passkey: malformed JSON".into(),
    }
}

fn step_err(e: ceremony::PasskeyError) -> CryptoError {
    CryptoError::InvalidInput {
        detail: e.code().into(),
    }
}

/// The PRF eval input to pass as `prf.eval.first` to an API that takes PRF inputs (it hashes them itself).
#[uniffi::export]
pub fn passkey_prf_eval_input() -> Vec<u8> {
    passkey::prf_eval_input().to_vec()
}

/// The CTAP2 hmac-secret salt, for an API that takes raw hmac-secret salts (the PRF hash already applied).
#[uniffi::export]
pub fn passkey_hmac_secret_salt() -> Vec<u8> {
    passkey::hmac_secret_salt().to_vec()
}

/// Wrap the vault key under a PRF output: the escrow blob for `POST /api/v1/auth/vault-key-escrow`.
#[uniffi::export]
pub fn passkey_wrap_vault_key(prf_output: Vec<u8>, master_key: Arc<MasterKeyHandle>) -> Result<Vec<u8>, CryptoError> {
    let prf = passkey::PrfOutput::from_slice(&zeroize::Zeroizing::new(prf_output))?;
    master_key
        .with_key(|mk| passkey::wrap_vault_key(&prf, mk))?
        .map_err(Into::into)
}

/// Open an escrow blob with a PRF output. The vault key comes back as a handle.
#[uniffi::export]
pub fn passkey_unwrap_vault_key(prf_output: Vec<u8>, blob: Vec<u8>) -> Result<Arc<MasterKeyHandle>, CryptoError> {
    let prf = passkey::PrfOutput::from_slice(&zeroize::Zeroizing::new(prf_output))?;
    Ok(MasterKeyHandle::new(passkey::unwrap_vault_key(&prf, &blob)?))
}

/// `register-start`'s answer → `RegistrationStart` JSON (options for the platform's create call).
#[uniffi::export]
pub fn passkey_parse_registration_start(answer_json: String) -> Result<String, CryptoError> {
    let answer: serde_json::Value = serde_json::from_str(&answer_json).map_err(json_err)?;
    serde_json::to_string(&ceremony::parse_registration_start(&answer).map_err(step_err)?).map_err(json_err)
}

/// `RegistrationStart` JSON + `NativeAttestation` JSON → `register-finish` body.
#[uniffi::export]
pub fn passkey_registration_finish_body(
    start_json: String,
    attestation_json: String,
    name: Option<String>,
) -> Result<String, CryptoError> {
    let start: ceremony::RegistrationStart = serde_json::from_str(&start_json).map_err(json_err)?;
    let att: ceremony::NativeAttestation = serde_json::from_str(&attestation_json).map_err(json_err)?;
    Ok(ceremony::registration_finish_body(&start, &att, name.as_deref()).to_string())
}

/// The `vault-key-escrow` body for a credential id and a blob from [`passkey_wrap_vault_key`].
#[uniffi::export]
pub fn passkey_escrow_body(credential_id: Vec<u8>, blob: Vec<u8>) -> String {
    ceremony::escrow_body(&credential_id, &blob).to_string()
}

/// `login-start`'s answer → `AssertionStart` JSON (options for the platform's get call).
#[uniffi::export]
pub fn passkey_parse_assertion_start(answer_json: String) -> Result<String, CryptoError> {
    let answer: serde_json::Value = serde_json::from_str(&answer_json).map_err(json_err)?;
    serde_json::to_string(&ceremony::parse_assertion_start(&answer).map_err(step_err)?).map_err(json_err)
}

/// `AssertionStart` JSON + `NativeAssertion` JSON → `login-finish` body.
#[uniffi::export]
pub fn passkey_assertion_finish_body(start_json: String, assertion_json: String) -> Result<String, CryptoError> {
    let start: ceremony::AssertionStart = serde_json::from_str(&start_json).map_err(json_err)?;
    let a: ceremony::NativeAssertion = serde_json::from_str(&assertion_json).map_err(json_err)?;
    Ok(ceremony::assertion_finish_body(&start, &a).to_string())
}

/// The escrow blob from `GET /api/v1/auth/vault-key-escrow/{id}`'s answer.
#[uniffi::export]
pub fn passkey_parse_escrow(answer_json: String) -> Result<Vec<u8>, CryptoError> {
    let answer: serde_json::Value = serde_json::from_str(&answer_json).map_err(json_err)?;
    ceremony::parse_escrow(&answer).map_err(step_err)
}

#[cfg(test)]
mod passkey_binding_tests {
    use super::*;

    #[test]
    fn passkey_binding_wraps_into_a_handle_and_parses_steps() {
        let mk = MasterKeyHandle::from_keychain_bytes(vec![7u8; 32]).unwrap();
        let blob = passkey_wrap_vault_key(vec![1u8; 32], mk).unwrap();
        assert_eq!(blob.len(), 60);
        let back = passkey_unwrap_vault_key(vec![1u8; 32], blob.clone()).unwrap();
        assert_eq!(back.with_key(|k| k.to_bytes()).unwrap(), [7u8; 32]);
        assert!(passkey_unwrap_vault_key(vec![2u8; 32], blob).is_err());
        assert_eq!(passkey_hmac_secret_salt().len(), 32);
        let answer = r#"{"publicKey":{"challenge":"AAAA","rpId":"beebeeb.io"},"auth_state":"s","user_id":"u"}"#;
        let start = passkey_parse_assertion_start(answer.into()).unwrap();
        let assertion = r#"{"credential_id":[1],"authenticator_data":[2],"client_data_json":[123,125],"signature":[3],"user_handle":null}"#;
        let body: serde_json::Value =
            serde_json::from_str(&passkey_assertion_finish_body(start, assertion.into()).unwrap()).unwrap();
        assert_eq!(body["credential"]["id"], "AQ");
        assert!(passkey_parse_assertion_start("{}".into()).is_err());
    }
}
