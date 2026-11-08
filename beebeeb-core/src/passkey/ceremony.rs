//! The passkey ceremonies' wire, without I/O: the server's options in, the platform-neutral options a native WebAuthn
//! call needs out; the platform's response in, the server's finish body out.
//!
//! The server is webauthn-rs (`repos/server/beebeeb-api/src/routes/passkeys.rs`, `routes/vault_keys.rs`); every
//! shape here matches what the web client sends today (`repos/web/src/lib/api-passkeys.ts`), so the server sees no
//! difference between a browser and a native client. Binary fields are base64url without padding on the WebAuthn
//! side; the escrow blob is standard base64 (web: `toBase64`).
//!
//! A native platform API builds no `clientDataJSON` of its own (webauthn.dll takes it from the caller), so core
//! builds it: [`CreationOptions::client_data_json`] / [`RequestOptions::client_data_json`]. The server checks the
//! challenge, the type and the origin in it.

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use zeroize::Zeroizing;

use super::{hmac_secret_salt, prf_eval_input};

/// Why a passkey step failed, as a code a client maps to its own words. Never carries a server body, a key, a token
/// or a URL.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PasskeyError {
    /// The person dismissed the platform prompt, or it timed out.
    #[error("passkey_cancelled")]
    Cancelled,
    /// The platform has no passkey support (or this OS is too old for it).
    #[error("passkey_unavailable")]
    Unavailable,
    /// The platform call failed for another reason; `code` is the platform's own error name.
    #[error("passkey_platform_error")]
    Platform { code: String },
    /// The server refused the request; `status` is the HTTP status, `code` the server's `error` field when it is a
    /// plain identifier.
    #[error("passkey_server_error")]
    Server { status: u16, code: Option<String> },
    /// The server needs a fresh step-up confirmation first (403 `confirmation_required`).
    #[error("passkey_confirmation_required")]
    ConfirmationRequired,
    /// The session is not valid (401).
    #[error("passkey_unauthorized")]
    Unauthorized,
    /// The network call did not complete.
    #[error("passkey_network")]
    Network,
    /// A server or platform answer did not have the expected shape.
    #[error("passkey_malformed: {0}")]
    Malformed(&'static str),
    /// The escrow blob did not open with this passkey's PRF output.
    #[error("passkey_vault_unwrap_failed")]
    VaultUnwrap,
    /// Wrapping the vault key failed.
    #[error("passkey_vault_wrap_failed")]
    VaultWrap,
    /// The server's relying-party id is not the one the host expects (or is `localhost` outside a development
    /// build). Nothing was handed to the platform.
    #[error("passkey_rp_mismatch")]
    RpMismatch,
    /// The step-up that guards adding or removing a passkey failed; `code` is [`AuthFlowError::code`].
    ///
    /// [`AuthFlowError::code`]: crate::auth_flow::AuthFlowError::code
    #[error("passkey_step_up_failed")]
    StepUp { code: &'static str },
}

impl PasskeyError {
    /// A stable, lower-case code for a client's error mapping (crypto rule 9: errors map to codes).
    pub fn code(&self) -> &'static str {
        match self {
            Self::Cancelled => "passkey_cancelled",
            Self::Unavailable => "passkey_unavailable",
            Self::Platform { .. } => "passkey_platform_error",
            Self::Server { .. } => "passkey_server_error",
            Self::ConfirmationRequired => "passkey_confirmation_required",
            Self::Unauthorized => "passkey_unauthorized",
            Self::Network => "passkey_network",
            Self::Malformed(_) => "passkey_malformed",
            Self::VaultUnwrap => "passkey_vault_unwrap_failed",
            Self::VaultWrap => "passkey_vault_wrap_failed",
            Self::RpMismatch => "passkey_rp_mismatch",
            Self::StepUp { .. } => "passkey_step_up_failed",
        }
    }
}

/// base64url without padding (WebAuthn's encoding on this wire).
pub fn b64url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Decode base64url, with or without padding.
pub fn from_b64url(text: &str) -> Result<Vec<u8>, PasskeyError> {
    URL_SAFE_NO_PAD
        .decode(text.trim_end_matches('='))
        .map_err(|_| PasskeyError::Malformed("base64url"))
}

/// The relying party the HOST expects (its own build configuration, never the server's answer). The server's
/// `rp.id` / `rpId` must equal it exactly, or the parse refuses with [`PasskeyError::RpMismatch`], so a server can
/// never make a client claim another origin.
///
/// `localhost` (the server's development default) is accepted only in a debug build or when the host passes the
/// explicit development flag ([`ExpectedRp::development`]); a release build without it never claims
/// `http://localhost:*`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedRp {
    rp_id: String,
    allow_localhost: bool,
}

impl ExpectedRp {
    /// The production relying party, e.g. `beebeeb.io`.
    pub fn new(rp_id: impl Into<String>) -> Self {
        Self {
            rp_id: rp_id.into(),
            allow_localhost: false,
        }
    }

    /// A development host: `localhost` is accepted even in a release build.
    pub fn development(rp_id: impl Into<String>) -> Self {
        Self {
            rp_id: rp_id.into(),
            allow_localhost: true,
        }
    }

    /// The expected relying-party id.
    pub fn rp_id(&self) -> &str {
        &self.rp_id
    }

    /// Check the server's `rp_id` and return the origin a native client claims in `clientDataJSON`:
    /// `https://<rp id>`, or for `localhost` the web dev server `http://localhost:5173` (`build_webauthn` in the
    /// server).
    pub fn origin_for(&self, server_rp_id: &str) -> Result<String, PasskeyError> {
        self.origin_for_build(server_rp_id, cfg!(debug_assertions))
    }

    fn origin_for_build(&self, server_rp_id: &str, debug_build: bool) -> Result<String, PasskeyError> {
        if self.rp_id.is_empty() || server_rp_id != self.rp_id {
            return Err(PasskeyError::RpMismatch);
        }
        if server_rp_id == "localhost" {
            if self.allow_localhost || debug_build {
                return Ok("http://localhost:5173".to_string());
            }
            return Err(PasskeyError::RpMismatch);
        }
        Ok(format!("https://{server_rp_id}"))
    }

    #[cfg(test)]
    pub(crate) fn origin_for_release_build(&self, server_rp_id: &str) -> Result<String, PasskeyError> {
        self.origin_for_build(server_rp_id, false)
    }
}

fn client_data_json(kind: &str, challenge: &[u8], origin: &str) -> Vec<u8> {
    // Same member order as a browser writes it; the server parses JSON, so the order is not load-bearing.
    serde_json::to_vec(&json!({
        "type": kind,
        "challenge": b64url(challenge),
        "origin": origin,
        "crossOrigin": false,
    }))
    .unwrap_or_default()
}

/// The PRF parts every ceremony carries: the browser's eval input and the native `hmac-secret` salt (module docs of
/// [`super`] say which one a platform takes).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrfSalts {
    pub prf_eval_input: Vec<u8>,
    pub hmac_secret_salt: Vec<u8>,
}

impl PrfSalts {
    fn new() -> Self {
        Self {
            prf_eval_input: prf_eval_input().to_vec(),
            hmac_secret_salt: hmac_secret_salt().to_vec(),
        }
    }
}

/// What a native `create` call needs, decoded from the server's `register-start` answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreationOptions {
    pub rp_id: String,
    pub rp_name: String,
    pub user_id: Vec<u8>,
    pub user_name: String,
    pub user_display_name: String,
    pub challenge: Vec<u8>,
    /// COSE algorithm ids, in the server's order of preference.
    pub algorithms: Vec<i32>,
    pub exclude_credentials: Vec<Vec<u8>>,
    pub timeout_ms: u32,
    /// `required`, `preferred` or `discouraged`.
    pub user_verification: String,
    /// `required`, `preferred` or `discouraged`.
    pub resident_key: String,
    /// `none`, `indirect`, `direct` or `enterprise`.
    pub attestation: String,
    /// `platform`, `cross-platform` or `None` for either.
    pub authenticator_attachment: Option<String>,
    pub origin: String,
    pub prf: PrfSalts,
}

impl CreationOptions {
    /// The `clientDataJSON` a native caller hands its platform and then returns in the attestation.
    pub fn client_data_json(&self) -> Vec<u8> {
        client_data_json("webauthn.create", &self.challenge, &self.origin)
    }
}

/// A started registration: the server's `reg_id` (it holds the ceremony state itself) and the options.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistrationStart {
    pub reg_id: String,
    pub options: CreationOptions,
}

/// The `publicKey` object, whether the answer wraps it once (`{publicKey: {...}}`) or twice, as web's
/// `serverOptsToCreateOptions` also accepts.
fn public_key(start: &Value) -> Option<&Value> {
    let pk = start.get("publicKey")?;
    if pk.get("challenge").is_some() {
        Some(pk)
    } else {
        pk.get("publicKey")
    }
}

fn str_field<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    v.get(key).and_then(Value::as_str)
}

fn credential_ids(list: Option<&Value>) -> Result<Vec<Vec<u8>>, PasskeyError> {
    let Some(list) = list.and_then(Value::as_array) else {
        return Ok(Vec::new());
    };
    list.iter()
        .map(|c| from_b64url(str_field(c, "id").ok_or(PasskeyError::Malformed("credential id"))?))
        .collect()
}

/// Read `POST /api/v1/auth/passkey/register-start`'s answer. The server's `rp.id` must be `expected`'s.
pub fn parse_registration_start(answer: &Value, expected: &ExpectedRp) -> Result<RegistrationStart, PasskeyError> {
    let reg_id = str_field(answer, "reg_id").ok_or(PasskeyError::Malformed("reg_id"))?;
    let pk = public_key(answer).ok_or(PasskeyError::Malformed("publicKey"))?;
    let rp = pk.get("rp").ok_or(PasskeyError::Malformed("rp"))?;
    let user = pk.get("user").ok_or(PasskeyError::Malformed("user"))?;
    let rp_id = str_field(rp, "id").ok_or(PasskeyError::Malformed("rp.id"))?.to_string();
    let origin = expected.origin_for(&rp_id)?;
    let selection = pk.get("authenticatorSelection");
    let algorithms = pk
        .get("pubKeyCredParams")
        .and_then(Value::as_array)
        .ok_or(PasskeyError::Malformed("pubKeyCredParams"))?
        .iter()
        .filter_map(|p| p.get("alg").and_then(Value::as_i64))
        .filter_map(|alg| i32::try_from(alg).ok())
        .collect::<Vec<_>>();
    if algorithms.is_empty() {
        return Err(PasskeyError::Malformed("pubKeyCredParams"));
    }
    let resident_key = selection
        .and_then(|s| str_field(s, "residentKey"))
        .map(str::to_string)
        .unwrap_or_else(|| {
            let required = selection
                .and_then(|s| s.get("requireResidentKey"))
                .and_then(Value::as_bool)
                .unwrap_or(false);
            if required { "required" } else { "discouraged" }.to_string()
        });
    Ok(RegistrationStart {
        reg_id: reg_id.to_string(),
        options: CreationOptions {
            origin,
            rp_name: str_field(rp, "name").unwrap_or("Beebeeb").to_string(),
            rp_id,
            user_id: from_b64url(str_field(user, "id").ok_or(PasskeyError::Malformed("user.id"))?)?,
            user_name: str_field(user, "name").unwrap_or_default().to_string(),
            user_display_name: str_field(user, "displayName").unwrap_or_default().to_string(),
            challenge: from_b64url(str_field(pk, "challenge").ok_or(PasskeyError::Malformed("challenge"))?)?,
            algorithms,
            exclude_credentials: credential_ids(pk.get("excludeCredentials"))?,
            timeout_ms: pk.get("timeout").and_then(Value::as_u64).unwrap_or(60_000) as u32,
            user_verification: selection
                .and_then(|s| str_field(s, "userVerification"))
                .unwrap_or("preferred")
                .to_string(),
            resident_key,
            attestation: str_field(pk, "attestation").unwrap_or("none").to_string(),
            authenticator_attachment: selection
                .and_then(|s| str_field(s, "authenticatorAttachment"))
                .map(str::to_string),
            prf: PrfSalts::new(),
        },
    })
}

/// A platform's answer to `create`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeAttestation {
    pub credential_id: Vec<u8>,
    pub attestation_object: Vec<u8>,
    /// Exactly the bytes the platform signed over (for a native caller: [`CreationOptions::client_data_json`]).
    pub client_data_json: Vec<u8>,
}

/// The body of `POST /api/v1/auth/passkey/register-finish` (web: `finishPasskeyRegistration`).
pub fn registration_finish_body(start: &RegistrationStart, att: &NativeAttestation, name: Option<&str>) -> Value {
    let id = b64url(&att.credential_id);
    let mut body = json!({
        "credential": {
            "id": id,
            "rawId": id,
            "type": "public-key",
            "response": {
                "attestationObject": b64url(&att.attestation_object),
                "clientDataJSON": b64url(&att.client_data_json),
            },
            "extensions": {},
        },
        "reg_id": start.reg_id,
    });
    if let Some(name) = name {
        body["name"] = json!(name);
    }
    body
}

/// The new passkey's row id, from `register-finish`'s answer (`{ id, name, created_at }`).
pub fn parse_registration_finish(answer: &Value) -> Result<String, PasskeyError> {
    str_field(answer, "id")
        .map(str::to_string)
        .ok_or(PasskeyError::Malformed("registration id"))
}

/// The body of `POST /api/v1/auth/vault-key-escrow`: the credential id as webauthn-rs stores it (base64url, which is
/// what the server matches against `credential.cred_id`) and the blob in standard base64.
pub fn escrow_body(credential_id: &[u8], blob: &[u8]) -> Value {
    json!({
        "credential_id": b64url(credential_id),
        "encrypted_vault_key": STANDARD.encode(blob),
    })
}

/// `GET` path of one credential's escrow blob.
pub fn escrow_path(credential_id: &[u8]) -> String {
    // base64url has no character that needs percent-encoding in a path segment.
    format!("/api/v1/auth/vault-key-escrow/{}", b64url(credential_id))
}

/// The blob from `GET /api/v1/auth/vault-key-escrow/{id}`'s answer.
pub fn parse_escrow(answer: &Value) -> Result<Vec<u8>, PasskeyError> {
    let b64 = str_field(answer, "encrypted_vault_key").ok_or(PasskeyError::Malformed("encrypted_vault_key"))?;
    STANDARD
        .decode(b64)
        .map_err(|_| PasskeyError::Malformed("encrypted_vault_key"))
}

/// What a native `get` call needs, decoded from the server's `login-start` answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestOptions {
    pub rp_id: String,
    pub challenge: Vec<u8>,
    pub allow_credentials: Vec<Vec<u8>>,
    pub timeout_ms: u32,
    pub user_verification: String,
    pub origin: String,
    pub prf: PrfSalts,
}

impl RequestOptions {
    /// The `clientDataJSON` a native caller hands its platform and then returns in the assertion.
    pub fn client_data_json(&self) -> Vec<u8> {
        client_data_json("webauthn.get", &self.challenge, &self.origin)
    }

    /// Options for a LOCAL assertion whose only purpose is the PRF output of a credential just created (a platform
    /// that cannot evaluate PRF during `create`). Its challenge is random and is never sent to the server. It asks
    /// for the creation's `user_verification`, never less: `hmac-secret` gives a different output with and without
    /// verification, and the sign-in requires it, so a weaker probe would escrow under a PRF output no sign-in
    /// reproduces.
    pub fn local_prf_probe(creation: &CreationOptions, credential_id: &[u8]) -> Self {
        let mut challenge = vec![0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut challenge);
        Self {
            rp_id: creation.rp_id.clone(),
            challenge,
            allow_credentials: vec![credential_id.to_vec()],
            timeout_ms: creation.timeout_ms,
            user_verification: creation.user_verification.clone(),
            origin: creation.origin.clone(),
            prf: PrfSalts::new(),
        }
    }
}

/// A started passkey sign-in: the server's opaque `auth_state` and `user_id` hint, echoed at finish, and the options.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssertionStart {
    pub auth_state: String,
    pub user_id: String,
    pub options: RequestOptions,
}

/// The body of `POST /api/v1/auth/passkey/login-start`.
pub fn login_start_body(email: &str) -> Value {
    json!({ "email": email })
}

/// Read `POST /api/v1/auth/passkey/login-start`'s answer. The server's `rpId` must be `expected`'s.
pub fn parse_assertion_start(answer: &Value, expected: &ExpectedRp) -> Result<AssertionStart, PasskeyError> {
    let pk = public_key(answer).ok_or(PasskeyError::Malformed("publicKey"))?;
    let rp_id = str_field(pk, "rpId")
        .ok_or(PasskeyError::Malformed("rpId"))?
        .to_string();
    let origin = expected.origin_for(&rp_id)?;
    Ok(AssertionStart {
        auth_state: str_field(answer, "auth_state")
            .ok_or(PasskeyError::Malformed("auth_state"))?
            .to_string(),
        user_id: str_field(answer, "user_id")
            .ok_or(PasskeyError::Malformed("user_id"))?
            .to_string(),
        options: RequestOptions {
            origin,
            rp_id,
            challenge: from_b64url(str_field(pk, "challenge").ok_or(PasskeyError::Malformed("challenge"))?)?,
            allow_credentials: credential_ids(pk.get("allowCredentials"))?,
            timeout_ms: pk.get("timeout").and_then(Value::as_u64).unwrap_or(60_000) as u32,
            user_verification: str_field(pk, "userVerification").unwrap_or("preferred").to_string(),
            prf: PrfSalts::new(),
        },
    })
}

/// A platform's answer to `get`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeAssertion {
    pub credential_id: Vec<u8>,
    pub authenticator_data: Vec<u8>,
    /// Exactly the bytes the platform signed over (for a native caller: [`RequestOptions::client_data_json`]).
    pub client_data_json: Vec<u8>,
    pub signature: Vec<u8>,
    pub user_handle: Option<Vec<u8>>,
}

/// The body of `POST /api/v1/auth/passkey/login-finish` (web: `finishPasskeyLogin`).
pub fn assertion_finish_body(start: &AssertionStart, assertion: &NativeAssertion) -> Value {
    let id = b64url(&assertion.credential_id);
    json!({
        "credential": {
            "id": id,
            "rawId": id,
            "type": "public-key",
            "response": {
                "authenticatorData": b64url(&assertion.authenticator_data),
                "clientDataJSON": b64url(&assertion.client_data_json),
                "signature": b64url(&assertion.signature),
                "userHandle": assertion.user_handle.as_deref().map(b64url),
            },
            "extensions": {},
        },
        "auth_state": start.auth_state,
        "user_id": start.user_id,
    })
}

/// A finished passkey sign-in: the account the SERVER says the assertion proved (never the `login-start` hint) and
/// its new session. Zeroized on drop.
pub struct LoginFinish {
    pub user_id: String,
    pub session_token: Zeroizing<String>,
}

impl std::fmt::Debug for LoginFinish {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoginFinish")
            .field("user_id", &self.user_id)
            .finish_non_exhaustive()
    }
}

/// Read `login-finish`'s answer (`{ user_id, session_token, salt }`).
pub fn parse_login_finish(answer: &Value) -> Result<LoginFinish, PasskeyError> {
    Ok(LoginFinish {
        user_id: str_field(answer, "user_id")
            .ok_or(PasskeyError::Malformed("user_id"))?
            .to_string(),
        session_token: Zeroizing::new(
            str_field(answer, "session_token")
                .ok_or(PasskeyError::Malformed("session_token"))?
                .to_string(),
        ),
    })
}

/// One passkey of the account, as `GET /api/v1/auth/passkeys` lists it. `last_used_at` and `prf` are read when the
/// server sends them (today it sends neither: `None`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasskeyInfo {
    pub id: String,
    pub name: String,
    pub created_at: String,
    pub last_used_at: Option<String>,
    pub prf: Option<bool>,
}

/// Read the list answer (`{ passkeys: [...] }`).
pub fn parse_passkey_list(answer: &Value) -> Result<Vec<PasskeyInfo>, PasskeyError> {
    answer
        .get("passkeys")
        .and_then(Value::as_array)
        .ok_or(PasskeyError::Malformed("passkeys"))?
        .iter()
        .map(|row| {
            Ok(PasskeyInfo {
                id: str_field(row, "id")
                    .ok_or(PasskeyError::Malformed("passkey id"))?
                    .to_string(),
                name: str_field(row, "name").unwrap_or_default().to_string(),
                created_at: str_field(row, "created_at").unwrap_or_default().to_string(),
                last_used_at: str_field(row, "last_used_at").map(str::to_string),
                prf: row.get("prf").and_then(Value::as_bool),
            })
        })
        .collect()
}

/// `DELETE` path of one passkey. The id must be a UUID (the server's row id), so nothing else reaches the path.
pub fn remove_path(id: &str) -> Result<String, PasskeyError> {
    let id = uuid::Uuid::parse_str(id).map_err(|_| PasskeyError::Malformed("passkey id"))?;
    Ok(format!("/api/v1/auth/passkeys/{id}"))
}

/// Map an HTTP failure to a code. The server's `error` field is kept only when it is a plain lower-case identifier;
/// its message is never kept.
pub fn server_error(status: u16, body: &Value) -> PasskeyError {
    let code = str_field(body, "error")
        .filter(|c| c.len() <= 64 && c.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'))
        .map(str::to_string);
    match (status, code.as_deref()) {
        (401, _) => PasskeyError::Unauthorized,
        (403, Some("confirmation_required")) => PasskeyError::ConfirmationRequired,
        _ => PasskeyError::Server { status, code },
    }
}
