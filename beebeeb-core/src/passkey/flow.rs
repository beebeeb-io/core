//! The passkey flows, as plain logic over two injected seams: the client's HTTP ([`PasskeyHttp`], which owns the base
//! URL, TLS and headers) and the platform's WebAuthn call ([`PasskeyAuthenticator`]). Core decides every step, every
//! body and every key operation; a client only moves bytes.
//!
//! ```mermaid
//! sequenceDiagram
//!   participant C as client (HTTP + platform call)
//!   participant K as core flow
//!   participant S as server
//!   K->>S: confirm-opaque-start / -finish (step-up from the password)
//!   S-->>K: single-use confirmation token (kept inside core)
//!   K->>S: register-start (X-Confirm-Token)
//!   S-->>K: options + reg_id
//!   K->>C: make_credential(options)
//!   C-->>K: attestation (+ PRF output)
//!   K->>S: register-finish
//!   K->>C: get_assertion(local probe), only when create gave no PRF output
//!   K->>S: vault-key-escrow (wrap(PRF, vault key))
//! ```
//!
//! No step returns a PRF output, a wrap key or a blob to the caller; the vault key comes back only from
//! [`sign_in`], inside a [`MasterKey`].

use std::future::Future;

use serde_json::Value;
use zeroize::Zeroizing;

use super::ceremony::{
    self, AssertionStart, CreationOptions, ExpectedRp, NativeAssertion, NativeAttestation, PasskeyError, PasskeyInfo,
    RequestOptions,
};
use super::{PrfOutput, unwrap_vault_key, wrap_vault_key};
use crate::auth_flow::step_up::{StepUp, StepUpPurpose, StepUpStep};
use crate::auth_flow::{self, AuthFlowError, RequestAuth};
use crate::kdf::MasterKey;

/// An HTTP method the passkey routes use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Get,
    Post,
    Delete,
}

/// One request to the API. `path` starts at `/api/v1/...`; the client adds its base URL.
pub struct ApiRequest {
    pub method: Method,
    pub path: String,
    pub body: Option<Value>,
    /// The session, sent as `Authorization: Bearer`.
    pub bearer: Option<Zeroizing<String>>,
    /// A step-up proof, sent as `X-Confirm-Token`.
    pub confirm_token: Option<Zeroizing<String>>,
}

impl std::fmt::Debug for ApiRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiRequest")
            .field("method", &self.method)
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

/// The API's answer: the status and the JSON body (`Value::Null` when there is none).
#[derive(Clone)]
pub struct ApiResponse {
    pub status: u16,
    pub body: Value,
}

impl std::fmt::Debug for ApiResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Bodies can carry session tokens, TOTP secrets, backup codes and mailed tokens: status only.
        f.debug_struct("ApiResponse")
            .field("status", &self.status)
            .finish_non_exhaustive()
    }
}

/// The client's HTTP. A transport failure is [`PasskeyError::Network`]; any status is an `Ok`.
pub trait PasskeyHttp {
    fn send(&self, request: ApiRequest) -> impl Future<Output = Result<ApiResponse, PasskeyError>> + Send;
}

/// A platform's `create` answer. `prf_output` is set when the platform evaluated PRF during `create`;
/// `prf_enabled` says whether the new credential supports PRF at all (`None`: the platform cannot tell).
pub struct Registration {
    pub attestation: NativeAttestation,
    pub prf_output: Option<PrfOutput>,
    pub prf_enabled: Option<bool>,
}

/// A platform's `get` answer and, when the authenticator evaluated it, the PRF output for `prf.eval.first`.
pub struct Assertion {
    pub assertion: NativeAssertion,
    pub prf_output: Option<PrfOutput>,
}

/// The platform's WebAuthn call. It passes the options' `client_data_json()` to the platform and the PRF salt the
/// platform takes (see [`super`]: `hmac_secret_salt` for a raw `hmac-secret` API, `prf_eval_input` for a PRF API).
pub trait PasskeyAuthenticator {
    fn make_credential(
        &self,
        options: &CreationOptions,
    ) -> impl Future<Output = Result<Registration, PasskeyError>> + Send;
    fn get_assertion(&self, options: &RequestOptions) -> impl Future<Output = Result<Assertion, PasskeyError>> + Send;
}

async fn call<H: PasskeyHttp>(http: &H, request: ApiRequest) -> Result<Value, PasskeyError> {
    let response = http.send(request).await?;
    if (200..300).contains(&response.status) {
        Ok(response.body)
    } else {
        Err(ceremony::server_error(response.status, &response.body))
    }
}

fn bearer(session: &str) -> Option<Zeroizing<String>> {
    Some(Zeroizing::new(session.to_string()))
}

fn step_up_error(e: AuthFlowError) -> PasskeyError {
    PasskeyError::StepUp { code: e.code() }
}

/// A step-up leg from `auth_flow` in this module's request shape (both legs are session POSTs).
fn from_auth(request: auth_flow::HttpRequest, session: &str) -> ApiRequest {
    let method = match request.method {
        auth_flow::Method::Get => Method::Get,
        auth_flow::Method::Delete => Method::Delete,
        // The step-up legs are POSTs; PUT and PATCH (B05e's access change) never reach this mapping.
        auth_flow::Method::Post | auth_flow::Method::Put | auth_flow::Method::Patch => Method::Post,
    };
    ApiRequest {
        method,
        path: request.path,
        body: request.body,
        bearer: match request.auth {
            RequestAuth::Session => bearer(session),
            RequestAuth::None => None,
        },
        confirm_token: request.confirm_token,
    }
}

/// Run the OPAQUE step-up (the generic grant) for the signed-in `session` over `http`, then put the minted
/// single-use token on `consuming`. The token never leaves core: no caller ever holds it.
async fn with_step_up<H: PasskeyHttp>(
    http: &H,
    session: &str,
    password: &[u8],
    consuming: ApiRequest,
) -> Result<ApiRequest, PasskeyError> {
    let (mut flow, mut next) = StepUp::start(password, StepUpPurpose::Generic).map_err(step_up_error)?;
    loop {
        let response = http.send(from_auth(next, session)).await?;
        match flow
            .on_response(auth_flow::HttpResponse::new(response.status, response.body))
            .map_err(step_up_error)?
        {
            StepUpStep::Send(request) => next = request,
            StepUpStep::Confirmed(token) => {
                return Ok(ApiRequest {
                    confirm_token: Some(token.into_header_value()),
                    ..consuming
                });
            }
        }
    }
}

/// What adding a passkey did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Added {
    /// The server's row id of the new passkey.
    pub id: String,
    /// The passkey gave a PRF output, so it can unlock the vault.
    pub prf: bool,
    /// The vault key was wrapped under it and stored in the escrow.
    pub escrowed: bool,
}

/// Add a passkey to the signed-in account (`session`). The step-up the server requires runs inside, from
/// `password` (OPAQUE; the single-use token goes straight onto `register-start`). The server's relying party must
/// be `rp`. When `vault_key` is given and the passkey has PRF, the vault key is wrapped under it
/// and escrowed, so the passkey can unlock the vault later. The passkey stays added when the escrow step fails (the
/// web client's rule): the answer then says `escrowed: false`.
pub async fn add_passkey<H: PasskeyHttp, A: PasskeyAuthenticator>(
    http: &H,
    authenticator: &A,
    session: &str,
    password: &[u8],
    name: Option<&str>,
    vault_key: Option<&MasterKey>,
    rp: &ExpectedRp,
) -> Result<Added, PasskeyError> {
    let register_start = with_step_up(
        http,
        session,
        password,
        ApiRequest {
            method: Method::Post,
            path: "/api/v1/auth/passkey/register-start".into(),
            body: None,
            bearer: bearer(session),
            confirm_token: None,
        },
    )
    .await?;
    let start = ceremony::parse_registration_start(&call(http, register_start).await?, rp)?;
    let registration = authenticator.make_credential(&start.options).await?;
    let id = ceremony::parse_registration_finish(
        &call(
            http,
            ApiRequest {
                method: Method::Post,
                path: "/api/v1/auth/passkey/register-finish".into(),
                body: Some(ceremony::registration_finish_body(
                    &start,
                    &registration.attestation,
                    name,
                )),
                bearer: bearer(session),
                confirm_token: None,
            },
        )
        .await?,
    )?;

    let credential_id = registration.attestation.credential_id.clone();
    let prf_output = match registration.prf_output {
        Some(prf) => Some(prf),
        // The platform could not evaluate PRF during create: one local assertion asks for it. Skipped when the
        // platform already said the credential has no PRF. A dismissed prompt only means no PRF.
        None if registration.prf_enabled != Some(false) => {
            let probe = RequestOptions::local_prf_probe(&start.options, &credential_id);
            authenticator
                .get_assertion(&probe)
                .await
                .ok()
                .and_then(|a| a.prf_output)
        }
        None => None,
    };
    let prf = prf_output.is_some();
    let escrowed = match (prf_output, vault_key) {
        (Some(prf_output), Some(vault_key)) => match wrap_vault_key(&prf_output, vault_key) {
            Ok(blob) => call(
                http,
                ApiRequest {
                    method: Method::Post,
                    path: "/api/v1/auth/vault-key-escrow".into(),
                    body: Some(ceremony::escrow_body(&credential_id, &blob)),
                    bearer: bearer(session),
                    confirm_token: None,
                },
            )
            .await
            .is_ok(),
            Err(_) => false,
        },
        _ => false,
    };
    Ok(Added { id, prf, escrowed })
}

/// What a passkey sign-in did to the vault.
pub enum VaultOutcome {
    /// The escrow opened: the vault key, for the client's credential store.
    Unlocked(MasterKey),
    /// The passkey gave no PRF output: the password or the recovery phrase is still needed (DW-A30).
    NoPrf,
    /// The passkey has PRF but no escrow was stored for it.
    NoEscrow,
    /// An escrow exists but did not open with this passkey's PRF output.
    UnwrapFailed,
}

impl VaultOutcome {
    /// The vault key, when unlocked.
    pub fn into_master_key(self) -> Option<MasterKey> {
        match self {
            Self::Unlocked(key) => Some(key),
            _ => None,
        }
    }
}

impl std::fmt::Debug for VaultOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Unlocked(_) => "Unlocked(..)",
            Self::NoPrf => "NoPrf",
            Self::NoEscrow => "NoEscrow",
            Self::UnwrapFailed => "UnwrapFailed",
        })
    }
}

/// A passkey sign-in: the account the server says the assertion proved, its new session, and the vault.
pub struct SignedIn {
    pub user_id: String,
    pub session_token: Zeroizing<String>,
    pub vault: VaultOutcome,
}

impl std::fmt::Debug for SignedIn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignedIn")
            .field("user_id", &self.user_id)
            .field("vault", &self.vault)
            .finish_non_exhaustive()
    }
}

/// Sign in with a passkey for `email`, then unlock the vault from the escrow when the passkey has PRF. The
/// server's relying party must be `rp`.
pub async fn sign_in<H: PasskeyHttp, A: PasskeyAuthenticator>(
    http: &H,
    authenticator: &A,
    email: &str,
    rp: &ExpectedRp,
) -> Result<SignedIn, PasskeyError> {
    let start: AssertionStart = ceremony::parse_assertion_start(
        &call(
            http,
            ApiRequest {
                method: Method::Post,
                path: "/api/v1/auth/passkey/login-start".into(),
                body: Some(ceremony::login_start_body(email)),
                bearer: None,
                confirm_token: None,
            },
        )
        .await?,
        rp,
    )?;
    let assertion = authenticator.get_assertion(&start.options).await?;
    let finish = ceremony::parse_login_finish(
        &call(
            http,
            ApiRequest {
                method: Method::Post,
                path: "/api/v1/auth/passkey/login-finish".into(),
                body: Some(ceremony::assertion_finish_body(&start, &assertion.assertion)),
                bearer: None,
                confirm_token: None,
            },
        )
        .await?,
    )?;
    let vault = match assertion.prf_output {
        None => VaultOutcome::NoPrf,
        Some(prf) => {
            let response = http
                .send(ApiRequest {
                    method: Method::Get,
                    path: ceremony::escrow_path(&assertion.assertion.credential_id),
                    body: None,
                    bearer: bearer(&finish.session_token),
                    confirm_token: None,
                })
                .await;
            match response {
                Ok(r) if r.status == 404 => VaultOutcome::NoEscrow,
                Ok(r) if (200..300).contains(&r.status) => match ceremony::parse_escrow(&r.body) {
                    Ok(blob) => match unwrap_vault_key(&prf, &blob) {
                        Ok(key) => VaultOutcome::Unlocked(key),
                        Err(_) => VaultOutcome::UnwrapFailed,
                    },
                    Err(_) => VaultOutcome::UnwrapFailed,
                },
                // The session exists; a failed escrow read leaves the vault locked, never the sign-in failed.
                _ => VaultOutcome::NoEscrow,
            }
        }
    };
    Ok(SignedIn {
        user_id: finish.user_id,
        session_token: finish.session_token,
        vault,
    })
}

/// The account's passkeys.
pub async fn list_passkeys<H: PasskeyHttp>(http: &H, session: &str) -> Result<Vec<PasskeyInfo>, PasskeyError> {
    ceremony::parse_passkey_list(
        &call(
            http,
            ApiRequest {
                method: Method::Get,
                path: "/api/v1/auth/passkeys".into(),
                body: None,
                bearer: bearer(session),
                confirm_token: None,
            },
        )
        .await?,
    )
}

/// Remove one passkey. The step-up runs inside, from `password`, and its single-use token goes only onto the
/// `DELETE` (task 2433 makes the server require it). The id is checked before any request is sent.
pub async fn remove_passkey<H: PasskeyHttp>(
    http: &H,
    session: &str,
    password: &[u8],
    id: &str,
) -> Result<(), PasskeyError> {
    let path = ceremony::remove_path(id)?;
    let request = with_step_up(
        http,
        session,
        password,
        ApiRequest {
            method: Method::Delete,
            path,
            body: None,
            bearer: bearer(session),
            confirm_token: None,
        },
    )
    .await?;
    call(http, request).await.map(|_| ())
}
