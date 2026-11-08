//! The OPAQUE password sign-in, then the second factor.
//!
//! ```text
//! SignIn::start(email, password) ──► POST /api/v1/opaque/login-start  {email, client_message}
//!   on_response ◄── {server_message, server_state, ksf_version}
//!               ──► POST /api/v1/opaque/login-finish {email, client_message, server_state}
//!   on_response ◄── {session_token}                    → SignInStep::SignedIn
//!               ◄── {requires_2fa: true, partial_token} → SignInStep::SecondFactor(PendingSecondFactor)
//! PendingSecondFactor::verify(code) ──► POST /api/v1/auth/2fa/verify {partial_token, code}
//!   on_verify_response ◄── {session_token}
//! ```
//!
//! `ksf_version` always comes from the server's login-start answer. A 401 or 404 on either leg,
//! and an OPAQUE finish that fails locally (wrong password), are all
//! [`AuthFlowError::InvalidCredentials`]: the client never learns which.
use base64::Engine;
use serde_json::json;
use zeroize::Zeroizing;

use super::{AuthFlowError, HttpRequest, HttpResponse, RequestAuth, b64, b64_decode, normalize_second_factor_code};
use crate::opaque_protocol;

pub const LOGIN_START_PATH: &str = "/api/v1/opaque/login-start";
pub const LOGIN_FINISH_PATH: &str = "/api/v1/opaque/login-finish";
pub const TWO_FACTOR_VERIFY_PATH: &str = "/api/v1/auth/2fa/verify";

enum Stage {
    AwaitStart { client_state: Zeroizing<Vec<u8>> },
    AwaitFinish,
    Done,
}

/// One password sign-in attempt. Holds the password and the OPAQUE client state until the
/// finish leg, then drops them.
pub struct SignIn {
    email: String,
    password: Zeroizing<Vec<u8>>,
    stage: Stage,
}

/// What the caller does next.
pub enum SignInStep {
    /// Send this request and pass the answer to [`SignIn::on_response`].
    Send(HttpRequest),
    /// Signed in: the session token for the credential store.
    SignedIn { session_token: Zeroizing<String> },
    /// The password was right; the account has two-factor on.
    SecondFactor(PendingSecondFactor),
}

/// Lowercased, trimmed: how every client sends the email.
pub fn canonical_email(email: &str) -> String {
    email.trim().to_lowercase()
}

/// Whether the sign-in button may be enabled: the email looks like an address and the
/// password is not empty (DW-A02).
pub fn can_submit(email: &str, password_len: usize) -> bool {
    let e = email.trim();
    let Some((local, domain)) = e.split_once('@') else {
        return false;
    };
    password_len > 0
        && !local.is_empty()
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && !e.contains(char::is_whitespace)
}

impl SignIn {
    /// Start a sign-in: returns the flow and the login-start request.
    pub fn start(email: &str, password: &[u8]) -> Result<(Self, HttpRequest), AuthFlowError> {
        let email = canonical_email(email);
        if !can_submit(&email, password.len()) {
            return Err(AuthFlowError::InvalidInput("email and password are required"));
        }
        let start =
            opaque_protocol::client_login_start(password).map_err(|_| AuthFlowError::Protocol("opaque start"))?;
        let request = HttpRequest::post(
            LOGIN_START_PATH,
            json!({ "email": email, "client_message": b64().encode(&start.message) }),
            RequestAuth::None,
        );
        let flow = Self {
            email,
            password: Zeroizing::new(password.to_vec()),
            stage: Stage::AwaitStart {
                client_state: Zeroizing::new(start.state),
            },
        };
        Ok((flow, request))
    }

    /// The email the sign-in is for, canonical.
    pub fn email(&self) -> &str {
        &self.email
    }

    /// Feed the answer to the last request.
    pub fn on_response(&mut self, resp: HttpResponse) -> Result<SignInStep, AuthFlowError> {
        match std::mem::replace(&mut self.stage, Stage::Done) {
            Stage::AwaitStart { client_state } => {
                if resp.status == 401 || resp.status == 404 {
                    return Err(AuthFlowError::InvalidCredentials);
                }
                if !resp.ok() {
                    return Err(AuthFlowError::from_status(&resp));
                }
                let server_message = b64_decode(resp.str_field("server_message")?)?;
                let server_state = resp.str_field("server_state")?.to_owned();
                let ksf_version = resp
                    .body
                    .get("ksf_version")
                    .and_then(|v| v.as_u64())
                    .ok_or(AuthFlowError::Protocol("missing ksf_version"))? as u32;
                let finish =
                    opaque_protocol::client_login_finish(&client_state, &self.password, &server_message, ksf_version)
                        .map_err(|_| AuthFlowError::InvalidCredentials)?;
                // The password and the OPAQUE keys are not needed past this point.
                self.password = Zeroizing::new(Vec::new());
                drop(Zeroizing::new(finish.session_key));
                drop(Zeroizing::new(finish.export_key));
                self.stage = Stage::AwaitFinish;
                Ok(SignInStep::Send(HttpRequest::post(
                    LOGIN_FINISH_PATH,
                    json!({
                        "email": self.email,
                        "client_message": b64().encode(&finish.message),
                        "server_state": server_state,
                    }),
                    RequestAuth::None,
                )))
            }
            Stage::AwaitFinish => {
                if resp.status == 401 {
                    return Err(AuthFlowError::InvalidCredentials);
                }
                if !resp.ok() {
                    return Err(AuthFlowError::from_status(&resp));
                }
                if resp.body.get("requires_2fa").and_then(|v| v.as_bool()).unwrap_or(false) {
                    let partial = Zeroizing::new(resp.str_field("partial_token")?.to_owned());
                    return Ok(SignInStep::SecondFactor(PendingSecondFactor {
                        email: self.email.clone(),
                        partial_token: partial,
                    }));
                }
                let token = Zeroizing::new(resp.str_field("session_token")?.to_owned());
                Ok(SignInStep::SignedIn { session_token: token })
            }
            Stage::Done => Err(AuthFlowError::WrongState),
        }
    }
}

/// The password was accepted and a second factor is due. Holds the short-lived partial token
/// in memory only; dropping it discards the partial session (DW-A26 "Back").
pub struct PendingSecondFactor {
    email: String,
    partial_token: Zeroizing<String>,
}

impl PendingSecondFactor {
    pub fn email(&self) -> &str {
        &self.email
    }

    /// The verify request for a typed code: 6 digits (authenticator) or 8 (backup code).
    pub fn verify(&self, code: &str) -> Result<HttpRequest, AuthFlowError> {
        let code = normalize_second_factor_code(code)?;
        Ok(HttpRequest::post(
            TWO_FACTOR_VERIFY_PATH,
            json!({ "partial_token": self.partial_token.as_str(), "code": code.as_str() }),
            RequestAuth::None,
        ))
    }

    /// The answer to [`Self::verify`]: the session token, or [`AuthFlowError::WrongCode`]
    /// (the pending state stays usable for the next code).
    pub fn on_verify_response(&self, resp: HttpResponse) -> Result<Zeroizing<String>, AuthFlowError> {
        if resp.status == 401 || resp.status == 400 {
            return Err(AuthFlowError::WrongCode);
        }
        if !resp.ok() {
            return Err(AuthFlowError::from_status(&resp));
        }
        Ok(Zeroizing::new(resp.str_field("session_token")?.to_owned()))
    }
}
