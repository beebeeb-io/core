//! Recovering an account with the 12-word phrase and setting a new password, sans-IO like
//! [`crate::signup_flow`]. Beebeeb cannot reset a password: the phrase re-derives the same master
//! key, the server checks a value derived from it, and only the OPAQUE password file changes.
//!
//! ```text
//! PhraseRecovery::start(email, phrase)  POST /api/v1/auth/recover-with-phrase-start {email, recovery_check}
//!   on_start_response ◄── {recovery_token}                     (kept here)
//! set_password(pw, pw2)                 POST /api/v1/auth/recover-opaque-register   {recovery_token, client_message}
//!   on_register_response ◄── {server_message}
//!                                       POST /api/v1/auth/recover-with-phrase-finalize
//!                                            {recovery_token, opaque_registration, recovery_check, x25519_public_key}
//!   on_finalize_response ◄── {session_token} → Recovered::SignedIn
//!                        ◄── {requires_2fa} or 409 password_set_sign_in_required → Recovered::SignInRequired
//! ```
//!
//! The phrase never leaves the device: only the recovery check (an HKDF of the master key) is sent.
//! The phrase, the password, the recovery token and the master key are [`Zeroizing`].
use std::fmt;

use base64::Engine;
use serde_json::json;
use zeroize::Zeroizing;

use crate::auth_flow::sign_in::{can_submit, canonical_email};
use crate::auth_flow::{HttpRequest, HttpResponse, RequestAuth, b64, b64_decode};
use crate::kdf::MasterKey;
use crate::onboarding::{BreachVerdict, PasswordEvaluation};
use crate::signup_flow::{BreachSlot, SignupError, SignupPolicy, evaluate};
use crate::{opaque, opaque_protocol, recovery};

pub const RECOVER_START_PATH: &str = "/api/v1/auth/recover-with-phrase-start";
pub const RECOVER_REGISTER_PATH: &str = "/api/v1/auth/recover-opaque-register";
pub const RECOVER_FINALIZE_PATH: &str = "/api/v1/auth/recover-with-phrase-finalize";

/// 0-based positions of the typed words that are not in the 2048-word list (DW-A48's mark).
/// Empty words are not marked.
pub fn unknown_word_positions<S: AsRef<str>>(words: &[S]) -> Vec<u32> {
    words
        .iter()
        .enumerate()
        .filter(|(_, w)| {
            let w = w.as_ref().trim().to_lowercase();
            !w.is_empty() && bip39::Language::English.find_word(&w).is_none()
        })
        .map(|(i, _)| i as u32)
        .collect()
}

/// How the recovery ended.
pub enum Recovered {
    /// Signed in with the new password: the session and the master key for the caller to store.
    SignedIn {
        session_token: Zeroizing<String>,
        master_key: MasterKey,
    },
    /// The password was changed, and the server wants a normal sign-in next (two-factor on, or an
    /// older server). Nothing else to store.
    SignInRequired,
}

impl fmt::Debug for Recovered {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::SignedIn { .. } => "Recovered::SignedIn",
            Self::SignInRequired => "Recovered::SignInRequired",
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stage {
    AwaitStart,
    PhraseAccepted,
    AwaitRegister,
    AwaitFinalize,
    Done,
}

pub struct PhraseRecovery {
    policy: SignupPolicy,
    master_key: MasterKey,
    recovery_check: Zeroizing<[u8; 32]>,
    token: Option<Zeroizing<String>>,
    password: Option<Zeroizing<String>>,
    client_state: Option<Zeroizing<Vec<u8>>>,
    breach: BreachSlot,
    stage: Stage,
}

impl fmt::Debug for PhraseRecovery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PhraseRecovery")
            .field("stage", &self.stage)
            .finish_non_exhaustive()
    }
}

impl PhraseRecovery {
    /// DW-A47: derive the master key from the phrase here and ask the server to check it.
    pub fn start(policy: SignupPolicy, email: &str, phrase: &str) -> Result<(Self, HttpRequest), SignupError> {
        let email = canonical_email(email);
        if !can_submit(&email, 1) {
            return Err(SignupError::InvalidEmail);
        }
        let normalized = recovery::normalize_phrase(phrase);
        if !recovery::phrase_is_complete(&normalized) {
            return Err(SignupError::InvalidPhrase);
        }
        let master_key = recovery::recover_from_phrase(&normalized).map_err(|_| SignupError::InvalidPhrase)?;
        let recovery_check = opaque::compute_recovery_check(&master_key);
        let req = HttpRequest::post(
            RECOVER_START_PATH,
            json!({ "email": email, "recovery_check": b64().encode(*recovery_check) }),
            RequestAuth::None,
        );
        let flow = Self {
            policy,
            master_key,
            recovery_check,
            token: None,
            password: None,
            client_state: None,
            breach: BreachSlot::default(),
            stage: Stage::AwaitStart,
        };
        Ok((flow, req))
    }

    /// The server's verdict on the phrase. Any refusal is one answer: nothing changed.
    pub fn on_start_response(&mut self, resp: &HttpResponse) -> Result<(), SignupError> {
        if self.stage != Stage::AwaitStart {
            return Err(SignupError::WrongState);
        }
        if resp.status == 429 {
            return Err(SignupError::from_status(resp));
        }
        if matches!(resp.status, 400 | 401 | 403 | 404) {
            return Err(SignupError::PhraseNotAccepted);
        }
        if !resp.ok() {
            return Err(SignupError::from_status(resp));
        }
        let token = resp
            .str_field("recovery_token")
            .map_err(|_| SignupError::Protocol("missing recovery_token"))?;
        self.token = Some(Zeroizing::new(token.to_owned()));
        self.stage = Stage::PhraseAccepted;
        Ok(())
    }

    pub fn evaluate(&self, password: &str) -> PasswordEvaluation {
        evaluate(&self.policy, password)
    }

    pub fn breach_request(&mut self, password: &str) -> Option<HttpRequest> {
        self.breach.request(&self.policy, password)
    }

    pub fn on_breach_response(&mut self, status: Option<u16>, body: &str) -> Option<BreachVerdict> {
        self.breach.record(&self.policy, status, body)
    }

    /// DW-A49: the same length and breach rules as sign-up, then the OPAQUE re-registration.
    pub fn set_password(&mut self, password: &str, confirmation: &str) -> Result<HttpRequest, SignupError> {
        if !matches!(self.stage, Stage::PhraseAccepted) {
            return Err(SignupError::WrongState);
        }
        if password != confirmation {
            return Err(SignupError::PasswordMismatch);
        }
        let eval = self.evaluate(password);
        if !eval.meets_minimum {
            return Err(SignupError::PasswordTooShort {
                missing: eval.missing_characters,
            });
        }
        if self.policy.breach_endpoint.is_some() {
            let check = self.breach.get().ok_or(SignupError::BreachCheckMissing)?;
            if !check.matches_password(password) {
                return Err(SignupError::BreachCheckMissing);
            }
            match check.verdict(self.policy.breach_fail_open) {
                None => return Err(SignupError::BreachCheckMissing),
                Some(BreachVerdict::Breached { .. }) => return Err(SignupError::PasswordBreached),
                Some(BreachVerdict::CheckFailedBlocked) => return Err(SignupError::BreachCheckBlocked),
                Some(_) => {}
            }
        }
        let token = self.token.as_ref().ok_or(SignupError::WrongState)?;
        let start = opaque_protocol::client_registration_start(password.as_bytes())
            .map_err(|_| SignupError::Protocol("opaque start"))?;
        let req = HttpRequest::post(
            RECOVER_REGISTER_PATH,
            json!({ "recovery_token": token.as_str(), "client_message": b64().encode(&start.message) }),
            RequestAuth::None,
        );
        self.password = Some(Zeroizing::new(password.to_owned()));
        self.client_state = Some(Zeroizing::new(start.state));
        self.stage = Stage::AwaitRegister;
        Ok(req)
    }

    fn token_refused(&mut self, resp: &HttpResponse) -> SignupError {
        self.password = None;
        self.client_state = None;
        if resp.status == 429 {
            self.stage = Stage::PhraseAccepted;
            return SignupError::from_status(resp);
        }
        if matches!(resp.status, 400 | 401 | 403 | 404 | 410) {
            self.token = None;
            self.stage = Stage::Done;
            return SignupError::RecoveryExpired;
        }
        self.stage = Stage::PhraseAccepted;
        SignupError::from_status(resp)
    }

    pub fn on_register_response(&mut self, resp: &HttpResponse) -> Result<HttpRequest, SignupError> {
        if self.stage != Stage::AwaitRegister {
            return Err(SignupError::WrongState);
        }
        if !resp.ok() {
            return Err(self.token_refused(resp));
        }
        let server_message = b64_decode(
            resp.str_field("server_message")
                .map_err(|_| SignupError::Protocol("missing server_message"))?,
        )
        .map_err(|_| SignupError::Protocol("invalid base64"))?;
        let state = self.client_state.take().ok_or(SignupError::WrongState)?;
        let password = self.password.take().ok_or(SignupError::WrongState)?;
        let upload = opaque_protocol::client_registration_finish(&state, password.as_bytes(), &server_message)
            .map_err(|_| SignupError::Protocol("opaque finish"))?;
        let token = self.token.as_ref().ok_or(SignupError::WrongState)?;
        let x25519_public = opaque::derive_x25519_public(&opaque::derive_x25519_private(&self.master_key));
        self.stage = Stage::AwaitFinalize;
        Ok(HttpRequest::post(
            RECOVER_FINALIZE_PATH,
            json!({
                "recovery_token": token.as_str(),
                "opaque_registration": b64().encode(&upload),
                "recovery_check": b64().encode(*self.recovery_check),
                "x25519_public_key": b64().encode(x25519_public),
            }),
            RequestAuth::None,
        ))
    }

    /// The password is changed. Consumes the flow: the master key moves to the caller.
    pub fn on_finalize_response(mut self, resp: &HttpResponse) -> Result<Recovered, SignupError> {
        if self.stage != Stage::AwaitFinalize {
            return Err(SignupError::WrongState);
        }
        if resp.status == 409 && resp.error_code() == Some("password_set_sign_in_required") {
            return Ok(Recovered::SignInRequired);
        }
        if !resp.ok() {
            return Err(self.token_refused(resp));
        }
        if resp.body.get("requires_2fa").and_then(|v| v.as_bool()) == Some(true) {
            return Ok(Recovered::SignInRequired);
        }
        let session_token = Zeroizing::new(
            resp.str_field("session_token")
                .map_err(|_| SignupError::Protocol("missing session_token"))?
                .to_owned(),
        );
        Ok(Recovered::SignedIn {
            session_token,
            master_key: self.master_key,
        })
    }
}

#[cfg(test)]
#[path = "recovery_flow_tests.rs"]
mod tests;
