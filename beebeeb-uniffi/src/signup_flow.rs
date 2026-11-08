//! Account creation and phrase recovery for mobile (`beebeeb_core::signup_flow`,
//! `beebeeb_core::recovery_flow`), in the style of [`crate::auth_flow`]. Thin: each object wraps
//! one core flow and converts requests and responses; no rule lives here. The app's transport
//! sends each [`AuthHttpRequest`] and passes the answer back as an [`AuthHttpResponse`].
//!
//! Secrets: the password, the phrase and the email ticket stay inside core. The 12 words leave
//! once, for the one-time display (`phrase_words`); the session token and the master key leave
//! once, at the end, for the app's credential store.
use std::sync::{Arc, Mutex};

use beebeeb_core::auth_flow::HttpRequest;
use beebeeb_core::recovery_flow::{self as rf, PhraseRecovery, Recovered};
use beebeeb_core::signup_flow::{SignupError, SignupFlow, SignupPolicy};
use zeroize::Zeroizing;

use crate::auth_flow::{AuthHttpRequest, AuthHttpResponse, into, out};
use crate::{BreachVerdictDto, PasswordEvaluationDto};

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum SignupFlowFfiError {
    /// `code` is `SignupError::code()` (`wrong_code`, `password_breached`, …).
    #[error("{code}")]
    Flow {
        code: String,
        retry_after_secs: Option<u64>,
    },
}

impl From<SignupError> for SignupFlowFfiError {
    fn from(e: SignupError) -> Self {
        let retry_after_secs = match e {
            SignupError::RateLimited { retry_after_secs } => Some(retry_after_secs),
            _ => None,
        };
        Self::Flow {
            code: e.code().to_owned(),
            retry_after_secs,
        }
    }
}

fn wrong_state() -> SignupFlowFfiError {
    SignupError::WrongState.into()
}

/// The request for the server's sign-up policy (`GET /api/v1/onboarding`).
#[uniffi::export]
pub fn signup_policy_request() -> AuthHttpRequest {
    out(SignupPolicy::request())
}

/// 0-based positions of words that are not BIP39 words (DW-A47's per-word hint).
#[uniffi::export]
pub fn recovery_unknown_word_positions(words: Vec<String>) -> Vec<u32> {
    let words: Vec<Zeroizing<String>> = words.into_iter().map(Zeroizing::new).collect();
    rf::unknown_word_positions(&words)
}

fn policy(response: AuthHttpResponse) -> Result<SignupPolicy, SignupFlowFfiError> {
    Ok(SignupPolicy::from_response(&into(response))?)
}

/// The account exists: store both in the credential store, then drop them.
#[derive(uniffi::Record)]
pub struct SignupCreatedFfi {
    pub session_token: String,
    pub user_id: String,
    pub master_key: Vec<u8>,
}

// ── Sign-up ──────────────────────────────────────────────────────────────────

/// One account creation, from the email to the first session.
#[derive(uniffi::Object)]
pub struct SignupFlowHandle {
    inner: Mutex<SignupFlow>,
}

impl SignupFlowHandle {
    fn with<T>(&self, f: impl FnOnce(&mut SignupFlow) -> Result<T, SignupError>) -> Result<T, SignupFlowFfiError> {
        let mut flow = self.inner.lock().map_err(|_| wrong_state())?;
        Ok(f(&mut flow)?)
    }
}

#[uniffi::export]
impl SignupFlowHandle {
    /// Start from the answer to [`signup_policy_request`].
    #[uniffi::constructor]
    pub fn new(policy_response: AuthHttpResponse) -> Result<Arc<Self>, SignupFlowFfiError> {
        Ok(Arc::new(Self {
            inner: Mutex::new(SignupFlow::new(policy(policy_response)?)),
        }))
    }

    pub fn send_code(&self, email: String) -> Result<AuthHttpRequest, SignupFlowFfiError> {
        self.with(|f| f.send_code(&email)).map(out)
    }

    pub fn on_code_sent(&self, response: AuthHttpResponse) -> Result<(), SignupFlowFfiError> {
        self.with(|f| f.on_code_sent(&into(response)))
    }

    pub fn verify_code(&self, code: String) -> Result<AuthHttpRequest, SignupFlowFfiError> {
        let code = Zeroizing::new(code);
        self.with(|f| f.verify_code(&code)).map(out)
    }

    pub fn on_code_verified(&self, response: AuthHttpResponse) -> Result<(), SignupFlowFfiError> {
        self.with(|f| f.on_code_verified(&into(response)))
    }

    pub fn evaluate(&self, password: String) -> Result<PasswordEvaluationDto, SignupFlowFfiError> {
        let password = Zeroizing::new(password);
        self.with(|f| Ok(f.evaluate(&password).into()))
    }

    /// The breach request for this password; `None` when the policy declares no check.
    pub fn breach_request(&self, password: String) -> Result<Option<AuthHttpRequest>, SignupFlowFfiError> {
        let password = Zeroizing::new(password);
        self.with(|f| Ok(f.breach_request(&password).map(out)))
    }

    /// `status` is `None` when the breach endpoint gave no answer at all.
    pub fn on_breach_response(
        &self,
        status: Option<u16>,
        body: String,
    ) -> Result<Option<BreachVerdictDto>, SignupFlowFfiError> {
        self.with(|f| Ok(f.on_breach_response(status, &body).map(Into::into)))
    }

    pub fn set_password(
        &self,
        password: String,
        confirmation: String,
    ) -> Result<PasswordEvaluationDto, SignupFlowFfiError> {
        let (password, confirmation) = (Zeroizing::new(password), Zeroizing::new(confirmation));
        self.with(|f| f.set_password(&password, &confirmation).map(Into::into))
    }

    /// The 12 words, for the one-time display. The same words on every call.
    pub fn phrase_words(&self) -> Result<Vec<String>, SignupFlowFfiError> {
        self.with(|f| Ok(f.phrase_words()?.iter().map(|w| w.to_string()).collect()))
    }

    pub fn acknowledge_phrase(&self) -> Result<(), SignupFlowFfiError> {
        self.with(SignupFlow::acknowledge_phrase)
    }

    /// 1-based word positions to ask for.
    pub fn challenge_positions(&self) -> Result<Vec<u32>, SignupFlowFfiError> {
        self.with(|f| f.challenge_positions())
    }

    pub fn confirm_phrase(&self, answers: Vec<String>) -> Result<(), SignupFlowFfiError> {
        let answers: Vec<Zeroizing<String>> = answers.into_iter().map(Zeroizing::new).collect();
        self.with(|f| f.confirm_phrase(&answers))
    }

    pub fn register_start(&self) -> Result<AuthHttpRequest, SignupFlowFfiError> {
        self.with(SignupFlow::register_start).map(out)
    }

    pub fn on_register_start(&self, response: AuthHttpResponse) -> Result<AuthHttpRequest, SignupFlowFfiError> {
        self.with(|f| f.on_register_start(&into(response))).map(out)
    }

    pub fn on_register_finish(&self, response: AuthHttpResponse) -> Result<SignupCreatedFfi, SignupFlowFfiError> {
        let created = self.with(|f| f.on_register_finish(&into(response)))?;
        Ok(SignupCreatedFfi {
            session_token: created.session_token.to_string(),
            user_id: created.user_id.clone(),
            master_key: Zeroizing::new(created.master_key.to_bytes()).to_vec(),
        })
    }

    /// Record the accepted terms version once signed in; `None` when the policy names none.
    pub fn terms_request(&self) -> Result<Option<AuthHttpRequest>, SignupFlowFfiError> {
        self.with(|f| Ok(f.terms_request().map(out)))
    }

    /// Forget everything (the person left the flow).
    pub fn wipe(&self) {
        if let Ok(mut f) = self.inner.lock() {
            f.wipe();
        }
    }
}

// ── Recovery with the 12 words ───────────────────────────────────────────────

#[derive(uniffi::Enum)]
pub enum RecoveredFfi {
    /// Signed in with the new password: store both, then drop them.
    SignedIn { session_token: String, master_key: Vec<u8> },
    /// The password changed; a normal sign-in comes next (two-factor on, or an older server).
    SignInRequired,
}

/// One recovery: the phrase is checked by the server, then a new password is registered.
#[derive(uniffi::Object)]
pub struct PhraseRecoveryHandle {
    inner: Mutex<Option<PhraseRecovery>>,
    first: Mutex<Option<HttpRequest>>,
}

impl PhraseRecoveryHandle {
    fn with<T>(&self, f: impl FnOnce(&mut PhraseRecovery) -> Result<T, SignupError>) -> Result<T, SignupFlowFfiError> {
        let mut guard = self.inner.lock().map_err(|_| wrong_state())?;
        let flow = guard.as_mut().ok_or_else(wrong_state)?;
        Ok(f(flow)?)
    }
}

#[uniffi::export]
impl PhraseRecoveryHandle {
    /// DW-A47: the master key is derived from the phrase here; `start()` gives the check request.
    #[uniffi::constructor]
    pub fn new(
        policy_response: AuthHttpResponse,
        email: String,
        phrase: String,
    ) -> Result<Arc<Self>, SignupFlowFfiError> {
        let phrase = Zeroizing::new(phrase);
        let (flow, first) = PhraseRecovery::start(policy(policy_response)?, &email, &phrase)?;
        Ok(Arc::new(Self {
            inner: Mutex::new(Some(flow)),
            first: Mutex::new(Some(first)),
        }))
    }

    pub fn start(&self) -> Result<AuthHttpRequest, SignupFlowFfiError> {
        self.first
            .lock()
            .map_err(|_| wrong_state())?
            .take()
            .map(out)
            .ok_or_else(wrong_state)
    }

    pub fn on_start_response(&self, response: AuthHttpResponse) -> Result<(), SignupFlowFfiError> {
        self.with(|f| f.on_start_response(&into(response)))
    }

    pub fn evaluate(&self, password: String) -> Result<PasswordEvaluationDto, SignupFlowFfiError> {
        let password = Zeroizing::new(password);
        self.with(|f| Ok(f.evaluate(&password).into()))
    }

    pub fn breach_request(&self, password: String) -> Result<Option<AuthHttpRequest>, SignupFlowFfiError> {
        let password = Zeroizing::new(password);
        self.with(|f| Ok(f.breach_request(&password).map(out)))
    }

    pub fn on_breach_response(
        &self,
        status: Option<u16>,
        body: String,
    ) -> Result<Option<BreachVerdictDto>, SignupFlowFfiError> {
        self.with(|f| Ok(f.on_breach_response(status, &body).map(Into::into)))
    }

    /// DW-A49: the same rules as sign-up, then the re-registration request.
    pub fn set_password(&self, password: String, confirmation: String) -> Result<AuthHttpRequest, SignupFlowFfiError> {
        let (password, confirmation) = (Zeroizing::new(password), Zeroizing::new(confirmation));
        self.with(|f| f.set_password(&password, &confirmation)).map(out)
    }

    pub fn on_register_response(&self, response: AuthHttpResponse) -> Result<AuthHttpRequest, SignupFlowFfiError> {
        self.with(|f| f.on_register_response(&into(response))).map(out)
    }

    /// The last step; the handle is spent afterwards.
    pub fn on_finalize_response(&self, response: AuthHttpResponse) -> Result<RecoveredFfi, SignupFlowFfiError> {
        let flow = self
            .inner
            .lock()
            .map_err(|_| wrong_state())?
            .take()
            .ok_or_else(wrong_state)?;
        Ok(match flow.on_finalize_response(&into(response))? {
            Recovered::SignedIn {
                session_token,
                master_key,
            } => RecoveredFfi::SignedIn {
                session_token: session_token.to_string(),
                master_key: Zeroizing::new(master_key.to_bytes()).to_vec(),
            },
            Recovered::SignInRequired => RecoveredFfi::SignInRequired,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(body: &str) -> AuthHttpResponse {
        AuthHttpResponse {
            status: 200,
            body_json: body.into(),
            retry_after_secs: None,
        }
    }

    #[test]
    fn signup_handle_runs_the_core_steps() {
        let flow = SignupFlowHandle::new(ok(r#"{"policy":{"password":{"min_length":12}}}"#)).unwrap();
        let req = flow.send_code("anna@example.eu".into()).unwrap();
        assert_eq!(
            (req.method.as_str(), req.path.as_str()),
            ("POST", "/api/v1/auth/signup/email-start")
        );
        assert!(!req.needs_session);
        flow.on_code_sent(ok("{}")).unwrap();
        let Err(SignupFlowFfiError::Flow { code, .. }) = flow.set_password("short".into(), "short".into()) else {
            panic!("a short password must be refused")
        };
        assert!(!code.is_empty());
        assert_eq!(flow.phrase_words().unwrap().len(), 12);
        assert_eq!(signup_policy_request().path, "/api/v1/onboarding");
    }

    #[test]
    fn recovery_handle_refuses_a_bad_phrase_and_flags_unknown_words() {
        let bad = PhraseRecoveryHandle::new(ok("{}"), "anna@example.eu".into(), "not twelve words".into());
        assert!(bad.is_err());
        let words = ["abandon", "zzzz", "ability"].map(String::from).to_vec();
        assert_eq!(recovery_unknown_word_positions(words), [1]);
    }
}
