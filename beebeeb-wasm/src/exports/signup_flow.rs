//! WASM surface for core's account creation and phrase recovery (`beebeeb_core::signup_flow`,
//! `beebeeb_core::recovery_flow`), in the style of [`super::auth_flow`]. Thin: no rule lives here.
//! JS sends each request with `fetch` (`{method, path, body, needsSession}`) and feeds the answer
//! back. Errors are thrown as the stable code (`wrong_code`, `password_breached`, ...;
//! `rate_limited:<secs>` for a 429).
//!
//! Secrets: the password, the phrase and the email ticket stay inside WASM memory. The 12 words
//! leave once, for the one-time display (`phraseWords`); the session token and the master key leave
//! once, at the end, for the caller's store.
use beebeeb_core::auth_flow::HttpRequest;
use beebeeb_core::onboarding::BreachVerdict;
use beebeeb_core::recovery_flow::{self as rf, PhraseRecovery, Recovered};
use beebeeb_core::signup_flow::{SignupError, SignupFlow, SignupPolicy};
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

use super::auth_flow::{out, resp, to_js};
use crate::password_evaluation_js;

fn err(e: SignupError) -> JsError {
    match e {
        SignupError::RateLimited { retry_after_secs } => JsError::new(&format!("rate_limited:{retry_after_secs}")),
        other => JsError::new(other.code()),
    }
}

fn wrong_state() -> JsError {
    err(SignupError::WrongState)
}

fn verdict(v: BreachVerdict) -> JsValue {
    let (kind, count) = match v {
        BreachVerdict::Clean => ("clean", None),
        BreachVerdict::Breached { count } => ("breached", Some(count as f64)),
        BreachVerdict::CheckFailedAllowed => ("check_failed_allowed", None),
        BreachVerdict::CheckFailedBlocked => ("check_failed_blocked", None),
        BreachVerdict::NotRequired => ("not_required", None),
    };
    to_js(&serde_json::json!({ "kind": kind, "count": count })).unwrap_or(JsValue::NULL)
}

fn policy(status: u16, body: &str) -> Result<SignupPolicy, JsError> {
    SignupPolicy::from_response(&resp(status, body, None)).map_err(err)
}

fn opt_out(req: Option<HttpRequest>) -> Result<JsValue, JsError> {
    req.map_or(Ok(JsValue::NULL), out)
}

/// The request for the server's sign-up policy (`GET /api/v1/onboarding`).
#[wasm_bindgen(js_name = signupPolicyRequest)]
pub fn signup_policy_request() -> Result<JsValue, JsError> {
    out(SignupPolicy::request())
}

/// 0-based positions of words that are not BIP39 words (DW-A47's per-word hint).
#[wasm_bindgen(js_name = recoveryUnknownWordPositions)]
pub fn recovery_unknown_word_positions(words: Vec<String>) -> Vec<u32> {
    let words: Vec<Zeroizing<String>> = words.into_iter().map(Zeroizing::new).collect();
    rf::unknown_word_positions(&words)
}

/// `new SignupFlow(policyStatus, policyBody)`; then the steps in order: `sendCode` /
/// `onCodeSent`, `verifyCode` / `onCodeVerified`, `evaluate`, `breachRequest` / `onBreachResponse`,
/// `setPassword`, `phraseWords`, `acknowledgePhrase`, `challengePositions`, `confirmPhrase`,
/// `registerStart` / `onRegisterStart` / `onRegisterFinish` (`{sessionToken, userId, masterKey}`),
/// `termsRequest`.
#[wasm_bindgen(js_name = SignupFlow)]
pub struct SignupFlowJs {
    inner: SignupFlow,
}

#[wasm_bindgen(js_class = SignupFlow)]
impl SignupFlowJs {
    #[wasm_bindgen(constructor)]
    pub fn new(policy_status: u16, policy_body: &str) -> Result<SignupFlowJs, JsError> {
        Ok(Self {
            inner: SignupFlow::new(policy(policy_status, policy_body)?),
        })
    }

    #[wasm_bindgen(js_name = sendCode)]
    pub fn send_code(&mut self, email: &str) -> Result<JsValue, JsError> {
        out(self.inner.send_code(email).map_err(err)?)
    }

    #[wasm_bindgen(js_name = onCodeSent)]
    pub fn on_code_sent(&self, status: u16, body: &str, retry_after_secs: Option<u32>) -> Result<(), JsError> {
        self.inner
            .on_code_sent(&resp(status, body, retry_after_secs))
            .map_err(err)
    }

    #[wasm_bindgen(js_name = verifyCode)]
    pub fn verify_code(&self, code: String) -> Result<JsValue, JsError> {
        let code = Zeroizing::new(code);
        out(self.inner.verify_code(&code).map_err(err)?)
    }

    #[wasm_bindgen(js_name = onCodeVerified)]
    pub fn on_code_verified(&mut self, status: u16, body: &str, retry_after_secs: Option<u32>) -> Result<(), JsError> {
        self.inner
            .on_code_verified(&resp(status, body, retry_after_secs))
            .map_err(err)
    }

    pub fn evaluate(&self, password: String) -> Result<JsValue, JsError> {
        let password = Zeroizing::new(password);
        to_js(&password_evaluation_js(&self.inner.evaluate(&password)))
    }

    /// The breach request for this password, or `null` when the policy declares no check.
    #[wasm_bindgen(js_name = breachRequest)]
    pub fn breach_request(&mut self, password: String) -> Result<JsValue, JsError> {
        let password = Zeroizing::new(password);
        opt_out(self.inner.breach_request(&password))
    }

    /// `status` is `undefined` when the endpoint gave no answer. `{kind, count}` or `null`.
    #[wasm_bindgen(js_name = onBreachResponse)]
    pub fn on_breach_response(&mut self, status: Option<u16>, body: &str) -> JsValue {
        self.inner
            .on_breach_response(status, body)
            .map_or(JsValue::NULL, verdict)
    }

    #[wasm_bindgen(js_name = setPassword)]
    pub fn set_password(&mut self, password: String, confirmation: String) -> Result<JsValue, JsError> {
        let (password, confirmation) = (Zeroizing::new(password), Zeroizing::new(confirmation));
        let e = self.inner.set_password(&password, &confirmation).map_err(err)?;
        to_js(&password_evaluation_js(&e))
    }

    /// The 12 words, for the one-time display.
    #[wasm_bindgen(js_name = phraseWords)]
    pub fn phrase_words(&mut self) -> Result<Vec<String>, JsError> {
        Ok(self
            .inner
            .phrase_words()
            .map_err(err)?
            .iter()
            .map(|w| w.to_string())
            .collect())
    }

    #[wasm_bindgen(js_name = acknowledgePhrase)]
    pub fn acknowledge_phrase(&mut self) -> Result<(), JsError> {
        self.inner.acknowledge_phrase().map_err(err)
    }

    /// 1-based word positions to ask for.
    #[wasm_bindgen(js_name = challengePositions)]
    pub fn challenge_positions(&self) -> Result<Vec<u32>, JsError> {
        self.inner.challenge_positions().map_err(err)
    }

    #[wasm_bindgen(js_name = confirmPhrase)]
    pub fn confirm_phrase(&mut self, answers: Vec<String>) -> Result<(), JsError> {
        let answers: Vec<Zeroizing<String>> = answers.into_iter().map(Zeroizing::new).collect();
        self.inner.confirm_phrase(&answers).map_err(err)
    }

    #[wasm_bindgen(js_name = registerStart)]
    pub fn register_start(&mut self) -> Result<JsValue, JsError> {
        out(self.inner.register_start().map_err(err)?)
    }

    #[wasm_bindgen(js_name = onRegisterStart)]
    pub fn on_register_start(
        &mut self,
        status: u16,
        body: &str,
        retry_after_secs: Option<u32>,
    ) -> Result<JsValue, JsError> {
        out(self
            .inner
            .on_register_start(&resp(status, body, retry_after_secs))
            .map_err(err)?)
    }

    /// `{sessionToken, userId, masterKey: Uint8Array}`: store, then drop.
    #[wasm_bindgen(js_name = onRegisterFinish)]
    pub fn on_register_finish(
        &mut self,
        status: u16,
        body: &str,
        retry_after_secs: Option<u32>,
    ) -> Result<JsValue, JsError> {
        let created = self
            .inner
            .on_register_finish(&resp(status, body, retry_after_secs))
            .map_err(err)?;
        let key = Zeroizing::new(created.master_key.to_bytes());
        signed_in(created.session_token.as_str(), Some(&created.user_id), &key)
    }

    #[wasm_bindgen(js_name = termsRequest)]
    pub fn terms_request(&self) -> Result<JsValue, JsError> {
        opt_out(self.inner.terms_request())
    }

    pub fn wipe(&mut self) {
        self.inner.wipe();
    }
}

fn signed_in(session_token: &str, user_id: Option<&str>, master_key: &[u8; 32]) -> Result<JsValue, JsError> {
    let obj = js_sys::Object::new();
    let set = |k: &str, v: JsValue| js_sys::Reflect::set(&obj, &JsValue::from_str(k), &v).map(|_| ());
    set("kind", JsValue::from_str("signed_in")).map_err(|_| JsError::new("protocol"))?;
    set("sessionToken", JsValue::from_str(session_token)).map_err(|_| JsError::new("protocol"))?;
    if let Some(id) = user_id {
        set("userId", JsValue::from_str(id)).map_err(|_| JsError::new("protocol"))?;
    }
    set("masterKey", js_sys::Uint8Array::from(&master_key[..]).into()).map_err(|_| JsError::new("protocol"))?;
    Ok(obj.into())
}

/// `new PhraseRecovery(policyStatus, policyBody, email, phrase)`; `start()` then
/// `onStartResponse`, `evaluate`, `breachRequest` / `onBreachResponse`, `setPassword` (a request),
/// `onRegisterResponse` (a request), `onFinalizeResponse` (`{kind: "signed_in", sessionToken,
/// masterKey}` or `{kind: "sign_in_required"}`).
#[wasm_bindgen(js_name = PhraseRecovery)]
pub struct PhraseRecoveryJs {
    inner: Option<PhraseRecovery>,
    first: Option<HttpRequest>,
}

impl PhraseRecoveryJs {
    fn flow(&mut self) -> Result<&mut PhraseRecovery, JsError> {
        self.inner.as_mut().ok_or_else(wrong_state)
    }
}

#[wasm_bindgen(js_class = PhraseRecovery)]
impl PhraseRecoveryJs {
    #[wasm_bindgen(constructor)]
    pub fn new(
        policy_status: u16,
        policy_body: &str,
        email: &str,
        phrase: String,
    ) -> Result<PhraseRecoveryJs, JsError> {
        let phrase = Zeroizing::new(phrase);
        let (flow, first) = PhraseRecovery::start(policy(policy_status, policy_body)?, email, &phrase).map_err(err)?;
        Ok(Self {
            inner: Some(flow),
            first: Some(first),
        })
    }

    pub fn start(&mut self) -> Result<JsValue, JsError> {
        out(self.first.take().ok_or_else(wrong_state)?)
    }

    #[wasm_bindgen(js_name = onStartResponse)]
    pub fn on_start_response(&mut self, status: u16, body: &str, retry_after_secs: Option<u32>) -> Result<(), JsError> {
        self.flow()?
            .on_start_response(&resp(status, body, retry_after_secs))
            .map_err(err)
    }

    pub fn evaluate(&mut self, password: String) -> Result<JsValue, JsError> {
        let password = Zeroizing::new(password);
        to_js(&password_evaluation_js(&self.flow()?.evaluate(&password)))
    }

    #[wasm_bindgen(js_name = breachRequest)]
    pub fn breach_request(&mut self, password: String) -> Result<JsValue, JsError> {
        let password = Zeroizing::new(password);
        opt_out(self.flow()?.breach_request(&password))
    }

    #[wasm_bindgen(js_name = onBreachResponse)]
    pub fn on_breach_response(&mut self, status: Option<u16>, body: &str) -> Result<JsValue, JsError> {
        Ok(self
            .flow()?
            .on_breach_response(status, body)
            .map_or(JsValue::NULL, verdict))
    }

    #[wasm_bindgen(js_name = setPassword)]
    pub fn set_password(&mut self, password: String, confirmation: String) -> Result<JsValue, JsError> {
        let (password, confirmation) = (Zeroizing::new(password), Zeroizing::new(confirmation));
        out(self.flow()?.set_password(&password, &confirmation).map_err(err)?)
    }

    #[wasm_bindgen(js_name = onRegisterResponse)]
    pub fn on_register_response(
        &mut self,
        status: u16,
        body: &str,
        retry_after_secs: Option<u32>,
    ) -> Result<JsValue, JsError> {
        out(self
            .flow()?
            .on_register_response(&resp(status, body, retry_after_secs))
            .map_err(err)?)
    }

    /// The last step; the object is spent afterwards.
    #[wasm_bindgen(js_name = onFinalizeResponse)]
    pub fn on_finalize_response(
        &mut self,
        status: u16,
        body: &str,
        retry_after_secs: Option<u32>,
    ) -> Result<JsValue, JsError> {
        let flow = self.inner.take().ok_or_else(wrong_state)?;
        match flow
            .on_finalize_response(&resp(status, body, retry_after_secs))
            .map_err(err)?
        {
            Recovered::SignedIn {
                session_token,
                master_key,
            } => {
                let key = Zeroizing::new(master_key.to_bytes());
                signed_in(session_token.as_str(), None, &key)
            }
            Recovered::SignInRequired => to_js(&serde_json::json!({ "kind": "sign_in_required" })),
        }
    }
}
