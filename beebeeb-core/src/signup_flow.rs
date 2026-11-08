//! Creating an account, as plain sans-IO logic shared by desktop (Rust), mobile (UniFFI) and web
//! (WASM), in the style of [`crate::auth_flow`]: each step hands the caller an [`HttpRequest`] and
//! takes the [`HttpResponse`] back, so each platform keeps its own transport.
//!
//! ```text
//! SignupPolicy::request()            GET  /api/v1/onboarding           → SignupPolicy::from_response
//! SignupFlow::send_code(email)       POST /api/v1/auth/signup/email-start  {email}          (202, same for any address)
//! SignupFlow::verify_code(code)      POST /api/v1/auth/signup/email-verify {email, code}    → signup_ticket (kept here)
//! SignupFlow::breach_request(pw)     GET  <policy.password.breach_check.endpoint, {prefix}> (k-anonymity, text body)
//! SignupFlow::set_password(pw, pw2)  the ceremony's gate: length, match, breach verdict
//! SignupFlow::begin_phrase()         12 BIP39 words generated here; confirm_phrase(answers) checks 3 of them
//! SignupFlow::register_start()       POST /api/v1/opaque/register-start  {email, client_message, signup_ticket}
//! SignupFlow::on_register_start(r)   POST /api/v1/opaque/register-finish {email, client_message, x25519_public_key,
//!                                                                         recovery_check, signup_ticket}
//! SignupFlow::on_register_finish(r)  → Created { session_token, user_id, master_key }
//! SignupFlow::terms_request()        POST /api/v1/account/terms-acceptance {version} (signed in)
//! ```
//!
//! The password, the phrase, the signup ticket and the master key live in [`Zeroizing`] buffers
//! (inside [`SignupCeremony`] for the first two) and never appear in a `Debug` print or an error.
//! Errors are codes ([`SignupError::code`]); a server body is never echoed.
use std::fmt;

use base64::Engine;
use serde_json::json;
use zeroize::Zeroizing;

use crate::auth_flow::sign_in::{can_submit, canonical_email};
use crate::auth_flow::{HttpRequest, HttpResponse, RequestAuth, b64, b64_decode};
use crate::kdf::MasterKey;
use crate::onboarding::{
    BreachCheck, BreachPolicy, BreachResponse, BreachVerdict, CeremonyConfig, CeremonyError, PasswordEvaluation,
    PasswordPolicy, SignupCeremony, evaluate_password,
};

pub const ONBOARDING_PATH: &str = "/api/v1/onboarding";
pub const EMAIL_START_PATH: &str = "/api/v1/auth/signup/email-start";
pub const EMAIL_VERIFY_PATH: &str = "/api/v1/auth/signup/email-verify";
pub const REGISTER_START_PATH: &str = "/api/v1/opaque/register-start";
pub const REGISTER_FINISH_PATH: &str = "/api/v1/opaque/register-finish";
pub const TERMS_ACCEPTANCE_PATH: &str = "/api/v1/account/terms-acceptance";

/// The numbers the server declares for sign-up (`policy` in `GET /api/v1/onboarding`). The client
/// reads them, never hard-codes them (DW-A32, DW-A36).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignupPolicy {
    /// Effective minimum, never below [`crate::onboarding::MIN_LENGTH_FLOOR`].
    pub min_length: u32,
    /// Same-origin path template with exactly one `{prefix}`; `None` = no breach check declared.
    pub breach_endpoint: Option<String>,
    pub breach_fail_open: bool,
    pub verify_word_count: u32,
    pub code_length: u32,
    pub code_ttl_secs: u32,
    pub resend_after_secs: u32,
    pub terms_version: Option<String>,
    pub terms_url: Option<String>,
    pub privacy_url: Option<String>,
}

impl Default for SignupPolicy {
    fn default() -> Self {
        Self {
            min_length: PasswordPolicy::from_server(0).min_length(),
            breach_endpoint: None,
            breach_fail_open: false,
            verify_word_count: crate::onboarding::VERIFY_WORD_COUNT_FLOOR,
            code_length: 8,
            code_ttl_secs: 900,
            resend_after_secs: 60,
            terms_version: None,
            terms_url: None,
            privacy_url: None,
        }
    }
}

fn own_https_url(v: Option<&serde_json::Value>) -> Option<String> {
    let s = v?.as_str()?;
    let rest = s.strip_prefix("https://")?;
    let host = rest.split('/').next()?;
    (host == "beebeeb.io" || host.ends_with(".beebeeb.io")).then(|| s.to_owned())
}

fn breach_path(v: Option<&serde_json::Value>) -> Option<String> {
    let s = v?.as_str()?;
    let ok = s.starts_with("/api/") && s.matches("{prefix}").count() == 1 && !s.contains("//") && !s.contains("..");
    ok.then(|| s.to_owned())
}

impl SignupPolicy {
    /// `GET /api/v1/onboarding` (no session).
    pub fn request() -> HttpRequest {
        HttpRequest::get(ONBOARDING_PATH.to_owned(), RequestAuth::None)
    }

    /// Parse the document's `policy`. Missing numbers fall back to the defaults the server
    /// documents; a minimum below the floor is raised to it.
    pub fn from_response(resp: &HttpResponse) -> Result<Self, SignupError> {
        if !resp.ok() {
            return Err(SignupError::from_status(resp));
        }
        let p = resp.body.get("policy").unwrap_or(&resp.body);
        let d = Self::default();
        let num = |v: Option<&serde_json::Value>, def: u32| {
            v.and_then(|v| v.as_u64())
                .map(|n| n.min(u32::MAX as u64) as u32)
                .unwrap_or(def)
        };
        let pw = p.get("password");
        let bc = pw.and_then(|pw| pw.get("breach_check"));
        let rp = p.get("recovery_phrase");
        let ec = p.get("email_code");
        let terms = p.get("terms");
        Ok(Self {
            min_length: PasswordPolicy::from_server(num(pw.and_then(|v| v.get("min_length")), d.min_length))
                .min_length(),
            breach_endpoint: breach_path(bc.and_then(|b| b.get("endpoint"))),
            breach_fail_open: bc
                .and_then(|b| b.get("fail_open"))
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
            verify_word_count: num(rp.and_then(|v| v.get("verify_word_count")), d.verify_word_count)
                .max(crate::onboarding::VERIFY_WORD_COUNT_FLOOR),
            code_length: num(ec.and_then(|v| v.get("length")), d.code_length),
            code_ttl_secs: num(ec.and_then(|v| v.get("ttl_seconds")), d.code_ttl_secs),
            resend_after_secs: num(ec.and_then(|v| v.get("resend_after_seconds")), d.resend_after_secs),
            terms_version: terms
                .and_then(|t| t.get("version"))
                .and_then(|v| v.as_str())
                .map(str::to_owned),
            terms_url: own_https_url(terms.and_then(|t| t.get("url"))),
            privacy_url: own_https_url(terms.and_then(|t| t.get("privacy_url"))),
        })
    }

    pub(crate) fn password_policy(&self) -> PasswordPolicy {
        PasswordPolicy::from_server(self.min_length)
    }

    pub(crate) fn breach_policy(&self) -> BreachPolicy {
        match self.breach_endpoint {
            Some(_) => BreachPolicy::Required {
                fail_open: self.breach_fail_open,
            },
            None => BreachPolicy::NotRequired,
        }
    }

    fn ceremony_config(&self) -> CeremonyConfig {
        CeremonyConfig {
            password_policy: self.password_policy(),
            email_verification_required: true,
            verify_word_count: self.verify_word_count,
            breach: self.breach_policy(),
        }
    }
}

/// What can go wrong while creating an account or recovering one, as codes the apps map to
/// their own words.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SignupError {
    InvalidEmail,
    /// HTTP 429: too many requests for this address or network.
    RateLimited {
        retry_after_secs: u64,
    },
    /// The email code was wrong or expired: one answer for both (DW-A33).
    WrongCode,
    /// The signup ticket from the email code expired or was used before the account was made
    /// (DW-A43): back to Verify, the password and phrase are kept.
    TicketExpired,
    /// Sign-up is by invitation on this server and no pilot key was given.
    PilotKeyRequired,
    PasswordMismatch,
    PasswordTooShort {
        missing: u32,
    },
    PasswordBreached,
    /// The breach check could not run and the policy does not let the person through.
    BreachCheckBlocked,
    /// The breach check for this exact password has not been answered yet.
    BreachCheckMissing,
    /// The typed-back words do not match (DW-A41). Does not say which.
    PhraseWordMismatch,
    /// Not 12 valid recovery words (checksum included).
    InvalidPhrase,
    /// The server did not accept the phrase for this email (DW-A48). Nothing changed.
    PhraseNotAccepted,
    /// The recovery token expired between verifying the phrase and setting the password.
    RecoveryExpired,
    /// Registration failed before anything was stored (DW-A43's Try again).
    RegistrationFailed,
    WrongState,
    Server {
        status: u16,
    },
    Protocol(&'static str),
}

impl SignupError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidEmail => "invalid_email",
            Self::RateLimited { .. } => "rate_limited",
            Self::WrongCode => "wrong_code",
            Self::TicketExpired => "ticket_expired",
            Self::PilotKeyRequired => "pilot_key_required",
            Self::PasswordMismatch => "password_mismatch",
            Self::PasswordTooShort { .. } => "password_too_short",
            Self::PasswordBreached => "password_breached",
            Self::BreachCheckBlocked => "breach_check_blocked",
            Self::BreachCheckMissing => "breach_check_missing",
            Self::PhraseWordMismatch => "phrase_word_mismatch",
            Self::InvalidPhrase => "invalid_phrase",
            Self::PhraseNotAccepted => "phrase_not_accepted",
            Self::RecoveryExpired => "recovery_expired",
            Self::RegistrationFailed => "registration_failed",
            Self::WrongState => "wrong_state",
            Self::Server { .. } => "server",
            Self::Protocol(_) => "protocol",
        }
    }

    pub(crate) fn from_status(resp: &HttpResponse) -> Self {
        match resp.status {
            429 => Self::RateLimited {
                retry_after_secs: resp.retry_after_secs.unwrap_or(60),
            },
            status => Self::Server { status },
        }
    }
}

impl fmt::Display for SignupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for SignupError {}

impl From<CeremonyError> for SignupError {
    fn from(e: CeremonyError) -> Self {
        match e {
            CeremonyError::PasswordMismatch => Self::PasswordMismatch,
            CeremonyError::PasswordTooShort { length, min_length } => Self::PasswordTooShort {
                missing: min_length.saturating_sub(length),
            },
            CeremonyError::PasswordBreached { .. } => Self::PasswordBreached,
            CeremonyError::BreachCheckBlocked => Self::BreachCheckBlocked,
            CeremonyError::BreachCheckMissing | CeremonyError::BreachCheckStale => Self::BreachCheckMissing,
            CeremonyError::PhraseWordMismatch | CeremonyError::PhraseAnswerCount { .. } => Self::PhraseWordMismatch,
            CeremonyError::Crypto(_) => Self::Protocol("crypto"),
            _ => Self::WrongState,
        }
    }
}

/// One k-anonymity breach check, shared by sign-up and recovery: the request for the password's
/// prefix, then the answer recorded against that same password.
#[derive(Default)]
pub(crate) struct BreachSlot {
    check: Option<BreachCheck>,
}

impl BreachSlot {
    pub(crate) fn request(&mut self, policy: &SignupPolicy, password: &str) -> Option<HttpRequest> {
        let endpoint = policy.breach_endpoint.as_ref()?;
        let check = BreachCheck::new(password);
        let path = endpoint.replace("{prefix}", check.prefix());
        self.check = Some(check);
        Some(HttpRequest::get(path, RequestAuth::None))
    }

    /// `status` None is a network failure; a non-2xx status or a refused body is an outage too.
    pub(crate) fn record(&mut self, policy: &SignupPolicy, status: Option<u16>, body: &str) -> Option<BreachVerdict> {
        let check = self.check.as_mut()?;
        let response = match status {
            Some(s) if (200..300).contains(&s) => BreachResponse::Body(body),
            _ => BreachResponse::Unavailable,
        };
        let prefix = check.prefix().to_owned();
        if check.record(&prefix, response).is_err() {
            let _ = check.record(&prefix, BreachResponse::Unavailable);
        }
        check.verdict(policy.breach_fail_open)
    }

    pub(crate) fn get(&self) -> Option<&BreachCheck> {
        self.check.as_ref()
    }
}

/// The password gate every flow that sets a password runs (sign-up's rules, DW-A49/A67): the
/// server's minimum (`policy`, already floored by `from_server`), then, when the policy declares a
/// breach check, the verdict of a `breach` check made for THIS password. `fail_open` is the
/// policy's: an outage passes only when the server says so, and a check never answered is missing.
pub fn password_gate(
    policy: &SignupPolicy,
    breach: Option<&crate::onboarding::BreachCheck>,
    password: &str,
) -> Result<(), SignupError> {
    let eval = evaluate(policy, password);
    if !eval.meets_minimum {
        return Err(SignupError::PasswordTooShort {
            missing: eval.missing_characters,
        });
    }
    if policy.breach_endpoint.is_some() {
        let check = breach.ok_or(SignupError::BreachCheckMissing)?;
        if !check.matches_password(password) {
            return Err(SignupError::BreachCheckMissing);
        }
        match check.verdict(policy.breach_fail_open) {
            None => return Err(SignupError::BreachCheckMissing),
            Some(BreachVerdict::Breached { .. }) => return Err(SignupError::PasswordBreached),
            Some(BreachVerdict::CheckFailedBlocked) => return Err(SignupError::BreachCheckBlocked),
            Some(_) => {}
        }
    }
    Ok(())
}

/// The meter and its hint while typing (DW-A36/A37): core's evaluator, so every client agrees.
pub fn evaluate(policy: &SignupPolicy, password: &str) -> PasswordEvaluation {
    evaluate_password(password, &policy.password_policy())
}

/// The account exists: what the caller stores (credential store, vault) and then wipes.
pub struct Created {
    pub session_token: Zeroizing<String>,
    pub user_id: String,
    pub master_key: MasterKey,
}

impl fmt::Debug for Created {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Created")
            .field("user_id", &self.user_id)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Registering {
    No,
    Started,
    Finishing,
}

/// One account creation, from the email to the first session.
pub struct SignupFlow {
    policy: SignupPolicy,
    ceremony: SignupCeremony,
    email: Option<String>,
    ticket: Option<Zeroizing<String>>,
    breach: BreachSlot,
    registering: Registering,
}

impl fmt::Debug for SignupFlow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignupFlow")
            .field("email_verified", &self.ticket.is_some())
            .field("registering", &self.registering)
            .finish_non_exhaustive()
    }
}

impl SignupFlow {
    pub fn new(policy: SignupPolicy) -> Self {
        let ceremony = SignupCeremony::new(policy.ceremony_config());
        Self {
            policy,
            ceremony,
            email: None,
            ticket: None,
            breach: BreachSlot::default(),
            registering: Registering::No,
        }
    }

    pub fn policy(&self) -> &SignupPolicy {
        &self.policy
    }

    /// The canonical email, once a code was asked for.
    pub fn email(&self) -> Option<&str> {
        self.email.as_deref()
    }

    /// Step 1 (DW-A31). A different address than before forgets the earlier code.
    pub fn send_code(&mut self, email: &str) -> Result<HttpRequest, SignupError> {
        let email = canonical_email(email);
        if !can_submit(&email, 1) {
            return Err(SignupError::InvalidEmail);
        }
        if self.email.as_deref() != Some(email.as_str()) {
            if self.email.is_some() {
                self.ceremony.email_changed();
            }
            self.ticket = None;
        }
        let req = HttpRequest::post(EMAIL_START_PATH, json!({ "email": email }), RequestAuth::None);
        self.email = Some(email);
        Ok(req)
    }

    /// The same answer for any address (anti-enumeration): only a rate limit or a failure differs.
    pub fn on_code_sent(&self, resp: &HttpResponse) -> Result<(), SignupError> {
        match resp.status {
            s if (200..300).contains(&s) => Ok(()),
            400 | 422 => Err(SignupError::InvalidEmail),
            _ => Err(SignupError::from_status(resp)),
        }
    }

    /// Step 2 (DW-A32): digits only, spaces stripped, exactly the policy's length.
    pub fn verify_code(&self, code: &str) -> Result<HttpRequest, SignupError> {
        let email = self.email.as_ref().ok_or(SignupError::WrongState)?;
        let digits: Zeroizing<String> =
            Zeroizing::new(code.chars().filter(|c| !c.is_whitespace() && *c != '-').collect());
        if digits.len() != self.policy.code_length as usize || !digits.chars().all(|c| c.is_ascii_digit()) {
            return Err(SignupError::WrongCode);
        }
        Ok(HttpRequest::post(
            EMAIL_VERIFY_PATH,
            json!({ "email": email, "code": digits.as_str() }),
            RequestAuth::None,
        ))
    }

    pub fn on_code_verified(&mut self, resp: &HttpResponse) -> Result<(), SignupError> {
        if resp.status == 400 || resp.status == 401 || resp.status == 404 {
            return Err(SignupError::WrongCode);
        }
        if !resp.ok() {
            return Err(SignupError::from_status(resp));
        }
        let ticket = resp
            .str_field("signup_ticket")
            .map_err(|_| SignupError::Protocol("missing signup_ticket"))?;
        self.ticket = Some(Zeroizing::new(ticket.to_owned()));
        self.ceremony.email_verified();
        Ok(())
    }

    pub fn email_verified(&self) -> bool {
        self.ticket.is_some()
    }

    pub fn evaluate(&self, password: &str) -> PasswordEvaluation {
        evaluate(&self.policy, password)
    }

    /// The breach request for this password, or `None` when the policy declares no check.
    pub fn breach_request(&mut self, password: &str) -> Option<HttpRequest> {
        self.breach.request(&self.policy, password)
    }

    /// Record the breach endpoint's answer (`status` None: no answer at all).
    pub fn on_breach_response(&mut self, status: Option<u16>, body: &str) -> Option<BreachVerdict> {
        self.breach.record(&self.policy, status, body)
    }

    /// Step 4's gate (DW-A36): the ceremony checks the match, the length and the breach verdict.
    pub fn set_password(&mut self, password: &str, confirmation: &str) -> Result<PasswordEvaluation, SignupError> {
        let eval = self.ceremony.set_password(password, confirmation, self.breach.get())?;
        self.registering = Registering::No;
        Ok(eval)
    }

    /// Step 5 (DW-A39): the 12 words, generated here once; calling again returns the same words.
    pub fn phrase_words(&mut self) -> Result<Vec<Zeroizing<String>>, SignupError> {
        self.ceremony.begin_phrase()?;
        let phrase = self.ceremony.phrase()?;
        Ok(phrase
            .split_whitespace()
            .map(|w| Zeroizing::new(w.to_owned()))
            .collect())
    }

    pub fn acknowledge_phrase(&mut self) -> Result<(), SignupError> {
        Ok(self.ceremony.acknowledge_phrase()?)
    }

    /// 1-based positions to ask for (DW-A40), stable for the life of the phrase.
    pub fn challenge_positions(&self) -> Result<Vec<u32>, SignupError> {
        Ok(self.ceremony.challenge_positions()?)
    }

    pub fn confirm_phrase<S: AsRef<str>>(&mut self, answers: &[S]) -> Result<(), SignupError> {
        Ok(self.ceremony.confirm_phrase(answers)?)
    }

    /// Step 6 (DW-A43), leg 1.
    pub fn register_start(&mut self) -> Result<HttpRequest, SignupError> {
        let email = self.email.clone().ok_or(SignupError::WrongState)?;
        let ticket = self.ticket.as_ref().ok_or(SignupError::TicketExpired)?;
        let start = self.ceremony.start_registration()?;
        self.registering = Registering::Started;
        Ok(HttpRequest::post(
            REGISTER_START_PATH,
            json!({
                "email": email,
                "client_message": b64().encode(&start.message),
                "signup_ticket": ticket.as_str(),
            }),
            RequestAuth::None,
        ))
    }

    fn registration_refused(&mut self, resp: &HttpResponse) -> SignupError {
        self.registering = Registering::No;
        match resp.error_code() {
            Some("signup_ticket_invalid") => {
                self.ticket = None;
                self.ceremony.email_ticket_invalidated();
                SignupError::TicketExpired
            }
            Some("pilot_key_required") => {
                self.ceremony.registration_failed();
                SignupError::PilotKeyRequired
            }
            _ => {
                self.ceremony.registration_failed();
                if resp.status == 429 {
                    SignupError::from_status(resp)
                } else {
                    SignupError::RegistrationFailed
                }
            }
        }
    }

    /// Leg 2: the register-finish request (keys derived from the phrase's master key).
    pub fn on_register_start(&mut self, resp: &HttpResponse) -> Result<HttpRequest, SignupError> {
        if self.registering != Registering::Started {
            return Err(SignupError::WrongState);
        }
        if !resp.ok() {
            return Err(self.registration_refused(resp));
        }
        let server_message = b64_decode(
            resp.str_field("server_message")
                .map_err(|_| SignupError::Protocol("missing server_message"))?,
        )
        .map_err(|_| SignupError::Protocol("invalid base64"))?;
        let finish = match self.ceremony.finish_registration(&server_message) {
            Ok(f) => f,
            Err(_) => {
                self.registering = Registering::No;
                self.ceremony.registration_failed();
                return Err(SignupError::RegistrationFailed);
            }
        };
        let email = self.email.clone().ok_or(SignupError::WrongState)?;
        let ticket = self.ticket.as_ref().ok_or(SignupError::TicketExpired)?;
        self.registering = Registering::Finishing;
        Ok(HttpRequest::post(
            REGISTER_FINISH_PATH,
            json!({
                "email": email,
                "client_message": b64().encode(&finish.upload),
                "x25519_public_key": b64().encode(finish.x25519_public),
                "recovery_check": b64().encode(finish.recovery_check),
                "signup_ticket": ticket.as_str(),
            }),
            RequestAuth::None,
        ))
    }

    /// The account exists: the session and the master key for the caller to store.
    pub fn on_register_finish(&mut self, resp: &HttpResponse) -> Result<Created, SignupError> {
        if self.registering != Registering::Finishing {
            return Err(SignupError::WrongState);
        }
        if !resp.ok() {
            return Err(self.registration_refused(resp));
        }
        let session_token = Zeroizing::new(
            resp.str_field("session_token")
                .map_err(|_| SignupError::Protocol("missing session_token"))?
                .to_owned(),
        );
        let user_id = resp
            .body
            .get("user_id")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_owned();
        let master_key = self.ceremony.account_created()?;
        self.ticket = None;
        self.registering = Registering::No;
        Ok(Created {
            session_token,
            user_id,
            master_key,
        })
    }

    /// Record the accepted terms version once signed in (DW-A35's rule). `None` when the policy
    /// names no version.
    pub fn terms_request(&self) -> Option<HttpRequest> {
        let version = self.policy.terms_version.as_ref()?;
        Some(HttpRequest::post(
            TERMS_ACCEPTANCE_PATH,
            json!({ "version": version }),
            RequestAuth::Session,
        ))
    }

    /// Forget everything (the person left the flow).
    pub fn wipe(&mut self) {
        self.ceremony.wipe();
        self.ticket = None;
        self.breach = BreachSlot::default();
        self.registering = Registering::No;
    }
}

#[cfg(test)]
#[path = "signup_flow_tests.rs"]
mod tests;
