//! Signup ceremony state machine (task 1744, spec sections 5.5 and 5.12).
//!
//! One implementation of the pre-account ceremony for web (WASM), iOS and
//! Android (UniFFI) and desktop (native Rust). It owns the ordering and
//! hygiene rules; it re-implements **no** cryptography. Phrase generation is
//! [`recovery::generate_recovery_phrase`], OPAQUE is
//! [`opaque_protocol`], and the account-binding values are the existing
//! [`opaque::derive_x25519_private`] / [`opaque::derive_x25519_public`] /
//! [`opaque::compute_recovery_check`].
//!
//! # What it enforces
//!
//! The spec's invariant (5.5): `create_account` runs only after every required
//! pre-account step is done, and key material and the phrase never leave the
//! device except as the OPAQUE messages and `recovery_check`.
//!
//! ```text
//!   verify_email_code (only if the server requires it)
//!   set_password            policy evaluation + bound breach check + confirmation
//!   save_recovery_phrase    SavePhrase (shown + acknowledged)
//!                           ConfirmPhrase (N words typed back)
//!   create_account          registration_start -> [server] -> registration_finish
//!                           -> [server accepts] -> account_created
//! ```
//!
//! The relative order of `set_password` and the phrase steps is **not**
//! enforced here: the shipped web client shows the phrase first, while the
//! spec's example document lists the password first, and the server's `steps`
//! array is what orders the UI. The machine gates only `create_account`
//! ([`SignupCeremony::pending_steps`] must be down to `CreateAccount`). See
//! [`SignupCeremony::step`] for the canonical order it reports.
//!
//! # Memory hygiene
//!
//! The password and the phrase are held in [`Zeroizing`] buffers and the master
//! key in a [`MasterKey`] (zeroized on drop). The phrase string is wiped the
//! moment it is confirmed; the master key derived from it is kept (so a retry
//! after a rejected `register-finish` does not force the user to write down a
//! different phrase) until [`SignupCeremony::account_created`] hands it to the
//! caller. The password is kept until then for the same retry reason, because
//! OPAQUE needs it again at the next `registration_start`.
//!
//! Dropping the ceremony wipes everything, but a binding's handle is freed on
//! the host's schedule (a JS finalizer, ARC, a GC), which can be minutes after
//! the user left the flow. Clients must therefore call
//! [`SignupCeremony::wipe`] (`abandon()` in the bindings) on back, cancel and
//! error exits instead of waiting for the handle to be collected.
//!
//! # The email address
//!
//! The ceremony has no notion of the email address; the server's signup ticket
//! is what binds a verified email to the account that gets created, and that
//! binding is mandatory server side. If the UI lets the user change the email
//! after verification, the client must call [`SignupCeremony::email_changed`].

use rand::rngs::OsRng;
use thiserror::Error;
use zeroize::Zeroizing;

use super::breach::{BreachCheck, BreachVerdict};
use super::password::{PasswordEvaluation, PasswordPolicy, evaluate_password};
use crate::CoreError;
use crate::kdf::MasterKey;
use crate::{opaque, opaque_protocol, recovery};

/// Floor for the number of words the user must type back, regardless of what
/// the server document says. Matches what the web client has always asked for.
/// This is a safe floor, not the policy: the number comes from
/// `policy.recovery_phrase.verify_word_count`.
pub const VERIFY_WORD_COUNT_FLOOR: u32 = 3;

/// Steps of the ceremony, in the canonical order [`SignupCeremony::step`] reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CeremonyStep {
    /// Server `verify_email_code`. Completed by the client calling
    /// [`SignupCeremony::email_verified`] after the server accepted the code.
    VerifyEmail,
    /// Server `set_password`.
    SetPassword,
    /// Server `save_recovery_phrase`, part 1: phrase generated, shown and acknowledged.
    SavePhrase,
    /// Server `save_recovery_phrase`, part 2: words typed back correctly.
    ConfirmPhrase,
    /// Server `create_account`: OPAQUE registration.
    CreateAccount,
    /// Terminal.
    Done,
}

impl CeremonyStep {
    /// Stable lowercase token, one per ceremony step (WASM and logs).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::VerifyEmail => "verify_email",
            Self::SetPassword => "set_password",
            Self::SavePhrase => "save_phrase",
            Self::ConfirmPhrase => "confirm_phrase",
            Self::CreateAccount => "create_account",
            Self::Done => "done",
        }
    }

    /// The server step id this ceremony step belongs to (spec 5.5).
    pub fn spec_step_id(self) -> &'static str {
        match self {
            Self::VerifyEmail => "verify_email_code",
            Self::SetPassword => "set_password",
            Self::SavePhrase | Self::ConfirmPhrase => "save_recovery_phrase",
            Self::CreateAccount => "create_account",
            Self::Done => "done",
        }
    }
}

/// Whether the server's document requires a breach check, and what to do when
/// the check cannot run. From `policy.password.breach_check`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BreachPolicy {
    /// The document declares no breach check. A supplied check is ignored.
    NotRequired,
    /// A [`BreachCheck`] bound to the password and holding the endpoint's
    /// answer is required. `fail_open` is applied by the ceremony itself when
    /// the check could not complete, so a client cannot choose it.
    Required { fail_open: bool },
}

/// Numbers and switches the server declares, applied once at construction.
#[derive(Clone, Copy, Debug)]
pub struct CeremonyConfig {
    /// From `policy.password.min_length`.
    pub password_policy: PasswordPolicy,
    /// Whether the server's `steps` include a required `verify_email_code`.
    pub email_verification_required: bool,
    /// From `policy.recovery_phrase.verify_word_count`; clamped to
    /// `[VERIFY_WORD_COUNT_FLOOR, phrase word count]`.
    pub verify_word_count: u32,
    /// From `policy.password.breach_check`.
    pub breach: BreachPolicy,
}

#[derive(Debug, Error)]
pub enum CeremonyError {
    /// The action needs an earlier step to be finished first.
    #[error("cannot {action} yet: step {blocking:?} is not done")]
    StepNotDone {
        action: &'static str,
        blocking: CeremonyStep,
    },
    /// The action is not valid in the current registration state.
    #[error("cannot {action}: {reason}")]
    InvalidState { action: &'static str, reason: &'static str },
    #[error("passwords do not match")]
    PasswordMismatch,
    #[error("password is too short: {length} characters, minimum {min_length}")]
    PasswordTooShort { length: u32, min_length: u32 },
    #[error("password appears in {count} known breaches")]
    PasswordBreached { count: u64 },
    #[error("the breach check could not run and the server requires it")]
    BreachCheckBlocked,
    #[error("the breach check is required and has not been answered")]
    BreachCheckMissing,
    #[error("the breach check was run for a different password")]
    BreachCheckStale,
    #[error("the recovery phrase is not available (not generated, or already confirmed)")]
    PhraseUnavailable,
    #[error("expected {expected} words, got {got}")]
    PhraseAnswerCount { expected: usize, got: usize },
    #[error("one or more words are incorrect")]
    PhraseWordMismatch,
    #[error(transparent)]
    Crypto(#[from] CoreError),
}

impl CeremonyError {
    /// Stable machine-readable code for clients (the Display text is English
    /// and is not a contract).
    pub fn code(&self) -> &'static str {
        match self {
            Self::StepNotDone { .. } => "step_not_done",
            Self::InvalidState { .. } => "invalid_state",
            Self::PasswordMismatch => "password_mismatch",
            Self::PasswordTooShort { .. } => "password_too_short",
            Self::PasswordBreached { .. } => "password_breached",
            Self::BreachCheckBlocked => "breach_check_blocked",
            Self::BreachCheckMissing => "breach_check_missing",
            Self::BreachCheckStale => "breach_check_stale",
            Self::PhraseUnavailable => "phrase_unavailable",
            Self::PhraseAnswerCount { .. } => "phrase_answer_count",
            Self::PhraseWordMismatch => "phrase_word_mismatch",
            Self::Crypto(_) => "crypto",
        }
    }
}

/// OPAQUE registration progress.
enum Registration {
    NotStarted,
    /// `registration_start` done; holds the client state for the finish call.
    Started(Zeroizing<Vec<u8>>),
    /// `registration_finish` done; waiting for the server to accept.
    Finished,
}

/// Output of [`SignupCeremony::start_registration`].
pub struct RegistrationStart {
    /// OPAQUE `RegistrationRequest` for `opaque/register-start`.
    pub message: Vec<u8>,
}

/// Output of [`SignupCeremony::finish_registration`]: everything
/// `opaque/register-finish` takes from the client.
pub struct RegistrationFinish {
    /// OPAQUE `RegistrationUpload`.
    pub upload: Vec<u8>,
    /// X25519 public key derived from the master key.
    pub x25519_public: [u8; 32],
    /// Recovery binding (HKDF of the master key).
    pub recovery_check: [u8; 32],
}

/// The pre-account ceremony. Not `Clone`, not `Send`-restricted; drive it from
/// one place.
pub struct SignupCeremony {
    config: CeremonyConfig,
    email_verified: bool,
    password: Option<Zeroizing<String>>,
    phrase: Option<Zeroizing<String>>,
    master_key: Option<MasterKey>,
    /// 0-based word positions the user must type back, ascending.
    challenge: Vec<usize>,
    phrase_acknowledged: bool,
    phrase_confirmed: bool,
    registration: Registration,
    done: bool,
}

impl SignupCeremony {
    pub fn new(config: CeremonyConfig) -> Self {
        Self {
            config,
            email_verified: false,
            password: None,
            phrase: None,
            master_key: None,
            challenge: Vec::new(),
            phrase_acknowledged: false,
            phrase_confirmed: false,
            registration: Registration::NotStarted,
            done: false,
        }
    }

    // -- progress ---------------------------------------------------------

    /// Steps not yet done, in canonical order. Empty only after
    /// [`account_created`](Self::account_created).
    pub fn pending_steps(&self) -> Vec<CeremonyStep> {
        if self.done {
            return Vec::new();
        }
        let mut out = Vec::new();
        if self.config.email_verification_required && !self.email_verified {
            out.push(CeremonyStep::VerifyEmail);
        }
        if self.password.is_none() {
            out.push(CeremonyStep::SetPassword);
        }
        if !self.phrase_acknowledged {
            out.push(CeremonyStep::SavePhrase);
        }
        if !self.phrase_confirmed {
            out.push(CeremonyStep::ConfirmPhrase);
        }
        out.push(CeremonyStep::CreateAccount);
        out
    }

    /// First pending step in canonical order, or `Done`. The UI follows the
    /// server's `steps` order; this is the order the machine itself would
    /// walk and the one it reports when asked "what is next".
    pub fn step(&self) -> CeremonyStep {
        self.pending_steps().first().copied().unwrap_or(CeremonyStep::Done)
    }

    // -- verify_email_code ------------------------------------------------

    /// The server accepted the email code. Idempotent.
    pub fn email_verified(&mut self) {
        self.email_verified = true;
    }

    /// The server said the signup ticket is no longer valid (it expires after
    /// `ticket_ttl_seconds`). The user must verify the email again; the
    /// password and the confirmed phrase are kept (spec 5.9). Also resets any
    /// in-flight OPAQUE registration.
    pub fn email_ticket_invalidated(&mut self) {
        self.email_verified = false;
        self.registration = Registration::NotStarted;
    }

    /// The user changed the email address after it was verified. The
    /// verification belonged to the old address, so it is withdrawn; the
    /// password and the confirmed phrase are kept. Also resets any in-flight
    /// OPAQUE registration. (The server's signup ticket binding is what
    /// actually prevents a mismatch; this keeps the client honest.)
    pub fn email_changed(&mut self) {
        self.email_verified = false;
        self.registration = Registration::NotStarted;
    }

    /// Abandon the signup: wipe the password, the phrase, the master key and
    /// every step already done, and return to the state of a fresh ceremony
    /// with the same config. Call on back, cancel and error exits; do not rely
    /// on the host freeing the handle promptly.
    pub fn wipe(&mut self) {
        // Assigning drops the old value, and every secret field zeroizes on drop.
        *self = Self::new(self.config);
    }

    // -- set_password -----------------------------------------------------

    /// Evaluate and store the password.
    ///
    /// `breach` is the client's [`BreachCheck`]: made for this password, with
    /// the endpoint's answer recorded. When the config requires a breach check
    /// the ceremony re-derives the digest from `password`, refuses a check made
    /// for a different one, and computes the verdict itself with the server's
    /// `fail_open`. A bare verdict is deliberately not accepted: it could be
    /// stale after the user edited the field, or forged.
    ///
    /// Rejections, in order: mismatch with `confirmation`, below the policy
    /// minimum, breach check missing, breach check for another password, found
    /// in a breach corpus, breach check required but could not run.
    ///
    /// Changing the password discards any in-flight OPAQUE registration, which
    /// is bound to the old one.
    pub fn set_password(
        &mut self,
        password: &str,
        confirmation: &str,
        breach: Option<&BreachCheck>,
    ) -> Result<PasswordEvaluation, CeremonyError> {
        if password != confirmation {
            return Err(CeremonyError::PasswordMismatch);
        }
        let eval = evaluate_password(password, &self.config.password_policy);
        if !eval.meets_minimum {
            return Err(CeremonyError::PasswordTooShort {
                length: eval.length,
                min_length: eval.min_length,
            });
        }
        let verdict = match self.config.breach {
            BreachPolicy::NotRequired => BreachVerdict::NotRequired,
            BreachPolicy::Required { fail_open } => {
                let check = breach.ok_or(CeremonyError::BreachCheckMissing)?;
                if !check.matches_password(password) {
                    return Err(CeremonyError::BreachCheckStale);
                }
                check.verdict(fail_open).ok_or(CeremonyError::BreachCheckMissing)?
            }
        };
        match verdict {
            BreachVerdict::Breached { count } => return Err(CeremonyError::PasswordBreached { count }),
            BreachVerdict::CheckFailedBlocked => return Err(CeremonyError::BreachCheckBlocked),
            BreachVerdict::Clean | BreachVerdict::CheckFailedAllowed | BreachVerdict::NotRequired => {}
        }
        self.password = Some(Zeroizing::new(password.to_owned()));
        self.registration = Registration::NotStarted;
        Ok(eval)
    }

    // -- save_recovery_phrase ---------------------------------------------

    /// Generate the recovery phrase and its master key (Argon2id, roughly a
    /// second). Idempotent: a second call keeps the existing phrase, so going
    /// back and forward in the UI never shows a different phrase.
    pub fn begin_phrase(&mut self) -> Result<(), CeremonyError> {
        if self.phrase.is_some() || self.phrase_confirmed {
            return Ok(());
        }
        let (phrase, master_key) = recovery::generate_recovery_phrase()?;
        self.install_phrase(Zeroizing::new(phrase), master_key);
        Ok(())
    }

    fn install_phrase(&mut self, phrase: Zeroizing<String>, master_key: MasterKey) {
        let word_count = phrase.split_whitespace().count();
        let wanted = (self.config.verify_word_count.max(VERIFY_WORD_COUNT_FLOOR) as usize).min(word_count);
        let mut picked = rand::seq::index::sample(&mut OsRng, word_count, wanted).into_vec();
        picked.sort_unstable();
        self.challenge = picked;
        self.phrase = Some(phrase);
        self.master_key = Some(master_key);
    }

    /// The phrase to show the user. Available from [`begin_phrase`](Self::begin_phrase)
    /// until the phrase is confirmed, after which it is wiped.
    pub fn phrase(&self) -> Result<Zeroizing<String>, CeremonyError> {
        self.phrase
            .as_ref()
            .map(|p| Zeroizing::new(p.as_str().to_owned()))
            .ok_or(CeremonyError::PhraseUnavailable)
    }

    /// The user confirms they saved the phrase (the "I have saved it" gate).
    pub fn acknowledge_phrase(&mut self) -> Result<(), CeremonyError> {
        if self.phrase.is_none() && !self.phrase_confirmed {
            return Err(CeremonyError::PhraseUnavailable);
        }
        self.phrase_acknowledged = true;
        Ok(())
    }

    /// 1-based positions of the words to ask for, ascending. Stable for the
    /// life of the phrase, so navigating away and back asks for the same words.
    pub fn challenge_positions(&self) -> Result<Vec<u32>, CeremonyError> {
        if self.phrase.is_none() {
            return Err(CeremonyError::PhraseUnavailable);
        }
        Ok(self.challenge.iter().map(|i| *i as u32 + 1).collect())
    }

    /// Check the typed-back words, in the order of
    /// [`challenge_positions`](Self::challenge_positions). Case and surrounding
    /// whitespace are ignored. On success the phrase string is wiped; the
    /// master key it produced is kept for registration. A wrong answer changes
    /// nothing and may be retried.
    pub fn confirm_phrase<S: AsRef<str>>(&mut self, answers: &[S]) -> Result<(), CeremonyError> {
        if !self.phrase_acknowledged {
            return Err(CeremonyError::StepNotDone {
                action: "confirm the recovery phrase",
                blocking: CeremonyStep::SavePhrase,
            });
        }
        if self.phrase_confirmed {
            return Ok(());
        }
        let phrase = self.phrase.as_ref().ok_or(CeremonyError::PhraseUnavailable)?;
        if answers.len() != self.challenge.len() {
            return Err(CeremonyError::PhraseAnswerCount {
                expected: self.challenge.len(),
                got: answers.len(),
            });
        }
        let words: Vec<&str> = phrase.split_whitespace().collect();
        let all_correct = self.challenge.iter().zip(answers).fold(true, |ok, (idx, answer)| {
            // Every position is compared whatever the earlier ones were (`&`, not
            // `&&`). This is not a constant-time claim: `eq_ignore_ascii_case`
            // still exits early on a length mismatch, which does not matter
            // because the user is checking their own typed words on their own
            // device, not authenticating to anyone.
            ok & words[*idx].eq_ignore_ascii_case(answer.as_ref().trim())
        });
        if !all_correct {
            return Err(CeremonyError::PhraseWordMismatch);
        }
        self.phrase_confirmed = true;
        self.phrase = None; // Zeroizing wipes on drop
        Ok(())
    }

    // -- create_account ---------------------------------------------------

    fn require_ready_for_registration(&self, action: &'static str) -> Result<(), CeremonyError> {
        if self.done {
            return Err(CeremonyError::InvalidState {
                action,
                reason: "the ceremony is already complete",
            });
        }
        if let Some(blocking) = self
            .pending_steps()
            .into_iter()
            .find(|s| *s != CeremonyStep::CreateAccount)
        {
            return Err(CeremonyError::StepNotDone { action, blocking });
        }
        Ok(())
    }

    /// OPAQUE step 1. Only after every other required step is done. Send
    /// `message` to `opaque/register-start`. Calling it again restarts the
    /// exchange.
    pub fn start_registration(&mut self) -> Result<RegistrationStart, CeremonyError> {
        self.require_ready_for_registration("start registration")?;
        let password = self.password.as_ref().ok_or(CeremonyError::InvalidState {
            action: "start registration",
            reason: "no password is set",
        })?;
        let started = opaque_protocol::client_registration_start(password.as_bytes())?;
        self.registration = Registration::Started(Zeroizing::new(started.state));
        Ok(RegistrationStart {
            message: started.message,
        })
    }

    /// OPAQUE step 2, from the server's `register-start` response. Returns what
    /// `opaque/register-finish` takes.
    pub fn finish_registration(&mut self, server_message: &[u8]) -> Result<RegistrationFinish, CeremonyError> {
        self.require_ready_for_registration("finish registration")?;
        let state = match &self.registration {
            Registration::Started(state) => state,
            _ => {
                return Err(CeremonyError::InvalidState {
                    action: "finish registration",
                    reason: "start_registration has not been called",
                });
            }
        };
        let password = self.password.as_ref().ok_or(CeremonyError::InvalidState {
            action: "finish registration",
            reason: "no password is set",
        })?;
        let master_key = self.master_key.as_ref().ok_or(CeremonyError::PhraseUnavailable)?;

        let upload = opaque_protocol::client_registration_finish(state, password.as_bytes(), server_message)?;
        let x25519_private = opaque::derive_x25519_private(master_key);
        let x25519_public = opaque::derive_x25519_public(&x25519_private);
        let recovery_check = *opaque::compute_recovery_check(master_key);

        self.registration = Registration::Finished;
        Ok(RegistrationFinish {
            upload,
            x25519_public,
            recovery_check,
        })
    }

    /// The server rejected `register-finish` for a reason the user can retry
    /// (conflict, transient error). Keeps the password and the phrase-derived
    /// key; the next [`start_registration`](Self::start_registration) begins a
    /// fresh OPAQUE exchange.
    pub fn registration_failed(&mut self) {
        self.registration = Registration::NotStarted;
    }

    /// The server accepted `register-finish`. Ends the ceremony and hands the
    /// master key to the caller, who now owns it. Everything else the ceremony
    /// held is wiped.
    pub fn account_created(&mut self) -> Result<MasterKey, CeremonyError> {
        if !matches!(self.registration, Registration::Finished) {
            return Err(CeremonyError::InvalidState {
                action: "complete the ceremony",
                reason: "finish_registration has not been called",
            });
        }
        let key = self.master_key.take().ok_or(CeremonyError::PhraseUnavailable)?;
        self.password = None;
        self.phrase = None;
        self.registration = Registration::NotStarted;
        self.done = true;
        Ok(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::onboarding::breach::{BreachCheck, BreachQuery, BreachResponse};

    const GOOD_PW: &str = "correct horse battery staple";

    fn cfg(email: bool) -> CeremonyConfig {
        CeremonyConfig {
            password_policy: PasswordPolicy::from_server(12),
            email_verification_required: email,
            verify_word_count: 3,
            breach: BreachPolicy::NotRequired,
        }
    }

    fn cfg_breach(fail_open: bool) -> CeremonyConfig {
        CeremonyConfig {
            breach: BreachPolicy::Required { fail_open },
            ..cfg(false)
        }
    }

    // SHA-1("correct horse battery staple") suffix is not needed: bodies below
    // either carry an unrelated suffix (clean) or the suffix of the password.
    const OTHER_SUFFIX: &str = "0018A45C4D1DEF81644B54AB7F969B88D65";

    /// A check for `password` with the endpoint's answer recorded.
    fn answered(password: &str, response: BreachResponse<'_>) -> BreachCheck {
        let mut c = BreachCheck::new(password);
        c.record(BreachQuery::from_password(password).prefix(), response)
            .unwrap();
        c
    }

    fn clean_body() -> String {
        format!("{OTHER_SUFFIX}:3\r\n")
    }

    /// A phrase with distinct words so wrong-position answers are detectable,
    /// installed without the 256 MiB Argon2id derivation.
    fn with_fixed_phrase(c: &mut SignupCeremony) {
        let phrase = "alpha bravo charlie delta echo foxtrot golf hotel india juliet kilo lima";
        c.install_phrase(Zeroizing::new(phrase.to_owned()), MasterKey::from_bytes([7u8; 32]));
    }

    fn answers_for(c: &SignupCeremony) -> Vec<String> {
        let phrase = c.phrase().unwrap();
        let words: Vec<&str> = phrase.split_whitespace().collect();
        c.challenge_positions()
            .unwrap()
            .iter()
            .map(|p| words[*p as usize - 1].to_owned())
            .collect()
    }

    fn ready_for_registration(c: &mut SignupCeremony) {
        c.email_verified();
        c.set_password(GOOD_PW, GOOD_PW, None).unwrap();
        with_fixed_phrase(c);
        c.acknowledge_phrase().unwrap();
        let a = answers_for(c);
        c.confirm_phrase(&a).unwrap();
    }

    #[test]
    fn fresh_ceremony_lists_every_step_in_canonical_order() {
        let c = SignupCeremony::new(cfg(true));
        assert_eq!(
            c.pending_steps(),
            vec![
                CeremonyStep::VerifyEmail,
                CeremonyStep::SetPassword,
                CeremonyStep::SavePhrase,
                CeremonyStep::ConfirmPhrase,
                CeremonyStep::CreateAccount
            ]
        );
        assert_eq!(c.step(), CeremonyStep::VerifyEmail);
    }

    #[test]
    fn email_step_is_absent_when_the_server_does_not_require_it() {
        let c = SignupCeremony::new(cfg(false));
        assert!(!c.pending_steps().contains(&CeremonyStep::VerifyEmail));
        assert_eq!(c.step(), CeremonyStep::SetPassword);
    }

    #[test]
    fn spec_step_ids_map_both_phrase_parts_to_one_server_step() {
        assert_eq!(CeremonyStep::SavePhrase.spec_step_id(), "save_recovery_phrase");
        assert_eq!(CeremonyStep::ConfirmPhrase.spec_step_id(), "save_recovery_phrase");
        assert_eq!(CeremonyStep::VerifyEmail.spec_step_id(), "verify_email_code");
        assert_eq!(CeremonyStep::CreateAccount.spec_step_id(), "create_account");
    }

    #[test]
    fn create_account_is_refused_until_every_prerequisite_is_done() {
        let mut c = SignupCeremony::new(cfg(true));
        assert!(matches!(
            c.start_registration(),
            Err(CeremonyError::StepNotDone {
                blocking: CeremonyStep::VerifyEmail,
                ..
            })
        ));
        c.email_verified();
        assert!(matches!(
            c.start_registration(),
            Err(CeremonyError::StepNotDone {
                blocking: CeremonyStep::SetPassword,
                ..
            })
        ));
        c.set_password(GOOD_PW, GOOD_PW, None).unwrap();
        assert!(matches!(
            c.start_registration(),
            Err(CeremonyError::StepNotDone {
                blocking: CeremonyStep::SavePhrase,
                ..
            })
        ));
        with_fixed_phrase(&mut c);
        c.acknowledge_phrase().unwrap();
        assert!(matches!(
            c.start_registration(),
            Err(CeremonyError::StepNotDone {
                blocking: CeremonyStep::ConfirmPhrase,
                ..
            })
        ));
        let a = answers_for(&c);
        c.confirm_phrase(&a).unwrap();
        assert_eq!(c.step(), CeremonyStep::CreateAccount);
        assert!(c.start_registration().is_ok());
    }

    #[test]
    fn password_and_phrase_steps_may_happen_in_either_order() {
        // Phrase first (what the shipped web client does today)...
        let mut a = SignupCeremony::new(cfg(false));
        with_fixed_phrase(&mut a);
        a.acknowledge_phrase().unwrap();
        let ans = answers_for(&a);
        a.confirm_phrase(&ans).unwrap();
        assert_eq!(a.step(), CeremonyStep::SetPassword);
        a.set_password(GOOD_PW, GOOD_PW, None).unwrap();
        assert_eq!(a.step(), CeremonyStep::CreateAccount);
        // ...and password first (the spec's example order) end in the same place.
        let mut b = SignupCeremony::new(cfg(false));
        b.set_password(GOOD_PW, GOOD_PW, None).unwrap();
        with_fixed_phrase(&mut b);
        b.acknowledge_phrase().unwrap();
        let ans = answers_for(&b);
        b.confirm_phrase(&ans).unwrap();
        assert_eq!(b.step(), CeremonyStep::CreateAccount);
    }

    #[test]
    fn set_password_rejections() {
        let mut c = SignupCeremony::new(cfg(false));
        assert!(matches!(
            c.set_password(GOOD_PW, "different", None),
            Err(CeremonyError::PasswordMismatch)
        ));
        assert!(matches!(
            c.set_password("short", "short", None),
            Err(CeremonyError::PasswordTooShort {
                length: 5,
                min_length: 12
            })
        ));
        assert_eq!(
            c.step(),
            CeremonyStep::SetPassword,
            "no rejection may store the password"
        );
        assert!(c.set_password(GOOD_PW, GOOD_PW, None).is_ok());
    }

    #[test]
    fn a_required_breach_check_gates_the_password() {
        let body = clean_body();
        let breached_body = format!(
            "{}:42\n",
            crate::onboarding::breach::BreachQuery::from_password(GOOD_PW)
                .suffix()
                .to_owned()
        );

        // Clean answer passes.
        let mut c = SignupCeremony::new(cfg_breach(false));
        let ok = answered(GOOD_PW, BreachResponse::Body(&body));
        assert!(c.set_password(GOOD_PW, GOOD_PW, Some(&ok)).is_ok());

        // Breached is refused with the count.
        let mut c = SignupCeremony::new(cfg_breach(true));
        let hit = answered(GOOD_PW, BreachResponse::Body(&breached_body));
        assert!(matches!(
            c.set_password(GOOD_PW, GOOD_PW, Some(&hit)),
            Err(CeremonyError::PasswordBreached { count: 42 })
        ));
        assert_eq!(c.step(), CeremonyStep::SetPassword, "a rejection stores nothing");

        // Outage: the SERVER's fail_open decides, via the config.
        let down = answered(GOOD_PW, BreachResponse::Unavailable);
        let mut open = SignupCeremony::new(cfg_breach(true));
        assert!(open.set_password(GOOD_PW, GOOD_PW, Some(&down)).is_ok());
        let mut closed = SignupCeremony::new(cfg_breach(false));
        assert!(matches!(
            closed.set_password(GOOD_PW, GOOD_PW, Some(&down)),
            Err(CeremonyError::BreachCheckBlocked)
        ));
        assert_eq!(closed.step(), CeremonyStep::SetPassword);
    }

    #[test]
    fn a_breach_check_for_another_password_is_refused() {
        // Task 1744 review M1 / Codex P1: the user edits the field while the
        // request is in flight; the old password's "clean" must not pass.
        let body = clean_body();
        let mut c = SignupCeremony::new(cfg_breach(true));
        let for_old = answered("an older password!", BreachResponse::Body(&body));
        let err = c.set_password(GOOD_PW, GOOD_PW, Some(&for_old)).unwrap_err();
        assert!(matches!(err, CeremonyError::BreachCheckStale), "{err}");
        assert_eq!(err.code(), "breach_check_stale");
        assert_eq!(c.step(), CeremonyStep::SetPassword, "nothing stored");
    }

    #[test]
    fn a_missing_or_unanswered_breach_check_is_refused_when_required() {
        let mut c = SignupCeremony::new(cfg_breach(true));
        let err = c.set_password(GOOD_PW, GOOD_PW, None).unwrap_err();
        assert!(matches!(err, CeremonyError::BreachCheckMissing), "{err}");
        assert_eq!(err.code(), "breach_check_missing");
        // Created for the right password but never answered: the same refusal,
        // even though fail_open is true (no answer is not an outage).
        let unanswered = BreachCheck::new(GOOD_PW);
        assert!(matches!(
            c.set_password(GOOD_PW, GOOD_PW, Some(&unanswered)),
            Err(CeremonyError::BreachCheckMissing)
        ));
        assert_eq!(c.step(), CeremonyStep::SetPassword);
    }

    #[test]
    fn an_empty_endpoint_body_does_not_satisfy_a_fail_closed_gate() {
        // Task 1744 review M2 through the ceremony: an unseeded server node.
        let mut c = SignupCeremony::new(cfg_breach(false));
        let empty = answered(GOOD_PW, BreachResponse::Body(""));
        assert!(matches!(
            c.set_password(GOOD_PW, GOOD_PW, Some(&empty)),
            Err(CeremonyError::BreachCheckBlocked)
        ));
    }

    #[test]
    fn a_supplied_breach_check_is_ignored_when_the_document_requires_none() {
        let mut c = SignupCeremony::new(cfg(false));
        let hit = answered(
            "something else entirely",
            BreachResponse::Body(&format!("{OTHER_SUFFIX}:1")),
        );
        assert!(c.set_password(GOOD_PW, GOOD_PW, Some(&hit)).is_ok());
    }

    #[test]
    fn server_policy_numbers_drive_the_gate() {
        let mut c = SignupCeremony::new(CeremonyConfig {
            password_policy: PasswordPolicy::from_server(40),
            ..cfg(false)
        });
        assert!(matches!(
            c.set_password(GOOD_PW, GOOD_PW, None),
            Err(CeremonyError::PasswordTooShort { min_length: 40, .. })
        ));
    }

    #[test]
    fn confirm_requires_acknowledgement_first() {
        let mut c = SignupCeremony::new(cfg(false));
        with_fixed_phrase(&mut c);
        let a = answers_for(&c);
        assert!(matches!(
            c.confirm_phrase(&a),
            Err(CeremonyError::StepNotDone {
                blocking: CeremonyStep::SavePhrase,
                ..
            })
        ));
    }

    #[test]
    fn challenge_is_stable_distinct_ascending_and_sized_by_the_server() {
        let mut c = SignupCeremony::new(CeremonyConfig {
            verify_word_count: 5,
            ..cfg(false)
        });
        with_fixed_phrase(&mut c);
        let first = c.challenge_positions().unwrap();
        assert_eq!(first, c.challenge_positions().unwrap(), "stable across calls");
        assert_eq!(first.len(), 5);
        assert!(first.windows(2).all(|w| w[0] < w[1]), "ascending and distinct");
        assert!(first.iter().all(|p| (1..=12).contains(p)), "1-based positions in range");
    }

    #[test]
    fn verify_word_count_is_floored_and_capped() {
        for (asked, expect) in [(0u32, 3usize), (1, 3), (3, 3), (12, 12), (99, 12)] {
            let mut c = SignupCeremony::new(CeremonyConfig {
                verify_word_count: asked,
                ..cfg(false)
            });
            with_fixed_phrase(&mut c);
            assert_eq!(c.challenge_positions().unwrap().len(), expect, "asked {asked}");
        }
    }

    #[test]
    fn confirm_phrase_accepts_case_and_whitespace_and_wipes_the_phrase() {
        let mut c = SignupCeremony::new(cfg(false));
        with_fixed_phrase(&mut c);
        c.acknowledge_phrase().unwrap();
        let sloppy: Vec<String> = answers_for(&c)
            .iter()
            .map(|w| format!("  {}  ", w.to_uppercase()))
            .collect();
        c.confirm_phrase(&sloppy).unwrap();
        assert!(
            matches!(c.phrase(), Err(CeremonyError::PhraseUnavailable)),
            "phrase wiped"
        );
        assert!(matches!(c.challenge_positions(), Err(CeremonyError::PhraseUnavailable)));
        assert!(
            c.master_key.is_some(),
            "the key derived from the phrase is kept for registration"
        );
        assert!(
            c.confirm_phrase(&[] as &[String]).is_ok(),
            "confirming again is a harmless no-op"
        );
    }

    #[test]
    fn wrong_words_are_rejected_and_retryable() {
        let mut c = SignupCeremony::new(cfg(false));
        with_fixed_phrase(&mut c);
        c.acknowledge_phrase().unwrap();
        let mut bad = answers_for(&c);
        bad[1] = "zulu".into();
        assert!(matches!(c.confirm_phrase(&bad), Err(CeremonyError::PhraseWordMismatch)));
        assert!(c.phrase().is_ok(), "a failed attempt must not wipe the phrase");
        assert!(matches!(
            c.confirm_phrase(&bad[..2]),
            Err(CeremonyError::PhraseAnswerCount { expected: 3, got: 2 })
        ));
        let good = answers_for(&c);
        assert!(c.confirm_phrase(&good).is_ok());
    }

    #[test]
    fn words_in_the_wrong_positions_do_not_pass() {
        let mut c = SignupCeremony::new(cfg(false));
        with_fixed_phrase(&mut c);
        c.acknowledge_phrase().unwrap();
        let mut swapped = answers_for(&c);
        swapped.swap(0, 2);
        assert!(matches!(
            c.confirm_phrase(&swapped),
            Err(CeremonyError::PhraseWordMismatch)
        ));
    }

    #[test]
    fn begin_phrase_is_idempotent_and_matches_recovery() {
        let mut c = SignupCeremony::new(cfg(false));
        c.begin_phrase().unwrap();
        let first = c.phrase().unwrap();
        c.begin_phrase().unwrap();
        assert_eq!(*first, *c.phrase().unwrap(), "a second call must not regenerate");
        assert_eq!(first.split_whitespace().count(), beebeeb_types::RECOVERY_WORD_COUNT);
        // The key the ceremony holds is exactly the one the phrase recovers.
        let recovered = recovery::recover_from_phrase(&first).unwrap();
        assert_eq!(c.master_key.as_ref().unwrap().as_bytes(), recovered.as_bytes());
    }

    #[test]
    fn acknowledging_before_a_phrase_exists_is_refused() {
        let mut c = SignupCeremony::new(cfg(false));
        assert!(matches!(c.acknowledge_phrase(), Err(CeremonyError::PhraseUnavailable)));
    }

    #[test]
    fn finish_before_start_and_complete_before_finish_are_refused() {
        let mut c = SignupCeremony::new(cfg(false));
        ready_for_registration(&mut c);
        assert!(matches!(
            c.finish_registration(&[0u8; 8]),
            Err(CeremonyError::InvalidState { .. })
        ));
        assert!(matches!(c.account_created(), Err(CeremonyError::InvalidState { .. })));
    }

    #[test]
    fn garbage_server_message_is_a_crypto_error_and_keeps_state() {
        let mut c = SignupCeremony::new(cfg(false));
        ready_for_registration(&mut c);
        c.start_registration().unwrap();
        let Err(err) = c.finish_registration(&[1, 2, 3]) else {
            panic!("garbage must fail")
        };
        assert!(matches!(err, CeremonyError::Crypto(_)), "{err}");
        assert_eq!(err.code(), "crypto");
        // Still in the Started state: the caller may retry with a good message
        // or call registration_failed.
        assert!(matches!(c.registration, Registration::Started(_)));
    }

    #[test]
    fn changing_the_password_discards_the_in_flight_registration() {
        let mut c = SignupCeremony::new(cfg(false));
        ready_for_registration(&mut c);
        c.start_registration().unwrap();
        assert!(matches!(c.registration, Registration::Started(_)));
        c.set_password("another long password!", "another long password!", None)
            .unwrap();
        assert!(matches!(c.registration, Registration::NotStarted));
    }

    #[test]
    fn ticket_invalidation_returns_to_the_email_step_but_keeps_secrets() {
        let mut c = SignupCeremony::new(cfg(true));
        ready_for_registration(&mut c);
        c.start_registration().unwrap();
        c.email_ticket_invalidated();
        assert_eq!(c.step(), CeremonyStep::VerifyEmail);
        assert!(c.password.is_some(), "typed password kept (spec 5.9)");
        assert!(c.master_key.is_some(), "the confirmed phrase's key kept (spec 5.9)");
        assert!(matches!(c.registration, Registration::NotStarted));
        assert!(
            matches!(c.start_registration(), Err(CeremonyError::StepNotDone { .. })),
            "and registration is blocked until the email is verified again"
        );
        c.email_verified();
        assert_eq!(c.step(), CeremonyStep::CreateAccount);
    }

    #[test]
    fn registration_failed_allows_a_fresh_exchange() {
        let mut c = SignupCeremony::new(cfg(false));
        ready_for_registration(&mut c);
        c.start_registration().unwrap();
        c.registration_failed();
        assert!(matches!(c.registration, Registration::NotStarted));
        assert!(c.start_registration().is_ok());
    }

    #[test]
    fn email_changed_withdraws_the_verification_but_keeps_secrets() {
        let mut c = SignupCeremony::new(cfg(true));
        ready_for_registration(&mut c);
        c.start_registration().unwrap();
        c.email_changed();
        assert_eq!(c.step(), CeremonyStep::VerifyEmail);
        assert!(matches!(c.registration, Registration::NotStarted));
        assert!(c.password.is_some() && c.master_key.is_some());
        assert!(matches!(
            c.start_registration(),
            Err(CeremonyError::StepNotDone {
                blocking: CeremonyStep::VerifyEmail,
                ..
            })
        ));
        c.email_verified();
        assert_eq!(c.step(), CeremonyStep::CreateAccount);
    }

    #[test]
    fn wipe_abandons_everything_and_the_ceremony_starts_over() {
        let mut c = SignupCeremony::new(cfg(true));
        ready_for_registration(&mut c);
        c.start_registration().unwrap();
        c.wipe();
        assert!(c.password.is_none(), "password gone");
        assert!(c.phrase.is_none(), "phrase gone");
        assert!(c.master_key.is_none(), "master key gone");
        assert!(c.challenge.is_empty());
        assert!(matches!(c.registration, Registration::NotStarted));
        assert_eq!(
            c.pending_steps(),
            SignupCeremony::new(cfg(true)).pending_steps(),
            "every step is pending again"
        );
        assert!(matches!(c.phrase(), Err(CeremonyError::PhraseUnavailable)));
        assert!(matches!(c.start_registration(), Err(CeremonyError::StepNotDone { .. })));
        // And the same object is usable for a fresh attempt with the same config.
        c.email_verified();
        c.set_password(GOOD_PW, GOOD_PW, None).unwrap();
        with_fixed_phrase(&mut c);
        c.acknowledge_phrase().unwrap();
        let a = answers_for(&c);
        c.confirm_phrase(&a).unwrap();
        assert_eq!(c.step(), CeremonyStep::CreateAccount);
    }

    #[test]
    fn wipe_after_completion_resets_the_done_state_too() {
        let mut c = SignupCeremony::new(cfg(false));
        c.done = true;
        c.wipe();
        assert!(!c.done);
        assert_eq!(c.step(), CeremonyStep::SetPassword);
    }

    /// The whole ceremony against a real server-side OPAQUE implementation,
    /// with the real phrase generator (two 256 MiB Argon2id runs plus one login).
    #[test]
    fn full_ceremony_registers_an_account_that_can_log_in() {
        let server_setup = opaque_protocol::create_server_setup();
        let username = b"ceremony@beebeeb.io";

        let mut c = SignupCeremony::new(cfg(true));
        c.email_verified();
        c.set_password(GOOD_PW, GOOD_PW, None).unwrap();
        c.begin_phrase().unwrap();
        let shown = c.phrase().unwrap();
        c.acknowledge_phrase().unwrap();

        // Answer from the phrase exactly as the user would copy it back.
        let words: Vec<&str> = shown.split_whitespace().collect();
        let answers: Vec<String> = c
            .challenge_positions()
            .unwrap()
            .iter()
            .map(|p| words[*p as usize - 1].to_owned())
            .collect();
        c.confirm_phrase(&answers).unwrap();
        assert_eq!(c.step(), CeremonyStep::CreateAccount);

        let start = c.start_registration().unwrap();
        let server_msg = opaque_protocol::server_registration_start(&server_setup, &start.message, username).unwrap();
        let fin = c.finish_registration(&server_msg).unwrap();
        let password_file = opaque_protocol::server_registration_finish(&fin.upload).unwrap();

        // Binding values are the ones the existing primitives produce for the phrase's key.
        let key_from_phrase = recovery::recover_from_phrase(&shown).unwrap();
        assert_eq!(fin.recovery_check, *opaque::compute_recovery_check(&key_from_phrase));
        assert_eq!(
            fin.x25519_public,
            opaque::derive_x25519_public(&opaque::derive_x25519_private(&key_from_phrase))
        );

        let handed_over = c.account_created().unwrap();
        assert_eq!(handed_over.as_bytes(), key_from_phrase.as_bytes());
        assert_eq!(c.step(), CeremonyStep::Done);
        assert!(c.pending_steps().is_empty());
        assert!(
            c.password.is_none() && c.phrase.is_none() && c.master_key.is_none(),
            "wiped"
        );
        assert!(matches!(
            c.start_registration(),
            Err(CeremonyError::InvalidState { .. })
        ));

        // The account the ceremony produced logs in with the typed password.
        let login = opaque_protocol::client_login_start(GOOD_PW.as_bytes()).unwrap();
        let server_login =
            opaque_protocol::server_login_start(&server_setup, &password_file, &login.message, username).unwrap();
        let client_finish =
            opaque_protocol::client_login_finish(&login.state, GOOD_PW.as_bytes(), &server_login.message, 1).unwrap();
        let server_key = opaque_protocol::server_login_finish(&server_login.state, &client_finish.message).unwrap();
        assert_eq!(client_finish.session_key, server_key);
    }
}
