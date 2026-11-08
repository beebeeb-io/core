//! UniFFI surface for core's account flows (desktop v2 B14). Thin: every rule lives in
//! `beebeeb_core::account_flows`. The host performs each HTTP step and feeds the reply
//! back; `confirm_token` goes straight into the `X-Confirm-Token` header.

use std::sync::{Arc, Mutex};

use beebeeb_core::account_flows::{self as af, AccountBinding, AccountFlow, HostSession};
use beebeeb_core::auth_flow::HttpResponse;
use beebeeb_core::signup_flow::SignupPolicy;
use zeroize::Zeroizing;

use crate::BreachCheckHandle;

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum AccountFlowFfiError {
    /// `code` is the stable error code (`wrong_password`, `invalid_code`, ...).
    #[error("account flow failed: {code}")]
    Failed { code: String },
}

impl From<af::AccountFlowError> for AccountFlowFfiError {
    fn from(e: af::AccountFlowError) -> Self {
        Self::Failed {
            code: e.code().to_string(),
        }
    }
}

#[derive(uniffi::Record)]
pub struct AccountFlowOutcome {
    pub kind: String,
    pub session_token: Option<String>,
    pub email: Option<String>,
    pub totp_secret: Option<String>,
    pub otpauth_uri: Option<String>,
    pub backup_codes: Vec<String>,
    pub revoked: u32,
    pub shred_after: Option<String>,
    pub cancel_until: Option<String>,
    pub link_expires_at: Option<String>,
    pub not_restored: Vec<String>,
}

#[derive(uniffi::Record)]
pub struct AccountFlowStep {
    pub done: bool,
    pub method: String,
    pub path: String,
    pub body_json: String,
    pub confirm_token: Option<String>,
    pub outcome: Option<AccountFlowOutcome>,
}

fn step(s: af::HostStep) -> AccountFlowStep {
    AccountFlowStep {
        done: s.done,
        method: s.method,
        path: s.path,
        body_json: s.body_json.to_string(),
        confirm_token: s.confirm_token.map(|t| t.to_string()),
        outcome: s.outcome.map(|o| AccountFlowOutcome {
            kind: o.kind,
            session_token: o.session_token.map(|t| t.to_string()),
            email: o.email,
            totp_secret: o.totp_secret.map(|t| t.to_string()),
            otpauth_uri: o.otpauth_uri.map(|t| t.to_string()),
            backup_codes: o.backup_codes.to_vec(),
            revoked: o.revoked,
            shred_after: o.shred_after,
            cancel_until: o.cancel_until,
            link_expires_at: o.link_expires_at,
            not_restored: o.not_restored,
        }),
    }
}

/// One account flow at a time. Drive it from ONE sequence.
#[derive(uniffi::Object)]
pub struct AccountFlowHandle {
    inner: Mutex<HostSession>,
}

impl AccountFlowHandle {
    fn begin(&self, flow: Result<AccountFlow, af::AccountFlowError>) -> Result<AccountFlowStep, AccountFlowFfiError> {
        let mut s = self.inner.lock().map_err(|_| AccountFlowFfiError::Failed {
            code: "poisoned".into(),
        })?;
        Ok(step(s.begin(flow?)?))
    }
}

fn binding(recovery_check_b64: String, x25519_public_b64: String) -> AccountBinding {
    AccountBinding {
        recovery_check_b64,
        x25519_public_b64,
    }
}

#[uniffi::export]
impl AccountFlowHandle {
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(HostSession::new()),
        })
    }

    /// `onboarding_status` / `onboarding_body` are the server's `GET /api/v1/onboarding` answer
    /// (its password policy); `breach_check` is a [`BreachCheckHandle`] made for `new_password`
    /// and answered, required when that policy declares a breach check (sign-up's gate).
    #[allow(clippy::too_many_arguments)]
    pub fn change_password(
        &self,
        current: String,
        new_password: String,
        recovery_check_b64: String,
        x25519_public_b64: String,
        onboarding_status: u16,
        onboarding_body: String,
        breach_check: Option<Arc<BreachCheckHandle>>,
    ) -> Result<AccountFlowStep, AccountFlowFfiError> {
        let current = Zeroizing::new(current);
        let new_password = Zeroizing::new(new_password);
        let policy = SignupPolicy::from_response(&HttpResponse::from_text(onboarding_status, &onboarding_body, None))
            .map_err(|_| AccountFlowFfiError::Failed {
            code: "policy_unavailable".into(),
        })?;
        let check = breach_check.as_ref().map(|h| crate::lock_tolerant(&h.check));
        self.begin(AccountFlow::change_password(
            &current,
            &new_password,
            binding(recovery_check_b64, x25519_public_b64),
            &policy,
            check.as_deref(),
        ))
    }

    pub fn change_email(
        &self,
        new_email: String,
        password: String,
        recovery_check_b64: String,
        x25519_public_b64: String,
    ) -> Result<AccountFlowStep, AccountFlowFfiError> {
        let password = Zeroizing::new(password);
        self.begin(AccountFlow::change_email(
            &new_email,
            &password,
            binding(recovery_check_b64, x25519_public_b64),
        ))
    }

    pub fn verify_email(&self, code: String) -> Result<AccountFlowStep, AccountFlowFfiError> {
        let code = Zeroizing::new(code);
        self.begin(AccountFlow::verify_email(&code))
    }

    pub fn totp_setup(
        &self,
        password: Option<String>,
        current_code: Option<String>,
    ) -> Result<AccountFlowStep, AccountFlowFfiError> {
        let password = password.map(Zeroizing::new);
        let current_code = current_code.map(Zeroizing::new);
        self.begin(AccountFlow::totp_setup(
            password.as_deref().map(String::as_str),
            current_code.as_deref().map(String::as_str),
        ))
    }

    pub fn totp_confirm(&self, code: String) -> Result<AccountFlowStep, AccountFlowFfiError> {
        let mut s = self.inner.lock().map_err(|_| AccountFlowFfiError::Failed {
            code: "poisoned".into(),
        })?;
        let code = Zeroizing::new(code);
        Ok(step(s.totp_confirm(&code)?))
    }

    pub fn totp_disable(&self, code: String) -> Result<AccountFlowStep, AccountFlowFfiError> {
        let code = Zeroizing::new(code);
        self.begin(AccountFlow::totp_disable(&code))
    }

    pub fn revoke_session(&self, session_id: String) -> Result<AccountFlowStep, AccountFlowFfiError> {
        self.begin(AccountFlow::revoke_session(&session_id))
    }

    pub fn revoke_other_sessions(&self) -> Result<AccountFlowStep, AccountFlowFfiError> {
        self.begin(Ok(AccountFlow::revoke_other_sessions()))
    }

    pub fn set_display_name(&self, name: String) -> Result<AccountFlowStep, AccountFlowFfiError> {
        self.begin(AccountFlow::set_display_name(&name))
    }

    /// Turning it off takes the password (a step-up inside); turning it on ignores it.
    pub fn set_activity_logging(
        &self,
        on: bool,
        password: Option<String>,
    ) -> Result<AccountFlowStep, AccountFlowFfiError> {
        let password = password.map(Zeroizing::new);
        self.begin(AccountFlow::set_activity_logging(
            on,
            password.as_deref().map(String::as_str),
        ))
    }

    /// New backup codes with the current authenticator code; the authenticator stays.
    pub fn regenerate_backup_codes(&self, code: String) -> Result<AccountFlowStep, AccountFlowFfiError> {
        let code = Zeroizing::new(code);
        self.begin(AccountFlow::regenerate_backup_codes(&code))
    }

    pub fn verify_password(&self, password: String) -> Result<AccountFlowStep, AccountFlowFfiError> {
        let password = Zeroizing::new(password);
        self.begin(AccountFlow::verify_password(&password))
    }

    /// Delete step 2: step-up + the second factor on a 2FA account; the server mails a link.
    pub fn delete_account(
        &self,
        password: String,
        code: Option<String>,
    ) -> Result<AccountFlowStep, AccountFlowFfiError> {
        let password = Zeroizing::new(password);
        let code = code.map(Zeroizing::new);
        self.begin(AccountFlow::delete_account(
            &password,
            code.as_deref().map(String::as_str),
        ))
    }

    /// Delete step 3: the mailed link's token (or the whole link).
    pub fn delete_confirm(&self, link_token: String) -> Result<AccountFlowStep, AccountFlowFfiError> {
        let link_token = Zeroizing::new(link_token);
        self.begin(AccountFlow::delete_confirm(&link_token))
    }

    /// Undo a scheduled deletion with the same link.
    pub fn delete_cancel(&self, link_token: String) -> Result<AccountFlowStep, AccountFlowFfiError> {
        let link_token = Zeroizing::new(link_token);
        self.begin(AccountFlow::delete_cancel(&link_token))
    }

    pub fn resume(&self, status: u16, body_text: String) -> Result<AccountFlowStep, AccountFlowFfiError> {
        let mut s = self.inner.lock().map_err(|_| AccountFlowFfiError::Failed {
            code: "poisoned".into(),
        })?;
        Ok(step(s.resume(status, &body_text)?))
    }

    pub fn abandon(&self) {
        if let Ok(mut s) = self.inner.lock() {
            s.abandon();
        }
    }
}
