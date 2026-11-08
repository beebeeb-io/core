//! UniFFI surface for core's account flows (desktop v2 B14). Thin: every rule lives in
//! `beebeeb_core::account_flows`. The host performs each HTTP step and feeds the reply
//! back; `confirm_token` goes straight into the `X-Confirm-Token` header.

use std::sync::{Arc, Mutex};

use beebeeb_core::account_flows::{self as af, AccountBinding, AccountFlow, HostSession};

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
        body_json: s.body_json,
        confirm_token: s.confirm_token,
        outcome: s.outcome.map(|o| AccountFlowOutcome {
            kind: o.kind,
            session_token: o.session_token,
            email: o.email,
            totp_secret: o.totp_secret,
            otpauth_uri: o.otpauth_uri,
            backup_codes: o.backup_codes,
            revoked: o.revoked,
            shred_after: o.shred_after,
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

    pub fn change_password(
        &self,
        current: String,
        new_password: String,
        recovery_check_b64: String,
        x25519_public_b64: String,
    ) -> Result<AccountFlowStep, AccountFlowFfiError> {
        self.begin(AccountFlow::change_password(
            &current,
            &new_password,
            binding(recovery_check_b64, x25519_public_b64),
        ))
    }

    pub fn change_email(
        &self,
        new_email: String,
        password: String,
        recovery_check_b64: String,
        x25519_public_b64: String,
    ) -> Result<AccountFlowStep, AccountFlowFfiError> {
        self.begin(AccountFlow::change_email(
            &new_email,
            &password,
            binding(recovery_check_b64, x25519_public_b64),
        ))
    }

    pub fn verify_email(&self, code: String) -> Result<AccountFlowStep, AccountFlowFfiError> {
        self.begin(AccountFlow::verify_email(&code))
    }

    pub fn totp_setup(
        &self,
        password: Option<String>,
        current_code: Option<String>,
    ) -> Result<AccountFlowStep, AccountFlowFfiError> {
        self.begin(AccountFlow::totp_setup(password.as_deref(), current_code.as_deref()))
    }

    pub fn totp_confirm(&self, code: String) -> Result<AccountFlowStep, AccountFlowFfiError> {
        let mut s = self.inner.lock().map_err(|_| AccountFlowFfiError::Failed {
            code: "poisoned".into(),
        })?;
        Ok(step(s.totp_confirm(&code)?))
    }

    pub fn totp_disable(&self, code: String) -> Result<AccountFlowStep, AccountFlowFfiError> {
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

    pub fn set_activity_logging(&self, on: bool) -> Result<AccountFlowStep, AccountFlowFfiError> {
        self.begin(Ok(AccountFlow::set_activity_logging(on)))
    }

    pub fn verify_password(&self, password: String) -> Result<AccountFlowStep, AccountFlowFfiError> {
        self.begin(AccountFlow::verify_password(&password))
    }

    pub fn delete_account(&self, password: String) -> Result<AccountFlowStep, AccountFlowFfiError> {
        self.begin(AccountFlow::delete_account(&password))
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
