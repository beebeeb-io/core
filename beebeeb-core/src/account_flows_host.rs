//! The account flows' host adapter for the bindings (UniFFI, WASM): a step in plain strings.

use super::{AccountFlow, AccountFlowError, AccountOutcome, ApiResponse, Step, TotpEnrollment};

/// A step in plain strings, for UniFFI and WASM hosts that perform the HTTP call.
/// `confirm_token` must go straight into the `X-Confirm-Token` header and nowhere else.
#[derive(serde::Serialize)]
pub struct HostStep {
    pub done: bool,
    pub method: String,
    pub path: String,
    pub body_json: String,
    pub confirm_token: Option<String>,
    pub outcome: Option<HostOutcome>,
}

/// A finished flow, flattened. `kind` is one of `done`, `password_changed`,
/// `email_changed`, `totp_enrollment`, `backup_codes`, `revoked`, `deletion_requested`,
/// `deletion_scheduled`, `deletion_cancelled`.
/// For `totp_enrollment` the backup codes stay in the [`HostSession`] until
/// [`HostSession::totp_confirm`] succeeds.
#[derive(serde::Serialize, Default)]
pub struct HostOutcome {
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

/// One flow at a time for a binding handle, plus the pending TOTP enrollment.
#[derive(Default)]
pub struct HostSession {
    flow: Option<AccountFlow>,
    enrollment: Option<TotpEnrollment>,
}

impl HostSession {
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace the current flow (a pending enrollment survives) and return its first step.
    pub fn begin(&mut self, mut flow: AccountFlow) -> Result<HostStep, AccountFlowError> {
        let step = flow.start();
        self.flow = Some(flow);
        self.convert(step)
    }

    /// Feed the reply to the last step.
    pub fn resume(&mut self, status: u16, body_text: &str) -> Result<HostStep, AccountFlowError> {
        let flow = self.flow.as_mut().ok_or(AccountFlowError::OutOfOrder)?;
        let step = flow.resume(ApiResponse::from_text(status, body_text));
        self.convert(step)
    }

    /// Confirm the pending TOTP enrollment with the first code.
    pub fn totp_confirm(&mut self, code: &str) -> Result<HostStep, AccountFlowError> {
        let enrollment = self.enrollment.take().ok_or(AccountFlowError::OutOfOrder)?;
        self.begin(AccountFlow::totp_confirm(enrollment, code)?)
    }

    /// Drop the flow and any pending enrollment (back, cancel, error exits).
    pub fn abandon(&mut self) {
        self.flow = None;
        self.enrollment = None;
    }

    fn convert(&mut self, step: Result<Step, AccountFlowError>) -> Result<HostStep, AccountFlowError> {
        let step = match step {
            Ok(s) => s,
            Err(e) => {
                self.flow = None;
                return Err(e);
            }
        };
        Ok(match step {
            Step::Send(req) => HostStep {
                done: false,
                method: req.method.as_str().to_string(),
                path: req.path.clone(),
                body_json: req.body_json(),
                confirm_token: req.confirm_token().map(str::to_string),
                outcome: None,
            },
            Step::Done(outcome) => {
                self.flow = None;
                let mut o = HostOutcome::default();
                match outcome {
                    AccountOutcome::Done => o.kind = "done".into(),
                    AccountOutcome::PasswordChanged { session_token } => {
                        o.kind = "password_changed".into();
                        o.session_token = Some(session_token.to_string());
                    }
                    AccountOutcome::EmailChanged { email } => {
                        o.kind = "email_changed".into();
                        o.email = Some(email);
                    }
                    AccountOutcome::TotpEnrollment(e) => {
                        o.kind = "totp_enrollment".into();
                        o.totp_secret = Some(e.secret.to_string());
                        o.otpauth_uri = Some(e.otpauth_uri.to_string());
                        self.enrollment = Some(e);
                    }
                    AccountOutcome::BackupCodes(codes) => {
                        o.kind = "backup_codes".into();
                        o.backup_codes = codes.to_vec();
                    }
                    AccountOutcome::Revoked { count } => {
                        o.kind = "revoked".into();
                        o.revoked = count;
                    }
                    AccountOutcome::DeletionRequested { link_expires_at } => {
                        o.kind = "deletion_requested".into();
                        o.link_expires_at = Some(link_expires_at);
                    }
                    AccountOutcome::DeletionScheduled {
                        shred_after,
                        cancel_until,
                    } => {
                        o.kind = "deletion_scheduled".into();
                        o.shred_after = Some(shred_after);
                        o.cancel_until = cancel_until;
                    }
                    AccountOutcome::DeletionCancelled { not_restored } => {
                        o.kind = "deletion_cancelled".into();
                        o.not_restored = not_restored;
                    }
                }
                HostStep {
                    done: true,
                    method: String::new(),
                    path: String::new(),
                    body_json: String::new(),
                    confirm_token: None,
                    outcome: Some(o),
                }
            }
        })
    }
}
