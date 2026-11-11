//! The OPAQUE step-up: re-prove the password of the signed-in account and mint one single-use
//! `X-Confirm-Token`.
//!
//! ```text
//! StepUp::start(password, purpose) ──► POST /api/v1/auth/confirm-opaque-start  {client_message}
//!   on_response ◄── {server_message, server_state, ksf_version}
//!               ──► POST /api/v1/auth/confirm-opaque-finish {client_message, server_state, purpose?, cli_code?}
//!   on_response ◄── {confirmation_token, expires_at}  → StepUpStep::Confirmed(ConfirmToken)
//! ```
//!
//! Both legs carry the signed-in session ([`RequestAuth::Session`]). A 409 with
//! `opaque_unavailable` is [`AuthFlowError::OpaqueUnavailable`]: there is no plaintext-password
//! fallback (`/auth/confirm` is never called from here).
//!
//! The minted [`ConfirmToken`] has no accessor that returns the string: it can only be put on a
//! request ([`ConfirmToken::attach`]), so the flow that asked for it spends it and drops it.
use base64::Engine;
use serde_json::json;
use zeroize::Zeroizing;

use super::{AuthFlowError, HttpRequest, HttpResponse, RequestAuth, b64, b64_decode, normalize_device_code};
use crate::opaque_protocol;

pub const CONFIRM_START_PATH: &str = "/api/v1/auth/confirm-opaque-start";
pub const CONFIRM_FINISH_PATH: &str = "/api/v1/auth/confirm-opaque-finish";
/// The step-up purpose the server requires before a device-approval claim.
pub const PURPOSE_CLI_DEVICE_APPROVAL: &str = "cli_device_approval";

/// What the token is minted for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StepUpPurpose {
    /// The server's generic destructive-action grant (no purpose field sent).
    Generic,
    /// A named purpose sent as `purpose`. Today the server accepts only `password_step_up` here
    /// (the same grant as [`StepUpPurpose::Generic`]) and refuses any other name; device approval
    /// is [`StepUpPurpose::DeviceApproval`].
    Named(String),
    /// A device approval, bound to this code (purpose `cli_device_approval`).
    DeviceApproval { code: String },
}

impl StepUpPurpose {
    /// The purpose from a binding's `(purpose, cli_code)` pair: neither is the generic grant, a
    /// `cli_code` alone (or with purpose `cli_device_approval`) a device approval, a purpose alone
    /// a named one. A `cli_code` with any other purpose is refused, never silently replaced, and
    /// so is `cli_device_approval` without a code. An empty purpose counts as none.
    pub fn from_parts(purpose: Option<String>, cli_code: Option<String>) -> Result<Self, AuthFlowError> {
        match (purpose.filter(|p| !p.is_empty()), cli_code) {
            (None, None) => Ok(Self::Generic),
            (None, Some(code)) => Ok(Self::DeviceApproval { code }),
            (Some(p), Some(code)) if p == PURPOSE_CLI_DEVICE_APPROVAL => Ok(Self::DeviceApproval { code }),
            (Some(_), Some(_)) => Err(AuthFlowError::InvalidInput(
                "cli_code is only valid with purpose cli_device_approval",
            )),
            (Some(p), None) if p == PURPOSE_CLI_DEVICE_APPROVAL => Err(AuthFlowError::InvalidInput(
                "purpose cli_device_approval needs a cli_code",
            )),
            (Some(p), None) => Ok(Self::Named(p)),
        }
    }
}

/// A single-use confirmation token. Wiped on drop; never printed.
pub struct ConfirmToken(Zeroizing<String>);

impl ConfirmToken {
    /// Put the token on `request` (the `X-Confirm-Token` header), consuming it.
    pub fn attach(self, mut request: HttpRequest) -> HttpRequest {
        request.confirm_token = Some(self.0);
        request
    }

    /// The header value, for a crate flow with its own request type (`account_flows`). Crate-only:
    /// no host ever receives the string; the caller puts it on exactly one request.
    pub(crate) fn into_header_value(self) -> Zeroizing<String> {
        self.0
    }

    #[cfg(test)]
    pub(crate) fn for_test(value: &str) -> Self {
        Self(Zeroizing::new(value.to_owned()))
    }
}

impl std::fmt::Debug for ConfirmToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ConfirmToken(<redacted>)")
    }
}

enum Stage {
    AwaitStart { client_state: Zeroizing<Vec<u8>> },
    AwaitFinish,
    Done,
}

pub struct StepUp {
    password: Zeroizing<Vec<u8>>,
    purpose: StepUpPurpose,
    stage: Stage,
}

pub enum StepUpStep {
    Send(HttpRequest),
    Confirmed(ConfirmToken),
}

impl StepUp {
    pub fn start(password: &[u8], purpose: StepUpPurpose) -> Result<(Self, HttpRequest), AuthFlowError> {
        if password.is_empty() {
            return Err(AuthFlowError::InvalidInput("password is required"));
        }
        if let StepUpPurpose::DeviceApproval { code } = &purpose
            && normalize_device_code(code).is_none()
        {
            return Err(AuthFlowError::InvalidInput("device code must be XXXX-XXXX"));
        }
        let start =
            opaque_protocol::client_login_start(password).map_err(|_| AuthFlowError::Protocol("opaque start"))?;
        let request = HttpRequest::post(
            CONFIRM_START_PATH,
            json!({ "client_message": b64().encode(&start.message) }),
            RequestAuth::Session,
        );
        Ok((
            Self {
                password: Zeroizing::new(password.to_vec()),
                purpose,
                stage: Stage::AwaitStart {
                    client_state: Zeroizing::new(start.state),
                },
            },
            request,
        ))
    }

    pub fn on_response(&mut self, resp: HttpResponse) -> Result<StepUpStep, AuthFlowError> {
        match std::mem::replace(&mut self.stage, Stage::Done) {
            Stage::AwaitStart { client_state } => {
                if resp.status == 409
                    && resp
                        .body
                        .get("opaque_unavailable")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false)
                {
                    return Err(AuthFlowError::OpaqueUnavailable);
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
                self.password = Zeroizing::new(Vec::new());
                drop(Zeroizing::new(finish.session_key));
                drop(Zeroizing::new(finish.export_key));
                let mut body = json!({
                    "client_message": b64().encode(&finish.message),
                    "server_state": server_state,
                });
                match &self.purpose {
                    StepUpPurpose::Generic => {}
                    StepUpPurpose::Named(p) => body["purpose"] = json!(p),
                    StepUpPurpose::DeviceApproval { code } => {
                        body["purpose"] = json!(PURPOSE_CLI_DEVICE_APPROVAL);
                        body["cli_code"] = json!(normalize_device_code(code));
                    }
                }
                self.stage = Stage::AwaitFinish;
                Ok(StepUpStep::Send(HttpRequest::post(
                    CONFIRM_FINISH_PATH,
                    body,
                    RequestAuth::Session,
                )))
            }
            Stage::AwaitFinish => {
                if !resp.ok() {
                    return Err(AuthFlowError::from_status(&resp));
                }
                let token = Zeroizing::new(resp.str_field("confirmation_token")?.to_owned());
                Ok(StepUpStep::Confirmed(ConfirmToken(token)))
            }
            Stage::Done => Err(AuthFlowError::WrongState),
        }
    }
}
