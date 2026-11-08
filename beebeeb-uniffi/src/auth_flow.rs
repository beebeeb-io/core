//! Sign-in flows for mobile (`beebeeb_core::auth_flow`). Thin: each object wraps one core flow
//! and converts requests and responses; no rule lives here. The app's transport sends each
//! [`AuthHttpRequest`] (adding the session for `needs_session`, and `X-Confirm-Token` when
//! `confirm_token` is set) and passes the answer back as an [`AuthHttpResponse`].
use std::sync::{Arc, Mutex};

use beebeeb_core::auth_flow::{self as af, AuthFlowError, HttpRequest, HttpResponse, RequestAuth};

#[derive(uniffi::Record)]
pub struct AuthHttpRequest {
    pub method: String,
    pub path: String,
    pub body_json: Option<String>,
    pub needs_session: bool,
    /// Single-use step-up token for the `X-Confirm-Token` header; only on a claim request.
    pub confirm_token: Option<String>,
}

#[derive(uniffi::Record)]
pub struct AuthHttpResponse {
    pub status: u16,
    pub body_json: String,
    pub retry_after_secs: Option<u64>,
}

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum AuthFlowFfiError {
    /// `code` is `AuthFlowError::code()` (`invalid_credentials`, `rate_limited`, …).
    #[error("{code}")]
    Flow {
        code: String,
        retry_after_secs: Option<u64>,
    },
}

impl From<AuthFlowError> for AuthFlowFfiError {
    fn from(e: AuthFlowError) -> Self {
        let retry_after_secs = match e {
            AuthFlowError::RateLimited { retry_after_secs } => Some(retry_after_secs),
            _ => None,
        };
        Self::Flow {
            code: e.code().to_owned(),
            retry_after_secs,
        }
    }
}

fn wrong_state() -> AuthFlowFfiError {
    AuthFlowError::WrongState.into()
}

pub(crate) fn out(req: HttpRequest) -> AuthHttpRequest {
    AuthHttpRequest {
        method: req.method.as_str().to_owned(),
        path: req.path.clone(),
        body_json: req.body.as_ref().map(|b| b.to_string()),
        needs_session: req.auth == RequestAuth::Session,
        confirm_token: req.confirm_token.as_ref().map(|t| t.as_str().to_owned()),
    }
}

pub(crate) fn into(resp: AuthHttpResponse) -> HttpResponse {
    HttpResponse::from_text(resp.status, &resp.body_json, resp.retry_after_secs)
}

// ── Password sign-in ─────────────────────────────────────────────────────────

#[derive(uniffi::Enum)]
pub enum SignInStepFfi {
    Send {
        request: AuthHttpRequest,
    },
    SignedIn {
        session_token: String,
    },
    /// Two-factor is on: call `verify_request(code)`.
    SecondFactor,
}

#[derive(uniffi::Object)]
pub struct SignInFlow {
    flow: Mutex<Option<af::sign_in::SignIn>>,
    pending: Mutex<Option<af::sign_in::PendingSecondFactor>>,
    first: Mutex<Option<HttpRequest>>,
}

#[uniffi::export]
impl SignInFlow {
    #[uniffi::constructor]
    pub fn new(email: String, password: String) -> Result<Arc<Self>, AuthFlowFfiError> {
        let password = zeroize::Zeroizing::new(password);
        let (flow, first) = af::sign_in::SignIn::start(&email, password.as_bytes())?;
        Ok(Arc::new(Self {
            flow: Mutex::new(Some(flow)),
            pending: Mutex::new(None),
            first: Mutex::new(Some(first)),
        }))
    }

    /// The login-start request (once).
    pub fn start(&self) -> Result<AuthHttpRequest, AuthFlowFfiError> {
        self.first
            .lock()
            .map_err(|_| wrong_state())?
            .take()
            .map(out)
            .ok_or_else(wrong_state)
    }

    pub fn on_response(&self, response: AuthHttpResponse) -> Result<SignInStepFfi, AuthFlowFfiError> {
        let mut guard = self.flow.lock().map_err(|_| wrong_state())?;
        let flow = guard.as_mut().ok_or_else(wrong_state)?;
        Ok(match flow.on_response(into(response))? {
            af::sign_in::SignInStep::Send(req) => SignInStepFfi::Send { request: out(req) },
            af::sign_in::SignInStep::SignedIn { session_token } => {
                *guard = None;
                SignInStepFfi::SignedIn {
                    session_token: session_token.as_str().to_owned(),
                }
            }
            af::sign_in::SignInStep::SecondFactor(p) => {
                *guard = None;
                *self.pending.lock().map_err(|_| wrong_state())? = Some(p);
                SignInStepFfi::SecondFactor
            }
        })
    }

    /// The verify request for a 6-digit authenticator or 8-digit backup code.
    pub fn verify_request(&self, code: String) -> Result<AuthHttpRequest, AuthFlowFfiError> {
        let guard = self.pending.lock().map_err(|_| wrong_state())?;
        Ok(out(guard.as_ref().ok_or_else(wrong_state)?.verify(&code)?))
    }

    /// The session token, or `wrong_code` (the flow stays ready for the next code).
    pub fn on_verify_response(&self, response: AuthHttpResponse) -> Result<String, AuthFlowFfiError> {
        let mut guard = self.pending.lock().map_err(|_| wrong_state())?;
        let token = guard
            .as_ref()
            .ok_or_else(wrong_state)?
            .on_verify_response(into(response))?;
        *guard = None;
        Ok(token.as_str().to_owned())
    }
}

// ── Step-up ──────────────────────────────────────────────────────────────────

#[derive(uniffi::Enum)]
pub enum StepUpStepFfi {
    Send {
        request: AuthHttpRequest,
    },
    /// The token is held inside; `attach_confirm_token` puts it on the consuming request.
    Confirmed,
}

#[derive(uniffi::Object)]
pub struct StepUpFlow {
    flow: Mutex<Option<af::step_up::StepUp>>,
    first: Mutex<Option<HttpRequest>>,
    token: Mutex<Option<af::step_up::ConfirmToken>>,
}

#[uniffi::export]
impl StepUpFlow {
    /// `purpose` empty: the generic grant; `cli_code` set: a device approval for that code.
    #[uniffi::constructor]
    pub fn new(
        password: String,
        purpose: Option<String>,
        cli_code: Option<String>,
    ) -> Result<Arc<Self>, AuthFlowFfiError> {
        let password = zeroize::Zeroizing::new(password);
        let purpose = match (purpose, cli_code) {
            (_, Some(code)) => af::step_up::StepUpPurpose::DeviceApproval { code },
            (Some(p), None) if !p.is_empty() => af::step_up::StepUpPurpose::Named(p),
            _ => af::step_up::StepUpPurpose::Generic,
        };
        let (flow, first) = af::step_up::StepUp::start(password.as_bytes(), purpose)?;
        Ok(Arc::new(Self {
            flow: Mutex::new(Some(flow)),
            first: Mutex::new(Some(first)),
            token: Mutex::new(None),
        }))
    }

    pub fn start(&self) -> Result<AuthHttpRequest, AuthFlowFfiError> {
        self.first
            .lock()
            .map_err(|_| wrong_state())?
            .take()
            .map(out)
            .ok_or_else(wrong_state)
    }

    pub fn on_response(&self, response: AuthHttpResponse) -> Result<StepUpStepFfi, AuthFlowFfiError> {
        let mut guard = self.flow.lock().map_err(|_| wrong_state())?;
        let flow = guard.as_mut().ok_or_else(wrong_state)?;
        Ok(match flow.on_response(into(response))? {
            af::step_up::StepUpStep::Send(req) => StepUpStepFfi::Send { request: out(req) },
            af::step_up::StepUpStep::Confirmed(t) => {
                *guard = None;
                *self.token.lock().map_err(|_| wrong_state())? = Some(t);
                StepUpStepFfi::Confirmed
            }
        })
    }

    /// Spend the token on the consuming request (POST `path` with `body_json`, with the session).
    pub fn attach_confirm_token(&self, path: String, body_json: String) -> Result<AuthHttpRequest, AuthFlowFfiError> {
        let token = self
            .token
            .lock()
            .map_err(|_| wrong_state())?
            .take()
            .ok_or_else(wrong_state)?;
        let body = serde_json::from_str(&body_json)
            .map_err(|_| AuthFlowFfiError::from(AuthFlowError::InvalidInput("body")))?;
        let req = HttpRequest {
            method: af::Method::Post,
            path,
            body: Some(body),
            auth: RequestAuth::Session,
            confirm_token: None,
        };
        Ok(out(token.attach(req)))
    }
}

// ── Sign in with another device ──────────────────────────────────────────────

#[derive(uniffi::Enum)]
pub enum DeviceRequestEventFfi {
    Waiting {
        user_code: String,
        verification_uri: String,
        expires_in: u64,
    },
    /// The keys arrived; the app stores both in its secure store at once.
    Approved { session_token: String, master_key: Vec<u8> },
}

#[derive(uniffi::Object)]
pub struct DeviceRequestFlow {
    inner: Mutex<af::device::DeviceRequest>,
}

#[uniffi::export]
impl DeviceRequestFlow {
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(af::device::DeviceRequest::new()),
        })
    }

    pub fn init_frame(
        &self,
        device_name: Option<String>,
        client: String,
        client_version: String,
        os: String,
    ) -> String {
        let facts = af::device::DeviceFacts {
            device_name,
            client,
            client_version,
            os,
        };
        self.inner.lock().map(|r| r.init_frame(&facts)).unwrap_or_default()
    }

    pub fn on_frame(&self, text: String) -> Result<DeviceRequestEventFfi, AuthFlowFfiError> {
        let mut guard = self.inner.lock().map_err(|_| wrong_state())?;
        Ok(match guard.on_frame(&text)? {
            af::device::DeviceRequestEvent::Waiting {
                user_code,
                verification_uri,
                expires_in,
            } => DeviceRequestEventFfi::Waiting {
                user_code,
                verification_uri,
                expires_in,
            },
            af::device::DeviceRequestEvent::Approved(c) => DeviceRequestEventFfi::Approved {
                session_token: c.session_token.clone(),
                master_key: c.master_key.to_vec(),
            },
        })
    }
}

#[derive(uniffi::Record)]
pub struct RequesterFactsFfi {
    pub requested_at: String,
    pub expires_at: String,
    pub ip: String,
    pub country: Option<String>,
    pub device_name: Option<String>,
    pub client: Option<String>,
    pub os: Option<String>,
}

#[derive(uniffi::Enum)]
pub enum ApproveStepFfi {
    Send { request: AuthHttpRequest },
    Approved,
}

enum ApprovalState {
    Lookup(af::device::ApprovalLookup),
    Pending(af::device::PendingApproval),
    Running(af::device::ApproveRun),
    Done,
}

#[derive(uniffi::Object)]
pub struct ApprovalFlow {
    state: Mutex<ApprovalState>,
    first: Mutex<Option<HttpRequest>>,
}

#[uniffi::export]
impl ApprovalFlow {
    /// Look up a waiting request by the typed code (`request_not_found` for a malformed one).
    #[uniffi::constructor]
    pub fn new(code: String) -> Result<Arc<Self>, AuthFlowFfiError> {
        let (lookup, first) = af::device::Approval::lookup(&code)?;
        Ok(Arc::new(Self {
            state: Mutex::new(ApprovalState::Lookup(lookup)),
            first: Mutex::new(Some(first)),
        }))
    }

    pub fn start(&self) -> Result<AuthHttpRequest, AuthFlowFfiError> {
        self.first
            .lock()
            .map_err(|_| wrong_state())?
            .take()
            .map(out)
            .ok_or_else(wrong_state)
    }

    pub fn on_lookup_response(&self, response: AuthHttpResponse) -> Result<RequesterFactsFfi, AuthFlowFfiError> {
        let mut guard = self.state.lock().map_err(|_| wrong_state())?;
        let ApprovalState::Lookup(lookup) = std::mem::replace(&mut *guard, ApprovalState::Done) else {
            return Err(wrong_state());
        };
        let pending = lookup.on_response(into(response))?;
        let f = pending.facts().clone();
        *guard = ApprovalState::Pending(pending);
        Ok(RequesterFactsFfi {
            requested_at: f.requested_at,
            expires_at: f.expires_at,
            ip: f.ip,
            country: f.country,
            device_name: f.device_name,
            client: f.client,
            os: f.os,
        })
    }

    pub fn code_matches(&self, typed: String) -> bool {
        matches!(&*self.state.lock().unwrap_or_else(|e| e.into_inner()), ApprovalState::Pending(p) if p.code_matches(&typed))
    }

    /// Approve after the app's own biometric prompt: step-up, claim, relay.
    pub fn approve(
        &self,
        typed_code: String,
        password: String,
        master_key: Vec<u8>,
    ) -> Result<AuthHttpRequest, AuthFlowFfiError> {
        let password = zeroize::Zeroizing::new(password);
        let master_key = zeroize::Zeroizing::new(master_key);
        let key: &[u8; 32] = master_key
            .as_slice()
            .try_into()
            .map_err(|_| AuthFlowFfiError::from(AuthFlowError::InvalidInput("master key")))?;
        let mut guard = self.state.lock().map_err(|_| wrong_state())?;
        let ApprovalState::Pending(pending) = std::mem::replace(&mut *guard, ApprovalState::Done) else {
            return Err(wrong_state());
        };
        let (run, req) = pending.approve(&typed_code, password.as_bytes(), key)?;
        *guard = ApprovalState::Running(run);
        Ok(out(req))
    }

    pub fn on_response(&self, response: AuthHttpResponse) -> Result<ApproveStepFfi, AuthFlowFfiError> {
        let mut guard = self.state.lock().map_err(|_| wrong_state())?;
        let ApprovalState::Running(run) = &mut *guard else {
            return Err(wrong_state());
        };
        Ok(match run.on_response(into(response))? {
            af::device::ApproveStep::Send(req) => ApproveStepFfi::Send { request: out(req) },
            af::device::ApproveStep::Approved => {
                *guard = ApprovalState::Done;
                ApproveStepFfi::Approved
            }
        })
    }
}
