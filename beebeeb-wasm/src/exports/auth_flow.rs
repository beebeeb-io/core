//! Sign-in flows for web (`beebeeb_core::auth_flow`). Thin: each class wraps one core flow and
//! converts requests and responses to plain JS objects; no rule lives here.
//!
//! A request is `{method, path, body?, needsSession, confirmToken?}`: the caller's `fetch` sends
//! `body` as JSON, adds the session for `needsSession` and `X-Confirm-Token` for `confirmToken`.
//! A response goes back as `(status, bodyText, retryAfterSecs?)`. Errors throw a `JsError` whose
//! message is the core code (`invalid_credentials`, `rate_limited:30`, …), never a server body.
use beebeeb_core::auth_flow::{self as af, AuthFlowError, HttpRequest, HttpResponse, RequestAuth};
use serde::Serialize;
use wasm_bindgen::prelude::*;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RequestJs {
    method: &'static str,
    path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    body: Option<serde_json::Value>,
    needs_session: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    confirm_token: Option<String>,
}

fn err(e: AuthFlowError) -> JsError {
    match e {
        AuthFlowError::RateLimited { retry_after_secs } => JsError::new(&format!("rate_limited:{retry_after_secs}")),
        other => JsError::new(other.code()),
    }
}

fn wrong_state() -> JsError {
    err(AuthFlowError::WrongState)
}

pub(crate) fn to_js<T: Serialize>(v: &T) -> Result<JsValue, JsError> {
    v.serialize(&serde_wasm_bindgen::Serializer::json_compatible())
        .map_err(|_| JsError::new("protocol"))
}

fn request_js(req: &HttpRequest) -> RequestJs {
    RequestJs {
        method: req.method.as_str(),
        path: req.path.clone(),
        body: req.body.clone(),
        needs_session: req.auth == RequestAuth::Session,
        confirm_token: req.confirm_token.as_ref().map(|t| t.as_str().to_owned()),
    }
}

/// A bare request (`start()`, `verifyRequest`, `approve`, `attachConfirmToken`).
pub(crate) fn out(req: HttpRequest) -> Result<JsValue, JsError> {
    to_js(&request_js(&req))
}

/// A step of `onResponse`: `{kind: "send", request}`.
fn send(req: HttpRequest) -> Result<JsValue, JsError> {
    #[derive(Serialize)]
    struct Send {
        kind: &'static str,
        request: RequestJs,
    }
    to_js(&Send {
        kind: "send",
        request: request_js(&req),
    })
}

pub(crate) fn resp(status: u16, body: &str, retry_after_secs: Option<u32>) -> HttpResponse {
    HttpResponse::from_text(status, body, retry_after_secs.map(u64::from))
}

/// `new AuthSignIn(email, password)`; `start()` then `onResponse(...)` until
/// `{kind: "signed_in", sessionToken}` or `{kind: "second_factor"}`, then `verifyRequest(code)` /
/// `onVerifyResponse(...)`.
#[wasm_bindgen(js_name = AuthSignIn)]
pub struct AuthSignIn {
    flow: Option<af::sign_in::SignIn>,
    pending: Option<af::sign_in::PendingSecondFactor>,
    first: Option<HttpRequest>,
}

#[wasm_bindgen(js_class = AuthSignIn)]
impl AuthSignIn {
    #[wasm_bindgen(constructor)]
    pub fn new(email: &str, password: &str) -> Result<AuthSignIn, JsError> {
        let (flow, first) = af::sign_in::SignIn::start(email, password.as_bytes()).map_err(err)?;
        Ok(Self {
            flow: Some(flow),
            pending: None,
            first: Some(first),
        })
    }

    pub fn start(&mut self) -> Result<JsValue, JsError> {
        out(self.first.take().ok_or_else(wrong_state)?)
    }

    #[wasm_bindgen(js_name = onResponse)]
    pub fn on_response(&mut self, status: u16, body: &str, retry_after_secs: Option<u32>) -> Result<JsValue, JsError> {
        let flow = self.flow.as_mut().ok_or_else(wrong_state)?;
        match flow.on_response(resp(status, body, retry_after_secs)).map_err(err)? {
            af::sign_in::SignInStep::Send(req) => send(req),
            af::sign_in::SignInStep::SignedIn { session_token } => {
                self.flow = None;
                to_js(&serde_json::json!({ "kind": "signed_in", "sessionToken": session_token.as_str() }))
            }
            af::sign_in::SignInStep::SecondFactor(p) => {
                self.flow = None;
                self.pending = Some(p);
                to_js(&serde_json::json!({ "kind": "second_factor" }))
            }
        }
    }

    #[wasm_bindgen(js_name = verifyRequest)]
    pub fn verify_request(&self, code: &str) -> Result<JsValue, JsError> {
        out(self
            .pending
            .as_ref()
            .ok_or_else(wrong_state)?
            .verify(code)
            .map_err(err)?)
    }

    /// The session token; throws `wrong_code` and stays ready for the next code.
    #[wasm_bindgen(js_name = onVerifyResponse)]
    pub fn on_verify_response(
        &mut self,
        status: u16,
        body: &str,
        retry_after_secs: Option<u32>,
    ) -> Result<String, JsError> {
        let pending = self.pending.as_ref().ok_or_else(wrong_state)?;
        let token = pending
            .on_verify_response(resp(status, body, retry_after_secs))
            .map_err(err)?;
        self.pending = None;
        Ok(token.as_str().to_owned())
    }
}

/// `new AuthStepUp(password, purpose?, cliCode?)`; `start()`, `onResponse(...)` until
/// `{kind: "confirmed"}`, then `attachConfirmToken(path, body)` gives the consuming request.
#[wasm_bindgen(js_name = AuthStepUp)]
pub struct AuthStepUp {
    flow: Option<af::step_up::StepUp>,
    first: Option<HttpRequest>,
    token: Option<af::step_up::ConfirmToken>,
}

#[wasm_bindgen(js_class = AuthStepUp)]
impl AuthStepUp {
    #[wasm_bindgen(constructor)]
    pub fn new(password: &str, purpose: Option<String>, cli_code: Option<String>) -> Result<AuthStepUp, JsError> {
        let purpose = match (purpose, cli_code) {
            (_, Some(code)) => af::step_up::StepUpPurpose::DeviceApproval { code },
            (Some(p), None) if !p.is_empty() => af::step_up::StepUpPurpose::Named(p),
            _ => af::step_up::StepUpPurpose::Generic,
        };
        let (flow, first) = af::step_up::StepUp::start(password.as_bytes(), purpose).map_err(err)?;
        Ok(Self {
            flow: Some(flow),
            first: Some(first),
            token: None,
        })
    }

    pub fn start(&mut self) -> Result<JsValue, JsError> {
        out(self.first.take().ok_or_else(wrong_state)?)
    }

    #[wasm_bindgen(js_name = onResponse)]
    pub fn on_response(&mut self, status: u16, body: &str, retry_after_secs: Option<u32>) -> Result<JsValue, JsError> {
        let flow = self.flow.as_mut().ok_or_else(wrong_state)?;
        match flow.on_response(resp(status, body, retry_after_secs)).map_err(err)? {
            af::step_up::StepUpStep::Send(req) => send(req),
            af::step_up::StepUpStep::Confirmed(t) => {
                self.flow = None;
                self.token = Some(t);
                to_js(&serde_json::json!({ "kind": "confirmed" }))
            }
        }
    }

    #[wasm_bindgen(js_name = attachConfirmToken)]
    pub fn attach_confirm_token(&mut self, path: String, body: JsValue) -> Result<JsValue, JsError> {
        let token = self.token.take().ok_or_else(wrong_state)?;
        let body: serde_json::Value =
            serde_wasm_bindgen::from_value(body).map_err(|_| JsError::new("invalid_input"))?;
        out(token.attach(HttpRequest {
            method: af::Method::Post,
            path,
            body: Some(body),
            auth: RequestAuth::Session,
            confirm_token: None,
        }))
    }
}

/// The requesting side of sign in with another device: `initFrame(...)` is the first socket
/// frame, `onFrame(text)` reads each server frame.
#[wasm_bindgen(js_name = AuthDeviceRequest)]
pub struct AuthDeviceRequest {
    inner: af::device::DeviceRequest,
}

#[wasm_bindgen(js_class = AuthDeviceRequest)]
impl AuthDeviceRequest {
    #[wasm_bindgen(constructor)]
    pub fn new() -> AuthDeviceRequest {
        Self {
            inner: af::device::DeviceRequest::new(),
        }
    }

    #[wasm_bindgen(js_name = initFrame)]
    pub fn init_frame(
        &self,
        device_name: Option<String>,
        client: String,
        client_version: String,
        os: String,
    ) -> String {
        self.inner.init_frame(&af::device::DeviceFacts {
            device_name,
            client,
            client_version,
            os,
        })
    }

    /// `{kind: "waiting", userCode, verificationUri, expiresIn}` or
    /// `{kind: "approved", sessionToken, masterKey: Uint8Array}`.
    #[wasm_bindgen(js_name = onFrame)]
    pub fn on_frame(&mut self, text: &str) -> Result<JsValue, JsError> {
        match self.inner.on_frame(text).map_err(err)? {
            af::device::DeviceRequestEvent::Waiting {
                user_code,
                verification_uri,
                expires_in,
            } => to_js(
                &serde_json::json!({ "kind": "waiting", "userCode": user_code, "verificationUri": verification_uri, "expiresIn": expires_in }),
            ),
            af::device::DeviceRequestEvent::Approved(c) => {
                let o = js_sys::Object::new();
                let set = |k: &str, v: &JsValue| js_sys::Reflect::set(&o, &JsValue::from_str(k), v).map(|_| ());
                set("kind", &JsValue::from_str("approved")).map_err(|_| wrong_state())?;
                set("sessionToken", &JsValue::from_str(&c.session_token)).map_err(|_| wrong_state())?;
                set("masterKey", &js_sys::Uint8Array::from(&c.master_key[..]).into()).map_err(|_| wrong_state())?;
                Ok(o.into())
            }
        }
    }
}

impl Default for AuthDeviceRequest {
    fn default() -> Self {
        Self::new()
    }
}

enum ApprovalState {
    Lookup(af::device::ApprovalLookup),
    Pending(af::device::PendingApproval),
    Running(af::device::ApproveRun),
    Denying(af::device::Denial),
    Done,
}

/// The approving side: `new AuthApproval(code)`, `start()`, `onLookupResponse(...)` (the facts),
/// `codeMatches(typed)`, `approve(typed, password, masterKey)`, then `onResponse(...)` until
/// `{kind: "approved"}`.
#[wasm_bindgen(js_name = AuthApproval)]
pub struct AuthApproval {
    state: ApprovalState,
    first: Option<HttpRequest>,
}

#[wasm_bindgen(js_class = AuthApproval)]
impl AuthApproval {
    #[wasm_bindgen(constructor)]
    pub fn new(code: &str) -> Result<AuthApproval, JsError> {
        let (lookup, first) = af::device::Approval::lookup(code).map_err(err)?;
        Ok(Self {
            state: ApprovalState::Lookup(lookup),
            first: Some(first),
        })
    }

    pub fn start(&mut self) -> Result<JsValue, JsError> {
        out(self.first.take().ok_or_else(wrong_state)?)
    }

    #[wasm_bindgen(js_name = onLookupResponse)]
    pub fn on_lookup_response(
        &mut self,
        status: u16,
        body: &str,
        retry_after_secs: Option<u32>,
    ) -> Result<JsValue, JsError> {
        let ApprovalState::Lookup(lookup) = std::mem::replace(&mut self.state, ApprovalState::Done) else {
            return Err(wrong_state());
        };
        let pending = lookup.on_response(resp(status, body, retry_after_secs)).map_err(err)?;
        let f = pending.facts().clone();
        self.state = ApprovalState::Pending(pending);
        to_js(&serde_json::json!({
            "requestedAt": f.requested_at, "expiresAt": f.expires_at, "ip": f.ip, "country": f.country,
            "deviceName": f.device_name, "client": f.client, "os": f.os,
        }))
    }

    #[wasm_bindgen(js_name = codeMatches)]
    pub fn code_matches(&self, typed: &str) -> bool {
        matches!(&self.state, ApprovalState::Pending(p) if p.code_matches(typed))
    }

    pub fn approve(&mut self, typed_code: &str, password: &str, master_key: &[u8]) -> Result<JsValue, JsError> {
        let key: &[u8; 32] = master_key.try_into().map_err(|_| JsError::new("invalid_input"))?;
        let ApprovalState::Pending(pending) = std::mem::replace(&mut self.state, ApprovalState::Done) else {
            return Err(wrong_state());
        };
        let (run, req) = pending.approve(typed_code, password.as_bytes(), key).map_err(err)?;
        self.state = ApprovalState::Running(run);
        out(req)
    }

    /// Deny the request shown for review (DW-A09); send the request, then `onDenyResponse`.
    pub fn deny(&mut self) -> Result<JsValue, JsError> {
        let ApprovalState::Pending(pending) = std::mem::replace(&mut self.state, ApprovalState::Done) else {
            return Err(wrong_state());
        };
        let (denial, req) = pending.deny();
        self.state = ApprovalState::Denying(denial);
        out(req)
    }

    #[wasm_bindgen(js_name = onDenyResponse)]
    pub fn on_deny_response(&mut self, status: u16, body: &str, retry_after_secs: Option<u32>) -> Result<(), JsError> {
        let ApprovalState::Denying(denial) = std::mem::replace(&mut self.state, ApprovalState::Done) else {
            return Err(wrong_state());
        };
        denial.on_response(resp(status, body, retry_after_secs)).map_err(err)
    }

    #[wasm_bindgen(js_name = onResponse)]
    pub fn on_response(&mut self, status: u16, body: &str, retry_after_secs: Option<u32>) -> Result<JsValue, JsError> {
        let ApprovalState::Running(run) = &mut self.state else {
            return Err(wrong_state());
        };
        match run.on_response(resp(status, body, retry_after_secs)).map_err(err)? {
            af::device::ApproveStep::Send(req) => send(req),
            af::device::ApproveStep::Approved => {
                self.state = ApprovalState::Done;
                to_js(&serde_json::json!({ "kind": "approved" }))
            }
        }
    }
}
