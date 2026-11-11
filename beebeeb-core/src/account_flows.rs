//! Account flows (desktop v2 B14): password change, email change, TOTP set-up /
//! confirm / disable, session revoke, display name, activity logging and account
//! deletion, as ONE implementation for desktop (Rust), mobile (UniFFI) and web (WASM).
//!
//! # Shape: sans-IO
//!
//! Core has no HTTP client, so every flow is a small state machine. The host calls
//! [`AccountFlow::start`], performs the [`ApiRequest`] it gets back with its own HTTP
//! stack (adding its session credential), and feeds the reply to
//! [`AccountFlow::resume`] until it receives [`Step::Done`]. The same machine runs
//! under tokio (desktop), Swift/Kotlin (UniFFI) and `fetch` (WASM).
//!
//! # Secrets go one way
//!
//! - Passwords enter the flow and never leave it. OPAQUE runs here, via
//!   [`crate::opaque_protocol`], with `ksf_version` taken from the server. There is no
//!   plaintext-password path: a `409 { opaque_unavailable }` is an error, never a fallback.
//! - Each destructive or security action does its own step-up
//!   (`/auth/confirm-opaque-{start,finish}`) inside the flow. The confirmation token is
//!   held in a [`Zeroizing`] buffer, attached to exactly the next request, and dropped.
//!   It is never part of an outcome. Password change does two step-ups, one per leg,
//!   because the server consumes one token per gated request.
//! - The only secret an outcome carries is the new `session_token` after a password
//!   change ([`AccountOutcome::PasswordChanged`]); the host stores it in its credential
//!   store and must never hand it to a UI layer. The TOTP secret, its `otpauth` URI and
//!   the backup codes are shown to the person by design (the set-up screens), each
//!   exactly once.
//!
//! # Step-up inside each destructive flow
//!
//! | flow | step-up | server wire |
//! |---|---|---|
//! | change password | 2 (one per leg) | `POST /auth/change-password-{start,finish}` |
//! | change email | 1 | `POST /me/email/{start,finish}` |
//! | TOTP set-up when already on | 1 (or the current code) | `POST /auth/2fa/setup` |
//! | TOTP disable | the current code | `POST /auth/2fa/disable` |
//! | regenerate backup codes | the current code | `POST /auth/2fa/backup-codes` |
//! | activity logging off | 1 | `PUT /me/tracking` |
//! | delete account (request) | 1 (+ code on a 2FA account) | `POST /auth/account/delete-request` |
//! | delete confirm / cancel | the mailed link token | `POST /auth/account/delete-{confirm,cancel}` |

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::auth_flow::step_up::{self as auth_step_up, ConfirmToken, StepUpPurpose, StepUpStep};
use crate::auth_flow::{self, AuthFlowError};
use crate::kdf::MasterKey;
use crate::onboarding::BreachCheck;
use crate::opaque::{compute_recovery_check, derive_x25519_private, derive_x25519_public};
use crate::opaque_protocol;
use crate::signup_flow::SignupPolicy;

/// Display name bounds (DW-A64 rules).
pub const MAX_NAME_CHARS: usize = 64;

pub const PATH_CONFIRM_START: &str = auth_step_up::CONFIRM_START_PATH;
pub const PATH_CONFIRM_FINISH: &str = auth_step_up::CONFIRM_FINISH_PATH;
pub const PATH_CHANGE_PASSWORD_START: &str = "/api/v1/auth/change-password-start";
pub const PATH_CHANGE_PASSWORD_FINISH: &str = "/api/v1/auth/change-password-finish";
pub const PATH_EMAIL_START: &str = "/api/v1/me/email/start";
pub const PATH_EMAIL_FINISH: &str = "/api/v1/me/email/finish";
pub const PATH_VERIFY_EMAIL: &str = "/api/v1/auth/verify-email";
pub const PATH_TOTP_SETUP: &str = "/api/v1/auth/2fa/setup";
pub const PATH_TOTP_ENABLE: &str = "/api/v1/auth/2fa/enable";
pub const PATH_TOTP_DISABLE: &str = "/api/v1/auth/2fa/disable";
pub const PATH_BACKUP_CODES: &str = "/api/v1/auth/2fa/backup-codes";
pub const PATH_PROFILE: &str = "/api/v1/me/profile";
pub const PATH_TRACKING: &str = "/api/v1/me/tracking";
pub const PATH_SESSIONS: &str = "/api/v1/account/sessions";
pub const PATH_REVOKE_OTHERS: &str = "/api/v1/account/sessions/revoke-all-others";
pub const PATH_DELETE_REQUEST: &str = "/api/v1/auth/account/delete-request";
pub const PATH_DELETE_CONFIRM: &str = "/api/v1/auth/account/delete-confirm";
pub const PATH_DELETE_CANCEL: &str = "/api/v1/auth/account/delete-cancel";
/// Longest delete-link token accepted (the server mints a short random token).
const MAX_LINK_TOKEN_CHARS: usize = 256;

/// HTTP method of an [`ApiRequest`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Get,
    Post,
    Put,
    Delete,
    Patch,
}

impl Method {
    pub fn as_str(self) -> &'static str {
        match self {
            Method::Get => "GET",
            Method::Post => "POST",
            Method::Put => "PUT",
            Method::Delete => "DELETE",
            Method::Patch => "PATCH",
        }
    }
}

/// One request the host must perform, relative to the API origin. The host adds its
/// own session credential; the flow adds `X-Confirm-Token` when a step-up gates it.
pub struct ApiRequest {
    pub method: Method,
    pub path: String,
    pub body: Option<Value>,
    confirm_token: Option<Zeroizing<String>>,
}

impl ApiRequest {
    fn new(method: Method, path: impl Into<String>, body: Option<Value>) -> Self {
        Self {
            method,
            path: path.into(),
            body,
            confirm_token: None,
        }
    }

    /// Spend `token` on this request (the `X-Confirm-Token` header).
    fn gated(self, token: ConfirmToken) -> Self {
        Self {
            confirm_token: Some(token.into_header_value()),
            ..self
        }
    }

    /// A step-up request from `auth_flow`; both legs are POSTs on the signed-in session.
    fn from_auth(request: auth_flow::HttpRequest) -> Self {
        let method = match request.method {
            auth_flow::Method::Get => Method::Get,
            auth_flow::Method::Post => Method::Post,
            auth_flow::Method::Delete => Method::Delete,
            auth_flow::Method::Put => Method::Put,
            auth_flow::Method::Patch => Method::Patch,
        };
        Self {
            method,
            path: request.path,
            body: request.body,
            confirm_token: request.confirm_token,
        }
    }

    /// The value for the `X-Confirm-Token` header, if this request is step-up gated.
    /// Host code passes it straight to the header and keeps no copy.
    pub fn confirm_token(&self) -> Option<&str> {
        self.confirm_token.as_ref().map(|t| t.as_str())
    }

    /// The JSON body as text (empty when there is none).
    pub fn body_json(&self) -> String {
        self.body.as_ref().map(|b| b.to_string()).unwrap_or_default()
    }
}

impl std::fmt::Debug for ApiRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Bodies can hold OPAQUE messages and tokens: never print them.
        f.debug_struct("ApiRequest")
            .field("method", &self.method)
            .field("path", &self.path)
            .field("gated", &self.confirm_token.is_some())
            .finish()
    }
}

/// The server's reply, as the host received it.
#[derive(Clone)]
pub struct ApiResponse {
    pub status: u16,
    pub body: Value,
}

impl std::fmt::Debug for ApiResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Bodies can carry session tokens, TOTP secrets, backup codes and mailed tokens: status only.
        f.debug_struct("ApiResponse")
            .field("status", &self.status)
            .finish_non_exhaustive()
    }
}

impl ApiResponse {
    pub fn new(status: u16, body: Value) -> Self {
        Self { status, body }
    }

    /// The same reply in `auth_flow`'s shape, for the shared step-up.
    fn to_auth(&self) -> auth_flow::HttpResponse {
        auth_flow::HttpResponse::new(self.status, self.body.clone())
    }

    /// Parse a raw body; an empty or non-JSON body becomes `null`.
    pub fn from_text(status: u16, text: &str) -> Self {
        Self {
            status,
            body: serde_json::from_str(text).unwrap_or(Value::Null),
        }
    }

    fn ok(&self) -> bool {
        (200..300).contains(&self.status)
    }

    fn str_field(&self, name: &str) -> Result<&str, AccountFlowError> {
        self.body
            .get(name)
            .and_then(Value::as_str)
            .ok_or(AccountFlowError::Protocol)
    }

    fn error_code(&self) -> Option<&str> {
        self.body
            .get("code")
            .or_else(|| self.body.get("error"))
            .and_then(Value::as_str)
    }
}

/// What the host does next.
#[derive(Debug)]
pub enum Step {
    Send(ApiRequest),
    Done(AccountOutcome),
}

/// Errors map to stable codes; the server body is never echoed (crypto review rule 9).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AccountFlowError {
    #[error("incorrect password")]
    WrongPassword,
    #[error("this account cannot confirm with OPAQUE yet")]
    OpaqueUnavailable,
    #[error("incorrect code")]
    InvalidCode,
    #[error("the password does not meet the policy")]
    WeakPassword,
    #[error("the new password is the same as the current one")]
    SamePassword,
    #[error("the password appears in a known breach")]
    PasswordBreached,
    #[error("the breach check for this password has not been answered")]
    BreachCheckMissing,
    #[error("the breach check is unavailable and the server does not allow skipping it")]
    BreachCheckBlocked,
    #[error("a name can't be empty")]
    NameEmpty,
    #[error("the name is too long")]
    NameTooLong,
    #[error("invalid email address")]
    InvalidEmail,
    #[error("this email is already in use")]
    EmailInUse,
    #[error("too many attempts")]
    RateLimited,
    #[error("not signed in")]
    Unauthorized,
    #[error("server error {0}")]
    Server(u16),
    #[error("unexpected server reply")]
    Protocol,
    #[error("the flow was resumed out of order")]
    OutOfOrder,
    #[error("an authenticator or backup code is required")]
    SecondFactorRequired,
    #[error("the link is invalid or expired")]
    LinkInvalid,
    #[error("the request needs a confirmation")]
    ConfirmationRequired,
}

impl AccountFlowError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::WrongPassword => "wrong_password",
            Self::OpaqueUnavailable => "opaque_unavailable",
            Self::InvalidCode => "invalid_code",
            Self::WeakPassword => "weak_password",
            Self::SamePassword => "same_password",
            Self::PasswordBreached => "password_breached",
            Self::BreachCheckMissing => "breach_check_missing",
            Self::BreachCheckBlocked => "breach_check_blocked",
            Self::NameEmpty => "name_empty",
            Self::NameTooLong => "name_too_long",
            Self::InvalidEmail => "invalid_email",
            Self::EmailInUse => "email_in_use",
            Self::RateLimited => "rate_limited",
            Self::Unauthorized => "unauthorized",
            Self::Server(_) => "server_error",
            Self::Protocol => "protocol",
            Self::OutOfOrder => "out_of_order",
            Self::SecondFactorRequired => "second_factor_required",
            Self::LinkInvalid => "link_invalid",
            Self::ConfirmationRequired => "confirmation_required",
        }
    }
}

fn generic_error(resp: &ApiResponse) -> AccountFlowError {
    match resp.status {
        401 => AccountFlowError::Unauthorized,
        429 => AccountFlowError::RateLimited,
        s => AccountFlowError::Server(s),
    }
}

/// A one-time TOTP enrollment: the secret and its `otpauth` URI are shown on the
/// set-up screen (DW-A69); the backup codes stay here until the code is confirmed.
pub struct TotpEnrollment {
    pub secret: Zeroizing<String>,
    pub otpauth_uri: Zeroizing<String>,
    backup_codes: Zeroizing<Vec<String>>,
}

impl std::fmt::Debug for TotpEnrollment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TotpEnrollment { .. }")
    }
}

/// The result of a finished flow.
pub enum AccountOutcome {
    /// The request succeeded and carries nothing.
    Done,
    /// Password changed. All other sessions ended; this is the new session for this
    /// device. Swap it into the credential store and the engine in one step; never
    /// show it to a UI.
    PasswordChanged { session_token: Zeroizing<String> },
    /// The sign-in email changed; the server sent a code to the new address.
    EmailChanged { email: String },
    /// TOTP set-up started; confirm with [`AccountFlow::totp_confirm`].
    TotpEnrollment(TotpEnrollment),
    /// TOTP is on; these are the 8 single-use backup codes, shown once.
    BackupCodes(Zeroizing<Vec<String>>),
    /// Sessions revoked (count from the server; 1 for a single revoke).
    Revoked { count: u32 },
    /// Delete step 1 done: a single-use link went to the owner's mailbox. Nothing is
    /// scheduled yet. RFC 3339 time the link stops working.
    DeletionRequested { link_expires_at: String },
    /// Account deletion scheduled (the link was confirmed); RFC 3339 times after which
    /// data is shredded and until which the same link can cancel it.
    DeletionScheduled {
        shred_after: String,
        cancel_until: Option<String>,
    },
    /// Deletion cancelled; `not_restored` names what the cancel does not bring back
    /// (`sessions`, `share_links`, ...), as the server reports it.
    DeletionCancelled { not_restored: Vec<String> },
}

impl std::fmt::Debug for AccountOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Done => f.write_str("Done"),
            Self::PasswordChanged { .. } => f.write_str("PasswordChanged { .. }"),
            Self::EmailChanged { .. } => f.write_str("EmailChanged { email: <redacted> }"),
            Self::TotpEnrollment(_) => f.write_str("TotpEnrollment { .. }"),
            Self::BackupCodes(c) => write!(f, "BackupCodes({} codes)", c.len()),
            Self::Revoked { count } => write!(f, "Revoked {{ count: {count} }}"),
            Self::DeletionRequested { link_expires_at } => write!(f, "DeletionRequested {{ {link_expires_at} }}"),
            Self::DeletionScheduled { shred_after, .. } => write!(f, "DeletionScheduled {{ {shred_after} }}"),
            Self::DeletionCancelled { not_restored } => {
                write!(f, "DeletionCancelled({} not restored)", not_restored.len())
            }
        }
    }
}

/// The public account binding values re-sent on a re-registration (not secret).
pub struct AccountBinding {
    pub recovery_check_b64: String,
    pub x25519_public_b64: String,
}

impl AccountBinding {
    pub fn from_master_key(master_key: &MasterKey) -> Self {
        let check = compute_recovery_check(master_key);
        let private = derive_x25519_private(master_key);
        let public = derive_x25519_public(&private);
        Self {
            recovery_check_b64: B64.encode(*check),
            x25519_public_b64: B64.encode(public),
        }
    }
}

// ─── step-up ────────────────────────────────────────────────────────────────

/// The step-up inside an account flow. It is [`crate::auth_flow::step_up::StepUp`], the one
/// implementation of the OPAQUE confirm ceremony (`/auth/confirm-opaque-{start,finish}`), with
/// the generic purpose (no `purpose` field: the account endpoints take the generic grant). This
/// type only translates the account wire types and errors; the ceremony, the password copy and
/// the [`ConfirmToken`] all live in `auth_flow`.
struct StepUp {
    machine: Option<auth_step_up::StepUp>,
}

impl StepUp {
    fn new() -> Self {
        Self { machine: None }
    }

    fn start(&mut self, password: &[u8]) -> Result<ApiRequest, AccountFlowError> {
        let (machine, request) =
            auth_step_up::StepUp::start(password, StepUpPurpose::Generic).map_err(step_up_error_at_start)?;
        self.machine = Some(machine);
        Ok(ApiRequest::from_auth(request))
    }

    fn on_start(&mut self, resp: &ApiResponse) -> Result<ApiRequest, AccountFlowError> {
        let machine = self.machine.as_mut().ok_or(AccountFlowError::OutOfOrder)?;
        match machine.on_response(resp.to_auth()) {
            Ok(StepUpStep::Send(request)) => Ok(ApiRequest::from_auth(request)),
            Ok(StepUpStep::Confirmed(_)) => Err(AccountFlowError::Protocol),
            Err(e) => Err(step_up_error(e, resp)),
        }
    }

    fn on_finish(&mut self, resp: &ApiResponse) -> Result<ConfirmToken, AccountFlowError> {
        let mut machine = self.machine.take().ok_or(AccountFlowError::OutOfOrder)?;
        match machine.on_response(resp.to_auth()) {
            Ok(StepUpStep::Confirmed(token)) => Ok(token),
            Ok(StepUpStep::Send(_)) => Err(AccountFlowError::Protocol),
            Err(e) => Err(step_up_error(e, resp)),
        }
    }
}

/// A step-up that could not start: an empty password is a wrong password here.
fn step_up_error_at_start(e: AuthFlowError) -> AccountFlowError {
    match e {
        AuthFlowError::InvalidInput(_) => AccountFlowError::WrongPassword,
        _ => AccountFlowError::Protocol,
    }
}

/// Map the ceremony's error onto the account codes. A wrong password and a wrong KSF are
/// indistinguishable by design (both are `InvalidCredentials`, as a 401 is).
fn step_up_error(e: AuthFlowError, resp: &ApiResponse) -> AccountFlowError {
    match e {
        AuthFlowError::OpaqueUnavailable => AccountFlowError::OpaqueUnavailable,
        AuthFlowError::InvalidCredentials => AccountFlowError::WrongPassword,
        _ if !resp.ok() => generic_error(resp),
        AuthFlowError::WrongState => AccountFlowError::OutOfOrder,
        _ => AccountFlowError::Protocol,
    }
}

// ─── the flow ──────────────────────────────────────────────────────────────

enum Kind {
    ChangePassword {
        current: Zeroizing<Vec<u8>>,
        new: Zeroizing<Vec<u8>>,
        binding: AccountBinding,
        reg_state: Option<Zeroizing<Vec<u8>>>,
        server_message: Option<Vec<u8>>,
    },
    ChangeEmail {
        new_email: String,
        password: Zeroizing<Vec<u8>>,
        binding: AccountBinding,
        reg_state: Option<Zeroizing<Vec<u8>>>,
    },
    TotpSetup {
        password: Option<Zeroizing<Vec<u8>>>,
        current_code: Option<Zeroizing<String>>,
    },
    TotpConfirm {
        enrollment: Option<TotpEnrollment>,
        code: Zeroizing<String>,
    },
    DeleteAccount {
        password: Zeroizing<Vec<u8>>,
        code: Option<Zeroizing<String>>,
    },
    TrackingOff {
        password: Zeroizing<Vec<u8>>,
    },
    VerifyPassword {
        password: Zeroizing<Vec<u8>>,
    },
    /// One request; `parse` turns the 2xx reply into the outcome, `map_err` maps a
    /// non-2xx reply to an error.
    Single {
        request: Option<ApiRequest>,
        parse: fn(&ApiResponse) -> Result<AccountOutcome, AccountFlowError>,
        map_err: fn(&ApiResponse) -> AccountFlowError,
    },
}

/// The phases a flow can be waiting in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    New,
    StepUpStart(u8),
    StepUpFinish(u8),
    Leg1,
    Leg2,
    Final,
    Finished,
}

/// One account flow. Build it with a constructor, then `start` / `resume`.
pub struct AccountFlow {
    kind: Kind,
    phase: Phase,
    step_up: StepUp,
}

/// Sign-up's gate ([`crate::signup_flow::password_gate`]) with the server's policy and the breach
/// check made for `new`, then "not the same as the current one". No hard-coded fallback policy.
fn validate_new_password(
    current: &str,
    new: &str,
    policy: &SignupPolicy,
    breach: Option<&BreachCheck>,
) -> Result<(), AccountFlowError> {
    use crate::signup_flow::SignupError as E;
    crate::signup_flow::password_gate(policy, breach, new).map_err(|e| match e {
        E::PasswordBreached => AccountFlowError::PasswordBreached,
        E::BreachCheckBlocked => AccountFlowError::BreachCheckBlocked,
        E::BreachCheckMissing => AccountFlowError::BreachCheckMissing,
        _ => AccountFlowError::WeakPassword,
    })?;
    if current == new {
        return Err(AccountFlowError::SamePassword);
    }
    Ok(())
}

fn validate_code(code: &str, len: usize) -> Result<Zeroizing<String>, AccountFlowError> {
    let digits: String = code.chars().filter(|c| !c.is_whitespace() && *c != '-').collect();
    if digits.len() != len || !digits.chars().all(|c| c.is_ascii_digit()) {
        return Err(AccountFlowError::InvalidCode);
    }
    Ok(Zeroizing::new(digits))
}

/// A 6-digit authenticator code or an 8-digit backup code.
fn validate_second_factor(code: &str) -> Result<Zeroizing<String>, AccountFlowError> {
    validate_code(code, 6).or_else(|_| validate_code(code, 8))
}

fn code_error(resp: &ApiResponse) -> AccountFlowError {
    match resp.status {
        400 | 401 | 403 | 422 => AccountFlowError::InvalidCode,
        _ => generic_error(resp),
    }
}

/// A delete-link token: what follows `#t=` in the mailed link. The whole link may be
/// pasted; the token is taken from its fragment.
fn validate_link_token(input: &str) -> Result<Zeroizing<String>, AccountFlowError> {
    let input = input.trim();
    let token = input.rsplit_once("#t=").map_or(input, |(_, t)| t);
    let token = token.split('&').next().unwrap_or_default();
    if token.is_empty()
        || token.len() > MAX_LINK_TOKEN_CHARS
        || !token.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(AccountFlowError::LinkInvalid);
    }
    Ok(Zeroizing::new(token.to_string()))
}

fn link_error(resp: &ApiResponse) -> AccountFlowError {
    match resp.status {
        400 | 404 | 410 => AccountFlowError::LinkInvalid,
        _ => generic_error(resp),
    }
}

fn parse_backup_codes(resp: &ApiResponse) -> Result<Zeroizing<Vec<String>>, AccountFlowError> {
    let codes: Vec<String> = resp
        .body
        .get("backup_codes")
        .and_then(Value::as_array)
        .ok_or(AccountFlowError::Protocol)?
        .iter()
        .map(|c| c.as_str().map(str::to_string).ok_or(AccountFlowError::Protocol))
        .collect::<Result<_, _>>()?;
    if codes.is_empty() {
        return Err(AccountFlowError::Protocol);
    }
    Ok(Zeroizing::new(codes))
}

/// Delete-request errors: a missing second factor, a wrong code, the mail limit.
fn delete_request_error(resp: &ApiResponse, sent_code: bool) -> AccountFlowError {
    let code = resp.error_code().unwrap_or_default();
    match resp.status {
        403 if code == "second_factor_required" => AccountFlowError::SecondFactorRequired,
        400 | 401 | 422 if sent_code && code != "unauthorized" => AccountFlowError::InvalidCode,
        _ => generic_error(resp),
    }
}

fn done(_: &ApiResponse) -> Result<AccountOutcome, AccountFlowError> {
    Ok(AccountOutcome::Done)
}

impl AccountFlow {
    fn with(kind: Kind) -> Self {
        Self {
            kind,
            phase: Phase::New,
            step_up: StepUp::new(),
        }
    }

    /// Change the password: OPAQUE re-registration with a step-up per leg (DW-A67).
    /// No master-key wrap: the master key is unchanged; the binding values are re-sent.
    ///
    /// `policy` is the server's (`GET /api/v1/onboarding`, [`SignupPolicy::from_response`]);
    /// `breach` is the [`BreachCheck`] made for `new` and answered, required when the policy
    /// declares a breach check. The same gate as sign-up and phrase recovery.
    pub fn change_password(
        current: &str,
        new: &str,
        binding: AccountBinding,
        policy: &SignupPolicy,
        breach: Option<&BreachCheck>,
    ) -> Result<Self, AccountFlowError> {
        validate_new_password(current, new, policy, breach)?;
        Ok(Self::with(Kind::ChangePassword {
            current: Zeroizing::new(current.as_bytes().to_vec()),
            new: Zeroizing::new(new.as_bytes().to_vec()),
            binding,
            reg_state: None,
            server_message: None,
        }))
    }

    /// Change the sign-in email: a step-up, then OPAQUE re-registration under the new
    /// address with the same password (the password file is bound to the email).
    pub fn change_email(new_email: &str, password: &str, binding: AccountBinding) -> Result<Self, AccountFlowError> {
        let email = new_email.trim().to_lowercase();
        let valid = email.len() <= 254
            && email
                .split_once('@')
                .is_some_and(|(l, d)| !l.is_empty() && d.contains('.') && !d.starts_with('.'))
            && !email.chars().any(char::is_whitespace);
        if !valid {
            return Err(AccountFlowError::InvalidEmail);
        }
        Ok(Self::with(Kind::ChangeEmail {
            new_email: email,
            password: Zeroizing::new(password.as_bytes().to_vec()),
            binding,
            reg_state: None,
        }))
    }

    /// Confirm the new address with the 8-digit code the server sent (DW-A66).
    pub fn verify_email(code: &str) -> Result<Self, AccountFlowError> {
        let code = validate_code(code, 8)?;
        Ok(Self::single(
            ApiRequest::new(Method::Post, PATH_VERIFY_EMAIL, Some(json!({ "code": code.as_str() }))),
            done,
            code_error,
        ))
    }

    /// Start TOTP set-up (DW-A69). With TOTP already on, the server requires a step-up:
    /// pass the password (step-up inside) or the current code (moving to a new
    /// authenticator, DW-A71). With TOTP off, pass neither.
    pub fn totp_setup(password: Option<&str>, current_code: Option<&str>) -> Result<Self, AccountFlowError> {
        let current_code = current_code.map(validate_second_factor).transpose()?;
        Ok(Self::with(Kind::TotpSetup {
            password: password.map(|p| Zeroizing::new(p.as_bytes().to_vec())),
            current_code,
        }))
    }

    /// Turn TOTP on with the first code; the outcome releases the backup codes.
    pub fn totp_confirm(enrollment: TotpEnrollment, code: &str) -> Result<Self, AccountFlowError> {
        let code = validate_code(code, 6)?;
        Ok(Self::with(Kind::TotpConfirm {
            enrollment: Some(enrollment),
            code,
        }))
    }

    /// Turn TOTP off with a current code (DW-A72).
    pub fn totp_disable(code: &str) -> Result<Self, AccountFlowError> {
        let code = validate_second_factor(code)?;
        Ok(Self::single(
            ApiRequest::new(Method::Post, PATH_TOTP_DISABLE, Some(json!({ "code": code.as_str() }))),
            done,
            code_error,
        ))
    }

    /// End one session of the account (DW-A56).
    pub fn revoke_session(session_id: &str) -> Result<Self, AccountFlowError> {
        if session_id.is_empty() || !session_id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err(AccountFlowError::Protocol);
        }
        Ok(Self::single(
            ApiRequest::new(Method::Delete, format!("{PATH_SESSIONS}/{session_id}"), None),
            |_| Ok(AccountOutcome::Revoked { count: 1 }),
            generic_error,
        ))
    }

    /// End every session of the account except this one (DW-A55).
    pub fn revoke_other_sessions() -> Self {
        Self::single(
            ApiRequest::new(Method::Post, PATH_REVOKE_OTHERS, None),
            |r| {
                let count = r.body.get("revoked").and_then(Value::as_u64).unwrap_or(0);
                Ok(AccountOutcome::Revoked {
                    count: u32::try_from(count).unwrap_or(u32::MAX),
                })
            },
            generic_error,
        )
    }

    /// Change the display name (DW-A64): 1 to 64 characters, trimmed.
    pub fn set_display_name(name: &str) -> Result<Self, AccountFlowError> {
        let name = name.trim();
        if name.is_empty() {
            return Err(AccountFlowError::NameEmpty);
        }
        if name.chars().count() > MAX_NAME_CHARS {
            return Err(AccountFlowError::NameTooLong);
        }
        Ok(Self::single(
            ApiRequest::new(Method::Put, PATH_PROFILE, Some(json!({ "display_name": name }))),
            done,
            generic_error,
        ))
    }

    /// Turn sign-in activity recording on or off (DW-A77 to A79). Turning it off is a
    /// security change: it takes a step-up with the password (server: `X-Confirm-Token`
    /// on `opted_in: false`). Turning it on needs no password; one passed is ignored.
    pub fn set_activity_logging(on: bool, password: Option<&str>) -> Result<Self, AccountFlowError> {
        if on {
            return Ok(Self::single(
                ApiRequest::new(Method::Put, PATH_TRACKING, Some(json!({ "opted_in": true }))),
                done,
                generic_error,
            ));
        }
        let password = password
            .filter(|p| !p.is_empty())
            .ok_or(AccountFlowError::WrongPassword)?;
        Ok(Self::with(Kind::TrackingOff {
            password: Zeroizing::new(password.as_bytes().to_vec()),
        }))
    }

    /// Make new backup codes (DW-A71): the current authenticator code (6 digits, not a
    /// backup code) proves the person; the authenticator stays, the old codes stop working.
    pub fn regenerate_backup_codes(code: &str) -> Result<Self, AccountFlowError> {
        let code = validate_code(code, 6)?;
        Ok(Self::single(
            ApiRequest::new(Method::Post, PATH_BACKUP_CODES, Some(json!({ "code": code.as_str() }))),
            |r| Ok(AccountOutcome::BackupCodes(parse_backup_codes(r)?)),
            code_error,
        ))
    }

    /// Check the password with a step-up and drop the token (delete step 1, DW-A58):
    /// nothing is changed or scheduled. Counts toward the sign-in lockout server side.
    pub fn verify_password(password: &str) -> Result<Self, AccountFlowError> {
        if password.is_empty() {
            return Err(AccountFlowError::WrongPassword);
        }
        Ok(Self::with(Kind::VerifyPassword {
            password: Zeroizing::new(password.as_bytes().to_vec()),
        }))
    }

    /// Delete step 2 (DW-A59): a step-up with the password, then
    /// `POST /auth/account/delete-request` with the second factor on a 2FA account (`code`:
    /// a 6-digit authenticator code or an 8-digit backup code). The server mails a
    /// single-use link; nothing is scheduled until that link is confirmed.
    pub fn delete_account(password: &str, code: Option<&str>) -> Result<Self, AccountFlowError> {
        if password.is_empty() {
            return Err(AccountFlowError::WrongPassword);
        }
        let code = code
            .filter(|c| !c.trim().is_empty())
            .map(validate_second_factor)
            .transpose()?;
        Ok(Self::with(Kind::DeleteAccount {
            password: Zeroizing::new(password.as_bytes().to_vec()),
            code,
        }))
    }

    /// Delete step 3: confirm with the mailed link's token. Schedules the deletion.
    pub fn delete_confirm(link_token: &str) -> Result<Self, AccountFlowError> {
        let token = validate_link_token(link_token)?;
        Ok(Self::single(
            ApiRequest::new(
                Method::Post,
                PATH_DELETE_CONFIRM,
                Some(json!({ "token": token.as_str() })),
            ),
            |r| {
                Ok(AccountOutcome::DeletionScheduled {
                    shred_after: r.str_field("shred_after")?.to_string(),
                    cancel_until: r.str_field("cancel_until").ok().map(str::to_string),
                })
            },
            link_error,
        ))
    }

    /// Undo a scheduled deletion with the same link token (DW-A81 / A82).
    pub fn delete_cancel(link_token: &str) -> Result<Self, AccountFlowError> {
        let token = validate_link_token(link_token)?;
        Ok(Self::single(
            ApiRequest::new(
                Method::Post,
                PATH_DELETE_CANCEL,
                Some(json!({ "token": token.as_str() })),
            ),
            |r| {
                if r.body.get("cancelled").and_then(Value::as_bool) != Some(true) {
                    return Err(AccountFlowError::Protocol);
                }
                let not_restored = r
                    .body
                    .get("not_restored")
                    .and_then(Value::as_array)
                    .map(|a| a.iter().filter_map(Value::as_str).map(str::to_string).collect())
                    .unwrap_or_default();
                Ok(AccountOutcome::DeletionCancelled { not_restored })
            },
            link_error,
        ))
    }

    fn single(
        request: ApiRequest,
        parse: fn(&ApiResponse) -> Result<AccountOutcome, AccountFlowError>,
        map_err: fn(&ApiResponse) -> AccountFlowError,
    ) -> Self {
        Self::with(Kind::Single {
            request: Some(request),
            parse,
            map_err,
        })
    }

    /// The first request.
    pub fn start(&mut self) -> Result<Step, AccountFlowError> {
        if self.phase != Phase::New {
            return Err(AccountFlowError::OutOfOrder);
        }
        let step = match &mut self.kind {
            Kind::ChangePassword { current, .. } => {
                self.phase = Phase::StepUpStart(1);
                self.step_up.start(current)?
            }
            Kind::ChangeEmail { password, .. }
            | Kind::DeleteAccount { password, .. }
            | Kind::TrackingOff { password }
            | Kind::VerifyPassword { password } => {
                self.phase = Phase::StepUpStart(1);
                self.step_up.start(password)?
            }
            Kind::TotpSetup { password: Some(p), .. } => {
                self.phase = Phase::StepUpStart(1);
                self.step_up.start(p)?
            }
            Kind::TotpSetup {
                password: None,
                current_code,
            } => {
                self.phase = Phase::Final;
                let body = current_code.as_ref().map(|c| json!({ "code": c.as_str() }));
                ApiRequest::new(Method::Post, PATH_TOTP_SETUP, body)
            }
            Kind::TotpConfirm { code, .. } => {
                self.phase = Phase::Final;
                ApiRequest::new(Method::Post, PATH_TOTP_ENABLE, Some(json!({ "code": code.as_str() })))
            }
            Kind::Single { request, .. } => {
                self.phase = Phase::Final;
                request.take().ok_or(AccountFlowError::OutOfOrder)?
            }
        };
        Ok(Step::Send(step))
    }

    /// Feed the reply to the last request.
    pub fn resume(&mut self, resp: ApiResponse) -> Result<Step, AccountFlowError> {
        let result = self.advance(&resp);
        if result.is_err() {
            self.phase = Phase::Finished;
        }
        result
    }

    fn advance(&mut self, resp: &ApiResponse) -> Result<Step, AccountFlowError> {
        match self.phase {
            Phase::StepUpStart(n) => {
                let req = self.step_up.on_start(resp)?;
                self.phase = Phase::StepUpFinish(n);
                Ok(Step::Send(req))
            }
            Phase::StepUpFinish(n) => {
                let token = self.step_up.on_finish(resp)?;
                self.after_step_up(n, token)
            }
            Phase::Leg1 => self.after_leg1(resp),
            Phase::Leg2 | Phase::Final => {
                let outcome = self.finish(resp)?;
                self.phase = Phase::Finished;
                Ok(Step::Done(outcome))
            }
            Phase::New | Phase::Finished => Err(AccountFlowError::OutOfOrder),
        }
    }

    fn after_step_up(&mut self, n: u8, token: ConfirmToken) -> Result<Step, AccountFlowError> {
        match &mut self.kind {
            Kind::ChangePassword {
                new,
                reg_state,
                server_message,
                binding,
                ..
            } => {
                if n == 1 {
                    let start =
                        opaque_protocol::client_registration_start(new).map_err(|_| AccountFlowError::Protocol)?;
                    *reg_state = Some(Zeroizing::new(start.state));
                    self.phase = Phase::Leg1;
                    Ok(Step::Send(
                        ApiRequest::new(
                            Method::Post,
                            PATH_CHANGE_PASSWORD_START,
                            Some(json!({ "client_message": B64.encode(&start.message) })),
                        )
                        .gated(token),
                    ))
                } else {
                    let state = reg_state.take().ok_or(AccountFlowError::OutOfOrder)?;
                    let msg = server_message.take().ok_or(AccountFlowError::OutOfOrder)?;
                    let upload = opaque_protocol::client_registration_finish(&state, new, &msg)
                        .map_err(|_| AccountFlowError::Protocol)?;
                    self.phase = Phase::Leg2;
                    Ok(Step::Send(
                        ApiRequest::new(
                            Method::Post,
                            PATH_CHANGE_PASSWORD_FINISH,
                            Some(json!({
                                "client_message": B64.encode(&upload),
                                "recovery_check": binding.recovery_check_b64,
                                "x25519_public_key": binding.x25519_public_b64,
                            })),
                        )
                        .gated(token),
                    ))
                }
            }
            Kind::ChangeEmail {
                new_email,
                password,
                reg_state,
                ..
            } => {
                let start =
                    opaque_protocol::client_registration_start(password).map_err(|_| AccountFlowError::Protocol)?;
                *reg_state = Some(Zeroizing::new(start.state));
                self.phase = Phase::Leg1;
                Ok(Step::Send(
                    ApiRequest::new(
                        Method::Post,
                        PATH_EMAIL_START,
                        Some(json!({ "new_email": new_email, "opaque_client_message": B64.encode(&start.message) })),
                    )
                    .gated(token),
                ))
            }
            Kind::VerifyPassword { .. } => {
                drop(token);
                self.phase = Phase::Finished;
                Ok(Step::Done(AccountOutcome::Done))
            }
            Kind::TotpSetup { .. } => {
                self.phase = Phase::Final;
                Ok(Step::Send(
                    ApiRequest::new(Method::Post, PATH_TOTP_SETUP, None).gated(token),
                ))
            }
            Kind::DeleteAccount { code, .. } => {
                self.phase = Phase::Final;
                let body = match code {
                    Some(c) => json!({ "code": c.as_str() }),
                    None => json!({}),
                };
                Ok(Step::Send(
                    ApiRequest::new(Method::Post, PATH_DELETE_REQUEST, Some(body)).gated(token),
                ))
            }
            Kind::TrackingOff { .. } => {
                self.phase = Phase::Final;
                Ok(Step::Send(
                    ApiRequest::new(Method::Put, PATH_TRACKING, Some(json!({ "opted_in": false }))).gated(token),
                ))
            }
            _ => Err(AccountFlowError::OutOfOrder),
        }
    }

    fn after_leg1(&mut self, resp: &ApiResponse) -> Result<Step, AccountFlowError> {
        match &mut self.kind {
            Kind::ChangePassword {
                current,
                server_message,
                ..
            } => {
                if !resp.ok() {
                    return Err(generic_error(resp));
                }
                *server_message = Some(
                    B64.decode(resp.str_field("server_message")?)
                        .map_err(|_| AccountFlowError::Protocol)?,
                );
                // Leg 2 needs its own single-use token.
                let req = self.step_up.start(current)?;
                self.phase = Phase::StepUpStart(2);
                Ok(Step::Send(req))
            }
            Kind::ChangeEmail {
                password,
                reg_state,
                binding,
                ..
            } => {
                if resp.status == 409 {
                    return Err(AccountFlowError::EmailInUse);
                }
                if resp.status == 400 && resp.error_code().is_some_and(|c| c.contains("email")) {
                    return Err(AccountFlowError::InvalidEmail);
                }
                if !resp.ok() {
                    return Err(generic_error(resp));
                }
                let msg = B64
                    .decode(resp.str_field("server_message")?)
                    .map_err(|_| AccountFlowError::Protocol)?;
                let ticket = Zeroizing::new(resp.str_field("email_change_token")?.to_string());
                let state = reg_state.take().ok_or(AccountFlowError::OutOfOrder)?;
                let upload = opaque_protocol::client_registration_finish(&state, password, &msg)
                    .map_err(|_| AccountFlowError::Protocol)?;
                self.phase = Phase::Final;
                Ok(Step::Send(ApiRequest::new(
                    Method::Post,
                    PATH_EMAIL_FINISH,
                    Some(json!({
                        "email_change_token": ticket.as_str(),
                        "opaque_registration": B64.encode(&upload),
                        "recovery_check": binding.recovery_check_b64,
                        "x25519_public_key": binding.x25519_public_b64,
                    })),
                )))
            }
            _ => Err(AccountFlowError::OutOfOrder),
        }
    }

    fn finish(&mut self, resp: &ApiResponse) -> Result<AccountOutcome, AccountFlowError> {
        match &mut self.kind {
            Kind::ChangePassword { .. } => {
                if !resp.ok() {
                    return Err(generic_error(resp));
                }
                Ok(AccountOutcome::PasswordChanged {
                    session_token: Zeroizing::new(resp.str_field("session_token")?.to_string()),
                })
            }
            Kind::ChangeEmail { .. } => {
                if !resp.ok() {
                    return Err(generic_error(resp));
                }
                Ok(AccountOutcome::EmailChanged {
                    email: resp.str_field("email")?.to_string(),
                })
            }
            Kind::TotpSetup { current_code, .. } => {
                if current_code.is_some() && !resp.ok() {
                    return Err(code_error(resp));
                }
                if !resp.ok() {
                    return Err(generic_error(resp));
                }
                let codes: Vec<String> = resp
                    .body
                    .get("backup_codes")
                    .and_then(Value::as_array)
                    .ok_or(AccountFlowError::Protocol)?
                    .iter()
                    .map(|c| c.as_str().map(str::to_string).ok_or(AccountFlowError::Protocol))
                    .collect::<Result<_, _>>()?;
                Ok(AccountOutcome::TotpEnrollment(TotpEnrollment {
                    secret: Zeroizing::new(resp.str_field("secret")?.to_string()),
                    otpauth_uri: Zeroizing::new(resp.str_field("qr_uri")?.to_string()),
                    backup_codes: Zeroizing::new(codes),
                }))
            }
            Kind::TotpConfirm { enrollment, .. } => {
                if !resp.ok() {
                    return Err(code_error(resp));
                }
                let mut enrollment = enrollment.take().ok_or(AccountFlowError::OutOfOrder)?;
                Ok(AccountOutcome::BackupCodes(std::mem::take(
                    &mut enrollment.backup_codes,
                )))
            }
            Kind::DeleteAccount { code, .. } => {
                if !resp.ok() {
                    return Err(delete_request_error(resp, code.is_some()));
                }
                Ok(AccountOutcome::DeletionRequested {
                    link_expires_at: resp.str_field("link_expires_at")?.to_string(),
                })
            }
            Kind::TrackingOff { .. } => {
                if resp.status == 403 && resp.error_code() == Some("confirmation_required") {
                    return Err(AccountFlowError::ConfirmationRequired);
                }
                if !resp.ok() {
                    return Err(generic_error(resp));
                }
                Ok(AccountOutcome::Done)
            }
            Kind::VerifyPassword { .. } => Err(AccountFlowError::OutOfOrder),
            Kind::Single { parse, map_err, .. } => {
                if !resp.ok() {
                    return Err(map_err(resp));
                }
                parse(resp)
            }
        }
    }
}

/// A host transport for the blocking driver [`run`].
pub trait AccountTransport {
    fn send(&mut self, request: &ApiRequest) -> Result<ApiResponse, AccountFlowError>;
}

/// Drive a flow to the end over a blocking transport (tests, CLI). Async hosts loop
/// over `start` / `resume` themselves.
pub fn run(mut flow: AccountFlow, transport: &mut dyn AccountTransport) -> Result<AccountOutcome, AccountFlowError> {
    let mut step = flow.start()?;
    loop {
        match step {
            Step::Done(outcome) => return Ok(outcome),
            Step::Send(req) => {
                let resp = transport.send(&req)?;
                drop(req);
                step = flow.resume(resp)?;
            }
        }
    }
}

// ─── host adapter for the bindings ─────────────────────────────────────────

#[path = "account_flows_host.rs"]
mod host;
pub use host::{HostOutcome, HostSession, HostStep};

#[cfg(test)]
#[path = "account_flows_tests.rs"]
mod tests;
