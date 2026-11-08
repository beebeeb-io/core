//! Account sign-in flows as plain logic, shared by desktop (Rust), mobile (UniFFI) and web (WASM).
//!
//! Every flow here is **sans-IO**: it hands the caller an [`HttpRequest`] to send and takes the
//! [`HttpResponse`] back, so each platform keeps its own transport (reqwest, URLSession, fetch)
//! while the protocol, the OPAQUE math and the error mapping live once, in core.
//!
//! - [`sign_in`]: the OPAQUE password login (`/api/v1/opaque/login-*`), then the second factor
//!   (`/api/v1/auth/2fa/verify`, a TOTP or a backup code).
//! - [`step_up`]: the OPAQUE re-authentication that mints a single-use `X-Confirm-Token`
//!   (`/api/v1/auth/confirm-opaque-*`), optionally bound to a purpose (`cli_device_approval` + the
//!   code). There is no plaintext-password path: an account without an OPAQUE credential is an
//!   error ([`AuthFlowError::OpaqueUnavailable`]), never a fallback to `/auth/confirm`.
//! - [`device`]: sign in with another device. The requesting side ([`device::DeviceRequest`])
//!   speaks the `/api/v1/auth/cli` socket frames; the approving side ([`device::Approval`]) looks
//!   the request up, steps up, claims the code and relays the keys encrypted to the requester's
//!   ephemeral P-256 key ([`crate::cli_auth`]: ECDH, HKDF-SHA256, AES-256-GCM; the server is a
//!   blind relay).
//!
//! Secrets (password, session token, partial token, confirm token, master key) are held in
//! [`Zeroizing`] buffers and never appear in a `Debug` print or an error. Errors are codes
//! ([`AuthFlowError`]); a server body is never echoed.
//!
//! The confirm token a step-up mints is consumed by the flow that asked for it (the approval
//! run puts it on its own claim request); no public API hands it to a caller as a value.
use std::fmt;

use base64::Engine;
use zeroize::Zeroizing;

pub mod device;
pub mod sign_in;
pub mod step_up;

#[cfg(test)]
mod tests;

pub(crate) fn b64() -> base64::engine::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}

pub(crate) fn b64_decode(s: &str) -> Result<Vec<u8>, AuthFlowError> {
    b64()
        .decode(s.trim())
        .map_err(|_| AuthFlowError::Protocol("invalid base64"))
}

/// HTTP verb of a flow request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    Get,
    Post,
    /// Only the share flows use it (revoking a link or an invite).
    Delete,
    /// Only the folder share flow uses it (registering a folder's custody record).
    Put,
}

impl Method {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Delete => "DELETE",
            Self::Put => "PUT",
        }
    }
}

/// Which credential the transport puts on the request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequestAuth {
    /// No credential (the login legs).
    None,
    /// The caller's signed-in session (`Authorization: Bearer …`), which the transport holds.
    Session,
}

/// One request a flow asks the caller to send. `path` is relative to the API base
/// (`/api/v1/...`); `body` is JSON. `confirm_token`, when present, goes in the
/// `X-Confirm-Token` header and is wiped when the request is dropped.
pub struct HttpRequest {
    pub method: Method,
    pub path: String,
    pub body: Option<serde_json::Value>,
    pub auth: RequestAuth,
    /// Not readable as a field outside core: only the platform transport reads it, through
    /// [`HttpRequest::confirm_token_header`], to fill the header.
    pub(crate) confirm_token: Option<Zeroizing<String>>,
}

impl HttpRequest {
    /// A POST on the signed-in session with no confirm token (bindings build the consuming request of
    /// a step-up with it, then attach the token inside core).
    pub fn session_post(path: String, body: serde_json::Value) -> Self {
        Self {
            method: Method::Post,
            path,
            body: Some(body),
            auth: RequestAuth::Session,
            confirm_token: None,
        }
    }

    /// The `X-Confirm-Token` header value, for the platform transport that sends this request and
    /// nothing else. It is set only on the request that consumes the token.
    pub fn confirm_token_header(&self) -> Option<&str> {
        self.confirm_token.as_ref().map(|t| t.as_str())
    }

    pub(crate) fn post(path: &str, body: serde_json::Value, auth: RequestAuth) -> Self {
        Self {
            method: Method::Post,
            path: path.to_owned(),
            body: Some(body),
            auth,
            confirm_token: None,
        }
    }

    pub(crate) fn delete(path: String, auth: RequestAuth) -> Self {
        Self {
            method: Method::Delete,
            path,
            body: None,
            auth,
            confirm_token: None,
        }
    }

    pub(crate) fn put(path: String, body: serde_json::Value, auth: RequestAuth) -> Self {
        Self {
            method: Method::Put,
            path,
            body: Some(body),
            auth,
            confirm_token: None,
        }
    }

    pub(crate) fn get(path: String, auth: RequestAuth) -> Self {
        Self {
            method: Method::Get,
            path,
            body: None,
            auth,
            confirm_token: None,
        }
    }
}

impl fmt::Debug for HttpRequest {
    // The body can hold a partial token or an OPAQUE message; the path and verb are enough to debug a flow.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpRequest")
            .field("method", &self.method)
            .field("path", &self.path)
            .field("auth", &self.auth)
            .field("confirm_token", &self.confirm_token.as_ref().map(|_| "<set>"))
            .finish_non_exhaustive()
    }
}

/// The server's answer to an [`HttpRequest`]. `body` is the parsed JSON (or `Null` when the
/// body was empty or not JSON); `retry_after_secs` is the `Retry-After` header on a 429.
#[derive(Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub body: serde_json::Value,
    pub retry_after_secs: Option<u64>,
}

impl HttpResponse {
    pub fn new(status: u16, body: serde_json::Value) -> Self {
        Self {
            status,
            body,
            retry_after_secs: None,
        }
    }

    /// Build a response from the raw body text (bindings): a body that is empty or not JSON is `Null`.
    pub fn from_text(status: u16, body: &str, retry_after_secs: Option<u64>) -> Self {
        Self {
            status,
            body: serde_json::from_str(body).unwrap_or(serde_json::Value::Null),
            retry_after_secs,
        }
    }

    /// A 2xx status.
    pub fn ok(&self) -> bool {
        (200..300).contains(&self.status)
    }

    pub(crate) fn str_field(&self, key: &str) -> Result<&str, AuthFlowError> {
        self.body
            .get(key)
            .and_then(|v| v.as_str())
            .ok_or(AuthFlowError::Protocol("missing field"))
    }

    /// The server's machine code for an error (`{"code": "..."}` or `{"error": "..."}`).
    pub(crate) fn error_code(&self) -> Option<&str> {
        self.body
            .get("code")
            .and_then(|v| v.as_str())
            .or_else(|| self.body.get("error").and_then(|v| v.as_str()))
    }
}

/// What can go wrong in a flow, as codes. The display strings are for logs; the apps map the
/// code to their own words.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthFlowError {
    /// Wrong password, unknown email or a locked account: the server answers all three alike
    /// (anti-enumeration), and so does this.
    InvalidCredentials,
    /// The TOTP or backup code was not accepted.
    WrongCode,
    /// HTTP 429: too many requests from this network. `retry_after_secs` from `Retry-After`.
    RateLimited { retry_after_secs: u64 },
    /// The account was deleted (`account_deleted`); shown only after correct credentials.
    AccountDeleted,
    /// The account has no OPAQUE credential. There is no plaintext fallback.
    OpaqueUnavailable,
    /// No waiting request with that code (wrong, expired or used: one answer).
    RequestNotFound,
    /// Another device already handled the request.
    AlreadyHandled,
    /// The request expired before it was approved.
    Expired,
    /// The approver said no.
    Denied,
    /// The keys arrived but did not decrypt: nothing was signed in.
    KeysDidNotArrive,
    /// The flow was used out of order (a response after it finished, a step skipped).
    WrongState,
    /// Input the flow refuses before sending (empty email, malformed code).
    InvalidInput(&'static str),
    /// Any other server status.
    Server { status: u16 },
    /// The server's answer did not have the expected shape.
    Protocol(&'static str),
}

impl AuthFlowError {
    /// A stable snake_case code for bindings and UI mapping.
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidCredentials => "invalid_credentials",
            Self::WrongCode => "wrong_code",
            Self::RateLimited { .. } => "rate_limited",
            Self::AccountDeleted => "account_deleted",
            Self::OpaqueUnavailable => "opaque_unavailable",
            Self::RequestNotFound => "request_not_found",
            Self::AlreadyHandled => "already_handled",
            Self::Expired => "expired",
            Self::Denied => "denied",
            Self::KeysDidNotArrive => "keys_did_not_arrive",
            Self::WrongState => "wrong_state",
            Self::InvalidInput(_) => "invalid_input",
            Self::Server { .. } => "server",
            Self::Protocol(_) => "protocol",
        }
    }

    /// The common mapping of a non-success status. 401 is the caller's to interpret first.
    pub(crate) fn from_status(resp: &HttpResponse) -> Self {
        if resp.error_code() == Some("account_deleted") {
            return Self::AccountDeleted;
        }
        match resp.status {
            429 => Self::RateLimited {
                retry_after_secs: resp.retry_after_secs.unwrap_or(30),
            },
            401 => Self::InvalidCredentials,
            status => Self::Server { status },
        }
    }
}

impl fmt::Display for AuthFlowError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RateLimited { retry_after_secs } => write!(f, "rate_limited ({retry_after_secs}s)"),
            Self::Server { status } => write!(f, "server ({status})"),
            Self::InvalidInput(why) => write!(f, "invalid_input ({why})"),
            Self::Protocol(why) => write!(f, "protocol ({why})"),
            other => f.write_str(other.code()),
        }
    }
}

impl std::error::Error for AuthFlowError {}

/// A second-factor code as typed: digits only once spaces and dashes are stripped; 6 digits
/// is an authenticator code, 8 a backup code.
pub fn normalize_second_factor_code(input: &str) -> Result<Zeroizing<String>, AuthFlowError> {
    let digits: Zeroizing<String> = Zeroizing::new(input.chars().filter(|c| !c.is_whitespace() && *c != '-').collect());
    let all_digits = digits.chars().all(|c| c.is_ascii_digit());
    if !all_digits || !(digits.len() == 6 || digits.len() == 8) {
        return Err(AuthFlowError::InvalidInput("code must be 6 or 8 digits"));
    }
    Ok(digits)
}

/// A device-approval code as typed (`k7qm 4wtd`, `K7QM-4WTD`) in its canonical `XXXX-XXXX` form.
/// Accepts what the server's `normalize_device_code` accepts (ASCII letters and digits), so the
/// two never disagree about a code's shape.
pub fn normalize_device_code(input: &str) -> Option<String> {
    let chars: Vec<char> = input
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .map(|c| c.to_ascii_uppercase())
        .collect();
    if chars.len() != 8 || !chars.iter().all(|c| c.is_ascii_alphanumeric()) {
        return None;
    }
    let s: String = chars.into_iter().collect();
    Some(format!("{}-{}", &s[..4], &s[4..]))
}
