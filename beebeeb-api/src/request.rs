use std::fmt;

use zeroize::{Zeroize, Zeroizing};

use crate::ApiError;

/// HTTP methods used by the product API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Get,
    Post,
    Put,
    Patch,
    Delete,
}

/// An owned header pair. Header lookup is ASCII-case-insensitive.
#[derive(Clone, PartialEq, Eq)]
pub struct Header {
    pub name: String,
    pub value: String,
}

impl Header {
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
        }
    }
}

/// The headers whose values `Debug` may print. Every other value is
/// `[REDACTED]`: `Authorization`, `Cookie`, `Set-Cookie` (the session cookie
/// on sign-in answers), tokens, passphrases, presigned `Location`s and any
/// header a server adds later (crypto review, P2-6).
const DEBUG_VISIBLE_HEADERS: &[&str] = &[
    "accept",
    "accept-encoding",
    "accept-ranges",
    "cache-control",
    "content-encoding",
    "content-length",
    "content-range",
    "content-type",
    "date",
    "etag",
    "range",
    "retry-after",
    "x-beebeeb-capabilities",
    "x-beebeeb-client",
    "x-beebeeb-client-os",
    "x-beebeeb-client-version",
    "x-request-id",
];

impl Header {
    /// Whether `Debug` may print this header's value (the allow-list above).
    pub fn value_is_printable(&self) -> bool {
        DEBUG_VISIBLE_HEADERS
            .iter()
            .any(|visible| self.name.eq_ignore_ascii_case(visible))
    }
}

impl fmt::Debug for Header {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Header")
            .field("name", &self.name)
            .field(
                "value",
                &if self.value_is_printable() {
                    self.value.as_str()
                } else {
                    "[REDACTED]"
                },
            )
            .finish()
    }
}

/// A complete transport-neutral HTTP request.
#[derive(Clone, PartialEq, Eq)]
pub struct Request {
    method: Method,
    path: String,
    headers: Vec<Header>,
    body: Vec<u8>,
    sensitive_path: bool,
}

impl Request {
    pub fn method(&self) -> Method {
        self.method
    }
    pub fn path(&self) -> &str {
        &self.path
    }
    pub fn headers(&self) -> &[Header] {
        &self.headers
    }
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|header| header.name.eq_ignore_ascii_case(name))
            .map(|header| header.value.as_str())
    }
}

impl Drop for Request {
    fn drop(&mut self) {
        self.body.zeroize();
        if self.sensitive_path {
            self.path.zeroize();
        }
        for header in &mut self.headers {
            if header.name.eq_ignore_ascii_case("authorization")
                || header.name.eq_ignore_ascii_case("x-share-passphrase")
                || header.name.to_ascii_lowercase().contains("token")
            {
                header.value.zeroize();
            }
        }
    }
}

impl fmt::Debug for Request {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Request")
            .field("method", &self.method)
            .field("path", &if self.sensitive_path { "[REDACTED]" } else { &self.path })
            .field("headers", &self.headers)
            .field("body", &format_args!("[REDACTED; {} bytes]", self.body.len()))
            .finish()
    }
}

/// Stable client labels added to every request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientIdentity {
    name: String,
    version: String,
    os: Option<String>,
}

impl ClientIdentity {
    pub fn new(name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            version: version.into(),
            os: None,
        }
    }

    pub fn with_os(mut self, os: impl Into<String>) -> Self {
        self.os = Some(os.into());
        self
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn version(&self) -> &str {
        &self.version
    }

    pub fn os(&self) -> Option<&str> {
        self.os.as_deref()
    }
}

/// The one path through which request descriptions are built.
pub struct RequestBuilder {
    client: ClientIdentity,
    auth_token: Option<Zeroizing<String>>,
    expected_user: Option<String>,
    capabilities: Vec<String>,
    confirmation_token: Option<Zeroizing<String>>,
}

pub(crate) struct RequestParts {
    pub method: Method,
    pub path: String,
    pub body: Vec<u8>,
    pub authenticated: bool,
    pub bearer_only: bool,
    pub send_capabilities: bool,
    pub sensitive_path: bool,
    pub content_type: &'static str,
    pub headers: Vec<Header>,
}

impl fmt::Debug for RequestBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RequestBuilder")
            .field("client", &self.client)
            .field("auth_token", &self.auth_token.as_ref().map(|_| "[REDACTED]"))
            .field("expected_user", &self.expected_user)
            .field("capabilities", &self.capabilities)
            .field(
                "confirmation_token",
                &self.confirmation_token.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

impl RequestBuilder {
    pub fn new(client: ClientIdentity) -> Self {
        Self {
            client,
            auth_token: None,
            expected_user: None,
            capabilities: Vec::new(),
            confirmation_token: None,
        }
    }

    pub fn with_auth(mut self, token: impl Into<String>, expected_user: impl Into<String>) -> Self {
        self.auth_token = Some(Zeroizing::new(token.into()));
        self.expected_user = Some(expected_user.into());
        self
    }

    pub fn with_bearer(mut self, token: impl Into<String>) -> Self {
        self.auth_token = Some(Zeroizing::new(token.into()));
        self.expected_user = None;
        self
    }

    pub fn with_capabilities<I, S>(mut self, capabilities: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.capabilities = capabilities.into_iter().map(Into::into).collect();
        self
    }

    pub fn with_confirmation(mut self, token: impl Into<String>) -> Self {
        self.confirmation_token = Some(Zeroizing::new(token.into()));
        self
    }

    pub(crate) fn build(&self, parts: RequestParts) -> Result<Request, ApiError> {
        validate_header_value(&self.client.name)?;
        validate_header_value(&self.client.version)?;
        let mut headers = vec![
            Header::new("Content-Type", parts.content_type),
            Header::new("X-Beebeeb-Client", self.client.name.clone()),
            Header::new("X-Beebeeb-Client-Version", self.client.version.clone()),
        ];
        if let Some(os) = &self.client.os {
            validate_header_value(os)?;
            headers.push(Header::new("X-Beebeeb-Client-OS", os.clone()));
        }
        if parts.authenticated {
            let token = self.auth_token.as_deref().ok_or(ApiError::MissingAuthentication)?;
            let expected_user = self.expected_user.as_deref().ok_or(ApiError::MissingExpectedUser)?;
            validate_header_value(token)?;
            validate_header_value(expected_user)?;
            headers.push(Header::new("Authorization", format!("Bearer {token}")));
            headers.push(Header::new("X-Beebeeb-Expected-User", expected_user));
        } else if parts.bearer_only {
            let token = self.auth_token.as_deref().ok_or(ApiError::MissingAuthentication)?;
            validate_header_value(token)?;
            headers.push(Header::new("Authorization", format!("Bearer {token}")));
        }
        // Never globally: only the routes whose server behaviour the declaration
        // gates carry it (`Endpoint::capabilities`).
        if parts.send_capabilities && !self.capabilities.is_empty() {
            for capability in &self.capabilities {
                validate_header_value(capability)?;
            }
            headers.push(Header::new("X-Beebeeb-Capabilities", self.capabilities.join(", ")));
        }
        if let Some(token) = self.confirmation_token.as_deref() {
            validate_header_value(token)?;
            headers.push(Header::new("X-Confirm-Token", token));
        }
        for header in parts.headers {
            validate_header_value(&header.name)?;
            validate_header_value(&header.value)?;
            headers.push(header);
        }
        Ok(Request {
            method: parts.method,
            path: parts.path,
            headers,
            body: parts.body,
            sensitive_path: parts.sensitive_path,
        })
    }
}

fn validate_header_value(value: &str) -> Result<(), ApiError> {
    if value.is_empty() || value.bytes().any(|byte| byte < 0x20 || byte == 0x7f) {
        return Err(ApiError::InvalidHeaderValue);
    }
    Ok(())
}

/// Percent-encode one path or query component without changing its bytes.
pub(crate) fn component(value: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(byte));
        } else {
            out.push('%');
            out.push(char::from(HEX[usize::from(byte >> 4)]));
            out.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
    }
    out
}
