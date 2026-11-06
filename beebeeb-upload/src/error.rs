//! Error types for the upload protocol.

use std::fmt;

use serde::de::DeserializeOwned;

/// Errors that can occur during file upload.
#[derive(Debug)]
pub enum UploadError {
    /// Network-level error (DNS, connection refused, timeout).
    Network(String),

    /// Server returned 5xx — retryable.
    ServerError { status: u16, message: String },

    /// Server returned 4xx — NOT retryable (bad request, auth, etc).
    ClientError { status: u16, message: String },

    /// Server returned 429 — rate limited. Retry after the given seconds.
    RateLimited { retry_after_secs: u64 },

    /// Filesystem I/O error (chunk file missing, permission denied).
    IoError(String),

    /// Response body could not be parsed.
    InvalidResponse(String),

    /// Invalid input parameters.
    InvalidInput(String),

    /// A valid storage frame is too large for this constrained context. File
    /// Providers should hand the operation to the main app and retry there.
    TooLargeForContext { frame_size: u64, context_limit: u64 },

    /// Maximum retry attempts exhausted.
    MaxRetriesExhausted { attempts: u32, last_error: String },
}

impl fmt::Display for UploadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Network(msg) => write!(f, "network error: {msg}"),
            Self::ServerError { status, message } => {
                write!(f, "server error (HTTP {status}): {message}")
            }
            Self::ClientError { status, message } => {
                write!(f, "client error (HTTP {status}): {message}")
            }
            Self::RateLimited { retry_after_secs } => {
                write!(f, "rate limited — retry after {retry_after_secs}s")
            }
            Self::IoError(msg) => write!(f, "I/O error: {msg}"),
            Self::InvalidResponse(msg) => write!(f, "invalid response: {msg}"),
            Self::InvalidInput(msg) => write!(f, "invalid input: {msg}"),
            Self::TooLargeForContext {
                frame_size,
                context_limit,
            } => write!(
                f,
                "valid frame size {frame_size} exceeds this context's {context_limit}-byte limit; hand off to the main app"
            ),
            Self::MaxRetriesExhausted { attempts, last_error } => {
                write!(f, "max retries exhausted ({attempts} attempts): {last_error}")
            }
        }
    }
}

impl std::error::Error for UploadError {}

impl UploadError {
    /// Whether this error is retryable (server errors and rate limits).
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::Network(_) | Self::ServerError { .. } | Self::RateLimited { .. }
        )
    }

    /// If this is a rate-limit error, return the retry-after duration.
    pub fn retry_after(&self) -> Option<std::time::Duration> {
        match self {
            Self::RateLimited { retry_after_secs } => Some(std::time::Duration::from_secs(
                (*retry_after_secs).min(beebeeb_types::limits::MAX_RETRY_AFTER_SECONDS),
            )),
            _ => None,
        }
    }
}

pub(crate) async fn read_server_error(mut response: reqwest::Response) -> beebeeb_core::api_error::ServerError {
    let status = response.status().as_u16();
    let limit = beebeeb_types::limits::MAX_SERVER_ERROR_BODY_BYTES;
    let mut body = Vec::new();
    while body.len() <= limit {
        match response.chunk().await {
            Ok(Some(bytes)) => {
                let remaining = limit.saturating_add(1).saturating_sub(body.len());
                body.extend_from_slice(&bytes[..bytes.len().min(remaining)]);
                if body.len() > limit {
                    break;
                }
            }
            Ok(None) | Err(_) => break,
        }
    }
    let body = String::from_utf8_lossy(&body);
    beebeeb_core::api_error::ServerError::parse_body(status, &body)
}

pub(crate) fn check_response_headers(response: &reqwest::Response) -> Result<(), UploadError> {
    let mut total = 0usize;
    for (name, value) in response.headers() {
        total = total
            .checked_add(name.as_str().len())
            .and_then(|size| size.checked_add(value.as_bytes().len()))
            .ok_or_else(|| UploadError::InvalidResponse("response header size overflow".into()))?;
        if total > beebeeb_types::limits::MAX_RESPONSE_HEADER_BYTES {
            return Err(UploadError::InvalidResponse(format!(
                "response headers exceed the maximum {} bytes",
                beebeeb_types::limits::MAX_RESPONSE_HEADER_BYTES
            )));
        }
    }
    Ok(())
}

pub(crate) async fn read_json<T: DeserializeOwned>(mut response: reqwest::Response) -> Result<T, UploadError> {
    let limit = beebeeb_types::limits::MAX_JSON_BODY_BYTES;
    let mut body = Vec::new();
    while let Some(bytes) = response
        .chunk()
        .await
        .map_err(|error| UploadError::Network(format!("reading JSON response: {error}")))?
    {
        if body.len().saturating_add(bytes.len()) > limit {
            return Err(UploadError::InvalidResponse(format!(
                "JSON response exceeds the maximum {limit} bytes"
            )));
        }
        body.extend_from_slice(&bytes);
    }
    serde_json::from_slice(&body).map_err(|error| UploadError::InvalidResponse(error.to_string()))
}
