//! Error types for the upload protocol.

use std::fmt;

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

    /// Maximum retry attempts exhausted.
    MaxRetriesExhausted {
        attempts: u32,
        last_error: String,
    },
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
            Self::MaxRetriesExhausted {
                attempts,
                last_error,
            } => {
                write!(
                    f,
                    "max retries exhausted ({attempts} attempts): {last_error}"
                )
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
            Self::RateLimited { retry_after_secs } => {
                Some(std::time::Duration::from_secs(*retry_after_secs))
            }
            _ => None,
        }
    }
}
