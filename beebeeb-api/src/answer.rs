use std::fmt;

use beebeeb_core::api_error::ServerError;

use crate::Header;
use zeroize::Zeroize;

/// A transport's complete answer, before route-specific decoding.
#[derive(Clone, PartialEq, Eq)]
pub struct Answer {
    pub status: u16,
    pub headers: Vec<Header>,
    pub body: Vec<u8>,
}

impl Answer {
    pub fn new(status: u16, headers: Vec<Header>, body: Vec<u8>) -> Self {
        Self { status, headers, body }
    }
}

impl Drop for Answer {
    fn drop(&mut self) {
        self.body.zeroize();
    }
}

impl fmt::Debug for Answer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Answer")
            .field("status", &self.status)
            .field("headers", &self.headers)
            .field("body", &format_args!("[REDACTED; {} bytes]", self.body.len()))
            .finish()
    }
}

/// Failures produced before or while decoding an answer.
pub enum ApiError {
    MissingAuthentication,
    MissingExpectedUser,
    InvalidHeaderValue,
    RequestBodyTooLarge { limit: usize, actual: usize },
    ResponseTooLarge { limit: usize, actual: usize },
    InvalidJson,
    SignupWebOnly { signup_url: String },
    Server(ServerError),
}

impl fmt::Debug for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingAuthentication => f.write_str("MissingAuthentication"),
            Self::MissingExpectedUser => f.write_str("MissingExpectedUser"),
            Self::InvalidHeaderValue => f.write_str("InvalidHeaderValue"),
            Self::RequestBodyTooLarge { limit, actual } => f
                .debug_struct("RequestBodyTooLarge")
                .field("limit", limit)
                .field("actual", actual)
                .finish(),
            Self::ResponseTooLarge { limit, actual } => f
                .debug_struct("ResponseTooLarge")
                .field("limit", limit)
                .field("actual", actual)
                .finish(),
            Self::InvalidJson => f.write_str("InvalidJson"),
            Self::SignupWebOnly { .. } => f.write_str("SignupWebOnly"),
            Self::Server(error) => f
                .debug_struct("Server")
                .field("status", &error.status)
                .field("code", &error.code)
                .finish_non_exhaustive(),
        }
    }
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingAuthentication => f.write_str("authentication is required"),
            Self::MissingExpectedUser => f.write_str("the expected account is required"),
            Self::InvalidHeaderValue => f.write_str("a header value is invalid"),
            Self::RequestBodyTooLarge { limit, actual } => {
                write!(f, "request body is {actual} bytes; limit is {limit}")
            }
            Self::ResponseTooLarge { limit, actual } => write!(f, "response body is {actual} bytes; limit is {limit}"),
            Self::InvalidJson => f.write_str("the response is not valid JSON"),
            Self::SignupWebOnly { .. } => f.write_str("account creation is available on the web"),
            Self::Server(error) => write!(f, "server returned status {}", error.status),
        }
    }
}

impl std::error::Error for ApiError {}
