use std::marker::PhantomData;

use beebeeb_core::api_error::ServerError;
use serde::{Serialize, de::DeserializeOwned};
use zeroize::Zeroize;

use crate::{Answer, ApiError, Header, Method, Request, RequestBuilder, request::RequestParts};

const DEFAULT_REQUEST_LIMIT: usize = 1024 * 1024;
const DEFAULT_RESPONSE_LIMIT: usize = 4 * 1024 * 1024;

/// A typed JSON endpoint.
pub struct Endpoint<Req, Res> {
    method: Method,
    path: String,
    authenticated: bool,
    bearer_only: bool,
    capabilities: bool,
    sensitive_path: bool,
    has_body: bool,
    raw_body: bool,
    coded_refusals: bool,
    step_up: bool,
    headers: Vec<Header>,
    max_request_bytes: usize,
    max_response_bytes: usize,
    marker: PhantomData<fn(Req) -> Res>,
}

impl<Req, Res> Endpoint<Req, Res> {
    pub(crate) fn new(method: Method, path: impl Into<String>, has_body: bool) -> Self {
        Self {
            method,
            path: path.into(),
            authenticated: true,
            bearer_only: false,
            capabilities: false,
            sensitive_path: false,
            has_body,
            raw_body: false,
            coded_refusals: false,
            step_up: false,
            headers: Vec::new(),
            max_request_bytes: DEFAULT_REQUEST_LIMIT,
            max_response_bytes: DEFAULT_RESPONSE_LIMIT,
            marker: PhantomData,
        }
    }

    pub(crate) fn public(mut self) -> Self {
        self.authenticated = false;
        self.bearer_only = false;
        self
    }
    pub(crate) fn bearer(mut self) -> Self {
        self.authenticated = false;
        self.bearer_only = true;
        self
    }
    pub(crate) fn capabilities(mut self) -> Self {
        self.capabilities = true;
        self
    }
    pub(crate) fn sensitive_path(mut self) -> Self {
        self.sensitive_path = true;
        self
    }
    pub(crate) fn raw_body(mut self) -> Self {
        self.raw_body = true;
        self
    }
    /// The route's own refusals put the stable code in `code` and the text in `error`
    /// ([`ServerError::parse_coded_body`]).
    pub(crate) fn coded_refusals(mut self) -> Self {
        self.coded_refusals = true;
        self
    }
    /// A password step-up route: it answers 401 to a refused step-up (a failed proof, or
    /// password checks locked after failed guesses) as it does to a dead session, so its
    /// 401 alone never means the session expired.
    pub(crate) fn step_up(mut self) -> Self {
        self.step_up = true;
        self
    }
    pub(crate) fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push(Header::new(name, value));
        self
    }
    pub(crate) fn limits(mut self, request: usize, response: usize) -> Self {
        self.max_request_bytes = request;
        self.max_response_bytes = response;
        self
    }

    pub fn method(&self) -> Method {
        self.method
    }
    pub fn path(&self) -> &str {
        &self.path
    }
    pub fn max_response_bytes(&self) -> usize {
        self.max_response_bytes
    }
    /// Whether this is a password step-up route ([`Self::step_up`]).
    pub fn is_step_up(&self) -> bool {
        self.step_up
    }
}

impl<Req, Res> Drop for Endpoint<Req, Res> {
    fn drop(&mut self) {
        if self.sensitive_path {
            self.path.zeroize();
        }
        for header in &mut self.headers {
            header.value.zeroize();
        }
    }
}

impl<Req: Serialize, Res> Endpoint<Req, Res> {
    pub fn build(&self, builder: &RequestBuilder, body: &Req) -> Result<Request, ApiError> {
        let body = if self.has_body {
            serde_json::to_vec(body).map_err(|_| ApiError::InvalidJson)?
        } else {
            Vec::new()
        };
        if body.len() > self.max_request_bytes {
            return Err(ApiError::RequestBodyTooLarge {
                limit: self.max_request_bytes,
                actual: body.len(),
            });
        }
        builder.build(RequestParts {
            method: self.method,
            path: self.path.clone(),
            body,
            authenticated: self.authenticated,
            bearer_only: self.bearer_only,
            send_capabilities: self.capabilities,
            sensitive_path: self.sensitive_path,
            content_type: "application/json",
            headers: self.headers.clone(),
        })
    }
}

impl<Req, Res: DeserializeOwned> Endpoint<Req, Res> {
    pub fn parse(&self, answer: Answer) -> Result<Res, ApiError> {
        enforce_limit(&answer, self.max_response_bytes)?;
        if !(200..=299).contains(&answer.status) {
            return Err(api_error(answer, self.coded_refusals));
        }
        let bytes: &[u8] = if answer.body.is_empty() { b"null" } else { &answer.body };
        serde_json::from_slice(bytes).map_err(|_| ApiError::InvalidJson)
    }
}

/// A typed request whose successful answer is raw bounded bytes.
pub struct RawEndpoint<Req>(Endpoint<Req, ()>);

impl<Req> RawEndpoint<Req> {
    pub(crate) fn new(endpoint: Endpoint<Req, ()>) -> Self {
        Self(endpoint)
    }
    pub fn max_response_bytes(&self) -> usize {
        self.0.max_response_bytes
    }
}

impl RawEndpoint<()> {
    pub fn build(&self, builder: &RequestBuilder, _body: &()) -> Result<Request, ApiError> {
        builder.build(RequestParts {
            method: self.0.method,
            path: self.0.path.clone(),
            body: Vec::new(),
            authenticated: self.0.authenticated,
            bearer_only: self.0.bearer_only,
            send_capabilities: self.0.capabilities,
            sensitive_path: self.0.sensitive_path,
            content_type: "application/json",
            headers: self.0.headers.clone(),
        })
    }
}

impl RawEndpoint<Vec<u8>> {
    pub fn build(&self, builder: &RequestBuilder, body: &[u8]) -> Result<Request, ApiError> {
        if body.len() > self.0.max_request_bytes {
            return Err(ApiError::RequestBodyTooLarge {
                limit: self.0.max_request_bytes,
                actual: body.len(),
            });
        }
        let content_type = if self.0.raw_body {
            "application/octet-stream"
        } else {
            "application/json"
        };
        builder.build(RequestParts {
            method: self.0.method,
            path: self.0.path.clone(),
            body: body.to_owned(),
            authenticated: self.0.authenticated,
            bearer_only: self.0.bearer_only,
            send_capabilities: self.0.capabilities,
            sensitive_path: self.0.sensitive_path,
            content_type,
            headers: self.0.headers.clone(),
        })
    }
}

impl<Req> RawEndpoint<Req> {
    pub fn parse(&self, mut answer: Answer) -> Result<Vec<u8>, ApiError> {
        enforce_limit(&answer, self.0.max_response_bytes)?;
        if !(200..=299).contains(&answer.status) {
            return Err(api_error(answer, self.0.coded_refusals));
        }
        Ok(std::mem::take(&mut answer.body))
    }
}

pub(crate) fn enforce_limit(answer: &Answer, limit: usize) -> Result<(), ApiError> {
    if answer.body.len() > limit {
        return Err(ApiError::ResponseTooLarge {
            limit,
            actual: answer.body.len(),
        });
    }
    Ok(())
}

fn server_error(answer: Answer, coded_refusals: bool) -> ServerError {
    let body = String::from_utf8_lossy(&answer.body);
    let error = if coded_refusals {
        ServerError::parse_coded_body(answer.status, &body)
    } else {
        ServerError::parse_body(answer.status, &body)
    };
    match answer
        .headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case("retry-after"))
    {
        Some(header) => error.with_retry_after_header(&header.value),
        None => error,
    }
}

fn api_error(answer: Answer, coded_refusals: bool) -> ApiError {
    if answer.status == 403
        && let Ok(value) = serde_json::from_slice::<serde_json::Value>(&answer.body)
        && value.get("error").and_then(serde_json::Value::as_str) == Some("signup_web_only")
        && let Some(signup_url) = value.get("signup_url").and_then(serde_json::Value::as_str)
        && !signup_url.is_empty()
        && signup_url.len() <= 2048
        && matches!(signup_url.split_once("://"), Some(("http" | "https", _)))
    {
        return ApiError::SignupWebOnly {
            signup_url: signup_url.to_owned(),
        };
    }
    ApiError::Server(server_error(answer, coded_refusals))
}
