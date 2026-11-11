//! The server error body, decoded once (move 7).
//!
//! The HTTP contract is two fields: `{ "error": "<stable code>", "message":
//! "<human text>" }`. Clients today parse it three-and-a-half ways, and the
//! desktop throws the code away entirely. This module retains only typed fields
//! clients use; arbitrary response objects never become loggable state.
//!
//! The decoder mirrors the web client's `parseErrorBody`: prefer `message`,
//! fall back to `error`, and unwrap the double-encoded variant where `error`
//! is itself a JSON-stringified `{ error, message }` object.
//!
//! Two departures are explicit: the account-delete routes put their own
//! refusals' code in `code` and the text in `error`, which
//! [`ServerError::parse_coded_body`] reads; and a delay the server sends only
//! as a `Retry-After` header joins through
//! [`ServerError::with_retry_after_header`].
//!
//! When the body carries no usable text, the raw body is shown instead — but
//! only its first 512 bytes and only after [`crate::direct_transfer::scrub`],
//! because that text is attacker-controlled: it may be a page of HTML or an
//! error string containing a signed storage URL whose query must not be copied
//! into a log, a report or the UI.

use std::fmt;

use beebeeb_types::limits::{MAX_DISPLAY_STRING_BYTES, MAX_SERVER_ERROR_BODY_BYTES};
use serde_json::Value;

/// A decoded server error: the stable code (when the body carried one), the
/// text a user should see, the HTTP status, and the typed fields clients use.
#[derive(Clone, PartialEq)]
pub struct ServerError {
    /// The body's `error` field (a coded route's `code` first:
    /// [`Self::parse_coded_body`]), after unwrapping a double-encoded payload.
    /// `None` when the body was empty, not JSON, or carried no string code.
    pub code: Option<String>,
    /// The body's `message`, else its `error`, else `"<status>: <excerpt>"`
    /// where the excerpt is the body cut to 512 bytes with storage URLs scrubbed.
    pub message: String,
    /// The HTTP status, or 0 for a failure that never got a response.
    pub status: u16,
    retry_after_seconds: Option<u64>,
    trial_cap: bool,
    limit_bytes: Option<u64>,
    used_bytes: Option<u64>,
}

impl fmt::Debug for ServerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServerError")
            .field("status", &self.status)
            .field("code", &self.code.as_ref().map(|_| "<redacted>"))
            .field("message", &"<redacted>")
            .field("retry_after_seconds", &self.retry_after_seconds)
            .field("trial_cap", &self.trial_cap)
            .field("limit_bytes", &self.limit_bytes)
            .field("used_bytes", &self.used_bytes)
            .finish()
    }
}

/// The raw-body fallback for [`ServerError::message`]: at most 512 BYTES of the
/// body, cut on a UTF-8 boundary, with [`crate::direct_transfer::scrub`] applied
/// so a signed storage URL (query signature, object key) is not copied onward.
fn body_excerpt(body: &str) -> String {
    let mut end = body.len().min(MAX_DISPLAY_STRING_BYTES);
    while !body.is_char_boundary(end) {
        end -= 1;
    }
    crate::direct_transfer::scrub(&body[..end])
}

fn display_string(value: &str) -> String {
    body_excerpt(value)
}

/// Where a body keeps its stable code.
#[derive(Clone, Copy)]
enum CodeField {
    /// `error`: the server's two-field contract.
    Error,
    /// `code` when it is a string, else `error`: a coded route's refusals.
    CodeThenError,
}

impl ServerError {
    /// Decode one response body. `status` is the HTTP status the body arrived
    /// with; a 200 with an error body still decodes, but
    /// [`Self::status_is_error`] stays false, so the status wins.
    pub fn parse_body(status: u16, body: &str) -> Self {
        Self::decode(status, body, CodeField::Error)
    }

    /// Decode a body from a route whose own refusals put the stable code in `code` and
    /// the text in `error` (`{ "error": "<human text>", "code": "<stable code>" }`: the
    /// account-delete routes). A body without a string `code` decodes as
    /// [`Self::parse_body`] does, so the refusals every route shares
    /// (`confirmation_required`) keep their code.
    pub fn parse_coded_body(status: u16, body: &str) -> Self {
        Self::decode(status, body, CodeField::CodeThenError)
    }

    fn decode(status: u16, body: &str, code_field: CodeField) -> Self {
        let body_fits = body.len() <= MAX_SERVER_ERROR_BODY_BYTES;
        let parsed = body_fits.then(|| serde_json::from_str::<Value>(body).ok()).flatten();
        let object = parsed.as_ref().and_then(Value::as_object);
        let text_field = |name: &str| object.and_then(|object| object.get(name)).and_then(Value::as_str);

        let mut code = match code_field {
            CodeField::Error => text_field("error"),
            CodeField::CodeThenError => text_field("code").or_else(|| text_field("error")),
        }
        .map(display_string);
        let mut message = object
            .and_then(|object| object.get("message").or_else(|| object.get("error")))
            .and_then(Value::as_str)
            .map(display_string);

        // The double-encoded shape: `error` is itself a JSON string holding
        // `{ error, message }` (task 1517's finding). Unwrap it so callers
        // compare the real code, never the serialised object.
        if let Some(inner) = code.as_deref().filter(|code| code.starts_with('{')) {
            if let Ok(inner) = serde_json::from_str::<Value>(inner) {
                if let Some(inner_code) = inner.get("error").and_then(Value::as_str) {
                    code = Some(display_string(inner_code));
                    if let Some(inner_message) = inner.get("message").and_then(Value::as_str) {
                        message = Some(display_string(inner_message));
                    }
                }
            }
        }

        Self {
            code,
            // No field to show: fall back to the raw body, which came from the
            // network and may be arbitrarily long or carry a signed URL.
            message: message.unwrap_or_else(|| format!("{status}: {}", body_excerpt(body))),
            status,
            retry_after_seconds: object
                .and_then(|object| object.get("retry_after"))
                .and_then(|value| {
                    value
                        .as_u64()
                        .or_else(|| value.as_str().and_then(crate::retry::parse_retry_after))
                })
                .map(|seconds| seconds.min(beebeeb_types::limits::MAX_RETRY_AFTER_SECONDS)),
            trial_cap: matches!(
                object.and_then(|object| object.get("is_trial_cap")),
                Some(Value::Bool(true))
            ),
            limit_bytes: object
                .and_then(|object| object.get("limit_bytes"))
                .and_then(Value::as_u64),
            used_bytes: object
                .and_then(|object| object.get("used_bytes"))
                .and_then(Value::as_u64),
        }
    }

    /// Take the delay from a `Retry-After` header when the body named none: the body's
    /// own `retry_after` wins. Delta-seconds only, capped as the body's is.
    pub fn with_retry_after_header(mut self, value: &str) -> Self {
        if self.retry_after_seconds.is_none() {
            self.retry_after_seconds = crate::retry::parse_retry_after(value);
        }
        self
    }

    /// True when the body's code equals `code` exactly (never a substring).
    pub fn is_code(&self, code: &str) -> bool {
        self.code.as_deref() == Some(code)
    }

    /// True for a 4xx/5xx status. A 200 that happens to carry an error body is
    /// not an error by this predicate.
    pub fn status_is_error(&self) -> bool {
        (400..=599).contains(&self.status)
    }

    /// True when the failure means the upload session no longer exists.
    ///
    /// A 404 always means gone on the proxy routes, but a node without the
    /// route also answers 404 on the direct routes, so `a_404_counts` lets the
    /// direct caller say "only a JSON-bodied 404 is the session". A 400 is the
    /// pre-sweep server's wording for the same thing; nothing else counts
    /// (a 409 or a quota error is a real failure, never a reason to re-init).
    pub fn is_session_gone(&self, a_404_counts: bool) -> bool {
        match self.status {
            404 => a_404_counts,
            400 => self.message.contains("upload session is not writable: expired"),
            _ => false,
        }
    }

    /// The body's `retry_after` field, as seconds. Accepts a JSON number or a
    /// digits-only string; anything else is `None`. Without one, the
    /// `Retry-After` header's delay ([`Self::with_retry_after_header`]).
    pub fn retry_after(&self) -> Option<u64> {
        self.retry_after_seconds
    }

    /// True when the body marks this as a trial-cap quota failure.
    pub fn is_trial_cap(&self) -> bool {
        self.trial_cap
    }

    /// The quota ceiling in bytes, when the body carried one.
    pub fn limit_bytes(&self) -> Option<u64> {
        self.limit_bytes
    }

    /// The usage in bytes, when the body carried one.
    pub fn used_bytes(&self) -> Option<u64> {
        self.used_bytes
    }
}

#[cfg(test)]
mod limit_tests {
    use super::*;

    #[test]
    fn parsed_fields_are_scrubbed_capped_and_debug_redacted() {
        let signed_url = "https://storage.example/private/object?X-Amz-Signature=SECRET";
        let body = format!(r#"{{"error":"bad","message":"{}{}"}}"#, signed_url, "x".repeat(2_000));
        let error = ServerError::parse_body(500, &body);
        assert!(!error.message.contains("SECRET"));
        assert!(error.message.len() <= 512);
        let debug = format!("{error:?}");
        assert!(!debug.contains("SECRET"));
        assert!(!debug.contains("private/object"));
    }

    #[test]
    fn oversized_json_is_not_parsed_or_retained() {
        let body = format!(r#"{{"error":"bad","message":"{}"}}"#, "x".repeat(100_000));
        let error = ServerError::parse_body(500, &body);
        assert_eq!(error.code, None);
        assert!(error.message.len() <= 512 + 5);
    }
}

#[cfg(test)]
mod shape_tests {
    use super::*;

    const ALREADY_SCHEDULED: &str = r#"{"code":"delete_already_scheduled","error":"This account is already scheduled for deletion. Cancel that first."}"#;

    #[test]
    fn a_coded_body_takes_its_code_from_code_and_its_text_from_error() {
        let coded = ServerError::parse_coded_body(409, ALREADY_SCHEDULED);
        assert_eq!(coded.code.as_deref(), Some("delete_already_scheduled"));
        assert!(coded.is_code("delete_already_scheduled"));
        assert_eq!(
            coded.message,
            "This account is already scheduled for deletion. Cancel that first."
        );

        let two_field = ServerError::parse_body(409, ALREADY_SCHEDULED);
        assert_eq!(
            two_field.code.as_deref(),
            Some("This account is already scheduled for deletion. Cancel that first."),
            "only a coded route reads `code`"
        );

        let long = format!(r#"{{"code":"{}","error":"refused"}}"#, "c".repeat(2_000));
        let capped = ServerError::parse_coded_body(409, &long);
        assert_eq!(
            capped.code.map(|code| code.len()),
            Some(512),
            "a coded code is capped too"
        );
    }

    #[test]
    fn a_coded_route_keeps_the_code_of_a_body_without_one() {
        let shared = ServerError::parse_coded_body(
            403,
            r#"{"error":"confirmation_required","message":"This action requires password confirmation"}"#,
        );
        assert_eq!(shared.code.as_deref(), Some("confirmation_required"));
        assert_eq!(shared.message, "This action requires password confirmation");
    }

    #[test]
    fn a_retry_after_header_stands_in_for_a_missing_body_field() {
        let rate_limited = r#"{"code":"delete_request_rate_limited","error":"A link was sent less than a minute ago. Check your email, or try again in a minute."}"#;
        let header = ServerError::parse_coded_body(429, rate_limited).with_retry_after_header("60");
        assert_eq!(header.retry_after(), Some(60));

        let body_wins =
            ServerError::parse_body(429, r#"{"error":"server_busy","retry_after":17}"#).with_retry_after_header("60");
        assert_eq!(body_wins.retry_after(), Some(17), "the body's own delay wins");

        let capped = ServerError::parse_body(503, r#"{"error":"busy"}"#).with_retry_after_header(" 99999 ");
        assert_eq!(capped.retry_after(), Some(300), "capped as the body's is");

        let http_date = ServerError::parse_body(503, r#"{"error":"busy"}"#)
            .with_retry_after_header("Wed, 11 Nov 2026 15:00:00 GMT");
        assert_eq!(http_date.retry_after(), None, "delta-seconds only");
    }
}
