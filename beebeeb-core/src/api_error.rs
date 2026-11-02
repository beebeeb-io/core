//! The server error body, decoded once (move 7).
//!
//! The HTTP contract is two fields: `{ "error": "<stable code>", "message":
//! "<human text>" }`. Clients today parse it three-and-a-half ways, and the
//! desktop throws the code away entirely (map §4.2 case 8). This module keeps
//! the whole parsed object in [`ServerError::details`], so a caller can read
//! the code exactly, branch on quota fields (`is_trial_cap`, `limit_bytes`,
//! `used_bytes`), and still see additive fields this version does not know.
//!
//! The decoder mirrors the web client's `parseErrorBody`: prefer `message`,
//! fall back to `error`, and unwrap the double-encoded variant where `error`
//! is itself a JSON-stringified `{ error, message }` object.
//!
//! When the body carries no usable text, the raw body is shown instead — but
//! only its first 512 bytes and only after [`crate::direct_transfer::scrub`],
//! because that text is attacker-controlled: it may be a page of HTML or an
//! error string containing a signed storage URL whose query must not be copied
//! into a log, a report or the UI.

use serde_json::{Map, Value};

/// A decoded server error: the stable code (when the body carried one), the
/// text a user should see, the HTTP status, and the whole parsed body.
#[derive(Debug, Clone, PartialEq)]
pub struct ServerError {
    /// The body's `error` field, after unwrapping a double-encoded payload.
    /// `None` when the body was empty, not JSON, or carried no string `error`.
    pub code: Option<String>,
    /// The body's `message`, else its `error`, else `"<status>: <excerpt>"`
    /// where the excerpt is the body cut to 512 bytes with storage URLs scrubbed.
    pub message: String,
    /// The HTTP status, or 0 for a failure that never got a response.
    pub status: u16,
    /// The parsed body object (empty when the body was empty or not an object).
    pub details: Map<String, Value>,
}

/// The raw-body fallback for [`ServerError::message`]: at most 512 BYTES of the
/// body, cut on a UTF-8 boundary, with [`crate::direct_transfer::scrub`] applied
/// so a signed storage URL (query signature, object key) is not copied onward.
fn body_excerpt(body: &str) -> String {
    const MAX_EXCERPT_BYTES: usize = 512;
    let mut end = body.len().min(MAX_EXCERPT_BYTES);
    while !body.is_char_boundary(end) {
        end -= 1;
    }
    crate::direct_transfer::scrub(&body[..end])
}

impl ServerError {
    /// Decode one response body. `status` is the HTTP status the body arrived
    /// with; a 200 with an error body still decodes, but
    /// [`Self::status_is_error`] stays false, so the status wins.
    pub fn parse_body(status: u16, body: &str) -> Self {
        let parsed = serde_json::from_str::<Value>(body).ok();
        let object = parsed.as_ref().and_then(Value::as_object);

        let mut code = object
            .and_then(|object| object.get("error"))
            .and_then(Value::as_str)
            .map(str::to_string);
        let mut message = object
            .and_then(|object| object.get("message").or_else(|| object.get("error")))
            .and_then(Value::as_str)
            .map(str::to_string);

        // The double-encoded shape: `error` is itself a JSON string holding
        // `{ error, message }` (task 1517's finding). Unwrap it so callers
        // compare the real code, never the serialised object.
        if let Some(inner) = code.as_deref().filter(|code| code.starts_with('{')) {
            if let Ok(inner) = serde_json::from_str::<Value>(inner) {
                if let Some(inner_code) = inner.get("error").and_then(Value::as_str) {
                    code = Some(inner_code.to_string());
                    if let Some(inner_message) = inner.get("message").and_then(Value::as_str) {
                        message = Some(inner_message.to_string());
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
            details: object.cloned().unwrap_or_default(),
        }
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
    /// digits-only string; anything else is `None`.
    pub fn retry_after(&self) -> Option<u64> {
        self.details.get("retry_after").and_then(|value| {
            value
                .as_u64()
                .or_else(|| value.as_str().and_then(crate::retry::parse_retry_after))
        })
    }

    /// True when the body marks this as a trial-cap quota failure.
    pub fn is_trial_cap(&self) -> bool {
        matches!(self.details.get("is_trial_cap"), Some(Value::Bool(true)))
    }

    /// The quota ceiling in bytes, when the body carried one.
    pub fn limit_bytes(&self) -> Option<u64> {
        self.details.get("limit_bytes").and_then(Value::as_u64)
    }

    /// The usage in bytes, when the body carried one.
    pub fn used_bytes(&self) -> Option<u64> {
        self.details.get("used_bytes").and_then(Value::as_u64)
    }
}
