//! What an API answer on a discovery or grant call means for the transfer
//! (review amendment R1.6, "mixed-node 404s").
//!
//! The same HTTP status can come from two different servers: axum's
//! unknown-route 404 has an EMPTY body, a real not-found is
//! `{"error": "not found"}`. In a cluster that is mid-rollout a node without the
//! direct routes answers the first, so only a JSON-bodied 404 is a statement
//! about the file. Misreading a bare 404 as terminal would fail a download the
//! API could have served; misreading a real not-found as "no direct transport"
//! costs one extra call, because the API path authorizes again. So the
//! classifier is strict about what counts as JSON: the content type must say
//! so AND the body must be an object with a string `error` field.
//!
//! Pure: the caller makes the request and passes what it saw.

use std::time::Duration;

use serde_json::Value;

/// Retry-After used when the header is missing or not a number of seconds.
pub const DEFAULT_RETRY_AFTER: Duration = Duration::from_secs(5);
/// A server cannot make a client sleep longer than this on one 429.
pub const MAX_RETRY_AFTER: Duration = Duration::from_secs(120);
/// Bytes of a response body worth inspecting; an error object is tiny.
pub const MAX_ERROR_BODY_BYTES: usize = 64 * 1024;

/// Which request the answer belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Call {
    /// `GET /api/v1/transfer/capabilities`.
    Discovery,
    /// `POST /api/v1/files/{id}/download-grants` (first window, later window or renewal).
    DownloadGrant,
}

impl Call {
    /// Stable machine name (bindings and vectors).
    pub fn code(self) -> &'static str {
        match self {
            Call::Discovery => "discovery",
            Call::DownloadGrant => "download_grant",
        }
    }

    /// The inverse of [`Call::code`].
    pub fn from_code(code: &str) -> Option<Call> {
        match code {
            "discovery" => Some(Call::Discovery),
            "download_grant" => Some(Call::DownloadGrant),
            _ => None,
        }
    }
}

/// What the client saw. Build it with [`ApiAnswer::from_parts`] (an HTTP
/// answer) or [`ApiAnswer::no_answer`] (connect failure, timeout, TLS error).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiAnswer {
    /// HTTP status; 0 when there was no HTTP answer.
    pub status: u16,
    /// The body's `error` field, only when the body really is a JSON error object.
    json_error: Option<String>,
    /// Parsed `Retry-After` (delta-seconds form only).
    retry_after: Option<Duration>,
}

impl ApiAnswer {
    /// An HTTP answer. `body` may be truncated at [`MAX_ERROR_BODY_BYTES`].
    pub fn from_parts(status: u16, content_type: Option<&str>, body: &[u8], retry_after: Option<&str>) -> Self {
        let json_error = if is_json_content_type(content_type) && body.len() <= MAX_ERROR_BODY_BYTES {
            json_error_code(body)
        } else {
            None
        };
        let retry_after = retry_after
            .and_then(|v| v.trim().parse::<u64>().ok())
            .map(Duration::from_secs);
        ApiAnswer {
            status,
            json_error,
            retry_after,
        }
    }

    /// The request never produced an HTTP answer.
    pub fn no_answer() -> Self {
        ApiAnswer {
            status: 0,
            json_error: None,
            retry_after: None,
        }
    }

    /// How long to wait before asking again: the server's `Retry-After`, else
    /// [`DEFAULT_RETRY_AFTER`], clamped to 1 s ..= [`MAX_RETRY_AFTER`].
    fn wait(&self) -> Duration {
        self.retry_after
            .unwrap_or(DEFAULT_RETRY_AFTER)
            .clamp(Duration::from_secs(1), MAX_RETRY_AFTER)
    }

    /// `true` when the body is a JSON error object (the answer is about the
    /// request, not about the route).
    pub fn has_json_error(&self) -> bool {
        self.json_error.is_some()
    }

    /// The server's `error` code, shortened and limited to printable ASCII so
    /// it is safe to show in a message.
    pub fn error_code(&self) -> Option<&str> {
        self.json_error.as_deref()
    }
}

fn is_json_content_type(content_type: Option<&str>) -> bool {
    let Some(ct) = content_type else {
        return false;
    };
    let media = ct.split(';').next().unwrap_or("").trim().to_ascii_lowercase();
    media == "application/json" || (media.starts_with("application/") && media.ends_with("+json"))
}

fn json_error_code(body: &[u8]) -> Option<String> {
    let Value::Object(map) = serde_json::from_slice::<Value>(body).ok()? else {
        return None;
    };
    let code = map.get("error")?.as_str()?;
    // Untrusted text that may reach a terminal: printable ASCII, bounded.
    let clean: String = code
        .chars()
        .filter(|c| c.is_ascii_graphic() || *c == ' ')
        .take(64)
        .collect();
    Some(clean)
}

/// A refusal the client must not route around.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Terminal {
    pub status: u16,
    /// The server's `error` code when the body had one.
    pub error: Option<String>,
}

/// What to do next.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Outcome {
    /// 2xx: decode the body and go on.
    Proceed,
    /// Discovery only: this server has no direct transport. Cache that for the
    /// process; use the API.
    NotSupported,
    /// No direct transport right now (bare 404/405, 5xx, redirect, network
    /// failure, anything unrecognised): use the API for this file now and ask
    /// discovery again later, at most once per command.
    UseApiNow,
    /// This file is served over the API (`direct_unavailable`, an unknown 409
    /// or other 4xx): today's path.
    ApiForThisFile,
    /// `version_unavailable`: the pinned version is gone. Discard what was
    /// fetched and restart from fresh metadata. Never mix versions.
    Restart,
    /// 429, or 409 `replace_in_progress` / `commit_in_progress`: wait this
    /// long, then ask again (the planner gives up after a bounded number).
    Backoff(Duration),
    /// 401, 403, or a JSON 404: an authorization answer, not a routing one.
    /// The API path would refuse too; do not fall back.
    Terminal(Terminal),
}

impl Outcome {
    /// Stable machine name of the variant (bindings and vectors).
    pub fn kind(&self) -> &'static str {
        match self {
            Outcome::Proceed => "proceed",
            Outcome::NotSupported => "not_supported",
            Outcome::UseApiNow => "use_api_now",
            Outcome::ApiForThisFile => "api_for_this_file",
            Outcome::Restart => "restart",
            Outcome::Backoff(_) => "backoff",
            Outcome::Terminal(_) => "terminal",
        }
    }
}

/// Classify an answer to `call`.
pub fn classify(call: Call, answer: &ApiAnswer) -> Outcome {
    let status = answer.status;
    if (200..300).contains(&status) {
        return Outcome::Proceed;
    }
    let terminal = || {
        Outcome::Terminal(Terminal {
            status,
            error: answer.json_error.clone(),
        })
    };
    match call {
        Call::Discovery => match status {
            // A real, JSON-bodied 404: the server says it has no such thing.
            404 if answer.has_json_error() => Outcome::NotSupported,
            // 401 means re-authenticate (unchanged behaviour), never a fallback.
            401 | 403 => terminal(),
            // A bare/HTML 404, 405, 429, 5xx, a redirect, no answer: ask again later.
            _ => Outcome::UseApiNow,
        },
        Call::DownloadGrant => match status {
            401 | 403 => terminal(),
            404 if answer.has_json_error() => terminal(),
            404 | 405 => Outcome::UseApiNow,
            409 => match answer.error_code() {
                Some("version_unavailable") => Outcome::Restart,
                // R1.13 / R2.6: another operation holds the file for a moment.
                // Wait and ask again; the planner bounds how often.
                Some("replace_in_progress" | "commit_in_progress") => Outcome::Backoff(answer.wait()),
                // `direct_unavailable`, and any 409 we do not know: the API
                // serves this file.
                _ => Outcome::ApiForThisFile,
            },
            429 => Outcome::Backoff(answer.wait()),
            500..=599 => Outcome::UseApiNow,
            // 400 (bad window), 410, 413, 422 …: not an authorization answer.
            // The API path authorizes and answers for itself.
            400..=499 => Outcome::ApiForThisFile,
            // 0 (no answer), 1xx, 3xx: nothing we asked for happened.
            _ => Outcome::UseApiNow,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const JSON: Option<&str> = Some("application/json");

    fn json(status: u16, body: &str) -> ApiAnswer {
        ApiAnswer::from_parts(status, JSON, body.as_bytes(), None)
    }

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    struct Row {
        what: &'static str,
        call: Call,
        answer: ApiAnswer,
        want: Outcome,
    }

    fn terminal(status: u16, error: Option<&str>) -> Outcome {
        Outcome::Terminal(Terminal {
            status,
            error: error.map(str::to_string),
        })
    }

    #[test]
    fn every_documented_row() {
        use Call::{Discovery, DownloadGrant};
        let html = ApiAnswer::from_parts(502, Some("text/html"), b"<html>Bad Gateway</html>", None);
        let html404 = ApiAnswer::from_parts(404, Some("text/html; charset=utf-8"), b"<h1>Not Found</h1>", None);
        let bare404 = ApiAnswer::from_parts(404, None, b"", None);
        let rows = vec![
            // ── Discovery ──
            Row {
                what: "discovery 200",
                call: Discovery,
                answer: json(200, "{}"),
                want: Outcome::Proceed,
            },
            Row {
                what: "discovery JSON 404 is 'not supported'",
                call: Discovery,
                answer: json(404, r#"{"error":"not found"}"#),
                want: Outcome::NotSupported,
            },
            Row {
                what: "discovery bare 404 (an old server's unknown route)",
                call: Discovery,
                answer: bare404.clone(),
                want: Outcome::UseApiNow,
            },
            Row {
                what: "discovery HTML 404",
                call: Discovery,
                answer: html404.clone(),
                want: Outcome::UseApiNow,
            },
            Row {
                what: "discovery 405",
                call: Discovery,
                answer: ApiAnswer::from_parts(405, None, b"", None),
                want: Outcome::UseApiNow,
            },
            Row {
                what: "discovery 500",
                call: Discovery,
                answer: json(500, r#"{"error":"internal"}"#),
                want: Outcome::UseApiNow,
            },
            Row {
                what: "discovery HTML 502",
                call: Discovery,
                answer: html.clone(),
                want: Outcome::UseApiNow,
            },
            Row {
                what: "discovery 503",
                call: Discovery,
                answer: ApiAnswer::from_parts(503, None, b"", None),
                want: Outcome::UseApiNow,
            },
            Row {
                what: "discovery network failure",
                call: Discovery,
                answer: ApiAnswer::no_answer(),
                want: Outcome::UseApiNow,
            },
            Row {
                what: "discovery 429 does not make the command wait",
                call: Discovery,
                answer: json(429, r#"{"error":"rate_limited"}"#),
                want: Outcome::UseApiNow,
            },
            Row {
                what: "discovery 401 re-authenticates, no fallback",
                call: Discovery,
                answer: json(401, r#"{"error":"unauthorized"}"#),
                want: terminal(401, Some("unauthorized")),
            },
            Row {
                what: "discovery 403",
                call: Discovery,
                answer: json(403, r#"{"error":"forbidden"}"#),
                want: terminal(403, Some("forbidden")),
            },
            // ── Grant: success and terminal ──
            Row {
                what: "grant 200",
                call: DownloadGrant,
                answer: json(200, "{}"),
                want: Outcome::Proceed,
            },
            Row {
                what: "grant 401",
                call: DownloadGrant,
                answer: json(401, r#"{"error":"unauthorized"}"#),
                want: terminal(401, Some("unauthorized")),
            },
            Row {
                what: "grant 403",
                call: DownloadGrant,
                answer: json(403, r#"{"error":"forbidden"}"#),
                want: terminal(403, Some("forbidden")),
            },
            Row {
                what: "grant 403 with a bare body",
                call: DownloadGrant,
                answer: ApiAnswer::from_parts(403, None, b"", None),
                want: terminal(403, None),
            },
            Row {
                what: "grant JSON 404 is a real not-found: terminal",
                call: DownloadGrant,
                answer: json(404, r#"{"error":"not found"}"#),
                want: terminal(404, Some("not found")),
            },
            // ── Grant: mixed-node 404/405 ──
            Row {
                what: "grant bare 404: this node has no route",
                call: DownloadGrant,
                answer: bare404.clone(),
                want: Outcome::UseApiNow,
            },
            Row {
                what: "grant HTML 404",
                call: DownloadGrant,
                answer: html404.clone(),
                want: Outcome::UseApiNow,
            },
            Row {
                what: "grant 405",
                call: DownloadGrant,
                answer: ApiAnswer::from_parts(405, None, b"", None),
                want: Outcome::UseApiNow,
            },
            // ── Grant: 409 ──
            Row {
                what: "409 direct_unavailable",
                call: DownloadGrant,
                answer: json(409, r#"{"error":"direct_unavailable","reason":"disabled"}"#),
                want: Outcome::ApiForThisFile,
            },
            Row {
                what: "409 version_unavailable",
                call: DownloadGrant,
                answer: json(409, r#"{"error":"version_unavailable"}"#),
                want: Outcome::Restart,
            },
            Row {
                what: "409 replace_in_progress",
                call: DownloadGrant,
                answer: json(409, r#"{"error":"replace_in_progress"}"#),
                want: Outcome::Backoff(DEFAULT_RETRY_AFTER),
            },
            Row {
                what: "409 unknown code",
                call: DownloadGrant,
                answer: json(409, r#"{"error":"something_new"}"#),
                want: Outcome::ApiForThisFile,
            },
            Row {
                what: "409 with no JSON body",
                call: DownloadGrant,
                answer: ApiAnswer::from_parts(409, None, b"", None),
                want: Outcome::ApiForThisFile,
            },
            Row {
                what: "409 whose error is not a string",
                call: DownloadGrant,
                answer: json(409, r#"{"error":7}"#),
                want: Outcome::ApiForThisFile,
            },
            // ── Grant: 429 ──
            Row {
                what: "429 with Retry-After",
                call: DownloadGrant,
                answer: ApiAnswer::from_parts(429, JSON, br#"{"error":"rate_limited"}"#, Some("17")),
                want: Outcome::Backoff(secs(17)),
            },
            Row {
                what: "429 without Retry-After",
                call: DownloadGrant,
                answer: json(429, r#"{"error":"rate_limited"}"#),
                want: Outcome::Backoff(DEFAULT_RETRY_AFTER),
            },
            Row {
                what: "429 with an HTTP-date Retry-After",
                call: DownloadGrant,
                answer: ApiAnswer::from_parts(429, JSON, b"{}", Some("Wed, 21 Oct 2026 07:28:00 GMT")),
                want: Outcome::Backoff(DEFAULT_RETRY_AFTER),
            },
            Row {
                what: "429 with Retry-After 0 still waits a second",
                call: DownloadGrant,
                answer: ApiAnswer::from_parts(429, JSON, b"{}", Some("0")),
                want: Outcome::Backoff(secs(1)),
            },
            Row {
                what: "429 with a huge Retry-After is capped",
                call: DownloadGrant,
                answer: ApiAnswer::from_parts(429, JSON, b"{}", Some("86400")),
                want: Outcome::Backoff(MAX_RETRY_AFTER),
            },
            Row {
                what: "429 with a padded Retry-After",
                call: DownloadGrant,
                answer: ApiAnswer::from_parts(429, JSON, b"{}", Some(" 9 ")),
                want: Outcome::Backoff(secs(9)),
            },
            // ── Grant: everything else ──
            Row {
                what: "grant 500",
                call: DownloadGrant,
                answer: json(500, r#"{"error":"internal"}"#),
                want: Outcome::UseApiNow,
            },
            Row {
                what: "grant HTML 502",
                call: DownloadGrant,
                answer: html,
                want: Outcome::UseApiNow,
            },
            Row {
                what: "grant 503",
                call: DownloadGrant,
                answer: ApiAnswer::from_parts(503, None, b"", None),
                want: Outcome::UseApiNow,
            },
            Row {
                what: "grant network failure",
                call: DownloadGrant,
                answer: ApiAnswer::no_answer(),
                want: Outcome::UseApiNow,
            },
            Row {
                what: "grant 302 (redirects are never followed)",
                call: DownloadGrant,
                answer: ApiAnswer::from_parts(302, None, b"", None),
                want: Outcome::UseApiNow,
            },
            Row {
                what: "grant 400 bad window",
                call: DownloadGrant,
                answer: json(400, r#"{"error":"count must be between 1 and 32"}"#),
                want: Outcome::ApiForThisFile,
            },
            Row {
                what: "grant 410",
                call: DownloadGrant,
                answer: json(410, r#"{"error":"gone"}"#),
                want: Outcome::ApiForThisFile,
            },
            Row {
                what: "grant 422",
                call: DownloadGrant,
                answer: json(422, "{}"),
                want: Outcome::ApiForThisFile,
            },
        ];
        for row in rows {
            assert_eq!(classify(row.call, &row.answer), row.want, "{}", row.what);
        }
    }

    #[test]
    fn a_file_held_by_another_operation_is_waited_for_not_given_to_the_api() {
        // R1.13 `replace_in_progress`, R2.6 `commit_in_progress`: bounded Backoff.
        for code in ["replace_in_progress", "commit_in_progress"] {
            let body = format!(r#"{{"error":"{code}"}}"#);
            let a = ApiAnswer::from_parts(409, JSON, body.as_bytes(), None);
            assert_eq!(
                classify(Call::DownloadGrant, &a),
                Outcome::Backoff(DEFAULT_RETRY_AFTER),
                "{code}"
            );
            let with_header = ApiAnswer::from_parts(409, JSON, body.as_bytes(), Some("3"));
            assert_eq!(
                classify(Call::DownloadGrant, &with_header),
                Outcome::Backoff(secs(3)),
                "{code}"
            );
            let huge = ApiAnswer::from_parts(409, JSON, body.as_bytes(), Some("86400"));
            assert_eq!(
                classify(Call::DownloadGrant, &huge),
                Outcome::Backoff(MAX_RETRY_AFTER),
                "{code}"
            );
            let zero = ApiAnswer::from_parts(409, JSON, body.as_bytes(), Some("0"));
            assert_eq!(
                classify(Call::DownloadGrant, &zero),
                Outcome::Backoff(secs(1)),
                "{code}"
            );
        }
        // Only on the strict JSON reading: a bare 409 stays the API's.
        let bare = ApiAnswer::from_parts(409, None, br#"{"error":"replace_in_progress"}"#, None);
        assert_eq!(classify(Call::DownloadGrant, &bare), Outcome::ApiForThisFile);
    }

    #[test]
    fn json_means_content_type_and_an_error_string() {
        // A JSON-looking body under the wrong content type is not JSON for R1.6.
        for ct in [
            None,
            Some("text/html"),
            Some("text/plain"),
            Some("application/octet-stream"),
        ] {
            let a = ApiAnswer::from_parts(404, ct, br#"{"error":"not found"}"#, None);
            assert!(!a.has_json_error(), "{ct:?}");
            assert_eq!(classify(Call::DownloadGrant, &a), Outcome::UseApiNow, "{ct:?}");
        }
        // Content-type forms that are JSON.
        for ct in [
            "application/json",
            "Application/JSON; charset=utf-8",
            "application/problem+json",
        ] {
            assert!(
                ApiAnswer::from_parts(404, Some(ct), br#"{"error":"x"}"#, None).has_json_error(),
                "{ct}"
            );
        }
        // JSON that is not an error object.
        for body in [
            "[]",
            "null",
            "\"error\"",
            r#"{"message":"x"}"#,
            r#"{"error":null}"#,
            "",
            "{",
            r#"{"error":{"a":1}}"#,
        ] {
            let a = ApiAnswer::from_parts(404, JSON, body.as_bytes(), None);
            assert!(!a.has_json_error(), "{body:?}");
            assert_eq!(classify(Call::DownloadGrant, &a), Outcome::UseApiNow, "{body:?}");
        }
        // An oversized body is not inspected.
        let big = format!(r#"{{"error":"x","pad":"{}"}}"#, "a".repeat(MAX_ERROR_BODY_BYTES));
        assert!(!ApiAnswer::from_parts(404, JSON, big.as_bytes(), None).has_json_error());
    }

    #[test]
    fn error_codes_are_safe_to_print() {
        let a = json(403, "{\"error\":\"fo\\u001b[31mrb\\nidden\\u00e9\"}");
        let code = a.error_code().unwrap();
        assert!(code.chars().all(|c| c.is_ascii_graphic() || c == ' '), "{code:?}");
        let long = json(403, &format!(r#"{{"error":"{}"}}"#, "x".repeat(500)));
        assert_eq!(long.error_code().unwrap().len(), 64);
    }

    #[test]
    fn call_codes_are_stable_and_invertible() {
        for (call, code) in [(Call::Discovery, "discovery"), (Call::DownloadGrant, "download_grant")] {
            assert_eq!(call.code(), code);
            assert_eq!(Call::from_code(code), Some(call));
        }
        assert_eq!(Call::from_code("Discovery"), None);
        assert_eq!(Call::from_code(""), None);
    }
}
