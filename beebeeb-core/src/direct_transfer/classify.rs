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
    /// `GET /api/v1/files/{id}/chunks/{index}?object_version_id=<pin>`: one chunk of the pinned
    /// version through the API (the fallback for a chunk storage could not give). Its answers are
    /// NOT the grant route's: a gone version is a 409 whose body is a sentence, not a code.
    PinnedChunk,
    /// `POST /api/v1/uploads/{session}/chunks/{index}/grant` (upload; spec "Upload: direct session").
    UploadGrant,
    /// `POST /api/v1/uploads/{session}/chunks/{index}/commit`: the staged chunk is verified,
    /// copied to its real key and recorded.
    UploadCommit,
}

impl Call {
    /// Stable machine name (bindings and vectors).
    pub fn code(self) -> &'static str {
        match self {
            Call::Discovery => "discovery",
            Call::DownloadGrant => "download_grant",
            Call::PinnedChunk => "pinned_chunk",
            Call::UploadGrant => "upload_grant",
            Call::UploadCommit => "upload_commit",
        }
    }

    /// The inverse of [`Call::code`].
    pub fn from_code(code: &str) -> Option<Call> {
        match code {
            "discovery" => Some(Call::Discovery),
            "download_grant" => Some(Call::DownloadGrant),
            "pinned_chunk" => Some(Call::PinnedChunk),
            "upload_grant" => Some(Call::UploadGrant),
            "upload_commit" => Some(Call::UploadCommit),
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
        self.stated_wait().unwrap_or(DEFAULT_RETRY_AFTER)
    }

    /// The server's `Retry-After`, when it sent one, clamped to 1 s ..= [`MAX_RETRY_AFTER`].
    fn stated_wait(&self) -> Option<Duration> {
        self.retry_after
            .map(|d| d.clamp(Duration::from_secs(1), MAX_RETRY_AFTER))
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
    /// trust period ([`DISCOVERY_TTL_MS`](super::DISCOVERY_TTL_MS)); use the API.
    NotSupported,
    /// No direct transport right now (bare 404/405, 5xx, redirect, network
    /// failure, anything unrecognised): use the API for this file now and ask
    /// discovery again later, at most once per command. (The upload calls never
    /// answer this: see [`Outcome::ApiForThisFile`].)
    UseApiNow,
    /// This file is served over the API (`direct_unavailable`, an unknown 409
    /// or other 4xx): today's path. **For an UPLOAD call it means this SESSION cannot go
    /// direct**: its transport never changes after init, so abandon the session and init
    /// again WITHOUT the capability token. A bare 404/405, a 1xx/3xx, `direct_unavailable`,
    /// `transport_mismatch` and any unknown 409 or 4xx are all this on `UploadGrant` and
    /// `UploadCommit`.
    ApiForThisFile,
    /// `version_unavailable`: the pinned version is gone. Discard what was
    /// fetched and restart from fresh metadata. Never mix versions.
    Restart,
    /// 429, or 409 `replace_in_progress` / `commit_in_progress` on a DOWNLOAD call: wait this
    /// long, then ask again (the planner gives up after a bounded number). On an upload call
    /// it is a counted wait (a 429, a 5xx that states one); the commit lock is [`Outcome::Held`].
    Backoff(Duration),
    /// 401, 403, or a JSON 404: an authorization answer, not a routing one.
    /// The API path would refuse too; do not fall back.
    Terminal(Terminal),
    /// `PinnedChunk`, `UploadGrant`, `UploadCommit`: a failure that may pass (5xx, a node without
    /// the route, no answer). Try again after the client's own bounded backoff
    /// ([`PinnedRetry`], [`UploadChunkState`](super::upload::UploadChunkState)).
    Retry,
    /// `UploadCommit` only (409 `chunk_not_stored`): the staged object is not there, or has the
    /// wrong length. Nothing was committed: ask for a new link and send the chunk again.
    Regrant,
    /// `UploadCommit` only (409 `commit_in_progress`): the server holds this chunk's commit lock. After
    /// a copy that failed, the lock lives its whole TTL
    /// ([`COMMIT_LOCK_TTL`](super::upload::COMMIT_LOCK_TTL), 420 s), so this can last minutes: it is a
    /// wait with its own allowance, not a counted failure
    /// ([`UploadChunkState`](super::upload::UploadChunkState)). The duration is the server's
    /// `Retry-After` when it sent one (clamped like any stated wait), `None` when it did not.
    ///
    /// The server (30c8ed62) also answers `commit_in_progress` when the lock is ALREADY released, if
    /// the record's in-lock HEAD could not tell (R3.4, `routes/direct_transfer.rs:1123`): on slow
    /// storage every poll of that case re-copies the chunk. A server that states those transient
    /// failures as a `503` with `Retry-After` (a counted wait) and keeps `commit_in_progress` for the
    /// lock alone removes the ambiguity; until then the allowance is also the bound on that case.
    Held(Option<Duration>),
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
            Outcome::Retry => "retry",
            Outcome::Regrant => "regrant",
            Outcome::Held(_) => "held",
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
        // Upload: the session's transport never changes, so everything that means "this session
        // cannot go direct" (a node without the route, `direct_unavailable`, `transport_mismatch`,
        // any 409 or 4xx we do not know) is `ApiForThisFile`: abandon the session and init again
        // WITHOUT the capability token (spec, "Transport exclusivity"; R1.6).
        Call::UploadGrant | Call::UploadCommit => match status {
            401 | 403 => terminal(),
            // A JSON 404 is the session (or file) being gone: the caller's session recovery owns it.
            404 if answer.has_json_error() => terminal(),
            // A bare 404/405 is a node (or proxy) without the route (R1.6): this session cannot go direct.
            404 | 405 => Outcome::ApiForThisFile,
            409 => match answer.error_code() {
                // R2.6/R3.1: another commit of this chunk holds the lock, or a copy that failed leaves it
                // held for its whole TTL. Only the COMMIT route sends it: a wait with its own allowance
                // ([`Outcome::Held`]); never terminal.
                Some("commit_in_progress") if call == Call::UploadCommit => Outcome::Held(answer.stated_wait()),
                // The grant route never sends it; if one ever does, a short counted wait.
                Some("commit_in_progress") => Outcome::Backoff(answer.wait()),
                // R1.1/R2.5: the staged object is absent or the wrong length. Nothing was committed.
                Some("chunk_not_stored") if call == Call::UploadCommit => Outcome::Regrant,
                // `direct_unavailable` (any reason), `transport_mismatch`, anything else.
                _ => Outcome::ApiForThisFile,
            },
            // The limiter, the per-chunk grant cap (R2.4) and the staging bound: the server states
            // how long. The policy bounds how often.
            429 => Outcome::Backoff(answer.wait()),
            500..=599 if answer.retry_after.is_some() => Outcome::Backoff(answer.wait()),
            500..=599 => Outcome::Retry,
            // 400 (a size the geometry does not allow), 402/413 (quota), 422 …: not an
            // authorization answer. The API path judges the same upload for itself.
            400..=499 => Outcome::ApiForThisFile,
            // 0: no answer at all (a network failure, a timeout): it may pass.
            0 => Outcome::Retry,
            // 1xx, 3xx: nothing we asked for happened, and a redirect or an interim answer is a path that
            // is wrong (a proxy, a captive portal), not a fault that passes: this session cannot go
            // direct (spec R1.6), like every other answer of this arm that is not worth another try.
            _ => Outcome::ApiForThisFile,
        },
        Call::PinnedChunk => match status {
            401 | 403 => terminal(),
            404 if answer.has_json_error() => terminal(),
            // A bare 404/405 is a node (or proxy) without the route; it may pass.
            404 | 405 => Outcome::Retry,
            409 => match answer.error_code() {
                // Another operation holds the file for a moment (the server sends this on the
                // UNPINNED branch only, but the contract allows it here): wait, ask again.
                Some("replace_in_progress" | "commit_in_progress") => Outcome::Backoff(answer.wait()),
                // Any other 409 means the pin is gone. The server's body here is a sentence
                // ("download version unavailable; restart download from fresh metadata"), not
                // the grant route's `version_unavailable` code, so the STATUS is the contract.
                _ => Outcome::Restart,
            },
            429 => Outcome::Backoff(answer.wait()),
            // A 5xx may say how long it needs (the server's 503 sends `Retry-After: 5`): then that
            // is a stated wait, the same as for a 429. Without it, the client's own backoff.
            500..=599 if answer.retry_after.is_some() => Outcome::Backoff(answer.wait()),
            500..=599 => Outcome::Retry,
            // 400 (an index out of range), 410, 413, 422 …: a retry will not change it. The
            // API stream serves the file.
            400..=499 => Outcome::ApiForThisFile,
            // 0 (no answer), 1xx, 3xx.
            _ => Outcome::Retry,
        },
    }
}

/// How hard a client tries the pinned per-chunk route before the file goes to the API stream.
/// Grants and this route share the per-user rate limiter server-side and a download that has
/// fallen back to it fetches several chunks at a time, so a 429 is likely and one must not cost
/// the whole transfer. One policy for every client: ask [`PinnedRetry::decide`] after each failed
/// attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PinnedRetry {
    /// Attempts in all, the first one included.
    pub attempts: u32,
    /// The most the retries may wait in total; a wait that would pass it ends them. It must hold the
    /// longest wait a server can state ([`MAX_RETRY_AFTER`], 120 s) plus a margin: the server's real
    /// 429 on `/api/v1/files/*` says `Retry-After: 60`, so a budget of 60 s would give up on a second
    /// 429, or on any stated wait that follows an earlier one, and restart the whole file.
    pub budget: Duration,
    /// The wait before the second attempt when the server named none; it doubles each time.
    pub base: Duration,
}

impl Default for PinnedRetry {
    fn default() -> Self {
        PinnedRetry {
            attempts: 4,
            budget: Duration::from_secs(150),
            base: Duration::from_secs(1),
        }
    }
}

/// What to do after a failed attempt on the pinned route.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryDecision {
    /// Wait this long, then try again.
    Wait(Duration),
    /// Stop: hand the file to the API stream (or, for `Restart` / `Terminal`, act on that verdict).
    GiveUp,
}

impl RetryDecision {
    /// Stable machine name (bindings and vectors).
    pub fn kind(&self) -> &'static str {
        match self {
            RetryDecision::Wait(_) => "wait",
            RetryDecision::GiveUp => "give_up",
        }
    }
}

impl PinnedRetry {
    /// `attempt` is the 1-based number of the attempt that just failed with `outcome`
    /// ([`classify`] of [`Call::PinnedChunk`]; `0` is read as `1`, the first attempt); `waited` is
    /// the total wait so far. Only [`Outcome::Backoff`] (the server's own wait) and
    /// [`Outcome::Retry`] (base, 2 x base, 4 x base …) are worth another try, and only while the
    /// attempts and the time budget last.
    pub fn decide(&self, attempt: u32, waited: Duration, outcome: &Outcome) -> RetryDecision {
        let attempt = attempt.max(1);
        let wait = match outcome {
            Outcome::Backoff(d) => *d,
            Outcome::Retry => self.base.saturating_mul(2u32.saturating_pow(attempt - 1)),
            _ => return RetryDecision::GiveUp,
        };
        if attempt >= self.attempts || waited.saturating_add(wait) > self.budget {
            RetryDecision::GiveUp
        } else {
            RetryDecision::Wait(wait)
        }
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
        for (call, code) in [
            (Call::Discovery, "discovery"),
            (Call::DownloadGrant, "download_grant"),
            (Call::PinnedChunk, "pinned_chunk"),
        ] {
            assert_eq!(call.code(), code);
            assert_eq!(Call::from_code(code), Some(call));
        }
        assert_eq!(Call::from_code("Discovery"), None);
        assert_eq!(Call::from_code(""), None);
    }

    // ── the pinned per-chunk route (PinnedChunk) ──

    /// What the server's pinned chunk route says for a version that is gone
    /// (`version_download.rs::unavailable`), as `{"error": <this>}`.
    const GONE_VERSION: &str = "download version unavailable; restart download from fresh metadata";

    fn pinned(status: u16, body: &str, retry_after: Option<&str>) -> Outcome {
        classify(
            Call::PinnedChunk,
            &ApiAnswer::from_parts(status, JSON, body.as_bytes(), retry_after),
        )
    }

    #[test]
    fn the_pinned_route_reads_its_own_answers() {
        // A gone pin is a 409 whose body is a sentence; the status is the contract.
        let real = format!(r#"{{"error":"{GONE_VERSION}"}}"#);
        assert_eq!(pinned(409, &real, None), Outcome::Restart);
        assert_eq!(pinned(409, "", None), Outcome::Restart, "a bare 409");
        assert_eq!(
            pinned(409, r#"{"error":"version_unavailable"}"#, None),
            Outcome::Restart
        );
        assert_eq!(pinned(409, r#"{"error":"anything new"}"#, None), Outcome::Restart);
        // Only "held" is a wait.
        assert_eq!(
            pinned(409, r#"{"error":"replace_in_progress"}"#, Some("3")),
            Outcome::Backoff(secs(3))
        );
        assert_eq!(
            pinned(409, r#"{"error":"commit_in_progress"}"#, None),
            Outcome::Backoff(DEFAULT_RETRY_AFTER)
        );
        assert_eq!(
            pinned(429, r#"{"error":"server_busy"}"#, Some("7")),
            Outcome::Backoff(secs(7))
        );
        assert_eq!(pinned(429, "", Some("100000")), Outcome::Backoff(MAX_RETRY_AFTER));
        // Server trouble may pass.
        for status in [0, 500, 502, 503, 504, 302] {
            assert_eq!(pinned(status, "", None), Outcome::Retry, "{status}");
        }
        // ... but a 5xx that names its wait is a stated wait (clamped like any other).
        assert_eq!(pinned(503, "", Some("5")), Outcome::Backoff(secs(5)));
        assert_eq!(pinned(500, "", Some("0")), Outcome::Backoff(secs(1)));
        assert_eq!(pinned(502, "", Some("86400")), Outcome::Backoff(MAX_RETRY_AFTER));
        assert_eq!(
            pinned(503, "", Some("soon")),
            Outcome::Retry,
            "an unreadable Retry-After names nothing"
        );
        assert_eq!(
            classify(Call::PinnedChunk, &ApiAnswer::from_parts(404, None, b"", None)),
            Outcome::Retry,
            "a bare 404 is a node without the route"
        );
        // An authorization answer is final; so is a refusal a retry cannot change.
        assert_eq!(
            pinned(401, r#"{"error":"unauthorized"}"#, None),
            terminal(401, Some("unauthorized"))
        );
        assert_eq!(
            pinned(403, r#"{"error":"forbidden"}"#, None),
            terminal(403, Some("forbidden"))
        );
        assert_eq!(
            pinned(404, r#"{"error":"not found"}"#, None),
            terminal(404, Some("not found"))
        );
        for status in [400, 410, 413, 422] {
            assert_eq!(pinned(status, "", None), Outcome::ApiForThisFile, "{status}");
        }
        assert_eq!(pinned(200, "", None), Outcome::Proceed);
    }

    #[test]
    fn the_retry_policy_is_bounded_in_attempts_and_in_waiting() {
        let policy = PinnedRetry::default();
        let none = Duration::ZERO;
        // What the server did not name doubles: 1 s, 2 s, 4 s, then the attempts are spent.
        assert_eq!(policy.decide(1, none, &Outcome::Retry), RetryDecision::Wait(secs(1)));
        assert_eq!(policy.decide(2, secs(1), &Outcome::Retry), RetryDecision::Wait(secs(2)));
        assert_eq!(policy.decide(3, secs(3), &Outcome::Retry), RetryDecision::Wait(secs(4)));
        assert_eq!(policy.decide(4, secs(7), &Outcome::Retry), RetryDecision::GiveUp);
        // The server's real 429 on /api/v1/files/* says `Retry-After: 60`: waited for at attempt 1
        // (nothing waited yet) and at attempt 2 (1 s waited), and again for a second 429.
        let limited = Outcome::Backoff(secs(60));
        assert_eq!(policy.decide(1, none, &limited), RetryDecision::Wait(secs(60)));
        assert_eq!(policy.decide(2, secs(1), &limited), RetryDecision::Wait(secs(60)));
        assert_eq!(policy.decide(2, secs(60), &limited), RetryDecision::Wait(secs(60)));
        // A ban (clamped to 120 s) is waited for once; a third wait of 60 s (180 s in all) is not.
        assert_eq!(
            policy.decide(1, none, &Outcome::Backoff(secs(120))),
            RetryDecision::Wait(secs(120))
        );
        assert_eq!(policy.decide(3, secs(120), &limited), RetryDecision::GiveUp);
        // The budget (150 s in all) is taken up to and including its last second, not beyond.
        assert_eq!(
            policy.decide(2, secs(90), &Outcome::Backoff(secs(60))),
            RetryDecision::Wait(secs(60))
        );
        assert_eq!(policy.decide(2, secs(91), &limited), RetryDecision::GiveUp);
        assert!(
            policy.budget >= MAX_RETRY_AFTER + secs(30),
            "room for the longest stated wait"
        );
        // `attempt == 0` is read as the first attempt, not as an underflow.
        assert_eq!(
            policy.decide(0, none, &Outcome::Retry),
            policy.decide(1, none, &Outcome::Retry)
        );
        assert_eq!(policy.decide(0, none, &limited), policy.decide(1, none, &limited));
        // Nothing else is worth another try.
        for outcome in [
            Outcome::Proceed,
            Outcome::Restart,
            Outcome::ApiForThisFile,
            Outcome::UseApiNow,
            terminal(403, None),
        ] {
            assert_eq!(policy.decide(1, none, &outcome), RetryDecision::GiveUp, "{outcome:?}");
        }
        // The doubling cannot overflow.
        assert_eq!(policy.decide(u32::MAX, none, &Outcome::Retry), RetryDecision::GiveUp);
    }

    #[test]
    fn the_upload_calls_are_classified_for_a_session_that_cannot_change_transport() {
        use Call::{UploadCommit, UploadGrant};
        let bare404 = ApiAnswer::from_parts(404, None, b"", None);
        let rows: Vec<(&str, Call, ApiAnswer, Outcome)> = vec![
            ("grant 200", UploadGrant, json(200, "{}"), Outcome::Proceed),
            ("commit 200", UploadCommit, json(200, "{}"), Outcome::Proceed),
            (
                "a bare 404 is a node without the route (R1.6)",
                UploadGrant,
                bare404.clone(),
                Outcome::ApiForThisFile,
            ),
            (
                "a bare 404 on commit too",
                UploadCommit,
                bare404,
                Outcome::ApiForThisFile,
            ),
            (
                "a JSON 404 is the session being gone",
                UploadCommit,
                json(404, r#"{"error":"not found"}"#),
                terminal(404, Some("not found")),
            ),
            (
                "401",
                UploadGrant,
                json(401, r#"{"error":"unauthorized"}"#),
                terminal(401, Some("unauthorized")),
            ),
            (
                "direct_unavailable: the session cannot go direct",
                UploadGrant,
                json(409, r#"{"error":"direct_unavailable","reason":"disabled"}"#),
                Outcome::ApiForThisFile,
            ),
            (
                "transport_mismatch",
                UploadCommit,
                json(409, r#"{"error":"transport_mismatch"}"#),
                Outcome::ApiForThisFile,
            ),
            (
                "commit_in_progress is a hold with its own allowance (R2.6, R3.1)",
                UploadCommit,
                json(409, r#"{"error":"commit_in_progress"}"#),
                Outcome::Held(None),
            ),
            (
                "a stated wait on a hold is kept, clamped like any other",
                UploadCommit,
                ApiAnswer::from_parts(409, JSON, br#"{"error":"commit_in_progress"}"#, Some("3")),
                Outcome::Held(Some(secs(3))),
            ),
            (
                "a hold that states an hour is clamped",
                UploadCommit,
                ApiAnswer::from_parts(409, JSON, br#"{"error":"commit_in_progress"}"#, Some("3600")),
                Outcome::Held(Some(MAX_RETRY_AFTER)),
            ),
            (
                "the grant route never sends commit_in_progress; if one does it is a counted wait",
                UploadGrant,
                json(409, r#"{"error":"commit_in_progress"}"#),
                Outcome::Backoff(DEFAULT_RETRY_AFTER),
            ),
            (
                "chunk_not_stored on commit: grant again",
                UploadCommit,
                json(409, r#"{"error":"chunk_not_stored"}"#),
                Outcome::Regrant,
            ),
            (
                "chunk_not_stored on a grant is nothing the server says there",
                UploadGrant,
                json(409, r#"{"error":"chunk_not_stored"}"#),
                Outcome::ApiForThisFile,
            ),
            (
                "429 states its wait",
                UploadGrant,
                ApiAnswer::from_parts(429, JSON, br#"{"error":"rate_limited"}"#, Some("60")),
                Outcome::Backoff(secs(60)),
            ),
            (
                "a 5xx may pass",
                UploadCommit,
                json(500, r#"{"error":"Something went wrong."}"#),
                Outcome::Retry,
            ),
            (
                "a 503 that states its wait",
                UploadGrant,
                ApiAnswer::from_parts(503, JSON, b"{}", Some("5")),
                Outcome::Backoff(secs(5)),
            ),
            (
                "no answer may pass",
                UploadGrant,
                ApiAnswer::no_answer(),
                Outcome::Retry,
            ),
            (
                "a redirect is a path that is wrong, not a fault that passes",
                UploadGrant,
                ApiAnswer::from_parts(302, None, b"", None),
                Outcome::ApiForThisFile,
            ),
            (
                "an interim answer on a commit likewise",
                UploadCommit,
                ApiAnswer::from_parts(100, None, b"", None),
                Outcome::ApiForThisFile,
            ),
            (
                "a 4xx the API judges for itself",
                UploadGrant,
                json(413, r#"{"error":"quota_exceeded"}"#),
                Outcome::ApiForThisFile,
            ),
        ];
        for (what, call, answer, want) in rows {
            assert_eq!(classify(call, &answer), want, "{what}");
        }
        assert_eq!(Call::from_code("upload_grant"), Some(Call::UploadGrant));
        assert_eq!(Call::from_code("upload_commit"), Some(Call::UploadCommit));
        assert_eq!(Call::UploadCommit.code(), "upload_commit");
        assert_eq!(Outcome::Regrant.kind(), "regrant");
        assert_eq!(Outcome::Held(None).kind(), "held");
    }
}
