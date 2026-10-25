//! The client rules of the direct upload (`object-upload-v1`): what a client may believe of
//! the server's grant and commit answers, and how hard it tries one chunk before the whole file
//! goes back to the API. Spec "Upload: direct session", binding amendments R1.1, R1.6, R2.4,
//! R2.6 and R3.4; checked against the merged server (#331, `routes/direct_transfer.rs`).
//!
//! Pure, like the rest of [`super`]: the caller makes the requests and passes what it saw.
//!
//! One chunk, in the order the caller does it:
//!
//! 1. `POST .../grant {"size"}` -> [`classify`](super::classify) with [`Call::UploadGrant`]; on
//!    `Proceed`, [`UploadGrant::from_answer`] decodes and validates the body. A `Link` is
//!    followed; `Skipped` means the chunk is already committed (R1.1, write-once): there is
//!    nothing to send.
//! 2. `PUT link` with exactly the chunk's ciphertext and `content-type` as granted, on the
//!    separate storage client. Any 2xx is stored ([`put_stored`]).
//! 3. `POST .../commit {"size"}` -> [`classify`](super::classify) with [`Call::UploadCommit`]; on
//!    `Proceed`, [`UploadCommitted::from_answer`] checks the echo.
//!
//! After any failure the caller asks [`UploadChunkState::failed`] what to do next. The session's
//! transport never changes after init, so "this session cannot go direct" is always the same
//! answer, [`UploadNext::UseApi`]: abandon the session and init again WITHOUT the capability token.

use std::fmt;
use std::time::Duration;

use super::authority::{Refusal, check_storage_url, redact};
use super::classify::{Call, Outcome, Terminal};
use super::wire::{CAP_OBJECT_UPLOAD_V1, Discovery, UploadCommitResponse, UploadGrantResponse};

/// `content-type` of a staged chunk. The server signs it into the link, so the PUT must send it.
pub const UPLOAD_CONTENT_TYPE: &str = "application/octet-stream";

/// Grants the server issues for one chunk of one session per link lifetime (R2.4: one, plus the
/// three renewals the client rules allow). A fifth is a 429, so a client never asks for it.
pub const MAX_GRANTS_PER_CHUNK: u32 = 4;

/// Why an upload answer is refused. The text never contains a URL.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum UploadViolation {
    #[error("the answer is not the contract's JSON")]
    Malformed,
    #[error("the server did not answer with the upload transport")]
    Transport,
    #[error("the answer is for a different chunk")]
    Index,
    #[error("the grant is not a PUT")]
    Method,
    #[error("a grant link was refused: {0}")]
    Authority(Refusal),
    #[error("the grant asks for headers other than the content type")]
    Headers,
    #[error("a grant's expiry is missing or unreadable")]
    Expiry,
    #[error("the committed size is not the size that was sent")]
    Size,
}

impl UploadViolation {
    /// Stable machine name (bindings and vectors). A refused link carries the reason as
    /// `authority_<refusal code>`, like [`Violation`](super::Violation).
    pub fn code(self) -> String {
        match self {
            UploadViolation::Malformed => "malformed".into(),
            UploadViolation::Transport => "transport".into(),
            UploadViolation::Index => "index".into(),
            UploadViolation::Method => "method".into(),
            UploadViolation::Authority(refusal) => format!("authority_{}", refusal.code()),
            UploadViolation::Headers => "headers".into(),
            UploadViolation::Expiry => "expiry".into(),
            UploadViolation::Size => "size".into(),
        }
    }
}

/// A presigned PUT for one chunk, after validation.
#[derive(Clone, PartialEq, Eq)]
pub struct UploadLink {
    pub index: u32,
    /// Presigned URL (a staging key, R1.1): a bearer capability until `expires_at`. Never log it.
    pub url: String,
    /// RFC 3339, whole seconds, UTC.
    pub expires_at: String,
}

impl UploadLink {
    /// The one header the PUT sends, as the server signed it.
    pub fn content_type(&self) -> &'static str {
        UPLOAD_CONTENT_TYPE
    }
}

impl fmt::Debug for UploadLink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UploadLink")
            .field("index", &self.index)
            .field("url", &redact(&self.url))
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// What a `200` upload grant means.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UploadGrant {
    /// Send the chunk to this link.
    Link(UploadLink),
    /// The index is already committed (R1.1): count the chunk as stored, send nothing.
    Skipped,
}

impl UploadGrant {
    /// Decode and validate the body of a `200` grant for chunk `index`. The link is checked the
    /// way a download link is ([`check_storage_url`]); it must be a PUT carrying no header but
    /// the content type; the expiry must be readable.
    pub fn from_answer(
        body: &[u8],
        index: u32,
        discovery: &Discovery,
        api_base: &str,
    ) -> Result<UploadGrant, UploadViolation> {
        let response = UploadGrantResponse::from_json(body).map_err(|_| UploadViolation::Malformed)?;
        if response.transport != CAP_OBJECT_UPLOAD_V1 {
            return Err(UploadViolation::Transport);
        }
        if response.index != index {
            return Err(UploadViolation::Index);
        }
        if response.skipped {
            return Ok(UploadGrant::Skipped);
        }
        if response.method.as_deref() != Some("PUT") {
            return Err(UploadViolation::Method);
        }
        let url = response.url.ok_or(UploadViolation::Malformed)?;
        check_storage_url(&url, discovery, api_base).map_err(UploadViolation::Authority)?;
        let mut headers = response.headers.iter();
        match (headers.next(), headers.next()) {
            (Some((name, value)), None)
                if name.eq_ignore_ascii_case("content-type") && value.eq_ignore_ascii_case(UPLOAD_CONTENT_TYPE) => {}
            _ => return Err(UploadViolation::Headers),
        }
        let expires_at = response.expires_at.ok_or(UploadViolation::Expiry)?;
        if chrono::DateTime::parse_from_rfc3339(&expires_at).is_err() {
            return Err(UploadViolation::Expiry);
        }
        Ok(UploadGrant::Link(UploadLink { index, url, expires_at }))
    }
}

/// What a `200` commit means: the chunk is recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UploadCommitted {
    /// The chunk was already recorded (an earlier commit, or a retry after a lost answer).
    pub skipped: bool,
}

impl UploadCommitted {
    /// Decode a `200` commit for chunk `index` that was asked to commit `size` bytes. The body also
    /// carries the object key (it names the tenant); it is read and dropped here, never kept.
    pub fn from_answer(body: &[u8], index: u32, size: u64) -> Result<UploadCommitted, UploadViolation> {
        let response = UploadCommitResponse::from_json(body).map_err(|_| UploadViolation::Malformed)?;
        if response.index != index {
            return Err(UploadViolation::Index);
        }
        if response.size != size {
            return Err(UploadViolation::Size);
        }
        Ok(UploadCommitted {
            skipped: response.skipped,
        })
    }
}

/// A PUT to storage worked when storage said any 2xx (spec, "Client wrapper rules").
pub fn put_stored(status: u16) -> bool {
    (200..300).contains(&status)
}

/// How hard one chunk is tried before the whole file goes back to the API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UploadChunkPolicy {
    /// Links to ask for, in all ([`MAX_GRANTS_PER_CHUNK`]: the server refuses a fifth).
    pub max_grants: u32,
    /// Failures of any kind (grant, PUT, commit) to ride out.
    pub attempts: u32,
    /// The most the retries may wait in total; a wait that would pass it ends them. It must hold
    /// the longest wait a server can state ([`MAX_RETRY_AFTER`](super::classify::MAX_RETRY_AFTER))
    /// plus a margin, as for [`PinnedRetry`](super::PinnedRetry): the real limiter's 429 says 60 s.
    pub budget: Duration,
    /// The wait after the first failure that named none; it doubles each time.
    pub base: Duration,
}

impl Default for UploadChunkPolicy {
    fn default() -> Self {
        UploadChunkPolicy {
            max_grants: MAX_GRANTS_PER_CHUNK,
            attempts: 8,
            budget: Duration::from_secs(150),
            base: Duration::from_secs(1),
        }
    }
}

/// What went wrong with one step of a chunk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UploadFailure {
    /// The grant request: [`classify`](super::classify) of [`Call::UploadGrant`] (not `Proceed`),
    /// or a `200` whose body [`UploadGrant::from_answer`] refused (pass `Outcome::ApiForThisFile`).
    Grant(Outcome),
    /// The PUT to storage: any status that is not a 2xx ([`put_stored`]), 0 when there was no answer.
    Put { status: u16 },
    /// The commit request: [`classify`](super::classify) of [`Call::UploadCommit`] (not `Proceed`),
    /// or a `200` whose body [`UploadCommitted::from_answer`] refused (pass `Outcome::ApiForThisFile`).
    Commit(Outcome),
}

/// What to do after a failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UploadNext {
    /// Wait `after`, then make this call again: [`Call::UploadGrant`] (a new link, then the PUT
    /// again) or [`Call::UploadCommit`] (the staged chunk is still there).
    Retry { after: Duration, call: Call },
    /// This session cannot finish direct: abandon it and init again without the capability token.
    UseApi,
    /// An authorization answer. Do not fall back; the API would refuse too (or the session is
    /// gone, which the caller's session recovery owns).
    Terminal(Terminal),
}

impl UploadNext {
    /// Stable machine name (vectors).
    pub fn kind(&self) -> &'static str {
        match self {
            UploadNext::Retry { .. } => "retry",
            UploadNext::UseApi => "use_api",
            UploadNext::Terminal(_) => "terminal",
        }
    }
}

/// The state of ONE chunk's tries. Make a new one per chunk.
#[derive(Debug, Clone)]
pub struct UploadChunkState {
    policy: UploadChunkPolicy,
    grants: u32,
    failures: u32,
    waited: Duration,
}

impl UploadChunkState {
    pub fn new(policy: UploadChunkPolicy) -> Self {
        UploadChunkState {
            policy,
            grants: 0,
            failures: 0,
            waited: Duration::ZERO,
        }
    }

    /// May another link be asked for? `false` once [`UploadChunkPolicy::max_grants`] links have
    /// been issued: ask [`UploadChunkState::failed`] instead of the server.
    pub fn may_ask_for_a_link(&self) -> bool {
        self.grants < self.policy.max_grants
    }

    /// The server issued a link (a `200` grant that was not `skipped`). Call it once per link,
    /// whether or not the link then validated: the server counted it.
    pub fn link_issued(&mut self) {
        self.grants = self.grants.saturating_add(1);
    }

    /// A step of this chunk failed. Returns what to do; the waits and tries it allows are bounded
    /// by the policy, after which the answer is [`UploadNext::UseApi`].
    pub fn failed(&mut self, failure: &UploadFailure) -> UploadNext {
        self.failures = self.failures.saturating_add(1);
        let backoff = self
            .policy
            .base
            .saturating_mul(2u32.saturating_pow(self.failures.saturating_sub(1)));
        let (after, call) = match failure {
            UploadFailure::Grant(outcome) => match outcome {
                Outcome::Backoff(d) => (*d, Call::UploadGrant),
                Outcome::Retry => (backoff, Call::UploadGrant),
                Outcome::Terminal(t) => return UploadNext::Terminal(t.clone()),
                _ => return UploadNext::UseApi,
            },
            // The link may have expired, been revoked, or the storage node had a bad moment: a new
            // link, bounded by the grant budget.
            UploadFailure::Put { .. } => (backoff, Call::UploadGrant),
            UploadFailure::Commit(outcome) => match outcome {
                Outcome::Backoff(d) => (*d, Call::UploadCommit),
                Outcome::Retry => (backoff, Call::UploadCommit),
                // Nothing was committed: the staged object is not there. A new link, no wait.
                Outcome::Regrant => (Duration::ZERO, Call::UploadGrant),
                Outcome::Terminal(t) => return UploadNext::Terminal(t.clone()),
                _ => return UploadNext::UseApi,
            },
        };
        let out_of_grants = call == Call::UploadGrant && !self.may_ask_for_a_link();
        if out_of_grants
            || self.failures >= self.policy.attempts
            || self.waited.saturating_add(after) > self.policy.budget
        {
            return UploadNext::UseApi;
        }
        self.waited = self.waited.saturating_add(after);
        UploadNext::Retry { after, call }
    }
}

#[cfg(test)]
mod tests {
    use super::super::wire::StorageBucket;
    use super::*;

    const API: &str = "https://api.beebeeb.test";

    fn discovery() -> Discovery {
        Discovery {
            upload: vec![CAP_OBJECT_UPLOAD_V1.into()],
            storage_hosts: vec!["s3.storage.test".into()],
            storage_buckets: vec![StorageBucket {
                host: "s3.storage.test".into(),
                bucket: "bb-01".into(),
            }],
            ..Default::default()
        }
    }

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    /// The server's own grant body (`upload_grant`, #331).
    fn grant_body(index: u32) -> String {
        format!(
            r#"{{"transport":"object-upload-v1","index":{index},"method":"PUT","url":"https://s3.storage.test/bb-01/tenants/t/files/f/versions/v/staging/{index}/g.bin?X-Amz-Signature=SIG","headers":{{"content-type":"application/octet-stream"}},"expires_at":"2027-01-15T08:05:00Z"}}"#
        )
    }

    #[test]
    fn a_grant_is_a_link_or_skipped_and_the_link_never_prints() {
        let link = UploadGrant::from_answer(grant_body(3).as_bytes(), 3, &discovery(), API).unwrap();
        let UploadGrant::Link(link) = link else {
            panic!("expected a link")
        };
        assert_eq!(link.index, 3);
        assert_eq!(link.content_type(), "application/octet-stream");
        assert!(
            link.url.contains("X-Amz-Signature=SIG"),
            "the caller gets the whole link"
        );
        let shown = format!("{link:?}");
        assert!(!shown.contains("SIG") && !shown.contains("X-Amz"), "{shown}");
        let skipped = br#"{"transport":"object-upload-v1","index":3,"skipped":true}"#;
        assert_eq!(
            UploadGrant::from_answer(skipped, 3, &discovery(), API),
            Ok(UploadGrant::Skipped)
        );
    }

    #[test]
    fn a_grant_that_breaks_the_contract_is_refused_with_its_code() {
        let ok = grant_body(0);
        let with = |from: &str, to: &str| ok.replace(from, to);
        let rows: Vec<(&str, String, UploadViolation)> = vec![
            ("not json", "{nope".into(), UploadViolation::Malformed),
            ("an array", "[]".into(), UploadViolation::Malformed),
            (
                "another transport",
                with("object-upload-v1", "object-upload-v2"),
                UploadViolation::Transport,
            ),
            (
                "another chunk",
                with("\"index\":0", "\"index\":1"),
                UploadViolation::Index,
            ),
            ("a GET", with("\"PUT\"", "\"GET\""), UploadViolation::Method),
            (
                "an extra header",
                with(
                    "\"content-type\":\"application/octet-stream\"",
                    "\"content-type\":\"application/octet-stream\",\"x-amz-acl\":\"public-read\"",
                ),
                UploadViolation::Headers,
            ),
            (
                "another content type",
                with("application/octet-stream\"}", "text/html\"}"),
                UploadViolation::Headers,
            ),
            (
                "no headers",
                with(",\"headers\":{\"content-type\":\"application/octet-stream\"}", ""),
                UploadViolation::Headers,
            ),
            (
                "an unreadable expiry",
                with("2027-01-15T08:05:00Z", "tomorrow"),
                UploadViolation::Expiry,
            ),
            (
                "a host that is not listed",
                with("s3.storage.test", "evil.test"),
                UploadViolation::Authority(Refusal::HostNotListed),
            ),
            (
                "a bucket that is not listed",
                with("/bb-01/", "/other/"),
                UploadViolation::Authority(Refusal::BucketNotListed),
            ),
            (
                "plain http",
                with("https://", "http://"),
                UploadViolation::Authority(Refusal::NotHttps),
            ),
        ];
        for (what, body, want) in rows {
            assert_eq!(
                UploadGrant::from_answer(body.as_bytes(), 0, &discovery(), API),
                Err(want),
                "{what}"
            );
        }
        // The violation's text and code never carry the link.
        let err = UploadGrant::from_answer(
            ok.replace("s3.storage.test", "evil.test").as_bytes(),
            0,
            &discovery(),
            API,
        )
        .unwrap_err();
        assert!(!format!("{err} {}", err.code()).contains("SIG"));
        assert_eq!(err.code(), "authority_host_not_listed");
    }

    #[test]
    fn a_commit_echoes_the_chunk_and_the_size_and_keeps_no_key() {
        let body = br#"{"index":2,"size":4194332,"skipped":false,"object_key":"tenants/t/files/f/versions/v/2.bin"}"#;
        assert_eq!(
            UploadCommitted::from_answer(body, 2, 4_194_332),
            Ok(UploadCommitted { skipped: false })
        );
        let skipped = br#"{"index":2,"size":4194332,"skipped":true,"object_key":"k"}"#;
        assert_eq!(
            UploadCommitted::from_answer(skipped, 2, 4_194_332),
            Ok(UploadCommitted { skipped: true })
        );
        assert_eq!(
            UploadCommitted::from_answer(body, 3, 4_194_332),
            Err(UploadViolation::Index)
        );
        assert_eq!(UploadCommitted::from_answer(body, 2, 1), Err(UploadViolation::Size));
        assert_eq!(
            UploadCommitted::from_answer(b"{}", 0, 0),
            Err(UploadViolation::Malformed)
        );
    }

    #[test]
    fn storage_put_is_stored_on_any_2xx_only() {
        for status in [200, 201, 204, 299] {
            assert!(put_stored(status), "{status}");
        }
        for status in [0, 100, 199, 300, 301, 403, 404, 500, 503] {
            assert!(!put_stored(status), "{status}");
        }
    }

    fn state() -> UploadChunkState {
        UploadChunkState::new(UploadChunkPolicy::default())
    }

    fn retry(after: Duration, call: Call) -> UploadNext {
        UploadNext::Retry { after, call }
    }

    #[test]
    fn a_failed_put_asks_for_a_new_link_until_the_grants_are_spent() {
        let mut s = state();
        for n in 0..3 {
            assert!(s.may_ask_for_a_link());
            s.link_issued();
            // The wait doubles with each failure: 1 s, 2 s, 4 s.
            assert_eq!(
                s.failed(&UploadFailure::Put { status: 403 }),
                retry(secs(1 << n), Call::UploadGrant),
                "failure {}",
                n + 1
            );
        }
        // The fourth link is the last the server will issue; its PUT fails too.
        s.link_issued();
        assert!(!s.may_ask_for_a_link());
        assert_eq!(s.failed(&UploadFailure::Put { status: 0 }), UploadNext::UseApi);
    }

    #[test]
    fn a_commit_that_is_busy_waits_the_stated_time_and_commits_again() {
        let mut s = state();
        s.link_issued();
        assert_eq!(
            s.failed(&UploadFailure::Commit(Outcome::Backoff(secs(5)))),
            retry(secs(5), Call::UploadCommit)
        );
        // Not tied to the grant count: the staged chunk is still there.
        assert_eq!(
            s.failed(&UploadFailure::Commit(Outcome::Retry)),
            retry(secs(2), Call::UploadCommit)
        );
    }

    #[test]
    fn a_chunk_that_was_not_stored_is_granted_again_without_waiting() {
        let mut s = state();
        s.link_issued();
        assert_eq!(
            s.failed(&UploadFailure::Commit(Outcome::Regrant)),
            retry(Duration::ZERO, Call::UploadGrant)
        );
        s.link_issued();
        s.link_issued();
        s.link_issued();
        assert_eq!(s.failed(&UploadFailure::Commit(Outcome::Regrant)), UploadNext::UseApi);
    }

    #[test]
    fn everything_that_means_this_session_cannot_go_direct_is_use_api() {
        for outcome in [
            Outcome::ApiForThisFile,
            Outcome::UseApiNow,
            Outcome::NotSupported,
            Outcome::Restart,
            Outcome::Proceed,
        ] {
            assert_eq!(
                state().failed(&UploadFailure::Grant(outcome.clone())),
                UploadNext::UseApi,
                "{outcome:?}"
            );
            assert_eq!(
                state().failed(&UploadFailure::Commit(outcome.clone())),
                UploadNext::UseApi,
                "{outcome:?}"
            );
        }
    }

    #[test]
    fn an_authorization_answer_is_terminal_never_a_fallback() {
        let t = Terminal {
            status: 403,
            error: Some("forbidden".into()),
        };
        assert_eq!(
            state().failed(&UploadFailure::Grant(Outcome::Terminal(t.clone()))),
            UploadNext::Terminal(t.clone())
        );
        assert_eq!(
            state().failed(&UploadFailure::Commit(Outcome::Terminal(t.clone()))),
            UploadNext::Terminal(t)
        );
    }

    #[test]
    fn the_waiting_is_bounded_by_the_budget_and_the_tries_by_the_attempts() {
        // The real limiter's 429 states 60 s (and a ban 120 s): two of those fit in 150 s, a third does not.
        let mut s = state();
        assert_eq!(
            s.failed(&UploadFailure::Grant(Outcome::Backoff(secs(60)))),
            retry(secs(60), Call::UploadGrant)
        );
        assert_eq!(
            s.failed(&UploadFailure::Grant(Outcome::Backoff(secs(60)))),
            retry(secs(60), Call::UploadGrant)
        );
        assert_eq!(
            s.failed(&UploadFailure::Grant(Outcome::Backoff(secs(60)))),
            UploadNext::UseApi,
            "180 s of waiting is past the 150 s budget"
        );
        // A wait that ends exactly at the budget is taken; a millisecond more is not.
        let mut s = state();
        assert_eq!(
            s.failed(&UploadFailure::Commit(Outcome::Backoff(secs(90)))),
            retry(secs(90), Call::UploadCommit)
        );
        assert_eq!(
            s.failed(&UploadFailure::Commit(Outcome::Backoff(secs(60)))),
            retry(secs(60), Call::UploadCommit)
        );
        assert_eq!(
            s.failed(&UploadFailure::Commit(Outcome::Backoff(Duration::from_millis(1)))),
            UploadNext::UseApi
        );
        // Short waits end by the number of failures: the eighth failure is the last the policy rides out.
        let mut s = UploadChunkState::new(UploadChunkPolicy {
            base: Duration::ZERO,
            ..UploadChunkPolicy::default()
        });
        for n in 1..8 {
            assert_eq!(
                s.failed(&UploadFailure::Commit(Outcome::Retry)),
                retry(Duration::ZERO, Call::UploadCommit),
                "failure {n}"
            );
        }
        assert_eq!(s.failed(&UploadFailure::Commit(Outcome::Retry)), UploadNext::UseApi);
    }

    #[test]
    fn a_grant_that_is_busy_or_unwell_is_asked_for_again() {
        let mut s = state();
        assert_eq!(
            s.failed(&UploadFailure::Grant(Outcome::Retry)),
            retry(secs(1), Call::UploadGrant)
        );
        assert_eq!(
            s.failed(&UploadFailure::Grant(Outcome::Backoff(secs(3)))),
            retry(secs(3), Call::UploadGrant)
        );
    }

    // ── the contract vectors (test-vectors/direct_upload.json) ──

    fn vectors() -> serde_json::Value {
        serde_json::from_str(include_str!("../../../test-vectors/direct_upload.json")).unwrap()
    }

    fn discovery_of(v: &serde_json::Value, name: &str) -> Discovery {
        serde_json::from_value(v["discoveries"][name].clone()).unwrap()
    }

    #[test]
    fn every_grant_answer_row_of_the_vectors() {
        let v = vectors();
        let rows = v["grant_answers"].as_array().unwrap();
        assert!(rows.len() >= 24, "{} rows", rows.len());
        for row in rows {
            let name = row["name"].as_str().unwrap();
            let api = v["api_bases"][row["api_base"].as_str().unwrap()].as_str().unwrap();
            let got = UploadGrant::from_answer(
                row["body"].as_str().unwrap().as_bytes(),
                row["index"].as_u64().unwrap() as u32,
                &discovery_of(&v, row["discovery"].as_str().unwrap()),
                api,
            );
            let want = &row["expect"];
            match (want["kind"].as_str().unwrap(), got) {
                ("link", Ok(UploadGrant::Link(link))) => {
                    assert_eq!(u64::from(link.index), want["index"].as_u64().unwrap(), "{name}");
                    assert_eq!(link.content_type(), want["content_type"].as_str().unwrap(), "{name}");
                }
                ("skipped", Ok(UploadGrant::Skipped)) => {}
                ("violation", Err(violation)) => assert_eq!(violation.code(), want["code"].as_str().unwrap(), "{name}"),
                (kind, got) => panic!("{name}: wanted {kind}, got {got:?}"),
            }
        }
    }

    #[test]
    fn every_commit_answer_row_of_the_vectors() {
        let v = vectors();
        let rows = v["commit_answers"].as_array().unwrap();
        assert!(rows.len() >= 8, "{} rows", rows.len());
        for row in rows {
            let name = row["name"].as_str().unwrap();
            let got = UploadCommitted::from_answer(
                row["body"].as_str().unwrap().as_bytes(),
                row["index"].as_u64().unwrap() as u32,
                row["size"].as_u64().unwrap(),
            );
            let want = &row["expect"];
            match (want["kind"].as_str().unwrap(), got) {
                ("committed", Ok(done)) => assert_eq!(done.skipped, want["skipped"].as_bool().unwrap(), "{name}"),
                ("violation", Err(violation)) => assert_eq!(violation.code(), want["code"].as_str().unwrap(), "{name}"),
                (kind, got) => panic!("{name}: wanted {kind}, got {got:?}"),
            }
        }
    }

    #[test]
    fn every_init_transport_row_of_the_vectors() {
        let v = vectors();
        let rows = v["init_transport"].as_array().unwrap();
        assert!(rows.len() >= 5);
        for row in rows {
            assert_eq!(
                super::super::upload_init_selects_direct(row["field"].as_str()),
                row["direct"].as_bool().unwrap(),
                "{}",
                row["name"]
            );
        }
    }

    #[test]
    fn every_policy_scenario_of_the_vectors() {
        use super::super::vectors::outcome_from_json;
        let v = vectors();
        let scenarios = v["policy"].as_array().unwrap();
        assert!(scenarios.len() >= 19, "{} scenarios", scenarios.len());
        for scenario in scenarios {
            let name = scenario["name"].as_str().unwrap();
            let mut state = state();
            for (i, step) in scenario["steps"].as_array().unwrap().iter().enumerate() {
                let at = format!("{name}, step {}", i + 1);
                match step["op"].as_str().unwrap() {
                    "link_issued" => state.link_issued(),
                    "may_ask" => assert_eq!(state.may_ask_for_a_link(), step["expect"].as_bool().unwrap(), "{at}"),
                    "failed" => {
                        let f = &step["failure"];
                        let failure = match f["kind"].as_str().unwrap() {
                            "grant" => UploadFailure::Grant(outcome_from_json(&f["outcome"])),
                            "commit" => UploadFailure::Commit(outcome_from_json(&f["outcome"])),
                            "put" => UploadFailure::Put {
                                status: f["status"].as_u64().unwrap() as u16,
                            },
                            other => panic!("{at}: unknown failure {other}"),
                        };
                        let got = state.failed(&failure);
                        let want = &step["expect"];
                        match (want["kind"].as_str().unwrap(), &got) {
                            ("retry", UploadNext::Retry { after, call }) => {
                                assert_eq!(after.as_millis() as u64, want["millis"].as_u64().unwrap(), "{at}");
                                assert_eq!(call.code(), want["call"].as_str().unwrap(), "{at}");
                            }
                            ("use_api", UploadNext::UseApi) => {}
                            ("terminal", UploadNext::Terminal(t)) => {
                                assert_eq!(u64::from(t.status), want["status"].as_u64().unwrap(), "{at}");
                                assert_eq!(t.error.as_deref(), want["error"].as_str(), "{at}");
                            }
                            (kind, got) => panic!("{at}: wanted {kind}, got {got:?}"),
                        }
                    }
                    other => panic!("{at}: unknown op {other}"),
                }
            }
        }
    }

    #[test]
    fn the_constants_are_the_ones_the_server_fixes() {
        // A client cannot import the server's constants. The vectors record them with their source, and this pins the
        // client's copies to that record; the server pins its own to core's (see the PR body), so a change on either
        // side turns a test red.
        let v = vectors();
        assert_eq!(
            u64::from(MAX_GRANTS_PER_CHUNK),
            v["constants"]["max_grants_per_chunk"].as_u64().unwrap()
        );
        assert_eq!(UPLOAD_CONTENT_TYPE, v["constants"]["content_type"].as_str().unwrap());
        assert_eq!(UploadChunkPolicy::default().max_grants, MAX_GRANTS_PER_CHUNK);
        assert!(
            v["constants"]["max_grants_per_chunk_source"]
                .as_str()
                .unwrap()
                .contains("MAX_GRANTS_PER_CHUNK")
        );
    }

    #[test]
    fn the_default_policy_matches_the_servers_grant_cap() {
        let p = UploadChunkPolicy::default();
        assert_eq!(p.max_grants, MAX_GRANTS_PER_CHUNK);
        assert_eq!(MAX_GRANTS_PER_CHUNK, 4);
        assert!(p.budget >= super::super::classify::MAX_RETRY_AFTER + secs(30));
    }
}
