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
//!
//! A commit the server answers with `409 commit_in_progress` ([`Outcome::Held`]) is not a failure: after
//! a copy that failed, the server keeps the chunk's lock for [`COMMIT_LOCK_TTL`], so the staged chunk is
//! still there and the commit will go through once the lock clears. Pass it to the same
//! [`UploadChunkState::failed`]; it is waited out on an allowance of its own and does not count against
//! the failure cap or the retry budget. The client's own backoff has equal jitter (seed one state per
//! chunk with [`UploadChunkState::with_seed`]) so many chunks do not come back together.

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

/// How long the server keeps a chunk's commit lock after a copy that failed (R2.3, R3.1): the lock
/// outlives every step it covers, and a copy that may still land holds it for its whole TTL. Server
/// `beebeeb-api/src/direct_transfer.rs:410-412` (`commit_lock_secs()` = 4 * `s3_op_timeout_secs()` + 60),
/// `storage.rs:1952-1958` (`s3_op_timeout_secs()` = 90 by default; env `S3_PUT_OP_TIMEOUT_SECS`), at
/// server 30c8ed62. Pinned by a test against `test-vectors/direct_upload.json` (`constants`), like
/// [`MAX_GRANTS_PER_CHUNK`]. A server run with a longer storage timeout holds longer; a client that
/// waits this long and then gives up costs the file a restart through the API, not a failure.
pub const COMMIT_LOCK_TTL: Duration = Duration::from_secs(420);

/// What a chunk waits for the commit lock beyond [`COMMIT_LOCK_TTL`]: the lock's clock starts on the
/// server before our next request and the answer takes a moment.
pub const COMMIT_HOLD_MARGIN: Duration = Duration::from_secs(30);

/// The shortest wait between two polls of a held commit, whatever was stated (`Held(Some(0))`, a hand-built
/// outcome with 0, negative or NaN milliseconds) or configured (`hold_poll` of 0): a hold must always end.
pub const MIN_HOLD_POLL: Duration = Duration::from_secs(1);

/// How hard one chunk is tried before the whole file goes back to the API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UploadChunkPolicy {
    /// Links to ask for, in all ([`MAX_GRANTS_PER_CHUNK`]: the server refuses a fifth).
    pub max_grants: u32,
    /// The failure that ends the tries: the `attempts`-th failure of any kind (grant, PUT, commit) is
    /// answered with [`UploadNext::UseApi`], so `attempts - 1` are ridden out. A hold
    /// ([`Outcome::Held`]) is not a failure and is not counted.
    pub attempts: u32,
    /// The most the retries may wait in total; a wait that would pass it ends them. It must hold
    /// the longest wait a server can state ([`MAX_RETRY_AFTER`](super::classify::MAX_RETRY_AFTER))
    /// plus a margin, as for [`PinnedRetry`](super::PinnedRetry): the real limiter's 429 says 60 s.
    /// With the default `base` the seven waits the doubling allows add up to at most 127 s (1 + 2 + ... +
    /// 64), inside it, so it binds stated waits, not the client's own backoff. Holds are not counted here
    /// either.
    pub budget: Duration,
    /// The wait after the first failure that named none; it doubles each time, with equal jitter
    /// (half to all of it) so many chunks backing off together do not come back together.
    pub base: Duration,
    /// The most one chunk waits, in all, for a commit lock to clear ([`COMMIT_LOCK_TTL`] plus
    /// [`COMMIT_HOLD_MARGIN`]); then the lock outlived its TTL and the session goes to the API.
    pub hold_budget: Duration,
    /// The first poll while the commit is held and the server named no wait; it doubles (equal
    /// jitter) up to [`hold_poll_max`](Self::hold_poll_max).
    pub hold_poll: Duration,
    /// The longest poll interval while held.
    pub hold_poll_max: Duration,
    /// The most polls of one held commit, whatever their waits: a second bound next to
    /// [`hold_budget`](Self::hold_budget) (a poll never waits less than [`MIN_HOLD_POLL`], so the
    /// budget alone ends it, but a policy with a huge budget must still end).
    pub hold_max_polls: u32,
}

impl Default for UploadChunkPolicy {
    fn default() -> Self {
        UploadChunkPolicy {
            max_grants: MAX_GRANTS_PER_CHUNK,
            attempts: 8,
            budget: Duration::from_secs(150),
            base: Duration::from_secs(1),
            hold_budget: COMMIT_LOCK_TTL + COMMIT_HOLD_MARGIN,
            hold_poll: Duration::from_secs(5),
            hold_poll_max: Duration::from_secs(15),
            hold_max_polls: 450,
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
    /// An [`Outcome::Held`] is a hold, not a failure: see [`UploadChunkPolicy::hold_budget`].
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
    /// Time spent waiting for a commit lock, and the polls it took (see [`UploadChunkPolicy::hold_budget`]).
    held: Duration,
    holds: u32,
    rng: u64,
}

impl UploadChunkState {
    /// A state whose jitter is the stream of seed 0: the same waits every time. **Tests only**: a client
    /// that used it would give every chunk of every installation the same backoff stream, which is what
    /// jitter is there to prevent. Production uses [`with_seed`](Self::with_seed) with random bytes.
    #[cfg(test)]
    pub fn new(policy: UploadChunkPolicy) -> Self {
        Self::with_seed(policy, 0)
    }

    /// `seed` starts the jitter of this chunk's backoff. Pass random bytes, one seed per chunk (the same
    /// seed gives the same waits, which is how the vectors pin them).
    pub fn with_seed(policy: UploadChunkPolicy, seed: u64) -> Self {
        UploadChunkState {
            policy,
            grants: 0,
            failures: 0,
            waited: Duration::ZERO,
            held: Duration::ZERO,
            holds: 0,
            rng: super::window::splitmix64(seed),
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
        // The server's commit lock is not a failure: after a copy that failed it lives its whole TTL,
        // minutes, and the staged chunk is still there. Waiting it out has its own allowance, so the
        // failure cap and the retry budget keep bounding real failures.
        if let UploadFailure::Commit(Outcome::Held(stated)) = failure {
            return self.held(*stated);
        }
        self.failures = self.failures.saturating_add(1);
        let (after, call) = match failure {
            UploadFailure::Grant(outcome) => match outcome {
                Outcome::Backoff(d) => (*d, Call::UploadGrant),
                Outcome::Retry => (self.backoff(), Call::UploadGrant),
                Outcome::Terminal(t) => return UploadNext::Terminal(t.clone()),
                _ => return UploadNext::UseApi,
            },
            // The link may have expired, been revoked, or the storage node had a bad moment: a new
            // link, bounded by the grant budget.
            UploadFailure::Put { .. } => (self.backoff(), Call::UploadGrant),
            UploadFailure::Commit(outcome) => match outcome {
                Outcome::Backoff(d) => (*d, Call::UploadCommit),
                Outcome::Retry => (self.backoff(), Call::UploadCommit),
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

    /// The client's own wait after the failures so far: `base` doubled per failure, with equal jitter.
    fn backoff(&mut self) -> Duration {
        let exp = self
            .policy
            .base
            .saturating_mul(2u32.saturating_pow(self.failures.saturating_sub(1)));
        jittered(&mut self.rng, exp)
    }

    /// The commit is held by the server's lock: poll again, inside [`UploadChunkPolicy::hold_budget`].
    fn held(&mut self, stated: Option<Duration>) -> UploadNext {
        let left = self.policy.hold_budget.saturating_sub(self.held);
        if left.is_zero() || self.holds >= self.policy.hold_max_polls {
            return UploadNext::UseApi;
        }
        let want = match stated {
            // The server's own wait is kept as it is.
            Some(d) => d,
            // 5 s, 10 s, 15 s, 15 s ... each with equal jitter.
            None => {
                let exp = self
                    .policy
                    .hold_poll
                    .saturating_mul(2u32.saturating_pow(self.holds.min(16)))
                    .min(self.policy.hold_poll_max);
                jittered(&mut self.rng, exp)
            }
        };
        // Never a busy loop: a stated 0 (or one that arrived as a negative or NaN number from a binding) and a
        // configured `hold_poll` of 0 both wait at least a second.
        let want = want.max(MIN_HOLD_POLL);
        // The last poll is cut to what is left, so the whole allowance is used and no more.
        let after = want.min(left);
        self.held = self.held.saturating_add(after);
        self.holds = self.holds.saturating_add(1);
        UploadNext::Retry {
            after,
            call: Call::UploadCommit,
        }
    }
}

/// `exp` with equal jitter (half to all of it), in whole milliseconds.
fn jittered(rng: &mut u64, exp: Duration) -> Duration {
    let ms = u64::try_from(exp.as_millis()).unwrap_or(u64::MAX);
    Duration::from_millis(super::window::equal_jitter(rng, ms))
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
            // The wait doubles with each failure (1 s, 2 s, 4 s), with equal jitter: half to all of it.
            let UploadNext::Retry { after, call } = s.failed(&UploadFailure::Put { status: 403 }) else {
                panic!("failure {} must be retried", n + 1);
            };
            assert_eq!(call, Call::UploadGrant);
            let exp = Duration::from_secs(1 << n);
            assert!(
                after >= exp / 2 && after <= exp,
                "failure {}: {after:?} outside [{:?}, {exp:?}]",
                n + 1,
                exp / 2
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
        // Not tied to the grant count: the staged chunk is still there. The second failure's own wait is
        // 2 s doubled-from-base with equal jitter: between 1 s and 2 s.
        let UploadNext::Retry { after, call } = s.failed(&UploadFailure::Commit(Outcome::Retry)) else {
            panic!("a plain commit failure is retried");
        };
        assert_eq!(call, Call::UploadCommit);
        assert!(after >= secs(1) && after <= secs(2), "{after:?}");
    }

    #[test]
    fn the_backoff_is_jittered_by_the_seed_and_the_same_seed_repeats() {
        let waits = |seed: u64| -> Vec<Duration> {
            let mut s = UploadChunkState::with_seed(UploadChunkPolicy::default(), seed);
            (0..7)
                .map(|_| match s.failed(&UploadFailure::Commit(Outcome::Retry)) {
                    UploadNext::Retry { after, .. } => after,
                    other => panic!("{other:?}"),
                })
                .collect()
        };
        assert_eq!(waits(1), waits(1), "the same seed, the same waits");
        assert_ne!(waits(1), waits(2), "the seed matters");
        assert_eq!(
            waits(0),
            {
                let mut s = state();
                (0..7)
                    .map(|_| match s.failed(&UploadFailure::Commit(Outcome::Retry)) {
                        UploadNext::Retry { after, .. } => after,
                        other => panic!("{other:?}"),
                    })
                    .collect::<Vec<_>>()
            },
            "`new` is seed 0"
        );
        // Every wait is within its equal-jitter bounds: [exp / 2, exp] for exp = 1 s, 2 s, ... 64 s.
        for (n, w) in waits(99).iter().enumerate() {
            let exp = Duration::from_secs(1 << n);
            assert!(*w >= exp / 2 && *w <= exp, "wait {} = {w:?}", n + 1);
        }
    }

    #[test]
    fn a_stated_wait_is_kept_exactly_and_draws_no_jitter() {
        // Two chunks, the same seed. The first failure of each draws NO jitter, one because the server stated its wait
        // (a Backoff), the other because it is a Regrant (a new link, no wait). The second failure of each is a plain
        // one whose jittered wait comes from the START of the stream in both cases: if a stated wait drew a value, the
        // two would differ.
        let second_wait = |first: Outcome| {
            let mut s = UploadChunkState::with_seed(UploadChunkPolicy::default(), 4);
            let got = s.failed(&UploadFailure::Commit(first.clone()));
            if let Outcome::Backoff(d) = first {
                assert_eq!(got, retry(d, Call::UploadCommit), "a stated wait is kept exactly");
            }
            s.failed(&UploadFailure::Commit(Outcome::Retry))
        };
        assert_eq!(second_wait(Outcome::Backoff(secs(5))), second_wait(Outcome::Regrant));
        // ... and the first failure of a chunk that DOES draw (a plain one) moves the stream, so this comparison can fail.
        let mut a = UploadChunkState::with_seed(UploadChunkPolicy::default(), 4);
        let mut b = UploadChunkState::with_seed(UploadChunkPolicy::default(), 4);
        let _ = a.failed(&UploadFailure::Commit(Outcome::Retry));
        let _ = b.failed(&UploadFailure::Commit(Outcome::Regrant));
        assert_ne!(
            a.failed(&UploadFailure::Commit(Outcome::Retry)),
            b.failed(&UploadFailure::Commit(Outcome::Retry)),
            "a plain failure draws, a regrant does not (different failure counts and streams)"
        );
    }

    // ── the commit lock: a hold is a wait with its own allowance, not a failure (P2-1) ──

    fn hold(s: &mut UploadChunkState, stated: Option<Duration>) -> UploadNext {
        s.failed(&UploadFailure::Commit(Outcome::Held(stated)))
    }

    #[test]
    fn a_held_commit_is_waited_out_for_the_whole_lock_ttl_without_leaving_the_direct_upload() {
        // The copy failed (a plain commit failure); the server's lock now lives COMMIT_LOCK_TTL.
        let mut s = state();
        assert!(matches!(
            s.failed(&UploadFailure::Commit(Outcome::Retry)),
            UploadNext::Retry {
                call: Call::UploadCommit,
                ..
            }
        ));
        let mut waited = Duration::ZERO;
        while waited < COMMIT_LOCK_TTL {
            match hold(&mut s, Some(secs(10))) {
                UploadNext::Retry { after, call } => {
                    assert_eq!(call, Call::UploadCommit);
                    assert_eq!(after, secs(10), "a stated wait is kept");
                    waited += after;
                }
                other => panic!("after {waited:?} of holds: {other:?}"),
            }
        }
        // The lock has now outlived its TTL by at most one poll; the margin still allows more polls.
        assert!(
            matches!(hold(&mut s, Some(secs(10))), UploadNext::Retry { .. }),
            "the margin covers the TTL"
        );
    }

    #[test]
    fn holds_leave_the_failure_cap_and_the_retry_budget_alone() {
        let mut s = state();
        for _ in 0..40 {
            assert!(matches!(hold(&mut s, Some(secs(10))), UploadNext::Retry { .. }));
        }
        // 400 s of holds; all 150 s of the retry budget are still there ...
        assert_eq!(
            s.failed(&UploadFailure::Commit(Outcome::Backoff(secs(150)))),
            retry(secs(150), Call::UploadCommit)
        );
        assert_eq!(
            s.failed(&UploadFailure::Commit(Outcome::Backoff(Duration::from_millis(1)))),
            UploadNext::UseApi
        );
        // ... and so are the failures: seven are ridden out, the eighth ends it.
        let mut s = UploadChunkState::new(UploadChunkPolicy {
            base: Duration::ZERO,
            ..UploadChunkPolicy::default()
        });
        for _ in 0..40 {
            hold(&mut s, Some(secs(10)));
        }
        for n in 1..8 {
            assert!(
                matches!(
                    s.failed(&UploadFailure::Commit(Outcome::Retry)),
                    UploadNext::Retry { .. }
                ),
                "failure {n}"
            );
        }
        assert_eq!(s.failed(&UploadFailure::Commit(Outcome::Retry)), UploadNext::UseApi);
    }

    #[test]
    fn the_hold_allowance_is_spent_to_the_millisecond_and_then_the_session_goes_to_the_api() {
        let mut s = state();
        for _ in 0..3 {
            assert_eq!(hold(&mut s, Some(secs(120))), retry(secs(120), Call::UploadCommit));
        }
        // 360 s used of 450 s: the next poll is cut to the 90 s that are left ...
        assert_eq!(hold(&mut s, Some(secs(120))), retry(secs(90), Call::UploadCommit));
        // ... and nothing is left.
        assert_eq!(hold(&mut s, Some(secs(1))), UploadNext::UseApi);
        assert_eq!(
            COMMIT_LOCK_TTL + COMMIT_HOLD_MARGIN,
            UploadChunkPolicy::default().hold_budget
        );
    }

    #[test]
    fn unstated_holds_are_polled_every_five_seconds_doubling_to_fifteen_with_jitter() {
        let mut s = UploadChunkState::with_seed(UploadChunkPolicy::default(), 17);
        let mut total = Duration::ZERO;
        let mut polls = Vec::new();
        loop {
            match hold(&mut s, None) {
                UploadNext::Retry { after, call } => {
                    assert_eq!(call, Call::UploadCommit);
                    total += after;
                    polls.push(after);
                }
                UploadNext::UseApi => break,
                other => panic!("{other:?}"),
            }
            assert!(polls.len() < 500, "the holds never end");
        }
        assert_eq!(
            total,
            COMMIT_LOCK_TTL + COMMIT_HOLD_MARGIN,
            "the whole allowance, no more"
        );
        // Poll n is within equal-jitter bounds of min(5 s * 2^(n-1), 15 s); only the last may be cut shorter.
        for (i, p) in polls.iter().enumerate() {
            let exp = secs((5u64 << i.min(8)).min(15));
            let last = i + 1 == polls.len();
            assert!(*p <= exp, "poll {} = {p:?} > {exp:?}", i + 1);
            assert!(last || *p >= exp / 2, "poll {} = {p:?} < {:?}", i + 1, exp / 2);
        }
    }

    #[test]
    fn a_hold_that_states_nothing_sensible_still_waits_at_least_a_second_and_ends() {
        // `Held(Some(0))` is what a binding hands over for 0, a negative or NaN number of milliseconds.
        for stated in [
            Some(Duration::ZERO),
            Some(Duration::from_millis(1)),
            Some(Duration::from_millis(999)),
        ] {
            let mut s = state();
            let mut total = Duration::ZERO;
            let mut polls = 0;
            loop {
                match hold(&mut s, stated) {
                    UploadNext::Retry { after, call } => {
                        assert_eq!(call, Call::UploadCommit);
                        assert!(after >= MIN_HOLD_POLL, "{stated:?}: poll {polls} waited {after:?}");
                        total += after;
                        polls += 1;
                    }
                    UploadNext::UseApi => break,
                    other => panic!("{other:?}"),
                }
                assert!(polls <= 1000, "{stated:?}: the hold never ends");
            }
            assert_eq!(total, COMMIT_LOCK_TTL + COMMIT_HOLD_MARGIN, "{stated:?}");
        }
        // A configured poll of 0 does not busy-loop either.
        let mut s = UploadChunkState::new(UploadChunkPolicy {
            hold_poll: Duration::ZERO,
            hold_poll_max: Duration::ZERO,
            ..UploadChunkPolicy::default()
        });
        match hold(&mut s, None) {
            UploadNext::Retry { after, .. } => assert!(after >= MIN_HOLD_POLL, "{after:?}"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn the_number_of_polls_is_capped_whatever_the_allowance() {
        let mut s = UploadChunkState::new(UploadChunkPolicy {
            hold_budget: Duration::from_secs(24 * 3600),
            hold_max_polls: 10,
            ..UploadChunkPolicy::default()
        });
        for n in 1..=10 {
            assert!(
                matches!(hold(&mut s, Some(secs(1))), UploadNext::Retry { .. }),
                "poll {n}"
            );
        }
        assert_eq!(
            hold(&mut s, Some(secs(1))),
            UploadNext::UseApi,
            "the 11th poll is refused"
        );
    }

    #[test]
    fn a_hold_is_only_a_hold_on_the_commit_side() {
        assert_eq!(
            state().failed(&UploadFailure::Grant(Outcome::Held(None))),
            UploadNext::UseApi,
            "no route sends it on a grant"
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
        // Short waits end by the number of failures: the eighth failure ends the tries (seven are ridden out).
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
        let UploadNext::Retry { after, call } = s.failed(&UploadFailure::Grant(Outcome::Retry)) else {
            panic!("an unwell grant is asked for again");
        };
        assert_eq!(call, Call::UploadGrant);
        assert!(after >= Duration::from_millis(500) && after <= secs(1), "{after:?}");
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
    fn every_row_of_the_vectors_says_where_it_comes_from() {
        let v = vectors();
        for section in ["grant_answers", "commit_answers", "init_transport", "policy"] {
            for row in v[section].as_array().unwrap() {
                let source = row["source"].as_str().unwrap_or("");
                assert!(source.len() > 20, "{section}: `{}` has no source", row["name"]);
            }
        }
        let d: serde_json::Value =
            serde_json::from_str(include_str!("../../../test-vectors/direct_transfer.json")).unwrap();
        let mut upload_rows = 0;
        for row in d["classify"].as_array().unwrap() {
            if row["call"].as_str().unwrap().starts_with("upload_") {
                upload_rows += 1;
                assert!(
                    row["source"].as_str().unwrap_or("").len() > 20,
                    "classify: `{}` has no source",
                    row["name"]
                );
            }
        }
        assert_eq!(upload_rows, 58, "classify rows for the upload calls");
    }

    #[test]
    fn every_grant_answer_row_of_the_vectors() {
        let v = vectors();
        let rows = v["grant_answers"].as_array().unwrap();
        assert_eq!(rows.len(), 24, "grant answer rows");
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
        assert_eq!(rows.len(), 8, "commit answer rows");
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
        assert_eq!(rows.len(), 5, "init transport rows");
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
        assert_eq!(
            scenarios.len(),
            29,
            "policy scenarios (27, and the two Put 403 / Put 0 rows of clients plan A1)"
        );
        for scenario in scenarios {
            let name = scenario["name"].as_str().unwrap();
            let mut state =
                UploadChunkState::with_seed(UploadChunkPolicy::default(), scenario["seed"].as_u64().unwrap());
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
                        // `repeat` runs the same failure with the same expectation n times (stated waits).
                        for round in 0..step["repeat"].as_u64().unwrap_or(1) {
                            let at = format!("{at}, round {}", round + 1);
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
                    }
                    // Poll an unstated hold until the allowance is spent: each wait within bounds (only the last
                    // may be cut shorter), the total exactly the allowance, then the API.
                    "exhaust_holds" => {
                        let outcome = outcome_from_json(&step["outcome"]);
                        let (max, min) = (
                            step["each_max_ms"].as_u64().unwrap(),
                            step["each_min_ms"].as_u64().unwrap(),
                        );
                        let mut total = step["already_ms"].as_u64().unwrap();
                        let mut cut = false;
                        for _ in 0..1000 {
                            match state.failed(&UploadFailure::Commit(outcome.clone())) {
                                UploadNext::Retry { after, call } => {
                                    assert_eq!(call, Call::UploadCommit, "{at}");
                                    let ms = after.as_millis() as u64;
                                    assert!(!cut, "{at}: a poll after the cut one");
                                    assert!(ms <= max, "{at}: {ms} ms > {max} ms");
                                    if ms < min {
                                        cut = true;
                                    }
                                    total += ms;
                                }
                                UploadNext::UseApi => break,
                                other => panic!("{at}: {other:?}"),
                            }
                        }
                        assert_eq!(total, step["total_ms"].as_u64().unwrap(), "{at}");
                    }
                    other => panic!("{at}: unknown op {other}"),
                }
            }
        }
    }

    #[test]
    fn the_constants_are_the_ones_the_server_fixes() {
        // A client cannot import the server's constants. The vectors record them with their source, and this pins the
        // client's copies to that record. Only core's side is pinned: this file is read by THESE tests alone (the
        // server does not read it, and neither do the WASM or UniFFI exports). The server-side half is a proposal
        // for the s3-server lane (an assert against core's constants once its CORE_REV carries this module), so until
        // then a change on the server turns no test red.
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
        // The commit lock's TTL (R2.3, R3.1): how long a chunk can be held after a copy that failed.
        assert_eq!(
            COMMIT_LOCK_TTL,
            Duration::from_secs(v["constants"]["commit_lock_ttl_seconds"].as_u64().unwrap())
        );
        assert!(
            v["constants"]["commit_lock_ttl_source"]
                .as_str()
                .unwrap()
                .contains("commit_lock_secs")
        );
        assert_eq!(
            UploadChunkPolicy::default().hold_budget,
            COMMIT_LOCK_TTL + COMMIT_HOLD_MARGIN,
            "the client waits the TTL plus its margin"
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
