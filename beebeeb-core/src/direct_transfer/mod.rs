//! Direct S3 transfers v1: the client-side rules (task 2173).
//!
//! The server signs short-lived links to a file's encrypted chunks and the
//! client fetches them straight from object storage. The wire contract is
//! `docs/specs/2026-10-23-direct-download-hosts.md` ("v1 wire contract" and the
//! binding amendments R1.1–R1.18). This module is the part of that contract
//! every client must apply identically, as **pure Rust**: no I/O, no HTTP
//! client, no async runtime, no clock. Each client keeps its own HTTP stack (CLI
//! reqwest, desktop `beebeeb-sync`, iOS `URLSession`, web `fetch`) and calls
//! these rules, so five clients do not re-implement authority checks and
//! fallback classification five ways. Like [`crate::onboarding`], it is meant to
//! be exported through `beebeeb-wasm` and `beebeeb-uniffi` without change.
//!
//! | file | what it decides |
//! | --- | --- |
//! | [`wire`] | constants and serde types: discovery, grant request/response, upload shapes (frozen, not yet served) |
//! | [`authority`] | [`check_storage_url`] (may this link be followed), [`redact`] / [`scrub`] (how a link may be shown) |
//! | [`classify`] | [`classify()`]: what an API answer on a discovery or grant call means (R1.6) |
//! | [`window`] | [`DownloadPlanner`]: windows, in-flight cap, renewals, per-chunk fallback |
//! | [`upload`] | the direct upload: [`UploadGrant`] / [`UploadCommitted`] validation, [`UploadChunkState`] (grants, waits, fallback per chunk) |
//! | this file | [`DiscoveryCache`]: how long discovery's answer is trusted |
//!
//! # What a client still has to do itself
//!
//! * Send `X-Beebeeb-Capabilities` ([`CAPABILITIES_HEADER`]) on grant requests
//!   only, never globally.
//! * Fetch storage links with a **separate** HTTP client: no default headers, no
//!   cookies, no `Authorization`, redirects disabled, https only (loopback http
//!   in development), and strip the URL from its own errors (reqwest
//!   `.without_url()`); run any error text through [`scrub`] before printing it.
//! * Check `200` and `Content-Length == grant.length` on every storage GET, and
//!   decrypt with [`crate::chunk_stream`] (frame and AAD position checks), never
//!   by trusting the manifest.
//! * Publish plaintext only after every chunk has authenticated.
//!
//! # Exporting to the bindings
//!
//! Not done in this module's first release. Everything public here is plain
//! owned data (`String`, integers, `Vec`, enums with data), so UniFFI records
//! and `serde-wasm-bindgen` values map one to one; the planner is a handle
//! (like `ChunkDecryptorHandle`) driven from one sequence, and `std::time::Duration`
//! in [`Outcome::Backoff`] becomes milliseconds at the boundary.

pub mod authority;
pub mod classify;
pub mod upload;
pub mod window;
pub mod wire;

/// Contract vectors and their interpreter (test-support only); see the module docs.
#[cfg(any(test, feature = "test-support"))]
pub mod vectors;

pub use authority::{MAX_URL_LEN, Refusal, check_storage_url, redact, scrub};
pub use classify::{ApiAnswer, Call, Outcome, PinnedRetry, RetryDecision, Terminal, classify};
pub use upload::{
    MAX_GRANTS_PER_CHUNK, UPLOAD_CONTENT_TYPE, UploadChunkPolicy, UploadChunkState, UploadCommitted, UploadFailure,
    UploadGrant, UploadLink, UploadNext, UploadViolation, put_stored,
};
pub use window::{DownloadPlanner, Geometry, PlanError, PlannerConfig, Poll, Verdict, Violation, WindowAnswer};
pub use wire::{
    CAP_OBJECT_DOWNLOAD_V1, CAP_OBJECT_UPLOAD_V1, CAPABILITIES_HEADER, ChunkGrant, DISCOVERY_PATH, Discovery,
    DownloadGrantRequest, DownloadGrantResponse, MAX_UPLOAD_BODY_BYTES, StorageBucket, UploadCommitRequest,
    UploadCommitResponse, UploadGrantRequest, UploadGrantResponse, WireError, download_grants_path, upload_commit_path,
    upload_grant_path, upload_init_selects_direct,
};

/// How long a discovery answer is trusted (spec: at most 10 minutes per API base).
pub const DISCOVERY_TTL_MS: i64 = 10 * 60 * 1000;
/// Failed discovery attempts per cache (one try plus one retry) before the
/// client stops asking and uses the API.
pub const DISCOVERY_ATTEMPTS: u8 = 2;

/// What to do about discovery right now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Lookup {
    /// Ask the server.
    Fetch,
    /// Use this answer (it may still say the server offers nothing).
    Cached(Discovery),
    /// Do not ask; use the API.
    UseApi,
}

#[derive(Debug)]
enum CacheState {
    Unknown,
    Known { discovery: Discovery, fetched_at_ms: i64 },
    NotSupported { at_ms: i64 },
}

/// Per-API-base discovery cache (R1.6: "the discovery cache is a hint, never
/// proof that every node has the route"):
///
/// * a good answer is reused for [`DISCOVERY_TTL_MS`];
/// * [`Outcome::NotSupported`] (a JSON 404) is remembered for [`DISCOVERY_TTL_MS`];
/// * [`Outcome::UseApiNow`] is not remembered as "unsupported": the next lookup
///   asks again, but only [`DISCOVERY_ATTEMPTS`] times within a trust period, so a
///   broken node costs one retry per command, not one per file.
///
/// Nothing is remembered for longer than the trust period: a Mac that woke before
/// its network, or a daemon started before the server was deployed, probes again
/// ten minutes later instead of staying off the direct transport until it is
/// restarted. The clock is injected; a clock that went backwards counts as expired.
///
/// Keep one per `ApiClient` (per API base); a new command starts a new cache.
#[derive(Debug)]
pub struct DiscoveryCache {
    state: CacheState,
    failures: u8,
    /// When the most recent failed attempt was recorded (meaningful while `failures > 0`).
    last_failure_ms: i64,
}

/// Is something recorded at `at_ms` still inside the trust period at `now_ms`?
fn within_trust(at_ms: i64, now_ms: i64) -> bool {
    now_ms >= at_ms && now_ms.saturating_sub(at_ms) < DISCOVERY_TTL_MS
}

impl Default for DiscoveryCache {
    fn default() -> Self {
        Self::new()
    }
}

impl DiscoveryCache {
    pub fn new() -> Self {
        DiscoveryCache {
            state: CacheState::Unknown,
            failures: 0,
            last_failure_ms: 0,
        }
    }

    pub fn lookup(&self, now_ms: i64) -> Lookup {
        match &self.state {
            CacheState::NotSupported { at_ms } if within_trust(*at_ms, now_ms) => Lookup::UseApi,
            CacheState::Known {
                discovery,
                fetched_at_ms,
            } if within_trust(*fetched_at_ms, now_ms) => Lookup::Cached(discovery.clone()),
            // Unknown, expired, or a clock that went backwards: ask again, unless asking has
            // already failed enough times within the last trust period.
            _ if self.failures >= DISCOVERY_ATTEMPTS && within_trust(self.last_failure_ms, now_ms) => Lookup::UseApi,
            _ => Lookup::Fetch,
        }
    }

    /// Record the result of a discovery call. `body` is the decoded answer when
    /// `outcome` is [`Outcome::Proceed`]; a `Proceed` whose body did not decode
    /// is recorded as a failed attempt.
    pub fn record(&mut self, outcome: &Outcome, body: Option<Discovery>, now_ms: i64) {
        match (outcome, body) {
            (Outcome::Proceed, Some(discovery)) => {
                self.failures = 0;
                self.state = CacheState::Known {
                    discovery,
                    fetched_at_ms: now_ms,
                };
            }
            (Outcome::NotSupported, _) => self.state = CacheState::NotSupported { at_ms: now_ms },
            _ => {
                // Failures older than the trust period are forgotten: this one starts a new count.
                if self.failures > 0 && !within_trust(self.last_failure_ms, now_ms) {
                    self.failures = 0;
                }
                self.failures = self.failures.saturating_add(1);
                self.last_failure_ms = now_ms;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn offers() -> Discovery {
        Discovery {
            download: vec![CAP_OBJECT_DOWNLOAD_V1.into()],
            ..Default::default()
        }
    }

    #[test]
    fn a_good_answer_is_reused_for_ten_minutes_then_refreshed() {
        assert_eq!(
            DISCOVERY_TTL_MS, 600_000,
            "spec: a discovery answer is cached for at most 10 minutes"
        );
        let mut c = DiscoveryCache::new();
        assert_eq!(c.lookup(0), Lookup::Fetch);
        c.record(&Outcome::Proceed, Some(offers()), 1_000);
        assert!(matches!(c.lookup(1_000), Lookup::Cached(d) if d.offers_download()));
        assert!(matches!(c.lookup(1_000 + DISCOVERY_TTL_MS - 1), Lookup::Cached(_)));
        assert_eq!(c.lookup(1_000 + DISCOVERY_TTL_MS), Lookup::Fetch);
        assert_eq!(
            c.lookup(999),
            Lookup::Fetch,
            "a clock that went backwards does not extend trust"
        );
    }

    #[test]
    fn not_supported_is_remembered_for_one_trust_period() {
        let mut c = DiscoveryCache::new();
        c.record(&Outcome::NotSupported, None, 1_000);
        assert_eq!(c.lookup(1_000), Lookup::UseApi);
        assert_eq!(c.lookup(1_000 + DISCOVERY_TTL_MS - 1), Lookup::UseApi);
        // Then it asks again: the server may have been deployed since.
        assert_eq!(c.lookup(1_000 + DISCOVERY_TTL_MS), Lookup::Fetch);
        assert_eq!(
            c.lookup(999),
            Lookup::Fetch,
            "a clock that went backwards does not extend it"
        );
        c.record(&Outcome::Proceed, Some(offers()), 1_000 + DISCOVERY_TTL_MS);
        assert!(matches!(c.lookup(2_000 + DISCOVERY_TTL_MS), Lookup::Cached(d) if d.offers_download()));
        // Still not supported on the next probe: remembered for another period.
        let mut c = DiscoveryCache::new();
        c.record(&Outcome::NotSupported, None, 0);
        c.record(&Outcome::NotSupported, None, DISCOVERY_TTL_MS);
        assert_eq!(c.lookup(DISCOVERY_TTL_MS + 1), Lookup::UseApi);
    }

    #[test]
    fn a_cache_that_gave_up_asks_again_after_one_trust_period() {
        let mut c = DiscoveryCache::new();
        c.record(&Outcome::UseApiNow, None, 1_000);
        c.record(&Outcome::UseApiNow, None, 2_000);
        assert_eq!(c.lookup(2_001), Lookup::UseApi, "given up");
        assert_eq!(c.lookup(2_000 + DISCOVERY_TTL_MS - 1), Lookup::UseApi);
        assert_eq!(c.lookup(2_000 + DISCOVERY_TTL_MS), Lookup::Fetch, "a re-probe");
        assert_eq!(
            c.lookup(1_500),
            Lookup::Fetch,
            "a clock that went backwards does not keep it parked"
        );
        // The re-probe gets a fresh allowance, not the old count: one failure, then one more try.
        let later = 2_000 + DISCOVERY_TTL_MS;
        c.record(&Outcome::UseApiNow, None, later);
        assert_eq!(c.lookup(later + 1), Lookup::Fetch);
        c.record(&Outcome::UseApiNow, None, later + 1);
        assert_eq!(c.lookup(later + 2), Lookup::UseApi, "two failures park it again");
    }

    #[test]
    fn failures_further_apart_than_a_trust_period_do_not_add_up() {
        let mut c = DiscoveryCache::new();
        c.record(&Outcome::UseApiNow, None, 0);
        c.record(&Outcome::UseApiNow, None, DISCOVERY_TTL_MS + 5);
        assert_eq!(
            c.lookup(DISCOVERY_TTL_MS + 6),
            Lookup::Fetch,
            "the first one had expired, so this is the first of two"
        );
    }

    #[test]
    fn use_api_now_is_retried_once_then_given_up_on() {
        let mut c = DiscoveryCache::new();
        c.record(&Outcome::UseApiNow, None, 0);
        assert_eq!(c.lookup(1), Lookup::Fetch, "one retry");
        c.record(&Outcome::UseApiNow, None, 1);
        assert_eq!(c.lookup(2), Lookup::UseApi, "no third attempt");
    }

    #[test]
    fn a_success_after_a_failure_clears_the_count() {
        let mut c = DiscoveryCache::new();
        c.record(&Outcome::UseApiNow, None, 0);
        c.record(&Outcome::Proceed, Some(offers()), 1);
        assert!(matches!(c.lookup(2), Lookup::Cached(_)));
        // Once the answer expires, a fresh failure budget applies.
        assert_eq!(c.lookup(1 + DISCOVERY_TTL_MS), Lookup::Fetch);
    }

    #[test]
    fn an_undecodable_success_counts_as_a_failure() {
        let mut c = DiscoveryCache::new();
        c.record(&Outcome::Proceed, None, 0);
        c.record(&Outcome::Proceed, None, 1);
        assert_eq!(c.lookup(2), Lookup::UseApi);
    }

    #[test]
    fn terminal_answers_are_not_cached_as_anything() {
        let mut c = DiscoveryCache::new();
        let t = Outcome::Terminal(Terminal {
            status: 401,
            error: None,
        });
        c.record(&t, None, 0);
        // Counted as a failed attempt only; re-authentication is the caller's business.
        assert_eq!(c.lookup(1), Lookup::Fetch);
    }
}
