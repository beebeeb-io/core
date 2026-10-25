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
pub mod window;
pub mod wire;

pub use authority::{MAX_URL_LEN, Refusal, check_storage_url, redact, scrub};
pub use classify::{ApiAnswer, Call, Outcome, Terminal, classify};
pub use window::{DownloadPlanner, Geometry, PlanError, PlannerConfig, Poll, Verdict, Violation};
pub use wire::{
    CAP_OBJECT_DOWNLOAD_V1, CAP_OBJECT_UPLOAD_V1, CAPABILITIES_HEADER, ChunkGrant, DISCOVERY_PATH, Discovery,
    DownloadGrantRequest, DownloadGrantResponse, StorageBucket, UploadCommitRequest, UploadCommitResponse,
    UploadGrantRequest, UploadGrantResponse, WireError, download_grants_path, upload_init_selects_direct,
};

/// How long a discovery answer is trusted (spec: at most 10 minutes per API base).
pub const DISCOVERY_TTL_MS: i64 = 10 * 60 * 1000;
/// Failed discovery attempts per cache (one try plus one retry) before the
/// client stops asking and uses the API.
pub const DISCOVERY_ATTEMPTS: u8 = 2;

/// What to do about discovery right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lookup<'a> {
    /// Ask the server.
    Fetch,
    /// Use this answer (it may still say the server offers nothing).
    Cached(&'a Discovery),
    /// Do not ask; use the API.
    UseApi,
}

#[derive(Debug)]
enum CacheState {
    Unknown,
    Known { discovery: Discovery, fetched_at_ms: i64 },
    NotSupported,
}

/// Per-API-base discovery cache (R1.6: "the discovery cache is a hint, never
/// proof that every node has the route"):
///
/// * a good answer is reused for [`DISCOVERY_TTL_MS`];
/// * [`Outcome::NotSupported`] (a JSON 404) is remembered for the life of the cache;
/// * [`Outcome::UseApiNow`] is not remembered as "unsupported": the next lookup
///   asks again, but only [`DISCOVERY_ATTEMPTS`] times in total, so a broken
///   node costs one retry per command, not one per file.
///
/// Keep one per `ApiClient` (per API base); a new command starts a new cache.
#[derive(Debug)]
pub struct DiscoveryCache {
    state: CacheState,
    failures: u8,
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
        }
    }

    pub fn lookup(&self, now_ms: i64) -> Lookup<'_> {
        match &self.state {
            CacheState::NotSupported => Lookup::UseApi,
            CacheState::Known {
                discovery,
                fetched_at_ms,
            } if now_ms.saturating_sub(*fetched_at_ms) < DISCOVERY_TTL_MS && now_ms >= *fetched_at_ms => {
                Lookup::Cached(discovery)
            }
            // Unknown, expired, or a clock that went backwards: ask again,
            // unless asking has already failed enough times.
            _ if self.failures >= DISCOVERY_ATTEMPTS => Lookup::UseApi,
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
            (Outcome::NotSupported, _) => self.state = CacheState::NotSupported,
            _ => self.failures = self.failures.saturating_add(1),
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
    fn not_supported_is_remembered_for_the_process() {
        let mut c = DiscoveryCache::new();
        c.record(&Outcome::NotSupported, None, 0);
        assert_eq!(c.lookup(0), Lookup::UseApi);
        assert_eq!(c.lookup(10 * DISCOVERY_TTL_MS), Lookup::UseApi);
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
