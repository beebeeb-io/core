//! The download window planner: a pure state machine that decides, for one
//! file, when to ask the API for the next window of grants, which chunk to
//! fetch from storage next, when a grant must be renewed, and when a chunk
//! gives up on storage and goes to the pinned API route.
//!
//! It owns no socket, thread or clock. The caller (the CLI, the desktop sync
//! engine, a UniFFI or WASM binding) performs the HTTP and drives the planner:
//!
//! ```text
//! loop {
//!     match planner.poll(now_ms) {
//!         Poll::RequestWindow(req) => POST it, then window_answered(..) or window_failed(..),
//!         Poll::Fetch { index, grant } => GET grant.url (separate client), then fetch_ok / fetch_failed,
//!         Poll::FetchViaApi { index, .. } => GET the pinned per-chunk API route, then fetch_ok,
//!         Poll::Wait { until_ms } => sleep until then or until an outstanding request returns,
//!         Poll::Done => break,
//!         Poll::Stop(verdict) => discard partial output and act on the verdict,
//!     }
//!     // chunks are decrypted and written IN ORDER; after each: planner.consumed(index),
//!     // or planner.chunk_unauthentic(index) when one does not open
//! }
//! ```
//!
//! # Rules it enforces (spec "Client wrapper rules", binding for every client)
//!
//! * At most [`MAX_IN_FLIGHT`] chunk requests are outstanding, AND no chunk
//!   further than that ahead of the first unconsumed one is requested: the
//!   decryptor takes frames in order, so a stalled chunk 0 must not let the
//!   reorder buffer grow without bound (chunks are up to 256 MiB).
//! * The next window is requested when [`REFILL_AT`] or fewer unused grants
//!   remain, one window request at a time (no renewal storms).
//! * A grant is not used inside the skew margin before it expires.
//! * A chunk that fails against storage gets one renewal per failure, at most
//!   [`MAX_RENEWALS_PER_CHUNK`], with exponential backoff and jitter; after
//!   that it goes to the pinned API route. A grant that ages out unused counts
//!   against the same budget, so no input makes the planner loop on the API.
//! * A chunk that fails authentication is fetched once through the API route
//!   before it becomes a hard error ([`Verdict::Corrupt`]).
//! * Every grant is validated against the response's own geometry and against
//!   [`super::check_storage_url`] before the caller ever sees it.
//!
//! # Time
//!
//! `now_ms` is the caller's clock in milliseconds (any epoch, but the same one
//! on every call and consistent with RFC 3339 times, i.e. Unix milliseconds in
//! production). A grant's usable window is measured on the CLIENT clock from
//! the moment the answer arrived, bounded by the server's `expires_at` only
//! when that is plausible: a client whose clock is minutes off must not see
//! every fresh grant as already expired and burn the API on renewals.

use std::collections::BTreeMap;

use chrono::DateTime;

use super::authority::{Refusal, check_storage_url};
use super::classify::{Outcome, Terminal};
use super::wire::{
    CAP_OBJECT_DOWNLOAD_V1, CHUNK_OVERHEAD, ChunkGrant, Discovery, DownloadGrantRequest, DownloadGrantResponse,
};
use crate::chunk_stream::MAX_CHUNK_SIZE;

/// Storage/API chunk requests outstanding at once, and the reorder window.
pub const MAX_IN_FLIGHT: usize = 4;
/// Request the next window when this many unused grants (or fewer) remain.
pub const REFILL_AT: usize = 2;
/// A grant is not used, and is renewed, this long before it expires.
pub const RENEW_SKEW_MS: i64 = 30_000;
/// Renewals per chunk before it falls back to the pinned API route.
pub const MAX_RENEWALS_PER_CHUNK: u8 = 3;
/// Consecutive 429s on window requests before the file goes to the API.
pub const MAX_RATE_LIMITS: u8 = 5;
/// First renewal backoff; doubles per failure of the same chunk.
pub const BACKOFF_BASE_MS: u64 = 250;
/// Ceiling of the renewal backoff.
pub const BACKOFF_CAP_MS: u64 = 8_000;
/// The longest the planner ever waits on its own: a server's `Retry-After` is
/// clamped to this (see `classify::MAX_RETRY_AFTER`). A deadline further away
/// than this from the current clock reading is a clock that stepped back, and
/// is pulled in.
pub const MAX_WAIT_MS: i64 = 120_000;
/// A stated link lifetime shorter than this is not believed: no server issues
/// 60 s links (`MIN_URL_LIFETIME`), so it is the client clock that is off.
pub const MIN_STATED_LIFETIME_MS: i64 = 60_000;

/// Tunables. [`PlannerConfig::from_discovery`] gives the production values;
/// tests change single fields.
#[derive(Debug, Clone)]
pub struct PlannerConfig {
    /// Grants asked per window.
    pub window: u32,
    pub refill_at: usize,
    /// Clamped to `1..=`[`MAX_IN_FLIGHT`] when the planner is built.
    pub max_in_flight: usize,
    pub renew_skew_ms: i64,
    /// Link lifetime assumed for plausibility checks, in milliseconds.
    pub url_ttl_ms: i64,
    pub max_renewals: u8,
    pub backoff_base_ms: u64,
    pub backoff_cap_ms: u64,
    pub max_rate_limits: u8,
    /// Seeds the jitter. Production passes random bytes; tests pass a constant.
    pub jitter_seed: u64,
}

impl PlannerConfig {
    pub fn from_discovery(discovery: &Discovery, jitter_seed: u64) -> Self {
        PlannerConfig {
            window: discovery.window(),
            refill_at: REFILL_AT,
            max_in_flight: MAX_IN_FLIGHT,
            renew_skew_ms: RENEW_SKEW_MS,
            url_ttl_ms: i64::try_from(discovery.url_ttl_secs().saturating_mul(1000)).unwrap_or(300_000),
            max_renewals: MAX_RENEWALS_PER_CHUNK,
            backoff_base_ms: BACKOFF_BASE_MS,
            backoff_cap_ms: BACKOFF_CAP_MS,
            max_rate_limits: MAX_RATE_LIMITS,
            jitter_seed,
        }
    }
}

/// The version's geometry as the first window states it; every later window
/// must repeat it exactly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Geometry {
    pub chunk_count: u32,
    /// Plaintext stride.
    pub chunk_size: u64,
    pub encrypted_size: u64,
    pub original_size: u64,
}

impl Geometry {
    /// The exact stored length of chunk `index` (stride + 28; the last chunk
    /// is whatever remains).
    ///
    /// `None` for an index outside the file and for numbers no real version
    /// has (checked arithmetic: nothing here can panic on a hostile geometry).
    pub fn chunk_length(&self, index: u32) -> Option<u64> {
        // (No chunks at all is covered here too: every index is >= 0.)
        if index >= self.chunk_count {
            return None;
        }
        let full = self.chunk_size.checked_add(CHUNK_OVERHEAD)?;
        if index + 1 < self.chunk_count {
            Some(full)
        } else {
            let before_last = full.checked_mul(u64::from(self.chunk_count - 1))?;
            self.encrypted_size.checked_sub(before_last)
        }
    }

    /// Could a real version have these numbers? (`encrypted = original + 28 *
    /// chunks`; every chunk but the last a full stride; the last 0..=stride
    /// plaintext bytes.) The server checks the same before it signs.
    fn is_consistent(&self) -> bool {
        if self.chunk_count == 0 || self.chunk_size > MAX_CHUNK_SIZE {
            return false;
        }
        let n = u128::from(self.chunk_count);
        let full = u128::from(self.chunk_size) + u128::from(CHUNK_OVERHEAD);
        let enc = u128::from(self.encrypted_size);
        let overhead = u128::from(CHUNK_OVERHEAD) * n;
        if enc != u128::from(self.original_size) + overhead {
            return false;
        }
        let before_last = full * (n - 1);
        enc >= before_last + u128::from(CHUNK_OVERHEAD) && enc <= before_last + full
    }
}

/// How the whole file ends when it cannot go on directly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Stop using direct transport for this file: discard any partial output and
    /// start it again on today's API path. Reached before the version is pinned
    /// (nothing was written yet), and as the last resort when the pinned API
    /// route itself fails ([`DownloadPlanner::api_fetch_failed`]). Once the
    /// version is pinned, a window that cannot be served moves the REST of the
    /// file to the pinned per-chunk API route instead and keeps what was written.
    ApiForFile,
    /// The pinned version is gone or changed: discard and restart from fresh
    /// metadata.
    Restart,
    /// An authorization answer. Do not fall back.
    Terminal(Terminal),
    /// A chunk failed authentication twice (once from storage, once from the
    /// API route): a hard error. Never publish partial plaintext.
    Corrupt,
}

/// What the caller must do now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Poll {
    /// `POST /api/v1/files/{id}/download-grants` with this body and the
    /// `X-Beebeeb-Capabilities` header, then report the answer.
    RequestWindow(DownloadGrantRequest),
    /// `GET` `grant.url` with the storage client; accept only `200` whose
    /// `Content-Length` is `grant.length`.
    Fetch { index: u32, grant: ChunkGrant },
    /// `GET /api/v1/files/{id}/chunks/{index}?object_version_id=<pinned>`.
    FetchViaApi { index: u32, object_version_id: String },
    /// Nothing to start. `until_ms` is the next moment the planner can act on
    /// its own (a backoff ends); `None` means it is waiting for a request the
    /// caller has outstanding.
    Wait { until_ms: Option<i64> },
    /// Every chunk has been consumed.
    Done,
    /// Cannot go on directly.
    Stop(Verdict),
}

/// Why a window answer was refused. The text never contains a URL.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Violation {
    #[error("the server did not answer with the transport that was asked for")]
    Transport,
    #[error("the answer is for a different file")]
    FileMismatch,
    #[error("the answer names a different version than the one pinned")]
    VersionChanged,
    #[error("the answer's sizes are not those of any real version")]
    Geometry,
    #[error("the answer's grants are not the window that was asked for")]
    Grants,
    #[error("a grant names a chunk length the geometry does not allow")]
    Length,
    #[error("a grant is not a GET")]
    Method,
    #[error("a grant link was refused: {0}")]
    Authority(Refusal),
    #[error("a grant's expiry is missing, unreadable or inside the renewal margin")]
    Expiry,
    #[error("an answer arrived that no request was waiting for")]
    Unexpected,
}

impl Violation {
    /// Stable machine name (bindings and vectors). A refused link carries the
    /// reason as `authority_<refusal code>`.
    pub fn code(self) -> &'static str {
        match self {
            Violation::Transport => "transport",
            Violation::FileMismatch => "file_mismatch",
            Violation::VersionChanged => "version_changed",
            Violation::Geometry => "geometry",
            Violation::Grants => "grants",
            Violation::Length => "length",
            Violation::Method => "method",
            Violation::Authority(Refusal::Malformed) => "authority_malformed",
            Violation::Authority(Refusal::NotHttps) => "authority_not_https",
            Violation::Authority(Refusal::Userinfo) => "authority_userinfo",
            Violation::Authority(Refusal::IpLiteral) => "authority_ip_literal",
            Violation::Authority(Refusal::Loopback) => "authority_loopback",
            Violation::Authority(Refusal::BadHost) => "authority_bad_host",
            Violation::Authority(Refusal::Port) => "authority_port",
            Violation::Authority(Refusal::HostNotListed) => "authority_host_not_listed",
            Violation::Authority(Refusal::BucketNotListed) => "authority_bucket_not_listed",
            Violation::Authority(Refusal::BadPath) => "authority_bad_path",
            Violation::Expiry => "expiry",
            Violation::Unexpected => "unexpected",
        }
    }
}

/// Why [`DownloadPlanner`] refuses the content of a window answer: [`Violation`] without `Unexpected`, which
/// is a caller's bug (an answer nobody asked for) and never a property of an answer's content. A separate
/// type makes the compiler prove that checking an answer cannot produce it, so `window_answered` has no
/// arm for it that could quietly come to be relied on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Rejected {
    Transport,
    FileMismatch,
    VersionChanged,
    Geometry,
    Grants,
    Length,
    Method,
    Authority(Refusal),
    Expiry,
}

impl From<Rejected> for Violation {
    fn from(rejected: Rejected) -> Self {
        match rejected {
            Rejected::Transport => Violation::Transport,
            Rejected::FileMismatch => Violation::FileMismatch,
            Rejected::VersionChanged => Violation::VersionChanged,
            Rejected::Geometry => Violation::Geometry,
            Rejected::Grants => Violation::Grants,
            Rejected::Length => Violation::Length,
            Rejected::Method => Violation::Method,
            Rejected::Authority(refusal) => Violation::Authority(refusal),
            Rejected::Expiry => Violation::Expiry,
        }
    }
}

/// What became of the body of a window answer ([`DownloadPlanner::window_answered_bytes`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowAnswer {
    /// The window was accepted; poll again.
    Accepted,
    /// The body was not the contract's JSON; the window is treated as one the
    /// server could not serve. Poll again.
    Malformed,
    /// The answer broke the contract; the file's verdict is set. Poll again.
    Refused(Violation),
}

impl WindowAnswer {
    /// Stable machine name (bindings and vectors): `accepted`, `malformed`, or
    /// the [`Violation::code`].
    pub fn code(self) -> &'static str {
        match self {
            WindowAnswer::Accepted => "accepted",
            WindowAnswer::Malformed => "malformed",
            WindowAnswer::Refused(violation) => violation.code(),
        }
    }
}

impl PlanError {
    /// Stable machine name (bindings and vectors).
    pub fn code(self) -> &'static str {
        match self {
            PlanError::NotInFlight(_) => "not_in_flight",
            PlanError::NotFetched(_) => "not_fetched",
            PlanError::OutOfOrder { .. } => "out_of_order",
            PlanError::ApiRouteFailure(_) => "api_route_failure",
        }
    }
}

impl Verdict {
    /// Stable machine name of the variant (bindings and vectors).
    pub fn kind(&self) -> &'static str {
        match self {
            Verdict::ApiForFile => "api_for_file",
            Verdict::Restart => "restart",
            Verdict::Terminal(_) => "terminal",
            Verdict::Corrupt => "corrupt",
        }
    }

    /// How firmly a verdict ends the file: `Corrupt` > `Terminal` > `Restart` > `ApiForFile`. A file
    /// that comes to two verdicts keeps the stronger ([`DownloadPlanner::set_verdict`]).
    fn strength(&self) -> u8 {
        match self {
            Verdict::ApiForFile => 0,
            Verdict::Restart => 1,
            Verdict::Terminal(_) => 2,
            Verdict::Corrupt => 3,
        }
    }
}

impl Poll {
    /// Stable machine name of the variant (bindings and vectors).
    pub fn kind(&self) -> &'static str {
        match self {
            Poll::RequestWindow(_) => "request_window",
            Poll::Fetch { .. } => "fetch",
            Poll::FetchViaApi { .. } => "fetch_via_api",
            Poll::Wait { .. } => "wait",
            Poll::Done => "done",
            Poll::Stop(_) => "stop",
        }
    }
}

/// A call that does not fit the planner's state: a bug in the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PlanError {
    #[error("chunk {0} is not outstanding")]
    NotInFlight(u32),
    #[error("chunk {0} is not waiting to be consumed")]
    NotFetched(u32),
    #[error("chunk {got} consumed out of order (expected {expected})")]
    OutOfOrder { expected: u32, got: u32 },
    #[error("chunk {0} is being fetched through the API route; report its failure with api_fetch_failed")]
    ApiRouteFailure(u32),
}

#[derive(Debug, Clone, Copy, Default)]
struct Attempts {
    renewals: u8,
    auth_failures: u8,
}

#[derive(Debug)]
enum Slot {
    NeedsGrant {
        attempts: Attempts,
        not_before_ms: i64,
    },
    Granted {
        attempts: Attempts,
        grant: ChunkGrant,
        usable_until_ms: i64,
    },
    Fetching {
        attempts: Attempts,
        via_api: bool,
    },
    /// Arrived whole; waits to be decrypted in order. `attempts` is kept so an
    /// authentication failure at decrypt time still counts.
    Fetched {
        attempts: Attempts,
    },
    ApiPending {
        attempts: Attempts,
    },
}

/// The planner for one file. See the module docs.
#[derive(Debug)]
pub struct DownloadPlanner {
    cfg: PlannerConfig,
    discovery: Discovery,
    api_base: String,
    file_id: String,
    geometry: Option<Geometry>,
    pinned: Option<String>,
    /// First index no window has covered yet.
    frontier: u32,
    /// Chunks `0..consumed` are decrypted and written.
    consumed: u32,
    /// Only chunks with something to say; everything else is implicit.
    slots: BTreeMap<u32, Slot>,
    window: Option<DownloadGrantRequest>,
    window_not_before_ms: i64,
    rate_limits: u8,
    /// Set once a window could not be served after the version was pinned: no
    /// more grants are asked for and every chunk still to fetch goes through
    /// the pinned per-chunk API route.
    api_only: bool,
    verdict: Option<Verdict>,
    rng: u64,
}

impl DownloadPlanner {
    /// `file_id` is the UUID string the grants are for; `discovery` and
    /// `api_base` feed the authority check on every grant.
    pub fn new(mut cfg: PlannerConfig, discovery: Discovery, api_base: &str, file_id: &str) -> Self {
        cfg.max_in_flight = cfg.max_in_flight.clamp(1, MAX_IN_FLIGHT);
        cfg.window = cfg.window.clamp(1, super::wire::MAX_WINDOW);
        let rng = splitmix64(cfg.jitter_seed);
        DownloadPlanner {
            cfg,
            discovery,
            api_base: api_base.to_string(),
            file_id: file_id.to_string(),
            geometry: None,
            pinned: None,
            frontier: 0,
            consumed: 0,
            slots: BTreeMap::new(),
            window: None,
            window_not_before_ms: i64::MIN,
            rate_limits: 0,
            api_only: false,
            verdict: None,
            rng,
        }
    }

    /// The version's geometry, once the first window has been accepted.
    pub fn geometry(&self) -> Option<Geometry> {
        self.geometry
    }

    /// The pinned `object_version_id`, once the first window has been accepted.
    pub fn pinned_version(&self) -> Option<&str> {
        self.pinned.as_deref()
    }

    /// Chunk requests (storage or API) currently outstanding.
    pub fn in_flight(&self) -> usize {
        self.slots
            .values()
            .filter(|s| matches!(s, Slot::Fetching { .. }))
            .count()
    }

    /// Grants held and not yet used.
    pub fn unused_grants(&self) -> usize {
        self.slots
            .values()
            .filter(|s| matches!(s, Slot::Granted { .. }))
            .count()
    }

    /// Grants held plus chunks that will get a grant on renewal: what the next
    /// fresh window is measured against.
    fn coverage(&self) -> usize {
        self.slots
            .values()
            .filter(|s| matches!(s, Slot::Granted { .. } | Slot::NeedsGrant { .. }))
            .count()
    }

    /// Chunks decrypted and written so far.
    pub fn consumed_count(&self) -> u32 {
        self.consumed
    }

    /// Slots currently tracked (bounded by the window sizes, never by the file's chunk count).
    pub fn tracked_chunks(&self) -> usize {
        self.slots.len()
    }

    /// What to do now. Call again after every report; each call that returns
    /// work also records it as started.
    pub fn poll(&mut self, now_ms: i64) -> Poll {
        if let Some(verdict) = &self.verdict {
            return Poll::Stop(verdict.clone());
        }
        self.clamp_deadlines(now_ms);
        let Some(geometry) = self.geometry else {
            return self.poll_first_window(now_ms);
        };
        if self.consumed >= geometry.chunk_count {
            return Poll::Done;
        }
        self.age_out_grants(now_ms);

        // A window request goes out BEFORE more fetches start, so it overlaps
        // the transfers already running instead of waiting behind them.
        if self.window.is_none() && now_ms >= self.window_not_before_ms {
            if let Some(request) = self.next_window(geometry, now_ms) {
                self.window = Some(request.clone());
                return Poll::RequestWindow(request);
            }
        }
        if let Some(work) = self.next_fetch(geometry) {
            return work;
        }
        Poll::Wait {
            until_ms: self.next_wake(now_ms),
        }
    }

    fn poll_first_window(&mut self, now_ms: i64) -> Poll {
        if self.window.is_some() {
            return Poll::Wait { until_ms: None };
        }
        if now_ms < self.window_not_before_ms {
            return Poll::Wait {
                until_ms: Some(self.window_not_before_ms),
            };
        }
        let request = DownloadGrantRequest {
            object_version_id: None,
            start_index: 0,
            count: self.cfg.window,
            renewal: false,
        };
        self.window = Some(request.clone());
        Poll::RequestWindow(request)
    }

    /// A clock that stepped BACKWARDS leaves deadlines computed on the old
    /// reading far in the future. No legitimate wait is longer than
    /// [`MAX_WAIT_MS`], and no link outlives the TTL, so pull both in.
    fn clamp_deadlines(&mut self, now_ms: i64) {
        let latest_wait = now_ms.saturating_add(MAX_WAIT_MS);
        let latest_use = now_ms.saturating_add((self.cfg.url_ttl_ms - self.cfg.renew_skew_ms).max(0));
        self.window_not_before_ms = self.window_not_before_ms.min(latest_wait);
        for slot in self.slots.values_mut() {
            match slot {
                Slot::NeedsGrant { not_before_ms, .. } => *not_before_ms = (*not_before_ms).min(latest_wait),
                Slot::Granted { usable_until_ms, .. } => *usable_until_ms = (*usable_until_ms).min(latest_use),
                _ => {}
            }
        }
    }

    /// The reorder window: chunks `consumed .. consumed + max_in_flight`.
    fn limit(&self, geometry: Geometry) -> u32 {
        self.consumed
            .saturating_add(self.cfg.max_in_flight as u32)
            .min(geometry.chunk_count)
    }

    /// A grant that has aged past its usable window is dropped and counts as a
    /// renewal of that chunk (the same budget a failure spends).
    fn age_out_grants(&mut self, now_ms: i64) {
        let max = self.cfg.max_renewals;
        let api_only = self.api_only;
        for slot in self.slots.values_mut() {
            let Slot::Granted {
                attempts,
                usable_until_ms,
                ..
            } = slot
            else {
                continue;
            };
            if *usable_until_ms > now_ms {
                continue;
            }
            let mut attempts = *attempts;
            attempts.renewals = attempts.renewals.saturating_add(1);
            *slot = if attempts.renewals > max || api_only {
                Slot::ApiPending { attempts }
            } else {
                Slot::NeedsGrant {
                    attempts,
                    not_before_ms: now_ms,
                }
            };
        }
    }

    fn next_fetch(&mut self, geometry: Geometry) -> Option<Poll> {
        if self.in_flight() >= self.cfg.max_in_flight {
            return None;
        }
        let limit = self.limit(geometry);
        if self.api_only {
            // No grants are coming: every chunk within reach that has nothing
            // yet is simply fetched through the pinned API route.
            for index in self.consumed..limit {
                self.slots.entry(index).or_insert(Slot::ApiPending {
                    attempts: Attempts::default(),
                });
            }
        }
        let index = self
            .slots
            .range(self.consumed..limit)
            .find(|(_, s)| matches!(s, Slot::Granted { .. } | Slot::ApiPending { .. }))
            .map(|(i, _)| *i)?;
        let slot = self.slots.get_mut(&index)?;
        let old = std::mem::replace(
            slot,
            Slot::Fetching {
                attempts: Attempts::default(),
                via_api: false,
            },
        );
        match old {
            Slot::Granted { attempts, grant, .. } => {
                *slot = Slot::Fetching {
                    attempts,
                    via_api: false,
                };
                Some(Poll::Fetch { index, grant })
            }
            Slot::ApiPending { attempts } => {
                *slot = Slot::Fetching {
                    attempts,
                    via_api: true,
                };
                Some(Poll::FetchViaApi {
                    index,
                    object_version_id: self.pinned.clone().unwrap_or_default(),
                })
            }
            other => {
                *slot = other;
                None
            }
        }
    }

    fn next_window(&self, geometry: Geometry, now_ms: i64) -> Option<DownloadGrantRequest> {
        if self.api_only {
            return None;
        }
        let pinned = self.pinned.clone()?;
        // Renewals first: they are what the consumer is waiting for.
        let limit = self.limit(geometry);
        let ready = |slot: &Slot| matches!(slot, Slot::NeedsGrant { not_before_ms, .. } if *not_before_ms <= now_ms);
        let first = self
            .slots
            .range(self.consumed..limit)
            .find(|(_, s)| ready(s))
            .map(|(i, _)| *i);
        if let Some(start) = first {
            let mut count = 0u32;
            while count < self.cfg.window
                && start + count < limit
                && self.slots.get(&(start + count)).is_some_and(ready)
            {
                count += 1;
            }
            return Some(DownloadGrantRequest {
                object_version_id: Some(pinned),
                start_index: start,
                count,
                renewal: true,
            });
        }
        // Coverage = grants held + chunks waiting for a renewal. Counting the
        // latter keeps grants that aged out behind a stalled chunk from
        // triggering fresh windows nobody can use yet.
        if self.frontier < geometry.chunk_count && self.coverage() <= self.cfg.refill_at {
            return Some(DownloadGrantRequest {
                object_version_id: Some(pinned),
                start_index: self.frontier,
                count: self.cfg.window.min(geometry.chunk_count - self.frontier),
                renewal: false,
            });
        }
        None
    }

    /// The next moment the planner can act without being told something.
    fn next_wake(&self, now_ms: i64) -> Option<i64> {
        let mut wake: Option<i64> = None;
        let mut note = |t: i64| {
            if t > now_ms {
                wake = Some(wake.map_or(t, |w| w.min(t)));
            }
        };
        if self.window.is_none() {
            note(self.window_not_before_ms);
            for slot in self.slots.values() {
                if let Slot::NeedsGrant { not_before_ms, .. } = slot {
                    note(*not_before_ms);
                }
            }
        }
        wake
    }

    /// The one place a verdict is written. A file can come to more than one (a stale or repeated
    /// window answer, a failure reported out of order, a chunk that fails after the window did), and
    /// the strongest stands: `Corrupt` > `Terminal` > `Restart` > `ApiForFile`. A stronger verdict may
    /// replace a weaker one; a weaker or equal one never replaces what is there. Otherwise a late
    /// answer could turn a chunk that does not authenticate, a revoked grant or a changed version
    /// into "use the API", which would hide it.
    fn set_verdict(&mut self, verdict: Verdict) {
        let stronger = self
            .verdict
            .as_ref()
            .is_none_or(|current| verdict.strength() > current.strength());
        if stronger {
            self.verdict = Some(verdict);
        }
    }

    /// The window answer for the outstanding request. `Err` means the answer
    /// was refused and the file's verdict is set (see [`DownloadPlanner::poll`]);
    /// a stronger verdict that was already set stands (`Corrupt` > `Terminal` > `Restart` > `ApiForFile`).
    pub fn window_answered(&mut self, response: DownloadGrantResponse, now_ms: i64) -> Result<(), Violation> {
        let Some(request) = self.window.take() else {
            self.set_verdict(Verdict::ApiForFile);
            return Err(Violation::Unexpected);
        };
        match self.accept(&request, response, now_ms) {
            Ok(()) => {
                self.rate_limits = 0;
                Ok(())
            }
            Err(Rejected::VersionChanged) => {
                self.set_verdict(Verdict::Restart);
                Err(Violation::VersionChanged)
            }
            Err(rejected) => {
                self.window_unusable();
                Err(rejected.into())
            }
        }
    }

    /// The 2xx body of the outstanding window request, as it came off the wire:
    /// decode it and judge it. A body that is not the contract's JSON is handled
    /// like any window the server could not serve ([`DownloadPlanner::window_malformed`]),
    /// so no client decides that for itself.
    ///
    /// An answer with no window request outstanding is a bug in the caller, and gets the verdict
    /// [`DownloadPlanner::window_answered`] gives it whatever the body is: [`Violation::Unexpected`],
    /// and the file goes to the API path (undecodable bytes are not "malformed" then, and the file
    /// does not carry on through the pinned route).
    pub fn window_answered_bytes(&mut self, body: &[u8], now_ms: i64) -> WindowAnswer {
        if self.window.is_none() {
            self.set_verdict(Verdict::ApiForFile);
            return WindowAnswer::Refused(Violation::Unexpected);
        }
        match DownloadGrantResponse::from_json(body) {
            Err(_) => {
                self.window_malformed();
                WindowAnswer::Malformed
            }
            Ok(response) => match self.window_answered(response, now_ms) {
                Ok(()) => WindowAnswer::Accepted,
                Err(violation) => WindowAnswer::Refused(violation),
            },
        }
    }

    /// A window request got an answer that cannot be decoded at all (a 2xx whose
    /// body is not the contract's JSON). Handled like any window the server
    /// could not serve.
    pub fn window_malformed(&mut self) {
        self.window = None;
        self.window_unusable();
    }

    /// A window could not be served and nothing says the file is gone: before
    /// the version is pinned nothing is written, so the file goes to the API
    /// path; after, the remaining chunks go to the pinned per-chunk API route
    /// and what was written stays (R1.6: the mixed-node rollout case).
    fn window_unusable(&mut self) {
        if self.pinned.is_none() {
            self.set_verdict(Verdict::ApiForFile);
            return;
        }
        self.api_only = true;
        for slot in self.slots.values_mut() {
            if let Slot::NeedsGrant { attempts, .. } = slot {
                *slot = Slot::ApiPending { attempts: *attempts };
            }
        }
    }

    fn accept(
        &mut self,
        request: &DownloadGrantRequest,
        response: DownloadGrantResponse,
        now_ms: i64,
    ) -> Result<(), Rejected> {
        if response.transport != CAP_OBJECT_DOWNLOAD_V1 {
            return Err(Rejected::Transport);
        }
        if !response.file_id.eq_ignore_ascii_case(&self.file_id) {
            return Err(Rejected::FileMismatch);
        }
        if response.object_version_id.is_empty() {
            return Err(Rejected::Geometry);
        }
        if let Some(pin) = request.object_version_id.as_ref().or(self.pinned.as_ref())
            && !response.object_version_id.eq_ignore_ascii_case(pin)
        {
            return Err(Rejected::VersionChanged);
        }
        let geometry = Geometry {
            chunk_count: response.chunk_count,
            chunk_size: response.chunk_size,
            encrypted_size: response.encrypted_size,
            original_size: response.original_size,
        };
        if !geometry.is_consistent() || self.geometry.is_some_and(|known| known != geometry) {
            return Err(Rejected::Geometry);
        }

        let start = request.start_index;
        if start >= geometry.chunk_count {
            return Err(Rejected::Grants);
        }
        let end = (u64::from(start) + u64::from(request.count)).min(u64::from(geometry.chunk_count)) as u32;
        if response.grants.len() != (end - start) as usize {
            return Err(Rejected::Grants);
        }
        if response.next_index != (end < geometry.chunk_count).then_some(end) {
            return Err(Rejected::Grants);
        }

        let mut accepted = Vec::with_capacity(response.grants.len());
        for (offset, grant) in response.grants.into_iter().enumerate() {
            if grant.index != start + offset as u32 {
                return Err(Rejected::Grants);
            }
            if grant.method != "GET" {
                return Err(Rejected::Method);
            }
            if Some(grant.length) != geometry.chunk_length(grant.index) {
                return Err(Rejected::Length);
            }
            check_storage_url(&grant.url, &self.discovery, &self.api_base).map_err(Rejected::Authority)?;
            let usable_until_ms = self.usable_until(&grant.expires_at, now_ms)?;
            accepted.push((grant, usable_until_ms));
        }

        // Everything checked: commit.
        if self.geometry.is_none() {
            self.geometry = Some(geometry);
            self.pinned = Some(response.object_version_id);
        }
        for (grant, usable_until_ms) in accepted {
            let index = grant.index;
            if index < self.consumed {
                continue;
            }
            let attempts = match self.slots.get(&index) {
                None => Attempts::default(),
                Some(Slot::NeedsGrant { attempts, .. } | Slot::Granted { attempts, .. }) => *attempts,
                // Already being fetched, fetched or API-bound: keep it.
                Some(_) => continue,
            };
            self.slots.insert(
                index,
                Slot::Granted {
                    attempts,
                    grant,
                    usable_until_ms,
                },
            );
        }
        self.frontier = self.frontier.max(end);
        Ok(())
    }

    /// When a grant that arrived at `now_ms` stops being usable, on the client clock.
    fn usable_until(&self, expires_at: &str, now_ms: i64) -> Result<i64, Rejected> {
        let expires_ms = DateTime::parse_from_rfc3339(expires_at)
            .map_err(|_| Rejected::Expiry)?
            .timestamp_millis();
        let ttl = self.cfg.url_ttl_ms;
        let skew = self.cfg.renew_skew_ms;
        let stated = expires_ms.saturating_sub(now_ms);
        // A link never lives longer than the TTL, and no server issues links
        // shorter than a minute: a stated lifetime under that is this clock
        // running ahead, so the lifetime counts from the arrival instead.
        let lifetime = if stated >= MIN_STATED_LIFETIME_MS.min(ttl) {
            stated.min(ttl)
        } else {
            ttl
        };
        let usable_until = now_ms.saturating_add(lifetime).saturating_sub(skew);
        if usable_until <= now_ms {
            return Err(Rejected::Expiry);
        }
        Ok(usable_until)
    }

    /// The outstanding window request failed; `outcome` is what
    /// [`super::classify`] said about the answer.
    pub fn window_failed(&mut self, outcome: Outcome, now_ms: i64) {
        self.window = None;
        match outcome {
            Outcome::Backoff(wait) => {
                self.rate_limits = self.rate_limits.saturating_add(1);
                if self.rate_limits > self.cfg.max_rate_limits {
                    self.window_unusable();
                } else {
                    let wait_ms = i64::try_from(wait.as_millis()).unwrap_or(i64::MAX).min(MAX_WAIT_MS);
                    self.window_not_before_ms = self.window_not_before_ms.max(now_ms.saturating_add(wait_ms));
                }
            }
            Outcome::Restart => self.set_verdict(Verdict::Restart),
            Outcome::Terminal(terminal) => self.set_verdict(Verdict::Terminal(terminal)),
            // Not a failure (a caller bug), or any routing answer: the API serves this file.
            _ => self.window_unusable(),
        }
    }

    /// Chunk `index` arrived whole (status and length checked). It now waits
    /// to be decrypted in order.
    pub fn fetch_ok(&mut self, index: u32) -> Result<(), PlanError> {
        let Some(Slot::Fetching { attempts, .. }) = self.slots.get(&index) else {
            return Err(PlanError::NotInFlight(index));
        };
        let attempts = *attempts;
        self.slots.insert(index, Slot::Fetched { attempts });
        Ok(())
    }

    /// The transfer of chunk `index` from storage failed: a non-200, a short
    /// body, a length that is not the grant's `length`, a connection error, a
    /// 404 after a migration, a 403 from an expired link (R1.13: one defined
    /// fallback). It is renewed (bounded, with backoff) and then goes to the
    /// pinned API route.
    ///
    /// A failure on the API route itself is reported with
    /// [`DownloadPlanner::api_fetch_failed`]; here it is an error.
    pub fn fetch_failed(&mut self, index: u32, now_ms: i64) -> Result<(), PlanError> {
        let Some(Slot::Fetching { attempts, via_api }) = self.slots.get(&index) else {
            return Err(PlanError::NotInFlight(index));
        };
        let (mut attempts, via_api) = (*attempts, *via_api);
        if via_api {
            return Err(PlanError::ApiRouteFailure(index));
        }
        attempts.renewals = attempts.renewals.saturating_add(1);
        if attempts.renewals > self.cfg.max_renewals || self.api_only {
            self.slots.insert(index, Slot::ApiPending { attempts });
        } else {
            let delay = self.backoff_ms(attempts.renewals);
            self.slots.insert(
                index,
                Slot::NeedsGrant {
                    attempts,
                    not_before_ms: now_ms.saturating_add(delay),
                },
            );
        }
        Ok(())
    }

    /// The fetch of chunk `index` through the pinned API route failed (network,
    /// 5xx, a length that is not the manifest's) after the caller's own retries.
    /// There is nothing left to try per chunk: the file ends with
    /// [`Verdict::ApiForFile`] (the caller restarts it on the API stream) and
    /// the chunk's slot is freed. 401/403 and 409 on that route are the
    /// caller's to turn into errors, not reported here.
    pub fn api_fetch_failed(&mut self, index: u32) -> Result<(), PlanError> {
        match self.slots.get(&index) {
            Some(Slot::Fetching { via_api: true, .. }) => {
                self.slots.remove(&index);
                self.set_verdict(Verdict::ApiForFile);
                Ok(())
            }
            _ => Err(PlanError::NotInFlight(index)),
        }
    }

    /// Chunk `index` arrived whole but did not authenticate when it was
    /// decrypted. It is fetched once through the pinned API route; if that copy
    /// does not authenticate either, the file ends with [`Verdict::Corrupt`].
    /// Never publish partial plaintext on that verdict.
    pub fn chunk_unauthentic(&mut self, index: u32) -> Result<(), PlanError> {
        let Some(Slot::Fetched { attempts }) = self.slots.get(&index) else {
            return Err(PlanError::NotFetched(index));
        };
        let mut attempts = *attempts;
        attempts.auth_failures = attempts.auth_failures.saturating_add(1);
        if attempts.auth_failures >= 2 {
            self.set_verdict(Verdict::Corrupt);
            self.slots.remove(&index);
        } else {
            self.slots.insert(index, Slot::ApiPending { attempts });
        }
        Ok(())
    }

    /// Chunk `index` has been decrypted and written. Strictly in order.
    pub fn consumed(&mut self, index: u32) -> Result<(), PlanError> {
        if index != self.consumed {
            return Err(PlanError::OutOfOrder {
                expected: self.consumed,
                got: index,
            });
        }
        match self.slots.get(&index) {
            Some(Slot::Fetched { .. }) => {
                self.slots.remove(&index);
                self.consumed += 1;
                Ok(())
            }
            _ => Err(PlanError::NotFetched(index)),
        }
    }

    /// Equal jitter: half the exponential delay plus a random share of the other half.
    fn backoff_ms(&mut self, attempt: u8) -> i64 {
        let shift = u32::from(attempt.saturating_sub(1)).min(20);
        let exp = self
            .cfg
            .backoff_base_ms
            .saturating_mul(1u64 << shift)
            .min(self.cfg.backoff_cap_ms);
        let half = exp / 2;
        let jitter = if half == 0 { 0 } else { self.next_random() % (half + 1) };
        i64::try_from(half + jitter).unwrap_or(i64::MAX)
    }

    /// xorshift64*: deterministic for a given seed, which is the point.
    fn next_random(&mut self) -> u64 {
        let mut x = self.rng;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.rng = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
}

/// Scramble a seed into a nonzero xorshift state; neighbouring seeds must not
/// give neighbouring (or equal) streams.
fn splitmix64(seed: u64) -> u64 {
    let mut z = seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^= z >> 31;
    if z == 0 { 0x9E37_79B9_7F4A_7C15 } else { z }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::super::wire::StorageBucket;
    use super::*;

    const API: &str = "https://api.beebeeb.test";
    const FILE: &str = "11111111-1111-4111-8111-111111111111";
    const VERSION: &str = "22222222-2222-4222-8222-222222222222";
    const T0: i64 = 1_800_000_000_000; // 2027-01-15, Unix ms
    const STRIDE: u64 = 1000;
    /// Upper bound of any drive loop: a broken planner fails an assertion instead of hanging the suite.
    const STEPS: usize = 5_000;
    const CHUNKS: u32 = 20;
    const LAST_PLAIN: u64 = 500;

    fn geometry() -> Geometry {
        let original = STRIDE * u64::from(CHUNKS - 1) + LAST_PLAIN;
        Geometry {
            chunk_count: CHUNKS,
            chunk_size: STRIDE,
            encrypted_size: original + CHUNK_OVERHEAD * u64::from(CHUNKS),
            original_size: original,
        }
    }

    fn discovery() -> Discovery {
        Discovery {
            download: vec![CAP_OBJECT_DOWNLOAD_V1.into()],
            storage_hosts: vec!["s3.storage.test".into()],
            storage_buckets: vec![StorageBucket {
                host: "s3.storage.test".into(),
                bucket: "bb-01".into(),
            }],
            ..Default::default()
        }
    }

    fn rfc3339(ms: i64) -> String {
        DateTime::from_timestamp_millis(ms)
            .unwrap()
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
    }

    fn planner() -> DownloadPlanner {
        DownloadPlanner::new(PlannerConfig::from_discovery(&discovery(), 7), discovery(), API, FILE)
    }

    /// The server's answer for `request`, issued at `now_ms` with the standard 300 s lifetime.
    fn answer(request: &DownloadGrantRequest, now_ms: i64) -> DownloadGrantResponse {
        let g = geometry();
        let end = (request.start_index + request.count).min(g.chunk_count);
        DownloadGrantResponse {
            transport: CAP_OBJECT_DOWNLOAD_V1.into(),
            file_id: FILE.into(),
            object_version_id: VERSION.into(),
            chunk_count: g.chunk_count,
            chunk_size: g.chunk_size,
            encrypted_size: g.encrypted_size,
            original_size: g.original_size,
            grants: (request.start_index..end)
                .map(|i| ChunkGrant {
                    index: i,
                    method: "GET".into(),
                    url: format!("https://s3.storage.test/bb-01/t/v/{i}.bin?X-Amz-Signature=SIG{i}"),
                    length: g.chunk_length(i).unwrap(),
                    expires_at: rfc3339(now_ms + 300_000),
                })
                .collect(),
            next_index: (end < g.chunk_count).then_some(end),
        }
    }

    fn expect_window(p: &mut DownloadPlanner, now: i64) -> DownloadGrantRequest {
        match p.poll(now) {
            Poll::RequestWindow(r) => r,
            other => panic!("expected a window request, got {other:?}"),
        }
    }

    fn expect_fetch(p: &mut DownloadPlanner, now: i64) -> u32 {
        match p.poll(now) {
            Poll::Fetch { index, .. } => index,
            other => panic!("expected a fetch, got {other:?}"),
        }
    }

    /// Open the transfer: first window answered at `T0`.
    fn started() -> DownloadPlanner {
        let mut p = planner();
        let first = expect_window(&mut p, T0);
        p.window_answered(answer(&first, T0), T0).unwrap();
        p
    }

    // ── first window ──

    #[test]
    fn the_first_request_is_unpinned_at_index_zero() {
        let mut p = planner();
        let r = expect_window(&mut p, T0);
        assert_eq!(
            r,
            DownloadGrantRequest {
                object_version_id: None,
                start_index: 0,
                count: 8,
                renewal: false
            }
        );
        // One request at a time: nothing else is asked while it is outstanding.
        assert_eq!(p.poll(T0), Poll::Wait { until_ms: None });
        assert_eq!(p.poll(T0 + 1), Poll::Wait { until_ms: None });
    }

    #[test]
    fn the_first_answer_pins_the_version_and_the_geometry() {
        let p = started();
        assert_eq!(p.pinned_version(), Some(VERSION));
        assert_eq!(p.geometry(), Some(geometry()));
        assert_eq!(p.unused_grants(), 8);
    }

    // ── in flight and the reorder window ──

    #[test]
    fn at_most_four_chunks_are_outstanding() {
        let mut p = started();
        let mut started_chunks = vec![];
        for _ in 0..4 {
            started_chunks.push(expect_fetch(&mut p, T0));
        }
        assert_eq!(started_chunks, vec![0, 1, 2, 3]);
        assert_eq!(p.in_flight(), 4);
        // The fifth waits for a slot, even though grants are held.
        assert_eq!(p.unused_grants(), 4);
        assert_eq!(p.poll(T0), Poll::Wait { until_ms: None });
        // A slot frees only when the first chunk is consumed in order.
        p.fetch_ok(2).unwrap();
        assert_eq!(
            p.poll(T0),
            Poll::Wait { until_ms: None },
            "chunk 2 done but 0 and 1 not consumed"
        );
        p.fetch_ok(0).unwrap();
        p.consumed(0).unwrap();
        assert_eq!(expect_fetch(&mut p, T0), 4);
    }

    #[test]
    fn a_config_asking_for_more_than_four_in_flight_is_clamped() {
        let mut cfg = PlannerConfig::from_discovery(&discovery(), 7);
        cfg.max_in_flight = 99;
        let mut p = DownloadPlanner::new(cfg, discovery(), API, FILE);
        let first = expect_window(&mut p, T0);
        p.window_answered(answer(&first, T0), T0).unwrap();
        for _ in 0..MAX_IN_FLIGHT {
            expect_fetch(&mut p, T0);
        }
        assert_eq!(p.poll(T0), Poll::Wait { until_ms: None });
        assert_eq!(p.in_flight(), MAX_IN_FLIGHT);
    }

    #[test]
    fn a_config_window_above_the_servers_cap_is_clamped() {
        let mut cfg = PlannerConfig::from_discovery(&discovery(), 7);
        cfg.window = 500;
        let mut p = DownloadPlanner::new(cfg, discovery(), API, FILE);
        let first = expect_window(&mut p, T0);
        assert_eq!(first.count, super::super::wire::MAX_WINDOW);

        let mut cfg = PlannerConfig::from_discovery(&discovery(), 7);
        cfg.window = 0;
        let mut p = DownloadPlanner::new(cfg, discovery(), API, FILE);
        assert_eq!(expect_window(&mut p, T0).count, 1);
    }

    #[test]
    fn a_stalled_first_chunk_bounds_how_far_ahead_the_others_run() {
        let mut p = started();
        for _ in 0..4 {
            expect_fetch(&mut p, T0);
        }
        // 1, 2, 3 finish; 0 is stuck. No fifth request, however long it takes.
        for i in 1..4 {
            p.fetch_ok(i).unwrap();
        }
        assert_eq!(p.in_flight(), 1);
        for step in 1..50 {
            if let Poll::Fetch { index, .. } = p.poll(T0 + step) {
                panic!("dispatched chunk {index} beyond the reorder window");
            }
        }
    }

    #[test]
    fn consuming_out_of_order_or_before_fetched_is_a_caller_bug() {
        let mut p = started();
        for _ in 0..2 {
            expect_fetch(&mut p, T0);
        }
        p.fetch_ok(1).unwrap();
        assert_eq!(p.consumed(1), Err(PlanError::OutOfOrder { expected: 0, got: 1 }));
        assert_eq!(p.consumed(0), Err(PlanError::NotFetched(0)));
        assert_eq!(p.fetch_ok(5), Err(PlanError::NotInFlight(5)));
        assert_eq!(p.fetch_failed(5, T0), Err(PlanError::NotInFlight(5)));
    }

    // ── window refill ──

    /// Mark chunk `index` fetched and consume every chunk that is ready, in order.
    fn finish(p: &mut DownloadPlanner, index: u32) {
        p.fetch_ok(index).unwrap();
        while p.consumed(p.consumed_count()).is_ok() {}
    }

    /// Run the transfer (start, finish and consume chunks) until the planner
    /// asks for its next window; return that request.
    fn drive_to_next_window(p: &mut DownloadPlanner, now: i64) -> DownloadGrantRequest {
        for _ in 0..1000 {
            match p.poll(now) {
                Poll::RequestWindow(r) => return r,
                Poll::Fetch { index, .. } => finish(p, index),
                other => panic!("expected the next window, got {other:?}"),
            }
        }
        panic!("the planner never asked for another window");
    }

    #[test]
    fn the_next_window_is_requested_exactly_when_two_unused_grants_remain() {
        let mut p = started();
        for _ in 0..4 {
            expect_fetch(&mut p, T0);
        }
        // 4 unused, all four slots busy: nothing to do.
        assert_eq!(p.unused_grants(), 4);
        assert_eq!(p.poll(T0), Poll::Wait { until_ms: None });

        // Chunk 0 done: a slot frees; 4 unused > 2, so it goes to fetching chunk 4.
        finish(&mut p, 0);
        assert_eq!(expect_fetch(&mut p, T0), 4);
        assert_eq!(p.unused_grants(), 3);
        assert_eq!(p.poll(T0), Poll::Wait { until_ms: None }, "3 unused: no window yet");

        // Chunk 1 done: the next fetch (chunk 5) leaves 2 unused ...
        finish(&mut p, 1);
        // ... and the window is asked for as soon as 2 remain, before more starts.
        match p.poll(T0) {
            Poll::Fetch { index: 5, .. } => {}
            other => panic!("with 3 unused the next chunk starts first, got {other:?}"),
        }
        assert_eq!(p.unused_grants(), 2);
        match p.poll(T0) {
            Poll::RequestWindow(r) => {
                assert_eq!(r.object_version_id.as_deref(), Some(VERSION));
                assert_eq!((r.start_index, r.count, r.renewal), (8, 8, false));
            }
            other => panic!("expected the refill at 2 unused grants, got {other:?}"),
        }
        // One request at a time.
        assert_eq!(p.poll(T0), Poll::Wait { until_ms: None });
    }

    #[test]
    fn a_window_request_goes_out_before_the_next_fetch_so_it_overlaps_it() {
        let mut p = started();
        for _ in 0..4 {
            expect_fetch(&mut p, T0);
        }
        finish(&mut p, 0);
        finish(&mut p, 1);
        finish(&mut p, 2);
        // 3 slots free, unused = 4: fetch 4, 5 (unused 2), then the refill precedes chunk 6.
        assert_eq!(expect_fetch(&mut p, T0), 4);
        assert_eq!(expect_fetch(&mut p, T0), 5);
        assert!(
            matches!(p.poll(T0), Poll::RequestWindow(_)),
            "refill before chunk 6 starts"
        );
        assert_eq!(
            expect_fetch(&mut p, T0),
            6,
            "and the fetch goes on while the request is out"
        );
    }

    #[test]
    fn the_refill_window_continues_where_the_last_one_ended() {
        let mut p = started();
        let r = drive_to_next_window(&mut p, T0);
        assert_eq!((r.start_index, r.count), (8, 8));
        p.window_answered(answer(&r, T0), T0).unwrap();
        let r = drive_to_next_window(&mut p, T0);
        assert_eq!(
            (r.start_index, r.count),
            (16, 4),
            "clamped to the 20 chunks of the file"
        );
        p.window_answered(answer(&r, T0), T0).unwrap();
        // Everything is covered: no further window, ever.
        for _ in 0..40 {
            match p.poll(T0) {
                Poll::Fetch { index, .. } => finish(&mut p, index),
                Poll::Done => return,
                other => panic!("{other:?}"),
            }
        }
        panic!("never finished");
    }

    #[test]
    fn the_last_window_is_clamped_and_then_nothing_more_is_requested() {
        let mut p = planner();
        let mut now = T0;
        let mut windows = vec![];
        let mut done = false;
        for _ in 0..STEPS {
            match p.poll(now) {
                Poll::RequestWindow(r) => {
                    windows.push((r.start_index, r.count));
                    p.window_answered(answer(&r, now), now).unwrap();
                }
                Poll::Fetch { index, .. } => {
                    p.fetch_ok(index).unwrap();
                    // consume in order as soon as possible
                    while p.consumed(p.consumed_count()).is_ok() {}
                }
                Poll::Done => {
                    done = true;
                    break;
                }
                Poll::Wait { .. } => now += 1,
                other => panic!("{other:?}"),
            }
        }
        assert!(done, "the transfer did not finish within {STEPS} steps");
        assert_eq!(windows, vec![(0, 8), (8, 8), (16, 4)]);
        assert_eq!(p.consumed_count(), CHUNKS);
    }

    #[test]
    fn memory_follows_the_window_not_the_file() {
        // A version of 4 billion tiny chunks: the planner tracks a handful of slots.
        let g = Geometry {
            chunk_count: u32::MAX,
            chunk_size: 1,
            encrypted_size: 29 * u64::from(u32::MAX),
            original_size: u64::from(u32::MAX),
        };
        assert!(g.is_consistent());
        let mut p = planner();
        let r = expect_window(&mut p, T0);
        let mut resp = answer(&r, T0);
        resp.chunk_count = g.chunk_count;
        resp.chunk_size = g.chunk_size;
        resp.encrypted_size = g.encrypted_size;
        resp.original_size = g.original_size;
        for grant in &mut resp.grants {
            grant.length = 29;
        }
        resp.next_index = Some(8);
        p.window_answered(resp, T0).unwrap();
        assert!(p.tracked_chunks() <= 8);
    }

    // ── expiry and renewal ──

    #[test]
    fn a_grant_is_not_used_inside_the_skew_margin_and_is_renewed_instead() {
        let mut p = started();
        // usable until T0 + 300 s - 30 s.
        let edge = T0 + 270_000;
        assert_eq!(
            expect_fetch(&mut p, edge - 1),
            0,
            "one millisecond before the margin: still usable"
        );
        let mut q = started();
        match q.poll(edge) {
            Poll::RequestWindow(r) => {
                assert!(r.renewal);
                assert_eq!(
                    (r.start_index, r.count),
                    (0, 4),
                    "the renewal covers the chunks about to be needed"
                );
                assert_eq!(r.object_version_id.as_deref(), Some(VERSION));
            }
            other => panic!("expected a renewal at the margin, got {other:?}"),
        }
    }

    #[test]
    fn renewals_are_limited_to_the_dispatchable_window_and_the_window_size() {
        let mut p = started();
        // Everything aged out: only the chunks that could start now (0..4) are renewed.
        match p.poll(T0 + 300_000) {
            Poll::RequestWindow(r) => assert_eq!((r.start_index, r.count, r.renewal), (0, 4, true)),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_failed_chunk_is_renewed_with_backoff_then_retried() {
        let mut p = started();
        let fail_at = T0 + 1_000;
        for _ in 0..4 {
            expect_fetch(&mut p, T0);
        }
        p.fetch_failed(0, fail_at).unwrap();
        match p.poll(fail_at) {
            Poll::Wait { until_ms: Some(t) } => {
                let delay = t - fail_at;
                assert!(
                    (125..=250).contains(&delay),
                    "first backoff {delay} ms is within equal-jitter bounds"
                );
            }
            other => panic!("expected a backoff wait, got {other:?}"),
        }
        let ready = fail_at + 250;
        match p.poll(ready) {
            Poll::RequestWindow(r) => assert_eq!((r.start_index, r.count, r.renewal), (0, 1, true)),
            other => panic!("expected the renewal after the backoff, got {other:?}"),
        }
        let renewal = DownloadGrantRequest {
            object_version_id: Some(VERSION.into()),
            start_index: 0,
            count: 1,
            renewal: true,
        };
        p.window_answered(answer(&renewal, ready), ready).unwrap();
        assert_eq!(expect_fetch(&mut p, ready), 0, "the renewed chunk is fetched again");
    }

    /// Fail chunk 0 `times` times in a row, answering each renewal; return the planner.
    fn fail_chunk_zero(times: u8) -> (DownloadPlanner, i64) {
        let mut p = started();
        let mut now = T0;
        for round in 0..times {
            // (re)start chunk 0 and fail it
            let mut fetch = false;
            for _ in 0..STEPS {
                match p.poll(now) {
                    Poll::Fetch { index: 0, .. } => {
                        fetch = true;
                        break;
                    }
                    Poll::Fetch { .. } => {}
                    Poll::RequestWindow(r) => {
                        p.window_answered(answer(&r, now), now).unwrap();
                    }
                    Poll::Wait { until_ms } => now = until_ms.unwrap_or(now + 1),
                    other => panic!("round {round}: {other:?}"),
                }
            }
            assert!(fetch, "round {round}: chunk 0 was never offered to storage");
            p.fetch_failed(0, now).unwrap();
        }
        (p, now)
    }

    #[test]
    fn the_fourth_failure_sends_the_chunk_to_the_api_route() {
        // Three failures are renewed; the budget is spent on the fourth.
        let (mut p, mut now) = fail_chunk_zero(3);
        // Third renewal granted, fourth attempt on storage.
        let mut offered = false;
        for _ in 0..STEPS {
            match p.poll(now) {
                Poll::Fetch { index: 0, .. } => {
                    offered = true;
                    break;
                }
                Poll::Fetch { .. } => {}
                Poll::RequestWindow(r) => {
                    assert!(r.renewal || r.start_index >= 8);
                    p.window_answered(answer(&r, now), now).unwrap();
                }
                Poll::Wait { until_ms } => now = until_ms.unwrap_or(now + 1),
                other => panic!("{other:?}"),
            }
        }
        assert!(offered, "chunk 0 was not offered to storage a fourth time");
        p.fetch_failed(0, now).unwrap();
        let mut via_api = false;
        for _ in 0..STEPS {
            match p.poll(now) {
                Poll::FetchViaApi {
                    index: 0,
                    object_version_id,
                } => {
                    assert_eq!(object_version_id, VERSION);
                    via_api = true;
                    break;
                }
                Poll::Fetch { .. } => {}
                Poll::Wait { until_ms } => now = until_ms.unwrap_or(now + 1),
                Poll::RequestWindow(r) => {
                    assert!(
                        !(r.renewal && r.start_index == 0),
                        "chunk 0 must not be renewed a fourth time"
                    );
                    p.window_answered(answer(&r, now), now).unwrap();
                }
                other => panic!("{other:?}"),
            }
        }
        assert!(via_api, "chunk 0 never went to the pinned API route");
    }

    #[test]
    fn three_failures_still_renew_and_never_reach_the_api() {
        let (mut p, mut now) = fail_chunk_zero(3);
        for _ in 0..200 {
            match p.poll(now) {
                Poll::FetchViaApi { index: 0, .. } => panic!("fell back after only three failures"),
                Poll::Fetch { index: 0, .. } => return,
                Poll::RequestWindow(r) => {
                    p.window_answered(answer(&r, now), now).unwrap();
                }
                Poll::Wait { until_ms } => now = until_ms.unwrap_or(now + 1),
                _ => {}
            }
        }
        panic!("chunk 0 was never offered to storage again after its third failure");
    }

    #[test]
    fn backoff_grows_and_is_deterministic_for_a_seed() {
        let delays = |seed: u64| -> Vec<i64> {
            let mut cfg = PlannerConfig::from_discovery(&discovery(), seed);
            cfg.max_renewals = 10;
            let mut p = DownloadPlanner::new(cfg, discovery(), API, FILE);
            (1..=8).map(|n| p.backoff_ms(n)).collect()
        };
        let a = delays(42);
        assert_eq!(a, delays(42), "same seed, same delays");
        assert_ne!(a, delays(43), "the seed matters");
        let caps = [250, 500, 1000, 2000, 4000, 8000, 8000, 8000];
        for (n, (delay, cap)) in a.iter().zip(caps).enumerate() {
            assert!(
                (cap / 2..=cap).contains(delay),
                "attempt {} delay {delay} outside [{}, {cap}]",
                n + 1,
                cap / 2
            );
        }
    }

    // ── authentication failures ──

    /// Start chunk 0, let it arrive, and report that it did not authenticate.
    fn fetched_but_unauthentic(p: &mut DownloadPlanner) {
        expect_fetch(p, T0);
        p.fetch_ok(0).unwrap();
        p.chunk_unauthentic(0).unwrap();
    }

    #[test]
    fn an_unauthentic_chunk_is_refetched_once_through_the_api_then_is_a_hard_error() {
        let mut p = started();
        fetched_but_unauthentic(&mut p);
        match p.poll(T0) {
            Poll::FetchViaApi {
                index,
                object_version_id,
            } => {
                assert_eq!((index, object_version_id.as_str()), (0, VERSION));
            }
            other => panic!("expected the API re-fetch, got {other:?}"),
        }
        p.fetch_ok(0).unwrap();
        p.chunk_unauthentic(0).unwrap();
        assert_eq!(p.poll(T0), Poll::Stop(Verdict::Corrupt));
        assert_eq!(p.poll(T0 + 1), Poll::Stop(Verdict::Corrupt), "the verdict sticks");
    }

    #[test]
    fn a_chunk_that_authenticates_on_the_api_route_goes_on() {
        let mut p = started();
        fetched_but_unauthentic(&mut p);
        assert!(matches!(p.poll(T0), Poll::FetchViaApi { index: 0, .. }));
        p.fetch_ok(0).unwrap();
        p.consumed(0).unwrap();
        assert_eq!(p.consumed_count(), 1);
    }

    #[test]
    fn an_unauthentic_chunk_that_arrived_after_storage_failures_still_gets_its_one_api_copy() {
        // Two storage failures first, then it arrives and fails to open: the budget of
        // authentication failures is separate from the renewal budget.
        let (mut p, mut now) = fail_chunk_zero(2);
        let mut offered = false;
        for _ in 0..STEPS {
            match p.poll(now) {
                Poll::Fetch { index: 0, .. } => {
                    offered = true;
                    break;
                }
                Poll::RequestWindow(r) => {
                    p.window_answered(answer(&r, now), now).unwrap();
                }
                Poll::Wait { until_ms } => now = until_ms.unwrap_or(now + 1),
                Poll::Fetch { .. } => {}
                other => panic!("{other:?}"),
            }
        }
        assert!(offered, "chunk 0 was not offered to storage again");
        p.fetch_ok(0).unwrap();
        p.chunk_unauthentic(0).unwrap();
        assert!(matches!(p.poll(now), Poll::FetchViaApi { index: 0, .. }));
    }

    #[test]
    fn api_route_transport_failures_are_the_callers_to_handle() {
        let mut p = started();
        fetched_but_unauthentic(&mut p);
        assert!(matches!(p.poll(T0), Poll::FetchViaApi { .. }));
        assert_eq!(p.fetch_failed(0, T0), Err(PlanError::ApiRouteFailure(0)));
    }

    #[test]
    fn unauthentic_is_only_valid_for_a_chunk_that_arrived() {
        let mut p = started();
        assert_eq!(p.chunk_unauthentic(0), Err(PlanError::NotFetched(0)), "not started");
        expect_fetch(&mut p, T0);
        assert_eq!(p.chunk_unauthentic(0), Err(PlanError::NotFetched(0)), "still in flight");
    }

    // ── window failures ──

    #[test]
    fn window_failures_map_to_verdicts() {
        let t = |status| Terminal { status, error: None };
        let cases: Vec<(Outcome, Verdict)> = vec![
            (Outcome::ApiForThisFile, Verdict::ApiForFile),
            (Outcome::UseApiNow, Verdict::ApiForFile),
            (Outcome::NotSupported, Verdict::ApiForFile),
            (Outcome::Restart, Verdict::Restart),
            (Outcome::Terminal(t(403)), Verdict::Terminal(t(403))),
            (Outcome::Proceed, Verdict::ApiForFile),
            (Outcome::Retry, Verdict::ApiForFile),
        ];
        for (outcome, want) in cases {
            let mut p = planner();
            expect_window(&mut p, T0);
            p.window_failed(outcome.clone(), T0);
            assert_eq!(p.poll(T0), Poll::Stop(want), "{outcome:?}");
        }
    }

    // ── a window that cannot be served after the version is pinned (R1.6) ──

    /// Poll until a window is requested, finishing fetches and advancing the clock meanwhile.
    fn next_window_request(p: &mut DownloadPlanner, now: &mut i64) -> DownloadGrantRequest {
        for _ in 0..STEPS {
            match p.poll(*now) {
                Poll::RequestWindow(r) => return r,
                Poll::Fetch { index, .. } => finish(p, index),
                Poll::Wait { until_ms } => *now = until_ms.unwrap_or(*now + 1),
                other => panic!("expected the next window, got {other:?}"),
            }
        }
        panic!("no window was requested");
    }

    /// Run the file to its end, serving every fetch; returns the chunks that went through the
    /// pinned API route and how many windows were still requested.
    fn run_to_the_end(p: &mut DownloadPlanner, now: &mut i64) -> (Vec<u32>, usize) {
        let (mut via_api, mut windows) = (vec![], 0);
        for _ in 0..STEPS {
            match p.poll(*now) {
                Poll::Fetch { index, .. } => finish(p, index),
                Poll::FetchViaApi {
                    index,
                    object_version_id,
                } => {
                    assert_eq!(object_version_id, VERSION, "the pin travels with every API fetch");
                    via_api.push(index);
                    finish(p, index);
                }
                Poll::RequestWindow(r) => {
                    windows += 1;
                    p.window_answered(answer(&r, *now), *now).unwrap();
                }
                Poll::Wait { until_ms } => *now = until_ms.unwrap_or(*now + 1),
                Poll::Done => return (via_api, windows),
                Poll::Stop(v) => panic!("stopped: {v:?}"),
            }
        }
        panic!("the file did not finish");
    }

    #[test]
    fn a_window_that_cannot_be_served_after_pinning_moves_the_rest_to_the_pinned_api_route() {
        // Every way a window can fail without saying the file is gone or forbidden.
        type Fail = fn(&mut DownloadPlanner, i64);
        let fails: Vec<(&str, Fail)> = vec![
            ("409 direct_unavailable", |p, now| {
                p.window_failed(Outcome::ApiForThisFile, now)
            }),
            ("bare 404 / 5xx / network", |p, now| {
                p.window_failed(Outcome::UseApiNow, now)
            }),
            ("not supported", |p, now| p.window_failed(Outcome::NotSupported, now)),
            ("a 2xx that does not decode", |p, _| p.window_malformed()),
        ];
        for (what, fail) in fails {
            let mut p = started();
            let mut now = T0;
            let r = next_window_request(&mut p, &mut now);
            assert_eq!(r.start_index, 8, "{what}");
            fail(&mut p, now);
            let (via_api, windows) = run_to_the_end(&mut p, &mut now);
            assert_eq!(windows, 0, "{what}: no further window is requested");
            assert_eq!(
                via_api,
                (8..CHUNKS).collect::<Vec<_>>(),
                "{what}: exactly the chunks without a grant go to the pinned route, in order"
            );
            assert_eq!(p.consumed_count(), CHUNKS, "{what}: the written chunks are kept");
        }
    }

    #[test]
    fn running_out_of_429s_after_pinning_also_moves_the_rest_to_the_api_route() {
        let mut p = started();
        let mut now = T0;
        for n in 1..=6 {
            let r = next_window_request(&mut p, &mut now);
            assert_eq!(r.start_index, 8, "attempt {n}");
            p.window_failed(Outcome::Backoff(Duration::from_secs(1)), now);
        }
        let (via_api, windows) = run_to_the_end(&mut p, &mut now);
        assert_eq!((windows, via_api), (0, (8..CHUNKS).collect::<Vec<_>>()));
    }

    #[test]
    fn a_bad_window_after_pinning_is_not_trusted_but_does_not_end_the_file() {
        // A later window that names an unlisted host (or any other broken answer, except a changed
        // version): the grants are dropped, the rest goes to the pinned route.
        let mut p = started();
        let mut now = T0;
        let r = next_window_request(&mut p, &mut now);
        let mut bad = answer(&r, now);
        bad.grants[1].url = "https://evil.storage.test/bb-01/k?s=1".into();
        assert_eq!(
            p.window_answered(bad, now),
            Err(Violation::Authority(Refusal::HostNotListed))
        );
        let (via_api, windows) = run_to_the_end(&mut p, &mut now);
        assert_eq!((windows, via_api), (0, (8..CHUNKS).collect::<Vec<_>>()));
    }

    #[test]
    fn restart_and_terminal_stay_final_after_pinning() {
        let mut p = started();
        let mut now = T0;
        next_window_request(&mut p, &mut now);
        p.window_failed(Outcome::Restart, now);
        assert_eq!(p.poll(now), Poll::Stop(Verdict::Restart));

        let t = Terminal {
            status: 403,
            error: None,
        };
        let mut q = started();
        let mut now = T0;
        next_window_request(&mut q, &mut now);
        q.window_failed(Outcome::Terminal(t.clone()), now);
        assert_eq!(q.poll(now), Poll::Stop(Verdict::Terminal(t)));
    }

    #[test]
    fn a_grant_that_ages_out_after_grants_stopped_goes_to_the_api_route() {
        let mut p = started();
        for _ in 0..4 {
            expect_fetch(&mut p, T0);
        }
        for i in 0..4 {
            finish(&mut p, i);
        }
        p.window_malformed(); // grants stop; 4..8 are held and unused
        match p.poll(T0 + 300_000) {
            Poll::FetchViaApi { index: 4, .. } => {}
            other => panic!("an aged-out grant must not wait for a renewal that cannot come, got {other:?}"),
        }
    }

    #[test]
    fn a_chunk_waiting_for_a_renewal_goes_to_the_api_route_when_grants_stop() {
        let mut p = started();
        for _ in 0..4 {
            expect_fetch(&mut p, T0);
        }
        p.fetch_failed(1, T0).unwrap(); // waits for a renewal, with a backoff
        p.window_malformed(); // grants stop for this file
        match p.poll(T0) {
            Poll::FetchViaApi { index: 1, .. } => {}
            other => panic!("the waiting chunk must not wait for a renewal that cannot come, got {other:?}"),
        }
    }

    #[test]
    fn a_huge_retry_after_is_capped_by_the_planner_too() {
        let mut p = planner();
        expect_window(&mut p, T0);
        p.window_failed(Outcome::Backoff(Duration::from_secs(86_400)), T0);
        assert_eq!(
            p.poll(T0 + 1),
            Poll::Wait {
                until_ms: Some(T0 + MAX_WAIT_MS)
            }
        );
    }

    #[test]
    fn a_malformed_first_window_sends_the_file_to_the_api_path() {
        let mut p = planner();
        expect_window(&mut p, T0);
        p.window_malformed();
        assert_eq!(
            p.poll(T0),
            Poll::Stop(Verdict::ApiForFile),
            "nothing is pinned, nothing is written"
        );
    }

    #[test]
    fn a_failed_api_route_fetch_ends_the_file_and_frees_its_slot() {
        let mut p = started();
        fetched_but_unauthentic(&mut p);
        assert!(matches!(p.poll(T0), Poll::FetchViaApi { index: 0, .. }));
        assert_eq!(p.in_flight(), 1);
        p.api_fetch_failed(0).unwrap();
        assert_eq!(p.in_flight(), 0, "the slot is free");
        assert_eq!(p.poll(T0), Poll::Stop(Verdict::ApiForFile));
        // Only a chunk that is being fetched through the API route can fail that way.
        let mut q = started();
        expect_fetch(&mut q, T0);
        assert_eq!(q.api_fetch_failed(0), Err(PlanError::NotInFlight(0)), "a storage fetch");
        assert_eq!(
            q.api_fetch_failed(9),
            Err(PlanError::NotInFlight(9)),
            "nothing outstanding"
        );
    }

    #[test]
    fn storage_failures_after_the_window_gave_up_go_straight_to_the_api_route() {
        let mut p = started();
        for _ in 0..4 {
            expect_fetch(&mut p, T0);
        }
        assert_eq!(p.poll(T0), Poll::Wait { until_ms: None }, "nothing is due");
        p.window_malformed(); // grants have stopped for this file
        p.fetch_failed(0, T0).unwrap();
        match p.poll(T0) {
            Poll::FetchViaApi { index: 0, .. } => {}
            other => panic!("no renewal is scheduled once grants have stopped, got {other:?}"),
        }
    }

    #[test]
    fn a_429_waits_then_asks_again_and_gives_up_after_five() {
        let mut p = planner();
        let mut now = T0;
        for n in 1..=5u8 {
            expect_window(&mut p, now);
            p.window_failed(Outcome::Backoff(Duration::from_secs(10)), now);
            assert_eq!(
                p.poll(now + 9_999),
                Poll::Wait {
                    until_ms: Some(now + 10_000)
                },
                "429 #{n}"
            );
            now += 10_000;
        }
        expect_window(&mut p, now);
        p.window_failed(Outcome::Backoff(Duration::from_secs(10)), now);
        assert_eq!(
            p.poll(now),
            Poll::Stop(Verdict::ApiForFile),
            "the sixth 429 in a row ends direct transport"
        );
    }

    #[test]
    fn a_successful_window_resets_the_429_count() {
        let mut p = planner();
        let mut now = T0;
        for _ in 0..3 {
            expect_window(&mut p, now);
            p.window_failed(Outcome::Backoff(Duration::from_secs(1)), now);
            now += 1_000;
        }
        let r = expect_window(&mut p, now);
        p.window_answered(answer(&r, now), now).unwrap();
        // Drive to the next window and fail it five more times without giving up.
        let mut fails = 0;
        for _ in 0..2000 {
            match p.poll(now) {
                Poll::RequestWindow(r) => {
                    if fails < 5 {
                        p.window_failed(Outcome::Backoff(Duration::from_secs(1)), now);
                        fails += 1;
                    } else {
                        p.window_answered(answer(&r, now), now).unwrap();
                        return;
                    }
                }
                Poll::Fetch { index, .. } => {
                    p.fetch_ok(index).unwrap();
                    while p.consumed(p.consumed_count()).is_ok() {}
                }
                Poll::Wait { until_ms } => now = until_ms.unwrap_or(now + 1),
                Poll::Stop(v) => panic!("gave up too early: {v:?} after {fails} failures"),
                other => panic!("{other:?}"),
            }
        }
        panic!("never reached the refill");
    }

    // ── answer validation ──

    fn first_answer() -> (DownloadPlanner, DownloadGrantRequest, DownloadGrantResponse) {
        let mut p = planner();
        let r = expect_window(&mut p, T0);
        let a = answer(&r, T0);
        (p, r, a)
    }

    fn refuses(mutate: impl FnOnce(&mut DownloadGrantResponse), want: Violation, verdict: Verdict) {
        let (mut p, _r, mut a) = first_answer();
        mutate(&mut a);
        assert_eq!(p.window_answered(a, T0), Err(want));
        assert_eq!(p.poll(T0), Poll::Stop(verdict), "{want:?}");
        assert_eq!(p.geometry(), None, "a refused answer pins nothing");
    }

    #[test]
    fn answers_that_break_the_contract_are_refused() {
        use Verdict::ApiForFile as Api;
        refuses(|a| a.transport = "object-download-v2".into(), Violation::Transport, Api);
        refuses(|a| a.transport.clear(), Violation::Transport, Api);
        refuses(
            |a| a.file_id = "33333333-3333-4333-8333-333333333333".into(),
            Violation::FileMismatch,
            Api,
        );
        refuses(|a| a.object_version_id.clear(), Violation::Geometry, Api);
        refuses(|a| a.chunk_count = 0, Violation::Geometry, Api);
        refuses(|a| a.encrypted_size += 1, Violation::Geometry, Api);
        refuses(|a| a.original_size += 1, Violation::Geometry, Api);
        refuses(|a| a.chunk_size = MAX_CHUNK_SIZE + 1, Violation::Geometry, Api);
        refuses(
            |a| {
                a.grants.pop();
            },
            Violation::Grants,
            Api,
        );
        refuses(
            |a| {
                let g = a.grants[0].clone();
                a.grants.push(g);
            },
            Violation::Grants,
            Api,
        );
        refuses(|a| a.grants[3].index = 4, Violation::Grants, Api);
        refuses(|a| a.grants.swap(1, 2), Violation::Grants, Api);
        refuses(|a| a.next_index = None, Violation::Grants, Api);
        refuses(|a| a.next_index = Some(9), Violation::Grants, Api);
        refuses(|a| a.grants[2].method = "PUT".into(), Violation::Method, Api);
        refuses(|a| a.grants[2].length += 1, Violation::Length, Api);
        refuses(|a| a.grants[2].length -= 1, Violation::Length, Api);
        refuses(
            |a| a.grants[1].url = "http://s3.storage.test/bb-01/k?s=1".into(),
            Violation::Authority(Refusal::NotHttps),
            Api,
        );
        refuses(
            |a| a.grants[1].url = "https://evil.test/bb-01/k?s=1".into(),
            Violation::Authority(Refusal::HostNotListed),
            Api,
        );
        refuses(
            |a| a.grants[7].url = "https://s3.storage.test/other/k?s=1".into(),
            Violation::Authority(Refusal::BucketNotListed),
            Api,
        );
        refuses(|a| a.grants[0].expires_at = "tomorrow".into(), Violation::Expiry, Api);
        refuses(|a| a.grants[0].expires_at.clear(), Violation::Expiry, Api);
    }

    #[test]
    fn a_link_lifetime_shorter_than_the_renewal_margin_is_refused() {
        // A stated lifetime under a minute is read as clock skew (the TTL counts), so only a TTL that
        // is itself shorter than the margin can leave a grant with no usable time: the server's
        // `url_ttl_seconds` says 20 s against a 30 s margin.
        let mut discovery = discovery();
        discovery.url_ttl_seconds = Some(20);
        let cfg = PlannerConfig::from_discovery(&discovery, 7);
        let mut p = DownloadPlanner::new(cfg, discovery, API, FILE);
        let r = expect_window(&mut p, T0);
        assert_eq!(p.window_answered(answer(&r, T0), T0), Err(Violation::Expiry));
        assert_eq!(p.poll(T0), Poll::Stop(Verdict::ApiForFile));
    }

    #[test]
    fn the_last_chunk_length_is_the_remainder() {
        let g = geometry();
        assert_eq!(g.chunk_length(0), Some(1028));
        assert_eq!(g.chunk_length(18), Some(1028));
        assert_eq!(g.chunk_length(19), Some(LAST_PLAIN + CHUNK_OVERHEAD));
        let single = Geometry {
            chunk_count: 1,
            chunk_size: 1000,
            encrypted_size: 28,
            original_size: 0,
        };
        assert!(single.is_consistent(), "the empty file is one empty chunk");
        assert_eq!(single.chunk_length(0), Some(28));
    }

    #[test]
    fn chunk_length_never_panics_on_hostile_numbers() {
        let g = geometry();
        assert_eq!(g.chunk_length(20), None, "one past the last chunk");
        assert_eq!(g.chunk_length(u32::MAX), None);
        let empty = Geometry {
            chunk_count: 0,
            chunk_size: 10,
            encrypted_size: 0,
            original_size: 0,
        };
        assert_eq!(empty.chunk_length(0), None, "no chunks, no lengths");
        let overflow = Geometry {
            chunk_count: u32::MAX,
            chunk_size: u64::MAX,
            encrypted_size: u64::MAX,
            original_size: u64::MAX,
        };
        for i in [0, 1, u32::MAX - 1, u32::MAX] {
            assert_eq!(overflow.chunk_length(i), None, "index {i}");
        }
        let stride_overflow = Geometry {
            chunk_count: 2,
            chunk_size: u64::MAX - 5,
            encrypted_size: 100,
            original_size: 44,
        };
        assert_eq!(stride_overflow.chunk_length(0), None);
        // A stride that fits, times a chunk count that does not.
        let product_overflow = Geometry {
            chunk_count: u32::MAX,
            chunk_size: 1 << 40,
            encrypted_size: u64::MAX,
            original_size: 0,
        };
        assert_eq!(product_overflow.chunk_length(u32::MAX - 1), None);
        // A total smaller than the full chunks before the last is no geometry.
        let short = Geometry {
            chunk_count: 3,
            chunk_size: 100,
            encrypted_size: 10,
            original_size: 0,
        };
        assert_eq!(short.chunk_length(2), None);
    }

    #[test]
    fn geometry_consistency_matches_the_servers_totals_check() {
        // server `totals_fit(10, 2, wire_total)`: 67, 76 and 66 fit; 65 and 77 do not.
        let g = |enc: u64| Geometry {
            chunk_count: 2,
            chunk_size: 10,
            encrypted_size: enc,
            original_size: enc.saturating_sub(56),
        };
        for fits in [66, 67, 76] {
            assert!(g(fits).is_consistent(), "{fits}");
        }
        for broken in [65, 77] {
            assert!(!g(broken).is_consistent(), "{broken}");
        }
        assert!(
            !Geometry {
                chunk_count: 0,
                chunk_size: 0,
                encrypted_size: 0,
                original_size: 0
            }
            .is_consistent()
        );
        // No arithmetic overflow on hostile numbers.
        let huge = Geometry {
            chunk_count: u32::MAX,
            chunk_size: MAX_CHUNK_SIZE,
            encrypted_size: u64::MAX,
            original_size: u64::MAX,
        };
        assert!(!huge.is_consistent());
    }

    #[test]
    fn later_windows_must_repeat_the_pinned_version_and_geometry() {
        let mut p = started();
        let r = drive_to_next_window(&mut p, T0);
        let mut other_version = answer(&r, T0);
        other_version.object_version_id = "44444444-4444-4444-8444-444444444444".into();
        assert_eq!(p.window_answered(other_version, T0), Err(Violation::VersionChanged));
        assert_eq!(
            p.poll(T0),
            Poll::Stop(Verdict::Restart),
            "a changed version restarts, never mixes"
        );

        let mut q = started();
        let r = drive_to_next_window(&mut q, T0);
        let mut other_geometry = answer(&r, T0);
        other_geometry.chunk_size += 1;
        other_geometry.encrypted_size += u64::from(CHUNKS);
        other_geometry.original_size += u64::from(CHUNKS);
        assert_eq!(q.window_answered(other_geometry, T0), Err(Violation::Geometry));
        // The version is pinned, so the rest is served through the pinned route, not abandoned.
        assert!(!matches!(q.poll(T0), Poll::Stop(_) | Poll::RequestWindow(_)));
    }

    #[test]
    fn an_answer_nobody_asked_for_is_refused() {
        let mut p = planner();
        let r = DownloadGrantRequest {
            object_version_id: None,
            start_index: 0,
            count: 8,
            renewal: false,
        };
        assert_eq!(p.window_answered(answer(&r, T0), T0), Err(Violation::Unexpected));
        assert_eq!(p.poll(T0), Poll::Stop(Verdict::ApiForFile));
    }

    // ── clock handling ──

    #[test]
    fn a_client_clock_far_ahead_does_not_burn_renewals() {
        // The server's expires_at is 10 minutes in the past by our clock.
        let mut p = planner();
        let r = expect_window(&mut p, T0);
        let skewed_now = T0 + 600_000;
        p.window_answered(answer(&r, T0), skewed_now).unwrap();
        assert_eq!(
            expect_fetch(&mut p, skewed_now),
            0,
            "usable: the lifetime counts from arrival"
        );
        assert!(matches!(
            p.poll(skewed_now + 269_000),
            Poll::Fetch { .. } | Poll::Wait { .. }
        ));
        // ... and it does age out 270 s after arrival.
        let mut q = planner();
        let r = expect_window(&mut q, T0);
        q.window_answered(answer(&r, T0), skewed_now).unwrap();
        assert!(matches!(q.poll(skewed_now + 270_000), Poll::RequestWindow(r) if r.renewal));
    }

    #[test]
    fn a_clock_just_ahead_is_not_mistaken_for_a_short_link() {
        // The server's expiry is 20 s away by this clock (it runs 280 s ahead): a stated lifetime
        // under a minute is clock skew, so the full TTL counts from arrival.
        for ahead in [270_000, 280_000, 299_000, 299_999] {
            let mut p = planner();
            let r = expect_window(&mut p, T0);
            let arrival = T0 + ahead;
            p.window_answered(answer(&r, T0), arrival)
                .unwrap_or_else(|v| panic!("{ahead} ms ahead: {v}"));
            assert!(
                matches!(p.poll(arrival + 269_999), Poll::Fetch { .. }),
                "{ahead} ms ahead: usable for the TTL from arrival"
            );
            let mut q = planner();
            let r = expect_window(&mut q, T0);
            q.window_answered(answer(&r, T0), arrival).unwrap();
            assert!(matches!(q.poll(arrival + 270_000), Poll::RequestWindow(r) if r.renewal));
        }
    }

    #[test]
    fn the_stated_lifetime_band_edges() {
        // 59.999 s stated: not believed (TTL). 60 s stated: believed (minus the margin).
        for (stated, usable) in [(59_999, 270_000), (60_000, 30_000), (61_000, 31_000)] {
            let mut p = planner();
            let r = expect_window(&mut p, T0);
            let mut a = answer(&r, T0);
            for g in &mut a.grants {
                g.expires_at = rfc3339(T0 + stated);
            }
            p.window_answered(a, T0).unwrap();
            assert!(matches!(p.poll(T0 + usable - 1), Poll::Fetch { .. }), "stated {stated}");
            let mut q = planner();
            let r = expect_window(&mut q, T0);
            let mut a = answer(&r, T0);
            for g in &mut a.grants {
                g.expires_at = rfc3339(T0 + stated);
            }
            q.window_answered(a, T0).unwrap();
            assert!(
                matches!(q.poll(T0 + usable), Poll::RequestWindow(r) if r.renewal),
                "stated {stated}"
            );
        }
    }

    #[test]
    fn a_client_clock_30_seconds_behind_does_not_stretch_a_link_past_the_ttl() {
        // The server's expiry is 330 s away by this clock: a link never outlives the TTL.
        let mut p = planner();
        let r = expect_window(&mut p, T0);
        let arrival = T0 - 30_000;
        p.window_answered(answer(&r, T0), arrival).unwrap();
        assert!(matches!(p.poll(arrival + 269_999), Poll::Fetch { .. }));
        let mut q = planner();
        let r = expect_window(&mut q, T0);
        q.window_answered(answer(&r, T0), arrival).unwrap();
        assert!(
            matches!(q.poll(arrival + 270_000), Poll::RequestWindow(r) if r.renewal),
            "renewed after TTL - margin, not after 330 s - margin"
        );
    }

    // ── a clock that steps backwards ──

    #[test]
    fn a_backoff_deadline_is_pulled_in_when_the_clock_steps_back() {
        let mut p = planner();
        expect_window(&mut p, T0);
        p.window_failed(Outcome::Backoff(Duration::from_secs(100)), T0);
        assert_eq!(
            p.poll(T0 + 1),
            Poll::Wait {
                until_ms: Some(T0 + 100_000)
            }
        );
        // An hour back: the old deadline would be an hour and 100 s away.
        let back = T0 - 3_600_000;
        assert_eq!(
            p.poll(back),
            Poll::Wait {
                until_ms: Some(back + MAX_WAIT_MS)
            }
        );
    }

    #[test]
    fn a_renewal_backoff_and_a_grant_deadline_are_pulled_in_too() {
        let mut cfg = PlannerConfig::from_discovery(&discovery(), 7);
        cfg.backoff_base_ms = 50_000_000;
        cfg.backoff_cap_ms = 50_000_000;
        let mut p = DownloadPlanner::new(cfg, discovery(), API, FILE);
        let first = expect_window(&mut p, T0);
        p.window_answered(answer(&first, T0), T0).unwrap();
        for _ in 0..4 {
            expect_fetch(&mut p, T0);
        }
        p.fetch_failed(0, T0).unwrap(); // not before T0 + ~25_000..50_000 s
        let back = T0 - 3_600_000;
        match p.poll(back) {
            Poll::Wait { until_ms: Some(t) } => assert_eq!(t, back + MAX_WAIT_MS, "NeedsGrant deadline clamped"),
            other => panic!("{other:?}"),
        }
        // The unused grants (4..8) would have lasted until T0 + 270 s: an hour later.
        // Clamped, they last 270 s from the new reading.
        let mut q = started();
        assert!(matches!(q.poll(back), Poll::Fetch { .. }));
        assert!(
            matches!(q.poll(back + 270_000), Poll::RequestWindow(r) if r.renewal),
            "a grant deadline from before the step does not outlive the TTL"
        );
    }

    #[test]
    fn a_client_clock_far_behind_cannot_stretch_a_link() {
        // expires_at is 10 minutes ahead by our clock: still 300 s from arrival.
        let mut p = planner();
        let r = expect_window(&mut p, T0);
        p.window_answered(answer(&r, T0 + 600_000), T0).unwrap();
        assert!(matches!(p.poll(T0 + 270_000), Poll::RequestWindow(r) if r.renewal));
    }

    #[test]
    fn a_plausible_server_expiry_tightens_the_window() {
        // The server says 100 s, shorter than the default lifetime.
        let mut p = planner();
        let r = expect_window(&mut p, T0);
        let mut a = answer(&r, T0);
        for g in &mut a.grants {
            g.expires_at = rfc3339(T0 + 100_000);
        }
        p.window_answered(a, T0).unwrap();
        assert!(matches!(p.poll(T0 + 69_999), Poll::Fetch { .. }));
        let mut q = planner();
        let r = expect_window(&mut q, T0);
        let mut a = answer(&r, T0);
        for g in &mut a.grants {
            g.expires_at = rfc3339(T0 + 100_000);
        }
        q.window_answered(a, T0).unwrap();
        assert!(matches!(q.poll(T0 + 70_000), Poll::RequestWindow(r) if r.renewal));
    }

    #[test]
    fn a_grant_that_keeps_aging_out_unused_ends_on_the_api_route() {
        // Nothing is ever fetched; each time the four reachable grants age out they
        // are renewed, and the renewal budget (3) is the same one a failure spends.
        let mut p = started();
        let mut now = T0;
        for round in 1..=3 {
            now += 300_000;
            match p.poll(now) {
                Poll::RequestWindow(r) => {
                    assert!(r.renewal && r.start_index == 0, "round {round}: {r:?}");
                    p.window_answered(answer(&r, now), now).unwrap();
                }
                other => panic!("round {round}: expected a renewal, got {other:?}"),
            }
        }
        now += 300_000;
        match p.poll(now) {
            Poll::FetchViaApi { index: 0, .. } => {}
            other => panic!("the fourth age-out must send chunk 0 to the API route, got {other:?}"),
        }
    }

    #[test]
    fn an_unused_grant_that_ages_out_spends_the_same_budget_and_cannot_loop() {
        // A consumer that never advances: chunk 0 in flight forever; the grants for 4..8
        // sit unused, age out, are renewed when they come within reach (never), so the
        // planner makes no API request for them.
        let mut p = started();
        for _ in 0..4 {
            expect_fetch(&mut p, T0);
        }
        let mut requests = 0;
        let mut now = T0;
        for _ in 0..50 {
            now += 60_000;
            if let Poll::RequestWindow(_) = p.poll(now) {
                requests += 1;
                p.window_failed(Outcome::UseApiNow, now);
                break;
            }
        }
        assert_eq!(requests, 0, "no grant requests for chunks outside the reorder window");
    }

    // ── verdict stickiness and secrets ──

    #[test]
    fn poll_output_never_prints_a_signature() {
        let mut p = started();
        let shown = format!("{:?}", p.poll(T0));
        assert!(!shown.contains("SIG0") && !shown.contains("X-Amz"), "{shown}");
        let state = format!("{p:?}");
        assert!(!state.contains("SIG") && !state.contains("X-Amz-Signature"), "{state}");
    }

    // ── window_answered_bytes: decode, judge, report ──

    #[test]
    fn window_answered_bytes_decodes_judges_and_reports_the_code() {
        let mut p = planner();
        let first = expect_window(&mut p, T0);
        let body = serde_json::to_vec(&answer(&first, T0)).unwrap();
        assert_eq!(p.window_answered_bytes(&body, T0), WindowAnswer::Accepted);
        assert_eq!(p.pinned_version(), Some(VERSION));

        // Not the contract's JSON: handled like a window the server could not serve.
        for junk in [&b"{not json"[..], b"[]", b"", b"null"] {
            let mut p = planner();
            expect_window(&mut p, T0);
            assert_eq!(p.window_answered_bytes(junk, T0), WindowAnswer::Malformed, "{junk:?}");
            assert_eq!(p.poll(T0), Poll::Stop(Verdict::ApiForFile), "{junk:?}");
        }

        // An answer that breaks the contract carries its code.
        let mut p = planner();
        let first = expect_window(&mut p, T0);
        let mut bad = answer(&first, T0);
        bad.transport = "object-download-v2".into();
        let got = p.window_answered_bytes(&serde_json::to_vec(&bad).unwrap(), T0);
        assert_eq!(got, WindowAnswer::Refused(Violation::Transport));
        assert_eq!(got.code(), "transport");
        assert_eq!(WindowAnswer::Accepted.code(), "accepted");
        assert_eq!(WindowAnswer::Malformed.code(), "malformed");
    }

    #[test]
    fn a_late_window_answer_is_the_same_caller_bug_whatever_the_body() {
        // The first window is answered; a second answer arrives with no request outstanding. The
        // planner is pinned, so junk used to read as "malformed" and let the file carry on through
        // the pinned route, while valid JSON sent it to the API path.
        let bodies: Vec<(&str, Vec<u8>)> = {
            let mut p = planner();
            let first = expect_window(&mut p, T0);
            vec![
                ("junk", b"{not json".to_vec()),
                ("empty", Vec::new()),
                ("valid", serde_json::to_vec(&answer(&first, T0)).unwrap()),
            ]
        };
        for (what, body) in bodies {
            let mut p = planner();
            let first = expect_window(&mut p, T0);
            let ok = serde_json::to_vec(&answer(&first, T0)).unwrap();
            assert_eq!(p.window_answered_bytes(&ok, T0), WindowAnswer::Accepted);
            assert_eq!(p.pinned_version(), Some(VERSION), "{what}: the version is pinned");
            assert_eq!(
                p.window_answered_bytes(&body, T0),
                WindowAnswer::Refused(Violation::Unexpected),
                "{what}"
            );
            assert_eq!(p.poll(T0), Poll::Stop(Verdict::ApiForFile), "{what}");
        }
        // Before the first request is even made, too.
        let mut p = planner();
        assert_eq!(
            p.window_answered_bytes(b"{not json", T0),
            WindowAnswer::Refused(Violation::Unexpected)
        );
        assert_eq!(p.poll(T0), Poll::Stop(Verdict::ApiForFile));
    }

    // ── a verdict that is set stands ──

    #[test]
    fn a_late_answer_does_not_replace_a_terminal_or_restart_verdict() {
        let terminal = Terminal {
            status: 403,
            error: None,
        };
        for (what, set_verdict, expected) in [
            (
                "terminal",
                (|p: &mut DownloadPlanner, t: &Terminal| p.window_failed(Outcome::Terminal(t.clone()), T0))
                    as fn(&mut DownloadPlanner, &Terminal),
                Verdict::Terminal(terminal.clone()),
            ),
            (
                "restart",
                |p, _| p.window_failed(Outcome::Restart, T0),
                Verdict::Restart,
            ),
        ] {
            let mut p = planner();
            let first = expect_window(&mut p, T0);
            let valid = serde_json::to_vec(&answer(&first, T0)).unwrap();
            set_verdict(&mut p, &terminal);
            assert_eq!(p.poll(T0), Poll::Stop(expected.clone()), "{what}");
            // The request is gone; every late answer is a caller bug and changes nothing.
            assert_eq!(
                p.window_answered_bytes(&valid, T0),
                WindowAnswer::Refused(Violation::Unexpected),
                "{what}"
            );
            assert_eq!(
                p.window_answered_bytes(b"{not json", T0),
                WindowAnswer::Refused(Violation::Unexpected),
                "{what}"
            );
            assert_eq!(
                p.window_answered(answer(&first, T0), T0),
                Err(Violation::Unexpected),
                "{what}"
            );
            assert_eq!(
                p.poll(T0),
                Poll::Stop(expected.clone()),
                "{what}: the first verdict stands"
            );
            // A stray failure report is not a new verdict either.
            p.window_failed(Outcome::UseApiNow, T0);
            p.window_malformed();
            assert_eq!(p.poll(T0), Poll::Stop(expected), "{what}: after stray failure reports");
        }
    }

    #[test]
    fn a_chunk_that_does_not_authenticate_stays_a_hard_error_when_a_stale_window_arrives() {
        // The next window is outstanding when the chunk fails twice; the window then answers for
        // another version (a Restart on its own). The file stays Corrupt: never publish plaintext.
        let mut p = started();
        let next = drive_to_next_window(&mut p, T0);
        let index = expect_fetch(&mut p, T0);
        p.fetch_ok(index).unwrap();
        p.chunk_unauthentic(index).unwrap();
        match p.poll(T0) {
            Poll::FetchViaApi { index: again, .. } => assert_eq!(again, index),
            other => panic!("expected the API re-fetch, got {other:?}"),
        }
        p.fetch_ok(index).unwrap();
        p.chunk_unauthentic(index).unwrap();
        assert_eq!(p.poll(T0), Poll::Stop(Verdict::Corrupt));

        let mut elsewhere = answer(&next, T0);
        elsewhere.object_version_id = "44444444-4444-4444-8444-444444444444".into();
        assert_eq!(p.window_answered(elsewhere, T0), Err(Violation::VersionChanged));
        assert_eq!(
            p.poll(T0),
            Poll::Stop(Verdict::Corrupt),
            "Restart did not replace Corrupt"
        );
    }

    // ── precedence: Corrupt > Terminal > Restart > ApiForFile ──

    fn forbidden() -> Terminal {
        Terminal {
            status: 403,
            error: Some("forbidden".into()),
        }
    }

    fn all_verdicts() -> Vec<Verdict> {
        vec![
            Verdict::ApiForFile,
            Verdict::Restart,
            Verdict::Terminal(forbidden()),
            Verdict::Corrupt,
        ]
    }

    #[test]
    fn the_strongest_verdict_stands_whatever_order_they_come_in() {
        // The rule itself, all sixteen pairs: a stronger verdict replaces, a weaker or equal one does not.
        for first in all_verdicts() {
            for then in all_verdicts() {
                let mut p = planner();
                p.set_verdict(first.clone());
                p.set_verdict(then.clone());
                let want = if then.strength() > first.strength() {
                    &then
                } else {
                    &first
                };
                assert_eq!(p.poll(T0), Poll::Stop(want.clone()), "{first:?} then {then:?}");
            }
        }
        // Among equals the first stands (the status the caller saw first is the one it reports).
        let mut p = planner();
        p.set_verdict(Verdict::Terminal(forbidden()));
        p.set_verdict(Verdict::Terminal(Terminal {
            status: 401,
            error: None,
        }));
        assert_eq!(p.poll(T0), Poll::Stop(Verdict::Terminal(forbidden())));
    }

    /// A pinned planner whose chunk 0 is in flight on the pinned API route.
    fn with_chunk_zero_on_the_api_route() -> DownloadPlanner {
        let mut p = started();
        assert_eq!(expect_fetch(&mut p, T0), 0);
        p.fetch_ok(0).unwrap();
        p.chunk_unauthentic(0).unwrap();
        match p.poll(T0) {
            Poll::FetchViaApi { index: 0, .. } => {}
            other => panic!("expected chunk 0 on the API route, got {other:?}"),
        }
        p
    }

    /// Chunk 1 fails authentication twice: the file is Corrupt.
    fn make_corrupt(p: &mut DownloadPlanner) {
        let index = expect_fetch(p, T0);
        p.fetch_ok(index).unwrap();
        p.chunk_unauthentic(index).unwrap();
        match p.poll(T0) {
            Poll::FetchViaApi { index: again, .. } => assert_eq!(again, index),
            other => panic!("expected the API re-fetch, got {other:?}"),
        }
        p.fetch_ok(index).unwrap();
        p.chunk_unauthentic(index).unwrap();
    }

    /// Bring a planner to `verdict` the way a client would, through the public calls.
    fn reach(p: &mut DownloadPlanner, verdict: &Verdict) {
        match verdict {
            Verdict::ApiForFile => {}
            Verdict::Restart => p.window_failed(Outcome::Restart, T0),
            Verdict::Terminal(t) => p.window_failed(Outcome::Terminal(t.clone()), T0),
            Verdict::Corrupt => make_corrupt(p),
        }
    }

    #[test]
    fn a_failed_api_fetch_never_downgrades_a_stronger_verdict() {
        for existing in all_verdicts().into_iter().skip(1) {
            let mut p = with_chunk_zero_on_the_api_route();
            reach(&mut p, &existing);
            assert_eq!(p.poll(T0), Poll::Stop(existing.clone()), "{existing:?}");
            p.api_fetch_failed(0).unwrap();
            assert_eq!(
                p.poll(T0),
                Poll::Stop(existing.clone()),
                "api_fetch_failed after {existing:?}"
            );
        }
        // With nothing before it, it is "use the API".
        let mut p = with_chunk_zero_on_the_api_route();
        p.api_fetch_failed(0).unwrap();
        assert_eq!(p.poll(T0), Poll::Stop(Verdict::ApiForFile));
    }

    #[test]
    fn a_window_failure_never_downgrades_a_stronger_verdict_and_escalates_a_weaker_one() {
        let other_terminal = Terminal {
            status: 401,
            error: None,
        };
        // After Corrupt neither a Restart nor a Terminal replaces it.
        let mut p = with_chunk_zero_on_the_api_route();
        make_corrupt(&mut p);
        p.window_failed(Outcome::Restart, T0);
        p.window_failed(Outcome::Terminal(other_terminal.clone()), T0);
        assert_eq!(p.poll(T0), Poll::Stop(Verdict::Corrupt), "after Corrupt");
        // After Terminal a Restart does not replace it, and a second Terminal does not either.
        let mut p = planner();
        expect_window(&mut p, T0);
        p.window_failed(Outcome::Terminal(forbidden()), T0);
        p.window_failed(Outcome::Restart, T0);
        p.window_failed(Outcome::Terminal(other_terminal.clone()), T0);
        assert_eq!(p.poll(T0), Poll::Stop(Verdict::Terminal(forbidden())), "after Terminal");
        // The other way round, the stronger replaces: Restart, then Terminal.
        let mut p = planner();
        expect_window(&mut p, T0);
        p.window_failed(Outcome::Restart, T0);
        assert_eq!(p.poll(T0), Poll::Stop(Verdict::Restart));
        p.window_failed(Outcome::Terminal(other_terminal.clone()), T0);
        assert_eq!(
            p.poll(T0),
            Poll::Stop(Verdict::Terminal(other_terminal)),
            "Restart, then Terminal"
        );
        // "Use the API" is replaced by Restart.
        let mut p = planner();
        expect_window(&mut p, T0);
        p.window_failed(Outcome::UseApiNow, T0);
        assert_eq!(p.poll(T0), Poll::Stop(Verdict::ApiForFile));
        p.window_failed(Outcome::Restart, T0);
        assert_eq!(p.poll(T0), Poll::Stop(Verdict::Restart), "ApiForFile, then Restart");
    }

    #[test]
    fn a_stray_window_failure_with_no_window_outstanding_changes_no_verdict() {
        for existing in all_verdicts().into_iter().skip(1) {
            for outcome in [
                Outcome::UseApiNow,
                Outcome::ApiForThisFile,
                Outcome::NotSupported,
                Outcome::Retry,
                Outcome::Backoff(Duration::from_secs(1)),
            ] {
                let mut p = with_chunk_zero_on_the_api_route();
                reach(&mut p, &existing);
                // No window request is outstanding (the first one was answered long ago).
                p.window_failed(outcome.clone(), T0);
                p.window_malformed();
                assert_eq!(
                    p.poll(T0),
                    Poll::Stop(existing.clone()),
                    "{outcome:?} after {existing:?}"
                );
            }
        }
    }

    #[test]
    fn a_chunk_that_does_not_authenticate_escalates_every_other_verdict_to_corrupt() {
        for existing in all_verdicts().into_iter().take(3) {
            let mut p = with_chunk_zero_on_the_api_route();
            reach(&mut p, &existing);
            make_corrupt(&mut p);
            assert_eq!(p.poll(T0), Poll::Stop(Verdict::Corrupt), "Corrupt after {existing:?}");
        }
    }

    #[test]
    fn every_rejection_maps_to_its_own_violation() {
        for (rejected, want, code) in [
            (Rejected::Transport, Violation::Transport, "transport"),
            (Rejected::FileMismatch, Violation::FileMismatch, "file_mismatch"),
            (Rejected::VersionChanged, Violation::VersionChanged, "version_changed"),
            (Rejected::Geometry, Violation::Geometry, "geometry"),
            (Rejected::Grants, Violation::Grants, "grants"),
            (Rejected::Length, Violation::Length, "length"),
            (Rejected::Method, Violation::Method, "method"),
            (
                Rejected::Authority(Refusal::HostNotListed),
                Violation::Authority(Refusal::HostNotListed),
                "authority_host_not_listed",
            ),
            (Rejected::Expiry, Violation::Expiry, "expiry"),
        ] {
            let got = Violation::from(rejected);
            assert_eq!(got, want, "{rejected:?}");
            assert_eq!(got.code(), code, "{rejected:?}");
        }
    }
}
