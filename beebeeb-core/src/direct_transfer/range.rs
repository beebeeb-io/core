//! The range planner (LD-0105, spec §6.3): a pure state machine that decides, for one file and
//! ONE recorded version, which chunks to ask grants for and fetch next when reads arrive at any
//! offset, in any order (a player that seeks, an opener that wants the whole file, read-ahead).
//!
//! It is a new type next to [`super::DownloadPlanner`], not built on it: that planner fetches in
//! order from a moving front and its client rules (`window.rs` "Client wrapper rules") bind every
//! existing client unchanged. What the range planner does instead:
//! - it holds a SET of released chunks, not a consumed prefix;
//! - it asks for windows at any start, with grants only for the next chunks it wants
//!   (at most one window size ahead of what it fetches);
//! - chunk 0 comes first: it carries the format and, for v2, the version id (spec I3, S4);
//! - then the demanded chunks (oldest demand first), then read-ahead: the last chunk, forward
//!   from the furthest demand, then the gaps from the start, until the file is whole (S5);
//! - an idle grant ages out WITHOUT spending the chunk's renewal budget, and is granted again
//!   only for a demanded chunk, at most once per demand (a paused player cannot keep a session
//!   re-granting);
//! - it holds at most [`storage_in_flight`]`(share, chunk_size)` chunks (C3) and runs at most
//!   [`API_IN_FLIGHT`] pinned API fetches.
//!
//! It composes the whole-file planner's pure checks, never copies them: every window answer goes
//! through the same `grant_check::check_window` (transport, file, pin, geometry, grants, method,
//! length, [`super::check_storage_url`], expiry inside the skew margin), and the renewal budget,
//! the 429 cap, the backoff and the verdict order are the same functions and constants.
//!
//! # Range-read amendment to the direct-transfer client rules
//!
//! `window.rs`'s rules stay binding for `DownloadPlanner`. For a range session they read:
//! chunks are released in any order, each only once `RangeOpener` has authenticated it at the
//! requested index; the reorder bound is the byte share (C3), not a consumed prefix; and nothing
//! of the session is "whole" before `RangeSession::finish()` (core `docs/agent-notes.md`, range
//! reads I1–I9).
//!
//! The driver loop, as in `window.rs`, with `released(index)` in place of `consumed(index)`:
//! ```text
//! loop {
//!     match planner.poll(now_ms) {
//!         RangePoll::RequestWindow(req) => POST it, then window_answered(..) / window_failed(..),
//!         RangePoll::Fetch { index, grant } => GET it, then fetch_ok / fetch_failed,
//!         RangePoll::FetchViaApi { index, .. } => GET the pinned chunk, then fetch_ok / api_fetch_failed,
//!         RangePoll::Wait { until_ms } => sleep until then, a reply or a new demand,
//!         RangePoll::Idle => nothing is wanted: wait for a demand,
//!         RangePoll::Done => every chunk was released,
//!         RangePoll::Stop(verdict) => fail the session (poison the sink if anything was released),
//!     }
//!     // open each fetched chunk with RangeOpener; then released(index) or chunk_unauthentic(index)
//! }
//! ```

mod parts;
#[cfg(test)]
mod tests;
#[cfg(any(test, feature = "test-support"))]
pub mod vectors;

use std::collections::{BTreeMap, BTreeSet};

pub use parts::{
    API_IN_FLIGHT, CutError, MAX_SESSION_LEASES, MAX_STORAGE_IN_FLIGHT, MIN_RANGE_WINDOW, PIECE_ALIGN, Piece,
    PieceCutter, RangeBudget, RunSet, demand_chunks, range_window, session_share, storage_in_flight,
};

use super::classify::Outcome;
use super::grant_check::{Attempts, Rejected, WindowCheck, backoff_delay, check_window, rate_limit_spent};
use super::window::{
    BACKOFF_BASE_MS, BACKOFF_CAP_MS, Geometry, MAX_RATE_LIMITS, MAX_RENEWALS_PER_CHUNK, MAX_WAIT_MS, REFILL_AT,
    RENEW_SKEW_MS, Verdict, Violation, WindowAnswer, splitmix64,
};
use super::wire::{ChunkGrant, Discovery, DownloadGrantRequest, DownloadGrantResponse, MAX_WINDOW};

/// Tunables. [`RangeConfig::from_discovery`] gives the production values; tests change fields.
#[derive(Debug, Clone)]
pub struct RangeConfig {
    /// The server's `max_window`, clamped to `1..=MAX_WINDOW` when the planner is built.
    pub server_max_window: u32,
    pub refill_at: usize,
    /// This session's byte share of the process budget ([`RangeBudget::share`]).
    pub share_bytes: u64,
    /// Pinned API fetches at once; clamped to `1..=`[`API_IN_FLIGHT`].
    pub api_in_flight: u32,
    pub renew_skew_ms: i64,
    pub url_ttl_ms: i64,
    pub max_renewals: u8,
    pub backoff_base_ms: u64,
    pub backoff_cap_ms: u64,
    pub max_rate_limits: u8,
    pub jitter_seed: u64,
}

impl RangeConfig {
    pub fn from_discovery(discovery: &Discovery, share_bytes: u64, jitter_seed: u64) -> RangeConfig {
        RangeConfig {
            server_max_window: discovery.max_window.unwrap_or(MAX_WINDOW),
            refill_at: REFILL_AT,
            share_bytes,
            api_in_flight: API_IN_FLIGHT,
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

/// What the caller must do now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RangePoll {
    /// `POST /api/v1/files/{id}/download-grants` with this body (it always carries the pin).
    RequestWindow(DownloadGrantRequest),
    /// `GET` `grant.url` with the storage client.
    Fetch { index: u32, grant: ChunkGrant },
    /// `GET /api/v1/files/{id}/chunks/{index}?object_version_id=<pinned>`.
    FetchViaApi { index: u32, object_version_id: String },
    /// Nothing to start; `until_ms` is the next moment the planner acts on its own, `None` waits
    /// for an outstanding request (or, with `may_fetch = false`, for budget).
    Wait { until_ms: Option<i64> },
    /// Nothing is wanted and nothing is outstanding: wait for a demand.
    Idle,
    /// Every chunk of the file was released.
    Done,
    /// The session cannot go on.
    Stop(Verdict),
}

impl RangePoll {
    /// Stable machine name of the variant (vectors).
    pub fn kind(&self) -> &'static str {
        match self {
            RangePoll::RequestWindow(_) => "request_window",
            RangePoll::Fetch { .. } => "fetch",
            RangePoll::FetchViaApi { .. } => "fetch_via_api",
            RangePoll::Wait { .. } => "wait",
            RangePoll::Idle => "idle",
            RangePoll::Done => "done",
            RangePoll::Stop(_) => "stop",
        }
    }
}

/// A call that does not fit the planner's state: a bug in the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RangeError {
    #[error("chunk {0} is not outstanding")]
    NotInFlight(u32),
    #[error("chunk {0} is not waiting to be released")]
    NotFetched(u32),
    #[error("chunk {0} is being fetched through the API route; report its failure with api_fetch_failed")]
    ApiRouteFailure(u32),
    #[error("demand {0} is already open")]
    DuplicateDemand(u64),
}

impl RangeError {
    /// Stable machine name (vectors).
    pub fn code(self) -> &'static str {
        match self {
            RangeError::NotInFlight(_) => "not_in_flight",
            RangeError::NotFetched(_) => "not_fetched",
            RangeError::ApiRouteFailure(_) => "api_route_failure",
            RangeError::DuplicateDemand(_) => "duplicate_demand",
        }
    }
}

#[derive(Debug)]
enum Slot {
    /// A failure is renewed after a backoff. `regranted_for` carries an idle re-grant's demand
    /// through its renewals, so every later age-out of it keeps spending the renewal budget.
    NeedsGrant {
        attempts: Attempts,
        not_before_ms: i64,
        regranted_for: Option<u64>,
    },
    Granted {
        attempts: Attempts,
        grant: ChunkGrant,
        usable_until_ms: i64,
        /// The demand this grant was an idle re-grant for, if it was one.
        regranted_for: Option<u64>,
    },
    Fetching {
        attempts: Attempts,
        via_api: bool,
    },
    /// Arrived whole; waits for the caller to open and release it.
    Fetched {
        attempts: Attempts,
    },
    ApiPending {
        attempts: Attempts,
    },
    /// Its grant aged out unused. Granted again only for a demand, once per demand.
    Idle {
        attempts: Attempts,
        regranted_for: Option<u64>,
    },
}

#[derive(Debug, Clone, Copy)]
struct Demand {
    id: u64,
    offset: u64,
    len: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Need {
    Fresh,
    Renewal,
    Regrant(u64),
}

/// The wanted-chunk list being built: unreleased, each chunk once, at most `k`.
struct Candidates<'a> {
    out: Vec<(u32, Option<u64>)>,
    seen: BTreeSet<u32>,
    k: usize,
    released: &'a RunSet,
}

impl Candidates<'_> {
    fn full(&self) -> bool {
        self.out.len() >= self.k
    }

    fn push(&mut self, index: u32, demand: Option<u64>) {
        if !self.full() && !self.released.contains(u64::from(index)) && self.seen.insert(index) {
            self.out.push((index, demand));
        }
    }

    /// Every unreleased chunk of `from..=to`, in order, until the list is full.
    fn walk(&mut self, from: u32, to: u32, demand: Option<u64>) {
        let mut i = u64::from(from);
        while i <= u64::from(to) && !self.full() {
            i = self.released.first_missing_from(i);
            if i > u64::from(to) {
                break;
            }
            self.push(i as u32, demand);
            i += 1;
        }
    }
}

/// The planner for one file and one recorded version. See the module docs.
#[derive(Debug)]
pub struct RangePlanner {
    cfg: RangeConfig,
    discovery: Discovery,
    api_base: String,
    file_id: String,
    pinned: String,
    geometry: Option<Geometry>,
    slots: BTreeMap<u32, Slot>,
    released: RunSet,
    demands: Vec<Demand>,
    read_ahead: bool,
    /// One past the furthest byte any demand asked for.
    furthest_end: u64,
    window: Option<DownloadGrantRequest>,
    window_not_before_ms: i64,
    rate_limits: u8,
    api_only: bool,
    storage_ok: bool,
    storage_given_up: bool,
    verdict: Option<Verdict>,
    rng: u64,
}

impl RangePlanner {
    /// `pinned` is the version the session is for (the placeholder's minted version): every
    /// window asks for it, and an answer for another version ends the session with
    /// [`Verdict::Restart`].
    pub fn new(
        mut cfg: RangeConfig,
        discovery: Discovery,
        api_base: &str,
        file_id: &str,
        pinned: &str,
    ) -> RangePlanner {
        cfg.server_max_window = cfg.server_max_window.clamp(1, MAX_WINDOW);
        cfg.api_in_flight = cfg.api_in_flight.clamp(1, API_IN_FLIGHT);
        let rng = splitmix64(cfg.jitter_seed);
        RangePlanner {
            cfg,
            discovery,
            api_base: api_base.to_string(),
            file_id: file_id.to_string(),
            pinned: pinned.to_string(),
            geometry: None,
            slots: BTreeMap::new(),
            released: RunSet::new(),
            demands: Vec::new(),
            read_ahead: false,
            furthest_end: 0,
            window: None,
            window_not_before_ms: i64::MIN,
            rate_limits: 0,
            api_only: false,
            storage_ok: false,
            storage_given_up: false,
            verdict: None,
            rng,
        }
    }

    /// The geometry the caller already knows (its own metadata). Every window must repeat it, and
    /// the first window is planned from the demands instead of asking for chunk 0 alone.
    pub fn with_geometry(mut self, geometry: Geometry) -> RangePlanner {
        if geometry.is_consistent() {
            self.geometry = Some(geometry);
        } else {
            self.set_verdict(Verdict::ApiForFile);
        }
        self
    }

    /// Fetch every chunk through the pinned per-chunk API route (`BB_TRANSPORT=api`). Needs the
    /// geometry ([`RangePlanner::with_geometry`]); without it the session ends with `ApiForFile`.
    pub fn force_api(&mut self) {
        self.api_only = true;
    }

    /// Change this session's byte share (another session took or gave back a lease). A chunk
    /// already held is never cancelled.
    pub fn set_share(&mut self, share_bytes: u64) {
        self.cfg.share_bytes = share_bytes;
    }

    pub fn geometry(&self) -> Option<Geometry> {
        self.geometry
    }

    pub fn pinned_version(&self) -> &str {
        &self.pinned
    }

    /// Chunks this session may hold on its share: [`storage_in_flight`] once the geometry is
    /// known, 1 before.
    pub fn slots(&self) -> u32 {
        self.geometry
            .map_or(1, |g| storage_in_flight(self.cfg.share_bytes, g.chunk_size))
    }

    /// Grants per window: [`range_window`] of the server's maximum and the slots.
    pub fn window_size(&self) -> u32 {
        range_window(self.cfg.server_max_window, self.slots())
    }

    /// Chunk requests outstanding (storage or API).
    pub fn in_flight(&self) -> usize {
        self.slots
            .values()
            .filter(|s| matches!(s, Slot::Fetching { .. }))
            .count()
    }

    fn api_in_flight(&self) -> u32 {
        self.slots
            .values()
            .filter(|s| matches!(s, Slot::Fetching { via_api: true, .. }))
            .count() as u32
    }

    /// Chunks held: fetching, or fetched and not yet released.
    pub fn held(&self) -> usize {
        self.slots
            .values()
            .filter(|s| matches!(s, Slot::Fetching { .. } | Slot::Fetched { .. }))
            .count()
    }

    /// Grants held and not yet used.
    pub fn unused_grants(&self) -> usize {
        self.slots
            .values()
            .filter(|s| matches!(s, Slot::Granted { .. }))
            .count()
    }

    /// Chunks released so far.
    pub fn released_count(&self) -> u64 {
        self.released.len()
    }

    pub fn is_released(&self, index: u32) -> bool {
        self.released.contains(u64::from(index))
    }

    /// Open demands.
    pub fn demands(&self) -> usize {
        self.demands.len()
    }

    pub fn reading_ahead(&self) -> bool {
        self.read_ahead
    }

    /// See `DownloadPlanner::storage_given_up`: the same breaker.
    pub fn storage_given_up(&self) -> bool {
        self.storage_given_up && !self.storage_ok
    }

    /// A read wants plaintext `[offset, offset + len)`. Read-ahead (re)starts.
    pub fn demand(&mut self, id: u64, offset: u64, len: u64) -> Result<(), RangeError> {
        if self.demands.iter().any(|d| d.id == id) {
            return Err(RangeError::DuplicateDemand(id));
        }
        self.demands.push(Demand { id, offset, len });
        self.furthest_end = self.furthest_end.max(offset.saturating_add(len));
        self.read_ahead = true;
        Ok(())
    }

    /// Demand `id` has every byte it asked for. Read-ahead goes on.
    pub fn demand_met(&mut self, id: u64) {
        self.demands.retain(|d| d.id != id);
    }

    /// Demand `id` was cancelled (`CANCEL_FETCH_DATA`). When no demand is left, read-ahead stops.
    pub fn cancel(&mut self, id: u64) {
        self.demands.retain(|d| d.id != id);
        if self.demands.is_empty() {
            self.read_ahead = false;
        }
    }

    /// No live requester is left: every demand is dropped and read-ahead stops. Requests already
    /// outstanding still report as usual.
    pub fn requester_gone(&mut self) {
        self.demands.clear();
        self.read_ahead = false;
    }

    /// The chunks demand `id` needs (inclusive), once the geometry is known.
    pub fn demand_range(&self, id: u64) -> Option<(u32, u32)> {
        let g = self.geometry?;
        let d = self.demands.iter().find(|d| d.id == id)?;
        demand_chunks(&g, d.offset, d.len)
    }

    /// What to do now, with fetches allowed.
    pub fn poll(&mut self, now_ms: i64) -> RangePoll {
        self.poll_with(now_ms, true)
    }

    /// What to do now. `may_fetch = false` (the process budget has no room) starts no fetch but
    /// still asks for windows. Each call that returns work records it as started.
    pub fn poll_with(&mut self, now_ms: i64, may_fetch: bool) -> RangePoll {
        if let Some(verdict) = &self.verdict {
            return RangePoll::Stop(verdict.clone());
        }
        self.clamp_deadlines(now_ms);
        let wanted = !self.demands.is_empty() || self.read_ahead;
        let Some(geometry) = self.geometry else {
            if self.api_only {
                self.set_verdict(Verdict::ApiForFile);
                return RangePoll::Stop(Verdict::ApiForFile);
            }
            if self.window.is_some() {
                return RangePoll::Wait { until_ms: None };
            }
            if !wanted {
                return RangePoll::Idle;
            }
            if now_ms < self.window_not_before_ms {
                return RangePoll::Wait {
                    until_ms: Some(self.window_not_before_ms),
                };
            }
            // Chunk 0 first: it fixes the geometry and carries the format and version id (I3).
            let request = self.request(0, 1, false);
            self.window = Some(request.clone());
            return RangePoll::RequestWindow(request);
        };
        if self.released.len() >= u64::from(geometry.chunk_count) {
            return RangePoll::Done;
        }
        self.age_out_grants(now_ms);
        if self.window.is_none() && now_ms >= self.window_not_before_ms {
            if let Some(request) = self.next_window(geometry, now_ms) {
                self.window = Some(request.clone());
                return RangePoll::RequestWindow(request);
            }
        }
        if may_fetch {
            if let Some(work) = self.next_fetch(geometry) {
                return work;
            }
        }
        if !wanted && self.in_flight() == 0 && self.window.is_none() {
            return RangePoll::Idle;
        }
        RangePoll::Wait {
            until_ms: self.next_wake(now_ms),
        }
    }

    fn request(&self, start_index: u32, count: u32, renewal: bool) -> DownloadGrantRequest {
        DownloadGrantRequest {
            object_version_id: Some(self.pinned.clone()),
            start_index,
            count,
            renewal,
        }
    }

    /// See `DownloadPlanner::clamp_deadlines`: a clock that stepped back is pulled in.
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

    /// The oldest open demand that needs chunk `index` (every demand needs chunk 0: I3).
    fn demand_for(&self, geometry: &Geometry, index: u32) -> Option<u64> {
        if index == 0 {
            return self.demands.first().map(|d| d.id);
        }
        self.demands
            .iter()
            .find(|d| demand_chunks(geometry, d.offset, d.len).is_some_and(|(a, b)| a <= index && index <= b))
            .map(|d| d.id)
    }

    /// The next `k` chunks this session wants, in order, each with the demand that wants it.
    fn candidates(&self, geometry: Geometry, k: usize) -> Vec<(u32, Option<u64>)> {
        let n = geometry.chunk_count;
        let mut list = Candidates {
            out: Vec::new(),
            seen: BTreeSet::new(),
            k,
            released: &self.released,
        };
        if !self.demands.is_empty() || self.read_ahead {
            list.push(0, self.demand_for(&geometry, 0));
        }
        for d in &self.demands {
            if let Some((first, last)) = demand_chunks(&geometry, d.offset, d.len) {
                list.walk(first, last, Some(d.id));
            }
        }
        if self.read_ahead {
            list.push(n - 1, self.demand_for(&geometry, n - 1));
            let forward = if self.furthest_end == 0 {
                0
            } else {
                demand_chunks(&geometry, self.furthest_end - 1, 1).map_or(0, |(_, last)| last.saturating_add(1))
            };
            if forward < n {
                list.walk(forward, n - 1, None);
            }
            list.walk(0, n - 1, None);
        }
        list.out
    }

    fn need(&self, index: u32, demand: Option<u64>, now_ms: i64) -> Option<Need> {
        match self.slots.get(&index) {
            None => Some(Need::Fresh),
            Some(Slot::NeedsGrant { not_before_ms, .. }) if *not_before_ms <= now_ms => Some(Need::Renewal),
            Some(Slot::Idle { regranted_for, .. }) => match demand {
                Some(d) if *regranted_for != Some(d) => Some(Need::Regrant(d)),
                _ => None,
            },
            _ => None,
        }
    }

    fn next_window(&mut self, geometry: Geometry, now_ms: i64) -> Option<DownloadGrantRequest> {
        if self.api_only {
            return None;
        }
        let w = self.window_size();
        let candidates = self.candidates(geometry, w as usize);
        let mut first: Option<(usize, Need)> = None;
        for (pos, &(index, demand)) in candidates.iter().enumerate() {
            match self.need(index, demand, now_ms) {
                Some(need) => {
                    first = Some((pos, need));
                    break;
                }
                // Read-ahead stops at a grant that aged out: a paused session asks for nothing.
                None if matches!(self.slots.get(&index), Some(Slot::Idle { .. })) && demand.is_none() => return None,
                None => {}
            }
        }
        let (pos, need) = first?;
        let renewal = !matches!(need, Need::Fresh);
        // A fresh window only when few unused grants are left (no renewal storms); a renewal or a
        // re-grant is for a chunk that is wanted now.
        if !renewal && self.unused_grants() > self.cfg.refill_at {
            return None;
        }
        let start = candidates[pos].0;
        let wanted: BTreeMap<u32, Option<u64>> = candidates.iter().copied().collect();
        let mut count = 0u32;
        while count < w {
            let index = start + count;
            let Some(&demand) = wanted.get(&index) else { break };
            let Some(this) = self.need(index, demand, now_ms) else {
                break;
            };
            if matches!(this, Need::Fresh) == renewal {
                break;
            }
            if let (Need::Regrant(d), Some(Slot::Idle { regranted_for, .. })) = (this, self.slots.get_mut(&index)) {
                *regranted_for = Some(d);
            }
            count += 1;
        }
        (count > 0).then(|| self.request(start, count, renewal))
    }

    fn next_fetch(&mut self, geometry: Geometry) -> Option<RangePoll> {
        if self.held() >= self.slots() as usize {
            return None;
        }
        let candidates = self.candidates(geometry, self.window_size() as usize);
        if self.api_only {
            for &(index, _) in &candidates {
                let slot = self.slots.entry(index).or_insert(Slot::ApiPending {
                    attempts: Attempts::default(),
                });
                if let Slot::NeedsGrant { attempts, .. } | Slot::Idle { attempts, .. } = slot {
                    *slot = Slot::ApiPending { attempts: *attempts };
                }
            }
        }
        let api_room = self.api_in_flight() < self.cfg.api_in_flight;
        let index = candidates.iter().map(|&(i, _)| i).find(|i| match self.slots.get(i) {
            Some(Slot::Granted { .. }) => true,
            Some(Slot::ApiPending { .. }) => api_room,
            _ => false,
        })?;
        let slot = self.slots.get_mut(&index)?;
        match std::mem::replace(
            slot,
            Slot::Fetched {
                attempts: Attempts::default(),
            },
        ) {
            Slot::Granted { attempts, grant, .. } => {
                *slot = Slot::Fetching {
                    attempts,
                    via_api: false,
                };
                Some(RangePoll::Fetch { index, grant })
            }
            Slot::ApiPending { attempts } => {
                *slot = Slot::Fetching {
                    attempts,
                    via_api: true,
                };
                Some(RangePoll::FetchViaApi {
                    index,
                    object_version_id: self.pinned.clone(),
                })
            }
            other => {
                *slot = other;
                None
            }
        }
    }

    /// A grant past its usable window is dropped WITHOUT spending a renewal, unless it was itself
    /// the re-grant for a demand that is still open: then it is that demand's second age-out, and
    /// it spends the renewal budget like a failure (so it ends on the API route, never in a loop).
    fn age_out_grants(&mut self, now_ms: i64) {
        let max = self.cfg.max_renewals;
        let api_only = self.api_only;
        let open: BTreeSet<u64> = self.demands.iter().map(|d| d.id).collect();
        for slot in self.slots.values_mut() {
            let Slot::Granted {
                attempts,
                usable_until_ms,
                regranted_for,
                ..
            } = slot
            else {
                continue;
            };
            if *usable_until_ms > now_ms {
                continue;
            }
            let (mut attempts, regranted_for) = (*attempts, *regranted_for);
            *slot = match regranted_for {
                Some(d) if open.contains(&d) => {
                    if attempts.spend_renewal(max) || api_only {
                        Slot::ApiPending { attempts }
                    } else {
                        Slot::NeedsGrant {
                            attempts,
                            not_before_ms: now_ms,
                            regranted_for,
                        }
                    }
                }
                _ if api_only => Slot::ApiPending { attempts },
                _ => Slot::Idle {
                    attempts,
                    regranted_for,
                },
            };
        }
    }

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

    /// The strongest verdict stands (`Corrupt` > `Terminal` > `Restart` > `ApiForFile`), as in
    /// `DownloadPlanner::set_verdict`.
    fn set_verdict(&mut self, verdict: Verdict) {
        if self.verdict.as_ref().is_none_or(|v| verdict.strength() > v.strength()) {
            self.verdict = Some(verdict);
        }
    }

    /// The answer to the outstanding window request; `Err` means it was refused.
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

    /// The 2xx body of the outstanding window request, as it came off the wire.
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

    /// A 2xx window answer that cannot be decoded at all.
    pub fn window_malformed(&mut self) {
        self.window = None;
        self.window_unusable();
    }

    /// A window cannot be served: the rest goes through the pinned per-chunk API route (the
    /// version is pinned from the start). Without a geometry nothing can be planned: `ApiForFile`.
    fn window_unusable(&mut self) {
        if self.geometry.is_none() {
            self.set_verdict(Verdict::ApiForFile);
            return;
        }
        self.api_only = true;
        for slot in self.slots.values_mut() {
            if let Slot::NeedsGrant { attempts, .. } | Slot::Idle { attempts, .. } = slot {
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
        let check = WindowCheck {
            file_id: &self.file_id,
            discovery: &self.discovery,
            api_base: &self.api_base,
            pinned: Some(&self.pinned),
            known: self.geometry,
            url_ttl_ms: self.cfg.url_ttl_ms,
            renew_skew_ms: self.cfg.renew_skew_ms,
        };
        let checked = check_window(&check, request, response, now_ms)?;
        self.geometry.get_or_insert(checked.geometry);
        for (grant, usable_until_ms) in checked.grants {
            let index = grant.index;
            if self.released.contains(u64::from(index)) {
                continue;
            }
            let (attempts, regranted_for) = match self.slots.get(&index) {
                None => (Attempts::default(), None),
                Some(
                    Slot::Granted {
                        attempts,
                        regranted_for,
                        ..
                    }
                    | Slot::Idle {
                        attempts,
                        regranted_for,
                    }
                    | Slot::NeedsGrant {
                        attempts,
                        regranted_for,
                        ..
                    },
                ) => (*attempts, *regranted_for),
                Some(_) => continue,
            };
            let slot = if self.storage_given_up {
                Slot::ApiPending { attempts }
            } else {
                Slot::Granted {
                    attempts,
                    grant,
                    usable_until_ms,
                    regranted_for,
                }
            };
            self.slots.insert(index, slot);
        }
        Ok(())
    }

    /// The outstanding window request failed; `outcome` is what [`super::classify`] said.
    pub fn window_failed(&mut self, outcome: Outcome, now_ms: i64) {
        self.window = None;
        match outcome {
            Outcome::Backoff(wait) => {
                if rate_limit_spent(&mut self.rate_limits, self.cfg.max_rate_limits) {
                    self.window_unusable();
                } else {
                    let wait_ms = i64::try_from(wait.as_millis()).unwrap_or(i64::MAX).min(MAX_WAIT_MS);
                    self.window_not_before_ms = self.window_not_before_ms.max(now_ms.saturating_add(wait_ms));
                }
            }
            Outcome::Restart => self.set_verdict(Verdict::Restart),
            Outcome::Terminal(terminal) => self.set_verdict(Verdict::Terminal(terminal)),
            _ => self.window_unusable(),
        }
    }

    /// Chunk `index` arrived whole (status and length checked). It waits to be opened.
    pub fn fetch_ok(&mut self, index: u32) -> Result<(), RangeError> {
        let Some(Slot::Fetching { attempts, via_api }) = self.slots.get(&index) else {
            return Err(RangeError::NotInFlight(index));
        };
        let (attempts, via_api) = (*attempts, *via_api);
        if !via_api {
            self.storage_ok = true;
        }
        self.slots.insert(index, Slot::Fetched { attempts });
        Ok(())
    }

    /// The storage fetch of chunk `index` failed: renewed with backoff, then the pinned API route
    /// (the renewal budget and the storage breaker of `DownloadPlanner::fetch_failed`).
    pub fn fetch_failed(&mut self, index: u32, now_ms: i64) -> Result<(), RangeError> {
        let Some(Slot::Fetching { attempts, via_api }) = self.slots.get(&index) else {
            return Err(RangeError::NotInFlight(index));
        };
        let (mut attempts, via_api) = (*attempts, *via_api);
        if via_api {
            return Err(RangeError::ApiRouteFailure(index));
        }
        let exhausted = attempts.spend_renewal(self.cfg.max_renewals);
        if exhausted || self.api_only {
            self.slots.insert(index, Slot::ApiPending { attempts });
            if exhausted && !self.api_only && !self.storage_ok {
                self.give_up_storage();
            }
        } else {
            let delay = backoff_delay(
                &mut self.rng,
                self.cfg.backoff_base_ms,
                self.cfg.backoff_cap_ms,
                attempts.renewals,
            );
            self.slots.insert(
                index,
                Slot::NeedsGrant {
                    attempts,
                    not_before_ms: now_ms.saturating_add(delay),
                    regranted_for: None,
                },
            );
        }
        Ok(())
    }

    fn give_up_storage(&mut self) {
        self.storage_given_up = true;
        self.api_only = true;
        for slot in self.slots.values_mut() {
            if let Slot::NeedsGrant { attempts, .. } | Slot::Granted { attempts, .. } | Slot::Idle { attempts, .. } =
                slot
            {
                *slot = Slot::ApiPending { attempts: *attempts };
            }
        }
    }

    /// The pinned API route failed for chunk `index` after the caller's retries: the session ends
    /// with [`Verdict::ApiForFile`].
    pub fn api_fetch_failed(&mut self, index: u32) -> Result<(), RangeError> {
        match self.slots.get(&index) {
            Some(Slot::Fetching { via_api: true, .. }) => {
                self.slots.remove(&index);
                self.set_verdict(Verdict::ApiForFile);
                Ok(())
            }
            _ => Err(RangeError::NotInFlight(index)),
        }
    }

    /// Chunk `index` arrived whole but `RangeOpener` refused it. It is fetched once through the
    /// pinned API route; if that copy does not open either, the session ends with
    /// [`Verdict::Corrupt`].
    ///
    /// A range session has released only frames `RangeOpener` authenticated; on this verdict it
    /// poisons the sink (I5) and releases nothing more.
    pub fn chunk_unauthentic(&mut self, index: u32) -> Result<(), RangeError> {
        let Some(Slot::Fetched { attempts }) = self.slots.get(&index) else {
            return Err(RangeError::NotFetched(index));
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

    /// Chunk `index` was opened by `RangeOpener` and handed over. Any order.
    pub fn released(&mut self, index: u32) -> Result<(), RangeError> {
        match self.slots.get(&index) {
            Some(Slot::Fetched { .. }) => {
                self.slots.remove(&index);
                self.released.insert(u64::from(index), u64::from(index) + 1);
                Ok(())
            }
            _ => Err(RangeError::NotFetched(index)),
        }
    }
}
