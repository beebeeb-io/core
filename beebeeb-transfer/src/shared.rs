//! State shared by every download of one `(api_base, account_id)` (plan K2).
//!
//! Discovery's answer and the storage-health hold live here, so two files in
//! one process do not each pay a discovery call and a broken storage host is
//! not retried per file. `DirectStore::global()` is the process-wide map;
//! [`DirectStore::forget_account`] drops everything an account knows (a sign
//! out, an account switch).

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::task::{Poll, Waker};

use beebeeb_core::direct_transfer::{DirectHealth, Direction, Discovery, DiscoveryCache, Lookup, Outcome};

/// The persisted health of one client: when each direction last gave up
/// direct, on the wall clock (an iOS client stores it across launches).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HealthSnapshot {
    pub download_gave_up_wall_ms: Option<i64>,
    pub upload_gave_up_wall_ms: Option<i64>,
}

/// The answer one discovery flight produced. Concurrent callers share it, so a
/// failure is counted once and asked once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DiscoveryFlightResult {
    /// The server offers direct download.
    Supported(Discovery),
    /// The server says it does not offer it (a JSON 404): cache it for the
    /// trust period.
    NotSupported,
    /// No usable answer right now (a 5xx, a bare 404/405, a redirect, a
    /// transport failure): use the API for this file, ask again later.
    Unavailable,
    /// The API answered 401: sign in again.
    Unauthorized,
    /// The API answered 403.
    Forbidden,
}

/// What to do about discovery right now, including who runs the call.
#[derive(Debug)]
pub(crate) enum DiscoveryStart {
    /// A trusted answer says direct is offered.
    Cached(Discovery),
    /// A trusted answer says the server does not offer it.
    NotSupported,
    /// Asking has already failed enough within the trust period.
    Unavailable,
    /// This caller runs the one discovery call.
    Lead,
    /// One call is already in flight; wait for its shared answer.
    Follow,
}

#[derive(Debug, Default)]
struct Flight {
    running: bool,
    last: Option<DiscoveryFlightResult>,
    waiters: Vec<Waker>,
}

#[derive(Debug, Default)]
struct DiscoveryState {
    cache: DiscoveryCache,
    /// Why the cache would say `Lookup::UseApi`: `true` = a cached
    /// `NotSupported`, `false` = the failure budget is spent.
    parked_not_supported: bool,
    flight: Flight,
}

/// Discovery, health and the in-flight bookkeeping of one API base and account.
#[derive(Debug)]
pub struct DirectShared {
    discovery: Mutex<DiscoveryState>,
    health: Mutex<DirectHealth>,
}

impl Default for DirectShared {
    fn default() -> Self {
        Self::new()
    }
}

impl DirectShared {
    pub(crate) fn new() -> Self {
        DirectShared {
            discovery: Mutex::new(DiscoveryState::default()),
            health: Mutex::new(DirectHealth::new()),
        }
    }

    /// What to do about discovery right now (the cache's view; tests and adapters).
    #[allow(dead_code)]
    pub(crate) fn discovery_lookup(&self, now_ms: i64) -> Lookup {
        self.discovery.lock().unwrap().cache.lookup(now_ms)
    }

    /// Start (or join) the one discovery call for this key.
    pub(crate) fn discovery_start(&self, now_ms: i64) -> DiscoveryStart {
        let mut state = self.discovery.lock().unwrap();
        match state.cache.lookup(now_ms) {
            Lookup::Cached(discovery) => DiscoveryStart::Cached(discovery),
            Lookup::UseApi => {
                if state.parked_not_supported {
                    DiscoveryStart::NotSupported
                } else {
                    DiscoveryStart::Unavailable
                }
            }
            Lookup::Fetch => {
                if state.flight.running {
                    DiscoveryStart::Follow
                } else {
                    state.flight.running = true;
                    DiscoveryStart::Lead
                }
            }
        }
    }

    /// Record a finished flight and wake every follower with the same answer.
    pub(crate) fn discovery_finished(&self, result: DiscoveryFlightResult, now_ms: i64) {
        {
            let mut state = self.discovery.lock().unwrap();
            let outcome = match &result {
                DiscoveryFlightResult::Supported(_) => Outcome::Proceed,
                DiscoveryFlightResult::NotSupported => Outcome::NotSupported,
                DiscoveryFlightResult::Unavailable => Outcome::UseApiNow,
                DiscoveryFlightResult::Unauthorized => Outcome::Terminal(beebeeb_core::direct_transfer::Terminal {
                    status: 401,
                    error: None,
                }),
                DiscoveryFlightResult::Forbidden => Outcome::Terminal(beebeeb_core::direct_transfer::Terminal {
                    status: 403,
                    error: None,
                }),
            };
            let discovery = match &result {
                DiscoveryFlightResult::Supported(discovery) => Some(discovery.clone()),
                _ => None,
            };
            state.cache.record(&outcome, discovery, now_ms);
            // The cache leaves authorization answers unchanged; keep the
            // parked reason for the state it actually holds.
            match &result {
                DiscoveryFlightResult::NotSupported => state.parked_not_supported = true,
                DiscoveryFlightResult::Unauthorized | DiscoveryFlightResult::Forbidden => {}
                _ => state.parked_not_supported = false,
            }
            state.flight.running = false;
            state.flight.last = Some(result);
            let waiters = std::mem::take(&mut state.flight.waiters);
            drop(state);
            for waker in waiters {
                waker.wake();
            }
        }
    }

    /// Wait for the flight another caller is running.
    pub(crate) async fn discovery_follow(&self) -> DiscoveryFlightResult {
        std::future::poll_fn(|cx| {
            let mut state = self.discovery.lock().unwrap();
            if state.flight.running {
                state.flight.waiters.push(cx.waker().clone());
                Poll::Pending
            } else {
                Poll::Ready(state.flight.last.clone().unwrap_or(DiscoveryFlightResult::Unavailable))
            }
        })
        .await
    }

    /// Record a discovery answer in the shared cache (single-caller form, for
    /// tests and restores).
    #[allow(dead_code)]
    pub(crate) fn record_discovery(&self, outcome: &Outcome, discovery: Option<Discovery>, now_ms: i64) {
        let mut state = self.discovery.lock().unwrap();
        state.cache.record(outcome, discovery, now_ms);
        match outcome {
            Outcome::NotSupported => state.parked_not_supported = true,
            Outcome::Terminal(answer) if matches!(answer.status, 401 | 403) => {}
            _ => state.parked_not_supported = false,
        }
    }

    /// May a new direct download start now? `mono_ms` is the driver's clock.
    pub(crate) fn may_start_download(&self, mono_ms: i64) -> bool {
        self.health.lock().unwrap().may_start(Direction::Download, mono_ms)
    }

    /// Record that downloads gave up direct at `mono_ms`.
    pub(crate) fn gave_up_download(&self, mono_ms: i64) {
        self.health.lock().unwrap().gave_up(Direction::Download, mono_ms);
    }

    /// Record that uploads gave up direct at `mono_ms` (the upload driver is a
    /// later task; the method keeps one store authoritative).
    #[allow(dead_code)]
    pub(crate) fn gave_up_upload(&self, mono_ms: i64) {
        self.health.lock().unwrap().gave_up(Direction::Upload, mono_ms);
    }

    /// The health as wall-clock timestamps, for persistence.
    pub fn health_snapshot(&self, wall_ms: i64, mono_ms: i64) -> HealthSnapshot {
        let health = self.health.lock().unwrap();
        let to_wall = |at: Option<i64>| at.map(|at| wall_ms.saturating_sub(mono_ms.saturating_sub(at)));
        HealthSnapshot {
            download_gave_up_wall_ms: to_wall(health.last_gave_up_ms(Direction::Download)),
            upload_gave_up_wall_ms: to_wall(health.last_gave_up_ms(Direction::Upload)),
        }
    }

    /// Restore a persisted snapshot. `None` clears that direction.
    pub fn restore(&self, snapshot: HealthSnapshot, wall_ms: i64, mono_ms: i64) {
        let to_mono = |at: Option<i64>| at.map(|at| mono_ms.saturating_sub(wall_ms.saturating_sub(at)));
        let mut health = DirectHealth::new();
        if let Some(at) = to_mono(snapshot.download_gave_up_wall_ms) {
            health.restore(Direction::Download, at);
        }
        if let Some(at) = to_mono(snapshot.upload_gave_up_wall_ms) {
            health.restore(Direction::Upload, at);
        }
        *self.health.lock().unwrap() = health;
    }

    /// Drop everything this account's state knows (discovery and health).
    pub(crate) fn forget(&self) {
        let mut state = self.discovery.lock().unwrap();
        state.cache = DiscoveryCache::new();
        state.parked_not_supported = false;
        state.flight.running = false;
        state.flight.last = None;
        let waiters = std::mem::take(&mut state.flight.waiters);
        drop(state);
        for waker in waiters {
            waker.wake();
        }
        *self.health.lock().unwrap() = DirectHealth::new();
    }
}

/// Normalise an API origin: no trailing slash, lowercase scheme and host. The
/// path (rare, but legal) keeps its case.
pub(crate) fn normalize_api_base(api_base: &str) -> String {
    let trimmed = api_base.trim_end_matches('/');
    match trimmed.split_once("://") {
        Some((scheme, rest)) => {
            let (authority, path) = match rest.find('/') {
                Some(index) => rest.split_at(index),
                None => (rest, ""),
            };
            format!(
                "{}://{}{path}",
                scheme.to_ascii_lowercase(),
                authority.to_ascii_lowercase()
            )
        }
        None => trimmed.to_ascii_lowercase(),
    }
}

/// Normalise an account id (a UUID, or an opaque handle in tests): lowercase.
pub(crate) fn normalize_account_id(account_id: &str) -> String {
    account_id.to_ascii_lowercase()
}

/// One shared state per `(api_base, account_id)`.
#[derive(Debug, Default)]
pub struct DirectStore {
    entries: Mutex<HashMap<(String, String), Arc<DirectShared>>>,
}

impl DirectStore {
    pub(crate) fn new() -> Self {
        DirectStore::default()
    }

    /// The process-wide store.
    pub fn global() -> &'static DirectStore {
        static GLOBAL: OnceLock<DirectStore> = OnceLock::new();
        GLOBAL.get_or_init(DirectStore::new)
    }

    /// The state for this API base and account, creating it on first use.
    pub fn entry(&self, api_base: &str, account_id: &str) -> Arc<DirectShared> {
        let key = (normalize_api_base(api_base), normalize_account_id(account_id));
        let mut entries = self.entries.lock().unwrap();
        entries
            .entry(key)
            .or_insert_with(|| Arc::new(DirectShared::new()))
            .clone()
    }

    /// Drop every entry of `account_id` (all API bases), and forget what each
    /// of them knew. Any spelling of the same key hits the same entry.
    pub fn forget_account(&self, account_id: &str) {
        let account = normalize_account_id(account_id);
        let mut entries = self.entries.lock().unwrap();
        let keys: Vec<(String, String)> = entries
            .keys()
            .filter(|(_, stored)| *stored == account)
            .cloned()
            .collect();
        for key in keys {
            if let Some(shared) = entries.remove(&key) {
                shared.forget();
            }
        }
    }
}
