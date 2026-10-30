//! State shared by every download of one `(api_base, account_id)` (plan K2).
//!
//! Discovery's answer and the storage-health hold live here, so two files in
//! one process do not each pay a discovery call and a broken storage host is
//! not retried per file. `DirectStore::global()` is the process-wide map;
//! [`DirectStore::forget_account`] drops everything an account knows (a sign
//! out, an account switch).

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

use beebeeb_core::direct_transfer::{DirectHealth, Direction, Discovery, DiscoveryCache, Lookup, Outcome};

/// The persisted health of one client: when each direction last gave up
/// direct, on the wall clock (an iOS client stores it across launches).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HealthSnapshot {
    pub download_gave_up_wall_ms: Option<i64>,
    pub upload_gave_up_wall_ms: Option<i64>,
}

/// Discovery, health and the in-flight bookkeeping of one API base and account.
#[derive(Debug)]
pub struct DirectShared {
    discovery: Mutex<DiscoveryCache>,
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
            discovery: Mutex::new(DiscoveryCache::new()),
            health: Mutex::new(DirectHealth::new()),
        }
    }

    /// What to do about discovery right now.
    pub(crate) fn discovery_lookup(&self, now_ms: i64) -> Lookup {
        self.discovery.lock().unwrap().lookup(now_ms)
    }

    /// Record a discovery answer in the shared cache.
    pub(crate) fn record_discovery(&self, outcome: &Outcome, discovery: Option<Discovery>, now_ms: i64) {
        self.discovery.lock().unwrap().record(outcome, discovery, now_ms);
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
        *self.discovery.lock().unwrap() = DiscoveryCache::new();
        *self.health.lock().unwrap() = DirectHealth::new();
    }
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
        let key = (api_base.to_string(), account_id.to_string());
        let mut entries = self.entries.lock().unwrap();
        entries
            .entry(key)
            .or_insert_with(|| Arc::new(DirectShared::new()))
            .clone()
    }

    /// Drop every entry of `account_id` (all API bases), and forget what each
    /// of them knew.
    pub fn forget_account(&self, account_id: &str) {
        let mut entries = self.entries.lock().unwrap();
        let keys: Vec<(String, String)> = entries
            .keys()
            .filter(|(_, account)| account == account_id)
            .cloned()
            .collect();
        for key in keys {
            if let Some(shared) = entries.remove(&key) {
                shared.forget();
            }
        }
    }
}
