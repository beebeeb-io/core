//! The backup manifest: each asset's backup copy as this device last saw it,
//! and the pass gate's state, kept by the platform ([`BackupManifestStore`]).

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex},
};

use super::{Asset, BackupCopyState, BackupError, BackupPassState};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupManifestRecord {
    pub local_identifier: String,
    pub file_id: String,
    pub state: BackupCopyState,
    pub local_present: bool,
    pub retry_count: u32,
    /// The asset's [`Asset::modified_ms`] and [`Asset::size_bytes`] as this
    /// record last saw them. A removed copy comes back only when the asset no
    /// longer matches; a side not known yet is taken from the asset at the
    /// next pass, which is not a change.
    pub modified_ms: Option<i64>,
    pub size_bytes: Option<u64>,
}

/// Whether `asset` changed on the device since `record` saw it: a side both
/// know that differs.
pub(super) fn asset_changed(record: &BackupManifestRecord, asset: &Asset) -> bool {
    matches!((record.modified_ms, asset.modified_ms), (Some(was), Some(now)) if was != now)
        || matches!((record.size_bytes, asset.size_bytes), (Some(was), Some(now)) if was != now)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum BackupManifestStoreError {
    #[error("the backup manifest store is unavailable")]
    Unavailable,
}

/// The platform's durable copy of the manifest and the pass state. Its
/// methods run while the [`BackupService`] holds its manifest or pass-state
/// lock: they must not call back into the service.
pub trait BackupManifestStore: Send + Sync {
    fn load(&self) -> Result<Vec<BackupManifestRecord>, BackupManifestStoreError>;
    fn replace(&self, records: &[BackupManifestRecord]) -> Result<(), BackupManifestStoreError>;
    /// The pass gate's state; [`BackupPassState::default`] when none was saved.
    fn load_pass_state(&self) -> Result<BackupPassState, BackupManifestStoreError>;
    fn save_pass_state(&self, state: &BackupPassState) -> Result<(), BackupManifestStoreError>;
    /// Remove every record and the pass state.
    fn clear(&self) -> Result<(), BackupManifestStoreError>;
}

#[derive(Default)]
pub struct MemoryBackupManifestStore {
    records: Mutex<Vec<BackupManifestRecord>>,
    pass: Mutex<BackupPassState>,
}

impl BackupManifestStore for MemoryBackupManifestStore {
    fn load(&self) -> Result<Vec<BackupManifestRecord>, BackupManifestStoreError> {
        Ok(self
            .records
            .lock()
            .map_err(|_| BackupManifestStoreError::Unavailable)?
            .clone())
    }

    fn replace(&self, records: &[BackupManifestRecord]) -> Result<(), BackupManifestStoreError> {
        *self.records.lock().map_err(|_| BackupManifestStoreError::Unavailable)? = records.to_vec();
        Ok(())
    }

    fn load_pass_state(&self) -> Result<BackupPassState, BackupManifestStoreError> {
        Ok(self
            .pass
            .lock()
            .map_err(|_| BackupManifestStoreError::Unavailable)?
            .clone())
    }

    fn save_pass_state(&self, state: &BackupPassState) -> Result<(), BackupManifestStoreError> {
        *self.pass.lock().map_err(|_| BackupManifestStoreError::Unavailable)? = state.clone();
        Ok(())
    }

    fn clear(&self) -> Result<(), BackupManifestStoreError> {
        self.records
            .lock()
            .map_err(|_| BackupManifestStoreError::Unavailable)?
            .clear();
        *self.pass.lock().map_err(|_| BackupManifestStoreError::Unavailable)? = BackupPassState::default();
        Ok(())
    }
}

#[derive(Clone)]
pub struct BackupManifest {
    entries: Arc<Mutex<BTreeMap<String, BackupManifestRecord>>>,
    pass: Arc<Mutex<BackupPassState>>,
    persistence: Arc<dyn BackupManifestStore>,
}

impl BackupManifest {
    pub fn open(persistence: Arc<dyn BackupManifestStore>) -> Result<Self, BackupError> {
        let entries = persistence
            .load()?
            .into_iter()
            .map(|record| (record.local_identifier.clone(), record))
            .collect();
        let pass = persistence.load_pass_state()?;
        Ok(Self {
            entries: Arc::new(Mutex::new(entries)),
            pass: Arc::new(Mutex::new(pass)),
            persistence,
        })
    }

    /// The pass gate's state.
    pub fn pass_state(&self) -> Result<BackupPassState, BackupError> {
        Ok(self.pass.lock().map_err(|_| BackupError::State)?.clone())
    }

    /// Change the pass state as it is now, under its lock: persist first,
    /// then remember, so a state the platform could not store is never acted
    /// on. Every write goes through here, so one writer never puts back a copy
    /// it read before another wrote (a stop sticks). Returns the new state.
    pub(crate) fn update_pass_state(
        &self,
        change: impl FnOnce(&mut BackupPassState),
    ) -> Result<BackupPassState, BackupError> {
        let mut pass = self.pass.lock().map_err(|_| BackupError::State)?;
        let mut state = pass.clone();
        change(&mut state);
        self.persistence.save_pass_state(&state)?;
        *pass = state.clone();
        Ok(state)
    }

    /// Forget every `Queued` record. Run once a stopped backup's uploads are
    /// cancelled, so none of them can be live; a pass after "Back up again"
    /// asks the server about them afresh.
    pub(super) fn forget_queued(&self) -> Result<(), BackupError> {
        let mut entries = self.entries.lock().map_err(|_| BackupError::State)?;
        let before = entries.len();
        entries.retain(|_, entry| entry.state != BackupCopyState::Queued);
        if entries.len() == before {
            return Ok(());
        }
        self.persist(&entries)
    }

    /// "Back up again": forget every record, so the backup starts fresh. A
    /// copy still on the server is found again by the server's check and
    /// counts as backed up (spec rules 3 and 10).
    pub(super) fn forget_all(&self) -> Result<(), BackupError> {
        let mut entries = self.entries.lock().map_err(|_| BackupError::State)?;
        entries.clear();
        self.persist(&entries)
    }

    /// Record a copy's state. The record keeps what it last saw of the asset;
    /// [`Self::remember_asset`] records that too.
    pub fn remember(&self, local_identifier: &str, file_id: &str, state: BackupCopyState) -> Result<(), BackupError> {
        self.record(local_identifier, file_id, state, None)
    }

    /// Record a copy's state, with the asset as the pass sees it now.
    pub(crate) fn remember_asset(
        &self,
        asset: &Asset,
        file_id: &str,
        state: BackupCopyState,
    ) -> Result<(), BackupError> {
        self.record(
            &asset.local_identifier,
            file_id,
            state,
            Some((asset.modified_ms, asset.size_bytes)),
        )
    }

    fn record(
        &self,
        local_identifier: &str,
        file_id: &str,
        state: BackupCopyState,
        seen: Option<(Option<i64>, Option<u64>)>,
    ) -> Result<(), BackupError> {
        let mut entries = self.entries.lock().map_err(|_| BackupError::State)?;
        let existing = entries.get(local_identifier);
        let retry_count = if state == BackupCopyState::Active {
            0
        } else {
            existing.map_or(0, |entry| entry.retry_count)
        };
        let (modified_ms, size_bytes) =
            seen.unwrap_or_else(|| existing.map_or((None, None), |entry| (entry.modified_ms, entry.size_bytes)));
        entries.insert(
            local_identifier.to_owned(),
            BackupManifestRecord {
                local_identifier: local_identifier.to_owned(),
                file_id: file_id.to_owned(),
                state,
                local_present: true,
                retry_count,
                modified_ms,
                size_bytes,
            },
        );
        self.persist(&entries)
    }

    /// Whether a pass may consider `asset` for an upload: it has no record,
    /// its upload failed, its copy is on the server and `check_active` (the
    /// server's check runs again), or its copy was removed and the asset
    /// changed on the device since (spec §4.2 rule 11). A removed record that
    /// does not know a side of the asset yet takes it now: that is the
    /// baseline a later change is measured against, never a change itself.
    pub(super) fn may_back_up(&self, asset: &Asset, check_active: bool) -> Result<bool, BackupError> {
        let mut entries = self.entries.lock().map_err(|_| BackupError::State)?;
        let Some(entry) = entries.get_mut(&asset.local_identifier) else {
            return Ok(true);
        };
        match entry.state {
            BackupCopyState::UploadFailed => Ok(true),
            BackupCopyState::Active => Ok(check_active),
            BackupCopyState::Queued => Ok(false),
            BackupCopyState::Trashed | BackupCopyState::Deleted | BackupCopyState::RemovedElsewhere => {
                if asset_changed(entry, asset) {
                    return Ok(true);
                }
                let learns = (entry.modified_ms.is_none() && asset.modified_ms.is_some())
                    || (entry.size_bytes.is_none() && asset.size_bytes.is_some());
                if learns {
                    entry.modified_ms = entry.modified_ms.or(asset.modified_ms);
                    entry.size_bytes = entry.size_bytes.or(asset.size_bytes);
                    self.persist(&entries)?;
                }
                Ok(false)
            }
        }
    }

    /// The server's check asked for a copy this device had backed up: it was
    /// removed elsewhere. It stays removed until the asset changes after now
    /// (the safer reading of rule 11: a change made before the removal does
    /// not bring the copy back).
    pub(super) fn mark_removed_elsewhere(&self, asset: &Asset) -> Result<(), BackupError> {
        let mut entries = self.entries.lock().map_err(|_| BackupError::State)?;
        if let Some(entry) = entries.get_mut(&asset.local_identifier) {
            entry.state = BackupCopyState::RemovedElsewhere;
            entry.modified_ms = asset.modified_ms;
            entry.size_bytes = asset.size_bytes;
        }
        self.persist(&entries)
    }

    pub fn copy_state(&self, local_identifier: &str) -> Option<BackupCopyState> {
        self.entries.lock().ok()?.get(local_identifier).map(|entry| entry.state)
    }

    pub fn file_id(&self, local_identifier: &str) -> Option<String> {
        self.entries
            .lock()
            .ok()?
            .get(local_identifier)
            .map(|entry| entry.file_id.clone())
    }

    pub fn retry_count(&self, local_identifier: &str) -> Option<u32> {
        self.entries
            .lock()
            .ok()?
            .get(local_identifier)
            .map(|entry| entry.retry_count)
    }

    pub(super) fn reconcile_local_identifiers(
        &self,
        present: &BTreeSet<String>,
        complete: bool,
    ) -> Result<(), BackupError> {
        let mut entries = self.entries.lock().map_err(|_| BackupError::State)?;
        for (identifier, entry) in entries.iter_mut() {
            if present.contains(identifier) {
                entry.local_present = true;
            } else if complete {
                // Phone-side deletion deliberately keeps the remote backup.
                entry.local_present = false;
            }
        }
        self.persist(&entries)
    }

    pub(super) fn mark_retryable(&self, local_identifier: &str, file_id: &str) -> Result<(), BackupError> {
        let mut entries = self.entries.lock().map_err(|_| BackupError::State)?;
        let entry = entries
            .entry(local_identifier.to_owned())
            .or_insert_with(|| BackupManifestRecord {
                local_identifier: local_identifier.to_owned(),
                file_id: file_id.to_owned(),
                state: BackupCopyState::UploadFailed,
                local_present: true,
                retry_count: 0,
                modified_ms: None,
                size_bytes: None,
            });
        entry.file_id = file_id.to_owned();
        entry.state = BackupCopyState::UploadFailed;
        entry.retry_count = entry.retry_count.saturating_add(1);
        self.persist(&entries)
    }

    /// The platform reports a copy's state. A copy reported removed forgets
    /// what it saw of the asset, so the next pass takes the asset as it is
    /// then: only a change after the removal brings it back (rule 11).
    pub(super) fn update_copy_state(&self, file_id: &str, state: BackupCopyState) -> Result<(), BackupError> {
        let mut entries = self.entries.lock().map_err(|_| BackupError::State)?;
        if let Some(entry) = entries.values_mut().find(|entry| entry.file_id == file_id) {
            if state.removed() && !entry.state.removed() {
                entry.modified_ms = None;
                entry.size_bytes = None;
            }
            entry.state = state;
        }
        self.persist(&entries)
    }

    pub fn clear(&self) -> Result<(), BackupError> {
        self.entries.lock().map_err(|_| BackupError::State)?.clear();
        *self.pass.lock().map_err(|_| BackupError::State)? = BackupPassState::default();
        self.persistence.clear()?;
        Ok(())
    }

    fn persist(&self, entries: &BTreeMap<String, BackupManifestRecord>) -> Result<(), BackupError> {
        self.persistence
            .replace(&entries.values().cloned().collect::<Vec<_>>())?;
        Ok(())
    }
}

impl Default for BackupManifest {
    fn default() -> Self {
        Self {
            entries: Arc::new(Mutex::new(BTreeMap::new())),
            pass: Arc::new(Mutex::new(BackupPassState::default())),
            persistence: Arc::new(MemoryBackupManifestStore::default()),
        }
    }
}
