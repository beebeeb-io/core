use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
    sync::{Arc, Mutex},
};

use beebeeb_types::backup::BackupStopReason;
use tokio::sync::broadcast;

use crate::{
    Client,
    uploads::{
        BackupUploadOutcomeKind, NetworkKind, TransferRule, UploadCompletionHandler, UploadRequest, UploadService,
        UploadServiceError,
    },
};

mod gate;

pub use gate::{BackupPassState, BackupStop, NOTICE_OVERLAP_MS};
use gate::{CheckedFolder, PassDecision};

const MAX_ASSETS_PER_PAGE: usize = 500;
const MAX_QUEUED_BACKUP_UPLOADS: usize = 64;
const MAX_BACKUP_FAILURES: u32 = 3;
/// The most backed-up copies one pass looks up on the server (one page: a
/// pass reads at most [`MAX_QUEUED_BACKUP_UPLOADS`] assets). Any more stay
/// `Active`, upload nothing and are looked up when the snapshot reaches them
/// again.
const MAX_COPY_LOOKUPS_PER_PASS: usize = MAX_QUEUED_BACKUP_UPLOADS;
/// The server reads a longer `X-Beebeeb-Device-Id` as missing.
const MAX_DEVICE_ID_BYTES: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackupPolicy {
    pub transfer: TransferRule,
}

impl Default for BackupPolicy {
    fn default() -> Self {
        Self {
            transfer: TransferRule { wifi_only: true },
        }
    }
}

impl BackupPolicy {
    pub fn may_start_batch(self, network: NetworkKind, deduplication_check_succeeded: bool) -> bool {
        deduplication_check_succeeded && self.transfer.allows(network)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AssetKind {
    Photo,
    ContactSnapshot,
    CalendarSnapshot,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Asset {
    pub local_identifier: String,
    pub export_path: PathBuf,
    pub name: String,
    pub mime_type: Option<String>,
    /// When the asset last changed on the device (ms) and its size in bytes,
    /// as the platform reports them; `None` when unknown. A copy removed from
    /// the backup is uploaded again only when one of them changes (backup
    /// spec §4.2 rule 11).
    pub modified_ms: Option<i64>,
    pub size_bytes: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssetSnapshot {
    /// False means the platform returned only a partial view. Missing assets
    /// then carry no deletion authority.
    pub complete: bool,
    pub assets: Vec<Asset>,
    /// Opaque platform cursor for the next page. `None` ends the snapshot.
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AssetSourceError {
    #[error("asset access is unavailable")]
    Unavailable,
    #[error("asset access was not permitted")]
    NotPermitted,
}

/// Platform seam for PhotoKit, Contacts and Calendar. Export paths are
/// platform-created inputs; core decides whether and where they are queued.
/// Called during [`BackupService::next_batch`], under its pass lock: never
/// call back into the service, nor wait on a thread inside `next_batch`.
pub trait AssetSource: Send + Sync {
    fn snapshot(&self, kind: AssetKind, cursor: Option<&str>, limit: usize) -> Result<AssetSnapshot, AssetSourceError>;

    /// Materialize one asset only after policy and deduplication selected it
    /// for the bounded upload queue.
    fn export(&self, _kind: AssetKind, asset: &Asset) -> Result<PathBuf, AssetSourceError> {
        Ok(asset.export_path.clone())
    }
}

/// The folder this device's backups are written into: a device folder, or a
/// category folder inside it, under the account's Backups root. The root is
/// the row whose `system_role` is `backups_root` (backup spec §4.2 rule 5);
/// [`BackupService`] checks that the folder is there before it queues anything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupFolder {
    pub id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupConfiguration {
    pub folder: BackupFolder,
    pub wifi_only: bool,
    /// This device's canonical id, the one the app already sends as
    /// `X-Beebeeb-Device-Id` (mobile: `getDeviceId()`). The server keys this
    /// device's photo-backup map by it; without it every device of the
    /// account would share one map, and one phone's photo ids would hide
    /// another's. Core never makes one up. Checked by [`Self::new`]: 1 to 128
    /// visible ASCII characters.
    pub device_id: String,
    /// When backups were turned on on this device, server clock, ms (backup
    /// spec Amendment 12c). With no pass yet, only notices newer than core's
    /// `first_pass_baseline` of this and [`Self::legacy_last_backup_ms`]
    /// stop the backup; with neither known, any removal notice does.
    pub setup_at_ms: Option<i64>,
    /// An upgraded device's last successful backup under the old engine,
    /// server clock, ms.
    pub legacy_last_backup_ms: Option<i64>,
}

impl BackupConfiguration {
    pub fn new(folder: BackupFolder, wifi_only: bool, device_id: impl Into<String>) -> Result<Self, BackupError> {
        if folder.id.is_empty() {
            return Err(BackupError::NotInBackups);
        }
        let device_id = device_id.into();
        if !valid_device_id(&device_id) {
            return Err(BackupError::InvalidDeviceId);
        }
        Ok(Self {
            folder,
            wifi_only,
            device_id,
            setup_at_ms: None,
            legacy_last_backup_ms: None,
        })
    }

    /// What this device knows for its first pass's baseline (Amendment 12c).
    pub fn with_first_pass(mut self, setup_at_ms: Option<i64>, legacy_last_backup_ms: Option<i64>) -> Self {
        self.setup_at_ms = setup_at_ms;
        self.legacy_last_backup_ms = legacy_last_backup_ms;
        self
    }
}

/// A device id the server keys by as sent: 1 to 128 visible ASCII
/// characters (nothing it would trim, nothing a header cannot carry).
fn valid_device_id(device_id: &str) -> bool {
    !device_id.is_empty()
        && device_id.len() <= MAX_DEVICE_ID_BYTES
        && device_id.bytes().all(|byte| byte.is_ascii_graphic())
}

/// Where an asset's backup copy stands. Only [`Self::UploadFailed`] and an
/// asset with no record are uploaded (again). A removed copy
/// ([`Self::removed`]) stays removed until the asset changes on the device
/// again: a new modification time or size (backup spec §4.2 rule 11; core
/// Never break: a stopped backup never fills the account up again by itself).
/// "Back up again" after a stop forgets every record and starts fresh.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackupCopyState {
    Active,
    Queued,
    /// In the Trash on the server, as the platform reported.
    Trashed,
    /// Deleted on the server, as the platform reported.
    Deleted,
    /// Gone from the server without a word here (trashed or deleted on the
    /// web or another device): the server's check asked for a copy this
    /// device had backed up (spec §4.2 rule 11, `removed_elsewhere`).
    RemovedElsewhere,
    /// The upload failed or was cancelled; it is tried again, at most
    /// three times.
    UploadFailed,
}

impl BackupCopyState {
    /// The copy was removed on the server.
    pub fn removed(self) -> bool {
        matches!(self, Self::Trashed | Self::Deleted | Self::RemovedElsewhere)
    }
}

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
fn asset_changed(record: &BackupManifestRecord, asset: &Asset) -> bool {
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
        Ok(*self.pass.lock().map_err(|_| BackupManifestStoreError::Unavailable)?)
    }

    fn save_pass_state(&self, state: &BackupPassState) -> Result<(), BackupManifestStoreError> {
        *self.pass.lock().map_err(|_| BackupManifestStoreError::Unavailable)? = *state;
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
        Ok(*self.pass.lock().map_err(|_| BackupError::State)?)
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
        let mut state = *pass;
        change(&mut state);
        self.persistence.save_pass_state(&state)?;
        *pass = state;
        Ok(state)
    }

    /// Forget every `Queued` record. Run once a stopped backup's uploads are
    /// cancelled, so none of them can be live; a pass after "Back up again"
    /// asks the server about them afresh.
    fn forget_queued(&self) -> Result<(), BackupError> {
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
    fn forget_all(&self) -> Result<(), BackupError> {
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
    fn may_back_up(&self, asset: &Asset, check_active: bool) -> Result<bool, BackupError> {
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
    fn mark_removed_elsewhere(&self, asset: &Asset) -> Result<(), BackupError> {
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

    fn reconcile_local_identifiers(&self, present: &BTreeSet<String>, complete: bool) -> Result<(), BackupError> {
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

    fn mark_retryable(&self, local_identifier: &str, file_id: &str) -> Result<(), BackupError> {
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
    fn update_copy_state(&self, file_id: &str, state: BackupCopyState) -> Result<(), BackupError> {
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupAssetChange {
    pub file_id: String,
    pub state: BackupCopyState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupBatch {
    pub kind: AssetKind,
    pub queued: usize,
    pub already_backed_up: usize,
    pub deferred_for_network: bool,
    pub snapshot_complete: bool,
    /// The backup is off and queued nothing: show core's
    /// `backup_stop_words(reason, …)` and offer "Back up again"
    /// ([`BackupService::back_up_again`]).
    pub stopped: Option<BackupStopReason>,
    /// The notices could not be read, so the pass queued nothing: show core's
    /// `MSG_STOP_CHECK_FAILED`; the next pass checks again.
    pub check_failed: bool,
}

impl BackupBatch {
    fn empty(kind: AssetKind) -> Self {
        Self {
            kind,
            queued: 0,
            already_backed_up: 0,
            deferred_for_network: false,
            snapshot_complete: false,
            stopped: None,
            check_failed: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackupEvent {
    BatchFinished(BackupBatch),
    ManifestChanged,
    SignedOut,
}

#[derive(Debug, thiserror::Error)]
pub enum BackupError {
    #[error("the backup state is unavailable")]
    State,
    #[error(transparent)]
    ManifestStore(#[from] BackupManifestStoreError),
    #[error("the backup folder is not a device folder inside the Backups folder")]
    NotInBackups,
    #[error("the device id is missing or invalid")]
    InvalidDeviceId,
    #[error("another backup service is running on this upload service")]
    AlreadyRunning,
    #[error("the Backups folder could not be checked")]
    Client(#[from] crate::ClientError),
    #[error("the asset source failed")]
    AssetSource(#[from] AssetSourceError),
    #[error("the asset snapshot exceeded the batch limit")]
    TooManyAssets,
    #[error("the server duplicate check failed; the whole batch was deferred")]
    DeduplicationDeferred,
    #[error("the server duplicate check did not classify every asset")]
    IncompleteDeduplicationAnswer,
    #[error("an upload could not be queued")]
    Upload(#[from] UploadServiceError),
    #[error("the backup server answer was invalid")]
    InvalidAnswer,
}

/// The native backup.
///
/// **One service per manifest store**, across processes too. The manifest
/// and the pass state are read from the store once, when the service is made,
/// and every write puts back the service's whole copy, so a second service on
/// the same store would write over the first one's stop, "Back up again" or
/// forgotten records. Within a process this is enforced per
/// [`UploadService`]: a second service on it is refused
/// ([`BackupError::AlreadyRunning`]) until the first is dropped. An app
/// extension or a second process must never open the same store while the
/// app's service lives.
///
/// **Re-entrancy.** The store's callbacks ([`BackupManifestStore`]) run while
/// the service holds its manifest or pass-state lock, and the asset source's
/// ([`AssetSource`]) while it holds the pass lock. A callback must not call
/// back into this service (`stopped`, `manifest().copy_state`,
/// `next_batch`, ...), and must not wait on a thread that is inside
/// [`Self::next_batch`]: either deadlocks.
pub struct BackupService {
    client: Arc<Client>,
    uploads: Arc<UploadService>,
    source: Arc<dyn AssetSource>,
    configuration: Arc<Mutex<BackupConfiguration>>,
    /// The folder whose place in the Backups tree has been checked, with its
    /// device and category folders.
    checked_folder: Mutex<Option<CheckedFolder>>,
    manifest: BackupManifest,
    pages: Mutex<BTreeMap<AssetKind, BackupPageState>>,
    events: broadcast::Sender<BackupEvent>,
    /// One pass at a time, whatever the kind or the calling thread: a pass
    /// that read the gate's state never runs alongside one that stops it.
    pass_lock: tokio::sync::Mutex<()>,
    /// Held while this service lives: the upload service refuses a second.
    _lease: Arc<()>,
}

#[derive(Default)]
struct BackupPageState {
    cursor: Option<String>,
    seen_cursors: BTreeSet<String>,
    seen_assets: BTreeSet<String>,
}

impl BackupService {
    pub fn new(
        client: Arc<Client>,
        uploads: Arc<UploadService>,
        source: Arc<dyn AssetSource>,
        configuration: BackupConfiguration,
    ) -> Result<Self, BackupError> {
        Self::start(client, uploads, source, configuration, BackupManifest::default())
    }

    pub fn with_manifest_store(
        client: Arc<Client>,
        uploads: Arc<UploadService>,
        source: Arc<dyn AssetSource>,
        configuration: BackupConfiguration,
        manifest_store: Arc<dyn BackupManifestStore>,
    ) -> Result<Self, BackupError> {
        let manifest = BackupManifest::open(manifest_store)?;
        Self::start(client, uploads, source, configuration, manifest)
    }

    /// Make the service. Create it when the upload service is made, before
    /// any upload resumes: a backup stopped before a crash (its stop saved,
    /// its uploads not yet cancelled) cancels them here, before they can
    /// publish.
    fn start(
        client: Arc<Client>,
        uploads: Arc<UploadService>,
        source: Arc<dyn AssetSource>,
        configuration: BackupConfiguration,
        manifest: BackupManifest,
    ) -> Result<Self, BackupError> {
        let lease = uploads.lease_backup()?.ok_or(BackupError::AlreadyRunning)?;
        let (events, _) = broadcast::channel(64);
        let service = Self {
            client,
            uploads,
            source,
            configuration: Arc::new(Mutex::new(configuration)),
            checked_folder: Mutex::new(None),
            manifest,
            pages: Mutex::new(BTreeMap::new()),
            events,
            pass_lock: tokio::sync::Mutex::new(()),
            _lease: lease,
        };
        service.install_completion_handler()?;
        if service.manifest.pass_state()?.stopped.is_some() {
            service.finish_stop(crate::uploads::transfer_now_ms()?)?;
        }
        Ok(service)
    }

    fn install_completion_handler(&self) -> Result<(), BackupError> {
        self.uploads.set_completion_handler(Arc::new(BackupUploadCompletion {
            client: self.client.clone(),
            manifest: self.manifest.clone(),
            configuration: self.configuration.clone(),
            events: self.events.clone(),
        }))?;
        Ok(())
    }

    fn device_id(&self) -> Result<String, BackupError> {
        Ok(self
            .configuration
            .lock()
            .map_err(|_| BackupError::State)?
            .device_id
            .clone())
    }

    pub fn configure(&self, configuration: BackupConfiguration) -> Result<(), BackupError> {
        *self.configuration.lock().map_err(|_| BackupError::State)? = configuration;
        *self.checked_folder.lock().map_err(|_| BackupError::State)? = None;
        Ok(())
    }

    /// A backup is written only into this device's part of the Backups tree:
    /// a device folder or deeper below the row whose `system_role` is
    /// `backups_root`. Anything else (outside the tree, or the root itself)
    /// queues nothing. Checked once per configured folder; the device and
    /// category folders found on the way are the ones each pass's gate reads.
    ///
    /// A folder the server no longer has (404, or 403 once it is not this
    /// account's) is gone for good: the gate reads it as a gone device folder,
    /// so the pass stops and says why instead of failing every time. Its
    /// device folder is not known then (nothing is cached across a restart),
    /// so a `backup_deleted` notice that names the device folder of a gone
    /// category folder is not matched, and the stop says `Unknown`'s words.
    async fn check_backup_folder(&self, folder: &BackupFolder) -> Result<CheckedFolder, BackupError> {
        if let Some(checked) = self
            .checked_folder
            .lock()
            .map_err(|_| BackupError::State)?
            .as_ref()
            .filter(|checked| checked.id == folder.id)
        {
            return Ok(checked.clone());
        }
        let row = match self.client.get_file(&folder.id).await {
            Ok(row) => row,
            Err(crate::ClientError::Api(beebeeb_api::ApiError::Server(server)))
                if matches!(server.status, 403 | 404) =>
            {
                return Ok(CheckedFolder::gone(&folder.id));
            }
            Err(error) => return Err(error.into()),
        };
        let chain = match self.client.backup_chain_of(&row).await {
            Ok(chain) => chain,
            Err(crate::backup_guard::GuardError::Client(error)) => return Err(error.into()),
            Err(_) => return Err(BackupError::NotInBackups),
        };
        // `chain` runs from the folder up to the root: the device folder is
        // the root's child, a category folder the device folder's.
        let Some(chain) = chain.filter(|chain| chain.len() >= 2) else {
            return Err(BackupError::NotInBackups);
        };
        let checked = CheckedFolder {
            id: folder.id.clone(),
            device_folder_id: chain[chain.len() - 2].id.clone(),
            category_folder_id: (chain.len() >= 3).then(|| chain[chain.len() - 3].id.clone()),
            gone: false,
        };
        *self.checked_folder.lock().map_err(|_| BackupError::State)? = Some(checked.clone());
        Ok(checked)
    }

    pub fn manifest(&self) -> BackupManifest {
        self.manifest.clone()
    }

    pub fn observe(&self) -> broadcast::Receiver<BackupEvent> {
        self.events.subscribe()
    }

    pub fn assets_changed(&self, changes: &[BackupAssetChange]) -> Result<(), BackupError> {
        for change in changes {
            self.manifest.update_copy_state(&change.file_id, change.state)?;
        }
        let _ = self.events.send(BackupEvent::ManifestChanged);
        Ok(())
    }

    /// Why the backup is off, or `None` while it is on.
    pub fn stopped(&self) -> Result<Option<BackupStopReason>, BackupError> {
        Ok(self.manifest.pass_state()?.stopped.map(|stop| stop.reason))
    }

    /// "Back up again", the person's choice after a stop (backup spec
    /// Amendment 12): the backup starts fresh. The notices it stopped on no
    /// longer count (`last_pass_at` moves past them, on the server's clock),
    /// and every record is forgotten, so the next pass asks the server about
    /// every asset again; a copy still there counts as backed up. Nothing
    /// changes while the backup is on.
    ///
    /// After a stop because the backup's folder was deleted (`Unknown` or
    /// `BackupDeleted`), [`Self::configure`] a live folder first: find this
    /// device's folder again (Amendment 12, `find_device_folder`; one restored
    /// from Trash is found again) or create a new one, then call this. Called
    /// with the deleted folder still configured, the next pass stops again.
    pub fn back_up_again(&self) -> Result<(), BackupError> {
        if self.manifest.pass_state()?.stopped.is_none() {
            return Ok(());
        }
        // Records first: cut off after this, the backup is still off and the
        // person chooses again.
        self.manifest.forget_all()?;
        self.manifest.update_pass_state(|state| {
            if let Some(stop) = state.stopped.take() {
                state.last_pass_at_ms = Some(
                    state
                        .last_pass_at_ms
                        .map_or(stop.through_ms, |last| last.max(stop.through_ms)),
                );
            }
        })?;
        *self.checked_folder.lock().map_err(|_| BackupError::State)? = None;
        self.pages.lock().map_err(|_| BackupError::State)?.clear();
        let _ = self.events.send(BackupEvent::ManifestChanged);
        Ok(())
    }

    /// Turn the backup off (a stopped backup never fills the account up
    /// again). The stop is recorded first, so a pass cut off anywhere after it
    /// is still stopped, and the next pass finishes the stop
    /// ([`Self::finish_stop`]). A backup already off keeps its first reason,
    /// which is the stop returned.
    fn stop(&self, stop: BackupStop, now_ms: i64) -> Result<BackupStop, BackupError> {
        let state = self.manifest.update_pass_state(|state| {
            state.stopped.get_or_insert(stop);
        })?;
        let _ = self.events.send(BackupEvent::ManifestChanged);
        self.finish_stop(now_ms)?;
        Ok(state.stopped.unwrap_or(stop))
    }

    /// Cancel every backup upload that is not done, then forget every
    /// `Queued` record: none of them has a live upload any more. Run by every
    /// pass while the backup is off, so a stop cut off part-way (or a cancel
    /// that failed for one upload) is finished by the next pass.
    fn finish_stop(&self, now_ms: i64) -> Result<(), BackupError> {
        let cancelled = self.uploads.cancel_backup_uploads(now_ms);
        self.manifest.forget_queued()?;
        cancelled?;
        Ok(())
    }

    fn finish_batch(&self, batch: BackupBatch) -> Result<BackupBatch, BackupError> {
        let _ = self.events.send(BackupEvent::BatchFinished(batch.clone()));
        Ok(batch)
    }

    /// The pass gate (backup spec Amendments 12 and 12c): whether this pass
    /// may queue anything. See [`gate`].
    async fn pass_gate(
        &self,
        kind: AssetKind,
        configuration: &BackupConfiguration,
        folder: &CheckedFolder,
        now_ms: i64,
    ) -> Result<PassDecision, BackupError> {
        let state = self.manifest.pass_state()?;
        if let Some(stop) = state.stopped {
            return Ok(PassDecision::Stopped(stop));
        }
        let baseline = gate::baseline(&state, configuration);
        let listing = self.client.backup_stop_listing(folder, kind).await;
        let read = match listing {
            Some(_) => self.client.backup_notices_since(baseline).await,
            None => None,
        };
        let decision = gate::decide(read.as_ref(), baseline, listing.as_ref());
        match (decision, read.as_ref()) {
            (PassDecision::Stopped(stop), _) => return Ok(PassDecision::Stopped(self.stop(stop, now_ms)?)),
            (PassDecision::Run, Some(read)) => {
                // A gone folder is never Run (its device folder is not live);
                // should the rule ever say so, nothing is queued into it.
                if folder.gone {
                    return Err(BackupError::NotInBackups);
                }
                let next = gate::next_last_pass_at(read, baseline);
                // Written on the state as it is now: a stop written meanwhile
                // stays, and `last_pass_at` never moves back.
                let now = self.manifest.update_pass_state(|state| {
                    state.last_pass_at_ms = Some(state.last_pass_at_ms.map_or(next, |last| last.max(next)));
                })?;
                if let Some(stop) = now.stopped {
                    self.finish_stop(now_ms)?;
                    return Ok(PassDecision::Stopped(stop));
                }
            }
            _ => {}
        }
        Ok(decision)
    }

    pub async fn next_batch(
        &self,
        kind: AssetKind,
        network: NetworkKind,
        now_ms: i64,
    ) -> Result<BackupBatch, BackupError> {
        let _pass = self.pass_lock.lock().await;
        self.reconcile_upload_outcomes(now_ms).await?;
        // A stopped backup queues nothing and keeps nothing queued, whatever
        // the network: only "Back up again" turns it on.
        if let Some(stop) = self.manifest.pass_state()?.stopped {
            self.finish_stop(now_ms)?;
            return self.finish_batch(BackupBatch {
                stopped: Some(stop.reason),
                ..BackupBatch::empty(kind)
            });
        }
        let configuration = self.configuration.lock().map_err(|_| BackupError::State)?.clone();
        let policy = BackupPolicy {
            transfer: TransferRule {
                wifi_only: configuration.wifi_only,
            },
        };
        if !policy.transfer.allows(network) {
            return self.finish_batch(BackupBatch {
                deferred_for_network: true,
                ..BackupBatch::empty(kind)
            });
        }

        // The gate runs even with the upload queue full, so a stop cancels the
        // uploads in flight.
        let folder = self.check_backup_folder(&configuration.folder).await?;
        match self.pass_gate(kind, &configuration, &folder, now_ms).await? {
            PassDecision::Run => {}
            PassDecision::Stopped(stop) => {
                return self.finish_batch(BackupBatch {
                    stopped: Some(stop.reason),
                    ..BackupBatch::empty(kind)
                });
            }
            PassDecision::CheckFailed => {
                return self.finish_batch(BackupBatch {
                    check_failed: true,
                    ..BackupBatch::empty(kind)
                });
            }
        }
        let available = MAX_QUEUED_BACKUP_UPLOADS.saturating_sub(self.uploads.active_backup_count()?);
        if available == 0 {
            return self.finish_batch(BackupBatch::empty(kind));
        }
        let cursor = self
            .pages
            .lock()
            .map_err(|_| BackupError::State)?
            .entry(kind)
            .or_default()
            .cursor
            .clone();
        let limit = available.min(MAX_ASSETS_PER_PAGE);
        let snapshot = self.source.snapshot(kind, cursor.as_deref(), limit)?;
        if snapshot.assets.len() > limit {
            return Err(BackupError::TooManyAssets);
        }
        validate_assets(&snapshot.assets)?;

        let candidates: BTreeSet<String> = if kind == AssetKind::Photo {
            self.photo_candidates(&snapshot).await?
        } else {
            let mut candidates = BTreeSet::new();
            for asset in &snapshot.assets {
                if self.retry_allowed(&asset.local_identifier) && self.manifest.may_back_up(asset, false)? {
                    candidates.insert(asset.local_identifier.clone());
                }
            }
            candidates
        };
        let mut queued = 0usize;
        for asset in &snapshot.assets {
            if !candidates.contains(&asset.local_identifier) {
                continue;
            }
            let export_path = self.source.export(kind, asset)?;
            if !export_path.is_file() {
                return Err(BackupError::InvalidAnswer);
            }
            let mut request = UploadRequest::new(
                export_path,
                &asset.name,
                asset.mime_type.clone(),
                Some(configuration.folder.id.clone()),
            )
            .for_backup(&asset.local_identifier);
            request.wifi_only = configuration.wifi_only;
            let upload_id = self.uploads.enqueue(request, now_ms)?;
            let summary = self
                .uploads
                .list()?
                .into_iter()
                .find(|item| item.id == upload_id)
                .ok_or(BackupError::State)?;
            self.manifest
                .remember_asset(asset, &summary.file_id, BackupCopyState::Queued)?;
            queued = queued.checked_add(1).ok_or(BackupError::TooManyAssets)?;
        }
        let snapshot_complete = snapshot.complete && snapshot.next_cursor.is_none();
        {
            let mut pages = self.pages.lock().map_err(|_| BackupError::State)?;
            let page = pages.entry(kind).or_default();
            for asset in &snapshot.assets {
                if !page.seen_assets.insert(asset.local_identifier.clone()) {
                    return Err(BackupError::InvalidAnswer);
                }
            }
            match snapshot.next_cursor.as_deref() {
                Some(next) if next.is_empty() || !page.seen_cursors.insert(next.to_owned()) => {
                    return Err(BackupError::InvalidAnswer);
                }
                Some(next) => page.cursor = Some(next.to_owned()),
                None => {
                    self.manifest
                        .reconcile_local_identifiers(&page.seen_assets, snapshot.complete)?;
                    pages.remove(&kind);
                }
            }
        }
        self.finish_batch(BackupBatch {
            queued,
            already_backed_up: snapshot.assets.len().saturating_sub(queued),
            snapshot_complete,
            ..BackupBatch::empty(kind)
        })
    }

    /// The photos to upload: those the server says need a backup, never one
    /// queued or out of retries. A removed copy is not even asked about until
    /// its photo changes on the device (spec §4.2 rule 11). A copy this device
    /// backed up (`Active`) that the check asks for again is never uploaded
    /// from that answer: its own file decides
    /// ([`Self::look_up_backed_up_copy`]; core Never break: a removed file
    /// never comes back unchanged). Every call carries this device's id.
    async fn photo_candidates(&self, snapshot: &AssetSnapshot) -> Result<BTreeSet<String>, BackupError> {
        let assets: BTreeMap<&str, &Asset> = snapshot
            .assets
            .iter()
            .map(|asset| (asset.local_identifier.as_str(), asset))
            .collect();
        let mut identifiers = Vec::new();
        let mut backed_up = BTreeSet::new();
        for asset in &snapshot.assets {
            if self.retry_allowed(&asset.local_identifier) && self.manifest.may_back_up(asset, true)? {
                if self.manifest.copy_state(&asset.local_identifier) == Some(BackupCopyState::Active) {
                    backed_up.insert(asset.local_identifier.clone());
                }
                identifiers.push(asset.local_identifier.clone());
            }
        }
        let device_id = self.device_id()?;
        let mut candidates = BTreeSet::new();
        let mut lookups = 0usize;
        for page in identifiers.chunks(MAX_ASSETS_PER_PAGE) {
            let page = page.to_vec();
            let answer: beebeeb_api::routes::photo_backup::CheckResult = self
                .client
                .execute(
                    &beebeeb_api::routes::photo_backup::check(&device_id),
                    &beebeeb_api::routes::photo_backup::Check {
                        identifiers: page.clone(),
                    },
                )
                .await
                .map_err(|_| BackupError::DeduplicationDeferred)?;

            let needs: BTreeSet<String> = answer.needs_backup.into_iter().collect();
            let already: BTreeSet<String> = answer.already_backed_up.into_iter().collect();
            let mapped: BTreeMap<String, String> = answer
                .backed_up
                .into_iter()
                .map(|entry| (entry.local_identifier, entry.file_id))
                .collect();
            if page.iter().any(|identifier| {
                !needs.contains(identifier) && !already.contains(identifier) && !mapped.contains_key(identifier)
            }) {
                return Err(BackupError::IncompleteDeduplicationAnswer);
            }
            for (identifier, file_id) in mapped {
                if page.contains(&identifier)
                    && let Some(asset) = assets.get(identifier.as_str())
                {
                    self.manifest.remember_asset(asset, &file_id, BackupCopyState::Active)?;
                }
            }
            for identifier in page.into_iter().filter(|identifier| needs.contains(identifier)) {
                match assets.get(identifier.as_str()) {
                    // Backed up by this device: never uploaded again from the
                    // check's answer alone. Its own copy decides.
                    Some(asset) if backed_up.contains(&identifier) => {
                        if lookups < MAX_COPY_LOOKUPS_PER_PASS {
                            lookups += 1;
                            self.look_up_backed_up_copy(asset, &device_id).await?;
                        }
                    }
                    _ => {
                        candidates.insert(identifier);
                    }
                }
            }
        }
        Ok(candidates)
    }

    /// The server's check no longer has a row for a copy this device backed
    /// up (`Active`). The row alone proves nothing: it is keyed by this
    /// device's id and can go while the file stays (a device id that changed,
    /// `clear-association`). Spec rule 11's signal is the record's own copy
    /// (lead ruling, decision 2394):
    ///
    /// - live: still backed up. It stays `Active` and `mark` is sent again to
    ///   repair the row; nothing is uploaded.
    /// - in the Trash, or gone (404): removed elsewhere, `RemovedElsewhere`.
    /// - anything else (another error, an answer about another file): nothing
    ///   changes and nothing is uploaded for it this pass.
    async fn look_up_backed_up_copy(&self, asset: &Asset, device_id: &str) -> Result<(), BackupError> {
        let Some(file_id) = self.manifest.file_id(&asset.local_identifier) else {
            return Ok(());
        };
        let removed = match self.client.get_file(&file_id).await {
            Ok(row) if !row.id.eq_ignore_ascii_case(&file_id) => return Ok(()),
            Ok(row) => row.is_trashed,
            Err(crate::ClientError::Api(beebeeb_api::ApiError::Server(server))) if server.status == 404 => true,
            Err(_) => return Ok(()),
        };
        if removed {
            self.manifest.mark_removed_elsewhere(asset)?;
            let _ = self.events.send(BackupEvent::ManifestChanged);
        } else {
            // A failed repair changes nothing: the record stays `Active`, and
            // the next pass that meets it looks again.
            let _ = mark_upload_completed(
                &self.client,
                &self.manifest,
                &self.events,
                device_id,
                &asset.local_identifier,
                &file_id,
            )
            .await;
        }
        Ok(())
    }

    fn retry_allowed(&self, local_identifier: &str) -> bool {
        self.manifest.retry_count(local_identifier).unwrap_or(0) < MAX_BACKUP_FAILURES
    }

    async fn reconcile_upload_outcomes(&self, now_ms: i64) -> Result<(), BackupError> {
        for outcome in self.uploads.pending_backup_outcomes()? {
            match outcome.kind {
                BackupUploadOutcomeKind::Completed => {
                    self.upload_completed(&outcome.local_identifier, &outcome.file_id)
                        .await?;
                }
                BackupUploadOutcomeKind::Failed | BackupUploadOutcomeKind::Cancelled => {
                    self.manifest
                        .mark_retryable(&outcome.local_identifier, &outcome.file_id)?;
                    let _ = self.events.send(BackupEvent::ManifestChanged);
                }
            }
            self.uploads.mark_backup_outcome_applied(outcome.upload_id, now_ms)?;
        }
        Ok(())
    }

    pub async fn upload_completed(&self, local_identifier: &str, file_id: &str) -> Result<(), BackupError> {
        let device_id = self.device_id()?;
        mark_upload_completed(
            &self.client,
            &self.manifest,
            &self.events,
            &device_id,
            local_identifier,
            file_id,
        )
        .await
    }

    pub fn sign_out(&self) -> Result<(), BackupError> {
        self.manifest.clear()?;
        let _ = self.events.send(BackupEvent::SignedOut);
        Ok(())
    }
}

struct BackupUploadCompletion {
    client: Arc<Client>,
    manifest: BackupManifest,
    configuration: Arc<Mutex<BackupConfiguration>>,
    events: broadcast::Sender<BackupEvent>,
}

impl UploadCompletionHandler for BackupUploadCompletion {
    fn completed<'a>(
        &'a self,
        local_identifier: &'a str,
        file_id: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), ()>> + Send + 'a>> {
        Box::pin(async move {
            let device_id = self.configuration.lock().map_err(|_| ())?.device_id.clone();
            mark_upload_completed(
                &self.client,
                &self.manifest,
                &self.events,
                &device_id,
                local_identifier,
                file_id,
            )
            .await
            .map_err(|_| ())
        })
    }
}

async fn mark_upload_completed(
    client: &Client,
    manifest: &BackupManifest,
    events: &broadcast::Sender<BackupEvent>,
    device_id: &str,
    local_identifier: &str,
    file_id: &str,
) -> Result<(), BackupError> {
    let generation = client.generation();
    let result: beebeeb_api::routes::photo_backup::MarkResult = client
        .execute(
            &beebeeb_api::routes::photo_backup::mark(device_id),
            &beebeeb_api::routes::photo_backup::Mark {
                local_identifier: local_identifier.to_owned(),
                file_id: file_id.to_owned(),
            },
        )
        .await
        .map_err(|_| BackupError::InvalidAnswer)?;
    // The server echoes the device id it keyed the row by: anything else
    // means the row landed in another device's map (or the shared `''` one).
    if result.local_identifier != local_identifier || result.file_id != file_id || result.device_id != device_id {
        return Err(BackupError::InvalidAnswer);
    }
    if generation != client.generation() {
        return Err(BackupError::InvalidAnswer);
    }
    manifest.remember(local_identifier, file_id, BackupCopyState::Active)?;
    let _ = events.send(BackupEvent::ManifestChanged);
    Ok(())
}

fn validate_assets(assets: &[Asset]) -> Result<(), BackupError> {
    let mut identifiers = BTreeSet::new();
    for asset in assets {
        if asset.local_identifier.is_empty()
            || asset.name.is_empty()
            || !identifiers.insert(asset.local_identifier.as_str())
        {
            return Err(BackupError::InvalidAnswer);
        }
    }
    Ok(())
}

pub use beebeeb_api::routes::photo_backup as api;
