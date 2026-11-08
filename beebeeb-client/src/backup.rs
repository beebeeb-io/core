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
    pub fn new(folder: BackupFolder, wifi_only: bool) -> Result<Self, BackupError> {
        if folder.id.is_empty() {
            return Err(BackupError::NotInBackups);
        }
        Ok(Self {
            folder,
            wifi_only,
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

/// Where an asset's backup copy stands. Only [`Self::UploadFailed`] and an
/// asset with no record are uploaded (again); a copy the person trashed or
/// deleted is never uploaded again by the pass (core Never break: a stopped
/// backup never fills the account up again by itself), until they choose
/// "Back up again" after a stop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackupCopyState {
    Active,
    Queued,
    /// In the Trash on the server.
    Trashed,
    /// Deleted on the server.
    Deleted,
    /// The upload failed or was cancelled; it is tried again, at most
    /// three times.
    UploadFailed,
}

impl BackupCopyState {
    /// The person removed this copy on the server.
    pub fn removed(self) -> bool {
        matches!(self, Self::Trashed | Self::Deleted)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupManifestRecord {
    pub local_identifier: String,
    pub file_id: String,
    pub state: BackupCopyState,
    pub local_present: bool,
    pub retry_count: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum BackupManifestStoreError {
    #[error("the backup manifest store is unavailable")]
    Unavailable,
}

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

    /// Persist first, then remember: a state the platform could not store is
    /// never acted on.
    fn set_pass_state(&self, state: BackupPassState) -> Result<(), BackupError> {
        let mut pass = self.pass.lock().map_err(|_| BackupError::State)?;
        self.persistence.save_pass_state(&state)?;
        *pass = state;
        Ok(())
    }

    /// Forget the records of `local_identifiers` that are still `Queued`
    /// (their uploads were cancelled by a stop), so a pass after "Back up
    /// again" asks the server about them afresh.
    fn forget_queued(&self, local_identifiers: &[String]) -> Result<(), BackupError> {
        let mut entries = self.entries.lock().map_err(|_| BackupError::State)?;
        for identifier in local_identifiers {
            if entries
                .get(identifier)
                .is_some_and(|entry| entry.state == BackupCopyState::Queued)
            {
                entries.remove(identifier);
            }
        }
        self.persist(&entries)
    }

    /// "Back up again": forget every copy that is not `Active` or `Queued`
    /// (trashed, deleted, failed), so the backup starts fresh.
    fn forget_removed_and_failed(&self) -> Result<(), BackupError> {
        let mut entries = self.entries.lock().map_err(|_| BackupError::State)?;
        entries.retain(|_, entry| matches!(entry.state, BackupCopyState::Active | BackupCopyState::Queued));
        self.persist(&entries)
    }

    pub fn remember(&self, local_identifier: &str, file_id: &str, state: BackupCopyState) -> Result<(), BackupError> {
        let mut entries = self.entries.lock().map_err(|_| BackupError::State)?;
        let retry_count = if state == BackupCopyState::Active {
            0
        } else {
            entries.get(local_identifier).map_or(0, |entry| entry.retry_count)
        };
        entries.insert(
            local_identifier.to_owned(),
            BackupManifestRecord {
                local_identifier: local_identifier.to_owned(),
                file_id: file_id.to_owned(),
                state,
                local_present: true,
                retry_count,
            },
        );
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
            });
        entry.file_id = file_id.to_owned();
        entry.state = BackupCopyState::UploadFailed;
        entry.retry_count = entry.retry_count.saturating_add(1);
        self.persist(&entries)
    }

    fn update_copy_state(&self, file_id: &str, state: BackupCopyState) -> Result<(), BackupError> {
        let mut entries = self.entries.lock().map_err(|_| BackupError::State)?;
        if let Some(entry) = entries.values_mut().find(|entry| entry.file_id == file_id) {
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

pub struct BackupService {
    client: Arc<Client>,
    uploads: Arc<UploadService>,
    source: Arc<dyn AssetSource>,
    configuration: Mutex<BackupConfiguration>,
    /// The folder whose place in the Backups tree has been checked, with its
    /// device and category folders.
    checked_folder: Mutex<Option<CheckedFolder>>,
    manifest: BackupManifest,
    pages: Mutex<BTreeMap<AssetKind, BackupPageState>>,
    events: broadcast::Sender<BackupEvent>,
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
        let (events, _) = broadcast::channel(64);
        let service = Self {
            client,
            uploads,
            source,
            configuration: Mutex::new(configuration),
            checked_folder: Mutex::new(None),
            manifest: BackupManifest::default(),
            pages: Mutex::new(BTreeMap::new()),
            events,
        };
        service.install_completion_handler()?;
        Ok(service)
    }

    pub fn with_manifest_store(
        client: Arc<Client>,
        uploads: Arc<UploadService>,
        source: Arc<dyn AssetSource>,
        configuration: BackupConfiguration,
        manifest_store: Arc<dyn BackupManifestStore>,
    ) -> Result<Self, BackupError> {
        let (events, _) = broadcast::channel(64);
        let service = Self {
            client,
            uploads,
            source,
            configuration: Mutex::new(configuration),
            checked_folder: Mutex::new(None),
            manifest: BackupManifest::open(manifest_store)?,
            pages: Mutex::new(BTreeMap::new()),
            events,
        };
        service.install_completion_handler()?;
        Ok(service)
    }

    fn install_completion_handler(&self) -> Result<(), BackupError> {
        self.uploads.set_completion_handler(Arc::new(BackupUploadCompletion {
            client: self.client.clone(),
            manifest: self.manifest.clone(),
            events: self.events.clone(),
        }))?;
        Ok(())
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
        let row = self.client.get_file(&folder.id).await?;
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
    /// and copies that were trashed, deleted or failed are forgotten, so the
    /// next pass asks the server about them again. Nothing changes while the
    /// backup is on.
    pub fn back_up_again(&self) -> Result<(), BackupError> {
        let mut state = self.manifest.pass_state()?;
        let Some(stop) = state.stopped.take() else {
            return Ok(());
        };
        state.last_pass_at_ms = Some(
            state
                .last_pass_at_ms
                .map_or(stop.through_ms, |last| last.max(stop.through_ms)),
        );
        self.manifest.forget_removed_and_failed()?;
        self.manifest.set_pass_state(state)?;
        self.pages.lock().map_err(|_| BackupError::State)?.clear();
        let _ = self.events.send(BackupEvent::ManifestChanged);
        Ok(())
    }

    /// Turn the backup off: cancel its uploads that are not done (a stopped
    /// backup never fills the account up again), then record why. Cancelling
    /// first means a crash in between only stops it again on the next pass.
    fn stop(&self, stop: BackupStop, now_ms: i64) -> Result<(), BackupError> {
        let cancelled = self.uploads.cancel_backup_uploads(now_ms)?;
        self.manifest.forget_queued(&cancelled)?;
        let mut state = self.manifest.pass_state()?;
        state.stopped = Some(stop);
        self.manifest.set_pass_state(state)?;
        let _ = self.events.send(BackupEvent::ManifestChanged);
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
        let mut state = self.manifest.pass_state()?;
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
            (PassDecision::Stopped(stop), _) => self.stop(stop, now_ms)?,
            (PassDecision::Run, Some(read)) => {
                state.last_pass_at_ms = Some(gate::next_last_pass_at(read, baseline));
                self.manifest.set_pass_state(state)?;
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
        self.reconcile_upload_outcomes(now_ms).await?;
        // A stopped backup queues nothing and keeps nothing queued, whatever
        // the network: only "Back up again" turns it on.
        if let Some(stop) = self.manifest.pass_state()?.stopped {
            let cancelled = self.uploads.cancel_backup_uploads(now_ms)?;
            self.manifest.forget_queued(&cancelled)?;
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

        let available = MAX_QUEUED_BACKUP_UPLOADS.saturating_sub(self.uploads.active_backup_count()?);
        if available == 0 {
            return self.finish_batch(BackupBatch::empty(kind));
        }
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
            snapshot
                .assets
                .iter()
                .filter(|asset| {
                    matches!(
                        self.manifest.copy_state(&asset.local_identifier),
                        None | Some(BackupCopyState::UploadFailed)
                    ) && self.retry_allowed(&asset.local_identifier)
                })
                .map(|asset| asset.local_identifier.clone())
                .collect()
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
                .remember(&asset.local_identifier, &summary.file_id, BackupCopyState::Queued)?;
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
    /// queued, out of retries, or whose copy the person trashed or deleted
    /// (core Never break: a stopped backup never fills the account up again;
    /// a removed copy comes back only after "Back up again").
    async fn photo_candidates(&self, snapshot: &AssetSnapshot) -> Result<BTreeSet<String>, BackupError> {
        let identifiers: Vec<String> = snapshot
            .assets
            .iter()
            .filter(|asset| {
                !matches!(
                    self.manifest.copy_state(&asset.local_identifier),
                    Some(BackupCopyState::Queued | BackupCopyState::Trashed | BackupCopyState::Deleted)
                ) && self.retry_allowed(&asset.local_identifier)
            })
            .map(|asset| asset.local_identifier.clone())
            .collect();
        let mut candidates = BTreeSet::new();
        for page in identifiers.chunks(MAX_ASSETS_PER_PAGE) {
            let page = page.to_vec();
            let answer: beebeeb_api::routes::photo_backup::CheckResult = self
                .client
                .execute(
                    &beebeeb_api::routes::photo_backup::check(),
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
                if page.contains(&identifier) {
                    self.manifest.remember(&identifier, &file_id, BackupCopyState::Active)?;
                }
            }
            candidates.extend(page.into_iter().filter(|identifier| needs.contains(identifier)));
        }
        Ok(candidates)
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
        mark_upload_completed(&self.client, &self.manifest, &self.events, local_identifier, file_id).await
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
    events: broadcast::Sender<BackupEvent>,
}

impl UploadCompletionHandler for BackupUploadCompletion {
    fn completed<'a>(
        &'a self,
        local_identifier: &'a str,
        file_id: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), ()>> + Send + 'a>> {
        Box::pin(async move {
            mark_upload_completed(&self.client, &self.manifest, &self.events, local_identifier, file_id)
                .await
                .map_err(|_| ())
        })
    }
}

async fn mark_upload_completed(
    client: &Client,
    manifest: &BackupManifest,
    events: &broadcast::Sender<BackupEvent>,
    local_identifier: &str,
    file_id: &str,
) -> Result<(), BackupError> {
    let generation = client.generation();
    let result: beebeeb_api::routes::photo_backup::MarkResult = client
        .execute(
            &beebeeb_api::routes::photo_backup::mark(),
            &beebeeb_api::routes::photo_backup::Mark {
                local_identifier: local_identifier.to_owned(),
                file_id: file_id.to_owned(),
            },
        )
        .await
        .map_err(|_| BackupError::InvalidAnswer)?;
    if result.local_identifier != local_identifier || result.file_id != file_id {
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
