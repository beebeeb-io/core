//! Platform integration seams and wrappers around the real client engines.

use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

use beebeeb_client::{
    auth::AccountReplacement,
    backup::{
        Asset, AssetKind, AssetSnapshot, AssetSource, AssetSourceError, BackupAssetChange, BackupBatch,
        BackupConfiguration, BackupCopyState, BackupEvent, BackupFolder, BackupManifestRecord, BackupManifestStore,
        BackupManifestStoreError, BackupPassState, BackupService, BackupStop,
    },
    file_provider::{
        DomainNotifier, DomainNotifierError, FileProviderChanges, FileProviderItem, FileProviderOutcome,
        FileProviderService, ItemWorkState,
    },
    platform::{
        AccountDataPurgeError, AccountDataPurger, PlatformCancellationError, PlatformTransferCanceller,
        ServiceCoordinator, SignOutFailure,
    },
    sync::SyncEngine,
    uploads::{NetworkKind, transfer_now_ms},
};
use beebeeb_store::Store;
use beebeeb_types::limits::MemoryBudget;
use uuid::Uuid;

use crate::{
    DeviceServiceHandle, DownloadData, DownloadServiceHandle, FileData, FilePageHandle, NativeClientHandle,
    SearchServiceHandle, ServiceError, ServiceErrorKind, ThumbnailServiceHandle, UploadEnqueueData,
    UploadServiceHandle, map_client_error,
};

fn invalid() -> ServiceError {
    ServiceError::new(ServiceErrorKind::InvalidInput)
}

fn unavailable() -> ServiceError {
    ServiceError::new(ServiceErrorKind::Unavailable)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum AssetKindData {
    Photo,
    ContactSnapshot,
    CalendarSnapshot,
}

impl From<AssetKindData> for AssetKind {
    fn from(value: AssetKindData) -> Self {
        match value {
            AssetKindData::Photo => Self::Photo,
            AssetKindData::ContactSnapshot => Self::ContactSnapshot,
            AssetKindData::CalendarSnapshot => Self::CalendarSnapshot,
        }
    }
}

impl From<AssetKind> for AssetKindData {
    fn from(value: AssetKind) -> Self {
        match value {
            AssetKind::Photo => Self::Photo,
            AssetKind::ContactSnapshot => Self::ContactSnapshot,
            AssetKind::CalendarSnapshot => Self::CalendarSnapshot,
        }
    }
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct AssetData {
    pub local_identifier: String,
    pub name: String,
    pub mime_type: Option<String>,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct AssetSnapshotData {
    pub complete: bool,
    pub assets: Vec<AssetData>,
    pub next_cursor: Option<String>,
}

#[uniffi::export(callback_interface)]
pub trait AssetSourceCallback: Send + Sync {
    /// Return metadata only. Export is requested separately for selected rows.
    fn snapshot(&self, kind: AssetKindData, cursor: Option<String>, limit: u64) -> Option<AssetSnapshotData>;
    fn export(&self, kind: AssetKindData, local_identifier: String) -> Option<String>;
}

struct AssetSourceAdapter {
    callback: Box<dyn AssetSourceCallback>,
}

impl AssetSource for AssetSourceAdapter {
    fn snapshot(&self, kind: AssetKind, cursor: Option<&str>, limit: usize) -> Result<AssetSnapshot, AssetSourceError> {
        let value = self
            .callback
            .snapshot(kind.into(), cursor.map(str::to_owned), limit as u64)
            .ok_or(AssetSourceError::Unavailable)?;
        Ok(AssetSnapshot {
            complete: value.complete,
            assets: value
                .assets
                .into_iter()
                .map(|asset| Asset {
                    local_identifier: asset.local_identifier,
                    export_path: PathBuf::new(),
                    name: asset.name,
                    mime_type: asset.mime_type,
                })
                .collect(),
            next_cursor: value.next_cursor,
        })
    }

    fn export(&self, kind: AssetKind, asset: &Asset) -> Result<PathBuf, AssetSourceError> {
        self.callback
            .export(kind.into(), asset.local_identifier.clone())
            .map(PathBuf::from)
            .ok_or(AssetSourceError::Unavailable)
    }
}

/// `Trashed` and `Deleted`: the person removed the copy on the server, and
/// the backup never uploads it again by itself. `UploadFailed`: the upload
/// failed and is tried again (at most three times).
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum BackupCopyStateData {
    Active,
    Queued,
    Trashed,
    Deleted,
    UploadFailed,
}

impl From<BackupCopyStateData> for BackupCopyState {
    fn from(value: BackupCopyStateData) -> Self {
        match value {
            BackupCopyStateData::Active => Self::Active,
            BackupCopyStateData::Queued => Self::Queued,
            BackupCopyStateData::Trashed => Self::Trashed,
            BackupCopyStateData::Deleted => Self::Deleted,
            BackupCopyStateData::UploadFailed => Self::UploadFailed,
        }
    }
}

impl From<BackupCopyState> for BackupCopyStateData {
    fn from(value: BackupCopyState) -> Self {
        match value {
            BackupCopyState::Active => Self::Active,
            BackupCopyState::Queued => Self::Queued,
            BackupCopyState::Trashed => Self::Trashed,
            BackupCopyState::Deleted => Self::Deleted,
            BackupCopyState::UploadFailed => Self::UploadFailed,
        }
    }
}

/// The backup pass gate's state (backup spec Amendments 12 and 12c), stored
/// by the platform next to the manifest records and removed with them by
/// `clear`. Times are on the server's clock, in milliseconds. A fresh store
/// answers all `None`. `stopped_reason` is a core wire string
/// (`backup_stop_words` renders it); with it, `stopped_through_ms` is set.
#[derive(Debug, Clone, Default, PartialEq, Eq, uniffi::Record)]
pub struct BackupPassStateData {
    pub last_pass_at_ms: Option<i64>,
    pub stopped_reason: Option<String>,
    pub stopped_through_ms: Option<i64>,
}

impl From<BackupPassState> for BackupPassStateData {
    fn from(value: BackupPassState) -> Self {
        Self {
            last_pass_at_ms: value.last_pass_at_ms,
            stopped_reason: value.stopped.map(|stop| stop.reason.as_str().to_owned()),
            stopped_through_ms: value.stopped.map(|stop| stop.through_ms),
        }
    }
}

/// A stored state that does not read back whole (an unknown reason, or a
/// reason without its time) is refused, never read as "not stopped".
fn pass_state(value: BackupPassStateData) -> Option<BackupPassState> {
    let stopped = match (value.stopped_reason, value.stopped_through_ms) {
        (None, None) => None,
        (Some(reason), Some(through_ms)) => Some(BackupStop {
            reason: beebeeb_types::backup::BackupStopReason::parse(&reason)?,
            through_ms,
        }),
        _ => return None,
    };
    Some(BackupPassState {
        last_pass_at_ms: value.last_pass_at_ms,
        stopped,
    })
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct BackupManifestRecordData {
    pub local_identifier: String,
    pub file_id: String,
    pub state: BackupCopyStateData,
    pub local_present: bool,
    pub retry_count: u32,
}

/// `None` / `false` means the store failed. `clear` removes the records and
/// the pass state.
#[uniffi::export(callback_interface)]
pub trait BackupManifestStoreCallback: Send + Sync {
    fn load(&self) -> Option<Vec<BackupManifestRecordData>>;
    fn replace(&self, records: Vec<BackupManifestRecordData>) -> bool;
    fn load_pass_state(&self) -> Option<BackupPassStateData>;
    fn save_pass_state(&self, state: BackupPassStateData) -> bool;
    fn clear(&self) -> bool;
}

struct BackupManifestStoreAdapter {
    callback: Box<dyn BackupManifestStoreCallback>,
}

impl BackupManifestStore for BackupManifestStoreAdapter {
    fn load(&self) -> Result<Vec<BackupManifestRecord>, BackupManifestStoreError> {
        self.callback
            .load()
            .ok_or(BackupManifestStoreError::Unavailable)
            .map(|records| {
                records
                    .into_iter()
                    .map(|record| BackupManifestRecord {
                        local_identifier: record.local_identifier,
                        file_id: record.file_id,
                        state: record.state.into(),
                        local_present: record.local_present,
                        retry_count: record.retry_count,
                    })
                    .collect()
            })
    }

    fn replace(&self, records: &[BackupManifestRecord]) -> Result<(), BackupManifestStoreError> {
        let records = records
            .iter()
            .map(|record| BackupManifestRecordData {
                local_identifier: record.local_identifier.clone(),
                file_id: record.file_id.clone(),
                state: record.state.into(),
                local_present: record.local_present,
                retry_count: record.retry_count,
            })
            .collect();
        self.callback
            .replace(records)
            .then_some(())
            .ok_or(BackupManifestStoreError::Unavailable)
    }

    fn load_pass_state(&self) -> Result<BackupPassState, BackupManifestStoreError> {
        self.callback
            .load_pass_state()
            .and_then(pass_state)
            .ok_or(BackupManifestStoreError::Unavailable)
    }

    fn save_pass_state(&self, state: &BackupPassState) -> Result<(), BackupManifestStoreError> {
        self.callback
            .save_pass_state((*state).into())
            .then_some(())
            .ok_or(BackupManifestStoreError::Unavailable)
    }

    fn clear(&self) -> Result<(), BackupManifestStoreError> {
        self.callback
            .clear()
            .then_some(())
            .ok_or(BackupManifestStoreError::Unavailable)
    }
}

/// `folder_id` is this device's folder under the Backups root (a device or
/// category folder); the service checks that before it queues anything.
/// `setup_at_ms` (when backups were turned on on this device) and
/// `legacy_last_backup_ms` (an upgraded device's last backup under the old
/// engine) are on the server's clock, in milliseconds; they set the first
/// pass's baseline (core `backup_first_pass_baseline`). Unknown is `None`.
#[derive(Debug, Clone, uniffi::Record)]
pub struct BackupConfigurationData {
    pub folder_id: String,
    pub wifi_only: bool,
    pub setup_at_ms: Option<i64>,
    pub legacy_last_backup_ms: Option<i64>,
}

fn backup_configuration(value: BackupConfigurationData) -> Result<BackupConfiguration, ServiceError> {
    BackupConfiguration::new(BackupFolder { id: value.folder_id }, value.wifi_only)
        .map(|configuration| configuration.with_first_pass(value.setup_at_ms, value.legacy_last_backup_ms))
        .map_err(|_| invalid())
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct BackupAssetChangeData {
    pub file_id: String,
    pub state: BackupCopyStateData,
}

/// `stopped_reason`: the backup is off (a core wire string; show
/// `backup_stop_words` and offer "Back up again"). `check_failed`: the
/// notices could not be read, so nothing was queued (show
/// `backup_check_failed_words`; the next pass checks again).
#[derive(Debug, Clone, uniffi::Record)]
pub struct BackupBatchData {
    pub kind: AssetKindData,
    pub queued: u64,
    pub already_backed_up: u64,
    pub deferred_for_network: bool,
    pub snapshot_complete: bool,
    pub stopped_reason: Option<String>,
    pub check_failed: bool,
}

impl From<BackupBatch> for BackupBatchData {
    fn from(value: BackupBatch) -> Self {
        Self {
            kind: value.kind.into(),
            queued: value.queued as u64,
            already_backed_up: value.already_backed_up as u64,
            deferred_for_network: value.deferred_for_network,
            snapshot_complete: value.snapshot_complete,
            stopped_reason: value.stopped.map(|reason| reason.as_str().to_owned()),
            check_failed: value.check_failed,
        }
    }
}

fn network(value: &str) -> Result<NetworkKind, ServiceError> {
    match value {
        "offline" => Ok(NetworkKind::Offline),
        "cellular" => Ok(NetworkKind::Cellular),
        "wifi" => Ok(NetworkKind::WiFi),
        _ => Err(invalid()),
    }
}

#[derive(uniffi::Object)]
pub struct BackupServiceHandle {
    pub(crate) root: Arc<NativeClientHandle>,
    pub(crate) service: Arc<BackupService>,
}

#[derive(uniffi::Object)]
pub struct BackupEventStreamHandle {
    runtime: beebeeb_client::ClientRuntime,
    receiver: Mutex<tokio::sync::broadcast::Receiver<BackupEvent>>,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct BackupEventData {
    pub kind: String,
    pub batch: Option<BackupBatchData>,
}

#[uniffi::export]
impl BackupEventStreamHandle {
    pub fn next(&self, timeout_ms: u64) -> Result<Option<BackupEventData>, ServiceError> {
        let mut receiver = self.receiver.lock().map_err(|_| unavailable())?;
        self.runtime.block_on(async {
            match tokio::time::timeout(Duration::from_millis(timeout_ms), receiver.recv()).await {
                Ok(Ok(BackupEvent::BatchFinished(batch))) => Ok(Some(BackupEventData {
                    kind: "batch_finished".into(),
                    batch: Some(batch.into()),
                })),
                Ok(Ok(BackupEvent::ManifestChanged)) => Ok(Some(BackupEventData {
                    kind: "manifest_changed".into(),
                    batch: None,
                })),
                Ok(Ok(BackupEvent::SignedOut)) => Ok(Some(BackupEventData {
                    kind: "signed_out".into(),
                    batch: None,
                })),
                Ok(Err(tokio::sync::broadcast::error::RecvError::Closed)) | Err(_) => Ok(None),
                Ok(Err(tokio::sync::broadcast::error::RecvError::Lagged(_))) => Err(unavailable()),
            }
        })
    }
}

#[uniffi::export]
impl BackupServiceHandle {
    pub fn configure(&self, configuration: BackupConfigurationData) -> Result<(), ServiceError> {
        self.service
            .configure(backup_configuration(configuration)?)
            .map_err(map_client_error)
    }

    pub fn events(&self) -> Arc<BackupEventStreamHandle> {
        Arc::new(BackupEventStreamHandle {
            runtime: self.root.runtime.clone(),
            receiver: Mutex::new(self.service.observe()),
        })
    }

    pub fn assets_changed(&self, changes: Vec<BackupAssetChangeData>) -> Result<(), ServiceError> {
        let changes: Vec<_> = changes
            .into_iter()
            .map(|change| BackupAssetChange {
                file_id: change.file_id,
                state: change.state.into(),
            })
            .collect();
        self.service.assets_changed(&changes).map_err(map_client_error)
    }

    pub fn next_batch(
        &self,
        kind: AssetKindData,
        network_name: String,
        now_ms: i64,
    ) -> Result<BackupBatchData, ServiceError> {
        self.root
            .runtime
            .block_on(self.service.next_batch(kind.into(), network(&network_name)?, now_ms))
            .map(Into::into)
            .map_err(map_client_error)
    }

    /// Why the backup is off (a core wire string), or `None` while it is on.
    pub fn stopped_reason(&self) -> Result<Option<String>, ServiceError> {
        self.service
            .stopped()
            .map(|reason| reason.map(|reason| reason.as_str().to_owned()))
            .map_err(map_client_error)
    }

    /// "Back up again" after a stop: the backup starts fresh.
    pub fn back_up_again(&self) -> Result<(), ServiceError> {
        self.service.back_up_again().map_err(map_client_error)
    }
}

#[uniffi::export]
impl NativeClientHandle {
    pub fn backup(
        self: &Arc<Self>,
        uploads: Arc<UploadServiceHandle>,
        source: Box<dyn AssetSourceCallback>,
        manifest_store: Box<dyn BackupManifestStoreCallback>,
        configuration: BackupConfigurationData,
    ) -> Result<Arc<BackupServiceHandle>, ServiceError> {
        if !Arc::ptr_eq(self, &uploads.root) {
            return Err(invalid());
        }
        let service = BackupService::with_manifest_store(
            self.client.clone(),
            uploads.service.clone(),
            Arc::new(AssetSourceAdapter { callback: source }),
            backup_configuration(configuration)?,
            Arc::new(BackupManifestStoreAdapter {
                callback: manifest_store,
            }),
        )
        .map_err(map_client_error)?;
        Ok(Arc::new(BackupServiceHandle {
            root: self.clone(),
            service: Arc::new(service),
        }))
    }
}

#[uniffi::export(callback_interface)]
pub trait DomainNotifierCallback: Send + Sync {
    fn signal_working_set(&self) -> bool;
}

struct DomainNotifierAdapter {
    callback: Box<dyn DomainNotifierCallback>,
}

impl DomainNotifier for DomainNotifierAdapter {
    fn signal_working_set(&self) -> Result<(), DomainNotifierError> {
        self.callback
            .signal_working_set()
            .then_some(())
            .ok_or(DomainNotifierError::Unavailable)
    }
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct FileProviderItemData {
    pub id: String,
    pub parent_id: Option<String>,
    pub name: String,
    pub name_undecryptable: bool,
    pub mime_type: Option<String>,
    pub is_folder: bool,
    pub size_bytes: u64,
    pub version_number: i32,
}

impl From<FileProviderItem> for FileProviderItemData {
    fn from(value: FileProviderItem) -> Self {
        Self {
            id: value.id.to_string(),
            parent_id: value.parent_id.map(|id| id.to_string()),
            name: value.name,
            name_undecryptable: value.name_undecryptable,
            mime_type: value.mime_type,
            is_folder: value.is_folder,
            size_bytes: value.size_bytes,
            version_number: value.version_number,
        }
    }
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct FileProviderChangesData {
    pub changed: Vec<FileProviderItemData>,
    pub deleted: Vec<String>,
    pub anchor: i64,
    pub more_coming: bool,
}

impl From<FileProviderChanges> for FileProviderChangesData {
    fn from(value: FileProviderChanges) -> Self {
        Self {
            changed: value.changed.into_iter().map(Into::into).collect(),
            deleted: value.deleted.into_iter().map(|id| id.to_string()).collect(),
            anchor: value.anchor,
            more_coming: value.more_coming,
        }
    }
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct FileProviderOutcomeData {
    pub kind: String,
    pub path: Option<String>,
    pub upload_id: Option<i64>,
    pub file_id: Option<String>,
    pub frame_size: Option<u64>,
    pub context_limit: Option<u64>,
}

impl From<FileProviderOutcome> for FileProviderOutcomeData {
    fn from(value: FileProviderOutcome) -> Self {
        let mut output = Self {
            kind: String::new(),
            path: None,
            upload_id: None,
            file_id: None,
            frame_size: None,
            context_limit: None,
        };
        match value {
            FileProviderOutcome::Ready(path) => {
                output.kind = "ready".into();
                output.path = Some(path.to_string_lossy().into_owned());
            }
            FileProviderOutcome::Saved => output.kind = "saved".into(),
            FileProviderOutcome::Queued { upload_id, file_id } => {
                output.kind = "queued".into();
                output.upload_id = Some(upload_id);
                output.file_id = Some(file_id);
            }
            FileProviderOutcome::HandOff {
                frame_size,
                context_limit,
            } => {
                output.kind = "hand_off".into();
                output.frame_size = Some(frame_size);
                output.context_limit = Some(context_limit);
            }
        }
        output
    }
}

#[derive(uniffi::Object)]
pub struct FileProviderServiceHandle {
    root: Arc<NativeClientHandle>,
    service: Arc<FileProviderService>,
}

fn parse_uuid(value: &str) -> Result<Uuid, ServiceError> {
    Uuid::parse_str(value).map_err(|_| invalid())
}

#[uniffi::export]
impl FileProviderServiceHandle {
    pub fn set_system_items(&self, ids: Vec<String>) -> Result<(), ServiceError> {
        let ids = ids.iter().map(|id| parse_uuid(id)).collect::<Result<Vec<_>, _>>()?;
        self.service.set_system_items(ids).map_err(map_client_error)
    }

    pub fn item(&self, id: String) -> Result<Option<FileProviderItemData>, ServiceError> {
        self.service
            .item(parse_uuid(&id)?)
            .map(|item| item.map(Into::into))
            .map_err(map_client_error)
    }

    pub fn children(&self, parent_id: Option<String>) -> Result<Vec<FileProviderItemData>, ServiceError> {
        let parent_id = parent_id.as_deref().map(parse_uuid).transpose()?;
        self.service
            .children(parent_id)
            .map(|items| items.into_iter().map(Into::into).collect())
            .map_err(map_client_error)
    }

    pub fn changes_since(&self, anchor: i64, limit: u16) -> Result<FileProviderChangesData, ServiceError> {
        self.service
            .changes_since(anchor, usize::from(limit))
            .map(Into::into)
            .map_err(map_client_error)
    }

    pub fn fetch_contents(
        &self,
        downloads: &DownloadServiceHandle,
        file: DownloadData,
    ) -> Result<FileProviderOutcomeData, ServiceError> {
        if !Arc::ptr_eq(&self.root, &downloads.root) {
            return Err(invalid());
        }
        self.root
            .runtime
            .block_on(self.service.fetch_contents(
                downloads.service.as_ref(),
                &file.into(),
                transfer_now_ms().map_err(|_| unavailable())?,
            ))
            .map(Into::into)
            .map_err(map_client_error)
    }

    pub fn create_folder(&self, name: String, parent_id: Option<String>) -> Result<FileData, ServiceError> {
        let session = self.root.session()?;
        self.root
            .runtime
            .block_on(
                self.service
                    .create_folder(&self.root.client, &session, &name, parent_id),
            )
            .map(|record| FileData::from(&record))
            .map_err(map_client_error)
    }

    pub fn create_file(
        &self,
        uploads: &UploadServiceHandle,
        data: UploadEnqueueData,
    ) -> Result<FileProviderOutcomeData, ServiceError> {
        if !Arc::ptr_eq(&self.root, &uploads.root) {
            return Err(invalid());
        }
        let (request, now_ms) = uploads.configured_request(data)?;
        self.service
            .create_file(uploads.service.as_ref(), request, now_ms)
            .map(Into::into)
            .map_err(map_client_error)
    }

    pub fn modify(
        &self,
        id: String,
        new_name: Option<String>,
        change_parent: bool,
        new_parent: Option<String>,
    ) -> Result<FileData, ServiceError> {
        let session = self.root.session()?;
        self.root
            .runtime
            .block_on(self.service.modify(
                &self.root.client,
                &session,
                parse_uuid(&id)?,
                new_name.as_deref(),
                change_parent.then_some(new_parent),
            ))
            .map(|record| FileData::from(&record))
            .map_err(map_client_error)
    }

    pub fn delete(&self, id: String) -> Result<(), ServiceError> {
        self.root
            .runtime
            .block_on(self.service.delete(&self.root.client, parse_uuid(&id)?))
            .map_err(map_client_error)
    }

    pub fn delete_local(&self, id: String) -> Result<(), ServiceError> {
        self.root
            .runtime
            .block_on(self.service.delete_local(&self.root.client, parse_uuid(&id)?))
            .map_err(map_client_error)
    }

    pub fn work_state(&self, id: String) -> Result<Option<String>, ServiceError> {
        Ok(self.service.work_state(parse_uuid(&id)?).map(|state| {
            match state {
                ItemWorkState::Queued => "queued",
                ItemWorkState::Running => "running",
                ItemWorkState::Succeeded => "succeeded",
                ItemWorkState::Failed => "failed",
                ItemWorkState::HandedOff => "handed_off",
            }
            .into()
        }))
    }
}

#[uniffi::export]
impl NativeClientHandle {
    /// Opens a targeted store-backed sync engine. With `RuntimeProfile::Lightweight`
    /// this is suitable for a File Provider extension and never hydrates the tree.
    pub fn file_provider(
        self: &Arc<Self>,
        store_path: String,
        device_id: String,
        notifier: Box<dyn DomainNotifierCallback>,
        memory_class: String,
    ) -> Result<Arc<FileProviderServiceHandle>, ServiceError> {
        let store = Store::open(store_path).map_err(|_| ServiceError::new(ServiceErrorKind::Storage))?;
        let engine = SyncEngine::with_store_backed(device_id, store).map_err(map_client_error)?;
        let budget = MemoryBudget::for_class_code(&memory_class).ok_or_else(invalid)?;
        let service =
            FileProviderService::with_budget(engine, Arc::new(DomainNotifierAdapter { callback: notifier }), budget);
        Ok(Arc::new(FileProviderServiceHandle {
            root: self.clone(),
            service: Arc::new(service),
        }))
    }
}

#[uniffi::export(callback_interface)]
pub trait PlatformTransferCancellerCallback: Send + Sync {
    fn cancel(&self, tickets: Vec<String>) -> bool;
}

struct PlatformTransferCancellerAdapter<'a> {
    callback: &'a dyn PlatformTransferCancellerCallback,
}

impl PlatformTransferCanceller for PlatformTransferCancellerAdapter<'_> {
    fn cancel(&self, tickets: &[String]) -> Result<(), PlatformCancellationError> {
        self.callback
            .cancel(tickets.to_vec())
            .then_some(())
            .ok_or(PlatformCancellationError::Failed)
    }
}

#[uniffi::export(callback_interface)]
pub trait AccountDataPurgerCallback: Send + Sync {
    fn purge_account_data(&self) -> bool;
}

struct AccountDataPurgerAdapter<'a> {
    callback: &'a dyn AccountDataPurgerCallback,
}

impl AccountDataPurger for AccountDataPurgerAdapter<'_> {
    fn purge_account_data(&self) -> Result<(), AccountDataPurgeError> {
        self.callback
            .purge_account_data()
            .then_some(())
            .ok_or(AccountDataPurgeError::Failed)
    }
}

#[derive(uniffi::Object)]
pub struct ServiceCoordinatorHandle {
    root: Arc<NativeClientHandle>,
    coordinator: ServiceCoordinator,
}

#[derive(uniffi::Object)]
pub struct AccountReplacementHandle {
    root: Arc<NativeClientHandle>,
    state: Mutex<Option<AccountReplacement>>,
}

impl AccountReplacementHandle {
    pub(crate) fn take(&self, root: &Arc<NativeClientHandle>) -> Result<AccountReplacement, ServiceError> {
        if !Arc::ptr_eq(&self.root, root) {
            return Err(invalid());
        }
        self.state.lock().map_err(|_| unavailable())?.take().ok_or_else(invalid)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum SignOutFailureData {
    UploadQueue,
    PlatformCancellation,
    DownloadCache,
    ThumbnailCache,
    BackupManifest,
    AccountData,
    Session,
}

impl From<SignOutFailure> for SignOutFailureData {
    fn from(value: SignOutFailure) -> Self {
        match value {
            SignOutFailure::UploadQueue => Self::UploadQueue,
            SignOutFailure::PlatformCancellation => Self::PlatformCancellation,
            SignOutFailure::DownloadCache => Self::DownloadCache,
            SignOutFailure::ThumbnailCache => Self::ThumbnailCache,
            SignOutFailure::BackupManifest => Self::BackupManifest,
            SignOutFailure::AccountData => Self::AccountData,
            SignOutFailure::Session => Self::Session,
        }
    }
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct SignOutReportData {
    pub platform_cancel_tickets: Vec<String>,
    pub failures: Vec<SignOutFailureData>,
    pub complete: bool,
}

fn sign_out_report(value: beebeeb_client::platform::SignOutReport) -> SignOutReportData {
    let complete = value.is_complete();
    SignOutReportData {
        platform_cancel_tickets: value.platform_cancel_tickets,
        failures: value.failures.into_iter().map(Into::into).collect(),
        complete,
    }
}

#[uniffi::export]
impl ServiceCoordinatorHandle {
    pub fn start(&self, page: &FilePageHandle) {
        self.coordinator.start(page.page.files.clone());
    }
}

#[uniffi::export]
impl NativeClientHandle {
    pub fn service_coordinator(
        self: &Arc<Self>,
        uploads: Arc<UploadServiceHandle>,
        downloads: Arc<DownloadServiceHandle>,
        thumbnails: Arc<ThumbnailServiceHandle>,
        backup: Arc<BackupServiceHandle>,
        search: Arc<SearchServiceHandle>,
        store: Arc<crate::StoreHandle>,
    ) -> Result<Arc<ServiceCoordinatorHandle>, ServiceError> {
        if !Arc::ptr_eq(self, &uploads.root)
            || !Arc::ptr_eq(self, &downloads.root)
            || !Arc::ptr_eq(self, &thumbnails.root)
            || !Arc::ptr_eq(self, &backup.root)
        {
            return Err(invalid());
        }
        Ok(Arc::new(ServiceCoordinatorHandle {
            root: self.clone(),
            coordinator: ServiceCoordinator::new(
                self.client.clone(),
                uploads.service.clone(),
                downloads.service.clone(),
                thumbnails.service.clone(),
                backup.service.clone(),
                search.service.clone(),
                store.store.clone(),
            ),
        }))
    }

    pub fn sign_out_this_app(
        self: &Arc<Self>,
        coordinator: &ServiceCoordinatorHandle,
        canceller: Box<dyn PlatformTransferCancellerCallback>,
        purger: Box<dyn AccountDataPurgerCallback>,
        now_ms: i64,
    ) -> Result<SignOutReportData, ServiceError> {
        if !Arc::ptr_eq(self, &coordinator.root) {
            return Err(invalid());
        }
        if self
            .secret_access
            .as_ref()
            .is_some_and(|callback| !callback.authorize_access("app_sign_out".into()))
        {
            return Err(ServiceError::new(ServiceErrorKind::Storage));
        }
        let platform = PlatformTransferCancellerAdapter {
            callback: canceller.as_ref(),
        };
        let account_data = AccountDataPurgerAdapter {
            callback: purger.as_ref(),
        };
        let report = self.runtime.block_on(coordinator.coordinator.sign_out_app(
            self.secret_store.as_ref(),
            &platform,
            &account_data,
            now_ms,
        ));
        *self.session.lock().map_err(|_| unavailable())? = None;
        Ok(sign_out_report(report))
    }

    pub fn prepare_account_replacement(
        self: &Arc<Self>,
        coordinator: &ServiceCoordinatorHandle,
        confirmed_last_device_warning: bool,
        canceller: Box<dyn PlatformTransferCancellerCallback>,
        purger: Box<dyn AccountDataPurgerCallback>,
        now_ms: i64,
    ) -> Result<Arc<AccountReplacementHandle>, ServiceError> {
        if !confirmed_last_device_warning {
            return Err(ServiceError::new(ServiceErrorKind::AnotherAccountOnDevice));
        }
        if !Arc::ptr_eq(self, &coordinator.root) {
            return Err(invalid());
        }
        if self
            .secret_access
            .as_ref()
            .is_some_and(|callback| !callback.authorize_access("account_replacement".into()))
        {
            return Err(ServiceError::new(ServiceErrorKind::Storage));
        }
        let platform = PlatformTransferCancellerAdapter {
            callback: canceller.as_ref(),
        };
        let account_data = AccountDataPurgerAdapter {
            callback: purger.as_ref(),
        };
        let replacement = self
            .runtime
            .block_on(coordinator.coordinator.prepare_account_replacement(
                self.secret_store.as_ref(),
                &platform,
                &account_data,
                now_ms,
            ))
            .map_err(|_| unavailable())?;
        *self.session.lock().map_err(|_| unavailable())? = None;
        Ok(Arc::new(AccountReplacementHandle {
            root: self.clone(),
            state: Mutex::new(Some(replacement)),
        }))
    }
}

#[uniffi::export]
impl DeviceServiceHandle {
    pub fn sign_out_whole_device(
        &self,
        coordinator: &ServiceCoordinatorHandle,
        device_id: String,
        confirm_last_device: bool,
        canceller: Box<dyn PlatformTransferCancellerCallback>,
        purger: Box<dyn AccountDataPurgerCallback>,
        now_ms: i64,
    ) -> Result<SignOutReportData, ServiceError> {
        if !Arc::ptr_eq(&self.root, &coordinator.root) {
            return Err(invalid());
        }
        if self
            .root
            .secret_access
            .as_ref()
            .is_some_and(|callback| !callback.authorize_access("whole_device_sign_out".into()))
        {
            return Err(ServiceError::new(ServiceErrorKind::Storage));
        }
        let platform = PlatformTransferCancellerAdapter {
            callback: canceller.as_ref(),
        };
        let account_data = AccountDataPurgerAdapter {
            callback: purger.as_ref(),
        };
        let report = self
            .root
            .runtime
            .block_on(coordinator.coordinator.sign_out_device(
                &device_id,
                confirm_last_device,
                self.root.secret_store.as_ref(),
                &platform,
                &account_data,
                now_ms,
            ))
            .map_err(|_| ServiceError::new(ServiceErrorKind::Authentication))?;
        *self.root.session.lock().map_err(|_| unavailable())? = None;
        Ok(sign_out_report(report))
    }
}

#[cfg(test)]
mod purge_callback_tests {
    use super::*;

    struct RefusesPurge;

    impl AccountDataPurgerCallback for RefusesPurge {
        fn purge_account_data(&self) -> bool {
            false
        }
    }

    #[test]
    fn false_platform_purge_answer_is_a_failure() {
        let callback = RefusesPurge;
        let adapter = AccountDataPurgerAdapter { callback: &callback };
        assert!(adapter.purge_account_data().is_err());
    }
}

#[cfg(test)]
mod backup_pass_state_tests {
    use super::*;
    use beebeeb_types::backup::BackupStopReason;

    #[test]
    fn a_stored_pass_state_round_trips_and_a_partial_one_is_refused() {
        let stopped = BackupPassState {
            last_pass_at_ms: Some(10),
            stopped: Some(BackupStop {
                reason: BackupStopReason::AccountLapsed,
                through_ms: 20,
            }),
        };
        let data = BackupPassStateData::from(stopped);
        assert_eq!(data.stopped_reason.as_deref(), Some("account_lapsed"));
        assert_eq!(pass_state(data), Some(stopped));
        assert_eq!(
            pass_state(BackupPassStateData::default()),
            Some(BackupPassState::default())
        );
        for partial in [
            BackupPassStateData {
                stopped_reason: Some("account_lapsed".into()),
                ..Default::default()
            },
            BackupPassStateData {
                stopped_through_ms: Some(20),
                ..Default::default()
            },
            BackupPassStateData {
                stopped_reason: Some("a_reason_from_later".into()),
                stopped_through_ms: Some(20),
                ..Default::default()
            },
        ] {
            assert_eq!(pass_state(partial), None);
        }
    }
}
