use std::{
    fs::File,
    future::Future,
    path::{Path, PathBuf},
    pin::Pin,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use beebeeb_api::routes::uploads::{CompleteRequest, InitRequest};
use beebeeb_core::{
    chunk_stream::{ChunkEncryptor, ExpectedChunkFormat, MAX_CHUNK_SIZE},
    encrypt::{encrypt_name_for_new_item, encrypt_name_for_new_item_version},
    item_id::NewItemId,
};
use beebeeb_store::{Store, TransferState};
use beebeeb_transfer::background::BackgroundError;
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

use crate::{Client, ClientError};

mod queue;
mod steps;

pub use beebeeb_transfer::background::{
    BackgroundFailure, BackgroundGrant, BackgroundRestartPlan, BackgroundRestore, BackgroundUploadPlanner, SignOutPlan,
    StageProgress, TransferFinished, TransferRequest, UploadSourceIdentity,
};
pub use beebeeb_transfer::upload::{UploadOutcome, UploadSession, upload};

const UPLOAD_KIND: &str = "upload-v1";
const DEFAULT_MAX_ATTEMPTS: u32 = 5;
const DEFAULT_DISK_LIMIT: u64 = 512 * 1024 * 1024;
const LEASE_MS: i64 = 10 * 60 * 1000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkKind {
    Offline,
    Cellular,
    WiFi,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransferRule {
    pub wifi_only: bool,
}

impl TransferRule {
    pub fn allows(self, network: NetworkKind) -> bool {
        matches!(network, NetworkKind::WiFi) || (!self.wifi_only && matches!(network, NetworkKind::Cellular))
    }
}

#[derive(Debug, Clone)]
pub struct UploadRequest {
    pub source_path: PathBuf,
    pub name: String,
    pub mime_type: Option<String>,
    pub parent_id: Option<String>,
    pub wifi_only: bool,
    pub disk_limit: u64,
    pub(crate) backup_local_identifier: Option<String>,
    replacement: Option<ReplacementUpload>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReplacementUpload {
    file_id: String,
    base_version_number: i32,
    current_version_metadata_encrypted: String,
    #[serde(default)]
    previous_version_counter: Option<u64>,
}

impl UploadRequest {
    pub fn new(
        source_path: impl Into<PathBuf>,
        name: impl Into<String>,
        mime_type: Option<String>,
        parent_id: Option<String>,
    ) -> Self {
        Self {
            source_path: source_path.into(),
            name: name.into(),
            mime_type,
            parent_id,
            wifi_only: true,
            disk_limit: DEFAULT_DISK_LIMIT,
            backup_local_identifier: None,
            replacement: None,
        }
    }

    pub fn replacement(
        source_path: impl Into<PathBuf>,
        name: impl Into<String>,
        mime_type: Option<String>,
        file_id: impl Into<String>,
        base_version_number: i32,
        current_version_metadata_encrypted: impl Into<String>,
    ) -> Self {
        Self {
            source_path: source_path.into(),
            name: name.into(),
            mime_type,
            parent_id: None,
            wifi_only: true,
            disk_limit: DEFAULT_DISK_LIMIT,
            backup_local_identifier: None,
            replacement: Some(ReplacementUpload {
                file_id: file_id.into(),
                base_version_number,
                current_version_metadata_encrypted: current_version_metadata_encrypted.into(),
                previous_version_counter: None,
            }),
        }
    }

    pub(crate) fn for_backup(mut self, local_identifier: &str) -> Self {
        self.backup_local_identifier = Some(local_identifier.to_owned());
        self
    }
}

pub trait UploadCompletionHandler: Send + Sync {
    fn completed<'a>(
        &'a self,
        local_identifier: &'a str,
        file_id: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(), ()>> + Send + 'a>>;
}

pub fn transfer_now_ms() -> Result<i64, UploadServiceError> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| UploadServiceError::State)?;
    i64::try_from(elapsed.as_millis()).map_err(|_| UploadServiceError::State)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UploadSummary {
    pub id: i64,
    pub file_id: String,
    pub name: String,
    pub state: TransferState,
    pub attempts: u32,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UploadEvent {
    Changed { id: i64, state: TransferState },
    TokenExpired { id: i64 },
    SourceChanged { id: i64 },
    QuotaFull { id: i64 },
}

#[derive(Debug, thiserror::Error)]
pub enum UploadServiceError {
    #[error("upload state is unavailable")]
    State,
    #[error("the upload source is unavailable")]
    Source,
    #[error("the server returned a hostile chunk plan")]
    HostileChunkPlan,
    #[error("the account has no storage space for this upload")]
    QuotaFull,
    #[error("the upload source changed; the old session was abandoned")]
    SourceChangedRestarted,
    #[error("upload encryption failed")]
    Encryption,
    #[error("the upload is not in an active state")]
    NotActive,
    #[error(transparent)]
    Client(#[from] ClientError),
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct UploadRecord {
    source_path: PathBuf,
    source_identity: UploadSourceIdentity,
    name: String,
    mime_type: Option<String>,
    parent_id: Option<String>,
    wifi_only: bool,
    disk_limit: u64,
    file_id: String,
    item_tag: Vec<u8>,
    session_id: Option<String>,
    chunk_size: Option<u64>,
    chunk_count: Option<u32>,
    planner: Option<Vec<u8>>,
    #[serde(default)]
    backup_local_identifier: Option<String>,
    #[serde(default)]
    replacement: Option<ReplacementUpload>,
    #[serde(default)]
    restart_intent: Option<RestartIntent>,
    #[serde(default)]
    remote_completed: bool,
    #[serde(default)]
    backup_outcome_applied: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackupUploadOutcomeKind {
    Completed,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupUploadOutcome {
    pub upload_id: i64,
    pub local_identifier: String,
    pub file_id: String,
    pub kind: BackupUploadOutcomeKind,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RestartIntent {
    source_identity: UploadSourceIdentity,
    file_id: String,
    upload_session_id: String,
    delete_files: Vec<PathBuf>,
}

pub struct UploadService {
    client: Arc<Client>,
    store: Arc<Mutex<Store>>,
    staging_root: PathBuf,
    events: broadcast::Sender<UploadEvent>,
    completion_handler: Mutex<Option<Arc<dyn UploadCompletionHandler>>>,
}

fn source_identity(path: &Path) -> Result<UploadSourceIdentity, UploadServiceError> {
    let metadata = std::fs::metadata(path).map_err(|_| UploadServiceError::Source)?;
    if !metadata.is_file() {
        return Err(UploadServiceError::Source);
    }
    let modified = metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH);
    let modified_unix_ms = match modified.duration_since(UNIX_EPOCH) {
        Ok(duration) => i64::try_from(duration.as_millis()).unwrap_or(i64::MAX),
        Err(_) => 0,
    };
    Ok(UploadSourceIdentity {
        size_bytes: metadata.len(),
        modified_unix_ms,
        content_hash: None,
    })
}

fn staged_files(directory: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(directory) else {
        return Vec::new();
    };
    entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.is_file())
        .collect()
}

fn validate_geometry(file_size: u64, chunk_size: u64, chunk_count: u64) -> Result<u32, UploadServiceError> {
    if chunk_size == 0 || chunk_size > MAX_CHUNK_SIZE {
        return Err(UploadServiceError::HostileChunkPlan);
    }
    let expected = if file_size == 0 {
        1
    } else {
        file_size
            .checked_sub(1)
            .and_then(|value| value.checked_div(chunk_size))
            .and_then(|value| value.checked_add(1))
            .ok_or(UploadServiceError::HostileChunkPlan)?
    };
    if chunk_count != expected {
        return Err(UploadServiceError::HostileChunkPlan);
    }
    u32::try_from(chunk_count).map_err(|_| UploadServiceError::HostileChunkPlan)
}

fn encode_record(record: &UploadRecord) -> Result<Vec<u8>, UploadServiceError> {
    serde_json::to_vec(record).map_err(|_| UploadServiceError::State)
}
fn decode_record(bytes: &[u8]) -> Result<UploadRecord, UploadServiceError> {
    serde_json::from_slice(bytes).map_err(|_| UploadServiceError::State)
}
fn map_background(_error: BackgroundError) -> UploadServiceError {
    UploadServiceError::State
}

fn client_upgrade_required(error: &ClientError) -> bool {
    matches!(
        error,
        ClientError::Api(beebeeb_api::ApiError::Server(server)) if server.status == 426
    )
}

fn upload_upgrade_required(error: &UploadServiceError) -> bool {
    matches!(error, UploadServiceError::Client(error) if client_upgrade_required(error))
}
fn remove_planned_files(plan: &SignOutPlan) {
    for path in &plan.delete_files {
        let _ = std::fs::remove_file(path);
    }
}
