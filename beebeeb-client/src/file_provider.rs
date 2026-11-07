use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
    sync::{Arc, Mutex},
};

use beebeeb_core::backup::Mutation;
use beebeeb_core::sync::{RemoteOp, SyncEngine, SyncEngineError, SyncOp, TreeNode};
use beebeeb_types::{ChunkProfile, limits::MemoryBudget, plan_chunks};
use serde_json::json;
use uuid::Uuid;

use crate::{
    Client, Session,
    backup_guard::Rule,
    downloads::{DownloadFile, DownloadResult, DownloadService, DownloadServiceError},
    files::{FileRecord, FileServiceError},
    uploads::{UploadRequest, UploadService, UploadServiceError},
};

const MAX_CHANGES: usize = 500;
const INTERNAL_BACKUP_MANIFEST: &str = ".beebeeb-backup-manifest";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ItemWorkState {
    Queued,
    Running,
    Succeeded,
    Failed,
    HandedOff,
}

impl ItemWorkState {
    pub fn is_final(self) -> bool {
        matches!(self, Self::Succeeded | Self::Failed | Self::HandedOff)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileProviderItem {
    pub id: Uuid,
    pub parent_id: Option<Uuid>,
    pub name: String,
    pub name_undecryptable: bool,
    pub mime_type: Option<String>,
    pub is_folder: bool,
    pub size_bytes: u64,
    pub version_number: i32,
}

impl From<TreeNode> for FileProviderItem {
    fn from(node: TreeNode) -> Self {
        Self {
            id: node.id,
            parent_id: node.parent_id,
            name: node.name,
            name_undecryptable: node.name_undecryptable,
            mime_type: node.mime_type,
            is_folder: node.is_folder,
            size_bytes: u64::try_from(node.size_bytes).unwrap_or(0),
            version_number: node.version_number,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileProviderChanges {
    pub changed: Vec<FileProviderItem>,
    pub deleted: Vec<Uuid>,
    pub anchor: i64,
    pub more_coming: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileProviderOutcome {
    Ready(PathBuf),
    Saved,
    Queued { upload_id: i64, file_id: String },
    HandOff { frame_size: u64, context_limit: u64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DomainNotifierError {
    #[error("the File Provider domain could not be signalled")]
    Unavailable,
}

/// Platform seam for `signalEnumerator(for: .workingSet)`. Signalling root is
/// deliberately absent because replicated File Providers ignore it.
pub trait DomainNotifier: Send + Sync {
    fn signal_working_set(&self) -> Result<(), DomainNotifierError>;
}

#[derive(Debug, thiserror::Error)]
pub enum FileProviderError {
    #[error("File Provider state is unavailable")]
    State,
    #[error("the item does not exist")]
    NotFound,
    #[error("the item identifier is invalid")]
    InvalidIdentifier,
    #[error("the requested change page is too large")]
    TooManyChanges,
    #[error("a valid frame is too large for this extension context")]
    TooLargeForContext { frame_size: u64, context_limit: u64 },
    #[error(transparent)]
    Sync(#[from] SyncEngineError),
    #[error(transparent)]
    Client(#[from] crate::ClientError),
    #[error(transparent)]
    Notify(#[from] DomainNotifierError),
    #[error(transparent)]
    File(#[from] FileServiceError),
    #[error(transparent)]
    Upload(#[from] UploadServiceError),
    #[error(transparent)]
    Download(#[from] DownloadServiceError),
}

pub struct FileProviderService {
    engine: Mutex<SyncEngine>,
    notifier: Arc<dyn DomainNotifier>,
    states: Mutex<BTreeMap<Uuid, ItemWorkState>>,
    system_items: Mutex<BTreeSet<Uuid>>,
    budget: MemoryBudget,
}

impl FileProviderService {
    pub fn new(engine: SyncEngine, notifier: Arc<dyn DomainNotifier>) -> Self {
        Self::with_budget(engine, notifier, MemoryBudget::MOBILE_EXTENSION)
    }

    pub fn with_budget(engine: SyncEngine, notifier: Arc<dyn DomainNotifier>, budget: MemoryBudget) -> Self {
        Self {
            engine: Mutex::new(engine),
            notifier,
            states: Mutex::new(BTreeMap::new()),
            system_items: Mutex::new(BTreeSet::new()),
            budget,
        }
    }

    /// Supply ids carrying an authenticated `managed_by` marker. They stay in
    /// the shared store for service ownership but are not vended to Files.
    pub fn set_system_items(&self, ids: impl IntoIterator<Item = Uuid>) -> Result<(), FileProviderError> {
        *self.system_items.lock().map_err(|_| FileProviderError::State)? = ids.into_iter().collect();
        Ok(())
    }

    /// One targeted store lookup; a store-backed engine never hydrates the
    /// rest of the vault for an item request.
    pub fn item(&self, id: Uuid) -> Result<Option<FileProviderItem>, FileProviderError> {
        let node = self
            .engine
            .lock()
            .map_err(|_| FileProviderError::State)?
            .lookup_node(id)?;
        let system_items = self.system_items.lock().map_err(|_| FileProviderError::State)?;
        Ok(node.filter(|node| visible_node(node, &system_items)).map(Into::into))
    }

    /// The store executes one indexed parent query. No whole-tree state is
    /// loaded into the extension.
    pub fn children(&self, parent_id: Option<Uuid>) -> Result<Vec<FileProviderItem>, FileProviderError> {
        let system_items = self.system_items.lock().map_err(|_| FileProviderError::State)?;
        Ok(self
            .engine
            .lock()
            .map_err(|_| FileProviderError::State)?
            .lookup_children(parent_id)?
            .into_iter()
            .filter(|node| visible_node(node, &system_items))
            .map(Into::into)
            .collect())
    }

    pub fn changes_since(&self, anchor: i64, limit: usize) -> Result<FileProviderChanges, FileProviderError> {
        if limit == 0 || limit > MAX_CHANGES {
            return Err(FileProviderError::TooManyChanges);
        }
        let engine = self.engine.lock().map_err(|_| FileProviderError::State)?;
        let system_items = self.system_items.lock().map_err(|_| FileProviderError::State)?;
        let operations = engine.changes_since(anchor, limit.saturating_add(1))?;
        let more_coming = operations.len() > limit;
        let mut changed = Vec::new();
        let mut deleted = Vec::new();
        let mut next_anchor = anchor;
        for operation in operations.into_iter().take(limit) {
            next_anchor = next_anchor.max(operation.seq_id);
            let Some(id) = operation
                .payload
                .get("id")
                .and_then(serde_json::Value::as_str)
                .and_then(|value| Uuid::parse_str(value).ok())
            else {
                continue;
            };
            if operation.op_type == "file_delete" || operation.op_type == "file_trash" {
                deleted.push(id);
            } else if let Some(node) = engine.lookup_node(id)?
                && visible_node(&node, &system_items)
            {
                changed.push(node.into());
            }
        }
        Ok(FileProviderChanges {
            changed,
            deleted,
            anchor: next_anchor,
            more_coming,
        })
    }

    pub async fn fetch_contents(
        &self,
        downloads: &DownloadService,
        file: &DownloadFile,
        now_ms: i64,
    ) -> Result<FileProviderOutcome, FileProviderError> {
        let id = parse_id(&file.file_id)?;
        self.set_state(id, ItemWorkState::Running)?;
        let outcome = downloads.open(file, now_ms).await;
        let result = match outcome {
            Ok(DownloadResult::Ready(path)) => {
                self.set_state(id, ItemWorkState::Succeeded)?;
                Ok(FileProviderOutcome::Ready(path))
            }
            Ok(DownloadResult::Saved) => {
                self.set_state(id, ItemWorkState::Succeeded)?;
                Ok(FileProviderOutcome::Saved)
            }
            Ok(DownloadResult::HandOff {
                frame_size,
                context_limit,
            })
            | Err(DownloadServiceError::HandOff {
                frame_size,
                context_limit,
            }) => {
                self.set_state(id, ItemWorkState::HandedOff)?;
                Ok(FileProviderOutcome::HandOff {
                    frame_size,
                    context_limit,
                })
            }
            Err(error) => {
                self.set_state(id, ItemWorkState::Failed)?;
                Err(error.into())
            }
        };
        self.signal_after_work(result)
    }

    pub async fn create_folder(
        &self,
        client: &Client,
        session: &Session,
        name: &str,
        parent_id: Option<String>,
    ) -> Result<FileRecord, FileProviderError> {
        let result = client.create_folder(session, name, parent_id).await.map_err(Into::into);
        match result {
            Ok(record) => {
                let id = parse_id(&record.id)?;
                self.set_state(id, ItemWorkState::Succeeded)?;
                self.notifier.signal_working_set()?;
                Ok(record)
            }
            Err(error) => {
                self.notifier.signal_working_set()?;
                Err(error)
            }
        }
    }

    pub fn create_file(
        &self,
        uploads: &UploadService,
        request: UploadRequest,
        now_ms: i64,
    ) -> Result<FileProviderOutcome, FileProviderError> {
        let size = std::fs::metadata(&request.source_path)
            .map_err(|_| FileProviderError::State)?
            .len();
        let frame_size = plan_chunks(size, ChunkProfile::Mobile)
            .chunk_size_bytes
            .min(size)
            .checked_add(28)
            .ok_or(FileProviderError::TooLargeForContext {
                frame_size: u64::MAX,
                context_limit: self.budget.download_frame_bytes,
            })?;
        if frame_size > self.budget.download_frame_bytes {
            return Ok(FileProviderOutcome::HandOff {
                frame_size,
                context_limit: self.budget.download_frame_bytes,
            });
        }
        let upload_id = uploads.enqueue(request, now_ms)?;
        let summary = uploads
            .list()?
            .into_iter()
            .find(|item| item.id == upload_id)
            .ok_or(FileProviderError::State)?;
        let id = parse_id(&summary.file_id)?;
        self.set_state(id, ItemWorkState::Queued)?;
        self.notifier.signal_working_set()?;
        Ok(FileProviderOutcome::Queued {
            upload_id,
            file_id: summary.file_id,
        })
    }

    pub async fn modify(
        &self,
        client: &Client,
        session: &Session,
        id: Uuid,
        new_name: Option<&str>,
        new_parent: Option<Option<String>>,
    ) -> Result<FileRecord, FileProviderError> {
        self.set_state(id, ItemWorkState::Running)?;
        let result = async {
            let node = self
                .engine
                .lock()
                .map_err(|_| FileProviderError::State)?
                .lookup_node(id)?
                .ok_or(FileProviderError::NotFound)?;
            let mut entry = wire_entry(&node);
            let mut result = None;
            // The Files app is a drive surface: core's drive rule, under which
            // nothing at or under the Backups root changes.
            if let Some(name) = new_name {
                let record = client.rename_entry_under(Rule::Drive, session, &entry, name).await?;
                entry = record.wire().clone();
                result = Some(record);
            }
            if let Some(parent) = new_parent {
                result = Some(client.move_entry_under(Rule::Drive, session, &entry, parent).await?);
            }
            result.ok_or(FileProviderError::State)
        }
        .await;
        self.finish_item_work(id, result)
    }

    pub async fn delete(&self, client: &Client, id: Uuid) -> Result<(), FileProviderError> {
        self.set_state(id, ItemWorkState::Running)?;
        let result = async {
            let node = self
                .engine
                .lock()
                .map_err(|_| FileProviderError::State)?
                .lookup_node(id)?
                .ok_or(FileProviderError::NotFound)?;
            client
                .trash_entry_under(Rule::Drive, &wire_entry(&node))
                .await
                .map_err(Into::into)
        }
        .await;
        self.finish_item_work(id, result)
    }

    /// Queue the local delete intent used by offline File Provider requests.
    /// A missing item is a terminal failure, never a permanent "syncing" row.
    pub async fn delete_local(&self, client: &Client, id: Uuid) -> Result<(), FileProviderError> {
        self.set_state(id, ItemWorkState::Running)?;
        let result = async {
            if self
                .engine
                .lock()
                .map_err(|_| FileProviderError::State)?
                .lookup_node(id)?
                .is_none()
            {
                return Err(FileProviderError::NotFound);
            }
            client
                .check_backup_mutation(Rule::Drive, &id.to_string(), Mutation::Trash)
                .await
                .map_err(FileServiceError::from)?;
            let (pending, device_id) = {
                let mut engine = self.engine.lock().map_err(|_| FileProviderError::State)?;
                if engine.lookup_node(id)?.is_none() {
                    return Err(FileProviderError::NotFound);
                }
                let device_id = engine.device_id().to_owned();
                let pending = engine.apply_local_op("file_delete", json!({"id": id.to_string()}))?;
                (pending, device_id)
            };
            let request = beebeeb_api::routes::sync::Submit {
                ops: vec![beebeeb_api::routes::sync::Op {
                    seq_id: None,
                    user_seq: None,
                    op_type: pending.op_type.clone(),
                    payload: pending.payload.clone(),
                    client_op_id: Some(pending.client_op_id.to_string()),
                    device_id: Some(device_id),
                    created_at: None,
                }],
            };
            let answer: beebeeb_api::routes::sync::SubmitResult =
                match client.execute(&beebeeb_api::routes::sync::submit(), &request).await {
                    Ok(answer) => answer,
                    Err(error) => {
                        self.engine
                            .lock()
                            .map_err(|_| FileProviderError::State)?
                            .cancel_local_op(pending.client_op_id)?;
                        return Err(error.into());
                    }
                };
            let Some(applied) = answer
                .applied
                .into_iter()
                .find(|applied| applied.client_op_id == pending.client_op_id.to_string())
            else {
                self.engine
                    .lock()
                    .map_err(|_| FileProviderError::State)?
                    .cancel_local_op(pending.client_op_id)?;
                return Err(FileProviderError::State);
            };
            self.engine
                .lock()
                .map_err(|_| FileProviderError::State)?
                .apply_remote_op(RemoteOp::from_authenticated_session(SyncOp {
                    seq_id: applied.seq_id,
                    user_seq: Some(applied.user_seq),
                    op_type: pending.op_type,
                    client_op_id: Some(pending.client_op_id),
                    payload: pending.payload,
                    device_id: None,
                    created_at: chrono::Utc::now(),
                }))?;
            Ok(())
        }
        .await;
        self.finish_item_work(id, result)
    }

    pub fn work_state(&self, id: Uuid) -> Option<ItemWorkState> {
        self.states.lock().ok()?.get(&id).copied()
    }

    fn set_state(&self, id: Uuid, state: ItemWorkState) -> Result<(), FileProviderError> {
        self.states
            .lock()
            .map_err(|_| FileProviderError::State)?
            .insert(id, state);
        Ok(())
    }

    fn finish_item_work<T>(&self, id: Uuid, result: Result<T, FileProviderError>) -> Result<T, FileProviderError> {
        self.set_state(
            id,
            if result.is_ok() {
                ItemWorkState::Succeeded
            } else {
                ItemWorkState::Failed
            },
        )?;
        let notified = self.notifier.signal_working_set();
        match (result, notified) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(error.into()),
        }
    }

    fn signal_after_work<T>(&self, result: Result<T, FileProviderError>) -> Result<T, FileProviderError> {
        let notified = self.notifier.signal_working_set();
        match (result, notified) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(error.into()),
        }
    }
}

fn parse_id(id: &str) -> Result<Uuid, FileProviderError> {
    Uuid::parse_str(id).map_err(|_| FileProviderError::InvalidIdentifier)
}

fn wire_entry(node: &TreeNode) -> beebeeb_api::routes::files::FileEntry {
    beebeeb_api::routes::files::FileEntry {
        id: node.id.to_string(),
        parent_id: node.parent_id.map(|id| id.to_string()),
        name_encrypted: Some(node.name_encrypted.clone()),
        is_folder: node.is_folder,
        is_trashed: node.is_trashed,
        size_bytes: u64::try_from(node.size_bytes).unwrap_or(0),
        extra: Default::default(),
    }
}

fn visible_node(node: &TreeNode, system_items: &BTreeSet<Uuid>) -> bool {
    visible_in_files_app(
        node.is_trashed,
        node.name == INTERNAL_BACKUP_MANIFEST || system_items.contains(&node.id),
    )
}

pub fn visible_in_files_app(is_trash: bool, is_system_file: bool) -> bool {
    !is_trash && !is_system_file
}

pub use beebeeb_store::{Node, Store};
