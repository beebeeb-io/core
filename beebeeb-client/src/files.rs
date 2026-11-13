use beebeeb_api::routes::files::{self as api, FileEntry, ListResponse};
use beebeeb_core::backup::{Mutation, Protected};
use beebeeb_core::system_folders::{SYSTEM_FOLDER_MANAGED_CODE, SYSTEM_FOLDER_MANAGED_MESSAGE};
#[cfg(feature = "store")]
use beebeeb_core::{
    chunk_stream::VersionCommitment,
    encrypt::{decrypt_file_metadata, encrypt_name_for_version},
    kdf::derive_file_key,
};
use serde_json::Value;
#[cfg(feature = "store")]
use std::sync::Mutex;

use crate::{
    Client, ClientError, Session,
    backup_guard::{GuardError, Rule},
};

pub const FILE_LIST_PAGE_CAP: u16 = 500;

#[derive(Debug, Clone)]
pub struct FileRecord {
    pub id: String,
    pub parent_id: Option<String>,
    pub name: String,
    pub mime_type: Option<String>,
    pub is_folder: bool,
    pub is_trashed: bool,
    pub size_bytes: u64,
    pub managed_by: Option<String>,
    pub storage_country: Option<String>,
    wire: FileEntry,
}

#[derive(Debug, Clone)]
pub struct FileRecordPage {
    pub files: Vec<FileRecord>,
    pub next_cursor: Option<String>,
}

impl FileRecord {
    pub fn wire(&self) -> &FileEntry {
        &self.wire
    }

    #[cfg(test)]
    pub(crate) fn for_test(id: &str, name: &str) -> Self {
        let wire = FileEntry {
            id: id.into(),
            parent_id: None,
            name_encrypted: Some("sealed".into()),
            is_folder: false,
            is_trashed: false,
            size_bytes: 0,
            extra: Default::default(),
        };
        Self {
            id: id.into(),
            parent_id: None,
            name: name.into(),
            mime_type: None,
            is_folder: false,
            is_trashed: false,
            size_bytes: 0,
            managed_by: None,
            storage_country: None,
            wire,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum FileServiceError {
    #[error(transparent)]
    Client(#[from] ClientError),
    #[error(transparent)]
    Crypto(#[from] beebeeb_core::CoreError),
    #[error("{message}")]
    ManagedByService { code: &'static str, message: &'static str },
    /// Core's Backups rule refused the change; the words are core's (backup
    /// spec Amendments 6 to 8).
    #[error("{0}")]
    Protected(Protected),
    #[error("the server returned an invalid file record")]
    InvalidRecord,
    #[error("the server returned a different id for a newly-created folder")]
    ItemIdMismatch,
    #[error("the folder listing exceeded its item limit")]
    ListingTooLarge,
    #[cfg(all(feature = "store", feature = "downloads", feature = "uploads"))]
    #[error("the source file requires handoff to a less constrained context")]
    HandOff { frame_size: u64, context_limit: u64 },
    #[cfg(all(feature = "store", feature = "downloads", feature = "uploads"))]
    #[error("the duplicate source could not be materialized")]
    Download(#[from] crate::downloads::DownloadServiceError),
    #[cfg(all(feature = "store", feature = "downloads", feature = "uploads"))]
    #[error("the duplicate could not be queued")]
    Upload(#[from] crate::uploads::UploadServiceError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BulkFileResult {
    pub completed: Vec<String>,
    pub already_done: Vec<String>,
    pub missing: Vec<String>,
    pub refused: Vec<String>,
}

#[cfg(feature = "store")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VersionRestoreResult {
    pub counter: Option<u64>,
}

#[cfg(all(feature = "store", feature = "downloads", feature = "uploads"))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DuplicateResult {
    pub upload_id: i64,
    pub new_file_id: String,
}

/// Duplicate by opening authenticated plaintext and queuing a fresh upload.
/// Ciphertext is never copied because v2 authenticates the original file id.
#[cfg(all(feature = "store", feature = "downloads", feature = "uploads"))]
pub async fn duplicate_file(
    downloads: &crate::downloads::DownloadService,
    uploads: &crate::uploads::UploadService,
    source: &crate::downloads::DownloadFile,
    new_name: &str,
    mime_type: Option<String>,
    parent_id: Option<String>,
    now_ms: i64,
) -> Result<DuplicateResult, FileServiceError> {
    downloads.person_call(crate::LockedAction::MutateFiles)?;
    let path = match downloads.open_inner(source, now_ms).await? {
        crate::downloads::DownloadResult::Ready(path) => path,
        crate::downloads::DownloadResult::HandOff {
            frame_size,
            context_limit,
        } => {
            return Err(FileServiceError::HandOff {
                frame_size,
                context_limit,
            });
        }
        crate::downloads::DownloadResult::Saved => return Err(FileServiceError::InvalidRecord),
    };
    let upload_id = uploads.enqueue_inner(
        crate::uploads::UploadRequest::new(path, new_name, mime_type, parent_id),
        now_ms,
    )?;
    let summary = uploads
        .list_inner()?
        .into_iter()
        .find(|item| item.id == upload_id)
        .ok_or(FileServiceError::InvalidRecord)?;
    Ok(DuplicateResult {
        upload_id,
        new_file_id: summary.file_id,
    })
}

impl Client {
    pub async fn list_files(&self, parent_id: Option<&str>, trashed: bool) -> Result<ListResponse, ClientError> {
        self.person_call(crate::LockedAction::ViewFiles)?;
        self.execute(&api::list(parent_id, trashed), &()).await
    }

    pub async fn list_file_records_page(
        &self,
        session: &Session,
        parent_id: Option<&str>,
        trashed: bool,
        cursor: Option<&str>,
        limit: u16,
    ) -> Result<FileRecordPage, FileServiceError> {
        self.person_call(crate::LockedAction::ViewFiles)?;
        if limit == 0 || limit > FILE_LIST_PAGE_CAP {
            return Err(FileServiceError::ListingTooLarge);
        }
        let response: ListResponse = self
            .execute(&api::list_page(parent_id, trashed, cursor, Some(limit)), &())
            .await?;
        if response.files.len() > usize::from(limit) {
            return Err(FileServiceError::ListingTooLarge);
        }
        let files = response
            .files
            .into_iter()
            .map(|entry| open_record(session, entry))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(FileRecordPage {
            files,
            next_cursor: response.next_cursor,
        })
    }

    pub async fn get_file(&self, id: &str) -> Result<FileEntry, ClientError> {
        self.person_call(crate::LockedAction::ViewFiles)?;
        self.get_file_inner(id).await
    }

    pub(crate) async fn get_file_inner(&self, id: &str) -> Result<FileEntry, ClientError> {
        self.execute(&api::get(id), &()).await
    }

    pub async fn get_file_record(&self, session: &Session, id: &str) -> Result<FileRecord, FileServiceError> {
        self.person_call(crate::LockedAction::ViewFiles)?;
        open_record(session, self.get_file_inner(id).await?)
    }

    pub async fn create_folder(
        &self,
        session: &Session,
        name: &str,
        parent_id: Option<String>,
    ) -> Result<FileRecord, FileServiceError> {
        self.person_call(crate::LockedAction::MutateFiles)?;
        self.create_folder_inner(session, name, parent_id).await
    }

    pub(crate) async fn create_folder_inner(
        &self,
        session: &Session,
        name: &str,
        parent_id: Option<String>,
    ) -> Result<FileRecord, FileServiceError> {
        self.check_backup_create_in(parent_id.as_deref()).await?;
        let (item, name_encrypted) = session.seal_new_folder(name)?;
        let request = api::CreateFolder {
            name_encrypted,
            parent_id,
            folder_id: item.as_str().to_string(),
        };
        let entry: FileEntry = self.execute(&api::create_folder(), &request).await?;
        if entry.id != item.as_str() {
            return Err(FileServiceError::ItemIdMismatch);
        }
        open_record(session, entry)
    }

    pub async fn rename_entry(
        &self,
        session: &Session,
        entry: &FileEntry,
        new_name: &str,
    ) -> Result<FileRecord, FileServiceError> {
        self.person_call(crate::LockedAction::MutateFiles)?;
        self.rename_entry_under(Rule::App, session, entry, new_name).await
    }

    pub(crate) async fn rename_entry_under(
        &self,
        rule: Rule,
        session: &Session,
        entry: &FileEntry,
        new_name: &str,
    ) -> Result<FileRecord, FileServiceError> {
        refuse_managed(entry)?;
        self.check_backup_mutation(rule, &entry.id, Mutation::Rename).await?;
        let current = entry.name_encrypted.as_deref().ok_or(FileServiceError::InvalidRecord)?;
        let name_encrypted = session.seal_rename(&entry.id, current, new_name)?;
        let updated = self
            .execute(
                &api::update(&entry.id),
                &api::UpdateFile {
                    name_encrypted: Some(name_encrypted),
                    parent_id: None,
                },
            )
            .await
            .map_err(map_client_error)?;
        open_record(session, updated)
    }

    pub async fn move_entry(
        &self,
        session: &Session,
        entry: &FileEntry,
        parent_id: Option<String>,
    ) -> Result<FileRecord, FileServiceError> {
        self.person_call(crate::LockedAction::MutateFiles)?;
        self.move_entry_under(Rule::App, session, entry, parent_id).await
    }

    /// A move is checked twice: the row that moves, and its destination as a
    /// new item there.
    pub(crate) async fn move_entry_under(
        &self,
        rule: Rule,
        session: &Session,
        entry: &FileEntry,
        parent_id: Option<String>,
    ) -> Result<FileRecord, FileServiceError> {
        refuse_managed(entry)?;
        self.check_backup_mutation(rule, &entry.id, Mutation::Move).await?;
        self.check_backup_create_in(parent_id.as_deref()).await?;
        let updated = self
            .execute(
                &api::update(&entry.id),
                &api::UpdateFile {
                    name_encrypted: None,
                    parent_id: Some(parent_id),
                },
            )
            .await
            .map_err(map_client_error)?;
        open_record(session, updated)
    }

    pub async fn trash_file(&self, id: &str) -> Result<(), ClientError> {
        self.person_call(crate::LockedAction::MutateFiles)?;
        self.execute(&api::trash(id), &()).await.map(|_| ())
    }

    pub async fn trash_entry(&self, entry: &FileEntry) -> Result<(), FileServiceError> {
        self.person_call(crate::LockedAction::MutateFiles)?;
        self.trash_entry_under(Rule::App, entry).await
    }

    pub(crate) async fn trash_entry_under(&self, rule: Rule, entry: &FileEntry) -> Result<(), FileServiceError> {
        refuse_managed(entry)?;
        self.check_backup_mutation(rule, &entry.id, Mutation::Trash).await?;
        self.execute(&api::trash(&entry.id), &())
            .await
            .map(|_| ())
            .map_err(map_client_error)?;
        Ok(())
    }

    pub async fn trash_entries(&self, entries: &[FileEntry]) -> Result<BulkFileResult, FileServiceError> {
        self.person_call(crate::LockedAction::MutateFiles)?;
        for entry in entries {
            refuse_managed(entry)?;
        }
        for entry in entries {
            self.check_backup_mutation(Rule::App, &entry.id, Mutation::Trash)
                .await?;
        }
        let value: Value = self
            .execute(
                &api::trash_many(),
                &api::Ids {
                    ids: entries.iter().map(|entry| entry.id.clone()).collect(),
                },
            )
            .await
            .map_err(map_client_error)?;
        Ok(bulk_result(&value, "trashed", "already_trashed", "refused"))
    }

    pub async fn restore_file(&self, id: &str) -> Result<(), ClientError> {
        self.person_call(crate::LockedAction::MutateFiles)?;
        self.execute(&api::restore(id), &()).await.map(|_| ())
    }

    /// Restore from the Trash. Deliberately not asked of core's Backups rule
    /// (review r4, decided): a restore writes nothing new, it undoes a trash
    /// the app rule allowed (a backup's device or category folder, or one
    /// file, rule 11). The server puts the item back where it was, or at the
    /// top of the drive when that folder is gone, never anywhere else, so
    /// nothing reaches the Backups tree that the device's own pass did not
    /// write. The backup spec relies on it: a folder restored before the pass
    /// "changes nothing: the records still match" (§4.2 rule 11), and
    /// "Back up again" finds a restored device folder (Amendment 12). A copy
    /// the pass recorded as trashed stays recorded so; it is never uploaded
    /// twice.
    pub async fn restore_entry(&self, entry: &FileEntry) -> Result<(), FileServiceError> {
        self.person_call(crate::LockedAction::MutateFiles)?;
        refuse_managed(entry)?;
        self.execute(&api::restore(&entry.id), &())
            .await
            .map(|_| ())
            .map_err(map_client_error)?;
        Ok(())
    }

    pub async fn delete_file_forever(&self, id: &str) -> Result<(), ClientError> {
        self.person_call(crate::LockedAction::MutateFiles)?;
        self.execute(&api::permanent_delete(id), &()).await.map(|_| ())
    }

    pub async fn delete_entry_forever(&self, entry: &FileEntry) -> Result<(), FileServiceError> {
        self.person_call(crate::LockedAction::MutateFiles)?;
        refuse_managed(entry)?;
        self.check_backup_mutation(Rule::App, &entry.id, Mutation::DeletePermanently)
            .await?;
        self.execute(&api::permanent_delete(&entry.id), &())
            .await
            .map(|_| ())
            .map_err(map_client_error)?;
        Ok(())
    }

    pub async fn delete_entries_forever(&self, entries: &[FileEntry]) -> Result<BulkFileResult, FileServiceError> {
        self.person_call(crate::LockedAction::MutateFiles)?;
        for entry in entries {
            refuse_managed(entry)?;
        }
        for entry in entries {
            self.check_backup_mutation(Rule::App, &entry.id, Mutation::DeletePermanently)
                .await?;
        }
        let value: Value = self
            .execute(
                &api::permanent_delete_many(),
                &api::Ids {
                    ids: entries.iter().map(|entry| entry.id.clone()).collect(),
                },
            )
            .await
            .map_err(map_client_error)?;
        Ok(bulk_result(&value, "deleted", "skipped_not_trashed", "refused"))
    }

    pub async fn file_versions(&self, id: &str) -> Result<api::Versions, ClientError> {
        self.person_call(crate::LockedAction::ViewFiles)?;
        self.execute(&api::versions(id), &()).await
    }

    /// Restore historical content while publishing fresh authenticated current
    /// metadata. The restored chunks keep their original frame-zero version id,
    /// while the counter advances beyond every version this device can see.
    #[cfg(feature = "store")]
    pub async fn restore_version(
        &self,
        session: &Session,
        store: &Mutex<beebeeb_store::Store>,
        file_id: &str,
        version_id: &str,
    ) -> Result<VersionRestoreResult, FileServiceError> {
        self.person_call(crate::LockedAction::MutateFiles)?;
        let current_entry = self.get_file_inner(file_id).await?;
        refuse_managed(&current_entry)?;
        // A restored version is new content of the file.
        self.check_backup_row(Rule::App, &current_entry, Mutation::Write)
            .await?;
        let current_encrypted = current_entry
            .name_encrypted
            .as_deref()
            .ok_or(FileServiceError::InvalidRecord)?;
        let current = decrypt_file_metadata(session.master_key(), file_id, current_encrypted)?;
        let versions: api::Versions = self.execute(&api::versions(file_id), &()).await?;
        if versions.file_id != file_id {
            return Err(FileServiceError::InvalidRecord);
        }
        let restored_encrypted = versions
            .versions
            .iter()
            .find(|version| version.id == version_id)
            .ok_or(FileServiceError::InvalidRecord)?
            .version_metadata_encrypted
            .as_deref();
        let restored = restored_encrypted
            .map(|encrypted| decrypt_file_metadata(session.master_key(), file_id, encrypted))
            .transpose()?;

        let remembered = store
            .lock()
            .map_err(|_| FileServiceError::InvalidRecord)?
            .highest_file_version(file_id)
            .map_err(|_| FileServiceError::InvalidRecord)?;
        let mut highest = remembered;
        if let Some(commitment) = current.version {
            highest = Some(highest.map_or(commitment.counter, |value| value.max(commitment.counter)));
        }
        for encrypted in versions
            .versions
            .iter()
            .filter_map(|version| version.version_metadata_encrypted.as_deref())
        {
            if let Some(commitment) = decrypt_file_metadata(session.master_key(), file_id, encrypted)?.version {
                highest = Some(highest.map_or(commitment.counter, |value| value.max(commitment.counter)));
            }
        }

        let (sealed, counter) = match restored.and_then(|metadata| metadata.version.map(|version| (metadata, version)))
        {
            Some((restored, restored_version)) => {
                let counter = highest
                    .unwrap_or(restored_version.counter)
                    .checked_add(1)
                    .ok_or(FileServiceError::InvalidRecord)?;
                let commitment = VersionCommitment::new(restored_version.version_id, counter)?;
                let key = derive_file_key(session.master_key(), file_id.as_bytes());
                let sealed = encrypt_name_for_version(
                    &key,
                    &current.name,
                    current.mime_type.as_deref(),
                    restored.chunk_format,
                    commitment,
                )?;
                (Some(sealed), Some(counter))
            }
            None if current.version.is_none() && remembered.is_none() => (None, None),
            None => return Err(FileServiceError::InvalidRecord),
        };
        self.execute(
            &api::restore_version(file_id, version_id),
            &api::RestoreVersionRequest {
                name_encrypted: sealed.clone(),
                version_metadata_encrypted: sealed,
            },
        )
        .await?;
        if let Some(counter) = counter {
            store
                .lock()
                .map_err(|_| FileServiceError::InvalidRecord)?
                .observe_file_version(file_id, counter)
                .map_err(|_| FileServiceError::InvalidRecord)?;
        }
        Ok(VersionRestoreResult { counter })
    }

    pub async fn storage_usage(&self) -> Result<api::StorageUsage, ClientError> {
        self.person_call(crate::LockedAction::ViewStatus)?;
        self.storage_usage_inner().await
    }

    pub(crate) async fn storage_usage_inner(&self) -> Result<api::StorageUsage, ClientError> {
        self.execute(&api::usage(), &()).await
    }
}

fn open_record(session: &Session, entry: FileEntry) -> Result<FileRecord, FileServiceError> {
    let encrypted = entry.name_encrypted.as_deref().ok_or(FileServiceError::InvalidRecord)?;
    let metadata = session.open_name(&entry.id, encrypted)?;
    let managed_by = entry.extra.get("managed_by").and_then(Value::as_str).map(str::to_owned);
    let storage_country = entry
        .extra
        .get("storage_location")
        .and_then(Value::as_object)
        .and_then(|location| location.get("country"))
        .and_then(Value::as_str)
        .map(str::to_owned);
    Ok(FileRecord {
        id: entry.id.clone(),
        parent_id: entry.parent_id.clone(),
        name: metadata.name,
        mime_type: metadata.mime_type,
        is_folder: entry.is_folder,
        is_trashed: entry.is_trashed,
        size_bytes: entry.size_bytes,
        managed_by,
        storage_country,
        wire: entry,
    })
}

fn refuse_managed(entry: &FileEntry) -> Result<(), FileServiceError> {
    if entry.extra.get("managed_by").is_some_and(|value| !value.is_null()) {
        return Err(FileServiceError::ManagedByService {
            code: SYSTEM_FOLDER_MANAGED_CODE,
            message: SYSTEM_FOLDER_MANAGED_MESSAGE,
        });
    }
    Ok(())
}

impl From<GuardError> for FileServiceError {
    fn from(error: GuardError) -> Self {
        match error {
            GuardError::Refused(protected) => Self::Protected(protected),
            // A parent loop or an over-deep tree is a broken server answer.
            GuardError::Unknown => Self::InvalidRecord,
            GuardError::Client(error) => map_client_error(error),
        }
    }
}

fn map_client_error(error: ClientError) -> FileServiceError {
    if matches!(
        &error,
        ClientError::Api(beebeeb_api::ApiError::Server(server))
            if server.is_code(SYSTEM_FOLDER_MANAGED_CODE)
    ) {
        FileServiceError::ManagedByService {
            code: SYSTEM_FOLDER_MANAGED_CODE,
            message: SYSTEM_FOLDER_MANAGED_MESSAGE,
        }
    } else {
        FileServiceError::Client(error)
    }
}

fn string_array(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect()
}

fn bulk_result(value: &Value, completed: &str, already: &str, refused: &str) -> BulkFileResult {
    let refused = value
        .get(refused)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|item| item.as_str().or_else(|| item.get("id").and_then(Value::as_str)))
        .map(str::to_owned)
        .collect();
    BulkFileResult {
        completed: string_array(value.get(completed)),
        already_done: string_array(value.get(already)),
        missing: string_array(value.get("missing")),
        refused,
    }
}
