use std::{
    collections::HashSet,
    io::Write,
    ops::Range,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

use beebeeb_core::{
    chunk_stream::{
        ChunkDecryptor, ExpectedChunkFormat, VersionCounterStatus, check_version_counter, open_version_chunk,
    },
    direct_transfer::{Outcome, PinnedRetry, RetryDecision},
    download::{DownloadFailure, checked_frame_size_with_budget},
    encrypt::{NameMetadata, decrypt_file_metadata},
    kdf::{FileKey, derive_file_key},
    path_safety::{Rules, TrustedDirectory},
};
use beebeeb_store::{AssetClass, BoundedInsert, CacheEntry, Store, VersionObservation};
use beebeeb_types::limits::MemoryBudget;
use tokio::sync::broadcast;

use crate::{Client, ClientError, EngineEvent, EngineEvents, SessionKey};

pub use beebeeb_transfer::{DownloadOutcome, download};

#[derive(Debug, Clone)]
pub struct DownloadFile {
    pub file_id: String,
    pub name_encrypted: String,
    pub size_bytes: u64,
    pub chunk_size_bytes: u64,
    pub chunk_count: u32,
    pub object_version_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DownloadEvent {
    Started {
        file_id: String,
    },
    Progress {
        file_id: String,
        chunks_done: u32,
        chunk_count: u32,
    },
    Ready {
        file_id: String,
        path: PathBuf,
    },
    Cancelled {
        file_id: String,
    },
    HandOff {
        file_id: String,
        frame_size: u64,
        context_limit: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DownloadResult {
    Ready(PathBuf),
    Saved,
    HandOff { frame_size: u64, context_limit: u64 },
}

#[derive(Debug, thiserror::Error)]
pub enum DownloadServiceError {
    #[error("download state is unavailable")]
    State,
    #[error("the download was cancelled")]
    Cancelled,
    #[error("the downloaded content was truncated or unauthentic")]
    Truncated,
    #[error("an older file version was observed")]
    VersionRollback,
    #[error("protected file metadata has no version commitment")]
    MissingVersionCommitment,
    #[error("the download description is invalid")]
    InvalidDescription,
    #[error("the valid file needs a less constrained execution context")]
    HandOff { frame_size: u64, context_limit: u64 },
    #[error("publishing the downloaded file failed")]
    Publish,
    #[error(transparent)]
    Client(#[from] ClientError),
}

pub struct DownloadService {
    client: Arc<Client>,
    store: Arc<Mutex<Store>>,
    cache_root: PathBuf,
    budget: MemoryBudget,
    cancelled: Mutex<HashSet<String>>,
    events: broadcast::Sender<DownloadEvent>,
    engine_events: EngineEvents,
}

impl DownloadService {
    pub fn new(
        client: Arc<Client>,
        store: Arc<Mutex<Store>>,
        cache_root: impl Into<PathBuf>,
        cache_limit_bytes: u64,
        budget: MemoryBudget,
    ) -> Result<Self, DownloadServiceError> {
        let cache_root = cache_root.into();
        std::fs::create_dir_all(&cache_root).map_err(|_| DownloadServiceError::State)?;
        store
            .lock()
            .map_err(|_| DownloadServiceError::State)?
            .set_asset_limit(AssetClass::Cache, cache_limit_bytes)
            .map_err(|_| DownloadServiceError::State)?;
        let (events, _) = broadcast::channel(64);
        let engine_events = client.events();
        Ok(Self {
            client,
            store,
            cache_root,
            budget,
            cancelled: Mutex::new(HashSet::new()),
            events,
            engine_events,
        })
    }

    #[cfg(test)]
    pub(crate) fn new_for_test(
        client: Arc<Client>,
        store: Arc<Mutex<Store>>,
        master_key: Arc<beebeeb_core::kdf::MasterKey>,
        cache_root: impl Into<PathBuf>,
        cache_limit_bytes: u64,
        budget: MemoryBudget,
    ) -> Result<Self, DownloadServiceError> {
        client.set_session_key_for_test(master_key)?;
        Self::new(client, store, cache_root, cache_limit_bytes, budget)
    }

    pub fn observe(&self) -> broadcast::Receiver<DownloadEvent> {
        self.events.subscribe()
    }

    pub fn cancel(&self, file_id: &str) -> Result<(), DownloadServiceError> {
        self.cancelled
            .lock()
            .map_err(|_| DownloadServiceError::State)?
            .insert(file_id.to_owned());
        Ok(())
    }

    pub async fn open(&self, file: &DownloadFile, now_ms: i64) -> Result<DownloadResult, DownloadServiceError> {
        let session_key = self.client.session_key()?;
        let metadata = self.metadata(file, &session_key)?;
        self.check_counter_before_authentication(file, &metadata)?;
        let (cache_key, version_id) = cache_identity(file, &metadata);
        let cached = {
            self.store
                .lock()
                .map_err(|_| DownloadServiceError::State)?
                .cache_entry(AssetClass::Cache, &cache_key)
                .map_err(|_| DownloadServiceError::State)?
        };
        if let Some(entry) = cached {
            let path = PathBuf::from(&entry.path);
            if path.is_file() {
                if !session_key.is_current(&self.client) {
                    return Err(ClientError::StaleAccount.into());
                }
                self.store
                    .lock()
                    .map_err(|_| DownloadServiceError::State)?
                    .touch_cache_entry(AssetClass::Cache, &cache_key, now_ms)
                    .map_err(|_| DownloadServiceError::State)?;
                self.observe_authenticated_counter(file, &metadata)?;
                return Ok(DownloadResult::Ready(path));
            }
        }
        let directory = TrustedDirectory::open(&self.cache_root).map_err(|_| DownloadServiceError::Publish)?;
        let name = format!("{}-{}.bbcache", file.file_id, cache_suffix(&version_id));
        let outcome = self
            .save_internal(
                file,
                &metadata,
                &session_key,
                &directory,
                &name,
                Some(self.cache_root.join(&name)),
            )
            .await?;
        let DownloadResult::Ready(path) = outcome else {
            return Ok(outcome);
        };
        let entry = CacheEntry {
            key: cache_key,
            file_id: Some(file.file_id.clone()),
            version_id: Some(version_id),
            path: path.to_string_lossy().into_owned(),
            size_bytes: std::fs::metadata(&path).map_err(|_| DownloadServiceError::State)?.len(),
            last_accessed: now_ms,
        };
        if !session_key.is_current(&self.client) {
            let _ = std::fs::remove_file(&path);
            return Err(ClientError::StaleAccount.into());
        }
        let evicted = self
            .store
            .lock()
            .map_err(|_| DownloadServiceError::State)?
            .put_cache_entry(AssetClass::Cache, &entry, BoundedInsert::EvictOldest)
            .map_err(|_| DownloadServiceError::State)?;
        if !evicted.accepted {
            let _ = std::fs::remove_file(&path);
            return Err(DownloadServiceError::Publish);
        }
        for old in evicted.paths_to_remove {
            let _ = std::fs::remove_file(old);
        }
        Ok(DownloadResult::Ready(path))
    }

    pub async fn save_to(
        &self,
        file: &DownloadFile,
        directory: &TrustedDirectory,
        output_name: &str,
    ) -> Result<DownloadResult, DownloadServiceError> {
        let session_key = self.client.session_key()?;
        let metadata = self.metadata(file, &session_key)?;
        self.save_internal(file, &metadata, &session_key, directory, output_name, None)
            .await
    }

    pub async fn video_range(&self, file: &DownloadFile, range: Range<u64>) -> Result<Vec<u8>, DownloadServiceError> {
        validate_description(file)?;
        if range.start > range.end || range.end > file.size_bytes {
            return Err(DownloadServiceError::InvalidDescription);
        }
        if range.is_empty() {
            return Ok(Vec::new());
        }
        if file.chunk_size_bytes == 0
            || file.chunk_count == 0
            || range.end.saturating_sub(range.start) > self.budget.archive_output_bytes
        {
            return Err(DownloadServiceError::InvalidDescription);
        }
        let session_key = self.client.session_key()?;
        let metadata = self.metadata(file, &session_key)?;
        self.check_counter_before_authentication(file, &metadata)?;
        if metadata.chunk_format != ExpectedChunkFormat::V2 || metadata.version.is_none() {
            return Err(DownloadServiceError::InvalidDescription);
        }
        if let Some(DownloadResult::HandOff {
            frame_size,
            context_limit,
        }) = self.check_budget(file)?
        {
            return Err(DownloadServiceError::HandOff {
                frame_size,
                context_limit,
            });
        }
        let first =
            u32::try_from(range.start / file.chunk_size_bytes).map_err(|_| DownloadServiceError::InvalidDescription)?;
        let last = u32::try_from((range.end - 1) / file.chunk_size_bytes)
            .map_err(|_| DownloadServiceError::InvalidDescription)?;
        let file_key = derive_file_key(session_key.master_key(), file.file_id.as_bytes());
        let mut selected = Vec::new();
        for index in first..=last {
            let expected_frame = share_frame_len(index, file.chunk_count, file.size_bytes, file.chunk_size_bytes)?;
            let frame = self
                .fetch_chunk(file, index, expected_frame, session_key.generation())
                .await?;
            if frame.len() as u64 != expected_frame {
                return Err(DownloadServiceError::Truncated);
            }
            let plain = open_version_chunk(
                &file_key,
                &file.file_id,
                &metadata,
                index,
                index + 1 == file.chunk_count,
                &frame,
            )
            .map_err(|_| DownloadServiceError::Truncated)?;
            let expected_plain = expected_frame
                .checked_sub(28)
                .ok_or(DownloadServiceError::InvalidDescription)?;
            if plain.len() as u64 != expected_plain {
                return Err(DownloadServiceError::Truncated);
            }
            selected.extend_from_slice(&plain);
        }
        let start_offset = usize::try_from(range.start % file.chunk_size_bytes)
            .map_err(|_| DownloadServiceError::InvalidDescription)?;
        let wanted = usize::try_from(range.end - range.start).map_err(|_| DownloadServiceError::InvalidDescription)?;
        let end = start_offset
            .checked_add(wanted)
            .ok_or(DownloadServiceError::InvalidDescription)?;
        if end > selected.len() {
            return Err(DownloadServiceError::Truncated);
        }
        if !session_key.is_current(&self.client) {
            return Err(ClientError::StaleAccount.into());
        }
        self.observe_authenticated_counter(file, &metadata)?;
        Ok(selected[start_offset..end].to_vec())
    }

    /// Account-free share-view download. The caller supplies the opaque share
    /// file key and the metadata already authenticated under that key.
    #[allow(clippy::too_many_arguments)]
    pub async fn share_view_download(
        &self,
        token: &str,
        passphrase: Option<&str>,
        file_id: &str,
        file_key: &FileKey,
        metadata: &NameMetadata,
        chunk_count: u32,
        size_bytes: u64,
        chunk_size_bytes: u64,
        directory: &TrustedDirectory,
        output_name: &str,
    ) -> Result<DownloadResult, DownloadServiceError> {
        let description = DownloadFile {
            file_id: file_id.to_owned(),
            name_encrypted: String::new(),
            size_bytes,
            chunk_size_bytes,
            chunk_count,
            object_version_id: String::new(),
        };
        if let Some(outcome) = self.check_budget(&description)? {
            return Ok(outcome);
        }
        let (pending, mut output) = directory
            .begin_publish(output_name, Rules::Host)
            .map_err(|_| DownloadServiceError::Publish)?;
        let key = FileKey::from_bytes(*file_key.as_bytes());
        let mut decryptor =
            ChunkDecryptor::for_version_with_file_key(key, file_id, metadata.chunk_format, metadata.version);
        let expected_ciphertext = size_bytes
            .checked_add(
                u64::from(chunk_count)
                    .checked_mul(28)
                    .ok_or(DownloadServiceError::InvalidDescription)?,
            )
            .ok_or(DownloadServiceError::InvalidDescription)?;
        let mut written = 0u64;
        let manifest = self
            .client
            .execute(&beebeeb_api::routes::shares::chunk_manifest(token, passphrase), &())
            .await;
        if let Ok(manifest) = manifest {
            if manifest.chunk_count != chunk_count
                || manifest.size_bytes != size_bytes
                || manifest.chunks.len() != chunk_count as usize
            {
                return Err(DownloadServiceError::InvalidDescription);
            }
            for index in 0..chunk_count {
                let description = manifest
                    .chunks
                    .get(index as usize)
                    .ok_or(DownloadServiceError::InvalidDescription)?;
                let expected = share_frame_len(index, chunk_count, size_bytes, chunk_size_bytes)?;
                if description.index != index || description.size_bytes != expected {
                    return Err(DownloadServiceError::InvalidDescription);
                }
                let frame = self
                    .client
                    .execute_raw(
                        &beebeeb_api::routes::shares::chunk(token, index, &manifest.download_token, passphrase),
                        &(),
                    )
                    .await?;
                if frame.len() as u64 != expected {
                    return Err(DownloadServiceError::Truncated);
                }
                let plain = decryptor
                    .push_frame(&frame)
                    .map_err(|_| DownloadServiceError::Truncated)?;
                output
                    .write_all(&plain.data)
                    .map_err(|_| DownloadServiceError::Publish)?;
                written = written
                    .checked_add(plain.data.len() as u64)
                    .ok_or(DownloadServiceError::InvalidDescription)?;
            }
        } else {
            let error = manifest.unwrap_err();
            const WHOLE_FILE_LIMIT: u64 = 256 * 1024 * 1024 + 28;
            if !is_not_found(&error) || expected_ciphertext > WHOLE_FILE_LIMIT {
                return Err(DownloadServiceError::Client(error));
            }
            let encrypted = self
                .client
                .execute_raw(&beebeeb_api::routes::downloads::share_file(token), &())
                .await?;
            if encrypted.len() as u64 != expected_ciphertext {
                return Err(DownloadServiceError::Truncated);
            }
            let mut offset = 0usize;
            for index in 0..chunk_count {
                let frame_len = usize::try_from(share_frame_len(index, chunk_count, size_bytes, chunk_size_bytes)?)
                    .map_err(|_| DownloadServiceError::InvalidDescription)?;
                let end = offset
                    .checked_add(frame_len)
                    .ok_or(DownloadServiceError::InvalidDescription)?;
                let frame = encrypted.get(offset..end).ok_or(DownloadServiceError::Truncated)?;
                let plain = decryptor
                    .push_frame(frame)
                    .map_err(|_| DownloadServiceError::Truncated)?;
                output
                    .write_all(&plain.data)
                    .map_err(|_| DownloadServiceError::Publish)?;
                written = written
                    .checked_add(plain.data.len() as u64)
                    .ok_or(DownloadServiceError::InvalidDescription)?;
                offset = end;
            }
        }
        decryptor.finish().map_err(|_| DownloadServiceError::Truncated)?;
        if written != size_bytes {
            return Err(DownloadServiceError::Truncated);
        }
        output.sync_all().map_err(|_| DownloadServiceError::Publish)?;
        drop(output);
        pending.commit().map_err(|_| DownloadServiceError::Publish)?;
        Ok(DownloadResult::Saved)
    }

    pub fn clear_cache(&self) -> Result<(), DownloadServiceError> {
        let paths = self
            .store
            .lock()
            .map_err(|_| DownloadServiceError::State)?
            .clear_cache_index(AssetClass::Cache)
            .map_err(|_| DownloadServiceError::State)?;
        for path in paths {
            let _ = std::fs::remove_file(path);
        }
        Ok(())
    }

    pub fn observe_file_version(
        &self,
        file_id: &str,
        counter: u64,
    ) -> Result<VersionObservation, DownloadServiceError> {
        let observed = self
            .store
            .lock()
            .map_err(|_| DownloadServiceError::State)?
            .observe_file_version(file_id, counter)
            .map_err(|_| DownloadServiceError::State)?;
        if let VersionObservation::Older { highest } = observed {
            self.engine_events.emit(EngineEvent::VersionRollback {
                file_id: file_id.to_owned(),
                observed: counter,
                highest,
            });
        }
        Ok(observed)
    }

    async fn save_internal(
        &self,
        file: &DownloadFile,
        metadata: &NameMetadata,
        session_key: &SessionKey,
        directory: &TrustedDirectory,
        output_name: &str,
        published_path: Option<PathBuf>,
    ) -> Result<DownloadResult, DownloadServiceError> {
        if let Some(outcome) = self.check_budget(file)? {
            return Ok(outcome);
        }
        self.check_counter_before_authentication(file, metadata)?;
        self.cancelled
            .lock()
            .map_err(|_| DownloadServiceError::State)?
            .remove(&file.file_id);
        let (pending, mut output) = directory
            .begin_publish(output_name, Rules::Host)
            .map_err(|_| DownloadServiceError::Publish)?;
        self.emit(DownloadEvent::Started {
            file_id: file.file_id.clone(),
        });
        let mut decryptor = ChunkDecryptor::for_current_version(session_key.master_key(), &file.file_id, metadata);
        let mut written = 0u64;
        for index in 0..file.chunk_count {
            if self
                .cancelled
                .lock()
                .map_err(|_| DownloadServiceError::State)?
                .contains(&file.file_id)
            {
                self.emit(DownloadEvent::Cancelled {
                    file_id: file.file_id.clone(),
                });
                return Err(DownloadServiceError::Cancelled);
            }
            let expected_frame = share_frame_len(index, file.chunk_count, file.size_bytes, file.chunk_size_bytes)?;
            let frame = self
                .fetch_chunk(file, index, expected_frame, session_key.generation())
                .await?;
            if frame.len() as u64 != expected_frame {
                return Err(DownloadServiceError::Truncated);
            }
            let plain = decryptor
                .push_frame(&frame)
                .map_err(|_| DownloadServiceError::Truncated)?;
            output
                .write_all(&plain.data)
                .map_err(|_| DownloadServiceError::Publish)?;
            written = written
                .checked_add(plain.data.len() as u64)
                .ok_or(DownloadServiceError::InvalidDescription)?;
            self.emit(DownloadEvent::Progress {
                file_id: file.file_id.clone(),
                chunks_done: index + 1,
                chunk_count: file.chunk_count,
            });
        }
        decryptor.finish().map_err(|_| DownloadServiceError::Truncated)?;
        if written != file.size_bytes {
            return Err(DownloadServiceError::Truncated);
        }
        if !session_key.is_current(&self.client) {
            return Err(ClientError::StaleAccount.into());
        }
        self.observe_authenticated_counter(file, metadata)?;
        output.sync_all().map_err(|_| DownloadServiceError::Publish)?;
        drop(output);
        pending.commit().map_err(|_| DownloadServiceError::Publish)?;
        match published_path {
            Some(path) => {
                self.emit(DownloadEvent::Ready {
                    file_id: file.file_id.clone(),
                    path: path.clone(),
                });
                Ok(DownloadResult::Ready(path))
            }
            None => Ok(DownloadResult::Saved),
        }
    }

    fn check_budget(&self, file: &DownloadFile) -> Result<Option<DownloadResult>, DownloadServiceError> {
        validate_description(file)?;
        match checked_frame_size_with_budget(
            file.size_bytes,
            file.chunk_count,
            Some(file.chunk_size_bytes),
            self.budget,
        ) {
            Ok(_) => Ok(None),
            Err(DownloadFailure::TooLargeForContext {
                frame_size,
                context_limit,
            }) => {
                self.emit(DownloadEvent::HandOff {
                    file_id: file.file_id.clone(),
                    frame_size,
                    context_limit,
                });
                self.engine_events.emit(EngineEvent::HandOff {
                    ticket: file.file_id.clone(),
                });
                Ok(Some(DownloadResult::HandOff {
                    frame_size,
                    context_limit,
                }))
            }
            Err(_) => Err(DownloadServiceError::InvalidDescription),
        }
    }

    fn metadata(&self, file: &DownloadFile, session_key: &SessionKey) -> Result<NameMetadata, DownloadServiceError> {
        let metadata = decrypt_file_metadata(session_key.master_key(), &file.file_id, &file.name_encrypted)
            .map_err(|_| DownloadServiceError::InvalidDescription)?;
        Ok(metadata)
    }

    fn check_counter_before_authentication(
        &self,
        file: &DownloadFile,
        metadata: &NameMetadata,
    ) -> Result<(), DownloadServiceError> {
        let highest = self
            .store
            .lock()
            .map_err(|_| DownloadServiceError::State)?
            .highest_file_version(&file.file_id)
            .map_err(|_| DownloadServiceError::State)?;
        let Some(version) = metadata.version else {
            if let Some(highest) = highest {
                self.engine_events.emit(EngineEvent::VersionRollback {
                    file_id: file.file_id.clone(),
                    observed: 0,
                    highest,
                });
                return Err(DownloadServiceError::VersionRollback);
            }
            return Ok(());
        };
        if check_version_counter(version.counter, highest) == VersionCounterStatus::Rollback {
            self.engine_events.emit(EngineEvent::VersionRollback {
                file_id: file.file_id.clone(),
                observed: version.counter,
                highest: highest.unwrap_or(version.counter),
            });
            return Err(DownloadServiceError::VersionRollback);
        }
        Ok(())
    }

    fn observe_authenticated_counter(
        &self,
        file: &DownloadFile,
        metadata: &NameMetadata,
    ) -> Result<(), DownloadServiceError> {
        let Some(version) = metadata.version else {
            return Ok(());
        };
        if matches!(
            self.observe_file_version(&file.file_id, version.counter)?,
            VersionObservation::Older { .. }
        ) {
            return Err(DownloadServiceError::VersionRollback);
        }
        Ok(())
    }

    async fn fetch_chunk(
        &self,
        file: &DownloadFile,
        index: u32,
        expected_frame: u64,
        generation: u64,
    ) -> Result<Vec<u8>, DownloadServiceError> {
        let max_bytes = usize::try_from(expected_frame).map_err(|_| DownloadServiceError::InvalidDescription)?;
        let retry = PinnedRetry::default();
        let mut waited = Duration::ZERO;
        let mut attempt = 1;
        loop {
            match self
                .client
                .execute_raw_bounded_for_generation(
                    &beebeeb_api::routes::downloads::chunk(&file.file_id, index, &file.object_version_id),
                    &(),
                    max_bytes,
                    generation,
                )
                .await
            {
                Ok(frame) => return Ok(frame),
                Err(error) => {
                    let outcome = retry_outcome(&error);
                    match retry.decide(attempt, waited, &outcome) {
                        RetryDecision::Wait(delay) => {
                            tokio::time::sleep(delay).await;
                            waited = waited.saturating_add(delay);
                            attempt = attempt.saturating_add(1);
                        }
                        RetryDecision::GiveUp => return Err(DownloadServiceError::Client(error)),
                    }
                }
            }
        }
    }

    fn emit(&self, event: DownloadEvent) {
        let _ = self.events.send(event);
    }
}

fn cache_identity(file: &DownloadFile, metadata: &NameMetadata) -> (String, Vec<u8>) {
    let version_id = metadata
        .version
        .map(|version| version.version_id.to_vec())
        .unwrap_or_else(|| beebeeb_core::hash::sha256(file.name_encrypted.as_bytes()));
    let key = format!("{}:{}", file.file_id, cache_suffix(&version_id));
    (key, version_id)
}

fn cache_suffix(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn retry_outcome(error: &ClientError) -> Outcome {
    match error {
        ClientError::Transport(crate::TransportError::Network) => Outcome::Retry,
        ClientError::Transport(_) => Outcome::ApiForThisFile,
        ClientError::Api(beebeeb_api::ApiError::Server(server)) if server.status == 429 || server.status >= 500 => {
            Outcome::Retry
        }
        _ => Outcome::ApiForThisFile,
    }
}

fn validate_description(file: &DownloadFile) -> Result<(), DownloadServiceError> {
    if file.chunk_size_bytes == 0 || file.chunk_count == 0 {
        return Err(DownloadServiceError::InvalidDescription);
    }
    let expected = if file.size_bytes == 0 {
        1
    } else {
        file.size_bytes
            .checked_sub(1)
            .and_then(|value| value.checked_div(file.chunk_size_bytes))
            .and_then(|value| value.checked_add(1))
            .ok_or(DownloadServiceError::InvalidDescription)?
    };
    if expected != u64::from(file.chunk_count) {
        return Err(DownloadServiceError::InvalidDescription);
    }
    Ok(())
}

fn share_frame_len(
    index: u32,
    chunk_count: u32,
    size_bytes: u64,
    chunk_size_bytes: u64,
) -> Result<u64, DownloadServiceError> {
    let plain_len = if index + 1 == chunk_count {
        size_bytes
            .checked_sub(
                u64::from(index)
                    .checked_mul(chunk_size_bytes)
                    .ok_or(DownloadServiceError::InvalidDescription)?,
            )
            .ok_or(DownloadServiceError::InvalidDescription)?
    } else {
        chunk_size_bytes
    };
    plain_len
        .checked_add(28)
        .ok_or(DownloadServiceError::InvalidDescription)
}

fn is_not_found(error: &ClientError) -> bool {
    matches!(error, ClientError::Api(beebeeb_api::ApiError::Server(server)) if server.status == 404)
}

pub fn observe_version_counter(
    events: &EngineEvents,
    file_id: &str,
    observed: u64,
    remembered_highest: Option<u64>,
) -> VersionCounterStatus {
    let status = check_version_counter(observed, remembered_highest);
    if status == VersionCounterStatus::Rollback {
        events.emit(EngineEvent::VersionRollback {
            file_id: file_id.to_owned(),
            observed,
            highest: remembered_highest.unwrap_or(observed),
        });
    }
    status
}
