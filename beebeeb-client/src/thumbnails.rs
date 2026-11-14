//! Thumbnail policy, persistence and generation. Pixel decoding/encoding is
//! the only platform operation; sealing, ordering, fallback and limits stay here.

use std::{
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

#[cfg(test)]
use beebeeb_core::kdf::MasterKey;
use beebeeb_core::{
    encrypt::decrypt_file_metadata,
    kdf::derive_file_key,
    path_safety::{Rules, TrustedDirectory},
    thumbnail::{BudgetVerdict, LadderStep, Platform, ThumbnailFormat, ThumbnailPolicy},
};
use beebeeb_store::{AssetClass, BoundedInsert, CacheEntry, Store};
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

use crate::uploads::{NetworkKind, TransferRule};
use crate::{Client, ClientError};

#[allow(deprecated)]
use beebeeb_core::encrypt::encrypt_thumbnail_for;

pub use beebeeb_core::encrypt::{
    decrypt_thumbnail_for_metadata, encrypt_thumbnail_for_new_item, encrypt_thumbnail_for_target,
};
pub use beebeeb_core::thumbnail::{ThumbnailConfig, ThumbnailVariant, resize_for_thumbnail};

const THUMBNAIL_KIND: &str = "thumbnail-v1";
const MAX_ATTEMPTS: u32 = 4;
const LEASE_MS: i64 = 5 * 60 * 1000;

pub trait ImageCodec: Send + Sync {
    fn encode(
        &self,
        source_path: &Path,
        max_dimension: u32,
        quality: f32,
        format: ThumbnailFormat,
    ) -> Result<Vec<u8>, ImageCodecError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ImageCodecError {
    #[error("the image cannot be decoded")]
    Decode,
    #[error("the image cannot be encoded")]
    Encode,
}

#[derive(Debug, Clone)]
pub struct ThumbnailJob {
    pub file_id: String,
    pub name_encrypted: String,
    pub source_path: PathBuf,
    pub variant: ThumbnailVariant,
    pub created_at_ms: i64,
    pub wifi_only: bool,
}

#[derive(Debug, Clone)]
pub struct FirstSyncThumbnail {
    pub file_id: String,
    pub name_encrypted: String,
    pub variant: ThumbnailVariant,
    pub created_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ThumbnailEvent {
    Queued {
        id: i64,
        file_id: String,
    },
    Ready {
        file_id: String,
        variant: ThumbnailVariant,
        path: PathBuf,
    },
    Retry {
        id: i64,
    },
    Failed {
        id: i64,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum ThumbnailServiceError {
    #[error("thumbnail state is unavailable")]
    State,
    #[error("thumbnail generation failed")]
    Generation,
    #[error("thumbnail authentication failed")]
    Authentication,
    #[error("the thumbnail is not available")]
    NotFound,
    #[error(transparent)]
    Client(#[from] ClientError),
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredJob {
    file_id: String,
    name_encrypted: String,
    source_path: PathBuf,
    variant: String,
    created_at_ms: i64,
    wifi_only: bool,
}

pub struct ThumbnailService {
    client: Arc<Client>,
    store: Arc<Mutex<Store>>,
    codec: Arc<dyn ImageCodec>,
    cache_root: PathBuf,
    platform: Platform,
    events: broadcast::Sender<ThumbnailEvent>,
}

impl ThumbnailService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        client: Arc<Client>,
        store: Arc<Mutex<Store>>,
        codec: Arc<dyn ImageCodec>,
        cache_root: impl Into<PathBuf>,
        cache_limit_bytes: u64,
        platform: Platform,
    ) -> Result<Self, ThumbnailServiceError> {
        let cache_root = cache_root.into();
        std::fs::create_dir_all(&cache_root).map_err(|_| ThumbnailServiceError::State)?;
        store
            .lock()
            .map_err(|_| ThumbnailServiceError::State)?
            .set_asset_limit(AssetClass::Thumbnail, cache_limit_bytes)
            .map_err(|_| ThumbnailServiceError::State)?;
        let (events, _) = broadcast::channel(64);
        Ok(Self {
            client,
            store,
            codec,
            cache_root,
            platform,
            events,
        })
    }

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_for_test(
        client: Arc<Client>,
        store: Arc<Mutex<Store>>,
        master_key: Arc<MasterKey>,
        codec: Arc<dyn ImageCodec>,
        cache_root: impl Into<PathBuf>,
        cache_limit_bytes: u64,
        platform: Platform,
    ) -> Result<Self, ThumbnailServiceError> {
        client.set_session_key_for_test(master_key)?;
        Self::new(client, store, codec, cache_root, cache_limit_bytes, platform)
    }

    pub fn observe(&self) -> broadcast::Receiver<ThumbnailEvent> {
        self.events.subscribe()
    }

    pub fn enqueue_generation(&self, job: ThumbnailJob, now_ms: i64) -> Result<i64, ThumbnailServiceError> {
        let stored = StoredJob {
            file_id: job.file_id.clone(),
            name_encrypted: job.name_encrypted,
            source_path: job.source_path,
            variant: job.variant.as_str().into(),
            created_at_ms: job.created_at_ms,
            wifi_only: job.wifi_only,
        };
        let payload = serde_json::to_vec(&stored).map_err(|_| ThumbnailServiceError::State)?;
        let id = self
            .store
            .lock()
            .map_err(|_| ThumbnailServiceError::State)?
            .enqueue_transfer(THUMBNAIL_KIND, &payload, MAX_ATTEMPTS, now_ms)
            .map_err(|_| ThumbnailServiceError::State)?;
        self.emit(ThumbnailEvent::Queued {
            id,
            file_id: job.file_id,
        });
        Ok(id)
    }

    /// Newest-first first-sync scheduling, bounded before any network work.
    pub fn enqueue_first_sync(
        &self,
        mut candidates: Vec<FirstSyncThumbnail>,
        limit_bytes: u64,
        now_ms: i64,
    ) -> Result<Vec<i64>, ThumbnailServiceError> {
        candidates.sort_by(|a, b| {
            b.created_at_ms
                .cmp(&a.created_at_ms)
                .then_with(|| a.file_id.cmp(&b.file_id))
        });
        let mut used = 0u64;
        let mut ids = Vec::new();
        for candidate in candidates {
            let estimated_bytes = u64::try_from(ThumbnailPolicy::for_variant(candidate.variant).config.target_bytes)
                .map_err(|_| ThumbnailServiceError::State)?;
            let Some(next) = used.checked_add(estimated_bytes) else {
                break;
            };
            if next > limit_bytes {
                break;
            }
            used = next;
            let stored = StoredJob {
                file_id: candidate.file_id.clone(),
                name_encrypted: candidate.name_encrypted,
                source_path: PathBuf::new(),
                variant: candidate.variant.as_str().into(),
                created_at_ms: candidate.created_at_ms,
                wifi_only: true,
            };
            let payload = serde_json::to_vec(&stored).map_err(|_| ThumbnailServiceError::State)?;
            let id = self
                .store
                .lock()
                .map_err(|_| ThumbnailServiceError::State)?
                .enqueue_transfer("thumbnail-fetch-v1", &payload, MAX_ATTEMPTS, now_ms)
                .map_err(|_| ThumbnailServiceError::State)?;
            ids.push(id);
        }
        Ok(ids)
    }

    pub async fn run_next(&self, network: NetworkKind, now_ms: i64) -> Result<Option<PathBuf>, ThumbnailServiceError> {
        self.client.work_call()?;
        let lease = now_ms.checked_add(LEASE_MS).ok_or(ThumbnailServiceError::State)?;
        let transfer = self
            .store
            .lock()
            .map_err(|_| ThumbnailServiceError::State)?
            .claim_transfer_kinds(THUMBNAIL_KIND, "thumbnail-fetch-v1", now_ms, lease)
            .map_err(|_| ThumbnailServiceError::State)?;
        let Some(transfer) = transfer else {
            return Ok(None);
        };
        let job: StoredJob = serde_json::from_slice(&transfer.payload).map_err(|_| ThumbnailServiceError::State)?;
        if !(TransferRule {
            wifi_only: job.wifi_only,
        })
        .allows(network)
        {
            self.store
                .lock()
                .map_err(|_| ThumbnailServiceError::State)?
                .release_transfer(transfer.id, now_ms)
                .map_err(|_| ThumbnailServiceError::State)?;
            return Ok(None);
        }
        let variant = parse_variant(&job.variant)?;
        let result = if transfer.kind == THUMBNAIL_KIND {
            self.generate_upload_and_cache(&job, variant, now_ms).await
        } else {
            self.fetch_and_cache(
                &job.file_id,
                &job.name_encrypted,
                variant,
                BoundedInsert::StopAtLimit,
                now_ms,
            )
            .await
        };
        match result {
            Ok(path) => {
                self.store
                    .lock()
                    .map_err(|_| ThumbnailServiceError::State)?
                    .mark_transfer_succeeded(transfer.id, now_ms)
                    .map_err(|_| ThumbnailServiceError::State)?;
                self.emit(ThumbnailEvent::Ready {
                    file_id: job.file_id,
                    variant,
                    path: path.clone(),
                });
                Ok(Some(path))
            }
            Err(error) => {
                let updated = self
                    .store
                    .lock()
                    .map_err(|_| ThumbnailServiceError::State)?
                    .record_transfer_failure(transfer.id, "thumbnail operation failed", now_ms)
                    .map_err(|_| ThumbnailServiceError::State)?;
                if updated.state == beebeeb_store::TransferState::Failed {
                    self.emit(ThumbnailEvent::Failed { id: transfer.id });
                } else {
                    self.emit(ThumbnailEvent::Retry { id: transfer.id });
                }
                Err(error)
            }
        }
    }

    pub async fn get(
        &self,
        file_id: &str,
        name_encrypted: &str,
        variant: ThumbnailVariant,
        now_ms: i64,
    ) -> Result<PathBuf, ThumbnailServiceError> {
        self.client.person_call(crate::LockedAction::ViewFiles)?;
        for fallback in fallback_order(variant) {
            let key = cache_key(file_id, *fallback);
            let entry = {
                self.store
                    .lock()
                    .map_err(|_| ThumbnailServiceError::State)?
                    .cache_entry(AssetClass::Thumbnail, &key)
                    .map_err(|_| ThumbnailServiceError::State)?
            };
            if let Some(entry) = entry {
                let path = PathBuf::from(&entry.path);
                if path.is_file() {
                    self.store
                        .lock()
                        .map_err(|_| ThumbnailServiceError::State)?
                        .touch_cache_entry(AssetClass::Thumbnail, &key, now_ms)
                        .map_err(|_| ThumbnailServiceError::State)?;
                    if *fallback != variant {
                        self.enqueue_requested_fetch(file_id, name_encrypted, variant, now_ms)?;
                    }
                    return Ok(path);
                }
            }
        }
        let mut last_error = ThumbnailServiceError::NotFound;
        for fallback in fallback_order(variant) {
            match self
                .fetch_and_cache(file_id, name_encrypted, *fallback, BoundedInsert::EvictOldest, now_ms)
                .await
            {
                Ok(path) => return Ok(path),
                Err(error) => last_error = error,
            }
        }
        Err(last_error)
    }

    fn enqueue_requested_fetch(
        &self,
        file_id: &str,
        name_encrypted: &str,
        variant: ThumbnailVariant,
        now_ms: i64,
    ) -> Result<(), ThumbnailServiceError> {
        let payload = serde_json::to_vec(&StoredJob {
            file_id: file_id.to_owned(),
            name_encrypted: name_encrypted.to_owned(),
            source_path: PathBuf::new(),
            variant: variant.as_str().into(),
            created_at_ms: now_ms,
            wifi_only: false,
        })
        .map_err(|_| ThumbnailServiceError::State)?;
        self.store
            .lock()
            .map_err(|_| ThumbnailServiceError::State)?
            .enqueue_transfer("thumbnail-fetch-v1", &payload, MAX_ATTEMPTS, now_ms)
            .map_err(|_| ThumbnailServiceError::State)?;
        Ok(())
    }

    pub fn clear(&self) -> Result<(), ThumbnailServiceError> {
        let paths = self
            .store
            .lock()
            .map_err(|_| ThumbnailServiceError::State)?
            .clear_cache_index(AssetClass::Thumbnail)
            .map_err(|_| ThumbnailServiceError::State)?;
        for path in paths {
            let _ = std::fs::remove_file(path);
        }
        Ok(())
    }

    pub fn sign_out(&self, now_ms: i64) -> Result<(), ThumbnailServiceError> {
        {
            let mut store = self.store.lock().map_err(|_| ThumbnailServiceError::State)?;
            let ids: Vec<i64> = store
                .transfers(None)
                .map_err(|_| ThumbnailServiceError::State)?
                .into_iter()
                .filter(|transfer| matches!(transfer.kind.as_str(), THUMBNAIL_KIND | "thumbnail-fetch-v1"))
                .map(|transfer| transfer.id)
                .collect();
            for id in ids {
                store
                    .cancel_transfer(id, now_ms)
                    .map_err(|_| ThumbnailServiceError::State)?;
            }
        }
        self.clear()
    }

    async fn generate_upload_and_cache(
        &self,
        job: &StoredJob,
        variant: ThumbnailVariant,
        now_ms: i64,
    ) -> Result<PathBuf, ThumbnailServiceError> {
        let session_key = self.client.held_key()?;
        let metadata = decrypt_file_metadata(session_key.master_key(), &job.file_id, &job.name_encrypted)
            .map_err(|_| ThumbnailServiceError::Authentication)?;
        let policy = ThumbnailPolicy::for_variant(variant);
        let format = policy.format_for(self.platform);
        let plain = encode_ladder(self.codec.as_ref(), &job.source_path, &policy, format)?;
        let file_key = derive_file_key(session_key.master_key(), job.file_id.as_bytes());
        #[allow(deprecated)]
        let sealed = encrypt_thumbnail_for(&file_key, &plain, metadata.chunk_format)
            .map_err(|_| ThumbnailServiceError::Authentication)?;
        self.client
            .execute_raw_for_generation(
                &beebeeb_api::routes::thumbnails::put(&job.file_id, api_variant(variant)),
                &sealed,
                session_key.generation(),
            )
            .await?;
        if !session_key.is_current(&self.client) {
            return Err(ClientError::StaleAccount.into());
        }
        self.cache_plaintext(&job.file_id, variant, &plain, BoundedInsert::EvictOldest, now_ms)
    }

    async fn fetch_and_cache(
        &self,
        file_id: &str,
        name_encrypted: &str,
        variant: ThumbnailVariant,
        mode: BoundedInsert,
        now_ms: i64,
    ) -> Result<PathBuf, ThumbnailServiceError> {
        let session_key = self.client.held_key()?;
        let metadata = decrypt_file_metadata(session_key.master_key(), file_id, name_encrypted)
            .map_err(|_| ThumbnailServiceError::Authentication)?;
        let sealed = self
            .client
            .execute_raw_for_generation(
                &beebeeb_api::routes::thumbnails::get(file_id, api_variant(variant)),
                &(),
                session_key.generation(),
            )
            .await?;
        if !session_key.is_current(&self.client) {
            return Err(ClientError::StaleAccount.into());
        }
        let file_key = derive_file_key(session_key.master_key(), file_id.as_bytes());
        let plain = decrypt_thumbnail_for_metadata(&file_key, &sealed, &metadata)
            .map_err(|_| ThumbnailServiceError::Authentication)?;
        self.cache_plaintext(file_id, variant, &plain, mode, now_ms)
    }

    fn cache_plaintext(
        &self,
        file_id: &str,
        variant: ThumbnailVariant,
        plain: &[u8],
        mode: BoundedInsert,
        now_ms: i64,
    ) -> Result<PathBuf, ThumbnailServiceError> {
        let directory = TrustedDirectory::open(&self.cache_root).map_err(|_| ThumbnailServiceError::State)?;
        let name = format!("{file_id}.{}.thumb", variant.as_str());
        directory
            .publish_bytes(&name, Rules::Host, plain)
            .map_err(|_| ThumbnailServiceError::State)?;
        let path = self.cache_root.join(&name);
        let entry = CacheEntry {
            key: cache_key(file_id, variant),
            file_id: None,
            version_id: None,
            path: path.to_string_lossy().into_owned(),
            size_bytes: plain.len() as u64,
            last_accessed: now_ms,
        };
        let result = self
            .store
            .lock()
            .map_err(|_| ThumbnailServiceError::State)?
            .put_cache_entry(AssetClass::Thumbnail, &entry, mode)
            .map_err(|_| ThumbnailServiceError::State)?;
        if !result.accepted {
            let _ = std::fs::remove_file(&path);
            return Err(ThumbnailServiceError::NotFound);
        }
        for old in result.paths_to_remove {
            let _ = std::fs::remove_file(old);
        }
        Ok(path)
    }

    fn emit(&self, event: ThumbnailEvent) {
        let _ = self.events.send(event);
    }
}

fn encode_ladder(
    codec: &dyn ImageCodec,
    source: &Path,
    policy: &ThumbnailPolicy,
    format: ThumbnailFormat,
) -> Result<Vec<u8>, ThumbnailServiceError> {
    let mut fallback = None;
    for LadderStep { max_dimension, quality } in &policy.config.ladder {
        let bytes = codec
            .encode(source, *max_dimension, *quality, format)
            .map_err(|_| ThumbnailServiceError::Generation)?;
        match policy.classify_size(bytes.len()) {
            BudgetVerdict::Target => return Ok(bytes),
            BudgetVerdict::Fallback if fallback.is_none() => fallback = Some(bytes),
            BudgetVerdict::Fallback | BudgetVerdict::Rejected => {}
        }
    }
    fallback.ok_or(ThumbnailServiceError::Generation)
}

fn parse_variant(value: &str) -> Result<ThumbnailVariant, ThumbnailServiceError> {
    match value {
        "small" => Ok(ThumbnailVariant::Small),
        "medium" => Ok(ThumbnailVariant::Medium),
        "large" => Ok(ThumbnailVariant::Large),
        _ => Err(ThumbnailServiceError::State),
    }
}
fn api_variant(value: ThumbnailVariant) -> beebeeb_api::routes::thumbnails::Variant {
    match value {
        ThumbnailVariant::Small => beebeeb_api::routes::thumbnails::Variant::Small,
        ThumbnailVariant::Medium => beebeeb_api::routes::thumbnails::Variant::Medium,
        ThumbnailVariant::Large => beebeeb_api::routes::thumbnails::Variant::Large,
    }
}
fn fallback_order(value: ThumbnailVariant) -> &'static [ThumbnailVariant] {
    match value {
        ThumbnailVariant::Large => &[
            ThumbnailVariant::Large,
            ThumbnailVariant::Medium,
            ThumbnailVariant::Small,
        ],
        ThumbnailVariant::Medium => &[ThumbnailVariant::Medium, ThumbnailVariant::Small],
        ThumbnailVariant::Small => &[ThumbnailVariant::Small],
    }
}
fn cache_key(file_id: &str, variant: ThumbnailVariant) -> String {
    format!("{file_id}:{}", variant.as_str())
}
