use super::*;

#[uniffi::export(callback_interface)]
pub trait ImageCodecCallback: Send + Sync {
    fn encode(&self, source_path: String, max_dimension: u32, quality: f32, format: String) -> Option<Vec<u8>>;
}

pub(super) struct ImageCodecAdapter {
    pub(super) callback: Box<dyn ImageCodecCallback>,
}

impl ImageCodec for ImageCodecAdapter {
    fn encode(
        &self,
        source_path: &std::path::Path,
        max_dimension: u32,
        quality: f32,
        format: ThumbnailFormat,
    ) -> Result<Vec<u8>, ImageCodecError> {
        self.callback
            .encode(
                source_path.to_string_lossy().into_owned(),
                max_dimension,
                quality,
                format.as_str().into(),
            )
            .ok_or(ImageCodecError::Encode)
    }
}

#[uniffi::export(callback_interface)]
pub trait ChunkTransport: Send + Sync {
    fn upload_file(&self, location: String, headers: Vec<String>, body_path: String) -> u16;
    fn download_range(&self, location: String, start: Option<u64>, end: Option<u64>, max_bytes: u64)
    -> Option<Vec<u8>>;
    fn cancel_background(&self, tickets: Vec<String>) -> bool;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum NetworkSignal {
    Offline,
    Cellular,
    Wifi,
}

impl From<NetworkSignal> for NetworkKind {
    fn from(value: NetworkSignal) -> Self {
        match value {
            NetworkSignal::Offline => NetworkKind::Offline,
            NetworkSignal::Cellular => NetworkKind::Cellular,
            NetworkSignal::Wifi => NetworkKind::WiFi,
        }
    }
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct UploadData {
    pub id: i64,
    pub file_id: String,
    pub name: String,
    pub state: String,
    pub attempts: u32,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct UploadEnqueueData {
    pub source_path: String,
    pub name: String,
    pub mime_type: Option<String>,
    pub parent_id: Option<String>,
}

#[derive(uniffi::Object)]
pub struct UploadServiceHandle {
    pub(crate) root: Arc<NativeClientHandle>,
    pub(crate) service: Arc<UploadService>,
    pub(crate) store: Arc<StoreHandle>,
    pub(crate) device_id: String,
    pub(crate) product: String,
}

impl UploadServiceHandle {
    /// The device's upload settings: (Wi-Fi only, per-file staging bytes).
    pub(crate) fn upload_settings(&self) -> Result<(bool, u64), ServiceError> {
        let session = self.root.session()?;
        let store = self.store.store.lock().map_err(|_| ServiceError::unavailable())?;
        let settings = beebeeb_client::settings::load_local_settings(&store, &session, &self.device_id, &self.product)
            .map_err(map_client_error)?
            .ok_or_else(|| ServiceError::new(ServiceErrorKind::InvalidInput))?;
        if settings.upload_staging_bytes == 0 {
            return Err(ServiceError::new(ServiceErrorKind::InvalidInput));
        }
        Ok((settings.wifi_only, settings.upload_staging_bytes))
    }

    pub(crate) fn configured_request(&self, data: UploadEnqueueData) -> Result<(UploadRequest, i64), ServiceError> {
        let (wifi_only, disk_limit) = self.upload_settings()?;
        let mut request = UploadRequest::new(data.source_path, data.name, data.mime_type, data.parent_id);
        request.wifi_only = wifi_only;
        request.disk_limit = disk_limit;
        Ok((request, transfer_now_ms().map_err(map_client_error)?))
    }
}

#[uniffi::export]
impl UploadServiceHandle {
    pub fn enqueue(&self, data: UploadEnqueueData) -> Result<i64, ServiceError> {
        let (request, now_ms) = self.configured_request(data)?;
        self.service.enqueue(request, now_ms).map_err(map_client_error)
    }

    pub fn pause(&self, id: i64) -> Result<bool, ServiceError> {
        self.service
            .pause(id, transfer_now_ms().map_err(map_client_error)?)
            .map_err(map_client_error)
    }

    pub fn resume(&self, id: i64) -> Result<bool, ServiceError> {
        self.service
            .resume(id, transfer_now_ms().map_err(map_client_error)?)
            .map_err(map_client_error)
    }

    pub fn cancel(&self, id: i64) -> Result<(), ServiceError> {
        self.service
            .cancel(id, transfer_now_ms().map_err(map_client_error)?)
            .map(|_| ())
            .map_err(map_client_error)
    }

    pub fn list(&self) -> Result<Vec<UploadData>, ServiceError> {
        self.service
            .list()
            .map(|items| {
                items
                    .into_iter()
                    .map(|item| UploadData {
                        id: item.id,
                        file_id: item.file_id,
                        name: item.name,
                        state: format!("{:?}", item.state).to_lowercase(),
                        attempts: item.attempts,
                        last_error: item.last_error,
                    })
                    .collect()
            })
            .map_err(map_client_error)
    }

    pub fn run_next(
        &self,
        limit: u32,
        network: NetworkSignal,
        transport: Box<dyn ChunkTransport>,
    ) -> Result<u32, ServiceError> {
        let now_ms = transfer_now_ms().map_err(map_client_error)?;
        let Some((id, requests)) = self
            .root
            .runtime
            .block_on(self.service.next_transfers(limit as usize, network.into(), now_ms))
            .map_err(map_client_error)?
        else {
            return Ok(0);
        };
        let mut completed = 0u32;
        for request in requests {
            let headers = request
                .headers
                .iter()
                .map(|(name, value)| format!("{name}: {value}"))
                .collect();
            let status = transport.upload_file(request.url, headers, request.body_path.to_string_lossy().into_owned());
            self.root
                .runtime
                .block_on(self.service.transfer_finished(
                    id,
                    &request.ticket,
                    status,
                    None,
                    None,
                    &[],
                    transfer_now_ms().map_err(map_client_error)?,
                ))
                .map_err(map_client_error)?;
            completed = completed.saturating_add(1);
        }
        Ok(completed)
    }
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct DownloadData {
    pub file_id: String,
    pub name_encrypted: String,
    pub size_bytes: u64,
    pub chunk_size_bytes: u64,
    pub chunk_count: u32,
    pub object_version_id: String,
}

impl From<DownloadData> for DownloadFile {
    fn from(value: DownloadData) -> Self {
        Self {
            file_id: value.file_id,
            name_encrypted: value.name_encrypted,
            size_bytes: value.size_bytes,
            chunk_size_bytes: value.chunk_size_bytes,
            chunk_count: value.chunk_count,
            object_version_id: value.object_version_id,
        }
    }
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct DownloadOutcomeData {
    pub kind: String,
    pub path: Option<String>,
    pub frame_size: Option<u64>,
    pub context_limit: Option<u64>,
}

fn download_outcome(value: DownloadResult) -> DownloadOutcomeData {
    match value {
        DownloadResult::Ready(path) => DownloadOutcomeData {
            kind: "ready".into(),
            path: Some(path.to_string_lossy().into_owned()),
            frame_size: None,
            context_limit: None,
        },
        DownloadResult::Saved => DownloadOutcomeData {
            kind: "saved".into(),
            path: None,
            frame_size: None,
            context_limit: None,
        },
        DownloadResult::HandOff {
            frame_size,
            context_limit,
        } => DownloadOutcomeData {
            kind: "hand_off".into(),
            path: None,
            frame_size: Some(frame_size),
            context_limit: Some(context_limit),
        },
    }
}

#[derive(uniffi::Object)]
pub struct DownloadServiceHandle {
    pub(crate) root: Arc<NativeClientHandle>,
    pub(crate) service: Arc<DownloadService>,
}

#[uniffi::export]
impl DownloadServiceHandle {
    pub fn open(&self, file: DownloadData) -> Result<DownloadOutcomeData, ServiceError> {
        self.root
            .runtime
            .block_on(
                self.service
                    .open(&file.into(), transfer_now_ms().map_err(map_client_error)?),
            )
            .map(download_outcome)
            .map_err(map_client_error)
    }

    pub fn cancel(&self, file_id: String) -> Result<(), ServiceError> {
        self.service.cancel(&file_id).map_err(map_client_error)
    }

    pub fn clear_cache(&self) -> Result<(), ServiceError> {
        self.service.clear_cache().map_err(map_client_error)
    }
}

fn thumbnail_variant(value: &str) -> Result<ThumbnailVariant, ServiceError> {
    match value {
        "small" => Ok(ThumbnailVariant::Small),
        "medium" => Ok(ThumbnailVariant::Medium),
        "large" => Ok(ThumbnailVariant::Large),
        _ => Err(ServiceError::new(ServiceErrorKind::InvalidInput)),
    }
}

pub(super) fn platform(value: &str) -> Platform {
    match value {
        "ios" => Platform::Ios,
        "macos" => Platform::MacOs,
        "android" => Platform::Android,
        "windows" => Platform::Windows,
        "linux" => Platform::Linux,
        "web" => Platform::Web,
        _ => Platform::Unknown,
    }
}

#[derive(uniffi::Object)]
pub struct ThumbnailServiceHandle {
    pub(crate) root: Arc<NativeClientHandle>,
    pub(crate) service: Arc<ThumbnailService>,
    pub(crate) store: Arc<StoreHandle>,
    pub(crate) device_id: String,
    pub(crate) product: String,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct ThumbnailEnqueueData {
    pub file_id: String,
    pub name_encrypted: String,
    pub source_path: String,
    pub variant: String,
    pub created_at_ms: i64,
}

#[uniffi::export]
impl ThumbnailServiceHandle {
    pub fn enqueue(&self, data: ThumbnailEnqueueData) -> Result<i64, ServiceError> {
        let session = self.root.session()?;
        let store = self.store.store.lock().map_err(|_| ServiceError::unavailable())?;
        let settings = beebeeb_client::settings::load_local_settings(&store, &session, &self.device_id, &self.product)
            .map_err(map_client_error)?
            .ok_or_else(|| ServiceError::new(ServiceErrorKind::InvalidInput))?;
        self.service
            .enqueue_generation(
                ThumbnailJob {
                    file_id: data.file_id,
                    name_encrypted: data.name_encrypted,
                    source_path: data.source_path.into(),
                    variant: thumbnail_variant(&data.variant)?,
                    created_at_ms: data.created_at_ms,
                    wifi_only: settings.wifi_only,
                },
                transfer_now_ms().map_err(map_client_error)?,
            )
            .map_err(map_client_error)
    }

    pub fn run_next(&self, network: NetworkSignal) -> Result<Option<String>, ServiceError> {
        self.root
            .runtime
            .block_on(
                self.service
                    .run_next(network.into(), transfer_now_ms().map_err(map_client_error)?),
            )
            .map(|path| path.map(|value| value.to_string_lossy().into_owned()))
            .map_err(map_client_error)
    }

    pub fn get(&self, file_id: String, name_encrypted: String, variant: String) -> Result<String, ServiceError> {
        self.root
            .runtime
            .block_on(self.service.get(
                &file_id,
                &name_encrypted,
                thumbnail_variant(&variant)?,
                transfer_now_ms().map_err(map_client_error)?,
            ))
            .map(|path| path.to_string_lossy().into_owned())
            .map_err(map_client_error)
    }

    pub fn clear(&self) -> Result<(), ServiceError> {
        self.service.clear().map_err(map_client_error)
    }
}
