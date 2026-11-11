//! `ArchiveServiceHandle`: the native archive service for Swift (archives
//! design §5.2). Every method forwards to `beebeeb_client::archives`; the
//! records are core's preview model, summary and words (`crate::archives`).
//! A password crosses as a `SecretString` and becomes an `ArchivePassword`
//! at once.

use beebeeb_client::archives::{
    ArchiveEvent, ArchiveId, ArchiveService, ArchiveServiceError, ExtractDestination, ExtractOptions, ExtractionId,
};
use beebeeb_core::archives::{ArchivePassword, ArchivePlatform, Selection};

use super::*;
use crate::archives as records;
use crate::secret_types::SecretString;

/// Why an archive call did nothing. `Refused` carries core's words.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum ArchiveError {
    /// The planner refused before anything was written (`reason`: core's
    /// binding string, `"backups"`, `"quota"`, ...).
    #[error("{}", text.text)]
    Refused { reason: String, text: records::ArchiveText },
    /// The archive cannot be listed.
    #[error("{}", text.text)]
    Unreadable {
        refusal: records::ArchiveRefusal,
        text: records::ArchiveText,
    },
    #[error("the archive is still being read")]
    Reading,
    #[error("an extraction holds this archive; open it again")]
    Busy,
    #[error("no archive is open under this id")]
    UnknownArchive,
    #[error("the archive has no such entry")]
    NoEntry,
    #[error("this entry is protected by a password")]
    PasswordNeeded,
    #[error("the password is wrong")]
    WrongPassword,
    #[error("this entry is damaged")]
    Corrupt,
    #[error("this entry is too large to open here")]
    TooLarge,
    #[error("this entry cannot be opened")]
    Skipped { reason: records::ArchiveSkipReason },
    #[error("{error}")]
    Service { error: ServiceErrorKind },
}

impl From<ArchiveServiceError> for ArchiveError {
    fn from(error: ArchiveServiceError) -> Self {
        match error {
            ArchiveServiceError::Plan(refusal) => Self::Refused {
                reason: refusal.as_str().into(),
                text: refusal.text().into(),
            },
            ArchiveServiceError::Refused(refusal) => Self::Unreadable {
                refusal: refusal.into(),
                text: beebeeb_core::archives::preview::refusal_text(refusal).into(),
            },
            ArchiveServiceError::Reading => Self::Reading,
            ArchiveServiceError::Busy => Self::Busy,
            ArchiveServiceError::UnknownArchive => Self::UnknownArchive,
            ArchiveServiceError::NoEntry => Self::NoEntry,
            ArchiveServiceError::PasswordNeeded => Self::PasswordNeeded,
            ArchiveServiceError::WrongPassword => Self::WrongPassword,
            ArchiveServiceError::Corrupt => Self::Corrupt,
            ArchiveServiceError::TooLarge => Self::TooLarge,
            ArchiveServiceError::Skipped(reason) => Self::Skipped { reason: reason.into() },
            ArchiveServiceError::ReadFailed => Self::Service {
                error: ServiceErrorKind::Network,
            },
            ArchiveServiceError::Destination | ArchiveServiceError::State => Self::Service {
                error: ServiceErrorKind::Unavailable,
            },
            other => Self::Service {
                error: service_kind(map_client_error(other)),
            },
        }
    }
}

fn service_kind(error: ServiceError) -> ServiceErrorKind {
    match error {
        ServiceError::InvalidInput => ServiceErrorKind::InvalidInput,
        ServiceError::SessionRequired => ServiceErrorKind::SessionRequired,
        ServiceError::Authentication => ServiceErrorKind::Authentication,
        ServiceError::Network => ServiceErrorKind::Network,
        ServiceError::Storage => ServiceErrorKind::Storage,
        ServiceError::Crypto => ServiceErrorKind::Crypto,
        ServiceError::Cancelled => ServiceErrorKind::Cancelled,
        ServiceError::ManagedByService => ServiceErrorKind::ManagedByService,
        ServiceError::Protected { .. } => ServiceErrorKind::Protected,
        ServiceError::Quota { .. } => ServiceErrorKind::Quota,
        ServiceError::SessionExpired => ServiceErrorKind::SessionExpired,
        ServiceError::RetryAfter { .. } => ServiceErrorKind::RetryAfter,
        ServiceError::AnchorExpired => ServiceErrorKind::AnchorExpired,
        ServiceError::AnotherAccountOnDevice => ServiceErrorKind::AnotherAccountOnDevice,
        ServiceError::Unavailable => ServiceErrorKind::Unavailable,
        ServiceError::BackupStopUnfinished { .. } => ServiceErrorKind::BackupStopUnfinished,
        ServiceError::ConfirmationRequired => ServiceErrorKind::ConfirmationRequired,
        ServiceError::SecondFactorRequired => ServiceErrorKind::SecondFactorRequired,
        ServiceError::SecondFactorRejected => ServiceErrorKind::SecondFactorRejected,
        ServiceError::DeletionAlreadyScheduled => ServiceErrorKind::DeletionAlreadyScheduled,
        ServiceError::SubscriptionActive => ServiceErrorKind::SubscriptionActive,
        ServiceError::EmailNotSent => ServiceErrorKind::EmailNotSent,
    }
}

impl std::fmt::Display for ServiceErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Where an extraction lands.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum ArchiveDestination {
    /// "Extract": the folder the archive is in.
    NextToArchive,
    /// "Extract to…": a chosen folder; `None` is the top of the drive.
    Folder { parent_id: Option<String> },
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ArchiveExtractOptions {
    /// Paths as the preview rows name them; `None` extracts everything.
    pub selection: Option<Vec<String>>,
    pub destination: ArchiveDestination,
    /// The device's free disk (staged files need room for the largest one).
    pub device_free_bytes: Option<u64>,
}

/// One archive event (`kind`: `"model"`, `"read_failed"`, `"finished"`).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ArchiveEventData {
    pub kind: String,
    /// The archive (`model`, `read_failed`).
    pub archive_id: Option<u64>,
    /// The extraction (`finished`).
    pub extraction_id: Option<u64>,
    pub model: Option<records::ArchivePreviewModel>,
    pub summary: Option<records::ExtractSummary>,
}

impl From<ArchiveEvent> for ArchiveEventData {
    fn from(event: ArchiveEvent) -> Self {
        let mut data = Self {
            kind: String::new(),
            archive_id: None,
            extraction_id: None,
            model: None,
            summary: None,
        };
        match event {
            ArchiveEvent::Model { id, model } => {
                data.kind = "model".into();
                data.archive_id = Some(id.0);
                data.model = Some(model.into());
            }
            ArchiveEvent::ReadFailed { id } => {
                data.kind = "read_failed".into();
                data.archive_id = Some(id.0);
            }
            ArchiveEvent::Finished { id, summary } => {
                data.kind = "finished".into();
                data.extraction_id = Some(id.0);
                data.summary = Some(summary.into());
            }
        }
        data
    }
}

#[derive(uniffi::Object)]
pub struct ArchiveEventStreamHandle {
    runtime: ClientRuntime,
    receiver: Mutex<tokio::sync::broadcast::Receiver<ArchiveEvent>>,
}

#[uniffi::export]
impl ArchiveEventStreamHandle {
    /// The next event, or `None` after `timeout_ms`. Missed events
    /// (`Unavailable`) mean: ask `preview` for the current screen.
    pub fn next(&self, timeout_ms: u64) -> Result<Option<ArchiveEventData>, ServiceError> {
        let mut receiver = self.receiver.lock().map_err(|_| ServiceError::unavailable())?;
        let wait = async {
            match tokio::time::timeout(Duration::from_millis(timeout_ms), receiver.recv()).await {
                Ok(Ok(event)) => Ok(Some(event.into())),
                Ok(Err(tokio::sync::broadcast::error::RecvError::Lagged(_))) => Err(ServiceError::unavailable()),
                Ok(Err(tokio::sync::broadcast::error::RecvError::Closed)) | Err(_) => Ok(None),
            }
        };
        self.runtime.block_on(wait)
    }
}

#[derive(uniffi::Object)]
pub struct ArchiveServiceHandle {
    root: Arc<NativeClientHandle>,
    uploads: Arc<UploadServiceHandle>,
    service: ArchiveService,
}

fn password(secret: Option<SecretString>) -> Option<ArchivePassword> {
    secret.map(|secret| ArchivePassword::new(String::from(secret)))
}

#[uniffi::export]
impl ArchiveServiceHandle {
    /// Open an archive and start listing it; the listing arrives as a
    /// `model` event.
    pub fn open(&self, file: DownloadData, name: String, parent_id: Option<String>) -> Result<u64, ArchiveError> {
        let file: DownloadFile = file.into();
        self.root
            .runtime
            .block_on(self.service.open(&file, name, parent_id))
            .map(|id| id.0)
            .map_err(Into::into)
    }

    pub fn preview(
        &self,
        archive_id: u64,
        folder: Vec<String>,
        selection: Vec<String>,
    ) -> Result<records::ArchivePreviewModel, ArchiveError> {
        self.root
            .runtime
            .block_on(self.service.preview(ArchiveId(archive_id), folder, selection))
            .map(Into::into)
            .map_err(Into::into)
    }

    /// Plan and start an extraction. Uploads follow the device's upload
    /// settings (Wi-Fi only, staging limit).
    pub fn extract(
        &self,
        archive_id: u64,
        options: ArchiveExtractOptions,
        password_text: Option<SecretString>,
    ) -> Result<u64, ArchiveError> {
        let (wifi_only, disk_limit) = self.uploads.upload_settings().map_err(|error| ArchiveError::Service {
            error: service_kind(error),
        })?;
        let options = ExtractOptions {
            selection: options.selection.map_or(Selection::All, Selection::Paths),
            destination: match options.destination {
                ArchiveDestination::NextToArchive => ExtractDestination::NextToArchive,
                ArchiveDestination::Folder { parent_id } => ExtractDestination::Folder(parent_id),
            },
            device_free_bytes: options.device_free_bytes,
            wifi_only,
            upload_disk_limit: Some(disk_limit),
        };
        self.root
            .runtime
            .block_on(
                self.service
                    .extract(ArchiveId(archive_id), options, password(password_text)),
            )
            .map(|id| id.0)
            .map_err(Into::into)
    }

    /// The password a run asked for (a `model` event in `needs_password`).
    pub fn supply_password(&self, extraction_id: u64, password_text: SecretString) {
        if let Some(password) = password(Some(password_text)) {
            self.service.supply_password(ExtractionId(extraction_id), password);
        }
    }

    /// One entry's bytes, after its own check passed (Open, Download).
    pub fn open_entry(
        &self,
        archive_id: u64,
        index: u32,
        password_text: Option<SecretString>,
    ) -> Result<Vec<u8>, ArchiveError> {
        self.root
            .runtime
            .block_on(
                self.service
                    .open_entry(ArchiveId(archive_id), index, password(password_text)),
            )
            .map_err(Into::into)
    }

    pub fn cancel(&self, extraction_id: u64) {
        self.service.cancel(ExtractionId(extraction_id));
    }

    pub fn close(&self, archive_id: u64) {
        self.service.close(ArchiveId(archive_id));
    }

    pub fn observe(&self) -> Arc<ArchiveEventStreamHandle> {
        Arc::new(ArchiveEventStreamHandle {
            runtime: self.root.runtime.clone(),
            receiver: Mutex::new(self.service.observe()),
        })
    }
}

#[uniffi::export]
impl NativeClientHandle {
    /// The archive service (`platform`: `"mobile_app"` on the phone). It owns
    /// `temp_root`, where extracted files wait for their uploads; one live
    /// service per `temp_root`. It needs the application runtime: on the
    /// lightweight one (a File Provider extension) listing and extraction
    /// would stall between calls, so it is refused (`unavailable`).
    pub fn archives(
        self: &Arc<Self>,
        downloads: Arc<DownloadServiceHandle>,
        uploads: Arc<UploadServiceHandle>,
        temp_root: String,
        platform: String,
    ) -> Result<Arc<ArchiveServiceHandle>, ServiceError> {
        if !self.runtime.runs_tasks_alone() {
            return Err(ServiceError::new(ServiceErrorKind::Unavailable));
        }
        let platform =
            ArchivePlatform::parse(&platform).ok_or_else(|| ServiceError::new(ServiceErrorKind::InvalidInput))?;
        let service = ArchiveService::new(
            self.client.clone(),
            Arc::clone(&downloads.service),
            Arc::clone(&uploads.service),
            temp_root.into(),
            platform,
        )
        .map_err(map_client_error)?;
        Ok(Arc::new(ArchiveServiceHandle {
            root: self.clone(),
            uploads,
            service,
        }))
    }
}
