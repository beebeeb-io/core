use std::sync::{Arc, Mutex};
use std::time::Duration;

use beebeeb_client::auth::{SignInChallenge, SignInStateKind};
use beebeeb_client::contacts::ContactTrust;
use beebeeb_client::downloads::{DownloadFile, DownloadResult, DownloadService};
use beebeeb_client::files::{FileRecord, FileRecordPage};
use beebeeb_client::search::SearchService;
use beebeeb_client::settings::DeviceSettings;
use beebeeb_client::thumbnails::{ImageCodec, ImageCodecError, ThumbnailJob, ThumbnailService};
use beebeeb_client::uploads::{NetworkKind, UploadRequest, UploadService, transfer_now_ms};
use beebeeb_client::{Client, ClientConfig, ClientRuntime, EngineEvent, KeychainSecretStore, Session};
use beebeeb_core::kdf::MasterKey;
use beebeeb_core::thumbnail::{Platform, ThumbnailFormat, ThumbnailVariant};
use beebeeb_store::Store;
use beebeeb_types::limits::MemoryBudget;
use zeroize::Zeroizing;

use crate::{AccountReplacementHandle, MasterKeyHandle};

mod auth;
mod client;
mod files;
mod settings;
mod sharing;
mod transfers;

pub use auth::*;
pub use client::*;
pub use files::*;
pub use settings::*;
pub use sharing::*;
pub use transfers::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum RuntimeProfile {
    Application,
    Lightweight,
}

impl RuntimeProfile {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Application => "application",
            Self::Lightweight => "lightweight",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum ServiceErrorKind {
    InvalidInput,
    SessionRequired,
    Authentication,
    Network,
    Storage,
    Crypto,
    Cancelled,
    ManagedByService,
    Protected,
    Quota,
    SessionExpired,
    RetryAfter,
    AnchorExpired,
    AnotherAccountOnDevice,
    Unavailable,
}

impl ServiceErrorKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidInput => "invalid_input",
            Self::SessionRequired => "session_required",
            Self::Authentication => "authentication",
            Self::Network => "network",
            Self::Storage => "storage",
            Self::Crypto => "crypto",
            Self::Cancelled => "cancelled",
            Self::ManagedByService => "managed_by_service",
            Self::Protected => "protected",
            Self::Quota => "quota",
            Self::SessionExpired => "session_expired",
            Self::RetryAfter => "retry_after",
            Self::AnchorExpired => "anchor_expired",
            Self::AnotherAccountOnDevice => "another_account_on_device",
            Self::Unavailable => "unavailable",
        }
    }
}

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum ServiceError {
    #[error("invalid input")]
    InvalidInput,
    #[error("an authenticated session is required")]
    SessionRequired,
    #[error("authentication failed")]
    Authentication,
    #[error("the network operation failed")]
    Network,
    #[error("local storage is unavailable")]
    Storage,
    #[error("cryptographic processing failed")]
    Crypto,
    #[error("the operation was cancelled")]
    Cancelled,
    #[error("this item is managed by a service")]
    ManagedByService,
    /// Core's Backups rule refused the change. `detail` is core's words, to
    /// be shown as they are (backup spec Amendments 6 to 8). Never `message`:
    /// a UniFFI error field of that name collides with Kotlin's
    /// `Exception.message` (tests/error_fields.rs).
    #[error("{detail}")]
    Protected { detail: String },
    #[error("the account storage quota was exceeded")]
    Quota {
        limit_bytes: Option<u64>,
        used_bytes: Option<u64>,
    },
    #[error("the authenticated session expired")]
    SessionExpired,
    #[error("the operation may be retried after {seconds} seconds")]
    RetryAfter { seconds: u64 },
    #[error("the local change anchor expired")]
    AnchorExpired,
    #[error("another account is stored on this device")]
    AnotherAccountOnDevice,
    #[error("the service is unavailable")]
    Unavailable,
}

impl ServiceError {
    pub(crate) fn new(kind: ServiceErrorKind) -> Self {
        match kind {
            ServiceErrorKind::InvalidInput => Self::InvalidInput,
            ServiceErrorKind::SessionRequired => Self::SessionRequired,
            ServiceErrorKind::Authentication => Self::Authentication,
            ServiceErrorKind::Network => Self::Network,
            ServiceErrorKind::Storage => Self::Storage,
            ServiceErrorKind::Crypto => Self::Crypto,
            ServiceErrorKind::Cancelled => Self::Cancelled,
            ServiceErrorKind::ManagedByService => Self::ManagedByService,
            ServiceErrorKind::Protected => Self::Protected { detail: String::new() },
            ServiceErrorKind::Quota => Self::Quota {
                limit_bytes: None,
                used_bytes: None,
            },
            ServiceErrorKind::SessionExpired => Self::SessionExpired,
            ServiceErrorKind::RetryAfter => Self::RetryAfter { seconds: 0 },
            ServiceErrorKind::AnchorExpired => Self::AnchorExpired,
            ServiceErrorKind::AnotherAccountOnDevice => Self::AnotherAccountOnDevice,
            ServiceErrorKind::Unavailable => Self::Unavailable,
        }
    }

    pub(crate) fn unavailable() -> Self {
        Self::new(ServiceErrorKind::Unavailable)
    }
}

pub(crate) fn map_client_error(error: impl std::error::Error + 'static) -> ServiceError {
    let mut current: &(dyn std::error::Error + 'static) = &error;
    loop {
        if let Some(file) = current.downcast_ref::<beebeeb_client::files::FileServiceError>() {
            match file {
                beebeeb_client::files::FileServiceError::ManagedByService { .. } => {
                    return ServiceError::ManagedByService;
                }
                beebeeb_client::files::FileServiceError::Protected(protected) => {
                    return ServiceError::Protected {
                        detail: protected.message.to_string(),
                    };
                }
                _ => {}
            }
        }
        if let Some(device) = current.downcast_ref::<beebeeb_client::devices::DeviceError>() {
            match device {
                beebeeb_client::devices::DeviceError::ConfirmationFailed
                | beebeeb_client::devices::DeviceError::DeviceNameChanged => return ServiceError::Authentication,
                beebeeb_client::devices::DeviceError::Crypto => return ServiceError::Crypto,
                beebeeb_client::devices::DeviceError::MalformedAnswer => return ServiceError::InvalidInput,
                beebeeb_client::devices::DeviceError::Client(client) => {
                    current = client;
                    continue;
                }
                _ => {}
            }
        }
        if let Some(beebeeb_client::backup::BackupError::NotInBackups) =
            current.downcast_ref::<beebeeb_client::backup::BackupError>()
        {
            return ServiceError::InvalidInput;
        }
        if let Some(beebeeb_client::uploads::UploadServiceError::Protected(protected)) =
            current.downcast_ref::<beebeeb_client::uploads::UploadServiceError>()
        {
            return ServiceError::Protected {
                detail: protected.message.to_string(),
            };
        }
        if let Some(sync) = current.downcast_ref::<beebeeb_core::sync::SyncEngineError>()
            && matches!(sync, beebeeb_core::sync::SyncEngineError::AnchorExpired { .. })
        {
            return ServiceError::AnchorExpired;
        }
        if let Some(upload) = current.downcast_ref::<beebeeb_client::uploads::UploadServiceError>()
            && matches!(upload, beebeeb_client::uploads::UploadServiceError::QuotaFull)
        {
            return ServiceError::Quota {
                limit_bytes: None,
                used_bytes: None,
            };
        }
        if let Some(download) = current.downcast_ref::<beebeeb_client::downloads::DownloadServiceError>()
            && matches!(download, beebeeb_client::downloads::DownloadServiceError::Cancelled)
        {
            return ServiceError::Cancelled;
        }
        if let Some(client) = current.downcast_ref::<beebeeb_client::ClientError>() {
            if let beebeeb_client::ClientError::Api(beebeeb_api::ApiError::Server(server)) = client {
                if server.is_code(beebeeb_core::system_folders::SYSTEM_FOLDER_MANAGED_CODE) {
                    return ServiceError::ManagedByService;
                }
                if server.is_code("quota_exceeded") || server.is_trial_cap() || server.status == 507 {
                    return ServiceError::Quota {
                        limit_bytes: server.limit_bytes(),
                        used_bytes: server.used_bytes(),
                    };
                }
                if server.is_code("cancelled") {
                    return ServiceError::Cancelled;
                }
                if server.status == 401 || server.is_code("session_expired") {
                    return ServiceError::SessionExpired;
                }
                if let Some(seconds) = server.retry_after() {
                    return ServiceError::RetryAfter { seconds };
                }
            }
            return match client {
                beebeeb_client::ClientError::Transport(_) => ServiceError::Network,
                beebeeb_client::ClientError::InvalidAuthentication => ServiceError::Authentication,
                _ => ServiceError::Unavailable,
            };
        }
        let Some(source) = current.source() else {
            break;
        };
        current = source;
    }
    ServiceError::unavailable()
}

#[cfg(test)]
mod service_error_tests {
    use super::*;
    use beebeeb_api::ApiError;
    use beebeeb_client::ClientError;
    use beebeeb_core::api_error::ServerError;

    fn server(status: u16, body: &str) -> ServiceError {
        map_client_error(ClientError::Api(ApiError::Server(ServerError::parse_body(
            status, body,
        ))))
    }

    #[test]
    fn server_failures_keep_their_typed_binding_cases() {
        assert!(matches!(
            server(409, r#"{"error":"system_folder_managed"}"#),
            ServiceError::ManagedByService
        ));
        assert!(matches!(
            server(507, r#"{"error":"quota_exceeded","limit_bytes":9,"used_bytes":8}"#),
            ServiceError::Quota {
                limit_bytes: Some(9),
                used_bytes: Some(8)
            }
        ));
        assert!(matches!(
            server(499, r#"{"error":"cancelled"}"#),
            ServiceError::Cancelled
        ));
        assert!(matches!(
            server(401, r#"{"error":"session_expired"}"#),
            ServiceError::SessionExpired
        ));
        assert!(matches!(
            server(503, r#"{"error":"busy","retry_after":17}"#),
            ServiceError::RetryAfter { seconds: 17 }
        ));
    }
}
