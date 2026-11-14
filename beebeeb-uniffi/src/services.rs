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

mod archives;
mod auth;
mod client;
mod files;
mod settings;
mod sharing;
mod transfers;

pub use archives::*;
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
    BackupStopUnfinished,
    ConfirmationRequired,
    SecondFactorRequired,
    SecondFactorRejected,
    DeletionAlreadyScheduled,
    SubscriptionActive,
    EmailNotSent,
    ShareRefused,
    ScreenLocked,
    VaultClosed,
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
            Self::BackupStopUnfinished => "backup_stop_unfinished",
            Self::ConfirmationRequired => "confirmation_required",
            Self::SecondFactorRequired => "second_factor_required",
            Self::SecondFactorRejected => "second_factor_rejected",
            Self::DeletionAlreadyScheduled => "deletion_already_scheduled",
            Self::SubscriptionActive => "subscription_active",
            Self::EmailNotSent => "email_not_sent",
            Self::ShareRefused => "share_refused",
            Self::ScreenLocked => "screen_locked",
            Self::VaultClosed => "vault_closed",
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
    /// The backup is off and could not finish its stop when the backup
    /// service was made, so none was made. `reason` is the stop's core wire
    /// string: show `backup_stop_words` for it as for a stopped batch, then
    /// make the service again later.
    #[error("the backup is off ({reason}) and could not finish stopping")]
    BackupStopUnfinished { reason: String },
    /// The server needs the password confirmed again before this action (its
    /// confirmation was missing, spent or expired). Ask for the password and
    /// call again.
    #[error("the action needs the password confirmed again")]
    ConfirmationRequired,
    /// The account has an authenticator: call again with its code or a backup
    /// code.
    #[error("an authenticator or backup code is required")]
    SecondFactorRequired,
    /// The authenticator or backup code was not accepted.
    #[error("the authenticator or backup code was not accepted")]
    SecondFactorRejected,
    /// The account is already scheduled for deletion; nothing changed. A new
    /// request needs that deletion cancelled first.
    #[error("the account is already scheduled for deletion")]
    DeletionAlreadyScheduled,
    /// The account still has a subscription the provider will charge; nothing
    /// changed. Cancel the subscription first.
    #[error("the account still has an active subscription")]
    SubscriptionActive,
    /// The server could not send the email the action needs (the deletion
    /// link), so nothing changed. Try again later.
    #[error("the email could not be sent")]
    EmailNotSent,
    /// Core's share flow or the server refused the share. `code` is the flow's stable code
    /// (`plan_required`, `trial_share_limit_reached`, `folder_needs_upgrade`, ...): show the app's
    /// words for it.
    #[error("the share was refused ({code})")]
    ShareRefused { code: String },
    /// The app is locked on this device and the call is one a person drives: core refused
    /// it before anything was sent. The stored session is untouched; unlock, then retry.
    #[error("the app is locked on this device")]
    ScreenLocked,
    /// The vault is closed: the work is stopped, and a person can only prove the account
    /// password, lock or sign out. Not an expired session: never remove the stored session
    /// on this answer.
    #[error("the vault is closed until the account password is proven")]
    VaultClosed,
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
            ServiceErrorKind::BackupStopUnfinished => Self::BackupStopUnfinished { reason: String::new() },
            ServiceErrorKind::ConfirmationRequired => Self::ConfirmationRequired,
            ServiceErrorKind::SecondFactorRequired => Self::SecondFactorRequired,
            ServiceErrorKind::SecondFactorRejected => Self::SecondFactorRejected,
            ServiceErrorKind::DeletionAlreadyScheduled => Self::DeletionAlreadyScheduled,
            ServiceErrorKind::SubscriptionActive => Self::SubscriptionActive,
            ServiceErrorKind::EmailNotSent => Self::EmailNotSent,
            ServiceErrorKind::ShareRefused => Self::ShareRefused { code: String::new() },
            ServiceErrorKind::ScreenLocked => Self::ScreenLocked,
            ServiceErrorKind::VaultClosed => Self::VaultClosed,
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
        match current.downcast_ref::<beebeeb_client::backup::BackupError>() {
            Some(
                beebeeb_client::backup::BackupError::NotInBackups
                | beebeeb_client::backup::BackupError::InvalidDeviceId,
            ) => return ServiceError::InvalidInput,
            // One backup service per upload service, until the first is dropped.
            Some(beebeeb_client::backup::BackupError::AlreadyRunning) => {
                return ServiceError::new(ServiceErrorKind::Unavailable);
            }
            Some(beebeeb_client::backup::BackupError::StopUnfinished { reason, .. }) => {
                return ServiceError::BackupStopUnfinished {
                    reason: reason.as_str().to_owned(),
                };
            }
            _ => {}
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
                if let Some(refusal) = coded_refusal(server) {
                    return refusal;
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
                // The lock's two refusals have their own kinds: neither says the session
                // expired, and a host never removes the stored session on either.
                beebeeb_client::ClientError::VaultClosed => ServiceError::VaultClosed,
                beebeeb_client::ClientError::ScreenLocked => ServiceError::ScreenLocked,
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

/// The refusals a screen answers with its own words: the step-up confirmation, the
/// second factor and the account deletion's own.
fn coded_refusal(server: &beebeeb_core::api_error::ServerError) -> Option<ServiceError> {
    Some(match server.code.as_deref()? {
        "confirmation_required" => ServiceError::ConfirmationRequired,
        "second_factor_required" => ServiceError::SecondFactorRequired,
        "invalid_totp_code" => ServiceError::SecondFactorRejected,
        "delete_already_scheduled" => ServiceError::DeletionAlreadyScheduled,
        "delete_subscription_active" => ServiceError::SubscriptionActive,
        "delete_email_failed" => ServiceError::EmailNotSent,
        _ => return None,
    })
}

/// The errors of the account changes a signed-in session makes: the authenticator,
/// the password, the email and the account deletion. Every request they send carries
/// the session, so a 401 that reaches here is the session's: the step-up's own
/// refusals arrive as `PasswordNotConfirmed`. Sign-in keeps its own mapping, as a
/// 401 there refuses a credential.
pub(crate) fn map_account_change_error(error: beebeeb_client::auth::AuthError) -> ServiceError {
    match error {
        beebeeb_client::auth::AuthError::PasswordNotConfirmed => ServiceError::Authentication,
        // `AuthError::Client` is transparent: its source chain skips the `ClientError`.
        beebeeb_client::auth::AuthError::Client(client) => map_client_error(client),
        other => map_client_error(other),
    }
}

#[cfg(test)]
mod service_error_tests {
    use super::*;
    use beebeeb_api::{Answer, ApiError, Header};
    use beebeeb_client::ClientError;
    use beebeeb_client::auth::AuthError;
    use beebeeb_core::api_error::ServerError;

    /// A delete-request refusal as the client hands it on: decoded by the route,
    /// inside the account change's error.
    fn delete_refusal(status: u16, headers: Vec<Header>, body: &str) -> AuthError {
        let refused = beebeeb_api::routes::account::request_deletion()
            .parse(Answer::new(status, headers, body.as_bytes().to_vec()))
            .expect_err("a refusal");
        AuthError::Client(ClientError::Api(refused))
    }

    #[test]
    fn account_deletion_refusals_reach_the_app_as_cases_it_can_tell_apart() {
        let cases = [
            (
                "a wrong password",
                AuthError::PasswordNotConfirmed,
                ServiceErrorKind::Authentication,
            ),
            (
                "a spent confirmation",
                delete_refusal(
                    403,
                    vec![],
                    r#"{"error":"confirmation_required","message":"This action requires password confirmation"}"#,
                ),
                ServiceErrorKind::ConfirmationRequired,
            ),
            (
                "a missing second factor",
                delete_refusal(
                    403,
                    vec![],
                    r#"{"code":"second_factor_required","error":"Enter the code from your authenticator app, or a backup code."}"#,
                ),
                ServiceErrorKind::SecondFactorRequired,
            ),
            (
                "a wrong second factor",
                delete_refusal(
                    400,
                    vec![],
                    r#"{"error":"invalid_totp_code","message":"That code didn't match. Check your authenticator app and try again."}"#,
                ),
                ServiceErrorKind::SecondFactorRejected,
            ),
            (
                "a deletion already scheduled",
                delete_refusal(
                    409,
                    vec![],
                    r#"{"code":"delete_already_scheduled","error":"This account is already scheduled for deletion. Cancel that first."}"#,
                ),
                ServiceErrorKind::DeletionAlreadyScheduled,
            ),
            (
                "an active subscription",
                delete_refusal(
                    409,
                    vec![],
                    r#"{"code":"delete_subscription_active","error":"You still have an active subscription. Cancel it first, then ask again. No link was sent."}"#,
                ),
                ServiceErrorKind::SubscriptionActive,
            ),
            (
                "a link sent a moment ago",
                delete_refusal(
                    429,
                    vec![Header::new("retry-after", "60")],
                    r#"{"code":"delete_request_rate_limited","error":"A link was sent less than a minute ago. Check your email, or try again in a minute."}"#,
                ),
                ServiceErrorKind::RetryAfter,
            ),
            (
                "a link email that failed",
                delete_refusal(
                    502,
                    vec![],
                    r#"{"code":"delete_email_failed","error":"The confirmation email could not be sent. Nothing was scheduled. Try again later."}"#,
                ),
                ServiceErrorKind::EmailNotSent,
            ),
            (
                "a session that is gone",
                delete_refusal(401, vec![], r#"{"error":"unauthorized"}"#),
                ServiceErrorKind::SessionExpired,
            ),
        ];

        let mut kinds: Vec<ServiceErrorKind> = Vec::new();
        let mut wrong = Vec::new();
        for (refusal, error, kind) in cases {
            let mapped = map_account_change_error(error);
            if std::mem::discriminant(&mapped) != std::mem::discriminant(&ServiceError::new(kind)) {
                wrong.push(format!("{refusal}: {mapped:?}, expected {}", kind.as_str()));
            }
            if let ServiceError::RetryAfter { seconds } = mapped {
                assert_eq!(seconds, 60, "{refusal}: the header's delay");
            }
            assert!(
                !kinds.contains(&kind),
                "{refusal}: a second refusal on {}",
                kind.as_str()
            );
            kinds.push(kind);
        }
        assert!(wrong.is_empty(), "refusals on the wrong case:\n{}", wrong.join("\n"));
        assert_eq!(kinds.len(), 9);
        assert!(!kinds.contains(&ServiceErrorKind::Unavailable));
    }

    /// The lock's refusals keep their own kinds: neither is an expired session.
    #[test]
    fn the_locks_refusals_have_their_own_kinds() {
        assert!(matches!(
            map_client_error(ClientError::ScreenLocked),
            ServiceError::ScreenLocked
        ));
        assert!(matches!(
            map_client_error(ClientError::VaultClosed),
            ServiceError::VaultClosed
        ));
        assert_eq!(ServiceErrorKind::ScreenLocked.as_str(), "screen_locked");
        assert_eq!(ServiceErrorKind::VaultClosed.as_str(), "vault_closed");
        assert!(matches!(
            ServiceError::new(ServiceErrorKind::VaultClosed),
            ServiceError::VaultClosed
        ));
    }

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
