use std::sync::Arc;

use crate::{
    Client, SecretStore, Session,
    auth::AccountReplacement,
    backup::BackupService,
    downloads::DownloadService,
    files::FileRecord,
    search::SearchService,
    thumbnails::ThumbnailService,
    uploads::{SignOutPlan, UploadService},
};
use beebeeb_store::Store;
use std::sync::Mutex;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignOutFailure {
    UploadQueue,
    PlatformCancellation,
    DownloadCache,
    ThumbnailCache,
    BackupManifest,
    AccountData,
    Session,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignOutReport {
    pub platform_cancel_tickets: Vec<String>,
    pub failures: Vec<SignOutFailure>,
}

impl SignOutReport {
    pub fn is_complete(&self) -> bool {
        self.failures.is_empty()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PlatformCancellationError {
    #[error("platform transfer cancellation failed")]
    Failed,
}

pub trait PlatformTransferCanceller: Send + Sync {
    fn cancel(&self, tickets: &[String]) -> Result<(), PlatformCancellationError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AccountDataPurgeError {
    #[error("account data purge failed")]
    Failed,
}

/// Platform-owned removal of account directories and, where an open shared
/// handle prevents Rust from unlinking it, the already-wiped database file.
/// It runs even when an earlier cleanup step failed.
pub trait AccountDataPurger: Send + Sync {
    fn purge_account_data(&self) -> Result<(), AccountDataPurgeError>;
}

/// Orders service startup and teardown around the account boundary.
pub struct ServiceCoordinator {
    client: Arc<Client>,
    uploads: Arc<UploadService>,
    downloads: Arc<DownloadService>,
    thumbnails: Arc<ThumbnailService>,
    backup: Arc<BackupService>,
    search: Arc<SearchService>,
    account_store: Arc<Mutex<Store>>,
}

impl ServiceCoordinator {
    pub fn new(
        client: Arc<Client>,
        uploads: Arc<UploadService>,
        downloads: Arc<DownloadService>,
        thumbnails: Arc<ThumbnailService>,
        backup: Arc<BackupService>,
        search: Arc<SearchService>,
        account_store: Arc<Mutex<Store>>,
    ) -> Self {
        Self {
            client,
            uploads,
            downloads,
            thumbnails,
            backup,
            search,
            account_store,
        }
    }

    /// Rebuild the device-local name index from authenticated local records
    /// before search is exposed after process start.
    pub fn start(&self, records: impl IntoIterator<Item = FileRecord>) {
        self.search.rebuild(records);
    }

    pub async fn sign_out_app(
        &self,
        secrets: &dyn SecretStore,
        platform: &dyn PlatformTransferCanceller,
        account_data: &dyn AccountDataPurger,
        now_ms: i64,
    ) -> SignOutReport {
        self.sign_out_local(platform, account_data, now_ms, || async {
            self.client.sign_out_this_app(secrets).await.map_err(|_| ())
        })
        .await
    }

    /// Purges all local state belonging to the current account and returns a
    /// one-shot capability that is required by account-replacing installs.
    pub async fn prepare_account_replacement(
        &self,
        secrets: &dyn SecretStore,
        platform: &dyn PlatformTransferCanceller,
        account_data: &dyn AccountDataPurger,
        now_ms: i64,
    ) -> Result<AccountReplacement, SignOutReport> {
        let report = self
            .sign_out_local(platform, account_data, now_ms, || async {
                let stored = Session::sign_out_device(secrets).map(|_| ()).map_err(|_| ());
                let local = self.client.clear_authentication().map(|_| ()).map_err(|_| ());
                stored.and(local)
            })
            .await;
        if report.is_complete() {
            Ok(AccountReplacement::authorized())
        } else {
            Err(report)
        }
    }

    pub async fn sign_out_device(
        &self,
        device_id: &str,
        confirm_last_device: bool,
        secrets: &dyn SecretStore,
        platform: &dyn PlatformTransferCanceller,
        account_data: &dyn AccountDataPurger,
        now_ms: i64,
    ) -> Result<SignOutReport, crate::devices::DeviceError> {
        let listed = self.client.list_devices().await?;
        if crate::devices::last_device_warning(&listed.devices, device_id) && !confirm_last_device {
            return Err(crate::devices::DeviceError::LastDeviceConfirmationRequired);
        }
        // Removal runs before account work stops, because stopping retires the
        // credentials and only the logout may use them after that.
        let removed = self.client.remove_device(device_id).await.map(|_| ()).map_err(|_| ());
        Ok(self
            .sign_out_local(platform, account_data, now_ms, || async {
                let ended = self.client.end_session_after_device_removal().await.map_err(|_| ());
                let stored = Session::sign_out_device(secrets).map(|_| ()).map_err(|_| ());
                let local = self.client.clear_authentication().map(|_| ()).map_err(|_| ());
                removed.and(ended).and(stored).and(local)
            })
            .await)
    }

    async fn sign_out_local<F, Fut>(
        &self,
        platform: &dyn PlatformTransferCanceller,
        account_data: &dyn AccountDataPurger,
        now_ms: i64,
        finish_session: F,
    ) -> SignOutReport
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<(), ()>>,
    {
        self.client.stop_account_work();
        let mut failures = Vec::new();
        let plan = match self.uploads.sign_out(now_ms) {
            Ok(plan) => plan,
            Err(_) => {
                failures.push(SignOutFailure::UploadQueue);
                SignOutPlan {
                    cancel_tickets: Vec::new(),
                    delete_files: Vec::new(),
                }
            }
        };
        if platform.cancel(&plan.cancel_tickets).is_err() {
            failures.push(SignOutFailure::PlatformCancellation);
        }
        self.uploads.finalize_sign_out(&plan);
        if self.downloads.clear_cache().is_err() {
            failures.push(SignOutFailure::DownloadCache);
        }
        if self.thumbnails.sign_out(now_ms).is_err() {
            failures.push(SignOutFailure::ThumbnailCache);
        }
        if self.backup.sign_out().is_err() {
            failures.push(SignOutFailure::BackupManifest);
        }
        self.search.clear();
        if self
            .account_store
            .lock()
            .map_err(|_| ())
            .and_then(|mut store| store.purge_account_data().map_err(|_| ()))
            .is_err()
        {
            failures.push(SignOutFailure::AccountData);
        }
        if account_data.purge_account_data().is_err() && !failures.contains(&SignOutFailure::AccountData) {
            failures.push(SignOutFailure::AccountData);
        }
        if finish_session().await.is_err() {
            failures.push(SignOutFailure::Session);
        }
        SignOutReport {
            platform_cancel_tickets: plan.cancel_tickets,
            failures,
        }
    }
}
