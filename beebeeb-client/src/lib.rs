//! Native client orchestration shared by Beebeeb applications.

#[cfg(any(feature = "files", feature = "store"))]
mod backup_guard;
mod chunk_transport;
mod client;
mod events;
mod runtime;
mod secrets;
mod session;
mod transport;

pub use chunk_transport::*;
pub use client::*;
pub use events::*;
pub use runtime::*;
pub use secrets::*;
pub use session::*;
pub use transport::*;

#[cfg(all(feature = "store", feature = "uploads", feature = "downloads", feature = "files"))]
pub mod archives;
#[cfg(feature = "auth")]
pub mod auth;
#[cfg(feature = "backup")]
pub mod backup;
#[cfg(feature = "contacts")]
pub mod contacts;
#[cfg(feature = "devices")]
pub mod devices;
#[cfg(all(feature = "downloads", feature = "store"))]
pub mod downloads;
#[cfg(all(feature = "downloads", not(feature = "store")))]
#[path = "downloads_minimal.rs"]
pub mod downloads;
#[cfg(feature = "file_provider")]
pub mod file_provider;
#[cfg(feature = "files")]
pub mod files;
#[cfg(all(
    feature = "store",
    feature = "uploads",
    feature = "downloads",
    feature = "thumbnails",
    feature = "backup",
    feature = "search",
    feature = "auth"
))]
pub mod platform;
#[cfg(feature = "search")]
pub mod search;
#[cfg(feature = "settings")]
pub mod settings;
#[cfg(feature = "shares")]
pub mod shares;
#[cfg(feature = "sync")]
pub mod sync;
#[cfg(all(feature = "thumbnails", feature = "store"))]
pub mod thumbnails;
#[cfg(all(feature = "thumbnails", not(feature = "store")))]
#[path = "thumbnails_minimal.rs"]
pub mod thumbnails;
#[cfg(all(feature = "uploads", feature = "store"))]
pub mod uploads;
#[cfg(all(feature = "uploads", not(feature = "store")))]
#[path = "uploads_minimal.rs"]
pub mod uploads;

#[cfg(any(test, feature = "test-support"))]
pub mod test_support;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_svc_archives;
#[cfg(test)]
mod tests_svc_auth;
#[cfg(test)]
mod tests_svc_backup_device;
#[cfg(test)]
mod tests_svc_backup_gate;
#[cfg(test)]
mod tests_svc_backups;
#[cfg(test)]
mod tests_svc_data;
#[cfg(test)]
mod tests_svc_platform;
#[cfg(test)]
mod tests_svc_shares;
#[cfg(test)]
mod tests_svc_sync_names;
#[cfg(test)]
mod tests_svc_transfer;
#[cfg(test)]
mod tests_svc_upload_source;
