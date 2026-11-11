//! The L2 direct-transfer driver (task 2173, plan K2): the download half that
//! performs I/O, shared by Beebeeb's native clients.
//!
//! Layer 1 is `beebeeb_core::direct_transfer`, the pure rules (wire shapes,
//! authority, classification, the window planner, health, pacing). This crate
//! is the layer above it: one `download` function that drives a file through
//! grant windows and presigned links, decrypts in order through core's
//! `ChunkDecryptor`, and writes only authenticated plaintext to the caller's
//! sink. Storage, API and clock are the caller's [`DirectIo`]; the caller
//! decides what to do after `Done` (publish the file) or `UseApi` (fetch it
//! through the API stream from the start).
//!
//! ```rust
//! use beebeeb_transfer::DownloadRequest;
//! use beebeeb_core::direct_transfer::MemoryClass;
//! use beebeeb_types::limits::MemoryBudget;
//!
//! let request = DownloadRequest {
//!     api_base: "https://api.example.test".into(),
//!     file_id: "11111111-2222-4333-8444-555555555555".into(),
//!     chunk_count: 3,
//!     pinned_version: None,
//!     memory: MemoryClass::Native,
//!     budget: MemoryBudget::NATIVE,
//!     authenticated_chunk_size: None,
//!     kbps_limit: None,
//!     forced_api: true,
//!     allow_legacy_chunk0: false,
//!     jitter_seed: 7,
//! };
//! assert!(request.forced_api);
//! ```

pub mod background;
pub mod download;
pub mod io;
pub mod observer;
pub mod range;
pub mod shared;
pub mod upload;

pub(crate) const V2_CAPABILITIES_HEADER: &str = "x-beebeeb-capabilities";
pub(crate) const V2_WRITE_CAPABILITIES: &str = "file-write-v2, version-metadata-v1";
pub(crate) const DIRECT_V2_WRITE_CAPABILITIES: &str = "object-upload-v1, file-write-v2, version-metadata-v1";

#[cfg(any(test, feature = "test-support"))]
pub mod test_support;

#[cfg(test)]
mod range_tests;
#[cfg(test)]
mod tests;

pub use background::{
    BackgroundError, BackgroundFailure, BackgroundGrant, BackgroundRestartPlan, BackgroundRestore,
    BackgroundUploadPlanner, CommitRequest, SignOutPlan, StageProgress, TransferFinished, TransferRequest,
    UploadSourceIdentity,
};
#[cfg(any(unix, windows))]
pub use download::download_current_to_directory;
pub use download::{
    AfterWriteCause, DownloadError, DownloadOutcome, DownloadRequest, DownloadStats, PlaintextSink, download,
    download_current, download_historical,
};
pub use io::{ApiCall, ApiMethod, ApiReply, DirectIo, SignedUrl, StorageReply};
pub use observer::{ChunkVia, Observer, TransferEvent, TransportKind, UseApiReason};
pub use range::{
    RangeControl, RangeIdentity, RangeLessor, RangeOutcome, RangeRequest, RangeSessionError, RangeSink, RangeStats,
    range_session,
};
pub use shared::{DirectShared, DirectStore, HealthSnapshot};
pub use upload::{
    UploadCommitment, UploadError, UploadFailureState, UploadOutcome, UploadSession, UploadStats, UploadTransport,
    upload,
};
