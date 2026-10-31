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
//!
//! let request = DownloadRequest {
//!     api_base: "https://api.example.test".into(),
//!     file_id: "11111111-2222-4333-8444-555555555555".into(),
//!     chunk_count: 3,
//!     pinned_version: None,
//!     memory: MemoryClass::Native,
//!     kbps_limit: None,
//!     forced_api: true,
//!     allow_legacy_chunk0: false,
//!     jitter_seed: 7,
//! };
//! assert!(request.forced_api);
//! ```

pub mod download;
pub mod io;
pub mod observer;
pub mod shared;

#[cfg(any(test, feature = "test-support"))]
pub mod test_support;

#[cfg(test)]
mod tests;

pub use download::{
    AfterWriteCause, DownloadError, DownloadOutcome, DownloadRequest, DownloadStats, PlaintextSink, download,
};
pub use io::{ApiCall, ApiMethod, ApiReply, DirectIo, SignedUrl, StorageReply};
pub use observer::{ChunkVia, Observer, TransferEvent, TransportKind, UseApiReason};
pub use shared::{DirectShared, DirectStore, HealthSnapshot};
