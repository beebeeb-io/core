//! Legacy desktop sync prototype.
//!
//! This crate is not a product sync authority and must not be shipped in a
//! product. Product clients use `beebeeb_core::sync`; desktop will be rebuilt
//! on that engine later.

pub mod config;
pub mod conflict;
pub mod engine;
pub mod error;
pub mod key_resolution;
pub mod selective;
pub mod state;
pub mod watcher;

pub use config::{SyncConfig, SyncMode};
pub use conflict::{Conflict, ConflictResolution};
pub use engine::SyncEngine;
pub use error::SyncError;
pub use selective::SelectiveConfig;
pub use state::{FileState, SyncState, SyncStatus};
pub use watcher::FileWatcher;
