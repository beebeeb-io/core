use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

/// High-level status of the sync engine.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SyncStatus {
    Idle,
    Syncing {
        files_remaining: u64,
        bytes_remaining: u64,
    },
    Paused,
    Error(String),
    Offline,
}

/// Per-file sync state — drives overlay icons in Finder / Explorer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum FileState {
    /// Matches the remote version.
    Synced,
    /// Changed locally, not yet uploaded.
    Modified,
    /// Upload in progress; f32 is 0.0..=1.0 fraction.
    Uploading(f32),
    /// Download in progress; f32 is 0.0..=1.0 fraction.
    Downloading(f32),
    /// Changed both locally and remotely — needs resolution.
    Conflict,
    /// File exists in the vault but is not stored on disk.
    OnlineOnly,
}

/// Snapshot of overall sync state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncState {
    pub status: SyncStatus,
    pub files: HashMap<PathBuf, FileState>,
    pub last_sync: Option<DateTime<Utc>>,
}

impl SyncState {
    pub fn new() -> Self {
        Self {
            status: SyncStatus::Idle,
            files: HashMap::new(),
            last_sync: None,
        }
    }

    /// Number of files currently in conflict.
    pub fn conflict_count(&self) -> usize {
        self.files
            .values()
            .filter(|s| matches!(s, FileState::Conflict))
            .count()
    }

    /// Number of files being uploaded or downloaded.
    pub fn transfer_count(&self) -> usize {
        self.files
            .values()
            .filter(|s| matches!(s, FileState::Uploading(_) | FileState::Downloading(_)))
            .count()
    }
}

impl Default for SyncState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_state_is_idle() {
        let state = SyncState::new();
        assert_eq!(state.status, SyncStatus::Idle);
        assert!(state.files.is_empty());
        assert!(state.last_sync.is_none());
    }

    #[test]
    fn conflict_count_tracks_conflicts() {
        let mut state = SyncState::new();
        state
            .files
            .insert(PathBuf::from("a.txt"), FileState::Synced);
        state
            .files
            .insert(PathBuf::from("b.txt"), FileState::Conflict);
        state
            .files
            .insert(PathBuf::from("c.txt"), FileState::Conflict);
        state
            .files
            .insert(PathBuf::from("d.txt"), FileState::Uploading(0.5));
        assert_eq!(state.conflict_count(), 2);
        assert_eq!(state.transfer_count(), 1);
    }
}
