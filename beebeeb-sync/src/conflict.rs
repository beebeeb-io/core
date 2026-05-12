use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// A detected conflict: the same file was modified both locally and remotely
/// since the last sync.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Conflict {
    pub path: PathBuf,
    pub local_modified: DateTime<Utc>,
    pub remote_modified: DateTime<Utc>,
    pub local_size: u64,
    pub remote_size: u64,
}

/// How the user (or auto-policy) wants to resolve a conflict.
///
/// Key design principle from the Beebeeb UI: **never silently drop a version**.
/// Even when the user picks `KeepLocal` or `KeepRemote`, the losing version is
/// renamed to `"file (Device, timestamp).ext"` so nothing is lost.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConflictResolution {
    /// Use the local copy as the canonical version, rename the remote copy.
    KeepLocal,
    /// Use the remote copy as the canonical version, rename the local copy.
    KeepRemote,
    /// Rename both to unique names so neither is overwritten.
    #[default]
    KeepBoth,
}

/// Metadata about a file, used for conflict detection.
#[derive(Debug, Clone)]
pub struct FileMeta {
    pub path: PathBuf,
    pub modified: DateTime<Utc>,
    pub size: u64,
}

/// Compare local and remote file lists and return any conflicts.
///
/// A conflict exists when the same relative path appears in both lists with
/// different modification timestamps — meaning both sides changed the file
/// since the last successful sync.
pub fn detect_conflicts(
    local_files: &[FileMeta],
    remote_files: &[FileMeta],
    last_sync: Option<DateTime<Utc>>,
) -> Vec<Conflict> {
    let remote_map: std::collections::HashMap<&Path, &FileMeta> =
        remote_files.iter().map(|f| (f.path.as_path(), f)).collect();

    let mut conflicts = Vec::new();
    for local in local_files {
        if let Some(remote) = remote_map.get(local.path.as_path()) {
            let both_changed = match last_sync {
                Some(ts) => local.modified > ts && remote.modified > ts,
                // No previous sync — if timestamps differ, treat as conflict.
                None => local.modified != remote.modified,
            };
            if both_changed {
                conflicts.push(Conflict {
                    path: local.path.clone(),
                    local_modified: local.modified,
                    remote_modified: remote.modified,
                    local_size: local.size,
                    remote_size: remote.size,
                });
            }
        }
    }
    conflicts
}

/// Build the "loser" filename used when one version is renamed to make way for
/// the winner. Pattern from the design: `"file (Device, HH:MM).ext"`.
pub fn loser_filename(original: &Path, device_name: &str, timestamp: &DateTime<Utc>) -> PathBuf {
    let stem = original.file_stem().and_then(|s| s.to_str()).unwrap_or("file");
    let ext = original.extension().and_then(|e| e.to_str());
    let ts = timestamp.format("%H:%M");

    let new_name = match ext {
        Some(e) => format!("{stem} ({device_name}, {ts}).{e}"),
        None => format!("{stem} ({device_name}, {ts})"),
    };

    let mut result = original.to_path_buf();
    result.set_file_name(new_name);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn utc(hour: u32, min: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 4, 23, hour, min, 0).unwrap()
    }

    #[test]
    fn detects_conflict_when_both_sides_changed() {
        let last = utc(12, 0);
        let local = vec![FileMeta {
            path: PathBuf::from("story-draft.md"),
            modified: utc(14, 22),
            size: 14_200,
        }];
        let remote = vec![FileMeta {
            path: PathBuf::from("story-draft.md"),
            modified: utc(14, 8),
            size: 13_800,
        }];

        let conflicts = detect_conflicts(&local, &remote, Some(last));
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].path, PathBuf::from("story-draft.md"));
        assert_eq!(conflicts[0].local_size, 14_200);
        assert_eq!(conflicts[0].remote_size, 13_800);
    }

    #[test]
    fn no_conflict_when_only_local_changed() {
        let last = utc(12, 0);
        let local = vec![FileMeta {
            path: PathBuf::from("notes.txt"),
            modified: utc(13, 0),
            size: 500,
        }];
        let remote = vec![FileMeta {
            path: PathBuf::from("notes.txt"),
            modified: utc(11, 0), // before last sync
            size: 500,
        }];

        let conflicts = detect_conflicts(&local, &remote, Some(last));
        assert!(conflicts.is_empty());
    }

    #[test]
    fn no_conflict_for_local_only_files() {
        let local = vec![FileMeta {
            path: PathBuf::from("new-file.txt"),
            modified: utc(14, 0),
            size: 100,
        }];
        let remote: Vec<FileMeta> = vec![];

        let conflicts = detect_conflicts(&local, &remote, Some(utc(12, 0)));
        assert!(conflicts.is_empty());
    }

    #[test]
    fn conflict_without_prior_sync_when_timestamps_differ() {
        let local = vec![FileMeta {
            path: PathBuf::from("doc.md"),
            modified: utc(14, 0),
            size: 200,
        }];
        let remote = vec![FileMeta {
            path: PathBuf::from("doc.md"),
            modified: utc(13, 0),
            size: 210,
        }];

        let conflicts = detect_conflicts(&local, &remote, None);
        assert_eq!(conflicts.len(), 1);
    }

    #[test]
    fn loser_filename_includes_device_and_time() {
        let ts = utc(14, 8);
        let result = loser_filename(Path::new("story-draft.md"), "iPhone", &ts);
        assert_eq!(result, PathBuf::from("story-draft (iPhone, 14:08).md"));
    }

    #[test]
    fn loser_filename_works_without_extension() {
        let ts = utc(9, 5);
        let result = loser_filename(Path::new("Makefile"), "MacBook Pro", &ts);
        assert_eq!(result, PathBuf::from("Makefile (MacBook Pro, 09:05)"));
    }

    #[test]
    fn default_resolution_is_keep_both() {
        assert_eq!(ConflictResolution::default(), ConflictResolution::KeepBoth);
    }
}
