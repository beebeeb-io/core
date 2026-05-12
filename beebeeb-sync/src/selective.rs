use serde::{Deserialize, Serialize};
use std::path::Path;

/// Configuration for selective sync — which folders live on disk vs online-only.
///
/// Mirrors the UI from the "What to keep on this Mac" / selective-sync tree,
/// where users check/uncheck folders.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelectiveConfig {
    /// Folder prefixes that should be synced to disk.
    /// Everything else is treated as online-only.
    /// An empty list means nothing is synced (purely online-only mode).
    /// Use `"/"` or `""` to mean "sync everything".
    pub included_paths: Vec<String>,

    /// Folder prefixes that are explicitly excluded even if a parent is included.
    pub excluded_paths: Vec<String>,
}

impl SelectiveConfig {
    /// Full sync — everything on disk.
    pub fn full() -> Self {
        Self {
            included_paths: vec![String::new()],
            excluded_paths: Vec::new(),
        }
    }

    /// Online-only — nothing on disk.
    pub fn online_only() -> Self {
        Self {
            included_paths: Vec::new(),
            excluded_paths: Vec::new(),
        }
    }

    /// Custom selection of specific folders.
    pub fn custom(included: Vec<String>, excluded: Vec<String>) -> Self {
        Self {
            included_paths: included,
            excluded_paths: excluded,
        }
    }
}

/// Whether a given file path should be stored on disk.
///
/// Returns `true` if:
/// - The path falls under an included prefix (e.g. `photos/cat.jpg` matches `photos/`), OR
/// - The path is a parent of an included prefix (e.g. directory `photos` matches `photos/`),
///   so directory traversal can descend into included subtrees.
///
/// Returns `false` if the path matches an exclusion, regardless of inclusions.
pub fn should_sync(path: &Path, config: &SelectiveConfig) -> bool {
    let path_str = path.to_string_lossy();

    // Check exclusions first — they win over inclusions.
    for exc in &config.excluded_paths {
        if path_str.starts_with(exc.as_str()) {
            return false;
        }
    }

    // If nothing is included, nothing syncs.
    if config.included_paths.is_empty() {
        return false;
    }

    // Normalise: ensure the path has a trailing slash for parent-prefix matching.
    let path_as_dir = if path_str.ends_with('/') {
        path_str.to_string()
    } else {
        format!("{path_str}/")
    };

    for inc in &config.included_paths {
        if inc.is_empty() {
            // Empty string = "sync everything".
            return true;
        }
        // Path is inside the included prefix (file or subdirectory).
        if path_str.starts_with(inc.as_str()) {
            return true;
        }
        // Path is a parent directory of the included prefix — allow descent.
        if inc.starts_with(path_as_dir.as_str()) {
            return true;
        }
    }

    false
}

/// Summary of disk usage under a selective-sync config.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskUsage {
    /// Bytes stored on local disk.
    pub on_disk_bytes: u64,
    /// Bytes kept online-only (not on disk).
    pub online_only_bytes: u64,
    /// Number of files on disk.
    pub on_disk_files: u64,
    /// Number of files online-only.
    pub online_only_files: u64,
}

/// A file with its size, used for disk-usage calculation.
#[derive(Debug, Clone)]
pub struct FileEntry {
    pub path: std::path::PathBuf,
    pub size: u64,
}

/// Calculate how much disk space a selective-sync config would use given the
/// full file listing from the vault.
pub fn calculate_disk_usage(config: &SelectiveConfig, files: &[FileEntry]) -> DiskUsage {
    let mut usage = DiskUsage {
        on_disk_bytes: 0,
        online_only_bytes: 0,
        on_disk_files: 0,
        online_only_files: 0,
    };

    for file in files {
        if should_sync(&file.path, config) {
            usage.on_disk_bytes += file.size;
            usage.on_disk_files += 1;
        } else {
            usage.online_only_bytes += file.size;
            usage.online_only_files += 1;
        }
    }

    usage
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};

    #[test]
    fn full_sync_includes_everything() {
        let cfg = SelectiveConfig::full();
        assert!(should_sync(Path::new("investigations/story.md"), &cfg));
        assert!(should_sync(Path::new("photos/cat.jpg"), &cfg));
        assert!(should_sync(Path::new("archive/old.zip"), &cfg));
    }

    #[test]
    fn online_only_excludes_everything() {
        let cfg = SelectiveConfig::online_only();
        assert!(!should_sync(Path::new("anything.txt"), &cfg));
        assert!(!should_sync(Path::new("deep/nested/file.md"), &cfg));
    }

    #[test]
    fn custom_includes_only_listed_folders() {
        let cfg = SelectiveConfig::custom(vec!["investigations/".into(), "photos/".into()], Vec::new());
        assert!(should_sync(Path::new("investigations/story.md"), &cfg));
        assert!(should_sync(Path::new("investigations/ledger-gap/data.csv"), &cfg));
        assert!(should_sync(Path::new("photos/cat.jpg"), &cfg));
        assert!(!should_sync(Path::new("archive/old.zip"), &cfg));
        assert!(!should_sync(Path::new("sketches/draft.png"), &cfg));
    }

    #[test]
    fn exclusions_override_inclusions() {
        let cfg = SelectiveConfig::custom(
            vec!["investigations/".into()],
            vec!["investigations/interviews-raw/".into()],
        );
        assert!(should_sync(Path::new("investigations/ledger-gap/doc.md"), &cfg));
        assert!(!should_sync(
            Path::new("investigations/interviews-raw/tape-01.m4a"),
            &cfg
        ));
    }

    #[test]
    fn disk_usage_partitions_files_correctly() {
        let cfg = SelectiveConfig::custom(vec!["photos/".into()], Vec::new());
        let files = vec![
            FileEntry {
                path: PathBuf::from("photos/cat.jpg"),
                size: 2_000_000,
            },
            FileEntry {
                path: PathBuf::from("photos/dog.jpg"),
                size: 3_000_000,
            },
            FileEntry {
                path: PathBuf::from("archive/old.zip"),
                size: 10_000_000,
            },
        ];

        let usage = calculate_disk_usage(&cfg, &files);
        assert_eq!(usage.on_disk_bytes, 5_000_000);
        assert_eq!(usage.online_only_bytes, 10_000_000);
        assert_eq!(usage.on_disk_files, 2);
        assert_eq!(usage.online_only_files, 1);
    }
}
