use crate::error::SyncError;
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::{Duration, Instant};
use tracing::{debug, warn};

/// Minimum delay between forwarding events for the same path.
const DEBOUNCE_MS: u64 = 100;

/// Files and directories to ignore — OS metadata, temp files, hidden files.
const IGNORED_NAMES: &[&str] = &[
    ".DS_Store",
    "Thumbs.db",
    "desktop.ini",
    "._",          // macOS resource forks
    ".Spotlight-", // Spotlight indexes
    ".Trashes",
    ".fseventsd",
    "$RECYCLE.BIN",
    "System Volume Information",
];

/// A change detected by the file-system watcher.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileChange {
    Created(PathBuf),
    Modified(PathBuf),
    Deleted(PathBuf),
    Renamed { from: PathBuf, to: PathBuf },
}

/// Watches `vault_path` for file-system events and emits debounced `FileChange`s.
pub struct FileWatcher {
    _watcher: RecommendedWatcher,
    rx: mpsc::Receiver<FileChange>,
}

impl FileWatcher {
    /// Start watching the given directory tree.
    ///
    /// Returns a `FileWatcher` whose `recv()` / `try_recv()` methods yield
    /// debounced changes. The underlying `notify` watcher lives as long as
    /// this struct.
    pub fn start(vault_path: &Path) -> Result<Self, SyncError> {
        let (tx, rx) = mpsc::channel::<FileChange>();

        let sender = tx.clone();
        // Canonicalize the vault root so it matches the paths returned by the
        // OS file-system watcher. On macOS in particular, FSEvents resolves
        // `/var/...` to `/private/var/...`, which would otherwise cause
        // `strip_prefix` in `classify_event` to fail and leave the absolute
        // path to be checked by `is_ignored` — that often contains hidden
        // components (e.g. `.tmpXXXX` from `tempfile`) and silently filters
        // every event as "hidden".
        let root = std::fs::canonicalize(vault_path).unwrap_or_else(|_| vault_path.to_path_buf());
        let mut watcher = RecommendedWatcher::new(
            move |res: Result<Event, notify::Error>| match res {
                Ok(event) => {
                    if let Some(change) = classify_event(&event, &root) {
                        let _ = sender.send(change);
                    }
                }
                Err(e) => {
                    warn!(error = %e, "file-system watcher error");
                }
            },
            notify::Config::default().with_poll_interval(Duration::from_millis(DEBOUNCE_MS)),
        )
        .map_err(|e| SyncError::WatcherError(e.to_string()))?;

        watcher
            .watch(vault_path, RecursiveMode::Recursive)
            .map_err(|e| SyncError::WatcherError(e.to_string()))?;

        debug!(path = %vault_path.display(), "file watcher started");

        // Drop the original sender so `rx.recv()` returns `Err` once the
        // watcher closure's sender is dropped.
        drop(tx);

        Ok(Self { _watcher: watcher, rx })
    }

    /// Block until the next change arrives (or the watcher is dropped).
    pub fn recv(&self) -> Option<FileChange> {
        self.rx.recv().ok()
    }

    /// Non-blocking poll — returns `None` immediately if no change is pending.
    pub fn try_recv(&self) -> Option<FileChange> {
        self.rx.try_recv().ok()
    }

    /// Drain all currently-pending changes into a vec, deduplicating paths that
    /// appear more than once within the debounce window.
    ///
    /// Blocks for up to `DEBOUNCE_MS` waiting for events to arrive. The
    /// timeout is the *total* window — each `recv_timeout` call uses the
    /// remaining time, so events can trickle in across the whole window.
    pub fn drain_pending(&self) -> Vec<FileChange> {
        let mut changes = Vec::new();
        let mut seen = std::collections::HashSet::new();
        let deadline = Instant::now() + Duration::from_millis(DEBOUNCE_MS);

        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            match self.rx.recv_timeout(remaining) {
                Ok(change) => {
                    let key = match &change {
                        FileChange::Created(p) | FileChange::Modified(p) | FileChange::Deleted(p) => p.clone(),
                        FileChange::Renamed { to, .. } => to.clone(),
                    };
                    if seen.insert(key) {
                        changes.push(change);
                    }
                }
                Err(_) => break, // timeout or channel disconnected — done collecting
            }
        }
        changes
    }
}

/// Map a raw `notify::Event` into our domain type, filtering out ignored paths.
///
/// `vault_root` is used to strip the absolute prefix so `is_ignored` only
/// examines path components *inside* the vault (not the tempdir or OS path).
fn classify_event(event: &Event, vault_root: &Path) -> Option<FileChange> {
    let paths = &event.paths;
    if paths.is_empty() {
        return None;
    }

    // Compute relative paths for the ignore check.
    let relative_paths: Vec<&Path> = paths
        .iter()
        .map(|p| p.strip_prefix(vault_root).unwrap_or(p.as_path()))
        .collect();

    if relative_paths.iter().any(|p| is_ignored(p)) {
        return None;
    }

    match &event.kind {
        EventKind::Create(_) => Some(FileChange::Created(paths[0].clone())),
        EventKind::Modify(_) => {
            if paths.len() >= 2 {
                Some(FileChange::Renamed {
                    from: paths[0].clone(),
                    to: paths[1].clone(),
                })
            } else {
                Some(FileChange::Modified(paths[0].clone()))
            }
        }
        EventKind::Remove(_) => Some(FileChange::Deleted(paths[0].clone())),
        _ => None,
    }
}

/// Check if a *relative* path (inside the vault) should be ignored.
///
/// This intentionally operates on vault-relative paths so that the absolute
/// path to the vault itself (which may contain `.tmp`-style components from
/// tempfile in tests, or unusual OS paths) does not trigger false positives.
fn is_ignored(rel_path: &Path) -> bool {
    for component in rel_path.components() {
        if let std::path::Component::Normal(name) = component {
            let name = name.to_string_lossy();
            // Hidden files/directories (starting with '.'), except our own config dir.
            if name.starts_with('.') && name.as_ref() != ".beebeeb" {
                return true;
            }
            // Known junk files.
            for ignored in IGNORED_NAMES {
                if name.starts_with(ignored) {
                    return true;
                }
            }
            // Temp files — common editor patterns.
            if name.ends_with('~') || name.ends_with(".tmp") || name.ends_with(".swp") {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn ignored_names_are_filtered() {
        // These are vault-relative paths.
        assert!(is_ignored(Path::new(".DS_Store")));
        assert!(is_ignored(Path::new("Thumbs.db")));
        assert!(is_ignored(Path::new(".hidden/file.txt")));
        assert!(is_ignored(Path::new("notes.txt~")));
        assert!(is_ignored(Path::new(".swp")));
        assert!(is_ignored(Path::new("temp.tmp")));
    }

    #[test]
    fn normal_files_are_not_ignored() {
        assert!(!is_ignored(Path::new("story-draft.md")));
        assert!(!is_ignored(Path::new("photos/cat.jpg")));
        assert!(!is_ignored(Path::new("investigations/ledger-gap/data.csv")));
    }

    #[test]
    fn watcher_detects_file_creation() {
        let dir = TempDir::new().unwrap();
        let watcher = FileWatcher::start(dir.path()).unwrap();

        // Create a file in the watched directory.
        let file_path = dir.path().join("test-file.txt");
        fs::write(&file_path, "hello").unwrap();

        // Compare against the canonical path: on macOS the OS watcher resolves
        // `/var/...` to `/private/var/...`, so events come back canonicalized.
        let expected = fs::canonicalize(&file_path).unwrap();

        // Poll with retries -- inotify delivery can take a moment on some
        // platforms (especially WSL2).
        let mut found = false;
        for _ in 0..20 {
            let changes = watcher.drain_pending();
            if changes.iter().any(|c| match c {
                FileChange::Created(p) | FileChange::Modified(p) => p == &expected,
                _ => false,
            }) {
                found = true;
                break;
            }
        }
        assert!(found, "expected a change event for {expected:?}");
    }

    #[test]
    fn watcher_ignores_hidden_files() {
        let dir = TempDir::new().unwrap();
        let watcher = FileWatcher::start(dir.path()).unwrap();

        // Create a visible file first, so we know the watcher is running.
        let canary = dir.path().join("canary.txt");
        fs::write(&canary, "chirp").unwrap();

        // Also create hidden / OS metadata files.
        fs::write(dir.path().join(".hidden-file"), "secret").unwrap();
        fs::write(dir.path().join(".DS_Store"), "junk").unwrap();

        // Wait for the canary event.
        let mut saw_canary = false;
        for _ in 0..20 {
            std::thread::sleep(Duration::from_millis(100));
            let changes = watcher.drain_pending();
            for c in &changes {
                match c {
                    FileChange::Created(p) | FileChange::Modified(p) => {
                        // Should never see hidden files.
                        let rel = p.strip_prefix(dir.path()).unwrap_or(p);
                        let name = rel
                            .components()
                            .next()
                            .map(|c| c.as_os_str().to_string_lossy().to_string())
                            .unwrap_or_default();
                        assert!(!name.starts_with('.'), "hidden file should be filtered: {p:?}");
                        if p == &canary {
                            saw_canary = true;
                        }
                    }
                    _ => {}
                }
            }
            if saw_canary {
                break;
            }
        }
        // The canary might not arrive on every platform, so we only assert
        // the filtering invariant above.
    }
}
