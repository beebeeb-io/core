use crate::config::SyncConfig;
use crate::conflict::{self, Conflict, ConflictResolution, FileMeta};
use crate::error::SyncError;
use crate::selective;
use crate::state::{FileState, SyncState, SyncStatus};
use crate::watcher::{FileChange, FileWatcher};
use chrono::Utc;
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};

/// An action the sync engine has decided to take during a sync cycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncOp {
    /// Upload a new or modified local file.
    Upload(PathBuf),
    /// Download a new or modified remote file.
    Download(PathBuf),
    /// Delete the remote copy (local file was removed).
    DeleteRemote(PathBuf),
    /// Delete the local copy (remote file was removed).
    DeleteLocal(PathBuf),
    /// A conflict that needs resolution before proceeding.
    Conflict(PathBuf),
}

/// Core sync engine — coordinates watching, diffing, and syncing.
pub struct SyncEngine {
    config: SyncConfig,
    state: SyncState,
    watcher: Option<FileWatcher>,
    /// Pending changes from the file watcher, accumulated between sync cycles.
    pending_changes: Vec<FileChange>,
    /// Selective-sync configuration derived from the sync mode.
    selective_config: selective::SelectiveConfig,
}

impl SyncEngine {
    pub fn new(config: SyncConfig) -> Self {
        let selective_config = selective_from_mode(&config.sync_mode);
        Self {
            config,
            state: SyncState::new(),
            watcher: None,
            pending_changes: Vec::new(),
            selective_config,
        }
    }

    /// Current sync state snapshot.
    pub fn state(&self) -> &SyncState {
        &self.state
    }

    /// Current config.
    pub fn config(&self) -> &SyncConfig {
        &self.config
    }

    /// Start the file watcher. Call this once to begin monitoring the vault.
    pub fn start(&mut self) -> Result<(), SyncError> {
        if self.watcher.is_some() {
            debug!("watcher already running");
            return Ok(());
        }

        info!(vault = %self.config.vault_path.display(), "starting sync engine");
        let watcher = FileWatcher::start(&self.config.vault_path)?;
        self.watcher = Some(watcher);
        self.state.status = SyncStatus::Idle;
        Ok(())
    }

    /// Stop the file watcher and mark the engine as idle.
    pub fn stop(&mut self) {
        info!("stopping sync engine");
        self.watcher = None;
        self.pending_changes.clear();
        self.state.status = SyncStatus::Idle;
    }

    /// Drain any pending file-system events from the watcher into the internal
    /// queue, so `sync_once` can process them.
    pub fn poll_watcher(&mut self) {
        if let Some(ref watcher) = self.watcher {
            let changes = watcher.drain_pending();
            if !changes.is_empty() {
                debug!(count = changes.len(), "new file-system events");
                self.pending_changes.extend(changes);
            }
        }
    }

    /// Perform a single sync cycle and return the list of operations.
    ///
    /// Steps:
    /// 1. List remote files via API (placeholder for now).
    /// 2. Compare with local file tree.
    /// 3. Detect conflicts (same file modified both locally and remotely).
    /// 4. Upload new/modified local files.
    /// 5. Download new/modified remote files.
    /// 6. Delete locally-removed files from remote (and vice versa).
    ///
    /// For now the actual upload/download calls are placeholder — they log
    /// what would happen. Real API integration will land when the backend
    /// file routes are finalized.
    pub fn sync_once(&mut self) -> Result<Vec<SyncOp>, SyncError> {
        info!("starting sync cycle");
        self.state.status = SyncStatus::Syncing {
            files_remaining: 0,
            bytes_remaining: 0,
        };

        // 1. List remote files (placeholder — would call the API).
        let remote_files = self.list_remote_files()?;

        // 2. Scan local file tree.
        let local_files = self.scan_local_files()?;

        // 3. Detect conflicts.
        let conflicts = conflict::detect_conflicts(&local_files, &remote_files, self.state.last_sync);
        for c in &conflicts {
            warn!(
                path = %c.path.display(),
                local = %c.local_modified,
                remote = %c.remote_modified,
                "conflict detected"
            );
            self.state.files.insert(c.path.clone(), FileState::Conflict);
        }

        // 4-6. Compute the operations list.
        let ops = self.compute_operations(&local_files, &remote_files, &conflicts);

        // Update counters.
        let remaining = ops
            .iter()
            .filter(|op| matches!(op, SyncOp::Upload(_) | SyncOp::Download(_)))
            .count() as u64;
        self.state.status = if remaining > 0 {
            SyncStatus::Syncing {
                files_remaining: remaining,
                bytes_remaining: 0, // would be computed from actual sizes
            }
        } else if !conflicts.is_empty() {
            SyncStatus::Error(format!("{} conflict(s) need resolution", conflicts.len()))
        } else {
            SyncStatus::Idle
        };

        // Execute placeholder operations (log only).
        for op in &ops {
            match op {
                SyncOp::Upload(p) => {
                    info!(path = %p.display(), "would upload");
                    self.state.files.insert(p.clone(), FileState::Uploading(0.0));
                }
                SyncOp::Download(p) => {
                    info!(path = %p.display(), "would download");
                    self.state.files.insert(p.clone(), FileState::Downloading(0.0));
                }
                SyncOp::DeleteRemote(p) => {
                    info!(path = %p.display(), "would delete from remote");
                    self.state.files.remove(p);
                }
                SyncOp::DeleteLocal(p) => {
                    // A file deleted on another device. Mirror the deletion to the
                    // local copy. `compute_operations` has already proven this is a
                    // genuine remote delete with NO unsynced local change (an
                    // unsynced edit is routed to `SyncOp::Conflict` instead and is
                    // never deleted), so removing the local mirror here cannot
                    // destroy local work. Best-effort + guarded: only clear the
                    // state entry once the on-disk file is actually gone, so a
                    // transient fs error retries next cycle instead of resurrecting.
                    if self.delete_local_file(p) {
                        info!(path = %p.display(), "deleted locally (removed remotely)");
                        self.state.files.remove(p);
                    }
                }
                SyncOp::Conflict(p) => {
                    debug!(path = %p.display(), "conflict queued for resolution");
                }
            }
        }

        // Mark sync time (even though we haven't actually transferred yet).
        self.state.last_sync = Some(Utc::now());
        self.pending_changes.clear();

        info!(ops = ops.len(), "sync cycle complete");
        Ok(ops)
    }

    /// Resolve a conflict for a given path.
    ///
    /// The "never silently drop" principle means even KeepLocal / KeepRemote
    /// will rename the losing version rather than deleting it.
    pub fn resolve_conflict(&mut self, path: &Path, resolution: ConflictResolution) -> Result<(), SyncError> {
        info!(
            path = %path.display(),
            resolution = ?resolution,
            "resolving conflict"
        );

        match resolution {
            ConflictResolution::KeepLocal => {
                // The remote version would be renamed to "file (Remote, HH:MM).ext"
                let loser = conflict::loser_filename(path, "Remote", &Utc::now());
                info!(loser = %loser.display(), "remote copy renamed (never dropped)");
                self.state.files.insert(path.to_path_buf(), FileState::Synced);
                self.state.files.insert(loser, FileState::Synced);
            }
            ConflictResolution::KeepRemote => {
                let loser = conflict::loser_filename(path, "This device", &Utc::now());
                info!(loser = %loser.display(), "local copy renamed (never dropped)");
                self.state.files.insert(path.to_path_buf(), FileState::Synced);
                self.state.files.insert(loser, FileState::Synced);
            }
            ConflictResolution::KeepBoth => {
                let loser_a = conflict::loser_filename(path, "Local", &Utc::now());
                let loser_b = conflict::loser_filename(path, "Remote", &Utc::now());
                info!(a = %loser_a.display(), b = %loser_b.display(), "both versions kept");
                self.state.files.insert(loser_a, FileState::Synced);
                self.state.files.insert(loser_b, FileState::Synced);
                self.state.files.remove(path);
            }
        }

        Ok(())
    }

    // ── Private helpers ─────────────────────────────────────────────────

    /// Placeholder: list remote files from the API.
    fn list_remote_files(&self) -> Result<Vec<FileMeta>, SyncError> {
        debug!(api = %self.config.api_url, "listing remote files (placeholder)");
        // Will call GET /v1/files once the API route exists.
        Ok(Vec::new())
    }

    /// Walk the local vault directory and collect file metadata.
    fn scan_local_files(&self) -> Result<Vec<FileMeta>, SyncError> {
        let mut files = Vec::new();
        if !self.config.vault_path.exists() {
            return Ok(files);
        }
        self.walk_dir(&self.config.vault_path, &mut files)?;
        debug!(count = files.len(), "scanned local files");
        Ok(files)
    }

    fn walk_dir(&self, dir: &Path, out: &mut Vec<FileMeta>) -> Result<(), SyncError> {
        let entries = std::fs::read_dir(dir)?;
        for entry in entries {
            let entry = entry?;
            let path = entry.path();

            // Respect selective sync.
            let rel = path.strip_prefix(&self.config.vault_path).unwrap_or(&path);
            if !selective::should_sync(rel, &self.selective_config) {
                continue;
            }

            if path.is_dir() {
                self.walk_dir(&path, out)?;
            } else {
                let meta = std::fs::metadata(&path)?;
                let modified = meta.modified().unwrap_or(std::time::SystemTime::UNIX_EPOCH);
                let modified: chrono::DateTime<Utc> = modified.into();
                out.push(FileMeta {
                    path: rel.to_path_buf(),
                    modified,
                    size: meta.len(),
                });
            }
        }
        Ok(())
    }

    /// Decide what to upload, download, or delete based on local/remote diff.
    fn compute_operations(
        &self,
        local_files: &[FileMeta],
        remote_files: &[FileMeta],
        conflicts: &[Conflict],
    ) -> Vec<SyncOp> {
        let mut ops = Vec::new();

        let remote_set: std::collections::HashSet<&Path> = remote_files.iter().map(|f| f.path.as_path()).collect();
        let local_set: std::collections::HashSet<&Path> = local_files.iter().map(|f| f.path.as_path()).collect();
        let conflict_set: std::collections::HashSet<&Path> = conflicts.iter().map(|c| c.path.as_path()).collect();

        // Files only on local -> upload.
        for local in local_files {
            if conflict_set.contains(local.path.as_path()) {
                ops.push(SyncOp::Conflict(local.path.clone()));
            } else if !remote_set.contains(local.path.as_path()) {
                // The path is absent from the remote snapshot. This is EITHER a
                // genuine remote delete (the file was synced before and another
                // device deleted it) OR a brand-new local file that has never
                // been uploaded. The `state.files` entry is the discriminator —
                // exactly the desktop analog of the CLI's manifest-based
                // `classify_remote_absent` (cli/src/commands/sync.rs):
                match self.classify_remote_absent(&local.path) {
                    RemoteAbsent::DeleteLocal => {
                        // Synced before, clean on disk → server is authoritative
                        // and the file is recoverable from server trash, so
                        // mirror the deletion locally.
                        ops.push(SyncOp::DeleteLocal(local.path.clone()));
                    }
                    RemoteAbsent::KeepLocalEdit => {
                        // DATA-SAFETY GATE: the file was synced before but has an
                        // unsynced LOCAL change (Modified / Uploading / Conflict).
                        // NEVER destroy an unsynced local edit on a remote delete —
                        // surface it as a conflict so the existing `KeepBoth`
                        // policy keeps the local copy (the upload pass re-adds it).
                        ops.push(SyncOp::Conflict(local.path.clone()));
                    }
                    RemoteAbsent::NewLocalFile => {
                        // Never synced → genuinely new; upload as before.
                        ops.push(SyncOp::Upload(local.path.clone()));
                    }
                }
            }
        }

        // Files only on remote -> download.
        for remote in remote_files {
            if !local_set.contains(remote.path.as_path()) && !conflict_set.contains(remote.path.as_path()) {
                ops.push(SyncOp::Download(remote.path.clone()));
            }
        }

        // Prior-synced paths that are gone from BOTH disk and the remote snapshot:
        // a completed remote delete whose local mirror is already gone too. Nothing
        // to delete on disk, but the stale `state.files` entry must be dropped or it
        // is silently resurrected on a later round-trip (the CLI's `(None, Some(_))`
        // arm — task 0806). Emit a `DeleteLocal` so the exec loop clears state; the
        // best-effort fs unlink is a no-op (already absent).
        for (rel, st) in &self.state.files {
            if local_set.contains(rel.as_path()) {
                continue; // still on disk — handled by the local pass above
            }
            if remote_set.contains(rel.as_path()) {
                continue; // still on the server — not a delete
            }
            // Only previously-settled rows. A mid-transfer row (Uploading /
            // Downloading) or an unresolved Conflict is not a completed delete.
            // (`Modified` is excluded too: an unsynced-edit row whose file is gone
            // from disk is ambiguous — leave it for the next cycle rather than
            // prune it here.)
            if matches!(st, FileState::Synced | FileState::OnlineOnly) {
                ops.push(SyncOp::DeleteLocal(rel.clone()));
            }
        }

        // Files from pending_changes that were deleted locally.
        for change in &self.pending_changes {
            if let FileChange::Deleted(p) = change {
                let rel = p.strip_prefix(&self.config.vault_path).unwrap_or(p);
                if remote_set.contains(rel) {
                    ops.push(SyncOp::DeleteRemote(rel.to_path_buf()));
                }
            }
        }

        ops
    }

    /// Classify a local file whose relative path is absent from the current
    /// remote snapshot. This is the ONE place the remote-delete vs unsynced-edit
    /// decision lives for the desktop engine, kept byte-for-byte consistent with
    /// the CLI's `classify_remote_absent` (cli/src/commands/sync.rs) so every
    /// client makes the identical call.
    ///
    /// The discriminator is the per-file [`FileState`] recorded in
    /// [`SyncState::files`] — the engine's in-model equivalent of the CLI's
    /// content-hashed manifest entry:
    ///
    /// - `Synced` / `OnlineOnly` → the file matched the remote at the last sync
    ///   and has no unsynced local change. Its disappearance from the snapshot is
    ///   a genuine REMOTE DELETE → [`RemoteAbsent::DeleteLocal`].
    /// - `Modified` / `Uploading` / `Conflict` → there IS an unsynced local change.
    ///   Deleting would destroy unsynced work, so we KEEP it →
    ///   [`RemoteAbsent::KeepLocalEdit`] (the CLI's `ReAddLocal`).
    /// - No state entry → the file was never synced; it is a brand-new local file,
    ///   not a delete → [`RemoteAbsent::NewLocalFile`] (the CLI's `NotADelete`).
    fn classify_remote_absent(&self, rel: &Path) -> RemoteAbsent {
        match self.state.files.get(rel) {
            // Settled, server-matched, clean on disk → safe to mirror the delete.
            Some(FileState::Synced) | Some(FileState::OnlineOnly) => RemoteAbsent::DeleteLocal,
            // Any unsettled state (an unsynced edit, an in-flight transfer, or an
            // open conflict) carries content we must not destroy on a remote
            // delete. Keep the local copy; the conflict/upload pass handles it.
            Some(FileState::Modified)
            | Some(FileState::Uploading(_))
            | Some(FileState::Downloading(_))
            | Some(FileState::Conflict) => RemoteAbsent::KeepLocalEdit,
            None => RemoteAbsent::NewLocalFile,
        }
    }

    /// Best-effort, guarded local filesystem delete for a `DeleteLocal` op.
    ///
    /// The engine owns the local fs mutations it performs directly (it already
    /// reads the vault in `scan_local_files`), so — matching the CLI's
    /// `reconcile_remote_deletions` — it unlinks `vault_path/rel` here rather than
    /// delegating to the desktop runtime. Returns `true` when the local mirror is
    /// gone after the call (either we removed it or it was already absent), so the
    /// caller may clear it from state; `false` on a real error (e.g. permission),
    /// so the state entry is preserved and the delete is retried next cycle.
    ///
    /// Never panics: a `NotFound` is treated as success (the user may have already
    /// removed it); any other error is logged and reported as a non-removal.
    fn delete_local_file(&self, rel: &Path) -> bool {
        let abs = self.config.vault_path.join(rel);
        match std::fs::remove_file(&abs) {
            Ok(()) => true,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => true,
            Err(e) => {
                warn!(path = %abs.display(), error = %e, "could not remove locally-deleted file; will retry");
                false
            }
        }
    }
}

/// What to do with a local file whose relative path is absent from the remote
/// snapshot. Mirrors the CLI's `RemoteAbsent` (the desktop equivalent of its
/// `DeleteLocal` / `ReAddLocal` / `NotADelete` arms).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RemoteAbsent {
    /// Synced before, no unsynced local change → genuine remote delete; remove
    /// the local mirror.
    DeleteLocal,
    /// Synced before but has an unsynced LOCAL change → never destroy it; keep
    /// the local copy (surfaced as a conflict so `KeepBoth` re-adds it).
    KeepLocalEdit,
    /// Never synced → a brand-new local file, not a delete; upload it.
    NewLocalFile,
}

/// Derive a `SelectiveConfig` from the high-level `SyncMode`.
fn selective_from_mode(mode: &crate::config::SyncMode) -> selective::SelectiveConfig {
    match mode {
        crate::config::SyncMode::Full => selective::SelectiveConfig::full(),
        crate::config::SyncMode::OnlineOnly => selective::SelectiveConfig::online_only(),
        crate::config::SyncMode::Custom(folders) => selective::SelectiveConfig::custom(folders.clone(), Vec::new()),
        crate::config::SyncMode::Smart => {
            // Smart mode syncs everything for now — real heuristics (recent, starred,
            // shared) will come once the API provides those signals.
            selective::SelectiveConfig::full()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn test_config(dir: &Path) -> SyncConfig {
        SyncConfig::new(dir.to_path_buf(), "https://api.beebeeb.io".into(), "tok_test".into())
    }

    #[test]
    fn sync_once_uploads_local_only_files() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("notes.txt"), "hello").unwrap();
        fs::write(dir.path().join("draft.md"), "world").unwrap();

        let mut cfg = test_config(dir.path());
        cfg.sync_mode = crate::config::SyncMode::Full;
        let mut engine = SyncEngine::new(cfg);

        let ops = engine.sync_once().unwrap();

        // Both files should be queued for upload (no remote files).
        let uploads: Vec<_> = ops
            .iter()
            .filter_map(|op| match op {
                SyncOp::Upload(p) => Some(p.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(uploads.len(), 2);
        assert!(uploads.contains(&PathBuf::from("notes.txt")));
        assert!(uploads.contains(&PathBuf::from("draft.md")));
    }

    #[test]
    fn sync_once_respects_selective_sync() {
        let dir = TempDir::new().unwrap();
        fs::create_dir_all(dir.path().join("photos")).unwrap();
        fs::create_dir_all(dir.path().join("archive")).unwrap();
        fs::write(dir.path().join("photos/cat.jpg"), "meow").unwrap();
        fs::write(dir.path().join("archive/old.zip"), "zzzz").unwrap();

        let mut cfg = test_config(dir.path());
        cfg.sync_mode = crate::config::SyncMode::Custom(vec!["photos/".into()]);
        let mut engine = SyncEngine::new(cfg);

        let ops = engine.sync_once().unwrap();

        let uploads: Vec<_> = ops
            .iter()
            .filter_map(|op| match op {
                SyncOp::Upload(p) => Some(p.clone()),
                _ => None,
            })
            .collect();
        // Only the photos file should be uploaded.
        assert_eq!(uploads.len(), 1);
        assert_eq!(uploads[0], PathBuf::from("photos/cat.jpg"));
    }

    #[test]
    fn sync_once_marks_last_sync() {
        let dir = TempDir::new().unwrap();
        let cfg = test_config(dir.path());
        let mut engine = SyncEngine::new(cfg);

        assert!(engine.state().last_sync.is_none());
        engine.sync_once().unwrap();
        assert!(engine.state().last_sync.is_some());
    }

    #[test]
    fn engine_start_stop_lifecycle() {
        let dir = TempDir::new().unwrap();
        let cfg = test_config(dir.path());
        let mut engine = SyncEngine::new(cfg);

        engine.start().unwrap();
        assert!(engine.watcher.is_some());
        assert_eq!(engine.state().status, SyncStatus::Idle);

        engine.stop();
        assert!(engine.watcher.is_none());
    }

    #[test]
    fn resolve_conflict_keep_both_removes_original() {
        let dir = TempDir::new().unwrap();
        let cfg = test_config(dir.path());
        let mut engine = SyncEngine::new(cfg);

        let path = PathBuf::from("story-draft.md");
        engine.state.files.insert(path.clone(), FileState::Conflict);

        engine.resolve_conflict(&path, ConflictResolution::KeepBoth).unwrap();

        // Original path should be gone, replaced by two renamed copies.
        assert!(!engine.state.files.contains_key(&path));
        assert!(engine.state.files.len() >= 2);
    }

    #[test]
    fn resolve_conflict_keep_local_preserves_both() {
        let dir = TempDir::new().unwrap();
        let cfg = test_config(dir.path());
        let mut engine = SyncEngine::new(cfg);

        let path = PathBuf::from("report.pdf");
        engine.state.files.insert(path.clone(), FileState::Conflict);

        engine.resolve_conflict(&path, ConflictResolution::KeepLocal).unwrap();

        // Original path is marked Synced, plus the renamed remote copy.
        assert_eq!(engine.state.files.get(&path), Some(&FileState::Synced));
        // There should be a second entry for the loser.
        assert!(engine.state.files.len() >= 2);
    }

    // ── Remote-delete reconciliation (task 0865) ────────────────────────────
    //
    // `compute_operations` is the producer; these tests drive it directly with
    // crafted local/remote snapshots + a seeded `state.files` (the discriminator),
    // which is exactly how the desktop engine knows whether an absent-from-remote
    // path is a genuine remote delete vs an unsynced local edit vs a new file.

    fn meta(rel: &str) -> FileMeta {
        FileMeta {
            path: PathBuf::from(rel),
            modified: Utc::now(),
            size: 5,
        }
    }

    /// (a) Present locally + absent remotely + CLEAN (previously Synced)
    ///     → produces `DeleteLocal`, NOT `Upload`.
    #[test]
    fn remote_delete_of_clean_synced_file_produces_delete_local() {
        let dir = TempDir::new().unwrap();
        let engine = SyncEngine::new(test_config(dir.path()));

        let path = PathBuf::from("notes.txt");
        let mut engine = engine;
        // The file was synced on a previous cycle → it is clean.
        engine.state.files.insert(path.clone(), FileState::Synced);

        // Local has it; remote no longer does (deleted on another device).
        let local = vec![meta("notes.txt")];
        let remote: Vec<FileMeta> = vec![];

        let ops = engine.compute_operations(&local, &remote, &[]);

        assert!(
            ops.contains(&SyncOp::DeleteLocal(path.clone())),
            "a clean, previously-synced file removed remotely must produce DeleteLocal; got {ops:?}"
        );
        assert!(
            !ops.iter().any(|op| matches!(op, SyncOp::Upload(_))),
            "a remote delete must NOT be re-uploaded (resurrected); got {ops:?}"
        );
    }

    /// (b) Present locally + absent remotely + LOCALLY-MODIFIED
    ///     → does NOT produce `DeleteLocal`; keeps the file (Conflict).
    ///     DATA-SAFETY: an unsynced local edit is never destroyed.
    #[test]
    fn remote_delete_of_locally_modified_file_is_never_deleted() {
        let dir = TempDir::new().unwrap();
        let mut engine = SyncEngine::new(test_config(dir.path()));

        let path = PathBuf::from("draft.md");
        // The file has an unsynced LOCAL change.
        engine.state.files.insert(path.clone(), FileState::Modified);

        let local = vec![meta("draft.md")];
        let remote: Vec<FileMeta> = vec![];

        let ops = engine.compute_operations(&local, &remote, &[]);

        assert!(
            !ops.contains(&SyncOp::DeleteLocal(path.clone())),
            "a locally-modified file removed remotely must NEVER produce DeleteLocal; got {ops:?}"
        );
        assert!(
            ops.contains(&SyncOp::Conflict(path.clone())),
            "a locally-modified file removed remotely must be kept (surfaced as Conflict); got {ops:?}"
        );
    }

    /// An in-flight upload removed remotely is likewise never auto-deleted.
    #[test]
    fn remote_delete_of_uploading_file_is_never_deleted() {
        let dir = TempDir::new().unwrap();
        let mut engine = SyncEngine::new(test_config(dir.path()));

        let path = PathBuf::from("video.mov");
        engine.state.files.insert(path.clone(), FileState::Uploading(0.4));

        let ops = engine.compute_operations(&[meta("video.mov")], &[], &[]);

        assert!(!ops.contains(&SyncOp::DeleteLocal(path.clone())));
        assert!(ops.contains(&SyncOp::Conflict(path)));
    }

    /// A genuinely-new local file (never synced, no state entry) absent from the
    /// remote is an Upload — NOT a delete.
    #[test]
    fn new_local_file_absent_remotely_is_uploaded_not_deleted() {
        let dir = TempDir::new().unwrap();
        let engine = SyncEngine::new(test_config(dir.path()));

        let path = PathBuf::from("fresh.txt");
        // No state entry → never synced.

        let ops = engine.compute_operations(&[meta("fresh.txt")], &[], &[]);

        assert!(ops.contains(&SyncOp::Upload(path.clone())));
        assert!(!ops.contains(&SyncOp::DeleteLocal(path)));
    }

    /// (c) The exec path removes the file from disk AND clears it from state.
    #[test]
    fn sync_once_delete_local_removes_file_and_state() {
        let dir = TempDir::new().unwrap();
        // A previously-synced file that exists on disk.
        let on_disk = dir.path().join("gone.txt");
        fs::write(&on_disk, "bye").unwrap();

        let mut cfg = test_config(dir.path());
        cfg.sync_mode = crate::config::SyncMode::Full;
        let mut engine = SyncEngine::new(cfg);

        let rel = PathBuf::from("gone.txt");
        engine.state.files.insert(rel.clone(), FileState::Synced);

        // `list_remote_files` is the placeholder empty snapshot, so the on-disk,
        // previously-synced file is absent from remote → a remote delete.
        let ops = engine.sync_once().unwrap();

        assert!(
            ops.contains(&SyncOp::DeleteLocal(rel.clone())),
            "expected DeleteLocal for the remotely-removed file; got {ops:?}"
        );
        // Exec removed it from disk …
        assert!(!on_disk.exists(), "the local mirror file must be removed from disk");
        // … and cleared it from state.
        assert!(
            !engine.state().files.contains_key(&rel),
            "the state entry must be cleared after the local delete"
        );
    }

    /// The exec delete is best-effort: an already-gone file is fine (NotFound is
    /// treated as success), and the state entry is still cleared.
    #[test]
    fn sync_once_delete_local_already_gone_clears_state() {
        let dir = TempDir::new().unwrap();
        let mut cfg = test_config(dir.path());
        cfg.sync_mode = crate::config::SyncMode::Full;
        let mut engine = SyncEngine::new(cfg);

        // Synced row whose on-disk file is already gone (and absent from remote):
        // a completed remote delete with the local mirror already removed.
        let rel = PathBuf::from("already-gone.txt");
        engine.state.files.insert(rel.clone(), FileState::Synced);

        let ops = engine.sync_once().unwrap();

        assert!(ops.contains(&SyncOp::DeleteLocal(rel.clone())));
        assert!(
            !engine.state().files.contains_key(&rel),
            "a stale settled row gone from both disk and remote must be pruned"
        );
    }

    /// A locally-modified file whose remote was deleted survives a full
    /// `sync_once` cycle on disk — end-to-end data-safety guarantee.
    #[test]
    fn sync_once_never_deletes_locally_modified_file_on_disk() {
        let dir = TempDir::new().unwrap();
        let on_disk = dir.path().join("keep-me.md");
        fs::write(&on_disk, "unsynced edit").unwrap();

        let mut cfg = test_config(dir.path());
        cfg.sync_mode = crate::config::SyncMode::Full;
        let mut engine = SyncEngine::new(cfg);

        let rel = PathBuf::from("keep-me.md");
        engine.state.files.insert(rel.clone(), FileState::Modified);

        let ops = engine.sync_once().unwrap();

        assert!(!ops.contains(&SyncOp::DeleteLocal(rel.clone())));
        assert!(
            on_disk.exists(),
            "a locally-modified file must NEVER be deleted on a remote delete"
        );
    }
}
