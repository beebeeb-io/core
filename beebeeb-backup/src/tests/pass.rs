//! `run_pass` against `FakeHost`, a host that keeps its records and server
//! tree in memory and records every call, over real temporary source folders.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Mutex;

use beebeeb_core::backup::{BackupRecord, FolderPresence, PassBudget, RecordRef, RecordState, RemoteEntry, SkipReason};
use beebeeb_types::backup::Category;
use uuid::Uuid;

use super::TempDir;
use crate::pass::{Handoff, PassFs, handoff, run_pass_with};
use crate::walk::walk_with_paths;
use crate::{BackupHost, DeviceTree, Fingerprint, HostError, UploadRequest, fingerprint, run_pass};

const BUDGET: PassBudget = PassBudget {
    max_uploads: 256,
    max_bytes: u64::MAX,
};

#[derive(Default)]
struct State {
    category_id: Uuid,
    device_folder_live: bool,
    category_folder_live: Option<bool>,
    /// (parent, name) -> id, so a repeated ensure returns the same folder.
    folders: HashMap<(Uuid, String), Uuid>,
    /// remote id -> (key under the category folder, size, uploaded_at_ms)
    files: HashMap<Uuid, (String, u64, i64)>,
    records: Vec<BackupRecord>,
    calls: Vec<String>,
    queued: Vec<UploadRequest>,
    /// The client finishes every queued upload right after the next
    /// `records` call returns (an upload completing mid-pass).
    finish_after_next_records: bool,
    /// What `device_tree` reports as `complete`.
    listing_complete: bool,
    /// What `held_keys` reports.
    held_keys: Vec<String>,
    /// Runs inside `ensure_folder`: between the walk and the fingerprints.
    on_ensure_folder: Option<Box<dyn Fn() + Send>>,
    /// `device_tree` leaves the category folder's id out (a broken host).
    omit_category_id: bool,
    /// A finishing upload writes this record (replacing the one at its key)
    /// right before the next `put_record` applies.
    /// The records the host holds just before the next `put_record`: an
    /// upload that finished after the pass read them.
    records_before_put: Option<Vec<BackupRecord>>,
}

struct FakeHost(Mutex<State>);

impl FakeHost {
    fn new() -> FakeHost {
        FakeHost(Mutex::new(State {
            category_id: Uuid::new_v4(),
            device_folder_live: true,
            category_folder_live: Some(true),
            listing_complete: true,
            ..State::default()
        }))
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.0.lock().expect("fake host lock")
    }

    fn calls(&self, prefix: &str) -> Vec<String> {
        self.state()
            .calls
            .iter()
            .filter(|c| c.starts_with(prefix))
            .cloned()
            .collect()
    }

    /// The key of folder `id` under the category folder.
    fn folder_key(state: &State, id: Uuid) -> Option<String> {
        if id == state.category_id {
            return Some(String::new());
        }
        let ((parent, name), _) = state.folders.iter().find(|(_, folder)| **folder == id)?;
        let parent_key = Self::folder_key(state, *parent)?;
        Some(if parent_key.is_empty() {
            name.clone()
        } else {
            format!("{parent_key}/{name}")
        })
    }

    /// The client finishing every queued upload: a server file and a record.
    fn complete_uploads(&self) -> Vec<String> {
        Self::complete(&mut self.state())
    }

    fn complete(state: &mut State) -> Vec<String> {
        let queued = std::mem::take(&mut state.queued);
        let mut keys = Vec::new();
        for req in queued {
            let id = Uuid::new_v4();
            let uploaded_at_ms = req.fingerprint.modified_ms.saturating_add(1_000);
            state
                .files
                .insert(id, (req.key.clone(), req.fingerprint.size, uploaded_at_ms));
            state.records.retain(|r| r.key != req.key);
            state.records.push(BackupRecord {
                key: req.key.clone(),
                size: req.fingerprint.size,
                modified_ms: req.fingerprint.modified_ms,
                remote_id: id,
                uploaded_at_ms,
                state: RecordState::BackedUp,
            });
            keys.push(req.key);
        }
        keys
    }

    /// A file this device backed up before, at `key`, matching `path` on disk.
    fn backed_up(&self, key: &str, path: &std::path::Path) -> Uuid {
        let fp = fingerprint(path).expect("fingerprint");
        let id = Uuid::new_v4();
        let mut state = self.state();
        state
            .files
            .insert(id, (key.to_string(), fp.size, fp.modified_ms + 1_000));
        state.records.push(BackupRecord {
            key: key.to_string(),
            size: fp.size,
            modified_ms: fp.modified_ms,
            remote_id: id,
            uploaded_at_ms: fp.modified_ms + 1_000,
            state: RecordState::BackedUp,
        });
        id
    }
}

impl BackupHost for FakeHost {
    async fn device_tree(&self, _c: &Category) -> Result<DeviceTree, HostError> {
        let mut state = self.state();
        state.calls.push("device_tree".to_string());
        let mut folders = HashMap::new();
        if state.category_folder_live != Some(false) {
            if !state.omit_category_id {
                folders.insert(String::new(), state.category_id);
            }
            for id in state.folders.values() {
                if let Some(key) = Self::folder_key(&state, *id) {
                    folders.insert(key, *id);
                }
            }
        }
        let files = state
            .files
            .iter()
            .map(|(id, (key, size, uploaded_at_ms))| RemoteEntry {
                key: key.clone(),
                remote_id: *id,
                size: *size,
                uploaded_at_ms: *uploaded_at_ms,
            })
            .collect();
        Ok(DeviceTree {
            device_folder_live: state.device_folder_live,
            category_folder_live: state.category_folder_live,
            folders,
            files,
            complete: state.listing_complete,
        })
    }

    async fn ensure_folder(&self, parent: Uuid, name: &str) -> Result<Uuid, HostError> {
        let mut state = self.state();
        state.calls.push(format!("ensure_folder {name}"));
        if let Some(hook) = &state.on_ensure_folder {
            hook();
        }
        let next = Uuid::new_v4();
        Ok(*state.folders.entry((parent, name.to_string())).or_insert(next))
    }

    async fn move_file(&self, id: Uuid, new_parent: Uuid, new_name: &str) -> Result<(), HostError> {
        let mut state = self.state();
        state.calls.push(format!("move_file {new_name}"));
        let parent_key = Self::folder_key(&state, new_parent).ok_or_else(|| HostError("no such folder".into()))?;
        let key = if parent_key.is_empty() {
            new_name.to_string()
        } else {
            format!("{parent_key}/{new_name}")
        };
        let file = state
            .files
            .get_mut(&id)
            .ok_or_else(|| HostError("no such file".into()))?;
        file.0 = key;
        Ok(())
    }

    async fn enqueue_upload(&self, req: UploadRequest) -> Result<(), HostError> {
        let mut state = self.state();
        state.calls.push(format!("enqueue_upload {}", req.key));
        state.queued.push(req);
        Ok(())
    }

    async fn held_keys(&self, _c: &Category) -> Result<Vec<String>, HostError> {
        Ok(self.state().held_keys.clone())
    }

    async fn records(&self, _c: &Category) -> Result<Vec<BackupRecord>, HostError> {
        let mut state = self.state();
        let records = state.records.clone();
        if std::mem::take(&mut state.finish_after_next_records) {
            Self::complete(&mut state);
        }
        Ok(records)
    }

    async fn put_record(&self, _c: &Category, expected: &RecordRef, record: BackupRecord) -> Result<bool, HostError> {
        let mut state = self.state();
        state.calls.push(format!("put_record {}", record.key));
        if let Some(records) = state.records_before_put.take() {
            state.records = records;
        }
        // Re-key the record the pass read, keeping its stored fields; or give
        // the moved file its record when no record names it any more.
        let stored = state
            .records
            .iter()
            .find(|r| r.key == expected.key && r.remote_id == expected.remote_id)
            .cloned();
        let to_store = match stored {
            Some(stored) => BackupRecord {
                key: record.key,
                state: record.state,
                ..stored
            },
            None if !state.records.iter().any(|r| r.remote_id == expected.remote_id) => record,
            None => return Ok(false),
        };
        // Upsert by key; one key per remote file (plan Amendment 1).
        state
            .records
            .retain(|r| r.key != to_store.key && r.remote_id != to_store.remote_id);
        state.records.push(to_store);
        Ok(true)
    }

    async fn mark_removed_elsewhere(&self, _c: &Category, records: &[RecordRef]) -> Result<(), HostError> {
        let mut state = self.state();
        let keys: Vec<&str> = records.iter().map(|m| m.key.as_str()).collect();
        state.calls.push(format!("mark_removed_elsewhere {}", keys.join(",")));
        // Compare-and-set on (key, remote_id), BackedUp only.
        for r in state.records.iter_mut().filter(|r| {
            r.state == RecordState::BackedUp && records.iter().any(|m| m.key == r.key && m.remote_id == r.remote_id)
        }) {
            r.state = RecordState::RemovedElsewhere;
        }
        Ok(())
    }

    async fn turn_off(&self, _c: &Category, why: FolderPresence) -> Result<(), HostError> {
        self.state().calls.push(format!("turn_off {why:?}"));
        Ok(())
    }
}

#[tokio::test]
async fn run_pass_first_pass_queues_all_and_creates_folders_parents_first() {
    let src = TempDir::new("first");
    src.write("a.jpg", b"aa");
    src.write("2026/05/b.jpg", b"bbb");
    src.write("2026/06/c.jpg", b"c");
    src.write("Thumbs.db", b"junk");
    let host = FakeHost::new();

    let report = run_pass(&host, src.path(), &[], &Category::Pictures, BUDGET)
        .await
        .expect("pass");
    assert_eq!(report.queued, 3);
    assert_eq!(report.skipped, BTreeMap::from([(SkipReason::Junk, 1)]));
    assert_eq!(
        host.calls("ensure_folder"),
        ["ensure_folder 2026", "ensure_folder 05", "ensure_folder 06"]
    );

    let state = host.state();
    let parent_of = |key: &str| state.queued.iter().find(|q| q.key == key).expect("queued").parent_id;
    let y2026 = state.folders[&(state.category_id, "2026".to_string())];
    assert_eq!(parent_of("a.jpg"), state.category_id);
    assert_eq!(parent_of("2026/05/b.jpg"), state.folders[&(y2026, "05".to_string())]);
    assert_eq!(parent_of("2026/06/c.jpg"), state.folders[&(y2026, "06".to_string())]);
    let b = state.queued.iter().find(|q| q.key == "2026/05/b.jpg").expect("queued");
    assert_eq!((b.name.as_str(), b.fingerprint.size), ("b.jpg", 3));
    assert_eq!(
        b.source_path,
        src.path().join("2026/05/b.jpg"),
        "uploaded from where it is"
    );
    assert!(state.records.is_empty(), "run_pass never writes a record for an upload");
}

#[tokio::test]
async fn run_pass_second_pass_after_records_queues_nothing() {
    let src = TempDir::new("second");
    src.write("a.jpg", b"aa");
    src.write("2026/05/b.jpg", b"bbb");
    let host = FakeHost::new();
    run_pass(&host, src.path(), &[], &Category::Pictures, BUDGET)
        .await
        .expect("pass 1");
    assert_eq!(host.complete_uploads().len(), 2);
    host.state().calls.clear();

    let report = run_pass(&host, src.path(), &[], &Category::Pictures, BUDGET)
        .await
        .expect("pass 2");
    assert_eq!((report.queued, report.unchanged, report.moved), (0, 2, 0));
    assert!(host.calls("ensure_folder").is_empty(), "{:?}", host.state().calls);
    assert!(host.calls("enqueue_upload").is_empty());
}

#[tokio::test]
async fn run_pass_deleted_category_folder_turns_off_and_queues_nothing() {
    let src = TempDir::new("turnoff");
    src.write("a.jpg", b"aa");
    let host = FakeHost::new();
    host.state().category_folder_live = Some(false);

    let report = run_pass(&host, src.path(), &[], &Category::Pictures, BUDGET)
        .await
        .expect("pass");
    assert_eq!(report.turned_off, Some(FolderPresence::CategoryDeleted));
    assert_eq!(report.queued, 0);
    assert_eq!(host.calls("turn_off"), ["turn_off CategoryDeleted"]);
    assert!(host.calls("enqueue_upload").is_empty() && host.calls("ensure_folder").is_empty());
}

#[tokio::test]
async fn run_pass_deleted_device_folder_turns_off() {
    let src = TempDir::new("devoff");
    src.write("a.jpg", b"aa");
    let host = FakeHost::new();
    host.state().device_folder_live = false;
    let report = run_pass(&host, src.path(), &[], &Category::Documents, BUDGET)
        .await
        .expect("pass");
    assert_eq!(report.turned_off, Some(FolderPresence::DeviceDeleted));
    assert!(host.calls("enqueue_upload").is_empty());
}

#[tokio::test]
async fn run_pass_removed_elsewhere_marks_and_does_not_upload() {
    let src = TempDir::new("elsewhere");
    let path = src.write("a.jpg", b"aa");
    let host = FakeHost::new();
    let id = host.backed_up("a.jpg", &path);
    host.state().files.remove(&id); // deleted from the backup on the web

    let report = run_pass(&host, src.path(), &[], &Category::Pictures, BUDGET)
        .await
        .expect("pass");
    assert_eq!(host.calls("mark_removed_elsewhere"), ["mark_removed_elsewhere a.jpg"]);
    assert_eq!(report.queued, 0);
    assert!(host.calls("enqueue_upload").is_empty());

    // It stays deleted while unchanged.
    host.state().calls.clear();
    let report = run_pass(&host, src.path(), &[], &Category::Pictures, BUDGET)
        .await
        .expect("pass 2");
    assert_eq!(report.queued, 0);
    assert!(host.calls("mark_removed_elsewhere").is_empty());
}

/// Review Focus 1: a big folder stays bounded per pass, and the next pass
/// picks up exactly where the budget stopped.
#[tokio::test]
async fn run_pass_large_folder_respects_budget_and_resumes() {
    let src = TempDir::new("large");
    for i in 0..20_000 {
        src.write(&format!("f{:03}/{i:05}.jpg", i / 100), b"x");
    }
    let host = FakeHost::new();

    let first = run_pass(&host, src.path(), &[], &Category::Downloads, BUDGET)
        .await
        .expect("pass 1");
    assert_eq!((first.queued, first.deferred), (256, 19_744));
    let pass1: HashSet<String> = host.complete_uploads().into_iter().collect();
    assert_eq!(pass1.len(), 256);

    let second = run_pass(&host, src.path(), &[], &Category::Downloads, BUDGET)
        .await
        .expect("pass 2");
    assert_eq!((second.queued, second.deferred, second.unchanged), (256, 19_488, 256));
    let pass2: HashSet<String> = host.complete_uploads().into_iter().collect();
    assert_eq!(pass2.len(), 256);
    assert!(pass1.is_disjoint(&pass2), "no key of pass 1 is queued again");
}

#[tokio::test]
async fn run_pass_move_rekeys_record_and_next_pass_plans_nothing() {
    let src = TempDir::new("move");
    let path = src.write("new/a.jpg", b"same bytes");
    let host = FakeHost::new();
    let id = host.backed_up("old/a.jpg", &path);

    let report = run_pass(&host, src.path(), &[], &Category::Pictures, BUDGET)
        .await
        .expect("pass");
    assert_eq!((report.moved, report.queued, report.gone_locally), (1, 0, 0));
    assert_eq!(host.calls("move_file"), ["move_file a.jpg"]);
    {
        let state = host.state();
        assert_eq!(state.records.len(), 1, "one record per remote file");
        assert_eq!(
            (state.records[0].key.as_str(), state.records[0].remote_id),
            ("new/a.jpg", id)
        );
        assert_eq!(state.files[&id].0, "new/a.jpg");
    }

    host.state().calls.clear();
    let again = run_pass(&host, src.path(), &[], &Category::Pictures, BUDGET)
        .await
        .expect("pass 2");
    assert_eq!((again.moved, again.queued, again.unchanged), (0, 0, 1));
    assert!(host.calls("move_file").is_empty() && host.calls("put_record").is_empty());
}

/// Review Focus 5 through the host: a case-only rename leaves exactly one
/// record for the remote file.
#[tokio::test]
async fn run_pass_case_only_rename_leaves_one_record() {
    let src = TempDir::new("case");
    let path = src.write("img.jpg", b"pixels");
    let host = FakeHost::new();
    let id = host.backed_up("IMG.JPG", &path);

    let report = run_pass(&host, src.path(), &[], &Category::Pictures, BUDGET)
        .await
        .expect("pass");
    assert_eq!((report.moved, report.queued), (1, 0));
    let state = host.state();
    let for_id: Vec<&BackupRecord> = state.records.iter().filter(|r| r.remote_id == id).collect();
    assert_eq!(for_id.len(), 1);
    assert_eq!(for_id[0].key, "img.jpg");
    assert_eq!(state.records.len(), 1);
}

/// Plan Amendment 1, items 5-6, end to end: an unreadable folder's records are
/// not a move source and not gone.
#[cfg(unix)]
#[tokio::test]
async fn run_pass_unreadable_folder_is_not_a_move_source() {
    use std::os::unix::fs::PermissionsExt;
    let src = TempDir::new("closed");
    let hidden = src.write("closed/a.jpg", b"same bytes");
    let open = src.write("open/a.jpg", b"same bytes");
    let host = FakeHost::new();
    let stamp = std::fs::metadata(&hidden).and_then(|m| m.modified()).expect("mtime");
    std::fs::File::options()
        .write(true)
        .open(&open)
        .and_then(|f| f.set_modified(stamp))
        .expect("same mtime");
    host.backed_up("closed/a.jpg", &hidden);
    let closed = src.path().join("closed");
    std::fs::set_permissions(&closed, std::fs::Permissions::from_mode(0o000)).expect("chmod");
    if std::fs::read_dir(&closed).is_ok() {
        std::fs::set_permissions(&closed, std::fs::Permissions::from_mode(0o755)).expect("chmod back");
        eprintln!("run_pass_unreadable_folder_is_not_a_move_source: permissions ignored (root); not checked");
        return;
    }
    let report = run_pass(&host, src.path(), &[], &Category::Pictures, BUDGET).await;
    std::fs::set_permissions(&closed, std::fs::Permissions::from_mode(0o755)).expect("chmod back");
    let report = report.expect("pass");
    assert_eq!((report.moved, report.queued, report.gone_locally), (0, 1, 0));
    assert_eq!(report.skipped, BTreeMap::from([(SkipReason::Unreadable, 1)]));
    assert!(host.calls("move_file").is_empty());
}

#[tokio::test]
async fn run_pass_missing_source_folder_is_an_error_without_a_path() {
    let src = TempDir::new("missing");
    let gone = src.path().join("not-there");
    let host = FakeHost::new();
    let err = run_pass(&host, &gone, &[], &Category::Pictures, BUDGET)
        .await
        .expect_err("no folder");
    assert!(!err.0.contains("not-there"), "errors never carry a path: {}", err.0);
    assert!(host.calls("enqueue_upload").is_empty());
}

/// An upload of an earlier pass that completes after this pass read its
/// records is not queued again (review finding 6): the pass reads the records
/// once more before it enqueues.
#[tokio::test]
async fn run_pass_upload_completed_mid_pass_is_not_queued_again() {
    let src = TempDir::new("midpass");
    src.write("a.jpg", b"aa");
    let host = FakeHost::new();
    run_pass(&host, src.path(), &[], &Category::Pictures, BUDGET)
        .await
        .expect("pass 1");
    assert_eq!(host.state().queued.len(), 1, "pass 1 queued a.jpg, not finished");
    host.state().finish_after_next_records = true;

    let report = run_pass(&host, src.path(), &[], &Category::Pictures, BUDGET)
        .await
        .expect("pass 2");
    assert_eq!((report.queued, report.unchanged), (0, 1));
    assert!(
        host.state().queued.is_empty(),
        "the finished upload is not queued twice"
    );
    assert_eq!(host.state().records.len(), 1);
}

/// Plan Amendment 1, item 8, through the pass: the sync root is counted as
/// excluded and nothing under it is queued.
#[tokio::test]
async fn run_pass_never_queues_from_an_excluded_path() {
    let src = TempDir::new("passexclude");
    src.write("a.jpg", b"aa");
    src.write("Beebeeb/Backups/b.jpg", b"bb");
    let host = FakeHost::new();
    let sync_root = src.path().join("Beebeeb");
    let report = run_pass(&host, src.path(), &[sync_root], &Category::Pictures, BUDGET)
        .await
        .expect("pass");
    assert_eq!(report.queued, 1);
    assert_eq!(report.skipped, BTreeMap::from([(SkipReason::Excluded, 1)]));
    assert_eq!(host.calls("enqueue_upload"), ["enqueue_upload a.jpg"]);
}

/// Review finding 2: a listing that misses a page proves no deletion, so a
/// partial tree marks nothing removed elsewhere and the record stays backed
/// up.
#[tokio::test]
async fn partial_device_tree_marks_nothing_removed() {
    let src = TempDir::new("partial");
    let path = src.write("a.jpg", b"aa");
    let host = FakeHost::new();
    let id = host.backed_up("a.jpg", &path);
    {
        let mut state = host.state();
        state.files.remove(&id);
        state.listing_complete = false;
    }
    let report = run_pass(&host, src.path(), &[], &Category::Pictures, BUDGET)
        .await
        .expect("pass");
    assert!(
        host.calls("mark_removed_elsewhere").is_empty(),
        "{:?}",
        host.state().calls
    );
    assert_eq!(host.state().records[0].state, RecordState::BackedUp);
    assert_eq!((report.queued, report.unchanged), (0, 0));

    // The same listing, complete: now the missing id is a deletion.
    host.state().listing_complete = true;
    run_pass(&host, src.path(), &[], &Category::Pictures, BUDGET)
        .await
        .expect("pass 2");
    assert_eq!(host.calls("mark_removed_elsewhere"), ["mark_removed_elsewhere a.jpg"]);
}

/// Review finding 3, through the pass: refused before anything is read.
#[tokio::test]
async fn run_pass_refuses_an_empty_exclude_path() {
    let src = TempDir::new("passemptyexclude");
    src.write("a.jpg", b"aa");
    let host = FakeHost::new();
    let err = run_pass(
        &host,
        src.path(),
        &[std::path::PathBuf::new()],
        &Category::Pictures,
        BUDGET,
    )
    .await
    .expect_err("an empty exclude path is refused");
    assert!(err.0.contains("excluded path"), "{}", err.0);
    assert!(
        host.state().calls.is_empty(),
        "nothing was read: {:?}",
        host.state().calls
    );
}

/// Review finding 5: a file whose fingerprint cannot be read (here it turned
/// into a symlink after the walk) is reported with its key, never a silent
/// deferral, and is not handed to the uploader.
#[cfg(unix)]
#[tokio::test]
async fn run_pass_reports_a_file_it_cannot_fingerprint() {
    let src = TempDir::new("nofingerprint");
    let path = src.write("sub/a.jpg", b"aa");
    src.write("sub/b.jpg", b"bb");
    let host = FakeHost::new();
    let target = src.path().join("sub/b.jpg");
    host.state().on_ensure_folder = Some(Box::new(move || {
        let _ = std::fs::remove_file(&path);
        let _ = std::os::unix::fs::symlink(&target, &path);
    }));
    let report = run_pass(&host, src.path(), &[], &Category::Pictures, BUDGET)
        .await
        .expect("pass");
    assert_eq!((report.queued, report.deferred, report.vanished), (1, 0, 0));
    assert_eq!(report.held_back, [("sub/a.jpg".to_string(), SkipReason::Unreadable)]);
    assert_eq!(report.skipped, BTreeMap::from([(SkipReason::Unreadable, 1)]));
    assert_eq!(host.calls("enqueue_upload"), ["enqueue_upload sub/b.jpg"]);
}

/// Review finding 5: the handoff decision from a fresh fingerprint. A file
/// that went online-only after the walk is held back as not local (reading
/// it would download it); a vanished one is counted, not reported unreadable.
#[test]
fn handoff_holds_back_what_went_online_only_or_cannot_be_read() {
    let fp = Fingerprint {
        size: 3,
        modified_ms: 1_000,
        file_id: None,
    };
    let local = beebeeb_core::backup::EntryAttrs::default();
    let online_only = beebeeb_core::backup::EntryAttrs {
        not_local: true,
        ..local
    };
    assert_eq!(handoff(Ok((fp, local))), Handoff::Queue(fp));
    assert_eq!(handoff(Ok((fp, online_only))), Handoff::Hold(SkipReason::NotLocal));
    let denied = std::io::Error::from(std::io::ErrorKind::PermissionDenied);
    assert_eq!(handoff(Err(denied)), Handoff::Hold(SkipReason::Unreadable));
    let gone = std::io::Error::from(std::io::ErrorKind::NotFound);
    assert_eq!(handoff(Err(gone)), Handoff::Vanished);
}

/// Review finding 4, end to end on Linux: an unreadable NFD folder hides
/// nothing of its readable NFC twin.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn run_pass_unreadable_nfd_twin_hides_nothing_of_the_nfc_twin() {
    use std::os::unix::fs::PermissionsExt;
    let src = TempDir::new("twinfolders");
    src.write("R\u{e9}/a.jpg", b"nfc");
    src.write("Re\u{301}/b.jpg", b"nfd");
    let closed = src.path().join("Re\u{301}");
    std::fs::set_permissions(&closed, std::fs::Permissions::from_mode(0o000)).expect("chmod");
    if std::fs::read_dir(&closed).is_ok() {
        std::fs::set_permissions(&closed, std::fs::Permissions::from_mode(0o755)).expect("chmod back");
        eprintln!(
            "run_pass_unreadable_nfd_twin_hides_nothing_of_the_nfc_twin: permissions ignored (root); not checked"
        );
        return;
    }
    let host = FakeHost::new();
    let report = run_pass(&host, src.path(), &[], &Category::Pictures, BUDGET).await;
    std::fs::set_permissions(&closed, std::fs::Permissions::from_mode(0o755)).expect("chmod back");
    let report = report.expect("pass");
    assert_eq!(report.queued, 1);
    assert_eq!(host.calls("enqueue_upload"), ["enqueue_upload R\u{e9}/a.jpg"]);
    assert_eq!(report.skipped, BTreeMap::from([(SkipReason::Unreadable, 1)]));
}

/// Review #1, through the pass: the keys the host holds (a lasting failure,
/// or in flight) are skipped and not charged, so the next file goes out.
#[tokio::test]
async fn run_pass_skips_keys_the_host_holds() {
    let src = TempDir::new("heldkeys");
    src.write("a.pst", b"locked");
    src.write("b.jpg", b"bb");
    let host = FakeHost::new();
    host.state().held_keys = vec!["a.pst".to_string()];
    let one = PassBudget {
        max_uploads: 1,
        max_bytes: u64::MAX,
    };
    let report = run_pass(&host, src.path(), &[], &Category::Documents, one)
        .await
        .expect("pass");
    assert_eq!((report.queued, report.held, report.deferred), (1, 1, 0));
    assert_eq!(host.calls("enqueue_upload"), ["enqueue_upload b.jpg"]);
}

/// Review #4 (spec Amendment 5): a lone NFD file, then an NFC twin in pass 2.
/// The NFD file keeps its record and is unchanged; the NFC twin uploads as a
/// new file. Its bytes never become a version of the NFD file's copy.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn run_pass_twin_appearing_in_pass_2_never_takes_the_first_files_record() {
    let src = TempDir::new("twinpass2");
    src.write("Rene\u{301}.txt", b"the first file");
    let host = FakeHost::new();
    run_pass(&host, src.path(), &[], &Category::Documents, BUDGET)
        .await
        .expect("pass 1");
    assert_eq!(host.complete_uploads(), ["Rene\u{301}.txt"]);
    let first_id = host.state().records[0].remote_id;

    src.write("Ren\u{e9}.txt", b"another file, longer");
    host.state().calls.clear();
    let report = run_pass(&host, src.path(), &[], &Category::Documents, BUDGET)
        .await
        .expect("pass 2");
    assert_eq!((report.queued, report.unchanged), (1, 1));
    let state = host.state();
    let queued = &state.queued[0];
    assert_eq!(queued.key, "Ren\u{e9}.txt");
    assert_eq!(queued.reason, beebeeb_core::backup::UploadReason::New);
    assert_eq!((queued.record_key.as_deref(), queued.remote_id), (None, None));
    let first = state
        .records
        .iter()
        .find(|r| r.remote_id == first_id)
        .expect("first record");
    assert_eq!(first.key, "Rene\u{301}.txt", "the first file keeps its key");
}

/// The real walk, with the given case rule.
fn real_fs(case_insensitive: bool) -> PassFs {
    PassFs {
        walk: Box::new(walk_with_paths),
        case_insensitive,
    }
}

/// Delta 3 #2: on Windows and macOS a folder renamed only in case (or only in
/// normalisation) is the same folder: its files move into the server folder
/// that is already there, never into a new sibling that differs only in case.
#[tokio::test]
async fn run_pass_case_only_folder_rename_creates_no_sibling() {
    for case_insensitive in [true, false] {
        let src = TempDir::new("caserename");
        let x = src.write("Photos/x.jpg", b"xx");
        let y = src.write("Photos/2026/y.jpg", b"yyy");
        let host = FakeHost::new();
        {
            let mut state = host.state();
            let (category, photos) = (state.category_id, Uuid::new_v4());
            state.folders.insert((category, "photos".to_string()), photos);
            state.folders.insert((photos, "2026".to_string()), Uuid::new_v4());
        }
        host.backed_up("photos/x.jpg", &x);
        host.backed_up("photos/2026/y.jpg", &y);

        let report = run_pass_with(
            &host,
            src.path(),
            &[],
            &Category::Pictures,
            BUDGET,
            real_fs(case_insensitive),
        )
        .await
        .expect("pass");
        assert_eq!(
            (report.moved, report.queued),
            (2, 0),
            "case_insensitive {case_insensitive}"
        );
        let mut keys: Vec<String> = host.state().records.iter().map(|r| r.key.clone()).collect();
        keys.sort();
        assert_eq!(keys, ["Photos/2026/y.jpg", "Photos/x.jpg"]);
        if case_insensitive {
            assert!(host.calls("ensure_folder").is_empty(), "{:?}", host.state().calls);
            assert!(
                host.calls("move_file").is_empty(),
                "already in place: {:?}",
                host.state().calls
            );
        } else {
            // Linux tells `photos` and `Photos` apart: a folder of its own.
            assert_eq!(
                host.calls("ensure_folder"),
                ["ensure_folder Photos", "ensure_folder 2026"]
            );
            assert_eq!(host.calls("move_file").len(), 2);
        }
    }
}

/// Delta 3 #6: on Windows a directory entry's size and mtime can be stale
/// (a file another process keeps open, a hard link), while the record holds
/// the handle's values. An entry whose listing differs from its record is
/// read again from the file before planning, so a stale entry never takes the
/// budget from a real change.
#[tokio::test]
async fn run_pass_stale_listing_never_takes_the_budget() {
    let src = TempDir::new("stale");
    let a = src.write("a.jpg", b"aa");
    src.write("b.jpg", b"bbb");
    let host = FakeHost::new();
    host.backed_up("a.jpg", &a);
    let stale = PassFs {
        walk: Box::new(|root, exclude| {
            let mut walk = walk_with_paths(root, exclude)?;
            for entry in walk.result.entries.iter_mut().filter(|e| e.key == "a.jpg") {
                entry.modified_ms -= 5_000;
            }
            Ok(walk)
        }),
        case_insensitive: false,
    };
    let one = PassBudget {
        max_uploads: 1,
        max_bytes: u64::MAX,
    };

    let report = run_pass_with(&host, src.path(), &[], &Category::Pictures, one, stale)
        .await
        .expect("pass");
    assert_eq!(
        (report.queued, report.deferred, report.unchanged),
        (1, 0, 1),
        "{report:?}"
    );
    assert_eq!(host.calls("enqueue_upload"), ["enqueue_upload b.jpg"]);
}

/// Delta 3 #8: run_pass checks what can fail before it changes anything. A
/// host whose tree lacks the category folder's id gets an error, and its
/// records and server files are as they were: nothing marked, moved or
/// re-keyed.
#[tokio::test]
async fn run_pass_error_before_any_change() {
    let src = TempDir::new("validate");
    let gone = src.write("gone.jpg", b"g");
    let moved = src.write("new/b.jpg", b"bb");
    let host = FakeHost::new();
    let gone_id = host.backed_up("gone.jpg", &gone);
    host.state().files.remove(&gone_id); // deleted from the backup elsewhere
    host.backed_up("old/b.jpg", &moved); // moved locally from old/ to new/
    host.state().omit_category_id = true;
    let (records, files) = {
        let state = host.state();
        (state.records.clone(), state.files.clone())
    };

    let err = run_pass(&host, src.path(), &[], &Category::Pictures, BUDGET)
        .await
        .expect_err("no category folder id");
    assert!(err.0.contains("no id"), "{err:?}");
    for mutation in [
        "mark_removed_elsewhere",
        "ensure_folder",
        "move_file",
        "put_record",
        "enqueue_upload",
    ] {
        assert!(host.calls(mutation).is_empty(), "{mutation}: {:?}", host.state().calls);
    }
    let state = host.state();
    assert_eq!((&state.records, &state.files), (&records, &files));
}

/// Review 4 #3: a fresh record that a finishing upload wrote (a new remote
/// file) after the pass read the records is never marked removed elsewhere:
/// the mark is compare-and-set on the key and the remote id the pass read.
#[tokio::test]
async fn run_pass_never_marks_a_record_a_finishing_upload_rewrote() {
    let src = TempDir::new("casmark");
    let path = src.write("a.jpg", b"aa");
    let host = FakeHost::new();
    let old = host.backed_up("a.jpg", &path);
    src.write("a.jpg", b"changed, and longer");
    run_pass(&host, src.path(), &[], &Category::Pictures, BUDGET)
        .await
        .expect("pass 1");
    assert_eq!(host.calls("enqueue_upload"), ["enqueue_upload a.jpg"]);
    {
        let mut state = host.state();
        state.files.remove(&old); // the old copy trashed on the web meanwhile
        state.finish_after_next_records = true; // the upload lands as a new file during pass 2
        state.calls.clear();
    }

    let report = run_pass(&host, src.path(), &[], &Category::Pictures, BUDGET)
        .await
        .expect("pass 2");
    let state = host.state();
    let record = state.records.iter().find(|r| r.key == "a.jpg").expect("record");
    assert_ne!(record.remote_id, old, "the finished upload's record");
    assert_eq!(
        record.state,
        RecordState::BackedUp,
        "it names a live file: {:?}",
        state.calls
    );
    assert_eq!(report.queued, 0, "{:?}", state.calls);
}

/// The record of a moved file, when an upload that finished at the old key
/// after the pass read the records replaced that key's record with another
/// remote file (review 4 #3, and the delta-4 self-review): the fresh record
/// stays, and the moved file keeps a record at its new key, so the next pass
/// plans nothing for it.
#[tokio::test]
async fn run_pass_move_keeps_a_record_for_the_moved_file_when_an_upload_rewrote_the_old_key() {
    let src = TempDir::new("casput");
    let old_path = src.write("old/b.jpg", b"bb");
    let host = FakeHost::new();
    let id = host.backed_up("old/b.jpg", &old_path);
    std::fs::create_dir_all(src.path().join("new")).expect("mkdir");
    std::fs::rename(&old_path, src.path().join("new/b.jpg")).expect("a move keeps the mtime");
    let before = host.state().records[0].clone();
    let fresh = BackupRecord {
        key: "old/b.jpg".to_string(),
        remote_id: Uuid::new_v4(),
        uploaded_at_ms: before.uploaded_at_ms + 1,
        ..before.clone()
    };
    host.state().records_before_put = Some(vec![fresh.clone()]);

    let report = run_pass(&host, src.path(), &[], &Category::Pictures, BUDGET)
        .await
        .expect("pass");
    assert_eq!((report.moved, report.deferred), (1, 0));
    {
        let state = host.state();
        assert_eq!(state.files[&id].0, "new/b.jpg", "the server file moved");
        let mut records = state.records.clone();
        records.sort_by(|a, b| a.key.cmp(&b.key));
        let moved = BackupRecord {
            key: "new/b.jpg".to_string(),
            ..before
        };
        assert_eq!(records, [moved, fresh], "{:?}", state.calls);
        // The next pass sees new/b.jpg backed up.
        drop(state);
    }
    host.state().calls.clear();
    let next = run_pass(&host, src.path(), &[], &Category::Pictures, BUDGET)
        .await
        .expect("pass 2");
    assert_eq!((next.queued, next.moved), (0, 0), "{:?}", host.state().calls);
}

/// The delta-4 self-review: a re-key keeps the fields an upload of a new
/// version wrote after the pass read the records, never the pass's older
/// copy (which would make the next pass upload the same bytes again).
#[tokio::test]
async fn run_pass_move_keeps_the_fields_a_finishing_upload_wrote() {
    let src = TempDir::new("casfields");
    let old_path = src.write("old/b.jpg", b"bb");
    let host = FakeHost::new();
    host.backed_up("old/b.jpg", &old_path);
    std::fs::create_dir_all(src.path().join("new")).expect("mkdir");
    std::fs::rename(&old_path, src.path().join("new/b.jpg")).expect("a move keeps the mtime");
    let before = host.state().records[0].clone();
    let fresh = BackupRecord {
        uploaded_at_ms: before.uploaded_at_ms + 1000,
        ..before.clone()
    };
    host.state().records_before_put = Some(vec![fresh.clone()]);

    let report = run_pass(&host, src.path(), &[], &Category::Pictures, BUDGET)
        .await
        .expect("pass");
    assert_eq!(report.moved, 1);
    let state = host.state();
    let moved = BackupRecord {
        key: "new/b.jpg".to_string(),
        ..fresh
    };
    assert_eq!(state.records, [moved], "{:?}", state.calls);
}

/// The re-key is left alone when another key's record names the remote file
/// by now: the move counts as deferred, not moved.
#[tokio::test]
async fn run_pass_move_leaves_a_record_another_key_holds() {
    let src = TempDir::new("casother");
    let old_path = src.write("old/b.jpg", b"bb");
    let host = FakeHost::new();
    host.backed_up("old/b.jpg", &old_path);
    std::fs::create_dir_all(src.path().join("new")).expect("mkdir");
    std::fs::rename(&old_path, src.path().join("new/b.jpg")).expect("a move keeps the mtime");
    let elsewhere = BackupRecord {
        key: "other/b.jpg".to_string(),
        ..host.state().records[0].clone()
    };
    host.state().records_before_put = Some(vec![elsewhere.clone()]);

    let report = run_pass(&host, src.path(), &[], &Category::Pictures, BUDGET)
        .await
        .expect("pass");
    assert_eq!((report.moved, report.deferred), (0, 1));
    let state = host.state();
    assert_eq!(state.records, [elsewhere], "{:?}", state.calls);
}
