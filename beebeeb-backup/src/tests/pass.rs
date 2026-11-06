//! `run_pass` against `FakeHost`, a host that keeps its records and server
//! tree in memory and records every call, over real temporary source folders.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Mutex;

use beebeeb_core::backup::{BackupRecord, FolderPresence, PassBudget, RecordState, RemoteEntry, SkipReason};
use beebeeb_types::backup::Category;
use uuid::Uuid;

use super::TempDir;
use crate::{BackupHost, DeviceTree, HostError, UploadRequest, fingerprint, run_pass};

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
}

struct FakeHost(Mutex<State>);

impl FakeHost {
    fn new() -> FakeHost {
        FakeHost(Mutex::new(State {
            category_id: Uuid::new_v4(),
            device_folder_live: true,
            category_folder_live: Some(true),
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
            folders.insert(String::new(), state.category_id);
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
        })
    }

    async fn ensure_folder(&self, parent: Uuid, name: &str) -> Result<Uuid, HostError> {
        let mut state = self.state();
        state.calls.push(format!("ensure_folder {name}"));
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

    async fn records(&self, _c: &Category) -> Result<Vec<BackupRecord>, HostError> {
        let mut state = self.state();
        let records = state.records.clone();
        if std::mem::take(&mut state.finish_after_next_records) {
            Self::complete(&mut state);
        }
        Ok(records)
    }

    async fn put_record(&self, _c: &Category, record: BackupRecord) -> Result<(), HostError> {
        let mut state = self.state();
        state.calls.push(format!("put_record {}", record.key));
        // Upsert by key; one key per remote file (plan Amendment 1).
        state
            .records
            .retain(|r| r.key != record.key && r.remote_id != record.remote_id);
        state.records.push(record);
        Ok(())
    }

    async fn mark_removed_elsewhere(&self, _c: &Category, keys: &[String]) -> Result<(), HostError> {
        let mut state = self.state();
        state.calls.push(format!("mark_removed_elsewhere {}", keys.join(",")));
        for r in state.records.iter_mut().filter(|r| keys.contains(&r.key)) {
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
