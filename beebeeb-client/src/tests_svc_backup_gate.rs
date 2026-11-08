//! The native backup's pass gate (backup spec Amendments 12 and 12c; core
//! `CLAUDE.md` Never break: "a stopped backup never fills the account up
//! again by itself"), and the copy states it relies on.

use std::{
    collections::VecDeque,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use beebeeb_api::Method;
use beebeeb_core::kdf::MasterKey;
use beebeeb_types::backup::BackupStopReason;
use serde_json::{Value, json};
use tempfile::tempdir;

use crate::{
    Client, ClientConfig,
    backup::{
        Asset, AssetKind, AssetSnapshot, AssetSource, AssetSourceError, BackupConfiguration, BackupCopyState,
        BackupFolder, BackupService, NOTICE_OVERLAP_MS,
    },
    test_support::{RouteAnswer, RoutedTransport, ScriptedTransport, json_answer},
    uploads::{NetworkKind, UploadService},
};

pub(crate) const ROOT: &str = "b0000000-0000-4000-8000-000000000001";
pub(crate) const DEVICE: &str = "b0000000-0000-4000-8000-000000000002";
pub(crate) const CATEGORY: &str = "b0000000-0000-4000-8000-000000000003";
/// The `Date` every gate answer carries, and the same time in ms.
const SERVER_DATE: &str = "Sun, 08 Nov 2026 03:10:00 GMT";
const SERVER_NOW_MS: i64 = 1_794_107_400_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum Row {
    #[default]
    Live,
    Trashed,
    Gone,
}

#[derive(Default)]
struct ServerState {
    device: Row,
    category: Row,
    /// Answers to notice requests, in order; when empty, one complete empty page.
    pages: VecDeque<RouteAnswer>,
    notice_paths: Vec<String>,
}

/// The rows and notices the backup gate reads. Everything else goes to the
/// test's [`ScriptedTransport`].
#[derive(Clone, Default)]
pub(crate) struct BackupServer {
    state: Arc<Mutex<ServerState>>,
}

fn folder_row(id: &str, parent: Option<&str>, trashed: bool) -> Vec<u8> {
    let mut row = json!({"id": id, "parent_id": parent, "is_folder": true, "is_trashed": trashed});
    if id == ROOT {
        row["system_role"] = Value::String("backups_root".into());
    }
    serde_json::to_vec(&row).unwrap()
}

fn row_answer(id: &str, parent: Option<&str>, row: Row) -> RouteAnswer {
    Ok(match row {
        Row::Live => json_answer(200, &[], folder_row(id, parent, false)),
        Row::Trashed => json_answer(200, &[], folder_row(id, parent, true)),
        Row::Gone => json_answer(404, &[], br#"{"code":"not_found","message":"not found"}"#.to_vec()),
    })
}

impl BackupServer {
    pub(crate) fn transport(&self, fallback: ScriptedTransport) -> RoutedTransport {
        let state = Arc::clone(&self.state);
        RoutedTransport::new(
            Arc::new(move |request| {
                if request.method() != Method::Get {
                    return None;
                }
                let path = request.path();
                let mut state = state.lock().unwrap();
                if path == format!("/api/v1/files/{ROOT}") {
                    Some(row_answer(ROOT, None, Row::Live))
                } else if path == format!("/api/v1/files/{DEVICE}") {
                    Some(row_answer(DEVICE, Some(ROOT), state.device))
                } else if path == format!("/api/v1/files/{CATEGORY}") {
                    Some(row_answer(CATEGORY, Some(DEVICE), state.category))
                } else if path.starts_with("/api/v1/notifications?") {
                    state.notice_paths.push(path.to_owned());
                    Some(state.pages.pop_front().unwrap_or_else(|| page(json!([]), None)))
                } else {
                    None
                }
            }),
            fallback,
        )
    }

    pub(crate) fn set_device(&self, row: Row) {
        self.state.lock().unwrap().device = row;
    }

    fn set_category(&self, row: Row) {
        self.state.lock().unwrap().category = row;
    }

    fn push_page(&self, answer: RouteAnswer) {
        self.state.lock().unwrap().pages.push_back(answer);
    }

    fn notice_paths(&self) -> Vec<String> {
        self.state.lock().unwrap().notice_paths.clone()
    }
}

/// One filtered page, dated [`SERVER_DATE`].
fn page(notices: Value, next_cursor: Option<&str>) -> RouteAnswer {
    Ok(json_answer(
        200,
        &[("Date", SERVER_DATE)],
        serde_json::to_vec(&json!({"notifications": notices, "unread_count": 0, "next_cursor": next_cursor})).unwrap(),
    ))
}

fn erased(created_at: &str) -> Value {
    json!({"id": "n1", "type": "files_removed", "title": "t", "body": null,
           "data": {"reason": "erase_request"}, "read": false, "created_at": created_at})
}

#[derive(Default)]
struct Source {
    snapshots: Mutex<VecDeque<AssetSnapshot>>,
    calls: Mutex<usize>,
}

impl AssetSource for Source {
    fn snapshot(&self, _: AssetKind, _: Option<&str>, _: usize) -> Result<AssetSnapshot, AssetSourceError> {
        *self.calls.lock().unwrap() += 1;
        self.snapshots
            .lock()
            .unwrap()
            .pop_front()
            .ok_or(AssetSourceError::Unavailable)
    }
}

fn one_photo(path: &Path) -> AssetSnapshot {
    AssetSnapshot {
        complete: true,
        assets: vec![Asset {
            local_identifier: "photo-1".into(),
            export_path: path.to_path_buf(),
            name: "photo-1.jpg".into(),
            mime_type: Some("image/jpeg".into()),
        }],
        next_cursor: None,
    }
}

struct Harness {
    _root: tempfile::TempDir,
    photo: PathBuf,
    server: BackupServer,
    scripted: ScriptedTransport,
    source: Arc<Source>,
    uploads: Arc<UploadService>,
    backup: BackupService,
}

/// A backup into the category folder, with `snapshots` photo snapshots and
/// the scripted (non-gate) answers `replies`.
fn harness(configuration: impl FnOnce(BackupConfiguration) -> BackupConfiguration, replies: &[&str]) -> Harness {
    let root = tempdir().unwrap();
    let photo = root.path().join("photo.jpg");
    std::fs::write(&photo, b"photo").unwrap();
    let scripted = ScriptedTransport::json(200, replies.first().copied().unwrap_or("{}").as_bytes().to_vec());
    for reply in replies.iter().skip(1) {
        scripted.push_json(200, reply.as_bytes().to_vec());
    }
    let server = BackupServer::default();
    let client =
        Arc::new(Client::new(ClientConfig::for_tests(), Arc::new(server.transport(scripted.clone()))).unwrap());
    client.set_authentication("token", "owner").unwrap();
    let uploads = Arc::new(
        UploadService::new_for_test(
            Arc::clone(&client),
            Arc::new(Mutex::new(beebeeb_store::Store::open_in_memory().unwrap())),
            Arc::new(MasterKey::from_bytes([7; 32])),
            root.path().join("staging"),
        )
        .unwrap(),
    );
    let source = Arc::new(Source::default());
    let config = configuration(BackupConfiguration::new(BackupFolder { id: CATEGORY.into() }, false).unwrap());
    let backup = BackupService::new(client, Arc::clone(&uploads), source.clone(), config).unwrap();
    Harness {
        _root: root,
        photo,
        server,
        scripted,
        source,
        uploads,
        backup,
    }
}

impl Harness {
    fn snapshot_photo(&self) {
        self.source.snapshots.lock().unwrap().push_back(one_photo(&self.photo));
    }

    async fn pass(&self, now_ms: i64) -> crate::backup::BackupBatch {
        self.backup
            .next_batch(AssetKind::Photo, NetworkKind::WiFi, now_ms)
            .await
            .unwrap()
    }
}

// ── Copy states (review r4, P1: a trashed or deleted copy came back) ────────

#[tokio::test]
async fn a_photo_whose_copy_was_trashed_is_never_uploaded_again() {
    let h = harness(|c| c, &[r#"{"needs_backup":["photo-1"]}"#]);
    h.backup
        .manifest()
        .remember("photo-1", "old-copy", BackupCopyState::Trashed)
        .unwrap();
    h.snapshot_photo();

    let batch = h.pass(1).await;

    assert_eq!(batch.queued, 0);
    assert!(h.uploads.list().unwrap().is_empty());
    assert_eq!(
        h.backup.manifest().copy_state("photo-1"),
        Some(BackupCopyState::Trashed)
    );
    // A removed copy is not even asked about: the server's answer cannot bring it back.
    assert_eq!(h.scripted.request_count(), 0);
}

#[tokio::test]
async fn a_photo_deleted_on_the_server_is_never_uploaded_again() {
    let h = harness(|c| c, &[r#"{"needs_backup":["photo-1"]}"#]);
    h.backup
        .manifest()
        .remember("photo-1", "old-copy", BackupCopyState::Deleted)
        .unwrap();
    h.snapshot_photo();

    let batch = h.pass(1).await;

    assert_eq!(batch.queued, 0);
    assert!(h.uploads.list().unwrap().is_empty());
}

#[tokio::test]
async fn a_failed_upload_is_still_retried() {
    let h = harness(|c| c, &[r#"{"needs_backup":["photo-1"]}"#]);
    h.backup
        .manifest()
        .remember("photo-1", "failed-copy", BackupCopyState::UploadFailed)
        .unwrap();
    h.snapshot_photo();

    let batch = h.pass(1).await;

    assert_eq!(batch.queued, 1);
    assert_eq!(h.backup.manifest().copy_state("photo-1"), Some(BackupCopyState::Queued));
}

#[tokio::test]
async fn a_removed_contact_snapshot_is_never_uploaded_again() {
    let h = harness(|c| c, &[]);
    h.backup
        .manifest()
        .remember("photo-1", "old-copy", BackupCopyState::Trashed)
        .unwrap();
    h.snapshot_photo();

    let batch = h
        .backup
        .next_batch(AssetKind::ContactSnapshot, NetworkKind::WiFi, 1)
        .await
        .unwrap();

    assert_eq!(batch.queued, 0);
    assert!(h.uploads.list().unwrap().is_empty());
}

// ── The gate ────────────────────────────────────────────────────────────────

#[tokio::test]
async fn an_erase_notice_stops_the_backup_before_anything_is_read_or_queued() {
    let h = harness(|c| c, &[r#"{"needs_backup":["photo-1"]}"#]);
    h.server.push_page(page(json!([erased("2026-11-08T03:00:00Z")]), None));
    h.snapshot_photo();

    let batch = h.pass(1).await;

    assert_eq!(batch.stopped, Some(BackupStopReason::EraseRequest));
    assert_eq!(batch.queued, 0);
    assert_eq!(*h.source.calls.lock().unwrap(), 0);
    assert!(h.uploads.list().unwrap().is_empty());
    assert_eq!(h.backup.stopped().unwrap(), Some(BackupStopReason::EraseRequest));

    // It stays off without reading anything, until "Back up again".
    let routed_before = h.server.notice_paths().len();
    let again = h.pass(2).await;
    assert_eq!(again.stopped, Some(BackupStopReason::EraseRequest));
    assert_eq!(h.server.notice_paths().len(), routed_before);
    assert_eq!(h.scripted.request_count(), 0);
}

#[tokio::test]
async fn a_failed_notice_check_skips_the_pass_and_keeps_its_baseline() {
    let h = harness(
        |c| c.with_first_pass(Some(1_000), None),
        &[r#"{"needs_backup":["photo-1"]}"#],
    );
    h.server
        .push_page(Ok(json_answer(500, &[], br#"{"code":"internal"}"#.to_vec())));
    h.snapshot_photo();

    let batch = h.pass(1).await;

    assert!(batch.check_failed);
    assert_eq!(batch.stopped, None);
    assert_eq!(batch.queued, 0);
    assert_eq!(*h.source.calls.lock().unwrap(), 0);
    assert_eq!(h.backup.manifest().pass_state().unwrap().last_pass_at_ms, None);

    // The next pass reads from the same baseline.
    let next = h.pass(2).await;
    assert!(!next.check_failed);
    assert_eq!(next.queued, 1);
    let paths = h.server.notice_paths();
    assert!(paths.iter().all(|path| path.contains("&since=1000&")), "{paths:?}");
}

#[tokio::test]
async fn an_answer_the_server_did_not_filter_skips_the_pass() {
    let h = harness(|c| c, &[]);
    h.server.push_page(Ok(json_answer(
        200,
        &[("Date", SERVER_DATE)],
        br#"{"notifications":[],"unread_count":0}"#.to_vec(),
    )));
    h.snapshot_photo();

    assert!(h.pass(1).await.check_failed);
    assert!(h.uploads.list().unwrap().is_empty());
}

#[tokio::test]
async fn every_notice_page_is_read_before_the_pass_runs() {
    let h = harness(|c| c, &[]);
    h.server.push_page(page(json!([]), Some("cursor+1")));
    h.server.push_page(page(json!([erased("2026-11-08T03:00:00Z")]), None));
    h.snapshot_photo();

    let batch = h.pass(1).await;

    assert_eq!(batch.stopped, Some(BackupStopReason::EraseRequest));
    let paths = h.server.notice_paths();
    assert_eq!(paths.len(), 2);
    assert!(paths[0].starts_with("/api/v1/notifications?type=files_removed,backup_deleted&since=0&limit=500"));
    assert!(paths[1].ends_with("&cursor=cursor%2B1"), "{paths:?}");
}

#[tokio::test]
async fn the_first_pass_ignores_notices_from_before_backups_were_set_up() {
    let before_setup_ms = SERVER_NOW_MS - 60_000;
    let h = harness(
        |c| c.with_first_pass(Some(before_setup_ms + 1), None),
        &[r#"{"needs_backup":["photo-1"]}"#],
    );
    h.server.push_page(page(json!([erased("2026-11-08T03:09:00Z")]), None));
    h.snapshot_photo();

    let batch = h.pass(1).await;

    assert_eq!(batch.stopped, None);
    assert_eq!(batch.queued, 1);
    assert!(h.server.notice_paths()[0].contains(&format!("&since={}&", before_setup_ms + 1)));
}

#[tokio::test]
async fn with_no_baseline_known_any_removal_notice_stops_the_first_pass() {
    let h = harness(|c| c, &[]);
    h.server.push_page(page(json!([erased("2020-01-01T00:00:00Z")]), None));
    h.snapshot_photo();

    assert_eq!(h.pass(1).await.stopped, Some(BackupStopReason::EraseRequest));
}

#[tokio::test]
async fn a_pass_that_ran_reads_from_its_server_start_less_the_overlap_next_time() {
    let h = harness(|c| c, &[r#"{"needs_backup":["photo-1"]}"#]);
    h.snapshot_photo();

    h.pass(1).await;

    let expected = SERVER_NOW_MS - NOTICE_OVERLAP_MS;
    assert_eq!(
        h.backup.manifest().pass_state().unwrap().last_pass_at_ms,
        Some(expected)
    );
    h.snapshot_photo();
    h.pass(2).await;
    assert!(h.server.notice_paths()[1].contains(&format!("&since={expected}&")));
}

#[tokio::test]
async fn a_trashed_device_folder_with_no_notice_stops_the_backup() {
    let h = harness(|c| c, &[]);
    h.server.set_device(Row::Trashed);
    h.snapshot_photo();

    assert_eq!(h.pass(1).await.stopped, Some(BackupStopReason::Unknown));
}

#[tokio::test]
async fn a_gone_category_folder_with_no_notice_stops_the_backup() {
    let h = harness(|c| c, &[r#"{"needs_backup":["photo-1"]}"#]);
    h.snapshot_photo();
    assert_eq!(h.pass(1).await.queued, 1);
    h.server.set_category(Row::Gone);
    h.snapshot_photo();

    assert_eq!(h.pass(2).await.stopped, Some(BackupStopReason::Unknown));
}

#[tokio::test]
async fn a_stop_cancels_the_queued_uploads_without_counting_a_failure() {
    let h = harness(|c| c, &[r#"{"needs_backup":["photo-1"]}"#]);
    h.snapshot_photo();
    assert_eq!(h.pass(1).await.queued, 1);
    h.server.push_page(page(json!([erased("2026-11-08T03:30:00Z")]), None));

    let batch = h.pass(2).await;

    assert_eq!(batch.stopped, Some(BackupStopReason::EraseRequest));
    let uploads = h.uploads.list().unwrap();
    assert_eq!(uploads.len(), 1);
    assert_eq!(uploads[0].state, beebeeb_store::TransferState::Cancelled);
    assert!(h.uploads.pending_backup_outcomes().unwrap().is_empty());
    assert_eq!(h.uploads.active_backup_count().unwrap(), 0);
    assert_eq!(h.backup.manifest().copy_state("photo-1"), None);
    assert_eq!(h.backup.manifest().retry_count("photo-1"), None);
}

#[tokio::test]
async fn back_up_again_moves_past_the_seen_notices_and_starts_fresh() {
    let h = harness(|c| c, &[r#"{"needs_backup":["photo-1"]}"#]);
    let notice = erased("2026-11-08T03:30:00Z");
    h.server.push_page(page(json!([notice.clone()]), None));
    h.backup
        .manifest()
        .remember("photo-1", "trashed-copy", BackupCopyState::Trashed)
        .unwrap();
    assert_eq!(h.pass(1).await.stopped, Some(BackupStopReason::EraseRequest));
    let through = h.backup.manifest().pass_state().unwrap().stopped.unwrap().through_ms;
    assert_eq!(
        through,
        SERVER_NOW_MS + 20 * 60_000,
        "the newest notice is later than the Date"
    );

    h.backup.back_up_again().unwrap();

    let state = h.backup.manifest().pass_state().unwrap();
    assert_eq!(state.stopped, None);
    assert_eq!(state.last_pass_at_ms, Some(through));
    assert_eq!(h.backup.manifest().copy_state("photo-1"), None);
    // The notice the person saw is served again (at or after `since`) but no
    // longer stops the backup; the photo is backed up fresh.
    h.server.push_page(page(json!([notice]), None));
    h.snapshot_photo();
    let batch = h.pass(2).await;
    assert_eq!(batch.stopped, None);
    assert_eq!(batch.queued, 1);
    assert!(h.server.notice_paths()[1].contains(&format!("&since={through}&")));
}

#[tokio::test]
async fn back_up_again_while_on_changes_nothing() {
    let h = harness(|c| c, &[]);
    h.backup
        .manifest()
        .remember("photo-1", "trashed-copy", BackupCopyState::Trashed)
        .unwrap();

    h.backup.back_up_again().unwrap();

    assert_eq!(
        h.backup.manifest().copy_state("photo-1"),
        Some(BackupCopyState::Trashed)
    );
    assert_eq!(h.backup.manifest().pass_state().unwrap().last_pass_at_ms, None);
}
