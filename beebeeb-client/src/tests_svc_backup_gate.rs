//! The native backup's pass gate (backup spec Amendments 12 and 12c; core
//! `CLAUDE.md` Never break: "a stopped backup never fills the account up
//! again by itself"), and the copy states it relies on.

use std::{
    collections::{BTreeMap, VecDeque},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use beebeeb_api::Method;
use beebeeb_core::{backup::NOTICE_OVERLAP_MS, kdf::MasterKey};
use beebeeb_types::backup::BackupStopReason;
use serde_json::{Value, json};
use tempfile::tempdir;

use crate::{
    Client, ClientConfig,
    backup::{
        Asset, AssetKind, AssetSnapshot, AssetSource, AssetSourceError, BackupAssetChange, BackupConfiguration,
        BackupCopyState, BackupFolder, BackupManifestRecord, BackupManifestStore, BackupManifestStoreError,
        BackupPassState, BackupService, BackupStop, MemoryBackupManifestStore,
    },
    test_support::{RouteAnswer, RoutedTransport, ScriptedTransport, json_answer},
    uploads::{NetworkKind, UploadService},
};

pub(crate) const ROOT: &str = "b0000000-0000-4000-8000-000000000001";
pub(crate) const DEVICE: &str = "b0000000-0000-4000-8000-000000000002";
pub(crate) const CATEGORY: &str = "b0000000-0000-4000-8000-000000000003";
/// This device's canonical id, as the app supplies it.
pub(crate) const THIS_DEVICE: &str = "this-device";
/// The `Date` every gate answer carries, and the same time in ms.
pub(crate) const SERVER_DATE: &str = "Sun, 08 Nov 2026 03:10:00 GMT";
const SERVER_NOW_MS: i64 = 1_794_107_400_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum Row {
    #[default]
    Live,
    Trashed,
    Gone,
}

type Hook = Box<dyn FnMut() + Send>;

/// What `GET /files/{id}` answers for a backed-up copy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CopyRow {
    Live,
    Trashed,
    Gone,
    Fails,
}

#[derive(Default)]
struct ServerState {
    device: Row,
    category: Row,
    /// Answers to notice requests, in order; when empty, one complete empty page.
    pages: VecDeque<RouteAnswer>,
    notice_paths: Vec<String>,
    /// Run while a notice request is served: another writer acting while a
    /// pass waits on the gate.
    on_notice: Option<Hook>,
    /// Backed-up copies `GET /files/{id}` answers for.
    copies: BTreeMap<String, CopyRow>,
    copy_reads: Vec<String>,
    /// The server's photo-backup map, `(X-Beebeeb-Device-Id or "", local id)
    /// → file id`, when this server answers `check` and `mark` itself.
    rows: Option<BTreeMap<(String, String), String>>,
    /// The device id each `check` and `mark` carried, in order.
    keyed_by: Vec<Option<String>>,
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
                let path = request.path();
                let mut state = state.lock().unwrap();
                if request.method() == Method::Post {
                    return photo_backup_answer(&mut state, request);
                }
                if request.method() != Method::Get {
                    return None;
                }
                if let Some(copy) = path
                    .strip_prefix("/api/v1/files/")
                    .and_then(|id| state.copies.get(id).copied())
                {
                    let id = path.trim_start_matches("/api/v1/files/").to_owned();
                    state.copy_reads.push(id.clone());
                    return Some(Ok(copy_answer(&id, copy)));
                }
                if path == format!("/api/v1/files/{ROOT}") {
                    Some(row_answer(ROOT, None, Row::Live))
                } else if path == format!("/api/v1/files/{DEVICE}") {
                    Some(row_answer(DEVICE, Some(ROOT), state.device))
                } else if path == format!("/api/v1/files/{CATEGORY}") {
                    Some(row_answer(CATEGORY, Some(DEVICE), state.category))
                } else if path.starts_with("/api/v1/notifications?") {
                    state.notice_paths.push(path.to_owned());
                    if let Some(hook) = state.on_notice.as_mut() {
                        hook();
                    }
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

    fn on_notice(&self, hook: impl FnMut() + Send + 'static) {
        self.state.lock().unwrap().on_notice = Some(Box::new(hook));
    }

    pub(crate) fn set_copy(&self, file_id: &str, copy: CopyRow) {
        self.state.lock().unwrap().copies.insert(file_id.to_owned(), copy);
    }

    pub(crate) fn copy_reads(&self) -> Vec<String> {
        self.state.lock().unwrap().copy_reads.clone()
    }

    /// Answer `check` and `mark` from a map keyed like the server's.
    pub(crate) fn keep_rows(&self) {
        self.state.lock().unwrap().rows = Some(BTreeMap::new());
    }

    pub(crate) fn rows(&self) -> BTreeMap<(String, String), String> {
        self.state.lock().unwrap().rows.clone().unwrap_or_default()
    }

    pub(crate) fn keyed_by(&self) -> Vec<Option<String>> {
        self.state.lock().unwrap().keyed_by.clone()
    }
}

fn copy_answer(id: &str, copy: CopyRow) -> beebeeb_api::Answer {
    let row = |trashed: bool| {
        serde_json::to_vec(&json!({"id": id, "parent_id": CATEGORY, "is_folder": false, "is_trashed": trashed}))
            .unwrap()
    };
    match copy {
        CopyRow::Live => json_answer(200, &[], row(false)),
        CopyRow::Trashed => json_answer(200, &[], row(true)),
        CopyRow::Gone => json_answer(404, &[], br#"{"code":"not_found","message":"not found"}"#.to_vec()),
        CopyRow::Fails => json_answer(500, &[], br#"{"code":"internal","message":"try later"}"#.to_vec()),
    }
}

/// The server's `check` and `mark` (`routes/photo_backup.rs`): rows keyed by
/// `(user, X-Beebeeb-Device-Id, local id)`, with `""` for a request without
/// the header. Only while [`BackupServer::keep_rows`] is on.
fn photo_backup_answer(state: &mut ServerState, request: &beebeeb_api::Request) -> Option<RouteAnswer> {
    let path = request.path();
    if path != "/api/v1/files/photo-backup/check" && path != "/api/v1/files/photo-backup/mark" {
        return None;
    }
    let header = request.header("X-Beebeeb-Device-Id").map(str::to_owned);
    let device = header.clone().unwrap_or_default();
    let rows = state.rows.as_mut()?;
    let body: Value = serde_json::from_slice(request.body()).unwrap();
    let answer = if path.ends_with("/check") {
        let (mut needs, mut backed_up) = (Vec::new(), Vec::new());
        for id in body["identifiers"].as_array().unwrap() {
            let id = id.as_str().unwrap().to_owned();
            match rows.get(&(device.clone(), id.clone())) {
                Some(file_id) => backed_up.push(json!({"local_identifier": id, "file_id": file_id})),
                None => needs.push(id),
            }
        }
        json!({"needs_backup": needs, "backed_up": backed_up})
    } else {
        let id = body["local_identifier"].as_str().unwrap().to_owned();
        let file_id = body["file_id"].as_str().unwrap().to_owned();
        rows.insert((device.clone(), id.clone()), file_id.clone());
        json!({"local_identifier": id, "file_id": file_id, "device_id": device, "status": "recorded"})
    };
    state.keyed_by.push(header);
    Some(Ok(json_answer(200, &[], serde_json::to_vec(&answer).unwrap())))
}

/// One filtered page, dated [`SERVER_DATE`].
pub(crate) fn page(notices: Value, next_cursor: Option<&str>) -> RouteAnswer {
    Ok(json_answer(
        200,
        &[("Date", SERVER_DATE)],
        serde_json::to_vec(&json!({"notifications": notices, "unread_count": 0, "next_cursor": next_cursor})).unwrap(),
    ))
}

/// One filtered page, dated `date`.
fn page_dated(notices: Value, date: &str) -> RouteAnswer {
    Ok(json_answer(
        200,
        &[("Date", date)],
        serde_json::to_vec(&json!({"notifications": notices, "unread_count": 0, "next_cursor": null})).unwrap(),
    ))
}

pub(crate) fn erased(created_at: &str) -> Value {
    json!({"id": "n1", "type": "files_removed", "title": "t", "body": null,
           "data": {"reason": "erase_request"}, "read": false, "created_at": created_at})
}

#[derive(Default)]
pub(crate) struct Source {
    pub(crate) snapshots: Mutex<VecDeque<AssetSnapshot>>,
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

pub(crate) fn one_photo(path: &Path) -> AssetSnapshot {
    AssetSnapshot {
        complete: true,
        assets: vec![Asset {
            local_identifier: "photo-1".into(),
            export_path: path.to_path_buf(),
            name: "photo-1.jpg".into(),
            mime_type: Some("image/jpeg".into()),
            modified_ms: Some(1_000),
            size_bytes: Some(5),
        }],
        next_cursor: None,
    }
}

/// The platform's manifest store, whose writes can be made to fail: every
/// write, or every write after the next `writes_left`.
#[derive(Default)]
pub(crate) struct FlakyStore {
    inner: MemoryBackupManifestStore,
    fail_writes: std::sync::atomic::AtomicBool,
    writes_left: Mutex<Option<usize>>,
}

impl FlakyStore {
    fn write(&self) -> Result<(), BackupManifestStoreError> {
        if self.fail_writes.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(BackupManifestStoreError::Unavailable);
        }
        let mut left = self.writes_left.lock().unwrap();
        match left.as_mut() {
            Some(0) => Err(BackupManifestStoreError::Unavailable),
            Some(n) => {
                *n -= 1;
                Ok(())
            }
            None => Ok(()),
        }
    }
}

impl BackupManifestStore for FlakyStore {
    fn load(&self) -> Result<Vec<BackupManifestRecord>, BackupManifestStoreError> {
        self.inner.load()
    }
    fn replace(&self, records: &[BackupManifestRecord]) -> Result<(), BackupManifestStoreError> {
        self.write()?;
        self.inner.replace(records)
    }
    fn load_pass_state(&self) -> Result<BackupPassState, BackupManifestStoreError> {
        self.inner.load_pass_state()
    }
    fn save_pass_state(&self, state: &BackupPassState) -> Result<(), BackupManifestStoreError> {
        self.write()?;
        self.inner.save_pass_state(state)
    }
    fn clear(&self) -> Result<(), BackupManifestStoreError> {
        self.write()?;
        self.inner.clear()
    }
}

pub(crate) struct Harness {
    _root: tempfile::TempDir,
    pub(crate) photo: PathBuf,
    pub(crate) server: BackupServer,
    pub(crate) scripted: ScriptedTransport,
    pub(crate) source: Arc<Source>,
    pub(crate) uploads: Arc<UploadService>,
    pub(crate) backup: BackupService,
    client: Arc<Client>,
    store: Arc<FlakyStore>,
    configuration: BackupConfiguration,
}

/// A backup into the category folder, with `snapshots` photo snapshots and
/// the scripted (non-gate) answers `replies`.
pub(crate) fn harness(
    configuration: impl FnOnce(BackupConfiguration) -> BackupConfiguration,
    replies: &[&str],
) -> Harness {
    harness_on(BackupServer::default(), configuration, replies)
}

/// [`harness`] on a server shared with another device.
pub(crate) fn harness_on(
    server: BackupServer,
    configuration: impl FnOnce(BackupConfiguration) -> BackupConfiguration,
    replies: &[&str],
) -> Harness {
    let root = tempdir().unwrap();
    let photo = root.path().join("photo.jpg");
    std::fs::write(&photo, b"photo").unwrap();
    let scripted = ScriptedTransport::json(200, replies.first().copied().unwrap_or("{}").as_bytes().to_vec());
    for reply in replies.iter().skip(1) {
        scripted.push_json(200, reply.as_bytes().to_vec());
    }
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
    let config =
        configuration(BackupConfiguration::new(BackupFolder { id: CATEGORY.into() }, false, THIS_DEVICE).unwrap());
    let store = Arc::new(FlakyStore::default());
    let backup = BackupService::with_manifest_store(
        Arc::clone(&client),
        Arc::clone(&uploads),
        source.clone(),
        config.clone(),
        store.clone(),
    )
    .unwrap();
    Harness {
        _root: root,
        photo,
        server,
        scripted,
        source,
        uploads,
        backup,
        client,
        store,
        configuration: config,
    }
}

impl Harness {
    /// The app restarts: the service is dropped and made again on the same
    /// manifest store and upload service.
    pub(crate) fn restart(self) -> Self {
        self.try_restart().unwrap()
    }

    /// The platform's store writes fail from now on.
    pub(crate) fn fail_store_writes(&self) {
        self.store.fail_writes.store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// The platform's store takes `writes` more writes, then fails.
    pub(crate) fn fail_store_writes_after(&self, writes: usize) {
        *self.store.writes_left.lock().unwrap() = Some(writes);
    }

    /// The platform's store works again.
    pub(crate) fn allow_store_writes(&self) {
        self.store.fail_writes.store(false, std::sync::atomic::Ordering::SeqCst);
        *self.store.writes_left.lock().unwrap() = None;
    }

    /// [`Self::restart`], whose new service may be refused.
    pub(crate) fn try_restart(self) -> Result<Self, crate::backup::BackupError> {
        let Self {
            _root,
            photo,
            server,
            scripted,
            source,
            uploads,
            backup,
            client,
            store,
            configuration,
        } = self;
        drop(backup);
        let backup = BackupService::with_manifest_store(
            Arc::clone(&client),
            Arc::clone(&uploads),
            source.clone(),
            configuration.clone(),
            store.clone(),
        )?;
        Ok(Self {
            _root,
            photo,
            server,
            scripted,
            source,
            uploads,
            backup,
            client,
            store,
            configuration,
        })
    }

    /// A second backup service on the same upload service.
    pub(crate) fn second_service(&self) -> Result<BackupService, crate::backup::BackupError> {
        BackupService::with_manifest_store(
            Arc::clone(&self.client),
            Arc::clone(&self.uploads),
            self.source.clone(),
            self.configuration.clone(),
            self.store.clone(),
        )
    }

    pub(crate) fn snapshot_photo(&self) {
        self.source.snapshots.lock().unwrap().push_back(one_photo(&self.photo));
    }

    pub(crate) async fn pass(&self, now_ms: i64) -> crate::backup::BackupBatch {
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
    let setup_ms = SERVER_NOW_MS - 60_000;
    let h = harness(
        |c| c.with_first_pass(Some(setup_ms), None),
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

    // The next pass reads from the same baseline, less core's overlap.
    let next = h.pass(2).await;
    assert!(!next.check_failed);
    assert_eq!(next.queued, 1);
    let since = format!("&since={}&", setup_ms - NOTICE_OVERLAP_MS);
    let paths = h.server.notice_paths();
    assert!(paths.iter().all(|path| path.contains(&since)), "{paths:?}");
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

/// Notices from before the setup, less core's overlap, do not apply. One
/// inside the overlap stops the first pass once (12d's accepted edge: it errs
/// toward stopping), covered by `the_12d_vectors_hold_through_the_service_decision`.
#[tokio::test]
async fn the_first_pass_ignores_notices_from_before_backups_were_set_up() {
    let setup_ms = SERVER_NOW_MS - 60_000;
    let h = harness(
        |c| c.with_first_pass(Some(setup_ms), None),
        &[r#"{"needs_backup":["photo-1"]}"#],
    );
    // 11 minutes before the Date: 10 before the setup, past the overlap.
    h.server.push_page(page(json!([erased("2026-11-08T02:59:00Z")]), None));
    h.snapshot_photo();

    let batch = h.pass(1).await;

    assert_eq!(batch.stopped, None);
    assert_eq!(batch.queued, 1);
    assert!(h.server.notice_paths()[0].contains(&format!("&since={}&", setup_ms - NOTICE_OVERLAP_MS)));
}

#[tokio::test]
async fn with_no_baseline_known_any_removal_notice_stops_the_first_pass() {
    let h = harness(|c| c, &[]);
    h.server.push_page(page(json!([erased("2020-01-01T00:00:00Z")]), None));
    h.snapshot_photo();

    assert_eq!(h.pass(1).await.stopped, Some(BackupStopReason::EraseRequest));
}

#[tokio::test]
async fn a_pass_that_ran_stores_its_server_start_and_reads_from_it_less_the_overlap() {
    let h = harness(|c| c, &[r#"{"needs_backup":["photo-1"]}"#]);
    h.snapshot_photo();

    h.pass(1).await;

    assert_eq!(
        h.backup.manifest().pass_state().unwrap().last_pass_at_ms,
        Some(SERVER_NOW_MS)
    );
    h.snapshot_photo();
    h.pass(2).await;
    let since = SERVER_NOW_MS - NOTICE_OVERLAP_MS;
    assert!(h.server.notice_paths()[1].contains(&format!("&since={since}&")));
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

/// (b) Amendment 12d: "Back up again" keeps the acknowledged ids, so the
/// notice the person saw never stops the backup again, even served again
/// inside the overlap and dated after the stop's `Date`; a new notice still
/// stops it.
#[tokio::test]
async fn back_up_again_after_a_notice_does_not_stop_again_on_it() {
    let h = harness(|c| c, &[r#"{"needs_backup":["photo-1"]}"#]);
    let notice = erased("2026-11-08T03:30:00Z");
    h.server.push_page(page(json!([notice.clone()]), None));
    h.backup
        .manifest()
        .remember("photo-1", "trashed-copy", BackupCopyState::Trashed)
        .unwrap();
    h.backup
        .manifest()
        .remember("photo-2", "live-copy", BackupCopyState::Active)
        .unwrap();
    assert_eq!(h.pass(1).await.stopped, Some(BackupStopReason::EraseRequest));
    let stopped = h.backup.manifest().pass_state().unwrap();
    assert_eq!(stopped.last_pass_at_ms, Some(SERVER_NOW_MS), "stored with the stop");
    assert_eq!(stopped.acknowledged, ["n1"], "stored with the stop");

    h.backup.back_up_again().unwrap();

    let state = h.backup.manifest().pass_state().unwrap();
    assert_eq!(state.stopped, None);
    assert_eq!(state.last_pass_at_ms, Some(SERVER_NOW_MS));
    assert_eq!(state.acknowledged, ["n1"], "kept by Back up again");
    assert_eq!(h.backup.manifest().copy_state("photo-1"), None);
    assert_eq!(
        h.backup.manifest().copy_state("photo-2"),
        None,
        "every record is forgotten"
    );
    // The notice the person saw is served again but no longer stops the
    // backup; the photo is backed up fresh.
    h.server.push_page(page(json!([notice.clone()]), None));
    h.snapshot_photo();
    let batch = h.pass(2).await;
    assert_eq!(batch.stopped, None);
    assert_eq!(batch.queued, 1);
    let since = SERVER_NOW_MS - NOTICE_OVERLAP_MS;
    assert!(h.server.notice_paths()[1].contains(&format!("&since={since}&")));
    // A notice written since then stops it.
    let mut later = erased("2026-11-08T03:40:00Z");
    later["id"] = json!("n2");
    h.server.push_page(page(json!([notice, later]), None));
    assert_eq!(h.pass(3).await.stopped, Some(BackupStopReason::EraseRequest));
    assert_eq!(h.backup.manifest().pass_state().unwrap().acknowledged, ["n1", "n2"]);
}

/// (a) Amendment 12d: a notice whose transaction was still open when a pass
/// read (dated before that pass's start, seen only after) is caught by the
/// next pass's overlap and acts once: it stops the backup, and two passes
/// that both read it do not act on it twice.
#[tokio::test]
async fn a_late_notice_inside_the_overlap_acts_once_across_two_passes() {
    let needs = r#"{"needs_backup":["photo-1"]}"#;
    let h = harness(|c| c, &[needs, needs]);
    h.snapshot_photo();
    assert_eq!(h.pass(1).await.queued, 1);
    assert_eq!(
        h.backup.manifest().pass_state().unwrap().last_pass_at_ms,
        Some(SERVER_NOW_MS)
    );

    // Dated a minute before pass 1's start, committed after pass 1 read.
    let late = erased("2026-11-08T03:09:00Z");
    h.server.push_page(page(json!([late.clone()]), None));
    let batch = h.pass(2).await;
    assert_eq!(
        batch.stopped,
        Some(BackupStopReason::EraseRequest),
        "the overlap catches it"
    );
    let since = SERVER_NOW_MS - NOTICE_OVERLAP_MS;
    assert!(h.server.notice_paths()[1].contains(&format!("&since={since}&")));
    assert_eq!(h.backup.manifest().pass_state().unwrap().acknowledged, ["n1"]);

    h.backup.back_up_again().unwrap();
    h.server.push_page(page(json!([late]), None));
    h.snapshot_photo();
    let again = h.pass(3).await;
    assert_eq!(again.stopped, None, "the same notice does not act twice");
    assert_eq!(again.queued, 1);
}

/// (c) Amendment 12d rule 4: the acknowledged ids, the stop and the new
/// `last_pass_at` are one write. Whichever write the platform refuses (the
/// first of the pass, or the one after it), the stored state is the old one
/// whole or the new one whole, never the new ids with the old `last_pass_at`;
/// memory follows the store; and the next pass decides again.
#[tokio::test]
async fn a_failed_write_keeps_the_old_acknowledged_set_and_last_pass_at_together() {
    const LATER_DATE: &str = "Sun, 08 Nov 2026 03:30:00 GMT";
    const LATER_MS: i64 = SERVER_NOW_MS + 20 * 60_000;
    for writes in [0, 1] {
        let needs = r#"{"needs_backup":["photo-1"]}"#;
        let h = harness(|c| c, &[needs, needs]);
        let mut old = erased("2026-11-08T03:05:00Z");
        old["id"] = json!("n0");
        h.server.push_page(page(json!([old.clone()]), None));
        assert_eq!(h.pass(1).await.stopped, Some(BackupStopReason::EraseRequest));
        h.backup.back_up_again().unwrap();
        let before = h.backup.manifest().pass_state().unwrap();
        assert_eq!(before.acknowledged, ["n0"]);
        assert_eq!(before.last_pass_at_ms, Some(SERVER_NOW_MS));

        // A new notice: the pass stops and acknowledges it, dated later.
        let notices = json!([old.clone(), erased("2026-11-08T03:20:00Z")]);
        h.server.push_page(page_dated(notices.clone(), LATER_DATE));
        h.snapshot_photo();
        h.fail_store_writes_after(writes);
        let _ = h.backup.next_batch(AssetKind::Photo, NetworkKind::WiFi, 2).await;
        assert_eq!(h.server.notice_paths().len(), 2, "{writes}: the gate read the notices");

        let stored = h.store.inner.load_pass_state().unwrap();
        assert_eq!(
            h.backup.manifest().pass_state().unwrap(),
            stored,
            "{writes}: memory follows the store"
        );
        let whole_new =
            stored.acknowledged == ["n0", "n1"] && stored.last_pass_at_ms == Some(LATER_MS) && stored.stopped.is_some();
        assert!(stored == before || whole_new, "{writes}: {stored:?}");
        if writes == 0 {
            assert_eq!(stored, before, "the pass's one write was refused");
            assert!(h.uploads.list().unwrap().is_empty());
            // The store works again: the same notices stop the next pass, stored whole.
            h.allow_store_writes();
            h.server.push_page(page_dated(notices, LATER_DATE));
            assert_eq!(h.pass(3).await.stopped, Some(BackupStopReason::EraseRequest));
            let after = h.store.inner.load_pass_state().unwrap();
            assert_eq!(after.acknowledged, ["n0", "n1"]);
            assert_eq!(after.last_pass_at_ms, Some(LATER_MS));
            assert!(after.stopped.is_some());
        } else {
            assert!(whole_new, "the pass's one write went through: {stored:?}");
        }
    }
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

// ── Review r5 ───────────────────────────────────────────────────────────────

/// The asset snapshot of `count` photos, `photo-0` up.
fn photos(path: &Path, count: usize) -> AssetSnapshot {
    AssetSnapshot {
        complete: true,
        assets: (0..count)
            .map(|index| Asset {
                local_identifier: format!("photo-{index}"),
                export_path: path.to_path_buf(),
                name: format!("photo-{index}.jpg"),
                mime_type: Some("image/jpeg".into()),
                modified_ms: None,
                size_bytes: None,
            })
            .collect(),
        next_cursor: None,
    }
}

/// P2-1 (spec §4.2 rule 11): the person trashes the copy on the web. The
/// phone hears nothing (no `assets_changed`), and no notice is written for
/// one file, so the gate runs. The server's check counts only live copies, so
/// it asks for the photo again; the copy itself (r6 P1-2) is in the Trash.
#[tokio::test]
async fn a_copy_trashed_elsewhere_is_not_uploaded_again() {
    let h = harness(|c| c, &[r#"{"needs_backup":["photo-1"]}"#]);
    h.server.set_copy("copy-1", CopyRow::Trashed);
    h.backup
        .manifest()
        .remember("photo-1", "copy-1", BackupCopyState::Active)
        .unwrap();
    h.snapshot_photo();

    let batch = h.pass(1).await;

    assert_eq!(batch.queued, 0);
    assert!(h.uploads.list().unwrap().is_empty());
    assert_eq!(
        h.backup.manifest().copy_state("photo-1"),
        Some(BackupCopyState::RemovedElsewhere)
    );
    // Unchanged, it stays removed and is not even asked about again.
    h.snapshot_photo();
    assert_eq!(h.pass(2).await.queued, 0);
    assert_eq!(h.scripted.request_count(), 1);
}

/// Rule 11: only a new modification time or size uploads it again.
#[tokio::test]
async fn a_copy_removed_elsewhere_comes_back_once_the_photo_changes() {
    let needs = r#"{"needs_backup":["photo-1"]}"#;
    let h = harness(|c| c, &[needs, needs]);
    h.server.set_copy("copy-1", CopyRow::Trashed);
    h.backup
        .manifest()
        .remember("photo-1", "copy-1", BackupCopyState::Active)
        .unwrap();
    h.snapshot_photo();
    assert_eq!(h.pass(1).await.queued, 0);

    let mut edited = one_photo(&h.photo);
    edited.assets[0].modified_ms = Some(2_000);
    h.source.snapshots.lock().unwrap().push_back(edited);
    let batch = h.pass(2).await;

    assert_eq!(batch.queued, 1);
    assert_eq!(h.backup.manifest().copy_state("photo-1"), Some(BackupCopyState::Queued));
}

/// A copy the platform reports trashed is measured against the photo as it
/// is after the removal: an edit made before it does not bring the copy back,
/// a later one does (the safer reading of rule 11).
#[tokio::test]
async fn a_copy_reported_trashed_comes_back_only_after_a_later_change() {
    let h = harness(
        |c| c,
        &[
            r#"{"backed_up":[{"local_identifier":"photo-1","file_id":"copy-1"}]}"#,
            r#"{"needs_backup":["photo-1"]}"#,
        ],
    );
    h.snapshot_photo();
    assert_eq!(h.pass(1).await.queued, 0);
    assert_eq!(h.backup.manifest().copy_state("photo-1"), Some(BackupCopyState::Active));
    h.backup
        .assets_changed(&[BackupAssetChange {
            file_id: "copy-1".into(),
            state: BackupCopyState::Trashed,
        }])
        .unwrap();

    let mut edited = one_photo(&h.photo);
    edited.assets[0].size_bytes = Some(6);
    h.source.snapshots.lock().unwrap().push_back(edited.clone());
    assert_eq!(h.pass(2).await.queued, 0, "the edit came before the removal");
    assert_eq!(h.scripted.request_count(), 1);

    edited.assets[0].size_bytes = Some(7);
    h.source.snapshots.lock().unwrap().push_back(edited);
    assert_eq!(h.pass(3).await.queued, 1);
}

/// P2-2: a stop cancels the upload, then the app dies before the manifest is
/// written, so the record is still `Queued` with no live upload.
#[tokio::test]
async fn a_stop_cut_off_after_its_cancel_never_strands_a_photo() {
    let h = harness(
        |c| c,
        &[r#"{"needs_backup":["photo-1"]}"#, r#"{"needs_backup":["photo-1"]}"#],
    );
    h.snapshot_photo();
    assert_eq!(h.pass(1).await.queued, 1);
    h.uploads.cancel_backup_uploads(2).unwrap();
    h.server.push_page(page(json!([erased("2026-11-08T03:30:00Z")]), None));

    assert_eq!(h.pass(3).await.stopped, Some(BackupStopReason::EraseRequest));
    assert_eq!(
        h.backup.manifest().copy_state("photo-1"),
        None,
        "no queued record outlives a stop"
    );

    h.backup.back_up_again().unwrap();
    h.snapshot_photo();
    assert_eq!(h.pass(4).await.queued, 1);
}

/// P3-1: a stop written while a pass waits on the gate's requests (another
/// kind's pass, or any other writer) is never written over by that pass.
#[tokio::test]
async fn a_stop_written_during_a_pass_sticks() {
    let h = harness(|c| c, &[r#"{"needs_backup":["photo-1"]}"#]);
    let manifest = h.backup.manifest();
    h.server.on_notice(move || {
        manifest
            .update_pass_state(|state| {
                state.stopped = Some(BackupStop {
                    reason: BackupStopReason::AccountReset,
                });
            })
            .unwrap();
    });
    h.snapshot_photo();

    let batch = h.pass(1).await;

    assert_eq!(h.backup.stopped().unwrap(), Some(BackupStopReason::AccountReset));
    assert_eq!(batch.stopped, Some(BackupStopReason::AccountReset));
    assert_eq!(batch.queued, 0);
    assert!(h.uploads.list().unwrap().is_empty());
}

/// P3-3: after a deleted-folder stop, "Back up again" needs a live folder
/// configured first; with the deleted one still configured it stops again.
#[tokio::test]
async fn back_up_again_after_a_deleted_folder_needs_a_live_folder_first() {
    let h = harness(|c| c, &[r#"{"needs_backup":["photo-1"]}"#]);
    h.server.set_category(Row::Trashed);
    assert_eq!(h.pass(1).await.stopped, Some(BackupStopReason::Unknown));

    h.backup.back_up_again().unwrap();
    assert_eq!(
        h.pass(2).await.stopped,
        Some(BackupStopReason::Unknown),
        "the deleted folder is still configured"
    );

    // The platform finds this device's folder again (Amendment 12), then the
    // person chooses again.
    h.backup
        .configure(BackupConfiguration::new(BackupFolder { id: DEVICE.into() }, false, THIS_DEVICE).unwrap())
        .unwrap();
    h.backup.back_up_again().unwrap();
    h.snapshot_photo();
    let batch = h.pass(3).await;
    assert_eq!(batch.stopped, None);
    assert_eq!(batch.queued, 1);
}

/// P3-2: after a restart nothing is cached, and the configured folder is gone
/// for good (404). The pass reaches the gate, stops and says why.
#[tokio::test]
async fn a_configured_folder_deleted_for_good_stops_the_backup_and_says_why() {
    let h = harness(|c| c, &[]);
    h.server.set_category(Row::Gone);
    h.snapshot_photo();

    let batch = h.pass(1).await;

    assert_eq!(batch.stopped, Some(BackupStopReason::Unknown));
    assert_eq!(h.backup.stopped().unwrap(), Some(BackupStopReason::Unknown));
    assert!(h.uploads.list().unwrap().is_empty());
}

#[tokio::test]
async fn a_device_folder_deleted_for_good_from_another_device_says_so() {
    let h = harness(
        |c| BackupConfiguration {
            folder: BackupFolder { id: DEVICE.into() },
            ..c
        },
        &[],
    );
    h.server.set_device(Row::Gone);
    h.server.push_page(page(
        json!([{"id": "n2", "type": "backup_deleted", "title": "t", "body": null,
                "data": {"device_folder_id": DEVICE}, "read": false,
                "created_at": "2026-11-08T03:00:00Z"}]),
        None,
    ));
    h.snapshot_photo();

    assert_eq!(h.pass(1).await.stopped, Some(BackupStopReason::BackupDeleted));
}

/// P3-4: with the upload queue full, the gate still runs, so a stop cancels
/// the uploads in flight instead of letting them land after an erase.
#[tokio::test]
async fn the_gate_runs_while_the_upload_queue_is_full() {
    let identifiers: Vec<String> = (0..64).map(|index| format!("photo-{index}")).collect();
    let reply = json!({ "needs_backup": identifiers }).to_string();
    let h = harness(|c| c, &[&reply]);
    h.source.snapshots.lock().unwrap().push_back(photos(&h.photo, 64));
    assert_eq!(h.pass(1).await.queued, 64);
    assert_eq!(h.uploads.active_backup_count().unwrap(), 64);
    h.server.push_page(page(json!([erased("2026-11-08T03:30:00Z")]), None));

    let batch = h.pass(2).await;

    assert_eq!(batch.stopped, Some(BackupStopReason::EraseRequest));
    assert_eq!(h.uploads.active_backup_count().unwrap(), 0);
}
