use std::{
    collections::{HashMap, VecDeque},
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

use beebeeb_api::{Answer, Header};
use beebeeb_core::{
    chunk_stream::ExpectedChunkFormat,
    encrypt::encrypt_name_for_new_item,
    item_id::NewItemId,
    kdf::MasterKey,
    sync::{StoredSyncMetadata, StoredSyncState, SyncOp, SyncStore, SyncStoreChanges, SyncStoreError, TreeNode},
};
use chrono::Utc;
use tempfile::tempdir;
use uuid::Uuid;

use crate::{
    Client, ClientConfig, EngineEvent, Session, StreamLimits,
    backup::{
        Asset, AssetKind, AssetSnapshot, AssetSource, AssetSourceError, BackupConfiguration, BackupCopyState,
        BackupError, BackupFolder, BackupManifest, BackupService, MemoryBackupManifestStore,
    },
    downloads::{DownloadFile, DownloadService},
    file_provider::{DomainNotifier, DomainNotifierError, FileProviderService, ItemWorkState},
    files::{FileRecord, duplicate_file},
    platform::{
        AccountDataPurgeError, AccountDataPurger, PlatformCancellationError, PlatformTransferCanceller,
        ServiceCoordinator, SignOutFailure,
    },
    search::SearchService,
    test_support::ScriptedTransport,
    thumbnails::{ImageCodec, ImageCodecError, ThumbnailService},
    uploads::{NetworkKind, UploadService},
};

mod coordinator;

fn authenticated_client(transport: ScriptedTransport) -> Arc<Client> {
    let client = Arc::new(Client::new(ClientConfig::for_tests(), Arc::new(transport)).unwrap());
    client.set_authentication("token", "owner").unwrap();
    client
}

#[derive(Default)]
struct Source {
    snapshots: Mutex<VecDeque<Result<AssetSnapshot, AssetSourceError>>>,
}

impl AssetSource for Source {
    fn snapshot(
        &self,
        _kind: AssetKind,
        _cursor: Option<&str>,
        _limit: usize,
    ) -> Result<AssetSnapshot, AssetSourceError> {
        self.snapshots.lock().unwrap().pop_front().unwrap()
    }
}

fn asset(id: &str, path: PathBuf) -> Asset {
    Asset {
        local_identifier: id.into(),
        export_path: path,
        name: format!("{id}.jpg"),
        mime_type: Some("image/jpeg".into()),
    }
}

struct CountingAssetSource {
    path: PathBuf,
    calls: AtomicUsize,
}

impl AssetSource for CountingAssetSource {
    fn snapshot(
        &self,
        _kind: AssetKind,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<AssetSnapshot, AssetSourceError> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        let start = cursor.and_then(|value| value.parse::<usize>().ok()).unwrap_or(0);
        let end = start.saturating_add(limit).min(100_000);
        Ok(AssetSnapshot {
            complete: true,
            assets: (start..end)
                .map(|index| asset(&format!("asset-{index:06}"), self.path.clone()))
                .collect(),
            next_cursor: (end < 100_000).then(|| end.to_string()),
        })
    }
}

#[tokio::test]
async fn backup_pages_a_hundred_thousand_assets_and_duplicate_checks() {
    let root = tempdir().unwrap();
    let path = root.path().join("photo.jpg");
    std::fs::write(&path, b"photo").unwrap();
    let first_ids: Vec<_> = (0..500).map(|index| format!("asset-{index:06}")).collect();
    let transport = ScriptedTransport::json(
        200,
        serde_json::to_vec(&serde_json::json!({"already_backed_up": first_ids})).unwrap(),
    );
    for page in 1..200 {
        let start = page * 500;
        let ids: Vec<_> = (start..start + 500).map(|index| format!("asset-{index:06}")).collect();
        transport.push_json(
            200,
            serde_json::to_vec(&serde_json::json!({"already_backed_up": ids})).unwrap(),
        );
    }
    let source = Arc::new(CountingAssetSource {
        path,
        calls: AtomicUsize::new(0),
    });
    let (backup, uploads) = backup_service(transport.clone(), source.clone(), root.path());

    let batch = backup.next_batch(AssetKind::Photo, NetworkKind::WiFi, 1).await.unwrap();

    assert_eq!(batch.already_backed_up, 64);
    assert_eq!(batch.queued, 0);
    assert!(!batch.snapshot_complete);
    assert_eq!(source.calls.load(Ordering::Relaxed), 1);
    // Three reads place the backup folder in the Backups tree (once per
    // service), then one duplicate check.
    assert_eq!(transport.request_count(), 4);
    assert!(uploads.list().unwrap().is_empty());
}

#[test]
fn backup_manifest_reopens_through_the_platform_persistence_seam() {
    let store = Arc::new(MemoryBackupManifestStore::default());
    let first = BackupManifest::open(store.clone()).unwrap();
    first.remember("photo", "remote", BackupCopyState::Trashed).unwrap();

    let reopened = BackupManifest::open(store).unwrap();

    assert_eq!(reopened.copy_state("photo"), Some(BackupCopyState::Trashed));
    assert_eq!(reopened.file_id("photo").as_deref(), Some("remote"));
}

/// The rows the backup service reads once to place its folder: a category
/// folder, its device folder, and the flagged Backups root.
fn answer_backup_folder_check(transport: &ScriptedTransport) {
    for row in [
        serde_json::json!({"id": "backups-root", "parent_id": null, "is_folder": true, "system_role": "backups_root"}),
        serde_json::json!({"id": "device-folder", "parent_id": "backups-root", "is_folder": true}),
        serde_json::json!({"id": "backup-folder", "parent_id": "device-folder", "is_folder": true}),
    ] {
        transport.respond_next_json(200, serde_json::to_vec(&row).unwrap());
    }
}

fn backup_service(
    transport: ScriptedTransport,
    source: Arc<dyn AssetSource>,
    root: &std::path::Path,
) -> (BackupService, Arc<UploadService>) {
    answer_backup_folder_check(&transport);
    let client = authenticated_client(transport);
    let uploads = Arc::new(
        UploadService::new_for_test(
            Arc::clone(&client),
            Arc::new(Mutex::new(beebeeb_store::Store::open_in_memory().unwrap())),
            Arc::new(MasterKey::from_bytes([7; 32])),
            root.join("staging"),
        )
        .unwrap(),
    );
    let config = BackupConfiguration::new(
        BackupFolder {
            id: "backup-folder".into(),
        },
        true,
    )
    .unwrap();
    (
        BackupService::new(client, Arc::clone(&uploads), source, config).unwrap(),
        uploads,
    )
}

#[tokio::test]
async fn failed_backup_deduplication_starts_no_upload_batch() {
    let root = tempdir().unwrap();
    let path = root.path().join("photo.jpg");
    std::fs::write(&path, b"photo").unwrap();
    let transport = ScriptedTransport::json(500, br#"{"code":"unavailable"}"#.to_vec());
    let source = Arc::new(Source::default());
    source.snapshots.lock().unwrap().push_back(Ok(AssetSnapshot {
        complete: true,
        assets: vec![asset("photo-1", path)],
        next_cursor: None,
    }));
    let (backup, uploads) = backup_service(transport, source, root.path());

    let result = backup.next_batch(AssetKind::Photo, NetworkKind::WiFi, 1).await;

    assert!(matches!(result, Err(BackupError::DeduplicationDeferred)));
    assert!(uploads.list().unwrap().is_empty());
}

#[tokio::test]
async fn incomplete_backup_snapshot_never_marks_missing_assets_deleted() {
    let root = tempdir().unwrap();
    let path = root.path().join("one.jpg");
    std::fs::write(&path, b"one").unwrap();
    let transport = ScriptedTransport::json(
        200,
        br#"{"already_backed_up":["one"],"backed_up":[{"local_identifier":"one","file_id":"remote-one"}]}"#.to_vec(),
    );
    let source = Arc::new(Source::default());
    source.snapshots.lock().unwrap().push_back(Ok(AssetSnapshot {
        complete: false,
        assets: vec![asset("one", path)],
        next_cursor: None,
    }));
    let (backup, _) = backup_service(transport, source, root.path());
    backup
        .manifest()
        .remember("missing", "remote-missing", BackupCopyState::Active)
        .unwrap();

    backup.next_batch(AssetKind::Photo, NetworkKind::WiFi, 1).await.unwrap();

    assert_eq!(backup.manifest().copy_state("missing"), Some(BackupCopyState::Active));
}

#[tokio::test]
async fn trashed_backup_copy_is_uploaded_again_even_if_it_was_seen_before() {
    let root = tempdir().unwrap();
    let path = root.path().join("photo.jpg");
    std::fs::write(&path, b"photo").unwrap();
    let transport = ScriptedTransport::json(200, br#"{"already_backed_up":["photo-1"]}"#.to_vec());
    let source = Arc::new(Source::default());
    source.snapshots.lock().unwrap().push_back(Ok(AssetSnapshot {
        complete: true,
        assets: vec![asset("photo-1", path)],
        next_cursor: None,
    }));
    let (backup, uploads) = backup_service(transport, source, root.path());
    backup
        .manifest()
        .remember("photo-1", "old-copy", BackupCopyState::Trashed)
        .unwrap();

    let batch = backup.next_batch(AssetKind::Photo, NetworkKind::WiFi, 1).await.unwrap();

    assert_eq!(batch.queued, 1);
    assert_eq!(uploads.list().unwrap().len(), 1);
}

#[tokio::test]
async fn queued_backup_asset_is_not_enqueued_again() {
    let root = tempdir().unwrap();
    let path = root.path().join("photo.jpg");
    std::fs::write(&path, b"photo").unwrap();
    let transport = ScriptedTransport::json(200, br#"{"needs_backup":["photo-1"]}"#.to_vec());
    let source = Arc::new(Source::default());
    source.snapshots.lock().unwrap().extend([
        Ok(AssetSnapshot {
            complete: true,
            assets: vec![asset("photo-1", path.clone())],
            next_cursor: None,
        }),
        Ok(AssetSnapshot {
            complete: true,
            assets: vec![asset("photo-1", path)],
            next_cursor: None,
        }),
    ]);
    let (backup, uploads) = backup_service(transport.clone(), source, root.path());

    backup.next_batch(AssetKind::Photo, NetworkKind::WiFi, 1).await.unwrap();
    let second = backup.next_batch(AssetKind::Photo, NetworkKind::WiFi, 2).await.unwrap();

    assert_eq!(second.queued, 0);
    assert_eq!(uploads.list().unwrap().len(), 1);
    // The folder is placed once (three reads) for both batches.
    assert_eq!(transport.request_count(), 4);
}

#[tokio::test]
async fn successful_backup_transfer_marks_manifest_without_platform_callback() {
    let root = tempdir().unwrap();
    let path = root.path().join("photo.jpg");
    std::fs::write(&path, b"photo").unwrap();
    let transport = ScriptedTransport::json(200, br#"{"needs_backup":["photo-1"]}"#.to_vec());
    let source = Arc::new(Source::default());
    source.snapshots.lock().unwrap().push_back(Ok(AssetSnapshot {
        complete: true,
        assets: vec![asset("photo-1", path)],
        next_cursor: None,
    }));
    let (backup, uploads) = backup_service(transport.clone(), source, root.path());
    backup.next_batch(AssetKind::Photo, NetworkKind::WiFi, 1).await.unwrap();
    let queued = uploads.list().unwrap().pop().unwrap();
    transport.push_json(
        200,
        serde_json::to_vec(&serde_json::json!({
            "upload_session_id": "session", "file_id": queued.file_id,
            "chunk_size_bytes": 32, "chunk_count": 1
        }))
        .unwrap(),
    );
    transport.push_json(
        200,
        serde_json::to_vec(&serde_json::json!({
            "token": "scoped", "upload_session_id": "session",
            "expires_at": "2099-01-01T00:00:00Z"
        }))
        .unwrap(),
    );
    transport.push_json(200, b"{}".to_vec());
    transport.push_json(
        200,
        serde_json::to_vec(&serde_json::json!({
            "local_identifier": "photo-1", "file_id": queued.file_id,
            "device_id": "device", "status": "active"
        }))
        .unwrap(),
    );

    let (upload_id, requests) = uploads.next_transfers(1, NetworkKind::WiFi, 2).await.unwrap().unwrap();
    assert_eq!(requests.len(), 1);
    uploads
        .transfer_finished(upload_id, &requests[0].ticket, 200, None, None, &[], 3)
        .await
        .unwrap();

    assert_eq!(backup.manifest().copy_state("photo-1"), Some(BackupCopyState::Active));
    assert_eq!(
        uploads.list().unwrap()[0].state,
        beebeeb_store::TransferState::Succeeded
    );
}

#[tokio::test]
async fn completion_without_a_handler_is_durable_and_applied_by_a_later_backup_service() {
    let root = tempdir().unwrap();
    let path = root.path().join("photo.jpg");
    std::fs::write(&path, b"photo").unwrap();
    let transport = ScriptedTransport::json(
        200,
        serde_json::to_vec(&serde_json::json!({
            "token": "scoped", "upload_session_id": "session",
            "expires_at": "2099-01-01T00:00:00Z"
        }))
        .unwrap(),
    );
    let client = authenticated_client(transport.clone());
    let store = Arc::new(Mutex::new(beebeeb_store::Store::open_in_memory().unwrap()));
    let uploads = Arc::new(
        UploadService::new_for_test(
            Arc::clone(&client),
            Arc::clone(&store),
            Arc::new(MasterKey::from_bytes([7; 32])),
            root.path().join("staging"),
        )
        .unwrap(),
    );
    let id = uploads
        .enqueue(
            crate::uploads::UploadRequest::new(&path, "photo.jpg", Some("image/jpeg".into()), None)
                .for_backup("photo-1"),
            1,
        )
        .unwrap();
    let file_id = uploads.list().unwrap()[0].file_id.clone();
    transport.respond_next_json(
        200,
        serde_json::to_vec(&serde_json::json!({
            "upload_session_id": "session", "file_id": file_id,
            "chunk_size_bytes": 32, "chunk_count": 1
        }))
        .unwrap(),
    );
    transport.push_json(200, b"{}".to_vec());
    let (_, requests) = uploads.next_transfers(1, NetworkKind::WiFi, 2).await.unwrap().unwrap();
    uploads
        .transfer_finished(id, &requests[0].ticket, 200, None, None, &[], 3)
        .await
        .unwrap();
    assert_eq!(
        uploads.list().unwrap()[0].state,
        beebeeb_store::TransferState::Succeeded
    );

    transport.push_json(
        200,
        serde_json::to_vec(&serde_json::json!({
            "local_identifier": "photo-1", "file_id": file_id,
            "device_id": "device", "status": "active"
        }))
        .unwrap(),
    );
    let backup = BackupService::new(
        client,
        Arc::clone(&uploads),
        Arc::new(Source::default()),
        BackupConfiguration::new(
            BackupFolder {
                id: "backup-folder".into(),
            },
            true,
        )
        .unwrap(),
    )
    .unwrap();

    backup
        .next_batch(AssetKind::Photo, NetworkKind::Offline, 4)
        .await
        .unwrap();

    assert_eq!(backup.manifest().copy_state("photo-1"), Some(BackupCopyState::Active));
    assert!(uploads.pending_backup_outcomes().unwrap().is_empty());
}

#[tokio::test]
async fn cancelled_backup_uploads_retry_only_three_times() {
    let root = tempdir().unwrap();
    let path = root.path().join("photo.jpg");
    std::fs::write(&path, b"photo").unwrap();
    let transport = ScriptedTransport::json(200, br#"{"needs_backup":["photo-1"]}"#.to_vec());
    transport.push_json(200, br#"{"needs_backup":["photo-1"]}"#.to_vec());
    transport.push_json(200, br#"{"needs_backup":["photo-1"]}"#.to_vec());
    let source = Arc::new(Source::default());
    for _ in 0..4 {
        source.snapshots.lock().unwrap().push_back(Ok(AssetSnapshot {
            complete: true,
            assets: vec![asset("photo-1", path.clone())],
            next_cursor: None,
        }));
    }
    let (backup, uploads) = backup_service(transport, source, root.path());

    for attempt in 0..3 {
        let batch = backup
            .next_batch(AssetKind::Photo, NetworkKind::WiFi, i64::from(attempt) * 2 + 1)
            .await
            .unwrap();
        assert_eq!(batch.queued, 1);
        let id = uploads
            .list()
            .unwrap()
            .into_iter()
            .filter(|upload| upload.state == beebeeb_store::TransferState::Queued)
            .map(|upload| upload.id)
            .max()
            .unwrap();
        uploads.cancel(id, i64::from(attempt) * 2 + 2).unwrap();
    }
    let exhausted = backup
        .next_batch(AssetKind::Photo, NetworkKind::WiFi, 10)
        .await
        .unwrap();

    assert_eq!(exhausted.queued, 0);
    assert_eq!(backup.manifest().retry_count("photo-1"), Some(3));
    assert_eq!(uploads.list().unwrap().len(), 3);
}

#[tokio::test]
async fn backup_wifi_default_blocks_before_asset_or_network_work() {
    let root = tempdir().unwrap();
    let transport = ScriptedTransport::json(200, b"{}".to_vec());
    let source = Arc::new(Source::default());
    let (backup, uploads) = backup_service(transport, source, root.path());

    let batch = backup
        .next_batch(AssetKind::Photo, NetworkKind::Cellular, 1)
        .await
        .unwrap();

    assert!(batch.deferred_for_network);
    assert!(uploads.list().unwrap().is_empty());
}

#[tokio::test]
async fn contact_and_calendar_snapshots_queue_in_the_managed_folder() {
    let root = tempdir().unwrap();
    let contacts = root.path().join("contacts.json");
    let calendar = root.path().join("calendar.json");
    std::fs::write(&contacts, b"[]").unwrap();
    std::fs::write(&calendar, b"[]").unwrap();
    let source = Arc::new(Source::default());
    source.snapshots.lock().unwrap().extend([
        Ok(AssetSnapshot {
            complete: true,
            assets: vec![asset("contacts-v1", contacts)],
            next_cursor: None,
        }),
        Ok(AssetSnapshot {
            complete: true,
            assets: vec![asset("calendar-v1", calendar)],
            next_cursor: None,
        }),
    ]);
    let (backup, uploads) = backup_service(ScriptedTransport::json(200, b"{}".to_vec()), source, root.path());

    backup
        .next_batch(AssetKind::ContactSnapshot, NetworkKind::WiFi, 1)
        .await
        .unwrap();
    backup
        .next_batch(AssetKind::CalendarSnapshot, NetworkKind::WiFi, 2)
        .await
        .unwrap();

    assert_eq!(uploads.list().unwrap().len(), 2);
}

struct CountingStore {
    state: StoredSyncState,
    reads: Arc<AtomicUsize>,
}

impl SyncStore for CountingStore {
    fn load(&self) -> Result<StoredSyncState, SyncStoreError> {
        panic!("the File Provider must not load the whole tree")
    }

    fn load_metadata(&self) -> Result<StoredSyncMetadata, SyncStoreError> {
        Ok(StoredSyncMetadata::from(&self.state))
    }

    fn get_node(&self, id: Uuid) -> Result<Option<TreeNode>, SyncStoreError> {
        self.reads.fetch_add(1, Ordering::Relaxed);
        Ok(self.state.tree.get(&id).cloned())
    }

    fn children(&self, parent_id: Option<Uuid>) -> Result<Vec<TreeNode>, SyncStoreError> {
        let children: Vec<_> = self
            .state
            .tree
            .values()
            .filter(|node| node.parent_id == parent_id)
            .cloned()
            .collect();
        self.reads.fetch_add(children.len(), Ordering::Relaxed);
        Ok(children)
    }

    fn changes_since(&self, seq_id: i64, limit: usize) -> Result<Vec<SyncOp>, SyncStoreError> {
        Ok(self
            .state
            .applied_ops
            .iter()
            .filter(|operation| operation.seq_id > seq_id)
            .take(limit)
            .cloned()
            .collect())
    }

    fn apply(&mut self, _changes: &SyncStoreChanges) -> Result<(), SyncStoreError> {
        Ok(())
    }
}

fn node(id: Uuid, parent_id: Option<Uuid>, name: String) -> TreeNode {
    TreeNode {
        id,
        name,
        name_undecryptable: false,
        name_encrypted: "sealed".into(),
        parent_id,
        is_folder: false,
        size_bytes: 1,
        mime_type: None,
        content_hash: None,
        version_number: 1,
        has_thumbnail: false,
        storage_pool_id: None,
        is_trashed: false,
        is_starred: false,
        updated_at: Utc::now(),
    }
}

#[derive(Default)]
struct Notifier(AtomicUsize);

impl DomainNotifier for Notifier {
    fn signal_working_set(&self) -> Result<(), DomainNotifierError> {
        self.0.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}

#[test]
fn file_provider_40k_item_lookup_reads_one_store_row() {
    let reads = Arc::new(AtomicUsize::new(0));
    let target = Uuid::from_u128(20_001);
    let listed_parent = Uuid::from_u128(90_000);
    let mut state = StoredSyncState::default();
    for index in 1..=40_000 {
        let id = Uuid::from_u128(index);
        state.tree.insert(
            id,
            node(id, Some(Uuid::from_u128(100_000 + index)), format!("file-{index}")),
        );
    }
    for index in 1..=3 {
        let id = Uuid::from_u128(50_000 + index);
        state
            .tree
            .insert(id, node(id, Some(listed_parent), format!("child-{index}")));
    }
    state.applied_ops.push_back(SyncOp {
        seq_id: 1,
        user_seq: Some(1),
        op_type: "file_update".into(),
        client_op_id: None,
        payload: serde_json::json!({"id": target.to_string()}),
        device_id: None,
        created_at: Utc::now(),
    });
    let engine = beebeeb_core::sync::SyncEngine::with_store_backed(
        "fp-device".into(),
        CountingStore {
            state,
            reads: Arc::clone(&reads),
        },
    )
    .unwrap();
    let provider = FileProviderService::new(engine, Arc::new(Notifier::default()));

    assert_eq!(provider.item(target).unwrap().unwrap().name, "file-20001");
    assert_eq!(reads.load(Ordering::Relaxed), 1);
    assert_eq!(provider.children(Some(listed_parent)).unwrap().len(), 3);
    assert_eq!(reads.load(Ordering::Relaxed), 4);
    let changes = provider.changes_since(0, 10).unwrap();
    assert_eq!(changes.changed.len(), 1);
    assert_eq!(changes.anchor, 1);
    assert_eq!(reads.load(Ordering::Relaxed), 5);
    provider.set_system_items([target]).unwrap();
    assert!(provider.item(target).unwrap().is_none());
    assert_eq!(reads.load(Ordering::Relaxed), 6);
}

#[tokio::test]
async fn file_provider_fetch_uses_download_service_and_finishes_ready() {
    use beebeeb_core::{
        chunk_stream::{ExpectedChunkFormat, VersionCommitment},
        encrypt::encrypt_name_with_version,
    };
    let root = tempdir().unwrap();
    let id = Uuid::from_u128(77);
    let cached = root.path().join("cached.bin");
    std::fs::write(&cached, b"cached").unwrap();
    let client = authenticated_client(ScriptedTransport::json(200, Vec::new()));
    let store = Arc::new(Mutex::new(beebeeb_store::Store::open_in_memory().unwrap()));
    let master = Arc::new(MasterKey::from_bytes([15; 32]));
    let commitment = VersionCommitment::new([0x15; 12], 1).unwrap();
    let name_encrypted = encrypt_name_with_version(
        &master,
        &id.to_string(),
        "cached.bin",
        None,
        ExpectedChunkFormat::V2,
        commitment,
    )
    .unwrap();
    let cache_key = format!("{}:{}", id, "15".repeat(12));
    let downloads = DownloadService::new_for_test(
        client,
        Arc::clone(&store),
        master,
        root.path().join("cache"),
        1024,
        beebeeb_types::limits::MemoryBudget::MOBILE_EXTENSION,
    )
    .unwrap();
    store
        .lock()
        .unwrap()
        .put_cache_entry(
            beebeeb_store::AssetClass::Cache,
            &beebeeb_store::CacheEntry {
                key: cache_key,
                file_id: Some(id.to_string()),
                version_id: Some(commitment.version_id.to_vec()),
                path: cached.to_string_lossy().into_owned(),
                size_bytes: 6,
                last_accessed: 0,
            },
            beebeeb_store::BoundedInsert::EvictOldest,
        )
        .unwrap();
    let notifier = Arc::new(Notifier::default());
    let provider = FileProviderService::new(
        beebeeb_core::sync::SyncEngine::new("fp-device".into()),
        notifier.clone(),
    );
    let file = DownloadFile {
        file_id: id.to_string(),
        name_encrypted,
        size_bytes: 6,
        chunk_size_bytes: 6,
        chunk_count: 1,
        object_version_id: "unused".into(),
    };

    let outcome = provider.fetch_contents(&downloads, &file, 1).await.unwrap();

    assert!(matches!(
        outcome,
        crate::file_provider::FileProviderOutcome::Ready(path) if path == cached
    ));
    assert_eq!(provider.work_state(id), Some(ItemWorkState::Succeeded));
    assert_eq!(notifier.0.load(Ordering::Relaxed), 1);
}

struct FileApiTransport;

impl crate::Transport for FileApiTransport {
    fn send<'a>(&'a self, request: beebeeb_api::Request, _limit: usize) -> crate::TransportFuture<'a> {
        Box::pin(async move {
            let answer = match (request.method(), request.path()) {
                (beebeeb_api::Method::Post, "/api/v1/files/folder") => {
                    let body: serde_json::Value = serde_json::from_slice(request.body()).unwrap();
                    serde_json::json!({
                        "id": body["folder_id"],
                        "parent_id": body["parent_id"],
                        "name_encrypted": body["name_encrypted"],
                        "is_folder": true
                    })
                }
                (beebeeb_api::Method::Patch, _) => {
                    let body: serde_json::Value = serde_json::from_slice(request.body()).unwrap();
                    let id = request.path().trim_start_matches("/api/v1/files/");
                    serde_json::json!({
                        "id": id,
                        "name_encrypted": body["name_encrypted"],
                        "is_folder": false,
                        "size_bytes": 1
                    })
                }
                (beebeeb_api::Method::Delete, _) => {
                    serde_json::json!({"message": "moved to trash", "trashed_count": 1})
                }
                // The Backups check reads the row: a top-level row outside
                // the Backups tree.
                (beebeeb_api::Method::Get, path) if path.starts_with("/api/v1/files/") => {
                    serde_json::json!({"id": path.trim_start_matches("/api/v1/files/"), "parent_id": null})
                }
                _ => panic!("unexpected file request"),
            };
            Ok(Answer::new(
                200,
                vec![Header::new("Content-Type", "application/json")],
                serde_json::to_vec(&answer).unwrap(),
            ))
        })
    }
}

#[tokio::test]
async fn file_provider_create_modify_delete_use_core_file_services_and_finish() {
    let key = [13; 32];
    let master = MasterKey::from_bytes(key);
    let item = NewItemId::owner(&master).unwrap();
    let encrypted =
        encrypt_name_for_new_item(&master, &item, "old.txt", Some("text/plain"), ExpectedChunkFormat::V2).unwrap();
    let mut state = StoredSyncState::default();
    state.tree.insert(
        item.as_str().parse().unwrap(),
        TreeNode {
            name_encrypted: encrypted,
            mime_type: Some("text/plain".into()),
            ..node(item.as_str().parse().unwrap(), None, "old.txt".into())
        },
    );
    let provider = FileProviderService::new(
        beebeeb_core::sync::SyncEngine::with_store_backed(
            "fp-device".into(),
            CountingStore {
                state,
                reads: Arc::new(AtomicUsize::new(0)),
            },
        )
        .unwrap(),
        Arc::new(Notifier::default()),
    );
    let client = Client::new(ClientConfig::for_tests(), Arc::new(FileApiTransport)).unwrap();
    client.set_authentication("token", "owner").unwrap();
    let session = Session::from_parts_for_test("https://api.example", "token", "owner", key, 1).unwrap();

    let folder = provider.create_folder(&client, &session, "Folder", None).await.unwrap();
    assert_eq!(folder.name, "Folder");
    let id = Uuid::parse_str(item.as_str()).unwrap();
    let modified = provider
        .modify(&client, &session, id, Some("new.txt"), None)
        .await
        .unwrap();
    assert_eq!(modified.name, "new.txt");
    provider.delete(&client, id).await.unwrap();
    assert_eq!(provider.work_state(id), Some(ItemWorkState::Succeeded));
}

struct SyncSubmitTransport;

impl crate::Transport for SyncSubmitTransport {
    fn send<'a>(&'a self, request: beebeeb_api::Request, _limit: usize) -> crate::TransportFuture<'a> {
        Box::pin(async move {
            if request.method() == beebeeb_api::Method::Get {
                // The Backups check reads the row first: outside the tree.
                let id = request.path().trim_start_matches("/api/v1/files/");
                return Ok(Answer::new(
                    200,
                    vec![Header::new("Content-Type", "application/json")],
                    serde_json::to_vec(&serde_json::json!({"id": id, "parent_id": null})).unwrap(),
                ));
            }
            assert_eq!(request.path(), "/api/v1/sync/ops");
            let body: serde_json::Value = serde_json::from_slice(request.body()).unwrap();
            let client_op_id = body["ops"][0]["client_op_id"].as_str().unwrap();
            Ok(Answer::new(
                200,
                vec![Header::new("Content-Type", "application/json")],
                serde_json::to_vec(&serde_json::json!({
                    "applied": [{"client_op_id": client_op_id, "seq_id": 1, "user_seq": 1}]
                }))
                .unwrap(),
            ))
        })
    }
}

#[tokio::test]
async fn file_provider_local_delete_submits_before_reporting_success() {
    let id = Uuid::new_v4();
    let mut engine = beebeeb_core::sync::SyncEngine::new("fp-device".into());
    engine
        .apply_complete_snapshot(
            beebeeb_core::sync::CompleteSnapshot::new(
                vec![node(id, None, "delete-me.txt".into())],
                beebeeb_core::sync::SyncPosition::default(),
            )
            .unwrap(),
        )
        .unwrap();
    let provider = FileProviderService::new(engine, Arc::new(Notifier::default()));
    let client = Client::new(ClientConfig::for_tests(), Arc::new(SyncSubmitTransport)).unwrap();
    client.set_authentication("token", "owner").unwrap();

    provider.delete_local(&client, id).await.unwrap();

    assert!(provider.item(id).unwrap().is_none());
    assert_eq!(provider.work_state(id), Some(ItemWorkState::Succeeded));
}

#[test]
fn file_provider_large_upload_returns_handoff_without_queueing() {
    let root = tempdir().unwrap();
    let source = root.path().join("source.bin");
    std::fs::write(&source, b"content").unwrap();
    let client = authenticated_client(ScriptedTransport::json(200, b"{}".to_vec()));
    let uploads = UploadService::new_for_test(
        client,
        Arc::new(Mutex::new(beebeeb_store::Store::open_in_memory().unwrap())),
        Arc::new(MasterKey::from_bytes([14; 32])),
        root.path().join("staging"),
    )
    .unwrap();
    let provider = FileProviderService::with_budget(
        beebeeb_core::sync::SyncEngine::new("fp-device".into()),
        Arc::new(Notifier::default()),
        beebeeb_types::limits::MemoryBudget::new(1, 1),
    );

    let outcome = provider
        .create_file(
            &uploads,
            crate::uploads::UploadRequest::new(source, "source.bin", None, None),
            1,
        )
        .unwrap();

    assert!(matches!(
        outcome,
        crate::file_provider::FileProviderOutcome::HandOff { .. }
    ));
    assert!(uploads.list().unwrap().is_empty());
}

#[tokio::test]
async fn file_provider_failure_is_terminal_and_signals_the_working_set() {
    let missing = Uuid::from_u128(99);
    let notifier = Arc::new(Notifier::default());
    let provider = FileProviderService::new(
        beebeeb_core::sync::SyncEngine::new("fp-device".into()),
        notifier.clone(),
    );

    let client = authenticated_client(ScriptedTransport::json(200, b"{}".to_vec()));
    assert!(provider.delete_local(&client, missing).await.is_err());
    assert_eq!(provider.work_state(missing), Some(ItemWorkState::Failed));
    assert!(provider.work_state(missing).unwrap().is_final());
    assert_eq!(notifier.0.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn stream_401_and_account_mismatch_emit_the_same_events_as_execute() {
    for (status, body, expected) in [
        (
            401,
            br#"{"error":"unauthorized"}"#.as_slice(),
            EngineEvent::SessionExpired,
        ),
        (
            409,
            br#"{"error":"account_mismatch"}"#.as_slice(),
            EngineEvent::AccountMismatch,
        ),
    ] {
        let transport = ScriptedTransport::json(status, body.to_vec());
        let client = authenticated_client(transport);
        let mut events = client.events().subscribe();
        let result = client
            .execute_stream(
                &beebeeb_api::routes::sync::stream("token"),
                StreamLimits {
                    max_event_bytes: 1024,
                    max_events: 1,
                    max_stream_bytes: 4096,
                },
            )
            .await;
        assert!(result.is_err());
        assert_eq!(events.try_recv().unwrap(), expected);
    }
}

#[tokio::test]
async fn regular_share_revoke_uses_the_authenticated_delete_route() {
    let transport = ScriptedTransport::json(200, br#"{"success":true}"#.to_vec());
    let client = authenticated_client(transport.clone());

    client.revoke_share_link("share-1").await.unwrap();

    let requests = transport.requests();
    assert_eq!(requests[0].method(), beebeeb_api::Method::Delete);
    assert_eq!(requests[0].path(), "/api/v1/shares/share-1");
    assert!(requests[0].header("Authorization").is_some());
}

#[tokio::test]
async fn duplicate_downloads_plaintext_then_queues_a_new_core_minted_id() {
    use beebeeb_core::{
        chunk_stream::{ExpectedChunkFormat, VersionCommitment},
        encrypt::encrypt_name_with_version,
    };
    let root = tempdir().unwrap();
    let source = root.path().join("downloaded.txt");
    std::fs::write(&source, b"copy me").unwrap();
    let client = authenticated_client(ScriptedTransport::json(200, b"{}".to_vec()));
    let store = Arc::new(Mutex::new(beebeeb_store::Store::open_in_memory().unwrap()));
    let master = Arc::new(MasterKey::from_bytes([8; 32]));
    let commitment = VersionCommitment::new([0x08; 12], 1).unwrap();
    let name_encrypted = encrypt_name_with_version(
        &master,
        "source-file-id",
        "source.txt",
        Some("text/plain"),
        ExpectedChunkFormat::V2,
        commitment,
    )
    .unwrap();
    let downloads = DownloadService::new_for_test(
        Arc::clone(&client),
        Arc::clone(&store),
        Arc::clone(&master),
        root.path().join("cache"),
        1024,
        beebeeb_types::limits::MemoryBudget::NATIVE,
    )
    .unwrap();
    store
        .lock()
        .unwrap()
        .put_cache_entry(
            beebeeb_store::AssetClass::Cache,
            &beebeeb_store::CacheEntry {
                key: format!("source-file-id:{}", "08".repeat(12)),
                file_id: Some("source-file-id".into()),
                version_id: Some(commitment.version_id.to_vec()),
                path: source.to_string_lossy().into_owned(),
                size_bytes: 7,
                last_accessed: 0,
            },
            beebeeb_store::BoundedInsert::EvictOldest,
        )
        .unwrap();
    let uploads = UploadService::new_for_test(client, store, master, root.path().join("staging")).unwrap();
    let description = DownloadFile {
        file_id: "source-file-id".into(),
        name_encrypted,
        size_bytes: 7,
        chunk_size_bytes: 7,
        chunk_count: 1,
        object_version_id: "unused".into(),
    };

    let duplicated = duplicate_file(
        &downloads,
        &uploads,
        &description,
        "copy.txt",
        Some("text/plain".into()),
        None,
        1,
    )
    .await
    .unwrap();

    assert_ne!(duplicated.new_file_id, "source-file-id");
    assert_eq!(uploads.list().unwrap()[0].name, "copy.txt");
}
