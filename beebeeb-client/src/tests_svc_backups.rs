//! The Backups tree in the native services (backup spec Amendments 6 to 8):
//! core's app rule in the app, core's drive rule in the Files app, and an
//! ordinary folder left as it was.

use std::sync::{Arc, Mutex};

use beebeeb_api::routes::files::FileEntry;
use beebeeb_core::{
    backup::{MSG_DELETE, MSG_MANAGED_IN_APP, MSG_READ_ONLY},
    kdf::MasterKey,
    sync::{CompleteSnapshot, SyncEngine, SyncPosition, TreeNode},
};
use serde_json::{Value, json};
use tempfile::tempdir;
use uuid::Uuid;

use crate::{
    Client, ClientConfig, Session,
    backup::{
        Asset, AssetKind, AssetSnapshot, AssetSource, AssetSourceError, BackupConfiguration, BackupError, BackupFolder,
        BackupService,
    },
    file_provider::{DomainNotifier, DomainNotifierError, FileProviderError, FileProviderService},
    files::FileServiceError,
    test_support::ScriptedTransport,
    uploads::{NetworkKind, UploadRequest, UploadService, UploadServiceError},
};

const ROOT: &str = "10000000-0000-4000-8000-000000000000";
const DEVICE: &str = "20000000-0000-4000-8000-000000000000";
const CATEGORY: &str = "30000000-0000-4000-8000-000000000000";
const PHOTO: &str = "40000000-0000-4000-8000-000000000000";
const ORDINARY: &str = "50000000-0000-4000-8000-000000000000";

fn row(id: &str, parent: Option<&str>, is_folder: bool) -> Vec<u8> {
    let mut row = json!({"id": id, "parent_id": parent, "name_encrypted": "sealed", "is_folder": is_folder});
    if id == ROOT {
        row["system_role"] = Value::String("backups_root".into());
    }
    serde_json::to_vec(&row).unwrap()
}

/// The server rows a position check reads, from `id` up to the root.
fn ancestors(id: &str) -> Vec<Vec<u8>> {
    let chain: &[(&str, Option<&str>, bool)] = &[
        (PHOTO, Some(CATEGORY), false),
        (CATEGORY, Some(DEVICE), true),
        (DEVICE, Some(ROOT), true),
        (ROOT, None, true),
    ];
    let start = chain.iter().position(|(row_id, _, _)| *row_id == id).unwrap();
    chain[start..]
        .iter()
        .map(|(row_id, parent, is_folder)| row(row_id, *parent, *is_folder))
        .collect()
}

/// A transport that answers `replies` in order, then fails.
fn scripted(replies: Vec<Vec<u8>>) -> ScriptedTransport {
    let mut replies = replies.into_iter();
    let transport = ScriptedTransport::json(200, replies.next().unwrap());
    for reply in replies {
        transport.push_json(200, reply);
    }
    transport
}

fn entry(id: &str, parent: Option<&str>, is_folder: bool) -> FileEntry {
    serde_json::from_slice(&row(id, parent, is_folder)).unwrap()
}

fn client(transport: &ScriptedTransport) -> Client {
    let client = Client::new(ClientConfig::for_tests(), Arc::new(transport.clone())).unwrap();
    client.set_authentication("token", "owner").unwrap();
    client
}

fn paths(transport: &ScriptedTransport) -> Vec<String> {
    transport
        .requests()
        .iter()
        .map(|request| format!("{:?} {}", request.method(), request.path()))
        .collect()
}

#[tokio::test]
async fn app_rename_inside_a_backup_is_refused_with_cores_words_and_nothing_is_written() {
    let transport = scripted(ancestors(PHOTO));
    let client = client(&transport);
    let session = Session::from_parts_for_test("https://api.example", "token", "owner", [9; 32], 1).unwrap();

    let error = client
        .rename_entry(&session, &entry(PHOTO, Some(CATEGORY), false), "edited.jpg")
        .await
        .unwrap_err();

    assert!(matches!(&error, FileServiceError::Protected(refused) if refused.message == MSG_READ_ONLY));
    let sent = paths(&transport);
    assert_eq!(sent.len(), 4, "{sent:?}");
    assert!(sent.iter().all(|line| line.starts_with("Get ")), "{sent:?}");
}

#[tokio::test]
async fn app_trash_of_the_root_is_refused_by_its_own_role_before_any_parent_is_read() {
    let transport = scripted(ancestors(ROOT));
    let client = client(&transport);

    let error = client.trash_entry(&entry(ROOT, None, true)).await.unwrap_err();

    assert!(matches!(&error, FileServiceError::Protected(refused) if refused.message == MSG_DELETE));
    assert_eq!(transport.request_count(), 1);
}

#[tokio::test]
async fn app_new_folder_in_a_device_folder_is_refused() {
    let transport = scripted(ancestors(DEVICE));
    let client = client(&transport);
    let session = Session::from_parts_for_test("https://api.example", "token", "owner", [9; 32], 1).unwrap();

    let error = client
        .create_folder(&session, "Mine", Some(DEVICE.into()))
        .await
        .unwrap_err();

    assert!(matches!(&error, FileServiceError::Protected(refused) if refused.message == MSG_READ_ONLY));
    assert!(paths(&transport).iter().all(|line| line.starts_with("Get ")));
}

#[tokio::test]
async fn app_may_delete_a_device_backup() {
    let mut replies = ancestors(DEVICE);
    replies.push(br#"{"message":"trashed","trashed_count":1}"#.to_vec());
    let transport = scripted(replies);
    let client = client(&transport);

    client.trash_entry(&entry(DEVICE, Some(ROOT), true)).await.unwrap();

    assert_eq!(
        paths(&transport).last().unwrap(),
        &format!("Delete /api/v1/files/{DEVICE}")
    );
}

/// A restore from the Trash undoes a trash the app rule allowed (rule 11): a
/// photo trashed from a backup goes back where it was, with no Backups check
/// (review r4, decided in `restore_entry`'s comment). Asking the create rule
/// of its category folder would refuse it.
#[tokio::test]
async fn a_photo_trashed_from_a_backup_is_restored_where_it_was() {
    // The rows a Backups check would read come first: the restore must not.
    let mut replies = ancestors(CATEGORY);
    replies.push(br#"{"restored":true}"#.to_vec());
    let transport = scripted(replies);
    let client = client(&transport);
    let mut trashed = entry(PHOTO, Some(CATEGORY), false);
    trashed.is_trashed = true;

    let result = client.restore_entry(&trashed).await;

    assert!(result.is_ok(), "{result:?}");
    assert_eq!(paths(&transport), vec![format!("Post /api/v1/files/{PHOTO}/restore")]);
}

/// Outside the tree a rename, which the app rule refuses everywhere under the
/// root, goes ahead as before.
#[tokio::test]
async fn an_ordinary_file_is_renamed_as_before() {
    let master = MasterKey::from_bytes([9; 32]);
    let item = beebeeb_core::item_id::NewItemId::owner(&master).unwrap();
    let sealed = beebeeb_core::encrypt::encrypt_name_for_new_item(
        &master,
        &item,
        "notes.txt",
        None,
        beebeeb_core::chunk_stream::ExpectedChunkFormat::V2,
    )
    .unwrap();
    let ordinary = json!({"id": item.as_str(), "parent_id": null, "name_encrypted": sealed, "is_folder": false});
    let transport = scripted(vec![
        serde_json::to_vec(&ordinary).unwrap(),
        serde_json::to_vec(&ordinary).unwrap(),
    ]);
    let client = client(&transport);
    let session = Session::from_parts_for_test("https://api.example", "token", "owner", [9; 32], 1).unwrap();
    let entry: FileEntry = serde_json::from_value(ordinary).unwrap();

    client.rename_entry(&session, &entry, "renamed.txt").await.unwrap();

    assert_eq!(
        paths(&transport),
        vec![
            format!("Get /api/v1/files/{}", item.as_str()),
            format!("Patch /api/v1/files/{}", item.as_str()),
        ]
    );
}

#[tokio::test]
async fn an_ordinary_folder_is_trashed_as_before() {
    let transport = scripted(vec![
        row(ORDINARY, None, true),
        br#"{"message":"trashed","trashed_count":1}"#.to_vec(),
    ]);
    let client = client(&transport);

    client.trash_entry(&entry(ORDINARY, None, true)).await.unwrap();

    assert_eq!(
        paths(&transport),
        vec![
            format!("Get /api/v1/files/{ORDINARY}"),
            format!("Delete /api/v1/files/{ORDINARY}"),
        ]
    );
}

#[derive(Default)]
struct Notifier;

impl DomainNotifier for Notifier {
    fn signal_working_set(&self) -> Result<(), DomainNotifierError> {
        Ok(())
    }
}

#[tokio::test]
async fn files_app_cannot_delete_a_device_backup_that_the_app_may_delete() {
    let id = Uuid::parse_str(DEVICE).unwrap();
    let mut engine = SyncEngine::new("fp-device".into());
    let node = TreeNode {
        id,
        name: "GLegion".into(),
        name_undecryptable: false,
        name_encrypted: "sealed".into(),
        parent_id: Some(Uuid::parse_str(ROOT).unwrap()),
        is_folder: true,
        size_bytes: 0,
        mime_type: None,
        content_hash: None,
        version_number: 1,
        has_thumbnail: false,
        storage_pool_id: None,
        is_trashed: false,
        is_starred: false,
        updated_at: chrono::Utc::now(),
    };
    engine
        .apply_complete_snapshot(CompleteSnapshot::new(vec![node], SyncPosition::default()).unwrap())
        .unwrap();
    let provider = FileProviderService::new(engine, Arc::new(Notifier));
    let transport = scripted(ancestors(DEVICE));
    let client = client(&transport);

    let error = provider.delete(&client, id).await.unwrap_err();

    assert!(matches!(
        &error,
        FileProviderError::File(FileServiceError::Protected(refused)) if refused.message == MSG_MANAGED_IN_APP
    ));
    assert!(paths(&transport).iter().all(|line| line.starts_with("Get ")));
}

#[tokio::test]
async fn an_upload_into_a_backup_is_refused_before_init_and_fails_for_good() {
    let root = tempdir().unwrap();
    let source = root.path().join("photo.jpg");
    std::fs::write(&source, b"pixels").unwrap();
    let transport = scripted(ancestors(CATEGORY));
    let client = Arc::new(client(&transport));
    let uploads = UploadService::new_for_test(
        client,
        Arc::new(Mutex::new(beebeeb_store::Store::open_in_memory().unwrap())),
        Arc::new(MasterKey::from_bytes([9; 32])),
        root.path().join("staging"),
    )
    .unwrap();
    uploads
        .enqueue(UploadRequest::new(source, "photo.jpg", None, Some(CATEGORY.into())), 1)
        .unwrap();

    let error = uploads.next_transfers(4, NetworkKind::WiFi, 2).await.unwrap_err();

    assert!(matches!(&error, UploadServiceError::Protected(refused) if refused.message == MSG_READ_ONLY));
    assert!(paths(&transport).iter().all(|line| line.starts_with("Get ")));
    assert!(uploads.next_transfers(4, NetworkKind::WiFi, 3).await.unwrap().is_none());
}

struct NoAssets;

impl AssetSource for NoAssets {
    fn snapshot(&self, _: AssetKind, _: Option<&str>, _: usize) -> Result<AssetSnapshot, AssetSourceError> {
        Err(AssetSourceError::Unavailable)
    }

    fn export(&self, _: AssetKind, _: &Asset) -> Result<std::path::PathBuf, AssetSourceError> {
        Err(AssetSourceError::Unavailable)
    }
}

#[tokio::test]
async fn the_backup_pass_queues_nothing_into_a_folder_outside_backups() {
    let root = tempdir().unwrap();
    let transport = scripted(vec![row(ORDINARY, None, true)]);
    let client = Arc::new(client(&transport));
    let uploads = Arc::new(
        UploadService::new_for_test(
            Arc::clone(&client),
            Arc::new(Mutex::new(beebeeb_store::Store::open_in_memory().unwrap())),
            Arc::new(MasterKey::from_bytes([9; 32])),
            root.path().join("staging"),
        )
        .unwrap(),
    );
    let configuration = BackupConfiguration::new(BackupFolder { id: ORDINARY.into() }, false, "device").unwrap();
    let backup = BackupService::new(client, Arc::clone(&uploads), Arc::new(NoAssets), configuration).unwrap();

    let error = backup
        .next_batch(AssetKind::Photo, NetworkKind::WiFi, 1)
        .await
        .unwrap_err();

    assert!(matches!(error, BackupError::NotInBackups), "{error:?}");
    assert_eq!(transport.request_count(), 1);
    assert!(uploads.list().unwrap().is_empty());
}
