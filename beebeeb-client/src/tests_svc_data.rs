use std::sync::Mutex;
use std::{sync::Arc, time::Duration};

use beebeeb_core::{
    chunk_stream::ExpectedChunkFormat, encrypt::encrypt_name_for_new_item, item_id::NewItemId, kdf::MasterKey,
};
use serde_json::{Value, json};

use crate::{
    Client, ClientConfig, Session,
    contacts::{ContactTrust, observe_contact_key},
    files::{FileRecord, FileServiceError},
    search::SearchService,
    settings::{DeviceSettings, load_local_settings, save_local_settings},
    shares::DEFAULT_LINK_EXPIRY_HOURS,
    sync::SyncLoopError,
    test_support::ScriptedTransport,
    transport::{StreamLimits, decode_sse},
};

struct NeverEndingStream;

impl crate::Transport for NeverEndingStream {
    fn send<'a>(&'a self, _request: beebeeb_api::Request, _limit: usize) -> crate::TransportFuture<'a> {
        Box::pin(async {
            Ok(beebeeb_api::Answer::new(
                200,
                vec![],
                br#"{"token":"stream-token"}"#.to_vec(),
            ))
        })
    }

    fn stream<'a>(&'a self, _request: beebeeb_api::Request, _limits: StreamLimits) -> crate::TransportStreamFuture<'a> {
        Box::pin(std::future::pending())
    }
}

fn session(bytes: [u8; 32]) -> Session {
    Session::from_parts_for_test("https://api.example", "token", "user-1", bytes, 1).unwrap()
}

fn authenticated_client(transport: ScriptedTransport) -> Client {
    let client = Client::new(ClientConfig::for_tests(), Arc::new(transport)).unwrap();
    client.set_authentication("token", "user-1").unwrap();
    client
}

#[tokio::test]
async fn file_listing_opens_names_and_never_returns_ciphertext_as_the_name() {
    let key = [7; 32];
    let master = MasterKey::from_bytes(key);
    let item = NewItemId::owner(&master).unwrap();
    let encrypted = encrypt_name_for_new_item(
        &master,
        &item,
        "Quarterly report.pdf",
        Some("application/pdf"),
        ExpectedChunkFormat::V2,
    )
    .unwrap();
    let transport = ScriptedTransport::json(
        200,
        serde_json::to_vec(&json!({"files": [{
            "id": item.as_str(), "name_encrypted": encrypted, "size_bytes": 42
        }]}))
        .unwrap(),
    );
    let client = authenticated_client(transport);

    let records = client
        .list_file_records_page(&session(key), None, false, None, 100)
        .await
        .unwrap()
        .files;

    assert_eq!(records.len(), 1);
    assert_eq!(records[0].name, "Quarterly report.pdf");
    assert_eq!(records[0].mime_type.as_deref(), Some("application/pdf"));
}

#[tokio::test]
async fn managed_folder_refusal_happens_before_network_io() {
    let transport = ScriptedTransport::json(200, b"null".to_vec());
    let client = authenticated_client(transport.clone());
    let entry = beebeeb_api::routes::files::FileEntry {
        id: "11111111-1111-4111-8111-111111111111".into(),
        parent_id: None,
        name_encrypted: Some("sealed".into()),
        is_folder: true,
        is_trashed: false,
        size_bytes: 0,
        extra: [("managed_by".into(), Value::String("mail_backup".into()))]
            .into_iter()
            .collect(),
    };

    let error = client.trash_entry(&entry).await.unwrap_err();

    assert!(matches!(error, FileServiceError::ManagedByService { .. }));
    assert_eq!(transport.request_count(), 0);
}

#[tokio::test]
async fn version_restore_reseals_the_current_name_for_the_old_content_above_every_seen_counter() {
    use beebeeb_core::{
        chunk_stream::{ExpectedChunkFormat, VersionCommitment},
        encrypt::{decrypt_file_metadata, encrypt_name_with_version},
    };

    const FILE_ID: &str = "11111111-2222-4333-8444-555555555555";
    let master = MasterKey::from_bytes([0x63; 32]);
    let current = encrypt_name_with_version(
        &master,
        FILE_ID,
        "renamed.txt",
        Some("text/plain"),
        ExpectedChunkFormat::V2,
        VersionCommitment::new([0x22; 12], 6).unwrap(),
    )
    .unwrap();
    let old = encrypt_name_with_version(
        &master,
        FILE_ID,
        "original.txt",
        Some("text/plain"),
        ExpectedChunkFormat::V2,
        VersionCommitment::new([0x11; 12], 2).unwrap(),
    )
    .unwrap();
    let newer = encrypt_name_with_version(
        &master,
        FILE_ID,
        "renamed.txt",
        Some("text/plain"),
        ExpectedChunkFormat::V2,
        VersionCommitment::new([0x33; 12], 7).unwrap(),
    )
    .unwrap();
    let transport = ScriptedTransport::json(
        200,
        serde_json::to_vec(&json!({
            "id": FILE_ID,
            "name_encrypted": current,
            "size_bytes": 4
        }))
        .unwrap(),
    );
    transport.push_json(
        200,
        serde_json::to_vec(&json!({
            "file_id": FILE_ID,
            "current_version": 3,
            "versions": [
                {"id":"old-version","version_number":1,"size_bytes":4,"chunk_count":1,"created_at":"2026-01-01T00:00:00Z","source":"object_version","version_metadata_encrypted":old},
                {"id":"new-version","version_number":2,"size_bytes":4,"chunk_count":1,"created_at":"2026-01-02T00:00:00Z","source":"object_version","version_metadata_encrypted":newer}
            ]
        }))
        .unwrap(),
    );
    transport.push_json(200, br#"{"version_number":4}"#.to_vec());
    let client = authenticated_client(transport.clone());
    let session = session([0x63; 32]);
    let store = Mutex::new(beebeeb_store::Store::open_in_memory().unwrap());
    store.lock().unwrap().observe_file_version(FILE_ID, 5).unwrap();

    let restored = client
        .restore_version(&session, &store, FILE_ID, "old-version")
        .await
        .unwrap();

    assert_eq!(restored.counter, Some(8));
    let requests = transport.requests();
    assert_eq!(
        requests[2].path(),
        "/api/v1/files/11111111-2222-4333-8444-555555555555/versions/old-version/restore"
    );
    let body: Value = serde_json::from_slice(requests[2].body()).unwrap();
    assert_eq!(body["name_encrypted"], body["version_metadata_encrypted"]);
    let sealed = body["name_encrypted"].as_str().unwrap();
    let metadata = decrypt_file_metadata(&master, FILE_ID, sealed).unwrap();
    assert_eq!(metadata.name, "renamed.txt");
    assert_eq!(
        metadata.version.unwrap(),
        VersionCommitment::new([0x11; 12], 8).unwrap()
    );
    assert_eq!(store.lock().unwrap().highest_file_version(FILE_ID).unwrap(), Some(8));
}

#[tokio::test]
async fn share_links_default_to_thirty_days() {
    let transport = ScriptedTransport::json(
        200,
        br#"{"id":"share-1","token":"secret","expires_at":"2026-12-03T00:00:00Z"}"#.to_vec(),
    );
    let client = authenticated_client(transport.clone());

    client
        .create_share_link("file-1", "wrapped-key", None, None)
        .await
        .unwrap();

    let requests = transport.requests();
    let body: Value = serde_json::from_slice(requests[0].body()).unwrap();
    assert_eq!(body["expires_in_hours"], DEFAULT_LINK_EXPIRY_HOURS);
}

#[test]
fn contacts_are_first_use_pinned_and_key_changes_require_acceptance() {
    let mut store = beebeeb_store::Store::open_in_memory().unwrap();
    assert_eq!(
        observe_contact_key(&mut store, "alice", &[1; 32], 1).unwrap(),
        ContactTrust::FirstUse
    );
    assert_eq!(
        observe_contact_key(&mut store, "alice", &[1; 32], 2).unwrap(),
        ContactTrust::Trusted
    );
    assert_eq!(
        observe_contact_key(&mut store, "alice", &[2; 32], 3).unwrap(),
        ContactTrust::KeyChanged
    );
    assert_eq!(store.contact_key("alice").unwrap().unwrap().public_key, [1; 32]);
}

#[tokio::test]
async fn search_is_local_binding_ready_and_incrementally_observable() {
    let search = SearchService::new(8);
    let mut changes = search.subscribe();
    search.upsert(FileRecord::for_test("one", "Résumé 2026.pdf"));

    let update = changes.recv().await.unwrap();
    let results = search.query("résumé");

    assert_eq!(update.revision, 1);
    assert_eq!(results[0].id, "one");
    assert_eq!(results[0].name, "Résumé 2026.pdf");
}

#[test]
fn settings_are_encrypted_in_the_store_and_round_trip() {
    let key = [9; 32];
    let session = session(key);
    let mut store = beebeeb_store::Store::open_in_memory().unwrap();
    let settings = DeviceSettings {
        cache_bytes: 1024,
        thumbnail_bytes: 2048,
        wifi_only: true,
        upload_staging_bytes: 4096,
        version_history_enabled: false,
        version_history_days: 30,
    };

    save_local_settings(
        &mut store,
        &session,
        "11111111-1111-4111-8111-111111111111",
        "mobile",
        &settings,
    )
    .unwrap();
    let stored = store
        .device_setting("11111111-1111-4111-8111-111111111111", "mobile", "data-settings-v1")
        .unwrap()
        .unwrap();

    assert!(!stored.windows(b"wifi_only".len()).any(|window| window == b"wifi_only"));
    assert_eq!(
        load_local_settings(&store, &session, "11111111-1111-4111-8111-111111111111", "mobile").unwrap(),
        Some(settings)
    );
}

#[test]
fn settings_envelopes_cannot_be_swapped_between_products() {
    let session = session([9; 32]);
    let mut store = beebeeb_store::Store::open_in_memory().unwrap();
    let settings = DeviceSettings {
        cache_bytes: 1024,
        thumbnail_bytes: 2048,
        wifi_only: true,
        upload_staging_bytes: 512 * 1024 * 1024,
        version_history_enabled: false,
        version_history_days: 30,
    };
    let device = "11111111-1111-4111-8111-111111111111";
    let envelope = save_local_settings(&mut store, &session, device, "drive", &settings).unwrap();
    store
        .put_device_setting(device, "mail", "data-settings-v1", envelope.as_bytes())
        .unwrap();

    assert!(load_local_settings(&store, &session, device, "mail").is_err());
}

#[test]
fn oversized_sse_event_is_rejected_before_json_parsing() {
    let limits = StreamLimits {
        max_event_bytes: 8,
        max_events: 4,
        max_stream_bytes: 64,
    };
    let error = decode_sse(b"data: 123456789\n\n", limits).unwrap_err();
    assert!(matches!(error, crate::TransportError::EventTooLarge));
}

#[tokio::test]
async fn catch_up_sorts_reordered_ops_and_ignores_repeats() {
    let key = [5; 32];
    let master = MasterKey::from_bytes(key);
    let first = NewItemId::owner(&master).unwrap();
    let second = NewItemId::owner(&master).unwrap();
    let third = NewItemId::owner(&master).unwrap();
    let first_name = encrypt_name_for_new_item(&master, &first, "one.txt", None, ExpectedChunkFormat::V2).unwrap();
    let second_name = encrypt_name_for_new_item(&master, &second, "two.txt", None, ExpectedChunkFormat::V2).unwrap();
    let third_name = encrypt_name_for_new_item(&master, &third, "three.txt", None, ExpectedChunkFormat::V2).unwrap();
    let operation = |seq: i64, user_seq: i64, id: &str, name: &str| {
        json!({
            "seq_id": seq,
            "user_seq": user_seq,
            "op_type": "file_create",
            "payload": {"id": id, "name_encrypted": name}
        })
    };
    let transport = ScriptedTransport::json(
        200,
        serde_json::to_vec(&json!({"ops": [
            operation(20, 2, second.as_str(), &second_name),
            operation(10, 1, first.as_str(), &first_name),
            operation(10, 1, first.as_str(), &first_name)
        ], "next_since": 20}))
        .unwrap(),
    );
    transport.push_json(
        200,
        serde_json::to_vec(&json!({
            "ops": [operation(20, 2, second.as_str(), &second_name)],
            "next_since": 30
        }))
        .unwrap(),
    );
    transport.push_json(
        200,
        serde_json::to_vec(&json!({
            "ops": [operation(40, 3, third.as_str(), &third_name)]
        }))
        .unwrap(),
    );
    let client = authenticated_client(transport);
    let mut engine = beebeeb_core::sync::SyncEngine::new("device-1".into());

    client.catch_up_sync(&session(key), &mut engine, 100).await.unwrap();

    assert_eq!(engine.position(), beebeeb_core::sync::SyncPosition::new(40, 3));
    assert_eq!(engine.tree_size(), 3);
    assert_eq!(
        engine.get_node(first.as_str().parse().unwrap()).unwrap().name,
        "one.txt"
    );
}

#[tokio::test]
async fn undecryptable_name_is_marked_without_blocking_later_sync_ops() {
    let key = [22; 32];
    let master = MasterKey::from_bytes(key);
    let other_master = MasterKey::from_bytes([23; 32]);
    let bad = NewItemId::owner(&other_master).unwrap();
    let bad_name = encrypt_name_for_new_item(&other_master, &bad, "bad.txt", None, ExpectedChunkFormat::V2).unwrap();
    let good = NewItemId::owner(&master).unwrap();
    let good_name = encrypt_name_for_new_item(&master, &good, "good.txt", None, ExpectedChunkFormat::V2).unwrap();
    let operation = |seq: i64, user_seq: i64, id: &str, name: &str| {
        json!({
            "seq_id": seq,
            "user_seq": user_seq,
            "op_type": "file_create",
            "payload": {"id": id, "name_encrypted": name}
        })
    };
    let transport = ScriptedTransport::json(
        200,
        serde_json::to_vec(&json!({"ops": [
            operation(1, 1, bad.as_str(), &bad_name),
            operation(2, 2, good.as_str(), &good_name)
        ]}))
        .unwrap(),
    );
    let client = authenticated_client(transport);
    let mut engine = beebeeb_core::sync::SyncEngine::new("device-1".into());

    client.catch_up_sync(&session(key), &mut engine, 100).await.unwrap();

    assert!(
        engine
            .get_node(bad.as_str().parse().unwrap())
            .unwrap()
            .name_undecryptable
    );
    let good_id = good.as_str().parse().unwrap();
    assert!(!engine.get_node(good_id).unwrap().name_undecryptable);
    assert_eq!(engine.get_node(good_id).unwrap().name, "good.txt");
    assert_eq!(engine.position(), beebeeb_core::sync::SyncPosition::new(2, 2));
}

#[tokio::test]
async fn sign_out_during_catch_up_discards_the_answer() {
    let transport = ScriptedTransport::paused_json(200, br#"{"ops":[]}"#.to_vec());
    let client = Arc::new(authenticated_client(transport.clone()));
    let running = client.clone();
    let task = tokio::spawn(async move {
        let mut engine = beebeeb_core::sync::SyncEngine::new("device-1".into());
        running.catch_up_sync(&session([3; 32]), &mut engine, 100).await
    });
    transport.wait_until_sent().await;
    client.clear_authentication().unwrap();
    transport.release();

    let result = task.await.unwrap();
    assert!(matches!(
        result,
        Err(SyncLoopError::Client(crate::ClientError::StaleAccount))
    ));
}

#[tokio::test]
async fn stream_that_never_ends_hits_the_client_deadline() {
    let client = Client::new(ClientConfig::for_tests(), Arc::new(NeverEndingStream)).unwrap();
    client.set_authentication("token", "user-1").unwrap();
    let mut engine = beebeeb_core::sync::SyncEngine::new("device-1".into());

    let result = client
        .foreground_sync_with_timeout(&session([4; 32]), &mut engine, 100, Duration::from_millis(5))
        .await;

    assert!(matches!(result, Err(SyncLoopError::StreamTimeout)));
}
