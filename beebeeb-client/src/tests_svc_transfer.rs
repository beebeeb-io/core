use std::sync::{Arc, Mutex};

use beebeeb_core::kdf::MasterKey;
use beebeeb_store::{Store, TransferState};
use tempfile::tempdir;

use crate::uploads::{NetworkKind, UploadRequest, UploadService, UploadServiceError};
use crate::{Client, ClientConfig, ClientError, test_support::ScriptedTransport};

#[test]
fn upload_completion_carries_both_sealed_commitment_fields() {
    let request = beebeeb_api::routes::uploads::CompleteRequest {
        name_encrypted: Some("sealed-name".into()),
        version_metadata_encrypted: Some("sealed-version".into()),
    };
    let json = serde_json::to_value(request).unwrap();
    assert_eq!(json["name_encrypted"], "sealed-name");
    assert_eq!(json["version_metadata_encrypted"], "sealed-version");
    assert!(json.get("mime_type_encrypted").is_none());
}

#[tokio::test]
async fn replacement_upload_initializes_against_the_current_protected_version() {
    let root = tempdir().unwrap();
    let source = root.path().join("replacement.bin");
    std::fs::write(&source, b"replacement").unwrap();
    let file_id = "8426867a-a17a-4a56-a05d-ddff0afa15f7";
    let master_key = MasterKey::from_bytes([7; 32]);
    #[allow(deprecated)]
    let current_metadata = beebeeb_core::encrypt::encrypt_name_with_version(
        &master_key,
        file_id,
        "current.bin",
        Some("application/octet-stream"),
        beebeeb_core::chunk_stream::ExpectedChunkFormat::V2,
        beebeeb_core::chunk_stream::VersionCommitment::new([9; 12], 4).unwrap(),
    )
    .unwrap();
    let transport = Arc::new(ScriptedTransport::json(
        200,
        format!(r#"{{"upload_session_id":"session","file_id":"{file_id}","chunk_size_bytes":4,"chunk_count":3}}"#)
            .into_bytes(),
    ));
    transport.push_json(
        200,
        br#"{"token":"scoped-token","upload_session_id":"session","expires_at":"2099-01-01T00:00:00Z"}"#.to_vec(),
    );
    let client = Arc::new(Client::new(ClientConfig::for_tests(), transport.clone()).unwrap());
    let service = UploadService::new_for_test(
        client,
        Arc::new(Mutex::new(Store::open_in_memory().unwrap())),
        Arc::new(master_key),
        root.path().join("staging"),
    )
    .unwrap();
    let request = UploadRequest::replacement(
        &source,
        "replacement.bin",
        Some("application/octet-stream".into()),
        file_id,
        4,
        current_metadata.clone(),
    );
    service.enqueue(request, 1).unwrap();

    let (_, transfers) = service
        .next_transfers(8, NetworkKind::WiFi, 2)
        .await
        .unwrap()
        .expect("the scripted upload should produce platform transfers");
    assert_eq!(transfers.len(), 3);
    assert!(transfers.iter().all(|transfer| {
        transfer
            .headers
            .iter()
            .any(|(name, value)| name == "x-beebeeb-capabilities" && value == "file-write-v2, version-metadata-v1")
    }));

    let request = transport
        .requests()
        .into_iter()
        .find(|request| request.path() == "/api/v1/uploads/init")
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(request.body()).unwrap();
    assert_eq!(body["file_id"], file_id);
    assert_eq!(body["base_version_number"], 4);
    assert_eq!(body["file_name"], current_metadata);
    assert_eq!(body["version_metadata_encrypted"], current_metadata);
}

#[tokio::test]
async fn upgrade_required_completion_is_typed_and_terminal_on_first_answer() {
    let root = tempdir().unwrap();
    let source = root.path().join("source.bin");
    std::fs::write(&source, b"one chunk").unwrap();
    let file_id = "8426867a-a17a-4a56-a05d-ddff0afa15f7";
    let master_key = MasterKey::from_bytes([7; 32]);
    #[allow(deprecated)]
    let current_metadata = beebeeb_core::encrypt::encrypt_name_with_version(
        &master_key,
        file_id,
        "source.bin",
        None,
        beebeeb_core::chunk_stream::ExpectedChunkFormat::V2,
        beebeeb_core::chunk_stream::VersionCommitment::new([9; 12], 1).unwrap(),
    )
    .unwrap();
    let transport = Arc::new(ScriptedTransport::json(
        200,
        format!(r#"{{"upload_session_id":"session","file_id":"{file_id}","chunk_size_bytes":32,"chunk_count":1}}"#)
            .into_bytes(),
    ));
    transport.push_json(
        200,
        br#"{"token":"scoped-token","upload_session_id":"session","expires_at":"2099-01-01T00:00:00Z"}"#.to_vec(),
    );
    transport.push_json(
        426,
        br#"{"error":"client_upgrade_required","secret":"must-not-escape"}"#.to_vec(),
    );
    let client = Arc::new(Client::new(ClientConfig::for_tests(), transport).unwrap());
    let store = Arc::new(Mutex::new(Store::open_in_memory().unwrap()));
    let service = UploadService::new_for_test(
        client,
        Arc::clone(&store),
        Arc::new(master_key),
        root.path().join("staging"),
    )
    .unwrap();
    let id = service
        .enqueue(
            UploadRequest::replacement(source, "source.bin", None, file_id, 1, current_metadata),
            1,
        )
        .unwrap();
    let (_, transfers) = service.next_transfers(1, NetworkKind::WiFi, 2).await.unwrap().unwrap();
    let request = &transfers[0];

    let error = service
        .transfer_finished(id, &request.ticket, 200, None, None, b"", 3)
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        UploadServiceError::Client(ClientError::Api(beebeeb_api::ApiError::Server(ref server)))
            if server.status == 426
    ));
    assert_eq!(
        store.lock().unwrap().transfer(id).unwrap().unwrap().state,
        TransferState::Failed
    );
    assert!(!format!("{error:?}").contains("must-not-escape"));
}

#[test]
fn upload_queue_pause_resume_and_cancel_are_durable() {
    let root = tempdir().unwrap();
    let source = root.path().join("source.bin");
    std::fs::write(&source, b"payload").unwrap();
    let transport = Arc::new(ScriptedTransport::json(200, b"{}".to_vec()));
    let client = Arc::new(Client::new(ClientConfig::for_tests(), transport).unwrap());
    let store = Arc::new(Mutex::new(Store::open_in_memory().unwrap()));
    let service = UploadService::new_for_test(
        client,
        Arc::clone(&store),
        Arc::new(MasterKey::from_bytes([7; 32])),
        root.path().join("staging"),
    )
    .unwrap();
    let id = service
        .enqueue(UploadRequest::new(source, "hello.txt", None, None), 10)
        .unwrap();

    assert!(service.pause(id, 11).unwrap());
    assert_eq!(
        store.lock().unwrap().transfer(id).unwrap().unwrap().state,
        TransferState::Paused
    );
    assert!(service.resume(id, 12).unwrap());
    assert_eq!(
        store.lock().unwrap().transfer(id).unwrap().unwrap().state,
        TransferState::Queued
    );
    let plan = service.cancel(id, 13).unwrap();
    assert!(plan.cancel_tickets.is_empty());
    assert_eq!(
        store.lock().unwrap().transfer(id).unwrap().unwrap().state,
        TransferState::Cancelled
    );
}

#[test]
fn cache_limit_evicts_the_oldest_decrypted_file() {
    use beebeeb_store::{AssetClass, BoundedInsert, CacheEntry};

    let mut store = Store::open_in_memory().unwrap();
    store.set_asset_limit(AssetClass::Cache, 8).unwrap();
    store
        .put_cache_entry(
            AssetClass::Cache,
            &CacheEntry {
                key: "old".into(),
                file_id: None,
                version_id: None,
                path: "old.bin".into(),
                size_bytes: 5,
                last_accessed: 1,
            },
            BoundedInsert::EvictOldest,
        )
        .unwrap();
    let result = store
        .put_cache_entry(
            AssetClass::Cache,
            &CacheEntry {
                key: "new".into(),
                file_id: None,
                version_id: None,
                path: "new.bin".into(),
                size_bytes: 5,
                last_accessed: 2,
            },
            BoundedInsert::EvictOldest,
        )
        .unwrap();
    assert_eq!(result.paths_to_remove, ["old.bin"]);
}

#[test]
fn signed_chunk_location_is_redacted_from_debug_and_errors() {
    let secret = "https://storage.example/object?X-Amz-Signature=secret";
    let location = crate::ChunkLocation::new(secret).unwrap();
    assert!(!format!("{location:?}").contains("secret"));
    assert!(
        !crate::ChunkTransportError::Unavailable
            .to_string()
            .contains("storage.example")
    );
}

#[test]
fn rollback_observation_emits_engine_warning() {
    use crate::downloads::DownloadService;
    use beebeeb_store::VersionObservation;
    use beebeeb_types::limits::MemoryBudget;

    let root = tempdir().unwrap();
    let transport = Arc::new(ScriptedTransport::json(200, Vec::new()));
    let client = Arc::new(Client::new(ClientConfig::for_tests(), transport).unwrap());
    let mut events = client.events().subscribe();
    let service = DownloadService::new_for_test(
        client,
        Arc::new(Mutex::new(Store::open_in_memory().unwrap())),
        Arc::new(MasterKey::from_bytes([3; 32])),
        root.path(),
        1024,
        MemoryBudget::NATIVE,
    )
    .unwrap();
    assert_eq!(
        service.observe_file_version("file", 7).unwrap(),
        VersionObservation::NewHighest
    );
    assert_eq!(
        service.observe_file_version("file", 6).unwrap(),
        VersionObservation::Older { highest: 7 }
    );
    assert!(matches!(
        events.try_recv().unwrap(),
        crate::EngineEvent::VersionRollback {
            observed: 6,
            highest: 7,
            ..
        }
    ));
}

#[tokio::test]
async fn thumbnail_worker_uploads_only_core_sealed_bytes() {
    use crate::thumbnails::{ImageCodec, ImageCodecError, ThumbnailJob, ThumbnailService};
    use crate::uploads::NetworkKind;
    #[allow(deprecated)]
    use beebeeb_core::encrypt::encrypt_name_with_chunk_format;
    use beebeeb_core::{
        chunk_stream::ExpectedChunkFormat,
        thumbnail::{Platform, ThumbnailFormat, ThumbnailVariant},
    };

    struct Codec;
    impl ImageCodec for Codec {
        fn encode(
            &self,
            _source_path: &std::path::Path,
            _max_dimension: u32,
            _quality: f32,
            _format: ThumbnailFormat,
        ) -> Result<Vec<u8>, ImageCodecError> {
            Ok(b"plaintext thumbnail".to_vec())
        }
    }

    const FILE_ID: &str = "11111111-2222-4333-8444-555555555555";
    let root = tempdir().unwrap();
    let source = root.path().join("photo.raw");
    std::fs::write(&source, b"pixels").unwrap();
    let master = Arc::new(MasterKey::from_bytes([4; 32]));
    #[allow(deprecated)]
    let metadata = encrypt_name_with_chunk_format(
        &master,
        FILE_ID,
        "photo.jpg",
        Some("image/jpeg"),
        ExpectedChunkFormat::V2,
    )
    .unwrap();
    let transport = Arc::new(ScriptedTransport::json(200, Vec::new()));
    let client = Arc::new(Client::new(ClientConfig::for_tests(), transport.clone()).unwrap());
    client.set_authentication("token", "owner").unwrap();
    let service = ThumbnailService::new_for_test(
        client,
        Arc::new(Mutex::new(Store::open_in_memory().unwrap())),
        master,
        Arc::new(Codec),
        root.path().join("thumbs"),
        1024,
        Platform::Ios,
    )
    .unwrap();
    service
        .enqueue_generation(
            ThumbnailJob {
                file_id: FILE_ID.into(),
                name_encrypted: metadata,
                source_path: source,
                variant: ThumbnailVariant::Small,
                created_at_ms: 1,
                wifi_only: false,
            },
            1,
        )
        .unwrap();
    service.run_next(NetworkKind::WiFi, 2).await.unwrap().unwrap();
    let request = transport.requests().pop().unwrap();
    assert_ne!(request.body(), b"plaintext thumbnail");
    assert!(request.path().contains("/thumbnail/small"));
    assert_eq!(
        request.header("x-beebeeb-capabilities"),
        Some("file-write-v2, version-metadata-v1")
    );
}

#[tokio::test]
async fn thumbnail_fallback_queues_the_requested_variant_for_later() {
    use crate::thumbnails::{ImageCodec, ImageCodecError, ThumbnailService};
    use beebeeb_core::thumbnail::{Platform, ThumbnailFormat, ThumbnailVariant};
    use beebeeb_store::{AssetClass, BoundedInsert, CacheEntry};

    struct Codec;
    impl ImageCodec for Codec {
        fn encode(
            &self,
            _source_path: &std::path::Path,
            _max_dimension: u32,
            _quality: f32,
            _format: ThumbnailFormat,
        ) -> Result<Vec<u8>, ImageCodecError> {
            Err(ImageCodecError::Decode)
        }
    }

    const FILE_ID: &str = "11111111-2222-4333-8444-555555555555";
    let root = tempdir().unwrap();
    let cached = root.path().join(format!("{FILE_ID}.small.thumb"));
    std::fs::write(&cached, b"small").unwrap();
    let store = Arc::new(Mutex::new(Store::open_in_memory().unwrap()));
    let client = Arc::new(
        Client::new(
            ClientConfig::for_tests(),
            Arc::new(ScriptedTransport::json(404, Vec::new())),
        )
        .unwrap(),
    );
    let service = ThumbnailService::new_for_test(
        client,
        Arc::clone(&store),
        Arc::new(MasterKey::from_bytes([0x43; 32])),
        Arc::new(Codec),
        root.path(),
        1024,
        Platform::Ios,
    )
    .unwrap();
    store
        .lock()
        .unwrap()
        .put_cache_entry(
            AssetClass::Thumbnail,
            &CacheEntry {
                key: format!("{FILE_ID}:small"),
                file_id: None,
                version_id: None,
                path: cached.to_string_lossy().into_owned(),
                size_bytes: 5,
                last_accessed: 1,
            },
            BoundedInsert::EvictOldest,
        )
        .unwrap();

    assert_eq!(
        service
            .get(FILE_ID, "sealed-metadata", ThumbnailVariant::Large, 2)
            .await
            .unwrap(),
        cached
    );
    let queued = store.lock().unwrap().transfers(Some("thumbnail-fetch-v1")).unwrap();
    assert_eq!(queued.len(), 1);
    assert!(
        std::str::from_utf8(&queued[0].payload)
            .unwrap()
            .contains("\"variant\":\"large\"")
    );
}

#[tokio::test]
async fn hostile_upload_chunk_list_is_refused_before_staging() {
    use crate::uploads::{NetworkKind, UploadServiceError};

    let root = tempdir().unwrap();
    let source = root.path().join("source.bin");
    std::fs::write(&source, b"payload").unwrap();
    let transport = Arc::new(ScriptedTransport::json(200, b"{}".to_vec()));
    let client = Arc::new(Client::new(ClientConfig::for_tests(), transport.clone()).unwrap());
    client.set_authentication("token", "owner").unwrap();
    let store = Arc::new(Mutex::new(Store::open_in_memory().unwrap()));
    let service = UploadService::new_for_test(
        client,
        store,
        Arc::new(MasterKey::from_bytes([8; 32])),
        root.path().join("staging"),
    )
    .unwrap();
    let id = service
        .enqueue(UploadRequest::new(source, "a.bin", None, None), 1)
        .unwrap();
    let file_id = service
        .list()
        .unwrap()
        .into_iter()
        .find(|item| item.id == id)
        .unwrap()
        .file_id;
    transport.respond_next_json(
        200,
        serde_json::to_vec(&serde_json::json!({
            "upload_session_id": "session",
            "file_id": file_id,
            "chunk_size_bytes": 4,
            "chunk_count": 999999999999u64
        }))
        .unwrap(),
    );
    let error = service.next_transfers(1, NetworkKind::WiFi, 2).await.unwrap_err();
    assert!(matches!(error, UploadServiceError::HostileChunkPlan));
}

#[tokio::test]
async fn changed_source_after_restart_executes_server_abandon() {
    use crate::uploads::{NetworkKind, UploadServiceError};

    let root = tempdir().unwrap();
    let source = root.path().join("source.bin");
    std::fs::write(&source, b"payload").unwrap();
    let transport = Arc::new(ScriptedTransport::json(
        200,
        serde_json::to_vec(&serde_json::json!({
            "token": "scoped", "upload_session_id": "session",
            "expires_at": "2099-01-01T00:00:00Z"
        }))
        .unwrap(),
    ));
    let client = Arc::new(Client::new(ClientConfig::for_tests(), transport.clone()).unwrap());
    client.set_authentication("token", "owner").unwrap();
    let store = Arc::new(Mutex::new(Store::open_in_memory().unwrap()));
    let master = Arc::new(MasterKey::from_bytes([6; 32]));
    let service = UploadService::new_for_test(
        Arc::clone(&client),
        Arc::clone(&store),
        Arc::clone(&master),
        root.path().join("staging"),
    )
    .unwrap();
    let id = service
        .enqueue(UploadRequest::new(source.clone(), "a.bin", None, None), 1)
        .unwrap();
    let file_id = service
        .list()
        .unwrap()
        .into_iter()
        .find(|item| item.id == id)
        .unwrap()
        .file_id;
    transport.respond_next_json(
        200,
        serde_json::to_vec(&serde_json::json!({
            "upload_session_id": "session", "file_id": file_id,
            "chunk_size_bytes": 32, "chunk_count": 1
        }))
        .unwrap(),
    );
    transport.push_json(
        200,
        serde_json::to_vec(&serde_json::json!({
            "id": file_id,
            "status": "reverted",
            "previous_version_number": 1,
            "deleted": false
        }))
        .unwrap(),
    );
    let (_, transfers) = service.next_transfers(1, NetworkKind::WiFi, 2).await.unwrap().unwrap();
    assert_eq!(transfers.len(), 1);
    std::fs::write(&source, b"changed and larger").unwrap();

    let restored = UploadService::new_for_test(client, store, master, root.path().join("staging")).unwrap();
    let error = restored
        .next_transfers(1, NetworkKind::WiFi, 700_000)
        .await
        .unwrap_err();
    assert!(matches!(error, UploadServiceError::SourceChangedRestarted));
    assert!(
        transport
            .requests()
            .iter()
            .any(|request| request.path().ends_with("/upload/abandon"))
    );
}

#[tokio::test]
async fn token_failure_persists_staging_and_counts_an_attempt() {
    use crate::uploads::NetworkKind;

    let root = tempdir().unwrap();
    let source = root.path().join("source.bin");
    std::fs::write(&source, b"payload").unwrap();
    let transport = Arc::new(ScriptedTransport::json(200, Vec::new()));
    let client = Arc::new(Client::new(ClientConfig::for_tests(), transport.clone()).unwrap());
    client.set_authentication("token", "owner").unwrap();
    let store = Arc::new(Mutex::new(Store::open_in_memory().unwrap()));
    let service = UploadService::new_for_test(
        client,
        Arc::clone(&store),
        Arc::new(MasterKey::from_bytes([0x61; 32])),
        root.path().join("staging"),
    )
    .unwrap();
    let id = service
        .enqueue(UploadRequest::new(source, "a.bin", None, None), 1)
        .unwrap();
    let file_id = service.list().unwrap()[0].file_id.clone();
    transport.respond_next_json(
        200,
        serde_json::to_vec(&serde_json::json!({
            "upload_session_id": "session", "file_id": file_id,
            "chunk_size_bytes": 32, "chunk_count": 1
        }))
        .unwrap(),
    );

    service.next_transfers(1, NetworkKind::WiFi, 2).await.unwrap_err();
    let transfer = store.lock().unwrap().transfer(id).unwrap().unwrap();
    assert_eq!(transfer.attempts, 1);
    assert_eq!(transfer.state, TransferState::Queued);

    transport.push_json(
        200,
        serde_json::to_vec(&serde_json::json!({
            "token": "scoped", "upload_session_id": "session",
            "expires_at": "2099-01-01T00:00:00Z"
        }))
        .unwrap(),
    );
    let (_, requests) = service.next_transfers(1, NetworkKind::WiFi, 3).await.unwrap().unwrap();
    assert_eq!(requests.len(), 1);
}

#[tokio::test]
async fn failed_abandon_keeps_staged_files_and_resumes_the_persisted_restart() {
    use crate::uploads::{NetworkKind, UploadServiceError};

    let root = tempdir().unwrap();
    let source = root.path().join("source.bin");
    std::fs::write(&source, b"payload").unwrap();
    let transport = Arc::new(ScriptedTransport::json(
        200,
        serde_json::to_vec(&serde_json::json!({
            "token": "scoped", "upload_session_id": "session",
            "expires_at": "2099-01-01T00:00:00Z"
        }))
        .unwrap(),
    ));
    let client = Arc::new(Client::new(ClientConfig::for_tests(), transport.clone()).unwrap());
    client.set_authentication("token", "owner").unwrap();
    let store = Arc::new(Mutex::new(Store::open_in_memory().unwrap()));
    let master = Arc::new(MasterKey::from_bytes([0x62; 32]));
    let service = UploadService::new_for_test(client, Arc::clone(&store), master, root.path().join("staging")).unwrap();
    let _id = service
        .enqueue(UploadRequest::new(source.clone(), "a.bin", None, None), 1)
        .unwrap();
    let file_id = service.list().unwrap()[0].file_id.clone();
    transport.respond_next_json(
        200,
        serde_json::to_vec(&serde_json::json!({
            "upload_session_id": "session", "file_id": file_id,
            "chunk_size_bytes": 32, "chunk_count": 1
        }))
        .unwrap(),
    );
    service.next_transfers(1, NetworkKind::WiFi, 2).await.unwrap();
    let staged = root.path().join("staging/upload-1/chunk-00000000.bbcipher");
    assert!(staged.is_file());
    std::fs::write(&source, b"changed and larger").unwrap();

    assert!(matches!(
        service.next_transfers(1, NetworkKind::WiFi, 700_000).await,
        Err(UploadServiceError::Client(_))
    ));
    assert!(staged.is_file(), "local ciphertext stays until abandon succeeds");
    transport.push_json(
        200,
        serde_json::to_vec(&serde_json::json!({
            "id": file_id, "status": "reverted",
            "previous_version_number": 1, "deleted": false
        }))
        .unwrap(),
    );
    assert!(matches!(
        service.next_transfers(1, NetworkKind::WiFi, 700_001).await,
        Err(UploadServiceError::SourceChangedRestarted)
    ));
    assert!(!staged.exists());
}

#[tokio::test]
async fn invalid_saved_upload_state_counts_toward_the_terminal_retry_limit() {
    let root = tempdir().unwrap();
    let source = root.path().join("source.bin");
    std::fs::write(&source, b"payload").unwrap();
    let transport = Arc::new(ScriptedTransport::json(500, Vec::new()));
    let client = Arc::new(Client::new(ClientConfig::for_tests(), transport).unwrap());
    let store = Arc::new(Mutex::new(Store::open_in_memory().unwrap()));
    let service = UploadService::new_for_test(
        client,
        Arc::clone(&store),
        Arc::new(MasterKey::from_bytes([7; 32])),
        root.path().join("staging"),
    )
    .unwrap();
    let id = service
        .enqueue(UploadRequest::new(source, "broken.bin", None, None), 0)
        .unwrap();
    store
        .lock()
        .unwrap()
        .update_transfer_payload(id, b"not-json", 0)
        .unwrap();

    for attempt in 0..5 {
        assert!(
            service
                .next_transfers(1, crate::uploads::NetworkKind::WiFi, i64::from(attempt) * 600_001)
                .await
                .is_err()
        );
    }

    let transfer = store.lock().unwrap().transfer(id).unwrap().unwrap();
    assert_eq!(transfer.attempts, 5);
    assert_eq!(transfer.state, TransferState::Failed);
}

#[tokio::test]
async fn completion_after_every_chunk_commits_does_not_reopen_the_source_file() {
    let root = tempdir().unwrap();
    let source = root.path().join("source.bin");
    std::fs::write(&source, b"payload").unwrap();
    let transport = Arc::new(ScriptedTransport::json(
        200,
        br#"{"upload_session_id":"session","token":"scoped","expires_at":"2026-01-01T00:00:00Z"}"#.to_vec(),
    ));
    let client = Arc::new(Client::new(ClientConfig::for_tests(), transport.clone()).unwrap());
    let store = Arc::new(Mutex::new(Store::open_in_memory().unwrap()));
    let service = UploadService::new_for_test(
        client,
        Arc::clone(&store),
        Arc::new(MasterKey::from_bytes([7; 32])),
        root.path().join("staging"),
    )
    .unwrap();
    let id = service
        .enqueue(UploadRequest::new(&source, "complete.bin", None, None), 0)
        .unwrap();
    let file_id = service.list().unwrap()[0].file_id.clone();
    transport.respond_next_json(
        200,
        serde_json::to_vec(&serde_json::json!({
            "upload_session_id": "session",
            "file_id": file_id,
            "chunk_size_bytes": 64,
            "chunk_count": 1
        }))
        .unwrap(),
    );
    transport.push_json(200, br#"{}"#.to_vec());
    let (_, requests) = service
        .next_transfers(1, crate::uploads::NetworkKind::WiFi, 1)
        .await
        .unwrap()
        .unwrap();
    let request = requests.into_iter().next().unwrap();
    std::fs::remove_file(source).unwrap();

    service
        .transfer_finished(id, &request.ticket, 200, None, None, &[], 2)
        .await
        .unwrap();

    assert_eq!(
        store.lock().unwrap().transfer(id).unwrap().unwrap().state,
        TransferState::Succeeded
    );
}

#[tokio::test]
async fn truncated_download_is_never_published() {
    use crate::downloads::{DownloadFile, DownloadService, DownloadServiceError};
    use beebeeb_core::{
        chunk_stream::{ChunkEncryptor, ExpectedChunkFormat},
        encrypt::encrypt_name_with_version,
    };
    use beebeeb_types::limits::MemoryBudget;

    const FILE_ID: &str = "11111111-2222-4333-8444-555555555555";
    let master = Arc::new(MasterKey::from_bytes([9; 32]));
    #[allow(deprecated)]
    let mut encryptor = ChunkEncryptor::for_push_with_chunk_size(&master, FILE_ID, 8, 4).unwrap();
    let first = encryptor.push_chunk(b"abcd").unwrap();
    let version = encryptor.version_commitment_after(None).unwrap();
    let _second = encryptor.push_chunk(b"efgh").unwrap();
    encryptor.finish().unwrap();
    #[allow(deprecated)]
    let name = encrypt_name_with_version(&master, FILE_ID, "a.bin", None, ExpectedChunkFormat::V2, version).unwrap();

    let transport = Arc::new(ScriptedTransport::json(200, first.data));
    transport.push_json(200, vec![0; 10]);
    let client = Arc::new(Client::new(ClientConfig::for_tests(), transport).unwrap());
    client.set_authentication("token", "owner").unwrap();
    let root = tempdir().unwrap();
    let service = DownloadService::new_for_test(
        client,
        Arc::new(Mutex::new(Store::open_in_memory().unwrap())),
        master,
        root.path(),
        1024,
        MemoryBudget::NATIVE,
    )
    .unwrap();
    let file = DownloadFile {
        file_id: FILE_ID.into(),
        name_encrypted: name,
        size_bytes: 8,
        chunk_size_bytes: 4,
        chunk_count: 2,
        object_version_id: "v".into(),
    };
    assert!(matches!(
        service.open(&file, 1).await,
        Err(DownloadServiceError::Truncated)
    ));
    assert!(!root.path().join(format!("{FILE_ID}.bbcache")).exists());
}

#[tokio::test]
async fn v2_metadata_without_a_version_commitment_stays_readable_until_a_counter_was_seen() {
    use crate::downloads::{DownloadFile, DownloadResult, DownloadService, DownloadServiceError};
    use beebeeb_core::chunk_stream::{ChunkEncryptor, ExpectedChunkFormat};
    #[allow(deprecated)]
    use beebeeb_core::encrypt::encrypt_name_with_chunk_format;
    use beebeeb_types::limits::MemoryBudget;

    const FILE_ID: &str = "11111111-2222-4333-8444-555555555555";
    let master = Arc::new(MasterKey::from_bytes([0x72; 32]));
    #[allow(deprecated)]
    let name =
        encrypt_name_with_chunk_format(&master, FILE_ID, "uncommitted.bin", None, ExpectedChunkFormat::V2).unwrap();
    #[allow(deprecated)]
    let mut encryptor = ChunkEncryptor::for_push_with_chunk_size(&master, FILE_ID, 4, 4).unwrap();
    let frame = encryptor.push_chunk(b"data").unwrap().data;
    encryptor.finish().unwrap();
    let transport = Arc::new(ScriptedTransport::json(200, frame));
    let client = Arc::new(Client::new(ClientConfig::for_tests(), transport.clone()).unwrap());
    let root = tempdir().unwrap();
    let store = Arc::new(Mutex::new(Store::open_in_memory().unwrap()));
    let service = DownloadService::new_for_test(
        client,
        Arc::clone(&store),
        master,
        root.path(),
        1024,
        MemoryBudget::NATIVE,
    )
    .unwrap();
    let file = DownloadFile {
        file_id: FILE_ID.into(),
        name_encrypted: name,
        size_bytes: 4,
        chunk_size_bytes: 4,
        chunk_count: 1,
        object_version_id: "v".into(),
    };
    assert!(matches!(service.open(&file, 1).await, Ok(DownloadResult::Ready(_))));

    store.lock().unwrap().observe_file_version(FILE_ID, 5).unwrap();
    assert!(matches!(
        service.open(&file, 2).await,
        Err(DownloadServiceError::VersionRollback)
    ));
    assert_eq!(
        transport.request_count(),
        1,
        "stripped metadata must be refused before fetching content"
    );
}

#[tokio::test]
async fn authenticated_counter_is_recorded_only_after_content_authenticates() {
    use crate::downloads::{DownloadFile, DownloadResult, DownloadService, DownloadServiceError};
    use beebeeb_core::{
        chunk_stream::{ChunkEncryptor, ExpectedChunkFormat, VersionCommitment},
        encrypt::encrypt_name_with_version,
    };
    use beebeeb_types::limits::MemoryBudget;

    const FILE_ID: &str = "11111111-2222-4333-8444-555555555555";
    let master = Arc::new(MasterKey::from_bytes([0x31; 32]));
    #[allow(deprecated)]
    let mut encryptor = ChunkEncryptor::for_push_with_chunk_size(&master, FILE_ID, 4, 4).unwrap();
    let valid_frame = encryptor.push_chunk(b"good").unwrap().data;
    let version_id = encryptor.version_id().unwrap();
    encryptor.finish().unwrap();
    let huge = VersionCommitment::new(version_id, 9_000).unwrap();
    let current = VersionCommitment::new(version_id, 5).unwrap();
    let huge_name = encrypt_name_with_version(&master, FILE_ID, "a.bin", None, ExpectedChunkFormat::V2, huge).unwrap();
    let current_name =
        encrypt_name_with_version(&master, FILE_ID, "a.bin", None, ExpectedChunkFormat::V2, current).unwrap();
    let transport = Arc::new(ScriptedTransport::json(200, vec![0; valid_frame.len()]));
    transport.push_json(200, valid_frame);
    let client = Arc::new(Client::new(ClientConfig::for_tests(), transport).unwrap());
    client.set_authentication("token", "owner").unwrap();
    let root = tempdir().unwrap();
    let store = Arc::new(Mutex::new(Store::open_in_memory().unwrap()));
    let service = DownloadService::new_for_test(
        client,
        Arc::clone(&store),
        master,
        root.path(),
        1024,
        MemoryBudget::NATIVE,
    )
    .unwrap();
    let description = |name_encrypted| DownloadFile {
        file_id: FILE_ID.into(),
        name_encrypted,
        size_bytes: 4,
        chunk_size_bytes: 4,
        chunk_count: 1,
        object_version_id: "version".into(),
    };
    assert!(matches!(
        service.open(&description(huge_name), 1).await,
        Err(DownloadServiceError::Truncated)
    ));
    assert_eq!(store.lock().unwrap().highest_file_version(FILE_ID).unwrap(), None);
    assert!(matches!(
        service.open(&description(current_name), 2).await,
        Ok(DownloadResult::Ready(_))
    ));
    assert_eq!(store.lock().unwrap().highest_file_version(FILE_ID).unwrap(), Some(5));
}

#[tokio::test]
async fn replaying_authenticated_version_four_after_five_is_refused() {
    use crate::downloads::{DownloadFile, DownloadService, DownloadServiceError};
    use beebeeb_core::{
        chunk_stream::{ChunkEncryptor, ExpectedChunkFormat, VersionCommitment},
        encrypt::encrypt_name_with_version,
    };
    use beebeeb_types::limits::MemoryBudget;

    const FILE_ID: &str = "11111111-2222-4333-8444-555555555555";
    let master = Arc::new(MasterKey::from_bytes([0x32; 32]));
    let make = |plain: &'static [u8], counter| {
        #[allow(deprecated)]
        let mut encryptor = ChunkEncryptor::for_push_with_chunk_size(&master, FILE_ID, 4, 4).unwrap();
        let frame = encryptor.push_chunk(plain).unwrap().data;
        let commitment = VersionCommitment::new(encryptor.version_id().unwrap(), counter).unwrap();
        encryptor.finish().unwrap();
        let name =
            encrypt_name_with_version(&master, FILE_ID, "a.bin", None, ExpectedChunkFormat::V2, commitment).unwrap();
        (frame, name)
    };
    let (frame5, name5) = make(b"five", 5);
    let (frame4, name4) = make(b"four", 4);
    let transport = Arc::new(ScriptedTransport::json(200, frame5));
    transport.push_json(200, frame4);
    let client = Arc::new(Client::new(ClientConfig::for_tests(), transport).unwrap());
    client.set_authentication("token", "owner").unwrap();
    let root = tempdir().unwrap();
    let service = DownloadService::new_for_test(
        client,
        Arc::new(Mutex::new(Store::open_in_memory().unwrap())),
        master,
        root.path(),
        1024,
        MemoryBudget::NATIVE,
    )
    .unwrap();
    let description = |name_encrypted, object_version_id: &str| DownloadFile {
        file_id: FILE_ID.into(),
        name_encrypted,
        size_bytes: 4,
        chunk_size_bytes: 4,
        chunk_count: 1,
        object_version_id: object_version_id.into(),
    };
    service.open(&description(name5, "v5"), 1).await.unwrap();
    assert!(matches!(
        service.open(&description(name4, "v4"), 2).await,
        Err(DownloadServiceError::VersionRollback)
    ));
}

#[tokio::test]
async fn video_range_refuses_zero_stride_and_fetches_only_selected_v2_chunks() {
    use crate::downloads::{DownloadFile, DownloadService, DownloadServiceError};
    use beebeeb_core::{
        chunk_stream::{ChunkEncryptor, ExpectedChunkFormat},
        encrypt::encrypt_name_with_version,
    };
    use beebeeb_types::limits::MemoryBudget;

    const FILE_ID: &str = "11111111-2222-4333-8444-555555555555";
    let master = Arc::new(MasterKey::from_bytes([0x71; 32]));
    #[allow(deprecated)]
    let mut encryptor = ChunkEncryptor::for_push_with_chunk_size(&master, FILE_ID, 8, 4).unwrap();
    let _first = encryptor.push_chunk(b"abcd").unwrap().data;
    let second = encryptor.push_chunk(b"efgh").unwrap().data;
    let commitment = encryptor.version_commitment_after(None).unwrap();
    encryptor.finish().unwrap();
    let metadata =
        encrypt_name_with_version(&master, FILE_ID, "video.bin", None, ExpectedChunkFormat::V2, commitment).unwrap();
    let transport = Arc::new(ScriptedTransport::json(200, second));
    let client = Arc::new(Client::new(ClientConfig::for_tests(), transport.clone()).unwrap());
    client.set_authentication("token", "owner").unwrap();
    let root = tempdir().unwrap();
    let service = DownloadService::new_for_test(
        client,
        Arc::new(Mutex::new(Store::open_in_memory().unwrap())),
        master,
        root.path(),
        1024,
        MemoryBudget::NATIVE,
    )
    .unwrap();
    let mut file = DownloadFile {
        file_id: FILE_ID.into(),
        name_encrypted: metadata,
        size_bytes: 8,
        chunk_size_bytes: 4,
        chunk_count: 2,
        object_version_id: "v".into(),
    };
    assert_eq!(service.video_range(&file, 4..8).await.unwrap(), b"efgh");
    let requests = transport.requests();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].path().contains("/chunks/1?"));

    file.chunk_size_bytes = 0;
    assert!(matches!(
        service.video_range(&file, 0..1).await,
        Err(DownloadServiceError::InvalidDescription)
    ));
}

#[tokio::test]
async fn public_share_download_uses_the_counted_chunk_manifest() {
    use crate::downloads::{DownloadResult, DownloadService};
    use beebeeb_core::{
        chunk_stream::{ChunkEncryptor, ExpectedChunkFormat},
        encrypt::{decrypt_file_metadata, encrypt_name_with_version},
        kdf::derive_file_key,
        path_safety::TrustedDirectory,
    };
    use beebeeb_types::limits::MemoryBudget;

    const FILE_ID: &str = "11111111-2222-4333-8444-555555555555";
    let root = tempdir().unwrap();
    let master = Arc::new(MasterKey::from_bytes([19; 32]));
    #[allow(deprecated)]
    let mut encryptor = ChunkEncryptor::for_push_with_chunk_size(&master, FILE_ID, 8, 4).unwrap();
    let first = encryptor.push_chunk(b"abcd").unwrap().data;
    let second = encryptor.push_chunk(b"efgh").unwrap().data;
    let version = encryptor.version_commitment_after(None).unwrap();
    encryptor.finish().unwrap();
    #[allow(deprecated)]
    let sealed_name =
        encrypt_name_with_version(&master, FILE_ID, "shared.bin", None, ExpectedChunkFormat::V2, version).unwrap();
    let metadata = decrypt_file_metadata(&master, FILE_ID, &sealed_name).unwrap();
    let key = derive_file_key(&master, FILE_ID.as_bytes());

    let transport = Arc::new(ScriptedTransport::json(
        200,
        serde_json::to_vec(&serde_json::json!({
            "chunk_count": 2,
            "size_bytes": 8,
            "chunks": [
                {"index": 0, "size_bytes": first.len()},
                {"index": 1, "size_bytes": second.len()}
            ],
            "download_token": "counted-ticket",
            "download_token_expires_at": "2099-01-01T00:00:00Z"
        }))
        .unwrap(),
    ));
    transport.push_json(200, first);
    transport.push_json(200, second);
    let client = Arc::new(Client::new(ClientConfig::for_tests(), transport.clone()).unwrap());
    let service = DownloadService::new_for_test(
        client,
        Arc::new(Mutex::new(Store::open_in_memory().unwrap())),
        master,
        root.path().join("cache"),
        1024,
        MemoryBudget::NATIVE,
    )
    .unwrap();
    let output_root = root.path().join("output");
    std::fs::create_dir(&output_root).unwrap();
    let directory = TrustedDirectory::open(&output_root).unwrap();
    assert_eq!(
        service
            .share_view_download(
                "share-secret",
                None,
                FILE_ID,
                &key,
                &metadata,
                2,
                8,
                4,
                &directory,
                "shared.bin",
            )
            .await
            .unwrap(),
        DownloadResult::Saved
    );
    assert_eq!(std::fs::read(output_root.join("shared.bin")).unwrap(), b"abcdefgh");
    let requests = transport.requests();
    assert_eq!(requests[0].path(), "/api/v1/shares/share-secret/chunks");
    assert_eq!(requests[1].header("X-Share-Download-Token"), Some("counted-ticket"));
    assert_eq!(requests[2].header("X-Share-Download-Token"), Some("counted-ticket"));
}
