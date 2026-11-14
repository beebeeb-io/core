//! The service coordinator: the purge on an account change, and device sign-out.

use super::*;

struct Codec;

impl ImageCodec for Codec {
    fn encode(
        &self,
        _source_path: &std::path::Path,
        _max_dimension: u32,
        _quality: f32,
        _format: beebeeb_core::thumbnail::ThumbnailFormat,
    ) -> Result<Vec<u8>, ImageCodecError> {
        Err(ImageCodecError::Encode)
    }
}

#[derive(Default)]
struct FailingCanceller(AtomicUsize);

impl PlatformTransferCanceller for FailingCanceller {
    fn cancel(&self, _tickets: &[String]) -> Result<(), PlatformCancellationError> {
        self.0.fetch_add(1, Ordering::Relaxed);
        Err(PlatformCancellationError::Failed)
    }
}

struct SuccessfulCanceller;

impl PlatformTransferCanceller for SuccessfulCanceller {
    fn cancel(&self, _tickets: &[String]) -> Result<(), PlatformCancellationError> {
        Ok(())
    }
}

#[derive(Default)]
struct Purger(AtomicUsize);

impl AccountDataPurger for Purger {
    fn purge_account_data(&self) -> Result<(), AccountDataPurgeError> {
        self.0.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}

#[derive(Default)]
struct Secrets(Mutex<HashMap<String, Vec<u8>>>);

impl crate::SecretStore for Secrets {
    fn set(&self, name: &str, value: &[u8]) -> Result<(), crate::SecretError> {
        self.0.lock().unwrap().insert(name.into(), value.into());
        Ok(())
    }

    fn get(&self, name: &str) -> Result<Option<zeroize::Zeroizing<Vec<u8>>>, crate::SecretError> {
        Ok(self.0.lock().unwrap().get(name).cloned().map(zeroize::Zeroizing::new))
    }

    fn delete(&self, name: &str) -> Result<(), crate::SecretError> {
        self.0.lock().unwrap().remove(name);
        Ok(())
    }
}

#[tokio::test]
async fn coordinator_purges_everything_even_when_platform_cancellation_fails() {
    let root = tempdir().unwrap();
    let source_path = root.path().join("queued.txt");
    std::fs::write(&source_path, b"queued").unwrap();
    let client = authenticated_client(ScriptedTransport::json(200, br#"{"message":"logged out"}"#.to_vec()));
    let store = Arc::new(Mutex::new(beebeeb_store::Store::open_in_memory().unwrap()));
    store
        .lock()
        .unwrap()
        .put_contact_key(&beebeeb_store::ContactKey {
            contact_id: "contact".into(),
            public_key: vec![7; 32],
            observed_at: 1,
        })
        .unwrap();
    let master = Arc::new(MasterKey::from_bytes([11; 32]));
    let uploads = Arc::new(
        UploadService::new_for_test(
            Arc::clone(&client),
            Arc::clone(&store),
            Arc::clone(&master),
            root.path().join("staging"),
        )
        .unwrap(),
    );
    uploads
        .enqueue(
            crate::uploads::UploadRequest::new(&source_path, "queued.txt", None, None),
            1,
        )
        .unwrap();
    let downloads = Arc::new(
        DownloadService::new_for_test(
            Arc::clone(&client),
            Arc::clone(&store),
            Arc::clone(&master),
            root.path().join("cache"),
            1024,
            beebeeb_types::limits::MemoryBudget::NATIVE,
        )
        .unwrap(),
    );
    let thumbnails = Arc::new(
        ThumbnailService::new_for_test(
            Arc::clone(&client),
            Arc::clone(&store),
            master,
            Arc::new(Codec),
            root.path().join("thumbs"),
            1024,
            beebeeb_core::thumbnail::Platform::Ios,
        )
        .unwrap(),
    );
    let backup_source = Arc::new(Source::default());
    let backup = Arc::new(
        BackupService::new(
            Arc::clone(&client),
            Arc::clone(&uploads),
            backup_source,
            BackupConfiguration::new(BackupFolder { id: "managed".into() }, true, "device").unwrap(),
        )
        .unwrap(),
    );
    backup
        .manifest()
        .remember("photo", "remote", BackupCopyState::Active)
        .unwrap();
    let search = Arc::new(SearchService::new(4));
    let coordinator = ServiceCoordinator::new(
        client,
        Arc::clone(&uploads),
        downloads,
        thumbnails,
        Arc::clone(&backup),
        Arc::clone(&search),
        Arc::clone(&store),
    );
    coordinator.start([FileRecord::for_test("one", "Readable before sign-out")]);
    let canceller = FailingCanceller::default();
    let purger = Purger::default();

    let report = coordinator
        .sign_out_app(&Secrets::default(), &canceller, &purger, 2)
        .await;

    assert_eq!(report.failures, [SignOutFailure::PlatformCancellation]);
    assert_eq!(canceller.0.load(Ordering::Relaxed), 1);
    assert_eq!(purger.0.load(Ordering::Relaxed), 1);
    assert!(search.query("Readable").is_empty());
    assert_eq!(backup.manifest().copy_state("photo"), None);
    assert!(store.lock().unwrap().contact_key("contact").unwrap().is_none());
    assert!(
        uploads
            .list()
            .unwrap()
            .iter()
            .all(|item| item.state == beebeeb_store::TransferState::Cancelled)
    );

    let replacement = coordinator
        .prepare_account_replacement(&Secrets::default(), &SuccessfulCanceller, &purger, 3)
        .await
        .unwrap();
    assert!(replacement.is_authorized());
}

const ONE_DEVICE_LISTING: &[u8] = br#"{"devices":[{"id":"device-1","hostname":"","platform":"macos","last_seen":"2026-11-05T12:00:00Z","created_at":"2026-11-05T12:00:00Z","holds_key":true}]}"#;

fn sign_out_coordinator(client: Arc<Client>, root: &std::path::Path) -> ServiceCoordinator {
    let store = Arc::new(Mutex::new(beebeeb_store::Store::open_in_memory().unwrap()));
    let master = Arc::new(MasterKey::from_bytes([11; 32]));
    let uploads = Arc::new(
        UploadService::new_for_test(
            Arc::clone(&client),
            Arc::clone(&store),
            Arc::clone(&master),
            root.join("staging"),
        )
        .unwrap(),
    );
    let downloads = Arc::new(
        DownloadService::new_for_test(
            Arc::clone(&client),
            Arc::clone(&store),
            Arc::clone(&master),
            root.join("cache"),
            1024,
            beebeeb_types::limits::MemoryBudget::NATIVE,
        )
        .unwrap(),
    );
    let thumbnails = Arc::new(
        ThumbnailService::new_for_test(
            Arc::clone(&client),
            Arc::clone(&store),
            master,
            Arc::new(Codec),
            root.join("thumbs"),
            1024,
            beebeeb_core::thumbnail::Platform::Ios,
        )
        .unwrap(),
    );
    let backup = Arc::new(
        BackupService::new(
            Arc::clone(&client),
            Arc::clone(&uploads),
            Arc::new(Source::default()),
            BackupConfiguration::new(BackupFolder { id: "managed".into() }, true, "device").unwrap(),
        )
        .unwrap(),
    );
    ServiceCoordinator::new(
        client,
        uploads,
        downloads,
        thumbnails,
        backup,
        Arc::new(SearchService::new(4)),
        store,
    )
}

fn request_lines(transport: &ScriptedTransport) -> Vec<String> {
    transport
        .requests()
        .iter()
        .map(|request| format!("{:?} {}", request.method(), request.path()))
        .collect()
}

#[tokio::test]
async fn coordinated_device_sign_out_removes_the_device_and_ends_the_session() {
    let root = tempdir().unwrap();
    let transport = ScriptedTransport::json(200, ONE_DEVICE_LISTING.to_vec());
    transport.push_json(204, Vec::new());
    transport.push_json(401, br#"{"error":"unauthorized"}"#.to_vec());
    let coordinator = sign_out_coordinator(authenticated_client(transport.clone()), root.path());

    let report = coordinator
        .sign_out_device(
            "device-1",
            true,
            &Secrets::default(),
            &SuccessfulCanceller,
            &Purger::default(),
            2,
        )
        .await
        .unwrap();

    assert_eq!(report.failures, []);
    assert_eq!(
        request_lines(&transport),
        [
            "Get /api/v1/clients/devices",
            "Delete /api/v1/clients/devices/device-1",
            "Post /api/v1/auth/logout",
        ]
    );
}

#[tokio::test]
async fn coordinated_device_sign_out_still_wipes_locally_when_removal_fails() {
    let root = tempdir().unwrap();
    let transport = ScriptedTransport::json(200, ONE_DEVICE_LISTING.to_vec());
    transport.push_json(500, br#"{"error":"unavailable"}"#.to_vec());
    transport.push_json(200, br#"{"message":"logged out"}"#.to_vec());
    let client = authenticated_client(transport.clone());
    let coordinator = sign_out_coordinator(Arc::clone(&client), root.path());

    let report = coordinator
        .sign_out_device(
            "device-1",
            true,
            &Secrets::default(),
            &SuccessfulCanceller,
            &Purger::default(),
            2,
        )
        .await
        .unwrap();

    assert_eq!(report.failures, [SignOutFailure::Session]);
    assert_eq!(
        request_lines(&transport).last().map(String::as_str),
        Some("Post /api/v1/auth/logout")
    );
    assert!(client.list_devices().await.is_err());
    assert_eq!(transport.request_count(), 3, "signed-out client sent another request");
}

#[tokio::test]
async fn direct_device_sign_out_ends_a_session_the_server_did_not_tie_to_the_device() {
    let transport = ScriptedTransport::json(200, ONE_DEVICE_LISTING.to_vec());
    transport.push_json(204, Vec::new());
    transport.push_json(200, br#"{"message":"logged out"}"#.to_vec());
    let client = authenticated_client(transport.clone());

    client
        .sign_out_whole_device("device-1", true, &Secrets::default())
        .await
        .unwrap();

    assert_eq!(
        request_lines(&transport).last().map(String::as_str),
        Some("Post /api/v1/auth/logout")
    );
}

#[tokio::test]
async fn direct_device_sign_out_treats_an_already_ended_session_as_success() {
    let transport = ScriptedTransport::json(200, ONE_DEVICE_LISTING.to_vec());
    transport.push_json(204, Vec::new());
    transport.push_json(401, br#"{"error":"unauthorized"}"#.to_vec());
    let client = authenticated_client(transport.clone());
    let mut events = client.events().subscribe();

    client
        .sign_out_whole_device("device-1", true, &Secrets::default())
        .await
        .unwrap();

    while let Ok(event) = events.try_recv() {
        assert_ne!(
            event,
            EngineEvent::SessionExpired,
            "a finished sign-out is not an expiry"
        );
    }
}

/// A screen-locked client over `transport`, the store it started from, and a listing of two
/// devices: `device-1` carries this device's stored hardware identity, `device-2` another's.
fn screen_locked_client(transport: &ScriptedTransport) -> (Arc<Client>, Secrets, Vec<u8>) {
    let secrets = Secrets::default();
    crate::Session::from_parts_for_test("https://api.example", "token", "user-1", [1; 32], 1)
        .unwrap()
        .save(&secrets, "test-app")
        .unwrap();
    let own = crate::session::HardwareIdentity::load_or_create(&secrets)
        .unwrap()
        .id()
        .to_owned();
    let device = |id: &str, hardware_id: &str| {
        serde_json::json!({
            "id": id, "hostname": "", "platform": "windows", "last_seen": "2026-11-05T12:00:00Z",
            "created_at": "2026-11-05T12:00:00Z", "holds_key": true, "hardware_id": hardware_id,
        })
    };
    let listing = serde_json::to_vec(&serde_json::json!({
        "devices": [device("device-1", &own), device("device-2", "5d0e0b3c-7a52-4f1a-9d2e-1c6f3a8b9e77")],
    }))
    .unwrap();
    let client = Arc::new(Client::new(ClientConfig::for_tests(), Arc::new(transport.clone())).unwrap());
    assert_eq!(
        client.start_from_store(&secrets).unwrap(),
        beebeeb_api::flows::LockState::ScreenLocked
    );
    (client, secrets, listing)
}

fn refused_on_a_locked_screen<T: std::fmt::Debug>(result: Result<T, crate::devices::DeviceError>) {
    assert!(
        matches!(
            result,
            Err(crate::devices::DeviceError::Client(crate::ClientError::ScreenLocked))
        ),
        "{result:?}"
    );
}

/// A sign-out is allowed on a locked screen, and it removes this device only: with another
/// device's id it would be a device removal, which a locked screen refuses.
#[tokio::test]
async fn a_screen_locked_device_sign_out_removes_this_device_and_no_other() {
    let transport = ScriptedTransport::json(200, Vec::new());
    let (client, secrets, listing) = screen_locked_client(&transport);
    transport.respond_next_json(200, listing.clone());

    refused_on_a_locked_screen(client.sign_out_whole_device("device-2", true, &secrets).await);
    assert_eq!(
        request_lines(&transport),
        ["Get /api/v1/clients/devices"],
        "nothing was removed"
    );
    assert_eq!(client.lock_state(), beebeeb_api::flows::LockState::ScreenLocked);
    assert!(client.held_key().is_ok());

    transport.respond_next_json(200, br#"{"message":"logged out"}"#.to_vec());
    transport.respond_next_json(204, Vec::new());
    transport.respond_next_json(200, listing);
    client.sign_out_whole_device("device-1", true, &secrets).await.unwrap();
    assert_eq!(
        request_lines(&transport)[1..],
        [
            "Get /api/v1/clients/devices",
            "Delete /api/v1/clients/devices/device-1",
            "Post /api/v1/auth/logout",
        ]
    );
    assert_eq!(client.lock_state(), beebeeb_api::flows::LockState::SignedOut);
}

#[tokio::test]
async fn a_screen_locked_coordinated_sign_out_removes_this_device_and_no_other() {
    let root = tempdir().unwrap();
    let transport = ScriptedTransport::json(200, Vec::new());
    let (client, secrets, listing) = screen_locked_client(&transport);
    let coordinator = sign_out_coordinator(Arc::clone(&client), root.path());
    assert_eq!(client.lock_state(), beebeeb_api::flows::LockState::ScreenLocked);
    transport.respond_next_json(200, listing.clone());

    refused_on_a_locked_screen(
        coordinator
            .sign_out_device("device-2", true, &secrets, &SuccessfulCanceller, &Purger::default(), 2)
            .await,
    );
    assert_eq!(
        request_lines(&transport),
        ["Get /api/v1/clients/devices"],
        "nothing was removed"
    );
    assert_eq!(client.lock_state(), beebeeb_api::flows::LockState::ScreenLocked);

    transport.respond_next_json(200, br#"{"message":"logged out"}"#.to_vec());
    transport.respond_next_json(204, Vec::new());
    transport.respond_next_json(200, listing);
    let report = coordinator
        .sign_out_device("device-1", true, &secrets, &SuccessfulCanceller, &Purger::default(), 2)
        .await
        .unwrap();
    assert_eq!(report.failures, []);
    assert_eq!(
        request_lines(&transport)[1..],
        [
            "Get /api/v1/clients/devices",
            "Delete /api/v1/clients/devices/device-1",
            "Post /api/v1/auth/logout",
        ]
    );
    assert_eq!(client.lock_state(), beebeeb_api::flows::LockState::SignedOut);
}

/// Duplicating a file is a change a person drives: refused on a locked screen, nothing read.
#[tokio::test]
async fn a_locked_screen_refuses_a_duplicate() {
    let root = tempdir().unwrap();
    let transport = ScriptedTransport::json(200, Vec::new());
    let (client, _secrets, _) = screen_locked_client(&transport);
    let store = Arc::new(Mutex::new(beebeeb_store::Store::open_in_memory().unwrap()));
    let downloads = DownloadService::new(
        Arc::clone(&client),
        Arc::clone(&store),
        root.path().join("cache"),
        1024,
        beebeeb_types::limits::MemoryBudget::NATIVE,
    )
    .unwrap();
    let uploads = UploadService::new(Arc::clone(&client), store, root.path().join("staging")).unwrap();
    let source = crate::downloads::DownloadFile {
        file_id: "file-1".into(),
        name_encrypted: "sealed".into(),
        size_bytes: 1,
        chunk_size_bytes: 1,
        chunk_count: 1,
        object_version_id: "v".into(),
    };

    let refused = crate::files::duplicate_file(&downloads, &uploads, &source, "copy", None, None, 1).await;
    assert!(
        matches!(
            refused,
            Err(crate::files::FileServiceError::Client(crate::ClientError::ScreenLocked))
        ),
        "{refused:?}"
    );
    assert_eq!(transport.request_count(), 0);
    assert!(uploads.list_inner().unwrap().is_empty(), "nothing was queued");
}
