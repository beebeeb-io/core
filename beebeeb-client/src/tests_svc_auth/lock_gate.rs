//! Core applies the screen lock itself: while `ScreenLocked` every call a person drives is
//! refused with `ClientError::ScreenLocked` before anything is sent, except unlock, lock the
//! vault and sign out; the work keeps running until the vault is closed.

use beebeeb_api::flows::LockState;

use super::lock::*;
use super::*;
use crate::contacts::ContactServiceError;
use crate::downloads::{DownloadFile, DownloadService, DownloadServiceError};
use crate::files::{FileRecord, FileServiceError};
use crate::shares::ShareServiceError;
use crate::sync::SyncLoopError;
use crate::uploads::{NetworkKind, UploadService, UploadServiceError};
use crate::{Call, LockedAction};

/// Whether an error is core's refusal of a call on a locked screen.
trait Refusal {
    fn is_screen_locked(&self) -> bool;
}

impl Refusal for ClientError {
    fn is_screen_locked(&self) -> bool {
        matches!(self, ClientError::ScreenLocked)
    }
}

macro_rules! wraps_the_refusal {
    ($($error:ty),+) => {$(
        impl Refusal for $error {
            fn is_screen_locked(&self) -> bool {
                matches!(self, Self::Client(ClientError::ScreenLocked))
            }
        }
    )+};
}
wraps_the_refusal!(
    AuthError,
    DeviceError,
    FileServiceError,
    ContactServiceError,
    ShareServiceError,
    DownloadServiceError,
    UploadServiceError
);

/// Asserts that each call is refused as `ScreenLocked`, and counts them.
macro_rules! refused {
    ($count:ident: $($name:literal => $call:expr),+ $(,)?) => {$(
        match $call {
            Err(error) => assert!(error.is_screen_locked(), "{}: {error:?}", $name),
            Ok(_) => panic!("{}: a locked screen let the call in", $name),
        }
        $count += 1;
    )+};
}

fn services(client: &Arc<Client>, root: &std::path::Path) -> (DownloadService, UploadService) {
    let store = Arc::new(Mutex::new(beebeeb_store::Store::open_in_memory().unwrap()));
    (
        DownloadService::new(
            client.clone(),
            store.clone(),
            root.join("cache"),
            1024,
            beebeeb_types::limits::MemoryBudget::NATIVE,
        )
        .unwrap(),
        UploadService::new(client.clone(), store, root.join("staging")).unwrap(),
    )
}

fn a_file() -> DownloadFile {
    DownloadFile {
        file_id: "0b3c7a52-5d0e-4f1a-9d2e-1c6f3a8b9e02".into(),
        name_encrypted: "sealed".into(),
        size_bytes: 1,
        chunk_size_bytes: 1,
        chunk_count: 1,
        object_version_id: "v".into(),
    }
}

#[tokio::test]
async fn a_locked_screen_refuses_every_call_a_person_drives_and_sends_nothing() {
    let server = LockServer::new();
    let store = store_with_session();
    let client = Arc::new(screen_locked(&server, &store, false));
    let root = tempfile::tempdir().unwrap();
    let (downloads, uploads) = services(&client, root.path());
    let session = session(OWNER, STORED_TOKEN, 1);
    let record = FileRecord::for_test("file-1", "name");
    let row = record.wire();
    let file = a_file();
    let mut local = beebeeb_store::Store::open_in_memory().unwrap();
    let mut count = 0;

    // The key does not leave core.
    refused!(count: "session_key" => client.session_key());
    // Files: names, listings, content, changes.
    refused!(count:
        "list_files" => client.list_files(None, false).await,
        "list_file_records_page" => client.list_file_records_page(&session, None, false, None, 10).await,
        "get_file" => client.get_file("file-1").await,
        "get_file_record" => client.get_file_record(&session, "file-1").await,
        "file_versions" => client.file_versions("file-1").await,
        "storage_usage" => client.storage_usage().await,
        "create_folder" => client.create_folder(&session, "folder", None).await,
        "rename_entry" => client.rename_entry(&session, row, "new name").await,
        "move_entry" => client.move_entry(&session, row, None).await,
        "trash_file" => client.trash_file("file-1").await,
        "trash_entry" => client.trash_entry(row).await,
        "trash_entries" => client.trash_entries(std::slice::from_ref(row)).await,
        "restore_file" => client.restore_file("file-1").await,
        "restore_entry" => client.restore_entry(row).await,
        "delete_file_forever" => client.delete_file_forever("file-1").await,
        "delete_entry_forever" => client.delete_entry_forever(row).await,
        "delete_entries_forever" => client.delete_entries_forever(std::slice::from_ref(row)).await,
        "downloads.open" => downloads.open(&file, 1).await,
        "downloads.video_range" => downloads.video_range(&file, 0..1).await,
        "downloads.read_range" => downloads.read_range(&file, 0..1).await,
        "downloads.range_reader" => downloads.range_reader(&file),
        "uploads.list" => uploads.list(),
        "uploads.pause" => uploads.pause(1, 1),
        "uploads.resume" => uploads.resume(1, 1),
        "uploads.cancel" => uploads.cancel(1, 1),
        "uploads.enqueue" => uploads.enqueue(
            crate::uploads::UploadRequest::new(root.path().join("picked.txt"), "picked.txt", None, None),
            1,
        ),
    );
    // Sharing and contacts.
    refused!(count:
        "my_share_links" => client.my_share_links().await,
        "revoke_share_link" => client.revoke_share_link("share-1").await,
        "incoming_invites" => client.incoming_invites().await,
        "sent_invites" => client.sent_invites().await,
        "deny_invite" => client.deny_invite("invite-1").await,
        "folder_links" => client.folder_links(None).await,
        "revoke_folder_link" => client.revoke_folder_link("link-1").await,
        "file_requests" => client.file_requests().await,
        "close_file_request" => client.close_file_request("request-1").await,
        "fetch_contact_public_key" => client.fetch_contact_public_key(OWNER).await,
        "observe_contact_key_from_server" => client.observe_contact_key_from_server(&mut local, OWNER, 1).await,
        "accept_contact_key_from_server" => client.accept_contact_key_from_server(&mut local, OWNER, 1).await,
    );
    // The account, its devices and its settings.
    refused!(count:
        "setup_authenticator" => client.setup_authenticator().await,
        "enable_authenticator" => client.enable_authenticator("123456".into()).await,
        "remove_authenticator" => client.remove_authenticator("123456".into()).await,
        "request_account_deletion" => client.request_account_deletion(password(PASSWORD), None).await,
        "change_password" => client.change_password(password(PASSWORD), password("another password 2026"), &store).await,
        "change_email" => client.change_email("new@example.test", password(PASSWORD), &store).await,
        "set_version_history" => client.set_version_history(true, 30).await,
        "start_device_link" => client.start_device_link("a new device".into()).await,
        "cancel_recovery" => client.cancel_recovery("recovery-1").await,
        "pending_device_links" => client.pending_device_links().await,
        "begin_typed_device_approval" => client.begin_typed_device_approval("link-1", "123456").await,
        "deny_device_link" => client.deny_device_link("link-1").await,
        "list_devices" => client.list_devices().await,
        "remove_device" => client.remove_device("device-1").await,
        "list_account_sessions" => client.list_account_sessions().await,
        "revoke_account_session" => client.revoke_account_session("session-1").await,
    );
    assert_eq!(count, 55, "every call above was refused");
    assert_eq!(server.requests().len(), 0, "a refused call sends nothing");
    assert_eq!(
        client.lock_state(),
        LockState::ScreenLocked,
        "a refusal changes nothing"
    );
    assert_eq!(
        entry(&store, "session.token.test-app").unwrap(),
        STORED_TOKEN.as_bytes()
    );

    // The same calls reach the server once the screen is open.
    client.unlock_screen_platform_verified(&store).unwrap();
    assert!(client.session_key().unwrap().is_current(&client));
    let answer = client.list_files(None, false).await;
    assert!(matches!(answer, Err(ClientError::Api(_))), "{answer:?}");
    assert_eq!(server.requests().len(), 1);
}

/// The work the screen lock keeps running: it is refused only on a closed vault.
#[tokio::test]
async fn the_work_runs_on_a_locked_screen_and_stops_on_a_closed_vault() {
    let server = LockServer::new();
    let store = store_with_session();
    let client = Arc::new(screen_locked(&server, &store, false));
    let root = tempfile::tempdir().unwrap();
    let (_downloads, uploads) = services(&client, root.path());
    let session = session(OWNER, STORED_TOKEN, 1);
    let mut engine = beebeeb_core::sync::SyncEngine::new("device-1".into());

    // Screen-locked: sync asks the server, the upload queue is served.
    let synced = client.catch_up_sync(&session, &mut engine, 100).await;
    assert!(
        matches!(synced, Err(SyncLoopError::Client(ClientError::Api(_)))),
        "the request went out and the test server has no such route: {synced:?}"
    );
    assert_eq!(server.requests().len(), 1);
    assert!(uploads.next_transfers(1, NetworkKind::WiFi, 1).await.unwrap().is_none());
    assert!(client.check_call(Call::Work).is_ok());
    // The three things a person may do there.
    for allowed in [
        LockedAction::UnlockScreen,
        LockedAction::LockVault,
        LockedAction::SignOut,
    ] {
        assert!(client.check_call(Call::Person(allowed)).is_ok(), "{allowed:?}");
    }
    assert!(matches!(
        client.check_call(Call::Person(LockedAction::ViewFiles)),
        Err(ClientError::ScreenLocked)
    ));

    // A closed vault: the work is refused before anything is sent.
    client.lock_vault(&store).await.unwrap();
    let asked = server.requests().len();
    assert!(matches!(
        client.catch_up_sync(&session, &mut engine, 100).await,
        Err(SyncLoopError::Client(ClientError::VaultClosed))
    ));
    assert!(matches!(
        client.refresh_sync_snapshot(&session, &mut engine).await,
        Err(SyncLoopError::Client(ClientError::VaultClosed))
    ));
    assert!(matches!(
        uploads.next_transfers(1, NetworkKind::WiFi, 1).await,
        Err(UploadServiceError::Client(ClientError::VaultClosed))
    ));
    assert!(matches!(
        uploads.enqueue_work(
            crate::uploads::UploadRequest::new(root.path().join("synced.txt"), "synced.txt", None, None),
            1,
        ),
        Err(UploadServiceError::Client(ClientError::VaultClosed))
    ));
    // A password change is made from an open app: a closed vault holds no key to keep.
    assert!(matches!(
        client
            .change_password(password(PASSWORD), password("another password 2026"), &store)
            .await,
        Err(AuthError::Client(ClientError::VaultClosed))
    ));
    assert_eq!(server.requests().len(), asked);
    assert!(matches!(client.check_call(Call::Work), Err(ClientError::VaultClosed)));
}

/// A closed vault may still hold credentials: a sign-in or a password change on its way set
/// them. They are for that proof alone. What a person drives is refused there too, before
/// anything is sent; the proofs, a lock and a sign-out pass.
#[tokio::test]
async fn a_closed_vault_that_holds_credentials_refuses_what_a_person_drives() {
    let server = LockServer::new();
    let store = store_with_session();
    let client = Arc::new(screen_locked(&server, &store, false));
    client.set_authentication("accepted-token", OWNER).unwrap();
    assert_eq!(client.lock_state(), LockState::VaultClosed);
    assert_eq!(client.account_id().unwrap(), OWNER, "credentials are held");

    macro_rules! closed {
        ($($call:expr),+ $(,)?) => {$(
            let answer = $call;
            assert!(
                matches!(&answer, Err(error) if format!("{error:?}").ends_with("VaultClosed)") || format!("{error:?}") == "VaultClosed"),
                "{}: {answer:?}", stringify!($call)
            );
        )+};
    }
    closed!(
        client.session_key().map(|_| ()),
        client.list_files(None, false).await.map(|_| ()),
        client.storage_usage().await.map(|_| ()),
        client.my_share_links().await.map(|_| ()),
    );
    assert!(matches!(
        client.list_devices().await,
        Err(DeviceError::Client(ClientError::VaultClosed))
    ));
    assert!(matches!(
        client.remove_device("device-2").await,
        Err(DeviceError::Client(ClientError::VaultClosed))
    ));
    assert!(matches!(
        client.setup_authenticator().await,
        Err(AuthError::Client(ClientError::VaultClosed))
    ));
    assert_eq!(server.requests().len(), 0, "a refused call sends nothing");

    // The proofs that lead out of a closed vault reach the server.
    let link = client.start_device_link("a new device".into()).await;
    assert!(
        matches!(link, Err(DeviceError::Client(ClientError::Api(_)))),
        "{link:?}"
    );
    assert_eq!(server.requests().len(), 1);
    for allowed in [
        LockedAction::StartKeyProof,
        LockedAction::ReadDeviceLinkResult,
        LockedAction::UseRecovery,
        LockedAction::LockVault,
        LockedAction::SignOut,
    ] {
        assert!(client.check_call(Call::Person(allowed)).is_ok(), "{allowed:?}");
    }
    assert!(matches!(
        client.check_call(Call::Person(LockedAction::ViewStatus)),
        Err(ClientError::VaultClosed)
    ));
}

/// A lock that cannot be read refuses: it reads as closed, a person and the work are
/// refused, and a restored session is not installed.
#[test]
fn an_unreadable_lock_refuses() {
    let store = store_with_session();
    let client = Arc::new(screen_locked(&LockServer::new(), &store, false));
    let poisoning = client.clone();
    let panicked = std::thread::spawn(move || {
        let _ = poisoning.with_lock_flow(|_| panic!("the lock is left poisoned"));
    })
    .join();
    assert!(panicked.is_err());

    assert_eq!(client.lock_state(), LockState::VaultClosed);
    assert!(matches!(client.session_key(), Err(ClientError::VaultClosed)));
    assert!(matches!(
        client.check_call(Call::Person(LockedAction::ViewFiles)),
        Err(ClientError::VaultClosed)
    ));
    assert!(matches!(client.check_call(Call::Work), Err(ClientError::VaultClosed)));
    assert!(matches!(
        client.set_session(&session(OWNER, STORED_TOKEN, 1)),
        Err(ClientError::State)
    ));
}

/// A host that installs its sessions itself and never starts the lock through core is
/// refused nothing: its lock state is `SignedOut`.
#[tokio::test]
async fn a_host_that_never_started_the_lock_is_refused_nothing() {
    let server = LockServer::new();
    let client = Client::new(config(false), server.clone()).unwrap();
    client.set_session(&session(OWNER, STORED_TOKEN, 1)).unwrap();
    assert_eq!(client.lock_state(), LockState::SignedOut);
    assert!(client.session_key().unwrap().is_current(&client));
    assert!(client.check_call(Call::Work).is_ok());
    let answer = client.list_files(None, false).await;
    assert!(matches!(answer, Err(ClientError::Api(_))), "{answer:?}");
    assert_eq!(server.requests().len(), 1);
}

/// The gated surface, read from the sources: in the files below, every public function of
/// `Client` or of a service asks the lock (`person_call` or `work_call`) or is named here as
/// one that does not. A new public function fails this test until it is put in one of the two.
#[test]
fn every_public_call_asks_the_lock_or_is_listed_as_ungated() {
    // (file, source, the public functions that do not ask the lock)
    let sources: [(&str, &str, &[&str]); 16] = [
        (
            "platform.rs",
            include_str!("../platform.rs"),
            // Construction, the start of search, and two sign-outs of the whole app, which
            // every lock state allows and which name no device.
            &["new", "start", "sign_out_app", "prepare_account_replacement"],
        ),
        (
            "file_provider.rs",
            include_str!("../file_provider.rs"),
            // Construction and reads of the local tree: the operating system's file manager
            // shows the sync folder on a locked screen by design. They hold no client.
            &[
                "new",
                "with_budget",
                "set_system_items",
                "item",
                "children",
                "changes_since",
                "work_state",
            ],
        ),
        ("files.rs", include_str!("../files.rs"), &[]),
        ("settings.rs", include_str!("../settings.rs"), &[]),
        ("contacts.rs", include_str!("../contacts.rs"), &[]),
        ("shares.rs", include_str!("../shares.rs"), &[]),
        ("sync.rs", include_str!("../sync.rs"), &[]),
        ("auth/account.rs", include_str!("../auth/account.rs"), &[]),
        (
            "auth/passkey.rs",
            include_str!("../auth/passkey.rs"),
            // A step of a sign-in on a new device: it runs before the app holds a key.
            &["open_with_passkey"],
        ),
        (
            "auth/recovery.rs",
            include_str!("../auth/recovery.rs"),
            // The steps of a recovery: a proof stronger than the screen lock, made with the
            // recovery's own secret. Cancelling by id is the session's, and asks.
            &[
                "start_recovery",
                "recovery_status",
                "complete_recovery",
                "install_recovered_session",
                "install_recovered_session_replacing_account",
                "cancel_recovery_with_token",
            ],
        ),
        (
            "devices.rs",
            include_str!("../devices.rs"),
            // The first step of a device link from a sign-in: it sets the accepted
            // credentials itself, which closes an app that held a key.
            &["start_device_link_for_sign_in"],
        ),
        (
            "downloads.rs",
            include_str!("../downloads.rs"),
            // Construction, events, a cancel, the cache, and the account-free share view.
            &[
                "new",
                "observe",
                "cancel",
                "share_view_download",
                "clear_cache",
                "observe_file_version",
            ],
        ),
        (
            "thumbnails.rs",
            include_str!("../thumbnails.rs"),
            // Construction, events, queueing for the cache, the cache, the sign-out.
            &[
                "new",
                "observe",
                "enqueue_generation",
                "enqueue_first_sync",
                "clear",
                "sign_out",
            ],
        ),
        (
            "archives.rs",
            include_str!("../archives.rs"),
            // Construction, events, and the calls that only end or feed a run a person started.
            &["new", "observe", "supply_password", "cancel", "close"],
        ),
        (
            "uploads/queue.rs",
            include_str!("../uploads/queue.rs"),
            // `enqueue`, `pause`, `resume` and `cancel` are a person's, `enqueue_work` and
            // `next_transfers` are work; these observe the queue, record what the work
            // finished, or clean up for the backup and the archive service.
            &[
                "new",
                "set_completion_handler",
                "observe",
                "transfer_finished",
                "cancel_sources_matching",
                "pending_backup_outcomes",
                "cancel_backup_uploads",
                "active_backup_count",
                "mark_backup_outcome_applied",
                "finalize_sign_out",
            ],
        ),
        (
            "backup.rs",
            include_str!("../backup.rs"),
            // The pass and `configure_saved` are work, `configure` and `back_up_again` a
            // person's; the rest reads the manifest or records what the platform reports.
            &[
                "new",
                "with_manifest_store",
                "manifest",
                "observe",
                "assets_changed",
                "stopped",
                "upload_completed",
                "sign_out",
            ],
        ),
    ];
    let mut gated = 0;
    for (file, source, ungated) in sources {
        // A checkout with CRLF line ends reads the same.
        let source = &source.replace("\r\n", "\n");
        let mut seen_ungated = Vec::new();
        for block in source.split("\nimpl ").skip(1) {
            let header = block.lines().next().unwrap_or_default();
            let owner = header.trim_end_matches(" {");
            if !(owner == "Client" || owner.ends_with("Service") || owner == "ServiceCoordinator") {
                continue;
            }
            let block = block.split("\n}\n").next().unwrap_or_default();
            for function in block.split("\n    pub ").skip(1) {
                let Some(signature) = function
                    .strip_prefix("async fn ")
                    .or_else(|| function.strip_prefix("fn "))
                else {
                    continue;
                };
                let name = signature
                    .split(|character: char| !(character.is_alphanumeric() || character == '_'))
                    .next()
                    .unwrap_or_default();
                let body = function.split("\n    }\n").next().unwrap_or_default();
                if body.contains("person_call(") || body.contains("work_call(") {
                    gated += 1;
                } else {
                    seen_ungated.push(name);
                }
            }
        }
        assert_eq!(
            seen_ungated, ungated,
            "{file}: the public functions that do not ask the lock"
        );
    }
    assert_eq!(gated, 103, "the public functions that ask the lock");
}

/// Every `pub fn` and `pub async fn` of one source file, free or in an `impl`, with its body.
fn public_functions(source: &str) -> Vec<(String, &str)> {
    let mut found = Vec::new();
    for indent in ["", "    "] {
        let start = format!("\n{indent}pub ");
        let end = format!("\n{indent}}}\n");
        let mut rest = source;
        while let Some(at) = rest.find(&start) {
            rest = &rest[at + start.len()..];
            let Some(signature) = rest.strip_prefix("async fn ").or_else(|| rest.strip_prefix("fn ")) else {
                continue;
            };
            let name: String = signature
                .chars()
                .take_while(|character| character.is_alphanumeric() || *character == '_')
                .collect();
            let body = &rest[..rest.find(&end).unwrap_or(rest.len())];
            found.push((name, body));
        }
    }
    found
}

fn source_files(directory: &std::path::Path, into: &mut Vec<std::path::PathBuf>) {
    for entry in std::fs::read_dir(directory).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        if name.starts_with("tests") || name == "test_support.rs" {
            continue;
        }
        if path.is_dir() {
            source_files(&path, into);
        } else if name.ends_with(".rs") {
            into.push(path);
        }
    }
}

/// The whole public surface of this crate, read from every source file: a public entry
/// point (a method of `Client`, of a service or of the coordinator, or a free function) that
/// reaches one of the ungated internals (`*_inner`, `held_key`) or sends a request itself
/// (`.execute*`) asks the lock itself first, or is named here with its reason. Dropping one
/// gate, or adding an ungated way in, fails here. The walk reads a function's own body: a
/// request sent by a private helper it calls is not seen.
#[test]
fn no_public_entry_point_reaches_the_ungated_internals_without_asking_the_lock() {
    let exempt = [
        // A sign-out: every lock state allows it.
        "auth/install.rs sign_out_this_app",
        // The strong installs: their `_inner` is their own body, and a proof stronger than
        // the screen lock opens the app from every state.
        "auth/install.rs install_new_device",
        "auth/install.rs install_new_device_replacing_account",
        // The lock's own call.
        "auth/lock.rs refresh_lock_from_server",
        // Steps of a sign-in, a recovery or a signup: proofs, made before a key is held or
        // with their own secret.
        "auth/passkey.rs open_with_passkey",
        "auth/recovery.rs start_recovery",
        "auth/recovery.rs recovery_status",
        "auth/recovery.rs complete_recovery",
        "auth/recovery.rs install_recovered_session",
        "auth/recovery.rs install_recovered_session_replacing_account",
        "auth/recovery.rs cancel_recovery_with_token",
        "auth/sign_in.rs submit_two_factor",
        "auth/sign_in.rs request_email_code",
        "auth/sign_in.rs submit_email_code",
        "auth/signup.rs fetch_onboarding",
        "auth/signup.rs start_signup_email",
        "auth/signup.rs verify_signup_email",
        "auth/signup.rs create_account",
        "devices.rs start_device_link_for_sign_in",
        // Account-free: a share view opened with its own key.
        "downloads.rs share_view_download",
        // The archive service's clean-up of its own staged files when it is made.
        "uploads/queue.rs cancel_sources_matching",
    ];
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    source_files(&root, &mut files);
    files.sort();
    let (mut walked, mut asking, mut ungated) = (0, 0, Vec::new());
    for path in &files {
        let source = std::fs::read_to_string(path).unwrap().replace("\r\n", "\n");
        let file = path.strip_prefix(&root).unwrap().to_string_lossy().replace('\\', "/");
        for (name, body) in public_functions(&source) {
            walked += 1;
            let reaches = body.contains("_inner(") || body.contains("held_key(") || body.contains(".execute");
            let asks = body.contains("person_call(") || body.contains("work_call(");
            if reaches && asks {
                asking += 1;
            } else if reaches {
                ungated.push(format!("{file} {name}"));
            }
        }
    }
    assert_eq!(
        ungated, exempt,
        "public entry points that reach an ungated internal without asking"
    );
    // The walk saw the surface: it is not green because it matched nothing.
    assert!(files.len() >= 40, "{} source files", files.len());
    assert!(walked >= 300, "{walked} public functions");
    assert_eq!(
        asking, 92,
        "public entry points that reach an ungated internal and ask the lock"
    );
}

/// Core's own code never goes through a gate it has a twin for: a gated call `x` with an
/// ungated `x_inner` is for the host, and work that called `x` would stop on a locked screen
/// (a backup pass that read the upload queue through `list` did). Read from every source
/// file: the calls of each such name, by anything in this crate.
#[test]
fn core_calls_the_ungated_twin_never_the_gated_call() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    source_files(&root, &mut files);
    let sources: Vec<String> = files
        .iter()
        .map(|path| std::fs::read_to_string(path).unwrap().replace("\r\n", "\n"))
        .collect();
    let mut twins: Vec<String> = sources
        .iter()
        .flat_map(|source| source.split("fn ").skip(1))
        .filter_map(|after| after.split('(').next()?.strip_suffix("_inner").map(str::to_owned))
        .filter(|name| !name.is_empty() && name.chars().all(|c| c.is_alphanumeric() || c == '_'))
        .collect();
    twins.sort();
    twins.dedup();
    assert_eq!(twins.len(), 18, "{twins:?}");
    let called: Vec<(String, usize)> = twins
        .into_iter()
        .map(|name| {
            let call = format!(".{name}(");
            let count = sources
                .iter()
                .flat_map(|source| source.lines())
                .filter(|line| !line.trim_start().starts_with("//"))
                .map(|line| line.matches(&call).count())
                .sum();
            (name, count)
        })
        .filter(|(_, count)| *count > 0)
        .collect();
    // `cancel`: a platform canceller's, an extraction's and the archive service's own.
    // `create_folder`: the archive driver's own method of that name. `open`: other types'
    // (a device link, a range opener, a file). None is a gated call of the client.
    assert_eq!(
        called,
        [
            ("cancel".to_owned(), 4),
            ("create_folder".to_owned(), 2),
            ("open".to_owned(), 4)
        ]
    );
}
