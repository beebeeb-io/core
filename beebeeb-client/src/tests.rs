use std::sync::Arc;

use beebeeb_api::routes;
use beebeeb_api::routes::sync::Snapshot;
use beebeeb_transfer::background::{BackgroundRestore, BackgroundUploadPlanner, UploadSourceIdentity};

use crate::{
    Client, ClientConfig, ClientError, EngineEvent, MemorySecretStore, Session, sync::complete_snapshot_from_answer,
    test_support::ScriptedTransport,
};

#[tokio::test]
async fn account_switch_discards_an_answer_that_finishes_late() {
    let transport = Arc::new(ScriptedTransport::paused_json(200, br#"{"files":[]}"#.to_vec()));
    let client = Arc::new(Client::new(ClientConfig::for_tests(), transport.clone()).unwrap());
    client.set_authentication("token-a", "account-a").unwrap();
    let task = tokio::spawn({
        let client = client.clone();
        async move { client.execute(&routes::files::list(None, false), &()).await }
    });
    transport.wait_until_sent().await;
    client.set_authentication("token-b", "account-b").unwrap();
    transport.release();

    assert!(matches!(task.await.unwrap(), Err(ClientError::StaleAccount)));
}

#[tokio::test]
async fn native_requests_declare_the_write_and_metadata_capabilities_only_where_checked() {
    let transport = Arc::new(ScriptedTransport::json(200, br#"{"files":[]}"#.to_vec()));
    let client = Client::new(ClientConfig::for_tests(), transport.clone()).unwrap();
    client.set_authentication("token", "account-a").unwrap();

    client.execute(&routes::files::list(None, false), &()).await.unwrap();
    // The scripted answer is not a submit result; only the request matters here.
    let _ = client
        .execute(&routes::sync::submit(), &routes::sync::Submit { ops: Vec::new() })
        .await;

    let requests = transport.requests();
    assert_eq!(requests[0].header("X-Beebeeb-Capabilities"), None);
    assert_eq!(
        requests[1].header("X-Beebeeb-Capabilities"),
        Some("file-write-v2, version-metadata-v1")
    );
}

#[test]
fn owner_mismatch_preserves_the_stored_account_and_does_not_read_its_key() {
    let store = MemorySecretStore::default();
    let session = Session::from_parts_for_test("https://api.example", "token", "account-a", [7; 32], 3).unwrap();
    session.save(&store, "test-app").unwrap();
    store.reset_reads();

    assert!(Session::load_for_user(&store, "account-b", "test-app").is_err());
    assert_eq!(store.read_count_for("session.master_key"), 0);
    assert!(
        Session::load_for_user(&store, "account-a", "test-app")
            .unwrap()
            .is_some()
    );
}

#[test]
fn client_session_key_is_bound_to_the_installed_generation() {
    let transport = Arc::new(ScriptedTransport::json(200, Vec::new()));
    let client = Client::new(ClientConfig::for_tests(), transport).unwrap();
    let session = Session::from_parts_for_test("https://api.example", "token", "account-a", [7; 32], 1).unwrap();

    client.set_session(&session).unwrap();
    let key = client.session_key().unwrap();
    assert!(key.is_current(&client));
    assert_eq!(key.generation(), client.generation());

    client.clear_authentication().unwrap();
    assert!(!key.is_current(&client));
    assert!(client.session_key().is_err());
}

#[tokio::test]
async fn request_bound_to_retired_session_key_never_reaches_transport() {
    let transport = Arc::new(ScriptedTransport::json(200, br#"{"files":[]}"#.to_vec()));
    let client = Client::new(ClientConfig::for_tests(), transport.clone()).unwrap();
    let session = Session::from_parts_for_test("https://api.example", "token-a", "account-a", [7; 32], 1).unwrap();
    client.set_session(&session).unwrap();
    let key = client.session_key().unwrap();

    client.set_authentication("token-b", "account-b").unwrap();
    let result = client
        .execute_for_generation(&routes::files::list(None, false), &(), key.generation())
        .await;

    assert!(matches!(result, Err(ClientError::StaleAccount)));
    assert_eq!(transport.request_count(), 0);
}

#[tokio::test]
async fn account_mismatch_becomes_an_engine_event() {
    let transport = Arc::new(ScriptedTransport::json(
        409,
        br#"{"error":"account_mismatch","message":"wrong account"}"#.to_vec(),
    ));
    let client = Client::new(ClientConfig::for_tests(), transport).unwrap();
    client.set_authentication("token", "account-a").unwrap();
    let mut events = client.events().subscribe();

    let result = client.execute(&routes::files::list(None, false), &()).await;

    assert!(result.is_err());
    assert_eq!(events.recv().await.unwrap(), EngineEvent::AccountMismatch);
}

#[tokio::test]
async fn session_expiry_emits_event_without_accepting_the_answer() {
    let transport = Arc::new(ScriptedTransport::json(401, br#"{"error":"expired"}"#.to_vec()));
    let client = Client::new(ClientConfig::for_tests(), transport).unwrap();
    client.set_authentication("token", "account-a").unwrap();
    let mut events = client.events().subscribe();
    while events.try_recv().is_ok() {}

    assert!(client.execute(&routes::files::list(None, false), &()).await.is_err());
    assert_eq!(events.recv().await.unwrap(), EngineEvent::SessionExpired);
}

#[tokio::test]
async fn sign_out_stops_in_flight_work() {
    let transport = Arc::new(ScriptedTransport::paused_json(200, br#"{"files":[]}"#.to_vec()));
    let client = Arc::new(Client::new(ClientConfig::for_tests(), transport.clone()).unwrap());
    client.set_authentication("token", "account-a").unwrap();
    let task = tokio::spawn({
        let client = client.clone();
        async move { client.execute(&routes::files::list(None, false), &()).await }
    });
    transport.wait_until_sent().await;

    client.clear_authentication().unwrap();
    transport.release();

    assert!(matches!(task.await.unwrap(), Err(ClientError::StaleAccount)));
}

#[tokio::test]
async fn work_started_after_sign_out_begins_cannot_use_retired_credentials() {
    let transport = Arc::new(ScriptedTransport::json(200, br#"{"files":[]}"#.to_vec()));
    let client = Client::new(ClientConfig::for_tests(), transport.clone()).unwrap();
    let session = Session::from_parts_for_test("https://api.example", "old-token", "account-a", [7; 32], 1).unwrap();
    client.set_session(&session).unwrap();

    client.stop_account_work();
    let result = client.execute(&routes::files::list(None, false), &()).await;

    assert!(matches!(result, Err(ClientError::StaleAccount)));
    assert_eq!(transport.request_count(), 0);
}

#[tokio::test]
async fn hostile_oversized_answer_is_rejected_before_json_parsing() {
    let transport = Arc::new(ScriptedTransport::json(200, vec![b'x'; 4 * 1024 * 1024 + 1]));
    let client = Client::new(ClientConfig::for_tests(), transport).unwrap();
    client.set_authentication("token", "account-a").unwrap();

    assert!(matches!(
        client.execute(&routes::auth::me(), &()).await,
        Err(ClientError::Transport(crate::TransportError::ResponseTooLarge))
    ));
}

#[test]
fn partial_snapshot_never_authorizes_deletion() {
    let answer = Snapshot {
        nodes: Vec::new(),
        seq_id: 10,
        user_seq: 8,
        complete: None,
    };
    assert!(complete_snapshot_from_answer(&answer, Vec::new()).is_err());
}

#[test]
fn process_death_restore_abandons_when_the_plaintext_source_changed() {
    let directory = tempfile::tempdir().unwrap();
    let original = UploadSourceIdentity {
        size_bytes: 4,
        modified_unix_ms: 1,
        content_hash: None,
    };
    let mut planner =
        BackgroundUploadPlanner::new("upload", "session", "file", directory.path(), 1024, 4, 1, original).unwrap();
    let changed = UploadSourceIdentity {
        size_bytes: 4,
        modified_unix_ms: 2,
        content_hash: None,
    };

    let restored =
        BackgroundUploadPlanner::from_bytes(&planner.to_bytes().unwrap(), directory.path(), &changed).unwrap();

    assert!(matches!(restored, BackgroundRestore::AbandonAndRestart(_)));
}
