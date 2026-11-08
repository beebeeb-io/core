//! The upload's source and its completion: a file that grew while it waited
//! is uploaded whole from the first pass, and a completion the server may
//! already have accepted is finished by sending the same request again,
//! never by a restart (a duplicate).

use std::{
    path::Path,
    sync::{Arc, Mutex},
};

use beebeeb_core::kdf::MasterKey;
use serde_json::{Value, json};
use tempfile::tempdir;

use crate::{
    Client, ClientConfig, TransportError,
    test_support::ScriptedTransport,
    uploads::{NetworkKind, UploadRequest, UploadService, UploadServiceError},
};

fn service(transport: &ScriptedTransport, root: &Path) -> UploadService {
    let client = Arc::new(Client::new(ClientConfig::for_tests(), Arc::new(transport.clone())).unwrap());
    client.set_authentication("token", "owner").unwrap();
    UploadService::new_for_test(
        client,
        Arc::new(Mutex::new(beebeeb_store::Store::open_in_memory().unwrap())),
        Arc::new(MasterKey::from_bytes([31; 32])),
        root.join("staging"),
    )
    .unwrap()
}

fn json_bytes(value: Value) -> Vec<u8> {
    serde_json::to_vec(&value).unwrap()
}

fn init_answer(file_id: &str, chunk_size: u64) -> Vec<u8> {
    json_bytes(
        json!({"upload_session_id": "session", "file_id": file_id, "chunk_size_bytes": chunk_size, "chunk_count": 1}),
    )
}

fn token_answer() -> Vec<u8> {
    json_bytes(json!({"token": "scoped", "upload_session_id": "session", "expires_at": "2099-01-01T00:00:00Z"}))
}

fn paths(transport: &ScriptedTransport) -> Vec<String> {
    transport
        .requests()
        .iter()
        .map(|request| format!("{:?} {}", request.method(), request.path()))
        .collect()
}

#[tokio::test]
async fn a_source_that_grew_while_queued_is_uploaded_whole_from_the_first_pass() {
    let root = tempdir().unwrap();
    let source = root.path().join("notes.txt");
    std::fs::write(&source, b"0123456789").unwrap();
    // Answers in order: init (put in front below, once the file id is known),
    // the scoped token, complete.
    let transport = ScriptedTransport::json(200, token_answer());
    let uploads = service(&transport, root.path());
    let id = uploads
        .enqueue(UploadRequest::new(&source, "notes.txt", None, None), 1)
        .unwrap();
    let file_id = uploads.list().unwrap()[0].file_id.clone();
    // The person appends while the upload waits for Wi-Fi.
    std::fs::write(&source, b"0123456789 and forty more bytes of new text..").unwrap();
    let grown = std::fs::metadata(&source).unwrap().len();
    transport.respond_next_json(200, init_answer(&file_id, 64));
    transport.push_json(200, json_bytes(json!({"id": file_id, "status": "completed"})));

    let (_, requests) = uploads.next_transfers(1, NetworkKind::WiFi, 2).await.unwrap().unwrap();
    uploads
        .transfer_finished(id, &requests[0].ticket, 200, None, None, &[], 3)
        .await
        .unwrap();

    let requests = transport.requests();
    let init = requests
        .iter()
        .find(|request| request.path().ends_with("/uploads/init"))
        .unwrap();
    let init: Value = serde_json::from_slice(init.body()).unwrap();
    assert_eq!(
        init["file_size_bytes"],
        json!(grown),
        "sized from the source as it is now"
    );
    assert!(
        paths(&transport).iter().all(|line| !line.ends_with("/upload/abandon")),
        "{:?}",
        paths(&transport)
    );
    assert_eq!(
        uploads.list().unwrap()[0].state,
        beebeeb_store::TransferState::Succeeded
    );
}

/// Stage and upload one chunk, then lose `complete`'s answer: the client
/// cannot tell whether the server published the file.
async fn upload_with_a_lost_completion(root: &Path) -> (ScriptedTransport, UploadService, i64, String) {
    let source = root.join("photo.jpg");
    std::fs::write(&source, b"photo").unwrap();
    let transport = ScriptedTransport::json(200, token_answer());
    let uploads = service(&transport, root);
    let id = uploads
        .enqueue(UploadRequest::new(&source, "photo.jpg", None, None), 1)
        .unwrap();
    let file_id = uploads.list().unwrap()[0].file_id.clone();
    transport.respond_next_json(200, init_answer(&file_id, 32));
    let (_, requests) = uploads.next_transfers(1, NetworkKind::WiFi, 2).await.unwrap().unwrap();
    transport.fail_next(TransportError::Network);
    assert!(
        uploads
            .transfer_finished(id, &requests[0].ticket, 200, None, None, &[], 3)
            .await
            .is_err()
    );
    // As after a crash once the server accepted it: the staging is gone and
    // the platform has rewritten the export.
    let _ = std::fs::remove_dir_all(root.join("staging").join(format!("upload-{id}")));
    std::fs::write(&source, b"photo, exported again").unwrap();
    (transport, uploads, id, file_id)
}

#[tokio::test]
async fn a_completion_sent_before_a_crash_is_sent_again_never_restarted() {
    let root = tempdir().unwrap();
    let (transport, uploads, _, file_id) = upload_with_a_lost_completion(root.path()).await;
    let before = transport.request_count();
    transport.push_json(
        200,
        json_bytes(json!({"id": file_id, "status": "completed", "already_completed": true})),
    );

    uploads.next_transfers(1, NetworkKind::WiFi, 10).await.unwrap();

    let sent = paths(&transport);
    assert_eq!(
        sent[before..],
        ["Post /api/v1/uploads/session/complete".to_owned()],
        "the same completion, no abandon, no new session"
    );
    let first: Value = serde_json::from_slice(transport.requests()[before - 1].body()).unwrap();
    let again: Value = serde_json::from_slice(transport.requests()[before].body()).unwrap();
    assert_eq!(first, again, "the same sealed metadata");
    assert_eq!(
        uploads.list().unwrap()[0].state,
        beebeeb_store::TransferState::Succeeded
    );
}

#[tokio::test]
async fn a_completion_answer_for_another_file_is_never_taken_as_done() {
    let root = tempdir().unwrap();
    let (transport, uploads, _, _) = upload_with_a_lost_completion(root.path()).await;
    transport.push_json(
        200,
        json_bytes(
            json!({"id": "00000000-0000-4000-8000-000000000000", "status": "completed", "already_completed": true}),
        ),
    );

    let error = uploads.next_transfers(1, NetworkKind::WiFi, 10).await.unwrap_err();

    assert!(matches!(error, UploadServiceError::HostileChunkPlan), "{error:?}");
    assert_ne!(
        uploads.list().unwrap()[0].state,
        beebeeb_store::TransferState::Succeeded
    );
}
