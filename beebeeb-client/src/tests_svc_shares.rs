use std::sync::{Arc, Mutex};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use beebeeb_api::{ApiError, Method, Request};
use beebeeb_core::{
    auth_flow::{
        HttpResponse,
        step_up::{ConfirmToken, StepUp, StepUpPurpose, StepUpStep},
    },
    kdf::{MasterKey, derive_file_key},
    opaque::{derive_x25519_private, derive_x25519_public},
    opaque_protocol::{
        client_registration_finish, client_registration_start, create_server_setup, server_login_start,
        server_registration_finish, server_registration_start,
    },
    share_flow::{
        ShareFlowError,
        folder::{FolderLinkInput, rebuild_folder_link},
        folder_keys::CustodyMemory,
        link::{LinkOptions, open_link_file_key, rebuild_link},
        member::{InviteOutcome, PeerKeyExpectation},
        open_member_file_key, revoke_link_request,
        safety::key_fingerprint,
    },
};
use serde_json::{Value, json};

use crate::{
    Client, ClientConfig, ClientError, EngineEvent, Session,
    contacts::observe_contact_key,
    shares::ShareServiceError,
    test_support::{RouteAnswer, RoutedTransport, ScriptedTransport, json_answer},
};

const APP: &str = "https://app.beebeeb.test";
const OWNER_KEY: [u8; 32] = [0x11; 32];
const RECIPIENT_KEY: [u8; 32] = [0x22; 32];
const FILE: &str = "550e8400-e29b-41d4-a716-446655440000";
const FOLDER: &str = "2237c000-0000-4000-8000-000000000001";
const CHILD: &str = "2237c000-0000-4000-8000-000000000002";
/// A foreign (`F`, UUID version 8) item id.
const FOREIGN: &str = "0193b1c2-1111-8222-9333-444455556666";
const INVITE: &str = "7a1d1c2e-0000-4000-8000-000000000001";
const SHARE: &str = "8d2f0000-0000-4000-8000-000000000001";
const CONTACT: &str = "32e1e894-5249-4ca1-995b-0f031d52b26f";

fn signed_in_with(transport: Arc<dyn crate::Transport>) -> Client {
    let client = Client::new(ClientConfig::for_tests(), transport).unwrap();
    let session = Session::from_parts_for_test("https://api.example", "token", "user-1", OWNER_KEY, 1).unwrap();
    client.set_session(&session).unwrap();
    client
}

fn signed_in(transport: &ScriptedTransport) -> Client {
    signed_in_with(Arc::new(transport.clone()))
}

fn owner() -> MasterKey {
    MasterKey::from_bytes(OWNER_KEY)
}

fn public_key(master: &MasterKey) -> [u8; 32] {
    derive_x25519_public(&derive_x25519_private(master))
}

fn body(transport: &ScriptedTransport, index: usize) -> Value {
    serde_json::from_slice(transport.requests()[index].body()).unwrap()
}

fn claimed(recipient_public_key: &[u8; 32]) -> Vec<u8> {
    json!({"invite_id": INVITE, "status": "claimed", "recipient_public_key": STANDARD.encode(recipient_public_key)})
        .to_string()
        .into_bytes()
}

const APPROVED: &[u8] = br#"{"message":"invite approved","status":"approved","permission":"read"}"#;

/// A link body: the expiry only when one is set, and the token with both owner copies, which the
/// owner opens again through `share_flow`'s rebuild path to a link whose key opens the file.
fn assert_link_body(body: &Value, owner: &MasterKey, expires_in_hours: Option<u32>) -> String {
    assert_eq!(body["expires_in_hours"], json!(expires_in_hours));
    let rebuilt = rebuild_link(
        APP,
        owner,
        body["owner_wrapped_key"].as_str(),
        body["owner_wrapped_token"].as_str(),
        body["wrapped_file_key"].as_str().unwrap_or_default(),
    )
    .expect("the owner rebuilds the link from the copies the body carried");
    let parsed = beebeeb_core::share_link::parse(&rebuilt).unwrap();
    let opened = open_link_file_key(&parsed.key, body["wrapped_file_key"].as_str().unwrap()).unwrap();
    assert_eq!(opened.as_bytes(), derive_file_key(owner, FILE.as_bytes()).as_bytes());
    rebuilt.to_string()
}

/// The sealed file key of an approval, opened by the recipient with the owner's public key.
fn assert_sealed_for_recipient(approval: &Value) {
    let sealed = STANDARD
        .decode(approval["encrypted_file_key"].as_str().unwrap())
        .unwrap();
    let recipient = MasterKey::from_bytes(RECIPIENT_KEY);
    let opened = open_member_file_key(&recipient, &public_key(&owner()), FILE, &sealed).unwrap();
    assert_eq!(opened.as_bytes(), derive_file_key(&owner(), FILE.as_bytes()).as_bytes());
}

#[tokio::test]
async fn a_link_carries_owner_copies_its_owner_opens_and_no_expiry_unless_set() {
    let created = json!({"id": SHARE, "token": "echoed"}).to_string().into_bytes();
    let transport = ScriptedTransport::json(201, created.clone());
    transport.push_json(201, created);
    let client = signed_in(&transport);
    let in_two_days = LinkOptions {
        expires_in_hours: Some(48),
        ..LinkOptions::default()
    };

    let unset = client
        .create_share_link(APP, FILE, &LinkOptions::default())
        .await
        .unwrap();
    let set = client.create_share_link(APP, FILE, &in_two_days).await.unwrap();

    let owner = owner();
    assert_eq!(transport.request_count(), 2);
    for (index, (created, expires_in_hours)) in [(unset, None), (set, Some(48))].into_iter().enumerate() {
        let request = &transport.requests()[index];
        assert_eq!((request.method(), request.path()), (Method::Post, "/api/v1/shares"));
        let sent = body(&transport, index);
        assert_eq!(sent["file_id"], FILE);
        assert!(
            sent.get("passphrase").is_none() && sent["max_opens"].is_null(),
            "{sent}"
        );
        let rebuilt = assert_link_body(&sent, &owner, expires_in_hours);
        assert_eq!(created.share_id, SHARE);
        assert_eq!(rebuilt, *created.link);
    }
}

#[tokio::test]
async fn a_link_token_collision_is_retried_once_with_a_fresh_token() {
    let transport = ScriptedTransport::json(409, br#"{"error":"share token already exists"}"#.to_vec());
    transport.push_json(201, json!({"id": SHARE}).to_string().into_bytes());
    let client = signed_in(&transport);

    let created = client
        .create_share_link(APP, FILE, &LinkOptions::default())
        .await
        .unwrap();

    assert_eq!(transport.request_count(), 2);
    let (first, second) = (body(&transport, 0), body(&transport, 1));
    assert_ne!(first["token"], second["token"]);
    assert_eq!(first["wrapped_file_key"], second["wrapped_file_key"]);
    assert_eq!(assert_link_body(&second, &owner(), None), *created.link);
}

#[tokio::test]
async fn a_typed_refusal_reaches_the_flow_and_an_expired_session_does_not() {
    let transport = ScriptedTransport::json(409, br#"{"code":"plan_required"}"#.to_vec());
    transport.push_json(401, br#"{"error":"session_expired"}"#.to_vec());
    let client = signed_in(&transport);
    let mut events = client.events().subscribe();

    let refused = client
        .create_share_link(APP, FILE, &LinkOptions::default())
        .await
        .unwrap_err();
    assert!(
        matches!(
            refused,
            ShareServiceError::Flow(ShareFlowError::Refused("plan_required"))
        ),
        "{refused:?}"
    );
    assert!(events.try_recv().is_err(), "a refusal is not a session event");

    let expired = client
        .create_share_link(APP, FILE, &LinkOptions::default())
        .await
        .unwrap_err();
    assert!(
        matches!(&expired, ShareServiceError::Client(ClientError::Api(ApiError::Server(error))) if error.status == 401),
        "{expired:?}"
    );
    assert_eq!(events.try_recv().unwrap(), EngineEvent::SessionExpired);
    assert_eq!(transport.request_count(), 2);
}

#[tokio::test]
async fn an_account_mismatch_during_a_share_is_the_clients_and_never_retried() {
    let transport = ScriptedTransport::json(409, br#"{"error":"account_mismatch"}"#.to_vec());
    let client = signed_in(&transport);
    let mut events = client.events().subscribe();

    let error = client
        .create_share_link(APP, FILE, &LinkOptions::default())
        .await
        .unwrap_err();

    assert!(
        matches!(&error, ShareServiceError::Client(ClientError::Api(ApiError::Server(error))) if error.is_code("account_mismatch")),
        "{error:?}"
    );
    assert_eq!(events.try_recv().unwrap(), EngineEvent::AccountMismatch);
    assert_eq!(
        transport.request_count(),
        1,
        "an untyped 409 of the account is not a token collision"
    );
}

/// A confirm token as core's step-up mints it: a real OPAQUE exchange with a server that holds the
/// account's password file, then the server's `confirmation_token`.
fn minted_confirm_token(confirmation_token: &str) -> ConfirmToken {
    const ACCOUNT: &[u8] = b"person@example.test";
    const PASSWORD: &[u8] = b"correct horse battery staple 42";
    let server_setup = create_server_setup();
    let registration = client_registration_start(PASSWORD).unwrap();
    let registered = server_registration_start(&server_setup, &registration.message, ACCOUNT).unwrap();
    let upload = client_registration_finish(&registration.state, PASSWORD, &registered).unwrap();
    let password_file = server_registration_finish(&upload).unwrap();

    let (mut step_up, start) = StepUp::start(PASSWORD, StepUpPurpose::Generic).unwrap();
    let client_message = STANDARD
        .decode(start.body.as_ref().unwrap()["client_message"].as_str().unwrap())
        .unwrap();
    let login = server_login_start(&server_setup, &password_file, &client_message, ACCOUNT).unwrap();
    let started = HttpResponse::new(
        200,
        json!({"server_message": STANDARD.encode(login.message), "server_state": "server-state-1", "ksf_version": 1}),
    );
    let StepUpStep::Send(_finish) = step_up.on_response(started).unwrap() else {
        panic!("the step-up asked for no finish");
    };
    match step_up
        .on_response(HttpResponse::new(
            200,
            json!({ "confirmation_token": confirmation_token }),
        ))
        .unwrap()
    {
        StepUpStep::Confirmed(token) => token,
        StepUpStep::Send(_) => panic!("the step-up confirmed nothing"),
    }
}

#[tokio::test]
async fn a_confirm_token_on_a_flow_request_is_sent_in_its_header_and_never_printed() {
    let transport = ScriptedTransport::json(200, br#"{"message":"share revoked"}"#.to_vec());
    let client = signed_in(&transport);
    let gated = minted_confirm_token("confirm-token-secret").attach(revoke_link_request(SHARE).unwrap());

    let answer = client.execute_share_flow(gated, client.generation()).await.unwrap();

    assert_eq!(answer.status, 200);
    let sent = &transport.requests()[0];
    assert_eq!(sent.header("X-Confirm-Token"), Some("confirm-token-secret"));
    assert_eq!(sent.header("Authorization"), Some("Bearer token"));
    let printed = format!("{sent:?}");
    assert!(!printed.contains("confirm-token-secret"), "{printed}");
}

#[tokio::test]
async fn an_invite_names_its_recipient_by_email_and_seals_only_for_the_claimed_key() {
    let recipient_public = public_key(&MasterKey::from_bytes(RECIPIENT_KEY));
    let transport = ScriptedTransport::json(201, claimed(&recipient_public));
    transport.push_json(200, APPROVED.to_vec());
    let client = signed_in(&transport);

    let outcome = client
        .create_invite(FILE, " Bob@Example.test ", PeerKeyExpectation::NotCompared)
        .await
        .unwrap();

    let sent = body(&transport, 0);
    assert_eq!(
        sent,
        serde_json::json!({"file_id": FILE, "recipient_email": "bob@example.test"})
    );
    assert_eq!(
        outcome,
        InviteOutcome::Shared {
            invite_id: INVITE.into(),
            recipient_public_key: recipient_public,
        }
    );
    assert_eq!(
        transport.requests()[1].path(),
        format!("/api/v1/shares/invites/{INVITE}/approve")
    );
    assert_sealed_for_recipient(&body(&transport, 1));
}

#[tokio::test]
async fn an_invite_without_a_recipient_key_seals_nothing() {
    let transport = ScriptedTransport::json(
        201,
        json!({"invite_id": INVITE, "status": "pending"})
            .to_string()
            .into_bytes(),
    );
    let client = signed_in(&transport);

    let outcome = client
        .create_invite(FILE, "new@example.test", PeerKeyExpectation::NotCompared)
        .await
        .unwrap();

    assert_eq!(
        outcome,
        InviteOutcome::Invited {
            invite_id: INVITE.into(),
            status: "pending".into(),
        }
    );
    assert_eq!(transport.request_count(), 1);
}

#[tokio::test]
async fn a_trusted_invite_seals_only_for_the_presented_key() {
    let presented = public_key(&MasterKey::from_bytes(RECIPIENT_KEY));
    let swapped = public_key(&MasterKey::from_bytes([0x33; 32]));
    let transport = ScriptedTransport::json(201, claimed(&swapped));
    transport.push_json(201, claimed(&presented));
    transport.push_json(200, APPROVED.to_vec());
    let client = signed_in(&transport);
    let mut store = beebeeb_store::Store::open_in_memory().unwrap();

    let refused = client
        .create_trusted_invite(&mut store, FILE, "bob@example.test", CONTACT, &presented, 1)
        .await
        .unwrap();
    assert_eq!(
        refused,
        InviteOutcome::PeerKeyChanged {
            invite_id: INVITE.into(),
            recipient_public_key: swapped,
        }
    );
    assert_eq!(transport.request_count(), 1, "nothing sealed, no approval sent");
    assert_eq!(
        store.contact_key(CONTACT).unwrap().unwrap().public_key,
        presented,
        "the first key is remembered"
    );

    let shared = client
        .create_trusted_invite(&mut store, FILE, "bob@example.test", CONTACT, &presented, 2)
        .await
        .unwrap();
    assert_eq!(
        shared,
        InviteOutcome::Shared {
            invite_id: INVITE.into(),
            recipient_public_key: presented,
        }
    );
    assert_sealed_for_recipient(&body(&transport, 2));
}

#[tokio::test]
async fn a_trusted_invite_refuses_a_changed_contact_key_before_sending() {
    let remembered = public_key(&MasterKey::from_bytes(RECIPIENT_KEY));
    let presented = public_key(&MasterKey::from_bytes([0x33; 32]));
    let transport = ScriptedTransport::json(201, claimed(&presented));
    let client = signed_in(&transport);
    let mut store = beebeeb_store::Store::open_in_memory().unwrap();
    observe_contact_key(&mut store, CONTACT, &remembered, 1).unwrap();

    let error = client
        .create_trusted_invite(&mut store, FILE, "bob@example.test", CONTACT, &presented, 2)
        .await
        .unwrap_err();

    assert!(matches!(error, ShareServiceError::ContactKeyChanged), "{error:?}");
    assert_eq!(transport.request_count(), 0);
    assert_eq!(store.contact_key(CONTACT).unwrap().unwrap().public_key, remembered);
}

#[tokio::test]
async fn an_approval_seals_the_file_key_for_the_listed_key_and_only_that_key() {
    let recipient_public = public_key(&MasterKey::from_bytes(RECIPIENT_KEY));
    let transport = ScriptedTransport::json(200, APPROVED.to_vec());
    transport.push_json(
        400,
        br#"{"error":"invite must be in 'claimed' state to approve, currently 'approved'"}"#.to_vec(),
    );
    let client = signed_in(&transport);
    let listed = STANDARD.encode(recipient_public);

    let sealed_for = client
        .approve_invite(INVITE, FILE, &listed, PeerKeyExpectation::NotCompared)
        .await
        .unwrap();
    assert_eq!(sealed_for, recipient_public);
    assert_eq!(
        transport.requests()[0].path(),
        format!("/api/v1/shares/invites/{INVITE}/approve")
    );
    assert_sealed_for_recipient(&body(&transport, 0));

    let refused = client
        .approve_invite(INVITE, FILE, &listed, PeerKeyExpectation::NotCompared)
        .await
        .unwrap_err();
    assert!(
        matches!(refused, ShareServiceError::Flow(ShareFlowError::Server { status: 400 })),
        "{refused:?}"
    );

    let other = key_fingerprint(&public_key(&MasterKey::from_bytes([0x33; 32]))).unwrap();
    let changed = client
        .approve_invite(INVITE, FILE, &listed, PeerKeyExpectation::Compared(other))
        .await
        .unwrap_err();
    assert!(
        matches!(changed, ShareServiceError::Flow(ShareFlowError::PeerKeyChanged)),
        "{changed:?}"
    );
    assert_eq!(transport.request_count(), 2, "nothing is sent for a changed key");
}

#[tokio::test]
async fn a_foreign_item_is_refused_before_anything_is_sent() {
    let transport = ScriptedTransport::json(201, json!({"id": SHARE}).to_string().into_bytes());
    let client = signed_in(&transport);
    let listed = STANDARD.encode(public_key(&MasterKey::from_bytes(RECIPIENT_KEY)));

    let link = client
        .create_share_link(APP, FOREIGN, &LinkOptions::default())
        .await
        .unwrap_err();
    let invite = client
        .create_invite(FOREIGN, "bob@example.test", PeerKeyExpectation::NotCompared)
        .await
        .unwrap_err();
    let approval = client
        .approve_invite(INVITE, FOREIGN, &listed, PeerKeyExpectation::NotCompared)
        .await
        .unwrap_err();

    for error in [link, invite, approval] {
        assert!(matches!(error, ShareServiceError::KeyUnavailable), "{error:?}");
    }
    assert_eq!(transport.request_count(), 0);
}

/// A server for one folder link: no custody record yet and no invite, one child, and the create
/// answered under the share id the flow proposed. Every request and custody mark goes in `log`.
fn folder_link_server(log: Arc<Mutex<Vec<String>>>) -> RoutedTransport {
    let route = Arc::new(move |request: &Request| -> Option<RouteAnswer> {
        log.lock()
            .unwrap()
            .push(format!("{:?} {}", request.method(), request.path()));
        let answer = match (request.method(), request.path()) {
            (Method::Get, path) if path == format!("/api/v1/shared-folders/{FOLDER}") => {
                json_answer(404, &[], br#"{"error":"not_found"}"#.to_vec())
            }
            (Method::Get, "/api/v1/shares/invites/sent") => json_answer(200, &[], br#"{"invites":[]}"#.to_vec()),
            (Method::Put, path) if path == format!("/api/v1/shared-folders/{FOLDER}/key") => {
                json_answer(200, &[], br#"{"key_version":1}"#.to_vec())
            }
            (Method::Get, path) if path.starts_with("/api/v1/files?parent_id=") => json_answer(
                200,
                &[],
                json!({"files": [{"id": CHILD, "is_folder": false}]})
                    .to_string()
                    .into_bytes(),
            ),
            (Method::Post, "/api/v1/shares/folder-links") => {
                let sent: Value = serde_json::from_slice(request.body()).unwrap();
                json_answer(
                    201,
                    &[],
                    json!({"id": sent["id"], "folder_id": FOLDER, "access_level": "view", "key_version": 1})
                        .to_string()
                        .into_bytes(),
                )
            }
            _ => return None,
        };
        Some(Ok(answer))
    });
    RoutedTransport::new(route, ScriptedTransport::json(500, Vec::new()))
}

fn folder_link_input() -> FolderLinkInput<'static> {
    FolderLinkInput {
        folder_id: FOLDER,
        app_url: APP,
        access_level: "view",
        label: None,
        expires_in_hours: None,
        cap_bytes: None,
        max_opens: None,
        passphrase: None,
        custody: CustodyMemory::default(),
    }
}

#[tokio::test]
async fn a_folder_link_carries_the_subtree_wraps_and_no_expiry_unless_set() {
    let log = Arc::new(Mutex::new(Vec::new()));
    let server = folder_link_server(log.clone());
    let client = signed_in_with(Arc::new(server.clone()));

    let created = client
        .create_folder_link(folder_link_input(), |folder_id| {
            log.lock().unwrap().push(format!("custody seen {folder_id}"));
            Ok(())
        })
        .await
        .unwrap();

    assert_eq!(
        *log.lock().unwrap(),
        [
            format!("Get /api/v1/shared-folders/{FOLDER}"),
            "Get /api/v1/shares/invites/sent".to_owned(),
            format!("Put /api/v1/shared-folders/{FOLDER}/key"),
            format!("custody seen {FOLDER}"),
            format!("Get /api/v1/files?parent_id={FOLDER}&limit=500"),
            "Post /api/v1/shares/folder-links".to_owned(),
        ],
        "the custody record is noted before the requests that use its key"
    );
    let routed = server.routed();
    let sent: Value = serde_json::from_slice(routed[routed.len() - 1].body()).unwrap();
    assert!(sent.get("expires_in_hours").is_none(), "{sent}");
    assert_eq!(sent["format"], "l7");
    assert!(sent["folder_keys"].as_array().is_some_and(|keys| !keys.is_empty()));
    let wrapped: Vec<&str> = sent["folder_keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["file_id"].as_str().unwrap())
        .collect();
    assert_eq!(wrapped, [FOLDER, CHILD], "the root's name key and every descendant");
    assert_eq!(sent["access_level"], "view");
    let rebuilt = rebuild_folder_link(
        APP,
        &owner(),
        &created.share_id,
        sent["owner_wrapped_key"].as_str(),
        sent["owner_wrapped_token"].as_str(),
        sent["wrapped_folder_key"].as_str(),
        false,
    )
    .expect("the owner rebuilds the folder link from the copies the body carried");
    assert_eq!(*rebuilt, *created.link);
    assert_eq!(sent["id"], created.share_id.as_str());
}

#[tokio::test]
async fn a_folder_link_carries_its_expiry_when_one_is_set() {
    let server = folder_link_server(Arc::new(Mutex::new(Vec::new())));
    let client = signed_in_with(Arc::new(server.clone()));
    let in_a_day = FolderLinkInput {
        expires_in_hours: Some(24),
        ..folder_link_input()
    };

    client.create_folder_link(in_a_day, |_| Ok(())).await.unwrap();

    let routed = server.routed();
    let sent: Value = serde_json::from_slice(routed[routed.len() - 1].body()).unwrap();
    assert_eq!(routed[routed.len() - 1].path(), "/api/v1/shares/folder-links");
    assert_eq!(sent["expires_in_hours"], 24);
}

#[tokio::test]
async fn a_folder_link_stops_unsent_when_its_custody_cannot_be_recorded() {
    let log = Arc::new(Mutex::new(Vec::new()));
    let client = signed_in_with(Arc::new(folder_link_server(log.clone())));

    let error = client
        .create_folder_link(folder_link_input(), |_| Err(ShareServiceError::CustodyNotRecorded))
        .await
        .unwrap_err();

    assert!(matches!(error, ShareServiceError::CustodyNotRecorded), "{error:?}");
    assert_eq!(
        log.lock().unwrap().last().map(String::as_str),
        Some(format!("Put /api/v1/shared-folders/{FOLDER}/key").as_str()),
        "no request uses the folder's key"
    );
}
