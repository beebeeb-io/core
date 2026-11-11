use beebeeb_api::{ClientIdentity, Method, RequestBuilder, proposed};
use beebeeb_core::system_folders::Service;

fn builder() -> RequestBuilder {
    RequestBuilder::new(ClientIdentity::new("test", "1")).with_auth("token", "account")
}

#[test]
fn proposed_routes_match_the_contract() {
    let routes = [
        (
            proposed::start_device_link().method(),
            proposed::start_device_link().path().to_owned(),
        ),
        (
            proposed::pending_device_links().method(),
            proposed::pending_device_links().path().to_owned(),
        ),
        (
            proposed::get_device_link("link").method(),
            proposed::get_device_link("link").path().to_owned(),
        ),
        (
            proposed::approve_device_link("link").method(),
            proposed::approve_device_link("link").path().to_owned(),
        ),
        (
            proposed::deny_device_link("link").method(),
            proposed::deny_device_link("link").path().to_owned(),
        ),
        (
            proposed::device_link_result("link").method(),
            proposed::device_link_result("link").path().to_owned(),
        ),
        (
            proposed::ack_device_link("link").method(),
            proposed::ack_device_link("link").path().to_owned(),
        ),
        (
            proposed::send_device_link_pake("link").method(),
            proposed::send_device_link_pake("link").path().to_owned(),
        ),
        (
            proposed::get_device_link_pake_for_role("link", proposed::DeviceLinkRole::NewDevice).method(),
            proposed::get_device_link_pake_for_role("link", proposed::DeviceLinkRole::NewDevice)
                .path()
                .to_owned(),
        ),
    ];
    assert_eq!(routes[0], (Method::Post, "/api/v1/devices/link/start".into()));
    assert_eq!(routes[1], (Method::Get, "/api/v1/devices/links/pending".into()));
    assert_eq!(
        routes[8],
        (Method::Get, "/api/v1/devices/link/link/pake?role=new_device".into())
    );
}

#[test]
fn device_link_bodies_never_send_the_code() {
    let start = proposed::start_device_link()
        .build(
            &builder(),
            &proposed::DeviceLinkStart {
                session_id: "session".into(),
                public_key: "public".into(),
                device_name: "phone".into(),
                hardware_id: None,
            },
        )
        .unwrap();
    let approval = proposed::approve_device_link("link")
        .build(
            &builder(),
            &proposed::DeviceLinkApproval {
                approver_public: Some("public".into()),
                nonce: "nonce".into(),
                ciphertext: "ciphertext".into(),
            },
        )
        .unwrap();
    for body in [start.body(), approval.body()] {
        let text = std::str::from_utf8(body).unwrap();
        assert!(!text.contains("typed_code"));
        assert!(!text.contains("code_commit"));
    }

    let typed_approval = proposed::approve_device_link("link")
        .build(
            &builder(),
            &proposed::DeviceLinkApproval {
                approver_public: None,
                nonce: "nonce".into(),
                ciphertext: "ciphertext".into(),
            },
        )
        .unwrap();
    let typed_json: serde_json::Value = serde_json::from_slice(typed_approval.body()).unwrap();
    assert!(typed_json.get("approver_public").is_none());
}

#[test]
fn recovery_uses_password_proven_token_and_answered_challenge() {
    let request = proposed::start_recovery()
        .build(
            &RequestBuilder::new(ClientIdentity::new("test", "1")),
            &proposed::RecoveryStart {
                email: "person@example.test".into(),
                challenge_id: "challenge".into(),
                response: "response".into(),
                password_proven: Some("single-use".into()),
            },
        )
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(request.body()).unwrap();
    assert_eq!(json["password_proven"], "single-use");
    assert!(json.get("has_password_proof").is_none());
}

#[test]
fn recovery_holder_routes_use_bearer_without_expected_user_or_body_token() {
    let holder = RequestBuilder::new(ClientIdentity::new("test", "1")).with_bearer("holder-token");
    let status = proposed::recovery_status("r").build(&holder, &()).unwrap();
    assert_eq!(status.header("Authorization"), Some("Bearer holder-token"));
    assert_eq!(status.header("X-Beebeeb-Expected-User"), None);

    let complete = proposed::complete_recovery("r")
        .build(
            &holder,
            &proposed::RecoveryComplete {
                opaque_registration: None,
                new_email: Some("new@example.test".into()),
                email_verification_code: None,
                authenticator: None,
            },
        )
        .unwrap();
    assert_eq!(complete.header("Authorization"), Some("Bearer holder-token"));
    let json: serde_json::Value = serde_json::from_slice(complete.body()).unwrap();
    assert!(json.get("recovery_token").is_none());

    let status = proposed::start_recovery()
        .parse(beebeeb_api::Answer::new(
            200,
            vec![],
            br#"{"id":"r","status":"pending","ready_at":"2026-11-03T12:00:00Z","recovery_token":"holder-token"}"#
                .to_vec(),
        ))
        .unwrap();
    assert!(!format!("{status:?}").contains("holder-token"));
}

#[test]
fn remaining_contract_routes_are_present() {
    assert_eq!(proposed::start_key_proof().path(), "/api/v1/auth/key-proof/start");
    assert_eq!(proposed::finish_key_proof().path(), "/api/v1/auth/key-proof/finish");
    assert_eq!(proposed::recovery_challenge().path(), "/api/v1/recovery/challenge");
    assert_eq!(proposed::recovery_status("r").path(), "/api/v1/recovery/r");
    assert_eq!(proposed::complete_recovery("r").path(), "/api/v1/recovery/r/complete");
    assert_eq!(
        proposed::enable_service(Service::MailBackup).path(),
        "/api/v1/services/mail_backup/enable"
    );
    assert_eq!(
        proposed::disable_service(Service::MailBackup).path(),
        "/api/v1/services/mail_backup/disable"
    );
    assert_eq!(proposed::complete_snapshot().path(), "/api/v1/sync/snapshot/complete");
    assert_eq!(proposed::mint_upload_token("u").path(), "/api/v1/uploads/u/token");
}

#[test]
fn email_code_wire_uses_the_server_challenge_and_ticket_shapes() {
    let public = RequestBuilder::new(ClientIdentity::new("test", "1"));
    let verify = proposed::submit_email_code()
        .build(
            &public,
            &proposed::EmailCodeSubmit {
                challenge: "challenge-token".into(),
                code: zeroize::Zeroizing::new("12345678".into()),
            },
        )
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(verify.body()).unwrap();
    assert_eq!(
        json,
        serde_json::json!({"challenge":"challenge-token","code":"12345678"})
    );

    let requested = proposed::request_email_code()
        .parse(beebeeb_api::Answer::new(
            202,
            vec![],
            br#"{"challenge":"challenge-token","expires_at":"2026-11-03T12:00:00Z","message":"sent"}"#.to_vec(),
        ))
        .unwrap();
    assert_eq!(requested.challenge, "challenge-token");
    let verified = proposed::submit_email_code()
        .parse(beebeeb_api::Answer::new(
            200,
            vec![],
            br#"{"email_code_ticket":"ticket","expires_in":600}"#.to_vec(),
        ))
        .unwrap();
    assert_eq!(verified.email_code_ticket, "ticket");
}

#[test]
fn key_proof_and_recovery_shapes_are_distinct() {
    let proof = proposed::start_key_proof()
        .parse(beebeeb_api::Answer::new(
            200,
            vec![],
            br#"{"session_id":"11111111-2222-4333-8444-555555555555","account_id":"aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee","nonce":"AA","server_public_key":"BB","expires_in_seconds":60}"#.to_vec(),
        ))
        .unwrap();
    assert_eq!(proof.server_public_key, "BB");
    assert_eq!(proof.session_id, "11111111-2222-4333-8444-555555555555");
    assert_eq!(proof.account_id, "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee");

    let recovery = proposed::recovery_challenge()
        .parse(beebeeb_api::Answer::new(
            200,
            vec![],
            br#"{"challenge_id":"id","nonce":"AA==","server_public":"BB==","canonical_email":"person@example.test","expires_at":"2026-11-03T12:00:00Z"}"#
                .to_vec(),
        ))
        .unwrap();
    assert_eq!(recovery.challenge_id, "id");
    assert_eq!(recovery.canonical_email, "person@example.test");

    let finish = proposed::finish_key_proof()
        .build(
            &builder(),
            &proposed::KeyProofAnswer {
                response: "tag".into(),
                email_code_ticket: Some("mail-ticket".into()),
            },
        )
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(finish.body()).unwrap();
    assert_eq!(
        json,
        serde_json::json!({"response":"tag","email_code_ticket":"mail-ticket"})
    );
}

#[test]
fn recovery_completion_and_password_proof_match_round_four() {
    let completed = proposed::complete_recovery("r")
        .parse(beebeeb_api::Answer::new(
            200,
            vec![],
            br#"{"session_token":"secret","user_id":"aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee","key_state":"proven"}"#
                .to_vec(),
        ))
        .unwrap();
    assert_eq!(
        completed.user_id.as_deref(),
        Some("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee")
    );
    assert!(!format!("{completed:?}").contains("secret"));

    let request = beebeeb_api::routes::auth::opaque_finish()
        .build(
            &RequestBuilder::new(ClientIdentity::new("test", "1")),
            &beebeeb_api::routes::auth::OpaqueFinishRequest {
                email: "person@example.test".into(),
                client_message: "message".into(),
                server_state: "state".into(),
                hardware_id: None,
                hardware_identity_secret: None,
                request_password_proof: true,
            },
        )
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(request.body()).unwrap();
    assert_eq!(json["request_password_proof"], true);

    let proof = beebeeb_api::routes::auth::opaque_finish()
        .parse(beebeeb_api::Answer::new(
            200,
            vec![],
            br#"{"password_proven":"one-use","expires_in_seconds":600}"#.to_vec(),
        ))
        .unwrap();
    assert_eq!(proof.expires_in_seconds, Some(600));
    assert!(!format!("{proof:?}").contains("one-use"));
}

#[test]
fn device_link_exposes_the_client_session_identifier() {
    let session_id = "ERERESIiQzOERFVVVVVVVQ==";
    let pending = proposed::pending_device_links()
        .parse(beebeeb_api::Answer::new(
            200,
            vec![],
            format!(
                r#"{{"links":[{{"id":"route","session_id":"{session_id}","device_name":"phone","reported_by_device":true,"created_at":"2026-11-03T12:00:00Z","expires_at":"2026-11-03T12:10:00Z"}}]}}"#
            )
            .into_bytes(),
        ))
        .unwrap();
    assert_eq!(pending.links[0].session_id, session_id);

    let detail = proposed::get_device_link("route")
        .parse(beebeeb_api::Answer::new(
            200,
            vec![],
            format!(
                r#"{{"id":"route","session_id":"{session_id}","public_key":"public","device_name":"phone","reported_by_device":true,"status":"pending","expires_at":"2026-11-03T12:10:00Z"}}"#
            )
            .into_bytes(),
        ))
        .unwrap();
    assert_eq!(detail.session_id, session_id);
}

#[test]
fn service_and_upload_token_shapes_match_the_server() {
    let enable = proposed::enable_service(Service::MailBackup)
        .build(
            &builder(),
            &proposed::ServiceEnable {
                folder_id: "11111111-2222-4333-8444-555555555555".into(),
                name_encrypted: "sealed".into(),
            },
        )
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(enable.body()).unwrap();
    assert_eq!(json["folder_id"], "11111111-2222-4333-8444-555555555555");
    // LD-0113: a system folder is always at the top level; the server
    // answers 400 to a parent, so the request never carries one.
    assert_eq!(
        json.as_object().unwrap().keys().collect::<Vec<_>>(),
        ["folder_id", "name_encrypted"]
    );

    let disabled = proposed::disable_service(Service::MailBackup)
        .parse(beebeeb_api::Answer::new(
            200,
            vec![],
            br#"{"service":"mail_backup","enabled":false,"folder_id":null}"#.to_vec(),
        ))
        .unwrap();
    assert!(!disabled.enabled);

    let token = proposed::mint_upload_token("11111111-2222-4333-8444-555555555555")
        .parse(beebeeb_api::Answer::new(
            200,
            vec![],
            br#"{"token":"bb_upl_secret","upload_session_id":"11111111-2222-4333-8444-555555555555","expires_at":"2026-11-03T12:00:00Z"}"#.to_vec(),
        ))
        .unwrap();
    assert_eq!(token.upload_session_id, "11111111-2222-4333-8444-555555555555");
    assert!(!format!("{token:?}").contains("bb_upl_secret"));
}
