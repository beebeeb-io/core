use super::*;

#[tokio::test]
async fn recovery_holder_token_is_bearer_and_ready_at_blocks_completion() {
    let transport = Arc::new(ScriptedTransport::json(
        200,
        br#"{"status":"pending","ready_at":"2099-01-01T00:00:00Z","expires_at":"2099-01-08T00:00:00Z"}"#.to_vec(),
    ));
    let client = Client::new(ClientConfig::for_tests(), transport.clone()).unwrap();
    let mut attempt =
        crate::auth::RecoveryAttempt::from_parts_for_test("recovery-id", "holder-secret", None, RecoveryState::Pending);

    assert_eq!(
        client.recovery_status(&mut attempt).await.unwrap(),
        RecoveryState::Pending
    );
    let status_request = transport.requests().pop().unwrap();
    assert_eq!(status_request.header("Authorization"), Some("Bearer holder-secret"));
    assert_eq!(status_request.header("X-Beebeeb-Expected-User"), None);

    let request_count = transport.request_count();
    assert!(matches!(
        client
            .complete_recovery(
                &attempt,
                "person@example.test",
                RecoveryChanges {
                    new_email: Some("new@example.test".into()),
                    ..RecoveryChanges::default()
                },
            )
            .await,
        Err(AuthError::RecoveryWaiting { .. })
    ));
    assert_eq!(transport.request_count(), request_count);

    let cancel = RecoveryCancelToken::from_alert("recovery-id", Zeroizing::new("cancel-secret".into())).unwrap();
    assert!(!format!("{cancel:?}").contains("cancel-secret"));
    transport.push_json(200, br#"{"ok":true}"#.to_vec());
    client.cancel_recovery_with_token(cancel).await.unwrap();
    let cancel_request = transport.requests().pop().unwrap();
    let body: serde_json::Value = serde_json::from_slice(cancel_request.body()).unwrap();
    assert_eq!(body["cancel_token"], "cancel-secret");
    assert_eq!(cancel_request.header("Authorization"), None);
}

#[tokio::test]
async fn a_device_clock_behind_the_server_does_not_block_a_ready_recovery() {
    let transport = Arc::new(ScriptedTransport::json(
        200,
        br#"{"status":"ready","ready_at":"2099-01-01T00:00:00Z","expires_at":"2099-01-08T00:00:00Z"}"#.to_vec(),
    ));
    transport.push_json(
        200,
        br#"{"session_token":"session-token","user_id":"account-id","key_state":"proven"}"#.to_vec(),
    );
    let client = Client::new(ClientConfig::for_tests(), transport.clone()).unwrap();
    let mut attempt =
        crate::auth::RecoveryAttempt::from_parts_for_test("recovery-id", "holder-secret", None, RecoveryState::Pending);

    assert_eq!(
        client.recovery_status(&mut attempt).await.unwrap(),
        RecoveryState::Ready
    );
    assert!(
        !attempt.waits(),
        "the server said ready, so the device must not show a wait"
    );
    client
        .complete_recovery(
            &attempt,
            "person@example.test",
            RecoveryChanges {
                remove_authenticator: true,
                ..RecoveryChanges::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(transport.request_count(), 2);
}

#[tokio::test]
async fn a_device_clock_ahead_of_the_server_does_not_end_the_recovery_wait() {
    let transport = Arc::new(ScriptedTransport::json(
        200,
        br#"{"status":"pending","ready_at":"2000-01-01T00:00:00Z","expires_at":"2099-01-08T00:00:00Z"}"#.to_vec(),
    ));
    let client = Client::new(ClientConfig::for_tests(), transport.clone()).unwrap();
    let mut attempt =
        crate::auth::RecoveryAttempt::from_parts_for_test("recovery-id", "holder-secret", None, RecoveryState::Pending);

    assert_eq!(
        client.recovery_status(&mut attempt).await.unwrap(),
        RecoveryState::Pending
    );
    assert!(
        attempt.waits(),
        "the server said pending, so the device must show the wait"
    );
    let requests = transport.request_count();
    assert!(matches!(
        client
            .complete_recovery(
                &attempt,
                "person@example.test",
                RecoveryChanges {
                    remove_authenticator: true,
                    ..RecoveryChanges::default()
                },
            )
            .await,
        Err(AuthError::RecoveryWaiting { .. })
    ));
    assert_eq!(transport.request_count(), requests);
}

#[tokio::test]
async fn recovery_completion_uses_holder_bearer_not_a_body_token() {
    let transport = Arc::new(ScriptedTransport::json(
        200,
        br#"{"session_token":"session-token-secret","user_id":"account-id","key_state":"proven"}"#.to_vec(),
    ));
    let client = Client::new(ClientConfig::for_tests(), transport.clone()).unwrap();
    let attempt =
        crate::auth::RecoveryAttempt::from_parts_for_test("recovery-id", "holder-secret", None, RecoveryState::Ready);

    let recovered = client
        .complete_recovery(
            &attempt,
            "person@example.test",
            RecoveryChanges {
                remove_authenticator: true,
                ..RecoveryChanges::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(recovered.owner(), "account-id");
    assert!(!format!("{recovered:?}").contains("session-token-secret"));

    let store = crate::MemorySecretStore::default();
    assert!(
        client
            .install_recovered_session(
                &recovered,
                MasterKey::from_bytes([0x5a; 32]),
                "http://not-loopback.example.test",
                &store,
            )
            .is_err()
    );
    session("account-a", "token-a", 1).save(&store, "test-app").unwrap();
    assert!(matches!(
        client.install_recovered_session(
            &recovered,
            MasterKey::from_bytes([0x5a; 32]),
            "http://localhost:8080",
            &store,
        ),
        Err(AuthError::AnotherAccountOnDevice)
    ));
    assert!(
        Session::load_for_user(&store, "account-a", "test-app")
            .unwrap()
            .is_some()
    );
    let installed = client
        .install_recovered_session_replacing_account(
            &recovered,
            MasterKey::from_bytes([0x5a; 32]),
            "http://localhost:8080",
            &store,
            crate::auth::AccountReplacement::authorized(),
        )
        .unwrap();
    assert_eq!(installed.owner(), "account-id");
    assert_eq!(
        Session::load_for_user(&store, "account-id", "test-app")
            .unwrap()
            .unwrap()
            .owner(),
        "account-id"
    );

    let ownerless = crate::MemorySecretStore::default();
    ownerless.set("session.master_key", &[1; 32]).unwrap();
    assert!(
        client
            .install_recovered_session_replacing_account(
                &recovered,
                MasterKey::from_bytes([0x5a; 32]),
                "http://localhost:8080",
                &ownerless,
                crate::auth::AccountReplacement::authorized(),
            )
            .is_ok()
    );

    let request = transport.requests().pop().unwrap();
    assert_eq!(request.header("Authorization"), Some("Bearer holder-secret"));
    assert_eq!(request.header("X-Beebeeb-Expected-User"), None);
    let body: serde_json::Value = serde_json::from_slice(request.body()).unwrap();
    assert!(body.get("recovery_token").is_none());
}

#[tokio::test]
async fn recovery_authenticator_replacement_matches_the_server_payload() {
    let transport = Arc::new(ScriptedTransport::json(
        200,
        br#"{"session_token":"session-token-secret","user_id":"account-id","key_state":"proven"}"#.to_vec(),
    ));
    let client = Client::new(ClientConfig::for_tests(), transport.clone()).unwrap();
    let attempt =
        crate::auth::RecoveryAttempt::from_parts_for_test("recovery-id", "holder-secret", None, RecoveryState::Ready);
    let replacement = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";

    client
        .complete_recovery(
            &attempt,
            "person@example.test",
            RecoveryChanges {
                new_authenticator: Some(Zeroizing::new(replacement.into())),
                authenticator_code: Some(Zeroizing::new("123456".into())),
                ..RecoveryChanges::default()
            },
        )
        .await
        .unwrap();

    let request = transport.requests().pop().unwrap();
    let body: serde_json::Value = serde_json::from_slice(request.body()).unwrap();
    assert_eq!(body["authenticator"]["action"], "replace");
    assert_eq!(body["authenticator"]["secret"], replacement);
    assert_eq!(body["authenticator"]["code"], "123456");
    assert!(body.get("opaque_registration").is_none() || body["opaque_registration"].is_null());
}

/// The server reports an attempt whose completion window has passed as
/// `expired`: a state of its own, never a malformed answer, and nothing is sent
/// to complete it.
#[tokio::test]
async fn an_expired_recovery_is_reported_as_expired_and_cannot_complete() {
    let transport = Arc::new(ScriptedTransport::json(
        200,
        br#"{"status":"expired","ready_at":"2000-01-01T00:00:00Z","expires_at":"2000-01-08T00:00:00Z"}"#.to_vec(),
    ));
    let client = Client::new(ClientConfig::for_tests(), transport.clone()).unwrap();
    let mut attempt =
        crate::auth::RecoveryAttempt::from_parts_for_test("recovery-id", "holder-secret", None, RecoveryState::Pending);

    let state = client.recovery_status(&mut attempt).await;

    assert!(matches!(state, Ok(RecoveryState::Expired)), "{state:?}");
    assert!(!attempt.waits());
    let requests = transport.request_count();
    assert!(matches!(
        client
            .complete_recovery(
                &attempt,
                "person@example.test",
                RecoveryChanges {
                    remove_authenticator: true,
                    ..RecoveryChanges::default()
                },
            )
            .await,
        Err(AuthError::RecoveryNotReady)
    ));
    assert_eq!(transport.request_count(), requests);
}
