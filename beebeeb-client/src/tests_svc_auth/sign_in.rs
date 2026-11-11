use super::*;

struct TestPasskeyPrompt {
    credential_id: String,
    prf_output: Vec<u8>,
}

impl PasskeyPrompt for TestPasskeyPrompt {
    fn create<'a>(&'a self) -> PasskeyPromptFuture<'a> {
        Box::pin(async { Err(PasskeyPromptError) })
    }

    fn authenticate<'a>(&'a self) -> PasskeyPromptFuture<'a> {
        Box::pin(async {
            Ok(PasskeyPromptOutput {
                credential_id: self.credential_id.clone(),
                prf_output: Zeroizing::new(self.prf_output.clone()),
            })
        })
    }
}

#[tokio::test]
async fn session_key_proof_binds_server_uuid_bytes() {
    let master_key = MasterKey::from_bytes([0x41; 32]);
    let (challenge, verifier) = create_challenge().unwrap();
    let session_id = uuid::Uuid::new_v4();
    let account_id = uuid::Uuid::new_v4();
    let transport = Arc::new(ScriptedTransport::json(
        200,
        serde_json::to_vec(&serde_json::json!({
            "session_id": session_id,
            "account_id": account_id,
            "nonce": STANDARD_NO_PAD.encode(challenge.nonce()),
            "server_public_key": STANDARD_NO_PAD.encode(challenge.server_public()),
            "expires_in_seconds": 60,
        }))
        .unwrap(),
    ));
    transport.push_json(200, br#"{"key_state":"proven"}"#.to_vec());
    let client = Client::new(ClientConfig::for_tests(), transport.clone()).unwrap();
    client
        .set_authentication("session-token", account_id.to_string())
        .unwrap();

    client.prove_session_key(&master_key).await.unwrap();

    let requests = transport.requests();
    let body: serde_json::Value = serde_json::from_slice(requests[1].body()).unwrap();
    let tag: [u8; 32] = STANDARD_NO_PAD
        .decode(body["response"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let account_public = derive_x25519_public(&derive_x25519_private(&master_key));
    verifier
        .verify(
            &account_public,
            KeyProofBinding::Session {
                session_id: session_id.as_bytes(),
                account_id: account_id.as_bytes(),
            },
            &KeyProofResponse::from_bytes(tag),
        )
        .unwrap();
}

#[tokio::test]
async fn malformed_key_proof_names_the_safe_step_and_field() {
    let (challenge, _) = create_challenge().unwrap();
    let transport = Arc::new(ScriptedTransport::json(
        200,
        serde_json::to_vec(&serde_json::json!({
            "session_id": "not-a-uuid",
            "account_id": uuid::Uuid::new_v4(),
            "nonce": STANDARD_NO_PAD.encode(challenge.nonce()),
            "server_public_key": STANDARD_NO_PAD.encode(challenge.server_public()),
            "expires_in_seconds": 60,
        }))
        .unwrap(),
    ));
    let client = Client::new(ClientConfig::for_tests(), transport).unwrap();
    client.set_authentication("session-token", "account").unwrap();

    let error = client
        .prove_session_key(&MasterKey::from_bytes([0x42; 32]))
        .await
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        "key-proof start: invalid session_id in the server answer"
    );
}

#[tokio::test]
async fn server_proven_session_still_proves_the_local_key_before_installing() {
    let master_key = MasterKey::from_bytes([0x51; 32]);
    let (challenge, _) = create_challenge().unwrap();
    let session_id = uuid::Uuid::new_v4();
    let account_id = uuid::Uuid::new_v4();
    let transport = Arc::new(ScriptedTransport::json(
        200,
        serde_json::to_vec(&serde_json::json!({
            "session_id": session_id,
            "account_id": account_id,
            "nonce": STANDARD_NO_PAD.encode(challenge.nonce()),
            "server_public_key": STANDARD_NO_PAD.encode(challenge.server_public()),
            "expires_in_seconds": 60,
        }))
        .unwrap(),
    ));
    transport.push_json(
        200,
        br#"{"key_state":"proven","hardware_identity_secret":"issued-after-proof"}"#.to_vec(),
    );
    transport.push_json(
        200,
        br#"{"id":"device-id","client_key":null,"hostname_encrypted":null,"hostname":"","platform":"macos","bb_version":"1","last_seen":"2026-11-04T12:00:00Z","created_at":"2026-11-04T12:00:00Z","hardware_id":"00000000-0000-4000-8000-000000000001","reported_name":"test-client","reported_by_device":true,"holds_key":true}"#.to_vec(),
    );
    let client = Client::new(ClientConfig::for_tests(), transport.clone()).unwrap();
    let store = crate::MemorySecretStore::default();
    let hardware_id = crate::session::HardwareIdentity::load_or_create(&store)
        .unwrap()
        .id()
        .to_owned();
    let accepted = PasswordAccepted {
        session_token: Zeroizing::new("session-token".into()),
        canonical_email: "person@example.test".into(),
        owner: account_id.to_string(),
        key_state: SessionKeyState::Proven,
        legacy_upgrade_required: false,
        factor_satisfied: false,
        email_code_satisfied: false,
        authenticator_required: false,
        hardware_id: Some(hardware_id),
        hardware_identity_secret: None,
    };
    let mut unlock = NewDeviceUnlock::recovery(accepted).unwrap();
    unlock
        .provide_email_code_ticket(beebeeb_api::proposed::EmailCodeTicket {
            email_code_ticket: "mail-ticket".into(),
            expires_in: 600,
        })
        .unwrap();
    unlock.provide_recovery_key(master_key).unwrap();
    let ready = unlock.into_ready().unwrap();
    client
        .install_new_device(ready, "http://localhost:8080", &store)
        .await
        .unwrap();

    assert_eq!(
        transport.request_count(),
        3,
        "installed session did not prove and report its device"
    );
    let requests = transport.requests();
    assert_eq!(requests[2].path(), "/api/v1/clients/devices");
    let proof_finish: serde_json::Value = serde_json::from_slice(requests[1].body()).unwrap();
    assert_eq!(proof_finish["email_code_ticket"], "mail-ticket");
    let report: serde_json::Value = serde_json::from_slice(requests[2].body()).unwrap();
    uuid::Uuid::parse_str(report["hardware_id"].as_str().unwrap()).unwrap();
    assert_eq!(
        report["client_key"], report["hardware_id"],
        "without its own key, a device shares one entry with others on its platform"
    );
    assert_eq!(report["reported_name"], "test-client");
    assert!(
        Session::load_for_user(&store, &account_id.to_string(), "test-app")
            .unwrap()
            .is_some()
    );
    assert_eq!(
        crate::session::HardwareIdentity::load_or_create(&store)
            .unwrap()
            .secret(),
        Some("issued-after-proof")
    );
}

#[tokio::test]
async fn known_device_mismatch_returns_typed_choice_without_purging_the_key() {
    let store = crate::MemorySecretStore::default();
    session("account-a", "token-a", 1).save(&store, "test-app").unwrap();
    let client = Client::new(
        ClientConfig::for_tests(),
        Arc::new(ScriptedTransport::json(500, Vec::new())),
    )
    .unwrap();
    let accepted = PasswordAccepted {
        session_token: Zeroizing::new("token-b".into()),
        canonical_email: "b@example.test".into(),
        owner: "account-b".into(),
        key_state: SessionKeyState::Locked,
        legacy_upgrade_required: false,
        factor_satisfied: false,
        email_code_satisfied: false,
        authenticator_required: false,
        hardware_id: None,
        hardware_identity_secret: None,
    };

    assert!(matches!(
        client.unlock_known_device(accepted, &store).await,
        Err(AuthError::AnotherAccountOnDevice)
    ));
    assert!(
        Session::load_for_user(&store, "account-a", "test-app")
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn passkey_fetch_uses_the_locked_password_session() {
    let account_id = uuid::Uuid::new_v4().to_string();
    let credential_id = "credential-id";
    let prf_output = vec![0x44; 32];
    let master_key = MasterKey::from_bytes([0x33; 32]);
    let sealed = beebeeb_core::passkey_seal::seal_master_key(
        &master_key,
        &prf_output,
        account_id.as_bytes(),
        credential_id.as_bytes(),
    )
    .unwrap();
    let transport = Arc::new(ScriptedTransport::json(
        200,
        serde_json::to_vec(&serde_json::json!({
            "credential_id": credential_id,
            "encrypted_vault_key": STANDARD.encode(sealed.to_bytes()),
        }))
        .unwrap(),
    ));
    let client = Client::new(ClientConfig::for_tests(), transport.clone()).unwrap();
    let accepted = PasswordAccepted {
        session_token: Zeroizing::new("locked-token".into()),
        canonical_email: "person@example.test".into(),
        owner: account_id,
        key_state: SessionKeyState::Locked,
        legacy_upgrade_required: false,
        factor_satisfied: false,
        email_code_satisfied: false,
        authenticator_required: false,
        hardware_id: None,
        hardware_identity_secret: None,
    };
    let prompt = TestPasskeyPrompt {
        credential_id: credential_id.into(),
        prf_output,
    };

    let opened = client.open_with_passkey(&accepted, &prompt).await.unwrap();

    assert_eq!(opened.to_bytes(), master_key.to_bytes());
    let request = transport.requests().pop().unwrap();
    assert_eq!(request.header("Authorization"), Some("Bearer locked-token"));
}

#[tokio::test]
async fn key_proof_refuses_a_challenge_for_another_account() {
    let (challenge, _) = create_challenge().unwrap();
    let expected = uuid::Uuid::new_v4();
    let other = uuid::Uuid::new_v4();
    let transport = Arc::new(ScriptedTransport::json(
        200,
        serde_json::to_vec(&serde_json::json!({
            "session_id": uuid::Uuid::new_v4(),
            "account_id": other,
            "nonce": STANDARD_NO_PAD.encode(challenge.nonce()),
            "server_public_key": STANDARD_NO_PAD.encode(challenge.server_public()),
            "expires_in_seconds": 60,
        }))
        .unwrap(),
    ));
    let client = Client::new(ClientConfig::for_tests(), transport).unwrap();
    client.set_authentication("locked-token", expected.to_string()).unwrap();

    assert!(matches!(
        client.prove_session_key(&MasterKey::from_bytes([7; 32])).await,
        Err(AuthError::InvalidAnswer {
            field: "account_id",
            ..
        })
    ));
}

#[tokio::test]
async fn recovery_key_proof_binds_server_canonical_email() {
    let master_key = MasterKey::from_bytes([0x32; 32]);
    let (challenge, verifier) = create_challenge().unwrap();
    let canonical = "server-canonical@example.test";
    let transport = Arc::new(ScriptedTransport::json(
        200,
        serde_json::to_vec(&serde_json::json!({
            "challenge_id": "challenge-id",
            "nonce": STANDARD.encode(challenge.nonce()),
            "server_public": STANDARD.encode(challenge.server_public()),
            "canonical_email": canonical,
            "expires_at": "2099-01-01T00:00:00Z",
        }))
        .unwrap(),
    ));
    transport.push_json(
        200,
        br#"{"id":"recovery-id","status":"pending","ready_at":"2099-01-01T00:00:00Z","recovery_token":"holder-token"}"#
            .to_vec(),
    );
    let client = Client::new(ClientConfig::for_tests(), transport.clone()).unwrap();

    client
        .start_recovery("Typed@Example.Test", &master_key, None)
        .await
        .unwrap();

    let requests = transport.requests();
    let body: serde_json::Value = serde_json::from_slice(requests[1].body()).unwrap();
    assert_eq!(body["email"], canonical);
    let tag: [u8; 32] = STANDARD
        .decode(body["response"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let account_public = derive_x25519_public(&derive_x25519_private(&master_key));
    verifier
        .verify(
            &account_public,
            KeyProofBinding::Recovery {
                canonical_email: canonical.as_bytes(),
            },
            &KeyProofResponse::from_bytes(tag),
        )
        .unwrap();
}

#[tokio::test]
async fn wrong_password_stays_a_login_error_not_session_expiry() {
    let transport = Arc::new(ScriptedTransport::json(
        401,
        br#"{"error":"invalid_credentials"}"#.to_vec(),
    ));
    let client = Client::new(ClientConfig::for_tests(), transport).unwrap();
    let mut events = client.events().subscribe();

    let result = client
        .sign_in("Person@Example.Test", Zeroizing::new("wrong password".into()), None)
        .await;

    assert!(matches!(result, Err(AuthError::Client(ClientError::Api(_)))));
    assert!(matches!(events.try_recv(), Err(TryRecvError::Empty)));
}

#[tokio::test]
async fn wrong_two_factor_code_stays_a_factor_error_not_session_expiry() {
    let transport = Arc::new(ScriptedTransport::json(401, br#"{"error":"invalid_code"}"#.to_vec()));
    let client = Client::new(ClientConfig::for_tests(), transport).unwrap();
    let mut events = client.events().subscribe();
    let challenge = TwoFactorChallenge {
        partial_token: Zeroizing::new("partial".into()),
        canonical_email: "person@example.test".into(),
        legacy_upgrade_required: false,
        hardware_id: None,
    };

    let result = client.submit_two_factor(challenge, "000000".into()).await;

    assert!(matches!(result, Err(AuthError::Client(ClientError::Api(_)))));
    assert!(matches!(events.try_recv(), Err(TryRecvError::Empty)));
}

#[tokio::test]
async fn authenticated_expiry_still_emits_session_expired() {
    let transport = Arc::new(ScriptedTransport::json(401, br#"{"error":"expired"}"#.to_vec()));
    let client = Client::new(ClientConfig::for_tests(), transport).unwrap();
    client.set_authentication("token", "account-a").unwrap();
    let mut events = client.events().subscribe();

    assert!(client.execute(&beebeeb_api::routes::auth::me(), &()).await.is_err());
    assert_eq!(events.recv().await.unwrap(), EngineEvent::SessionExpired);
}

#[tokio::test]
async fn account_switch_during_sign_in_discards_the_public_answer() {
    let transport = Arc::new(ScriptedTransport::paused_json(
        401,
        br#"{"error":"invalid_credentials"}"#.to_vec(),
    ));
    let client = Arc::new(Client::new(ClientConfig::for_tests(), transport.clone()).unwrap());
    let task = tokio::spawn({
        let client = client.clone();
        async move {
            client
                .sign_in("person@example.test", Zeroizing::new("password".into()), None)
                .await
        }
    });
    transport.wait_until_sent().await;
    client.set_authentication("other-token", "other-account").unwrap();
    transport.release();

    assert!(matches!(
        task.await.unwrap(),
        Err(AuthError::Client(ClientError::StaleAccount))
    ));
}

#[test]
fn passkey_key_cannot_be_supplied_before_the_email_step() {
    let accepted = PasswordAccepted {
        session_token: Zeroizing::new("token".into()),
        canonical_email: "person@example.test".into(),
        owner: "account".into(),
        key_state: SessionKeyState::Locked,
        legacy_upgrade_required: false,
        factor_satisfied: false,
        email_code_satisfied: false,
        authenticator_required: false,
        hardware_id: None,
        hardware_identity_secret: None,
    };
    let mut unlock = NewDeviceUnlock::passkey(accepted).unwrap();

    assert!(matches!(
        unlock.provide_passkey(MasterKey::from_bytes([5; 32])),
        Err(AuthError::InvalidTransition { .. })
    ));
}

fn recorded_login_state(body: &str, legacy_upgrade_required: bool) -> Result<SignInChallenge, AuthError> {
    let response = beebeeb_api::routes::auth::opaque_finish()
        .parse(beebeeb_api::Answer::new(200, vec![], body.as_bytes().to_vec()))
        .unwrap();
    sign_in_state(
        "person@example.test".into(),
        response,
        legacy_upgrade_required,
        Some("00000000-0000-4000-8000-000000000001".into()),
        false,
    )
}

#[test]
fn recorded_opaque_full_session_omits_the_factor_flag() {
    let state = recorded_login_state(
        r#"{"session_token":"opaque-session","user_id":"00000000-0000-4000-8000-000000000002","key_state":"locked"}"#,
        false,
    )
    .unwrap();
    assert!(matches!(state, SignInChallenge::PasswordAccepted(_)));

    let state = recorded_login_state(r#"{"requires_2fa":true,"partial_token":"partial-session"}"#, false).unwrap();
    assert!(matches!(state, SignInChallenge::TwoFactor(_)));

    let malformed = [
        r#"{"partial_token":"partial-session"}"#,
        r#"{"requires_2fa":false,"partial_token":"partial-session"}"#,
        r#"{"requires_2fa":true,"session_token":"full-session","user_id":"account"}"#,
        r#"{"requires_2fa":true,"session_token":"full-session","partial_token":"partial-session","user_id":"account"}"#,
        r#"{"session_token":"full-session","partial_token":"partial-session","user_id":"account"}"#,
        r#"{}"#,
    ];
    for (index, body) in malformed.into_iter().enumerate() {
        assert!(
            matches!(
                recorded_login_state(body, false),
                Err(AuthError::InvalidAnswer {
                    step: "OPAQUE login finish",
                    field: "token combination",
                })
            ),
            "malformed recorded answer {index} was not refused"
        );
    }
}

#[test]
fn recorded_legacy_password_full_session_omits_the_factor_flag() {
    let state = recorded_login_state(
        r#"{"session_token":"legacy-session","user_id":"00000000-0000-4000-8000-000000000003","salt":"0123456789abcdef","key_state":"locked"}"#,
        true,
    )
    .unwrap();
    let SignInChallenge::PasswordAccepted(accepted) = state else {
        panic!("recorded legacy full-session answer was not accepted")
    };
    assert!(accepted.legacy_upgrade_required());
}

#[test]
fn recorded_passkey_full_session_omits_the_factor_flag() {
    let state = recorded_login_state(
        r#"{"session_token":"passkey-session","user_id":"00000000-0000-4000-8000-000000000004","salt":"0123456789abcdef","key_state":"locked"}"#,
        false,
    )
    .unwrap();
    assert!(matches!(state, SignInChallenge::PasswordAccepted(_)));
}

#[test]
fn unlock_transition_errors_name_the_safe_step() {
    let accepted = PasswordAccepted {
        session_token: Zeroizing::new("token".into()),
        canonical_email: "person@example.test".into(),
        owner: "account".into(),
        key_state: SessionKeyState::Locked,
        legacy_upgrade_required: false,
        factor_satisfied: false,
        email_code_satisfied: false,
        authenticator_required: true,
        hardware_id: None,
        hardware_identity_secret: None,
    };

    let error = NewDeviceUnlock::approval(accepted).unwrap_err();
    assert_eq!(
        error.to_string(),
        "new-device approval: authenticator factor was not satisfied"
    );
}
