use super::*;

struct SignupHardwareTransport {
    server_setup: Vec<u8>,
    requests: Mutex<Vec<beebeeb_api::Request>>,
    session_id: uuid::Uuid,
    account_id: uuid::Uuid,
    challenge: beebeeb_core::key_proof::KeyProofChallenge,
}

impl SignupHardwareTransport {
    fn new() -> Self {
        let (challenge, _) = create_challenge().unwrap();
        Self {
            server_setup: create_server_setup(),
            requests: Mutex::new(Vec::new()),
            session_id: uuid::Uuid::new_v4(),
            account_id: uuid::Uuid::new_v4(),
            challenge,
        }
    }

    fn requests(&self) -> std::sync::MutexGuard<'_, Vec<beebeeb_api::Request>> {
        self.requests.lock().unwrap()
    }

    fn json(body: serde_json::Value) -> beebeeb_api::Answer {
        beebeeb_api::Answer::new(200, Vec::new(), serde_json::to_vec(&body).unwrap())
    }
}

impl Transport for SignupHardwareTransport {
    fn send<'a>(&'a self, request: beebeeb_api::Request, max_response_bytes: usize) -> TransportFuture<'a> {
        Box::pin(async move {
            let body: serde_json::Value = serde_json::from_slice(request.body()).unwrap_or(serde_json::Value::Null);
            let answer = match request.path() {
                "/api/v1/auth/signup/email-verify" => Self::json(serde_json::json!({
                    "signup_ticket": "signup-ticket"
                })),
                "/api/v1/opaque/register-start" => {
                    let client_message = body["client_message"].as_str().ok_or(TransportError::Network)?;
                    let client_message = STANDARD.decode(client_message).map_err(|_| TransportError::Network)?;
                    let server_message =
                        server_registration_start(&self.server_setup, &client_message, b"person@example.test")
                            .map_err(|_| TransportError::Network)?;
                    Self::json(serde_json::json!({
                        "server_message": STANDARD.encode(server_message)
                    }))
                }
                "/api/v1/opaque/register-finish" => Self::json(serde_json::json!({
                    "user_id": self.account_id,
                    "session_token": "signup-session",
                    "key_state": "locked"
                })),
                "/api/v1/auth/key-proof/start" => Self::json(serde_json::json!({
                    "session_id": self.session_id,
                    "account_id": self.account_id,
                    "nonce": STANDARD_NO_PAD.encode(self.challenge.nonce()),
                    "server_public_key": STANDARD_NO_PAD.encode(self.challenge.server_public()),
                    "expires_in_seconds": 60
                })),
                "/api/v1/auth/key-proof/finish" => Self::json(serde_json::json!({
                    "key_state": "proven",
                    "hardware_identity_secret": "issued-for-signup-device"
                })),
                "/api/v1/clients/devices" => Self::json(serde_json::json!({
                    "id": "device-id",
                    "client_key": null,
                    "hostname_encrypted": null,
                    "hostname": "",
                    "platform": "macos",
                    "bb_version": "1",
                    "last_seen": "2026-11-04T12:00:00Z",
                    "created_at": "2026-11-04T12:00:00Z",
                    "hardware_id": body["hardware_id"],
                    "reported_name": "test-client",
                    "reported_by_device": true,
                    "holds_key": true
                })),
                _ => return Err(TransportError::Network),
            };
            if answer.body.len() > max_response_bytes {
                return Err(TransportError::ResponseTooLarge);
            }
            self.requests.lock().map_err(|_| TransportError::Network)?.push(request);
            Ok(answer)
        })
    }
}

#[test]
fn signup_web_only_refusal_preserves_the_redirect_url() {
    let error = AuthError::from(ClientError::Api(beebeeb_api::ApiError::SignupWebOnly {
        signup_url: "https://app.beebeeb.io/signup".to_owned(),
    }));
    match error {
        AuthError::SignupWebOnly { signup_url } => {
            assert_eq!(signup_url, "https://app.beebeeb.io/signup");
        }
        other => panic!("expected typed signup refusal, got {other:?}"),
    }
}

#[test]
fn hardware_identity_secret_is_device_local_and_redacted() {
    let store = crate::MemorySecretStore::default();
    let first = crate::session::HardwareIdentity::load_or_create(&store).unwrap();
    let id = first.id().to_owned();
    crate::session::HardwareIdentity::store_secret(&store, "server-issued-secret").unwrap();
    let loaded = crate::session::HardwareIdentity::load_or_create(&store).unwrap();
    assert_eq!(loaded.id(), id);
    assert_eq!(loaded.secret(), Some("server-issued-secret"));
    assert!(!format!("{loaded:?}").contains("server-issued-secret"));
    crate::Session::sign_out_device(&store).unwrap();
    let signed_out = crate::session::HardwareIdentity::load_or_create(&store).unwrap();
    assert_eq!(signed_out.id(), id);
    assert_eq!(signed_out.secret(), None);
}

#[test]
fn missing_key_state_is_unknown_and_never_proven() {
    assert_eq!(SessionKeyState::parse(None).unwrap(), SessionKeyState::Unknown);
    assert_eq!(SessionKeyState::parse(Some("proven")).unwrap(), SessionKeyState::Proven);
}

#[tokio::test]
async fn signup_registers_and_persists_its_hardware_identity() {
    let transport = Arc::new(SignupHardwareTransport::new());
    let client = Client::new(ClientConfig::for_tests(), transport.clone()).unwrap();
    let store = crate::MemorySecretStore::default();
    let mut signup = SignupService::new(
        "person@example.test",
        CeremonyConfig {
            password_policy: PasswordPolicy::from_server(12),
            email_verification_required: true,
            verify_word_count: 3,
            breach: BreachPolicy::NotRequired,
        },
    )
    .unwrap();
    client.verify_signup_email(&mut signup, "123456".into()).await.unwrap();
    signup
        .set_password("Valid-password-A9!", "Valid-password-A9!", None)
        .unwrap();
    let kit = signup.begin_recovery_kit().unwrap();
    let words: Vec<String> = kit.words().map(str::to_owned).collect();
    signup.mark_recovery_output_saved(RecoveryKitOutput::Pdf);
    signup.mark_recovery_output_saved(RecoveryKitOutput::Text);
    signup.acknowledge_recovery_kit().unwrap();
    let answers: Vec<String> = signup
        .challenge_positions()
        .unwrap()
        .into_iter()
        .map(|position| words[position as usize - 1].clone())
        .collect();
    signup.confirm_phrase(&answers).unwrap();

    let created = client
        .create_account(&mut signup, "terms-v1".into(), &store)
        .await
        .unwrap();
    client
        .install_new_device(created.into_ready(), "http://localhost:8080", &store)
        .await
        .unwrap();

    let requests = transport.requests();
    let registration: serde_json::Value = serde_json::from_slice(
        requests
            .iter()
            .find(|request| request.path() == "/api/v1/opaque/register-finish")
            .unwrap()
            .body(),
    )
    .unwrap();
    let hardware_id = registration["hardware_id"].as_str().unwrap();
    uuid::Uuid::parse_str(hardware_id).unwrap();
    assert_eq!(
        STANDARD
            .decode(registration["x25519_public_key"].as_str().unwrap())
            .unwrap()
            .len(),
        32
    );
    assert_eq!(
        STANDARD
            .decode(registration["recovery_check"].as_str().unwrap())
            .unwrap()
            .len(),
        32
    );

    let proof: serde_json::Value = serde_json::from_slice(
        requests
            .iter()
            .find(|request| request.path() == "/api/v1/auth/key-proof/finish")
            .unwrap()
            .body(),
    )
    .unwrap();
    assert!(
        proof.get("email_code_ticket").is_none(),
        "signup proof must omit a login email ticket"
    );
    let stored = crate::session::HardwareIdentity::load_or_create(&store).unwrap();
    assert_eq!(stored.id(), hardware_id);
    assert_eq!(stored.secret(), Some("issued-for-signup-device"));
}

#[tokio::test]
async fn public_unauthorized_answer_does_not_emit_session_expired() {
    let transport = Arc::new(ScriptedTransport::json(
        401,
        br#"{"error":"invalid_credentials"}"#.to_vec(),
    ));
    let client = Client::new(ClientConfig::for_tests(), transport).unwrap();
    client.set_authentication("unrelated-session", "account-a").unwrap();
    let mut events = client.events().subscribe();

    let result = client
        .execute(
            &beebeeb_api::routes::auth::opaque_start(),
            &beebeeb_api::routes::auth::OpaqueStartRequest {
                email: "person@example.test".into(),
                client_message: "message".into(),
            },
        )
        .await;

    assert!(result.is_err());
    assert!(matches!(events.try_recv(), Err(TryRecvError::Empty)));
}

#[test]
fn replacing_a_session_never_publishes_an_owner_over_old_secrets() {
    for failed_write in 1..=7 {
        let store = FailingWriteStore::default();
        let old = session("account-a", "token-a", 1);
        old.save(&store, "test-app").unwrap();
        store.fail_on_write(failed_write);

        let replacement = session("account-b", "token-b", 2);
        assert!(
            replacement.save(&store, "test-app").is_err(),
            "write {failed_write} must fail"
        );
        assert!(
            !matches!(Session::load_for_user(&store, "account-b", "test-app"), Ok(Some(_))),
            "write {failed_write} left a loadable partial session"
        );

        let operations = store.operations();
        let owner_delete = operations
            .iter()
            .position(|operation| operation == "delete:session.owner");
        let new_key = operations
            .iter()
            .position(|operation| operation == "set:session.master_key");
        assert!(
            new_key.is_none_or(|new_key| owner_delete.is_some_and(|owner_delete| owner_delete < new_key)),
            "new key was written while the old owner was still published: {operations:?}"
        );

        store.allow_writes();
        replacement.save(&store, "test-app").unwrap();
        assert_eq!(
            Session::load_for_user(&store, "account-b", "test-app")
                .unwrap()
                .unwrap()
                .owner(),
            "account-b"
        );
    }
}

#[test]
fn every_interrupted_first_save_allows_a_different_account_to_install() {
    for failed_write in 1..=8 {
        let store = FailingWriteStore::default();
        store.fail_on_write(failed_write);
        let _ = session("account-a", "token-a", 1).save(&store, "test-app");

        store.allow_writes();
        let replacement = session("account-b", "token-b", 2);
        replacement.save(&store, "test-app").unwrap();
        assert_eq!(
            Session::load_for_user(&store, "account-b", "test-app")
                .unwrap()
                .unwrap()
                .owner(),
            "account-b",
            "first save interrupted at write {failed_write}"
        );
    }
}

#[test]
fn same_owner_refresh_keeps_the_key_across_every_failed_write() {
    for failed_write in 1..=6 {
        let store = FailingWriteStore::default();
        Session::from_parts_for_test("https://api.example", "token-a", "account-a", [7; 32], 1)
            .unwrap()
            .save(&store, "test-app")
            .unwrap();
        store.fail_on_write(failed_write);

        let refreshed =
            Session::from_parts_for_test("https://api.example", "token-b", "account-a", [7; 32], 2).unwrap();
        let _ = refreshed.save(&store, "test-app");

        assert!(
            store.get("session.master_key").unwrap().is_some(),
            "write {failed_write} deleted the key"
        );
        assert!(
            store.get("session.owner").unwrap().is_some(),
            "write {failed_write} deleted the owner"
        );
    }
}

#[test]
fn unknown_ownerless_partial_session_keeps_the_key_and_does_not_block_sign_in() {
    let store = FailingWriteStore::default();
    store.set("session.api_url", b"https://api.example").unwrap();
    store.set("session.token.test-app", b"partial-token").unwrap();
    store.set("session.master_key", &[7; 32]).unwrap();

    assert!(
        Session::load_for_user(&store, "account-b", "test-app")
            .unwrap()
            .is_none()
    );
    assert!(store.get("session.master_key").unwrap().is_some());
    let replacement = Session::from_parts_for_test("https://api.example", "token-b", "account-b", [7; 32], 2).unwrap();
    replacement.save(&store, "test-app").unwrap();
    assert!(
        Session::load_for_user(&store, "account-b", "test-app")
            .unwrap()
            .is_some()
    );

    let unknown = FailingWriteStore::default();
    unknown.set("session.master_key", &[7; 32]).unwrap();
    let different_key =
        Session::from_parts_for_test("https://api.example", "token-b", "account-b", [8; 32], 2).unwrap();
    assert!(matches!(
        different_key.save(&unknown, "test-app"),
        Err(SecretError::OwnerMismatch)
    ));
    assert_eq!(unknown.get("session.master_key").unwrap().unwrap().as_slice(), &[7; 32]);
}

#[test]
fn api_url_loopback_host_must_match_exactly() {
    assert!(Session::from_parts_for_test("http://localhost.example.com", "token", "account", [1; 32], 0,).is_err());
    assert!(Session::from_parts_for_test("http://127.0.0.1.example.com", "token", "account", [1; 32], 0,).is_err());
    assert!(Session::from_parts_for_test("http://localhost:8080", "token", "account", [1; 32], 0).is_ok());
    assert!(Session::from_parts_for_test("http://[::1]:8080", "token", "account", [1; 32], 0).is_ok());
}

#[test]
fn canonical_email_matches_server_unicode_lowercasing() {
    assert_eq!(canonical_email("  İNFO@EXAMPLE.TEST  "), "i̇nfo@example.test");
}

#[test]
fn recovery_kit_requires_pdf_and_text_but_not_print() {
    let mut signup = SignupService::new(
        "person@example.test",
        CeremonyConfig {
            password_policy: PasswordPolicy::from_server(12),
            email_verification_required: false,
            verify_word_count: 3,
            breach: BreachPolicy::NotRequired,
        },
    )
    .unwrap();
    let _kit = signup.begin_recovery_kit().unwrap();
    signup.mark_recovery_output_saved(RecoveryKitOutput::Pdf);
    assert!(matches!(
        signup.acknowledge_recovery_kit(),
        Err(AuthError::RecoveryKitIncomplete)
    ));
    signup.mark_recovery_output_saved(RecoveryKitOutput::Text);
    signup.acknowledge_recovery_kit().unwrap();
}

#[tokio::test]
async fn signup_email_uses_the_shared_unicode_canonical_form() {
    let transport = Arc::new(ScriptedTransport::json(
        202,
        br#"{"message":"If that address can sign up, we've sent you a code."}"#.to_vec(),
    ));
    let client = Client::new(ClientConfig::for_tests(), transport.clone()).unwrap();
    let signup = SignupService::new(
        "  İNFO@EXAMPLE.TEST  ",
        CeremonyConfig {
            password_policy: PasswordPolicy::from_server(12),
            email_verification_required: true,
            verify_word_count: 3,
            breach: BreachPolicy::NotRequired,
        },
    )
    .unwrap();

    client.start_signup_email(&signup).await.unwrap();

    let request = transport.requests().pop().unwrap();
    let body: serde_json::Value = serde_json::from_slice(request.body()).unwrap();
    assert_eq!(body["email"], "i̇nfo@example.test");
}

#[tokio::test]
async fn signing_out_this_app_preserves_another_apps_session_and_the_shared_key() {
    let store = FailingWriteStore::default();
    let mail = session("account-a", "mail-token", 1);
    mail.save(&store, "mail").unwrap();
    let drive = session("account-a", "drive-token", 1);
    drive.save(&store, "drive").unwrap();

    let transport = Arc::new(ScriptedTransport::json(200, br#"{"message":"logged out"}"#.to_vec()));
    let client = Client::new(ClientConfig::new("test-client", "1", "mail"), transport).unwrap();
    client.set_session(&mail).unwrap();
    client.sign_out_this_app(&store).await.unwrap();

    assert!(Session::load_for_user(&store, "account-a", "mail").unwrap().is_none());
    assert!(Session::load_for_user(&store, "account-a", "drive").unwrap().is_some());
    assert!(store.get("session.master_key").unwrap().is_some());
    assert!(store.get("session.owner").unwrap().is_some());
}

#[test]
fn whole_device_sign_out_removes_all_app_tokens_and_shared_session_material() {
    let store = FailingWriteStore::default();
    session("account-a", "mail-token", 1).save(&store, "mail").unwrap();
    session("account-a", "drive-token", 1).save(&store, "drive").unwrap();

    assert_eq!(Session::sign_out_device(&store).unwrap(), 2);

    for name in [
        "session.token.mail",
        "session.token.drive",
        "session.app_ids",
        "session.api_url",
        "session.master_key",
        "session.owner",
    ] {
        assert!(
            store.get(name).unwrap().is_none(),
            "{name} survived whole-device sign-out"
        );
    }
    assert_eq!(store.get("account.generation").unwrap().unwrap().as_slice(), b"2");
}

#[test]
fn last_device_warning_counts_only_key_holders_and_fails_closed_for_unknown_current_device() {
    let devices: beebeeb_api::routes::devices::Devices = serde_json::from_value(serde_json::json!({
        "devices": [
            {
                "id": "current", "hostname": "", "platform": "ios", "last_seen": "", "created_at": "",
                "holds_key": true
            },
            {
                "id": "locked", "hostname": "", "platform": "web", "last_seen": "", "created_at": "",
                "holds_key": false
            }
        ]
    }))
    .unwrap();

    assert!(crate::devices::last_device_warning(&devices.devices, "current"));
    assert!(crate::devices::last_device_warning(&devices.devices, "missing"));
}

#[derive(Default)]
struct FailingWriteStore {
    values: Mutex<HashMap<String, Zeroizing<Vec<u8>>>>,
    writes: Mutex<(usize, Option<usize>)>,
    operations: Mutex<Vec<String>>,
}

impl FailingWriteStore {
    fn fail_on_write(&self, position: usize) {
        *self.writes.lock().unwrap() = (0, Some(position));
        self.operations.lock().unwrap().clear();
    }

    fn allow_writes(&self) {
        *self.writes.lock().unwrap() = (0, None);
    }

    fn operations(&self) -> Vec<String> {
        self.operations.lock().unwrap().clone()
    }
}

impl SecretStore for FailingWriteStore {
    fn set(&self, name: &str, value: &[u8]) -> Result<(), SecretError> {
        self.operations
            .lock()
            .map_err(|_| SecretError::Backend)?
            .push(format!("set:{name}"));
        let mut writes = self.writes.lock().map_err(|_| SecretError::Backend)?;
        writes.0 += 1;
        if writes.1 == Some(writes.0) {
            return Err(SecretError::Backend);
        }
        self.values
            .lock()
            .map_err(|_| SecretError::Backend)?
            .insert(name.to_owned(), Zeroizing::new(value.to_vec()));
        Ok(())
    }

    fn get(&self, name: &str) -> Result<Option<Zeroizing<Vec<u8>>>, SecretError> {
        Ok(self.values.lock().map_err(|_| SecretError::Backend)?.get(name).cloned())
    }

    fn delete(&self, name: &str) -> Result<(), SecretError> {
        self.operations
            .lock()
            .map_err(|_| SecretError::Backend)?
            .push(format!("delete:{name}"));
        self.values.lock().map_err(|_| SecretError::Backend)?.remove(name);
        Ok(())
    }
}
