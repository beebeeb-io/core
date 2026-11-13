//! The two-level lock: the start rule, the vault lock, an ended session, the strong unlock
//! and both purge places. The password path is in `lock_password.rs`.

use std::collections::HashSet;
use std::sync::OnceLock;

use beebeeb_api::{Answer, Header, flows::LockState};
use beebeeb_core::opaque_protocol::{
    client_registration_finish, client_registration_start, server_login_finish, server_login_start,
    server_registration_finish,
};
use beebeeb_core::screen_lock::{self, AttemptState, CheckOutcome, ScreenCheckRecord};
use tokio::sync::broadcast;

use super::*;
use crate::MemorySecretStore;
use crate::session::{LOCK_ASK_AT_START, LOCK_ATTEMPTS, LOCK_SCREEN_CHECK, LOCK_VAULT_CLOSED};

pub(super) const OWNER: &str = "0b3c7a52-5d0e-4f1a-9d2e-1c6f3a8b9e01";
pub(super) const EMAIL: &str = "person@example.test";
pub(super) const PASSWORD: &str = "correct horse battery staple 42";
pub(super) const OLD_PASSWORD: &str = "the password before the change";
pub(super) const STORED_TOKEN: &str = "stored-session-token";
pub(super) const NEW_TOKEN: &str = "new-session-token";
pub(super) const KEY_ENTRY: &str = "session.master_key";
pub(super) const PROOF_START: &str = "/api/v1/auth/password-proof/start";
pub(super) const PROOF_FINISH: &str = "/api/v1/auth/password-proof/finish";
pub(super) const ME: &str = "/api/v1/auth/me";
pub(super) const LOGOUT: &str = "/api/v1/auth/logout";
const LOGIN_START: &str = "/api/v1/opaque/login-start";
const LOGIN_FINISH: &str = "/api/v1/opaque/login-finish";
const TWO_FACTOR: &str = "/api/v1/auth/2fa/verify";
const KEY_PROOF_START: &str = "/api/v1/auth/key-proof/start";
const KEY_PROOF_FINISH: &str = "/api/v1/auth/key-proof/finish";
const DEVICES: &str = "/api/v1/clients/devices";
const STEP_UP_START: &str = "/api/v1/auth/confirm-opaque-start";
const STEP_UP_FINISH: &str = "/api/v1/auth/confirm-opaque-finish";
const CHANGE_START: &str = "/api/v1/auth/change-password-start";
const CHANGE_FINISH: &str = "/api/v1/auth/change-password-finish";

/// One account's OPAQUE registration for [`PASSWORD`], made once for the whole test run (it
/// costs a canonical Argon2id run).
struct Account {
    server_setup: Vec<u8>,
    password_file: Vec<u8>,
}

fn account() -> &'static Account {
    static ACCOUNT: OnceLock<Account> = OnceLock::new();
    ACCOUNT.get_or_init(|| {
        let server_setup = create_server_setup();
        let started = client_registration_start(PASSWORD.as_bytes()).unwrap();
        let answer = server_registration_start(&server_setup, &started.message, EMAIL.as_bytes()).unwrap();
        let upload = client_registration_finish(&started.state, PASSWORD.as_bytes(), &answer).unwrap();
        Account {
            server_setup,
            password_file: server_registration_finish(&upload).unwrap(),
        }
    })
}

/// A check record for `password` and [`OWNER`] at counter 0, enrolled once per password.
pub(super) fn record_for(password: &'static str) -> Vec<u8> {
    static RECORDS: OnceLock<Mutex<HashMap<&'static str, Vec<u8>>>> = OnceLock::new();
    let mut records = RECORDS.get_or_init(Default::default).lock().unwrap();
    records
        .entry(password)
        .or_insert_with(|| {
            screen_lock::enroll(&Zeroizing::new(password.to_owned()), OWNER, 0)
                .unwrap()
                .to_bytes()
        })
        .clone()
}

pub(super) fn password(text: &str) -> Zeroizing<String> {
    Zeroizing::new(text.to_owned())
}

/// How the server answers one route instead of its normal answer.
#[derive(Clone)]
pub(super) enum Reply {
    Status(u16, serde_json::Value, Vec<Header>),
    /// The request never reaches the server.
    Offline,
}

type Hook = Box<dyn Fn(&str) + Send + Sync>;

#[derive(Default)]
struct ServerState {
    replies: HashMap<&'static str, Reply>,
    offline: bool,
    session_gone: bool,
    password_counter: Option<u64>,
    two_factor: bool,
    login_state: Option<Vec<u8>>,
    requests: Vec<beebeeb_api::Request>,
    gate: Option<Arc<tokio::sync::Notify>>,
}

/// A server that holds [`account`]: the password proof, the sign-in, the key proof, the
/// account (`/auth/me`), the step-up and the password change. Every other path is a 404.
pub(super) struct LockServer {
    state: Mutex<ServerState>,
    hook: Mutex<Option<Hook>>,
    challenge: beebeeb_core::key_proof::KeyProofChallenge,
    session_id: uuid::Uuid,
}

impl LockServer {
    pub(super) fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::default(),
            hook: Mutex::new(None),
            challenge: create_challenge().unwrap().0,
            session_id: uuid::Uuid::new_v4(),
        })
    }

    fn edit(&self, edit: impl FnOnce(&mut ServerState)) {
        edit(&mut self.state.lock().unwrap());
    }

    pub(super) fn reply(&self, path: &'static str, reply: Reply) {
        self.edit(|state| {
            state.replies.insert(path, reply);
        });
    }

    pub(super) fn refuse(&self, path: &'static str, status: u16, code: &str) {
        self.reply(
            path,
            Reply::Status(status, serde_json::json!({ "error": code }), Vec::new()),
        );
    }

    pub(super) fn answer_normally(&self, path: &'static str) {
        self.edit(|state| {
            state.replies.remove(path);
        });
    }

    pub(super) fn go_offline(&self, offline: bool) {
        self.edit(|state| state.offline = offline);
    }

    pub(super) fn end_the_session(&self) {
        self.edit(|state| state.session_gone = true);
    }

    pub(super) fn report_password_counter(&self, counter: u64) {
        self.edit(|state| state.password_counter = Some(counter));
    }

    fn ask_for_an_authenticator_code(&self) {
        self.edit(|state| state.two_factor = true);
    }

    /// Holds every request until the returned gate is notified once per request.
    pub(super) fn hold_requests(&self) -> Arc<tokio::sync::Notify> {
        let gate = Arc::new(tokio::sync::Notify::new());
        self.edit(|state| state.gate = Some(gate.clone()));
        gate
    }

    /// Runs `hook` with the path of every request, before it is answered.
    pub(super) fn on_request(&self, hook: impl Fn(&str) + Send + Sync + 'static) {
        *self.hook.lock().unwrap() = Some(Box::new(hook));
    }

    pub(super) fn requests(&self) -> Vec<beebeeb_api::Request> {
        self.state.lock().unwrap().requests.clone()
    }

    pub(super) fn paths(&self) -> Vec<String> {
        self.requests()
            .iter()
            .map(|request| request.path().to_owned())
            .collect()
    }

    pub(super) fn count(&self, path: &str) -> usize {
        self.paths().iter().filter(|seen| *seen == path).count()
    }

    /// The bearer tokens of the logout requests, in order.
    fn logged_out_tokens(&self) -> Vec<String> {
        self.requests()
            .iter()
            .filter(|request| request.path() == LOGOUT)
            .map(|request| request.header("Authorization").unwrap_or_default().to_owned())
            .collect()
    }

    fn json(status: u16, body: serde_json::Value) -> Answer {
        Answer::new(
            status,
            vec![Header::new("Content-Type", "application/json")],
            serde_json::to_vec(&body).unwrap(),
        )
    }

    fn session_answer(&self) -> serde_json::Value {
        serde_json::json!({ "session_token": NEW_TOKEN, "user_id": OWNER, "key_state": "locked" })
    }
}

impl Transport for LockServer {
    fn send<'a>(&'a self, request: beebeeb_api::Request, _max_response_bytes: usize) -> TransportFuture<'a> {
        Box::pin(async move {
            if let Some(hook) = self.hook.lock().unwrap().as_ref() {
                hook(request.path());
            }
            let gate = self.state.lock().unwrap().gate.clone();
            if let Some(gate) = gate {
                gate.notified().await;
            }
            let mut state = self.state.lock().unwrap();
            state.requests.push(request.clone());
            if state.offline {
                return Err(TransportError::Network);
            }
            match state.replies.get(request.path()) {
                Some(Reply::Offline) => return Err(TransportError::Network),
                Some(Reply::Status(status, body, headers)) => {
                    let mut headers = headers.clone();
                    headers.push(Header::new("Content-Type", "application/json"));
                    return Ok(Answer::new(*status, headers, serde_json::to_vec(body).unwrap()));
                }
                None => {}
            }
            let body: serde_json::Value = serde_json::from_slice(request.body()).unwrap_or(serde_json::Value::Null);
            let client_message = || {
                body["client_message"]
                    .as_str()
                    .and_then(|text| STANDARD.decode(text).ok())
                    .ok_or(TransportError::Network)
            };
            let account = account();
            Ok(match request.path() {
                ME | PROOF_START | PROOF_FINISH | STEP_UP_START | STEP_UP_FINISH if state.session_gone => {
                    Self::json(401, serde_json::json!({ "error": "unauthorized" }))
                }
                ME => {
                    let mut user = serde_json::json!({ "id": OWNER, "email": EMAIL });
                    if let Some(counter) = state.password_counter {
                        user["password_counter"] = counter.into();
                    }
                    Self::json(200, user)
                }
                PROOF_START | STEP_UP_START | LOGIN_START => {
                    let started = server_login_start(
                        &account.server_setup,
                        &account.password_file,
                        &client_message()?,
                        EMAIL.as_bytes(),
                    )
                    .map_err(|_| TransportError::Network)?;
                    state.login_state = Some(started.state);
                    Self::json(
                        200,
                        serde_json::json!({
                            "server_message": STANDARD.encode(started.message),
                            "server_state": "server-state-1",
                            "ksf_version": 1,
                        }),
                    )
                }
                PROOF_FINISH | STEP_UP_FINISH | LOGIN_FINISH => {
                    let login = state.login_state.take().ok_or(TransportError::Network)?;
                    let proven = server_login_finish(&login, &client_message()?).is_ok();
                    match (request.path(), proven) {
                        (PROOF_FINISH, true) => {
                            let mut proven = serde_json::json!({ "proven": true });
                            if let Some(counter) = state.password_counter {
                                proven["password_counter"] = counter.into();
                            }
                            Self::json(200, proven)
                        }
                        (PROOF_FINISH, false) => Self::json(403, serde_json::json!({ "error": "password_not_proven" })),
                        (STEP_UP_FINISH, true) => Self::json(
                            200,
                            serde_json::json!({
                                "confirmation_token": "confirm-token",
                                "expires_at": "2026-11-13T12:05:00Z",
                            }),
                        ),
                        (LOGIN_FINISH, true) if state.two_factor => Self::json(
                            200,
                            serde_json::json!({ "requires_2fa": true, "partial_token": "partial-token" }),
                        ),
                        (LOGIN_FINISH, true) => Self::json(200, self.session_answer()),
                        _ => Self::json(401, serde_json::json!({ "error": "invalid credentials" })),
                    }
                }
                TWO_FACTOR => Self::json(200, self.session_answer()),
                KEY_PROOF_START => Self::json(
                    200,
                    serde_json::json!({
                        "session_id": self.session_id,
                        "account_id": OWNER,
                        "nonce": STANDARD_NO_PAD.encode(self.challenge.nonce()),
                        "server_public_key": STANDARD_NO_PAD.encode(self.challenge.server_public()),
                        "expires_in_seconds": 60,
                    }),
                ),
                KEY_PROOF_FINISH => Self::json(200, serde_json::json!({ "key_state": "proven" })),
                DEVICES => Self::json(
                    200,
                    serde_json::json!({
                        "id": "device-id", "client_key": null, "hostname_encrypted": null, "hostname": "",
                        "platform": "windows", "bb_version": "1", "last_seen": "2026-11-13T12:00:00Z",
                        "created_at": "2026-11-13T12:00:00Z", "hardware_id": body["hardware_id"],
                        "reported_name": "test-client", "reported_by_device": true, "holds_key": true,
                    }),
                ),
                CHANGE_START => {
                    let answer = server_registration_start(&account.server_setup, &client_message()?, EMAIL.as_bytes())
                        .map_err(|_| TransportError::Network)?;
                    Self::json(200, serde_json::json!({ "server_message": STANDARD.encode(answer) }))
                }
                CHANGE_FINISH => {
                    let mut changed = self.session_answer();
                    if let Some(counter) = state.password_counter {
                        changed["password_counter"] = counter.into();
                    }
                    Self::json(200, changed)
                }
                LOGOUT => Self::json(200, serde_json::json!({ "message": "signed out" })),
                _ => Self::json(404, serde_json::json!({ "error": "not found" })),
            })
        })
    }
}

/// A secret store whose reads, writes or deletes of chosen entries fail.
#[derive(Default)]
pub(super) struct FaultyStore {
    pub(super) inner: MemorySecretStore,
    fail_get: Mutex<HashSet<&'static str>>,
    fail_set: Mutex<HashSet<&'static str>>,
    fail_delete: Mutex<HashSet<&'static str>>,
}

impl FaultyStore {
    /// Over a store that holds one installed session of [`OWNER`].
    pub(super) fn with_session() -> Self {
        Self {
            inner: store_with_session(),
            ..Self::default()
        }
    }

    pub(super) fn fail_reads_of(&self, name: &'static str) {
        self.fail_get.lock().unwrap().insert(name);
    }

    pub(super) fn fail_writes_of(&self, name: &'static str) {
        self.fail_set.lock().unwrap().insert(name);
    }

    pub(super) fn fail_deletes_of(&self, name: &'static str) {
        self.fail_delete.lock().unwrap().insert(name);
    }
}

impl SecretStore for FaultyStore {
    fn set(&self, name: &str, value: &[u8]) -> Result<(), SecretError> {
        if self.fail_set.lock().unwrap().contains(name) {
            return Err(SecretError::Backend);
        }
        self.inner.set(name, value)
    }

    fn get(&self, name: &str) -> Result<Option<Zeroizing<Vec<u8>>>, SecretError> {
        if self.fail_get.lock().unwrap().contains(name) {
            return Err(SecretError::Backend);
        }
        self.inner.get(name)
    }

    fn delete(&self, name: &str) -> Result<(), SecretError> {
        if self.fail_delete.lock().unwrap().contains(name) {
            return Err(SecretError::Backend);
        }
        self.inner.delete(name)
    }
}

pub(super) fn config(password_path: bool) -> ClientConfig {
    let mut config = ClientConfig::for_tests();
    config.lock_password_path = password_path;
    config
}

/// A store that holds one installed session of [`OWNER`] for the test app.
pub(super) fn store_with_session() -> MemorySecretStore {
    let store = MemorySecretStore::default();
    session(OWNER, STORED_TOKEN, 1).save(&store, "test-app").unwrap();
    store.reset_reads();
    store
}

pub(super) fn entry(store: &dyn SecretStore, name: &str) -> Option<Vec<u8>> {
    store.get(name).unwrap().map(|value| value.to_vec())
}

pub(super) fn attempts(store: &dyn SecretStore) -> Option<(u32, u64)> {
    entry(store, LOCK_ATTEMPTS).map(|bytes| {
        let state = AttemptState::from_bytes(&bytes).expect("a stored attempt state");
        (state.failures(), state.last_failure_ms())
    })
}

pub(super) fn seed_attempts(store: &dyn SecretStore, failures: u32, last_failure_ms: u64) {
    let mut state = AttemptState::new();
    for _ in 0..failures {
        state = state.counting_try(last_failure_ms);
    }
    store.set(LOCK_ATTEMPTS, &state.to_bytes()).unwrap();
}

/// A client started from `store`: screen-locked, the key loaded.
pub(super) fn screen_locked(server: &Arc<LockServer>, store: &dyn SecretStore, password_path: bool) -> Client {
    let client = Client::new(config(password_path), server.clone()).unwrap();
    assert_eq!(client.start_from_store(store).unwrap(), LockState::ScreenLocked);
    client
}

pub(super) fn drained(events: &mut broadcast::Receiver<EngineEvent>) -> Vec<EngineEvent> {
    std::iter::from_fn(|| events.try_recv().ok()).collect()
}

pub(super) fn count_of(events: &[EngineEvent], wanted: &EngineEvent) -> usize {
    events.iter().filter(|event| *event == wanted).count()
}

#[test]
fn a_start_without_a_stored_session_is_signed_out() {
    let store = MemorySecretStore::default();
    let client = Client::new(config(false), LockServer::new()).unwrap();
    assert_eq!(client.lock_state(), LockState::SignedOut);
    assert_eq!(client.start_from_store(&store).unwrap(), LockState::SignedOut);
    assert!(client.session_key().is_err());
    // A session of another app on the device is not this app's.
    session(OWNER, STORED_TOKEN, 1).save(&store, "another-app").unwrap();
    store.reset_reads();
    assert_eq!(client.start_from_store(&store).unwrap(), LockState::SignedOut);
    assert_eq!(store.read_count_for(KEY_ENTRY), 0);
}

#[test]
fn a_start_with_a_stored_session_is_screen_locked_with_the_key_loaded() {
    let store = store_with_session();
    let client = Client::new(config(false), LockServer::new()).unwrap();
    assert_eq!(client.start_from_store(&store).unwrap(), LockState::ScreenLocked);
    assert_eq!(client.lock_state(), LockState::ScreenLocked);
    assert!(client.session_key().unwrap().is_current(&client));
    assert_eq!(client.account_id().unwrap(), OWNER);
    // The lock starts once: a second start cannot re-open or re-lock anything.
    assert!(matches!(
        client.start_from_store(&store),
        Err(AuthError::InvalidTransition { step: "lock start", .. })
    ));
}

#[test]
fn a_closed_or_unreadable_start_reads_the_key_entry_zero_times() {
    type Arrange = fn(&FaultyStore);
    let cases: [(&str, Arrange); 6] = [
        ("the setting is on", |store| {
            store.inner.set(LOCK_ASK_AT_START, b"1").unwrap()
        }),
        ("the closed mark is set", |store| {
            store.inner.set(LOCK_VAULT_CLOSED, b"1").unwrap()
        }),
        ("the setting is not a flag", |store| {
            store.inner.set(LOCK_ASK_AT_START, b"").unwrap()
        }),
        ("the mark is not a flag", |store| {
            store.inner.set(LOCK_VAULT_CLOSED, b"yes").unwrap()
        }),
        ("the setting cannot be read", |store| {
            store.fail_reads_of(LOCK_ASK_AT_START)
        }),
        ("the mark cannot be read", |store| {
            store.fail_reads_of(LOCK_VAULT_CLOSED)
        }),
    ];
    for (name, arrange) in cases {
        let store = FaultyStore::with_session();
        arrange(&store);
        store.inner.reset_reads();
        let client = Client::new(config(false), LockServer::new()).unwrap();
        assert_eq!(
            client.start_from_store(&store).unwrap(),
            LockState::VaultClosed,
            "{name}"
        );
        assert_eq!(store.inner.read_count_for(KEY_ENTRY), 0, "{name}");
        assert!(client.session_key().is_err(), "{name}");
        // A start that is closed for any reason is marked closed, so that every restore
        // path stays closed with it (a mark that cannot be read already refuses them).
        if name != "the mark cannot be read" {
            assert_eq!(
                entry(&store.inner, LOCK_VAULT_CLOSED).as_deref(),
                Some(b"1".as_slice()),
                "{name}"
            );
        }
        // Neither screen proof opens it, and a restore is refused.
        assert!(client.unlock_screen_platform_verified(&store).is_err(), "{name}");
        assert!(matches!(
            Session::load_for_user(&store, OWNER, "test-app"),
            Err(SecretError::VaultClosed)
        ));
        assert!(matches!(
            client.set_session(&session(OWNER, STORED_TOKEN, 1)),
            Err(ClientError::VaultClosed)
        ));
        assert_eq!(client.lock_state(), LockState::VaultClosed, "{name}");
        assert_eq!(store.inner.read_count_for(KEY_ENTRY), 0, "{name}");
    }
}

#[tokio::test]
async fn a_locked_vault_stays_closed_across_a_restart_and_keeps_the_stored_session() {
    let server = LockServer::new();
    let store = store_with_session();
    let client = screen_locked(&server, &store, false);
    let key_before = entry(&store, KEY_ENTRY).unwrap();

    let locked = client.lock_vault(&store).await.unwrap();
    assert!(locked.survives_restart());
    assert_eq!(client.lock_state(), LockState::VaultClosed);
    assert_eq!(entry(&store, LOCK_VAULT_CLOSED).as_deref(), Some(b"1".as_slice()));
    // The key is dropped from the process, not from the store.
    assert_eq!(entry(&store, KEY_ENTRY).unwrap(), key_before);
    assert_eq!(
        entry(&store, "session.token.test-app").unwrap(),
        STORED_TOKEN.as_bytes()
    );
    // The session it held is ended at the server, with that session's own token.
    assert_eq!(server.logged_out_tokens(), [format!("Bearer {STORED_TOKEN}")]);

    // Quit and start again: still closed, and the key entry is not read.
    store.reset_reads();
    let restarted = Client::new(config(false), server.clone()).unwrap();
    assert_eq!(restarted.start_from_store(&store).unwrap(), LockState::VaultClosed);
    assert_eq!(store.read_count_for(KEY_ENTRY), 0);
    assert!(restarted.session_key().is_err());
}

#[tokio::test]
async fn after_a_vault_lock_every_key_copy_is_stale_and_work_has_stopped() {
    let server = LockServer::new();
    let store = store_with_session();
    let client = screen_locked(&server, &store, false);
    client.unlock_screen_platform_verified(&store).unwrap();
    let copy = client.session_key().unwrap();
    assert!(copy.is_current(&client));
    let mut events = client.events().subscribe();

    let locked = client.lock_vault(&store).await.unwrap();
    assert_eq!(locked.generation(), client.generation());
    assert!(locked.generation() > copy.generation());
    assert!(
        !copy.is_current(&client),
        "a key copy handed out before the lock is stale"
    );
    assert!(matches!(client.session_key(), Err(ClientError::InvalidAuthentication)));
    let events = drained(&mut events);
    assert_eq!(count_of(&events, &EngineEvent::WorkStopped), 1);
    assert!(events.contains(&EngineEvent::AccountChanged {
        generation: locked.generation()
    }));
    // Work that belongs to the old generation is refused.
    assert!(
        client
            .execute_for_generation(&beebeeb_api::routes::auth::me(), &(), copy.generation())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn a_vault_lock_whose_mark_cannot_be_stored_still_closes_this_process() {
    let server = LockServer::new();
    let store = FaultyStore::with_session();
    let client = screen_locked(&server, &store, false);
    store.fail_writes_of(LOCK_VAULT_CLOSED);
    let locked = client.lock_vault(&store).await.unwrap();
    assert!(
        !locked.survives_restart(),
        "the caller is told the lock will not survive a restart"
    );
    assert_eq!(client.lock_state(), LockState::VaultClosed);
    assert!(client.session_key().is_err());
    // A signed-out app has no vault to lock.
    let signed_out = Client::new(config(false), server.clone()).unwrap();
    assert!(signed_out.lock_vault(&MemorySecretStore::default()).await.is_err());
}

#[test]
fn the_screen_lock_opens_with_platform_verification_and_locks_again() {
    let store = store_with_session();
    let client = screen_locked(&LockServer::new(), &store, false);
    seed_attempts(&store, 3, 1_000);
    let generation = client.generation();
    client.unlock_screen_platform_verified(&store).unwrap();
    assert_eq!(client.lock_state(), LockState::Open);
    assert_eq!(
        attempts(&store),
        None,
        "any successful unlock resets the wrong-try count"
    );
    // The key and the work are the same on both sides of the screen lock.
    assert_eq!(client.generation(), generation);
    assert!(client.unlock_screen_platform_verified(&store).is_err(), "already open");
    client.lock_screen().unwrap();
    assert_eq!(client.lock_state(), LockState::ScreenLocked);
    assert_eq!(client.generation(), generation);
    assert!(client.session_key().unwrap().is_current(&client));
}

#[tokio::test]
async fn an_ended_session_closes_the_vault_and_deletes_the_check_record() {
    let server = LockServer::new();
    let store = store_with_session();
    let client = screen_locked(&server, &store, true);
    store.set(LOCK_SCREEN_CHECK, &[7u8; 102]).unwrap();
    seed_attempts(&store, 2, 5);
    let mut events = client.events().subscribe();
    server.end_the_session();

    assert_eq!(
        client.refresh_lock_from_server(&store).await.unwrap(),
        LockState::VaultClosed
    );
    assert!(client.session_key().is_err(), "the key is dropped");
    assert_eq!(entry(&store, LOCK_SCREEN_CHECK), None);
    assert_eq!(attempts(&store), None);
    assert_eq!(entry(&store, LOCK_VAULT_CLOSED).as_deref(), Some(b"1".as_slice()));
    let events = drained(&mut events);
    assert_eq!(count_of(&events, &EngineEvent::SessionExpired), 1);
    assert_eq!(count_of(&events, &EngineEvent::WorkStopped), 1);
    // The next start does not load the key for a session the server no longer accepts.
    store.reset_reads();
    let restarted = Client::new(config(true), server.clone()).unwrap();
    assert_eq!(restarted.start_from_store(&store).unwrap(), LockState::VaultClosed);
    assert_eq!(store.read_count_for(KEY_ENTRY), 0);
}

#[tokio::test]
async fn any_refused_session_drops_the_key_at_once_and_the_host_records_it() {
    let server = LockServer::new();
    let store = store_with_session();
    let client = screen_locked(&server, &store, false);
    client.unlock_screen_platform_verified(&store).unwrap();
    store.set(LOCK_SCREEN_CHECK, &[7u8; 102]).unwrap();
    server.end_the_session();
    // Any request of the app, not a lock call: the arrow is core's.
    assert!(client.execute(&beebeeb_api::routes::auth::me(), &()).await.is_err());
    assert_eq!(client.lock_state(), LockState::VaultClosed);
    assert!(client.session_key().is_err());
    // The host heard `SessionExpired` and records it in the store.
    assert_eq!(client.session_ended(&store).unwrap(), LockState::VaultClosed);
    assert_eq!(entry(&store, LOCK_SCREEN_CHECK), None);
    assert_eq!(entry(&store, LOCK_VAULT_CLOSED).as_deref(), Some(b"1".as_slice()));
}

/// A host that restores sessions itself and never starts the lock keeps today's behaviour:
/// the state machine is not started for it, so a refused session only raises the event.
#[tokio::test]
async fn a_host_that_never_started_the_lock_keeps_its_session_on_a_refusal() {
    let server = LockServer::new();
    let client = Client::new(config(false), server.clone()).unwrap();
    client.set_session(&session(OWNER, STORED_TOKEN, 1)).unwrap();
    assert_eq!(client.lock_state(), LockState::SignedOut);
    let mut events = client.events().subscribe();
    server.end_the_session();
    assert!(client.execute(&beebeeb_api::routes::auth::me(), &()).await.is_err());
    assert_eq!(count_of(&drained(&mut events), &EngineEvent::SessionExpired), 1);
    assert!(client.session_key().is_ok());
    assert_eq!(client.lock_state(), LockState::SignedOut);
}

fn seed_lock_entries(store: &dyn SecretStore) {
    for name in [LOCK_SCREEN_CHECK, LOCK_ATTEMPTS, LOCK_ASK_AT_START, LOCK_VAULT_CLOSED] {
        store.set(name, b"0").unwrap();
    }
}

fn lock_entries_left(store: &dyn SecretStore) -> usize {
    [LOCK_SCREEN_CHECK, LOCK_ATTEMPTS, LOCK_ASK_AT_START, LOCK_VAULT_CLOSED]
        .into_iter()
        .filter(|name| entry(store, name).is_some())
        .count()
}

#[test]
fn both_purge_places_remove_all_four_lock_entries_and_an_app_sign_out_keeps_them() {
    // The device-session purge.
    let store = store_with_session();
    seed_lock_entries(&store);
    Session::sign_out_app(&store, "test-app").unwrap();
    assert_eq!(lock_entries_left(&store), 4, "they belong to the account on the device");
    Session::sign_out_device(&store).unwrap();
    assert_eq!(lock_entries_left(&store), 0);

    // The account-change branch of the session save.
    let store = store_with_session();
    seed_lock_entries(&store);
    let other = "7f9e2d14-3a6b-4c8d-8e1f-2b4a6c8d0e12";
    session(other, "other-token", 2)
        .save_replacing(&store, "test-app")
        .unwrap();
    assert_eq!(Session::stored_owner(&store).unwrap().as_deref(), Some(other));
    assert_eq!(lock_entries_left(&store), 0);

    // A save for the same account keeps them.
    let store = store_with_session();
    seed_lock_entries(&store);
    session(OWNER, "refreshed-token", 1).save(&store, "test-app").unwrap();
    assert_eq!(lock_entries_left(&store), 4);
}

#[tokio::test]
async fn an_app_sign_out_leaves_the_lock_signed_out() {
    let server = LockServer::new();
    let store = store_with_session();
    let client = screen_locked(&server, &store, false);
    seed_lock_entries(&store);
    // Sign-out from the screen lock needs no proof.
    client.sign_out_this_app(&store).await.unwrap();
    assert_eq!(client.lock_state(), LockState::SignedOut);
    assert!(client.session_key().is_err());
    assert_eq!(lock_entries_left(&store), 4);
}

async fn accepted_password(client: &Client, store: &dyn SecretStore) -> PasswordAccepted {
    match client
        .sign_in_on_device(EMAIL, password(PASSWORD), None, store)
        .await
        .unwrap()
    {
        SignInChallenge::PasswordAccepted(accepted) => accepted,
        other => panic!("expected an accepted password, got {other:?}"),
    }
}

#[tokio::test]
async fn the_strong_unlock_opens_a_closed_vault_clears_the_mark_and_ends_the_replaced_session() {
    let server = LockServer::new();
    let store = store_with_session();
    store.set(LOCK_VAULT_CLOSED, b"1").unwrap();
    seed_attempts(&store, 6, 9);
    store.reset_reads();
    let client = Client::new(config(false), server.clone()).unwrap();
    assert_eq!(client.start_from_store(&store).unwrap(), LockState::VaultClosed);

    let accepted = accepted_password(&client, &store).await;
    assert!(
        accepted.screen_check.is_none(),
        "no stretch while the password path is off"
    );
    assert_eq!(
        client.lock_state(),
        LockState::VaultClosed,
        "a proven password alone opens nothing"
    );
    assert_eq!(
        store.read_count_for(KEY_ENTRY),
        0,
        "zero reads of the key entry before the strong unlock"
    );

    let installed = client.unlock_known_device(accepted, &store).await.unwrap();
    assert_eq!(installed.owner(), OWNER);
    assert_eq!(client.lock_state(), LockState::Open);
    assert!(client.session_key().unwrap().is_current(&client));
    assert_eq!(
        entry(&store, LOCK_VAULT_CLOSED),
        None,
        "the mark is cleared in the same step"
    );
    assert_eq!(attempts(&store), None);
    assert_eq!(entry(&store, "session.token.test-app").unwrap(), NEW_TOKEN.as_bytes());
    // The session it replaced is ended, after the new one was proven and installed.
    assert_eq!(server.logged_out_tokens(), [format!("Bearer {STORED_TOKEN}")]);
    let paths = server.paths();
    assert_eq!(paths.last().map(String::as_str), Some(LOGOUT));
    assert_eq!(server.count(ME), 0, "no counter is read while the password path is off");
    assert_eq!(entry(&store, LOCK_SCREEN_CHECK), None);
}

#[tokio::test]
async fn a_failed_strong_unlock_leaves_the_vault_closed_and_marked() {
    let server = LockServer::new();
    let store = store_with_session();
    store.set(LOCK_VAULT_CLOSED, b"1").unwrap();
    let client = Client::new(config(false), server.clone()).unwrap();
    client.start_from_store(&store).unwrap();
    let accepted = accepted_password(&client, &store).await;
    server.refuse(KEY_PROOF_FINISH, 403, "key_proof_failed");
    assert!(client.unlock_known_device(accepted, &store).await.is_err());
    assert_eq!(client.lock_state(), LockState::VaultClosed);
    assert!(client.session_key().is_err());
    assert_eq!(entry(&store, LOCK_VAULT_CLOSED).as_deref(), Some(b"1".as_slice()));
    assert_eq!(
        entry(&store, "session.token.test-app").unwrap(),
        STORED_TOKEN.as_bytes()
    );
    assert_eq!(
        server.count(LOGOUT),
        0,
        "the stored session is not ended by a failed unlock"
    );
}

fn verifies(store: &dyn SecretStore, typed: &str) -> CheckOutcome {
    let record = ScreenCheckRecord::from_bytes(&entry(store, LOCK_SCREEN_CHECK).expect("a check record"));
    screen_lock::verify(&record, &password(typed), OWNER).unwrap()
}

#[tokio::test]
async fn a_sign_in_enrols_the_check_record_with_the_installed_session() {
    let server = LockServer::new();
    server.report_password_counter(3);
    let store = store_with_session();
    store.set(LOCK_VAULT_CLOSED, b"1").unwrap();
    // A record of the password before the change: it must not survive the sign-in.
    store.set(LOCK_SCREEN_CHECK, &record_for(OLD_PASSWORD)).unwrap();
    let client = Client::new(config(true), server.clone()).unwrap();
    client.start_from_store(&store).unwrap();

    let accepted = accepted_password(&client, &store).await;
    assert!(accepted.screen_check.is_some());
    let printed = format!("{accepted:?}");
    assert!(printed.contains("screen_check: Some(\"[REDACTED]\")"), "{printed}");
    assert_eq!(
        entry(&store, LOCK_SCREEN_CHECK).unwrap(),
        record_for(OLD_PASSWORD),
        "nothing is written before the session is installed"
    );

    client.unlock_known_device(accepted, &store).await.unwrap();
    let record = ScreenCheckRecord::from_bytes(&entry(&store, LOCK_SCREEN_CHECK).unwrap());
    assert_eq!(
        record.password_counter(),
        Some(3),
        "the server's counter at the enrolment"
    );
    assert_eq!(verifies(&store, PASSWORD), CheckOutcome::Match);
}

#[tokio::test]
async fn the_stretch_travels_through_the_authenticator_challenge() {
    let server = LockServer::new();
    server.ask_for_an_authenticator_code();
    let store = store_with_session();
    store.set(LOCK_VAULT_CLOSED, b"1").unwrap();
    let client = Client::new(config(true), server.clone()).unwrap();
    client.start_from_store(&store).unwrap();
    let challenge = match client
        .sign_in_on_device(EMAIL, password(PASSWORD), None, &store)
        .await
        .unwrap()
    {
        SignInChallenge::TwoFactor(challenge) => challenge,
        other => panic!("expected the authenticator step, got {other:?}"),
    };
    assert!(format!("{challenge:?}").contains("screen_check: Some(\"[REDACTED]\")"));
    let accepted = client.submit_two_factor(challenge, "123456".into()).await.unwrap();
    assert!(accepted.screen_check.is_some());
    client.unlock_known_device(accepted, &store).await.unwrap();
    assert_eq!(client.lock_state(), LockState::Open);
    let record = ScreenCheckRecord::from_bytes(&entry(&store, LOCK_SCREEN_CHECK).unwrap());
    assert_eq!(
        record.password_counter(),
        Some(0),
        "0 when the server reports no counter"
    );
    assert!(record.is_readable());
}

#[tokio::test]
async fn a_password_change_on_this_device_replaces_the_old_passwords_record() {
    const NEW_PASSWORD: &str = "a brand new password 2026";
    for password_path in [true, false] {
        let server = LockServer::new();
        server.report_password_counter(9);
        let store = store_with_session();
        store.set(LOCK_SCREEN_CHECK, &record_for(PASSWORD)).unwrap();
        let client = screen_locked(&server, &store, password_path);
        client.unlock_screen_platform_verified(&store).unwrap();
        // A screen lock that lands while the change is on its way (here: at its last
        // request before the new session is proven) stays locked.
        let locking = password_path.then(|| Arc::new(std::sync::atomic::AtomicBool::new(false)));
        let client = Arc::new(client);
        if let Some(locked) = locking.clone() {
            let screen = client.clone();
            server.on_request(move |path| {
                if path == CHANGE_FINISH {
                    screen.lock_screen().unwrap();
                    locked.store(true, std::sync::atomic::Ordering::SeqCst);
                }
            });
        }
        client
            .change_password(password(PASSWORD), password(NEW_PASSWORD), &store)
            .await
            .unwrap();
        let expected = if locking.is_some() {
            LockState::ScreenLocked
        } else {
            LockState::Open
        };
        assert_eq!(client.lock_state(), expected);
        assert!(client.session_key().unwrap().is_current(&client));
        if password_path {
            let record = ScreenCheckRecord::from_bytes(&entry(&store, LOCK_SCREEN_CHECK).unwrap());
            assert_eq!(record.password_counter(), Some(9));
            assert_eq!(verifies(&store, NEW_PASSWORD), CheckOutcome::Match);
        } else {
            assert_eq!(entry(&store, LOCK_SCREEN_CHECK), None, "the old record never survives");
        }
    }
}

#[tokio::test]
async fn a_changed_password_counter_deletes_the_record() {
    let server = LockServer::new();
    let store = store_with_session();
    let client = screen_locked(&server, &store, true);
    let seed = || {
        store.set(LOCK_SCREEN_CHECK, &record_for(PASSWORD)).unwrap();
        seed_attempts(&store, 2, 5);
    };
    // The server reports no counter: nothing to compare.
    seed();
    assert_eq!(
        client.refresh_lock_from_server(&store).await.unwrap(),
        LockState::ScreenLocked
    );
    assert_eq!(entry(&store, LOCK_SCREEN_CHECK).unwrap(), record_for(PASSWORD));
    // The same counter: kept.
    server.report_password_counter(0);
    client.refresh_lock_from_server(&store).await.unwrap();
    assert_eq!(entry(&store, LOCK_SCREEN_CHECK).unwrap(), record_for(PASSWORD));
    assert_eq!(attempts(&store), Some((2, 5)));
    // The password was changed on another device and this session survived: the record is
    // stale, and goes also for a person who only ever unlocks with platform verification.
    server.report_password_counter(1);
    assert_eq!(
        client.refresh_lock_from_server(&store).await.unwrap(),
        LockState::ScreenLocked
    );
    assert_eq!(entry(&store, LOCK_SCREEN_CHECK), None);
    assert_eq!(attempts(&store), None);
    // A closed vault asks the server nothing.
    client.lock_vault(&store).await.unwrap();
    let asked = server.count(ME);
    assert_eq!(
        client.refresh_lock_from_server(&store).await.unwrap(),
        LockState::VaultClosed
    );
    assert_eq!(server.count(ME), asked);
}

/// The store was not at hand when the refusal arrived, and the app quit before the host
/// recorded it: the next start is screen-locked, and its first contact closes it for good.
#[tokio::test]
async fn an_unrecorded_ended_session_closes_again_at_the_first_contact_after_a_restart() {
    let server = LockServer::new();
    let store = store_with_session();
    let client = screen_locked(&server, &store, false);
    server.end_the_session();
    assert!(client.execute(&beebeeb_api::routes::auth::me(), &()).await.is_err());
    assert_eq!(client.lock_state(), LockState::VaultClosed);
    assert_eq!(entry(&store, LOCK_VAULT_CLOSED), None, "nothing recorded it");
    drop(client);

    let restarted = screen_locked(&server, &store, false);
    assert_eq!(
        restarted.refresh_lock_from_server(&store).await.unwrap(),
        LockState::VaultClosed
    );
    assert!(restarted.session_key().is_err());
    assert_eq!(entry(&store, LOCK_VAULT_CLOSED).as_deref(), Some(b"1".as_slice()));
}

/// Credentials without a key (a password accepted for a sign-in, for any account) replace
/// the session of an app that held the key: its lock state must not go on describing it.
#[tokio::test]
async fn credentials_without_a_key_close_a_screen_locked_app() {
    let server = LockServer::new();
    let store = store_with_session();
    let client = screen_locked(&server, &store, true);
    store.set(LOCK_SCREEN_CHECK, &record_for(PASSWORD)).unwrap();
    client.set_authentication("another-token", "another-account").unwrap();
    assert_eq!(client.lock_state(), LockState::VaultClosed);
    // Neither screen proof opens what is left, and nothing was asked or written.
    assert!(client.unlock_screen_platform_verified(&store).is_err());
    assert!(
        client
            .unlock_screen_with_password(password(PASSWORD), &store, 1)
            .await
            .is_err()
    );
    assert_eq!(server.requests().len(), 0);
    assert_eq!(entry(&store, LOCK_SCREEN_CHECK).unwrap(), record_for(PASSWORD));
    assert_eq!(client.lock_state(), LockState::VaultClosed);
}

#[tokio::test]
async fn a_sign_out_from_a_closed_vault_ends_the_stored_session_with_its_own_token() {
    let server = LockServer::new();
    let store = store_with_session();
    store.set(LOCK_VAULT_CLOSED, b"1").unwrap();
    store.reset_reads();
    let client = Client::new(config(false), server.clone()).unwrap();
    assert_eq!(client.start_from_store(&store).unwrap(), LockState::VaultClosed);
    // A person who cannot unlock can leave: no proof, and the key entry is not read.
    client.sign_out_this_app(&store).await.unwrap();
    assert_eq!(client.lock_state(), LockState::SignedOut);
    assert_eq!(server.logged_out_tokens(), [format!("Bearer {STORED_TOKEN}")]);
    assert_eq!(entry(&store, "session.token.test-app"), None);
    assert_eq!(store.read_count_for(KEY_ENTRY), 0);

    // Half-way through an unlock (the password was accepted, nothing is installed yet) the
    // new session is in memory beside the stored one: leaving ends both.
    let server = LockServer::new();
    let store = store_with_session();
    store.set(LOCK_VAULT_CLOSED, b"1").unwrap();
    let client = Client::new(config(false), server.clone()).unwrap();
    client.start_from_store(&store).unwrap();
    client.set_authentication(NEW_TOKEN, OWNER).unwrap();
    client.sign_out_this_app(&store).await.unwrap();
    assert_eq!(client.lock_state(), LockState::SignedOut);
    assert_eq!(
        server.logged_out_tokens(),
        [format!("Bearer {NEW_TOKEN}"), format!("Bearer {STORED_TOKEN}")]
    );
}

#[tokio::test]
async fn a_strong_unlock_that_cannot_clear_the_mark_installs_nothing() {
    let server = LockServer::new();
    let store = FaultyStore::with_session();
    store.inner.set(LOCK_VAULT_CLOSED, b"1").unwrap();
    let client = Client::new(config(false), server.clone()).unwrap();
    client.start_from_store(&store).unwrap();
    let accepted = accepted_password(&client, &store).await;
    store.fail_deletes_of(LOCK_VAULT_CLOSED);
    assert!(matches!(
        client.unlock_known_device(accepted, &store).await,
        Err(AuthError::Secret(SecretError::Backend))
    ));
    // The mark is cleared in the step that installs, or the install does not happen.
    assert_eq!(client.lock_state(), LockState::VaultClosed);
    assert!(client.session_key().is_err());
    assert_eq!(entry(&store.inner, LOCK_VAULT_CLOSED).as_deref(), Some(b"1".as_slice()));
}

/// A lock that lands while the strong unlock is still on its way is not undone by it.
#[tokio::test]
async fn a_strong_unlock_overtaken_by_another_session_installs_nothing() {
    let server = LockServer::new();
    let store = Arc::new(store_with_session());
    store.set(LOCK_VAULT_CLOSED, b"1").unwrap();
    let client = Arc::new(Client::new(config(true), server.clone()).unwrap());
    client.start_from_store(store.as_ref()).unwrap();
    let accepted = accepted_password(&client, store.as_ref()).await;
    // While the unlock reads the password counter, the session in this process changes.
    let overtaking = client.clone();
    server.on_request(move |path| {
        if path == ME {
            overtaking
                .set_authentication("another-token", "another-account")
                .unwrap();
        }
    });
    assert!(matches!(
        client.unlock_known_device(accepted, store.as_ref()).await,
        Err(AuthError::Client(ClientError::StaleAccount))
    ));
    assert_eq!(client.lock_state(), LockState::VaultClosed);
    assert!(client.session_key().is_err());
    assert_eq!(
        entry(store.as_ref(), LOCK_VAULT_CLOSED).as_deref(),
        Some(b"1".as_slice())
    );
    assert_eq!(
        entry(store.as_ref(), "session.token.test-app").unwrap(),
        STORED_TOKEN.as_bytes(),
        "nothing was saved"
    );
    assert_eq!(entry(store.as_ref(), LOCK_SCREEN_CHECK), None);
}

/// A recovery is a strong install: it opens a closed vault, clears the mark, and the check
/// record of the password it replaced does not survive it.
#[tokio::test]
async fn a_recovered_session_opens_a_closed_vault_and_drops_the_old_passwords_record() {
    let transport = Arc::new(ScriptedTransport::json(
        200,
        serde_json::to_vec(&serde_json::json!({
            "session_token": "recovered-token", "user_id": OWNER, "key_state": "proven",
        }))
        .unwrap(),
    ));
    let store = store_with_session();
    store.set(LOCK_VAULT_CLOSED, b"1").unwrap();
    store.set(LOCK_SCREEN_CHECK, &[7u8; 102]).unwrap();
    seed_attempts(&store, 4, 9);
    let client = Client::new(config(true), transport).unwrap();
    assert_eq!(client.start_from_store(&store).unwrap(), LockState::VaultClosed);
    let attempt =
        crate::auth::RecoveryAttempt::from_parts_for_test("recovery-id", "holder-secret", None, RecoveryState::Ready);
    let recovered = client
        .complete_recovery(
            &attempt,
            EMAIL,
            RecoveryChanges {
                remove_authenticator: true,
                ..RecoveryChanges::default()
            },
        )
        .await
        .unwrap();
    client
        .install_recovered_session(
            &recovered,
            MasterKey::from_bytes([1; 32]),
            "http://localhost:8080",
            &store,
        )
        .unwrap();
    assert_eq!(client.lock_state(), LockState::Open);
    assert!(client.session_key().unwrap().is_current(&client));
    assert_eq!(entry(&store, LOCK_VAULT_CLOSED), None);
    assert_eq!(entry(&store, LOCK_SCREEN_CHECK), None);
    assert_eq!(attempts(&store), None);
    // The app can be locked again: the lock knows this session.
    client.lock_screen().unwrap();
    assert_eq!(client.lock_state(), LockState::ScreenLocked);
}
