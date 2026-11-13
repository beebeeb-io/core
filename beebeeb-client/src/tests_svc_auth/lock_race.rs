//! What lands between the last answer of an install and the install itself: a vault lock or a
//! sign-out made from another thread wins. The key is not installed again, the lock is not
//! opened, and the store keeps what the later call wrote.
//!
//! The tail of an install is synchronous, so the only place another call can land in it is one
//! of its store writes: the store here runs a call on another thread, to its end, inside a
//! chosen write.

use beebeeb_api::flows::LockState;

use super::lock::*;
use super::*;
use crate::MemorySecretStore;
use crate::session::{LOCK_SCREEN_CHECK, LOCK_VAULT_CLOSED};

const TOKEN_ENTRY: &str = "session.token.test-app";
const NEW_PASSWORD: &str = "a brand new password 2026";

type Landing = Box<dyn FnOnce() + Send>;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Write {
    Set(&'static str),
    Delete(&'static str),
}

/// A store that runs one call, once, just before a chosen write reaches the entries.
struct RacingStore {
    inner: Arc<MemorySecretStore>,
    at: Write,
    landing: Mutex<Option<Landing>>,
}

impl RacingStore {
    fn new(inner: Arc<MemorySecretStore>, at: Write, landing: impl FnOnce() + Send + 'static) -> Self {
        Self {
            inner,
            at,
            landing: Mutex::new(Some(Box::new(landing))),
        }
    }

    fn land(&self, write: Write) {
        if write == self.at {
            let landing = self.landing.lock().unwrap().take();
            if let Some(landing) = landing {
                landing();
            }
        }
    }

    fn landed(&self) -> bool {
        self.landing.lock().unwrap().is_none()
    }
}

impl SecretStore for RacingStore {
    fn set(&self, name: &str, value: &[u8]) -> Result<(), SecretError> {
        if let Write::Set(at) = self.at
            && at == name
        {
            self.land(self.at);
        }
        self.inner.set(name, value)
    }

    fn get(&self, name: &str) -> Result<Option<Zeroizing<Vec<u8>>>, SecretError> {
        self.inner.get(name)
    }

    fn delete(&self, name: &str) -> Result<(), SecretError> {
        if let Write::Delete(at) = self.at
            && at == name
        {
            self.land(self.at);
        }
        self.inner.delete(name)
    }
}

/// Runs an async call of the client on another thread, to its end.
fn on_another_thread<F>(call: impl FnOnce() -> F + Send + 'static)
where
    F: std::future::Future<Output = ()>,
{
    std::thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(call());
    })
    .join()
    .unwrap();
}

fn vault_lock(client: &Arc<Client>, store: &Arc<MemorySecretStore>) -> impl FnOnce() + Send + 'static {
    let (client, store) = (client.clone(), store.clone());
    move || {
        on_another_thread(move || async move {
            let locked = client.lock_vault(store.as_ref()).await.unwrap();
            assert!(locked.survives_restart());
        })
    }
}

fn sign_out(client: &Arc<Client>, store: &Arc<MemorySecretStore>) -> impl FnOnce() + Send + 'static {
    let (client, store) = (client.clone(), store.clone());
    move || on_another_thread(move || async move { client.sign_out_this_app(store.as_ref()).await.unwrap() })
}

/// An open app with a stored session and an old check record.
fn open_app(server: &Arc<LockServer>) -> (Arc<Client>, Arc<MemorySecretStore>) {
    let store = Arc::new(store_with_session());
    store.set(LOCK_SCREEN_CHECK, &[7u8; 102]).unwrap();
    let client = screen_locked(server, store.as_ref(), false);
    client.unlock_screen_platform_verified(store.as_ref()).unwrap();
    assert_eq!(client.lock_state(), LockState::Open);
    (Arc::new(client), store)
}

fn mark(store: &MemorySecretStore) -> Option<Vec<u8>> {
    entry(store, LOCK_VAULT_CLOSED)
}

fn stale<T: std::fmt::Debug>(result: Result<T, AuthError>) {
    assert!(
        matches!(result, Err(AuthError::Client(ClientError::StaleAccount))),
        "{result:?}"
    );
}

/// A vault lock that lands after the last answer of a password change, in the save of the
/// new session or in the write of the check record before it, is not undone.
#[tokio::test]
async fn a_vault_lock_in_the_tail_of_a_password_change_wins() {
    for at in [Write::Set(TOKEN_ENTRY), Write::Delete(LOCK_SCREEN_CHECK)] {
        let server = LockServer::new();
        let (client, store) = open_app(&server);
        let racing = RacingStore::new(store.clone(), at, vault_lock(&client, &store));

        stale(
            client
                .change_password(password(PASSWORD), password(NEW_PASSWORD), &racing)
                .await,
        );
        assert!(racing.landed(), "the lock landed in the tail");
        assert_eq!(
            server.paths().iter().rev().nth(1).map(String::as_str),
            Some("/api/v1/auth/key-proof/finish"),
            "the lock landed after the last answer of the change: only its own sign-out followed"
        );
        assert_eq!(
            client.lock_state(),
            LockState::VaultClosed,
            "the lock is not opened again"
        );
        assert!(client.held_key().is_err(), "the key is not installed again");
        assert!(client.account_id().is_err(), "no credentials are left in the process");
        assert_eq!(mark(&store).as_deref(), Some(b"1".as_slice()));
        assert_eq!(
            entry(store.as_ref(), LOCK_SCREEN_CHECK),
            None,
            "the old password's record is gone: the server has changed the password"
        );
    }
}

/// A sign-out that lands there is not undone either: not in the process, and not in the store.
#[tokio::test]
async fn a_sign_out_in_the_tail_of_a_password_change_wins() {
    let server = LockServer::new();
    let (client, store) = open_app(&server);
    let racing = RacingStore::new(store.clone(), Write::Set(TOKEN_ENTRY), sign_out(&client, &store));

    stale(
        client
            .change_password(password(PASSWORD), password(NEW_PASSWORD), &racing)
            .await,
    );
    assert!(racing.landed());
    assert_eq!(client.lock_state(), LockState::SignedOut);
    assert!(client.held_key().is_err());
    assert!(client.account_id().is_err());
    assert_eq!(
        entry(store.as_ref(), TOKEN_ENTRY),
        None,
        "the session the change saved is removed again"
    );
    assert_eq!(Session::stored_owner_for_app(store.as_ref(), "test-app").unwrap(), None);
}

/// The strong unlock compares and installs in one step: a vault lock that lands in its save
/// wins, and the mark the unlock cleared a moment before is set again.
#[tokio::test]
async fn a_vault_lock_in_the_tail_of_a_strong_unlock_wins() {
    for at in [Write::Set(TOKEN_ENTRY), Write::Delete(LOCK_VAULT_CLOSED)] {
        let server = LockServer::new();
        let store = Arc::new(store_with_session());
        store.set(LOCK_VAULT_CLOSED, b"1").unwrap();
        let client = Arc::new(Client::new(config(false), server.clone()).unwrap());
        assert_eq!(client.start_from_store(store.as_ref()).unwrap(), LockState::VaultClosed);
        let accepted = accepted_password(&client, store.as_ref()).await;
        let racing = RacingStore::new(store.clone(), at, vault_lock(&client, &store));

        stale(client.unlock_known_device(accepted, &racing).await);
        assert!(racing.landed());
        assert_eq!(client.lock_state(), LockState::VaultClosed);
        assert!(client.held_key().is_err());
        assert!(client.account_id().is_err());
        assert_eq!(
            mark(&store).as_deref(),
            Some(b"1".as_slice()),
            "the lock is the later of the two: its mark stands"
        );
    }
}

/// The other order: a strong unlock that finishes while a vault lock is between its mark and
/// its key drop cleared that mark. The lock is the later of the two and writes it again.
#[tokio::test]
async fn a_vault_lock_overtaken_by_a_strong_unlock_keeps_its_mark() {
    let server = LockServer::new();
    let store = Arc::new(store_with_session());
    store.set(LOCK_VAULT_CLOSED, b"1").unwrap();
    let client = Arc::new(Client::new(config(false), server.clone()).unwrap());
    client.start_from_store(store.as_ref()).unwrap();
    let accepted = accepted_password(&client, store.as_ref()).await;
    let unlock = {
        let (client, store) = (client.clone(), store.clone());
        move || {
            on_another_thread(move || async move {
                client.unlock_known_device(accepted, store.as_ref()).await.unwrap();
                assert_eq!(client.lock_state(), LockState::Open);
                assert_eq!(mark(&store), None);
            })
        }
    };
    let racing = RacingStore::new(store.clone(), Write::Set(LOCK_VAULT_CLOSED), unlock);

    let locked = client.lock_vault(&racing).await.unwrap();
    assert!(racing.landed());
    assert!(locked.survives_restart());
    assert_eq!(client.lock_state(), LockState::VaultClosed);
    assert!(client.held_key().is_err());
    assert_eq!(mark(&store).as_deref(), Some(b"1".as_slice()));
}

/// A recovery install is for the account generation it starts at, like every strong install.
#[tokio::test]
async fn a_recovered_install_overtaken_by_a_vault_lock_installs_nothing() {
    let completing = Client::new(
        config(false),
        Arc::new(ScriptedTransport::json(
            200,
            serde_json::to_vec(&serde_json::json!({
                "session_token": "recovered-token", "user_id": OWNER, "key_state": "proven",
            }))
            .unwrap(),
        )),
    )
    .unwrap();
    let attempt =
        crate::auth::RecoveryAttempt::from_parts_for_test("recovery-id", "holder-secret", None, RecoveryState::Ready);
    let recovered = completing
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
    let server = LockServer::new();
    let (client, store) = open_app(&server);
    let racing = RacingStore::new(store.clone(), Write::Set(TOKEN_ENTRY), vault_lock(&client, &store));

    stale(client.install_recovered_session(
        &recovered,
        MasterKey::from_bytes([1; 32]),
        "https://api.example",
        &racing,
    ));
    assert!(racing.landed());
    assert_eq!(client.lock_state(), LockState::VaultClosed);
    assert!(client.held_key().is_err());
    assert_eq!(mark(&store).as_deref(), Some(b"1".as_slice()));
}
