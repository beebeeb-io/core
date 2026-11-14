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
    /// Just after the entry was written, where the others land just before.
    AfterSet(&'static str),
    /// Just before the entry is read.
    Get(&'static str),
}

/// A store that runs one call, once, at a chosen write: just before it reaches the entries,
/// or just after.
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
        self.inner.set(name, value)?;
        if let Write::AfterSet(at) = self.at
            && at == name
        {
            self.land(self.at);
        }
        Ok(())
    }

    fn get(&self, name: &str) -> Result<Option<Zeroizing<Vec<u8>>>, SecretError> {
        if let Write::Get(at) = self.at
            && at == name
        {
            self.land(self.at);
        }
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

/// The local half of a sign-out of the whole device, as `sign_out_whole_device` and the
/// coordinator run it: the process first, then the purge of the store.
fn device_sign_out(client: &Arc<Client>, store: &Arc<MemorySecretStore>) -> impl FnOnce() + Send + 'static {
    let (client, store) = (client.clone(), store.clone());
    move || {
        on_another_thread(move || async move {
            client.sign_out_device_authentication().unwrap();
            Session::sign_out_device(store.as_ref()).unwrap();
        })
    }
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

/// A sign-out of the whole device purges the store, and a change that was saving its new
/// session leaves nothing behind: no owner, no key entry, no token, no lock entry.
#[tokio::test]
async fn a_device_sign_out_in_the_tail_of_a_password_change_leaves_the_store_purged() {
    for at in [Write::Set(TOKEN_ENTRY), Write::Delete(LOCK_SCREEN_CHECK)] {
        let server = LockServer::new();
        let (client, store) = open_app(&server);
        let racing = RacingStore::new(store.clone(), at, device_sign_out(&client, &store));

        stale(
            client
                .change_password(password(PASSWORD), password(NEW_PASSWORD), &racing)
                .await,
        );
        assert!(racing.landed());
        assert_eq!(client.lock_state(), LockState::SignedOut);
        assert!(client.held_key().is_err());
        for name in [
            "session.owner",
            KEY_ENTRY,
            TOKEN_ENTRY,
            "session.api_url",
            LOCK_SCREEN_CHECK,
            LOCK_VAULT_CLOSED,
        ] {
            assert_eq!(entry(store.as_ref(), name), None, "{name}");
        }
    }
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
    let racing = RacingStore::new(store.clone(), Write::AfterSet(LOCK_VAULT_CLOSED), unlock);

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

/// Before the tail: a vault lock that lands between the last answer of a password change and
/// the step that sets its new credentials (here: in the store read that follows the answer)
/// is not taken as the state the change started in. The credentials are not set, no key is
/// proven or loaded again, and the vault stays closed.
#[tokio::test]
async fn a_vault_lock_before_the_tail_of_a_password_change_wins() {
    let server = LockServer::new();
    let (client, store) = open_app(&server);
    let racing = RacingStore::new(store.clone(), Write::Get("session.owner"), vault_lock(&client, &store));

    stale(
        client
            .change_password(password(PASSWORD), password(NEW_PASSWORD), &racing)
            .await,
    );
    assert!(racing.landed());
    assert_eq!(client.lock_state(), LockState::VaultClosed);
    assert!(client.held_key().is_err(), "a closed vault holds no key");
    assert!(client.account_id().is_err(), "the new credentials were not set");
    assert_eq!(
        server.count("/api/v1/auth/key-proof/start"),
        0,
        "nothing is proven for it"
    );
    assert_eq!(mark(&store).as_deref(), Some(b"1".as_slice()));
    assert_eq!(entry(store.as_ref(), TOKEN_ENTRY).unwrap(), STORED_TOKEN.as_bytes());
    assert_eq!(
        entry(store.as_ref(), LOCK_SCREEN_CHECK),
        None,
        "the old password's record is gone: the server has changed the password"
    );
}

/// A sign-out that lands there, after the change read the stored session, is not undone.
#[tokio::test]
async fn a_sign_out_before_the_tail_of_a_password_change_wins() {
    let server = LockServer::new();
    let (client, store) = open_app(&server);
    let racing = RacingStore::new(store.clone(), Write::Get(KEY_ENTRY), sign_out(&client, &store));

    stale(
        client
            .change_password(password(PASSWORD), password(NEW_PASSWORD), &racing)
            .await,
    );
    assert!(racing.landed());
    assert_eq!(client.lock_state(), LockState::SignedOut);
    assert!(client.held_key().is_err());
    assert!(client.account_id().is_err());
    assert_eq!(server.count("/api/v1/auth/key-proof/start"), 0);
    assert_eq!(entry(store.as_ref(), TOKEN_ENTRY), None, "nothing is saved again");
}

/// A screen lock asked for while a password change holds the app closed is refused there (a
/// closed vault is never screen-locked), and it is not lost: the change installs into a
/// locked screen.
#[tokio::test]
async fn a_screen_lock_asked_for_in_the_tail_of_a_password_change_is_applied() {
    let server = LockServer::new();
    let (client, store) = open_app(&server);
    let asking = client.clone();
    let racing = RacingStore::new(store.clone(), Write::Set(TOKEN_ENTRY), move || {
        assert_eq!(asking.lock_state(), LockState::VaultClosed);
        assert!(asking.lock_screen().is_err());
    });

    client
        .change_password(password(PASSWORD), password(NEW_PASSWORD), &racing)
        .await
        .unwrap();
    assert!(racing.landed());
    assert_eq!(client.lock_state(), LockState::ScreenLocked);
    assert!(client.held_key().unwrap().is_current(&client));
}

/// The same for a strong unlock: a screen lock asked for between its proof and its install
/// (here: in its save) is refused there and applied by that install.
#[tokio::test]
async fn a_screen_lock_asked_for_in_the_tail_of_a_strong_unlock_is_applied() {
    let server = LockServer::new();
    let store = Arc::new(store_with_session());
    store.set(LOCK_VAULT_CLOSED, b"1").unwrap();
    let client = Arc::new(Client::new(config(false), server.clone()).unwrap());
    assert_eq!(client.start_from_store(store.as_ref()).unwrap(), LockState::VaultClosed);
    let accepted = accepted_password(&client, store.as_ref()).await;
    let asking = client.clone();
    let racing = RacingStore::new(store.clone(), Write::Set(TOKEN_ENTRY), move || {
        assert_eq!(asking.lock_state(), LockState::VaultClosed);
        assert!(asking.lock_screen().is_err());
    });

    client.unlock_known_device(accepted, &racing).await.unwrap();
    assert!(racing.landed());
    assert_eq!(client.lock_state(), LockState::ScreenLocked);
    assert!(client.held_key().unwrap().is_current(&client), "the key is installed");
    assert_eq!(mark(&store), None, "the vault is open: only the screen is locked");
}

/// A screen lock that was refused on a closed vault BEFORE the proof began is not kept for a
/// later unlock: that unlock is the stronger and the newer proof, and the app opens.
#[tokio::test]
async fn a_screen_lock_refused_before_a_strong_unlock_began_is_not_applied() {
    let server = LockServer::new();
    let store = Arc::new(store_with_session());
    store.set(LOCK_VAULT_CLOSED, b"1").unwrap();
    let client = Arc::new(Client::new(config(false), server.clone()).unwrap());
    assert_eq!(client.start_from_store(store.as_ref()).unwrap(), LockState::VaultClosed);
    assert!(client.lock_screen().is_err(), "a closed vault is never screen-locked");

    let accepted = accepted_password(&client, store.as_ref()).await;
    client.unlock_known_device(accepted, store.as_ref()).await.unwrap();
    assert_eq!(client.lock_state(), LockState::Open);
}

/// Asking for the screen lock, and recording a refused request, is one step: while it runs,
/// no other thread can read or move the lock, so no install can land between the two.
#[test]
fn asking_for_the_screen_lock_is_one_step_with_the_lock() {
    let server = LockServer::new();
    let (client, _store) = open_app(&server);
    let other = client.clone();
    let (done, finished) = std::sync::mpsc::channel();
    let mut reader = None;

    let answer = client
        .ask_screen_lock(|flow| {
            reader = Some(std::thread::spawn(move || {
                let state = other.lock_state();
                done.send(state).unwrap();
            }));
            assert!(
                finished.recv_timeout(std::time::Duration::from_millis(300)).is_err(),
                "another thread read the lock while the screen lock was being asked for"
            );
            flow.lock(beebeeb_api::flows::LockLevel::Screen)
        })
        .unwrap();
    assert!(answer.is_ok());
    reader.unwrap().join().unwrap();
    assert_eq!(
        finished.recv().unwrap(),
        LockState::ScreenLocked,
        "the reader saw the lock only after the step: already screen-locked"
    );
}
