//! App lock (the per-device setting of the screen level): the start, the automatic lock and
//! the rule for turning it off.

use beebeeb_api::flows::LockState;

use super::lock::*;
use super::*;
use crate::MemorySecretStore;
use crate::auth::AppLockProof;
use crate::session::{LOCK_APP_LOCK, LOCK_ASK_AT_START, LOCK_SCREEN_CHECK, LOCK_VAULT_CLOSED};

const NOW: u64 = 1_800_000_000_000;

#[test]
fn a_start_with_app_lock_off_is_open_with_the_key_loaded() {
    let store = store_with_session();
    store.set(LOCK_APP_LOCK, b"0").unwrap();
    let client = Client::new(config(false), LockServer::new()).unwrap();
    assert_eq!(client.start_from_store(&store).unwrap(), LockState::Open);
    assert!(client.held_key().unwrap().is_current(&client));
    assert_eq!(client.account_id().unwrap(), OWNER);
    assert!(!client.app_lock(&store));
}

#[test]
fn an_absent_or_unreadable_app_lock_starts_screen_locked() {
    type Arrange = fn(&FaultyStore);
    let cases: [(&str, Arrange); 4] = [
        ("there is no entry", |_| {}),
        ("it is on", |store| store.inner.set(LOCK_APP_LOCK, b"1").unwrap()),
        ("it is not a flag", |store| {
            store.inner.set(LOCK_APP_LOCK, b"off").unwrap()
        }),
        ("it cannot be read", |store| store.fail_reads_of(LOCK_APP_LOCK)),
    ];
    for (name, arrange) in cases {
        let store = FaultyStore::with_session();
        arrange(&store);
        let client = Client::new(config(false), LockServer::new()).unwrap();
        assert_eq!(
            client.start_from_store(&store).unwrap(),
            LockState::ScreenLocked,
            "{name}"
        );
        assert!(client.held_key().unwrap().is_current(&client), "{name}");
        assert!(client.app_lock(&store), "{name}");
    }
}

#[test]
fn app_lock_off_never_opens_a_closed_start() {
    for closing in [LOCK_ASK_AT_START, LOCK_VAULT_CLOSED] {
        let store = FaultyStore::with_session();
        store.inner.set(LOCK_APP_LOCK, b"0").unwrap();
        store.inner.set(closing, b"1").unwrap();
        store.inner.reset_reads();
        let client = Client::new(config(false), LockServer::new()).unwrap();
        assert_eq!(
            client.start_from_store(&store).unwrap(),
            LockState::VaultClosed,
            "{closing}"
        );
        assert_eq!(store.inner.read_count_for(KEY_ENTRY), 0, "{closing}");
        assert_eq!(
            client.lock_after_away(&store).unwrap(),
            LockState::VaultClosed,
            "{closing}"
        );
    }
}

#[test]
fn the_automatic_lock_follows_app_lock_and_lock_now_always_locks() {
    let store = FaultyStore::with_session();
    store.inner.set(LOCK_APP_LOCK, b"0").unwrap();
    let client = Client::new(config(false), LockServer::new()).unwrap();
    assert_eq!(client.lock_after_away(&store).unwrap(), LockState::SignedOut);
    assert_eq!(client.start_from_store(&store).unwrap(), LockState::Open);
    // App lock off: away changes nothing.
    assert_eq!(client.lock_after_away(&store).unwrap(), LockState::Open);
    // "Lock now" locks all the same.
    client.lock_screen().unwrap();
    assert_eq!(client.lock_state(), LockState::ScreenLocked);
    client.unlock_screen_platform_verified(&store).unwrap();
    // App lock on, not a flag, or unreadable: away locks the screen, and again changes nothing.
    type Arrange = fn(&FaultyStore);
    let cases: [(&str, Arrange); 3] = [
        ("on", |store| store.inner.set(LOCK_APP_LOCK, b"1").unwrap()),
        ("not a flag", |store| store.inner.set(LOCK_APP_LOCK, b"").unwrap()),
        ("unreadable", |store| store.fail_reads_of(LOCK_APP_LOCK)),
    ];
    for (name, arrange) in cases {
        arrange(&store);
        assert_eq!(
            client.lock_after_away(&store).unwrap(),
            LockState::ScreenLocked,
            "{name}"
        );
        assert_eq!(
            client.lock_after_away(&store).unwrap(),
            LockState::ScreenLocked,
            "{name}"
        );
        client.unlock_screen_platform_verified(&store).unwrap();
    }
}

#[tokio::test]
async fn turning_app_lock_off_needs_a_fresh_screen_proof() {
    let server = LockServer::new();
    let store = &FaultyStore::with_session();
    let client = screen_locked(&server, store, true);
    let set = |on, proof| client.set_app_lock(on, proof, store, NOW);
    let typed = |text: &str| Some(AppLockProof::Password(password(text)));
    let stored = || entry(store, LOCK_APP_LOCK);
    // Not from the screen lock, either way.
    for on in [true, false] {
        assert!(matches!(
            set(on, Some(AppLockProof::PlatformVerified)).await,
            Err(AuthError::InvalidTransition {
                step: "app lock",
                requirement: "the app is open",
            })
        ));
    }
    client.unlock_screen_platform_verified(store).unwrap();
    // Off without a proof: refused, nothing checked, nothing written.
    assert!(matches!(
        set(false, None).await,
        Err(AuthError::InvalidTransition {
            step: "app lock",
            requirement: "a proof the screen unlock accepts, given for this change",
        })
    ));
    assert_eq!(server.requests().len(), 0);
    assert_eq!(stored(), None);
    assert!(client.app_lock(store), "on by default");
    // A wrong password is a counted try and writes nothing.
    assert!(matches!(
        set(false, typed("wrong")).await,
        Err(AuthError::PasswordWrong {
            local_check_off: false,
            ..
        })
    ));
    assert_eq!(attempts(store).map(|(failures, _)| failures), Some(1));
    assert_eq!(stored(), None);
    // The password, proven to the server: off, and the next start is open.
    set(false, typed(PASSWORD)).await.unwrap();
    assert_eq!(stored().as_deref(), Some(b"0".as_slice()));
    assert!(!client.app_lock(store));
    let restarted = Client::new(config(true), server.clone()).unwrap();
    assert_eq!(restarted.start_from_store(store).unwrap(), LockState::Open);
    // On asks for nothing.
    let asked = server.requests().len();
    set(true, None).await.unwrap();
    assert_eq!(stored().as_deref(), Some(b"1".as_slice()));
    assert_eq!(server.requests().len(), asked, "turning it on asks for nothing");
    // Offline the local check is a proof the screen unlock accepts.
    store.set(LOCK_SCREEN_CHECK, &record_for(PASSWORD)).unwrap();
    server.go_offline(true);
    set(false, typed(PASSWORD)).await.unwrap();
    assert_eq!(stored().as_deref(), Some(b"0".as_slice()));
    // Platform verification is one too.
    set(true, None).await.unwrap();
    set(false, Some(AppLockProof::PlatformVerified)).await.unwrap();
    assert_eq!(stored().as_deref(), Some(b"0".as_slice()));
    // The proof never shows in a log.
    assert_eq!(format!("{:?}", typed(PASSWORD)), "Some(Password(..))");
}

#[tokio::test]
async fn app_lock_off_by_platform_verification_needs_no_password_path() {
    let server = LockServer::new();
    let store = store_with_session();
    let client = screen_locked(&server, &store, false);
    client.unlock_screen_platform_verified(&store).unwrap();
    assert!(matches!(
        client
            .set_app_lock(false, Some(AppLockProof::Password(password(PASSWORD))), &store, NOW)
            .await,
        Err(AuthError::PasswordCheckUnavailable)
    ));
    assert_eq!(entry(&store, LOCK_APP_LOCK), None);
    client
        .set_app_lock(false, Some(AppLockProof::PlatformVerified), &store, NOW)
        .await
        .unwrap();
    assert_eq!(entry(&store, LOCK_APP_LOCK).as_deref(), Some(b"0".as_slice()));
    assert_eq!(server.requests().len(), 0, "no proof route is called");
}

#[test]
fn an_interrupted_sign_out_never_leaves_app_lock_off_for_the_next_account() {
    // The sign-out deletes the app lock entry first: stopped after any one delete, it is gone.
    for deletes_that_succeed in 1..=3 {
        let store = CrashingDeleteStore::new(store_with_session(), deletes_that_succeed);
        store.set(LOCK_APP_LOCK, b"0").unwrap();
        let _ = Session::sign_out_device(&store);
        assert_eq!(
            entry(&store, LOCK_APP_LOCK),
            None,
            "after {deletes_that_succeed} delete(s)"
        );
    }
    // And whatever is left behind, the first save of an account clears every lock entry.
    let store = MemorySecretStore::default();
    for name in [LOCK_APP_LOCK, LOCK_ASK_AT_START, LOCK_VAULT_CLOSED, LOCK_SCREEN_CHECK] {
        store.set(name, b"0").unwrap();
    }
    session("account-b", "token-b", 1).save(&store, "test-app").unwrap();
    for name in [LOCK_APP_LOCK, LOCK_ASK_AT_START, LOCK_VAULT_CLOSED, LOCK_SCREEN_CHECK] {
        assert_eq!(entry(&store, name), None, "{name} survived the first save");
    }
    let client = Client::new(config(false), LockServer::new()).unwrap();
    assert_eq!(client.start_from_store(&store).unwrap(), LockState::ScreenLocked);
}

/// A store whose deletes stop working after `allowed` of them: a sign-out cut short.
struct CrashingDeleteStore {
    inner: MemorySecretStore,
    allowed: std::sync::atomic::AtomicUsize,
}

impl CrashingDeleteStore {
    fn new(inner: MemorySecretStore, allowed: usize) -> Self {
        Self {
            inner,
            allowed: allowed.into(),
        }
    }
}

impl SecretStore for CrashingDeleteStore {
    fn set(&self, name: &str, value: &[u8]) -> Result<(), SecretError> {
        self.inner.set(name, value)
    }
    fn get(&self, name: &str) -> Result<Option<Zeroizing<Vec<u8>>>, SecretError> {
        self.inner.get(name)
    }
    fn delete(&self, name: &str) -> Result<(), SecretError> {
        use std::sync::atomic::Ordering::SeqCst;
        if self.allowed.load(SeqCst) == 0 {
            return Err(SecretError::Backend);
        }
        self.allowed.fetch_sub(1, SeqCst);
        self.inner.delete(name)
    }
}

#[tokio::test]
async fn a_screen_lock_during_the_proof_wait_stops_app_lock_from_turning_off() {
    let server = LockServer::new();
    let store = store_with_session();
    let client = Arc::new(screen_locked(&server, &store, true));
    client.unlock_screen_platform_verified(&store).unwrap();
    let locking = client.clone();
    server.on_request(move |_| {
        locking.lock_screen().unwrap();
    });
    let result = client
        .set_app_lock(false, Some(AppLockProof::Password(password(PASSWORD))), &store, NOW)
        .await;
    assert!(
        matches!(
            result,
            Err(AuthError::InvalidTransition {
                step: "app lock",
                requirement: "the app is open"
            })
        ),
        "{result:?}"
    );
    assert_eq!(client.lock_state(), LockState::ScreenLocked);
    assert_eq!(
        entry(&store, LOCK_APP_LOCK),
        None,
        "nothing written while screen-locked"
    );
}

#[tokio::test]
async fn a_wrong_password_as_the_app_lock_proof_carries_the_wait_and_the_local_check_off() {
    use beebeeb_core::screen_lock::{LOCAL_CHECK_OFF_AT, wait_after_ms};
    let server = LockServer::new();
    let store = store_with_session();
    let client = screen_locked(&server, &store, true);
    client.unlock_screen_platform_verified(&store).unwrap();
    let wrong = |now| client.set_app_lock(false, Some(AppLockProof::Password(password("wrong"))), &store, now);
    let first = wrong(NOW).await;
    assert!(
        matches!(first, Err(AuthError::PasswordWrong { wait_ms, local_check_off: false }) if wait_ms == wait_after_ms(1)),
        "{first:?}"
    );
    seed_attempts(&store, LOCAL_CHECK_OFF_AT - 1, NOW);
    let tenth = wrong(NOW + wait_after_ms(LOCAL_CHECK_OFF_AT - 1) + 1).await;
    assert!(
        matches!(
            tenth,
            Err(AuthError::PasswordWrong {
                local_check_off: true,
                ..
            })
        ),
        "{tenth:?}"
    );
    assert_eq!(entry(&store, LOCK_APP_LOCK), None);
}
