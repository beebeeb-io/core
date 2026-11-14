//! The password path of the screen lock: the wrong-try accounting, online first, the local
//! record only when the server cannot be reached, and the start setting.
//!
//! Every OPAQUE finish, enrolment and local check here is a real canonical Argon2id run.

use beebeeb_api::{Header, flows::LockState};
use beebeeb_core::screen_lock::{self, CheckOutcome, ScreenCheckRecord};

use super::lock::*;
use super::*;
use crate::auth::ScreenUnlock;
use crate::session::{LOCK_ASK_AT_START, LOCK_SCREEN_CHECK, LOCK_VAULT_CLOSED};

const NOW: u64 = 1_800_000_000_000;
const HOUR: u64 = 3_600_000;

struct Setup {
    server: Arc<LockServer>,
    store: Arc<FaultyStore>,
    client: Arc<Client>,
}

/// A screen-locked client with the password path on.
fn setup() -> Setup {
    let server = LockServer::new();
    let store = Arc::new(FaultyStore::with_session());
    let client = Arc::new(screen_locked(&server, store.as_ref(), true));
    Setup { server, store, client }
}

impl Setup {
    async fn unlock(&self, typed: &str, now_ms: u64) -> Result<ScreenUnlock, AuthError> {
        self.client
            .unlock_screen_with_password(password(typed), self.store.as_ref(), now_ms)
            .await
    }

    fn record(&self) -> Option<Vec<u8>> {
        entry(self.store.as_ref(), LOCK_SCREEN_CHECK)
    }

    fn seed_record(&self, typed: &'static str) {
        self.store.set(LOCK_SCREEN_CHECK, &record_for(typed)).unwrap();
    }
}

#[tokio::test]
async fn the_right_password_online_opens_and_writes_the_record() {
    let s = setup();
    s.server.report_password_counter(5);
    seed_attempts(s.store.as_ref(), 2, NOW - 10);
    assert_eq!(s.unlock(PASSWORD, NOW).await.unwrap(), ScreenUnlock::Opened);
    assert_eq!(s.client.lock_state(), LockState::Open);
    assert_eq!(s.server.paths(), [PROOF_START, PROOF_FINISH]);
    let record = ScreenCheckRecord::from_bytes(&s.record().expect("the record is written"));
    assert_eq!(record.password_counter(), Some(5));
    assert_eq!(attempts(s.store.as_ref()), None, "a success resets the count");
    // Only the OPAQUE messages travel: never the password.
    for request in s.server.requests() {
        assert!(
            !request
                .body()
                .windows(PASSWORD.len())
                .any(|window| window == PASSWORD.as_bytes())
        );
    }
    // An open app has no screen to unlock.
    assert!(matches!(
        s.unlock(PASSWORD, NOW).await,
        Err(AuthError::InvalidTransition {
            step: "screen unlock",
            ..
        })
    ));
}

#[tokio::test]
async fn a_wrong_password_online_is_counted_once_and_never_sent() {
    let s = setup();
    s.seed_record(PASSWORD);
    assert_eq!(
        s.unlock("not the password", NOW).await.unwrap(),
        ScreenUnlock::Wrong { wait_ms: 0 }
    );
    assert_eq!(s.client.lock_state(), LockState::ScreenLocked);
    assert_eq!(
        attempts(s.store.as_ref()),
        Some((1, NOW)),
        "one typed password counts once"
    );
    // It failed on this device, in the OPAQUE finish: the server never saw a proof.
    assert_eq!(s.server.paths(), [PROOF_START]);
    assert_eq!(s.record().unwrap(), record_for(PASSWORD), "the record is untouched");
}

/// Section 3.7: when the server can be reached the password is proven online, so a stale
/// record is never what opens the screen of a connected device.
#[tokio::test]
async fn a_stale_record_never_opens_a_connected_device() {
    let s = setup();
    // The password was changed elsewhere and this session survived: the record still holds
    // the old password, and the server reports the counter the record was made at.
    s.seed_record(OLD_PASSWORD);
    s.server.report_password_counter(1);
    assert_eq!(
        s.unlock(OLD_PASSWORD, NOW).await.unwrap(),
        ScreenUnlock::Wrong { wait_ms: 0 },
        "the old password matches the record, and the server refuses it"
    );
    assert_eq!(s.client.lock_state(), LockState::ScreenLocked);
    assert_eq!(s.record().unwrap(), record_for(OLD_PASSWORD));
    // The new password is accepted by the server and replaces the record.
    assert_eq!(s.unlock(PASSWORD, NOW + 1).await.unwrap(), ScreenUnlock::Opened);
    let record = ScreenCheckRecord::from_bytes(&s.record().unwrap());
    assert_eq!(record.password_counter(), Some(1));
    assert_ne!(s.record().unwrap(), record_for(OLD_PASSWORD));
}

/// The record's counter is not authenticated, so it is never a reason to keep a record: a
/// record that carries the server's counter but was made for another password is replaced by
/// one for the password the server has just accepted.
#[tokio::test]
async fn an_online_unlock_makes_the_record_again_whatever_its_counter_says() {
    for counter in [Some(0), None] {
        let s = setup();
        // Made for another password, at the counter the server reports.
        s.seed_record(OLD_PASSWORD);
        if let Some(counter) = counter {
            s.server.report_password_counter(counter);
        }
        assert_eq!(s.unlock(PASSWORD, NOW).await.unwrap(), ScreenUnlock::Opened);
        let record = ScreenCheckRecord::from_bytes(&s.record().unwrap());
        assert!(record.is_readable());
        assert_eq!(
            screen_lock::verify(&record, &password(PASSWORD), OWNER).unwrap(),
            CheckOutcome::Match,
            "{counter:?}: the record is the accepted password's"
        );
    }
}

/// One check at a time: the count is read, written and restored around requests, so a second
/// try while one is on its way checks nothing and costs nothing.
#[tokio::test]
async fn a_second_try_while_one_is_on_its_way_checks_nothing() {
    let s = setup();
    s.seed_record(PASSWORD);
    let gate = s.server.hold_requests();
    let first = s.unlock("wrong", NOW);
    let second = async {
        // The first try is at the server by now.
        tokio::task::yield_now().await;
        let refused = s.unlock(PASSWORD, NOW).await;
        let seen = (s.server.requests().len(), attempts(s.store.as_ref()));
        gate.notify_one();
        (refused, seen)
    };
    let (first, (second, seen_meanwhile)) = tokio::join!(first, second);
    assert!(matches!(
        second,
        Err(AuthError::InvalidTransition {
            step: "password check",
            ..
        })
    ));
    assert_eq!(
        seen_meanwhile,
        (0, Some((1, NOW))),
        "one try counted, and the second sent nothing"
    );
    assert_eq!(first.unwrap(), ScreenUnlock::Wrong { wait_ms: 0 });
    assert_eq!(attempts(s.store.as_ref()), Some((1, NOW)));
    assert_eq!(s.client.lock_state(), LockState::ScreenLocked);
}

#[tokio::test]
async fn offline_the_record_decides() {
    let s = setup();
    s.seed_record(PASSWORD);
    s.server.go_offline(true);
    seed_attempts(s.store.as_ref(), 1, NOW - 10);
    assert_eq!(s.unlock(PASSWORD, NOW).await.unwrap(), ScreenUnlock::Opened);
    assert_eq!(s.client.lock_state(), LockState::Open);
    assert_eq!(attempts(s.store.as_ref()), None);
    assert_eq!(s.server.paths(), [PROOF_START], "the server was tried first");
    assert_eq!(s.record().unwrap(), record_for(PASSWORD));
}

#[tokio::test]
async fn offline_wrong_tries_run_into_the_wait_and_the_wait_checks_nothing() {
    let s = setup();
    s.seed_record(PASSWORD);
    s.server.go_offline(true);
    seed_attempts(s.store.as_ref(), 4, NOW - 1);
    // The fifth wrong try in a row: 30 seconds before the next one.
    assert_eq!(
        s.unlock("wrong", NOW).await.unwrap(),
        ScreenUnlock::Wrong { wait_ms: 30_000 }
    );
    assert_eq!(attempts(s.store.as_ref()), Some((5, NOW)));
    // During the wait nothing is checked, online or locally, not even the right password.
    let sent = s.server.requests().len();
    assert_eq!(
        s.unlock(PASSWORD, NOW + 1).await.unwrap(),
        ScreenUnlock::Wait { wait_ms: 29_999 }
    );
    s.server.go_offline(false);
    assert_eq!(
        s.unlock(PASSWORD, NOW + 29_999).await.unwrap(),
        ScreenUnlock::Wait { wait_ms: 1 },
        "the wait gates the online check too"
    );
    assert_eq!(s.server.requests().len(), sent);
    assert_eq!(
        attempts(s.store.as_ref()),
        Some((5, NOW)),
        "a refused try is not a wrong try"
    );
    assert_eq!(s.client.lock_state(), LockState::ScreenLocked);
    // The wait is over: the next wrong try is the sixth.
    s.server.go_offline(true);
    assert_eq!(
        s.unlock("wrong", NOW + 30_000).await.unwrap(),
        ScreenUnlock::Wrong { wait_ms: 60_000 }
    );
    assert_eq!(attempts(s.store.as_ref()), Some((6, NOW + 30_000)));
}

#[tokio::test]
async fn the_tenth_wrong_try_turns_the_local_check_off_until_the_server_accepts_the_password() {
    let s = setup();
    s.seed_record(PASSWORD);
    s.server.go_offline(true);
    seed_attempts(s.store.as_ref(), 9, NOW - HOUR);
    assert_eq!(s.unlock("wrong", NOW).await.unwrap(), ScreenUnlock::LocalCheckOff);
    assert_eq!(s.record(), None, "the record is deleted");
    assert_eq!(attempts(s.store.as_ref()), Some((10, NOW)));
    // The lockout removes the offline password path only: the key and the session stay.
    assert!(s.client.held_key().is_ok());
    assert_eq!(s.client.lock_state(), LockState::ScreenLocked);
    // Offline, even the right password opens nothing now, and it is not a wrong try.
    assert_eq!(
        s.unlock(PASSWORD, NOW + HOUR).await.unwrap(),
        ScreenUnlock::OfflineNoRecord
    );
    assert_eq!(attempts(s.store.as_ref()), Some((10, NOW)));
    // A record put back by hand while the local check is off is deleted, not used.
    s.seed_record(PASSWORD);
    assert_eq!(
        s.unlock(PASSWORD, NOW + HOUR).await.unwrap(),
        ScreenUnlock::OfflineNoRecord
    );
    assert_eq!(s.record(), None);
    // Online, the server accepts the password: open, and the offline path is back.
    s.server.go_offline(false);
    assert_eq!(s.unlock(PASSWORD, NOW + HOUR).await.unwrap(), ScreenUnlock::Opened);
    assert!(s.record().is_some());
    assert_eq!(attempts(s.store.as_ref()), None);
}

#[tokio::test]
async fn offline_without_a_usable_record_is_not_a_wrong_try() {
    let s = setup();
    s.server.go_offline(true);
    assert_eq!(s.unlock(PASSWORD, NOW).await.unwrap(), ScreenUnlock::OfflineNoRecord);
    assert_eq!(attempts(s.store.as_ref()), None);
    // A record this version cannot read (another version byte) is deleted and treated as absent.
    let mut other_version = record_for(PASSWORD);
    other_version[0] = 2;
    s.store.set(LOCK_SCREEN_CHECK, &other_version).unwrap();
    seed_attempts(s.store.as_ref(), 3, NOW - 5);
    assert_eq!(s.unlock(PASSWORD, NOW).await.unwrap(), ScreenUnlock::OfflineNoRecord);
    assert_eq!(s.record(), None);
    assert_eq!(
        attempts(s.store.as_ref()),
        Some((3, NOW - 5)),
        "the count is what it was"
    );
    assert_eq!(s.client.lock_state(), LockState::ScreenLocked);
}

#[tokio::test]
async fn the_try_is_counted_before_any_check_runs() {
    let s = setup();
    seed_attempts(s.store.as_ref(), 2, NOW - 7);
    // What the store holds at the moment the first check reaches the server.
    let seen = Arc::new(Mutex::new(Vec::new()));
    let (store, log) = (s.store.clone(), seen.clone());
    s.server.on_request(move |path| {
        log.lock().unwrap().push((path.to_owned(), attempts(store.as_ref())));
    });
    s.server.reply(PROOF_START, Reply::Offline);
    assert_eq!(s.unlock(PASSWORD, NOW).await.unwrap(), ScreenUnlock::OfflineNoRecord);
    // A process ended mid-check would have left this count behind: no free try.
    assert_eq!(*seen.lock().unwrap(), [(PROOF_START.to_owned(), Some((3, NOW)))]);
    assert_eq!(
        attempts(s.store.as_ref()),
        Some((2, NOW - 7)),
        "nothing was judged: restored"
    );
}

#[tokio::test]
async fn a_count_that_cannot_be_written_refuses_the_try() {
    let s = setup();
    s.seed_record(PASSWORD);
    s.store.fail_writes_of(crate::session::LOCK_ATTEMPTS);
    assert!(matches!(
        s.unlock(PASSWORD, NOW).await,
        Err(AuthError::Secret(SecretError::Backend))
    ));
    assert_eq!(s.server.requests().len(), 0, "no check ran");
    assert_eq!(s.client.lock_state(), LockState::ScreenLocked);
    // The same for a count that cannot be read.
    let s = setup();
    s.store.fail_reads_of(crate::session::LOCK_ATTEMPTS);
    assert!(matches!(
        s.unlock(PASSWORD, NOW).await,
        Err(AuthError::Secret(SecretError::Backend))
    ));
    assert_eq!(s.server.requests().len(), 0);
    assert_eq!(s.client.lock_state(), LockState::ScreenLocked);
}

#[tokio::test]
async fn the_servers_limit_is_not_a_wrong_try() {
    let s = setup();
    s.seed_record(PASSWORD);
    seed_attempts(s.store.as_ref(), 1, NOW - 9);
    s.server.reply(
        PROOF_START,
        Reply::Status(
            429,
            serde_json::json!({ "error": "password_proof_limited", "limit": "session" }),
            vec![Header::new("Retry-After", "17")],
        ),
    );
    assert_eq!(
        s.unlock(PASSWORD, NOW).await.unwrap(),
        ScreenUnlock::ServerLimit { wait_ms: Some(17_000) }
    );
    assert_eq!(attempts(s.store.as_ref()), Some((1, NOW - 9)));
    assert_eq!(
        s.client.lock_state(),
        LockState::ScreenLocked,
        "the record is not asked instead"
    );
    // The same at the finish, with no wait named.
    s.server.answer_normally(PROOF_START);
    s.server.refuse(PROOF_FINISH, 429, "password_proof_limited");
    assert_eq!(
        s.unlock(PASSWORD, NOW).await.unwrap(),
        ScreenUnlock::ServerLimit { wait_ms: None }
    );
    assert_eq!(attempts(s.store.as_ref()), Some((1, NOW - 9)));
    assert_eq!(s.client.lock_state(), LockState::ScreenLocked);
}

#[tokio::test]
async fn a_401_on_a_live_session_is_the_servers_limit_and_not_a_wrong_try() {
    for leg in [PROOF_START, PROOF_FINISH] {
        let s = setup();
        s.seed_record(PASSWORD);
        let mut events = s.client.events().subscribe();
        s.server.refuse(leg, 401, "unauthorized");
        assert_eq!(
            s.unlock(PASSWORD, NOW).await.unwrap(),
            ScreenUnlock::ServerLimit { wait_ms: None },
            "{leg}"
        );
        assert_eq!(attempts(s.store.as_ref()), None, "{leg}");
        assert_eq!(s.client.lock_state(), LockState::ScreenLocked, "{leg}");
        assert!(s.client.held_key().is_ok(), "{leg}");
        assert_eq!(s.server.count(ME), 1, "core asks whether the session still lives");
        assert_eq!(
            count_of(&drained(&mut events), &EngineEvent::SessionExpired),
            0,
            "{leg}"
        );
        assert_eq!(s.record().unwrap(), record_for(PASSWORD));
    }
}

#[tokio::test]
async fn a_401_on_an_ended_session_closes_the_vault_and_is_not_a_wrong_try() {
    for leg in [PROOF_START, PROOF_FINISH] {
        let s = setup();
        s.seed_record(PASSWORD);
        seed_attempts(s.store.as_ref(), 2, NOW - 3);
        let mut events = s.client.events().subscribe();
        if leg == PROOF_START {
            s.server.end_the_session();
        } else {
            // The session ends between the two legs.
            let server = s.server.clone();
            s.server.on_request(move |path| {
                if path == PROOF_FINISH {
                    server.end_the_session();
                }
            });
        }
        assert_eq!(
            s.unlock(PASSWORD, NOW).await.unwrap(),
            ScreenUnlock::SessionEnded,
            "{leg}"
        );
        assert_eq!(s.client.lock_state(), LockState::VaultClosed, "{leg}");
        assert!(s.client.held_key().is_err(), "{leg}");
        assert_eq!(s.record(), None, "the check record is deleted");
        assert_eq!(attempts(s.store.as_ref()), None);
        assert_eq!(
            entry(s.store.as_ref(), LOCK_VAULT_CLOSED).as_deref(),
            Some(b"1".as_slice())
        );
        assert_eq!(
            count_of(&drained(&mut events), &EngineEvent::SessionExpired),
            1,
            "{leg}"
        );
        // Neither the password nor platform verification opens it now.
        assert!(s.unlock(PASSWORD, NOW).await.is_err());
        assert!(s.client.unlock_screen_platform_verified(s.store.as_ref()).is_err());
    }
}

#[tokio::test]
async fn an_account_on_the_legacy_stretch_is_its_own_outcome() {
    let s = setup();
    s.seed_record(PASSWORD);
    s.server.reply(
        PROOF_START,
        Reply::Status(
            200,
            serde_json::json!({ "server_message": "AA==", "server_state": "s", "ksf_version": 0 }),
            Vec::new(),
        ),
    );
    assert_eq!(
        s.unlock(PASSWORD, NOW).await.unwrap(),
        ScreenUnlock::AccountUpgradeNeeded
    );
    s.server.refuse(PROOF_START, 409, "opaque_unavailable");
    assert_eq!(
        s.unlock(PASSWORD, NOW).await.unwrap(),
        ScreenUnlock::AccountUpgradeNeeded
    );
    // A key-stretch version this build does not know, or a message it cannot read, judged
    // nothing about the password either.
    for version in [7, 1] {
        s.server.reply(
            PROOF_START,
            Reply::Status(
                200,
                serde_json::json!({ "server_message": "AA==", "server_state": "s", "ksf_version": version }),
                Vec::new(),
            ),
        );
        assert!(
            matches!(s.unlock(PASSWORD, NOW).await, Err(AuthError::Crypto)),
            "{version}"
        );
    }
    assert_eq!(attempts(s.store.as_ref()), None, "never a wrong password");
    assert_eq!(s.client.lock_state(), LockState::ScreenLocked);
}

/// A server that answers, but not with a judgement (the route is missing, an outage), is
/// neither a wrong try nor "unreachable": the record must not be asked instead.
#[tokio::test]
async fn a_server_that_answers_without_a_judgement_never_falls_back_to_the_record() {
    for (status, code) in [
        (404, "not found"),
        (500, "internal"),
        (409, "password_proof_stale"),
        (403, "session_required"),
    ] {
        let s = setup();
        s.seed_record(PASSWORD);
        seed_attempts(s.store.as_ref(), 1, NOW - 4);
        s.server.refuse(PROOF_START, status, code);
        assert!(
            matches!(s.unlock(PASSWORD, NOW).await, Err(AuthError::Client(_))),
            "{status}"
        );
        assert_eq!(s.client.lock_state(), LockState::ScreenLocked, "{status}");
        assert_eq!(attempts(s.store.as_ref()), Some((1, NOW - 4)), "{status}");
        assert_eq!(s.server.paths(), [PROOF_START], "{status}");
    }
}

#[tokio::test]
async fn a_proof_the_server_judged_and_refused_is_a_wrong_try() {
    let s = setup();
    s.seed_record(PASSWORD);
    s.server.refuse(PROOF_FINISH, 403, "password_not_proven");
    assert_eq!(
        s.unlock(PASSWORD, NOW).await.unwrap(),
        ScreenUnlock::Wrong { wait_ms: 0 }
    );
    assert_eq!(attempts(s.store.as_ref()), Some((1, NOW)));
    assert_eq!(s.client.lock_state(), LockState::ScreenLocked);
    // Another 403 is not a judgement.
    s.server.refuse(PROOF_FINISH, 403, "session_required");
    assert!(s.unlock(PASSWORD, NOW + 1).await.is_err());
    assert_eq!(attempts(s.store.as_ref()), Some((1, NOW)));
}

#[tokio::test]
async fn a_clock_set_back_restarts_the_full_wait() {
    let s = setup();
    s.seed_record(PASSWORD);
    seed_attempts(s.store.as_ref(), 6, NOW);
    let earlier = NOW - HOUR;
    assert_eq!(
        s.unlock(PASSWORD, earlier).await.unwrap(),
        ScreenUnlock::Wait { wait_ms: 60_000 }
    );
    assert_eq!(
        attempts(s.store.as_ref()),
        Some((6, earlier)),
        "the wait now runs from this clock"
    );
    assert_eq!(
        s.unlock(PASSWORD, earlier + 59_999).await.unwrap(),
        ScreenUnlock::Wait { wait_ms: 1 }
    );
    assert_eq!(s.server.requests().len(), 0);
    // An entry that is not a stored state never buys tries: the longest wait.
    s.store.set(crate::session::LOCK_ATTEMPTS, b"garbage").unwrap();
    assert_eq!(
        s.unlock(PASSWORD, NOW).await.unwrap(),
        ScreenUnlock::Wait { wait_ms: HOUR }
    );
    assert_eq!(s.server.requests().len(), 0);
    // That wait is stored once, so it does run out: half-way, then over.
    assert_eq!(attempts(s.store.as_ref()), Some((10, NOW)));
    assert_eq!(
        s.unlock(PASSWORD, NOW + HOUR / 2).await.unwrap(),
        ScreenUnlock::Wait { wait_ms: HOUR / 2 }
    );
    assert_eq!(s.unlock(PASSWORD, NOW + HOUR).await.unwrap(), ScreenUnlock::Opened);
}

/// The answer belongs to the session it was asked for.
#[tokio::test]
async fn an_answer_that_outlives_its_session_opens_nothing() {
    let s = setup();
    s.seed_record(PASSWORD);
    // While the check is on its way the account in this process changes, and the server
    // cannot be reached: the local record matches the typed password.
    let client = s.client.clone();
    s.server.on_request(move |_| {
        client.set_authentication("another-token", "another-account").unwrap();
    });
    s.server.reply(PROOF_START, Reply::Offline);
    assert!(matches!(
        s.unlock(PASSWORD, NOW).await,
        Err(AuthError::Client(ClientError::StaleAccount))
    ));
    assert_eq!(s.client.lock_state(), LockState::VaultClosed);
}

#[tokio::test]
async fn with_the_password_path_off_nothing_is_checked_enrolled_or_counted() {
    let server = LockServer::new();
    let store = store_with_session();
    store.set(LOCK_SCREEN_CHECK, &record_for(PASSWORD)).unwrap();
    let client = screen_locked(&server, &store, false);
    assert!(matches!(
        client
            .unlock_screen_with_password(password(PASSWORD), &store, NOW)
            .await,
        Err(AuthError::PasswordCheckUnavailable)
    ));
    client.unlock_screen_platform_verified(&store).unwrap();
    for on in [true, false] {
        assert!(matches!(
            client
                .set_ask_password_at_start(on, Some(password(PASSWORD)), &store, NOW)
                .await,
            Err(AuthError::PasswordCheckUnavailable)
        ));
    }
    assert_eq!(server.requests().len(), 0, "no proof route is called");
    assert_eq!(attempts(&store), None);
    assert_eq!(entry(&store, LOCK_ASK_AT_START), None);
}

#[tokio::test]
async fn the_start_setting_turns_on_freely_and_off_only_with_the_server_proven_password() {
    let s = setup();
    let store = s.store.as_ref();
    // Not from the screen lock.
    assert!(matches!(
        s.client.set_ask_password_at_start(true, None, store, NOW).await,
        Err(AuthError::InvalidTransition {
            step: "start setting",
            ..
        })
    ));
    s.client.unlock_screen_platform_verified(store).unwrap();
    s.client
        .set_ask_password_at_start(true, None, store, NOW)
        .await
        .unwrap();
    assert_eq!(entry(store, LOCK_ASK_AT_START).as_deref(), Some(b"1".as_slice()));
    assert_eq!(s.server.requests().len(), 0, "turning it on asks for nothing");
    // With the setting on, a start is closed and reads no key.
    s.store.inner.reset_reads();
    let restarted = Client::new(config(true), s.server.clone()).unwrap();
    assert_eq!(restarted.start_from_store(store).unwrap(), LockState::VaultClosed);
    assert_eq!(s.store.inner.read_count_for(KEY_ENTRY), 0);

    let off = |typed: Option<&str>, now_ms| {
        s.client
            .set_ask_password_at_start(false, typed.map(password), store, now_ms)
    };
    let still_on = || assert_eq!(entry(store, LOCK_ASK_AT_START).as_deref(), Some(b"1".as_slice()));
    assert!(matches!(
        off(None, NOW).await,
        Err(AuthError::InvalidTransition {
            requirement: "the account password",
            ..
        })
    ));
    still_on();
    // Offline it cannot be turned off: the local record is never enough here.
    s.seed_record(PASSWORD);
    s.server.go_offline(true);
    assert!(matches!(
        off(Some(PASSWORD), NOW).await,
        Err(AuthError::PasswordProofOffline)
    ));
    assert_eq!(attempts(store), None);
    still_on();
    s.server.go_offline(false);
    // A wrong password is counted as the screen lock counts it.
    assert!(matches!(
        off(Some("wrong"), NOW).await,
        Err(AuthError::PasswordNotConfirmed)
    ));
    assert_eq!(attempts(store), Some((1, NOW)));
    still_on();
    seed_attempts(store, 5, NOW);
    assert!(matches!(
        off(Some(PASSWORD), NOW + 1).await,
        Err(AuthError::PasswordTryWait { wait_ms: 29_999 })
    ));
    still_on();
    // The server accepts the password: off.
    off(Some(PASSWORD), NOW + 30_000).await.unwrap();
    assert_eq!(entry(store, LOCK_ASK_AT_START).as_deref(), Some(b"0".as_slice()));
    assert_eq!(attempts(store), None);
    assert_eq!(s.client.lock_state(), LockState::Open);
}
