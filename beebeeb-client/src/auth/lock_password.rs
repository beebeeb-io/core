//! The password path of the screen lock: the mandatory wrong-try accounting, the online
//! proof (the server's grant-nothing password proof for the current session), and the local
//! check record that decides only when the server cannot be reached.
//!
//! The whole path sits behind `ClientConfig::lock_password_path`. The wire shape of the proof
//! is in `beebeeb_api::proposed` (`password_proof_*`), and this file is its only caller.

use beebeeb_api::flows::LockFlow;
use beebeeb_api::proposed::password_proof_codes;
use beebeeb_core::screen_lock::{
    self, AttemptState, CheckOutcome, LOCAL_CHECK_OFF_AT, ScreenCheckRecord, TryDecision, next_try, wait_after_ms,
};

use super::lock::{is_unauthorized, refused, replace_screen_check};
use super::*;
use crate::TransportError;
use crate::session::{LOCK_ASK_AT_START, LOCK_ATTEMPTS, LOCK_SCREEN_CHECK, write_lock_flag};

/// The answer of [`Client::unlock_screen_with_password`]. Only `Wrong` and `LocalCheckOff`
/// are wrong tries; every other refusal counted nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScreenUnlock {
    /// The password was accepted: by the server, or by the local record while the server
    /// could not be reached. The app is open.
    Opened,
    /// A wrong password. `wait_ms` is the wait before the next try (0: none yet).
    Wrong { wait_ms: u64 },
    /// Nothing was checked: a wait after earlier wrong tries is still running.
    Wait { wait_ms: u64 },
    /// The server's own limit on password checks, not a wrong try. `None`: it named no wait.
    ServerLimit { wait_ms: Option<u64> },
    /// This wrong try was the tenth in a row: the local check is off and its record is
    /// deleted. Only platform verification or the online check opens the screen now.
    LocalCheckOff,
    /// The server cannot be reached and this device has no usable record of the password.
    OfflineNoRecord,
    /// The account is still on the legacy key stretch: sign in again to finish its upgrade.
    AccountUpgradeNeeded,
    /// The server ended the session: the vault is closed, and the strong unlock opens it.
    SessionEnded,
}

/// What the server said about one typed password.
enum OnlineProof {
    Proven {
        password_counter: u64,
    },
    /// Judged and refused: the OPAQUE finish failed on this device, or the server refused it.
    Wrong,
    Unreachable,
    Limited {
        wait_ms: Option<u64>,
    },
    Unauthorized,
    UpgradeNeeded,
    Failed(AuthError),
}

/// One typed password after the wrong-try rule and the checks.
enum Judgement {
    Accepted,
    /// A judged wrong password; `failures` is the count including this one.
    Wrong {
        failures: u32,
    },
    Wait {
        wait_ms: u64,
    },
    ServerLimit {
        wait_ms: Option<u64>,
    },
    OfflineNoRecord,
    UpgradeNeeded,
    SessionEnded,
}

fn refusal(error: ClientError) -> OnlineProof {
    match &error {
        ClientError::Transport(TransportError::Network) => OnlineProof::Unreachable,
        ClientError::Api(beebeeb_api::ApiError::Server(server)) => match server.status {
            401 => OnlineProof::Unauthorized,
            429 => OnlineProof::Limited {
                wait_ms: server.retry_after().map(|seconds| seconds.saturating_mul(1_000)),
            },
            403 if server.is_code(password_proof_codes::NOT_PROVEN) => OnlineProof::Wrong,
            409 if server.is_code(password_proof_codes::UNAVAILABLE) => OnlineProof::UpgradeNeeded,
            _ => OnlineProof::Failed(error.into()),
        },
        _ => OnlineProof::Failed(error.into()),
    }
}

fn load_attempts(store: &dyn SecretStore, now_ms: u64) -> Result<AttemptState, SecretError> {
    Ok(match store.get(LOCK_ATTEMPTS)? {
        None => AttemptState::new(),
        // An entry that is not a stored state never buys tries: the longest wait, from now.
        Some(bytes) => AttemptState::from_bytes(&bytes).unwrap_or_else(|| AttemptState::unreadable(now_ms)),
    })
}

fn store_attempts(store: &dyn SecretStore, state: &AttemptState) -> Result<(), SecretError> {
    if state.failures() == 0 {
        store.delete(LOCK_ATTEMPTS)
    } else {
        store.set(LOCK_ATTEMPTS, &state.to_bytes())
    }
}

impl Client {
    /// Opens the screen lock with the account password.
    ///
    /// When the server can be reached the password is proven online, and the local record is
    /// then written or refreshed; the local record alone decides only when the server cannot
    /// be reached, so a stale record never opens a connected device. Every try is counted
    /// before any check runs, and the wait after wrong tries gates the online check too.
    pub async fn unlock_screen_with_password(
        &self,
        password: Zeroizing<String>,
        store: &dyn SecretStore,
        now_ms: u64,
    ) -> Result<ScreenUnlock, AuthError> {
        if !self.lock_password_path() {
            return Err(AuthError::PasswordCheckUnavailable);
        }
        if self.lock_state() != LockState::ScreenLocked {
            return Err(AuthError::InvalidTransition {
                step: "screen unlock",
                requirement: "the app is screen-locked",
            });
        }
        if password.is_empty() {
            return Err(AuthError::MalformedAnswer);
        }
        let generation = self.generation();
        Ok(
            match self.counted_password_check(&password, store, now_ms, true).await? {
                Judgement::Accepted => {
                    // The answer belongs to the session it was asked for: never open another one.
                    if self.generation() != generation {
                        return Err(ClientError::StaleAccount.into());
                    }
                    self.with_lock_flow(LockFlow::password_checked)?
                        .map_err(|error| refused("screen unlock", error))?;
                    ScreenUnlock::Opened
                }
                Judgement::Wrong { failures } if failures == LOCAL_CHECK_OFF_AT => ScreenUnlock::LocalCheckOff,
                Judgement::Wrong { failures } => ScreenUnlock::Wrong {
                    wait_ms: wait_after_ms(failures),
                },
                Judgement::Wait { wait_ms } => ScreenUnlock::Wait { wait_ms },
                Judgement::ServerLimit { wait_ms } => ScreenUnlock::ServerLimit { wait_ms },
                Judgement::OfflineNoRecord => ScreenUnlock::OfflineNoRecord,
                Judgement::UpgradeNeeded => ScreenUnlock::AccountUpgradeNeeded,
                Judgement::SessionEnded => ScreenUnlock::SessionEnded,
            },
        )
    }

    /// The "ask for my password when the app starts" setting. Turning it on asks for
    /// nothing. Turning it off needs the password proven to the server: never the local
    /// check, never platform verification, so it cannot be turned off offline. The wrong-try
    /// rule counts these tries as it counts the screen lock's.
    pub async fn set_ask_password_at_start(
        &self,
        on: bool,
        password: Option<Zeroizing<String>>,
        store: &dyn SecretStore,
        now_ms: u64,
    ) -> Result<(), AuthError> {
        // Without the online proof the setting could be turned on and never off again.
        if !self.lock_password_path() {
            return Err(AuthError::PasswordCheckUnavailable);
        }
        if self.lock_state() != LockState::Open {
            return Err(AuthError::InvalidTransition {
                step: "start setting",
                requirement: "the app is open",
            });
        }
        if on {
            return write_lock_flag(store, LOCK_ASK_AT_START, true).map_err(Into::into);
        }
        let password = password
            .filter(|password| !password.is_empty())
            .ok_or(AuthError::InvalidTransition {
                step: "start setting",
                requirement: "the account password",
            })?;
        let generation = self.generation();
        match self.counted_password_check(&password, store, now_ms, false).await? {
            Judgement::Accepted => {
                if self.generation() != generation {
                    return Err(ClientError::StaleAccount.into());
                }
                write_lock_flag(store, LOCK_ASK_AT_START, false).map_err(Into::into)
            }
            Judgement::Wrong { .. } => Err(AuthError::PasswordNotConfirmed),
            Judgement::Wait { wait_ms } => Err(AuthError::PasswordTryWait { wait_ms }),
            Judgement::ServerLimit { wait_ms } => Err(AuthError::PasswordCheckLimited { wait_ms }),
            Judgement::OfflineNoRecord => Err(AuthError::PasswordProofOffline),
            Judgement::UpgradeNeeded => Err(AuthError::LegacyUpgradeNotAuthorized),
            Judgement::SessionEnded => Err(ClientError::InvalidAuthentication.into()),
        }
    }

    /// One typed password, counted once whichever checks it goes through.
    ///
    /// The count is written before any check runs, so ending the process mid-check does not
    /// buy a free try, and a count that cannot be written refuses the try. A judged wrong
    /// password keeps the count; a success resets it; an outcome that judged nothing (the
    /// server's limit, an ended session, no record offline, an error) restores what it was.
    async fn counted_password_check(
        &self,
        password: &Zeroizing<String>,
        store: &dyn SecretStore,
        now_ms: u64,
        offline_allowed: bool,
    ) -> Result<Judgement, AuthError> {
        let owner = self.authenticated_owner()?;
        let stored = load_attempts(store, now_ms)?;
        let before = stored.rebased(now_ms);
        if before != stored {
            store_attempts(store, &before)?;
        }
        let local_allowed = match next_try(&before, now_ms) {
            TryDecision::WaitUntil(until) => {
                return Ok(Judgement::Wait {
                    wait_ms: until.saturating_sub(now_ms),
                });
            }
            TryDecision::Allowed => offline_allowed,
            TryDecision::LocalCheckOff => {
                let _ = store.delete(LOCK_SCREEN_CHECK);
                false
            }
        };
        let counted = before.counting_try(now_ms);
        store_attempts(store, &counted)?;
        let judged = self.judge_password(password, &owner, store, local_allowed).await;
        match &judged {
            Ok(Judgement::Accepted) => {
                // A count that cannot be removed stays: it only makes the next wait longer.
                let _ = store_attempts(store, &AttemptState::new());
            }
            Ok(Judgement::Wrong { .. }) => {
                if counted.failures() >= LOCAL_CHECK_OFF_AT {
                    let _ = store.delete(LOCK_SCREEN_CHECK);
                }
            }
            Ok(_) | Err(_) => {
                let _ = store_attempts(store, &before);
            }
        }
        judged.map(|judgement| match judgement {
            Judgement::Wrong { .. } => Judgement::Wrong {
                failures: counted.failures(),
            },
            other => other,
        })
    }

    async fn judge_password(
        &self,
        password: &Zeroizing<String>,
        owner: &str,
        store: &dyn SecretStore,
        local_allowed: bool,
    ) -> Result<Judgement, AuthError> {
        match self.prove_password_online(password).await {
            OnlineProof::Proven { password_counter } => {
                // The server has just accepted this exact password: write or refresh the record.
                replace_screen_check(store, screen_lock::enroll(password, owner, password_counter).ok());
                Ok(Judgement::Accepted)
            }
            OnlineProof::Wrong => Ok(Judgement::Wrong { failures: 0 }),
            OnlineProof::Unreachable if !local_allowed => Ok(Judgement::OfflineNoRecord),
            OnlineProof::Unreachable => {
                let Some(bytes) = store.get(LOCK_SCREEN_CHECK)? else {
                    return Ok(Judgement::OfflineNoRecord);
                };
                let record = ScreenCheckRecord::from_bytes(&bytes);
                match screen_lock::verify(&record, password, owner) {
                    Ok(CheckOutcome::Match) => Ok(Judgement::Accepted),
                    Ok(CheckOutcome::NoMatch) => Ok(Judgement::Wrong { failures: 0 }),
                    Ok(CheckOutcome::Unusable) => {
                        let _ = store.delete(LOCK_SCREEN_CHECK);
                        Ok(Judgement::OfflineNoRecord)
                    }
                    Err(_) => Err(AuthError::LocalCheckUnavailable),
                }
            }
            OnlineProof::Limited { wait_ms } => Ok(Judgement::ServerLimit { wait_ms }),
            // A 401 on either leg is never a wrong try: ask whether the session still lives.
            OnlineProof::Unauthorized => match self.execute(&auth::me(), &()).await {
                Ok(_) => Ok(Judgement::ServerLimit { wait_ms: None }),
                Err(error) if is_unauthorized(&error) => {
                    // The vault is closed in memory whatever the store answers here.
                    let _ = self.session_ended(store);
                    Ok(Judgement::SessionEnded)
                }
                Err(error) => Err(error.into()),
            },
            OnlineProof::UpgradeNeeded => Ok(Judgement::UpgradeNeeded),
            OnlineProof::Failed(error) => Err(error),
        }
    }

    /// The grant-nothing password proof for the current session. A wrong password fails on
    /// this device, in the OPAQUE finish, before anything is sent.
    async fn prove_password_online(&self, password: &Zeroizing<String>) -> OnlineProof {
        let Ok(started) = client_login_start(password.as_bytes()) else {
            return OnlineProof::Failed(AuthError::Crypto);
        };
        let state = Zeroizing::new(started.state);
        let answer = match self
            .execute(
                &proposed::password_proof_start(),
                &proposed::PasswordProofStart {
                    client_message: STANDARD.encode(started.message),
                },
            )
            .await
        {
            Ok(answer) => answer,
            Err(error) => return refusal(error),
        };
        if answer.ksf_version == 0 {
            return OnlineProof::UpgradeNeeded;
        }
        let Ok(server_message) = STANDARD.decode(answer.server_message) else {
            return OnlineProof::Failed(AuthError::MalformedAnswer);
        };
        // OPAQUE's finish fails alike for a wrong password and a record made for another one.
        let Ok(finish) = client_login_finish(
            &state,
            password.as_bytes(),
            &server_message,
            u32::from(answer.ksf_version),
        ) else {
            return OnlineProof::Wrong;
        };
        match self
            .execute(
                &proposed::password_proof_finish(),
                &proposed::PasswordProofFinish {
                    client_message: STANDARD.encode(finish.message),
                    server_state: answer.server_state,
                },
            )
            .await
        {
            Ok(proven) if proven.proven => OnlineProof::Proven {
                password_counter: proven.password_counter.unwrap_or(0),
            },
            Ok(_) => OnlineProof::Failed(AuthError::MalformedAnswer),
            Err(error) => refusal(error),
        }
    }
}
