//! The two-level lock as a service over the secret store and the transport: the start rule,
//! the screen lock, the vault lock, and what an ended session does. The state machine is
//! `beebeeb_api::flows::LockFlow`; the check record and the wrong-try rule are
//! `beebeeb_core::screen_lock`. A client binds these calls and keeps no lock state of its own.
//!
//! Neither level is encryption of the device: the account key stays in the OS credential
//! store. The screen lock gates the app window; the vault lock removes the key from this
//! app's process and stops the work.

use beebeeb_api::flows::{FlowError, LockFlow, LockLevel, StartFacts};
use beebeeb_core::screen_lock::ScreenCheckRecord;

pub use beebeeb_api::flows::LockState;

use super::*;
use crate::session::{
    LOCK_ASK_AT_START, LOCK_ATTEMPTS, LOCK_SCREEN_CHECK, LOCK_VAULT_CLOSED, read_lock_flag, write_lock_flag,
};

/// What [`Client::lock_vault`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VaultLocked {
    generation: u64,
    mark_stored: bool,
}

impl VaultLocked {
    /// The account generation after the lock: every key copy handed out before it is stale.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Whether the closed mark was stored. When `false` the vault is closed in this process
    /// only: tell the person that the lock will not survive a restart.
    pub fn survives_restart(&self) -> bool {
        self.mark_stored
    }
}

pub(super) fn refused(step: &'static str, error: FlowError) -> AuthError {
    AuthError::InvalidTransition {
        step,
        requirement: match error {
            FlowError::StepNotRequired => "the app is not locked at this level",
            FlowError::StepOutOfOrder => "the step is out of order",
            FlowError::NotReady => "this lock state is opened only by the account password proven to the server",
        },
    }
}

impl Client {
    /// Starts the lock for this app process, once, before any session is installed.
    ///
    /// With a stored session the app starts `ScreenLocked` (the key is loaded, work may
    /// start) only when the start setting is off and no closed mark is set. When the setting
    /// is on, the mark is set, or either cannot be read, it starts `VaultClosed` and the key
    /// entry is not read at all.
    pub fn start_from_store(&self, store: &dyn SecretStore) -> Result<LockState, AuthError> {
        if self.lock_state() != LockState::SignedOut || self.authenticated_owner().is_ok() {
            return Err(AuthError::InvalidTransition {
                step: "lock start",
                requirement: "the lock starts once, before any session is installed",
            });
        }
        let owner = Session::stored_owner_for_app(store, self.app_id())?;
        let facts = StartFacts {
            session_stored: owner.is_some(),
            ask_password_at_start: read_lock_flag(store, LOCK_ASK_AT_START),
            vault_closed: read_lock_flag(store, LOCK_VAULT_CLOSED),
        };
        let mut flow = LockFlow::at_start(facts);
        if flow.state() == LockState::VaultClosed && facts.vault_closed != Some(true) {
            // Closed by the start setting (or by an entry that cannot be read): mark it, so
            // every restore path stays closed until the strong unlock, which clears the mark.
            // A mark that cannot be written leaves this process closed all the same.
            let _ = write_lock_flag(store, LOCK_VAULT_CLOSED, true);
        }
        if let (LockState::ScreenLocked, Some(owner)) = (flow.state(), owner.as_deref()) {
            match Session::load_for_user_proven(store, owner, self.app_id())? {
                Some(session) => {
                    self.install_session(&session)?;
                }
                None => flow.signed_out(),
            }
        }
        let state = flow.state();
        self.with_lock_flow(|current| *current = flow)?;
        Ok(state)
    }

    /// Locks the screen level by hand, by host policy or with the OS session. The key and
    /// the work stay as they are.
    ///
    /// A closed vault is never screen-locked, so the call is refused there. One case keeps
    /// the request all the same: while a password change holds the app closed between its
    /// last answer and its install, the lock that was asked for is applied when the change
    /// installs, and the app comes back screen-locked.
    pub fn lock_screen(&self) -> Result<(), AuthError> {
        self.screen_lock_asked();
        self.with_lock_flow(|flow| flow.lock(LockLevel::Screen))?
            .map_err(|error| refused("screen lock", error))
    }

    /// Opens the screen lock on the host's statement that the operating system verified the
    /// current user. Call it only after the OS prompt returned success: a cancelled or
    /// unavailable prompt calls nothing. It never opens a closed vault.
    pub fn unlock_screen_platform_verified(&self, store: &dyn SecretStore) -> Result<(), AuthError> {
        self.with_lock_flow(LockFlow::platform_verified)?
            .map_err(|error| refused("platform unlock", error))?;
        // Any successful unlock resets the wrong-try count. A count that cannot be removed
        // stays, which only makes the next wait longer.
        let _ = store.delete(LOCK_ATTEMPTS);
        Ok(())
    }

    /// Closes the vault. In this order: the closed mark is written; the key is dropped from
    /// this process, the lock closes and the account generation advances in one step, so
    /// every key copy handed out is refused as stale and wiped when its holder drops it, and
    /// an install that was on its way installs nothing; work stops (`WorkStopped`); the
    /// session is ended at the server, best effort. The stored session and key stay in the
    /// secret store. If the mark cannot be written the vault is still closed in this process
    /// and [`VaultLocked::survives_restart`] is `false`.
    pub async fn lock_vault(&self, store: &dyn SecretStore) -> Result<VaultLocked, AuthError> {
        if self.lock_state() == LockState::SignedOut {
            return Err(refused("vault lock", FlowError::NotReady));
        }
        let mut mark_stored = write_lock_flag(store, LOCK_VAULT_CLOSED, true).is_ok();
        let (generation, retired) = self
            .drop_key_for_vault_lock()?
            .map_err(|error| refused("vault lock", error))?;
        // A strong install that finished just before the key was dropped cleared the mark
        // after it was written above: the lock is the later of the two, so its mark stands.
        if read_lock_flag(store, LOCK_VAULT_CLOSED) != Some(true) {
            mark_stored = write_lock_flag(store, LOCK_VAULT_CLOSED, true).is_ok();
        }
        if let Some(retired) = retired {
            self.end_session_best_effort(&retired.token, &retired.owner).await;
        }
        Ok(VaultLocked {
            generation,
            mark_stored,
        })
    }

    /// Records that the server ended the session (the host heard `SessionExpired`, or core
    /// saw the refusal itself): the key is dropped if it was still held, the check record and
    /// the wrong-try count are deleted, and the closed mark is written, so the next start
    /// does not load the key for a session the server no longer accepts.
    pub fn session_ended(&self, store: &dyn SecretStore) -> Result<LockState, AuthError> {
        if matches!(self.lock_state(), LockState::Open | LockState::ScreenLocked) {
            self.clear_authentication()?;
        }
        let state = self.lock_state();
        if state == LockState::VaultClosed {
            let record = store.delete(LOCK_SCREEN_CHECK);
            let attempts = store.delete(LOCK_ATTEMPTS);
            let mark = write_lock_flag(store, LOCK_VAULT_CLOSED, true);
            record?;
            attempts?;
            mark?;
        }
        Ok(state)
    }

    /// Asks the server about the session while the app holds the key. An ended session
    /// closes the vault ([`Self::session_ended`]); a password counter that differs from the
    /// check record's deletes the record, also for a person who only ever unlocks with
    /// platform verification. Call it when the app starts with a connection and when one
    /// comes back.
    pub async fn refresh_lock_from_server(&self, store: &dyn SecretStore) -> Result<LockState, AuthError> {
        if !matches!(self.lock_state(), LockState::Open | LockState::ScreenLocked) {
            return Ok(self.lock_state());
        }
        match self.execute(&auth::me(), &()).await {
            Ok(user) => {
                reconcile_password_counter(store, user.password_counter)?;
                Ok(self.lock_state())
            }
            Err(error) if account::is_unauthorized(&error) => self.session_ended(store),
            Err(error) => Err(error.into()),
        }
    }

    pub(super) async fn end_session_best_effort(&self, token: &str, owner: &str) {
        // The answer does not matter: a session that is already gone is the goal.
        let _ = self.end_retired_session(token, owner).await;
    }

    /// Seals the sign-in's stretched password for the account that was just accepted, with
    /// the password counter the server reports for it. `None` (no record) when the sign-in
    /// carried no stretch (it never does while the password path is off) or the counter
    /// could not be read.
    pub(super) async fn seal_screen_check(&self, accepted: &mut PasswordAccepted) -> Option<ScreenCheckRecord> {
        let pending = accepted.screen_check.take()?;
        let user = self.execute(&auth::me(), &()).await.ok()?;
        if user.id != accepted.owner {
            return None;
        }
        pending.seal(&accepted.owner, user.password_counter.unwrap_or(0)).ok()
    }

    /// Ends the stored session of a closed vault at the server with its own token: no
    /// credentials are in memory there. For a sign-out from a closed vault.
    pub(super) async fn end_stored_session(&self, store: &dyn SecretStore) -> Result<(), AuthError> {
        if let Some((token, owner)) = Session::stored_token_for_app(store, self.app_id())? {
            self.end_retired_session(&token, &owner).await?;
        }
        Ok(())
    }

    /// A strong install, from the save to the open lock. The install belongs to the session
    /// that was proven at account generation `proven_at`: anything that landed since (a vault
    /// lock, a sign-out, an ended session, another sign-in) wins, the key is not installed,
    /// the lock is not opened, and the answer is `StaleAccount`.
    ///
    /// The lock's part is done with the save: the closed mark is cleared (here and nowhere
    /// else), the check record of the password that was just proven replaces any older one,
    /// and the wrong-try count is reset. A refused install puts the mark back.
    pub(super) fn strong_install(
        &self,
        session: &Session,
        store: &dyn SecretStore,
        record: Option<ScreenCheckRecord>,
        replace_account: bool,
        proven_at: u64,
        save_identity: impl FnOnce() -> Result<(), AuthError>,
    ) -> Result<(), AuthError> {
        let sign_outs = self.sign_outs();
        // Nothing is written for a session that is no longer the one in the process.
        if self.generation() != proven_at {
            return Err(ClientError::StaleAccount.into());
        }
        if replace_account {
            session.save_replacing(store, self.app_id())?;
        } else {
            session.save(store, self.app_id())?;
        }
        save_identity()?;
        store.delete(LOCK_VAULT_CLOSED)?;
        replace_screen_check(store, record);
        let _ = store.delete(LOCK_ATTEMPTS);
        let installed = self.install_session_at(session, proven_at, |flow| {
            // The strong unlock opens from every state.
            let _ = flow.known_device_unlocked();
        });
        if let Err(error) = installed {
            // The vault is closed (or the app signed out) by whatever landed: the mark that
            // was cleared a moment ago is written again, and a sign-out keeps its store.
            let _ = write_lock_flag(store, LOCK_VAULT_CLOSED, true);
            self.forget_refused_save(store, sign_outs);
            return Err(error.into());
        }
        Ok(())
    }

    /// After an install that was refused because the session changed: when this process
    /// signed out since `before` ([`Client::sign_outs`], read before the first store write),
    /// what this call wrote is removed again, so a sign-out is not undone in the store
    /// either. A sign-out of the whole device purges the stored session again, the key entry
    /// and the lock entries included; a sign-out of the app removes the app's token.
    pub(super) fn forget_refused_save(&self, store: &dyn SecretStore, before: (u64, u64)) {
        let (all, device) = self.sign_outs();
        if device != before.1 {
            // The purge follows the app registry, which the sign-out already emptied: the
            // token this call wrote goes by name first.
            let _ = Session::sign_out_app(store, self.app_id());
            let _ = Session::sign_out_device(store);
        } else if all != before.0 {
            let _ = Session::sign_out_app(store, self.app_id());
        }
    }
}

/// Stores `record`, or leaves no record at all: an older one may belong to a password the
/// server no longer accepts, so it never survives a failed write.
pub(super) fn replace_screen_check(store: &dyn SecretStore, record: Option<ScreenCheckRecord>) {
    let stored = record.is_some_and(|record| store.set(LOCK_SCREEN_CHECK, &record.to_bytes()).is_ok());
    if !stored {
        let _ = store.delete(LOCK_SCREEN_CHECK);
    }
}

/// Deletes the check record when the server's password counter differs from the record's,
/// or the record is not one this version reads. The wrong-try count stays: a password
/// changed elsewhere does not end a wait that wrong tries on this device earned.
pub(super) fn reconcile_password_counter(store: &dyn SecretStore, server: Option<u64>) -> Result<(), SecretError> {
    let Some(server) = server else {
        return Ok(());
    };
    let Some(bytes) = store.get(LOCK_SCREEN_CHECK)? else {
        return Ok(());
    };
    if ScreenCheckRecord::from_bytes(&bytes).password_counter() != Some(server) {
        store.delete(LOCK_SCREEN_CHECK)?;
    }
    Ok(())
}
