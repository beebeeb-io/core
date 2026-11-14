//! The two-level lock of a native app: the screen lock and the vault lock.
//!
//! One state machine per app process. It holds progress only: no key material, no I/O, no
//! clock. `ScreenLocked` and `Open` differ only in what the host may show and do; the account
//! key and the work are the same. `VaultClosed` has no usable key in this app's process.
//!
//! There is no arrow from `VaultClosed` to `ScreenLocked`, and none into `Open` except the
//! strong unlock ([`LockFlow::known_device_unlocked`]): a weaker proof never opens the stronger
//! level, also not by restarting the app.
//!
//! The names avoid `Locked`: `SessionKeyState::Locked` means "this session has not proved the
//! key" and is a different thing.

use super::{FlowError, LockedAction};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockState {
    /// No stored session.
    SignedOut,
    /// The key is loaded, work runs, the host shows the account.
    Open,
    /// The key is loaded and work runs; the host shows nothing of the account.
    ScreenLocked,
    /// No usable key in this process; work is stopped until the strong unlock.
    VaultClosed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockLevel {
    Screen,
    Vault,
}

/// What a start reads from the device. `None` means the entry could not be read: the vault
/// starts closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StartFacts {
    pub session_stored: bool,
    /// The "ask for my password when the app starts" setting.
    pub ask_password_at_start: Option<bool>,
    /// The persisted mark of a closed vault.
    pub vault_closed: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockFlow {
    state: LockState,
}

impl LockFlow {
    /// The state an app process starts in. With a stored session it is never `Open`: the app
    /// always starts at least screen-locked, and closed unless both facts were read as `false`.
    pub fn at_start(facts: StartFacts) -> Self {
        let state = if !facts.session_stored {
            LockState::SignedOut
        } else if facts.ask_password_at_start == Some(false) && facts.vault_closed == Some(false) {
            LockState::ScreenLocked
        } else {
            LockState::VaultClosed
        };
        Self { state }
    }

    pub fn state(&self) -> LockState {
        self.state
    }

    /// Locks a level. Locking the level the app is already at (or the screen of a closed
    /// vault's stronger level) changes nothing; a closed vault never becomes screen-locked.
    pub fn lock(&mut self, level: LockLevel) -> Result<(), FlowError> {
        self.state = match (self.state, level) {
            (LockState::SignedOut, _) => return Err(FlowError::NotReady),
            (LockState::Open | LockState::ScreenLocked, LockLevel::Screen) => LockState::ScreenLocked,
            (LockState::VaultClosed, LockLevel::Screen) => return Err(FlowError::StepNotRequired),
            (LockState::Open | LockState::ScreenLocked | LockState::VaultClosed, LockLevel::Vault) => {
                LockState::VaultClosed
            }
        };
        Ok(())
    }

    /// The host states that the operating system verified the user. Core cannot check it, so
    /// it opens only the level that is a screen gate.
    pub fn platform_verified(&mut self) -> Result<(), FlowError> {
        self.open_screen()
    }

    /// The account password was accepted from the screen lock (the online check, or the local
    /// one when the server cannot be reached).
    pub fn password_checked(&mut self) -> Result<(), FlowError> {
        self.open_screen()
    }

    fn open_screen(&mut self) -> Result<(), FlowError> {
        match self.state {
            LockState::ScreenLocked => {
                self.state = LockState::Open;
                Ok(())
            }
            LockState::Open => Err(FlowError::StepNotRequired),
            // A closed vault and a signed-out app are never opened by a screen proof.
            LockState::VaultClosed | LockState::SignedOut => Err(FlowError::NotReady),
        }
    }

    /// The server no longer accepts the session: the key is dropped, and only a fresh
    /// password sign-in with the known-device unlock opens the app again.
    pub fn session_ended(&mut self) {
        if matches!(self.state, LockState::Open | LockState::ScreenLocked) {
            self.state = LockState::VaultClosed;
        }
    }

    /// The strong unlock finished: the password was proven to the server (with the
    /// authenticator code when the account has one), the key was proven for the new session
    /// and the session was installed. It is the arrow out of `VaultClosed` and `SignedOut`;
    /// from the other states the strongest proof leaves the app open too.
    pub fn known_device_unlocked(&mut self) -> Result<(), FlowError> {
        self.state = LockState::Open;
        Ok(())
    }

    pub fn signed_out(&mut self) {
        self.state = LockState::SignedOut;
    }
}

/// Whether this app's process may hold the account key.
pub const fn key_may_be_loaded(state: LockState) -> bool {
    matches!(state, LockState::Open | LockState::ScreenLocked)
}

/// Whether sync, transfers, thumbnails and search may run.
pub const fn work_may_run(state: LockState) -> bool {
    matches!(state, LockState::Open | LockState::ScreenLocked)
}

/// What a person may do while `ScreenLocked`: unlock, lock the vault, and sign out. Everything
/// else is refused, and no file name, account data or thumbnail is shown.
pub const fn screen_locked_allows(action: LockedAction) -> bool {
    matches!(
        action,
        LockedAction::UnlockScreen | LockedAction::LockVault | LockedAction::SignOut
    )
}

/// Who drives a call into core.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Call {
    /// A person, through the app's window: the action it is.
    Person(LockedAction),
    /// The work that runs without the window: sync, transfers, backup, thumbnails made for
    /// the cache, the operating system's file provider.
    Work,
}

/// Why the lock refused a call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallRefused {
    /// The screen is locked and the call is not one of [`screen_locked_allows`].
    ScreenLocked,
    /// The vault is closed: work is stopped until the strong unlock.
    VaultClosed,
}

/// The lock's answer for one call. The screen lock refuses what a person drives, except
/// [`screen_locked_allows`], and leaves the work running; a closed vault refuses the work
/// ([`work_may_run`]). `SignedOut` is also the state of a host that never started the lock
/// through core and installs its sessions itself: nothing is refused there.
pub const fn call_may_run(state: LockState, call: Call) -> Result<(), CallRefused> {
    match (state, call) {
        (LockState::ScreenLocked, Call::Person(action)) if !screen_locked_allows(action) => {
            Err(CallRefused::ScreenLocked)
        }
        (LockState::Open | LockState::ScreenLocked | LockState::VaultClosed, Call::Work) if !work_may_run(state) => {
            Err(CallRefused::VaultClosed)
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: [LockState; 4] = [
        LockState::SignedOut,
        LockState::Open,
        LockState::ScreenLocked,
        LockState::VaultClosed,
    ];

    fn at(state: LockState) -> LockFlow {
        LockFlow { state }
    }

    fn after(
        state: LockState,
        step: impl FnOnce(&mut LockFlow) -> Result<(), FlowError>,
    ) -> Result<LockState, FlowError> {
        let mut flow = at(state);
        step(&mut flow).map(|()| flow.state())
    }

    #[test]
    fn the_start_state_follows_the_stored_facts() {
        let facts = |session_stored, ask, closed| StartFacts {
            session_stored,
            ask_password_at_start: ask,
            vault_closed: closed,
        };
        let flags = [Some(false), Some(true), None];
        let mut screen_locked = 0;
        for ask in flags {
            for closed in flags {
                assert_eq!(
                    LockFlow::at_start(facts(false, ask, closed)).state(),
                    LockState::SignedOut
                );
                let expected = if (ask, closed) == (Some(false), Some(false)) {
                    screen_locked += 1;
                    LockState::ScreenLocked
                } else {
                    LockState::VaultClosed
                };
                assert_eq!(
                    LockFlow::at_start(facts(true, ask, closed)).state(),
                    expected,
                    "{ask:?} {closed:?}"
                );
            }
        }
        // Exactly one of the nine combinations loads the key at start; none starts open.
        assert_eq!(screen_locked, 1);
    }

    #[test]
    fn locking_moves_down_and_never_up() {
        use LockLevel::{Screen, Vault};
        use LockState::*;
        assert_eq!(after(Open, |f| f.lock(Screen)), Ok(ScreenLocked));
        assert_eq!(after(ScreenLocked, |f| f.lock(Screen)), Ok(ScreenLocked));
        assert_eq!(after(Open, |f| f.lock(Vault)), Ok(VaultClosed));
        assert_eq!(after(ScreenLocked, |f| f.lock(Vault)), Ok(VaultClosed));
        assert_eq!(after(VaultClosed, |f| f.lock(Vault)), Ok(VaultClosed));
        // No arrow from VaultClosed to ScreenLocked.
        assert_eq!(after(VaultClosed, |f| f.lock(Screen)), Err(FlowError::StepNotRequired));
        assert_eq!(after(SignedOut, |f| f.lock(Screen)), Err(FlowError::NotReady));
        assert_eq!(after(SignedOut, |f| f.lock(Vault)), Err(FlowError::NotReady));
    }

    #[test]
    fn a_screen_proof_opens_only_the_screen_lock() {
        use LockState::*;
        type Step = fn(&mut LockFlow) -> Result<(), FlowError>;
        let proofs: [Step; 2] = [LockFlow::platform_verified, LockFlow::password_checked];
        for proof in proofs {
            assert_eq!(after(ScreenLocked, proof), Ok(Open));
            assert_eq!(after(Open, proof), Err(FlowError::StepNotRequired));
            for closed in [VaultClosed, SignedOut] {
                let mut flow = at(closed);
                assert_eq!(proof(&mut flow), Err(FlowError::NotReady));
                assert_eq!(flow.state(), closed, "a refused proof changes nothing");
            }
        }
    }

    #[test]
    fn an_ended_session_closes_the_vault() {
        use LockState::*;
        for (from, to) in [
            (Open, VaultClosed),
            (ScreenLocked, VaultClosed),
            (VaultClosed, VaultClosed),
            (SignedOut, SignedOut),
        ] {
            let mut flow = at(from);
            flow.session_ended();
            assert_eq!(flow.state(), to);
        }
    }

    #[test]
    fn the_strong_unlock_opens_and_sign_out_leaves() {
        for from in ALL {
            assert_eq!(after(from, LockFlow::known_device_unlocked), Ok(LockState::Open));
            let mut flow = at(from);
            flow.signed_out();
            assert_eq!(flow.state(), LockState::SignedOut);
        }
    }

    #[test]
    fn the_key_and_the_work_follow_the_state() {
        use LockState::*;
        for (state, allowed) in [
            (SignedOut, false),
            (Open, true),
            (ScreenLocked, true),
            (VaultClosed, false),
        ] {
            assert_eq!(key_may_be_loaded(state), allowed, "{state:?}");
            assert_eq!(work_may_run(state), allowed, "{state:?}");
        }
    }

    #[test]
    fn the_screen_lock_allows_unlock_lock_vault_and_sign_out_only() {
        use LockedAction::*;
        let all = [
            ViewStatus,
            StartKeyProof,
            FinishKeyProof,
            StartDeviceLink,
            ReadDeviceLinkResult,
            AcknowledgeDeviceLink,
            ExchangeDeviceLinkPake,
            UseRecovery,
            SetEmptyKeyAnchors,
            SignOut,
            ManageFactors,
            RemoveDevice,
            EndSession,
            MutateFiles,
            ChangeSettings,
            DeleteAccount,
            UnlockScreen,
            LockVault,
            ViewFiles,
            ShareFiles,
            ApproveDevice,
            UseKey,
        ];
        let allowed: Vec<_> = all.into_iter().filter(|action| screen_locked_allows(*action)).collect();
        assert_eq!(allowed, [SignOut, UnlockScreen, LockVault]);
        // The same list is what core lets a person do in each state, and what it lets the
        // work do: the screen lock stops the person and not the work, a closed vault stops
        // the work, and a host that never started the lock is refused nothing.
        for state in ALL {
            for action in all {
                let refused = state == LockState::ScreenLocked && !allowed.contains(&action);
                assert_eq!(
                    call_may_run(state, Call::Person(action)),
                    if refused {
                        Err(CallRefused::ScreenLocked)
                    } else {
                        Ok(())
                    },
                    "{state:?} {action:?}"
                );
            }
            assert_eq!(
                call_may_run(state, Call::Work),
                if state == LockState::VaultClosed {
                    Err(CallRefused::VaultClosed)
                } else {
                    Ok(())
                },
                "{state:?}"
            );
        }
        // The two new actions belong to the screen lock, not to a locked account.
        assert!(!crate::flows::locked_account_allows(UnlockScreen));
        assert!(!crate::flows::locked_account_allows(LockVault));
    }
}
