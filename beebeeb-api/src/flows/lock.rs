//! The two-level lock of a native app: the screen lock and the vault lock.
//!
//! One state machine per app process. It holds progress only: no key material, no I/O, no
//! clock. `ScreenLocked` and `Open` differ only in what the host may show and do; the account
//! key and the work are the same. `VaultClosed` has no usable key in this app's process.
//!
//! Out of `VaultClosed` lead only the strong unlock ([`LockFlow::known_device_unlocked`]) and
//! sign-out: there is no arrow from `VaultClosed` to `ScreenLocked`, and a weaker proof never
//! opens the stronger level, also not by restarting the app. Into `Open` lead the strong
//! unlock, a screen proof from `ScreenLocked`, and one arrow without a proof: a start with the
//! owner's per-device "app lock" setting off ([`StartFacts::app_lock`]), and only where that
//! start would otherwise be screen-locked. App lock is the screen level's alone; it never
//! opens a closed vault.
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
/// starts closed, and an unreadable app lock counts as on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StartFacts {
    pub session_stored: bool,
    /// The "ask for my password when the app starts" setting.
    pub ask_password_at_start: Option<bool>,
    /// The persisted mark of a closed vault.
    pub vault_closed: Option<bool>,
    /// The per-device "app lock" setting, on by default. Off (`Some(false)`) means the app
    /// does not lock its screen by itself: a start that would be screen-locked starts open,
    /// and the automatic lock ([`LockFlow::lock_after_away`]) changes nothing.
    pub app_lock: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockFlow {
    state: LockState,
}

impl LockFlow {
    /// The state an app process starts in. With a stored session it is closed unless both
    /// vault facts were read as `false`. Then it is screen-locked, or open when app lock was
    /// read as off; an app lock that cannot be read starts screen-locked.
    pub fn at_start(facts: StartFacts) -> Self {
        let state = if !facts.session_stored {
            LockState::SignedOut
        } else if facts.ask_password_at_start == Some(false) && facts.vault_closed == Some(false) {
            LockState::ScreenLocked // STUB: today's start ignores app lock
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
    /// This is the lock a person asks for ("Lock now"): it locks whatever app lock says. The
    /// lock the host applies by itself is [`Self::lock_after_away`].
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

    /// The automatic lock: the host states that the person was away for the delay they chose,
    /// or that the operating system's session was locked. Core holds no clock, so the host
    /// says when and core says what: with app lock on (or unreadable) an open app becomes
    /// screen-locked, as `lock(LockLevel::Screen)` makes it; with app lock off nothing
    /// changes. From any other state nothing changes either, so a host may call it whenever
    /// its timer fires, without an answer to handle.
    pub fn lock_after_away(&mut self, app_lock: Option<bool>) {
        // STUB: today the host's only lock is `lock(Screen)`, whatever app lock says.
        let _ = app_lock;
        let _ = self.lock(LockLevel::Screen);
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
    /// The vault is closed: work is stopped until the strong unlock, and a person may only
    /// prove, lock or sign out ([`closed_vault_allows`]).
    VaultClosed,
}

/// What a person may do while `VaultClosed`: the proofs that lead out of it (a sign-in's key
/// proof, a device link as the new device, recovery), lock the vault again, and sign out.
/// Nothing else: a closed vault may still hold credentials (a sign-in or a password change
/// on its way), and they are for that proof alone.
pub const fn closed_vault_allows(action: LockedAction) -> bool {
    matches!(action, LockedAction::LockVault)
        || (super::locked_account_allows(action) && !matches!(action, LockedAction::ViewStatus))
}

/// The lock's answer for one call. The screen lock refuses what a person drives, except
/// [`screen_locked_allows`], and leaves the work running; a closed vault refuses the work
/// ([`work_may_run`]) and what a person drives, except [`closed_vault_allows`]. `SignedOut`
/// is also the state of a host that never started the lock through core and installs its
/// sessions itself: nothing is refused there.
pub const fn call_may_run(state: LockState, call: Call) -> Result<(), CallRefused> {
    match (state, call) {
        (LockState::ScreenLocked, Call::Person(action)) if !screen_locked_allows(action) => {
            Err(CallRefused::ScreenLocked)
        }
        (LockState::VaultClosed, Call::Person(action)) if !closed_vault_allows(action) => Err(CallRefused::VaultClosed),
        (LockState::Open | LockState::ScreenLocked | LockState::VaultClosed, Call::Work) if !work_may_run(state) => {
            Err(CallRefused::VaultClosed)
        }
        _ => Ok(()),
    }
}

/// Whether the automatic lock ([`LockFlow::lock_after_away`]) locks the screen: always,
/// unless app lock was read as off. An app lock that cannot be read counts as on.
pub const fn away_locks_screen(app_lock: Option<bool>) -> bool {
    !matches!(app_lock, Some(false))
}

/// A proof the screen unlock accepts, given by the person for one change, right before it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScreenProof {
    /// The operating system verified the user: the host's statement, as for
    /// [`LockFlow::platform_verified`].
    PlatformVerified,
    /// The account password was accepted, as for [`LockFlow::password_checked`].
    PasswordChecked,
}

/// Whether the app lock setting may be set to `on` now. Only an open app changes it
/// (`NotReady` from every other state). Turning it on needs nothing. Turning it off lowers
/// what the screen lock protects, so it needs a proof the screen unlock would accept, given
/// for this change; without one it is `StepOutOfOrder` (the proof comes first). The unlock
/// that opened the app earlier is not that proof, and a host never keeps a proof for later.
pub const fn app_lock_may_change(state: LockState, on: bool, proof: Option<ScreenProof>) -> Result<(), FlowError> {
    // STUB: today no rule guards the setting.
    let _ = (state, on, proof);
    Ok(())
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

    fn facts(session_stored: bool, ask: Option<bool>, closed: Option<bool>, app_lock: Option<bool>) -> StartFacts {
        StartFacts {
            session_stored,
            ask_password_at_start: ask,
            vault_closed: closed,
            app_lock,
        }
    }

    /// A start with a stored session, the vault facts that load the key, and this app lock.
    fn started(app_lock: Option<bool>) -> LockFlow {
        LockFlow::at_start(facts(true, Some(false), Some(false), app_lock))
    }

    #[test]
    fn the_start_state_follows_the_stored_facts() {
        let flags = [Some(false), Some(true), None];
        let (mut open, mut screen_locked) = (0, 0);
        for ask in flags {
            for closed in flags {
                for app_lock in flags {
                    assert_eq!(
                        LockFlow::at_start(facts(false, ask, closed, app_lock)).state(),
                        LockState::SignedOut
                    );
                    let expected = match (ask, closed, app_lock) {
                        (Some(false), Some(false), Some(false)) => {
                            open += 1;
                            LockState::Open
                        }
                        (Some(false), Some(false), _) => {
                            screen_locked += 1;
                            LockState::ScreenLocked
                        }
                        _ => LockState::VaultClosed,
                    };
                    assert_eq!(
                        LockFlow::at_start(facts(true, ask, closed, app_lock)).state(),
                        expected,
                        "{ask:?} {closed:?} {app_lock:?}"
                    );
                }
            }
        }
        // Of the 27 combinations three load the key at start; one starts open (app lock read
        // as off), two screen-locked (app lock on or unreadable), 24 closed.
        assert_eq!((open, screen_locked), (1, 2));
    }

    #[test]
    fn app_lock_off_starts_open() {
        assert_eq!(started(Some(false)).state(), LockState::Open);
        assert_eq!(started(Some(true)).state(), LockState::ScreenLocked);
    }

    #[test]
    fn an_unreadable_app_lock_starts_screen_locked() {
        assert_eq!(started(None).state(), LockState::ScreenLocked);
    }

    #[test]
    fn app_lock_off_with_ask_at_start_on_starts_closed() {
        for ask in [Some(true), None] {
            let flow = LockFlow::at_start(facts(true, ask, Some(false), Some(false)));
            assert_eq!(flow.state(), LockState::VaultClosed, "{ask:?}");
        }
    }

    #[test]
    fn app_lock_off_with_a_closed_mark_starts_closed() {
        for closed in [Some(true), None] {
            let flow = LockFlow::at_start(facts(true, Some(false), closed, Some(false)));
            assert_eq!(flow.state(), LockState::VaultClosed, "{closed:?}");
        }
    }

    #[test]
    fn away_with_app_lock_on_locks_the_screen() {
        for app_lock in [Some(true), None] {
            let mut flow = at(LockState::Open);
            flow.lock_after_away(app_lock);
            assert_eq!(flow.state(), LockState::ScreenLocked, "{app_lock:?}");
        }
    }

    #[test]
    fn away_with_app_lock_off_stays_open() {
        let mut flow = started(Some(false));
        assert_eq!(flow.state(), LockState::Open);
        flow.lock_after_away(Some(false));
        assert_eq!(flow.state(), LockState::Open);
        // From every other state the automatic lock changes nothing, whatever app lock says.
        for state in [LockState::SignedOut, LockState::ScreenLocked, LockState::VaultClosed] {
            for app_lock in [Some(false), Some(true), None] {
                let mut flow = at(state);
                flow.lock_after_away(app_lock);
                assert_eq!(flow.state(), state, "{state:?} {app_lock:?}");
            }
        }
    }

    #[test]
    fn a_lock_by_hand_locks_with_app_lock_off() {
        let mut flow = started(Some(false));
        assert_eq!(flow.state(), LockState::Open);
        assert_eq!(flow.lock(LockLevel::Screen), Ok(()));
        assert_eq!(flow.state(), LockState::ScreenLocked);
        // The vault level is the same with app lock off.
        let mut flow = started(Some(false));
        assert_eq!(flow.lock(LockLevel::Vault), Ok(()));
        assert_eq!(flow.state(), LockState::VaultClosed);
        // And a screen-locked app opens only with a proof.
        assert_eq!(
            after(LockState::ScreenLocked, LockFlow::password_checked),
            Ok(LockState::Open)
        );
    }

    #[test]
    fn turning_app_lock_off_needs_a_fresh_proof() {
        use LockState::*;
        let proofs = [ScreenProof::PlatformVerified, ScreenProof::PasswordChecked];
        // Off: refused without a proof, allowed with either one.
        assert_eq!(app_lock_may_change(Open, false, None), Err(FlowError::StepOutOfOrder));
        for proof in proofs {
            assert_eq!(app_lock_may_change(Open, false, Some(proof)), Ok(()), "{proof:?}");
        }
        // On: allowed with or without one.
        assert_eq!(app_lock_may_change(Open, true, None), Ok(()));
        assert_eq!(
            app_lock_may_change(Open, true, Some(ScreenProof::PasswordChecked)),
            Ok(())
        );
        // Only an open app changes it.
        for state in [SignedOut, ScreenLocked, VaultClosed] {
            for on in [true, false] {
                for proof in [None, Some(proofs[0]), Some(proofs[1])] {
                    assert_eq!(
                        app_lock_may_change(state, on, proof),
                        Err(FlowError::NotReady),
                        "{state:?} {on} {proof:?}"
                    );
                }
            }
        }
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
        let closed: Vec<_> = all.into_iter().filter(|action| closed_vault_allows(*action)).collect();
        assert_eq!(
            closed,
            [
                StartKeyProof,
                FinishKeyProof,
                StartDeviceLink,
                ReadDeviceLinkResult,
                AcknowledgeDeviceLink,
                ExchangeDeviceLinkPake,
                UseRecovery,
                SetEmptyKeyAnchors,
                SignOut,
                LockVault,
            ]
        );
        for state in ALL {
            for action in all {
                let expected = match state {
                    LockState::ScreenLocked if !allowed.contains(&action) => Err(CallRefused::ScreenLocked),
                    LockState::VaultClosed if !closed.contains(&action) => Err(CallRefused::VaultClosed),
                    _ => Ok(()),
                };
                assert_eq!(
                    call_may_run(state, Call::Person(action)),
                    expected,
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
