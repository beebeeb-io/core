//! I/O-free account flows. These types hold only progress flags; key material
//! is represented by caller-defined opaque handles.

mod lock;
mod permissions;
mod recovery;
mod sign_in;

pub use lock::{
    Call, CallRefused, LockFlow, LockLevel, LockState, StartFacts, call_may_run, key_may_be_loaded,
    screen_locked_allows, work_may_run,
};
pub use permissions::{
    LockedAction, SessionKeyState, SignOutAdvice, locked_account_allows, password_change_keeps_session, sign_out_advice,
};
pub use recovery::{RecoveryDecision, RecoveryFlow};
pub use sign_in::{FlowError, KeyHandle, KeySource, KeySourceKind, NewDeviceFlow, SignInFlow, SignInPath, UnlockError};
