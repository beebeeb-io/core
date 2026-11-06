#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockedAction {
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
}

pub const fn locked_account_allows(action: LockedAction) -> bool {
    matches!(
        action,
        LockedAction::ViewStatus
            | LockedAction::StartKeyProof
            | LockedAction::FinishKeyProof
            | LockedAction::StartDeviceLink
            | LockedAction::ReadDeviceLinkResult
            | LockedAction::AcknowledgeDeviceLink
            | LockedAction::ExchangeDeviceLinkPake
            | LockedAction::UseRecovery
            | LockedAction::SetEmptyKeyAnchors
            | LockedAction::SignOut
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionKeyState {
    Legacy,
    Locked,
    Proven,
}

/// A password change evicts every session that has not proved possession of
/// the account key. Proven sessions remain usable.
pub const fn password_change_keeps_session(state: SessionKeyState) -> bool {
    matches!(state, SessionKeyState::Proven)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignOutAdvice {
    Proceed,
    ProceedAppOnly,
    WarnLastDevice,
}

pub const fn sign_out_advice(signed_in_devices: usize, whole_device: bool) -> SignOutAdvice {
    if !whole_device {
        SignOutAdvice::ProceedAppOnly
    } else if signed_in_devices <= 1 {
        SignOutAdvice::WarnLastDevice
    } else {
        SignOutAdvice::Proceed
    }
}
