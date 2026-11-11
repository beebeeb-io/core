use beebeeb_api::flows::{
    KeyHandle, KeySource, KeySourceKind, LockedAction, NewDeviceFlow, RecoveryDecision, RecoveryFlow, SessionKeyState,
    SignInFlow, SignInPath, SignOutAdvice, locked_account_allows, password_change_keeps_session, sign_out_advice,
};

#[derive(Debug, PartialEq, Eq)]
struct Handle(u8);
impl KeyHandle for Handle {}

struct Source(KeySourceKind, u8);
impl KeySource<Handle> for Source {
    type Error = ();
    fn kind(&self) -> KeySourceKind {
        self.0
    }
    fn open(&self) -> Result<Handle, Self::Error> {
        Ok(Handle(self.1))
    }
}

#[test]
fn sign_in_enforces_each_path() {
    let mut flow = SignInFlow::new(SignInPath::NewDeviceApproval {
        authenticator_required: true,
    });
    assert!(flow.ready_key_source().is_none());
    flow.password_accepted().unwrap();
    flow.device_approved().unwrap();
    assert!(flow.ready_key_source().is_none());
    flow.authenticator_accepted().unwrap();
    assert_eq!(flow.ready_key_source(), Some(KeySourceKind::Approval));
    assert_eq!(flow.unlock(&Source(KeySourceKind::Approval, 7)).unwrap(), Handle(7));

    let mut passkey = SignInFlow::new(SignInPath::NewDevicePasskey);
    passkey.password_accepted().unwrap();
    passkey.email_code_accepted().unwrap();
    passkey.passkey_accepted().unwrap();
    assert_eq!(passkey.ready_key_source(), Some(KeySourceKind::Passkey));
}

#[test]
fn sign_in_rejects_out_of_order_and_wrong_key_sources() {
    let mut approval = SignInFlow::new(SignInPath::NewDeviceApproval {
        authenticator_required: false,
    });
    assert!(approval.device_approved().is_err());
    approval.password_accepted().unwrap();
    approval.device_approved().unwrap();
    assert!(approval.authenticator_accepted().is_err());
    assert!(matches!(
        approval.unlock(&Source(KeySourceKind::Passkey, 1)),
        Err(beebeeb_api::flows::UnlockError::WrongKeySource)
    ));

    let mut recovery = SignInFlow::new(SignInPath::NewDeviceRecovery {
        authenticator_required: true,
        transition_phrase: false,
    });
    assert!(recovery.email_code_accepted().is_err());
    recovery.password_accepted().unwrap();
    recovery.email_code_accepted().unwrap();
    recovery.recovery_phrase_entered().unwrap();
    assert!(recovery.ready_key_source().is_none());
    recovery.authenticator_accepted().unwrap();
    assert_eq!(recovery.ready_key_source(), Some(KeySourceKind::RecoveryKey));
}

#[test]
fn known_device_needs_password_and_uses_existing_handle() {
    let mut flow = SignInFlow::new(SignInPath::KnownDevice);
    assert!(flow.ready_key_source().is_none());
    flow.password_accepted().unwrap();
    assert_eq!(flow.ready_key_source(), Some(KeySourceKind::ExistingDevice));
    assert_eq!(
        flow.unlock(&Source(KeySourceKind::ExistingDevice, 9)).unwrap(),
        Handle(9)
    );
}

#[test]
fn new_device_sources_include_one_time_existing_account_phrase() {
    let mut flow = NewDeviceFlow::existing_account_phrase();
    assert!(flow.screen_sharing_warning_required());
    flow.password_accepted().unwrap();
    flow.email_code_accepted().unwrap();
    flow.recovery_phrase_entered().unwrap();
    assert_eq!(flow.ready_key_source(), Some(KeySourceKind::RecoveryKey));
}

#[test]
fn recovery_waits_only_without_password() {
    assert_eq!(
        RecoveryFlow::new(true).recovery_key_accepted().unwrap().decision(),
        RecoveryDecision::ImmediateWithAlerts
    );
    assert_eq!(
        RecoveryFlow::new(false).recovery_key_accepted().unwrap().decision(),
        RecoveryDecision::WaitWithAlertsAndCancellation
    );
}

#[test]
fn recovery_never_opens_before_phrase_and_only_accepts_recovery_source() {
    let flow = RecoveryFlow::new(true);
    assert!(matches!(
        flow.unlock(&Source(KeySourceKind::RecoveryKey, 1)),
        Err(beebeeb_api::flows::UnlockError::Flow(_))
    ));
    let flow = RecoveryFlow::new(false).recovery_key_accepted().unwrap();
    assert!(matches!(
        flow.clone().unlock(&Source(KeySourceKind::RecoveryKey, 1)),
        Err(beebeeb_api::flows::UnlockError::Flow(_))
    ));
    let mut flow = flow;
    flow.wait_completed().unwrap();
    assert!(matches!(
        flow.unlock(&Source(KeySourceKind::Approval, 1)),
        Err(beebeeb_api::flows::UnlockError::WrongKeySource)
    ));
}

#[test]
fn locked_permissions_are_an_allowlist() {
    for allowed in [
        LockedAction::ViewStatus,
        LockedAction::StartKeyProof,
        LockedAction::FinishKeyProof,
        LockedAction::StartDeviceLink,
        LockedAction::ReadDeviceLinkResult,
        LockedAction::AcknowledgeDeviceLink,
        LockedAction::ExchangeDeviceLinkPake,
        LockedAction::UseRecovery,
        LockedAction::SetEmptyKeyAnchors,
        LockedAction::SignOut,
    ] {
        assert!(locked_account_allows(allowed));
    }
    for denied in [
        LockedAction::ManageFactors,
        LockedAction::RemoveDevice,
        LockedAction::EndSession,
        LockedAction::MutateFiles,
        LockedAction::ChangeSettings,
        LockedAction::DeleteAccount,
    ] {
        assert!(!locked_account_allows(denied));
    }
}

#[test]
fn password_change_ends_unproven_sessions() {
    assert!(!password_change_keeps_session(SessionKeyState::Locked));
    assert!(!password_change_keeps_session(SessionKeyState::Legacy));
    assert!(password_change_keeps_session(SessionKeyState::Proven));
}

#[test]
fn last_device_sign_out_warns() {
    assert_eq!(sign_out_advice(1, true), SignOutAdvice::WarnLastDevice);
    assert_eq!(sign_out_advice(2, true), SignOutAdvice::Proceed);
    assert_eq!(sign_out_advice(1, false), SignOutAdvice::ProceedAppOnly);
}
