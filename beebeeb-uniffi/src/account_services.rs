//! Opaque, one-shot account workflows exposed to Swift and Kotlin.

use std::sync::{Arc, Mutex};

use beebeeb_api::proposed::DeviceLinkRole;
use beebeeb_client::Session;
use beebeeb_client::auth::{
    AuthenticatorEnrollment, RecoveredSession, RecoveryAttempt, RecoveryChanges, RecoveryKitData, RecoveryKitOutput,
    RecoveryState, SignupService,
};
use beebeeb_client::devices::{
    AccountKeyMaterial, ApprovedDeviceLink, DeviceLinkAcknowledgement, DeviceLinkPoll, DeviceLinkQr,
    PendingNewDeviceLink, PendingTypedApproval, PendingTypedLink, PendingTypedReceiver,
};
use beebeeb_core::kdf::MasterKey;
use beebeeb_core::onboarding::{BreachPolicy, CeremonyConfig, PasswordPolicy};
use zeroize::Zeroizing;

use crate::{
    AccountReplacementHandle, AuthServiceHandle, BreachCheckHandle, CeremonyStepDto, DeviceServiceHandle,
    MasterKeyHandle, NativeClientHandle, PasswordAcceptedHandle, PasswordEvaluationDto, ServiceError, ServiceErrorKind,
    copy_master_key, lock_tolerant, map_client_error, take_password_accepted,
};

fn invalid() -> ServiceError {
    ServiceError::new(ServiceErrorKind::InvalidInput)
}

fn unavailable() -> ServiceError {
    ServiceError::new(ServiceErrorKind::Unavailable)
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct DeviceLinkQrData {
    pub session_id: Vec<u8>,
    pub fingerprint: Vec<u8>,
}

impl From<DeviceLinkQr> for DeviceLinkQrData {
    fn from(value: DeviceLinkQr) -> Self {
        Self {
            session_id: value.session_id().to_vec(),
            fingerprint: value.fingerprint().to_vec(),
        }
    }
}

fn device_link_qr(value: DeviceLinkQrData) -> Result<DeviceLinkQr, ServiceError> {
    let session_id: [u8; 16] = value.session_id.try_into().map_err(|_| invalid())?;
    let fingerprint: [u8; 32] = value.fingerprint.try_into().map_err(|_| invalid())?;
    Ok(DeviceLinkQr::from_parts(session_id, fingerprint))
}

#[derive(uniffi::Object)]
pub struct DeviceLinkHandle {
    state: Mutex<Option<PendingNewDeviceLink>>,
    id: String,
    expires_at: String,
}

#[uniffi::export]
impl DeviceLinkHandle {
    pub fn id(&self) -> String {
        self.id.clone()
    }

    pub fn expires_at(&self) -> String {
        self.expires_at.clone()
    }

    pub fn qr(&self) -> Result<DeviceLinkQrData, ServiceError> {
        self.state
            .lock()
            .map_err(|_| unavailable())?
            .as_ref()
            .ok_or_else(invalid)?
            .qr()
            .map(Into::into)
            .map_err(|_| invalid())
    }

    pub fn typed_code(&self) -> Result<String, ServiceError> {
        self.state
            .lock()
            .map_err(|_| unavailable())?
            .as_ref()
            .ok_or_else(invalid)?
            .typed_code()
            .map(ToOwned::to_owned)
            .map_err(|_| invalid())
    }

    pub fn begin_typed_path(&self) -> Result<TypedDeviceLinkStartData, ServiceError> {
        let pending = self
            .state
            .lock()
            .map_err(|_| unavailable())?
            .take()
            .ok_or_else(invalid)?;
        let (pending, outbound_message) = pending.begin_typed_path().map_err(|_| invalid())?;
        Ok(TypedDeviceLinkStartData {
            handle: Arc::new(TypedDeviceLinkHandle {
                state: Mutex::new(Some(pending)),
            }),
            outbound_message,
        })
    }
}

#[derive(Debug, uniffi::Object)]
pub struct TypedDeviceLinkHandle {
    state: Mutex<Option<PendingTypedLink>>,
}

#[uniffi::export]
impl TypedDeviceLinkHandle {
    pub fn finish(&self, peer_message: Vec<u8>) -> Result<Arc<TypedDeviceReceiverHandle>, ServiceError> {
        let pending = self
            .state
            .lock()
            .map_err(|_| unavailable())?
            .take()
            .ok_or_else(invalid)?;
        let receiver = pending.finish(&peer_message).map_err(|_| invalid())?;
        Ok(Arc::new(TypedDeviceReceiverHandle {
            state: Mutex::new(Some(receiver)),
        }))
    }
}

#[derive(Debug, uniffi::Record)]
pub struct TypedDeviceLinkStartData {
    pub handle: Arc<TypedDeviceLinkHandle>,
    pub outbound_message: Vec<u8>,
}

#[derive(uniffi::Object)]
pub struct TypedDeviceReceiverHandle {
    state: Mutex<Option<PendingTypedReceiver>>,
}

#[derive(Debug, uniffi::Object)]
pub struct TypedDeviceApprovalHandle {
    state: Mutex<Option<PendingTypedApproval>>,
}

#[derive(Debug, uniffi::Record)]
pub struct TypedDeviceApprovalStartData {
    pub handle: Arc<TypedDeviceApprovalHandle>,
    pub outbound_message: Vec<u8>,
}

#[derive(Debug, uniffi::Object)]
pub struct DeviceApprovalHandle {
    material: Mutex<Option<AccountKeyMaterial>>,
    acknowledgement: Mutex<Option<DeviceLinkAcknowledgement>>,
}

impl DeviceApprovalHandle {
    fn new(value: ApprovedDeviceLink) -> Arc<Self> {
        Arc::new(Self {
            material: Mutex::new(Some(value.material)),
            acknowledgement: Mutex::new(Some(value.acknowledgement)),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum DeviceLinkPollKind {
    Pending,
    Denied,
    Expired,
    Approved,
}

#[derive(Debug, uniffi::Record)]
pub struct DeviceLinkPollData {
    pub kind: DeviceLinkPollKind,
    pub approval: Option<Arc<DeviceApprovalHandle>>,
}

fn link_poll(value: DeviceLinkPoll) -> DeviceLinkPollData {
    match value {
        DeviceLinkPoll::Pending => DeviceLinkPollData {
            kind: DeviceLinkPollKind::Pending,
            approval: None,
        },
        DeviceLinkPoll::Denied => DeviceLinkPollData {
            kind: DeviceLinkPollKind::Denied,
            approval: None,
        },
        DeviceLinkPoll::Expired => DeviceLinkPollData {
            kind: DeviceLinkPollKind::Expired,
            approval: None,
        },
        DeviceLinkPoll::Approved(value) => DeviceLinkPollData {
            kind: DeviceLinkPollKind::Approved,
            approval: Some(DeviceApprovalHandle::new(value)),
        },
    }
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct PendingDeviceLinkData {
    pub id: String,
    pub device_name: String,
    pub reported_by_device: bool,
    pub created_at: String,
    pub expires_at: String,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct AccountSessionData {
    pub id: String,
    pub is_current: bool,
    pub created_at: String,
    pub expires_at: String,
}

#[uniffi::export]
impl DeviceServiceHandle {
    pub fn start_device_link_for_sign_in(
        &self,
        accepted: &PasswordAcceptedHandle,
        device_name: String,
    ) -> Result<Arc<DeviceLinkHandle>, ServiceError> {
        let state = accepted.state.lock().map_err(|_| unavailable())?;
        let accepted = state.as_ref().ok_or_else(invalid)?;
        let pending = self
            .root
            .runtime
            .block_on(self.root.client.start_device_link_for_sign_in(accepted, device_name))
            .map_err(map_client_error)?;
        let id = pending.id().to_owned();
        let expires_at = pending.expires_at().to_owned();
        Ok(Arc::new(DeviceLinkHandle {
            state: Mutex::new(Some(pending)),
            id,
            expires_at,
        }))
    }

    pub fn start_device_link(&self, device_name: String) -> Result<Arc<DeviceLinkHandle>, ServiceError> {
        let pending = self
            .root
            .runtime
            .block_on(self.root.client.start_device_link(device_name))
            .map_err(map_client_error)?;
        let id = pending.id().to_owned();
        let expires_at = pending.expires_at().to_owned();
        Ok(Arc::new(DeviceLinkHandle {
            state: Mutex::new(Some(pending)),
            id,
            expires_at,
        }))
    }

    pub fn poll_device_link(&self, handle: &DeviceLinkHandle) -> Result<DeviceLinkPollData, ServiceError> {
        let mut state = handle.state.lock().map_err(|_| unavailable())?;
        let pending = state.as_mut().ok_or_else(invalid)?;
        self.root
            .runtime
            .block_on(self.root.client.poll_device_link(pending))
            .map(link_poll)
            .map_err(map_client_error)
    }

    pub fn pending_device_links(&self) -> Result<Vec<PendingDeviceLinkData>, ServiceError> {
        self.root
            .runtime
            .block_on(self.root.client.pending_device_links())
            .map(|value| {
                value
                    .links
                    .into_iter()
                    .map(|link| PendingDeviceLinkData {
                        id: link.id,
                        device_name: link.device_name,
                        reported_by_device: link.reported_by_device,
                        created_at: link.created_at,
                        expires_at: link.expires_at,
                    })
                    .collect()
            })
            .map_err(map_client_error)
    }

    pub fn approve_device_link(
        &self,
        id: String,
        qr: DeviceLinkQrData,
        typed_code: String,
    ) -> Result<(), ServiceError> {
        self.root
            .runtime
            .block_on(
                self.root
                    .client
                    .approve_device_link(&id, &device_link_qr(qr)?, &typed_code),
            )
            .map_err(map_client_error)
    }

    pub fn begin_typed_device_approval(
        &self,
        id: String,
        typed_code: String,
    ) -> Result<TypedDeviceApprovalStartData, ServiceError> {
        let (approval, outbound_message) = self
            .root
            .runtime
            .block_on(self.root.client.begin_typed_device_approval(&id, &typed_code))
            .map_err(|_| invalid())?;
        Ok(TypedDeviceApprovalStartData {
            handle: Arc::new(TypedDeviceApprovalHandle {
                state: Mutex::new(Some(approval)),
            }),
            outbound_message,
        })
    }

    pub fn approve_typed_device_link(
        &self,
        approval: &TypedDeviceApprovalHandle,
        new_device_message: Vec<u8>,
    ) -> Result<(), ServiceError> {
        let approval = approval
            .state
            .lock()
            .map_err(|_| unavailable())?
            .take()
            .ok_or_else(invalid)?;
        self.root
            .runtime
            .block_on(
                self.root
                    .client
                    .approve_typed_device_link(approval, &new_device_message),
            )
            .map_err(map_client_error)
    }

    pub fn poll_typed_device_link(
        &self,
        receiver: &TypedDeviceReceiverHandle,
    ) -> Result<DeviceLinkPollData, ServiceError> {
        let mut state = receiver.state.lock().map_err(|_| unavailable())?;
        let pending = state.as_mut().ok_or_else(invalid)?;
        self.root
            .runtime
            .block_on(self.root.client.poll_typed_device_link(pending))
            .map(link_poll)
            .map_err(map_client_error)
    }

    pub fn deny_device_link(&self, id: String) -> Result<(), ServiceError> {
        self.root
            .runtime
            .block_on(self.root.client.deny_device_link(&id))
            .map_err(map_client_error)
    }

    pub fn send_typed_new_device_message(&self, id: String, message: Vec<u8>) -> Result<(), ServiceError> {
        self.send_device_link_message(id, DeviceLinkRole::NewDevice, message)
    }

    pub fn send_typed_approval_message(&self, id: String, message: Vec<u8>) -> Result<(), ServiceError> {
        self.send_device_link_message(id, DeviceLinkRole::Approver, message)
    }

    pub fn typed_new_device_message(&self, id: String) -> Result<Option<Vec<u8>>, ServiceError> {
        self.typed_device_link_message(id, DeviceLinkRole::NewDevice)
    }

    pub fn typed_approval_message(&self, id: String) -> Result<Option<Vec<u8>>, ServiceError> {
        self.typed_device_link_message(id, DeviceLinkRole::Approver)
    }

    pub fn acknowledge_device_link(&self, approval: &DeviceApprovalHandle) -> Result<(), ServiceError> {
        let acknowledgement = approval
            .acknowledgement
            .lock()
            .map_err(|_| unavailable())?
            .take()
            .ok_or_else(invalid)?;
        self.root
            .runtime
            .block_on(self.root.client.acknowledge_device_link(acknowledgement))
            .map_err(map_client_error)
    }

    pub fn list_account_sessions(&self) -> Result<Vec<AccountSessionData>, ServiceError> {
        self.root
            .runtime
            .block_on(self.root.client.list_account_sessions())
            .map(|value| {
                value
                    .sessions
                    .into_iter()
                    .map(|session| AccountSessionData {
                        id: session.id,
                        is_current: session.is_current,
                        created_at: session.created_at,
                        expires_at: session.expires_at,
                    })
                    .collect()
            })
            .map_err(map_client_error)
    }

    pub fn revoke_account_session(&self, id: String) -> Result<(), ServiceError> {
        self.root
            .runtime
            .block_on(self.root.client.revoke_account_session(&id))
            .map_err(map_client_error)
    }
}

impl DeviceServiceHandle {
    fn send_device_link_message(&self, id: String, role: DeviceLinkRole, message: Vec<u8>) -> Result<(), ServiceError> {
        self.root
            .runtime
            .block_on(self.root.client.send_device_link_pake(&id, role, &message))
            .map_err(map_client_error)
    }

    fn typed_device_link_message(&self, id: String, role: DeviceLinkRole) -> Result<Option<Vec<u8>>, ServiceError> {
        self.root
            .runtime
            .block_on(self.root.client.get_device_link_pake(&id, role))
            .map_err(map_client_error)
    }
}

#[uniffi::export]
impl AuthServiceHandle {
    pub fn install_device_approval(
        &self,
        accepted: &PasswordAcceptedHandle,
        approval: &DeviceApprovalHandle,
    ) -> Result<u64, ServiceError> {
        install_device_approval_inner(self, accepted, approval, None)
    }

    pub fn install_device_approval_replacing_account(
        &self,
        accepted: &PasswordAcceptedHandle,
        approval: &DeviceApprovalHandle,
        replacement: &AccountReplacementHandle,
    ) -> Result<u64, ServiceError> {
        install_device_approval_inner(self, accepted, approval, Some(replacement))
    }
}

fn install_device_approval_inner(
    service: &AuthServiceHandle,
    accepted: &PasswordAcceptedHandle,
    approval: &DeviceApprovalHandle,
    replacement: Option<&AccountReplacementHandle>,
) -> Result<u64, ServiceError> {
    if replacement.is_none() {
        service.refuse_account_mismatch(accepted)?;
    }
    let accepted = take_password_accepted(accepted)?;
    let owner = accepted.owner().to_owned();
    let material = approval
        .material
        .lock()
        .map_err(|_| unavailable())?
        .take()
        .ok_or_else(invalid)?;
    let mut unlock = beebeeb_client::auth::NewDeviceUnlock::approval(accepted).map_err(|_| invalid())?;
    unlock.provide_approval(material).map_err(|_| invalid())?;
    let ready = unlock.into_ready().map_err(|_| invalid())?;
    let installed = if let Some(replacement) = replacement {
        let replacement = replacement.take(&service.root)?;
        service
            .root
            .runtime
            .block_on(service.root.client.install_new_device_replacing_account(
                ready,
                &service.root.api_base,
                service.root.secret_store.as_ref(),
                replacement,
            ))
    } else {
        service.root.runtime.block_on(service.root.client.install_new_device(
            ready,
            &service.root.api_base,
            service.root.secret_store.as_ref(),
        ))
    }
    .map_err(map_client_error)?;
    service.root.load_installed_session(&owner)?;
    Ok(installed.generation())
}

#[uniffi::export]
impl AuthServiceHandle {
    pub fn start_recovery(
        &self,
        email: String,
        master_key: &MasterKeyHandle,
    ) -> Result<Arc<RecoveryAttemptHandle>, ServiceError> {
        let key = copy_master_key(master_key)?;
        let attempt = self
            .root
            .runtime
            .block_on(self.root.client.start_recovery(&email, key.as_ref(), None))
            .map_err(map_client_error)?;
        let id = attempt.id().to_owned();
        Ok(Arc::new(RecoveryAttemptHandle {
            state: Mutex::new(Some(attempt)),
            id,
        }))
    }

    pub fn start_recovery_with_password(
        &self,
        email: String,
        password: String,
        master_key: &MasterKeyHandle,
    ) -> Result<Arc<RecoveryAttemptHandle>, ServiceError> {
        let key = copy_master_key(master_key)?;
        let attempt = self
            .root
            .runtime
            .block_on(self.root.client.start_recovery_with_password(
                &email,
                Zeroizing::new(password),
                key.as_ref(),
                None,
            ))
            .map_err(map_client_error)?;
        let id = attempt.id().to_owned();
        Ok(Arc::new(RecoveryAttemptHandle {
            state: Mutex::new(Some(attempt)),
            id,
        }))
    }

    pub fn setup_authenticator(&self) -> Result<Arc<AuthenticatorEnrollmentHandle>, ServiceError> {
        let enrollment = self
            .root
            .runtime
            .block_on(self.root.client.setup_authenticator())
            .map_err(map_client_error)?;
        Ok(Arc::new(AuthenticatorEnrollmentHandle {
            state: Mutex::new(Some(enrollment)),
        }))
    }

    pub fn enable_authenticator(
        &self,
        enrollment: &AuthenticatorEnrollmentHandle,
        code: String,
    ) -> Result<(), ServiceError> {
        enrollment
            .state
            .lock()
            .map_err(|_| unavailable())?
            .take()
            .ok_or_else(invalid)?;
        self.root
            .runtime
            .block_on(self.root.client.enable_authenticator(code))
            .map_err(map_client_error)
    }

    pub fn remove_authenticator(&self, code: String) -> Result<(), ServiceError> {
        self.root
            .runtime
            .block_on(self.root.client.remove_authenticator(code))
            .map_err(map_client_error)
    }

    pub fn change_password(&self, current_password: String, new_password: String) -> Result<u64, ServiceError> {
        let installed = self
            .root
            .runtime
            .block_on(self.root.client.change_password(
                Zeroizing::new(current_password),
                Zeroizing::new(new_password),
                self.root.secret_store.as_ref(),
            ))
            .map_err(map_client_error)?;
        self.root.load_installed_session(installed.owner())?;
        Ok(installed.generation())
    }

    pub fn change_email(&self, new_email: String, password: String) -> Result<String, ServiceError> {
        self.root
            .runtime
            .block_on(self.root.client.change_email(
                &new_email,
                Zeroizing::new(password),
                self.root.secret_store.as_ref(),
            ))
            .map_err(map_client_error)
    }

    pub fn request_account_deletion(
        &self,
        password: String,
        authenticator_code: Option<String>,
    ) -> Result<(), ServiceError> {
        self.root
            .runtime
            .block_on(
                self.root
                    .client
                    .request_account_deletion(Zeroizing::new(password), authenticator_code),
            )
            .map_err(map_client_error)
    }

    pub fn signup(
        &self,
        email: String,
        configuration: SignupConfiguration,
    ) -> Result<Arc<SignupServiceHandle>, ServiceError> {
        let breach = if configuration.breach_required {
            BreachPolicy::Required {
                fail_open: configuration.breach_fail_open,
            }
        } else {
            BreachPolicy::NotRequired
        };
        let service = SignupService::new(
            &email,
            CeremonyConfig {
                password_policy: PasswordPolicy::from_server(configuration.minimum_password_length),
                email_verification_required: configuration.email_verification_required,
                verify_word_count: configuration.verify_word_count,
                breach,
            },
        )
        .map_err(|_| invalid())?;
        Ok(Arc::new(SignupServiceHandle {
            root: self.root.clone(),
            state: Mutex::new(Some(service)),
        }))
    }
}

#[derive(uniffi::Object)]
pub struct RecoveryAttemptHandle {
    state: Mutex<Option<RecoveryAttempt>>,
    id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum RecoveryStateData {
    Pending,
    Ready,
    Completed,
    Cancelled,
}

impl From<RecoveryState> for RecoveryStateData {
    fn from(value: RecoveryState) -> Self {
        match value {
            RecoveryState::Pending => Self::Pending,
            RecoveryState::Ready => Self::Ready,
            RecoveryState::Completed => Self::Completed,
            RecoveryState::Cancelled => Self::Cancelled,
        }
    }
}

#[derive(Debug, Clone, Default, uniffi::Record)]
pub struct RecoveryChangesData {
    pub new_password: Option<String>,
    pub new_email: Option<String>,
    pub email_verification_code: Option<String>,
    pub new_authenticator: Option<String>,
    pub authenticator_code: Option<String>,
    pub remove_authenticator: bool,
}

#[derive(uniffi::Object)]
pub struct RecoveredSessionHandle {
    state: Mutex<Option<RecoveredSession>>,
    owner: String,
    canonical_email: String,
}

#[uniffi::export]
impl RecoveredSessionHandle {
    pub fn owner(&self) -> String {
        self.owner.clone()
    }

    pub fn canonical_email(&self) -> String {
        self.canonical_email.clone()
    }
}

#[uniffi::export]
impl RecoveryAttemptHandle {
    pub fn id(&self) -> String {
        self.id.clone()
    }

    pub fn ready_at(&self) -> Result<Option<String>, ServiceError> {
        Ok(self
            .state
            .lock()
            .map_err(|_| unavailable())?
            .as_ref()
            .ok_or_else(invalid)?
            .ready_at()
            .cloned())
    }

    pub fn waits(&self) -> Result<bool, ServiceError> {
        Ok(self
            .state
            .lock()
            .map_err(|_| unavailable())?
            .as_ref()
            .ok_or_else(invalid)?
            .waits())
    }

    pub fn status(&self, auth: &AuthServiceHandle) -> Result<RecoveryStateData, ServiceError> {
        let mut state = self.state.lock().map_err(|_| unavailable())?;
        let attempt = state.as_mut().ok_or_else(invalid)?;
        auth.root
            .runtime
            .block_on(auth.root.client.recovery_status(attempt))
            .map(Into::into)
            .map_err(map_client_error)
    }

    pub fn cancel(&self, auth: &AuthServiceHandle) -> Result<(), ServiceError> {
        let id = {
            let state = self.state.lock().map_err(|_| unavailable())?;
            state.as_ref().ok_or_else(invalid)?.id().to_owned()
        };
        auth.root
            .runtime
            .block_on(auth.root.client.cancel_recovery(&id))
            .map_err(map_client_error)?;
        self.state.lock().map_err(|_| unavailable())?.take();
        Ok(())
    }

    pub fn complete(
        &self,
        auth: &AuthServiceHandle,
        email: String,
        changes: RecoveryChangesData,
    ) -> Result<Arc<RecoveredSessionHandle>, ServiceError> {
        let mut state = self.state.lock().map_err(|_| unavailable())?;
        let attempt = state.as_ref().ok_or_else(invalid)?;
        let changes = RecoveryChanges {
            new_password: changes.new_password.map(Zeroizing::new),
            new_email: changes.new_email,
            email_verification_code: changes.email_verification_code,
            new_authenticator: changes.new_authenticator.map(Zeroizing::new),
            authenticator_code: changes.authenticator_code,
            remove_authenticator: changes.remove_authenticator,
        };
        let recovered = auth
            .root
            .runtime
            .block_on(auth.root.client.complete_recovery(attempt, &email, changes))
            .map_err(map_client_error)?;
        let owner = recovered.owner().to_owned();
        let canonical_email = recovered.canonical_email().to_owned();
        state.take();
        Ok(Arc::new(RecoveredSessionHandle {
            state: Mutex::new(Some(recovered)),
            owner,
            canonical_email,
        }))
    }
}

#[uniffi::export]
impl AuthServiceHandle {
    pub fn install_recovered_session(
        &self,
        recovered: &RecoveredSessionHandle,
        master_key: &MasterKeyHandle,
    ) -> Result<u64, ServiceError> {
        install_recovered_session_inner(self, recovered, master_key, None)
    }

    pub fn install_recovered_session_replacing_account(
        &self,
        recovered: &RecoveredSessionHandle,
        master_key: &MasterKeyHandle,
        replacement: &AccountReplacementHandle,
    ) -> Result<u64, ServiceError> {
        install_recovered_session_inner(self, recovered, master_key, Some(replacement))
    }
}

fn install_recovered_session_inner(
    service: &AuthServiceHandle,
    recovered: &RecoveredSessionHandle,
    master_key: &MasterKeyHandle,
    replacement: Option<&AccountReplacementHandle>,
) -> Result<u64, ServiceError> {
    if replacement.is_none()
        && Session::stored_owner(service.root.secret_store.as_ref())
            .map_err(|_| ServiceError::new(ServiceErrorKind::Storage))?
            .as_deref()
            .is_some_and(|owner| owner != recovered.owner)
    {
        return Err(ServiceError::new(ServiceErrorKind::AnotherAccountOnDevice));
    }
    let key = copy_master_key(master_key)?;
    let mut state = recovered.state.lock().map_err(|_| unavailable())?;
    let recovered = state.as_ref().ok_or_else(invalid)?;
    let owner = recovered.owner().to_owned();
    let key = {
        let bytes = Zeroizing::new(*key.to_bytes());
        MasterKey::from_bytes(*bytes)
    };
    let installed = if let Some(replacement) = replacement {
        let replacement = replacement.take(&service.root)?;
        service.root.client.install_recovered_session_replacing_account(
            recovered,
            key,
            &service.root.api_base,
            service.root.secret_store.as_ref(),
            replacement,
        )
    } else {
        service.root.client.install_recovered_session(
            recovered,
            key,
            &service.root.api_base,
            service.root.secret_store.as_ref(),
        )
    }
    .map_err(map_client_error)?;
    state.take();
    service.root.load_installed_session(&owner)?;
    Ok(installed.generation())
}

#[derive(uniffi::Object)]
pub struct AuthenticatorEnrollmentHandle {
    state: Mutex<Option<AuthenticatorEnrollment>>,
}

#[uniffi::export]
impl AuthenticatorEnrollmentHandle {
    /// A QR URI is display-only. The underlying authenticator secret has no
    /// binding getter and is discarded when enrollment is enabled/cancelled.
    pub fn qr_uri(&self) -> Result<Option<String>, ServiceError> {
        Ok(self
            .state
            .lock()
            .map_err(|_| unavailable())?
            .as_ref()
            .ok_or_else(invalid)?
            .qr_uri()
            .map(ToOwned::to_owned))
    }

    pub fn cancel(&self) -> Result<(), ServiceError> {
        self.state
            .lock()
            .map_err(|_| unavailable())?
            .take()
            .ok_or_else(invalid)?;
        Ok(())
    }
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct SignupConfiguration {
    pub minimum_password_length: u32,
    pub email_verification_required: bool,
    pub verify_word_count: u32,
    pub breach_required: bool,
    pub breach_fail_open: bool,
}

#[derive(uniffi::Object)]
pub struct SignupServiceHandle {
    root: Arc<NativeClientHandle>,
    state: Mutex<Option<SignupService>>,
}

#[derive(uniffi::Object)]
pub struct RecoveryKitHandle {
    state: Mutex<Option<RecoveryKitData>>,
}

#[uniffi::export]
impl RecoveryKitHandle {
    pub fn filename_stem(&self) -> Result<String, ServiceError> {
        Ok(self
            .state
            .lock()
            .map_err(|_| unavailable())?
            .as_ref()
            .ok_or_else(invalid)?
            .filename_stem()
            .into())
    }

    pub fn title(&self) -> Result<String, ServiceError> {
        Ok(self
            .state
            .lock()
            .map_err(|_| unavailable())?
            .as_ref()
            .ok_or_else(invalid)?
            .title()
            .into())
    }

    pub fn warnings(&self) -> Result<Vec<String>, ServiceError> {
        Ok(self
            .state
            .lock()
            .map_err(|_| unavailable())?
            .as_ref()
            .ok_or_else(invalid)?
            .warnings()
            .into_iter()
            .map(Into::into)
            .collect())
    }

    pub fn words(&self) -> Result<Vec<String>, ServiceError> {
        Ok(self
            .state
            .lock()
            .map_err(|_| unavailable())?
            .as_ref()
            .ok_or_else(invalid)?
            .words()
            .map(Into::into)
            .collect())
    }

    pub fn text_file(&self) -> Result<String, ServiceError> {
        Ok(self
            .state
            .lock()
            .map_err(|_| unavailable())?
            .as_ref()
            .ok_or_else(invalid)?
            .text_file()
            .to_string())
    }

    pub fn discard(&self) -> Result<(), ServiceError> {
        self.state
            .lock()
            .map_err(|_| unavailable())?
            .take()
            .ok_or_else(invalid)?;
        Ok(())
    }
}

#[uniffi::export]
impl SignupServiceHandle {
    pub fn step(&self) -> Result<CeremonyStepDto, ServiceError> {
        Ok(self
            .state
            .lock()
            .map_err(|_| unavailable())?
            .as_ref()
            .ok_or_else(invalid)?
            .step()
            .into())
    }

    pub fn start_email(&self) -> Result<(), ServiceError> {
        let state = self.state.lock().map_err(|_| unavailable())?;
        let signup = state.as_ref().ok_or_else(invalid)?;
        self.root
            .runtime
            .block_on(self.root.client.start_signup_email(signup))
            .map_err(map_client_error)
    }

    pub fn verify_email(&self, code: String) -> Result<(), ServiceError> {
        let mut state = self.state.lock().map_err(|_| unavailable())?;
        let signup = state.as_mut().ok_or_else(invalid)?;
        self.root
            .runtime
            .block_on(self.root.client.verify_signup_email(signup, code))
            .map_err(map_client_error)
    }

    pub fn set_password(
        &self,
        password: String,
        confirmation: String,
        breach: Option<Arc<BreachCheckHandle>>,
    ) -> Result<PasswordEvaluationDto, ServiceError> {
        let mut state = self.state.lock().map_err(|_| unavailable())?;
        let signup = state.as_mut().ok_or_else(invalid)?;
        let password = Zeroizing::new(password);
        let confirmation = Zeroizing::new(confirmation);
        match breach {
            Some(handle) => signup
                .set_password(&password, &confirmation, Some(&lock_tolerant(&handle.check)))
                .map(Into::into)
                .map_err(|_| invalid()),
            None => signup
                .set_password(&password, &confirmation, None)
                .map(Into::into)
                .map_err(|_| invalid()),
        }
    }

    pub fn begin_recovery_kit(&self) -> Result<Arc<RecoveryKitHandle>, ServiceError> {
        let kit = self
            .state
            .lock()
            .map_err(|_| unavailable())?
            .as_mut()
            .ok_or_else(invalid)?
            .begin_recovery_kit()
            .map_err(|_| invalid())?;
        Ok(Arc::new(RecoveryKitHandle {
            state: Mutex::new(Some(kit)),
        }))
    }

    pub fn mark_recovery_pdf_saved(&self) -> Result<(), ServiceError> {
        self.mark_recovery_saved(RecoveryKitOutput::Pdf)
    }

    pub fn mark_recovery_text_saved(&self) -> Result<(), ServiceError> {
        self.mark_recovery_saved(RecoveryKitOutput::Text)
    }

    pub fn mark_recovery_printed(&self) -> Result<(), ServiceError> {
        self.mark_recovery_saved(RecoveryKitOutput::Print)
    }

    pub fn acknowledge_recovery_kit(&self) -> Result<(), ServiceError> {
        self.state
            .lock()
            .map_err(|_| unavailable())?
            .as_mut()
            .ok_or_else(invalid)?
            .acknowledge_recovery_kit()
            .map_err(|_| invalid())
    }

    pub fn challenge_positions(&self) -> Result<Vec<u32>, ServiceError> {
        self.state
            .lock()
            .map_err(|_| unavailable())?
            .as_ref()
            .ok_or_else(invalid)?
            .challenge_positions()
            .map_err(|_| invalid())
    }

    pub fn confirm_recovery_words(&self, answers: Vec<String>) -> Result<(), ServiceError> {
        self.state
            .lock()
            .map_err(|_| unavailable())?
            .as_mut()
            .ok_or_else(invalid)?
            .confirm_phrase(&answers)
            .map_err(|_| invalid())
    }

    pub fn create_account(&self, terms_version: String) -> Result<u64, ServiceError> {
        let mut signup = self
            .state
            .lock()
            .map_err(|_| unavailable())?
            .take()
            .ok_or_else(invalid)?;
        let created = self
            .root
            .runtime
            .block_on(
                self.root
                    .client
                    .create_account(&mut signup, terms_version, self.root.secret_store.as_ref()),
            )
            .map_err(map_client_error)?;
        let owner = created.sign_in.owner().to_owned();
        let installed = self
            .root
            .runtime
            .block_on(self.root.client.install_new_device(
                created.into_ready(),
                &self.root.api_base,
                self.root.secret_store.as_ref(),
            ))
            .map_err(map_client_error)?;
        self.root.load_installed_session(&owner)?;
        Ok(installed.generation())
    }

    pub fn abandon(&self) -> Result<(), ServiceError> {
        let mut signup = self
            .state
            .lock()
            .map_err(|_| unavailable())?
            .take()
            .ok_or_else(invalid)?;
        signup.wipe();
        Ok(())
    }
}

impl SignupServiceHandle {
    fn mark_recovery_saved(&self, output: RecoveryKitOutput) -> Result<(), ServiceError> {
        self.state
            .lock()
            .map_err(|_| unavailable())?
            .as_mut()
            .ok_or_else(invalid)?
            .mark_recovery_output_saved(output);
        Ok(())
    }
}
