//! Device approval and account-session orchestration.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use beebeeb_api::{proposed, routes::devices};
use beebeeb_core::{CoreError, kdf::MasterKey};
use zeroize::Zeroizing;

use crate::{Client, ClientError, SecretStore, Session, auth::PasswordAccepted};

pub use beebeeb_core::device_link::{
    AccountKeyMaterial, ConfirmedTypedApproval, DeviceLinkQr, NewDeviceLink, PakeSealedAccountKeyMaterial,
    SealedAccountKeyMaterial, TypedCodeApprover, TypedCodeReceiver, canonical_device_name,
};

#[derive(Debug, thiserror::Error)]
pub enum DeviceError {
    #[error(transparent)]
    Client(#[from] ClientError),
    #[error("device-link cryptography failed")]
    Crypto,
    #[error("the device-link answer is malformed")]
    MalformedAnswer,
    /// The approver checked the new device's confirmation and it failed: the
    /// typed code did not match, or the device's reported details were changed
    /// on the way. Show it as a failed attempt; the link has been denied.
    #[error("the code did not match, or the device's details were changed on the way")]
    ConfirmationFailed,
    /// QR path: the relay reports another name than the one in the scanned
    /// QR, so the name was changed on the way. Nothing was sealed; the link
    /// has been denied.
    #[error("the device's name was changed on the way")]
    DeviceNameChanged,
    #[error("the device link is no longer pending")]
    NotPending,
    #[error("signing out the last device requires explicit confirmation")]
    LastDeviceConfirmationRequired,
    #[error(transparent)]
    Secret(#[from] crate::SecretError),
}

impl From<CoreError> for DeviceError {
    fn from(_: CoreError) -> Self {
        Self::Crypto
    }
}

pub struct PendingNewDeviceLink {
    id: String,
    expires_at: beebeeb_api::routes::Timestamp,
    link: Option<NewDeviceLink>,
}

impl std::fmt::Debug for PendingNewDeviceLink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingNewDeviceLink")
            .field("id", &self.id)
            .field("expires_at", &self.expires_at)
            .field("link", &self.link.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

impl PendingNewDeviceLink {
    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn expires_at(&self) -> &beebeeb_api::routes::Timestamp {
        &self.expires_at
    }

    pub fn qr(&self) -> Result<DeviceLinkQr, DeviceError> {
        self.link.as_ref().map(NewDeviceLink::qr).ok_or(DeviceError::NotPending)
    }

    /// The text to render as the QR ([`DeviceLinkQr::payload`]).
    pub fn qr_payload(&self) -> Result<String, DeviceError> {
        self.link
            .as_ref()
            .map(NewDeviceLink::qr_payload)
            .ok_or(DeviceError::NotPending)
    }

    /// The canonical name this link reported to the relay.
    pub fn device_name(&self) -> Result<&str, DeviceError> {
        self.link
            .as_ref()
            .map(NewDeviceLink::device_name)
            .ok_or(DeviceError::NotPending)
    }

    pub fn typed_code(&self) -> Result<&str, DeviceError> {
        self.link
            .as_ref()
            .map(NewDeviceLink::typed_code)
            .ok_or(DeviceError::NotPending)
    }

    /// Typed-code path: answer the approver's one message (relayed under role
    /// `approver`). Consumes the link; relay the returned message under role
    /// `new_device`, then poll with [`Client::poll_typed_device_link`].
    pub fn answer_typed_path(
        mut self,
        approver_message: &[u8],
    ) -> Result<(PendingTypedReceiver, Vec<u8>), DeviceError> {
        let link = self.link.take().ok_or(DeviceError::NotPending)?;
        let (receiver, outbound) = link.answer_typed_code(approver_message).map_err(|error| match error {
            CoreError::InvalidInput(_) => DeviceError::MalformedAnswer,
            _ => DeviceError::Crypto,
        })?;
        Ok((
            PendingTypedReceiver {
                id: self.id,
                receiver: Some(receiver),
            },
            outbound,
        ))
    }
}

pub struct PendingTypedReceiver {
    id: String,
    receiver: Option<TypedCodeReceiver>,
}

impl std::fmt::Debug for PendingTypedReceiver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingTypedReceiver")
            .field("id", &self.id)
            .field("receiver", &self.receiver.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

impl PendingTypedReceiver {
    pub fn id(&self) -> &str {
        &self.id
    }
}

pub struct PendingTypedApproval {
    id: String,
    approver: TypedCodeApprover,
}

impl std::fmt::Debug for PendingTypedApproval {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingTypedApproval")
            .field("id", &self.id)
            .field("approver", &self.approver)
            .finish()
    }
}

impl PendingTypedApproval {
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The device name to show the person while they type. The new device's
    /// confirmation proves it reported exactly this name; a relay that changed
    /// it makes [`Client::approve_typed_device_link`] fail.
    pub fn device_name(&self) -> &str {
        self.approver.device_name()
    }
}

#[derive(Debug, Clone)]
pub struct DeviceLinkAcknowledgement {
    id: String,
}

pub struct ApprovedDeviceLink {
    pub material: AccountKeyMaterial,
    pub acknowledgement: DeviceLinkAcknowledgement,
}

impl std::fmt::Debug for ApprovedDeviceLink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApprovedDeviceLink")
            .field("material", &"[REDACTED]")
            .field("acknowledgement", &self.acknowledgement)
            .finish()
    }
}

#[derive(Debug)]
pub enum DeviceLinkPoll {
    Pending,
    Denied,
    Expired,
    Approved(ApprovedDeviceLink),
}

impl Client {
    /// Starts a link from the locked session created by a successful password
    /// sign-in. The session token remains inside the accepted-state handle.
    pub async fn start_device_link_for_sign_in(
        &self,
        accepted: &PasswordAccepted,
        device_name: String,
    ) -> Result<PendingNewDeviceLink, DeviceError> {
        self.set_authentication(accepted.session_token.to_string(), accepted.owner.clone())?;
        let result = self.start_device_link_inner(device_name).await;
        if result.is_err() {
            let _ = self.clear_authentication();
        }
        result
    }

    pub async fn start_device_link(&self, device_name: String) -> Result<PendingNewDeviceLink, DeviceError> {
        self.person_call(crate::LockedAction::StartDeviceLink)?;
        self.start_device_link_inner(device_name).await
    }

    pub(crate) async fn start_device_link_inner(
        &self,
        device_name: String,
    ) -> Result<PendingNewDeviceLink, DeviceError> {
        let id = uuid::Uuid::new_v4();
        // The canonical name is what goes to the relay and what the typed-code
        // confirmation binds; a name with nothing visible is refused.
        let link = NewDeviceLink::generate(*id.as_bytes(), &device_name).map_err(|error| match error {
            CoreError::InvalidInput(_) => DeviceError::MalformedAnswer,
            _ => DeviceError::Crypto,
        })?;
        let answer = self
            .execute(
                &proposed::start_device_link(),
                &proposed::DeviceLinkStart {
                    session_id: STANDARD.encode(id.as_bytes()),
                    public_key: STANDARD.encode(link.public_key()),
                    device_name: link.device_name().to_owned(),
                    hardware_id: None,
                },
            )
            .await?;
        Ok(PendingNewDeviceLink {
            id: if answer.id.is_empty() {
                id.to_string()
            } else {
                answer.id
            },
            expires_at: answer.expires_at,
            link: Some(link),
        })
    }

    pub async fn poll_device_link(&self, pending: &mut PendingNewDeviceLink) -> Result<DeviceLinkPoll, DeviceError> {
        self.person_call(crate::LockedAction::ReadDeviceLinkResult)?;
        if pending.link.is_none() {
            return Err(DeviceError::NotPending);
        }
        let answer = self.execute(&proposed::device_link_result(&pending.id), &()).await?;
        match answer.status {
            proposed::DeviceLinkStatus::Pending => Ok(DeviceLinkPoll::Pending),
            proposed::DeviceLinkStatus::Denied => Ok(DeviceLinkPoll::Denied),
            proposed::DeviceLinkStatus::Expired => Ok(DeviceLinkPoll::Expired),
            proposed::DeviceLinkStatus::Acked => Err(DeviceError::NotPending),
            proposed::DeviceLinkStatus::Approved => {
                let link = pending.link.take().ok_or(DeviceError::NotPending)?;
                if answer.approver_public.is_none() {
                    return Err(DeviceError::MalformedAnswer);
                }
                let approver_public = decode_fixed::<32>(answer.approver_public.as_deref())?;
                let nonce = decode_fixed::<12>(answer.nonce.as_deref())?;
                let ciphertext = decode_vec(answer.ciphertext.as_deref())?;
                let sealed = SealedAccountKeyMaterial::from_parts(
                    *link.qr().session_id(),
                    *link.public_key(),
                    approver_public,
                    nonce,
                    ciphertext,
                )?;
                let material = link.open(sealed)?;
                Ok(DeviceLinkPoll::Approved(ApprovedDeviceLink {
                    material,
                    acknowledgement: DeviceLinkAcknowledgement { id: pending.id.clone() },
                }))
            }
        }
    }

    pub async fn acknowledge_device_link(&self, acknowledgement: DeviceLinkAcknowledgement) -> Result<(), DeviceError> {
        self.person_call(crate::LockedAction::AcknowledgeDeviceLink)?;
        self.execute(&proposed::ack_device_link(&acknowledgement.id), &())
            .await
            .map(|_| ())
            .map_err(Into::into)
    }

    pub async fn pending_device_links(&self) -> Result<proposed::PendingDeviceLinks, DeviceError> {
        self.person_call(crate::LockedAction::ApproveDevice)?;
        self.execute(&proposed::pending_device_links(), &())
            .await
            .map_err(Into::into)
    }

    /// QR path. `qr` must be [`DeviceLinkQr::parse`] of text scanned from the
    /// new device's screen; without a camera, use the typed-code path, because
    /// the code alone gives no protection against a substituted key here.
    /// Show [`DeviceLinkQr::device_name`] while the person confirms, never the
    /// relay's name. A relay name that differs from the scanned one denies the
    /// link and returns [`DeviceError::DeviceNameChanged`] before anything is
    /// sealed (Guus's ruling of 2026-11-07).
    pub async fn approve_device_link(&self, id: &str, qr: &DeviceLinkQr, typed_code: &str) -> Result<(), DeviceError> {
        self.person_call(crate::LockedAction::ApproveDevice)?;
        let session_key = self.held_key()?;
        let detail = self
            .execute_for_generation(&proposed::get_device_link(id), &(), session_key.generation())
            .await?;
        if detail.status != proposed::DeviceLinkStatus::Pending {
            return Err(DeviceError::NotPending);
        }
        let session_id = decode_fixed::<16>(Some(&detail.session_id))?;
        if &session_id != qr.session_id() {
            return Err(DeviceError::MalformedAnswer);
        }
        if !qr.matches_relayed_name(&detail.device_name) {
            let _ = self.deny_device_link_inner(id).await;
            return Err(DeviceError::DeviceNameChanged);
        }
        let public_key = decode_fixed::<32>(Some(&detail.public_key))?;
        let key_bytes = Zeroizing::new(*session_key.master_key().to_bytes());
        let sealed = beebeeb_core::device_link::seal_for_new_device(
            qr,
            &public_key,
            &detail.device_name,
            typed_code,
            AccountKeyMaterial::from_master_key(MasterKey::from_bytes(*key_bytes)),
        )?;
        self.execute_for_generation(
            &proposed::approve_device_link(id),
            &proposed::DeviceLinkApproval {
                approver_public: Some(STANDARD.encode(sealed.approver_public())),
                nonce: STANDARD.encode(sealed.nonce()),
                ciphertext: STANDARD.encode(sealed.ciphertext()),
            },
            session_key.generation(),
        )
        .await
        .map(|_| ())
        .map_err(Into::into)
    }

    /// Typed-code path, approver side: start the one attempt for link `id`.
    /// Relay the returned message under role `approver`, wait for the new
    /// device's answer (role `new_device`), then call
    /// [`Self::approve_typed_device_link`].
    pub async fn begin_typed_device_approval(
        &self,
        id: &str,
        typed_code: &str,
    ) -> Result<(PendingTypedApproval, Vec<u8>), DeviceError> {
        self.person_call(crate::LockedAction::ApproveDevice)?;
        let detail = self.execute(&proposed::get_device_link(id), &()).await?;
        if detail.status != proposed::DeviceLinkStatus::Pending {
            return Err(DeviceError::NotPending);
        }
        let session_id = decode_fixed::<16>(Some(&detail.session_id))?;
        let (approver, outbound) =
            TypedCodeApprover::start(typed_code, &session_id, &detail.device_name).map_err(|error| match error {
                CoreError::InvalidInput(_) => DeviceError::MalformedAnswer,
                _ => DeviceError::Crypto,
            })?;
        Ok((
            PendingTypedApproval {
                id: id.to_owned(),
                approver,
            },
            outbound,
        ))
    }

    /// Check the new device's confirmation, and only then seal the master key
    /// and relay it. A failed check denies the link (so the new device sees it
    /// end) and returns [`DeviceError::ConfirmationFailed`] for a wrong code or
    /// changed device details, [`DeviceError::MalformedAnswer`] for a message
    /// that is not a typed-code answer.
    pub async fn approve_typed_device_link(
        &self,
        approval: PendingTypedApproval,
        new_device_message: &[u8],
    ) -> Result<(), DeviceError> {
        self.person_call(crate::LockedAction::ApproveDevice)?;
        let PendingTypedApproval { id, approver } = approval;
        let confirmed = match approver.confirm(new_device_message) {
            Ok(confirmed) => confirmed,
            Err(error) => {
                let _ = self.deny_device_link_inner(&id).await;
                return Err(match error {
                    CoreError::Decryption => DeviceError::ConfirmationFailed,
                    _ => DeviceError::MalformedAnswer,
                });
            }
        };
        let session_key = self.held_key()?;
        let key_bytes = Zeroizing::new(*session_key.master_key().to_bytes());
        let material = AccountKeyMaterial::from_master_key(MasterKey::from_bytes(*key_bytes));
        let sealed = confirmed.seal(material)?;
        self.execute_for_generation(
            &proposed::approve_device_link(&id),
            &proposed::DeviceLinkApproval {
                approver_public: None,
                nonce: STANDARD.encode(sealed.nonce()),
                ciphertext: STANDARD.encode(sealed.ciphertext()),
            },
            session_key.generation(),
        )
        .await
        .map(|_| ())
        .map_err(Into::into)
    }

    pub async fn poll_typed_device_link(
        &self,
        pending: &mut PendingTypedReceiver,
    ) -> Result<DeviceLinkPoll, DeviceError> {
        self.person_call(crate::LockedAction::ReadDeviceLinkResult)?;
        if pending.receiver.is_none() {
            return Err(DeviceError::NotPending);
        }
        let answer = self.execute(&proposed::device_link_result(&pending.id), &()).await?;
        match answer.status {
            proposed::DeviceLinkStatus::Pending => Ok(DeviceLinkPoll::Pending),
            proposed::DeviceLinkStatus::Denied => Ok(DeviceLinkPoll::Denied),
            proposed::DeviceLinkStatus::Expired => Ok(DeviceLinkPoll::Expired),
            proposed::DeviceLinkStatus::Acked => Err(DeviceError::NotPending),
            proposed::DeviceLinkStatus::Approved => {
                let receiver = pending.receiver.take().ok_or(DeviceError::NotPending)?;
                if answer.approver_public.is_some() {
                    return Err(DeviceError::MalformedAnswer);
                }
                let nonce = decode_fixed::<12>(answer.nonce.as_deref())?;
                let ciphertext = decode_vec(answer.ciphertext.as_deref())?;
                let sealed = PakeSealedAccountKeyMaterial::from_parts(nonce, ciphertext)?;
                let material = receiver.open(sealed)?;
                Ok(DeviceLinkPoll::Approved(ApprovedDeviceLink {
                    material,
                    acknowledgement: DeviceLinkAcknowledgement { id: pending.id.clone() },
                }))
            }
        }
    }

    pub async fn deny_device_link(&self, id: &str) -> Result<(), DeviceError> {
        self.person_call(crate::LockedAction::ApproveDevice)?;
        self.deny_device_link_inner(id).await
    }

    pub(crate) async fn deny_device_link_inner(&self, id: &str) -> Result<(), DeviceError> {
        self.execute(&proposed::deny_device_link(id), &())
            .await
            .map(|_| ())
            .map_err(Into::into)
    }

    pub async fn send_device_link_pake(
        &self,
        id: &str,
        role: proposed::DeviceLinkRole,
        message: &[u8],
    ) -> Result<(), DeviceError> {
        self.person_call(crate::LockedAction::ExchangeDeviceLinkPake)?;
        if message.is_empty() {
            return Err(DeviceError::MalformedAnswer);
        }
        self.execute(
            &proposed::send_device_link_pake(id),
            &proposed::DeviceLinkPakeMessage {
                role,
                message: STANDARD.encode(message),
            },
        )
        .await
        .map(|_| ())
        .map_err(Into::into)
    }

    pub async fn get_device_link_pake(
        &self,
        id: &str,
        role: proposed::DeviceLinkRole,
    ) -> Result<Option<Vec<u8>>, DeviceError> {
        self.person_call(crate::LockedAction::ExchangeDeviceLinkPake)?;
        let answer = self
            .execute(&proposed::get_device_link_pake_for_role(id, role), &())
            .await?;
        match answer.status {
            proposed::DeviceLinkPakeStatus::Pending => Ok(None),
            proposed::DeviceLinkPakeStatus::Ready => {
                let message = answer.message.as_deref().ok_or(DeviceError::MalformedAnswer)?;
                let decoded = STANDARD.decode(message).map_err(|_| DeviceError::MalformedAnswer)?;
                if decoded.is_empty() {
                    return Err(DeviceError::MalformedAnswer);
                }
                Ok(Some(decoded))
            }
            proposed::DeviceLinkPakeStatus::Finished => Err(DeviceError::NotPending),
        }
    }

    pub async fn list_devices(&self) -> Result<devices::Devices, DeviceError> {
        self.person_call(crate::LockedAction::ViewStatus)?;
        self.list_devices_inner().await
    }

    pub(crate) async fn list_devices_inner(&self) -> Result<devices::Devices, DeviceError> {
        self.execute(&devices::list(), &()).await.map_err(Into::into)
    }

    pub async fn remove_device(&self, id: &str) -> Result<(), DeviceError> {
        self.person_call(crate::LockedAction::RemoveDevice)?;
        self.remove_device_inner(id).await
    }

    pub(crate) async fn remove_device_inner(&self, id: &str) -> Result<(), DeviceError> {
        self.execute(&devices::remove(id), &())
            .await
            .map(|_| ())
            .map_err(Into::into)
    }

    pub async fn list_account_sessions(&self) -> Result<proposed::AccountSessions, DeviceError> {
        self.person_call(crate::LockedAction::ViewStatus)?;
        self.execute(&proposed::list_account_sessions(), &())
            .await
            .map_err(Into::into)
    }

    pub async fn revoke_account_session(&self, id: &str) -> Result<(), DeviceError> {
        self.person_call(crate::LockedAction::EndSession)?;
        self.execute(&proposed::revoke_account_session(id), &())
            .await
            .map(|_| ())
            .map_err(Into::into)
    }

    pub async fn sign_out_whole_device(
        &self,
        device_id: &str,
        confirm_last_device: bool,
        store: &dyn SecretStore,
    ) -> Result<u64, DeviceError> {
        self.person_call(crate::LockedAction::SignOut)?;
        let listed = self.list_devices_inner().await?;
        self.check_sign_out_device(&listed.devices, device_id, store)?;
        if last_device_warning(&listed.devices, device_id) && !confirm_last_device {
            return Err(DeviceError::LastDeviceConfirmationRequired);
        }
        self.remove_device_inner(device_id).await?;
        let ended = self.end_session_after_device_removal().await;
        // The process first, then the store (see `Client::sign_out_this_app`).
        let local = self.sign_out_device_authentication();
        let generation = Session::sign_out_device(store)?;
        local?;
        ended?;
        Ok(generation)
    }

    /// A sign-out removes a device. Where removing a device is refused (a locked screen),
    /// the sign-out may remove this device only: the listed entry that carries this device's
    /// stored hardware identity. Any other id is refused as the removal itself would be.
    pub(crate) fn check_sign_out_device(
        &self,
        listed: &[devices::Device],
        device_id: &str,
        store: &dyn SecretStore,
    ) -> Result<(), DeviceError> {
        let Err(refused) = self.person_call(crate::LockedAction::RemoveDevice) else {
            return Ok(());
        };
        // Read, never made: a device without a stored identity cannot name itself here.
        // An empty id names no device: it would equal an empty listed one.
        let own = crate::session::HardwareIdentity::stored_id(store)
            .ok()
            .flatten()
            .filter(|id| !id.is_empty());
        let this_device = own.is_some()
            && listed
                .iter()
                .any(|device| device.id == device_id && device.hardware_id == own);
        if this_device { Ok(()) } else { Err(refused.into()) }
    }

    /// Ends the calling session once its device has been removed. The server
    /// ends sessions recorded on the removed hardware itself, so 401 means the
    /// work is done. A session with no recorded hardware, such as one from
    /// recovery, ends only through this request.
    pub(crate) async fn end_session_after_device_removal(&self) -> Result<(), ClientError> {
        match self.execute_retired_logout().await {
            Err(ClientError::Api(beebeeb_api::ApiError::Server(error))) if error.status == 401 => Ok(()),
            result => result.map(|_| ()),
        }
    }
}

pub fn last_device_warning(devices: &[devices::Device], current_device_id: &str) -> bool {
    let Some(current) = devices.iter().find(|device| device.id == current_device_id) else {
        return true;
    };
    if current.holds_key != Some(true) {
        return true;
    }
    devices.iter().filter(|device| device.holds_key == Some(true)).count() <= 1
}

fn decode_fixed<const N: usize>(value: Option<&str>) -> Result<[u8; N], DeviceError> {
    let bytes = decode_vec(value)?;
    bytes.try_into().map_err(|_| DeviceError::MalformedAnswer)
}

fn decode_vec(value: Option<&str>) -> Result<Vec<u8>, DeviceError> {
    let value = value.ok_or(DeviceError::MalformedAnswer)?;
    STANDARD.decode(value).map_err(|_| DeviceError::MalformedAnswer)
}
