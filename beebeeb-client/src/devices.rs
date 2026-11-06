//! Device approval and account-session orchestration.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use beebeeb_api::{proposed, routes::devices};
use beebeeb_core::{CoreError, kdf::MasterKey};
use zeroize::Zeroizing;

use crate::{Client, ClientError, SecretStore, Session, auth::PasswordAccepted};

pub use beebeeb_core::device_link::{
    AccountKeyMaterial, DeviceLinkQr, NewDeviceLink, PakeSealedAccountKeyMaterial, SealedAccountKeyMaterial,
    TypedCodeChannel, TypedCodePake,
};

#[derive(Debug, thiserror::Error)]
pub enum DeviceError {
    #[error(transparent)]
    Client(#[from] ClientError),
    #[error("device-link cryptography failed")]
    Crypto,
    #[error("the device-link answer is malformed")]
    MalformedAnswer,
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

    pub fn typed_code(&self) -> Result<&str, DeviceError> {
        self.link
            .as_ref()
            .map(NewDeviceLink::typed_code)
            .ok_or(DeviceError::NotPending)
    }

    pub fn begin_typed_path(mut self) -> Result<(PendingTypedLink, Vec<u8>), DeviceError> {
        let link = self.link.take().ok_or(DeviceError::NotPending)?;
        let session_id = *link.qr().session_id();
        let (pake, outbound) = link.start_pake()?;
        Ok((
            PendingTypedLink {
                id: self.id,
                session_id,
                pake,
            },
            outbound,
        ))
    }
}

pub struct PendingTypedLink {
    id: String,
    session_id: [u8; 16],
    pake: TypedCodePake,
}

impl std::fmt::Debug for PendingTypedLink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingTypedLink")
            .field("id", &self.id)
            .field("pake", &"[REDACTED]")
            .finish()
    }
}

impl PendingTypedLink {
    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn finish(self, peer_message: &[u8]) -> Result<PendingTypedReceiver, DeviceError> {
        Ok(PendingTypedReceiver {
            id: self.id,
            session_id: self.session_id,
            channel: Some(self.pake.finish(peer_message)?),
        })
    }
}

pub struct PendingTypedReceiver {
    id: String,
    session_id: [u8; 16],
    channel: Option<TypedCodeChannel>,
}

impl std::fmt::Debug for PendingTypedReceiver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingTypedReceiver")
            .field("id", &self.id)
            .field("session_id", &self.session_id)
            .field("channel", &self.channel.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

pub struct PendingTypedApproval {
    id: String,
    session_id: [u8; 16],
    pake: TypedCodePake,
}

impl std::fmt::Debug for PendingTypedApproval {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingTypedApproval")
            .field("id", &self.id)
            .field("session_id", &self.session_id)
            .field("pake", &"[REDACTED]")
            .finish()
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
        let result = self.start_device_link(device_name).await;
        if result.is_err() {
            let _ = self.clear_authentication();
        }
        result
    }

    pub async fn start_device_link(&self, device_name: String) -> Result<PendingNewDeviceLink, DeviceError> {
        if device_name.trim().is_empty() {
            return Err(DeviceError::MalformedAnswer);
        }
        let id = uuid::Uuid::new_v4();
        let link = NewDeviceLink::generate(*id.as_bytes())?;
        let answer = self
            .execute(
                &proposed::start_device_link(),
                &proposed::DeviceLinkStart {
                    session_id: STANDARD.encode(id.as_bytes()),
                    public_key: STANDARD.encode(link.public_key()),
                    device_name,
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
                let code = link.typed_code().to_owned();
                let material = link.open(&code, sealed)?;
                Ok(DeviceLinkPoll::Approved(ApprovedDeviceLink {
                    material,
                    acknowledgement: DeviceLinkAcknowledgement { id: pending.id.clone() },
                }))
            }
        }
    }

    pub async fn acknowledge_device_link(&self, acknowledgement: DeviceLinkAcknowledgement) -> Result<(), DeviceError> {
        self.execute(&proposed::ack_device_link(&acknowledgement.id), &())
            .await
            .map(|_| ())
            .map_err(Into::into)
    }

    pub async fn pending_device_links(&self) -> Result<proposed::PendingDeviceLinks, DeviceError> {
        self.execute(&proposed::pending_device_links(), &())
            .await
            .map_err(Into::into)
    }

    pub async fn approve_device_link(&self, id: &str, qr: &DeviceLinkQr, typed_code: &str) -> Result<(), DeviceError> {
        let session_key = self.session_key()?;
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
        let public_key = decode_fixed::<32>(Some(&detail.public_key))?;
        let key_bytes = Zeroizing::new(*session_key.master_key().to_bytes());
        let sealed = beebeeb_core::device_link::seal_for_new_device(
            qr,
            &public_key,
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

    pub async fn begin_typed_device_approval(
        &self,
        id: &str,
        typed_code: &str,
    ) -> Result<(PendingTypedApproval, Vec<u8>), DeviceError> {
        let detail = self.execute(&proposed::get_device_link(id), &()).await?;
        if detail.status != proposed::DeviceLinkStatus::Pending {
            return Err(DeviceError::NotPending);
        }
        let session_id = decode_fixed::<16>(Some(&detail.session_id))?;
        let (pake, outbound) = TypedCodePake::start_approver(typed_code, &session_id)?;
        Ok((
            PendingTypedApproval {
                id: id.to_owned(),
                session_id,
                pake,
            },
            outbound,
        ))
    }

    pub async fn approve_typed_device_link(
        &self,
        approval: PendingTypedApproval,
        new_device_message: &[u8],
    ) -> Result<(), DeviceError> {
        let session_key = self.session_key()?;
        let key_bytes = Zeroizing::new(*session_key.master_key().to_bytes());
        let material = AccountKeyMaterial::from_master_key(MasterKey::from_bytes(*key_bytes));
        let channel = approval.pake.finish(new_device_message)?;
        let sealed = channel.seal(approval.session_id, material)?;
        self.execute_for_generation(
            &proposed::approve_device_link(&approval.id),
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
        if pending.channel.is_none() {
            return Err(DeviceError::NotPending);
        }
        let answer = self.execute(&proposed::device_link_result(&pending.id), &()).await?;
        match answer.status {
            proposed::DeviceLinkStatus::Pending => Ok(DeviceLinkPoll::Pending),
            proposed::DeviceLinkStatus::Denied => Ok(DeviceLinkPoll::Denied),
            proposed::DeviceLinkStatus::Expired => Ok(DeviceLinkPoll::Expired),
            proposed::DeviceLinkStatus::Acked => Err(DeviceError::NotPending),
            proposed::DeviceLinkStatus::Approved => {
                let channel = pending.channel.take().ok_or(DeviceError::NotPending)?;
                if answer.approver_public.is_some() {
                    return Err(DeviceError::MalformedAnswer);
                }
                let nonce = decode_fixed::<12>(answer.nonce.as_deref())?;
                let ciphertext = decode_vec(answer.ciphertext.as_deref())?;
                let sealed = PakeSealedAccountKeyMaterial::from_parts(pending.session_id, nonce, ciphertext)?;
                let material = channel.open(sealed)?;
                Ok(DeviceLinkPoll::Approved(ApprovedDeviceLink {
                    material,
                    acknowledgement: DeviceLinkAcknowledgement { id: pending.id.clone() },
                }))
            }
        }
    }

    pub async fn deny_device_link(&self, id: &str) -> Result<(), DeviceError> {
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
        self.execute(&devices::list(), &()).await.map_err(Into::into)
    }

    pub async fn remove_device(&self, id: &str) -> Result<(), DeviceError> {
        self.execute(&devices::remove(id), &())
            .await
            .map(|_| ())
            .map_err(Into::into)
    }

    pub async fn list_account_sessions(&self) -> Result<proposed::AccountSessions, DeviceError> {
        self.execute(&proposed::list_account_sessions(), &())
            .await
            .map_err(Into::into)
    }

    pub async fn revoke_account_session(&self, id: &str) -> Result<(), DeviceError> {
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
        let listed = self.list_devices().await?;
        if last_device_warning(&listed.devices, device_id) && !confirm_last_device {
            return Err(DeviceError::LastDeviceConfirmationRequired);
        }
        self.remove_device(device_id).await?;
        let ended = self.end_session_after_device_removal().await;
        let generation = Session::sign_out_device(store)?;
        self.clear_authentication()?;
        ended?;
        Ok(generation)
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
