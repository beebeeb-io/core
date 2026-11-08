//! Share flows for mobile (`beebeeb_core::share_flow`). Thin: each object wraps one core flow and
//! converts requests and responses (the same [`AuthHttpRequest`] / [`AuthHttpResponse`] records
//! the sign-in flows use); no rule lives here.
use std::sync::{Arc, Mutex};

use beebeeb_core::auth_flow::HttpRequest;
use beebeeb_core::kdf::{FileKey, MasterKey};
use beebeeb_core::share_flow::{
    self as sf, ShareFlowError,
    link::{CreateLink, LinkOptions, LinkStep},
    member::{InviteOutcome, InviteStep, MemberInvite, PeerKeyExpectation, ShareTarget},
};
use zeroize::Zeroizing;

use crate::auth_flow::{AuthHttpRequest, AuthHttpResponse, into, out};
use crate::{FileKeyHandle, MasterKeyHandle};

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum ShareFlowFfiError {
    /// `code` is `ShareFlowError::code()` (`plan_required`, `folder_keys_unavailable`, …).
    #[error("{code}")]
    Flow { code: String },
}

impl From<ShareFlowError> for ShareFlowFfiError {
    fn from(e: ShareFlowError) -> Self {
        Self::Flow {
            code: e.code().to_owned(),
        }
    }
}

fn wrong_state() -> ShareFlowFfiError {
    ShareFlowError::WrongState.into()
}

fn key32(bytes: &[u8]) -> Result<Zeroizing<[u8; 32]>, ShareFlowFfiError> {
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| ShareFlowFfiError::from(ShareFlowError::InvalidInput("key length")))?;
    Ok(Zeroizing::new(arr))
}

/// The key inside a handle, for one core call (keys cross UniFFI only as handles).
pub(crate) fn master(handle: &MasterKeyHandle) -> Result<MasterKey, ShareFlowFfiError> {
    handle
        .with_key(|k| MasterKey::from_bytes(k.to_bytes()))
        .map_err(|_| ShareFlowError::InvalidInput("master key handle").into())
}

pub(crate) fn file_key_of(handle: &FileKeyHandle) -> Result<FileKey, ShareFlowFfiError> {
    handle
        .with_key(|k| FileKey::from_bytes(*k.as_bytes()))
        .map_err(|_| ShareFlowError::InvalidInput("file key handle").into())
}

// ── Person shares ────────────────────────────────────────────────────────────

#[derive(uniffi::Enum)]
pub enum InviteStepFfi {
    Send {
        request: AuthHttpRequest,
    },
    /// `recipient_public_key`: the exact key the file key was sealed to (safety number, mark).
    Shared {
        invite_id: String,
        recipient_public_key: Vec<u8>,
    },
    Invited {
        invite_id: String,
        status: String,
    },
    AwaitingApproval {
        invite_id: String,
        recipient_public_key: Option<Vec<u8>>,
    },
    /// Code `peer_key_changed`: the server's key is not the compared one; nothing was sealed.
    PeerKeyChanged {
        invite_id: String,
        recipient_public_key: Vec<u8>,
    },
}

/// What the host knows about the recipient's key: REQUIRED on every member seal.
#[derive(Clone, Debug, uniffi::Enum)]
pub enum PeerKeyExpectationFfi {
    /// The host holds a compared mark; `fingerprint` is 32 bytes (`share_key_fingerprint`).
    Compared { fingerprint: Vec<u8> },
    /// No compared mark for this person.
    NotCompared,
}

pub(crate) fn expectation(e: PeerKeyExpectationFfi) -> Result<PeerKeyExpectation, ShareFlowFfiError> {
    match e {
        PeerKeyExpectationFfi::NotCompared => Ok(PeerKeyExpectation::NotCompared),
        PeerKeyExpectationFfi::Compared { fingerprint } => <[u8; 32]>::try_from(fingerprint.as_slice())
            .map(PeerKeyExpectation::Compared)
            .map_err(|_| ShareFlowError::InvalidInput("fingerprint length").into()),
    }
}

pub(crate) fn outcome_ffi(o: InviteOutcome) -> InviteStepFfi {
    match o {
        InviteOutcome::Shared {
            invite_id,
            recipient_public_key,
        } => InviteStepFfi::Shared {
            invite_id,
            recipient_public_key: recipient_public_key.to_vec(),
        },
        InviteOutcome::Invited { invite_id, status } => InviteStepFfi::Invited { invite_id, status },
        InviteOutcome::AwaitingApproval {
            invite_id,
            recipient_public_key,
        } => InviteStepFfi::AwaitingApproval {
            invite_id,
            recipient_public_key: recipient_public_key.map(|k| k.to_vec()),
        },
        InviteOutcome::PeerKeyChanged {
            invite_id,
            recipient_public_key,
        } => InviteStepFfi::PeerKeyChanged {
            invite_id,
            recipient_public_key: recipient_public_key.to_vec(),
        },
    }
}

#[derive(uniffi::Object)]
pub struct MemberInviteFlow {
    flow: Mutex<MemberInvite>,
    first: Mutex<Option<HttpRequest>>,
}

#[uniffi::export]
impl MemberInviteFlow {
    /// `is_folder` is required: a folder is refused here: it goes through `FolderShareFlow`.
    #[uniffi::constructor]
    pub fn new(
        item_id: String,
        is_folder: bool,
        email: String,
        master_key: Arc<MasterKeyHandle>,
        file_key: Arc<FileKeyHandle>,
        peer_key: PeerKeyExpectationFfi,
    ) -> Result<Arc<Self>, ShareFlowFfiError> {
        let target = ShareTarget { item_id, is_folder };
        let (flow, first) = MemberInvite::start(
            &target,
            &email,
            &master(&master_key)?,
            &file_key_of(&file_key)?,
            expectation(peer_key)?,
        )?;
        Ok(Arc::new(Self {
            flow: Mutex::new(flow),
            first: Mutex::new(Some(first)),
        }))
    }

    pub fn start(&self) -> Result<AuthHttpRequest, ShareFlowFfiError> {
        self.first
            .lock()
            .map_err(|_| wrong_state())?
            .take()
            .map(out)
            .ok_or_else(wrong_state)
    }

    pub fn on_response(&self, response: AuthHttpResponse) -> Result<InviteStepFfi, ShareFlowFfiError> {
        let mut flow = self.flow.lock().map_err(|_| wrong_state())?;
        Ok(match flow.on_response(into(response))? {
            InviteStep::Send(req) => InviteStepFfi::Send { request: out(req) },
            InviteStep::Done(outcome) => outcome_ffi(outcome),
        })
    }
}

/// The approval request and the exact recipient key the file key was sealed to.
#[derive(uniffi::Record)]
pub struct SealedApprovalFfi {
    pub request: AuthHttpRequest,
    pub recipient_public_key: Vec<u8>,
}

/// Approve a claimed file invite later: the file key sealed for the recipient. With
/// `Compared(fingerprint)` a different server key is refused (`peer_key_changed`), unsealed. After
/// `peer_key_changed` and the user's "share anyway", pass the key bytes the refusal carried and
/// `Compared(share_key_fingerprint(those bytes))`, never a re-fetched key. Returns the sealed key.
#[uniffi::export]
pub fn share_approve_file_invite_request(
    invite_id: String,
    file_id: String,
    recipient_public_key_b64: String,
    master_key: Arc<MasterKeyHandle>,
    file_key: Arc<FileKeyHandle>,
    peer_key: PeerKeyExpectationFfi,
) -> Result<SealedApprovalFfi, ShareFlowFfiError> {
    let sealed = sf::member::approve_request(
        &invite_id,
        &file_id,
        &recipient_public_key_b64,
        &master(&master_key)?,
        &file_key_of(&file_key)?,
        expectation(peer_key)?,
    )?;
    Ok(SealedApprovalFfi {
        request: out(sealed.request),
        recipient_public_key: sealed.recipient_public_key.to_vec(),
    })
}

/// The recipient side of a person share: the file key, opened with the owner's X25519 public key.
#[uniffi::export]
pub fn share_open_member_file_key(
    master_key: Arc<MasterKeyHandle>,
    owner_public_key: Vec<u8>,
    file_id: String,
    sealed: Vec<u8>,
) -> Result<Arc<FileKeyHandle>, ShareFlowFfiError> {
    let key = sf::open_member_file_key(&master(&master_key)?, &*key32(&owner_public_key)?, &file_id, &sealed)?;
    Ok(FileKeyHandle::new(key))
}

// ── Links ────────────────────────────────────────────────────────────────────

#[derive(uniffi::Enum)]
pub enum LinkStepFfi {
    Send {
        request: AuthHttpRequest,
    },
    /// `link` carries the key in its `#key=` part; `display` is the part before `#`.
    Created {
        share_id: String,
        link: String,
        display: String,
    },
}

/// One file of a bundle: its id, its position in the link's order, and the key that opens its row.
#[derive(uniffi::Record)]
pub struct BundleItemFfi {
    pub file_id: String,
    pub position: u32,
    pub file_key: Arc<FileKeyHandle>,
}

#[derive(uniffi::Object)]
pub struct CreateLinkFlow {
    flow: Mutex<CreateLink>,
    first: Mutex<Option<HttpRequest>>,
}

#[uniffi::export]
impl CreateLinkFlow {
    /// A bundle link over `items` (web's bundle branch). Each item carries the key that opens its row.
    #[uniffi::constructor]
    pub fn bundle(
        app_url: String,
        items: Vec<BundleItemFfi>,
        master_key: Arc<MasterKeyHandle>,
        expires_in_hours: Option<u32>,
        max_opens: Option<u32>,
        passphrase: Option<String>,
    ) -> Result<Arc<Self>, ShareFlowFfiError> {
        let keys = items
            .iter()
            .map(|i| file_key_of(&i.file_key))
            .collect::<Result<Vec<_>, _>>()?;
        let core_items: Vec<sf::bundle::BundleItem<'_>> = items
            .iter()
            .zip(&keys)
            .map(|(i, k)| sf::bundle::BundleItem {
                file_id: &i.file_id,
                position: i.position,
                file_key: k,
            })
            .collect();
        let options = LinkOptions {
            expires_in_hours,
            max_opens,
            passphrase: passphrase.map(Zeroizing::new),
        };
        let (flow, first) = CreateLink::bundle(&app_url, &core_items, &master(&master_key)?, &options)?;
        drop(core_items);
        Ok(Arc::new(Self {
            flow: Mutex::new(flow),
            first: Mutex::new(Some(first)),
        }))
    }

    #[uniffi::constructor]
    pub fn new(
        app_url: String,
        file_id: String,
        master_key: Arc<MasterKeyHandle>,
        file_key: Arc<FileKeyHandle>,
        expires_in_hours: Option<u32>,
        max_opens: Option<u32>,
        passphrase: Option<String>,
    ) -> Result<Arc<Self>, ShareFlowFfiError> {
        let options = LinkOptions {
            expires_in_hours,
            max_opens,
            passphrase: passphrase.map(Zeroizing::new),
        };
        let (flow, first) = CreateLink::start(
            &app_url,
            &file_id,
            &master(&master_key)?,
            &file_key_of(&file_key)?,
            &options,
        )?;
        Ok(Arc::new(Self {
            flow: Mutex::new(flow),
            first: Mutex::new(Some(first)),
        }))
    }

    pub fn start(&self) -> Result<AuthHttpRequest, ShareFlowFfiError> {
        self.first
            .lock()
            .map_err(|_| wrong_state())?
            .take()
            .map(out)
            .ok_or_else(wrong_state)
    }

    pub fn on_response(&self, response: AuthHttpResponse) -> Result<LinkStepFfi, ShareFlowFfiError> {
        let mut flow = self.flow.lock().map_err(|_| wrong_state())?;
        Ok(match flow.on_response(into(response))? {
            LinkStep::Send(req) => LinkStepFfi::Send { request: out(req) },
            LinkStep::Created(c) => LinkStepFfi::Created {
                display: sf::display_form(&c.link),
                share_id: c.share_id,
                link: c.link.to_string(),
            },
        })
    }
}

/// The owner's working link from a share's owner blobs; `None` when it can't be rebuilt.
/// `wrapped_file_key` (the link's stored `wrapped_file_key`, required) must open under the rebuilt
/// link key. A bundle uses `share_rebuild_bundle_link`.
#[uniffi::export]
pub fn share_rebuild_link(
    app_url: String,
    master_key: Arc<MasterKeyHandle>,
    owner_wrapped_key: Option<String>,
    owner_wrapped_token: Option<String>,
    wrapped_file_key: String,
) -> Result<Option<String>, ShareFlowFfiError> {
    Ok(sf::link::rebuild_link(
        &app_url,
        &master(&master_key)?,
        owner_wrapped_key.as_deref(),
        owner_wrapped_token.as_deref(),
        &wrapped_file_key,
    )
    .map(|l| l.to_string()))
}

/// [`share_rebuild_link`] for a bundle (no single wrapped file key).
#[uniffi::export]
pub fn share_rebuild_bundle_link(
    app_url: String,
    master_key: Arc<MasterKeyHandle>,
    owner_wrapped_key: Option<String>,
    owner_wrapped_token: Option<String>,
) -> Result<Option<String>, ShareFlowFfiError> {
    Ok(sf::link::rebuild_bundle_link(
        &app_url,
        &master(&master_key)?,
        owner_wrapped_key.as_deref(),
        owner_wrapped_token.as_deref(),
    )
    .map(|l| l.to_string()))
}

/// The recipient side of a link: the file key from the link's `#key=` value.
#[uniffi::export]
pub fn share_open_link_file_key(
    fragment_key: String,
    wrapped_file_key_b64: String,
) -> Result<Arc<FileKeyHandle>, ShareFlowFfiError> {
    Ok(FileKeyHandle::new(sf::link::open_link_file_key(
        &fragment_key,
        &wrapped_file_key_b64,
    )?))
}

/// `DELETE` a link (`/shares/{id}`) or a person share (`/shares/invites/{id}`).
#[uniffi::export]
pub fn share_revoke_request(id: String, is_invite: bool) -> Result<AuthHttpRequest, ShareFlowFfiError> {
    Ok(out(if is_invite {
        sf::cancel_invite_request(&id)?
    } else {
        sf::revoke_link_request(&id)?
    }))
}

#[cfg(test)]
mod share_handle_tests {
    use super::*;
    use beebeeb_core::passkey::ceremony::{b64url, escrow_body};

    #[test]
    fn link_keys_cross_as_handles_both_ways() {
        // In: the link constructor takes handles.
        let master_key = MasterKeyHandle::from_keychain_bytes(vec![3u8; 32]).unwrap();
        let file_key = FileKeyHandle::from_key_bytes(vec![7u8; 32]).unwrap();
        let flow = CreateLinkFlow::new(
            "https://app.beebeeb.io".into(),
            "2237c000-0000-4000-8000-000000000002".into(),
            master_key,
            file_key,
            None,
            None,
            None,
        )
        .unwrap();
        assert!(flow.first.lock().unwrap().is_some());
        // Out: the recipient side hands back a handle, never the key bytes.
        let k_c = [9u8; 32];
        let wrapped = sf::wrap_key_for_share(&k_c, &[7u8; 32]).unwrap();
        // `escrow_body` encodes in standard base64, the wire's encoding for `wrapped_file_key`.
        let wrapped_b64 = escrow_body(&[], &wrapped)["encrypted_vault_key"]
            .as_str()
            .unwrap()
            .to_owned();
        let opened: Arc<FileKeyHandle> = share_open_link_file_key(b64url(&k_c), wrapped_b64).unwrap();
        assert_eq!(file_key_of(&opened).unwrap().as_bytes(), &[7u8; 32]);
    }
}
