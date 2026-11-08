//! Share flows for mobile (`beebeeb_core::share_flow`). Thin: each object wraps one core flow and
//! converts requests and responses (the same [`AuthHttpRequest`] / [`AuthHttpResponse`] records
//! the sign-in flows use); no rule lives here.
use std::sync::{Arc, Mutex};

use beebeeb_core::auth_flow::HttpRequest;
use beebeeb_core::kdf::{FileKey, MasterKey};
use beebeeb_core::share_flow::{
    self as sf, ShareFlowError,
    link::{CreateLink, LinkOptions, LinkStep},
    member::{InviteOutcome, InviteStep, MemberInvite, ShareTarget},
};
use zeroize::Zeroizing;

use crate::auth_flow::{AuthHttpRequest, AuthHttpResponse, into, out};

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum ShareFlowFfiError {
    /// `code` is `ShareFlowError::code()` (`folder_invite_unsupported`, `plan_required`, …).
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

fn master(bytes: &[u8]) -> Result<MasterKey, ShareFlowFfiError> {
    Ok(MasterKey::from_bytes(*key32(bytes)?))
}

fn file_key(bytes: &[u8]) -> Result<FileKey, ShareFlowFfiError> {
    Ok(FileKey::from_bytes(*key32(bytes)?))
}

// ── Person shares ────────────────────────────────────────────────────────────

#[derive(uniffi::Enum)]
pub enum InviteStepFfi {
    Send { request: AuthHttpRequest },
    Shared { invite_id: String },
    Invited { invite_id: String, status: String },
    AwaitingApproval { invite_id: String },
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
        master_key: Vec<u8>,
        file_key_bytes: Vec<u8>,
    ) -> Result<Arc<Self>, ShareFlowFfiError> {
        let (master_key, file_key_bytes) = (Zeroizing::new(master_key), Zeroizing::new(file_key_bytes));
        let target = ShareTarget { item_id, is_folder };
        let (flow, first) = MemberInvite::start(&target, &email, &master(&master_key)?, &file_key(&file_key_bytes)?)?;
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
            InviteStep::Done(InviteOutcome::Shared { invite_id }) => InviteStepFfi::Shared { invite_id },
            InviteStep::Done(InviteOutcome::Invited { invite_id, status }) => {
                InviteStepFfi::Invited { invite_id, status }
            }
            InviteStep::Done(InviteOutcome::AwaitingApproval { invite_id }) => {
                InviteStepFfi::AwaitingApproval { invite_id }
            }
        })
    }
}

/// Approve a claimed file invite later: the file key sealed for the recipient.
#[uniffi::export]
pub fn share_approve_file_invite_request(
    invite_id: String,
    file_id: String,
    recipient_public_key_b64: String,
    master_key: Vec<u8>,
    file_key_bytes: Vec<u8>,
) -> Result<AuthHttpRequest, ShareFlowFfiError> {
    let (master_key, file_key_bytes) = (Zeroizing::new(master_key), Zeroizing::new(file_key_bytes));
    Ok(out(sf::member::approve_request(
        &invite_id,
        &file_id,
        &recipient_public_key_b64,
        &master(&master_key)?,
        &file_key(&file_key_bytes)?,
    )?))
}

/// The recipient side of a person share: the file key, opened with the owner's X25519 public key.
#[uniffi::export]
pub fn share_open_member_file_key(
    master_key: Vec<u8>,
    owner_public_key: Vec<u8>,
    file_id: String,
    sealed: Vec<u8>,
) -> Result<Vec<u8>, ShareFlowFfiError> {
    let master_key = Zeroizing::new(master_key);
    let key = sf::open_member_file_key(&master(&master_key)?, &*key32(&owner_public_key)?, &file_id, &sealed)?;
    Ok(key.as_bytes().to_vec())
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
    pub file_key: Vec<u8>,
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
        master_key: Vec<u8>,
        expires_in_hours: Option<u32>,
        max_opens: Option<u32>,
        passphrase: Option<String>,
    ) -> Result<Arc<Self>, ShareFlowFfiError> {
        let master_key = Zeroizing::new(master_key);
        let keys = items
            .iter()
            .map(|i| file_key(&Zeroizing::new(i.file_key.clone())))
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
        for mut item in items {
            zeroize::Zeroize::zeroize(&mut item.file_key);
        }
        Ok(Arc::new(Self {
            flow: Mutex::new(flow),
            first: Mutex::new(Some(first)),
        }))
    }

    #[uniffi::constructor]
    pub fn new(
        app_url: String,
        file_id: String,
        master_key: Vec<u8>,
        file_key_bytes: Vec<u8>,
        expires_in_hours: Option<u32>,
        max_opens: Option<u32>,
        passphrase: Option<String>,
    ) -> Result<Arc<Self>, ShareFlowFfiError> {
        let (master_key, file_key_bytes) = (Zeroizing::new(master_key), Zeroizing::new(file_key_bytes));
        let options = LinkOptions {
            expires_in_hours,
            max_opens,
            passphrase: passphrase.map(Zeroizing::new),
        };
        let (flow, first) = CreateLink::start(
            &app_url,
            &file_id,
            &master(&master_key)?,
            &file_key(&file_key_bytes)?,
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
#[uniffi::export]
pub fn share_rebuild_link(
    app_url: String,
    master_key: Vec<u8>,
    owner_wrapped_key: Option<String>,
    owner_wrapped_token: Option<String>,
) -> Result<Option<String>, ShareFlowFfiError> {
    let master_key = Zeroizing::new(master_key);
    Ok(sf::link::rebuild_link(
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
) -> Result<Vec<u8>, ShareFlowFfiError> {
    Ok(sf::link::open_link_file_key(&fragment_key, &wrapped_file_key_b64)?
        .as_bytes()
        .to_vec())
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
