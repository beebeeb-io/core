//! Folder invites and folder links for mobile (`beebeeb_core::share_flow::folder`). Thin: the object wraps the core
//! flow and converts requests and responses; no rule lives here.
use std::sync::{Arc, Mutex};

use beebeeb_core::kdf::MasterKey;
use beebeeb_core::share_flow::{
    ShareFlowError, display_form,
    folder::{FolderInviteInput, FolderLinkInput, FolderSend, FolderShare, FolderStep},
    folder_keys::CustodyMemory,
    member::InviteOutcome,
};
use zeroize::Zeroizing;

use crate::auth_flow::{AuthHttpRequest, AuthHttpResponse, into, out};
use crate::share_flow::ShareFlowFfiError;

/// A `Send` with `mark_custody_seen`: persist the id in the device's custody memory BEFORE sending.
#[derive(uniffi::Enum)]
pub enum FolderStepFfi {
    Send {
        request: AuthHttpRequest,
        mark_custody_seen: Option<String>,
    },
    Shared {
        invite_id: String,
    },
    Invited {
        invite_id: String,
        status: String,
    },
    AwaitingApproval {
        invite_id: String,
    },
    /// `link` carries `#key=`; `display` is the part before `#`.
    LinkCreated {
        share_id: String,
        link: String,
        display: String,
        access_level: String,
        passphrase_protected: bool,
        key_version: u64,
    },
}

fn step_ffi(step: FolderStep) -> FolderStepFfi {
    match step {
        FolderStep::Send(FolderSend {
            request,
            mark_custody_seen,
        }) => FolderStepFfi::Send {
            request: out(request),
            mark_custody_seen,
        },
        FolderStep::Done(InviteOutcome::Shared { invite_id }) => FolderStepFfi::Shared { invite_id },
        FolderStep::Done(InviteOutcome::Invited { invite_id, status }) => FolderStepFfi::Invited { invite_id, status },
        FolderStep::Done(InviteOutcome::AwaitingApproval { invite_id }) => {
            FolderStepFfi::AwaitingApproval { invite_id }
        }
        FolderStep::LinkCreated(c) => FolderStepFfi::LinkCreated {
            display: display_form(&c.link),
            link: c.link.to_string(),
            share_id: c.share_id,
            access_level: c.access_level,
            passphrase_protected: c.passphrase_protected,
            key_version: c.key_version,
        },
    }
}

fn wrong_state() -> ShareFlowFfiError {
    ShareFlowError::WrongState.into()
}

#[derive(uniffi::Object)]
pub struct FolderShareFlow {
    flow: Mutex<FolderShare>,
    first: Mutex<Option<FolderStep>>,
}

#[uniffi::export]
impl FolderShareFlow {
    /// `shared_folders_write` is the `shared_folders_v1` flag read at send time; a host that cannot
    /// read it must not start the flow. `custody_seen` / `custody_unreadable` are the device's
    /// custody memory (L7d).
    #[uniffi::constructor]
    pub fn new(
        folder_id: String,
        email: String,
        shared_folders_write: bool,
        custody_seen: Vec<String>,
        custody_unreadable: bool,
        master_key: Vec<u8>,
    ) -> Result<Arc<Self>, ShareFlowFfiError> {
        let master_key = Zeroizing::new(master_key);
        let bytes: [u8; 32] = master_key
            .as_slice()
            .try_into()
            .map_err(|_| ShareFlowFfiError::from(ShareFlowError::InvalidInput("key length")))?;
        let master = MasterKey::from_bytes(*Zeroizing::new(bytes));
        let input = FolderInviteInput {
            folder_id: &folder_id,
            email: &email,
            shared_folders_write,
            custody: CustodyMemory::new(custody_seen, custody_unreadable),
        };
        let (flow, first) = FolderShare::invite(input, &master)?;
        Ok(Arc::new(Self {
            flow: Mutex::new(flow),
            first: Mutex::new(Some(first)),
        }))
    }

    /// A live folder link (web `createFolderLinkWithKeys`).
    #[uniffi::constructor]
    #[allow(clippy::too_many_arguments)]
    pub fn link(
        folder_id: String,
        app_url: String,
        access_level: String,
        label: Option<String>,
        expires_in_hours: Option<u32>,
        cap_bytes: Option<u64>,
        max_opens: Option<u32>,
        passphrase: Option<String>,
        custody_seen: Vec<String>,
        custody_unreadable: bool,
        master_key: Vec<u8>,
    ) -> Result<Arc<Self>, ShareFlowFfiError> {
        let (master_key, passphrase) = (Zeroizing::new(master_key), passphrase.map(Zeroizing::new));
        let bytes: [u8; 32] = master_key
            .as_slice()
            .try_into()
            .map_err(|_| ShareFlowFfiError::from(ShareFlowError::InvalidInput("key length")))?;
        let master = MasterKey::from_bytes(*Zeroizing::new(bytes));
        let input = FolderLinkInput {
            folder_id: &folder_id,
            app_url: &app_url,
            access_level: &access_level,
            label: label.as_deref(),
            expires_in_hours,
            cap_bytes,
            max_opens,
            passphrase,
            custody: CustodyMemory::new(custody_seen, custody_unreadable),
        };
        let (flow, first) = FolderShare::link(input, &master)?;
        Ok(Arc::new(Self {
            flow: Mutex::new(flow),
            first: Mutex::new(Some(first)),
        }))
    }

    pub fn start(&self) -> Result<FolderStepFfi, ShareFlowFfiError> {
        self.first
            .lock()
            .map_err(|_| wrong_state())?
            .take()
            .map(step_ffi)
            .ok_or_else(wrong_state)
    }

    pub fn on_response(&self, response: AuthHttpResponse) -> Result<FolderStepFfi, ShareFlowFfiError> {
        let mut flow = self.flow.lock().map_err(|_| wrong_state())?;
        Ok(step_ffi(flow.on_response(into(response))?))
    }
}

// ── File requests ────────────────────────────────────────────────────────────

/// The created request. `link` carries `R_pub` after `#`; `display` is the part before `#`.
#[derive(uniffi::Record)]
pub struct CreatedRequestFfi {
    pub id: String,
    pub link: String,
    pub display: String,
}

#[derive(uniffi::Object)]
pub struct CreateRequestFlow {
    flow: Mutex<beebeeb_core::share_flow::request::CreateRequest>,
    first: Mutex<Option<beebeeb_core::auth_flow::HttpRequest>>,
}

#[uniffi::export]
impl CreateRequestFlow {
    #[uniffi::constructor]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        app_url: String,
        title: String,
        description: Option<String>,
        target_folder_id: Option<String>,
        max_files: Option<u32>,
        max_total_bytes: Option<u64>,
        expires_in_secs: Option<u64>,
        master_key: Vec<u8>,
    ) -> Result<Arc<Self>, ShareFlowFfiError> {
        let master_key = Zeroizing::new(master_key);
        let bytes: [u8; 32] = master_key
            .as_slice()
            .try_into()
            .map_err(|_| ShareFlowFfiError::from(ShareFlowError::InvalidInput("key length")))?;
        let master = MasterKey::from_bytes(*Zeroizing::new(bytes));
        let options = beebeeb_core::share_flow::request::RequestOptions {
            title,
            description,
            target_folder_id,
            max_files,
            max_total_bytes,
            expires_in_secs,
        };
        let (flow, first) = beebeeb_core::share_flow::request::CreateRequest::start(&app_url, &options, &master)?;
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

    pub fn on_response(&self, response: AuthHttpResponse) -> Result<CreatedRequestFfi, ShareFlowFfiError> {
        let mut flow = self.flow.lock().map_err(|_| wrong_state())?;
        let c = flow.on_response(into(response))?;
        Ok(CreatedRequestFfi {
            id: c.id,
            link: c.link.to_string(),
            display: c.display,
        })
    }
}

/// A request's link again from its stored wrap; `None` when it can't be rebuilt.
#[uniffi::export]
pub fn file_request_rebuild_link(
    app_url: String,
    master_key: Vec<u8>,
    token: Option<String>,
    wrapped_private_key: Option<String>,
    wrap_nonce: Option<String>,
) -> Result<Option<String>, ShareFlowFfiError> {
    let master_key = Zeroizing::new(master_key);
    let bytes: [u8; 32] = master_key
        .as_slice()
        .try_into()
        .map_err(|_| ShareFlowFfiError::from(ShareFlowError::InvalidInput("key length")))?;
    let master = MasterKey::from_bytes(*Zeroizing::new(bytes));
    Ok(beebeeb_core::share_flow::request::rebuild_request_link(
        &app_url,
        &master,
        token.as_deref(),
        wrapped_private_key.as_deref(),
        wrap_nonce.as_deref(),
    )
    .map(|l| l.to_string()))
}

/// `POST /api/v1/file-requests/{id}/close`.
#[uniffi::export]
pub fn file_request_close_request(id: String) -> Result<AuthHttpRequest, ShareFlowFfiError> {
    Ok(out(beebeeb_core::share_flow::request::close_request(&id)?))
}

/// Web `rebuildFolderLinkUrl`: the owner's folder link again; `None` when it can't be rebuilt.
#[uniffi::export]
pub fn share_rebuild_folder_link(
    app_url: String,
    master_key: Vec<u8>,
    share_id: String,
    owner_wrapped_key: Option<String>,
    owner_wrapped_token: Option<String>,
    wrapped_folder_key: Option<String>,
    passphrase_protected: bool,
) -> Result<Option<String>, ShareFlowFfiError> {
    let master_key = Zeroizing::new(master_key);
    let bytes: [u8; 32] = master_key
        .as_slice()
        .try_into()
        .map_err(|_| ShareFlowFfiError::from(ShareFlowError::InvalidInput("key length")))?;
    let master = MasterKey::from_bytes(*Zeroizing::new(bytes));
    Ok(beebeeb_core::share_flow::folder::rebuild_folder_link(
        &app_url,
        &master,
        &share_id,
        owner_wrapped_key.as_deref(),
        owner_wrapped_token.as_deref(),
        wrapped_folder_key.as_deref(),
        passphrase_protected,
    )
    .map(|l| l.to_string()))
}
