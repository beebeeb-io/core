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
