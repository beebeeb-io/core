//! Folder invites for mobile (`beebeeb_core::share_flow::folder`). Thin: the object wraps the core
//! flow and converts requests and responses; no rule lives here.
use std::sync::{Arc, Mutex};

use beebeeb_core::kdf::MasterKey;
use beebeeb_core::share_flow::{
    ShareFlowError,
    folder::{FolderInvite, FolderInviteInput, FolderInviteStep, FolderSend},
    folder_keys::CustodyMemory,
    member::InviteOutcome,
};
use zeroize::Zeroizing;

use crate::auth_flow::{AuthHttpRequest, AuthHttpResponse, into, out};
use crate::share_flow::ShareFlowFfiError;

/// A `Send` with `mark_custody_seen`: persist the id in the device's custody memory BEFORE sending.
#[derive(uniffi::Enum)]
pub enum FolderInviteStepFfi {
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
}

fn step_ffi(step: FolderInviteStep) -> FolderInviteStepFfi {
    match step {
        FolderInviteStep::Send(FolderSend {
            request,
            mark_custody_seen,
        }) => FolderInviteStepFfi::Send {
            request: out(request),
            mark_custody_seen,
        },
        FolderInviteStep::Done(InviteOutcome::Shared { invite_id }) => FolderInviteStepFfi::Shared { invite_id },
        FolderInviteStep::Done(InviteOutcome::Invited { invite_id, status }) => {
            FolderInviteStepFfi::Invited { invite_id, status }
        }
        FolderInviteStep::Done(InviteOutcome::AwaitingApproval { invite_id }) => {
            FolderInviteStepFfi::AwaitingApproval { invite_id }
        }
    }
}

fn wrong_state() -> ShareFlowFfiError {
    ShareFlowError::WrongState.into()
}

#[derive(uniffi::Object)]
pub struct FolderInviteFlow {
    flow: Mutex<FolderInvite>,
    first: Mutex<Option<FolderInviteStep>>,
}

#[uniffi::export]
impl FolderInviteFlow {
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
        let (flow, first) = FolderInvite::start(input, &master)?;
        Ok(Arc::new(Self {
            flow: Mutex::new(flow),
            first: Mutex::new(Some(first)),
        }))
    }

    pub fn start(&self) -> Result<FolderInviteStepFfi, ShareFlowFfiError> {
        self.first
            .lock()
            .map_err(|_| wrong_state())?
            .take()
            .map(step_ffi)
            .ok_or_else(wrong_state)
    }

    pub fn on_response(&self, response: AuthHttpResponse) -> Result<FolderInviteStepFfi, ShareFlowFfiError> {
        let mut flow = self.flow.lock().map_err(|_| wrong_state())?;
        Ok(step_ffi(flow.on_response(into(response))?))
    }
}
