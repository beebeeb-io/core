//! Folder invites for web (`beebeeb_core::share_flow::folder`). Thin: the class wraps the core flow;
//! no rule lives here. Errors throw a `JsError` whose message is the core code
//! (`folder_key_unverified`, `folder_keys_unavailable`, `folder_needs_upgrade`, `folder_too_large`, …).
use beebeeb_core::kdf::MasterKey;
use beebeeb_core::share_flow::{
    ShareFlowError,
    folder::{FolderInvite, FolderInviteInput, FolderInviteStep, FolderSend},
    folder_keys::CustodyMemory,
    member::InviteOutcome,
};
use serde_json::json;
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

use super::auth_flow::{request_js, resp, to_js};

fn err(e: ShareFlowError) -> JsError {
    JsError::new(e.code())
}

fn step_js(step: FolderInviteStep) -> Result<JsValue, JsError> {
    match step {
        FolderInviteStep::Send(FolderSend {
            request,
            mark_custody_seen,
        }) => to_js(&json!({
            "kind": "send",
            "request": request_js(&request),
            "markCustodySeen": mark_custody_seen,
        })),
        FolderInviteStep::Done(InviteOutcome::Shared { invite_id }) => {
            to_js(&json!({"kind": "shared", "inviteId": invite_id}))
        }
        FolderInviteStep::Done(InviteOutcome::Invited { invite_id, status }) => {
            to_js(&json!({"kind": "invited", "inviteId": invite_id, "status": status}))
        }
        FolderInviteStep::Done(InviteOutcome::AwaitingApproval { invite_id }) => {
            to_js(&json!({"kind": "awaiting_approval", "inviteId": invite_id}))
        }
    }
}

/// `new ShareFolderInvite(folderId, email, sharedFoldersWrite, custodySeen, custodyUnreadable, masterKey)`;
/// `start()`, then `onResponse(...)` until `{kind: "shared" | "invited" | "awaiting_approval"}`. A
/// `{kind: "send", markCustodySeen}` with an id: persist the id BEFORE sending the request.
#[wasm_bindgen(js_name = ShareFolderInvite)]
pub struct ShareFolderInvite {
    flow: FolderInvite,
    first: Option<FolderInviteStep>,
}

#[wasm_bindgen(js_class = ShareFolderInvite)]
impl ShareFolderInvite {
    #[wasm_bindgen(constructor)]
    pub fn new(
        folder_id: &str,
        email: &str,
        shared_folders_write: bool,
        custody_seen: Vec<String>,
        custody_unreadable: bool,
        master_key: &[u8],
    ) -> Result<ShareFolderInvite, JsError> {
        let bytes: [u8; 32] = master_key
            .try_into()
            .map_err(|_| err(ShareFlowError::InvalidInput("key length")))?;
        let master = MasterKey::from_bytes(*Zeroizing::new(bytes));
        let input = FolderInviteInput {
            folder_id,
            email,
            shared_folders_write,
            custody: CustodyMemory::new(custody_seen, custody_unreadable),
        };
        let (flow, first) = FolderInvite::start(input, &master).map_err(err)?;
        Ok(Self {
            flow,
            first: Some(first),
        })
    }

    pub fn start(&mut self) -> Result<JsValue, JsError> {
        step_js(self.first.take().ok_or_else(|| err(ShareFlowError::WrongState))?)
    }

    #[wasm_bindgen(js_name = onResponse)]
    pub fn on_response(&mut self, status: u16, body: &str, retry_after_secs: Option<u32>) -> Result<JsValue, JsError> {
        step_js(
            self.flow
                .on_response(resp(status, body, retry_after_secs))
                .map_err(err)?,
        )
    }
}
