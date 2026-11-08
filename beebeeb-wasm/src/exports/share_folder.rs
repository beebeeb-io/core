//! Folder invites and folder links for web (`beebeeb_core::share_flow::folder`). Thin: the class wraps the core flow;
//! no rule lives here. Errors throw a `JsError` whose message is the core code
//! (`folder_key_unverified`, `folder_keys_unavailable`, `folder_needs_upgrade`, `folder_too_large`, …).
use beebeeb_core::kdf::MasterKey;
use beebeeb_core::share_flow::{
    ShareFlowError, display_form,
    folder::{FolderInviteInput, FolderLinkInput, FolderSend, FolderShare, FolderStep},
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

fn step_js(step: FolderStep) -> Result<JsValue, JsError> {
    match step {
        FolderStep::Send(FolderSend {
            request,
            mark_custody_seen,
        }) => to_js(&json!({
            "kind": "send",
            "request": request_js(&request),
            "markCustodySeen": mark_custody_seen,
        })),
        FolderStep::Done(InviteOutcome::Shared { invite_id }) => {
            to_js(&json!({"kind": "shared", "inviteId": invite_id}))
        }
        FolderStep::Done(InviteOutcome::Invited { invite_id, status }) => {
            to_js(&json!({"kind": "invited", "inviteId": invite_id, "status": status}))
        }
        FolderStep::Done(InviteOutcome::AwaitingApproval { invite_id }) => {
            to_js(&json!({"kind": "awaiting_approval", "inviteId": invite_id}))
        }
        FolderStep::LinkCreated(c) => to_js(&json!({
            "kind": "link_created",
            "shareId": c.share_id,
            "link": *c.link,
            "display": display_form(&c.link),
            "accessLevel": c.access_level,
            "passphraseProtected": c.passphrase_protected,
            "keyVersion": c.key_version,
        })),
    }
}

/// `new ShareFolderInvite(folderId, email, sharedFoldersWrite, custodySeen, custodyUnreadable, masterKey)`
/// or `ShareFolderInvite.link(folderId, appUrl, accessLevel, label?, expiresInHours?, capBytes?,
/// maxOpens?, passphrase?, custodySeen, custodyUnreadable, masterKey)`; `start()`, then
/// `onResponse(...)` until `{kind: "shared" | "invited" | "awaiting_approval" | "link_created"}`. A
/// `{kind: "send", markCustodySeen}` with an id: persist the id BEFORE sending the request.
#[wasm_bindgen(js_name = ShareFolderInvite)]
pub struct ShareFolderInvite {
    flow: FolderShare,
    first: Option<FolderStep>,
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
        let (flow, first) = FolderShare::invite(input, &master).map_err(err)?;
        Ok(Self {
            flow,
            first: Some(first),
        })
    }

    /// A live folder link (web `createFolderLinkWithKeys`).
    #[allow(clippy::too_many_arguments)]
    pub fn link(
        folder_id: &str,
        app_url: &str,
        access_level: &str,
        label: Option<String>,
        expires_in_hours: Option<u32>,
        cap_bytes: Option<f64>,
        max_opens: Option<u32>,
        passphrase: Option<String>,
        custody_seen: Vec<String>,
        custody_unreadable: bool,
        master_key: &[u8],
    ) -> Result<ShareFolderInvite, JsError> {
        let passphrase = passphrase.map(Zeroizing::new);
        let bytes: [u8; 32] = master_key
            .try_into()
            .map_err(|_| err(ShareFlowError::InvalidInput("key length")))?;
        let master = MasterKey::from_bytes(*Zeroizing::new(bytes));
        let cap_bytes = match cap_bytes {
            Some(c) if c.is_finite() && c >= 0.0 && c.fract() == 0.0 && c <= 9_007_199_254_740_991.0 => Some(c as u64),
            Some(_) => return Err(err(ShareFlowError::InvalidInput("cap bytes"))),
            None => None,
        };
        let input = FolderLinkInput {
            folder_id,
            app_url,
            access_level,
            label: label.as_deref(),
            expires_in_hours,
            cap_bytes,
            max_opens,
            passphrase,
            custody: CustodyMemory::new(custody_seen, custody_unreadable),
        };
        let (flow, first) = FolderShare::link(input, &master).map_err(err)?;
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
