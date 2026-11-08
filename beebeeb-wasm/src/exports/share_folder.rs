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

// ── File requests ────────────────────────────────────────────────────────────

/// `new ShareCreateRequest(appUrl, title, description?, targetFolderId?, maxFiles?, maxTotalBytes?,
/// expiresInSecs?, masterKey)`; `start()`, then `onResponse(...)` → `{id, link, display}`.
#[wasm_bindgen(js_name = ShareCreateRequest)]
pub struct ShareCreateRequest {
    flow: beebeeb_core::share_flow::request::CreateRequest,
    first: Option<beebeeb_core::auth_flow::HttpRequest>,
}

fn js_u64(v: Option<f64>, what: &'static str) -> Result<Option<u64>, JsError> {
    match v {
        Some(c) if c.is_finite() && c >= 0.0 && c.fract() == 0.0 && c <= 9_007_199_254_740_991.0 => Ok(Some(c as u64)),
        Some(_) => Err(err(ShareFlowError::InvalidInput(what))),
        None => Ok(None),
    }
}

#[wasm_bindgen(js_class = ShareCreateRequest)]
impl ShareCreateRequest {
    #[wasm_bindgen(constructor)]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        app_url: &str,
        title: String,
        description: Option<String>,
        target_folder_id: Option<String>,
        max_files: Option<u32>,
        max_total_bytes: Option<f64>,
        expires_in_secs: Option<f64>,
        master_key: &[u8],
    ) -> Result<ShareCreateRequest, JsError> {
        let bytes: [u8; 32] = master_key
            .try_into()
            .map_err(|_| err(ShareFlowError::InvalidInput("key length")))?;
        let master = MasterKey::from_bytes(*Zeroizing::new(bytes));
        let options = beebeeb_core::share_flow::request::RequestOptions {
            title,
            description,
            target_folder_id,
            max_files,
            max_total_bytes: js_u64(max_total_bytes, "max total bytes")?,
            expires_in_secs: js_u64(expires_in_secs, "expires in secs")?,
        };
        let (flow, first) =
            beebeeb_core::share_flow::request::CreateRequest::start(app_url, &options, &master).map_err(err)?;
        Ok(Self {
            flow,
            first: Some(first),
        })
    }

    pub fn start(&mut self) -> Result<JsValue, JsError> {
        to_js(&request_js(
            &self.first.take().ok_or_else(|| err(ShareFlowError::WrongState))?,
        ))
    }

    #[wasm_bindgen(js_name = onResponse)]
    pub fn on_response(&mut self, status: u16, body: &str, retry_after_secs: Option<u32>) -> Result<JsValue, JsError> {
        let c = self
            .flow
            .on_response(resp(status, body, retry_after_secs))
            .map_err(err)?;
        to_js(&json!({ "id": c.id, "link": *c.link, "display": c.display }))
    }
}

/// Web `handleCopyExisting` in core: the request's link, or `undefined`.
#[wasm_bindgen(js_name = fileRequestRebuildLink)]
pub fn file_request_rebuild_link(
    app_url: &str,
    master_key: &[u8],
    token: Option<String>,
    wrapped_private_key: Option<String>,
    wrap_nonce: Option<String>,
) -> Result<Option<String>, JsError> {
    let bytes: [u8; 32] = master_key
        .try_into()
        .map_err(|_| err(ShareFlowError::InvalidInput("key length")))?;
    let master = MasterKey::from_bytes(*Zeroizing::new(bytes));
    Ok(beebeeb_core::share_flow::request::rebuild_request_link(
        app_url,
        &master,
        token.as_deref(),
        wrapped_private_key.as_deref(),
        wrap_nonce.as_deref(),
    )
    .map(|l| l.to_string()))
}

/// `shareCreateBundle(appUrl, fileIds, positions, fileKeys, masterKey, expiresInHours?, maxOpens?, passphrase?)`:
/// a `ShareCreateLink` over an ordered set of files (web's bundle branch). `fileKeys` is the
/// concatenation of each item's 32-byte key, in the order of `fileIds`.
#[wasm_bindgen(js_name = shareCreateBundle)]
#[allow(clippy::too_many_arguments)]
pub fn share_create_bundle(
    app_url: &str,
    file_ids: Vec<String>,
    positions: Vec<u32>,
    file_keys: &[u8],
    master_key: &[u8],
    expires_in_hours: Option<u32>,
    max_opens: Option<u32>,
    passphrase: Option<String>,
) -> Result<super::share_flow::ShareCreateLink, JsError> {
    if file_ids.len() != positions.len() || file_keys.len() != file_ids.len() * 32 {
        return Err(err(ShareFlowError::InvalidInput("items")));
    }
    let keys: Vec<beebeeb_core::kdf::FileKey> = file_keys
        .chunks_exact(32)
        .map(|c| {
            let arr: [u8; 32] = c.try_into().expect("32-byte chunk");
            beebeeb_core::kdf::FileKey::from_bytes(*Zeroizing::new(arr))
        })
        .collect();
    let items: Vec<beebeeb_core::share_flow::bundle::BundleItem<'_>> = file_ids
        .iter()
        .zip(&positions)
        .zip(&keys)
        .map(|((id, p), k)| beebeeb_core::share_flow::bundle::BundleItem {
            file_id: id,
            position: *p,
            file_key: k,
        })
        .collect();
    let bytes: [u8; 32] = master_key
        .try_into()
        .map_err(|_| err(ShareFlowError::InvalidInput("key length")))?;
    let master = MasterKey::from_bytes(*Zeroizing::new(bytes));
    let options = beebeeb_core::share_flow::link::LinkOptions {
        expires_in_hours,
        max_opens,
        passphrase: passphrase.map(Zeroizing::new),
    };
    let (flow, first) =
        beebeeb_core::share_flow::link::CreateLink::bundle(app_url, &items, &master, &options).map_err(err)?;
    Ok(super::share_flow::ShareCreateLink::from_parts(flow, first))
}
