//! Share flows for web (`beebeeb_core::share_flow`). Thin: each class wraps one core flow and
//! converts requests and responses the way `exports::auth_flow` does; no rule lives here.
//! Errors throw a `JsError` whose message is the core code (`invalid_input`, `plan_required`, …).
use beebeeb_core::auth_flow::HttpRequest;
use beebeeb_core::kdf::{FileKey, MasterKey};
use beebeeb_core::share_flow::{
    self as sf, ShareFlowError,
    link::{CreateLink, LinkOptions, LinkStep},
    member::{InviteOutcome, InviteStep, MemberInvite, ShareTarget},
};
use serde_json::json;
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

use super::auth_flow::{request_js, resp, to_js};

fn err(e: ShareFlowError) -> JsError {
    JsError::new(e.code())
}

fn wrong_state() -> JsError {
    err(ShareFlowError::WrongState)
}

fn key32(bytes: &[u8]) -> Result<Zeroizing<[u8; 32]>, JsError> {
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| err(ShareFlowError::InvalidInput("key length")))?;
    Ok(Zeroizing::new(arr))
}

/// An invite outcome as JS: `recipientPublicKey` (hex) is the exact key the share was sealed to.
pub(crate) fn outcome_js(o: InviteOutcome) -> Result<JsValue, JsError> {
    let hex = |k: &[u8; 32]| k.iter().map(|b| format!("{b:02x}")).collect::<String>();
    to_js(&match o {
        InviteOutcome::Shared {
            invite_id,
            recipient_public_key,
        } => json!({"kind": "shared", "inviteId": invite_id, "recipientPublicKey": hex(&recipient_public_key)}),
        InviteOutcome::Invited { invite_id, status } => {
            json!({"kind": "invited", "inviteId": invite_id, "status": status})
        }
        InviteOutcome::AwaitingApproval {
            invite_id,
            recipient_public_key,
        } => json!({"kind": "awaiting_approval", "inviteId": invite_id,
            "recipientPublicKey": recipient_public_key.as_ref().map(hex)}),
        InviteOutcome::PeerKeyChanged {
            invite_id,
            recipient_public_key,
        } => json!({"kind": "peer_key_changed", "inviteId": invite_id,
            "recipientPublicKey": hex(&recipient_public_key)}),
    })
}

/// A compared mark's fingerprint (32 bytes) or `invalid_input`.
pub(crate) fn expected_fp(fp: Option<Vec<u8>>) -> Result<Option<[u8; 32]>, JsError> {
    fp.map(|v| <[u8; 32]>::try_from(v.as_slice()).map_err(|_| err(ShareFlowError::InvalidInput("fingerprint length"))))
        .transpose()
}

fn send(req: HttpRequest) -> Result<JsValue, JsError> {
    to_js(&json!({ "kind": "send", "request": request_js(&req) }))
}

/// Web's `wrapKeyForShare` in core: `nonce(12) || ciphertext`, no AAD.
#[wasm_bindgen(js_name = shareWrapKey)]
pub fn share_wrap_key(wrap_key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, JsError> {
    sf::wrap_key_for_share(&*key32(wrap_key)?, plaintext).map_err(err)
}

#[wasm_bindgen(js_name = shareUnwrapKey)]
pub fn share_unwrap_key(wrap_key: &[u8], wrapped: &[u8]) -> Result<Vec<u8>, JsError> {
    sf::unwrap_key_from_share(&*key32(wrap_key)?, wrapped)
        .map(|k| k.to_vec())
        .map_err(err)
}

/// `new ShareMemberInvite(itemId, isFolder, email, masterKey, fileKey)`; `start()`, then
/// `onResponse(...)` until `{kind: "shared" | "invited" | "awaiting_approval", inviteId}`.
#[wasm_bindgen(js_name = ShareMemberInvite)]
pub struct ShareMemberInvite {
    flow: MemberInvite,
    first: Option<HttpRequest>,
}

#[wasm_bindgen(js_class = ShareMemberInvite)]
impl ShareMemberInvite {
    #[wasm_bindgen(constructor)]
    pub fn new(
        item_id: String,
        is_folder: bool,
        email: &str,
        master_key: &[u8],
        file_key: &[u8],
        expected_peer_fingerprint: Option<Vec<u8>>,
    ) -> Result<ShareMemberInvite, JsError> {
        let target = ShareTarget { item_id, is_folder };
        let master = MasterKey::from_bytes(*key32(master_key)?);
        let key = FileKey::from_bytes(*key32(file_key)?);
        let expected = expected_fp(expected_peer_fingerprint)?;
        let (flow, first) = MemberInvite::start(&target, email, &master, &key, expected).map_err(err)?;
        Ok(Self {
            flow,
            first: Some(first),
        })
    }

    pub fn start(&mut self) -> Result<JsValue, JsError> {
        to_js(&request_js(&self.first.take().ok_or_else(wrong_state)?))
    }

    #[wasm_bindgen(js_name = onResponse)]
    pub fn on_response(&mut self, status: u16, body: &str, retry_after_secs: Option<u32>) -> Result<JsValue, JsError> {
        match self
            .flow
            .on_response(resp(status, body, retry_after_secs))
            .map_err(err)?
        {
            InviteStep::Send(req) => send(req),
            InviteStep::Done(outcome) => outcome_js(outcome),
        }
    }
}

/// `new ShareCreateLink(appUrl, fileId, masterKey, fileKey, expiresInHours?, maxOpens?, passphrase?)`;
/// `start()`, then `onResponse(...)` until `{kind: "created", shareId, link, display}`.
#[wasm_bindgen(js_name = ShareCreateLink)]
pub struct ShareCreateLink {
    flow: CreateLink,
    first: Option<HttpRequest>,
}

impl ShareCreateLink {
    pub(crate) fn from_parts(flow: CreateLink, first: HttpRequest) -> Self {
        Self {
            flow,
            first: Some(first),
        }
    }
}

#[wasm_bindgen(js_class = ShareCreateLink)]
impl ShareCreateLink {
    #[wasm_bindgen(constructor)]
    pub fn new(
        app_url: &str,
        file_id: &str,
        master_key: &[u8],
        file_key: &[u8],
        expires_in_hours: Option<u32>,
        max_opens: Option<u32>,
        passphrase: Option<String>,
    ) -> Result<ShareCreateLink, JsError> {
        let master = MasterKey::from_bytes(*key32(master_key)?);
        let key = FileKey::from_bytes(*key32(file_key)?);
        let options = LinkOptions {
            expires_in_hours,
            max_opens,
            passphrase: passphrase.map(Zeroizing::new),
        };
        let (flow, first) = CreateLink::start(app_url, file_id, &master, &key, &options).map_err(err)?;
        Ok(Self {
            flow,
            first: Some(first),
        })
    }

    pub fn start(&mut self) -> Result<JsValue, JsError> {
        to_js(&request_js(&self.first.take().ok_or_else(wrong_state)?))
    }

    #[wasm_bindgen(js_name = onResponse)]
    pub fn on_response(&mut self, status: u16, body: &str, retry_after_secs: Option<u32>) -> Result<JsValue, JsError> {
        match self
            .flow
            .on_response(resp(status, body, retry_after_secs))
            .map_err(err)?
        {
            LinkStep::Send(req) => send(req),
            LinkStep::Created(c) => to_js(&json!({
                "kind": "created",
                "shareId": c.share_id,
                "display": sf::display_form(&c.link),
                "link": c.link.as_str(),
            })),
        }
    }
}

/// The owner's working link from a share's owner blobs; `undefined` when it can't be rebuilt.
#[wasm_bindgen(js_name = shareRebuildLink)]
pub fn share_rebuild_link(
    app_url: &str,
    master_key: &[u8],
    owner_wrapped_key: Option<String>,
    owner_wrapped_token: Option<String>,
) -> Result<Option<String>, JsError> {
    let master = MasterKey::from_bytes(*key32(master_key)?);
    Ok(sf::link::rebuild_link(
        app_url,
        &master,
        owner_wrapped_key.as_deref(),
        owner_wrapped_token.as_deref(),
    )
    .map(|l| l.to_string()))
}

/// The recipient side of a person share.
#[wasm_bindgen(js_name = shareOpenMemberFileKey)]
pub fn share_open_member_file_key(
    master_key: &[u8],
    owner_public_key: &[u8],
    file_id: &str,
    sealed: &[u8],
) -> Result<Vec<u8>, JsError> {
    let master = MasterKey::from_bytes(*key32(master_key)?);
    sf::open_member_file_key(&master, &*key32(owner_public_key)?, file_id, sealed)
        .map(|k| k.as_bytes().to_vec())
        .map_err(err)
}
