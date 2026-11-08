//! A live folder link (web `folder-link-create.ts` `createFolderLinkWithKeys`).
//!
//! The folder key comes from custody exactly as for an invite on the shared-folders path
//! (`ensureOwnerFolderKey`), every descendant is an L7 wrap, and then:
//! - a random 32-byte token (base64url, no padding) and a random link key `K_c`;
//! - `wrapped_folder_key = wrap(combine_folder_link_key(K_c, stretch?), folder_key)`, where the
//!   stretch is core's Argon2id of the NFC passphrase bound to the token; `K_c` stays in `#key=`;
//! - the share id is proposed here (UUIDv4), and both owner copies (`K_c`, the token) and the
//!   label are sealed under it (L6a, L16); a `409 id_taken` re-seals under a fresh id, at most
//!   [`LINK_ID_ATTEMPTS`] tries; a server that stores another id is refused.
use base64::Engine;
use serde_json::{Value, json};
use zeroize::Zeroizing;

use super::super::{ShareFlowError, b64, display_form, frame, wrap_key_for_share};
use super::{FolderShare, FolderStep, Purpose, Stage, error_code, send};
use crate::auth_flow::{HttpRequest, HttpResponse, RequestAuth};
use crate::kdf::{self, FileKey, MasterKey};
use crate::share_link::{self, ShareRoute};

/// Web `LINK_ID_ATTEMPTS`: how often a create is re-sealed under a fresh id after `409 id_taken`.
pub const LINK_ID_ATTEMPTS: u32 = 3;
#[cfg(test)]
mod tests;

const FOLDER_LINKS_PATH: &str = "/api/v1/shares/folder-links";
const ACCESS_LEVELS: [&str; 3] = ["view", "add", "edit"];

/// What a folder link is made from. `None` means "not set" for every option, as in web.
pub struct FolderLinkInput<'a> {
    pub folder_id: &'a str,
    pub app_url: &'a str,
    /// `view`, `add` or `edit`.
    pub access_level: &'a str,
    pub label: Option<&'a str>,
    pub expires_in_hours: Option<u32>,
    pub cap_bytes: Option<u64>,
    pub max_opens: Option<u32>,
    pub passphrase: Option<Zeroizing<String>>,
    pub custody: super::CustodyMemory,
}

pub(super) struct LinkPlan {
    app_url: String,
    access_level: String,
    label: Option<String>,
    expires_in_hours: Option<u32>,
    cap_bytes: Option<u64>,
    max_opens: Option<u32>,
    passphrase: Option<Zeroizing<String>>,
    sealed: Option<Sealed>,
}

/// Everything that stays the same across `id_taken` retries.
struct Sealed {
    token: Zeroizing<String>,
    k_c: FileKey,
    wrapped_folder_key: String,
    folder_keys: Vec<Value>,
}

/// The stored link. `link` is the full URL with `#key=`; `display` is the part before `#`.
pub struct CreatedFolderLink {
    pub share_id: String,
    pub link: Zeroizing<String>,
    pub display: String,
    pub access_level: String,
    pub passphrase_protected: bool,
    pub key_version: u64,
}

impl std::fmt::Debug for CreatedFolderLink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CreatedFolderLink")
            .field("share_id", &self.share_id)
            .field("display", &self.display)
            .finish_non_exhaustive()
    }
}

/// Web `normalizeLinkPassphrase`: NFC, and a passphrase that is only spaces is refused.
fn normalize_passphrase(raw: &str) -> Result<Zeroizing<String>, ShareFlowError> {
    use unicode_normalization::UnicodeNormalization;
    let nfc = Zeroizing::new(raw.nfc().collect::<String>());
    if nfc.trim().is_empty() {
        return Err(ShareFlowError::InvalidInput("passphrase empty"));
    }
    Ok(nfc)
}

fn random32() -> Result<Zeroizing<[u8; 32]>, ShareFlowError> {
    use rand::RngCore;
    let mut bytes = Zeroizing::new([0u8; 32]);
    rand::rngs::OsRng
        .try_fill_bytes(&mut *bytes)
        .map_err(|_| ShareFlowError::Crypto)?;
    Ok(bytes)
}

impl FolderShare {
    /// A live folder link. Like web, it always goes through the folder's custody record.
    pub fn link(input: FolderLinkInput<'_>, master: &MasterKey) -> Result<(Self, FolderStep), ShareFlowError> {
        if !ACCESS_LEVELS.contains(&input.access_level) {
            return Err(ShareFlowError::InvalidInput("access level"));
        }
        // An empty passphrase means "none"; anything typed is used exactly (NFC).
        let passphrase = match input.passphrase.as_deref().filter(|p| !p.is_empty()) {
            Some(p) => Some(normalize_passphrase(p)?),
            None => None,
        };
        let plan = LinkPlan {
            app_url: input.app_url.to_owned(),
            access_level: input.access_level.to_owned(),
            label: input.label.filter(|l| !l.is_empty()).map(str::to_owned),
            expires_in_hours: input.expires_in_hours,
            cap_bytes: input.cap_bytes,
            max_opens: input.max_opens,
            passphrase,
            sealed: None,
        };
        let mut flow = Self::new(input.folder_id, Purpose::Link(Box::new(plan)), master, input.custody)?;
        flow.stage = Stage::EnsureRead;
        let step = send(super::get(super::custody_path(&flow.folder_id)));
        Ok((flow, step))
    }

    /// The first create request, once the folder key and every child wrap exist.
    pub(super) fn link_request(&mut self, folder_keys: Vec<Value>) -> Result<FolderStep, ShareFlowError> {
        let keyed = self.keyed.as_ref().ok_or(ShareFlowError::WrongState)?;
        if keyed.format != super::FolderWrapFormat::L7 {
            return Err(ShareFlowError::WrongState);
        }
        let Purpose::Link(plan) = &mut self.purpose else {
            return Err(ShareFlowError::WrongState);
        };
        let token = Zeroizing::new(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(*random32()?));
        let k_c = FileKey::from_bytes(*random32()?);
        let stretch = match &plan.passphrase {
            Some(p) => Some(kdf::derive_folder_link_passphrase_stretch(p, &token).map_err(|_| ShareFlowError::Crypto)?),
            None => None,
        };
        let unwrap_key = Zeroizing::new(kdf::combine_folder_link_key(k_c.as_bytes(), stretch.as_deref()));
        let wrapped_folder_key = b64(&wrap_key_for_share(&unwrap_key, keyed.folder_key.as_bytes())?);
        plan.sealed = Some(Sealed {
            token,
            k_c,
            wrapped_folder_key,
            folder_keys,
        });
        self.send_link(1)
    }

    /// Seal the owner copies and the label under a fresh share id, and send the create.
    fn send_link(&mut self, attempt: u32) -> Result<FolderStep, ShareFlowError> {
        let Purpose::Link(plan) = &self.purpose else {
            return Err(ShareFlowError::WrongState);
        };
        let sealed = plan.sealed.as_ref().ok_or(ShareFlowError::WrongState)?;
        let id = uuid::Uuid::new_v4().hyphenated().to_string();
        let crypto = |_| ShareFlowError::Crypto;
        let owner_key = kdf::wrap_link_owner_key(&self.master, id.as_bytes(), &sealed.k_c).map_err(crypto)?;
        let owner_token =
            kdf::wrap_link_owner_token(&self.master, id.as_bytes(), sealed.token.as_bytes()).map_err(crypto)?;
        let mut body = json!({
            "id": id,
            "folder_id": self.folder_id,
            "token": *sealed.token,
            "access_level": plan.access_level,
            "wrapped_folder_key": sealed.wrapped_folder_key,
            "owner_wrapped_key": b64(&frame(owner_key)),
            "owner_wrapped_token": b64(&frame(owner_token)),
            "folder_keys": sealed.folder_keys,
            "format": "l7",
        });
        if let Some(label) = &plan.label {
            let share = uuid::Uuid::parse_str(&id).map_err(|_| ShareFlowError::WrongState)?;
            let wrapped = kdf::wrap_link_label(&self.master, share.as_bytes(), label)
                .map_err(|_| ShareFlowError::InvalidInput("label"))?;
            body["label_encrypted"] = json!(b64(&frame(wrapped)));
        }
        if let Some(h) = plan.expires_in_hours {
            body["expires_in_hours"] = json!(h);
        }
        if let Some(n) = plan.max_opens {
            body["max_opens"] = json!(n);
        }
        if let Some(c) = plan.cap_bytes {
            body["cap_bytes"] = json!(c);
        }
        if let Some(p) = &plan.passphrase {
            body["passphrase"] = json!(**p);
        }
        self.stage = Stage::AwaitLink { id, attempt };
        Ok(send(HttpRequest::post(FOLDER_LINKS_PATH, body, RequestAuth::Session)))
    }

    pub(super) fn on_link_response(
        &mut self,
        resp: HttpResponse,
        id: String,
        attempt: u32,
    ) -> Result<FolderStep, ShareFlowError> {
        if !resp.ok() {
            if error_code(&resp) == Some("id_taken") && attempt < LINK_ID_ATTEMPTS {
                return self.send_link(attempt + 1);
            }
            if resp.status == 409 && error_code(&resp) == Some("upgrade_required") {
                return Err(ShareFlowError::FolderNeedsUpgrade);
            }
            return Err(ShareFlowError::from_status(&resp));
        }
        // The owner copies are bound to `id`: another stored id is a link its owner can't copy again.
        if resp.body.get("id").and_then(Value::as_str) != Some(id.as_str()) {
            return Err(ShareFlowError::Protocol("stored under another id"));
        }
        let Purpose::Link(plan) = &mut self.purpose else {
            return Err(ShareFlowError::WrongState);
        };
        let sealed = plan.sealed.take().ok_or(ShareFlowError::WrongState)?;
        let fragment = Zeroizing::new(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sealed.k_c.as_bytes()));
        let link = Zeroizing::new(share_link::build_for(
            &plan.app_url,
            &sealed.token,
            &fragment,
            ShareRoute::Folder,
        ));
        self.keyed = None;
        Ok(FolderStep::LinkCreated(CreatedFolderLink {
            display: display_form(&link),
            link,
            share_id: id,
            access_level: resp
                .body
                .get("access_level")
                .and_then(Value::as_str)
                .unwrap_or(&plan.access_level)
                .to_owned(),
            passphrase_protected: plan.passphrase.is_some(),
            key_version: resp
                .body
                .get("key_version")
                .and_then(Value::as_u64)
                .ok_or(ShareFlowError::Protocol("key version"))?,
        }))
    }
}
