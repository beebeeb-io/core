//! A double-encrypted public link to one file (web `share-dialog.tsx`, "the only mode, task
//! 0538") and its owner-side rebuild (web `share-link.ts` `buildShareLink`).
//!
//! ```text
//! CreateLink::start ──► POST /api/v1/shares
//!     {file_id, expires_in_hours, max_opens, passphrase?, wrapped_file_key,
//!      owner_wrapped_key, token, owner_wrapped_token}
//!   on_response ◄── 409 without a typed code (a token collision) ──► the same body, fresh token (once)
//!   on_response ◄── {id, ...} ──► Created { share_id, link: {app}/s/{token}#key={b64url(K_c)} }
//! ```
//!
//! `wrapped_file_key = wrap(K_c, file_key)`, `owner_wrapped_key = wrap(master, K_c)` and
//! `owner_wrapped_token = wrap(master, utf8(token))`, all [`super::wrap_key_for_share`] frames in
//! standard base64. The server never sees `K_c` or the file key; it receives the raw token and
//! hashes it at rest.
use base64::Engine;
use serde_json::{Value, json};
use zeroize::Zeroizing;

use super::{
    SHARE_REFUSAL_CODES, ShareFlowError, b64, b64_decode, path_id, require_ok, str_field, unwrap_key_from_share,
    wrap_key_for_share,
};
use crate::auth_flow::{HttpRequest, HttpResponse, RequestAuth};
use crate::kdf::{FileKey, MasterKey};
use crate::share_link::{self, ShareRoute};
use crate::share_token::generate_share_token;

pub const SHARES_PATH: &str = "/api/v1/shares";
/// Web refuses a passphrase shorter than this (after trimming).
pub const MIN_PASSPHRASE_LEN: usize = 4;

/// The link's limits, as web's share dialog sends them. `None` is "never" / "unlimited".
#[derive(Default)]
pub struct LinkOptions {
    pub expires_in_hours: Option<u32>,
    pub max_opens: Option<u32>,
    pub passphrase: Option<Zeroizing<String>>,
}

/// A link the server accepted. `link` carries `K_c`: put it on the clipboard, show
/// [`super::display_form`] instead.
pub struct CreatedLink {
    pub share_id: String,
    pub link: Zeroizing<String>,
}

impl std::fmt::Debug for CreatedLink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CreatedLink")
            .field("share_id", &self.share_id)
            .field("link", &"<redacted>")
            .finish()
    }
}

#[derive(Debug)]
pub enum LinkStep {
    Send(HttpRequest),
    Created(CreatedLink),
}

pub struct CreateLink {
    app_url: String,
    master: MasterKey,
    k_c: Zeroizing<[u8; 32]>,
    body: Value,
    token: Zeroizing<String>,
    retried: bool,
    done: bool,
}

impl std::fmt::Debug for CreateLink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CreateLink(<redacted>)")
    }
}

fn random_key() -> Result<Zeroizing<[u8; 32]>, ShareFlowError> {
    let key = FileKey::generate().map_err(|_| ShareFlowError::Crypto)?;
    Ok(Zeroizing::new(*key.as_bytes()))
}

impl CreateLink {
    /// `file_key` is the key that opens the row (web's `shareFileKey`); `app_url` is the web origin
    /// the link points at (`https://app.beebeeb.io`).
    pub fn start(
        app_url: &str,
        file_id: &str,
        master: &MasterKey,
        file_key: &FileKey,
        options: &LinkOptions,
    ) -> Result<(Self, HttpRequest), ShareFlowError> {
        let file_id = path_id(file_id).map_err(|_| ShareFlowError::InvalidInput("item id"))?;
        let passphrase = Self::check(app_url, options)?;
        let k_c = random_key()?;
        let wrapped_file_key = wrap_key_for_share(&k_c, file_key.as_bytes())?;
        let owner_wrapped_key = wrap_key_for_share(master.as_bytes(), &*k_c)?;
        let mut body = json!({
            "file_id": file_id,
            "expires_in_hours": options.expires_in_hours,
            "max_opens": options.max_opens,
            "wrapped_file_key": b64(&wrapped_file_key),
            "owner_wrapped_key": b64(&owner_wrapped_key),
        });
        if let Some(p) = passphrase {
            body["passphrase"] = json!(p);
        }
        Self::from_body(app_url, master, k_c, body)
    }

    /// Checks shared by every link kind: the app URL and the passphrase (trimmed, at least
    /// [`MIN_PASSPHRASE_LEN`] characters). Returns the trimmed passphrase.
    pub(super) fn check<'a>(app_url: &str, options: &'a LinkOptions) -> Result<Option<&'a str>, ShareFlowError> {
        if !(app_url.starts_with("https://") || app_url.starts_with("http://localhost")) {
            return Err(ShareFlowError::InvalidInput("app url"));
        }
        let passphrase = options.passphrase.as_ref().map(|p| p.trim()).filter(|p| !p.is_empty());
        if passphrase.is_some_and(|p| p.chars().count() < MIN_PASSPHRASE_LEN) {
            return Err(ShareFlowError::InvalidInput("passphrase too short"));
        }
        Ok(passphrase)
    }

    pub(super) fn new_client_key() -> Result<Zeroizing<[u8; 32]>, ShareFlowError> {
        random_key()
    }

    /// The token leg shared by file links and bundles: a fresh token, its owner copy, one retry.
    pub(super) fn from_body(
        app_url: &str,
        master: &MasterKey,
        k_c: Zeroizing<[u8; 32]>,
        body: Value,
    ) -> Result<(Self, HttpRequest), ShareFlowError> {
        let mut flow = Self {
            app_url: app_url.trim_end_matches('/').to_owned(),
            master: super::own_master(master),
            k_c,
            body,
            token: Zeroizing::new(String::new()),
            retried: false,
            done: false,
        };
        let request = flow.request_with_fresh_token()?;
        Ok((flow, request))
    }

    fn request_with_fresh_token(&mut self) -> Result<HttpRequest, ShareFlowError> {
        self.token = Zeroizing::new(generate_share_token());
        let owner_wrapped_token = wrap_key_for_share(self.master.as_bytes(), self.token.as_bytes())?;
        self.body["token"] = json!(self.token.as_str());
        self.body["owner_wrapped_token"] = json!(b64(&owner_wrapped_token));
        Ok(HttpRequest::post(SHARES_PATH, self.body.clone(), RequestAuth::Session))
    }

    pub fn on_response(&mut self, resp: HttpResponse) -> Result<LinkStep, ShareFlowError> {
        if self.done {
            return Err(ShareFlowError::WrongState);
        }
        if resp.status == 409 && !self.retried {
            let code = resp.body.get("code").and_then(|v| v.as_str());
            if !code.is_some_and(|c| SHARE_REFUSAL_CODES.contains(&c)) {
                self.retried = true;
                return self.request_with_fresh_token().map(LinkStep::Send);
            }
        }
        self.done = true;
        require_ok(&resp)?;
        let share_id = path_id(str_field(&resp, "id")?)?.to_owned();
        let key = Zeroizing::new(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(*self.k_c));
        let link = Zeroizing::new(share_link::build_for(
            &self.app_url,
            &self.token,
            &key,
            ShareRoute::Single,
        ));
        Ok(LinkStep::Created(CreatedLink { share_id, link }))
    }
}

/// Rebuild a working link from a share's owner blobs (web `buildShareLink`). `None` when the share
/// has no blobs (a legacy share), a blob does not open, `K_c` is not 32 bytes or the token is empty:
/// the caller shows its honest "the key isn't stored" copy instead.
pub fn rebuild_link(
    app_url: &str,
    master: &MasterKey,
    owner_wrapped_key_b64: Option<&str>,
    owner_wrapped_token_b64: Option<&str>,
) -> Option<Zeroizing<String>> {
    let wrapped_key = b64_decode(owner_wrapped_key_b64.filter(|s| !s.is_empty())?).ok()?;
    let wrapped_token = b64_decode(owner_wrapped_token_b64.filter(|s| !s.is_empty())?).ok()?;
    let k_c = unwrap_key_from_share(master.as_bytes(), &wrapped_key).ok()?;
    if k_c.len() != 32 {
        return None;
    }
    let token_bytes = unwrap_key_from_share(master.as_bytes(), &wrapped_token).ok()?;
    let token = Zeroizing::new(String::from_utf8(token_bytes.to_vec()).ok()?);
    if token.is_empty() {
        return None;
    }
    let key = Zeroizing::new(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&*k_c));
    Some(Zeroizing::new(share_link::build_for(
        app_url,
        &token,
        &key,
        ShareRoute::Single,
    )))
}

/// The recipient side: open a link's `wrapped_file_key` with the `#key=` value of the link.
pub fn open_link_file_key(fragment_key: &str, wrapped_file_key_b64: &str) -> Result<FileKey, ShareFlowError> {
    let k_c = Zeroizing::new(share_link::key_bytes(fragment_key).ok_or(ShareFlowError::InvalidInput("link key"))?);
    let k_c: &[u8; 32] = k_c
        .as_slice()
        .try_into()
        .map_err(|_| ShareFlowError::InvalidInput("link key"))?;
    let plain = unwrap_key_from_share(k_c, &b64_decode(wrapped_file_key_b64)?)?;
    let bytes: [u8; 32] = plain.as_slice().try_into().map_err(|_| ShareFlowError::Crypto)?;
    Ok(FileKey::from_bytes(bytes))
}
