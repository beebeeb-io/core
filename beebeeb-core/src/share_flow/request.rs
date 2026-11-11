//! File requests: a link anyone can upload into (web `pages/file-request.tsx`).
//!
//! ```text
//! CreateRequest::start ──► POST /api/v1/file-requests
//!     {title, description?, target_folder_id?, max_files?, max_total_bytes?, expires_in_secs?,
//!      wrapped_private_key, wrap_nonce}
//!   on_response ◄── {id, token, …} ──► Created { link: {app}/r/{token}#{b64url(R_pub)} }
//! ```
//!
//! A random X25519 keypair per request; `R_priv` is wrapped under the owner's master key with
//! [`crate::file_request::wrap_request_private`] and an EMPTY request id (web
//! `FILE_REQUEST_EMPTY_ID`: the id is the server's, and does not exist yet). `R_pub` lives only in
//! the link's fragment. [`rebuild_request_link`] is web's `handleCopyExisting`.
use base64::Engine;
use serde_json::json;
use zeroize::Zeroizing;

use super::{ShareFlowError, b64, b64_decode, display_form, path_id, require_ok, str_field};
use crate::auth_flow::{HttpRequest, HttpResponse, RequestAuth};
use crate::file_request::{unwrap_request_private, wrap_request_private};
use crate::kdf::MasterKey;
use crate::opaque::derive_x25519_public;

pub const FILE_REQUESTS_PATH: &str = "/api/v1/file-requests";
/// Web `FILE_REQUEST_EMPTY_ID`.
const EMPTY_ID: &[u8] = &[];

#[cfg(test)]
#[path = "request_tests.rs"]
mod tests;

/// The create form. `None` (or an empty description) leaves the field out, as web does.
#[derive(Clone, Debug, Default)]
pub struct RequestOptions {
    pub title: String,
    pub description: Option<String>,
    pub target_folder_id: Option<String>,
    pub max_files: Option<u32>,
    pub max_total_bytes: Option<u64>,
    pub expires_in_secs: Option<u64>,
}

/// The stored request. `link` carries `R_pub` after `#`; `display` is the part before `#`.
pub struct CreatedRequest {
    pub id: String,
    pub link: Zeroizing<String>,
    pub display: String,
}

impl std::fmt::Debug for CreatedRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CreatedRequest")
            .field("id", &self.id)
            .field("display", &self.display)
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub struct CreateRequest {
    app_url: String,
    r_pub: [u8; 32],
    done: bool,
}

fn link(app_url: &str, token: &str, r_pub: &[u8; 32]) -> Result<Zeroizing<String>, ShareFlowError> {
    // The token goes into the path: the same character rule as a share token.
    if token.is_empty()
        || !token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(ShareFlowError::Protocol("bad token"));
    }
    let fragment = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(r_pub);
    Ok(Zeroizing::new(format!(
        "{}/r/{token}#{fragment}",
        app_url.trim_end_matches('/')
    )))
}

impl CreateRequest {
    pub fn start(
        app_url: &str,
        options: &RequestOptions,
        master: &MasterKey,
    ) -> Result<(Self, HttpRequest), ShareFlowError> {
        let title = options.title.trim();
        if title.is_empty() {
            return Err(ShareFlowError::InvalidInput("title"));
        }
        let mut r_priv = Zeroizing::new([0u8; 32]);
        {
            use rand::RngCore;
            rand::rngs::OsRng
                .try_fill_bytes(&mut *r_priv)
                .map_err(|_| ShareFlowError::Crypto)?;
        }
        let r_pub = derive_x25519_public(&r_priv);
        let (wrapped, nonce) = wrap_request_private(master, EMPTY_ID, &r_priv).map_err(|_| ShareFlowError::Crypto)?;
        let mut body = json!({
            "title": title,
            "wrapped_private_key": b64(&wrapped),
            "wrap_nonce": b64(&nonce),
        });
        if let Some(d) = options.description.as_deref().map(str::trim).filter(|d| !d.is_empty()) {
            body["description"] = json!(d);
        }
        if let Some(folder) = &options.target_folder_id {
            body["target_folder_id"] = json!(path_id(folder).map_err(|_| ShareFlowError::InvalidInput("folder id"))?);
        }
        if let Some(n) = options.max_files {
            body["max_files"] = json!(n);
        }
        if let Some(n) = options.max_total_bytes {
            body["max_total_bytes"] = json!(n);
        }
        if let Some(n) = options.expires_in_secs {
            body["expires_in_secs"] = json!(n);
        }
        Ok((
            Self {
                app_url: app_url.to_owned(),
                r_pub,
                done: false,
            },
            HttpRequest::post(FILE_REQUESTS_PATH, body, RequestAuth::Session),
        ))
    }

    pub fn on_response(&mut self, resp: HttpResponse) -> Result<CreatedRequest, ShareFlowError> {
        if std::mem::replace(&mut self.done, true) {
            return Err(ShareFlowError::WrongState);
        }
        require_ok(&resp)?;
        let id = path_id(str_field(&resp, "id")?)?.to_owned();
        let link = link(&self.app_url, str_field(&resp, "token")?, &self.r_pub)?;
        Ok(CreatedRequest {
            display: display_form(&link),
            link,
            id,
        })
    }
}

/// Web `handleCopyExisting`: the request's link again, from its stored wrapped private key.
/// `None` when the row lacks key material or it does not open (the caller shows its honest copy).
pub fn rebuild_request_link(
    app_url: &str,
    master: &MasterKey,
    token: Option<&str>,
    wrapped_private_key_b64: Option<&str>,
    wrap_nonce_b64: Option<&str>,
) -> Option<Zeroizing<String>> {
    let wrapped = b64_decode(wrapped_private_key_b64.filter(|s| !s.is_empty())?).ok()?;
    let nonce = b64_decode(wrap_nonce_b64.filter(|s| !s.is_empty())?).ok()?;
    let r_priv = unwrap_request_private(master, EMPTY_ID, &wrapped, &nonce).ok()?;
    link(
        app_url,
        token.filter(|t| !t.is_empty())?,
        &derive_x25519_public(&r_priv),
    )
    .ok()
}

/// `POST /api/v1/file-requests/{id}/close`: no new uploads; received files are kept.
pub fn close_request(id: &str) -> Result<HttpRequest, ShareFlowError> {
    Ok(HttpRequest {
        method: crate::auth_flow::Method::Post,
        path: format!("{FILE_REQUESTS_PATH}/{}/close", path_id(id)?),
        body: None,
        auth: RequestAuth::Session,
        confirm_token: None,
    })
}
