//! Bundle links: one public link over an ordered set of files (web `share-dialog.tsx` bundle
//! branch, `prepareBundleShareItems`, `wrapBundleToken`; task 0417, folder snapshot 2238).
//!
//! ```text
//! CreateLink::bundle ──► POST /api/v1/shares
//!     {share_type: "bundle", items: [{file_id, position, wrapped_file_key}], expires_in_hours?,
//!      max_opens, passphrase?, token, owner_wrapped_key, owner_wrapped_token}
//!   409 (untyped) ──► once more with a fresh token;  2xx ──► Created { /s/{token}#key={K_c} }
//! ```
//!
//! One random `K_c` wraps every item's key (`nonce || ct`, no AAD); `K_c` and the token are wrapped
//! under the raw master key, as for a file link. Each item's key is the one that opens its row
//! (the caller resolves it, as web's `getFileKeyForFile`); a request row has none and must not be
//! passed. Which files a folder snapshot holds (the walk, names, order) is the caller's.
use serde_json::json;

use super::link::{CreateLink, LinkOptions};
use super::{ShareFlowError, b64, path_id, wrap_key_for_share};
use crate::auth_flow::HttpRequest;
use crate::kdf::{FileKey, MasterKey};

/// Web `FOLDER_BUNDLE_MAX_ITEMS`: a link covers at most this many files.
pub const BUNDLE_MAX_ITEMS: usize = 256;

#[cfg(test)]
#[path = "bundle_tests.rs"]
mod tests;

/// One file of a bundle, at its position in the link's order.
pub struct BundleItem<'a> {
    pub file_id: &'a str,
    pub position: u32,
    pub file_key: &'a FileKey,
}

impl CreateLink {
    /// A bundle link over `items`, in the order given by each item's `position`.
    pub fn bundle(
        app_url: &str,
        items: &[BundleItem<'_>],
        master: &MasterKey,
        options: &LinkOptions,
    ) -> Result<(Self, HttpRequest), ShareFlowError> {
        if items.is_empty() {
            return Err(ShareFlowError::InvalidInput("no items"));
        }
        if items.len() > BUNDLE_MAX_ITEMS {
            return Err(ShareFlowError::InvalidInput("too many items"));
        }
        let passphrase = Self::check(app_url, options)?;
        let k_c = Self::new_client_key()?;
        let mut wire = Vec::with_capacity(items.len());
        for item in items {
            let file_id = path_id(item.file_id).map_err(|_| ShareFlowError::InvalidInput("item id"))?;
            let wrapped = wrap_key_for_share(&k_c, item.file_key.as_bytes())?;
            wire.push(json!({ "file_id": file_id, "position": item.position, "wrapped_file_key": b64(&wrapped) }));
        }
        let owner_wrapped_key = wrap_key_for_share(master.as_bytes(), &*k_c)?;
        let mut body = json!({
            "share_type": "bundle",
            "items": wire,
            "max_opens": options.max_opens,
            "owner_wrapped_key": b64(&owner_wrapped_key),
        });
        // Web sends `expires_in_hours ?? undefined`: "never" leaves the field out.
        if let Some(h) = options.expires_in_hours {
            body["expires_in_hours"] = json!(h);
        }
        if let Some(p) = passphrase {
            body["passphrase"] = json!(p);
        }
        Self::from_body(app_url, master, k_c, body)
    }
}
