//! Request-row seal and rename-target exports (task 2275 §15). Split out of
//! `lib.rs`, which is already over the file-size ratchet; the existing
//! `resolve_request_row`/`RequestRowKeys` surface stays unchanged.

use super::*;

/// Mint a guest (F) item id with NO master key (task 2275 §15). The anonymous
/// uploader path uses this; the id is a canonical RFC 9562 UUID v8.
#[uniffi::export]
pub fn mint_guest_item_id() -> Result<String, CryptoError> {
    Ok(beebeeb_core::item_id::mint_guest_item_id()?)
}

/// The name key, origin and pin a request-row rename must use (task 2275 §15).
#[derive(uniffi::Record)]
pub struct RequestRenameTarget {
    pub key: Arc<FileKeyHandle>,
    pub origin: String,
    pub pin: u8,
}

/// A request row with its seal and rename target (task 2275 §15). Additive
/// alongside [`RequestRowKeys`]: the older record is unchanged.
#[derive(uniffi::Record)]
pub struct ResolvedRequestRow {
    pub content_key: Arc<FileKeyHandle>,
    pub name_key: Arc<FileKeyHandle>,
    pub name_origin: String,
    pub name: String,
    pub mime_type: Option<String>,
    pub chunk_format: u8,
    /// `"bound"` (2236 seal) or `"unbound"` (the shipped empty-id convention).
    pub seal: String,
    /// `None` when the name is upper-repair (read-only).
    pub rename_target: Option<RequestRenameTarget>,
}

#[uniffi::export]
impl MasterKeyHandle {
    /// Task 2275 §15: like `resolve_request_row`, but also reports which seal
    /// opened the row (`"bound"`/`"unbound"`) and the rename target (or `None`
    /// for an upper-repair name). Additive: the older method is unchanged.
    ///
    /// `request_wrap_context` is the context the owner wrapped the request
    /// private key under: empty for every request created so far. A real
    /// request id refuses a shipped row; the contexts are never both tried.
    #[allow(clippy::too_many_arguments)]
    pub fn resolve_request_row_detailed(
        &self,
        item_id: String,
        request_wrap_context: Vec<u8>,
        wrapped_request_private: Vec<u8>,
        wrap_nonce: Vec<u8>,
        sender_ephemeral_pubkey: Vec<u8>,
        wrapped_content_key: Vec<u8>,
        name_encrypted: String,
    ) -> Result<ResolvedRequestRow, CryptoError> {
        let e_pub: [u8; 32] = sender_ephemeral_pubkey
            .try_into()
            .map_err(|_| CryptoError::InvalidInput {
                detail: "sender_ephemeral_pubkey must be exactly 32 bytes".into(),
            })?;
        let row = self.with_key(|mk| {
            beebeeb_core::owned_keys::resolve_request_row(
                mk,
                &item_id,
                &request_wrap_context,
                &wrapped_request_private,
                &wrap_nonce,
                &e_pub,
                &wrapped_content_key,
                &name_encrypted,
            )
        })??;
        Ok(ResolvedRequestRow {
            content_key: FileKeyHandle::new(row.content_key),
            name_key: FileKeyHandle::new(row.name_key),
            name_origin: row.name_origin.as_str().to_string(),
            name: row.name.name,
            mime_type: row.name.mime_type,
            chunk_format: row.name.chunk_format.as_u8(),
            seal: row.seal.as_str().to_string(),
            rename_target: row.rename_target.map(|target| RequestRenameTarget {
                key: FileKeyHandle::new(kdf::FileKey::from_bytes(*target.key().as_bytes())),
                origin: target.origin().as_str().to_string(),
                pin: target.pin().as_u8(),
            }),
        })
    }
}
