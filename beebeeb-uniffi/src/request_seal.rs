//! Request-row seal and rename-target exports (task 2275 §15). Split out of
//! `lib.rs`, which is already over the file-size ratchet. Request-row results
//! carry a decrypt-only content handle and the opened name, never a raw key:
//! renames go through the core sealer.

use super::*;

/// Mint a guest (F) item id with NO master key (task 2275 §15). The anonymous
/// uploader path uses this; the id is a canonical RFC 9562 UUID v8.
#[uniffi::export]
pub fn mint_guest_item_id() -> Result<String, CryptoError> {
    Ok(beebeeb_core::item_id::mint_guest_item_id()?)
}

/// A request row's decrypt-only content reader (task 2275 §15; 2326 delta2
/// P2-2). It owns a copy of the row's content key `C`, bound to the row's file
/// id and recorded chunk-format pin; the key is zeroized when the reader drops
/// and no getter exposes it.
///
/// `decryptor()` returns a FRESH sequential [`ChunkDecryptorHandle`] at chunk 0
/// on every call (retry after a mid-stream error); `open_frame(...)` opens ONE
/// frame by index for a seek / range read.
#[derive(uniffi::Object)]
pub struct RequestContentReader {
    inner: beebeeb_core::request_content::RequestContentReader,
}

#[uniffi::export]
impl RequestContentReader {
    /// The file id every frame of this row must be bound to.
    pub fn file_id(&self) -> String {
        self.inner.file_id().to_string()
    }

    /// The row's recorded chunk-format pin: 0 = unrecorded, 2 = v2.
    pub fn chunk_format(&self) -> u8 {
        self.inner.pin().as_u8()
    }

    /// A FRESH sequential decryptor at chunk 0. Call again after any error.
    ///
    /// Retry contract: discard EVERYTHING the failed attempt produced; never
    /// splice attempt 1's prefix with attempt 2's suffix (after a replace that
    /// splices two uploads of one id). The failed cursor is not poisoned
    /// (`open_next` does not advance `next_index` on an error), but the output
    /// must still be rebuilt from frame 0.
    pub fn decryptor(&self) -> Result<Arc<ChunkDecryptorHandle>, CryptoError> {
        Ok(Arc::new(ChunkDecryptorHandle {
            inner: Mutex::new(Some(self.inner.decryptor())),
        }))
    }

    /// Open ONE content frame at `index` without the frames before it (seek /
    /// range read). `is_last = index == chunk_count - 1`. `format` (1 = v1,
    /// 2 = v2) and `version_id` (12 bytes, v2 only) must come from
    /// authenticated data. When the row is pinned to v2, `format: 1` is
    /// refused.
    pub fn open_frame(
        &self,
        version_id: Vec<u8>,
        index: u32,
        is_last: bool,
        format: u8,
        frame: Vec<u8>,
    ) -> Result<Vec<u8>, CryptoError> {
        let format = ChunkFormat::from_u8(format)?;
        self.inner
            .open_frame(&version_id, index, is_last, format, &frame)
            .map_err(Into::into)
    }
}

/// The origin and pin a request-row rename must use (task 2275 §15). There is
/// no key here: the sealer re-derives it in core from the item id.
#[derive(uniffi::Record)]
pub struct RequestRenameTarget {
    pub origin: String,
    pub pin: u8,
    pub version_id: Option<Vec<u8>>,
    pub version_counter: Option<u64>,
}

/// A request row with its seal and rename target (task 2275 §15). Carries a
/// decrypt-only content handle and the opened name, never a raw key.
#[derive(uniffi::Record)]
pub struct ResolvedRequestRow {
    /// Decrypt-only reader for the row's content; no key getter.
    pub content: Arc<RequestContentReader>,
    pub name_origin: String,
    pub name: String,
    pub mime_type: Option<String>,
    pub chunk_format: u8,
    /// `"bound"` (2236 seal) or `"unbound"` (the shipped empty-id convention).
    pub seal: String,
    /// `None` when the name is upper-repair (read-only).
    pub rename_target: Option<RequestRenameTarget>,
}

/// A 2236 request row (task 2275): a decrypt-only content handle and the
/// opened name. **Legacy**: `resolve_request_row` keeps this for read-only
/// callers; it carries no raw key, so a rename must go through
/// [`MasterKeyHandle::seal_request_rename`].
#[derive(uniffi::Record)]
pub struct RequestRowKeys {
    pub content: Arc<RequestContentReader>,
    pub name_origin: String,
    pub name: String,
    pub mime_type: Option<String>,
    pub chunk_format: u8,
}

#[uniffi::export]
impl MasterKeyHandle {
    /// Task 2275 §15: like `resolve_request_row`, but also reports which seal
    /// opened the row (`"bound"`/`"unbound"`) and the rename target (or `None`
    /// for an upper-repair name). The older method remains as a legacy
    /// read-only view.
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
        let chunk_format = row.name.chunk_format.as_u8();
        let content = Arc::new(RequestContentReader {
            inner: beebeeb_core::request_content::RequestContentReader::for_metadata(
                row.content_key,
                item_id.clone(),
                &row.name,
            ),
        });
        Ok(ResolvedRequestRow {
            content,
            name_origin: row.name_origin.as_str().to_string(),
            name: row.name.name,
            mime_type: row.name.mime_type,
            chunk_format,
            seal: row.seal.as_str().to_string(),
            rename_target: row.rename_target.map(|target| RequestRenameTarget {
                origin: target.origin().as_str().to_string(),
                pin: target.pin().as_u8(),
                version_id: target.version().map(|version| version.version_id.to_vec()),
                version_counter: target.version().map(|version| version.counter),
            }),
        })
    }
}

#[uniffi::export]
impl MasterKeyHandle {
    /// **Legacy**: resolve a 2236 request row for reading. Returns a
    /// decrypt-only content handle and the opened name; it never hands back a
    /// content or name key, so a caller cannot seal a name with it. Renames go
    /// through [`MasterKeyHandle::seal_request_rename`] (or
    /// `resolve_request_row_detailed` for the seal and rename target).
    /// `request_wrap_context` is empty for every request created so far.
    #[allow(clippy::too_many_arguments)]
    pub fn resolve_request_row(
        &self,
        item_id: String,
        request_wrap_context: Vec<u8>,
        wrapped_request_private: Vec<u8>,
        wrap_nonce: Vec<u8>,
        sender_ephemeral_pubkey: Vec<u8>,
        wrapped_content_key: Vec<u8>,
        name_encrypted: String,
    ) -> Result<RequestRowKeys, CryptoError> {
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
        let chunk_format = row.name.chunk_format.as_u8();
        let content = Arc::new(RequestContentReader {
            inner: beebeeb_core::request_content::RequestContentReader::for_metadata(
                row.content_key,
                item_id.clone(),
                &row.name,
            ),
        });
        Ok(RequestRowKeys {
            content,
            name_origin: row.name_origin.as_str().to_string(),
            name: row.name.name,
            mime_type: row.name.mime_type,
            chunk_format,
        })
    }
}

#[uniffi::export]
impl MasterKeyHandle {
    /// Seal a request-row rename under the section 15 string-convention key
    /// derived from `item_id`, keeping the row's recorded pin (`chunk_format`
    /// from `resolve_request_row_detailed`). This is the only sealing path a
    /// request-row result offers: the resolvers hand back no key, so a rename
    /// cannot be sealed under the content key `C` that the anonymous uploader
    /// holds (A9).
    ///
    /// An F id is refused by the same owner-class check the resolver runs.
    /// `pin` is the pin from the resolver's `RenameTarget` (`chunk_format`),
    /// never a server field. Pin risk, both directions: a pin of 2 on a v1 row
    /// makes the file unreadable until it is renamed again with the correct
    /// pin; a pin of 0 on a v2 row drops the recorded 2 and turns frame-0
    /// detection back on, so a server can serve the uploader's old no-AAD name
    /// blob under `C` as a one-frame v1 file.
    pub fn seal_request_rename(
        &self,
        item_id: String,
        pin: u8,
        filename: String,
        mime_type: Option<String>,
    ) -> Result<String, CryptoError> {
        let pin = ExpectedChunkFormat::from_u8(pin)?;
        self.with_key(|mk| {
            beebeeb_core::rename::encrypt_name_for_request_rename(mk, &item_id, pin, &filename, mime_type.as_deref())
        })?
        .map_err(CryptoError::from)
    }

    /// Protected request-row rename. The version fields come from the
    /// resolver's `RequestRenameTarget` and are preserved unchanged.
    pub fn seal_request_rename_with_version(
        &self,
        item_id: String,
        pin: u8,
        version_id: Vec<u8>,
        version_counter: u64,
        filename: String,
        mime_type: Option<String>,
    ) -> Result<String, CryptoError> {
        let pin = ExpectedChunkFormat::from_u8(pin)?;
        let version = version_commitment_from_parts(version_id, version_counter)?;
        self.with_key(|mk| {
            beebeeb_core::rename::encrypt_name_for_request_rename_with_version(
                mk,
                &item_id,
                pin,
                Some(version),
                &filename,
                mime_type.as_deref(),
            )
        })?
        .map_err(CryptoError::from)
    }
}
