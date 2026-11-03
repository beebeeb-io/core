//! Request-row and guest-id exports (task 2275 §15). Split out of `lib.rs`,
//! which is already over the file-size ratchet; the exported names and shapes
//! are unchanged for existing callers.

use super::*;

/// Mint a guest (F) item id with NO master key (task 2275 §15). The anonymous
/// uploader path uses this; the id is a canonical RFC 9562 UUID v8 and core's
/// class check classifies it as foreign. The server has no T2 F-class check
/// yet (future server work), so only the core check protects this id today.
#[wasm_bindgen(js_name = mintGuestItemId)]
pub fn mint_guest_item_id() -> Result<String, JsError> {
    beebeeb_core::item_id::mint_guest_item_id().map_err(|e| JsError::new(&e.to_string()))
}

/// A request row's decrypt-only content reader (task 2275 §15; 2326 delta2
/// P2-2). It owns a copy of the row's content key `C`, bound to the row's file
/// id and recorded chunk-format pin; the key is zeroized when the reader drops
/// and no getter exposes it.
///
/// `decryptor()` returns a FRESH sequential [`WasmChunkDecryptor`] at chunk 0
/// on every call (retry after a mid-stream error); `openFrame(...)` opens ONE
/// frame by index for a seek / range read.
#[wasm_bindgen]
pub struct WasmRequestContentReader {
    inner: beebeeb_core::request_content::RequestContentReader,
}

#[wasm_bindgen]
impl WasmRequestContentReader {
    /// The file id every frame of this row must be bound to.
    #[wasm_bindgen(getter, js_name = fileId)]
    pub fn file_id(&self) -> String {
        self.inner.file_id().to_string()
    }

    /// The row's recorded chunk-format pin: 0 = unrecorded, 2 = v2.
    #[wasm_bindgen(getter, js_name = chunkFormat)]
    pub fn chunk_format(&self) -> u8 {
        self.inner.pin().as_u8()
    }

    /// A FRESH sequential decryptor at chunk 0. Call again after any error.
    pub fn decryptor(&self) -> WasmChunkDecryptor {
        WasmChunkDecryptor {
            inner: self.inner.decryptor(),
        }
    }

    /// Open ONE content frame at `index` without the frames before it (seek /
    /// range read). `isLast = index == chunkCount - 1`. `format` (1 = v1,
    /// 2 = v2) and `versionId` (12 bytes, v2 only) must come from authenticated
    /// data. When the row is pinned to v2, `format: 1` is refused.
    #[wasm_bindgen(js_name = openFrame)]
    pub fn open_frame(
        &self,
        version_id: &[u8],
        index: u32,
        is_last: bool,
        format: u8,
        frame: &[u8],
    ) -> Result<Vec<u8>, JsError> {
        let format = beebeeb_core::chunk_stream::ChunkFormat::from_u8(format)
            .map_err(|e| JsError::new(&e.to_string()))?;
        self.inner
            .open_frame(version_id, index, is_last, format, frame)
            .map_err(|e| JsError::new(&e.to_string()))
    }
}

/// Resolve a 2236 request row: `{content, nameOrigin, name, mimeType,
/// chunkFormat, seal, renameTarget}`. `content` is a decrypt-only
/// `WasmRequestContentReader` for the row's content key; no raw key reaches JS,
/// so a request-row result offers no sealing path. The seal is `"bound"` or
/// `"unbound"` (§15), and `renameTarget` is `{origin, pin}` or null when the
/// name is upper-repair (read-only). Renames go through `sealRequestRename`.
///
/// `request_wrap_context` is the context the owner wrapped the request private
/// key under: empty for every request created so far (the server mints the
/// request id after the wrap). A real request id refuses a shipped row; this
/// function never tries both contexts.
#[wasm_bindgen(js_name = resolveRequestRow)]
#[allow(clippy::too_many_arguments)]
pub fn resolve_request_row(
    master_key: &[u8],
    item_id: &str,
    request_wrap_context: &[u8],
    wrapped_request_private: &[u8],
    wrap_nonce: &[u8],
    sender_ephemeral_pubkey: &[u8],
    wrapped_content_key: &[u8],
    name_encrypted: &str,
) -> Result<JsValue, JsError> {
    let master = master_key_from_slice(master_key)?;
    let e_pub: [u8; 32] = sender_ephemeral_pubkey
        .try_into()
        .map_err(|_| JsError::new("sender_ephemeral_pubkey must be exactly 32 bytes"))?;
    let row = beebeeb_core::owned_keys::resolve_request_row(
        &master,
        item_id,
        request_wrap_context,
        wrapped_request_private,
        wrap_nonce,
        &e_pub,
        wrapped_content_key,
        name_encrypted,
    )
    .map_err(|e| JsError::new(&e.to_string()))?;
    let content = WasmRequestContentReader {
        inner: beebeeb_core::request_content::RequestContentReader::new(
            row.content_key,
            item_id.to_string(),
            row.name.chunk_format,
        ),
    };
    let obj = js_sys::Object::new();
    set(&obj, "content", JsValue::from(content))?;
    set(&obj, "nameOrigin", JsValue::from_str(row.name_origin.as_str()))?;
    set(&obj, "name", JsValue::from_str(&row.name.name))?;
    set(
        &obj,
        "mimeType",
        match &row.name.mime_type {
            Some(mime) => JsValue::from_str(mime),
            None => JsValue::NULL,
        },
    )?;
    set(
        &obj,
        "chunkFormat",
        JsValue::from_f64(row.name.chunk_format.as_u8() as f64),
    )?;
    set(&obj, "seal", JsValue::from_str(row.seal.as_str()))?;
    let rename_target = match &row.rename_target {
        Some(target) => {
            let rt = js_sys::Object::new();
            set(&rt, "origin", JsValue::from_str(target.origin().as_str()))?;
            set(&rt, "pin", JsValue::from_f64(target.pin().as_u8() as f64))?;
            rt.into()
        }
        None => JsValue::NULL,
    };
    set(&obj, "renameTarget", rename_target)?;
    Ok(obj.into())
}

/// Seal a request-row rename under the section 15 string-convention key derived
/// from `item_id`, keeping the row's recorded `pin` (`chunkFormat` from
/// `resolveRequestRow`). This is the only sealing path a request-row result
/// offers: `resolveRequestRow` hands back no key, so a rename cannot be sealed
/// under the content key `C` that the anonymous uploader holds (A9).
#[wasm_bindgen(js_name = sealRequestRename)]
pub fn seal_request_rename(
    master_key: &[u8],
    item_id: &str,
    pin: u8,
    filename: &str,
    mime_type: Option<String>,
) -> Result<String, JsError> {
    let master = master_key_from_slice(master_key)?;
    let pin =
        beebeeb_core::chunk_stream::ExpectedChunkFormat::from_u8(pin).map_err(|e| JsError::new(&e.to_string()))?;
    beebeeb_core::rename::encrypt_name_for_request_rename(&master, item_id, pin, filename, mime_type.as_deref())
        .map_err(|e| JsError::new(&e.to_string()))
}
