//! Request-row and guest-id exports (task 2275 §15). Split out of `lib.rs`,
//! which is already over the file-size ratchet; the exported names and shapes
//! are unchanged for existing callers.

use super::*;

/// Mint a guest (F) item id with NO master key (task 2275 §15). The anonymous
/// uploader path uses this; the id is a canonical RFC 9562 UUID v8 and core's
/// class check (and the server's T2 check) classifies it as foreign.
#[wasm_bindgen(js_name = mintGuestItemId)]
pub fn mint_guest_item_id() -> Result<String, JsError> {
    beebeeb_core::item_id::mint_guest_item_id().map_err(|e| JsError::new(&e.to_string()))
}

/// Resolve a 2236 request row: `{content, nameOrigin, name, mimeType,
/// chunkFormat, seal, renameTarget}`. `content` is a decrypt-only
/// `WasmChunkDecryptor` for the row's content key; no raw key reaches JS, so a
/// caller cannot seal a name with it. The seal is `"bound"` or `"unbound"`
/// (§15), and `renameTarget` is `{origin, pin}` or null when the name is
/// upper-repair (read-only). Renames go through `sealRequestRename`.
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
    let content = WasmChunkDecryptor::from_file_key(
        row.content_key.as_bytes(),
        item_id.to_string(),
        row.name.chunk_format.as_u8(),
    )?;
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
/// `resolveRequestRow`). This is the only sealing path: `resolveRequestRow`
/// hands back no key, so a rename cannot be sealed under the content key `C`
/// that the anonymous uploader holds (A9).
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
