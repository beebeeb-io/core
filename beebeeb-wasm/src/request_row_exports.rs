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

/// Resolve a 2236 request row: `{contentKey, nameKey, nameOrigin, name,
/// mimeType, chunkFormat, seal, renameTarget}`. Read-only content; the seal is
/// `"bound"` or `"unbound"` (§15), and `renameTarget` is
/// `{key, origin, pin}` or null when the name is upper-repair (read-only).
#[wasm_bindgen(js_name = resolveRequestRow)]
#[allow(clippy::too_many_arguments)]
pub fn resolve_request_row(
    master_key: &[u8],
    item_id: &str,
    request_id: &[u8],
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
        request_id,
        wrapped_request_private,
        wrap_nonce,
        &e_pub,
        wrapped_content_key,
        name_encrypted,
    )
    .map_err(|e| JsError::new(&e.to_string()))?;
    let obj = js_sys::Object::new();
    set(
        &obj,
        "contentKey",
        js_sys::Uint8Array::from(row.content_key.as_bytes().as_slice()).into(),
    )?;
    set(
        &obj,
        "nameKey",
        js_sys::Uint8Array::from(row.name_key.as_bytes().as_slice()).into(),
    )?;
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
            set(
                &rt,
                "key",
                js_sys::Uint8Array::from(target.key().as_bytes().as_slice()).into(),
            )?;
            set(&rt, "origin", JsValue::from_str(target.origin().as_str()))?;
            set(&rt, "pin", JsValue::from_f64(target.pin().as_u8() as f64))?;
            rt.into()
        }
        None => JsValue::NULL,
    };
    set(&obj, "renameTarget", rename_target)?;
    Ok(obj.into())
}
