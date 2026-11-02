//! Move 9's share-link grammar, as the web client mints and reads links.
//!
//! `buildShareLink` keeps each route's existing encoding (the `#key=` value is
//! percent-encoded exactly like `encodeURIComponent`, so current base64url
//! links and legacy standard-base64 links both stay byte-identical), and
//! `parseShareLink` accepts both alphabets on both routes. No rule lives here:
//! the grammar, the percent codec and the key decoder are
//! `beebeeb_core::share_link`, proved by
//! `test-vectors/consolidation/share_link.json`.
use beebeeb_core::share_link::{self, ShareRoute};
use serde::Serialize;
use wasm_bindgen::prelude::*;

/// A parsed share link, with the same field names core uses.
#[derive(Serialize)]
struct ShareLinkJs {
    base_url: String,
    route: String,
    token: String,
    key: String,
}

fn route_from_js(route: Option<String>) -> Result<ShareRoute, JsError> {
    match route.as_deref() {
        None | Some("s") => Ok(ShareRoute::Single),
        Some("f") => Ok(ShareRoute::Folder),
        Some(other) => Err(JsError::new(&format!("unknown share route: {other}"))),
    }
}

/// Build `{app_url}/{s|f}/{token}#key={key}`. `route` is `"s"` (the default
/// when omitted or `null`) or `"f"`.
#[wasm_bindgen(js_name = buildShareLink)]
pub fn build_share_link(
    app_url: &str,
    token: &str,
    key: &str,
    route: Option<String>,
) -> Result<String, JsError> {
    Ok(share_link::build_for(
        app_url,
        token,
        key,
        route_from_js(route)?,
    ))
}

/// Parse a share link on either route and on any `https` host (legacy hosts
/// included; plain `http` only for loopback). Returns
/// `{ base_url, route, token, key }`; `key` is the percent-decoded fragment
/// value, not yet decoded as bytes — use `shareKeyBytes(key)` for that.
///
/// The thrown message starts with core's stable code, so a caller can branch:
/// `missing_fragment`, `missing_key`, `missing_token`, `not_a_share_link`.
#[wasm_bindgen(js_name = parseShareLink)]
pub fn parse_share_link(url: &str) -> Result<JsValue, JsError> {
    let link = share_link::parse(url).map_err(share_error)?;
    serde_wasm_bindgen::to_value(&ShareLinkJs {
        base_url: link.base_url,
        route: link.route.as_str().to_owned(),
        token: link.token,
        key: link.key,
    })
    .map_err(|error| JsError::new(&format!("cannot serialize the share link: {error}")))
}

/// Decode a `#key=` value as bytes, accepting standard base64 (legacy links) and
/// base64url (current links), padded or unpadded; `null` when it is neither.
#[wasm_bindgen(js_name = shareKeyBytes)]
pub fn share_key_bytes(key: &str) -> JsValue {
    match share_link::key_bytes(key) {
        Some(bytes) => js_sys::Uint8Array::from(bytes.as_slice()).into(),
        None => JsValue::NULL,
    }
}

fn share_error(error: share_link::ShareLinkError) -> JsError {
    JsError::new(&format!("{}: {error}", error.code()))
}