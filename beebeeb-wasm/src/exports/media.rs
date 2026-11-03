//! The per-platform preview table, for the web client (Guus, 2026-11-03).
//!
//! `previewableBatchFor(names, platform)` is the additive answer to the mistake
//! the consolidation made: web's own allowlist was replaced by core's, and web
//! lost 18 types. The table lives in `beebeeb_core::media`; this module only
//! converts the platform name and the bitset, and reports an unknown platform
//! as an error instead of guessing one.
//!
//! 0 exports were removed for this: `previewableBatch` (the old, platform-less
//! shape) never existed here, and `previewable_batch` in core is untouched.
use beebeeb_core::media::PreviewPlatform;
use wasm_bindgen::prelude::*;

/// One preview decision per name, for one platform: `result[i]` is `1` when
/// `names[i]` can be previewed in-app on `platform`, `0` otherwise.
///
/// `platform` is `"web"`, `"desktop"` or `"mobile"`. Any other string throws
/// `unknown preview platform \`…\`` — it never falls back to a default, because
/// answering for the wrong client is exactly the regression this export exists
/// to prevent.
///
/// The vector `test-vectors/consolidation/preview_platforms.json` carries the
/// expected answer for every extension of the three-way union, per platform.
#[wasm_bindgen(js_name = previewableBatchFor)]
pub fn previewable_batch_for(names: Vec<String>, platform: &str) -> Result<Vec<u8>, JsError> {
    let resolved = PreviewPlatform::from_name(platform)
        .ok_or_else(|| JsError::new(&format!("unknown preview platform `{platform}`")))?;
    Ok(beebeeb_core::media::previewable_batch_for(&names, resolved)
        .into_iter()
        .map(u8::from)
        .collect())
}
