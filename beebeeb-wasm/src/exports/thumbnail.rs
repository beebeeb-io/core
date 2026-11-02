//! Move 12's thumbnail policy, as data the web client can read.
//!
//! The ladder, the two byte budgets per variant, the per-platform format choice
//! and the budget verdict are core's (`beebeeb_core::thumbnail`); this module
//! only shapes them for JS. The encoder stays platform-native: a browser resizes
//! and encodes with its own canvas, so `resize_for_thumbnail` is not exported.
use beebeeb_core::thumbnail::{Platform, ThumbnailPolicy, ThumbnailVariant};
use serde::Serialize;
use wasm_bindgen::prelude::*;

/// One ladder step: the longest side to try and the encoder quality.
#[derive(Serialize)]
struct LadderStepJs {
    max_dimension: u32,
    quality: f32,
}

/// One variant's policy: its ladder and its two byte budgets.
#[derive(Serialize)]
struct ThumbnailPolicyJs {
    variant: String,
    target_px: u32,
    target_bytes: usize,
    max_bytes: usize,
    steps: Vec<LadderStepJs>,
}

fn variant_from_js(variant: &str) -> Result<ThumbnailVariant, JsError> {
    match variant {
        "small" => Ok(ThumbnailVariant::Small),
        "medium" => Ok(ThumbnailVariant::Medium),
        "large" => Ok(ThumbnailVariant::Large),
        other => Err(JsError::new(&format!("unknown thumbnail variant: {other}"))),
    }
}

fn platform_from_js(platform: &str) -> Result<Platform, JsError> {
    match platform {
        "ios" => Ok(Platform::Ios),
        "macos" => Ok(Platform::MacOs),
        "android" => Ok(Platform::Android),
        "windows" => Ok(Platform::Windows),
        "linux" => Ok(Platform::Linux),
        "web" => Ok(Platform::Web),
        "unknown" => Ok(Platform::Unknown),
        other => Err(JsError::new(&format!("unknown platform: {other}"))),
    }
}

/// The policy for one variant (`small`, `medium`, `large`):
/// `{ variant, target_px, target_bytes, max_bytes, steps }`, where each step is
/// `{ max_dimension, quality }`.
#[wasm_bindgen(js_name = thumbnailPolicy)]
pub fn thumbnail_policy(variant: &str) -> Result<JsValue, JsError> {
    let policy = ThumbnailPolicy::for_variant(variant_from_js(variant)?);
    serde_wasm_bindgen::to_value(&ThumbnailPolicyJs {
        variant: policy.variant.as_str().to_owned(),
        target_px: policy.target_px,
        target_bytes: policy.config.target_bytes,
        max_bytes: policy.config.max_bytes,
        steps: policy
            .config
            .ladder
            .iter()
            .map(|step| LadderStepJs {
                max_dimension: step.max_dimension,
                quality: step.quality,
            })
            .collect(),
    })
    .map_err(|error| JsError::new(&format!("cannot serialize the thumbnail policy: {error}")))
}

/// Where `bytes` falls against one variant's budgets: `"target"` (at or below
/// `target_bytes`, stop the ladder), `"fallback"` (above target but at or below
/// `max_bytes`, keep it and keep trying) or `"rejected"` (above `max_bytes`).
#[wasm_bindgen(js_name = thumbnailBudget)]
pub fn thumbnail_budget(variant: &str, bytes: f64) -> Result<String, JsError> {
    if !bytes.is_finite() || bytes < 0.0 {
        return Err(JsError::new("bytes must be a non-negative number"));
    }
    let policy = ThumbnailPolicy::for_variant(variant_from_js(variant)?);
    Ok(policy.classify_size(bytes as usize).as_str().to_owned())
}

/// The encoder output a variant asks for on `platform`: `"heic"` on iOS and
/// macOS (the OS owns the encoder), `"webp"` everywhere else.
#[wasm_bindgen(js_name = thumbnailFormat)]
pub fn thumbnail_format(variant: &str, platform: &str) -> Result<String, JsError> {
    let policy = ThumbnailPolicy::for_variant(variant_from_js(variant)?);
    Ok(policy
        .format_for(platform_from_js(platform)?)
        .as_str()
        .to_owned())
}