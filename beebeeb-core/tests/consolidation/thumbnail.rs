//! Move 12 — the thumbnail policy (spec §16.2).
//!
//! Cases live in `test-vectors/consolidation/thumbnail.json`. The ladder and
//! budgets are the frozen WebP cascade; the policy adds the variant name, the
//! default target size and the per-platform format choice.

use beebeeb_core::thumbnail::{
    Platform, ThumbnailError, ThumbnailFormat, ThumbnailPolicy, ThumbnailVariant, resize_for_thumbnail,
};
use serde_json::Value;

pub const CONCEPT: &str = "thumbnail";

fn variant_of(case: &Value) -> ThumbnailVariant {
    match case["variant"].as_str().expect("variant") {
        "small" => ThumbnailVariant::Small,
        "medium" => ThumbnailVariant::Medium,
        "large" => ThumbnailVariant::Large,
        other => panic!("unknown variant `{other}`"),
    }
}

fn platform_of(case: &Value) -> Platform {
    match case["platform"].as_str().expect("platform") {
        "ios" => Platform::Ios,
        "macos" => Platform::MacOs,
        "android" => Platform::Android,
        "windows" => Platform::Windows,
        "linux" => Platform::Linux,
        "web" => Platform::Web,
        "unknown" => Platform::Unknown,
        other => panic!("unknown platform `{other}`"),
    }
}

#[test]
fn thumbnail_cases_match_core() {
    let cases = super::cases(CONCEPT);
    assert_eq!(cases.len(), 23, "every named thumbnail case is present");

    let mut ladders = 0;
    let mut formats = 0;
    let mut budgets = 0;
    let mut resizes = 0;

    for case in &cases {
        let id = case["id"].as_str().expect("case id");
        match case["kind"].as_str().expect("case kind") {
            "ladder" => {
                ladders += 1;
                let policy = ThumbnailPolicy::for_variant(variant_of(case));
                let steps = case["steps"].as_array().expect("steps");
                assert_eq!(policy.config.ladder.len(), steps.len(), "{id}: step count");
                for (index, step) in steps.iter().enumerate() {
                    let got = &policy.config.ladder[index];
                    assert_eq!(
                        got.max_dimension,
                        step["max_dimension"].as_u64().unwrap() as u32,
                        "{id}: step {index}"
                    );
                    assert_eq!(got.quality, step["quality"].as_f64().unwrap() as f32, "{id}: q {index}");
                }
                assert_eq!(
                    policy.config.target_bytes,
                    case["target_bytes"].as_u64().unwrap() as usize,
                    "{id}"
                );
                assert_eq!(
                    policy.config.max_bytes,
                    case["max_bytes"].as_u64().unwrap() as usize,
                    "{id}"
                );
                assert_eq!(policy.target_px, case["target_px"].as_u64().unwrap() as u32, "{id}");
                // The instance constructors are the same policy.
                let same = match variant_of(case) {
                    ThumbnailVariant::Small => beebeeb_core::thumbnail::ThumbnailConfig::small(),
                    ThumbnailVariant::Medium => beebeeb_core::thumbnail::ThumbnailConfig::medium(),
                    ThumbnailVariant::Large => beebeeb_core::thumbnail::ThumbnailConfig::large(),
                };
                assert_eq!(policy.config.target_bytes, same.target_bytes, "{id}: instance");
                assert_eq!(policy.config.max_bytes, same.max_bytes, "{id}: instance");
            }
            "format" => {
                formats += 1;
                let policy = ThumbnailPolicy::for_variant(variant_of(case));
                let want = match case["expected"].as_str().expect("expected") {
                    "heic" => ThumbnailFormat::Heic,
                    "webp" => ThumbnailFormat::Webp,
                    other => panic!("unknown format `{other}`"),
                };
                assert_eq!(policy.format_for(platform_of(case)), want, "{id}");
                assert_eq!(
                    policy.format_for(platform_of(case)).as_str(),
                    case["expected"].as_str().unwrap()
                );
            }
            "budget" => {
                budgets += 1;
                let policy = ThumbnailPolicy::for_variant(variant_of(case));
                let got = policy.classify_size(case["bytes"].as_u64().expect("bytes") as usize);
                assert_eq!(got.as_str(), case["expected"].as_str().expect("expected"), "{id}");
            }
            "resize" => {
                resizes += 1;
                let width = case["width"].as_u64().expect("width") as u32;
                let height = case["height"].as_u64().expect("height") as u32;
                let max_dimension = case["max_dimension"].as_u64().expect("max") as u32;
                let policy = ThumbnailPolicy::medium();
                match case.get("expect").and_then(Value::as_str) {
                    Some("reject") => {
                        assert!(
                            matches!(policy.check_source(width, height), Err(ThumbnailError::InvalidInput(_))),
                            "{id}: a zero dimension must be refused"
                        );
                    }
                    _ => {
                        policy
                            .check_source(width, height)
                            .unwrap_or_else(|e| panic!("{id}: {e}"));
                        let rgba = vec![0u8; (width as usize) * (height as usize) * 4];
                        let (_, got_width, got_height) = resize_for_thumbnail(&rgba, width, height, max_dimension)
                            .unwrap_or_else(|e| panic!("{id}: {e}"));
                        assert_eq!(
                            got_width,
                            case["expected_width"].as_u64().unwrap() as u32,
                            "{id}: width"
                        );
                        assert_eq!(
                            got_height,
                            case["expected_height"].as_u64().unwrap() as u32,
                            "{id}: height"
                        );
                    }
                }
            }
            other => panic!("{id}: unknown case kind `{other}`"),
        }
    }

    assert_eq!((ladders, formats, budgets, resizes), (3, 7, 9, 4));
    for required in [
        "thumb_format_ios",
        "thumb_format_macos",
        "thumb_format_web",
        "thumb_zero_dimension",
    ] {
        assert!(cases.iter().any(|case| case["id"] == required), "missing `{required}`");
    }
}
