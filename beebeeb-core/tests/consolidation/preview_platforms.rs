//! Move 3 addendum — the per-platform preview table (Guus, 2026-11-03).
//!
//! The consolidation replaced each client's own preview allowlist with
//! `is_previewable_by_extension`, and web lost 18 types it rendered before. The
//! per-platform table must restore every column exactly, so this vector carries
//! one expected answer per platform for every extension of the three-way union
//! (123 rows) plus the shape cases, and proves the existing predicate still
//! answers the `Mobile` column, unchanged.
//!
//! Cases live in `test-vectors/consolidation/preview_platforms.json`.

use beebeeb_core::media::{
    BitSet, PreviewPlatform, is_previewable_by_extension, is_previewable_by_extension_for, previewable_batch_for,
};
use serde_json::Value;

pub const CONCEPT: &str = "preview_platforms";

/// Column order, lower-case names as the bindings spell them.
const PLATFORMS: [(&str, PreviewPlatform); 3] = [
    ("web", PreviewPlatform::Web),
    ("desktop", PreviewPlatform::Desktop),
    ("mobile", PreviewPlatform::Mobile),
];

/// The 18 types web rendered before the consolidation switch.
const RESTORED: [&str; 18] = [
    "aif", "aiff", "alac", "arw", "cr2", "cr3", "dng", "hevc", "key", "nef", "oga", "orf", "ppt", "raf", "rw2", "tsv",
    "xls", "zip",
];

/// Archives preview on every platform through core's archive reader (core
/// archives, 2026-11-08), so `zip`, one of the 18, is no longer web-only.
const ARCHIVES: [&str; 4] = ["zip", "tar", "tgz", "gz"];

/// The rows beyond the union: names, not extensions.
const SHAPE: [&str; 8] = [
    "preview_platform_uppercase",
    "preview_platform_dotless_dockerfile",
    "preview_platform_no_extension",
    "preview_platform_empty_name",
    "preview_platform_unknown_extension",
    "preview_platform_trailing_dot",
    "preview_platform_dot_only",
    "preview_platform_hidden_file",
];

fn text<'a>(case: &'a Value, key: &str) -> &'a str {
    case[key]
        .as_str()
        .unwrap_or_else(|| panic!("case `{}` needs a string `{key}`", case["id"]))
}

fn expected_one(case: &Value, platform: &str) -> bool {
    case["expected"][platform]
        .as_bool()
        .unwrap_or_else(|| panic!("case `{}` needs a bool `expected.{platform}`", case["id"]))
}

fn strings(value: &Value, id: &str) -> Vec<String> {
    value
        .as_array()
        .unwrap_or_else(|| panic!("{id}: needs a list"))
        .iter()
        .map(|entry| entry.as_str().expect("list entries are strings").to_string())
        .collect()
}

#[test]
fn preview_platform_cases_match_each_client() {
    let doc = super::load(CONCEPT);
    let cases = super::cases(CONCEPT);

    let union = doc["counts"]["union"].as_u64().expect("counts.union") as usize;
    assert_eq!(
        cases.len(),
        union + SHAPE.len(),
        "one row per union extension plus the shape cases"
    );
    for shape in SHAPE {
        assert!(
            cases.iter().any(|case| case["id"] == shape),
            "missing named case `{shape}`"
        );
    }

    let mut names: Vec<String> = Vec::new();
    let mut want: [BitSet; 3] = [BitSet::new(), BitSet::new(), BitSet::new()];
    let mut web_only: Vec<String> = Vec::new();

    for case in &cases {
        let id = text(case, "id");
        assert_eq!(
            text(case, "kind"),
            "extension",
            "{id}: only extension rows in this vector"
        );
        let name = text(case, "name");

        for (index, (label, platform)) in PLATFORMS.iter().enumerate() {
            let expected = expected_one(case, label);
            assert_eq!(
                is_previewable_by_extension_for(name, *platform),
                expected,
                "{id}: `{name}` on {label}"
            );
            want[index].push(expected);
        }

        // The existing predicate never changed: it is the Mobile column.
        assert_eq!(
            is_previewable_by_extension(name),
            expected_one(case, "mobile"),
            "{id}: `{name}` — the existing predicate must still answer the Mobile column"
        );

        if expected_one(case, "web") && !expected_one(case, "mobile") {
            web_only.push(text(case, "extension").to_string());
        }

        names.push(name.to_string());
    }

    // Every archive extension previews on all three platforms.
    for ext in ARCHIVES {
        let case = cases
            .iter()
            .find(|case| case["extension"] == ext)
            .unwrap_or_else(|| panic!("missing the archive row `{ext}`"));
        for (label, _) in PLATFORMS {
            assert!(expected_one(case, label), "`{ext}` must preview on {label}");
        }
    }

    // The 18 web types the switch removed are back, and the web-only rows are
    // exactly that set less the archives — no more, none missing.
    let restored = strings(&doc["web_only_restored"], "web_only_restored");
    assert_eq!(RESTORED.len(), 18, "web lost 18 types");
    assert_eq!(restored.len(), RESTORED.len(), "the json names all 18");
    let mut derived = web_only.clone();
    derived.sort();
    let mut expected_web_only: Vec<String> = RESTORED
        .iter()
        .filter(|ext| !ARCHIVES.contains(ext))
        .map(|ext| ext.to_string())
        .collect();
    expected_web_only.sort();
    assert_eq!(
        derived, expected_web_only,
        "the web-only rows are the 18 restored types less the archives"
    );

    for ext in RESTORED {
        let has_row = cases.iter().any(|case| case["extension"] == ext);
        assert!(has_row, "missing the restored web type `{ext}`");
    }

    // One crossing per platform: the batch answer is the per-row answer, in order.
    for (index, (label, platform)) in PLATFORMS.iter().enumerate() {
        let batch = previewable_batch_for(&names, *platform);
        assert_eq!(batch.len(), names.len(), "{label}: one bit per name");
        assert_eq!(batch, want[index], "{label}: the whole corpus, in order");
        assert_eq!(
            previewable_batch_for(&[], *platform),
            BitSet::new(),
            "{label}: empty in, empty out"
        );
        assert_eq!(
            previewable_batch_for(&names, *platform),
            names
                .iter()
                .map(|name| is_previewable_by_extension_for(name, *platform))
                .collect::<BitSet>(),
            "{label}: batch must equal per row"
        );
    }

    // An unknown platform name is never a default: it does not resolve at all.
    for unknown in ["", "Web", "ios", "mobile ", "android", "desktop\n"] {
        assert_eq!(
            PreviewPlatform::from_name(unknown),
            None,
            "`{unknown}` must not resolve to a platform"
        );
    }
    for (label, platform) in PLATFORMS {
        assert_eq!(PreviewPlatform::from_name(label), Some(platform), "{label} resolves");
    }

    // The batches in the json agree with the per-platform predicates.
    let batches = doc["batches"].as_array().expect("batches must be a list");
    assert_eq!(batches.len(), PLATFORMS.len(), "one batch per platform");
    for batch in batches {
        let id = text(batch, "id");
        let label = text(batch, "platform");
        let platform = PreviewPlatform::from_name(label).unwrap_or_else(|| panic!("{id}: unknown platform `{label}`"));
        let input = strings(&batch["names"], id);
        let expected: BitSet = batch["expected"]
            .as_array()
            .unwrap_or_else(|| panic!("{id}: needs an `expected` array"))
            .iter()
            .map(|bit| bit.as_bool().expect("batch expectations are bools"))
            .collect();
        assert_eq!(expected.len(), input.len(), "{id}: one bit per name");
        assert_eq!(previewable_batch_for(&input, platform), expected, "{id}");
    }
}
