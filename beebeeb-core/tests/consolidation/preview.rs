//! Move 3 — media and preview extensions (spec §16.2).
//!
//! Cases live in `test-vectors/consolidation/preview.json`: all 91 of core's
//! extensions (90, plus `zip` since archives preview through core's reader),
//! the 47 extensions where the web client's list disagrees, and the shape
//! cases. The batch predicate must answer the whole corpus in
//! order, exactly as the per-row predicate does.

use beebeeb_core::media::{BitSet, is_previewable_by_extension, previewable_batch};
use serde_json::Value;

pub const CONCEPT: &str = "preview";

fn text<'a>(case: &'a Value, key: &str) -> &'a str {
    case[key]
        .as_str()
        .unwrap_or_else(|| panic!("case `{}` needs a string `{key}`", case["id"]))
}

fn expected(case: &Value) -> bool {
    case["expected"]
        .as_bool()
        .unwrap_or_else(|| panic!("case `{}` needs a bool `expected`", case["id"]))
}

#[test]
fn preview_cases_match_core() {
    let cases = super::cases(CONCEPT);

    let mut extensions = 0;
    let mut disagreements = 0;
    let mut names: Vec<String> = Vec::new();
    let mut want: BitSet = BitSet::new();

    for case in &cases {
        let id = text(case, "id");
        match text(case, "kind") {
            "extension" => {
                extensions += 1;
                let name = text(case, "name");
                assert_eq!(
                    is_previewable_by_extension(name),
                    expected(case),
                    "{id}: core's answer for `{name}`"
                );
                names.push(name.to_string());
                want.push(expected(case));
            }
            "web-disagreement" => {
                disagreements += 1;
                let name = text(case, "name");
                // The `web` field records the other client's answer; it is
                // documentation, never something this test asserts.
                assert!(case["web"].is_boolean(), "{id}: needs the web answer");
                assert_eq!(
                    is_previewable_by_extension(name),
                    expected(case),
                    "{id}: core's answer for `{name}`"
                );
                assert_ne!(
                    case["web"].as_bool().unwrap(),
                    expected(case),
                    "{id}: a disagreement case must actually disagree"
                );
                names.push(name.to_string());
                want.push(expected(case));
            }
            "batch" => {
                let input: Vec<String> = case["names"]
                    .as_array()
                    .unwrap_or_else(|| panic!("{id}: needs `names`"))
                    .iter()
                    .map(|name| name.as_str().expect("batch names are strings").to_string())
                    .collect();
                let batch_want: BitSet = case["expected"]
                    .as_array()
                    .unwrap_or_else(|| panic!("{id}: needs an `expected` array"))
                    .iter()
                    .map(|bit| bit.as_bool().expect("batch expectations are bools"))
                    .collect();
                assert_eq!(batch_want.len(), input.len(), "{id}: one bit per name");
                let batch = previewable_batch(&input);
                assert_eq!(batch.len(), input.len(), "{id}: result length");
                assert_eq!(batch, batch_want, "{id}: batch answer");
                let per_row: BitSet = input.iter().map(|name| is_previewable_by_extension(name)).collect();
                assert_eq!(batch, per_row, "{id}: batch must equal per row");
            }
            other => panic!("{id}: unknown case kind `{other}`"),
        }
    }

    // All 91 of core's extensions, all 47 disagreements (zip agrees since
    // archives preview through core's reader), the three shape cases
    // (unknown extension, uppercase extension, empty name).
    assert_eq!(extensions, 91 + 3, "91 core extensions plus 3 shape cases");
    assert_eq!(disagreements, 47, "the web disagreement count");
    for required in [
        "preview_unknown_extension",
        "preview_uppercase_extension",
        "preview_empty_name",
    ] {
        assert!(
            cases.iter().any(|case| case["id"] == required),
            "missing named case `{required}`"
        );
    }

    // One crossing for the whole corpus: the batch answer is the per-row answer
    // for every case in file order, and an empty list is empty.
    let per_row: BitSet = names.iter().map(|name| is_previewable_by_extension(name)).collect();
    assert_eq!(per_row, want, "the corpus expectations");
    assert_eq!(previewable_batch(&names), want, "all cases, in order");
    assert_eq!(previewable_batch(&[]), BitSet::new(), "empty in, empty out");
}
