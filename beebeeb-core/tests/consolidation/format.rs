//! Move 4 — one byte formatter (spec §16.2).
//!
//! Cases live in `test-vectors/consolidation/format.json`: the canonical SI
//! form, the binary/IEC form, and the explicit-decimals compact form. The
//! frozen `format_storage_si` path must agree with `format_si` on every case.

use beebeeb_types::{format_binary, format_compact, format_si};
use serde_json::Value;

pub const CONCEPT: &str = "format";

fn expected(case: &Value) -> &str {
    case["expected"]
        .as_str()
        .unwrap_or_else(|| panic!("case `{}` needs a string `expected`", case["id"]))
}

#[test]
fn format_cases_match_core() {
    let cases = super::cases(CONCEPT);

    let mut si = 0;
    let mut binary = 0;
    let mut compact = 0;

    for case in &cases {
        let id = case["id"].as_str().expect("case id");
        let bytes = case["bytes"]
            .as_i64()
            .unwrap_or_else(|| panic!("{id}: `bytes` must fit in an i64"));
        let want = expected(case);
        match case["kind"].as_str().expect("case kind") {
            "si" => {
                si += 1;
                assert_eq!(format_si(bytes), want, "{id}: format_si");
                // The frozen path is the same function: both re-exports agree.
                assert_eq!(
                    beebeeb_types::format_storage_si(bytes),
                    want,
                    "{id}: the root re-export is byte-identical"
                );
                assert_eq!(
                    beebeeb_types::quota::format_storage_si(bytes),
                    want,
                    "{id}: the quota re-export is byte-identical"
                );
            }
            "binary" => {
                binary += 1;
                assert_eq!(format_binary(bytes), want, "{id}: format_binary");
            }
            "compact" => {
                compact += 1;
                let decimals = case["decimals"]
                    .as_u64()
                    .unwrap_or_else(|| panic!("{id}: `decimals` must be a number"))
                    as usize;
                assert_eq!(
                    format_compact(bytes, decimals),
                    want,
                    "{id}: format_compact with {decimals} decimals"
                );
            }
            other => panic!("{id}: unknown case kind `{other}`"),
        }
    }

    assert_eq!(si, 12, "the SI cases");
    assert_eq!(binary, 5, "the binary cases");
    assert_eq!(compact, 7, "the compact cases (0, 1 and 2 decimals)");
    for decimals in [0, 1, 2] {
        assert!(
            cases
                .iter()
                .any(|case| case["kind"] == "compact" && case["decimals"] == decimals),
            "missing a compact case with {decimals} decimals"
        );
    }
}
