//! Move 11 — path and filename safety (spec §16.2).
//!
//! Cases live in `test-vectors/consolidation/path_safety.json`. The pure rules
//! are checked with explicit `portable`/`windows` flags so the Windows branch is
//! proven on any host; containment uses a real temp directory.

use beebeeb_core::path_safety::{
    Rules, archive_component, check_component_for, ensure_contained, safe_rel_join, sanitize_component,
};
use serde_json::Value;

pub const CONCEPT: &str = "path_safety";

fn expect_ok_or_reason(case: &Value, result: Result<(), impl std::fmt::Display>) -> String {
    match (case["expect"].as_str().expect("expect"), result) {
        ("ok", Ok(())) => "ok".to_string(),
        ("reject", Err(error)) => {
            let reason = case["reason"].as_str().unwrap_or("");
            let text = error.to_string();
            assert!(
                text.contains(reason),
                "{}: `{text}` must contain `{reason}`",
                case["id"].as_str().unwrap_or("?")
            );
            text
        }
        ("ok", Err(error)) => panic!("{}: expected a clean name, got `{error}`", case["id"]),
        ("reject", Ok(())) => panic!("{}: expected a refusal, the name was accepted", case["id"]),
        (other, _) => panic!("{}: unknown expect `{other}`", case["id"]),
    }
}

#[test]
fn path_safety_cases_match_core() {
    let cases = super::cases(CONCEPT);
    assert_eq!(cases.len(), 47, "every named path-safety case is present");

    let mut checks = 0;
    let mut sanitized = 0;
    let mut rel_joins = 0;
    let mut contained = 0;

    for case in &cases {
        let id = case["id"].as_str().expect("case id");
        match case["kind"].as_str().expect("case kind") {
            "check" => {
                checks += 1;
                let name = case["name"].as_str().expect("name");
                let portable = case["portable"].as_bool().expect("portable");
                let windows = case["windows"].as_bool().expect("windows");
                expect_ok_or_reason(case, check_component_for(name, portable, windows));
                if portable && !windows {
                    // The public entry point must agree with the explicit flags
                    // for the portable rule set on every host (the Windows-only
                    // cosmetics are the `windows` flag's business).
                    let via_rules = beebeeb_core::path_safety::check_component(name, Rules::Portable);
                    assert_eq!(via_rules.is_ok(), case["expect"] == "ok", "{id}: Rules::Portable");
                }
            }
            "sanitize" => {
                sanitized += 1;
                match sanitize_component(case["name"].as_str().expect("name"), Rules::Portable) {
                    Ok(clean) => {
                        assert_eq!(case["expect"], "ok", "{id}: unexpected clean output {clean:?}");
                        let expected = case["expected"].as_str().expect("expected");
                        assert_eq!(clean, expected, "{id}");
                        // The rewrite must itself satisfy the strictest rules
                        // and must be stable.
                        check_component_for(&clean, true, true).unwrap_or_else(|e| panic!("{id}: {e}"));
                        assert_eq!(
                            sanitize_component(&clean, Rules::Portable).as_deref(),
                            Ok(expected),
                            "{id}: idempotent"
                        );
                        // The archive rule is the portable one.
                        assert_eq!(
                            archive_component(case["name"].as_str().unwrap()).as_deref(),
                            Ok(expected)
                        );
                    }
                    Err(error) => {
                        assert_eq!(case["expect"], "reject", "{id}: unexpectedly rejected: {error}");
                    }
                }
            }
            "rel-join" => {
                rel_joins += 1;
                let root = std::env::temp_dir().join(format!("bb-path-safety-{id}"));
                let _ = std::fs::remove_dir_all(&root);
                std::fs::create_dir_all(&root).expect("create root");
                let rel = case["rel"].as_str().expect("rel");
                match safe_rel_join(&root, rel, Rules::Portable) {
                    Ok(joined) => {
                        assert_eq!(case["expect"], "ok", "{id}: unexpectedly accepted {joined:?}");
                        assert!(joined.starts_with(&root), "{id}: {joined:?} escapes {}", root.display());
                    }
                    Err(error) => {
                        assert_eq!(case["expect"], "reject", "{id}: unexpectedly accepted");
                        let reason = case["reason"].as_str().unwrap_or("");
                        assert!(error.contains(reason), "{id}: `{error}` must contain `{reason}`");
                    }
                }
                let _ = std::fs::remove_dir_all(&root);
            }
            "contained" => {
                contained += 1;
                let root = std::env::temp_dir().join(format!("bb-path-contained-{id}"));
                let _ = std::fs::remove_dir_all(&root);
                std::fs::create_dir_all(&root).expect("create root");
                let sub = case["sub"].as_str().expect("sub");
                match ensure_contained(&root, &root.join(sub)) {
                    Ok(()) => assert_eq!(case["expect"], "ok", "{id}: unexpectedly accepted"),
                    Err(error) => {
                        assert_eq!(case["expect"], "reject", "{id}: unexpectedly accepted");
                        let reason = case["reason"].as_str().unwrap_or("");
                        assert!(error.contains(reason), "{id}: `{error}` must contain `{reason}`");
                    }
                }
                let _ = std::fs::remove_dir_all(&root);
            }
            other => panic!("{id}: unknown case kind `{other}`"),
        }
    }

    assert_eq!((checks, sanitized, rel_joins, contained), (32, 9, 4, 2));
    for required in [
        "path_reject_dotdot",
        "path_reject_reserved_con",
        "path_reject_trailing_dot",
        "path_sanitize_bidi",
        "path_ensure_contained_escape",
    ] {
        assert!(cases.iter().any(|case| case["id"] == required), "missing `{required}`");
    }
}
