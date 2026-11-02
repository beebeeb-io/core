//! Move 8 — recovery-phrase split and count (spec §16.2).
//!
//! Cases live in `test-vectors/consolidation/recovery.json`; this runner
//! executes them against `beebeeb_core::recovery`. The split normalises the
//! same whitespace mobile's `normalizePhrase` does — including non-breaking
//! and ideographic spaces — so a pasted phrase is not accepted in one client
//! and rejected by another.

use beebeeb_core::recovery::{normalize_phrase, phrase_is_complete, phrase_progress, phrase_word_count, split_phrase};
use beebeeb_types::RECOVERY_WORD_COUNT;

pub const CONCEPT: &str = "recovery";

#[test]
fn recovery_cases_match_core() {
    let cases = super::cases(CONCEPT);
    let mut splits = 0;

    for case in &cases {
        let id = case["id"].as_str().expect("case id");
        assert_eq!(case["kind"].as_str(), Some("split"), "{id}: case kind");
        splits += 1;

        let input = case["input"].as_str().expect("input");
        let expected_words: Vec<String> = case["expected_words"]
            .as_array()
            .expect("expected_words")
            .iter()
            .map(|word| word.as_str().expect("word").to_string())
            .collect();
        let expected_count = case["expected_count"].as_u64().expect("expected_count") as usize;
        let expected_complete = case["expected_complete"].as_bool().expect("expected_complete");

        let split_words = split_phrase(input);
        let split: Vec<&str> = split_words.iter().map(|word| word.as_str()).collect();
        assert_eq!(split, expected_words, "{id}: split");
        assert_eq!(phrase_word_count(input), expected_count, "{id}: count");
        assert_eq!(phrase_is_complete(input), expected_complete, "{id}: complete");
        assert_eq!(
            phrase_progress(input),
            (expected_count, RECOVERY_WORD_COUNT),
            "{id}: progress"
        );

        let normalized = normalize_phrase(input);
        let expected_normalized = expected_words.join(" ");
        assert_eq!(normalized.as_str(), expected_normalized, "{id}: normalisation");
        assert_eq!(
            normalize_phrase(&normalized).as_str(),
            normalized.as_str(),
            "{id}: normalisation is idempotent"
        );
        assert!(!normalized.contains("  "), "{id}: no doubled space survives");
        assert_eq!(
            normalized.trim(),
            normalized.as_str(),
            "{id}: no edge space survives"
        );
    }

    assert_eq!(splits, 12, "the split cases");
    for required in [
        "recovery_split_12_words",
        "recovery_split_24_words",
        "recovery_split_double_spaces",
        "recovery_split_nbsp",
        "recovery_split_ideographic_space",
        "recovery_split_11_words",
        "recovery_split_word_outside_list",
        "recovery_split_uppercase",
        "recovery_split_newlines_and_tabs",
        "recovery_split_trim",
        "recovery_split_empty",
        "recovery_split_whitespace_only",
    ] {
        assert!(
            cases.iter().any(|case| case["id"] == required),
            "{required} is a named case"
        );
    }
}
