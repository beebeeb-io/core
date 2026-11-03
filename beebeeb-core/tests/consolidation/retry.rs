//! Move 6 — the one backoff policy (spec §16.2).
//!
//! Cases live in `test-vectors/consolidation/retry.json`; this runner executes
//! them against `beebeeb_core::retry`. The module is pure: no clock, no sleep.

use beebeeb_core::retry::{Jitter, RetryOutcome, RetryPolicy, parse_retry_after};
use serde_json::Value;

pub const CONCEPT: &str = "retry";

fn outcome_of(value: &Value) -> RetryOutcome {
    match value {
        Value::String(kind) => match kind.as_str() {
            "network" => RetryOutcome::Network,
            "success" => RetryOutcome::Success,
            "fatal" => RetryOutcome::Fatal,
            other => panic!("unknown outcome `{other}`"),
        },
        Value::Object(map) => {
            let status = map
                .get("status")
                .and_then(Value::as_u64)
                .expect("status outcome needs a numeric status") as u16;
            RetryOutcome::Status(status)
        }
        other => panic!("unknown outcome shape {other}"),
    }
}

#[test]
fn retry_cases_match_core() {
    let cases = super::cases(CONCEPT);
    let policy = RetryPolicy::DEFAULT;

    let mut ladder = 0;
    let mut jitter = 0;
    let mut decisions = 0;
    let mut parsed = 0;

    for case in &cases {
        let id = case["id"].as_str().expect("case id");
        match case["kind"].as_str().expect("case kind") {
            "ladder" => {
                ladder += 1;
                let retry = case["retry"].as_u64().expect("retry") as u32;
                let expected = case["expected_ms"].as_u64().expect("expected_ms");
                assert_eq!(policy.delay_ms(retry), expected, "{id}: ladder");
            }
            "jitter" => {
                jitter += 1;
                let mut jittered = policy;
                jittered.jitter = match case["jitter"].as_str().expect("jitter") {
                    "none" => Jitter::None,
                    "full" => Jitter::Full,
                    other => panic!("{id}: unknown jitter `{other}`"),
                };
                let retry = case["retry"].as_u64().expect("retry") as u32;
                let sample = case["sample_permille"].as_u64().expect("sample_permille") as u32;
                let expected = case["expected_ms"].as_u64().expect("expected_ms");
                assert_eq!(jittered.jittered_delay_ms(retry, sample), expected, "{id}: jitter");
            }
            "decision" => {
                decisions += 1;
                let attempts = case["attempts_made"].as_u64().expect("attempts_made") as u32;
                let retry_after = case["retry_after_seconds"].as_u64();
                let expected = case["expected_ms"].as_u64();
                let actual = policy.decide(attempts, outcome_of(&case["outcome"]), retry_after);
                assert_eq!(actual, expected, "{id}: decision");
            }
            "parse" => {
                parsed += 1;
                let value = case["value"].as_str().expect("value");
                let expected = case["expected_seconds"].as_u64();
                assert_eq!(parse_retry_after(value), expected, "{id}: Retry-After");
            }
            other => panic!("{id}: unknown case kind `{other}`"),
        }
    }

    assert_eq!(ladder, 8, "the ladder cases");
    assert_eq!(jitter, 5, "the jitter cases");
    assert_eq!(decisions, 9, "the decision cases");
    assert_eq!(parsed, 8, "the Retry-After cases");
    for required in [
        "retry_429_with_retry_after",
        "retry_429_without_retry_after",
        "retry_5xx",
        "retry_network_error",
        "retry_budget_exhausted",
        "retry_jitter_bounds_full",
    ] {
        assert!(
            cases.iter().any(|case| case["id"] == required),
            "{required} is a named case"
        );
    }
}
