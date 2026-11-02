//! Move 7 — the server error body and its branches (spec §16.2).
//!
//! Cases live in `test-vectors/consolidation/error_body.json`; this runner
//! executes them against `beebeeb_core::api_error`. The typed error keeps the
//! whole parsed body, so fields a client branches on (`is_trial_cap`,
//! `limit_bytes`, `used_bytes`, and future ones) survive the decode.

use beebeeb_core::api_error::ServerError;
use serde_json::Value;

pub const CONCEPT: &str = "error_body";

#[test]
fn error_body_cases_match_core() {
    let cases = super::cases(CONCEPT);
    let mut bodies = 0;

    for case in &cases {
        let id = case["id"].as_str().expect("case id");
        assert_eq!(case["kind"].as_str(), Some("body"), "{id}: case kind");
        bodies += 1;

        let status = case["status"].as_u64().expect("status") as u16;
        let payload = case["payload"].as_str().expect("payload");
        let expected = &case["expected"];

        let err = ServerError::parse_body(status, payload);

        assert_eq!(err.status, status, "{id}: status");
        assert_eq!(err.code, expected["code"].as_str().map(str::to_string), "{id}: code");
        assert_eq!(
            err.message,
            expected["message"].as_str().expect("message"),
            "{id}: message"
        );
        assert_eq!(
            err.status_is_error(),
            expected["status_is_error"].as_bool().expect("status_is_error"),
            "{id}: status_is_error"
        );
        assert_eq!(
            err.is_session_gone(true),
            expected["session_gone_404"].as_bool().expect("session_gone_404"),
            "{id}: 404 counts"
        );
        assert_eq!(
            err.is_session_gone(false),
            expected["session_gone_strict"].as_bool().expect("session_gone_strict"),
            "{id}: a 404 does not count"
        );
        assert_eq!(err.retry_after(), expected["retry_after"].as_u64(), "{id}: retry_after");
        assert_eq!(
            err.is_trial_cap(),
            expected["is_trial_cap"].as_bool().expect("is_trial_cap"),
            "{id}: is_trial_cap"
        );
        assert_eq!(err.limit_bytes(), expected["limit_bytes"].as_u64(), "{id}: limit_bytes");
        assert_eq!(err.used_bytes(), expected["used_bytes"].as_u64(), "{id}: used_bytes");

        for code in expected["is_code"].as_array().expect("is_code") {
            let code = code.as_str().expect("code string");
            assert!(err.is_code(code), "{id}: is_code({code})");
        }
        for code in expected["not_code"].as_array().expect("not_code") {
            let code = code.as_str().expect("code string");
            assert!(!err.is_code(code), "{id}: not is_code({code})");
        }

        if let Some(details) = case.get("details_preserved").and_then(Value::as_array) {
            for field in details {
                let field = field.as_str().expect("field name");
                assert!(err.details.contains_key(field), "{id}: details keeps `{field}`");
            }
        }
    }

    assert_eq!(bodies, 14, "the error-body cases");
    for required in [
        "error_body_quota_exceeded",
        "error_body_unauthorized",
        "error_body_plan_required",
        "error_body_account_lapsed",
        "error_body_missing_body",
        "error_body_non_json",
        "error_body_200_with_error",
        "error_body_trial_cap_keeps_flag",
        "error_body_quota_keeps_limit_bytes",
        "error_body_double_encoded",
        "error_body_session_gone_404",
        "error_body_session_gone_400_expired",
        "error_body_session_gone_409",
        "error_body_retry_after_field",
    ] {
        assert!(
            cases.iter().any(|case| case["id"] == required),
            "{required} is a named case"
        );
    }
}
