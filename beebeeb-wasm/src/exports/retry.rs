//! Retry rules for the WASM surface, backed by `beebeeb_core::retry`.
//!
//! The policy is a plain object (`retryPolicy()` returns core's default) so a
//! web caller can keep it, override a field, then ask core for the delay or the
//! decision. No rule lives here: the ladder, the jitter bounds, the retryable
//! outcomes and `Retry-After` are core's, proved by
//! `test-vectors/consolidation/retry.json`.
use beebeeb_core::retry::{self, Jitter, RetryOutcome, RetryPolicy};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

/// The JS shape of a policy: what `retryPolicy()` returns and what every
/// function here accepts back. Fields are core's (`snake_case`), and `jitter`
/// is `"none"` (the shipped default) or `"full"`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryPolicyJs {
    pub max_attempts: u32,
    pub base_ms: u64,
    pub cap_ms: u64,
    pub jitter: String,
}

impl RetryPolicyJs {
    fn from_core(policy: RetryPolicy) -> Self {
        Self {
            max_attempts: policy.max_attempts,
            base_ms: policy.base_ms,
            cap_ms: policy.cap_ms,
            jitter: match policy.jitter {
                Jitter::None => "none".to_owned(),
                Jitter::Full => "full".to_owned(),
            },
        }
    }

    fn to_core(&self) -> Result<RetryPolicy, JsError> {
        let jitter = match self.jitter.as_str() {
            "none" => Jitter::None,
            "full" => Jitter::Full,
            other => return Err(JsError::new(&format!("unknown retry jitter: {other}"))),
        };
        Ok(RetryPolicy {
            max_attempts: self.max_attempts,
            base_ms: self.base_ms,
            cap_ms: self.cap_ms,
            jitter,
        })
    }
}

fn policy_from_js(policy: &JsValue) -> Result<RetryPolicy, JsError> {
    if policy.is_null() || policy.is_undefined() {
        return Ok(RetryPolicy::DEFAULT);
    }
    let parsed: RetryPolicyJs = serde_wasm_bindgen::from_value(policy.clone())
        .map_err(|error| JsError::new(&format!("invalid retry policy: {error}")))?;
    parsed.to_core()
}

/// The shipped policy: six requests in all (one try plus five retries), 500 ms
/// base, a 30 s cap, no jitter, and a server `Retry-After` honoured.
#[wasm_bindgen(js_name = retryPolicy)]
pub fn retry_policy() -> Result<JsValue, JsError> {
    serde_wasm_bindgen::to_value(&RetryPolicyJs::from_core(RetryPolicy::DEFAULT))
        .map_err(|error| JsError::new(&format!("cannot serialize the retry policy: {error}")))
}

/// The un-jittered ladder delay before retry number `retry` (1-based; retry 0
/// means "no retry" and is 0 ms), capped at the policy's `cap_ms`.
#[wasm_bindgen(js_name = retryDelayMs)]
pub fn retry_delay_ms(policy: JsValue, retry: u32) -> Result<f64, JsError> {
    Ok(policy_from_js(&policy)?.delay_ms(retry) as f64)
}

/// The ladder delay shortened per the policy's jitter, with a caller-supplied
/// sample in permille (`0..=1000`; larger values are clamped). A `"none"`
/// policy ignores the sample.
#[wasm_bindgen(js_name = retryJitteredDelayMs)]
pub fn retry_jittered_delay_ms(policy: JsValue, retry: u32, sample_permille: u32) -> Result<f64, JsError> {
    Ok(policy_from_js(&policy)?.jittered_delay_ms(retry, sample_permille) as f64)
}

/// The decision after `attempts_made` attempts: the delay in milliseconds to
/// wait before the next attempt, or `null` to surface the last error. A server
/// `Retry-After` (`retry_after_seconds`, a number of seconds or `null`)
/// replaces the ladder exactly.
///
/// `outcome` is `"success"`, `"network"`, `"fatal"`, or `{ status: 503 }`.
#[wasm_bindgen(js_name = retryDecide)]
pub fn retry_decide(
    policy: JsValue,
    attempts_made: u32,
    outcome: JsValue,
    retry_after_seconds: JsValue,
) -> Result<JsValue, JsError> {
    let policy = policy_from_js(&policy)?;
    let outcome = outcome_from_js(&outcome)?;
    let retry_after = retry_after_from_js(&retry_after_seconds)?;
    Ok(match policy.decide(attempts_made, outcome, retry_after) {
        Some(delay) => JsValue::from_f64(delay as f64),
        None => JsValue::NULL,
    })
}

/// Parse a `Retry-After` delta-seconds header: the number of seconds, or `null`
/// for anything else (empty, negative, fractional, an HTTP date), so the caller
/// falls back to the ladder.
#[wasm_bindgen(js_name = parseRetryAfter)]
pub fn parse_retry_after(value: &str) -> JsValue {
    match retry::parse_retry_after(value) {
        Some(seconds) => JsValue::from_f64(seconds as f64),
        None => JsValue::NULL,
    }
}

fn outcome_from_js(outcome: &JsValue) -> Result<RetryOutcome, JsError> {
    if let Some(text) = outcome.as_string() {
        return match text.as_str() {
            "success" => Ok(RetryOutcome::Success),
            "network" => Ok(RetryOutcome::Network),
            "fatal" => Ok(RetryOutcome::Fatal),
            other => Err(JsError::new(&format!("unknown retry outcome: {other}"))),
        };
    }
    if outcome.is_object() {
        let status = js_sys::Reflect::get(outcome, &JsValue::from_str("status"))
            .map_err(|_| JsError::new("retry outcome object has no status"))?;
        if let Some(status) = status.as_f64() {
            return Ok(RetryOutcome::Status(status as u16));
        }
    }
    Err(JsError::new(
        "retry outcome must be \"success\", \"network\", \"fatal\" or { status }",
    ))
}

fn retry_after_from_js(value: &JsValue) -> Result<Option<u64>, JsError> {
    if value.is_null() || value.is_undefined() {
        return Ok(None);
    }
    match value.as_f64() {
        Some(seconds) if seconds >= 0.0 => Ok(Some(seconds as u64)),
        Some(_) => Err(JsError::new("retry_after_seconds must not be negative")),
        None => Err(JsError::new("retry_after_seconds must be a number or null")),
    }
}
