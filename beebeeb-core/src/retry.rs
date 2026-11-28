//! The one retry/backoff policy (move 6), and the one client wait after a 429.
//!
//! This module is pure: it decides *whether* to retry and *how long* to wait;
//! the transport owns the clock and the sleep. The ladder constants are the
//! ones `beebeeb-upload::retry` has shipped with (six total attempts, 500 ms
//! base, 30 s cap), expressed once so every client can share the decision
//! without sharing the transport.
//!
//! A 429 does not use the ladder. [`rate_limit_wait_ms`] is the wait: a floor
//! of [`RATE_LIMIT_WAIT_FLOOR_MS`] that doubles with each 429 in a row, up to
//! [`RATE_LIMIT_WAIT_CAP_MS`]; a longer server `Retry-After` wins, up to
//! `MAX_RETRY_AFTER_SECONDS`; then 0-25 % jitter is added from the caller's
//! sample. [`RetryPolicy::decide`] applies the same rule without jitter.
//!
//! Jitter is deterministic on purpose: the caller supplies a sample in
//! permille, so a test can pin the bounds and a production caller can feed it
//! a random sample. [`Jitter::Full`] shortens a ladder delay (never longer
//! than the ladder); the 429 jitter only lengthens the wait (never shorter
//! than the floor or the server's `Retry-After`).

use beebeeb_types::limits::MAX_RETRY_AFTER_SECONDS;

// Client 429 contract (rate-limit epic 08a-08d, rate-limit-backoff). Every
// client follows it:
//   * `hint = max(Retry-After header, body.retry_after)`;
//   * a hint above [`CLIENT_429_POLICY_REFUSAL_SECONDS`] or `error: "banned"`
//     is a policy refusal: show "temporarily blocked", never "can't connect",
//     and do not wait or retry;
//   * otherwise pause for `rate_limit_wait_ms(streak, hint, random 0..=1000)`.
//     The pause is shared by the whole client (process, tab group, uploader),
//     not one request: every request waits for a running pause before it is
//     sent, and a 429 that arrives while a pause runs does not start or
//     lengthen another one;
//   * `streak` is 0 for the first 429 of a run of refusals and resets on the
//     first non-429 answer;
//   * only an idempotent request (GET/HEAD/OPTIONS, or a write with an
//     idempotency key) is sent again, at most [`CLIENT_429_MAX_RETRIES`]
//     times. Any other request gets its 429 back.
// The 429 body is `{"error": "rate_limited" | "banned", "scope", "retry_after", "message"}`.

/// Most retries of one idempotent request after a 429.
pub const CLIENT_429_MAX_RETRIES: u32 = 4;
/// A `Retry-After` above this many seconds is a policy refusal, not a wait.
pub const CLIENT_429_POLICY_REFUSAL_SECONDS: u64 = 60;
/// Upper bound of the extra jitter added to a 429 wait, in percent.
pub const CLIENT_429_WAIT_JITTER_PERCENT: u64 = 25;
/// The shortest wait after a 429, before jitter. It doubles per 429 in a row.
pub const RATE_LIMIT_WAIT_FLOOR_MS: u64 = 2_000;
/// Upper bound of the doubling floor. A longer server `Retry-After` still wins.
pub const RATE_LIMIT_WAIT_CAP_MS: u64 = 60_000;

/// How long a client pauses after a 429, in milliseconds.
///
/// `streak` counts the 429s in a row before this one (0 for the first). The
/// base is the larger of the doubling floor (capped at
/// [`RATE_LIMIT_WAIT_CAP_MS`]) and the server's `retry_after_seconds` (capped
/// at `MAX_RETRY_AFTER_SECONDS`). `jitter_permille` (`0..=1000`; larger values
/// are clamped) then adds 0 to [`CLIENT_429_WAIT_JITTER_PERCENT`] percent.
pub fn rate_limit_wait_ms(streak: u32, retry_after_seconds: Option<u64>, jitter_permille: u32) -> u64 {
    let floor = RATE_LIMIT_WAIT_FLOOR_MS
        .saturating_mul(2u64.saturating_pow(streak))
        .min(RATE_LIMIT_WAIT_CAP_MS);
    let hinted = retry_after_seconds
        .unwrap_or(0)
        .min(MAX_RETRY_AFTER_SECONDS)
        .saturating_mul(1000);
    let base = floor.max(hinted);
    let jitter = base
        .saturating_mul(CLIENT_429_WAIT_JITTER_PERCENT)
        .saturating_mul(u64::from(jitter_permille.min(1000)))
        / 100_000;
    base.saturating_add(jitter)
}

/// How the ladder delay is shortened for a retry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Jitter {
    /// Use the ladder delay exactly.
    None,
    /// Full jitter: `delay * sample_permille / 1000`, sampled in `0..=1000`.
    Full,
}

/// The outcome of one attempt, as far as the retry decision is concerned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryOutcome {
    /// The attempt succeeded.
    Success,
    /// The server answered with this status.
    Status(u16),
    /// The transport failed without a status (timeout, reset, DNS).
    Network,
    /// A caller-classified permanent error (4xx other than 429, I/O).
    Fatal,
}

/// One backoff policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryPolicy {
    /// Total attempts allowed, including the first one.
    pub max_attempts: u32,
    /// Delay before the first retry, in milliseconds.
    pub base_ms: u64,
    /// Upper bound on any ladder delay, in milliseconds.
    pub cap_ms: u64,
    /// How the ladder delay is shortened.
    pub jitter: Jitter,
}

impl RetryPolicy {
    /// The policy core has always shipped: one attempt plus five retries,
    /// 500 ms base, 30 s cap, [`Jitter::Full`] (the caller feeds the sample to
    /// [`Self::jittered_delay_ms`]; [`Self::decide`] stays un-jittered),
    /// `Retry-After` honoured.
    pub const DEFAULT: Self = Self {
        max_attempts: 6,
        base_ms: 500,
        cap_ms: 30_000,
        jitter: Jitter::Full,
    };

    /// The un-jittered ladder delay before retry number `retry` (1-based).
    /// Retry 0 means "no retry" and returns 0.
    pub fn delay_ms(&self, retry: u32) -> u64 {
        if retry == 0 {
            return 0;
        }
        let factor = 2u64.saturating_pow(retry - 1);
        self.base_ms.saturating_mul(factor).min(self.cap_ms)
    }

    /// The ladder delay shortened per this policy's [`Jitter`], with a caller
    /// sample in permille (`0..=1000`; larger values are clamped).
    pub fn jittered_delay_ms(&self, retry: u32, sample_permille: u32) -> u64 {
        let delay = self.delay_ms(retry);
        match self.jitter {
            Jitter::None => delay,
            Jitter::Full => delay.saturating_mul(u64::from(sample_permille.min(1000))) / 1000,
        }
    }

    /// Whether `attempts_made` attempts leave budget for another one.
    pub fn has_budget(&self, attempts_made: u32) -> bool {
        attempts_made < self.max_attempts
    }

    /// Whether `outcome` is worth another attempt at all, regardless of budget.
    pub fn is_retryable(&self, outcome: RetryOutcome) -> bool {
        match outcome {
            RetryOutcome::Success | RetryOutcome::Fatal => false,
            RetryOutcome::Network => true,
            RetryOutcome::Status(429) => true,
            RetryOutcome::Status(status) => (500..=599).contains(&status),
        }
    }

    /// The decision after `attempts_made` attempts: `Some(delay_ms)` to retry
    /// after that wait, `None` to surface the last error.
    ///
    /// A 429 waits [`rate_limit_wait_ms`] without jitter, with the 429s before
    /// this one (`attempts_made - 1`) as the streak. For any other outcome a
    /// server `Retry-After` replaces the ladder exactly, and the ladder delay
    /// is un-jittered; a transport running with [`Jitter::Full`] takes its
    /// wait from [`Self::jittered_delay_ms`] instead.
    pub fn decide(&self, attempts_made: u32, outcome: RetryOutcome, retry_after_seconds: Option<u64>) -> Option<u64> {
        if !self.is_retryable(outcome) || !self.has_budget(attempts_made) {
            return None;
        }
        if outcome == RetryOutcome::Status(429) {
            return Some(rate_limit_wait_ms(
                attempts_made.saturating_sub(1),
                retry_after_seconds,
                0,
            ));
        }
        Some(match retry_after_seconds {
            Some(seconds) => seconds.min(MAX_RETRY_AFTER_SECONDS).saturating_mul(1000),
            None => self.delay_ms(attempts_made),
        })
    }
}

/// Parse a `Retry-After` delta-seconds header. HTTP-dates are not supported
/// (no client here sends one); a non-numeric value returns `None` so the
/// caller falls back to the ladder.
pub fn parse_retry_after(value: &str) -> Option<u64> {
    let value = value.trim();
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    value
        .parse::<u64>()
        .ok()
        .map(|seconds| seconds.min(MAX_RETRY_AFTER_SECONDS))
}

#[cfg(test)]
mod limit_tests {
    use super::*;

    #[test]
    fn default_jitter_is_full() {
        assert_eq!(RetryPolicy::DEFAULT.jitter, Jitter::Full);
        assert_eq!(RetryPolicy::DEFAULT.jittered_delay_ms(1, 500), 250);
        assert_eq!(RetryPolicy::DEFAULT.delay_ms(1), 500);
    }

    #[test]
    fn retry_after_is_capped() {
        assert_eq!(parse_retry_after("99999999999"), Some(300));
        assert_eq!(
            RetryPolicy::DEFAULT.decide(1, RetryOutcome::Status(429), Some(u64::MAX)),
            Some(300_000)
        );
    }
}
