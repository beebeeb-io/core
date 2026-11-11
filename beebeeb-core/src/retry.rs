//! The one retry/backoff policy (move 6).
//!
//! This module is pure: it decides *whether* to retry and *how long* to wait;
//! the transport owns the clock and the sleep. The constants are the ones
//! `beebeeb-upload::retry` has shipped with — six total attempts, 500 ms base,
//! 30 s cap, and a server `Retry-After` winning over the ladder — expressed
//! once so every client can share the decision without sharing the transport.
//!
//! Jitter is deterministic on purpose: [`Jitter::Full`] takes a caller-supplied
//! sample in permille of the ladder delay, so a test can pin the bounds and a
//! production caller can feed it a random sample. A jittered wait is never
//! longer than the ladder delay, and a server `Retry-After` is never jittered.

use beebeeb_types::limits::MAX_RETRY_AFTER_SECONDS;

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
    /// 500 ms base, 30 s cap, no jitter, `Retry-After` honoured.
    pub const DEFAULT: Self = Self {
        max_attempts: 6,
        base_ms: 500,
        cap_ms: 30_000,
        jitter: Jitter::None,
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
    /// A server `Retry-After` replaces the ladder exactly. The ladder delay is
    /// un-jittered; a transport running with [`Jitter::Full`] takes its wait
    /// from [`Self::jittered_delay_ms`] instead.
    pub fn decide(&self, attempts_made: u32, outcome: RetryOutcome, retry_after_seconds: Option<u64>) -> Option<u64> {
        if !self.is_retryable(outcome) || !self.has_budget(attempts_made) {
            return None;
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
    fn retry_after_is_capped() {
        assert_eq!(parse_retry_after("99999999999"), Some(300));
        assert_eq!(
            RetryPolicy::DEFAULT.decide(1, RetryOutcome::Status(429), Some(u64::MAX)),
            Some(300_000)
        );
    }
}
