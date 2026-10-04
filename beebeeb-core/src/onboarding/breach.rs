//! k-anonymity breached-password helper (task 1744, spec section 2.5 item 1).
//!
//! Core does the hashing, the prefix/suffix split and the response matching.
//! **Core does no I/O.** Each client makes the HTTP call itself and hands the
//! response body back, so the network stack, TLS pinning and cookies stay a
//! client concern and core stays synchronous and WASM-clean.
//!
//! # Where the call goes (no-US-systems rule)
//!
//! The helper is deliberately endpoint-agnostic and names no third-party
//! service. The endpoint is Beebeeb's own: the server exposes
//! `GET /api/v1/auth/pwned-range/{prefix}` (`beebeeb-api/src/routes/auth.rs`),
//! answering from a node-local, read-only corpus (server tasks 0766 and 0767),
//! and the onboarding document declares it as
//! `policy.password.breach_check.endpoint`. The public HaveIBeenPwned API sits
//! behind a US CDN and must never be called from a client (task 0995).
//!
//! # Flow
//!
//! 1. [`BreachQuery::from_password`]: SHA-1 the password, upper-case hex, split
//!    into a 5-character prefix and a 35-character suffix.
//! 2. The client sends **only the prefix** to the declared endpoint.
//! 3. The client passes the response body (or "the request failed") to
//!    [`evaluate_breach_response`] together with the declared `fail_open`.
//!
//! # Failure policy
//!
//! A transport failure, a non-2xx status, or a body that is not in the
//! `SUFFIX:COUNT` format is an *outage*, not "clean". With `fail_open = true`
//! the verdict is [`BreachVerdict::CheckFailedAllowed`]: the client proceeds
//! but can say honestly that the check did not run. With `fail_open = false`
//! it is [`BreachVerdict::CheckFailedBlocked`]. An empty body is **not** an
//! outage: the server answers an empty body for a prefix that is not in the
//! corpus (and for an unseeded node), which is the same as "no match".
//!
//! SHA-1 here only addresses the corpus (it is the key of the public dataset).
//! It is not used for integrity or authentication.

use sha1::{Digest, Sha1};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Characters of the SHA-1 digest sent to the server. This is the k-anonymity
/// parameter of the corpus format and of the server route, not a policy knob.
pub const BREACH_PREFIX_LEN: usize = 5;

/// Characters of the digest kept on the client for matching (40 - 5).
pub const BREACH_SUFFIX_LEN: usize = 35;

/// The two halves of an upper-case hex SHA-1 digest of a password.
///
/// Zeroized on drop: together the halves are an unsalted SHA-1 of the password
/// and would let anyone holding them test guesses offline.
#[derive(ZeroizeOnDrop)]
pub struct BreachQuery {
    prefix: String,
    suffix: String,
}

impl BreachQuery {
    /// Hash `password` (UTF-8 bytes, exactly as typed, no normalisation) and
    /// split the digest.
    pub fn from_password(password: &str) -> Self {
        let mut digest = Sha1::digest(password.as_bytes());
        let mut hex = upper_hex(digest.as_slice());
        digest.as_mut_slice().zeroize();
        let query = Self {
            prefix: hex[..BREACH_PREFIX_LEN].to_owned(),
            suffix: hex[BREACH_PREFIX_LEN..].to_owned(),
        };
        hex.zeroize();
        query
    }

    /// Convenience for [`evaluate_breach_response`].
    pub fn evaluate(&self, response: BreachResponse<'_>, fail_open: bool) -> BreachVerdict {
        evaluate_breach_response(self, response, fail_open)
    }

    /// The 5 characters to send to the server (upper-case hex).
    pub fn prefix(&self) -> &str {
        &self.prefix
    }

    /// The 35 characters that must never leave the device.
    pub fn suffix(&self) -> &str {
        &self.suffix
    }
}

/// What the client observed when it called the declared endpoint.
#[derive(Clone, Copy, Debug)]
pub enum BreachResponse<'a> {
    /// A 2xx response; the body text.
    Body(&'a str),
    /// Network error, timeout, non-2xx status, or the body could not be read.
    Unavailable,
}

/// Outcome of a breach check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BreachVerdict {
    /// The corpus was consulted and the password is not in it.
    Clean,
    /// The password is in the corpus; `count` is how many times it was seen.
    Breached { count: u64 },
    /// The check did not run (outage or malformed answer) and the server says
    /// to fail open: the client may proceed.
    CheckFailedAllowed,
    /// The check did not run and the server says to fail closed: the client
    /// must not proceed.
    CheckFailedBlocked,
    /// The server document declares no breach check, so none was attempted.
    /// Constructed by the client, never returned by
    /// [`evaluate_breach_response`].
    NotRequired,
}

impl BreachVerdict {
    /// Whether the client may let the user continue with this password.
    /// `Breached` and `CheckFailedBlocked` stop it.
    pub fn allows_proceeding(&self) -> bool {
        matches!(self, Self::Clean | Self::CheckFailedAllowed | Self::NotRequired)
    }

    /// Stable lowercase token for clients that cannot share the enum (WASM).
    pub fn kind_str(&self) -> &'static str {
        match self {
            Self::Clean => "clean",
            Self::Breached { .. } => "breached",
            Self::CheckFailedAllowed => "check_failed_allowed",
            Self::CheckFailedBlocked => "check_failed_blocked",
            Self::NotRequired => "not_required",
        }
    }

    /// True when the corpus was not actually consulted.
    pub fn check_failed(&self) -> bool {
        matches!(self, Self::CheckFailedAllowed | Self::CheckFailedBlocked)
    }
}

/// Decide the verdict for `query` from what the endpoint returned.
///
/// `fail_open` is `policy.password.breach_check.fail_open` from the server
/// document and is applied only when the check could not complete.
pub fn evaluate_breach_response(query: &BreachQuery, response: BreachResponse<'_>, fail_open: bool) -> BreachVerdict {
    let outage = if fail_open {
        BreachVerdict::CheckFailedAllowed
    } else {
        BreachVerdict::CheckFailedBlocked
    };

    let body = match response {
        BreachResponse::Body(b) => b,
        BreachResponse::Unavailable => return outage,
    };

    // Parse the whole body first so one malformed line anywhere marks the
    // answer untrustworthy (a captive-portal page returned with status 200
    // must not read as "clean").
    let mut found: Option<u64> = None;
    for raw in body.lines() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        let (suffix_part, count) = match line.split_once(':') {
            Some((s, c)) => match c.trim().parse::<u64>() {
                Ok(n) => (s.trim(), n),
                Err(_) => return outage,
            },
            // A bare suffix means "present", the same as the web client treated it.
            None => (line, 1),
        };
        if suffix_part.len() != BREACH_SUFFIX_LEN || !suffix_part.bytes().all(|b| b.is_ascii_hexdigit()) {
            return outage;
        }
        if suffix_part.eq_ignore_ascii_case(query.suffix()) {
            // Count 0 is range padding (`Add-Padding` style) and means "not present".
            let seen = found.unwrap_or(0).max(count);
            found = Some(seen);
        }
    }

    match found {
        Some(count) if count > 0 => BreachVerdict::Breached { count },
        _ => BreachVerdict::Clean,
    }
}

fn upper_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
    // (the canonical k-anonymity example in the public dataset documentation).
    const PW: &str = "password";
    const PW_PREFIX: &str = "5BAA6";
    const PW_SUFFIX: &str = "1E4C9B93F3F0682250B6CF8331B7EE68FD8";

    #[test]
    fn known_vector_splits_into_prefix_and_suffix() {
        let q = BreachQuery::from_password(PW);
        assert_eq!(q.prefix(), PW_PREFIX);
        assert_eq!(q.suffix(), PW_SUFFIX);
        assert_eq!(q.prefix().len(), BREACH_PREFIX_LEN);
        assert_eq!(q.suffix().len(), BREACH_SUFFIX_LEN);
    }

    #[test]
    fn empty_password_vector() {
        // SHA-1("") = DA39A3EE5E6B4B0D3255BFEF95601890AFD80709
        let q = BreachQuery::from_password("");
        assert_eq!(q.prefix(), "DA39A");
        assert_eq!(q.suffix(), "3EE5E6B4B0D3255BFEF95601890AFD80709");
    }

    #[test]
    fn utf8_bytes_are_hashed_without_normalisation() {
        // "e" + combining acute vs precomposed: different bytes, different digests.
        let a = BreachQuery::from_password("e\u{0301}");
        let b = BreachQuery::from_password("\u{00E9}");
        assert_ne!(
            format!("{}{}", a.prefix(), a.suffix()),
            format!("{}{}", b.prefix(), b.suffix())
        );
    }

    fn body_with(suffix: &str, count: &str) -> String {
        format!(
            "0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n{suffix}:{count}\r\n011053FD0102E94D6AE2F8B83D76FAF94F6:1\r\n"
        )
    }

    #[test]
    fn matching_suffix_is_breached_with_count() {
        let q = BreachQuery::from_password(PW);
        let v = evaluate_breach_response(&q, BreachResponse::Body(&body_with(PW_SUFFIX, "9545824")), true);
        assert_eq!(v, BreachVerdict::Breached { count: 9_545_824 });
        assert!(!v.allows_proceeding());
        assert!(!v.check_failed());
    }

    #[test]
    fn matching_is_case_insensitive_and_whitespace_tolerant() {
        let q = BreachQuery::from_password(PW);
        let lower = PW_SUFFIX.to_lowercase();
        let body = format!("  {lower} : 3  \n");
        // "suffix : count" with spaces around the colon
        assert_eq!(
            evaluate_breach_response(&q, BreachResponse::Body(&body), true),
            BreachVerdict::Breached { count: 3 }
        );
    }

    #[test]
    fn bare_suffix_without_count_means_present() {
        let q = BreachQuery::from_password(PW);
        let body = format!("{PW_SUFFIX}\n");
        assert_eq!(
            evaluate_breach_response(&q, BreachResponse::Body(&body), true),
            BreachVerdict::Breached { count: 1 }
        );
    }

    #[test]
    fn non_matching_body_is_clean() {
        let q = BreachQuery::from_password(PW);
        let body = "0018A45C4D1DEF81644B54AB7F969B88D65:1\n011053FD0102E94D6AE2F8B83D76FAF94F6:2\n";
        let v = evaluate_breach_response(&q, BreachResponse::Body(body), true);
        assert_eq!(v, BreachVerdict::Clean);
        assert!(v.allows_proceeding());
    }

    #[test]
    fn empty_body_is_clean_not_an_outage() {
        // The server answers an empty body for an unseeded node or an absent prefix.
        let q = BreachQuery::from_password(PW);
        for fail_open in [true, false] {
            assert_eq!(
                evaluate_breach_response(&q, BreachResponse::Body(""), fail_open),
                BreachVerdict::Clean
            );
        }
    }

    #[test]
    fn zero_count_entry_is_padding_and_means_not_present() {
        let q = BreachQuery::from_password(PW);
        let body = format!("{PW_SUFFIX}:0\n");
        assert_eq!(
            evaluate_breach_response(&q, BreachResponse::Body(&body), true),
            BreachVerdict::Clean
        );
    }

    #[test]
    fn outage_fails_open_when_the_server_says_so() {
        let q = BreachQuery::from_password(PW);
        let v = evaluate_breach_response(&q, BreachResponse::Unavailable, true);
        assert_eq!(v, BreachVerdict::CheckFailedAllowed);
        assert!(v.allows_proceeding(), "fail_open=true must let the user continue");
        assert!(v.check_failed(), "and must say honestly that the check did not run");
    }

    #[test]
    fn outage_fails_closed_when_the_server_says_so() {
        let q = BreachQuery::from_password(PW);
        let v = evaluate_breach_response(&q, BreachResponse::Unavailable, false);
        assert_eq!(v, BreachVerdict::CheckFailedBlocked);
        assert!(!v.allows_proceeding(), "fail_open=false must block on outage");
        assert!(v.check_failed());
    }

    #[test]
    fn malformed_body_is_an_outage_not_clean() {
        let q = BreachQuery::from_password(PW);
        let html = "<html><body>Please log in to the wifi</body></html>";
        assert_eq!(
            evaluate_breach_response(&q, BreachResponse::Body(html), true),
            BreachVerdict::CheckFailedAllowed
        );
        assert_eq!(
            evaluate_breach_response(&q, BreachResponse::Body(html), false),
            BreachVerdict::CheckFailedBlocked
        );
    }

    #[test]
    fn one_malformed_line_taints_the_whole_answer() {
        let q = BreachQuery::from_password(PW);
        // A valid matching line followed by garbage: the answer is not trustworthy.
        let body = format!("{PW_SUFFIX}:5\nnot-a-suffix:1\n");
        assert_eq!(
            evaluate_breach_response(&q, BreachResponse::Body(&body), true),
            BreachVerdict::CheckFailedAllowed
        );
        // Non-numeric count.
        let body = format!("{PW_SUFFIX}:many\n");
        assert_eq!(
            evaluate_breach_response(&q, BreachResponse::Body(&body), false),
            BreachVerdict::CheckFailedBlocked
        );
        // Wrong suffix length.
        let body = "ABCDEF:1\n";
        assert_eq!(
            evaluate_breach_response(&q, BreachResponse::Body(body), true),
            BreachVerdict::CheckFailedAllowed
        );
    }

    #[test]
    fn not_required_allows_proceeding_and_is_not_a_failed_check() {
        let v = BreachVerdict::NotRequired;
        assert!(v.allows_proceeding());
        assert!(!v.check_failed());
    }

    #[test]
    fn duplicate_matching_lines_keep_the_largest_count() {
        let q = BreachQuery::from_password(PW);
        let body = format!("{PW_SUFFIX}:2\n{PW_SUFFIX}:7\n");
        assert_eq!(
            evaluate_breach_response(&q, BreachResponse::Body(&body), true),
            BreachVerdict::Breached { count: 7 }
        );
    }
}
