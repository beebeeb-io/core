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
//! A transport failure, a non-2xx status, an **empty** body, a body larger than
//! [`MAX_BODY_BYTES`], or a body that is not in the `SUFFIX:COUNT` format is an
//! *outage*, not "clean". With `fail_open = true` the verdict is
//! [`BreachVerdict::CheckFailedAllowed`]: the client proceeds but can say
//! honestly that the check did not run. With `fail_open = false` it is
//! [`BreachVerdict::CheckFailedBlocked`].
//!
//! Why an empty body is an outage (task 1744 review M2): the server route
//! answers `200` with an empty body when its node-local corpus is unseeded,
//! when the corpus read fails, and when the prefix is absent
//! (`routes/auth.rs::pwned_range` unwraps all three to an empty string). A
//! seeded corpus has hundreds of suffixes behind every prefix, so an empty
//! block means the corpus was not consulted, and reporting "clean" would tell
//! the user a check ran when it did not. Server follow-up: answer `503` for an
//! unseeded node so the outage is explicit rather than inferred.
//!
//! # Binding a verdict to its password
//!
//! [`BreachQuery`] / [`evaluate_breach_response`] give a verdict a UI can show.
//! The signup ceremony does **not** accept a bare verdict (it could be stale,
//! for a different password, or forged by a caller). It takes a
//! [`BreachCheck`]: the query plus the recorded response, which the ceremony
//! re-derives from the password it stores and evaluates itself with the
//! server's `fail_open`.
//!
//! # Hashing hygiene (task 1744 review L1)
//!
//! `sha1` 0.10 has no `zeroize` support, so the hasher's internal block buffer
//! (up to 63 bytes of the password) is freed unwiped. The digest and hex are
//! wiped. The password is already present in the caller's string and the FFI
//! copies, so this is accepted rather than worked around.
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

/// Largest response body core will read, in bytes. A real range block is tens
/// of KiB (a few hundred `SUFFIX:COUNT` lines); anything bigger is a hostile or
/// broken endpoint and counts as an outage. Clients should stop reading the
/// response at this many bytes rather than buffer an unbounded stream.
pub const MAX_BODY_BYTES: usize = 256 * 1024;

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

/// A breach check bound to the password it was computed for, with the
/// endpoint's recorded answer. This is what the signup ceremony accepts
/// (task 1744 review M1): the ceremony re-derives the digest from the password
/// it stores and refuses a check made for a different one, so a stale or
/// forged "clean" cannot satisfy the gate.
///
/// Flow: [`BreachCheck::new`], send [`prefix`](Self::prefix), then
/// [`record`](Self::record) what came back (or that the call failed).
pub struct BreachCheck {
    query: BreachQuery,
    recorded: Option<Recorded>,
}

/// Why [`BreachCheck::record`] refused an answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum BreachError {
    /// The prefix the client says it requested is not this password's prefix,
    /// so the body is the corpus block for some other password and would
    /// evaluate as "not present" (clean). Nothing is recorded.
    #[error("the breach lookup was made for a different prefix than this password's")]
    PrefixMismatch,
}

impl BreachError {
    /// Stable machine-readable code (same style as `CeremonyError::code`).
    pub fn code(&self) -> &'static str {
        match self {
            Self::PrefixMismatch => "breach_prefix_mismatch",
        }
    }
}

enum Recorded {
    Body(String),
    Unavailable,
}

impl BreachCheck {
    /// Hash `password` and split the digest. No answer is recorded yet.
    pub fn new(password: &str) -> Self {
        Self {
            query: BreachQuery::from_password(password),
            recorded: None,
        }
    }

    /// The 5 characters to send to the server (upper-case hex).
    pub fn prefix(&self) -> &str {
        self.query.prefix()
    }

    /// Record what the endpoint returned, replacing any earlier answer.
    /// `requested_prefix` is the prefix the client actually put in the request
    /// URL (or read the cached entry for). If it is not this password's prefix
    /// (compared case-insensitively) the answer is refused, any earlier answer
    /// is discarded, and nothing is recorded: a body for another prefix would
    /// otherwise evaluate as "not present". A body over [`MAX_BODY_BYTES`] is
    /// recorded as an outage and not retained.
    pub fn record(&mut self, requested_prefix: &str, response: BreachResponse<'_>) -> Result<(), BreachError> {
        if !requested_prefix.eq_ignore_ascii_case(self.query.prefix()) {
            self.recorded = None;
            return Err(BreachError::PrefixMismatch);
        }
        self.recorded = Some(match response {
            BreachResponse::Body(b) if b.len() <= MAX_BODY_BYTES => Recorded::Body(b.to_owned()),
            BreachResponse::Body(_) | BreachResponse::Unavailable => Recorded::Unavailable,
        });
        Ok(())
    }

    /// Whether an answer (including "the call failed") has been recorded.
    pub fn is_answered(&self) -> bool {
        self.recorded.is_some()
    }

    /// The verdict for the recorded answer, or `None` before [`record`](Self::record).
    pub fn verdict(&self, fail_open: bool) -> Option<BreachVerdict> {
        let response = match self.recorded.as_ref()? {
            Recorded::Body(b) => BreachResponse::Body(b),
            Recorded::Unavailable => BreachResponse::Unavailable,
        };
        Some(evaluate_breach_response(&self.query, response, fail_open))
    }

    /// Record `response` and return its verdict in one step (what the bindings'
    /// `evaluate` does, so the UI shows the verdict the ceremony will compute).
    pub fn record_and_evaluate(
        &mut self,
        requested_prefix: &str,
        response: BreachResponse<'_>,
        fail_open: bool,
    ) -> Result<BreachVerdict, BreachError> {
        self.record(requested_prefix, response)?;
        Ok(self.verdict(fail_open).unwrap_or(BreachVerdict::CheckFailedBlocked))
    }

    /// Whether this check was computed for exactly `password`.
    pub fn matches_password(&self, password: &str) -> bool {
        let other = BreachQuery::from_password(password);
        let mut diff =
            (self.query.prefix().len() ^ other.prefix().len()) | (self.query.suffix().len() ^ other.suffix().len());
        for (a, b) in self
            .query
            .prefix()
            .bytes()
            .zip(other.prefix().bytes())
            .chain(self.query.suffix().bytes().zip(other.suffix().bytes()))
        {
            diff |= usize::from(a ^ b);
        }
        diff == 0
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

    // A hostile endpoint must not make the client chew an unbounded body, and
    // an empty body is not an answer: the server returns one when its corpus is
    // missing or unreadable, and a seeded corpus never has an empty block.
    if body.len() > MAX_BODY_BYTES || body.trim().is_empty() {
        return outage;
    }

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
    fn empty_body_is_an_outage_not_clean() {
        // Task 1744 review M2. The server answers 200 with an EMPTY body when
        // its corpus is unseeded, when the SQLite read errors, and when the
        // prefix is absent (`routes/auth.rs::pwned_range` unwraps all three to
        // an empty string). A seeded corpus has hundreds of suffixes behind
        // every 5-hex prefix, so an empty body means the corpus was not
        // consulted. Reading it as "clean" would tell the user a check ran
        // when it did not, even under `fail_open = false`.
        let q = BreachQuery::from_password(PW);
        for body in ["", "\n", "  \r\n \t"] {
            assert_eq!(
                evaluate_breach_response(&q, BreachResponse::Body(body), true),
                BreachVerdict::CheckFailedAllowed,
                "{body:?}"
            );
            assert_eq!(
                evaluate_breach_response(&q, BreachResponse::Body(body), false),
                BreachVerdict::CheckFailedBlocked,
                "{body:?}"
            );
        }
    }

    #[test]
    fn oversized_body_is_an_outage_even_if_it_contains_the_match() {
        // Task 1744 review L2.
        let q = BreachQuery::from_password(PW);
        let line = "0018A45C4D1DEF81644B54AB7F969B88D65:1\n"; // 38 bytes
        let fits = line.repeat(MAX_BODY_BYTES / line.len());
        assert!(fits.len() <= MAX_BODY_BYTES);
        assert_eq!(
            evaluate_breach_response(&q, BreachResponse::Body(&fits), true),
            BreachVerdict::Clean,
            "a body at the cap is still read"
        );
        let too_big = format!("{fits}{PW_SUFFIX}:5\n{}", line.repeat(8));
        assert!(too_big.len() > MAX_BODY_BYTES);
        assert_eq!(
            evaluate_breach_response(&q, BreachResponse::Body(&too_big), true),
            BreachVerdict::CheckFailedAllowed
        );
        assert_eq!(
            evaluate_breach_response(&q, BreachResponse::Body(&too_big), false),
            BreachVerdict::CheckFailedBlocked
        );
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

    #[test]
    fn breach_check_is_bound_to_its_password() {
        let c = BreachCheck::new(PW);
        assert_eq!(c.prefix(), PW_PREFIX);
        assert!(c.matches_password(PW));
        assert!(!c.matches_password("passwore"));
        assert!(!c.matches_password(""));
        assert!(!c.matches_password("Password"));
    }

    #[test]
    fn breach_check_has_no_verdict_until_an_answer_is_recorded() {
        let mut c = BreachCheck::new(PW);
        assert!(!c.is_answered());
        assert_eq!(c.verdict(true), None);
        c.record(PW_PREFIX, BreachResponse::Unavailable).unwrap();
        assert!(c.is_answered());
        assert_eq!(c.verdict(true), Some(BreachVerdict::CheckFailedAllowed));
        assert_eq!(c.verdict(false), Some(BreachVerdict::CheckFailedBlocked));
        // The same recorded answer is re-evaluated under whichever fail_open is asked.
        let body = body_with(PW_SUFFIX, "4");
        let v = c
            .record_and_evaluate(PW_PREFIX, BreachResponse::Body(&body), false)
            .unwrap();
        assert_eq!(v, BreachVerdict::Breached { count: 4 });
        assert_eq!(c.verdict(true), Some(v), "the later answer replaced the earlier one");
    }

    #[test]
    fn breach_check_does_not_retain_an_oversized_body() {
        let mut c = BreachCheck::new(PW);
        let huge = format!("{PW_SUFFIX}:5\n{}", "x".repeat(MAX_BODY_BYTES));
        c.record(PW_PREFIX, BreachResponse::Body(&huge)).unwrap();
        assert_eq!(c.verdict(true), Some(BreachVerdict::CheckFailedAllowed));
        assert!(matches!(c.recorded, Some(Recorded::Unavailable)));
    }

    #[test]
    fn record_refuses_a_body_requested_for_another_prefix() {
        let mut c = BreachCheck::new(PW);
        // A block for a different prefix that does not contain our suffix would read as Clean.
        let other_block = body_with("0000000000000000000000000000000000A", "3");
        let err = c
            .record("ABCDE", BreachResponse::Body(&other_block))
            .expect_err("a mismatched prefix must be refused");
        assert_eq!(err, BreachError::PrefixMismatch);
        assert_eq!(err.code(), "breach_prefix_mismatch");
        assert!(!c.is_answered(), "nothing is recorded on a mismatch");
        assert_eq!(c.verdict(true), None);
        // An outage report for the wrong prefix is refused the same way.
        assert_eq!(
            c.record("ABCDE", BreachResponse::Unavailable),
            Err(BreachError::PrefixMismatch)
        );
        assert!(!c.is_answered());
        assert_eq!(
            c.record_and_evaluate("ABCDE", BreachResponse::Body(&other_block), true),
            Err(BreachError::PrefixMismatch)
        );
    }

    #[test]
    fn a_mismatch_clears_an_earlier_answer() {
        let mut c = BreachCheck::new(PW);
        c.record(PW_PREFIX, BreachResponse::Unavailable).unwrap();
        assert!(c.is_answered());
        assert!(c.record("00000", BreachResponse::Body("X:1")).is_err());
        assert!(!c.is_answered(), "a refused record leaves no stale answer behind");
    }

    #[test]
    fn record_accepts_the_matching_prefix_in_either_case() {
        let mut c = BreachCheck::new(PW);
        let body = body_with(PW_SUFFIX, "4");
        c.record(PW_PREFIX, BreachResponse::Body(&body)).unwrap();
        assert_eq!(c.verdict(true), Some(BreachVerdict::Breached { count: 4 }));
        let mut d = BreachCheck::new(PW);
        d.record(&PW_PREFIX.to_ascii_lowercase(), BreachResponse::Body(&body))
            .unwrap();
        assert_eq!(d.verdict(true), Some(BreachVerdict::Breached { count: 4 }));
    }
}
