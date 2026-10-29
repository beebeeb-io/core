//! When the user's download ceiling lets the next storage request start (task 2173, plan K1).
//!
//! Desktop already holds requests back instead of sleeping after each chunk, so that up to four
//! requests in flight average out to the same rate as the API path's post-chunk sleep. The formula
//! is desktop's (`src-tauri/src/direct_download.rs:194-199`), unchanged in value: `kbps` is KiB/s,
//! and `kbps == 0` means no ceiling at all ([`i64::MIN`], which every caller reads as "no wait").
//!
//! Pure arithmetic: no clock, no I/O.

/// When `wire_bytes` received since `start_ms` at `kbps` KiB/s may be followed by the next request.
/// `i64::MIN` means there is no ceiling.
pub fn paced_until_ms(start_ms: i64, wire_bytes: u64, kbps: u64) -> i64 {
    if kbps == 0 {
        return i64::MIN;
    }
    let ms = u128::from(wire_bytes) * 1000 / (u128::from(kbps) * 1024);
    start_ms.saturating_add(i64::try_from(ms).unwrap_or(i64::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The rows desktop's own pacing test uses, copied with their source line
    /// (`desktop/src-tauri/src/direct_download.rs:1538-1544`), plus two extra rows.
    #[test]
    fn pacing_matches_the_formula_it_replaces() {
        assert_eq!(paced_until_ms(1_000, 0, 8), 1_000, "no bytes received yet: no wait");
        assert_eq!(
            paced_until_ms(1_000, 8 * 1024, 8),
            2_000,
            "8 KiB at 8 KiB/s is one second"
        );
        assert_eq!(
            paced_until_ms(0, u64::MAX, 1),
            i64::try_from(u128::from(u64::MAX) * 1000 / 1024).unwrap_or(i64::MAX),
            "the largest count saturates instead of wrapping"
        );
        assert_eq!(
            paced_until_ms(1_800_000_000_000, 4 * 1024 * 1024 + 28, 1000),
            1_800_000_004_096,
            "a 4 MiB chunk at 1000 KiB/s"
        );
        assert_eq!(paced_until_ms(500, 1, 1), 500, "less than a millisecond is no wait");
    }

    #[test]
    fn no_limit_means_no_wait() {
        assert_eq!(paced_until_ms(1_000, 10_000, 0), i64::MIN, "no ceiling");
        assert_eq!(paced_until_ms(0, u64::MAX, 0), i64::MIN, "a zero ceiling never waits");
    }
}
