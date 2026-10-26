//! The time bounds every client applies to a direct transfer (task 2173, clients plan A2).
//!
//! Each client keeps its own HTTP stack but not its own idea of "how long": the timers below are the
//! ones the clients design (6.2) fixes, and the two totals are one formula, so the CLI, the desktop,
//! the web and iOS cannot drift apart on how long a chunk may take.
//!
//! * A storage request is bounded by a connect timeout, by an idle timeout for a GET only (a PUT has
//!   none: a slow uplink is still sending, and an idle timer that the body upload does not reset
//!   would cut it off), and by a **total** that grows with the chunk.
//! * The total is `60 s + ceil(len / 131072) s` over the **ciphertext** length: a minute plus the
//!   chunk at 1 Mbit/s. It must stay under the server's late-write fence for a PUT
//!   (`max(300 s, ceil(len * 8 / min_uplink) + 60 s)`, server `direct_transfer.rs:434-437`), so that a
//!   client always gives up before the server could still accept its bytes; a test checks that for
//!   every length up to the largest chunk, using the server's numbers recorded in
//!   `test-vectors/direct_upload.json` (`constants`).
//!
//! Pure data and arithmetic: no clock, no I/O.

use std::time::Duration;

/// Opening a connection to storage.
pub const STORAGE_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// A storage GET with no byte for this long is cut. There is no PUT equivalent.
pub const STORAGE_GET_IDLE: Duration = Duration::from_secs(30);

/// The discovery call (`GET /api/v1/transfer/capabilities`).
pub const DISCOVERY_TIMEOUT: Duration = Duration::from_secs(15);

/// A grant or commit call to the API.
pub const API_CALL_TIMEOUT: Duration = Duration::from_secs(60);

/// A background session's resource timeout for a storage PUT (iOS). No app timer runs in the
/// background, and the timer starts at `resume()`, which may be as late as the link's expiry, so it
/// must stay under the server's allowance floor (300 s) by a minute: `expiry + 240 s < expiry + 300 s`.
pub const BACKGROUND_PUT_RESOURCE_TIMEOUT: Duration = Duration::from_secs(240);

/// The part of a storage total that does not depend on the chunk.
pub const STORAGE_TOTAL_BASE: Duration = Duration::from_secs(60);

/// The rate a storage total allows for the chunk itself: 131072 bytes per second, 1 Mbit/s.
pub const STORAGE_TOTAL_BYTES_PER_SECOND: u64 = 131_072;

/// The most a storage PUT of `len` ciphertext bytes may take, in all: `60 s + ceil(len / 131072) s`.
/// Any length is safe to pass: a huge one is a long timeout, never an overflow.
pub fn storage_put_total(len: u64) -> Duration {
    STORAGE_TOTAL_BASE + Duration::from_secs(len.div_ceil(STORAGE_TOTAL_BYTES_PER_SECOND))
}

/// The most a storage GET of `len` ciphertext bytes may take, in all (the same formula as a PUT).
pub fn storage_get_total(len: u64) -> Duration {
    storage_put_total(len)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    const MIB: u64 = 1024 * 1024;

    fn constants() -> serde_json::Value {
        let v: serde_json::Value =
            serde_json::from_str(include_str!("../../../test-vectors/direct_upload.json")).unwrap();
        v["constants"].clone()
    }

    fn secs(d: Duration) -> u64 {
        assert_eq!(d.subsec_nanos(), 0, "a whole number of seconds");
        d.as_secs()
    }

    #[test]
    fn the_put_total_is_a_minute_plus_the_chunk_at_one_mebibit() {
        assert_eq!(secs(storage_put_total(0)), 60);
        assert_eq!(secs(storage_put_total(131_072)), 61);
        assert_eq!(secs(storage_put_total(131_073)), 62, "a started second counts");
        assert_eq!(secs(storage_put_total(4 * MIB + 28)), 93, "a 4 MiB chunk");
        assert_eq!(secs(storage_put_total(256 * MIB + 28)), 2109, "the largest chunk");
    }

    #[test]
    fn the_get_total_is_the_same_formula() {
        for len in [0, 1, 131_072, 131_073, 4 * MIB + 28, 256 * MIB + 28] {
            assert_eq!(storage_get_total(len), storage_put_total(len), "len {len}");
        }
        assert_eq!(secs(storage_get_total(4 * MIB + 28)), 93);
    }

    #[test]
    fn no_length_can_overflow_or_panic() {
        // A hostile or buggy length is a long timeout, never a panic and never a wrap to a short one.
        assert!(storage_put_total(u64::MAX) > storage_put_total(256 * MIB + 28));
        assert!(storage_get_total(u64::MAX) > storage_get_total(256 * MIB + 28));
    }

    /// The server's late-write fence for a PUT of `len` bytes: `max(floor, ceil(len * 8 / min_uplink) + 60)`,
    /// computed from the recorded server numbers the way the server does (`put_allowance_secs`).
    fn fence_secs(len: u64) -> u128 {
        let c = constants();
        let floor = u128::from(c["put_allowance_floor_seconds"].as_u64().unwrap());
        let max = u128::from(c["max_ciphertext_chunk_bytes"].as_u64().unwrap());
        let lease = u128::from(c["upload_lease_seconds"].as_u64().unwrap());
        let min_uplink = (max * 8).div_ceil(lease);
        (u128::from(len) * 8).div_ceil(min_uplink).saturating_add(60).max(floor)
    }

    #[test]
    fn a_put_never_outlives_the_server_fence_for_any_chunk_length() {
        let max = constants()["max_ciphertext_chunk_bytes"].as_u64().unwrap();
        assert_eq!(
            max,
            256 * MIB + 28,
            "the recorded largest chunk is a 256 MiB plaintext stride plus the AEAD overhead"
        );

        let mut lens: Vec<u64> = vec![28, 4 * MIB + 28, max];
        // Every power of two (plus the overhead) up to the largest chunk.
        lens.extend((0..=28).map(|k| (1u64 << k) + 28).filter(|l| *l <= max));
        // The speed test's sizes (task 2201).
        lens.extend([1_000_000, 5_000_000, 10_000_000, 20_000_000]);
        // 4096 evenly spaced lengths over the whole range.
        lens.extend((0..4096u64).map(|i| 28 + i * (max - 28) / 4095));
        assert!(lens.len() >= 4096 + 30);

        for len in lens {
            let total = u128::from(storage_put_total(len).as_secs());
            assert!(
                total <= fence_secs(len),
                "a PUT of {len} bytes may run {total} s but the server fences it after {} s",
                fence_secs(len)
            );
        }
    }

    #[test]
    fn the_fence_this_test_computes_is_the_servers_number() {
        // Pins the test's own instrument: the server's tests assert these (server 30c8ed62, direct_transfer.rs
        // `the_put_fence_covers_a_large_chunk_at_the_minimum_uplink`: the floor for a 44-byte chunk, more than the
        // floor for the largest).
        assert_eq!(fence_secs(44), 300, "the floor");
        assert!(
            fence_secs(256 * MIB + 28) > 3600,
            "the largest chunk is fenced for about its whole lease"
        );
        assert!(fence_secs(256 * MIB + 28) <= 3660);
    }

    #[test]
    fn a_background_put_ends_before_the_fence_from_any_start_up_to_link_expiry() {
        // No app timer runs in the background, so the session's resource timeout is the only bound, and it
        // starts at `resume()`, which may be as late as the link's expiry (clients design, 9.3, review BL1).
        let floor = constants()["put_allowance_floor_seconds"].as_u64().unwrap();
        assert!(
            BACKGROUND_PUT_RESOURCE_TIMEOUT.as_secs() <= floor - 60,
            "{} s against a floor of {floor} s",
            BACKGROUND_PUT_RESOURCE_TIMEOUT.as_secs()
        );
    }

    #[test]
    fn the_timeouts_equal_the_vector_file() {
        let c = constants();
        let get = |k: &str| c[k].as_u64().unwrap_or_else(|| panic!("constants.{k}"));
        assert_eq!(
            STORAGE_CONNECT_TIMEOUT.as_secs(),
            get("storage_connect_timeout_seconds")
        );
        assert_eq!(STORAGE_GET_IDLE.as_secs(), get("storage_get_idle_seconds"));
        assert_eq!(DISCOVERY_TIMEOUT.as_secs(), get("discovery_timeout_seconds"));
        assert_eq!(API_CALL_TIMEOUT.as_secs(), get("api_call_timeout_seconds"));
        assert_eq!(
            BACKGROUND_PUT_RESOURCE_TIMEOUT.as_secs(),
            get("background_put_resource_timeout_seconds")
        );
        assert_eq!(STORAGE_TOTAL_BASE.as_secs(), get("storage_total_base_seconds"));
        assert_eq!(STORAGE_TOTAL_BYTES_PER_SECOND, get("storage_total_bytes_per_second"));
        // The server numbers carry their source lines, like the constants beside them.
        for key in [
            "url_ttl_seconds_source",
            "put_allowance_floor_seconds_source",
            "upload_lease_seconds_source",
            "max_ciphertext_chunk_bytes_source",
        ] {
            assert!(c[key].as_str().is_some_and(|s| s.contains("server 30c8ed62")), "{key}");
        }
    }
}
