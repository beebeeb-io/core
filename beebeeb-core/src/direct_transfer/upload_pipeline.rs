//! Bounded direct-upload scheduling (task 2173, option A).

/// Commit concurrency is chosen from the file's stride, including for a short final chunk.
pub const UPLOAD_COMMIT_SLOTS_SMALL: u32 = 2;
pub const UPLOAD_COMMIT_SLOTS_LARGE: u32 = 1;
pub const UPLOAD_COMMIT_SLOTS_SMALL_BELOW: u64 = 16 * 1024 * 1024;
/// Grants and storage PUTs share one lane per file.
pub const UPLOAD_PUT_LANES: u32 = 1;
pub const UPLOAD_FILE_CONCURRENCY_DEFAULT: u32 = 4;
pub const UPLOAD_FILE_CONCURRENCY_MAX: u32 = 8;
/// Files finishing commits and complete after releasing their PUT lane.
pub const UPLOAD_TAIL_FILES_MAX: u32 = 4;
/// The process-wide upload API pacer, on both transports.
pub const UPLOAD_API_REQUESTS_PER_SECOND_MAX: u32 = 60;
pub const UPLOAD_API_BURST: u32 = 20;

pub fn commit_slots(chunk_size_bytes: u64) -> u32 {
    if chunk_size_bytes < UPLOAD_COMMIT_SLOTS_SMALL_BELOW {
        UPLOAD_COMMIT_SLOTS_SMALL
    } else {
        UPLOAD_COMMIT_SLOTS_LARGE
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::direct_transfer::timeouts::{put_allowance, storage_put_total, storage_put_total_shared};
    use std::time::Duration;

    const MIB: u64 = 1024 * 1024;

    fn lengths() -> Vec<u64> {
        let max = 256 * MIB + 28;
        let mut lens = vec![0, 1, 28, 4 * MIB + 28, 32 * MIB + 28, max, u64::MAX];
        lens.extend((0..=28).map(|k| (1u64 << k) + 28).filter(|l| *l <= max));
        lens.extend([1_000_000, 5_000_000, 10_000_000, 20_000_000]);
        lens.extend((0..4096u64).map(|i| 28 + i * (max - 28) / 4095));
        assert_eq!(lens.len(), 4136);
        lens
    }

    #[test]
    fn commit_slots_is_two_below_sixteen_mib_and_one_from_it() {
        for len in [0, 4 * MIB, 16 * MIB - 1] {
            assert_eq!(commit_slots(len), 2, "{len}");
        }
        for len in [16 * MIB, 128 * MIB, u64::MAX] {
            assert_eq!(commit_slots(len), 1, "{len}");
        }
    }

    #[test]
    fn constants_equal_the_vector_file() {
        let v: serde_json::Value =
            serde_json::from_str(include_str!("../../../test-vectors/direct_upload_pipeline.json")).unwrap();
        let c = v["constants"].as_object().unwrap();
        let actual = [
            ("UPLOAD_COMMIT_SLOTS_SMALL", u64::from(UPLOAD_COMMIT_SLOTS_SMALL)),
            ("UPLOAD_COMMIT_SLOTS_LARGE", u64::from(UPLOAD_COMMIT_SLOTS_LARGE)),
            ("UPLOAD_COMMIT_SLOTS_SMALL_BELOW", UPLOAD_COMMIT_SLOTS_SMALL_BELOW),
            ("UPLOAD_PUT_LANES", u64::from(UPLOAD_PUT_LANES)),
            (
                "UPLOAD_FILE_CONCURRENCY_DEFAULT",
                u64::from(UPLOAD_FILE_CONCURRENCY_DEFAULT),
            ),
            ("UPLOAD_FILE_CONCURRENCY_MAX", u64::from(UPLOAD_FILE_CONCURRENCY_MAX)),
            ("UPLOAD_TAIL_FILES_MAX", u64::from(UPLOAD_TAIL_FILES_MAX)),
            (
                "UPLOAD_API_REQUESTS_PER_SECOND_MAX",
                u64::from(UPLOAD_API_REQUESTS_PER_SECOND_MAX),
            ),
            ("UPLOAD_API_BURST", u64::from(UPLOAD_API_BURST)),
        ];
        assert_eq!(c.len(), actual.len());
        for (name, value) in actual {
            assert_eq!(c[name].as_u64(), Some(value), "{name}");
        }
    }

    #[test]
    fn a_shared_put_total_never_exceeds_the_fence() {
        for len in lengths() {
            for k in 1..=8 {
                assert!(
                    storage_put_total_shared(len, k) <= put_allowance(len) - Duration::from_secs(30),
                    "len={len}, k={k}"
                );
            }
        }
    }

    #[test]
    fn with_one_put_in_flight_the_shared_total_is_the_single_put_total() {
        for len in lengths() {
            assert_eq!(storage_put_total_shared(len, 1), storage_put_total(len), "len={len}");
            assert_eq!(
                storage_put_total_shared(len, 0),
                storage_put_total(len),
                "zero in-flight, len={len}"
            );
        }
    }

    #[test]
    fn thirty_two_mib_gives_317_s_at_k1_and_480_s_at_k2() {
        let len = 32 * MIB + 28;
        assert_eq!(put_allowance(len).as_secs(), 510);
        assert_eq!(storage_put_total_shared(len, 1).as_secs(), 317);
        assert_eq!(storage_put_total_shared(len, 2).as_secs(), 480);
        assert!(storage_put_total_shared(u64::MAX, u32::MAX) <= put_allowance(u64::MAX) - Duration::from_secs(30));
    }
}
