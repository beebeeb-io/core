//! Shared bounds for values supplied by a server, file, binding or caller.
//!
//! Limits that protect optional work, such as archive preview, may decline the
//! work on constrained platforms. Limits used while opening or uploading the
//! user's files must accept every valid storage-format value in the main app.

/// One mebibyte.
pub const MIB: u64 = 1024 * 1024;

/// Largest accepted aggregate response-header bytes.
pub const MAX_RESPONSE_HEADER_BYTES: usize = 16 * 1024;
/// Largest error body inspected as JSON. Larger bodies are treated as text.
pub const MAX_SERVER_ERROR_BODY_BYTES: usize = 16 * 1024;
/// Largest displayable string derived from an untrusted response.
pub const MAX_DISPLAY_STRING_BYTES: usize = 512;
/// Largest ordinary JSON body buffered by a core service.
pub const MAX_JSON_BODY_BYTES: usize = MIB as usize;
/// Per-frame overhead for the storage format: nonce (12) plus tag (16).
pub const ENCRYPTED_FRAME_OVERHEAD_BYTES: u64 = 28;
/// Largest valid encrypted storage frame emitted by any chunk profile.
pub const MAX_ENCRYPTED_FRAME_BYTES: u64 =
    crate::ChunkProfile::BackupAgent.static_cap() + ENCRYPTED_FRAME_OVERHEAD_BYTES;
/// Largest valid chunk count for an account at the 99 TB entitlement ceiling,
/// including legacy V1 files whose fixed plaintext chunks were 1 MiB.
pub const MAX_CHUNK_COUNT: u32 = {
    let bytes = crate::quota::MAX_TOTAL_STORAGE as u64;
    let chunks = bytes / MIB + if bytes % MIB == 0 { 0 } else { 1 };
    chunks as u32
};
/// Allocation guard for helper APIs that materialise one entry per chunk.
/// The streaming download path uses [`MAX_CHUNK_COUNT`] instead.
pub const MAX_MATERIALIZED_CHUNK_COUNT: u32 = 1_000_000;
/// Largest search name, identifier or query in UTF-8 bytes.
pub const MAX_SEARCH_INPUT_BYTES: usize = 4 * 1024;
/// Search uses one layout in every binding.
pub const MAX_SEARCH_SHARDS: u32 = 64;
/// Largest encrypted search page.
pub const MAX_SEARCH_SHARD_BYTES: usize = 128 * 1024;
/// Largest local or remote search manifest.
pub const MAX_SEARCH_MANIFEST_ENTRIES: usize = 65_536;
/// Largest decimal precision supported by the compact formatter.
pub const MAX_FORMAT_PRECISION: usize = 2;
/// A server cannot suspend a client for more than five minutes.
pub const MAX_RETRY_AFTER_SECONDS: u64 = 5 * 60;
/// Longest accepted queue before a producer must apply backpressure.
pub const MAX_QUEUE_LENGTH: usize = 10_000;
/// Largest list accepted at an FFI boundary.
pub const MAX_FFI_LIST_LENGTH: usize = 100_000;
/// Highest non-negative millisecond timestamp accepted from JSON/FFI.
pub const MAX_TIMESTAMP_MS: u64 = i64::MAX as u64;

/// Resource policy for one operation.
///
/// `download_frame_bytes` may be smaller than the storage format only for a
/// constrained extension, where the caller can hand work to the main app. The
/// main-app/browser/native presets accept the full format. Archive output is
/// optional preview work and may be refused. File publication has no size cap
/// by default; callers may opt into `temp_disk_bytes` for disposable caches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryBudget {
    pub download_frame_bytes: u64,
    pub archive_output_bytes: u64,
    pub temp_disk_bytes: Option<u64>,
    pub queue_length: usize,
    pub ffi_list_length: usize,
}

impl MemoryBudget {
    pub const NATIVE: Self = Self::new(MAX_ENCRYPTED_FRAME_BYTES, 256 * MIB);
    pub const BROWSER: Self = Self::new(MAX_ENCRYPTED_FRAME_BYTES, 64 * MIB);
    pub const MOBILE_APP: Self = Self::new(MAX_ENCRYPTED_FRAME_BYTES, 32 * MIB);
    pub const MOBILE_EXTENSION: Self = Self::new(4 * MIB + ENCRYPTED_FRAME_OVERHEAD_BYTES, 8 * MIB);

    pub const fn new(download_frame_bytes: u64, archive_output_bytes: u64) -> Self {
        Self {
            download_frame_bytes,
            archive_output_bytes,
            temp_disk_bytes: None,
            queue_length: MAX_QUEUE_LENGTH,
            ffi_list_length: MAX_FFI_LIST_LENGTH,
        }
    }

    /// Add an explicit output-size limit for optional cache publication.
    /// Never use this to gate opening or uploading the user's own files.
    pub const fn with_temp_disk_limit(mut self, bytes: u64) -> Self {
        self.temp_disk_bytes = Some(bytes);
        self
    }

    /// Match the stable codes of core's existing `MemoryClass`.
    pub const fn for_class_code(code: &str) -> Option<Self> {
        match code.as_bytes() {
            b"native" => Some(Self::NATIVE),
            b"browser" => Some(Self::BROWSER),
            b"mobile_app" => Some(Self::MOBILE_APP),
            b"mobile_extension" => Some(Self::MOBILE_EXTENSION),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn platform_budgets_keep_main_apps_format_complete() {
        for code in ["native", "browser", "mobile_app"] {
            assert_eq!(
                MemoryBudget::for_class_code(code).unwrap().download_frame_bytes,
                MAX_ENCRYPTED_FRAME_BYTES
            );
        }
        let extension = MemoryBudget::for_class_code(std::hint::black_box("mobile_extension")).unwrap();
        assert!(extension.download_frame_bytes < MAX_ENCRYPTED_FRAME_BYTES);
        assert_eq!(
            MemoryBudget::for_class_code("mobile_extension"),
            Some(MemoryBudget::MOBILE_EXTENSION)
        );
    }

    #[test]
    fn main_app_disk_budget_does_not_refuse_a_large_valid_file() {
        assert_eq!(MemoryBudget::MOBILE_APP.temp_disk_bytes, None);
        assert_eq!(MemoryBudget::BROWSER.temp_disk_bytes, None);
        assert_eq!(MemoryBudget::NATIVE.temp_disk_bytes, None);
        assert_eq!(MemoryBudget::MOBILE_EXTENSION.temp_disk_bytes, None);
        assert_eq!(
            MemoryBudget::MOBILE_APP.with_temp_disk_limit(513 * MIB).temp_disk_bytes,
            Some(513 * MIB)
        );
    }

    #[test]
    fn chunk_count_limit_accepts_the_largest_mobile_plan() {
        let plan = crate::plan_chunks(crate::quota::MAX_TOTAL_STORAGE as u64, crate::ChunkProfile::Mobile);
        assert!(
            plan.chunk_count <= u64::from(MAX_CHUNK_COUNT),
            "{} valid chunks exceeds {}",
            plan.chunk_count,
            MAX_CHUNK_COUNT
        );
    }
}
