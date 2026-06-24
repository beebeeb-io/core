use serde::{Deserialize, Serialize};

/// Storage metadata format used by the launch upload protocol.
///
/// V1 used a fixed 1 MiB chunk size and is superseded by V2 (dynamic ladder).
/// This constant is retained for historical reference and legacy-file detection
/// but is no longer produced by any new upload path. All new uploads use
/// [`STORAGE_FORMAT_VERSION_V2`].
#[allow(dead_code)]
pub const STORAGE_FORMAT_VERSION_V1: u16 = 1;

/// Storage metadata format used by dynamic chunk planning and object versions.
pub const STORAGE_FORMAT_VERSION_V2: u16 = 2;

const MIB: u64 = 1024 * 1024;
const GIB: u64 = 1024 * MIB;

/// Plaintext chunk-size floor. Every profile uses at least this.
const MIN_CHUNK_SIZE_BYTES: u64 = 4 * MIB;
/// Plaintext ceiling for the dynamic ladder — BackupAgent's static cap and the
/// most permissive value any profile can emit.
const MAX_CHUNK_SIZE_BYTES: u64 = 256 * MIB;

/// Target number of chunks the dynamic ladder aims for: each chunk is
/// ~`file_size / N` rounded up to a power of two, clamped to `[MIN, MAX]`. N
/// decides *where* rungs engage (the concurrency-aware cap decides *whether*
/// the larger rungs are reachable).
const TARGET_CHUNK_COUNT: u64 = 32;

// ── Per-profile static caps ────────────────────────────────────────────────
const BACKUP_MAX_CHUNK_SIZE_BYTES: u64 = 256 * MIB;
const DESKTOP_MAX_CHUNK_SIZE_BYTES: u64 = 128 * MIB;
const CLI_MAX_CHUNK_SIZE_BYTES: u64 = 128 * MIB;
const WEB_MAX_CHUNK_SIZE_BYTES: u64 = 32 * MIB;
const MOBILE_MAX_CHUNK_SIZE_BYTES: u64 = 32 * MIB;

/// Memory budget governing the concurrency-aware cap: the sum of in-flight
/// cipher buffers across all parallel chunk streams should stay within this,
/// assuming a ~5× transient-buffer multiplier per stream. At `concurrency = c`
/// the per-stream cap is `pow2_floor(BUDGET / (c × MULTIPLIER))`.
const CONCURRENCY_MEMORY_BUDGET_BYTES: u64 = 2 * GIB;
const CONCURRENCY_BUFFER_MULTIPLIER: u64 = 5;

/// Client/runtime profile used to choose memory-safe chunk sizes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChunkProfile {
    /// Interactive desktop GUI client uploads (128 MiB static cap).
    Desktop,
    /// `bb` command-line client uploads (128 MiB static cap). Distinct from
    /// Desktop so the two can diverge; both shrink under parallel `bb sync`.
    Cli,
    /// Desktop backup agent uploads, including very large backup files
    /// (256 MiB static cap — the most permissive profile).
    BackupAgent,
    /// Browser uploads, capped for tab memory safety (32 MiB static cap).
    Web,
    /// Mobile uploads, capped aggressively for low-end device memory (32 MiB).
    Mobile,
}

/// Strategy used by a [`ChunkPlan`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChunkStrategy {
    /// Uses the full dynamic storage-v2 chunk ladder (cap at the 256 MiB max).
    Dynamic,
    /// Uses the dynamic ladder but clamps the selected chunk size to this cap.
    Capped { max_chunk_size_bytes: u64 },
}

/// Deterministic chunk plan for one file upload/object version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChunkPlan {
    /// Original file size in bytes.
    pub file_size_bytes: u64,
    /// Plaintext bytes per chunk before encryption. The last chunk may be smaller.
    pub chunk_size_bytes: u64,
    /// Number of chunks to upload. Empty files still produce one empty chunk.
    pub chunk_count: u64,
    /// Profile-derived strategy used to produce the chunk size.
    pub strategy: ChunkStrategy,
    /// Storage metadata format version associated with this plan.
    pub storage_format_version: u16,
}

/// Overflow-safe ceiling division (avoids the `a + b - 1` overflow at `u64::MAX`).
const fn div_ceil_u64(a: u64, b: u64) -> u64 {
    a / b + if a % b != 0 { 1 } else { 0 }
}

/// Smallest power of two `>= n` (with `next_pow2(0) == 1`). Const + overflow-safe
/// for every value this module feeds it (`<= div_ceil(u64::MAX, 32) ≈ 2^59`).
const fn next_pow2(n: u64) -> u64 {
    if n <= 1 {
        return 1;
    }
    let bits = 64 - (n - 1).leading_zeros();
    1u64 << bits
}

/// Largest power of two `<= n` (with `pow2_floor(0) == 0`).
const fn pow2_floor(n: u64) -> u64 {
    if n == 0 {
        return 0;
    }
    1u64 << (63 - n.leading_zeros())
}

/// The base (profile-independent) plaintext chunk size for a file:
/// `clamp(next_pow2(file_size / N), MIN, MAX)`. Pure integer math, identical
/// across Rust / WASM / UniFFI.
pub const fn base_chunk_size(file_size_bytes: u64) -> u64 {
    let target = div_ceil_u64(file_size_bytes, TARGET_CHUNK_COUNT);
    let p2 = next_pow2(target);
    if p2 < MIN_CHUNK_SIZE_BYTES {
        MIN_CHUNK_SIZE_BYTES
    } else if p2 > MAX_CHUNK_SIZE_BYTES {
        MAX_CHUNK_SIZE_BYTES
    } else {
        p2
    }
}

impl ChunkProfile {
    /// The profile's static (concurrency-independent) plaintext chunk-size cap.
    pub const fn static_cap(self) -> u64 {
        match self {
            Self::Desktop => DESKTOP_MAX_CHUNK_SIZE_BYTES,
            Self::Cli => CLI_MAX_CHUNK_SIZE_BYTES,
            Self::BackupAgent => BACKUP_MAX_CHUNK_SIZE_BYTES,
            Self::Web => WEB_MAX_CHUNK_SIZE_BYTES,
            Self::Mobile => MOBILE_MAX_CHUNK_SIZE_BYTES,
        }
    }
}

/// The effective plaintext chunk-size cap at a given upload concurrency:
/// `min(static_cap(profile), pow2_floor(BUDGET / (concurrency × MULTIPLIER)))`.
///
/// Parallel uploads multiply peak memory, so the budget cap shrinks the chunk
/// size as concurrency rises (e.g. Cli: conc=1→128, conc=2→128, conc=4→64,
/// conc=8→32 MiB). `concurrency == 0` is treated as 1. Never drops below the
/// 4 MiB floor.
pub const fn effective_cap(profile: ChunkProfile, concurrency: u32) -> u64 {
    let c = if concurrency == 0 { 1 } else { concurrency as u64 };
    let budget = pow2_floor(CONCURRENCY_MEMORY_BUDGET_BYTES / (c * CONCURRENCY_BUFFER_MULTIPLIER));
    let budget = if budget < MIN_CHUNK_SIZE_BYTES {
        MIN_CHUNK_SIZE_BYTES
    } else {
        budget
    };
    let sc = profile.static_cap();
    if sc < budget { sc } else { budget }
}

/// Build a plan for `file_size_bytes` using `cap` as the chunk-size ceiling.
fn plan_with_cap(file_size_bytes: u64, cap: u64) -> ChunkPlan {
    let chunk_size_bytes = base_chunk_size(file_size_bytes).min(cap);
    let chunk_count = if file_size_bytes == 0 {
        1
    } else {
        file_size_bytes.div_ceil(chunk_size_bytes)
    };
    // Below the 256 MiB ladder max ⇒ the cap is actively constraining the size.
    let strategy = if cap >= MAX_CHUNK_SIZE_BYTES {
        ChunkStrategy::Dynamic
    } else {
        ChunkStrategy::Capped {
            max_chunk_size_bytes: cap,
        }
    };
    ChunkPlan {
        file_size_bytes,
        chunk_size_bytes,
        chunk_count,
        strategy,
        storage_format_version: STORAGE_FORMAT_VERSION_V2,
    }
}

/// Plan chunks for a file using the profile's **static** cap (concurrency-
/// agnostic). Used by web/mobile/server and any single-stream caller. Existing
/// call sites keep this signature unchanged.
pub fn plan_chunks(file_size_bytes: u64, profile: ChunkProfile) -> ChunkPlan {
    plan_with_cap(file_size_bytes, profile.static_cap())
}

/// Plan chunks accounting for the number of concurrent upload streams. The
/// chunk size is clamped to [`effective_cap`], which shrinks as `concurrency`
/// rises so parallel uploads stay within the memory budget. `concurrency == 1`
/// is identical to [`plan_chunks`].
pub fn plan_chunks_concurrent(file_size_bytes: u64, profile: ChunkProfile, concurrency: u32) -> ChunkPlan {
    plan_with_cap(file_size_bytes, effective_cap(profile, concurrency))
}

/// Largest *plaintext* chunk any client profile will emit for a file of
/// `file_size_bytes`. Single source of truth for the server's per-chunk body
/// limit (replaces the inline `plan_chunks(_, BackupAgent)` derivation in
/// `beebeeb-api/src/routes/files.rs`). `BackupAgent` is the most permissive
/// profile, so this never under-bounds a legitimate upload.
pub fn max_plaintext_chunk_bytes(file_size_bytes: u64) -> u64 {
    plan_chunks(file_size_bytes, ChunkProfile::BackupAgent).chunk_size_bytes
}
