use serde::{Deserialize, Serialize};

/// Storage metadata format used by the launch upload protocol.
pub const STORAGE_FORMAT_VERSION_V1: u16 = 1;

/// Storage metadata format used by dynamic chunk planning and object versions.
pub const STORAGE_FORMAT_VERSION_V2: u16 = 2;

const MIB: u64 = 1024 * 1024;
const GIB: u64 = 1024 * MIB;

const MIN_CHUNK_SIZE_BYTES: u64 = 4 * MIB;
const WEB_MAX_CHUNK_SIZE_BYTES: u64 = 64 * MIB;
const MOBILE_MAX_CHUNK_SIZE_BYTES: u64 = 64 * MIB;

/// Client/runtime profile used to choose memory-safe chunk sizes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChunkProfile {
    /// Interactive desktop client uploads.
    Desktop,
    /// Desktop backup agent uploads, including very large backup files.
    BackupAgent,
    /// Browser uploads, capped below the backup maximum for tab memory safety.
    Web,
    /// Mobile uploads, capped aggressively to avoid transient memory pressure.
    Mobile,
}

/// Strategy used by a [`ChunkPlan`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChunkStrategy {
    /// Uses the full dynamic storage-v2 chunk ladder.
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

/// Plan chunks for a file using the storage-v2 dynamic chunk-size ladder.
///
/// Thresholds are inclusive: a file exactly at a threshold remains in the
/// smaller chunk-size tier, and the next byte moves it to the next tier.
pub fn plan_chunks(file_size_bytes: u64, profile: ChunkProfile) -> ChunkPlan {
    let strategy = profile.strategy();
    let chunk_size_bytes = base_chunk_size(file_size_bytes).min(profile.max_chunk_size_bytes());
    let chunk_count = if file_size_bytes == 0 {
        1
    } else {
        file_size_bytes.div_ceil(chunk_size_bytes)
    };

    ChunkPlan {
        file_size_bytes,
        chunk_size_bytes,
        chunk_count,
        strategy,
        storage_format_version: STORAGE_FORMAT_VERSION_V2,
    }
}

impl ChunkProfile {
    const fn strategy(self) -> ChunkStrategy {
        match self {
            Self::Desktop | Self::BackupAgent => ChunkStrategy::Dynamic,
            Self::Web => ChunkStrategy::Capped {
                max_chunk_size_bytes: WEB_MAX_CHUNK_SIZE_BYTES,
            },
            Self::Mobile => ChunkStrategy::Capped {
                max_chunk_size_bytes: MOBILE_MAX_CHUNK_SIZE_BYTES,
            },
        }
    }

    const fn max_chunk_size_bytes(self) -> u64 {
        match self {
            Self::Desktop | Self::BackupAgent => 256 * MIB,
            Self::Web => WEB_MAX_CHUNK_SIZE_BYTES,
            Self::Mobile => MOBILE_MAX_CHUNK_SIZE_BYTES,
        }
    }
}

const fn base_chunk_size(file_size_bytes: u64) -> u64 {
    if file_size_bytes <= 64 * MIB {
        MIN_CHUNK_SIZE_BYTES
    } else if file_size_bytes <= GIB {
        8 * MIB
    } else if file_size_bytes <= 10 * GIB {
        16 * MIB
    } else if file_size_bytes <= 100 * GIB {
        64 * MIB
    } else {
        256 * MIB
    }
}
