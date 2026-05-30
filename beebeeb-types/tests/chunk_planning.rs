//! Cross-client chunk-planning vector test (N=32 ladder, task 0661).
//!
//! The ladder is pure integer math single-sourced in `beebeeb-types::chunk`, so
//! these vectors hold identically in Rust, WASM (`beebeeb-wasm::plan_chunks`),
//! and UniFFI (`beebeeb-uniffi::plan_chunks`). The server's
//! `infer_v2_chunk_size_bytes` must accept every `(chunk_size, chunk_count)`
//! pair produced here.

use beebeeb_types::{
    ChunkProfile, ChunkStrategy, STORAGE_FORMAT_VERSION_V2, base_chunk_size, effective_cap,
    max_plaintext_chunk_bytes, plan_chunks, plan_chunks_concurrent,
};

const MIB: u64 = 1024 * 1024;
const GIB: u64 = 1024 * MIB;

// ── Canonical N=32 ladder via the 256-cap (BackupAgent) path ────────────────
// (file_size, expected_chunk_size, expected_chunk_count)
const LADDER_VECTORS: &[(u64, u64, u64)] = &[
    (0, 4 * MIB, 1),
    (1, 4 * MIB, 1),
    (4 * MIB, 4 * MIB, 1),
    (64 * MIB, 4 * MIB, 16),
    (128 * MIB, 4 * MIB, 32),       // ≤128 MiB stays on 4 MiB
    (256 * MIB, 8 * MIB, 32),       // >128 MiB → 8 MiB
    (512 * MIB, 16 * MIB, 32),      // >256 MiB → 16 MiB
    (2 * GIB, 64 * MIB, 32),        // >1 GiB → 64 MiB
    (4 * GIB, 128 * MIB, 32),       // >2 GiB → 128 MiB
    (8 * GIB, 256 * MIB, 32),       // >4 GiB → 256 MiB (clamp)
    (4 * GIB + 1, 256 * MIB, 17),   // just past 4 GiB → sawtooth floor 17
    (100 * GIB, 256 * MIB, 400),
    (100 * GIB + 1, 256 * MIB, 401),
    (u64::MAX, 256 * MIB, 68_719_476_736),
];

#[test]
fn n32_ladder_vectors_hold_for_backup_profile() {
    for &(size, want_chunk, want_count) in LADDER_VECTORS {
        let plan = plan_chunks(size, ChunkProfile::BackupAgent);
        assert_eq!(
            (plan.chunk_size_bytes, plan.chunk_count),
            (want_chunk, want_count),
            "BackupAgent size={size}"
        );
        assert_eq!(plan.file_size_bytes, size);
        assert_eq!(plan.storage_format_version, STORAGE_FORMAT_VERSION_V2);
        // base_chunk_size (profile-independent) drives the size up to the cap.
        assert_eq!(base_chunk_size(size).min(256 * MIB), want_chunk, "base size={size}");
    }
}

#[test]
fn zero_and_one_byte_are_single_4mib_chunks() {
    for profile in [
        ChunkProfile::BackupAgent,
        ChunkProfile::Desktop,
        ChunkProfile::Cli,
        ChunkProfile::Web,
        ChunkProfile::Mobile,
    ] {
        for size in [0u64, 1] {
            let plan = plan_chunks(size, profile);
            assert_eq!(plan.chunk_size_bytes, 4 * MIB, "{profile:?} size={size}");
            assert_eq!(plan.chunk_count, 1, "{profile:?} size={size}");
        }
    }
}

#[test]
fn static_caps_per_profile() {
    // 8 GiB base size is 256 MiB; each profile clamps to its static cap.
    let cases = [
        (ChunkProfile::BackupAgent, 256 * MIB, 32),
        (ChunkProfile::Desktop, 128 * MIB, 64),
        (ChunkProfile::Cli, 128 * MIB, 64),
        (ChunkProfile::Web, 32 * MIB, 256),
        (ChunkProfile::Mobile, 32 * MIB, 256),
    ];
    for (profile, want_chunk, want_count) in cases {
        let plan = plan_chunks(8 * GIB, profile);
        assert_eq!(
            (plan.chunk_size_bytes, plan.chunk_count),
            (want_chunk, want_count),
            "{profile:?} @ 8 GiB"
        );
    }
}

#[test]
fn strategy_is_dynamic_only_at_the_256_mib_max() {
    // Cap actively binding (below 256) → Capped; at the 256 max → Dynamic.
    assert_eq!(plan_chunks(8 * GIB, ChunkProfile::BackupAgent).strategy, ChunkStrategy::Dynamic);
    assert_eq!(
        plan_chunks(8 * GIB, ChunkProfile::Cli).strategy,
        ChunkStrategy::Capped { max_chunk_size_bytes: 128 * MIB }
    );
    assert_eq!(
        plan_chunks(8 * GIB, ChunkProfile::Web).strategy,
        ChunkStrategy::Capped { max_chunk_size_bytes: 32 * MIB }
    );
}

#[test]
fn effective_cap_shrinks_with_concurrency() {
    // Budget cap = pow2_floor(2 GiB / (conc × 5)): 256, 128, 64, 32 MiB.
    assert_eq!(effective_cap(ChunkProfile::BackupAgent, 1), 256 * MIB);
    assert_eq!(effective_cap(ChunkProfile::BackupAgent, 2), 128 * MIB);
    assert_eq!(effective_cap(ChunkProfile::BackupAgent, 4), 64 * MIB);
    assert_eq!(effective_cap(ChunkProfile::BackupAgent, 8), 32 * MIB);

    // Cli static cap (128) bounds conc=1/2; the budget bounds conc≥4.
    assert_eq!(effective_cap(ChunkProfile::Cli, 1), 128 * MIB);
    assert_eq!(effective_cap(ChunkProfile::Cli, 2), 128 * MIB);
    assert_eq!(effective_cap(ChunkProfile::Cli, 4), 64 * MIB); // bb sync default
    assert_eq!(effective_cap(ChunkProfile::Cli, 8), 32 * MIB);

    // concurrency 0 is treated as 1.
    assert_eq!(effective_cap(ChunkProfile::Cli, 0), effective_cap(ChunkProfile::Cli, 1));
}

#[test]
fn concurrent_planning_applies_the_effective_cap() {
    // 8 GiB (base 256 MiB) under the CLI at various concurrencies.
    assert_eq!(plan_chunks_concurrent(8 * GIB, ChunkProfile::Cli, 1).chunk_size_bytes, 128 * MIB);
    assert_eq!(plan_chunks_concurrent(8 * GIB, ChunkProfile::Cli, 4).chunk_size_bytes, 64 * MIB);
    assert_eq!(plan_chunks_concurrent(8 * GIB, ChunkProfile::Cli, 8).chunk_size_bytes, 32 * MIB);
    // bb push (conc=1) on BackupAgent reaches the full 256 MiB rung.
    assert_eq!(plan_chunks_concurrent(8 * GIB, ChunkProfile::BackupAgent, 1).chunk_size_bytes, 256 * MIB);
    // conc=1 is identical to the static plan.
    assert_eq!(
        plan_chunks_concurrent(8 * GIB, ChunkProfile::Web, 1).chunk_size_bytes,
        plan_chunks(8 * GIB, ChunkProfile::Web).chunk_size_bytes
    );
}

#[test]
fn max_plaintext_chunk_bytes_tracks_backup_profile() {
    for &(size, _, _) in LADDER_VECTORS {
        assert_eq!(
            max_plaintext_chunk_bytes(size),
            plan_chunks(size, ChunkProfile::BackupAgent).chunk_size_bytes,
            "size={size}"
        );
    }
    // Never exceeds the 256 MiB ladder ceiling (the server body limit).
    assert_eq!(max_plaintext_chunk_bytes(u64::MAX), 256 * MIB);
}
