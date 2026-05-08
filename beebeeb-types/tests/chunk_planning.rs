use beebeeb_types::{ChunkProfile, ChunkStrategy, STORAGE_FORMAT_VERSION_V2, plan_chunks};

const MIB: u64 = 1024 * 1024;
const GIB: u64 = 1024 * MIB;

#[test]
fn empty_file_uses_one_smallest_non_zero_chunk() {
    let plan = plan_chunks(0, ChunkProfile::BackupAgent);

    assert_eq!(plan.file_size_bytes, 0);
    assert_eq!(plan.chunk_size_bytes, 4 * MIB);
    assert_eq!(plan.chunk_count, 1);
    assert_eq!(plan.storage_format_version, STORAGE_FORMAT_VERSION_V2);
    assert_eq!(plan.strategy, ChunkStrategy::Dynamic);
}

#[test]
fn one_byte_file_uses_one_smallest_chunk() {
    let plan = plan_chunks(1, ChunkProfile::Desktop);

    assert_eq!(plan.chunk_size_bytes, 4 * MIB);
    assert_eq!(plan.chunk_count, 1);
}

#[test]
fn backup_profile_keeps_64_mib_boundary_on_4_mib_chunks() {
    let plan = plan_chunks(64 * MIB, ChunkProfile::BackupAgent);

    assert_eq!(plan.chunk_size_bytes, 4 * MIB);
    assert_eq!(plan.chunk_count, 16);
}

#[test]
fn backup_profile_moves_above_64_mib_to_8_mib_chunks() {
    let plan = plan_chunks((64 * MIB) + 1, ChunkProfile::BackupAgent);

    assert_eq!(plan.chunk_size_bytes, 8 * MIB);
    assert_eq!(plan.chunk_count, 9);
}

#[test]
fn backup_profile_keeps_1_gib_boundary_on_8_mib_chunks() {
    let plan = plan_chunks(GIB, ChunkProfile::BackupAgent);

    assert_eq!(plan.chunk_size_bytes, 8 * MIB);
    assert_eq!(plan.chunk_count, 128);
}

#[test]
fn backup_profile_keeps_10_gib_boundary_on_16_mib_chunks() {
    let plan = plan_chunks(10 * GIB, ChunkProfile::BackupAgent);

    assert_eq!(plan.chunk_size_bytes, 16 * MIB);
    assert_eq!(plan.chunk_count, 640);
}

#[test]
fn backup_profile_keeps_100_gib_boundary_on_64_mib_chunks() {
    let plan = plan_chunks(100 * GIB, ChunkProfile::BackupAgent);

    assert_eq!(plan.chunk_size_bytes, 64 * MIB);
    assert_eq!(plan.chunk_count, 1600);
}

#[test]
fn backup_profile_uses_256_mib_chunks_for_500_gib() {
    let plan = plan_chunks(500 * GIB, ChunkProfile::BackupAgent);

    assert_eq!(plan.chunk_size_bytes, 256 * MIB);
    assert_eq!(plan.chunk_count, 2000);
}

#[test]
fn web_profile_caps_large_files_at_64_mib_chunks() {
    let plan = plan_chunks(500 * GIB, ChunkProfile::Web);

    assert_eq!(plan.chunk_size_bytes, 64 * MIB);
    assert_eq!(plan.chunk_count, 8000);
    assert_eq!(
        plan.strategy,
        ChunkStrategy::Capped {
            max_chunk_size_bytes: 64 * MIB,
        }
    );
}

#[test]
fn mobile_profile_caps_large_files_at_16_mib_chunks() {
    let plan = plan_chunks(500 * GIB, ChunkProfile::Mobile);

    assert_eq!(plan.chunk_size_bytes, 16 * MIB);
    assert_eq!(plan.chunk_count, 32_000);
    assert_eq!(
        plan.strategy,
        ChunkStrategy::Capped {
            max_chunk_size_bytes: 16 * MIB,
        }
    );
}
