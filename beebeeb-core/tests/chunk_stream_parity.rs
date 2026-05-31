//! Cross-path parity for the shared streaming primitive.
//!
//! Guards two invariants that the whole effort depends on:
//!
//! 1. `file_encrypt::encrypt_file_to_chunks` (the disk-to-disk path) produces
//!    EXACTLY the same chunk plan — chunk count and per-chunk plaintext /
//!    ciphertext sizes — as a direct `ChunkEncryptor` loop over the same bytes.
//!    Since `file_encrypt` now delegates to `ChunkEncryptor`, this fails the
//!    instant someone re-introduces a hand-rolled chunk loop that drifts.
//! 2. Output written by the new primitive decrypts with the pre-existing
//!    low-level `encrypt::decrypt_chunk_raw` — i.e. the wire format is unchanged.

use std::io::Cursor;

use beebeeb_core::chunk_stream::ChunkEncryptor;
use beebeeb_core::encrypt::decrypt_chunk_raw;
use beebeeb_core::file_encrypt::encrypt_file_to_chunks;
use beebeeb_core::kdf::{derive_file_key, derive_master_key};
use beebeeb_types::ChunkProfile;

const MIB: usize = 1024 * 1024;

fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

/// `(plaintext_size, ciphertext_size)` per chunk from a direct ChunkEncryptor.
fn direct_loop_sizes(
    master: &beebeeb_core::kdf::MasterKey,
    file_id: &str,
    data: &[u8],
    profile: ChunkProfile,
) -> (u32, Vec<(u64, u64)>) {
    let mut enc =
        ChunkEncryptor::from_reader(master, file_id, data.len() as u64, profile, Cursor::new(data.to_vec())).unwrap();
    let mut sizes = Vec::new();
    while let Some(c) = enc.next_chunk().unwrap() {
        let ct = c.data.len() as u64;
        sizes.push((ct - 28, ct));
    }
    let summary = enc.finish().unwrap();
    (summary.chunk_count, sizes)
}

#[test]
fn file_encrypt_matches_direct_chunk_encryptor_loop() {
    let master = derive_master_key("parity-pass", b"parity-salt-16by").unwrap();
    let file_id = "parity-file-001";
    let profile = ChunkProfile::Desktop;

    // 9 MiB -> Desktop 4 MiB chunks -> 3 chunks (4 + 4 + 1).
    let content = pattern(9 * MIB);

    let dir = std::env::temp_dir().join("beebeeb_chunk_stream_parity");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let input_path = dir.join("input.bin");
    std::fs::write(&input_path, &content).unwrap();
    let output_dir = dir.join("chunks");

    // Path A: disk-to-disk (delegates to ChunkEncryptor).
    let result = encrypt_file_to_chunks(&master, file_id, &input_path, &output_dir, profile, None).unwrap();
    let file_sizes: Vec<(u64, u64)> = result
        .chunks
        .iter()
        .map(|c| (c.plaintext_size, c.ciphertext_size))
        .collect();

    // Path B: direct in-memory ChunkEncryptor loop.
    let (direct_count, direct_sizes) = direct_loop_sizes(&master, file_id, &content, profile);

    // Identical plan: count + per-chunk plaintext/ciphertext sizes.
    assert_eq!(result.chunks.len() as u32, direct_count);
    assert_eq!(file_sizes, direct_sizes);
    assert_eq!(result.total_plaintext_bytes, content.len() as u64);
    assert_eq!(
        result.total_ciphertext_bytes,
        content.len() as u64 + 28 * direct_count as u64
    );

    // The on-disk frames decrypt with the legacy low-level function.
    let file_key = derive_file_key(&master, file_id.as_bytes());
    let mut recovered = Vec::new();
    for chunk in &result.chunks {
        let raw = std::fs::read(&chunk.output_path).unwrap();
        recovered.extend_from_slice(&decrypt_chunk_raw(&file_key, &raw).unwrap());
    }
    assert_eq!(recovered, content);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn file_encrypt_empty_file_parity() {
    let master = derive_master_key("parity-empty", b"parity-salt-16by").unwrap();
    let file_id = "parity-empty-001";
    let profile = ChunkProfile::Desktop;

    let dir = std::env::temp_dir().join("beebeeb_chunk_stream_parity_empty");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let input_path = dir.join("empty.bin");
    std::fs::write(&input_path, b"").unwrap();
    let output_dir = dir.join("chunks");

    let result = encrypt_file_to_chunks(&master, file_id, &input_path, &output_dir, profile, None).unwrap();
    let (direct_count, direct_sizes) = direct_loop_sizes(&master, file_id, &[], profile);

    assert_eq!(result.chunks.len(), 1);
    assert_eq!(result.chunks.len() as u32, direct_count);
    assert_eq!(direct_sizes, vec![(0, 28)]);
    assert_eq!(result.chunks[0].ciphertext_size, 28);

    // Decrypt-back via the legacy path yields empty plaintext.
    let file_key = derive_file_key(&master, file_id.as_bytes());
    let raw = std::fs::read(&result.chunks[0].output_path).unwrap();
    assert!(decrypt_chunk_raw(&file_key, &raw).unwrap().is_empty());

    let _ = std::fs::remove_dir_all(&dir);
}
