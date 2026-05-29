//! Disk-to-disk file encryption and decryption.
//!
//! These functions read from disk chunk-by-chunk, encrypt/decrypt with
//! AES-256-GCM, and write back to disk. Peak memory usage: 2x chunk_size
//! (one plaintext buffer + one ciphertext buffer). No full-file copies.

use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};

use beebeeb_types::{ChunkProfile, plan_chunks};

use crate::chunk_stream::ChunkEncryptor;
use crate::encrypt::{NONCE_LEN, TAG_LEN, decrypt_chunk_raw};
use crate::kdf::{MasterKey, derive_file_key};
use crate::CoreError;

/// Information about a single encrypted chunk written to disk.
#[derive(Debug, Clone)]
pub struct EncryptedChunkInfo {
    /// Zero-based chunk index.
    pub chunk_index: u32,
    /// Path to the `.enc` file on disk.
    pub output_path: PathBuf,
    /// The 12-byte nonce used for this chunk's encryption.
    pub nonce: Vec<u8>,
    /// Plaintext size of this chunk (before encryption).
    pub plaintext_size: u64,
    /// Ciphertext size on disk (nonce + ciphertext + GCM tag).
    pub ciphertext_size: u64,
}

/// Result of encrypting a complete file.
#[derive(Debug, Clone)]
pub struct EncryptedFileResult {
    /// Info for each encrypted chunk, ordered by chunk index.
    pub chunks: Vec<EncryptedChunkInfo>,
    /// Total plaintext bytes read from the input file.
    pub total_plaintext_bytes: u64,
    /// Total ciphertext bytes written across all chunk files.
    pub total_ciphertext_bytes: u64,
    /// Chunk size used for splitting (plaintext bytes per chunk).
    pub chunk_size_bytes: u64,
}

/// Result of decrypting chunks back to a file.
#[derive(Debug, Clone)]
pub struct DecryptedFileResult {
    /// Path to the decrypted output file.
    pub output_path: PathBuf,
    /// Total plaintext bytes written.
    pub total_bytes: u64,
    /// Number of chunks processed.
    pub chunks_processed: u32,
}

/// Progress callback trait for file encryption/decryption operations.
pub trait FileProgressCallback: Send + Sync {
    /// Called after each chunk is processed.
    fn on_progress(&self, chunks_completed: u32, chunks_total: u32);
}

/// Encrypt a file from disk, writing each chunk as a separate `.enc` file.
///
/// Reads the input file chunk-by-chunk according to the chunk plan derived
/// from the file size and profile. Each chunk is encrypted with AES-256-GCM
/// using a fresh nonce, then written as `nonce || ciphertext` to
/// `{output_dir}/{chunk_index}.enc.tmp`, followed by an atomic rename to `.enc`.
///
/// Peak memory: 2x `chunk_size` (one read buffer + one ciphertext buffer).
pub fn encrypt_file_to_chunks(
    master_key: &MasterKey,
    file_id: &str,
    input_path: &Path,
    output_dir: &Path,
    profile: ChunkProfile,
    callback: Option<&dyn FileProgressCallback>,
) -> Result<EncryptedFileResult, CoreError> {
    // Stat the input file
    let metadata = fs::metadata(input_path)
        .map_err(|e| CoreError::Io(format!("stat input: {e}")))?;
    let file_size = metadata.len();

    // Ensure output directory exists
    fs::create_dir_all(output_dir)
        .map_err(|e| CoreError::Io(format!("create output dir: {e}")))?;

    // Open input file. The BufReader capacity is bounded to 8 MiB so a large
    // chunk size does not force a huge buffered-reader allocation; the streaming
    // primitive reads one chunk at a time regardless.
    let input_file = File::open(input_path)
        .map_err(|e| CoreError::Io(format!("open input: {e}")))?;
    let plan = plan_chunks(file_size, profile);
    let buf_cap = (plan.chunk_size_bytes as usize).min(8 * 1024 * 1024);
    let reader = BufReader::with_capacity(buf_cap, input_file);

    // Delegate the chunk loop to the shared streaming primitive so there is
    // exactly ONE chunk-encryption code path across every client. A parity test
    // (tests/chunk_stream_parity.rs) fails the instant this drifts from a direct
    // ChunkEncryptor loop.
    let mut encryptor =
        ChunkEncryptor::from_reader(master_key, file_id, file_size, profile, reader)?;
    let plan = encryptor.chunk_plan();
    // Safe cast: from_reader already validated chunk_count fits in u32.
    let chunk_count = plan.chunk_count as u32;

    let mut chunks = Vec::with_capacity(chunk_count as usize);
    let mut total_plaintext: u64 = 0;
    let mut total_ciphertext: u64 = 0;

    while let Some(chunk) = encryptor.next_chunk()? {
        let chunk_index = chunk.index;
        let encrypted = chunk.data; // nonce || ciphertext || tag
        let ciphertext_size = encrypted.len() as u64;
        let nonce = encrypted[..NONCE_LEN].to_vec();
        let plaintext_size = ciphertext_size - (NONCE_LEN + TAG_LEN) as u64;

        // Write to .tmp then atomic rename to .enc
        let enc_path = output_dir.join(format!("{chunk_index}.enc"));
        let tmp_path = output_dir.join(format!("{chunk_index}.enc.tmp"));

        let mut writer = BufWriter::new(
            File::create(&tmp_path)
                .map_err(|e| CoreError::Io(format!("create chunk file: {e}")))?,
        );
        writer
            .write_all(&encrypted)
            .map_err(|e| CoreError::Io(format!("write chunk: {e}")))?;
        writer
            .flush()
            .map_err(|e| CoreError::Io(format!("flush chunk: {e}")))?;
        drop(writer);

        // Atomic rename
        fs::rename(&tmp_path, &enc_path)
            .map_err(|e| CoreError::Io(format!("rename chunk: {e}")))?;

        total_plaintext += plaintext_size;
        total_ciphertext += ciphertext_size;

        chunks.push(EncryptedChunkInfo {
            chunk_index,
            output_path: enc_path,
            nonce,
            plaintext_size,
            ciphertext_size,
        });

        if let Some(cb) = callback {
            cb.on_progress(chunk_index + 1, chunk_count);
        }
    }

    // Integrity guard: detects an input that shrank between stat and read.
    let _summary = encryptor.finish()?;

    Ok(EncryptedFileResult {
        chunks,
        total_plaintext_bytes: total_plaintext,
        total_ciphertext_bytes: total_ciphertext,
        chunk_size_bytes: plan.chunk_size_bytes,
    })
}

/// Decrypt chunk files back to a single output file.
///
/// Reads each chunk file (which contains `nonce || ciphertext`), decrypts it,
/// and appends the plaintext to the output. The output is first written to a
/// `.tmp` file, then atomically renamed to the final path.
pub fn decrypt_chunks_to_file(
    master_key: &MasterKey,
    file_id: &str,
    chunk_paths: &[&Path],
    output_path: &Path,
    callback: Option<&dyn FileProgressCallback>,
) -> Result<DecryptedFileResult, CoreError> {
    let file_key = derive_file_key(master_key, file_id.as_bytes());
    let chunks_total = chunk_paths.len() as u32;

    // Write to .tmp then atomic rename
    let tmp_path = output_path.with_extension("tmp");

    // Ensure parent directory exists
    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| CoreError::Io(format!("create output parent dir: {e}")))?;
    }

    let output_file = File::create(&tmp_path)
        .map_err(|e| CoreError::Io(format!("create output file: {e}")))?;
    let mut writer = BufWriter::new(output_file);

    let mut total_bytes: u64 = 0;
    let mut chunks_processed: u32 = 0;

    for (i, chunk_path) in chunk_paths.iter().enumerate() {
        // Read the entire chunk file
        let raw = fs::read(chunk_path)
            .map_err(|e| CoreError::Io(format!("read chunk {i}: {e}")))?;

        // Decrypt: raw is nonce || ciphertext
        let plaintext = decrypt_chunk_raw(&file_key, &raw)?;

        writer
            .write_all(&plaintext)
            .map_err(|e| CoreError::Io(format!("write output: {e}")))?;

        total_bytes += plaintext.len() as u64;
        chunks_processed += 1;

        if let Some(cb) = callback {
            cb.on_progress(chunks_processed, chunks_total);
        }
    }

    writer
        .flush()
        .map_err(|e| CoreError::Io(format!("flush output: {e}")))?;
    drop(writer);

    // Atomic rename to final path
    fs::rename(&tmp_path, output_path)
        .map_err(|e| CoreError::Io(format!("rename output: {e}")))?;

    Ok(DecryptedFileResult {
        output_path: output_path.to_path_buf(),
        total_bytes,
        chunks_processed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kdf::derive_master_key;
    use std::fs;

    fn test_master_key() -> MasterKey {
        derive_master_key("test-password", b"test-salt-16bytes").unwrap()
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let mk = test_master_key();
        let dir = std::env::temp_dir().join("beebeeb_file_encrypt_roundtrip");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        // Create a test file with known content
        let input_path = dir.join("input.bin");
        let content = b"Hello, Beebeeb! This is a test file for encryption.";
        fs::write(&input_path, content).unwrap();

        // Encrypt
        let output_dir = dir.join("chunks");
        let result = encrypt_file_to_chunks(
            &mk,
            "test-file-001",
            &input_path,
            &output_dir,
            ChunkProfile::Mobile,
            None,
        )
        .unwrap();

        assert_eq!(result.total_plaintext_bytes, content.len() as u64);
        assert!(!result.chunks.is_empty());

        // Verify chunk files exist
        for chunk in &result.chunks {
            assert!(chunk.output_path.exists());
            let on_disk = fs::read(&chunk.output_path).unwrap();
            assert_eq!(on_disk.len() as u64, chunk.ciphertext_size);
        }

        // Decrypt
        let output_path = dir.join("output.bin");
        let chunk_paths: Vec<&Path> = result.chunks.iter().map(|c| c.output_path.as_path()).collect();
        let dec_result = decrypt_chunks_to_file(
            &mk,
            "test-file-001",
            &chunk_paths,
            &output_path,
            None,
        )
        .unwrap();

        assert_eq!(dec_result.total_bytes, content.len() as u64);
        assert_eq!(dec_result.chunks_processed, result.chunks.len() as u32);

        let recovered = fs::read(&output_path).unwrap();
        assert_eq!(recovered, content);

        // Cleanup
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn encrypt_decrypt_empty_file() {
        let mk = test_master_key();
        let dir = std::env::temp_dir().join("beebeeb_file_encrypt_empty");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let input_path = dir.join("empty.bin");
        fs::write(&input_path, b"").unwrap();

        let output_dir = dir.join("chunks");
        let result = encrypt_file_to_chunks(
            &mk,
            "empty-file",
            &input_path,
            &output_dir,
            ChunkProfile::Mobile,
            None,
        )
        .unwrap();

        assert_eq!(result.total_plaintext_bytes, 0);
        // plan_chunks returns 1 chunk for empty files
        assert_eq!(result.chunks.len(), 1);
        assert_eq!(result.chunks[0].plaintext_size, 0);

        let output_path = dir.join("output.bin");
        let chunk_paths: Vec<&Path> = result.chunks.iter().map(|c| c.output_path.as_path()).collect();
        let dec_result = decrypt_chunks_to_file(
            &mk,
            "empty-file",
            &chunk_paths,
            &output_path,
            None,
        )
        .unwrap();

        assert_eq!(dec_result.total_bytes, 0);
        let recovered = fs::read(&output_path).unwrap();
        assert!(recovered.is_empty());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn encrypt_decrypt_smaller_than_chunk() {
        let mk = test_master_key();
        let dir = std::env::temp_dir().join("beebeeb_file_encrypt_small");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        // 100 bytes is much smaller than the 4 MiB minimum chunk size
        let input_path = dir.join("small.bin");
        let content: Vec<u8> = (0..100u8).collect();
        fs::write(&input_path, &content).unwrap();

        let output_dir = dir.join("chunks");
        let result = encrypt_file_to_chunks(
            &mk,
            "small-file",
            &input_path,
            &output_dir,
            ChunkProfile::Desktop,
            None,
        )
        .unwrap();

        assert_eq!(result.chunks.len(), 1);
        assert_eq!(result.total_plaintext_bytes, 100);

        let output_path = dir.join("output.bin");
        let chunk_paths: Vec<&Path> = result.chunks.iter().map(|c| c.output_path.as_path()).collect();
        let dec_result = decrypt_chunks_to_file(
            &mk,
            "small-file",
            &chunk_paths,
            &output_path,
            None,
        )
        .unwrap();

        let recovered = fs::read(&output_path).unwrap();
        assert_eq!(recovered, content);
        assert_eq!(dec_result.total_bytes, 100);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn encrypt_decrypt_with_mobile_profile() {
        let mk = test_master_key();
        let dir = std::env::temp_dir().join("beebeeb_file_encrypt_mobile");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let input_path = dir.join("photo.bin");
        // 5 MiB file -> should be 2 chunks with 4 MiB chunk size
        let content = vec![0xABu8; 5 * 1024 * 1024];
        fs::write(&input_path, &content).unwrap();

        let output_dir = dir.join("chunks");
        let result = encrypt_file_to_chunks(
            &mk,
            "photo-file",
            &input_path,
            &output_dir,
            ChunkProfile::Mobile,
            None,
        )
        .unwrap();

        assert_eq!(result.chunks.len(), 2);
        assert_eq!(result.chunk_size_bytes, 4 * 1024 * 1024);
        assert_eq!(result.total_plaintext_bytes, 5 * 1024 * 1024);

        let output_path = dir.join("output.bin");
        let chunk_paths: Vec<&Path> = result.chunks.iter().map(|c| c.output_path.as_path()).collect();
        let dec_result = decrypt_chunks_to_file(
            &mk,
            "photo-file",
            &chunk_paths,
            &output_path,
            None,
        )
        .unwrap();

        let recovered = fs::read(&output_path).unwrap();
        assert_eq!(recovered.len(), content.len());
        assert_eq!(recovered, content);
        assert_eq!(dec_result.chunks_processed, 2);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn encrypt_decrypt_with_desktop_profile() {
        let mk = test_master_key();
        let dir = std::env::temp_dir().join("beebeeb_file_encrypt_desktop");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let input_path = dir.join("document.bin");
        let content = vec![0xCDu8; 1024 * 512]; // 512 KiB
        fs::write(&input_path, &content).unwrap();

        let output_dir = dir.join("chunks");
        let result = encrypt_file_to_chunks(
            &mk,
            "doc-file",
            &input_path,
            &output_dir,
            ChunkProfile::Desktop,
            None,
        )
        .unwrap();

        assert_eq!(result.chunks.len(), 1);
        assert_eq!(result.total_plaintext_bytes, content.len() as u64);

        let output_path = dir.join("output.bin");
        let chunk_paths: Vec<&Path> = result.chunks.iter().map(|c| c.output_path.as_path()).collect();
        let dec_result = decrypt_chunks_to_file(
            &mk,
            "doc-file",
            &chunk_paths,
            &output_path,
            None,
        )
        .unwrap();

        let recovered = fs::read(&output_path).unwrap();
        assert_eq!(recovered, content);
        assert_eq!(dec_result.chunks_processed, 1);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn progress_callback_fires() {
        use std::sync::atomic::{AtomicU32, Ordering};
        use std::sync::Arc;

        struct TestCallback {
            last_completed: AtomicU32,
            last_total: AtomicU32,
            call_count: AtomicU32,
        }

        impl FileProgressCallback for TestCallback {
            fn on_progress(&self, completed: u32, total: u32) {
                self.last_completed.store(completed, Ordering::SeqCst);
                self.last_total.store(total, Ordering::SeqCst);
                self.call_count.fetch_add(1, Ordering::SeqCst);
            }
        }

        let mk = test_master_key();
        let dir = std::env::temp_dir().join("beebeeb_file_encrypt_progress");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let input_path = dir.join("progress.bin");
        // 5 MiB -> 2 chunks
        let content = vec![0xFFu8; 5 * 1024 * 1024];
        fs::write(&input_path, &content).unwrap();

        let cb = Arc::new(TestCallback {
            last_completed: AtomicU32::new(0),
            last_total: AtomicU32::new(0),
            call_count: AtomicU32::new(0),
        });

        let output_dir = dir.join("chunks");
        encrypt_file_to_chunks(
            &mk,
            "progress-file",
            &input_path,
            &output_dir,
            ChunkProfile::Mobile,
            Some(cb.as_ref()),
        )
        .unwrap();

        assert_eq!(cb.call_count.load(Ordering::SeqCst), 2);
        assert_eq!(cb.last_completed.load(Ordering::SeqCst), 2);
        assert_eq!(cb.last_total.load(Ordering::SeqCst), 2);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn wrong_key_fails_decryption() {
        let mk = test_master_key();
        let dir = std::env::temp_dir().join("beebeeb_file_encrypt_wrongkey");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let input_path = dir.join("secret.bin");
        fs::write(&input_path, b"secret data").unwrap();

        let output_dir = dir.join("chunks");
        let result = encrypt_file_to_chunks(
            &mk,
            "secret-file",
            &input_path,
            &output_dir,
            ChunkProfile::Mobile,
            None,
        )
        .unwrap();

        // Try to decrypt with wrong key
        let wrong_mk = derive_master_key("wrong-password", b"wrong-salt-16byte").unwrap();
        let output_path = dir.join("output.bin");
        let chunk_paths: Vec<&Path> = result.chunks.iter().map(|c| c.output_path.as_path()).collect();
        let dec_result = decrypt_chunks_to_file(
            &wrong_mk,
            "secret-file",
            &chunk_paths,
            &output_path,
            None,
        );

        assert!(dec_result.is_err());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn wrong_file_id_fails_decryption() {
        let mk = test_master_key();
        let dir = std::env::temp_dir().join("beebeeb_file_encrypt_wrongid");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let input_path = dir.join("data.bin");
        fs::write(&input_path, b"important data").unwrap();

        let output_dir = dir.join("chunks");
        let result = encrypt_file_to_chunks(
            &mk,
            "file-001",
            &input_path,
            &output_dir,
            ChunkProfile::Mobile,
            None,
        )
        .unwrap();

        // Try to decrypt with wrong file ID (derives different file key)
        let output_path = dir.join("output.bin");
        let chunk_paths: Vec<&Path> = result.chunks.iter().map(|c| c.output_path.as_path()).collect();
        let dec_result = decrypt_chunks_to_file(
            &mk,
            "file-002",
            &chunk_paths,
            &output_path,
            None,
        );

        assert!(dec_result.is_err());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn nonexistent_input_returns_io_error() {
        let mk = test_master_key();
        let dir = std::env::temp_dir().join("beebeeb_file_encrypt_nofile");
        let input_path = dir.join("does_not_exist.bin");
        let output_dir = dir.join("chunks");

        let result = encrypt_file_to_chunks(
            &mk,
            "no-file",
            &input_path,
            &output_dir,
            ChunkProfile::Mobile,
            None,
        );

        assert!(matches!(result, Err(CoreError::Io(_))));
    }
}
