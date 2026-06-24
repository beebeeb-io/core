use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use rand::RngCore;

use beebeeb_types::{CipherSuite, EncryptedBlob};

use crate::CoreError;
use crate::kdf::FileKey;

/// AES-256-GCM nonce length in bytes. Single source of truth for the
/// `encrypt` / `file_encrypt` / `chunk_stream` cluster.
pub(crate) const NONCE_LEN: usize = 12;

/// AES-256-GCM authentication tag length in bytes. Single source of truth for
/// the `encrypt` / `file_encrypt` / `chunk_stream` cluster.
pub(crate) const TAG_LEN: usize = 16;

/// Encrypt an arbitrary plaintext chunk with AES-256-GCM.
///
/// A fresh random 12-byte nonce is generated for every call.
pub fn encrypt_chunk(key: &FileKey, plaintext: &[u8]) -> Result<EncryptedBlob, CoreError> {
    let cipher = Aes256Gcm::new_from_slice(key.as_bytes()).map_err(|e| CoreError::Encryption(e.to_string()))?;

    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| CoreError::Encryption(e.to_string()))?;

    Ok(EncryptedBlob {
        cipher_suite: CipherSuite::V1Aes256Gcm,
        nonce: nonce_bytes.to_vec(),
        ciphertext,
    })
}

/// Decrypt a blob that was produced by [`encrypt_chunk`].
pub fn decrypt_chunk(key: &FileKey, blob: &EncryptedBlob) -> Result<Vec<u8>, CoreError> {
    if blob.cipher_suite != CipherSuite::V1Aes256Gcm {
        return Err(CoreError::Decryption);
    }
    if blob.nonce.len() != NONCE_LEN {
        return Err(CoreError::Decryption);
    }

    let cipher = Aes256Gcm::new_from_slice(key.as_bytes()).map_err(|e| CoreError::Encryption(e.to_string()))?;
    let nonce = Nonce::from_slice(&blob.nonce);

    cipher
        .decrypt(nonce, blob.ciphertext.as_ref())
        .map_err(|_| CoreError::Decryption)
}

/// Encrypt a UTF-8 metadata string (e.g. filename / path) with AES-256-GCM.
pub fn encrypt_metadata(key: &FileKey, metadata: &str) -> Result<EncryptedBlob, CoreError> {
    encrypt_chunk(key, metadata.as_bytes())
}

/// Decrypt a metadata blob back to a UTF-8 string.
pub fn decrypt_metadata(key: &FileKey, blob: &EncryptedBlob) -> Result<String, CoreError> {
    let plaintext = decrypt_chunk(key, blob)?;
    String::from_utf8(plaintext).map_err(|_| CoreError::Decryption)
}

// ── High-level API for all clients ──────────────────────────────────
//
// These functions handle key derivation + encryption + canonical JSON
// serialization in one call. ALL clients (CLI, web/WASM, mobile/UniFFI)
// should use these instead of hand-rolling serialization.

/// Encrypt a filename (with MIME type) and return the canonical JSON string.
///
/// This is the **only** way clients should produce `name_encrypted`.
/// The plaintext is `{"name":"filename","mime_type":"type/subtype"}` —
/// matching the web app's zero-knowledge format where MIME is encrypted,
/// never sent in plaintext to the server.
///
/// The output envelope is `{"cipher_suite":"V1Aes256Gcm","nonce":[...],"ciphertext":[...]}`.
pub fn encrypt_name(
    master_key: &crate::kdf::MasterKey,
    file_id: &str,
    filename: &str,
    mime_type: Option<&str>,
) -> Result<String, CoreError> {
    let plaintext = serde_json::json!({
        "name": filename,
        "mime_type": mime_type,
    })
    .to_string();
    let file_key = crate::kdf::derive_file_key(master_key, file_id.as_bytes());
    let blob = encrypt_metadata(&file_key, &plaintext)?;
    serde_json::to_string(&blob).map_err(|e| CoreError::Encryption(e.to_string()))
}

/// Decrypt a `name_encrypted` JSON string back to a plaintext filename.
///
/// Handles both formats:
/// - New: `{"name":"file.pdf","mime_type":"application/pdf"}` (extracts `name`)
/// - Legacy: bare filename string `"file.pdf"`
pub fn decrypt_name(
    master_key: &crate::kdf::MasterKey,
    file_id: &str,
    name_encrypted: &str,
) -> Result<String, CoreError> {
    let blob: EncryptedBlob = serde_json::from_str(name_encrypted).map_err(|_| CoreError::Decryption)?;
    let file_key = crate::kdf::derive_file_key(master_key, file_id.as_bytes());
    let decrypted = decrypt_metadata(&file_key, &blob)?;

    // Extract filename from JSON metadata envelope, or return bare string
    if let Ok(meta) = serde_json::from_str::<serde_json::Value>(&decrypted) {
        if let Some(name) = meta.get("name").and_then(|v| v.as_str()) {
            return Ok(name.to_string());
        }
    }
    Ok(decrypted)
}

/// Decrypt a `name_encrypted` JSON string and return both filename and MIME type.
pub fn decrypt_name_with_mime(
    master_key: &crate::kdf::MasterKey,
    file_id: &str,
    name_encrypted: &str,
) -> Result<(String, Option<String>), CoreError> {
    let blob: EncryptedBlob = serde_json::from_str(name_encrypted).map_err(|_| CoreError::Decryption)?;
    let file_key = crate::kdf::derive_file_key(master_key, file_id.as_bytes());
    let decrypted = decrypt_metadata(&file_key, &blob)?;

    if let Ok(meta) = serde_json::from_str::<serde_json::Value>(&decrypted) {
        let name = meta
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or(&decrypted)
            .to_string();
        let mime = meta.get("mime_type").and_then(|v| v.as_str()).map(|s| s.to_string());
        return Ok((name, mime));
    }
    Ok((decrypted, None))
}

/// Batch-decrypt many file names in one call (task 0806).
///
/// Every client decrypts folder names one-by-one across the WASM/UniFFI
/// boundary today — N crossings per folder. This collapses that to ONE crossing
/// and parallelises natively (rayon, off-wasm).
///
/// Per item it mirrors [`decrypt_name_with_mime`] (envelope → `name` + optional
/// `mime_type`, bare-string fallback), and — like the CLI's `decrypt_name`
/// compatibility shim — tries **both** file-key derivations a file could have
/// been created under, returning the first that authenticates: the **string-UUID**
/// form (`uuid.to_string().as_bytes()` — web/mobile + server-canonical
/// hyphenated-lowercase, the common case) first, then the legacy **binary-UUID**
/// form (`uuid.as_bytes()`, 16 raw bytes — CLI/desktop origin).
///
/// AES-256-GCM is authenticated, so a wrong-format key fails the tag (never a
/// false success). A bad/garbage item yields `Err` for THAT item only — it never
/// fails the whole batch. Order of results matches the input.
pub fn decrypt_names(
    master_key: &crate::kdf::MasterKey,
    items: &[(uuid::Uuid, &str)],
) -> Vec<Result<(String, Option<String>), CoreError>> {
    #[cfg(not(target_arch = "wasm32"))]
    {
        use rayon::prelude::*;
        items
            .par_iter()
            .map(|(file_id, name_encrypted)| decrypt_one_name(master_key, file_id, name_encrypted))
            .collect()
    }
    #[cfg(target_arch = "wasm32")]
    {
        // wasm32 is single-threaded; rayon can't target it. Sequential here; the
        // win on wasm is collapsing N boundary crossings into one call.
        items
            .iter()
            .map(|(file_id, name_encrypted)| decrypt_one_name(master_key, file_id, name_encrypted))
            .collect()
    }
}

/// Decrypt one `(file_id, name_encrypted)` — the per-item core of [`decrypt_names`].
fn decrypt_one_name(
    master_key: &crate::kdf::MasterKey,
    file_id: &uuid::Uuid,
    name_encrypted: &str,
) -> Result<(String, Option<String>), CoreError> {
    let blob: EncryptedBlob = serde_json::from_str(name_encrypted).map_err(|_| CoreError::Decryption)?;

    // String-UUID form first (the common case: web/mobile/server-canonical).
    let key_string = crate::kdf::derive_file_key(master_key, file_id.to_string().as_bytes());
    if let Ok(decrypted) = decrypt_metadata(&key_string, &blob) {
        return Ok(parse_name_and_mime(decrypted));
    }
    // Legacy binary-UUID form (CLI/desktop origin).
    let key_binary = crate::kdf::derive_file_key(master_key, file_id.as_bytes());
    if let Ok(decrypted) = decrypt_metadata(&key_binary, &blob) {
        return Ok(parse_name_and_mime(decrypted));
    }
    Err(CoreError::Decryption)
}

/// Extract `(name, mime_type)` from a decrypted metadata string — the shared
/// envelope semantics of [`decrypt_name_with_mime`]: a `{"name","mime_type"}`
/// JSON envelope, or a bare filename string (legacy).
fn parse_name_and_mime(decrypted: String) -> (String, Option<String>) {
    if let Ok(meta) = serde_json::from_str::<serde_json::Value>(&decrypted) {
        let name = meta
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or(&decrypted)
            .to_string();
        let mime = meta.get("mime_type").and_then(|v| v.as_str()).map(|s| s.to_string());
        return (name, mime);
    }
    (decrypted, None)
}

/// Encrypt a file chunk and return the canonical JSON string.
///
/// This is the **only** way clients should produce chunk data for upload.
pub fn encrypt_chunk_json(
    master_key: &crate::kdf::MasterKey,
    file_id: &str,
    plaintext: &[u8],
) -> Result<String, CoreError> {
    let file_key = crate::kdf::derive_file_key(master_key, file_id.as_bytes());
    let blob = encrypt_chunk(&file_key, plaintext)?;
    serde_json::to_string(&blob).map_err(|e| CoreError::Encryption(e.to_string()))
}

/// Encrypt a chunk → raw binary: nonce (12 bytes) || ciphertext (includes GCM tag).
/// This is the canonical chunk wire format. No JSON, no base64.
pub fn encrypt_chunk_raw(key: &FileKey, plaintext: &[u8]) -> Result<Vec<u8>, CoreError> {
    let cipher = Aes256Gcm::new_from_slice(key.as_bytes()).map_err(|e| CoreError::Encryption(e.to_string()))?;
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| CoreError::Encryption(e.to_string()))?;
    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt a sequence of encrypted chunks and write the plaintext to a file.
/// Each chunk is an `EncryptedBlob` (V1Aes256Gcm with 12-byte nonce).
/// Returns the total number of plaintext bytes written.
pub fn decrypt_chunks_to_file(
    key: &FileKey,
    chunks: Vec<(Vec<u8>, Vec<u8>)>, // Vec of (nonce, ciphertext) pairs
    output_path: &str,
) -> Result<u64, CoreError> {
    use std::fs::File;
    use std::io::Write;

    let mut file = File::create(output_path).map_err(|e| CoreError::Io(format!("create file: {e}")))?;
    let mut total: u64 = 0;
    for (nonce, ciphertext) in chunks {
        let blob = EncryptedBlob {
            cipher_suite: CipherSuite::V1Aes256Gcm,
            nonce,
            ciphertext,
        };
        let plaintext = decrypt_chunk(key, &blob)?;
        file.write_all(&plaintext)
            .map_err(|e| CoreError::Io(format!("write: {e}")))?;
        total += plaintext.len() as u64;
    }
    file.flush().map_err(|e| CoreError::Io(format!("flush: {e}")))?;
    Ok(total)
}

/// Decrypt a raw binary chunk: nonce (12 bytes) || ciphertext.
pub fn decrypt_chunk_raw(key: &FileKey, raw: &[u8]) -> Result<Vec<u8>, CoreError> {
    if raw.len() < NONCE_LEN + 16 {
        return Err(CoreError::Decryption);
    }
    let (nonce_bytes, ciphertext) = raw.split_at(NONCE_LEN);
    let cipher = Aes256Gcm::new_from_slice(key.as_bytes()).map_err(|e| CoreError::Encryption(e.to_string()))?;
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher.decrypt(nonce, ciphertext).map_err(|_| CoreError::Decryption)
}

/// Decrypt a contiguous encrypted body into a file.
///
/// `body` is the wire format produced by concatenating encrypted chunks:
/// each chunk is `nonce (12 bytes) || ciphertext (chunk_size bytes of AEAD
/// output + 16 byte GCM tag)`. All chunks but the last produce `chunk_size`
/// bytes of plaintext; the final chunk is whatever remains in `body` and
/// may be shorter.
///
/// Streams chunk-by-chunk — peak memory is one plaintext chunk, not the
/// full file. Returns the total number of plaintext bytes written.
///
/// **Atomic output:** plaintext is written to `{output_path}.tmp`, flushed, and
/// `rename`d to `output_path` only on full success. On **any** error the `.tmp`
/// file is removed, so no partial plaintext ever appears at `output_path`. This
/// removes the previous caller-cleanup obligation and prevents an
/// existence-based cache from serving a truncated decrypt as if complete. (Same
/// `.tmp` + atomic-rename pattern as
/// [`crate::file_encrypt::decrypt_chunks_to_file`].)
pub fn decrypt_contiguous_to_file(
    key: &FileKey,
    body: &[u8],
    chunk_size: u64,
    output_path: &str,
) -> Result<u64, CoreError> {
    if chunk_size == 0 {
        return Err(CoreError::InvalidInput("chunk_size must be positive".into()));
    }
    let chunk_size_usize: usize = chunk_size
        .try_into()
        .map_err(|_| CoreError::InvalidInput(format!("chunk_size {chunk_size} exceeds usize range")))?;
    let encrypted_chunk_len = NONCE_LEN
        .checked_add(chunk_size_usize)
        .and_then(|v| v.checked_add(TAG_LEN))
        .ok_or_else(|| CoreError::InvalidInput("chunk_size overflows".into()))?;

    // Write to a sibling .tmp, then atomically rename on success only.
    let tmp_path = format!("{output_path}.tmp");

    // Inner closure does the streaming decrypt; on ANY Err the outer code
    // removes the .tmp so no partial plaintext survives at output_path.
    let result = decrypt_contiguous_to_tmp(key, body, encrypted_chunk_len, &tmp_path);

    match result {
        Ok(total) => {
            std::fs::rename(&tmp_path, output_path).map_err(|e| {
                // Rename failed: drop the temp so it can't poison a cache.
                std::fs::remove_file(&tmp_path).ok();
                CoreError::Io(format!("rename output: {e}"))
            })?;
            Ok(total)
        }
        Err(e) => {
            // Remove the partial temp on every failure path.
            std::fs::remove_file(&tmp_path).ok();
            Err(e)
        }
    }
}

/// Streaming decrypt body → `tmp_path`. Helper for [`decrypt_contiguous_to_file`]
/// so the caller can guarantee `.tmp` cleanup on every error path.
fn decrypt_contiguous_to_tmp(
    key: &FileKey,
    body: &[u8],
    encrypted_chunk_len: usize,
    tmp_path: &str,
) -> Result<u64, CoreError> {
    use std::fs::File;
    use std::io::Write;

    let mut file = File::create(tmp_path).map_err(|e| CoreError::Io(format!("create file: {e}")))?;
    let mut total: u64 = 0;
    let mut offset = 0usize;

    while offset < body.len() {
        let remaining = body.len() - offset;
        let take = remaining.min(encrypted_chunk_len);
        // Need at least NONCE_LEN + TAG_LEN to even attempt a decrypt.
        if take < NONCE_LEN + TAG_LEN {
            return Err(CoreError::Decryption);
        }
        let raw_chunk = &body[offset..offset + take];
        let plaintext = decrypt_chunk_raw(key, raw_chunk)?;
        file.write_all(&plaintext)
            .map_err(|e| CoreError::Io(format!("write: {e}")))?;
        total += plaintext.len() as u64;
        offset += take;
    }
    file.flush().map_err(|e| CoreError::Io(format!("flush: {e}")))?;
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kdf::{derive_file_key, derive_master_key};

    fn test_file_key() -> FileKey {
        let mk = derive_master_key("test-password", b"test-salt-16bytes").unwrap();
        derive_file_key(&mk, b"test-file-id")
    }

    #[test]
    fn roundtrip_encrypt_decrypt_chunk() {
        let key = test_file_key();
        let plaintext = b"hello, beebeeb!";

        let blob = encrypt_chunk(&key, plaintext).unwrap();
        assert_eq!(blob.cipher_suite, CipherSuite::V1Aes256Gcm);
        assert_eq!(blob.nonce.len(), 12);
        assert_ne!(&blob.ciphertext[..plaintext.len()], plaintext.as_slice());

        let decrypted = decrypt_chunk(&key, &blob).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn wrong_key_fails_decryption() {
        let key = test_file_key();
        let blob = encrypt_chunk(&key, b"secret").unwrap();

        let mk = derive_master_key("different-password", b"different-salt-16").unwrap();
        let wrong_key = derive_file_key(&mk, b"wrong-file");
        assert!(decrypt_chunk(&wrong_key, &blob).is_err());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let key = test_file_key();
        let mut blob = encrypt_chunk(&key, b"important data").unwrap();

        if let Some(byte) = blob.ciphertext.first_mut() {
            *byte ^= 0xFF;
        }

        assert!(decrypt_chunk(&key, &blob).is_err());
    }

    #[test]
    fn tampered_nonce_fails() {
        let key = test_file_key();
        let mut blob = encrypt_chunk(&key, b"important data").unwrap();

        if let Some(byte) = blob.nonce.first_mut() {
            *byte ^= 0xFF;
        }

        assert!(decrypt_chunk(&key, &blob).is_err());
    }

    #[test]
    fn invalid_nonce_length_fails() {
        let key = test_file_key();
        let blob = EncryptedBlob {
            cipher_suite: CipherSuite::V1Aes256Gcm,
            nonce: vec![0u8; 8], // wrong length
            ciphertext: vec![0u8; 32],
        };
        assert!(decrypt_chunk(&key, &blob).is_err());
    }

    #[test]
    fn empty_plaintext_roundtrip() {
        let key = test_file_key();
        let blob = encrypt_chunk(&key, b"").unwrap();
        let decrypted = decrypt_chunk(&key, &blob).unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn roundtrip_metadata() {
        let key = test_file_key();
        let filename = "photos/vacation/IMG_2024.jpg";

        let blob = encrypt_metadata(&key, filename).unwrap();
        let recovered = decrypt_metadata(&key, &blob).unwrap();
        assert_eq!(recovered, filename);
    }

    #[test]
    fn metadata_wrong_key_fails() {
        let key = test_file_key();
        let blob = encrypt_metadata(&key, "secret.txt").unwrap();

        let mk = derive_master_key("other", b"other-salt-16byte").unwrap();
        let wrong_key = derive_file_key(&mk, b"wrong");
        assert!(decrypt_metadata(&wrong_key, &blob).is_err());
    }

    #[test]
    fn unique_nonces_per_encryption() {
        let key = test_file_key();
        let blob1 = encrypt_chunk(&key, b"same").unwrap();
        let blob2 = encrypt_chunk(&key, b"same").unwrap();
        assert_ne!(blob1.nonce, blob2.nonce);
    }

    #[test]
    fn decrypt_chunks_to_file_roundtrip() {
        let key = test_file_key();
        let chunk1 = b"hello, ";
        let chunk2 = b"beebeeb!";

        let blob1 = encrypt_chunk(&key, chunk1).unwrap();
        let blob2 = encrypt_chunk(&key, chunk2).unwrap();

        let chunks = vec![(blob1.nonce, blob1.ciphertext), (blob2.nonce, blob2.ciphertext)];

        let dir = std::env::temp_dir();
        let path = dir.join("beebeeb_test_decrypt_chunks.bin");
        let path_str = path.to_str().unwrap();

        let total = decrypt_chunks_to_file(&key, chunks, path_str).unwrap();
        assert_eq!(total, (chunk1.len() + chunk2.len()) as u64);

        let written = std::fs::read(&path).unwrap();
        assert_eq!(written, b"hello, beebeeb!");

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn decrypt_chunks_to_file_empty() {
        let key = test_file_key();

        let dir = std::env::temp_dir();
        let path = dir.join("beebeeb_test_decrypt_empty.bin");
        let path_str = path.to_str().unwrap();

        let total = decrypt_chunks_to_file(&key, vec![], path_str).unwrap();
        assert_eq!(total, 0);

        let written = std::fs::read(&path).unwrap();
        assert!(written.is_empty());

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn decrypt_chunks_to_file_wrong_key_fails() {
        let key = test_file_key();
        let blob = encrypt_chunk(&key, b"secret data").unwrap();
        let chunks = vec![(blob.nonce, blob.ciphertext)];

        let mk = derive_master_key("different-password", b"different-salt-16").unwrap();
        let wrong_key = derive_file_key(&mk, b"wrong-file");

        let dir = std::env::temp_dir();
        let path = dir.join("beebeeb_test_decrypt_wrong_key.bin");
        let path_str = path.to_str().unwrap();

        assert!(decrypt_chunks_to_file(&wrong_key, chunks, path_str).is_err());

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn large_plaintext_roundtrip() {
        let key = test_file_key();
        let plaintext = vec![0x42u8; 1024 * 1024]; // 1 MiB
        let blob = encrypt_chunk(&key, &plaintext).unwrap();
        let decrypted = decrypt_chunk(&key, &blob).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    fn pack_chunk(blob: &EncryptedBlob) -> Vec<u8> {
        let mut out = Vec::with_capacity(blob.nonce.len() + blob.ciphertext.len());
        out.extend_from_slice(&blob.nonce);
        out.extend_from_slice(&blob.ciphertext);
        out
    }

    #[test]
    fn decrypt_contiguous_roundtrip_two_uniform_chunks() {
        let key = test_file_key();
        let chunk_size: u64 = 8;
        let p1 = b"AAAAAAAA";
        let p2 = b"BBBBBBBB";
        let blob1 = encrypt_chunk(&key, p1).unwrap();
        let blob2 = encrypt_chunk(&key, p2).unwrap();
        let mut body = pack_chunk(&blob1);
        body.extend(pack_chunk(&blob2));

        let path = std::env::temp_dir().join("beebeeb_test_contig_uniform.bin");
        let total = decrypt_contiguous_to_file(&key, &body, chunk_size, path.to_str().unwrap()).unwrap();
        assert_eq!(total, 16);

        let written = std::fs::read(&path).unwrap();
        assert_eq!(written, b"AAAAAAAABBBBBBBB");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn decrypt_contiguous_roundtrip_with_remainder() {
        let key = test_file_key();
        let chunk_size: u64 = 8;
        let p1 = b"AAAAAAAA"; // full chunk
        let p2 = b"BBB"; // short final chunk
        let blob1 = encrypt_chunk(&key, p1).unwrap();
        let blob2 = encrypt_chunk(&key, p2).unwrap();
        let mut body = pack_chunk(&blob1);
        body.extend(pack_chunk(&blob2));

        let path = std::env::temp_dir().join("beebeeb_test_contig_remainder.bin");
        let total = decrypt_contiguous_to_file(&key, &body, chunk_size, path.to_str().unwrap()).unwrap();
        assert_eq!(total, 11);

        let written = std::fs::read(&path).unwrap();
        assert_eq!(written, b"AAAAAAAABBB");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn decrypt_contiguous_empty_body() {
        let key = test_file_key();
        let path = std::env::temp_dir().join("beebeeb_test_contig_empty.bin");
        let total = decrypt_contiguous_to_file(&key, &[], 8, path.to_str().unwrap()).unwrap();
        assert_eq!(total, 0);
        let written = std::fs::read(&path).unwrap();
        assert!(written.is_empty());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn decrypt_contiguous_zero_chunk_size_rejected() {
        let key = test_file_key();
        let body = vec![0u8; NONCE_LEN + 16];
        let path = std::env::temp_dir().join("beebeeb_test_contig_zero.bin");
        let err = decrypt_contiguous_to_file(&key, &body, 0, path.to_str().unwrap()).unwrap_err();
        match err {
            CoreError::InvalidInput(_) => {}
            other => panic!("expected InvalidInput, got {other:?}"),
        }
        // Empty file may exist on err; clean up if so.
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn decrypt_contiguous_wrong_key_fails() {
        let key = test_file_key();
        let wrong_key = derive_file_key(
            &derive_master_key("different-password", b"test-salt-16bytes").unwrap(),
            b"test-file-id",
        );
        let blob = encrypt_chunk(&key, b"secrets").unwrap();
        let body = pack_chunk(&blob);
        let path = std::env::temp_dir().join("beebeeb_test_contig_wrong_key.bin");
        let err = decrypt_contiguous_to_file(&wrong_key, &body, 7, path.to_str().unwrap()).unwrap_err();
        assert!(matches!(err, CoreError::Decryption));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn decrypt_contiguous_truncated_body_rejected() {
        let key = test_file_key();
        // Body shorter than NONCE_LEN + TAG_LEN — cannot even attempt decrypt.
        let body = vec![0u8; NONCE_LEN + 8]; // 8 bytes < 16 byte tag
        let path = std::env::temp_dir().join("beebeeb_test_contig_truncated.bin");
        let err = decrypt_contiguous_to_file(&key, &body, 64, path.to_str().unwrap()).unwrap_err();
        assert!(matches!(err, CoreError::Decryption));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn decrypt_contiguous_leaves_no_partial_file_on_midstream_failure() {
        // R2: chunk 1 decrypts fine, chunk 2's tag is corrupt. The function must
        // fail AND leave no partial plaintext at output_path — otherwise an
        // existence-based cache would serve the truncated first chunk as a
        // "complete" decrypt on every subsequent open.
        let key = test_file_key();
        let chunk_size: u64 = 8;
        let blob1 = encrypt_chunk(&key, b"AAAAAAAA").unwrap();
        let blob2 = encrypt_chunk(&key, b"BBBBBBBB").unwrap();
        let mut body = pack_chunk(&blob1);
        let mut second = pack_chunk(&blob2);
        // Corrupt the GCM tag of the second chunk (flip the last byte).
        let last = second.len() - 1;
        second[last] ^= 0xFF;
        body.extend(second);

        let path = std::env::temp_dir().join("beebeeb_test_contig_partial_cleanup.bin");
        // Ensure a stale file from a prior run does not mask the assertion.
        std::fs::remove_file(&path).ok();

        let err = decrypt_contiguous_to_file(&key, &body, chunk_size, path.to_str().unwrap()).unwrap_err();
        assert!(matches!(err, CoreError::Decryption));
        assert!(
            !path.exists(),
            "no partial plaintext file may remain at output_path after a failed decrypt"
        );
        // No .tmp artifact may survive either.
        let tmp = std::env::temp_dir().join("beebeeb_test_contig_partial_cleanup.bin.tmp");
        assert!(!tmp.exists(), "no .tmp artifact may remain after a failed decrypt");
    }

    #[test]
    fn decrypt_contiguous_atomic_no_partial_visible_at_final_path() {
        // R2: on a wrong key the very first chunk fails. The final output path
        // must never have been created (atomic .tmp + rename means the final
        // path only appears on full success).
        let key = test_file_key();
        let wrong_key = derive_file_key(
            &derive_master_key("different-password", b"test-salt-16bytes").unwrap(),
            b"test-file-id",
        );
        let blob = encrypt_chunk(&key, b"secrets!").unwrap();
        let body = pack_chunk(&blob);
        let path = std::env::temp_dir().join("beebeeb_test_contig_atomic_firstfail.bin");
        std::fs::remove_file(&path).ok();

        let err = decrypt_contiguous_to_file(&wrong_key, &body, 8, path.to_str().unwrap()).unwrap_err();
        assert!(matches!(err, CoreError::Decryption));
        assert!(
            !path.exists(),
            "final output path must not exist after a first-chunk failure"
        );
    }

    // ── decrypt_names batch primitive (task 0806) ───────────────────────────

    #[test]
    fn decrypt_names_batch_matches_single_byte_for_byte() {
        let master = derive_master_key("batch-test-pw", b"batch-salt-16byte").unwrap();
        // N names encrypted under the string-UUID form (web/mobile/server form).
        let owned: Vec<(uuid::Uuid, String)> = (0..50)
            .map(|i| {
                let id = uuid::Uuid::new_v4();
                let enc = encrypt_name(&master, &id.to_string(), &format!("file_{i}.txt"), Some("text/plain")).unwrap();
                (id, enc)
            })
            .collect();
        let items: Vec<(uuid::Uuid, &str)> = owned.iter().map(|(id, e)| (*id, e.as_str())).collect();

        let batch = decrypt_names(&master, &items);
        assert_eq!(batch.len(), owned.len());
        for (i, ((id, enc), res)) in owned.iter().zip(&batch).enumerate() {
            let single = decrypt_name_with_mime(&master, &id.to_string(), enc).unwrap();
            let got = res.as_ref().expect("batch item should decrypt");
            assert_eq!(
                *got, single,
                "item {i}: batch must match single decrypt_name_with_mime byte-for-byte"
            );
            assert_eq!(got.0, format!("file_{i}.txt"));
            assert_eq!(got.1.as_deref(), Some("text/plain"));
        }
    }

    #[test]
    fn decrypt_names_isolates_partial_failure() {
        let master = derive_master_key("pw-partial", b"salt-16-bytes-ok").unwrap();
        let good_id = uuid::Uuid::new_v4();
        let good = encrypt_name(&master, &good_id.to_string(), "good.pdf", Some("application/pdf")).unwrap();
        // Valid blob but encrypted under a DIFFERENT master key → GCM tag fails.
        let other = derive_master_key("other-pw", b"other-salt-16byt").unwrap();
        let wrong_id = uuid::Uuid::new_v4();
        let wrong = encrypt_name(&other, &wrong_id.to_string(), "secret.txt", None).unwrap();
        let bad_id = uuid::Uuid::new_v4();

        let items: Vec<(uuid::Uuid, &str)> = vec![
            (good_id, good.as_str()),
            (bad_id, "{ not a valid blob"), // garbage → parse fails
            (wrong_id, wrong.as_str()),
        ];
        let res = decrypt_names(&master, &items);
        assert_eq!(res.len(), 3);
        assert_eq!(res[0].as_ref().unwrap().0, "good.pdf", "good item decrypts");
        assert!(res[1].is_err(), "garbage blob → Err for that item only");
        assert!(res[2].is_err(), "wrong-key blob → Err (GCM tag), batch not failed");
    }

    #[test]
    fn decrypt_names_empty_input() {
        let master = derive_master_key("pw-empty", b"salt-16-bytes-ok").unwrap();
        assert!(decrypt_names(&master, &[]).is_empty());
    }

    #[test]
    fn decrypt_names_handles_legacy_binary_uuid_form() {
        // A file keyed under the legacy binary-UUID form (CLI/desktop origin) must
        // still decrypt — via the second derivation attempt.
        let master = derive_master_key("pw-bin", b"salt-16-bytes-ok").unwrap();
        let id = uuid::Uuid::new_v4();
        let bin_key = derive_file_key(&master, id.as_bytes());
        let plaintext = serde_json::json!({"name": "legacy.bin", "mime_type": "application/octet-stream"}).to_string();
        let blob = encrypt_metadata(&bin_key, &plaintext).unwrap();
        let enc = serde_json::to_string(&blob).unwrap();

        let res = decrypt_names(&master, &[(id, enc.as_str())]);
        let (name, mime) = res[0]
            .as_ref()
            .expect("binary-form name should decrypt via 2nd attempt");
        assert_eq!(name, "legacy.bin");
        assert_eq!(mime.as_deref(), Some("application/octet-stream"));
    }
}
