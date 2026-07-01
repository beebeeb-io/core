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

/// Decrypt a `name_encrypted` value from the server back to a plaintext
/// filename. **This is the SINGLE source of truth for name decryption across
/// every client** (CLI, desktop, mobile/UniFFI, web/WASM) — do not re-implement
/// the format/key-derivation matrix anywhere else.
///
/// The server stores `name_encrypted` in several shapes depending on which
/// client wrote the file, and the per-file key may have been derived from two
/// different byte representations of the same UUID. This function tries every
/// combination and returns the first that decrypts to valid UTF-8.
///
/// ## Blob formats handled (per key)
///
/// 1. **Plaintext** — a bare string (not JSON). Legacy entries / server-created
///    folders that predate client-side name encryption. Returned verbatim.
/// 2. **Native `EncryptedBlob`** — JSON with `cipher_suite` + `nonce`/`ciphertext`
///    as numeric byte arrays. Produced by the CLI and any `beebeeb-core` client
///    serializing [`EncryptedBlob`] via serde.
/// 3. **Web base64 blob** — JSON `{"nonce":"<base64>","ciphertext":"<base64>"}`
///    with no `cipher_suite`. Produced by older web builds that base64-encoded
///    the raw `Uint8Array`s (see `repos/web/src/lib/crypto.ts`). The numeric-array
///    variant of this shape is also accepted (tolerant
///    [`crate::metadata_wire::parse_encrypted_metadata`]).
///
/// ## Key derivation handled
///
/// - **String-UUID** — `derive_file_key(mk, file_id.as_bytes())`. Current web +
///   current CLI + post-`bb repair` files (`TextEncoder.encode(fileId)` on web).
/// - **Binary-UUID** — `derive_file_key(mk, uuid.as_bytes())` (the 16-byte form).
///   Legacy pre-`bb repair` CLI files.
///
/// ## Fallback order (matches `repos/cli/src/crypto::decrypt_name`)
///
/// string-UUID key first, then binary-UUID key; within each key the native blob
/// is tried before the web base64 blob. The plaintext fast-path short-circuits
/// before any key derivation.
///
/// Returns `CoreError::Decryption` only when the value looks encrypted but no
/// combination succeeds (wrong key, corrupt blob).
///
/// The decrypted plaintext envelope (`{"name":..,"mime_type":..}`) is unwrapped
/// to the bare `name`; a legacy bare-filename plaintext is returned as-is.
pub fn decrypt_name(
    master_key: &crate::kdf::MasterKey,
    file_id: &str,
    name_encrypted: &str,
) -> Result<String, CoreError> {
    decrypt_name_with_mime(master_key, file_id, name_encrypted).map(|(name, _)| name)
}

/// Decrypt a `name_encrypted` value and return both the filename and the MIME
/// type (if the encrypted payload carried one).
///
/// Handles the **exact same** format + key-derivation matrix as [`decrypt_name`]
/// — they share one implementation. See [`decrypt_name`] for the full list of
/// blob formats and key derivations covered.
pub fn decrypt_name_with_mime(
    master_key: &crate::kdf::MasterKey,
    file_id: &str,
    name_encrypted: &str,
) -> Result<(String, Option<String>), CoreError> {
    // Format 1 (fast path): plaintext — not JSON at all. Legacy / folder rows.
    if !name_encrypted.starts_with('{') {
        return Ok((name_encrypted.to_string(), None));
    }

    // Derive both candidate per-file keys. The web app derives from the UUID
    // *string* bytes (TextEncoder.encode(fileId)); the legacy CLI derived from
    // the 16-byte *binary* UUID. Try string-UUID first (the common case), then
    // binary-UUID. If `file_id` is not a valid UUID we can still try the
    // string-derived key — only the binary derivation is skipped.
    let key_from_string = crate::kdf::derive_file_key(master_key, file_id.as_bytes());
    let key_from_binary = file_id
        .parse::<uuid::Uuid>()
        .ok()
        .map(|u| crate::kdf::derive_file_key(master_key, u.as_bytes()));

    if let Some(result) = decrypt_name_envelope(&key_from_string, name_encrypted) {
        return Ok(result);
    }
    if let Some(key) = key_from_binary {
        if let Some(result) = decrypt_name_envelope(&key, name_encrypted) {
            return Ok(result);
        }
    }

    Err(CoreError::Decryption)
}

/// Decrypt a `name_encrypted` envelope with a **known** [`FileKey`], trying the
/// native `EncryptedBlob` blob first and the web base64 `{nonce,ciphertext}`
/// blob second, then unwrapping the `{name,mime_type}` metadata JSON.
///
/// Used directly by callers that already hold the file key (e.g. file-request
/// uploads, where the content key `C` is recovered via the request-key path and
/// the filename is encrypted under `FileKey(C)`, not a master-derived key).
/// A bare (non-JSON) plaintext name passes straight through; otherwise returns
/// `None` if neither blob format decrypts under this key.
pub fn decrypt_name_with_key(file_key: &FileKey, name_encrypted: &str) -> Option<String> {
    // Plaintext fast path — not JSON at all (legacy / folder rows).
    if !name_encrypted.starts_with('{') {
        return Some(name_encrypted.to_string());
    }
    decrypt_name_envelope(file_key, name_encrypted).map(|(name, _)| name)
}

/// Inner worker for [`decrypt_name_with_mime`] / [`decrypt_name_with_key`]:
/// given one file key, try both supported JSON blob formats and return the
/// unwrapped `(name, mime_type)` on the first that decrypts to valid UTF-8.
fn decrypt_name_envelope(file_key: &FileKey, name_encrypted: &str) -> Option<(String, Option<String>)> {
    // Format 2: native EncryptedBlob (cipher_suite + numeric-array fields).
    if let Ok(blob) = serde_json::from_str::<EncryptedBlob>(name_encrypted) {
        if let Ok(plaintext) = decrypt_metadata(file_key, &blob) {
            return Some(unwrap_metadata_json(&plaintext));
        }
    }

    // Format 3: web base64 (or numeric-array) `{nonce, ciphertext}` blob — no
    // `cipher_suite`. `parse_encrypted_metadata` tolerantly handles both the
    // base64-string and legacy numeric-array encodings.
    if let Ok((nonce, ciphertext)) = crate::metadata_wire::parse_encrypted_metadata(name_encrypted) {
        let blob = EncryptedBlob {
            cipher_suite: CipherSuite::V1Aes256Gcm,
            nonce,
            ciphertext,
        };
        if let Ok(plaintext) = decrypt_metadata(file_key, &blob) {
            return Some(unwrap_metadata_json(&plaintext));
        }
    }

    None
}

/// Unwrap a decrypted plaintext into `(name, mime_type)`.
///
/// The ZK-safe envelope is `{"name":"report.pdf","mime_type":"application/pdf"}`;
/// extract `name` (+ optional `mime_type`). A legacy bare-filename plaintext
/// (not JSON, or JSON without a `name` field) is returned as the name with no
/// MIME type.
fn unwrap_metadata_json(decrypted: &str) -> (String, Option<String>) {
    if let Ok(meta) = serde_json::from_str::<serde_json::Value>(decrypted) {
        if let Some(name) = meta.get("name").and_then(|v| v.as_str()) {
            let mime = meta.get("mime_type").and_then(|v| v.as_str()).map(|s| s.to_string());
            return (name.to_string(), mime);
        }
    }
    (decrypted.to_string(), None)
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
///
/// Delegates to [`decrypt_name_with_mime`] so the batch path shares EXACTLY the
/// same format/key-derivation matrix as every single-item caller (plaintext
/// fast-path, native `EncryptedBlob`, and the legacy web base64
/// `{nonce,ciphertext}` blob). This used to re-implement a narrower subset
/// (native blob only, no plaintext fast-path, no web base64 format) which
/// silently failed to batch-decrypt a name encrypted in either of those two
/// formats. Fixed 2026-07-01, found while reviewing this rebase — present on
/// `origin/main` too (a smaller, self-contained fix landed there separately,
/// since `origin/main`'s own `decrypt_name_with_mime` doesn't yet have this
/// branch's full multi-format consolidation to delegate to).
fn decrypt_one_name(
    master_key: &crate::kdf::MasterKey,
    file_id: &uuid::Uuid,
    name_encrypted: &str,
) -> Result<(String, Option<String>), CoreError> {
    decrypt_name_with_mime(master_key, &file_id.to_string(), name_encrypted)
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
///
/// **Atomic output:** plaintext is written to `{output_path}.tmp`, flushed, and
/// `rename`d to `output_path` only on full success. On **any** error (including
/// a mid-stream decrypt failure) the `.tmp` file is removed, so no partial
/// plaintext ever appears at `output_path`. (Same `.tmp` + atomic-rename +
/// remove-on-error pattern as [`decrypt_contiguous_to_file`].)
pub fn decrypt_chunks_to_file(
    key: &FileKey,
    chunks: Vec<(Vec<u8>, Vec<u8>)>, // Vec of (nonce, ciphertext) pairs
    output_path: &str,
) -> Result<u64, CoreError> {
    // Write to a sibling .tmp, then atomically rename on success only.
    let tmp_path = format!("{output_path}.tmp");

    // Inner helper does the streaming decrypt into the .tmp; on ANY Err the
    // outer code removes the .tmp so no partial plaintext survives at output_path.
    let result = decrypt_chunks_to_tmp(key, chunks, &tmp_path);

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

/// Streaming decrypt of `(nonce, ciphertext)` chunks → `tmp_path`. Helper for
/// [`decrypt_chunks_to_file`] so the caller can guarantee `.tmp` cleanup on
/// every error path.
fn decrypt_chunks_to_tmp(
    key: &FileKey,
    chunks: Vec<(Vec<u8>, Vec<u8>)>,
    tmp_path: &str,
) -> Result<u64, CoreError> {
    use std::fs::File;
    use std::io::Write;

    let mut file = File::create(tmp_path).map_err(|e| CoreError::Io(format!("create file: {e}")))?;
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
    fn decrypt_chunks_to_file_leaves_no_partial_file_on_midstream_failure() {
        // Mirror of decrypt_contiguous_leaves_no_partial_file_on_midstream_failure:
        // chunk 1 decrypts fine, chunk 2's GCM tag is corrupt. The function must
        // fail AND leave no partial plaintext at output_path AND no .tmp artifact.
        let key = test_file_key();
        let blob1 = encrypt_chunk(&key, b"AAAAAAAA").unwrap();
        let mut blob2 = encrypt_chunk(&key, b"BBBBBBBB").unwrap();
        // Corrupt the GCM tag of the second chunk (flip the last ciphertext byte).
        let last = blob2.ciphertext.len() - 1;
        blob2.ciphertext[last] ^= 0xFF;
        let chunks = vec![
            (blob1.nonce, blob1.ciphertext),
            (blob2.nonce, blob2.ciphertext),
        ];

        let path = std::env::temp_dir().join("beebeeb_test_chunks_partial_cleanup.bin");
        let tmp = std::path::PathBuf::from(format!("{}.tmp", path.to_str().unwrap()));
        // Ensure stale artifacts from a prior run do not mask the assertion.
        std::fs::remove_file(&path).ok();
        std::fs::remove_file(&tmp).ok();

        let err = decrypt_chunks_to_file(&key, chunks, path.to_str().unwrap()).unwrap_err();
        assert!(matches!(err, CoreError::Decryption));
        assert!(
            !path.exists(),
            "no partial plaintext file may remain at output_path after a failed decrypt"
        );
        assert!(!tmp.exists(), "no .tmp artifact may remain after a failed decrypt");
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

    /// Regression test (found 2026-07-01): `decrypt_one_name` used to
    /// re-implement a NARROWER parser than `decrypt_name_with_mime` — only the
    /// native `EncryptedBlob` direct-deserialize path, no plaintext fast-path,
    /// no legacy web base64 `{nonce,ciphertext}` format. `decrypt_one_name` now
    /// delegates to `decrypt_name_with_mime` so the two paths can never drift.
    #[test]
    fn decrypt_names_batch_handles_web_base64_format() {
        let master = derive_master_key("pw-web-format", b"salt-16-bytes-ok").unwrap();
        let id = uuid::Uuid::new_v4();
        // Web derives the file key from the UUID STRING bytes (the common case).
        let key = derive_file_key(&master, id.to_string().as_bytes());
        let plaintext = serde_json::json!({"name": "web-upload.png", "mime_type": "image/png"}).to_string();
        let blob = encrypt_metadata(&key, &plaintext).unwrap();
        // Legacy web wire format: base64 {"nonce":"...","ciphertext":"..."} — NO
        // `cipher_suite` field, unlike the native `EncryptedBlob` JSON shape.
        let web_enc = crate::metadata_wire::serialize_encrypted_metadata(&blob.nonce, &blob.ciphertext);

        // Sanity: the single-item path already handles this format correctly.
        let single = decrypt_name_with_mime(&master, &id.to_string(), &web_enc).unwrap();
        assert_eq!(single, ("web-upload.png".to_string(), Some("image/png".to_string())));

        // The batch path must match it byte-for-byte, not silently fail.
        let res = decrypt_names(&master, &[(id, web_enc.as_str())]);
        let got = res[0].as_ref().expect("batch must decrypt the web base64 blob format");
        assert_eq!(*got, single);
    }

    /// Companion regression test: a bare (non-JSON) legacy plaintext filename
    /// must also survive the batch path — the same gap this fix closes.
    #[test]
    fn decrypt_names_batch_handles_plaintext_fast_path() {
        let master = derive_master_key("pw-plaintext", b"salt-16-bytes-ok").unwrap();
        let id = uuid::Uuid::new_v4();
        let res = decrypt_names(&master, &[(id, "legacy-plain-name.txt")]);
        let (name, mime) = res[0].as_ref().expect("bare plaintext name must pass through the batch path");
        assert_eq!(name, "legacy-plain-name.txt");
        assert_eq!(*mime, None);
    }

    // ── decrypt_name: multi-format / multi-key consolidation (the SINGLE
    //    source of truth shared by CLI / desktop / mobile / web). ──────────────

    use crate::kdf::MasterKey;

    /// A fixed UUID file id used across the name-decryption format tests.
    const NAME_FID: &str = "3e15382b-1111-2222-3333-444455556666";

    fn name_master_key() -> MasterKey {
        derive_master_key("test-password", b"test-salt-16bytes").unwrap()
    }

    /// Encode the plaintext into the **web base64** `{nonce, ciphertext}` blob
    /// shape that older web builds produced (base64 strings, no `cipher_suite`).
    /// Mirrors `repos/web/src/lib/crypto.ts` legacy serializer.
    fn web_base64_blob(file_key: &FileKey, plaintext: &str) -> String {
        use base64::Engine as _;
        let blob = encrypt_metadata(file_key, plaintext).unwrap();
        let b64 = base64::engine::general_purpose::STANDARD;
        serde_json::json!({
            "nonce": b64.encode(&blob.nonce),
            "ciphertext": b64.encode(&blob.ciphertext),
        })
        .to_string()
    }

    /// Format 1: a bare (non-JSON) plaintext name passes straight through. This
    /// is how server-created folders / pre-encryption rows are stored.
    #[test]
    fn decrypt_name_plaintext_passthrough() {
        let mk = name_master_key();
        assert_eq!(decrypt_name(&mk, NAME_FID, "Documents").unwrap(), "Documents");
        let (n, mime) = decrypt_name_with_mime(&mk, NAME_FID, "Documents").unwrap();
        assert_eq!(n, "Documents");
        assert_eq!(mime, None);
    }

    /// Format 2 + string-UUID key: the canonical CLI/core path —
    /// `encrypt_name` produces a native EncryptedBlob with the `{name,mime}`
    /// envelope; `decrypt_name` round-trips it.
    #[test]
    fn decrypt_name_native_blob_string_uuid_roundtrip() {
        let mk = name_master_key();
        let enc = encrypt_name(&mk, NAME_FID, "report.pdf", Some("application/pdf")).unwrap();
        assert_eq!(decrypt_name(&mk, NAME_FID, &enc).unwrap(), "report.pdf");
        let (name, mime) = decrypt_name_with_mime(&mk, NAME_FID, &enc).unwrap();
        assert_eq!(name, "report.pdf");
        assert_eq!(mime.as_deref(), Some("application/pdf"));
    }

    /// Format 3 + string-UUID key: the **web app base64 blob** — the format
    /// that was failing for web-app-created files before this consolidation.
    /// The web client derives the file key from the UUID *string* bytes, so the
    /// string-UUID derivation must match.
    #[test]
    fn decrypt_name_web_base64_blob_string_uuid() {
        let mk = name_master_key();
        let fk = derive_file_key(&mk, NAME_FID.as_bytes());
        // Web encrypts the `{name,mime_type}` JSON envelope, base64-wrapped.
        let envelope = serde_json::json!({"name": "vacation.jpg", "mime_type": "image/jpeg"}).to_string();
        let blob = web_base64_blob(&fk, &envelope);
        assert!(!blob.contains("cipher_suite"), "web blob has no cipher_suite field");

        assert_eq!(decrypt_name(&mk, NAME_FID, &blob).unwrap(), "vacation.jpg");
        let (name, mime) = decrypt_name_with_mime(&mk, NAME_FID, &blob).unwrap();
        assert_eq!(name, "vacation.jpg");
        assert_eq!(mime.as_deref(), Some("image/jpeg"));
    }

    /// Format 3 web base64 blob carrying a **bare filename** plaintext (the
    /// oldest web shape, pre-`{name,mime}` envelope) — returned as-is, no MIME.
    #[test]
    fn decrypt_name_web_base64_blob_bare_filename() {
        let mk = name_master_key();
        let fk = derive_file_key(&mk, NAME_FID.as_bytes());
        let blob = web_base64_blob(&fk, "legacy-name.txt");
        assert_eq!(decrypt_name(&mk, NAME_FID, &blob).unwrap(), "legacy-name.txt");
        let (_, mime) = decrypt_name_with_mime(&mk, NAME_FID, &blob).unwrap();
        assert_eq!(mime, None);
    }

    /// Native blob encrypted under the **binary-UUID** key (legacy pre-`bb
    /// repair` CLI file): `decrypt_name` must fall back to the binary derivation.
    #[test]
    fn decrypt_name_native_blob_binary_uuid_fallback() {
        let mk = name_master_key();
        let uuid: uuid::Uuid = NAME_FID.parse().unwrap();
        let fk = derive_file_key(&mk, uuid.as_bytes());
        let envelope = serde_json::json!({"name": "old.doc", "mime_type": null}).to_string();
        let blob = encrypt_metadata(&fk, &envelope).unwrap();
        let blob_json = serde_json::to_string(&blob).unwrap();
        assert_eq!(decrypt_name(&mk, NAME_FID, &blob_json).unwrap(), "old.doc");
    }

    /// Web base64 blob encrypted under the **binary-UUID** key — both legacy
    /// dimensions at once (web shape + binary derivation).
    #[test]
    fn decrypt_name_web_base64_blob_binary_uuid_fallback() {
        let mk = name_master_key();
        let uuid: uuid::Uuid = NAME_FID.parse().unwrap();
        let fk = derive_file_key(&mk, uuid.as_bytes());
        let blob = web_base64_blob(&fk, "binary-key.png");
        assert_eq!(decrypt_name(&mk, NAME_FID, &blob).unwrap(), "binary-key.png");
    }

    /// A wrong master key fails cleanly with `Decryption` after trying every
    /// (key, format) combination — no panic, no partial result.
    #[test]
    fn decrypt_name_wrong_key_fails() {
        let mk = name_master_key();
        let enc = encrypt_name(&mk, NAME_FID, "secret.txt", None).unwrap();
        let wrong = derive_master_key("other-password", b"other-salt-16byte").unwrap();
        assert!(matches!(
            decrypt_name(&wrong, NAME_FID, &enc),
            Err(CoreError::Decryption)
        ));
    }

    /// A non-UUID file id still decrypts via the string-UUID key (binary
    /// derivation is simply skipped when the id won't parse as a UUID).
    #[test]
    fn decrypt_name_non_uuid_file_id_uses_string_key() {
        let mk = name_master_key();
        let fid = "not-a-uuid-just-a-string";
        let enc = encrypt_name(&mk, fid, "named.bin", None).unwrap();
        assert_eq!(decrypt_name(&mk, fid, &enc).unwrap(), "named.bin");
    }

    /// `decrypt_name_with_key` (the known-file-key entry point used by
    /// file-request uploads) handles both the native and web base64 blobs.
    #[test]
    fn decrypt_name_with_key_handles_both_blob_formats() {
        let mk = name_master_key();
        let fk = derive_file_key(&mk, NAME_FID.as_bytes());

        let native = encrypt_name(&mk, NAME_FID, "via-key.pdf", Some("application/pdf")).unwrap();
        assert_eq!(decrypt_name_with_key(&fk, &native).as_deref(), Some("via-key.pdf"));

        let web = web_base64_blob(&fk, &serde_json::json!({"name": "web-via-key.txt"}).to_string());
        assert_eq!(decrypt_name_with_key(&fk, &web).as_deref(), Some("web-via-key.txt"));

        // Plaintext fast path also works on the known-key entry point.
        assert_eq!(decrypt_name_with_key(&fk, "Inbox").as_deref(), Some("Inbox"));
    }
}
