use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use rand::RngCore;

use beebeeb_types::{CipherSuite, EncryptedBlob};

use crate::CoreError;
use crate::kdf::FileKey;

const NONCE_LEN: usize = 12;

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
    }).to_string();
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
    let blob: EncryptedBlob = serde_json::from_str(name_encrypted)
        .map_err(|_| CoreError::Decryption)?;
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
    let blob: EncryptedBlob = serde_json::from_str(name_encrypted)
        .map_err(|_| CoreError::Decryption)?;
    let file_key = crate::kdf::derive_file_key(master_key, file_id.as_bytes());
    let decrypted = decrypt_metadata(&file_key, &blob)?;

    if let Ok(meta) = serde_json::from_str::<serde_json::Value>(&decrypted) {
        let name = meta.get("name").and_then(|v| v.as_str()).unwrap_or(&decrypted).to_string();
        let mime = meta.get("mime_type").and_then(|v| v.as_str()).map(|s| s.to_string());
        return Ok((name, mime));
    }
    Ok((decrypted, None))
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
    let cipher = Aes256Gcm::new_from_slice(key.as_bytes())
        .map_err(|e| CoreError::Encryption(e.to_string()))?;
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

/// Decrypt a raw binary chunk: nonce (12 bytes) || ciphertext.
pub fn decrypt_chunk_raw(key: &FileKey, raw: &[u8]) -> Result<Vec<u8>, CoreError> {
    if raw.len() < NONCE_LEN + 16 {
        return Err(CoreError::Decryption);
    }
    let (nonce_bytes, ciphertext) = raw.split_at(NONCE_LEN);
    let cipher = Aes256Gcm::new_from_slice(key.as_bytes())
        .map_err(|e| CoreError::Encryption(e.to_string()))?;
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| CoreError::Decryption)
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
    fn large_plaintext_roundtrip() {
        let key = test_file_key();
        let plaintext = vec![0x42u8; 1024 * 1024]; // 1 MiB
        let blob = encrypt_chunk(&key, &plaintext).unwrap();
        let decrypted = decrypt_chunk(&key, &blob).unwrap();
        assert_eq!(decrypted, plaintext);
    }
}
