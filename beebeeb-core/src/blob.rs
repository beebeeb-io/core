//! Blob encrypt/decrypt — thin wrappers around AES-256-GCM for opaque blobs.
//!
//! Used by the search index and anywhere a raw byte buffer needs authenticated
//! encryption with a caller-supplied 32-byte key. The wire format is simply
//! `nonce (12 bytes) || ciphertext (includes GCM tag)`.

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use rand::RngCore;

use crate::CoreError;

const NONCE_LEN: usize = 12;
const GCM_TAG_LEN: usize = 16;

/// Encrypt an arbitrary byte buffer with AES-256-GCM.
///
/// Returns `nonce (12 bytes) || ciphertext (plaintext + 16-byte GCM tag)`.
/// A fresh random nonce is generated for every call.
pub fn encrypt_blob(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, CoreError> {
    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|e| CoreError::Encryption(e.to_string()))?;

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

/// Decrypt a blob produced by [`encrypt_blob`].
///
/// Expects `nonce (12 bytes) || ciphertext`. Returns the original plaintext.
pub fn decrypt_blob(key: &[u8; 32], ciphertext: &[u8]) -> Result<Vec<u8>, CoreError> {
    if ciphertext.len() < NONCE_LEN + GCM_TAG_LEN {
        return Err(CoreError::Decryption);
    }

    let (nonce_bytes, ct) = ciphertext.split_at(NONCE_LEN);
    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|e| CoreError::Encryption(e.to_string()))?;
    let nonce = Nonce::from_slice(nonce_bytes);

    cipher
        .decrypt(nonce, ct)
        .map_err(|_| CoreError::Decryption)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> [u8; 32] {
        [0x42u8; 32]
    }

    #[test]
    fn roundtrip() {
        let key = test_key();
        let plaintext = b"search index entry";
        let encrypted = encrypt_blob(&key, plaintext).unwrap();
        assert!(encrypted.len() > NONCE_LEN + GCM_TAG_LEN);
        let decrypted = decrypt_blob(&key, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn empty_plaintext_roundtrip() {
        let key = test_key();
        let encrypted = encrypt_blob(&key, b"").unwrap();
        let decrypted = decrypt_blob(&key, &encrypted).unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn wrong_key_fails() {
        let encrypted = encrypt_blob(&[0x42u8; 32], b"secret").unwrap();
        assert!(decrypt_blob(&[0x99u8; 32], &encrypted).is_err());
    }

    #[test]
    fn truncated_ciphertext_fails() {
        assert!(decrypt_blob(&test_key(), &[0u8; 10]).is_err());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let key = test_key();
        let mut encrypted = encrypt_blob(&key, b"important").unwrap();
        // flip a byte in the ciphertext portion
        let last = encrypted.len() - 1;
        encrypted[last] ^= 0xFF;
        assert!(decrypt_blob(&key, &encrypted).is_err());
    }

    #[test]
    fn unique_nonces() {
        let key = test_key();
        let a = encrypt_blob(&key, b"same").unwrap();
        let b = encrypt_blob(&key, b"same").unwrap();
        assert_ne!(&a[..NONCE_LEN], &b[..NONCE_LEN]);
    }

    #[test]
    fn large_payload() {
        let key = test_key();
        let data = vec![0xABu8; 1024 * 1024]; // 1 MiB
        let encrypted = encrypt_blob(&key, &data).unwrap();
        let decrypted = decrypt_blob(&key, &encrypted).unwrap();
        assert_eq!(decrypted, data);
    }
}
