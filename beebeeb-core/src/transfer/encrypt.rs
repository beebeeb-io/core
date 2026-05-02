//! AES-256-GCM transfer encryption with the derived transfer key.
//!
//! Wire format: `[12-byte random nonce][AES-256-GCM ciphertext+tag]`.
//! The nonce is fresh per-encryption — never reuse a `(transfer_key, nonce)` pair.

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use rand::RngCore;

use crate::CoreError;

const NONCE_LEN: usize = 12;

/// Encrypt `plaintext` under `key`. Returns `nonce || ciphertext` ready for the wire.
pub fn encrypt_transfer(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, CoreError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| CoreError::Encryption(e.to_string()))?;

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

/// Decrypt a `nonce || ciphertext` blob produced by [`encrypt_transfer`].
pub fn decrypt_transfer(key: &[u8; 32], blob: &[u8]) -> Result<Vec<u8>, CoreError> {
    if blob.len() < NONCE_LEN {
        return Err(CoreError::Decryption);
    }
    let (nonce_bytes, ciphertext) = blob.split_at(NONCE_LEN);

    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| CoreError::Encryption(e.to_string()))?;
    let nonce = Nonce::from_slice(nonce_bytes);

    cipher.decrypt(nonce, ciphertext).map_err(|_| CoreError::Decryption)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_encrypt_decrypt() {
        let key = [0x11u8; 32];
        let plaintext = b"hello constellation";
        let blob = encrypt_transfer(&key, plaintext).unwrap();
        assert!(blob.len() >= NONCE_LEN + plaintext.len());
        let decrypted = decrypt_transfer(&key, &blob).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn empty_plaintext_roundtrip() {
        let key = [0x22u8; 32];
        let blob = encrypt_transfer(&key, b"").unwrap();
        let decrypted = decrypt_transfer(&key, &blob).unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn large_plaintext_roundtrip() {
        let key = [0x33u8; 32];
        let plaintext = vec![0x55u8; 1024 * 1024];
        let blob = encrypt_transfer(&key, &plaintext).unwrap();
        let decrypted = decrypt_transfer(&key, &blob).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn wrong_key_fails_decryption() {
        let key = [0x11u8; 32];
        let blob = encrypt_transfer(&key, b"secret payload").unwrap();
        let wrong_key = [0x99u8; 32];
        assert!(decrypt_transfer(&wrong_key, &blob).is_err());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let key = [0x11u8; 32];
        let mut blob = encrypt_transfer(&key, b"sensitive").unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0xFF;
        assert!(decrypt_transfer(&key, &blob).is_err());
    }

    #[test]
    fn truncated_blob_fails() {
        let key = [0x11u8; 32];
        assert!(decrypt_transfer(&key, &[0u8; 4]).is_err());
        assert!(decrypt_transfer(&key, &[]).is_err());
    }

    #[test]
    fn nonces_are_unique_across_encryptions() {
        let key = [0x44u8; 32];
        let b1 = encrypt_transfer(&key, b"same").unwrap();
        let b2 = encrypt_transfer(&key, b"same").unwrap();
        assert_ne!(&b1[..NONCE_LEN], &b2[..NONCE_LEN]);
    }
}
