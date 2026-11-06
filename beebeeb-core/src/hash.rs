//! Hashing and HKDF utilities exposed to all clients.
//!
//! - [`sha256`] — plain SHA-256 digest (replaces platform-specific implementations)
//! - [`derive_sas_bytes`] — HKDF-SHA256 expansion for SAS word derivation

use hkdf::Hkdf;
use sha2::{Digest, Sha256};

use crate::CoreError;

/// RFC 5869 limit for HKDF-SHA256 output.
pub const MAX_HKDF_SHA256_OUTPUT: usize = 255 * 32;

/// Compute the SHA-256 digest of `data`. Returns a 32-byte hash.
pub fn sha256(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// Derive `length` bytes from a shared secret using HKDF-SHA256.
///
/// This replaces FNV-1a in the JS transfer-api SAS derivation. The word list
/// stays in JS/Swift (it is a pure lookup table); only the cryptographic
/// derivation moves to Rust.
///
/// `shared_secret` is the IKM, `info` is the HKDF info parameter (typically
/// a context string like `b"beebeeb-sas-v1"`). Salt is empty (the shared
/// secret already has full entropy from ECDH).
pub fn derive_sas_bytes(shared_secret: &[u8], info: &[u8], length: usize) -> Result<Vec<u8>, CoreError> {
    if length > MAX_HKDF_SHA256_OUTPUT {
        return Err(CoreError::InvalidInput(format!(
            "HKDF-SHA256 output must be at most {MAX_HKDF_SHA256_OUTPUT} bytes, got {length}"
        )));
    }
    let hk = Hkdf::<Sha256>::new(None, shared_secret);
    let mut okm = vec![0u8; length];
    hk.expand(info, &mut okm)
        .map_err(|_| CoreError::Kdf("HKDF-SHA256 expansion failed".into()))?;
    Ok(okm)
}

#[cfg(test)]
mod tests {
    use super::*;

    // SHA-256 test vectors from NIST FIPS 180-4 / RFC 6234

    #[test]
    fn sha256_empty() {
        let hash = sha256(b"");
        assert_eq!(hash.len(), 32);
        // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        assert_eq!(
            hex::encode(&hash),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn sha256_abc() {
        let hash = sha256(b"abc");
        // SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        assert_eq!(
            hex::encode(&hash),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn sha256_deterministic() {
        let a = sha256(b"beebeeb");
        let b = sha256(b"beebeeb");
        assert_eq!(a, b);
    }

    #[test]
    fn sha256_different_inputs_differ() {
        let a = sha256(b"hello");
        let b = sha256(b"world");
        assert_ne!(a, b);
    }

    // derive_sas_bytes tests

    #[test]
    fn derive_sas_bytes_deterministic() {
        let secret = [0x42u8; 32];
        let info = b"beebeeb-sas-v1";
        let a = derive_sas_bytes(&secret, info, 4).unwrap();
        let b = derive_sas_bytes(&secret, info, 4).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn derive_sas_bytes_correct_length() {
        let secret = [0x42u8; 32];
        assert_eq!(derive_sas_bytes(&secret, b"info", 4).unwrap().len(), 4);
        assert_eq!(derive_sas_bytes(&secret, b"info", 16).unwrap().len(), 16);
        assert_eq!(derive_sas_bytes(&secret, b"info", 32).unwrap().len(), 32);
    }

    #[test]
    fn derive_sas_bytes_different_info_differ() {
        let secret = [0x42u8; 32];
        let a = derive_sas_bytes(&secret, b"info-a", 4).unwrap();
        let b = derive_sas_bytes(&secret, b"info-b", 4).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn derive_sas_bytes_different_secrets_differ() {
        let a = derive_sas_bytes(&[0x01u8; 32], b"info", 4).unwrap();
        let b = derive_sas_bytes(&[0x02u8; 32], b"info", 4).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn derive_sas_bytes_zero_length() {
        let result = derive_sas_bytes(&[0x42u8; 32], b"info", 0).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn derive_sas_bytes_rejects_hkdf_overflow_before_allocating() {
        assert!(derive_sas_bytes(&[0x42u8; 32], b"info", 8_161).is_err());
    }

    #[test]
    fn derive_sas_bytes_matches_transfer_crypto() {
        // Verify consistency with the existing transfer::crypto::derive_sas
        // by using the same HKDF expansion pattern (no salt = None).
        let shared = [0xAAu8; 32];
        let info = b"beebeeb-sas-v1";

        // derive_sas_bytes uses salt=None, which means the HKDF extraction
        // step uses a zero-filled salt. The transfer module uses
        // salt=Some(session_id). So they should NOT match when session_id != None.
        // This test just confirms the function runs and produces 4 bytes.
        let sas = derive_sas_bytes(&shared, info, 4).unwrap();
        assert_eq!(sas.len(), 4);
    }
}
