use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::CoreError;

/// 32-byte master key derived from a user password. Zeroized on drop.
/// Not `Clone` — use `Arc<MasterKey>` if multiple owners are needed.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MasterKey {
    bytes: [u8; 32],
}

impl MasterKey {
    pub(crate) fn from_zeroizing(mut src: Zeroizing<[u8; 32]>) -> Self {
        let mk = Self { bytes: *src };
        src.zeroize();
        mk
    }

    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

/// 32-byte file-encryption key derived from a master key. Zeroized on drop.
/// Not `Clone` — one key per file, one owner.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct FileKey {
    bytes: [u8; 32],
}

impl FileKey {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

const MIN_SALT_LEN: usize = 16;

/// Derive a master key from a user password and salt using Argon2id.
///
/// Parameters: memory = 256 MiB, iterations = 4, parallelism = 2, output = 32 bytes.
/// Salt must be at least 16 bytes (128 bits) per NIST SP 800-132.
pub fn derive_master_key(password: &str, salt: &[u8]) -> Result<MasterKey, CoreError> {
    if salt.len() < MIN_SALT_LEN {
        return Err(CoreError::InvalidInput(format!(
            "salt must be at least {MIN_SALT_LEN} bytes, got {}",
            salt.len()
        )));
    }

    let params =
        Params::new(256 * 1024, 4, 2, Some(32)).map_err(|e| CoreError::Kdf(format!("invalid argon2 params: {e}")))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut output = Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut *output)
        .map_err(|e| CoreError::Kdf(format!("argon2 hashing failed: {e}")))?;

    Ok(MasterKey::from_zeroizing(output))
}

/// Derive a per-file encryption key from a master key using HKDF-SHA256.
///
/// `file_id` must be unique per file (typically a random UUID assigned at creation).
/// This ensures each file gets its own key, limiting the blast radius of any single
/// key compromise and keeping AES-256-GCM nonce collision risk per-file.
pub fn derive_file_key(master_key: &MasterKey, file_id: &[u8]) -> FileKey {
    let hk = Hkdf::<Sha256>::new(None, master_key.as_bytes());

    let mut info = Vec::with_capacity(19 + file_id.len());
    info.extend_from_slice(b"beebeeb-file-key-v1");
    info.extend_from_slice(file_id);

    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(&info, &mut *okm)
        .expect("HKDF-SHA256 expand for 32 bytes cannot fail");
    FileKey { bytes: *okm }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SALT: &[u8] = b"test-salt-16bytes";
    const TEST_FILE_ID: &[u8] = b"file-0001";

    #[test]
    fn derive_master_key_produces_32_bytes() {
        let mk = derive_master_key("correct horse battery staple", TEST_SALT).unwrap();
        assert_eq!(mk.as_bytes().len(), 32);
    }

    #[test]
    fn derive_master_key_deterministic() {
        let mk1 = derive_master_key("password", TEST_SALT).unwrap();
        let mk2 = derive_master_key("password", TEST_SALT).unwrap();
        assert_eq!(mk1.as_bytes(), mk2.as_bytes());
    }

    #[test]
    fn different_passwords_yield_different_keys() {
        let mk1 = derive_master_key("alpha", TEST_SALT).unwrap();
        let mk2 = derive_master_key("bravo", TEST_SALT).unwrap();
        assert_ne!(mk1.as_bytes(), mk2.as_bytes());
    }

    #[test]
    fn different_salts_yield_different_keys() {
        let mk1 = derive_master_key("password", b"salt-aaaa-16bytes").unwrap();
        let mk2 = derive_master_key("password", b"salt-bbbb-16bytes").unwrap();
        assert_ne!(mk1.as_bytes(), mk2.as_bytes());
    }

    #[test]
    fn salt_too_short_returns_error() {
        let result = derive_master_key("password", b"short");
        assert!(result.is_err());
    }

    #[test]
    fn salt_exactly_16_bytes_succeeds() {
        let result = derive_master_key("password", b"exactly-16-bytes");
        assert!(result.is_ok());
    }

    #[test]
    fn derive_file_key_deterministic() {
        let mk = derive_master_key("password", TEST_SALT).unwrap();
        let fk1 = derive_file_key(&mk, TEST_FILE_ID);
        let fk2 = derive_file_key(&mk, TEST_FILE_ID);
        assert_eq!(fk1.as_bytes(), fk2.as_bytes());
    }

    #[test]
    fn file_key_differs_from_master_key() {
        let mk = derive_master_key("password", TEST_SALT).unwrap();
        let fk = derive_file_key(&mk, TEST_FILE_ID);
        assert_ne!(mk.as_bytes(), fk.as_bytes());
    }

    #[test]
    fn different_file_ids_yield_different_keys() {
        let mk = derive_master_key("password", TEST_SALT).unwrap();
        let fk1 = derive_file_key(&mk, b"file-A");
        let fk2 = derive_file_key(&mk, b"file-B");
        assert_ne!(fk1.as_bytes(), fk2.as_bytes());
    }

    #[test]
    fn empty_password_is_valid() {
        let result = derive_master_key("", TEST_SALT);
        assert!(result.is_ok());
    }
}
