use std::sync::{Arc, Mutex};

use zeroize::Zeroize;

use beebeeb_core::constellation;
use beebeeb_core::encrypt;
use beebeeb_core::kdf;
use beebeeb_core::recovery;
use beebeeb_types::{CipherSuite, EncryptedBlob};

uniffi::setup_scaffolding!();

// ---------------------------------------------------------------------------
// Error type — UniFFI-compatible enum
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum CryptoError {
    #[error("encryption failed: {detail}")]
    Encryption { detail: String },

    #[error("decryption failed: ciphertext is invalid or key is wrong")]
    Decryption,

    #[error("key derivation failed: {detail}")]
    Kdf { detail: String },

    #[error("invalid recovery phrase")]
    InvalidRecoveryPhrase,

    #[error("invalid input: {detail}")]
    InvalidInput { detail: String },

    #[error("OPAQUE protocol error: {detail}")]
    Opaque { detail: String },
}

impl From<beebeeb_core::CoreError> for CryptoError {
    fn from(e: beebeeb_core::CoreError) -> Self {
        match e {
            beebeeb_core::CoreError::Encryption(s) => CryptoError::Encryption { detail: s },
            beebeeb_core::CoreError::Decryption => CryptoError::Decryption,
            beebeeb_core::CoreError::Kdf(s) => CryptoError::Kdf { detail: s },
            beebeeb_core::CoreError::InvalidRecoveryPhrase => CryptoError::InvalidRecoveryPhrase,
            beebeeb_core::CoreError::InvalidInput(s) => CryptoError::InvalidInput { detail: s },
            beebeeb_core::CoreError::Opaque(s) => CryptoError::Opaque { detail: s },
        }
    }
}

// ---------------------------------------------------------------------------
// Return types — UniFFI records
// ---------------------------------------------------------------------------

/// Result of encrypting a chunk or metadata. Contains the cipher suite
/// identifier, a random nonce, and the ciphertext (including the GCM tag).
#[derive(uniffi::Record)]
pub struct EncryptedData {
    pub cipher_suite: String,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

/// Master key bytes returned from `derive_master_key`.
#[derive(uniffi::Record)]
pub struct MasterKeyResult {
    pub key: Vec<u8>,
}

/// Result of starting an OPAQUE registration or login.
#[derive(uniffi::Record)]
pub struct OpaqueStartResult {
    pub message: Vec<u8>,
    pub state: Vec<u8>,
}

/// Result of finishing an OPAQUE client login.
#[derive(uniffi::Record)]
pub struct OpaqueLoginFinishResult {
    pub message: Vec<u8>,
    pub session_key: Vec<u8>,
    pub export_key: Vec<u8>,
}

/// Result of generating a recovery phrase.
#[derive(uniffi::Record)]
pub struct RecoveryPhraseResult {
    pub phrase: String,
    pub master_key: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn file_key_from_slice(key: &[u8]) -> Result<kdf::FileKey, CryptoError> {
    let mut bytes: [u8; 32] = key.try_into().map_err(|_| CryptoError::InvalidInput {
        detail: "key must be exactly 32 bytes".into(),
    })?;
    let fk = kdf::FileKey::from_bytes(bytes);
    bytes.zeroize();
    Ok(fk)
}

fn master_key_from_slice(key: &[u8]) -> Result<kdf::MasterKey, CryptoError> {
    let mut bytes: [u8; 32] = key.try_into().map_err(|_| CryptoError::InvalidInput {
        detail: "master_key must be exactly 32 bytes".into(),
    })?;
    let mk = kdf::MasterKey::from_bytes(bytes);
    bytes.zeroize();
    Ok(mk)
}

fn encrypted_blob_to_data(blob: &EncryptedBlob) -> EncryptedData {
    let suite = match blob.cipher_suite {
        CipherSuite::V1Aes256Gcm => "V1Aes256Gcm",
    };
    EncryptedData {
        cipher_suite: suite.to_string(),
        nonce: blob.nonce.clone(),
        ciphertext: blob.ciphertext.clone(),
    }
}

// ---------------------------------------------------------------------------
// Key derivation
// ---------------------------------------------------------------------------

/// Derive a 32-byte master key from a password and salt (>= 16 bytes) via
/// Argon2id. Returns the key bytes.
#[uniffi::export]
pub fn derive_master_key(password: String, salt: Vec<u8>) -> Result<MasterKeyResult, CryptoError> {
    let mk = kdf::derive_master_key(&password, &salt)?;
    let bytes = mk.to_bytes();
    Ok(MasterKeyResult { key: bytes.to_vec() })
}

/// Derive a per-file encryption key from a master key and file ID via
/// HKDF-SHA256. Returns the 32-byte file key.
#[uniffi::export]
pub fn derive_file_key(master_key: Vec<u8>, file_id: Vec<u8>) -> Result<Vec<u8>, CryptoError> {
    let mk = master_key_from_slice(&master_key)?;
    let fk = kdf::derive_file_key(&mk, &file_id);
    Ok(fk.as_bytes().to_vec())
}

// ---------------------------------------------------------------------------
// Encryption
// ---------------------------------------------------------------------------

/// Encrypt a plaintext chunk with AES-256-GCM. Returns the encrypted data
/// containing cipher suite, nonce, and ciphertext.
#[uniffi::export]
pub fn encrypt_chunk(key: Vec<u8>, plaintext: Vec<u8>) -> Result<EncryptedData, CryptoError> {
    let fk = file_key_from_slice(&key)?;
    let blob = encrypt::encrypt_chunk(&fk, &plaintext)?;
    Ok(encrypted_blob_to_data(&blob))
}

/// Decrypt a ciphertext chunk that was produced by `encrypt_chunk`.
#[uniffi::export]
pub fn decrypt_chunk(key: Vec<u8>, nonce: Vec<u8>, ciphertext: Vec<u8>) -> Result<Vec<u8>, CryptoError> {
    let fk = file_key_from_slice(&key)?;
    let blob = EncryptedBlob {
        cipher_suite: CipherSuite::V1Aes256Gcm,
        nonce,
        ciphertext,
    };
    Ok(encrypt::decrypt_chunk(&fk, &blob)?)
}

// ---------------------------------------------------------------------------
// Metadata
// ---------------------------------------------------------------------------

/// Encrypt a UTF-8 metadata string (filename, path, etc.) with AES-256-GCM.
#[uniffi::export]
pub fn encrypt_metadata(key: Vec<u8>, metadata: String) -> Result<EncryptedData, CryptoError> {
    let fk = file_key_from_slice(&key)?;
    let blob = encrypt::encrypt_metadata(&fk, &metadata)?;
    Ok(encrypted_blob_to_data(&blob))
}

/// Decrypt a metadata blob back to a UTF-8 string.
#[uniffi::export]
pub fn decrypt_metadata(key: Vec<u8>, nonce: Vec<u8>, ciphertext: Vec<u8>) -> Result<String, CryptoError> {
    let fk = file_key_from_slice(&key)?;
    let blob = EncryptedBlob {
        cipher_suite: CipherSuite::V1Aes256Gcm,
        nonce,
        ciphertext,
    };
    Ok(encrypt::decrypt_metadata(&fk, &blob)?)
}

// ---------------------------------------------------------------------------
// Recovery phrase
// ---------------------------------------------------------------------------

/// Generate a new 12-word BIP39 recovery phrase and the corresponding master
/// key. The phrase IS the master secret.
#[uniffi::export]
pub fn generate_recovery_phrase() -> Result<RecoveryPhraseResult, CryptoError> {
    let (phrase, mk) = recovery::generate_recovery_phrase()?;
    let bytes = mk.to_bytes();
    Ok(RecoveryPhraseResult {
        phrase,
        master_key: bytes.to_vec(),
    })
}

/// Recover a master key from a 12-word BIP39 recovery phrase.
/// Returns the 32-byte master key.
#[uniffi::export]
pub fn recover_from_phrase(phrase: String) -> Result<Vec<u8>, CryptoError> {
    let mk = recovery::recover_from_phrase(&phrase)?;
    Ok(mk.to_bytes().to_vec())
}

// ---------------------------------------------------------------------------
// OPAQUE protocol
// ---------------------------------------------------------------------------

/// Start OPAQUE client registration. Returns the registration message and
/// client state (both needed for the finish step).
#[uniffi::export]
pub fn opaque_registration_start(password: Vec<u8>) -> Result<OpaqueStartResult, CryptoError> {
    let result = beebeeb_core::opaque_protocol::client_registration_start(&password)?;
    Ok(OpaqueStartResult {
        message: result.message,
        state: result.state,
    })
}

/// Finish OPAQUE client registration. Takes the client state from the start
/// step, the password, and the server's response. Returns the registration
/// upload bytes to send to the server.
#[uniffi::export]
pub fn opaque_registration_finish(
    client_state: Vec<u8>,
    password: Vec<u8>,
    server_response: Vec<u8>,
) -> Result<Vec<u8>, CryptoError> {
    Ok(beebeeb_core::opaque_protocol::client_registration_finish(
        &client_state,
        &password,
        &server_response,
    )?)
}

/// Start OPAQUE client login. Returns the login message and client state.
#[uniffi::export]
pub fn opaque_login_start(password: Vec<u8>) -> Result<OpaqueStartResult, CryptoError> {
    let result = beebeeb_core::opaque_protocol::client_login_start(&password)?;
    Ok(OpaqueStartResult {
        message: result.message,
        state: result.state,
    })
}

/// Finish OPAQUE client login. Returns the finalization message, the session
/// key, and the export key (used to derive the master key envelope).
#[uniffi::export]
pub fn opaque_login_finish(
    client_state: Vec<u8>,
    password: Vec<u8>,
    server_response: Vec<u8>,
) -> Result<OpaqueLoginFinishResult, CryptoError> {
    let result = beebeeb_core::opaque_protocol::client_login_finish(&client_state, &password, &server_response)?;
    Ok(OpaqueLoginFinishResult {
        message: result.message,
        session_key: result.session_key,
        export_key: result.export_key,
    })
}

// ---------------------------------------------------------------------------
// X25519 identity + sharing
// ---------------------------------------------------------------------------

/// Derive an X25519 secret scalar from a master key. Returns 32 bytes.
#[uniffi::export]
pub fn derive_x25519_private(master_key: Vec<u8>) -> Result<Vec<u8>, CryptoError> {
    let mk = master_key_from_slice(&master_key)?;
    Ok(beebeeb_core::opaque::derive_x25519_private(&mk).to_vec())
}

/// Derive an X25519 public point from a secret scalar. Returns 32 bytes.
#[uniffi::export]
pub fn derive_x25519_public(private_key: Vec<u8>) -> Result<Vec<u8>, CryptoError> {
    let pk: [u8; 32] = private_key.try_into().map_err(|_| CryptoError::InvalidInput {
        detail: "secret scalar must be 32 bytes".into(),
    })?;
    Ok(beebeeb_core::opaque::derive_x25519_public(&pk).to_vec())
}

/// Compute an X25519 shared secret from my secret scalar and their public point.
/// Returns 32-byte shared secret.
#[uniffi::export]
pub fn x25519_shared_secret(my_private: Vec<u8>, their_public: Vec<u8>) -> Result<Vec<u8>, CryptoError> {
    let priv_key: [u8; 32] = my_private.try_into().map_err(|_| CryptoError::InvalidInput {
        detail: "secret scalar must be 32 bytes".into(),
    })?;
    let pub_key: [u8; 32] = their_public.try_into().map_err(|_| CryptoError::InvalidInput {
        detail: "public key must be 32 bytes".into(),
    })?;
    Ok(beebeeb_core::opaque::x25519_shared_secret(&priv_key, &pub_key).to_vec())
}

/// Derive a share key from a shared secret and file ID. Returns 32-byte share key.
#[uniffi::export]
pub fn derive_share_key(shared_secret: Vec<u8>, file_id: Vec<u8>) -> Result<Vec<u8>, CryptoError> {
    let ss: [u8; 32] = shared_secret.try_into().map_err(|_| CryptoError::InvalidInput {
        detail: "shared_secret must be 32 bytes".into(),
    })?;
    Ok(beebeeb_core::opaque::derive_share_key(&ss, &file_id).to_vec())
}

/// Compute a recovery check value from a master key. Returns 32-byte check value.
/// This is stored server-side so we can verify a recovery phrase produces the
/// correct master key.
#[uniffi::export]
pub fn compute_recovery_check(master_key: Vec<u8>) -> Result<Vec<u8>, CryptoError> {
    let mk = master_key_from_slice(&master_key)?;
    Ok(beebeeb_core::opaque::compute_recovery_check(&mk).to_vec())
}

// ---------------------------------------------------------------------------
// Object handles — keys stay in Rust memory; only export_for_keychain crosses
// ---------------------------------------------------------------------------

/// Opaque handle to a MasterKey. The key bytes never leave Rust except via
/// `export_for_keychain`, which is only called once to persist to the OS keychain.
#[derive(uniffi::Object)]
pub struct MasterKeyHandle {
    inner: Mutex<Option<kdf::MasterKey>>,
}

impl MasterKeyHandle {
    fn new(mk: kdf::MasterKey) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(Some(mk)),
        })
    }

    fn with_key<T, F: FnOnce(&kdf::MasterKey) -> T>(&self, f: F) -> Result<T, CryptoError> {
        let guard = self.inner.lock().unwrap();
        guard.as_ref().map(f).ok_or(CryptoError::InvalidInput {
            detail: "key handle has been cleared".into(),
        })
    }
}

#[uniffi::export]
impl MasterKeyHandle {
    /// Reconstruct a MasterKeyHandle from a 12-word BIP39 recovery phrase.
    #[uniffi::constructor]
    pub fn from_recovery_phrase(phrase: String) -> Result<Arc<Self>, CryptoError> {
        let mk = recovery::recover_from_phrase(&phrase)?;
        Ok(Self::new(mk))
    }

    /// Reconstruct a MasterKeyHandle from 32 raw bytes read from the OS keychain.
    #[uniffi::constructor]
    pub fn from_keychain_bytes(bytes: Vec<u8>) -> Result<Arc<Self>, CryptoError> {
        let arr: [u8; 32] = bytes.try_into().map_err(|_| CryptoError::InvalidInput {
            detail: "keychain bytes must be exactly 32 bytes".into(),
        })?;
        let mk = kdf::MasterKey::from_bytes(arr);
        Ok(Self::new(mk))
    }

    /// Derive a FileKeyHandle for the given file ID.
    pub fn derive_file_key(&self, file_id: Vec<u8>) -> Result<Arc<FileKeyHandle>, CryptoError> {
        self.with_key(|mk| {
            let fk = kdf::derive_file_key(mk, &file_id);
            FileKeyHandle::new(fk)
        })
    }

    /// Derive the X25519 secret scalar from the master key. Returns 32 bytes.
    pub fn derive_x25519_private(&self) -> Result<Vec<u8>, CryptoError> {
        self.with_key(|mk| beebeeb_core::opaque::derive_x25519_private(mk).to_vec())
    }

    /// Export the raw 32-byte key for writing to the OS keychain.
    /// Only call this once at account setup; never log or transmit the result.
    pub fn export_for_keychain(&self) -> Result<Vec<u8>, CryptoError> {
        self.with_key(|mk| mk.to_bytes().to_vec())
    }

    /// Compute the recovery-check value (stored server-side to verify the phrase).
    pub fn compute_recovery_check(&self) -> Result<Vec<u8>, CryptoError> {
        self.with_key(|mk| beebeeb_core::opaque::compute_recovery_check(mk).to_vec())
    }
}

/// Opaque handle to a FileKey. Created via `MasterKeyHandle::derive_file_key`.
#[derive(uniffi::Object)]
pub struct FileKeyHandle {
    inner: Mutex<Option<kdf::FileKey>>,
}

impl FileKeyHandle {
    fn new(fk: kdf::FileKey) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(Some(fk)),
        })
    }

    fn with_key<T, F: FnOnce(&kdf::FileKey) -> T>(&self, f: F) -> Result<T, CryptoError> {
        let guard = self.inner.lock().unwrap();
        guard.as_ref().map(f).ok_or(CryptoError::InvalidInput {
            detail: "key handle has been cleared".into(),
        })
    }
}

#[uniffi::export]
impl FileKeyHandle {
    pub fn encrypt_chunk(&self, plaintext: Vec<u8>) -> Result<EncryptedData, CryptoError> {
        self.with_key(|fk| encrypt::encrypt_chunk(fk, &plaintext))?
            .map(|blob| encrypted_blob_to_data(&blob))
            .map_err(Into::into)
    }

    pub fn decrypt_chunk(&self, nonce: Vec<u8>, ciphertext: Vec<u8>) -> Result<Vec<u8>, CryptoError> {
        let blob = EncryptedBlob {
            cipher_suite: CipherSuite::V1Aes256Gcm,
            nonce,
            ciphertext,
        };
        self.with_key(|fk| encrypt::decrypt_chunk(fk, &blob))?
            .map_err(Into::into)
    }

    pub fn encrypt_metadata(&self, metadata: String) -> Result<EncryptedData, CryptoError> {
        self.with_key(|fk| encrypt::encrypt_metadata(fk, &metadata))?
            .map(|blob| encrypted_blob_to_data(&blob))
            .map_err(Into::into)
    }

    pub fn decrypt_metadata(&self, nonce: Vec<u8>, ciphertext: Vec<u8>) -> Result<String, CryptoError> {
        let blob = EncryptedBlob {
            cipher_suite: CipherSuite::V1Aes256Gcm,
            nonce,
            ciphertext,
        };
        self.with_key(|fk| encrypt::decrypt_metadata(fk, &blob))?
            .map_err(Into::into)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SALT: &[u8] = b"test-salt-16bytes";
    const TEST_FILE_ID: &[u8] = b"file-0001";

    #[test]
    fn roundtrip_derive_master_key() {
        let result = derive_master_key("password".into(), TEST_SALT.to_vec()).unwrap();
        assert_eq!(result.key.len(), 32);
    }

    #[test]
    fn roundtrip_derive_file_key() {
        let mk = derive_master_key("password".into(), TEST_SALT.to_vec()).unwrap();
        let fk = derive_file_key(mk.key, TEST_FILE_ID.to_vec()).unwrap();
        assert_eq!(fk.len(), 32);
    }

    #[test]
    fn roundtrip_encrypt_decrypt_chunk() {
        let mk = derive_master_key("password".into(), TEST_SALT.to_vec()).unwrap();
        let fk = derive_file_key(mk.key, TEST_FILE_ID.to_vec()).unwrap();
        let plaintext = b"hello, beebeeb!";

        let encrypted = encrypt_chunk(fk.clone(), plaintext.to_vec()).unwrap();
        assert_eq!(encrypted.cipher_suite, "V1Aes256Gcm");

        let decrypted = decrypt_chunk(fk, encrypted.nonce, encrypted.ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn roundtrip_encrypt_decrypt_metadata() {
        let mk = derive_master_key("password".into(), TEST_SALT.to_vec()).unwrap();
        let fk = derive_file_key(mk.key, TEST_FILE_ID.to_vec()).unwrap();
        let filename = "photos/vacation/IMG_2024.jpg";

        let encrypted = encrypt_metadata(fk.clone(), filename.into()).unwrap();
        let recovered = decrypt_metadata(fk, encrypted.nonce, encrypted.ciphertext).unwrap();
        assert_eq!(recovered, filename);
    }

    #[test]
    fn roundtrip_recovery_phrase() {
        let result = generate_recovery_phrase().unwrap();
        let words: Vec<&str> = result.phrase.split_whitespace().collect();
        assert_eq!(words.len(), 12);
        assert_eq!(result.master_key.len(), 32);

        let recovered = recover_from_phrase(result.phrase).unwrap();
        assert_eq!(recovered, result.master_key);
    }

    #[test]
    fn opaque_registration_start_works() {
        let result = opaque_registration_start(b"test-password".to_vec()).unwrap();
        assert!(!result.message.is_empty());
        assert!(!result.state.is_empty());
    }

    #[test]
    fn opaque_login_start_works() {
        let result = opaque_login_start(b"test-password".to_vec()).unwrap();
        assert!(!result.message.is_empty());
        assert!(!result.state.is_empty());
    }

    #[test]
    fn x25519_keypair_roundtrip() {
        let mk = derive_master_key("password".into(), TEST_SALT.to_vec()).unwrap();
        let private = derive_x25519_private(mk.key).unwrap();
        assert_eq!(private.len(), 32);

        let public = derive_x25519_public(private.clone()).unwrap();
        assert_eq!(public.len(), 32);
        assert_ne!(private, public);
    }

    #[test]
    fn x25519_shared_secret_works() {
        let mk_a = derive_master_key("alice".into(), TEST_SALT.to_vec()).unwrap();
        let mk_b = derive_master_key("bob-b".into(), TEST_SALT.to_vec()).unwrap();

        let priv_a = derive_x25519_private(mk_a.key).unwrap();
        let pub_a = derive_x25519_public(priv_a.clone()).unwrap();
        let priv_b = derive_x25519_private(mk_b.key).unwrap();
        let pub_b = derive_x25519_public(priv_b.clone()).unwrap();

        let shared_ab = x25519_shared_secret(priv_a, pub_b).unwrap();
        let shared_ba = x25519_shared_secret(priv_b, pub_a).unwrap();
        assert_eq!(shared_ab, shared_ba);
    }

    #[test]
    fn derive_share_key_works() {
        let mk_a = derive_master_key("alice".into(), TEST_SALT.to_vec()).unwrap();
        let mk_b = derive_master_key("bob-b".into(), TEST_SALT.to_vec()).unwrap();

        let priv_a = derive_x25519_private(mk_a.key).unwrap();
        let pub_b = derive_x25519_public(derive_x25519_private(mk_b.key).unwrap()).unwrap();

        let shared = x25519_shared_secret(priv_a, pub_b).unwrap();
        let sk = derive_share_key(shared, b"test-file-uuid".to_vec()).unwrap();
        assert_eq!(sk.len(), 32);
    }

    #[test]
    fn compute_recovery_check_works() {
        let mk = derive_master_key("password".into(), TEST_SALT.to_vec()).unwrap();
        let check = compute_recovery_check(mk.key).unwrap();
        assert_eq!(check.len(), 32);
    }

    #[test]
    fn wrong_key_size_returns_error() {
        let result = derive_file_key(vec![0u8; 16], TEST_FILE_ID.to_vec());
        assert!(result.is_err());
    }

    // --- MasterKeyHandle tests ---

    #[test]
    fn master_key_handle_from_recovery_phrase_roundtrip() {
        let phrase_result = generate_recovery_phrase().unwrap();
        let handle = MasterKeyHandle::from_recovery_phrase(phrase_result.phrase.clone()).unwrap();
        // export_for_keychain should return the same bytes as the free function
        let exported = handle.export_for_keychain().unwrap();
        assert_eq!(exported, phrase_result.master_key);
    }

    #[test]
    fn master_key_handle_from_keychain_bytes() {
        let mk = derive_master_key("password".into(), TEST_SALT.to_vec()).unwrap();
        let handle = MasterKeyHandle::from_keychain_bytes(mk.key.clone()).unwrap();
        let exported = handle.export_for_keychain().unwrap();
        assert_eq!(exported, mk.key);
    }

    #[test]
    fn master_key_handle_bad_keychain_bytes() {
        let result = MasterKeyHandle::from_keychain_bytes(vec![0u8; 16]);
        assert!(result.is_err());
    }

    #[test]
    fn master_key_handle_derive_file_key() {
        let mk = derive_master_key("password".into(), TEST_SALT.to_vec()).unwrap();
        let handle = MasterKeyHandle::from_keychain_bytes(mk.key).unwrap();
        let fk_handle = handle.derive_file_key(TEST_FILE_ID.to_vec()).unwrap();

        // Encrypt then decrypt via the FileKeyHandle
        let plaintext = b"handle roundtrip";
        let enc = fk_handle.encrypt_chunk(plaintext.to_vec()).unwrap();
        let dec = fk_handle.decrypt_chunk(enc.nonce, enc.ciphertext).unwrap();
        assert_eq!(dec, plaintext);
    }

    #[test]
    fn master_key_handle_derive_x25519() {
        let mk = derive_master_key("password".into(), TEST_SALT.to_vec()).unwrap();
        let handle = MasterKeyHandle::from_keychain_bytes(mk.key.clone()).unwrap();
        let priv_via_handle = handle.derive_x25519_private().unwrap();
        let priv_via_free = derive_x25519_private(mk.key).unwrap();
        assert_eq!(priv_via_handle, priv_via_free);
    }

    #[test]
    fn master_key_handle_recovery_check() {
        let mk = derive_master_key("password".into(), TEST_SALT.to_vec()).unwrap();
        let handle = MasterKeyHandle::from_keychain_bytes(mk.key.clone()).unwrap();
        let check_via_handle = handle.compute_recovery_check().unwrap();
        let check_via_free = compute_recovery_check(mk.key).unwrap();
        assert_eq!(check_via_handle, check_via_free);
    }

    // --- FileKeyHandle tests ---

    #[test]
    fn file_key_handle_encrypt_decrypt_metadata() {
        let mk = derive_master_key("password".into(), TEST_SALT.to_vec()).unwrap();
        let handle = MasterKeyHandle::from_keychain_bytes(mk.key).unwrap();
        let fk_handle = handle.derive_file_key(TEST_FILE_ID.to_vec()).unwrap();

        let name = "documents/taxes/2025.pdf";
        let enc = fk_handle.encrypt_metadata(name.into()).unwrap();
        let dec = fk_handle.decrypt_metadata(enc.nonce, enc.ciphertext).unwrap();
        assert_eq!(dec, name);
    }

    // --- Constellation tests ---

    #[test]
    fn constellation_session_roundtrip() {
        let init = constellation_new_session(300);
        assert_eq!(init.confirm_code.len(), 6);

        let decoder = ConstellationDecoderHandle::new();
        let mut recovered: Option<ConstellationPayloadDto> = None;
        for frame_index in 0..16u32 {
            let frame = constellation_encode(init.payload.clone(), frame_index).unwrap();
            let observations: Vec<ObservedNodeDto> = frame
                .nodes
                .iter()
                .enumerate()
                .map(|(i, n)| ObservedNodeDto {
                    idx: i as u32,
                    brightness: n.brightness,
                    confidence: 1.0,
                })
                .collect();
            recovered = decoder.ingest_frame(observations);
            if recovered.is_some() {
                break;
            }
        }
        let recovered = recovered.expect("decoder recovers payload");
        assert_eq!(recovered.session_id, init.payload.session_id);
        assert_eq!(recovered.ephemeral_pubkey, init.payload.ephemeral_pubkey);
        assert!(constellation_verify_code(recovered, init.confirm_code));
    }
}

// ---------------------------------------------------------------------------
// Constellation visual auth codec
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, uniffi::Record)]
pub struct ConstellationPayloadDto {
    pub session_id: Vec<u8>,
    pub ephemeral_pubkey: Vec<u8>,
    pub nonce: Vec<u8>,
    pub expires_at_unix_ms: u64,
    pub confirm_code_hash: Vec<u8>,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct ConstellationNodeDto {
    pub kind: u8,
    pub x: f32,
    pub y: f32,
    pub z: f32,
    pub brightness: f32,
    pub pulse_phase: f32,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct ConstellationEdgeDto {
    pub from_idx: u32,
    pub to_idx: u32,
    pub weight: f32,
    pub flow_speed: f32,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct ConstellationFrameDto {
    pub frame_index: u32,
    pub seed: u64,
    pub nodes: Vec<ConstellationNodeDto>,
    pub edges: Vec<ConstellationEdgeDto>,
    pub ring_phase: f32,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct ConstellationSessionInitDto {
    pub payload: ConstellationPayloadDto,
    pub confirm_code: String,
    pub ephemeral_private: Vec<u8>,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct ObservedNodeDto {
    pub idx: u32,
    pub brightness: f32,
    pub confidence: f32,
}

fn payload_to_dto(p: &constellation::ConstellationPayload) -> ConstellationPayloadDto {
    ConstellationPayloadDto {
        session_id: p.session_id.to_vec(),
        ephemeral_pubkey: p.ephemeral_pubkey.to_vec(),
        nonce: p.nonce.to_vec(),
        expires_at_unix_ms: p.expires_at_unix_ms,
        confirm_code_hash: p.confirm_code_hash.to_vec(),
    }
}

fn payload_from_dto(dto: &ConstellationPayloadDto) -> Result<constellation::ConstellationPayload, CryptoError> {
    let session_id: [u8; 16] = dto
        .session_id
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::InvalidInput {
            detail: "session_id must be 16 bytes".into(),
        })?;
    let ephemeral_pubkey: [u8; 32] =
        dto.ephemeral_pubkey
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::InvalidInput {
                detail: "ephemeral_pubkey must be 32 bytes".into(),
            })?;
    let nonce: [u8; 16] = dto.nonce.as_slice().try_into().map_err(|_| CryptoError::InvalidInput {
        detail: "nonce must be 16 bytes".into(),
    })?;
    let confirm_code_hash: [u8; 32] =
        dto.confirm_code_hash
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::InvalidInput {
                detail: "confirm_code_hash must be 32 bytes".into(),
            })?;
    Ok(constellation::ConstellationPayload {
        session_id,
        ephemeral_pubkey,
        nonce,
        expires_at_unix_ms: dto.expires_at_unix_ms,
        confirm_code_hash,
    })
}

/// Generate a fresh pairing session (display side).
#[uniffi::export]
pub fn constellation_new_session(expires_in_secs: u32) -> ConstellationSessionInitDto {
    let init = constellation::constellation_new_session(expires_in_secs);
    ConstellationSessionInitDto {
        payload: payload_to_dto(&init.payload),
        confirm_code: init.confirm_code,
        ephemeral_private: init.ephemeral_private.to_vec(),
    }
}

/// Encode `payload` into the visualisation frame at `frame_index`.
#[uniffi::export]
pub fn constellation_encode(
    payload: ConstellationPayloadDto,
    frame_index: u32,
) -> Result<ConstellationFrameDto, CryptoError> {
    let p = payload_from_dto(&payload)?;
    let frame = constellation::constellation_encode(&p, frame_index);
    Ok(ConstellationFrameDto {
        frame_index: frame.frame_index,
        seed: frame.seed,
        nodes: frame
            .nodes
            .into_iter()
            .map(|n| ConstellationNodeDto {
                kind: n.kind,
                x: n.x,
                y: n.y,
                z: n.z,
                brightness: n.brightness,
                pulse_phase: n.pulse_phase,
            })
            .collect(),
        edges: frame
            .edges
            .into_iter()
            .map(|e| ConstellationEdgeDto {
                from_idx: e.from_idx,
                to_idx: e.to_idx,
                weight: e.weight,
                flow_speed: e.flow_speed,
            })
            .collect(),
        ring_phase: frame.ring_phase,
    })
}

/// Constant-time verify a 6-digit code against a payload.
#[uniffi::export]
pub fn constellation_verify_code(payload: ConstellationPayloadDto, code: String) -> bool {
    let Ok(p) = payload_from_dto(&payload) else {
        return false;
    };
    constellation::constellation_verify_code(&p, &code)
}

/// Stateful decoder handle.
#[derive(uniffi::Object)]
pub struct ConstellationDecoderHandle {
    inner: constellation::ConstellationDecoder,
}

#[uniffi::export]
impl ConstellationDecoderHandle {
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: constellation::ConstellationDecoder::new(),
        })
    }

    /// Feed one observed frame. Returns the recovered payload when the
    /// codeword is complete, otherwise `None`.
    pub fn ingest_frame(&self, observations: Vec<ObservedNodeDto>) -> Option<ConstellationPayloadDto> {
        let obs: Vec<constellation::ObservedNode> = observations
            .into_iter()
            .map(|o| constellation::ObservedNode {
                idx: o.idx,
                brightness: o.brightness,
                confidence: o.confidence,
            })
            .collect();
        self.inner.ingest_frame(&obs).map(|p| payload_to_dto(&p))
    }

    pub fn progress(&self) -> f32 {
        self.inner.progress()
    }

    pub fn shards_collected(&self) -> u32 {
        self.inner.shards_collected()
    }

    pub fn frames_ingested(&self) -> u32 {
        self.inner.frames_ingested()
    }

    pub fn reset(&self) {
        self.inner.reset();
    }
}
