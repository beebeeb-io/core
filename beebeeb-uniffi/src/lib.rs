use std::sync::{Arc, Mutex};

use zeroize::Zeroize;

use beebeeb_core::chunk_stream::{ChunkDecryptor, ChunkEncryptor};
use beebeeb_core::constellation;
use beebeeb_core::encrypt;
use beebeeb_core::kdf;
use beebeeb_core::media;
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

    #[error("operation cancelled")]
    Cancelled,

    #[error("I/O error: {detail}")]
    Io { detail: String },
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
            beebeeb_core::CoreError::Cancelled => CryptoError::Cancelled,
            beebeeb_core::CoreError::Io(s) => CryptoError::Io { detail: s },
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

/// A single encrypted chunk (nonce + ciphertext) for batch decryption.
#[derive(uniffi::Record)]
pub struct EncryptedChunkData {
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

/// A request's X25519 private key wrapped under the owner's master key
/// (AES-256-GCM ciphertext + nonce). Stored server-side.
#[derive(uniffi::Record)]
pub struct WrappedRequestPrivate {
    pub wrapped: Vec<u8>,
    pub nonce: Vec<u8>,
}

/// A content key sealed to a request public key: the uploader's ephemeral
/// X25519 public key and the wrapped content key (raw `nonce ‖ ciphertext`).
#[derive(uniffi::Record)]
pub struct SealedRequestUpload {
    pub e_pub: Vec<u8>,
    pub wrapped_key: Vec<u8>,
}

/// Info about a single encrypted chunk written to disk by `encrypt_file`.
#[derive(uniffi::Record)]
pub struct EncryptedChunkInfo {
    pub chunk_index: u32,
    pub output_path: String,
    pub nonce: Vec<u8>,
    pub plaintext_size: u64,
    pub ciphertext_size: u64,
}

/// Result of encrypting a complete file to disk chunks.
#[derive(uniffi::Record)]
pub struct EncryptedFileInfo {
    pub chunks: Vec<EncryptedChunkInfo>,
    pub total_plaintext_bytes: u64,
    pub total_ciphertext_bytes: u64,
    pub chunk_size_bytes: u64,
}

/// Result of decrypting chunk files back to a single file.
#[derive(uniffi::Record)]
pub struct DecryptedFileInfo {
    pub output_path: String,
    pub total_bytes: u64,
    pub chunks_processed: u32,
}

/// Result of decrypting a name_encrypted blob with MIME type.
#[derive(uniffi::Record)]
pub struct DecryptedNameWithMime {
    pub name: String,
    pub mime_type: Option<String>,
}

/// Parsed encrypted metadata payload (nonce + ciphertext bytes).
#[derive(uniffi::Record)]
pub struct EncryptedMetadataParts {
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

// ---------------------------------------------------------------------------
// File progress callback — UniFFI callback interface for Swift/Kotlin
// ---------------------------------------------------------------------------

#[uniffi::export(callback_interface)]
pub trait FileProgressCallback: Send + Sync {
    fn on_progress(&self, chunks_completed: u32, chunks_total: u32);
}

/// Adapter: bridges the UniFFI callback interface to the core trait.
struct ProgressAdapter<'a> {
    inner: &'a dyn FileProgressCallback,
}

impl<'a> beebeeb_core::file_encrypt::FileProgressCallback for ProgressAdapter<'a> {
    fn on_progress(&self, chunks_completed: u32, chunks_total: u32) {
        self.inner.on_progress(chunks_completed, chunks_total);
    }
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

/// Decrypt a sequence of encrypted chunks and write the plaintext to a file.
///
/// Chunks are decrypted sequentially and written in order; peak memory is
/// bounded by the size of the largest single chunk's plaintext, not the
/// total file size. The output file is created (truncating any existing
/// file) before the first chunk.
///
/// On `Err`, the output file may exist on disk in a partially-written
/// state — the caller is responsible for deleting it so a downstream
/// cache layer does not treat the partial file as complete.
///
/// Returns the total number of plaintext bytes written.
#[uniffi::export]
pub fn decrypt_chunks_to_file(
    key: Vec<u8>,
    chunks: Vec<EncryptedChunkData>,
    output_path: String,
) -> Result<u64, CryptoError> {
    let fk = file_key_from_slice(&key)?;
    let chunk_pairs: Vec<(Vec<u8>, Vec<u8>)> = chunks.into_iter().map(|c| (c.nonce, c.ciphertext)).collect();
    encrypt::decrypt_chunks_to_file(&fk, chunk_pairs, &output_path).map_err(CryptoError::from)
}

/// Decrypt a contiguous encrypted body into a file.
///
/// `body` is the wire format produced by stacking encrypted chunks back
/// to back: each chunk is `nonce (12 bytes) || ciphertext (chunk_size +
/// 16 byte AES-GCM tag)`. All chunks but the last produce `chunk_size`
/// bytes of plaintext; the final chunk is whatever remains.
///
/// Compared to `decrypt_chunks_to_file`, this variant lets the caller
/// hand over the full encrypted blob without pre-slicing — Rust performs
/// the chunk boundaries internally. Saves N small `ByteArray` allocations
/// + per-chunk marshalling overhead across the FFI for files with many
/// chunks (a 100 MB / 1 MB-chunk file is one allocation here vs. 200
/// across the bridge with the pre-sliced variant).
///
/// Streams chunk-by-chunk — peak memory is one plaintext chunk, not the
/// full file. Returns the total number of plaintext bytes written.
///
/// On `Err`, the output file may exist on disk in a partially-written
/// state — the caller is responsible for deleting it so a downstream
/// cache layer does not treat the partial file as complete.
#[uniffi::export]
pub fn decrypt_contiguous_to_file(
    file_key: Vec<u8>,
    body: Vec<u8>,
    chunk_size: u64,
    output_path: String,
) -> Result<u64, CryptoError> {
    let fk = file_key_from_slice(&file_key)?;
    encrypt::decrypt_contiguous_to_file(&fk, &body, chunk_size, &output_path).map_err(CryptoError::from)
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
// Name encryption (encrypt_name / decrypt_name)
// ---------------------------------------------------------------------------

/// Encrypt a filename + optional MIME type into the canonical JSON envelope.
/// The result is a JSON string containing cipher_suite, nonce, and ciphertext.
#[uniffi::export]
pub fn encrypt_name(
    master_key: Vec<u8>,
    file_id: String,
    filename: String,
    mime_type: Option<String>,
) -> Result<String, CryptoError> {
    let mk = master_key_from_slice(&master_key)?;
    encrypt::encrypt_name(&mk, &file_id, &filename, mime_type.as_deref()).map_err(CryptoError::from)
}

/// Decrypt a `name_encrypted` JSON envelope back to a plaintext filename.
/// Handles both new format (`{"name":"...","mime_type":"..."}`) and legacy bare strings.
#[uniffi::export]
pub fn decrypt_name(master_key: Vec<u8>, file_id: String, name_encrypted: String) -> Result<String, CryptoError> {
    let mk = master_key_from_slice(&master_key)?;
    encrypt::decrypt_name(&mk, &file_id, &name_encrypted).map_err(CryptoError::from)
}

/// Decrypt a `name_encrypted` JSON envelope and return both the filename and
/// the MIME type (if present in the encrypted payload).
#[uniffi::export]
pub fn decrypt_name_with_mime(
    master_key: Vec<u8>,
    file_id: String,
    name_encrypted: String,
) -> Result<DecryptedNameWithMime, CryptoError> {
    let mk = master_key_from_slice(&master_key)?;
    let (name, mime) = encrypt::decrypt_name_with_mime(&mk, &file_id, &name_encrypted).map_err(CryptoError::from)?;
    Ok(DecryptedNameWithMime { name, mime_type: mime })
}

// ---------------------------------------------------------------------------
// Media utilities
// ---------------------------------------------------------------------------

/// Returns `true` if the given MIME type represents media (image or video).
/// Single source of truth for all clients.
#[uniffi::export]
pub fn is_media(mime_type: Option<String>) -> bool {
    media::is_media(mime_type.as_deref())
}

/// Guess the MIME type from a filename extension.
/// Returns `None` for unknown extensions.
#[uniffi::export]
pub fn guess_mime_type(filename: String) -> Option<String> {
    media::guess_mime_type(&filename).map(|s| s.to_string())
}

/// Returns `true` if the given MIME type can be previewed in-app.
#[uniffi::export]
fn is_previewable(mime_type: Option<String>) -> bool {
    beebeeb_core::media::is_previewable(mime_type.as_deref())
}

/// Returns `true` if the file extension indicates a previewable file.
#[uniffi::export]
fn is_previewable_by_extension(filename: String) -> bool {
    beebeeb_core::media::is_previewable_by_extension(&filename)
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
    let shared = beebeeb_core::opaque::x25519_shared_secret(&priv_key, &pub_key)
        .map_err(|e| CryptoError::InvalidInput { detail: e.to_string() })?;
    Ok(shared.to_vec())
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
// File requests (sealed-box / ECIES per request)
// ---------------------------------------------------------------------------

/// Derive the per-request private-key-wrapping key from the owner's master key.
/// Returns 32 bytes.
#[uniffi::export]
pub fn derive_request_wrap_key(master_key: Vec<u8>, request_id: Vec<u8>) -> Result<Vec<u8>, CryptoError> {
    let mk = master_key_from_slice(&master_key)?;
    Ok(beebeeb_core::file_request::derive_request_wrap_key(&mk, &request_id).to_vec())
}

/// Wrap a request's X25519 private key under the owner's master key.
#[uniffi::export]
pub fn wrap_request_private(
    master_key: Vec<u8>,
    request_id: Vec<u8>,
    r_priv: Vec<u8>,
) -> Result<WrappedRequestPrivate, CryptoError> {
    let mk = master_key_from_slice(&master_key)?;
    let r_priv_arr: [u8; 32] = r_priv.try_into().map_err(|_| CryptoError::InvalidInput {
        detail: "r_priv must be 32 bytes".into(),
    })?;
    let (wrapped, nonce) = beebeeb_core::file_request::wrap_request_private(&mk, &request_id, &r_priv_arr)?;
    Ok(WrappedRequestPrivate { wrapped, nonce })
}

/// Unwrap a request's X25519 private key. Returns 32 bytes.
#[uniffi::export]
pub fn unwrap_request_private(
    master_key: Vec<u8>,
    request_id: Vec<u8>,
    wrapped: Vec<u8>,
    nonce: Vec<u8>,
) -> Result<Vec<u8>, CryptoError> {
    let mk = master_key_from_slice(&master_key)?;
    let r_priv = beebeeb_core::file_request::unwrap_request_private(&mk, &request_id, &wrapped, &nonce)?;
    Ok(r_priv.to_vec())
}

/// Seal a content key to a request's public key (anonymous uploader path).
#[uniffi::export]
pub fn seal_to_request(
    r_pub: Vec<u8>,
    file_id: Vec<u8>,
    content_key: Vec<u8>,
) -> Result<SealedRequestUpload, CryptoError> {
    let r_pub_arr: [u8; 32] = r_pub.try_into().map_err(|_| CryptoError::InvalidInput {
        detail: "r_pub must be 32 bytes".into(),
    })?;
    let content_key_arr: [u8; 32] = content_key.try_into().map_err(|_| CryptoError::InvalidInput {
        detail: "content_key must be 32 bytes".into(),
    })?;
    let sealed = beebeeb_core::file_request::seal_to_request(&r_pub_arr, &file_id, &content_key_arr)?;
    Ok(SealedRequestUpload {
        e_pub: sealed.e_pub.to_vec(),
        wrapped_key: sealed.wrapped_key,
    })
}

/// Open a sealed request upload (owner decrypt path). Returns the 32-byte content key.
#[uniffi::export]
pub fn open_request_upload(
    r_priv: Vec<u8>,
    e_pub: Vec<u8>,
    file_id: Vec<u8>,
    wrapped_key: Vec<u8>,
) -> Result<Vec<u8>, CryptoError> {
    let r_priv_arr: [u8; 32] = r_priv.try_into().map_err(|_| CryptoError::InvalidInput {
        detail: "r_priv must be 32 bytes".into(),
    })?;
    let e_pub_arr: [u8; 32] = e_pub.try_into().map_err(|_| CryptoError::InvalidInput {
        detail: "e_pub must be 32 bytes".into(),
    })?;
    let content_key = beebeeb_core::file_request::open_request_upload(&r_priv_arr, &e_pub_arr, &file_id, &wrapped_key)?;
    Ok(content_key.to_vec())
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

    /// Encrypt a filename + optional MIME type using the handle's master key.
    pub fn encrypt_name(
        &self,
        file_id: String,
        filename: String,
        mime_type: Option<String>,
    ) -> Result<String, CryptoError> {
        self.with_key(|mk| encrypt::encrypt_name(mk, &file_id, &filename, mime_type.as_deref()))?
            .map_err(CryptoError::from)
    }

    /// Decrypt a `name_encrypted` envelope using the handle's master key.
    pub fn decrypt_name(&self, file_id: String, name_encrypted: String) -> Result<String, CryptoError> {
        self.with_key(|mk| encrypt::decrypt_name(mk, &file_id, &name_encrypted))?
            .map_err(CryptoError::from)
    }

    /// Decrypt a `name_encrypted` envelope and return both filename and MIME type.
    pub fn decrypt_name_with_mime(
        &self,
        file_id: String,
        name_encrypted: String,
    ) -> Result<DecryptedNameWithMime, CryptoError> {
        let (name, mime) = self
            .with_key(|mk| encrypt::decrypt_name_with_mime(mk, &file_id, &name_encrypted))?
            .map_err(CryptoError::from)?;
        Ok(DecryptedNameWithMime { name, mime_type: mime })
    }

    /// Encrypt a file from disk, writing each chunk as a `.enc` file.
    ///
    /// Reads the input file chunk-by-chunk, encrypts with AES-256-GCM,
    /// writes `nonce || ciphertext` to `{output_dir}/{chunk_index}.enc`.
    /// Peak memory: 2x chunk_size.
    ///
    /// `profile` must be one of: `"desktop"`, `"web"`, `"mobile"`, `"backup"`.
    pub fn encrypt_file(
        &self,
        file_id: String,
        input_path: String,
        output_dir: String,
        profile: String,
        callback: Option<Box<dyn FileProgressCallback>>,
    ) -> Result<EncryptedFileInfo, CryptoError> {
        use std::path::Path;

        let chunk_profile = match profile.as_str() {
            "desktop" => beebeeb_types::ChunkProfile::Desktop,
            "cli" => beebeeb_types::ChunkProfile::Cli,
            "web" => beebeeb_types::ChunkProfile::Web,
            "mobile" => beebeeb_types::ChunkProfile::Mobile,
            "backup" => beebeeb_types::ChunkProfile::BackupAgent,
            _ => {
                return Err(CryptoError::InvalidInput {
                    detail: format!("unknown profile: {profile}"),
                });
            }
        };

        let adapter = callback.as_ref().map(|cb| ProgressAdapter { inner: cb.as_ref() });
        let core_cb: Option<&dyn beebeeb_core::file_encrypt::FileProgressCallback> = adapter
            .as_ref()
            .map(|a| a as &dyn beebeeb_core::file_encrypt::FileProgressCallback);

        let result = self.with_key(|mk| {
            beebeeb_core::file_encrypt::encrypt_file_to_chunks(
                mk,
                &file_id,
                Path::new(&input_path),
                Path::new(&output_dir),
                chunk_profile,
                core_cb,
            )
        })??;

        Ok(EncryptedFileInfo {
            chunks: result
                .chunks
                .into_iter()
                .map(|c| EncryptedChunkInfo {
                    chunk_index: c.chunk_index,
                    output_path: c.output_path.to_string_lossy().into_owned(),
                    nonce: c.nonce,
                    plaintext_size: c.plaintext_size,
                    ciphertext_size: c.ciphertext_size,
                })
                .collect(),
            total_plaintext_bytes: result.total_plaintext_bytes,
            total_ciphertext_bytes: result.total_ciphertext_bytes,
            chunk_size_bytes: result.chunk_size_bytes,
        })
    }

    /// Decrypt chunk files back to a single output file.
    ///
    /// Reads each chunk file (containing `nonce || ciphertext`), decrypts,
    /// and writes plaintext to output. Atomic rename at end.
    pub fn decrypt_file(
        &self,
        file_id: String,
        chunk_paths: Vec<String>,
        output_path: String,
        callback: Option<Box<dyn FileProgressCallback>>,
    ) -> Result<DecryptedFileInfo, CryptoError> {
        use std::path::{Path, PathBuf};

        let path_bufs: Vec<PathBuf> = chunk_paths.iter().map(PathBuf::from).collect();
        let path_refs: Vec<&Path> = path_bufs.iter().map(|p| p.as_path()).collect();

        let adapter = callback.as_ref().map(|cb| ProgressAdapter { inner: cb.as_ref() });
        let core_cb: Option<&dyn beebeeb_core::file_encrypt::FileProgressCallback> = adapter
            .as_ref()
            .map(|a| a as &dyn beebeeb_core::file_encrypt::FileProgressCallback);

        let result = self.with_key(|mk| {
            beebeeb_core::file_encrypt::decrypt_chunks_to_file(
                mk,
                &file_id,
                &path_refs,
                Path::new(&output_path),
                core_cb,
            )
        })??;

        Ok(DecryptedFileInfo {
            output_path: result.output_path.to_string_lossy().into_owned(),
            total_bytes: result.total_bytes,
            chunks_processed: result.chunks_processed,
        })
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
// Streaming chunk primitive — UniFFI handles (mobile/desktop convergence)
// ---------------------------------------------------------------------------
//
// These wrap `beebeeb_core::chunk_stream::{ChunkEncryptor, ChunkDecryptor}` — the
// ONE shared chunk loop — so mobile/desktop drop their bespoke encrypt loops and
// converge on core. The key is derived IN CORE from a borrowed `&MasterKeyHandle`
// (via `with_key`); raw key bytes never cross the FFI boundary.
//
// THREADING CONTRACT (single-consumer): a handle is a stateful, ordered cursor.
// Drive each handle from ONE logical sequence — `next_chunk`/`push_chunk` advance
// an internal index, so concurrent calls would interleave chunk indices and
// corrupt the stream. The `Mutex` exists only because `#[uniffi::Object]` requires
// `Send + Sync`; it is a safety backstop against a torn read, NOT a license for
// concurrent use. There is deliberately NO UniFFI callback inside these handles —
// a callback invoked while the lock is held could re-enter the handle and
// deadlock (contrast `MasterKeyHandle::encrypt_file`, which takes a progress
// callback but never re-enters). Progress is reported by the caller counting the
// chunks it pulls.

/// One encrypted chunk produced by [`ChunkEncryptorHandle`]:
/// `data` = `nonce(12) || ciphertext || tag(16)`.
#[derive(uniffi::Record)]
pub struct EncryptedChunkDto {
    pub index: u32,
    pub data: Vec<u8>,
}

/// One decrypted chunk produced by [`ChunkDecryptorHandle`].
#[derive(uniffi::Record)]
pub struct DecryptedChunkDto {
    pub index: u32,
    pub data: Vec<u8>,
}

/// Summary returned by [`ChunkEncryptorHandle::finish`] after the integrity guard.
#[derive(uniffi::Record)]
pub struct ChunkEncryptorSummaryDto {
    pub chunk_count: u32,
    pub total_plaintext: u64,
    pub total_ciphertext: u64,
    pub chunk_size_bytes: u64,
}

fn parse_chunk_profile(profile: &str) -> Result<beebeeb_types::ChunkProfile, CryptoError> {
    match profile {
        "desktop" => Ok(beebeeb_types::ChunkProfile::Desktop),
        "cli" => Ok(beebeeb_types::ChunkProfile::Cli),
        "web" => Ok(beebeeb_types::ChunkProfile::Web),
        "mobile" => Ok(beebeeb_types::ChunkProfile::Mobile),
        "backup" => Ok(beebeeb_types::ChunkProfile::BackupAgent),
        _ => Err(CryptoError::InvalidInput {
            detail: format!("unknown profile: {profile}"),
        }),
    }
}

/// Stateful streaming encryptor handle. Single-consumer (see module note).
///
/// `inner` is `None` only after [`finish`](Self::finish) has consumed the
/// encryptor; any method called afterwards returns `InvalidInput`.
#[derive(uniffi::Object)]
pub struct ChunkEncryptorHandle {
    inner: Mutex<Option<ChunkEncryptor>>,
}

impl ChunkEncryptorHandle {
    /// Run `f` against the live encryptor, or error if it has been finished.
    fn with_inner<T, F: FnOnce(&mut ChunkEncryptor) -> T>(&self, f: F) -> Result<T, CryptoError> {
        let mut guard = self.inner.lock().unwrap();
        let enc = guard.as_mut().ok_or(CryptoError::InvalidInput {
            detail: "chunk encryptor handle has been finished or cleared".into(),
        })?;
        Ok(f(enc))
    }
}

#[uniffi::export]
impl ChunkEncryptorHandle {
    /// PULL constructor: stream-encrypt a file from disk. The file is stat'd for
    /// its size and the chunk plan is derived from (`size`, `profile`). The key is
    /// derived in core from the borrowed master key.
    ///
    /// `profile` must be one of: `"desktop"`, `"web"`, `"mobile"`, `"backup"`.
    #[uniffi::constructor]
    pub fn from_file(
        master_key: &MasterKeyHandle,
        file_id: String,
        input_path: String,
        profile: String,
    ) -> Result<Arc<Self>, CryptoError> {
        let chunk_profile = parse_chunk_profile(&profile)?;
        let path = std::path::Path::new(&input_path);
        let metadata = std::fs::metadata(path).map_err(|e| CryptoError::Io {
            detail: format!("stat input: {e}"),
        })?;
        let file_size = metadata.len();
        let file = std::fs::File::open(path).map_err(|e| CryptoError::Io {
            detail: format!("open input: {e}"),
        })?;
        // Bound the read-ahead buffer to one chunk (≤8 MiB) — the primitive reads
        // one chunk at a time regardless.
        let plan = beebeeb_types::plan_chunks(file_size, chunk_profile);
        let buf_cap = (plan.chunk_size_bytes as usize).clamp(8 * 1024, 8 * 1024 * 1024);
        let reader = std::io::BufReader::with_capacity(buf_cap, file);
        let enc =
            master_key.with_key(|mk| ChunkEncryptor::from_reader(mk, &file_id, file_size, chunk_profile, reader))??;
        Ok(Arc::new(Self {
            inner: Mutex::new(Some(enc)),
        }))
    }

    /// PUSH constructor: the caller slices the plaintext and feeds chunks via
    /// [`push_chunk`](Self::push_chunk). Plan derived from (`file_size`, `profile`).
    #[uniffi::constructor]
    pub fn for_push(
        master_key: &MasterKeyHandle,
        file_id: String,
        file_size: u64,
        profile: String,
    ) -> Result<Arc<Self>, CryptoError> {
        let chunk_profile = parse_chunk_profile(&profile)?;
        let enc = master_key.with_key(|mk| ChunkEncryptor::for_push(mk, &file_id, file_size, chunk_profile))??;
        Ok(Arc::new(Self {
            inner: Mutex::new(Some(enc)),
        }))
    }

    /// PULL: emit the next encrypted chunk, or `None` once the plan is exhausted.
    pub fn next_chunk(&self) -> Result<Option<EncryptedChunkDto>, CryptoError> {
        let chunk = self.with_inner(|e| e.next_chunk())??;
        Ok(chunk.map(|c| EncryptedChunkDto {
            index: c.index,
            data: c.data,
        }))
    }

    /// PUSH: encrypt one caller-provided plaintext chunk.
    pub fn push_chunk(&self, plaintext: Vec<u8>) -> Result<EncryptedChunkDto, CryptoError> {
        let chunk = self.with_inner(|e| e.push_chunk(&plaintext))??;
        Ok(EncryptedChunkDto {
            index: chunk.index,
            data: chunk.data,
        })
    }

    /// The chunk plan (size + count) this encryptor follows.
    pub fn chunk_plan(&self) -> Result<ChunkPlanResult, CryptoError> {
        let plan = self.with_inner(|e| e.chunk_plan())?;
        Ok(ChunkPlanResult {
            chunk_size_bytes: plan.chunk_size_bytes,
            chunk_count: plan.chunk_count,
        })
    }

    /// Expected total ciphertext bytes: `file_size + 28 * chunk_count`. Use for
    /// `upload_init` without reading the whole file.
    pub fn expected_total_ciphertext(&self) -> Result<u64, CryptoError> {
        self.with_inner(|e| e.expected_total_ciphertext())
    }

    /// How many chunks have been emitted so far.
    pub fn chunks_emitted(&self) -> Result<u32, CryptoError> {
        self.with_inner(|e| e.chunks_emitted())
    }

    /// Consume the encryptor (by value) and return the summary after the integrity
    /// guard (detects a source that shrank). The handle is unusable afterwards.
    pub fn finish(&self) -> Result<ChunkEncryptorSummaryDto, CryptoError> {
        let mut guard = self.inner.lock().unwrap();
        let enc = guard.take().ok_or(CryptoError::InvalidInput {
            detail: "chunk encryptor handle has been finished or cleared".into(),
        })?;
        let summary = enc.finish().map_err(CryptoError::from)?;
        Ok(ChunkEncryptorSummaryDto {
            chunk_count: summary.chunk_count,
            total_plaintext: summary.total_plaintext,
            total_ciphertext: summary.total_ciphertext,
            chunk_size_bytes: summary.chunk_size_bytes,
        })
    }
}

/// Stateful streaming decryptor handle. Single-consumer (see module note).
#[derive(uniffi::Object)]
pub struct ChunkDecryptorHandle {
    inner: Mutex<Option<ChunkDecryptor>>,
}

impl ChunkDecryptorHandle {
    fn with_inner<T, F: FnOnce(&mut ChunkDecryptor) -> T>(&self, f: F) -> Result<T, CryptoError> {
        let mut guard = self.inner.lock().unwrap();
        let dec = guard.as_mut().ok_or(CryptoError::InvalidInput {
            detail: "chunk decryptor handle has been cleared".into(),
        })?;
        Ok(f(dec))
    }
}

#[uniffi::export]
impl ChunkDecryptorHandle {
    /// PULL constructor: stream-decrypt an encrypted file from disk.
    /// `chunk_size_bytes` is the PLAINTEXT chunk size used at encryption (the wire
    /// frame is `nonce(12) + chunk_size + tag(16)`). Errors if it is 0.
    #[uniffi::constructor]
    pub fn from_file(
        master_key: &MasterKeyHandle,
        file_id: String,
        chunk_size_bytes: u64,
        input_path: String,
    ) -> Result<Arc<Self>, CryptoError> {
        let file = std::fs::File::open(std::path::Path::new(&input_path)).map_err(|e| CryptoError::Io {
            detail: format!("open input: {e}"),
        })?;
        let buf_cap = (chunk_size_bytes as usize)
            .saturating_add(28)
            .clamp(8 * 1024, 8 * 1024 * 1024);
        let reader = std::io::BufReader::with_capacity(buf_cap, file);
        let dec = master_key.with_key(|mk| ChunkDecryptor::from_reader(mk, &file_id, chunk_size_bytes, reader))??;
        Ok(Arc::new(Self {
            inner: Mutex::new(Some(dec)),
        }))
    }

    /// PUSH constructor: the caller feeds wire frames via
    /// [`push_frame`](Self::push_frame). Each frame is self-describing, so no chunk
    /// size is needed.
    #[uniffi::constructor]
    pub fn for_push(master_key: &MasterKeyHandle, file_id: String) -> Result<Arc<Self>, CryptoError> {
        let dec = master_key.with_key(|mk| ChunkDecryptor::for_push(mk, &file_id))?;
        Ok(Arc::new(Self {
            inner: Mutex::new(Some(dec)),
        }))
    }

    /// PULL: emit the next decrypted chunk, or `None` at clean EOF.
    pub fn next_chunk(&self) -> Result<Option<DecryptedChunkDto>, CryptoError> {
        let chunk = self.with_inner(|d| d.next_chunk())??;
        Ok(chunk.map(|c| DecryptedChunkDto {
            index: c.index,
            data: c.data,
        }))
    }

    /// PUSH: decrypt one caller-provided wire frame (`nonce || ciphertext || tag`).
    pub fn push_frame(&self, frame: Vec<u8>) -> Result<DecryptedChunkDto, CryptoError> {
        let chunk = self.with_inner(|d| d.push_frame(&frame))??;
        Ok(DecryptedChunkDto {
            index: chunk.index,
            data: chunk.data,
        })
    }
}

// ---------------------------------------------------------------------------
// Streaming handle smoke tests (in-process — exercises the Send+Sync stateful
// path). Verifies the Rust handle logic + roundtrip; NOT a real on-device upload.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod chunk_stream_handle_tests {
    use super::*;

    fn mk_handle() -> Arc<MasterKeyHandle> {
        // Any 32 bytes is a valid master key for a roundtrip test.
        MasterKeyHandle::from_keychain_bytes(vec![7u8; 32]).unwrap()
    }

    #[test]
    fn push_roundtrip_via_handles() {
        let mk = mk_handle();
        let file_id = "ffi-push-roundtrip".to_string();
        let data = b"hello via the uniffi chunk-stream handle".to_vec();

        let enc = ChunkEncryptorHandle::for_push(&mk, file_id.clone(), data.len() as u64, "mobile".into()).unwrap();
        assert_eq!(enc.chunk_plan().unwrap().chunk_count, 1);
        let frame = enc.push_chunk(data.clone()).unwrap();
        assert_eq!(frame.index, 0);
        assert_ne!(frame.data, data); // ciphertext != plaintext
        let summary = enc.finish().unwrap();
        assert_eq!(summary.chunk_count, 1);
        assert_eq!(summary.total_plaintext, data.len() as u64);

        let dec = ChunkDecryptorHandle::for_push(&mk, file_id).unwrap();
        let out = dec.push_frame(frame.data).unwrap();
        assert_eq!(out.index, 0);
        assert_eq!(out.data, data);
    }

    #[test]
    fn finished_handle_rejects_reuse() {
        let mk = mk_handle();
        let enc = ChunkEncryptorHandle::for_push(&mk, "x".into(), 4, "mobile".into()).unwrap();
        let _ = enc.push_chunk(vec![1, 2, 3, 4]).unwrap();
        enc.finish().unwrap();
        assert!(enc.push_chunk(vec![0]).is_err());
        assert!(enc.finish().is_err());
        assert!(enc.next_chunk().is_err());
    }

    #[test]
    fn wrong_key_decrypt_errors() {
        let mk = mk_handle();
        let enc = ChunkEncryptorHandle::for_push(&mk, "secret".into(), 5, "mobile".into()).unwrap();
        let frame = enc.push_chunk(b"hello".to_vec()).unwrap();
        let wrong = MasterKeyHandle::from_keychain_bytes(vec![9u8; 32]).unwrap();
        let dec = ChunkDecryptorHandle::for_push(&wrong, "secret".into()).unwrap();
        assert!(dec.push_frame(frame.data).is_err());
    }

    #[test]
    fn pull_file_roundtrip_via_handles() {
        use std::io::Write;
        let mk = mk_handle();
        let dir = std::env::temp_dir().join("beebeeb_uniffi_chunk_stream_pull");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let input = dir.join("in.bin");
        // 9 MiB → mobile profile 4 MiB chunks → 3 chunks (4 + 4 + 1).
        let content: Vec<u8> = (0..9 * 1024 * 1024).map(|i| (i % 251) as u8).collect();
        std::fs::write(&input, &content).unwrap();

        let enc = ChunkEncryptorHandle::from_file(
            &mk,
            "pullfile".into(),
            input.to_string_lossy().into_owned(),
            "mobile".into(),
        )
        .unwrap();
        let chunk_size = enc.chunk_plan().unwrap().chunk_size_bytes;
        assert_eq!(chunk_size, 4 * 1024 * 1024);

        let enc_path = dir.join("in.enc");
        let mut out_file = std::fs::File::create(&enc_path).unwrap();
        let mut frames = 0u32;
        while let Some(c) = enc.next_chunk().unwrap() {
            out_file.write_all(&c.data).unwrap();
            frames += 1;
        }
        out_file.flush().unwrap();
        drop(out_file);
        assert_eq!(frames, 3);
        let summary = enc.finish().unwrap();
        assert_eq!(summary.total_plaintext, content.len() as u64);

        let dec = ChunkDecryptorHandle::from_file(
            &mk,
            "pullfile".into(),
            chunk_size,
            enc_path.to_string_lossy().into_owned(),
        )
        .unwrap();
        let mut recovered = Vec::new();
        while let Some(c) = dec.next_chunk().unwrap() {
            recovered.extend_from_slice(&c.data);
        }
        assert_eq!(recovered, content);

        let _ = std::fs::remove_dir_all(&dir);
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
    fn file_request_wrap_unwrap_roundtrip() {
        let mk = derive_master_key("owner".into(), TEST_SALT.to_vec()).unwrap();
        let request_id = b"req-uniffi-001".to_vec();
        // The request private key is itself an X25519 scalar.
        let r_priv = derive_x25519_private(mk.key.clone()).unwrap();

        let wrap_key = derive_request_wrap_key(mk.key.clone(), request_id.clone()).unwrap();
        assert_eq!(wrap_key.len(), 32);

        let wrapped = wrap_request_private(mk.key.clone(), request_id.clone(), r_priv.clone()).unwrap();
        let recovered = unwrap_request_private(mk.key, request_id, wrapped.wrapped, wrapped.nonce).unwrap();
        assert_eq!(recovered, r_priv);
    }

    #[test]
    fn file_request_seal_open_roundtrip() {
        let mk = derive_master_key("owner".into(), TEST_SALT.to_vec()).unwrap();
        let r_priv = derive_x25519_private(mk.key).unwrap();
        let r_pub = derive_x25519_public(r_priv.clone()).unwrap();
        let file_id = b"uniffi-uploaded-file".to_vec();
        let content_key = vec![0x42u8; 32];

        let sealed = seal_to_request(r_pub, file_id.clone(), content_key.clone()).unwrap();
        assert_eq!(sealed.e_pub.len(), 32);
        let opened = open_request_upload(r_priv, sealed.e_pub, file_id, sealed.wrapped_key).unwrap();
        assert_eq!(opened, content_key);
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

    // --- encrypt_name / decrypt_name tests ---

    #[test]
    fn roundtrip_encrypt_decrypt_name() {
        let mk = derive_master_key("password".into(), TEST_SALT.to_vec()).unwrap();
        let file_id = "file-0001";
        let filename = "vacation.jpg";
        let mime = Some("image/jpeg".to_string());

        let encrypted = encrypt_name(mk.key.clone(), file_id.into(), filename.into(), mime).unwrap();
        let decrypted = decrypt_name(mk.key, file_id.into(), encrypted).unwrap();
        assert_eq!(decrypted, filename);
    }

    #[test]
    fn roundtrip_encrypt_decrypt_name_with_mime() {
        let mk = derive_master_key("password".into(), TEST_SALT.to_vec()).unwrap();
        let file_id = "file-0002";
        let filename = "report.pdf";
        let mime = Some("application/pdf".to_string());

        let encrypted = encrypt_name(mk.key.clone(), file_id.into(), filename.into(), mime.clone()).unwrap();
        let result = decrypt_name_with_mime(mk.key, file_id.into(), encrypted).unwrap();
        assert_eq!(result.name, filename);
        assert_eq!(result.mime_type, mime);
    }

    #[test]
    fn encrypt_name_no_mime() {
        let mk = derive_master_key("password".into(), TEST_SALT.to_vec()).unwrap();
        let file_id = "file-0003";

        let encrypted = encrypt_name(mk.key.clone(), file_id.into(), "notes.txt".into(), None).unwrap();
        let result = decrypt_name_with_mime(mk.key, file_id.into(), encrypted).unwrap();
        assert_eq!(result.name, "notes.txt");
        assert_eq!(result.mime_type, None);
    }

    #[test]
    fn master_key_handle_encrypt_decrypt_name() {
        let mk = derive_master_key("password".into(), TEST_SALT.to_vec()).unwrap();
        let handle = MasterKeyHandle::from_keychain_bytes(mk.key).unwrap();
        let file_id = "file-0004";

        let encrypted = handle
            .encrypt_name(file_id.into(), "photo.png".into(), Some("image/png".into()))
            .unwrap();
        let decrypted = handle.decrypt_name(file_id.into(), encrypted).unwrap();
        assert_eq!(decrypted, "photo.png");
    }

    #[test]
    fn master_key_handle_decrypt_name_with_mime() {
        let mk = derive_master_key("password".into(), TEST_SALT.to_vec()).unwrap();
        let handle = MasterKeyHandle::from_keychain_bytes(mk.key).unwrap();
        let file_id = "file-0005";

        let encrypted = handle
            .encrypt_name(file_id.into(), "video.mp4".into(), Some("video/mp4".into()))
            .unwrap();
        let result = handle.decrypt_name_with_mime(file_id.into(), encrypted).unwrap();
        assert_eq!(result.name, "video.mp4");
        assert_eq!(result.mime_type, Some("video/mp4".into()));
    }

    // --- media utility tests ---

    #[test]
    fn is_media_image() {
        assert!(is_media(Some("image/jpeg".into())));
        assert!(is_media(Some("image/png".into())));
        assert!(is_media(Some("video/mp4".into())));
        assert!(!is_media(Some("application/pdf".into())));
        assert!(!is_media(None));
    }

    #[test]
    fn guess_mime_type_known_extensions() {
        assert_eq!(guess_mime_type("photo.jpg".into()), Some("image/jpeg".into()));
        assert_eq!(guess_mime_type("doc.pdf".into()), Some("application/pdf".into()));
        assert_eq!(guess_mime_type("clip.mp4".into()), Some("video/mp4".into()));
        assert_eq!(guess_mime_type("unknown.xyz".into()), None);
    }

    // --- plan_chunks tests ---

    #[test]
    fn plan_chunks_small_file() {
        let result = plan_chunks(10_000_000, "mobile".into()).unwrap();
        assert_eq!(result.chunk_size_bytes, 4 * 1024 * 1024); // 4 MiB for files <= 64 MiB
        assert_eq!(result.chunk_count, 3); // ceil(10_000_000 / 4_194_304)
    }

    #[test]
    fn plan_chunks_large_file() {
        // N=32 ladder: 2e9 bytes (~1.86 GiB) → base_chunk_size = 64 MiB.
        let result = plan_chunks(2_000_000_000, "desktop".into()).unwrap();
        assert_eq!(result.chunk_size_bytes, 64 * 1024 * 1024);
    }

    #[test]
    fn plan_chunks_cli_profile_is_accepted() {
        // The new "cli" profile parses (128 MiB static cap; not binding here).
        let result = plan_chunks(2_000_000_000, "cli".into()).unwrap();
        assert_eq!(result.chunk_size_bytes, 64 * 1024 * 1024);
    }

    #[test]
    fn plan_chunks_unknown_profile_errors() {
        let result = plan_chunks(1000, "unknown".into());
        assert!(result.is_err());
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
// Blob encrypt/decrypt (P3-1: search index encryption)
// ---------------------------------------------------------------------------

/// Encrypt an arbitrary byte buffer with AES-256-GCM.
///
/// Returns `nonce (12 bytes) || ciphertext`. The key must be exactly 32 bytes.
/// Used by the search index and anywhere an opaque blob needs authenticated encryption.
#[uniffi::export]
pub fn encrypt_blob(key: Vec<u8>, plaintext: Vec<u8>) -> Result<Vec<u8>, CryptoError> {
    let k: [u8; 32] = key.try_into().map_err(|_| CryptoError::InvalidInput {
        detail: "key must be exactly 32 bytes".into(),
    })?;
    beebeeb_core::blob::encrypt_blob(&k, &plaintext).map_err(CryptoError::from)
}

/// Decrypt a blob produced by `encrypt_blob`.
///
/// Expects `nonce (12 bytes) || ciphertext`. Returns the original plaintext.
#[uniffi::export]
pub fn decrypt_blob(key: Vec<u8>, ciphertext: Vec<u8>) -> Result<Vec<u8>, CryptoError> {
    let k: [u8; 32] = key.try_into().map_err(|_| CryptoError::InvalidInput {
        detail: "key must be exactly 32 bytes".into(),
    })?;
    beebeeb_core::blob::decrypt_blob(&k, &ciphertext).map_err(CryptoError::from)
}

// ---------------------------------------------------------------------------
// Metadata wire format (P3-6: metadata serialization)
// ---------------------------------------------------------------------------

/// Serialize a nonce + ciphertext pair into the canonical JSON metadata format.
///
/// Output: `{"nonce":"<base64>","ciphertext":"<base64>"}`.
#[uniffi::export]
pub fn serialize_encrypted_metadata(nonce: Vec<u8>, ciphertext: Vec<u8>) -> String {
    beebeeb_core::metadata_wire::serialize_encrypted_metadata(&nonce, &ciphertext)
}

/// Parse a JSON-encoded encrypted metadata payload.
///
/// Accepts both base64 strings (canonical) and numeric arrays (legacy).
/// Returns a record with `nonce` and `ciphertext` byte vectors.
#[uniffi::export]
pub fn parse_encrypted_metadata(payload: String) -> Result<EncryptedMetadataParts, CryptoError> {
    let (nonce, ciphertext) =
        beebeeb_core::metadata_wire::parse_encrypted_metadata(&payload).map_err(CryptoError::from)?;
    Ok(EncryptedMetadataParts { nonce, ciphertext })
}

// ---------------------------------------------------------------------------
// SHA-256 (P3-4)
// ---------------------------------------------------------------------------

/// Compute the SHA-256 digest of `data`. Returns a 32-byte hash.
#[uniffi::export]
pub fn sha256(data: Vec<u8>) -> Vec<u8> {
    beebeeb_core::hash::sha256(&data)
}

// ---------------------------------------------------------------------------
// SAS byte derivation (P2-4)
// ---------------------------------------------------------------------------

/// Derive `length` bytes from a shared secret using HKDF-SHA256.
///
/// Used for SAS word derivation — the word list lookup stays in JS/Swift.
/// `info` is typically `b"beebeeb-sas-v1"` or similar context string.
#[uniffi::export]
pub fn derive_sas_bytes(shared_secret: Vec<u8>, info: Vec<u8>, length: u32) -> Vec<u8> {
    beebeeb_core::hash::derive_sas_bytes(&shared_secret, &info, length as usize)
}

// ---------------------------------------------------------------------------
// Upload protocol — synchronous blocking wrapper for Swift/Kotlin
// ---------------------------------------------------------------------------

/// Error from the upload protocol (UniFFI-compatible enum).
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum UploadError {
    #[error("network error: {detail}")]
    Network { detail: String },

    #[error("server error (HTTP {status}): {message}")]
    ServerError { status: u16, message: String },

    #[error("client error (HTTP {status}): {message}")]
    ClientError { status: u16, message: String },

    #[error("rate limited — retry after {retry_after_secs}s")]
    RateLimited { retry_after_secs: u64 },

    #[error("I/O error: {detail}")]
    UploadIo { detail: String },

    #[error("invalid response: {detail}")]
    InvalidResponse { detail: String },

    #[error("invalid input: {detail}")]
    UploadInvalidInput { detail: String },

    #[error("max retries exhausted ({attempts} attempts): {last_error}")]
    MaxRetriesExhausted { attempts: u32, last_error: String },
}

impl From<beebeeb_upload::UploadError> for UploadError {
    fn from(e: beebeeb_upload::UploadError) -> Self {
        match e {
            beebeeb_upload::UploadError::Network(s) => UploadError::Network { detail: s },
            beebeeb_upload::UploadError::ServerError { status, message } => {
                UploadError::ServerError { status, message }
            }
            beebeeb_upload::UploadError::ClientError { status, message } => {
                UploadError::ClientError { status, message }
            }
            beebeeb_upload::UploadError::RateLimited { retry_after_secs } => {
                UploadError::RateLimited { retry_after_secs }
            }
            beebeeb_upload::UploadError::IoError(s) => UploadError::UploadIo { detail: s },
            beebeeb_upload::UploadError::InvalidResponse(s) => UploadError::InvalidResponse { detail: s },
            beebeeb_upload::UploadError::InvalidInput(s) => UploadError::UploadInvalidInput { detail: s },
            beebeeb_upload::UploadError::MaxRetriesExhausted { attempts, last_error } => {
                UploadError::MaxRetriesExhausted { attempts, last_error }
            }
        }
    }
}

/// Result of a successful file upload.
#[derive(uniffi::Record)]
pub struct UploadResultData {
    pub file_id: String,
    pub upload_session_id: String,
    pub chunks_uploaded: u32,
    pub total_bytes: u64,
}

/// Callback interface for upload progress. Implemented by Swift/Kotlin.
#[uniffi::export(callback_interface)]
pub trait UploadProgressCallback: Send + Sync {
    fn on_chunk_uploaded(&self, chunk_index: u32, total_chunks: u32);
    fn on_complete(&self, file_id: String);
    fn on_error(&self, error: String);
}

/// Bridge from UniFFI callback to core upload callback.
///
/// `Send + Sync` are inherited from the trait bound on
/// [`UploadProgressCallback`] — no `unsafe impl` is needed because shared
/// references to a `Sync` trait object are already `Send + Sync`.
struct UploadCallbackBridge<'a>(&'a dyn UploadProgressCallback);

impl beebeeb_upload::UploadProgressCallback for UploadCallbackBridge<'_> {
    fn on_chunk_uploaded(&self, chunk_index: u32, total_chunks: u32) {
        self.0.on_chunk_uploaded(chunk_index, total_chunks);
    }
    fn on_complete(&self, file_id: &str) {
        self.0.on_complete(file_id.to_string());
    }
    fn on_error(&self, error: &str) {
        self.0.on_error(error.to_string());
    }
}

/// Upload encrypted chunk files to the server. Blocking — call from Swift's
/// `Task { }` or Kotlin's `withContext(Dispatchers.IO) { }`.
///
/// Creates a tokio runtime internally and blocks until complete.
// FFI surface (UniFFI): the flat argument list IS the Swift/Kotlin ABI; a
// params struct would have to be mirrored in both bindings for no benefit.
#[allow(clippy::too_many_arguments)]
#[uniffi::export]
pub fn upload_encrypted_file(
    api_url: String,
    token: String,
    file_id: String,
    name_encrypted: String,
    parent_id: Option<String>,
    mime_type: Option<String>,
    is_media: bool,
    chunk_paths: Vec<String>,
    original_size: u64,
    created_at: Option<String>,
    callback: Option<Box<dyn UploadProgressCallback>>,
) -> Result<UploadResultData, UploadError> {
    let bridge = callback.as_ref().map(|cb| UploadCallbackBridge(cb.as_ref()));
    let core_cb: Option<Box<dyn beebeeb_upload::UploadProgressCallback + '_>> =
        bridge.map(|b| Box::new(b) as Box<dyn beebeeb_upload::UploadProgressCallback>);

    let result = beebeeb_upload::upload_encrypted_file(
        &api_url,
        &token,
        &file_id,
        &name_encrypted,
        parent_id,
        mime_type,
        is_media,
        chunk_paths,
        original_size,
        created_at,
        core_cb,
    )?;

    Ok(UploadResultData {
        file_id: result.file_id,
        upload_session_id: result.upload_session_id,
        chunks_uploaded: result.chunks_uploaded,
        total_bytes: result.total_bytes,
    })
}

// ---------------------------------------------------------------------------
// Quota / plan helpers
// ---------------------------------------------------------------------------

/// Return the base storage quota (in bytes) for a plan slug.
#[uniffi::export]
pub fn plan_base_storage_bytes(plan_slug: String) -> i64 {
    beebeeb_types::Plan::from_slug(&plan_slug).base_storage_bytes()
}

/// Compute the effective quota after add-ons and bonus bytes.
#[uniffi::export]
pub fn plan_effective_quota(plan_slug: String, extra_tb: i64, bonus_bytes: i64) -> i64 {
    let plan = beebeeb_types::Plan::from_slug(&plan_slug);
    beebeeb_types::effective_quota(plan, extra_tb, bonus_bytes)
}

/// Maximum additional TB a plan may purchase.
#[uniffi::export]
pub fn plan_max_extra_tb(plan_slug: String) -> i64 {
    beebeeb_types::Plan::from_slug(&plan_slug).max_extra_tb()
}

/// Whether the plan supports purchasing extra storage.
#[uniffi::export]
pub fn plan_can_add_storage(plan_slug: String) -> bool {
    beebeeb_types::Plan::from_slug(&plan_slug).can_add_storage()
}

/// Monthly cost in cents for a plan with optional add-ons.
#[uniffi::export]
pub fn plan_monthly_cost_cents(plan_slug: String, extra_tb: i64, extra_users: i64) -> i64 {
    let plan = beebeeb_types::Plan::from_slug(&plan_slug);
    beebeeb_types::monthly_cost_cents(plan, extra_tb, extra_users)
}

/// Format a byte count as a human-readable SI string (e.g. "5.0 TB").
#[uniffi::export]
pub fn storage_format_si(bytes: i64) -> String {
    beebeeb_types::format_storage_si(bytes)
}

// ---------------------------------------------------------------------------
// Chunk planning
// ---------------------------------------------------------------------------

/// Result of planning chunks for a file upload. Contains the chunk size and
/// count needed for the given file size and client profile.
#[derive(uniffi::Record)]
pub struct ChunkPlanResult {
    pub chunk_size_bytes: u64,
    pub chunk_count: u64,
}

/// Plan how to split a file into chunks for upload based on the client profile.
///
/// `profile` must be one of: `"desktop"`, `"web"`, `"mobile"`, `"backup"`.
/// Returns the chunk size and count for the given file size.
#[uniffi::export]
pub fn plan_chunks(file_size_bytes: u64, profile: String) -> Result<ChunkPlanResult, CryptoError> {
    // Single-source the profile vocabulary through parse_chunk_profile so the
    // "cli" profile (and any future addition) can't drift between call sites.
    let p = parse_chunk_profile(&profile)?;
    let plan = beebeeb_types::plan_chunks(file_size_bytes, p);
    Ok(ChunkPlanResult {
        chunk_size_bytes: plan.chunk_size_bytes,
        chunk_count: plan.chunk_count,
    })
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

// ---------------------------------------------------------------------------
// Thumbnail generation
// ---------------------------------------------------------------------------
//
// NOTE: The WebP-encode path (generate_thumbnail_*) is gated behind the
// `webp-encode` feature. When building for iOS, beebeeb-uniffi is compiled
// WITHOUT this feature so that the webp C binding is not linked (it conflicts
// with aws-lc-sys during iOS cross-compilation). iOS generates WebP thumbnails
// natively via PhotoKit/vImage and calls `resize_for_thumbnail` instead.
//
// For all other targets (CLI, desktop, server, Android), `webp-encode` is
// enabled and the full generate_thumbnail_* API is available.

/// Error from thumbnail generation (UniFFI-compatible enum).
///
/// Always available — used by both `resize_for_thumbnail` and
/// `generate_thumbnail_*`.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum ThumbnailError {
    #[error("no ladder step produced output under max_bytes")]
    AllStepsFailed,
    #[error("resize failed: {detail}")]
    ResizeFailed { detail: String },
    #[error("encode failed: {detail}")]
    EncodeFailed { detail: String },
    #[error("invalid input: {detail}")]
    ThumbnailInvalidInput { detail: String },
}

impl From<beebeeb_core::thumbnail::ThumbnailError> for ThumbnailError {
    fn from(e: beebeeb_core::thumbnail::ThumbnailError) -> Self {
        match e {
            beebeeb_core::thumbnail::ThumbnailError::AllStepsFailed => ThumbnailError::AllStepsFailed,
            beebeeb_core::thumbnail::ThumbnailError::ResizeFailed(s) => ThumbnailError::ResizeFailed { detail: s },
            beebeeb_core::thumbnail::ThumbnailError::EncodeFailed(s) => ThumbnailError::EncodeFailed { detail: s },
            beebeeb_core::thumbnail::ThumbnailError::InvalidInput(s) => {
                ThumbnailError::ThumbnailInvalidInput { detail: s }
            }
        }
    }
}

/// Resize RGBA pixel data for thumbnail use. Always available (no WebP
/// dependency). The longest side is scaled to `max_dimension` preserving
/// aspect ratio. If the source already fits, the buffer is returned as-is.
///
/// Returns `(resized_rgba, new_width, new_height)` packed as three fields.
///
/// iOS calls this and then encodes to WebP natively via vImage/ImageIO.
#[derive(uniffi::Record)]
pub struct ResizeResult {
    pub rgba: Vec<u8>,
    pub width: u32,
    pub height: u32,
}

#[uniffi::export]
pub fn resize_for_thumbnail(
    rgba: Vec<u8>,
    src_width: u32,
    src_height: u32,
    max_dimension: u32,
) -> Result<ResizeResult, ThumbnailError> {
    let (resized, w, h) = beebeeb_core::thumbnail::resize_for_thumbnail(&rgba, src_width, src_height, max_dimension)?;
    Ok(ResizeResult {
        rgba: resized,
        width: w,
        height: h,
    })
}

// --- WebP encode path (disabled for iOS) ------------------------------------

#[cfg(feature = "webp-encode")]
/// A single quality-cascade step for thumbnail generation.
#[derive(uniffi::Record)]
pub struct ThumbnailLadderStep {
    pub max_dimension: u32,
    pub quality: f32,
}

#[cfg(feature = "webp-encode")]
/// Configuration for thumbnail generation.
#[derive(uniffi::Record)]
pub struct ThumbnailConfigData {
    pub ladder: Vec<ThumbnailLadderStep>,
    pub target_bytes: u64,
    pub max_bytes: u64,
}

#[cfg(feature = "webp-encode")]
/// Result of thumbnail generation.
#[derive(uniffi::Record)]
pub struct ThumbnailResult {
    pub data: Vec<u8>,
    pub width: u32,
    pub height: u32,
    pub quality: f32,
    pub step_index: u32,
}

#[cfg(feature = "webp-encode")]
fn config_from_dto(dto: &ThumbnailConfigData) -> beebeeb_core::thumbnail::ThumbnailConfig {
    beebeeb_core::thumbnail::ThumbnailConfig {
        ladder: dto
            .ladder
            .iter()
            .map(|s| beebeeb_core::thumbnail::LadderStep {
                max_dimension: s.max_dimension,
                quality: s.quality,
            })
            .collect(),
        target_bytes: dto.target_bytes as usize,
        max_bytes: dto.max_bytes as usize,
    }
}

/// Generate a lossy WebP thumbnail from raw RGBA pixel data.
///
/// Tries each step in the config's quality ladder in order. Returns the
/// first result that fits under `target_bytes`. If none fit the target but
/// one fits under `max_bytes`, returns that as a fallback.
///
/// Not available when building for iOS (feature `webp-encode` is disabled).
#[cfg(feature = "webp-encode")]
#[uniffi::export]
pub fn generate_thumbnail(
    rgba: Vec<u8>,
    src_width: u32,
    src_height: u32,
    config: ThumbnailConfigData,
) -> Result<ThumbnailResult, ThumbnailError> {
    let cfg = config_from_dto(&config);
    let out = beebeeb_core::thumbnail::generate_thumbnail(&rgba, src_width, src_height, &cfg)?;
    Ok(ThumbnailResult {
        data: out.data,
        width: out.width,
        height: out.height,
        quality: out.quality,
        step_index: out.step_index as u32,
    })
}

/// Convenience: generate a thumbnail using the built-in "medium" config.
///
/// Not available when building for iOS (feature `webp-encode` is disabled).
#[cfg(feature = "webp-encode")]
#[uniffi::export]
pub fn generate_thumbnail_medium(
    rgba: Vec<u8>,
    src_width: u32,
    src_height: u32,
) -> Result<ThumbnailResult, ThumbnailError> {
    let cfg = beebeeb_core::thumbnail::ThumbnailConfig::medium();
    let out = beebeeb_core::thumbnail::generate_thumbnail(&rgba, src_width, src_height, &cfg)?;
    Ok(ThumbnailResult {
        data: out.data,
        width: out.width,
        height: out.height,
        quality: out.quality,
        step_index: out.step_index as u32,
    })
}

/// Convenience: generate a thumbnail using the built-in "small" config.
///
/// Not available when building for iOS (feature `webp-encode` is disabled).
#[cfg(feature = "webp-encode")]
#[uniffi::export]
pub fn generate_thumbnail_small(
    rgba: Vec<u8>,
    src_width: u32,
    src_height: u32,
) -> Result<ThumbnailResult, ThumbnailError> {
    let cfg = beebeeb_core::thumbnail::ThumbnailConfig::small();
    let out = beebeeb_core::thumbnail::generate_thumbnail(&rgba, src_width, src_height, &cfg)?;
    Ok(ThumbnailResult {
        data: out.data,
        width: out.width,
        height: out.height,
        quality: out.quality,
        step_index: out.step_index as u32,
    })
}

/// Convenience: generate a thumbnail using the built-in "large" config.
///
/// Not available when building for iOS (feature `webp-encode` is disabled).
#[cfg(feature = "webp-encode")]
#[uniffi::export]
pub fn generate_thumbnail_large(
    rgba: Vec<u8>,
    src_width: u32,
    src_height: u32,
) -> Result<ThumbnailResult, ThumbnailError> {
    let cfg = beebeeb_core::thumbnail::ThumbnailConfig::large();
    let out = beebeeb_core::thumbnail::generate_thumbnail(&rgba, src_width, src_height, &cfg)?;
    Ok(ThumbnailResult {
        data: out.data,
        width: out.width,
        height: out.height,
        quality: out.quality,
        step_index: out.step_index as u32,
    })
}

// ---------------------------------------------------------------------------
// PDF generation
// ---------------------------------------------------------------------------

/// Generate a recovery kit PDF with a title, recovery words, and metadata.
///
/// Returns the raw PDF bytes (valid PDF 1.4).
#[uniffi::export]
pub fn generate_recovery_pdf(
    title: String,
    words: Vec<String>,
    metadata_keys: Vec<String>,
    metadata_values: Vec<String>,
) -> Result<Vec<u8>, CryptoError> {
    if metadata_keys.len() != metadata_values.len() {
        return Err(CryptoError::InvalidInput {
            detail: "metadata_keys and metadata_values must have the same length".into(),
        });
    }
    let pairs: Vec<(&str, &str)> = metadata_keys
        .iter()
        .zip(metadata_values.iter())
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    Ok(beebeeb_core::pdf::generate_recovery_pdf(&title, &words, &pairs))
}

// ---------------------------------------------------------------------------
// Archive parsing
// ---------------------------------------------------------------------------

/// A single entry inside an archive (TAR, GZ, TGZ).
#[derive(uniffi::Record)]
pub struct ArchiveEntryDto {
    pub name: String,
    pub size: u64,
    pub is_directory: bool,
}

/// List entries in a TAR archive from raw bytes.
#[uniffi::export]
pub fn list_tar_entries(data: Vec<u8>) -> Result<Vec<ArchiveEntryDto>, CryptoError> {
    let entries = beebeeb_core::archive::list_tar_entries(&data)?;
    Ok(entries.into_iter().map(archive_entry_to_dto).collect())
}

/// Decompress gzip-compressed data.
#[uniffi::export]
pub fn decompress_gzip(data: Vec<u8>) -> Result<Vec<u8>, CryptoError> {
    beebeeb_core::archive::decompress_gzip(&data).map_err(CryptoError::from)
}

/// List entries in an archive, detecting format from the filename extension.
///
/// Supported: `.tar`, `.gz`, `.tgz`, `.tar.gz`.
#[uniffi::export]
pub fn list_archive(data: Vec<u8>, filename: String) -> Result<Vec<ArchiveEntryDto>, CryptoError> {
    let entries = beebeeb_core::archive::list_archive(&data, &filename)?;
    Ok(entries.into_iter().map(archive_entry_to_dto).collect())
}

fn archive_entry_to_dto(e: beebeeb_core::archive::ArchiveEntry) -> ArchiveEntryDto {
    ArchiveEntryDto {
        name: e.name,
        size: e.size,
        is_directory: e.is_directory,
    }
}

// ---------------------------------------------------------------------------
// Download + decrypt — synchronous blocking wrapper for Swift/Kotlin
// ---------------------------------------------------------------------------

/// Result of a successful file download + decrypt.
#[derive(uniffi::Record)]
pub struct DownloadResultData {
    pub output_path: String,
    pub plaintext_size: u64,
    pub chunks_decrypted: u32,
}

/// Callback interface for download progress. Implemented by Swift/Kotlin.
#[uniffi::export(callback_interface)]
pub trait DownloadProgressCallback: Send + Sync {
    fn on_chunk_decrypted(&self, chunk_index: u32, total_chunks: u32);
    fn on_complete(&self, output_path: String);
    fn on_error(&self, error: String);
}

/// Bridge from UniFFI callback to core download callback.
///
/// `Send + Sync` are inherited from the trait bound on
/// [`DownloadProgressCallback`] — no `unsafe impl` is needed because shared
/// references to a `Sync` trait object are already `Send + Sync`.
struct DownloadCallbackBridge<'a>(&'a dyn DownloadProgressCallback);

impl beebeeb_upload::DownloadProgressCallback for DownloadCallbackBridge<'_> {
    fn on_chunk_decrypted(&self, chunk_index: u32, total_chunks: u32) {
        self.0.on_chunk_decrypted(chunk_index, total_chunks);
    }
    fn on_complete(&self, output_path: &str) {
        self.0.on_complete(output_path.to_string());
    }
    fn on_error(&self, error: &str) {
        self.0.on_error(error.to_string());
    }
}

/// Download an encrypted file, decrypt it, and write plaintext to disk.
/// Blocking — call from Swift `Task { }` or Kotlin `withContext(Dispatchers.IO)`.
///
/// Uses the MasterKeyHandle to derive the per-file key via HKDF, then
/// fetches `GET /api/v1/files/{file_id}/download`, splits into chunks,
/// decrypts each with AES-256-GCM, and writes to `output_path`.
#[uniffi::export]
pub fn download_and_decrypt_file(
    api_url: String,
    token: String,
    master_key_handle: &MasterKeyHandle,
    file_id: String,
    output_path: String,
    callback: Option<Box<dyn DownloadProgressCallback>>,
) -> Result<DownloadResultData, UploadError> {
    // Extract the raw master key bytes while the lock is held, then release.
    let mk_bytes = master_key_handle
        .with_key(|mk| mk.to_bytes())
        .map_err(|_| UploadError::UploadInvalidInput {
            detail: "master key handle has been cleared".into(),
        })?;
    let mk = kdf::MasterKey::from_bytes(mk_bytes);

    let bridge = callback.as_ref().map(|cb| DownloadCallbackBridge(cb.as_ref()));
    let core_cb: Option<Box<dyn beebeeb_upload::DownloadProgressCallback + '_>> =
        bridge.map(|b| Box::new(b) as Box<dyn beebeeb_upload::DownloadProgressCallback>);

    let result = beebeeb_upload::download_and_decrypt_file(&api_url, &token, &mk, &file_id, &output_path, core_cb)?;

    Ok(DownloadResultData {
        output_path: result.output_path,
        plaintext_size: result.plaintext_size,
        chunks_decrypted: result.chunks_decrypted,
    })
}

// ---------------------------------------------------------------------------
// FileProvider SQLite cache — UniFFI object
// ---------------------------------------------------------------------------

/// A cached file/folder entry for the iOS FileProvider extension.
#[derive(uniffi::Record)]
pub struct CachedFileEntryData {
    pub id: String,
    pub parent_id: Option<String>,
    pub name_encrypted: Option<String>,
    pub name_decrypted: Option<String>,
    pub mime_type: Option<String>,
    pub size_bytes: i64,
    pub is_folder: bool,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

fn cache_entry_to_dto(e: beebeeb_core::fp_cache::CachedFileEntry) -> CachedFileEntryData {
    CachedFileEntryData {
        id: e.id,
        parent_id: e.parent_id,
        name_encrypted: e.name_encrypted,
        name_decrypted: e.name_decrypted,
        mime_type: e.mime_type,
        size_bytes: e.size_bytes,
        is_folder: e.is_folder,
        created_at: e.created_at,
        updated_at: e.updated_at,
    }
}

fn cache_entry_from_dto(d: &CachedFileEntryData) -> beebeeb_core::fp_cache::CachedFileEntry {
    beebeeb_core::fp_cache::CachedFileEntry {
        id: d.id.clone(),
        parent_id: d.parent_id.clone(),
        name_encrypted: d.name_encrypted.clone(),
        name_decrypted: d.name_decrypted.clone(),
        mime_type: d.mime_type.clone(),
        size_bytes: d.size_bytes,
        is_folder: d.is_folder,
        created_at: d.created_at.clone(),
        updated_at: d.updated_at.clone(),
    }
}

/// Opaque handle to a FileProviderCache SQLite database.
///
/// Thread-safe — the underlying connection is mutex-protected.
#[derive(uniffi::Object)]
pub struct FileProviderCacheHandle {
    inner: beebeeb_core::fp_cache::FileProviderCache,
}

#[uniffi::export]
impl FileProviderCacheHandle {
    /// Open (or create) the cache database at `db_path`.
    /// Pass `":memory:"` for an in-memory database (tests).
    #[uniffi::constructor]
    pub fn open(db_path: String) -> Result<Arc<Self>, CryptoError> {
        let cache = beebeeb_core::fp_cache::FileProviderCache::open(&db_path)?;
        Ok(Arc::new(Self { inner: cache }))
    }

    /// Insert or update entries in bulk. Returns the number of rows affected.
    pub fn upsert_entries(&self, entries: Vec<CachedFileEntryData>) -> Result<u32, CryptoError> {
        let core_entries: Vec<beebeeb_core::fp_cache::CachedFileEntry> =
            entries.iter().map(cache_entry_from_dto).collect();
        let count = self.inner.upsert_entries(&core_entries)?;
        Ok(count as u32)
    }

    /// Get all children of a parent folder. Pass `None` for root items.
    pub fn get_children(&self, parent_id: Option<String>) -> Result<Vec<CachedFileEntryData>, CryptoError> {
        let entries = self.inner.get_children(parent_id.as_deref())?;
        Ok(entries.into_iter().map(cache_entry_to_dto).collect())
    }

    /// Get a single item by ID.
    pub fn get_item(&self, id: String) -> Result<Option<CachedFileEntryData>, CryptoError> {
        let entry = self.inner.get_item(&id)?;
        Ok(entry.map(cache_entry_to_dto))
    }

    /// Delete a single entry by ID. Returns `true` if a row was deleted.
    pub fn delete_item(&self, id: String) -> Result<bool, CryptoError> {
        self.inner.delete_item(&id).map_err(CryptoError::from)
    }

    /// Delete all entries. Returns the number of rows deleted.
    pub fn clear(&self) -> Result<u32, CryptoError> {
        let count = self.inner.clear()?;
        Ok(count as u32)
    }

    /// Return the total number of cached entries.
    pub fn count(&self) -> Result<u32, CryptoError> {
        let count = self.inner.count()?;
        Ok(count as u32)
    }
}
