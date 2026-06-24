use serde::{Deserialize, Serialize};

/// The output of encrypting a chunk of data (or metadata) with an AEAD cipher.
///
/// An `EncryptedBlob` bundles everything needed to decrypt data back:
///
/// - **Which algorithm** was used ([`cipher_suite`](EncryptedBlob::cipher_suite))
/// - **The nonce** that was mixed into encryption ([`nonce`](EncryptedBlob::nonce))
/// - **The ciphertext** including the authentication tag ([`ciphertext`](EncryptedBlob::ciphertext))
///
/// The encryption key is *not* stored here — it must be derived separately
/// from the user's master key via HKDF (for owned files) or from an X25519
/// shared secret (for shared files).
///
/// # Wire format
///
/// `EncryptedBlob` serializes to JSON (via serde) for API transport and is
/// stored as-is in the database. The `nonce` and `ciphertext` fields are
/// base64-encoded by serde when using a JSON serializer.
///
/// # Size
///
/// For AES-256-GCM ([`CipherSuite::V1Aes256Gcm`](super::CipherSuite::V1Aes256Gcm)):
/// - `nonce`: always 12 bytes
/// - `ciphertext`: `plaintext.len() + 16` bytes (16-byte GCM auth tag appended)
///
/// # Security notes
///
/// - A **fresh random nonce** is generated for every encryption call. Never
///   reuse a nonce with the same key — AES-GCM is catastrophically broken
///   under nonce reuse.
/// - The GCM tag provides **authenticated encryption**: any modification to
///   the nonce or ciphertext causes decryption to fail.
///
/// # Example
///
/// ```
/// use beebeeb_types::{CipherSuite, EncryptedBlob};
///
/// // Typically produced by beebeeb_core::encrypt::encrypt_chunk(),
/// // but can be constructed manually for testing:
/// let blob = EncryptedBlob {
///     cipher_suite: CipherSuite::V1Aes256Gcm,
///     nonce: vec![0u8; 12],
///     ciphertext: vec![0u8; 32], // 16 bytes plaintext + 16 bytes tag
/// };
///
/// assert_eq!(blob.nonce.len(), 12);
/// ```
///
/// # Consumers
///
/// - `beebeeb-core` — [`encrypt_chunk`](https://docs.rs/beebeeb-core) /
///   [`decrypt_chunk`](https://docs.rs/beebeeb-core) produce and consume blobs
/// - `beebeeb-wasm` — converts blobs to/from JS objects for the web client
/// - `beebeeb-uniffi` — converts blobs to/from `EncryptedData` records for mobile
/// - `beebeeb-server` — stores and retrieves blobs in PostgreSQL
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedBlob {
    /// The AEAD cipher suite that produced this blob.
    ///
    /// Stored so that future clients can select the correct decryption
    /// algorithm even after the platform migrates to a newer suite.
    pub cipher_suite: super::CipherSuite,

    /// Random nonce (initialization vector) used during encryption.
    ///
    /// For [`CipherSuite::V1Aes256Gcm`](super::CipherSuite::V1Aes256Gcm)
    /// this is exactly 12 bytes. Decryption will fail if the length is wrong.
    ///
    /// Must never be reused with the same key.
    pub nonce: Vec<u8>,

    /// The encrypted data with the authentication tag appended.
    ///
    /// For AES-256-GCM the tag is the last 16 bytes:
    /// `ciphertext.len() == plaintext.len() + 16`.
    ///
    /// Any modification to these bytes — even a single bit flip — will cause
    /// decryption to fail with an authentication error.
    pub ciphertext: Vec<u8>,
}

/// Metadata for a single chunk within a chunked file upload.
///
/// Files are split into sequential chunks sized by the dynamic ladder in
/// [`beebeeb_types::plan_chunks`] (4–256 MiB depending on profile). Each chunk
/// is encrypted independently, and a `ChunkMeta` record is created to track its
/// position, size, and integrity.
///
/// > **Note:** `ChunkMeta` is superseded by [`ChunkPlan`] + the object-version
/// > model for V2 uploads. Existing V1 metadata may still be encountered on
/// > legacy files.
///
/// # Fields
///
/// | Field | Description |
/// |-------|-------------|
/// | `index` | Zero-based position of this chunk in the file |
/// | `size` | Size of the **plaintext** chunk in bytes (before encryption) |
/// | `hash` | SHA-256 hash of the **plaintext** chunk for integrity verification |
///
/// # Example
///
/// ```
/// use beebeeb_types::ChunkMeta;
///
/// let meta = ChunkMeta {
///     index: 0,
///     size: 1_048_576, // 1 MiB — a full chunk
///     hash: [0u8; 32], // SHA-256 digest
/// };
///
/// assert_eq!(meta.index, 0);
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkMeta {
    /// Zero-based index of this chunk within the file.
    ///
    /// Chunk 0 is the first `chunk_size_bytes` bytes of the file
    /// (as determined by [`beebeeb_types::plan_chunks`]), chunk 1 is the next,
    /// and so on. The last chunk may be smaller.
    pub index: u32,

    /// Size of the plaintext chunk in bytes, before encryption.
    ///
    /// For all chunks except the last, this equals the `chunk_size_bytes` from
    /// the [`ChunkPlan`]. The final chunk holds the remainder (or the full chunk
    /// size if the file is an exact multiple).
    pub size: u64,

    /// SHA-256 hash of the plaintext chunk content.
    ///
    /// Used to verify integrity after decryption: the client hashes the
    /// decrypted bytes and compares against this value. A mismatch indicates
    /// corruption or a bug in reassembly.
    pub hash: [u8; 32],
}
