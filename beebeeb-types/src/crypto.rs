use serde::{Deserialize, Serialize};

/// Identifies which AEAD cipher was used to produce an [`super::EncryptedBlob`].
///
/// Every encrypted blob stores its cipher suite so that future clients can
/// decrypt data even after the platform migrates to a newer algorithm. When a
/// new suite is added (e.g. XChaCha20-Poly1305), the old variant stays and
/// existing ciphertext remains decryptable.
///
/// # Variants
///
/// | Variant | Algorithm | Nonce size | Tag size |
/// |---------|-----------|-----------|----------|
/// | [`V1Aes256Gcm`](CipherSuite::V1Aes256Gcm) | AES-256-GCM | 12 bytes | 16 bytes (appended to ciphertext) |
///
/// # Example
///
/// ```
/// use beebeeb_types::CipherSuite;
///
/// let suite = CipherSuite::V1Aes256Gcm;
/// assert_eq!(format!("{suite:?}"), "V1Aes256Gcm");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CipherSuite {
    /// AES-256-GCM — the launch cipher suite.
    ///
    /// Uses a 256-bit key with a random 12-byte (96-bit) nonce generated per
    /// encryption call. The GCM authentication tag (16 bytes) is appended to
    /// the ciphertext by the `aes-gcm` crate, so
    /// `ciphertext.len() == plaintext.len() + 16`.
    V1Aes256Gcm,
}

/// Identifies which key derivation function is used to stretch a user's
/// password into a 32-byte master key.
///
/// The KDF algorithm tag is stored alongside [`KdfParams`] in the user's
/// server-side record so that the client knows how to re-derive the master key
/// at login time — even if the platform later upgrades to a different KDF.
///
/// # Variants
///
/// | Variant | Algorithm | Output |
/// |---------|-----------|--------|
/// | [`Argon2id13`](KdfAlgorithm::Argon2id13) | Argon2id v1.3 (RFC 9106) | 32 bytes |
///
/// # Example
///
/// ```
/// use beebeeb_types::KdfAlgorithm;
///
/// let alg = KdfAlgorithm::Argon2id13;
/// assert_eq!(format!("{alg:?}"), "Argon2id13");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KdfAlgorithm {
    /// Argon2id version 1.3 — memory-hard, hybrid side-channel-resistant KDF.
    ///
    /// Chosen for its resistance to both GPU/ASIC brute-force attacks
    /// (memory-hard) and timing side channels (hybrid data-independent +
    /// data-dependent passes). See RFC 9106 for the full specification.
    Argon2id13,
}

/// Tuning parameters for the key derivation function.
///
/// These parameters control how expensive it is to derive a master key from a
/// password. Higher values make brute-force attacks harder but increase login
/// latency. The defaults are calibrated for modern hardware (2024+):
///
/// | Parameter | Default | Meaning |
/// |-----------|---------|---------|
/// | `memory_kib` | 262144 (256 MiB) | Peak memory the KDF may allocate |
/// | `iterations` | 4 | Number of passes over memory |
/// | `parallelism` | 2 | Lanes (threads) used in parallel |
///
/// These defaults produce ~0.5-1s derivation time on a typical laptop and
/// require 256 MiB of RAM, making GPU attacks economically impractical.
///
/// # Example
///
/// ```
/// use beebeeb_types::KdfParams;
///
/// let params = KdfParams::default();
/// assert_eq!(params.memory_kib, 256 * 1024);
/// assert_eq!(params.iterations, 4);
/// assert_eq!(params.parallelism, 2);
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KdfParams {
    /// Which KDF algorithm to use. Currently always [`KdfAlgorithm::Argon2id13`].
    pub algorithm: KdfAlgorithm,

    /// Peak memory budget in kibibytes (1 KiB = 1024 bytes).
    ///
    /// Default: 262144 KiB (256 MiB). Must be at least 8 * `parallelism` KiB
    /// per the Argon2 spec.
    pub memory_kib: u32,

    /// Number of passes (time cost) over the memory region.
    ///
    /// Default: 4. Higher values increase CPU time linearly.
    pub iterations: u32,

    /// Number of parallel lanes (threads) used during hashing.
    ///
    /// Default: 2. Should not exceed the number of available CPU cores.
    pub parallelism: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            algorithm: KdfAlgorithm::Argon2id13,
            memory_kib: 256 * 1024, // 256 MiB
            iterations: 4,
            parallelism: 2,
        }
    }
}

/// Default chunk size for splitting files before encryption: 1 MiB (1,048,576 bytes).
///
/// **Deprecated.** The system now uses a dynamic 4–256 MiB chunk-size ladder
/// driven by [`beebeeb_types::ChunkProfile`] and [`beebeeb_types::plan_chunks`].
/// This constant is retained for historical compatibility but is no longer used
/// anywhere in the codebase — use the `chunk.rs` planning functions instead.
#[deprecated(
    since = "0.2.0",
    note = "Use beebeeb_types::plan_chunks / ChunkProfile instead; the system uses a 4-256 MiB dynamic ladder."
)]
pub const CHUNK_SIZE: usize = 1024 * 1024; // 1 MiB

/// Number of words in a BIP39 recovery phrase: 12.
///
/// A 12-word BIP39 mnemonic encodes 128 bits of entropy, which is the master
/// secret for the user's account. The recovery phrase can recreate the master
/// key independently of the password — it is the ultimate backup.
///
/// Used by `beebeeb-core::recovery` to generate and validate phrases.
pub const RECOVERY_WORD_COUNT: usize = 12;
