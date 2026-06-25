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

    /// Export the raw key bytes. **WASM boundary only** — the caller is
    /// responsible for zeroizing the returned array when it is no longer needed.
    /// Prefer keeping a `MasterKey` handle whenever possible.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.bytes
    }

    /// Reconstruct a `MasterKey` from raw bytes that previously crossed
    /// the WASM boundary. The source array is zeroized after construction.
    pub fn from_bytes(mut bytes: [u8; 32]) -> Self {
        let mk = Self { bytes };
        bytes.zeroize();
        mk
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

    /// Reconstruct a `FileKey` from raw bytes that previously crossed
    /// the WASM boundary. The source array is zeroized after construction.
    pub fn from_bytes(mut bytes: [u8; 32]) -> Self {
        let fk = Self { bytes };
        bytes.zeroize();
        fk
    }
}

const MIN_SALT_LEN: usize = 16;

/// Canonical Argon2id master-key parameters: 256 MiB memory, 4 iterations,
/// 2 lanes, 32-byte output. These are the project-wide strong defaults — they
/// match `beebeeb_types::KdfParams::default()` and the recovery-phrase
/// derivation in `recovery::derive_key_from_entropy`. **Do not lower them:**
/// `derive_master_key` is a prod-callable export (web via WASM
/// `derive_master_key`, mobile via UniFFI `deriveMasterKey`), so any weakening
/// here weakens a real client-reachable master-key derivation.
const MK_MEMORY_KIB: u32 = 256 * 1024; // 256 MiB
const MK_ITERATIONS: u32 = 4;
const MK_PARALLELISM: u32 = 2;

/// Derive a master key from a user password and salt using Argon2id.
///
/// Parameters: memory = 256 MiB, iterations = 4, parallelism = 2, output = 32
/// bytes — the canonical strong derivation (≈0.5–1s on a modern laptop), shared
/// with `KdfParams::default()` and the recovery-phrase path. This is a
/// prod-callable export reachable from web (WASM) and mobile (UniFFI), so it
/// uses the full memory-hard cost rather than any "fast" dev profile.
/// Salt must be at least 16 bytes (128 bits) per NIST SP 800-132.
pub fn derive_master_key(password: &str, salt: &[u8]) -> Result<MasterKey, CoreError> {
    if salt.len() < MIN_SALT_LEN {
        return Err(CoreError::InvalidInput(format!(
            "salt must be at least {MIN_SALT_LEN} bytes, got {}",
            salt.len()
        )));
    }

    let params = Params::new(MK_MEMORY_KIB, MK_ITERATIONS, MK_PARALLELISM, Some(32))
        .map_err(|e| CoreError::Kdf(format!("invalid argon2 params: {e}")))?;
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
    // NB: salt=None is intentional — this derivation is used for both encrypting
    // and decrypting existing files. Changing the salt would silently break
    // decryption of every file already stored. A future migration (new
    // cipher_suite version) could introduce a salted v2 derivation for newly
    // created files while keeping this path for legacy decryption.
    let hk = Hkdf::<Sha256>::new(None, master_key.as_bytes());

    let mut info = Vec::with_capacity(19 + file_id.len());
    info.extend_from_slice(b"beebeeb-file-key-v1");
    info.extend_from_slice(file_id);

    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(&info, &mut *okm)
        .expect("HKDF-SHA256 expand for 32 bytes cannot fail");
    FileKey { bytes: *okm }
}

/// Derive a per-shard key for the encrypted search index (task 0778).
///
/// Each shard (bucket) of the search index is encrypted under its own key,
/// derived from the master key via HKDF-SHA256 with a domain-separation label
/// (`beebeeb-search-index-shard-v1`) distinct from the per-file label. This
/// keeps the index keyspace cryptographically separate from file keys and
/// limits the blast radius to a single shard. The returned `FileKey` is the
/// same 32-byte AEAD key type used by `encrypt_chunk` / `decrypt_chunk`; it is
/// zeroized on drop.
pub fn derive_search_index_key(master_key: &MasterKey, bucket: u32) -> FileKey {
    let hk = Hkdf::<Sha256>::new(None, master_key.as_bytes());

    let mut info = Vec::with_capacity(29 + 4);
    info.extend_from_slice(b"beebeeb-search-index-shard-v1");
    info.extend_from_slice(&bucket.to_le_bytes());

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
    fn master_key_params_are_the_canonical_strong_set() {
        // Guard against a regression that re-introduces weak (fast) Argon2
        // params. `derive_master_key` is a prod-callable export (WASM/UniFFI),
        // so these MUST stay at the canonical 256 MiB / 4 iter / 2 par — the
        // same set as KdfParams::default() and the recovery-phrase derivation.
        assert_eq!(MK_MEMORY_KIB, 256 * 1024, "memory must be 256 MiB");
        assert_eq!(MK_ITERATIONS, 4, "iterations must be 4");
        assert_eq!(MK_PARALLELISM, 2, "parallelism must be 2");
        // The defaults type in beebeeb-types must agree (single source of truth).
        let canonical = beebeeb_types::KdfParams::default();
        assert_eq!(MK_MEMORY_KIB, canonical.memory_kib);
        assert_eq!(MK_ITERATIONS, canonical.iterations);
        assert_eq!(MK_PARALLELISM, canonical.parallelism);
    }

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

    #[test]
    fn search_index_key_deterministic() {
        let mk = derive_master_key("password", TEST_SALT).unwrap();
        let k1 = derive_search_index_key(&mk, 7);
        let k2 = derive_search_index_key(&mk, 7);
        assert_eq!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn search_index_keys_differ_per_bucket() {
        let mk = derive_master_key("password", TEST_SALT).unwrap();
        let k1 = derive_search_index_key(&mk, 0);
        let k2 = derive_search_index_key(&mk, 1);
        assert_ne!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn search_index_key_is_domain_separated_from_file_key() {
        // Same master key, and a file_id whose bytes equal the bucket's LE bytes,
        // must NOT collide with the search-index derivation (distinct HKDF info).
        let mk = derive_master_key("password", TEST_SALT).unwrap();
        let sik = derive_search_index_key(&mk, 0);
        let fk = derive_file_key(&mk, &0u32.to_le_bytes());
        assert_ne!(sik.as_bytes(), fk.as_bytes());
    }

    // ---------------------------------------------------------------------
    // Cross-client KAT (known-answer test) for the search-index shard key.
    //
    // `derive_search_index_key` is the ONE definition of the search-index
    // shard-key derivation for EVERY client: web consumes it via WASM
    // (`WasmSearchIndex`) and mobile via UniFFI (`SearchIndexHandle`), both of
    // which call `search_index::SearchIndex::{encrypt_shards,
    // from_encrypted_shards}` — which in turn call THIS function. Neither
    // binding re-implements the derivation, so the single vector below is the
    // cross-client contract for all of them.
    //
    // The expected bytes are PINNED. HKDF-SHA256 is deterministic, so for the
    // fixed 32-byte master key and bucket index below the output can never
    // change unless the derivation itself changes (the HKDF salt, the
    // `beebeeb-search-index-shard-v1` domain-separation label, the bucket
    // encoding, or the hash). If you change this function and this test fails,
    // that is NOT a test to "just update": a changed vector means every client's
    // already-uploaded, server-side encrypted search index becomes
    // undecryptable and MUST be re-derived/rebuilt under the new key — a
    // coordinated cross-client migration, never a silent refactor.
    //
    // Master key: 32 bytes all 0x01. Vectors cover bucket 0, an interior
    // bucket (7), and the last bucket of the default 64-shard layout (63).
    const KAT_MASTER_KEY: [u8; 32] = [0x01u8; 32];

    #[test]
    fn search_index_key_known_answer_vectors() {
        let mk = MasterKey::from_bytes(KAT_MASTER_KEY);

        // bucket -> pinned 32-byte HKDF-SHA256 output, lowercase hex.
        let vectors: [(u32, &str); 3] = [
            (
                0,
                "08c1676ae10ef9b8cfb4993db59bb7f899885b9364e54c466e80b4ca1047c364",
            ),
            (
                7,
                "352c86bacad05a8e681ae66080c1b79b304c5e8451672dc9a62f85ee2a29b920",
            ),
            (
                63,
                "d1e0ac588ec8a495e527f9b80364bbac628f97dc782d08cde4897603dddd1e27",
            ),
        ];

        for (bucket, expected_hex) in vectors {
            let key = derive_search_index_key(&mk, bucket);
            assert_eq!(
                hex::encode(key.as_bytes()),
                expected_hex,
                "search-index KAT diverged for bucket {bucket} — this breaks every \
                 client's stored search index; see comment above this test"
            );
        }
    }
}
