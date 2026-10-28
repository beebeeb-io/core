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
    /// Generate an independent 256-bit key from the OS CSPRNG.
    pub fn generate() -> Result<Self, CoreError> {
        use rand::RngCore;
        let mut bytes = Zeroizing::new([0u8; 32]);
        rand::rngs::OsRng
            .try_fill_bytes(&mut *bytes)
            .map_err(|e| CoreError::Encryption(format!("OS randomness unavailable: {e}")))?;
        Ok(Self::from_bytes(*bytes))
    }

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

/// Derive a purpose-bound subkey of a per-file key: `HKDF-SHA256(salt = none,
/// ikm = file_key, info)`. Each purpose (v2 content frames, the name/MIME
/// envelope, thumbnails, file notes) uses its own `info`, so a blob sealed for
/// one purpose can never authenticate as another (task 1908).
pub fn derive_file_subkey(file_key: &FileKey, info: &[u8]) -> FileKey {
    let hk = Hkdf::<Sha256>::new(None, file_key.as_bytes());
    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(info, &mut *okm)
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

/// Domain-separation label for a shared folder's encrypted search index
/// (task 2237). Deliberately distinct from `beebeeb-search-index-shard-v1`:
/// a shared folder's index is keyed from the folder key, so a collision with
/// the account index key would let one keyspace decrypt the other.
pub const SHARED_FOLDER_INDEX_KEY_INFO: &[u8] = b"beebeeb-shared-folder-index-v1";

/// Derive the per-bucket key of a shared folder's encrypted search index
/// (task 2237): `HKDF-SHA256(salt = none, ikm = folder_key, info = label ||
/// bucket as u32 little-endian)`, 32 bytes. Mirrors `derive_search_index_key`
/// with a different IKM and label, so the same folder key yields an
/// independent key per bucket.
pub fn derive_shared_folder_index_key(folder_key: &FileKey, bucket: u32) -> FileKey {
    let hk = Hkdf::<Sha256>::new(None, folder_key.as_bytes());
    let mut info = Vec::with_capacity(SHARED_FOLDER_INDEX_KEY_INFO.len() + 4);
    info.extend_from_slice(SHARED_FOLDER_INDEX_KEY_INFO);
    info.extend_from_slice(&bucket.to_le_bytes());
    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(&info, &mut *okm)
        .expect("HKDF-SHA256 expand for 32 bytes cannot fail");
    FileKey { bytes: *okm }
}

/// Domain-separation label for the folder link key combiner (task 2237b).
pub const FOLDER_LINK_KEY_INFO: &[u8] = b"beebeeb-folder-link-key-v1";

/// Token-bound salt domain for a folder link's Argon2id passphrase stretch.
pub const FOLDER_LINK_PASSPHRASE_SALT_LABEL: &[u8] = b"beebeeb-folder-link-passphrase-v1";

/// Stretch a folder-link passphrase with the canonical strong Argon2id cost.
/// Salt = SHA-256(UTF-8 token || label)[0..16]. A KDF failure is an error;
/// callers must never downgrade a protected link to a plain link.
pub fn derive_folder_link_passphrase_stretch(passphrase: &str, token: &str) -> Result<Zeroizing<[u8; 32]>, CoreError> {
    use sha2::Digest;
    let mut digest = Sha256::new();
    digest.update(token.as_bytes());
    digest.update(FOLDER_LINK_PASSPHRASE_SALT_LABEL);
    let salt = digest.finalize();
    let key = derive_master_key(passphrase, &salt[..16])?;
    Ok(Zeroizing::new(*key.as_bytes()))
}

/// Combine a folder link's fragment key `K_c` with an optional passphrase
/// stretch into the 32-byte key that unwraps the link's sealed folder key.
///
/// - `None` (no passphrase): `HKDF-SHA256(salt = none, ikm = K_c,
///   info = label || 0x00)`.
/// - `Some(stretch)`: `HKDF-SHA256(salt = none, ikm = K_c || stretch,
///   info = label || 0x01)`, where `stretch` is the client's Argon2id output
///   over the passphrase and the link salt.
///
/// The presence byte and the distinct IKM keep the two modes (and both modes
/// from any other derivation in this module) cryptographically separate, so a
/// link can never be opened with the wrong mode's key. This derivation is
/// public by design: `K_c` is in the link fragment and never reaches the
/// server; it is not an account key.
pub fn combine_folder_link_key(k_c: &[u8; 32], passphrase_stretch: Option<&[u8; 32]>) -> [u8; 32] {
    let mut ikm = Zeroizing::new(Vec::with_capacity(64));
    ikm.extend_from_slice(k_c);
    if let Some(stretch) = passphrase_stretch {
        ikm.extend_from_slice(stretch);
    }
    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut info = Vec::with_capacity(FOLDER_LINK_KEY_INFO.len() + 1);
    info.extend_from_slice(FOLDER_LINK_KEY_INFO);
    info.push(u8::from(passphrase_stretch.is_some()));
    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(&info, &mut *okm)
        .expect("HKDF-SHA256 expand for 32 bytes cannot fail");
    *okm
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn folder_link_passphrase_stretch_matches_the_web_vector() {
        let doc: serde_json::Value = serde_json::from_str(include_str!("../../test-vectors/vectors.json")).unwrap();
        let v = doc["vectors"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["name"] == "folder_link_passphrase")
            .unwrap();
        let stretch =
            derive_folder_link_passphrase_stretch(v["passphrase"].as_str().unwrap(), v["token"].as_str().unwrap())
                .unwrap();
        assert_eq!(hex::encode(*stretch), v["stretch_hex"].as_str().unwrap());
    }

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

    // ---------------------------------------------------------------------
    // Cross-client KAT for the shared-folder index key (task 2237).
    //
    // A shared folder's search index uses its own key hierarchy: the folder
    // key (not an account master key) is the IKM, and the domain-separation
    // label is `beebeeb-shared-folder-index-v1`. One key per bucket, exactly
    // like the account index. Same warning as above: a changed vector means
    // every stored shared-folder index becomes undecryptable.
    //
    // Folder key: 32 bytes 0x80..=0x9f. Vectors cover bucket 0, an interior
    // bucket (7), and the last bucket of the default 64-bucket layout (63).
    const KAT_FOLDER_KEY: [u8; 32] = {
        let mut k = [0u8; 32];
        let mut i = 0;
        while i < 32 {
            k[i] = 0x80 + i as u8;
            i += 1;
        }
        k
    };

    #[test]
    fn shared_folder_index_key_known_answer_vectors() {
        let folder_key = FileKey::from_bytes(KAT_FOLDER_KEY);

        let vectors: [(u32, &str); 3] = [
            (0, "a4a09ac7b7e2d845a05c1b67930024a043c6bda3ed280f5fcf627ddb15d1208c"),
            (7, "d137ca8982ca27f94260e6cf43ef1479b6fe5e658ac65741fcaca848522df0fd"),
            (63, "c88fd54b38b22e112085870cf8d1cf7b6ce124ab232b8d817e11c1bec16aa0a2"),
        ];

        for (bucket, expected_hex) in vectors {
            let key = derive_shared_folder_index_key(&folder_key, bucket);
            assert_eq!(
                hex::encode(key.as_bytes()),
                expected_hex,
                "shared-folder index KAT diverged for bucket {bucket} — this breaks \
                 every stored shared-folder search index; see comment above this test"
            );
        }
    }

    #[test]
    fn combine_folder_link_key_known_answer_vectors() {
        // K_c = 0x80..=0x9f, passphrase stretch = 0xa0..=0xbf. These pin the
        // public combiner every client uses to open a folder link; a change
        // breaks every link already handed out.
        let k_c: [u8; 32] = KAT_FOLDER_KEY;
        let stretch: [u8; 32] = {
            let mut s = [0u8; 32];
            for (i, b) in s.iter_mut().enumerate() {
                *b = 0xa0 + i as u8;
            }
            s
        };

        assert_eq!(
            hex::encode(combine_folder_link_key(&k_c, None)),
            "5fb510b7068bfa1e9290e8a8ed296da4f610e5451a567699dc48e9bc3bd1badc"
        );
        assert_eq!(
            hex::encode(combine_folder_link_key(&k_c, Some(&stretch))),
            "1b87f03afb4b81c4b17c1a6f74648a4e725d1d5c1e0750b5767df89ee653b13b"
        );
    }

    #[test]
    fn combine_folder_link_key_modes_are_domain_separated() {
        let k_c = KAT_FOLDER_KEY;
        let none = combine_folder_link_key(&k_c, None);
        assert_ne!(none, k_c, "a passphrase-free link still uses the combiner domain");
        let zero_stretch = combine_folder_link_key(&k_c, Some(&[0u8; 32]));
        assert_ne!(none, zero_stretch, "presence byte distinguishes the modes");

        // Distinct from every other derivation in this module even with the
        // same 32 input bytes.
        let folder_key = FileKey::from_bytes(KAT_FOLDER_KEY);
        assert_ne!(none, *derive_shared_folder_index_key(&folder_key, 0).as_bytes());
        let mk = MasterKey::from_bytes(KAT_FOLDER_KEY);
        assert_ne!(none, *derive_search_index_key(&mk, 0).as_bytes());

        // A different K_c or stretch never collides.
        let mut other = KAT_FOLDER_KEY;
        other[31] ^= 1;
        assert_ne!(none, combine_folder_link_key(&other, None));
        let mut other_stretch = [0xa0u8; 32];
        other_stretch[0] ^= 1;
        assert_ne!(zero_stretch, combine_folder_link_key(&k_c, Some(&other_stretch)));
    }

    #[test]
    fn shared_folder_index_key_is_domain_separated_from_search_index_key() {
        // Same 32 key bytes fed to both derivations must not collide: the two
        // index keyspaces are cryptographically separate even for bucket 0.
        let folder_key = FileKey::from_bytes(KAT_FOLDER_KEY);
        let mk = MasterKey::from_bytes(KAT_FOLDER_KEY);
        let shared = derive_shared_folder_index_key(&folder_key, 0);
        let account = derive_search_index_key(&mk, 0);
        assert_ne!(shared.as_bytes(), account.as_bytes());
    }

    #[test]
    fn shared_folder_index_keys_differ_per_bucket() {
        let folder_key = FileKey::from_bytes(KAT_FOLDER_KEY);
        let k1 = derive_shared_folder_index_key(&folder_key, 0);
        let k2 = derive_shared_folder_index_key(&folder_key, 1);
        assert_ne!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn search_index_key_known_answer_vectors() {
        let mk = MasterKey::from_bytes(KAT_MASTER_KEY);

        // bucket -> pinned 32-byte HKDF-SHA256 output, lowercase hex.
        let vectors: [(u32, &str); 3] = [
            (0, "08c1676ae10ef9b8cfb4993db59bb7f899885b9364e54c466e80b4ca1047c364"),
            (7, "352c86bacad05a8e681ae66080c1b79b304c5e8451672dc9a62f85ee2a29b920"),
            (63, "d1e0ac588ec8a495e527f9b80364bbac628f97dc782d08cde4897603dddd1e27"),
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
