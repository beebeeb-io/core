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
    let mut memory = allocate_argon_memory(params.block_count())?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut output = Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into_with_memory(password.as_bytes(), salt, &mut *output, memory.as_mut_slice())
        .map_err(|e| CoreError::Kdf(format!("argon2 hashing failed: {e}")))?;

    Ok(MasterKey::from_zeroizing(output))
}

fn allocate_argon_memory(block_count: usize) -> Result<Zeroizing<Vec<argon2::Block>>, CoreError> {
    let mut memory = Vec::new();
    memory
        .try_reserve_exact(block_count)
        .map_err(|_| CoreError::Kdf("insufficient memory for Argon2id".into()))?;
    memory.resize(block_count, argon2::Block::new());
    Ok(Zeroizing::new(memory))
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
    if passphrase.is_empty() {
        return Err(CoreError::InvalidInput(
            "folder-link passphrase must not be empty".into(),
        ));
    }
    let normalized = normalize_passphrase(passphrase)?;
    let mut digest = Sha256::new();
    digest.update(token.as_bytes());
    digest.update(FOLDER_LINK_PASSPHRASE_SALT_LABEL);
    let salt = digest.finalize();
    let key = derive_master_key(&normalized, &salt[..16])?;
    Ok(Zeroizing::new(*key.as_bytes()))
}

// Canonical normalization with owned, fallibly allocated, wiped scratch. The
// standard NFC iterator can spill nonstarters to an unwiped heap allocation.
fn normalize_passphrase(input: &str) -> Result<Zeroizing<String>, CoreError> {
    use unicode_normalization::char::{canonical_combining_class as ccc, compose, decompose_canonical};
    let allocation_error = || CoreError::Kdf("insufficient normalization memory".into());
    let mut count = Some(0usize);
    for ch in input.chars() {
        decompose_canonical(ch, |_| {
            count = count.and_then(|n| n.checked_add(1));
        });
    }
    let mut scratch = Zeroizing::new(Vec::<char>::new());
    scratch
        .try_reserve_exact(count.ok_or_else(allocation_error)?)
        .map_err(|_| allocation_error())?;
    for ch in input.chars() {
        decompose_canonical(ch, |c| scratch.push(c));
    }
    // Stable in-place ordering avoids the allocating sort scratch. Equal
    // classes retain their order; starters delimit combining sequences.
    for i in 1..scratch.len() {
        let class = ccc(scratch[i]);
        if class == 0 {
            continue;
        }
        let mut j = i;
        while j > 0 && ccc(scratch[j - 1]) > class {
            scratch.swap(j - 1, j);
            j -= 1;
        }
    }
    let mut written = 0usize;
    let mut starter: Option<usize> = None;
    let mut last_class = 0;
    for i in 0..scratch.len() {
        let ch = scratch[i];
        let class = ccc(ch);
        if let Some(at) = starter {
            if last_class == 0 || last_class < class {
                if let Some(composed) = compose(scratch[at], ch) {
                    scratch[at] = composed;
                    continue;
                }
            }
        }
        scratch[written] = ch;
        if class == 0 {
            starter = Some(written);
        }
        last_class = class;
        written += 1;
    }
    let bytes = scratch[..written]
        .iter()
        .try_fold(0usize, |n, c| n.checked_add(c.len_utf8()))
        .ok_or_else(allocation_error)?;
    let mut output = Zeroizing::new(String::new());
    output.try_reserve_exact(bytes).map_err(|_| allocation_error())?;
    for &ch in &scratch[..written] {
        output.push(ch);
    }
    // Keep the entire scratch length alive so its duplicate tail is wiped too.
    Ok(output)
}

/// L7: root UUID bytes, item UUID bytes, and kind (1=file, 2=folder).
pub const FOLDER_CHILD_LABEL: &[u8] = b"beebeeb-folder-child-v1";
fn folder_child_context(root: &[u8], item: &[u8], kind: u8) -> Result<Vec<u8>, CoreError> {
    if root.len() != 16 || item.len() != 16 || !matches!(kind, 1 | 2) {
        return Err(CoreError::InvalidInput(
            "folder child requires 16-byte root/item UUIDs and kind 1 or 2".into(),
        ));
    }
    Ok([FOLDER_CHILD_LABEL, root, item, &[kind]].concat())
}
pub(crate) fn wrap_folder_child_with_nonce(
    folder: &FileKey,
    root: &[u8],
    item: &[u8],
    kind: u8,
    child: &FileKey,
    nonce: &[u8; 12],
) -> Result<beebeeb_types::EncryptedBlob, CoreError> {
    let context = folder_child_context(root, item, kind)?;
    let raw = crate::encrypt::seal_raw_with_nonce(folder, nonce, child.as_bytes(), &context)?;
    Ok(beebeeb_types::EncryptedBlob {
        cipher_suite: beebeeb_types::CipherSuite::V1Aes256Gcm,
        nonce: raw[..12].to_vec(),
        ciphertext: raw[12..].to_vec(),
    })
}
pub fn wrap_folder_child(
    folder: &FileKey,
    root: &[u8],
    item: &[u8],
    kind: u8,
    child: &FileKey,
) -> Result<beebeeb_types::EncryptedBlob, CoreError> {
    use rand::RngCore;
    let mut nonce = [0; 12];
    rand::rngs::OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|e| CoreError::Encryption(format!("OS randomness unavailable: {e}")))?;
    wrap_folder_child_with_nonce(folder, root, item, kind, child, &nonce)
}
pub fn unwrap_folder_child(
    folder: &FileKey,
    root: &[u8],
    item: &[u8],
    kind: u8,
    blob: &beebeeb_types::EncryptedBlob,
) -> Result<FileKey, CoreError> {
    let context = folder_child_context(root, item, kind)?;
    if blob.cipher_suite != beebeeb_types::CipherSuite::V1Aes256Gcm
        || blob.nonce.len() != 12
        || blob.ciphertext.len() != 48
    {
        return Err(CoreError::Decryption);
    }
    let bytes = Zeroizing::new(crate::encrypt::open_raw_with_aad(
        folder,
        &[blob.nonce.as_slice(), blob.ciphertext.as_slice()].concat(),
        &context,
    )?);
    let key: &[u8; 32] = bytes.as_slice().try_into().map_err(|_| CoreError::Decryption)?;
    Ok(FileKey::from_bytes(*key))
}

/// L6/L8: purpose and record id are bound twice: as HKDF info and AEAD AAD.
pub const OWNER_FILE_KEY_LABEL: &[u8] = b"beebeeb-owner-file-key-v1";
pub const FOLDER_CUSTODY_LABEL: &[u8] = b"beebeeb-folder-custody-v1";
pub const LINK_OWNER_KEY_LABEL: &[u8] = b"beebeeb-link-owner-key-v1";
pub const LINK_OWNER_TOKEN_LABEL: &[u8] = b"beebeeb-link-owner-token-v1";

fn purpose_context(label: &[u8], id: &[u8]) -> Result<Vec<u8>, CoreError> {
    if id.is_empty() {
        return Err(CoreError::InvalidInput("wrap record id must not be empty".into()));
    }
    Ok([label, id].concat())
}

fn purpose_key(master: &MasterKey, context: &[u8]) -> FileKey {
    let mut bytes = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(None, master.as_bytes())
        .expand(context, &mut *bytes)
        .expect("HKDF-SHA256 expand for 32 bytes cannot fail");
    FileKey::from_bytes(*bytes)
}

pub(crate) fn purpose_wrap_with_nonce(
    master: &MasterKey,
    label: &[u8],
    id: &[u8],
    plaintext: &[u8],
    nonce: &[u8; 12],
) -> Result<beebeeb_types::EncryptedBlob, CoreError> {
    let context = purpose_context(label, id)?;
    let raw = crate::encrypt::seal_raw_with_nonce(&purpose_key(master, &context), nonce, plaintext, &context)?;
    Ok(beebeeb_types::EncryptedBlob {
        cipher_suite: beebeeb_types::CipherSuite::V1Aes256Gcm,
        nonce: raw[..12].to_vec(),
        ciphertext: raw[12..].to_vec(),
    })
}

fn purpose_wrap(
    master: &MasterKey,
    label: &[u8],
    id: &[u8],
    plaintext: &[u8],
) -> Result<beebeeb_types::EncryptedBlob, CoreError> {
    use rand::RngCore;
    let mut nonce = [0u8; 12];
    rand::rngs::OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|e| CoreError::Encryption(format!("OS randomness unavailable: {e}")))?;
    purpose_wrap_with_nonce(master, label, id, plaintext, &nonce)
}

fn purpose_unwrap(
    master: &MasterKey,
    label: &[u8],
    id: &[u8],
    blob: &beebeeb_types::EncryptedBlob,
) -> Result<Zeroizing<Vec<u8>>, CoreError> {
    if blob.cipher_suite != beebeeb_types::CipherSuite::V1Aes256Gcm || blob.nonce.len() != 12 {
        return Err(CoreError::Decryption);
    }
    let context = purpose_context(label, id)?;
    crate::encrypt::open_raw_with_aad(
        &purpose_key(master, &context),
        &[blob.nonce.as_slice(), blob.ciphertext.as_slice()].concat(),
        &context,
    )
    .map(Zeroizing::new)
}

fn purpose_unwrap_key(
    master: &MasterKey,
    label: &[u8],
    id: &[u8],
    blob: &beebeeb_types::EncryptedBlob,
) -> Result<FileKey, CoreError> {
    let bytes = purpose_unwrap(master, label, id, blob)?;
    let key: &[u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| CoreError::InvalidInput("wrapped key must be exactly 32 bytes".into()))?;
    Ok(FileKey::from_bytes(*key))
}

/// Owner file-key adoption, bound to the item ID using the L6 encoding.
/// Never accepts legacy name/content ciphertext or unbound owner wraps.
pub fn wrap_owner_file_key(
    master: &MasterKey,
    item_id: &[u8],
    key: &FileKey,
) -> Result<beebeeb_types::EncryptedBlob, CoreError> {
    purpose_wrap(master, OWNER_FILE_KEY_LABEL, item_id, key.as_bytes())
}

/// Open only an L8 purpose-bound, exactly 32-byte owner file key.
pub fn unwrap_owner_file_key(
    master: &MasterKey,
    item_id: &[u8],
    blob: &beebeeb_types::EncryptedBlob,
) -> Result<FileKey, CoreError> {
    purpose_unwrap_key(master, OWNER_FILE_KEY_LABEL, item_id, blob)
}

/// L9 (task 2255): the most distinct `file_id`s one legacy possession proof
/// examines. A server can send any number of rows; the proof stays bounded.
pub const LEGACY_FOLDER_KEY_PROOF_CAP: usize = 64;

/// A legacy key wrap on the wire: nonce(12) || ciphertext(32) || tag(16), no AAD.
const LEGACY_KEY_WRAP_LEN: usize = 12 + 32 + 16;

/// L9 (task 2255, corrected 2026-10-28): may `candidate`, read from a LEGACY
/// invite owner copy, be reused as the folder's key?
///
/// A legacy owner copy is sealed under `derive_file_key(master, folder_id)`
/// with no AAD. That is the same key that seals the folder's own name JSON, so
/// a server can hand back the name blob as an "owner copy". The rules:
/// 1. A candidate that is valid UTF-8 is refused. Everything sealed under that
///    key for a folder is text (its name JSON); a random 32-byte key is valid
///    UTF-8 with probability about 2^-30.
/// 2. Possession: some row `(file_id, wrap)` of the folder must open under the
///    candidate (legacy format, empty AAD) to exactly
///    `derive_file_key(master, file_id)`. Any of the folder's rows counts,
///    except the folder's own row (`file_id == folder_id`): the honest invite
///    flow never writes it, and it carries the folder's name key. Each
///    `file_id` is examined once, and at most [`LEGACY_FOLDER_KEY_PROOF_CAP`]
///    distinct ids are examined.
/// 3. That comparison is constant-time.
///
/// What this does NOT prove. Owner-derived child keys are shared by design
/// (file links, share recipients, folder members), so the proof only shows
/// that someone holds one of them. Named residuals:
/// - Attack B: a server that knows the folder's own name key (from a pre-2238
///   folder link; once any folder link exists, from ANY link guest or invite
///   member it colludes with, because the link path writes the folder's own
///   row; or a colluding member of an enclosing shared folder) and one child's
///   key can seal a non-text key of its choice as a legacy owner copy, plus a
///   matching row, and this check passes.
///   See `invite_legacy_residual_attack_b_name_key_holder_can_forge`.
/// - Rule 1 trusts the server's `is_folder`: a FILE id passed off as a folder
///   could have non-text content sealed under that key. Contrived; the chunk
///   AAD of task 1908 closes it.
/// - P3-3: no key version is bound, so an older genuine owner copy passes too.
pub fn verify_legacy_folder_key<I, F, W>(master: &MasterKey, folder_id: &[u8], candidate: &[u8], rows: I) -> bool
where
    I: IntoIterator<Item = (F, W)>,
    F: AsRef<[u8]>,
    W: AsRef<[u8]>,
{
    use subtle::ConstantTimeEq;
    let Ok(candidate): Result<&[u8; 32], _> = candidate.try_into() else {
        return false;
    };
    // Rule 1. `from_utf8` exits early, so its timing hints where the first
    // non-UTF-8 byte of a real key sits; that leaks a few bits at most, to a
    // local observer only.
    if std::str::from_utf8(candidate).is_ok() {
        return false;
    }
    let key = FileKey::from_bytes(*candidate);
    let mut seen = std::collections::BTreeSet::new();
    for (file_id, wrap) in rows {
        if seen.len() >= LEGACY_FOLDER_KEY_PROOF_CAP {
            break;
        }
        let (file_id, wrap) = (file_id.as_ref(), wrap.as_ref());
        if !seen.insert(file_id.to_vec())
            || file_id.is_empty()
            || file_id == folder_id
            || wrap.len() != LEGACY_KEY_WRAP_LEN
        {
            continue;
        }
        let Ok(opened) = crate::encrypt::open_raw_with_aad(&key, wrap, &[]) else {
            continue;
        };
        let opened = Zeroizing::new(opened);
        if bool::from(opened.as_slice().ct_eq(derive_file_key(master, file_id).as_bytes())) {
            return true;
        }
    }
    false
}

/// L9: open a LEGACY invite owner copy and return its key only when
/// [`verify_legacy_folder_key`] proves it over the folder's `rows`. Returns
/// `None` when the copy does not open, is not exactly 32 bytes, or is not
/// proven; the caller then refuses to reuse it (it must never mint a second
/// key for a folder that already has members). The unproven candidate never
/// leaves core. Attack B and P3-3 apply; see [`verify_legacy_folder_key`].
pub fn open_legacy_invite_owner_copy<I, F, W>(
    master: &MasterKey,
    folder_id: &[u8],
    legacy_copy: &[u8],
    rows: I,
) -> Option<FileKey>
where
    I: IntoIterator<Item = (F, W)>,
    F: AsRef<[u8]>,
    W: AsRef<[u8]>,
{
    if folder_id.is_empty() || legacy_copy.len() != LEGACY_KEY_WRAP_LEN {
        return None;
    }
    let opened =
        Zeroizing::new(crate::encrypt::open_raw_with_aad(&derive_file_key(master, folder_id), legacy_copy, &[]).ok()?);
    let candidate: Zeroizing<[u8; 32]> = Zeroizing::new(opened.as_slice().try_into().ok()?);
    verify_legacy_folder_key(master, folder_id, &*candidate, rows).then(|| FileKey::from_bytes(*candidate))
}

/// Purpose domain for invite owner copies, distinct from custody and metadata.
pub const INVITE_OWNER_COPY_LABEL: &[u8] = b"beebeeb-invite-owner-copy-v1";

/// Seal an invite's owner copy, binding its purpose and folder id (L9).
pub fn wrap_invite_owner_copy(
    master: &MasterKey,
    folder_id: &[u8],
    key: &FileKey,
) -> Result<beebeeb_types::EncryptedBlob, CoreError> {
    purpose_wrap(master, INVITE_OWNER_COPY_LABEL, folder_id, key.as_bytes())
}

/// Open only the purpose-bound invite format; legacy proof is a separate path.
pub fn unwrap_invite_owner_copy(
    master: &MasterKey,
    folder_id: &[u8],
    blob: &beebeeb_types::EncryptedBlob,
) -> Result<FileKey, CoreError> {
    purpose_unwrap_key(master, INVITE_OWNER_COPY_LABEL, folder_id, blob)
}

/// Permanent folder custody. Never accepts legacy name/file-key ciphertext.
pub fn wrap_folder_custody(
    master: &MasterKey,
    folder_id: &[u8],
    key: &FileKey,
) -> Result<beebeeb_types::EncryptedBlob, CoreError> {
    purpose_wrap(master, FOLDER_CUSTODY_LABEL, folder_id, key.as_bytes())
}
pub fn unwrap_folder_custody(
    master: &MasterKey,
    folder_id: &[u8],
    blob: &beebeeb_types::EncryptedBlob,
) -> Result<FileKey, CoreError> {
    purpose_unwrap_key(master, FOLDER_CUSTODY_LABEL, folder_id, blob)
}
/// Link fragment recovery is bound to the share's id, never the folder's id.
pub fn wrap_link_owner_key(
    master: &MasterKey,
    share_id: &[u8],
    key: &FileKey,
) -> Result<beebeeb_types::EncryptedBlob, CoreError> {
    purpose_wrap(master, LINK_OWNER_KEY_LABEL, share_id, key.as_bytes())
}
pub fn unwrap_link_owner_key(
    master: &MasterKey,
    share_id: &[u8],
    blob: &beebeeb_types::EncryptedBlob,
) -> Result<FileKey, CoreError> {
    purpose_unwrap_key(master, LINK_OWNER_KEY_LABEL, share_id, blob)
}
pub fn wrap_link_owner_token(
    master: &MasterKey,
    share_id: &[u8],
    token: &[u8],
) -> Result<beebeeb_types::EncryptedBlob, CoreError> {
    purpose_wrap(master, LINK_OWNER_TOKEN_LABEL, share_id, token)
}
pub fn unwrap_link_owner_token(
    master: &MasterKey,
    share_id: &[u8],
    blob: &beebeeb_types::EncryptedBlob,
) -> Result<Zeroizing<Vec<u8>>, CoreError> {
    purpose_unwrap(master, LINK_OWNER_TOKEN_LABEL, share_id, blob)
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
    fn rv44_normalization_matches_unicode_reference() {
        use unicode_normalization::UnicodeNormalization;
        for c in (0..=0x10ffff).filter_map(char::from_u32) {
            let input = c.to_string();
            assert_eq!(
                &*normalize_passphrase(&input).unwrap(),
                &input.nfc().collect::<String>()
            );
        }
        for input in [
            "a\u{35c}\u{323}\u{301}",
            "\u{301}\u{323}a",
            "\u{1100}\u{1161}\u{11a8}",
            "a\u{301}\u{300}",
            "\u{344}",
        ] {
            assert_eq!(&*normalize_passphrase(input).unwrap(), &input.nfc().collect::<String>());
        }
    }
    #[test]
    fn l7_child_round_trip_both_kinds() {
        let folder = FileKey::from_bytes([0x40; 32]);
        let child = FileKey::from_bytes([0x60; 32]);
        for kind in [1, 2] {
            let b = wrap_folder_child(&folder, &[1; 16], &[2; 16], kind, &child).unwrap();
            assert_eq!(
                unwrap_folder_child(&folder, &[1; 16], &[2; 16], kind, &b)
                    .unwrap()
                    .as_bytes(),
                child.as_bytes()
            );
        }
    }
    #[test]
    fn l7_swap_rejected() {
        let k = FileKey::from_bytes([3; 32]);
        let b = wrap_folder_child(&k, &[1; 16], &[2; 16], 1, &k).unwrap();
        assert!(unwrap_folder_child(&k, &[1; 16], &[4; 16], 1, &b).is_err());
    }
    #[test]
    fn l7_cross_folder_same_key_rejected() {
        let k = FileKey::from_bytes([3; 32]);
        let b = wrap_folder_child(&k, &[1; 16], &[2; 16], 1, &k).unwrap();
        assert!(unwrap_folder_child(&k, &[4; 16], &[2; 16], 1, &b).is_err());
    }
    #[test]
    fn l7_kind_confusion_rejected() {
        let k = FileKey::from_bytes([3; 32]);
        let b = wrap_folder_child(&k, &[1; 16], &[2; 16], 1, &k).unwrap();
        assert!(unwrap_folder_child(&k, &[1; 16], &[2; 16], 2, &b).is_err());
    }
    #[test]
    fn l6_passphrase_nfd_equals_nfc() {
        let nfc = derive_folder_link_passphrase_stretch("folder café 2237", "token").unwrap();
        let nfd = derive_folder_link_passphrase_stretch("folder cafe\u{301} 2237", "token").unwrap();
        assert_eq!(*nfc, *nfd, "canonically equivalent passphrases must agree");
    }

    #[test]
    fn l6_empty_passphrase_is_rejected() {
        assert!(
            derive_folder_link_passphrase_stretch("", "token").is_err(),
            "empty passphrase accepted"
        );
    }

    #[test]
    fn l6_argon_allocation_is_fallible() {
        assert!(allocate_argon_memory(usize::MAX).is_err());
        assert_eq!(allocate_argon_memory(4).unwrap().len(), 4);
    }

    #[test]
    fn l8_owner_file_key_requires_aad() {
        let master = MasterKey::from_bytes([0x40; 32]);
        let item = b"11111111-1111-4111-8111-111111111111";
        let context = purpose_context(OWNER_FILE_KEY_LABEL, item).unwrap();
        let wrapping_key = purpose_key(&master, &context);
        let key = FileKey::from_bytes([0x60; 32]);
        let no_aad = crate::encrypt::encrypt_chunk(&wrapping_key, key.as_bytes()).unwrap();
        assert!(
            unwrap_owner_file_key(&master, item, &no_aad).is_err(),
            "empty AAD accepted"
        );
        let bound = wrap_owner_file_key(&master, item, &key).unwrap();
        assert!(
            crate::encrypt::decrypt_chunk(&wrapping_key, &bound).is_err(),
            "writer omitted AAD"
        );
    }

    #[test]
    fn l8_owner_file_key_requires_exactly_32_authenticated_bytes() {
        let master = MasterKey::from_bytes([0x40; 32]);
        for length in [0, 31, 32, 33, 64] {
            let blob =
                purpose_wrap_with_nonce(&master, OWNER_FILE_KEY_LABEL, b"item", &vec![0x60; length], &[0x37; 12])
                    .unwrap();
            assert_eq!(
                unwrap_owner_file_key(&master, b"item", &blob).is_ok(),
                length == 32,
                "length {length}"
            );
        }
    }

    #[test]
    fn l6_folder_name_cannot_be_substituted_for_custody() {
        let master = MasterKey::from_bytes([0x40; 32]);
        let name = crate::encrypt::encrypt_name(&master, "folder", "ABCD", None).unwrap();
        let blob: beebeeb_types::EncryptedBlob = serde_json::from_str(&name).unwrap();
        let legacy = crate::encrypt::decrypt_chunk(&derive_file_key(&master, b"folder"), &blob).unwrap();
        assert_eq!(legacy.len(), 32, "regression fixture must pass the old length gate");
        assert!(unwrap_folder_custody(&master, b"folder", &blob).is_err());
    }

    #[test]
    fn l6_wraps_bind_purpose_and_identifier() {
        let master = MasterKey::from_bytes([0x40; 32]);
        let key = FileKey::from_bytes([0x60; 32]);
        let custody = wrap_folder_custody(&master, b"folder", &key).unwrap();
        assert_eq!(
            unwrap_folder_custody(&master, b"folder", &custody).unwrap().as_bytes(),
            key.as_bytes()
        );
        assert!(unwrap_folder_custody(&master, b"other", &custody).is_err());
        assert!(unwrap_link_owner_key(&master, b"folder", &custody).is_err());
        let owner = wrap_link_owner_key(&master, b"share", &key).unwrap();
        assert_eq!(
            unwrap_link_owner_key(&master, b"share", &owner).unwrap().as_bytes(),
            key.as_bytes()
        );
        assert!(unwrap_link_owner_key(&master, b"other", &owner).is_err());
        assert!(unwrap_link_owner_token(&master, b"share", &owner).is_err());
        let token = wrap_link_owner_token(&master, b"share", b"token").unwrap();
        assert_eq!(&*unwrap_link_owner_token(&master, b"share", &token).unwrap(), b"token");
        assert!(unwrap_link_owner_token(&master, b"other", &token).is_err());
        assert!(unwrap_link_owner_key(&master, b"share", &token).is_err());
    }

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

#[cfg(test)]
mod invite_owner_copy_tests {
    use super::*;
    use crate::encrypt::{encrypt_chunk, seal_raw_with_nonce};

    fn wire(blob: beebeeb_types::EncryptedBlob) -> Vec<u8> {
        [blob.nonce, blob.ciphertext].concat()
    }
    const FOLDER: &[u8] = b"11111111-1111-4111-8111-111111111111";
    /// The 32-byte name JSON of a folder called "Docs": valid UTF-8, the shape of
    /// everything sealed under `derive_file_key(master, folder_id)` for a folder.
    const NAME: &[u8; 32] = br#"{"name":"Docs","mime_type":null}"#;

    fn master() -> MasterKey {
        MasterKey::from_bytes([7; 32])
    }
    /// A random-looking folder key; 0xF8 never occurs in UTF-8.
    fn folder_key() -> FileKey {
        FileKey::from_bytes([0xF8; 32])
    }
    /// The legacy (empty-AAD) wrap web's flag-off invites write.
    fn legacy_wrap(key: &FileKey, inner: &[u8]) -> Vec<u8> {
        wire(encrypt_chunk(key, inner).unwrap())
    }
    /// A row the owner wrote: the owner-derived key of `id` under the folder key.
    fn owner_row(master: &MasterKey, key: &FileKey, id: &str) -> (Vec<u8>, Vec<u8>) {
        (
            id.as_bytes().to_vec(),
            legacy_wrap(key, derive_file_key(master, id.as_bytes()).as_bytes()),
        )
    }
    /// A row the owner's derived key does not open to (a member upload, a request upload).
    fn foreign_row(key: &FileKey, id: &str) -> (Vec<u8>, Vec<u8>) {
        (id.as_bytes().to_vec(), legacy_wrap(key, &[0x5A; 32]))
    }
    fn legacy_copy(master: &MasterKey, inner: &[u8]) -> Vec<u8> {
        legacy_wrap(&derive_file_key(master, FOLDER), inner)
    }

    #[test]
    fn invite_legacy_utf8_candidate_is_rejected_even_with_a_passing_row() {
        // Attack A (the review's P1-1): the server knows ONE owner-derived child
        // key (a file link, a share recipient), so it can build a row that opens
        // under the name JSON to exactly that key. Only rule 1 stops it.
        let master = master();
        let name_key = FileKey::from_bytes(*NAME);
        let known = derive_file_key(&master, b"shared-by-link");
        let forged = (b"shared-by-link".to_vec(), legacy_wrap(&name_key, known.as_bytes()));
        assert!(std::str::from_utf8(NAME).is_ok());
        assert!(!verify_legacy_folder_key(&master, FOLDER, NAME, [forged.clone()]));
        // End to end: the folder's own name blob as the "owner copy" opens nothing.
        assert!(open_legacy_invite_owner_copy(&master, FOLDER, &legacy_copy(&master, NAME), [forged]).is_none());
    }

    #[test]
    fn invite_legacy_true_key_is_proven_by_any_row() {
        // Rows that cannot prove (member uploads, request uploads) come first;
        // a nested descendant's owner row proves it. No direct-child filter.
        let (master, key) = (master(), folder_key());
        let rows = vec![
            foreign_row(&key, "member-upload"),
            foreign_row(&key, "request-upload"),
            owner_row(&master, &key, "nested/grandchild"),
        ];
        assert!(verify_legacy_folder_key(&master, FOLDER, key.as_bytes(), rows.clone()));
        let opened = open_legacy_invite_owner_copy(&master, FOLDER, &legacy_copy(&master, key.as_bytes()), rows);
        assert_eq!(opened.unwrap().as_bytes(), key.as_bytes());
        // Except the folder's own row (file_id == folder_id): the honest invite
        // flow never writes it, and it holds the folder's name key.
        let own = owner_row(&master, &key, std::str::from_utf8(FOLDER).unwrap());
        assert!(!verify_legacy_folder_key(&master, FOLDER, key.as_bytes(), [own]));
    }

    #[test]
    fn invite_legacy_fabricated_row_is_rejected() {
        // A wrap under the candidate that holds a server-chosen key is no proof.
        let (master, key) = (master(), folder_key());
        let fabricated = (b"child".to_vec(), legacy_wrap(&key, &[9; 32]));
        assert!(!verify_legacy_folder_key(&master, FOLDER, key.as_bytes(), [fabricated]));
        // The right row under another owner's master proves nothing either.
        let row = owner_row(&master, &key, "child");
        assert!(!verify_legacy_folder_key(
            &MasterKey::from_bytes([6; 32]),
            FOLDER,
            key.as_bytes(),
            [row]
        ));
    }

    #[test]
    fn invite_legacy_without_rows_is_not_proven() {
        let (master, key) = (master(), folder_key());
        let none: [(Vec<u8>, Vec<u8>); 0] = [];
        assert!(!verify_legacy_folder_key(&master, FOLDER, key.as_bytes(), none.clone()));
        assert!(open_legacy_invite_owner_copy(&master, FOLDER, &legacy_copy(&master, key.as_bytes()), none).is_none());
    }

    #[test]
    fn invite_legacy_checks_each_file_id_once() {
        // The first row for an id is the one checked; a later duplicate row with
        // the same id is never tried.
        let (master, key) = (master(), folder_key());
        let good = owner_row(&master, &key, "child");
        let bad = (good.0.clone(), vec![0; LEGACY_KEY_WRAP_LEN]);
        assert!(verify_legacy_folder_key(
            &master,
            FOLDER,
            key.as_bytes(),
            [good.clone()]
        ));
        assert!(!verify_legacy_folder_key(&master, FOLDER, key.as_bytes(), [bad, good]));
    }

    #[test]
    fn invite_legacy_proof_examines_at_most_64_distinct_ids() {
        let (master, key) = (master(), folder_key());
        let junk = |n: usize| {
            (0..n)
                .map(|i| foreign_row(&key, &format!("junk-{i}")))
                .collect::<Vec<_>>()
        };
        let good = owner_row(&master, &key, "child");
        // The proof as the 64th distinct id is examined; as the 65th it is not.
        let at_cap = [junk(LEGACY_FOLDER_KEY_PROOF_CAP - 1), vec![good.clone()]].concat();
        assert!(verify_legacy_folder_key(&master, FOLDER, key.as_bytes(), at_cap));
        let past_cap = [junk(LEGACY_FOLDER_KEY_PROOF_CAP), vec![good.clone()]].concat();
        assert!(!verify_legacy_folder_key(&master, FOLDER, key.as_bytes(), past_cap));
        // Duplicates are skipped without using up the cap.
        let dupes = vec![foreign_row(&key, "junk-0"); 500];
        let with_dupes = [junk(LEGACY_FOLDER_KEY_PROOF_CAP - 1), dupes, vec![good]].concat();
        assert!(verify_legacy_folder_key(&master, FOLDER, key.as_bytes(), with_dupes));
    }

    #[test]
    fn invite_legacy_rejects_invalid_lengths_and_bound_rows() {
        let (master, key) = (master(), folder_key());
        let row = owner_row(&master, &key, "child");
        for len in [0, 31, 33] {
            assert!(!verify_legacy_folder_key(
                &master,
                FOLDER,
                &vec![0xF8; len],
                [row.clone()]
            ));
        }
        for len in [0, 27, 59, 61] {
            assert!(!verify_legacy_folder_key(
                &master,
                FOLDER,
                key.as_bytes(),
                [(row.0.clone(), vec![0; len])]
            ));
        }
        assert!(!verify_legacy_folder_key(
            &master,
            FOLDER,
            key.as_bytes(),
            [(Vec::new(), row.1.clone())]
        ));
        // An L7-bound child wrap is not a legacy row.
        let (root, item) = ([1u8; 16], [2u8; 16]);
        let bound = wire(wrap_folder_child(&key, &root, &item, 1, &derive_file_key(&master, &item)).unwrap());
        assert!(!verify_legacy_folder_key(
            &master,
            FOLDER,
            key.as_bytes(),
            [(item.to_vec(), bound)]
        ));
        // The opener: wrong copy lengths, an empty folder id, another folder.
        let copy = legacy_copy(&master, key.as_bytes());
        let long = [copy.as_slice(), &[0]].concat();
        for bad in [&copy[..59], long.as_slice()] {
            assert!(open_legacy_invite_owner_copy(&master, FOLDER, bad, [row.clone()]).is_none());
        }
        assert!(open_legacy_invite_owner_copy(&master, b"", &copy, [row.clone()]).is_none());
        assert!(open_legacy_invite_owner_copy(&master, b"other-folder", &copy, [row.clone()]).is_none());
        // A purpose-bound copy never opens as a legacy one.
        let bound_copy = wire(wrap_invite_owner_copy(&master, FOLDER, &key).unwrap());
        assert!(open_legacy_invite_owner_copy(&master, FOLDER, &bound_copy, [row]).is_none());
    }

    #[test]
    fn invite_legacy_residual_attack_b_name_key_holder_can_forge() {
        // RESIDUAL, named in task 2255 (attack B), NOT fixed here. A server that
        // knows the folder's own name key (a pre-2238 folder link; once any folder
        // link exists, ANY link guest or invite member colluding with it) and one
        // child's key seals a key of its choice as the legacy owner copy, plus a
        // row proving it. This test pins the gap: when the follow-up closes it,
        // this assertion must flip.
        let master = master();
        let name_key = derive_file_key(&master, FOLDER);
        let child_key = derive_file_key(&master, b"child");
        let chosen = FileKey::from_bytes([0xF9; 32]);
        let copy = legacy_wrap(&name_key, chosen.as_bytes());
        let row = (b"child".to_vec(), legacy_wrap(&chosen, child_key.as_bytes()));
        let opened = open_legacy_invite_owner_copy(&master, FOLDER, &copy, [row]);
        assert_eq!(opened.unwrap().as_bytes(), chosen.as_bytes());
    }

    #[test]
    fn invite_owner_copy_roundtrip_and_separation() {
        let master = MasterKey::from_bytes([7; 32]);
        let key = FileKey::from_bytes([8; 32]);
        let copy = wrap_invite_owner_copy(&master, b"folder", &key).unwrap();
        assert_eq!(
            unwrap_invite_owner_copy(&master, b"folder", &copy).unwrap().as_bytes(),
            key.as_bytes()
        );
        assert!(unwrap_invite_owner_copy(&master, b"other", &copy).is_err());
        assert!(unwrap_folder_custody(&master, b"folder", &copy).is_err());
        let legacy = encrypt_chunk(&derive_file_key(&master, b"folder"), key.as_bytes()).unwrap();
        assert!(unwrap_invite_owner_copy(&master, b"folder", &legacy).is_err());
        let custody = wrap_folder_custody(&master, b"folder", &key).unwrap();
        assert!(unwrap_invite_owner_copy(&master, b"folder", &custody).is_err());
        let owner_file = wrap_owner_file_key(&master, b"folder", &key).unwrap();
        assert!(unwrap_invite_owner_copy(&master, b"folder", &owner_file).is_err());
        assert!(unwrap_owner_file_key(&master, b"folder", &copy).is_err());
        assert!(wrap_invite_owner_copy(&master, b"", &key).is_err());
    }
    #[test]
    fn invite_owner_copy_python_vector() {
        let vectors: serde_json::Value = serde_json::from_str(include_str!("../../test-vectors/vectors.json")).unwrap();
        let v = vectors["vectors"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["name"] == "invite_owner_copy_v1")
            .unwrap();
        let unhex = |s: &str| -> Vec<u8> {
            (0..s.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
                .collect()
        };
        let master = MasterKey::from_bytes(unhex(v["master_key_hex"].as_str().unwrap()).try_into().unwrap());
        let raw = unhex(v["wrapped_hex"].as_str().unwrap());
        let blob = beebeeb_types::EncryptedBlob {
            cipher_suite: beebeeb_types::CipherSuite::V1Aes256Gcm,
            nonce: raw[..12].to_vec(),
            ciphertext: raw[12..].to_vec(),
        };
        assert_eq!(
            unwrap_invite_owner_copy(&master, v["record_id"].as_str().unwrap().as_bytes(), &blob)
                .unwrap()
                .as_bytes()
                .as_slice(),
            unhex(v["plaintext_hex"].as_str().unwrap())
        );
        let context = unhex(v["context_hex"].as_str().unwrap());
        let plaintext = unhex(v["plaintext_hex"].as_str().unwrap());
        let key = purpose_key(&master, &context);
        let nonce: [u8; 12] = raw[..12].try_into().unwrap();
        assert_eq!(seal_raw_with_nonce(&key, &nonce, &plaintext, &context).unwrap(), raw);
    }
}
