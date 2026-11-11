use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use rand::RngCore;

use beebeeb_types::{CipherSuite, EncryptedBlob};

use crate::CoreError;
use crate::item_id::{ItemClass, NewItemId, item_class};
use crate::kdf::FileKey;
use crate::owned_keys::WriteTarget;

/// AES-256-GCM nonce length in bytes. Single source of truth for the
/// `encrypt` / `file_encrypt` / `chunk_stream` cluster.
pub(crate) const NONCE_LEN: usize = 12;

/// AES-256-GCM authentication tag length in bytes. Single source of truth for
/// the `encrypt` / `file_encrypt` / `chunk_stream` cluster.
pub(crate) const TAG_LEN: usize = 16;

/// Encrypt an arbitrary plaintext chunk with AES-256-GCM.
///
/// A fresh random 12-byte nonce is generated for every call.
pub fn encrypt_chunk(key: &FileKey, plaintext: &[u8]) -> Result<EncryptedBlob, CoreError> {
    let cipher = Aes256Gcm::new_from_slice(key.as_bytes()).map_err(|e| CoreError::Encryption(e.to_string()))?;

    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| CoreError::Encryption(e.to_string()))?;

    Ok(EncryptedBlob {
        cipher_suite: CipherSuite::V1Aes256Gcm,
        nonce: nonce_bytes.to_vec(),
        ciphertext,
    })
}

/// Decrypt a blob that was produced by [`encrypt_chunk`].
pub fn decrypt_chunk(key: &FileKey, blob: &EncryptedBlob) -> Result<Vec<u8>, CoreError> {
    if blob.cipher_suite != CipherSuite::V1Aes256Gcm {
        return Err(CoreError::Decryption);
    }
    if blob.nonce.len() != NONCE_LEN {
        return Err(CoreError::Decryption);
    }

    let cipher = Aes256Gcm::new_from_slice(key.as_bytes()).map_err(|e| CoreError::Encryption(e.to_string()))?;
    let nonce = Nonce::from_slice(&blob.nonce);

    cipher
        .decrypt(nonce, blob.ciphertext.as_ref())
        .map_err(|_| CoreError::Decryption)
}

/// Encrypt a UTF-8 metadata string (e.g. filename / path) with AES-256-GCM.
///
/// Generic, no AAD. Never call it with a per-file key to seal a file's name,
/// thumbnail or note: use [`encrypt_name_with_chunk_format`],
/// [`encrypt_thumbnail_for`] and [`encrypt_note_for`] (task 1908). A no-AAD
/// blob under the raw file key opens as a v1 content frame and, in envelope
/// shape, as a pin-less name.
pub fn encrypt_metadata(key: &FileKey, metadata: &str) -> Result<EncryptedBlob, CoreError> {
    encrypt_chunk(key, metadata.as_bytes())
}

/// Decrypt a metadata blob back to a UTF-8 string.
pub fn decrypt_metadata(key: &FileKey, blob: &EncryptedBlob) -> Result<String, CoreError> {
    let plaintext = decrypt_chunk(key, blob)?;
    String::from_utf8(plaintext).map_err(|_| CoreError::Decryption)
}

// ── High-level API for all clients ──────────────────────────────────
//
// These functions handle key derivation + encryption + canonical JSON
// serialization in one call. ALL clients (CLI, web/WASM, mobile/UniFFI)
// should use these instead of hand-rolling serialization.

/// Encrypt a filename (with MIME type) and return the canonical JSON string.
///
/// This is the **only** way clients should produce `name_encrypted`.
/// The plaintext is `{"name":"filename","mime_type":"type/subtype"}` —
/// matching the web app's zero-knowledge format where MIME is encrypted,
/// never sent in plaintext to the server.
///
/// The output envelope is `{"cipher_suite":"V1Aes256Gcm","nonce":[...],"ciphertext":[...]}`.
///
/// **Write shape (task 2275):** deprecated for writes. A new row uses
/// [`encrypt_name_for_new_item`] (core-minted id); a replacement uses
/// [`encrypt_name_for_target`] (the resolved row's key and pin). This
/// entry point remains for readers, tests and rows core has not resolved.
#[deprecated(
    note = "task 2275 L13: use the NewItemId/WriteTarget sealers (encrypt_*_for_new_item / encrypt_*_for_target)"
)]
#[allow(deprecated)]
pub fn encrypt_name(
    master_key: &crate::kdf::MasterKey,
    file_id: &str,
    filename: &str,
    mime_type: Option<&str>,
) -> Result<String, CoreError> {
    encrypt_name_with_chunk_format(
        master_key,
        file_id,
        filename,
        mime_type,
        crate::chunk_stream::ExpectedChunkFormat::Unrecorded,
    )
}

/// JSON field in the encrypted name metadata that records the file's chunk
/// format (task 1908). Present only as `2` (v2); absent = unrecorded.
pub const METADATA_CHUNK_FORMAT_FIELD: &str = "chunk_format";
/// Hex-encoded frame-0 nonce committed by protected metadata.
pub const METADATA_VERSION_ID_FIELD: &str = "version_id";
/// Monotonic per-file version counter committed by protected metadata.
pub const METADATA_VERSION_COUNTER_FIELD: &str = "version_counter";

/// [`encrypt_name`] that also records the file's chunk format **inside the
/// encrypted metadata** (task 1908 review round 2, P1-1), so readers can pin
/// it: `{"name":..,"mime_type":..,"chunk_format":2}`. With
/// [`ExpectedChunkFormat::Unrecorded`] the output is exactly [`encrypt_name`]'s.
///
/// `chunk_format: 2` asserts that **every upload (version) of this file id is
/// v2**, because the server keeps one metadata blob per file and readers of
/// older versions pin with it too. So:
/// - new file id: pass [`ExpectedChunkFormat::recorded_for`] of the encryptor's
///   [`format`](crate::chunk_stream::ChunkEncryptor::format);
/// - rename / replace of an existing file: pass the value you decrypted from
///   its current metadata ([`decrypt_file_metadata`]) — never upgrade a file id
///   with v1 history to `V2` (its old versions would stop opening), and never
///   drop a recorded `V2` (that silently re-enables detection for the file).
///   The replace's content writer takes the same value
///   ([`ChunkEncryptor::with_recorded_pin`](crate::chunk_stream::ChunkEncryptor::with_recorded_pin)),
///   and so does its thumbnail ([`encrypt_thumbnail_for`]) — round 4, I-1.
///
/// [`ExpectedChunkFormat::Unrecorded`]: crate::chunk_stream::ExpectedChunkFormat::Unrecorded
/// [`ExpectedChunkFormat::recorded_for`]: crate::chunk_stream::ExpectedChunkFormat::recorded_for
#[deprecated(
    note = "task 2275 L13: use the NewItemId/WriteTarget sealers (encrypt_*_for_new_item / encrypt_*_for_target)"
)]
pub fn encrypt_name_with_chunk_format(
    master_key: &crate::kdf::MasterKey,
    file_id: &str,
    filename: &str,
    mime_type: Option<&str>,
    chunk_format: crate::chunk_stream::ExpectedChunkFormat,
) -> Result<String, CoreError> {
    // A v2 file's metadata is ALWAYS sealed under the name subkey: only a
    // reader on this core can open v2 content anyway, so nothing breaks, and a
    // v2 file then has no blob under its raw file key at all. Everything else
    // follows the write format. One rule
    // for content, names and thumbnails: chunk_format_for_pin + metadata_seal_for.
    let file_key = crate::kdf::derive_file_key(master_key, file_id.as_bytes());
    encrypt_name_for(&file_key, filename, mime_type, chunk_format)
}

/// Seal file metadata for a newly written version. The commitment is generated
/// by [`crate::chunk_stream::ChunkEncryptor::version_commitment`] after frame 0
/// has been sealed.
pub fn encrypt_name_with_version(
    master_key: &crate::kdf::MasterKey,
    file_id: &str,
    filename: &str,
    mime_type: Option<&str>,
    chunk_format: crate::chunk_stream::ExpectedChunkFormat,
    version: crate::chunk_stream::VersionCommitment,
) -> Result<String, CoreError> {
    let file_key = crate::kdf::derive_file_key(master_key, file_id.as_bytes());
    encrypt_name_for_version(&file_key, filename, mime_type, chunk_format, version)
}

/// Key for a brand-new row (task 2275, L13). Only an owner id can be sealed
/// this way; a foreign row is adopted first and then written through its
/// [`WriteTarget`]. (`NewItemId::foreign` exists for the content path, which
/// derives the member's own key under the F id; a foreign row's name still
/// goes through adoption.)
fn new_item_name_key(master_key: &crate::kdf::MasterKey, item_id: &NewItemId) -> Result<FileKey, CoreError> {
    if item_class(item_id.as_str())? != ItemClass::Owner {
        return Err(CoreError::InvalidInput(
            "a new foreign item is sealed after adoption, through its write target".into(),
        ));
    }
    Ok(crate::kdf::derive_file_key(master_key, item_id.as_str().as_bytes()))
}

/// Seal the name of a **new** row (task 2275, L13): the id is minted by core.
#[allow(deprecated)]
pub fn encrypt_name_for_new_item(
    master_key: &crate::kdf::MasterKey,
    item_id: &NewItemId,
    filename: &str,
    mime_type: Option<&str>,
    chunk_format: crate::chunk_stream::ExpectedChunkFormat,
) -> Result<String, CoreError> {
    let key = new_item_name_key(master_key, item_id)?;
    encrypt_name_for(&key, filename, mime_type, chunk_format)
}

/// Protected metadata writer for a new core-minted row.
pub fn encrypt_name_for_new_item_version(
    master_key: &crate::kdf::MasterKey,
    item_id: &NewItemId,
    filename: &str,
    mime_type: Option<&str>,
    chunk_format: crate::chunk_stream::ExpectedChunkFormat,
    version: crate::chunk_stream::VersionCommitment,
) -> Result<String, CoreError> {
    let key = new_item_name_key(master_key, item_id)?;
    encrypt_name_for_version(&key, filename, mime_type, chunk_format, version)
}

/// Seal a **replacement** name through the row's [`WriteTarget`] (task 2275,
/// L13): id, key and format pin all come from the resolved row.
pub fn encrypt_name_for_target(
    target: &WriteTarget,
    filename: &str,
    mime_type: Option<&str>,
) -> Result<String, CoreError> {
    match target.version() {
        Some(version) => encrypt_name_for_version(target.key(), filename, mime_type, target.pin(), version),
        None => encrypt_name_for(target.key(), filename, mime_type, target.pin()),
    }
}

/// Seal metadata for a replacement version through a resolved target. The
/// caller obtains `version` from the replacement encryptor using the target's
/// current commitment; this function verifies the counter transition before
/// writing it.
pub fn encrypt_name_for_target_version(
    target: &WriteTarget,
    filename: &str,
    mime_type: Option<&str>,
    version: crate::chunk_stream::VersionCommitment,
) -> Result<String, CoreError> {
    let expected = match target.version() {
        None => 1,
        Some(current) => current
            .counter
            .checked_add(1)
            .ok_or_else(|| CoreError::InvalidInput("version counter overflow".into()))?,
    };
    if version.counter != expected {
        return Err(CoreError::InvalidInput(format!(
            "replacement version counter must be {expected}, got {}",
            version.counter
        )));
    }
    encrypt_name_for_version(target.key(), filename, mime_type, target.pin(), version)
}

#[cfg(test)]
pub(crate) fn encrypt_name_sealed(
    master_key: &crate::kdf::MasterKey,
    file_id: &str,
    filename: &str,
    mime_type: Option<&str>,
    chunk_format: crate::chunk_stream::ExpectedChunkFormat,
    seal: MetadataSeal,
) -> Result<String, CoreError> {
    let file_key = crate::kdf::derive_file_key(master_key, file_id.as_bytes());
    seal_name_envelope(&file_key, filename, mime_type, chunk_format, None, seal, random_nonce())
}

/// Seal the name/MIME envelope under a per-file key, by the rule of the `pin`
/// the file's encrypted metadata records (from [`decrypt_file_metadata_with_key`]
/// / [`decrypt_file_metadata`], never a server field) — task 1958. The only
/// name writer that takes a key instead of deriving one, so it is the writer
/// for every file whose key is not derived from the caller's master key
/// (file-request uploads, shared-folder files):
/// - a v2 pin records `chunk_format: 2` and is ALWAYS sealed under the name
///   subkey (as [`encrypt_name_with_chunk_format`] does);
/// - `Unrecorded` follows [`METADATA_SEAL_WRITE`] and records no format pin.
///
/// Which `pin` to pass:
/// - an EXISTING file (rename): the pin its metadata records;
/// - a NEW file (e.g. a file-request upload, whose key the uploader holds):
///   [`ExpectedChunkFormat::recorded_for`] of the format its content was written
///   in (`ChunkEncryptor::format`), exactly as
///   [`encrypt_name_with_chunk_format`] is used at upload. Any other pin for a
///   new file records a format its content does not have.
///
/// [`encrypt_name_with_chunk_format`] is this writer after deriving the file key,
/// and the published name vectors are written through the same path
/// ([`encrypt_name_for_nonce`]), so they pin this writer's key choice and
/// plaintext.
///
/// [`ExpectedChunkFormat::recorded_for`]: crate::chunk_stream::ExpectedChunkFormat::recorded_for
pub fn encrypt_name_for(
    file_key: &FileKey,
    filename: &str,
    mime_type: Option<&str>,
    pin: crate::chunk_stream::ExpectedChunkFormat,
) -> Result<String, CoreError> {
    encrypt_name_for_nonce(file_key, filename, mime_type, pin, random_nonce())
}

/// Known-key writer for a new current version. It records the authenticated
/// frame-0 version id and monotonic counter together.
pub fn encrypt_name_for_version(
    file_key: &FileKey,
    filename: &str,
    mime_type: Option<&str>,
    pin: crate::chunk_stream::ExpectedChunkFormat,
    version: crate::chunk_stream::VersionCommitment,
) -> Result<String, CoreError> {
    let seal = metadata_seal_for(crate::chunk_stream::ChunkFormat::V2);
    seal_name_envelope(file_key, filename, mime_type, pin, Some(version), seal, random_nonce())
}

/// Rename a file while carrying its format and version commitment forward
/// unchanged. A replace uses [`encrypt_name_for_version`] with the successor
/// commitment instead.
pub fn encrypt_name_carrying_version(
    file_key: &FileKey,
    filename: &str,
    mime_type: Option<&str>,
    current: &NameMetadata,
) -> Result<String, CoreError> {
    let seal = metadata_seal_for(crate::chunk_stream::chunk_format_for_pin(current.chunk_format));
    seal_name_envelope(
        file_key,
        filename,
        mime_type,
        current.chunk_format,
        current.version,
        seal,
        random_nonce(),
    )
}

/// [`encrypt_name_for`] with the nonce as a parameter: the shipped writers pass a
/// fresh [`random_nonce`], and only the `cfg(test)` / `test-support` vector seams
/// ([`encrypt_name_for_with_nonce`], [`encrypt_name_with_chunk_format_and_nonce`])
/// pass a fixed one. Private, so no shipped API takes a nonce. Everything that
/// depends on the pin (the seal and the recorded `chunk_format`) happens here
/// and in [`seal_name_envelope`], on the path both share (task 1958 round 2, I-1).
fn encrypt_name_for_nonce(
    file_key: &FileKey,
    filename: &str,
    mime_type: Option<&str>,
    pin: crate::chunk_stream::ExpectedChunkFormat,
    nonce: [u8; NONCE_LEN],
) -> Result<String, CoreError> {
    let seal = metadata_seal_for(crate::chunk_stream::chunk_format_for_pin(pin));
    seal_name_envelope(file_key, filename, mime_type, pin, None, seal, nonce)
}

/// The one name sealer: [`encrypt_name_for_nonce`] (every pin-ruled writer and
/// vector seam) and, in the crate's tests, [`encrypt_name_sealed`] (an explicit
/// seal) both end here. The key choice and the blob framing exist once.
fn seal_name_envelope(
    file_key: &FileKey,
    filename: &str,
    mime_type: Option<&str>,
    chunk_format: crate::chunk_stream::ExpectedChunkFormat,
    version: Option<crate::chunk_stream::VersionCommitment>,
    seal: MetadataSeal,
    nonce: [u8; NONCE_LEN],
) -> Result<String, CoreError> {
    let plaintext = name_plaintext(filename, mime_type, chunk_format, version);
    // The blob `encrypt_metadata` builds (no AAD), with the caller's nonce.
    let frame = match seal {
        MetadataSeal::Legacy => seal_raw_with_nonce(file_key, &nonce, plaintext.as_bytes(), &[])?,
        MetadataSeal::Subkey => seal_raw_with_nonce(&derive_name_key(file_key), &nonce, plaintext.as_bytes(), &[])?,
    };
    let blob = EncryptedBlob {
        cipher_suite: CipherSuite::V1Aes256Gcm,
        nonce: frame[..NONCE_LEN].to_vec(),
        ciphertext: frame[NONCE_LEN..].to_vec(),
    };
    serde_json::to_string(&blob).map_err(|e| CoreError::Encryption(e.to_string()))
}

/// [`encrypt_name_with_chunk_format`] with a FIXED nonce — for the published
/// known-answer vectors only (`test-vectors/vectors.json`, task 1943). Compiled
/// only under `cfg(test)` or the `test-support` feature, never in a shipped
/// client: a fixed nonce reused under one key breaks AES-GCM. It derives the
/// file key and takes the shipped writer's own path ([`encrypt_name_for_nonce`]),
/// so a vector is what the writer emits apart from the nonce, by construction.
/// [`encrypt_name_with_chunk_format`] with an explicit seal — for the crate's own
/// tests only (a subkey-sealed name on a v1 file, ahead of the
/// [`METADATA_SEAL_WRITE`] switch). `cfg(test)`, so no build of a shipped client
/// contains a writer that can choose the seal against the pin.
#[cfg(any(test, feature = "test-support"))]
pub fn encrypt_name_with_chunk_format_and_nonce(
    master_key: &crate::kdf::MasterKey,
    file_id: &str,
    filename: &str,
    mime_type: Option<&str>,
    chunk_format: crate::chunk_stream::ExpectedChunkFormat,
    nonce: [u8; NONCE_LEN],
) -> Result<String, CoreError> {
    let file_key = crate::kdf::derive_file_key(master_key, file_id.as_bytes());
    encrypt_name_for_nonce(&file_key, filename, mime_type, chunk_format, nonce)
}

/// Fixed-nonce version-commitment vector seam. Never compiled into a shipped
/// client; production callers use [`encrypt_name_with_version`].
#[cfg(any(test, feature = "test-support"))]
pub fn encrypt_name_with_version_and_nonce(
    master_key: &crate::kdf::MasterKey,
    file_id: &str,
    filename: &str,
    mime_type: Option<&str>,
    chunk_format: crate::chunk_stream::ExpectedChunkFormat,
    version: crate::chunk_stream::VersionCommitment,
    nonce: [u8; NONCE_LEN],
) -> Result<String, CoreError> {
    let file_key = crate::kdf::derive_file_key(master_key, file_id.as_bytes());
    seal_name_envelope(
        &file_key,
        filename,
        mime_type,
        chunk_format,
        Some(version),
        MetadataSeal::Subkey,
        nonce,
    )
}

/// [`encrypt_name_for`] with a FIXED nonce — for the published known-answer
/// vectors only (task 1958), under the same `cfg(test)` / `test-support` gate as
/// every other nonce seam. The shipped writer's own path
/// ([`encrypt_name_for_nonce`]), so the key choice and plaintext are its own.
#[cfg(any(test, feature = "test-support"))]
pub fn encrypt_name_for_with_nonce(
    file_key: &FileKey,
    filename: &str,
    mime_type: Option<&str>,
    pin: crate::chunk_stream::ExpectedChunkFormat,
    nonce: [u8; NONCE_LEN],
) -> Result<String, CoreError> {
    encrypt_name_for_nonce(file_key, filename, mime_type, pin, nonce)
}

/// The name/MIME envelope plaintext: `{"name":..,"mime_type":..}` plus
/// `"chunk_format":2` for a v2 pin (nothing recorded otherwise). Built only in
/// [`seal_name_envelope`], the sealer every name writer shares.
fn name_plaintext(
    filename: &str,
    mime_type: Option<&str>,
    chunk_format: crate::chunk_stream::ExpectedChunkFormat,
    version: Option<crate::chunk_stream::VersionCommitment>,
) -> String {
    let mut meta = serde_json::json!({
        "name": filename,
        "mime_type": mime_type,
    });
    if chunk_format == crate::chunk_stream::ExpectedChunkFormat::V2 {
        meta[METADATA_CHUNK_FORMAT_FIELD] = serde_json::json!(chunk_format.as_u8());
    }
    if let Some(version) = version {
        meta[METADATA_VERSION_ID_FIELD] = serde_json::json!(encode_version_id(&version.version_id));
        meta[METADATA_VERSION_COUNTER_FIELD] = serde_json::json!(version.counter);
    }
    meta.to_string()
}

// ── Metadata sealing: name/MIME envelope + thumbnails (task 1908 round 3, P1-B) ──
//
// Before this, the name/MIME envelope and the thumbnails were AES-256-GCM with
// no AAD under the RAW per-file key — the same key and the same (empty) AAD as
// a v1 content frame. So a server could serve a file's own name envelope or
// thumbnail as a one-frame "v1 file" wherever a reader detects the format
// (metadata that records none). New blobs are sealed under purpose-bound
// subkeys instead, so they can never open as content (v1: raw key; v2: chunk
// subkey) or as each other. Readers try the subkey first, then the legacy raw
// key, so every blob already stored keeps opening.

/// HKDF-SHA256 `info` of the name/MIME-envelope subkey (ikm = the per-file key).
pub const NAME_KEY_INFO: &[u8; 15] = b"beebeeb/name/v1";

/// HKDF-SHA256 `info` of the thumbnail subkey (ikm = the per-file key).
pub const THUMBNAIL_KEY_INFO: &[u8; 16] = b"beebeeb/thumb/v1";

/// How a name envelope or thumbnail is sealed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MetadataSeal {
    /// The raw per-file key, no AAD — every blob written before task 1908
    /// round 3, and what clients not yet on this core can read.
    Legacy,
    /// The purpose subkey ([`NAME_KEY_INFO`] / [`THUMBNAIL_KEY_INFO`] /
    /// [`NOTE_KEY_INFO`]).
    Subkey,
}

/// How new name envelopes, thumbnails and file notes are sealed. Tied to
/// [`crate::chunk_stream::WRITE_FORMAT`]. A name that records
/// `chunk_format: 2` (and a thumbnail written with [`encrypt_thumbnail_for`] a
/// v2 pin, and a note written with [`encrypt_note_for`] a v2 pin) is
/// subkey-sealed regardless. `= metadata_seal_for(WRITE_FORMAT)`.
pub const METADATA_SEAL_WRITE: MetadataSeal = metadata_seal_for(crate::chunk_stream::WRITE_FORMAT);

/// How names, thumbnails and file notes are sealed for content written in `format`
/// (task 1908 review round 4, P2-1): v1 content → [`MetadataSeal::Legacy`]
/// (readable by clients not yet on this core), v2 content →
/// [`MetadataSeal::Subkey`] (only a reader on this core opens v2 content
/// anyway). Both arms remain pinned by tests for legacy vector compatibility.
pub const fn metadata_seal_for(format: crate::chunk_stream::ChunkFormat) -> MetadataSeal {
    match format {
        crate::chunk_stream::ChunkFormat::V1Legacy => MetadataSeal::Legacy,
        crate::chunk_stream::ChunkFormat::V2 => MetadataSeal::Subkey,
    }
}

/// Seal a thumbnail for a file whose encrypted metadata records `pin` (task
/// 1908 review round 4, P2-4) — the same rule as names: a v2 pin is ALWAYS
/// subkey-sealed; `Unrecorded` follows [`METADATA_SEAL_WRITE`]. Use this for
/// every thumbnail of an EXISTING file (replace / new version / regenerated
/// thumbnail), with `pin` from [`decrypt_file_metadata`]; for a new file
/// [`encrypt_thumbnail`] is the same as `Unrecorded`.
///
/// **Write shape (task 2275):** deprecated for writes — use
/// [`encrypt_thumbnail_for_new_item`] or [`encrypt_thumbnail_for_target`].
#[deprecated(
    note = "task 2275 L13: use the NewItemId/WriteTarget sealers (encrypt_*_for_new_item / encrypt_*_for_target)"
)]
pub fn encrypt_thumbnail_for(
    file_key: &FileKey,
    plaintext: &[u8],
    pin: crate::chunk_stream::ExpectedChunkFormat,
) -> Result<Vec<u8>, CoreError> {
    let seal = metadata_seal_for(crate::chunk_stream::chunk_format_for_pin(pin));
    encrypt_thumbnail_sealed(file_key, plaintext, seal)
}

/// Seal a thumbnail for a **new** row (task 2275, L13), with core-minted id.
#[allow(deprecated)]
pub fn encrypt_thumbnail_for_new_item(
    master_key: &crate::kdf::MasterKey,
    item_id: &NewItemId,
    plaintext: &[u8],
    pin: crate::chunk_stream::ExpectedChunkFormat,
) -> Result<Vec<u8>, CoreError> {
    let key = new_item_name_key(master_key, item_id)?;
    encrypt_thumbnail_for(&key, plaintext, pin)
}

/// Seal a replacement thumbnail through the row's [`WriteTarget`] (task 2275, L13).
#[allow(deprecated)]
pub fn encrypt_thumbnail_for_target(target: &WriteTarget, plaintext: &[u8]) -> Result<Vec<u8>, CoreError> {
    encrypt_thumbnail_for(target.key(), plaintext, target.pin())
}

/// Name/MIME-envelope subkey of a per-file key.
pub(crate) fn derive_name_key(file_key: &FileKey) -> FileKey {
    crate::kdf::derive_file_subkey(file_key, NAME_KEY_INFO)
}

/// Thumbnail subkey of a per-file key.
pub(crate) fn derive_thumbnail_key(file_key: &FileKey) -> FileKey {
    crate::kdf::derive_file_subkey(file_key, THUMBNAIL_KEY_INFO)
}

/// Encrypt a thumbnail (already-encoded image bytes) for upload of a NEW file.
/// Wire format unchanged: `nonce(12) || ciphertext || tag(16)` (web
/// `thumbnail.ts`). Sealed per [`METADATA_SEAL_WRITE`]; read it back with
/// [`decrypt_thumbnail`]. For a thumbnail of an existing file use
/// [`encrypt_thumbnail_for`] with the file's recorded pin. These two are the
/// only ways clients should seal a thumbnail — not [`encrypt_chunk_raw`] /
/// `encrypt_chunk`.
pub fn encrypt_thumbnail(file_key: &FileKey, plaintext: &[u8]) -> Result<Vec<u8>, CoreError> {
    encrypt_thumbnail_sealed(file_key, plaintext, METADATA_SEAL_WRITE)
}

/// [`encrypt_thumbnail`] with an explicit seal — crate-internal (tests), so no
/// client can write subkey-sealed thumbnails ahead of the switch.
pub(crate) fn encrypt_thumbnail_sealed(
    file_key: &FileKey,
    plaintext: &[u8],
    seal: MetadataSeal,
) -> Result<Vec<u8>, CoreError> {
    match seal {
        MetadataSeal::Legacy => seal_raw_with_aad(file_key, plaintext, &[]),
        MetadataSeal::Subkey => seal_raw_with_aad(&derive_thumbnail_key(file_key), plaintext, &[]),
    }
}

/// Decrypt a thumbnail frame (`nonce || ct || tag`): the thumbnail subkey
/// first, then the legacy raw file key (thumbnails stored before the switch).
pub fn decrypt_thumbnail(file_key: &FileKey, frame: &[u8]) -> Result<Vec<u8>, CoreError> {
    open_raw_with_aad(&derive_thumbnail_key(file_key), frame, &[]).or_else(|_| open_raw_with_aad(file_key, frame, &[]))
}

/// Open a thumbnail under an authenticated file-metadata record. Protected
/// files never try the legacy raw file key.
pub fn decrypt_thumbnail_for_metadata(
    file_key: &FileKey,
    frame: &[u8],
    metadata: &NameMetadata,
) -> Result<Vec<u8>, CoreError> {
    let opened = open_raw_with_aad(&derive_thumbnail_key(file_key), frame, &[]);
    if metadata.chunk_format == crate::chunk_stream::ExpectedChunkFormat::V2 || metadata.version.is_some() {
        opened
    } else {
        opened.or_else(|_| open_raw_with_aad(file_key, frame, &[]))
    }
}

// ── File notes (task 1908 review round 5) ──────────────────────────────────
//
// Web sealed a file's note with `encrypt_metadata` under the RAW per-file key
// (`file-details-panel.tsx`), stored as an `EncryptedBlob` JSON in
// `files.note_encrypted` — the same key, the same (empty) AAD and the same
// envelope shape as a legacy name. A server could serve that note as a v2
// file's `name_encrypted`: the name reader's legacy fallback opens it, the
// non-JSON text reads as a name with NO pin (`Unrecorded`), detection is back
// on, and the same note bytes then open as a one-frame v1 "file". So a raw-key
// note undid the v2 pin. Notes now have their own purpose subkey, under the
// same seal rule as names and thumbnails (`chunk_format_for_pin` +
// `metadata_seal_for`), so a note sealed for a v2 file never opens as a name,
// a thumbnail or content (test `raw_key_note_served_as_name_downgrades_v2_file`).

/// HKDF-SHA256 `info` of the file-note subkey (ikm = the per-file key).
pub const NOTE_KEY_INFO: &[u8; 15] = b"beebeeb/note/v1";

/// File-note subkey of a per-file key.
pub(crate) fn derive_note_key(file_key: &FileKey) -> FileKey {
    crate::kdf::derive_file_subkey(file_key, NOTE_KEY_INFO)
}

/// Seal a file note for a file with no recorded pin yet (a note written in the
/// same flow that creates the file). Follows [`METADATA_SEAL_WRITE`], exactly
/// like [`encrypt_thumbnail`]. For a note on an EXISTING file (the usual case:
/// the details panel) use [`encrypt_note_for`] with the file's recorded pin.
///
/// Returns the canonical `EncryptedBlob` JSON (`{"cipher_suite":"V1Aes256Gcm",
/// "nonce":[..],"ciphertext":[..]}`) — the shape web stores in
/// `note_encrypted` today. Read it back with
/// [`decrypt_note`]. These two writers are the only way clients should seal a
/// note — never `encrypt_metadata` / `encrypt_chunk` under the file key.
///
/// **Write shape (task 2275):** deprecated for writes — use
/// [`encrypt_note_for_new_item`] or [`encrypt_note_for_target`].
#[deprecated(
    note = "task 2275 L13: use the NewItemId/WriteTarget sealers (encrypt_*_for_new_item / encrypt_*_for_target)"
)]
pub fn encrypt_note(file_key: &FileKey, note: &str) -> Result<String, CoreError> {
    encrypt_note_sealed(file_key, note, METADATA_SEAL_WRITE)
}

/// Seal a note of an EXISTING file whose encrypted metadata records `pin` (from
/// [`decrypt_file_metadata`], never a server field). The same rule as names
/// and thumbnails: a v2 pin is ALWAYS sealed under the note subkey (the note
/// can then never stand in for the file's name or content); `Unrecorded`
/// follows [`METADATA_SEAL_WRITE`].
#[deprecated(
    note = "task 2275 L13: use the NewItemId/WriteTarget sealers (encrypt_*_for_new_item / encrypt_*_for_target)"
)]
pub fn encrypt_note_for(
    file_key: &FileKey,
    note: &str,
    pin: crate::chunk_stream::ExpectedChunkFormat,
) -> Result<String, CoreError> {
    let seal = metadata_seal_for(crate::chunk_stream::chunk_format_for_pin(pin));
    encrypt_note_sealed(file_key, note, seal)
}

/// Seal a note for a **new** row (task 2275, L13), with core-minted id.
#[allow(deprecated)]
pub fn encrypt_note_for_new_item(
    master_key: &crate::kdf::MasterKey,
    item_id: &NewItemId,
    note: &str,
    pin: crate::chunk_stream::ExpectedChunkFormat,
) -> Result<String, CoreError> {
    let key = new_item_name_key(master_key, item_id)?;
    encrypt_note_for(&key, note, pin)
}

/// Seal a replacement note through the row's [`WriteTarget`] (task 2275, L13).
#[allow(deprecated)]
pub fn encrypt_note_for_target(target: &WriteTarget, note: &str) -> Result<String, CoreError> {
    encrypt_note_for(target.key(), note, target.pin())
}

/// [`encrypt_note`] with an explicit seal — crate-internal (tests), so no
/// client can write subkey-sealed notes for a v1 file ahead of the switch.
pub(crate) fn encrypt_note_sealed(file_key: &FileKey, note: &str, seal: MetadataSeal) -> Result<String, CoreError> {
    let blob = match seal {
        MetadataSeal::Legacy => encrypt_metadata(file_key, note)?,
        MetadataSeal::Subkey => encrypt_metadata(&derive_note_key(file_key), note)?,
    };
    serde_json::to_string(&blob).map_err(|e| CoreError::Encryption(e.to_string()))
}

/// Open a `note_encrypted` envelope (native `EncryptedBlob` JSON or the legacy
/// web `{nonce, ciphertext}` shape): the note subkey first, then the legacy raw
/// file key (every note stored before the switch). A plaintext (non-JSON)
/// value, or one that opens under neither key, is an error — the caller shows
/// no note. Never open a note with `decrypt_metadata` / `decrypt_name*`.
pub fn decrypt_note(file_key: &FileKey, note_encrypted: &str) -> Result<String, CoreError> {
    if !note_encrypted.starts_with('{') {
        return Err(CoreError::InvalidInput(
            "note is not an encrypted envelope (task 1908)".into(),
        ));
    }
    decrypt_envelope_plaintext_under(&derive_note_key(file_key), note_encrypted)
        .or_else(|| decrypt_envelope_plaintext_under(file_key, note_encrypted))
        .ok_or(CoreError::Decryption)
}

/// Open a note under an authenticated file-metadata record. Protected files
/// never try the legacy raw file key.
pub fn decrypt_note_for_metadata(
    file_key: &FileKey,
    note_encrypted: &str,
    metadata: &NameMetadata,
) -> Result<String, CoreError> {
    if !note_encrypted.starts_with('{') {
        return Err(CoreError::InvalidInput("note is not an encrypted envelope".into()));
    }
    let opened = decrypt_envelope_plaintext_under(&derive_note_key(file_key), note_encrypted);
    if metadata.chunk_format == crate::chunk_stream::ExpectedChunkFormat::V2 || metadata.version.is_some() {
        opened.ok_or(CoreError::Decryption)
    } else {
        opened
            .or_else(|| decrypt_envelope_plaintext_under(file_key, note_encrypted))
            .ok_or(CoreError::Decryption)
    }
}

/// The decrypted name metadata of a file, including the chunk format its
/// content must be read with (task 1908).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameMetadata {
    /// The filename.
    pub name: String,
    /// The MIME type, when the metadata carries one.
    pub mime_type: Option<String>,
    /// What to pass to every file-content reader. `V2` only when an
    /// **encrypted** metadata envelope that authenticated under this file's key
    /// records it; a plaintext legacy name, or an envelope without the field,
    /// is `Unrecorded`.
    pub chunk_format: crate::chunk_stream::ExpectedChunkFormat,
    /// Authenticated current/historical version identity. `None` means the
    /// stored metadata predates replay protection and is readable but
    /// unprotected.
    pub version: Option<crate::chunk_stream::VersionCommitment>,
}

impl NameMetadata {
    /// Whether content reads can bind frame 0 to this metadata record.
    pub fn is_version_protected(&self) -> bool {
        self.version.is_some()
    }
}

/// Decrypt `name_encrypted` (same format + key matrix as [`decrypt_name`]) and
/// return the name, MIME type and the recorded [`ExpectedChunkFormat`]. Fails
/// if the envelope records a chunk format this core does not know (never a
/// silent fallback to detection).
///
/// **Folders and display only.** A plaintext (non-JSON) value is accepted as a
/// legacy name here. To get the pin for reading a FILE's content use
/// [`decrypt_file_metadata`], which refuses plaintext (task 1908 round 3).
///
/// [`ExpectedChunkFormat`]: crate::chunk_stream::ExpectedChunkFormat
pub fn decrypt_name_metadata(
    master_key: &crate::kdf::MasterKey,
    file_id: &str,
    name_encrypted: &str,
) -> Result<NameMetadata, CoreError> {
    if !name_encrypted.starts_with('{') {
        return Ok(legacy_plaintext_metadata(name_encrypted));
    }
    let key_from_string = crate::kdf::derive_file_key(master_key, file_id.as_bytes());
    if let Some(meta) = decrypt_file_metadata_under(&key_from_string, name_encrypted)? {
        return Ok(meta);
    }
    if let Some(key) = file_id
        .parse::<uuid::Uuid>()
        .ok()
        .map(|u| crate::kdf::derive_file_key(master_key, u.as_bytes()))
    {
        if let Some(meta) = decrypt_file_metadata_under(&key, name_encrypted)? {
            return Ok(meta);
        }
    }
    Err(CoreError::Decryption)
}

/// [`decrypt_name_metadata`] with a **known** file key (share recipients,
/// file-request content keys) — mirrors [`decrypt_name_with_key`].
pub fn decrypt_name_metadata_with_key(file_key: &FileKey, name_encrypted: &str) -> Result<NameMetadata, CoreError> {
    if !name_encrypted.starts_with('{') {
        return Ok(legacy_plaintext_metadata(name_encrypted));
    }
    decrypt_file_metadata_under(file_key, name_encrypted)?.ok_or(CoreError::Decryption)
}

/// The metadata reader for **files** (task 1908 round 3, P1-B): exactly
/// [`decrypt_name_metadata`], except that a plaintext (non-JSON)
/// `name_encrypted` is REFUSED instead of read as a legacy name.
///
/// Why: a plaintext name carries no authenticated chunk format, so it reads as
/// [`ExpectedChunkFormat::Unrecorded`] and re-enables frame-0 detection. A
/// server could replace a v2 file's metadata with a plaintext name and then
/// serve some no-AAD blob under the file's key as a one-frame v1 "file".
/// Every client must use this reader to get the pin for file content; the
/// plaintext form stays accepted for folders ([`decrypt_name_metadata`]).
///
/// [`ExpectedChunkFormat::Unrecorded`]: crate::chunk_stream::ExpectedChunkFormat::Unrecorded
pub fn decrypt_file_metadata(
    master_key: &crate::kdf::MasterKey,
    file_id: &str,
    name_encrypted: &str,
) -> Result<NameMetadata, CoreError> {
    refuse_plaintext_file_name(name_encrypted)?;
    decrypt_name_metadata(master_key, file_id, name_encrypted)
}

/// [`decrypt_file_metadata`] with a known file key (share recipients,
/// file-request content keys).
pub fn decrypt_file_metadata_with_key(file_key: &FileKey, name_encrypted: &str) -> Result<NameMetadata, CoreError> {
    refuse_plaintext_file_name(name_encrypted)?;
    decrypt_name_metadata_with_key(file_key, name_encrypted)
}

/// A file's `name_encrypted` must be an encrypted JSON envelope.
fn refuse_plaintext_file_name(name_encrypted: &str) -> Result<(), CoreError> {
    if name_encrypted.starts_with('{') {
        Ok(())
    } else {
        Err(CoreError::InvalidInput(
            "file metadata is plaintext, not an encrypted envelope; refusing to read the file (task 1908)".into(),
        ))
    }
}

fn legacy_plaintext_metadata(name: &str) -> NameMetadata {
    NameMetadata {
        name: name.to_string(),
        mime_type: None,
        chunk_format: crate::chunk_stream::ExpectedChunkFormat::Unrecorded,
        version: None,
    }
}

/// Parse a decrypted metadata plaintext into [`NameMetadata`].
fn parse_name_metadata(decrypted: &str) -> Result<NameMetadata, CoreError> {
    let (name, mime_type) = unwrap_metadata_json(decrypted);
    let recorded = serde_json::from_str::<serde_json::Value>(decrypted)
        .ok()
        .and_then(|v| v.get(METADATA_CHUNK_FORMAT_FIELD).cloned());
    let chunk_format = match recorded {
        None => crate::chunk_stream::ExpectedChunkFormat::Unrecorded,
        Some(v) => {
            let code = v
                .as_u64()
                .and_then(|c| u8::try_from(c).ok())
                .ok_or_else(|| CoreError::InvalidInput("metadata chunk_format is not a format code".into()))?;
            match crate::chunk_stream::ExpectedChunkFormat::from_u8(code)? {
                // `0` is never written; an envelope that spells it out is malformed.
                crate::chunk_stream::ExpectedChunkFormat::Unrecorded => {
                    return Err(CoreError::InvalidInput(
                        "metadata chunk_format 0 is not a recorded format".into(),
                    ));
                }
                f => f,
            }
        }
    };
    let parsed = serde_json::from_str::<serde_json::Value>(decrypted).ok();
    let version_id = parsed.as_ref().and_then(|value| value.get(METADATA_VERSION_ID_FIELD));
    let version_counter = parsed
        .as_ref()
        .and_then(|value| value.get(METADATA_VERSION_COUNTER_FIELD));
    let version = match (version_id, version_counter) {
        (None, None) => None,
        (Some(version_id), Some(version_counter)) => {
            let encoded = version_id
                .as_str()
                .ok_or_else(|| CoreError::InvalidInput("metadata version_id is not a hex string".into()))?;
            if encoded.len() != crate::chunk_stream::VERSION_ID_LEN * 2
                || encoded
                    .bytes()
                    .any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
            {
                return Err(CoreError::InvalidInput(
                    "metadata version_id must be 24 lowercase hexadecimal characters".into(),
                ));
            }
            let version_id = decode_version_id(encoded)?;
            let counter = version_counter
                .as_u64()
                .ok_or_else(|| CoreError::InvalidInput("metadata version_counter is not an unsigned integer".into()))?;
            Some(crate::chunk_stream::VersionCommitment::new(version_id, counter)?)
        }
        _ => {
            return Err(CoreError::InvalidInput(
                "metadata version_id and version_counter must appear together".into(),
            ));
        }
    };
    Ok(NameMetadata {
        name,
        mime_type,
        chunk_format,
        version,
    })
}

fn encode_version_id(version_id: &[u8; crate::chunk_stream::VERSION_ID_LEN]) -> String {
    version_id.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn decode_version_id(encoded: &str) -> Result<[u8; crate::chunk_stream::VERSION_ID_LEN], CoreError> {
    if encoded.len() != crate::chunk_stream::VERSION_ID_LEN * 2 || !encoded.is_ascii() {
        return Err(CoreError::InvalidInput(
            "metadata version_id has the wrong length".into(),
        ));
    }
    let mut decoded = [0u8; crate::chunk_stream::VERSION_ID_LEN];
    for (index, output) in decoded.iter_mut().enumerate() {
        let start = index * 2;
        *output = u8::from_str_radix(&encoded[start..start + 2], 16)
            .map_err(|_| CoreError::InvalidInput("metadata version_id is not valid hexadecimal".into()))?;
    }
    Ok(decoded)
}

/// Open one name envelope and retain which key authenticated it. Protected
/// metadata is valid only under the purpose subkey; raw-key fallback remains
/// solely for old unpinned, uncommitted records.
fn decrypt_file_metadata_under(file_key: &FileKey, name_encrypted: &str) -> Result<Option<NameMetadata>, CoreError> {
    if let Some(plaintext) = decrypt_envelope_plaintext_under(&derive_name_key(file_key), name_encrypted) {
        return parse_name_metadata(&plaintext).map(Some);
    }
    let Some(plaintext) = decrypt_envelope_plaintext_under(file_key, name_encrypted) else {
        return Ok(None);
    };
    let metadata = parse_name_metadata(&plaintext)?;
    if metadata.chunk_format == crate::chunk_stream::ExpectedChunkFormat::V2 || metadata.version.is_some() {
        return Err(CoreError::Decryption);
    }
    Ok(Some(metadata))
}

/// Decrypt a `name_encrypted` value from the server back to a plaintext
/// filename. **This is the SINGLE source of truth for name decryption across
/// every client** (CLI, desktop, mobile/UniFFI, web/WASM) — do not re-implement
/// the format/key-derivation matrix anywhere else.
///
/// The server stores `name_encrypted` in several shapes depending on which
/// client wrote the file, and the per-file key may have been derived from two
/// different byte representations of the same UUID. This function tries every
/// combination and returns the first that decrypts to valid UTF-8.
///
/// ## Blob formats handled (per key)
///
/// 1. **Plaintext** — a bare string (not JSON). Legacy entries / server-created
///    folders that predate client-side name encryption. Returned verbatim.
/// 2. **Native `EncryptedBlob`** — JSON with `cipher_suite` + `nonce`/`ciphertext`
///    as numeric byte arrays. Produced by the CLI and any `beebeeb-core` client
///    serializing [`EncryptedBlob`] via serde.
/// 3. **Web base64 blob** — JSON `{"nonce":"<base64>","ciphertext":"<base64>"}`
///    with no `cipher_suite`. Produced by older web builds that base64-encoded
///    the raw `Uint8Array`s (see `repos/web/src/lib/crypto.ts`). The numeric-array
///    variant of this shape is also accepted (tolerant
///    [`crate::metadata_wire::parse_encrypted_metadata`]).
///
/// ## Key derivation handled
///
/// - **String-UUID** — `derive_file_key(mk, file_id.as_bytes())`. Current web +
///   current CLI + post-`bb repair` files (`TextEncoder.encode(fileId)` on web).
/// - **Binary-UUID** — `derive_file_key(mk, uuid.as_bytes())` (the 16-byte form).
///   Legacy pre-`bb repair` CLI files.
///
/// ## Fallback order (matches `repos/cli/src/crypto::decrypt_name`)
///
/// string-UUID key first, then binary-UUID key; within each key the native blob
/// is tried before the web base64 blob. The plaintext fast-path short-circuits
/// before any key derivation.
///
/// The uppercase repair convention (SF-0002) is deliberately NOT part of this
/// shared reader: it is reachable only through
/// [`crate::kdf::owner_file_key_for_name`], which reports the convention so a
/// client can treat the file as read-only.
///
/// Returns `CoreError::Decryption` only when the value looks encrypted but no
/// combination succeeds (wrong key, corrupt blob).
///
/// The decrypted plaintext envelope (`{"name":..,"mime_type":..}`) is unwrapped
/// to the bare `name`; a legacy bare-filename plaintext is returned as-is.
pub fn decrypt_name(
    master_key: &crate::kdf::MasterKey,
    file_id: &str,
    name_encrypted: &str,
) -> Result<String, CoreError> {
    decrypt_name_with_mime(master_key, file_id, name_encrypted).map(|(name, _)| name)
}

/// Decrypt a `name_encrypted` value and return both the filename and the MIME
/// type (if the encrypted payload carried one).
///
/// Handles the **exact same** format + key-derivation matrix as [`decrypt_name`]
/// — they share one implementation. See [`decrypt_name`] for the full list of
/// blob formats and key derivations covered.
pub fn decrypt_name_with_mime(
    master_key: &crate::kdf::MasterKey,
    file_id: &str,
    name_encrypted: &str,
) -> Result<(String, Option<String>), CoreError> {
    // Format 1 (fast path): plaintext — not JSON at all. Legacy / folder rows.
    if !name_encrypted.starts_with('{') {
        return Ok((name_encrypted.to_string(), None));
    }

    // Derive both candidate per-file keys. The web app derives from the UUID
    // *string* bytes (TextEncoder.encode(fileId)); the legacy CLI derived from
    // the 16-byte *binary* UUID. Try string-UUID first (the common case), then
    // binary-UUID. If `file_id` is not a valid UUID we can still try the
    // string-derived key — only the binary derivation is skipped.
    let key_from_string = crate::kdf::derive_file_key(master_key, file_id.as_bytes());
    let key_from_binary = file_id
        .parse::<uuid::Uuid>()
        .ok()
        .map(|u| crate::kdf::derive_file_key(master_key, u.as_bytes()));

    if let Some(result) = decrypt_name_envelope(&key_from_string, name_encrypted) {
        return Ok(result);
    }
    if let Some(key) = key_from_binary {
        if let Some(result) = decrypt_name_envelope(&key, name_encrypted) {
            return Ok(result);
        }
    }

    Err(CoreError::Decryption)
}

/// Decrypt a `name_encrypted` envelope with a **known** [`FileKey`], trying the
/// native `EncryptedBlob` blob first and the web base64 `{nonce,ciphertext}`
/// blob second, then unwrapping the `{name,mime_type}` metadata JSON.
///
/// Used directly by callers that already hold the file key (e.g. file-request
/// uploads, where the content key `C` is recovered via the request-key path and
/// the filename is encrypted under `FileKey(C)`, not a master-derived key).
/// A bare (non-JSON) plaintext name passes straight through; otherwise returns
/// `None` if neither blob format decrypts under this key.
pub fn decrypt_name_with_key(file_key: &FileKey, name_encrypted: &str) -> Option<String> {
    // Plaintext fast path — not JSON at all (legacy / folder rows).
    if !name_encrypted.starts_with('{') {
        return Some(name_encrypted.to_string());
    }
    decrypt_name_envelope(file_key, name_encrypted).map(|(name, _)| name)
}

/// Inner worker for [`decrypt_name_with_mime`] / [`decrypt_name_with_key`]:
/// given one file key, try both supported JSON blob formats and return the
/// unwrapped `(name, mime_type)` on the first that decrypts to valid UTF-8.
fn decrypt_name_envelope(file_key: &FileKey, name_encrypted: &str) -> Option<(String, Option<String>)> {
    decrypt_envelope_plaintext(file_key, name_encrypted).map(|pt| unwrap_metadata_json(&pt))
}

/// Decrypt one `name_encrypted` JSON envelope under one key, trying the native
/// `EncryptedBlob` shape then the web `{nonce, ciphertext}` shape, and return
/// the metadata plaintext (usually the `{name, mime_type[, chunk_format]}` JSON).
fn decrypt_envelope_plaintext(file_key: &FileKey, name_encrypted: &str) -> Option<String> {
    if let Some(plaintext) = decrypt_envelope_plaintext_under(&derive_name_key(file_key), name_encrypted) {
        return Some(plaintext);
    }
    let plaintext = decrypt_envelope_plaintext_under(file_key, name_encrypted)?;
    let metadata = parse_name_metadata(&plaintext).ok()?;
    if metadata.chunk_format == crate::chunk_stream::ExpectedChunkFormat::V2 || metadata.version.is_some() {
        None
    } else {
        Some(plaintext)
    }
}

/// Whether `name_encrypted` authenticates under `file_key` — exactly the
/// envelope reader [`decrypt_name_metadata`] uses, exposed crate-internally so
/// [`crate::kdf::owner_file_key_for_name`] can test a candidate key without
/// duplicating the format matrix. This only borrows `file_key`; the caller owns
/// the key and remains responsible for dropping it (which zeroizes its bytes).
pub(crate) fn name_envelope_authenticates(file_key: &FileKey, name_encrypted: &str) -> bool {
    decrypt_envelope_plaintext(file_key, name_encrypted).is_some()
}

/// [`decrypt_envelope_plaintext`] under exactly one key.
fn decrypt_envelope_plaintext_under(file_key: &FileKey, name_encrypted: &str) -> Option<String> {
    // Format 2: native EncryptedBlob (cipher_suite + numeric-array fields).
    if let Ok(blob) = serde_json::from_str::<EncryptedBlob>(name_encrypted) {
        if let Ok(plaintext) = decrypt_metadata(file_key, &blob) {
            return Some(plaintext);
        }
    }

    // Format 3: web base64 (or numeric-array) `{nonce, ciphertext}` blob — no
    // `cipher_suite`. `parse_encrypted_metadata` tolerantly handles both the
    // base64-string and legacy numeric-array encodings.
    if let Ok((nonce, ciphertext)) = crate::metadata_wire::parse_encrypted_metadata(name_encrypted) {
        let blob = EncryptedBlob {
            cipher_suite: CipherSuite::V1Aes256Gcm,
            nonce,
            ciphertext,
        };
        if let Ok(plaintext) = decrypt_metadata(file_key, &blob) {
            return Some(plaintext);
        }
    }

    None
}

/// Unwrap a decrypted plaintext into `(name, mime_type)`.
///
/// The ZK-safe envelope is `{"name":"report.pdf","mime_type":"application/pdf"}`;
/// extract `name` (+ optional `mime_type`). A legacy bare-filename plaintext
/// (not JSON, or JSON without a `name` field) is returned as the name with no
/// MIME type.
fn unwrap_metadata_json(decrypted: &str) -> (String, Option<String>) {
    if let Ok(meta) = serde_json::from_str::<serde_json::Value>(decrypted) {
        if let Some(name) = meta.get("name").and_then(|v| v.as_str()) {
            let mime = meta.get("mime_type").and_then(|v| v.as_str()).map(|s| s.to_string());
            return (name.to_string(), mime);
        }
    }
    (decrypted.to_string(), None)
}

/// Batch-decrypt many file names in one call (task 0806).
///
/// Every client decrypts folder names one-by-one across the WASM/UniFFI
/// boundary today — N crossings per folder. This collapses that to ONE crossing
/// and parallelises natively (rayon, off-wasm).
///
/// Per item it mirrors [`decrypt_name_with_mime`] (envelope → `name` + optional
/// `mime_type`, bare-string fallback), and — like the CLI's `decrypt_name`
/// compatibility shim — tries **both** file-key derivations a file could have
/// been created under, returning the first that authenticates: the **string-UUID**
/// form (`uuid.to_string().as_bytes()` — web/mobile + server-canonical
/// hyphenated-lowercase, the common case) first, then the legacy **binary-UUID**
/// form (`uuid.as_bytes()`, 16 raw bytes — CLI/desktop origin).
///
/// AES-256-GCM is authenticated, so a wrong-format key fails the tag (never a
/// false success). A bad/garbage item yields `Err` for THAT item only — it never
/// fails the whole batch. Order of results matches the input.
pub fn decrypt_names(
    master_key: &crate::kdf::MasterKey,
    items: &[(uuid::Uuid, &str)],
) -> Vec<Result<(String, Option<String>), CoreError>> {
    #[cfg(not(target_arch = "wasm32"))]
    {
        use rayon::prelude::*;
        items
            .par_iter()
            .map(|(file_id, name_encrypted)| decrypt_one_name(master_key, file_id, name_encrypted))
            .collect()
    }
    #[cfg(target_arch = "wasm32")]
    {
        // wasm32 is single-threaded; rayon can't target it. Sequential here; the
        // win on wasm is collapsing N boundary crossings into one call.
        items
            .iter()
            .map(|(file_id, name_encrypted)| decrypt_one_name(master_key, file_id, name_encrypted))
            .collect()
    }
}

/// Decrypt one `(file_id, name_encrypted)` — the per-item core of [`decrypt_names`].
///
/// Delegates to [`decrypt_name_with_mime`] so the batch path shares EXACTLY the
/// same format/key-derivation matrix as every single-item caller (plaintext
/// fast-path, native `EncryptedBlob`, and the legacy web base64
/// `{nonce,ciphertext}` blob). This used to re-implement a narrower subset
/// (native blob only, no plaintext fast-path, no web base64 format) which
/// silently failed to batch-decrypt a name encrypted in either of those two
/// formats. Fixed 2026-07-01, found while reviewing this rebase — present on
/// `origin/main` too (a smaller, self-contained fix landed there separately,
/// since `origin/main`'s own `decrypt_name_with_mime` doesn't yet have this
/// branch's full multi-format consolidation to delegate to).
fn decrypt_one_name(
    master_key: &crate::kdf::MasterKey,
    file_id: &uuid::Uuid,
    name_encrypted: &str,
) -> Result<(String, Option<String>), CoreError> {
    decrypt_name_with_mime(master_key, &file_id.to_string(), name_encrypted)
}

/// Encrypt a file chunk and return the canonical JSON string.
///
/// This is the **only** way clients should produce chunk data for upload.
pub fn encrypt_chunk_json(
    master_key: &crate::kdf::MasterKey,
    file_id: &str,
    plaintext: &[u8],
) -> Result<String, CoreError> {
    let file_key = crate::kdf::derive_file_key(master_key, file_id.as_bytes());
    let blob = encrypt_chunk(&file_key, plaintext)?;
    serde_json::to_string(&blob).map_err(|e| CoreError::Encryption(e.to_string()))
}

/// Encrypt a chunk → raw binary: nonce (12 bytes) || ciphertext (includes GCM tag).
///
/// This is the **v1 (legacy) frame**: AES-256-GCM with NO associated data, so
/// nothing binds the frame to its position in a file. It remains the generic
/// raw AEAD seal (search-index shards, file-request key wrap), but file content
/// goes through [`crate::chunk_stream::ChunkEncryptor`] (position-bound v2
/// frames) and thumbnails through [`encrypt_thumbnail`] (task 1908). Never
/// call it with a per-file key: a no-AAD blob under that key is
/// indistinguishable from a v1 content frame.
pub fn encrypt_chunk_raw(key: &FileKey, plaintext: &[u8]) -> Result<Vec<u8>, CoreError> {
    seal_raw_with_aad(key, plaintext, &[])
}

/// Shared raw seal: `nonce(12) || AES-256-GCM(key, nonce, plaintext, aad)`.
/// An empty `aad` is byte-identical to the v1 (no-AAD) frame.
pub(crate) fn seal_raw_with_aad(key: &FileKey, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CoreError> {
    seal_raw_with_nonce(key, &random_nonce(), plaintext, aad)
}

/// A fresh random 96-bit AES-GCM nonce from the OS RNG.
pub(crate) fn random_nonce() -> [u8; NONCE_LEN] {
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    nonce_bytes
}

/// Raw seal with a caller-chosen nonce: `nonce(12) || AES-256-GCM(key, nonce,
/// plaintext, aad)`. Callers MUST pass a fresh [`random_nonce`], except the
/// `cfg(test)` / `test-support` known-answer vector seams
/// ([`ChunkEncryptor::with_vector_nonces`](crate::chunk_stream::ChunkEncryptor::with_vector_nonces),
/// [`encrypt_name_with_chunk_format_and_nonce`], [`encrypt_name_for_with_nonce`]),
/// which no shipped build compiles. The name sealer ([`seal_name_envelope`])
/// passes its caller's nonce through: a fresh one from every shipped writer
/// (`shipped_name_writers_draw_a_fresh_nonce_each_call` pins that).
///
/// It exists because chunk format v2 binds frame 0's nonce (the per-upload
/// version id) into frame 0's own AAD, so the nonce has to be known before the
/// AAD is built. The name sealer reuses it so the vector seams take the shipped
/// path.
pub(crate) fn seal_raw_with_nonce(
    key: &FileKey,
    nonce_bytes: &[u8; NONCE_LEN],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CoreError> {
    let cipher = Aes256Gcm::new_from_slice(key.as_bytes()).map_err(|e| CoreError::Encryption(e.to_string()))?;
    let nonce = Nonce::from_slice(nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, Payload { msg: plaintext, aad })
        .map_err(|e| CoreError::Encryption(e.to_string()))?;
    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Shared raw open of a `nonce(12) || ciphertext || tag(16)` frame under `aad`.
///
/// aes-gcm 0.10.3 verifies the tag BEFORE applying the keystream, so a failed
/// open (wrong key, wrong AAD, tampered bytes) never materialises plaintext —
/// which is what makes trial opens (v2 then v1, last=0 then last=1) safe.
pub(crate) fn open_raw_with_aad(key: &FileKey, raw: &[u8], aad: &[u8]) -> Result<Vec<u8>, CoreError> {
    if raw.len() < NONCE_LEN + TAG_LEN {
        return Err(CoreError::Decryption);
    }
    let (nonce_bytes, ciphertext) = raw.split_at(NONCE_LEN);
    let cipher = Aes256Gcm::new_from_slice(key.as_bytes()).map_err(|e| CoreError::Encryption(e.to_string()))?;
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher
        .decrypt(nonce, Payload { msg: ciphertext, aad })
        .map_err(|_| CoreError::Decryption)
}

/// Decrypt a sequence of encrypted chunks and write the plaintext to a file.
/// Each chunk is an `EncryptedBlob` (V1Aes256Gcm with 12-byte nonce).
/// Returns the total number of plaintext bytes written.
///
/// **Atomic output:** plaintext is written to `{output_path}.tmp`, flushed, and
/// `rename`d to `output_path` only on full success. On **any** error (including
/// a mid-stream decrypt failure) the `.tmp` file is removed, so no partial
/// plaintext ever appears at `output_path`. (Same `.tmp` + atomic-rename +
/// remove-on-error pattern as [`decrypt_contiguous_to_file`].) On Windows an
/// `output_path` or `.tmp` whose name reaches a DIFFERENT existing file through
/// its 8.3 short name is refused (`InvalidInput`) and nothing is written.
///
/// **Chunk format (task 1908):** the chunks are opened in order as one file's
/// stream. `file_id` is the id the file was uploaded under (bound into every
/// v2 frame); `expected` and `version` come from the file's encrypted metadata
/// ([`decrypt_file_metadata`]): v2 opens only as the upload `version` names,
/// and with no `version` only a v1 file opens (the ruling of 2026-11-07). A v2
/// file that is reordered, mixes frames of two uploads, has a chunk
/// duplicated/dropped/appended, or ends before its last chunk is rejected.
pub fn decrypt_chunks_to_file(
    key: &FileKey,
    file_id: &str,
    expected: crate::chunk_stream::ExpectedChunkFormat,
    version: Option<crate::chunk_stream::VersionCommitment>,
    chunks: Vec<(Vec<u8>, Vec<u8>)>, // Vec of (nonce, ciphertext) pairs
    output_path: &str,
) -> Result<u64, CoreError> {
    // Stream into a sibling .tmp, published as output_path on success only;
    // on ANY Err the .tmp is removed so no partial plaintext survives.
    let opener = crate::chunk_stream::StreamOpener::with_version_commitment(key, file_id, expected, version);
    crate::path_safety::write_through_tmp(output_path.as_ref(), |file| {
        decrypt_chunks_to_tmp(key, opener, chunks, file)
    })
}

/// Streaming decrypt of `(nonce, ciphertext)` chunks into the temp `file`. Helper for
/// [`decrypt_chunks_to_file`] so the caller can guarantee `.tmp` cleanup on
/// every error path.
fn decrypt_chunks_to_tmp(
    key: &FileKey,
    mut opener: crate::chunk_stream::StreamOpener,
    chunks: Vec<(Vec<u8>, Vec<u8>)>,
    mut file: std::fs::File,
) -> Result<u64, CoreError> {
    use std::io::Write;

    let mut total: u64 = 0;
    for (nonce, ciphertext) in chunks {
        if nonce.len() != NONCE_LEN {
            return Err(CoreError::Decryption);
        }
        let mut frame = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        frame.extend_from_slice(&nonce);
        frame.extend_from_slice(&ciphertext);
        let chunk = opener.open_next(key, &frame)?;
        file.write_all(&chunk.data)
            .map_err(|e| CoreError::Io(format!("write: {e}")))?;
        total += chunk.data.len() as u64;
    }
    // Truncation check: a v2 file must have reached its last chunk.
    opener.finish()?;
    file.flush().map_err(|e| CoreError::Io(format!("flush: {e}")))?;
    Ok(total)
}

/// Decrypt a raw binary **v1** frame: nonce (12 bytes) || ciphertext, no AAD.
///
/// This opens ONLY legacy v1 frames (and the other no-AAD raw blobs: search
/// shards, file-request key wrap). It rejects every v2 file-content frame by
/// construction — that is the downgrade guarantee of task 1908. To read file
/// content (v1 or v2) use [`crate::chunk_stream::ChunkDecryptor`] or
/// [`crate::chunk_stream::open_chunk`].
pub fn decrypt_chunk_raw(key: &FileKey, raw: &[u8]) -> Result<Vec<u8>, CoreError> {
    open_raw_with_aad(key, raw, &[])
}

/// Decrypt a contiguous encrypted body into a file.
///
/// `body` is the wire format produced by concatenating encrypted chunks:
/// each chunk is `nonce (12 bytes) || ciphertext (chunk_size bytes of AEAD
/// output + 16 byte GCM tag)`. All chunks but the last produce `chunk_size`
/// bytes of plaintext; the final chunk is whatever remains in `body` and
/// may be shorter.
///
/// Streams chunk-by-chunk — peak memory is one plaintext chunk, not the
/// full file. Returns the total number of plaintext bytes written.
///
/// **Atomic output:** plaintext is written to `{output_path}.tmp`, flushed, and
/// `rename`d to `output_path` only on full success. On **any** error the `.tmp`
/// file is removed, so no partial plaintext ever appears at `output_path`. This
/// removes the previous caller-cleanup obligation and prevents an
/// existence-based cache from serving a truncated decrypt as if complete. (Same
/// `.tmp` + atomic-rename pattern as
/// [`crate::file_encrypt::decrypt_chunks_to_file`].) On Windows an
/// `output_path` or `.tmp` whose name reaches a DIFFERENT existing file through
/// its 8.3 short name is refused (`InvalidInput`) and nothing is written.
///
/// **Chunk format (task 1908):** the body is opened as one file's stream.
/// `file_id` is the id the file was uploaded under (bound into every v2 frame);
/// `expected` and `version` come from the file's encrypted metadata
/// ([`decrypt_file_metadata`]): v2 opens only as the upload `version` names,
/// and with no `version` only a v1 body opens (the ruling of 2026-11-07). A v2
/// body that is reordered, spliced (within or across uploads), has trailing
/// frames, or ends before its last chunk is rejected.
pub fn decrypt_contiguous_to_file(
    key: &FileKey,
    file_id: &str,
    expected: crate::chunk_stream::ExpectedChunkFormat,
    version: Option<crate::chunk_stream::VersionCommitment>,
    body: &[u8],
    chunk_size: u64,
    output_path: &str,
) -> Result<u64, CoreError> {
    if chunk_size == 0 {
        return Err(CoreError::InvalidInput("chunk_size must be positive".into()));
    }
    let chunk_size_usize: usize = chunk_size
        .try_into()
        .map_err(|_| CoreError::InvalidInput(format!("chunk_size {chunk_size} exceeds usize range")))?;
    let encrypted_chunk_len = NONCE_LEN
        .checked_add(chunk_size_usize)
        .and_then(|v| v.checked_add(TAG_LEN))
        .ok_or_else(|| CoreError::InvalidInput("chunk_size overflows".into()))?;

    // Stream into a sibling .tmp, published as output_path on success only;
    // on ANY Err the .tmp is removed so no partial plaintext survives.
    let opener = crate::chunk_stream::StreamOpener::with_version_commitment(key, file_id, expected, version);
    crate::path_safety::write_through_tmp(output_path.as_ref(), |file| {
        decrypt_contiguous_to_tmp(key, opener, body, encrypted_chunk_len, file)
    })
}

/// Streaming decrypt body into the temp `file`. Helper for [`decrypt_contiguous_to_file`]
/// so the caller can guarantee `.tmp` cleanup on every error path.
fn decrypt_contiguous_to_tmp(
    key: &FileKey,
    mut opener: crate::chunk_stream::StreamOpener,
    body: &[u8],
    encrypted_chunk_len: usize,
    mut file: std::fs::File,
) -> Result<u64, CoreError> {
    use std::io::Write;

    let mut total: u64 = 0;
    let mut offset = 0usize;

    while offset < body.len() {
        let remaining = body.len() - offset;
        let take = remaining.min(encrypted_chunk_len);
        // Need at least NONCE_LEN + TAG_LEN to even attempt a decrypt.
        if take < NONCE_LEN + TAG_LEN {
            return Err(CoreError::Decryption);
        }
        let raw_chunk = &body[offset..offset + take];
        let chunk = opener.open_next(key, raw_chunk)?;
        file.write_all(&chunk.data)
            .map_err(|e| CoreError::Io(format!("write: {e}")))?;
        total += chunk.data.len() as u64;
        offset += take;
    }
    // Truncation check: a v2 file must have reached its last chunk (and an
    // empty body is never a valid file).
    opener.finish()?;
    file.flush().map_err(|e| CoreError::Io(format!("flush: {e}")))?;
    Ok(total)
}

#[cfg(test)]
mod tests;

/// Task 1958: `encrypt_name_for`, the rename writer under a GIVEN per-file key.
#[cfg(test)]
mod encrypt_name_for_tests_1958 {
    #![allow(deprecated)]
    use super::*;
    use crate::chunk_stream::ExpectedChunkFormat;

    /// Round 3, I-2: the nonce is a parameter of the shared name path, so the
    /// shipped writers must draw a fresh one on every call. The same input
    /// sealed twice carries two different nonces, under a given key
    /// (`encrypt_name_for`) and under a master key
    /// (`encrypt_name_with_chunk_format`), for both pins. A constant nonce in
    /// the shipped path is red here.
    #[test]
    fn shipped_name_writers_draw_a_fresh_nonce_each_call() {
        let nonce = |name_encrypted: &str| serde_json::from_str::<EncryptedBlob>(name_encrypted).unwrap().nonce;
        let mk = crate::kdf::MasterKey::from_bytes([0x41; 32]);
        for pin in [ExpectedChunkFormat::Unrecorded, ExpectedChunkFormat::V2] {
            let seal_given = || encrypt_name_for(&given_key(), "same.pdf", Some("application/pdf"), pin).unwrap();
            assert_ne!(
                nonce(&seal_given()),
                nonce(&seal_given()),
                "encrypt_name_for reused a nonce ({pin:?})"
            );
            let seal_derived =
                || encrypt_name_with_chunk_format(&mk, "file-1958", "same.pdf", Some("application/pdf"), pin).unwrap();
            assert_ne!(
                nonce(&seal_derived()),
                nonce(&seal_derived()),
                "encrypt_name_with_chunk_format reused a nonce ({pin:?})"
            );
        }
    }

    /// A key not derived from any master key: what a file-request upload or a
    /// shared-folder file is sealed under.
    fn given_key() -> FileKey {
        FileKey::from_bytes([0x37; 32])
    }

    fn opens_under(key: &FileKey, name_encrypted: &str) -> bool {
        serde_json::from_str::<EncryptedBlob>(name_encrypted)
            .ok()
            .and_then(|blob| decrypt_metadata(key, &blob).ok())
            .is_some()
    }

    /// A v2-pinned rename keeps the pin and is sealed under the name subkey, not
    /// the raw file key (which would open as a one-frame v1 "file" again).
    #[test]
    fn a_pinned_rename_keeps_the_pin_and_is_subkey_sealed() {
        let fk = given_key();
        let sealed = encrypt_name_for(&fk, "taxes 2026.pdf", Some("application/pdf"), ExpectedChunkFormat::V2).unwrap();
        let meta = decrypt_file_metadata_with_key(&fk, &sealed).unwrap();
        assert_eq!(meta.name, "taxes 2026.pdf");
        assert_eq!(meta.mime_type.as_deref(), Some("application/pdf"));
        assert_eq!(
            meta.chunk_format,
            ExpectedChunkFormat::V2,
            "the pin survives the rename"
        );
        assert!(
            opens_under(&derive_name_key(&fk), &sealed),
            "sealed under the name subkey"
        );
        assert!(!opens_under(&fk, &sealed), "never under the raw file key");
    }

    /// An unpinned rename follows the read-only-phase write rule: the raw key
    /// (legacy) and nothing recorded, exactly like an unpinned new file's name.
    #[test]
    fn an_unpinned_rename_follows_the_write_format() {
        let fk = given_key();
        let sealed = encrypt_name_for(&fk, "notes.txt", None, ExpectedChunkFormat::Unrecorded).unwrap();
        let meta = decrypt_file_metadata_with_key(&fk, &sealed).unwrap();
        assert_eq!(
            (meta.name.as_str(), meta.chunk_format),
            ("notes.txt", ExpectedChunkFormat::Unrecorded)
        );
        assert_eq!(
            opens_under(&fk, &sealed),
            METADATA_SEAL_WRITE == MetadataSeal::Legacy,
            "unpinned names follow METADATA_SEAL_WRITE"
        );
    }

    /// For a key derived from the master key, the per-file-key writer IS the
    /// master-key writer: identical bytes under the same nonce, for both pins,
    /// and the shipped (random-nonce) writers read back identically.
    #[test]
    fn the_filekey_writer_matches_the_master_key_writer_for_a_derived_key() {
        let mk = crate::kdf::MasterKey::from_bytes([0x11; 32]);
        let id = "1958f00d-0000-4000-8000-000000001958";
        let fk = crate::kdf::derive_file_key(&mk, id.as_bytes());
        for pin in [ExpectedChunkFormat::V2, ExpectedChunkFormat::Unrecorded] {
            let nonce = [0x42; NONCE_LEN];
            let by_master =
                encrypt_name_with_chunk_format_and_nonce(&mk, id, "a.pdf", Some("application/pdf"), pin, nonce)
                    .unwrap();
            let by_key = encrypt_name_for_with_nonce(&fk, "a.pdf", Some("application/pdf"), pin, nonce).unwrap();
            assert_eq!(by_master, by_key, "{pin:?}: same bytes");

            let shipped_master =
                encrypt_name_with_chunk_format(&mk, id, "a.pdf", Some("application/pdf"), pin).unwrap();
            let shipped_key = encrypt_name_for(&fk, "a.pdf", Some("application/pdf"), pin).unwrap();
            assert_eq!(
                decrypt_file_metadata(&mk, id, &shipped_master).unwrap(),
                decrypt_file_metadata(&mk, id, &shipped_key).unwrap(),
                "{pin:?}: same metadata through the master-key reader"
            );
        }
    }
}

/// Task 2275 L13: the new-item sealer must be byte-identical to the derived
/// path for the same id and nonce (same key, same pin, same plaintext).
#[cfg(test)]
mod write_shape_tests {
    #![allow(deprecated)]
    use super::*;

    #[test]
    fn new_item_name_matches_the_derived_path_byte_for_byte() {
        let master = crate::kdf::MasterKey::from_bytes(std::array::from_fn(|i| i as u8));
        let id = NewItemId::owner(&master).unwrap();
        let nonce = [0x42; NONCE_LEN];
        let key = new_item_name_key(&master, &id).unwrap();
        let via_new = encrypt_name_for_with_nonce(
            &key,
            "a.txt",
            Some("text/plain"),
            crate::chunk_stream::ExpectedChunkFormat::Unrecorded,
            nonce,
        )
        .unwrap();
        let via_derived = encrypt_name_with_chunk_format_and_nonce(
            &master,
            id.as_str(),
            "a.txt",
            Some("text/plain"),
            crate::chunk_stream::ExpectedChunkFormat::Unrecorded,
            nonce,
        )
        .unwrap();
        assert_eq!(via_new, via_derived);
    }
}
