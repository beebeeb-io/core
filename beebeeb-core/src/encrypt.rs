use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use rand::RngCore;

use beebeeb_types::{CipherSuite, EncryptedBlob};

use crate::CoreError;
use crate::kdf::FileKey;

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
    // follows the write switch (legacy during the read-only phase, so clients
    // not yet on this core keep reading the names this core writes). One rule
    // for content, names and thumbnails: chunk_format_for_pin + metadata_seal_for.
    let seal = metadata_seal_for(crate::chunk_stream::chunk_format_for_pin(chunk_format));
    encrypt_name_sealed(master_key, file_id, filename, mime_type, chunk_format, seal)
}

/// [`encrypt_name_with_chunk_format`] with an explicit seal — crate-internal,
/// so no shipped client can write subkey-sealed names for a v1 file ahead of
/// the [`METADATA_SEAL_WRITE`] switch.
pub(crate) fn encrypt_name_sealed(
    master_key: &crate::kdf::MasterKey,
    file_id: &str,
    filename: &str,
    mime_type: Option<&str>,
    chunk_format: crate::chunk_stream::ExpectedChunkFormat,
    seal: MetadataSeal,
) -> Result<String, CoreError> {
    let (key, plaintext) = name_envelope(master_key, file_id, filename, mime_type, chunk_format, seal);
    let blob = encrypt_metadata(&key, &plaintext)?;
    serde_json::to_string(&blob).map_err(|e| CoreError::Encryption(e.to_string()))
}

/// [`encrypt_name_with_chunk_format`] with a FIXED nonce — for the published
/// known-answer vectors only (`test-vectors/vectors.json`, task 1943). Compiled
/// only under `cfg(test)` or the `test-support` feature, never in a shipped
/// client: a fixed nonce reused under one key breaks AES-GCM. Same rule as the
/// real writer (the pin picks the seal), so the vector IS what the writer emits
/// apart from the nonce.
#[cfg(any(test, feature = "test-support"))]
pub fn encrypt_name_with_chunk_format_and_nonce(
    master_key: &crate::kdf::MasterKey,
    file_id: &str,
    filename: &str,
    mime_type: Option<&str>,
    chunk_format: crate::chunk_stream::ExpectedChunkFormat,
    nonce: [u8; NONCE_LEN],
) -> Result<String, CoreError> {
    let seal = metadata_seal_for(crate::chunk_stream::chunk_format_for_pin(chunk_format));
    let (key, plaintext) = name_envelope(master_key, file_id, filename, mime_type, chunk_format, seal);
    // The same blob `encrypt_metadata` builds (no AAD), with the given nonce.
    let frame = seal_raw_with_nonce(&key, &nonce, plaintext.as_bytes(), &[])?;
    let blob = EncryptedBlob {
        cipher_suite: CipherSuite::V1Aes256Gcm,
        nonce: frame[..NONCE_LEN].to_vec(),
        ciphertext: frame[NONCE_LEN..].to_vec(),
    };
    serde_json::to_string(&blob).map_err(|e| CoreError::Encryption(e.to_string()))
}

/// The name/MIME envelope plaintext and the key it is sealed under — shared by
/// the real writer ([`encrypt_name_sealed`], random nonce) and the vector seam
/// ([`encrypt_name_with_chunk_format_and_nonce`]), so a fixed nonce is never a
/// parameter of any code a shipped build compiles.
fn name_envelope(
    master_key: &crate::kdf::MasterKey,
    file_id: &str,
    filename: &str,
    mime_type: Option<&str>,
    chunk_format: crate::chunk_stream::ExpectedChunkFormat,
    seal: MetadataSeal,
) -> (FileKey, String) {
    let mut meta = serde_json::json!({
        "name": filename,
        "mime_type": mime_type,
    });
    if chunk_format == crate::chunk_stream::ExpectedChunkFormat::V2 {
        meta[METADATA_CHUNK_FORMAT_FIELD] = serde_json::json!(chunk_format.as_u8());
    }
    let plaintext = meta.to_string();
    let file_key = crate::kdf::derive_file_key(master_key, file_id.as_bytes());
    let key = match seal {
        MetadataSeal::Legacy => file_key,
        MetadataSeal::Subkey => derive_name_key(&file_key),
    };
    (key, plaintext)
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

/// How new name envelopes (of files whose metadata records no v2 format), new
/// thumbnails and new file notes are sealed. Tied to [`crate::chunk_stream::WRITE_FORMAT`] so
/// the two flip in ONE gated release: while content is still written as v1,
/// a subkey-sealed name would be unreadable by every client not yet on this
/// core, and there is no v2 file for it to protect. A name that records
/// `chunk_format: 2` (and a thumbnail written with [`encrypt_thumbnail_for`] a
/// v2 pin, and a note written with [`encrypt_note_for`] a v2 pin) is
/// subkey-sealed regardless. `= metadata_seal_for(WRITE_FORMAT)`.
pub const METADATA_SEAL_WRITE: MetadataSeal = metadata_seal_for(crate::chunk_stream::WRITE_FORMAT);

/// How names, thumbnails and file notes are sealed for content written in `format`
/// (task 1908 review round 4, P2-1): v1 content → [`MetadataSeal::Legacy`]
/// (readable by clients not yet on this core), v2 content →
/// [`MetadataSeal::Subkey`] (only a reader on this core opens v2 content
/// anyway). Both arms are pinned by a test, so the V2 arm is checked although
/// [`METADATA_SEAL_WRITE`] does not take it yet.
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
pub fn encrypt_thumbnail_for(
    file_key: &FileKey,
    plaintext: &[u8],
    pin: crate::chunk_stream::ExpectedChunkFormat,
) -> Result<Vec<u8>, CoreError> {
    let seal = metadata_seal_for(crate::chunk_stream::chunk_format_for_pin(pin));
    encrypt_thumbnail_sealed(file_key, plaintext, seal)
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
/// `note_encrypted` today, so readers not yet on this core still open notes
/// this core writes during the read-only phase. Read it back with
/// [`decrypt_note`]. These two writers are the only way clients should seal a
/// note — never `encrypt_metadata` / `encrypt_chunk` under the file key.
pub fn encrypt_note(file_key: &FileKey, note: &str) -> Result<String, CoreError> {
    encrypt_note_sealed(file_key, note, METADATA_SEAL_WRITE)
}

/// Seal a note of an EXISTING file whose encrypted metadata records `pin` (from
/// [`decrypt_file_metadata`], never a server field). The same rule as names
/// and thumbnails: a v2 pin is ALWAYS sealed under the note subkey (the note
/// can then never stand in for the file's name or content); `Unrecorded`
/// follows [`METADATA_SEAL_WRITE`] (legacy during the read-only phase).
pub fn encrypt_note_for(
    file_key: &FileKey,
    note: &str,
    pin: crate::chunk_stream::ExpectedChunkFormat,
) -> Result<String, CoreError> {
    let seal = metadata_seal_for(crate::chunk_stream::chunk_format_for_pin(pin));
    encrypt_note_sealed(file_key, note, seal)
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
    if let Some(pt) = decrypt_envelope_plaintext(&key_from_string, name_encrypted) {
        return parse_name_metadata(&pt);
    }
    if let Some(key) = file_id
        .parse::<uuid::Uuid>()
        .ok()
        .map(|u| crate::kdf::derive_file_key(master_key, u.as_bytes()))
    {
        if let Some(pt) = decrypt_envelope_plaintext(&key, name_encrypted) {
            return parse_name_metadata(&pt);
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
    let pt = decrypt_envelope_plaintext(file_key, name_encrypted).ok_or(CoreError::Decryption)?;
    parse_name_metadata(&pt)
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
    Ok(NameMetadata {
        name,
        mime_type,
        chunk_format,
    })
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
    // Name subkey first (envelopes written since task 1908 round 3), then the
    // legacy raw file key (every envelope written before).
    decrypt_envelope_plaintext_under(&derive_name_key(file_key), name_encrypted)
        .or_else(|| decrypt_envelope_plaintext_under(file_key, name_encrypted))
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
/// [`encrypt_name_with_chunk_format_and_nonce`]), which no shipped build
/// compiles. The only reason this exists is that chunk format v2 binds frame
/// 0's nonce (the per-upload version id) into frame 0's own AAD, so the nonce
/// has to be known before the AAD is built.
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
/// remove-on-error pattern as [`decrypt_contiguous_to_file`].)
///
/// **Chunk format (task 1908):** the chunks are opened in order as one file's
/// stream. `file_id` is the id the file was uploaded under (bound into every
/// v2 frame); `expected` comes from the file's encrypted metadata
/// ([`decrypt_file_metadata`]): `V2` accepts only v2 frames, `Unrecorded`
/// (legacy metadata) lets chunk 0 decide. A v2 file that is reordered, mixes
/// frames of two uploads, has a chunk duplicated/dropped/appended, or ends
/// before its last chunk is rejected.
pub fn decrypt_chunks_to_file(
    key: &FileKey,
    file_id: &str,
    expected: crate::chunk_stream::ExpectedChunkFormat,
    chunks: Vec<(Vec<u8>, Vec<u8>)>, // Vec of (nonce, ciphertext) pairs
    output_path: &str,
) -> Result<u64, CoreError> {
    // Write to a sibling .tmp, then atomically rename on success only.
    let tmp_path = format!("{output_path}.tmp");

    // Inner helper does the streaming decrypt into the .tmp; on ANY Err the
    // outer code removes the .tmp so no partial plaintext survives at output_path.
    let result = decrypt_chunks_to_tmp(key, file_id, expected, chunks, &tmp_path);

    match result {
        Ok(total) => {
            std::fs::rename(&tmp_path, output_path).map_err(|e| {
                // Rename failed: drop the temp so it can't poison a cache.
                std::fs::remove_file(&tmp_path).ok();
                CoreError::Io(format!("rename output: {e}"))
            })?;
            Ok(total)
        }
        Err(e) => {
            // Remove the partial temp on every failure path.
            std::fs::remove_file(&tmp_path).ok();
            Err(e)
        }
    }
}

/// Streaming decrypt of `(nonce, ciphertext)` chunks → `tmp_path`. Helper for
/// [`decrypt_chunks_to_file`] so the caller can guarantee `.tmp` cleanup on
/// every error path.
fn decrypt_chunks_to_tmp(
    key: &FileKey,
    file_id: &str,
    expected: crate::chunk_stream::ExpectedChunkFormat,
    chunks: Vec<(Vec<u8>, Vec<u8>)>,
    tmp_path: &str,
) -> Result<u64, CoreError> {
    use std::fs::File;
    use std::io::Write;

    let mut file = File::create(tmp_path).map_err(|e| CoreError::Io(format!("create file: {e}")))?;
    let mut opener = crate::chunk_stream::StreamOpener::new(key, file_id, expected);
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
/// [`crate::file_encrypt::decrypt_chunks_to_file`].)
///
/// **Chunk format (task 1908):** the body is opened as one file's stream.
/// `file_id` is the id the file was uploaded under (bound into every v2 frame);
/// `expected` comes from the file's encrypted metadata
/// ([`decrypt_file_metadata`]): `V2` accepts only v2 frames, `Unrecorded`
/// (legacy metadata) lets chunk 0 decide. A v2 body that is reordered, spliced
/// (within or across uploads), has trailing frames, or ends before its last
/// chunk is rejected.
pub fn decrypt_contiguous_to_file(
    key: &FileKey,
    file_id: &str,
    expected: crate::chunk_stream::ExpectedChunkFormat,
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

    // Write to a sibling .tmp, then atomically rename on success only.
    let tmp_path = format!("{output_path}.tmp");

    // Inner closure does the streaming decrypt; on ANY Err the outer code
    // removes the .tmp so no partial plaintext survives at output_path.
    let result = decrypt_contiguous_to_tmp(key, file_id, expected, body, encrypted_chunk_len, &tmp_path);

    match result {
        Ok(total) => {
            std::fs::rename(&tmp_path, output_path).map_err(|e| {
                // Rename failed: drop the temp so it can't poison a cache.
                std::fs::remove_file(&tmp_path).ok();
                CoreError::Io(format!("rename output: {e}"))
            })?;
            Ok(total)
        }
        Err(e) => {
            // Remove the partial temp on every failure path.
            std::fs::remove_file(&tmp_path).ok();
            Err(e)
        }
    }
}

/// Streaming decrypt body → `tmp_path`. Helper for [`decrypt_contiguous_to_file`]
/// so the caller can guarantee `.tmp` cleanup on every error path.
fn decrypt_contiguous_to_tmp(
    key: &FileKey,
    file_id: &str,
    expected: crate::chunk_stream::ExpectedChunkFormat,
    body: &[u8],
    encrypted_chunk_len: usize,
    tmp_path: &str,
) -> Result<u64, CoreError> {
    use std::fs::File;
    use std::io::Write;

    let mut file = File::create(tmp_path).map_err(|e| CoreError::Io(format!("create file: {e}")))?;
    let mut opener = crate::chunk_stream::StreamOpener::new(key, file_id, expected);
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
mod tests {
    use super::*;
    use crate::chunk_stream::ExpectedChunkFormat::{Unrecorded, V2};
    use crate::kdf::{derive_file_key, derive_master_key};

    fn test_file_key() -> FileKey {
        let mk = derive_master_key("test-password", b"test-salt-16bytes").unwrap();
        derive_file_key(&mk, b"test-file-id")
    }

    #[test]
    fn roundtrip_encrypt_decrypt_chunk() {
        let key = test_file_key();
        let plaintext = b"hello, beebeeb!";

        let blob = encrypt_chunk(&key, plaintext).unwrap();
        assert_eq!(blob.cipher_suite, CipherSuite::V1Aes256Gcm);
        assert_eq!(blob.nonce.len(), 12);
        assert_ne!(&blob.ciphertext[..plaintext.len()], plaintext.as_slice());

        let decrypted = decrypt_chunk(&key, &blob).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn wrong_key_fails_decryption() {
        let key = test_file_key();
        let blob = encrypt_chunk(&key, b"secret").unwrap();

        let mk = derive_master_key("different-password", b"different-salt-16").unwrap();
        let wrong_key = derive_file_key(&mk, b"wrong-file");
        assert!(decrypt_chunk(&wrong_key, &blob).is_err());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let key = test_file_key();
        let mut blob = encrypt_chunk(&key, b"important data").unwrap();

        if let Some(byte) = blob.ciphertext.first_mut() {
            *byte ^= 0xFF;
        }

        assert!(decrypt_chunk(&key, &blob).is_err());
    }

    #[test]
    fn tampered_nonce_fails() {
        let key = test_file_key();
        let mut blob = encrypt_chunk(&key, b"important data").unwrap();

        if let Some(byte) = blob.nonce.first_mut() {
            *byte ^= 0xFF;
        }

        assert!(decrypt_chunk(&key, &blob).is_err());
    }

    #[test]
    fn invalid_nonce_length_fails() {
        let key = test_file_key();
        let blob = EncryptedBlob {
            cipher_suite: CipherSuite::V1Aes256Gcm,
            nonce: vec![0u8; 8], // wrong length
            ciphertext: vec![0u8; 32],
        };
        assert!(decrypt_chunk(&key, &blob).is_err());
    }

    #[test]
    fn empty_plaintext_roundtrip() {
        let key = test_file_key();
        let blob = encrypt_chunk(&key, b"").unwrap();
        let decrypted = decrypt_chunk(&key, &blob).unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn roundtrip_metadata() {
        let key = test_file_key();
        let filename = "photos/vacation/IMG_2024.jpg";

        let blob = encrypt_metadata(&key, filename).unwrap();
        let recovered = decrypt_metadata(&key, &blob).unwrap();
        assert_eq!(recovered, filename);
    }

    #[test]
    fn metadata_wrong_key_fails() {
        let key = test_file_key();
        let blob = encrypt_metadata(&key, "secret.txt").unwrap();

        let mk = derive_master_key("other", b"other-salt-16byte").unwrap();
        let wrong_key = derive_file_key(&mk, b"wrong");
        assert!(decrypt_metadata(&wrong_key, &blob).is_err());
    }

    #[test]
    fn unique_nonces_per_encryption() {
        let key = test_file_key();
        let blob1 = encrypt_chunk(&key, b"same").unwrap();
        let blob2 = encrypt_chunk(&key, b"same").unwrap();
        assert_ne!(blob1.nonce, blob2.nonce);
    }

    #[test]
    fn decrypt_chunks_to_file_roundtrip() {
        let key = test_file_key();
        let chunk1 = b"hello, ";
        let chunk2 = b"beebeeb!";

        let blob1 = encrypt_chunk(&key, chunk1).unwrap();
        let blob2 = encrypt_chunk(&key, chunk2).unwrap();

        let chunks = vec![(blob1.nonce, blob1.ciphertext), (blob2.nonce, blob2.ciphertext)];

        let dir = std::env::temp_dir();
        let path = dir.join("beebeeb_test_decrypt_chunks.bin");
        let path_str = path.to_str().unwrap();

        let total = decrypt_chunks_to_file(&key, "test-file-id", Unrecorded, chunks, path_str).unwrap();
        assert_eq!(total, (chunk1.len() + chunk2.len()) as u64);

        let written = std::fs::read(&path).unwrap();
        assert_eq!(written, b"hello, beebeeb!");

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn decrypt_chunks_to_file_empty_is_rejected() {
        // Task 1908 (justified behaviour change): this used to return Ok(0) and
        // write an empty file. No real file has zero frames — even an empty file
        // is one 28-byte frame in v1 and v2 — so a zero-frame list is a server
        // that withheld every chunk: total truncation. It must be an error, and
        // no output may appear.
        let key = test_file_key();

        let dir = std::env::temp_dir();
        let path = dir.join("beebeeb_test_decrypt_empty.bin");
        let path_str = path.to_str().unwrap();
        std::fs::remove_file(&path).ok();

        let err = decrypt_chunks_to_file(&key, "test-file-id", Unrecorded, vec![], path_str).unwrap_err();
        assert!(matches!(err, CoreError::Decryption));
        assert!(!path.exists(), "no output may appear for a zero-frame file");
    }

    #[test]
    fn decrypt_chunks_to_file_leaves_no_partial_file_on_midstream_failure() {
        // Mirror of decrypt_contiguous_leaves_no_partial_file_on_midstream_failure:
        // chunk 1 decrypts fine, chunk 2's GCM tag is corrupt. The function must
        // fail AND leave no partial plaintext at output_path AND no .tmp artifact.
        let key = test_file_key();
        let blob1 = encrypt_chunk(&key, b"AAAAAAAA").unwrap();
        let mut blob2 = encrypt_chunk(&key, b"BBBBBBBB").unwrap();
        // Corrupt the GCM tag of the second chunk (flip the last ciphertext byte).
        let last = blob2.ciphertext.len() - 1;
        blob2.ciphertext[last] ^= 0xFF;
        let chunks = vec![(blob1.nonce, blob1.ciphertext), (blob2.nonce, blob2.ciphertext)];

        let path = std::env::temp_dir().join("beebeeb_test_chunks_partial_cleanup.bin");
        let tmp = std::path::PathBuf::from(format!("{}.tmp", path.to_str().unwrap()));
        // Ensure stale artifacts from a prior run do not mask the assertion.
        std::fs::remove_file(&path).ok();
        std::fs::remove_file(&tmp).ok();

        let err = decrypt_chunks_to_file(&key, "test-file-id", Unrecorded, chunks, path.to_str().unwrap()).unwrap_err();
        assert!(matches!(err, CoreError::Decryption));
        assert!(
            !path.exists(),
            "no partial plaintext file may remain at output_path after a failed decrypt"
        );
        assert!(!tmp.exists(), "no .tmp artifact may remain after a failed decrypt");
    }

    #[test]
    fn decrypt_chunks_to_file_wrong_key_fails() {
        let key = test_file_key();
        let blob = encrypt_chunk(&key, b"secret data").unwrap();
        let chunks = vec![(blob.nonce, blob.ciphertext)];

        let mk = derive_master_key("different-password", b"different-salt-16").unwrap();
        let wrong_key = derive_file_key(&mk, b"wrong-file");

        let dir = std::env::temp_dir();
        let path = dir.join("beebeeb_test_decrypt_wrong_key.bin");
        let path_str = path.to_str().unwrap();

        assert!(decrypt_chunks_to_file(&wrong_key, "test-file-id", Unrecorded, chunks, path_str).is_err());

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn large_plaintext_roundtrip() {
        let key = test_file_key();
        let plaintext = vec![0x42u8; 1024 * 1024]; // 1 MiB
        let blob = encrypt_chunk(&key, &plaintext).unwrap();
        let decrypted = decrypt_chunk(&key, &blob).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    fn pack_chunk(blob: &EncryptedBlob) -> Vec<u8> {
        let mut out = Vec::with_capacity(blob.nonce.len() + blob.ciphertext.len());
        out.extend_from_slice(&blob.nonce);
        out.extend_from_slice(&blob.ciphertext);
        out
    }

    #[test]
    fn decrypt_contiguous_roundtrip_two_uniform_chunks() {
        let key = test_file_key();
        let chunk_size: u64 = 8;
        let p1 = b"AAAAAAAA";
        let p2 = b"BBBBBBBB";
        let blob1 = encrypt_chunk(&key, p1).unwrap();
        let blob2 = encrypt_chunk(&key, p2).unwrap();
        let mut body = pack_chunk(&blob1);
        body.extend(pack_chunk(&blob2));

        let path = std::env::temp_dir().join("beebeeb_test_contig_uniform.bin");
        let total = decrypt_contiguous_to_file(
            &key,
            "test-file-id",
            Unrecorded,
            &body,
            chunk_size,
            path.to_str().unwrap(),
        )
        .unwrap();
        assert_eq!(total, 16);

        let written = std::fs::read(&path).unwrap();
        assert_eq!(written, b"AAAAAAAABBBBBBBB");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn decrypt_contiguous_roundtrip_with_remainder() {
        let key = test_file_key();
        let chunk_size: u64 = 8;
        let p1 = b"AAAAAAAA"; // full chunk
        let p2 = b"BBB"; // short final chunk
        let blob1 = encrypt_chunk(&key, p1).unwrap();
        let blob2 = encrypt_chunk(&key, p2).unwrap();
        let mut body = pack_chunk(&blob1);
        body.extend(pack_chunk(&blob2));

        let path = std::env::temp_dir().join("beebeeb_test_contig_remainder.bin");
        let total = decrypt_contiguous_to_file(
            &key,
            "test-file-id",
            Unrecorded,
            &body,
            chunk_size,
            path.to_str().unwrap(),
        )
        .unwrap();
        assert_eq!(total, 11);

        let written = std::fs::read(&path).unwrap();
        assert_eq!(written, b"AAAAAAAABBB");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn decrypt_contiguous_empty_body_is_rejected() {
        // Task 1908 (justified behaviour change, same reasoning as
        // decrypt_chunks_to_file_empty_is_rejected): an empty body is never a
        // valid encrypted file, so it is total truncation, not an empty file.
        let key = test_file_key();
        let path = std::env::temp_dir().join("beebeeb_test_contig_empty.bin");
        std::fs::remove_file(&path).ok();
        let err =
            decrypt_contiguous_to_file(&key, "test-file-id", Unrecorded, &[], 8, path.to_str().unwrap()).unwrap_err();
        assert!(matches!(err, CoreError::Decryption));
        assert!(!path.exists(), "no output may appear for an empty body");
    }

    /// v2 frames for `data` split into `cs`-byte chunks, via the shared encryptor.
    fn v2_body(file_id: &str, data: &[u8], cs: u64) -> (crate::kdf::MasterKey, Vec<Vec<u8>>) {
        use crate::chunk_stream::{ChunkEncryptor, ChunkFormat};
        let mk = derive_master_key("test-password", b"test-salt-16bytes").unwrap();
        let mut enc = ChunkEncryptor::for_push_with_chunk_size(&mk, file_id, data.len() as u64, cs)
            .unwrap()
            .with_format(ChunkFormat::V2)
            .unwrap();
        let frames: Vec<Vec<u8>> = data
            .chunks(cs as usize)
            .map(|c| enc.push_chunk(c).unwrap().data)
            .collect();
        enc.finish().unwrap();
        (mk, frames)
    }

    #[test]
    fn decrypt_contiguous_v2_roundtrip_and_swap_rejected() {
        let data = b"AAAAAAAABBBBBBBBCCC";
        let (mk, frames) = v2_body("contig-v2", data, 8);
        let key = derive_file_key(&mk, b"contig-v2");
        let path = std::env::temp_dir().join("beebeeb_test_contig_v2.bin");

        let total =
            decrypt_contiguous_to_file(&key, "contig-v2", V2, &frames.concat(), 8, path.to_str().unwrap()).unwrap();
        assert_eq!(total, data.len() as u64);
        assert_eq!(std::fs::read(&path).unwrap(), data);
        std::fs::remove_file(&path).ok();

        // Equal-size chunks 0 and 1 swapped: must fail, and leave no output.
        let swapped = [frames[1].clone(), frames[0].clone(), frames[2].clone()].concat();
        let err = decrypt_contiguous_to_file(&key, "contig-v2", V2, &swapped, 8, path.to_str().unwrap()).unwrap_err();
        assert!(matches!(err, CoreError::Decryption));
        assert!(!path.exists());

        // Last chunk withheld: truncation must fail.
        let truncated = [frames[0].clone(), frames[1].clone()].concat();
        let err = decrypt_contiguous_to_file(&key, "contig-v2", V2, &truncated, 8, path.to_str().unwrap()).unwrap_err();
        assert!(matches!(err, CoreError::Decryption));
        assert!(!path.exists());
    }

    #[test]
    fn decrypt_chunks_to_file_v2_roundtrip_and_drop_rejected() {
        let data = b"AAAAAAAABBBBBBBBCCCCCCCC";
        let (mk, frames) = v2_body("pairs-v2", data, 8);
        let key = derive_file_key(&mk, b"pairs-v2");
        let pairs = |fs: &[Vec<u8>]| -> Vec<(Vec<u8>, Vec<u8>)> {
            fs.iter()
                .map(|f| (f[..NONCE_LEN].to_vec(), f[NONCE_LEN..].to_vec()))
                .collect()
        };
        let path = std::env::temp_dir().join("beebeeb_test_pairs_v2.bin");

        let total = decrypt_chunks_to_file(&key, "pairs-v2", V2, pairs(&frames), path.to_str().unwrap()).unwrap();
        assert_eq!(total, data.len() as u64);
        std::fs::remove_file(&path).ok();

        // Middle chunk dropped: must fail.
        let dropped = [frames[0].clone(), frames[2].clone()];
        let err = decrypt_chunks_to_file(&key, "pairs-v2", V2, pairs(&dropped), path.to_str().unwrap()).unwrap_err();
        assert!(matches!(err, CoreError::Decryption));
        assert!(!path.exists());
    }

    #[test]
    fn decrypt_contiguous_zero_chunk_size_rejected() {
        let key = test_file_key();
        let body = vec![0u8; NONCE_LEN + 16];
        let path = std::env::temp_dir().join("beebeeb_test_contig_zero.bin");
        let err =
            decrypt_contiguous_to_file(&key, "test-file-id", Unrecorded, &body, 0, path.to_str().unwrap()).unwrap_err();
        match err {
            CoreError::InvalidInput(_) => {}
            other => panic!("expected InvalidInput, got {other:?}"),
        }
        // Empty file may exist on err; clean up if so.
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn decrypt_contiguous_wrong_key_fails() {
        let key = test_file_key();
        let wrong_key = derive_file_key(
            &derive_master_key("different-password", b"test-salt-16bytes").unwrap(),
            b"test-file-id",
        );
        let blob = encrypt_chunk(&key, b"secrets").unwrap();
        let body = pack_chunk(&blob);
        let path = std::env::temp_dir().join("beebeeb_test_contig_wrong_key.bin");
        let err = decrypt_contiguous_to_file(&wrong_key, "test-file-id", Unrecorded, &body, 7, path.to_str().unwrap())
            .unwrap_err();
        assert!(matches!(err, CoreError::Decryption));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn decrypt_contiguous_truncated_body_rejected() {
        let key = test_file_key();
        // Body shorter than NONCE_LEN + TAG_LEN — cannot even attempt decrypt.
        let body = vec![0u8; NONCE_LEN + 8]; // 8 bytes < 16 byte tag
        let path = std::env::temp_dir().join("beebeeb_test_contig_truncated.bin");
        let err = decrypt_contiguous_to_file(&key, "test-file-id", Unrecorded, &body, 64, path.to_str().unwrap())
            .unwrap_err();
        assert!(matches!(err, CoreError::Decryption));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn decrypt_contiguous_leaves_no_partial_file_on_midstream_failure() {
        // R2: chunk 1 decrypts fine, chunk 2's tag is corrupt. The function must
        // fail AND leave no partial plaintext at output_path — otherwise an
        // existence-based cache would serve the truncated first chunk as a
        // "complete" decrypt on every subsequent open.
        let key = test_file_key();
        let chunk_size: u64 = 8;
        let blob1 = encrypt_chunk(&key, b"AAAAAAAA").unwrap();
        let blob2 = encrypt_chunk(&key, b"BBBBBBBB").unwrap();
        let mut body = pack_chunk(&blob1);
        let mut second = pack_chunk(&blob2);
        // Corrupt the GCM tag of the second chunk (flip the last byte).
        let last = second.len() - 1;
        second[last] ^= 0xFF;
        body.extend(second);

        let path = std::env::temp_dir().join("beebeeb_test_contig_partial_cleanup.bin");
        // Ensure a stale file from a prior run does not mask the assertion.
        std::fs::remove_file(&path).ok();

        let err = decrypt_contiguous_to_file(
            &key,
            "test-file-id",
            Unrecorded,
            &body,
            chunk_size,
            path.to_str().unwrap(),
        )
        .unwrap_err();
        assert!(matches!(err, CoreError::Decryption));
        assert!(
            !path.exists(),
            "no partial plaintext file may remain at output_path after a failed decrypt"
        );
        // No .tmp artifact may survive either.
        let tmp = std::env::temp_dir().join("beebeeb_test_contig_partial_cleanup.bin.tmp");
        assert!(!tmp.exists(), "no .tmp artifact may remain after a failed decrypt");
    }

    #[test]
    fn decrypt_contiguous_atomic_no_partial_visible_at_final_path() {
        // R2: on a wrong key the very first chunk fails. The final output path
        // must never have been created (atomic .tmp + rename means the final
        // path only appears on full success).
        let key = test_file_key();
        let wrong_key = derive_file_key(
            &derive_master_key("different-password", b"test-salt-16bytes").unwrap(),
            b"test-file-id",
        );
        let blob = encrypt_chunk(&key, b"secrets!").unwrap();
        let body = pack_chunk(&blob);
        let path = std::env::temp_dir().join("beebeeb_test_contig_atomic_firstfail.bin");
        std::fs::remove_file(&path).ok();

        let err = decrypt_contiguous_to_file(&wrong_key, "test-file-id", Unrecorded, &body, 8, path.to_str().unwrap())
            .unwrap_err();
        assert!(matches!(err, CoreError::Decryption));
        assert!(
            !path.exists(),
            "final output path must not exist after a first-chunk failure"
        );
    }

    // ── decrypt_names batch primitive (task 0806) ───────────────────────────

    #[test]
    fn decrypt_names_batch_matches_single_byte_for_byte() {
        let master = derive_master_key("batch-test-pw", b"batch-salt-16byte").unwrap();
        // N names encrypted under the string-UUID form (web/mobile/server form).
        let owned: Vec<(uuid::Uuid, String)> = (0..50)
            .map(|i| {
                let id = uuid::Uuid::new_v4();
                let enc = encrypt_name(&master, &id.to_string(), &format!("file_{i}.txt"), Some("text/plain")).unwrap();
                (id, enc)
            })
            .collect();
        let items: Vec<(uuid::Uuid, &str)> = owned.iter().map(|(id, e)| (*id, e.as_str())).collect();

        let batch = decrypt_names(&master, &items);
        assert_eq!(batch.len(), owned.len());
        for (i, ((id, enc), res)) in owned.iter().zip(&batch).enumerate() {
            let single = decrypt_name_with_mime(&master, &id.to_string(), enc).unwrap();
            let got = res.as_ref().expect("batch item should decrypt");
            assert_eq!(
                *got, single,
                "item {i}: batch must match single decrypt_name_with_mime byte-for-byte"
            );
            assert_eq!(got.0, format!("file_{i}.txt"));
            assert_eq!(got.1.as_deref(), Some("text/plain"));
        }
    }

    #[test]
    fn decrypt_names_isolates_partial_failure() {
        let master = derive_master_key("pw-partial", b"salt-16-bytes-ok").unwrap();
        let good_id = uuid::Uuid::new_v4();
        let good = encrypt_name(&master, &good_id.to_string(), "good.pdf", Some("application/pdf")).unwrap();
        // Valid blob but encrypted under a DIFFERENT master key → GCM tag fails.
        let other = derive_master_key("other-pw", b"other-salt-16byt").unwrap();
        let wrong_id = uuid::Uuid::new_v4();
        let wrong = encrypt_name(&other, &wrong_id.to_string(), "secret.txt", None).unwrap();
        let bad_id = uuid::Uuid::new_v4();

        let items: Vec<(uuid::Uuid, &str)> = vec![
            (good_id, good.as_str()),
            (bad_id, "{ not a valid blob"), // garbage → parse fails
            (wrong_id, wrong.as_str()),
        ];
        let res = decrypt_names(&master, &items);
        assert_eq!(res.len(), 3);
        assert_eq!(res[0].as_ref().unwrap().0, "good.pdf", "good item decrypts");
        assert!(res[1].is_err(), "garbage blob → Err for that item only");
        assert!(res[2].is_err(), "wrong-key blob → Err (GCM tag), batch not failed");
    }

    #[test]
    fn decrypt_names_empty_input() {
        let master = derive_master_key("pw-empty", b"salt-16-bytes-ok").unwrap();
        assert!(decrypt_names(&master, &[]).is_empty());
    }

    #[test]
    fn decrypt_names_handles_legacy_binary_uuid_form() {
        // A file keyed under the legacy binary-UUID form (CLI/desktop origin) must
        // still decrypt — via the second derivation attempt.
        let master = derive_master_key("pw-bin", b"salt-16-bytes-ok").unwrap();
        let id = uuid::Uuid::new_v4();
        let bin_key = derive_file_key(&master, id.as_bytes());
        let plaintext = serde_json::json!({"name": "legacy.bin", "mime_type": "application/octet-stream"}).to_string();
        let blob = encrypt_metadata(&bin_key, &plaintext).unwrap();
        let enc = serde_json::to_string(&blob).unwrap();

        let res = decrypt_names(&master, &[(id, enc.as_str())]);
        let (name, mime) = res[0]
            .as_ref()
            .expect("binary-form name should decrypt via 2nd attempt");
        assert_eq!(name, "legacy.bin");
        assert_eq!(mime.as_deref(), Some("application/octet-stream"));
    }

    /// Regression test (found 2026-07-01): `decrypt_one_name` used to
    /// re-implement a NARROWER parser than `decrypt_name_with_mime` — only the
    /// native `EncryptedBlob` direct-deserialize path, no plaintext fast-path,
    /// no legacy web base64 `{nonce,ciphertext}` format. `decrypt_one_name` now
    /// delegates to `decrypt_name_with_mime` so the two paths can never drift.
    #[test]
    fn decrypt_names_batch_handles_web_base64_format() {
        let master = derive_master_key("pw-web-format", b"salt-16-bytes-ok").unwrap();
        let id = uuid::Uuid::new_v4();
        // Web derives the file key from the UUID STRING bytes (the common case).
        let key = derive_file_key(&master, id.to_string().as_bytes());
        let plaintext = serde_json::json!({"name": "web-upload.png", "mime_type": "image/png"}).to_string();
        let blob = encrypt_metadata(&key, &plaintext).unwrap();
        // Legacy web wire format: base64 {"nonce":"...","ciphertext":"..."} — NO
        // `cipher_suite` field, unlike the native `EncryptedBlob` JSON shape.
        let web_enc = crate::metadata_wire::serialize_encrypted_metadata(&blob.nonce, &blob.ciphertext);

        // Sanity: the single-item path already handles this format correctly.
        let single = decrypt_name_with_mime(&master, &id.to_string(), &web_enc).unwrap();
        assert_eq!(single, ("web-upload.png".to_string(), Some("image/png".to_string())));

        // The batch path must match it byte-for-byte, not silently fail.
        let res = decrypt_names(&master, &[(id, web_enc.as_str())]);
        let got = res[0].as_ref().expect("batch must decrypt the web base64 blob format");
        assert_eq!(*got, single);
    }

    /// Companion regression test: a bare (non-JSON) legacy plaintext filename
    /// must also survive the batch path — the same gap this fix closes.
    #[test]
    fn decrypt_names_batch_handles_plaintext_fast_path() {
        let master = derive_master_key("pw-plaintext", b"salt-16-bytes-ok").unwrap();
        let id = uuid::Uuid::new_v4();
        let res = decrypt_names(&master, &[(id, "legacy-plain-name.txt")]);
        let (name, mime) = res[0]
            .as_ref()
            .expect("bare plaintext name must pass through the batch path");
        assert_eq!(name, "legacy-plain-name.txt");
        assert_eq!(*mime, None);
    }

    // ── decrypt_name: multi-format / multi-key consolidation (the SINGLE
    //    source of truth shared by CLI / desktop / mobile / web). ──────────────

    use crate::kdf::MasterKey;

    /// A fixed UUID file id used across the name-decryption format tests.
    const NAME_FID: &str = "3e15382b-1111-2222-3333-444455556666";

    fn name_master_key() -> MasterKey {
        derive_master_key("test-password", b"test-salt-16bytes").unwrap()
    }

    /// Encode the plaintext into the **web base64** `{nonce, ciphertext}` blob
    /// shape that older web builds produced (base64 strings, no `cipher_suite`).
    /// Mirrors `repos/web/src/lib/crypto.ts` legacy serializer.
    fn web_base64_blob(file_key: &FileKey, plaintext: &str) -> String {
        use base64::Engine as _;
        let blob = encrypt_metadata(file_key, plaintext).unwrap();
        let b64 = base64::engine::general_purpose::STANDARD;
        serde_json::json!({
            "nonce": b64.encode(&blob.nonce),
            "ciphertext": b64.encode(&blob.ciphertext),
        })
        .to_string()
    }

    /// Format 1: a bare (non-JSON) plaintext name passes straight through. This
    /// is how server-created folders / pre-encryption rows are stored.
    #[test]
    fn decrypt_name_plaintext_passthrough() {
        let mk = name_master_key();
        assert_eq!(decrypt_name(&mk, NAME_FID, "Documents").unwrap(), "Documents");
        let (n, mime) = decrypt_name_with_mime(&mk, NAME_FID, "Documents").unwrap();
        assert_eq!(n, "Documents");
        assert_eq!(mime, None);
    }

    /// Format 2 + string-UUID key: the canonical CLI/core path —
    /// `encrypt_name` produces a native EncryptedBlob with the `{name,mime}`
    /// envelope; `decrypt_name` round-trips it.
    #[test]
    fn decrypt_name_native_blob_string_uuid_roundtrip() {
        let mk = name_master_key();
        let enc = encrypt_name(&mk, NAME_FID, "report.pdf", Some("application/pdf")).unwrap();
        assert_eq!(decrypt_name(&mk, NAME_FID, &enc).unwrap(), "report.pdf");
        let (name, mime) = decrypt_name_with_mime(&mk, NAME_FID, &enc).unwrap();
        assert_eq!(name, "report.pdf");
        assert_eq!(mime.as_deref(), Some("application/pdf"));
    }

    /// Format 3 + string-UUID key: the **web app base64 blob** — the format
    /// that was failing for web-app-created files before this consolidation.
    /// The web client derives the file key from the UUID *string* bytes, so the
    /// string-UUID derivation must match.
    #[test]
    fn decrypt_name_web_base64_blob_string_uuid() {
        let mk = name_master_key();
        let fk = derive_file_key(&mk, NAME_FID.as_bytes());
        // Web encrypts the `{name,mime_type}` JSON envelope, base64-wrapped.
        let envelope = serde_json::json!({"name": "vacation.jpg", "mime_type": "image/jpeg"}).to_string();
        let blob = web_base64_blob(&fk, &envelope);
        assert!(!blob.contains("cipher_suite"), "web blob has no cipher_suite field");

        assert_eq!(decrypt_name(&mk, NAME_FID, &blob).unwrap(), "vacation.jpg");
        let (name, mime) = decrypt_name_with_mime(&mk, NAME_FID, &blob).unwrap();
        assert_eq!(name, "vacation.jpg");
        assert_eq!(mime.as_deref(), Some("image/jpeg"));
    }

    /// Format 3 web base64 blob carrying a **bare filename** plaintext (the
    /// oldest web shape, pre-`{name,mime}` envelope) — returned as-is, no MIME.
    #[test]
    fn decrypt_name_web_base64_blob_bare_filename() {
        let mk = name_master_key();
        let fk = derive_file_key(&mk, NAME_FID.as_bytes());
        let blob = web_base64_blob(&fk, "legacy-name.txt");
        assert_eq!(decrypt_name(&mk, NAME_FID, &blob).unwrap(), "legacy-name.txt");
        let (_, mime) = decrypt_name_with_mime(&mk, NAME_FID, &blob).unwrap();
        assert_eq!(mime, None);
    }

    /// Native blob encrypted under the **binary-UUID** key (legacy pre-`bb
    /// repair` CLI file): `decrypt_name` must fall back to the binary derivation.
    #[test]
    fn decrypt_name_native_blob_binary_uuid_fallback() {
        let mk = name_master_key();
        let uuid: uuid::Uuid = NAME_FID.parse().unwrap();
        let fk = derive_file_key(&mk, uuid.as_bytes());
        let envelope = serde_json::json!({"name": "old.doc", "mime_type": null}).to_string();
        let blob = encrypt_metadata(&fk, &envelope).unwrap();
        let blob_json = serde_json::to_string(&blob).unwrap();
        assert_eq!(decrypt_name(&mk, NAME_FID, &blob_json).unwrap(), "old.doc");
    }

    /// Web base64 blob encrypted under the **binary-UUID** key — both legacy
    /// dimensions at once (web shape + binary derivation).
    #[test]
    fn decrypt_name_web_base64_blob_binary_uuid_fallback() {
        let mk = name_master_key();
        let uuid: uuid::Uuid = NAME_FID.parse().unwrap();
        let fk = derive_file_key(&mk, uuid.as_bytes());
        let blob = web_base64_blob(&fk, "binary-key.png");
        assert_eq!(decrypt_name(&mk, NAME_FID, &blob).unwrap(), "binary-key.png");
    }

    /// A wrong master key fails cleanly with `Decryption` after trying every
    /// (key, format) combination — no panic, no partial result.
    #[test]
    fn decrypt_name_wrong_key_fails() {
        let mk = name_master_key();
        let enc = encrypt_name(&mk, NAME_FID, "secret.txt", None).unwrap();
        let wrong = derive_master_key("other-password", b"other-salt-16byte").unwrap();
        assert!(matches!(
            decrypt_name(&wrong, NAME_FID, &enc),
            Err(CoreError::Decryption)
        ));
    }

    /// A non-UUID file id still decrypts via the string-UUID key (binary
    /// derivation is simply skipped when the id won't parse as a UUID).
    #[test]
    fn decrypt_name_non_uuid_file_id_uses_string_key() {
        let mk = name_master_key();
        let fid = "not-a-uuid-just-a-string";
        let enc = encrypt_name(&mk, fid, "named.bin", None).unwrap();
        assert_eq!(decrypt_name(&mk, fid, &enc).unwrap(), "named.bin");
    }

    /// `decrypt_name_with_key` (the known-file-key entry point used by
    /// file-request uploads) handles both the native and web base64 blobs.
    #[test]
    fn decrypt_name_with_key_handles_both_blob_formats() {
        let mk = name_master_key();
        let fk = derive_file_key(&mk, NAME_FID.as_bytes());

        let native = encrypt_name(&mk, NAME_FID, "via-key.pdf", Some("application/pdf")).unwrap();
        assert_eq!(decrypt_name_with_key(&fk, &native).as_deref(), Some("via-key.pdf"));

        let web = web_base64_blob(&fk, &serde_json::json!({"name": "web-via-key.txt"}).to_string());
        assert_eq!(decrypt_name_with_key(&fk, &web).as_deref(), Some("web-via-key.txt"));

        // Plaintext fast path also works on the known-key entry point.
        assert_eq!(decrypt_name_with_key(&fk, "Inbox").as_deref(), Some("Inbox"));
    }

    // ── Task 1908: chunk format recorded in the encrypted name metadata ──────

    /// Decrypt the raw metadata plaintext of a native-blob `name_encrypted`.
    fn metadata_plaintext(mk: &MasterKey, file_id: &str, name_encrypted: &str) -> String {
        let fk = derive_file_key(mk, file_id.as_bytes());
        decrypt_envelope_plaintext(&fk, name_encrypted).unwrap()
    }

    /// Seal an arbitrary metadata plaintext as a native `name_encrypted`.
    fn seal_metadata(mk: &MasterKey, file_id: &str, plaintext: &str) -> String {
        let fk = derive_file_key(mk, file_id.as_bytes());
        serde_json::to_string(&encrypt_metadata(&fk, plaintext).unwrap()).unwrap()
    }

    #[test]
    fn name_metadata_records_v2_and_reads_it_back() {
        let mk = name_master_key();
        let ne = encrypt_name_with_chunk_format(&mk, NAME_FID, "a.pdf", Some("application/pdf"), V2).unwrap();
        let meta = decrypt_name_metadata(&mk, NAME_FID, &ne).unwrap();
        assert_eq!(meta.name, "a.pdf");
        assert_eq!(meta.mime_type.as_deref(), Some("application/pdf"));
        assert_eq!(meta.chunk_format, V2);
        // The existing readers still see the same name/MIME.
        assert_eq!(decrypt_name(&mk, NAME_FID, &ne).unwrap(), "a.pdf");
        // Known-key reader (share recipients) agrees.
        let fk = derive_file_key(&mk, NAME_FID.as_bytes());
        assert_eq!(decrypt_name_metadata_with_key(&fk, &ne).unwrap().chunk_format, V2);
    }

    #[test]
    fn encrypt_name_writes_no_chunk_format_field() {
        // Unrecorded = byte-for-byte the pre-1908 plaintext shape, so every
        // existing reader and every pre-1908 client sees what it always saw.
        let mk = name_master_key();
        let ne = encrypt_name(&mk, NAME_FID, "b.txt", None).unwrap();
        assert_eq!(
            metadata_plaintext(&mk, NAME_FID, &ne),
            r#"{"mime_type":null,"name":"b.txt"}"#
        );
        assert_eq!(
            decrypt_name_metadata(&mk, NAME_FID, &ne).unwrap().chunk_format,
            Unrecorded
        );
        let ne2 = encrypt_name_with_chunk_format(&mk, NAME_FID, "b.txt", None, Unrecorded).unwrap();
        assert_eq!(
            metadata_plaintext(&mk, NAME_FID, &ne2),
            r#"{"mime_type":null,"name":"b.txt"}"#
        );
        let ne3 = encrypt_name_with_chunk_format(&mk, NAME_FID, "b.txt", None, V2).unwrap();
        assert_eq!(
            metadata_plaintext(&mk, NAME_FID, &ne3),
            r#"{"chunk_format":2,"mime_type":null,"name":"b.txt"}"#
        );
    }

    #[test]
    fn name_metadata_legacy_shapes_are_unrecorded() {
        let mk = name_master_key();
        // Plaintext legacy name.
        let meta = decrypt_name_metadata(&mk, NAME_FID, "Inbox").unwrap();
        assert_eq!((meta.name.as_str(), meta.chunk_format), ("Inbox", Unrecorded));
        // Bare-filename plaintext inside an envelope.
        let ne = seal_metadata(&mk, NAME_FID, "old-name.txt");
        let meta = decrypt_name_metadata(&mk, NAME_FID, &ne).unwrap();
        assert_eq!((meta.name.as_str(), meta.chunk_format), ("old-name.txt", Unrecorded));
    }

    #[test]
    fn name_metadata_unknown_chunk_format_is_an_error_not_detection() {
        let mk = name_master_key();
        for bad in [
            r#"{"name":"x","chunk_format":1}"#,
            r#"{"name":"x","chunk_format":0}"#,
            r#"{"name":"x","chunk_format":3}"#,
            r#"{"name":"x","chunk_format":"2"}"#,
            r#"{"name":"x","chunk_format":null}"#,
        ] {
            let ne = seal_metadata(&mk, NAME_FID, bad);
            assert!(decrypt_name_metadata(&mk, NAME_FID, &ne).is_err(), "{bad}");
        }
        let ne = seal_metadata(&mk, NAME_FID, r#"{"name":"x","chunk_format":2}"#);
        assert_eq!(decrypt_name_metadata(&mk, NAME_FID, &ne).unwrap().chunk_format, V2);
    }

    #[test]
    fn name_metadata_wrong_key_fails() {
        let mk = name_master_key();
        let ne = encrypt_name_with_chunk_format(&mk, NAME_FID, "a", None, V2).unwrap();
        let other = derive_master_key("other-password", b"test-salt-16bytes").unwrap();
        assert!(decrypt_name_metadata(&other, NAME_FID, &ne).is_err());
    }
}
