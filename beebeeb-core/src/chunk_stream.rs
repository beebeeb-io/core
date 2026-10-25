//! Streaming chunk encryption / decryption — the one primitive all clients share.
//!
//! This module exists so that the CLI, desktop, mobile (UniFFI) and web (WASM)
//! clients converge on a **single** chunk-encryption loop instead of each
//! re-implementing it. Having one code path means the wire format and the
//! chunking behaviour cannot drift between clients.
//!
//! Two directions, one generic-free public type each:
//!
//! - [`ChunkEncryptor`] turns a plaintext source into a sequence of
//!   `nonce(12) || ciphertext || tag(16)` frames.
//! - [`ChunkDecryptor`] turns those frames back into plaintext.
//!
//! Each comes in two flavours:
//!
//! - **Pull** (`from_reader`): the primitive owns a boxed `Read` and pulls one
//!   chunk at a time into a reused buffer. Used by native clients (cli, desktop,
//!   mobile-from-file) where streaming I/O is available.
//! - **Push** (`for_push` / `for_push_with_chunk_size` / `push_chunk` /
//!   `push_frame`): the caller slices the data and feeds it chunk-by-chunk.
//!   Used by single-threaded WASM where the worker holds the bytes already.
//!
//! ## Key handling
//!
//! The per-file key is derived **once** in the constructor via
//! [`derive_file_key`] and held as a [`FileKey`], which is `ZeroizeOnDrop`, so
//! it is wiped when the encryptor/decryptor drops. The reused plaintext read
//! buffer is wrapped in [`Zeroizing`] so residual plaintext is wiped too.
//!
//! ## Wire format
//!
//! Every frame is `nonce(12) || ciphertext || tag(16)` with a fresh random
//! nonce per chunk. The layout and sizes are the same in both formats; they
//! differ only in the AES-GCM associated data (task 1908):
//!
//! - **v1 (legacy)**: no AAD — byte-for-byte [`crate::encrypt::encrypt_chunk_raw`].
//!   Frames are not bound to a position: a server could reorder, duplicate,
//!   drop or truncate them undetected. Still readable for existing files.
//! - **v2**: sealed under a chunk subkey `HKDF-SHA256(file_key,
//!   "beebeeb/chunk/v2/key")` (no other blob type uses it), with AAD =
//!   `"beebeeb/chunk/v2" || u32_be(len(file_id)) || file_id || version_id(12) ||
//!   u32_be(index) || u8(is_last)` (STREAM construction). `version_id` is the
//!   random nonce of the upload's frame 0, so every upload (every version of a
//!   file id) has its own. See [`chunk_aad_v2`] and the crate-private
//!   `StreamOpener` for the binding and the decrypt rules.
//!
//! [`ChunkEncryptor`] writes [`WRITE_FORMAT`] (still v1 during the read-only
//! rollout phase). [`ChunkDecryptor`] reads both, but only under an
//! [`ExpectedChunkFormat`] that the caller MUST take from the file's
//! authenticated (encrypted) metadata via
//! [`crate::encrypt::decrypt_file_metadata`]: a file whose metadata records v2
//! opens ONLY as v2. Detection from frame 0 is used only for files whose
//! metadata records no format (written before the v2 write switch).
//!
//! A resumed upload asks [`ChunkEncryptor::resume_policy`] whether it may
//! continue its old server session: a v2 upload never may (see
//! [`SessionResume`]; restart = abandon the session or let its lease expire,
//! then re-init — never the old session on a 409).
//!
//! A replace / new version of an existing file builds its writer with
//! [`ChunkEncryptor::with_recorded_pin`] (the pin from the file's encrypted
//! metadata): a v2-pinned file is written as v2 even while [`WRITE_FORMAT`] is
//! v1, because the server keeps the v2 metadata on replace.
//!
//! ## Sync, reactor-agnostic
//!
//! Core stays synchronous — no tokio. [`ChunkEncryptor`] and [`ChunkDecryptor`]
//! are `Send`, so a caller can move one into a blocking thread (e.g. the CLI's
//! `spawn_blocking`) and keep AES off the async reactor.

use std::io::Read;

use zeroize::Zeroizing;

use beebeeb_types::{ChunkPlan, ChunkProfile, ChunkStrategy, STORAGE_FORMAT_VERSION_V2, plan_chunks};

use crate::CoreError;
use crate::encrypt::{NONCE_LEN, TAG_LEN, open_raw_with_aad, random_nonce, seal_raw_with_aad, seal_raw_with_nonce};
use crate::kdf::{FileKey, MasterKey, derive_file_key};

/// Per-chunk AEAD overhead on the wire: `nonce(12) + tag(16)` = 28 bytes. The ONE
/// definition: `direct_transfer` sizes chunk lengths from it.
pub const CHUNK_OVERHEAD: u64 = (NONCE_LEN + TAG_LEN) as u64;

/// Hard upper bound on an explicit (server-dictated or concurrency-derived)
/// `chunk_size_bytes`. Matches the top of the `ChunkProfile` ladder (256 MiB,
/// the most permissive profile cap), so every legitimate plan is well under it.
///
/// This is a resource-exhaustion guard: the push/pull `*_with_chunk_size`
/// constructors size their read buffer / data slicing to this value, so an
/// unbounded value supplied by a compromised or misconfigured server would
/// drive a multi-GB allocation → client OOM (WASM tab kill / mobile crash)
/// before a single byte is processed. Reject above the cap instead.
pub const MAX_CHUNK_SIZE: u64 = 256 * 1024 * 1024;

// ─── Chunk format v2: position binding (task 1908) ──────────────────────────
//
// v1 frames are AES-256-GCM with NO associated data: every frame of a file is
// sealed independently under the one per-file key, so a server can reorder,
// duplicate, drop or truncate frames within a file undetected.
//
// v2 keeps the frame layout byte-for-byte (`nonce(12) || ct || tag(16)`, same
// sizes, so the server, the upload protocol and every size computation are
// unchanged) and authenticates the frame's position as GCM associated data,
// STREAM-style (Hoang–Reyhanitabar–Rogaway–Vizár; as in age / Tink):
//
//   AAD = "beebeeb/chunk/v2"            16 bytes, domain tag incl. version
//      || u32_be(len(file_id))          length prefix, keeps the AAD injective
//      || file_id                       the exact bytes fed to derive_file_key
//      || version_id                    12 bytes: the nonce of THIS upload's frame 0
//      || u32_be(chunk_index)           0-based
//      || u8(is_last)                   1 on the final chunk, else 0
//
// Key: v2 frames are sealed under a dedicated chunk subkey
// HKDF-SHA256(ikm = file_key, info = "beebeeb/chunk/v2/key"), never under the
// raw file key that also seals the encrypted name/MIME and thumbnails.
//
// Version id (review round 2, P1-2): a replace re-uploads under the SAME file
// id and therefore the same file key, so file id + index alone let a server
// mix frames of two versions. The version id is the random 96-bit nonce of
// the upload's frame 0: client-generated, unique per upload, transmitted in
// frame 0 itself and authenticated by every frame's tag (frame 0's own AAD
// contains it too). A frame from another version carries another version id
// in its AAD and fails. It is deliberately NOT stored in the file metadata:
// the server keeps one metadata blob per file, not per version, so a
// metadata-held id could not open older versions, and a pre-1908 client that
// rewrites the metadata (rename) would drop it and make the file unreadable.
//
// The AAD is never transmitted: the decryptor rebuilds it from what it already
// knows (the file id it asked for, frame 0's nonce, the index it expects next).
// So it cannot be "stripped": opening a v2 frame with the empty v1 AAD (or
// under the raw file key) fails the tag.

/// Domain-separation tag (and format version) at the start of every v2 AAD.
pub const CHUNK_AAD_DOMAIN_V2: &[u8; 16] = b"beebeeb/chunk/v2";

/// HKDF-SHA256 `info` of the v2 chunk subkey (ikm = the per-file key).
pub const CHUNK_KEY_INFO_V2: &[u8; 20] = b"beebeeb/chunk/v2/key";

/// Length of a v2 version id (= a frame nonce).
pub const VERSION_ID_LEN: usize = NONCE_LEN;

/// Derive the v2 chunk subkey from a per-file key. Domain-separated from every
/// other use of the file key (name/MIME metadata, thumbnails, v1 frames), so no
/// blob sealed for another purpose can ever open as a v2 frame.
pub(crate) fn derive_chunk_key_v2(file_key: &FileKey) -> FileKey {
    crate::kdf::derive_file_subkey(file_key, CHUNK_KEY_INFO_V2)
}

/// The on-the-wire chunk format of a file. The frame layout is identical; the
/// formats differ only in the AES-GCM associated data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChunkFormat {
    /// Legacy: no associated data, no position binding. Readable forever for
    /// files written before task 1908; no longer written by default.
    V1Legacy,
    /// Position-bound: sealed under the chunk subkey
    /// `HKDF-SHA256(file_key, "beebeeb/chunk/v2/key")` with AAD = domain tag ||
    /// len(file id) || file id || version id (frame 0's nonce, one per upload) ||
    /// chunk index || last flag. See [`chunk_aad_v2`].
    V2,
}

impl ChunkFormat {
    /// Stable numeric code for the FFI/WASM boundary and encrypted metadata.
    pub fn as_u8(self) -> u8 {
        match self {
            ChunkFormat::V1Legacy => 1,
            ChunkFormat::V2 => 2,
        }
    }

    /// Inverse of [`as_u8`](Self::as_u8). Unknown codes are an error, never a
    /// silent fallback to v1.
    pub fn from_u8(code: u8) -> Result<Self, CoreError> {
        match code {
            1 => Ok(ChunkFormat::V1Legacy),
            2 => Ok(ChunkFormat::V2),
            other => Err(CoreError::InvalidInput(format!("unknown chunk format {other}"))),
        }
    }
}

/// The format [`ChunkEncryptor`] writes for every new file.
///
/// **Read-only rollout phase (task 1908 review round 2, P2-1): still v1.** A
/// client on this core reads v2 everywhere but keeps writing v1, because a v2
/// file is unreadable by every client whose read path is not yet on this core
/// (web `decrypt_chunk` loop, mobile video streamer / FileProvider, older
/// builds). Flipping this to [`ChunkFormat::V2`] is a separate, gated core
/// release once every client's read path is live — see task 1908.
pub const WRITE_FORMAT: ChunkFormat = ChunkFormat::V1Legacy;

/// What a file's **authenticated** (encrypted) metadata says about its chunk
/// format — the mandatory input of every file-content reader (review round 2,
/// P1-1).
///
/// The format is NOT decided from frame 0 alone for new files: every file also
/// has no-AAD blobs under its per-file key (the encrypted name/MIME, the
/// thumbnail), and a server could serve one of those as "frame 0" of a v2 file
/// to make it look like a complete one-frame v1 file. So a reader must say what
/// the metadata promised:
///
/// - [`V2`](Self::V2): the encrypted metadata records `"chunk_format": 2`. Only
///   v2 frames are accepted — no detection, no v1 fallback.
/// - [`Unrecorded`](Self::Unrecorded): the metadata records no format — a file
///   written before task 1908 (or before the v2 write switch), or metadata
///   rewritten by a pre-1908 client. The format is detected from frame 0 (v2
///   tried first, then v1). This is the only path on which a downgrade is still
///   possible, and only for such files — the residual risk of keeping v1 files
///   readable.
///
/// Read it with [`crate::encrypt::decrypt_file_metadata`] (or
/// `decrypt_file_metadata_with_key`), never from a server field. The file
/// reader refuses a plaintext (non-JSON) name: a plaintext name carries no
/// pin, so accepting one for a file would let a server re-enable detection
/// (review round 3, P1-B).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExpectedChunkFormat {
    /// Metadata records no chunk format: detect from frame 0 (legacy files).
    Unrecorded,
    /// Metadata records v2: accept only v2 frames.
    V2,
}

impl ExpectedChunkFormat {
    /// Stable code for the FFI/WASM boundary and the metadata JSON:
    /// 0 = unrecorded (detect), 2 = v2.
    pub fn as_u8(self) -> u8 {
        match self {
            ExpectedChunkFormat::Unrecorded => 0,
            ExpectedChunkFormat::V2 => 2,
        }
    }

    /// Inverse of [`as_u8`](Self::as_u8). Any other code is an error, never a
    /// silent fallback to detection.
    pub fn from_u8(code: u8) -> Result<Self, CoreError> {
        match code {
            0 => Ok(ExpectedChunkFormat::Unrecorded),
            2 => Ok(ExpectedChunkFormat::V2),
            other => Err(CoreError::InvalidInput(format!(
                "unknown expected chunk format {other} (0 = unrecorded, 2 = v2)"
            ))),
        }
    }

    /// What a writer records in the metadata for a file whose content it wrote
    /// in `format`: `V2` for a v2 upload, `Unrecorded` for a v1 upload.
    pub fn recorded_for(format: ChunkFormat) -> Self {
        match format {
            ChunkFormat::V1Legacy => ExpectedChunkFormat::Unrecorded,
            ChunkFormat::V2 => ExpectedChunkFormat::V2,
        }
    }
}

/// What a client must do when it resumes an interrupted upload whose server
/// session already holds some frames (task 1908 review round 3, P1-A).
///
/// The server keeps the frames it already stored and skips re-PUTs of those
/// indices (`{skipped: true}`). That is harmless for v1 (every frame stands
/// alone), but a v2 upload's frames all bind ONE version id — the random nonce
/// of that encryptor's frame 0. A resumed upload builds a new encryptor, which
/// has a new version id, so continuing the old session would store frames of
/// two version ids side by side: a file that completes and can never be read.
/// Re-creating the old version id is not an option either: it IS a nonce, and
/// re-sealing chunk 0 under it would reuse a nonce.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SessionResume {
    /// Keep the session and re-PUT from chunk 0 (the server skips the frames it
    /// holds). Only for a v1 session resumed by a v1 writer.
    ContinueSession,
    /// Abandon the session (never PUT to it again) and upload from chunk 0
    /// into a FRESH upload session with this new encryptor.
    ///
    /// The restart path, precisely (review round 4, P2-3; server
    /// `routes/uploads.rs` init, `routes/files.rs` abandon): the server refuses
    /// a new init for a file whose upload session still holds a live lease
    /// (409 "upload is already in progress for this file"). So the client
    /// first calls `POST /api/v1/files/{id}/upload/abandon` (a replace reverts
    /// to the previous version; a never-completed first upload is deleted), or
    /// waits until the session's lease expires (default 3600 s; an init after
    /// expiry takes the session over inline), then inits again with the same
    /// file id and uploads from chunk 0. On a 409 from that init it abandons /
    /// waits and retries; it NEVER falls back to PUTting into the old session,
    /// because that stores frames of two version ids: a file that completes
    /// and never opens.
    RestartWithFreshSession,
}

impl SessionResume {
    /// Stable lowercase token for the WASM boundary.
    pub fn as_str(self) -> &'static str {
        match self {
            SessionResume::ContinueSession => "continue",
            SessionResume::RestartWithFreshSession => "restart",
        }
    }
}

/// The resume rule — see [`SessionResume`].
///
/// - `stored`: the chunk format of the frames the session already holds, as the
///   client recorded it when it opened the session (persist
///   [`ChunkEncryptor::format`] next to the session id). `None` = the resume
///   record does not say (written before this rule existed): restart.
/// - `writing`: the format of the encryptor that would continue the upload.
///
/// Only `(Some(V1Legacy), V1Legacy)` may continue; everything else restarts.
pub fn resume_policy(stored: Option<ChunkFormat>, writing: ChunkFormat) -> SessionResume {
    match (stored, writing) {
        (Some(ChunkFormat::V1Legacy), ChunkFormat::V1Legacy) => SessionResume::ContinueSession,
        _ => SessionResume::RestartWithFreshSession,
    }
}

/// The chunk format a writer must use for an upload to a file whose encrypted
/// metadata records `pin` (task 1908 review round 4, I-1).
///
/// - [`ExpectedChunkFormat::V2`] → [`ChunkFormat::V2`], ALWAYS, also during the
///   read-only phase. The server keeps a file's `name_encrypted` on replace, so
///   a new version of a v2-pinned file is read under the v2 pin: written as v1
///   it would complete and never open.
/// - [`ExpectedChunkFormat::Unrecorded`] → [`WRITE_FORMAT`] (a new file id, or
///   a file whose metadata records nothing; detection reads either format).
///
/// Used by [`ChunkEncryptor::with_recorded_pin`] and, for the metadata seal,
/// by `encrypt::encrypt_name_with_chunk_format` / `encrypt::encrypt_thumbnail_for`,
/// so content, name and thumbnail of one upload always follow ONE rule.
pub const fn chunk_format_for_pin(pin: ExpectedChunkFormat) -> ChunkFormat {
    match pin {
        ExpectedChunkFormat::V2 => ChunkFormat::V2,
        ExpectedChunkFormat::Unrecorded => WRITE_FORMAT,
    }
}

/// Build the v2 associated data for one chunk. Public so the layout can be
/// pinned by a known-answer test and inspected by reviewers; clients never need
/// to call it (seal/open happen in core).
pub fn chunk_aad_v2(file_id: &[u8], version_id: &[u8; VERSION_ID_LEN], index: u32, is_last: bool) -> Vec<u8> {
    let mut aad = Vec::with_capacity(CHUNK_AAD_DOMAIN_V2.len() + 4 + file_id.len() + VERSION_ID_LEN + 4 + 1);
    aad.extend_from_slice(CHUNK_AAD_DOMAIN_V2);
    // File ids are UUID strings (36 bytes); anything near u32::MAX is absurd,
    // and saturating keeps this infallible without making the encoding ambiguous
    // for any id that could actually exist.
    aad.extend_from_slice(&u32::try_from(file_id.len()).unwrap_or(u32::MAX).to_be_bytes());
    aad.extend_from_slice(file_id);
    aad.extend_from_slice(version_id);
    aad.extend_from_slice(&index.to_be_bytes());
    aad.push(u8::from(is_last));
    aad
}

/// The version id a v2 frame 0 carries: its nonce. Only meaningful once that
/// frame has authenticated (its tag covers the nonce and the AAD that repeats it).
fn version_id_of(frame: &[u8]) -> Option<[u8; VERSION_ID_LEN]> {
    frame.get(..VERSION_ID_LEN)?.try_into().ok()
}

/// **Stateless, random-access open** of one chunk frame at a known position.
///
/// For callers that seek (video streaming, range previews) instead of reading
/// the file front to back. The caller supplies what it *expects*: the chunk
/// `index` it requested and `is_last = (index == chunk_count - 1)`. A server
/// that serves a different chunk, or lies about `chunk_count` (and therefore
/// about which chunk is last), fails the tag — so even an unauthenticated
/// chunk count cannot be used to truncate or extend a v2 file.
///
/// `format` and `version_id` must be established from authenticated data:
/// - `format`: [`ChunkFormat::V2`] when the encrypted metadata records v2
///   ([`ExpectedChunkFormat::V2`]); for a file whose metadata records nothing,
///   the [`ChunkDecryptor::format`] of a decryptor that opened chunk 0.
/// - `version_id`: [`ChunkDecryptor::version_id`] after chunk 0 opened (or the
///   first 12 bytes of chunk 0: if a server lies about them, only frames of the
///   one version they belong to can open, so the reader sees that version
///   consistently or nothing). Must be 12 bytes for v2; ignored for v1.
///
/// For [`ChunkFormat::V1Legacy`] the position arguments are ignored (v1 binds
/// nothing).
pub fn open_chunk(
    file_key: &FileKey,
    file_id: &str,
    version_id: &[u8],
    index: u32,
    is_last: bool,
    format: ChunkFormat,
    frame: &[u8],
) -> Result<Vec<u8>, CoreError> {
    match format {
        ChunkFormat::V1Legacy => open_raw_with_aad(file_key, frame, &[]),
        ChunkFormat::V2 => {
            let version_id: &[u8; VERSION_ID_LEN] = version_id.try_into().map_err(|_| {
                CoreError::InvalidInput(format!("version_id must be {VERSION_ID_LEN} bytes for a v2 file"))
            })?;
            let chunk_key = derive_chunk_key_v2(file_key);
            open_raw_with_aad(
                &chunk_key,
                frame,
                &chunk_aad_v2(file_id.as_bytes(), version_id, index, is_last),
            )
        }
    }
}

/// Sequential STREAM-open state, shared by [`ChunkDecryptor`] (which owns its
/// key) and the legacy borrowed-key disk helpers in `encrypt` / `file_encrypt`
/// (which do not).
///
/// Rules, in order:
/// 1. Nothing may follow the frame that authenticated as last.
/// 2. Frame `i` is opened ONLY at index `i` (the next expected index).
/// 3. The file's format: with [`ExpectedChunkFormat::V2`] (the authenticated
///    metadata records v2) only v2 frames open — there is no detection and no
///    v1 fallback, so a same-key no-AAD blob (name, thumbnail) served as frame 0
///    fails. With [`ExpectedChunkFormat::Unrecorded`] (legacy metadata) frame 0
///    decides: v2 if it authenticates as a v2 frame 0, else v1 if it
///    authenticates with no AAD. Either way the result is locked: a v2 file can
///    never continue as v1 and vice versa.
/// 4. v2: frame 0's nonce is the upload's version id; every later frame must
///    authenticate under that same version id (no mixing of two uploads of one
///    file id).
/// 5. v2: [`finish`](Self::finish) fails unless the last frame was seen —
///    truncation detection. v1 has no last marker; it cannot detect truncation
///    (the legacy weakness this task fixes for new files).
pub(crate) struct StreamOpener {
    file_id: Vec<u8>,
    /// v2 chunk subkey, derived once from the per-file key at construction.
    chunk_key: FileKey,
    expected: ExpectedChunkFormat,
    next_index: u32,
    format: Option<ChunkFormat>,
    version_id: Option<[u8; VERSION_ID_LEN]>,
    seen_last: bool,
}

impl StreamOpener {
    /// `file_key` is the per-file key every later [`open_next`](Self::open_next)
    /// call passes (v1 frames open under it; v2 under its derived subkey).
    pub(crate) fn new(file_key: &FileKey, file_id: &str, expected: ExpectedChunkFormat) -> Self {
        Self {
            file_id: file_id.as_bytes().to_vec(),
            chunk_key: derive_chunk_key_v2(file_key),
            expected,
            next_index: 0,
            format: None,
            version_id: None,
            seen_last: false,
        }
    }

    pub(crate) fn format(&self) -> Option<ChunkFormat> {
        self.format
    }

    pub(crate) fn version_id(&self) -> Option<[u8; VERSION_ID_LEN]> {
        self.version_id
    }

    pub(crate) fn frames_opened(&self) -> u32 {
        self.next_index
    }

    /// Try the v2 AAD at the expected index under `version_id`: `is_last =
    /// false` first (every frame but one), then `is_last = true`. Returns
    /// `(plaintext, is_last)`.
    fn try_v2(&self, version_id: &[u8; VERSION_ID_LEN], frame: &[u8]) -> Option<(Vec<u8>, bool)> {
        for is_last in [false, true] {
            let aad = chunk_aad_v2(&self.file_id, version_id, self.next_index, is_last);
            if let Ok(pt) = open_raw_with_aad(&self.chunk_key, frame, &aad) {
                return Some((pt, is_last));
            }
        }
        None
    }

    /// Open frame 0 as a v2 frame: its own nonce is the version id it claims.
    fn try_v2_frame0(&self, frame: &[u8]) -> Option<(Vec<u8>, bool, [u8; VERSION_ID_LEN])> {
        let vid = version_id_of(frame)?;
        self.try_v2(&vid, frame).map(|(pt, last)| (pt, last, vid))
    }

    /// Open the next frame in sequence. Returns its (authenticated) index.
    pub(crate) fn open_next(&mut self, key: &FileKey, frame: &[u8]) -> Result<DecryptedChunk, CoreError> {
        if self.seen_last {
            // Rule 1: a frame after the authenticated last chunk.
            return Err(CoreError::Decryption);
        }
        if frame.len() < NONCE_LEN + TAG_LEN {
            return Err(CoreError::Decryption);
        }
        let index = self.next_index;
        let next = index.checked_add(1).ok_or(CoreError::Decryption)?;

        let (data, format, is_last) = match (self.format, self.version_id) {
            // Locked v2: every later frame under the version id of frame 0.
            (Some(ChunkFormat::V2), Some(vid)) => {
                let (pt, last) = self.try_v2(&vid, frame).ok_or(CoreError::Decryption)?;
                (pt, ChunkFormat::V2, last)
            }
            (Some(ChunkFormat::V2), None) => return Err(CoreError::Decryption), // unreachable by construction
            (Some(ChunkFormat::V1Legacy), _) => (open_raw_with_aad(key, frame, &[])?, ChunkFormat::V1Legacy, false),
            // Frame 0.
            (None, _) => match self.expected {
                // Rule 3: metadata says v2 — v2 or nothing. A no-AAD blob under
                // the file key (name, thumbnail, a v1 frame) never gets here as v1.
                ExpectedChunkFormat::V2 => {
                    let (pt, last, vid) = self.try_v2_frame0(frame).ok_or(CoreError::Decryption)?;
                    self.version_id = Some(vid);
                    (pt, ChunkFormat::V2, last)
                }
                // Legacy metadata: detect. Unambiguous between v1 and v2 FRAMES
                // (a v2 frame never opens without its AAD and subkey, a v1 frame
                // never opens as v2) — but NOT against other no-AAD blobs under
                // the same key, which is why metadata that records v2 must use
                // the arm above.
                ExpectedChunkFormat::Unrecorded => {
                    if let Some((pt, last, vid)) = self.try_v2_frame0(frame) {
                        self.version_id = Some(vid);
                        (pt, ChunkFormat::V2, last)
                    } else {
                        (open_raw_with_aad(key, frame, &[])?, ChunkFormat::V1Legacy, false)
                    }
                }
            },
        };

        self.format = Some(format);
        self.seen_last = is_last;
        self.next_index = next;
        Ok(DecryptedChunk { index, data })
    }

    /// End-of-stream check. Errors if no frame was opened at all (every file,
    /// even an empty one, has one frame) or if a v2 stream ended before its
    /// last chunk (truncation).
    pub(crate) fn finish(&self) -> Result<ChunkDecryptorSummary, CoreError> {
        match self.format {
            None => Err(CoreError::Decryption),
            Some(ChunkFormat::V2) if !self.seen_last => Err(CoreError::Decryption),
            Some(format) => Ok(ChunkDecryptorSummary {
                chunk_count: self.next_index,
                format,
            }),
        }
    }
}

/// Summary returned by [`ChunkDecryptor::finish`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkDecryptorSummary {
    /// Number of frames opened.
    pub chunk_count: u32,
    /// The file's format, as authenticated by its frames.
    pub format: ChunkFormat,
}

/// One encrypted chunk produced by [`ChunkEncryptor`].
///
/// `data` is the full wire frame: `nonce(12) || ciphertext || tag(16)`.
#[derive(Debug, Clone)]
pub struct EncryptedChunk {
    /// Zero-based chunk index, ascending.
    pub index: u32,
    /// `nonce(12) || ciphertext || tag(16)`.
    pub data: Vec<u8>,
}

/// One decrypted chunk produced by [`ChunkDecryptor`].
#[derive(Debug, Clone)]
pub struct DecryptedChunk {
    /// Zero-based chunk index, ascending.
    pub index: u32,
    /// Plaintext bytes for this chunk.
    pub data: Vec<u8>,
}

/// Summary returned by [`ChunkEncryptor::finish`] after the integrity guard
/// passes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkEncryptorSummary {
    /// Number of chunks emitted (equals the planned `chunk_count`).
    pub chunk_count: u32,
    /// Total plaintext bytes consumed across all chunks.
    pub total_plaintext: u64,
    /// Total ciphertext bytes emitted (plaintext + `28 * chunk_count`).
    pub total_ciphertext: u64,
    /// Plaintext bytes per chunk (the last chunk may be smaller).
    pub chunk_size_bytes: u64,
}

/// Erases the concrete reader type so [`ChunkEncryptor`] is generic-free and
/// therefore FFI-safe (it can cross UniFFI without a `<R>` parameter).
enum Source {
    /// Native streaming: the primitive owns the reader and pulls chunks.
    Pull(Box<dyn Read + Send>),
    /// The caller feeds chunks via [`ChunkEncryptor::push_chunk`].
    Push,
}

/// Streaming chunk encryptor — see the [module docs](self).
pub struct ChunkEncryptor {
    /// Derived once; `ZeroizeOnDrop` wipes it when this struct drops.
    file_key: FileKey,
    /// The plan this encryptor follows (chunk size + count).
    plan: ChunkPlan,
    /// `plan.chunk_count`, validated to fit in `u32`.
    chunk_count: u32,
    /// `plan.chunk_size_bytes`, validated to fit in `usize` (pull buffer size).
    chunk_size: usize,
    /// Index of the next chunk to emit.
    next_index: u32,
    /// How many chunks have actually been emitted.
    emitted_chunks: u32,
    /// Running total of ciphertext bytes emitted.
    running_ciphertext: u64,
    /// Running total of plaintext bytes consumed.
    running_plaintext: u64,
    /// Where plaintext comes from.
    source: Source,
    /// Reused plaintext read buffer (pull mode only); zeroized on drop.
    buf: Zeroizing<Vec<u8>>,
    /// Format of every frame this encryptor writes ([`WRITE_FORMAT`] unless a
    /// test overrides it before the first chunk).
    format: ChunkFormat,
    /// The exact bytes the file key was derived from (bound into the v2 AAD).
    file_id: Vec<u8>,
    /// v2 chunk subkey (`HKDF(file_key, "beebeeb/chunk/v2/key")`); zeroized on drop.
    chunk_key: FileKey,
    /// v2: the nonce of frame 0 = this upload's version id (set when frame 0 is sealed).
    version_id: Option<[u8; VERSION_ID_LEN]>,
    /// Known-answer vectors only ([`Self::with_vector_nonces`]): the v2 frame
    /// nonces to use, in order. Never present in a shipped client build.
    #[cfg(any(test, feature = "test-support"))]
    vector_nonces: std::collections::VecDeque<[u8; NONCE_LEN]>,
}

impl ChunkEncryptor {
    /// **Pull** constructor: the encryptor owns `reader` and pulls one chunk at
    /// a time. The plan is derived from `file_size` + `profile`.
    ///
    /// Returns `Err` if the resulting `chunk_count` does not fit in `u32` or the
    /// chunk size does not fit in `usize`.
    pub fn from_reader<R: Read + Send + 'static>(
        mk: &MasterKey,
        file_id: &str,
        file_size: u64,
        profile: ChunkProfile,
        reader: R,
    ) -> Result<Self, CoreError> {
        let plan = plan_chunks(file_size, profile);
        Self::new(mk, file_id, plan, Source::Pull(Box::new(reader)))
    }

    /// **Push** constructor: the caller slices the data and calls
    /// [`push_chunk`](Self::push_chunk). The plan is derived from `file_size` +
    /// `profile`.
    pub fn for_push(mk: &MasterKey, file_id: &str, file_size: u64, profile: ChunkProfile) -> Result<Self, CoreError> {
        let plan = plan_chunks(file_size, profile);
        Self::new(mk, file_id, plan, Source::Push)
    }

    /// **Push** constructor with an explicit, server-dictated chunk size.
    ///
    /// Closes the plan-divergence gap when a v2 server overrides `chunk_size` at
    /// init: the caller passes the exact size the server expects rather than
    /// relying on the client ladder. Returns `Err` if `chunk_size_bytes == 0`,
    /// `chunk_size_bytes` exceeds [`MAX_CHUNK_SIZE`] (resource-exhaustion guard
    /// against a hostile/misconfigured server value), the derived `chunk_count`
    /// does not fit in `u32`, or the size does not fit in `usize`.
    pub fn for_push_with_chunk_size(
        mk: &MasterKey,
        file_id: &str,
        file_size: u64,
        chunk_size_bytes: u64,
    ) -> Result<Self, CoreError> {
        check_explicit_chunk_size(chunk_size_bytes)?;
        let chunk_count = if file_size == 0 {
            1
        } else {
            file_size.div_ceil(chunk_size_bytes)
        };
        let plan = ChunkPlan {
            file_size_bytes: file_size,
            chunk_size_bytes,
            chunk_count,
            strategy: ChunkStrategy::Capped {
                max_chunk_size_bytes: chunk_size_bytes,
            },
            storage_format_version: STORAGE_FORMAT_VERSION_V2,
        };
        Self::new(mk, file_id, plan, Source::Push)
    }

    /// **Pull** constructor with an explicit chunk size — the reader-form analog
    /// of [`for_push_with_chunk_size`](Self::for_push_with_chunk_size). Lets a
    /// caller apply a concurrency-aware chunk size (e.g.
    /// `beebeeb_types::plan_chunks_concurrent`) instead of the profile's static
    /// ladder. Returns `Err` if `chunk_size_bytes == 0`, `chunk_size_bytes`
    /// exceeds [`MAX_CHUNK_SIZE`] (resource-exhaustion guard), the derived
    /// `chunk_count` does not fit in `u32`, or the size does not fit in `usize`.
    pub fn from_reader_with_chunk_size<R: Read + Send + 'static>(
        mk: &MasterKey,
        file_id: &str,
        file_size: u64,
        chunk_size_bytes: u64,
        reader: R,
    ) -> Result<Self, CoreError> {
        check_explicit_chunk_size(chunk_size_bytes)?;
        let chunk_count = if file_size == 0 {
            1
        } else {
            file_size.div_ceil(chunk_size_bytes)
        };
        let plan = ChunkPlan {
            file_size_bytes: file_size,
            chunk_size_bytes,
            chunk_count,
            strategy: ChunkStrategy::Capped {
                max_chunk_size_bytes: chunk_size_bytes,
            },
            storage_format_version: STORAGE_FORMAT_VERSION_V2,
        };
        Self::new(mk, file_id, plan, Source::Pull(Box::new(reader)))
    }

    /// Shared constructor body: validates the plan, derives the key once, sizes
    /// the read buffer (pull only).
    fn new(mk: &MasterKey, file_id: &str, plan: ChunkPlan, source: Source) -> Result<Self, CoreError> {
        let chunk_count: u32 = plan.chunk_count.try_into().map_err(|_| {
            CoreError::InvalidInput(format!(
                "chunk_count {} exceeds u32::MAX; file too large for this chunk size",
                plan.chunk_count
            ))
        })?;
        let chunk_size: usize = plan.chunk_size_bytes.try_into().map_err(|_| {
            CoreError::InvalidInput(format!(
                "chunk_size_bytes {} exceeds usize range",
                plan.chunk_size_bytes
            ))
        })?;

        let file_key = derive_file_key(mk, file_id.as_bytes());
        let chunk_key = derive_chunk_key_v2(&file_key);

        // Only the pull path reads into a buffer; push callers own their bytes.
        let buf = match source {
            Source::Pull(_) => Zeroizing::new(vec![0u8; chunk_size]),
            Source::Push => Zeroizing::new(Vec::new()),
        };

        Ok(Self {
            file_key,
            plan,
            chunk_count,
            chunk_size,
            next_index: 0,
            emitted_chunks: 0,
            running_ciphertext: 0,
            running_plaintext: 0,
            source,
            buf,
            format: WRITE_FORMAT,
            file_id: file_id.as_bytes().to_vec(),
            chunk_key,
            version_id: None,
            #[cfg(any(test, feature = "test-support"))]
            vector_nonces: std::collections::VecDeque::new(),
        })
    }

    /// Seal the v2 frames with these FIXED nonces, in order — for the published
    /// known-answer vectors only (`test-vectors/vectors.json`, task 1943).
    /// Compiled only under `cfg(test)` or the `test-support` feature (like
    /// [`Self::with_format`]), never in a shipped client: a nonce reused under
    /// one key breaks AES-GCM. Frame 0's nonce is the version id, as always.
    /// Only before the first chunk, only on a v2 writer (v1 frames draw their
    /// own nonce), exactly one nonce per planned frame, and no nonce twice.
    #[cfg(any(test, feature = "test-support"))]
    pub fn with_vector_nonces(mut self, nonces: Vec<[u8; NONCE_LEN]>) -> Result<Self, CoreError> {
        if self.emitted_chunks != 0 {
            return Err(CoreError::InvalidInput(
                "with_vector_nonces must be called before the first chunk".into(),
            ));
        }
        if self.format != ChunkFormat::V2 {
            return Err(CoreError::InvalidInput(
                "with_vector_nonces needs a v2 writer (set the format first)".into(),
            ));
        }
        if nonces.len() as u64 != self.chunk_count as u64 {
            return Err(CoreError::InvalidInput(format!(
                "with_vector_nonces needs one nonce per frame ({} frames, {} nonces)",
                self.chunk_count,
                nonces.len()
            )));
        }
        let distinct: std::collections::HashSet<_> = nonces.iter().collect();
        if distinct.len() != nonces.len() {
            return Err(CoreError::InvalidInput(
                "with_vector_nonces got the same nonce twice".into(),
            ));
        }
        self.vector_nonces = nonces.into();
        Ok(self)
    }

    /// Override the written format — **tests only** (v1 fixtures, v2 attack
    /// tests independent of [`WRITE_FORMAT`]). Compiled only under `cfg(test)`
    /// or the `test-support` feature, which the workspace's binding crates
    /// enable in `[dev-dependencies]` alone, so no shipped client can opt into
    /// v2 writes ahead of the gated [`WRITE_FORMAT`] switch. Only before the
    /// first chunk, so a file can never mix formats.
    #[cfg(any(test, feature = "test-support"))]
    pub fn with_format(mut self, format: ChunkFormat) -> Result<Self, CoreError> {
        if self.emitted_chunks != 0 {
            return Err(CoreError::InvalidInput(
                "with_format must be called before the first chunk".into(),
            ));
        }
        self.format = format;
        Ok(self)
    }

    /// The format this encryptor writes. Clients record
    /// [`ExpectedChunkFormat::recorded_for`] of it in the encrypted file
    /// metadata at upload ([`crate::encrypt::encrypt_name_with_chunk_format`]),
    /// so readers can pin it.
    pub fn format(&self) -> ChunkFormat {
        self.format
    }

    /// Write in the format the file's **recorded pin** requires
    /// ([`chunk_format_for_pin`]) — task 1908 review round 4, I-1. Every
    /// replace / new version of an existing file MUST build its encryptor this
    /// way, with `pin` = the `chunk_format` that
    /// [`crate::encrypt::decrypt_file_metadata`] returned for that file (never
    /// a server field). A v2 pin forces v2 frames even while [`WRITE_FORMAT`]
    /// is still v1; `Unrecorded` keeps [`WRITE_FORMAT`].
    ///
    /// **New-file rule (lead ruling 2026-10-17, round 5).** Pass `V2` ONLY
    /// with the pin read from an EXISTING file's authenticated metadata. A
    /// brand-new file id has no pin: use the plain constructor, which writes
    /// [`WRITE_FORMAT`], and record [`ExpectedChunkFormat::recorded_for`] of
    /// [`format`](Self::format). Never pass `V2` for a new file — before the
    /// switch that would create a v2 file that clients not yet on this core
    /// cannot read. Core cannot tell the two cases apart; it is a client rule
    /// (adoption checklist in `CLAUDE.md`). Only before the first chunk, so a
    /// file can never mix formats. Pair it with
    /// `encrypt::encrypt_thumbnail_for(.., pin)`,
    /// `encrypt::encrypt_note_for(.., pin)` and, when the name is rewritten,
    /// `encrypt_name_with_chunk_format(.., pin)`.
    ///
    /// ```
    /// use beebeeb_core::chunk_stream::{ChunkDecryptor, ChunkEncryptor, ExpectedChunkFormat, WRITE_FORMAT};
    /// use beebeeb_core::encrypt::{decrypt_file_metadata, encrypt_name_with_chunk_format};
    /// use beebeeb_core::kdf::MasterKey;
    ///
    /// let mk = MasterKey::from_bytes([7u8; 32]);
    /// let id = "3f1c0e7a-0000-4000-8000-000000000001";
    /// let v1 = b"first version".to_vec();
    ///
    /// // NEW file: no pin exists. Plain constructor (= WRITE_FORMAT), then
    /// // record what the encryptor actually wrote. Never `with_recorded_pin(V2)`.
    /// let mut enc = ChunkEncryptor::for_push_with_chunk_size(&mk, id, v1.len() as u64, 16).unwrap();
    /// assert_eq!(enc.format(), WRITE_FORMAT);
    /// let frames: Vec<Vec<u8>> = v1.chunks(16).map(|c| enc.push_chunk(c).unwrap().data).collect();
    /// let recorded = ExpectedChunkFormat::recorded_for(enc.format());
    /// enc.finish().unwrap();
    /// let name_encrypted = encrypt_name_with_chunk_format(&mk, id, "a.txt", None, recorded).unwrap();
    ///
    /// // REPLACE (new version of that file): the pin comes from the file's own
    /// // authenticated metadata (never a server field), and the writer obeys it.
    /// let pin = decrypt_file_metadata(&mk, id, &name_encrypted).unwrap().chunk_format;
    /// let v2 = b"second version".to_vec();
    /// let mut enc = ChunkEncryptor::for_push_with_chunk_size(&mk, id, v2.len() as u64, 16)
    ///     .unwrap()
    ///     .with_recorded_pin(pin)
    ///     .unwrap();
    /// let frames2: Vec<Vec<u8>> = v2.chunks(16).map(|c| enc.push_chunk(c).unwrap().data).collect();
    /// enc.finish().unwrap();
    ///
    /// // Both versions read back under the one metadata blob the server keeps.
    /// for (frames, want) in [(frames, v1), (frames2, v2)] {
    ///     let mut dec = ChunkDecryptor::for_push(&mk, id, pin);
    ///     let mut out = Vec::new();
    ///     for f in &frames {
    ///         out.extend_from_slice(&dec.push_frame(f).unwrap().data);
    ///     }
    ///     dec.finish().unwrap();
    ///     assert_eq!(out, want);
    /// }
    /// ```
    pub fn with_recorded_pin(mut self, pin: ExpectedChunkFormat) -> Result<Self, CoreError> {
        if self.emitted_chunks != 0 {
            return Err(CoreError::InvalidInput(
                "with_recorded_pin must be called before the first chunk".into(),
            ));
        }
        self.format = chunk_format_for_pin(pin);
        Ok(self)
    }

    /// Whether this (new) encryptor may continue an interrupted upload session
    /// whose stored frames are in format `stored` — [`resume_policy`]`(stored,
    /// self.format())`. For a v2 encryptor the answer is always
    /// [`SessionResume::RestartWithFreshSession`]: its version id differs from
    /// the one the stored frames bind.
    pub fn resume_policy(&self, stored: Option<ChunkFormat>) -> SessionResume {
        resume_policy(stored, self.format)
    }

    /// The chunk plan this encryptor follows.
    pub fn chunk_plan(&self) -> ChunkPlan {
        self.plan
    }

    /// Expected total ciphertext: `file_size + 28 * chunk_count`.
    pub fn expected_total_ciphertext(&self) -> u64 {
        self.plan.file_size_bytes + CHUNK_OVERHEAD * self.chunk_count as u64
    }

    /// How many chunks have been emitted so far.
    pub fn chunks_emitted(&self) -> u32 {
        self.emitted_chunks
    }

    /// The single crypto point shared by pull and push. Encrypts `plaintext`
    /// and advances the running counters.
    fn encrypt_next(&mut self, plaintext: &[u8]) -> Result<EncryptedChunk, CoreError> {
        let index = self.next_index;
        // The plan fixes the count up front, so the last chunk is known when it
        // is sealed (STREAM's last flag). Both callers check
        // `next_index < chunk_count` first, so `index + 1` cannot overflow.
        let is_last = index + 1 == self.chunk_count;
        let data = match self.format {
            ChunkFormat::V1Legacy => {
                // Vector nonces are v2-only; a format switched back to v1
                // after they were set must not silently drop them.
                #[cfg(any(test, feature = "test-support"))]
                if !self.vector_nonces.is_empty() {
                    return Err(CoreError::InvalidInput("vector nonces are for v2 frames only".into()));
                }
                seal_raw_with_aad(&self.file_key, plaintext, &[])?
            }
            ChunkFormat::V2 => {
                #[cfg(any(test, feature = "test-support"))]
                let nonce = self.vector_nonces.pop_front().unwrap_or_else(random_nonce);
                #[cfg(not(any(test, feature = "test-support")))]
                let nonce = random_nonce();
                // Frame 0's nonce becomes this upload's version id; every frame
                // (frame 0 included) binds it.
                let version_id = *self.version_id.get_or_insert(nonce);
                let aad = chunk_aad_v2(&self.file_id, &version_id, index, is_last);
                seal_raw_with_nonce(&self.chunk_key, &nonce, plaintext, &aad)?
            }
        };
        self.next_index += 1;
        self.emitted_chunks += 1;
        self.running_plaintext += plaintext.len() as u64;
        self.running_ciphertext += data.len() as u64;
        Ok(EncryptedChunk { index, data })
    }

    /// **Pull** the next chunk. Plan-driven: emits exactly `chunk_count` chunks
    /// and then returns `Ok(None)` once. If the underlying file is shorter than
    /// declared, the trailing chunks are simply shorter (or empty) — the
    /// mismatch is caught by [`finish`](Self::finish).
    ///
    /// Returns `Err` if called on a push-mode encryptor.
    pub fn next_chunk(&mut self) -> Result<Option<EncryptedChunk>, CoreError> {
        if self.next_index >= self.chunk_count {
            return Ok(None);
        }

        // Move the reusable buffer out so the reader borrow (`self.source`) and
        // the encryptor-state borrow (`encrypt_next` takes `&mut self`) do not
        // overlap. Moving a `Vec` preserves its capacity, so there is no
        // per-chunk reallocation.
        let mut buf = std::mem::take(&mut self.buf);
        let read_result = match &mut self.source {
            Source::Pull(reader) => read_exact_or_eof(reader.as_mut(), &mut buf[..]),
            Source::Push => Err(CoreError::InvalidInput(
                "next_chunk called on a push-mode ChunkEncryptor; use push_chunk".into(),
            )),
        };
        let result = match read_result {
            Ok(n) => self.encrypt_next(&buf[..n]).map(Some),
            Err(e) => Err(e),
        };
        self.buf = buf; // restore (capacity retained for reuse)
        result
    }

    /// **Push** one chunk of plaintext (the caller owns the slicing).
    ///
    /// Returns `Err` if more chunks are pushed than the plan allows.
    pub fn push_chunk(&mut self, plaintext: &[u8]) -> Result<EncryptedChunk, CoreError> {
        if self.next_index >= self.chunk_count {
            return Err(CoreError::InvalidInput(format!(
                "push_chunk exceeds plan: {} chunks already emitted, plan has {}",
                self.emitted_chunks, self.chunk_count
            )));
        }
        self.encrypt_next(plaintext)
    }

    /// Consume the encryptor and return a summary, after an integrity guard.
    ///
    /// The guard requires that **all** planned chunks were emitted and that the
    /// running ciphertext total equals [`expected_total_ciphertext`]. This
    /// **detects a source that shrank** mid-stream (short reads → fewer
    /// ciphertext bytes than expected).
    ///
    /// It **cannot** detect a source that *grew*: the loop is plan-driven and
    /// stops at the original `chunk_count`, so when `file_size` is an exact
    /// multiple of the chunk size and the file grew, the extra bytes are never
    /// read and the totals still match. Callers that need to defend against a
    /// concurrent same-size+grow replace must re-stat before init and rely on
    /// content-hash reconciliation on the next run. See [`expected_total_ciphertext`].
    ///
    /// [`expected_total_ciphertext`]: Self::expected_total_ciphertext
    pub fn finish(self) -> Result<ChunkEncryptorSummary, CoreError> {
        let expected = self.expected_total_ciphertext();
        if self.emitted_chunks != self.chunk_count {
            return Err(CoreError::InvalidInput(format!(
                "incomplete encryption: emitted {} of {} planned chunks (source shrank?)",
                self.emitted_chunks, self.chunk_count
            )));
        }
        if self.running_ciphertext != expected {
            return Err(CoreError::InvalidInput(format!(
                "ciphertext total mismatch: emitted {} bytes, expected {} (source shrank?)",
                self.running_ciphertext, expected
            )));
        }
        Ok(ChunkEncryptorSummary {
            chunk_count: self.chunk_count,
            total_plaintext: self.running_plaintext,
            total_ciphertext: self.running_ciphertext,
            chunk_size_bytes: self.plan.chunk_size_bytes,
        })
    }
}

impl std::fmt::Debug for ChunkEncryptor {
    /// Deliberately omits the file key, source, and buffer — never log key
    /// material or plaintext.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChunkEncryptor")
            .field("format", &self.format)
            .field("chunk_count", &self.chunk_count)
            .field("chunk_size", &self.chunk_size)
            .field("next_index", &self.next_index)
            .field("emitted_chunks", &self.emitted_chunks)
            .field("running_plaintext", &self.running_plaintext)
            .field("running_ciphertext", &self.running_ciphertext)
            .finish_non_exhaustive()
    }
}

/// Erases the concrete reader type so [`ChunkDecryptor`] is generic-free /
/// FFI-safe.
enum DecSource {
    /// Native streaming: the primitive owns the reader and pulls frames.
    Pull(Box<dyn Read + Send>),
    /// The caller feeds frames via [`ChunkDecryptor::push_frame`].
    Push,
}

/// Streaming chunk decryptor — the symmetric counterpart to [`ChunkEncryptor`].
///
/// Reads v2 (position-bound) and v1 (legacy) files. Every constructor takes
/// the [`ExpectedChunkFormat`] from the file's authenticated metadata: `V2`
/// accepts only v2 frames; `Unrecorded` (legacy metadata) lets frame 0 decide.
/// The format is then locked for the rest of the stream; see `StreamOpener`
/// for the full rules. In v2 every frame must be the next index in order and
/// from the same upload (version) as frame 0, nothing may follow the last
/// chunk, and the stream must reach its last chunk: call
/// [`finish`](Self::finish) (push form) or read to `Ok(None)` (pull form,
/// which runs the same check at EOF).
pub struct ChunkDecryptor {
    /// Derived once; `ZeroizeOnDrop` wipes it when this struct drops.
    file_key: FileKey,
    /// Position/format state (STREAM open).
    opener: StreamOpener,
    /// Where ciphertext frames come from.
    source: DecSource,
    /// Reused encrypted-frame read buffer (pull mode only).
    buf: Zeroizing<Vec<u8>>,
}

impl ChunkDecryptor {
    /// **Pull** constructor: the decryptor owns `reader` and reads one wire
    /// frame at a time. `chunk_size_bytes` is the **plaintext** chunk size used
    /// at encryption — the read frame size is `nonce(12) + chunk_size + tag(16)`.
    ///
    /// Returns `Err` if `chunk_size_bytes == 0` or the frame size overflows.
    pub fn from_reader<R: Read + Send + 'static>(
        mk: &MasterKey,
        file_id: &str,
        expected: ExpectedChunkFormat,
        chunk_size_bytes: u64,
        reader: R,
    ) -> Result<Self, CoreError> {
        if chunk_size_bytes == 0 {
            return Err(CoreError::InvalidInput("chunk_size_bytes must be positive".into()));
        }
        let chunk_size: usize = chunk_size_bytes
            .try_into()
            .map_err(|_| CoreError::InvalidInput(format!("chunk_size_bytes {chunk_size_bytes} exceeds usize range")))?;
        let frame_len = NONCE_LEN
            .checked_add(chunk_size)
            .and_then(|v| v.checked_add(TAG_LEN))
            .ok_or_else(|| CoreError::InvalidInput("chunk_size_bytes overflows frame length".into()))?;

        let file_key = derive_file_key(mk, file_id.as_bytes());
        let opener = StreamOpener::new(&file_key, file_id, expected);
        Ok(Self {
            file_key,
            opener,
            source: DecSource::Pull(Box::new(reader)),
            buf: Zeroizing::new(vec![0u8; frame_len]),
        })
    }

    /// **Push** constructor: the caller feeds wire frames via
    /// [`push_frame`](Self::push_frame). Infallible — no buffer is allocated and
    /// no chunk size is needed (each frame is self-describing).
    pub fn for_push(mk: &MasterKey, file_id: &str, expected: ExpectedChunkFormat) -> Self {
        Self::for_push_with_file_key(derive_file_key(mk, file_id.as_bytes()), file_id, expected)
    }

    /// **Push** constructor from an already-derived/unwrapped [`FileKey`] — for
    /// callers that hold the file key but not the owner's master key (shared-link
    /// and share recipients, file-request content keys). `file_id` must be the
    /// id the file was uploaded under (it is bound into every v2 frame).
    pub fn for_push_with_file_key(file_key: FileKey, file_id: &str, expected: ExpectedChunkFormat) -> Self {
        let opener = StreamOpener::new(&file_key, file_id, expected);
        Self {
            file_key,
            opener,
            source: DecSource::Push,
            buf: Zeroizing::new(Vec::new()),
        }
    }

    /// The file's format once frame 0 has been opened (`None` before).
    pub fn format(&self) -> Option<ChunkFormat> {
        self.opener.format()
    }

    /// v2: the version id (frame 0's nonce) once frame 0 has authenticated —
    /// what a seeking reader passes to [`open_chunk`]. `None` before frame 0
    /// and for v1 files.
    pub fn version_id(&self) -> Option<[u8; VERSION_ID_LEN]> {
        self.opener.version_id()
    }

    /// How many frames have been opened so far.
    pub fn chunks_decrypted(&self) -> u32 {
        self.opener.frames_opened()
    }

    /// **Pull** the next decrypted chunk. Reads up to one full frame. At EOF
    /// returns `Ok(None)` only if the stream is complete (v2: the last chunk
    /// was seen; v1: at least one frame) — a truncated v2 body is `Err`. A
    /// trailing partial frame (the last chunk) is decrypted normally; a frame
    /// shorter than `nonce + tag` is rejected; any bytes after the v2 last
    /// chunk are rejected.
    ///
    /// Returns `Err` if called on a push-mode decryptor.
    pub fn next_chunk(&mut self) -> Result<Option<DecryptedChunk>, CoreError> {
        let mut buf = std::mem::take(&mut self.buf);
        let read_result = match &mut self.source {
            DecSource::Pull(reader) => read_exact_or_eof(reader.as_mut(), &mut buf[..]),
            DecSource::Push => Err(CoreError::InvalidInput(
                "next_chunk called on a push-mode ChunkDecryptor; use push_frame".into(),
            )),
        };
        let result = match read_result {
            // EOF: legitimate only if the stream is complete.
            Ok(0) => self.opener.finish().map(|_| None),
            Ok(n) => self.opener.open_next(&self.file_key, &buf[..n]).map(Some),
            Err(e) => Err(e),
        };
        self.buf = buf; // restore (capacity retained for reuse)
        result
    }

    /// **Push** one wire frame (`nonce || ciphertext || tag`) for decryption.
    /// Frames must be pushed in order, starting at chunk 0.
    pub fn push_frame(&mut self, frame: &[u8]) -> Result<DecryptedChunk, CoreError> {
        self.opener.open_next(&self.file_key, frame)
    }

    /// End-of-stream check (push form; the pull form runs it at EOF). Errors if
    /// no frame was pushed, or if a v2 file ended before its last chunk
    /// (truncation). Callers MUST treat an `Err` here as a failed download and
    /// discard the plaintext they wrote.
    pub fn finish(self) -> Result<ChunkDecryptorSummary, CoreError> {
        self.opener.finish()
    }
}

impl std::fmt::Debug for ChunkDecryptor {
    /// Deliberately omits the file key, source, and buffer — never log key
    /// material or plaintext.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChunkDecryptor")
            .field("next_index", &self.opener.frames_opened())
            .field("format", &self.opener.format())
            .finish_non_exhaustive()
    }
}

/// Validate an explicit, caller/server-supplied `chunk_size_bytes` before it is
/// used to size any allocation. Rejects `0` (no progress) and anything above
/// [`MAX_CHUNK_SIZE`] (resource-exhaustion / OOM guard). Single source of truth
/// for the two `*_with_chunk_size` constructors.
fn check_explicit_chunk_size(chunk_size_bytes: u64) -> Result<(), CoreError> {
    if chunk_size_bytes == 0 {
        return Err(CoreError::InvalidInput("chunk_size_bytes must be positive".into()));
    }
    if chunk_size_bytes > MAX_CHUNK_SIZE {
        return Err(CoreError::InvalidInput(format!(
            "chunk_size_bytes {chunk_size_bytes} exceeds MAX_CHUNK_SIZE {MAX_CHUNK_SIZE} \
             (rejected to prevent client OOM from an oversized server-dictated value)"
        )));
    }
    Ok(())
}

/// Read exactly `buf.len()` bytes, or fewer if EOF is reached first.
/// Returns the number of bytes actually read. `Interrupted` errors retry.
///
/// `pub(crate)` and defined once here: the single source of truth for the
/// `chunk_stream` / `file_encrypt` streaming read loop.
pub(crate) fn read_exact_or_eof(reader: &mut dyn Read, buf: &mut [u8]) -> Result<usize, CoreError> {
    let mut total = 0;
    while total < buf.len() {
        match reader.read(&mut buf[total..]) {
            Ok(0) => break, // EOF
            Ok(n) => total += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(CoreError::Io(format!("read input: {e}"))),
        }
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encrypt::decrypt_chunk_raw;
    use crate::kdf::derive_master_key;
    use std::io::Cursor;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

    const MIB: usize = 1024 * 1024;

    fn mk() -> MasterKey {
        derive_master_key("test-password", b"test-salt-16bytes").unwrap()
    }

    /// Deterministic, non-trivial test data.
    fn pattern(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8).collect()
    }

    /// Encrypt every chunk of `data` via the pull path and return the frames.
    fn encrypt_all(
        master: &MasterKey,
        file_id: &str,
        data: &[u8],
        profile: ChunkProfile,
    ) -> (Vec<EncryptedChunk>, ChunkEncryptorSummary) {
        let mut enc =
            ChunkEncryptor::from_reader(master, file_id, data.len() as u64, profile, Cursor::new(data.to_vec()))
                .unwrap();
        let mut frames = Vec::new();
        while let Some(c) = enc.next_chunk().unwrap() {
            frames.push(c);
        }
        let summary = enc.finish().unwrap();
        (frames, summary)
    }

    /// Decrypt a sequence of frames via the push decryptor and concatenate.
    fn decrypt_frames(master: &MasterKey, file_id: &str, frames: &[EncryptedChunk]) -> Vec<u8> {
        let mut dec = ChunkDecryptor::for_push(master, file_id, exp());
        let mut out = Vec::new();
        for f in frames {
            out.extend_from_slice(&dec.push_frame(&f.data).unwrap().data);
        }
        out
    }

    /// What the metadata records for a file written by the default encryptor.
    fn exp() -> ExpectedChunkFormat {
        ExpectedChunkFormat::recorded_for(WRITE_FORMAT)
    }

    fn assert_send<T: Send>() {}

    #[test]
    fn types_are_send() {
        // Compile-time guard: both primitives must be movable into a blocking
        // thread (the CLI's spawn_blocking).
        assert_send::<ChunkEncryptor>();
        assert_send::<ChunkDecryptor>();
    }

    #[test]
    fn roundtrip_single_chunk_equality_not_byte_equality() {
        let m = mk();
        let data = pattern(4096);
        let (frames, summary) = encrypt_all(&m, "f1", &data, ChunkProfile::Desktop);
        assert_eq!(frames.len(), 1);
        assert_eq!(summary.chunk_count, 1);

        // Ciphertext frame must not equal the plaintext.
        assert_ne!(frames[0].data, data);
        // ...but it must decrypt back to it.
        let recovered = decrypt_frames(&m, "f1", &frames);
        assert_eq!(recovered, data);

        // Re-encrypting the same bytes yields different ciphertext (random nonce)
        // but the same plaintext on decrypt.
        let (frames2, _) = encrypt_all(&m, "f1", &data, ChunkProfile::Desktop);
        assert_ne!(frames2[0].data, frames[0].data);
        assert_eq!(decrypt_frames(&m, "f1", &frames2), data);
    }

    #[test]
    fn empty_file_one_chunk_total_28_decrypts_empty() {
        let m = mk();
        let (frames, summary) = encrypt_all(&m, "empty", &[], ChunkProfile::Desktop);
        assert_eq!(frames.len(), 1, "empty file still produces one chunk");
        assert_eq!(frames[0].data.len(), NONCE_LEN + TAG_LEN); // 28
        assert_eq!(summary.chunk_count, 1);
        assert_eq!(summary.total_plaintext, 0);
        assert_eq!(summary.total_ciphertext, 28);

        let recovered = decrypt_frames(&m, "empty", &frames);
        assert!(recovered.is_empty());
    }

    #[test]
    fn expected_total_ciphertext_for_empty_is_28() {
        let m = mk();
        let enc = ChunkEncryptor::from_reader(&m, "e", 0, ChunkProfile::Desktop, Cursor::new(Vec::new())).unwrap();
        assert_eq!(enc.expected_total_ciphertext(), 28);
    }

    #[test]
    fn sub_chunk_roundtrip() {
        let m = mk();
        let data = pattern(100); // far below the 4 MiB minimum chunk
        let (frames, summary) = encrypt_all(&m, "small", &data, ChunkProfile::Desktop);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].data.len(), 100 + 28);
        assert_eq!(summary.total_plaintext, 100);
        assert_eq!(decrypt_frames(&m, "small", &frames), data);
    }

    #[test]
    fn multi_chunk_roundtrip() {
        let m = mk();
        // 9 MiB with Desktop (<=64 MiB -> 4 MiB chunk) => 3 chunks: 4 + 4 + 1.
        let data = pattern(9 * MIB);
        let (frames, summary) = encrypt_all(&m, "multi", &data, ChunkProfile::Desktop);
        assert_eq!(frames.len(), 3);
        assert_eq!(summary.chunk_count, 3);
        assert_eq!(frames[0].data.len(), 4 * MIB + 28);
        assert_eq!(frames[1].data.len(), 4 * MIB + 28);
        assert_eq!(frames[2].data.len(), MIB + 28);
        assert_eq!(summary.total_plaintext, 9 * MIB as u64);
        assert_eq!(decrypt_frames(&m, "multi", &frames), data);
    }

    #[test]
    fn exact_multiple_has_no_trailing_empty_chunk() {
        let m = mk();
        // 8 MiB == exactly two 4 MiB chunks; must NOT emit a third empty chunk.
        let data = pattern(8 * MIB);
        let (frames, summary) = encrypt_all(&m, "exact", &data, ChunkProfile::Desktop);
        assert_eq!(frames.len(), 2);
        assert_eq!(summary.chunk_count, 2);
        assert_eq!(frames[1].data.len(), 4 * MIB + 28);
        assert_eq!(decrypt_frames(&m, "exact", &frames), data);
    }

    #[test]
    fn wrong_key_decrypt_errors_no_panic() {
        let m = mk();
        let data = pattern(2048);
        let (frames, _) = encrypt_all(&m, "secret", &data, ChunkProfile::Desktop);

        // Wrong master key.
        let wrong = derive_master_key("different-password", b"different-salt-16").unwrap();
        let mut dec = ChunkDecryptor::for_push(&wrong, "secret", exp());
        assert!(matches!(dec.push_frame(&frames[0].data), Err(CoreError::Decryption)));

        // Right master key, wrong file_id.
        let mut dec2 = ChunkDecryptor::for_push(&m, "other-file", exp());
        assert!(matches!(dec2.push_frame(&frames[0].data), Err(CoreError::Decryption)));
    }

    #[test]
    fn push_form_equals_pull_form() {
        let m = mk();
        let data = pattern(9 * MIB);

        // Pull
        let (pull_frames, _) = encrypt_all(&m, "pp", &data, ChunkProfile::Desktop);

        // Push, caller slicing by the plan's chunk size.
        let mut push = ChunkEncryptor::for_push(&m, "pp", data.len() as u64, ChunkProfile::Desktop).unwrap();
        let chunk_size = push.chunk_plan().chunk_size_bytes as usize;
        let mut push_frames = Vec::new();
        for slice in data.chunks(chunk_size) {
            push_frames.push(push.push_chunk(slice).unwrap());
        }
        let push_summary = push.finish().unwrap();

        // Same count and same per-chunk sizes (deterministic: pt + 28).
        assert_eq!(pull_frames.len(), push_frames.len());
        for (a, b) in pull_frames.iter().zip(&push_frames) {
            assert_eq!(a.index, b.index);
            assert_eq!(a.data.len(), b.data.len());
        }
        // Both decrypt to the original plaintext.
        assert_eq!(decrypt_frames(&m, "pp", &pull_frames), data);
        assert_eq!(decrypt_frames(&m, "pp", &push_frames), data);
        assert_eq!(push_summary.chunk_count, 3);
        assert_eq!(push_summary.total_plaintext, 9 * MIB as u64);
    }

    #[test]
    fn finish_ok_on_complete() {
        let m = mk();
        let data = pattern(5 * MIB);
        let mut enc = ChunkEncryptor::from_reader(
            &m,
            "ok",
            data.len() as u64,
            ChunkProfile::Desktop,
            Cursor::new(data.clone()),
        )
        .unwrap();
        while enc.next_chunk().unwrap().is_some() {}
        let summary = enc.finish().unwrap();
        assert_eq!(summary.total_plaintext, 5 * MIB as u64);
        assert_eq!(
            summary.total_ciphertext,
            5 * MIB as u64 + 28 * summary.chunk_count as u64
        );
    }

    #[test]
    fn finish_err_on_short_read_shrink() {
        let m = mk();
        // Declare 9 MiB (3 chunks) but the reader only has 4 MiB of data: the
        // file shrank between stat and read. finish() must reject it.
        let declared = 9 * MIB as u64;
        let actual = pattern(4 * MIB);
        let mut enc =
            ChunkEncryptor::from_reader(&m, "shrink", declared, ChunkProfile::Desktop, Cursor::new(actual)).unwrap();
        // Pull all planned chunks (later ones come back empty).
        let mut emitted = 0;
        while enc.next_chunk().unwrap().is_some() {
            emitted += 1;
        }
        assert_eq!(emitted, 3);
        let err = enc.finish().unwrap_err();
        assert!(matches!(err, CoreError::InvalidInput(_)));
    }

    #[test]
    fn finish_err_when_caller_stops_early() {
        let m = mk();
        let data = pattern(9 * MIB);
        let mut enc =
            ChunkEncryptor::from_reader(&m, "early", data.len() as u64, ChunkProfile::Desktop, Cursor::new(data))
                .unwrap();
        // Only pull the first of three planned chunks.
        let _ = enc.next_chunk().unwrap().unwrap();
        let err = enc.finish().unwrap_err();
        assert!(matches!(err, CoreError::InvalidInput(_)));
    }

    #[test]
    fn grown_source_is_not_detected_documented_limitation() {
        // DOCUMENTED LIMITATION: when file_size is an exact multiple of the
        // chunk size, a source that grew after stat is NOT detected — the
        // plan-driven loop stops at the original chunk_count and the extra
        // bytes are silently ignored. finish() returns Ok.
        let m = mk();
        let declared = 8 * MIB as u64; // exactly two 4 MiB chunks
        let bigger = pattern(10 * MIB); // grew by 2 MiB after stat
        let mut enc =
            ChunkEncryptor::from_reader(&m, "grow", declared, ChunkProfile::Desktop, Cursor::new(bigger.clone()))
                .unwrap();
        let mut frames = Vec::new();
        while let Some(c) = enc.next_chunk().unwrap() {
            frames.push(c);
        }
        // Only the two declared chunks were emitted; the growth was ignored.
        assert_eq!(frames.len(), 2);
        let summary = enc
            .finish()
            .expect("growth on an exact-multiple file is NOT caught by finish()");
        assert_eq!(summary.total_plaintext, 8 * MIB as u64);

        // The recovered plaintext is the first 8 MiB only — the appended 2 MiB
        // is lost. This is the residual edge documented on finish().
        let recovered = decrypt_frames(&m, "grow", &frames);
        assert_eq!(recovered, bigger[..8 * MIB]);
    }

    #[test]
    fn u32_chunk_count_guard_rejects() {
        let m = mk();
        // u64::MAX / 1-byte chunks overflows u32 chunk_count.
        let err = ChunkEncryptor::for_push_with_chunk_size(&m, "huge", u64::MAX, 1).unwrap_err();
        assert!(matches!(err, CoreError::InvalidInput(_)));

        // Same overflow via the profile ladder (256 MiB chunks at u64::MAX size).
        let err2 = ChunkEncryptor::for_push(&m, "huge", u64::MAX, ChunkProfile::Desktop).unwrap_err();
        assert!(matches!(err2, CoreError::InvalidInput(_)));
    }

    #[test]
    fn for_push_with_chunk_size_rejects_above_max() {
        // R3: a hostile/misconfigured server returning an oversized chunk size
        // must be rejected before it can drive a multi-GB allocation.
        let m = mk();
        let too_big = MAX_CHUNK_SIZE + 1;
        let err = ChunkEncryptor::for_push_with_chunk_size(&m, "oom", 10 * MIB as u64, too_big).unwrap_err();
        assert!(matches!(err, CoreError::InvalidInput(_)));

        // The exact cap is accepted (boundary is inclusive).
        let ok = ChunkEncryptor::for_push_with_chunk_size(&m, "edge", 10 * MIB as u64, MAX_CHUNK_SIZE);
        assert!(ok.is_ok());
    }

    #[test]
    fn from_reader_with_chunk_size_rejects_above_max() {
        // R3: same cap on the pull-form override constructor.
        let m = mk();
        let too_big = MAX_CHUNK_SIZE + 1;
        let err =
            ChunkEncryptor::from_reader_with_chunk_size(&m, "oom2", 10 * MIB as u64, too_big, Cursor::new(Vec::new()))
                .unwrap_err();
        assert!(matches!(err, CoreError::InvalidInput(_)));
    }

    #[test]
    fn for_push_with_chunk_size_honors_override() {
        let m = mk();
        let data = pattern(40);
        let mut enc = ChunkEncryptor::for_push_with_chunk_size(&m, "ovr", 40, 16).unwrap();
        let plan = enc.chunk_plan();
        assert_eq!(plan.chunk_size_bytes, 16);
        assert_eq!(plan.chunk_count, 3); // 16 + 16 + 8

        let mut frames = Vec::new();
        for slice in data.chunks(16) {
            frames.push(enc.push_chunk(slice).unwrap());
        }
        assert_eq!(frames[0].data.len(), 16 + 28);
        assert_eq!(frames[1].data.len(), 16 + 28);
        assert_eq!(frames[2].data.len(), 8 + 28);

        let summary = enc.finish().unwrap();
        assert_eq!(summary.chunk_count, 3);
        assert_eq!(summary.total_plaintext, 40);
        assert_eq!(summary.chunk_size_bytes, 16);

        assert_eq!(decrypt_frames(&m, "ovr", &frames), data);
    }

    #[test]
    fn from_reader_with_chunk_size_honors_override() {
        let m = mk();
        let data = pattern(40);
        let mut enc =
            ChunkEncryptor::from_reader_with_chunk_size(&m, "rdrovr", 40, 16, Cursor::new(data.clone())).unwrap();
        assert_eq!(enc.chunk_plan().chunk_size_bytes, 16);
        assert_eq!(enc.chunk_plan().chunk_count, 3); // 16 + 16 + 8
        let mut frames = Vec::new();
        while let Some(c) = enc.next_chunk().unwrap() {
            frames.push(c);
        }
        assert_eq!(frames[0].data.len(), 16 + 28);
        assert_eq!(frames[2].data.len(), 8 + 28);
        assert_eq!(decrypt_frames(&m, "rdrovr", &frames), data);
    }

    #[test]
    fn from_reader_with_chunk_size_rejects_zero() {
        let m = mk();
        let err = ChunkEncryptor::from_reader_with_chunk_size(&m, "z2", 40, 0, Cursor::new(Vec::new())).unwrap_err();
        assert!(matches!(err, CoreError::InvalidInput(_)));
    }

    #[test]
    fn push_chunk_beyond_plan_errors() {
        let m = mk();
        let mut enc = ChunkEncryptor::for_push_with_chunk_size(&m, "cap", 16, 16).unwrap();
        assert_eq!(enc.chunk_plan().chunk_count, 1);
        let _ = enc.push_chunk(&pattern(16)).unwrap();
        let err = enc.push_chunk(&[0u8]).unwrap_err();
        assert!(matches!(err, CoreError::InvalidInput(_)));
    }

    #[test]
    fn decryptor_pull_roundtrip() {
        let m = mk();
        let data = pattern(9 * MIB);
        let (frames, _) = encrypt_all(&m, "decpull", &data, ChunkProfile::Desktop);

        // Concatenate frames into a contiguous wire body, then stream-decrypt.
        let mut body = Vec::new();
        for f in &frames {
            body.extend_from_slice(&f.data);
        }
        let chunk_size = ChunkEncryptor::from_reader(
            &m,
            "decpull",
            data.len() as u64,
            ChunkProfile::Desktop,
            Cursor::new(Vec::new()),
        )
        .unwrap()
        .chunk_plan()
        .chunk_size_bytes;

        let mut dec = ChunkDecryptor::from_reader(&m, "decpull", exp(), chunk_size, Cursor::new(body)).unwrap();
        let mut out = Vec::new();
        let mut idx = 0u32;
        while let Some(c) = dec.next_chunk().unwrap() {
            assert_eq!(c.index, idx);
            idx += 1;
            out.extend_from_slice(&c.data);
        }
        assert_eq!(idx, 3);
        assert_eq!(out, data);
    }

    #[test]
    fn decryptor_chunk_size_zero_errors() {
        let m = mk();
        let err = ChunkDecryptor::from_reader(&m, "z", exp(), 0, Cursor::new(Vec::new())).unwrap_err();
        assert!(matches!(err, CoreError::InvalidInput(_)));
    }

    #[test]
    fn decryptor_rejects_truncated_frame() {
        let m = mk();
        let mut dec = ChunkDecryptor::for_push(&m, "trunc", exp());
        // Fewer than nonce(12) + tag(16) bytes — cannot be a valid frame.
        let err = dec.push_frame(&[0u8; 20]).unwrap_err();
        assert!(matches!(err, CoreError::Decryption));
    }

    /// A reader that synthesizes up to `remaining` bytes WITHOUT ever allocating
    /// them, recording the largest single read it is asked to perform.
    struct CountingReader {
        remaining: u64,
        max_read: Arc<AtomicUsize>,
        total_served: Arc<AtomicU64>,
    }

    impl Read for CountingReader {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.max_read.fetch_max(buf.len(), Ordering::SeqCst);
            if self.remaining == 0 {
                return Ok(0);
            }
            let n = (buf.len() as u64).min(self.remaining) as usize;
            for b in &mut buf[..n] {
                *b = 0xAB;
            }
            self.remaining -= n as u64;
            self.total_served.fetch_add(n as u64, Ordering::SeqCst);
            Ok(n)
        }
    }

    #[test]
    fn memory_ceiling_8gib_no_full_allocation() {
        let m = mk();
        let max_read = Arc::new(AtomicUsize::new(0));
        let total = Arc::new(AtomicU64::new(0));
        let eight_gib: u64 = 8 * 1024 * 1024 * 1024;

        let reader = CountingReader {
            remaining: eight_gib,
            max_read: max_read.clone(),
            total_served: total.clone(),
        };
        // Explicit 16 MiB chunk so this memory-mechanics test is independent of
        // the chunk-size ladder (the ladder is covered by beebeeb-types' vector
        // test). The point here is that the read buffer is sized to the chunk,
        // not to the 8 GiB file.
        let mut enc =
            ChunkEncryptor::from_reader_with_chunk_size(&m, "huge", eight_gib, 16 * MIB as u64, reader).unwrap();

        let plan = enc.chunk_plan();
        assert_eq!(plan.chunk_size_bytes, 16 * MIB as u64);
        assert_eq!(plan.chunk_count, eight_gib / (16 * MIB as u64)); // 512
        assert_eq!(enc.expected_total_ciphertext(), eight_gib + 28 * plan.chunk_count);

        // The read buffer is sized to the chunk, NOT the 8 GiB file.
        let cap_before = enc.buf.capacity();
        assert_eq!(cap_before, 16 * MIB);

        // Pull a handful of chunks — enough to prove the buffer is reused and
        // never grows, and that no read ever exceeds the chunk size.
        for _ in 0..8 {
            let c = enc.next_chunk().unwrap().unwrap();
            assert_eq!(c.data.len(), 16 * MIB + 28);
            assert_eq!(enc.buf.capacity(), cap_before, "read buffer capacity must not grow");
            assert!(
                max_read.load(Ordering::SeqCst) <= 16 * MIB,
                "no single read may exceed the chunk size"
            );
        }

        // We consumed only 8 * 16 MiB = 128 MiB of the 8 GiB stream.
        assert_eq!(total.load(Ordering::SeqCst), 8 * (16 * MIB as u64));
    }

    #[test]
    fn default_output_opens_via_legacy_decrypt_chunk_raw_only_while_write_format_is_v1() {
        // Task 1908: before 1908 this asserted that new frames open with the
        // legacy no-AAD `decrypt_chunk_raw` ("wire format unchanged"). During
        // the read-only rollout phase WRITE_FORMAT is still v1, so that holds;
        // once it is v2 the legacy open MUST fail (downgrade resistance). Same
        // layout and sizes either way; the shared decryptor reads both.
        let m = mk();
        let data = pattern(9 * MIB);
        let (frames, _) = encrypt_all(&m, "legacy", &data, ChunkProfile::Desktop);
        let file_key = derive_file_key(&m, b"legacy");
        for f in &frames {
            assert_eq!(
                decrypt_chunk_raw(&file_key, &f.data).is_ok(),
                WRITE_FORMAT == ChunkFormat::V1Legacy
            );
            assert_eq!(f.data.len(), frames_len_for(&data, f.index));
        }
        assert_eq!(decrypt_frames(&m, "legacy", &frames), data);
    }

    #[test]
    fn v2_output_does_not_open_via_legacy_decrypt_chunk_raw() {
        // A v2 frame never opens with the legacy no-AAD open (it is sealed
        // under the chunk subkey, with AAD), so the binding cannot be stripped.
        let m = mk();
        let data = pattern(9 * MIB);
        let mut enc = ChunkEncryptor::from_reader(
            &m,
            "legacy-v2",
            data.len() as u64,
            ChunkProfile::Desktop,
            Cursor::new(data.clone()),
        )
        .unwrap()
        .with_format(ChunkFormat::V2)
        .unwrap();
        let file_key = derive_file_key(&m, b"legacy-v2");
        let mut dec = ChunkDecryptor::for_push(&m, "legacy-v2", ExpectedChunkFormat::V2);
        let mut out = Vec::new();
        while let Some(f) = enc.next_chunk().unwrap() {
            assert!(decrypt_chunk_raw(&file_key, &f.data).is_err());
            assert_eq!(f.data.len(), frames_len_for(&data, f.index));
            out.extend_from_slice(&dec.push_frame(&f.data).unwrap().data);
        }
        enc.finish().unwrap();
        dec.finish().unwrap();
        assert_eq!(out, data);
    }

    /// Frame length is plaintext + 28 in both formats (layout unchanged).
    fn frames_len_for(data: &[u8], index: u32) -> usize {
        let start = index as usize * 4 * MIB;
        (data.len() - start).min(4 * MIB) + NONCE_LEN + TAG_LEN
    }

    #[test]
    fn write_format_is_v1_during_the_read_only_rollout_phase() {
        // Task 1908 review round 2 (P2-1): clients on this core READ v2 but keep
        // WRITING v1 until every client's read path is live. Flipping this is
        // the gated switch recorded in task 1908 — change this test with it.
        assert_eq!(WRITE_FORMAT, ChunkFormat::V1Legacy);
        let m = mk();
        let enc = ChunkEncryptor::for_push(&m, "fmt", 10, ChunkProfile::Web).unwrap();
        assert_eq!(enc.format(), ChunkFormat::V1Legacy);
        assert_eq!(
            ExpectedChunkFormat::recorded_for(enc.format()),
            ExpectedChunkFormat::Unrecorded
        );
    }
}

/// Task 1908: chunk-position binding. Each test models one thing a malicious
/// server can do to the opaque frames of a single file. Written red-first
/// against origin/main (where frames carry no AAD), see the task Notes.
#[cfg(test)]
mod binding_tests {
    use super::*;
    use crate::encrypt::decrypt_chunk_raw;
    use crate::kdf::derive_master_key;
    use std::io::Cursor;

    fn mk() -> MasterKey {
        derive_master_key("binding-password", b"binding-salt-16b").unwrap()
    }

    /// 16-byte chunks so every frame of a 64-byte file is the same size —
    /// the case where a reorder/duplicate is invisible to a length check.
    const CS: u64 = 16;

    fn pattern(len: usize, seed: u8) -> Vec<u8> {
        (0..len)
            .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
            .collect()
    }

    /// The writer under test: a v2 (position-bound) encryptor.
    fn v2_encryptor(m: &MasterKey, file_id: &str, size: u64) -> ChunkEncryptor {
        ChunkEncryptor::for_push_with_chunk_size(m, file_id, size, CS)
            .unwrap()
            .with_format(ChunkFormat::V2)
            .unwrap()
    }

    fn v2_frames(m: &MasterKey, file_id: &str, data: &[u8]) -> Vec<Vec<u8>> {
        let mut enc = v2_encryptor(m, file_id, data.len() as u64);
        let frames = if data.is_empty() {
            vec![enc.push_chunk(&[]).unwrap().data]
        } else {
            data.chunks(CS as usize)
                .map(|c| enc.push_chunk(c).unwrap().data)
                .collect()
        };
        enc.finish().unwrap();
        frames
    }

    /// Push every frame in order under `expected`; the stream is accepted only
    /// if every frame decrypts AND the decryptor's end-of-stream check passes.
    fn push_with(
        m: &MasterKey,
        file_id: &str,
        expected: ExpectedChunkFormat,
        frames: &[Vec<u8>],
    ) -> Result<Vec<u8>, CoreError> {
        let mut dec = ChunkDecryptor::for_push(m, file_id, expected);
        let mut out = Vec::new();
        for f in frames {
            out.extend_from_slice(&dec.push_frame(f)?.data);
        }
        dec.finish()?;
        Ok(out)
    }

    /// Pull-form decrypt of a contiguous body (the download path).
    fn pull_with(
        m: &MasterKey,
        file_id: &str,
        expected: ExpectedChunkFormat,
        frames: &[Vec<u8>],
    ) -> Result<Vec<u8>, CoreError> {
        let body: Vec<u8> = frames.concat();
        let mut dec = ChunkDecryptor::from_reader(m, file_id, expected, CS, Cursor::new(body))?;
        let mut out = Vec::new();
        while let Some(c) = dec.next_chunk()? {
            out.extend_from_slice(&c.data);
        }
        Ok(out)
    }

    /// A v2 file is read the same way whether its metadata records v2 (pinned)
    /// or nothing (detected): every v2 STREAM guarantee must hold under both.
    /// Returns the common result; panics if the two readers disagree.
    fn both_pins(r_v2: Result<Vec<u8>, CoreError>, r_unrec: Result<Vec<u8>, CoreError>) -> Result<Vec<u8>, CoreError> {
        match (&r_v2, &r_unrec) {
            (Ok(a), Ok(b)) => assert_eq!(a, b, "pinned and detected readers disagree"),
            (Err(_), Err(_)) => {}
            _ => panic!("pinned (v2) and detected (unrecorded) readers disagree: {r_v2:?} vs {r_unrec:?}"),
        }
        r_v2
    }

    fn push_all(m: &MasterKey, file_id: &str, frames: &[Vec<u8>]) -> Result<Vec<u8>, CoreError> {
        both_pins(
            push_with(m, file_id, ExpectedChunkFormat::V2, frames),
            push_with(m, file_id, ExpectedChunkFormat::Unrecorded, frames),
        )
    }

    fn pull_all(m: &MasterKey, file_id: &str, frames: &[Vec<u8>]) -> Result<Vec<u8>, CoreError> {
        both_pins(
            pull_with(m, file_id, ExpectedChunkFormat::V2, frames),
            pull_with(m, file_id, ExpectedChunkFormat::Unrecorded, frames),
        )
    }

    #[test]
    fn v2_roundtrip_push_and_pull() {
        let m = mk();
        let data = pattern(64, 1);
        let frames = v2_frames(&m, "rt", &data);
        assert_eq!(frames.len(), 4);
        assert_eq!(push_all(&m, "rt", &frames).unwrap(), data);
        assert_eq!(pull_all(&m, "rt", &frames).unwrap(), data);
    }

    #[test]
    fn v2_two_chunk_swap_fails() {
        let m = mk();
        let data = pattern(64, 2);
        let mut frames = v2_frames(&m, "swap", &data);
        frames.swap(1, 2);
        assert!(
            push_all(&m, "swap", &frames).is_err(),
            "swapped chunks must not decrypt"
        );
        assert!(pull_all(&m, "swap", &frames).is_err());
    }

    #[test]
    fn v2_duplicated_chunk_fails() {
        let m = mk();
        let data = pattern(64, 3);
        let mut frames = v2_frames(&m, "dup", &data);
        // Replace chunk 2 by a copy of chunk 1 (same size, valid tag).
        frames[2] = frames[1].clone();
        assert!(
            push_all(&m, "dup", &frames).is_err(),
            "a duplicated chunk must not decrypt"
        );
        assert!(pull_all(&m, "dup", &frames).is_err());
    }

    #[test]
    fn v2_dropped_middle_chunk_fails() {
        let m = mk();
        let data = pattern(64, 4);
        let mut frames = v2_frames(&m, "drop", &data);
        frames.remove(1);
        assert!(
            push_all(&m, "drop", &frames).is_err(),
            "dropping a middle chunk must not decrypt"
        );
        assert!(pull_all(&m, "drop", &frames).is_err());
    }

    #[test]
    fn v2_truncated_missing_last_fails() {
        let m = mk();
        let data = pattern(64, 5);
        let mut frames = v2_frames(&m, "trunc", &data);
        frames.pop(); // the server withholds the final chunk
        assert!(
            pull_all(&m, "trunc", &frames).is_err(),
            "a stream that ends before the last chunk must be rejected (pull)"
        );
        assert!(
            push_all(&m, "trunc", &frames).is_err(),
            "a stream that ends before the last chunk must be rejected (push finish)"
        );
    }

    #[test]
    fn v2_extra_chunk_after_last_fails() {
        let m = mk();
        let data = pattern(64, 6);
        let mut frames = v2_frames(&m, "extra", &data);
        let again = frames[0].clone();
        frames.push(again); // a valid frame appended after the last one
        assert!(
            push_all(&m, "extra", &frames).is_err(),
            "nothing may follow the last chunk"
        );
        assert!(pull_all(&m, "extra", &frames).is_err());
    }

    #[test]
    fn v2_chunk_from_another_file_fails() {
        let m = mk();
        let a = pattern(64, 7);
        let b = pattern(64, 8);
        let mut fa = v2_frames(&m, "file-a", &a);
        let fb = v2_frames(&m, "file-b", &b);
        fa[1] = fb[1].clone(); // same index, same size, other file
        assert!(push_all(&m, "file-a", &fa).is_err());
    }

    #[test]
    fn v2_extension_with_frame_from_longer_same_id_fails() {
        // A longer earlier file under the SAME id (same key) has valid frames at
        // indices 4 (not last) and 5 (last). Appending them after this file's
        // last chunk would yield a complete-looking v2 stream (indices 0..5,
        // ending on a last-sealed frame) — only the "nothing after the last
        // chunk" rule stops this splice.
        let m = mk();
        let short = v2_frames(&m, "same-id", &pattern(64, 10)); // 4 chunks
        let long = v2_frames(&m, "same-id", &pattern(96, 11)); // 6 chunks

        let mut one_more = short.clone();
        one_more.push(long[4].clone());
        assert!(push_all(&m, "same-id", &one_more).is_err());
        assert!(pull_all(&m, "same-id", &one_more).is_err());

        let mut whole_tail = short.clone();
        whole_tail.extend_from_slice(&long[4..]);
        assert!(
            push_all(&m, "same-id", &whole_tail).is_err(),
            "frames after the authenticated last chunk must be rejected"
        );
        assert!(pull_all(&m, "same-id", &whole_tail).is_err());

        // Control: the short file alone is fine.
        assert_eq!(push_all(&m, "same-id", &short).unwrap(), pattern(64, 10));
    }

    #[test]
    fn v2_truncation_to_a_shorter_same_id_prefix_fails() {
        // The first 4 frames of a 6-chunk file under the same id: indices all
        // match, but frame 3 is not sealed as last — finish must reject.
        let m = mk();
        let long = v2_frames(&m, "same-id-2", &pattern(96, 12));
        assert!(push_all(&m, "same-id-2", &long[..4]).is_err());
        assert!(pull_all(&m, "same-id-2", &long[..4]).is_err());
    }

    #[test]
    fn same_key_other_file_id_fails() {
        // Defence in depth: even if two files ever shared a key (a reused or
        // mis-derived key, an unwrapped content key), the file id in the AAD
        // keeps their frames apart.
        let m = mk();
        let data = pattern(64, 13);
        let frames = v2_frames(&m, "owner-id", &data);
        let key_bytes = *derive_file_key(&m, b"owner-id").as_bytes();

        let mut right =
            ChunkDecryptor::for_push_with_file_key(FileKey::from_bytes(key_bytes), "owner-id", ExpectedChunkFormat::V2);
        for f in &frames {
            right.push_frame(f).unwrap();
        }
        right.finish().unwrap();

        let mut wrong =
            ChunkDecryptor::for_push_with_file_key(FileKey::from_bytes(key_bytes), "other-id", ExpectedChunkFormat::V2);
        assert!(
            wrong.push_frame(&frames[0]).is_err(),
            "same key, other file id must not open"
        );
    }

    #[test]
    fn v1_frame_spliced_into_v2_stream_fails() {
        // Format lock: chunk 0 decides. A legacy (no-AAD) frame under the same
        // key at position 1 of a v2 file must be rejected.
        let m = mk();
        let data = pattern(64, 14);
        let mut frames = v2_frames(&m, "mixed", &data);
        let fk = derive_file_key(&m, b"mixed");
        frames[1] = crate::encrypt::encrypt_chunk_raw(&fk, &data[16..32]).unwrap();
        assert!(push_all(&m, "mixed", &frames).is_err());
        assert!(pull_all(&m, "mixed", &frames).is_err());
    }

    /// v1 (legacy) frames, as every client wrote them before task 1908.
    fn v1_frames(m: &MasterKey, file_id: &str, data: &[u8]) -> Vec<Vec<u8>> {
        let mut enc = ChunkEncryptor::for_push_with_chunk_size(m, file_id, data.len() as u64, CS)
            .unwrap()
            .with_format(ChunkFormat::V1Legacy)
            .unwrap();
        let frames: Vec<Vec<u8>> = if data.is_empty() {
            vec![enc.push_chunk(&[]).unwrap().data]
        } else {
            data.chunks(CS as usize)
                .map(|c| enc.push_chunk(c).unwrap().data)
                .collect()
        };
        enc.finish().unwrap();
        frames
    }

    #[test]
    fn v1_frames_still_decrypt_push_and_pull() {
        let m = mk();
        for len in [0usize, 1, 16, 40, 64] {
            let data = pattern(len, 15);
            let frames = v1_frames(&m, "legacy", &data);
            // Byte-compatible with the pre-1908 primitive.
            let fk = derive_file_key(&m, b"legacy");
            for f in &frames {
                decrypt_chunk_raw(&fk, f).unwrap();
            }
            // Legacy metadata records no format: detection reads them.
            let unrec = ExpectedChunkFormat::Unrecorded;
            assert_eq!(push_with(&m, "legacy", unrec, &frames).unwrap(), data, "push len {len}");
            assert_eq!(pull_with(&m, "legacy", unrec, &frames).unwrap(), data, "pull len {len}");
            let mut dec = ChunkDecryptor::for_push(&m, "legacy", unrec);
            for f in &frames {
                dec.push_frame(f).unwrap();
            }
            assert_eq!(dec.format(), Some(ChunkFormat::V1Legacy));
        }
    }

    #[test]
    fn v1_fixture_from_vectors_json_still_decrypts() {
        // The committed cross-client fixture (test-vectors/vectors.json,
        // `chunk_encrypt_decrypt`) is a real v1 frame. It must keep opening via
        // the file-key decryptor; v1 binds no file id, so any id works.
        let v: serde_json::Value = serde_json::from_str(include_str!("../../test-vectors/vectors.json")).unwrap();
        let vec = v["vectors"]
            .as_array()
            .unwrap()
            .iter()
            .find(|x| x["name"] == "chunk_encrypt_decrypt")
            .unwrap();
        let hex = |k: &str| hex::decode(vec[k].as_str().unwrap()).unwrap();
        let key: [u8; 32] = hex("file_key_hex").try_into().unwrap();
        let frame = [hex("nonce_hex"), hex("ciphertext_hex")].concat();

        let mut dec =
            ChunkDecryptor::for_push_with_file_key(FileKey::from_bytes(key), "any-id", ExpectedChunkFormat::Unrecorded);
        let pt = dec.push_frame(&frame).unwrap().data;
        assert_eq!(pt, hex("plaintext_hex"));
        let summary = dec.finish().unwrap();
        assert_eq!(summary.format, ChunkFormat::V1Legacy);
        assert_eq!(summary.chunk_count, 1);
    }

    #[test]
    fn metadata_v2_pin_refuses_v1_frames_and_unrecorded_reads_both() {
        let m = mk();
        let data = pattern(40, 16);
        let v1 = v1_frames(&m, "pin", &data);
        let v2 = v2_frames(&m, "pin", &data);

        // Metadata records v2: a v1 copy under the same key is refused — at
        // frame 0 (no detection) and therefore as a whole stream.
        let mut dec = ChunkDecryptor::for_push(&m, "pin", ExpectedChunkFormat::V2);
        assert!(dec.push_frame(&v1[0]).is_err());
        assert!(push_with(&m, "pin", ExpectedChunkFormat::V2, &v1).is_err());

        // Metadata records v2 and the file is v2: opens.
        assert_eq!(push_with(&m, "pin", ExpectedChunkFormat::V2, &v2).unwrap(), data);

        // Legacy metadata (unrecorded): frame 0 decides, both formats open.
        assert_eq!(
            push_with(&m, "pin", ExpectedChunkFormat::Unrecorded, &v1).unwrap(),
            data
        );
        assert_eq!(
            push_with(&m, "pin", ExpectedChunkFormat::Unrecorded, &v2).unwrap(),
            data
        );
    }

    #[test]
    fn v2_roundtrip_all_sizes_incl_empty_and_exactly_one_chunk() {
        let m = mk();
        // 0 = empty file (one frame, sealed as last); 16 = exactly one chunk;
        // 17 = one full + one 1-byte chunk; 64 = exact multiple.
        for len in [0usize, 1, 15, 16, 17, 31, 32, 33, 64, 65] {
            let data = pattern(len, 17);
            let frames = v2_frames(&m, "sizes", &data);
            let expect_frames = if len == 0 { 1 } else { len.div_ceil(CS as usize) };
            assert_eq!(frames.len(), expect_frames, "len {len}");
            assert_eq!(push_all(&m, "sizes", &frames).unwrap(), data, "push len {len}");
            assert_eq!(pull_all(&m, "sizes", &frames).unwrap(), data, "pull len {len}");
        }
    }

    #[test]
    fn empty_stream_is_rejected() {
        // Zero frames is never a file (an empty file is one frame).
        let m = mk();
        assert!(push_all(&m, "none", &[]).is_err());
        assert!(pull_all(&m, "none", &[]).is_err());
        // An empty v2 file truncated to nothing.
        let frames = v2_frames(&m, "empty", &[]);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].len(), NONCE_LEN + TAG_LEN);
        assert!(push_all(&m, "empty", &frames[..0]).is_err());
    }

    #[test]
    fn chunk_aad_v2_known_answer() {
        // Pins the exact AAD layout (a wire-format change must show up here).
        let vid = [0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB];
        let aad = chunk_aad_v2(b"abc", &vid, 0x0102_0304, true);
        let mut expect = b"beebeeb/chunk/v2".to_vec();
        expect.extend_from_slice(&[0, 0, 0, 3]);
        expect.extend_from_slice(b"abc");
        expect.extend_from_slice(&vid);
        expect.extend_from_slice(&[1, 2, 3, 4]);
        expect.push(1);
        assert_eq!(aad, expect);
        assert_eq!(chunk_aad_v2(b"abc", &vid, 0x0102_0304, false).last(), Some(&0));
        assert_eq!(aad.len(), 16 + 4 + 3 + 12 + 4 + 1);
    }

    #[test]
    fn chunk_subkey_v2_known_answer() {
        // HKDF-SHA256(salt = none, ikm = file key, info = "beebeeb/chunk/v2/key"),
        // computed independently (Python hmac/hashlib, RFC 5869 by hand).
        let fk = FileKey::from_bytes(std::array::from_fn(|i| i as u8));
        let sub = derive_chunk_key_v2(&fk);
        assert_eq!(
            hex::encode(sub.as_bytes()),
            "2947435440f809ccc93b0650af23acfee9fd37d82e238c6a254a712af3a71ffc"
        );
    }

    #[test]
    fn v2_frames_are_sealed_under_the_chunk_subkey_not_the_file_key() {
        // Key separation (review round 2): with the right AAD a v2 frame opens
        // only under the derived chunk subkey, never under the raw file key that
        // also seals the name/MIME and thumbnails.
        let m = mk();
        let frames = v2_frames(&m, "subkey", &pattern(40, 19));
        let fk = derive_file_key(&m, b"subkey");
        let vid: [u8; VERSION_ID_LEN] = frames[0][..VERSION_ID_LEN].try_into().unwrap();
        let aad = chunk_aad_v2(b"subkey", &vid, 0, false);
        assert!(open_raw_with_aad(&derive_chunk_key_v2(&fk), &frames[0], &aad).is_ok());
        assert!(
            open_raw_with_aad(&fk, &frames[0], &aad).is_err(),
            "a v2 frame must not open under the raw file key"
        );
    }

    #[test]
    fn version_id_is_frame0_nonce_and_differs_per_upload() {
        let m = mk();
        let data = pattern(64, 20);
        let a = v2_frames(&m, "vid", &data);
        let b = v2_frames(&m, "vid", &data);
        let mut dec = ChunkDecryptor::for_push(&m, "vid", ExpectedChunkFormat::V2);
        assert_eq!(dec.version_id(), None);
        dec.push_frame(&a[0]).unwrap();
        assert_eq!(dec.version_id().unwrap().as_slice(), &a[0][..VERSION_ID_LEN]);
        assert_ne!(
            a[0][..VERSION_ID_LEN],
            b[0][..VERSION_ID_LEN],
            "two uploads, two version ids"
        );
        // v1 files have no version id.
        let mut dec = ChunkDecryptor::for_push(&m, "vid", ExpectedChunkFormat::Unrecorded);
        dec.push_frame(&v1_frames(&m, "vid", &data)[0]).unwrap();
        assert_eq!(dec.version_id(), None);
    }

    #[test]
    fn open_chunk_random_access() {
        let m = mk();
        let data = pattern(64, 18);
        let frames = v2_frames(&m, "seek", &data);
        let fk = derive_file_key(&m, b"seek");
        let vid = frames[0][..VERSION_ID_LEN].to_vec();
        // Correct position: opens, in any order (seeking).
        for i in [2u32, 0, 3, 1] {
            let last = i == 3;
            let pt = open_chunk(&fk, "seek", &vid, i, last, ChunkFormat::V2, &frames[i as usize]).unwrap();
            assert_eq!(pt, data[i as usize * 16..(i as usize + 1) * 16]);
        }
        // Server answers a request for chunk 1 with chunk 2: fails.
        assert!(open_chunk(&fk, "seek", &vid, 1, false, ChunkFormat::V2, &frames[2]).is_err());
        // Server under-reports the count so the client thinks 2 is last: fails.
        assert!(open_chunk(&fk, "seek", &vid, 2, true, ChunkFormat::V2, &frames[2]).is_err());
        // Server over-reports: the real last chunk is not accepted as non-last.
        assert!(open_chunk(&fk, "seek", &vid, 3, false, ChunkFormat::V2, &frames[3]).is_err());
        // Server answers with the same index from another upload of the file.
        let other = v2_frames(&m, "seek", &data);
        assert!(open_chunk(&fk, "seek", &vid, 1, false, ChunkFormat::V2, &other[1]).is_err());
        // A version id of the wrong length is refused, not truncated/padded.
        assert!(open_chunk(&fk, "seek", &vid[..11], 1, false, ChunkFormat::V2, &frames[1]).is_err());
        // Wrong format argument: a v2 frame never opens as v1.
        assert!(open_chunk(&fk, "seek", &vid, 0, false, ChunkFormat::V1Legacy, &frames[0]).is_err());
        // v1 files: position and version arguments are ignored.
        let v1 = v1_frames(&m, "seek", &data);
        assert_eq!(
            open_chunk(&fk, "seek", &[], 99, true, ChunkFormat::V1Legacy, &v1[1]).unwrap(),
            data[16..32]
        );
    }

    #[test]
    fn chunk_format_codes() {
        assert_eq!(ChunkFormat::from_u8(1).unwrap(), ChunkFormat::V1Legacy);
        assert_eq!(ChunkFormat::from_u8(2).unwrap(), ChunkFormat::V2);
        assert!(ChunkFormat::from_u8(0).is_err());
        assert!(ChunkFormat::from_u8(3).is_err());
        assert_eq!(ChunkFormat::V2.as_u8(), 2);
        assert_eq!(
            ExpectedChunkFormat::from_u8(0).unwrap(),
            ExpectedChunkFormat::Unrecorded
        );
        assert_eq!(ExpectedChunkFormat::from_u8(2).unwrap(), ExpectedChunkFormat::V2);
        for bad in [1u8, 3, 255] {
            assert!(ExpectedChunkFormat::from_u8(bad).is_err(), "code {bad}");
        }
        assert_eq!(ExpectedChunkFormat::V2.as_u8(), 2);
        assert_eq!(ExpectedChunkFormat::Unrecorded.as_u8(), 0);
    }

    #[test]
    fn v2_frame_decrypted_as_v1_fails() {
        // Downgrade: the legacy (no-AAD) open must reject every v2 frame, so the
        // binding cannot be stripped by asking for the old format.
        let m = mk();
        let data = pattern(64, 9);
        let frames = v2_frames(&m, "down", &data);
        let fk = derive_file_key(&m, b"down");
        for (i, f) in frames.iter().enumerate() {
            assert!(
                decrypt_chunk_raw(&fk, f).is_err(),
                "v2 frame {i} must not open as a v1 frame"
            );
        }
    }
}

/// Task 1908 review round 2: the two server-controlled bypasses the crypto
/// review demonstrated (P1-1 downgrade via a same-key no-AAD blob at frame 0,
/// P1-2 splicing frames across versions of one file id). Red first.
#[cfg(test)]
mod review_round2_tests {
    use super::*;
    use crate::kdf::derive_master_key;

    fn mk() -> MasterKey {
        derive_master_key("round2-password", b"round2-salt-16by").unwrap()
    }

    const CS: u64 = 16;

    fn pattern(len: usize, seed: u8) -> Vec<u8> {
        (0..len)
            .map(|i| (i as u8).wrapping_mul(17).wrapping_add(seed))
            .collect()
    }

    /// One upload (= one version) of `data` under `file_id`, v2 frames.
    fn v2_upload(m: &MasterKey, file_id: &str, data: &[u8]) -> Vec<Vec<u8>> {
        let mut enc = ChunkEncryptor::for_push_with_chunk_size(m, file_id, data.len() as u64, CS)
            .unwrap()
            .with_format(ChunkFormat::V2)
            .unwrap();
        let frames: Vec<Vec<u8>> = data
            .chunks(CS as usize)
            .map(|c| enc.push_chunk(c).unwrap().data)
            .collect();
        enc.finish().unwrap();
        frames
    }

    /// The metadata a v2 upload writes: `name_encrypted` recording v2.
    fn v2_name_encrypted(m: &MasterKey, file_id: &str) -> String {
        crate::encrypt::encrypt_name_with_chunk_format(
            m,
            file_id,
            "report.pdf",
            Some("application/pdf"),
            ExpectedChunkFormat::V2,
        )
        .unwrap()
    }

    /// A client reading a file: the pin comes from the decrypted metadata (the
    /// FILE reader, which refuses plaintext names — round 3), then frames are
    /// opened in order and the stream must finish.
    fn read_file(m: &MasterKey, file_id: &str, name_encrypted: &str, frames: &[Vec<u8>]) -> Result<Vec<u8>, CoreError> {
        let meta = crate::encrypt::decrypt_file_metadata(m, file_id, name_encrypted)?;
        let mut dec = ChunkDecryptor::for_push(m, file_id, meta.chunk_format);
        let mut out = Vec::new();
        for f in frames {
            out.extend_from_slice(&dec.push_frame(f)?.data);
        }
        dec.finish()?;
        Ok(out)
    }

    /// The reader for a file uploaded as v2 (metadata records v2).
    fn read_v2(m: &MasterKey, file_id: &str, frames: &[Vec<u8>]) -> Result<Vec<u8>, CoreError> {
        read_file(m, file_id, &v2_name_encrypted(m, file_id), frames)
    }

    /// A `name_encrypted` JSON envelope (no AAD, same per-file key) as a wire
    /// frame `nonce || ct || tag`.
    fn blob_frame(name_encrypted: &str) -> Vec<u8> {
        let blob: beebeeb_types::EncryptedBlob = serde_json::from_str(name_encrypted).unwrap();
        [blob.nonce, blob.ciphertext].concat()
    }

    #[test]
    fn p1_1_name_blob_served_as_frame0_of_a_v2_file_is_rejected() {
        let m = mk();
        let id = "fresh-v2-file";
        let real = v2_upload(&m, id, &pattern(64, 1));
        let name_encrypted = v2_name_encrypted(&m, id);
        assert_eq!(read_file(&m, id, &name_encrypted, &real).unwrap(), pattern(64, 1));
        // The server serves the file's OWN name blob as its single frame.
        let forged = vec![blob_frame(&name_encrypted)];
        let got = read_file(&m, id, &name_encrypted, &forged);
        assert!(
            got.is_err(),
            "a v2 file must not be downgradable to v1 by serving its own name blob as frame 0 (got {} plaintext bytes)",
            got.map(|p| p.len()).unwrap_or(0)
        );
    }

    #[test]
    fn p1_1_thumbnail_blob_served_as_frame0_of_a_v2_file_is_rejected() {
        let m = mk();
        let id = "fresh-v2-photo";
        let _real = v2_upload(&m, id, &pattern(64, 2));
        // Thumbnails are a no-AAD seal under the raw per-file key (web thumbnail.ts).
        let fk = derive_file_key(&m, id.as_bytes());
        let thumb = crate::encrypt::encrypt_chunk_raw(&fk, b"\xff\xd8\xff\xe0 fake jpeg thumbnail").unwrap();
        assert!(
            read_v2(&m, id, &[thumb]).is_err(),
            "a same-key thumbnail blob must not be accepted as a complete v1 file"
        );
    }

    #[test]
    fn residual_unrecorded_metadata_still_detects_documented() {
        // The residual risk, pinned so a change to it is visible: a file whose
        // metadata records NO format (pre-1908 metadata, or rewritten by a
        // pre-1908 client) is read with detection, and detection cannot tell a
        // genuine one-frame v1 file from another no-AAD blob under the same
        // key. This is why every v2 upload records `chunk_format: 2` and why
        // renames must carry it forward (see encrypt_name_with_chunk_format).
        // Round 3 narrows it to LEGACY-sealed blobs (names/thumbnails sealed
        // under the raw file key: every one written before the metadata seal
        // switch); subkey-sealed ones never open as content
        // (`review_round3_tests::p1b_*`). Decision on the rest: workspace task
        // 1912.
        let m = mk();
        let id = "legacy-metadata-file";
        let legacy_name = crate::encrypt::encrypt_name(&m, id, "old.txt", None).unwrap();
        let meta = crate::encrypt::decrypt_name_metadata(&m, id, &legacy_name).unwrap();
        assert_eq!(meta.chunk_format, ExpectedChunkFormat::Unrecorded);
        let forged = vec![blob_frame(&legacy_name)];
        let got = read_file(&m, id, &legacy_name, &forged).unwrap();
        assert!(
            got.starts_with(b"{"),
            "detection accepts a same-key blob as v1 — the documented residual"
        );
    }

    #[test]
    fn p1_2_middle_splice_from_another_version_is_rejected() {
        // Version A and version B of ONE file id (a replace keeps the id, so
        // both versions share the per-file key). Same sizes, every frame valid.
        let m = mk();
        let id = "versioned-doc";
        let a = v2_upload(&m, id, &pattern(96, 3)); // 6 chunks
        let b = v2_upload(&m, id, &pattern(96, 4)); // 6 chunks
        let mut spliced = b.clone();
        spliced[1] = a[1].clone();
        assert!(
            read_v2(&m, id, &spliced).is_err(),
            "version A's chunk 1 spliced into version B must be rejected"
        );
    }

    #[test]
    fn p1_2_truncation_with_another_versions_last_frame_is_rejected() {
        // Version A has 4 chunks (A3 sealed as last); version B has 6. Serving
        // B0 B1 B2 + A3 looks like a complete 4-chunk file.
        let m = mk();
        let id = "versioned-doc-2";
        let a = v2_upload(&m, id, &pattern(64, 5)); // 4 chunks
        let b = v2_upload(&m, id, &pattern(96, 6)); // 6 chunks
        let forged = vec![b[0].clone(), b[1].clone(), b[2].clone(), a[3].clone()];
        assert!(
            read_v2(&m, id, &forged).is_err(),
            "B truncated with A's last-sealed frame must be rejected"
        );
    }

    #[test]
    fn p1_2_tail_from_another_version_is_rejected() {
        let m = mk();
        let id = "versioned-doc-3";
        let a = v2_upload(&m, id, &pattern(64, 7));
        let b = v2_upload(&m, id, &pattern(64, 8));
        let forged = vec![b[0].clone(), b[1].clone(), a[2].clone(), a[3].clone()];
        assert!(
            read_v2(&m, id, &forged).is_err(),
            "B's head with A's tail must be rejected"
        );
    }
}

/// Task 1908 review round 3: P1-A (a resumed v2 upload must never complete as
/// a mix of two version ids) and P1-B (a name/thumbnail blob must never open as
/// content; files must not accept a plaintext name). Red first.
#[cfg(test)]
mod review_round3_tests {
    use super::*;
    use crate::encrypt::{
        MetadataSeal, decrypt_file_metadata, decrypt_file_metadata_with_key, decrypt_name_metadata,
        decrypt_name_metadata_with_key, decrypt_thumbnail, encrypt_name, encrypt_name_sealed,
        encrypt_name_with_chunk_format, encrypt_thumbnail, encrypt_thumbnail_sealed,
    };
    use crate::kdf::derive_master_key;
    use std::collections::BTreeMap;

    fn mk() -> MasterKey {
        derive_master_key("round3-password", b"round3-salt-16by").unwrap()
    }

    const CS: u64 = 16;

    fn pattern(len: usize, seed: u8) -> Vec<u8> {
        (0..len)
            .map(|i| (i as u8).wrapping_mul(29).wrapping_add(seed))
            .collect()
    }

    fn encryptor(m: &MasterKey, file_id: &str, size: u64, format: ChunkFormat) -> ChunkEncryptor {
        ChunkEncryptor::for_push_with_chunk_size(m, file_id, size, CS)
            .unwrap()
            .with_format(format)
            .unwrap()
    }

    /// A server upload session: PUT of an index it already holds is skipped
    /// (`{skipped: true}`) — the server keeps the FIRST frame stored there.
    #[derive(Default)]
    struct FakeSession {
        frames: BTreeMap<u32, Vec<u8>>,
    }

    impl FakeSession {
        fn put(&mut self, index: u32, frame: Vec<u8>) {
            self.frames.entry(index).or_insert(frame);
        }
        fn body(&self) -> Vec<Vec<u8>> {
            self.frames.values().cloned().collect()
        }
    }

    /// The client's resume record: session + the format of the frames it holds.
    struct ResumeRecord {
        session: FakeSession,
        stored_format: Option<ChunkFormat>,
    }

    /// Attempt 1: open a session, record its format, PUT the first `upto`
    /// frames, then get interrupted.
    fn interrupted_upload(m: &MasterKey, id: &str, data: &[u8], format: ChunkFormat, upto: usize) -> ResumeRecord {
        let mut enc = encryptor(m, id, data.len() as u64, format);
        let mut rec = ResumeRecord {
            session: FakeSession::default(),
            stored_format: Some(enc.format()),
        };
        for c in data.chunks(CS as usize).take(upto) {
            let f = enc.push_chunk(c).unwrap();
            rec.session.put(f.index, f.data);
        }
        rec
    }

    /// Attempt 2, the way a client must resume: a NEW encryptor (the file key
    /// derives from the file id, nothing else survives a restart), then what
    /// core's resume policy says. Returns the stored body after `complete`.
    fn resume_following_policy(
        m: &MasterKey,
        id: &str,
        data: &[u8],
        format: ChunkFormat,
        rec: ResumeRecord,
    ) -> (SessionResume, Vec<Vec<u8>>) {
        let mut enc = encryptor(m, id, data.len() as u64, format);
        let policy = enc.resume_policy(rec.stored_format);
        let mut session = match policy {
            SessionResume::ContinueSession => rec.session,
            SessionResume::RestartWithFreshSession => FakeSession::default(),
        };
        for c in data.chunks(CS as usize) {
            let f = enc.push_chunk(c).unwrap();
            session.put(f.index, f.data);
        }
        enc.finish().unwrap();
        (policy, session.body())
    }

    fn read(m: &MasterKey, id: &str, expected: ExpectedChunkFormat, frames: &[Vec<u8>]) -> Result<Vec<u8>, CoreError> {
        let mut dec = ChunkDecryptor::for_push(m, id, expected);
        let mut out = Vec::new();
        for f in frames {
            out.extend_from_slice(&dec.push_frame(f)?.data);
        }
        dec.finish()?;
        Ok(out)
    }

    // ── P1-A: resume ────────────────────────────────────────────────────────

    #[test]
    fn p1a_probe_b_resumed_v2_upload_following_core_policy_is_readable() {
        // Probe B from the round-3 review: interrupt a v2 upload after 2 of 4
        // chunks, resume with a new encryptor. Following core's policy must
        // yield a readable file — never a stored-but-unreadable one.
        let m = mk();
        let id = "resumed-v2";
        let data = pattern(64, 1);
        let rec = interrupted_upload(&m, id, &data, ChunkFormat::V2, 2);
        let (policy, body) = resume_following_policy(&m, id, &data, ChunkFormat::V2, rec);
        let got = read(&m, id, ExpectedChunkFormat::V2, &body);
        assert!(
            got.is_ok(),
            "a resumed v2 upload that follows core's resume policy ({policy:?}) must be readable; got {got:?}"
        );
        assert_eq!(got.unwrap(), data);
        assert_eq!(policy, SessionResume::RestartWithFreshSession);
    }

    #[test]
    fn p1a_continuing_the_old_session_with_a_new_v2_encryptor_is_unreadable_documented() {
        // Why the policy exists: what a client that ignores it would store.
        let m = mk();
        let id = "mixed-v2";
        let data = pattern(64, 2);
        let mut rec = interrupted_upload(&m, id, &data, ChunkFormat::V2, 2);
        let mut enc = encryptor(&m, id, data.len() as u64, ChunkFormat::V2);
        for c in data.chunks(CS as usize) {
            let f = enc.push_chunk(c).unwrap();
            rec.session.put(f.index, f.data);
        }
        assert_eq!(rec.session.frames.len(), 4, "the mixed upload completes server-side");
        assert!(
            read(&m, id, ExpectedChunkFormat::V2, &rec.session.body()).is_err(),
            "frames of two version ids must not open as one file"
        );
    }

    #[test]
    fn p1a_v1_resume_still_continues_the_session_and_reads() {
        let m = mk();
        let id = "resumed-v1";
        let data = pattern(64, 3);
        let rec = interrupted_upload(&m, id, &data, ChunkFormat::V1Legacy, 2);
        let (policy, body) = resume_following_policy(&m, id, &data, ChunkFormat::V1Legacy, rec);
        assert_eq!(policy, SessionResume::ContinueSession);
        assert_eq!(read(&m, id, ExpectedChunkFormat::Unrecorded, &body).unwrap(), data);
    }

    #[test]
    fn p1a_resume_policy_matrix() {
        use ChunkFormat::{V1Legacy, V2};
        use SessionResume::{ContinueSession as C, RestartWithFreshSession as R};
        let cases = [
            (Some(V1Legacy), V1Legacy, C),
            (Some(V1Legacy), V2, R),
            (Some(V2), V2, R),
            (Some(V2), V1Legacy, R),
            (None, V1Legacy, R),
            (None, V2, R),
        ];
        for (stored, writing, want) in cases {
            assert_eq!(
                resume_policy(stored, writing),
                want,
                "stored {stored:?}, writing {writing:?}"
            );
        }
        assert_eq!(C.as_str(), "continue");
        assert_eq!(R.as_str(), "restart");
    }

    // ── P1-B (1): domain separation of names and thumbnails ─────────────────

    fn blob_frame(name_encrypted: &str) -> Vec<u8> {
        let blob: beebeeb_types::EncryptedBlob = serde_json::from_str(name_encrypted).unwrap();
        [blob.nonce, blob.ciphertext].concat()
    }

    #[test]
    fn p1b_subkey_sealed_name_never_opens_as_content() {
        // Even where a reader detects the format (metadata that records none),
        // a name envelope sealed the new way must not open as frame 0 — not as
        // v1 (raw key, no AAD) and not as v2 (chunk subkey).
        let m = mk();
        for (id, fmt) in [
            ("v2-file", ExpectedChunkFormat::V2),
            ("v1-file", ExpectedChunkFormat::Unrecorded),
        ] {
            let name =
                encrypt_name_sealed(&m, id, "report.pdf", Some("application/pdf"), fmt, MetadataSeal::Subkey).unwrap();
            let got = read(&m, id, ExpectedChunkFormat::Unrecorded, &[blob_frame(&name)]);
            assert!(
                got.is_err(),
                "a subkey-sealed name envelope ({id}) must not open as a one-frame file (got {} bytes)",
                got.map(|p| p.len()).unwrap_or(0)
            );
        }
    }

    #[test]
    fn p1b_v2_name_is_always_subkey_sealed() {
        // The public writer: a name that records chunk_format 2 never sits under
        // the raw file key, whatever the write switch says.
        let m = mk();
        let id = "v2-file-public-writer";
        let name = encrypt_name_with_chunk_format(&m, id, "a.pdf", None, ExpectedChunkFormat::V2).unwrap();
        let got = read(&m, id, ExpectedChunkFormat::Unrecorded, &[blob_frame(&name)]);
        assert!(got.is_err(), "a v2 file's own name must not open as its content");
        assert_eq!(
            decrypt_file_metadata(&m, id, &name).unwrap().chunk_format,
            ExpectedChunkFormat::V2
        );
    }

    #[test]
    fn p1b_subkey_sealed_thumbnail_never_opens_as_content() {
        let m = mk();
        let id = "photo";
        let fk = derive_file_key(&m, id.as_bytes());
        let thumb = encrypt_thumbnail_sealed(&fk, b"\xff\xd8\xff\xe0 thumbnail", MetadataSeal::Subkey).unwrap();
        assert_eq!(decrypt_thumbnail(&fk, &thumb).unwrap(), b"\xff\xd8\xff\xe0 thumbnail");
        let got = read(&m, id, ExpectedChunkFormat::Unrecorded, &[thumb]);
        assert!(
            got.is_err(),
            "a subkey-sealed thumbnail must not open as a one-frame file (got {} bytes)",
            got.map(|p| p.len()).unwrap_or(0)
        );
    }

    #[test]
    fn p1b_name_and_thumbnail_subkeys_are_distinct_from_each_other_and_from_content() {
        let fk = FileKey::from_bytes(std::array::from_fn(|i| (i as u8) ^ 0x5a));
        let name = crate::encrypt::derive_name_key(&fk);
        let thumb = crate::encrypt::derive_thumbnail_key(&fk);
        let chunk = derive_chunk_key_v2(&fk);
        let keys = [fk.as_bytes(), name.as_bytes(), thumb.as_bytes(), chunk.as_bytes()];
        for i in 0..keys.len() {
            for j in i + 1..keys.len() {
                assert_ne!(keys[i], keys[j], "subkeys {i} and {j} must differ");
            }
        }
        // A thumbnail never opens as a name and vice versa.
        let t = encrypt_thumbnail_sealed(&fk, b"{\"name\":\"x\"}", MetadataSeal::Subkey).unwrap();
        assert!(open_raw_with_aad(&name, &t, &[]).is_err());
    }

    #[test]
    fn name_subkey_known_answer() {
        // HKDF-SHA256(salt = none, ikm = file key, info = "beebeeb/name/v1"),
        // computed independently (Python hmac/hashlib, RFC 5869 by hand).
        let fk = FileKey::from_bytes(std::array::from_fn(|i| i as u8));
        assert_eq!(
            hex::encode(crate::encrypt::derive_name_key(&fk).as_bytes()),
            "c7ca9a948dc4137a6574435914b69199e575c795c24099eea8b41679bebbfe59"
        );
    }

    #[test]
    fn thumbnail_subkey_known_answer() {
        // HKDF-SHA256(salt = none, ikm = file key, info = "beebeeb/thumb/v1").
        let fk = FileKey::from_bytes(std::array::from_fn(|i| i as u8));
        assert_eq!(
            hex::encode(crate::encrypt::derive_thumbnail_key(&fk).as_bytes()),
            "796c11cf5c05ecff6c3a03facfd5c8f53aea6b1a64b4cc3b00b517c27e10b808"
        );
    }

    #[test]
    fn p1b_legacy_sealed_names_and_thumbnails_still_open() {
        // Everything stored before the switch: raw-key name envelopes (also the
        // legacy web base64 shape) and raw-key thumbnails.
        let m = mk();
        let id = "legacy-file";
        let legacy = encrypt_name_sealed(
            &m,
            id,
            "old.txt",
            None,
            ExpectedChunkFormat::Unrecorded,
            MetadataSeal::Legacy,
        )
        .unwrap();
        let meta = decrypt_file_metadata(&m, id, &legacy).unwrap();
        assert_eq!(
            (meta.name.as_str(), meta.chunk_format),
            ("old.txt", ExpectedChunkFormat::Unrecorded)
        );
        assert_eq!(crate::encrypt::decrypt_name(&m, id, &legacy).unwrap(), "old.txt");
        let fk = derive_file_key(&m, id.as_bytes());
        let blob: beebeeb_types::EncryptedBlob = serde_json::from_str(&legacy).unwrap();
        let web = crate::metadata_wire::serialize_encrypted_metadata(&blob.nonce, &blob.ciphertext);
        assert_eq!(decrypt_file_metadata_with_key(&fk, &web).unwrap().name, "old.txt");
        let thumb = crate::encrypt::encrypt_chunk_raw(&fk, b"old thumbnail").unwrap();
        assert_eq!(decrypt_thumbnail(&fk, &thumb).unwrap(), b"old thumbnail");
    }

    #[test]
    fn p1b_subkey_sealed_names_read_through_every_name_reader() {
        // Once the seal switch flips, every existing name reader (single, with
        // MIME, known key, batch, web base64 shape) must open the new envelopes
        // — otherwise flipping it silently blanks names in every client.
        let m = mk();
        let id = "6f9619ff-8b86-d011-b42d-00cf4fc964ff";
        let sealed = encrypt_name_sealed(
            &m,
            id,
            "plan.txt",
            Some("text/plain"),
            ExpectedChunkFormat::Unrecorded,
            MetadataSeal::Subkey,
        )
        .unwrap();
        let fk = derive_file_key(&m, id.as_bytes());
        let blob: beebeeb_types::EncryptedBlob = serde_json::from_str(&sealed).unwrap();
        assert!(
            crate::encrypt::decrypt_metadata(&fk, &blob).is_err(),
            "a subkey-sealed envelope must not open under the raw file key"
        );
        let web = crate::metadata_wire::serialize_encrypted_metadata(&blob.nonce, &blob.ciphertext);
        for env in [sealed.as_str(), web.as_str()] {
            assert_eq!(crate::encrypt::decrypt_name(&m, id, env).unwrap(), "plan.txt");
            assert_eq!(
                crate::encrypt::decrypt_name_with_mime(&m, id, env).unwrap(),
                ("plan.txt".to_string(), Some("text/plain".to_string()))
            );
            assert_eq!(
                crate::encrypt::decrypt_name_with_key(&fk, env).as_deref(),
                Some("plan.txt")
            );
            assert_eq!(decrypt_name_metadata(&m, id, env).unwrap().name, "plan.txt");
            assert_eq!(decrypt_file_metadata(&m, id, env).unwrap().name, "plan.txt");
            assert_eq!(decrypt_file_metadata_with_key(&fk, env).unwrap().name, "plan.txt");
            let uuid: uuid::Uuid = id.parse().unwrap();
            let batch = crate::encrypt::decrypt_names(&m, &[(uuid, env)]);
            assert_eq!(batch[0].as_ref().unwrap().0, "plan.txt");
        }
    }

    #[test]
    fn p1b_write_switch_keeps_legacy_sealing_during_the_read_only_phase() {
        // Read-only rollout phase: what this core writes for v1 files must stay
        // readable by clients NOT on this core (raw file key, no AAD).
        assert_eq!(WRITE_FORMAT, ChunkFormat::V1Legacy);
        assert_eq!(crate::encrypt::METADATA_SEAL_WRITE, MetadataSeal::Legacy);
        let m = mk();
        let id = "read-only-phase";
        let fk = derive_file_key(&m, id.as_bytes());
        let name = encrypt_name(&m, id, "n.txt", None).unwrap();
        let blob: beebeeb_types::EncryptedBlob = serde_json::from_str(&name).unwrap();
        assert!(
            crate::encrypt::decrypt_metadata(&fk, &blob).is_ok(),
            "old clients must read new v1 names"
        );
        let thumb = encrypt_thumbnail(&fk, b"t").unwrap();
        assert!(
            open_raw_with_aad(&fk, &thumb, &[]).is_ok(),
            "old clients must read new thumbnails"
        );
    }

    // ── P1-B (2): files refuse plaintext names ──────────────────────────────

    #[test]
    fn p1b_file_reader_refuses_a_plaintext_name_folder_reader_keeps_it() {
        let m = mk();
        let fk = derive_file_key(&m, b"f");
        assert!(
            decrypt_file_metadata(&m, "f", "report.pdf").is_err(),
            "a file's metadata must not be accepted as a plaintext name"
        );
        assert!(
            decrypt_file_metadata_with_key(&fk, "report.pdf").is_err(),
            "a file's metadata must not be accepted as a plaintext name (known key)"
        );
        // Folders keep the legacy plaintext form.
        assert_eq!(decrypt_name_metadata(&m, "f", "Photos").unwrap().name, "Photos");
        assert_eq!(decrypt_name_metadata_with_key(&fk, "Photos").unwrap().name, "Photos");
    }

    #[test]
    fn p1b_plaintext_name_substitution_on_a_v2_file_is_refused() {
        // The attack end to end: the server replaces a v2 file's metadata with
        // a plaintext name (no pin) and serves a same-key no-AAD blob (a legacy
        // thumbnail) as a one-frame file. A client reading files the way core
        // prescribes (decrypt_file_metadata -> pin -> decryptor) must refuse.
        let m = mk();
        let id = "v2-file-renamed-by-server";
        let fk = derive_file_key(&m, id.as_bytes());
        let forged_frame = crate::encrypt::encrypt_chunk_raw(&fk, b"legacy thumbnail bytes").unwrap();
        let got = decrypt_file_metadata(&m, id, "innocent.txt")
            .and_then(|meta| read(&m, id, meta.chunk_format, std::slice::from_ref(&forged_frame)));
        assert!(
            got.is_err(),
            "plaintext metadata + a same-key blob must not read as a file (got {} bytes)",
            got.map(|p| p.len()).unwrap_or(0)
        );
    }
}

/// Task 1908 review round 4 (independent re-review of 38e225d): writers honour
/// the file's recorded pin (I-1), the seal rule as a function (P2-1), name /
/// thumbnail separation through the public functions (P2-2) and the
/// pin-aware thumbnail writer (P2-4).
#[cfg(test)]
mod review_round4_tests {
    use super::*;
    use crate::encrypt::{
        METADATA_SEAL_WRITE, MetadataSeal, NAME_KEY_INFO, THUMBNAIL_KEY_INFO, decrypt_file_metadata,
        decrypt_file_metadata_with_key, decrypt_metadata, decrypt_name, decrypt_name_metadata, decrypt_thumbnail,
        encrypt_name_with_chunk_format, encrypt_thumbnail_for, metadata_seal_for,
    };
    use crate::kdf::derive_master_key;
    use beebeeb_types::{CipherSuite, EncryptedBlob};

    const CS: u64 = 16;

    fn mk() -> MasterKey {
        derive_master_key("round4-password", b"round4-salt-16by").unwrap()
    }

    fn pattern(len: usize, seed: u8) -> Vec<u8> {
        (0..len)
            .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
            .collect()
    }

    fn write(enc: &mut ChunkEncryptor, data: &[u8]) -> Vec<Vec<u8>> {
        data.chunks(CS as usize)
            .map(|c| enc.push_chunk(c).unwrap().data)
            .collect()
    }

    fn read(m: &MasterKey, id: &str, expected: ExpectedChunkFormat, frames: &[Vec<u8>]) -> Result<Vec<u8>, CoreError> {
        let mut dec = ChunkDecryptor::for_push(m, id, expected);
        let mut out = Vec::new();
        for f in frames {
            out.extend_from_slice(&dec.push_frame(f)?.data);
        }
        dec.finish()?;
        Ok(out)
    }

    /// HKDF-SHA256(salt = none, ikm = file key, info) computed with the hkdf
    /// crate directly — NOT through `kdf::derive_file_subkey` or the
    /// `derive_*_key` helpers, so a mutation of those helpers (or of which one
    /// a writer calls) cannot also move this reference key.
    fn independent_subkey(fk: &FileKey, info: &[u8]) -> FileKey {
        let hk = hkdf::Hkdf::<sha2::Sha256>::new(None, fk.as_bytes());
        let mut okm = [0u8; 32];
        hk.expand(info, &mut okm).unwrap();
        FileKey::from_bytes(okm)
    }

    /// Wrap a `nonce || ct || tag` frame as a native `name_encrypted` envelope.
    fn frame_as_envelope(frame: &[u8]) -> String {
        serde_json::to_string(&EncryptedBlob {
            cipher_suite: CipherSuite::V1Aes256Gcm,
            nonce: frame[..NONCE_LEN].to_vec(),
            ciphertext: frame[NONCE_LEN..].to_vec(),
        })
        .unwrap()
    }

    /// The `nonce || ct || tag` frame inside a native `name_encrypted` envelope.
    fn envelope_as_frame(envelope: &str) -> Vec<u8> {
        let blob: EncryptedBlob = serde_json::from_str(envelope).unwrap();
        let mut frame = blob.nonce.clone();
        frame.extend_from_slice(&blob.ciphertext);
        frame
    }

    // ── I-1: a replace / new version honours the file's recorded pin ────────

    #[test]
    fn i1_probe_default_writer_under_a_v2_pin_is_unreadable_documented() {
        // The reviewer's probe, kept as documentation of WHY the pin-aware
        // writer exists: a file whose metadata records v2 (written after the
        // switch) replaced by a client using the default writer (v1 during
        // the read-only phase). The server keeps the v2 metadata on replace,
        // so the new version is unreadable.
        assert_eq!(WRITE_FORMAT, ChunkFormat::V1Legacy);
        let m = mk();
        let id = "probe-v2-pinned";
        let name = encrypt_name_with_chunk_format(&m, id, "a.pdf", None, ExpectedChunkFormat::V2).unwrap();
        let pin = decrypt_file_metadata(&m, id, &name).unwrap().chunk_format;
        assert_eq!(pin, ExpectedChunkFormat::V2);
        let data = pattern(40, 1);
        let mut enc = ChunkEncryptor::for_push_with_chunk_size(&m, id, data.len() as u64, CS).unwrap();
        let frames = write(&mut enc, &data);
        assert!(read(&m, id, pin, &frames).is_err());
    }

    #[test]
    fn i1_replace_of_a_v2_pinned_file_with_the_recorded_pin_is_readable() {
        // The inverse of the probe: the replace takes the pin from the file's
        // metadata and builds its writer with `with_recorded_pin`. The new
        // version must read back under the same (server-kept) metadata.
        let m = mk();
        let id = "replace-v2-pinned";
        let name = encrypt_name_with_chunk_format(&m, id, "a.pdf", None, ExpectedChunkFormat::V2).unwrap();
        let pin = decrypt_file_metadata(&m, id, &name).unwrap().chunk_format;
        assert_eq!(pin, ExpectedChunkFormat::V2);
        let data = pattern(40, 2);
        let mut enc = ChunkEncryptor::for_push_with_chunk_size(&m, id, data.len() as u64, CS)
            .unwrap()
            .with_recorded_pin(pin)
            .unwrap();
        assert_eq!(
            enc.format(),
            ChunkFormat::V2,
            "a v2-pinned file must be written as v2 even in the read-only phase"
        );
        let frames = write(&mut enc, &data);
        enc.finish().unwrap();
        // The server did not touch name_encrypted on replace: the metadata
        // still opens and still pins v2, and the new version reads under it.
        let meta = decrypt_file_metadata(&m, id, &name).unwrap();
        assert_eq!(meta.name, "a.pdf");
        assert_eq!(
            read(&m, id, meta.chunk_format, &frames).expect("a replace written with the recorded pin must be readable"),
            data
        );

        // Pull form too.
        let mut pull = ChunkEncryptor::from_reader_with_chunk_size(
            &m,
            id,
            data.len() as u64,
            CS,
            std::io::Cursor::new(data.clone()),
        )
        .unwrap()
        .with_recorded_pin(pin)
        .unwrap();
        let mut pulled = Vec::new();
        while let Some(c) = pull.next_chunk().unwrap() {
            pulled.push(c.data);
        }
        assert_eq!(read(&m, id, pin, &pulled).unwrap(), data);
    }

    #[test]
    fn i1_unrecorded_pin_writes_the_write_format() {
        // Both arms of the rule: V2 -> V2 always; Unrecorded -> WRITE_FORMAT.
        assert_eq!(chunk_format_for_pin(ExpectedChunkFormat::V2), ChunkFormat::V2);
        assert_eq!(chunk_format_for_pin(ExpectedChunkFormat::Unrecorded), WRITE_FORMAT);
        let m = mk();
        let id = "replace-unrecorded";
        let data = pattern(20, 3);
        let mut enc = ChunkEncryptor::for_push_with_chunk_size(&m, id, data.len() as u64, CS)
            .unwrap()
            .with_recorded_pin(ExpectedChunkFormat::Unrecorded)
            .unwrap();
        assert_eq!(enc.format(), WRITE_FORMAT);
        let frames = write(&mut enc, &data);
        assert_eq!(read(&m, id, ExpectedChunkFormat::Unrecorded, &frames).unwrap(), data);
    }

    #[test]
    fn i1_recorded_pin_only_before_the_first_chunk() {
        let m = mk();
        let mut enc = ChunkEncryptor::for_push_with_chunk_size(&m, "late-pin", 40, CS).unwrap();
        enc.push_chunk(&[0u8; 16]).unwrap();
        assert!(
            enc.with_recorded_pin(ExpectedChunkFormat::V2).is_err(),
            "switching format after a frame was sealed would mix formats in one file"
        );
    }

    // ── P2-1: the seal rule, both arms ──────────────────────────────────────

    #[test]
    fn p2_1_metadata_seal_for_both_arms() {
        assert_eq!(metadata_seal_for(ChunkFormat::V1Legacy), MetadataSeal::Legacy);
        assert_eq!(
            metadata_seal_for(ChunkFormat::V2),
            MetadataSeal::Subkey,
            "the v2 write switch must flip names and thumbnails to their subkeys"
        );
        assert_eq!(METADATA_SEAL_WRITE, metadata_seal_for(WRITE_FORMAT));
    }

    // ── P2-2: name / thumbnail separation through the public functions ──────

    #[test]
    fn p2_2_subkey_sealed_thumbnail_wrapped_as_a_name_envelope_is_refused() {
        let m = mk();
        let id = "thumb-as-name";
        let fk = derive_file_key(&m, id.as_bytes());
        let name_shaped = br#"{"name":"evil.exe","mime_type":null}"#;

        // Control (proves the wrapping is a valid envelope): the LEGACY
        // raw-key thumbnail wrapped this way does open as a name — that is the
        // pre-switch residual (decision 1912), not something this test fixes.
        let legacy = crate::encrypt::encrypt_thumbnail_sealed(&fk, name_shaped, MetadataSeal::Legacy).unwrap();
        assert_eq!(decrypt_name(&m, id, &frame_as_envelope(&legacy)).unwrap(), "evil.exe");

        let thumb = encrypt_thumbnail_for(&fk, name_shaped, ExpectedChunkFormat::V2).unwrap();
        assert_eq!(decrypt_thumbnail(&fk, &thumb).unwrap(), name_shaped);
        let env = frame_as_envelope(&thumb);
        assert!(
            decrypt_file_metadata(&m, id, &env).is_err(),
            "a subkey-sealed thumbnail must not open as a file's metadata"
        );
        assert!(decrypt_file_metadata_with_key(&fk, &env).is_err());
        assert!(decrypt_name_metadata(&m, id, &env).is_err());
        assert!(
            decrypt_name(&m, id, &env).is_err(),
            "a subkey-sealed thumbnail must not open as a name"
        );
    }

    #[test]
    fn p2_2_v2_name_blob_is_not_a_thumbnail() {
        let m = mk();
        let id = "name-as-thumb";
        let fk = derive_file_key(&m, id.as_bytes());

        // Control: a legacy (raw-key) name opens through decrypt_thumbnail's
        // legacy fallback — the residual again, and proof the frame is valid.
        let legacy = crate::encrypt::encrypt_name(&m, id, "old.txt", None).unwrap();
        assert!(decrypt_thumbnail(&fk, &envelope_as_frame(&legacy)).is_ok());

        let v2 = encrypt_name_with_chunk_format(&m, id, "a.pdf", None, ExpectedChunkFormat::V2).unwrap();
        assert!(
            decrypt_thumbnail(&fk, &envelope_as_frame(&v2)).is_err(),
            "a v2 file's name envelope must not open as its thumbnail"
        );
    }

    #[test]
    fn p2_2_v2_name_opens_only_under_an_independently_derived_name_key() {
        let m = mk();
        let id = "name-key-independent";
        let fk = derive_file_key(&m, id.as_bytes());
        let env = encrypt_name_with_chunk_format(&m, id, "a.pdf", None, ExpectedChunkFormat::V2).unwrap();
        let blob: EncryptedBlob = serde_json::from_str(&env).unwrap();
        let pt = decrypt_metadata(&independent_subkey(&fk, b"beebeeb/name/v1"), &blob)
            .expect("a v2 name must be sealed under HKDF(file_key, \"beebeeb/name/v1\")");
        assert!(pt.contains("\"chunk_format\":2"), "{pt}");
        assert_eq!(NAME_KEY_INFO, b"beebeeb/name/v1");
        for other in [
            independent_subkey(&fk, b"beebeeb/thumb/v1"),
            independent_subkey(&fk, b"beebeeb/chunk/v2/key"),
            FileKey::from_bytes(*fk.as_bytes()),
        ] {
            assert!(decrypt_metadata(&other, &blob).is_err());
        }
    }

    // ── P2-4: thumbnails follow the pin like names ──────────────────────────

    #[test]
    fn p2_4_thumbnail_for_a_v2_pin_is_subkey_sealed() {
        let m = mk();
        let id = "thumb-v2-pin";
        let fk = derive_file_key(&m, id.as_bytes());
        let t = encrypt_thumbnail_for(&fk, b"\xff\xd8 thumb", ExpectedChunkFormat::V2).unwrap();
        assert!(
            open_raw_with_aad(&fk, &t, &[]).is_err(),
            "a v2-pinned file's thumbnail must not be sealed under the raw file key"
        );
        assert_eq!(
            open_raw_with_aad(&independent_subkey(&fk, b"beebeeb/thumb/v1"), &t, &[]).unwrap(),
            b"\xff\xd8 thumb"
        );
        assert_eq!(THUMBNAIL_KEY_INFO, b"beebeeb/thumb/v1");
        assert_eq!(decrypt_thumbnail(&fk, &t).unwrap(), b"\xff\xd8 thumb");
        assert!(read(&m, id, ExpectedChunkFormat::Unrecorded, &[t]).is_err());
    }

    #[test]
    fn p2_4_thumbnail_for_an_unrecorded_pin_follows_the_write_switch() {
        let m = mk();
        let fk = derive_file_key(&m, b"thumb-unrecorded");
        let t = encrypt_thumbnail_for(&fk, b"thumb", ExpectedChunkFormat::Unrecorded).unwrap();
        let raw_opens = open_raw_with_aad(&fk, &t, &[]).is_ok();
        assert_eq!(raw_opens, METADATA_SEAL_WRITE == MetadataSeal::Legacy);
        assert_eq!(decrypt_thumbnail(&fk, &t).unwrap(), b"thumb");
    }
}

/// Task 1908 review round 5 — file notes (spec 2026-10-17-1912 §6, lead
/// ruling 2026-10-17). Web sealed notes with `encrypt_metadata` under the RAW
/// file key, in the same envelope shape as a legacy name; a server could serve
/// such a note as a v2 file's metadata (it reads as a pin-less name) and then
/// as its only frame (a one-frame v1 "file"). Notes now have their own
/// subkey under the same seal rule as names and thumbnails.
#[cfg(test)]
mod review_round5_tests {
    use super::*;
    use crate::encrypt::{
        METADATA_SEAL_WRITE, MetadataSeal, NOTE_KEY_INFO, decrypt_file_metadata, decrypt_file_metadata_with_key,
        decrypt_metadata, decrypt_name, decrypt_name_metadata, decrypt_name_metadata_with_key, decrypt_name_with_key,
        decrypt_names, decrypt_note, decrypt_thumbnail, encrypt_metadata, encrypt_name_with_chunk_format, encrypt_note,
        encrypt_note_for, encrypt_note_sealed, encrypt_thumbnail_for,
    };
    use beebeeb_types::{CipherSuite, EncryptedBlob};

    const CS: u64 = 16;

    fn mk() -> MasterKey {
        // Fixed bytes instead of Argon2id: the attack does not depend on how
        // the master key was derived, and this keeps the module fast.
        MasterKey::from_bytes(std::array::from_fn(|i| (i as u8).wrapping_mul(7) ^ 0xa5))
    }

    fn pattern(len: usize, seed: u8) -> Vec<u8> {
        (0..len)
            .map(|i| (i as u8).wrapping_mul(37).wrapping_add(seed))
            .collect()
    }

    fn read(m: &MasterKey, id: &str, expected: ExpectedChunkFormat, frames: &[Vec<u8>]) -> Result<Vec<u8>, CoreError> {
        let mut dec = ChunkDecryptor::for_push(m, id, expected);
        let mut out = Vec::new();
        for f in frames {
            out.extend_from_slice(&dec.push_frame(f)?.data);
        }
        dec.finish()?;
        Ok(out)
    }

    /// A client reading a file: pin from the FILE metadata reader, then frames.
    fn read_file(m: &MasterKey, id: &str, name_encrypted: &str, frames: &[Vec<u8>]) -> Result<Vec<u8>, CoreError> {
        let meta = decrypt_file_metadata(m, id, name_encrypted)?;
        read(m, id, meta.chunk_format, frames)
    }

    /// A v2 file as a client on this core writes it: v2 frames + a name that
    /// records `chunk_format: 2`.
    fn v2_file(m: &MasterKey, id: &str, data: &[u8]) -> (String, Vec<Vec<u8>>) {
        let mut enc = ChunkEncryptor::for_push_with_chunk_size(m, id, data.len() as u64, CS)
            .unwrap()
            .with_format(ChunkFormat::V2)
            .unwrap();
        let frames: Vec<Vec<u8>> = data
            .chunks(CS as usize)
            .map(|c| enc.push_chunk(c).unwrap().data)
            .collect();
        let summary_format = enc.format();
        enc.finish().unwrap();
        let name = encrypt_name_with_chunk_format(
            m,
            id,
            "report.pdf",
            Some("application/pdf"),
            ExpectedChunkFormat::recorded_for(summary_format),
        )
        .unwrap();
        (name, frames)
    }

    /// The note web writes on c089a27 and today (`file-details-panel.tsx`
    /// ~247): `encrypt_metadata` under the RAW file key, serialized as the
    /// canonical envelope (`serializeEncryptedBlob`).
    fn web_raw_key_note(fk: &FileKey, text: &str) -> String {
        serde_json::to_string(&encrypt_metadata(fk, text).unwrap()).unwrap()
    }

    /// `nonce || ct || tag` inside a native envelope.
    fn envelope_as_frame(envelope: &str) -> Vec<u8> {
        let blob: EncryptedBlob = serde_json::from_str(envelope).unwrap();
        [blob.nonce, blob.ciphertext].concat()
    }

    /// A `nonce || ct || tag` frame wrapped as a native envelope.
    fn frame_as_envelope(frame: &[u8]) -> String {
        serde_json::to_string(&EncryptedBlob {
            cipher_suite: CipherSuite::V1Aes256Gcm,
            nonce: frame[..NONCE_LEN].to_vec(),
            ciphertext: frame[NONCE_LEN..].to_vec(),
        })
        .unwrap()
    }

    /// HKDF-SHA256 with the hkdf crate directly — not through
    /// `kdf::derive_file_subkey` / `derive_note_key`, so a mutation of those
    /// cannot also move this reference key.
    fn independent_subkey(fk: &FileKey, info: &[u8]) -> FileKey {
        let hk = hkdf::Hkdf::<sha2::Sha256>::new(None, fk.as_bytes());
        let mut okm = [0u8; 32];
        hk.expand(info, &mut okm).unwrap();
        FileKey::from_bytes(okm)
    }

    /// The downgrade: the server serves `note` as the file's `name_encrypted`
    /// AND the same blob as the file's only frame; the client reads it the way
    /// every client reads a file.
    fn serve_note_as_file(m: &MasterKey, id: &str, note: &str) -> Result<Vec<u8>, CoreError> {
        read_file(m, id, note, &[envelope_as_frame(note)])
    }

    #[test]
    fn raw_key_note_served_as_name_downgrades_v2_file() {
        let m = mk();
        let id = "v2-file-with-a-note";
        let data = pattern(40, 7);
        let (name, frames) = v2_file(&m, id, &data);
        assert_eq!(read_file(&m, id, &name, &frames).unwrap(), data);
        let fk = derive_file_key(&m, id.as_bytes());

        // Control (proves the instrument): a note sealed the way web seals it
        // (raw key) DOES downgrade this v2 file — the metadata reads as a
        // pin-less name and the note opens as a one-frame v1 file.
        let raw = web_raw_key_note(&fk, "meeting notes");
        assert_eq!(
            decrypt_file_metadata(&m, id, &raw).unwrap().chunk_format,
            ExpectedChunkFormat::Unrecorded
        );
        assert_eq!(
            serve_note_as_file(&m, id, &raw).expect("control: a raw-key note must reproduce the downgrade"),
            b"meeting notes"
        );

        // The fix: the note a client writes THROUGH CORE for this file, with
        // the pin read from the file's own authenticated metadata.
        let pin = decrypt_file_metadata(&m, id, &name).unwrap().chunk_format;
        assert_eq!(pin, ExpectedChunkFormat::V2);
        let note = encrypt_note_for(&fk, "meeting notes", pin).unwrap();
        assert_eq!(decrypt_note(&fk, &note).unwrap(), "meeting notes");
        let got = serve_note_as_file(&m, id, &note);
        assert!(
            got.is_err(),
            "a v2 file's note must not stand in for its metadata and content (got {} plaintext bytes)",
            got.map(|p| p.len()).unwrap_or(0)
        );
        // Share recipients (known file key) are covered too.
        assert!(decrypt_file_metadata_with_key(&fk, &note).is_err());
    }

    #[test]
    fn v2_note_never_opens_through_any_name_reader() {
        let m = mk();
        let id = "note-as-name";
        let fk = derive_file_key(&m, id.as_bytes());
        let name_shaped = r#"{"name":"evil.exe","mime_type":null,"chunk_format":2}"#;

        // Control: the legacy raw-key note with the same text DOES open as a
        // name (the pre-switch residual, decision 1912) — the wrapping is valid.
        assert_eq!(
            decrypt_name(&m, id, &web_raw_key_note(&fk, name_shaped)).unwrap(),
            "evil.exe"
        );

        let note = encrypt_note_for(&fk, name_shaped, ExpectedChunkFormat::V2).unwrap();
        assert!(decrypt_file_metadata(&m, id, &note).is_err(), "decrypt_file_metadata");
        assert!(
            decrypt_file_metadata_with_key(&fk, &note).is_err(),
            "decrypt_file_metadata_with_key"
        );
        assert!(decrypt_name_metadata(&m, id, &note).is_err(), "decrypt_name_metadata");
        assert!(
            decrypt_name_metadata_with_key(&fk, &note).is_err(),
            "decrypt_name_metadata_with_key"
        );
        assert!(decrypt_name(&m, id, &note).is_err(), "decrypt_name");
        assert!(decrypt_name_with_key(&fk, &note).is_none(), "decrypt_name_with_key");
        let uuid_id = uuid::Uuid::from_bytes([9; 16]);
        let fk_u = derive_file_key(&m, uuid_id.to_string().as_bytes());
        let note_u = encrypt_note_for(&fk_u, name_shaped, ExpectedChunkFormat::V2).unwrap();
        assert!(
            decrypt_names(&m, &[(uuid_id, note_u.as_str())])[0].is_err(),
            "decrypt_names"
        );
    }

    #[test]
    fn v2_note_never_opens_as_content() {
        let m = mk();
        let id = "note-as-content";
        let fk = derive_file_key(&m, id.as_bytes());
        let note = encrypt_note_for(&fk, "a note", ExpectedChunkFormat::V2).unwrap();
        let frame = envelope_as_frame(&note);
        for expected in [ExpectedChunkFormat::Unrecorded, ExpectedChunkFormat::V2] {
            let got = read(&m, id, expected, std::slice::from_ref(&frame));
            assert!(
                got.is_err(),
                "a v2 note must not open as a one-frame file under {expected:?} (got {} bytes)",
                got.map(|p| p.len()).unwrap_or(0)
            );
        }
        // Nor as the first frame of a real v2 file's stream.
        let (_, mut frames) = v2_file(&m, id, &pattern(32, 3));
        frames[0] = frame;
        assert!(read(&m, id, ExpectedChunkFormat::Unrecorded, &frames).is_err());
    }

    #[test]
    fn notes_names_and_thumbnails_never_open_as_each_other() {
        let m = mk();
        let id = "note-name-thumb";
        let fk = derive_file_key(&m, id.as_bytes());
        let note = encrypt_note_for(&fk, "a note", ExpectedChunkFormat::V2).unwrap();
        assert!(
            decrypt_thumbnail(&fk, &envelope_as_frame(&note)).is_err(),
            "a v2 note must not open as a thumbnail"
        );
        let name = encrypt_name_with_chunk_format(&m, id, "a.pdf", None, ExpectedChunkFormat::V2).unwrap();
        assert!(decrypt_note(&fk, &name).is_err(), "a v2 name must not open as a note");
        let thumb = encrypt_thumbnail_for(&fk, b"thumb", ExpectedChunkFormat::V2).unwrap();
        assert!(
            decrypt_note(&fk, &frame_as_envelope(&thumb)).is_err(),
            "a v2 thumbnail must not open as a note"
        );
        let (_, frames) = v2_file(&m, id, &pattern(20, 9));
        assert!(
            decrypt_note(&fk, &frame_as_envelope(&frames[0])).is_err(),
            "a v2 content frame must not open as a note"
        );
    }

    #[test]
    fn v2_note_opens_only_under_an_independently_derived_note_key() {
        let fk = derive_file_key(&mk(), b"note-key-independent");
        let note = encrypt_note_for(&fk, "only under the note key", ExpectedChunkFormat::V2).unwrap();
        let blob: EncryptedBlob = serde_json::from_str(&note).unwrap();
        assert_eq!(
            decrypt_metadata(&independent_subkey(&fk, b"beebeeb/note/v1"), &blob)
                .expect("a v2 note must be sealed under HKDF(file_key, \"beebeeb/note/v1\")"),
            "only under the note key"
        );
        assert_eq!(NOTE_KEY_INFO, b"beebeeb/note/v1");
        for other in [
            independent_subkey(&fk, b"beebeeb/name/v1"),
            independent_subkey(&fk, b"beebeeb/thumb/v1"),
            independent_subkey(&fk, b"beebeeb/chunk/v2/key"),
            FileKey::from_bytes(*fk.as_bytes()),
        ] {
            assert!(decrypt_metadata(&other, &blob).is_err());
        }
    }

    #[test]
    fn note_subkey_known_answer() {
        // HKDF-SHA256(salt = none, ikm = 00..1f, info = "beebeeb/note/v1"),
        // computed independently (Python hmac/hashlib, RFC 5869 by hand; the
        // same script reproduces the name and thumbnail KATs).
        let fk = FileKey::from_bytes(std::array::from_fn(|i| i as u8));
        assert_eq!(
            hex::encode(crate::encrypt::derive_note_key(&fk).as_bytes()),
            "763d4d38632f509d75366d1262cb35b1c999339e0ce03c54403ed9ed4fdfe247"
        );
    }

    #[test]
    fn note_subkey_is_distinct_from_every_other_file_key() {
        let fk = FileKey::from_bytes(std::array::from_fn(|i| (i as u8) ^ 0x3c));
        let note = crate::encrypt::derive_note_key(&fk);
        for (what, other) in [
            ("raw", FileKey::from_bytes(*fk.as_bytes())),
            ("name", crate::encrypt::derive_name_key(&fk)),
            ("thumb", crate::encrypt::derive_thumbnail_key(&fk)),
            ("chunk", derive_chunk_key_v2(&fk)),
        ] {
            assert_ne!(note.as_bytes(), other.as_bytes(), "note key == {what} key");
        }
    }

    #[test]
    fn legacy_raw_key_notes_still_open() {
        let fk = derive_file_key(&mk(), b"legacy-note");
        // Canonical shape, exactly what web stores today.
        assert_eq!(
            decrypt_note(&fk, &web_raw_key_note(&fk, "old note")).unwrap(),
            "old note"
        );
        // Older web base64 `{nonce, ciphertext}` shape.
        let blob = encrypt_metadata(&fk, "older note").unwrap();
        let b64 = crate::metadata_wire::serialize_encrypted_metadata(&blob.nonce, &blob.ciphertext);
        assert_eq!(decrypt_note(&fk, &b64).unwrap(), "older note");
        // Crate-internal Legacy seal = the same bytes shape.
        let legacy = encrypt_note_sealed(&fk, "x", MetadataSeal::Legacy).unwrap();
        assert_eq!(decrypt_note(&fk, &legacy).unwrap(), "x");
        // Wrong key, plaintext and garbage are errors, never a note.
        let other = derive_file_key(&mk(), b"another-file");
        assert!(decrypt_note(&other, &web_raw_key_note(&fk, "old note")).is_err());
        assert!(decrypt_note(&fk, "a plaintext note").is_err());
        assert!(decrypt_note(&fk, "{\"nonce\":1}").is_err());
    }

    #[test]
    fn note_roundtrip_and_wire_shape_for_both_pins() {
        let fk = derive_file_key(&mk(), b"note-roundtrip");
        let text = "Notitie — 会議 \u{1F41D} \"quoted\"\nline 2";
        for pin in [ExpectedChunkFormat::Unrecorded, ExpectedChunkFormat::V2] {
            let note = encrypt_note_for(&fk, text, pin).unwrap();
            assert_eq!(decrypt_note(&fk, &note).unwrap(), text, "{pin:?}");
            // The canonical envelope web's parseEncryptedBlob already reads.
            let v: serde_json::Value = serde_json::from_str(&note).unwrap();
            assert_eq!(v["cipher_suite"], "V1Aes256Gcm");
            assert!(v["nonce"].is_array() && v["ciphertext"].is_array());
        }
        assert_eq!(decrypt_note(&fk, &encrypt_note(&fk, text).unwrap()).unwrap(), text);
    }

    #[test]
    fn note_for_an_unrecorded_pin_follows_the_write_switch() {
        let fk = derive_file_key(&mk(), b"note-unrecorded");
        let raw_opens = |note: &str| {
            let blob: EncryptedBlob = serde_json::from_str(note).unwrap();
            decrypt_metadata(&fk, &blob).is_ok()
        };
        let legacy_now = METADATA_SEAL_WRITE == MetadataSeal::Legacy;
        assert_eq!(
            raw_opens(&encrypt_note_for(&fk, "n", ExpectedChunkFormat::Unrecorded).unwrap()),
            legacy_now
        );
        assert_eq!(raw_opens(&encrypt_note(&fk, "n").unwrap()), legacy_now);
        assert!(
            !raw_opens(&encrypt_note_for(&fk, "n", ExpectedChunkFormat::V2).unwrap()),
            "a v2-pinned file's note must not be sealed under the raw file key"
        );
    }

    /// The vector-nonce seam refuses what it would otherwise get wrong
    /// silently: a v1 writer (v1 frames draw their own nonce), a count that is
    /// not one nonce per frame (the rest would be random), a nonce twice
    /// (AES-GCM nonce reuse under one key), and a format switched back to v1
    /// after the nonces were set.
    #[test]
    fn vector_nonces_are_v2_only_one_per_frame_and_distinct() {
        let m = mk();
        // 71 bytes in 32-byte chunks: 3 frames.
        let v2 = || {
            ChunkEncryptor::for_push_with_chunk_size(&m, "vn", 71, 32)
                .unwrap()
                .with_format(ChunkFormat::V2)
                .unwrap()
        };
        let three = vec![[1u8; NONCE_LEN], [2u8; NONCE_LEN], [3u8; NONCE_LEN]];

        let v1 = ChunkEncryptor::for_push_with_chunk_size(&m, "vn", 71, 32)
            .unwrap()
            .with_format(ChunkFormat::V1Legacy)
            .unwrap();
        assert!(v1.with_vector_nonces(three.clone()).is_err(), "v1 writer");
        assert!(v2().with_vector_nonces(three[..2].to_vec()).is_err(), "too few");
        let mut four = three.clone();
        four.push([4u8; NONCE_LEN]);
        assert!(v2().with_vector_nonces(four).is_err(), "too many");
        let dup = vec![[1u8; NONCE_LEN], [2u8; NONCE_LEN], [1u8; NONCE_LEN]];
        assert!(v2().with_vector_nonces(dup).is_err(), "a nonce twice");

        let mut back_to_v1 = v2()
            .with_vector_nonces(three.clone())
            .unwrap()
            .with_format(ChunkFormat::V1Legacy)
            .unwrap();
        assert!(back_to_v1.push_chunk(&[0u8; 32]).is_err(), "nonces dropped on v1");

        let mut ok = v2().with_vector_nonces(three.clone()).unwrap();
        let data: Vec<u8> = (0..71u8).collect();
        for (i, part) in data.chunks(32).enumerate() {
            let frame = ok.push_chunk(part).unwrap();
            assert_eq!(&frame.data[..NONCE_LEN], &three[i], "frame {i} uses its vector nonce");
        }
        ok.finish().unwrap();
    }
}
