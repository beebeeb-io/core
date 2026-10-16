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
//! - **v2**: AAD = `"beebeeb/chunk/v2" || u32_be(len(file_id)) || file_id ||
//!   u32_be(index) || u8(is_last)` (STREAM construction). See
//!   [`chunk_aad_v2`] and the crate-private `StreamOpener` for the binding and the decrypt rules.
//!
//! [`ChunkEncryptor`] writes [`WRITE_FORMAT`]; [`ChunkDecryptor`] reads both,
//! deciding the format from what frame 0 authenticates under (never from a
//! server field) and locking it for the rest of the file.
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
use crate::encrypt::{NONCE_LEN, TAG_LEN, open_raw_with_aad, seal_raw_with_aad};
use crate::kdf::{FileKey, MasterKey, derive_file_key};

/// Per-chunk AEAD overhead on the wire: `nonce(12) + tag(16)`.
const CHUNK_OVERHEAD: u64 = (NONCE_LEN + TAG_LEN) as u64;

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
//      || u32_be(chunk_index)           0-based
//      || u8(is_last)                   1 on the final chunk, else 0
//
// The AAD is never transmitted: the decryptor rebuilds it from what it already
// knows (the file id it asked for, the index it expects next). So it cannot be
// "stripped": opening a v2 frame with the empty v1 AAD fails the tag.

/// Domain-separation tag (and format version) at the start of every v2 AAD.
pub const CHUNK_AAD_DOMAIN_V2: &[u8; 16] = b"beebeeb/chunk/v2";

/// The on-the-wire chunk format of a file. The frame layout is identical; the
/// formats differ only in the AES-GCM associated data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChunkFormat {
    /// Legacy: no associated data, no position binding. Readable forever for
    /// files written before task 1908; no longer written by default.
    V1Legacy,
    /// Position-bound: AAD = domain tag || file id || chunk index || last flag.
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
pub const WRITE_FORMAT: ChunkFormat = ChunkFormat::V2;

/// Build the v2 associated data for one chunk. Public so the layout can be
/// pinned by a known-answer test and inspected by reviewers; clients never need
/// to call it (seal/open happen in core).
pub fn chunk_aad_v2(file_id: &[u8], index: u32, is_last: bool) -> Vec<u8> {
    let mut aad = Vec::with_capacity(CHUNK_AAD_DOMAIN_V2.len() + 4 + file_id.len() + 4 + 1);
    aad.extend_from_slice(CHUNK_AAD_DOMAIN_V2);
    // File ids are UUID strings (36 bytes); anything near u32::MAX is absurd,
    // and saturating keeps this infallible without making the encoding ambiguous
    // for any id that could actually exist.
    aad.extend_from_slice(&u32::try_from(file_id.len()).unwrap_or(u32::MAX).to_be_bytes());
    aad.extend_from_slice(file_id);
    aad.extend_from_slice(&index.to_be_bytes());
    aad.push(u8::from(is_last));
    aad
}

/// Seal one chunk in `format`. v1 ignores `file_id` / `index` / `is_last`.
fn seal_chunk(
    file_key: &FileKey,
    format: ChunkFormat,
    file_id: &[u8],
    index: u32,
    is_last: bool,
    plaintext: &[u8],
) -> Result<Vec<u8>, CoreError> {
    match format {
        ChunkFormat::V1Legacy => seal_raw_with_aad(file_key, plaintext, &[]),
        ChunkFormat::V2 => seal_raw_with_aad(file_key, plaintext, &chunk_aad_v2(file_id, index, is_last)),
    }
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
/// `format` must be the file's format as already established from
/// authenticated data (a [`ChunkDecryptor`] that opened chunk 0, or a version
/// recorded in the encrypted file metadata) — never from a server field.
/// For [`ChunkFormat::V1Legacy`] the position arguments are ignored (v1 binds
/// nothing).
pub fn open_chunk(
    file_key: &FileKey,
    file_id: &str,
    index: u32,
    is_last: bool,
    format: ChunkFormat,
    frame: &[u8],
) -> Result<Vec<u8>, CoreError> {
    match format {
        ChunkFormat::V1Legacy => open_raw_with_aad(file_key, frame, &[]),
        ChunkFormat::V2 => open_raw_with_aad(file_key, frame, &chunk_aad_v2(file_id.as_bytes(), index, is_last)),
    }
}

/// Sequential STREAM-open state, shared by [`ChunkDecryptor`] (which owns its
/// key) and the legacy borrowed-key disk helpers in `encrypt` (which do not).
///
/// Rules, in order:
/// 1. Nothing may follow the frame that authenticated as last.
/// 2. Frame `i` is opened ONLY at index `i` (the next expected index).
/// 3. The file's format is decided by frame 0 and then locked: v2 if frame 0
///    authenticates under the v2 AAD, else v1 if it authenticates with none
///    (unless the caller pinned a format). A v2 file can never continue as v1
///    and vice versa.
/// 4. In v2, [`finish`](Self::finish) fails unless the last frame was seen —
///    truncation detection. v1 has no last marker; it cannot detect truncation
///    (the legacy weakness this task fixes for new files).
pub(crate) struct StreamOpener {
    file_id: Vec<u8>,
    next_index: u32,
    pinned: Option<ChunkFormat>,
    format: Option<ChunkFormat>,
    seen_last: bool,
}

impl StreamOpener {
    pub(crate) fn new(file_id: &str) -> Self {
        Self {
            file_id: file_id.as_bytes().to_vec(),
            next_index: 0,
            pinned: None,
            format: None,
            seen_last: false,
        }
    }

    /// Pin the expected format (from authenticated metadata). Only before the
    /// first frame — the lock must not change mid-stream.
    pub(crate) fn expect_format(&mut self, format: ChunkFormat) -> Result<(), CoreError> {
        if self.next_index != 0 {
            return Err(CoreError::InvalidInput(
                "expect_format must be called before the first frame".into(),
            ));
        }
        self.pinned = Some(format);
        Ok(())
    }

    pub(crate) fn format(&self) -> Option<ChunkFormat> {
        self.format
    }

    pub(crate) fn frames_opened(&self) -> u32 {
        self.next_index
    }

    /// Try the v2 AAD at the expected index: `is_last = false` first (every
    /// frame but one), then `is_last = true`. Returns `(plaintext, is_last)`.
    fn try_v2(&self, key: &FileKey, frame: &[u8]) -> Option<(Vec<u8>, bool)> {
        for is_last in [false, true] {
            let aad = chunk_aad_v2(&self.file_id, self.next_index, is_last);
            if let Ok(pt) = open_raw_with_aad(key, frame, &aad) {
                return Some((pt, is_last));
            }
        }
        None
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

        let (data, format, is_last) = match self.format.or(self.pinned) {
            Some(ChunkFormat::V2) => {
                let (pt, last) = self.try_v2(key, frame).ok_or(CoreError::Decryption)?;
                (pt, ChunkFormat::V2, last)
            }
            Some(ChunkFormat::V1Legacy) => (open_raw_with_aad(key, frame, &[])?, ChunkFormat::V1Legacy, false),
            None => {
                // Frame 0, nothing pinned: detect. v2 first — a v2 frame never
                // opens as v1 (its tag covers the AAD), and a v1 frame never
                // opens as v2, so the answer is unambiguous.
                if let Some((pt, last)) = self.try_v2(key, frame) {
                    (pt, ChunkFormat::V2, last)
                } else {
                    (open_raw_with_aad(key, frame, &[])?, ChunkFormat::V1Legacy, false)
                }
            }
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
    /// crate-internal caller overrides it before the first chunk).
    format: ChunkFormat,
    /// The exact bytes the file key was derived from (bound into the v2 AAD).
    file_id: Vec<u8>,
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
        })
    }

    /// Override the written format — test-only (v1 fixtures, v2 attack tests
    /// independent of [`WRITE_FORMAT`]). Clients always get [`WRITE_FORMAT`].
    /// Only before the first chunk, so a file can never mix formats.
    #[cfg(test)]
    pub(crate) fn with_format(mut self, format: ChunkFormat) -> Result<Self, CoreError> {
        if self.emitted_chunks != 0 {
            return Err(CoreError::InvalidInput(
                "with_format must be called before the first chunk".into(),
            ));
        }
        self.format = format;
        Ok(self)
    }

    /// The format this encryptor writes. Clients that record the format in the
    /// encrypted file metadata (to pin it on read) take it from here.
    pub fn format(&self) -> ChunkFormat {
        self.format
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
        let data = seal_chunk(&self.file_key, self.format, &self.file_id, index, is_last, plaintext)?;
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
/// Reads v2 (position-bound) and v1 (legacy) files. The format is decided by
/// the first frame — whichever AAD it authenticates under — and locked for the
/// rest of the stream; see `StreamOpener` for the full rules. In v2 every frame
/// must be the next index in order, nothing may follow the last chunk, and the
/// stream must reach its last chunk: call [`finish`](Self::finish) (push form)
/// or read to `Ok(None)` (pull form, which runs the same check at EOF).
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
        Ok(Self {
            file_key,
            opener: StreamOpener::new(file_id),
            source: DecSource::Pull(Box::new(reader)),
            buf: Zeroizing::new(vec![0u8; frame_len]),
        })
    }

    /// **Push** constructor: the caller feeds wire frames via
    /// [`push_frame`](Self::push_frame). Infallible — no buffer is allocated and
    /// no chunk size is needed (each frame is self-describing).
    pub fn for_push(mk: &MasterKey, file_id: &str) -> Self {
        Self::for_push_with_file_key(derive_file_key(mk, file_id.as_bytes()), file_id)
    }

    /// **Push** constructor from an already-derived/unwrapped [`FileKey`] — for
    /// callers that hold the file key but not the owner's master key (shared-link
    /// and share recipients, file-request content keys). `file_id` must be the
    /// id the file was uploaded under (it is bound into every v2 frame).
    pub fn for_push_with_file_key(file_key: FileKey, file_id: &str) -> Self {
        Self {
            file_key,
            opener: StreamOpener::new(file_id),
            source: DecSource::Push,
            buf: Zeroizing::new(Vec::new()),
        }
    }

    /// Pin the format the file must have, taken from authenticated data (e.g. a
    /// version recorded in the encrypted file metadata). With a pin, a v2 file
    /// cannot be served as v1 even if v1 frames exist under the same key.
    /// Must be called before the first frame.
    pub fn expect_format(&mut self, format: ChunkFormat) -> Result<(), CoreError> {
        self.opener.expect_format(format)
    }

    /// The file's format once frame 0 has been opened (`None` before).
    pub fn format(&self) -> Option<ChunkFormat> {
        self.opener.format()
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
        let mut dec = ChunkDecryptor::for_push(master, file_id);
        let mut out = Vec::new();
        for f in frames {
            out.extend_from_slice(&dec.push_frame(&f.data).unwrap().data);
        }
        out
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
        let mut dec = ChunkDecryptor::for_push(&wrong, "secret");
        assert!(matches!(dec.push_frame(&frames[0].data), Err(CoreError::Decryption)));

        // Right master key, wrong file_id.
        let mut dec2 = ChunkDecryptor::for_push(&m, "other-file");
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

        let mut dec = ChunkDecryptor::from_reader(&m, "decpull", chunk_size, Cursor::new(body)).unwrap();
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
        let err = ChunkDecryptor::from_reader(&m, "z", 0, Cursor::new(Vec::new())).unwrap_err();
        assert!(matches!(err, CoreError::InvalidInput(_)));
    }

    #[test]
    fn decryptor_rejects_truncated_frame() {
        let m = mk();
        let mut dec = ChunkDecryptor::for_push(&m, "trunc");
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
    fn new_output_is_v2_and_does_not_open_via_legacy_decrypt_chunk_raw() {
        // Task 1908 (justified inversion): until 1908 this asserted that new
        // frames open with the legacy no-AAD `decrypt_chunk_raw` ("wire format
        // unchanged"). New frames are now v2 — same layout and sizes, but the
        // position is in the GCM AAD — so the legacy open MUST fail (downgrade
        // resistance) while the shared decryptor reads them.
        let m = mk();
        let data = pattern(9 * MIB);
        let (frames, _) = encrypt_all(&m, "legacy", &data, ChunkProfile::Desktop);
        let file_key = derive_file_key(&m, b"legacy");
        for f in &frames {
            assert!(decrypt_chunk_raw(&file_key, &f.data).is_err());
            assert_eq!(f.data.len(), frames_len_for(&data, f.index));
        }
        assert_eq!(decrypt_frames(&m, "legacy", &frames), data);
    }

    /// Frame length is plaintext + 28 in both formats (layout unchanged).
    fn frames_len_for(data: &[u8], index: u32) -> usize {
        let start = index as usize * 4 * MIB;
        (data.len() - start).min(4 * MIB) + NONCE_LEN + TAG_LEN
    }

    #[test]
    fn default_write_format_is_v2() {
        assert_eq!(WRITE_FORMAT, ChunkFormat::V2);
        let m = mk();
        let enc = ChunkEncryptor::for_push(&m, "fmt", 10, ChunkProfile::Web).unwrap();
        assert_eq!(enc.format(), ChunkFormat::V2);
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

    /// Push every frame in order; the stream is accepted only if every frame
    /// decrypts AND the decryptor's end-of-stream check passes.
    fn push_all(m: &MasterKey, file_id: &str, frames: &[Vec<u8>]) -> Result<Vec<u8>, CoreError> {
        let mut dec = ChunkDecryptor::for_push(m, file_id);
        let mut out = Vec::new();
        for f in frames {
            out.extend_from_slice(&dec.push_frame(f)?.data);
        }
        dec.finish()?;
        Ok(out)
    }

    /// Pull-form decrypt of a contiguous body (the download path).
    fn pull_all(m: &MasterKey, file_id: &str, frames: &[Vec<u8>]) -> Result<Vec<u8>, CoreError> {
        let body: Vec<u8> = frames.concat();
        let mut dec = ChunkDecryptor::from_reader(m, file_id, CS, Cursor::new(body))?;
        let mut out = Vec::new();
        while let Some(c) = dec.next_chunk()? {
            out.extend_from_slice(&c.data);
        }
        Ok(out)
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

        let mut right = ChunkDecryptor::for_push_with_file_key(FileKey::from_bytes(key_bytes), "owner-id");
        for f in &frames {
            right.push_frame(f).unwrap();
        }
        right.finish().unwrap();

        let mut wrong = ChunkDecryptor::for_push_with_file_key(FileKey::from_bytes(key_bytes), "other-id");
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
            assert_eq!(push_all(&m, "legacy", &frames).unwrap(), data, "push len {len}");
            assert_eq!(pull_all(&m, "legacy", &frames).unwrap(), data, "pull len {len}");
            let mut dec = ChunkDecryptor::for_push(&m, "legacy");
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

        let mut dec = ChunkDecryptor::for_push_with_file_key(FileKey::from_bytes(key), "any-id");
        let pt = dec.push_frame(&frame).unwrap().data;
        assert_eq!(pt, hex("plaintext_hex"));
        let summary = dec.finish().unwrap();
        assert_eq!(summary.format, ChunkFormat::V1Legacy);
        assert_eq!(summary.chunk_count, 1);
    }

    #[test]
    fn pinned_format_rejects_the_other_format() {
        let m = mk();
        let data = pattern(40, 16);
        let v1 = v1_frames(&m, "pin", &data);
        let v2 = v2_frames(&m, "pin", &data);

        // Pinned v2 (from authenticated metadata): a v1 copy is refused.
        let mut dec = ChunkDecryptor::for_push(&m, "pin");
        dec.expect_format(ChunkFormat::V2).unwrap();
        assert!(dec.push_frame(&v1[0]).is_err());

        // Pinned v1: a v2 file is refused (no silent cross-format open).
        let mut dec = ChunkDecryptor::for_push(&m, "pin");
        dec.expect_format(ChunkFormat::V1Legacy).unwrap();
        assert!(dec.push_frame(&v2[0]).is_err());

        // Pinned correctly: both open.
        let mut dec = ChunkDecryptor::for_push(&m, "pin");
        dec.expect_format(ChunkFormat::V2).unwrap();
        for f in &v2 {
            dec.push_frame(f).unwrap();
        }
        assert_eq!(dec.finish().unwrap().format, ChunkFormat::V2);

        // The pin cannot move mid-stream.
        let mut dec = ChunkDecryptor::for_push(&m, "pin");
        dec.push_frame(&v2[0]).unwrap();
        assert!(dec.expect_format(ChunkFormat::V1Legacy).is_err());
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
        let aad = chunk_aad_v2(b"abc", 0x0102_0304, true);
        let mut expect = b"beebeeb/chunk/v2".to_vec();
        expect.extend_from_slice(&[0, 0, 0, 3]);
        expect.extend_from_slice(b"abc");
        expect.extend_from_slice(&[1, 2, 3, 4]);
        expect.push(1);
        assert_eq!(aad, expect);
        assert_eq!(chunk_aad_v2(b"abc", 0x0102_0304, false).last(), Some(&0));
        assert_eq!(aad.len(), 16 + 4 + 3 + 4 + 1);
    }

    #[test]
    fn open_chunk_random_access() {
        let m = mk();
        let data = pattern(64, 18);
        let frames = v2_frames(&m, "seek", &data);
        let fk = derive_file_key(&m, b"seek");
        // Correct position: opens, in any order (seeking).
        for i in [2u32, 0, 3, 1] {
            let last = i == 3;
            let pt = open_chunk(&fk, "seek", i, last, ChunkFormat::V2, &frames[i as usize]).unwrap();
            assert_eq!(pt, data[i as usize * 16..(i as usize + 1) * 16]);
        }
        // Server answers a request for chunk 1 with chunk 2: fails.
        assert!(open_chunk(&fk, "seek", 1, false, ChunkFormat::V2, &frames[2]).is_err());
        // Server under-reports the count so the client thinks 2 is last: fails.
        assert!(open_chunk(&fk, "seek", 2, true, ChunkFormat::V2, &frames[2]).is_err());
        // Server over-reports: the real last chunk is not accepted as non-last.
        assert!(open_chunk(&fk, "seek", 3, false, ChunkFormat::V2, &frames[3]).is_err());
        // Wrong format argument: a v2 frame never opens as v1.
        assert!(open_chunk(&fk, "seek", 0, false, ChunkFormat::V1Legacy, &frames[0]).is_err());
        // v1 files: position arguments are ignored.
        let v1 = v1_frames(&m, "seek", &data);
        assert_eq!(
            open_chunk(&fk, "seek", 99, true, ChunkFormat::V1Legacy, &v1[1]).unwrap(),
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
