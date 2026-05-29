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
//! ## Wire format (unchanged)
//!
//! Every frame is `nonce(12) || ciphertext || tag(16)` with a fresh random
//! nonce per chunk — byte-for-byte the format produced by
//! [`crate::encrypt::encrypt_chunk_raw`]. Output is therefore roundtrip
//! compatible with every existing file; it is **not** byte-identical to a
//! previous encryption because the nonce is random, which is intentional.
//!
//! ## Sync, reactor-agnostic
//!
//! Core stays synchronous — no tokio. [`ChunkEncryptor`] and [`ChunkDecryptor`]
//! are `Send`, so a caller can move one into a blocking thread (e.g. the CLI's
//! `spawn_blocking`) and keep AES off the async reactor.

use std::io::Read;

use zeroize::Zeroizing;

use beebeeb_types::{
    ChunkPlan, ChunkProfile, ChunkStrategy, STORAGE_FORMAT_VERSION_V2, plan_chunks,
};

use crate::CoreError;
use crate::encrypt::{NONCE_LEN, TAG_LEN, decrypt_chunk_raw, encrypt_chunk_raw};
use crate::kdf::{FileKey, MasterKey, derive_file_key};

/// Per-chunk AEAD overhead on the wire: `nonce(12) + tag(16)`.
const CHUNK_OVERHEAD: u64 = (NONCE_LEN + TAG_LEN) as u64;

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
    pub fn for_push(
        mk: &MasterKey,
        file_id: &str,
        file_size: u64,
        profile: ChunkProfile,
    ) -> Result<Self, CoreError> {
        let plan = plan_chunks(file_size, profile);
        Self::new(mk, file_id, plan, Source::Push)
    }

    /// **Push** constructor with an explicit, server-dictated chunk size.
    ///
    /// Closes the plan-divergence gap when a v2 server overrides `chunk_size` at
    /// init: the caller passes the exact size the server expects rather than
    /// relying on the client ladder. Returns `Err` if `chunk_size_bytes == 0`,
    /// the derived `chunk_count` does not fit in `u32`, or the size does not fit
    /// in `usize`.
    pub fn for_push_with_chunk_size(
        mk: &MasterKey,
        file_id: &str,
        file_size: u64,
        chunk_size_bytes: u64,
    ) -> Result<Self, CoreError> {
        if chunk_size_bytes == 0 {
            return Err(CoreError::InvalidInput(
                "chunk_size_bytes must be positive".into(),
            ));
        }
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

    /// Shared constructor body: validates the plan, derives the key once, sizes
    /// the read buffer (pull only).
    fn new(
        mk: &MasterKey,
        file_id: &str,
        plan: ChunkPlan,
        source: Source,
    ) -> Result<Self, CoreError> {
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
        })
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
        let data = encrypt_chunk_raw(&self.file_key, plaintext)?;
        let index = self.next_index;
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
pub struct ChunkDecryptor {
    /// Derived once; `ZeroizeOnDrop` wipes it when this struct drops.
    file_key: FileKey,
    /// Index of the next chunk to emit.
    next_index: u32,
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
            return Err(CoreError::InvalidInput(
                "chunk_size_bytes must be positive".into(),
            ));
        }
        let chunk_size: usize = chunk_size_bytes.try_into().map_err(|_| {
            CoreError::InvalidInput(format!(
                "chunk_size_bytes {chunk_size_bytes} exceeds usize range"
            ))
        })?;
        let frame_len = NONCE_LEN
            .checked_add(chunk_size)
            .and_then(|v| v.checked_add(TAG_LEN))
            .ok_or_else(|| {
                CoreError::InvalidInput("chunk_size_bytes overflows frame length".into())
            })?;

        let file_key = derive_file_key(mk, file_id.as_bytes());
        Ok(Self {
            file_key,
            next_index: 0,
            source: DecSource::Pull(Box::new(reader)),
            buf: Zeroizing::new(vec![0u8; frame_len]),
        })
    }

    /// **Push** constructor: the caller feeds wire frames via
    /// [`push_frame`](Self::push_frame). Infallible — no buffer is allocated and
    /// no chunk size is needed (each frame is self-describing).
    pub fn for_push(mk: &MasterKey, file_id: &str) -> Self {
        let file_key = derive_file_key(mk, file_id.as_bytes());
        Self {
            file_key,
            next_index: 0,
            source: DecSource::Push,
            buf: Zeroizing::new(Vec::new()),
        }
    }

    /// The single crypto point shared by pull and push. Decrypts one wire frame.
    fn decrypt_frame_internal(&mut self, frame: &[u8]) -> Result<DecryptedChunk, CoreError> {
        if frame.len() < NONCE_LEN + TAG_LEN {
            return Err(CoreError::Decryption);
        }
        let data = decrypt_chunk_raw(&self.file_key, frame)?;
        let index = self.next_index;
        self.next_index += 1;
        Ok(DecryptedChunk { index, data })
    }

    /// **Pull** the next decrypted chunk. Reads up to one full frame; returns
    /// `Ok(None)` at clean EOF. A trailing partial frame (the last chunk) is
    /// decrypted normally; a frame shorter than `nonce + tag` is rejected.
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
            Ok(0) => Ok(None), // clean EOF
            Ok(n) => self.decrypt_frame_internal(&buf[..n]).map(Some),
            Err(e) => Err(e),
        };
        self.buf = buf; // restore (capacity retained for reuse)
        result
    }

    /// **Push** one wire frame (`nonce || ciphertext || tag`) for decryption.
    pub fn push_frame(&mut self, frame: &[u8]) -> Result<DecryptedChunk, CoreError> {
        self.decrypt_frame_internal(frame)
    }
}

impl std::fmt::Debug for ChunkDecryptor {
    /// Deliberately omits the file key, source, and buffer — never log key
    /// material or plaintext.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChunkDecryptor")
            .field("next_index", &self.next_index)
            .finish_non_exhaustive()
    }
}

/// Read exactly `buf.len()` bytes, or fewer if EOF is reached first.
/// Returns the number of bytes actually read. `Interrupted` errors retry.
///
/// `pub(crate)` and defined once here: the single source of truth for the
/// `chunk_stream` / `file_encrypt` streaming read loop.
pub(crate) fn read_exact_or_eof(
    reader: &mut dyn Read,
    buf: &mut [u8],
) -> Result<usize, CoreError> {
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
        let mut enc = ChunkEncryptor::from_reader(
            master,
            file_id,
            data.len() as u64,
            profile,
            Cursor::new(data.to_vec()),
        )
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
        let enc =
            ChunkEncryptor::from_reader(&m, "e", 0, ChunkProfile::Desktop, Cursor::new(Vec::new()))
                .unwrap();
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
        assert!(matches!(
            dec.push_frame(&frames[0].data),
            Err(CoreError::Decryption)
        ));

        // Right master key, wrong file_id.
        let mut dec2 = ChunkDecryptor::for_push(&m, "other-file");
        assert!(matches!(
            dec2.push_frame(&frames[0].data),
            Err(CoreError::Decryption)
        ));
    }

    #[test]
    fn push_form_equals_pull_form() {
        let m = mk();
        let data = pattern(9 * MIB);

        // Pull
        let (pull_frames, _) = encrypt_all(&m, "pp", &data, ChunkProfile::Desktop);

        // Push, caller slicing by the plan's chunk size.
        let mut push = ChunkEncryptor::for_push(&m, "pp", data.len() as u64, ChunkProfile::Desktop)
            .unwrap();
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
        let mut enc = ChunkEncryptor::from_reader(
            &m,
            "shrink",
            declared,
            ChunkProfile::Desktop,
            Cursor::new(actual),
        )
        .unwrap();
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
        let mut enc = ChunkEncryptor::from_reader(
            &m,
            "early",
            data.len() as u64,
            ChunkProfile::Desktop,
            Cursor::new(data),
        )
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
        let mut enc = ChunkEncryptor::from_reader(
            &m,
            "grow",
            declared,
            ChunkProfile::Desktop,
            Cursor::new(bigger.clone()),
        )
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
        let err2 = ChunkEncryptor::for_push(&m, "huge", u64::MAX, ChunkProfile::Desktop)
            .unwrap_err();
        assert!(matches!(err2, CoreError::InvalidInput(_)));
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

        let mut dec =
            ChunkDecryptor::from_reader(&m, "decpull", chunk_size, Cursor::new(body)).unwrap();
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
        let mut enc =
            ChunkEncryptor::from_reader(&m, "huge", eight_gib, ChunkProfile::Desktop, reader)
                .unwrap();

        // Desktop ladder: 8 GiB is in (1 GiB, 10 GiB] -> 16 MiB chunks.
        let plan = enc.chunk_plan();
        assert_eq!(plan.chunk_size_bytes, 16 * MIB as u64);
        assert_eq!(plan.chunk_count, eight_gib / (16 * MIB as u64)); // 512
        assert_eq!(
            enc.expected_total_ciphertext(),
            eight_gib + 28 * plan.chunk_count
        );

        // The read buffer is sized to the chunk, NOT the 8 GiB file.
        let cap_before = enc.buf.capacity();
        assert_eq!(cap_before, 16 * MIB);

        // Pull a handful of chunks — enough to prove the buffer is reused and
        // never grows, and that no read ever exceeds the chunk size.
        for _ in 0..8 {
            let c = enc.next_chunk().unwrap().unwrap();
            assert_eq!(c.data.len(), 16 * MIB + 28);
            assert_eq!(
                enc.buf.capacity(),
                cap_before,
                "read buffer capacity must not grow"
            );
            assert!(
                max_read.load(Ordering::SeqCst) <= 16 * MIB,
                "no single read may exceed the chunk size"
            );
        }

        // We consumed only 8 * 16 MiB = 128 MiB of the 8 GiB stream.
        assert_eq!(total.load(Ordering::SeqCst), 8 * (16 * MIB as u64));
    }

    #[test]
    fn new_output_decrypts_via_legacy_decrypt_chunk_raw() {
        // Frames from the new primitive must decrypt with the pre-existing
        // low-level decrypt_chunk_raw (proves the wire format is unchanged).
        let m = mk();
        let data = pattern(9 * MIB);
        let (frames, _) = encrypt_all(&m, "legacy", &data, ChunkProfile::Desktop);
        let file_key = derive_file_key(&m, b"legacy");
        let mut out = Vec::new();
        for f in &frames {
            out.extend_from_slice(&decrypt_chunk_raw(&file_key, &f.data).unwrap());
        }
        assert_eq!(out, data);
    }
}
