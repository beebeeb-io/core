//! Local seals: the recovery snapshot of an unsaved document and the per-session scratch stream.
//!
//! Contract: `docs/superpowers/specs/2026-11-18-local-snapshot-and-scratch-seal.md`. This module does no
//! file I/O of its own (the snapshot functions take and return bytes; the scratch types wrap a caller's
//! `Read` / `Write`). The engine writes the files, replaces them atomically and deletes them.
//!
//! * **Recovery snapshot** ([`seal_recovery_snapshot`], [`open_recovery_snapshot`]): one AES-256-GCM frame
//!   under a key derived from the account key and the file id with its own labels, never the file key.
//! * **Scratch** ([`ScratchKey`], [`ScratchWriter`], [`ScratchReader`], [`verify_scratch`]): a random key per
//!   account session that exists only in memory, and a framed stream whose every frame is bound to its
//!   header, position and finality.
//!
//! Nothing here is exported to `beebeeb-uniffi` or `beebeeb-wasm`: no key bytes may cross an FFI boundary.

use std::io::{self, Read, Write};

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::CoreError;
use crate::chunk_stream::MAX_CHUNK_SIZE;
use crate::encrypt::{NONCE_LEN, TAG_LEN, open_raw_with_aad, random_nonce, seal_raw_with_nonce};
use crate::item_id::item_class;
use crate::kdf::{FileKey, MasterKey, derive_file_subkey};

/// HKDF `info` prefix of the recovery-snapshot key (`|| file id`, under the account key).
pub const SNAPSHOT_KEY_LABEL: &[u8] = b"beebeeb-local-snapshot-v1";
/// AES-GCM associated-data prefix of a recovery snapshot.
pub const SNAPSHOT_AAD_LABEL: &[u8] = b"beebeeb-local-snapshot-aad-v1";
/// HKDF `info` prefix of a per-file scratch key (`|| scratch id`, under the session scratch key).
pub const SCRATCH_KEY_LABEL: &[u8] = b"beebeeb-scratch-chunk-key-v1";
/// AES-GCM associated-data prefix of a scratch frame.
pub const SCRATCH_AAD_LABEL: &[u8] = b"beebeeb-scratch-chunk-aad-v1";

/// Largest plaintext of one recovery snapshot. The app's own save cap must not exceed it (the engine
/// asserts that at compile time).
pub const MAX_SNAPSHOT_BYTES: usize = 256 * 1024 * 1024;
const _: () = assert!(MAX_SNAPSHOT_BYTES as u64 <= MAX_CHUNK_SIZE);

const SNAPSHOT_MAGIC: &[u8; 4] = b"BBSN";
const SNAPSHOT_VERSION: u8 = 1;
/// magic(4) || version(1) || kind(1) || base_version(8) || saved_at(8)
const SNAPSHOT_HEADER_LEN: usize = 22;
const SNAPSHOT_MIN_LEN: usize = SNAPSHOT_HEADER_LEN + NONCE_LEN + TAG_LEN;
const KIND_DOCX: u8 = 1;
const KIND_PPTX: u8 = 3;

/// What a snapshot says about itself: the file version the edits start from, when it was written (unix
/// seconds) and the document kind (1 docx, 2 xlsx, 3 pptx).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SnapshotMeta {
    pub base_version: i64,
    pub saved_at: i64,
    pub kind: u8,
}

fn check_meta(meta: &SnapshotMeta) -> Result<(), CoreError> {
    if !(KIND_DOCX..=KIND_PPTX).contains(&meta.kind) {
        return Err(CoreError::InvalidInput(format!("unknown snapshot kind {}", meta.kind)));
    }
    if meta.base_version < 0 || meta.saved_at < 0 {
        return Err(CoreError::InvalidInput(
            "snapshot base_version and saved_at must not be negative".into(),
        ));
    }
    Ok(())
}

fn snapshot_header(meta: &SnapshotMeta) -> [u8; SNAPSHOT_HEADER_LEN] {
    let mut h = [0u8; SNAPSHOT_HEADER_LEN];
    h[0..4].copy_from_slice(SNAPSHOT_MAGIC);
    h[4] = SNAPSHOT_VERSION;
    h[5] = meta.kind;
    h[6..14].copy_from_slice(&meta.base_version.to_be_bytes());
    h[14..22].copy_from_slice(&meta.saved_at.to_be_bytes());
    h
}

/// The key of one file's recovery snapshot: `HKDF-SHA256(salt = none, ikm = account key,
/// info = SNAPSHOT_KEY_LABEL || file id)`. A local key: `FileKey` is only the carrier type the raw AEAD
/// takes. Module-private on purpose, so nothing outside this module can use it as a content key.
fn derive_snapshot_key(master: &MasterKey, file_id: &str) -> Result<FileKey, CoreError> {
    // Owner and foreign ids both pass; anything that is not a canonical id is refused.
    item_class(file_id)?;
    let hk = Hkdf::<Sha256>::new(None, master.as_bytes());
    let mut info = Vec::with_capacity(SNAPSHOT_KEY_LABEL.len() + file_id.len());
    info.extend_from_slice(SNAPSHOT_KEY_LABEL);
    info.extend_from_slice(file_id.as_bytes());
    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(&info, &mut *okm)
        .expect("HKDF-SHA256 expand for 32 bytes cannot fail");
    Ok(FileKey::from_bytes(*okm))
}

fn snapshot_aad(file_id: &str, meta: &SnapshotMeta) -> Vec<u8> {
    let mut aad = Vec::with_capacity(SNAPSHOT_AAD_LABEL.len() + 4 + file_id.len() + 8 + 8 + 2);
    aad.extend_from_slice(SNAPSHOT_AAD_LABEL);
    aad.extend_from_slice(&(file_id.len() as u32).to_be_bytes());
    aad.extend_from_slice(file_id.as_bytes());
    aad.extend_from_slice(&meta.base_version.to_be_bytes());
    aad.extend_from_slice(&meta.saved_at.to_be_bytes());
    aad.push(meta.kind);
    aad.push(SNAPSHOT_VERSION);
    aad
}

fn seal_snapshot_with_nonce(
    master: &MasterKey,
    file_id: &str,
    meta: &SnapshotMeta,
    plaintext: &[u8],
    nonce: &[u8; NONCE_LEN],
) -> Result<Vec<u8>, CoreError> {
    check_meta(meta)?;
    if plaintext.len() > MAX_SNAPSHOT_BYTES {
        return Err(CoreError::InvalidInput(format!(
            "snapshot of {} bytes exceeds the {MAX_SNAPSHOT_BYTES}-byte limit",
            plaintext.len()
        )));
    }
    let key = derive_snapshot_key(master, file_id)?;
    let frame = seal_raw_with_nonce(&key, nonce, plaintext, &snapshot_aad(file_id, meta))?;
    let mut out = Vec::with_capacity(SNAPSHOT_HEADER_LEN + frame.len());
    out.extend_from_slice(&snapshot_header(meta));
    out.extend_from_slice(&frame);
    Ok(out)
}

/// Seal an unsaved document: `header(22) || nonce(12) || ciphertext || tag(16)`, so the blob is exactly
/// `plaintext.len() + 50` bytes. The file id is bound into the tag but not stored: the caller names the
/// blob's file and folder by it, and a blob moved to another file's slot does not open.
pub fn seal_recovery_snapshot(
    master: &MasterKey,
    file_id: &str,
    meta: &SnapshotMeta,
    plaintext: &[u8],
) -> Result<Vec<u8>, CoreError> {
    seal_snapshot_with_nonce(master, file_id, meta, plaintext, &random_nonce())
}

/// Known-answer seam: a caller-chosen nonce. Never compiled into a shipped build.
#[cfg(any(test, feature = "test-support"))]
pub fn seal_recovery_snapshot_with_nonce(
    master: &MasterKey,
    file_id: &str,
    meta: &SnapshotMeta,
    plaintext: &[u8],
    nonce: &[u8; NONCE_LEN],
) -> Result<Vec<u8>, CoreError> {
    seal_snapshot_with_nonce(master, file_id, meta, plaintext, nonce)
}

/// Open a snapshot sealed for `file_id` under `master`. Returns the meta it authenticated (the only meta
/// a decision may use) and the plaintext. Magic, version and kind are checked first (`InvalidInput`);
/// a wrong key, another file id, a changed byte or a truncated blob is `Decryption`.
pub fn open_recovery_snapshot(
    master: &MasterKey,
    file_id: &str,
    sealed: &[u8],
) -> Result<(SnapshotMeta, Zeroizing<Vec<u8>>), CoreError> {
    let meta = peek_snapshot_meta(sealed)?;
    let key = derive_snapshot_key(master, file_id)?;
    if sealed.len() < SNAPSHOT_MIN_LEN {
        return Err(CoreError::Decryption);
    }
    if sealed.len() - SNAPSHOT_MIN_LEN > MAX_SNAPSHOT_BYTES {
        return Err(CoreError::InvalidInput("snapshot exceeds the size limit".into()));
    }
    let plaintext = open_raw_with_aad(&key, &sealed[SNAPSHOT_HEADER_LEN..], &snapshot_aad(file_id, &meta))?;
    Ok((meta, Zeroizing::new(plaintext)))
}

/// Read the header of a snapshot blob: magic, version, kind and the two numbers. Opens nothing and needs
/// no key, so the result is **unauthenticated**: use it for display only (a restore prompt line such as
/// "unsaved changes from 14:32"), never to decide what to restore, replace or delete. Decisions use the
/// meta that [`open_recovery_snapshot`] returns.
pub fn peek_snapshot_meta(sealed: &[u8]) -> Result<SnapshotMeta, CoreError> {
    if sealed.len() < SNAPSHOT_HEADER_LEN {
        return Err(CoreError::InvalidInput("snapshot header is truncated".into()));
    }
    if &sealed[0..4] != SNAPSHOT_MAGIC {
        return Err(CoreError::InvalidInput("not a recovery snapshot".into()));
    }
    if sealed[4] != SNAPSHOT_VERSION {
        return Err(CoreError::InvalidInput(format!(
            "unsupported snapshot version {}",
            sealed[4]
        )));
    }
    let meta = SnapshotMeta {
        kind: sealed[5],
        base_version: i64::from_be_bytes(sealed[6..14].try_into().expect("8 bytes")),
        saved_at: i64::from_be_bytes(sealed[14..22].try_into().expect("8 bytes")),
    };
    check_meta(&meta)?;
    Ok(meta)
}

// ─── Scratch ────────────────────────────────────────────────────────────────

/// Smallest scratch chunk: with the 4 GiB file cap a file is at most 65 536 frames.
pub const MIN_SCRATCH_CHUNK: u32 = 64 * 1024;
/// Default scratch chunk size.
pub const DEFAULT_SCRATCH_CHUNK: u32 = 1024 * 1024;
/// Largest plaintext of one scratch file.
pub const MAX_SCRATCH_BYTES: u64 = 4 * 1024 * 1024 * 1024;
/// A document the host spilled out of memory.
pub const SCRATCH_PURPOSE_SPILL: u8 = 1;
/// A staged save payload awaiting upload.
pub const SCRATCH_PURPOSE_STAGED_SAVE: u8 = 2;

const SCRATCH_MAGIC: &[u8; 4] = b"BBSC";
const SCRATCH_VERSION: u8 = 1;
/// magic(4) || version(1) || purpose(1) || chunk_size(4) || scratch_id(16)
const SCRATCH_HEADER_LEN: usize = 26;
const FRAME_OVERHEAD: usize = NONCE_LEN + TAG_LEN;

/// The random key of one account session, held in memory only. It is never derived from an account key,
/// is not `Clone`, prints as `ScratchKey(..)`, has no byte accessor and no serialise path, and is wiped
/// on drop. Create it when an account session starts; drop it (and delete the session's scratch files) on
/// sign-out, account switch and lock.
///
/// ```
/// use beebeeb_core::local_seal::ScratchKey;
/// let key = ScratchKey::generate().unwrap();
/// assert_eq!(format!("{key:?}"), "ScratchKey(..)");
/// ```
///
/// There is no way to read the bytes back:
///
/// ```compile_fail
/// use beebeeb_core::local_seal::ScratchKey;
/// let key = ScratchKey::generate().unwrap();
/// let _ = key.as_bytes();
/// ```
///
/// ```compile_fail
/// use beebeeb_core::local_seal::ScratchKey;
/// let key = ScratchKey::generate().unwrap();
/// let _ = key.to_bytes();
/// ```
///
/// It cannot be copied:
///
/// ```compile_fail
/// use beebeeb_core::local_seal::ScratchKey;
/// let key = ScratchKey::generate().unwrap();
/// let _copy = key.clone();
/// ```
///
/// It cannot be serialised:
///
/// ```compile_fail
/// use beebeeb_core::local_seal::ScratchKey;
/// let key = ScratchKey::generate().unwrap();
/// let _ = serde_json::to_string(&key);
/// ```
///
/// It cannot be built from bytes:
///
/// ```compile_fail
/// use beebeeb_core::local_seal::ScratchKey;
/// let _key = ScratchKey::from([0u8; 32]);
/// ```
#[derive(ZeroizeOnDrop)]
pub struct ScratchKey {
    key: FileKey,
}

impl ScratchKey {
    /// 32 bytes from the OS CSPRNG.
    pub fn generate() -> Result<Self, CoreError> {
        Ok(Self {
            key: FileKey::generate()?,
        })
    }

    /// Known-answer seam for vectors. Never compiled into a shipped build.
    #[cfg(any(test, feature = "test-support"))]
    pub fn for_vectors(bytes: [u8; 32]) -> Self {
        Self {
            key: FileKey::from_bytes(bytes),
        }
    }

    /// `HKDF-SHA256(salt = none, ikm = scratch key, info = SCRATCH_KEY_LABEL || scratch_id)`.
    fn file_key(&self, scratch_id: &[u8; 16]) -> FileKey {
        let mut info = Vec::with_capacity(SCRATCH_KEY_LABEL.len() + 16);
        info.extend_from_slice(SCRATCH_KEY_LABEL);
        info.extend_from_slice(scratch_id);
        derive_file_subkey(&self.key, &info)
    }
}

impl std::fmt::Debug for ScratchKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ScratchKey(..)")
    }
}

fn check_purpose(purpose: u8) -> Result<(), CoreError> {
    if purpose == SCRATCH_PURPOSE_SPILL || purpose == SCRATCH_PURPOSE_STAGED_SAVE {
        Ok(())
    } else {
        Err(CoreError::InvalidInput(format!("unknown scratch purpose {purpose}")))
    }
}

fn check_chunk(chunk_size: u32, min_chunk: u32) -> Result<(), CoreError> {
    if chunk_size < min_chunk || u64::from(chunk_size) > MAX_CHUNK_SIZE {
        return Err(CoreError::InvalidInput(format!(
            "scratch chunk size {chunk_size} is outside {min_chunk}..={MAX_CHUNK_SIZE}"
        )));
    }
    Ok(())
}

fn frame_aad(header: &[u8; SCRATCH_HEADER_LEN], index: u32, is_final: bool) -> Vec<u8> {
    let mut aad = Vec::with_capacity(SCRATCH_AAD_LABEL.len() + SCRATCH_HEADER_LEN + 5);
    aad.extend_from_slice(SCRATCH_AAD_LABEL);
    aad.extend_from_slice(header);
    aad.extend_from_slice(&index.to_be_bytes());
    aad.push(u8::from(is_final));
    aad
}

fn to_io(e: CoreError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e)
}

/// Writes a scratch file: a 26-byte header, then frames of `chunk_size` plaintext bytes. One chunk is held
/// back so the last frame is sealed as final; a document whose length is a multiple of `chunk_size` ends in
/// one full final frame. Call [`finish`](Self::finish): a writer dropped without it leaves a file with no
/// final frame, which never opens.
pub struct ScratchWriter<W: Write> {
    out: W,
    key: FileKey,
    header: [u8; SCRATCH_HEADER_LEN],
    chunk: usize,
    buf: Zeroizing<Vec<u8>>,
    index: u32,
    total: u64,
    failed: bool,
    #[cfg(any(test, feature = "test-support"))]
    nonces: Option<std::collections::VecDeque<[u8; NONCE_LEN]>>,
}

impl<W: Write> ScratchWriter<W> {
    /// Start a file for `purpose` (1 spill, 2 staged save) with a fresh random `scratch_id` and write its
    /// header to `out`.
    pub fn new(key: &ScratchKey, out: W, purpose: u8, chunk_size: u32) -> Result<Self, CoreError> {
        let mut id = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut id);
        Self::start(key, out, purpose, chunk_size, MIN_SCRATCH_CHUNK, id)
    }

    fn start(
        key: &ScratchKey,
        mut out: W,
        purpose: u8,
        chunk_size: u32,
        min_chunk: u32,
        scratch_id: [u8; 16],
    ) -> Result<Self, CoreError> {
        check_purpose(purpose)?;
        check_chunk(chunk_size, min_chunk)?;
        let mut header = [0u8; SCRATCH_HEADER_LEN];
        header[0..4].copy_from_slice(SCRATCH_MAGIC);
        header[4] = SCRATCH_VERSION;
        header[5] = purpose;
        header[6..10].copy_from_slice(&chunk_size.to_be_bytes());
        header[10..26].copy_from_slice(&scratch_id);
        out.write_all(&header).map_err(|e| CoreError::Io(e.to_string()))?;
        let chunk = chunk_size as usize;
        Ok(Self {
            out,
            key: key.file_key(&scratch_id),
            header,
            chunk,
            buf: Zeroizing::new(Vec::with_capacity(chunk)),
            index: 0,
            total: 0,
            failed: false,
            #[cfg(any(test, feature = "test-support"))]
            nonces: None,
        })
    }

    /// Known-answer seam: fixed scratch id, a queue of frame nonces and a lowered chunk floor. Never
    /// compiled into a shipped build.
    #[cfg(any(test, feature = "test-support"))]
    pub fn with_vector_params(
        key: &ScratchKey,
        out: W,
        purpose: u8,
        chunk_size: u32,
        min_chunk: u32,
        scratch_id: [u8; 16],
        nonces: Vec<[u8; NONCE_LEN]>,
    ) -> Result<Self, CoreError> {
        let mut w = Self::start(key, out, purpose, chunk_size, min_chunk, scratch_id)?;
        w.nonces = Some(nonces.into());
        Ok(w)
    }

    /// The id of this file; it is in the header and in every frame's associated data.
    pub fn scratch_id(&self) -> [u8; 16] {
        self.header[10..26].try_into().expect("16 bytes")
    }

    fn next_nonce(&mut self) -> [u8; NONCE_LEN] {
        #[cfg(any(test, feature = "test-support"))]
        if let Some(q) = self.nonces.as_mut() {
            return q.pop_front().expect("vector nonce queue exhausted");
        }
        random_nonce()
    }

    fn seal_frame(&mut self, is_final: bool) -> Result<(), CoreError> {
        let index = self.index;
        let nonce = self.next_nonce();
        let frame = seal_raw_with_nonce(&self.key, &nonce, &self.buf, &frame_aad(&self.header, index, is_final))?;
        self.out.write_all(&frame).map_err(|e| CoreError::Io(e.to_string()))?;
        self.buf.zeroize();
        if !is_final {
            self.index = index
                .checked_add(1)
                .ok_or_else(|| CoreError::InvalidInput("scratch file has too many frames".into()))?;
        }
        Ok(())
    }

    /// Seal the final frame and return the sink and the number of plaintext bytes written.
    pub fn finish(mut self) -> Result<(W, u64), CoreError> {
        if self.failed {
            return Err(CoreError::InvalidInput("scratch writer failed earlier".into()));
        }
        self.seal_frame(true)?;
        self.out.flush().map_err(|e| CoreError::Io(e.to_string()))?;
        Ok((self.out, self.total))
    }
}

impl<W: Write> Write for ScratchWriter<W> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if self.failed {
            return Err(to_io(CoreError::InvalidInput("scratch writer failed earlier".into())));
        }
        if data.is_empty() {
            return Ok(0);
        }
        if self.total.saturating_add(data.len() as u64) > MAX_SCRATCH_BYTES {
            return Err(to_io(CoreError::InvalidInput(format!(
                "scratch file exceeds {MAX_SCRATCH_BYTES} bytes"
            ))));
        }
        // The chunk is sealed only when more data arrives, so the last one can be sealed as final.
        if self.buf.len() == self.chunk {
            if let Err(e) = self.seal_frame(false) {
                self.failed = true;
                return Err(match e {
                    CoreError::Io(m) => io::Error::other(m),
                    other => to_io(other),
                });
            }
        }
        let take = (self.chunk - self.buf.len()).min(data.len());
        self.buf.extend_from_slice(&data[..take]);
        self.total += take as u64;
        Ok(take)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Reads a scratch file one frame at a time. A frame's plaintext is released only after that frame
/// authenticated, but a cut or extended file is known only at the end: a consumer that publishes the
/// payload MUST NOT use any of it until a full read ended in `Ok`, and discards all of it on any `Err`.
/// Errors surface as `io::Error` (kind `InvalidData`) wrapping the [`CoreError`].
pub struct ScratchReader<R: Read> {
    input: R,
    key: FileKey,
    header: [u8; SCRATCH_HEADER_LEN],
    chunk: usize,
    index: u32,
    plain: Zeroizing<Vec<u8>>,
    pos: usize,
    lookahead: Option<u8>,
    done: bool,
    failed: bool,
}

struct ParsedHeader {
    raw: [u8; SCRATCH_HEADER_LEN],
    chunk: u32,
    id: [u8; 16],
}

fn read_header<R: Read>(
    input: &mut R,
    expected_purpose: u8,
    expected_id: Option<&[u8; 16]>,
    min_chunk: u32,
) -> Result<ParsedHeader, CoreError> {
    check_purpose(expected_purpose)?;
    let mut raw = [0u8; SCRATCH_HEADER_LEN];
    input.read_exact(&mut raw).map_err(|e| {
        if e.kind() == io::ErrorKind::UnexpectedEof {
            CoreError::InvalidInput("scratch header is truncated".into())
        } else {
            CoreError::Io(e.to_string())
        }
    })?;
    if &raw[0..4] != SCRATCH_MAGIC {
        return Err(CoreError::InvalidInput("not a scratch file".into()));
    }
    if raw[4] != SCRATCH_VERSION {
        return Err(CoreError::InvalidInput(format!(
            "unsupported scratch version {}",
            raw[4]
        )));
    }
    check_purpose(raw[5])?;
    let chunk = u32::from_be_bytes(raw[6..10].try_into().expect("4 bytes"));
    check_chunk(chunk, min_chunk)?;
    let id: [u8; 16] = raw[10..26].try_into().expect("16 bytes");
    if raw[5] != expected_purpose {
        return Err(CoreError::Decryption);
    }
    if let Some(expected) = expected_id {
        if &id != expected {
            return Err(CoreError::Decryption);
        }
    }
    Ok(ParsedHeader { raw, chunk, id })
}

impl<R: Read> ScratchReader<R> {
    /// Read and check the header. `expected_id` is the id [`verify_scratch`] returned (or the writer
    /// reported): another file, even a valid one of the same session, is `Decryption`. A purpose that is
    /// not 1 or 2, a bad magic or version or a chunk size outside the bounds is `InvalidInput`; a known
    /// purpose other than `expected_purpose` is `Decryption`.
    pub fn new(key: &ScratchKey, input: R, expected_purpose: u8, expected_id: &[u8; 16]) -> Result<Self, CoreError> {
        Self::open(key, input, expected_purpose, Some(expected_id), MIN_SCRATCH_CHUNK)
    }

    /// Known-answer seam: a lowered chunk floor. Never compiled into a shipped build.
    #[cfg(any(test, feature = "test-support"))]
    pub fn with_min_chunk(
        key: &ScratchKey,
        input: R,
        expected_purpose: u8,
        expected_id: &[u8; 16],
        min_chunk: u32,
    ) -> Result<Self, CoreError> {
        Self::open(key, input, expected_purpose, Some(expected_id), min_chunk)
    }

    fn open(
        key: &ScratchKey,
        mut input: R,
        expected_purpose: u8,
        expected_id: Option<&[u8; 16]>,
        min_chunk: u32,
    ) -> Result<Self, CoreError> {
        let h = read_header(&mut input, expected_purpose, expected_id, min_chunk)?;
        Ok(Self::from_header(key, input, h))
    }

    fn from_header(key: &ScratchKey, input: R, h: ParsedHeader) -> Self {
        Self {
            input,
            key: key.file_key(&h.id),
            header: h.raw,
            chunk: h.chunk as usize,
            index: 0,
            plain: Zeroizing::new(Vec::new()),
            pos: 0,
            lookahead: None,
            done: false,
            failed: false,
        }
    }

    /// The id of the file being read.
    pub fn scratch_id(&self) -> [u8; 16] {
        self.header[10..26].try_into().expect("16 bytes")
    }

    fn load_frame(&mut self) -> Result<(), CoreError> {
        let full = self.chunk + FRAME_OVERHEAD;
        // The buffer grows with the bytes that are really there, so a hostile chunk size in a header
        // allocates nothing beyond the file.
        let mut raw: Vec<u8> = Vec::new();
        if let Some(b) = self.lookahead.take() {
            raw.push(b);
        }
        let want = (full - raw.len()) as u64;
        (&mut self.input)
            .take(want)
            .read_to_end(&mut raw)
            .map_err(|e| CoreError::Io(e.to_string()))?;
        if raw.len() < FRAME_OVERHEAD {
            // A file cut before the final frame, or never finished.
            return Err(CoreError::Decryption);
        }
        let is_final = if raw.len() < full {
            true
        } else {
            let mut one = [0u8; 1];
            match self.input.read(&mut one) {
                Ok(0) => true,
                Ok(_) => {
                    self.lookahead = Some(one[0]);
                    false
                }
                Err(e) => return Err(CoreError::Io(e.to_string())),
            }
        };
        let aad = frame_aad(&self.header, self.index, is_final);
        let plain = open_raw_with_aad(&self.key, &raw, &aad)?;
        self.plain = Zeroizing::new(plain);
        self.pos = 0;
        if is_final {
            self.done = true;
        } else {
            self.index = self.index.checked_add(1).ok_or(CoreError::Decryption)?;
        }
        Ok(())
    }
}

impl<R: Read> Read for ScratchReader<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.failed {
            return Err(to_io(CoreError::Decryption));
        }
        if out.is_empty() {
            return Ok(0);
        }
        while self.pos >= self.plain.len() {
            if self.done {
                return Ok(0);
            }
            if let Err(e) = self.load_frame() {
                self.failed = true;
                self.plain.zeroize();
                return Err(match e {
                    CoreError::Io(m) => io::Error::other(m),
                    other => to_io(other),
                });
            }
        }
        let n = out.len().min(self.plain.len() - self.pos);
        out[..n].copy_from_slice(&self.plain[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

/// What [`verify_scratch`] learned from one full authenticating pass.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifiedScratch {
    pub plaintext_len: u64,
    pub scratch_id: [u8; 16],
}

fn verify_with(
    key: &ScratchKey,
    mut input: impl Read,
    expected_purpose: u8,
    min_chunk: u32,
) -> Result<VerifiedScratch, CoreError> {
    let h = read_header(&mut input, expected_purpose, None, min_chunk)?;
    let scratch_id = h.id;
    let mut reader = ScratchReader::from_header(key, input, h);
    let mut sink = Zeroizing::new(vec![0u8; 64 * 1024]);
    let mut plaintext_len = 0u64;
    loop {
        match reader.read(&mut sink) {
            Ok(0) => break,
            Ok(n) => plaintext_len += n as u64,
            Err(e) => {
                return Err(match e.get_ref().and_then(|inner| inner.downcast_ref::<CoreError>()) {
                    Some(CoreError::Decryption) => CoreError::Decryption,
                    Some(CoreError::InvalidInput(m)) => CoreError::InvalidInput(m.clone()),
                    _ => CoreError::Io(e.to_string()),
                });
            }
        }
    }
    Ok(VerifiedScratch {
        plaintext_len,
        scratch_id,
    })
}

/// One full authenticating pass over a scratch file that keeps nothing: checks every frame, the final
/// flag and the end of file, and returns the plaintext length and the file's `scratch_id`. For a staged
/// save, run it first, then start the upload pass with a [`ScratchReader`] built with the returned id, and
/// commit only after that second pass ended in `Ok`.
pub fn verify_scratch<R: Read>(key: &ScratchKey, input: R, expected_purpose: u8) -> Result<VerifiedScratch, CoreError> {
    verify_with(key, input, expected_purpose, MIN_SCRATCH_CHUNK)
}

/// Known-answer seam: a lowered chunk floor. Never compiled into a shipped build.
#[cfg(any(test, feature = "test-support"))]
pub fn verify_scratch_with_min_chunk<R: Read>(
    key: &ScratchKey,
    input: R,
    expected_purpose: u8,
    min_chunk: u32,
) -> Result<VerifiedScratch, CoreError> {
    verify_with(key, input, expected_purpose, min_chunk)
}

#[cfg(test)]
mod tests;
