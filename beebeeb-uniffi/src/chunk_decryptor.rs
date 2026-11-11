//! Stateful streaming decryptor handle. Moved out of `lib.rs` when its
//! constructors began to take the decrypted metadata (crypto review,
//! P2-4): every constructor applies the version commitment the record carries.

use std::sync::{Arc, Mutex, MutexGuard};

use beebeeb_core::chunk_stream::{ChunkDecryptor, ChunkFormat, ExpectedChunkFormat, VersionCommitment};
use beebeeb_core::encrypt::{self, NameMetadata};
use beebeeb_core::kdf;
use zeroize::Zeroizing;

use crate::{
    ChunkDecryptorSummaryDto, CryptoError, DecryptedChunkDto, EncryptedChunkData, FileKeyHandle, MasterKeyHandle,
    NameMetadataDto, file_key_from_slice, version_commitment_from_parts,
};

/// Lock a handle's state. A poisoned lock (a panic while the handle was in
/// use) leaves the state untrusted: it is dropped (a key is wiped, an
/// encryptor or decryptor ends), so nothing more is written or released
/// through it, and the call fails instead of panicking across FFI.
pub(crate) fn lock_handle<T>(mutex: &Mutex<Option<T>>) -> Result<MutexGuard<'_, Option<T>>, CryptoError> {
    mutex.lock().map_err(|poisoned| {
        *poisoned.into_inner() = None;
        CryptoError::InvalidInput {
            detail: "the handle failed while in use and cannot be used again".into(),
        }
    })
}

/// The format pin and commitment a content reader enforces. A record with a
/// commitment binds frame 0 to it. A record with neither field is legacy
/// metadata: it opens v1 content only, and a `chunk_format: 2` record without
/// a commitment is refused here (Guus's ruling of 2026-11-07, "refuse v2
/// without commitment"; core refuses its v2 frames too). Half a commitment is
/// refused.
pub(crate) fn version_pin(
    expected_chunk_format: u8,
    version_id: Option<Vec<u8>>,
    version_counter: Option<u64>,
) -> Result<(ExpectedChunkFormat, Option<VersionCommitment>), CryptoError> {
    let expected = ExpectedChunkFormat::from_u8(expected_chunk_format)?;
    let version = match (version_id, version_counter) {
        (None, None) => None,
        (Some(version_id), Some(counter)) => Some(version_commitment_from_parts(version_id, counter)?),
        _ => {
            return Err(CryptoError::InvalidInput {
                detail: "version_id and version_counter must be supplied together".into(),
            });
        }
    };
    if expected == ExpectedChunkFormat::V2 && version.is_none() {
        return Err(CryptoError::InvalidInput {
            detail: "a chunk_format 2 record without a version commitment is refused".into(),
        });
    }
    Ok((expected, version))
}

pub(crate) fn metadata_pin(
    metadata: NameMetadataDto,
) -> Result<(ExpectedChunkFormat, Option<VersionCommitment>), CryptoError> {
    version_pin(metadata.chunk_format, metadata.version_id, metadata.version_counter)
}

/// The record a disk or random-access reader passes to core: only the content
/// pin and the commitment, checked by [`version_pin`].
pub(crate) fn metadata_record(metadata: NameMetadataDto) -> Result<NameMetadata, CryptoError> {
    let (chunk_format, version) = metadata_pin(metadata)?;
    Ok(NameMetadata {
        name: String::new(),
        mime_type: None,
        chunk_format,
        version,
    })
}

/// Stateful streaming decryptor handle. Single-consumer (see module note).
#[derive(uniffi::Object)]
pub struct ChunkDecryptorHandle {
    pub(crate) inner: Mutex<Option<ChunkDecryptor>>,
}

impl ChunkDecryptorHandle {
    fn with_inner<T, F: FnOnce(&mut ChunkDecryptor) -> T>(&self, f: F) -> Result<T, CryptoError> {
        let mut guard = lock_handle(&self.inner)?;
        let dec = guard.as_mut().ok_or(CryptoError::InvalidInput {
            detail: "chunk decryptor handle has been cleared".into(),
        })?;
        Ok(f(dec))
    }

    fn push_with_pin(
        file_key: kdf::FileKey,
        file_id: &str,
        (expected, version): (ExpectedChunkFormat, Option<VersionCommitment>),
    ) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(Some(ChunkDecryptor::for_version_with_file_key(
                file_key, file_id, expected, version,
            ))),
        })
    }

    #[cfg(all(test, not(feature = "legacy-bindings")))]
    pub(crate) fn for_push_with_file_key(
        file_key: Vec<u8>,
        file_id: String,
        metadata: NameMetadataDto,
    ) -> Result<Arc<Self>, CryptoError> {
        let file_key = Zeroizing::new(file_key);
        let fk = file_key_from_slice(&file_key)?;
        Ok(Self::push_with_pin(fk, &file_id, metadata_pin(metadata)?))
    }
}

#[uniffi::export]
impl ChunkDecryptorHandle {
    /// PULL constructor: stream-decrypt an encrypted file from disk.
    /// `chunk_size_bytes` is the PLAINTEXT chunk size used at encryption (the wire
    /// frame is `nonce(12) + chunk_size + tag(16)`). Errors if it is 0.
    ///
    /// `metadata` is the `NameMetadataDto` `decrypt_file_metadata` returned for
    /// the version on disk: its `chunk_format`, and its version commitment,
    /// which frame 0 must match. A record without one opens v1 content only.
    #[uniffi::constructor]
    pub fn from_file(
        master_key: &MasterKeyHandle,
        file_id: String,
        metadata: NameMetadataDto,
        chunk_size_bytes: u64,
        input_path: String,
    ) -> Result<Arc<Self>, CryptoError> {
        let record = metadata_record(metadata)?;
        let file = std::fs::File::open(std::path::Path::new(&input_path)).map_err(|e| CryptoError::Io {
            detail: format!("open input: {e}"),
        })?;
        let buf_cap = (chunk_size_bytes as usize)
            .saturating_add(28)
            .clamp(8 * 1024, 8 * 1024 * 1024);
        let reader = std::io::BufReader::with_capacity(buf_cap, file);
        let dec = master_key.with_key(|mk| {
            ChunkDecryptor::from_reader_for_current_version(mk, &file_id, &record, chunk_size_bytes, reader)
        })??;
        Ok(Arc::new(Self {
            inner: Mutex::new(Some(dec)),
        }))
    }

    /// PUSH constructor: the caller feeds wire frames via
    /// [`push_frame`](Self::push_frame). Each frame is self-describing, so no chunk
    /// size is needed. `metadata` is the version's `NameMetadataDto` from
    /// `decrypt_file_metadata`; its commitment is enforced, and a record
    /// without one opens v1 content only.
    #[uniffi::constructor]
    pub fn for_push(
        master_key: &MasterKeyHandle,
        file_id: String,
        metadata: NameMetadataDto,
    ) -> Result<Arc<Self>, CryptoError> {
        let pin = metadata_pin(metadata)?;
        let file_key = master_key.with_key(|mk| kdf::derive_file_key(mk, file_id.as_bytes()))?;
        Ok(Self::push_with_pin(file_key, &file_id, pin))
    }

    /// Current/historical protected read. Pass the fields from the matching
    /// `NameMetadataDto`; omit both only for legacy metadata, which opens v1
    /// content only (`expected_chunk_format` 2 without them is refused).
    #[uniffi::constructor]
    pub fn for_version(
        master_key: &MasterKeyHandle,
        file_id: String,
        expected_chunk_format: u8,
        version_id: Option<Vec<u8>>,
        version_counter: Option<u64>,
    ) -> Result<Arc<Self>, CryptoError> {
        let pin = version_pin(expected_chunk_format, version_id, version_counter)?;
        let file_key = master_key.with_key(|mk| kdf::derive_file_key(mk, file_id.as_bytes()))?;
        Ok(Self::push_with_pin(file_key, &file_id, pin))
    }

    /// PUSH constructor from a [`FileKeyHandle`] — for callers that hold the
    /// file key but not the owner's master key (share / shared-link recipients).
    /// The raw key never reaches Swift/Kotlin. `file_id` must be the id the file
    /// was uploaded under (bound into every v2 frame); `metadata` is what
    /// `decrypt_file_metadata_with_key` returned, its commitment enforced.
    #[uniffi::constructor]
    pub fn for_push_with_file_key_handle(
        file_key: &FileKeyHandle,
        file_id: String,
        metadata: NameMetadataDto,
    ) -> Result<Arc<Self>, CryptoError> {
        let pin = metadata_pin(metadata)?;
        // Copy into a fresh zeroize-on-drop key owned by the decryptor
        // (`FileKey::from_bytes` wipes its by-value input).
        let fk = file_key.with_key(|fk| kdf::FileKey::from_bytes(*fk.as_bytes()))?;
        Ok(Self::push_with_pin(fk, &file_id, pin))
    }

    /// [`for_version`](Self::for_version) for key-handle holders (share and
    /// shared-link recipients): the fields of that version's own decrypted
    /// metadata record; omit both only for legacy metadata, which opens v1
    /// content only.
    #[uniffi::constructor]
    pub fn for_version_with_file_key_handle(
        file_key: &FileKeyHandle,
        file_id: String,
        expected_chunk_format: u8,
        version_id: Option<Vec<u8>>,
        version_counter: Option<u64>,
    ) -> Result<Arc<Self>, CryptoError> {
        let pin = version_pin(expected_chunk_format, version_id, version_counter)?;
        let fk = file_key.with_key(|fk| kdf::FileKey::from_bytes(*fk.as_bytes()))?;
        Ok(Self::push_with_pin(fk, &file_id, pin))
    }

    /// The file's chunk format (1 = v1 legacy, 2 = v2) once chunk 0 has been
    /// opened; `None` before.
    pub fn chunk_format(&self) -> Result<Option<u8>, CryptoError> {
        self.with_inner(|d| d.format().map(ChunkFormat::as_u8))
    }

    /// v2: the upload's version id (chunk 0's 12-byte nonce) once chunk 0 has
    /// authenticated — what a seeking reader passes to
    /// `FileKeyHandle.decrypt_chunk_frame`. `None` before chunk 0 and for v1.
    pub fn version_id(&self) -> Result<Option<Vec<u8>>, CryptoError> {
        self.with_inner(|d| d.version_id().map(|v| v.to_vec()))
    }

    /// End-of-stream check, consuming the decryptor. MUST be called after the
    /// last pushed frame: it fails if no frame was pushed or if a v2 file ended
    /// before its last chunk (truncation). Treat an `Err` as a failed download
    /// and discard the plaintext. The pull form runs the same check at EOF.
    pub fn finish(&self) -> Result<ChunkDecryptorSummaryDto, CryptoError> {
        let mut guard = lock_handle(&self.inner)?;
        let dec = guard.take().ok_or(CryptoError::InvalidInput {
            detail: "chunk decryptor handle has been finished or cleared".into(),
        })?;
        let summary = dec.finish().map_err(CryptoError::from)?;
        Ok(ChunkDecryptorSummaryDto {
            chunk_count: summary.chunk_count,
            format: summary.format.as_u8(),
        })
    }

    /// PULL: emit the next decrypted chunk, or `None` at clean EOF.
    pub fn next_chunk(&self) -> Result<Option<DecryptedChunkDto>, CryptoError> {
        let chunk = self.with_inner(|d| d.next_chunk())??;
        Ok(chunk.map(|c| DecryptedChunkDto {
            index: c.index,
            data: c.data,
        }))
    }

    /// PUSH: decrypt one caller-provided wire frame (`nonce || ciphertext || tag`).
    pub fn push_frame(&self, frame: Vec<u8>) -> Result<DecryptedChunkDto, CryptoError> {
        let chunk = self.with_inner(|d| d.push_frame(&frame))??;
        Ok(DecryptedChunkDto {
            index: chunk.index,
            data: chunk.data,
        })
    }
}

#[cfg(feature = "legacy-bindings")]
#[uniffi::export]
impl ChunkDecryptorHandle {
    /// Compatibility constructor for hosts that still hold a raw shared key
    /// (default-off `legacy-bindings`). It too takes the decrypted metadata
    /// and enforces its commitment.
    #[uniffi::constructor]
    pub fn for_push_with_file_key(
        file_key: Vec<u8>,
        file_id: String,
        metadata: NameMetadataDto,
    ) -> Result<Arc<Self>, CryptoError> {
        let file_key = Zeroizing::new(file_key);
        let fk = file_key_from_slice(&file_key)?;
        Ok(Self::push_with_pin(fk, &file_id, metadata_pin(metadata)?))
    }
}

// Disk helpers: moved from `lib.rs` (size baseline) when they began to take
// the decrypted metadata (the ruling of 2026-11-07).

/// Decrypt a sequence of encrypted chunks and write the plaintext to a file.
///
/// Chunks are decrypted sequentially and written in order; peak memory is
/// bounded by the size of the largest single chunk's plaintext, not the
/// total file size. The output file is created (truncating any existing
/// file) before the first chunk.
///
/// On `Err`, the output file may exist on disk in a partially-written
/// state — the caller is responsible for deleting it so a downstream
/// cache layer does not treat the partial file as complete.
///
/// Returns the total number of plaintext bytes written.
///
/// **Task 1908:** `file_id` (the id the file was uploaded under) and
/// `metadata` (the version's `NameMetadataDto` from `decrypt_file_metadata`)
/// are required: the chunks are opened as one file's ordered stream — v2
/// frames are bound to (file id, upload, index, last) and open only as the
/// upload the record's commitment names; a record without one opens v1 content
/// only (the ruling of 2026-11-07). Reordered, spliced, duplicated, dropped or
/// truncated v2 chunks fail. The output is atomic (core `.tmp` + rename).
#[cfg_attr(feature = "legacy-bindings", uniffi::export)]
pub fn decrypt_chunks_to_file(
    key: Vec<u8>,
    file_id: String,
    metadata: NameMetadataDto,
    chunks: Vec<EncryptedChunkData>,
    output_path: String,
) -> Result<u64, CryptoError> {
    let key = Zeroizing::new(key);
    let fk = file_key_from_slice(&key)?;
    let (expected, version) = metadata_pin(metadata)?;
    let chunk_pairs: Vec<(Vec<u8>, Vec<u8>)> = chunks.into_iter().map(|c| (c.nonce, c.ciphertext)).collect();
    encrypt::decrypt_chunks_to_file(&fk, &file_id, expected, version, chunk_pairs, &output_path)
        .map_err(CryptoError::from)
}

/// Decrypt a contiguous encrypted body into a file.
///
/// `body` is the wire format produced by stacking encrypted chunks back
/// to back: each chunk is `nonce (12 bytes) || ciphertext (chunk_size +
/// 16 byte AES-GCM tag)`. All chunks but the last produce `chunk_size`
/// bytes of plaintext; the final chunk is whatever remains.
///
/// Compared to `decrypt_chunks_to_file`, this variant lets the caller
/// hand over the full encrypted blob without pre-slicing — Rust performs
/// the chunk boundaries internally. Saves N small `ByteArray` allocations
/// + per-chunk marshalling overhead across the FFI for files with many
///   chunks (a 100 MB / 1 MB-chunk file is one allocation here vs. 200
///   across the bridge with the pre-sliced variant).
///
/// Streams chunk-by-chunk — peak memory is one plaintext chunk, not the
/// full file. Returns the total number of plaintext bytes written.
///
/// **Atomic output:** core writes plaintext to a sibling `.tmp` and renames it
/// to `output_path` only on full success; on any error the `.tmp` is removed and
/// `output_path` is never created/overwritten. Callers no longer need to clean
/// up a partial file on `Err`, and an existence-based cache cannot serve a
/// truncated decrypt.
///
/// **Task 1908:** `file_id` (the id the file was uploaded under) is required —
/// it is bound into every v2 frame together with the upload's version id, the
/// chunk index and the last-chunk flag — and so is `metadata`, the version's
/// `NameMetadataDto` from `decrypt_file_metadata`: v2 opens only as the upload
/// its commitment names, and a record without one opens v1 content only (the
/// ruling of 2026-11-07). A reordered/spliced/truncated v2 body fails.
#[cfg_attr(feature = "legacy-bindings", uniffi::export)]
pub fn decrypt_contiguous_to_file(
    file_key: Vec<u8>,
    file_id: String,
    metadata: NameMetadataDto,
    body: Vec<u8>,
    chunk_size: u64,
    output_path: String,
) -> Result<u64, CryptoError> {
    let file_key = Zeroizing::new(file_key);
    let fk = file_key_from_slice(&file_key)?;
    let (expected, version) = metadata_pin(metadata)?;
    encrypt::decrypt_contiguous_to_file(&fk, &file_id, expected, version, &body, chunk_size, &output_path)
        .map_err(CryptoError::from)
}

#[cfg(test)]
mod poisoned_handle_tests {
    use super::*;

    /// Poison a handle's lock the way a panic during another call would: the
    /// guard is held while the thread unwinds.
    macro_rules! poison {
        ($handle:expr) => {{
            let clone = Arc::clone(&$handle);
            let panicked = std::thread::spawn(move || {
                let _guard = clone.inner.lock();
                panic!("a panic while the handle is locked");
            })
            .join();
            assert!(panicked.is_err());
            assert!($handle.inner.is_poisoned());
        }};
    }

    #[test]
    fn a_poisoned_handle_answers_with_an_error_never_a_panic_across_ffi() {
        let decryptor = Arc::new(ChunkDecryptorHandle {
            inner: Mutex::new(None),
        });
        poison!(decryptor);
        assert!(matches!(
            decryptor.chunk_format(),
            Err(CryptoError::InvalidInput { .. })
        ));
        assert!(matches!(decryptor.finish(), Err(CryptoError::InvalidInput { .. })));

        let encryptor = Arc::new(crate::ChunkEncryptorHandle {
            inner: Mutex::new(None),
        });
        poison!(encryptor);
        assert!(matches!(
            encryptor.resume_policy(None),
            Err(CryptoError::InvalidInput { .. })
        ));
        assert!(matches!(
            encryptor.apply_recorded_pin(2),
            Err(CryptoError::InvalidInput { .. })
        ));
        assert!(matches!(encryptor.finish(), Err(CryptoError::InvalidInput { .. })));

        let master = MasterKeyHandle::new(kdf::MasterKey::from_bytes([3; 32]));
        poison!(master);
        assert!(matches!(master.with_key(|_| ()), Err(CryptoError::InvalidInput { .. })));
        assert!(
            master
                .inner
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .is_none(),
            "the key was wiped"
        );
    }
}
