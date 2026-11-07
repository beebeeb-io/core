//! Stateful streaming decryptor handle. Moved out of `lib.rs` when its
//! constructors began to take the decrypted metadata (crypto review,
//! P2-4): every constructor applies the version commitment the record carries.

use std::sync::{Arc, Mutex};

use beebeeb_core::chunk_stream::{ChunkDecryptor, ChunkFormat, ExpectedChunkFormat, VersionCommitment};
use beebeeb_core::encrypt::NameMetadata;
use beebeeb_core::kdf;
#[cfg(any(test, feature = "legacy-bindings"))]
use zeroize::Zeroizing;

#[cfg(any(test, feature = "legacy-bindings"))]
use crate::file_key_from_slice;
use crate::{
    ChunkDecryptorSummaryDto, CryptoError, DecryptedChunkDto, FileKeyHandle, MasterKeyHandle, NameMetadataDto,
    version_commitment_from_parts,
};

/// The format pin and commitment a content reader enforces. A record with a
/// commitment binds frame 0 to it; a record with neither field is legacy
/// metadata, readable but unprotected (core's compatibility rule); half a
/// commitment is refused.
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
    Ok((expected, version))
}

fn metadata_pin(metadata: NameMetadataDto) -> Result<(ExpectedChunkFormat, Option<VersionCommitment>), CryptoError> {
    version_pin(metadata.chunk_format, metadata.version_id, metadata.version_counter)
}

/// Stateful streaming decryptor handle. Single-consumer (see module note).
#[derive(uniffi::Object)]
pub struct ChunkDecryptorHandle {
    pub(crate) inner: Mutex<Option<ChunkDecryptor>>,
}

impl ChunkDecryptorHandle {
    fn with_inner<T, F: FnOnce(&mut ChunkDecryptor) -> T>(&self, f: F) -> Result<T, CryptoError> {
        let mut guard = self.inner.lock().unwrap();
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
    /// which frame 0 must match when the record carries one.
    #[uniffi::constructor]
    pub fn from_file(
        master_key: &MasterKeyHandle,
        file_id: String,
        metadata: NameMetadataDto,
        chunk_size_bytes: u64,
        input_path: String,
    ) -> Result<Arc<Self>, CryptoError> {
        let (chunk_format, version) = metadata_pin(metadata)?;
        let record = NameMetadata {
            name: String::new(),
            mime_type: None,
            chunk_format,
            version,
        };
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
    /// `decrypt_file_metadata`; its commitment is enforced when present.
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
    /// `NameMetadataDto`; omit both only for unprotected legacy metadata.
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
    /// metadata record; omit both only for unprotected legacy metadata.
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
        let mut guard = self.inner.lock().unwrap();
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
