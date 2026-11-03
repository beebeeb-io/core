//! Request-row content reader (task 2275 §15; 2326 delta2 P2-2).
//!
//! A request row's content key `C` is decrypt-only: the anonymous uploader
//! holds it, so the owner must never seal anything under it. This reader owns a
//! copy of `C` bound to the row's file id and recorded chunk-format pin. It has
//! no key getter, and the key is `ZeroizeOnDrop` with the reader (via
//! [`FileKey`]).
//!
//! - [`RequestContentReader::decryptor`] hands out a FRESH sequential
//!   [`ChunkDecryptor`] per call, so retrying after a mid-stream error does not
//!   resume a poisoned cursor.
//! - [`RequestContentReader::open_frame`] is the random-access (seek / range)
//!   path: one frame by index, without the frames before it.

use crate::chunk_stream::{open_chunk, ChunkDecryptor, ChunkFormat, ExpectedChunkFormat};
use crate::kdf::FileKey;
use crate::CoreError;

/// A request row's decrypt-only content reader. One key, one row.
pub struct RequestContentReader {
    file_key: FileKey,
    file_id: String,
    pin: ExpectedChunkFormat,
}

impl RequestContentReader {
    /// Bind the row's content key `C` to the row's `file_id` (the id every v2
    /// frame is bound to) and the `chunk_format` pin its name authenticated.
    pub fn new(file_key: FileKey, file_id: impl Into<String>, pin: ExpectedChunkFormat) -> Self {
        Self {
            file_key,
            file_id: file_id.into(),
            pin,
        }
    }

    /// The id every frame must be bound to; never a server-supplied value.
    pub fn file_id(&self) -> &str {
        &self.file_id
    }

    /// The recorded chunk-format pin the row's name authenticated
    /// (`0` = unrecorded, `2` = v2).
    pub fn pin(&self) -> ExpectedChunkFormat {
        self.pin
    }

    /// A FRESH sequential decryptor over this row's content, at chunk 0. Every
    /// call returns a new cursor, so a caller may retry after a mid-stream
    /// error without rebuilding the reader.
    pub fn decryptor(&self) -> ChunkDecryptor {
        ChunkDecryptor::for_push_with_file_key(self.copy_key(), &self.file_id, self.pin)
    }

    /// Random-access open of ONE content frame at `index` — no earlier frames
    /// are needed (seek / range read). `is_last = index == chunk_count - 1`.
    ///
    /// `format` and `version_id` must come from authenticated data, exactly as
    /// [`open_chunk`] documents. When the row's pin is
    /// [`ExpectedChunkFormat::V2`], a v1 `format` is refused: the name already
    /// authenticated v2 for this row.
    pub fn open_frame(
        &self,
        version_id: &[u8],
        index: u32,
        is_last: bool,
        format: ChunkFormat,
        frame: &[u8],
    ) -> Result<Vec<u8>, CoreError> {
        if self.pin == ExpectedChunkFormat::V2 && format != ChunkFormat::V2 {
            return Err(CoreError::InvalidInput(
                "request content reader: the row records chunk format 2; a v1 frame cannot be its content".into(),
            ));
        }
        open_chunk(&self.file_key, &self.file_id, version_id, index, is_last, format, frame)
    }

    /// A fresh key for a decryptor. `FileKey` is deliberately not `Clone`.
    fn copy_key(&self) -> FileKey {
        FileKey::from_bytes(*self.file_key.as_bytes())
    }
}

impl std::fmt::Debug for RequestContentReader {
    /// Deliberately omits the key — never log key material.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RequestContentReader")
            .field("file_id", &self.file_id)
            .field("pin", &self.pin)
            .finish_non_exhaustive()
    }
}
