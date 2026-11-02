//! Download-side chunk math and the frame-to-plaintext loop.
//!
//! Move 10 (spec §16.2) promotes the decision logic of
//! `beebeeb-upload/src/download.rs` into core so every client shares one rule:
//! the chunk boundaries (the offset rule the mobile `VideoChunkMath` depends
//! on), the wire frame size for the streaming reader, and the loop that opens
//! frames with [`ChunkDecryptor`] and writes plaintext through.
//!
//! The HTTP transport stays in `beebeeb-upload`: core takes the bytes it was
//! given. Breaking changes are not allowed (spec §16.4) — the upload crate
//! keeps its public names and signatures and delegates here.

use std::fmt;
use std::io::Write;

use crate::chunk_stream::{CHUNK_OVERHEAD, ChunkDecryptor, ExpectedChunkFormat};
use crate::kdf::FileKey;

/// Smallest legal wire frame: `nonce(12) || tag(16)` with no plaintext.
pub const MIN_FRAME_LEN: usize = CHUNK_OVERHEAD as usize;

/// What a finished download decrypt wrote.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DecryptSummary {
    /// Total plaintext bytes written.
    pub plaintext_size: u64,
    /// Number of frames that opened successfully.
    pub chunks_decrypted: u32,
}

/// Why a download could not be decrypted.
///
/// `beebeeb-upload` maps these onto its own `UploadError` variants, so the
/// messages a client sees are the ones it saw before the move.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DownloadFailure {
    /// The caller's own arguments are unusable (`chunk_count == 0`).
    InvalidInput(String),
    /// The payload does not have the shape its headers promised.
    InvalidResponse(String),
    /// A frame failed authentication or chunk-format validation.
    ChunkDecryption { chunk: u32, reason: String },
    /// Every frame opened but the stream never reached its last chunk.
    Incomplete { chunks: u32, reason: String },
    /// Writing plaintext failed.
    Io(String),
}

impl fmt::Display for DownloadFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput(message) | Self::InvalidResponse(message) | Self::Io(message) => f.write_str(message),
            Self::ChunkDecryption { chunk, reason } => {
                write!(f, "decryption failed for chunk {chunk}: {reason}")
            }
            Self::Incomplete { chunks, reason } => {
                write!(f, "download incomplete after {chunks} chunks: {reason}")
            }
        }
    }
}

impl std::error::Error for DownloadFailure {}

/// Byte ranges `(start, end)` of each frame in the encrypted payload.
///
/// Every frame has the same size except the last, which takes the remainder.
/// Each frame must hold at least a nonce and a tag (28 bytes).
pub fn compute_chunk_boundaries(total_len: usize, chunk_count: u32) -> Result<Vec<(usize, usize)>, DownloadFailure> {
    if chunk_count == 0 {
        return Err(DownloadFailure::InvalidInput("chunk_count must be > 0".into()));
    }

    let n = chunk_count as usize;

    if total_len == 0 {
        return Err(DownloadFailure::InvalidResponse("encrypted payload is empty".into()));
    }

    // For a single chunk, the entire payload is that chunk.
    if n == 1 {
        if total_len < MIN_FRAME_LEN {
            return Err(DownloadFailure::InvalidResponse(format!(
                "chunk too small: {total_len} bytes (need at least {MIN_FRAME_LEN})"
            )));
        }
        return Ok(vec![(0, total_len)]);
    }

    // Multi-chunk: divide evenly, last chunk gets the remainder.
    let base_chunk_size = total_len / n;
    if base_chunk_size < MIN_FRAME_LEN {
        return Err(DownloadFailure::InvalidResponse(format!(
            "chunk too small: {base_chunk_size} bytes (need at least {MIN_FRAME_LEN})"
        )));
    }

    let mut boundaries = Vec::with_capacity(n);
    let mut offset = 0;
    for i in 0..n {
        let size = if i == n - 1 {
            total_len - offset
        } else {
            base_chunk_size
        };
        boundaries.push((offset, offset + size));
        offset += size;
    }
    Ok(boundaries)
}

/// Where frame `chunk_index` starts in the encrypted payload.
///
/// This is the offset a resumed download seeks to; it is derived from the same
/// rule as [`compute_chunk_boundaries`], so a resume never re-splits.
pub fn chunk_offset(total_len: usize, chunk_count: u32, chunk_index: u32) -> Result<usize, DownloadFailure> {
    let boundaries = compute_chunk_boundaries(total_len, chunk_count)?;
    boundaries
        .get(chunk_index as usize)
        .map(|(start, _)| *start)
        .ok_or_else(|| {
            DownloadFailure::InvalidInput(format!(
                "chunk index {chunk_index} is out of range for {chunk_count} chunks"
            ))
        })
}

/// Wire frame size for the streaming reader.
///
/// When the server sends `X-Chunk-Size` (v2 files) each frame is the uniform
/// plaintext chunk size plus the GCM overhead, exact even when the file size is
/// not a multiple of the chunk size. Only legacy v1 responses (no header) fall
/// back to the `total / chunk_count` average. A single frame is the whole body.
pub fn frame_size(total_len: u64, chunk_count: u32, chunk_size: Option<u64>) -> usize {
    if chunk_count <= 1 {
        return usize::MAX;
    }
    if let Some(chunk_size) = chunk_size {
        return (chunk_size + CHUNK_OVERHEAD) as usize;
    }
    (total_len / chunk_count as u64) as usize
}

/// Open `frames` in order and write their plaintext to `writer`.
///
/// `frames` must hold exactly `chunk_count` frames: an under- or over-stated
/// count is a response-shape error, never a silent truncation. A frame that
/// fails authentication is `ChunkDecryption` for that index. `on_chunk` is
/// called after each frame with `(decrypted_so_far, chunk_count)`.
pub fn decrypt_frames_to<W: Write, F: FnMut(u32, u32)>(
    file_key: &FileKey,
    file_id: &str,
    expected: ExpectedChunkFormat,
    chunk_count: u32,
    frames: &[&[u8]],
    writer: &mut W,
    mut on_chunk: F,
) -> Result<DecryptSummary, DownloadFailure> {
    if chunk_count == 0 {
        return Err(DownloadFailure::InvalidInput("chunk_count must be > 0".into()));
    }
    if frames.len() != chunk_count as usize {
        return Err(DownloadFailure::InvalidResponse(format!(
            "download truncated: got {} of {chunk_count} frames",
            frames.len()
        )));
    }

    // The decryptor owns its key; copy the borrowed one into a fresh
    // zeroize-on-drop FileKey (`from_bytes` wipes its by-value input).
    let mut decryptor =
        ChunkDecryptor::for_push_with_file_key(FileKey::from_bytes(*file_key.as_bytes()), file_id, expected);
    let mut summary = DecryptSummary::default();

    for (index, frame) in frames.iter().enumerate() {
        let plaintext = decryptor
            .push_frame(frame)
            .map_err(|e| DownloadFailure::ChunkDecryption {
                chunk: index as u32,
                reason: e.to_string(),
            })?;
        writer
            .write_all(&plaintext.data)
            .map_err(|e| DownloadFailure::Io(format!("write output: {e}")))?;
        summary.plaintext_size += plaintext.data.len() as u64;
        summary.chunks_decrypted += 1;
        on_chunk(summary.chunks_decrypted, chunk_count);
    }

    decryptor.finish().map_err(|e| DownloadFailure::Incomplete {
        chunks: summary.chunks_decrypted,
        reason: e.to_string(),
    })?;
    Ok(summary)
}

/// Split `payload` with [`compute_chunk_boundaries`] and decrypt every frame.
pub fn decrypt_chunks_to<W: Write, F: FnMut(u32, u32)>(
    file_key: &FileKey,
    file_id: &str,
    expected: ExpectedChunkFormat,
    chunk_count: u32,
    payload: &[u8],
    writer: &mut W,
    on_chunk: F,
) -> Result<DecryptSummary, DownloadFailure> {
    let boundaries = compute_chunk_boundaries(payload.len(), chunk_count)?;
    let frames: Vec<&[u8]> = boundaries.iter().map(|(start, end)| &payload[*start..*end]).collect();
    decrypt_frames_to(file_key, file_id, expected, chunk_count, &frames, writer, on_chunk)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boundaries_cover_the_payload_once() {
        let boundaries = compute_chunk_boundaries(1000, 3).unwrap();
        assert_eq!(boundaries, vec![(0, 333), (333, 666), (666, 1000)]);
        assert_eq!(chunk_offset(1000, 3, 2).unwrap(), 666);
    }

    #[test]
    fn a_zero_chunk_count_is_an_input_error() {
        assert!(matches!(
            compute_chunk_boundaries(40, 0),
            Err(DownloadFailure::InvalidInput(_))
        ));
        assert_eq!(
            compute_chunk_boundaries(40, 0).unwrap_err().to_string(),
            "chunk_count must be > 0"
        );
    }
}
