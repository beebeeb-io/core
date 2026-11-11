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

use crate::chunk_stream::{CHUNK_OVERHEAD, ChunkDecryptor, ExpectedChunkFormat, MAX_CHUNK_SIZE, VersionCommitment};
use crate::kdf::FileKey;
use beebeeb_types::limits::{MAX_CHUNK_COUNT, MAX_MATERIALIZED_CHUNK_COUNT, MemoryBudget};

/// Smallest legal wire frame: `nonce(12) || tag(16)` with no plaintext.
pub const MIN_FRAME_LEN: usize = CHUNK_OVERHEAD as usize;

/// Largest legal wire frame: the largest plaintext chunk plus `nonce(12) ||
/// tag(16)`. A reader must refuse anything larger, including a legacy
/// no-header frame whose average or drained remainder would exceed it.
pub const MAX_FRAME_SIZE: usize = MAX_CHUNK_SIZE as usize + CHUNK_OVERHEAD as usize;

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
/// `beebeeb-upload` maps these onto its own `UploadError` variants, preserving
/// the distinction between invalid data and valid data that needs the app.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DownloadFailure {
    /// The caller's own arguments are unusable (`chunk_count == 0`).
    InvalidInput(String),
    /// The payload does not have the shape its headers promised.
    InvalidResponse(String),
    /// The frame is valid, but this constrained execution context cannot open
    /// it. A File Provider must hand the request to the main app and retry
    /// there; it must not report the file as corrupt or hostile.
    TooLargeForContext { frame_size: u64, context_limit: u64 },
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
            Self::TooLargeForContext {
                frame_size,
                context_limit,
            } => write!(
                f,
                "valid frame size {frame_size} exceeds this context's {context_limit}-byte limit; hand off to the main app"
            ),
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
    check_materialized_chunk_count(chunk_count)?;

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
///
/// Computed arithmetically on purpose: a server-declared chunk count is
/// untrusted, and materialising the boundary table would let a huge count
/// allocate before the index was ever checked.
pub fn chunk_offset(total_len: usize, chunk_count: u32, chunk_index: u32) -> Result<usize, DownloadFailure> {
    if chunk_count == 0 {
        return Err(DownloadFailure::InvalidInput("chunk_count must be > 0".into()));
    }
    let n = chunk_count as usize;
    if total_len == 0 {
        return Err(DownloadFailure::InvalidResponse("encrypted payload is empty".into()));
    }
    // Same validation messages as compute_chunk_boundaries.
    if n == 1 {
        if total_len < MIN_FRAME_LEN {
            return Err(DownloadFailure::InvalidResponse(format!(
                "chunk too small: {total_len} bytes (need at least {MIN_FRAME_LEN})"
            )));
        }
    } else {
        let base_chunk_size = total_len / n;
        if base_chunk_size < MIN_FRAME_LEN {
            return Err(DownloadFailure::InvalidResponse(format!(
                "chunk too small: {base_chunk_size} bytes (need at least {MIN_FRAME_LEN})"
            )));
        }
    }
    if chunk_index as usize >= n {
        return Err(DownloadFailure::InvalidInput(format!(
            "chunk index {chunk_index} is out of range for {chunk_count} chunks"
        )));
    }
    // The offset rule of compute_chunk_boundaries: uniform `total / n`, with
    // the remainder in the last frame. `chunk_index < n`, so the product never
    // exceeds `total_len` and no Vec is needed.
    let base = if n == 1 { total_len } else { total_len / n };
    Ok(base * chunk_index as usize)
}

/// Wire frame size for the streaming reader, with the server header checked.
///
/// `chunk_size` and `chunk_count` come from the response, so they are
/// untrusted. The size must survive `+ CHUNK_OVERHEAD`, fit `usize`, and not
/// exceed [`MAX_CHUNK_SIZE`]; otherwise the reader would be asked to buffer an
/// absurd frame. `chunk_count <= 1` still means "the whole body is one frame"
/// and returns [`usize::MAX`].
pub fn checked_frame_size(total_len: u64, chunk_count: u32, chunk_size: Option<u64>) -> Result<usize, DownloadFailure> {
    let format_budget = MemoryBudget::new(MAX_FRAME_SIZE as u64, MemoryBudget::NATIVE.archive_output_bytes);
    checked_frame_size_with_budget(total_len, chunk_count, chunk_size, format_budget)
}

pub fn checked_frame_size_with_budget(
    total_len: u64,
    chunk_count: u32,
    chunk_size: Option<u64>,
    budget: MemoryBudget,
) -> Result<usize, DownloadFailure> {
    check_chunk_count(chunk_count)?;
    if chunk_count <= 1 {
        if total_len > MAX_FRAME_SIZE as u64 {
            return Err(DownloadFailure::InvalidResponse(format!(
                "single frame size {total_len} exceeds the maximum {MAX_FRAME_SIZE}"
            )));
        }
        check_context_frame_size(total_len, budget)?;
        return Ok(usize::MAX);
    }
    if let Some(chunk_size) = chunk_size {
        let with_overhead = chunk_size.checked_add(CHUNK_OVERHEAD).ok_or_else(|| {
            DownloadFailure::InvalidResponse(format!(
                "frame size overflow: chunk size {chunk_size} + overhead {CHUNK_OVERHEAD} does not fit in u64"
            ))
        })?;
        // Reject before any cast/allocation: a frame can never be larger than
        // the largest chunk the encryptor will produce.
        if with_overhead > MAX_CHUNK_SIZE + CHUNK_OVERHEAD {
            return Err(DownloadFailure::InvalidResponse(format!(
                "chunk size {chunk_size} exceeds the maximum {MAX_CHUNK_SIZE}"
            )));
        }
        check_context_frame_size(with_overhead, budget)?;
        return usize::try_from(with_overhead).map_err(|_| {
            DownloadFailure::InvalidResponse(format!("frame size {with_overhead} does not fit this platform's usize"))
        });
    }
    let average = total_len / chunk_count as u64;
    // The legacy no-header path is untrusted too: an average larger than one
    // maximum chunk would ask the reader to buffer an absurd frame.
    if average > MAX_FRAME_SIZE as u64 {
        return Err(DownloadFailure::InvalidResponse(format!(
            "average frame size {average} exceeds the maximum {MAX_FRAME_SIZE}"
        )));
    }
    check_context_frame_size(average, budget)?;
    usize::try_from(average).map_err(|_| {
        DownloadFailure::InvalidResponse(format!(
            "average frame size {average} does not fit this platform's usize"
        ))
    })
}

fn check_chunk_count(chunk_count: u32) -> Result<(), DownloadFailure> {
    if chunk_count == 0 {
        return Err(DownloadFailure::InvalidInput("chunk_count must be > 0".into()));
    }
    if chunk_count > MAX_CHUNK_COUNT {
        return Err(DownloadFailure::InvalidResponse(format!(
            "chunk count {chunk_count} exceeds the maximum {MAX_CHUNK_COUNT}"
        )));
    }
    Ok(())
}

fn check_materialized_chunk_count(chunk_count: u32) -> Result<(), DownloadFailure> {
    check_chunk_count(chunk_count)?;
    if chunk_count > MAX_MATERIALIZED_CHUNK_COUNT {
        return Err(DownloadFailure::InvalidResponse(format!(
            "chunk count {chunk_count} exceeds the materialized API maximum {MAX_MATERIALIZED_CHUNK_COUNT}; use streaming"
        )));
    }
    Ok(())
}

fn check_context_frame_size(frame_size: u64, budget: MemoryBudget) -> Result<(), DownloadFailure> {
    if frame_size > budget.download_frame_bytes {
        return Err(DownloadFailure::TooLargeForContext {
            frame_size,
            context_limit: budget.download_frame_bytes,
        });
    }
    Ok(())
}

/// Open `frames` in order and write their plaintext to `writer`.
///
/// `frames` must hold exactly `chunk_count` frames: an under- or over-stated
/// count is a response-shape error, never a silent truncation. A frame that
/// fails authentication is `ChunkDecryption` for that index. `on_chunk` is
/// called after each frame with `(decrypted_so_far, chunk_count)`.
///
/// `expected` and `version` come from the version's encrypted metadata: a v2
/// file opens only as the upload `version` names, and with no `version` only a
/// v1 file opens (Guus's ruling of 2026-11-07).
///
/// # Partial output on error
///
/// **The writer's contents MUST be discarded on any `Err`.** Frames are written
/// as they authenticate, so an error can arrive after a prefix is already on
/// disk: that prefix is authenticated plaintext but not the whole file (a
/// truncated download, or — for a v2 stream whose final frame never carried
/// its last-chunk seal — a stream that is not provably complete). Treating it
/// as the file would hand the caller a silently truncated document. Callers
/// write to a temporary path and delete it on error; never rename a partial
/// file into place.
#[allow(clippy::too_many_arguments)]
pub fn decrypt_frames_to<W: Write, F: FnMut(u32, u32)>(
    file_key: &FileKey,
    file_id: &str,
    expected: ExpectedChunkFormat,
    version: Option<VersionCommitment>,
    chunk_count: u32,
    frames: &[&[u8]],
    writer: &mut W,
    mut on_chunk: F,
) -> Result<DecryptSummary, DownloadFailure> {
    check_materialized_chunk_count(chunk_count)?;
    if frames.len() != chunk_count as usize {
        return Err(DownloadFailure::InvalidResponse(format!(
            "download truncated: got {} of {chunk_count} frames",
            frames.len()
        )));
    }

    // The decryptor owns its key; copy the borrowed one into a fresh
    // zeroize-on-drop FileKey (`from_bytes` wipes its by-value input).
    let mut decryptor = ChunkDecryptor::for_version_with_file_key(
        FileKey::from_bytes(*file_key.as_bytes()),
        file_id,
        expected,
        version,
    );
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
        summary.plaintext_size = summary
            .plaintext_size
            .checked_add(plaintext.data.len() as u64)
            .ok_or_else(|| DownloadFailure::InvalidResponse("plaintext size overflow".into()))?;
        summary.chunks_decrypted = summary
            .chunks_decrypted
            .checked_add(1)
            .ok_or_else(|| DownloadFailure::InvalidResponse("decrypted chunk count overflow".into()))?;
        on_chunk(summary.chunks_decrypted, chunk_count);
    }

    decryptor.finish().map_err(|e| DownloadFailure::Incomplete {
        chunks: summary.chunks_decrypted,
        reason: e.to_string(),
    })?;
    Ok(summary)
}

/// Split `payload` with [`compute_chunk_boundaries`] and decrypt every frame.
#[allow(clippy::too_many_arguments)]
pub fn decrypt_chunks_to<W: Write, F: FnMut(u32, u32)>(
    file_key: &FileKey,
    file_id: &str,
    expected: ExpectedChunkFormat,
    version: Option<VersionCommitment>,
    chunk_count: u32,
    payload: &[u8],
    writer: &mut W,
    on_chunk: F,
) -> Result<DecryptSummary, DownloadFailure> {
    let boundaries = compute_chunk_boundaries(payload.len(), chunk_count)?;
    let frames: Vec<&[u8]> = boundaries.iter().map(|(start, end)| &payload[*start..*end]).collect();
    decrypt_frames_to(
        file_key,
        file_id,
        expected,
        version,
        chunk_count,
        &frames,
        writer,
        on_chunk,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chunk_stream::{ChunkEncryptor, ChunkFormat};

    #[test]
    fn boundaries_cover_the_payload_once() {
        let boundaries = compute_chunk_boundaries(1000, 3).unwrap();
        assert_eq!(boundaries, vec![(0, 333), (333, 666), (666, 1000)]);
        assert_eq!(chunk_offset(1000, 3, 2).unwrap(), 666);
    }

    #[test]
    fn an_understated_v2_count_is_incomplete_after_writing() {
        let key = FileKey::from_bytes([7u8; 32]);
        let file_id = "3f1c0e7a-0000-4000-8000-000000000002";
        let plaintext: Vec<u8> = (0..100u8).collect();
        let mut encryptor = ChunkEncryptor::for_push_with_file_key(
            FileKey::from_bytes(*key.as_bytes()),
            file_id,
            plaintext.len() as u64,
            40,
        )
        .expect("encryptor")
        .with_format(ChunkFormat::V2)
        .expect("v2 format");
        let frames: Vec<Vec<u8>> = plaintext
            .chunks(40)
            .map(|chunk| encryptor.push_chunk(chunk).expect("push_chunk").data)
            .collect();
        let version = encryptor.version_commitment(None).expect("commitment");
        encryptor.finish().expect("finish");

        // Three real frames; the header understates two, so both frames open
        // and are written, but the stream never presents its last-chunk seal.
        let refs: Vec<&[u8]> = frames[..2].iter().map(|frame| frame.as_slice()).collect();
        let mut out = Vec::new();
        let error = decrypt_frames_to(
            &key,
            file_id,
            ExpectedChunkFormat::V2,
            Some(version),
            2,
            &refs,
            &mut out,
            |_, _| {},
        )
        .expect_err("an understated count must not look complete");
        assert!(
            matches!(error, DownloadFailure::Incomplete { chunks: 2, .. }),
            "expected Incomplete after 2 chunk(s), got {error:?}"
        );
        // The authenticated prefix is on the writer and MUST be discarded.
        assert_eq!(out.len(), 80, "the prefix written before the error is a truncated file");
    }

    #[test]
    fn an_overflowing_chunk_size_header_is_refused() {
        // u64::MAX - 27 + CHUNK_OVERHEAD(28) overflows u64. The old unchecked
        // `chunk_size + CHUNK_OVERHEAD` panicked (debug) or wrapped (release).
        let failure = checked_frame_size(1024, 2, Some(u64::MAX - 27)).unwrap_err();
        assert!(
            matches!(failure, DownloadFailure::InvalidResponse(_)),
            "expected InvalidResponse, got {failure:?}"
        );
    }

    #[test]
    fn a_chunk_size_above_the_maximum_is_refused() {
        let failure = checked_frame_size(1024, 2, Some(MAX_CHUNK_SIZE + 1)).unwrap_err();
        assert!(
            matches!(failure, DownloadFailure::InvalidResponse(_)),
            "expected InvalidResponse, got {failure:?}"
        );
        assert_eq!(
            checked_frame_size(1024, 2, Some(MAX_CHUNK_SIZE)).unwrap(),
            MAX_CHUNK_SIZE as usize + CHUNK_OVERHEAD as usize
        );
    }

    #[test]
    fn an_oversized_legacy_average_is_refused() {
        // No size header: the average is all the reader has. One byte over the
        // maximum frame must be refused, exactly at it must pass.
        let over = (MAX_FRAME_SIZE as u64 + 1) * 2;
        let failure = checked_frame_size(over, 2, None).unwrap_err();
        assert!(
            matches!(failure, DownloadFailure::InvalidResponse(_)),
            "expected InvalidResponse, got {failure:?}"
        );
        assert_eq!(
            checked_frame_size((MAX_FRAME_SIZE as u64) * 2, 2, None).unwrap(),
            MAX_FRAME_SIZE
        );
    }

    #[test]
    fn the_single_frame_sentinel_is_unchanged() {
        assert_eq!(checked_frame_size(1024, 1, Some(4096)).unwrap(), usize::MAX);
        assert!(checked_frame_size(1024, 0, None).is_err());
    }

    #[test]
    fn device_budget_is_stricter_than_the_wire_format_cap() {
        let failure = checked_frame_size_with_budget(
            8 * 1024 * 1024,
            2,
            Some(4 * 1024 * 1024 + 1),
            MemoryBudget::MOBILE_EXTENSION,
        )
        .expect_err("ciphertext overhead exceeds the extension's one-frame budget");
        assert!(matches!(failure, DownloadFailure::TooLargeForContext { .. }));
    }

    #[test]
    fn main_app_budgets_accept_every_valid_profile_frame_cap() {
        let mib = 1024 * 1024u64;
        for (budget, plaintext_cap) in [
            (MemoryBudget::MOBILE_APP, 32 * mib),
            (MemoryBudget::BROWSER, 128 * mib),
            (MemoryBudget::NATIVE, 256 * mib),
        ] {
            let frame = plaintext_cap + CHUNK_OVERHEAD;
            assert_eq!(
                checked_frame_size_with_budget(frame * 2, 2, Some(plaintext_cap), budget),
                Ok(frame as usize),
                "budget {budget:?} must open its profile's valid frame cap"
            );
        }
    }

    #[test]
    fn extension_limit_returns_a_typed_handoff_error() {
        let plaintext_size = 32 * 1024 * 1024u64;
        let frame_size = plaintext_size + CHUNK_OVERHEAD;
        let failure =
            checked_frame_size_with_budget(frame_size * 2, 2, Some(plaintext_size), MemoryBudget::MOBILE_EXTENSION)
                .unwrap_err();
        assert_eq!(
            failure,
            DownloadFailure::TooLargeForContext {
                frame_size,
                context_limit: MemoryBudget::MOBILE_EXTENSION.download_frame_bytes,
            }
        );
    }

    #[test]
    fn largest_entitled_legacy_chunk_count_is_streamable() {
        assert!(std::hint::black_box(MAX_CHUNK_COUNT) > MAX_MATERIALIZED_CHUNK_COUNT);
        assert_eq!(
            checked_frame_size_with_budget(
                beebeeb_types::quota::MAX_TOTAL_STORAGE as u64,
                MAX_CHUNK_COUNT,
                Some(1024 * 1024),
                MemoryBudget::MOBILE_APP,
            ),
            Ok(1024 * 1024 + CHUNK_OVERHEAD as usize)
        );
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
