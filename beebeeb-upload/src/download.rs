//! Download + decrypt protocol for Beebeeb E2E encrypted storage.
//!
//! Mirrors the upload protocol: fetches encrypted bytes from the server,
//! splits into `nonce(12) || ciphertext` chunks, decrypts each with the
//! per-file AES-256-GCM key derived via HKDF, and writes the plaintext to
//! disk. Atomic rename at the end.

use std::io::{BufWriter, Write};

use beebeeb_core::chunk_stream::{ChunkDecryptor, ExpectedChunkFormat, VersionCommitment};
use beebeeb_core::download::DownloadFailure;
use beebeeb_types::limits::MemoryBudget;

use crate::error::UploadError;
use crate::retry;

/// Per-chunk wire overhead: `nonce(12) + tag(16)`.
const GCM_OVERHEAD: u64 = beebeeb_core::chunk_stream::CHUNK_OVERHEAD;

/// Map core's download failure onto this crate's error, keeping the variant a
/// client already branches on and the message it already prints.
fn map_download_failure(failure: DownloadFailure) -> UploadError {
    match failure {
        DownloadFailure::InvalidInput(message) => UploadError::InvalidInput(message),
        DownloadFailure::Io(message) => UploadError::IoError(message),
        DownloadFailure::TooLargeForContext {
            frame_size,
            context_limit,
        } => UploadError::TooLargeForContext {
            frame_size,
            context_limit,
        },
        other => UploadError::InvalidResponse(other.to_string()),
    }
}

fn check_temp_disk_limit(total: u64, budget: MemoryBudget) -> Result<(), UploadError> {
    if let Some(limit) = budget.temp_disk_bytes {
        if total > limit {
            return Err(UploadError::InvalidResponse(format!(
                "download exceeds the caller's temporary cache limit {limit} bytes"
            )));
        }
    }
    Ok(())
}

/// The `{output}.tmp` file a download writes into before the atomic rename.
///
/// `Drop` removes it unless [`Self::commit`] renamed it into place, so every
/// error path in unwind builds — a `?` while reading the body, a decryption
/// failure, a flush error, a failed rename — leaves no decrypted frames
/// behind. (The old explicit `remove_file` at each `return` missed the `?`
/// exits.) This holds only where unwinding runs `Drop`: the workspace sets
/// `panic = "abort"` for release builds (`Cargo.toml`), so a panic does not
/// unwind there and the temp file can remain. The guard is error cleanup, not
/// a panic safety net.
#[cfg(not(unix))]
struct TempOutput {
    path: std::path::PathBuf,
    renamed: bool,
}

#[cfg(not(unix))]
impl TempOutput {
    /// Create the parent directory and the temp file; the guard removes the
    /// file on drop until it is committed.
    fn create(output_path: &str) -> Result<(Self, std::fs::File), UploadError> {
        let path = std::path::PathBuf::from(format!("{output_path}.tmp"));
        if let Some(parent) = std::path::Path::new(output_path).parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| UploadError::IoError(format!("create output parent dir: {e}")))?;
        }
        let file =
            std::fs::File::create(&path).map_err(|e| UploadError::IoError(format!("create output file: {e}")))?;
        Ok((Self { path, renamed: false }, file))
    }

    /// Rename the temp file into place and disarm the guard.
    fn commit(mut self, output_path: &str) -> Result<(), UploadError> {
        std::fs::rename(&self.path, output_path).map_err(|e| UploadError::IoError(format!("rename output: {e}")))?;
        self.renamed = true;
        Ok(())
    }
}

#[cfg(not(unix))]
impl Drop for TempOutput {
    fn drop(&mut self) {
        if !self.renamed {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

#[cfg(unix)]
struct TempOutput {
    pending: Option<beebeeb_core::path_safety::PendingPublish>,
}

#[cfg(unix)]
impl TempOutput {
    fn create(output_path: &str) -> Result<(Self, std::fs::File), UploadError> {
        let output = std::path::Path::new(output_path);
        let parent = output
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| std::path::Path::new("."));
        std::fs::create_dir_all(parent)
            .map_err(|error| UploadError::IoError(format!("create output parent dir: {error}")))?;
        let name = output
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| UploadError::InvalidInput("output path has no UTF-8 file name".into()))?;
        let directory = beebeeb_core::path_safety::TrustedDirectory::open(parent)
            .map_err(|error| UploadError::IoError(format!("open output directory: {error}")))?;
        let (pending, file) = directory
            .begin_publish(name, beebeeb_core::path_safety::Rules::Host)
            .map_err(|error| UploadError::IoError(format!("create output temp file: {error}")))?;
        Ok((Self { pending: Some(pending) }, file))
    }

    fn commit(mut self, _output_path: &str) -> Result<(), UploadError> {
        self.pending
            .take()
            .ok_or_else(|| UploadError::IoError("output publication already finished".into()))?
            .commit()
            .map_err(|error| UploadError::IoError(format!("publish output: {error}")))
    }
}

/// Read more body bytes (via `Response::chunk`) until `buf.len() >= want` or EOF.
async fn fill_to(
    resp: &mut reqwest::Response,
    buf: &mut Vec<u8>,
    want: usize,
    limit: usize,
) -> Result<(), UploadError> {
    while buf.len() < want {
        match resp
            .chunk()
            .await
            .map_err(|e| UploadError::Network(format!("reading response body: {e}")))?
        {
            Some(b) => push_frame_bytes(buf, &b, limit)?,
            None => break,
        }
    }
    Ok(())
}

/// Append one body read to `buf`, refusing a frame over `limit` BEFORE the
/// bytes are buffered. `limit` is a parameter so the boundary is testable
/// without allocating a maximum-size frame.
fn push_frame_bytes(buf: &mut Vec<u8>, bytes: &[u8], limit: usize) -> Result<(), UploadError> {
    if buf.len().saturating_add(bytes.len()) > limit {
        return Err(UploadError::InvalidResponse(format!(
            "frame exceeds the maximum {limit} bytes"
        )));
    }
    buf.extend_from_slice(bytes);
    Ok(())
}

fn encrypted_size_estimate(
    content_length: Option<u64>,
    original_size: u64,
    chunk_count: u32,
) -> Result<u64, UploadError> {
    if let Some(length) = content_length.filter(|length| *length > 0) {
        return Ok(length);
    }
    let overhead = GCM_OVERHEAD
        .checked_mul(u64::from(chunk_count))
        .ok_or_else(|| UploadError::InvalidResponse("encrypted size overhead overflow".into()))?;
    original_size
        .checked_add(overhead)
        .ok_or_else(|| UploadError::InvalidResponse("encrypted size estimate overflow".into()))
}

/// Drain the rest of the response body into `buf`, capped at one maximum wire
/// frame. The last frame (and the single-frame `usize::MAX` case) has no size
/// header to trust, so the cap is enforced here while reading.
async fn drain_rest(resp: &mut reqwest::Response, buf: &mut Vec<u8>, limit: usize) -> Result<(), UploadError> {
    while let Some(b) = resp
        .chunk()
        .await
        .map_err(|e| UploadError::Network(format!("reading response body: {e}")))?
    {
        push_frame_bytes(buf, &b, limit)?;
    }
    Ok(())
}

/// Callback for download progress reporting. Implemented by Swift/Kotlin callers.
pub trait DownloadProgressCallback: Send + Sync {
    /// Called after each chunk is successfully decrypted and written.
    fn on_chunk_decrypted(&self, chunk_index: u32, total_chunks: u32);
    /// Called when the download + decryption completes successfully.
    fn on_complete(&self, output_path: &str);
    /// Called when a non-recoverable error occurs.
    fn on_error(&self, error: &str);
}

/// Result of a successful download + decrypt.
#[derive(Debug, Clone)]
pub struct DownloadResult {
    /// Path to the decrypted output file.
    pub output_path: String,
    /// Total plaintext bytes written.
    pub plaintext_size: u64,
    /// Number of chunks that were decrypted.
    pub chunks_decrypted: u32,
}

/// HTTP client for the Beebeeb download protocol.
///
/// Each instance is bound to a single API base URL and auth token.
pub struct DownloadClient {
    api_url: String,
    token: String,
    http: reqwest::Client,
    memory_budget: MemoryBudget,
}

impl DownloadClient {
    /// Create a new download client.
    ///
    /// `api_url` is the base URL (e.g. `https://api.beebeeb.io`), without
    /// trailing slash. `token` is the bearer auth token.
    pub fn new(api_url: &str, token: &str) -> Self {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(600))
            .build()
            .expect("failed to build reqwest client");

        Self {
            api_url: api_url.trim_end_matches('/').to_string(),
            token: token.to_string(),
            http,
            memory_budget: MemoryBudget::MOBILE_APP,
        }
    }

    pub fn with_memory_budget(mut self, memory_budget: MemoryBudget) -> Self {
        self.memory_budget = memory_budget;
        self
    }

    /// Download an encrypted file and **stream-decrypt** it to disk with
    /// constant memory.
    ///
    /// `GET /api/v1/files/{file_id}/download` returns the chunks concatenated
    /// (`nonce(12) || ciphertext || tag(16)` each) with `X-Chunk-Count`,
    /// `X-Original-Size`, and (for V2 files) `X-Chunk-Size` headers. The body is
    /// read incrementally with `Response::chunk()`, one logical frame at a time,
    /// each decrypted through the shared [`ChunkDecryptor`] (single crypto
    /// point) and written out — never buffering the whole payload.
    ///
    /// Frame sizing: the server's `X-Chunk-Size` (uniform plaintext chunk size
    /// for the file's version) is authoritative — each wire frame is
    /// `chunk_size + GCM_OVERHEAD` for the first N-1 chunks, remainder for the
    /// last. Streaming uploads make every chunk but the last exactly that size,
    /// so the old `total / chunk_count` average mis-sized frame 0 whenever the
    /// file size was not an exact multiple of the chunk size, failing the GCM
    /// tag. When the header is absent (legacy V1) we fall back to
    /// `total / chunk_count`, matching [`compute_chunk_boundaries`]. The file
    /// key is derived via `HKDF(master_key, file_id)`.
    ///
    /// `expected` (task 1908) and `version` come from the file's encrypted
    /// metadata ([`beebeeb_core::encrypt::decrypt_file_metadata`]), never from a
    /// server field: a v2 file opens only as the upload `version` names, and
    /// with no `version` only a v1 file opens (core's ruling of 2026-11-07).
    pub async fn download_and_decrypt(
        &self,
        master_key: &beebeeb_core::kdf::MasterKey,
        file_id: &str,
        expected: ExpectedChunkFormat,
        version: Option<VersionCommitment>,
        output_path: &str,
        callback: Option<&dyn DownloadProgressCallback>,
    ) -> Result<DownloadResult, UploadError> {
        let url = format!("{}/api/v1/files/{}/download", self.api_url, file_id);

        // The retry covers obtaining a good response (connect + status); once we
        // start streaming the body a mid-stream failure is not retried.
        let mut resp = retry::with_retry(|| async {
            let resp = self
                .http
                .get(&url)
                .bearer_auth(&self.token)
                .send()
                .await
                .map_err(|e| UploadError::Network(e.to_string()))?;
            crate::error::check_response_headers(&resp)?;

            let status = resp.status().as_u16();
            if status == 429 {
                return Err(Self::parse_rate_limit(&resp).await);
            }
            if status >= 500 {
                let error = crate::error::read_server_error(resp).await;
                return Err(UploadError::ServerError {
                    status,
                    message: error.message,
                });
            }
            if status >= 400 {
                let error = crate::error::read_server_error(resp).await;
                return Err(UploadError::ClientError {
                    status,
                    message: error.message,
                });
            }
            Ok(resp)
        })
        .await?;

        let chunk_count: u32 = resp
            .headers()
            .get("X-Chunk-Count")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok())
            .unwrap_or(1);
        let original_size: u64 = resp
            .headers()
            .get("X-Original-Size")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        // Uniform plaintext chunk size for this file's version (V2 files only).
        // When present it is authoritative for frame sizing; absent → legacy V1
        // fallback to the `total / chunk_count` average.
        let chunk_size: Option<u64> = resp
            .headers()
            .get("X-Chunk-Size")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok())
            .filter(|&v| v > 0);
        // Total encrypted length: prefer Content-Length, else derive from the
        // plaintext size + per-chunk overhead. Only sizes the first N-1 frames;
        // the last frame drains the remainder, so a small estimate error
        // self-corrects (and a wrong size fails the GCM tag).
        let total = encrypted_size_estimate(resp.content_length(), original_size, chunk_count)?;

        self.stream_decrypt_to_disk(
            &mut resp,
            master_key,
            file_id,
            expected,
            version,
            chunk_count,
            total,
            chunk_size,
            output_path,
            callback,
        )
        .await
    }

    /// Read the response body incrementally and decrypt frame-by-frame.
    #[allow(clippy::too_many_arguments)]
    async fn stream_decrypt_to_disk(
        &self,
        resp: &mut reqwest::Response,
        master_key: &beebeeb_core::kdf::MasterKey,
        file_id: &str,
        expected: ExpectedChunkFormat,
        version: Option<VersionCommitment>,
        chunk_count: u32,
        total: u64,
        chunk_size: Option<u64>,
        output_path: &str,
        callback: Option<&dyn DownloadProgressCallback>,
    ) -> Result<DownloadResult, UploadError> {
        if chunk_count == 0 {
            return Err(UploadError::InvalidInput("chunk_count must be > 0".into()));
        }
        let n = chunk_count as usize;
        // Frame size for the first n-1 frames; the last drains the remainder.
        // When the server sends `X-Chunk-Size` (V2 files) each wire frame is the
        // uniform plaintext chunk size + GCM_OVERHEAD (nonce + tag) — exact even
        // when the file size is not a multiple of the chunk size. Only legacy V1
        // responses (no header) fall back to the `total / chunk_count` average,
        // which matches `compute_chunk_boundaries`.
        let frame_size =
            beebeeb_core::download::checked_frame_size_with_budget(total, chunk_count, chunk_size, self.memory_budget)
                .map_err(map_download_failure)?;
        let frame_limit = usize::try_from(self.memory_budget.download_frame_bytes)
            .map_err(|_| UploadError::InvalidInput("download memory budget does not fit usize".into()))?;

        // Write to .tmp then atomic rename; the guard deletes the temp file on
        // every error path (including the `?` before the loop finishes).
        let (tmp, output_file) = TempOutput::create(output_path)?;
        let mut writer = BufWriter::new(output_file);

        let mut decryptor = ChunkDecryptor::for_version_with_file_key(
            beebeeb_core::kdf::derive_file_key(master_key, file_id.as_bytes()),
            file_id,
            expected,
            version,
        );
        let mut carry: Vec<u8> = Vec::new();
        let mut total_plaintext: u64 = 0;
        let mut chunks_decrypted: u32 = 0;

        for i in 0..n {
            let is_last = i == n - 1;
            let frame: Vec<u8> = if is_last || frame_size == usize::MAX {
                drain_rest(resp, &mut carry, frame_limit).await?;
                std::mem::take(&mut carry)
            } else {
                fill_to(resp, &mut carry, frame_size, frame_limit).await?;
                if carry.len() < frame_size {
                    return Err(UploadError::InvalidResponse(format!(
                        "download truncated at chunk {i}/{n}: wanted {frame_size}, got {}",
                        carry.len()
                    )));
                }
                carry.drain(..frame_size).collect()
            };

            let dec = match decryptor.push_frame(&frame) {
                Ok(d) => d,
                Err(e) => {
                    return Err(UploadError::InvalidResponse(format!(
                        "decryption failed for chunk {i}: {e}"
                    )));
                }
            };

            if let Err(e) = writer.write_all(&dec.data) {
                return Err(UploadError::IoError(format!("write output: {e}")));
            }
            let next_total = total_plaintext
                .checked_add(dec.data.len() as u64)
                .ok_or_else(|| UploadError::InvalidResponse("plaintext size overflow".into()))?;
            check_temp_disk_limit(next_total, self.memory_budget)?;
            total_plaintext = next_total;
            chunks_decrypted += 1;
            if let Some(cb) = callback {
                cb.on_chunk_decrypted(chunks_decrypted, chunk_count);
            }
        }

        // Task 1908: end-of-stream check. `X-Chunk-Count` is a server value; a v2
        // file whose count was understated ends before its last chunk and fails
        // here (an overstated count already failed above: nothing may follow the
        // last chunk). Never rename a truncated plaintext into place.
        if let Err(e) = decryptor.finish() {
            drop(writer);
            return Err(UploadError::InvalidResponse(format!(
                "download incomplete after {chunks_decrypted} chunks: {e}"
            )));
        }

        writer
            .flush()
            .map_err(|e| UploadError::IoError(format!("flush output: {e}")))?;
        drop(writer);
        tmp.commit(output_path)?;

        if let Some(cb) = callback {
            cb.on_complete(output_path);
        }
        tracing::info!(
            chunks = chunks_decrypted,
            plaintext_bytes = total_plaintext,
            "streaming download + decrypt complete"
        );

        Ok(DownloadResult {
            output_path: output_path.to_string(),
            plaintext_size: total_plaintext,
            chunks_decrypted,
        })
    }

    async fn parse_rate_limit(resp: &reqwest::Response) -> UploadError {
        let retry_after = resp
            .headers()
            .get("Retry-After")
            .and_then(|v| v.to_str().ok())
            .and_then(beebeeb_core::retry::parse_retry_after)
            .unwrap_or(60);

        UploadError::RateLimited {
            retry_after_secs: retry_after,
        }
    }
}

/// Split encrypted bytes into chunks and decrypt each to the output file.
///
/// This is a pure function (no HTTP) — testable in isolation.
///
/// The encrypted payload is a concatenation of equal-sized encrypted chunks
/// (last chunk may be smaller). Each chunk: `nonce(12) || ciphertext`.
/// Given `chunk_count` and total `encrypted_bytes.len()`, we derive each
/// chunk's byte range.
///
/// Task 1908: the chunks are opened as one file's ordered stream (v2
/// position-bound or v1 legacy, decided by chunk 0). `file_id` is the id the
/// file was uploaded under; it is bound into every v2 frame. `expected` comes
/// from the file's encrypted metadata (see [`DownloadClient::download_and_decrypt`]).
#[allow(clippy::too_many_arguments)]
pub fn decrypt_downloaded_bytes(
    file_key: &beebeeb_core::kdf::FileKey,
    file_id: &str,
    expected: ExpectedChunkFormat,
    version: Option<VersionCommitment>,
    encrypted_bytes: &[u8],
    chunk_count: u32,
    output_path: &str,
    callback: Option<&dyn DownloadProgressCallback>,
) -> Result<DownloadResult, UploadError> {
    if chunk_count == 0 {
        return Err(UploadError::InvalidInput("chunk_count must be > 0".into()));
    }
    // Write to .tmp then atomic rename; the guard deletes the temp file on
    // every error path (a chunk failure, a flush error and the `?` exits).
    let (tmp, output_file) = TempOutput::create(output_path)?;
    let mut writer = BufWriter::new(output_file);

    // The loop itself is core's (move 10); this crate still owns the temp file,
    // the progress callback and the atomic rename.
    let summary = match beebeeb_core::download::decrypt_chunks_to(
        file_key,
        file_id,
        expected,
        version,
        chunk_count,
        encrypted_bytes,
        &mut writer,
        |done, total| {
            if let Some(callback) = callback {
                callback.on_chunk_decrypted(done, total);
            }
        },
    ) {
        Ok(summary) => summary,
        Err(failure) => {
            drop(writer);
            return Err(map_download_failure(failure));
        }
    };
    let total_plaintext = summary.plaintext_size;
    let chunks_decrypted = summary.chunks_decrypted;

    writer
        .flush()
        .map_err(|e| UploadError::IoError(format!("flush output: {e}")))?;
    drop(writer);

    // Atomic rename
    tmp.commit(output_path)?;

    if let Some(cb) = callback {
        cb.on_complete(output_path);
    }

    tracing::info!(
        file_id = "?",
        chunks = chunks_decrypted,
        plaintext_bytes = total_plaintext,
        "download + decrypt complete"
    );

    Ok(DownloadResult {
        output_path: output_path.to_string(),
        plaintext_size: total_plaintext,
        chunks_decrypted,
    })
}

/// Compute (start, end) byte ranges for each chunk within the encrypted payload.
///
/// All chunks except the last have the same size. The last chunk gets the remainder.
/// Each chunk must be at least `NONCE_LEN + GCM_TAG_LEN` bytes (28 bytes: 12 nonce + 16 tag).
pub fn compute_chunk_boundaries(total_len: usize, chunk_count: u32) -> Result<Vec<(usize, usize)>, UploadError> {
    beebeeb_core::download::compute_chunk_boundaries(total_len, chunk_count).map_err(map_download_failure)
}

/// Synchronous blocking wrapper for `download_and_decrypt`.
///
/// Creates a tokio runtime internally and blocks until complete.
/// Designed to be called from Swift `Task { }` or Kotlin
/// `withContext(Dispatchers.IO) { }`.
#[allow(clippy::too_many_arguments)]
pub fn download_and_decrypt_file<'a>(
    api_url: &str,
    token: &str,
    master_key: &beebeeb_core::kdf::MasterKey,
    file_id: &str,
    expected: ExpectedChunkFormat,
    version: Option<VersionCommitment>,
    output_path: &str,
    callback: Option<Box<dyn DownloadProgressCallback + 'a>>,
) -> Result<DownloadResult, UploadError> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| UploadError::IoError(format!("failed to create tokio runtime: {e}")))?;

    rt.block_on(async {
        let client = DownloadClient::new(api_url, token);
        client
            .download_and_decrypt(
                master_key,
                file_id,
                expected,
                version,
                output_path,
                callback.as_ref().map(|b| b.as_ref() as &dyn DownloadProgressCallback),
            )
            .await
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- DownloadResult construction --

    #[test]
    fn download_result_fields() {
        let result = DownloadResult {
            output_path: "/tmp/file.bin".into(),
            plaintext_size: 1024,
            chunks_decrypted: 2,
        };
        assert_eq!(result.output_path, "/tmp/file.bin");
        assert_eq!(result.plaintext_size, 1024);
        assert_eq!(result.chunks_decrypted, 2);
    }

    #[test]
    fn hostile_original_size_cannot_overflow_even_with_content_length() {
        assert_eq!(encrypted_size_estimate(Some(42), u64::MAX, u32::MAX).unwrap(), 42);
        assert!(encrypted_size_estimate(None, u64::MAX, 1).is_err());
    }

    // -- compute_chunk_boundaries --

    #[test]
    fn boundaries_single_chunk() {
        let boundaries = compute_chunk_boundaries(100, 1).unwrap();
        assert_eq!(boundaries, vec![(0, 100)]);
    }

    #[test]
    fn boundaries_two_equal_chunks() {
        let boundaries = compute_chunk_boundaries(200, 2).unwrap();
        assert_eq!(boundaries, vec![(0, 100), (100, 200)]);
    }

    #[test]
    fn boundaries_three_chunks_with_remainder() {
        let boundaries = compute_chunk_boundaries(301, 3).unwrap();
        // base = 100, remainder = 1 -> last chunk gets 101
        assert_eq!(boundaries, vec![(0, 100), (100, 200), (200, 301)]);
    }

    #[test]
    fn boundaries_zero_chunks_error() {
        assert!(compute_chunk_boundaries(100, 0).is_err());
    }

    #[test]
    fn boundaries_empty_payload_error() {
        assert!(compute_chunk_boundaries(0, 1).is_err());
    }

    #[test]
    fn boundaries_chunk_too_small_error() {
        // 27 bytes is less than NONCE_LEN(12) + GCM_TAG_LEN(16) = 28
        assert!(compute_chunk_boundaries(27, 1).is_err());
    }

    #[test]
    fn boundaries_multi_chunk_too_small_error() {
        // 56 bytes / 3 = 18 bytes per chunk — too small
        assert!(compute_chunk_boundaries(56, 3).is_err());
    }

    #[test]
    fn boundaries_minimum_valid_single_chunk() {
        // Exactly 28 bytes = NONCE(12) + TAG(16) + 0 plaintext
        let boundaries = compute_chunk_boundaries(28, 1).unwrap();
        assert_eq!(boundaries, vec![(0, 28)]);
    }

    // -- decrypt_downloaded_bytes (integration with real crypto) --

    #[test]
    fn decrypt_downloaded_single_chunk() {
        use beebeeb_core::encrypt::encrypt_chunk_raw;
        use beebeeb_core::kdf::{derive_file_key, derive_master_key};

        let mk = derive_master_key("test-password", b"test-salt-16bytes").unwrap();
        let fk = derive_file_key(&mk, b"file-001");

        // Encrypt a small plaintext
        let plaintext = b"hello, download!";
        let encrypted = encrypt_chunk_raw(&fk, plaintext).unwrap();

        let dir = std::env::temp_dir().join("beebeeb_download_single");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let output = dir.join("output.bin");
        let output_str = output.to_str().unwrap();

        let result = decrypt_downloaded_bytes(
            &fk,
            "file-001",
            ExpectedChunkFormat::Unrecorded,
            None,
            &encrypted,
            1,
            output_str,
            None,
        )
        .unwrap();

        assert_eq!(result.plaintext_size, plaintext.len() as u64);
        assert_eq!(result.chunks_decrypted, 1);
        let recovered = std::fs::read(&output).unwrap();
        assert_eq!(recovered, plaintext);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn decrypt_downloaded_multi_chunk() {
        use beebeeb_core::encrypt::encrypt_chunk_raw;
        use beebeeb_core::kdf::{derive_file_key, derive_master_key};

        let mk = derive_master_key("test-password", b"test-salt-16bytes").unwrap();
        let fk = derive_file_key(&mk, b"file-002");

        let chunk1_plain = b"first chunk data";
        let chunk2_plain = b"second chunk data here";

        let enc1 = encrypt_chunk_raw(&fk, chunk1_plain).unwrap();
        let enc2 = encrypt_chunk_raw(&fk, chunk2_plain).unwrap();

        // Server concatenates all chunks
        let mut payload = Vec::new();
        payload.extend_from_slice(&enc1);
        payload.extend_from_slice(&enc2);

        // Both encrypted chunks are the same size because plaintext lengths differ
        // but nonce(12) + plaintext + tag(16) can differ per chunk. We need
        // the chunks to be equal-sized for the splitter to work when chunk_count > 1.
        // In practice, the server stores fixed-size encrypted chunks (same plaintext
        // chunk size, so same encrypted size). For this test, we pad to equal size.

        // Actually, in the real protocol each chunk except the last is the same
        // plaintext size, so same encrypted size. The last may be smaller.
        // For this test, use same-size plaintext chunks.
        let chunk_plain = vec![0xABu8; 64];
        let enc_a = encrypt_chunk_raw(&fk, &chunk_plain).unwrap();
        let enc_b = encrypt_chunk_raw(&fk, &chunk_plain).unwrap();

        // Both are same encrypted size: 12 + 64 + 16 = 92 bytes each
        assert_eq!(enc_a.len(), enc_b.len());

        let mut payload = Vec::new();
        payload.extend_from_slice(&enc_a);
        payload.extend_from_slice(&enc_b);

        let dir = std::env::temp_dir().join("beebeeb_download_multi");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let output = dir.join("output.bin");
        let output_str = output.to_str().unwrap();

        let result = decrypt_downloaded_bytes(
            &fk,
            "file-002",
            ExpectedChunkFormat::Unrecorded,
            None,
            &payload,
            2,
            output_str,
            None,
        )
        .unwrap();

        assert_eq!(result.chunks_decrypted, 2);
        assert_eq!(result.plaintext_size, 128); // 64 + 64
        let recovered = std::fs::read(&output).unwrap();
        let mut expected = Vec::new();
        expected.extend_from_slice(&chunk_plain);
        expected.extend_from_slice(&chunk_plain);
        assert_eq!(recovered, expected);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn decrypt_downloaded_wrong_key_fails() {
        use beebeeb_core::encrypt::encrypt_chunk_raw;
        use beebeeb_core::kdf::{derive_file_key, derive_master_key};

        let mk = derive_master_key("test-password", b"test-salt-16bytes").unwrap();
        let fk = derive_file_key(&mk, b"file-003");
        let encrypted = encrypt_chunk_raw(&fk, b"secret").unwrap();

        let wrong_mk = derive_master_key("wrong-password", b"wrong-salt-16byte").unwrap();
        let wrong_fk = derive_file_key(&wrong_mk, b"file-003");

        let dir = std::env::temp_dir().join("beebeeb_download_wrongkey");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let output = dir.join("output.bin");
        let output_str = output.to_str().unwrap();

        let result = decrypt_downloaded_bytes(
            &wrong_fk,
            "file-003",
            ExpectedChunkFormat::Unrecorded,
            None,
            &encrypted,
            1,
            output_str,
            None,
        );
        assert!(result.is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn decrypt_downloaded_empty_plaintext() {
        use beebeeb_core::encrypt::encrypt_chunk_raw;
        use beebeeb_core::kdf::{derive_file_key, derive_master_key};

        let mk = derive_master_key("test-password", b"test-salt-16bytes").unwrap();
        let fk = derive_file_key(&mk, b"file-empty");
        let encrypted = encrypt_chunk_raw(&fk, b"").unwrap();
        // encrypted is 12 + 0 + 16 = 28 bytes

        let dir = std::env::temp_dir().join("beebeeb_download_empty");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let output = dir.join("output.bin");
        let output_str = output.to_str().unwrap();

        let result = decrypt_downloaded_bytes(
            &fk,
            "file-empty",
            ExpectedChunkFormat::Unrecorded,
            None,
            &encrypted,
            1,
            output_str,
            None,
        )
        .unwrap();

        assert_eq!(result.plaintext_size, 0);
        assert_eq!(result.chunks_decrypted, 1);
        let recovered = std::fs::read(&output).unwrap();
        assert!(recovered.is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn decrypt_zero_chunk_count_errors() {
        let dir = std::env::temp_dir().join("beebeeb_download_zero_chunks");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let output = dir.join("output.bin");
        let output_str = output.to_str().unwrap();

        use beebeeb_core::kdf::{derive_file_key, derive_master_key};
        let mk = derive_master_key("test-password", b"test-salt-16bytes").unwrap();
        let fk = derive_file_key(&mk, b"file-zero");

        let result = decrypt_downloaded_bytes(
            &fk,
            "file-zero",
            ExpectedChunkFormat::Unrecorded,
            None,
            &[0u8; 100],
            0,
            output_str,
            None,
        );
        assert!(result.is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// v2 frames as every client writes them after task 1908 (32-byte chunks).
    #[allow(deprecated)] // a test fixture: the id comes from the test, not from core
    fn v2_payload(mk: &beebeeb_core::kdf::MasterKey, file_id: &str, data: &[u8]) -> (Vec<Vec<u8>>, VersionCommitment) {
        use beebeeb_core::chunk_stream::{ChunkEncryptor, ChunkFormat};
        // WRITE_FORMAT is still v1 (read-only rollout phase), so these tests
        // ask for v2 explicitly via the dev-only `test-support` feature.
        let mut enc = ChunkEncryptor::for_push_with_chunk_size(mk, file_id, data.len() as u64, 32)
            .unwrap()
            .with_format(ChunkFormat::V2)
            .unwrap();
        let frames: Vec<Vec<u8>> = data.chunks(32).map(|c| enc.push_chunk(c).unwrap().data).collect();
        assert_eq!(enc.format(), ChunkFormat::V2, "v2_payload requires a v2 writer");
        let version = enc.version_commitment(None).unwrap();
        enc.finish().unwrap();
        (frames, version)
    }

    #[test]
    fn decrypt_downloaded_v2_swap_and_truncation_rejected() {
        use beebeeb_core::kdf::{derive_file_key, derive_master_key};
        let mk = derive_master_key("test-password", b"test-salt-16bytes").unwrap();
        let data: Vec<u8> = (0..96u8).collect(); // 3 equal 32-byte chunks
        let (frames, version) = v2_payload(&mk, "file-v2", &data);
        let v = Some(version);
        let fk = derive_file_key(&mk, b"file-v2");

        let dir = std::env::temp_dir().join("beebeeb_download_v2");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let output = dir.join("output.bin");
        let out = output.to_str().unwrap();

        let ok = decrypt_downloaded_bytes(
            &fk,
            "file-v2",
            ExpectedChunkFormat::V2,
            v,
            &frames.concat(),
            3,
            out,
            None,
        )
        .unwrap();
        assert_eq!(ok.plaintext_size, 96);
        assert_eq!(std::fs::read(&output).unwrap(), data);
        std::fs::remove_file(&output).unwrap();

        // Server swaps two equal-size chunks.
        let swapped = [frames[1].clone(), frames[0].clone(), frames[2].clone()].concat();
        assert!(decrypt_downloaded_bytes(&fk, "file-v2", ExpectedChunkFormat::V2, v, &swapped, 3, out, None).is_err());
        assert!(!output.exists());

        // Server withholds the last chunk and reports chunk_count = 2.
        let truncated = [frames[0].clone(), frames[1].clone()].concat();
        assert!(
            decrypt_downloaded_bytes(&fk, "file-v2", ExpectedChunkFormat::V2, v, &truncated, 2, out, None).is_err()
        );
        assert!(!output.exists(), "a truncated download must not be renamed into place");
        assert!(!dir.join("output.bin.tmp").exists());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn oversized_last_frame_is_refused_without_buffering() {
        // A no-header last frame is drained, not sized; the cap lives in
        // `push_frame_bytes` so the extra bytes never reach the buffer.
        let mut buf = vec![0u8; 8];
        let err = push_frame_bytes(&mut buf, &[1], 8).expect_err("a frame over the limit must be refused");
        assert!(matches!(err, UploadError::InvalidResponse(_)), "got {err:?}");
        assert_eq!(buf.len(), 8, "the refused byte is not buffered");

        // The production limit is one maximum chunk plus the GCM overhead.
        assert_eq!(
            beebeeb_core::download::MAX_FRAME_SIZE,
            256 * 1024 * 1024 + 28,
            "MAX_CHUNK_SIZE + nonce(12) + tag(16)"
        );
        let mut ok = Vec::new();
        push_frame_bytes(&mut ok, &[1, 2, 3], 3).expect("a frame at the limit is accepted");
        assert_eq!(ok.len(), 3);
    }

    #[test]
    fn main_app_does_not_refuse_a_file_above_512_mib_by_size() {
        let size = 513 * 1024 * 1024;
        assert!(check_temp_disk_limit(size, MemoryBudget::MOBILE_APP).is_ok());
        assert!(check_temp_disk_limit(size, MemoryBudget::MOBILE_APP.with_temp_disk_limit(512 * 1024 * 1024)).is_err());
    }

    #[test]
    fn download_client_constructor() {
        let client = DownloadClient::new("https://api.beebeeb.io/", "test-token");
        assert_eq!(client.api_url, "https://api.beebeeb.io");
        assert_eq!(client.token, "test-token");
    }

    #[test]
    fn download_client_trims_trailing_slash() {
        let client = DownloadClient::new("https://api.beebeeb.io///", "tok");
        // trim_end_matches removes all trailing slashes
        assert!(!client.api_url.ends_with('/'));
    }

    // -- .tmp cleanup on a failed download --

    /// Serve one HTTP response whose body stops short of its `Content-Length`,
    /// so the client sees a mid-body failure after the bytes that arrived.
    fn serve_truncated_body(
        body: Vec<u8>,
        declared_length: usize,
        extra_headers: &str,
    ) -> (String, std::thread::JoinHandle<()>) {
        use std::io::{Read, Write};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let addr = listener.local_addr().unwrap();
        let head =
            format!("HTTP/1.1 200 OK\r\nContent-Length: {declared_length}\r\n{extra_headers}Connection: close\r\n\r\n");
        let handle = std::thread::spawn(move || {
            let (mut sock, _) = listener.accept().expect("accept");
            let mut request = Vec::new();
            let mut buf = [0u8; 1024];
            loop {
                let n = sock.read(&mut buf).expect("read request");
                if n == 0 {
                    break;
                }
                request.extend_from_slice(&buf[..n]);
                if request.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            sock.write_all(head.as_bytes()).expect("write head");
            sock.write_all(&body).expect("write body");
            sock.flush().expect("flush");
            // Dropping the socket with `declared_length > body.len()` is a
            // truncated response: the reader fails after the delivered frames.
        });
        (format!("http://{addr}"), handle)
    }

    struct CountingCallback(std::sync::atomic::AtomicU32);

    impl DownloadProgressCallback for CountingCallback {
        fn on_chunk_decrypted(&self, chunk_index: u32, _total_chunks: u32) {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            assert_eq!(chunk_index, 1, "the first frame is the only one that decrypts");
        }
        fn on_complete(&self, _output_path: &str) {}
        fn on_error(&self, _error: &str) {}
    }

    #[tokio::test]
    async fn failed_download_leaves_no_tmp_file() {
        use beebeeb_core::encrypt::encrypt_chunk_raw;
        use beebeeb_core::kdf::{derive_file_key, derive_master_key};

        let mk = derive_master_key("test-password", b"test-salt-16bytes").unwrap();
        let chunk = vec![0x7Bu8; 64];
        let frame = encrypt_chunk_raw(&derive_file_key(&mk, b"file-partial"), &chunk).unwrap();

        // Two equal frames; the first arrives whole, the second is cut off by a
        // connection closed before `Content-Length` bytes were delivered. That
        // failure happens after frame 0 was decrypted and written to `{out}.tmp`.
        let mut body = frame.clone();
        body.extend_from_slice(&frame[..10]);
        let (base, server) =
            serve_truncated_body(body, frame.len() * 2, "X-Chunk-Count: 2\r\nX-Original-Size: 128\r\n");

        let dir = std::env::temp_dir().join("beebeeb_download_partial");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let output = dir.join("output.bin");
        let out = output.to_str().unwrap();

        let callback = CountingCallback(std::sync::atomic::AtomicU32::new(0));
        let client = DownloadClient::new(&base, "test-token");
        let result = client
            .download_and_decrypt(
                &mk,
                "file-partial",
                ExpectedChunkFormat::Unrecorded,
                None,
                out,
                Some(&callback),
            )
            .await;

        assert!(
            result.is_err(),
            "a body shorter than Content-Length must fail the download"
        );
        assert_eq!(
            callback.0.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "the failure must come after the first good frame"
        );
        assert!(!output.exists(), "no truncated plaintext may be renamed into place");
        assert!(
            !dir.join("output.bin.tmp").exists(),
            "a failed download must not leave decrypted frames in {out}.tmp"
        );
        server.join().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
