//! Download + decrypt protocol for Beebeeb E2E encrypted storage.
//!
//! Mirrors the upload protocol: fetches encrypted bytes from the server,
//! splits into `nonce(12) || ciphertext` chunks, decrypts each with the
//! per-file AES-256-GCM key derived via HKDF, and writes the plaintext to
//! disk. Atomic rename at the end.

use std::io::{BufWriter, Write};

use beebeeb_core::chunk_stream::ChunkDecryptor;

use crate::error::UploadError;
use crate::retry;

const NONCE_LEN: usize = 12;
/// AES-256-GCM tag length in bytes.
const GCM_TAG_LEN: usize = 16;
/// Per-chunk wire overhead: `nonce(12) + tag(16)`.
const GCM_OVERHEAD: u64 = (NONCE_LEN + GCM_TAG_LEN) as u64;

/// Read more body bytes (via `Response::chunk`) until `buf.len() >= want` or EOF.
async fn fill_to(
    resp: &mut reqwest::Response,
    buf: &mut Vec<u8>,
    want: usize,
) -> Result<(), UploadError> {
    while buf.len() < want {
        match resp
            .chunk()
            .await
            .map_err(|e| UploadError::Network(format!("reading response body: {e}")))?
        {
            Some(b) => buf.extend_from_slice(&b),
            None => break,
        }
    }
    Ok(())
}

/// Drain the rest of the response body into `buf`.
async fn drain_rest(resp: &mut reqwest::Response, buf: &mut Vec<u8>) -> Result<(), UploadError> {
    while let Some(b) = resp
        .chunk()
        .await
        .map_err(|e| UploadError::Network(format!("reading response body: {e}")))?
    {
        buf.extend_from_slice(&b);
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
        }
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
    pub async fn download_and_decrypt(
        &self,
        master_key: &beebeeb_core::kdf::MasterKey,
        file_id: &str,
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

            let status = resp.status().as_u16();
            if status == 429 {
                return Err(Self::parse_rate_limit(&resp).await);
            }
            if status >= 500 {
                let text = resp.text().await.unwrap_or_default();
                return Err(UploadError::ServerError { status, message: text });
            }
            if status >= 400 {
                let text = resp.text().await.unwrap_or_default();
                return Err(UploadError::ClientError { status, message: text });
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
        let total: u64 = resp
            .content_length()
            .filter(|&v| v > 0)
            .unwrap_or(original_size + GCM_OVERHEAD * chunk_count as u64);

        self.stream_decrypt_to_disk(
            &mut resp,
            master_key,
            file_id,
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
        let frame_size = if n <= 1 {
            usize::MAX // single frame == whole body
        } else if let Some(cs) = chunk_size {
            (cs + GCM_OVERHEAD) as usize
        } else {
            (total / chunk_count as u64) as usize
        };

        // Write to .tmp then atomic rename.
        let tmp_path = format!("{output_path}.tmp");
        if let Some(parent) = std::path::Path::new(output_path).parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| UploadError::IoError(format!("create output parent dir: {e}")))?;
        }
        let output_file = std::fs::File::create(&tmp_path)
            .map_err(|e| UploadError::IoError(format!("create output file: {e}")))?;
        let mut writer = BufWriter::new(output_file);

        let mut decryptor = ChunkDecryptor::for_push(master_key, file_id);
        let mut carry: Vec<u8> = Vec::new();
        let mut total_plaintext: u64 = 0;
        let mut chunks_decrypted: u32 = 0;

        for i in 0..n {
            let is_last = i == n - 1;
            let frame: Vec<u8> = if is_last || frame_size == usize::MAX {
                drain_rest(resp, &mut carry).await?;
                std::mem::take(&mut carry)
            } else {
                fill_to(resp, &mut carry, frame_size).await?;
                if carry.len() < frame_size {
                    let _ = std::fs::remove_file(&tmp_path);
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
                    let _ = std::fs::remove_file(&tmp_path);
                    return Err(UploadError::InvalidResponse(format!(
                        "decryption failed for chunk {i}: {e}"
                    )));
                }
            };

            if let Err(e) = writer.write_all(&dec.data) {
                let _ = std::fs::remove_file(&tmp_path);
                return Err(UploadError::IoError(format!("write output: {e}")));
            }
            total_plaintext += dec.data.len() as u64;
            chunks_decrypted += 1;
            if let Some(cb) = callback {
                cb.on_chunk_decrypted(chunks_decrypted, chunk_count);
            }
        }

        writer
            .flush()
            .map_err(|e| UploadError::IoError(format!("flush output: {e}")))?;
        drop(writer);
        std::fs::rename(&tmp_path, output_path)
            .map_err(|e| UploadError::IoError(format!("rename output: {e}")))?;

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
            .and_then(|v| v.parse::<u64>().ok())
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
pub fn decrypt_downloaded_bytes(
    file_key: &beebeeb_core::kdf::FileKey,
    encrypted_bytes: &[u8],
    chunk_count: u32,
    output_path: &str,
    callback: Option<&dyn DownloadProgressCallback>,
) -> Result<DownloadResult, UploadError> {
    if chunk_count == 0 {
        return Err(UploadError::InvalidInput(
            "chunk_count must be > 0".into(),
        ));
    }

    let total_len = encrypted_bytes.len();

    // When there is only one chunk, the entire payload is that chunk.
    // When there are multiple, compute the per-chunk size from the total.
    // All chunks except the last are the same size; the last may be smaller.
    let chunk_boundaries = compute_chunk_boundaries(total_len, chunk_count)?;

    // Write to .tmp then atomic rename
    let tmp_path = format!("{output_path}.tmp");

    // Ensure parent directory exists
    if let Some(parent) = std::path::Path::new(output_path).parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| UploadError::IoError(format!("create output parent dir: {e}")))?;
    }

    let output_file = std::fs::File::create(&tmp_path)
        .map_err(|e| UploadError::IoError(format!("create output file: {e}")))?;
    let mut writer = BufWriter::new(output_file);

    let mut total_plaintext: u64 = 0;
    let mut chunks_decrypted: u32 = 0;

    for (i, (start, end)) in chunk_boundaries.iter().enumerate() {
        let chunk_data = &encrypted_bytes[*start..*end];

        let plaintext =
            beebeeb_core::encrypt::decrypt_chunk_raw(file_key, chunk_data)
                .map_err(|e| {
                    UploadError::InvalidResponse(format!(
                        "decryption failed for chunk {i}: {e}"
                    ))
                })?;

        writer
            .write_all(&plaintext)
            .map_err(|e| UploadError::IoError(format!("write output: {e}")))?;

        total_plaintext += plaintext.len() as u64;
        chunks_decrypted += 1;

        if let Some(cb) = callback {
            cb.on_chunk_decrypted(chunks_decrypted, chunk_count);
        }
    }

    writer
        .flush()
        .map_err(|e| UploadError::IoError(format!("flush output: {e}")))?;
    drop(writer);

    // Atomic rename
    std::fs::rename(&tmp_path, output_path)
        .map_err(|e| UploadError::IoError(format!("rename output: {e}")))?;

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
pub fn compute_chunk_boundaries(
    total_len: usize,
    chunk_count: u32,
) -> Result<Vec<(usize, usize)>, UploadError> {
    if chunk_count == 0 {
        return Err(UploadError::InvalidInput("chunk_count must be > 0".into()));
    }

    let n = chunk_count as usize;

    if total_len == 0 {
        return Err(UploadError::InvalidResponse(
            "encrypted payload is empty".into(),
        ));
    }

    // For a single chunk, the entire payload is that chunk.
    if n == 1 {
        if total_len < NONCE_LEN + GCM_TAG_LEN {
            return Err(UploadError::InvalidResponse(format!(
                "chunk too small: {total_len} bytes (need at least {})",
                NONCE_LEN + GCM_TAG_LEN
            )));
        }
        return Ok(vec![(0, total_len)]);
    }

    // Multi-chunk: divide evenly, last chunk gets remainder.
    let base_chunk_size = total_len / n;
    let remainder = total_len % n;

    // Validate minimum chunk size
    let min_chunk = if remainder == 0 {
        base_chunk_size
    } else {
        // Last chunk is base_chunk_size + remainder, others are base_chunk_size
        base_chunk_size
    };

    if min_chunk < NONCE_LEN + GCM_TAG_LEN {
        return Err(UploadError::InvalidResponse(format!(
            "chunk too small: {min_chunk} bytes (need at least {})",
            NONCE_LEN + GCM_TAG_LEN
        )));
    }

    let mut boundaries = Vec::with_capacity(n);
    let mut offset = 0;

    for i in 0..n {
        let size = if i == n - 1 {
            total_len - offset // last chunk gets remainder
        } else {
            base_chunk_size
        };
        boundaries.push((offset, offset + size));
        offset += size;
    }

    Ok(boundaries)
}

/// Synchronous blocking wrapper for `download_and_decrypt`.
///
/// Creates a tokio runtime internally and blocks until complete.
/// Designed to be called from Swift `Task { }` or Kotlin
/// `withContext(Dispatchers.IO) { }`.
pub fn download_and_decrypt_file<'a>(
    api_url: &str,
    token: &str,
    master_key: &beebeeb_core::kdf::MasterKey,
    file_id: &str,
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
                output_path,
                callback
                    .as_ref()
                    .map(|b| b.as_ref() as &dyn DownloadProgressCallback),
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

        let result =
            decrypt_downloaded_bytes(&fk, &encrypted, 1, output_str, None).unwrap();

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

        let result =
            decrypt_downloaded_bytes(&fk, &payload, 2, output_str, None).unwrap();

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

        let wrong_mk =
            derive_master_key("wrong-password", b"wrong-salt-16byte").unwrap();
        let wrong_fk = derive_file_key(&wrong_mk, b"file-003");

        let dir = std::env::temp_dir().join("beebeeb_download_wrongkey");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let output = dir.join("output.bin");
        let output_str = output.to_str().unwrap();

        let result =
            decrypt_downloaded_bytes(&wrong_fk, &encrypted, 1, output_str, None);
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

        let result =
            decrypt_downloaded_bytes(&fk, &encrypted, 1, output_str, None).unwrap();

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

        let result = decrypt_downloaded_bytes(&fk, &[0u8; 100], 0, output_str, None);
        assert!(result.is_err());

        let _ = std::fs::remove_dir_all(&dir);
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
}
