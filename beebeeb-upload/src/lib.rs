//! Upload protocol for Beebeeb E2E encrypted storage.
//!
//! Handles the complete upload lifecycle:
//! 1. Init session via `POST /api/v1/uploads/init`
//! 2. Upload encrypted chunk files via `PUT /api/v1/uploads/{session_id}/chunks/{index}`
//! 3. Complete session via `POST /api/v1/uploads/{session_id}/complete`
//!
//! Replaces 600+ lines of Swift upload code with a shared Rust implementation
//! that works on iOS (via UniFFI) and future Android.

pub mod download;
mod error;
mod retry;
#[cfg(test)]
mod tests;

pub use download::{download_and_decrypt_file, DownloadClient, DownloadProgressCallback, DownloadResult};
pub use error::UploadError;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Result of a successful upload.
#[derive(Debug, Clone)]
pub struct UploadResult {
    pub file_id: String,
    pub upload_session_id: String,
    pub chunks_uploaded: u32,
    pub total_bytes: u64,
}

/// Callback for upload progress reporting. Implemented by Swift/Kotlin callers.
pub trait UploadProgressCallback: Send + Sync {
    /// Called after each chunk is successfully uploaded.
    fn on_chunk_uploaded(&self, chunk_index: u32, total_chunks: u32);
    /// Called when the upload completes successfully.
    fn on_complete(&self, file_id: &str);
    /// Called when a non-recoverable error occurs.
    fn on_error(&self, error: &str);
}

// ---------------------------------------------------------------------------
// Internal request/response types
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct InitUploadRequest<'a> {
    file_name: &'a str,
    file_size_bytes: u64,
    chunk_count: u64,
    chunk_size_bytes: u64,
    profile: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    parent_id: Option<&'a str>,
    is_media: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    created_at: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    file_id: Option<&'a str>,
}

#[derive(Deserialize)]
struct InitUploadResponse {
    file_id: String,
    upload_session_id: String,
    #[allow(dead_code)]
    chunk_size_bytes: u64,
    #[allow(dead_code)]
    chunk_count: u64,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct ChunkUploadResponse {
    index: u32,
    size: i64,
    skipped: bool,
}

#[derive(Deserialize)]
struct CompleteUploadResponse {
    id: String,
}

// ---------------------------------------------------------------------------
// UploadClient
// ---------------------------------------------------------------------------

/// HTTP client for the Beebeeb upload protocol.
///
/// Each instance is bound to a single API base URL and auth token. Create a
/// new client per upload session or reuse across uploads to the same server.
pub struct UploadClient {
    api_url: String,
    token: String,
    http: reqwest::Client,
}

impl UploadClient {
    /// Create a new upload client.
    ///
    /// `api_url` is the base URL (e.g. `https://api.beebeeb.io`), without
    /// trailing slash. `token` is the bearer auth token.
    pub fn new(api_url: &str, token: &str) -> Self {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(300))
            .build()
            .expect("failed to build reqwest client");

        Self {
            api_url: api_url.trim_end_matches('/').to_string(),
            token: token.to_string(),
            http,
        }
    }

    /// Upload a set of already-encrypted chunk files to the server.
    ///
    /// This executes the full upload protocol:
    /// 1. `POST /api/v1/uploads/init` to create an upload session
    /// 2. `PUT /api/v1/uploads/{session_id}/chunks/{index}` for each chunk
    /// 3. `POST /api/v1/uploads/{session_id}/complete` to finalize
    ///
    /// `chunk_paths` should be paths to `.enc` files on disk, in order.
    /// Each file contains `nonce || ciphertext` (the output of encrypt_file).
    ///
    /// Retries automatically on 429 (rate limit) and 5xx (server error) with
    /// exponential backoff.
    // Mirrors the v2 upload protocol surface (id, name, parent, mime, sizes,
    // counts, progress callback); a params struct would only shuffle the same
    // fields without reducing the caller's burden.
    #[allow(clippy::too_many_arguments)]
    pub async fn upload_encrypted_chunks(
        &self,
        file_id: &str,
        name_encrypted: &str,
        parent_id: Option<&str>,
        _mime_type: Option<&str>,
        is_media: bool,
        chunk_paths: &[String],
        _original_size: u64,
        created_at: Option<&str>,
        callback: Option<&dyn UploadProgressCallback>,
    ) -> Result<UploadResult, UploadError> {
        let total_chunks = chunk_paths.len() as u32;

        if total_chunks == 0 {
            return Err(UploadError::InvalidInput("chunk_paths must not be empty".into()));
        }

        // Compute total ciphertext size from the chunk files on disk.
        let mut total_ciphertext_bytes: u64 = 0;
        for path in chunk_paths {
            let meta = tokio::fs::metadata(path)
                .await
                .map_err(|e| UploadError::IoError(format!("failed to stat chunk file {path}: {e}")))?;
            total_ciphertext_bytes += meta.len();
        }

        // Determine chunk size from the first chunk file.
        let first_chunk_size = tokio::fs::metadata(&chunk_paths[0])
            .await
            .map_err(|e| UploadError::IoError(format!("failed to stat first chunk file {}: {e}", &chunk_paths[0])))?
            .len();

        // --- Step 1: Init upload session ---
        let init_resp = self
            .init_upload_session(
                file_id,
                name_encrypted,
                parent_id,
                is_media,
                total_ciphertext_bytes,
                total_chunks as u64,
                first_chunk_size,
                created_at,
            )
            .await?;

        let session_id = &init_resp.upload_session_id;
        let server_file_id = &init_resp.file_id;

        // --- Step 2: Upload each chunk ---
        for (index, chunk_path) in chunk_paths.iter().enumerate() {
            let chunk_data = tokio::fs::read(chunk_path)
                .await
                .map_err(|e| UploadError::IoError(format!("failed to read chunk file {chunk_path}: {e}")))?;

            self.upload_chunk(session_id, index as u32, chunk_data).await?;

            if let Some(cb) = callback {
                cb.on_chunk_uploaded(index as u32, total_chunks);
            }
        }

        // --- Step 3: Complete upload ---
        let complete_resp = self.complete_upload(session_id).await?;

        let result = UploadResult {
            file_id: complete_resp.id,
            upload_session_id: session_id.clone(),
            chunks_uploaded: total_chunks,
            total_bytes: total_ciphertext_bytes,
        };

        if let Some(cb) = callback {
            cb.on_complete(&result.file_id);
        }

        tracing::info!(
            file_id = %server_file_id,
            chunks = total_chunks,
            bytes = total_ciphertext_bytes,
            "upload complete"
        );

        Ok(result)
    }

    // -----------------------------------------------------------------------
    // Protocol steps
    // -----------------------------------------------------------------------

    // Carries the upload/init request fields one-to-one (id, name, parent,
    // media flag, sizes, counts); grouping them adds indirection, not clarity.
    #[allow(clippy::too_many_arguments)]
    async fn init_upload_session(
        &self,
        file_id: &str,
        name_encrypted: &str,
        parent_id: Option<&str>,
        is_media: bool,
        total_size_bytes: u64,
        chunk_count: u64,
        chunk_size_bytes: u64,
        created_at: Option<&str>,
    ) -> Result<InitUploadResponse, UploadError> {
        let url = format!("{}/api/v1/uploads/init", self.api_url);

        let body = InitUploadRequest {
            file_name: name_encrypted,
            file_size_bytes: total_size_bytes,
            chunk_count,
            chunk_size_bytes,
            profile: "mobile",
            parent_id,
            is_media,
            created_at,
            file_id: Some(file_id),
        };

        retry::with_retry(|| async {
            let resp = self
                .http
                .post(&url)
                .bearer_auth(&self.token)
                .json(&body)
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

            resp.json::<InitUploadResponse>()
                .await
                .map_err(|e| UploadError::InvalidResponse(e.to_string()))
        })
        .await
    }

    async fn upload_chunk(
        &self,
        session_id: &str,
        index: u32,
        data: Vec<u8>,
    ) -> Result<ChunkUploadResponse, UploadError> {
        let url = format!("{}/api/v1/uploads/{}/chunks/{}", self.api_url, session_id, index);

        // Clone data for retry. In practice retries are rare so this is
        // acceptable. The chunk data is already in memory from the disk read.
        retry::with_retry(|| {
            let data = data.clone();
            let url = url.clone();
            async move {
                let resp = self
                    .http
                    .put(&url)
                    .bearer_auth(&self.token)
                    .header("Content-Type", "application/octet-stream")
                    .body(data)
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

                resp.json::<ChunkUploadResponse>()
                    .await
                    .map_err(|e| UploadError::InvalidResponse(e.to_string()))
            }
        })
        .await
    }

    async fn complete_upload(&self, session_id: &str) -> Result<CompleteUploadResponse, UploadError> {
        let url = format!("{}/api/v1/uploads/{}/complete", self.api_url, session_id);

        retry::with_retry(|| async {
            let resp = self
                .http
                .post(&url)
                .bearer_auth(&self.token)
                .header("Content-Type", "application/json")
                .body("{}")
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

            resp.json::<CompleteUploadResponse>()
                .await
                .map_err(|e| UploadError::InvalidResponse(e.to_string()))
        })
        .await
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    async fn parse_rate_limit(resp: &reqwest::Response) -> UploadError {
        // Try Retry-After header first
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

// ---------------------------------------------------------------------------
// Synchronous blocking wrapper for UniFFI
// ---------------------------------------------------------------------------

/// Upload encrypted chunk files to the server. Blocking wrapper for UniFFI.
///
/// This creates a tokio runtime internally and blocks until the upload is
/// complete. Designed to be called from Swift's `Task` or Kotlin's
/// `withContext(Dispatchers.IO)`.
///
/// Returns the file ID and upload stats on success.
// FFI entry point (UniFFI): the flat argument list is the cross-language ABI
// surface (url, token, id, name, parent, mime, sizes, counts, callback); a
// struct would have to be mirrored in Swift/Kotlin for no benefit.
#[allow(clippy::too_many_arguments)]
pub fn upload_encrypted_file<'a>(
    api_url: &str,
    token: &str,
    file_id: &str,
    name_encrypted: &str,
    parent_id: Option<String>,
    mime_type: Option<String>,
    is_media: bool,
    chunk_paths: Vec<String>,
    original_size: u64,
    created_at: Option<String>,
    callback: Option<Box<dyn UploadProgressCallback + 'a>>,
) -> Result<UploadResult, UploadError> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| UploadError::IoError(format!("failed to create tokio runtime: {e}")))?;

    rt.block_on(async {
        let client = UploadClient::new(api_url, token);
        client
            .upload_encrypted_chunks(
                file_id,
                name_encrypted,
                parent_id.as_deref(),
                mime_type.as_deref(),
                is_media,
                &chunk_paths,
                original_size,
                created_at.as_deref(),
                callback.as_ref().map(|b| b.as_ref() as &dyn UploadProgressCallback),
            )
            .await
    })
}
