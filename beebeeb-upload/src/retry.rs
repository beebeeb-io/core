//! Retry logic with exponential backoff for upload operations.

use crate::UploadError;
use std::future::Future;

/// Maximum number of retry attempts for a single operation.
const MAX_RETRIES: u32 = 5;

/// Base delay for exponential backoff (in milliseconds).
const BASE_DELAY_MS: u64 = 500;

/// Maximum delay cap (in milliseconds).
const MAX_DELAY_MS: u64 = 30_000;

/// Execute an async operation with retry logic.
///
/// Retries on:
/// - Network errors (connection reset, timeout)
/// - Server errors (5xx)
/// - Rate limits (429) — uses server-provided Retry-After
///
/// Does NOT retry on:
/// - Client errors (4xx except 429)
/// - I/O errors (missing files)
/// - Invalid responses
pub async fn with_retry<F, Fut, T>(mut operation: F) -> Result<T, UploadError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, UploadError>>,
{
    let mut attempt = 0u32;

    loop {
        match operation().await {
            Ok(result) => return Ok(result),
            Err(err) => {
                attempt += 1;

                if !err.is_retryable() || attempt > MAX_RETRIES {
                    // Non-retryable or exhausted retries
                    if attempt > MAX_RETRIES {
                        return Err(UploadError::MaxRetriesExhausted {
                            attempts: attempt,
                            last_error: err.to_string(),
                        });
                    }
                    return Err(err);
                }

                // Compute delay
                let delay = if let Some(retry_after) = err.retry_after() {
                    // Server told us how long to wait (rate limit)
                    tracing::warn!(
                        attempt,
                        retry_after_secs = retry_after.as_secs(),
                        "rate limited, waiting"
                    );
                    retry_after
                } else {
                    // Exponential backoff: 500ms, 1s, 2s, 4s, 8s (capped at 30s)
                    let delay_ms =
                        (BASE_DELAY_MS * 2u64.saturating_pow(attempt - 1)).min(MAX_DELAY_MS);
                    tracing::warn!(
                        attempt,
                        delay_ms,
                        error = %err,
                        "retrying after backoff"
                    );
                    std::time::Duration::from_millis(delay_ms)
                };

                tokio::time::sleep(delay).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    #[tokio::test]
    async fn succeeds_immediately() {
        let result = with_retry(|| async { Ok::<_, UploadError>(42) }).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 42);
    }

    #[tokio::test]
    async fn retries_on_server_error() {
        let attempts = AtomicU32::new(0);

        let result = with_retry(|| {
            let count = attempts.fetch_add(1, Ordering::SeqCst);
            async move {
                if count < 2 {
                    Err(UploadError::ServerError {
                        status: 500,
                        message: "internal server error".into(),
                    })
                } else {
                    Ok(42)
                }
            }
        })
        .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 42);
        assert_eq!(attempts.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn does_not_retry_client_error() {
        let attempts = AtomicU32::new(0);

        let result: Result<i32, _> = with_retry(|| {
            attempts.fetch_add(1, Ordering::SeqCst);
            async {
                Err(UploadError::ClientError {
                    status: 400,
                    message: "bad request".into(),
                })
            }
        })
        .await;

        assert!(result.is_err());
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn retries_on_network_error() {
        let attempts = AtomicU32::new(0);

        let result = with_retry(|| {
            let count = attempts.fetch_add(1, Ordering::SeqCst);
            async move {
                if count < 1 {
                    Err(UploadError::Network("connection reset".into()))
                } else {
                    Ok("ok")
                }
            }
        })
        .await;

        assert!(result.is_ok());
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn exhausts_retries() {
        let attempts = AtomicU32::new(0);

        let result: Result<i32, _> = with_retry(|| {
            attempts.fetch_add(1, Ordering::SeqCst);
            async {
                Err(UploadError::ServerError {
                    status: 503,
                    message: "service unavailable".into(),
                })
            }
        })
        .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            UploadError::MaxRetriesExhausted { attempts: a, .. } => {
                assert_eq!(a, MAX_RETRIES + 1);
            }
            other => panic!("expected MaxRetriesExhausted, got: {other}"),
        }
    }

    #[tokio::test]
    async fn does_not_retry_io_error() {
        let attempts = AtomicU32::new(0);

        let result: Result<i32, _> = with_retry(|| {
            attempts.fetch_add(1, Ordering::SeqCst);
            async {
                Err(UploadError::IoError("file not found".into()))
            }
        })
        .await;

        assert!(result.is_err());
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
    }
}
