//! Tests for upload protocol types and logic.

use crate::error::UploadError;
use crate::UploadResult;

#[test]
fn upload_error_is_retryable() {
    assert!(UploadError::Network("timeout".into()).is_retryable());
    assert!(UploadError::ServerError {
        status: 500,
        message: "internal".into(),
    }
    .is_retryable());
    assert!(UploadError::ServerError {
        status: 502,
        message: "bad gateway".into(),
    }
    .is_retryable());
    assert!(UploadError::ServerError {
        status: 503,
        message: "unavailable".into(),
    }
    .is_retryable());
    assert!(UploadError::RateLimited { retry_after_secs: 30 }.is_retryable());
}

#[test]
fn upload_error_not_retryable() {
    assert!(!UploadError::ClientError {
        status: 400,
        message: "bad request".into(),
    }
    .is_retryable());
    assert!(!UploadError::ClientError {
        status: 401,
        message: "unauthorized".into(),
    }
    .is_retryable());
    assert!(!UploadError::ClientError {
        status: 404,
        message: "not found".into(),
    }
    .is_retryable());
    assert!(!UploadError::IoError("file not found".into()).is_retryable());
    assert!(!UploadError::InvalidResponse("parse error".into()).is_retryable());
    assert!(!UploadError::InvalidInput("empty".into()).is_retryable());
}

#[test]
fn upload_error_retry_after() {
    let err = UploadError::RateLimited { retry_after_secs: 60 };
    let duration = err.retry_after().unwrap();
    assert_eq!(duration.as_secs(), 60);
}

#[test]
fn upload_error_no_retry_after_for_non_rate_limit() {
    let err = UploadError::ServerError {
        status: 500,
        message: "error".into(),
    };
    assert!(err.retry_after().is_none());
}

#[test]
fn upload_error_display() {
    let err = UploadError::Network("connection refused".into());
    assert_eq!(err.to_string(), "network error: connection refused");

    let err = UploadError::ServerError {
        status: 500,
        message: "internal server error".into(),
    };
    assert_eq!(err.to_string(), "server error (HTTP 500): internal server error");

    let err = UploadError::ClientError {
        status: 404,
        message: "not found".into(),
    };
    assert_eq!(err.to_string(), "client error (HTTP 404): not found");

    let err = UploadError::RateLimited { retry_after_secs: 30 };
    assert_eq!(err.to_string(), "rate limited — retry after 30s");

    let err = UploadError::MaxRetriesExhausted {
        attempts: 5,
        last_error: "server error".into(),
    };
    assert_eq!(err.to_string(), "max retries exhausted (5 attempts): server error");
}

#[test]
fn upload_result_fields() {
    let result = UploadResult {
        file_id: "abc-123".into(),
        upload_session_id: "sess-456".into(),
        chunks_uploaded: 3,
        total_bytes: 12_582_912,
    };
    assert_eq!(result.file_id, "abc-123");
    assert_eq!(result.upload_session_id, "sess-456");
    assert_eq!(result.chunks_uploaded, 3);
    assert_eq!(result.total_bytes, 12_582_912);
}

#[tokio::test]
async fn upload_client_rejects_empty_chunks() {
    let client = crate::UploadClient::new("http://localhost:3001", "test-token");
    let result = client
        .upload_encrypted_chunks("file-id", "name_enc", None, None, false, &[], 0, None, None)
        .await;
    assert!(result.is_err());
    match result.unwrap_err() {
        UploadError::InvalidInput(msg) => {
            assert!(msg.contains("empty"), "expected 'empty' in: {msg}");
        }
        other => panic!("expected InvalidInput, got: {other}"),
    }
}

#[tokio::test]
async fn upload_client_rejects_missing_chunk_file() {
    let client = crate::UploadClient::new("http://localhost:3001", "test-token");
    let result = client
        .upload_encrypted_chunks(
            "file-id",
            "name_enc",
            None,
            None,
            false,
            &["/nonexistent/path/chunk.enc".to_string()],
            1024,
            None,
            None,
        )
        .await;
    assert!(result.is_err());
    match result.unwrap_err() {
        UploadError::IoError(msg) => {
            assert!(msg.contains("nonexistent"), "expected path in error: {msg}");
        }
        other => panic!("expected IoError, got: {other}"),
    }
}
