//! Wire constants and serde types of the direct S3 transfer contract v1
//! (`docs/specs/2026-10-23-direct-download-hosts.md`, "v1 wire contract" and
//! "Review round 1: binding amendments").
//!
//! Plain data: no I/O, no HTTP client, no clock. Every type here is lenient on
//! READ (unknown fields are ignored, missing lists are empty) because the
//! server may grow fields before every client does, and strict where a value
//! decides trust (the planner and [`super::authority`] validate; this module
//! only decodes).
//!
//! **Signed URLs never print.** The grant types carry a presigned URL, which is
//! a bearer capability until it expires. Their `Debug` impls show the URL with
//! its query removed, so a `{:?}` in a log line, panic message or test
//! failure cannot leak a signature (spec: "No URL in logs, errors, panics").

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Deserializer, Serialize};

use super::authority::redact;

/// Capability token: the client can download through grant windows.
pub const CAP_OBJECT_DOWNLOAD_V1: &str = "object-download-v1";
/// Capability token: the client can upload through per-chunk grants.
pub const CAP_OBJECT_UPLOAD_V1: &str = "object-upload-v1";
/// Header that carries a client's capability tokens. Sent ONLY on the grant
/// (download) and init (upload) requests, never globally.
pub const CAPABILITIES_HEADER: &str = "X-Beebeeb-Capabilities";
/// `GET` (authenticated): which directions this server offers and which
/// storage authorities its links may name.
pub const DISCOVERY_PATH: &str = "/api/v1/transfer/capabilities";

/// Hard maximum of grants per window request (server limit, spec).
pub const MAX_WINDOW: u32 = 32;
/// Grants asked per window when discovery names no smaller maximum.
pub const DEFAULT_WINDOW: u32 = 8;
/// Link lifetime assumed when discovery omits `url_ttl_seconds`.
pub const DEFAULT_URL_TTL_SECS: u64 = 300;
/// Largest discovery body a client should read (the real one is < 1 KiB).
pub const MAX_DISCOVERY_BYTES: usize = 256 * 1024;
/// Largest grant-window body a client should read: 32 links of at most a few
/// KiB each, plus the envelope.
pub const MAX_GRANT_BODY_BYTES: usize = 1024 * 1024;
/// AEAD overhead per chunk on the wire: `nonce(12) + tag(16)`.
pub const CHUNK_OVERHEAD: u64 = 28;

/// Path of the download-grant route for `file_id` (a UUID string).
pub fn download_grants_path(file_id: &str) -> String {
    format!("/api/v1/files/{file_id}/download-grants")
}

/// Why a body could not be decoded (never contains the body).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WireError {
    #[error("body larger than {0} bytes")]
    TooLarge(usize),
    #[error("body is not the expected JSON")]
    Malformed,
}

/// Decode a JSON OBJECT. serde's derived struct deserializer also accepts a
/// JSON array (positional fields), which would let `[]` pass as an all-defaults
/// answer; an answer that is not an object is malformed.
fn object_from_slice<T: serde::de::DeserializeOwned>(body: &[u8]) -> Result<T, WireError> {
    let value: serde_json::Value = serde_json::from_slice(body).map_err(|_| WireError::Malformed)?;
    if !value.is_object() {
        return Err(WireError::Malformed);
    }
    serde_json::from_value(value).map_err(|_| WireError::Malformed)
}

/// `null` or absent is the empty/default value.
fn null_as_default<'de, D, T>(de: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    Ok(Option::<T>::deserialize(de)?.unwrap_or_default())
}

/// One `{host, bucket}` pair a signed link may name (R1.12: path-style
/// addressing means one host serves every bucket, so the pair is the unit).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageBucket {
    /// Exact authority, `host` or `host:port` (port only when not the scheme default).
    pub host: String,
    pub bucket: String,
}

/// The answer of `GET /api/v1/transfer/capabilities`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Discovery {
    /// Download tokens the server offers right now (`[]` when off).
    #[serde(default, deserialize_with = "null_as_default")]
    pub download: Vec<String>,
    /// Upload tokens the server offers right now (`[]` when off).
    #[serde(default, deserialize_with = "null_as_default")]
    pub upload: Vec<String>,
    #[serde(default, deserialize_with = "null_as_default")]
    pub storage_hosts: Vec<String>,
    #[serde(default, deserialize_with = "null_as_default")]
    pub storage_buckets: Vec<StorageBucket>,
    #[serde(default)]
    pub max_window: Option<u32>,
    #[serde(default)]
    pub url_ttl_seconds: Option<u64>,
}

impl Discovery {
    /// Decode a discovery body. Unknown fields are ignored, missing lists are empty.
    pub fn from_json(body: &[u8]) -> Result<Self, WireError> {
        if body.len() > MAX_DISCOVERY_BYTES {
            return Err(WireError::TooLarge(MAX_DISCOVERY_BYTES));
        }
        object_from_slice(body)
    }

    /// The server offers direct downloads (the client still has to declare the
    /// token on the grant request AND get the exact token back).
    pub fn offers_download(&self) -> bool {
        self.download.iter().any(|t| t == CAP_OBJECT_DOWNLOAD_V1)
    }

    /// The server offers direct uploads.
    pub fn offers_upload(&self) -> bool {
        self.upload.iter().any(|t| t == CAP_OBJECT_UPLOAD_V1)
    }

    /// Grants to ask per window: [`DEFAULT_WINDOW`], never above what the
    /// server states and never above [`MAX_WINDOW`] (an untrusted number
    /// cannot raise it), never below 1.
    pub fn window(&self) -> u32 {
        let ceiling = self.max_window.unwrap_or(MAX_WINDOW).clamp(1, MAX_WINDOW);
        DEFAULT_WINDOW.min(ceiling)
    }

    /// Link lifetime the server states (default [`DEFAULT_URL_TTL_SECS`]).
    /// A stated 0 or an absurd value falls back to the default: it only
    /// decides when a client renews, never what the server accepts.
    pub fn url_ttl_secs(&self) -> u64 {
        match self.url_ttl_seconds {
            Some(s) if (1..=3600).contains(&s) => s,
            _ => DEFAULT_URL_TTL_SECS,
        }
    }
}

/// `POST /api/v1/files/{id}/download-grants` body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DownloadGrantRequest {
    /// `None` (JSON null) only on the first window of a transfer; every later
    /// window and every renewal sends the pinned id.
    pub object_version_id: Option<String>,
    pub start_index: u32,
    /// 1..=[`MAX_WINDOW`].
    pub count: u32,
    /// Informational: the server ignores it (R1.8) and counts by its own record.
    #[serde(default)]
    pub renewal: bool,
}

/// One presigned link for one encrypted chunk.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChunkGrant {
    pub index: u32,
    /// `"GET"` for downloads.
    pub method: String,
    /// Presigned URL: a bearer capability until `expires_at`. Never log it.
    pub url: String,
    /// Exact stored ciphertext length of the chunk (`nonce || ct || tag`).
    pub length: u64,
    /// RFC 3339, whole seconds, UTC (`2026-10-24T18:00:00Z`).
    pub expires_at: String,
}

impl fmt::Debug for ChunkGrant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChunkGrant")
            .field("index", &self.index)
            .field("method", &self.method)
            .field("url", &redact(&self.url))
            .field("length", &self.length)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// `200` body of the download-grants route.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DownloadGrantResponse {
    /// Must equal [`CAP_OBJECT_DOWNLOAD_V1`]: the server selects transport per
    /// request and says so; a client never assumes it from discovery alone.
    pub transport: String,
    pub file_id: String,
    pub object_version_id: String,
    pub chunk_count: u32,
    /// Plaintext stride (what `X-Chunk-Size` says on the API path).
    pub chunk_size: u64,
    pub encrypted_size: u64,
    pub original_size: u64,
    #[serde(default, deserialize_with = "null_as_default")]
    pub grants: Vec<ChunkGrant>,
    /// First index of the next window; `None` after the last chunk.
    #[serde(default)]
    pub next_index: Option<u32>,
}

impl DownloadGrantResponse {
    pub fn from_json(body: &[u8]) -> Result<Self, WireError> {
        if body.len() > MAX_GRANT_BODY_BYTES {
            return Err(WireError::TooLarge(MAX_GRANT_BODY_BYTES));
        }
        object_from_slice(body)
    }
}

// ─────────────────────────────── upload (frozen, not yet served) ───────────────────────────────
//
// FROZEN BY THE SPEC, NOT YET EXERCISED AGAINST A SERVER. The server's upload
// routes are task 2173 PR 2 (s3-server lane), not merged when this module was
// written. The shapes below are the spec's text; they get verified against the
// real routes (and may change with the server's PR) before any client sends
// them. Nothing in this crate's planner uses them yet.

/// `transport` value the server adds to the `POST /uploads/init` 201 body.
/// A body without it (or with any other value) means today's chunk PUT route.
pub fn upload_init_selects_direct(transport_field: Option<&str>) -> bool {
    transport_field == Some(CAP_OBJECT_UPLOAD_V1)
}

/// `POST /uploads/{session}/chunks/{index}/grant` body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UploadGrantRequest {
    /// Exact ciphertext bytes of this chunk (stride + 28, or the exact last remainder + 28).
    pub size: u64,
}

/// `200` body of the upload grant route. Either a link, or (R1.1) `skipped:
/// true` for an index that is already committed, with no link.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UploadGrantResponse {
    pub transport: String,
    pub index: u32,
    #[serde(default)]
    pub skipped: bool,
    #[serde(default)]
    pub method: Option<String>,
    /// Presigned URL (staging key, R1.1). Never log it.
    #[serde(default)]
    pub url: Option<String>,
    /// Headers the PUT must carry exactly (e.g. `content-type`).
    #[serde(default, deserialize_with = "null_as_default")]
    pub headers: BTreeMap<String, String>,
    #[serde(default)]
    pub expires_at: Option<String>,
}

impl fmt::Debug for UploadGrantResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UploadGrantResponse")
            .field("transport", &self.transport)
            .field("index", &self.index)
            .field("skipped", &self.skipped)
            .field("method", &self.method)
            .field("url", &self.url.as_deref().map(redact))
            .field("headers", &self.headers)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// `POST /uploads/{session}/chunks/{index}/commit` body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UploadCommitRequest {
    pub size: u64,
}

/// `200` body of the commit route: the proxy chunk route's body (R1.18).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UploadCommitResponse {
    pub index: u32,
    pub size: u64,
    #[serde(default)]
    pub skipped: bool,
    /// Present for compatibility with the proxy body; carries the tenant id,
    /// so a client must not log or display it.
    #[serde(default)]
    pub object_key: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovery_ignores_unknown_fields_and_defaults_missing_lists() {
        let d = Discovery::from_json(br#"{"download":["object-download-v1"],"future":{"x":1}}"#).unwrap();
        assert!(d.offers_download());
        assert!(!d.offers_upload());
        assert!(d.upload.is_empty() && d.storage_hosts.is_empty() && d.storage_buckets.is_empty());
        assert_eq!(d.window(), DEFAULT_WINDOW);
        assert_eq!(d.url_ttl_secs(), DEFAULT_URL_TTL_SECS);
    }

    #[test]
    fn discovery_null_lists_are_empty_and_empty_object_is_valid() {
        let d = Discovery::from_json(br#"{"download":null,"upload":null,"storage_hosts":null,"storage_buckets":null}"#)
            .unwrap();
        assert_eq!(d, Discovery::default());
        assert_eq!(Discovery::from_json(b"{}").unwrap(), Discovery::default());
    }

    #[test]
    fn discovery_full_body() {
        let d = Discovery::from_json(
            br#"{"download":["object-download-v1"],"upload":[],"storage_hosts":["s3.storage.test"],
                 "storage_buckets":[{"host":"s3.storage.test","bucket":"bb-01"}],"max_window":32,"url_ttl_seconds":300}"#,
        )
        .unwrap();
        assert_eq!(
            d.storage_buckets,
            vec![StorageBucket {
                host: "s3.storage.test".into(),
                bucket: "bb-01".into()
            }]
        );
        assert_eq!(d.window(), 8);
    }

    #[test]
    fn window_is_bounded_by_the_server_and_never_raised_by_it() {
        let with = |max_window| Discovery {
            max_window,
            ..Default::default()
        };
        assert_eq!(with(Some(4)).window(), 4);
        assert_eq!(with(Some(0)).window(), 1, "a stated 0 still asks for one grant");
        assert_eq!(
            with(Some(10_000)).window(),
            DEFAULT_WINDOW,
            "an untrusted ceiling cannot raise the window"
        );
        assert_eq!(with(None).window(), DEFAULT_WINDOW);
    }

    #[test]
    fn url_ttl_rejects_nonsense() {
        let mut d = Discovery::default();
        for bad in [0u64, 3601, u64::MAX] {
            d.url_ttl_seconds = Some(bad);
            assert_eq!(d.url_ttl_secs(), DEFAULT_URL_TTL_SECS);
        }
        d.url_ttl_seconds = Some(120);
        assert_eq!(d.url_ttl_secs(), 120);
    }

    #[test]
    fn oversized_or_malformed_bodies_are_refused_without_echoing_them() {
        let big = vec![b' '; MAX_DISCOVERY_BYTES + 1];
        assert_eq!(
            Discovery::from_json(&big),
            Err(WireError::TooLarge(MAX_DISCOVERY_BYTES))
        );
        assert_eq!(Discovery::from_json(b"<html>"), Err(WireError::Malformed));
        assert_eq!(
            Discovery::from_json(b"[]"),
            Err(WireError::Malformed),
            "an array is not an object"
        );
        assert_eq!(Discovery::from_json(b"null"), Err(WireError::Malformed));
        assert_eq!(Discovery::from_json(b"\"x\""), Err(WireError::Malformed));
        assert_eq!(
            DownloadGrantResponse::from_json(br#"["object-download-v1","f","v",1,1,29,1,[],null]"#),
            Err(WireError::Malformed),
            "positional arrays must not decode as a grant answer"
        );
    }

    #[test]
    fn grant_response_decodes_the_documented_shape() {
        let body = br#"{"transport":"object-download-v1","file_id":"f","object_version_id":"v","chunk_count":12,
            "chunk_size":4194304,"encrypted_size":50331984,"original_size":50331648,
            "grants":[{"index":0,"method":"GET","url":"https://h.test/b/k?X-Amz-Signature=SECRET","length":4194332,
            "expires_at":"2026-10-24T18:00:00Z","extra":1}],"next_index":8,"extra":true}"#;
        let r = DownloadGrantResponse::from_json(body).unwrap();
        assert_eq!(r.transport, CAP_OBJECT_DOWNLOAD_V1);
        assert_eq!(r.grants.len(), 1);
        assert_eq!(r.next_index, Some(8));
        let last = DownloadGrantResponse::from_json(
            br#"{"transport":"t","file_id":"f","object_version_id":"v","chunk_count":1,"chunk_size":1,
                 "encrypted_size":29,"original_size":1,"grants":[],"next_index":null}"#,
        )
        .unwrap();
        assert_eq!(last.next_index, None);
    }

    #[test]
    fn debug_never_prints_a_signature() {
        let grant = ChunkGrant {
            index: 3,
            method: "GET".into(),
            url: "https://s3.storage.test/bb-01/k?X-Amz-Signature=SECRETSIG&X-Amz-Credential=AKIDSECRET".into(),
            length: 10,
            expires_at: "2026-10-24T18:00:00Z".into(),
        };
        let shown = format!("{grant:?}");
        assert!(!shown.contains("SECRETSIG") && !shown.contains("AKIDSECRET") && !shown.contains("X-Amz"));
        assert!(
            shown.contains("s3.storage.test/bb-01/k"),
            "the redacted URL stays useful: {shown}"
        );

        let up = UploadGrantResponse {
            transport: CAP_OBJECT_UPLOAD_V1.into(),
            index: 0,
            skipped: false,
            method: Some("PUT".into()),
            url: Some("https://s3.storage.test/bb-01/k?X-Amz-Signature=SECRETSIG".into()),
            headers: BTreeMap::new(),
            expires_at: None,
        };
        let shown = format!("{up:?}");
        assert!(!shown.contains("SECRETSIG"), "{shown}");
        let wrapped = format!("{:#?}", vec![grant]);
        assert!(!wrapped.contains("SECRETSIG"), "{wrapped}");
    }

    #[test]
    fn upload_shapes_decode_including_the_skipped_answer() {
        let g: UploadGrantResponse = serde_json::from_str(
            r#"{"transport":"object-upload-v1","index":3,"method":"PUT","url":"https://h.test/b/k?s=1",
                "headers":{"content-type":"application/octet-stream"},"expires_at":"2026-10-24T18:00:00Z"}"#,
        )
        .unwrap();
        assert!(!g.skipped);
        assert_eq!(g.headers["content-type"], "application/octet-stream");
        let skipped: UploadGrantResponse =
            serde_json::from_str(r#"{"transport":"object-upload-v1","index":3,"skipped":true}"#).unwrap();
        assert!(skipped.skipped && skipped.url.is_none());
        let c: UploadCommitResponse =
            serde_json::from_str(r#"{"index":3,"size":4194332,"skipped":false,"object_key":"t/k"}"#).unwrap();
        assert_eq!(c.size, 4194332);
        assert!(upload_init_selects_direct(Some(CAP_OBJECT_UPLOAD_V1)));
        assert!(!upload_init_selects_direct(None));
        assert!(!upload_init_selects_direct(Some("object-upload-v2")));
    }

    #[test]
    fn request_serializes_the_documented_shape() {
        let first = DownloadGrantRequest {
            object_version_id: None,
            start_index: 0,
            count: 8,
            renewal: false,
        };
        assert_eq!(
            serde_json::to_string(&first).unwrap(),
            r#"{"object_version_id":null,"start_index":0,"count":8,"renewal":false}"#
        );
        assert_eq!(download_grants_path("abc"), "/api/v1/files/abc/download-grants");
    }
}
