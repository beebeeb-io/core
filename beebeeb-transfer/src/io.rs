//! The I/O boundary of the direct download driver (plan K2).
//!
//! The driver decides what to ask for; a client's [`DirectIo`] performs it. The
//! transport owns every byte the driver must not see: the signed URL is only
//! ever handed over as a [`SignedUrl`], which prints scheme and host and never
//! its query, and a storage error is at most a status number, so nothing that
//! leaves this crate can carry a signature.
//!
//! The contract a transport keeps (the conformance suite checks it):
//!
//! * `storage_get` reads at most `expected_len + 1` body bytes and then stops,
//!   so an overlong body is visible as one byte too many and memory stays
//!   bounded by the chunk;
//! * `storage_get` returns `status: 0` for any transport error (no answer, a
//!   timeout, TLS, a redirect it refuses), never an error string;
//! * no error, display or debug output of a transport ever contains the URL;
//! * a storage request carries no `Authorization`, no `X-Beebeeb-*` header,
//!   no cookie and no redirect follower.

use std::fmt;
use std::future::Future;
use std::time::Duration;

use beebeeb_core::direct_transfer::redact;
use bytes::Bytes;

/// HTTP method of an API call. Storage links are always `GET`/`PUT` and are
/// described by their own methods, never by this enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiMethod {
    Get,
    Post,
}

/// One API request, fully described. The transport adds the `Authorization`
/// header and its client headers; it sends `capabilities` ONLY when this field
/// is `Some` (the grant requests), never on discovery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiCall {
    pub method: ApiMethod,
    /// Path and query, relative to the API base (`/api/v1/...`).
    pub path: String,
    pub body: Option<Vec<u8>>,
    pub capabilities: Option<&'static str>,
    pub timeout: Duration,
    /// The most body bytes worth reading; the rest is not needed.
    pub max_body: usize,
}

/// What the API answered. `status` is `0` when there was no HTTP answer: a
/// connect failure, a timeout or a TLS error.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct ApiReply {
    pub status: u16,
    pub content_type: Option<String>,
    pub retry_after: Option<String>,
    pub body: Vec<u8>,
}

/// Prints status, content type and body length only. A grant reply's body holds
/// signed URLs: a derived `Debug` would put one (byte list included) in any
/// `{:?}` panic message or log line.
impl fmt::Debug for ApiReply {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApiReply")
            .field("status", &self.status)
            .field("content_type", &self.content_type)
            .field("body_len", &self.body.len())
            .finish()
    }
}

/// What a storage GET saw. `status` is `0` when there was no HTTP answer.
///
/// Every field is a number or bytes: there is no string field, so by its type a
/// reply cannot carry the link (a transport that kept one would have to add a
/// field of its own).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StorageReply {
    pub status: u16,
    pub content_length: Option<u64>,
    pub body: Option<Bytes>,
}

/// A presigned storage link. Private: it is constructed by the driver from a
/// verified grant and reaches a transport only by reference. Its `Debug` and
/// `Display` show scheme and host, never the query that carries the signature.
#[derive(Clone, PartialEq, Eq)]
pub struct SignedUrl(String);

impl SignedUrl {
    pub(crate) fn new(url: impl Into<String>) -> Self {
        SignedUrl(url.into())
    }

    /// The link itself, for the transport that has to connect. Not for logs,
    /// errors or events.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SignedUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&redact(&self.0))
    }
}

impl fmt::Display for SignedUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&redact(&self.0))
    }
}

/// The transport of one client: HTTP for the API and for storage, plus the
/// clocks and the sleep the driver needs. `Send + Sync` because the driver
/// holds several of its futures at once.
pub trait DirectIo: Send + Sync {
    /// One authenticated API call. The transport adds `Authorization` and its
    /// client headers, and sends the capability header only when asked.
    fn api(&self, call: ApiCall) -> impl Future<Output = ApiReply> + Send;

    /// Fetch one encrypted chunk from its link. At most `expected_len + 1`
    /// body bytes are read; anything else is a `status` (0 when there was no
    /// HTTP answer). The URL never reaches an error.
    ///
    /// `idle` cuts a body that delivered no byte for that long; `connect`
    /// bounds opening the connection; `total` bounds the whole call.
    fn storage_get(
        &self,
        url: &SignedUrl,
        expected_len: u64,
        total: Duration,
        idle: Duration,
        connect: Duration,
    ) -> impl Future<Output = StorageReply> + Send;

    /// PUT one object to its link. The answer is the HTTP status; `0` when
    /// there was none. (Uploads are plan K3; the method is here because one
    /// transport serves both directions.)
    fn storage_put(
        &self,
        url: &SignedUrl,
        body: Bytes,
        headers: &[(&'static str, String)],
        total: Duration,
    ) -> impl Future<Output = u16> + Send;

    /// Wait. The driver uses this for the planner's backoff and for pacing.
    fn sleep(&self, d: Duration) -> impl Future<Output = ()> + Send;

    /// Unix milliseconds: the clock the planner, discovery and the persisted
    /// health snapshot use.
    fn wall_ms(&self) -> i64;

    /// A monotonic millisecond clock: backoff and pacing. Never compared with
    /// `wall_ms`.
    ///
    /// It must be ONE process-wide clock: milliseconds since a process-global
    /// epoch (a `static OnceLock<Instant>`), not since this transport was
    /// created. The storage breaker and every shared entry compare the values a
    /// previous transport instance recorded, so a per-instance clock would let
    /// a fresh transport skip a hold it should respect. Two instances created a
    /// second apart report values within 200 ms of each other at the same
    /// moment (the conformance suite checks this).
    fn mono_ms(&self) -> i64;
}
