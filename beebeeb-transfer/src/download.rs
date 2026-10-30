//! The download driver (plan K2): the half of a direct download that performs
//! I/O, shared by the native clients.
//!
//! The rules are core's (`beebeeb_core::direct_transfer`): this module makes
//! the calls the planner asks for, feeds every answer back, decrypts the
//! chunks strictly in order through core's [`ChunkDecryptor`], and writes
//! plaintext to the caller's sink. It publishes nothing: after `Done` the
//! caller owns a complete, authenticated plaintext and may publish it.
//!
//! Nothing that leaves this module carries a URL: storage links travel only as
//! [`SignedUrl`], and events and errors carry numbers and enum values only.

use std::collections::{BTreeMap, HashSet};
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use beebeeb_core::chunk_stream::ChunkDecryptor;
use beebeeb_core::direct_transfer::{
    self as dt, API_CALL_TIMEOUT, Call, Direction, Discovery, DownloadGrantResponse, DownloadPlanner, Lookup,
    MemoryClass, Outcome, PinnedRetry, PlannerConfig, Poll, StorageBody, StorageGet, Verdict, classify,
    download_grants_path, max_in_flight_bytes, paced_until_ms, storage_get_total,
};
use bytes::Bytes;
use futures_util::stream::{FuturesUnordered, StreamExt};

use crate::io::{ApiCall, ApiMethod, DirectIo, SignedUrl};
use crate::observer::{ChunkVia, Observer, TransferEvent, TransportKind, UseApiReason};
use crate::shared::DirectShared;

/// What to download and how the caller wants it done.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DownloadRequest {
    /// API origin, e.g. `https://api.beebeeb.io`.
    pub api_base: String,
    pub file_id: String,
    /// The chunk count the caller's metadata states.
    pub chunk_count: u32,
    /// The pinned object version, when the caller has one; a window for another
    /// version means the file changed.
    pub pinned_version: Option<String>,
    pub memory: MemoryClass,
    /// `Some(kbps)`: hold the wire rate at or under this (KiB/s).
    pub kbps_limit: Option<u64>,
    /// The caller asked for the API path; no request is made.
    pub forced_api: bool,
    /// Chunk 0 that does not authenticate may be a legacy file: hand it to the
    /// caller's API path instead of failing.
    pub allow_legacy_chunk0: bool,
    /// Seed for the planner's renewal jitter.
    pub jitter_seed: u64,
}

/// Where authenticated plaintext goes. The driver calls `write` in file order;
/// nothing is written for a chunk that did not authenticate.
pub trait PlaintextSink: Send {
    fn write(&mut self, plain: &[u8]) -> std::io::Result<()>;
}

/// The file could not be downloaded directly, for a reason the API path will
/// not fix.
#[derive(Debug)]
pub enum DownloadError {
    /// The API answered 401: sign in again.
    Unauthorized,
    /// The API answered 403.
    Forbidden,
    /// The pinned version is gone, or the server sent another version: fresh
    /// metadata is needed; nothing was published.
    FileChanged,
    /// Chunk `index` did not authenticate from storage and then from the pinned
    /// API route; nothing was published.
    Unauthentic { index: u32 },
    /// Writing to the caller's sink failed.
    Sink(std::io::Error),
}

impl fmt::Display for DownloadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DownloadError::Unauthorized => f.write_str("sign in again"),
            DownloadError::Forbidden => f.write_str("this account may not download the file"),
            DownloadError::FileChanged => f.write_str("the file changed while it was downloading; nothing was written"),
            DownloadError::Unauthentic { index } => write!(
                f,
                "chunk {index} did not authenticate from storage or from the API; nothing was written"
            ),
            DownloadError::Sink(e) => write!(f, "writing the file failed: {e}"),
        }
    }
}

impl std::error::Error for DownloadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            DownloadError::Sink(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for DownloadError {
    fn from(e: std::io::Error) -> Self {
        DownloadError::Sink(e)
    }
}

/// What a completed download delivered.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DownloadStats {
    pub plaintext_bytes: u64,
    pub ciphertext_bytes: u64,
    /// Chunks that came whole from storage.
    pub chunks_storage: u32,
    /// Chunks that came through the pinned API route.
    pub chunks_pinned: u32,
    /// Windows the planner accepted.
    pub windows: u32,
}

/// The outcome of one attempt.
#[derive(Debug)]
pub enum DownloadOutcome {
    /// Every chunk authenticated and the sink holds the plaintext.
    Done(DownloadStats),
    /// The API path must serve this file; `sink` received nothing.
    UseApi(UseApiReason),
}

/// Download one file through the direct transport.
///
/// `Ok(UseApi(..))` means nothing was written and the caller's API path can take
/// the file from the start. `Err(..)` is a failure the API path would not fix;
/// nothing was published either.
pub async fn download<I: DirectIo>(
    io: &I,
    shared: &DirectShared,
    req: DownloadRequest,
    decryptor: ChunkDecryptor,
    sink: &mut dyn PlaintextSink,
    observer: &dyn Observer,
) -> Result<DownloadOutcome, DownloadError> {
    if req.forced_api {
        observer.event(TransferEvent::Decided(TransportKind::Api));
        return Ok(DownloadOutcome::UseApi(UseApiReason::ForcedApi));
    }
    if !shared.may_start_download(io.mono_ms()) {
        observer.event(TransferEvent::Decided(TransportKind::Api));
        return Ok(DownloadOutcome::UseApi(UseApiReason::BreakerHold));
    }

    let Some(discovery) = discovery(io, shared, observer).await else {
        return Ok(DownloadOutcome::UseApi(UseApiReason::NotSupported));
    };
    if !discovery.offers_download() {
        observer.event(TransferEvent::Decided(TransportKind::Api));
        return Ok(DownloadOutcome::UseApi(UseApiReason::NotSupported));
    }

    observer.event(TransferEvent::Decided(TransportKind::Direct));
    let config = PlannerConfig::from_discovery(&discovery, req.jitter_seed);
    let mut planner = DownloadPlanner::new(config, discovery, &req.api_base, &req.file_id);
    planner.set_max_in_flight_bytes(Some(max_in_flight_bytes(req.memory)));

    let mut decryptor = decryptor;
    let mut tasks: FuturesUnordered<Task<'_>> = FuturesUnordered::new();
    let mut ready: BTreeMap<u32, Bytes> = BTreeMap::new();
    let mut attempted: HashSet<u32> = HashSet::new();
    let mut stats = DownloadStats::default();
    let mut last_unauthentic = 0u32;
    let start_mono = io.mono_ms();

    loop {
        let wake: Option<i64> = loop {
            match planner.poll(io.wall_ms()) {
                Poll::RequestWindow(request) => {
                    let path = download_grants_path(&req.file_id);
                    let Ok(body) = serde_json::to_vec(&request) else {
                        return Ok(DownloadOutcome::UseApi(UseApiReason::ApiForFile));
                    };
                    tasks.push(Box::pin(async move {
                        let reply = io
                            .api(ApiCall {
                                method: ApiMethod::Post,
                                path,
                                body: Some(body),
                                capabilities: Some(dt::CAP_OBJECT_DOWNLOAD_V1),
                                timeout: API_CALL_TIMEOUT,
                                max_body: dt::wire::MAX_GRANT_BODY_BYTES,
                            })
                            .await;
                        Event::Window(reply)
                    }));
                }
                Poll::Fetch { index, grant } => {
                    if !attempted.insert(index) {
                        observer.event(TransferEvent::Renewed { index });
                    }
                    let url = SignedUrl::new(grant.url);
                    let expected_len = grant.length;
                    let total = storage_get_total(expected_len);
                    tasks.push(Box::pin(async move {
                        let reply = io.storage_get(&url, expected_len, total).await;
                        Event::Storage {
                            index,
                            expected_len,
                            reply,
                        }
                    }));
                }
                Poll::FetchViaApi {
                    index,
                    object_version_id,
                } => {
                    let Some(expected_len) = planner.geometry().and_then(|g| g.chunk_length(index)) else {
                        return Ok(DownloadOutcome::UseApi(UseApiReason::ApiForFile));
                    };
                    let file_id = req.file_id.clone();
                    tasks.push(Box::pin(async move {
                        let result = pinned_fetch(io, &file_id, index, &object_version_id, expected_len).await;
                        Event::Pinned { index, result }
                    }));
                }
                Poll::Wait { until_ms } => break until_ms,
                Poll::Done => {
                    if decryptor.finish().is_err() {
                        record_breaker(io, shared, observer, &planner);
                        return Err(DownloadError::Unauthentic {
                            index: last_unauthentic,
                        });
                    }
                    if planner.storage_given_up() {
                        record_breaker(io, shared, observer, &planner);
                    }
                    return Ok(DownloadOutcome::Done(stats));
                }
                Poll::Stop(verdict) => {
                    record_breaker(io, shared, observer, &planner);
                    return match verdict {
                        Verdict::ApiForFile => Ok(DownloadOutcome::UseApi(UseApiReason::ApiForFile)),
                        Verdict::Restart => Err(DownloadError::FileChanged),
                        Verdict::Terminal(t) => match t.status {
                            401 => Err(DownloadError::Unauthorized),
                            403 => Err(DownloadError::Forbidden),
                            _ => Ok(DownloadOutcome::UseApi(UseApiReason::ApiForFile)),
                        },
                        Verdict::Corrupt => Err(DownloadError::Unauthentic {
                            index: last_unauthentic,
                        }),
                    };
                }
            }
        };

        let event = if tasks.is_empty() {
            match wake {
                Some(at) => {
                    let nap = (at - io.wall_ms()).max(0);
                    io.sleep(Duration::from_millis(nap as u64)).await;
                    None
                }
                // Nothing outstanding and nothing scheduled: never hang a
                // download on a stuck planner; the API path is always correct.
                None => return Ok(DownloadOutcome::UseApi(UseApiReason::ApiForFile)),
            }
        } else {
            tasks.next().await
        };

        match event {
            None => {}
            Some(Event::Window(reply)) => {
                let answer = dt::ApiAnswer::from_parts(
                    reply.status,
                    reply.content_type.as_deref(),
                    &reply.body,
                    reply.retry_after.as_deref(),
                );
                match classify(Call::DownloadGrant, &answer) {
                    Outcome::Proceed => match DownloadGrantResponse::from_json(&reply.body) {
                        Ok(window) => {
                            if let Some(expected) = &req.pinned_version {
                                if &window.object_version_id != expected {
                                    return Err(DownloadError::FileChanged);
                                }
                            }
                            if planner.window_answered(window, io.wall_ms()).is_ok() {
                                stats.windows += 1;
                            }
                        }
                        Err(_) => planner.window_malformed(),
                    },
                    other => planner.window_failed(other, io.wall_ms()),
                }
            }
            Some(Event::Storage {
                index,
                expected_len,
                reply,
            }) => {
                let stored = match StorageBody::from_head(reply.status, reply.content_length, expected_len) {
                    Ok(mut body) => {
                        if let Some(bytes) = &reply.body {
                            let _ = body.push(bytes.len() as u64);
                        }
                        body.finish()
                    }
                    Err(failed) => failed,
                };
                match (stored, reply.body) {
                    (StorageGet::Stored, Some(body)) => {
                        if planner.fetch_ok(index).is_err() {
                            return Ok(DownloadOutcome::UseApi(UseApiReason::ApiForFile));
                        }
                        stats.chunks_storage += 1;
                        observer.event(TransferEvent::Chunk {
                            index,
                            via: ChunkVia::Storage,
                        });
                        ready.insert(index, body);
                    }
                    _ => {
                        if planner.fetch_failed(index, io.wall_ms()).is_err() {
                            return Ok(DownloadOutcome::UseApi(UseApiReason::ApiForFile));
                        }
                    }
                }
            }
            Some(Event::Pinned { index, result }) => match result {
                Pinned::Ok(bytes) => {
                    if planner.fetch_ok(index).is_err() {
                        return Ok(DownloadOutcome::UseApi(UseApiReason::ApiForFile));
                    }
                    stats.chunks_pinned += 1;
                    observer.event(TransferEvent::Chunk {
                        index,
                        via: ChunkVia::Pinned,
                    });
                    ready.insert(index, Bytes::from(bytes));
                }
                Pinned::Terminal(401) => return Err(DownloadError::Unauthorized),
                Pinned::Terminal(403) => return Err(DownloadError::Forbidden),
                Pinned::Terminal(_) => return Ok(DownloadOutcome::UseApi(UseApiReason::ApiForFile)),
                Pinned::Restart => return Err(DownloadError::FileChanged),
                Pinned::GiveUp => {
                    if planner.api_fetch_failed(index).is_err() {
                        return Ok(DownloadOutcome::UseApi(UseApiReason::ApiForFile));
                    }
                }
            },
        }

        // Decrypt and write what is ready, strictly in order.
        loop {
            let next = planner.consumed_count();
            let Some(frame) = ready.remove(&next) else { break };
            match decryptor.push_frame(&frame) {
                Ok(chunk) => {
                    sink.write(&chunk.data)?;
                    stats.plaintext_bytes += chunk.data.len() as u64;
                    stats.ciphertext_bytes += frame.len() as u64;
                    observer.event(TransferEvent::Bytes(chunk.data.len() as u64));
                    if planner.consumed(next).is_err() {
                        return Ok(DownloadOutcome::UseApi(UseApiReason::ApiForFile));
                    }
                    if let Some(kbps) = req.kbps_limit {
                        let until = paced_until_ms(start_mono, stats.ciphertext_bytes, kbps);
                        let now = io.mono_ms();
                        if until > now {
                            io.sleep(Duration::from_millis((until - now) as u64)).await;
                        }
                    }
                }
                Err(_) => {
                    if req.allow_legacy_chunk0 && next == 0 {
                        return Ok(DownloadOutcome::UseApi(UseApiReason::LegacyFile));
                    }
                    last_unauthentic = next;
                    if planner.chunk_unauthentic(next).is_err() {
                        return Ok(DownloadOutcome::UseApi(UseApiReason::ApiForFile));
                    }
                    break;
                }
            }
        }
    }
}

/// One discovery answer, from the shared cache when it is fresh.
async fn discovery<I: DirectIo>(io: &I, shared: &DirectShared, observer: &dyn Observer) -> Option<Discovery> {
    let now = io.wall_ms();
    let lookup = shared.discovery_lookup(now);
    let fetched = matches!(lookup, Lookup::Fetch);
    let (outcome, discovery) = match lookup {
        Lookup::Cached(discovery) => (Outcome::Proceed, Some(discovery)),
        Lookup::UseApi => (Outcome::UseApiNow, None),
        Lookup::Fetch => {
            let reply = io
                .api(ApiCall {
                    method: ApiMethod::Get,
                    path: dt::DISCOVERY_PATH.to_string(),
                    body: None,
                    capabilities: None,
                    timeout: dt::DISCOVERY_TIMEOUT,
                    max_body: dt::wire::MAX_DISCOVERY_BYTES,
                })
                .await;
            let answer = dt::ApiAnswer::from_parts(
                reply.status,
                reply.content_type.as_deref(),
                &reply.body,
                reply.retry_after.as_deref(),
            );
            match classify(Call::Discovery, &answer) {
                Outcome::Proceed => match Discovery::from_json(&reply.body) {
                    Ok(discovery) => (Outcome::Proceed, Some(discovery)),
                    Err(_) => (Outcome::UseApiNow, None),
                },
                other => (other, None),
            }
        }
    };
    let fresh = matches!(outcome, Outcome::Proceed) && discovery.is_some();
    if fetched {
        shared.record_discovery(&outcome, discovery.clone(), now);
    }
    if fresh {
        discovery
    } else {
        observer.event(TransferEvent::Decided(TransportKind::Api));
        None
    }
}

fn record_breaker<I: DirectIo>(io: &I, shared: &DirectShared, observer: &dyn Observer, planner: &DownloadPlanner) {
    if planner.storage_given_up() {
        shared.gave_up_download(io.mono_ms());
        observer.event(TransferEvent::GaveUp(Direction::Download));
    }
}

enum Event {
    Window(crate::io::ApiReply),
    Storage {
        index: u32,
        expected_len: u64,
        reply: crate::io::StorageReply,
    },
    Pinned {
        index: u32,
        result: Pinned,
    },
}

enum Pinned {
    Ok(Vec<u8>),
    Terminal(u16),
    Restart,
    GiveUp,
}

type Task<'a> = Pin<Box<dyn Future<Output = Event> + Send + 'a>>;

/// One chunk through the pinned API route, with core's retry policy.
async fn pinned_fetch<I: DirectIo>(io: &I, file_id: &str, index: u32, version: &str, expected_len: u64) -> Pinned {
    let retry = PinnedRetry::default();
    let mut waited = Duration::ZERO;
    let mut attempt = 1u32;
    loop {
        let reply = io
            .api(ApiCall {
                method: ApiMethod::Get,
                path: format!("/api/v1/files/{file_id}/chunks/{index}?object_version_id={version}"),
                body: None,
                capabilities: None,
                // The body, not the API's own timeout, bounds this call.
                timeout: storage_get_total(expected_len),
                max_body: usize::try_from(expected_len).unwrap_or(usize::MAX).saturating_add(1),
            })
            .await;
        let answer = dt::ApiAnswer::from_parts(
            reply.status,
            reply.content_type.as_deref(),
            &reply.body,
            reply.retry_after.as_deref(),
        );
        let outcome = classify(Call::PinnedChunk, &answer);
        match outcome {
            Outcome::Proceed => {
                return if reply.body.len() as u64 == expected_len {
                    Pinned::Ok(reply.body)
                } else {
                    Pinned::GiveUp
                };
            }
            Outcome::Terminal(t) => return Pinned::Terminal(t.status),
            Outcome::Restart => return Pinned::Restart,
            other => match retry.decide(attempt, waited, &other) {
                dt::RetryDecision::Wait(wait) => {
                    io.sleep(wait).await;
                    waited += wait;
                    attempt += 1;
                }
                dt::RetryDecision::GiveUp => return Pinned::GiveUp,
            },
        }
    }
}
