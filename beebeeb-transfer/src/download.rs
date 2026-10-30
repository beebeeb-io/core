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
    self as dt, API_CALL_TIMEOUT, Call, Direction, Discovery, DownloadGrantResponse, DownloadPlanner, MemoryClass,
    Outcome, PinnedRetry, PlannerConfig, Poll, STORAGE_CONNECT_TIMEOUT, STORAGE_GET_IDLE, StorageBody, StorageGet,
    Verdict, classify, download_grants_path, max_in_flight_bytes, paced_until_ms, pinned_chunk_path, storage_get_total,
};
use bytes::Bytes;
use futures_util::future::{Either, select};
use futures_util::stream::{FuturesUnordered, StreamExt};
use zeroize::Zeroizing;

use crate::io::{ApiCall, ApiMethod, DirectIo, SignedUrl};
use crate::observer::{ChunkVia, Observer, TransferEvent, TransportKind, UseApiReason};
use crate::shared::{DirectShared, DiscoveryFlightResult};

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
///
/// When an attempt fails after a write, the driver uses [`discardable`] and
/// [`discard`] so `UseApi` can still promise an empty sink. A sink that cannot
/// throw its bytes away must say so, and the driver reports
/// [`DownloadError::DirectFailedAfterWrite`] instead of handing the file to the
/// API path.
///
/// [`discardable`]: PlaintextSink::discardable
/// [`discard`]: PlaintextSink::discard
pub trait PlaintextSink: Send {
    fn write(&mut self, plain: &[u8]) -> std::io::Result<()>;
    /// Can everything written so far be thrown away? A `.part` file or a memory
    /// buffer: yes. stdout, a pipe: no.
    fn discardable(&self) -> bool;
    /// Throw away everything written. After it, every `write` returns an error
    /// (the sink is dead, so it cannot be reused or stitched). Called by the
    /// driver only when `discardable()` is true.
    fn discard(&mut self) -> std::io::Result<()>;
}

/// Why an attempt that had already written plaintext failed.
#[derive(Debug)]
pub enum AfterWriteCause {
    /// The direct attempt cannot finish, but the API path can serve the file.
    ApiNeeded(UseApiReason),
    /// The attempt failed for a reason the API path will not fix.
    Failed(Box<DownloadError>),
}

impl fmt::Display for AfterWriteCause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AfterWriteCause::ApiNeeded(_) => f.write_str("the API path must serve the file"),
            AfterWriteCause::Failed(error) => write!(f, "{error}"),
        }
    }
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
    /// metadata is needed.
    FileChanged,
    /// Chunk `index` did not authenticate from storage and then from the pinned
    /// API route.
    Unauthentic { index: u32 },
    /// The stream ended before the last chunk; the decryptor's integrity guard
    /// refused the file.
    Truncated,
    /// Writing to the caller's sink failed.
    Sink(std::io::Error),
    /// Direct failed after plaintext had already reached a sink that cannot
    /// discard it. The sink now holds a prefix of the file and must not be
    /// reused or stitched.
    DirectFailedAfterWrite {
        written_plaintext_bytes: u64,
        chunks_written: u32,
        cause: AfterWriteCause,
    },
}

impl fmt::Display for DownloadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DownloadError::Unauthorized => f.write_str("sign in again"),
            DownloadError::Forbidden => f.write_str("this account may not download the file"),
            DownloadError::FileChanged => f.write_str("the file changed while it was downloading"),
            DownloadError::Unauthentic { index } => {
                write!(f, "chunk {index} did not authenticate from storage or from the API")
            }
            DownloadError::Truncated => f.write_str("the download ended before its last chunk"),
            DownloadError::Sink(e) => write!(f, "writing the file failed: {e}"),
            DownloadError::DirectFailedAfterWrite {
                written_plaintext_bytes,
                chunks_written,
                cause,
            } => write!(
                f,
                "the direct download failed after {written_plaintext_bytes} bytes in {chunks_written} chunks \
                 and the output is incomplete: {cause}"
            ),
        }
    }
}

impl std::error::Error for DownloadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            DownloadError::Sink(e) => Some(e),
            DownloadError::DirectFailedAfterWrite { cause, .. } => match cause {
                AfterWriteCause::Failed(error) => Some(error.as_ref()),
                AfterWriteCause::ApiNeeded(_) => None,
            },
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
    /// The API path must serve this file; the sink holds nothing (never
    /// written, or discarded).
    UseApi(UseApiReason),
}

/// The dirty flag and the counters of one attempt, plus the drop guard that
/// applies the discard table when the future is dropped (cancel).
struct Attempt<'a> {
    sink: &'a mut dyn PlaintextSink,
    observer: &'a dyn Observer,
    /// Set BEFORE each write: a write that fails partway still counts.
    dirty: bool,
    plaintext_bytes: u64,
    ciphertext_bytes: u64,
    chunks_written: u32,
    finished: bool,
}

impl<'a> Attempt<'a> {
    fn new(sink: &'a mut dyn PlaintextSink, observer: &'a dyn Observer) -> Self {
        Attempt {
            sink,
            observer,
            dirty: false,
            plaintext_bytes: 0,
            ciphertext_bytes: 0,
            chunks_written: 0,
            finished: false,
        }
    }

    fn write(&mut self, plain: &[u8]) -> std::io::Result<()> {
        self.dirty = true;
        self.chunks_written = self.chunks_written.saturating_add(1);
        self.sink.write(plain)?;
        self.plaintext_bytes = self.plaintext_bytes.saturating_add(plain.len() as u64);
        Ok(())
    }

    fn note_ciphertext(&mut self, bytes: u64) {
        self.ciphertext_bytes = self.ciphertext_bytes.saturating_add(bytes);
    }

    /// The ONE exit: apply the table to the attempt's final result.
    fn finish(mut self, result: Result<DownloadOutcome, DownloadError>) -> Result<DownloadOutcome, DownloadError> {
        self.finished = true;
        if !self.dirty {
            return result;
        }
        match &result {
            // A done attempt keeps its plaintext.
            Ok(DownloadOutcome::Done(_)) => result,
            _ if self.sink.discardable() => {
                // A failed discard is reported to the observer and never hides
                // the original error or changes the outcome.
                let _ = self.sink.discard();
                self.observer.event(TransferEvent::Discarded {
                    plaintext_bytes: self.plaintext_bytes,
                    ciphertext_bytes: self.ciphertext_bytes,
                });
                result
            }
            _ => {
                let cause = match result {
                    Ok(DownloadOutcome::UseApi(reason)) => AfterWriteCause::ApiNeeded(reason),
                    Err(error) => AfterWriteCause::Failed(Box::new(error)),
                    Ok(DownloadOutcome::Done(_)) => unreachable!("handled above"),
                };
                Err(DownloadError::DirectFailedAfterWrite {
                    written_plaintext_bytes: self.plaintext_bytes,
                    chunks_written: self.chunks_written,
                    cause,
                })
            }
        }
    }
}

impl Drop for Attempt<'_> {
    fn drop(&mut self) {
        if self.finished || !self.dirty {
            return;
        }
        // Cancel: the future was dropped. Discard what can be discarded; there
        // is no result to change.
        if self.sink.discardable() {
            let _ = self.sink.discard();
            self.observer.event(TransferEvent::Discarded {
                plaintext_bytes: self.plaintext_bytes,
                ciphertext_bytes: self.ciphertext_bytes,
            });
        }
    }
}

/// One attempt's result plus whether the planner gave up storage, so the ONE
/// exit can record the breaker.
struct AttemptEnd {
    result: Result<DownloadOutcome, DownloadError>,
    storage_given_up: bool,
}

impl AttemptEnd {
    /// An exit before a planner exists.
    fn plain(result: Result<DownloadOutcome, DownloadError>) -> Self {
        AttemptEnd {
            result,
            storage_given_up: false,
        }
    }
}

/// Download one file through the direct transport.
///
/// `Ok(UseApi(..))` means the sink holds nothing and the caller's API path can
/// take the file from the start. `Err(..)` is a failure the API path would not
/// fix. If an attempt wrote plaintext into a sink that cannot discard it, the
/// error is [`DownloadError::DirectFailedAfterWrite`] and the caller must
/// report an incomplete output, never retry into that sink.
pub async fn download<I: DirectIo>(
    io: &I,
    shared: &DirectShared,
    req: DownloadRequest,
    decryptor: ChunkDecryptor,
    sink: &mut dyn PlaintextSink,
    observer: &dyn Observer,
) -> Result<DownloadOutcome, DownloadError> {
    let mut attempt = Attempt::new(sink, observer);
    let end = run(io, shared, &req, decryptor, &mut attempt, observer).await;
    finish_attempt(attempt, end, io, shared, observer)
}

/// The single exit: record the breaker on every exit, then apply the sink
/// table.
fn finish_attempt<I: DirectIo>(
    attempt: Attempt<'_>,
    end: AttemptEnd,
    io: &I,
    shared: &DirectShared,
    observer: &dyn Observer,
) -> Result<DownloadOutcome, DownloadError> {
    if end.storage_given_up {
        shared.gave_up_download(io.mono_ms());
        observer.event(TransferEvent::GaveUp(Direction::Download));
    }
    attempt.finish(end.result)
}

#[allow(clippy::too_many_lines)]
async fn run<I: DirectIo>(
    io: &I,
    shared: &DirectShared,
    req: &DownloadRequest,
    mut decryptor: ChunkDecryptor,
    attempt: &mut Attempt<'_>,
    observer: &dyn Observer,
) -> AttemptEnd {
    if req.forced_api {
        observer.event(TransferEvent::Decided(TransportKind::Api));
        return AttemptEnd::plain(Ok(DownloadOutcome::UseApi(UseApiReason::ForcedApi)));
    }
    if !shared.may_start_download(io.mono_ms()) {
        observer.event(TransferEvent::Decided(TransportKind::Api));
        return AttemptEnd::plain(Ok(DownloadOutcome::UseApi(UseApiReason::BreakerHold)));
    }

    let discovery = match discovery(io, shared, observer).await {
        Ok(discovery) => discovery,
        Err(DiscoveryFailure::NotSupported) => {
            return AttemptEnd::plain(Ok(DownloadOutcome::UseApi(UseApiReason::NotSupported)));
        }
        Err(DiscoveryFailure::Unavailable) => {
            return AttemptEnd::plain(Ok(DownloadOutcome::UseApi(UseApiReason::DiscoveryUnavailable)));
        }
        Err(DiscoveryFailure::Unauthorized) => return AttemptEnd::plain(Err(DownloadError::Unauthorized)),
        Err(DiscoveryFailure::Forbidden) => return AttemptEnd::plain(Err(DownloadError::Forbidden)),
    };
    if !discovery.offers_download() {
        observer.event(TransferEvent::Decided(TransportKind::Api));
        return AttemptEnd::plain(Ok(DownloadOutcome::UseApi(UseApiReason::NotSupported)));
    }

    observer.event(TransferEvent::Decided(TransportKind::Direct));
    let config = PlannerConfig::from_discovery(&discovery, req.jitter_seed);
    let mut planner = DownloadPlanner::new(config, discovery, &req.api_base, &req.file_id);
    planner.set_max_in_flight_bytes(Some(max_in_flight_bytes(req.memory)));

    let mut tasks: FuturesUnordered<Task<'_>> = FuturesUnordered::new();
    let mut ready: BTreeMap<u32, Bytes> = BTreeMap::new();
    let mut attempted: HashSet<u32> = HashSet::new();
    let mut chunks_storage = 0u32;
    let mut chunks_pinned = 0u32;
    let mut windows = 0u32;
    let mut last_unauthentic = 0u32;
    let start_mono = io.mono_ms();
    let mut pace_until = 0i64;

    macro_rules! stop {
        ($e:expr) => {
            return AttemptEnd {
                result: $e,
                storage_given_up: planner.storage_given_up(),
            }
        };
    }

    loop {
        // Deadlines gathered while asking the planner what to do next.
        let mut wait_wall: Option<i64> = None;
        let mut wait_pace: Option<i64> = None;
        // While the pace holds, do not poll the planner at all: a Poll::Fetch
        // marks the chunk in flight, so a fetch that is not started yet must
        // not be consumed. Windows and replies already in tasks still run.
        let paced = req.kbps_limit.is_some() && io.mono_ms() < pace_until;
        if paced {
            wait_pace = Some(pace_until);
        } else {
            loop {
                match planner.poll(io.wall_ms()) {
                    Poll::RequestWindow(request) => {
                        let path = download_grants_path(&req.file_id);
                        let Ok(body) = serde_json::to_vec(&request) else {
                            stop!(Ok(DownloadOutcome::UseApi(UseApiReason::ApiForFile)));
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
                            let reply = io
                                .storage_get(&url, expected_len, total, STORAGE_GET_IDLE, STORAGE_CONNECT_TIMEOUT)
                                .await;
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
                            stop!(Ok(DownloadOutcome::UseApi(UseApiReason::ApiForFile)));
                        };
                        let Ok(path) = pinned_chunk_path(&req.file_id, index, &object_version_id) else {
                            stop!(Ok(DownloadOutcome::UseApi(UseApiReason::ApiForFile)));
                        };
                        tasks.push(Box::pin(async move {
                            let result = pinned_fetch(io, path, expected_len).await;
                            Event::Pinned { index, result }
                        }));
                    }
                    Poll::Wait { until_ms } => {
                        wait_wall = until_ms;
                        break;
                    }
                    Poll::Done => {
                        if decryptor.finish().is_err() {
                            stop!(Err(DownloadError::Truncated));
                        }
                        let stats = DownloadStats {
                            plaintext_bytes: attempt.plaintext_bytes,
                            ciphertext_bytes: attempt.ciphertext_bytes,
                            chunks_storage,
                            chunks_pinned,
                            windows,
                        };
                        stop!(Ok(DownloadOutcome::Done(stats)));
                    }
                    Poll::Stop(verdict) => {
                        stop!(match verdict {
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
                        });
                    }
                }
            }
        }

        // Never sleep while requests sit unpolled: race the sleep against the
        // next event.
        let nap = match (wait_wall, wait_pace) {
            (None, None) => None,
            (wall, pace) => {
                let mut shortest: Option<u64> = None;
                if let Some(at) = wall {
                    let ms = (at - io.wall_ms()).max(0) as u64;
                    shortest = Some(shortest.map_or(ms, |s| s.min(ms)));
                }
                if let Some(at) = pace {
                    let ms = (at - io.mono_ms()).max(0) as u64;
                    shortest = Some(shortest.map_or(ms, |s| s.min(ms)));
                }
                shortest.map(Duration::from_millis)
            }
        };

        let event = if tasks.is_empty() {
            match nap {
                Some(nap) => {
                    io.sleep(nap).await;
                    None
                }
                // Nothing outstanding and nothing scheduled: never hang a
                // download on a stuck planner; the API path is always correct.
                None => stop!(Ok(DownloadOutcome::UseApi(UseApiReason::ApiForFile))),
            }
        } else {
            next_event(&mut tasks, io, nap).await
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
                            // The grant route's geometry must agree with what
                            // the caller asked for; a different file is not
                            // something the API path fixes.
                            if window.chunk_count != req.chunk_count {
                                stop!(Err(DownloadError::FileChanged));
                            }
                            if let Some(expected) = &req.pinned_version {
                                if !window.object_version_id.eq_ignore_ascii_case(expected) {
                                    stop!(Err(DownloadError::FileChanged));
                                }
                            }
                            if planner.window_answered(window, io.wall_ms()).is_ok() {
                                windows += 1;
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
                            stop!(Ok(DownloadOutcome::UseApi(UseApiReason::ApiForFile)));
                        }
                        chunks_storage += 1;
                        observer.event(TransferEvent::Chunk {
                            index,
                            via: ChunkVia::Storage,
                        });
                        ready.insert(index, body);
                    }
                    _ => {
                        if planner.fetch_failed(index, io.wall_ms()).is_err() {
                            stop!(Ok(DownloadOutcome::UseApi(UseApiReason::ApiForFile)));
                        }
                    }
                }
            }
            Some(Event::Pinned { index, result }) => match result {
                Pinned::Ok(bytes) => {
                    if planner.fetch_ok(index).is_err() {
                        stop!(Ok(DownloadOutcome::UseApi(UseApiReason::ApiForFile)));
                    }
                    chunks_pinned += 1;
                    observer.event(TransferEvent::Chunk {
                        index,
                        via: ChunkVia::Pinned,
                    });
                    ready.insert(index, Bytes::from(bytes));
                }
                Pinned::Terminal(401) => stop!(Err(DownloadError::Unauthorized)),
                Pinned::Terminal(403) => stop!(Err(DownloadError::Forbidden)),
                Pinned::Terminal(_) => stop!(Ok(DownloadOutcome::UseApi(UseApiReason::ApiForFile))),
                Pinned::Restart => stop!(Err(DownloadError::FileChanged)),
                Pinned::GiveUp => {
                    if planner.api_fetch_failed(index).is_err() {
                        stop!(Ok(DownloadOutcome::UseApi(UseApiReason::ApiForFile)));
                    }
                }
            },
        }

        // Decrypt and write what is ready, strictly in order.
        loop {
            let next = planner.consumed_count();
            let Some(frame) = ready.remove(&next) else { break };
            let frame_len = frame.len() as u64;
            match decryptor.push_frame(&frame) {
                Ok(chunk) => {
                    // The chunk's plaintext is wiped after the write.
                    let plain = Zeroizing::new(chunk.data);
                    if let Err(error) = attempt.write(&plain) {
                        stop!(Err(DownloadError::Sink(error)));
                    }
                    attempt.note_ciphertext(frame_len);
                    observer.event(TransferEvent::Bytes(plain.len() as u64));
                    // The set is only an event dedupe: a consumed index can
                    // never be fetched again, so it must not grow with the file.
                    attempted.remove(&next);
                    if planner.consumed(next).is_err() {
                        stop!(Ok(DownloadOutcome::UseApi(UseApiReason::ApiForFile)));
                    }
                    if let Some(kbps) = req.kbps_limit {
                        pace_until = pace_until.max(paced_until_ms(start_mono, attempt.ciphertext_bytes, kbps));
                    }
                }
                Err(_) => {
                    if req.allow_legacy_chunk0 && next == 0 {
                        stop!(Ok(DownloadOutcome::UseApi(UseApiReason::LegacyFile)));
                    }
                    last_unauthentic = next;
                    if planner.chunk_unauthentic(next).is_err() {
                        stop!(Ok(DownloadOutcome::UseApi(UseApiReason::ApiForFile)));
                    }
                    break;
                }
            }
        }
    }
}

/// Wait for the next task event, but no longer than `nap`; the sleep is raced
/// against the tasks so a reply that arrives during the wait is handled at
/// once.
async fn next_event<'a, I: DirectIo>(
    tasks: &mut FuturesUnordered<Task<'a>>,
    io: &I,
    nap: Option<Duration>,
) -> Option<Event> {
    let Some(nap) = nap else {
        return tasks.next().await;
    };
    let sleep = io.sleep(nap);
    let next = tasks.next();
    futures_util::pin_mut!(sleep);
    futures_util::pin_mut!(next);
    match select(next, sleep).await {
        Either::Left((event, _)) => event,
        Either::Right(((), _)) => None,
    }
}

/// Why discovery did not produce a usable answer.
enum DiscoveryFailure {
    NotSupported,
    Unavailable,
    Unauthorized,
    Forbidden,
}

/// One discovery answer, from the shared cache, the one in-flight flight, or
/// this caller's own request.
async fn discovery<I: DirectIo>(
    io: &I,
    shared: &DirectShared,
    observer: &dyn Observer,
) -> Result<Discovery, DiscoveryFailure> {
    let now = io.wall_ms();
    let start = shared.discovery_start(now);
    match start {
        crate::shared::DiscoveryStart::Cached(discovery) => Ok(discovery),
        crate::shared::DiscoveryStart::NotSupported => Err(DiscoveryFailure::NotSupported),
        crate::shared::DiscoveryStart::Unavailable => {
            observer.event(TransferEvent::Decided(TransportKind::Api));
            Err(DiscoveryFailure::Unavailable)
        }
        crate::shared::DiscoveryStart::Follow => {
            let result = shared.discovery_follow().await;
            discovery_result(result, observer)
        }
        crate::shared::DiscoveryStart::Lead => {
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
            let result = match classify(Call::Discovery, &answer) {
                Outcome::Proceed => match Discovery::from_json(&reply.body) {
                    Ok(discovery) => DiscoveryFlightResult::Supported(discovery),
                    Err(_) => DiscoveryFlightResult::Unavailable,
                },
                Outcome::NotSupported => DiscoveryFlightResult::NotSupported,
                Outcome::Terminal(t) if t.status == 401 => DiscoveryFlightResult::Unauthorized,
                Outcome::Terminal(_) => DiscoveryFlightResult::Forbidden,
                _ => DiscoveryFlightResult::Unavailable,
            };
            shared.discovery_finished(result.clone(), io.wall_ms());
            discovery_result(result, observer)
        }
    }
}

fn discovery_result(result: DiscoveryFlightResult, observer: &dyn Observer) -> Result<Discovery, DiscoveryFailure> {
    match result {
        DiscoveryFlightResult::Supported(discovery) => Ok(discovery),
        DiscoveryFlightResult::NotSupported => Err(DiscoveryFailure::NotSupported),
        DiscoveryFlightResult::Unavailable => {
            observer.event(TransferEvent::Decided(TransportKind::Api));
            Err(DiscoveryFailure::Unavailable)
        }
        DiscoveryFlightResult::Unauthorized => Err(DiscoveryFailure::Unauthorized),
        DiscoveryFlightResult::Forbidden => Err(DiscoveryFailure::Forbidden),
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
async fn pinned_fetch<I: DirectIo>(io: &I, path: String, expected_len: u64) -> Pinned {
    let retry = PinnedRetry::default();
    let mut waited = Duration::ZERO;
    let mut attempt = 1u32;
    loop {
        let reply = io
            .api(ApiCall {
                method: ApiMethod::Get,
                path: path.clone(),
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
