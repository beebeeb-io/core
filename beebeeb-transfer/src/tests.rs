//! The 18 lib tests of plan K2. Every one runs on [`ScriptedIo`] with virtual
//! clocks: no socket is opened here (the conformance suite has its own server).

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use beebeeb_core::chunk_stream::{ChunkDecryptor, ChunkEncryptor, ExpectedChunkFormat};
use beebeeb_core::direct_transfer::{
    CAP_OBJECT_DOWNLOAD_V1, DISCOVERY_PATH, Direction, Discovery, DownloadGrantRequest, Lookup, MemoryClass, Outcome,
    storage_get_total,
};
use beebeeb_core::kdf::FileKey;
use bytes::Bytes;
use futures_util::FutureExt;

use crate::download::{AfterWriteCause, DownloadError, DownloadOutcome, DownloadRequest, PlaintextSink, download};
use crate::io::{ApiCall, ApiReply, SignedUrl, StorageReply};
use crate::observer::{ChunkVia, Observer, TransferEvent, TransportKind, UseApiReason};
use crate::shared::{DirectShared, DirectStore};
use crate::test_support::scripted::{Clock, Gate, Recorded, Reply, Request, ScriptedIo, WALL_START_MS};

const FILE_ID: &str = "11111111-2222-4333-8444-555555555555";
const VERSION: &str = "22222222-3333-4444-8555-666666666666";
const KEY: [u8; 32] = [7u8; 32];
const SECRET: &str = "SECRETSIG2173";

// ─────────────────────────────── fixtures ───────────────────────────────

struct Fixture {
    frames: Vec<Vec<u8>>,
    chunk_count: u32,
    chunk_size: u64,
    original_size: u64,
    encrypted_size: u64,
}

impl Fixture {
    fn new(plain: &[u8], chunk_size: u64) -> Fixture {
        Fixture::with_key(plain, chunk_size, KEY)
    }

    fn with_key(plain: &[u8], chunk_size: u64, key: [u8; 32]) -> Fixture {
        let mut encryptor =
            ChunkEncryptor::for_push_with_file_key(FileKey::from_bytes(key), FILE_ID, plain.len() as u64, chunk_size)
                .unwrap();
        let mut frames = Vec::new();
        if plain.is_empty() {
            frames.push(encryptor.push_chunk(&[]).unwrap().data);
        } else {
            for piece in plain.chunks(chunk_size as usize) {
                frames.push(encryptor.push_chunk(piece).unwrap().data);
            }
        }
        let plan = encryptor.chunk_plan();
        let summary = encryptor.finish().unwrap();
        Fixture {
            frames,
            chunk_count: plan.chunk_count as u32,
            chunk_size,
            original_size: summary.total_plaintext,
            encrypted_size: summary.total_ciphertext,
        }
    }

    /// A geometry with no frames: every storage fetch is answered with a
    /// status, so only the planner's bounds are exercised.
    fn synthetic(chunk_count: u32, chunk_size: u64) -> Fixture {
        let original_size = chunk_size * u64::from(chunk_count - 1) + 1;
        Fixture {
            frames: Vec::new(),
            chunk_count,
            chunk_size,
            original_size,
            encrypted_size: original_size + 28 * u64::from(chunk_count),
        }
    }

    fn chunk_len(&self, index: u32) -> u64 {
        let full = self.chunk_size + 28;
        if index + 1 < self.chunk_count {
            full
        } else {
            self.encrypted_size - full * u64::from(self.chunk_count - 1)
        }
    }

    fn window(&self, start: u32, count: u32, now_ms: i64) -> serde_json::Value {
        let end = (start + count).min(self.chunk_count);
        let grants: Vec<serde_json::Value> = (start..end)
            .map(|index| {
                serde_json::json!({
                    "index": index,
                    "method": "GET",
                    "url": format!("https://storage.test/k/obj/{index}?X-Amz-Signature={SECRET}&i={index}"),
                    "length": self.chunk_len(index),
                    "expires_at": rfc3339(now_ms + 300_000),
                })
            })
            .collect();
        serde_json::json!({
            "transport": CAP_OBJECT_DOWNLOAD_V1,
            "file_id": FILE_ID,
            "object_version_id": VERSION,
            "chunk_count": self.chunk_count,
            "chunk_size": self.chunk_size,
            "encrypted_size": self.encrypted_size,
            "original_size": self.original_size,
            "grants": grants,
            "next_index": if end < self.chunk_count { Some(end) } else { None },
        })
    }

    fn storage_reply(&self, url: &str) -> Reply {
        let index = url_index(url);
        let frame = &self.frames[index as usize];
        Reply::Storage(StorageReply {
            status: 200,
            content_length: Some(frame.len() as u64),
            body: Some(Bytes::from(frame.clone())),
        })
    }
}

#[derive(Default)]
struct VecSink(Vec<u8>);

impl PlaintextSink for VecSink {
    fn write(&mut self, plain: &[u8]) -> std::io::Result<()> {
        self.0.extend_from_slice(plain);
        Ok(())
    }

    fn discardable(&self) -> bool {
        true
    }

    fn discard(&mut self) -> std::io::Result<()> {
        self.0.clear();
        Ok(())
    }
}

/// A mock sink that records what the driver did to it. A non-discardable sink
/// panics if `discard` is called, which is what the contract must prevent.
#[derive(Default)]
struct MockSink {
    data: Vec<u8>,
    discardable: bool,
    discard_fails: bool,
    discard_calls: usize,
    dead: bool,
    writes: usize,
    /// Fail this write after accepting half of the bytes (1-based).
    partial_error_on_write: Option<usize>,
    clock: Option<Clock>,
    write_times: Vec<i64>,
}

impl MockSink {
    fn discardable() -> MockSink {
        MockSink {
            discardable: true,
            ..MockSink::default()
        }
    }

    fn non_discardable() -> MockSink {
        MockSink::default()
    }

    fn failing_discard() -> MockSink {
        MockSink {
            discardable: true,
            discard_fails: true,
            ..MockSink::default()
        }
    }

    fn with_clock(mut self, clock: Clock) -> MockSink {
        self.clock = Some(clock);
        self
    }
}

impl PlaintextSink for MockSink {
    fn write(&mut self, plain: &[u8]) -> std::io::Result<()> {
        if self.dead {
            return Err(std::io::Error::other("the sink is dead"));
        }
        self.writes += 1;
        if let Some(clock) = &self.clock {
            self.write_times.push(clock.mono());
        }
        if self.partial_error_on_write == Some(self.writes) {
            self.data.extend_from_slice(&plain[..plain.len() / 2]);
            return Err(std::io::Error::other("disk full"));
        }
        self.data.extend_from_slice(plain);
        Ok(())
    }

    fn discardable(&self) -> bool {
        self.discardable
    }

    fn discard(&mut self) -> std::io::Result<()> {
        assert!(
            self.discardable,
            "discard() must never be called on a non-discardable sink"
        );
        self.discard_calls += 1;
        if self.discard_fails {
            self.dead = true;
            return Err(std::io::Error::other("discard failed"));
        }
        self.data.clear();
        self.dead = true;
        Ok(())
    }
}

#[derive(Clone, Default)]
struct Events(Arc<Mutex<Vec<TransferEvent>>>);

impl Observer for Events {
    fn event(&self, e: TransferEvent) {
        self.0.lock().unwrap().push(e);
    }
}

fn discovery_reply() -> Reply {
    discovery_reply_window(8)
}

fn discovery_reply_window(max_window: u32) -> Reply {
    json_reply(
        200,
        serde_json::json!({
            "download": [CAP_OBJECT_DOWNLOAD_V1],
            "upload": [],
            "storage_hosts": ["storage.test"],
            "storage_buckets": [{"host": "storage.test", "bucket": "k"}],
            "max_window": max_window,
            "url_ttl_seconds": 300,
        }),
    )
}

fn json_reply(status: u16, value: serde_json::Value) -> Reply {
    Reply::Api(ApiReply {
        status,
        content_type: Some("application/json".into()),
        retry_after: None,
        body: value.to_string().into_bytes(),
    })
}

fn bytes_reply(status: u16, body: Vec<u8>) -> Reply {
    Reply::Api(ApiReply {
        status,
        content_type: Some("application/octet-stream".into()),
        retry_after: None,
        body,
    })
}

/// RFC 3339 with whole seconds, UTC, as the wire contract writes it
/// (`2026-10-24T18:00:00Z`). No chrono in the test support.
fn rfc3339(ms: i64) -> String {
    let secs = ms.div_euclid(1000);
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (hour, minute, second) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { y + 1 } else { y };
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

fn grant_body(call: &ApiCall) -> DownloadGrantRequest {
    serde_json::from_slice(call.body.as_deref().expect("a grant request has a body")).unwrap()
}

fn url_index(url: &str) -> u32 {
    url.split_once("i=")
        .map(|(_, rest)| rest.split('&').next().unwrap_or(rest))
        .and_then(|v| v.parse().ok())
        .expect("the test links carry their index")
}

fn pinned_index(path: &str) -> Option<u32> {
    let rest = path.split_once("/chunks/")?.1;
    rest.split('?').next()?.parse().ok()
}

fn standard_handler(fx: Arc<Fixture>) -> impl Fn(&Request, i64, i64) -> Reply + Send + Sync + 'static {
    move |req, wall, _mono| match req {
        Request::Api(call) if call.path == DISCOVERY_PATH => discovery_reply(),
        Request::Api(call) if call.path == beebeeb_core::direct_transfer::download_grants_path(FILE_ID) => {
            let request = grant_body(call);
            json_reply(200, fx.window(request.start_index, request.count, wall))
        }
        Request::StorageGet { url, .. } => fx.storage_reply(url),
        Request::Api(call) if pinned_index(&call.path).is_some() => {
            bytes_reply(200, fx.frames[pinned_index(&call.path).unwrap() as usize].clone())
        }
        other => panic!("unexpected request {other:?}"),
    }
}

fn request_for(fx: &Fixture) -> DownloadRequest {
    DownloadRequest {
        api_base: "https://api.test".into(),
        file_id: FILE_ID.into(),
        chunk_count: fx.chunk_count,
        pinned_version: None,
        memory: MemoryClass::Native,
        kbps_limit: None,
        forced_api: false,
        allow_legacy_chunk0: false,
        jitter_seed: 11,
    }
}

async fn run_download(
    io: &ScriptedIo,
    shared: &DirectShared,
    request: DownloadRequest,
) -> (Result<DownloadOutcome, DownloadError>, VecSink, Events) {
    let decryptor =
        ChunkDecryptor::for_push_with_file_key(FileKey::from_bytes(KEY), FILE_ID, ExpectedChunkFormat::Unrecorded);
    let mut sink = VecSink::default();
    let events = Events::default();
    let outcome = download(io, shared, request, decryptor, &mut sink, &events).await;
    (outcome, sink, events)
}

fn api_count(io: &ScriptedIo, path: &str) -> usize {
    io.count(|r| matches!(r, Request::Api(call) if call.path == path))
}

fn storage_gets(io: &ScriptedIo) -> usize {
    io.count(|r| matches!(r, Request::StorageGet { .. }))
}

fn pinned_calls(io: &ScriptedIo) -> usize {
    io.count(|r| matches!(r, Request::Api(call) if pinned_index(&call.path).is_some()))
}

fn renewed(events: &Events) -> usize {
    events
        .0
        .lock()
        .unwrap()
        .iter()
        .filter(|e| matches!(e, TransferEvent::Renewed { .. }))
        .count()
}

// ─────────────────────────────── the tests ───────────────────────────────

#[tokio::test]
async fn a_file_downloads_direct_with_one_discovery_and_one_window() {
    let plain: Vec<u8> = (0..6 * 4096).map(|i| (i % 251) as u8).collect();
    let fx = Arc::new(Fixture::new(&plain, 4096));
    let io = ScriptedIo::new(standard_handler(fx.clone()));
    let shared = DirectShared::new();

    let (outcome, sink, _events) = run_download(&io, &shared, request_for(&fx)).await;
    let DownloadOutcome::Done(stats) = outcome.expect("a direct download completes") else {
        panic!("expected Done");
    };
    assert_eq!(sink.0, plain);
    assert_eq!(stats.plaintext_bytes, plain.len() as u64);
    assert_eq!(stats.chunks_storage, 6);
    assert_eq!(stats.chunks_pinned, 0);
    assert_eq!(stats.windows, 1);
    assert_eq!(api_count(&io, DISCOVERY_PATH), 1, "one discovery");
    assert_eq!(
        api_count(&io, &beebeeb_core::direct_transfer::download_grants_path(FILE_ID),),
        1,
        "one window"
    );
    assert_eq!(storage_gets(&io), 6, "one GET per chunk");
    assert_eq!(pinned_calls(&io), 0, "no pinned fallback");
}

#[tokio::test]
async fn the_capability_header_rides_on_grants_only() {
    let fx = Arc::new(Fixture::new(&vec![3u8; 3 * 1024], 1024));
    let io = ScriptedIo::new(standard_handler(fx.clone()));
    let (outcome, _, _) = run_download(&io, &DirectShared::new(), request_for(&fx)).await;
    assert!(matches!(outcome, Ok(DownloadOutcome::Done(_))));

    let requests = io.requests();
    let discovery = requests
        .iter()
        .find_map(|r| match &r.request {
            Request::Api(call) if call.path == DISCOVERY_PATH => Some(call),
            _ => None,
        })
        .expect("a discovery request");
    assert_eq!(
        discovery.capabilities, None,
        "discovery never carries the capability header"
    );
    let grant = requests
        .iter()
        .find_map(|r| match &r.request {
            Request::Api(call) if call.path == beebeeb_core::direct_transfer::download_grants_path(FILE_ID) => {
                Some(call)
            }
            _ => None,
        })
        .expect("a grant request");
    assert_eq!(grant.capabilities, Some(CAP_OBJECT_DOWNLOAD_V1));
    for recorded in &requests {
        if let Request::Api(call) = &recorded.request
            && pinned_index(&call.path).is_some()
        {
            assert_eq!(call.capabilities, None, "the pinned route carries no capability header");
        }
    }
}

#[tokio::test]
async fn a_failed_get_is_renewed_then_served_by_the_pinned_route() {
    let plain: Vec<u8> = (0..4096).map(|i| (i % 199) as u8).collect();
    let fx = Arc::new(Fixture::new(&plain, 4096));
    let failures = Arc::new(Mutex::new(0u32));
    let io = ScriptedIo::new({
        let fx = fx.clone();
        move |req, wall, _mono| match req {
            Request::Api(call) if call.path == DISCOVERY_PATH => discovery_reply(),
            Request::Api(call) if call.path == beebeeb_core::direct_transfer::download_grants_path(FILE_ID) => {
                let request = grant_body(call);
                json_reply(200, fx.window(request.start_index, request.count, wall))
            }
            Request::StorageGet { .. } => {
                let mut seen = failures.lock().unwrap();
                *seen += 1;
                if *seen <= 4 {
                    // A 200 that states the full length but delivers one byte
                    // less: only core's body counter catches it.
                    Reply::Storage(StorageReply {
                        status: 200,
                        content_length: Some(fx.chunk_len(0)),
                        body: Some(Bytes::from(vec![0u8; (fx.chunk_len(0) - 1) as usize])),
                    })
                } else {
                    panic!("the planner asked storage again after giving up")
                }
            }
            Request::Api(call) if pinned_index(&call.path).is_some() => {
                bytes_reply(200, fx.frames[pinned_index(&call.path).unwrap() as usize].clone())
            }
            other => panic!("unexpected request {other:?}"),
        }
    });
    let (outcome, sink, events) = run_download(&io, &DirectShared::new(), request_for(&fx)).await;
    let DownloadOutcome::Done(stats) = outcome.expect("the pinned route completes the file") else {
        panic!("expected Done");
    };
    assert_eq!(sink.0, plain, "identical output");
    assert_eq!(renewed(&events), 3, "three renewals, then the pinned route");
    assert_eq!(pinned_calls(&io), 1, "one chunk served by the pinned route");
    assert_eq!(stats.chunks_pinned, 1);
    assert_eq!(storage_gets(&io), 4);
}

#[tokio::test]
async fn storage_that_never_answers_trips_the_breaker_and_holds_downloads() {
    let plain: Vec<u8> = (0..5 * 2048).map(|i| (i % 241) as u8).collect();
    let fx = Arc::new(Fixture::new(&plain, 2048));
    let io = ScriptedIo::new({
        let fx = fx.clone();
        move |req, wall, _mono| match req {
            Request::Api(call) if call.path == DISCOVERY_PATH => discovery_reply(),
            Request::Api(call) if call.path == beebeeb_core::direct_transfer::download_grants_path(FILE_ID) => {
                let request = grant_body(call);
                json_reply(200, fx.window(request.start_index, request.count, wall))
            }
            Request::StorageGet { .. } => Reply::Storage(StorageReply {
                status: 0,
                content_length: None,
                body: None,
            }),
            Request::Api(call) if pinned_index(&call.path).is_some() => {
                bytes_reply(200, fx.frames[pinned_index(&call.path).unwrap() as usize].clone())
            }
            other => panic!("unexpected request {other:?}"),
        }
    });
    let shared = DirectShared::new();
    let (outcome, sink, events) = run_download(&io, &shared, request_for(&fx)).await;
    let DownloadOutcome::Done(stats) = outcome.expect("the pinned route completes the file") else {
        panic!("expected Done");
    };
    assert_eq!(sink.0, plain);
    assert_eq!(stats.chunks_pinned, fx.chunk_count);
    assert!(
        storage_gets(&io) <= 16,
        "at most 16 storage GETs, got {}",
        storage_gets(&io)
    );
    assert!(
        events
            .0
            .lock()
            .unwrap()
            .iter()
            .any(|e| matches!(e, TransferEvent::GaveUp(Direction::Download))),
        "the breaker is reported"
    );

    // A second file on the same shared state starts no request at all, inside the trust period.
    let second = ScriptedIo::new(|_: &Request, _: i64, _: i64| panic!("a held download made a request"));
    second.set_wall(io.wall_now() + 1_000);
    second.set_mono(io.mono_now() + 1_000);
    let (outcome, sink, _) = run_download(&second, &shared, request_for(&fx)).await;
    assert!(matches!(
        outcome,
        Ok(DownloadOutcome::UseApi(UseApiReason::BreakerHold))
    ));
    assert!(sink.0.is_empty());
    assert!(second.requests().is_empty(), "zero requests while the breaker holds");
}

#[tokio::test]
async fn a_replaced_file_is_file_changed() {
    let fx = Arc::new(Fixture::new(&vec![1u8; 2048], 2048));
    let io = ScriptedIo::new({
        let fx = fx.clone();
        move |req, wall, _mono| match req {
            Request::Api(call) if call.path == DISCOVERY_PATH => discovery_reply(),
            Request::Api(call) if call.path == beebeeb_core::direct_transfer::download_grants_path(FILE_ID) => {
                let request = grant_body(call);
                let mut window = fx.window(request.start_index, request.count, wall);
                window["object_version_id"] = serde_json::json!("33333333-4444-4555-8666-777777777777");
                json_reply(200, window)
            }
            other => panic!("unexpected request {other:?}"),
        }
    });
    let mut request = request_for(&fx);
    request.pinned_version = Some(VERSION.to_string());
    let (outcome, sink, _) = run_download(&io, &DirectShared::new(), request).await;
    assert!(matches!(outcome, Err(DownloadError::FileChanged)), "{outcome:?}");
    assert!(sink.0.is_empty());
    assert_eq!(storage_gets(&io), 0, "nothing is fetched for another version");
}

#[tokio::test]
async fn an_unauthentic_chunk_ends_as_unauthentic_after_the_planners_retry() {
    let plain: Vec<u8> = (0..2048).map(|i| (i % 233) as u8).collect();
    let good = Arc::new(Fixture::new(&plain, 2048));
    let bad = Arc::new(Fixture::with_key(&plain, 2048, [9u8; 32]));
    let io = ScriptedIo::new({
        let good = good.clone();
        let bad = bad.clone();
        move |req, wall, _mono| match req {
            Request::Api(call) if call.path == DISCOVERY_PATH => discovery_reply(),
            Request::Api(call) if call.path == beebeeb_core::direct_transfer::download_grants_path(FILE_ID) => {
                let request = grant_body(call);
                json_reply(200, good.window(request.start_index, request.count, wall))
            }
            Request::StorageGet { url, .. } => {
                let index = url_index(url);
                let frame = &bad.frames[index as usize];
                Reply::Storage(StorageReply {
                    status: 200,
                    content_length: Some(frame.len() as u64),
                    body: Some(Bytes::from(frame.clone())),
                })
            }
            Request::Api(call) if pinned_index(&call.path).is_some() => {
                bytes_reply(200, bad.frames[pinned_index(&call.path).unwrap() as usize].clone())
            }
            other => panic!("unexpected request {other:?}"),
        }
    });
    let (outcome, sink, _) = run_download(&io, &DirectShared::new(), request_for(&good)).await;
    assert!(
        matches!(outcome, Err(DownloadError::Unauthentic { index: 0 })),
        "{outcome:?}"
    );
    assert!(sink.0.is_empty(), "no partial plaintext");
    assert_eq!(pinned_calls(&io), 1, "one pinned re-fetch before giving up");
}

#[tokio::test]
async fn a_zero_byte_file_downloads_empty() {
    let fx = Arc::new(Fixture::new(&[], 4096));
    assert_eq!(fx.frames.len(), 1);
    assert_eq!(fx.frames[0].len(), 28, "one empty frame");
    let io = ScriptedIo::new(standard_handler(fx.clone()));
    let (outcome, sink, _) = run_download(&io, &DirectShared::new(), request_for(&fx)).await;
    let DownloadOutcome::Done(stats) = outcome.expect("an empty file completes") else {
        panic!("expected Done");
    };
    assert_eq!(stats.plaintext_bytes, 0);
    assert_eq!(stats.ciphertext_bytes, 28);
    assert!(sink.0.is_empty());
}

#[tokio::test]
async fn links_that_expired_during_a_suspend_are_renewed_without_a_failure() {
    let plain: Vec<u8> = (0..6 * 1024).map(|i| (i % 197) as u8).collect();
    let fx = Arc::new(Fixture::new(&plain, 1024));
    let suspended = Arc::new(AtomicBool::new(false));
    let clock = Clock::new();
    let io = ScriptedIo::with_clock(clock.clone(), {
        let fx = fx.clone();
        let suspended = suspended.clone();
        move |req, wall, _mono| match req {
            Request::Api(call) if call.path == DISCOVERY_PATH => discovery_reply_window(8),
            Request::Api(call) if call.path == beebeeb_core::direct_transfer::download_grants_path(FILE_ID) => {
                let request = grant_body(call);
                json_reply(200, fx.window(request.start_index, request.count, wall))
            }
            Request::StorageGet { url, .. } => {
                if url_index(url) == 0 && !suspended.swap(true, Ordering::SeqCst) {
                    // The device slept for ten minutes and came back with a live
                    // clock: ten minutes of wall time, one second of monotonic time.
                    clock.advance_wall(600_000);
                    clock.advance_mono(1_000);
                }
                fx.storage_reply(url)
            }
            Request::Api(call) if pinned_index(&call.path).is_some() => {
                bytes_reply(200, fx.frames[pinned_index(&call.path).unwrap() as usize].clone())
            }
            other => panic!("unexpected request {other:?}"),
        }
    });
    let (outcome, sink, events) = run_download(&io, &DirectShared::new(), request_for(&fx)).await;
    let DownloadOutcome::Done(stats) = outcome.expect("the renewed links complete the file") else {
        panic!("expected Done");
    };
    assert_eq!(sink.0, plain);
    assert!(
        stats.windows >= 2,
        "a fresh window after the suspend: {}",
        stats.windows
    );
    assert_eq!(renewed(&events), 0, "an expired link is not a counted failure");
}

#[tokio::test]
async fn a_clock_ten_minutes_off_still_completes() {
    for offset in [-600_000i64, 600_000] {
        let plain: Vec<u8> = (0..1024).map(|i| (i % 181) as u8).collect();
        let fx = Arc::new(Fixture::new(&plain, 1024));
        let io = ScriptedIo::new(standard_handler(fx.clone()));
        io.set_wall(1_700_000_000_000 + offset);
        let (outcome, sink, _) = run_download(&io, &DirectShared::new(), request_for(&fx)).await;
        let DownloadOutcome::Done(_) = outcome.expect("a clock ten minutes off still completes") else {
            panic!("expected Done for offset {offset}");
        };
        assert_eq!(sink.0, plain, "offset {offset}");
    }
}

#[tokio::test]
async fn the_memory_class_bounds_ciphertext_in_flight() {
    async fn max_live(chunk_count: u32, chunk_size: u64, memory: MemoryClass) -> usize {
        let fx = Arc::new(Fixture::synthetic(chunk_count, chunk_size));
        let gate = Gate::new();
        let io = ScriptedIo::new({
            let fx = fx.clone();
            move |req, wall, _mono| match req {
                Request::Api(call) if call.path == DISCOVERY_PATH => discovery_reply(),
                Request::Api(call) if call.path == beebeeb_core::direct_transfer::download_grants_path(FILE_ID) => {
                    let request = grant_body(call);
                    json_reply(200, fx.window(request.start_index, request.count, wall))
                }
                Request::StorageGet { .. } => Reply::Storage(StorageReply {
                    status: 500,
                    content_length: None,
                    body: None,
                }),
                Request::Api(call) if pinned_index(&call.path).is_some() => {
                    json_reply(503, serde_json::json!({"error": "busy"}))
                }
                other => panic!("unexpected request {other:?}"),
            }
        })
        .with_gate(gate.clone());
        let mut request = request_for(&fx);
        request.memory = memory;
        let _ = run_download(&io, &DirectShared::new(), request).await;
        gate.max_live()
    }

    assert_eq!(max_live(2, 256 * 1024 * 1024, MemoryClass::MobileExtension).await, 1);
    assert_eq!(max_live(8, 4 * 1024 * 1024, MemoryClass::Native).await, 4);
}

#[tokio::test]
async fn forced_api_is_use_api_with_zero_requests() {
    let fx = Arc::new(Fixture::new(&vec![1u8; 1024], 1024));
    let io = ScriptedIo::new(|_: &Request, _: i64, _: i64| panic!("a forced API download made a request"));
    let mut request = request_for(&fx);
    request.forced_api = true;
    let (outcome, sink, _) = run_download(&io, &DirectShared::new(), request).await;
    assert!(matches!(outcome, Ok(DownloadOutcome::UseApi(UseApiReason::ForcedApi))));
    assert!(sink.0.is_empty());
    assert!(io.requests().is_empty());
}

#[tokio::test]
async fn not_supported_is_cached_across_files() {
    let io = ScriptedIo::new(|req: &Request, _: i64, _: i64| match req {
        Request::Api(call) if call.path == DISCOVERY_PATH => json_reply(404, serde_json::json!({"error": "not_found"})),
        other => panic!("unexpected request {other:?}"),
    });
    let shared = DirectShared::new();
    let fx = Fixture::new(&vec![1u8; 1024], 1024);
    let (first, sink, _) = run_download(&io, &shared, request_for(&fx)).await;
    assert!(matches!(first, Ok(DownloadOutcome::UseApi(UseApiReason::NotSupported))));
    assert!(sink.0.is_empty());

    let io2 = ScriptedIo::new(|_: &Request, _: i64, _: i64| panic!("the cached answer made a request"));
    io2.set_wall(io.wall_now());
    let (second, _, _) = run_download(&io2, &shared, request_for(&fx)).await;
    assert!(matches!(
        second,
        Ok(DownloadOutcome::UseApi(UseApiReason::NotSupported))
    ));
    assert_eq!(api_count(&io, DISCOVERY_PATH), 1, "one discovery for both files");
    assert!(io2.requests().is_empty());
}

#[tokio::test]
async fn a_401_on_the_grant_is_unauthorized_not_use_api() {
    let fx = Fixture::new(&vec![1u8; 1024], 1024);
    let io = ScriptedIo::new(|req: &Request, _: i64, _: i64| match req {
        Request::Api(call) if call.path == DISCOVERY_PATH => discovery_reply(),
        Request::Api(_) => json_reply(401, serde_json::json!({"error": "unauthorized"})),
        other => panic!("unexpected request {other:?}"),
    });
    let (outcome, sink, _) = run_download(&io, &DirectShared::new(), request_for(&fx)).await;
    assert!(matches!(outcome, Err(DownloadError::Unauthorized)), "{outcome:?}");
    assert!(sink.0.is_empty());
    assert_eq!(storage_gets(&io), 0);
}

#[tokio::test]
async fn two_entries_of_one_account_share_health_and_another_account_does_not() {
    let store = DirectStore::new();
    let first = store.entry("https://api.test", "account-1");
    let second = store.entry("https://api.test", "account-1");
    assert!(Arc::ptr_eq(&first, &second), "one shared state per (api_base, account)");

    first.gave_up_download(1_000);
    assert!(!second.may_start_download(2_000), "health is shared");

    let other = store.entry("https://api.test", "account-2");
    assert!(!Arc::ptr_eq(&first, &other));
    assert!(other.may_start_download(2_000), "another account is independent");
}

#[tokio::test]
async fn forget_account_drops_discovery_and_health() {
    let store = DirectStore::new();
    let shared = store.entry("https://api.test", "account-1");
    shared.record_discovery(&Outcome::Proceed, Some(Discovery::default()), 1_000);
    shared.gave_up_download(1_000);
    assert!(matches!(shared.discovery_lookup(2_000), Lookup::Cached(_)));
    assert!(!shared.may_start_download(2_000));

    store.forget_account("account-1");
    let fresh = store.entry("https://api.test", "account-1");
    assert!(
        matches!(fresh.discovery_lookup(2_000), Lookup::Fetch),
        "discovery is forgotten"
    );
    assert!(fresh.may_start_download(2_000), "health is forgotten");
}

#[tokio::test]
async fn pacing_holds_the_kbps_limit() {
    let plain: Vec<u8> = (0..1024 * 1024).map(|i| (i % 251) as u8).collect();
    let fx = Arc::new(Fixture::new(&plain, 1024 * 1024));
    let io = ScriptedIo::new(standard_handler(fx.clone()));
    let mut request = request_for(&fx);
    request.kbps_limit = Some(512);
    let (outcome, sink, _) = run_download(&io, &DirectShared::new(), request).await;
    assert!(matches!(outcome, Ok(DownloadOutcome::Done(_))), "{outcome:?}");
    assert_eq!(sink.0, plain);
    assert!(
        io.mono_now() >= 2_000,
        "1 MiB at 512 KiB/s takes at least 2000 ms of the monotonic clock, got {}",
        io.mono_now()
    );
}

#[tokio::test]
async fn no_url_reaches_an_event_an_error_or_a_debug_string() {
    let events = [
        TransferEvent::Decided(TransportKind::Direct),
        TransferEvent::Chunk {
            index: 1,
            via: ChunkVia::Storage,
        },
        TransferEvent::Renewed { index: 2 },
        TransferEvent::GaveUp(Direction::Download),
        TransferEvent::Bytes(1234),
        TransferEvent::Discarded {
            plaintext_bytes: 10,
            ciphertext_bytes: 38,
        },
    ];
    for event in events {
        let text = format!("{event:?}");
        assert!(!text.contains("X-Amz-Signature"), "{text}");
    }
    let errors = [
        DownloadError::Unauthorized,
        DownloadError::Forbidden,
        DownloadError::FileChanged,
        DownloadError::Unauthentic { index: 3 },
        DownloadError::Truncated,
        DownloadError::Sink(std::io::Error::other("closed")),
        DownloadError::DirectFailedAfterWrite {
            written_plaintext_bytes: 10,
            chunks_written: 1,
            cause: AfterWriteCause::ApiNeeded(UseApiReason::ApiForFile),
        },
    ];
    for error in errors {
        let text = format!("{error} {error:?}");
        assert!(!text.contains("X-Amz-Signature"), "{text}");
    }
    let url = SignedUrl::new(format!("https://storage.test/b/k?X-Amz-Signature={SECRET}"));
    let text = format!("{url} {url:?}");
    assert!(!text.contains("X-Amz-Signature"), "{text}");
    assert!(!text.contains(SECRET), "{text}");
    assert!(text.contains("storage.test"), "the host may show: {text}");
}

#[tokio::test]
async fn storage_gets_use_the_core_total() {
    let fx = Arc::new(Fixture::new(&vec![5u8; 3 * 2048], 2048));
    let io = ScriptedIo::new(standard_handler(fx.clone()));
    let (outcome, _, _) = run_download(&io, &DirectShared::new(), request_for(&fx)).await;
    assert!(matches!(outcome, Ok(DownloadOutcome::Done(_))));
    let gets: Vec<_> = io
        .requests()
        .into_iter()
        .filter_map(|r| match r.request {
            Request::StorageGet {
                expected_len, total, ..
            } => Some((expected_len, total)),
            _ => None,
        })
        .collect();
    assert_eq!(gets.len(), 3);
    for (expected_len, total) in gets {
        assert_eq!(
            total,
            storage_get_total(expected_len),
            "the core total for {expected_len} bytes"
        );
    }
}

// ----------------------- round 2: the sink contract -----------------------

async fn run_with_sink(
    io: &ScriptedIo,
    shared: &DirectShared,
    request: DownloadRequest,
    sink: &mut dyn PlaintextSink,
    events: &Events,
) -> Result<DownloadOutcome, DownloadError> {
    let decryptor =
        ChunkDecryptor::for_push_with_file_key(FileKey::from_bytes(KEY), FILE_ID, ExpectedChunkFormat::Unrecorded);
    download(io, shared, request, decryptor, sink, events).await
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Trigger {
    PinnedGiveUp,
    Refill404,
    PinnedRestart,
    Pinned401,
    VersionChanged,
    SinkWriteError,
}

/// A 12-chunk file whose attempt writes chunk 0 and then fails at the trigger.
/// The first window holds 8 chunks, so the refill happens only after chunks
/// 0..3 are consumed: every trigger has plaintext in the sink.
fn scenario(trigger: Trigger) -> (ScriptedIo, DownloadRequest, Arc<Fixture>) {
    let plain: Vec<u8> = (0..12 * 1024).map(|i| (i % 241) as u8).collect();
    let fx = Arc::new(Fixture::new(&plain, 1024));
    let storage_fails = matches!(trigger, Trigger::PinnedGiveUp | Trigger::PinnedRestart | Trigger::Pinned401);
    let io = ScriptedIo::new({
        let fx = fx.clone();
        move |req, wall, _mono| match req {
            Request::Api(call) if call.path == DISCOVERY_PATH => discovery_reply_window(8),
            Request::Api(call) if call.path == beebeeb_core::direct_transfer::download_grants_path(FILE_ID) => {
                let request = grant_body(call);
                if trigger == Trigger::Refill404 && request.start_index > 0 {
                    return json_reply(404, serde_json::json!({"error": "not_found"}));
                }
                let mut window = fx.window(request.start_index, request.count, wall);
                if trigger == Trigger::VersionChanged && request.start_index > 0 {
                    window["object_version_id"] = serde_json::json!("33333333-4444-4555-8666-777777777777");
                }
                json_reply(200, window)
            }
            Request::StorageGet { url, .. } => {
                if storage_fails && url_index(url) > 0 {
                    Reply::Storage(StorageReply {
                        status: 0,
                        content_length: None,
                        body: None,
                    })
                } else {
                    fx.storage_reply(url)
                }
            }
            Request::Api(call) if pinned_index(&call.path).is_some() => match trigger {
                Trigger::PinnedGiveUp => json_reply(503, serde_json::json!({"error": "busy"})),
                Trigger::PinnedRestart => Reply::Api(ApiReply {
                    status: 409,
                    content_type: None,
                    retry_after: None,
                    body: Vec::new(),
                }),
                Trigger::Pinned401 => json_reply(401, serde_json::json!({"error": "unauthorized"})),
                _ => bytes_reply(200, fx.frames[pinned_index(&call.path).unwrap() as usize].clone()),
            },
            other => panic!("unexpected request {other:?}"),
        }
    });
    let mut request = request_for(&fx);
    request.jitter_seed = 231;
    (io, request, fx)
}

fn sink_for(trigger: Trigger, discardable: bool) -> MockSink {
    let mut sink = if discardable {
        MockSink::discardable()
    } else {
        MockSink::non_discardable()
    };
    if trigger == Trigger::SinkWriteError {
        sink.partial_error_on_write = Some(2);
    }
    sink
}

#[tokio::test]
async fn every_failure_after_a_write_follows_the_sink_table() {
    for trigger in [
        Trigger::PinnedGiveUp,
        Trigger::Refill404,
        Trigger::PinnedRestart,
        Trigger::Pinned401,
        Trigger::VersionChanged,
        Trigger::SinkWriteError,
    ] {
        // Discardable: the original outcome stands and the sink is emptied.
        let (io, request, _) = scenario(trigger);
        let mut sink = sink_for(trigger, true);
        let outcome = run_with_sink(&io, &DirectShared::new(), request, &mut sink, &Events::default()).await;
        assert_eq!(
            sink.discard_calls, 1,
            "{trigger:?}: discard called exactly once"
        );
        assert!(sink.data.is_empty(), "{trigger:?}: the sink is empty");
        match trigger {
            Trigger::PinnedGiveUp | Trigger::Refill404 => assert!(
                matches!(outcome, Ok(DownloadOutcome::UseApi(UseApiReason::ApiForFile))),
                "{trigger:?}: {outcome:?}"
            ),
            Trigger::PinnedRestart | Trigger::VersionChanged => {
                assert!(
                    matches!(outcome, Err(DownloadError::FileChanged)),
                    "{trigger:?}: {outcome:?}"
                )
            }
            Trigger::Pinned401 => {
                assert!(
                    matches!(outcome, Err(DownloadError::Unauthorized)),
                    "{trigger:?}: {outcome:?}"
                )
            }
            Trigger::SinkWriteError => {
                assert!(
                    matches!(outcome, Err(DownloadError::Sink(_))),
                    "{trigger:?}: {outcome:?}"
                )
            }
        }

        // Non-discardable: an honest failure, the original cause inside.
        let (io, request, _) = scenario(trigger);
        let mut sink = sink_for(trigger, false);
        let outcome = run_with_sink(&io, &DirectShared::new(), request, &mut sink, &Events::default()).await;
        let Err(DownloadError::DirectFailedAfterWrite {
            written_plaintext_bytes,
            chunks_written,
            cause,
        }) = outcome
        else {
            panic!("{trigger:?}: expected DirectFailedAfterWrite, got {outcome:?}");
        };
        assert!(written_plaintext_bytes > 0, "{trigger:?}: bytes counted");
        assert!(chunks_written >= 1, "{trigger:?}: chunks counted");
        assert_eq!(sink.discard_calls, 0, "{trigger:?}: discard never called");
        let cause_is_api = matches!(cause, AfterWriteCause::ApiNeeded(_));
        assert_eq!(
            cause_is_api,
            matches!(trigger, Trigger::PinnedGiveUp | Trigger::Refill404),
            "{trigger:?}: cause {cause:?}"
        );
    }
}

#[tokio::test]
async fn a_cancelled_download_discards_a_discardable_sink_and_never_the_other() {
    let plain: Vec<u8> = (0..4 * 1024).map(|i| (i % 199) as u8).collect();
    let fx = Arc::new(Fixture::new(&plain, 1024));
    let make_io = || {
        ScriptedIo::new({
            let fx = fx.clone();
            move |req, wall, _mono| match req {
                Request::Api(call) if call.path == DISCOVERY_PATH => discovery_reply(),
                Request::Api(call) if call.path == beebeeb_core::direct_transfer::download_grants_path(FILE_ID) => {
                    let request = grant_body(call);
                    json_reply(200, fx.window(request.start_index, request.count, wall))
                }
                Request::StorageGet { url, .. } => fx.storage_reply(url),
                other => panic!("unexpected request {other:?}"),
            }
        })
        .with_storage_delay_for(1, 10_000)
    };

    let io = make_io();
    let mut sink = MockSink::discardable();
    let events = Events::default();
    let request = request_for(&fx);
    let decryptor =
        ChunkDecryptor::for_push_with_file_key(FileKey::from_bytes(KEY), FILE_ID, ExpectedChunkFormat::Unrecorded);
    let shared = DirectShared::new();
    let future = download(&io, &shared, request, decryptor, &mut sink, &events);
    assert!(future.now_or_never().is_none(), "the download is pending");
    assert_eq!(sink.discard_calls, 1, "a cancelled attempt discards");

    let io = make_io();
    let mut sink = MockSink::non_discardable();
    let request = request_for(&fx);
    let events = Events::default();
    let decryptor =
        ChunkDecryptor::for_push_with_file_key(FileKey::from_bytes(KEY), FILE_ID, ExpectedChunkFormat::Unrecorded);
    let shared = DirectShared::new();
    let future = download(&io, &shared, request, decryptor, &mut sink, &events);
    assert!(future.now_or_never().is_none(), "the download is pending");
    assert_eq!(sink.discard_calls, 0, "a non-discardable sink is left alone");
}

#[tokio::test]
async fn a_discarded_sink_refuses_writes() {
    let mut sink = MockSink::discardable();
    sink.write(b"abc").unwrap();
    sink.discard().unwrap();
    assert!(sink.write(b"d").is_err(), "a discarded sink refuses writes");
}

#[tokio::test]
async fn a_sink_whose_discard_fails_still_refuses_writes() {
    let mut sink = MockSink::failing_discard();
    sink.write(b"abc").unwrap();
    assert!(sink.discard().is_err());
    assert!(
        sink.write(b"d").is_err(),
        "a failed discard still marks the sink dead"
    );
}

#[tokio::test]
async fn a_failed_discard_keeps_the_original_error() {
    let (io, request, _) = scenario(Trigger::Pinned401);
    let mut sink = MockSink::failing_discard();
    let outcome = run_with_sink(&io, &DirectShared::new(), request, &mut sink, &Events::default()).await;
    assert!(
        matches!(outcome, Err(DownloadError::Unauthorized)),
        "{outcome:?}"
    );
    assert_eq!(sink.discard_calls, 1);
}

#[tokio::test]
async fn a_partial_write_error_counts_as_written() {
    let (io, request, _) = scenario(Trigger::SinkWriteError);
    let mut sink = MockSink::non_discardable();
    sink.partial_error_on_write = Some(2);
    let outcome = run_with_sink(&io, &DirectShared::new(), request, &mut sink, &Events::default()).await;
    let Err(DownloadError::DirectFailedAfterWrite {
        written_plaintext_bytes,
        chunks_written,
        cause,
    }) = outcome
    else {
        panic!("a partial write counts as written: {outcome:?}");
    };
    assert!(written_plaintext_bytes > 0);
    assert_eq!(chunks_written, 2, "the failing write counts");
    assert!(matches!(cause, AfterWriteCause::Failed(_)));
}

#[tokio::test]
async fn no_message_after_a_write_says_nothing_was_written() {
    let errors = [
        DownloadError::Unauthorized,
        DownloadError::Forbidden,
        DownloadError::FileChanged,
        DownloadError::Unauthentic { index: 3 },
        DownloadError::Truncated,
        DownloadError::Sink(std::io::Error::other("closed")),
        DownloadError::DirectFailedAfterWrite {
            written_plaintext_bytes: 1024,
            chunks_written: 1,
            cause: AfterWriteCause::ApiNeeded(UseApiReason::ApiForFile),
        },
        DownloadError::DirectFailedAfterWrite {
            written_plaintext_bytes: 1024,
            chunks_written: 1,
            cause: AfterWriteCause::Failed(Box::new(DownloadError::FileChanged)),
        },
    ];
    for error in errors {
        let text = format!("{error} {error:?}");
        assert!(
            !text.to_ascii_lowercase().contains("nothing was written"),
            "{text}"
        );
    }
}

#[tokio::test]
async fn discarded_events_carry_the_rolled_back_bytes() {
    let (io, request, _) = scenario(Trigger::Refill404);
    let mut sink = MockSink::discardable();
    let events = Events::default();
    let outcome = run_with_sink(&io, &DirectShared::new(), request, &mut sink, &events).await;
    assert!(
        matches!(outcome, Ok(DownloadOutcome::UseApi(_))),
        "{outcome:?}"
    );
    let discarded: Vec<TransferEvent> = events
        .0
        .lock()
        .unwrap()
        .iter()
        .filter(|e| matches!(e, TransferEvent::Discarded { .. }))
        .cloned()
        .collect();
    assert_eq!(discarded.len(), 1, "{discarded:?}");
    let TransferEvent::Discarded {
        plaintext_bytes,
        ciphertext_bytes,
    } = discarded[0]
    else {
        unreachable!()
    };
    assert!(plaintext_bytes > 0);
    assert_eq!(
        ciphertext_bytes,
        plaintext_bytes + 28 * (plaintext_bytes / 1024),
        "the rolled-back ciphertext includes the per-chunk overhead"
    );
}

// ----------------------- round 2: the driver findings -----------------------

#[tokio::test]
async fn a_v1_file_whose_geometry_has_fewer_chunks_is_refused_not_done() {
    let fx = Arc::new(Fixture::new(&vec![4u8; 3 * 1024], 1024));
    let io = ScriptedIo::new(standard_handler(fx.clone()));
    let mut request = request_for(&fx);
    request.chunk_count = fx.chunk_count + 1;
    let (outcome, sink, _) = run_download(&io, &DirectShared::new(), request).await;
    assert!(
        matches!(outcome, Err(DownloadError::FileChanged)),
        "{outcome:?}"
    );
    assert!(sink.0.is_empty(), "zero bytes written");
}

#[tokio::test]
async fn pacing_holds_new_starts_and_polls_in_flight_replies() {
    let chunk = 64 * 1024;
    let plain: Vec<u8> = (0..8 * chunk).map(|i| (i % 251) as u8).collect();
    let fx = Arc::new(Fixture::new(&plain, chunk as u64));
    let clock = Clock::new();
    let io = ScriptedIo::with_clock(clock.clone(), {
        let fx = fx.clone();
        move |req, wall, _mono| match req {
            Request::Api(call) if call.path == DISCOVERY_PATH => discovery_reply(),
            Request::Api(call) if call.path == beebeeb_core::direct_transfer::download_grants_path(FILE_ID) => {
                let request = grant_body(call);
                json_reply(200, fx.window(request.start_index, request.count, wall))
            }
            Request::StorageGet { url, .. } => fx.storage_reply(url),
            other => panic!("unexpected request {other:?}"),
        }
    })
    .with_storage_delay_for(3, 100);
    let mut sink = MockSink::discardable().with_clock(clock);
    let mut request = request_for(&fx);
    request.kbps_limit = Some(256);
    let events = Events::default();
    let outcome = run_with_sink(&io, &DirectShared::new(), request, &mut sink, &events).await;
    assert!(
        matches!(outcome, Ok(DownloadOutcome::Done(_))),
        "{outcome:?} events {:?} requests {:?} mono {}",
        events.0,
        io.requests().iter().map(|r| (r.request.path().to_string(), r.mono_ms)).collect::<Vec<_>>(),
        io.mono_now()
    );
    assert_eq!(sink.data, plain);
    assert_eq!(
        sink.write_times[3], 100,
        "the reply due at 100 ms is written at once, not after the paced nap"
    );

    let later: Vec<i64> = io
        .requests()
        .into_iter()
        .filter_map(|r| match r.request {
            Request::StorageGet { url, .. } if url_index(&url) >= 4 => Some(r.mono_ms),
            _ => None,
        })
        .collect();
    assert!(!later.is_empty());
    let paced_from =
        beebeeb_core::direct_transfer::paced_until_ms(sink.write_times[0], 4 * (chunk as u64 + 28), 256);
    assert!(
        later.iter().all(|at| *at >= paced_from),
        "new storage starts held to the pace: {later:?} vs {paced_from}"
    );
}

#[tokio::test]
async fn a_renewal_due_while_gets_run_is_requested_on_time() {
    let plain: Vec<u8> = (0..4 * 1024).map(|i| (i % 233) as u8).collect();
    let fx = Arc::new(Fixture::new(&plain, 1024));
    let first_get = Arc::new(AtomicUsize::new(0));
    let clock = Clock::new();
    let io = ScriptedIo::with_clock(clock.clone(), {
        let fx = fx.clone();
        let first_get = first_get.clone();
        move |req, wall, _mono| match req {
            Request::Api(call) if call.path == DISCOVERY_PATH => discovery_reply(),
            Request::Api(call) if call.path == beebeeb_core::direct_transfer::download_grants_path(FILE_ID) => {
                let request = grant_body(call);
                json_reply(200, fx.window(request.start_index, request.count, wall))
            }
            Request::StorageGet { url, .. } => {
                if url_index(url) == 0 && first_get.fetch_add(1, Ordering::SeqCst) == 0 {
                    Reply::Storage(StorageReply {
                        status: 0,
                        content_length: None,
                        body: None,
                    })
                } else {
                    fx.storage_reply(url)
                }
            }
            Request::Api(call) if pinned_index(&call.path).is_some() => {
                bytes_reply(200, fx.frames[pinned_index(&call.path).unwrap() as usize].clone())
            }
            other => panic!("unexpected request {other:?}"),
        }
    })
    .with_storage_delay_for(1, 1_000)
    .with_storage_delay_for(2, 1_000)
    .with_storage_delay_for(3, 1_000);
    let mut request = request_for(&fx);
    request.jitter_seed = 231;
    // The three slow GETs are pending on the virtual clock once the renewal
    // has gone out; advance it from outside so they can finish.
    let advance = {
        let clock = clock.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            for _ in 0..20 {
                clock.advance_mono(100);
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            }
        })
    };
    let (outcome, sink, _) = run_download(&io, &DirectShared::new(), request).await;
    advance.abort();
    assert!(matches!(outcome, Ok(DownloadOutcome::Done(_))), "{outcome:?}");
    assert_eq!(sink.0, plain);

    let grants: Vec<Recorded> = io
        .requests()
        .into_iter()
        .filter(|r| {
            matches!(&r.request, Request::Api(call)
                if call.path == beebeeb_core::direct_transfer::download_grants_path(FILE_ID))
        })
        .collect();
    assert!(grants.len() >= 2, "a renewal was requested");
    assert_eq!(
        grants[1].wall_ms,
        WALL_START_MS + 250,
        "the renewal due at 250 ms is requested at 250 ms, not after the slow GETs"
    );
    assert!(
        storage_gets(&io) >= 5,
        "the three slow GETs and the renewed chunk were fetched"
    );
}

#[tokio::test]
async fn discovery_outcomes_are_classified_by_status() {
    async fn run_with_discovery(reply: Reply, shared: &DirectShared) -> Result<DownloadOutcome, DownloadError> {
        let fx = Fixture::new(&vec![7u8; 1024], 1024);
        let io = ScriptedIo::new(move |req: &Request, _: i64, _: i64| match req {
            Request::Api(call) if call.path == DISCOVERY_PATH => reply.clone(),
            other => panic!("unexpected request {other:?}"),
        });
        let (outcome, _, _) = run_download(&io, shared, request_for(&fx)).await;
        outcome
    }
    let bare_404 = Reply::Api(ApiReply {
        status: 404,
        content_type: None,
        retry_after: None,
        body: Vec::new(),
    });
    let shared = DirectShared::new();
    assert!(matches!(
        run_with_discovery(
            json_reply(401, serde_json::json!({"error": "unauthorized"})),
            &shared
        )
        .await,
        Err(DownloadError::Unauthorized)
    ));
    let shared = DirectShared::new();
    assert!(matches!(
        run_with_discovery(json_reply(403, serde_json::json!({"error": "forbidden"})), &shared).await,
        Err(DownloadError::Forbidden)
    ));
    for reply in [
        json_reply(500, serde_json::json!({"error": "boom"})),
        bare_404,
        Reply::Api(ApiReply::default()),
    ] {
        let shared = DirectShared::new();
        assert!(
            matches!(
                run_with_discovery(reply, &shared).await,
                Ok(DownloadOutcome::UseApi(UseApiReason::DiscoveryUnavailable))
            ),
            "a routing failure is DiscoveryUnavailable"
        );
    }
    // A JSON 404 is the server saying it does not offer it.
    let shared = DirectShared::new();
    assert!(matches!(
        run_with_discovery(
            json_reply(404, serde_json::json!({"error": "not_found"})),
            &shared
        )
        .await,
        Ok(DownloadOutcome::UseApi(UseApiReason::NotSupported))
    ));
    // A parked lookup is unavailable, not "not supported".
    let shared = DirectShared::new();
    shared.record_discovery(&Outcome::UseApiNow, None, WALL_START_MS - 20);
    shared.record_discovery(&Outcome::UseApiNow, None, WALL_START_MS - 10);
    let io = ScriptedIo::new(|_: &Request, _: i64, _: i64| panic!("a parked lookup made a request"));
    let fx = Fixture::new(&vec![7u8; 1024], 1024);
    let (outcome, _, _) = run_download(&io, &shared, request_for(&fx)).await;
    assert!(matches!(
        outcome,
        Ok(DownloadOutcome::UseApi(UseApiReason::DiscoveryUnavailable))
    ));
}

#[tokio::test]
async fn a_breaker_trip_survives_a_pinned_restart() {
    let plain: Vec<u8> = (0..2 * 1024).map(|i| (i % 227) as u8).collect();
    let fx = Arc::new(Fixture::new(&plain, 1024));
    let io = ScriptedIo::new({
        let fx = fx.clone();
        move |req, wall, _mono| match req {
            Request::Api(call) if call.path == DISCOVERY_PATH => discovery_reply(),
            Request::Api(call) if call.path == beebeeb_core::direct_transfer::download_grants_path(FILE_ID) => {
                let request = grant_body(call);
                json_reply(200, fx.window(request.start_index, request.count, wall))
            }
            Request::StorageGet { .. } => Reply::Storage(StorageReply {
                status: 0,
                content_length: None,
                body: None,
            }),
            Request::Api(call) if pinned_index(&call.path).is_some() => Reply::Api(ApiReply {
                status: 409,
                content_type: None,
                retry_after: None,
                body: Vec::new(),
            }),
            other => panic!("unexpected request {other:?}"),
        }
    });
    let shared = DirectShared::new();
    let (outcome, sink, events) = run_download(&io, &shared, request_for(&fx)).await;
    assert!(
        matches!(outcome, Err(DownloadError::FileChanged)),
        "{outcome:?}"
    );
    assert!(sink.0.is_empty());
    assert!(events
        .0
        .lock()
        .unwrap()
        .iter()
        .any(|e| matches!(e, TransferEvent::GaveUp(Direction::Download))));

    let second = ScriptedIo::new(|_: &Request, _: i64, _: i64| panic!("a held download made a request"));
    second.set_wall(io.wall_now() + 1_000);
    second.set_mono(io.mono_now() + 1_000);
    let (held, _, _) = run_download(&second, &shared, request_for(&fx)).await;
    assert!(matches!(
        held,
        Ok(DownloadOutcome::UseApi(UseApiReason::BreakerHold))
    ));
    assert!(second.requests().is_empty());
}

#[tokio::test]
async fn a_grant_reply_debug_prints_no_url_or_bytes() {
    let body = format!(
        r#"{{"transport":"object-download-v1","grants":[{{"url":"https://storage.test/k?X-Amz-Signature={SECRET}"}}]}}"#
    )
    .into_bytes();
    let reply = ApiReply {
        status: 200,
        content_type: Some("application/json".into()),
        retry_after: None,
        body,
    };
    let text = format!("{reply:?}");
    assert!(!text.contains(SECRET), "{text}");
    assert!(!text.contains("X-Amz-Signature"), "{text}");
    assert!(!text.contains("storage.test"), "{text}");
    assert!(text.contains("body_len"), "{text}");
    assert!(text.contains("200"), "{text}");
}

#[tokio::test]
async fn the_version_check_ignores_ascii_case() {
    let fx = Arc::new(Fixture::new(&vec![5u8; 1024], 1024));
    let io = ScriptedIo::new(standard_handler(fx.clone()));
    let mut request = request_for(&fx);
    request.pinned_version = Some(VERSION.to_ascii_uppercase());
    let (outcome, sink, _) = run_download(&io, &DirectShared::new(), request).await;
    assert!(matches!(outcome, Ok(DownloadOutcome::Done(_))), "{outcome:?}");
    assert_eq!(sink.0, vec![5u8; 1024]);
}

#[tokio::test]
async fn concurrent_downloads_share_one_discovery_and_one_failure() {
    async fn one(
        io: &ScriptedIo,
        shared: &DirectShared,
        fx: &Fixture,
    ) -> Result<DownloadOutcome, DownloadError> {
        let mut sink = VecSink::default();
        let events = Events::default();
        let decryptor =
            ChunkDecryptor::for_push_with_file_key(FileKey::from_bytes(KEY), FILE_ID, ExpectedChunkFormat::Unrecorded);
        download(io, shared, request_for(fx), decryptor, &mut sink, &events).await
    }

    let fx = Fixture::new(&vec![6u8; 1024], 1024);
    let discoveries = Arc::new(AtomicUsize::new(0));
    let clock = Clock::new();
    let io = ScriptedIo::with_clock(clock.clone(), {
        let discoveries = discoveries.clone();
        move |req: &Request, _: i64, _: i64| match req {
            Request::Api(call) if call.path == DISCOVERY_PATH => {
                discoveries.fetch_add(1, Ordering::SeqCst);
                json_reply(503, serde_json::json!({"error": "busy"}))
            }
            other => panic!("unexpected request {other:?}"),
        }
    })
    .with_api_delay(50);
    let advance = {
        let clock = clock.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            clock.advance_mono(100);
        })
    };
    let shared = DirectShared::new();
    let (a, b, c, d) = tokio::join!(
        one(&io, &shared, &fx),
        one(&io, &shared, &fx),
        one(&io, &shared, &fx),
        one(&io, &shared, &fx)
    );
    advance.abort();
    for outcome in [a, b, c, d] {
        assert!(
            matches!(
                outcome,
                Ok(DownloadOutcome::UseApi(UseApiReason::DiscoveryUnavailable))
            ),
            "{outcome:?}"
        );
    }
    assert_eq!(discoveries.load(Ordering::SeqCst), 1, "one discovery call");
    assert!(
        matches!(shared.discovery_lookup(io.wall_now()), Lookup::Fetch),
        "one failure recorded, not two"
    );
}

#[tokio::test]
async fn forget_account_with_another_spelling_still_clears() {
    let store = DirectStore::new();
    let shared = store.entry("https://API.Test/", "ABCDEF00-1111-4222-8333-444444444444");
    shared.record_discovery(&Outcome::Proceed, Some(Discovery::default()), 1_000);
    shared.gave_up_download(1_000);
    store.forget_account("abcdef00-1111-4222-8333-444444444444");
    let fresh = store.entry("https://api.test", "abcdef00-1111-4222-8333-444444444444");
    assert!(!Arc::ptr_eq(&shared, &fresh), "the normalized key was cleared");
    assert!(
        matches!(fresh.discovery_lookup(2_000), Lookup::Fetch),
        "discovery is forgotten"
    );
    assert!(fresh.may_start_download(2_000), "health is forgotten");
}
