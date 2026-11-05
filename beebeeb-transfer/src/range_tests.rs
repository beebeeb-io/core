//! `RangeSession` tests (LD-0105 plan C2, crypto review T6–T8), all on [`ScriptedIo`] with
//! virtual clocks: no socket is opened.

use std::sync::{Arc, Mutex};

use beebeeb_core::chunk_stream::{ChunkEncryptor, ChunkFormat, ExpectedChunkFormat};
use beebeeb_core::direct_transfer::range::RunSet;
use beebeeb_core::direct_transfer::window::Geometry;
use beebeeb_core::direct_transfer::{
    CAP_OBJECT_DOWNLOAD_V1, DISCOVERY_PATH, DownloadGrantRequest, download_grants_path,
};
use beebeeb_core::kdf::FileKey;
use bytes::Bytes;

use crate::io::{ApiReply, StorageReply};
use crate::observer::{Observer, TransferEvent};
use crate::range::{
    RangeControl, RangeIdentity, RangeLessor, RangeOutcome, RangeRequest, RangeSessionError, RangeSink, range_session,
};
use crate::shared::DirectShared;
use crate::test_support::scripted::{Reply, Request, ScriptedIo};

const FILE_ID: &str = "11111111-2222-4333-8444-555555555555";
const VERSION: &str = "22222222-3333-4444-8555-666666666666";
const KEY: [u8; 32] = [7u8; 32];
const STRIDE: u64 = 4096;
const BIG: u64 = 1 << 30;

struct Fx {
    frames: Vec<Vec<u8>>,
    plain: Vec<u8>,
    geometry: Geometry,
}

impl Fx {
    fn new(len: usize, format: ChunkFormat) -> Fx {
        Fx::with_stride(len, format, STRIDE)
    }

    fn with_stride(len: usize, format: ChunkFormat, stride: u64) -> Fx {
        let plain: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
        let mut enc = ChunkEncryptor::for_push_with_file_key(FileKey::from_bytes(KEY), FILE_ID, len as u64, stride)
            .unwrap()
            .with_format(format)
            .unwrap();
        let frames: Vec<Vec<u8>> = plain
            .chunks(stride as usize)
            .map(|p| enc.push_chunk(p).unwrap().data)
            .collect();
        let s = enc.finish().unwrap();
        let geometry = Geometry {
            chunk_count: frames.len() as u32,
            chunk_size: stride,
            encrypted_size: s.total_ciphertext,
            original_size: s.total_plaintext,
        };
        Fx {
            frames,
            plain,
            geometry,
        }
    }

    fn window(&self, g: Geometry, request: &DownloadGrantRequest) -> serde_json::Value {
        let end = (request.start_index + request.count).min(g.chunk_count);
        let grants: Vec<serde_json::Value> = (request.start_index..end)
            .map(|i| {
                serde_json::json!({"index": i, "method": "GET", "length": g.chunk_length(i).unwrap(),
                    "url": format!("https://storage.test/k/obj/{i}?X-Amz-Signature=S&i={i}"),
                    "expires_at": "2099-01-01T00:00:00Z"})
            })
            .collect();
        serde_json::json!({"transport": CAP_OBJECT_DOWNLOAD_V1, "file_id": FILE_ID, "object_version_id": VERSION,
            "chunk_count": g.chunk_count, "chunk_size": g.chunk_size, "encrypted_size": g.encrypted_size,
            "original_size": g.original_size, "grants": grants, "next_index": (end < g.chunk_count).then_some(end)})
    }
}

fn json(status: u16, value: serde_json::Value) -> Reply {
    Reply::Api(ApiReply {
        status,
        content_type: Some("application/json".into()),
        retry_after: None,
        body: value.to_string().into_bytes(),
    })
}

fn discovery_reply() -> Reply {
    json(
        200,
        serde_json::json!({"download": [CAP_OBJECT_DOWNLOAD_V1], "upload": [], "storage_hosts": ["storage.test"],
        "storage_buckets": [{"host": "storage.test", "bucket": "k"}], "max_window": 32, "url_ttl_seconds": 300}),
    )
}

fn index_of(url: &str) -> usize {
    url.rsplit("i=").next().unwrap().parse().unwrap()
}

fn pinned_index(path: &str) -> Option<usize> {
    path.split_once("/chunks/")?.1.split('?').next()?.parse().ok()
}

/// The standard server: windows for `g` (what the server states), frames from `frames`.
fn handler(
    fx: Arc<Fx>,
    g: Geometry,
    frames: Vec<Vec<u8>>,
    window_status: impl Fn(&DownloadGrantRequest) -> u16 + Send + Sync + 'static,
) -> impl Fn(&Request, i64, i64) -> Reply + Send + Sync + 'static {
    move |req, _, _| match req {
        Request::Api(call) if call.path == DISCOVERY_PATH => discovery_reply(),
        Request::Api(call) if call.path == download_grants_path(FILE_ID) => {
            let request: DownloadGrantRequest = serde_json::from_slice(call.body.as_deref().unwrap()).unwrap();
            match window_status(&request) {
                200 => json(200, fx.window(g, &request)),
                409 => json(409, serde_json::json!({"error": "version_unavailable"})),
                status => json(status, serde_json::json!({"error": "nope"})),
            }
        }
        Request::Api(call) if pinned_index(&call.path).is_some() => {
            let frame = frames[pinned_index(&call.path).unwrap()].clone();
            Reply::Api(ApiReply {
                status: 200,
                content_type: Some("application/octet-stream".into()),
                retry_after: None,
                body: frame,
            })
        }
        Request::StorageGet { url, .. } => {
            let frame = &frames[index_of(url)];
            Reply::Storage(StorageReply {
                status: 200,
                content_length: Some(frame.len() as u64),
                body: Some(Bytes::from(frame.clone())),
            })
        }
        other => panic!("unexpected request {other:?}"),
    }
}

#[derive(Default)]
struct Placeholder {
    buf: Vec<u8>,
    have: RunSet,
    identity: Option<RangeIdentity>,
    transfers_before_identity: usize,
    transfers: usize,
    offsets: Vec<u64>,
    met: Vec<u64>,
    failed: Vec<u64>,
    close_when_met: Option<RangeControl>,
}

impl Placeholder {
    fn sized(size: u64) -> Placeholder {
        Placeholder {
            buf: vec![0; size as usize],
            ..Placeholder::default()
        }
    }
}

impl RangeSink for Placeholder {
    fn record_identity(&mut self, identity: &RangeIdentity) -> std::io::Result<()> {
        self.identity = Some(identity.clone());
        Ok(())
    }

    fn transfer(&mut self, offset: u64, plain: &[u8]) -> std::io::Result<()> {
        if self.identity.is_none() {
            self.transfers_before_identity += 1;
        }
        assert!(offset % 4096 == 0, "a piece starts on a 4 KiB boundary");
        assert!(
            !self
                .have
                .runs()
                .iter()
                .any(|&(s, e)| s < offset + plain.len() as u64 && offset < e),
            "no overlap"
        );
        self.buf[offset as usize..offset as usize + plain.len()].copy_from_slice(plain);
        self.have.insert(offset, offset + plain.len() as u64);
        self.transfers += 1;
        self.offsets.push(offset);
        Ok(())
    }

    fn demand_met(&mut self, id: u64) {
        self.met.push(id);
        if let Some(c) = &self.close_when_met {
            c.close();
        }
    }

    fn demand_failed(&mut self, id: u64) {
        self.failed.push(id);
    }
}

#[derive(Clone, Default)]
struct Events(Arc<Mutex<Vec<TransferEvent>>>);

impl Observer for Events {
    fn event(&self, e: TransferEvent) {
        self.0.lock().unwrap().push(e);
    }
}

impl Events {
    fn bytes(&self) -> u64 {
        self.0
            .lock()
            .unwrap()
            .iter()
            .map(|e| if let TransferEvent::Bytes(n) = e { *n } else { 0 })
            .sum()
    }
}

fn request(size: u64) -> RangeRequest {
    RangeRequest {
        api_base: "https://api.test".into(),
        file_id: FILE_ID.into(),
        object_version_id: VERSION.into(),
        file_size: size,
        pin: ExpectedChunkFormat::Unrecorded,
        geometry: None,
        recorded: None,
        on_disk_bytes: 0,
        forced_api: false,
        jitter_seed: 3,
    }
}

async fn run(
    io: &ScriptedIo,
    lessor: &RangeLessor,
    req: RangeRequest,
    control: &RangeControl,
    sink: &mut Placeholder,
) -> (Result<RangeOutcome, RangeSessionError>, Events) {
    let events = Events::default();
    let shared = DirectShared::default();
    let out = range_session(
        io,
        &shared,
        lessor,
        req,
        FileKey::from_bytes(KEY),
        control,
        sink,
        &events,
    )
    .await;
    (out, events)
}

fn storage_gets(io: &ScriptedIo) -> usize {
    io.count(|r| matches!(r, Request::StorageGet { .. }))
}

#[tokio::test]
async fn a_whole_file_demand_streams_every_chunk_and_ends_whole() {
    let fx = Arc::new(Fx::new(5 * STRIDE as usize - 300, ChunkFormat::V1Legacy));
    let g = fx.geometry;
    let io = ScriptedIo::new(handler(fx.clone(), g, fx.frames.clone(), |_| 200));
    let control = RangeControl::new();
    control.demand(1, 0, g.original_size);
    let mut sink = Placeholder::sized(g.original_size);
    let (out, events) = run(
        &io,
        &RangeLessor::new(BIG),
        request(g.original_size),
        &control,
        &mut sink,
    )
    .await;
    assert!(
        matches!(out, Ok(RangeOutcome::Whole(s)) if s.transferred_bytes == g.original_size),
        "{out:?}"
    );
    assert_eq!(sink.buf, fx.plain);
    assert_eq!(
        sink.transfers_before_identity, 0,
        "the identity is recorded before the first transfer (I4)"
    );
    assert_eq!(sink.identity.as_ref().unwrap().format, ChunkFormat::V1Legacy);
    assert_eq!(sink.met, vec![1]);
    assert_eq!(events.bytes(), g.original_size, "progress carries real bytes only");
    assert_eq!(storage_gets(&io), 5, "no chunk fetched twice");
}

/// T6 (and the tag flip): chunk k does not authenticate from storage nor from the pinned API
/// route. The sink holds exactly chunks 0..k-1, 0 bytes of chunk k, and the session never reports
/// whole. Mutant: a frame is released before it is opened.
#[tokio::test]
async fn t6_a_tag_flip_at_chunk_k_leaves_exactly_chunks_0_to_k_minus_1() {
    let fx = Arc::new(Fx::new(6 * STRIDE as usize, ChunkFormat::V1Legacy));
    let g = fx.geometry;
    let k = 3usize;
    let mut frames = fx.frames.clone();
    let last = frames[k].len() - 1;
    frames[k][last] ^= 1;
    let io = ScriptedIo::new(handler(fx.clone(), g, frames, |_| 200));
    let control = RangeControl::new();
    control.demand(1, 0, g.original_size);
    let mut sink = Placeholder::sized(g.original_size);
    // One chunk of budget: chunks arrive and are released one at a time.
    let lessor = RangeLessor::new(STRIDE + 28);
    let (out, events) = run(&io, &lessor, request(g.original_size), &control, &mut sink).await;
    match out {
        Err(RangeSessionError::DirectFailedAfterWrite {
            transferred_bytes,
            cause,
        }) => {
            assert_eq!(transferred_bytes, k as u64 * STRIDE);
            assert!(
                matches!(*cause, RangeSessionError::Unauthentic { index: 3 }),
                "{cause:?}"
            );
        }
        other => panic!("expected a failure after the write, got {other:?}"),
    }
    assert_eq!(sink.have.runs(), &[(0, k as u64 * STRIDE)], "exactly chunks 0..k-1");
    assert_eq!(&sink.buf[..k * STRIDE as usize], &fx.plain[..k * STRIDE as usize]);
    assert_eq!(sink.failed, vec![1], "the demand failed, no filler");
    assert_eq!(events.bytes(), k as u64 * STRIDE);
}

/// A v2 file whose listing and grants claim one chunk fewer: the would-be last chunk does not
/// open as last, and nothing past chunk k-1 is released.
#[tokio::test]
async fn a_v2_geometry_one_chunk_short_releases_nothing_past_k_minus_1() {
    let fx = Arc::new(Fx::new(4 * STRIDE as usize, ChunkFormat::V2));
    let claimed = Geometry {
        chunk_count: 3,
        chunk_size: STRIDE,
        encrypted_size: 3 * (STRIDE + 28),
        original_size: 3 * STRIDE,
    };
    let io = ScriptedIo::new(handler(fx.clone(), claimed, fx.frames.clone(), |_| 200));
    let control = RangeControl::new();
    control.demand(1, 0, claimed.original_size);
    let mut sink = Placeholder::sized(claimed.original_size);
    let mut req = request(claimed.original_size);
    req.pin = ExpectedChunkFormat::V2;
    let (out, _) = run(&io, &RangeLessor::new(STRIDE + 28), req, &control, &mut sink).await;
    assert!(
        matches!(&out, Err(RangeSessionError::DirectFailedAfterWrite { cause, .. }) if matches!(**cause, RangeSessionError::Unauthentic { index: 2 })),
        "{out:?}"
    );
    assert_eq!(sink.have.runs(), &[(0, 2 * STRIDE)]);
}

/// T7: the version goes away after a piece was released. The session fails with
/// `DirectFailedAfterWrite`, never a restart or a fallback into the written sink. Mutant: the
/// failure is reported as if nothing had been written (restart in place).
#[tokio::test]
async fn t7_no_restart_into_a_written_sink() {
    let fx = Arc::new(Fx::new(4 * STRIDE as usize, ChunkFormat::V1Legacy));
    let g = fx.geometry;
    // Chunk 1's storage GET is refused; its renewal window finds the version gone. By then chunk 0
    // is out.
    let base = handler(fx.clone(), g, fx.frames.clone(), |r| if r.renewal { 409 } else { 200 });
    let io = ScriptedIo::new(move |req, wall, mono| match req {
        Request::StorageGet { url, .. } if index_of(url) == 1 => Reply::Storage(StorageReply {
            status: 403,
            content_length: None,
            body: None,
        }),
        _ => base(req, wall, mono),
    });
    let control = RangeControl::new();
    control.demand(1, 0, g.original_size);
    let mut sink = Placeholder::sized(g.original_size);
    let (out, _) = run(
        &io,
        &RangeLessor::new(STRIDE + 28),
        request(g.original_size),
        &control,
        &mut sink,
    )
    .await;
    match out {
        Err(RangeSessionError::DirectFailedAfterWrite {
            transferred_bytes,
            cause,
        }) => {
            assert!(transferred_bytes >= STRIDE, "chunk 0 was out: {transferred_bytes}");
            assert_eq!(transferred_bytes, sink.have.len());
            assert!(!sink.have.covers(STRIDE, STRIDE + 1), "never chunk 1");
            assert!(matches!(*cause, RangeSessionError::FileChanged));
        }
        other => panic!("expected DirectFailedAfterWrite, got {other:?}"),
    }
    assert_eq!(sink.failed, vec![1]);
}

/// T8: a placeholder recorded for another version (or holding bytes with no record) gets nothing
/// until it is emptied; one recorded for this very identity resumes. Mutant: the identity check
/// is skipped.
#[tokio::test]
async fn t8_an_identity_mismatch_transfers_nothing_and_a_match_resumes() {
    let fx = Arc::new(Fx::new(3 * STRIDE as usize, ChunkFormat::V1Legacy));
    let g = fx.geometry;
    let this = RangeIdentity {
        object_version_id: VERSION.into(),
        format: ChunkFormat::V1Legacy,
        version_id: None,
    };
    let other_version = RangeIdentity {
        object_version_id: "99999999-3333-4444-8555-666666666666".into(),
        ..this.clone()
    };
    let other_format = RangeIdentity {
        format: ChunkFormat::V2,
        version_id: Some([1; 12]),
        ..this.clone()
    };
    let cases: [(Option<RangeIdentity>, u64, bool); 4] = [
        (Some(other_version), 10, false),
        (None, 10, false),
        (Some(other_format), 10, false),
        (Some(this), 10, true),
    ];
    for (recorded, on_disk, resumes) in cases {
        let io = ScriptedIo::new(handler(fx.clone(), g, fx.frames.clone(), |_| 200));
        let control = RangeControl::new();
        control.demand(1, 0, g.original_size);
        let mut sink = Placeholder::sized(g.original_size);
        let mut req = request(g.original_size);
        req.recorded = recorded.clone();
        req.on_disk_bytes = on_disk;
        let (out, _) = run(&io, &RangeLessor::new(BIG), req, &control, &mut sink).await;
        if resumes {
            assert!(matches!(out, Ok(RangeOutcome::Whole(_))), "{recorded:?}: {out:?}");
        } else {
            assert!(
                matches!(out, Err(RangeSessionError::IdentityMismatch)),
                "{recorded:?}: {out:?}"
            );
            assert_eq!(sink.transfers, 0, "{recorded:?}: nothing transferred");
            assert_eq!(sink.failed, vec![1]);
        }
    }
}

/// T8, the v2 half (crypto review P2-1): a v2 placeholder recorded for another upload of the same
/// object version (another frame-0 version id) gets nothing; one recorded for this upload resumes.
/// Mutant: the version-id comparison dropped from the frame-0 identity check.
#[tokio::test]
async fn t8_a_v2_placeholder_recorded_for_another_upload_gets_nothing() {
    let fx = Arc::new(Fx::new(3 * STRIDE as usize, ChunkFormat::V2));
    let other = Fx::new(3 * STRIDE as usize, ChunkFormat::V2);
    let vid = |f: &Fx| -> [u8; 12] { f.frames[0][..12].try_into().unwrap() };
    assert_ne!(vid(&fx), vid(&other), "two uploads, two version ids");
    let g = fx.geometry;
    for (recorded_vid, resumes) in [(vid(&other), false), (vid(&fx), true)] {
        let io = ScriptedIo::new(handler(fx.clone(), g, fx.frames.clone(), |_| 200));
        let control = RangeControl::new();
        control.demand(1, 0, g.original_size);
        let mut sink = Placeholder::sized(g.original_size);
        let mut req = request(g.original_size);
        req.pin = ExpectedChunkFormat::V2;
        req.recorded = Some(RangeIdentity {
            object_version_id: VERSION.into(),
            format: ChunkFormat::V2,
            version_id: Some(recorded_vid),
        });
        req.on_disk_bytes = 10;
        let (out, _) = run(&io, &RangeLessor::new(BIG), req, &control, &mut sink).await;
        if resumes {
            assert!(matches!(out, Ok(RangeOutcome::Whole(_))), "{out:?}");
        } else {
            assert!(matches!(out, Err(RangeSessionError::IdentityMismatch)), "{out:?}");
            assert_eq!(
                sink.transfers, 0,
                "nothing of this upload reaches the other's placeholder"
            );
        }
    }
}

/// I6 (crypto review P2-2): a stride that is not a multiple of 4 KiB, released out of order, so
/// heads and tails are carried between chunks. Whole only when every byte reached the sink.
/// Mutant: the piece cutter skips the tail flush.
#[tokio::test]
async fn a_stride_not_a_multiple_of_4_kib_is_carried_and_whole_only_when_every_byte_is_out() {
    let stride = 5000u64;
    let fx = Arc::new(Fx::with_stride(27_000, ChunkFormat::V1Legacy, stride));
    let g = fx.geometry;
    assert_eq!(g.chunk_count, 6);
    let io = ScriptedIo::new(handler(fx.clone(), g, fx.frames.clone(), |_| 200));
    let control = RangeControl::new();
    control.demand(1, 3 * stride + 10, 100);
    let mut sink = Placeholder::sized(g.original_size);
    // One chunk of budget: released strictly in the planner's order 0, 2, 3, 5, 4, 1.
    let lessor = RangeLessor::new(stride + 28);
    let (out, _) = run(&io, &lessor, request(g.original_size), &control, &mut sink).await;
    assert!(matches!(out, Ok(RangeOutcome::Whole(_))), "got {out:?}");
    assert_eq!(sink.buf, fx.plain);
    assert!(sink.have.covers(0, g.original_size));
    assert!(
        sink.offsets.windows(2).any(|w| w[1] < w[0]),
        "released out of order: {:?}",
        sink.offsets
    );
}

/// S10: a window the server cannot serve, before any write, moves the session to pinned
/// per-chunk API fetches (the bytes still come from the same `RangeOpener`).
#[tokio::test]
async fn an_unservable_window_streams_through_the_pinned_api_route() {
    let fx = Arc::new(Fx::new(3 * STRIDE as usize, ChunkFormat::V1Legacy));
    let g = fx.geometry;
    let io = ScriptedIo::new(handler(fx.clone(), g, fx.frames.clone(), |_| 405));
    let control = RangeControl::new();
    control.demand(1, 0, g.original_size);
    let mut sink = Placeholder::sized(g.original_size);
    let mut req = request(g.original_size);
    req.geometry = Some(g);
    let (out, _) = run(&io, &RangeLessor::new(BIG), req, &control, &mut sink).await;
    assert!(
        matches!(out, Ok(RangeOutcome::Whole(s)) if s.chunks_pinned == 3),
        "{out:?}"
    );
    assert_eq!(storage_gets(&io), 0);
    assert_eq!(sink.buf, fx.plain);
}

#[tokio::test]
async fn forced_api_streams_through_the_pinned_route_and_asks_no_discovery() {
    let fx = Arc::new(Fx::new(3 * STRIDE as usize, ChunkFormat::V1Legacy));
    let g = fx.geometry;
    let io = ScriptedIo::new(handler(fx.clone(), g, fx.frames.clone(), |_| 200));
    let control = RangeControl::new();
    control.demand(1, 0, g.original_size);
    let mut sink = Placeholder::sized(g.original_size);
    let mut req = request(g.original_size);
    req.forced_api = true;
    req.geometry = Some(g);
    let (out, _) = run(&io, &RangeLessor::new(BIG), req.clone(), &control, &mut sink).await;
    assert!(matches!(out, Ok(RangeOutcome::Whole(_))), "{out:?}");
    assert_eq!(
        io.count(|r| matches!(r, Request::Api(c) if c.path == DISCOVERY_PATH)),
        0
    );
    // Without a geometry there is nothing to plan: nothing written, the caller's own path.
    req.geometry = None;
    let control = RangeControl::new();
    control.demand(1, 0, 10);
    let mut sink = Placeholder::sized(g.original_size);
    let (out, _) = run(&io, &RangeLessor::new(BIG), req, &control, &mut sink).await;
    assert!(matches!(out, Ok(RangeOutcome::UseApi(_))), "{out:?}");
    assert_eq!(sink.failed, vec![1]);
}

#[tokio::test]
async fn a_seek_releases_chunk_0_and_the_demanded_chunk_then_closes_unwhole() {
    let fx = Arc::new(Fx::new(20 * STRIDE as usize, ChunkFormat::V1Legacy));
    let g = fx.geometry;
    let io = ScriptedIo::new(handler(fx.clone(), g, fx.frames.clone(), |_| 200));
    let control = RangeControl::new();
    control.demand(7, 12 * STRIDE + 10, 100);
    let mut sink = Placeholder::sized(g.original_size);
    sink.close_when_met = Some(control.clone());
    let lessor = RangeLessor::new(2 * (STRIDE + 28));
    let (out, _) = run(&io, &lessor, request(g.original_size), &control, &mut sink).await;
    assert!(matches!(out, Ok(RangeOutcome::Closed(_))), "never whole: {out:?}");
    assert_eq!(sink.met, vec![7]);
    assert!(sink.have.covers(0, STRIDE), "chunk 0 first (I3)");
    assert!(sink.have.covers(12 * STRIDE, 13 * STRIDE));
    assert!(sink.have.len() < g.original_size);
}

#[tokio::test]
async fn a_gone_requester_fails_its_demands_and_starts_no_fetch() {
    let fx = Arc::new(Fx::new(3 * STRIDE as usize, ChunkFormat::V1Legacy));
    let g = fx.geometry;
    let io = ScriptedIo::new(handler(fx.clone(), g, fx.frames.clone(), |_| 200));
    let control = RangeControl::new();
    control.demand(1, 0, g.original_size);
    control.requester_gone();
    control.close();
    let mut sink = Placeholder::sized(g.original_size);
    let (out, _) = run(
        &io,
        &RangeLessor::new(BIG),
        request(g.original_size),
        &control,
        &mut sink,
    )
    .await;
    assert!(matches!(out, Ok(RangeOutcome::Closed(_))), "{out:?}");
    assert_eq!(sink.failed, vec![1]);
    assert_eq!(storage_gets(&io), 0);
}

/// Spec S8: five sessions on one budget. At most four hold a lease; the fifth waits for one; what
/// is held never exceeds max(budget, leased * chunk); every session still ends whole.
#[tokio::test]
async fn five_sessions_share_the_budget_and_a_fifth_waits_for_a_lease() {
    let fx = Arc::new(Fx::new(4 * STRIDE as usize, ChunkFormat::V1Legacy));
    let g = fx.geometry;
    let chunk = STRIDE + 28;
    let lessor = RangeLessor::new(2 * chunk);
    let ios: Vec<ScriptedIo> = (0..5)
        .map(|_| ScriptedIo::new(handler(fx.clone(), g, fx.frames.clone(), |_| 200)))
        .collect();
    let controls: Vec<RangeControl> = (0..5)
        .map(|_| {
            let c = RangeControl::new();
            c.demand(1, 0, g.original_size);
            c
        })
        .collect();
    let mut sinks: Vec<Placeholder> = (0..5).map(|_| Placeholder::sized(g.original_size)).collect();
    let runs = ios
        .iter()
        .zip(controls.iter())
        .zip(sinks.iter_mut())
        .map(|((io, c), sink)| run(io, &lessor, request(g.original_size), c, sink));
    let outs = futures_util::future::join_all(runs).await;
    for (out, _) in &outs {
        assert!(matches!(out, Ok(RangeOutcome::Whole(_))), "{out:?}");
    }
    let (peak_total, peak_leased) = lessor.peaks();
    assert!(peak_leased <= 4, "at most four leases: {peak_leased}");
    assert!(peak_total <= 4 * chunk, "held {peak_total}");
    for sink in &sinks {
        assert_eq!(sink.buf, fx.plain);
    }
}

/// Review finding 5: a placeholder that already holds bytes (a matching record) is a written sink
/// from the start: no early failure may hand it back as empty (`UseApi`).
#[tokio::test]
async fn a_resume_over_bytes_on_disk_never_reports_use_api() {
    let io = ScriptedIo::new(|req, _, _| match req {
        Request::Api(call) if call.path == DISCOVERY_PATH => json(404, serde_json::json!({"error": "not_found"})),
        other => panic!("unexpected request {other:?}"),
    });
    let control = RangeControl::new();
    control.demand(1, 0, 10);
    let mut sink = Placeholder::sized(3 * STRIDE);
    let mut req = request(3 * STRIDE);
    req.recorded = Some(RangeIdentity {
        object_version_id: VERSION.into(),
        format: ChunkFormat::V1Legacy,
        version_id: None,
    });
    req.on_disk_bytes = STRIDE;
    let (out, _) = run(&io, &RangeLessor::new(BIG), req, &control, &mut sink).await;
    assert!(
        matches!(
            &out,
            Err(RangeSessionError::DirectFailedAfterWrite {
                transferred_bytes: 0,
                ..
            })
        ),
        "{out:?}"
    );
    assert_eq!(sink.failed, vec![1]);
}
