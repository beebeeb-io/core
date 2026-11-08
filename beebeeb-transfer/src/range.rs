//! `RangeSession` (the contract's name for [`range_session`]; LD-0105, plan C2): one download per
//! (file id, recorded version) that serves reads at any offset while it runs, releasing each chunk
//! as soon as core's `RangeOpener` has authenticated it at the requested index (core
//! `docs/agent-notes.md`, range reads I1–I9).
//!
//! The rules are core's: `direct_transfer::range::RangePlanner` decides what to ask and fetch,
//! `chunk_stream::RangeOpener` opens frames, `PieceCutter` cuts 4 KiB pieces, `RangeBudget` books
//! the process byte budget. This module does the I/O through the caller's [`DirectIo`] and hands
//! plaintext to a [`RangeSink`] (on Windows: the Cloud Files placeholder).
//!
//! What it guarantees the sink:
//! - nothing is transferred before its frame authenticated (I1), at `index * chunk_size` of the
//!   session's one geometry, whose size must be the size the caller states (I2, S9);
//! - the identity `(object_version_id, format, v2 version id)` is checked against the caller's
//!   record and handed to [`RangeSink::record_identity`] BEFORE the first transfer (I3, I4); no
//!   record while the sink already holds bytes is a mismatch;
//! - a failure after the first transfer is [`RangeSessionError::DirectFailedAfterWrite`]: the
//!   session never restarts or falls back into a written sink (I4, I5);
//! - every pending demand is answered: met, or failed with no filler (I7);
//! - "whole" is [`RangeOutcome::Whole`] only, reached when `RangeOpener::finish()` passes (I6);
//! - plaintext is `Zeroizing`, at most one chunk plus the cutter's partial blocks (I8); no event,
//!   error or `Debug` string carries a URL or a name.

use std::collections::{BTreeMap, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::task::{Context, Poll as TaskPoll, Waker};
use std::time::Duration;

use beebeeb_core::chunk_stream::{ChunkFormat, ExpectedChunkFormat, RangeOpener, VERSION_ID_LEN, VersionCommitment};
use beebeeb_core::direct_transfer::range::{
    PieceCutter, RangeBudget, RangeConfig, RangePlanner, RangePoll, RunSet, demand_chunks,
};
use beebeeb_core::direct_transfer::window::Geometry;
use beebeeb_core::direct_transfer::{
    self as dt, API_CALL_TIMEOUT, Call, MemoryClass, Outcome, STORAGE_CONNECT_TIMEOUT, STORAGE_GET_IDLE, StorageBody,
    StorageGet, Verdict, classify, download_grants_path, max_in_flight_bytes, pinned_chunk_path, storage_get_total,
};
use beebeeb_core::kdf::FileKey;
use bytes::Bytes;
use futures_util::future::{Either, select};
use futures_util::stream::{FuturesUnordered, StreamExt};

use crate::download::{DiscoveryFailure, Pinned, discovery, pinned_fetch};
use crate::io::{ApiCall, ApiMethod, DirectIo, SignedUrl};
use crate::observer::{ChunkVia, Observer, TransferEvent, TransportKind, UseApiReason};
use crate::shared::DirectShared;

/// Who a placeholder's bytes belong to: one attempt of one version (I4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RangeIdentity {
    pub object_version_id: String,
    pub format: ChunkFormat,
    /// A v2 file's version id (frame 0's nonce); `None` for v1.
    pub version_id: Option<[u8; VERSION_ID_LEN]>,
}

/// What to serve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RangeRequest {
    pub api_base: String,
    pub file_id: String,
    /// The placeholder's minted version: every window asks for it, and another is a refresh.
    pub object_version_id: String,
    /// The size the OS holds for the file; the session's geometry must state the same (I2, S9).
    pub file_size: u64,
    /// The content pin from `decrypt_file_metadata[_with_key]` (I3).
    pub pin: ExpectedChunkFormat,
    /// The version commitment from the same authenticated metadata (`NameMetadata::version`).
    /// When present, frame 0 must be the committed upload, so an older one cannot be served.
    pub version: Option<VersionCommitment>,
    /// Plaintext chunk stride from authenticated metadata, when present. A geometry with any
    /// other stride is refused before anything is released.
    pub authenticated_chunk_size: Option<u64>,
    /// The geometry the caller already knows. Required to stream through the pinned API route.
    pub geometry: Option<Geometry>,
    /// The identity the caller recorded for this placeholder, if any (I4).
    pub recorded: Option<RangeIdentity>,
    /// Plaintext bytes the placeholder already holds (ONDISK). With no record, more than 0 is a
    /// mismatch (I4).
    pub on_disk_bytes: u64,
    /// `BB_TRANSPORT=api`: every chunk through the pinned per-chunk API route.
    pub forced_api: bool,
    pub jitter_seed: u64,
}

/// Where authenticated plaintext goes. Every call is made from the session's own task. A sink's
/// errors must not carry a file name or path; the session shows only their kind anyway.
pub trait RangeSink: Send {
    /// Record `identity` durably. Called once, before the first [`RangeSink::transfer`]; an
    /// `Err` ends the session with nothing transferred.
    fn record_identity(&mut self, identity: &RangeIdentity) -> std::io::Result<()>;
    /// Hand `plain` to the OS at `offset`: authenticated, and cut on 4 KiB boundaries (or ending
    /// on the end of the file).
    fn transfer(&mut self, offset: u64, plain: &[u8]) -> std::io::Result<()>;
    /// Demand `id` has every byte it asked for.
    fn demand_met(&mut self, id: u64);
    /// Demand `id` cannot be served: answer its remaining range with a failure, never filler (I7).
    fn demand_failed(&mut self, id: u64);
}

/// How a session ended without an error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RangeOutcome {
    /// Every chunk was opened and transferred in THIS attempt and `RangeOpener::finish()` passed:
    /// the only "whole" (I6).
    Whole(RangeStats),
    /// The caller closed the session first. What was transferred stays; it is never "whole".
    Closed(RangeStats),
    /// Nothing was transferred and direct cannot serve the file: the caller's own path is correct.
    UseApi(UseApiReason),
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RangeStats {
    pub transferred_bytes: u64,
    pub chunks_storage: u32,
    pub chunks_pinned: u32,
    pub windows: u32,
}

/// Why a session failed.
#[derive(Debug)]
pub enum RangeSessionError {
    Unauthorized,
    Forbidden,
    /// The version is gone or another was served: refresh the placeholder.
    FileChanged,
    /// Chunk `index` did not authenticate from storage or from the pinned API route.
    Unauthentic {
        index: u32,
    },
    /// The placeholder holds bytes of another (or an unknown) identity. Nothing was transferred;
    /// the caller poisons and empties it before any session may write (I4).
    IdentityMismatch,
    /// The geometry's size is not the size the caller states (task 0783). Nothing transferred.
    SizeMismatch,
    /// The metadata pins v2 and carries no version commitment, so no frame of the file may open
    /// (Guus's ruling of 2026-11-07, "refuse v2 without commitment"). Refused before any request.
    MissingVersionCommitment,
    /// The sink refused before anything was transferred.
    Sink(std::io::Error),
    /// Every chunk opened, but the sink did not get every byte (or the piece cutter still holds
    /// some): never whole (I6).
    Incomplete,
    /// Only the API path could go on (a cause inside `DirectFailedAfterWrite`: after a write the
    /// session never falls back into the same sink).
    ApiNeeded(UseApiReason),
    /// The session failed after it had transferred plaintext. The sink holds a prefix of
    /// authenticated chunks and must not be reused until it is verifiably empty (I4, I5).
    DirectFailedAfterWrite {
        transferred_bytes: u64,
        cause: Box<RangeSessionError>,
    },
}

impl std::fmt::Display for RangeSessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RangeSessionError::Unauthorized => f.write_str("sign in again"),
            RangeSessionError::Forbidden => f.write_str("this account may not download the file"),
            RangeSessionError::FileChanged => f.write_str("the file changed"),
            RangeSessionError::Unauthentic { index } => write!(f, "chunk {index} did not authenticate"),
            RangeSessionError::IdentityMismatch => f.write_str("the placeholder holds another version's bytes"),
            RangeSessionError::SizeMismatch => f.write_str("the file's size is not the size it is known to have"),
            RangeSessionError::MissingVersionCommitment => {
                f.write_str("the file's metadata records v2 content without a version commitment")
            }
            RangeSessionError::Sink(e) => write!(f, "handing bytes to the system failed ({:?})", e.kind()),
            RangeSessionError::Incomplete => f.write_str("every chunk opened, but not every byte reached the system"),
            RangeSessionError::ApiNeeded(_) => f.write_str("only the API path could go on"),
            RangeSessionError::DirectFailedAfterWrite {
                transferred_bytes,
                cause,
            } => write!(
                f,
                "failed after at least {transferred_bytes} bytes were handed over: {cause}"
            ),
        }
    }
}

impl std::error::Error for RangeSessionError {}

enum Command {
    Demand { id: u64, offset: u64, len: u64 },
    Cancel(u64),
    RequesterGone,
    Close,
}

#[derive(Default)]
struct MailState {
    commands: VecDeque<Command>,
    kicked: bool,
    waker: Option<Waker>,
}

/// A session's inbox: commands from the reads, and kicks from the lessor when budget frees up.
#[derive(Default)]
struct Mailbox(Mutex<MailState>);

impl Mailbox {
    fn post(&self, command: Option<Command>) {
        let mut s = self.0.lock().unwrap_or_else(|e| e.into_inner());
        match command {
            Some(c) => s.commands.push_back(c),
            None => s.kicked = true,
        }
        if let Some(w) = s.waker.take() {
            w.wake();
        }
    }

    fn take(&self) -> Vec<Command> {
        let mut s = self.0.lock().unwrap_or_else(|e| e.into_inner());
        s.kicked = false;
        s.commands.drain(..).collect()
    }

    fn wait(&self) -> MailWait<'_> {
        MailWait(self)
    }
}

struct MailWait<'a>(&'a Mailbox);

impl Future for MailWait<'_> {
    type Output = ();
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> TaskPoll<()> {
        let mut s = self.0.0.lock().unwrap_or_else(|e| e.into_inner());
        if s.kicked || !s.commands.is_empty() {
            TaskPoll::Ready(())
        } else {
            s.waker = Some(cx.waker().clone());
            TaskPoll::Pending
        }
    }
}

/// The reads' handle on one session: demands, cancels, and the end.
#[derive(Clone)]
pub struct RangeControl(Arc<Mailbox>);

impl RangeControl {
    pub fn new() -> RangeControl {
        RangeControl(Arc::new(Mailbox::default()))
    }

    /// A read wants plaintext `[offset, offset + len)`; answered by `demand_met` or `demand_failed`.
    pub fn demand(&self, id: u64, offset: u64, len: u64) {
        self.0.post(Some(Command::Demand { id, offset, len }));
    }

    /// `CANCEL_FETCH_DATA` for demand `id`. When no demand is left, read-ahead stops.
    pub fn cancel(&self, id: u64) {
        self.0.post(Some(Command::Cancel(id)));
    }

    /// No live requester is left: every pending demand fails, read-ahead stops.
    pub fn requester_gone(&self) {
        self.0.post(Some(Command::RequesterGone));
    }

    /// End the session; pending demands fail.
    pub fn close(&self) {
        self.0.post(Some(Command::Close));
    }
}

impl Default for RangeControl {
    fn default() -> Self {
        RangeControl::new()
    }
}

struct LessorState {
    book: RangeBudget,
    waiting: BTreeMap<u64, Arc<Mailbox>>,
    peak_total: u64,
    peak_leased: usize,
}

/// The process byte budget range sessions lease (spec S8): at most four sessions hold a lease,
/// a fifth waits; a session's fetch is booked before it starts. One per process
/// ([`RangeLessor::global`]); tests make their own.
#[derive(Clone)]
pub struct RangeLessor(Arc<Mutex<LessorState>>);

static NEXT_SESSION: AtomicU64 = AtomicU64::new(1);

impl RangeLessor {
    pub fn new(budget_bytes: u64) -> RangeLessor {
        RangeLessor(Arc::new(Mutex::new(LessorState {
            book: RangeBudget::new(budget_bytes),
            waiting: BTreeMap::new(),
            peak_total: 0,
            peak_leased: 0,
        })))
    }

    /// The process lessor, on the native budget.
    pub fn global() -> &'static RangeLessor {
        static GLOBAL: OnceLock<RangeLessor> = OnceLock::new();
        GLOBAL.get_or_init(|| RangeLessor::new(max_in_flight_bytes(MemoryClass::Native)))
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, LessorState> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The most ciphertext bytes ever booked at once, and the most leases ever held.
    pub fn peaks(&self) -> (u64, usize) {
        let s = self.lock();
        (s.peak_total, s.peak_leased)
    }

    fn lease(&self, session: u64, mailbox: &Arc<Mailbox>) -> bool {
        let mut s = self.lock();
        if s.book.lease(session) {
            s.waiting.remove(&session);
            s.peak_leased = s.peak_leased.max(s.book.leased());
            true
        } else {
            s.waiting.insert(session, mailbox.clone());
            false
        }
    }

    fn share(&self) -> u64 {
        self.lock().book.share()
    }

    fn try_hold(&self, session: u64, len: u64, mailbox: &Arc<Mailbox>) -> bool {
        let mut s = self.lock();
        if s.book.try_hold(session, len) {
            s.peak_total = s.peak_total.max(s.book.total_held());
            true
        } else {
            s.waiting.insert(session, mailbox.clone());
            false
        }
    }

    /// Give bytes (or the whole lease) back and wake every session that waits for room.
    fn give_back(&self, session: u64, len: u64, lease: bool) {
        let waiting: Vec<Arc<Mailbox>> = {
            let mut s = self.lock();
            if lease {
                s.book.release(session);
                s.waiting.remove(&session);
            } else {
                s.book.unhold(session, len);
            }
            std::mem::take(&mut s.waiting).into_values().collect()
        };
        for mailbox in waiting {
            mailbox.post(None);
        }
    }
}

/// Test seam: another session's lease and bytes, booked by the book's own rules.
#[cfg(test)]
impl RangeLessor {
    pub(crate) fn lease_and_hold(&self, session: u64, len: u64) -> bool {
        let mut s = self.lock();
        s.book.lease(session) && (len == 0 || s.book.try_hold(session, len))
    }

    pub(crate) fn release_lease(&self, session: u64) {
        self.give_back(session, 0, true);
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

type Task<'a> = Pin<Box<dyn Future<Output = Event> + Send + 'a>>;

/// Hands the lease back on every exit, a cancelled future included.
struct LeaseGuard<'a> {
    lessor: &'a RangeLessor,
    session: u64,
    leased: bool,
}

impl Drop for LeaseGuard<'_> {
    fn drop(&mut self) {
        if self.leased {
            self.lessor.give_back(self.session, 0, true);
        }
    }
}

struct State<'a> {
    sink: &'a mut dyn RangeSink,
    observer: &'a dyn Observer,
    demands: BTreeMap<u64, (u64, u64)>,
    transferred: RunSet,
    wrote: bool,
    stats: RangeStats,
}

impl State<'_> {
    /// Fail every pending demand, then turn `cause` into the session's error: after a write the
    /// sink is poisoned (I4, I5), never handed back for a retry.
    fn fail(&mut self, cause: RangeSessionError) -> Result<RangeOutcome, RangeSessionError> {
        for id in std::mem::take(&mut self.demands).into_keys() {
            self.sink.demand_failed(id);
        }
        // A mismatch is always reported as itself: it is checked before this session's first
        // transfer, and the caller's answer (poison, then empty) is the same either way.
        if self.wrote && !matches!(cause, RangeSessionError::IdentityMismatch) {
            Err(RangeSessionError::DirectFailedAfterWrite {
                transferred_bytes: self.transferred.len(),
                cause: Box::new(cause),
            })
        } else {
            Err(cause)
        }
    }

    fn use_api(&mut self, reason: UseApiReason) -> Result<RangeOutcome, RangeSessionError> {
        if self.wrote {
            return self.fail(RangeSessionError::ApiNeeded(reason));
        }
        for id in std::mem::take(&mut self.demands).into_keys() {
            self.sink.demand_failed(id);
        }
        Ok(RangeOutcome::UseApi(reason))
    }

    /// Answer every demand whose bytes are all out.
    fn settle(&mut self, planner: &mut RangePlanner, size: u64) {
        let met: Vec<u64> = self
            .demands
            .iter()
            .filter(|(_, (o, l))| self.transferred.covers(*o, o.saturating_add(*l).min(size)))
            .map(|(id, _)| *id)
            .collect();
        for id in met {
            self.demands.remove(&id);
            planner.demand_met(id);
            self.sink.demand_met(id);
        }
    }
}

/// The one "whole" verdict (I6): every index opened in this attempt (`RangeOpener::finish`), every
/// byte of the file handed to the sink, and nothing left in the piece cutter.
fn whole(
    st: &mut State<'_>,
    opener: Option<&RangeOpener>,
    cutter: &PieceCutter,
    file_size: u64,
) -> Result<RangeOutcome, RangeSessionError> {
    let opened = opener.is_some_and(|o| o.finish().is_ok());
    if opened && st.transferred.covers(0, file_size) && cutter.held_bytes() == 0 {
        Ok(RangeOutcome::Whole(st.stats))
    } else {
        st.fail(RangeSessionError::Incomplete)
    }
}

/// The planner's verdict as the session's end. `index` is the chunk a `Corrupt` verdict is for.
fn stop(st: &mut State<'_>, verdict: Verdict, index: u32) -> Result<RangeOutcome, RangeSessionError> {
    match verdict {
        Verdict::ApiForFile => st.use_api(UseApiReason::ApiForFile),
        Verdict::Restart => st.fail(RangeSessionError::FileChanged),
        Verdict::Terminal(t) if t.status == 401 => st.fail(RangeSessionError::Unauthorized),
        Verdict::Terminal(t) if t.status == 403 => st.fail(RangeSessionError::Forbidden),
        Verdict::Terminal(_) => st.use_api(UseApiReason::ApiForFile),
        Verdict::Corrupt => st.fail(RangeSessionError::Unauthentic { index }),
    }
}

/// A fetch of `index` ended without a release: give its booking back, except chunk 0's, which it
/// keeps until chunk 0 is released (its refetch runs on it; `RangePlanner::poll_with`).
fn unbook(lessor: &RangeLessor, session: u64, booked: &mut BTreeMap<u32, u64>, index: u32) {
    if index != 0 {
        lessor.give_back(session, booked.remove(&index).unwrap_or(0), false);
    }
}

/// Serve one placeholder until it is whole, the caller closes it, or it fails. `file_key` is the
/// file's key; `control` carries the reads. See the module docs for what the sink is promised.
#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
pub async fn range_session<I: DirectIo>(
    io: &I,
    shared: &DirectShared,
    lessor: &RangeLessor,
    req: RangeRequest,
    file_key: FileKey,
    control: &RangeControl,
    sink: &mut dyn RangeSink,
    observer: &dyn Observer,
) -> Result<RangeOutcome, RangeSessionError> {
    let mut st = State {
        sink,
        observer,
        demands: BTreeMap::new(),
        transferred: RunSet::new(),
        // A sink that already holds bytes is written: no failure may hand it back as empty (I4).
        wrote: req.on_disk_bytes > 0,
        stats: RangeStats::default(),
    };
    // Demands posted before the session started are pending demands too: every early exit
    // answers them (I7).
    let mut early: Vec<Command> = control.0.take();
    for command in &early {
        if let Command::Demand { id, offset, len } = command {
            st.demands.insert(*id, (*offset, *len));
        }
    }
    // Spec S3: with ONDISK = 0 there is nothing to trust, whatever an old record says.
    let mut req = req;
    if req.on_disk_bytes == 0 {
        req.recorded = None;
    }
    // I4: the placeholder must hold nothing, or bytes of exactly this version.
    let identity_ok = match &req.recorded {
        None => req.on_disk_bytes == 0,
        Some(recorded) => recorded.object_version_id.eq_ignore_ascii_case(&req.object_version_id),
    };
    if !identity_ok {
        return st.fail(RangeSessionError::IdentityMismatch);
    }
    // A v2 pin without a commitment opens nothing (core refuses it too): no request is made.
    if req.pin == ExpectedChunkFormat::V2 && req.version.is_none() {
        return st.fail(RangeSessionError::MissingVersionCommitment);
    }
    let mailbox = control.0.clone();
    let session = NEXT_SESSION.fetch_add(1, Ordering::Relaxed);
    let mut guard = LeaseGuard {
        lessor,
        session,
        leased: false,
    };

    let direct = if req.forced_api {
        None
    } else {
        match discovery(io, shared, observer).await {
            Ok(d) if d.offers_download() => Some(d),
            Ok(_) | Err(DiscoveryFailure::NotSupported | DiscoveryFailure::Unavailable) => None,
            Err(DiscoveryFailure::Unauthorized) => return st.fail(RangeSessionError::Unauthorized),
            Err(DiscoveryFailure::Forbidden) => return st.fail(RangeSessionError::Forbidden),
        }
    };
    // Without direct transport the session streams through the pinned API route, which needs the
    // geometry from the caller (S10).
    if direct.is_none() && req.geometry.is_none() {
        let reason = if req.forced_api {
            UseApiReason::ForcedApi
        } else {
            UseApiReason::NotSupported
        };
        return st.use_api(reason);
    }
    observer.event(TransferEvent::Decided(if direct.is_some() {
        TransportKind::Direct
    } else {
        TransportKind::Api
    }));
    let discovery = direct.clone().unwrap_or_default();
    let cfg = RangeConfig::from_discovery(&discovery, lessor.share(), req.jitter_seed);
    let mut planner = RangePlanner::new(cfg, discovery, &req.api_base, &req.file_id, &req.object_version_id);
    if let Some(g) = req.geometry {
        planner = planner.with_geometry(g);
    }
    if direct.is_none() {
        planner.force_api();
    }

    let mut file_key = Some(file_key);
    let mut opener: Option<RangeOpener> = None;
    let mut cutter = PieceCutter::new(req.file_size);
    let mut identity_recorded = false;
    let mut tasks: FuturesUnordered<Task<'_>> = FuturesUnordered::new();
    let mut ready: BTreeMap<u32, Bytes> = BTreeMap::new();
    let mut booked: BTreeMap<u32, u64> = BTreeMap::new();
    let mut last_unauthentic = 0u32;

    loop {
        let mut commands = std::mem::take(&mut early);
        commands.extend(mailbox.take());
        for command in commands {
            match command {
                Command::Demand { id, offset, len } => {
                    // A repeated id is the demand already pending: it gets one answer.
                    if planner.demand(id, offset, len).is_ok() {
                        st.demands.insert(id, (offset, len));
                    }
                }
                Command::Cancel(id) => {
                    planner.cancel(id);
                    st.demands.remove(&id);
                }
                Command::RequesterGone => {
                    planner.requester_gone();
                    for id in std::mem::take(&mut st.demands).into_keys() {
                        st.sink.demand_failed(id);
                    }
                }
                Command::Close => {
                    for id in std::mem::take(&mut st.demands).into_keys() {
                        st.sink.demand_failed(id);
                    }
                    return Ok(RangeOutcome::Closed(st.stats));
                }
            }
        }
        st.settle(&mut planner, req.file_size);

        // A lease while there is work; none while idle, so an idle session never blocks a fifth.
        let busy = planner.demands() > 0 || planner.reading_ahead() || !tasks.is_empty() || !ready.is_empty();
        if busy && !guard.leased {
            guard.leased = lessor.lease(session, &mailbox);
        } else if !busy && guard.leased {
            // Nothing is out or waiting, so at most chunk 0's kept booking goes with the lease.
            lessor.give_back(session, 0, true);
            guard.leased = false;
            booked.clear();
            planner.bookings_returned();
        }
        if guard.leased {
            planner.set_share(lessor.share());
        }

        let mut nap: Option<Duration> = None;
        // The planner had a fetch to start and only budget room was missing: the lessor wakes this
        // session when some frees.
        let mut short_of_room = false;
        if guard.leased {
            loop {
                // Book one chunk's worth before the planner may start a fetch; settle it after.
                let reserve = planner
                    .geometry()
                    .map_or(0, |g| g.chunk_size + dt::wire::CHUNK_OVERHEAD);
                let room = reserve > 0 && lessor.try_hold(session, reserve, &mailbox);
                let poll = planner.poll_with(io.wall_ms(), room);
                short_of_room = planner.waits_for_room();
                let fetched = match &poll {
                    RangePoll::Fetch { index, .. } | RangePoll::FetchViaApi { index, .. } => Some(*index),
                    _ => None,
                };
                match fetched {
                    // Chunk 0's refetch runs on the booking it kept since its first fetch (the
                    // planner starts it even with no room, so the chunks waiting for it never
                    // leave it without room).
                    Some(index) if booked.contains_key(&index) => {
                        if room {
                            lessor.give_back(session, reserve, false);
                        }
                    }
                    Some(index) => {
                        debug_assert!(room, "chunk {index} started with no booking");
                        if room {
                            let len = planner
                                .geometry()
                                .and_then(|g| g.chunk_length(index))
                                .unwrap_or(reserve);
                            lessor.give_back(session, reserve - len.min(reserve), false);
                            booked.insert(index, len.min(reserve));
                        }
                    }
                    None if room => lessor.give_back(session, reserve, false),
                    None => {}
                }
                match poll {
                    RangePoll::RequestWindow(request) => {
                        let path = download_grants_path(&req.file_id);
                        let Ok(body) = serde_json::to_vec(&request) else {
                            return st.use_api(UseApiReason::ApiForFile);
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
                    RangePoll::Fetch { index, grant } => {
                        let url = SignedUrl::new(grant.url);
                        let expected_len = grant.length;
                        tasks.push(Box::pin(async move {
                            let total = storage_get_total(expected_len);
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
                    RangePoll::FetchViaApi {
                        index,
                        object_version_id,
                    } => {
                        let expected = planner.geometry().and_then(|g| g.chunk_length(index));
                        let path = pinned_chunk_path(&req.file_id, index, &object_version_id).ok();
                        let (Some(expected_len), Some(path)) = (expected, path) else {
                            return st.use_api(UseApiReason::ApiForFile);
                        };
                        tasks.push(Box::pin(async move {
                            let result = pinned_fetch(io, path, expected_len).await;
                            Event::Pinned { index, result }
                        }));
                    }
                    RangePoll::Wait { until_ms } => {
                        nap = until_ms.map(|at| Duration::from_millis((at - io.wall_ms()).max(0) as u64));
                        break;
                    }
                    RangePoll::Idle => break,
                    RangePoll::Done => return whole(&mut st, opener.as_ref(), &cutter, req.file_size),
                    RangePoll::Stop(verdict) => return stop(&mut st, verdict, last_unauthentic),
                }
            }
        }

        // A paused session (no demand, nothing out, nothing scheduled: read-ahead stalled at aged-out
        // grants) gives its lease back, so it never blocks a fifth session. A new demand takes one
        // again. Short of room it keeps the lease and stays on the lessor's wait list: it wakes when
        // budget frees up, and read-ahead goes on to the whole file.
        if guard.leased
            && planner.demands() == 0
            && tasks.is_empty()
            && ready.is_empty()
            && nap.is_none()
            && !short_of_room
        {
            lessor.give_back(session, 0, true);
            guard.leased = false;
            booked.clear();
            planner.bookings_returned();
        }

        // Wait for a reply, a command, a lessor kick or the planner's own deadline.
        let event = {
            let mail = mailbox.wait();
            futures_util::pin_mut!(mail);
            let timer = async {
                match nap {
                    Some(d) => io.sleep(d).await,
                    None => std::future::pending::<()>().await,
                }
            };
            futures_util::pin_mut!(timer);
            let wake = select(mail, timer);
            if tasks.is_empty() {
                wake.await;
                None
            } else {
                match select(tasks.next(), wake).await {
                    Either::Left((event, _)) => event,
                    Either::Right(_) => None,
                }
            }
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
                    Outcome::Proceed => {
                        if planner.window_answered_bytes(&reply.body, io.wall_ms()) == dt::WindowAnswer::Accepted {
                            st.stats.windows += 1;
                        }
                    }
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
                    (StorageGet::Stored, Some(body)) if planner.fetch_ok(index).is_ok() => {
                        st.stats.chunks_storage += 1;
                        observer.event(TransferEvent::Chunk {
                            index,
                            via: ChunkVia::Storage,
                        });
                        ready.insert(index, body);
                    }
                    _ => {
                        unbook(lessor, session, &mut booked, index);
                        if planner.fetch_failed(index, io.wall_ms()).is_err() {
                            return st.use_api(UseApiReason::ApiForFile);
                        }
                    }
                }
            }
            Some(Event::Pinned { index, result }) => match result {
                Pinned::Ok(bytes) if planner.fetch_ok(index).is_ok() => {
                    st.stats.chunks_pinned += 1;
                    observer.event(TransferEvent::Chunk {
                        index,
                        via: ChunkVia::Pinned,
                    });
                    ready.insert(index, Bytes::from(bytes));
                }
                Pinned::Terminal(401) => return st.fail(RangeSessionError::Unauthorized),
                Pinned::Terminal(403) => return st.fail(RangeSessionError::Forbidden),
                Pinned::Restart => return st.fail(RangeSessionError::FileChanged),
                _ => {
                    unbook(lessor, session, &mut booked, index);
                    if planner.api_fetch_failed(index).is_err() {
                        return st.use_api(UseApiReason::ApiForFile);
                    }
                }
            },
        }

        // The geometry is known from the first accepted window (or the caller): fix the opener.
        if opener.is_none() {
            if let (Some(g), Some(key)) = (planner.geometry(), file_key.take()) {
                if req
                    .authenticated_chunk_size
                    .is_some_and(|stride| stride != g.chunk_size)
                {
                    return st.fail(RangeSessionError::SizeMismatch);
                }
                match RangeOpener::new(key, &req.file_id, req.pin, req.version, g, req.file_size) {
                    Ok(o) => opener = Some(o),
                    Err(_) => return st.fail(RangeSessionError::SizeMismatch),
                }
            }
        }
        let Some(o) = opener.as_mut() else { continue };

        // Open and release what arrived: frame 0 first (I3; the keys are in order), then, in the
        // same pass, every frame that waited for it.
        let order: Vec<u32> = ready.keys().copied().collect();
        for index in order {
            if index != 0 && o.format().is_none() {
                continue;
            }
            let Some(frame) = ready.remove(&index) else { continue };
            let plain = match o.open(index, &frame) {
                Ok(plain) => plain,
                Err(_) => {
                    last_unauthentic = index;
                    unbook(lessor, session, &mut booked, index);
                    if planner.chunk_unauthentic(index).is_err() {
                        return st.use_api(UseApiReason::ApiForFile);
                    }
                    // On a verdict (the second failure: Corrupt) nothing more is released (I5).
                    if let Some(verdict) = planner.verdict() {
                        return stop(&mut st, verdict.clone(), index);
                    }
                    continue;
                }
            };
            if !identity_recorded {
                let (Some(format), true) = (o.format(), index == 0) else {
                    return st.fail(RangeSessionError::Unauthentic { index });
                };
                let identity = RangeIdentity {
                    object_version_id: req.object_version_id.clone(),
                    format,
                    version_id: o.version_id(),
                };
                let same = |r: &RangeIdentity| {
                    r.object_version_id.eq_ignore_ascii_case(&identity.object_version_id)
                        && r.format == identity.format
                        && r.version_id == identity.version_id
                };
                if req.recorded.as_ref().is_some_and(|r| !same(r)) {
                    return st.fail(RangeSessionError::IdentityMismatch);
                }
                if let Err(e) = st.sink.record_identity(&identity) {
                    return st.fail(RangeSessionError::Sink(e));
                }
                identity_recorded = true;
            }
            let offset = o.plaintext_offset(index).unwrap_or(0);
            let Ok(pieces) = cutter.cut(offset, &plain) else {
                return st.fail(RangeSessionError::SizeMismatch);
            };
            for piece in &pieces {
                // Written is set BEFORE the call: a transfer that fails partway counts.
                st.wrote = true;
                if let Err(e) = st.sink.transfer(piece.offset(), piece.bytes(&plain)) {
                    return st.fail(RangeSessionError::Sink(e));
                }
                st.transferred.insert(piece.offset(), piece.offset() + piece.len());
                st.stats.transferred_bytes += piece.len();
                st.observer.event(TransferEvent::Bytes(piece.len()));
            }
            drop(plain);
            lessor.give_back(session, booked.remove(&index).unwrap_or(0), false);
            if planner.released(index).is_err() {
                return st.fail(RangeSessionError::Unauthentic { index });
            }
        }
        st.settle(&mut planner, req.file_size);
        if planner
            .geometry()
            .is_some_and(|g| planner.released_count() == u64::from(g.chunk_count))
        {
            return whole(&mut st, opener.as_ref(), &cutter, req.file_size);
        }
        // Demands that ask for nothing inside the file are met at once.
        if let Some(g) = planner.geometry() {
            let empty: Vec<u64> = st
                .demands
                .iter()
                .filter(|(_, (o, l))| demand_chunks(&g, *o, *l).is_none())
                .map(|(id, _)| *id)
                .collect();
            for id in empty {
                st.demands.remove(&id);
                planner.demand_met(id);
                st.sink.demand_met(id);
            }
        }
    }
}

impl std::fmt::Debug for RangeControl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RangeControl")
    }
}
