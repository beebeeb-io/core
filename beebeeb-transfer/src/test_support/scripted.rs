//! A transport that answers from a script (plan K2 tests).
//!
//! Every request is recorded with the virtual clocks at the moment it was
//! made, so a test can assert both what was asked and when. No socket is
//! opened: `wall` and `mono` advance only through the test's calls and
//! `sleep`.

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Poll, Waker};
use std::time::Duration;

use bytes::Bytes;

use crate::io::{ApiCall, ApiReply, DirectIo, SignedUrl, StorageReply};

/// The start of the virtual wall clock (2023-11-14T22:13:20Z).
pub const WALL_START_MS: i64 = 1_700_000_000_000;

/// One request the scripted transport saw.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    Api(ApiCall),
    StorageGet {
        /// The link. Tests compare it; the driver itself never prints it.
        url: String,
        expected_len: u64,
        total: Duration,
    },
    StoragePut {
        url: String,
        body: Bytes,
        headers: Vec<(String, String)>,
        total: Duration,
    },
}

impl Request {
    /// The API path (or the storage path, for a storage request).
    pub fn path(&self) -> &str {
        match self {
            Request::Api(call) => &call.path,
            Request::StorageGet { url, .. } | Request::StoragePut { url, .. } => url.split('?').next().unwrap_or(url),
        }
    }

    /// The `object_version_id` query value, when the request has one.
    pub fn object_version_id(&self) -> Option<&str> {
        let url = match self {
            Request::Api(call) => &call.path,
            Request::StorageGet { url, .. } | Request::StoragePut { url, .. } => url,
        };
        url.split_once("object_version_id=")
            .map(|(_, rest)| rest.split('&').next().unwrap_or(rest))
    }
}

/// What the script answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reply {
    Api(ApiReply),
    Storage(StorageReply),
    Put(u16),
}

/// A request and the clocks it was made at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recorded {
    pub request: Request,
    pub wall_ms: i64,
    pub mono_ms: i64,
}

/// A handle on the scripted transport's virtual clocks, so a script can move
/// time while it answers (a link that expires during a suspend).
#[derive(Clone, Debug)]
pub struct Clock {
    wall: Arc<AtomicI64>,
    mono: Arc<AtomicI64>,
}

impl Default for Clock {
    fn default() -> Clock {
        Clock::new()
    }
}

impl Clock {
    pub fn new() -> Clock {
        Clock {
            wall: Arc::new(AtomicI64::new(WALL_START_MS)),
            mono: Arc::new(AtomicI64::new(0)),
        }
    }

    pub fn wall(&self) -> i64 {
        self.wall.load(Ordering::SeqCst)
    }

    pub fn mono(&self) -> i64 {
        self.mono.load(Ordering::SeqCst)
    }

    pub fn set_wall(&self, ms: i64) {
        self.wall.store(ms, Ordering::SeqCst);
    }

    pub fn advance_wall(&self, ms: i64) {
        self.wall.fetch_add(ms, Ordering::SeqCst);
    }

    pub fn advance_mono(&self, ms: i64) {
        self.mono.fetch_add(ms, Ordering::SeqCst);
    }
}

/// What a script answers: request plus the clocks at that moment.
pub type Handler = Box<dyn Fn(&Request, i64, i64) -> Reply + Send + Sync>;

/// The scripted transport.
pub struct ScriptedIo {
    handler: Handler,
    log: Mutex<Vec<Recorded>>,
    wall: Arc<AtomicI64>,
    mono: Arc<AtomicI64>,
    gate: Option<Arc<Gate>>,
}

impl ScriptedIo {
    pub fn new(handler: impl Fn(&Request, i64, i64) -> Reply + Send + Sync + 'static) -> Self {
        ScriptedIo {
            handler: Box::new(handler),
            log: Mutex::new(Vec::new()),
            wall: Arc::new(AtomicI64::new(WALL_START_MS)),
            mono: Arc::new(AtomicI64::new(0)),
            gate: None,
        }
    }

    /// The same clocks this transport uses, for a script that moves time.
    pub fn clock(&self) -> Clock {
        Clock {
            wall: self.wall.clone(),
            mono: self.mono.clone(),
        }
    }

    /// A transport on an externally held clock, so the script itself can move
    /// time while it answers.
    pub fn with_clock(clock: Clock, handler: impl Fn(&Request, i64, i64) -> Reply + Send + Sync + 'static) -> Self {
        ScriptedIo {
            handler: Box::new(handler),
            log: Mutex::new(Vec::new()),
            wall: clock.wall,
            mono: clock.mono,
            gate: None,
        }
    }

    /// Every storage GET holds this gate until its whole burst has arrived;
    /// `Gate::max_live` then shows the planner's concurrency.
    pub fn with_gate(mut self, gate: Arc<Gate>) -> Self {
        self.gate = Some(gate);
        self
    }

    pub fn wall_now(&self) -> i64 {
        self.wall.load(Ordering::SeqCst)
    }

    pub fn mono_now(&self) -> i64 {
        self.mono.load(Ordering::SeqCst)
    }

    pub fn set_wall(&self, ms: i64) {
        self.wall.store(ms, Ordering::SeqCst);
    }

    pub fn advance_wall(&self, ms: i64) {
        self.wall.fetch_add(ms, Ordering::SeqCst);
    }

    pub fn set_mono(&self, ms: i64) {
        self.mono.store(ms, Ordering::SeqCst);
    }

    pub fn advance_mono(&self, ms: i64) {
        self.mono.fetch_add(ms, Ordering::SeqCst);
    }

    pub fn requests(&self) -> Vec<Recorded> {
        self.log.lock().unwrap().clone()
    }

    pub fn count(&self, pred: impl Fn(&Request) -> bool) -> usize {
        self.requests().iter().filter(|r| pred(&r.request)).count()
    }

    fn record(&self, request: Request) -> (i64, i64) {
        let (wall, mono) = (self.wall_now(), self.mono_now());
        self.log.lock().unwrap().push(Recorded {
            request,
            wall_ms: wall,
            mono_ms: mono,
        });
        (wall, mono)
    }
}

impl DirectIo for ScriptedIo {
    async fn api(&self, call: ApiCall) -> ApiReply {
        let request = Request::Api(call);
        let (wall, mono) = self.record(request.clone());
        match (self.handler)(&request, wall, mono) {
            Reply::Api(reply) => reply,
            other => panic!("the script answered an API call with {other:?}"),
        }
    }

    async fn storage_get(&self, url: &SignedUrl, expected_len: u64, total: Duration) -> StorageReply {
        if let Some(gate) = &self.gate {
            gate.arrive();
            gate.wait().await;
        }
        let request = Request::StorageGet {
            url: url.expose().to_string(),
            expected_len,
            total,
        };
        let (wall, mono) = self.record(request.clone());
        let reply = match (self.handler)(&request, wall, mono) {
            Reply::Storage(reply) => reply,
            other => panic!("the script answered a storage GET with {other:?}"),
        };
        if let Some(gate) = &self.gate {
            gate.depart();
        }
        reply
    }

    async fn storage_put(
        &self,
        url: &SignedUrl,
        body: Bytes,
        headers: &[(&'static str, String)],
        total: Duration,
    ) -> u16 {
        let request = Request::StoragePut {
            url: url.expose().to_string(),
            body,
            headers: headers.iter().map(|(k, v)| (k.to_string(), v.clone())).collect(),
            total,
        };
        let (wall, mono) = self.record(request.clone());
        match (self.handler)(&request, wall, mono) {
            Reply::Put(status) => status,
            other => panic!("the script answered a storage PUT with {other:?}"),
        }
    }

    async fn sleep(&self, d: Duration) {
        let ms = i64::try_from(d.as_millis()).unwrap_or(i64::MAX);
        self.wall.fetch_add(ms, Ordering::SeqCst);
        self.mono.fetch_add(ms, Ordering::SeqCst);
    }

    fn wall_ms(&self) -> i64 {
        self.wall_now()
    }

    fn mono_ms(&self) -> i64 {
        self.mono_now()
    }
}

#[derive(Debug, Default)]
struct GateState {
    live: usize,
    max_live: usize,
    released: bool,
    started: bool,
    wakers: Vec<Waker>,
}

/// A burst gate: the first storage GET of a burst starts a short timer; when
/// it fires every GET of the burst is released together. Enough for the
/// planner's concurrency to show without depending on the scheduler.
#[derive(Debug, Default)]
pub struct Gate {
    state: Mutex<GateState>,
}

impl Gate {
    pub fn new() -> Arc<Gate> {
        Arc::new(Gate::default())
    }

    /// The most storage GETs that were ever live at once.
    pub fn max_live(&self) -> usize {
        self.state.lock().unwrap().max_live
    }

    fn arrive(self: &Arc<Self>) {
        let mut state = self.state.lock().unwrap();
        state.live += 1;
        state.max_live = state.max_live.max(state.live);
        let start = !state.started;
        if start {
            state.started = true;
            state.released = false;
        }
        drop(state);
        if start {
            let gate = self.clone();
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(5));
                let mut state = gate.state.lock().unwrap();
                state.released = true;
                state.started = false;
                let wakers = std::mem::take(&mut state.wakers);
                drop(state);
                for waker in wakers {
                    waker.wake();
                }
            });
        }
    }

    async fn wait(&self) {
        std::future::poll_fn(|cx| {
            let mut state = self.state.lock().unwrap();
            if state.released {
                Poll::Ready(())
            } else {
                state.wakers.push(cx.waker().clone());
                Poll::Pending
            }
        })
        .await;
    }

    fn depart(&self) {
        let mut state = self.state.lock().unwrap();
        state.live = state.live.saturating_sub(1);
        if state.live == 0 && !state.started {
            state.released = false;
        }
    }
}
