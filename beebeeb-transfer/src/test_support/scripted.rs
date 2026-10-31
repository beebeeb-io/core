//! A transport that answers from a script (plan K2 tests).
//!
//! Every request is recorded with the virtual clocks at the moment it was
//! made, so a test can assert both what was asked and when. No socket is
//! opened: `wall` and `mono` advance only through the test's calls and
//! `sleep`. A reply can be made to arrive after a virtual delay, and a
//! `sleep` advances the clocks in steps to the nearest pending waiter, so a
//! reply that becomes due during a wait is observable before the wait ends.

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

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Which {
    Wall,
    Mono,
}

#[derive(Debug)]
struct Waiter {
    which: Which,
    target: i64,
    waker: Waker,
}

/// A handle on the scripted transport's virtual clocks, so a script can move
/// time while it answers (a link that expires during a suspend).
#[derive(Clone, Debug)]
pub struct Clock {
    wall: Arc<AtomicI64>,
    mono: Arc<AtomicI64>,
    waiters: Arc<Mutex<Vec<Waiter>>>,
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
            waiters: Arc::new(Mutex::new(Vec::new())),
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
        self.notify();
    }

    pub fn advance_wall(&self, ms: i64) {
        self.wall.fetch_add(ms, Ordering::SeqCst);
        self.notify();
    }

    pub fn set_mono(&self, ms: i64) {
        self.mono.store(ms, Ordering::SeqCst);
        self.notify();
    }

    pub fn advance_mono(&self, ms: i64) {
        self.mono.fetch_add(ms, Ordering::SeqCst);
        self.notify();
    }

    fn notify(&self) {
        let waiters = {
            let mut waiters = self.waiters.lock().unwrap();
            let (due, later): (Vec<_>, Vec<_>) = std::mem::take(&mut *waiters)
                .into_iter()
                .partition(|w| self.now(w.which) >= w.target);
            *waiters = later;
            due
        };
        for waiter in waiters {
            waiter.waker.wake();
        }
    }

    fn now(&self, which: Which) -> i64 {
        match which {
            Which::Wall => self.wall(),
            Which::Mono => self.mono(),
        }
    }

    fn register(&self, which: Which, target: i64, waker: Waker) {
        self.waiters.lock().unwrap().push(Waiter { which, target, waker });
    }

    /// The smallest positive step to the next waiter or to `target`.
    fn next_delta(&self, target: i64) -> i64 {
        let mut delta = (target - self.mono()).max(1);
        for waiter in self.waiters.lock().unwrap().iter() {
            let step = waiter.target - self.now(waiter.which);
            if step > 0 {
                delta = delta.min(step);
            }
        }
        delta
    }

    fn advance_both(&self, ms: i64) {
        self.wall.fetch_add(ms, Ordering::SeqCst);
        self.mono.fetch_add(ms, Ordering::SeqCst);
        self.notify();
    }

    async fn wait_until(&self, which: Which, target: i64) {
        let clock = self.clone();
        std::future::poll_fn(move |cx| {
            if clock.now(which) >= target {
                return Poll::Ready(());
            }
            clock.register(which, target, cx.waker().clone());
            Poll::Pending
        })
        .await;
    }
}

/// What a script answers: request plus the clocks at that moment.
pub type Handler = Box<dyn Fn(&Request, i64, i64) -> Reply + Send + Sync>;

/// The scripted transport.
pub struct ScriptedIo {
    handler: Handler,
    log: Mutex<Vec<Recorded>>,
    clock: Clock,
    gate: Option<Arc<Gate>>,
    /// Virtual delay before a storage GET answers, by chunk index; `None`
    /// matches every request, a `Some(index)` entry wins over it.
    delays: Vec<(Option<u32>, i64)>,
    /// Virtual delay before an API call answers.
    api_delay_ms: Option<i64>,
    /// Virtual delay before an API call whose path starts with this prefix
    /// answers; a match wins over `api_delay_ms`.
    api_delays: Vec<(String, i64)>,
}

impl ScriptedIo {
    pub fn new(handler: impl Fn(&Request, i64, i64) -> Reply + Send + Sync + 'static) -> Self {
        ScriptedIo {
            handler: Box::new(handler),
            log: Mutex::new(Vec::new()),
            clock: Clock::new(),
            gate: None,
            delays: Vec::new(),
            api_delay_ms: None,
            api_delays: Vec::new(),
        }
    }

    /// The same clocks this transport uses, for a script that moves time.
    pub fn clock(&self) -> Clock {
        self.clock.clone()
    }

    /// A transport on an externally held clock, so the script itself can move
    /// time while it answers.
    pub fn with_clock(clock: Clock, handler: impl Fn(&Request, i64, i64) -> Reply + Send + Sync + 'static) -> Self {
        ScriptedIo {
            handler: Box::new(handler),
            log: Mutex::new(Vec::new()),
            clock,
            gate: None,
            delays: Vec::new(),
            api_delay_ms: None,
            api_delays: Vec::new(),
        }
    }

    /// Every storage GET holds this gate until its whole burst has arrived;
    /// `Gate::max_live` then shows the planner's concurrency.
    pub fn with_gate(mut self, gate: Arc<Gate>) -> Self {
        self.gate = Some(gate);
        self
    }

    /// Every API call answers after this much virtual time.
    pub fn with_api_delay(mut self, ms: i64) -> Self {
        self.api_delay_ms = Some(ms);
        self
    }

    /// API calls whose path starts with `prefix` answer after `ms` of virtual
    /// time, even when a global API delay is set.
    pub fn with_api_delay_for(mut self, prefix: impl Into<String>, ms: i64) -> Self {
        self.api_delays.push((prefix.into(), ms));
        self
    }

    /// Every storage GET answers after this much virtual time.
    pub fn with_storage_delay(mut self, ms: i64) -> Self {
        self.delays.push((None, ms));
        self
    }

    /// A named chunk's storage GET answers after `ms` of virtual time.
    pub fn with_storage_delay_for(mut self, index: u32, ms: i64) -> Self {
        self.delays.push((Some(index), ms));
        self
    }

    fn delay_for(&self, url: &str) -> Option<i64> {
        let index = url
            .split_once("i=")
            .map(|(_, rest)| rest.split('&').next().unwrap_or(rest))
            .and_then(|v| v.parse::<u32>().ok());
        self.delays
            .iter()
            .find(|(which, _)| *which == index)
            .or_else(|| self.delays.iter().find(|(which, _)| which.is_none()))
            .map(|(_, ms)| *ms)
    }

    pub fn wall_now(&self) -> i64 {
        self.clock.wall()
    }

    pub fn mono_now(&self) -> i64 {
        self.clock.mono()
    }

    pub fn set_wall(&self, ms: i64) {
        self.clock.set_wall(ms);
    }

    pub fn advance_wall(&self, ms: i64) {
        self.clock.advance_wall(ms);
    }

    pub fn set_mono(&self, ms: i64) {
        self.clock.set_mono(ms);
    }

    pub fn advance_mono(&self, ms: i64) {
        self.clock.advance_mono(ms);
    }

    pub fn requests(&self) -> Vec<Recorded> {
        self.log.lock().unwrap().clone()
    }

    pub fn count(&self, pred: impl Fn(&Request) -> bool) -> usize {
        self.requests().iter().filter(|r| pred(&r.request)).count()
    }

    fn record(&self, request: Request) -> (i64, i64) {
        let (wall, mono) = (self.clock.wall(), self.clock.mono());
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
        let path_delay = self
            .api_delays
            .iter()
            .find(|(prefix, _)| call.path.starts_with(prefix))
            .map(|(_, ms)| *ms);
        let request = Request::Api(call);
        let (wall, mono) = self.record(request.clone());
        if let Some(delay) = path_delay.or(self.api_delay_ms) {
            self.clock.wait_until(Which::Mono, mono + delay).await;
        }
        match (self.handler)(&request, wall, mono) {
            Reply::Api(reply) => reply,
            other => panic!("the script answered an API call with {other:?}"),
        }
    }

    async fn storage_get(
        &self,
        url: &SignedUrl,
        expected_len: u64,
        total: Duration,
        _idle: Duration,
        _connect: Duration,
    ) -> StorageReply {
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
        let url = url.expose().to_string();
        if let Some(delay) = self.delay_for(&url) {
            self.clock.wait_until(Which::Mono, mono + delay).await;
        }
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
        let target = self.clock.mono() + ms;
        if self.clock.mono() >= target {
            return;
        }
        // Advance to the nearest pending waiter, or to the target when no
        // waiter comes sooner. Stopping at a waiter lets the driver poll the
        // tasks at the moment their reply is due, then continue the nap.
        let delta = self.clock.next_delta(target);
        self.clock.advance_both(delta);
    }

    fn wall_ms(&self) -> i64 {
        self.clock.wall()
    }

    fn mono_ms(&self) -> i64 {
        self.clock.mono()
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
