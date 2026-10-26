//! Cross-client contract vectors for [`crate::direct_transfer`] (task 2173).
//!
//! `test-vectors/direct_transfer.json` is hand-authored from the spec (R1.6,
//! R1.12, R1.13, R2.6 and the core #33 review): the expected answer of every
//! row is what the CONTRACT says, not what the code printed. This module is the
//! one interpreter of that file. Every surface that exports the rules (core
//! itself, the WASM bindings, the UniFFI bindings, later the web and mobile test
//! suites) implements [`Surface`] over its own exported functions and calls
//! [`run_all`], so a binding cannot drift from core: both execute the same rows
//! through their own public API.
//!
//! Test-support only (`feature = "test-support"` or `cfg(test)`); never in a
//! shipped build.

use serde_json::{Value, json};

use super::{
    ApiAnswer, Call, DirectHealth, Direction, Discovery, DiscoveryCache, DiscoveryState, DownloadPlanner, Geometry,
    Lookup, Outcome, PinnedRetry, PlannerConfig, Poll, RecordedTransport, RetryDecision, Terminal, WindowAnswer,
    check_storage_url, classify, redact, resume_transport, scrub,
};

const API_PROD: &str = "https://api.beebeeb.test";
const API_DEV: &str = "http://127.0.0.1:3001";

/// The vectors file, embedded.
pub const VECTORS_JSON: &str = include_str!("../../../test-vectors/direct_transfer.json");

/// The API base a row names. An unknown one is a broken row, not "the dev one".
fn api_base_of(named: &str, row: &str) -> &'static str {
    match named {
        API_PROD => API_PROD,
        API_DEV => API_DEV,
        other => panic!("authority row {row:?}: unknown api_base {other:?}"),
    }
}

/// A surface the rules are exported through. Values cross as `serde_json`
/// values shaped like the file; failures cross as the stable `code` strings.
pub trait Surface {
    type Planner: PlannerSurface;
    type Cache: CacheSurface;
    type Health: HealthSurface;

    fn check_storage_url(&self, url: &str, discovery: &Value, api_base: &str) -> Result<(), String>;
    fn classify(
        &self,
        call: &str,
        status: u16,
        content_type: Option<&str>,
        body: &[u8],
        retry_after: Option<&str>,
    ) -> Value;
    fn redact(&self, input: &str) -> String;
    fn scrub(&self, input: &str) -> String;
    /// [`PinnedRetry::decide`] with the default policy: `outcome` is `{kind, millis?, ...}`, the
    /// answer `{kind: "wait", millis}` or `{kind: "give_up"}`.
    fn pinned_retry(&self, outcome: &Value, attempt: u32, waited_ms: u64) -> Value;
    fn chunk_length(&self, chunk_count: u32, chunk_size: u64, encrypted_size: u64, index: u32) -> Option<u64>;
    fn planner(&self, discovery: &Value, api_base: &str, file_id: &str, seed: u64) -> Self::Planner;
    fn cache(&self) -> Self::Cache;
    fn health(&self) -> Self::Health;
    /// [`resume_transport`]: `recorded` is `"api"` or `"direct"`, `discovery` is `{kind, upload?}` with `kind` one of
    /// `offers`, `not_supported`, `unknown`, `unauthorized`; the answer is the action's code.
    fn resume_transport(&self, recorded: &str, discovery: &Value, forced_api: bool) -> String;
}

/// The give-up memory as a surface exports it. Directions cross as their codes (`"download"`, `"upload"`).
pub trait HealthSurface {
    fn gave_up(&mut self, direction: &str, now_ms: i64);
    fn may_start(&self, direction: &str, now_ms: i64) -> bool;
    fn may_start_file(&self, direction: &str, now_ms: i64, file_gave_up: bool) -> bool;
    fn last_gave_up_ms(&self, direction: &str) -> Option<i64>;
    fn restore(&mut self, direction: &str, last_gave_up_ms: i64);
}

/// The discovery cache as a surface exports it.
pub trait CacheSurface {
    /// `"fetch"`, `"cached"` or `"use_api"`.
    fn lookup(&self, now_ms: i64) -> String;
    /// `outcome` is `{kind, ...}`; `body` is the discovery answer's body, as the client read it.
    fn record(&mut self, outcome: &Value, body: Option<&[u8]>, now_ms: i64);
}

/// The planner as a surface exports it.
pub trait PlannerSurface {
    /// The poll result as `{kind, ...}` (see [`poll_json`]).
    fn poll(&mut self, now_ms: i64) -> Value;
    /// The raw 2xx body of the outstanding window request. `Ok` when the window was
    /// accepted; else the code: `malformed` (not the contract's JSON) or a violation.
    fn window_answered(&mut self, body: &[u8], now_ms: i64) -> Result<(), String>;
    /// `outcome` is `{kind, millis?, status?, error?}`.
    fn window_failed(&mut self, outcome: &Value, now_ms: i64);
    fn window_malformed(&mut self);
    fn fetch_ok(&mut self, index: u32) -> Result<(), String>;
    fn fetch_failed(&mut self, index: u32, now_ms: i64) -> Result<(), String>;
    fn api_fetch_failed(&mut self, index: u32) -> Result<(), String>;
    fn chunk_unauthentic(&mut self, index: u32) -> Result<(), String>;
    fn consumed(&mut self, index: u32) -> Result<(), String>;
    /// What the planner reports about itself, as [`inspect_json`].
    fn inspect(&self) -> Value;
    /// Set the byte ceiling on held chunks (`PlannerConfig::max_in_flight_bytes`) before the first poll.
    fn set_max_in_flight_bytes(&mut self, bytes: u64);
    /// Did the storage breaker trip?
    fn storage_given_up(&self) -> bool;
}

/// How many rows of each kind ran. A runner asserts these equal the file's
/// counts, so a section that was skipped is a failure, not a pass.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Report {
    pub authority: usize,
    pub classify: usize,
    pub redact: usize,
    pub scrub: usize,
    pub chunk_length: usize,
    pub pinned_retry: usize,
    pub cache_scenarios: usize,
    pub cache_steps: usize,
    pub scenarios: usize,
    pub steps: usize,
    pub refusals: usize,
    pub health_scenarios: usize,
    pub health_steps: usize,
    pub resume_transport: usize,
}

/// The counts the file itself contains.
pub fn expected_report() -> Report {
    let v = vectors();
    let len = |k: &str| v[k].as_array().map_or(0, Vec::len);
    let mut r = Report {
        authority: len("authority"),
        classify: len("classify"),
        redact: len("redact"),
        scrub: len("scrub"),
        chunk_length: len("chunk_length"),
        pinned_retry: len("pinned_retry"),
        cache_scenarios: len("discovery_cache"),
        scenarios: len("planner"),
        health_scenarios: len("health"),
        resume_transport: len("resume_transport"),
        ..Report::default()
    };
    for s in v["health"].as_array().into_iter().flatten() {
        r.health_steps += s["steps"].as_array().map_or(0, Vec::len);
    }
    for s in v["discovery_cache"].as_array().into_iter().flatten() {
        r.cache_steps += s["steps"].as_array().map_or(0, Vec::len);
    }
    for s in v["planner"].as_array().into_iter().flatten() {
        r.steps += s["steps"].as_array().map_or(0, Vec::len);
        r.refusals += s["refusals"].as_array().map_or(0, Vec::len);
    }
    r
}

pub fn vectors() -> Value {
    serde_json::from_str(VECTORS_JSON).expect("the vectors file is valid JSON")
}

/// A surface that returns numbers as `f64` (the WASM convention) normalises them
/// before comparison: an integral float becomes an integer, recursively.
pub fn normalize_numbers(v: Value) -> Value {
    match v {
        Value::Number(n) => match n.as_f64() {
            Some(f) if n.is_f64() && f.fract() == 0.0 && f.abs() < 9_007_199_254_740_992.0 => json!(f as i64),
            _ => Value::Number(n),
        },
        Value::Array(a) => Value::Array(a.into_iter().map(normalize_numbers).collect()),
        Value::Object(o) => Value::Object(o.into_iter().map(|(k, v)| (k, normalize_numbers(v))).collect()),
        other => other,
    }
}

/// A number written as a JSON number or, beyond 2^53, as a decimal string.
fn as_u64(v: &Value) -> u64 {
    match v {
        Value::String(s) => s.parse().expect("decimal u64"),
        other => other.as_u64().expect("u64"),
    }
}

/// Run every row of the file through `surface`. Panics (with the row's name) on the first mismatch.
pub fn run_all<S: Surface>(surface: &S) -> Report {
    let v = vectors();
    let mut report = Report::default();

    for row in v["authority"].as_array().expect("authority") {
        let name = row["name"].as_str().unwrap();
        let api = api_base_of(row["api_base"].as_str().unwrap(), name);
        let disc = &v["discoveries"][row["discovery"].as_str().unwrap()];
        let got = surface.check_storage_url(row["url"].as_str().unwrap(), disc, api);
        let want = row["expect"].as_str().unwrap();
        match (&got, want) {
            (Ok(()), "ok") => {}
            (Err(code), want) if code == want => {}
            _ => panic!("authority row {name:?}: expected {want}, got {got:?}"),
        }
        report.authority += 1;
    }

    for row in v["classify"].as_array().expect("classify") {
        let name = row["name"].as_str().unwrap();
        let got = surface.classify(
            row["call"].as_str().unwrap(),
            row["status"].as_u64().unwrap() as u16,
            row["content_type"].as_str(),
            row["body"].as_str().unwrap().as_bytes(),
            row["retry_after"].as_str(),
        );
        let want = &row["expect"];
        for key in ["kind", "millis", "status", "error"] {
            assert_eq!(
                got.get(key),
                want.get(key),
                "classify row {name:?}: field {key} (got {got})"
            );
        }
        report.classify += 1;
    }

    for row in v["redact"].as_array().expect("redact") {
        assert_eq!(
            surface.redact(row["input"].as_str().unwrap()),
            row["expect"].as_str().unwrap(),
            "redact {row}"
        );
        report.redact += 1;
    }
    for row in v["scrub"].as_array().expect("scrub") {
        assert_eq!(
            surface.scrub(row["input"].as_str().unwrap()),
            row["expect"].as_str().unwrap(),
            "scrub {row}"
        );
        report.scrub += 1;
    }
    for row in v["chunk_length"].as_array().expect("chunk_length") {
        let got = surface.chunk_length(
            row["chunk_count"].as_u64().unwrap() as u32,
            as_u64(&row["chunk_size"]),
            as_u64(&row["encrypted_size"]),
            row["index"].as_u64().unwrap() as u32,
        );
        let want = row["expect"].as_u64();
        assert_eq!(got, want, "chunk_length row {:?}", row["name"]);
        report.chunk_length += 1;
    }

    for row in v["pinned_retry"].as_array().expect("pinned_retry") {
        let got = surface.pinned_retry(
            &row["outcome"],
            row["attempt"].as_u64().unwrap() as u32,
            as_u64(&row["waited_ms"]),
        );
        assert_eq!(got, row["expect"], "pinned_retry row {:?}", row["name"]);
        report.pinned_retry += 1;
    }

    for scenario in v["discovery_cache"].as_array().expect("discovery_cache") {
        let name = scenario["name"].as_str().unwrap();
        let mut cache = surface.cache();
        for (i, step) in scenario["steps"].as_array().unwrap().iter().enumerate() {
            let now = step["now"].as_i64().unwrap();
            match step["op"].as_str().unwrap() {
                "lookup" => assert_eq!(
                    cache.lookup(now),
                    step["expect"].as_str().unwrap(),
                    "cache scenario {name:?}, step {i} {step}"
                ),
                "record" => {
                    let body: Option<Vec<u8>> = match step["body"].as_str() {
                        None => None,
                        // `@name`: that discovery document; anything else is sent as it is.
                        Some(name) if name.starts_with('@') => {
                            Some(serde_json::to_vec(&v["discoveries"][&name[1..]]).expect("discovery"))
                        }
                        Some(raw) => Some(raw.as_bytes().to_vec()),
                    };
                    cache.record(&step["outcome"], body.as_deref(), now);
                }
                other => panic!("unknown cache op {other}"),
            }
            report.cache_steps += 1;
        }
        report.cache_scenarios += 1;
    }

    for scenario in v["health"].as_array().expect("health") {
        let name = scenario["name"].as_str().unwrap();
        let mut health = surface.health();
        for (i, step) in scenario["steps"].as_array().unwrap().iter().enumerate() {
            run_health_step(&mut health, step)
                .unwrap_or_else(|e| panic!("health scenario {name:?}, step {i} {step}: {e}"));
            report.health_steps += 1;
        }
        report.health_scenarios += 1;
    }

    for row in v["resume_transport"].as_array().expect("resume_transport") {
        let got = surface.resume_transport(
            row["recorded"].as_str().unwrap(),
            &row["discovery"],
            row["forced_api"].as_bool().unwrap(),
        );
        assert_eq!(
            got,
            row["expect"].as_str().unwrap(),
            "resume_transport row {:?}",
            row["name"]
        );
        report.resume_transport += 1;
    }

    let file_id = v["file_id"].as_str().unwrap();
    for scenario in v["planner"].as_array().expect("planner") {
        let name = scenario["name"].as_str().unwrap();
        let disc = &v["discoveries"][scenario["discovery"].as_str().unwrap()];
        let seed = scenario["seed"].as_u64().unwrap();
        for refusal in scenario["refusals"].as_array().into_iter().flatten() {
            let mut p = surface.planner(disc, API_PROD, file_id, seed);
            let first = p.poll(vectors_t0(&v));
            assert_eq!(
                first["kind"], "request_window",
                "{name}: the first poll asks for a window"
            );
            let got = p.window_answered(&body_bytes(refusal), vectors_t0(&v));
            assert_eq!(
                got,
                Err(refusal["expect"].as_str().unwrap().to_string()),
                "{name}: {}",
                refusal["name"]
            );
            report.refusals += 1;
        }
        if let Some(steps) = scenario["steps"].as_array() {
            let mut p = surface.planner(disc, API_PROD, file_id, seed);
            if let Some(bytes) = scenario.get("max_in_flight_bytes") {
                p.set_max_in_flight_bytes(as_u64(bytes));
            }
            for (i, step) in steps.iter().enumerate() {
                run_step(&mut p, step).unwrap_or_else(|e| panic!("scenario {name:?}, step {i} {step}: {e}"));
                report.steps += 1;
            }
        }
        report.scenarios += 1;
    }
    report
}

/// The body of a window answer: a JSON `response` is serialised, a `body` string is sent as it is
/// (so a row can be something that is not the contract's JSON at all).
fn body_bytes(row: &Value) -> Vec<u8> {
    match row["body"].as_str() {
        Some(raw) => raw.as_bytes().to_vec(),
        None => serde_json::to_vec(&row["response"]).expect("a response row serialises"),
    }
}

fn vectors_t0(v: &Value) -> i64 {
    v["t0_ms"].as_i64().unwrap()
}

/// One step of a health scenario. `expect` is a bool for `may_start*` and a number or null for `last_gave_up`.
fn run_health_step<H: HealthSurface>(h: &mut H, step: &Value) -> Result<(), String> {
    let direction = step["direction"].as_str().ok_or("no direction")?;
    // `now` is mandatory for every op that reads the clock: a typo must fail the step, not become 0.
    let now = || step["now"].as_i64().ok_or("no `now` (a number)");
    match step["op"].as_str().unwrap() {
        "gave_up" => h.gave_up(direction, now()?),
        "restore" => h.restore(direction, step["ms"].as_i64().ok_or("no ms")?),
        "may_start" => {
            let got = h.may_start(direction, now()?);
            if Some(got) != step["expect"].as_bool() {
                return Err(format!("expected {}, got {got}", step["expect"]));
            }
        }
        "may_start_file" => {
            let got = h.may_start_file(
                direction,
                now()?,
                step["file_gave_up"].as_bool().ok_or("no file_gave_up")?,
            );
            if Some(got) != step["expect"].as_bool() {
                return Err(format!("expected {}, got {got}", step["expect"]));
            }
        }
        "last_gave_up" => {
            let got = h.last_gave_up_ms(direction);
            // `expect` is mandatory: a number, or an explicit null for "nothing recorded".
            let want = match step.get("expect") {
                Some(Value::Null) => None,
                Some(v) => Some(v.as_i64().ok_or("`expect` is neither a number nor null")?),
                None => return Err("no `expect` (a number, or null)".to_string()),
            };
            if got != want {
                return Err(format!("expected {want:?}, got {got:?}"));
            }
        }
        other => return Err(format!("unknown health op {other}")),
    }
    Ok(())
}

fn run_step<P: PlannerSurface>(p: &mut P, step: &Value) -> Result<(), String> {
    let now = step["now"].as_i64().unwrap_or(0);
    let index = step["index"].as_u64().unwrap_or(0) as u32;
    let expect = |got: Result<(), String>| -> Result<(), String> {
        let want = step["expect"].as_str().unwrap_or("ok");
        match (got, want) {
            (Ok(()), "ok") => Ok(()),
            (Err(code), want) if code == want => Ok(()),
            (got, want) => Err(format!("expected {want}, got {got:?}")),
        }
    };
    match step["op"].as_str().unwrap() {
        "poll" => {
            let got = p.poll(now);
            let want = &step["expect"];
            if let Some(range) = want.get("until_ms_between") {
                let (lo, hi) = (range[0].as_i64().unwrap(), range[1].as_i64().unwrap());
                let until = got["until_ms"]
                    .as_i64()
                    .ok_or_else(|| format!("no wait deadline in {got}"))?;
                if got["kind"] != "wait" || !(lo..=hi).contains(&until) {
                    return Err(format!("expected a wait ending in {lo}..={hi}, got {got}"));
                }
                return Ok(());
            }
            if &got == want {
                Ok(())
            } else {
                Err(format!("expected {want}, got {got}"))
            }
        }
        "window_answered" => expect(p.window_answered(&body_bytes(step), now)),
        "window_failed" => {
            p.window_failed(&step["outcome"], now);
            Ok(())
        }
        "window_malformed" => {
            p.window_malformed();
            Ok(())
        }
        "fetch_ok" => expect(p.fetch_ok(index)),
        "fetch_failed" => expect(p.fetch_failed(index, now)),
        "api_fetch_failed" => expect(p.api_fetch_failed(index)),
        "chunk_unauthentic" => expect(p.chunk_unauthentic(index)),
        "consumed" => expect(p.consumed(index)),
        "storage_given_up" => {
            let got = p.storage_given_up();
            if Some(got) == step["expect"].as_bool() {
                Ok(())
            } else {
                Err(format!("expected storage_given_up {}, got {got}", step["expect"]))
            }
        }
        "inspect" => {
            let got = p.inspect();
            if got == step["expect"] {
                Ok(())
            } else {
                Err(format!("expected {}, got {got}", step["expect"]))
            }
        }
        other => Err(format!("unknown op {other}")),
    }
}

// ─────────────────────────── core's own surface ───────────────────────────

/// Core, called directly: the reference the other surfaces are held to.
pub struct CoreSurface;

/// `{kind, ...}` for a poll result: the shape every surface returns.
pub fn poll_json(poll: &Poll) -> Value {
    match poll {
        Poll::RequestWindow(r) => json!({"kind": poll.kind(), "request": {
            "object_version_id": r.object_version_id, "start_index": r.start_index,
            "count": r.count, "renewal": r.renewal}}),
        Poll::Fetch { index, grant } => {
            json!({"kind": poll.kind(), "index": index, "url": grant.url, "length": grant.length})
        }
        Poll::FetchViaApi {
            index,
            object_version_id,
        } => json!({"kind": poll.kind(), "index": index, "object_version_id": object_version_id}),
        Poll::Wait { until_ms } => json!({"kind": poll.kind(), "until_ms": until_ms}),
        Poll::Done => json!({"kind": poll.kind()}),
        Poll::Stop(v) => {
            let mut verdict = json!({"kind": v.kind()});
            if let super::Verdict::Terminal(t) = v {
                verdict["status"] = json!(t.status);
                verdict["error"] = json!(t.error);
            }
            json!({"kind": poll.kind(), "verdict": verdict})
        }
    }
}

/// `{kind, millis?, status?, error?}` for an outcome.
pub fn outcome_json(outcome: &Outcome) -> Value {
    let mut v = json!({"kind": outcome.kind()});
    match outcome {
        Outcome::Backoff(d) => v["millis"] = json!(d.as_millis() as u64),
        // The server's stated wait, or null when it sent none.
        Outcome::Held(d) => v["millis"] = json!(d.map(|d| d.as_millis() as u64)),
        Outcome::Terminal(t) => {
            v["status"] = json!(t.status);
            v["error"] = json!(t.error);
        }
        _ => {}
    }
    v
}

/// The inverse of [`outcome_json`] for the kinds a window failure can carry.
pub fn outcome_from_json(v: &Value) -> Outcome {
    match v["kind"].as_str().unwrap() {
        "proceed" => Outcome::Proceed,
        "not_supported" => Outcome::NotSupported,
        "use_api_now" => Outcome::UseApiNow,
        "api_for_this_file" => Outcome::ApiForThisFile,
        "restart" => Outcome::Restart,
        "retry" => Outcome::Retry,
        "regrant" => Outcome::Regrant,
        // `millis` is the server's stated wait, or null when it sent none.
        "held" => Outcome::Held(v["millis"].as_u64().map(std::time::Duration::from_millis)),
        "backoff" => Outcome::Backoff(std::time::Duration::from_millis(v["millis"].as_u64().unwrap())),
        "terminal" => Outcome::Terminal(Terminal {
            status: v["status"].as_u64().unwrap() as u16,
            error: v["error"].as_str().map(str::to_string),
        }),
        other => panic!("unknown outcome kind {other}"),
    }
}

/// `{kind: "wait", millis}` or `{kind: "give_up"}` for a retry decision.
pub fn decision_json(decision: &RetryDecision) -> Value {
    match decision {
        RetryDecision::Wait(d) => json!({"kind": decision.kind(), "millis": d.as_millis() as u64}),
        RetryDecision::GiveUp => json!({"kind": decision.kind()}),
    }
}

/// `{geometry, pinned_version, consumed, in_flight}`: the planner's state as every surface reports it.
pub fn inspect_json(p: &DownloadPlanner) -> Value {
    json!({
        "geometry": p.geometry().map(|g| json!({
            "chunk_count": g.chunk_count, "chunk_size": g.chunk_size,
            "encrypted_size": g.encrypted_size, "original_size": g.original_size})),
        "pinned_version": p.pinned_version(),
        "consumed": p.consumed_count(),
        "in_flight": p.in_flight(),
    })
}

impl PlannerSurface for DownloadPlanner {
    fn poll(&mut self, now_ms: i64) -> Value {
        poll_json(&DownloadPlanner::poll(self, now_ms))
    }
    fn window_answered(&mut self, body: &[u8], now_ms: i64) -> Result<(), String> {
        match DownloadPlanner::window_answered_bytes(self, body, now_ms) {
            WindowAnswer::Accepted => Ok(()),
            other => Err(other.code().to_string()),
        }
    }
    fn window_failed(&mut self, outcome: &Value, now_ms: i64) {
        DownloadPlanner::window_failed(self, outcome_from_json(outcome), now_ms);
    }
    fn window_malformed(&mut self) {
        DownloadPlanner::window_malformed(self);
    }
    fn fetch_ok(&mut self, index: u32) -> Result<(), String> {
        DownloadPlanner::fetch_ok(self, index).map_err(|e| e.code().to_string())
    }
    fn fetch_failed(&mut self, index: u32, now_ms: i64) -> Result<(), String> {
        DownloadPlanner::fetch_failed(self, index, now_ms).map_err(|e| e.code().to_string())
    }
    fn api_fetch_failed(&mut self, index: u32) -> Result<(), String> {
        DownloadPlanner::api_fetch_failed(self, index).map_err(|e| e.code().to_string())
    }
    fn chunk_unauthentic(&mut self, index: u32) -> Result<(), String> {
        DownloadPlanner::chunk_unauthentic(self, index).map_err(|e| e.code().to_string())
    }
    fn consumed(&mut self, index: u32) -> Result<(), String> {
        DownloadPlanner::consumed(self, index).map_err(|e| e.code().to_string())
    }
    fn inspect(&self) -> Value {
        inspect_json(self)
    }
    fn set_max_in_flight_bytes(&mut self, bytes: u64) {
        DownloadPlanner::set_max_in_flight_bytes(self, Some(bytes));
    }
    fn storage_given_up(&self) -> bool {
        DownloadPlanner::storage_given_up(self)
    }
}

fn direction_of(code: &str) -> Direction {
    Direction::from_code(code).unwrap_or_else(|| panic!("unknown direction {code:?}"))
}

impl HealthSurface for DirectHealth {
    fn gave_up(&mut self, direction: &str, now_ms: i64) {
        DirectHealth::gave_up(self, direction_of(direction), now_ms);
    }
    fn may_start(&self, direction: &str, now_ms: i64) -> bool {
        DirectHealth::may_start(self, direction_of(direction), now_ms)
    }
    fn may_start_file(&self, direction: &str, now_ms: i64, file_gave_up: bool) -> bool {
        DirectHealth::may_start_file(self, direction_of(direction), now_ms, file_gave_up)
    }
    fn last_gave_up_ms(&self, direction: &str) -> Option<i64> {
        DirectHealth::last_gave_up_ms(self, direction_of(direction))
    }
    fn restore(&mut self, direction: &str, last_gave_up_ms: i64) {
        DirectHealth::restore(self, direction_of(direction), last_gave_up_ms);
    }
}

/// The discovery state a row names: `{kind, upload?}`.
pub fn discovery_state_from_json(v: &Value) -> DiscoveryState {
    DiscoveryState::from_parts(v["kind"].as_str().unwrap(), v["upload"].as_bool())
        .unwrap_or_else(|| panic!("unknown discovery state {v}"))
}

impl CacheSurface for DiscoveryCache {
    fn lookup(&self, now_ms: i64) -> String {
        match DiscoveryCache::lookup(self, now_ms) {
            Lookup::Fetch => "fetch",
            Lookup::Cached(_) => "cached",
            Lookup::UseApi => "use_api",
        }
        .to_string()
    }
    fn record(&mut self, outcome: &Value, body: Option<&[u8]>, now_ms: i64) {
        let discovery = body.and_then(|b| Discovery::from_json(b).ok());
        DiscoveryCache::record(self, &outcome_from_json(outcome), discovery, now_ms);
    }
}

impl Surface for CoreSurface {
    type Planner = DownloadPlanner;
    type Cache = DiscoveryCache;
    type Health = DirectHealth;

    fn check_storage_url(&self, url: &str, discovery: &Value, api_base: &str) -> Result<(), String> {
        let d: Discovery = serde_json::from_value(discovery.clone()).map_err(|e| e.to_string())?;
        check_storage_url(url, &d, api_base).map_err(|r| r.code().to_string())
    }
    fn classify(
        &self,
        call: &str,
        status: u16,
        content_type: Option<&str>,
        body: &[u8],
        retry_after: Option<&str>,
    ) -> Value {
        let answer = ApiAnswer::from_parts(status, content_type, body, retry_after);
        outcome_json(&classify(Call::from_code(call).expect("known call"), &answer))
    }
    fn redact(&self, input: &str) -> String {
        redact(input)
    }
    fn scrub(&self, input: &str) -> String {
        scrub(input)
    }
    fn pinned_retry(&self, outcome: &Value, attempt: u32, waited_ms: u64) -> Value {
        decision_json(&PinnedRetry::default().decide(
            attempt,
            std::time::Duration::from_millis(waited_ms),
            &outcome_from_json(outcome),
        ))
    }
    fn chunk_length(&self, chunk_count: u32, chunk_size: u64, encrypted_size: u64, index: u32) -> Option<u64> {
        Geometry {
            chunk_count,
            chunk_size,
            encrypted_size,
            original_size: 0,
        }
        .chunk_length(index)
    }
    fn planner(&self, discovery: &Value, api_base: &str, file_id: &str, seed: u64) -> DownloadPlanner {
        let d: Discovery = serde_json::from_value(discovery.clone()).expect("discovery");
        DownloadPlanner::new(PlannerConfig::from_discovery(&d, seed), d, api_base, file_id)
    }
    fn cache(&self) -> DiscoveryCache {
        DiscoveryCache::new()
    }
    fn health(&self) -> DirectHealth {
        DirectHealth::new()
    }
    fn resume_transport(&self, recorded: &str, discovery: &Value, forced_api: bool) -> String {
        resume_transport(
            RecordedTransport::from_code(recorded).unwrap_or_else(|| panic!("unknown recorded transport {recorded:?}")),
            discovery_state_from_json(discovery),
            forced_api,
        )
        .code()
        .to_string()
    }
}

#[cfg(test)]
mod tests {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    use super::*;

    /// Wraps core and changes ONE answer, to prove the runner goes red (a guard that has never
    /// failed is not trusted).
    struct Drift(&'static str);

    /// A cache that never expires (it reads every lookup as if no time had passed).
    struct StickyCache(DiscoveryCache, bool);

    impl CacheSurface for StickyCache {
        fn lookup(&self, now_ms: i64) -> String {
            CacheSurface::lookup(&self.0, if self.1 { 0 } else { now_ms })
        }
        fn record(&mut self, outcome: &Value, body: Option<&[u8]>, now_ms: i64) {
            CacheSurface::record(&mut self.0, outcome, body, now_ms)
        }
    }

    /// A health memory that drifts in ONE way: `"direction"` ignores the direction (one hold for both),
    /// `"file_bit"` ignores the file's own bit, `"future"` trusts a recorded time in the future.
    struct DriftingHealth(DirectHealth, &'static str);

    impl HealthSurface for DriftingHealth {
        fn gave_up(&mut self, direction: &str, now_ms: i64) {
            let direction = if self.1 == "direction" { "download" } else { direction };
            HealthSurface::gave_up(&mut self.0, direction, now_ms)
        }
        fn may_start(&self, direction: &str, now_ms: i64) -> bool {
            let direction = if self.1 == "direction" { "download" } else { direction };
            if self.1 == "future"
                && self
                    .0
                    .last_gave_up_ms(direction_of(direction))
                    .is_some_and(|at| at > now_ms)
            {
                return false;
            }
            HealthSurface::may_start(&self.0, direction, now_ms)
        }
        fn may_start_file(&self, direction: &str, now_ms: i64, file_gave_up: bool) -> bool {
            let file_gave_up = file_gave_up && self.1 != "file_bit";
            HealthSurface::may_start_file(&self.0, direction, now_ms, file_gave_up)
        }
        fn last_gave_up_ms(&self, direction: &str) -> Option<i64> {
            HealthSurface::last_gave_up_ms(&self.0, direction)
        }
        fn restore(&mut self, direction: &str, ms: i64) {
            HealthSurface::restore(&mut self.0, direction, ms)
        }
    }

    impl Surface for Drift {
        type Planner = DownloadPlanner;
        type Cache = StickyCache;
        type Health = DriftingHealth;
        fn cache(&self) -> StickyCache {
            StickyCache(DiscoveryCache::new(), self.0 == "cache")
        }
        fn health(&self) -> DriftingHealth {
            DriftingHealth(DirectHealth::new(), self.0)
        }
        fn resume_transport(&self, recorded: &str, discovery: &Value, forced_api: bool) -> String {
            let got = CoreSurface.resume_transport(recorded, discovery, forced_api);
            // a binding that reads "could not be read" as a no
            if self.0 == "resume" && got == "keep_record_and_fail" {
                "abandon_to_api".to_string()
            } else {
                got
            }
        }
        fn check_storage_url(&self, url: &str, discovery: &Value, api_base: &str) -> Result<(), String> {
            if self.0 == "authority" && url.contains("evil.test") {
                return Ok(()); // a binding that lets an unlisted host through
            }
            CoreSurface.check_storage_url(url, discovery, api_base)
        }
        fn classify(&self, call: &str, status: u16, ct: Option<&str>, body: &[u8], ra: Option<&str>) -> Value {
            let mut v = CoreSurface.classify(call, status, ct, body, ra);
            if self.0 == "classify" && v["kind"] == "restart" {
                v["kind"] = json!("api_for_this_file");
            }
            if self.0 == "millis" && v["kind"] == "backoff" {
                v["millis"] = json!(v["millis"].as_u64().unwrap() + 1); // a binding that mangles the wait
            }
            v
        }
        fn redact(&self, input: &str) -> String {
            if self.0 == "redact" {
                input.split('?').next().unwrap().to_string()
            } else {
                CoreSurface.redact(input)
            }
        }
        fn scrub(&self, input: &str) -> String {
            CoreSurface.scrub(input)
        }
        fn pinned_retry(&self, outcome: &Value, attempt: u32, waited_ms: u64) -> Value {
            let mut v = CoreSurface.pinned_retry(outcome, attempt, waited_ms);
            if self.0 == "retry" && v["kind"] == "wait" {
                v["millis"] = json!(v["millis"].as_u64().unwrap() + 1); // a binding that mangles the wait
            }
            v
        }
        fn chunk_length(&self, n: u32, s: u64, e: u64, i: u32) -> Option<u64> {
            if self.0 == "geometry" {
                Some(0)
            } else {
                CoreSurface.chunk_length(n, s, e, i)
            }
        }
        fn planner(&self, d: &Value, api: &str, file: &str, seed: u64) -> DownloadPlanner {
            CoreSurface.planner(d, api, file, seed)
        }
    }

    /// A planner that drifts in ONE way: `"pin"` forgets the pin on renewals, `"inspect"` reports
    /// a wrong count of consumed chunks, `"breaker"` never reports the storage breaker, `"cap"` ignores the byte cap.
    struct ForgetfulPlanner(DownloadPlanner, &'static str);

    impl PlannerSurface for ForgetfulPlanner {
        fn poll(&mut self, now_ms: i64) -> Value {
            let mut v = PlannerSurface::poll(&mut self.0, now_ms);
            if self.1 == "pin" && v["kind"] == "request_window" && v["request"]["renewal"] == true {
                v["request"]["object_version_id"] = Value::Null;
            }
            v
        }
        fn window_answered(&mut self, b: &[u8], n: i64) -> Result<(), String> {
            PlannerSurface::window_answered(&mut self.0, b, n)
        }
        fn window_failed(&mut self, o: &Value, n: i64) {
            PlannerSurface::window_failed(&mut self.0, o, n)
        }
        fn window_malformed(&mut self) {
            PlannerSurface::window_malformed(&mut self.0)
        }
        fn fetch_ok(&mut self, i: u32) -> Result<(), String> {
            PlannerSurface::fetch_ok(&mut self.0, i)
        }
        fn fetch_failed(&mut self, i: u32, n: i64) -> Result<(), String> {
            PlannerSurface::fetch_failed(&mut self.0, i, n)
        }
        fn api_fetch_failed(&mut self, i: u32) -> Result<(), String> {
            PlannerSurface::api_fetch_failed(&mut self.0, i)
        }
        fn chunk_unauthentic(&mut self, i: u32) -> Result<(), String> {
            PlannerSurface::chunk_unauthentic(&mut self.0, i)
        }
        fn consumed(&mut self, i: u32) -> Result<(), String> {
            PlannerSurface::consumed(&mut self.0, i)
        }
        fn inspect(&self) -> Value {
            let mut v = PlannerSurface::inspect(&self.0);
            if self.1 == "inspect" {
                v["consumed"] = json!(v["consumed"].as_u64().unwrap() + 1);
            }
            v
        }
        fn set_max_in_flight_bytes(&mut self, bytes: u64) {
            if self.1 != "cap" {
                PlannerSurface::set_max_in_flight_bytes(&mut self.0, bytes);
            }
        }
        fn storage_given_up(&self) -> bool {
            self.1 != "breaker" && PlannerSurface::storage_given_up(&self.0)
        }
    }

    struct Forgetful(&'static str);

    impl Surface for Forgetful {
        type Planner = ForgetfulPlanner;
        type Cache = DiscoveryCache;
        type Health = DirectHealth;
        fn cache(&self) -> DiscoveryCache {
            DiscoveryCache::new()
        }
        fn health(&self) -> DirectHealth {
            DirectHealth::new()
        }
        fn resume_transport(&self, recorded: &str, discovery: &Value, forced_api: bool) -> String {
            CoreSurface.resume_transport(recorded, discovery, forced_api)
        }
        fn check_storage_url(&self, u: &str, d: &Value, a: &str) -> Result<(), String> {
            CoreSurface.check_storage_url(u, d, a)
        }
        fn classify(&self, c: &str, s: u16, ct: Option<&str>, b: &[u8], r: Option<&str>) -> Value {
            CoreSurface.classify(c, s, ct, b, r)
        }
        fn redact(&self, i: &str) -> String {
            CoreSurface.redact(i)
        }
        fn scrub(&self, i: &str) -> String {
            CoreSurface.scrub(i)
        }
        fn pinned_retry(&self, o: &Value, a: u32, w: u64) -> Value {
            CoreSurface.pinned_retry(o, a, w)
        }
        fn chunk_length(&self, n: u32, s: u64, e: u64, i: u32) -> Option<u64> {
            CoreSurface.chunk_length(n, s, e, i)
        }
        fn planner(&self, d: &Value, api: &str, file: &str, seed: u64) -> ForgetfulPlanner {
            ForgetfulPlanner(CoreSurface.planner(d, api, file, seed), self.0)
        }
    }

    #[test]
    fn core_runs_every_row_of_the_vectors() {
        let report = run_all(&CoreSurface);
        assert_eq!(report, expected_report(), "a section that did not run is a failure");
        // Counts, not adjectives: the file is not empty and the sections are what the review asked for.
        assert!(
            report.authority >= 59
                && report.classify >= 121
                && report.chunk_length >= 8
                && report.pinned_retry >= 20
                && report.cache_scenarios >= 9
                && report.cache_steps >= 45,
            "{report:?}"
        );
        assert!(
            report.scenarios >= 42 && report.steps >= 367 && report.refusals >= 21,
            "{report:?}"
        );
        assert!(
            report.health_scenarios >= 8 && report.health_steps >= 37 && report.resume_transport >= 20,
            "{report:?}"
        );
    }

    #[test]
    fn a_malformed_health_step_is_an_error_not_a_pass() {
        let mut h = DirectHealth::new();
        for step in [
            json!({"op": "gave_up", "direction": "upload"}), // no `now`
            json!({"op": "may_start", "direction": "upload", "expect": true}), // no `now`
            json!({"op": "may_start_file", "direction": "upload", "now": 1, "expect": true}), // no `file_gave_up`
            json!({"op": "last_gave_up", "direction": "upload"}), // no `expect`
            json!({"op": "last_gave_up", "direction": "upload", "expect": "none"}), // wrong type
            json!({"op": "may_start", "direction": "upload", "now": "1", "expect": true}), // `now` not a number
            json!({"op": "restore", "direction": "upload"}), // no `ms`
        ] {
            assert!(run_health_step(&mut h, &step).is_err(), "{step} must not pass");
        }
        // And a well-formed one still passes, including an explicit null for "nothing recorded".
        assert!(
            run_health_step(
                &mut h,
                &json!({"op": "last_gave_up", "direction": "upload", "expect": null})
            )
            .is_ok()
        );
    }

    #[test]
    fn an_unknown_api_base_is_a_broken_row_not_the_dev_one() {
        assert_eq!(api_base_of(API_PROD, "r"), API_PROD);
        assert_eq!(api_base_of(API_DEV, "r"), API_DEV);
        let result = catch_unwind(AssertUnwindSafe(|| api_base_of("https://api.example.invalid", "r")));
        assert!(result.is_err(), "an unknown api_base must fail the run");
    }

    #[test]
    fn every_row_has_a_distinct_name() {
        let v = vectors();
        for section in [
            "authority",
            "classify",
            "chunk_length",
            "pinned_retry",
            "discovery_cache",
            "planner",
            "health",
            "resume_transport",
        ] {
            let mut names: Vec<&str> = v[section]
                .as_array()
                .unwrap()
                .iter()
                .map(|r| r["name"].as_str().unwrap())
                .collect();
            let total = names.len();
            names.sort_unstable();
            names.dedup();
            assert_eq!(names.len(), total, "duplicate row name in {section}");
        }
    }

    #[test]
    fn the_runner_goes_red_when_a_surface_drifts() {
        for what in [
            "authority",
            "classify",
            "millis",
            "retry",
            "cache",
            "redact",
            "geometry",
            "direction",
            "file_bit",
            "future",
            "resume",
        ] {
            let result = catch_unwind(AssertUnwindSafe(|| run_all(&Drift(what))));
            assert!(
                result.is_err(),
                "a surface that drifted on {what} must fail the vectors"
            );
        }
        for what in ["pin", "inspect", "breaker", "cap"] {
            let result = catch_unwind(AssertUnwindSafe(|| run_all(&Forgetful(what))));
            assert!(result.is_err(), "a planner that drifts on {what} must fail the vectors");
        }
    }
}

/// The single event/action interpreter shared by native, WASM and UniFFI upload planners.
/// Surfaces cross their real JSON boundary here, so missing or renamed fields are observable.
pub trait PipelineSurface {
    fn on(&mut self, event_json: &str, now_ms: u64) -> Result<Value, String>;
    fn retained(&self) -> usize;
    fn is_done(&self) -> bool;
}

impl PipelineSurface for super::upload_pipeline::PipelinePlan {
    fn on(&mut self, event_json: &str, now_ms: u64) -> Result<Value, String> {
        let event = super::upload_pipeline::PipelineEvent::from_json(event_json)?;
        serde_json::to_value(self.on(event, now_ms)).map_err(|_| "invalid pipeline actions".into())
    }
    fn retained(&self) -> usize {
        self.retained()
    }
    fn is_done(&self) -> bool {
        self.is_done()
    }
}

pub const PIPELINE_VECTORS_JSON: &str = include_str!("../../../test-vectors/direct_upload_pipeline.json");

#[derive(Debug, PartialEq, Eq)]
pub struct PipelineReport {
    pub scenarios: usize,
    pub steps: usize,
    pub failures: Vec<String>,
}

pub fn expected_pipeline_report() -> PipelineReport {
    let v: Value = serde_json::from_str(PIPELINE_VECTORS_JSON).expect("pipeline vectors JSON");
    let rows = v["scenarios"].as_array().expect("scenarios");
    assert!(rows.len() >= 45, "non-vacuous scenario count");
    assert_eq!(v["scenario_count"].as_u64(), Some(rows.len() as u64));
    PipelineReport {
        scenarios: rows.len(),
        steps: rows.iter().map(|r| r["steps"].as_array().expect("steps").len()).sum(),
        failures: Vec::new(),
    }
}

pub fn run_pipeline_all<S: PipelineSurface>(
    make: impl Fn(u64, Vec<u64>, super::upload_pipeline::GrantVersion, super::UploadChunkPolicy) -> S,
) -> PipelineReport {
    use std::time::Duration;
    let v: Value = serde_json::from_str(PIPELINE_VECTORS_JSON).expect("pipeline vectors JSON");
    let mut report = PipelineReport {
        scenarios: 0,
        steps: 0,
        failures: Vec::new(),
    };
    let mut names = std::collections::BTreeSet::new();
    for row in v["scenarios"].as_array().expect("scenarios") {
        let name = row["name"].as_str().expect("scenario name");
        assert!(names.insert(name), "duplicate pipeline scenario {name}");
        assert!(
            row["source"]
                .as_str()
                .is_some_and(|s| s.starts_with("task 2173 pipelining design ")),
            "source for {name}"
        );
        let version = serde_json::from_value(row["version"].clone()).expect("grant version");
        let mut policy = super::UploadChunkPolicy::default();
        if let Some(p) = row.get("policy") {
            for (key, value) in p.as_object().expect("policy") {
                let n = value.as_u64().expect("policy integer");
                match key.as_str() {
                    "attempts" => policy.attempts = u32::try_from(n).expect("attempts u32"),
                    "max_grants" => policy.max_grants = u32::try_from(n).expect("max_grants u32"),
                    "budget_ms" => policy.budget = Duration::from_millis(n),
                    "hold_budget_ms" => policy.hold_budget = Duration::from_millis(n),
                    _ => panic!("unknown policy field {key}"),
                }
            }
        }
        let lengths = row["chunk_lens"]
            .as_array()
            .expect("chunk lengths")
            .iter()
            .map(|x| x.as_u64().expect("length u64"))
            .collect();
        let mut surface = make(
            row["chunk_size_bytes"].as_u64().expect("chunk size"),
            lengths,
            version,
            policy,
        );
        report.scenarios += 1;
        for (i, step) in row["steps"].as_array().expect("scenario steps").iter().enumerate() {
            report.steps += 1;
            let got = surface.on(&step["event"].to_string(), step["now_ms"].as_u64().expect("now_ms"));
            if got.as_ref().ok() != Some(&step["expect"]) {
                report
                    .failures
                    .push(format!("{name} step {i}: actions {got:?}, expected {}", step["expect"]));
                break;
            }
            if let Some(retained) = step.get("retained") {
                if Some(surface.retained() as u64) != retained.as_u64() {
                    report.failures.push(format!(
                        "{name} step {i}: retained {}, expected {retained}",
                        surface.retained()
                    ));
                    break;
                }
            }
            if surface.is_done() != step["done"].as_bool().expect("done") {
                report.failures.push(format!(
                    "{name} step {i}: done {}, expected {}",
                    surface.is_done(),
                    step["done"]
                ));
                break;
            }
        }
    }
    report
}
