//! The transport conformance suite (plan K2).
//!
//! A client's [`DirectIo`] must keep the storage-side contract, not just work
//! against a happy server: a credential on the API call but never on a
//! presigned link, no redirect followed, no cookie, a bounded read, a bounded
//! idle and total, one process-wide monotonic clock. `run` starts an
//! in-process HTTP server on `127.0.0.1` and reports one check per rule.
//!
//! Before fetching a link, a transport must call core's
//! [`check_storage_url`](beebeeb_core::direct_transfer::check_storage_url): it
//! refuses a non-https host (loopback development aside), an off-list host, an
//! unlisted bucket, a non-default port and dot segments. The suite cannot
//! express those rules against its own arbitrary paths, so it does not pretend
//! to; the transports use the core helper directly.
//!
//! The suite is feature-gated (`test-support`): it is a test seam, never part
//! of a shipped client.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use beebeeb_core::direct_transfer::{DISCOVERY_PATH, STORAGE_CONNECT_TIMEOUT, STORAGE_GET_IDLE};
use bytes::Bytes;

use crate::io::{ApiCall, ApiMethod, ApiReply, DirectIo, SignedUrl, StorageReply};

/// One check's result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckResult {
    pub name: &'static str,
    pub passed: bool,
    pub detail: String,
}

/// What the suite found.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConformanceReport {
    pub checks: Vec<CheckResult>,
}

impl ConformanceReport {
    /// Every check passed.
    pub fn passed(&self) -> bool {
        self.checks.iter().all(|c| c.passed)
    }

    /// The names of the checks that failed.
    pub fn failures(&self) -> Vec<&'static str> {
        self.checks.iter().filter(|c| !c.passed).map(|c| c.name).collect()
    }

    /// A human-readable report, for a panic message.
    pub fn describe(&self) -> String {
        let mut out = String::new();
        for check in &self.checks {
            out.push_str(&format!(
                "{} {}: {}\n",
                if check.passed { "PASS" } else { "FAIL" },
                check.name,
                check.detail
            ));
        }
        out
    }
}

fn check(name: &'static str, passed: bool, detail: impl Into<String>) -> CheckResult {
    CheckResult {
        name,
        passed,
        detail: detail.into(),
    }
}

/// One request the suite's server saw.
#[derive(Debug, Clone)]
struct Seen {
    target: String,
    headers: Vec<(String, String)>,
}

impl Seen {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    fn path(&self) -> &str {
        self.target.split('?').next().unwrap_or(&self.target)
    }
}

struct Server {
    base: String,
    seen: std::sync::Arc<Mutex<Vec<Seen>>>,
}

impl Server {
    fn start() -> Server {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let seen: std::sync::Arc<Mutex<Vec<Seen>>> = std::sync::Arc::default();
        let seen_thread = seen.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                let seen = seen_thread.clone();
                std::thread::spawn(move || serve(stream, &seen));
            }
        });
        Server {
            base: format!("http://{address}"),
            seen,
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }

    fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }

    fn count_path(&self, path: &str) -> usize {
        self.seen().iter().filter(|s| s.path() == path).count()
    }
}

fn serve(mut stream: TcpStream, seen: &Mutex<Vec<Seen>>) {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        let Ok(n) = stream.read(&mut chunk) else { return };
        if n == 0 {
            return;
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break p + 4;
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
    let mut lines = head.split("\r\n");
    let first = lines.next().unwrap_or("");
    let mut parts = first.split_whitespace();
    let _method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("").to_string();
    let headers: Vec<(String, String)> = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect();
    seen.lock().unwrap().push(Seen {
        target: target.clone(),
        headers,
    });
    let path = target.split('?').next().unwrap_or("");
    let len: usize = target
        .split_once("len=")
        .and_then(|(_, rest)| rest.split('&').next())
        .and_then(|v| v.parse().ok())
        .unwrap_or(4);
    match path {
        "/redirect" => respond(&mut stream, 302, &[("Location", "/ok?len=4")], b""),
        "/cookie" => respond(&mut stream, 200, &[("Set-Cookie", "sid=1")], b"abcd"),
        "/idle" => {
            // Headers and two bytes, then silence: a half-open connection that
            // outlives any client total the suite passes.
            let _ = write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\n"
            );
            let _ = stream.write_all(&[7u8; 2]);
            let _ = stream.flush();
            std::thread::sleep(Duration::from_secs(45));
        }
        "/slow" => {
            // A body that arrives slower than the call's total allows.
            let _ = write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\n"
            );
            let _ = stream.write_all(&[7u8]);
            let _ = stream.flush();
            std::thread::sleep(Duration::from_secs(5));
        }
        _ => respond(&mut stream, 200, &[], &vec![b'x'; len]),
    }
}

fn respond(stream: &mut TcpStream, status: u16, headers: &[(&str, &str)], body: &[u8]) {
    let reason = match status {
        200 => "OK",
        302 => "Found",
        _ => "Status",
    };
    let mut head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    );
    for (name, value) in headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str("\r\n");
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(body);
    let _ = stream.flush();
}

/// Run every check against a transport built by `make`; `make` receives the
/// suite's API base (loopback http, as in development).
pub async fn run<T: DirectIo>(make: impl Fn(&str) -> T) -> ConformanceReport {
    let server = Server::start();
    let io = make(&server.base);
    let mut checks = Vec::new();

    // The API call carries the credential. Checked first, so the storage
    // checks below are meaningful: a transport that never authenticates would
    // pass them vacuously.
    let _ = io
        .api(ApiCall {
            method: ApiMethod::Get,
            path: DISCOVERY_PATH.to_string(),
            body: None,
            capabilities: None,
            timeout: Duration::from_secs(5),
            max_body: 64 * 1024,
        })
        .await;
    let api_auth = server
        .seen()
        .iter()
        .any(|s| s.path() == DISCOVERY_PATH && s.header("authorization").is_some());
    checks.push(check(
        "the_api_call_carries_the_credential",
        api_auth,
        format!("{} request(s) to the API", server.count_path(DISCOVERY_PATH)),
    ));

    // Redirects are not followed: the link is a bearer capability and its
    // target is not the authority the grant was checked against.
    let redirect = io
        .storage_get(
            &SignedUrl::new(server.url("/redirect")),
            4,
            Duration::from_secs(5),
            STORAGE_GET_IDLE,
            STORAGE_CONNECT_TIMEOUT,
        )
        .await;
    let followed = server.count_path("/ok") > 0;
    checks.push(check(
        "redirects_are_not_followed",
        !followed && redirect.status != 200,
        format!("status {}, target requested: {}", redirect.status, followed),
    ));

    // A cookie a storage host sets is never sent back, and none is sent at all.
    let _ = io
        .storage_get(
            &SignedUrl::new(server.url("/cookie")),
            4,
            Duration::from_secs(5),
            STORAGE_GET_IDLE,
            STORAGE_CONNECT_TIMEOUT,
        )
        .await;
    let _ = io
        .storage_get(
            &SignedUrl::new(server.url("/ok?len=4")),
            4,
            Duration::from_secs(5),
            STORAGE_GET_IDLE,
            STORAGE_CONNECT_TIMEOUT,
        )
        .await;
    let cookies: Vec<String> = server
        .seen()
        .iter()
        .filter_map(|s| s.header("cookie").map(str::to_string))
        .collect();
    checks.push(check(
        "cookies_are_not_sent",
        cookies.is_empty(),
        format!("cookie headers seen: {cookies:?}"),
    ));

    // No credential and no client header reaches a storage host.
    let leaked: Vec<String> = server
        .seen()
        .iter()
        .filter(|s| s.path() != DISCOVERY_PATH)
        .flat_map(|s| s.headers.iter())
        .filter(|(name, _)| {
            name.eq_ignore_ascii_case("authorization") || name.to_ascii_lowercase().starts_with("x-beebeeb-")
        })
        .map(|(name, _)| name.clone())
        .collect();
    checks.push(check(
        "no_credentials_or_client_headers_reach_storage",
        leaked.is_empty(),
        format!("headers seen: {leaked:?}"),
    ));

    // A body that goes silent fails at the idle bound, before the (longer)
    // total.
    let started = Instant::now();
    let idle = io
        .storage_get(
            &SignedUrl::new(server.url("/idle")),
            100,
            STORAGE_GET_IDLE + Duration::from_secs(10),
            STORAGE_GET_IDLE,
            STORAGE_CONNECT_TIMEOUT,
        )
        .await;
    let idle_elapsed = started.elapsed();
    checks.push(check(
        "an_idle_body_times_out",
        idle.status == 0 && idle_elapsed <= STORAGE_GET_IDLE + Duration::from_secs(2),
        format!("status {} after {idle_elapsed:?}", idle.status),
    ));

    // The call's total bounds the whole body.
    let started = Instant::now();
    let slow = io
        .storage_get(
            &SignedUrl::new(server.url("/slow")),
            1000,
            Duration::from_millis(150),
            STORAGE_GET_IDLE,
            STORAGE_CONNECT_TIMEOUT,
        )
        .await;
    let elapsed = started.elapsed();
    checks.push(check(
        "the_total_bounds_the_body",
        slow.status == 0 && elapsed < Duration::from_secs(3),
        format!("status {} after {elapsed:?}", slow.status),
    ));

    // At most `expected_len + 1` bytes are read, so an overlong body is one
    // byte too many and memory stays bounded.
    let overlong = io
        .storage_get(
            &SignedUrl::new(server.url("/ok?len=8")),
            4,
            Duration::from_secs(5),
            STORAGE_GET_IDLE,
            STORAGE_CONNECT_TIMEOUT,
        )
        .await;
    let read = overlong.body.as_ref().map(Bytes::len);
    checks.push(check(
        "an_overlong_body_is_read_as_one_byte_too_many",
        overlong.status == 200 && read == Some(5),
        format!("status {}, body bytes {read:?}", overlong.status),
    ));

    // The monotonic clock is process-wide: an instance created a second later
    // reports the same epoch.
    std::thread::sleep(Duration::from_secs(1));
    let second = make(&server.base);
    // Both are sampled at the same moment, from instances created 1 s apart.
    let first_mono = io.mono_ms();
    let second_mono = second.mono_ms();
    let skew = (second_mono - first_mono).abs();
    checks.push(check(
        "the_mono_clock_is_process_wide",
        skew <= 200,
        format!("two instances created 1 s apart differ by {skew} ms"),
    ));

    ConformanceReport { checks }
}

/// A transport that does nothing, for `make` closures that need a fallback.
pub struct NullIo;

impl DirectIo for NullIo {
    async fn api(&self, _call: ApiCall) -> ApiReply {
        ApiReply::default()
    }

    async fn storage_get(
        &self,
        _url: &SignedUrl,
        _expected_len: u64,
        _total: Duration,
        _idle: Duration,
        _connect: Duration,
    ) -> StorageReply {
        StorageReply::default()
    }

    async fn storage_put(
        &self,
        _url: &SignedUrl,
        _body: Bytes,
        _headers: &[(&'static str, String)],
        _total: Duration,
    ) -> u16 {
        0
    }

    async fn sleep(&self, _d: Duration) {}

    fn wall_ms(&self) -> i64 {
        0
    }

    fn mono_ms(&self) -> i64 {
        0
    }
}
