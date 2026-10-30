//! The transport conformance suite (plan K2).
//!
//! A client's [`DirectIo`] must keep the storage-side contract, not just work
//! against a happy server: no redirect, no cookie, no credential or client
//! header on a presigned link, a bounded read, a bounded total, no URL in an
//! error, and no plain http to a host that is not loopback. `run` starts an
//! in-process HTTP server on `127.0.0.1` and reports one check per rule.
//!
//! The suite is feature-gated (`test-support`): it is a test seam, never part
//! of a shipped client.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use bytes::Bytes;

use crate::io::{ApiCall, ApiReply, DirectIo, SignedUrl, StorageReply};

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
            // Headers and two bytes, then silence: a half-open connection.
            let _ = write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\n"
            );
            let _ = stream.write_all(&[7u8; 2]);
            let _ = stream.flush();
            std::thread::sleep(Duration::from_secs(31));
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

/// Is `url` plain http to a host that is not loopback? A transport must refuse
/// that without connecting.
fn plain_http_off_loopback(url: &str) -> bool {
    let rest = url.strip_prefix("http://").or_else(|| url.strip_prefix("HTTP://"));
    let Some(rest) = rest else { return false };
    let authority = rest.split('/').next().unwrap_or(rest);
    let host = authority.rsplit_once(':').map(|(h, _)| h).unwrap_or(authority);
    !matches!(host, "127.0.0.1" | "localhost" | "[::1]")
}

/// Run every check against a transport built by `make`; `make` receives the
/// suite's API base (loopback http, as in development).
pub async fn run<T: DirectIo>(make: impl Fn(&str) -> T) -> ConformanceReport {
    let server = Server::start();
    let io = make(&server.base);
    let mut checks = Vec::new();

    // Redirects are not followed: the link is a bearer capability and its
    // target is not the authority the grant was checked against.
    let redirect = io
        .storage_get(&SignedUrl::new(server.url("/redirect")), 4, Duration::from_secs(5))
        .await;
    let followed = server.count_path("/ok") > 0;
    checks.push(check(
        "redirects_are_not_followed",
        !followed && redirect.status != 200,
        format!("status {}, target requested: {}", redirect.status, followed),
    ));

    // A cookie a storage host sets is never sent back, and none is sent at all.
    let _ = io
        .storage_get(&SignedUrl::new(server.url("/cookie")), 4, Duration::from_secs(5))
        .await;
    let _ = io
        .storage_get(&SignedUrl::new(server.url("/ok?len=4")), 4, Duration::from_secs(5))
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

    // A body that goes silent fails at the idle bound.
    let started = Instant::now();
    let idle = io
        .storage_get(&SignedUrl::new(server.url("/idle")), 100, Duration::from_secs(35))
        .await;
    checks.push(check(
        "an_idle_body_times_out",
        idle.status == 0,
        format!("status {} after {:?}", idle.status, started.elapsed()),
    ));

    // The call's total bounds the whole body.
    let started = Instant::now();
    let slow = io
        .storage_get(&SignedUrl::new(server.url("/slow")), 1000, Duration::from_millis(150))
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
        .storage_get(&SignedUrl::new(server.url("/ok?len=8")), 4, Duration::from_secs(5))
        .await;
    let read = overlong.body.as_ref().map(Bytes::len);
    checks.push(check(
        "an_overlong_body_is_read_as_one_byte_too_many",
        overlong.status == 200 && read == Some(5),
        format!("status {}, body bytes {read:?}", overlong.status),
    ));

    // Nothing that leaves a failed fetch carries the link.
    let secret = "SECRETSIG2173";
    let url = SignedUrl::new(server.url(&format!("/ok?len=4&X-Amz-Signature={secret}")));
    let _ = io.storage_get(&url, 4, Duration::from_secs(5)).await;
    let text = format!("{idle:?} {slow:?} {overlong:?} {url} {url:?}");
    checks.push(check(
        "no_url_reaches_a_debug_string",
        !text.contains("X-Amz-Signature"),
        "formatted replies and the link".to_string(),
    ));

    // Plain http to a host that is not loopback is refused without connecting.
    let started = Instant::now();
    let off_host = io
        .storage_get(
            &SignedUrl::new("http://192.0.2.1/b/k?X-Amz-Signature=SECRETSIG2173"),
            4,
            Duration::from_secs(5),
        )
        .await;
    let elapsed = started.elapsed();
    checks.push(check(
        "plain_http_to_a_non_loopback_host_is_refused",
        off_host.status == 0 && elapsed < Duration::from_secs(2),
        format!("status {} after {elapsed:?}", off_host.status),
    ));

    ConformanceReport { checks }
}

/// Re-export for transports that want to reuse the rule the suite checks.
pub fn refuse_plain_http(url: &str) -> bool {
    plain_http_off_loopback(url)
}

/// A transport that does nothing, for `make` closures that need a fallback.
pub struct NullIo;

impl DirectIo for NullIo {
    async fn api(&self, _call: ApiCall) -> ApiReply {
        ApiReply::default()
    }

    async fn storage_get(&self, _url: &SignedUrl, _expected_len: u64, _total: Duration) -> StorageReply {
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
