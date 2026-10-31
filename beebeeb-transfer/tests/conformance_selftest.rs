//! The conformance suite's own self-tests: a reference transport passes, and a
//! transport that follows redirects, sends cookies, sends the bearer to
//! storage, has no read timeout or uses a per-instance monotonic clock is
//! caught. A real HTTP client (reqwest + tokio) is used here only; the crate
//! itself has none.

use std::sync::OnceLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use beebeeb_transfer::test_support::conformance;
use beebeeb_transfer::{ApiCall, ApiMethod, ApiReply, DirectIo, SignedUrl, StorageReply};
use bytes::Bytes;

#[derive(Clone, Copy)]
struct Wrong {
    follow_redirects: bool,
    send_cookie: bool,
    send_auth_to_storage: bool,
    read_timeout: bool,
    per_instance_clock: bool,
    uncapped_api: bool,
    api_timeout: bool,
}

impl Wrong {
    const NONE: Wrong = Wrong {
        follow_redirects: false,
        send_cookie: false,
        send_auth_to_storage: false,
        read_timeout: true,
        per_instance_clock: false,
        uncapped_api: false,
        api_timeout: true,
    };
}

/// A correct transport, with switches that make it wrong on purpose.
struct ReferenceIo {
    client: reqwest::Client,
    base: String,
    wrong: Wrong,
    epoch: Instant,
}

impl ReferenceIo {
    fn new(api_base: &str, wrong: Wrong) -> ReferenceIo {
        let redirect = if wrong.follow_redirects {
            reqwest::redirect::Policy::limited(10)
        } else {
            reqwest::redirect::Policy::none()
        };
        let mut builder = reqwest::Client::builder()
            .redirect(redirect)
            .connect_timeout(Duration::from_secs(15));
        if wrong.read_timeout {
            builder = builder.read_timeout(Duration::from_secs(30));
        }
        let client = builder.build().expect("the reference client builds");
        ReferenceIo {
            client,
            base: api_base.trim_end_matches('/').to_string(),
            wrong,
            epoch: Instant::now(),
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }
}

impl DirectIo for ReferenceIo {
    async fn api(&self, call: ApiCall) -> ApiReply {
        let mut request = self
            .client
            .request(
                match call.method {
                    ApiMethod::Get => reqwest::Method::GET,
                    ApiMethod::Post => reqwest::Method::POST,
                },
                self.url(&call.path),
            )
            .header("Authorization", "Bearer conformance-self-test")
            .header("Accept", "application/json");
        if self.wrong.api_timeout {
            request = request.timeout(call.timeout);
        }
        if let Some(body) = call.body {
            request = request.body(body);
        }
        let response = match request.send().await {
            Ok(response) => response,
            Err(_) => return ApiReply::default(),
        };
        let status = response.status().as_u16();
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let body = if self.wrong.uncapped_api {
            response.bytes().await.map(|b| b.to_vec()).unwrap_or_default()
        } else {
            // At most `max_body` bytes, then stop: the caller asked for no more.
            let mut body: Vec<u8> = Vec::new();
            let mut response = response;
            while body.len() < call.max_body {
                match response.chunk().await {
                    Ok(Some(piece)) => {
                        let room = call.max_body - body.len();
                        body.extend_from_slice(&piece[..piece.len().min(room)]);
                    }
                    Ok(None) => break,
                    Err(_) => return ApiReply::default(),
                }
            }
            body
        };
        ApiReply {
            status,
            content_type,
            retry_after: None,
            body,
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
        let mut request = self.client.get(url.expose()).timeout(total);
        if self.wrong.send_cookie {
            request = request.header("Cookie", "sid=1");
        }
        if self.wrong.send_auth_to_storage {
            request = request.header("Authorization", "Bearer conformance-self-test");
        }
        let response = match request.send().await {
            Ok(response) => response,
            Err(_) => return StorageReply::default(),
        };
        let status = response.status().as_u16();
        let content_length = response.content_length();
        // At most `expected_len + 1` bytes, then stop: an overlong body is visible
        // as one byte too many and memory is bounded by the chunk.
        let cap = expected_len.saturating_add(1);
        let mut body: Vec<u8> = Vec::new();
        let mut response = response;
        while (body.len() as u64) < cap {
            match response.chunk().await {
                Ok(Some(piece)) => {
                    let room = usize::try_from(cap - body.len() as u64).unwrap_or(usize::MAX);
                    body.extend_from_slice(&piece[..piece.len().min(room)]);
                }
                Ok(None) => break,
                Err(_) => return StorageReply::default(),
            }
        }
        StorageReply {
            status,
            content_length,
            body: Some(Bytes::from(body)),
        }
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

    async fn sleep(&self, d: Duration) {
        tokio::time::sleep(d).await;
    }

    fn wall_ms(&self) -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0)
    }

    fn mono_ms(&self) -> i64 {
        if self.wrong.per_instance_clock {
            return self.epoch.elapsed().as_millis() as i64;
        }
        static START: OnceLock<Instant> = OnceLock::new();
        START.get_or_init(Instant::now).elapsed().as_millis() as i64
    }
}

#[tokio::test]
async fn conformance_passes_the_reference_transport() {
    let report = conformance::run(|base: &str| ReferenceIo::new(base, Wrong::NONE)).await;
    assert!(report.passed(), "{}", report.describe());
}

#[tokio::test]
async fn conformance_fails_a_transport_that_follows_redirects() {
    let wrong = Wrong {
        follow_redirects: true,
        ..Wrong::NONE
    };
    let report = conformance::run(|base: &str| ReferenceIo::new(base, wrong)).await;
    assert!(!report.passed(), "{}", report.describe());
    assert!(
        report.failures().contains(&"redirects_are_not_followed"),
        "{}",
        report.describe()
    );
}

#[tokio::test]
async fn conformance_fails_a_transport_that_sends_cookies() {
    let wrong = Wrong {
        send_cookie: true,
        ..Wrong::NONE
    };
    let report = conformance::run(|base: &str| ReferenceIo::new(base, wrong)).await;
    assert!(!report.passed(), "{}", report.describe());
    assert!(
        report.failures().contains(&"cookies_are_not_sent"),
        "{}",
        report.describe()
    );
}

#[tokio::test]
async fn conformance_fails_a_transport_that_sends_the_bearer_to_storage() {
    let wrong = Wrong {
        send_auth_to_storage: true,
        ..Wrong::NONE
    };
    let report = conformance::run(|base: &str| ReferenceIo::new(base, wrong)).await;
    assert!(!report.passed(), "{}", report.describe());
    assert!(
        report
            .failures()
            .contains(&"no_credentials_or_client_headers_reach_storage"),
        "{}",
        report.describe()
    );
}

#[tokio::test]
async fn conformance_fails_a_transport_without_a_read_timeout() {
    let wrong = Wrong {
        read_timeout: false,
        ..Wrong::NONE
    };
    let report = conformance::run(|base: &str| ReferenceIo::new(base, wrong)).await;
    assert!(!report.passed(), "{}", report.describe());
    assert!(
        report.failures().contains(&"an_idle_body_times_out"),
        "{}",
        report.describe()
    );
}

#[tokio::test]
async fn conformance_fails_a_transport_that_reads_the_whole_api_body() {
    let wrong = Wrong {
        uncapped_api: true,
        ..Wrong::NONE
    };
    let report = conformance::run(|base: &str| ReferenceIo::new(base, wrong)).await;
    assert!(!report.passed(), "{}", report.describe());
    assert!(
        report.failures().contains(&"the_api_call_reads_at_most_max_body"),
        "{}",
        report.describe()
    );
}

#[tokio::test]
async fn conformance_fails_a_transport_without_an_api_timeout() {
    let wrong = Wrong {
        api_timeout: false,
        ..Wrong::NONE
    };
    let report = conformance::run(|base: &str| ReferenceIo::new(base, wrong)).await;
    assert!(!report.passed(), "{}", report.describe());
    assert!(
        report.failures().contains(&"the_api_timeout_bounds_the_call"),
        "{}",
        report.describe()
    );
}

#[tokio::test]
async fn conformance_fails_a_transport_with_a_per_instance_mono_clock() {
    let wrong = Wrong {
        per_instance_clock: true,
        ..Wrong::NONE
    };
    let report = conformance::run(|base: &str| ReferenceIo::new(base, wrong)).await;
    assert!(!report.passed(), "{}", report.describe());
    assert!(
        report.failures().contains(&"the_mono_clock_is_process_wide"),
        "{}",
        report.describe()
    );
}
