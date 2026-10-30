//! The conformance suite's own self-tests: a reference transport passes, and a
//! transport that follows redirects or sends cookies is caught. A real HTTP
//! client (reqwest + tokio) is used here only; the crate itself has none.

use std::sync::OnceLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use beebeeb_transfer::test_support::conformance::{self, refuse_plain_http};
use beebeeb_transfer::{ApiCall, ApiReply, DirectIo, SignedUrl, StorageReply};
use bytes::Bytes;

/// A correct transport, with two switches that make it wrong on purpose.
struct ReferenceIo {
    client: reqwest::Client,
    send_cookie: bool,
}

impl ReferenceIo {
    fn new(_api_base: &str, follow_redirects: bool, send_cookie: bool) -> ReferenceIo {
        let redirect = if follow_redirects {
            reqwest::redirect::Policy::limited(10)
        } else {
            reqwest::redirect::Policy::none()
        };
        let client = reqwest::Client::builder()
            .redirect(redirect)
            .connect_timeout(Duration::from_secs(15))
            .read_timeout(Duration::from_secs(30))
            .build()
            .expect("the reference client builds");
        ReferenceIo { client, send_cookie }
    }
}

impl DirectIo for ReferenceIo {
    async fn api(&self, _call: ApiCall) -> ApiReply {
        ApiReply::default()
    }

    async fn storage_get(&self, url: &SignedUrl, expected_len: u64, total: Duration) -> StorageReply {
        if refuse_plain_http(url.expose()) {
            return StorageReply::default();
        }
        let mut request = self.client.get(url.expose()).timeout(total);
        if self.send_cookie {
            request = request.header("Cookie", "sid=1");
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
        static START: OnceLock<Instant> = OnceLock::new();
        START.get_or_init(Instant::now).elapsed().as_millis() as i64
    }
}

#[tokio::test]
async fn conformance_passes_the_reference_transport() {
    let report = conformance::run(|base: &str| ReferenceIo::new(base, false, false)).await;
    assert!(report.passed(), "{}", report.describe());
}

#[tokio::test]
async fn conformance_fails_a_transport_that_follows_redirects() {
    let report = conformance::run(|base: &str| ReferenceIo::new(base, true, false)).await;
    assert!(!report.passed(), "{}", report.describe());
    assert!(
        report.failures().contains(&"redirects_are_not_followed"),
        "{}",
        report.describe()
    );
}

#[tokio::test]
async fn conformance_fails_a_transport_that_sends_cookies() {
    let report = conformance::run(|base: &str| ReferenceIo::new(base, false, true)).await;
    assert!(!report.passed(), "{}", report.describe());
    assert!(
        report.failures().contains(&"cookies_are_not_sent"),
        "{}",
        report.describe()
    );
}
