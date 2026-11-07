#![allow(deprecated)]
//! The cross-client contract vectors, run through this crate's exported functions and
//! methods wherever they can run without a JS engine, and otherwise through the seam the
//! `JsValue` wrapper calls. The same file `beebeeb-core` runs through core directly: a
//! wrapper that drifts from core fails here.

use beebeeb_core::direct_transfer::vectors::{
    self, CacheSurface, HealthSurface, PlannerSurface, StorageBodySurface, Surface,
};
use serde_json::{Value, json};

use super::*;

struct WasmSurface;

struct WasmPlannerSurface(WasmDownloadPlanner);

struct WasmCacheSurface(WasmDirectDiscoveryCache);

struct WasmHealthSurface(WasmDirectHealth);

impl HealthSurface for WasmHealthSurface {
    fn gave_up(&mut self, direction: &str, now_ms: i64) {
        self.0.gave_up(direction, now_ms as f64).unwrap();
    }
    fn may_start(&self, direction: &str, now_ms: i64) -> bool {
        self.0.may_start(direction, now_ms as f64).unwrap()
    }
    fn may_start_file(&self, direction: &str, now_ms: i64, file_gave_up: bool) -> bool {
        self.0.may_start_file(direction, now_ms as f64, file_gave_up).unwrap()
    }
    fn last_gave_up_ms(&self, direction: &str) -> Option<i64> {
        self.0.last_gave_up_ms(direction).unwrap().map(|ms| ms as i64)
    }
    fn restore(&mut self, direction: &str, last_gave_up_ms: i64) {
        self.0.restore(direction, last_gave_up_ms as f64).unwrap();
    }
}

impl CacheSurface for WasmCacheSurface {
    fn lookup(&self, now_ms: i64) -> String {
        match self.0.lookup_dto(now_ms) {
            DirectLookupJs::Fetch => "fetch",
            DirectLookupJs::Cached { .. } => "cached",
            DirectLookupJs::UseApi => "use_api",
        }
        .to_string()
    }

    fn record(&mut self, outcome: &Value, body: Option<&[u8]>, now_ms: i64) {
        let outcome: DirectOutcomeJs = serde_json::from_value(outcome.clone()).unwrap();
        self.0.record_core(&outcome, body, now_ms);
    }
}

/// The shape the vectors use: the flat fetch has no `method`/`expires_at`, numbers are integers.
fn poll_value(dto: DirectPollJs) -> Value {
    let mut v = serde_json::to_value(dto).unwrap();
    if v["kind"] == "fetch" {
        v.as_object_mut().unwrap().remove("method");
        v.as_object_mut().unwrap().remove("expires_at");
    }
    vectors::normalize_numbers(v)
}

impl Surface for WasmSurface {
    type Planner = WasmPlannerSurface;
    type Cache = WasmCacheSurface;
    type Health = WasmHealthSurface;

    fn cache(&self) -> WasmCacheSurface {
        WasmCacheSurface(WasmDirectDiscoveryCache::new())
    }

    fn health(&self) -> WasmHealthSurface {
        WasmHealthSurface(WasmDirectHealth::new())
    }

    fn resume_transport(&self, recorded: &str, discovery: &Value, forced_api: bool) -> String {
        direct_resume_transport(
            recorded,
            discovery["kind"].as_str().unwrap(),
            discovery["upload"].as_bool(),
            forced_api,
        )
        .unwrap()
    }

    fn check_storage_url(&self, url: &str, discovery: &Value, api_base: &str) -> Result<(), String> {
        let d: dt::Discovery = serde_json::from_value(discovery.clone()).map_err(|e| e.to_string())?;
        direct_check_url(url, &d, api_base).map_err(|f| f.code.to_string())
    }

    fn classify(
        &self,
        call: &str,
        status: u16,
        content_type: Option<&str>,
        body: &[u8],
        retry_after: Option<&str>,
    ) -> Value {
        let outcome = direct_classify(call, status, content_type, body, retry_after).expect("known call");
        vectors::normalize_numbers(serde_json::to_value(outcome).unwrap())
    }

    fn redact(&self, input: &str) -> String {
        redact_url(input)
    }

    fn pinned_retry(&self, outcome: &Value, attempt: u32, waited_ms: u64) -> Value {
        let outcome: DirectOutcomeJs = serde_json::from_value(outcome.clone()).unwrap();
        vectors::normalize_numbers(
            serde_json::to_value(direct_pinned_retry(&outcome, attempt, waited_ms as f64)).unwrap(),
        )
    }

    fn scrub(&self, input: &str) -> String {
        scrub_text(input)
    }

    fn chunk_length(&self, chunk_count: u32, chunk_size: u64, encrypted_size: u64, index: u32) -> Option<u64> {
        dt::Geometry {
            chunk_count,
            chunk_size,
            encrypted_size,
            original_size: 0,
        }
        .chunk_length(index)
    }

    fn check_storage_get(&self, status: u16, content_length: Option<u64>, expected: u64) -> Value {
        // Through the exported seam's own f64 conversion, so the surface cannot disagree with
        // `checkStorageGet` about which statuses cross.
        check_storage_get_value(status as f64, content_length.map(|n| n as f64), expected as f64)
            .expect("the row's status and lengths fit the exported seam")
    }

    fn check_storage_body(&self, received: u64, expected: u64) -> Value {
        storage_body_json(received, expected)
    }

    fn storage_body(&self, status: u16, content_length: Option<u64>, expected: u64, pushes: &[u64]) -> Value {
        // The head → pushes → stop → finish contract lives once, in `vectors::drive_storage_body`;
        // a failure's status comes from the binding's own error, never from the row.
        vectors::drive_storage_body(self, status, content_length, expected, pushes)
    }

    fn paced_until_ms(&self, start_ms: i64, wire_bytes: u64, kbps: u64) -> i64 {
        // The export crosses the answer as a JS number (`-Infinity` for no ceiling); the
        // vectors file writes that sentinel as core's `i64::MIN`.
        match paced_until_ms_value(start_ms, wire_bytes, kbps) {
            ms if ms == f64::NEG_INFINITY => i64::MIN,
            ms => ms as i64,
        }
    }

    fn max_in_flight_bytes(&self, class: &str) -> u64 {
        max_in_flight_bytes_value(class).unwrap() as u64
    }

    fn pairs_allowed(&self, discovery: &Value, direction: &str, allowlist: &Value) -> bool {
        let d: dt::Discovery = serde_json::from_value(discovery.clone()).unwrap();
        let allowlist: Vec<dt::StorageBucket> = serde_json::from_value(allowlist.clone()).unwrap();
        pairs_allowed_value(&d, direct_direction(direction).unwrap(), &allowlist)
    }

    fn planner(&self, discovery: &Value, api_base: &str, file_id: &str, seed: u64) -> WasmPlannerSurface {
        let d: dt::Discovery = serde_json::from_value(discovery.clone()).unwrap();
        WasmPlannerSurface(WasmDownloadPlanner::from_parts(d, api_base, file_id, seed))
    }
}

impl StorageBodySurface for WasmSurface {
    type Body = WasmStorageBody;

    fn body_from_head(&self, status: u16, content_length: Option<u64>, expected: u64) -> Result<Self::Body, Value> {
        WasmStorageBody::from_head(status as f64, content_length.map(|n| n as f64), expected as f64).map_err(|failed| {
            // The status comes from the binding's error; the row only supplied the input.
            json!({"kind": failed.code, "status": failed.status.expect("a storage body failure carries its status")})
        })
    }

    fn body_push(&self, body: &mut Self::Body, n: u64) -> Result<(), Value> {
        body.push(n as f64).map_err(|failed| {
            json!({"kind": failed.code, "status": failed.status.expect("a storage body failure carries its status")})
        })
    }

    fn body_finish(&self, body: Self::Body) -> Value {
        body.finish_json()
    }
}

impl PlannerSurface for WasmPlannerSurface {
    fn poll(&mut self, now_ms: i64) -> Value {
        poll_value(self.0.poll_dto(now_ms))
    }

    fn window_answered(&mut self, body: &[u8], now_ms: i64) -> Result<(), String> {
        match self.0.window_answered(body, now_ms as f64).as_str() {
            "accepted" => Ok(()),
            code => Err(code.to_string()),
        }
    }

    fn window_failed(&mut self, outcome: &Value, now_ms: i64) {
        let outcome: DirectOutcomeJs = serde_json::from_value(outcome.clone()).unwrap();
        self.0.failed_core(&outcome, now_ms);
    }

    fn window_malformed(&mut self) {
        self.0.window_malformed();
    }

    fn fetch_ok(&mut self, index: u32) -> Result<(), String> {
        self.0.fetch_ok(index).map_err(|f| f.code.to_string())
    }

    fn fetch_failed(&mut self, index: u32, now_ms: i64) -> Result<(), String> {
        self.0
            .fetch_failed(index, now_ms as f64)
            .map_err(|f| f.code.to_string())
    }

    fn api_fetch_failed(&mut self, index: u32) -> Result<(), String> {
        self.0.api_fetch_failed(index).map_err(|f| f.code.to_string())
    }

    fn chunk_unauthentic(&mut self, index: u32) -> Result<(), String> {
        self.0.chunk_unauthentic(index).map_err(|f| f.code.to_string())
    }

    fn consumed(&mut self, index: u32) -> Result<(), String> {
        self.0.consumed(index).map_err(|f| f.code.to_string())
    }

    fn inspect(&self) -> Value {
        vectors::normalize_numbers(json!({
            "geometry": serde_json::to_value(self.0.geometry_dto()).unwrap(),
            "pinned_version": self.0.pinned_version(),
            "consumed": self.0.consumed_count(),
            "in_flight": self.0.in_flight(),
        }))
    }

    fn set_max_in_flight_bytes(&mut self, bytes: u64) {
        self.0.set_max_in_flight_bytes(bytes as f64).unwrap();
    }

    fn storage_given_up(&self) -> bool {
        self.0.storage_given_up()
    }
}

#[test]
fn the_wasm_seams_pass_every_row_of_the_vectors() {
    let report = vectors::run_all(&WasmSurface);
    assert_eq!(
        report,
        vectors::expected_report(),
        "a section that did not run is a failure"
    );
}

/// The storage body's failures carry the status the head (or the refused push) answered, so no
/// client re-derives it from its own input; a status that is not a whole number that fits a
/// `u16` is `status_invalid`.
#[test]
fn the_storage_body_error_carries_its_status() {
    let chunk = (4 * 1024 * 1024 + 28) as f64;
    match WasmStorageBody::from_head(206.0, Some(chunk), chunk) {
        Err(failed) => {
            assert_eq!(failed.code, "failed");
            assert_eq!(failed.status, Some(206));
        }
        Ok(_) => panic!("a 206 head must throw"),
    }
    match WasmStorageBody::from_head(0.0, None, chunk) {
        Err(failed) => assert_eq!(failed.status, Some(0), "no answer keeps status 0"),
        Ok(_) => panic!("a head with no length must throw"),
    }
    let mut body = WasmStorageBody::from_head(200.0, Some(chunk), chunk).expect("an exact head");
    body.push(chunk - 1.0).expect("inside the grant");
    match body.push(2.0) {
        Err(failed) => {
            assert_eq!(failed.code, "failed");
            assert_eq!(failed.status, Some(200));
        }
        Ok(()) => panic!("a push past the grant must throw"),
    }
    for bad in [65736.0, 200.9, -1.0, f64::NAN] {
        match WasmStorageBody::from_head(bad, Some(chunk), chunk) {
            Err(failed) => assert_eq!(failed.code, "status_invalid", "{bad}"),
            Ok(_) => panic!("{bad} is not an HTTP status"),
        }
    }
}

/// `checkStorageGet` validates the head's status exactly as `WasmStorageBody.fromHead` does: a
/// number that is not a whole number fitting a `u16` is `status_invalid`, never a truncated
/// status that silently checks a different answer.
#[test]
fn check_storage_get_validates_its_status_like_the_body_head() {
    let chunk = (4 * 1024 * 1024 + 28) as f64;
    for bad in [65736.0, 200.9] {
        assert_eq!(
            check_storage_get_value(bad, Some(chunk), chunk).unwrap_err().code,
            "status_invalid",
            "checkStorageGet({bad})"
        );
        match WasmStorageBody::from_head(bad, Some(chunk), chunk) {
            Err(failed) => assert_eq!(failed.code, "status_invalid", "fromHead({bad})"),
            Ok(_) => panic!("fromHead({bad}) must throw status_invalid"),
        }
    }
    // 1000 is a whole number that fits a u16: the bindings only convert the type. What it means
    // is core's rule, so both bindings answer the same class (a failed head carrying 1000).
    assert_eq!(
        check_storage_get_value(1000.0, Some(chunk), chunk).unwrap(),
        serde_json::json!({"kind": "failed", "status": 1000}),
        "checkStorageGet(1000) is a failed head, not a caller error"
    );
    match WasmStorageBody::from_head(1000.0, Some(chunk), chunk) {
        Err(failed) => {
            assert_eq!(failed.code, "failed");
            assert_eq!(failed.status, Some(1000), "the head's own status rides on the error");
        }
        Ok(_) => panic!("a 1000 head is a failed head"),
    }
    // The u16 boundary: 65535 crosses and is core's failed head; 65536 cannot cross.
    assert_eq!(
        check_storage_get_value(65535.0, Some(chunk), chunk).unwrap(),
        serde_json::json!({"kind": "failed", "status": 65535}),
        "65535 is the largest HTTP status"
    );
    assert_eq!(
        check_storage_get_value(65536.0, Some(chunk), chunk).unwrap_err().code,
        "status_invalid",
        "65536 does not fit a u16"
    );
    match WasmStorageBody::from_head(65535.0, Some(chunk), chunk) {
        Err(failed) => {
            assert_eq!(failed.code, "failed");
            assert_eq!(failed.status, Some(65535), "the head's own status rides on the error");
        }
        Ok(_) => panic!("a 65535 head is a failed head"),
    }
    match WasmStorageBody::from_head(65536.0, Some(chunk), chunk) {
        Err(failed) => assert_eq!(failed.code, "status_invalid", "fromHead(65536)"),
        Ok(_) => panic!("65536 is not an HTTP status"),
    }
}

/// A length crosses as a JS number: only a finite, whole, non-negative number below 2^53 is a length.
#[test]
fn storage_totals_follow_core_and_refuse_a_length_that_is_not_one() {
    // A 4 MiB chunk (plus the AEAD overhead): 60 s + 33 s, in milliseconds.
    let len = (4 * 1024 * 1024 + 28) as f64;
    assert_eq!(storage_put_total_ms(len).unwrap(), 93_000.0);
    assert_eq!(storage_get_total_ms(len).unwrap(), 93_000.0);
    assert_eq!(storage_put_total_ms(0.0).unwrap(), 60_000.0);
    for bad in [-1.0, f64::NAN, f64::INFINITY, 1.5, 9_007_199_254_740_992.0] {
        assert_eq!(storage_put_total_ms(bad).unwrap_err().code, "length_invalid", "{bad}");
        assert_eq!(storage_get_total_ms(bad).unwrap_err().code, "length_invalid", "{bad}");
    }
}

#[test]
fn health_refuses_a_direction_that_is_not_one() {
    let mut h = WasmDirectHealth::new();
    for bad in ["", "Download", "up", "both"] {
        assert_eq!(h.gave_up(bad, 0.0).unwrap_err().code, "direction_invalid", "{bad:?}");
        assert_eq!(h.may_start(bad, 0.0).unwrap_err().code, "direction_invalid");
        assert_eq!(h.may_start_file(bad, 0.0, false).unwrap_err().code, "direction_invalid");
        assert_eq!(h.last_gave_up_ms(bad).unwrap_err().code, "direction_invalid");
        assert_eq!(h.restore(bad, 0.0).unwrap_err().code, "direction_invalid");
    }
    // Nothing was recorded by the refused calls.
    assert_eq!(h.last_gave_up_ms("download").unwrap(), None);
    assert_eq!(h.last_gave_up_ms("upload").unwrap(), None);
}

#[test]
fn health_refuses_a_time_that_is_not_a_number() {
    // A NaN or infinite time would be turned into 0 or a saturated number, which makes the ten-minute hold silently
    // ineffective (a give-up recorded at the epoch is 56 years old).
    let mut h = WasmDirectHealth::new();
    for bad in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
        assert_eq!(h.gave_up("download", bad).unwrap_err().code, "time_invalid", "{bad}");
        assert_eq!(h.may_start("download", bad).unwrap_err().code, "time_invalid");
        assert_eq!(
            h.may_start_file("download", bad, false).unwrap_err().code,
            "time_invalid"
        );
        assert_eq!(h.restore("download", bad).unwrap_err().code, "time_invalid");
    }
    assert_eq!(h.last_gave_up_ms("download").unwrap(), None, "nothing was recorded");
}

#[test]
fn resume_transport_refuses_names_it_does_not_know() {
    let ok = |r: &str, k: &str, u: Option<bool>, f: bool| direct_resume_transport(r, k, u, f);
    assert_eq!(ok("direct", "offers", Some(true), false).unwrap(), "continue_direct");
    assert_eq!(ok("direct", "unknown", None, false).unwrap(), "keep_record_and_fail");
    assert_eq!(
        ok("sideways", "offers", Some(true), false).unwrap_err().code,
        "recorded_invalid"
    );
    assert_eq!(
        ok("direct", "offers", None, false).unwrap_err().code,
        "discovery_state_invalid"
    );
    assert_eq!(
        ok("direct", "maybe", None, false).unwrap_err().code,
        "discovery_state_invalid"
    );
}

#[test]
fn the_byte_cap_refuses_a_number_that_is_not_a_byte_count() {
    let discovery = dt::Discovery {
        download: vec![dt::CAP_OBJECT_DOWNLOAD_V1.into()],
        ..Default::default()
    };
    let mut p = WasmDownloadPlanner::from_parts(discovery, "https://api.beebeeb.test", "f", 1);
    for bad in [-1.0, f64::NAN, f64::INFINITY, 1.5, 9_007_199_254_740_992.0] {
        assert_eq!(
            p.set_max_in_flight_bytes(bad).unwrap_err().code,
            "bytes_invalid",
            "{bad}"
        );
    }
    p.set_max_in_flight_bytes(0.0).unwrap();
    p.set_max_in_flight_bytes(67_108_864.0).unwrap();
    assert!(!p.storage_given_up(), "a new planner has not given up storage");
}

#[test]
fn the_constants_carry_core_s_time_bounds() {
    let c = direct_constants();
    assert_eq!(
        u64::from(c.storage_connect_timeout_ms),
        dt::timeouts::STORAGE_CONNECT_TIMEOUT.as_millis() as u64
    );
    assert_eq!(
        u64::from(c.storage_get_idle_ms),
        dt::timeouts::STORAGE_GET_IDLE.as_millis() as u64
    );
    assert_eq!(
        u64::from(c.discovery_timeout_ms),
        dt::timeouts::DISCOVERY_TIMEOUT.as_millis() as u64
    );
    assert_eq!(
        u64::from(c.api_call_timeout_ms),
        dt::timeouts::API_CALL_TIMEOUT.as_millis() as u64
    );
    assert_eq!(
        u64::from(c.background_put_resource_timeout_ms),
        dt::timeouts::BACKGROUND_PUT_RESOURCE_TIMEOUT.as_millis() as u64
    );
    assert_eq!(
        (
            c.storage_connect_timeout_ms,
            c.storage_get_idle_ms,
            c.discovery_timeout_ms,
            c.api_call_timeout_ms,
            c.background_put_resource_timeout_ms
        ),
        (15_000, 30_000, 15_000, 60_000, 240_000),
        "the numbers of the clients design, 6.2"
    );
}

#[test]
fn discovery_decoding_and_the_cache_follow_core() {
    let body = br#"{"download":["object-download-v1"],"upload":null,"storage_hosts":["s3.storage.test"],"future":1}"#;
    let d = direct_parse_discovery(body).unwrap();
    assert!(d.offers_download() && d.upload.is_empty());
    assert_eq!(direct_parse_discovery(b"[]").unwrap_err().code, "discovery_malformed");
    assert_eq!(
        direct_parse_discovery(&vec![b' '; dt::wire::MAX_DISCOVERY_BYTES + 1])
            .unwrap_err()
            .code,
        "discovery_too_large"
    );

    let mut cache = WasmDirectDiscoveryCache::new();
    assert!(matches!(cache.lookup_dto(0), DirectLookupJs::Fetch));
    cache.record_core(&DirectOutcomeJs::Proceed, Some(body), 1_000);
    assert!(matches!(cache.lookup_dto(1_000), DirectLookupJs::Cached { .. }));
    assert!(
        matches!(cache.lookup_dto(1_000 + 10 * 60 * 1000), DirectLookupJs::Fetch),
        "trusted for 10 minutes"
    );
    // A success whose body does not decode is a failed attempt; two of them stop the asking.
    let mut bad = WasmDirectDiscoveryCache::new();
    bad.record_core(&DirectOutcomeJs::Proceed, Some(b"nope"), 0);
    bad.record_core(&DirectOutcomeJs::Proceed, None, 1);
    assert!(matches!(bad.lookup_dto(2), DirectLookupJs::UseApi));
    let mut gone = WasmDirectDiscoveryCache::new();
    gone.record_core(&DirectOutcomeJs::NotSupported, None, 0);
    assert!(
        matches!(gone.lookup_dto(1), DirectLookupJs::UseApi),
        "NotSupported is remembered"
    );
}

#[test]
fn classify_refuses_an_unknown_call_and_outcomes_round_trip() {
    assert_eq!(
        direct_classify("nope", 200, None, b"", None).unwrap_err().code,
        "unknown_call"
    );
    for outcome in [
        json!({"kind": "backoff", "millis": 1500.0}),
        json!({"kind": "terminal", "status": 403, "error": null}),
        json!({"kind": "restart"}),
        json!({"kind": "retry"}),
        // The upload commit's "the staged chunk is not there": the JS side hands it back to core
        // (a planner or a retry decision), where it must still be a regrant and not a catch-all.
        json!({"kind": "regrant"}),
        // The commit hold: with the server's stated wait, and without.
        json!({"kind": "held", "millis": 3000.0}),
        json!({"kind": "held", "millis": null}),
    ] {
        let parsed: DirectOutcomeJs = serde_json::from_value(outcome.clone()).unwrap();
        assert_eq!(
            serde_json::to_value(DirectOutcomeJs::from_core(&parsed.to_core())).unwrap(),
            outcome
        );
    }
}

#[test]
fn a_math_random_seed_is_not_zero_and_distinct_numbers_are_distinct_seeds() {
    let seeds: Vec<u64> = [0.0, 0.1, 0.25, 0.5, 0.75, 0.999_999]
        .iter()
        .map(|s| direct_seed(*s))
        .collect();
    for (i, a) in seeds.iter().enumerate() {
        for b in &seeds[i + 1..] {
            assert_ne!(a, b);
        }
    }
    assert!(
        seeds[1..].iter().all(|s| *s != 0),
        "a number below 1 must not collapse to 0"
    );
    assert_eq!(direct_seed(42.0), direct_seed(42.0));
}

#[test]
fn a_signed_url_object_prints_only_scheme_and_host() {
    let link = "https://s3.storage.test/bb-01/t/v/0.bin?X-Amz-Signature=SECRETSIG";
    let url = WasmSignedUrl { url: link.to_string() };
    for shown in [url.to_string_redacted(), url.to_json_redacted(), url.redacted()] {
        assert!(!shown.contains("SECRETSIG") && !shown.contains("X-Amz"), "{shown}");
        assert!(shown.contains("s3.storage.test"), "{shown}");
    }
    assert_eq!(url.raw(), link, "the one way to the link is explicit");
}

#[test]
fn the_jitter_seed_reaches_the_planner() {
    // The same failure, on planners seeded differently, waits different times (equal jitter);
    // the same seed repeats. A binding that drops the seed would give every client one schedule.
    let vectors = vectors::vectors();
    let t0 = vectors["t0_ms"].as_i64().unwrap();
    let file_id = vectors["file_id"].as_str().unwrap().to_string();
    let wait_after_a_failure = |seed: u64| -> i64 {
        let discovery: dt::Discovery = serde_json::from_value(vectors["discoveries"]["std"].clone()).unwrap();
        let mut p = WasmDownloadPlanner::from_parts(discovery, "https://api.beebeeb.test", &file_id, seed);
        p.poll_dto(t0);
        let window = vectors["planner"][0]["steps"][2]["response"].clone();
        assert_eq!(
            p.window_answered(&serde_json::to_vec(&window).unwrap(), t0 as f64),
            "accepted"
        );
        for _ in 0..3 {
            p.poll_dto(t0);
        }
        p.fetch_failed(0, t0 as f64).unwrap();
        match p.poll_dto(t0) {
            DirectPollJs::Wait { until_ms: Some(t) } => t as i64,
            _ => panic!("expected a wait for the renewal"),
        }
    };
    let waits: Vec<i64> = (1..=6).map(wait_after_a_failure).collect();
    assert!(waits.iter().any(|w| *w != waits[0]), "{waits:?}");
    assert_eq!(wait_after_a_failure(3), wait_after_a_failure(3));
}

#[test]
fn the_constants_are_the_contracts_names_and_numbers() {
    let c = serde_json::to_value(direct_constants()).unwrap();
    assert_eq!(
        c,
        json!({
            "cap_object_download_v1": "object-download-v1",
            "cap_object_upload_v1": "object-upload-v1",
            "capabilities_header": "X-Beebeeb-Capabilities",
            "discovery_path": "/api/v1/transfer/capabilities",
            "max_window": 32,
            "default_window": 8,
            "chunk_overhead": 28,
            "max_discovery_body_bytes": 256 * 1024,
            "max_grant_body_bytes": 1024 * 1024,
            "max_chunk_body_bytes": 256 * 1024 * 1024 + 28,
            "storage_connect_timeout_ms": 15_000,
            "storage_get_idle_ms": 30_000,
            "discovery_timeout_ms": 15_000,
            "api_call_timeout_ms": 60_000,
            "background_put_resource_timeout_ms": 240_000,
        })
    );
    assert_eq!(
        direct_download_grants_path("11111111-1111-4111-8111-111111111111"),
        "/api/v1/files/11111111-1111-4111-8111-111111111111/download-grants"
    );
}

#[test]
fn no_signature_survives_the_planner_debug_or_the_error_text() {
    // A planner that holds signed links: its Debug shows none of them.
    let vectors = vectors::vectors();
    let discovery: dt::Discovery = serde_json::from_value(vectors["discoveries"]["std"].clone()).unwrap();
    let mut planner = WasmDownloadPlanner::from_parts(discovery, "https://api.beebeeb.test", "f", 1);
    let window = json!({
        "transport": "object-download-v1",
        "file_id": "f",
        "object_version_id": "22222222-2222-4222-8222-222222222222",
        "chunk_count": 1, "chunk_size": 1000, "encrypted_size": 1028, "original_size": 1000,
        "grants": [{"index": 0, "method": "GET", "length": 1028, "expires_at": "2027-01-15T08:05:00Z",
                    "url": "https://s3.storage.test/bb-01/t/v/0.bin?X-Amz-Signature=SECRETSIG"}],
        "next_index": null,
    });
    planner.poll_dto(1_800_000_000_000);
    assert_eq!(
        planner.window_answered(&serde_json::to_vec(&window).unwrap(), 1_800_000_000_000.0),
        "accepted"
    );
    assert!(matches!(
        planner.poll_dto(1_800_000_000_000),
        DirectPollJs::Fetch { .. }
    ));
    let shown = format!("{:?}", planner.inner);
    assert!(!shown.contains("SECRETSIG") && !shown.contains("X-Amz"), "{shown}");
    // The error a refused link throws never contains the link.
    let failure = direct_check_url(
        "https://evil.test@s3.storage.test/bb-01/k?X-Amz-Signature=SECRETSIG",
        &dt::Discovery::default(),
        "https://api.beebeeb.test",
    )
    .unwrap_err();
    let shown = format!("{failure:?} {}", failure.message);
    assert_eq!(failure.code, "userinfo");
    assert!(!shown.contains("SECRETSIG") && !shown.contains("evil.test"), "{shown}");
}

#[test]
fn folder_keyed_index_from_wasm() {
    // wasm-bindgen imports cannot be called on the host, so this covers the
    // core path the wrapper delegates to; the JS surface (both exports and
    // the shard methods) is covered by beebeeb-wasm/js-tests/folder_link.test.cjs.
    let folder_key = kdf::FileKey::from_bytes([0x5a; 32]);
    let mut idx = search_index::SearchIndex::new(search_index::DEFAULT_NUM_SHARDS);
    idx.upsert("f1", "NF_song.mp3");
    let shards = idx
        .encrypt_shards_with(search_index::ShardKeySource::Folder(&folder_key))
        .unwrap();
    let restored = search_index::SearchIndex::from_encrypted_shards_with(
        search_index::ShardKeySource::Folder(&folder_key),
        &shards,
        idx.num_shards(),
    )
    .unwrap();
    assert_eq!(
        restored.query("nf"),
        std::collections::BTreeSet::from(["f1".to_string()])
    );
    assert!(
        search_index::SearchIndex::from_encrypted_shards_with(
            search_index::ShardKeySource::Master(&kdf::MasterKey::from_bytes([0x11; 32])),
            &shards,
            idx.num_shards(),
        )
        .is_err()
    );
}
