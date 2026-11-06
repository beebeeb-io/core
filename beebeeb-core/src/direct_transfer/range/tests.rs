//! `RangePlanner` unit tests, and the parity suite: `direct_transfer.json`'s grant refusals and
//! authority rows replayed against the range planner, which must judge every one exactly as the
//! whole-file planner does (it calls the same `grant_check::check_window`).

use chrono::DateTime;
use serde_json::Value;

use super::*;
use crate::direct_transfer::wire::{CAP_OBJECT_DOWNLOAD_V1, CHUNK_OVERHEAD, StorageBucket};

const API: &str = "https://api.beebeeb.test";
const FILE: &str = "11111111-1111-4111-8111-111111111111";
const VERSION: &str = "22222222-2222-4222-8222-222222222222";
const T0: i64 = 1_800_000_000_000;
const STRIDE: u64 = 8192;
const CHUNKS: u32 = 20;
const SHARE: u64 = 256 * 1024 * 1024;

fn geometry_of(chunk_count: u32) -> Geometry {
    let original = STRIDE * u64::from(chunk_count - 1) + 500;
    Geometry {
        chunk_count,
        chunk_size: STRIDE,
        encrypted_size: original + CHUNK_OVERHEAD * u64::from(chunk_count),
        original_size: original,
    }
}

fn discovery() -> Discovery {
    Discovery {
        download: vec![CAP_OBJECT_DOWNLOAD_V1.into()],
        storage_hosts: vec!["s3.storage.test".into()],
        storage_buckets: vec![StorageBucket {
            host: "s3.storage.test".into(),
            bucket: "bb-01".into(),
        }],
        max_window: Some(32),
        ..Default::default()
    }
}

fn planner(share: u64) -> RangePlanner {
    RangePlanner::new(
        RangeConfig::from_discovery(&discovery(), share, 7),
        discovery(),
        API,
        FILE,
        VERSION,
    )
}

fn rfc3339(ms: i64) -> String {
    DateTime::from_timestamp_millis(ms)
        .unwrap()
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

fn answer_for(g: Geometry, request: &DownloadGrantRequest, now_ms: i64) -> DownloadGrantResponse {
    let end = (request.start_index + request.count).min(g.chunk_count);
    DownloadGrantResponse {
        transport: CAP_OBJECT_DOWNLOAD_V1.into(),
        file_id: FILE.into(),
        object_version_id: VERSION.into(),
        chunk_count: g.chunk_count,
        chunk_size: g.chunk_size,
        encrypted_size: g.encrypted_size,
        original_size: g.original_size,
        grants: (request.start_index..end)
            .map(|i| ChunkGrant {
                index: i,
                method: "GET".into(),
                url: format!("https://s3.storage.test/bb-01/t/v/{i}.bin?X-Amz-Signature=SIG{i}"),
                length: g.chunk_length(i).unwrap(),
                expires_at: rfc3339(now_ms + 300_000),
            })
            .collect(),
        next_index: (end < g.chunk_count).then_some(end),
    }
}

fn window(p: &mut RangePlanner, now: i64, may_fetch: bool) -> DownloadGrantRequest {
    match p.poll_with(now, may_fetch) {
        RangePoll::RequestWindow(r) => r,
        other => panic!("expected a window request, got {other:?}"),
    }
}

fn fetch(p: &mut RangePlanner, now: i64) -> u32 {
    match p.poll(now) {
        RangePoll::Fetch { index, .. } => index,
        other => panic!("expected a fetch, got {other:?}"),
    }
}

/// Answer the outstanding window with the standard grants for `g`.
fn answer(p: &mut RangePlanner, g: Geometry, request: &DownloadGrantRequest, now: i64) {
    p.window_answered(answer_for(g, request, now), now).unwrap();
}

fn req(start_index: u32, count: u32, renewal: bool) -> DownloadGrantRequest {
    DownloadGrantRequest {
        object_version_id: Some(VERSION.into()),
        start_index,
        count,
        renewal,
    }
}

/// A planner with chunk 0 granted and the geometry known, after `demand`.
fn started(share: u64, chunk_count: u32, demand: (u64, u64)) -> (RangePlanner, Geometry) {
    let g = geometry_of(chunk_count);
    let mut p = planner(share);
    p.demand(1, demand.0, demand.1).unwrap();
    let first = window(&mut p, T0, true);
    assert_eq!(first, req(0, 1, false), "chunk 0 alone first, with the pin");
    answer(&mut p, g, &first, T0);
    (p, g)
}

#[test]
fn nothing_is_asked_before_a_demand() {
    let mut p = planner(SHARE);
    assert_eq!(p.poll(T0), RangePoll::Idle);
}

#[test]
fn a_seek_fetches_chunk_0_first_then_the_demand_then_the_last_chunk() {
    let (mut p, g) = started(SHARE, CHUNKS, (10 * STRIDE, STRIDE));
    assert_eq!(p.slots(), 16);
    assert_eq!(p.window_size(), 18, "min(32, max(8, 16 + 2))");
    let second = window(&mut p, T0, true);
    assert_eq!(
        second,
        req(10, 10, false),
        "the demand, then read-ahead to the end: grants only for wanted chunks"
    );
    assert_eq!(fetch(&mut p, T0), 0, "chunk 0 first (I3)");
    answer(&mut p, g, &second, T0);
    let order: Vec<u32> = (0..3).map(|_| fetch(&mut p, T0)).collect();
    assert_eq!(order, vec![10, 19, 11], "the demand, the last chunk, then forward");
}

#[test]
fn the_slots_bound_what_is_held_and_release_frees_one() {
    let (mut p, g) = started(2 * (STRIDE + CHUNK_OVERHEAD), CHUNKS, (0, u64::MAX));
    assert_eq!(p.slots(), 2);
    let w = window(&mut p, T0, true);
    assert_eq!(w.start_index, 1);
    assert_eq!(fetch(&mut p, T0), 0);
    answer(&mut p, g, &w, T0);
    assert_eq!(fetch(&mut p, T0), 1);
    assert!(matches!(p.poll(T0), RangePoll::Wait { .. }), "two held: no third fetch");
    p.fetch_ok(1).unwrap();
    p.released(1).unwrap();
    assert_eq!(fetch(&mut p, T0), 2, "a released chunk frees its slot, in any order");
    assert_eq!(p.held(), 2);
}

#[test]
fn no_budget_room_starts_no_fetch() {
    let (mut p, _) = started(SHARE, CHUNKS, (0, u64::MAX));
    let _ = window(&mut p, T0, false);
    assert_eq!(p.poll_with(T0, false), RangePoll::Wait { until_ms: None });
    assert_eq!(p.in_flight(), 0);
}

#[test]
fn every_chunk_released_is_done_and_a_whole_read_needs_no_read_ahead() {
    let (mut p, g) = started(SHARE, 3, (0, u64::MAX));
    let w = window(&mut p, T0, true);
    answer(&mut p, g, &w, T0);
    for _ in 0..3 {
        let i = fetch(&mut p, T0);
        p.fetch_ok(i).unwrap();
        p.released(i).unwrap();
    }
    assert_eq!(p.poll(T0), RangePoll::Done);
}

#[test]
fn cancel_with_no_demand_left_stops_read_ahead() {
    let (mut p, _) = started(SHARE, CHUNKS, (10 * STRIDE, 10));
    p.cancel(1);
    assert!(!p.reading_ahead());
    assert_eq!(p.poll(T0), RangePoll::Idle, "nothing wanted, nothing outstanding");
    p.demand(2, 3 * STRIDE, 10).unwrap();
    assert!(
        matches!(p.poll(T0), RangePoll::RequestWindow(_)),
        "a new demand starts it again"
    );
}

#[test]
fn a_gone_requester_drops_every_demand() {
    let (mut p, _) = started(SHARE, CHUNKS, (10 * STRIDE, 10));
    p.demand(2, 0, 10).unwrap();
    p.requester_gone();
    assert_eq!(p.demands(), 0);
    assert_eq!(p.poll(T0), RangePoll::Idle);
}

/// An idle grant ages out without spending the renewal budget; it is granted again only for a
/// demanded chunk, at most once per demand; a read-ahead chunk whose grant aged out asks for nothing.
#[test]
fn an_idle_grant_is_regranted_only_for_a_demand_and_once_per_demand() {
    let (mut p, g) = started(SHARE, CHUNKS, (5 * STRIDE, 10));
    let w = window(&mut p, T0, false);
    assert_eq!(w, req(5, 15, false));
    answer(&mut p, g, &w, T0);
    // Nothing fetched (no budget room); every grant ages out.
    let later = T0 + 300_000;
    assert_eq!(
        window(&mut p, later, false),
        req(0, 1, true),
        "chunk 0: every demand needs it"
    );
    answer(&mut p, g, &req(0, 1, true), later);
    assert_eq!(
        window(&mut p, later, false),
        req(5, 1, true),
        "the demanded chunk, alone"
    );
    answer(&mut p, g, &req(5, 1, true), later);
    assert_eq!(
        p.poll_with(later, false),
        RangePoll::Wait { until_ms: None },
        "read-ahead chunks whose grants aged out are not granted again"
    );
    // A new demand may re-grant its chunk once.
    p.demand(2, 6 * STRIDE, 10).unwrap();
    assert_eq!(window(&mut p, later, false), req(6, 1, true));
    answer(&mut p, g, &req(6, 1, true), later);
    // The same demand's re-grant ageing out again spends a renewal: a renewal window, not a loop.
    let again = later + 300_000;
    let w = window(&mut p, again, false);
    assert!(w.renewal);
    assert_eq!(w.start_index, 0);
}

#[test]
fn a_renewal_budget_spent_by_idle_regrants_ends_on_the_api_route() {
    let (mut p, g) = started(SHARE, 3, (0, 10));
    let mut now = T0;
    // Chunk 0's grant keeps ageing out under the same demand: once idle, then renewals.
    for _ in 0..8 {
        now += 300_000;
        match p.poll_with(now, false) {
            RangePoll::RequestWindow(r) => answer(&mut p, g, &r, now),
            RangePoll::Wait { .. } => {}
            other => panic!("unexpected {other:?}"),
        }
    }
    match p.poll(now) {
        RangePoll::FetchViaApi {
            index: 0,
            object_version_id,
        } => assert_eq!(object_version_id, VERSION),
        other => panic!("expected the pinned API route, got {other:?}"),
    }
}

#[test]
fn another_version_restarts_the_session() {
    let g = geometry_of(CHUNKS);
    let mut p = planner(SHARE);
    p.demand(1, 0, 10).unwrap();
    let w = window(&mut p, T0, true);
    let mut wrong = answer_for(g, &w, T0);
    wrong.object_version_id = "33333333-3333-4333-8333-333333333333".into();
    assert_eq!(p.window_answered(wrong, T0), Err(Violation::VersionChanged));
    assert_eq!(p.poll(T0), RangePoll::Stop(Verdict::Restart));
    let mut q = planner(SHARE);
    q.demand(1, 0, 10).unwrap();
    let _ = window(&mut q, T0, true);
    q.window_failed(Outcome::Restart, T0);
    assert_eq!(q.poll(T0), RangePoll::Stop(Verdict::Restart));
}

#[test]
fn an_unusable_window_moves_the_rest_to_the_pinned_api_route_four_at_once() {
    let (mut p, _) = started(SHARE, CHUNKS, (0, u64::MAX));
    let _ = window(&mut p, T0, true);
    p.window_failed(Outcome::ApiForThisFile, T0);
    let mut via_api = Vec::new();
    loop {
        match p.poll(T0) {
            RangePoll::FetchViaApi { index, .. } => via_api.push(index),
            RangePoll::Fetch { index, .. } => assert_eq!(index, 0, "chunk 0's grant is still usable"),
            RangePoll::Wait { .. } => break,
            other => panic!("unexpected {other:?}"),
        }
    }
    assert_eq!(via_api.len(), API_IN_FLIGHT as usize);
}

#[test]
fn without_a_geometry_an_unusable_window_or_forced_api_is_api_for_file() {
    let mut p = planner(SHARE);
    p.demand(1, 0, 10).unwrap();
    let _ = window(&mut p, T0, true);
    p.window_failed(Outcome::NotSupported, T0);
    assert_eq!(p.poll(T0), RangePoll::Stop(Verdict::ApiForFile));
    let mut q = planner(SHARE);
    q.force_api();
    q.demand(1, 0, 10).unwrap();
    assert_eq!(q.poll(T0), RangePoll::Stop(Verdict::ApiForFile));
    let mut r = planner(SHARE).with_geometry(geometry_of(3));
    r.force_api();
    r.demand(1, 0, 10).unwrap();
    assert!(matches!(r.poll(T0), RangePoll::FetchViaApi { index: 0, .. }));
}

#[test]
fn a_chunk_that_fails_to_open_twice_is_corrupt() {
    let (mut p, _) = started(SHARE, 1, (0, 10));
    assert_eq!(fetch(&mut p, T0), 0);
    p.fetch_ok(0).unwrap();
    p.chunk_unauthentic(0).unwrap();
    assert!(
        matches!(p.poll(T0), RangePoll::FetchViaApi { index: 0, .. }),
        "once through the API route"
    );
    p.fetch_ok(0).unwrap();
    p.chunk_unauthentic(0).unwrap();
    assert_eq!(p.poll(T0), RangePoll::Stop(Verdict::Corrupt));
}

#[test]
fn a_known_geometry_plans_the_first_window_from_the_demand() {
    let mut p = planner(SHARE).with_geometry(geometry_of(CHUNKS));
    p.demand(1, 10 * STRIDE, 10).unwrap();
    assert_eq!(
        window(&mut p, T0, true),
        req(0, 8, false),
        "chunk 0 first, then the wanted run after it (0..8; the demand's chunk 10 comes next)"
    );
}

// ─────────────────────────────── parity ───────────────────────────────

fn vectors() -> Value {
    serde_json::from_str(crate::direct_transfer::vectors::VECTORS_JSON).unwrap()
}

/// Every refusal row of `direct_transfer.json` ("answers that break the contract") is refused by
/// the range planner with the same code the whole-file planner gives.
#[test]
fn parity_the_grant_refusal_rows_are_refused_the_same_way() {
    let v = vectors();
    let t0 = v["t0_ms"].as_i64().unwrap();
    let file_id = v["file_id"].as_str().unwrap();
    let mut rows = 0;
    for scenario in v["planner"].as_array().unwrap() {
        let disc: Discovery =
            serde_json::from_value(v["discoveries"][scenario["discovery"].as_str().unwrap()].clone()).unwrap();
        for refusal in scenario["refusals"].as_array().into_iter().flatten() {
            let g = Geometry {
                chunk_count: 3,
                chunk_size: 1000,
                encrypted_size: 2584,
                original_size: 2500,
            };
            let mut p = RangePlanner::new(
                RangeConfig::from_discovery(&disc, SHARE, 7),
                disc.clone(),
                API,
                file_id,
                VERSION,
            )
            .with_geometry(g);
            p.demand(1, 0, 2500).unwrap();
            let RangePoll::RequestWindow(r) = p.poll(t0) else {
                panic!("a window first")
            };
            assert_eq!((r.start_index, r.count), (0, 3), "the window the rows were written for");
            let body = match refusal["body"].as_str() {
                Some(raw) => raw.as_bytes().to_vec(),
                None => serde_json::to_vec(&refusal["response"]).unwrap(),
            };
            let got = p.window_answered_bytes(&body, t0);
            assert_eq!(got.code(), refusal["expect"].as_str().unwrap(), "{}", refusal["name"]);
            rows += 1;
        }
    }
    assert_eq!(rows, 21, "every refusal row ran");
}

/// Every authority row's link, served as the grant of a one-chunk window, is accepted or refused
/// by the range planner exactly as `check_storage_url` judges it.
#[test]
fn parity_the_authority_rows_are_judged_the_same_way() {
    let v = vectors();
    let t0 = v["t0_ms"].as_i64().unwrap();
    let file_id = v["file_id"].as_str().unwrap();
    let mut rows = 0;
    for row in v["authority"].as_array().unwrap() {
        let disc: Discovery =
            serde_json::from_value(v["discoveries"][row["discovery"].as_str().unwrap()].clone()).unwrap();
        let api_base = row["api_base"].as_str().unwrap();
        let g = Geometry {
            chunk_count: 1,
            chunk_size: 1000,
            encrypted_size: 1028,
            original_size: 1000,
        };
        let mut p = RangePlanner::new(
            RangeConfig::from_discovery(&disc, SHARE, 7),
            disc,
            api_base,
            file_id,
            VERSION,
        );
        p.demand(1, 0, 1000).unwrap();
        let RangePoll::RequestWindow(r) = p.poll(t0) else {
            panic!("a window first")
        };
        let mut response = answer_for(g, &r, t0);
        response.file_id = file_id.into();
        response.grants[0].url = row["url"].as_str().unwrap().into();
        let got = p.window_answered_bytes(&serde_json::to_vec(&response).unwrap(), t0);
        let expect = match row["expect"].as_str().unwrap() {
            "ok" => "accepted".to_string(),
            refusal => format!("authority_{refusal}"),
        };
        assert_eq!(got.code(), expect, "{}", row["name"]);
        rows += 1;
    }
    assert_eq!(rows, 59, "every authority row ran");
}

/// Review finding 1: chunks after chunk 0 cannot be released before it, so they must never take
/// the last slot while chunk 0 still has to be fetched (again).
#[test]
fn a_failed_chunk_0_always_keeps_a_slot() {
    let (mut p, g) = started(2 * (STRIDE + CHUNK_OVERHEAD), CHUNKS, (0, u64::MAX));
    let w = window(&mut p, T0, true);
    assert_eq!(fetch(&mut p, T0), 0);
    answer(&mut p, g, &w, T0);
    assert_eq!(fetch(&mut p, T0), 1);
    p.fetch_ok(1).unwrap();
    p.fetch_failed(0, T0).unwrap();
    // From the moment of the failure: chunk 0 waits out its backoff while chunk 2 is granted.
    let mut now = T0;
    for _ in 0..20 {
        let polled = p.poll(now);
        now += 10_000;
        match polled {
            RangePoll::RequestWindow(r) => answer(&mut p, g, &r, now),
            RangePoll::Fetch { index, .. } => {
                assert_eq!(index, 0, "chunk 0 first; chunk {index} would starve it");
                return;
            }
            RangePoll::Wait { .. } => {}
            other => panic!("unexpected {other:?}"),
        }
    }
    panic!("chunk 0 was never fetched again");
}

/// Review finding 2: a re-grant window that fails does not use up the demand's re-grant.
#[test]
fn a_regrant_window_that_fails_is_asked_again() {
    let (mut p, g) = started(SHARE, CHUNKS, (5 * STRIDE, 10));
    let w = window(&mut p, T0, false);
    answer(&mut p, g, &w, T0);
    let later = T0 + 300_000;
    assert_eq!(window(&mut p, later, false), req(0, 1, true));
    p.window_failed(Outcome::Backoff(std::time::Duration::from_secs(1)), later);
    assert_eq!(
        window(&mut p, later + 2_000, false),
        req(0, 1, true),
        "the same re-grant, asked again"
    );
}

/// Delta review P1: chunk 0's storage GET fails while 15 later chunks wait for it (I3), then
/// another session's lease shrinks this session's share to 8 slots. Chunk 0 is fetched again
/// anyway, even with no budget room: it runs on the slot and the booking it kept. Otherwise
/// nothing could ever be released, and the session would hang with its demands unanswered (I7).
#[test]
fn chunk_0_is_fetched_again_after_the_share_shrank_below_what_is_held() {
    let chunk = STRIDE + CHUNK_OVERHEAD;
    let (mut p, g) = started(16 * chunk, CHUNKS, (0, u64::MAX));
    assert_eq!(p.slots(), 16);
    let w = window(&mut p, T0, true);
    assert_eq!(fetch(&mut p, T0), 0);
    answer(&mut p, g, &w, T0);
    for _ in 0..15 {
        let index = fetch(&mut p, T0);
        p.fetch_ok(index).unwrap();
    }
    assert_eq!(p.held(), 16);
    p.fetch_failed(0, T0).unwrap();
    p.set_share(8 * chunk);
    assert_eq!((p.slots(), p.held()), (8, 15));
    let mut now = T0;
    for _ in 0..50 {
        match p.poll_with(now, false) {
            RangePoll::RequestWindow(r) => answer(&mut p, g, &r, now),
            RangePoll::Fetch { index, .. } => {
                assert_eq!(index, 0, "only chunk 0 runs on a kept booking");
                return;
            }
            RangePoll::Wait { until_ms } => now = until_ms.unwrap_or(now + 1_000),
            other => panic!("unexpected {other:?}"),
        }
    }
    panic!("chunk 0 was never fetched again: nothing can be released, the session hangs");
}

/// Delta review P1, the other half: no later chunk starts before chunk 0 has (here chunk 0's grant
/// aged out unused while the later grants are still good), so chunks waiting for chunk 0 never
/// hold room that chunk 0 then lacks.
#[test]
fn no_later_chunk_starts_before_chunk_0_has() {
    let (mut p, g) = started(SHARE, CHUNKS, (5 * STRIDE, 10));
    let w = window(&mut p, T0, false);
    assert_eq!(w, req(5, 15, false));
    answer(&mut p, g, &w, T0 + 60_000);
    // Chunk 0's grant (from T0) is past its usable window; 5..19 (from T0 + 60 s) are not.
    let later = T0 + 300_000 - RENEW_SKEW_MS;
    assert_eq!(
        window(&mut p, later, true),
        req(0, 1, true),
        "chunk 0 again, for the demand"
    );
    assert_eq!(
        p.poll(later),
        RangePoll::Wait { until_ms: None },
        "chunk 5 waits for chunk 0"
    );
    answer(&mut p, g, &req(0, 1, true), later);
    assert_eq!(fetch(&mut p, later), 0);
    assert_eq!(fetch(&mut p, later), 5);
}

/// Delta review P3: a storage failure on an idle re-grant keeps its demand, so when the renewed
/// grant ages out unused it spends a renewal instead of earning the demand a second free re-grant.
#[test]
fn a_failed_regrant_is_still_that_demands_one_regrant() {
    let (mut p, g) = started(SHARE, CHUNKS, (5 * STRIDE, 10));
    let w = window(&mut p, T0, false);
    answer(&mut p, g, &w, T0);
    let later = T0 + 300_000;
    assert_eq!(
        window(&mut p, later, false),
        req(0, 1, true),
        "chunk 0's re-grant for demand 1"
    );
    answer(&mut p, g, &req(0, 1, true), later);
    assert_eq!(window(&mut p, later, true), req(5, 1, true));
    assert_eq!(fetch(&mut p, later), 0);
    p.fetch_failed(0, later).unwrap();
    assert!(
        matches!(
            p.slots.get(&0),
            Some(Slot::NeedsGrant {
                regranted_for: Some(1),
                ..
            })
        ),
        "the failed re-grant keeps its demand: {:?}",
        p.slots.get(&0)
    );
    answer(&mut p, g, &req(5, 1, true), later);
    // The renewal after the backoff, then that grant ages out unused.
    let mut now = later;
    loop {
        match p.poll_with(now, false) {
            RangePoll::RequestWindow(r) => {
                assert_eq!(r, req(0, 1, true));
                answer(&mut p, g, &r, now);
                break;
            }
            RangePoll::Wait { until_ms: Some(at) } => now = at,
            other => panic!("unexpected {other:?}"),
        }
    }
    now += 300_000;
    assert_eq!(window(&mut p, now, false), req(0, 1, true));
    assert!(
        matches!(p.slots.get(&0), Some(Slot::NeedsGrant { attempts, .. }) if attempts.renewals == 2),
        "the second age-out spent a renewal (one for the failure, one now): {:?}",
        p.slots.get(&0)
    );
}

/// Self-review: a closed demand's re-grant mark goes with it. A later demand that reuses the id
/// gets its chunks granted again; before, `Idle { regranted_for: Some(id) }` made the planner
/// skip them, and the demand was never answered (I7).
#[test]
fn a_demand_that_reuses_a_closed_id_is_granted_again() {
    let (mut p, g) = started(SHARE, CHUNKS, (5 * STRIDE, 10));
    let w = window(&mut p, T0, false);
    answer(&mut p, g, &w, T0);
    let later = T0 + 300_000;
    assert_eq!(window(&mut p, later, false), req(0, 1, true));
    answer(&mut p, g, &req(0, 1, true), later);
    assert_eq!(window(&mut p, later, false), req(5, 1, true));
    answer(&mut p, g, &req(5, 1, true), later);
    p.demand_met(1);
    // Both re-grants age out unused while no demand is open; then a new read comes in under the
    // same id.
    let again = later + 300_000;
    assert_eq!(p.poll_with(again, false), RangePoll::Wait { until_ms: None });
    assert!(
        matches!(p.slots.get(&5), Some(Slot::Idle { .. })),
        "{:?}",
        p.slots.get(&5)
    );
    p.demand(1, 5 * STRIDE, 10).unwrap();
    assert_eq!(
        window(&mut p, again, false),
        req(0, 1, true),
        "chunk 0 for the new demand"
    );
    answer(&mut p, g, &req(0, 1, true), again);
    assert_eq!(window(&mut p, again, false), req(5, 1, true), "and its own chunk");
}

/// Self-review: the planner says it waits for budget room only when a fetch could have started.
/// A session whose read-ahead stalled at aged-out grants is not waiting for room (it gives its
/// lease back); one with a granted chunk and no room is.
#[test]
fn waits_for_room_only_when_a_fetch_could_start() {
    let (mut p, _) = started(SHARE, CHUNKS, (0, 10));
    let _ = window(&mut p, T0, false);
    assert_eq!(p.poll_with(T0, false), RangePoll::Wait { until_ms: None });
    assert!(p.waits_for_room(), "chunk 0 is granted; only room is missing");
    assert_eq!(fetch(&mut p, T0), 0);
    assert!(!p.waits_for_room());

    let (mut q, _) = started(SHARE, CHUNKS, (0, 10));
    q.demand_met(1);
    let later = T0 + 300_000;
    assert!(matches!(
        q.poll_with(later, false),
        RangePoll::Wait { .. } | RangePoll::Idle
    ));
    assert!(
        !q.waits_for_room(),
        "read-ahead stalled at an aged-out grant: nothing could start"
    );
}
