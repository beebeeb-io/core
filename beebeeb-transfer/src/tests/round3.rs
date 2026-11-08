//! Round 3 of the review: the discovery flight under cancellation, and truncated
//! streams, cancel bookkeeping and chunk-index drift.

use super::*;

// ----------------------- round 3: the discovery flight -----------------------

/// Poll `future` at most `budget` times. A hang shows as `None`, never as a
/// wall-clock timeout.
fn poll_bounded<F: std::future::Future>(mut future: std::pin::Pin<&mut F>, budget: usize) -> Option<F::Output> {
    let waker = futures_util::task::noop_waker();
    let mut cx = std::task::Context::from_waker(&waker);
    for _ in 0..budget {
        if let std::task::Poll::Ready(output) = future.as_mut().poll(&mut cx) {
            return Some(output);
        }
    }
    None
}

#[tokio::test]
async fn a_cancelled_discovery_leader_does_not_hang_the_next_download() {
    let fx = Arc::new(Fixture::new(&vec![4u8; 2048], 2048));
    let shared = DirectShared::new();

    // The leader's discovery call never answers: its future is dropped
    // mid-flight (a cancel) before the scripted clock moves.
    let leader_io = ScriptedIo::new(standard_handler(fx.clone())).with_api_delay(50);
    let mut leader_sink = VecSink::default();
    let leader_events = Events::default();
    let leader_decryptor = fx.decryptor();
    let leader = download(
        &leader_io,
        &shared,
        request_for(&fx),
        leader_decryptor,
        &mut leader_sink,
        &leader_events,
    );
    assert!(leader.now_or_never().is_none(), "the leader is pending in discovery");

    // The next download is not stuck behind the abandoned flight.
    let io = ScriptedIo::new(standard_handler(fx.clone()));
    let mut sink = VecSink::default();
    let events = Events::default();
    let decryptor = fx.decryptor();
    let mut second = Box::pin(download(&io, &shared, request_for(&fx), decryptor, &mut sink, &events));
    let outcome = poll_bounded(second.as_mut(), 100).expect("the next download completes within the poll budget");
    drop(second);
    assert!(matches!(outcome, Ok(DownloadOutcome::Done(_))), "{outcome:?}");
    assert_eq!(sink.0.len(), 2048, "the whole file is written");
}

#[tokio::test]
async fn a_follower_polled_repeatedly_keeps_one_waiter() {
    let shared = DirectShared::new();
    assert!(
        matches!(shared.discovery_start(WALL_START_MS), DiscoveryStart::Lead),
        "the test is the leader"
    );
    let mut follow = Box::pin(shared.discovery_follow());
    let waker = futures_util::task::noop_waker();
    let mut cx = std::task::Context::from_waker(&waker);
    for _ in 0..8 {
        assert!(
            follow.as_mut().poll(&mut cx).is_pending(),
            "the flight is still running"
        );
    }
    assert_eq!(shared.discovery_waiters(), 1, "one waiter, not one per poll");
    drop(follow);
    shared.discovery_finished(DiscoveryFlightResult::Unavailable, WALL_START_MS);
}

// ----------------------- round 3: truncation, cancel, index drift -----------------------

#[tokio::test]
async fn a_v2_stream_that_ends_before_its_last_chunk_is_truncated() {
    let plain: Vec<u8> = (0..3 * 1024).map(|i| (i % 239) as u8).collect();
    let fx = Arc::new(Fixture::truncated_v2(&plain, 1024, 2));
    let make_decryptor = || {
        ChunkDecryptor::for_version_with_file_key(
            FileKey::from_bytes(KEY),
            FILE_ID,
            ExpectedChunkFormat::V2,
            fx.version(),
        )
    };

    // Discardable: the original `Truncated` stands and the plaintext is gone.
    let io = ScriptedIo::new(standard_handler(fx.clone()));
    let mut sink = MockSink::discardable();
    let events = Events::default();
    let outcome = download(
        &io,
        &DirectShared::new(),
        request_for(&fx),
        make_decryptor(),
        &mut sink,
        &events,
    )
    .await;
    assert!(matches!(outcome, Err(DownloadError::Truncated)), "{outcome:?}");
    assert_eq!(sink.discard_calls, 1, "the written prefix is discarded");
    assert!(sink.data.is_empty());

    // Non-discardable: the table row, with the cause inside.
    let io = ScriptedIo::new(standard_handler(fx.clone()));
    let mut sink = MockSink::non_discardable();
    let events = Events::default();
    let outcome = download(
        &io,
        &DirectShared::new(),
        request_for(&fx),
        make_decryptor(),
        &mut sink,
        &events,
    )
    .await;
    let Err(DownloadError::DirectFailedAfterWrite {
        written_plaintext_bytes,
        chunks_written,
        cause,
    }) = outcome
    else {
        panic!("a non-discardable sink gets an honest failure: {outcome:?}");
    };
    assert_eq!(written_plaintext_bytes, 2 * 1024);
    assert_eq!(chunks_written, 2);
    assert!(
        matches!(&cause, AfterWriteCause::Failed(error) if matches!(**error, DownloadError::Truncated)),
        "{cause:?}"
    );
    assert_eq!(sink.discard_calls, 0);
}

#[tokio::test]
async fn a_cancelled_download_records_the_storage_breaker() {
    let plain: Vec<u8> = (0..2 * 1024).map(|i| (i % 233) as u8).collect();
    let fx = Arc::new(Fixture::new(&plain, 1024));
    let pinned = pinned_chunk_path(FILE_ID, 0, VERSION).expect("a pinned path");
    let io = ScriptedIo::new({
        let fx = fx.clone();
        move |req, wall, _mono| match req {
            Request::Api(call) if call.path == DISCOVERY_PATH => discovery_reply(),
            Request::Api(call) if call.path == beebeeb_core::direct_transfer::download_grants_path(FILE_ID) => {
                let request = grant_body(call);
                json_reply(200, fx.window(request.start_index, request.count, wall))
            }
            Request::StorageGet { .. } => Reply::Storage(StorageReply {
                status: 0,
                content_length: None,
                body: None,
            }),
            Request::Api(call) if pinned_index(&call.path).is_some() => {
                bytes_reply(200, fx.frames[pinned_index(&call.path).unwrap() as usize].clone())
            }
            other => panic!("unexpected request {other:?}"),
        }
    })
    .with_api_delay_for(pinned, 50);
    let shared = DirectShared::new();
    let mut sink = MockSink::discardable();
    let events = Events::default();
    let decryptor = fx.decryptor();
    let future = download(&io, &shared, request_for(&fx), decryptor, &mut sink, &events);
    assert!(
        future.now_or_never().is_none(),
        "the download is pending on the pinned route after storage gave up"
    );

    let second = ScriptedIo::new(|_: &Request, _: i64, _: i64| panic!("a held download made a request"));
    second.set_wall(io.wall_now() + 1_000);
    second.set_mono(io.mono_now() + 1_000);
    let (held, _, _) = run_download(&second, &shared, request_for(&fx), &fx).await;
    assert!(
        matches!(held, Ok(DownloadOutcome::UseApi(UseApiReason::BreakerHold))),
        "the cancelled download recorded the breaker: {held:?}"
    );
    assert!(second.requests().is_empty(), "no storage request while held");
}

#[test]
fn a_decrypted_chunk_with_another_index_is_unauthentic() {
    assert!(unexpected_chunk(2, 2).is_none(), "the expected index passes");
    assert!(
        matches!(unexpected_chunk(3, 2), Some(DownloadError::Unauthentic { index: 2 })),
        "a drifted index fails at the planner's next chunk"
    );
}
