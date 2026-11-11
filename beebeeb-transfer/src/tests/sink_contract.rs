//! Round 2 of the review: the sink contract. Moved out of `tests.rs` to keep
//! that file under its size baseline.

use super::*;

// ----------------------- round 2: the sink contract -----------------------

pub(super) async fn run_with_sink(
    io: &ScriptedIo,
    shared: &DirectShared,
    request: DownloadRequest,
    fx: &Fixture,
    sink: &mut dyn PlaintextSink,
    events: &Events,
) -> Result<DownloadOutcome, DownloadError> {
    let decryptor = fx.decryptor();
    download(io, shared, request, decryptor, sink, events).await
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Trigger {
    PinnedGiveUp,
    Refill404,
    PinnedRestart,
    Pinned401,
    VersionChanged,
    SinkWriteError,
}

/// A 12-chunk file whose attempt writes chunk 0 and then fails at the trigger.
/// The first window holds 8 chunks, so the refill happens only after chunks
/// 0..3 are consumed: every trigger has plaintext in the sink.
fn scenario(trigger: Trigger) -> (ScriptedIo, DownloadRequest, Arc<Fixture>) {
    let plain: Vec<u8> = (0..12 * 1024).map(|i| (i % 241) as u8).collect();
    let fx = Arc::new(Fixture::new(&plain, 1024));
    let storage_fails = matches!(
        trigger,
        Trigger::PinnedGiveUp | Trigger::PinnedRestart | Trigger::Pinned401
    );
    let io = ScriptedIo::new({
        let fx = fx.clone();
        move |req, wall, _mono| match req {
            Request::Api(call) if call.path == DISCOVERY_PATH => discovery_reply_window(8),
            Request::Api(call) if call.path == beebeeb_core::direct_transfer::download_grants_path(FILE_ID) => {
                let request = grant_body(call);
                if trigger == Trigger::Refill404 && request.start_index > 0 {
                    return json_reply(404, serde_json::json!({"error": "not_found"}));
                }
                let mut window = fx.window(request.start_index, request.count, wall);
                if trigger == Trigger::VersionChanged && request.start_index > 0 {
                    window["object_version_id"] = serde_json::json!("33333333-4444-4555-8666-777777777777");
                }
                json_reply(200, window)
            }
            Request::StorageGet { url, .. } => {
                if storage_fails && url_index(url) > 0 {
                    Reply::Storage(StorageReply {
                        status: 0,
                        content_length: None,
                        body: None,
                    })
                } else {
                    fx.storage_reply(url)
                }
            }
            Request::Api(call) if pinned_index(&call.path).is_some() => match trigger {
                Trigger::PinnedGiveUp => json_reply(503, serde_json::json!({"error": "busy"})),
                Trigger::PinnedRestart => Reply::Api(ApiReply {
                    status: 409,
                    content_type: None,
                    retry_after: None,
                    body: Vec::new(),
                }),
                Trigger::Pinned401 => json_reply(401, serde_json::json!({"error": "unauthorized"})),
                _ => bytes_reply(200, fx.frames[pinned_index(&call.path).unwrap() as usize].clone()),
            },
            other => panic!("unexpected request {other:?}"),
        }
    });
    let mut request = request_for(&fx);
    request.jitter_seed = 231;
    (io, request, fx)
}

fn sink_for(trigger: Trigger, discardable: bool) -> MockSink {
    let mut sink = if discardable {
        MockSink::discardable()
    } else {
        MockSink::non_discardable()
    };
    if trigger == Trigger::SinkWriteError {
        sink.partial_error_on_write = Some(2);
    }
    sink
}

#[tokio::test]
async fn every_failure_after_a_write_follows_the_sink_table() {
    for trigger in [
        Trigger::PinnedGiveUp,
        Trigger::Refill404,
        Trigger::PinnedRestart,
        Trigger::Pinned401,
        Trigger::VersionChanged,
        Trigger::SinkWriteError,
    ] {
        // Discardable: the original outcome stands and the sink is emptied.
        let (io, request, fx) = scenario(trigger);
        let mut sink = sink_for(trigger, true);
        let outcome = run_with_sink(&io, &DirectShared::new(), request, &fx, &mut sink, &Events::default()).await;
        assert_eq!(sink.discard_calls, 1, "{trigger:?}: discard called exactly once");
        assert!(sink.data.is_empty(), "{trigger:?}: the sink is empty");
        match trigger {
            Trigger::PinnedGiveUp | Trigger::Refill404 => assert!(
                matches!(outcome, Ok(DownloadOutcome::UseApi(UseApiReason::ApiForFile))),
                "{trigger:?}: {outcome:?}"
            ),
            Trigger::PinnedRestart | Trigger::VersionChanged => {
                assert!(
                    matches!(outcome, Err(DownloadError::FileChanged)),
                    "{trigger:?}: {outcome:?}"
                )
            }
            Trigger::Pinned401 => {
                assert!(
                    matches!(outcome, Err(DownloadError::Unauthorized)),
                    "{trigger:?}: {outcome:?}"
                )
            }
            Trigger::SinkWriteError => {
                assert!(
                    matches!(outcome, Err(DownloadError::Sink(_))),
                    "{trigger:?}: {outcome:?}"
                )
            }
        }

        // Non-discardable: an honest failure, the original cause inside.
        let (io, request, fx) = scenario(trigger);
        let mut sink = sink_for(trigger, false);
        let outcome = run_with_sink(&io, &DirectShared::new(), request, &fx, &mut sink, &Events::default()).await;
        let Err(DownloadError::DirectFailedAfterWrite {
            written_plaintext_bytes,
            chunks_written,
            cause,
        }) = outcome
        else {
            panic!("{trigger:?}: expected DirectFailedAfterWrite, got {outcome:?}");
        };
        assert!(written_plaintext_bytes > 0, "{trigger:?}: bytes counted");
        assert!(chunks_written >= 1, "{trigger:?}: chunks counted");
        assert_eq!(sink.discard_calls, 0, "{trigger:?}: discard never called");
        let cause_is_api = matches!(cause, AfterWriteCause::ApiNeeded(_));
        assert_eq!(
            cause_is_api,
            matches!(trigger, Trigger::PinnedGiveUp | Trigger::Refill404),
            "{trigger:?}: cause {cause:?}"
        );
    }
}

#[tokio::test]
async fn a_cancelled_download_discards_a_discardable_sink_and_never_the_other() {
    let plain: Vec<u8> = (0..4 * 1024).map(|i| (i % 199) as u8).collect();
    let fx = Arc::new(Fixture::new(&plain, 1024));
    let make_io = || {
        ScriptedIo::new({
            let fx = fx.clone();
            move |req, wall, _mono| match req {
                Request::Api(call) if call.path == DISCOVERY_PATH => discovery_reply(),
                Request::Api(call) if call.path == beebeeb_core::direct_transfer::download_grants_path(FILE_ID) => {
                    let request = grant_body(call);
                    json_reply(200, fx.window(request.start_index, request.count, wall))
                }
                Request::StorageGet { url, .. } => fx.storage_reply(url),
                other => panic!("unexpected request {other:?}"),
            }
        })
        .with_storage_delay_for(1, 10_000)
    };

    let io = make_io();
    let mut sink = MockSink::discardable();
    let events = Events::default();
    let request = request_for(&fx);
    let decryptor = fx.decryptor();
    let shared = DirectShared::new();
    let future = download(&io, &shared, request, decryptor, &mut sink, &events);
    assert!(future.now_or_never().is_none(), "the download is pending");
    assert_eq!(sink.discard_calls, 1, "a cancelled attempt discards");

    let io = make_io();
    let mut sink = MockSink::non_discardable();
    let request = request_for(&fx);
    let events = Events::default();
    let decryptor = fx.decryptor();
    let shared = DirectShared::new();
    let future = download(&io, &shared, request, decryptor, &mut sink, &events);
    assert!(future.now_or_never().is_none(), "the download is pending");
    assert_eq!(sink.discard_calls, 0, "a non-discardable sink is left alone");
}

#[tokio::test]
async fn a_discarded_sink_refuses_writes() {
    let mut sink = MockSink::discardable();
    sink.write(b"abc").unwrap();
    sink.discard().unwrap();
    assert!(sink.write(b"d").is_err(), "a discarded sink refuses writes");
}

#[tokio::test]
async fn a_sink_whose_discard_fails_still_refuses_writes() {
    let mut sink = MockSink::failing_discard();
    sink.write(b"abc").unwrap();
    assert!(sink.discard().is_err());
    assert!(sink.write(b"d").is_err(), "a failed discard still marks the sink dead");
}

#[tokio::test]
async fn a_failed_discard_keeps_the_original_error() {
    let (io, request, fx) = scenario(Trigger::Pinned401);
    let mut sink = MockSink::failing_discard();
    let events = Events::default();
    let outcome = run_with_sink(&io, &DirectShared::new(), request, &fx, &mut sink, &events).await;
    assert!(matches!(outcome, Err(DownloadError::Unauthorized)), "{outcome:?}");
    assert_eq!(sink.discard_calls, 1);
    let events = events.0.lock().unwrap().clone();
    assert!(
        events.iter().any(|e| matches!(e, TransferEvent::DiscardFailed { .. })),
        "a failed discard is reported as its own event: {events:?}"
    );
    assert!(
        !events.iter().any(|e| matches!(e, TransferEvent::Discarded { .. })),
        "a failed discard is never reported as a successful rollback: {events:?}"
    );
}

#[tokio::test]
async fn a_partial_write_error_counts_as_written() {
    // The FIRST write fails after accepting half of its bytes: no full byte
    // was counted, but the sink is dirty and must not be treated as untouched.
    let fx = Arc::new(Fixture::new(&vec![9u8; 1024], 1024));
    let io = ScriptedIo::new(standard_handler(fx.clone()));
    let mut sink = MockSink::non_discardable();
    sink.partial_error_on_write = Some(1);
    let outcome = run_with_sink(
        &io,
        &DirectShared::new(),
        request_for(&fx),
        &fx,
        &mut sink,
        &Events::default(),
    )
    .await;
    let Err(DownloadError::DirectFailedAfterWrite {
        written_plaintext_bytes,
        chunks_written,
        cause,
    }) = outcome
    else {
        panic!("a partial write counts as written: {outcome:?}");
    };
    assert_eq!(
        written_plaintext_bytes, 1024,
        "the bytes handed to the failing write may be on the output"
    );
    assert_eq!(chunks_written, 1, "the failing write counts");
    assert!(matches!(cause, AfterWriteCause::Failed(_)));
    assert_eq!(sink.discard_calls, 0);
}

#[tokio::test]
async fn no_message_after_a_write_says_nothing_was_written() {
    let errors = [
        DownloadError::Unauthorized,
        DownloadError::Forbidden,
        DownloadError::FileChanged,
        DownloadError::Unauthentic { index: 3 },
        DownloadError::Truncated,
        DownloadError::Sink(std::io::Error::other("closed")),
        DownloadError::DirectFailedAfterWrite {
            written_plaintext_bytes: 1024,
            chunks_written: 1,
            cause: AfterWriteCause::ApiNeeded(UseApiReason::ApiForFile),
        },
        DownloadError::DirectFailedAfterWrite {
            written_plaintext_bytes: 1024,
            chunks_written: 1,
            cause: AfterWriteCause::Failed(Box::new(DownloadError::FileChanged)),
        },
        DownloadError::DirectFailedAfterWrite {
            written_plaintext_bytes: 0,
            chunks_written: 1,
            cause: AfterWriteCause::ApiNeeded(UseApiReason::ApiForFile),
        },
    ];
    for error in errors {
        let text = format!("{error} {error:?}");
        assert!(!text.to_ascii_lowercase().contains("nothing was written"), "{text}");
        if let DownloadError::DirectFailedAfterWrite { chunks_written, .. } = &error
            && *chunks_written > 0
        {
            assert!(
                !text.contains("after 0 bytes"),
                "a write was attempted, so the message must not claim zero bytes: {text}"
            );
        }
    }
}

#[tokio::test]
async fn discarded_events_carry_the_rolled_back_bytes() {
    let (io, request, fx) = scenario(Trigger::Refill404);
    let mut sink = MockSink::discardable();
    let events = Events::default();
    let outcome = run_with_sink(&io, &DirectShared::new(), request, &fx, &mut sink, &events).await;
    assert!(matches!(outcome, Ok(DownloadOutcome::UseApi(_))), "{outcome:?}");
    let discarded: Vec<TransferEvent> = events
        .0
        .lock()
        .unwrap()
        .iter()
        .filter(|e| matches!(e, TransferEvent::Discarded { .. }))
        .cloned()
        .collect();
    assert_eq!(discarded.len(), 1, "{discarded:?}");
    let TransferEvent::Discarded {
        plaintext_bytes,
        ciphertext_bytes,
    } = discarded[0]
    else {
        unreachable!()
    };
    assert!(plaintext_bytes > 0);
    assert_eq!(
        ciphertext_bytes,
        plaintext_bytes + 28 * (plaintext_bytes / 1024),
        "the rolled-back ciphertext includes the per-chunk overhead"
    );
}
