//! Staged files and the service's life: every staged file deleted on each
//! path (done, stopped, failed, a retried entry, a dropped service, an
//! earlier process), 0600, one live service per temp root, and a stop
//! that backpressure does not hold.

use super::*;

#[tokio::test]
async fn archive_service_temp_files_deleted() {
    let data = fixture("plain.zip");
    // Done.
    let server = Server::new();
    let file = put_v2(
        &server,
        "bbbbbbbb-0000-4000-8000-000000000008",
        "plain.zip",
        None,
        &data,
        256,
    );
    let mut env = Env::with_server(server);
    let id = env.open_listed(&file, "plain.zip", None).await;
    let run = env
        .service
        .extract(id, options(ExtractDestination::NextToArchive), None)
        .await
        .unwrap();
    assert_eq!(env.pump_until_finished(run).await.outcome, ExtractOutcome::Done);
    assert_eq!(env.temp_files(), 0, "after Done");

    // Stopped with every file staged and queued.
    let server = Server::new();
    let file = put_v2(
        &server,
        "bbbbbbbb-0000-4000-8000-000000000009",
        "plain.zip",
        None,
        &data,
        256,
    );
    let mut env = Env::with_server(server);
    let id = env.open_listed(&file, "plain.zip", None).await;
    let run = env
        .service
        .extract(id, options(ExtractDestination::NextToArchive), None)
        .await
        .unwrap();
    env.queued_uploads(5).await;
    assert_eq!(env.temp_files(), 5, "five files staged");
    #[cfg(unix)]
    for entry in std::fs::read_dir(env.root.path().join("archives")).unwrap() {
        use std::os::unix::fs::PermissionsExt;
        let mode = entry.unwrap().metadata().unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "staged files are this user's only");
    }
    env.service.cancel(run);
    assert_eq!(env.finished(run).await.outcome, ExtractOutcome::Stopped);
    assert_eq!(env.temp_files(), 0, "after Stopped");

    // Failed (storage full) with files still queued.
    let server = Server::new();
    let file = put_v2(
        &server,
        "bbbbbbbb-0000-4000-8000-00000000000a",
        "plain.zip",
        None,
        &data,
        256,
    );
    server.state.lock().unwrap().uploads_left = Some(0);
    let mut env = Env::with_server(server);
    let id = env.open_listed(&file, "plain.zip", None).await;
    let run = env
        .service
        .extract(id, options(ExtractDestination::NextToArchive), None)
        .await
        .unwrap();
    let summary = env.pump_until_finished(run).await;
    assert_eq!(summary.outcome, ExtractOutcome::Failed(FailReason::StorageFull));
    assert_eq!(env.temp_files(), 0, "after Failed");

    // What an earlier process left is gone when the service starts: its
    // queued upload is cancelled and its staged file deleted; other files
    // stay. A second live service on the same root is refused.
    let root = env.root.path().join("archives");
    let leftover = root.join("archive-0123456789abcdef0123456789abcdef-1-1.bbtmp");
    std::fs::write(&leftover, b"plaintext").unwrap();
    let other = root.join("other.txt");
    std::fs::write(&other, b"not the service's").unwrap();
    let now = transfer_now_ms().unwrap();
    let queued = env
        .uploads
        .enqueue(UploadRequest::new(&leftover, "left.txt", None, None), now)
        .unwrap();
    let new_service = || {
        ArchiveService::new(
            Arc::new(Client::new(ClientConfig::for_tests(), Arc::new(Server::new())).unwrap()),
            Arc::clone(&env.downloads),
            Arc::clone(&env.uploads),
            root.clone(),
            ArchivePlatform::MobileApp,
        )
    };
    assert!(
        matches!(new_service(), Err(ArchiveServiceError::State)),
        "one live service per root"
    );
    drop(env.service);
    let _service = new_service().unwrap();
    assert!(!leftover.exists());
    assert!(other.exists());
    let state = env
        .uploads
        .list()
        .unwrap()
        .into_iter()
        .find(|u| u.id == queued)
        .unwrap()
        .state;
    assert_eq!(state, TransferState::Cancelled);
}

#[tokio::test]
async fn archive_service_stop_is_not_held_by_backpressure() {
    // Unpacking outruns uploading: once the staged bytes pass the limit
    // the run waits for uploads. A stop must not wait with it (on cellular
    // with Wi-Fi only, nothing drains).
    let server = Server::new();
    let file = put_v2(
        &server,
        "bbbbbbbb-0000-4000-8000-00000000000d",
        "notes.txt.gz",
        None,
        &fixture("notes.txt.gz"),
        256,
    );
    let mut env = Env::with_server(server);
    env.service.set_staging_ahead_for_test(1);
    let id = env.open_listed(&file, "notes.txt.gz", None).await;
    let run = env
        .service
        .extract(id, options(ExtractDestination::NextToArchive), None)
        .await
        .unwrap();
    env.queued_uploads(1).await;
    env.service.cancel(run);
    assert_eq!(env.finished(run).await.outcome, ExtractOutcome::Stopped);
    assert_eq!(env.temp_files(), 0);
    assert!(
        env.uploads
            .list()
            .unwrap()
            .iter()
            .all(|u| u.state == TransferState::Cancelled)
    );
}

#[tokio::test]
async fn archive_service_dropped_stops_its_runs() {
    // Sign-out or a new handle drops the service: its run stops, cancels
    // its queued uploads and deletes what it staged, without waiting for
    // the next service to start.
    let server = Server::new();
    let file = put_v2(
        &server,
        "bbbbbbbb-0000-4000-8000-00000000000e",
        "plain.zip",
        None,
        &fixture("plain.zip"),
        256,
    );
    let mut env = Env::with_server(server);
    let id = env.open_listed(&file, "plain.zip", None).await;
    let run = env
        .service
        .extract(id, options(ExtractDestination::NextToArchive), None)
        .await
        .unwrap();
    env.queued_uploads(5).await;
    drop(env.service);
    let summary = loop {
        match tokio::time::timeout(Duration::from_secs(10), env.events.recv()).await {
            Ok(Ok(ArchiveEvent::Finished { id, summary })) if id == run => break summary,
            Ok(Ok(_)) => {}
            other => panic!("no Finished within 10 s: {other:?}"),
        }
    };
    assert_eq!(summary.outcome, ExtractOutcome::Stopped);
    assert_eq!(std::fs::read_dir(env.root.path().join("archives")).unwrap().count(), 0);
    assert!(
        env.uploads
            .list()
            .unwrap()
            .iter()
            .all(|u| u.state == TransferState::Cancelled)
    );
}

/// A wrong password that passes entry `index`'s check byte: found by a
/// fixed search, so the same one every run.
fn quick_check_candidate(data: &[u8], index: u32) -> String {
    /// The archive's bytes, all at hand.
    struct Whole(Vec<u8>);
    impl ByteSource for Whole {
        fn len(&self) -> u64 {
            self.0.len() as u64
        }
        fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<usize, SourceError> {
            let start = (offset as usize).min(self.0.len());
            let n = buf.len().min(self.0.len() - start);
            buf[..n].copy_from_slice(&self.0[start..start + n]);
            Ok(n)
        }
    }
    let mut session = ArchiveSession::open(Whole(data.to_vec()), ArchivePlatform::Native);
    assert_eq!(session.step(), SessionStep::Listed);
    (0..100_000)
        .map(|i| format!("candidate-{i}"))
        .find(|c| session.check_password(index, &ArchivePassword::new(c.clone())) == PasswordStep::Accepted)
        .expect("about one in 256 candidates passes a check byte")
}

#[tokio::test]
async fn archive_service_failed_attempt_leaves_no_staged_file() {
    // A wrong password that passes the entry's check byte is read to the
    // end and fails its CRC: what it staged is deleted before the person
    // is asked again, and the entry is read again with the new password.
    let data = fixture("zipcrypto-crc-check.zip");
    let wrong = quick_check_candidate(&data, 1);
    let server = Server::new();
    let file = put_v2(
        &server,
        "bbbbbbbb-0000-4000-8000-00000000000c",
        "crc.zip",
        None,
        &data,
        256,
    );
    let mut env = Env::with_server(server.clone());
    let id = env.open_listed(&file, "crc.zip", None).await;
    let options = ExtractOptions {
        selection: Selection::Paths(vec!["secret.txt".into()]),
        ..options(ExtractDestination::NextToArchive)
    };
    let run = env
        .service
        .extract(id, options, Some(ArchivePassword::new(wrong)))
        .await
        .unwrap();
    loop {
        if let ArchiveEvent::Model { model, .. } = env.next_event().await
            && let PreviewState::NeedsPassword { wrong } = model.state
        {
            assert!(wrong, "asked again after the CRC failed");
            break;
        }
    }
    assert_eq!(env.temp_files(), 0, "the failed attempt's staged bytes are gone");
    env.service.supply_password(run, ArchivePassword::new(PASSWORD.into()));
    let summary = env.pump_until_finished(run).await;
    assert_eq!(summary.outcome, ExtractOutcome::Done);
    assert_eq!((summary.files_done, summary.files_total), (1, 1));
    assert!(summary.skipped.is_empty(), "{:?}", summary.skipped);
    let secret = b"The protected test file.\n".repeat(40);
    assert_eq!(
        tree(&server, None),
        expected(&[("crc/", b""), ("crc/secret.txt", &secret)])
    );
    assert_eq!(env.temp_files(), 0);
}
