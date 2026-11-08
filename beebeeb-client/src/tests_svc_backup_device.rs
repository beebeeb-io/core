//! Review r5 of #74, P1-1 and P1-2, and its P3s: the native backup keys its
//! server map by this device's id, decides "removed elsewhere" from its own
//! copy, runs one service per upload service, and finishes a saved stop when
//! it starts.

use beebeeb_types::backup::BackupStopReason;

use crate::{
    backup::{BackupConfiguration, BackupCopyState, BackupDeviceId, BackupError, BackupFolder, BackupStop},
    tests_svc_backup_gate::{BackupServer, CATEGORY, CopyRow, THIS_DEVICE, harness, harness_on, one_photo},
};

const NEEDS: &str = r#"{"needs_backup":["photo-1"]}"#;

// ── P1-1: every photo-backup call carries this device's id ──────────────────

/// The server keys every row by `X-Beebeeb-Device-Id` and uses `""` without
/// it, the map every device of the account would then share.
#[tokio::test]
async fn check_and_mark_carry_this_devices_id() {
    let h = harness(|c| c, &[]);
    h.server.keep_rows();
    h.snapshot_photo();

    assert_eq!(h.pass(1).await.queued, 1);
    h.backup.upload_completed("photo-1", "copy-1").await.unwrap();

    assert_eq!(
        h.server.keyed_by(),
        [Some(THIS_DEVICE.to_owned()), Some(THIS_DEVICE.to_owned())]
    );
    assert_eq!(
        h.server.rows().get(&(THIS_DEVICE.to_owned(), "photo-1".to_owned())),
        Some(&"copy-1".to_owned())
    );
}

/// Two Android phones on one account share MediaStore ids. Phone B's own
/// `photo-1` must never be taken for the copy phone A backed up under the
/// same id: keyed by device, B's check does not see A's row.
#[tokio::test]
async fn a_photo_another_device_backed_up_under_the_same_id_is_still_uploaded() {
    let server = BackupServer::default();
    server.keep_rows();
    let phone_a = harness_on(
        server.clone(),
        |c| BackupConfiguration {
            device_id: BackupDeviceId::new("phone-a").unwrap(),
            ..c
        },
        &[],
    );
    phone_a.snapshot_photo();
    assert_eq!(phone_a.pass(1).await.queued, 1);
    phone_a.backup.upload_completed("photo-1", "copy-of-a").await.unwrap();

    let phone_b = harness_on(
        server.clone(),
        |c| BackupConfiguration {
            device_id: BackupDeviceId::new("phone-b").unwrap(),
            ..c
        },
        &[],
    );
    phone_b.snapshot_photo();
    let batch = phone_b.pass(1).await;

    assert_eq!(
        (batch.queued, phone_b.backup.manifest().copy_state("photo-1")),
        (1, Some(BackupCopyState::Queued)),
        "phone B's own photo-1 was never on the server"
    );
    assert_eq!(server.rows().len(), 1, "{:?}", server.rows());
}

/// The server drops an id it would trim or one over 128 bytes, and files the
/// rows under `""`: such an id is refused before anything is sent. The id is
/// a `BackupDeviceId`, made only by its checked constructor, so a struct
/// literal or `configure` cannot skip the check either (review r6, P3-1:
/// `" phone"` reached the server through a struct literal).
#[test]
fn a_device_id_the_server_would_not_key_by_is_refused() {
    let folder = || BackupFolder { id: CATEGORY.into() };
    for bad in [
        String::new(),
        " phone".into(),
        "phone a".into(),
        "x".repeat(129),
        "tel\u{e9}fono".into(),
    ] {
        assert!(
            matches!(BackupDeviceId::new(bad.clone()), Err(BackupError::InvalidDeviceId)),
            "{bad:?}"
        );
        assert!(
            matches!(
                BackupConfiguration::new(folder(), false, bad.clone()),
                Err(BackupError::InvalidDeviceId)
            ),
            "{bad:?}"
        );
    }
    assert!(BackupConfiguration::new(folder(), false, "x".repeat(128)).is_ok());
    assert!(BackupConfiguration::new(folder(), false, "6f1c2d3e-0000-4000-8000-00000000abcd").is_ok());
}

// ── P1-2: "removed elsewhere" is decided from the record's own copy ─────────

/// Only the row is missing (a changed device id, `clear-association`): the
/// copy is live. It stays `Active`, its row is repaired, nothing uploads.
#[tokio::test]
async fn a_live_copy_is_not_marked_removed_elsewhere_and_its_row_is_repaired() {
    // The server's map has no row for this device (`keep_rows` starts empty).
    let h = harness(|c| c, &[]);
    h.server.set_copy("copy-1", CopyRow::Live);
    h.server.keep_rows();
    h.backup
        .manifest()
        .remember("photo-1", "copy-1", BackupCopyState::Active)
        .unwrap();
    h.snapshot_photo();

    let batch = h.pass(1).await;

    assert_eq!(h.server.copy_reads(), ["copy-1"]);
    assert_eq!(
        (batch.queued, h.backup.manifest().copy_state("photo-1")),
        (0, Some(BackupCopyState::Active))
    );
    assert!(h.uploads.list().unwrap().is_empty());
    assert_eq!(
        h.server.rows().get(&(THIS_DEVICE.to_owned(), "photo-1".to_owned())),
        Some(&"copy-1".to_owned()),
        "mark was sent again"
    );
}

/// Spec rule 11, "trashed or gone": a 404 is removed elsewhere too
/// (decision 2394).
#[tokio::test]
async fn a_copy_gone_for_good_is_removed_elsewhere() {
    let h = harness(|c| c, &[NEEDS]);
    h.server.set_copy("copy-1", CopyRow::Gone);
    h.backup
        .manifest()
        .remember("photo-1", "copy-1", BackupCopyState::Active)
        .unwrap();
    h.snapshot_photo();

    assert_eq!(h.pass(1).await.queued, 0);
    assert_eq!(
        h.backup.manifest().copy_state("photo-1"),
        Some(BackupCopyState::RemovedElsewhere)
    );
}

/// Any other answer changes nothing and uploads nothing this pass.
#[tokio::test]
async fn a_failed_copy_lookup_changes_nothing() {
    let h = harness(|c| c, &[NEEDS]);
    h.server.set_copy("copy-1", CopyRow::Fails);
    h.backup
        .manifest()
        .remember("photo-1", "copy-1", BackupCopyState::Active)
        .unwrap();
    h.snapshot_photo();

    assert_eq!(h.pass(1).await.queued, 0);
    assert_eq!(h.server.copy_reads(), ["copy-1"]);
    assert_eq!(h.backup.manifest().copy_state("photo-1"), Some(BackupCopyState::Active));
    assert!(h.uploads.list().unwrap().is_empty());
    assert_eq!(h.scripted.request_count(), 1, "the check only: no mark");
}

/// "Missing never counts as changed", every combination on a removed copy
/// (the reviewer's fourth probe).
#[tokio::test]
async fn a_missing_side_never_counts_as_a_change() {
    let h = harness(|c| c, &[NEEDS]);
    let manifest = h.backup.manifest();
    let mut photo = one_photo(&h.photo);
    // A record from before this release: neither side known.
    manifest
        .remember("photo-1", "copy-1", BackupCopyState::Deleted)
        .unwrap();
    for (modified, size) in [
        (None, None),
        (Some(1_000), None),
        (None, Some(5)),
        (Some(1_000), Some(5)),
    ] {
        photo.assets[0].modified_ms = modified;
        photo.assets[0].size_bytes = size;
        h.source.snapshots.lock().unwrap().push_back(photo.clone());
        assert_eq!(h.pass(1).await.queued, 0, "{modified:?} {size:?}");
    }
    // Now both known (1_000, 5). An asset that stops reporting is no change.
    photo.assets[0].modified_ms = None;
    photo.assets[0].size_bytes = None;
    h.source.snapshots.lock().unwrap().push_back(photo.clone());
    assert_eq!(h.pass(2).await.queued, 0);
    // One side changed, the other unknown on the asset: a change.
    photo.assets[0].modified_ms = Some(2_000);
    h.source.snapshots.lock().unwrap().push_back(photo);
    assert_eq!(h.pass(3).await.queued, 1);
    assert_eq!(h.scripted.request_count(), 1, "only the changed pass asked the server");
}

// ── P3s ─────────────────────────────────────────────────────────────────────

/// One backup service per upload service: a second would steal the
/// completion handler and write over the first one's manifest.
#[tokio::test]
async fn a_second_backup_service_on_one_upload_service_is_refused() {
    let h = harness(|c| c, &[]);

    assert!(matches!(h.second_service(), Err(BackupError::AlreadyRunning)));

    // Dropped, the first lets another start.
    let h = h.restart();
    assert!(matches!(h.second_service(), Err(BackupError::AlreadyRunning)));
}

/// The app dies after a stop was saved and before its uploads were
/// cancelled. When the service starts again it cancels them, before any
/// upload resumes.
#[tokio::test]
async fn a_stop_saved_before_a_crash_cancels_its_uploads_when_the_service_starts() {
    let h = harness(|c| c, &[NEEDS]);
    h.snapshot_photo();
    assert_eq!(h.pass(1).await.queued, 1);
    h.backup
        .manifest()
        .update_pass_state(|state| {
            state.stopped = Some(BackupStop {
                reason: BackupStopReason::EraseRequest,
                through_ms: 5,
            });
        })
        .unwrap();
    assert_eq!(h.uploads.active_backup_count().unwrap(), 1);

    let h = h.restart();

    assert_eq!(h.uploads.active_backup_count().unwrap(), 0);
    assert_eq!(h.backup.manifest().copy_state("photo-1"), None);
    assert_eq!(h.backup.stopped().unwrap(), Some(BackupStopReason::EraseRequest));
}

/// Review r6, P3-3: the stop cannot be finished when the service starts (the
/// store fails), so no service is made; the error still names the stop, so
/// the app can show its words.
#[tokio::test]
async fn a_stop_the_service_cannot_finish_at_start_still_names_its_reason() {
    let h = harness(|c| c, &[NEEDS]);
    h.snapshot_photo();
    assert_eq!(h.pass(1).await.queued, 1);
    h.backup
        .manifest()
        .update_pass_state(|state| {
            state.stopped = Some(BackupStop {
                reason: BackupStopReason::AccountLapsed,
                through_ms: 5,
            });
        })
        .unwrap();
    h.fail_store_writes();

    let refused = h.try_restart().err().expect("no service while the stop cannot finish");

    assert!(
        matches!(
            refused,
            BackupError::StopUnfinished {
                reason: BackupStopReason::AccountLapsed,
                ..
            }
        ),
        "{refused:?}"
    );
}
