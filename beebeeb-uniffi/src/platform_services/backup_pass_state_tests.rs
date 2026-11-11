//! The backup pass state and manifest records across the platform seam.

use super::*;
use beebeeb_types::backup::BackupStopReason;

/// Review r6, P3-3: a stop the service could not finish at start reaches
/// the app typed, with its reason, so the app can show the stop's words.
#[test]
fn an_unfinished_stop_reaches_the_app_with_its_reason() {
    let error = map_client_error(beebeeb_client::backup::BackupError::StopUnfinished {
        reason: BackupStopReason::AccountLapsed,
        cause: Box::new(beebeeb_client::backup::BackupError::State),
    });
    assert!(
        matches!(&error, ServiceError::BackupStopUnfinished { reason } if reason == "account_lapsed"),
        "{error:?}"
    );
}

/// Amendment 12d: the acknowledged notice ids cross the seam with the stop
/// and `last_pass_at_ms`, in the one record the platform stores.
#[test]
fn a_stored_pass_state_round_trips_and_an_unknown_reason_is_refused() {
    let stopped = BackupPassState {
        last_pass_at_ms: Some(10),
        stopped: Some(BackupStop {
            reason: BackupStopReason::AccountLapsed,
        }),
        acknowledged: vec!["n1".into(), "n2".into()],
    };
    let data = BackupPassStateData::from(stopped.clone());
    assert_eq!(data.stopped_reason.as_deref(), Some("account_lapsed"));
    assert_eq!(data.acknowledged, ["n1", "n2"]);
    assert_eq!(pass_state(data), Some(stopped));
    assert_eq!(
        pass_state(BackupPassStateData::default()),
        Some(BackupPassState::default())
    );
    assert_eq!(
        pass_state(BackupPassStateData {
            stopped_reason: Some("a_reason_from_later".into()),
            ..Default::default()
        }),
        None
    );
}

/// Review r5, P2-1: what a record saw of its asset (rule 11's baseline)
/// crosses the platform both ways, with the `RemovedElsewhere` state.
#[test]
fn what_a_record_saw_of_its_asset_crosses_the_platform() {
    struct Records(std::sync::Mutex<Vec<BackupManifestRecordData>>);
    impl BackupManifestStoreCallback for Records {
        fn load(&self) -> Option<Vec<BackupManifestRecordData>> {
            Some(self.0.lock().unwrap().clone())
        }
        fn replace(&self, records: Vec<BackupManifestRecordData>) -> bool {
            *self.0.lock().unwrap() = records;
            true
        }
        fn load_pass_state(&self) -> Option<BackupPassStateData> {
            Some(BackupPassStateData::default())
        }
        fn save_pass_state(&self, _: BackupPassStateData) -> bool {
            true
        }
        fn clear(&self) -> bool {
            true
        }
    }
    struct Photos;
    impl AssetSourceCallback for Photos {
        fn snapshot(&self, _: AssetKindData, _: Option<String>, _: u64) -> Option<AssetSnapshotData> {
            Some(AssetSnapshotData {
                complete: true,
                assets: vec![AssetData {
                    local_identifier: "photo".into(),
                    name: "photo.jpg".into(),
                    mime_type: None,
                    modified_ms: Some(7),
                    size_bytes: Some(9),
                }],
                next_cursor: None,
            })
        }
        fn export(&self, _: AssetKindData, _: String) -> Option<String> {
            None
        }
    }

    let snapshot = AssetSourceAdapter {
        callback: Box::new(Photos),
    }
    .snapshot(AssetKind::Photo, None, 1)
    .unwrap();
    assert_eq!(
        (snapshot.assets[0].modified_ms, snapshot.assets[0].size_bytes),
        (Some(7), Some(9))
    );

    let store = BackupManifestStoreAdapter {
        callback: Box::new(Records(std::sync::Mutex::new(Vec::new()))),
    };
    let record = BackupManifestRecord {
        local_identifier: "photo".into(),
        file_id: "copy".into(),
        state: BackupCopyState::RemovedElsewhere,
        local_present: true,
        retry_count: 0,
        modified_ms: Some(7),
        size_bytes: Some(9),
    };
    store.replace(std::slice::from_ref(&record)).unwrap();
    assert_eq!(store.load().unwrap(), vec![record]);
}
