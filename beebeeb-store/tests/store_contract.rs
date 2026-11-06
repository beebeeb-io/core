use beebeeb_core::sync::{StoredSyncState, SyncStore, SyncStoreChanges, TreeNode};
use beebeeb_store::{
    AssetClass, BackupAsset, BoundedInsert, CacheEntry, ContactKey, Device, Node, SignOutDirectories, Store,
    TransferState, VersionObservation,
};
use chrono::Utc;
use uuid::Uuid;

fn node(id: &str, parent_id: Option<&str>, name: &str) -> Node {
    Node {
        id: id.into(),
        parent_id: parent_id.map(str::to_owned),
        encrypted_name: Some(format!("sealed-{name}")),
        decrypted_name: Some(name.into()),
        mime_type: Some("text/plain".into()),
        size_bytes: 12,
        is_folder: false,
        created_at: Some("2026-11-03T00:00:00Z".into()),
        updated_at: Some("2026-11-03T00:00:00Z".into()),
        payload: vec![1, 2, 3],
    }
}

#[test]
fn stores_every_required_row_type_and_file_provider_reads() {
    let mut store = Store::open_in_memory().unwrap();
    store
        .upsert_nodes(&[node("root", None, "root"), node("child", Some("root"), "a")])
        .unwrap();
    assert_eq!(
        store.get_node("child").unwrap().unwrap().decrypted_name.as_deref(),
        Some("a")
    );
    assert_eq!(store.list_children(Some("root")).unwrap().len(), 1);

    let op_id = store.append_op("rename", b"opaque", 10).unwrap();
    assert_eq!(store.pending_ops(10).unwrap()[0].id, op_id);
    store.ack_op(op_id).unwrap();
    store.set_sync_position("drive", b"cursor").unwrap();
    assert_eq!(store.sync_position("drive").unwrap().as_deref(), Some(&b"cursor"[..]));

    store
        .put_backup_asset(&BackupAsset {
            id: "asset".into(),
            source_id: "photo".into(),
            state: "queued".into(),
            payload: vec![4],
            updated_at: 11,
        })
        .unwrap();
    assert!(store.backup_asset("asset").unwrap().is_some());
    store
        .put_device_setting("device", "drive", "thumb-limit", b"42")
        .unwrap();
    assert_eq!(
        store
            .device_setting("device", "drive", "thumb-limit")
            .unwrap()
            .as_deref(),
        Some(&b"42"[..])
    );
    store
        .put_contact_key(&ContactKey {
            contact_id: "c".into(),
            public_key: vec![5],
            observed_at: 12,
        })
        .unwrap();
    assert!(store.contact_key("c").unwrap().is_some());
    store
        .put_device(&Device {
            id: "d".into(),
            name: "phone".into(),
            public_key: vec![6],
            updated_at: 13,
        })
        .unwrap();
    assert_eq!(store.devices().unwrap().len(), 1);

    assert_eq!(
        store.observe_file_version("f", 7).unwrap(),
        VersionObservation::NewHighest
    );
    assert_eq!(
        store.observe_file_version("f", 6).unwrap(),
        VersionObservation::Older { highest: 7 }
    );
}

#[test]
fn transfer_retry_limit_is_durable_and_terminal() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.sqlite");
    let id = {
        let mut store = Store::open(&path).unwrap();
        store.enqueue_transfer("upload", b"work", 2, 1).unwrap()
    };
    let mut store = Store::open(&path).unwrap();
    let claimed = store.claim_transfer(10, 20).unwrap().unwrap();
    assert_eq!(claimed.id, id);
    store.record_transfer_failure(id, "network", 11).unwrap();
    store.claim_transfer(12, 20).unwrap().unwrap();
    let failed = store.record_transfer_failure(id, "again", 13).unwrap();
    assert_eq!(failed.state, TransferState::Failed);
    assert!(store.claim_transfer(100, 200).unwrap().is_none());
}

#[test]
fn expired_transfer_lease_is_resumed_after_process_loss() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.sqlite");
    {
        let mut store = Store::open(&path).unwrap();
        store.enqueue_transfer("download", b"work", 3, 1).unwrap();
        store.claim_transfer(2, 20).unwrap().unwrap();
    }
    let mut store = Store::open(&path).unwrap();
    assert!(store.claim_transfer(19, 30).unwrap().is_none());
    assert!(store.claim_transfer(20, 30).unwrap().is_some());
}

#[test]
fn bounded_indexes_evict_oldest_or_stop_at_first_sync_limit() {
    let mut store = Store::open_in_memory().unwrap();
    store.set_asset_limit(AssetClass::Thumbnail, 10).unwrap();
    let mk = |key: &str, size, at| CacheEntry {
        key: key.into(),
        file_id: None,
        version_id: None,
        path: format!("/{key}"),
        size_bytes: size,
        last_accessed: at,
    };
    assert!(
        store
            .put_cache_entry(AssetClass::Thumbnail, &mk("old", 6, 1), BoundedInsert::EvictOldest)
            .unwrap()
            .accepted
    );
    let outcome = store
        .put_cache_entry(AssetClass::Thumbnail, &mk("new", 6, 2), BoundedInsert::EvictOldest)
        .unwrap();
    assert_eq!(outcome.paths_to_remove, vec!["/old"]);
    let stopped = store
        .put_cache_entry(
            AssetClass::Thumbnail,
            &mk("first-sync", 8, 3),
            BoundedInsert::StopAtLimit,
        )
        .unwrap();
    assert!(!stopped.accepted);
    assert!(stopped.paths_to_remove.is_empty());
    assert_eq!(store.clear_cache_index(AssetClass::Thumbnail).unwrap(), vec!["/new"]);
}

#[test]
fn rejects_sizes_and_counters_sqlite_cannot_represent() {
    let mut store = Store::open_in_memory().unwrap();
    assert!(store.set_asset_limit(AssetClass::Cache, u64::MAX).is_err());
    assert!(store.observe_file_version("f", u64::MAX).is_err());
}

#[test]
fn suspension_checkpoint_and_sign_out_close_the_database() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("account.sqlite");
    let cache = dir.path().join("cache");
    let thumbnails = dir.path().join("thumbs");
    let mut store = Store::open(&path).unwrap();
    store.append_op("write", b"value", 1).unwrap();
    store.prepare_for_suspension().unwrap();
    let clear = store
        .sign_out(SignOutDirectories {
            cache: cache.clone(),
            thumbnails: thumbnails.clone(),
        })
        .unwrap();
    assert_eq!(clear.cache, cache);
    assert_eq!(clear.thumbnails, thumbnails);
    assert!(!path.exists());
}

#[test]
fn sync_store_applies_only_the_changed_node_in_a_large_tree() {
    let mut before = StoredSyncState::default();
    for index in 0..40_000 {
        let id = Uuid::from_u128(index + 1);
        before.tree.insert(
            id,
            TreeNode {
                id,
                name: format!("file-{index}"),
                name_undecryptable: false,
                name_encrypted: "sealed".into(),
                parent_id: None,
                is_folder: false,
                size_bytes: 1,
                mime_type: None,
                content_hash: None,
                version_number: 1,
                has_thumbnail: false,
                storage_pool_id: None,
                is_trashed: false,
                is_starred: false,
                updated_at: Utc::now(),
            },
        );
    }
    let mut store = Store::open_in_memory().unwrap();
    store
        .apply(&SyncStoreChanges::between(&StoredSyncState::default(), &before))
        .unwrap();
    let mut after = before.clone();
    after.tree.get_mut(&Uuid::from_u128(20_001)).unwrap().name = "renamed".into();
    let changes = SyncStoreChanges::between(&before, &after);
    assert_eq!(changes.upserted_nodes.len(), 1);

    store.apply(&changes).unwrap();

    assert_eq!(store.load().unwrap(), after);
}
