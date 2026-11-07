use super::*;
use serde_json::json;
use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

struct FailingStore {
    state: StoredSyncState,
}

struct CountingStore {
    metadata: super::super::store::StoredSyncMetadata,
    nodes: HashMap<Uuid, TreeNode>,
    rows_read: Arc<AtomicUsize>,
}

impl SyncStore for CountingStore {
    fn load(&self) -> Result<StoredSyncState, SyncStoreError> {
        panic!("store-backed engine must not load the whole tree")
    }

    fn load_metadata(&self) -> Result<super::super::store::StoredSyncMetadata, SyncStoreError> {
        Ok(self.metadata.clone())
    }

    fn get_node(&self, id: Uuid) -> Result<Option<TreeNode>, SyncStoreError> {
        self.rows_read.fetch_add(1, Ordering::Relaxed);
        Ok(self.nodes.get(&id).cloned())
    }

    fn children(&self, parent_id: Option<Uuid>) -> Result<Vec<TreeNode>, SyncStoreError> {
        Ok(self
            .nodes
            .values()
            .filter(|node| node.parent_id == parent_id)
            .cloned()
            .collect())
    }

    fn changes_since(&self, seq_id: i64, limit: usize) -> Result<Vec<SyncOp>, SyncStoreError> {
        Ok(self
            .metadata
            .applied_ops
            .iter()
            .filter(|operation| operation.seq_id > seq_id)
            .take(limit)
            .cloned()
            .collect())
    }

    fn apply(&mut self, changes: &SyncStoreChanges) -> Result<(), SyncStoreError> {
        for id in &changes.deleted_node_ids {
            self.nodes.remove(id);
        }
        for node in &changes.upserted_nodes {
            self.nodes.insert(node.id, node.clone());
        }
        if let Some(metadata) = &changes.metadata {
            self.metadata.clone_from(metadata);
        }
        Ok(())
    }
}

impl SyncStore for FailingStore {
    fn load(&self) -> Result<StoredSyncState, SyncStoreError> {
        Ok(self.state.clone())
    }

    fn apply(&mut self, _changes: &SyncStoreChanges) -> Result<(), SyncStoreError> {
        Err(SyncStoreError::new("disk unavailable"))
    }
}

fn node(id: Uuid, name: &str, parent: Option<Uuid>, is_folder: bool) -> TreeNode {
    TreeNode {
        id,
        name: name.to_string(),
        name_undecryptable: false,
        name_encrypted: format!("enc:{}", name),
        parent_id: parent,
        is_folder,
        size_bytes: if is_folder { 0 } else { 100 },
        mime_type: if is_folder { None } else { Some("text/plain".into()) },
        content_hash: None,
        version_number: 1,
        has_thumbnail: false,
        storage_pool_id: None,
        is_trashed: false,
        is_starred: false,
        updated_at: Utc::now(),
    }
}

fn op(seq_id: i64, op_type: &str, payload: Value) -> SyncOp {
    SyncOp {
        seq_id,
        user_seq: Some(seq_id),
        op_type: op_type.into(),
        client_op_id: None,
        payload,
        device_id: Some("dev-other".into()),
        created_at: Utc::now(),
    }
}

#[test]
fn test_snapshot_load() {
    let mut engine = SyncEngine::new("dev-1".into());
    let folder = Uuid::new_v4();
    let file_a = Uuid::new_v4();
    let file_b = Uuid::new_v4();
    engine
        .apply_complete_snapshot(
            CompleteSnapshot::new(
                vec![
                    node(folder, "Documents", None, true),
                    node(file_a, "a.txt", Some(folder), false),
                    node(file_b, "b.txt", Some(folder), false),
                ],
                SyncPosition::new(42, 42),
            )
            .unwrap(),
        )
        .unwrap();

    assert_eq!(engine.tree_size(), 3);
    assert_eq!(engine.last_seq(), 42);
    assert_eq!(engine.children(Some(folder)).len(), 2);
    assert_eq!(engine.children(None).len(), 1);
}

#[test]
fn test_apply_remote_file_create() {
    let mut engine = SyncEngine::new("dev-1".into());
    let id = Uuid::new_v4();
    let event = engine
        .apply_remote_op(RemoteOp::from_authenticated_session(op(
            1,
            "file_create",
            json!({
                "id": id.to_string(),
                "name_encrypted": "enc:hello.txt",
                "size_bytes": 256,
                "mime_type": "text/plain",
            }),
        )))
        .unwrap();

    assert!(matches!(event, Some(SyncEvent::FileCreated { .. })));
    assert!(engine.get_node(id).is_some());
    assert_eq!(engine.last_seq(), 1);
    let n = engine.get_node(id).unwrap();
    assert_eq!(n.size_bytes, 256);
    assert_eq!(n.name_encrypted, "enc:hello.txt");
    assert!(!n.is_folder);
}

#[test]
fn test_apply_remote_file_rename() {
    let mut engine = SyncEngine::new("dev-1".into());
    let id = Uuid::new_v4();
    engine
        .apply_complete_snapshot(
            CompleteSnapshot::new(vec![node(id, "old.txt", None, false)], SyncPosition::new(1, 1)).unwrap(),
        )
        .unwrap();

    let event = engine
        .apply_remote_op(RemoteOp::from_authenticated_session(op(
            2,
            "file_rename",
            json!({
                "id": id.to_string(),
                "new_name_encrypted": "enc:new.txt",
                "new_name": "new.txt",
            }),
        )))
        .unwrap();

    assert!(matches!(event, Some(SyncEvent::FileRenamed { .. })));
    let n = engine.get_node(id).unwrap();
    assert_eq!(n.name, "new.txt");
    assert_eq!(n.name_encrypted, "enc:new.txt");
}

#[test]
fn test_apply_remote_file_move() {
    let mut engine = SyncEngine::new("dev-1".into());
    let folder_a = Uuid::new_v4();
    let folder_b = Uuid::new_v4();
    let file = Uuid::new_v4();
    engine
        .apply_complete_snapshot(
            CompleteSnapshot::new(
                vec![
                    node(folder_a, "A", None, true),
                    node(folder_b, "B", None, true),
                    node(file, "f.txt", Some(folder_a), false),
                ],
                SyncPosition::new(1, 1),
            )
            .unwrap(),
        )
        .unwrap();

    let event = engine
        .apply_remote_op(RemoteOp::from_authenticated_session(op(
            2,
            "file_move",
            json!({
                "id": file.to_string(),
                "old_parent_id": folder_a.to_string(),
                "new_parent_id": folder_b.to_string(),
            }),
        )))
        .unwrap();

    assert!(matches!(
        event,
        Some(SyncEvent::FileMoved {
            new_parent: Some(_),
            ..
        })
    ));
    assert_eq!(engine.get_node(file).unwrap().parent_id, Some(folder_b));
    assert_eq!(engine.children(Some(folder_a)).len(), 0);
    assert_eq!(engine.children(Some(folder_b)).len(), 1);
}

#[test]
fn test_echo_suppression() {
    let mut engine = SyncEngine::new("dev-1".into());
    let id = Uuid::new_v4();
    let pending = engine
        .apply_local_op(
            "file_create",
            json!({
                "id": id.to_string(),
                "name_encrypted": "enc:local.txt",
                "name": "local.txt",
                "size_bytes": 10,
            }),
        )
        .unwrap();

    assert!(engine.get_node(id).is_some());
    assert_eq!(engine.pending_ops().len(), 1);

    let echoed = SyncOp {
        seq_id: 7,
        user_seq: Some(1),
        op_type: "file_create".into(),
        client_op_id: Some(pending.client_op_id),
        payload: json!({
            "id": id.to_string(),
            "name_encrypted": "enc:local.txt",
            "size_bytes": 10,
        }),
        device_id: Some("dev-1".into()),
        created_at: Utc::now(),
    };

    let event = engine
        .apply_remote_op(RemoteOp::from_authenticated_session(echoed))
        .unwrap();
    assert!(event.is_none(), "echoed op must be suppressed");
    assert_eq!(engine.pending_ops().len(), 0);
    assert_eq!(engine.last_seq(), 7);
    assert!(engine.get_node(id).is_some(), "tree state preserved");
}

#[test]
fn test_reject_rollback() {
    let mut engine = SyncEngine::new("dev-1".into());
    let id = Uuid::new_v4();
    engine
        .apply_complete_snapshot(
            CompleteSnapshot::new(vec![node(id, "original.txt", None, false)], SyncPosition::new(1, 1)).unwrap(),
        )
        .unwrap();

    let pending = engine
        .apply_local_op(
            "file_rename",
            json!({
                "id": id.to_string(),
                "new_name_encrypted": "enc:my-rename.txt",
                "new_name": "my-rename.txt",
            }),
        )
        .unwrap();
    assert_eq!(engine.get_node(id).unwrap().name, "my-rename.txt");

    // Server rejects ours and gives us the winning op (renamed by another device).
    let winner = op(
        2,
        "file_rename",
        json!({
            "id": id.to_string(),
            "new_name_encrypted": "enc:winner.txt",
            "new_name": "winner.txt",
        }),
    );
    let event = engine
        .reject_op(pending.client_op_id, RemoteOp::from_authenticated_session(winner))
        .unwrap();

    assert!(matches!(event, Some(SyncEvent::FileRenamed { .. })));
    let n = engine.get_node(id).unwrap();
    assert_eq!(n.name, "winner.txt", "winning op applied after rollback");
    assert_eq!(engine.pending_ops().len(), 0);
}

#[test]
fn test_search() {
    let mut engine = SyncEngine::new("dev-1".into());
    engine
        .apply_complete_snapshot(
            CompleteSnapshot::new(
                vec![
                    node(Uuid::new_v4(), "Tax Returns 2024.pdf", None, false),
                    node(Uuid::new_v4(), "vacation-photos", None, true),
                    node(Uuid::new_v4(), "tax_summary.txt", None, false),
                    node(Uuid::new_v4(), "notes.md", None, false),
                ],
                SyncPosition::new(1, 1),
            )
            .unwrap(),
        )
        .unwrap();

    let hits = engine.search("tax");
    assert_eq!(hits.len(), 2);
    assert!(hits.iter().any(|n| n.name == "Tax Returns 2024.pdf"));
    assert!(hits.iter().any(|n| n.name == "tax_summary.txt"));

    assert_eq!(engine.search("xyz").len(), 0);
    assert_eq!(engine.search("PHOTOS").len(), 1);
}

#[test]
fn test_trash_and_restore() {
    let mut engine = SyncEngine::new("dev-1".into());
    let id = Uuid::new_v4();
    engine
        .apply_complete_snapshot(
            CompleteSnapshot::new(vec![node(id, "a.txt", None, false)], SyncPosition::new(1, 1)).unwrap(),
        )
        .unwrap();

    engine
        .apply_remote_op(RemoteOp::from_authenticated_session(op(
            2,
            "file_trash",
            json!({"id": id.to_string()}),
        )))
        .unwrap();
    assert!(engine.get_node(id).unwrap().is_trashed);
    assert_eq!(engine.children(None).len(), 0);

    engine
        .apply_remote_op(RemoteOp::from_authenticated_session(op(
            3,
            "file_restore",
            json!({"id": id.to_string()}),
        )))
        .unwrap();
    assert!(!engine.get_node(id).unwrap().is_trashed);
    assert_eq!(engine.children(None).len(), 1);
}

#[test]
fn test_permanent_delete_clears_pin() {
    let mut engine = SyncEngine::new("dev-1".into());
    let id = Uuid::new_v4();
    engine
        .apply_complete_snapshot(
            CompleteSnapshot::new(vec![node(id, "a.txt", None, false)], SyncPosition::new(1, 1)).unwrap(),
        )
        .unwrap();
    engine.pin(id).unwrap();
    assert!(engine.is_pinned(id));

    engine
        .apply_remote_op(RemoteOp::from_authenticated_session(op(
            2,
            "file_delete",
            json!({"id": id.to_string()}),
        )))
        .unwrap();
    assert!(engine.get_node(id).is_none());
    assert!(!engine.is_pinned(id));
}

#[test]
fn incomplete_snapshot_cannot_remove_an_absent_node() {
    let mut engine = SyncEngine::new("dev-1".into());
    let id = Uuid::new_v4();
    engine
        .apply_complete_snapshot(
            CompleteSnapshot::new(vec![node(id, "keep.txt", None, false)], SyncPosition::new(8, 3)).unwrap(),
        )
        .unwrap();

    engine
        .observe_incomplete_snapshot(IncompleteSnapshot::new(Vec::new()))
        .unwrap();

    assert!(engine.get_node(id).is_some());
    assert_eq!(engine.position(), SyncPosition::new(8, 3));
}

#[test]
fn complete_snapshot_removes_absent_nodes() {
    let mut engine = SyncEngine::new("dev-1".into());
    let id = Uuid::new_v4();
    engine
        .apply_complete_snapshot(
            CompleteSnapshot::new(vec![node(id, "gone.txt", None, false)], SyncPosition::new(8, 3)).unwrap(),
        )
        .unwrap();

    engine
        .apply_complete_snapshot(CompleteSnapshot::new(Vec::new(), SyncPosition::new(12, 4)).unwrap())
        .unwrap();

    assert!(engine.get_node(id).is_none());
}

#[test]
fn complete_snapshot_never_moves_cursors_backwards() {
    let mut engine = SyncEngine::new("dev-1".into());
    engine
        .apply_complete_snapshot(CompleteSnapshot::new(Vec::new(), SyncPosition::new(12, 4)).unwrap())
        .unwrap();

    let error = engine
        .apply_complete_snapshot(CompleteSnapshot::new(Vec::new(), SyncPosition::new(11, 3)).unwrap())
        .expect_err("older snapshots must be refused");

    assert!(matches!(error, SyncEngineError::SnapshotBehind { .. }));
    assert_eq!(engine.position(), SyncPosition::new(12, 4));
}

#[test]
fn complete_snapshot_expires_older_change_anchors() {
    let mut engine = SyncEngine::new("dev-1".into());
    engine
        .apply_complete_snapshot(CompleteSnapshot::new(Vec::new(), SyncPosition::new(12, 4)).unwrap())
        .unwrap();

    assert!(matches!(
        engine.changes_since(11, 10),
        Err(SyncEngineError::AnchorExpired {
            oldest_available: 12,
            requested: 11
        })
    ));
    assert!(engine.changes_since(12, 10).unwrap().is_empty());
}

#[test]
fn global_sequence_may_jump_when_user_sequence_is_contiguous() {
    let mut engine = SyncEngine::new("dev-1".into());
    let mut remote = op(41, "share_update", json!({}));
    remote.user_seq = Some(1);

    engine
        .apply_remote_op(RemoteOp::from_authenticated_session(remote))
        .unwrap();

    assert_eq!(engine.position(), SyncPosition::new(41, 1));
}

#[test]
fn per_user_sequence_gap_requires_rebase_without_mutation() {
    let mut engine = SyncEngine::new("dev-1".into());
    let id = Uuid::new_v4();
    let mut remote = op(41, "file_create", json!({"id": id.to_string()}));
    remote.user_seq = Some(2);

    let error = engine
        .apply_remote_op(RemoteOp::from_authenticated_session(remote))
        .expect_err("gap must require a complete snapshot");

    assert!(matches!(
        error,
        SyncEngineError::SequenceGap {
            expected_user_seq: 1,
            received_user_seq: 2
        }
    ));
    assert!(engine.get_node(id).is_none());
    assert_eq!(engine.position(), SyncPosition::default());
}

#[test]
fn local_delete_waits_for_authenticated_remote_echo() {
    let mut engine = SyncEngine::new("dev-1".into());
    let id = Uuid::new_v4();
    engine
        .apply_complete_snapshot(
            CompleteSnapshot::new(vec![node(id, "keep.txt", None, false)], SyncPosition::new(8, 3)).unwrap(),
        )
        .unwrap();

    engine
        .apply_local_op("file_delete", json!({"id": id.to_string()}))
        .unwrap();

    assert!(engine.get_node(id).is_some());
}

#[test]
fn complete_snapshot_rebases_pending_local_operations() {
    let mut engine = SyncEngine::new("dev-1".into());
    let id = Uuid::new_v4();
    engine
        .apply_local_op(
            "file_create",
            json!({"id": id.to_string(), "name": "local.txt", "name_encrypted": "enc:local"}),
        )
        .unwrap();

    engine
        .apply_complete_snapshot(CompleteSnapshot::new(Vec::new(), SyncPosition::new(12, 4)).unwrap())
        .unwrap();

    assert!(engine.get_node(id).is_some());
    assert_eq!(engine.pending_ops().len(), 1);
}

#[test]
fn authenticated_delete_echo_removes_local_item() {
    let mut engine = SyncEngine::new("dev-1".into());
    let id = Uuid::new_v4();
    engine
        .apply_complete_snapshot(
            CompleteSnapshot::new(vec![node(id, "keep.txt", None, false)], SyncPosition::new(8, 3)).unwrap(),
        )
        .unwrap();
    let pending = engine
        .apply_local_op("file_delete", json!({"id": id.to_string()}))
        .unwrap();
    let remote = SyncOp {
        seq_id: 12,
        user_seq: Some(4),
        op_type: "file_delete".into(),
        client_op_id: Some(pending.client_op_id),
        payload: json!({"id": id.to_string()}),
        device_id: Some("dev-1".into()),
        created_at: Utc::now(),
    };

    let event = engine
        .apply_remote_op(RemoteOp::from_authenticated_session(remote))
        .unwrap();

    assert!(matches!(event, Some(SyncEvent::FileDeleted { id: event_id }) if event_id == id));
    assert!(engine.get_node(id).is_none());
}

#[test]
fn failed_persistence_rolls_back_in_memory_mutation() {
    let id = Uuid::new_v4();
    let mut state = StoredSyncState::default();
    state.tree.insert(id, node(id, "keep.txt", None, false));
    let store = FailingStore { state: state.clone() };
    let mut engine = SyncEngine::with_store("dev-1".into(), store).unwrap();

    let result = engine.observe_incomplete_snapshot(IncompleteSnapshot::new(vec![node(
        Uuid::new_v4(),
        "new.txt",
        None,
        false,
    )]));

    assert!(matches!(result, Err(SyncEngineError::Store(_))));
    assert_eq!(engine.tree_size(), 1);
    assert!(engine.get_node(id).is_some());
}

#[test]
fn store_backed_single_op_reads_one_row_in_a_40k_vault() {
    let rows_read = Arc::new(AtomicUsize::new(0));
    let mut nodes = HashMap::new();
    for value in 1..=40_000 {
        let id = Uuid::from_u128(value);
        nodes.insert(id, node(id, &format!("file-{value}"), None, false));
    }
    let target = Uuid::from_u128(20_000);
    let store = CountingStore {
        metadata: super::super::store::StoredSyncMetadata::default(),
        nodes,
        rows_read: rows_read.clone(),
    };
    let mut engine = SyncEngine::with_store_backed("dev-1".into(), store).unwrap();

    engine
        .apply_remote_op(RemoteOp::from_authenticated_session(op(
            1,
            "file_rename",
            json!({
                "id": target.to_string(),
                "new_name": "renamed.txt",
                "new_name_encrypted": "sealed-renamed"
            }),
        )))
        .unwrap();

    assert_eq!(rows_read.load(Ordering::Relaxed), 1);
    assert_eq!(engine.lookup_node(target).unwrap().unwrap().name, "renamed.txt");
    assert_eq!(rows_read.load(Ordering::Relaxed), 2);
}
