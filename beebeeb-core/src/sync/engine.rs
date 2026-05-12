use std::collections::{HashMap, HashSet, VecDeque};

use chrono::Utc;
use serde_json::Value;
use uuid::Uuid;

use super::events::SyncEvent;
use super::types::{PendingOp, SyncOp, TreeNode};

/// In-memory tree + op log state. See spec §3.
pub struct SyncEngine {
    tree: HashMap<Uuid, TreeNode>,
    last_seq: i64,
    pending_ops: VecDeque<PendingOp>,
    pinned_files: HashSet<Uuid>,
    device_id: String,
}

impl SyncEngine {
    pub fn new(device_id: String) -> Self {
        Self {
            tree: HashMap::new(),
            last_seq: 0,
            pending_ops: VecDeque::new(),
            pinned_files: HashSet::new(),
            device_id,
        }
    }

    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    /// Replace the entire tree with a server snapshot. Resets `last_seq` to the
    /// snapshot cursor — pending ops are NOT cleared (they'll be flushed after
    /// reconnect).
    pub fn load_snapshot(&mut self, nodes: Vec<TreeNode>, seq_id: i64) {
        self.tree.clear();
        for node in nodes {
            self.tree.insert(node.id, node);
        }
        self.last_seq = seq_id;
    }

    /// Apply a server-assigned op. Returns the UI event to emit, or `None` if
    /// the op was suppressed (matched a pending local op via `client_op_id`).
    pub fn apply_remote_op(&mut self, op: SyncOp) -> Option<SyncEvent> {
        // Echo suppression — our own op coming back via SSE.
        if let Some(client_op_id) = op.client_op_id {
            if let Some(pos) = self.pending_ops.iter().position(|p| p.client_op_id == client_op_id) {
                self.pending_ops.remove(pos);
                self.last_seq = self.last_seq.max(op.seq_id);
                return None;
            }
        }

        let event = self.apply_op_to_tree(&op.op_type, &op.payload);
        self.last_seq = self.last_seq.max(op.seq_id);
        event
    }

    /// Optimistically apply a local op and queue it for the server. Returns
    /// the queued [`PendingOp`] so the caller can POST it.
    pub fn apply_local_op(&mut self, op_type: &str, payload: Value) -> PendingOp {
        let client_op_id = Uuid::new_v4();
        let rollback = self.snapshot_for_rollback(op_type, &payload);

        // Optimistic apply — ignore the event, the UI emits its own optimistic
        // update for local actions.
        let _ = self.apply_op_to_tree(op_type, &payload);

        let pending = PendingOp {
            client_op_id,
            op_type: op_type.to_string(),
            payload,
            rollback,
        };
        self.pending_ops.push_back(pending.clone());
        pending
    }

    /// Server confirmed the op — drop it from the pending queue. (The echoed
    /// op coming back via SSE will also remove it; this is for the direct
    /// `POST /sync/ops` response path.)
    pub fn confirm_op(&mut self, client_op_id: Uuid) {
        if let Some(pos) = self.pending_ops.iter().position(|p| p.client_op_id == client_op_id) {
            self.pending_ops.remove(pos);
        }
    }

    /// Server rejected our op (typically a conflict). Roll back the optimistic
    /// change and apply the winning op so the tree converges with the server.
    pub fn reject_op(&mut self, client_op_id: Uuid, winning_op: SyncOp) -> Option<SyncEvent> {
        if let Some(pos) = self.pending_ops.iter().position(|p| p.client_op_id == client_op_id) {
            let pending = self.pending_ops.remove(pos).expect("position just found");
            self.rollback(&pending);
        }
        self.apply_remote_op(winning_op)
    }

    pub fn get_node(&self, id: Uuid) -> Option<&TreeNode> {
        self.tree.get(&id)
    }

    /// Children of a folder. Pass `None` for root-level nodes.
    pub fn children(&self, parent_id: Option<Uuid>) -> Vec<&TreeNode> {
        self.tree
            .values()
            .filter(|n| n.parent_id == parent_id && !n.is_trashed)
            .collect()
    }

    /// Case-insensitive substring match on the decrypted name. Searches the
    /// full tree (including trashed nodes — callers can filter).
    pub fn search(&self, query: &str) -> Vec<&TreeNode> {
        let needle = query.to_lowercase();
        self.tree
            .values()
            .filter(|n| n.name.to_lowercase().contains(&needle))
            .collect()
    }

    pub fn last_seq(&self) -> i64 {
        self.last_seq
    }

    pub fn pending_ops(&self) -> &VecDeque<PendingOp> {
        &self.pending_ops
    }

    pub fn tree_size(&self) -> usize {
        self.tree.len()
    }

    pub fn pin(&mut self, id: Uuid) {
        self.pinned_files.insert(id);
    }

    pub fn unpin(&mut self, id: Uuid) {
        self.pinned_files.remove(&id);
    }

    pub fn is_pinned(&self, id: Uuid) -> bool {
        self.pinned_files.contains(&id)
    }

    // ---------------------------------------------------------------- helpers

    /// Capture the pre-mutation node so we can roll back on server reject.
    fn snapshot_for_rollback(&self, op_type: &str, payload: &Value) -> Option<TreeNode> {
        let id = payload.get("id")?.as_str().and_then(|s| Uuid::parse_str(s).ok())?;
        match op_type {
            "file_create" | "folder_create" => None, // nothing to roll back to
            _ => self.tree.get(&id).cloned(),
        }
    }

    fn rollback(&mut self, pending: &PendingOp) {
        let id = pending
            .payload
            .get("id")
            .and_then(|v| v.as_str())
            .and_then(|s| Uuid::parse_str(s).ok());

        match (pending.op_type.as_str(), id, &pending.rollback) {
            ("file_create" | "folder_create", Some(id), _) => {
                self.tree.remove(&id);
            }
            (_, Some(id), Some(snapshot)) => {
                self.tree.insert(id, snapshot.clone());
            }
            (_, Some(id), None) => {
                // We had no pre-state (e.g. delete of a node we never had).
                self.tree.remove(&id);
            }
            _ => {}
        }
    }

    fn apply_op_to_tree(&mut self, op_type: &str, payload: &Value) -> Option<SyncEvent> {
        match op_type {
            "file_create" => self.apply_create(payload, false),
            "folder_create" => self.apply_create(payload, true),
            "file_update" => self.apply_update(payload),
            "file_rename" | "folder_rename" => self.apply_rename(payload),
            "file_move" | "folder_move" => self.apply_move(payload),
            "file_trash" => self.apply_trash(payload),
            "file_restore" => self.apply_restore(payload),
            "file_delete" => self.apply_delete(payload),
            // share_create / share_revoke are notification-only — handled at a
            // higher layer (it triggers a refetch of `/shares/mine`).
            _ => None,
        }
    }

    fn apply_create(&mut self, payload: &Value, is_folder: bool) -> Option<SyncEvent> {
        let id = uuid_field(payload, "id")?;
        let parent_id = uuid_field(payload, "parent_id");
        let name_encrypted = string_field(payload, "name_encrypted").unwrap_or_default();
        // Decrypted name is filled in by the caller (sync engine consumer);
        // the engine only stores ciphertext + a placeholder until decryption.
        // For local ops the caller may include `name` in the payload.
        let name = string_field(payload, "name").unwrap_or_default();

        let node = TreeNode {
            id,
            name,
            name_encrypted,
            parent_id,
            is_folder,
            size_bytes: payload.get("size_bytes").and_then(|v| v.as_i64()).unwrap_or(0),
            mime_type: string_field(payload, "mime_type"),
            content_hash: string_field(payload, "content_hash"),
            version_number: payload.get("version_number").and_then(|v| v.as_i64()).unwrap_or(1) as i32,
            has_thumbnail: payload.get("has_thumbnail").and_then(|v| v.as_bool()).unwrap_or(false),
            storage_pool_id: uuid_field(payload, "storage_pool_id"),
            is_trashed: false,
            is_starred: false,
            updated_at: Utc::now(),
        };

        self.tree.insert(id, node.clone());
        Some(if is_folder {
            SyncEvent::FolderCreated { node }
        } else {
            SyncEvent::FileCreated { node }
        })
    }

    fn apply_update(&mut self, payload: &Value) -> Option<SyncEvent> {
        let id = uuid_field(payload, "id")?;
        let node = self.tree.get_mut(&id)?;
        if let Some(size) = payload.get("size_bytes").and_then(|v| v.as_i64()) {
            node.size_bytes = size;
        }
        if let Some(version) = payload.get("version_number").and_then(|v| v.as_i64()) {
            node.version_number = version as i32;
        }
        if let Some(hash) = string_field(payload, "content_hash") {
            node.content_hash = Some(hash);
        }
        node.updated_at = Utc::now();
        Some(SyncEvent::FileUpdated { node: node.clone() })
    }

    fn apply_rename(&mut self, payload: &Value) -> Option<SyncEvent> {
        let id = uuid_field(payload, "id")?;
        let node = self.tree.get_mut(&id)?;
        if let Some(new_name_encrypted) = string_field(payload, "new_name_encrypted") {
            node.name_encrypted = new_name_encrypted;
        }
        // For local ops the caller can include the plaintext name; for remote
        // ops the higher layer is responsible for decryption.
        if let Some(new_name) = string_field(payload, "new_name") {
            node.name = new_name;
        }
        node.updated_at = Utc::now();
        Some(SyncEvent::FileRenamed {
            id,
            new_name: node.name.clone(),
        })
    }

    fn apply_move(&mut self, payload: &Value) -> Option<SyncEvent> {
        let id = uuid_field(payload, "id")?;
        let new_parent = uuid_field(payload, "new_parent_id");
        let node = self.tree.get_mut(&id)?;
        let old_parent = node.parent_id;
        node.parent_id = new_parent;
        node.updated_at = Utc::now();
        Some(SyncEvent::FileMoved {
            id,
            old_parent,
            new_parent,
        })
    }

    fn apply_trash(&mut self, payload: &Value) -> Option<SyncEvent> {
        let id = uuid_field(payload, "id")?;
        let node = self.tree.get_mut(&id)?;
        node.is_trashed = true;
        node.updated_at = Utc::now();
        Some(SyncEvent::FileTrashed { id })
    }

    fn apply_restore(&mut self, payload: &Value) -> Option<SyncEvent> {
        let id = uuid_field(payload, "id")?;
        let node = self.tree.get_mut(&id)?;
        node.is_trashed = false;
        node.updated_at = Utc::now();
        Some(SyncEvent::FileRestored { id })
    }

    fn apply_delete(&mut self, payload: &Value) -> Option<SyncEvent> {
        let id = uuid_field(payload, "id")?;
        self.tree.remove(&id);
        self.pinned_files.remove(&id);
        Some(SyncEvent::FileDeleted { id })
    }
}

fn uuid_field(payload: &Value, key: &str) -> Option<Uuid> {
    payload
        .get(key)
        .and_then(|v| v.as_str())
        .and_then(|s| Uuid::parse_str(s).ok())
}

fn string_field(payload: &Value, key: &str) -> Option<String> {
    payload.get(key).and_then(|v| v.as_str()).map(|s| s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn node(id: Uuid, name: &str, parent: Option<Uuid>, is_folder: bool) -> TreeNode {
        TreeNode {
            id,
            name: name.to_string(),
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
        engine.load_snapshot(
            vec![
                node(folder, "Documents", None, true),
                node(file_a, "a.txt", Some(folder), false),
                node(file_b, "b.txt", Some(folder), false),
            ],
            42,
        );

        assert_eq!(engine.tree_size(), 3);
        assert_eq!(engine.last_seq(), 42);
        assert_eq!(engine.children(Some(folder)).len(), 2);
        assert_eq!(engine.children(None).len(), 1);
    }

    #[test]
    fn test_apply_remote_file_create() {
        let mut engine = SyncEngine::new("dev-1".into());
        let id = Uuid::new_v4();
        let event = engine.apply_remote_op(op(
            1,
            "file_create",
            json!({
                "id": id.to_string(),
                "name_encrypted": "enc:hello.txt",
                "size_bytes": 256,
                "mime_type": "text/plain",
            }),
        ));

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
        engine.load_snapshot(vec![node(id, "old.txt", None, false)], 1);

        let event = engine.apply_remote_op(op(
            2,
            "file_rename",
            json!({
                "id": id.to_string(),
                "new_name_encrypted": "enc:new.txt",
                "new_name": "new.txt",
            }),
        ));

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
        engine.load_snapshot(
            vec![
                node(folder_a, "A", None, true),
                node(folder_b, "B", None, true),
                node(file, "f.txt", Some(folder_a), false),
            ],
            1,
        );

        let event = engine.apply_remote_op(op(
            2,
            "file_move",
            json!({
                "id": file.to_string(),
                "old_parent_id": folder_a.to_string(),
                "new_parent_id": folder_b.to_string(),
            }),
        ));

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
        let pending = engine.apply_local_op(
            "file_create",
            json!({
                "id": id.to_string(),
                "name_encrypted": "enc:local.txt",
                "name": "local.txt",
                "size_bytes": 10,
            }),
        );

        assert!(engine.get_node(id).is_some());
        assert_eq!(engine.pending_ops().len(), 1);

        let echoed = SyncOp {
            seq_id: 7,
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

        let event = engine.apply_remote_op(echoed);
        assert!(event.is_none(), "echoed op must be suppressed");
        assert_eq!(engine.pending_ops().len(), 0);
        assert_eq!(engine.last_seq(), 7);
        assert!(engine.get_node(id).is_some(), "tree state preserved");
    }

    #[test]
    fn test_reject_rollback() {
        let mut engine = SyncEngine::new("dev-1".into());
        let id = Uuid::new_v4();
        engine.load_snapshot(vec![node(id, "original.txt", None, false)], 1);

        let pending = engine.apply_local_op(
            "file_rename",
            json!({
                "id": id.to_string(),
                "new_name_encrypted": "enc:my-rename.txt",
                "new_name": "my-rename.txt",
            }),
        );
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
        let event = engine.reject_op(pending.client_op_id, winner);

        assert!(matches!(event, Some(SyncEvent::FileRenamed { .. })));
        let n = engine.get_node(id).unwrap();
        assert_eq!(n.name, "winner.txt", "winning op applied after rollback");
        assert_eq!(engine.pending_ops().len(), 0);
    }

    #[test]
    fn test_search() {
        let mut engine = SyncEngine::new("dev-1".into());
        engine.load_snapshot(
            vec![
                node(Uuid::new_v4(), "Tax Returns 2024.pdf", None, false),
                node(Uuid::new_v4(), "vacation-photos", None, true),
                node(Uuid::new_v4(), "tax_summary.txt", None, false),
                node(Uuid::new_v4(), "notes.md", None, false),
            ],
            1,
        );

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
        engine.load_snapshot(vec![node(id, "a.txt", None, false)], 1);

        engine.apply_remote_op(op(2, "file_trash", json!({"id": id.to_string()})));
        assert!(engine.get_node(id).unwrap().is_trashed);
        assert_eq!(engine.children(None).len(), 0);

        engine.apply_remote_op(op(3, "file_restore", json!({"id": id.to_string()})));
        assert!(!engine.get_node(id).unwrap().is_trashed);
        assert_eq!(engine.children(None).len(), 1);
    }

    #[test]
    fn test_permanent_delete_clears_pin() {
        let mut engine = SyncEngine::new("dev-1".into());
        let id = Uuid::new_v4();
        engine.load_snapshot(vec![node(id, "a.txt", None, false)], 1);
        engine.pin(id);
        assert!(engine.is_pinned(id));

        engine.apply_remote_op(op(2, "file_delete", json!({"id": id.to_string()})));
        assert!(engine.get_node(id).is_none());
        assert!(!engine.is_pinned(id));
    }
}
