use std::collections::VecDeque;
use std::fmt;

use chrono::Utc;
use serde_json::Value;
use uuid::Uuid;

use super::events::SyncEvent;
use super::store::{InMemorySyncStore, StoredSyncState, SyncStore, SyncStoreChanges, SyncStoreError};
use super::types::{PendingOp, SyncOp, SyncPosition, TreeNode};

const MAX_APPLIED_OPS: usize = 4096;

/// A complete account snapshot tied to both server cursors.
pub struct CompleteSnapshot {
    nodes: Vec<TreeNode>,
    position: SyncPosition,
}

impl CompleteSnapshot {
    pub fn new(nodes: Vec<TreeNode>, position: SyncPosition) -> Result<Self, SyncEngineError> {
        if !position.is_known() {
            return Err(SyncEngineError::InvalidPosition(position));
        }
        Ok(Self { nodes, position })
    }
}

/// A failed, partial, or otherwise non-authoritative listing.
///
/// It can contribute nodes but carries no cursor and has no deletion path.
pub struct IncompleteSnapshot {
    nodes: Vec<TreeNode>,
}

impl IncompleteSnapshot {
    pub fn new(nodes: Vec<TreeNode>) -> Self {
        Self { nodes }
    }
}

/// An operation received over the authenticated sync channel.
pub struct RemoteOp(SyncOp);

impl RemoteOp {
    pub fn from_authenticated_session(op: SyncOp) -> Self {
        Self(op)
    }
}

#[derive(Debug)]
pub enum SyncEngineError {
    Store(SyncStoreError),
    InvalidPosition(SyncPosition),
    SequenceGap {
        expected_user_seq: i64,
        received_user_seq: i64,
    },
    SnapshotBehind {
        current: SyncPosition,
        received: SyncPosition,
    },
    AnchorExpired {
        oldest_available: i64,
        requested: i64,
    },
}

impl fmt::Display for SyncEngineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Store(error) => write!(f, "sync store: {error}"),
            Self::InvalidPosition(position) => {
                write!(f, "invalid sync position ({}, {})", position.seq_id, position.user_seq)
            }
            Self::SequenceGap {
                expected_user_seq,
                received_user_seq,
            } => write!(
                f,
                "sync sequence gap: expected user_seq {expected_user_seq}, received {received_user_seq}"
            ),
            Self::SnapshotBehind { current, received } => write!(
                f,
                "sync snapshot moved backwards from ({}, {}) to ({}, {})",
                current.seq_id, current.user_seq, received.seq_id, received.user_seq
            ),
            Self::AnchorExpired {
                oldest_available,
                requested,
            } => write!(
                f,
                "sync anchor {requested} expired; oldest available anchor is {oldest_available}"
            ),
        }
    }
}

impl std::error::Error for SyncEngineError {}

impl From<SyncStoreError> for SyncEngineError {
    fn from(value: SyncStoreError) -> Self {
        Self::Store(value)
    }
}

/// In-memory tree + op log state. See spec §3.
pub struct SyncEngine {
    state: StoredSyncState,
    persisted_state: StoredSyncState,
    store: Box<dyn SyncStore>,
    device_id: String,
    store_backed: bool,
    replace_tree_on_persist: bool,
}

impl SyncEngine {
    pub fn new(device_id: String) -> Self {
        Self {
            state: StoredSyncState::default(),
            persisted_state: StoredSyncState::default(),
            store: Box::<InMemorySyncStore>::default(),
            device_id,
            store_backed: false,
            replace_tree_on_persist: false,
        }
    }

    pub fn with_store(device_id: String, store: impl SyncStore + 'static) -> Result<Self, SyncEngineError> {
        let state = store.load()?;
        Ok(Self {
            persisted_state: state.clone(),
            state,
            store: Box::new(store),
            device_id,
            store_backed: false,
            replace_tree_on_persist: false,
        })
    }

    /// Open a large-vault engine without loading its tree. Operations hydrate
    /// only the row they mutate; enumeration stays store-backed.
    pub fn with_store_backed(device_id: String, store: impl SyncStore + 'static) -> Result<Self, SyncEngineError> {
        let metadata = store.load_metadata()?;
        let state = StoredSyncState {
            position: metadata.position,
            pending_ops: metadata.pending_ops,
            applied_ops: metadata.applied_ops,
            change_anchor_floor: metadata.change_anchor_floor,
            pinned_files: metadata.pinned_files,
            conflict_decisions: metadata.conflict_decisions,
            ..StoredSyncState::default()
        };
        Ok(Self {
            persisted_state: state.clone(),
            state,
            store: Box::new(store),
            device_id,
            store_backed: true,
            replace_tree_on_persist: false,
        })
    }

    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    /// Merge a non-authoritative listing without removing absent nodes or
    /// advancing the cursor.
    pub fn observe_incomplete_snapshot(&mut self, snapshot: IncompleteSnapshot) -> Result<(), SyncEngineError> {
        for node in snapshot.nodes {
            self.state.tree.insert(node.id, node);
        }
        self.persist()
    }

    /// Replace the tree from a snapshot explicitly marked complete at a known
    /// position. Pending local operations remain queued for replay.
    pub fn apply_complete_snapshot(&mut self, snapshot: CompleteSnapshot) -> Result<(), SyncEngineError> {
        if snapshot.position.seq_id < self.state.position.seq_id
            || snapshot.position.user_seq < self.state.position.user_seq
        {
            return Err(SyncEngineError::SnapshotBehind {
                current: self.state.position,
                received: snapshot.position,
            });
        }
        self.state.tree = snapshot.nodes.into_iter().map(|node| (node.id, node)).collect();
        self.state.position = snapshot.position;
        self.state.applied_ops.clear();
        self.state.change_anchor_floor = self.state.change_anchor_floor.max(snapshot.position.seq_id);
        self.state.pinned_files.retain(|id| self.state.tree.contains_key(id));
        let mut pending = std::mem::take(&mut self.state.pending_ops);
        for operation in &mut pending {
            operation.rollback = self.snapshot_for_rollback(&operation.op_type, &operation.payload);
            if operation.op_type != "file_delete" {
                let _ = self.apply_op_to_tree(&operation.op_type, &operation.payload);
            }
        }
        self.state.pending_ops = pending;
        self.replace_tree_on_persist = true;
        self.persist()
    }

    /// Apply a server-assigned op. Returns the UI event to emit, or `None` if
    /// the op was suppressed (matched a pending local op via `client_op_id`).
    pub fn apply_remote_op(&mut self, remote: RemoteOp) -> Result<Option<SyncEvent>, SyncEngineError> {
        let op = remote.0;
        if op.seq_id <= self.state.position.seq_id {
            return Ok(None);
        }
        if let Some(user_seq) = op.user_seq {
            if user_seq <= self.state.position.user_seq {
                return Ok(None);
            }
            let expected = self.state.position.user_seq.saturating_add(1);
            if user_seq != expected {
                return Err(SyncEngineError::SequenceGap {
                    expected_user_seq: expected,
                    received_user_seq: user_seq,
                });
            }
        }
        self.hydrate_target(&op.op_type, &op.payload)?;
        // Echo suppression — our own op coming back via SSE.
        if let Some(client_op_id) = op.client_op_id {
            if let Some(pos) = self
                .state
                .pending_ops
                .iter()
                .position(|p| p.client_op_id == client_op_id)
            {
                let pending = self.state.pending_ops.remove(pos);
                let event = pending
                    .filter(|pending| pending.op_type == "file_delete")
                    .and_then(|_| self.apply_op_to_tree(&op.op_type, &op.payload));
                self.advance_position(&op);
                self.remember_applied_op(op);
                self.persist()?;
                return Ok(event);
            }
        }

        let event = self.apply_op_to_tree(&op.op_type, &op.payload);
        self.advance_position(&op);
        self.remember_applied_op(op);
        self.persist()?;
        Ok(event)
    }

    /// Optimistically apply a local op and queue it for the server. Returns
    /// the queued [`PendingOp`] so the caller can POST it.
    pub fn apply_local_op(&mut self, op_type: &str, payload: Value) -> Result<PendingOp, SyncEngineError> {
        self.hydrate_target(op_type, &payload)?;
        let client_op_id = Uuid::new_v4();
        let rollback = self.snapshot_for_rollback(op_type, &payload);

        // Optimistic apply — ignore the event, the UI emits its own optimistic
        // update for local actions.
        if op_type != "file_delete" {
            let _ = self.apply_op_to_tree(op_type, &payload);
        }

        let pending = PendingOp {
            client_op_id,
            op_type: op_type.to_string(),
            payload,
            rollback,
        };
        self.state.pending_ops.push_back(pending.clone());
        self.persist()?;
        Ok(pending)
    }

    /// Server confirmed the op — drop it from the pending queue. (The echoed
    /// op coming back via SSE will also remove it; this is for the direct
    /// `POST /sync/ops` response path.)
    pub fn confirm_op(&mut self, client_op_id: Uuid) -> Result<(), SyncEngineError> {
        if let Some(pos) = self
            .state
            .pending_ops
            .iter()
            .position(|p| p.client_op_id == client_op_id)
        {
            self.state.pending_ops.remove(pos);
        }
        self.persist()
    }

    /// Roll back a locally queued operation when submission itself failed or
    /// the server rejected it without supplying a winning operation.
    pub fn cancel_local_op(&mut self, client_op_id: Uuid) -> Result<(), SyncEngineError> {
        if let Some(pos) = self
            .state
            .pending_ops
            .iter()
            .position(|pending| pending.client_op_id == client_op_id)
            && let Some(pending) = self.state.pending_ops.remove(pos)
        {
            self.rollback(&pending);
        }
        self.persist()
    }

    /// Server rejected our op (typically a conflict). Roll back the optimistic
    /// change and apply the winning op so the tree converges with the server.
    pub fn reject_op(
        &mut self,
        client_op_id: Uuid,
        winning_op: RemoteOp,
    ) -> Result<Option<SyncEvent>, SyncEngineError> {
        let state_before_reject = self.state.clone();
        if let Some(pos) = self
            .state
            .pending_ops
            .iter()
            .position(|p| p.client_op_id == client_op_id)
        {
            if let Some(pending) = self.state.pending_ops.remove(pos) {
                self.rollback(&pending);
            }
        }
        match self.apply_remote_op(winning_op) {
            Ok(event) => Ok(event),
            Err(error) => {
                self.state = state_before_reject;
                Err(error)
            }
        }
    }

    pub fn get_node(&self, id: Uuid) -> Option<&TreeNode> {
        self.state.tree.get(&id)
    }

    pub fn lookup_node(&self, id: Uuid) -> Result<Option<TreeNode>, SyncEngineError> {
        if let Some(node) = self.state.tree.get(&id) {
            return Ok(Some(node.clone()));
        }
        self.store.get_node(id).map_err(Into::into)
    }

    pub fn lookup_children(&self, parent_id: Option<Uuid>) -> Result<Vec<TreeNode>, SyncEngineError> {
        if self.store_backed {
            self.store.children(parent_id).map_err(Into::into)
        } else {
            Ok(self.children(parent_id).into_iter().cloned().collect())
        }
    }

    pub fn changes_since(&self, seq_id: i64, limit: usize) -> Result<Vec<SyncOp>, SyncEngineError> {
        if seq_id < self.state.change_anchor_floor {
            return Err(SyncEngineError::AnchorExpired {
                oldest_available: self.state.change_anchor_floor,
                requested: seq_id,
            });
        }
        self.store.changes_since(seq_id, limit).map_err(Into::into)
    }

    /// Children of a folder. Pass `None` for root-level nodes.
    pub fn children(&self, parent_id: Option<Uuid>) -> Vec<&TreeNode> {
        self.state
            .tree
            .values()
            .filter(|n| n.parent_id == parent_id && !n.is_trashed)
            .collect()
    }

    /// Case-insensitive substring match on the decrypted name. Searches the
    /// full tree (including trashed nodes — callers can filter).
    pub fn search(&self, query: &str) -> Vec<&TreeNode> {
        let needle = query.to_lowercase();
        self.state
            .tree
            .values()
            .filter(|n| n.name.to_lowercase().contains(&needle))
            .collect()
    }

    pub fn last_seq(&self) -> i64 {
        self.state.position.seq_id
    }

    pub fn position(&self) -> SyncPosition {
        self.state.position
    }

    pub fn pending_ops(&self) -> &VecDeque<PendingOp> {
        &self.state.pending_ops
    }

    pub fn applied_ops(&self) -> &VecDeque<SyncOp> {
        &self.state.applied_ops
    }

    pub fn tree_size(&self) -> usize {
        self.state.tree.len()
    }

    pub fn pin(&mut self, id: Uuid) -> Result<(), SyncEngineError> {
        self.state.pinned_files.insert(id);
        self.persist()
    }

    pub fn unpin(&mut self, id: Uuid) -> Result<(), SyncEngineError> {
        self.state.pinned_files.remove(&id);
        self.persist()
    }

    pub fn is_pinned(&self, id: Uuid) -> bool {
        self.state.pinned_files.contains(&id)
    }

    pub fn record_conflict_decision(
        &mut self,
        id: Uuid,
        resolution: super::conflict::Resolution,
    ) -> Result<(), SyncEngineError> {
        self.state.conflict_decisions.insert(id, resolution);
        self.persist()
    }

    pub fn conflict_decision(&self, id: Uuid) -> Option<super::conflict::Resolution> {
        self.state.conflict_decisions.get(&id).copied()
    }

    pub fn conflict_outcome(
        &self,
        policy: super::conflict::ConflictPolicy,
        local: &super::conflict::VersionInfo,
        remote: &super::conflict::VersionInfo,
        base: Option<&super::conflict::VersionInfo>,
        detected_at: u64,
        now: u64,
    ) -> super::conflict::ConflictOutcome {
        policy.resolve(local, remote, base, detected_at, now)
    }

    // ---------------------------------------------------------------- helpers

    fn persist(&mut self) -> Result<(), SyncEngineError> {
        let result = if self.replace_tree_on_persist {
            let nodes: Vec<_> = self.state.tree.values().cloned().collect();
            self.store
                .replace_snapshot(&nodes, &super::store::StoredSyncMetadata::from(&self.state))
        } else {
            self.store
                .apply(&SyncStoreChanges::between(&self.persisted_state, &self.state))
        };
        match result {
            Ok(()) => {
                self.persisted_state = self.state.clone();
                self.replace_tree_on_persist = false;
                self.evict_store_backed_tree();
                Ok(())
            }
            Err(error) => {
                self.state = self.persisted_state.clone();
                self.replace_tree_on_persist = false;
                self.evict_store_backed_tree();
                Err(error.into())
            }
        }
    }

    fn hydrate_target(&mut self, op_type: &str, payload: &Value) -> Result<(), SyncEngineError> {
        if !self.store_backed || matches!(op_type, "file_create" | "folder_create") {
            return Ok(());
        }
        let Some(id) = uuid_field(payload, "id") else {
            return Ok(());
        };
        if self.state.tree.contains_key(&id) {
            return Ok(());
        }
        if let Some(node) = self.store.get_node(id)? {
            self.persisted_state.tree.insert(id, node.clone());
            self.state.tree.insert(id, node);
        }
        Ok(())
    }

    fn evict_store_backed_tree(&mut self) {
        if self.store_backed {
            self.state.tree.clear();
            self.persisted_state.tree.clear();
        }
    }

    fn advance_position(&mut self, op: &SyncOp) {
        self.state.position.seq_id = op.seq_id;
        if let Some(user_seq) = op.user_seq {
            self.state.position.user_seq = user_seq;
        }
    }

    fn remember_applied_op(&mut self, op: SyncOp) {
        self.state.applied_ops.push_back(op);
        while self.state.applied_ops.len() > MAX_APPLIED_OPS {
            if let Some(expired) = self.state.applied_ops.pop_front() {
                self.state.change_anchor_floor = self.state.change_anchor_floor.max(expired.seq_id);
            }
        }
    }

    /// Capture the pre-mutation node so we can roll back on server reject.
    fn snapshot_for_rollback(&self, op_type: &str, payload: &Value) -> Option<TreeNode> {
        let id = payload.get("id")?.as_str().and_then(|s| Uuid::parse_str(s).ok())?;
        match op_type {
            "file_create" | "folder_create" => None, // nothing to roll back to
            _ => self.state.tree.get(&id).cloned(),
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
                self.state.tree.remove(&id);
            }
            (_, Some(id), Some(snapshot)) => {
                self.state.tree.insert(id, snapshot.clone());
            }
            (_, Some(id), None) => {
                // We had no pre-state (e.g. delete of a node we never had).
                self.state.tree.remove(&id);
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
        let name_undecryptable = payload
            .get("name_undecryptable")
            .and_then(Value::as_bool)
            .unwrap_or(false);

        let node = TreeNode {
            id,
            name,
            name_undecryptable,
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

        self.state.tree.insert(id, node.clone());
        Some(if is_folder {
            SyncEvent::FolderCreated { node }
        } else {
            SyncEvent::FileCreated { node }
        })
    }

    fn apply_update(&mut self, payload: &Value) -> Option<SyncEvent> {
        let id = uuid_field(payload, "id")?;
        let node = self.state.tree.get_mut(&id)?;
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
        let node = self.state.tree.get_mut(&id)?;
        if let Some(new_name_encrypted) = string_field(payload, "new_name_encrypted") {
            node.name_encrypted = new_name_encrypted;
        }
        // For local ops the caller can include the plaintext name; for remote
        // ops the higher layer is responsible for decryption.
        if let Some(new_name) = string_field(payload, "new_name") {
            node.name = new_name;
            node.name_undecryptable = false;
        } else if payload
            .get("new_name_undecryptable")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            node.name.clear();
            node.name_undecryptable = true;
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
        let node = self.state.tree.get_mut(&id)?;
        let old_parent = node.parent_id;
        node.parent_id = new_parent;
        // The server's move carries no name. A client that resolved a name
        // clash in the destination (the drive's conflict name, or the item's
        // own name back when it leaves a clash) adds the plaintext `new_name`.
        if let Some(new_name) = string_field(payload, "new_name") {
            node.name = new_name;
            node.name_undecryptable = false;
        }
        node.updated_at = Utc::now();
        Some(SyncEvent::FileMoved {
            id,
            old_parent,
            new_parent,
        })
    }

    fn apply_trash(&mut self, payload: &Value) -> Option<SyncEvent> {
        let id = uuid_field(payload, "id")?;
        let node = self.state.tree.get_mut(&id)?;
        node.is_trashed = true;
        node.updated_at = Utc::now();
        Some(SyncEvent::FileTrashed { id })
    }

    fn apply_restore(&mut self, payload: &Value) -> Option<SyncEvent> {
        let id = uuid_field(payload, "id")?;
        let node = self.state.tree.get_mut(&id)?;
        node.is_trashed = false;
        node.updated_at = Utc::now();
        Some(SyncEvent::FileRestored { id })
    }

    fn apply_delete(&mut self, payload: &Value) -> Option<SyncEvent> {
        let id = uuid_field(payload, "id")?;
        self.state.tree.remove(&id);
        self.state.pinned_files.remove(&id);
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
mod tests;
