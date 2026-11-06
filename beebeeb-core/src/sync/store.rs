use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::conflict::Resolution;
use super::types::{PendingOp, SyncOp, SyncPosition, TreeNode};

/// Durable state owned by the sync authority.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredSyncState {
    pub tree: HashMap<Uuid, TreeNode>,
    pub position: SyncPosition,
    pub pending_ops: VecDeque<PendingOp>,
    pub applied_ops: VecDeque<SyncOp>,
    /// Anchors below this value predate the retained change window.
    #[serde(default)]
    pub change_anchor_floor: i64,
    pub pinned_files: HashSet<Uuid>,
    pub conflict_decisions: HashMap<Uuid, Resolution>,
}

/// The non-tree portion of a sync transaction.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredSyncMetadata {
    pub position: SyncPosition,
    pub pending_ops: VecDeque<PendingOp>,
    pub applied_ops: VecDeque<SyncOp>,
    #[serde(default)]
    pub change_anchor_floor: i64,
    pub pinned_files: HashSet<Uuid>,
    pub conflict_decisions: HashMap<Uuid, Resolution>,
}

impl From<&StoredSyncState> for StoredSyncMetadata {
    fn from(state: &StoredSyncState) -> Self {
        Self {
            position: state.position,
            pending_ops: state.pending_ops.clone(),
            applied_ops: state.applied_ops.clone(),
            change_anchor_floor: state.change_anchor_floor,
            pinned_files: state.pinned_files.clone(),
            conflict_decisions: state.conflict_decisions.clone(),
        }
    }
}

/// One atomic, incremental persistence transaction.
#[derive(Debug, Clone, Default)]
pub struct SyncStoreChanges {
    pub upserted_nodes: Vec<TreeNode>,
    pub deleted_node_ids: Vec<Uuid>,
    pub replace_non_tree_state: bool,
    pub metadata: Option<StoredSyncMetadata>,
}

impl SyncStoreChanges {
    pub fn between(before: &StoredSyncState, after: &StoredSyncState) -> Self {
        let upserted_nodes = after
            .tree
            .iter()
            .filter(|(id, node)| before.tree.get(id) != Some(*node))
            .map(|(_, node)| node.clone())
            .collect();
        let deleted_node_ids = before
            .tree
            .keys()
            .filter(|id| !after.tree.contains_key(id))
            .copied()
            .collect();
        let before_metadata = StoredSyncMetadata::from(before);
        let after_metadata = StoredSyncMetadata::from(after);
        let replace_non_tree_state = before_metadata != after_metadata;
        Self {
            upserted_nodes,
            deleted_node_ids,
            replace_non_tree_state,
            metadata: replace_non_tree_state.then_some(after_metadata),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.upserted_nodes.is_empty() && self.deleted_node_ids.is_empty() && !self.replace_non_tree_state
    }
}

/// The persistence seam used by the pure sync engine.
///
/// Implementations apply the supplied changes in one atomic transaction. A
/// one-node mutation therefore never rewrites an otherwise unchanged vault.
pub trait SyncStore: Send {
    fn load(&self) -> Result<StoredSyncState, SyncStoreError>;

    /// Load only cursors and bounded bookkeeping, without reading tree rows.
    fn load_metadata(&self) -> Result<StoredSyncMetadata, SyncStoreError> {
        let state = self.load()?;
        Ok(StoredSyncMetadata::from(&state))
    }

    fn get_node(&self, id: Uuid) -> Result<Option<TreeNode>, SyncStoreError> {
        Ok(self.load()?.tree.remove(&id))
    }

    fn children(&self, parent_id: Option<Uuid>) -> Result<Vec<TreeNode>, SyncStoreError> {
        Ok(self
            .load()?
            .tree
            .into_values()
            .filter(|node| node.parent_id == parent_id && !node.is_trashed)
            .collect())
    }

    fn changes_since(&self, seq_id: i64, limit: usize) -> Result<Vec<SyncOp>, SyncStoreError> {
        Ok(self
            .load_metadata()?
            .applied_ops
            .into_iter()
            .filter(|operation| operation.seq_id > seq_id)
            .take(limit)
            .collect())
    }

    /// Atomically replace the tree and metadata from an authoritative complete
    /// snapshot. The default is intentionally allowed to scan here: complete
    /// snapshots are the exceptional full-vault path, not the per-op path.
    fn replace_snapshot(&mut self, nodes: &[TreeNode], metadata: &StoredSyncMetadata) -> Result<(), SyncStoreError> {
        let before = self.load()?;
        let after = StoredSyncState {
            tree: nodes.iter().cloned().map(|node| (node.id, node)).collect(),
            position: metadata.position,
            pending_ops: metadata.pending_ops.clone(),
            applied_ops: metadata.applied_ops.clone(),
            change_anchor_floor: metadata.change_anchor_floor,
            pinned_files: metadata.pinned_files.clone(),
            conflict_decisions: metadata.conflict_decisions.clone(),
        };
        self.apply(&SyncStoreChanges::between(&before, &after))
    }

    fn apply(&mut self, changes: &SyncStoreChanges) -> Result<(), SyncStoreError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncStoreError(String);

impl SyncStoreError {
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for SyncStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for SyncStoreError {}

/// In-memory persistence for tests and ephemeral clients.
#[derive(Debug, Clone, Default)]
pub struct InMemorySyncStore {
    state: StoredSyncState,
}

impl InMemorySyncStore {
    pub fn state(&self) -> &StoredSyncState {
        &self.state
    }
}

impl SyncStore for InMemorySyncStore {
    fn load(&self) -> Result<StoredSyncState, SyncStoreError> {
        Ok(self.state.clone())
    }

    fn apply(&mut self, changes: &SyncStoreChanges) -> Result<(), SyncStoreError> {
        for id in &changes.deleted_node_ids {
            self.state.tree.remove(id);
        }
        for node in &changes.upserted_nodes {
            self.state.tree.insert(node.id, node.clone());
        }
        if let Some(metadata) = &changes.metadata {
            self.state.position = metadata.position;
            self.state.pending_ops.clone_from(&metadata.pending_ops);
            self.state.applied_ops.clone_from(&metadata.applied_ops);
            self.state.change_anchor_floor = metadata.change_anchor_floor;
            self.state.pinned_files.clone_from(&metadata.pinned_files);
            self.state.conflict_decisions.clone_from(&metadata.conflict_decisions);
        }
        Ok(())
    }
}

#[cfg(test)]
mod incremental_tests {
    use super::*;
    use chrono::Utc;

    fn node(id: Uuid, name: String) -> TreeNode {
        TreeNode {
            id,
            name,
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
        }
    }

    #[test]
    fn one_change_in_a_40k_tree_produces_one_node_write() {
        let mut before = StoredSyncState::default();
        for index in 0..40_000 {
            let id = Uuid::from_u128(index + 1);
            before.tree.insert(id, node(id, format!("file-{index}")));
        }
        let mut after = before.clone();
        after.tree.get_mut(&Uuid::from_u128(20_001)).unwrap().name = "renamed".into();

        let changes = SyncStoreChanges::between(&before, &after);

        assert_eq!(changes.upserted_nodes.len(), 1);
        assert!(changes.deleted_node_ids.is_empty());
        assert!(!changes.replace_non_tree_state);
    }
}
