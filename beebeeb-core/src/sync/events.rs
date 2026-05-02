use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::types::TreeNode;

/// Events emitted by the sync engine for the UI layer to react to.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SyncEvent {
    FileCreated {
        node: TreeNode,
    },
    FileUpdated {
        node: TreeNode,
    },
    FileMoved {
        id: Uuid,
        old_parent: Option<Uuid>,
        new_parent: Option<Uuid>,
    },
    FileRenamed {
        id: Uuid,
        new_name: String,
    },
    FileTrashed {
        id: Uuid,
    },
    FileRestored {
        id: Uuid,
    },
    FileDeleted {
        id: Uuid,
    },
    FolderCreated {
        node: TreeNode,
    },
    /// Emitted after a snapshot bulk-load.
    TreeReloaded,
}
