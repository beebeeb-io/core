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
        /// The item's name after the move: a client that resolved a name
        /// clash in the destination may have given it a new one.
        name: String,
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
