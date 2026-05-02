use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A single node in the file tree — folder or file.
///
/// `name` is the decrypted filename (client-only). `name_encrypted` is the
/// ciphertext as stored on the server. The server never sees `name`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TreeNode {
    pub id: Uuid,
    pub name: String,
    pub name_encrypted: String,
    pub parent_id: Option<Uuid>,
    pub is_folder: bool,
    pub size_bytes: i64,
    pub mime_type: Option<String>,
    /// BLAKE3 of the encrypted blob — `None` for folders and unuploaded files.
    pub content_hash: Option<String>,
    pub version_number: i32,
    pub has_thumbnail: bool,
    pub storage_pool_id: Option<Uuid>,
    pub is_trashed: bool,
    pub is_starred: bool,
    pub updated_at: DateTime<Utc>,
}

/// A server-assigned op streamed via SSE or fetched via `GET /sync/ops`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncOp {
    pub seq_id: i64,
    pub op_type: String,
    pub client_op_id: Option<Uuid>,
    pub payload: serde_json::Value,
    pub device_id: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// A locally-applied op awaiting server confirmation. Holds a pre-mutation
/// snapshot for rollback if the server rejects the op.
#[derive(Debug, Clone)]
pub struct PendingOp {
    pub client_op_id: Uuid,
    pub op_type: String,
    pub payload: serde_json::Value,
    pub rollback: Option<TreeNode>,
}
