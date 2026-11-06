use std::path::PathBuf;

/// Decrypted tree metadata stored for sync and File Provider enumeration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Node {
    pub id: String,
    pub parent_id: Option<String>,
    pub encrypted_name: Option<String>,
    /// Plaintext by product decision; protect the database at the OS layer.
    pub decrypted_name: Option<String>,
    pub mime_type: Option<String>,
    pub size_bytes: u64,
    pub is_folder: bool,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
    /// Sync-owned opaque metadata.
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpLogEntry {
    pub id: i64,
    pub kind: String,
    pub payload: Vec<u8>,
    pub created_at: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferState {
    Queued,
    Running,
    Paused,
    Succeeded,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transfer {
    pub id: i64,
    pub kind: String,
    pub payload: Vec<u8>,
    pub attempts: u32,
    pub max_attempts: u32,
    pub state: TransferState,
    pub lease_until: Option<i64>,
    pub last_error: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssetClass {
    Cache,
    Thumbnail,
}

impl AssetClass {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Cache => "cache",
            Self::Thumbnail => "thumbnail",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheEntry {
    pub key: String,
    /// Stable file identity for replacing old plaintext versions. Thumbnail
    /// entries leave both authenticated version fields empty.
    pub file_id: Option<String>,
    pub version_id: Option<Vec<u8>>,
    pub path: String,
    pub size_bytes: u64,
    pub last_accessed: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoundedInsert {
    EvictOldest,
    /// Reject the new item at the limit, used during the first thumbnail sync.
    StopAtLimit,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheInsertOutcome {
    pub accepted: bool,
    /// Files are removed by the caller after the transaction commits.
    pub paths_to_remove: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupAsset {
    pub id: String,
    pub source_id: String,
    pub state: String,
    pub payload: Vec<u8>,
    pub updated_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContactKey {
    pub contact_id: String,
    pub public_key: Vec<u8>,
    pub observed_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Device {
    pub id: String,
    pub name: String,
    pub public_key: Vec<u8>,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VersionObservation {
    NewHighest,
    Equal,
    Older { highest: u64 },
}

/// Account-owned directories which the platform must recursively clear.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignOutDirectories {
    pub cache: PathBuf,
    pub thumbnails: PathBuf,
}
