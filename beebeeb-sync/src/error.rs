use thiserror::Error;

#[derive(Debug, Error)]
pub enum SyncError {
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("network error: {0}")]
    NetworkError(String),

    #[error("conflict detected on {path}: modified locally at {local_modified} and remotely at {remote_modified}")]
    ConflictDetected {
        path: String,
        local_modified: String,
        remote_modified: String,
    },

    #[error("session has expired — please re-authenticate")]
    AuthExpired,

    #[error("storage full: {used_bytes} of {limit_bytes} bytes used")]
    StorageFull { used_bytes: u64, limit_bytes: u64 },

    #[error("watcher error: {0}")]
    WatcherError(String),

    #[error("{0}")]
    Other(String),
}
