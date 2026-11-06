use std::path::PathBuf;

/// Errors returned by the local store.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// SQLite rejected an operation or found corrupt data.
    #[error("local database operation failed: {0}")]
    Database(#[from] rusqlite::Error),
    /// A filesystem operation failed.
    #[error("local store filesystem operation failed at {path}: {source}")]
    Io {
        /// Path involved in the operation.
        path: PathBuf,
        /// Underlying I/O error.
        source: std::io::Error,
    },
    /// A caller-provided value cannot be represented safely by SQLite.
    #[error("invalid local store value: {0}")]
    InvalidValue(&'static str),
    /// The database was created by a newer, unsupported schema.
    #[error("unsupported local database schema version {found}; latest supported is {latest}")]
    UnsupportedSchema {
        /// Version found in the file.
        found: u32,
        /// Latest version understood by this crate.
        latest: u32,
    },
    /// A bounded cache cannot accept entries until its limit is configured.
    #[error("asset size limit is not configured")]
    MissingAssetLimit,
    /// A row requested by identifier does not exist.
    #[error("local store row was not found")]
    NotFound,
    /// SQLite reported that the database is inconsistent.
    #[error("local database integrity check failed")]
    Integrity,
}

/// Result type used by this crate.
pub type Result<T> = std::result::Result<T, StoreError>;

pub(crate) fn io_error(path: impl Into<PathBuf>, source: std::io::Error) -> StoreError {
    StoreError::Io {
        path: path.into(),
        source,
    }
}
