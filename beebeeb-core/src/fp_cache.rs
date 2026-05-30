//! FileProvider SQLite cache for iOS Files integration.
//!
//! Stores decrypted file/folder metadata in a local SQLite database so the
//! iOS FileProvider extension can enumerate items without re-fetching from
//! the server on every call. The cache is the extension's single source of
//! truth for directory structure.

use crate::CoreError;

/// A single cached file/folder entry.
#[derive(Debug, Clone)]
pub struct CachedFileEntry {
    /// Server-assigned file/folder ID (UUID string).
    pub id: String,
    /// Parent folder ID, or `None` for root items.
    pub parent_id: Option<String>,
    /// Encrypted name blob (JSON envelope). Stored so we can re-derive if
    /// the master key changes without re-fetching.
    pub name_encrypted: Option<String>,
    /// Decrypted human-readable name.
    pub name_decrypted: Option<String>,
    /// MIME type (e.g. `image/jpeg`), `None` for folders.
    pub mime_type: Option<String>,
    /// File size in bytes (0 for folders).
    pub size_bytes: i64,
    /// `true` if this entry is a folder.
    pub is_folder: bool,
    /// ISO-8601 created timestamp from the server.
    pub created_at: Option<String>,
    /// ISO-8601 updated timestamp from the server.
    pub updated_at: Option<String>,
}

/// SQLite-backed cache for the iOS FileProvider extension.
///
/// Thread-safe: the inner connection is wrapped in a `Mutex` so multiple
/// FileProvider threads can share one instance.
pub struct FileProviderCache {
    db: std::sync::Mutex<rusqlite::Connection>,
}

impl FileProviderCache {
    /// Open (or create) the cache database at `db_path`.
    ///
    /// Pass `":memory:"` for an in-memory database (useful for tests).
    /// The schema is created automatically if the table does not exist.
    pub fn open(db_path: &str) -> Result<Self, CoreError> {
        let conn = if db_path == ":memory:" {
            rusqlite::Connection::open_in_memory()
        } else {
            // Ensure parent directory exists
            if let Some(parent) = std::path::Path::new(db_path).parent() {
                std::fs::create_dir_all(parent).map_err(|e| CoreError::Io(format!("create cache dir: {e}")))?;
            }
            rusqlite::Connection::open(db_path)
        }
        .map_err(|e| CoreError::Io(format!("open cache db: {e}")))?;

        // Enable WAL mode for better concurrent read performance
        conn.execute_batch("PRAGMA journal_mode=WAL;")
            .map_err(|e| CoreError::Io(format!("set WAL mode: {e}")))?;

        // Create schema
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS fp_entries (
                id             TEXT PRIMARY KEY NOT NULL,
                parent_id      TEXT,
                name_encrypted TEXT,
                name_decrypted TEXT,
                mime_type      TEXT,
                size_bytes     INTEGER NOT NULL DEFAULT 0,
                is_folder      INTEGER NOT NULL DEFAULT 0,
                created_at     TEXT,
                updated_at     TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_fp_entries_parent
                ON fp_entries(parent_id);",
        )
        .map_err(|e| CoreError::Io(format!("create cache schema: {e}")))?;

        Ok(Self {
            db: std::sync::Mutex::new(conn),
        })
    }

    /// Insert or update entries in bulk. Returns the number of rows affected.
    ///
    /// Uses `INSERT OR REPLACE` so existing rows are fully overwritten.
    pub fn upsert_entries(&self, entries: &[CachedFileEntry]) -> Result<usize, CoreError> {
        let conn = self
            .db
            .lock()
            .map_err(|e| CoreError::Io(format!("lock cache db: {e}")))?;

        let tx = conn
            .unchecked_transaction()
            .map_err(|e| CoreError::Io(format!("begin transaction: {e}")))?;

        let mut count = 0usize;
        {
            let mut stmt = tx
                .prepare_cached(
                    "INSERT OR REPLACE INTO fp_entries
                        (id, parent_id, name_encrypted, name_decrypted,
                         mime_type, size_bytes, is_folder, created_at, updated_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                )
                .map_err(|e| CoreError::Io(format!("prepare upsert: {e}")))?;

            for entry in entries {
                stmt.execute(rusqlite::params![
                    entry.id,
                    entry.parent_id,
                    entry.name_encrypted,
                    entry.name_decrypted,
                    entry.mime_type,
                    entry.size_bytes,
                    entry.is_folder as i32,
                    entry.created_at,
                    entry.updated_at,
                ])
                .map_err(|e| CoreError::Io(format!("upsert entry: {e}")))?;
                count += 1;
            }
        }

        tx.commit()
            .map_err(|e| CoreError::Io(format!("commit transaction: {e}")))?;

        Ok(count)
    }

    /// Get all children of a parent folder.
    ///
    /// Pass `None` for root-level items (where `parent_id IS NULL`).
    pub fn get_children(&self, parent_id: Option<&str>) -> Result<Vec<CachedFileEntry>, CoreError> {
        let conn = self
            .db
            .lock()
            .map_err(|e| CoreError::Io(format!("lock cache db: {e}")))?;

        let mut stmt = match parent_id {
            Some(_) => conn
                .prepare_cached(
                    "SELECT id, parent_id, name_encrypted, name_decrypted,
                            mime_type, size_bytes, is_folder, created_at, updated_at
                     FROM fp_entries
                     WHERE parent_id = ?1
                     ORDER BY is_folder DESC, name_decrypted ASC",
                )
                .map_err(|e| CoreError::Io(format!("prepare get_children: {e}")))?,
            None => conn
                .prepare_cached(
                    "SELECT id, parent_id, name_encrypted, name_decrypted,
                            mime_type, size_bytes, is_folder, created_at, updated_at
                     FROM fp_entries
                     WHERE parent_id IS NULL
                     ORDER BY is_folder DESC, name_decrypted ASC",
                )
                .map_err(|e| CoreError::Io(format!("prepare get_children (root): {e}")))?,
        };

        let rows = match parent_id {
            Some(pid) => stmt
                .query_map(rusqlite::params![pid], row_to_entry)
                .map_err(|e| CoreError::Io(format!("query children: {e}")))?,
            None => stmt
                .query_map([], row_to_entry)
                .map_err(|e| CoreError::Io(format!("query children (root): {e}")))?,
        };

        let mut entries = Vec::new();
        for row in rows {
            entries.push(row.map_err(|e| CoreError::Io(format!("read row: {e}")))?);
        }
        Ok(entries)
    }

    /// Get a single item by ID.
    pub fn get_item(&self, id: &str) -> Result<Option<CachedFileEntry>, CoreError> {
        let conn = self
            .db
            .lock()
            .map_err(|e| CoreError::Io(format!("lock cache db: {e}")))?;

        let mut stmt = conn
            .prepare_cached(
                "SELECT id, parent_id, name_encrypted, name_decrypted,
                        mime_type, size_bytes, is_folder, created_at, updated_at
                 FROM fp_entries
                 WHERE id = ?1",
            )
            .map_err(|e| CoreError::Io(format!("prepare get_item: {e}")))?;

        let mut rows = stmt
            .query_map(rusqlite::params![id], row_to_entry)
            .map_err(|e| CoreError::Io(format!("query item: {e}")))?;

        match rows.next() {
            Some(row) => Ok(Some(row.map_err(|e| CoreError::Io(format!("read row: {e}")))?)),
            None => Ok(None),
        }
    }

    /// Delete a single entry by ID. Returns `true` if a row was deleted.
    pub fn delete_item(&self, id: &str) -> Result<bool, CoreError> {
        let conn = self
            .db
            .lock()
            .map_err(|e| CoreError::Io(format!("lock cache db: {e}")))?;

        let affected = conn
            .execute("DELETE FROM fp_entries WHERE id = ?1", rusqlite::params![id])
            .map_err(|e| CoreError::Io(format!("delete item: {e}")))?;

        Ok(affected > 0)
    }

    /// Delete all entries. Returns the number of rows deleted.
    pub fn clear(&self) -> Result<usize, CoreError> {
        let conn = self
            .db
            .lock()
            .map_err(|e| CoreError::Io(format!("lock cache db: {e}")))?;

        let affected = conn
            .execute("DELETE FROM fp_entries", [])
            .map_err(|e| CoreError::Io(format!("clear cache: {e}")))?;

        Ok(affected)
    }

    /// Return the total number of cached entries.
    pub fn count(&self) -> Result<usize, CoreError> {
        let conn = self
            .db
            .lock()
            .map_err(|e| CoreError::Io(format!("lock cache db: {e}")))?;

        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM fp_entries", [], |row| row.get(0))
            .map_err(|e| CoreError::Io(format!("count entries: {e}")))?;

        Ok(count as usize)
    }
}

/// Map a SQLite row to a `CachedFileEntry`.
fn row_to_entry(row: &rusqlite::Row<'_>) -> rusqlite::Result<CachedFileEntry> {
    let is_folder_int: i32 = row.get(6)?;
    Ok(CachedFileEntry {
        id: row.get(0)?,
        parent_id: row.get(1)?,
        name_encrypted: row.get(2)?,
        name_decrypted: row.get(3)?,
        mime_type: row.get(4)?,
        size_bytes: row.get(5)?,
        is_folder: is_folder_int != 0,
        created_at: row.get(7)?,
        updated_at: row.get(8)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_entry(id: &str, parent: Option<&str>, name: &str, is_folder: bool) -> CachedFileEntry {
        CachedFileEntry {
            id: id.to_string(),
            parent_id: parent.map(|s| s.to_string()),
            name_encrypted: Some(format!("{{\"encrypted\":\"{name}\"}}")),
            name_decrypted: Some(name.to_string()),
            mime_type: if is_folder {
                None
            } else {
                Some("application/octet-stream".to_string())
            },
            size_bytes: if is_folder { 0 } else { 1024 },
            is_folder,
            created_at: Some("2026-01-01T00:00:00Z".to_string()),
            updated_at: Some("2026-01-01T00:00:00Z".to_string()),
        }
    }

    #[test]
    fn open_in_memory() {
        let cache = FileProviderCache::open(":memory:").unwrap();
        assert_eq!(cache.count().unwrap(), 0);
    }

    #[test]
    fn upsert_and_count() {
        let cache = FileProviderCache::open(":memory:").unwrap();
        let entries = vec![
            make_entry("f1", None, "Photos", true),
            make_entry("f2", None, "Documents", true),
            make_entry("f3", Some("f1"), "vacation.jpg", false),
        ];
        let count = cache.upsert_entries(&entries).unwrap();
        assert_eq!(count, 3);
        assert_eq!(cache.count().unwrap(), 3);
    }

    #[test]
    fn upsert_replaces_existing() {
        let cache = FileProviderCache::open(":memory:").unwrap();

        let entry_v1 = make_entry("f1", None, "Old Name", false);
        cache.upsert_entries(&[entry_v1]).unwrap();

        let entry_v2 = make_entry("f1", None, "New Name", false);
        cache.upsert_entries(&[entry_v2]).unwrap();

        assert_eq!(cache.count().unwrap(), 1);
        let item = cache.get_item("f1").unwrap().unwrap();
        assert_eq!(item.name_decrypted.as_deref(), Some("New Name"));
    }

    #[test]
    fn get_children_root() {
        let cache = FileProviderCache::open(":memory:").unwrap();
        let entries = vec![
            make_entry("f1", None, "Photos", true),
            make_entry("f2", None, "readme.txt", false),
            make_entry("f3", Some("f1"), "child.jpg", false),
        ];
        cache.upsert_entries(&entries).unwrap();

        let root = cache.get_children(None).unwrap();
        assert_eq!(root.len(), 2);
        // Folders first, then files (by name ASC)
        assert_eq!(root[0].id, "f1"); // Photos (folder)
        assert_eq!(root[1].id, "f2"); // readme.txt (file)
    }

    #[test]
    fn get_children_subfolder() {
        let cache = FileProviderCache::open(":memory:").unwrap();
        let entries = vec![
            make_entry("f1", None, "Photos", true),
            make_entry("f3", Some("f1"), "a.jpg", false),
            make_entry("f4", Some("f1"), "b.jpg", false),
            make_entry("f5", Some("f1"), "Subfolder", true),
        ];
        cache.upsert_entries(&entries).unwrap();

        let children = cache.get_children(Some("f1")).unwrap();
        assert_eq!(children.len(), 3);
        // Folder first
        assert!(children[0].is_folder);
        assert_eq!(children[0].name_decrypted.as_deref(), Some("Subfolder"));
    }

    #[test]
    fn get_children_empty() {
        let cache = FileProviderCache::open(":memory:").unwrap();
        let entries = vec![make_entry("f1", None, "EmptyFolder", true)];
        cache.upsert_entries(&entries).unwrap();

        let children = cache.get_children(Some("f1")).unwrap();
        assert!(children.is_empty());
    }

    #[test]
    fn get_item_found() {
        let cache = FileProviderCache::open(":memory:").unwrap();
        let entry = make_entry("abc-123", None, "test.pdf", false);
        cache.upsert_entries(&[entry]).unwrap();

        let item = cache.get_item("abc-123").unwrap().unwrap();
        assert_eq!(item.id, "abc-123");
        assert_eq!(item.name_decrypted.as_deref(), Some("test.pdf"));
        assert_eq!(item.mime_type.as_deref(), Some("application/octet-stream"));
        assert_eq!(item.size_bytes, 1024);
        assert!(!item.is_folder);
    }

    #[test]
    fn get_item_not_found() {
        let cache = FileProviderCache::open(":memory:").unwrap();
        let item = cache.get_item("nonexistent").unwrap();
        assert!(item.is_none());
    }

    #[test]
    fn delete_item() {
        let cache = FileProviderCache::open(":memory:").unwrap();
        cache.upsert_entries(&[make_entry("f1", None, "test", false)]).unwrap();
        assert_eq!(cache.count().unwrap(), 1);

        assert!(cache.delete_item("f1").unwrap());
        assert_eq!(cache.count().unwrap(), 0);

        // Deleting non-existent returns false
        assert!(!cache.delete_item("f1").unwrap());
    }

    #[test]
    fn clear() {
        let cache = FileProviderCache::open(":memory:").unwrap();
        let entries = vec![
            make_entry("f1", None, "a", false),
            make_entry("f2", None, "b", false),
            make_entry("f3", None, "c", false),
        ];
        cache.upsert_entries(&entries).unwrap();
        assert_eq!(cache.count().unwrap(), 3);

        let deleted = cache.clear().unwrap();
        assert_eq!(deleted, 3);
        assert_eq!(cache.count().unwrap(), 0);
    }

    #[test]
    fn upsert_empty_list() {
        let cache = FileProviderCache::open(":memory:").unwrap();
        let count = cache.upsert_entries(&[]).unwrap();
        assert_eq!(count, 0);
        assert_eq!(cache.count().unwrap(), 0);
    }

    #[test]
    fn null_optional_fields() {
        let cache = FileProviderCache::open(":memory:").unwrap();
        let entry = CachedFileEntry {
            id: "bare".to_string(),
            parent_id: None,
            name_encrypted: None,
            name_decrypted: None,
            mime_type: None,
            size_bytes: 0,
            is_folder: false,
            created_at: None,
            updated_at: None,
        };
        cache.upsert_entries(&[entry]).unwrap();

        let item = cache.get_item("bare").unwrap().unwrap();
        assert!(item.parent_id.is_none());
        assert!(item.name_encrypted.is_none());
        assert!(item.name_decrypted.is_none());
        assert!(item.mime_type.is_none());
        assert!(item.created_at.is_none());
        assert!(item.updated_at.is_none());
    }

    #[test]
    fn folder_entry_properties() {
        let cache = FileProviderCache::open(":memory:").unwrap();
        let entry = make_entry("folder-1", None, "MyFolder", true);
        cache.upsert_entries(&[entry]).unwrap();

        let item = cache.get_item("folder-1").unwrap().unwrap();
        assert!(item.is_folder);
        assert_eq!(item.size_bytes, 0);
        assert!(item.mime_type.is_none());
    }
}
