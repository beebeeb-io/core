use crate::{Result, StoreError};
use rusqlite::{Connection, TransactionBehavior};

pub(crate) const LATEST_SCHEMA: u32 = 4;

pub(crate) fn migrate(conn: &mut Connection) -> Result<()> {
    loop {
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        // Read under the write lock: another process may have migrated between
        // opening this connection and acquiring the migration transaction.
        let found: u32 = tx.pragma_query_value(None, "user_version", |row| row.get(0))?;
        if found > LATEST_SCHEMA {
            return Err(StoreError::UnsupportedSchema {
                found,
                latest: LATEST_SCHEMA,
            });
        }
        if found == LATEST_SCHEMA {
            tx.commit()?;
            return Ok(());
        }
        let version = found + 1;
        match version {
            1 => tx.execute_batch(SCHEMA_V1)?,
            2 => tx.execute_batch(SCHEMA_V2)?,
            3 => tx.execute_batch(SCHEMA_V3)?,
            4 => tx.execute_batch(SCHEMA_V4)?,
            _ => {
                return Err(StoreError::UnsupportedSchema {
                    found: version,
                    latest: LATEST_SCHEMA,
                });
            }
        }
        tx.pragma_update(None, "user_version", version)?;
        tx.commit()?;
    }
}

const SCHEMA_V1: &str = r#"
CREATE TABLE nodes (
 id TEXT PRIMARY KEY NOT NULL, parent_id TEXT, encrypted_name TEXT, decrypted_name TEXT,
 mime_type TEXT, size_bytes INTEGER NOT NULL CHECK(size_bytes >= 0), is_folder INTEGER NOT NULL,
 created_at TEXT, updated_at TEXT, payload BLOB NOT NULL
);
CREATE TABLE op_log (
 id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT NOT NULL, payload BLOB NOT NULL,
 created_at INTEGER NOT NULL, acknowledged INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE sync_positions (scope TEXT PRIMARY KEY NOT NULL, value BLOB NOT NULL);
CREATE TABLE transfers (
 id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT NOT NULL, payload BLOB NOT NULL,
 attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts >= 0),
 max_attempts INTEGER NOT NULL CHECK(max_attempts > 0),
 state TEXT NOT NULL CHECK(state IN ('queued','running','succeeded','failed')),
 lease_until INTEGER, last_error TEXT, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
);
CREATE TABLE asset_limits (
 class TEXT PRIMARY KEY NOT NULL CHECK(class IN ('cache','thumbnail')),
 size_bytes INTEGER NOT NULL CHECK(size_bytes >= 0)
);
CREATE TABLE cache_index (
 class TEXT NOT NULL CHECK(class IN ('cache','thumbnail')), key TEXT NOT NULL, path TEXT NOT NULL,
 size_bytes INTEGER NOT NULL CHECK(size_bytes >= 0), last_accessed INTEGER NOT NULL,
 PRIMARY KEY(class, key)
);
CREATE TABLE backup_assets (
 id TEXT PRIMARY KEY NOT NULL, source_id TEXT NOT NULL, state TEXT NOT NULL,
 payload BLOB NOT NULL, updated_at INTEGER NOT NULL
);
CREATE TABLE device_settings (
 device_id TEXT NOT NULL, product TEXT NOT NULL, key TEXT NOT NULL, value BLOB NOT NULL,
 PRIMARY KEY(device_id, product, key)
);
CREATE TABLE contact_keys (
 contact_id TEXT PRIMARY KEY NOT NULL, public_key BLOB NOT NULL, observed_at INTEGER NOT NULL
);
CREATE TABLE file_versions (
 file_id TEXT PRIMARY KEY NOT NULL, highest INTEGER NOT NULL CHECK(highest >= 0)
);
CREATE TABLE devices (
 id TEXT PRIMARY KEY NOT NULL, name TEXT NOT NULL, public_key BLOB NOT NULL, updated_at INTEGER NOT NULL
);
"#;

const SCHEMA_V2: &str = r#"
CREATE INDEX nodes_by_parent ON nodes(parent_id, is_folder DESC, decrypted_name, id);
CREATE INDEX pending_ops ON op_log(acknowledged, id);
CREATE INDEX claimable_transfers ON transfers(state, lease_until, id);
CREATE INDEX cache_eviction ON cache_index(class, last_accessed, key);
"#;

const SCHEMA_V3: &str = r#"
ALTER TABLE transfers RENAME TO transfers_v2;
CREATE TABLE transfers (
 id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT NOT NULL, payload BLOB NOT NULL,
 attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts >= 0),
 max_attempts INTEGER NOT NULL CHECK(max_attempts > 0),
 state TEXT NOT NULL CHECK(state IN ('queued','running','paused','succeeded','failed','cancelled')),
 lease_until INTEGER, last_error TEXT, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
);
INSERT INTO transfers SELECT * FROM transfers_v2;
DROP TABLE transfers_v2;
CREATE INDEX claimable_transfers ON transfers(state, lease_until, id);
"#;

const SCHEMA_V4: &str = r#"
ALTER TABLE cache_index ADD COLUMN file_id TEXT;
ALTER TABLE cache_index ADD COLUMN version_id BLOB;
UPDATE cache_index SET file_id=key WHERE class='cache';
CREATE INDEX cache_file_version ON cache_index(class,file_id,version_id);
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interrupted_migration_rolls_back_schema_and_version() {
        let mut conn = Connection::open_in_memory().unwrap();
        let tx = conn.transaction().unwrap();
        tx.execute_batch("CREATE TABLE half_migrated (id INTEGER);").unwrap();
        tx.pragma_update(None, "user_version", 1).unwrap();
        drop(tx);

        let version: u32 = conn.pragma_query_value(None, "user_version", |row| row.get(0)).unwrap();
        assert_eq!(version, 0);
        let tables: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='half_migrated'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(tables, 0);
        migrate(&mut conn).unwrap();
        let version: u32 = conn.pragma_query_value(None, "user_version", |row| row.get(0)).unwrap();
        assert_eq!(version, LATEST_SCHEMA);
    }

    #[test]
    fn migration_preserves_rows_from_an_older_version() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(SCHEMA_V1).unwrap();
        conn.pragma_update(None, "user_version", 1).unwrap();
        conn.execute("INSERT INTO sync_positions(scope,value) VALUES ('drive',X'0102')", [])
            .unwrap();
        migrate(&mut conn).unwrap();
        let value: Vec<u8> = conn
            .query_row("SELECT value FROM sync_positions WHERE scope='drive'", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(value, [1, 2]);
    }

    #[test]
    fn migration_adds_authenticated_cache_identity_columns() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(SCHEMA_V1).unwrap();
        conn.pragma_update(None, "user_version", 1).unwrap();
        migrate(&mut conn).unwrap();
        let columns: Vec<String> = {
            let mut statement = conn.prepare("PRAGMA table_info(cache_index)").unwrap();
            statement
                .query_map([], |row| row.get(1))
                .unwrap()
                .collect::<rusqlite::Result<_>>()
                .unwrap()
        };
        assert!(columns.iter().any(|column| column == "file_id"));
        assert!(columns.iter().any(|column| column == "version_id"));
    }
}
