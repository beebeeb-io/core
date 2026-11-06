use crate::{
    AssetClass, BackupAsset, BoundedInsert, CacheEntry, CacheInsertOutcome, ContactKey, Device, Node, OpLogEntry,
    Result, SignOutDirectories, StoreError, Transfer, TransferState, VersionObservation, error::io_error, migrations,
};
use beebeeb_core::sync::{StoredSyncMetadata, StoredSyncState, SyncStore, SyncStoreChanges, SyncStoreError, TreeNode};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use std::{
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

const BUSY_TIMEOUT: Duration = Duration::from_secs(10);

/// A blocking connection to one account's database for one product.
///
/// Each call finishes its transaction before returning. There are no callback
/// APIs, so a write lock is never held while caller code runs.
pub struct Store {
    conn: Connection,
    path: Option<PathBuf>,
}

impl Store {
    /// Opens or creates a database at a caller-selected account/product path.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        if path.as_os_str().is_empty() {
            return Err(StoreError::InvalidValue("database path must not be empty"));
        }
        if let Some(parent) = path.parent().filter(|parent| !parent.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent).map_err(|error| io_error(parent, error))?;
        }
        Self::finish_open(Connection::open(path)?, Some(path.to_owned()))
    }

    /// Opens an isolated in-memory store, primarily for tests.
    pub fn open_in_memory() -> Result<Self> {
        Self::finish_open(Connection::open_in_memory()?, None)
    }

    fn finish_open(mut conn: Connection, path: Option<PathBuf>) -> Result<Self> {
        conn.busy_timeout(BUSY_TIMEOUT)?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        if path.is_some() {
            retry_busy(|| {
                let mode: String = conn.pragma_query_value(None, "journal_mode", |row| row.get(0))?;
                if !mode.eq_ignore_ascii_case("wal") {
                    conn.pragma_update(None, "journal_mode", "WAL")?;
                }
                Ok(())
            })?;
        }
        retry_busy(|| conn.pragma_update(None, "synchronous", "FULL"))?;
        migrations::migrate(&mut conn)?;
        Ok(Self { conn, path })
    }

    fn conn(&self) -> &Connection {
        &self.conn
    }

    fn conn_mut(&mut self) -> &mut Connection {
        &mut self.conn
    }

    /// Checkpoints and truncates this database's WAL before app suspension.
    pub fn prepare_for_suspension(&self) -> Result<()> {
        self.conn()
            .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()))?;
        Ok(())
    }

    /// Closes the SQLite connection.
    pub fn close(self) -> Result<()> {
        self.conn.close().map_err(|(_, error)| error)?;
        Ok(())
    }

    /// Closes and deletes the database and its known SQLite sidecars, then
    /// returns account-owned directories for the platform to recursively clear.
    pub fn sign_out(self, directories: SignOutDirectories) -> Result<SignOutDirectories> {
        let Self { conn, path } = self;
        conn.close().map_err(|(_, error)| error)?;
        if let Some(path) = path {
            remove_file_if_present(&path)?;
            remove_file_if_present(&sidecar_path(&path, "-wal"))?;
            remove_file_if_present(&sidecar_path(&path, "-shm"))?;
        }
        Ok(directories)
    }

    /// Atomically remove every account-owned row while the shared connection
    /// is still reachable. The platform may subsequently remove the closed
    /// database file and recursively delete account directories.
    pub fn purge_account_data(&mut self) -> Result<()> {
        let tx = self
            .conn_mut()
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute_batch(
            "DELETE FROM nodes;
             DELETE FROM op_log;
             DELETE FROM sync_positions;
             DELETE FROM transfers;
             DELETE FROM asset_limits;
             DELETE FROM cache_index;
             DELETE FROM backup_assets;
             DELETE FROM device_settings;
             DELETE FROM contact_keys;
             DELETE FROM file_versions;
             DELETE FROM devices;",
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn upsert_nodes(&mut self, nodes: &[Node]) -> Result<()> {
        let tx = self
            .conn_mut()
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        {
            let mut stmt = tx.prepare_cached(
                "INSERT INTO nodes (id,parent_id,encrypted_name,decrypted_name,mime_type,size_bytes,is_folder,created_at,updated_at,payload)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)
                 ON CONFLICT(id) DO UPDATE SET parent_id=excluded.parent_id, encrypted_name=excluded.encrypted_name,
                 decrypted_name=excluded.decrypted_name, mime_type=excluded.mime_type, size_bytes=excluded.size_bytes,
                 is_folder=excluded.is_folder, created_at=excluded.created_at, updated_at=excluded.updated_at, payload=excluded.payload",
            )?;
            for node in nodes {
                stmt.execute(params![
                    node.id,
                    node.parent_id,
                    node.encrypted_name,
                    node.decrypted_name,
                    node.mime_type,
                    sql_u64(node.size_bytes, "node size exceeds SQLite integer range")?,
                    node.is_folder,
                    node.created_at,
                    node.updated_at,
                    node.payload,
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    pub fn get_node(&self, id: &str) -> Result<Option<Node>> {
        self.conn()
            .query_row(NODE_SELECT_BY_ID, [id], row_to_node)
            .optional()
            .map_err(Into::into)
    }

    /// Provides the same item enumeration needed by the former File Provider cache.
    pub fn list_children(&self, parent_id: Option<&str>) -> Result<Vec<Node>> {
        let (sql, value) = match parent_id {
            Some(parent) => (
                format!("{NODE_SELECT} WHERE parent_id = ?1 ORDER BY is_folder DESC, decrypted_name ASC, id ASC"),
                Some(parent),
            ),
            None => (
                format!("{NODE_SELECT} WHERE parent_id IS NULL ORDER BY is_folder DESC, decrypted_name ASC, id ASC"),
                None,
            ),
        };
        let mut stmt = self.conn().prepare(&sql)?;
        let mapped = match value {
            Some(parent) => stmt.query_map([parent], row_to_node)?,
            None => stmt.query_map([], row_to_node)?,
        };
        mapped.collect::<rusqlite::Result<Vec<_>>>().map_err(Into::into)
    }

    pub fn delete_node(&mut self, id: &str) -> Result<bool> {
        Ok(self.conn_mut().execute("DELETE FROM nodes WHERE id=?1", [id])? != 0)
    }

    pub fn node_count(&self) -> Result<u64> {
        count(self.conn(), "nodes")
    }

    pub fn append_op(&mut self, kind: &str, payload: &[u8], created_at: i64) -> Result<i64> {
        self.conn_mut().execute(
            "INSERT INTO op_log(kind,payload,created_at) VALUES (?1,?2,?3)",
            params![kind, payload, created_at],
        )?;
        Ok(self.conn().last_insert_rowid())
    }

    pub fn pending_ops(&self, limit: u32) -> Result<Vec<OpLogEntry>> {
        let mut stmt = self
            .conn()
            .prepare("SELECT id,kind,payload,created_at FROM op_log WHERE acknowledged=0 ORDER BY id LIMIT ?1")?;
        let rows = stmt.query_map([i64::from(limit)], |row| {
            Ok(OpLogEntry {
                id: row.get(0)?,
                kind: row.get(1)?,
                payload: row.get(2)?,
                created_at: row.get(3)?,
            })
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(Into::into)
    }

    pub fn ack_op(&mut self, id: i64) -> Result<bool> {
        Ok(self
            .conn_mut()
            .execute("UPDATE op_log SET acknowledged=1 WHERE id=?1", [id])?
            != 0)
    }

    pub fn op_count(&self) -> Result<u64> {
        count(self.conn(), "op_log")
    }

    pub fn set_sync_position(&mut self, scope: &str, value: &[u8]) -> Result<()> {
        self.conn_mut().execute("INSERT INTO sync_positions(scope,value) VALUES (?1,?2) ON CONFLICT(scope) DO UPDATE SET value=excluded.value", params![scope, value])?;
        Ok(())
    }

    pub fn sync_position(&self, scope: &str) -> Result<Option<Vec<u8>>> {
        self.conn()
            .query_row("SELECT value FROM sync_positions WHERE scope=?1", [scope], |row| {
                row.get(0)
            })
            .optional()
            .map_err(Into::into)
    }

    pub fn enqueue_transfer(&mut self, kind: &str, payload: &[u8], max_attempts: u32, now: i64) -> Result<i64> {
        if max_attempts == 0 {
            return Err(StoreError::InvalidValue("transfer retry limit must be positive"));
        }
        self.conn_mut().execute("INSERT INTO transfers(kind,payload,max_attempts,state,created_at,updated_at) VALUES (?1,?2,?3,'queued',?4,?4)", params![kind, payload, i64::from(max_attempts), now])?;
        Ok(self.conn().last_insert_rowid())
    }

    /// Atomically leases the oldest queued or expired transfer.
    pub fn claim_transfer(&mut self, now: i64, lease_until: i64) -> Result<Option<Transfer>> {
        self.claim_transfer_where(now, lease_until, None)
    }

    pub fn claim_transfer_kind(&mut self, kind: &str, now: i64, lease_until: i64) -> Result<Option<Transfer>> {
        self.claim_transfer_where(now, lease_until, Some((kind, None)))
    }

    pub fn claim_transfer_kinds(
        &mut self,
        first_kind: &str,
        second_kind: &str,
        now: i64,
        lease_until: i64,
    ) -> Result<Option<Transfer>> {
        self.claim_transfer_where(now, lease_until, Some((first_kind, Some(second_kind))))
    }

    fn claim_transfer_where(
        &mut self,
        now: i64,
        lease_until: i64,
        kinds: Option<(&str, Option<&str>)>,
    ) -> Result<Option<Transfer>> {
        if lease_until <= now {
            return Err(StoreError::InvalidValue("transfer lease must end after it starts"));
        }
        let tx = self
            .conn_mut()
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let id: Option<i64> = match kinds {
            None => tx.query_row("SELECT id FROM transfers WHERE state='queued' OR (state='running' AND lease_until <= ?1) ORDER BY id LIMIT 1", [now], |row| row.get(0)).optional()?,
            Some((first, None)) => tx.query_row("SELECT id FROM transfers WHERE kind=?2 AND (state='queued' OR (state='running' AND lease_until <= ?1)) ORDER BY id LIMIT 1", params![now, first], |row| row.get(0)).optional()?,
            Some((first, Some(second))) => tx.query_row("SELECT id FROM transfers WHERE kind IN (?2,?3) AND (state='queued' OR (state='running' AND lease_until <= ?1)) ORDER BY id LIMIT 1", params![now, first, second], |row| row.get(0)).optional()?,
        };
        let Some(id) = id else {
            tx.commit()?;
            return Ok(None);
        };
        tx.execute(
            "UPDATE transfers SET state='running',lease_until=?2,updated_at=?1 WHERE id=?3",
            params![now, lease_until, id],
        )?;
        let transfer = get_transfer_from(&tx, id)?;
        tx.commit()?;
        Ok(Some(transfer))
    }

    pub fn record_transfer_failure(&mut self, id: i64, message: &str, now: i64) -> Result<Transfer> {
        let tx = self
            .conn_mut()
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (attempts, maximum): (i64, i64) = tx
            .query_row(
                "SELECT attempts,max_attempts FROM transfers WHERE id=?1 AND state='running'",
                [id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?
            .ok_or(StoreError::NotFound)?;
        let attempts = attempts
            .checked_add(1)
            .ok_or(StoreError::InvalidValue("transfer attempt count overflow"))?;
        let state = if attempts >= maximum { "failed" } else { "queued" };
        tx.execute(
            "UPDATE transfers SET attempts=?1,state=?2,lease_until=NULL,last_error=?3,updated_at=?4 WHERE id=?5",
            params![attempts, state, message, now, id],
        )?;
        let transfer = get_transfer_from(&tx, id)?;
        tx.commit()?;
        Ok(transfer)
    }

    /// Replace the durable service-owned state for an active transfer.
    pub fn update_transfer_payload(&mut self, id: i64, payload: &[u8], now: i64) -> Result<bool> {
        Ok(self.conn_mut().execute(
            "UPDATE transfers SET payload=?1,updated_at=?2 WHERE id=?3 AND state IN ('queued','running','paused')",
            params![payload, now, id],
        )? != 0)
    }

    /// Update service-owned bookkeeping after a transfer reached a final
    /// state. The transfer state itself is never reopened by this operation.
    pub fn update_final_transfer_payload(&mut self, id: i64, payload: &[u8], now: i64) -> Result<bool> {
        Ok(self.conn_mut().execute(
            "UPDATE transfers SET payload=?1,updated_at=?2 WHERE id=?3 AND state IN ('succeeded','failed','cancelled')",
            params![payload, now, id],
        )? != 0)
    }

    pub fn release_transfer(&mut self, id: i64, now: i64) -> Result<bool> {
        Ok(self.conn_mut().execute(
            "UPDATE transfers SET state='queued',lease_until=NULL,updated_at=?1 WHERE id=?2 AND state='running'",
            params![now, id],
        )? != 0)
    }

    pub fn pause_transfer(&mut self, id: i64, now: i64) -> Result<bool> {
        Ok(self.conn_mut().execute(
            "UPDATE transfers SET state='paused',lease_until=NULL,updated_at=?1 WHERE id=?2 AND state IN ('queued','running')",
            params![now, id],
        )? != 0)
    }

    pub fn resume_transfer(&mut self, id: i64, now: i64) -> Result<bool> {
        Ok(self.conn_mut().execute(
            "UPDATE transfers SET state='queued',lease_until=NULL,updated_at=?1 WHERE id=?2 AND state='paused'",
            params![now, id],
        )? != 0)
    }

    pub fn cancel_transfer(&mut self, id: i64, now: i64) -> Result<bool> {
        Ok(self.conn_mut().execute(
            "UPDATE transfers SET state='cancelled',lease_until=NULL,updated_at=?1 WHERE id=?2 AND state IN ('queued','running','paused')",
            params![now, id],
        )? != 0)
    }

    pub fn mark_transfer_failed(&mut self, id: i64, message: &str, now: i64) -> Result<bool> {
        Ok(self.conn_mut().execute(
            "UPDATE transfers SET state='failed',lease_until=NULL,last_error=?1,updated_at=?2 WHERE id=?3 AND state IN ('queued','running','paused')",
            params![message, now, id],
        )? != 0)
    }

    pub fn transfers(&self, kind: Option<&str>) -> Result<Vec<Transfer>> {
        let mut rows = Vec::new();
        match kind {
            Some(kind) => {
                let mut stmt = self.conn().prepare(
                    "SELECT id,kind,payload,attempts,max_attempts,state,lease_until,last_error,created_at,updated_at FROM transfers WHERE kind=?1 ORDER BY id",
                )?;
                let mapped = stmt.query_map([kind], row_to_transfer)?;
                rows.extend(mapped.collect::<rusqlite::Result<Vec<_>>>()?);
            }
            None => {
                let mut stmt = self.conn().prepare(
                    "SELECT id,kind,payload,attempts,max_attempts,state,lease_until,last_error,created_at,updated_at FROM transfers ORDER BY id",
                )?;
                let mapped = stmt.query_map([], row_to_transfer)?;
                rows.extend(mapped.collect::<rusqlite::Result<Vec<_>>>()?);
            }
        }
        Ok(rows)
    }

    pub fn mark_transfer_succeeded(&mut self, id: i64, now: i64) -> Result<bool> {
        Ok(self.conn_mut().execute("UPDATE transfers SET state='succeeded',lease_until=NULL,last_error=NULL,updated_at=?1 WHERE id=?2 AND state='running'", params![now, id])? != 0)
    }

    pub fn transfer(&self, id: i64) -> Result<Option<Transfer>> {
        match get_transfer_from(self.conn(), id) {
            Err(StoreError::Database(rusqlite::Error::QueryReturnedNoRows)) => Ok(None),
            value => value.map(Some),
        }
    }

    pub fn set_asset_limit(&mut self, class: AssetClass, size_bytes: u64) -> Result<()> {
        let size = sql_u64(size_bytes, "asset limit exceeds SQLite integer range")?;
        self.conn_mut().execute("INSERT INTO asset_limits(class,size_bytes) VALUES (?1,?2) ON CONFLICT(class) DO UPDATE SET size_bytes=excluded.size_bytes", params![class.as_str(), size])?;
        Ok(())
    }

    pub fn asset_limit(&self, class: AssetClass) -> Result<Option<u64>> {
        self.conn()
            .query_row(
                "SELECT size_bytes FROM asset_limits WHERE class=?1",
                [class.as_str()],
                |row| nonnegative(row.get(0)?),
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn put_cache_entry(
        &mut self,
        class: AssetClass,
        entry: &CacheEntry,
        mode: BoundedInsert,
    ) -> Result<CacheInsertOutcome> {
        let entry_size = sql_u64(entry.size_bytes, "cache entry exceeds SQLite integer range")?;
        let tx = self
            .conn_mut()
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let limit: i64 = tx
            .query_row(
                "SELECT size_bytes FROM asset_limits WHERE class=?1",
                [class.as_str()],
                |row| row.get(0),
            )
            .optional()?
            .ok_or(StoreError::MissingAssetLimit)?;
        if entry_size > limit {
            tx.commit()?;
            return Ok(CacheInsertOutcome {
                accepted: false,
                paths_to_remove: Vec::new(),
            });
        }
        let existing: Option<(i64, String)> = tx
            .query_row(
                "SELECT size_bytes,path FROM cache_index WHERE class=?1 AND key=?2",
                params![class.as_str(), entry.key],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let total: i64 = tx.query_row(
            "SELECT COALESCE(SUM(size_bytes),0) FROM cache_index WHERE class=?1",
            [class.as_str()],
            |row| row.get(0),
        )?;
        let old_size = existing.as_ref().map_or(0, |value| value.0);
        let mut projected = total
            .checked_sub(old_size)
            .and_then(|value| value.checked_add(entry_size))
            .ok_or(StoreError::InvalidValue("cache size total overflow"))?;
        if projected > limit && mode == BoundedInsert::StopAtLimit {
            tx.commit()?;
            return Ok(CacheInsertOutcome {
                accepted: false,
                paths_to_remove: Vec::new(),
            });
        }
        let mut paths = Vec::new();
        if class == AssetClass::Cache {
            if let (Some(file_id), Some(version_id)) = (&entry.file_id, &entry.version_id) {
                let old_versions = {
                    let mut statement = tx.prepare(
                        "SELECT key,path,size_bytes FROM cache_index WHERE class=?1 AND file_id=?2 AND (version_id IS NULL OR version_id<>?3) ORDER BY key",
                    )?;
                    statement
                        .query_map(params![class.as_str(), file_id, version_id], |row| {
                            Ok((
                                row.get::<_, String>(0)?,
                                row.get::<_, String>(1)?,
                                row.get::<_, i64>(2)?,
                            ))
                        })?
                        .collect::<rusqlite::Result<Vec<_>>>()?
                };
                for (key, path, size) in old_versions {
                    tx.execute(
                        "DELETE FROM cache_index WHERE class=?1 AND key=?2",
                        params![class.as_str(), key],
                    )?;
                    projected = projected
                        .checked_sub(size)
                        .ok_or(StoreError::InvalidValue("cache size total underflow"))?;
                    paths.push(path);
                }
            }
        }
        if let Some((_, old_path)) = &existing {
            if old_path != &entry.path {
                paths.push(old_path.clone());
            }
        }
        if projected > limit {
            for (key, path, size) in eviction_candidates(&tx, class, &entry.key)? {
                if projected <= limit {
                    break;
                }
                tx.execute(
                    "DELETE FROM cache_index WHERE class=?1 AND key=?2",
                    params![class.as_str(), key],
                )?;
                projected = projected
                    .checked_sub(size)
                    .ok_or(StoreError::InvalidValue("cache size total underflow"))?;
                paths.push(path);
            }
        }
        tx.execute("INSERT INTO cache_index(class,key,file_id,version_id,path,size_bytes,last_accessed) VALUES (?1,?2,?3,?4,?5,?6,?7) ON CONFLICT(class,key) DO UPDATE SET file_id=excluded.file_id,version_id=excluded.version_id,path=excluded.path,size_bytes=excluded.size_bytes,last_accessed=excluded.last_accessed", params![class.as_str(), entry.key, entry.file_id, entry.version_id, entry.path, entry_size, entry.last_accessed])?;
        tx.commit()?;
        Ok(CacheInsertOutcome {
            accepted: true,
            paths_to_remove: paths,
        })
    }

    pub fn touch_cache_entry(&mut self, class: AssetClass, key: &str, at: i64) -> Result<bool> {
        Ok(self.conn_mut().execute(
            "UPDATE cache_index SET last_accessed=?1 WHERE class=?2 AND key=?3",
            params![at, class.as_str(), key],
        )? != 0)
    }

    pub fn cache_entry(&self, class: AssetClass, key: &str) -> Result<Option<CacheEntry>> {
        self.conn()
            .query_row(
                "SELECT key,file_id,version_id,path,size_bytes,last_accessed FROM cache_index WHERE class=?1 AND key=?2",
                params![class.as_str(), key],
                |row| {
                    Ok(CacheEntry {
                        key: row.get(0)?,
                        file_id: row.get(1)?,
                        version_id: row.get(2)?,
                        path: row.get(3)?,
                        size_bytes: row_u64(row, 4)?,
                        last_accessed: row.get(5)?,
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn clear_cache_index(&mut self, class: AssetClass) -> Result<Vec<String>> {
        let tx = self
            .conn_mut()
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let paths = {
            let mut stmt = tx.prepare("SELECT path FROM cache_index WHERE class=?1 ORDER BY last_accessed,key")?;
            stmt.query_map([class.as_str()], |row| row.get(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?
        };
        tx.execute("DELETE FROM cache_index WHERE class=?1", [class.as_str()])?;
        tx.commit()?;
        Ok(paths)
    }

    pub fn put_backup_asset(&mut self, asset: &BackupAsset) -> Result<()> {
        self.conn_mut().execute("INSERT INTO backup_assets(id,source_id,state,payload,updated_at) VALUES (?1,?2,?3,?4,?5) ON CONFLICT(id) DO UPDATE SET source_id=excluded.source_id,state=excluded.state,payload=excluded.payload,updated_at=excluded.updated_at", params![asset.id, asset.source_id, asset.state, asset.payload, asset.updated_at])?;
        Ok(())
    }

    pub fn backup_asset(&self, id: &str) -> Result<Option<BackupAsset>> {
        self.conn()
            .query_row(
                "SELECT id,source_id,state,payload,updated_at FROM backup_assets WHERE id=?1",
                [id],
                |row| {
                    Ok(BackupAsset {
                        id: row.get(0)?,
                        source_id: row.get(1)?,
                        state: row.get(2)?,
                        payload: row.get(3)?,
                        updated_at: row.get(4)?,
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn put_device_setting(&mut self, device_id: &str, product: &str, key: &str, value: &[u8]) -> Result<()> {
        self.conn_mut().execute(
            "INSERT INTO device_settings(device_id,product,key,value) VALUES (?1,?2,?3,?4)
             ON CONFLICT(device_id,product,key) DO UPDATE SET value=excluded.value",
            params![device_id, product, key, value],
        )?;
        Ok(())
    }

    pub fn device_setting(&self, device_id: &str, product: &str, key: &str) -> Result<Option<Vec<u8>>> {
        self.conn()
            .query_row(
                "SELECT value FROM device_settings WHERE device_id=?1 AND product=?2 AND key=?3",
                params![device_id, product, key],
                |row| row.get(0),
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn put_contact_key(&mut self, key: &ContactKey) -> Result<()> {
        self.conn_mut().execute("INSERT INTO contact_keys(contact_id,public_key,observed_at) VALUES (?1,?2,?3) ON CONFLICT(contact_id) DO UPDATE SET public_key=excluded.public_key,observed_at=excluded.observed_at", params![key.contact_id,key.public_key,key.observed_at])?;
        Ok(())
    }

    pub fn contact_key(&self, id: &str) -> Result<Option<ContactKey>> {
        self.conn()
            .query_row(
                "SELECT contact_id,public_key,observed_at FROM contact_keys WHERE contact_id=?1",
                [id],
                |row| {
                    Ok(ContactKey {
                        contact_id: row.get(0)?,
                        public_key: row.get(1)?,
                        observed_at: row.get(2)?,
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn observe_file_version(&mut self, file_id: &str, counter: u64) -> Result<VersionObservation> {
        let counter = sql_u64(counter, "file version exceeds SQLite integer range")?;
        let tx = self
            .conn_mut()
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let previous: Option<i64> = tx
            .query_row("SELECT highest FROM file_versions WHERE file_id=?1", [file_id], |row| {
                row.get(0)
            })
            .optional()?;
        let observation = match previous {
            None => {
                tx.execute(
                    "INSERT INTO file_versions(file_id,highest) VALUES (?1,?2)",
                    params![file_id, counter],
                )?;
                VersionObservation::NewHighest
            }
            Some(highest) if counter > highest => {
                tx.execute(
                    "UPDATE file_versions SET highest=?1 WHERE file_id=?2",
                    params![counter, file_id],
                )?;
                VersionObservation::NewHighest
            }
            Some(highest) if counter == highest => VersionObservation::Equal,
            Some(highest) => VersionObservation::Older {
                highest: nonnegative(highest)?,
            },
        };
        tx.commit()?;
        Ok(observation)
    }

    pub fn highest_file_version(&self, file_id: &str) -> Result<Option<u64>> {
        self.conn()
            .query_row("SELECT highest FROM file_versions WHERE file_id=?1", [file_id], |row| {
                nonnegative(row.get(0)?)
            })
            .optional()
            .map_err(Into::into)
    }

    pub fn put_device(&mut self, device: &Device) -> Result<()> {
        self.conn_mut().execute("INSERT INTO devices(id,name,public_key,updated_at) VALUES (?1,?2,?3,?4) ON CONFLICT(id) DO UPDATE SET name=excluded.name,public_key=excluded.public_key,updated_at=excluded.updated_at", params![device.id,device.name,device.public_key,device.updated_at])?;
        Ok(())
    }

    pub fn devices(&self) -> Result<Vec<Device>> {
        let mut stmt = self
            .conn()
            .prepare("SELECT id,name,public_key,updated_at FROM devices ORDER BY id")?;
        let rows = stmt.query_map([], |row| {
            Ok(Device {
                id: row.get(0)?,
                name: row.get(1)?,
                public_key: row.get(2)?,
                updated_at: row.get(3)?,
            })
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(Into::into)
    }

    pub fn integrity_check(&self) -> Result<()> {
        let result: String = self.conn().query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
        if result == "ok" {
            Ok(())
        } else {
            Err(StoreError::Integrity)
        }
    }
}

const CORE_SYNC_METADATA_SCOPE: &str = "core-sync-metadata-v1";

impl SyncStore for Store {
    fn load(&self) -> std::result::Result<StoredSyncState, SyncStoreError> {
        let mut state = StoredSyncState::default();
        let mut statement = self
            .conn()
            .prepare("SELECT payload FROM nodes")
            .map_err(sync_store_error)?;
        let rows = statement
            .query_map([], |row| row.get::<_, Vec<u8>>(0))
            .map_err(sync_store_error)?;
        for row in rows {
            let payload = row.map_err(sync_store_error)?;
            let node: TreeNode =
                serde_json::from_slice(&payload).map_err(|_| SyncStoreError::new("invalid stored sync node"))?;
            state.tree.insert(node.id, node);
        }
        let metadata: Option<Vec<u8>> = self
            .conn()
            .query_row(
                "SELECT value FROM sync_positions WHERE scope=?1",
                [CORE_SYNC_METADATA_SCOPE],
                |row| row.get(0),
            )
            .optional()
            .map_err(sync_store_error)?;
        if let Some(bytes) = metadata {
            let metadata: StoredSyncMetadata =
                serde_json::from_slice(&bytes).map_err(|_| SyncStoreError::new("invalid stored sync metadata"))?;
            state.position = metadata.position;
            state.pending_ops = metadata.pending_ops;
            state.applied_ops = metadata.applied_ops;
            state.change_anchor_floor = metadata.change_anchor_floor;
            state.pinned_files = metadata.pinned_files;
            state.conflict_decisions = metadata.conflict_decisions;
        }
        Ok(state)
    }

    fn load_metadata(&self) -> std::result::Result<StoredSyncMetadata, SyncStoreError> {
        let value: Option<Vec<u8>> = self
            .conn()
            .query_row(
                "SELECT value FROM sync_positions WHERE scope=?1",
                [CORE_SYNC_METADATA_SCOPE],
                |row| row.get(0),
            )
            .optional()
            .map_err(sync_store_error)?;
        value.map_or_else(
            || Ok(StoredSyncMetadata::default()),
            |bytes| serde_json::from_slice(&bytes).map_err(|_| SyncStoreError::new("invalid stored sync metadata")),
        )
    }

    fn get_node(&self, id: uuid::Uuid) -> std::result::Result<Option<TreeNode>, SyncStoreError> {
        let payload: Option<Vec<u8>> = self
            .conn()
            .query_row("SELECT payload FROM nodes WHERE id=?1", [id.to_string()], |row| {
                row.get(0)
            })
            .optional()
            .map_err(sync_store_error)?;
        payload
            .map(|bytes| serde_json::from_slice(&bytes).map_err(|_| SyncStoreError::new("invalid stored sync node")))
            .transpose()
    }

    fn children(&self, parent_id: Option<uuid::Uuid>) -> std::result::Result<Vec<TreeNode>, SyncStoreError> {
        let sql = if parent_id.is_some() {
            "SELECT payload FROM nodes WHERE parent_id=?1 ORDER BY is_folder DESC,decrypted_name,id"
        } else {
            "SELECT payload FROM nodes WHERE parent_id IS NULL ORDER BY is_folder DESC,decrypted_name,id"
        };
        let mut statement = self.conn().prepare(sql).map_err(sync_store_error)?;
        let mut nodes = Vec::new();
        if let Some(parent_id) = parent_id {
            let rows = statement
                .query_map([parent_id.to_string()], |row| row.get::<_, Vec<u8>>(0))
                .map_err(sync_store_error)?;
            for row in rows {
                let payload = row.map_err(sync_store_error)?;
                let node: TreeNode =
                    serde_json::from_slice(&payload).map_err(|_| SyncStoreError::new("invalid stored sync node"))?;
                if !node.is_trashed {
                    nodes.push(node);
                }
            }
        } else {
            let rows = statement
                .query_map([], |row| row.get::<_, Vec<u8>>(0))
                .map_err(sync_store_error)?;
            for row in rows {
                let payload = row.map_err(sync_store_error)?;
                let node: TreeNode =
                    serde_json::from_slice(&payload).map_err(|_| SyncStoreError::new("invalid stored sync node"))?;
                if !node.is_trashed {
                    nodes.push(node);
                }
            }
        }
        Ok(nodes)
    }

    fn changes_since(
        &self,
        seq_id: i64,
        limit: usize,
    ) -> std::result::Result<Vec<beebeeb_core::sync::SyncOp>, SyncStoreError> {
        Ok(self
            .load_metadata()?
            .applied_ops
            .into_iter()
            .filter(|operation| operation.seq_id > seq_id)
            .take(limit)
            .collect())
    }

    fn apply(&mut self, changes: &SyncStoreChanges) -> std::result::Result<(), SyncStoreError> {
        if changes.is_empty() {
            return Ok(());
        }
        let tx = self
            .conn_mut()
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sync_store_error)?;
        for id in &changes.deleted_node_ids {
            tx.execute("DELETE FROM nodes WHERE id=?1", [id.to_string()])
                .map_err(sync_store_error)?;
        }
        for node in &changes.upserted_nodes {
            let size = u64::try_from(node.size_bytes)
                .ok()
                .and_then(|value| i64::try_from(value).ok())
                .ok_or_else(|| SyncStoreError::new("sync node size is outside the supported range"))?;
            let payload =
                serde_json::to_vec(node).map_err(|_| SyncStoreError::new("sync node could not be encoded"))?;
            tx.execute(
                "INSERT INTO nodes (id,parent_id,encrypted_name,decrypted_name,mime_type,size_bytes,is_folder,created_at,updated_at,payload)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,NULL,?8,?9)
                 ON CONFLICT(id) DO UPDATE SET parent_id=excluded.parent_id,encrypted_name=excluded.encrypted_name,
                 decrypted_name=excluded.decrypted_name,mime_type=excluded.mime_type,size_bytes=excluded.size_bytes,
                 is_folder=excluded.is_folder,updated_at=excluded.updated_at,payload=excluded.payload",
                params![
                    node.id.to_string(),
                    node.parent_id.map(|id| id.to_string()),
                    node.name_encrypted,
                    node.name,
                    node.mime_type,
                    size,
                    node.is_folder,
                    node.updated_at.to_rfc3339(),
                    payload,
                ],
            )
            .map_err(sync_store_error)?;
        }
        if let Some(metadata) = &changes.metadata {
            let value =
                serde_json::to_vec(metadata).map_err(|_| SyncStoreError::new("sync metadata could not be encoded"))?;
            tx.execute(
                "INSERT INTO sync_positions(scope,value) VALUES (?1,?2)
                 ON CONFLICT(scope) DO UPDATE SET value=excluded.value",
                params![CORE_SYNC_METADATA_SCOPE, value],
            )
            .map_err(sync_store_error)?;
        }
        tx.commit().map_err(sync_store_error)
    }
}

fn sync_store_error(_error: rusqlite::Error) -> SyncStoreError {
    SyncStoreError::new("local sync store operation failed")
}

const NODE_SELECT: &str = "SELECT id,parent_id,encrypted_name,decrypted_name,mime_type,size_bytes,is_folder,created_at,updated_at,payload FROM nodes";
const NODE_SELECT_BY_ID: &str = "SELECT id,parent_id,encrypted_name,decrypted_name,mime_type,size_bytes,is_folder,created_at,updated_at,payload FROM nodes WHERE id=?1";

fn row_to_node(row: &rusqlite::Row<'_>) -> rusqlite::Result<Node> {
    Ok(Node {
        id: row.get(0)?,
        parent_id: row.get(1)?,
        encrypted_name: row.get(2)?,
        decrypted_name: row.get(3)?,
        mime_type: row.get(4)?,
        size_bytes: row_u64(row, 5)?,
        is_folder: row.get(6)?,
        created_at: row.get(7)?,
        updated_at: row.get(8)?,
        payload: row.get(9)?,
    })
}

fn row_u64(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<u64> {
    let value: i64 = row.get(index)?;
    u64::try_from(value).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(index, rusqlite::types::Type::Integer, Box::new(error))
    })
}

fn sql_u64(value: u64, message: &'static str) -> Result<i64> {
    i64::try_from(value).map_err(|_| StoreError::InvalidValue(message))
}

fn nonnegative(value: i64) -> rusqlite::Result<u64> {
    u64::try_from(value)
        .map_err(|error| rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Integer, Box::new(error)))
}

fn transfer_state(value: &str) -> rusqlite::Result<TransferState> {
    match value {
        "queued" => Ok(TransferState::Queued),
        "running" => Ok(TransferState::Running),
        "paused" => Ok(TransferState::Paused),
        "succeeded" => Ok(TransferState::Succeeded),
        "failed" => Ok(TransferState::Failed),
        "cancelled" => Ok(TransferState::Cancelled),
        _ => Err(rusqlite::Error::InvalidQuery),
    }
}

trait ConnectionLike {
    fn as_connection(&self) -> &Connection;
}
impl ConnectionLike for Connection {
    fn as_connection(&self) -> &Connection {
        self
    }
}
impl ConnectionLike for Transaction<'_> {
    fn as_connection(&self) -> &Connection {
        self
    }
}

fn get_transfer_from(conn: &impl ConnectionLike, id: i64) -> Result<Transfer> {
    conn.as_connection().query_row("SELECT id,kind,payload,attempts,max_attempts,state,lease_until,last_error,created_at,updated_at FROM transfers WHERE id=?1", [id], row_to_transfer).map_err(Into::into)
}

fn row_to_transfer(row: &rusqlite::Row<'_>) -> rusqlite::Result<Transfer> {
    let attempts: i64 = row.get(3)?;
    let maximum: i64 = row.get(4)?;
    let state: String = row.get(5)?;
    Ok(Transfer {
        id: row.get(0)?,
        kind: row.get(1)?,
        payload: row.get(2)?,
        attempts: u32::try_from(attempts).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(3, rusqlite::types::Type::Integer, Box::new(error))
        })?,
        max_attempts: u32::try_from(maximum).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(4, rusqlite::types::Type::Integer, Box::new(error))
        })?,
        state: transfer_state(&state)?,
        lease_until: row.get(6)?,
        last_error: row.get(7)?,
        created_at: row.get(8)?,
        updated_at: row.get(9)?,
    })
}

fn eviction_candidates(tx: &Transaction<'_>, class: AssetClass, excluded: &str) -> Result<Vec<(String, String, i64)>> {
    let mut stmt = tx
        .prepare("SELECT key,path,size_bytes FROM cache_index WHERE class=?1 AND key<>?2 ORDER BY last_accessed,key")?;
    let rows = stmt.query_map(params![class.as_str(), excluded], |row| {
        Ok((row.get(0)?, row.get(1)?, row.get(2)?))
    })?;
    rows.collect::<rusqlite::Result<Vec<_>>>().map_err(Into::into)
}

fn count(conn: &Connection, table: &str) -> Result<u64> {
    let sql = match table {
        "nodes" => "SELECT COUNT(*) FROM nodes",
        "op_log" => "SELECT COUNT(*) FROM op_log",
        _ => return Err(StoreError::InvalidValue("unknown count table")),
    };
    let value: i64 = conn.query_row(sql, [], |row| row.get(0))?;
    nonnegative(value).map_err(Into::into)
}

fn sidecar_path(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_owned();
    value.push(suffix);
    PathBuf::from(value)
}

fn remove_file_if_present(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(io_error(path, error)),
    }
}

fn retry_busy<T>(mut operation: impl FnMut() -> rusqlite::Result<T>) -> rusqlite::Result<T> {
    let deadline = Instant::now() + BUSY_TIMEOUT;
    loop {
        match operation() {
            Err(error) if sqlite_is_busy(&error) && Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10));
            }
            result => return result,
        }
    }
}

fn sqlite_is_busy(error: &rusqlite::Error) -> bool {
    matches!(
        error,
        rusqlite::Error::SqliteFailure(inner, _)
            if matches!(
                inner.code,
                rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked
            )
    )
}
