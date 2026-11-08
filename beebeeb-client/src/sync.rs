use std::{collections::BTreeMap, time::Duration};

use beebeeb_api::routes::sync::{self as api, Snapshot};
use beebeeb_core::{
    name_clash::{ItemKind, TakenNames, drive_conflict_name},
    path_safety::{Rules, check_component},
    sync::{CompleteSnapshot, SyncEngineError, SyncOp, SyncPosition, TreeNode},
};
use chrono::{DateTime, Utc};
use serde_json::Value;
use uuid::Uuid;

use crate::{Client, ClientError, EngineEvent, Session, StreamLimits};

pub use beebeeb_core::sync::{IncompleteSnapshot, RemoteOp, SyncEngine};

const MAX_CATCH_UP_PAGES: usize = 1024;
const DEFAULT_EVENT_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncWake {
    ForegroundStream,
    ReturnedToForegroundCatchUp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConflictState {
    pub file_id: String,
    pub status: &'static str,
    pub decision_deadline: Option<u64>,
}

pub fn conflict_state(
    file_id: impl Into<String>,
    local: &beebeeb_core::sync::conflict::VersionInfo,
    remote: &beebeeb_core::sync::conflict::VersionInfo,
    base: Option<&beebeeb_core::sync::conflict::VersionInfo>,
    detected_at: u64,
    now: u64,
) -> ConflictState {
    let policy = beebeeb_core::sync::conflict::ConflictPolicy::default();
    let outcome = policy.resolve(local, remote, base, detected_at, now);
    ConflictState {
        file_id: file_id.into(),
        status: outcome.as_str(),
        decision_deadline: (outcome == beebeeb_core::sync::conflict::ConflictOutcome::NeedsUser)
            .then(|| policy.deadline(detected_at))
            .flatten(),
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SnapshotError {
    #[error("the server answer was not explicitly complete")]
    Incomplete,
    #[error(transparent)]
    Invalid(#[from] SyncEngineError),
}

#[derive(Debug, thiserror::Error)]
pub enum SyncLoopError {
    #[error(transparent)]
    Client(#[from] ClientError),
    #[error(transparent)]
    Engine(#[from] SyncEngineError),
    #[error(transparent)]
    Crypto(#[from] beebeeb_core::CoreError),
    #[error("the sync answer contained invalid data")]
    InvalidAnswer,
    #[error("sync catch-up exceeded its page limit")]
    TooManyPages,
    #[error("the sync stream did not yield within its deadline")]
    StreamTimeout,
}

/// The transport answer alone cannot create an authoritative snapshot. The
/// caller must also supply nodes whose names and metadata were opened by core.
pub fn complete_snapshot_from_answer(
    answer: &Snapshot,
    authenticated_nodes: Vec<TreeNode>,
) -> Result<CompleteSnapshot, SnapshotError> {
    if answer.complete != Some(true) {
        return Err(SnapshotError::Incomplete);
    }
    CompleteSnapshot::new(authenticated_nodes, SyncPosition::new(answer.seq_id, answer.user_seq)).map_err(Into::into)
}

impl Client {
    /// Pull every currently available operation after the durable cursor.
    /// Reordered answers are sorted by the account sequence; repeats are
    /// harmless because the engine rejects already-applied positions.
    pub async fn catch_up_sync(
        &self,
        session: &Session,
        engine: &mut SyncEngine,
        limit: u16,
    ) -> Result<(), SyncLoopError> {
        if limit == 0 {
            return Err(SyncLoopError::InvalidAnswer);
        }
        let mut since = engine.position().seq_id;
        for _ in 0..MAX_CATCH_UP_PAGES {
            let answer: api::Ops = self.execute(&api::ops(since, limit), &()).await?;
            let next_since = answer.next_since;
            let mut operations = answer
                .ops
                .into_iter()
                .map(|operation| open_operation(session, operation))
                .collect::<Result<Vec<_>, _>>()?;
            operations.sort_by_key(|operation| (operation.user_seq.unwrap_or(i64::MAX), operation.seq_id));
            for mut operation in operations {
                resolve_operation_collision(session, engine, &mut operation)?;
                engine.apply_remote_op(RemoteOp::from_authenticated_session(operation))?;
            }
            let after = engine.position();
            match next_since {
                None => {
                    self.events().emit(EngineEvent::SyncCaughtUp {
                        seq_id: after.seq_id,
                        user_seq: after.user_seq,
                    });
                    return Ok(());
                }
                Some(next) => {
                    let advanced = next.max(after.seq_id);
                    if advanced <= since {
                        return Err(SyncLoopError::InvalidAnswer);
                    }
                    since = advanced;
                }
            }
        }
        Err(SyncLoopError::TooManyPages)
    }

    /// Fetch a snapshot and apply deletion authority only when the server
    /// explicitly marks it complete at known cursors.
    pub async fn refresh_sync_snapshot(&self, session: &Session, engine: &mut SyncEngine) -> Result<(), SyncLoopError> {
        let answer = self.execute(&beebeeb_api::proposed::complete_snapshot(), &()).await?;
        let nodes = open_snapshot_nodes(session, engine, &answer)?;
        if answer.complete == Some(true) {
            engine.apply_complete_snapshot(CompleteSnapshot::new(
                nodes,
                SyncPosition::new(answer.seq_id, answer.user_seq),
            )?)?;
        } else {
            engine.observe_incomplete_snapshot(IncompleteSnapshot::new(nodes))?;
        }
        Ok(())
    }

    /// Rebase from one authoritative snapshot after a per-account sequence
    /// gap, then consume every operation that followed that snapshot.
    pub async fn recover_sync_gap(
        &self,
        session: &Session,
        engine: &mut SyncEngine,
        catch_up_limit: u16,
    ) -> Result<(), SyncLoopError> {
        self.refresh_sync_snapshot(session, engine).await?;
        self.catch_up_sync(session, engine, catch_up_limit).await
    }

    /// Consume one bounded foreground SSE batch. A clean end triggers cursor
    /// catch-up so dropped events cannot leave a permanent gap.
    pub async fn foreground_sync_once(
        &self,
        session: &Session,
        engine: &mut SyncEngine,
        catch_up_limit: u16,
    ) -> Result<bool, SyncLoopError> {
        self.foreground_sync_with_timeout(session, engine, catch_up_limit, Duration::from_secs(35))
            .await
    }

    pub async fn foreground_sync_with_timeout(
        &self,
        session: &Session,
        engine: &mut SyncEngine,
        catch_up_limit: u16,
        timeout: Duration,
    ) -> Result<bool, SyncLoopError> {
        let token: api::StreamToken = self.execute(&api::stream_token(), &()).await?;
        let batch = tokio::time::timeout(
            timeout,
            self.execute_stream(
                &api::stream(&token.token),
                StreamLimits {
                    max_event_bytes: DEFAULT_EVENT_BYTES,
                    max_events: 1,
                    max_stream_bytes: DEFAULT_EVENT_BYTES + 4096,
                },
            ),
        )
        .await
        .map_err(|_| SyncLoopError::StreamTimeout)??;
        for event in batch.events {
            let value: Value = serde_json::from_slice(&event).map_err(|_| SyncLoopError::InvalidAnswer)?;
            if value.get("op_type").is_none() || value.get("payload").is_none() {
                continue;
            }
            let wire: api::Op = serde_json::from_value(value).map_err(|_| SyncLoopError::InvalidAnswer)?;
            let mut operation = open_operation(session, wire)?;
            resolve_operation_collision(session, engine, &mut operation)?;
            engine.apply_remote_op(RemoteOp::from_authenticated_session(operation))?;
        }
        if batch.ended {
            self.catch_up_sync(session, engine, catch_up_limit).await?;
        }
        Ok(batch.ended)
    }
}

fn open_operation(session: &Session, operation: api::Op) -> Result<SyncOp, SyncLoopError> {
    let seq_id = operation.seq_id.ok_or(SyncLoopError::InvalidAnswer)?;
    let client_op_id = operation
        .client_op_id
        .map(|value| Uuid::parse_str(&value).map_err(|_| SyncLoopError::InvalidAnswer))
        .transpose()?;
    let created_at = operation
        .created_at
        .as_deref()
        .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
        .map(|value| value.with_timezone(&Utc))
        .unwrap_or_else(Utc::now);
    let mut payload = operation.payload;
    open_payload_name(session, &operation.op_type, &mut payload);
    Ok(SyncOp {
        seq_id,
        user_seq: operation.user_seq,
        op_type: operation.op_type,
        client_op_id,
        payload,
        device_id: operation.device_id,
        created_at,
    })
}

/// The plaintext name fields of a remote op come from core's decryption and
/// nothing else (zero-knowledge: the server never chooses a name the person
/// sees). Whatever `name` / `new_name` or undecryptable marker the server put
/// in the payload is dropped first; then each sealed name that opens to a
/// name the portable path rule accepts fills its plaintext field, and every
/// other one is marked undecryptable, shown as such, without stopping the
/// sync. A create whose name is not sealed at all is marked too. Local ops
/// never come through here and keep their own plaintext.
fn open_payload_name(session: &Session, op_type: &str, payload: &mut Value) {
    let Some(object) = payload.as_object_mut() else {
        return;
    };
    for field in ["name", "new_name", "name_undecryptable", "new_name_undecryptable"] {
        object.remove(field);
    }
    let id = object.get("id").and_then(Value::as_str).map(str::to_owned);
    for (encrypted_field, plain_field, marker) in [
        ("name_encrypted", "name", "name_undecryptable"),
        ("new_name_encrypted", "new_name", "new_name_undecryptable"),
    ] {
        let Some(encrypted) = object.get(encrypted_field).and_then(Value::as_str).map(str::to_owned) else {
            if plain_field == "name" && matches!(op_type, "file_create" | "folder_create") {
                object.insert(marker.into(), Value::Bool(true));
            }
            continue;
        };
        match id.as_deref().map(|id| session.open_name(id, &encrypted)) {
            Some(Ok(metadata)) if check_component(&metadata.name, Rules::Portable).is_ok() => {
                object.insert(plain_field.into(), Value::String(metadata.name));
            }
            _ => {
                object.insert(marker.into(), Value::Bool(true));
            }
        }
    }
}

/// The device in a pull-side conflict name. The device whose write came
/// second is not known by name here (a sync op carries at most an opaque
/// client id, and an op written through the REST routes none), so the name
/// takes core's generic word: `report (conflict, device).pdf`.
const UNKNOWN_WRITER: &str = "";

fn item_kind(is_folder: bool) -> ItemKind {
    if is_folder { ItemKind::Folder } else { ItemKind::File }
}

/// An optional id field: absent or `null` is the drive root.
fn parent_field(payload: &Value, key: &str) -> Result<Option<Uuid>, SyncLoopError> {
    match payload.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value
            .as_str()
            .and_then(|value| Uuid::parse_str(value).ok())
            .map(Some)
            .ok_or(SyncLoopError::InvalidAnswer),
    }
}

/// A remote create, rename, move or restore can give an item a name its
/// folder already holds: names are sealed, so the server keeps both. The drive
/// keeps both too and asks nothing (1022 G5): the item that arrives second,
/// this op's, takes core's `drive_conflict_name` from its own incoming name,
/// never from the existing item's; two names clash when core's normal forms
/// are equal (`TakenNames`). The folder is the one the item lands in: a
/// create's `parent_id`, a move's `new_parent_id`, and for a rename or a
/// restore (whose ops carry no parent) the item's current folder in the
/// engine. Only live siblings hold a name, so a restore is checked too: an
/// item may have taken the name while this one was in the Trash. A move or a
/// restore carries no name, so its opened name is added as `new_name` (the
/// engine applies it): moving out of a clash gives the item its own name back.
fn resolve_operation_collision(
    session: &Session,
    engine: &SyncEngine,
    operation: &mut SyncOp,
) -> Result<(), SyncLoopError> {
    let id = operation
        .payload
        .get("id")
        .and_then(Value::as_str)
        .and_then(|value| Uuid::parse_str(value).ok());
    let (field, name, parent, kind) = match operation.op_type.as_str() {
        "file_create" | "folder_create" => {
            let Some(name) = operation.payload.get("name").and_then(Value::as_str) else {
                return Ok(());
            };
            (
                "name",
                name.to_owned(),
                parent_field(&operation.payload, "parent_id")?,
                item_kind(operation.op_type == "folder_create"),
            )
        }
        "file_rename" | "folder_rename" => {
            let Some(name) = operation.payload.get("new_name").and_then(Value::as_str) else {
                return Ok(());
            };
            // An item the engine does not have is not renamed by the op either.
            let Some(node) = id.map(|id| engine.lookup_node(id)).transpose()?.flatten() else {
                return Ok(());
            };
            ("new_name", name.to_owned(), node.parent_id, item_kind(node.is_folder))
        }
        "file_move" | "folder_move" | "file_restore" => {
            // The server's move and restore carry no name: any name in the
            // payload is not this item's to take.
            if let Some(object) = operation.payload.as_object_mut() {
                object.remove("new_name");
                object.remove("new_name_undecryptable");
            }
            let Some(node) = id.map(|id| engine.lookup_node(id)).transpose()?.flatten() else {
                return Ok(());
            };
            // A name this device cannot open, or one the portable path rule
            // refuses, takes no name: it clashes with nothing.
            let Ok(metadata) = session.open_name(&node.id.to_string(), &node.name_encrypted) else {
                return Ok(());
            };
            if check_component(&metadata.name, Rules::Portable).is_err() {
                return Ok(());
            }
            let parent = if operation.op_type == "file_restore" {
                node.parent_id
            } else {
                parent_field(&operation.payload, "new_parent_id")?
            };
            ("new_name", metadata.name, parent, item_kind(node.is_folder))
        }
        _ => return Ok(()),
    };
    let mut taken = TakenNames::new();
    for child in engine.lookup_children(parent)? {
        if Some(child.id) != id && !child.name_undecryptable {
            taken.insert(&child.name);
        }
    }
    let name = if taken.contains(&name) {
        drive_conflict_name(&name, kind, UNKNOWN_WRITER, &taken)
    } else {
        name
    };
    operation
        .payload
        .as_object_mut()
        .ok_or(SyncLoopError::InvalidAnswer)?
        .insert(field.into(), Value::String(name));
    Ok(())
}

fn open_snapshot_nodes(
    session: &Session,
    engine: &SyncEngine,
    answer: &Snapshot,
) -> Result<Vec<TreeNode>, SyncLoopError> {
    let mut nodes = answer
        .nodes
        .iter()
        .map(|wire| open_snapshot_node(session, wire))
        .collect::<Result<Vec<_>, _>>()?;
    name_snapshot_clashes(engine, &mut nodes)?;
    Ok(nodes)
}

/// Siblings whose names clash keep both (1022 G5), named the same whatever
/// order the server lists them in: the sibling that already holds the name
/// in the engine keeps it, otherwise the smallest id; every other one takes
/// core's `drive_conflict_name` of its own name, in id order, clear of every
/// sibling's real name. Undecryptable names take no name and clash with
/// nothing.
fn name_snapshot_clashes(engine: &SyncEngine, nodes: &mut [TreeNode]) -> Result<(), SyncLoopError> {
    let mut folders: BTreeMap<Option<Uuid>, Vec<usize>> = BTreeMap::new();
    for (index, node) in nodes.iter().enumerate() {
        if !node.name_undecryptable {
            folders.entry(node.parent_id).or_default().push(index);
        }
    }
    for siblings in folders.values() {
        let mut taken = TakenNames::new();
        let mut clash = false;
        for &index in siblings {
            clash |= taken.contains(&nodes[index].name);
            taken.insert(&nodes[index].name);
        }
        if !clash {
            continue;
        }
        let mut order = Vec::with_capacity(siblings.len());
        for &index in siblings {
            let node = &nodes[index];
            let holds = engine.lookup_node(node.id)?.is_some_and(|known| {
                known.parent_id == node.parent_id && !known.name_undecryptable && known.name == node.name
            });
            order.push((!holds, node.id, index));
        }
        order.sort_unstable();
        let mut kept = TakenNames::new();
        for (_, _, index) in order {
            if kept.contains(&nodes[index].name) {
                let renamed = drive_conflict_name(
                    &nodes[index].name,
                    item_kind(nodes[index].is_folder),
                    UNKNOWN_WRITER,
                    &taken,
                );
                taken.insert(&renamed);
                kept.insert(&renamed);
                nodes[index].name = renamed;
            } else {
                kept.insert(&nodes[index].name);
            }
        }
    }
    Ok(())
}

fn open_snapshot_node(session: &Session, wire: &api::Node) -> Result<TreeNode, SyncLoopError> {
    let id = Uuid::parse_str(&wire.id).map_err(|_| SyncLoopError::InvalidAnswer)?;
    let parent_id = wire
        .parent_id
        .as_deref()
        .map(Uuid::parse_str)
        .transpose()
        .map_err(|_| SyncLoopError::InvalidAnswer)?;
    let encrypted = field_string(&wire.fields, "name_encrypted").ok_or(SyncLoopError::InvalidAnswer)?;
    // A name that does not open, or that the portable path rule refuses, is
    // shown as undecryptable; it never stops the snapshot.
    let (name, mime_type, name_undecryptable) = match session.open_name(&wire.id, &encrypted) {
        Ok(metadata) if check_component(&metadata.name, Rules::Portable).is_ok() => {
            (metadata.name, metadata.mime_type, false)
        }
        _ => (String::new(), None, true),
    };
    let size_bytes = wire.fields.get("size_bytes").and_then(Value::as_i64).unwrap_or(0);
    let version_number = wire
        .fields
        .get("version_number")
        .and_then(Value::as_i64)
        .and_then(|value| i32::try_from(value).ok())
        .unwrap_or(1);
    Ok(TreeNode {
        id,
        name,
        name_undecryptable,
        name_encrypted: encrypted,
        parent_id,
        is_folder: wire.fields.get("is_folder").and_then(Value::as_bool).unwrap_or(false),
        size_bytes,
        mime_type,
        content_hash: field_string(&wire.fields, "content_hash"),
        version_number,
        has_thumbnail: wire
            .fields
            .get("has_thumbnail")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        storage_pool_id: field_string(&wire.fields, "storage_pool_id")
            .map(|value| Uuid::parse_str(&value).map_err(|_| SyncLoopError::InvalidAnswer))
            .transpose()?,
        is_trashed: wire.fields.get("is_trashed").and_then(Value::as_bool).unwrap_or(false),
        is_starred: wire.fields.get("is_starred").and_then(Value::as_bool).unwrap_or(false),
        updated_at: field_string(&wire.fields, "updated_at")
            .as_deref()
            .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
            .map(|value| value.with_timezone(&Utc))
            .unwrap_or_else(Utc::now),
    })
}

fn field_string(fields: &beebeeb_api::routes::ExtraFields, key: &str) -> Option<String> {
    fields.get(key).and_then(Value::as_str).map(str::to_owned)
}
