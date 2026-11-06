use std::{
    collections::{BTreeMap, BTreeSet},
    time::Duration,
};

use beebeeb_api::routes::sync::{self as api, Snapshot};
use beebeeb_core::sync::{CompleteSnapshot, SyncEngineError, SyncOp, SyncPosition, TreeNode};
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
                resolve_operation_collision(engine, &mut operation)?;
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
        let nodes = open_snapshot_nodes(session, &answer)?;
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
            resolve_operation_collision(engine, &mut operation)?;
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
    open_payload_name(session, &mut payload)?;
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

fn open_payload_name(session: &Session, payload: &mut Value) -> Result<(), SyncLoopError> {
    let Some(id) = payload.get("id").and_then(Value::as_str).map(str::to_owned) else {
        return Ok(());
    };
    for (encrypted_field, plain_field) in [("name_encrypted", "name"), ("new_name_encrypted", "new_name")] {
        let Some(encrypted) = payload.get(encrypted_field).and_then(Value::as_str).map(str::to_owned) else {
            continue;
        };
        let object = payload.as_object_mut().ok_or(SyncLoopError::InvalidAnswer)?;
        match session.open_name(&id, &encrypted) {
            Ok(metadata) => {
                object.insert(plain_field.into(), Value::String(metadata.name));
            }
            Err(_) => {
                let marker = if plain_field == "new_name" {
                    "new_name_undecryptable"
                } else {
                    "name_undecryptable"
                };
                object.insert(marker.into(), Value::Bool(true));
            }
        }
    }
    Ok(())
}

fn resolve_operation_collision(engine: &SyncEngine, operation: &mut SyncOp) -> Result<(), SyncLoopError> {
    let field = if operation.payload.get("new_name").is_some() {
        "new_name"
    } else if operation.payload.get("name").is_some() {
        "name"
    } else {
        return Ok(());
    };
    let Some(name) = operation.payload.get(field).and_then(Value::as_str) else {
        return Ok(());
    };
    let parent = operation
        .payload
        .get("new_parent_id")
        .or_else(|| operation.payload.get("parent_id"))
        .and_then(Value::as_str)
        .map(Uuid::parse_str)
        .transpose()
        .map_err(|_| SyncLoopError::InvalidAnswer)?;
    let current_id = operation
        .payload
        .get("id")
        .and_then(Value::as_str)
        .and_then(|value| Uuid::parse_str(value).ok());
    let mut used = BTreeSet::new();
    for child in engine.lookup_children(parent)? {
        if current_id != Some(child.id) {
            used.insert(child.name);
        }
    }
    let deduplicated =
        beebeeb_core::path_safety::deduplicate_component(name, &mut used).map_err(|_| SyncLoopError::InvalidAnswer)?;
    operation
        .payload
        .as_object_mut()
        .ok_or(SyncLoopError::InvalidAnswer)?
        .insert(field.into(), Value::String(deduplicated));
    Ok(())
}

fn open_snapshot_nodes(session: &Session, answer: &Snapshot) -> Result<Vec<TreeNode>, SyncLoopError> {
    let mut used: BTreeMap<Option<Uuid>, BTreeSet<String>> = BTreeMap::new();
    answer
        .nodes
        .iter()
        .map(|wire| {
            let id = Uuid::parse_str(&wire.id).map_err(|_| SyncLoopError::InvalidAnswer)?;
            let parent_id = wire
                .parent_id
                .as_deref()
                .map(Uuid::parse_str)
                .transpose()
                .map_err(|_| SyncLoopError::InvalidAnswer)?;
            let encrypted = field_string(&wire.fields, "name_encrypted").ok_or(SyncLoopError::InvalidAnswer)?;
            let (name, mime_type, name_undecryptable) = match session.open_name(&wire.id, &encrypted) {
                Ok(metadata) => (
                    beebeeb_core::path_safety::deduplicate_component(
                        &metadata.name,
                        used.entry(parent_id).or_default(),
                    )
                    .map_err(|_| SyncLoopError::InvalidAnswer)?,
                    metadata.mime_type,
                    false,
                ),
                Err(_) => (String::new(), None, true),
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
        })
        .collect()
}

fn field_string(fields: &beebeeb_api::routes::ExtraFields, key: &str) -> Option<String> {
    fields.get(key).and_then(Value::as_str).map(str::to_owned)
}
