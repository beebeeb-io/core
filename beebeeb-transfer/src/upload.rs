//! Foreground upload driver for API-route and direct upload sessions.
//!
//! Session initialization stays with the caller because its encrypted metadata
//! and parent fields are product-specific. Once initialized, this driver owns
//! the transport loop: v2 chunk encryption, heartbeat, bounded retries,
//! direct-upload scheduling, completion and abandon.

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::time::Duration;

use beebeeb_core::chunk_stream::{ChunkEncryptor, ChunkFormat, ExpectedChunkFormat, SessionResume, VersionCommitment};
use beebeeb_core::direct_transfer::{
    self as dt, API_CALL_TIMEOUT, Call, Discovery, GiveUpReason, GrantVersion, Outcome, PipelineAction, PipelineEvent,
    PipelinePlan, UploadChunkPolicy, UploadFailure, UploadGrant, classify, put_stored, storage_put_total,
    upload_commit_path, upload_grant_path,
};
use beebeeb_core::retry::{RetryOutcome, RetryPolicy, parse_retry_after};
use bytes::Bytes;
use futures_util::future::{Either, select};
use serde::Deserialize;

use crate::io::{ApiCall, ApiMethod, DirectIo, SignedUrl};

/// The transport selected at session initialization. It never changes during
/// that session.
#[derive(Debug, Clone)]
pub enum UploadTransport {
    Api,
    Direct {
        discovery: Discovery,
        grant_version: GrantVersion,
    },
}

/// Durable fields from an initialized upload session.
#[derive(Debug, Clone)]
pub struct UploadSession {
    pub api_base: String,
    pub file_id: String,
    pub upload_session_id: String,
    pub chunk_size_bytes: u64,
    pub chunk_count: u32,
    pub heartbeat_interval: Duration,
    pub lease: Duration,
    pub transport: UploadTransport,
    /// Set only when this is an unfinished session loaded from disk.
    pub resumed_format: Option<ChunkFormat>,
    pub is_resume: bool,
}

/// Successful upload metadata that must be sealed into the file's metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UploadCommitment {
    pub format: ExpectedChunkFormat,
    pub version: VersionCommitment,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UploadStats {
    pub chunks: u32,
    pub ciphertext_bytes: u64,
    pub commitment: UploadCommitment,
}

/// A terminal state is explicit and durable at the caller boundary. The
/// caller may display it, but must not silently start an unbounded retry loop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UploadOutcome {
    Done(UploadStats),
    /// The old session was successfully abandoned and a fresh initialization
    /// must start from chunk zero.
    RestartRequired,
    Failed(UploadFailureState),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UploadFailureState {
    Unauthorized,
    Forbidden,
    SessionExpired,
    UpgradeRequired,
    RetryLimit,
    Protocol,
    Producer,
    AbandonFailed,
}

#[derive(Debug, thiserror::Error)]
pub enum UploadError {
    #[error("upload encryption failed")]
    Encryption,
    #[error("upload session geometry does not match the encryptor")]
    Geometry,
}

/// Drive an already-initialized upload session to completion or a final state.
pub async fn upload<I: DirectIo>(
    io: &I,
    session: &UploadSession,
    mut encryptor: ChunkEncryptor,
    previous_version_counter: Option<u64>,
    jitter_seed: u64,
) -> Result<UploadOutcome, UploadError> {
    let plan = encryptor.chunk_plan();
    if encryptor.format() != ChunkFormat::V2
        || plan.chunk_size_bytes != session.chunk_size_bytes
        || plan.chunk_count != u64::from(session.chunk_count)
    {
        return Err(UploadError::Geometry);
    }
    if session.is_resume && encryptor.resume_policy(session.resumed_format) == SessionResume::RestartWithFreshSession {
        return Ok(if abandon(io, &session.file_id).await {
            UploadOutcome::RestartRequired
        } else {
            UploadOutcome::Failed(UploadFailureState::AbandonFailed)
        });
    }

    let mut heartbeat = Heartbeat::new(io.mono_ms(), session);
    let transfer = match &session.transport {
        UploadTransport::Api => upload_api(io, session, &mut encryptor, &mut heartbeat).await,
        UploadTransport::Direct {
            discovery,
            grant_version,
        } => {
            upload_direct(
                io,
                session,
                discovery,
                *grant_version,
                &mut encryptor,
                &mut heartbeat,
                jitter_seed,
            )
            .await
        }
    };

    let (chunks, ciphertext_bytes) = match transfer {
        Ok(value) => value,
        Err(reason) => {
            let final_reason = if abandon(io, &session.file_id).await {
                reason
            } else {
                UploadFailureState::AbandonFailed
            };
            return Ok(UploadOutcome::Failed(final_reason));
        }
    };
    let version = encryptor
        .version_commitment_after(previous_version_counter)
        .map_err(|_| UploadError::Encryption)?;
    encryptor.finish().map_err(|_| UploadError::Encryption)?;
    if !heartbeat.beat_if_due(io, session).await {
        let _ = abandon(io, &session.file_id).await;
        return Ok(UploadOutcome::Failed(heartbeat.failure()));
    }
    let completion_call = io.api(ApiCall {
        method: ApiMethod::Post,
        path: format!("/api/v1/uploads/{}/complete", session.upload_session_id),
        body: None,
        capabilities: Some(crate::V2_WRITE_CAPABILITIES),
        timeout: API_CALL_TIMEOUT,
        max_body: dt::wire::MAX_UPLOAD_BODY_BYTES,
    });
    let completion = match await_with_heartbeat(io, session, &mut heartbeat, completion_call).await {
        Ok(reply) => reply,
        Err(reason) => return Ok(UploadOutcome::Failed(reason)),
    };
    if !(200..300).contains(&completion.status) || !completion_matches(&completion.body, &session.file_id) {
        // Completion may have committed even when its answer was lost. Never
        // abandon here: that could delete the newly valid version.
        return Ok(UploadOutcome::Failed(status_failure(completion.status)));
    }
    Ok(UploadOutcome::Done(UploadStats {
        chunks,
        ciphertext_bytes,
        commitment: UploadCommitment {
            format: ExpectedChunkFormat::recorded_for(ChunkFormat::V2),
            version,
        },
    }))
}

async fn upload_api<I: DirectIo>(
    io: &I,
    session: &UploadSession,
    encryptor: &mut ChunkEncryptor,
    heartbeat: &mut Heartbeat,
) -> Result<(u32, u64), UploadFailureState> {
    let mut chunks = 0u32;
    let mut ciphertext_bytes = 0u64;
    while let Some(chunk) = encryptor.next_chunk().map_err(|_| UploadFailureState::Producer)? {
        let path = format!("/api/v1/uploads/{}/chunks/{}", session.upload_session_id, chunk.index);
        let mut attempts = 0u32;
        loop {
            if !heartbeat.beat_if_due(io, session).await {
                return Err(heartbeat.failure());
            }
            attempts = attempts.saturating_add(1);
            let call = io.api(ApiCall {
                method: ApiMethod::Put,
                path: path.clone(),
                body: Some(chunk.data.clone()),
                capabilities: Some(crate::V2_WRITE_CAPABILITIES),
                timeout: storage_put_total(chunk.data.len() as u64),
                max_body: dt::classify::MAX_ERROR_BODY_BYTES,
            });
            let reply = await_with_heartbeat(io, session, heartbeat, call).await?;
            if (200..300).contains(&reply.status) {
                break;
            }
            if reply.status == 426 {
                return Err(UploadFailureState::UpgradeRequired);
            }
            let outcome = if reply.status == 0 {
                RetryOutcome::Network
            } else {
                RetryOutcome::Status(reply.status)
            };
            let wait = RetryPolicy::DEFAULT.decide(
                attempts,
                outcome,
                reply.retry_after.as_deref().and_then(parse_retry_after),
            );
            let Some(wait) = wait else {
                return Err(status_failure(reply.status));
            };
            io.sleep(Duration::from_millis(wait)).await;
        }
        chunks = chunks.saturating_add(1);
        ciphertext_bytes = ciphertext_bytes.saturating_add(chunk.data.len() as u64);
    }
    Ok((chunks, ciphertext_bytes))
}

#[allow(clippy::too_many_arguments)]
async fn upload_direct<I: DirectIo>(
    io: &I,
    session: &UploadSession,
    discovery: &Discovery,
    grant_version: GrantVersion,
    encryptor: &mut ChunkEncryptor,
    heartbeat: &mut Heartbeat,
    jitter_seed: u64,
) -> Result<(u32, u64), UploadFailureState> {
    let plan = encryptor.chunk_plan();
    let mut lens = Vec::with_capacity(session.chunk_count as usize);
    for index in 0..session.chunk_count {
        let plain = if index + 1 == session.chunk_count {
            plan.file_size_bytes
                .checked_sub(plan.chunk_size_bytes.saturating_mul(u64::from(index)))
                .ok_or(UploadFailureState::Producer)?
        } else {
            plan.chunk_size_bytes
        };
        lens.push(plain.checked_add(28).ok_or(UploadFailureState::Producer)?);
    }
    let mut pipeline = PipelinePlan::with_seed(
        session.chunk_size_bytes,
        lens,
        grant_version,
        UploadChunkPolicy::default(),
        jitter_seed,
    );
    let mut actions: VecDeque<PipelineAction> = pipeline.on(PipelineEvent::Tick, monotonic_u64(io)).into();
    let mut retained: HashMap<u32, Bytes> = HashMap::new();
    let mut direct_links: HashMap<u32, String> = HashMap::new();
    let mut chunks = 0u32;
    let mut ciphertext_bytes = 0u64;
    let mut idle_spins = 0u8;

    while let Some(action) = actions.pop_front() {
        if !heartbeat.beat_if_due(io, session).await {
            return Err(heartbeat.failure());
        }
        let event = match action {
            PipelineAction::Accept => match encryptor.next_chunk().map_err(|_| UploadFailureState::Producer)? {
                Some(chunk) => {
                    let digest = if grant_version == GrantVersion::V2 {
                        let hash = beebeeb_core::hash::sha256(&chunk.data);
                        let mut digest = [0u8; 16];
                        digest.copy_from_slice(&hash[..16]);
                        Some(digest)
                    } else {
                        None
                    };
                    let index = chunk.index;
                    let len = chunk.data.len() as u64;
                    retained.insert(index, Bytes::from(chunk.data));
                    PipelineEvent::ChunkProduced { index, len, digest }
                }
                None => PipelineEvent::ProducerFailed,
            },
            PipelineAction::Grant { index, digest: _ } => {
                let commits_outstanding = actions
                    .iter()
                    .any(|action| matches!(action, PipelineAction::Commit { .. }));
                let Some(body_bytes) = retained.get(&index) else {
                    return Err(UploadFailureState::Producer);
                };
                let body = serde_json::to_vec(&dt::UploadGrantRequest {
                    size: body_bytes.len() as u64,
                })
                .map_err(|_| UploadFailureState::Producer)?;
                let call = io.api(ApiCall {
                    method: ApiMethod::Post,
                    path: upload_grant_path(&session.upload_session_id, index),
                    body: Some(body),
                    capabilities: Some(crate::DIRECT_V2_WRITE_CAPABILITIES),
                    timeout: API_CALL_TIMEOUT,
                    max_body: dt::wire::MAX_UPLOAD_BODY_BYTES,
                });
                let reply = await_with_heartbeat(io, session, heartbeat, call).await?;
                let answer = dt::ApiAnswer::from_parts(
                    reply.status,
                    reply.content_type.as_deref(),
                    &reply.body,
                    reply.retry_after.as_deref(),
                );
                match classify(Call::UploadGrant, &answer) {
                    Outcome::Proceed => {
                        match UploadGrant::from_answer(&reply.body, index, discovery, &session.api_base) {
                            Ok(UploadGrant::Skipped) => PipelineEvent::GrantSkipped { index },
                            Ok(UploadGrant::Link(link)) => {
                                // Keep the validated link only until the immediately
                                // following Put action; it never enters an error.
                                direct_links.insert(index, link.url);
                                PipelineEvent::GrantOk { index }
                            }
                            Err(_) => PipelineEvent::GrantRefused {
                                index,
                                status: reply.status,
                                failure: UploadFailure::Grant(Outcome::ApiForThisFile),
                                commits_outstanding,
                            },
                        }
                    }
                    outcome => PipelineEvent::GrantRefused {
                        index,
                        status: reply.status,
                        failure: UploadFailure::Grant(outcome),
                        commits_outstanding,
                    },
                }
            }
            PipelineAction::Put { index } => {
                let Some(bytes) = retained.get(&index).cloned() else {
                    return Err(UploadFailureState::Producer);
                };
                let Some(url) = direct_links.remove(&index) else {
                    return Err(UploadFailureState::Producer);
                };
                let signed_url = SignedUrl::new(url);
                let headers = [("content-type", dt::UPLOAD_CONTENT_TYPE.to_owned())];
                let put = io.storage_put(
                    &signed_url,
                    bytes.clone(),
                    &headers,
                    storage_put_total(bytes.len() as u64),
                );
                let status = await_with_heartbeat(io, session, heartbeat, put).await?;
                if put_stored(status) {
                    PipelineEvent::PutDone { index }
                } else if status == 412 {
                    PipelineEvent::PutAlreadyThere { index }
                } else {
                    PipelineEvent::PutFailed {
                        index,
                        failure: UploadFailure::Put { status },
                    }
                }
            }
            PipelineAction::Commit { index } => {
                let Some(bytes) = retained.get(&index) else {
                    return Err(UploadFailureState::Producer);
                };
                let size = bytes.len() as u64;
                let body =
                    serde_json::to_vec(&dt::UploadCommitRequest { size }).map_err(|_| UploadFailureState::Producer)?;
                let call = io.api(ApiCall {
                    method: ApiMethod::Post,
                    path: upload_commit_path(&session.upload_session_id, index),
                    body: Some(body),
                    capabilities: Some(crate::V2_WRITE_CAPABILITIES),
                    timeout: API_CALL_TIMEOUT,
                    max_body: dt::wire::MAX_UPLOAD_BODY_BYTES,
                });
                let reply = await_with_heartbeat(io, session, heartbeat, call).await?;
                let answer = dt::ApiAnswer::from_parts(
                    reply.status,
                    reply.content_type.as_deref(),
                    &reply.body,
                    reply.retry_after.as_deref(),
                );
                match classify(Call::UploadCommit, &answer) {
                    Outcome::Proceed if dt::UploadCommitted::from_answer(&reply.body, index, size).is_ok() => {
                        retained.remove(&index);
                        chunks = chunks.saturating_add(1);
                        ciphertext_bytes = ciphertext_bytes.saturating_add(size);
                        PipelineEvent::CommitDone { index }
                    }
                    outcome => PipelineEvent::CommitFailed {
                        index,
                        status: reply.status,
                        failure: UploadFailure::Commit(if matches!(outcome, Outcome::Proceed) {
                            Outcome::ApiForThisFile
                        } else {
                            outcome
                        }),
                    },
                }
            }
            PipelineAction::Wait { until_ms, .. } => {
                let now = monotonic_u64(io);
                io.sleep(Duration::from_millis(until_ms.saturating_sub(now))).await;
                PipelineEvent::Tick
            }
            PipelineAction::AwaitAck { .. } => PipelineEvent::Ack,
            PipelineAction::ReleaseLane => PipelineEvent::Tick,
            PipelineAction::Cancel { index } => {
                retained.remove(&index);
                PipelineEvent::Tick
            }
            PipelineAction::GiveUp { reason } => return Err(give_up_failure(reason)),
            PipelineAction::Complete => return Ok((chunks, ciphertext_bytes)),
            PipelineAction::Idle => {
                idle_spins = idle_spins.saturating_add(1);
                if idle_spins > 2 {
                    return Err(UploadFailureState::RetryLimit);
                }
                PipelineEvent::Tick
            }
        };
        if !matches!(event, PipelineEvent::Tick) {
            idle_spins = 0;
        }
        actions.extend(pipeline.on(event, monotonic_u64(io)));
    }
    Err(UploadFailureState::RetryLimit)
}

async fn await_with_heartbeat<I, F, T>(
    io: &I,
    session: &UploadSession,
    heartbeat: &mut Heartbeat,
    operation: F,
) -> Result<T, UploadFailureState>
where
    I: DirectIo,
    F: Future<Output = T> + Send,
{
    let mut operation = Box::pin(operation);
    loop {
        let wait_ms = u64::try_from(heartbeat.next_ms.saturating_sub(io.mono_ms()).max(0)).unwrap_or(u64::MAX);
        let sleep = Box::pin(io.sleep(Duration::from_millis(wait_ms)));
        match select(operation, sleep).await {
            Either::Left((result, _)) => return Ok(result),
            Either::Right(((), pending)) => {
                operation = pending;
                if !heartbeat.beat_if_due(io, session).await {
                    return Err(heartbeat.failure());
                }
            }
        }
    }
}

struct Heartbeat {
    next_ms: i64,
    first_failure_ms: Option<i64>,
    consecutive_failures: u32,
    failure: UploadFailureState,
}

impl Heartbeat {
    fn new(now_ms: i64, session: &UploadSession) -> Self {
        Self {
            next_ms: now_ms.saturating_add(duration_ms(session.heartbeat_interval.max(Duration::from_secs(1)))),
            first_failure_ms: None,
            consecutive_failures: 0,
            failure: UploadFailureState::RetryLimit,
        }
    }

    async fn beat_if_due<I: DirectIo>(&mut self, io: &I, session: &UploadSession) -> bool {
        if io.mono_ms() < self.next_ms {
            return true;
        }
        let reply = io
            .api(ApiCall {
                method: ApiMethod::Post,
                path: format!("/api/v1/uploads/{}/heartbeat", session.upload_session_id),
                body: None,
                capabilities: Some(crate::V2_WRITE_CAPABILITIES),
                timeout: session.heartbeat_interval.max(Duration::from_secs(1)),
                max_body: dt::classify::MAX_ERROR_BODY_BYTES,
            })
            .await;
        let now = io.mono_ms();
        self.next_ms = now.saturating_add(duration_ms(session.heartbeat_interval.max(Duration::from_secs(1))));
        if (200..300).contains(&reply.status) {
            self.first_failure_ms = None;
            self.consecutive_failures = 0;
            return true;
        }
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        let first = *self.first_failure_ms.get_or_insert(now);
        self.failure = status_failure(reply.status);
        !matches!(reply.status, 401 | 403 | 404 | 426)
            && (self.consecutive_failures < 3
                || now.saturating_sub(first) < duration_ms(session.lease.max(Duration::from_secs(3))))
    }

    fn failure(&self) -> UploadFailureState {
        self.failure.clone()
    }
}

async fn abandon<I: DirectIo>(io: &I, file_id: &str) -> bool {
    let reply = io
        .api(ApiCall {
            method: ApiMethod::Post,
            path: format!("/api/v1/files/{file_id}/upload/abandon"),
            body: None,
            capabilities: None,
            timeout: Duration::from_secs(15),
            max_body: dt::classify::MAX_ERROR_BODY_BYTES,
        })
        .await;
    (200..300).contains(&reply.status) || reply.status == 404
}

#[derive(Deserialize)]
struct CompleteResponse {
    id: String,
}

fn completion_matches(body: &[u8], file_id: &str) -> bool {
    serde_json::from_slice::<CompleteResponse>(body)
        .map(|response| response.id == file_id)
        .unwrap_or(false)
}

fn status_failure(status: u16) -> UploadFailureState {
    match status {
        401 => UploadFailureState::Unauthorized,
        403 => UploadFailureState::Forbidden,
        404 => UploadFailureState::SessionExpired,
        426 => UploadFailureState::UpgradeRequired,
        _ => UploadFailureState::RetryLimit,
    }
}

fn give_up_failure(reason: GiveUpReason) -> UploadFailureState {
    match reason {
        GiveUpReason::Terminal { status, .. } => status_failure(status),
        GiveUpReason::SessionGone => UploadFailureState::SessionExpired,
        GiveUpReason::Producer => UploadFailureState::Producer,
        GiveUpReason::UseApi => UploadFailureState::RetryLimit,
    }
}

fn monotonic_u64<I: DirectIo>(io: &I) -> u64 {
    u64::try_from(io.mono_ms()).unwrap_or(0)
}

fn duration_ms(duration: Duration) -> i64 {
    i64::try_from(duration.as_millis()).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::io::ApiReply;
    use crate::test_support::scripted::{Reply, Request, ScriptedIo};
    use beebeeb_core::kdf::FileKey;

    const FILE_ID: &str = "11111111-2222-4333-8444-555555555555";

    fn session() -> UploadSession {
        UploadSession {
            api_base: "https://api.test".into(),
            file_id: FILE_ID.into(),
            upload_session_id: "22222222-3333-4444-8555-666666666666".into(),
            chunk_size_bytes: 8,
            chunk_count: 2,
            heartbeat_interval: Duration::from_secs(60),
            lease: Duration::from_secs(180),
            transport: UploadTransport::Api,
            resumed_format: None,
            is_resume: false,
        }
    }

    fn encryptor() -> ChunkEncryptor {
        let plain = b"twelve bytes".to_vec();
        ChunkEncryptor::from_reader_with_file_key(
            FileKey::from_bytes([4; 32]),
            FILE_ID,
            plain.len() as u64,
            8,
            std::io::Cursor::new(plain),
        )
        .unwrap()
    }

    fn reply(status: u16, body: serde_json::Value) -> Reply {
        Reply::Api(ApiReply {
            status,
            content_type: Some("application/json".into()),
            retry_after: None,
            body: body.to_string().into_bytes(),
        })
    }

    #[tokio::test]
    async fn a_v1_resume_is_abandoned_before_a_fresh_v2_session_is_requested() {
        let io = ScriptedIo::new(|request, _, _| match request {
            Request::Api(call) if call.path == format!("/api/v1/files/{FILE_ID}/upload/abandon") => {
                reply(200, serde_json::json!({"status":"deleted"}))
            }
            other => panic!("only abandon is allowed before restart: {other:?}"),
        });
        let mut session = session();
        session.is_resume = true;
        session.resumed_format = Some(ChunkFormat::V1Legacy);
        let outcome = upload(&io, &session, encryptor(), None, 1).await.unwrap();
        assert_eq!(outcome, UploadOutcome::RestartRequired);
        assert_eq!(io.requests().len(), 1);
    }

    #[tokio::test]
    async fn session_expiry_mid_upload_is_final_and_the_session_is_abandoned() {
        let io = ScriptedIo::new(|request, _, _| match request {
            Request::Api(call) if call.path.contains("/chunks/") => {
                reply(404, serde_json::json!({"error":"not_found"}))
            }
            Request::Api(call) if call.path.ends_with("/upload/abandon") => {
                reply(200, serde_json::json!({"status":"deleted"}))
            }
            other => panic!("unexpected request: {other:?}"),
        });
        let outcome = upload(&io, &session(), encryptor(), None, 1).await.unwrap();
        assert_eq!(outcome, UploadOutcome::Failed(UploadFailureState::SessionExpired));
    }

    #[tokio::test]
    async fn retry_after_is_bounded_and_the_item_eventually_becomes_failed() {
        let io = ScriptedIo::new(|request, _, _| match request {
            Request::Api(call) if call.path.contains("/chunks/") => Reply::Api(ApiReply {
                status: 429,
                content_type: Some("application/json".into()),
                retry_after: Some("1".into()),
                body: br#"{"error":"busy"}"#.to_vec(),
            }),
            Request::Api(call) if call.path.ends_with("/upload/abandon") => {
                reply(200, serde_json::json!({"status":"deleted"}))
            }
            Request::Api(call) if call.path.ends_with("/heartbeat") => reply(200, serde_json::json!({"ok":true})),
            other => panic!("unexpected request: {other:?}"),
        });
        let outcome = upload(&io, &session(), encryptor(), None, 1).await.unwrap();
        assert_eq!(outcome, UploadOutcome::Failed(UploadFailureState::RetryLimit));
        let chunk_calls = io.count(|request| matches!(request, Request::Api(call) if call.path.contains("/chunks/")));
        assert_eq!(chunk_calls, RetryPolicy::DEFAULT.max_attempts as usize);
    }

    #[tokio::test]
    async fn upgrade_required_is_typed_and_not_retried() {
        let io = ScriptedIo::new(|request, _, _| match request {
            Request::Api(call) if call.path.contains("/chunks/") => reply(
                426,
                serde_json::json!({"error":"client_upgrade_required","secret":"must-not-escape"}),
            ),
            Request::Api(call) if call.path.ends_with("/upload/abandon") => {
                reply(200, serde_json::json!({"status":"deleted"}))
            }
            other => panic!("unexpected request: {other:?}"),
        });
        let outcome = upload(&io, &session(), encryptor(), None, 1).await.unwrap();
        assert_eq!(outcome, UploadOutcome::Failed(UploadFailureState::UpgradeRequired));
        assert_eq!(
            io.count(|request| matches!(request, Request::Api(call) if call.path.contains("/chunks/"))),
            1
        );
        assert!(!format!("{outcome:?}").contains("must-not-escape"));
    }

    #[tokio::test]
    async fn api_upload_returns_the_v2_format_and_version_commitment() {
        let io = ScriptedIo::new(|request, _, _| match request {
            Request::Api(call) if call.path.contains("/chunks/") => reply(200, serde_json::json!({"ok":true})),
            Request::Api(call) if call.path.ends_with("/complete") => reply(200, serde_json::json!({"id":FILE_ID})),
            other => panic!("unexpected request: {other:?}"),
        });
        let outcome = upload(&io, &session(), encryptor(), None, 1).await.unwrap();
        let UploadOutcome::Done(stats) = outcome else {
            panic!("upload did not complete: {outcome:?}");
        };
        assert_eq!(stats.chunks, 2);
        assert_eq!(stats.commitment.format, ExpectedChunkFormat::V2);
        assert_eq!(stats.commitment.version.counter, 1);
        assert!(io.requests().iter().all(|record| match &record.request {
            Request::Api(call) if call.path.contains("/chunks/") || call.path.ends_with("/complete") => {
                call.capabilities == Some("file-write-v2, version-metadata-v1")
            }
            _ => true,
        }));
    }

    #[tokio::test]
    async fn a_long_chunk_call_is_heartbeated_while_it_is_in_flight() {
        let session = session();
        let chunk_prefix = format!("/api/v1/uploads/{}/chunks/", session.upload_session_id);
        let io = ScriptedIo::new(|request, _, _| match request {
            Request::Api(call) if call.path.contains("/chunks/") => reply(200, serde_json::json!({"ok":true})),
            Request::Api(call) if call.path.ends_with("/heartbeat") => reply(200, serde_json::json!({"ok":true})),
            Request::Api(call) if call.path.ends_with("/complete") => reply(200, serde_json::json!({"id":FILE_ID})),
            other => panic!("unexpected request: {other:?}"),
        })
        .with_api_delay_for(chunk_prefix, 65_000);
        let outcome = upload(&io, &session, encryptor(), None, 1).await.unwrap();
        assert!(matches!(outcome, UploadOutcome::Done(_)), "{outcome:?}");
        assert!(io.count(|request| matches!(request, Request::Api(call) if call.path.ends_with("/heartbeat"))) >= 1);
        assert!(io.requests().iter().all(|record| match &record.request {
            Request::Api(call)
                if call.path.contains("/chunks/")
                    || call.path.ends_with("/heartbeat")
                    || call.path.ends_with("/complete") =>
            {
                call.capabilities == Some("file-write-v2, version-metadata-v1")
            }
            _ => true,
        }));
    }

    #[tokio::test]
    async fn direct_upload_is_driven_by_the_pipeline_plan() {
        let io = ScriptedIo::new(|request, _, _| match request {
            Request::Api(call) if call.path.ends_with("/grant") => {
                let index = call
                    .path
                    .split("/chunks/")
                    .nth(1)
                    .and_then(|tail| tail.split('/').next())
                    .and_then(|value| value.parse::<u32>().ok())
                    .unwrap();
                reply(
                    200,
                    serde_json::json!({
                        "transport": dt::CAP_OBJECT_UPLOAD_V1,
                        "index": index,
                        "method": "PUT",
                        "url": format!("https://storage.test/bucket/chunk-{index}?signature=hidden"),
                        "headers": {"content-type": dt::UPLOAD_CONTENT_TYPE},
                        "expires_at": "2030-01-01T00:00:00Z"
                    }),
                )
            }
            Request::StoragePut { .. } => Reply::Put(200),
            Request::Api(call) if call.path.ends_with("/commit") => {
                let index = call
                    .path
                    .split("/chunks/")
                    .nth(1)
                    .and_then(|tail| tail.split('/').next())
                    .and_then(|value| value.parse::<u32>().ok())
                    .unwrap();
                let request: dt::UploadCommitRequest = serde_json::from_slice(call.body.as_deref().unwrap()).unwrap();
                reply(
                    200,
                    serde_json::json!({"index":index,"size":request.size,"skipped":false}),
                )
            }
            Request::Api(call) if call.path.ends_with("/complete") => reply(200, serde_json::json!({"id":FILE_ID})),
            other => panic!("unexpected request: {other:?}"),
        });
        let mut session = session();
        session.transport = UploadTransport::Direct {
            discovery: Discovery {
                upload: vec![dt::CAP_OBJECT_UPLOAD_V1.into()],
                storage_hosts: vec!["storage.test".into()],
                storage_buckets: vec![dt::StorageBucket {
                    host: "storage.test".into(),
                    bucket: "bucket".into(),
                }],
                ..Discovery::default()
            },
            grant_version: GrantVersion::V1,
        };
        let outcome = upload(&io, &session, encryptor(), None, 9).await.unwrap();
        assert!(matches!(outcome, UploadOutcome::Done(_)), "{outcome:?}");
        assert_eq!(io.count(|request| matches!(request, Request::StoragePut { .. })), 2);
        assert!(io.requests().iter().all(|record| match &record.request {
            Request::Api(call) if call.path.ends_with("/grant") => {
                call.capabilities == Some("object-upload-v1, file-write-v2, version-metadata-v1")
            }
            Request::Api(call) if call.path.ends_with("/commit") || call.path.ends_with("/complete") => {
                call.capabilities == Some("file-write-v2, version-metadata-v1")
            }
            _ => true,
        }));
    }
}
