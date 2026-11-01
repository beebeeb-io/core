//! Bounded direct-upload scheduling (task 2173, option A).

/// Commit concurrency is chosen from the file's stride, including for a short final chunk.
pub const UPLOAD_COMMIT_SLOTS_SMALL: u32 = 2;
pub const UPLOAD_COMMIT_SLOTS_LARGE: u32 = 1;
pub const UPLOAD_COMMIT_SLOTS_SMALL_BELOW: u64 = 16 * 1024 * 1024;
/// Grants and storage PUTs share one lane per file.
pub const UPLOAD_PUT_LANES: u32 = 1;
pub const UPLOAD_FILE_CONCURRENCY_DEFAULT: u32 = 4;
pub const UPLOAD_FILE_CONCURRENCY_MAX: u32 = 8;
/// Files finishing commits and complete after releasing their PUT lane.
pub const UPLOAD_TAIL_FILES_MAX: u32 = 4;
/// The process-wide upload API pacer, on both transports.
pub const UPLOAD_API_REQUESTS_PER_SECOND_MAX: u32 = 60;
pub const UPLOAD_API_BURST: u32 = 20;

pub fn commit_slots(chunk_size_bytes: u64) -> u32 {
    if chunk_size_bytes < UPLOAD_COMMIT_SLOTS_SMALL_BELOW {
        UPLOAD_COMMIT_SLOTS_SMALL
    } else {
        UPLOAD_COMMIT_SLOTS_LARGE
    }
}

use std::time::Duration;

use super::{Call, Outcome, Terminal, UploadChunkPolicy, UploadChunkState, UploadFailure, UploadNext};
use serde::{Deserialize, Serialize};

/// Fixed by the session init; never inferred from a storage response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantVersion {
    V1,
    V2,
}

/// The driver reports one completed operation at a time. Keep the status: Backoff alone loses
/// the distinction between grant 429 (ack wait) and 503 (gate), and commit 429 and 503.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PipelineEvent {
    ChunkProduced {
        index: u32,
        len: u64,
        digest: Option<[u8; 16]>,
    },
    GrantOk {
        index: u32,
    },
    GrantSkipped {
        index: u32,
    },
    PutDone {
        index: u32,
    },
    PutAlreadyThere {
        index: u32,
    },
    PutFailed {
        index: u32,
        failure: UploadFailure,
    },
    CommitDone {
        index: u32,
    },
    CommitFailed {
        index: u32,
        status: u16,
        failure: UploadFailure,
    },
    GrantRefused {
        index: u32,
        status: u16,
        failure: UploadFailure,
        commits_outstanding: bool,
    },
    SessionGone,
    ProducerFailed,
    Interrupt,
    Ack,
    Tick,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WaitKind {
    Gate,
    Chunk(u32),
    Hold(u32),
}

/// Producer errors preserve the session and do not arm a direct-transport hold.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum GiveUpReason {
    UseApi,
    Terminal { status: u16, error: Option<String> },
    SessionGone,
    Producer,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PipelineAction {
    Accept,
    Grant {
        index: u32,
        digest: Option<[u8; 16]>,
    },
    Put {
        index: u32,
    },
    Commit {
        index: u32,
    },
    ReleaseLane,
    AwaitAck {
        index: u32,
    },
    Wait {
        until_ms: u64,
        #[serde(rename = "wait_kind")]
        kind: WaitKind,
    },
    Cancel {
        index: u32,
    },
    GiveUp {
        reason: GiveUpReason,
    },
    Complete,
    Idle,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stage {
    Unproduced,
    Queued,
    Granting,
    Putting,
    Staged,
    Committing,
    WaitGrant { until: u64 },
    WaitCommit { until: u64 },
    AwaitAck { since: u64, after: Duration },
    Stored,
    Stopped,
}

#[derive(Debug)]
struct Chunk {
    len: u64,
    digest: Option<[u8; 16]>,
    stage: Stage,
    retry: UploadChunkState,
    regrant: bool,
    queue_order: u64,
    ack_retry: bool,
    ack_waited: u64,
}

/// Pure scheduler of one file. It owns metadata, never ciphertext, HTTP calls or a clock.
/// The caller retains bytes until Stored, and reads exactly once per Accept action.
#[derive(Debug)]
pub struct PipelinePlan {
    chunks: Vec<Chunk>,
    version: GrantVersion,
    policy: UploadChunkPolicy,
    slots: usize,
    next_input: usize,
    accept_pending: bool,
    queue_order: u64,
    gate_until: u64,
    released: bool,
    interrupted: bool,
    finished: bool,
    invalid: bool,
    last_now: u64,
}

impl PipelinePlan {
    /// Deterministic seed-0 constructor, useful for parity tests. Drivers should use with_seed
    /// with fresh caller-supplied entropy per file, so independent uploads do not synchronize.
    pub fn new(chunk_size_bytes: u64, chunk_lens: Vec<u64>, version: GrantVersion, policy: UploadChunkPolicy) -> Self {
        Self::with_seed(chunk_size_bytes, chunk_lens, version, policy, 0)
    }

    pub fn with_seed(
        chunk_size_bytes: u64,
        chunk_lens: Vec<u64>,
        version: GrantVersion,
        policy: UploadChunkPolicy,
        seed: u64,
    ) -> Self {
        let invalid = chunk_size_bytes == 0
            || chunk_lens.is_empty()
            || chunk_lens.len() > u32::MAX as usize
            || chunk_lens.contains(&0);
        let chunks = chunk_lens
            .into_iter()
            .enumerate()
            .map(|(i, len)| Chunk {
                len,
                digest: None,
                stage: Stage::Unproduced,
                retry: UploadChunkState::with_seed(policy, seed.wrapping_add(i as u64)),
                regrant: false,
                queue_order: 0,
                ack_retry: false,
                ack_waited: 0,
            })
            .collect();
        Self {
            chunks,
            version,
            policy,
            slots: commit_slots(chunk_size_bytes) as usize,
            next_input: 0,
            accept_pending: false,
            queue_order: 0,
            gate_until: 0,
            released: false,
            interrupted: false,
            finished: false,
            invalid,
            last_now: 0,
        }
    }

    pub fn retained(&self) -> usize {
        self.chunks
            .iter()
            .filter(|c| !matches!(c.stage, Stage::Unproduced | Stage::Stored | Stage::Stopped))
            .count()
    }

    /// True after Complete, GiveUp, or the interrupt's already-started commits have drained.
    pub fn is_done(&self) -> bool {
        self.finished
    }

    /// Events must be driven from one sequence. Repeated Tick/Ack events do not create additional
    /// admission permits or duplicate requests. A backwards injected clock cannot shorten a wait.
    pub fn on(&mut self, event: PipelineEvent, now_ms: u64) -> Vec<PipelineAction> {
        if self.finished {
            return vec![PipelineAction::Idle];
        }
        let now = now_ms.max(self.last_now);
        self.last_now = now;
        let mut out = Vec::new();
        if self.invalid {
            self.give_up(GiveUpReason::Producer, &mut out);
            return out;
        }
        match event {
            PipelineEvent::SessionGone => self.give_up(GiveUpReason::SessionGone, &mut out),
            PipelineEvent::ProducerFailed => self.give_up(GiveUpReason::Producer, &mut out),
            PipelineEvent::Interrupt => {
                self.interrupted = true;
                self.accept_pending = false;
                for (i, c) in self.chunks.iter_mut().enumerate() {
                    if c.stage == Stage::Putting {
                        out.push(PipelineAction::Cancel { index: i as u32 });
                    }
                    if !matches!(c.stage, Stage::Stored | Stage::Staged | Stage::Committing) {
                        c.stage = Stage::Stopped;
                    }
                }
            }
            PipelineEvent::Tick => self.expire_ack_waits(now, false, &mut out),
            PipelineEvent::Ack => self.expire_ack_waits(now, true, &mut out),
            PipelineEvent::ChunkProduced { index, len, digest } => {
                let i = index as usize;
                if self.interrupted {
                    return vec![PipelineAction::Idle];
                }
                if !self.accept_pending
                    || i != self.next_input
                    || i >= self.chunks.len()
                    || self.chunks[i].stage != Stage::Unproduced
                    || len != self.chunks[i].len
                    || (self.version == GrantVersion::V2 && digest.is_none())
                {
                    self.give_up(GiveUpReason::Producer, &mut out);
                } else {
                    self.accept_pending = false;
                    self.next_input += 1;
                    self.queue_order = self.queue_order.saturating_add(1);
                    let c = &mut self.chunks[i];
                    c.digest = digest;
                    c.stage = Stage::Queued;
                    c.queue_order = self.queue_order;
                }
            }
            other => {
                let index = match &other {
                    PipelineEvent::GrantOk { index }
                    | PipelineEvent::GrantSkipped { index }
                    | PipelineEvent::PutDone { index }
                    | PipelineEvent::PutAlreadyThere { index }
                    | PipelineEvent::PutFailed { index, .. }
                    | PipelineEvent::CommitDone { index }
                    | PipelineEvent::CommitFailed { index, .. }
                    | PipelineEvent::GrantRefused { index, .. } => *index as usize,
                    _ => unreachable!(),
                };
                if index >= self.chunks.len() {
                    self.give_up(GiveUpReason::Producer, &mut out);
                } else {
                    self.response(index, other, now, &mut out);
                }
            }
        }
        if !self.finished {
            self.schedule(now, &mut out);
        }
        if out.is_empty() {
            out.push(PipelineAction::Idle);
        }
        out
    }

    fn response(&mut self, i: usize, event: PipelineEvent, now: u64, out: &mut Vec<PipelineAction>) {
        let stage = self.chunks[i].stage;
        // Late results of cancelled operations cannot restart work or send a second commit.
        if matches!(stage, Stage::Stored | Stage::Stopped) {
            return;
        }
        match event {
            PipelineEvent::GrantOk { .. } if stage == Stage::Granting => {
                self.chunks[i].retry.link_issued();
                self.chunks[i].ack_retry = false;
                self.chunks[i].stage = Stage::Putting;
                out.push(PipelineAction::Put { index: i as u32 });
            }
            PipelineEvent::GrantSkipped { .. } if stage == Stage::Granting => self.chunks[i].stage = Stage::Stored,
            PipelineEvent::PutDone { .. } if stage == Stage::Putting => self.chunks[i].stage = Stage::Staged,
            PipelineEvent::PutAlreadyThere { .. } if stage == Stage::Putting => {
                if self.version == GrantVersion::V2 {
                    self.chunks[i].stage = Stage::Staged;
                } else {
                    self.chunks[i].stage = Stage::Queued;
                    self.failure(i, UploadFailure::Put { status: 412 }, 412, now, out);
                }
            }
            PipelineEvent::PutFailed { failure, .. } if stage == Stage::Putting => {
                if !matches!(failure, UploadFailure::Put { .. }) {
                    self.give_up(GiveUpReason::Producer, out);
                } else {
                    self.chunks[i].stage = Stage::Queued;
                    self.failure(i, failure, 0, now, out);
                }
            }
            PipelineEvent::CommitDone { .. } if stage == Stage::Committing => self.chunks[i].stage = Stage::Stored,
            PipelineEvent::CommitFailed { failure, status, .. } if stage == Stage::Committing => {
                if self.interrupted {
                    self.chunks[i].stage = Stage::Stopped;
                } else if !matches!(failure, UploadFailure::Commit(_)) {
                    self.give_up(GiveUpReason::Producer, out);
                } else {
                    self.failure(i, failure, status, now, out);
                }
            }
            PipelineEvent::GrantRefused {
                failure,
                status,
                commits_outstanding,
                ..
            } if stage == Stage::Granting => {
                if !matches!(failure, UploadFailure::Grant(_)) {
                    self.give_up(GiveUpReason::Producer, out);
                    return;
                }
                if status == 429
                    && commits_outstanding
                    && !self.chunks[i].ack_retry
                    && self.chunks[i].ack_waited < millis(self.policy.budget)
                    && let UploadFailure::Grant(Outcome::Backoff(after)) = &failure
                {
                    self.chunks[i].ack_retry = true;
                    self.chunks[i].stage = Stage::AwaitAck {
                        since: now,
                        after: *after,
                    };
                    out.push(PipelineAction::AwaitAck { index: i as u32 });
                } else {
                    self.failure(i, failure, status, now, out);
                }
            }
            _ => self.give_up(GiveUpReason::Producer, out),
        }
    }

    fn expire_ack_waits(&mut self, now: u64, ack: bool, out: &mut Vec<PipelineAction>) {
        for i in 0..self.chunks.len() {
            if self.finished {
                break;
            }
            if let Stage::AwaitAck { since, after } = self.chunks[i].stage {
                let elapsed = now.saturating_sub(since);
                let budget = millis(self.policy.budget);
                let left = budget.saturating_sub(self.chunks[i].ack_waited);
                if ack || elapsed >= left {
                    self.chunks[i].ack_waited = self.chunks[i].ack_waited.saturating_add(elapsed.min(left));
                    if self.chunks[i].ack_waited >= budget {
                        self.failure(i, UploadFailure::Grant(Outcome::Backoff(after)), 429, now, out);
                    } else {
                        self.chunks[i].stage = Stage::Queued;
                    }
                }
            }
        }
    }

    fn failure(&mut self, i: usize, mut failure: UploadFailure, status: u16, now: u64, out: &mut Vec<PipelineAction>) {
        // Defensively enforce the same stated-wait clamp even on manually constructed events.
        match &mut failure {
            UploadFailure::Grant(Outcome::Backoff(d)) | UploadFailure::Commit(Outcome::Backoff(d)) => {
                *d = (*d).clamp(Duration::from_secs(1), super::classify::MAX_RETRY_AFTER);
            }
            _ => {}
        }
        let held = matches!(failure, UploadFailure::Commit(Outcome::Held(_)));
        let gate = match &failure {
            UploadFailure::Grant(Outcome::Backoff(_)) => matches!(status, 429 | 503),
            UploadFailure::Commit(Outcome::Backoff(_)) => status == 429,
            _ => false,
        };
        match self.chunks[i].retry.failed(&failure) {
            UploadNext::UseApi => self.give_up(GiveUpReason::UseApi, out),
            UploadNext::Terminal(t) => self.give_up(
                GiveUpReason::Terminal {
                    status: t.status,
                    error: t.error,
                },
                out,
            ),
            UploadNext::Retry { after, call } => {
                let until = now.saturating_add(millis(after));
                match call {
                    Call::UploadGrant => {
                        self.queue_order = self.queue_order.saturating_add(1);
                        let c = &mut self.chunks[i];
                        c.stage = Stage::WaitGrant { until };
                        c.regrant = true;
                        c.queue_order = self.queue_order;
                        self.released = false;
                    }
                    Call::UploadCommit => self.chunks[i].stage = Stage::WaitCommit { until },
                    _ => unreachable!(),
                }
                if gate {
                    self.gate_until = self.gate_until.max(until);
                }
                if !after.is_zero() {
                    out.push(PipelineAction::Wait {
                        until_ms: until,
                        kind: if gate {
                            WaitKind::Gate
                        } else if held {
                            WaitKind::Hold(i as u32)
                        } else {
                            WaitKind::Chunk(i as u32)
                        },
                    });
                }
            }
        }
    }

    fn schedule(&mut self, now: u64, out: &mut Vec<PipelineAction>) {
        // Retry commits already own a slot, including during their hold or counted backoff.
        for (i, c) in self.chunks.iter_mut().enumerate() {
            if matches!(c.stage,Stage::WaitCommit {until} if now>=until) && !self.interrupted {
                c.stage = Stage::Committing;
                out.push(PipelineAction::Commit { index: i as u32 });
            }
        }
        let mut occupied = self
            .chunks
            .iter()
            .filter(|c| matches!(c.stage, Stage::Committing | Stage::WaitCommit { .. }))
            .count();
        for (i, c) in self.chunks.iter_mut().enumerate() {
            if c.stage == Stage::Staged && occupied < self.slots {
                c.stage = Stage::Committing;
                occupied += 1;
                out.push(PipelineAction::Commit { index: i as u32 });
            }
        }
        if self.interrupted {
            self.finished = !self
                .chunks
                .iter()
                .any(|c| matches!(c.stage, Stage::Committing | Stage::Staged));
            return;
        }
        let lane_busy = self
            .chunks
            .iter()
            .any(|c| matches!(c.stage, Stage::Granting | Stage::Putting | Stage::AwaitAck { .. }));
        if !lane_busy && now >= self.gate_until {
            let candidate = self
                .chunks
                .iter()
                .enumerate()
                .filter(|(_, c)| c.stage == Stage::Queued || matches!(c.stage,Stage::WaitGrant {until} if now>=until))
                .min_by_key(|(_, c)| (!c.regrant, c.queue_order))
                .map(|(i, _)| i);
            if let Some(i) = candidate {
                if !self.chunks[i].retry.may_ask_for_a_link() {
                    self.give_up(GiveUpReason::UseApi, out);
                    return;
                }
                let c = &mut self.chunks[i];
                c.stage = Stage::Granting;
                self.released = false;
                out.push(PipelineAction::Grant {
                    index: i as u32,
                    digest: c.digest,
                });
            }
        }
        // A tail may retain only S chunks. If the last PUT stages behind S occupied slots,
        // release after one ack admits that staged commit, rather than retaining S+1 in a tail.
        if !self.released
            && self
                .chunks
                .iter()
                .all(|c| matches!(c.stage, Stage::Stored | Stage::Committing | Stage::WaitCommit { .. }))
        {
            self.released = true;
            out.push(PipelineAction::ReleaseLane);
        }
        if self.chunks.iter().all(|c| c.stage == Stage::Stored) {
            self.finished = true;
            out.push(PipelineAction::Complete);
        } else if !self.accept_pending && self.next_input < self.chunks.len() && self.retained() < 1 + self.slots {
            self.accept_pending = true;
            out.push(PipelineAction::Accept);
        }
    }

    fn give_up(&mut self, reason: GiveUpReason, out: &mut Vec<PipelineAction>) {
        self.finished = true;
        self.accept_pending = false;
        for (i, c) in self.chunks.iter().enumerate() {
            if c.stage == Stage::Putting {
                out.push(PipelineAction::Cancel { index: i as u32 });
            }
        }
        out.push(PipelineAction::GiveUp { reason });
    }
}

fn millis(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

/// Binding/event JSON deliberately contains integer milliseconds, not serde's Duration layout.
/// Deserialize with a closed vocabulary and reject malformed input before changing a plan.
#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum JsonEvent {
    ChunkProduced {
        index: u32,
        len: u64,
        digest: Option<[u8; 16]>,
    },
    GrantOk {
        index: u32,
    },
    GrantSkipped {
        index: u32,
    },
    PutDone {
        index: u32,
    },
    PutAlreadyThere {
        index: u32,
    },
    PutFailed {
        index: u32,
        status: u16,
    },
    CommitDone {
        index: u32,
    },
    CommitFailed {
        index: u32,
        status: u16,
        outcome: JsonOutcome,
    },
    GrantRefused {
        index: u32,
        status: u16,
        outcome: JsonOutcome,
        commits_outstanding: bool,
    },
    SessionGone,
    ProducerFailed,
    Interrupt,
    Ack,
    Tick,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum JsonOutcome {
    Backoff { after_ms: u64 },
    Held { after_ms: Option<u64> },
    Retry,
    Regrant,
    ApiForThisFile,
    Terminal { status: u16, error: Option<String> },
}

impl JsonOutcome {
    fn outcome(self) -> Outcome {
        match self {
            Self::Backoff { after_ms } => Outcome::Backoff(Duration::from_millis(after_ms)),
            Self::Held { after_ms } => Outcome::Held(after_ms.map(Duration::from_millis)),
            Self::Retry => Outcome::Retry,
            Self::Regrant => Outcome::Regrant,
            Self::ApiForThisFile => Outcome::ApiForThisFile,
            Self::Terminal { status, error } => Outcome::Terminal(Terminal { status, error }),
        }
    }
}

impl PipelineEvent {
    /// Invalid input reports a fixed message: neither event bodies nor bearer URLs are echoed.
    pub fn from_json(input: &str) -> Result<Self, &'static str> {
        let wire: JsonEvent = serde_json::from_str(input).map_err(|_| "invalid pipeline event")?;
        Ok(match wire {
            JsonEvent::ChunkProduced { index, len, digest } => Self::ChunkProduced { index, len, digest },
            JsonEvent::GrantOk { index } => Self::GrantOk { index },
            JsonEvent::GrantSkipped { index } => Self::GrantSkipped { index },
            JsonEvent::PutDone { index } => Self::PutDone { index },
            JsonEvent::PutAlreadyThere { index } => Self::PutAlreadyThere { index },
            JsonEvent::PutFailed { index, status } => Self::PutFailed {
                index,
                failure: UploadFailure::Put { status },
            },
            JsonEvent::CommitDone { index } => Self::CommitDone { index },
            JsonEvent::CommitFailed { index, status, outcome } => Self::CommitFailed {
                index,
                status,
                failure: UploadFailure::Commit(outcome.outcome()),
            },
            JsonEvent::GrantRefused {
                index,
                status,
                outcome,
                commits_outstanding,
            } => Self::GrantRefused {
                index,
                status,
                failure: UploadFailure::Grant(outcome.outcome()),
                commits_outstanding,
            },
            JsonEvent::SessionGone => Self::SessionGone,
            JsonEvent::ProducerFailed => Self::ProducerFailed,
            JsonEvent::Interrupt => Self::Interrupt,
            JsonEvent::Ack => Self::Ack,
            JsonEvent::Tick => Self::Tick,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::direct_transfer::timeouts::{put_allowance, storage_put_total, storage_put_total_shared};
    use std::time::Duration;

    #[test]
    fn core_runs_every_pipeline_scenario() {
        let report = crate::direct_transfer::vectors::run_pipeline_all(|size, lens, version, policy| {
            PipelinePlan::new(size, lens, version, policy)
        });
        assert_eq!(report, crate::direct_transfer::vectors::expected_pipeline_report());
        assert_eq!(report.scenarios, 66);
        println!(
            "pipeline vectors: {} scenarios, {} steps",
            report.scenarios, report.steps
        );
    }

    const MIB: u64 = 1024 * 1024;

    fn lengths() -> Vec<u64> {
        let max = 256 * MIB + 28;
        let mut lens = vec![0, 1, 28, 4 * MIB + 28, 32 * MIB + 28, max, u64::MAX];
        lens.extend((0..=28).map(|k| (1u64 << k) + 28).filter(|l| *l <= max));
        lens.extend([1_000_000, 5_000_000, 10_000_000, 20_000_000]);
        lens.extend((0..4096u64).map(|i| 28 + i * (max - 28) / 4095));
        assert_eq!(lens.len(), 4136);
        lens
    }

    #[test]
    fn commit_slots_is_two_below_sixteen_mib_and_one_from_it() {
        for len in [0, 4 * MIB, 16 * MIB - 1] {
            assert_eq!(commit_slots(len), 2, "{len}");
        }
        for len in [16 * MIB, 128 * MIB, u64::MAX] {
            assert_eq!(commit_slots(len), 1, "{len}");
        }
    }

    #[test]
    fn constants_equal_the_vector_file() {
        let v: serde_json::Value =
            serde_json::from_str(include_str!("../../../test-vectors/direct_upload_pipeline.json")).unwrap();
        let c = v["constants"].as_object().unwrap();
        let actual = [
            ("UPLOAD_COMMIT_SLOTS_SMALL", u64::from(UPLOAD_COMMIT_SLOTS_SMALL)),
            ("UPLOAD_COMMIT_SLOTS_LARGE", u64::from(UPLOAD_COMMIT_SLOTS_LARGE)),
            ("UPLOAD_COMMIT_SLOTS_SMALL_BELOW", UPLOAD_COMMIT_SLOTS_SMALL_BELOW),
            ("UPLOAD_PUT_LANES", u64::from(UPLOAD_PUT_LANES)),
            (
                "UPLOAD_FILE_CONCURRENCY_DEFAULT",
                u64::from(UPLOAD_FILE_CONCURRENCY_DEFAULT),
            ),
            ("UPLOAD_FILE_CONCURRENCY_MAX", u64::from(UPLOAD_FILE_CONCURRENCY_MAX)),
            ("UPLOAD_TAIL_FILES_MAX", u64::from(UPLOAD_TAIL_FILES_MAX)),
            (
                "UPLOAD_API_REQUESTS_PER_SECOND_MAX",
                u64::from(UPLOAD_API_REQUESTS_PER_SECOND_MAX),
            ),
            ("UPLOAD_API_BURST", u64::from(UPLOAD_API_BURST)),
        ];
        assert_eq!(c.len(), actual.len());
        for (name, value) in actual {
            assert_eq!(c[name].as_u64(), Some(value), "{name}");
        }
    }

    #[test]
    fn a_shared_put_total_never_exceeds_the_fence() {
        for len in lengths() {
            for k in 1..=8 {
                assert!(
                    storage_put_total_shared(len, k) <= put_allowance(len) - Duration::from_secs(30),
                    "len={len}, k={k}"
                );
            }
        }
    }

    #[test]
    fn with_one_put_in_flight_the_shared_total_is_the_single_put_total() {
        for len in lengths() {
            assert_eq!(storage_put_total_shared(len, 1), storage_put_total(len), "len={len}");
            assert_eq!(
                storage_put_total_shared(len, 0),
                storage_put_total(len),
                "zero in-flight, len={len}"
            );
        }
    }

    #[test]
    fn thirty_two_mib_gives_317_s_at_k1_and_480_s_at_k2() {
        let len = 32 * MIB + 28;
        assert_eq!(put_allowance(len).as_secs(), 510);
        assert_eq!(storage_put_total_shared(len, 1).as_secs(), 317);
        assert_eq!(storage_put_total_shared(len, 2).as_secs(), 480);
        assert!(storage_put_total_shared(u64::MAX, u32::MAX) <= put_allowance(u64::MAX) - Duration::from_secs(30));
    }
}
