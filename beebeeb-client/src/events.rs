use tokio::sync::broadcast;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EngineEvent {
    AccountChanged {
        generation: u64,
    },
    AccountMismatch,
    SessionExpired,
    HandOff {
        ticket: String,
    },
    VersionRollback {
        file_id: String,
        observed: u64,
        highest: u64,
    },
    SyncCaughtUp {
        seq_id: i64,
        user_seq: i64,
    },
    WorkStopped,
}

#[derive(Clone)]
pub struct EngineEvents {
    sender: broadcast::Sender<EngineEvent>,
}

impl EngineEvents {
    pub fn new(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity.max(1));
        Self { sender }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<EngineEvent> {
        self.sender.subscribe()
    }

    pub fn emit(&self, event: EngineEvent) {
        let _ = self.sender.send(event);
    }
}

impl Default for EngineEvents {
    fn default() -> Self {
        Self::new(64)
    }
}
