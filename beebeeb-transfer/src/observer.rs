//! Progress and decision events of one download (plan K2).
//!
//! Events carry numbers and enum values only: no URL, no header, no error
//! text. A client's observer can therefore log or show them without a
//! redaction step.

use beebeeb_core::direct_transfer::Direction;

/// Which transport this file is on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportKind {
    Direct,
    Api,
}

/// How one chunk arrived.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChunkVia {
    Storage,
    Pinned,
}

/// Why the driver handed the file to the API path without fetching anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UseApiReason {
    /// The caller forced the API path.
    ForcedApi,
    /// The storage breaker held this direction off after an earlier give-up.
    BreakerHold,
    /// The server does not offer the direct transport.
    NotSupported,
    /// Discovery gave no usable answer (a 5xx, a bare 404/405, a redirect, a
    /// transport failure, or its retry budget is spent): try again later.
    DiscoveryUnavailable,
    /// The server or the planner said the API serves this file.
    ApiForFile,
    /// Chunk 0 did not authenticate and the caller allowed the legacy readers.
    LegacyFile,
}

/// One event of a download. `Observer::event` is called on the task that runs
/// the driver; an implementation must not block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferEvent {
    /// The transport decision for this file was made.
    Decided(TransportKind),
    /// A chunk was fetched whole.
    Chunk { index: u32, via: ChunkVia },
    /// A chunk's storage link failed and a fresh one will be asked for.
    Renewed { index: u32 },
    /// The storage breaker tripped for this direction.
    GaveUp(Direction),
    /// Plaintext bytes were written to the sink.
    Bytes(u64),
    /// Everything written so far was thrown away, so progress can roll back.
    Discarded {
        plaintext_bytes: u64,
        ciphertext_bytes: u64,
    },
}

/// Receives [`TransferEvent`]s. The default does nothing.
pub trait Observer: Send + Sync {
    fn event(&self, _e: TransferEvent) {}
}
