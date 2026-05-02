//! Client sync engine — shared by web (WASM), mobile (UniFFI), CLI, and desktop.
//!
//! See `docs/specs/2026-05-02-crdt-sync-engine-design.md` section 3.
//!
//! The engine holds a full in-memory tree, applies remote ops streamed from the
//! server, and provides optimistic local mutations with rollback on conflict.

pub mod engine;
pub mod events;
pub mod hash;
pub mod types;

pub use engine::SyncEngine;
pub use events::SyncEvent;
pub use hash::blake3_hash;
pub use types::{PendingOp, SyncOp, TreeNode};
