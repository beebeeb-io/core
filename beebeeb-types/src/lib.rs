//! Shared types for the Beebeeb end-to-end encrypted cloud storage platform.
//!
//! This crate defines the canonical data structures and constants used across
//! every layer of the Beebeeb stack:
//!
//! - **`beebeeb-core`** — encryption, key derivation, recovery phrases
//! - **`beebeeb-wasm`** — WebAssembly bindings for the web client
//! - **`beebeeb-uniffi`** — native bindings for iOS/Android via UniFFI
//! - **`beebeeb-sync`** — desktop file sync engine
//! - **`beebeeb-server`** (via `beebeeb-core`) — the Axum API server
//!
//! # Design principles
//!
//! - **Single source of truth.** Every crate imports these types rather than
//!   defining its own. Changes here propagate everywhere.
//! - **Serialization-ready.** All types derive [`serde::Serialize`] and
//!   [`serde::Deserialize`] so they can be stored, transmitted over the wire,
//!   or converted to JSON/MessagePack without adapters.
//! - **No crypto logic.** This crate contains only type definitions and
//!   constants. Actual encryption, key derivation, and protocol logic live
//!   in `beebeeb-core`.
//!
//! # Modules
//!
//! - [`chunk`] — storage format versions and dynamic chunk planning
//! - [`crypto`] — cipher suites, KDF parameters, and cryptographic constants
//! - [`file`] — encrypted blob and chunk metadata types

pub mod chunk;
pub mod crypto;
pub mod file;

pub use chunk::*;
pub use crypto::*;
pub use file::*;
