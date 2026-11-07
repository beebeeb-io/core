//! The C3 WASM surface (core run 3): thin `#[wasm_bindgen]` bindings over the
//! core modules the web lane shares with the other clients.
//!
//! Every function here forwards to `beebeeb-core` or `beebeeb-types` and only
//! converts between JS and the core types. No rule lives in this module: a
//! change to a message, a budget or a naming rule is a change in core, proved
//! by the shared vector in `test-vectors/consolidation/`, and this surface
//! follows it.
//!
//! It is a separate tree on purpose: `lib.rs` is baseline-capped, so it only
//! declares `mod exports;` and the new surface grows here.

pub mod backup;
pub mod contacts;
pub mod format;
pub mod media;
pub mod metadata_wire;
pub mod path_safety;
pub mod retry;
pub mod share_link;
pub mod thumbnail;
