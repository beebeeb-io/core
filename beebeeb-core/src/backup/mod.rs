//! The backup rules every client shares (LD-0113, spec
//! `2026-11-06-backup-from-source-design.md` §4.2).
//!
//! Pure rules: no I/O, no clock, no network. Core decides the rule and the
//! client performs the I/O (the `direct_transfer` pattern). The filesystem
//! pass that uses these rules is the `beebeeb-backup` crate; iOS and the web
//! reach them through the uniffi and wasm bindings.
//!
//! - layout: the `Backups/<device>/<category>/<path>` tree and its names;
//! - protection: the Backups root is never trashed, deleted, renamed or moved;
//! - skip: what is never backed up (OS junk, library bundles, links, files
//!   whose bytes are not on this device).
//!
//! The root is never located by path: it is the folder whose server row
//! carries [`beebeeb_types::backup::SystemRole::BackupsRoot`].

mod layout;
mod protect;
mod skip;

pub use layout::*;
pub use protect::*;
pub use skip::*;
