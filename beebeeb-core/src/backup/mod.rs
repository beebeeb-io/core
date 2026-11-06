//! The backup rules every client shares (LD-0113, spec
//! `2026-11-06-backup-from-source-design.md` §4.2).
//!
//! Pure rules: no I/O, no clock, no network. Core decides the rule and the
//! client performs the I/O (the `direct_transfer` pattern). The filesystem
//! pass that uses these rules is the `beebeeb-backup` crate; iOS and the web
//! reach them through the uniffi and wasm bindings.
//!
//! - layout: the `Backups/<device>/<category>/<path>` tree and its names;
//! - device: the device folder's name, the desktop device id, and which
//!   folder is this device's;
//! - manifest: the encrypted `.device.json` in each device folder;
//! - root and merge: which folder is the root, and folding legacy duplicate
//!   roots into it;
//! - protection: who may change what in the backup tree (the app, drive and
//!   root rules, with their words);
//! - skip: what is never backed up (OS junk, library bundles, links, files
//!   whose bytes are not on this device);
//! - plan and rebuild: what one pass uploads, moves or marks, and records
//!   rebuilt from the server after a reinstall.
//!
//! The root is never located by path or name: it is the folder whose server
//! row carries [`beebeeb_types::backup::SystemRole::BackupsRoot`].

mod device;
mod layout;
mod manifest;
mod merge;
mod plan;
mod protect;
mod rebuild;
mod root;
mod skip;

pub use device::*;
pub use layout::*;
pub use manifest::*;
pub use merge::*;
pub use plan::*;
pub use protect::*;
pub use rebuild::*;
pub use root::*;
pub use skip::*;

/// Names compare as a case-insensitive filesystem would show them: two
/// siblings that differ only in case or normalisation collide in a drive. The
/// one fold every backup rule uses (sibling clashes, device-name collisions,
/// the walk's excluded paths on Windows and macOS).
pub fn fold_name(name: &str) -> String {
    use unicode_normalization::UnicodeNormalization;
    name.nfc().collect::<String>().to_lowercase()
}
