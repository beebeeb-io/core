//! The backup filesystem pass for the clients that walk files: desktop
//! (Windows, macOS, Linux) and the CLI (LD-0113, spec
//! `2026-11-06-backup-from-source-design.md` §4.3).
//!
//! The rules live in `beebeeb_core::backup` (pure). This crate performs the
//! one kind of I/O they need, reading a folder's listing and attributes, and
//! hands the rest to the client (the `beebeeb-transfer` pattern):
//!
//! - [`walk_source`]: list a backed-up folder without opening a file, skipping
//!   what is never backed up and never descending into what is not local;
//! - [`fingerprint`]: what the uploader compares before and after reading a
//!   file in place, so a file that changes mid-upload never lands torn.
//!
//! The source folder is the person's own: nothing here writes, renames,
//! deletes, truncates or changes the attributes of anything in it. Logs and
//! errors carry counts and kinds, never a name or a path.

mod fingerprint;
mod walk;

pub use fingerprint::{Fingerprint, fingerprint};
pub use walk::{MAX_DEPTH, WalkResult, attrs_of, walk_source};

#[cfg(test)]
mod tests;
