//! The fingerprint rule (spec §4.3): the uploader reads the person's file in
//! place, with no staged copy, so it records the file's fingerprint before the
//! first chunk and compares after the last. Any difference means the file
//! changed while it was read: the session is abandoned
//! (`POST …/upload/abandon`) and the file is retried next pass, so a torn copy
//! never lands. A resume continues only with an unchanged fingerprint.

use std::fs::Metadata;
use std::io;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use beebeeb_core::backup::EntryAttrs;

use crate::walk::attrs_of;

/// What identifies one version of a file without reading it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fingerprint {
    pub size: u64,
    pub modified_ms: i64,
    /// The inode on Unix. `None` on Windows: std has no stable file id there,
    /// so size and mtime carry it.
    pub file_id: Option<u128>,
}

/// Milliseconds since the Unix epoch, negative before 1970 (cameras with a
/// dead clock), saturating instead of overflowing; 0 when the platform has no
/// modification time.
pub(crate) fn system_time_ms(time: SystemTime) -> i64 {
    match time.duration_since(UNIX_EPOCH) {
        Ok(after) => i64::try_from(after.as_millis()).unwrap_or(i64::MAX),
        Err(before) => i64::try_from(before.duration().as_millis()).map_or(i64::MIN, |ms| -ms),
    }
}

pub(crate) fn modified_ms(meta: &Metadata) -> i64 {
    meta.modified().map_or(0, system_time_ms)
}

#[cfg(unix)]
fn file_id(meta: &Metadata) -> Option<u128> {
    use std::os::unix::fs::MetadataExt;
    Some(u128::from(meta.ino()))
}

#[cfg(not(unix))]
fn file_id(_meta: &Metadata) -> Option<u128> {
    None
}

/// The fingerprint of the regular file at `path`, from its metadata only (the
/// file is not opened for reading, and a link is not followed).
pub fn fingerprint(path: &Path) -> io::Result<Fingerprint> {
    fingerprint_with_attrs(path).map(|(fp, _)| fp)
}

/// The fingerprint and the entry's attributes as they are now, so the pass
/// can re-check, right before the handoff, that the bytes are still here (a
/// OneDrive file can go online-only after the walk). Called only for a file
/// the walk already found local: on Windows `symlink_metadata` opens a handle
/// with no data access, which reads attributes and never recalls a file.
pub(crate) fn fingerprint_with_attrs(path: &Path) -> io::Result<(Fingerprint, EntryAttrs)> {
    let meta = std::fs::symlink_metadata(path)?;
    if !meta.is_file() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "not a regular file"));
    }
    let fp = Fingerprint {
        size: meta.len(),
        modified_ms: modified_ms(&meta),
        file_id: file_id(&meta),
    };
    Ok((fp, attrs_of(&meta)))
}
