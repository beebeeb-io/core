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
/// file is not opened, and a link is not followed).
pub fn fingerprint(path: &Path) -> io::Result<Fingerprint> {
    let meta = std::fs::symlink_metadata(path)?;
    if !meta.is_file() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "not a regular file"));
    }
    Ok(Fingerprint {
        size: meta.len(),
        modified_ms: modified_ms(&meta),
        file_id: file_id(&meta),
    })
}
