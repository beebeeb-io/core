//! Tests for the walk, the fingerprint and `run_pass`, over real temporary
//! folders (std only: no test-only dependency).

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use beebeeb_core::backup::SkipReason;

use crate::walk::{attrs_from_parts, walk_with_paths};
use crate::{MAX_DEPTH, fingerprint, walk_source};

/// A fresh directory under the system temp dir, removed on drop.
pub(crate) struct TempDir(PathBuf);

impl TempDir {
    pub(crate) fn new(tag: &str) -> TempDir {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "bb-backup-{tag}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&path).expect("create temp dir");
        TempDir(path)
    }

    pub(crate) fn path(&self) -> &Path {
        &self.0
    }

    pub(crate) fn write(&self, rel: &str, bytes: &[u8]) -> PathBuf {
        let path = self.0.join(rel);
        std::fs::create_dir_all(path.parent().expect("parent")).expect("create parent");
        std::fs::write(&path, bytes).expect("write fixture");
        path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn keys(result: &crate::WalkResult) -> Vec<&str> {
    result.entries.iter().map(|e| e.key.as_str()).collect()
}

#[cfg(unix)]
#[test]
fn walk_skips_junk_links_and_bundles() {
    let dir = TempDir::new("junk");
    dir.write("Thumbs.db", b"junk");
    dir.write("a/b/c.txt", b"hello");
    dir.write("x.photoslibrary/database/Photos.sqlite", b"db");
    std::os::unix::fs::symlink(dir.path().join("a"), dir.path().join("shortcut")).expect("symlink");

    let result = walk_source(dir.path()).expect("walk");
    assert_eq!(keys(&result), ["a", "a/b", "a/b/c.txt"]);
    let mut skipped = result.skipped.clone();
    skipped.sort();
    assert_eq!(
        skipped,
        [
            ("Thumbs.db".to_string(), SkipReason::Junk),
            ("shortcut".to_string(), SkipReason::Link),
            ("x.photoslibrary".to_string(), SkipReason::LibraryBundle),
        ]
    );
    let file = &result.entries[2];
    assert_eq!((file.is_dir, file.size), (false, 5));
    assert!(result.entries[0].is_dir && result.entries[1].is_dir);
}

#[cfg(unix)]
#[test]
fn walk_never_opens_files() {
    use std::os::unix::fs::PermissionsExt;
    let dir = TempDir::new("closed");
    let locked = dir.write("private.txt", b"secret");
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).expect("chmod");
    let result = walk_source(dir.path()).expect("walk");
    assert_eq!(keys(&result), ["private.txt"]);
    assert_eq!(result.entries[0].size, 6);
    assert!(result.skipped.is_empty());
}

#[test]
fn walk_depth_cap() {
    let dir = TempDir::new("deep");
    let mut path = dir.path().to_path_buf();
    for _ in 0..70 {
        path.push("d");
    }
    std::fs::create_dir_all(&path).expect("nested folders");

    let result = walk_source(dir.path()).expect("walk");
    let deepest = result.entries.iter().map(|e| e.key.split('/').count()).max();
    assert_eq!(deepest, Some(MAX_DEPTH));
    assert_eq!(result.entries.len(), MAX_DEPTH);
    assert_eq!(result.skipped.len(), 1);
    assert_eq!(result.skipped[0].1, SkipReason::TooDeep);
    assert_eq!(result.skipped[0].0.split('/').count(), MAX_DEPTH + 1);
}

#[test]
fn walk_keys_are_nfc() {
    let dir = TempDir::new("nfc");
    let nfd = "Rene\u{301}.txt";
    dir.write(nfd, b"x");
    let walk = walk_with_paths(dir.path()).expect("walk");
    assert_eq!(keys(&walk.result), ["Ren\u{e9}.txt"]);
    // The key is NFC; the path the uploader reads is the real one on disk.
    let real = walk.paths.get("Ren\u{e9}.txt").expect("a path for the key");
    assert!(real.exists(), "{}", real.display());
}

#[cfg(unix)]
#[test]
fn walk_reports_an_unreadable_folder_and_keeps_going() {
    use std::os::unix::fs::PermissionsExt;
    let dir = TempDir::new("unreadable");
    dir.write("closed/inside.txt", b"x");
    dir.write("open.txt", b"y");
    let closed = dir.path().join("closed");
    std::fs::set_permissions(&closed, std::fs::Permissions::from_mode(0o000)).expect("chmod");
    let readable_anyway = std::fs::read_dir(&closed).is_ok();
    let result = walk_source(dir.path()).expect("walk");
    std::fs::set_permissions(&closed, std::fs::Permissions::from_mode(0o755)).expect("chmod back");
    if readable_anyway {
        // Running as root: permissions do not apply, so there is nothing to refuse.
        assert_eq!(keys(&result), ["closed", "closed/inside.txt", "open.txt"]);
        eprintln!(
            "walk_reports_an_unreadable_folder_and_keeps_going: permissions ignored (root); checked the listing only"
        );
        return;
    }
    assert_eq!(keys(&result), ["closed", "open.txt"]);
    assert_eq!(result.skipped, [("closed".to_string(), SkipReason::Unreadable)]);
}

/// The plan's fallback for the Windows fixture (Task A6): the attribute words
/// are decoded by a pure function, checked here on every host.
#[test]
fn attrs_of_decodes_the_not_local_and_reparse_bits() {
    const RECALL_ON_DATA_ACCESS: u32 = 0x0040_0000;
    const RECALL_ON_OPEN: u32 = 0x0004_0000;
    const OFFLINE: u32 = 0x1000;
    const REPARSE_POINT: u32 = 0x400;
    const ARCHIVE: u32 = 0x20;
    const SF_DATALESS: u32 = 0x4000_0000;

    let win = |bits: u32| attrs_from_parts("IMG_1.jpg", false, false, Some(bits), None);
    assert!(win(RECALL_ON_DATA_ACCESS).not_local);
    assert!(win(RECALL_ON_OPEN).not_local);
    assert!(win(OFFLINE).not_local);
    assert!(win(REPARSE_POINT).is_link && !win(REPARSE_POINT).not_local);
    let plain = win(ARCHIVE);
    assert!(!plain.not_local && !plain.is_link);
    // A OneDrive cloud-only file is a reparse point with a recall bit: it is
    // reported as not local (the reason a person is shown), never read.
    let cloud = win(REPARSE_POINT | RECALL_ON_DATA_ACCESS);
    assert_eq!(
        beebeeb_core::backup::skip_reason("IMG_1.jpg", &cloud),
        Some(SkipReason::NotLocal)
    );

    let mac = |flags: u32| attrs_from_parts("IMG_1.jpg", true, false, None, Some(flags));
    assert!(mac(SF_DATALESS).not_local && mac(SF_DATALESS).is_dir);
    assert!(!mac(0).not_local);

    assert!(attrs_from_parts(".IMG_1.jpg.icloud", false, false, None, None).not_local);
    assert!(attrs_from_parts(".notes.ICLOUD", false, false, None, None).not_local);
    assert!(!attrs_from_parts("IMG_1.icloud", false, false, None, None).not_local);
    assert!(attrs_from_parts("fifo", false, true, None, None).is_link);
}

#[test]
fn fingerprint_tracks_size_mtime_and_file_id() {
    let dir = TempDir::new("fingerprint");
    let path = dir.write("a.txt", b"one");
    let first = fingerprint(&path).expect("fingerprint");
    assert_eq!(
        first,
        fingerprint(&path).expect("again"),
        "stable while nothing changes"
    );
    assert_eq!(first.size, 3);
    #[cfg(unix)]
    assert!(first.file_id.is_some());
    #[cfg(windows)]
    assert!(first.file_id.is_none());

    std::fs::write(&path, b"one more").expect("rewrite");
    let second = fingerprint(&path).expect("fingerprint");
    assert_ne!(first, second);
    assert_eq!(second.size, 8);

    let folder = dir.path().join("folder");
    std::fs::create_dir(&folder).expect("mkdir");
    assert!(fingerprint(&folder).is_err(), "a folder has no fingerprint");
}
