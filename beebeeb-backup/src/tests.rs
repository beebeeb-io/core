//! Tests for the walk, the fingerprint and `run_pass`, over real temporary
//! folders (std only: no test-only dependency).

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use beebeeb_core::backup::SkipReason;

use crate::walk::{Excludes, attrs_from_parts, collect_listing, is_within, walk_with_paths};
use crate::{MAX_DEPTH, fingerprint, walk_source};

/// `run_pass` over a recording host.
mod pass;

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

    let result = walk_source(dir.path(), &[]).expect("walk");
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
    let result = walk_source(dir.path(), &[]).expect("walk");
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

    let result = walk_source(dir.path(), &[]).expect("walk");
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
    let walk = walk_with_paths(dir.path(), &[]).expect("walk");
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
    let result = walk_source(dir.path(), &[]).expect("walk");
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

    let win = |bits: u32| attrs_from_parts(false, false, Some(bits), None);
    assert!(win(RECALL_ON_DATA_ACCESS).not_local);
    assert!(win(RECALL_ON_OPEN).not_local);
    assert!(win(OFFLINE).not_local);
    // Plan Amendment 1, item 7: OneDrive sets the reparse bit on every file,
    // local ones included. Alone it is a local file, backed up; a link is
    // std's name-surrogate test (`link_or_special`), never this bit.
    let local_onedrive = win(REPARSE_POINT | ARCHIVE);
    assert!(!local_onedrive.is_link && !local_onedrive.not_local);
    assert_eq!(beebeeb_core::backup::skip_reason("IMG_1.jpg", &local_onedrive), None);
    let plain = win(ARCHIVE);
    assert!(!plain.not_local && !plain.is_link);
    // A OneDrive cloud-only file is a reparse point with a recall bit: it is
    // reported as not local (the reason a person is shown), never read.
    let cloud = win(REPARSE_POINT | RECALL_ON_DATA_ACCESS);
    assert_eq!(
        beebeeb_core::backup::skip_reason("IMG_1.jpg", &cloud),
        Some(SkipReason::NotLocal)
    );

    let mac = |flags: u32| attrs_from_parts(true, false, None, Some(flags));
    assert!(mac(SF_DATALESS).not_local && mac(SF_DATALESS).is_dir);
    assert!(!mac(0).not_local);

    // A symlink, a junction, a FIFO: never followed, never read.
    assert!(attrs_from_parts(false, true, Some(REPARSE_POINT), None).is_link);
    assert!(attrs_from_parts(false, true, None, None).is_link);
}

/// Plan Amendment 1, item 8: the client's own sync root inside a backed-up
/// folder is never listed or entered, so the drive (its Backups included) is
/// never backed up into itself.
#[test]
fn walk_never_descends_into_excluded_path() {
    let dir = TempDir::new("exclude");
    dir.write("report.pdf", b"x");
    dir.write("Beebeeb/notes.txt", b"y");
    dir.write("Beebeeb/Backups/GLegion/Documents/report.pdf", b"x");
    dir.write("BeebeebOld/kept.txt", b"z");
    let sync_root = dir.path().join("Beebeeb");

    let result = walk_source(dir.path(), &[sync_root]).expect("walk");
    let under: Vec<&str> = keys(&result)
        .into_iter()
        .filter(|k| *k == "Beebeeb" || k.starts_with("Beebeeb/"))
        .collect();
    assert!(under.is_empty(), "{under:?}");
    assert_eq!(result.skipped, [("Beebeeb".to_string(), SkipReason::Excluded)]);
    assert_eq!(keys(&result), ["BeebeebOld", "BeebeebOld/kept.txt", "report.pdf"]);
}

#[test]
fn excluded_paths_compare_by_component_and_by_case_where_the_os_does() {
    let base = Path::new("/home/u/Documents/Beebeeb");
    assert!(is_within(Path::new("/home/u/Documents/Beebeeb"), base, false));
    assert!(is_within(Path::new("/home/u/Documents/Beebeeb/Backups"), base, false));
    assert!(is_within(Path::new("/home/u/Documents/Beebeeb/"), base, false));
    assert!(!is_within(Path::new("/home/u/Documents/BeebeebOld"), base, false));
    assert!(!is_within(Path::new("/home/u/Documents"), base, false));
    assert!(!is_within(Path::new("/home/u/documents/beebeeb"), base, false));
    // Windows and macOS: no case, and NFC.
    assert!(is_within(Path::new("/home/u/documents/BEEBEEB/x"), base, true));
    assert!(is_within(
        Path::new("/home/u/Cafe\u{301}/a"),
        Path::new("/home/u/caf\u{e9}"),
        true
    ));
    assert!(!is_within(Path::new("/home/u/documents/beebeebold"), base, true));
}

/// Two names in one Linux folder that differ only in normalisation are both
/// backed up, each from its own bytes; the NFC one keeps the NFC key. The NFD
/// name sorts first byte-wise, so taking names in listing order fails this.
#[cfg(target_os = "linux")]
#[test]
fn walk_nfc_and_nfd_twins_both_listed() {
    let dir = TempDir::new("twins");
    dir.write("Rene\u{301}.txt", b"nfd");
    dir.write("Ren\u{e9}.txt", b"nfc");
    let walk = walk_with_paths(dir.path(), &[]).expect("walk");
    assert_eq!(walk.result.entries.len(), 2);
    assert!(walk.result.skipped.is_empty(), "{:?}", walk.result.skipped);
    assert_eq!(std::fs::read(&walk.paths["Ren\u{e9}.txt"]).expect("nfc"), b"nfc");
    assert_eq!(std::fs::read(&walk.paths["Rene\u{301}.txt"]).expect("nfd"), b"nfd");
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

/// Review finding 2: a listing that fails partway yields no entries at all,
/// so the folder is reported unreadable as a whole (or, for the backed-up
/// folder itself, the pass stops) instead of half its files being planned.
#[test]
fn a_listing_that_fails_partway_is_not_used() {
    let listing = vec![
        Ok(("a.jpg".to_string(), ())),
        Err(std::io::Error::other("the listing broke off")),
        Ok(("b.jpg".to_string(), ())),
    ];
    assert!(collect_listing(listing.into_iter()).is_err());
    let whole = vec![Ok(("b.jpg".to_string(), ())), Ok(("a.jpg".to_string(), ()))];
    let names: Vec<String> = collect_listing(whole.into_iter())
        .expect("listing")
        .into_iter()
        .map(|(name, ())| name)
        .collect();
    assert_eq!(names, ["a.jpg", "b.jpg"]);
}

/// Review finding 3: an empty path would exclude everything (no components)
/// and a relative or `..` one nothing, so both are refused.
#[test]
fn empty_exclude_path_is_refused() {
    let dir = TempDir::new("emptyexclude");
    dir.write("a.txt", b"x");
    for bad in [
        PathBuf::new(),
        PathBuf::from("Beebeeb"),
        dir.path().join("x/../Beebeeb"),
    ] {
        let err = walk_source(dir.path(), std::slice::from_ref(&bad)).expect_err("refused");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput, "{bad:?}");
    }
    assert_eq!(keys(&walk_source(dir.path(), &[]).expect("walk")), ["a.txt"]);
}

/// An excluded path two folders down: the folders above it are walked, the
/// path itself is not.
#[test]
fn walk_excludes_a_nested_path_only() {
    let dir = TempDir::new("nestedexclude");
    dir.write("a/x.txt", b"x");
    dir.write("a/b/inside.txt", b"y");
    dir.write("b/kept.txt", b"z");
    let result = walk_source(dir.path(), &[dir.path().join("a/b")]).expect("walk");
    assert_eq!(keys(&result), ["a", "a/x.txt", "b", "b/kept.txt"]);
    assert_eq!(result.skipped, [("a/b".to_string(), SkipReason::Excluded)]);
}

/// Review finding 10: the excluded paths are folded once; a name is compared
/// only while an excluded path runs through its folder, without case where
/// the OS has none.
#[test]
fn excludes_are_folded_once_and_followed_by_component() {
    use std::ffi::OsStr;
    let root = Path::new("/home/u/Documents");
    let sync = [PathBuf::from("/home/u/documents/BEEBEEB/Drive")];
    let folded = Excludes::new(root, &sync, true).expect("excludes");
    let through = folded
        .step(&folded.everywhere(), 0, OsStr::new("Beebeeb"))
        .expect("runs on");
    assert_eq!(through.len(), 1);
    assert_eq!(folded.step(&through, 1, OsStr::new("drive")), None, "excluded");
    assert_eq!(folded.step(&through, 1, OsStr::new("Other")), Some(Vec::new()));
    assert_eq!(
        folded.step(&[], 1, OsStr::new("drive")),
        Some(Vec::new()),
        "no path runs through"
    );
    // With case (Linux), the spelling differs from the root: nothing is excluded.
    let exact = Excludes::new(root, &sync, false).expect("excludes");
    assert!(exact.everywhere().is_empty());
    // The root inside an excluded path: every entry is.
    let inside = Excludes::new(root, &[PathBuf::from("/home/u")], false).expect("excludes");
    assert_eq!(inside.step(&[], 0, OsStr::new("anything")), None);
}
