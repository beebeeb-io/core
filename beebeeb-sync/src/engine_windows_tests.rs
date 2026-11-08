//! Windows: a remote delete never deletes another file through its 8.3 short
//! name (task 2404). The test first shows that its fixture really aliases (an
//! ordinary read of the short name reaches the other file); a volume that makes
//! no 8.3 names skips with the reason printed, and fails with `CI` set. Only
//! the v0.2.6 API is used, so the file runs unchanged at the parent (red).

use super::*;
use std::fs;
use tempfile::TempDir;

/// The 8.3 short name the volume gave `path`'s last component, if it differs
/// from the long name.
fn short_name(path: &Path) -> Option<String> {
    use std::os::windows::ffi::OsStrExt as _;
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetShortPathNameW(long: *const u16, short: *mut u16, length: u32) -> u32;
    }
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain([0]).collect();
    let mut buffer = vec![0u16; 1024];
    // SAFETY: `wide` is NUL-terminated; `buffer` holds the length passed.
    let written = unsafe { GetShortPathNameW(wide.as_ptr(), buffer.as_mut_ptr(), buffer.len() as u32) };
    assert!(
        written != 0 && (written as usize) < buffer.len(),
        "GetShortPathNameW failed for {}",
        path.display()
    );
    let short = String::from_utf16(&buffer[..written as usize]).expect("short path is UTF-16");
    let last = short.rsplit('\\').next().unwrap_or(&short).to_owned();
    let long = path.file_name().expect("a file name").to_string_lossy();
    (last != long).then_some(last)
}

/// A synced row whose name is now another file's short name (the remote file
/// it named is gone): the remote delete must not delete that other file.
#[test]
fn a_remote_delete_never_deletes_another_file_through_its_short_name() {
    let dir = TempDir::new().unwrap();
    let existing = dir.path().join("Report for 2026.pdf");
    fs::write(&existing, b"precious").unwrap();
    let Some(alias) = short_name(&existing) else {
        assert!(
            std::env::var_os("CI").is_none(),
            "the volume made no 8.3 short name, so this test proves nothing here"
        );
        eprintln!("skipped: the volume makes no 8.3 names");
        return;
    };
    assert_eq!(
        fs::read(dir.path().join(&alias)).unwrap(),
        b"precious",
        "the fixture must alias: {alias} reaches Report for 2026.pdf"
    );

    let mut cfg = SyncConfig::new(
        dir.path().to_path_buf(),
        "https://api.beebeeb.io".into(),
        "tok_test".into(),
    );
    cfg.sync_mode = crate::config::SyncMode::Full;
    let mut engine = SyncEngine::new(cfg);
    let rel = PathBuf::from(&alias);
    engine.state.files.insert(rel.clone(), FileState::Synced);

    // `list_remote_files` is the placeholder empty snapshot, and the listing
    // shows only the long name: the row is a completed remote delete.
    let ops = engine.sync_once().unwrap();
    assert!(
        ops.contains(&SyncOp::DeleteLocal(rel.clone())),
        "the fixture must reach the delete: {ops:?}"
    );
    assert_eq!(
        fs::read(&existing).ok().as_deref(),
        Some(&b"precious"[..]),
        "Report for 2026.pdf must survive a delete of {alias}"
    );
    // The row's own file is not on disk, so the row is settled and dropped.
    assert!(!engine.state.files.contains_key(&rel), "the stale row must be cleared");
}
