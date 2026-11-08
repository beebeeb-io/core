//! Windows tests for the trusted publisher (#74 round 8). Each check first
//! shows that what it looks for is there to see (the temp file is listed
//! before the drop; the junction does redirect an ordinary path walk), so a
//! pass is never a check that could not fail.

use super::*;
use std::io::{Read as _, Write as _};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

/// A private scratch directory under the system temp dir, removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(label: &str) -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after 1970")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("beebeeb-publish-{label}-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create scratch dir");
        Self(dir)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn entries(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .expect("list directory")
        .map(|entry| entry.expect("entry").file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

/// A directory junction at `link` pointing at `target`. `mklink /J` needs no
/// privilege, unlike a symbolic link.
fn junction(link: &Path, target: &Path) {
    let status = Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(link)
        .arg(target)
        .stdout(Stdio::null())
        .status()
        .expect("run mklink");
    assert!(
        status.success(),
        "mklink /J {} {} failed",
        link.display(),
        target.display()
    );
}

#[test]
fn a_junction_in_place_of_the_directory_is_refused() {
    let scratch = Scratch::new("junction");
    let real = scratch.path().join("real");
    std::fs::create_dir(&real).unwrap();
    let link = scratch.path().join("link");
    junction(&link, &real);
    // The fixture really redirects: an ordinary path walk through it lands in `real`.
    std::fs::write(link.join("through.txt"), b"x").unwrap();
    assert_eq!(entries(&real), ["through.txt"]);
    std::fs::remove_file(real.join("through.txt")).unwrap();

    let error = TrustedDirectory::open(&link).expect_err("a junction must be refused");
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput, "{error}");
    assert!(entries(&real).is_empty());
    // The directory it points at is a plain directory, and is accepted.
    TrustedDirectory::open(&real)
        .unwrap()
        .publish_bytes("ok.txt", Rules::Host, b"ok")
        .unwrap();
    assert_eq!(entries(&real), ["ok.txt"]);
}

#[test]
fn a_directory_symlink_in_place_of_the_directory_is_refused() {
    let scratch = Scratch::new("symlink");
    let real = scratch.path().join("real");
    std::fs::create_dir(&real).unwrap();
    let link = scratch.path().join("link");
    match std::os::windows::fs::symlink_dir(&real, &link) {
        Ok(()) => {}
        // ERROR_PRIVILEGE_NOT_HELD: a symbolic link needs Developer Mode or an
        // elevated prompt. CI has it; a developer machine may not.
        Err(error) if error.raw_os_error() == Some(1314) && std::env::var_os("CI").is_none() => {
            eprintln!("skipped: {error}");
            return;
        }
        Err(error) => panic!("symlink_dir: {error}"),
    }
    std::fs::write(link.join("through.txt"), b"x").unwrap();
    assert_eq!(entries(&real), ["through.txt"]);

    let error = TrustedDirectory::open(&link).expect_err("a directory symlink must be refused");
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput, "{error}");
}

#[test]
fn a_file_in_place_of_the_directory_is_refused() {
    let scratch = Scratch::new("file");
    let file = scratch.path().join("not-a-dir");
    std::fs::write(&file, b"x").unwrap();
    let error = TrustedDirectory::open(&file).expect_err("a file must be refused");
    assert_eq!(error.kind(), io::ErrorKind::NotADirectory, "{error}");
}

#[test]
fn an_uncommitted_publish_leaves_no_temp_file() {
    let scratch = Scratch::new("uncommitted");
    let directory = TrustedDirectory::open(scratch.path()).unwrap();

    // Dropped while the writer is still open: a failed download drops the
    // pending publication before the sink.
    let (pending, mut file) = directory.begin_publish("out.bin", Rules::Host).unwrap();
    file.write_all(b"partial plaintext").unwrap();
    let listed = entries(scratch.path());
    assert_eq!(listed.len(), 1, "{listed:?}");
    assert!(listed[0].starts_with(".bbtmp-"), "{listed:?}");
    drop(pending);
    drop(file);
    assert!(entries(scratch.path()).is_empty(), "{:?}", entries(scratch.path()));

    // Dropped after the writer closed.
    let (pending, mut file) = directory.begin_publish("out.bin", Rules::Host).unwrap();
    file.write_all(b"partial plaintext").unwrap();
    drop(file);
    assert_eq!(entries(scratch.path()).len(), 1);
    drop(pending);
    assert!(entries(scratch.path()).is_empty(), "{:?}", entries(scratch.path()));
}

#[test]
fn a_failed_commit_leaves_no_temp_file_and_never_replaces_a_directory() {
    let scratch = Scratch::new("failed-commit");
    std::fs::create_dir(scratch.path().join("taken")).unwrap();
    std::fs::write(scratch.path().join("taken").join("inside.txt"), b"keep").unwrap();
    let directory = TrustedDirectory::open(scratch.path()).unwrap();
    let (pending, mut file) = directory.begin_publish("taken", Rules::Host).unwrap();
    file.write_all(b"new").unwrap();
    drop(file);
    assert_eq!(entries(scratch.path()).len(), 2);
    pending.commit().expect_err("a directory is never replaced");
    assert_eq!(entries(scratch.path()), ["taken"]);
    assert_eq!(
        std::fs::read(scratch.path().join("taken").join("inside.txt")).unwrap(),
        b"keep"
    );
}

#[test]
fn a_committed_publish_replaces_the_target_atomically() {
    let scratch = Scratch::new("committed");
    let target = scratch.path().join("doc.txt");
    std::fs::write(&target, b"old contents").unwrap();
    // A reader holding the old file open (std shares delete) must not block it.
    let mut reader = File::open(&target).unwrap();
    let directory = TrustedDirectory::open(scratch.path()).unwrap();

    let (pending, mut file) = directory.begin_publish("doc.txt", Rules::Host).unwrap();
    file.write_all(b"new").unwrap();
    drop(file);
    // Until the commit, the target is the old file, whole; the new bytes are
    // only in the temp sibling.
    assert_eq!(std::fs::read(&target).unwrap(), b"old contents");
    assert_eq!(entries(scratch.path()).len(), 2);

    pending.commit().unwrap();
    assert_eq!(std::fs::read(&target).unwrap(), b"new");
    assert_eq!(entries(scratch.path()), ["doc.txt"]);
    // The reader still has the file it opened.
    let mut old = Vec::new();
    reader.read_to_end(&mut old).unwrap();
    assert_eq!(old, b"old contents");
}

#[test]
fn the_publish_stays_in_the_opened_directory_when_its_path_moves() {
    let scratch = Scratch::new("moved");
    let original = scratch.path().join("cache");
    std::fs::create_dir(&original).unwrap();
    let directory = TrustedDirectory::open(&original).unwrap();
    let moved = scratch.path().join("moved");
    std::fs::rename(&original, &moved).unwrap();
    // Something else now sits at the old path.
    std::fs::create_dir(&original).unwrap();

    directory.publish_bytes("thumb.bin", Rules::Host, b"thumb").unwrap();
    assert_eq!(entries(&moved), ["thumb.bin"]);
    assert!(entries(&original).is_empty());
    assert_eq!(std::fs::read(moved.join("thumb.bin")).unwrap(), b"thumb");
}

#[test]
fn windows_names_are_checked_before_anything_is_created() {
    let scratch = Scratch::new("names");
    let directory = TrustedDirectory::open(scratch.path()).unwrap();
    for name in ["a:stream", "CON", "trailing.", "a\\b", "..", ""] {
        let error = directory.begin_publish(name, Rules::Host).expect_err(name);
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput, "{name:?}: {error}");
    }
    assert!(entries(scratch.path()).is_empty());
}
