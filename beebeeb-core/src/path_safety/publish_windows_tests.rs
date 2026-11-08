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

/// Whether a symbolic link could be made. ERROR_PRIVILEGE_NOT_HELD: a link
/// needs Developer Mode or an elevated prompt. CI has it (a skip there
/// fails); a developer machine may not.
fn linked(made: io::Result<()>) -> bool {
    match made {
        Ok(()) => true,
        Err(error) if error.raw_os_error() == Some(1314) && std::env::var_os("CI").is_none() => {
            eprintln!("skipped: {error}");
            false
        }
        Err(error) => panic!("symlink: {error}"),
    }
}

#[test]
fn a_directory_symlink_in_place_of_the_directory_is_refused() {
    let scratch = Scratch::new("symlink");
    let real = scratch.path().join("real");
    std::fs::create_dir(&real).unwrap();
    let link = scratch.path().join("link");
    if !linked(std::os::windows::fs::symlink_dir(&real, &link)) {
        return;
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

#[test]
fn a_file_symlink_at_the_final_name_is_replaced_without_following_it() {
    let scratch = Scratch::new("final-symlink");
    let outside = Scratch::new("final-symlink-outside");
    let victim = outside.path().join("victim.txt");
    std::fs::write(&victim, b"keep").unwrap();
    let target = scratch.path().join("out.txt");
    if !linked(std::os::windows::fs::symlink_file(&victim, &target)) {
        return;
    }
    // The fixture really redirects: an ordinary read through it reaches `victim`.
    assert_eq!(std::fs::read(&target).unwrap(), b"keep");

    TrustedDirectory::open(scratch.path())
        .unwrap()
        .publish_bytes("out.txt", Rules::Host, b"new")
        .unwrap();
    assert_eq!(std::fs::read(&victim).unwrap(), b"keep");
    assert!(!std::fs::symlink_metadata(&target).unwrap().file_type().is_symlink());
    assert_eq!(std::fs::read(&target).unwrap(), b"new");
    assert_eq!(entries(scratch.path()), ["out.txt"]);
}

#[test]
fn a_255_byte_name_publishes_and_a_longer_one_is_refused() {
    let scratch = Scratch::new("long-name");
    let directory = TrustedDirectory::open(scratch.path()).unwrap();
    let longest = "a".repeat(MAX_PUBLISH_COMPONENT_BYTES);
    directory.publish_bytes(&longest, Rules::Host, b"x").unwrap();
    assert_eq!(entries(scratch.path()), std::slice::from_ref(&longest));
    let error = directory
        .begin_publish(&format!("{longest}a"), Rules::Host)
        .expect_err("256 bytes");
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput, "{error}");
    assert_eq!(entries(scratch.path()), std::slice::from_ref(&longest));
}

#[test]
fn the_temp_create_never_opens_or_follows_a_planted_link() {
    use std::os::windows::fs::MetadataExt as _;
    let scratch = Scratch::new("planted");
    let elsewhere = Scratch::new("planted-elsewhere");
    let planted = scratch.path().join(".bbtmp-planted");
    junction(&planted, elsewhere.path());
    std::fs::write(scratch.path().join(".bbtmp-taken"), b"keep").unwrap();
    let directory = TrustedDirectory::open(scratch.path()).unwrap();

    // NTFS answers a create over a directory junction with "access denied"
    // (windows-latest), not "exists": either way nothing is opened or followed.
    let error = create_in(&directory.directory, ".bbtmp-planted").expect_err("an existing name is never opened");
    assert!(
        matches!(
            error.kind(),
            io::ErrorKind::AlreadyExists | io::ErrorKind::PermissionDenied
        ),
        "{error}"
    );
    assert!(entries(elsewhere.path()).is_empty());
    let attributes = std::fs::symlink_metadata(&planted).unwrap().file_attributes();
    assert_ne!(
        attributes & FILE_ATTRIBUTE_REPARSE_POINT,
        0,
        "the junction is still there"
    );
    // A plain file at the name: refused, and left as it was.
    let error = create_in(&directory.directory, ".bbtmp-taken").expect_err("an existing file is never opened");
    assert!(
        matches!(
            error.kind(),
            io::ErrorKind::AlreadyExists | io::ErrorKind::PermissionDenied
        ),
        "{error}"
    );
    assert_eq!(std::fs::read(scratch.path().join(".bbtmp-taken")).unwrap(), b"keep");
    // A fresh name is created, as a plain file.
    drop(create_in(&directory.directory, ".bbtmp-fresh").unwrap());
    assert!(
        std::fs::symlink_metadata(scratch.path().join(".bbtmp-fresh"))
            .unwrap()
            .is_file()
    );
}

#[test]
fn a_commit_blocked_by_an_open_target_leaves_no_temp_file() {
    let scratch = Scratch::new("blocked");
    let target = scratch.path().join("doc.txt");
    std::fs::write(&target, b"old contents").unwrap();
    // Another program holds the file open without FILE_SHARE_DELETE.
    let holder = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .open(&target)
        .unwrap();
    let directory = TrustedDirectory::open(scratch.path()).unwrap();
    let (pending, mut file) = directory.begin_publish("doc.txt", Rules::Host).unwrap();
    file.write_all(b"new").unwrap();
    drop(file);
    assert_eq!(entries(scratch.path()).len(), 2);

    pending.commit().expect_err("the open file cannot be replaced");
    assert_eq!(entries(scratch.path()), ["doc.txt"]);
    drop(holder);
    assert_eq!(std::fs::read(&target).unwrap(), b"old contents");
}

/// The 8.3 short name of `path`'s last component, if the volume gave it one.
fn short_name(path: &Path) -> Option<String> {
    use std::os::windows::ffi::OsStrExt as _;
    use windows_sys::Win32::Storage::FileSystem::GetShortPathNameW;
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain([0]).collect();
    let mut buffer = vec![0u16; 1024];
    // SAFETY: `wide` is NUL-terminated; `buffer` holds its stated length.
    let written = unsafe { GetShortPathNameW(wide.as_ptr(), buffer.as_mut_ptr(), buffer.len() as u32) };
    assert!(written != 0 && (written as usize) < buffer.len(), "GetShortPathNameW");
    let short = String::from_utf16_lossy(&buffer[..written as usize]);
    let last = short.rsplit('\\').next().unwrap_or(&short).to_owned();
    let long = path.file_name().unwrap().to_string_lossy();
    (last != long).then_some(last)
}

#[test]
fn a_short_name_alias_never_replaces_another_file() {
    let scratch = Scratch::new("short-name");
    let original = scratch.path().join("Report final.pdf");
    std::fs::write(&original, b"precious").unwrap();
    let Some(alias) = short_name(&original) else {
        // The CI runner's C: makes 8.3 names (its TEMP path holds one).
        assert!(std::env::var_os("CI").is_none(), "no 8.3 name on this volume");
        eprintln!("skipped: the volume makes no 8.3 names");
        return;
    };
    // The fixture really aliases: an ordinary read of the short name reaches the file.
    assert_eq!(std::fs::read(scratch.path().join(&alias)).unwrap(), b"precious");
    let directory = TrustedDirectory::open(scratch.path()).unwrap();

    let error = directory
        .publish_bytes(&alias, Rules::Host, b"attacker")
        .expect_err("a short-name alias must not replace another file");
    assert_eq!(error.kind(), io::ErrorKind::AlreadyExists, "{alias}: {error}");
    assert_eq!(std::fs::read(&original).unwrap(), b"precious");
    assert_eq!(entries(scratch.path()), ["Report final.pdf"]);

    // The same long name in another case is the same file, replaced as before.
    directory
        .publish_bytes("report FINAL.pdf", Rules::Host, b"new")
        .unwrap();
    assert_eq!(std::fs::read(&original).unwrap(), b"new");
    assert_eq!(entries(scratch.path()).len(), 1);
}
