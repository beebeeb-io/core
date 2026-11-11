//! Windows tests for [`TempSibling`]'s publish (task 2404). Each first shows
//! that its fixture aliases (an ordinary read of the short name reaches the
//! other file), so a pass is never a check that could not fail. A volume that
//! makes no 8.3 names skips with the reason printed; with `CI` set it fails.

use super::*;
use std::io::Write as _;
use std::time::{SystemTime, UNIX_EPOCH};

const PRECIOUS: &[u8] = b"precious";

/// A private scratch directory under the system temp dir, removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(label: &str) -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after 1970")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("beebeeb-publish-{label}-{}-{nanos}", std::process::id()));
        fs::create_dir_all(&dir).expect("create scratch dir");
        Self(dir)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn entries(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .expect("list directory")
        .map(|entry| entry.expect("entry").file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

/// The 8.3 short name the volume gave `path`'s last component, or `None`
/// after printing why (with `CI` set, a missing short name fails instead).
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
    if last != long {
        return Some(last);
    }
    assert!(
        std::env::var_os("CI").is_none(),
        "{}: the volume made no 8.3 short name, so this test proves nothing here",
        path.display()
    );
    eprintln!("skipped: {} has no 8.3 short name", path.display());
    None
}

/// `dir/Report for 2026.pdf` holding [`PRECIOUS`], and its short name, after
/// showing that a read through the short name reaches it.
fn aliased(dir: &Path) -> Option<String> {
    fs::write(dir.join("Report for 2026.pdf"), PRECIOUS).unwrap();
    let alias = short_name(&dir.join("Report for 2026.pdf"))?;
    assert_eq!(fs::read(dir.join(&alias)).unwrap(), PRECIOUS, "the fixture must alias");
    Some(alias)
}

/// The hard-link publish fails on a name that reaches another file through
/// its short name; that file keeps its contents.
#[test]
fn publishing_a_new_name_never_replaces_what_a_short_name_reaches() {
    let scratch = Scratch::new("link");
    let dir = &scratch.0;
    let Some(alias) = aliased(dir) else {
        return;
    };
    fs::write(dir.join("t1"), b"attacker").unwrap();

    let error = publish_new(&dir.join("t1"), &dir.join(&alias)).unwrap_err();

    assert_eq!(fs::read(dir.join("Report for 2026.pdf")).unwrap(), PRECIOUS);
    assert_eq!(error.kind(), io::ErrorKind::AlreadyExists, "{alias}: {error}");
    assert_eq!(entries(dir), ["Report for 2026.pdf", "t1"]);
}

/// The publish for a volume without hard links fails the same way.
#[test]
fn publishing_by_exclusive_create_never_replaces_what_a_short_name_reaches() {
    let scratch = Scratch::new("exclusive");
    let dir = &scratch.0;
    let Some(alias) = aliased(dir) else {
        return;
    };
    fs::write(dir.join("t1"), b"attacker").unwrap();

    let error = publish_by_exclusive_create(&dir.join("t1"), &dir.join(&alias)).unwrap_err();

    assert_eq!(fs::read(dir.join("Report for 2026.pdf")).unwrap(), PRECIOUS);
    assert_eq!(error.kind(), io::ErrorKind::AlreadyExists, "{alias}: {error}");
    assert_eq!(entries(dir), ["Report for 2026.pdf", "t1"]);
}

/// An entry that appears while the file is written, and that the output name
/// reaches through its short name, is never replaced: the publish fails and
/// only the temp goes.
#[test]
fn an_entry_that_appears_during_the_write_is_never_replaced() {
    let scratch = Scratch::new("appears");
    let dir = &scratch.0;
    // The first `REPORT*.pdf` in an empty folder gets `REPORT~1.PDF`; checked
    // below, once the file exists.
    let output = dir.join("REPORT~1.PDF");
    let (temp, mut file) = TempSibling::create(&output).unwrap();
    file.write_all(b"attacker").unwrap();
    drop(file);
    let Some(alias) = aliased(dir) else {
        return;
    };
    assert_eq!(alias, "REPORT~1.PDF", "the fixture must alias the output name");

    let error = temp.publish().unwrap_err();

    assert_eq!(fs::read(dir.join("Report for 2026.pdf")).unwrap(), PRECIOUS);
    assert_eq!(error.kind(), io::ErrorKind::AlreadyExists, "{error}");
    assert!(error.to_string().contains("8.3"), "not the short-name refusal: {error}");
    assert_eq!(entries(dir), ["Report for 2026.pdf"], "only the temp went");
}
