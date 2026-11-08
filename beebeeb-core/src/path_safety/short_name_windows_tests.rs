//! Windows tests for [`short_name_alias`] (task 2404). Each first shows that
//! its fixture aliases (an ordinary path through the short name reaches the
//! other entry), so a pass is never a check that could not fail. A volume that
//! makes no 8.3 names skips with the reason printed; with `CI` set it fails.

use super::*;
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
        let dir = std::env::temp_dir().join(format!("beebeeb-alias-{label}-{}-{nanos}", std::process::id()));
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

fn conflict(requested: &str, existing: Option<&str>) -> Option<ShortNameAlias> {
    Some(ShortNameAlias {
        requested: requested.to_owned(),
        existing: existing.map(str::to_owned),
    })
}

#[test]
fn the_check_names_the_entry_a_short_name_reaches() {
    let scratch = Scratch::new("file");
    let dir = scratch.path();
    std::fs::write(dir.join("Report for 2026.pdf"), b"precious").unwrap();
    let Some(alias) = short_name(&dir.join("Report for 2026.pdf")) else {
        return;
    };
    assert_eq!(
        std::fs::read(dir.join(&alias)).unwrap(),
        b"precious",
        "the fixture must alias"
    );

    assert_eq!(
        short_name_alias(dir, Path::new(&alias)).unwrap(),
        conflict(&alias, Some("Report for 2026.pdf"))
    );
    for own in [
        "Report for 2026.pdf",
        "report FOR 2026.PDF",
        "new.pdf",
        "new folder/new.pdf",
    ] {
        assert_eq!(short_name_alias(dir, Path::new(own)).unwrap(), None, "{own}");
    }
}

#[test]
fn a_short_name_in_any_segment_is_a_conflict() {
    let scratch = Scratch::new("segments");
    let base = scratch.path();
    let folder = base.join("Photos 2026");
    std::fs::create_dir(&folder).unwrap();
    std::fs::write(folder.join("Holiday in Lisbon.jpg"), b"precious").unwrap();
    let (Some(folder_alias), Some(file_alias)) =
        (short_name(&folder), short_name(&folder.join("Holiday in Lisbon.jpg")))
    else {
        return;
    };
    assert_eq!(
        std::fs::read(base.join(&folder_alias).join(&file_alias)).unwrap(),
        b"precious",
        "the fixture must alias"
    );

    let through_folder = format!("{folder_alias}/Holiday in Lisbon.jpg");
    assert_eq!(
        short_name_alias(base, Path::new(&through_folder)).unwrap(),
        conflict(&folder_alias, Some("Photos 2026"))
    );
    let to_file = format!("Photos 2026/{file_alias}");
    assert_eq!(
        short_name_alias(base, Path::new(&to_file)).unwrap(),
        conflict(&file_alias, Some("Holiday in Lisbon.jpg"))
    );
    assert_eq!(
        short_name_alias(base, Path::new("Photos 2026/Holiday in Lisbon.jpg")).unwrap(),
        None
    );
}

/// A link is opened through by `canonicalize`, so it is judged by the
/// directory listing: its own long name is fine, its short name is not. A
/// directory junction needs no privilege, unlike a symbolic link.
#[test]
fn a_link_is_judged_by_its_own_long_name() {
    let scratch = Scratch::new("link");
    let base = scratch.path();
    let target = base.join("target");
    std::fs::create_dir(&target).unwrap();
    std::fs::write(target.join("inside.txt"), b"precious").unwrap();
    let link = base.join("Photos link 2026");
    let made = Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(&link)
        .arg(&target)
        .stdout(Stdio::null())
        .status()
        .expect("run mklink");
    assert!(made.success(), "mklink /J failed");
    assert!(
        std::fs::symlink_metadata(&link).unwrap().file_type().is_symlink(),
        "std reports a junction as a link"
    );
    let Some(alias) = short_name(&link) else {
        return;
    };
    assert_eq!(
        std::fs::read(base.join(&alias).join("inside.txt")).unwrap(),
        b"precious",
        "the fixture must alias: {alias} reaches the junction"
    );

    assert_eq!(
        short_name_alias(base, Path::new(&alias)).unwrap(),
        conflict(&alias, None)
    );
    assert_eq!(short_name_alias(base, Path::new("photos LINK 2026")).unwrap(), None);
}

/// An 8.3-shaped long name that the handle reports as its own is confirmed by
/// the listing, which finds it: the entry's own name, in any case, is fine.
#[test]
fn an_eight_three_shaped_own_name_is_confirmed_by_the_listing() {
    let scratch = Scratch::new("shape");
    let dir = scratch.path();
    for name in ["IMG_0001.JPG", "a.txt", "README"] {
        std::fs::write(dir.join(name), b"own").unwrap();
    }
    for own in ["IMG_0001.JPG", "img_0001.jpg", "a.txt", "A.TXT", "README", "readme"] {
        assert_eq!(short_name_alias(dir, Path::new(own)).unwrap(), None, "{own}");
    }
}
