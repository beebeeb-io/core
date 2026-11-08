//! Windows: a download never writes through another file's 8.3 short name
//! (task 2404). Each test first shows that its fixture really aliases (an
//! ordinary read of the short name reaches the other file); a volume that makes
//! no 8.3 names skips with the reason printed, and fails with `CI` set. Only
//! the v0.2.6 API is used, so the file runs unchanged at the parent (red).

use crate::download::decrypt_downloaded_bytes;
use beebeeb_core::chunk_stream::ExpectedChunkFormat::Unrecorded;
use beebeeb_core::encrypt::encrypt_chunk_raw;
use beebeeb_core::kdf::FileKey;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const PRECIOUS: &[u8] = b"precious";
const WRITTEN: &[u8] = b"attacker";

/// A private scratch directory under the system temp dir (on the system
/// volume, which makes 8.3 names by default), removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(label: &str) -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after 1970")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "beebeeb-upload-short-name-{label}-{}-{nanos}",
            std::process::id()
        ));
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

/// A download to `dir/<to_output(short name of existing)>` must refuse with
/// the short-name conflict and leave `existing` untouched.
fn assert_refused(label: &str, existing: &str, to_output: impl Fn(&str) -> String) {
    let dir = Scratch::new(label);
    let existing_path = dir.path().join(existing);
    std::fs::write(&existing_path, PRECIOUS).expect("write the existing file");
    let Some(alias) = short_name(&existing_path) else {
        assert!(
            std::env::var_os("CI").is_none(),
            "{existing}: the volume made no 8.3 short name, so this test proves nothing here"
        );
        eprintln!("skipped: {existing} has no 8.3 short name (8.3 name generation is off on this volume)");
        return;
    };
    assert_eq!(
        std::fs::read(dir.path().join(&alias)).expect("read through the short name"),
        PRECIOUS,
        "the fixture must alias: {alias} reaches {existing}"
    );
    let key = FileKey::from_bytes([7u8; 32]);
    let body = encrypt_chunk_raw(&key, WRITTEN).expect("encrypt");
    let output = dir.path().join(to_output(&alias));

    let result = decrypt_downloaded_bytes(
        &key,
        "short-name-test",
        Unrecorded,
        &body,
        1,
        output.to_str().expect("UTF-8 path"),
        None,
    );
    assert_eq!(
        std::fs::read(&existing_path).ok().as_deref(),
        Some(PRECIOUS),
        "{existing} must stay untouched by a download to {}",
        output.display()
    );
    assert_eq!(entries(dir.path()), [existing], "no entry may appear, move or go");
    let error = result
        .map(drop)
        .expect_err("a short name of another file is a name conflict");
    assert!(error.to_string().contains("8.3"), "not the short-name refusal: {error}");
}

#[test]
fn a_download_never_replaces_another_file_through_its_short_name() {
    assert_refused("replace", "Report for 2026.pdf", str::to_owned);
}

/// The download's temp sibling `{output}.tmp` reaches another file through its
/// short name: the temp name is the download's own choice, so a taken one is
/// skipped. The download succeeds through a fresh temp name and never opens
/// that file.
#[test]
fn a_download_never_truncates_another_file_through_its_tmp_name() {
    let dir = Scratch::new("tmp");
    let existing_path = dir.path().join("Report for 2026.tmp");
    std::fs::write(&existing_path, PRECIOUS).expect("write the existing file");
    let Some(alias) = short_name(&existing_path) else {
        assert!(
            std::env::var_os("CI").is_none(),
            "the volume made no 8.3 short name, so this test proves nothing here"
        );
        eprintln!("skipped: the volume makes no 8.3 names");
        return;
    };
    // `REPORT~1.TMP` gives the output `REPORT~1`, whose temp is `REPORT~1.tmp`.
    let output_name = alias
        .strip_suffix(".TMP")
        .unwrap_or_else(|| panic!("{alias}: a short name keeps the TMP extension"))
        .to_owned();
    assert_eq!(
        std::fs::read(dir.path().join(format!("{output_name}.tmp"))).expect("read through the temp name"),
        PRECIOUS,
        "the fixture must alias: {output_name}.tmp reaches Report for 2026.tmp"
    );
    let key = FileKey::from_bytes([7u8; 32]);
    let body = encrypt_chunk_raw(&key, WRITTEN).expect("encrypt");
    let output = dir.path().join(&output_name);

    let result = decrypt_downloaded_bytes(
        &key,
        "short-name-test",
        Unrecorded,
        &body,
        1,
        output.to_str().expect("UTF-8 path"),
        None,
    );
    assert_eq!(
        std::fs::read(&existing_path).ok().as_deref(),
        Some(PRECIOUS),
        "Report for 2026.tmp must stay untouched by a download to {output_name}"
    );
    result.map(drop).expect("the output name itself is free");
    assert_eq!(std::fs::read(&output).unwrap(), WRITTEN);
    let mut expected = vec!["Report for 2026.tmp".to_owned(), output_name];
    expected.sort();
    assert_eq!(entries(dir.path()), expected, "no temp file may remain");
}

/// The control: the existing file's own long name in another case is that
/// file, and a download still replaces it.
#[test]
fn a_download_to_the_existing_files_own_name_still_replaces_it() {
    let dir = Scratch::new("own");
    std::fs::write(dir.path().join("Report for 2026.pdf"), PRECIOUS).expect("write the existing file");
    let key = FileKey::from_bytes([7u8; 32]);
    let body = encrypt_chunk_raw(&key, WRITTEN).expect("encrypt");
    let output = dir.path().join("report FOR 2026.PDF");
    decrypt_downloaded_bytes(
        &key,
        "short-name-test",
        Unrecorded,
        &body,
        1,
        output.to_str().expect("UTF-8 path"),
        None,
    )
    .expect("the file's own name");
    assert_eq!(entries(dir.path()).len(), 1);
    assert_eq!(std::fs::read(dir.path().join("Report for 2026.pdf")).unwrap(), WRITTEN);
}
