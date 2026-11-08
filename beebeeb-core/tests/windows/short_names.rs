//! Windows: a create, truncate or replace by name never touches a DIFFERENT
//! existing entry that the name reaches through its 8.3 short name (task 2404).
//!
//! Each test first shows that its fixture really aliases: the volume gave the
//! existing entry a short name, and an ordinary read of that short name reaches
//! the entry. Only then does it ask core to write by that name, so a pass is
//! never a check that could not fail. A volume that makes no 8.3 names skips
//! with the reason printed; with `CI` set it fails instead.
//!
//! The tests use only the v0.2.6 API, so this file runs unchanged at the parent
//! (red: the write reaches the other file) and at the fix (green).

use beebeeb_core::chunk_stream::ExpectedChunkFormat::Unrecorded;
use beebeeb_core::encrypt::{decrypt_chunks_to_file, decrypt_contiguous_to_file, encrypt_chunk};
use beebeeb_core::file_encrypt;
use beebeeb_core::kdf::{FileKey, MasterKey, derive_file_key};
use beebeeb_core::path_safety::{Rules, default_output_path, safe_child, safe_rel_join};
use beebeeb_types::ChunkProfile;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

const PRECIOUS: &[u8] = b"precious";
const WRITTEN: &[u8] = b"attacker";
const FILE_ID: &str = "short-name-test";

/// A private scratch directory under the system temp dir (on the system
/// volume, which makes 8.3 names by default), removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(label: &str) -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after 1970")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("beebeeb-short-name-{label}-{}-{nanos}", std::process::id()));
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

/// The current directory, restored on drop (declare it after the `Scratch` it
/// enters, so it is restored before the scratch directory is removed).
struct CurrentDir(PathBuf);

impl CurrentDir {
    fn enter(dir: &Path) -> Self {
        let previous = std::env::current_dir().expect("current dir");
        std::env::set_current_dir(dir).expect("enter scratch dir");
        Self(previous)
    }
}

impl Drop for CurrentDir {
    fn drop(&mut self) {
        let _ = std::env::set_current_dir(&self.0);
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

/// `path`'s short name, or `None` after printing why this volume cannot run the
/// test. With `CI` set a missing short name is a failure, never a skip.
fn alias_or_skip(path: &Path) -> Option<String> {
    let alias = short_name(path);
    if alias.is_none() {
        assert!(
            std::env::var_os("CI").is_none(),
            "{}: the volume made no 8.3 short name, so this test proves nothing here",
            path.display()
        );
        eprintln!(
            "skipped: {} has no 8.3 short name (8.3 name generation is off on this volume)",
            path.display()
        );
    }
    alias
}

/// Create `dir/long` holding [`PRECIOUS`] and return its short name, after
/// showing that an ordinary read of the short name reaches `long`.
fn aliased_file(dir: &Path, long: &str) -> Option<String> {
    std::fs::write(dir.join(long), PRECIOUS).expect("write the existing file");
    let alias = alias_or_skip(&dir.join(long))?;
    assert_eq!(
        std::fs::read(dir.join(&alias)).expect("read through the short name"),
        PRECIOUS,
        "the fixture must alias: {alias} reaches {long}"
    );
    Some(alias)
}

/// The output name whose `.tmp` sibling is the short name `alias` of a
/// `*.tmp` file: `REPORT~1.TMP` gives `REPORT~1`.
fn stem_of_tmp_alias(alias: &str) -> String {
    alias
        .strip_suffix(".TMP")
        .unwrap_or_else(|| panic!("{alias}: a short name keeps the TMP extension"))
        .to_owned()
}

fn file_key() -> FileKey {
    FileKey::from_bytes([7u8; 32])
}

fn master_key() -> MasterKey {
    MasterKey::from_bytes([9u8; 32])
}

/// `write(output)` writes a decrypted file at `output`, where `existing` holds
/// [`PRECIOUS`] and `to_output` turns its short name into the output name. The
/// write must refuse with the short-name conflict and touch nothing.
fn assert_refused(
    label: &str,
    existing: &str,
    to_output: impl Fn(&str) -> String,
    write: impl Fn(&Path) -> Result<(), String>,
) {
    let scratch = Scratch::new(label);
    let dir = scratch.path();
    let Some(alias) = aliased_file(dir, existing) else {
        return;
    };
    let output = dir.join(to_output(&alias));
    let result = write(&output);
    assert_eq!(
        std::fs::read(dir.join(existing)).ok().as_deref(),
        Some(PRECIOUS),
        "{label}: {existing} must stay untouched by a write to {}",
        output.display()
    );
    assert_eq!(entries(dir), [existing], "{label}: no entry may appear, move or go");
    let error = result.expect_err(&format!("{label}: a short name of another file is a name conflict"));
    assert!(error.contains("8.3"), "{label}: not the short-name refusal: {error}");
}

fn contiguous_to(output: &Path) -> Result<(), String> {
    let key = file_key();
    let blob = encrypt_chunk(&key, WRITTEN).map_err(|e| e.to_string())?;
    let body = [blob.nonce, blob.ciphertext].concat();
    let path = output.to_str().expect("UTF-8 path");
    decrypt_contiguous_to_file(&key, FILE_ID, Unrecorded, &body, WRITTEN.len() as u64, path)
        .map(drop)
        .map_err(|e| e.to_string())
}

fn chunks_to(output: &Path) -> Result<(), String> {
    let key = file_key();
    let blob = encrypt_chunk(&key, WRITTEN).map_err(|e| e.to_string())?;
    let path = output.to_str().expect("UTF-8 path");
    decrypt_chunks_to_file(&key, FILE_ID, Unrecorded, vec![(blob.nonce, blob.ciphertext)], path)
        .map(drop)
        .map_err(|e| e.to_string())
}

fn chunk_files_to(output: &Path) -> Result<(), String> {
    let master = master_key();
    let file_key = derive_file_key(&master, FILE_ID.as_bytes());
    let staging = Scratch::new("staging");
    let chunk = staging.path().join("0.enc");
    let blob = encrypt_chunk(&file_key, WRITTEN).map_err(|e| e.to_string())?;
    std::fs::write(&chunk, [blob.nonce, blob.ciphertext].concat()).expect("write chunk file");
    file_encrypt::decrypt_chunks_to_file(&master, FILE_ID, Unrecorded, &[chunk.as_path()], output, None)
        .map(drop)
        .map_err(|e| e.to_string())
}

#[test]
fn safe_child_never_hands_out_another_files_short_name() {
    let scratch = Scratch::new("child");
    let dir = scratch.path();
    let Some(alias) = aliased_file(dir, "Report for 2026.pdf") else {
        return;
    };
    for rules in [Rules::Host, Rules::Portable] {
        let error = safe_child(dir, &alias, rules).expect_err("a short name of another file is a name conflict");
        assert!(error.contains("8.3"), "{alias}: not the short-name refusal: {error}");
    }
    // The entry's own long name, in any case, is that entry; a new name is free.
    for own in ["Report for 2026.pdf", "report FOR 2026.PDF", "new.pdf"] {
        safe_child(dir, own, Rules::Host).unwrap_or_else(|error| panic!("{own}: {error}"));
    }
    assert_eq!(entries(dir), ["Report for 2026.pdf"]);
}

#[test]
fn safe_rel_join_never_walks_through_another_entrys_short_name() {
    let scratch = Scratch::new("rel");
    let base = scratch.path();
    let folder = base.join("Photos 2026");
    std::fs::create_dir(&folder).expect("create folder");
    let Some(file_alias) = aliased_file(&folder, "Holiday in Lisbon.jpg") else {
        return;
    };
    let Some(folder_alias) = alias_or_skip(&folder) else {
        return;
    };
    assert_eq!(
        std::fs::read(base.join(&folder_alias).join("Holiday in Lisbon.jpg"))
            .expect("read through the folder's short name"),
        PRECIOUS,
        "the fixture must alias: {folder_alias} reaches Photos 2026"
    );
    for rel in [
        format!("{folder_alias}/Holiday in Lisbon.jpg"),
        format!("{folder_alias}/new.jpg"),
        format!("Photos 2026/{file_alias}"),
        folder_alias.clone(),
    ] {
        let error =
            safe_rel_join(base, &rel, Rules::Host).expect_err(&format!("{rel}: a short name is a name conflict"));
        assert!(error.contains("8.3"), "{rel}: not the short-name refusal: {error}");
    }
    for own in [
        "Photos 2026/Holiday in Lisbon.jpg",
        "PHOTOS 2026/holiday IN lisbon.JPG",
        "Photos 2026/new.jpg",
        "New folder/new.jpg",
    ] {
        safe_rel_join(base, own, Rules::Host).unwrap_or_else(|error| panic!("{own}: {error}"));
    }
}

#[test]
fn default_output_path_never_names_another_file_in_the_current_directory() {
    let scratch = Scratch::new("cwd");
    let Some(alias) = aliased_file(scratch.path(), "Report for 2026.pdf") else {
        return;
    };
    // Only this test changes the current directory, and every other test in
    // this binary uses absolute paths.
    let _cwd = CurrentDir::enter(scratch.path());
    let error = default_output_path(&alias).expect_err("a short name of another file is a name conflict");
    assert!(error.contains("8.3"), "{alias}: not the short-name refusal: {error}");
    for own in ["Report for 2026.pdf", "report FOR 2026.PDF", "new.pdf"] {
        default_output_path(own).unwrap_or_else(|error| panic!("{own}: {error}"));
    }
}

#[test]
fn decrypt_contiguous_to_file_never_replaces_another_file_through_its_short_name() {
    assert_refused("contiguous", "Report for 2026.pdf", str::to_owned, contiguous_to);
}

#[test]
fn decrypt_contiguous_to_file_never_truncates_another_file_through_its_tmp_name() {
    assert_refused(
        "contiguous-tmp",
        "Report for 2026.tmp",
        stem_of_tmp_alias,
        contiguous_to,
    );
}

#[test]
fn decrypt_chunks_to_file_never_replaces_another_file_through_its_short_name() {
    assert_refused("chunks", "Report for 2026.pdf", str::to_owned, chunks_to);
}

#[test]
fn decrypt_chunks_to_file_never_truncates_another_file_through_its_tmp_name() {
    assert_refused("chunks-tmp", "Report for 2026.tmp", stem_of_tmp_alias, chunks_to);
}

#[test]
fn file_decrypt_chunks_to_file_never_replaces_another_file_through_its_short_name() {
    assert_refused("chunk-files", "Report for 2026.pdf", str::to_owned, chunk_files_to);
}

#[test]
fn file_decrypt_chunks_to_file_never_truncates_another_file_through_its_tmp_name() {
    // This path's temp file is `output.with_extension("tmp")`.
    assert_refused(
        "chunk-files-tmp",
        "Report for 2026.tmp",
        |alias| format!("{}.pdf", stem_of_tmp_alias(alias)),
        chunk_files_to,
    );
}

/// The control: the existing file's own long name, in another case, is that
/// file, and each write path still replaces it as before.
#[test]
fn decrypting_to_the_existing_files_own_name_still_replaces_it() {
    let writes: [(&str, fn(&Path) -> Result<(), String>); 3] = [
        ("contiguous", contiguous_to),
        ("chunks", chunks_to),
        ("chunk-files", chunk_files_to),
    ];
    for (label, write) in writes {
        let scratch = Scratch::new(label);
        let dir = scratch.path();
        std::fs::write(dir.join("Report for 2026.pdf"), PRECIOUS).expect("write the existing file");
        write(&dir.join("report FOR 2026.PDF")).unwrap_or_else(|error| panic!("{label}: {error}"));
        let names = entries(dir);
        assert_eq!(names.len(), 1, "{label}: {names:?}");
        assert_eq!(
            std::fs::read(dir.join("Report for 2026.pdf")).unwrap(),
            WRITTEN,
            "{label}"
        );
    }
}

/// NTFS gives every short name it generates a `~`, so a chunk named `0.enc` has
/// an alias only where a short name was set by hand. `fsutil file setshortname`
/// needs an elevated prompt: without one this skips (with `CI` set it fails).
#[test]
fn encrypt_file_to_chunks_never_replaces_another_file_through_its_short_name() {
    let scratch = Scratch::new("encrypt-chunks");
    let out_dir = scratch.path().join("out");
    std::fs::create_dir(&out_dir).expect("create output dir");
    let existing = out_dir.join("chunk zero backup.enc");
    std::fs::write(&existing, PRECIOUS).expect("write the existing file");
    let set = Command::new("fsutil")
        .args(["file", "setshortname"])
        .arg(&existing)
        .arg("0.ENC")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success());
    if !set {
        assert!(
            std::env::var_os("CI").is_none(),
            "fsutil file setshortname failed (needs an elevated prompt)"
        );
        eprintln!("skipped: fsutil file setshortname needs an elevated prompt");
        return;
    }
    assert_eq!(
        std::fs::read(out_dir.join("0.enc")).expect("read through the short name"),
        PRECIOUS,
        "the fixture must alias: 0.enc reaches chunk zero backup.enc"
    );
    let input = scratch.path().join("input.bin");
    std::fs::write(&input, WRITTEN).expect("write input");

    let result =
        file_encrypt::encrypt_file_to_chunks(&master_key(), FILE_ID, &input, &out_dir, ChunkProfile::Desktop, None);
    assert_eq!(std::fs::read(&existing).ok().as_deref(), Some(PRECIOUS));
    assert_eq!(entries(&out_dir), ["chunk zero backup.enc"]);
    let error = result
        .map(drop)
        .expect_err("a short name of another file is a name conflict");
    assert!(error.to_string().contains("8.3"), "not the short-name refusal: {error}");
}
