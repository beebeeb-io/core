//! Write a file through a temp sibling, then publish it, without ever
//! touching an entry the output name was not meant for (task 2404).
//!
//! Core's file writers (the decrypt-to-file paths, the chunk writer) and
//! beebeeb-upload's downloads all go through [`TempSibling`], so the rules
//! below hold in one place.

use super::short_name::{ShortNameAlias, Walk, walk_last};
use crate::CoreError;
use rand::RngCore as _;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};

/// A temp file beside `output` that becomes `output` only through
/// [`publish`](Self::publish).
///
/// - [`create`](Self::create) refuses an `output` that reaches a different
///   existing entry ([`super::short_name_alias`]), then creates the temp
///   EXCLUSIVELY (`create_new`): `{output}.tmp`, or `{output}.{16 hex}.tmp`
///   when that name is taken, by a temp left behind by an earlier crash or by
///   a file of the user's own. An existing entry is never opened, truncated
///   or deleted, whatever name reaches it.
/// - [`publish`](Self::publish) checks `output` again. When `output` is that
///   entry's own name, the temp is renamed over it, as before. When nothing is
///   there (Windows), the temp is published WITHOUT replacing: a hard link, or
///   on a volume without hard links an exclusive create of `output` and a
///   rename over the empty file that made. An entry created at `output` in the
///   meantime then fails the publish instead of being replaced. Other hosts
///   rename, as before (they resolve a name only to the entry of that name).
/// - Dropping it unpublished removes the temp (and only the temp).
///
/// A conflict, in either step, is an error of kind
/// [`io::ErrorKind::AlreadyExists`]; for a short-name alias its inner error
/// is the [`ShortNameAlias`].
#[derive(Debug)]
pub struct TempSibling {
    output: PathBuf,
    temp: PathBuf,
    published: bool,
}

impl TempSibling {
    /// Create the temp sibling of `output`; write the returned file, then
    /// [`publish`](Self::publish). The parent directory must exist.
    pub fn create(output: &Path) -> io::Result<(Self, File)> {
        Self::create_with(output, |_| Ok(()))
    }

    /// [`create`](Self::create), telling `before_create` each candidate temp
    /// path immediately BEFORE it is created (task 2434), so a caller can
    /// record the path first and create second: a process killed in between
    /// leaves a recorded name, never an unrecorded temp.
    ///
    /// Each candidate is checked first (`symlink_metadata`, so a dangling
    /// symlink counts as taken): the plain `{output}.tmp`, then a random name
    /// for each one that is taken. A taken name is skipped WITHOUT telling
    /// `before_create`, so every call names a path that was free when checked,
    /// never a file of the user's or a crash's leftover. Only a creator that
    /// races in between can still make the create fail with `AlreadyExists`;
    /// the next random name is then offered, and the earlier path stays
    /// recorded though it was never created by this call. An error from
    /// `before_create` stops the create, with nothing made.
    pub fn create_with(
        output: &Path,
        mut before_create: impl FnMut(&Path) -> io::Result<()>,
    ) -> io::Result<(Self, File)> {
        if let Walk::Alias(conflict) = walk_last(output)? {
            return Err(conflict_error(conflict));
        }
        let mut temp = with_suffix(output, ".tmp");
        // A taken name is skipped, never opened: 8 random 64-bit names cannot
        // all be taken unless something is wrong.
        for _ in 0..8 {
            if exists(&temp)? {
                temp = random_sibling(output);
                continue;
            }
            before_create(&temp)?;
            match OpenOptions::new().write(true).create_new(true).open(&temp) {
                Ok(file) => {
                    let sibling = Self {
                        output: output.to_path_buf(),
                        temp,
                        published: false,
                    };
                    return Ok((sibling, file));
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    temp = random_sibling(output);
                }
                Err(error) => return Err(error),
            }
        }
        Err(io::Error::other(format!(
            "{}: no free temp name beside it",
            output.display()
        )))
    }

    /// Check `output` again, then publish the temp as `output` (see the type's
    /// docs). On an error the temp is removed and nothing else changes.
    pub fn publish(mut self) -> io::Result<()> {
        match walk_last(&self.output)? {
            Walk::Alias(conflict) => return Err(conflict_error(conflict)),
            Walk::Missing => publish_new(&self.temp, &self.output)?,
            Walk::Own | Walk::Unchecked => fs::rename(&self.temp, &self.output)?,
        }
        self.published = true;
        Ok(())
    }
}

impl Drop for TempSibling {
    fn drop(&mut self) {
        if !self.published {
            let _ = fs::remove_file(&self.temp);
        }
    }
}

/// Whether anything is at `path`, without following a symlink.
fn exists(path: &Path) -> io::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

fn random_sibling(output: &Path) -> PathBuf {
    with_suffix(output, &format!(".{:016x}.tmp", rand::rngs::OsRng.next_u64()))
}

/// `path` with `suffix` appended to its last component.
fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

fn conflict_error(conflict: ShortNameAlias) -> io::Error {
    io::Error::new(io::ErrorKind::AlreadyExists, conflict)
}

fn appeared(output: &Path) -> io::Error {
    io::Error::new(
        io::ErrorKind::AlreadyExists,
        format!(
            "name conflict: an entry reached by {:?} appeared while the file was written; not replacing it",
            output.file_name().unwrap_or(output.as_os_str())
        ),
    )
}

/// Publish `temp` as `output`, where the check found nothing: never replaces
/// an entry that appeared at `output` since, whatever name reaches it.
fn publish_new(temp: &Path, output: &Path) -> io::Result<()> {
    match fs::hard_link(temp, output) {
        Ok(()) => {
            // `output` is published. A temp that cannot be removed stays as a
            // second name of the same file; the publish still succeeded.
            let _ = fs::remove_file(temp);
            Ok(())
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Err(appeared(output)),
        // Every other failure is read as a volume without hard links (FAT,
        // exFAT, some network shares). The fallback below replaces nothing
        // either; if the failure had another cause, it fails the same way.
        Err(_) => publish_by_exclusive_create(temp, output),
    }
}

/// The publish without hard links: claim `output` with an exclusive create
/// (which fails on any entry the name reaches), then rename `temp` over the
/// empty file that create just made. Between the two steps `output` exists
/// and is empty; the rename is a single step and replaces only that file.
fn publish_by_exclusive_create(temp: &Path, output: &Path) -> io::Result<()> {
    match OpenOptions::new().write(true).create_new(true).open(output) {
        Ok(_claimed) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => return Err(appeared(output)),
        Err(error) => return Err(error),
    }
    fs::rename(temp, output).inspect_err(|_| {
        // Drop the empty file this publish made, so no empty output is left.
        let _ = fs::remove_file(output);
    })
}

/// A [`TempSibling`] error as core's error: a name conflict is
/// [`CoreError::InvalidInput`] naming it, anything else [`CoreError::Io`].
pub(crate) fn core_error(context: &str, error: io::Error) -> CoreError {
    if error.kind() == io::ErrorKind::AlreadyExists {
        CoreError::InvalidInput(error.to_string())
    } else {
        CoreError::Io(format!("{context}: {error}"))
    }
}

/// Write `output` through a [`TempSibling`]: `write` fills the temp file, which
/// is then published; on any error the temp is removed, so no partial
/// plaintext survives at either name.
pub(crate) fn write_through_tmp<T>(
    output: &Path,
    write: impl FnOnce(File) -> Result<T, CoreError>,
) -> Result<T, CoreError> {
    let (temp, file) = TempSibling::create(output).map_err(|e| core_error("create output file", e))?;
    let value = write(file)?;
    temp.publish().map_err(|e| core_error("rename output", e))?;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use std::time::{SystemTime, UNIX_EPOCH};

    /// A private scratch directory under the system temp dir, removed on drop.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(label: &str) -> Self {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock after 1970")
                .as_nanos();
            let dir = std::env::temp_dir().join(format!("beebeeb-temp-sibling-{label}-{}-{nanos}", std::process::id()));
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

    fn write_and_publish(output: &Path, contents: &[u8]) -> io::Result<PathBuf> {
        let (temp, mut file) = TempSibling::create(output)?;
        file.write_all(contents)?;
        drop(file);
        let temp_path = temp.temp.clone();
        temp.publish()?;
        Ok(temp_path)
    }

    /// A taken temp name (a crash's leftover, or a file of the user's own) is
    /// skipped, never opened: it keeps its contents.
    #[test]
    fn a_taken_temp_name_is_never_opened() {
        let scratch = Scratch::new("taken");
        let dir = &scratch.0;
        fs::write(dir.join("notes.pdf.tmp"), b"the user's own file").unwrap();

        let temp = write_and_publish(&dir.join("notes.pdf"), b"new").unwrap();

        assert_ne!(temp, dir.join("notes.pdf.tmp"), "a fresh temp name was used");
        assert_eq!(fs::read(dir.join("notes.pdf.tmp")).unwrap(), b"the user's own file");
        assert_eq!(fs::read(dir.join("notes.pdf")).unwrap(), b"new");
        assert_eq!(entries(dir), ["notes.pdf", "notes.pdf.tmp"]);
    }

    /// The path handed to the callback is exactly the file the create then
    /// makes, and it does not exist yet when the callback runs (task 2434).
    #[test]
    fn create_with_hands_out_the_path_before_it_creates_it() {
        let scratch = Scratch::new("with-plain");
        let dir = &scratch.0;
        let mut seen: Vec<(PathBuf, bool)> = Vec::new();

        let (temp, file) = TempSibling::create_with(&dir.join("out.bin"), |path| {
            seen.push((path.to_path_buf(), path.exists()));
            Ok(())
        })
        .unwrap();
        drop(file);

        assert_eq!(seen, [(dir.join("out.bin.tmp"), false)], "one call, before the create");
        assert_eq!(temp.temp, dir.join("out.bin.tmp"));
        assert_eq!(entries(dir), ["out.bin.tmp"]);
    }

    /// On the random-name branch the callback sees only the name that is then
    /// created, and that name does not exist yet when the callback runs: the
    /// taken plain name is skipped without a call.
    #[test]
    fn create_with_hands_out_the_random_name_it_then_creates() {
        let scratch = Scratch::new("with-random");
        let dir = &scratch.0;
        fs::write(dir.join("out.bin.tmp"), b"the user's own file").unwrap();
        let mut seen: Vec<PathBuf> = Vec::new();
        let mut existed_at_call: Vec<bool> = Vec::new();

        let (temp, file) = TempSibling::create_with(&dir.join("out.bin"), |path| {
            seen.push(path.to_path_buf());
            existed_at_call.push(fs::symlink_metadata(path).is_ok());
            Ok(())
        })
        .unwrap();
        drop(file);

        assert_eq!(
            seen,
            std::slice::from_ref(&temp.temp),
            "one call, naming the created file"
        );
        assert_eq!(existed_at_call, [false], "the callback ran before the create");
        assert_ne!(temp.temp, dir.join("out.bin.tmp"));
        assert_eq!(fs::read(dir.join("out.bin.tmp")).unwrap(), b"the user's own file");
        let mut expected = vec![
            "out.bin.tmp".to_string(),
            temp.temp.file_name().unwrap().to_string_lossy().into_owned(),
        ];
        expected.sort();
        assert_eq!(entries(dir), expected);
    }

    /// A dangling symlink at the plain temp name counts as taken: no call for
    /// it, and it is neither followed nor replaced.
    #[cfg(unix)]
    #[test]
    fn a_dangling_symlink_is_taken_and_never_offered() {
        let scratch = Scratch::new("with-symlink");
        let dir = &scratch.0;
        std::os::unix::fs::symlink(dir.join("nowhere"), dir.join("out.bin.tmp")).unwrap();
        let mut seen: Vec<PathBuf> = Vec::new();

        let (temp, file) = TempSibling::create_with(&dir.join("out.bin"), |path| {
            seen.push(path.to_path_buf());
            Ok(())
        })
        .unwrap();
        drop(file);

        assert_eq!(seen, std::slice::from_ref(&temp.temp));
        assert_ne!(temp.temp, dir.join("out.bin.tmp"));
        assert!(!dir.join("nowhere").exists(), "the symlink target was not created");
        assert!(fs::symlink_metadata(dir.join("out.bin.tmp")).unwrap().is_symlink());
    }

    /// A taken name is never offered to the callback, however many calls.
    #[test]
    fn a_taken_name_is_never_offered_to_the_callback() {
        let scratch = Scratch::new("with-taken");
        let dir = &scratch.0;
        fs::write(dir.join("out.bin.tmp"), b"the user's own file").unwrap();
        let mut offered_taken = false;

        let (_temp, file) = TempSibling::create_with(&dir.join("out.bin"), |path| {
            offered_taken |= path == dir.join("out.bin.tmp");
            Ok(())
        })
        .unwrap();
        drop(file);

        assert!(!offered_taken, "the user's file was offered as a temp");
    }

    /// A callback that fails stops the create: no temp file is made.
    #[test]
    fn a_failing_callback_creates_nothing() {
        let scratch = Scratch::new("with-error");
        let dir = &scratch.0;

        let error =
            TempSibling::create_with(&dir.join("out.bin"), |_| Err(io::Error::other("record failed"))).unwrap_err();

        assert_eq!(error.to_string(), "record failed");
        assert_eq!(entries(dir), Vec::<String>::new());
    }

    /// The usual temp name when it is free; the output's own name is replaced.
    #[test]
    fn publish_replaces_the_outputs_own_name() {
        let scratch = Scratch::new("own");
        let dir = &scratch.0;
        fs::write(dir.join("out.bin"), b"old").unwrap();

        let temp = write_and_publish(&dir.join("out.bin"), b"new").unwrap();

        assert_eq!(temp, dir.join("out.bin.tmp"));
        assert_eq!(fs::read(dir.join("out.bin")).unwrap(), b"new");
        assert_eq!(entries(dir), ["out.bin"]);
    }

    /// An unpublished temp is removed on drop, and nothing else is.
    #[test]
    fn an_unpublished_temp_is_removed_and_nothing_else() {
        let scratch = Scratch::new("drop");
        let dir = &scratch.0;
        fs::write(dir.join("out.bin"), b"old").unwrap();
        let (temp, mut file) = TempSibling::create(&dir.join("out.bin")).unwrap();
        file.write_all(b"partial").unwrap();
        drop(file);
        assert_eq!(
            entries(dir),
            ["out.bin", "out.bin.tmp"],
            "the temp exists before the drop"
        );

        drop(temp);

        assert_eq!(entries(dir), ["out.bin"]);
        assert_eq!(fs::read(dir.join("out.bin")).unwrap(), b"old");
    }

    /// The publish without hard links never replaces what is there, and
    /// publishes into a free name (on every host: it is plain std).
    #[test]
    fn publishing_by_exclusive_create_never_replaces() {
        let scratch = Scratch::new("exclusive");
        let dir = &scratch.0;
        fs::write(dir.join("taken.bin"), b"keep").unwrap();
        fs::write(dir.join("t1"), b"new").unwrap();

        let error = publish_by_exclusive_create(&dir.join("t1"), &dir.join("taken.bin")).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists, "{error}");
        assert_eq!(fs::read(dir.join("taken.bin")).unwrap(), b"keep");

        publish_by_exclusive_create(&dir.join("t1"), &dir.join("free.bin")).unwrap();
        assert_eq!(fs::read(dir.join("free.bin")).unwrap(), b"new");
        assert_eq!(entries(dir), ["free.bin", "taken.bin"]);
    }

    /// The hard-link publish never replaces what is there either.
    #[test]
    fn publishing_a_new_name_never_replaces() {
        let scratch = Scratch::new("new");
        let dir = &scratch.0;
        fs::write(dir.join("taken.bin"), b"keep").unwrap();
        fs::write(dir.join("t1"), b"new").unwrap();

        let error = publish_new(&dir.join("t1"), &dir.join("taken.bin")).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists, "{error}");
        assert_eq!(fs::read(dir.join("taken.bin")).unwrap(), b"keep");

        publish_new(&dir.join("t1"), &dir.join("free.bin")).unwrap();
        assert_eq!(fs::read(dir.join("free.bin")).unwrap(), b"new");
        assert_eq!(
            entries(dir),
            ["free.bin", "taken.bin"],
            "the temp is gone after the link"
        );
    }
}

#[cfg(all(test, windows))]
#[path = "temp_sibling_windows_tests.rs"]
mod windows_tests;
