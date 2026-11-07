//! Turning a server-provided name into a local path, safely.
//!
//! Every file and folder name a client writes to disk comes from the server (or
//! from an anonymous uploader, so the decrypted name is attacker-controlled).
//! `dir.join(name)` is not safe on such input:
//!
//! - an absolute name (`/etc/cron.d/x`) REPLACES `dir` in [`Path::join`];
//! - `..` components climb out of `dir`;
//! - a name with a separator creates (and writes into) arbitrary subtrees;
//! - a pre-existing symlink inside `dir` redirects the write elsewhere.
//!
//! Move 11 (spec §16.2) promotes the cli's `safe_path` rules into core so the
//! cli, desktop and web share one answer. Two rule sets ([`Rules`]):
//!
//! - **Portable**: what a name must satisfy on any host. Pulled trees are
//!   artefacts users copy around, so separators and drive prefixes are refused
//!   everywhere.
//! - **Host**: only what is dangerous on THIS host. Sync mirrors a tree both
//!   ways and must keep working for legitimate local names uploaded earlier (a
//!   Linux file named `a\b`); refusing those would look like a remote delete.
//!
//! The pure naming rules build for wasm too; the filesystem part
//! ([`ensure_contained`], [`safe_child`], [`safe_rel_join`]) is native-only.

use std::collections::BTreeSet;
use std::fmt;

use crate::invisible::is_display_invisible;
use unicode_normalization::UnicodeNormalization;

/// Which rule set to apply; see the module docs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rules {
    /// Reject anything that is a separator, drive prefix or control character
    /// on any supported platform.
    Portable,
    /// Reject only what is dangerous on the current host.
    Host,
}

/// Why a name was refused. `Display` gives the short reason shown to the user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsafeName(pub &'static str);

impl fmt::Display for UnsafeName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for UnsafeName {}

/// Longest single name a mainstream filesystem stores, in UTF-8 bytes.
pub const MAX_COMPONENT_BYTES: usize = 255;
/// Longest final name accepted by the safe publisher. Temporary siblings use
/// an independent short name, so publication never shortens the valid range.
pub const MAX_PUBLISH_COMPONENT_BYTES: usize = MAX_COMPONENT_BYTES;
/// Longest relative path a mainstream filesystem stores, in bytes.
pub const MAX_PATH_BYTES: usize = 4096;

/// Windows device names that cannot be used as file names (with or without an
/// extension).
const WINDOWS_RESERVED: &[&str] = &[
    "CON",
    "PRN",
    "AUX",
    "NUL",
    "CONIN$",
    "CONOUT$",
    "COM0",
    "COM1",
    "COM2",
    "COM3",
    "COM4",
    "COM5",
    "COM6",
    "COM7",
    "COM8",
    "COM9",
    "LPT0",
    "LPT1",
    "LPT2",
    "LPT3",
    "LPT4",
    "LPT5",
    "LPT6",
    "LPT7",
    "LPT8",
    "LPT9",
    // Windows also reserves the superscript spellings (U+00B9, U+00B2, U+00B3).
    "COM\u{b9}",
    "COM\u{b2}",
    "COM\u{b3}",
    "LPT\u{b9}",
    "LPT\u{b2}",
    "LPT\u{b3}",
];

/// Check one name (a single path component, never a path).
pub fn check_component(name: &str, rules: Rules) -> Result<(), UnsafeName> {
    check_component_for(name, rules == Rules::Portable, cfg!(target_os = "windows"))
}

/// Testable core of [`check_component`]. `portable` = the strict cross-platform
/// rules; `windows` = this host applies Windows path semantics.
pub fn check_component_for(name: &str, portable: bool, windows: bool) -> Result<(), UnsafeName> {
    // Bidi marks and zero-width characters are real text (Hebrew, Arabic,
    // Persian, Indic), but they render as nothing: a name made only of them
    // looks empty, and `.` plus marks looks like `.` or `..`. Judge emptiness
    // and the dot names on what a renderer shows, not on the raw bytes.
    let visible: std::borrow::Cow<'_, str> = if name.chars().any(is_display_invisible) {
        name.chars().filter(|c| !is_display_invisible(*c)).collect()
    } else {
        std::borrow::Cow::Borrowed(name)
    };
    if visible.is_empty() {
        return Err(UnsafeName("empty name"));
    }
    if visible == "." || visible == ".." {
        return Err(UnsafeName("'.' and '..' are not file names"));
    }
    if name.len() > MAX_COMPONENT_BYTES {
        return Err(UnsafeName("is longer than 255 bytes"));
    }
    if name.contains('\0') {
        return Err(UnsafeName("contains a NUL byte"));
    }
    if name.contains('/') {
        return Err(UnsafeName("contains a path separator"));
    }
    if portable || windows {
        if name.contains('\\') {
            return Err(UnsafeName("contains a path separator"));
        }
        if name.chars().any(|c| c.is_control()) {
            return Err(UnsafeName("contains a control character"));
        }
        // Bidi overrides and isolates are not `char::is_control`, but they let
        // a name render as a different name. Refuse them wherever a path may be
        // shown or interpreted by the host. (Bidi MARKS are real text in Hebrew
        // and Arabic, so they are only stripped by `sanitize_component`.)
        if name.chars().any(is_bidi_control) {
            return Err(UnsafeName("contains a bidirection-control character"));
        }
        let bytes = name.as_bytes();
        if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
            return Err(UnsafeName("starts with a Windows drive prefix"));
        }
    }
    if windows {
        if name.contains(':') {
            return Err(UnsafeName("contains ':' (drive prefix or alternate data stream)"));
        }
        if name.chars().any(|c| matches!(c, '<' | '>' | '"' | '|' | '?' | '*')) {
            return Err(UnsafeName("contains a character Windows does not allow"));
        }
        if name.ends_with('.') || name.ends_with(' ') {
            return Err(UnsafeName("ends with a dot or space (Windows strips it)"));
        }
        if is_windows_reserved_stem(name) {
            return Err(UnsafeName("is a reserved Windows device name"));
        }
    }
    Ok(())
}

/// Whether `name`'s stem (the part before the first `.`, trailing spaces
/// trimmed) is a reserved Windows device name, ASCII case-insensitively. The
/// one copy of this test: `check_component_for`, `sanitize_component` and the
/// backup device-folder name all call it.
pub(crate) fn is_windows_reserved_stem(name: &str) -> bool {
    let stem = name.split('.').next().unwrap_or(name).trim_end();
    WINDOWS_RESERVED
        .iter()
        .any(|reserved| reserved.eq_ignore_ascii_case(stem))
}

/// Bidirectional OVERRIDE and ISOLATE characters. They are not control
/// characters to `char::is_control`, but a name containing one can render as a
/// different name (`evil\u{202e}fdp.exe` shows as `evilexe.pdf`), so they are
/// refused outright.
pub(crate) fn is_bidi_control(c: char) -> bool {
    matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
}

/// Bidirectional MARKS: LEFT-TO-RIGHT MARK, RIGHT-TO-LEFT MARK and ARABIC
/// LETTER MARK. These are ordinary text in Hebrew and Arabic — refusing them
/// would reject legitimate names — but they still let a renderer reorder
/// neighbouring characters, so [`sanitize_component`] removes them.
fn is_bidi_mark(c: char) -> bool {
    matches!(c, '\u{200e}' | '\u{200f}' | '\u{061c}')
}

/// One name as it may appear INSIDE AN ARCHIVE.
///
/// An archive is extracted somewhere else, often on Windows, so the host's own
/// rules are not enough. The structural checks of [`Rules::Portable`] still
/// REFUSE the name (separators, `.`/`..`, control characters, drive prefixes:
/// those are traversal, not cosmetics). Everything else Windows or a renderer
/// would mangle is REWRITTEN instead, so the file is not lost:
///
/// - `: < > " | ? *` become `_` (a `:` is an NTFS alternate data stream);
/// - trailing dots and spaces become `_` (Windows silently strips them);
/// - a reserved device name (`CON`, `NUL`, `COM1`, ... with or without an
///   extension) gets a leading `_`;
/// - bidi overrides, isolates and marks are removed.
///
/// Rewriting can make two names equal; the caller de-duplicates afterwards.
/// The result always satisfies the strictest rule set, or the name is refused.
pub fn sanitize_component(name: &str, rules: Rules) -> Result<String, UnsafeName> {
    // Strip bidi controls and marks BEFORE the check: they are a rendering
    // hazard the archive rule rewrites, not traversal. The structural checks
    // still see the same name, except that stripping CAN neutralise a name made
    // only of marks (it becomes empty) or `.` plus marks (it becomes `.`/`..`),
    // so `check_component` runs its empty and dot-name checks on the stripped
    // form as well and still refuses those rather than writing an invisible or
    // dot name.
    let visible: String = name
        .chars()
        .filter(|c| !is_bidi_control(*c) && !is_bidi_mark(*c))
        .collect();
    check_component(&visible, rules)?;
    let mut out: String = visible
        .chars()
        .map(|c| {
            if matches!(c, ':' | '<' | '>' | '"' | '|' | '?' | '*') {
                '_'
            } else {
                c
            }
        })
        .collect();
    let trimmed = out.trim_end_matches(['.', ' ']).len();
    if trimmed != out.len() {
        let pad = "_".repeat(out.len() - trimmed);
        out.truncate(trimmed);
        out.push_str(&pad);
    }
    if is_windows_reserved_stem(&out) {
        out.insert(0, '_');
    }
    check_component_for(&out, true, true)?;
    Ok(out)
}

/// [`sanitize_component`] with the portable rules — the archive/extract rule.
pub fn archive_component(name: &str) -> Result<String, UnsafeName> {
    sanitize_component(name, Rules::Portable)
}

/// NFC and Unicode-lowercase key used to detect names that collide on common
/// case-insensitive or normalization-insensitive filesystems.
pub fn fold_key(name: &str) -> String {
    name.nfc().flat_map(char::to_lowercase).collect()
}

/// Keep `name` when its folded key is free, otherwise add ` (n)` before the
/// extension until it is unique. The returned name is always portable.
pub fn deduplicate_component(name: &str, used: &mut BTreeSet<String>) -> Result<String, UnsafeName> {
    check_component(name, Rules::Portable)?;
    if used.insert(fold_key(name)) {
        return Ok(name.to_owned());
    }
    let (stem, extension) = match name.rsplit_once('.') {
        Some((stem, extension)) if !stem.is_empty() => (stem, format!(".{extension}")),
        _ => (name, String::new()),
    };
    for number in 2u32..=10_000 {
        let candidate = format!("{stem} ({number}){extension}");
        check_component(&candidate, Rules::Portable)?;
        if used.insert(fold_key(&candidate)) {
            return Ok(candidate);
        }
    }
    Err(UnsafeName("has too many colliding names"))
}

#[cfg(unix)]
mod publish {
    use super::*;
    use rand::{RngCore, rngs::OsRng};
    use rustix::fs::{self, AtFlags, Mode, OFlags};
    use std::fs::File;
    use std::io;
    use std::path::Path;

    /// An already-open trusted directory. All publication operations are
    /// relative to this handle, so renaming or replacing an ancestor cannot
    /// redirect the eventual file create.
    #[derive(Debug)]
    pub struct TrustedDirectory {
        directory: File,
    }

    impl TrustedDirectory {
        pub fn open(path: &Path) -> io::Result<Self> {
            let fd = fs::open(
                path,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )?;
            Ok(Self { directory: fd.into() })
        }

        /// Create a restrictive, no-follow sibling temp file. Dropping the
        /// pending publication removes it through the trusted directory handle.
        pub fn begin_publish(&self, name: &str, rules: Rules) -> io::Result<(PendingPublish, File)> {
            check_component(name, rules).map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
            if name.len() > MAX_PUBLISH_COMPONENT_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("publish name is longer than {MAX_PUBLISH_COMPONENT_BYTES} bytes"),
                ));
            }
            let mut random = [0u8; 16];
            OsRng
                .try_fill_bytes(&mut random)
                .map_err(|error| io::Error::other(format!("generate temp suffix: {error}")))?;
            let mut suffix = String::with_capacity(32);
            for byte in random {
                suffix.push_str(&format!("{byte:02x}"));
            }
            let temp_name = format!(".bbtmp-{suffix}");
            let fd = fs::openat(
                &self.directory,
                temp_name.as_str(),
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::RUSR | Mode::WUSR,
            )?;
            let file: File = fd.into();
            let sync_file = file.try_clone()?;
            let pending = PendingPublish {
                directory: self.directory.try_clone()?,
                sync_file,
                temp_name,
                target_name: name.to_owned(),
                committed: false,
            };
            Ok((pending, file))
        }

        pub fn publish_bytes(&self, name: &str, rules: Rules, bytes: &[u8]) -> io::Result<()> {
            use std::io::Write as _;
            let (pending, mut file) = self.begin_publish(name, rules)?;
            file.write_all(bytes)?;
            drop(file);
            pending.commit()
        }
    }

    #[derive(Debug)]
    pub struct PendingPublish {
        directory: File,
        sync_file: File,
        temp_name: String,
        target_name: String,
        committed: bool,
    }

    impl PendingPublish {
        /// Flush file data, atomically replace the final directory entry, then
        /// flush the directory entry itself.
        pub fn commit(mut self) -> io::Result<()> {
            self.sync_file.sync_all()?;
            fs::renameat(
                &self.directory,
                self.temp_name.as_str(),
                &self.directory,
                self.target_name.as_str(),
            )?;
            self.directory.sync_all()?;
            self.committed = true;
            Ok(())
        }
    }

    impl Drop for PendingPublish {
        fn drop(&mut self) {
            if !self.committed {
                let _ = fs::unlinkat(&self.directory, self.temp_name.as_str(), AtFlags::empty());
            }
        }
    }
}

#[cfg(unix)]
pub use publish::{PendingPublish, TrustedDirectory};

#[cfg(not(target_arch = "wasm32"))]
mod native {
    use super::*;
    use std::path::{Component, Path, PathBuf};

    /// Canonicalise the deepest EXISTING ancestor of `path` (resolving
    /// symlinks), then re-append the not-yet-existing tail.
    fn canonicalize_deepest(path: &Path) -> Result<PathBuf, String> {
        let mut existing = path;
        let mut tail: Vec<&std::ffi::OsStr> = Vec::new();
        loop {
            match std::fs::symlink_metadata(existing) {
                Ok(_) => break,
                Err(_) => {
                    let name = existing
                        .file_name()
                        .ok_or_else(|| format!("{}: no existing ancestor", path.display()))?;
                    tail.push(name);
                    existing = existing
                        .parent()
                        .ok_or_else(|| format!("{}: no existing ancestor", path.display()))?;
                    if existing.as_os_str().is_empty() {
                        existing = Path::new(".");
                        break;
                    }
                }
            }
        }
        let mut out = existing
            .canonicalize()
            .map_err(|e| format!("{}: cannot resolve: {e}", existing.display()))?;
        for component in tail.iter().rev() {
            out.push(component);
        }
        Ok(out)
    }

    /// Assert that `path`, with every symlink on its way resolved, stays inside
    /// `root`. `path` need not exist yet (its deepest existing ancestor is
    /// resolved).
    pub fn ensure_contained(root: &Path, path: &Path) -> Result<(), String> {
        let root_canonical = canonicalize_deepest(root)?;
        let path_canonical = canonicalize_deepest(path)?;
        if path_canonical.starts_with(&root_canonical) {
            Ok(())
        } else {
            Err(format!(
                "{} resolves to {}, outside {}",
                path.display(),
                path_canonical.display(),
                root_canonical.display()
            ))
        }
    }

    /// Refuse a symlink at `path` itself (a write there would go through it).
    fn reject_symlink(path: &Path) -> Result<(), String> {
        match std::fs::symlink_metadata(path) {
            Ok(meta) if meta.file_type().is_symlink() => {
                Err(format!("{} is a symlink; refusing to write through it", path.display()))
            }
            _ => Ok(()),
        }
    }

    /// `dir/name` for ONE server-provided name: the name is validated as a
    /// single safe component, the target must not be a symlink, and its
    /// resolved location must stay inside `dir`.
    pub fn safe_child(dir: &Path, name: &str, rules: Rules) -> Result<PathBuf, String> {
        check_component(name, rules).map_err(|e| format!("unsafe name {name:?} ({e})"))?;
        let target = dir.join(name);
        debug_assert!(matches!(
            Path::new(name).components().collect::<Vec<_>>().as_slice(),
            [Component::Normal(_)]
        ));
        reject_symlink(&target)?;
        ensure_contained(dir, &target)?;
        Ok(target)
    }

    /// `base/rel` for a `/`-separated remote-relative path: every segment is
    /// validated, and the resolved location must stay inside `base`.
    pub fn safe_rel_join(base: &Path, rel: &str, rules: Rules) -> Result<PathBuf, String> {
        if rel.is_empty() {
            return Err("unsafe name \"\" (empty path)".to_string());
        }
        if rel.len() > MAX_PATH_BYTES {
            return Err(format!("unsafe path ({MAX_PATH_BYTES}-byte limit exceeded)"));
        }
        let mut target = base.to_path_buf();
        for segment in rel.split('/') {
            check_component(segment, rules).map_err(|e| format!("unsafe name {rel:?} ({e})"))?;
            target.push(segment);
        }
        reject_symlink(&target)?;
        ensure_contained(base, &target)?;
        Ok(target)
    }

    /// Default output path for a pulled file without an explicit `-o`: the
    /// server-provided name, relative to the current directory.
    pub fn default_output_path(name: &str) -> Result<PathBuf, String> {
        check_component(name, Rules::Portable).map_err(|e| {
            format!("the server-provided file name {name:?} is unsafe ({e}); pass -o <path> to choose where to save it")
        })?;
        let path = PathBuf::from(name);
        reject_symlink(&path)?;
        Ok(path)
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub use native::{default_output_path, ensure_contained, safe_child, safe_rel_join};

#[cfg(all(test, unix))]
mod symlink_tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt, symlink};
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    /// A private scratch directory under the system temp dir, removed on drop.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(label: &str) -> Self {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock after 1970")
                .as_nanos();
            let dir = std::env::temp_dir().join(format!("beebeeb-path-safety-{label}-{}-{nanos}", std::process::id()));
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

    /// A symlink AT the target must be refused: writing through it would land
    /// wherever it points, not inside the root.
    #[test]
    fn a_symlink_as_the_final_target_is_refused() {
        let scratch = Scratch::new("final-symlink");
        let root = scratch.path().join("root");
        std::fs::create_dir_all(&root).expect("create root");
        let outside = scratch.path().join("outside.txt");
        std::fs::write(&outside, b"do not touch").expect("write outside marker");
        std::os::unix::fs::symlink(&outside, root.join("link.txt")).expect("create symlink");

        let error =
            safe_child(&root, "link.txt", Rules::Portable).expect_err("a symlink as the target must be refused");
        assert!(
            error.contains("refusing to write through it"),
            "unexpected error: {error}"
        );
    }

    /// A symlinked INTERMEDIATE directory that resolves outside the root must be
    /// refused: the final component need not be a symlink for the write to
    /// escape.
    #[test]
    fn an_intermediate_directory_symlinked_outside_the_root_is_refused() {
        let scratch = Scratch::new("intermediate-symlink");
        let root = scratch.path().join("root");
        let outside = scratch.path().join("outside");
        std::fs::create_dir_all(&root).expect("create root");
        std::fs::create_dir_all(&outside).expect("create outside dir");
        std::fs::write(outside.join("file.bin"), b"do not touch").expect("write outside file");
        std::os::unix::fs::symlink(&outside, root.join("dir")).expect("create dir symlink");

        let error = safe_rel_join(&root, "dir/file.bin", Rules::Portable)
            .expect_err("a path resolving outside the root must be refused");
        assert!(error.contains("outside"), "unexpected error: {error}");
    }

    #[test]
    fn safe_publish_replaces_a_symlink_without_following_it() {
        let scratch = Scratch::new("publish-symlink");
        let root = scratch.path().join("root");
        std::fs::create_dir_all(&root).unwrap();
        let outside = scratch.path().join("outside");
        std::fs::write(&outside, b"outside").unwrap();
        symlink(&outside, root.join("result")).unwrap();

        let directory = TrustedDirectory::open(&root).unwrap();
        directory.publish_bytes("result", Rules::Portable, b"inside").unwrap();

        assert_eq!(std::fs::read(root.join("result")).unwrap(), b"inside");
        assert_eq!(std::fs::read(&outside).unwrap(), b"outside");
        assert_eq!(std::fs::metadata(root.join("result")).unwrap().mode() & 0o777, 0o600);
    }

    #[test]
    fn safe_publish_accepts_a_maximum_length_valid_component() {
        let scratch = Scratch::new("publish-max-name");
        let root = scratch.path().join("root");
        std::fs::create_dir_all(&root).unwrap();
        let name = "x".repeat(MAX_COMPONENT_BYTES);

        TrustedDirectory::open(&root)
            .unwrap()
            .publish_bytes(&name, Rules::Host, b"valid")
            .unwrap();

        assert_eq!(std::fs::read(root.join(name)).unwrap(), b"valid");
    }

    #[test]
    fn failed_publish_cleans_up_its_temp_file() {
        let scratch = Scratch::new("publish-cleanup");
        let root = scratch.path().join("root");
        std::fs::create_dir_all(&root).unwrap();
        let directory = TrustedDirectory::open(&root).unwrap();
        let (pending, file) = directory.begin_publish("result", Rules::Portable).unwrap();
        drop(file);
        drop(pending);
        assert_eq!(std::fs::read_dir(&root).unwrap().count(), 0);
    }

    #[test]
    fn folded_names_are_deduplicated() {
        let mut used = BTreeSet::new();
        assert_eq!(deduplicate_component("Café.txt", &mut used).unwrap(), "Café.txt");
        assert_eq!(deduplicate_component("Café.TXT", &mut used).unwrap(), "Café (2).TXT");
        assert_eq!(fold_key("Café.txt"), fold_key("Café.TXT"));
    }
}
