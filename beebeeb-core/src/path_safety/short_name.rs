//! A name that reaches a DIFFERENT existing entry (task 2404).
//!
//! Windows looks a name up among both the long names and the 8.3 short names
//! of a directory, so a name such as `REPORT~1.PDF` can reach an existing
//! `Report for 2026.pdf`. A create, truncate, replace or delete by that name
//! would then touch a file it never named. Core's rule: such a match is a name
//! conflict. A caller with a conflict path ("(2)", a conflict copy) takes it;
//! otherwise core refuses with [`ShortNameAlias`]. It never opens, truncates,
//! replaces or deletes the entry the name reaches.
//!
//! The check reads the existing entry's own long name from the file system
//! (from the handle the name opens, else from the directory listing), never
//! from the shape of the requested name: real files have `~` in their names.

use crate::CoreError;
use std::fmt;
use std::io;
use std::path::{Component, Path};

/// A create, truncate, replace or delete by [`requested`](Self::requested)
/// would reach a different existing entry: the file system resolves the name
/// to an entry whose own long name is another name (on Windows, an 8.3 short
/// name such as `REPORT~1.PDF` for `Report for 2026.pdf`). A name conflict:
/// take the conflict path or refuse, never touch that entry.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ShortNameAlias {
    /// The name that was asked for (one path component).
    pub requested: String,
    /// The long name of the entry it reaches, when the check could read it.
    pub existing: Option<String>,
}

impl fmt::Display for ShortNameAlias {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "name conflict: {:?} reaches ", self.requested)?;
        match &self.existing {
            Some(existing) => write!(f, "the existing entry {existing:?}")?,
            None => f.write_str("a different existing entry")?,
        }
        f.write_str(" through an 8.3 short name or another alias; refusing to touch it")
    }
}

impl std::error::Error for ShortNameAlias {}

/// One UTF-16 code unit upper-cased the way NTFS compares names: its upcase
/// table maps each code unit to one code unit. A letter whose uppercase is
/// several letters (`ß` → `SS`) or lies outside the Basic Multilingual Plane
/// stays as it is, and so does a surrogate (characters outside the BMP are
/// compared exactly).
#[cfg_attr(not(windows), allow(dead_code))] // the Windows lookup; tests everywhere
fn upcase_unit(unit: u16) -> u16 {
    let Some(c) = char::from_u32(u32::from(unit)) else {
        return unit;
    };
    let mut upper = c.to_uppercase();
    match (upper.next(), upper.next()) {
        (Some(single), None) => u16::try_from(u32::from(single)).unwrap_or(unit),
        _ => unit,
    }
}

/// The decision, on names alone (as UTF-16, which is what Windows stores): the
/// file system resolved `requested` to an existing entry whose own long name is
/// `existing_long`. The same name (in any case, as NTFS compares, one code unit
/// at a time) is that entry and may be touched; any other long name means
/// `requested` is another name of a DIFFERENT entry, a name conflict.
#[cfg_attr(not(windows), allow(dead_code))] // the Windows lookup; tests everywhere
fn is_own_name(requested: impl Iterator<Item = u16>, existing_long: impl Iterator<Item = u16>) -> bool {
    requested.map(upcase_unit).eq(existing_long.map(upcase_unit))
}

/// What one component names in its directory.
#[cfg(windows)]
enum Lookup {
    /// Nothing: a create makes exactly this name.
    Missing,
    /// An entry whose own long name is this name.
    Own,
    /// A different entry, reached through another of its names.
    Alias(ShortNameAlias),
}

/// Look `name` up in `dir` and compare the entry it reaches with its own long
/// name.
#[cfg(windows)]
fn lookup(dir: &Path, name: &std::ffi::OsStr) -> io::Result<Lookup> {
    use std::os::windows::ffi::OsStrExt as _;
    let path = dir.join(name);
    let meta = match std::fs::symlink_metadata(&path) {
        Ok(meta) => meta,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Lookup::Missing),
        Err(error) => return Err(error),
    };
    let own = |long: &std::ffi::OsStr| is_own_name(name.encode_wide(), long.encode_wide());
    let mut existing = None;
    // `canonicalize` opens the entry the name reaches and asks that handle for
    // its normalized path (GetFinalPathNameByHandleW), whose last component is
    // the entry's own long name. It opens THROUGH a link, so a link's own name
    // is not in that answer: a link goes straight to the listing.
    if !meta.file_type().is_symlink()
        && let Ok(canonical) = std::fs::canonicalize(&path)
        && let Some(long) = canonical.file_name()
    {
        if own(long) {
            return Ok(Lookup::Own);
        }
        existing = Some(long.to_string_lossy().into_owned());
    }
    // The listing holds every entry's long name. An entry listed under `name`
    // is the entry `name` reaches (a directory never holds a short name equal
    // to another entry's long name); with none, `name` reached another entry.
    let listed = if dir.as_os_str().is_empty() {
        Path::new(".")
    } else {
        dir
    };
    for entry in std::fs::read_dir(listed)? {
        if own(&entry?.file_name()) {
            return Ok(Lookup::Own);
        }
    }
    Ok(Lookup::Alias(ShortNameAlias {
        requested: name.to_string_lossy().into_owned(),
        existing,
    }))
}

/// [`short_name_alias`] on every target, for core's own write paths (which
/// build for wasm too, where nothing is looked up).
pub(crate) fn alias_below(base: &Path, rel: &Path) -> io::Result<Option<ShortNameAlias>> {
    let names: Vec<&std::ffi::OsStr> = rel
        .components()
        .filter(|component| !matches!(component, Component::CurDir))
        .map(|component| match component {
            Component::Normal(name) => Ok(name),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{}: not a relative path of plain names", rel.display()),
            )),
        })
        .collect::<io::Result<_>>()?;
    #[cfg(windows)]
    {
        let mut dir = base.to_path_buf();
        for name in names {
            match lookup(&dir, name)? {
                // Nothing below a missing entry exists either.
                Lookup::Missing => return Ok(None),
                Lookup::Own => dir.push(name),
                Lookup::Alias(alias) => return Ok(Some(alias)),
            }
        }
    }
    #[cfg(not(windows))]
    let _ = (base, names);
    Ok(None)
}

/// Whether creating, truncating, replacing or deleting `base/rel` would touch
/// a DIFFERENT existing entry that a component of `rel` reaches through
/// another of its names (on Windows, an 8.3 short name: `REPORT~1.PDF` for
/// `Report for 2026.pdf`).
///
/// `rel` is walked below `base` one component at a time; `base` itself is
/// trusted (a root the user chose may well be written as a short name). Pass
/// the directory as `base` and the name as `rel` for one name.
///
/// - `Ok(None)`: no conflict. Every component that exists is its entry's own
///   long name (in any case, as NTFS compares), and the first that does not
///   exist ends the walk.
/// - `Ok(Some(conflict))`: a name conflict. Take the conflict path ("(2)", a
///   conflict copy) or refuse; never open, truncate, replace or delete it.
/// - `Err(_)`: the check could not finish, or `rel` is not a relative path of
///   plain names (`..`, a root or a prefix). Refuse.
///
/// Only Windows resolves a name to a differently named entry, so on every
/// other host this answers `Ok(None)` (after checking `rel`) without touching
/// the disk. [`super::safe_child`], [`super::safe_rel_join`] and
/// [`super::default_output_path`] already refuse such a name.
#[cfg(not(target_arch = "wasm32"))]
pub fn short_name_alias(base: &Path, rel: &Path) -> io::Result<Option<ShortNameAlias>> {
    alias_below(base, rel)
}

/// `path` as a directory and its last component: the one name a write to
/// `path` creates or replaces. `None` when `path` names no entry (`/`, `..`).
fn split_last(path: &Path) -> Option<(&Path, &Path)> {
    let name = path.file_name()?;
    Some((path.parent().unwrap_or(Path::new("")), Path::new(name)))
}

/// The `String` refusal of [`super::safe_child`], [`super::safe_rel_join`] and
/// [`super::default_output_path`].
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn refuse_alias(base: &Path, rel: &Path) -> Result<(), String> {
    match alias_below(base, rel) {
        Ok(None) => Ok(()),
        Ok(Some(conflict)) => Err(conflict.to_string()),
        Err(error) => Err(format!(
            "{}: cannot check the name against the existing entries ({error})",
            base.join(rel).display()
        )),
    }
}

/// Refuse a write to `path` whose last component reaches a different existing
/// entry: the conflict is [`CoreError::InvalidInput`] naming it (core's error
/// type cannot grow a variant in a patch release), a failed check is
/// [`CoreError::Io`].
pub(crate) fn refuse_alias_at(path: &Path) -> Result<(), CoreError> {
    let Some((dir, name)) = split_last(path) else {
        return Ok(());
    };
    match alias_below(dir, name) {
        Ok(None) => Ok(()),
        Ok(Some(conflict)) => Err(CoreError::InvalidInput(conflict.to_string())),
        Err(error) => Err(CoreError::Io(format!(
            "{}: cannot check the name against the existing entries: {error}",
            path.display()
        ))),
    }
}

/// Write `output` through its sibling `tmp`: `write` fills `tmp`, which is
/// then renamed over `output`; on any error after `tmp` may exist, `tmp` is
/// removed, so no partial plaintext survives at either name.
///
/// Before `tmp` is created, neither name may reach a different existing entry
/// ([`refuse_alias_at`]), and `output` is checked again just before the
/// rename, since a decrypt can take a while.
pub(crate) fn write_through_tmp<T>(
    output: &Path,
    tmp: &Path,
    write: impl FnOnce() -> Result<T, CoreError>,
) -> Result<T, CoreError> {
    refuse_alias_at(output)?;
    refuse_alias_at(tmp)?;
    let result = write().and_then(|value| {
        refuse_alias_at(output)?;
        std::fs::rename(tmp, output).map_err(|e| CoreError::Io(format!("rename output: {e}")))?;
        Ok(value)
    });
    if result.is_err() {
        // Drop the temp so it can't poison a cache.
        std::fs::remove_file(tmp).ok();
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decide(requested: &str, existing_long: &str) -> bool {
        is_own_name(requested.encode_utf16(), existing_long.encode_utf16())
    }

    /// The pairs a Windows lookup produces: the name asked for and the long
    /// name of the entry it reached. Another long name is a name conflict.
    #[test]
    fn another_long_name_is_a_name_conflict() {
        for (requested, existing) in [
            ("REPORT~1.PDF", "Report for 2026.pdf"),
            ("PHOTOS~1", "Photos 2026"),
            ("REPORT~1.TMP", "Report for 2026.tmp"),
            ("0.ENC", "chunk zero backup.enc"),
            ("report~1.pdf", "Report for 2026.pdf"),
            // NTFS does not fold `ß` to `SS`: these are two names.
            ("STRASSE.TXT", "straße.txt"),
            // Nor characters outside the BMP (Deseret capital and small long I).
            ("\u{10400}.txt", "\u{10428}.txt"),
            // A trailing dot is stripped by the Win32 lookup, never by NTFS.
            ("Report.pdf.", "Report.pdf"),
        ] {
            assert!(
                !decide(requested, existing),
                "{requested} reaching {existing} is a name conflict"
            );
        }
    }

    /// The entry's own long name in any case (NTFS compares case-insensitively,
    /// one UTF-16 unit at a time) is that entry, and a real name with `~` in it
    /// is just a name.
    #[test]
    fn the_same_long_name_in_any_case_is_the_same_entry() {
        for (requested, existing) in [
            ("Report for 2026.pdf", "Report for 2026.pdf"),
            ("report FOR 2026.PDF", "Report for 2026.pdf"),
            ("REPORT~1.PDF", "REPORT~1.PDF"),
            ("report~1.pdf", "REPORT~1.PDF"),
            ("ÄRGER.TXT", "ärger.txt"),
            ("ΣΟΦΊΑ", "σοφία"),
            ("ǅ", "ǆ"),
            ("\u{10400}.txt", "\u{10400}.TXT"),
        ] {
            assert!(decide(requested, existing), "{requested} is {existing}'s own name");
        }
    }

    #[test]
    fn the_conflict_names_the_request_and_the_entry_it_reaches() {
        let mut conflict = ShortNameAlias {
            requested: "REPORT~1.PDF".into(),
            existing: Some("Report for 2026.pdf".into()),
        };
        assert_eq!(
            conflict.to_string(),
            "name conflict: \"REPORT~1.PDF\" reaches the existing entry \"Report for 2026.pdf\" through an 8.3 \
             short name or another alias; refusing to touch it"
        );
        conflict.existing = None;
        assert_eq!(
            conflict.to_string(),
            "name conflict: \"REPORT~1.PDF\" reaches a different existing entry through an 8.3 short name or \
             another alias; refusing to touch it"
        );
    }

    /// The check takes a relative path of plain names on every host: a `..`,
    /// a root or a prefix is refused, never walked.
    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn only_a_relative_path_of_plain_names_is_checked() {
        let base = std::env::temp_dir();
        for rel in ["../x", "a/../b", "/etc/x"] {
            let error = short_name_alias(&base, Path::new(rel)).expect_err(rel);
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput, "{rel}");
        }
        for rel in ["", ".", "./beebeeb-no-such-entry", "beebeeb-no-such-dir/x"] {
            assert_eq!(short_name_alias(&base, Path::new(rel)).unwrap(), None, "{rel}");
        }
    }
}

#[cfg(all(test, windows))]
#[path = "short_name_windows_tests.rs"]
mod windows_tests;
