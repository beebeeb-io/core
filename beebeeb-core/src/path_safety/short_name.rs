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
/// table holds the Unicode SIMPLE uppercase of each code unit, one unit for
/// one. A letter without a one-letter uppercase (`ß`, whose full uppercase is
/// `SS`) or whose uppercase lies outside the Basic Multilingual Plane stays as
/// it is, and so does a surrogate (characters outside the BMP are compared
/// exactly).
///
/// A known limit: NTFS compares with the volume's own `$UpCase` table, written
/// when the volume was formatted, while this uses Rust's current Unicode
/// tables. The default table maps `ı` (U+0131) and `ſ` (U+017F) to themselves
/// where `char` maps them to `I` and `S`, and tables written by older Windows
/// versions lack case pairs added to Unicode since. Folding more than the
/// volume errs toward "own name", but only for a long name equal to the
/// requested short name but for such letters, which needs a contrived name.
#[cfg_attr(not(windows), allow(dead_code))] // the Windows lookup; tests everywhere
fn upcase_unit(unit: u16) -> u16 {
    // The 27 BMP letters whose full uppercase is two letters but whose simple
    // uppercase is one: Greek with ypogegrammeni (`ᾳ` → `ᾼ`). `char` has only
    // the full mapping.
    match unit {
        0x1F80..=0x1F87 | 0x1F90..=0x1F97 | 0x1FA0..=0x1FA7 => return unit + 8,
        0x1FB3 | 0x1FC3 | 0x1FF3 => return unit + 9,
        _ => {}
    }
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

/// Whether `name` has the shape of an 8.3 name: 1 to 8 code units, then
/// optionally a dot and 1 to 3 more, and no other dot. It only selects the
/// extra listing check in [`judge`]; it never decides.
#[cfg_attr(not(windows), allow(dead_code))] // the Windows lookup; tests everywhere
fn has_short_shape(name: &[u16]) -> bool {
    let mut parts = name.split(|&unit| unit == u16::from(b'.'));
    let base = parts.next().unwrap_or_default();
    let extension = parts.next();
    parts.next().is_none()
        && (1..=8).contains(&base.len())
        && extension.is_none_or(|extension| (1..=3).contains(&extension.len()))
}

/// What the lookup decides about one existing entry.
#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(not(windows), allow(dead_code))] // the Windows lookup; tests everywhere
enum Verdict {
    /// The entry's own long name is the requested name.
    Own,
    /// A different entry, with this long name when it is known.
    Alias(Option<Vec<u16>>),
}

/// The lookup's decision for an entry that `requested` reaches, from what the
/// file system answered: `canonical` is the long name the handle reports
/// (`None` for a link, which the handle opens through, or when the handle
/// could not be opened), and `listed` says whether the directory listing holds
/// an entry whose long name is `requested`.
///
/// A handle that reports another long name is final. One that reports the
/// requested name itself is final too, unless that name has the shape of an
/// 8.3 name: some file systems and redirectors (older SMB dialects,
/// third-party drivers) answer with the name as opened, so the listing
/// confirms it. Without a handle answer the listing decides. (The listing
/// holds every long name, and a directory never holds a short name equal to
/// another entry's long name, so an entry listed under `requested` is the
/// entry it reaches. In a folder made case-sensitive, a short name could still
/// match another entry's long name in a different case: a limit of the
/// listing.)
#[cfg_attr(not(windows), allow(dead_code))] // the Windows lookup; tests everywhere
fn judge(
    requested: &[u16],
    canonical: Option<&[u16]>,
    listed: impl FnOnce() -> io::Result<bool>,
) -> io::Result<Verdict> {
    let own = |long: &[u16]| is_own_name(requested.iter().copied(), long.iter().copied());
    match canonical {
        Some(long) if !own(long) => return Ok(Verdict::Alias(Some(long.to_vec()))),
        Some(_) if !has_short_shape(requested) => return Ok(Verdict::Own),
        Some(_) | None => {}
    }
    Ok(if listed()? { Verdict::Own } else { Verdict::Alias(None) })
}

/// What a path's components name on disk ([`walk`]).
#[derive(Debug)]
#[cfg_attr(not(windows), allow(dead_code))] // only Windows looks names up
pub(crate) enum Walk {
    /// A component does not exist: a create makes exactly this name.
    Missing,
    /// Every component exists under its own long name.
    Own,
    /// A component reaches a different entry.
    Alias(ShortNameAlias),
    /// Not looked up: this host never resolves a name to another entry.
    Unchecked,
}

/// Look `name` up in `dir`.
#[cfg(windows)]
fn lookup(dir: &Path, name: &std::ffi::OsStr) -> io::Result<Walk> {
    use std::os::windows::ffi::OsStrExt as _;
    let path = dir.join(name);
    let meta = match std::fs::symlink_metadata(&path) {
        Ok(meta) => meta,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Walk::Missing),
        Err(error) => return Err(error),
    };
    let requested: Vec<u16> = name.encode_wide().collect();
    // `canonicalize` opens the entry the name reaches and asks that handle for
    // its normalized path (GetFinalPathNameByHandleW), whose last component is
    // the entry's own long name.
    let canonical: Option<Vec<u16>> = if meta.file_type().is_symlink() {
        None
    } else {
        std::fs::canonicalize(&path)
            .ok()
            .and_then(|canonical| canonical.file_name().map(|long| long.encode_wide().collect()))
    };
    let listed = || -> io::Result<bool> {
        let listed_dir = if dir.as_os_str().is_empty() {
            Path::new(".")
        } else {
            dir
        };
        for entry in std::fs::read_dir(listed_dir)? {
            if is_own_name(requested.iter().copied(), entry?.file_name().encode_wide()) {
                return Ok(true);
            }
        }
        Ok(false)
    };
    Ok(match judge(&requested, canonical.as_deref(), listed)? {
        Verdict::Own => Walk::Own,
        Verdict::Alias(existing) => Walk::Alias(ShortNameAlias {
            requested: name.to_string_lossy().into_owned(),
            existing: existing.map(|long| String::from_utf16_lossy(&long)),
        }),
    })
}

/// Walk `rel` below `base` one component at a time (`base` is trusted), on
/// every target: core's own write paths build for wasm too.
pub(crate) fn walk(base: &Path, rel: &Path) -> io::Result<Walk> {
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
                Walk::Own => dir.push(name),
                // Nothing below a missing entry exists either.
                other => return Ok(other),
            }
        }
        Ok(Walk::Own)
    }
    #[cfg(not(windows))]
    {
        let _ = (base, names);
        Ok(Walk::Unchecked)
    }
}

/// [`walk`] for the last component of `path`, the one name a write to `path`
/// creates or replaces (its directory is the caller's). A path that names no
/// entry (`/`, `..`) is not looked up.
pub(crate) fn walk_last(path: &Path) -> io::Result<Walk> {
    let Some(name) = path.file_name() else {
        return Ok(Walk::Unchecked);
    };
    walk(path.parent().unwrap_or(Path::new("")), Path::new(name))
}

fn alias_only(walked: Walk) -> Option<ShortNameAlias> {
    match walked {
        Walk::Alias(conflict) => Some(conflict),
        Walk::Missing | Walk::Own | Walk::Unchecked => None,
    }
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
/// [`super::default_output_path`] already refuse such a name, and
/// [`super::TempSibling`] writes a file without ever touching such an entry.
#[cfg(not(target_arch = "wasm32"))]
pub fn short_name_alias(base: &Path, rel: &Path) -> io::Result<Option<ShortNameAlias>> {
    walk(base, rel).map(alias_only)
}

/// The `String` refusal of [`super::safe_child`], [`super::safe_rel_join`] and
/// [`super::default_output_path`].
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn refuse_alias(base: &Path, rel: &Path) -> Result<(), String> {
    match walk(base, rel).map(alias_only) {
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
    match walk_last(path).map(alias_only) {
        Ok(None) => Ok(()),
        Ok(Some(conflict)) => Err(CoreError::InvalidInput(conflict.to_string())),
        Err(error) => Err(CoreError::Io(format!(
            "{}: cannot check the name against the existing entries: {error}",
            path.display()
        ))),
    }
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
            // Simple uppercase, not full: `ᾳ` is `ᾼ` (full uppercase `ΑΙ`).
            ("ᾳ.txt", "ᾼ.txt"),
            ("ᾀ", "ᾈ"),
            ("ῳ", "ῼ"),
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

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().collect()
    }

    fn listing_not_asked() -> io::Result<bool> {
        panic!("the handle's answer is final here; the listing must not be read")
    }

    /// A handle that reports another long name is final, and so is one that
    /// reports a requested name without an 8.3 shape.
    #[test]
    fn a_final_handle_answer_needs_no_listing() {
        assert_eq!(
            judge(
                &wide("REPORT~1.PDF"),
                Some(&wide("Report for 2026.pdf")),
                listing_not_asked
            )
            .unwrap(),
            Verdict::Alias(Some(wide("Report for 2026.pdf")))
        );
        assert_eq!(
            judge(
                &wide("report FOR 2026.PDF"),
                Some(&wide("Report for 2026.pdf")),
                listing_not_asked
            )
            .unwrap(),
            Verdict::Own
        );
    }

    /// Some redirectors (older SMB dialects) and third-party drivers answer with
    /// the name as opened: an 8.3-shaped name the handle reports as its own is
    /// confirmed against the listing.
    #[test]
    fn an_eight_three_name_the_handle_reports_as_its_own_is_confirmed_by_the_listing() {
        assert_eq!(
            judge(&wide("REPORT~1.PDF"), Some(&wide("REPORT~1.PDF")), || Ok(false)).unwrap(),
            Verdict::Alias(None),
            "the listing holds no entry with that long name: it reached another entry"
        );
        assert_eq!(
            judge(&wide("IMG_0001.JPG"), Some(&wide("IMG_0001.JPG")), || Ok(true)).unwrap(),
            Verdict::Own
        );
        let failed = judge(&wide("A.TXT"), Some(&wide("A.TXT")), || {
            Err(io::Error::other("listing failed"))
        });
        assert_eq!(failed.unwrap_err().to_string(), "listing failed");
    }

    /// Without a handle answer (a link, or an entry the handle cannot open),
    /// the listing decides.
    #[test]
    fn without_a_handle_answer_the_listing_decides() {
        assert_eq!(judge(&wide("Photos link"), None, || Ok(true)).unwrap(), Verdict::Own);
        assert_eq!(
            judge(&wide("PHOTOS~1"), None, || Ok(false)).unwrap(),
            Verdict::Alias(None)
        );
    }

    #[test]
    fn the_eight_three_shape() {
        for name in ["A", "REPORT~1", "REPORT~1.PDF", "IMG_0001.JPG", "a.b", "12345678.123"] {
            assert!(has_short_shape(&wide(name)), "{name}");
        }
        for name in [
            "",
            ".pdf",
            "name.",
            "123456789",
            "REPORT~1.PDFX",
            "a.b.c",
            "Report for 2026.pdf",
        ] {
            assert!(!has_short_shape(&wide(name)), "{name}");
        }
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
