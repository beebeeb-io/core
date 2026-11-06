//! What is never backed up (spec §4.2 rule 8).
//!
//! Everything else is backed up, hidden files included: a `.git` folder in
//! Documents is the person's data.

use serde::{Deserialize, Serialize};

/// What the walk knows about an entry without opening it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EntryAttrs {
    pub is_dir: bool,
    /// A symlink, junction or other reparse point, or any entry that is
    /// neither a regular file nor a folder: never followed, never read.
    pub is_link: bool,
    /// The entry reports its bytes are not on this device (OneDrive Files
    /// On-Demand, iCloud dataless). Reading it would download it, so it is
    /// counted and shown, never read. A legacy `.icloud` stub is recognised
    /// by its name in [`skip_reason`], whatever this says.
    pub not_local: bool,
}

/// Why an entry is not backed up.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkipReason {
    /// OS bookkeeping: `desktop.ini`, `Thumbs.db`, Office lock files, partial
    /// downloads, `$RECYCLE.BIN`, ...
    Junk,
    /// A macOS library bundle (`*.photoslibrary`, ...): a database that would
    /// upload whole on every change.
    LibraryBundle,
    /// Not followed (see [`EntryAttrs::is_link`]).
    Link,
    /// Its bytes are not on this device. A not-local folder is not descended
    /// into either: listing it would fetch its contents.
    NotLocal,
    /// Another program holds the file locked; it is retried next pass. Set by
    /// the client's uploader.
    Locked,
    /// The server refused the size. Set by the client's uploader.
    TooLarge,
    /// Deeper than the walk's depth cap. Plan Amendment 1 (lead, 2026-11-06).
    TooDeep,
    /// The walk could not list this folder or read this entry's attributes
    /// (permission denied); it is retried next pass and not descended into.
    Unreadable,
    /// A path the client told the walk to leave out (its own sync root): not
    /// listed, not read, not descended into. Plan Amendment 1, item 8.
    Excluded,
}

impl SkipReason {
    /// The stable string the bindings and the vectors use (`"not_local"`, ...).
    pub const fn as_str(self) -> &'static str {
        match self {
            SkipReason::Junk => "junk",
            SkipReason::LibraryBundle => "library_bundle",
            SkipReason::Link => "link",
            SkipReason::NotLocal => "not_local",
            SkipReason::Locked => "locked",
            SkipReason::TooLarge => "too_large",
            SkipReason::TooDeep => "too_deep",
            SkipReason::Unreadable => "unreadable",
            SkipReason::Excluded => "excluded",
        }
    }
}

/// Exact junk names, compared ASCII case-insensitively.
const JUNK_NAMES: &[&str] = &[
    "desktop.ini",
    "Thumbs.db",
    ".DS_Store",
    "Icon\r",
    "$RECYCLE.BIN",
    "System Volume Information",
];
/// Office lock files.
const JUNK_PREFIX: &str = "~$";
/// Partial downloads.
const JUNK_SUFFIXES: &[&str] = &[".crdownload", ".part", ".partial"];
/// macOS library bundles; folders only.
const LIBRARY_SUFFIXES: &[&str] = &[".photoslibrary", ".musiclibrary", ".tvlibrary"];

fn ends_with_ignore_ascii_case(name: &str, suffix: &str) -> bool {
    let (name, suffix) = (name.as_bytes(), suffix.as_bytes());
    name.len() >= suffix.len() && name[name.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
}

fn is_junk(name: &str) -> bool {
    JUNK_NAMES.iter().any(|junk| junk.eq_ignore_ascii_case(name))
        || name.starts_with(JUNK_PREFIX)
        || JUNK_SUFFIXES
            .iter()
            .any(|suffix| ends_with_ignore_ascii_case(name, suffix))
}

/// A legacy iCloud stub, `.<name>.icloud` (ASCII case ignored), stands in for
/// a file whose bytes are not on this Mac.
fn is_icloud_stub(name: &str) -> bool {
    const STUB_SUFFIX: &str = ".icloud";
    name.len() > STUB_SUFFIX.len() + 1 && name.starts_with('.') && ends_with_ignore_ascii_case(name, STUB_SUFFIX)
}

/// `Some(reason)` when the entry `name` (one path component) is never backed
/// up. The name rules come first, then the attributes: a not-local entry is
/// reported as [`SkipReason::NotLocal`] even when it is also a reparse point,
/// so the "online-only" count a client shows is the real one.
pub fn skip_reason(name: &str, attrs: &EntryAttrs) -> Option<SkipReason> {
    if is_junk(name) {
        return Some(SkipReason::Junk);
    }
    if attrs.is_dir
        && LIBRARY_SUFFIXES
            .iter()
            .any(|suffix| ends_with_ignore_ascii_case(name, suffix))
    {
        return Some(SkipReason::LibraryBundle);
    }
    if attrs.not_local || is_icloud_stub(name) {
        return Some(SkipReason::NotLocal);
    }
    if attrs.is_link {
        return Some(SkipReason::Link);
    }
    None
}
