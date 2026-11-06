//! Walking a backed-up folder (spec §4.3).
//!
//! The walk lists names and reads attributes only: it never opens a file, so
//! walking cannot hydrate a OneDrive or iCloud placeholder. It never follows a
//! symlink or junction, never leaves the root (every path is the root plus
//! names read from its own listings), and never descends into a folder it
//! skips.

use std::collections::{HashMap, HashSet};
use std::fs::Metadata;
use std::io;
use std::path::{Path, PathBuf};

use beebeeb_core::backup::{EntryAttrs, SkipReason, SourceEntry, skip_reason};
use unicode_normalization::UnicodeNormalization;

use crate::fingerprint::modified_ms;

/// The deepest entry the walk lists, counted from the backed-up folder (its
/// direct children are depth 1).
pub const MAX_DEPTH: usize = 64;

/// What one walk found.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WalkResult {
    /// Files and folders to plan with, sorted by key.
    pub entries: Vec<SourceEntry>,
    /// Entries not backed up, with the reason, sorted by key. A skipped folder
    /// was not descended into.
    pub skipped: Vec<(String, SkipReason)>,
}

impl WalkResult {
    /// Every key the walk did not look at or into (NFC). A record at or under
    /// one of them is not gone: the planner leaves it untouched (plan
    /// Amendment 1, items 5-6).
    pub fn unseen(&self) -> Vec<String> {
        self.skipped.iter().map(|(key, _)| key.clone()).collect()
    }
}

/// A walk plus the real path of every file entry. The key is NFC; the path is
/// what is on disk, which can differ (an NFD name on Linux).
pub(crate) struct Walk {
    pub(crate) result: WalkResult,
    pub(crate) paths: HashMap<String, PathBuf>,
}

/// Windows file attribute bits (`winnt.h`).
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
const FILE_ATTRIBUTE_OFFLINE: u32 = 0x1000;
const FILE_ATTRIBUTE_RECALL_ON_OPEN: u32 = 0x0004_0000;
const FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS: u32 = 0x0040_0000;
/// macOS `st_flags`: the file's data is not on this device (`sys/stat.h`).
const SF_DATALESS: u32 = 0x4000_0000;

fn ends_with_ignore_ascii_case(name: &str, suffix: &str) -> bool {
    let (name, suffix) = (name.as_bytes(), suffix.as_bytes());
    name.len() >= suffix.len() && name[name.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
}

/// The pure decoding behind [`attrs_of`], testable on every host.
/// `link_or_special`: a symlink or anything that is neither a file nor a
/// folder. `windows_attributes` / `st_flags`: the platform's attribute word,
/// `None` on other platforms.
pub(crate) fn attrs_from_parts(
    name: &str,
    is_dir: bool,
    link_or_special: bool,
    windows_attributes: Option<u32>,
    st_flags: Option<u32>,
) -> EntryAttrs {
    let mut attrs = EntryAttrs {
        is_dir,
        is_link: link_or_special,
        not_local: false,
    };
    if let Some(bits) = windows_attributes {
        let recall = FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS | FILE_ATTRIBUTE_RECALL_ON_OPEN | FILE_ATTRIBUTE_OFFLINE;
        attrs.not_local |= bits & recall != 0;
        attrs.is_link |= bits & FILE_ATTRIBUTE_REPARSE_POINT != 0;
    }
    if let Some(flags) = st_flags {
        attrs.not_local |= flags & SF_DATALESS != 0;
    }
    // A legacy iCloud stub: `.<name>.icloud` stands in for an evicted file.
    attrs.not_local |= name.starts_with('.') && ends_with_ignore_ascii_case(name, ".icloud");
    attrs
}

#[cfg(windows)]
fn windows_attributes(meta: &Metadata) -> Option<u32> {
    use std::os::windows::fs::MetadataExt;
    Some(meta.file_attributes())
}

#[cfg(not(windows))]
fn windows_attributes(_meta: &Metadata) -> Option<u32> {
    None
}

#[cfg(target_os = "macos")]
fn st_flags(meta: &Metadata) -> Option<u32> {
    use std::os::macos::fs::MetadataExt;
    Some(meta.st_flags())
}

#[cfg(not(target_os = "macos"))]
fn st_flags(_meta: &Metadata) -> Option<u32> {
    None
}

/// What an entry is, from its metadata (never from opening it). `meta` must
/// not follow links (`symlink_metadata` or `DirEntry::metadata`).
pub fn attrs_of(meta: &Metadata, name: &str) -> EntryAttrs {
    let kind = meta.file_type();
    attrs_from_parts(
        name,
        kind.is_dir(),
        kind.is_symlink() || !(kind.is_dir() || kind.is_file()),
        windows_attributes(meta),
        st_flags(meta),
    )
}

/// Walk `root`, a folder the person chose to back up. Only a root that cannot
/// be read is an error; inside it, what cannot be read is reported as
/// [`SkipReason::Unreadable`] and the rest of the walk goes on.
pub fn walk_source(root: &Path) -> io::Result<WalkResult> {
    walk_with_paths(root).map(|walk| walk.result)
}

pub(crate) fn walk_with_paths(root: &Path) -> io::Result<Walk> {
    // The root itself may be a link (an XDG folder on another disk): it is the
    // person's choice, so it is followed. Nothing inside it is.
    if !std::fs::metadata(root)?.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::NotADirectory,
            "the backed-up folder is not a folder",
        ));
    }
    let mut walk = Walk {
        result: WalkResult::default(),
        paths: HashMap::new(),
    };
    let mut seen: HashSet<String> = HashSet::new();
    let mut stack: Vec<(PathBuf, String, usize)> = vec![(root.to_path_buf(), String::new(), 0)];
    while let Some((dir, prefix, depth)) = stack.pop() {
        let listing = match std::fs::read_dir(&dir) {
            Ok(listing) => listing,
            Err(e) if depth == 0 => return Err(e),
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(_) => {
                unreadable(&mut walk.result, &prefix);
                continue;
            }
        };
        for item in listing {
            let Ok(item) = item else {
                unreadable(&mut walk.result, &prefix);
                break;
            };
            let raw_name = item.file_name();
            let name = raw_name.to_string_lossy();
            let Some(key) = unique_key(&prefix, &name, &mut seen) else {
                unreadable(&mut walk.result, &prefix);
                continue;
            };
            if depth + 1 > MAX_DEPTH {
                walk.result.skipped.push((key, SkipReason::TooDeep));
                continue;
            }
            let meta = match item.metadata() {
                Ok(meta) => meta,
                Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                Err(_) => {
                    walk.result.skipped.push((key, SkipReason::Unreadable));
                    continue;
                }
            };
            let attrs = attrs_of(&meta, &name);
            if let Some(reason) = skip_reason(&name, &attrs) {
                walk.result.skipped.push((key, reason));
                continue;
            }
            walk.result.entries.push(SourceEntry {
                key: key.clone(),
                is_dir: attrs.is_dir,
                size: if attrs.is_dir { 0 } else { meta.len() },
                modified_ms: modified_ms(&meta),
            });
            if attrs.is_dir {
                stack.push((item.path(), key, depth + 1));
            } else {
                walk.paths.insert(key, item.path());
            }
        }
    }
    walk.result.entries.sort_by(|a, b| a.key.cmp(&b.key));
    walk.result.skipped.sort();
    walk.result.skipped.dedup();
    Ok(walk)
}

/// A folder (`prefix`) that could not be listed. The root itself is never
/// reported here: an unreadable root is the walk's error.
fn unreadable(result: &mut WalkResult, prefix: &str) {
    result.skipped.push((prefix.to_string(), SkipReason::Unreadable));
}

/// The key of `name` under `prefix`: NFC, unless that collides with a key
/// already listed (two names in one Linux folder that differ only in
/// normalisation), then the name as it is. `None` when both collide.
fn unique_key(prefix: &str, name: &str, seen: &mut HashSet<String>) -> Option<String> {
    let join = |segment: &str| {
        if prefix.is_empty() {
            segment.to_string()
        } else {
            format!("{prefix}/{segment}")
        }
    };
    [join(&name.nfc().collect::<String>()), join(name)]
        .into_iter()
        .find(|key| seen.insert(key.clone()))
}
