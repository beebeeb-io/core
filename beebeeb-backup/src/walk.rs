//! Walking a backed-up folder (spec §4.3).
//!
//! The walk lists names and reads attributes only: it never opens a file, so
//! walking cannot hydrate a OneDrive or iCloud placeholder. It never follows a
//! symlink or junction, never leaves the root (every path is the root plus
//! names read from its own listings), never descends into a folder it skips,
//! and never enters a path the client excludes (its own sync root).

use std::collections::{HashMap, HashSet};
use std::ffi::OsStr;
use std::fs::{DirEntry, Metadata};
use std::io;
use std::path::{Component, Path, PathBuf, Prefix};

use beebeeb_core::backup::{EntryAttrs, SkipReason, SourceEntry, fold_name, skip_reason};
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
    /// was not descended into. A key ending in NUL marks a name that cannot
    /// be told apart from another one in its folder once read as Unicode (a
    /// non-UTF-8 name); NUL is in no file name, so it covers no other key.
    pub skipped: Vec<(String, SkipReason)>,
}

impl WalkResult {
    /// Every key the walk did not look at or into. A record at or under
    /// one of them is not gone: the planner leaves it untouched (plan
    /// Amendment 1, items 5-6).
    pub fn unseen(&self) -> Vec<String> {
        self.skipped.iter().map(|(key, _)| key.clone()).collect()
    }
}

/// A walk plus the real path of every file entry. The key is NFC on macOS
/// (the path is what is on disk, which can be NFD) and the name itself on
/// Linux and Windows (spec Amendment 5).
pub(crate) struct Walk {
    pub(crate) result: WalkResult,
    pub(crate) paths: HashMap<String, PathBuf>,
}

/// Windows file attribute bits (`winnt.h`) that say the bytes are not here.
const FILE_ATTRIBUTE_OFFLINE: u32 = 0x1000;
const FILE_ATTRIBUTE_RECALL_ON_OPEN: u32 = 0x0004_0000;
const FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS: u32 = 0x0040_0000;
/// macOS `st_flags`: the file's data is not on this device (`sys/stat.h`).
const SF_DATALESS: u32 = 0x4000_0000;

/// The pure decoding behind [`attrs_of`], testable on every host.
///
/// `link_or_special` is std's `FileType::is_symlink()` (or anything that is
/// neither a file nor a folder). On Windows std reads the reparse TAG's
/// name-surrogate bit: true for symlinks and junctions, false for a cloud
/// placeholder. The raw `FILE_ATTRIBUTE_REPARSE_POINT` bit is NOT a link:
/// OneDrive marks every file and folder with it, local ones included, and
/// a placeholder whose bytes are not here carries a recall or offline bit
/// instead, which makes it not local (never read). Plan Amendment 1, item 7.
/// `windows_attributes` / `st_flags`: the platform's attribute word, `None`
/// elsewhere.
pub(crate) fn attrs_from_parts(
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
    }
    if let Some(flags) = st_flags {
        attrs.not_local |= flags & SF_DATALESS != 0;
    }
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
/// not follow links and, on Windows, must come from the directory listing
/// (`DirEntry::metadata`), never from `fs::metadata` / `fs::symlink_metadata`
/// on its path: those open a handle, and a handle on a recall-on-open folder
/// can fetch it. The `.icloud` stub rule is a name rule, in
/// `beebeeb_core::backup::skip_reason`.
pub fn attrs_of(meta: &Metadata) -> EntryAttrs {
    let kind = meta.file_type();
    attrs_from_parts(
        kind.is_dir(),
        kind.is_symlink() || !(kind.is_dir() || kind.is_file()),
        windows_attributes(meta),
        st_flags(meta),
    )
}

/// Walk `root`, a folder the person chose to back up. Only a root that cannot
/// be read, whole or in part, is an error; inside it, what cannot be read is
/// reported as [`SkipReason::Unreadable`] and the rest of the walk goes on.
///
/// - `exclude`: paths the walk never lists, reads or descends into, each
///   reported as [`SkipReason::Excluded`] (plan Amendment 1, item 8). Desktop
///   passes its sync root, the CLI its own sync folders: otherwise a sync root
///   inside a backed-up folder would back the drive, its own Backups
///   included, up into Backups. Each is absolute and without `..`; an empty,
///   relative or `..` path is an `InvalidInput` error, never "exclude
///   everything". They are compared with `root` component by component (a
///   relative `root` is made absolute first, without touching the disk), and
///   without case on Windows and macOS, so spell both from the same base. A
///   `root` that itself lies inside an excluded path is refused by the client
///   (desktop D4), not here; passed anyway, every entry is excluded and
///   nothing is backed up.
/// - Attributes come from the directory listing alone (plan Amendment 1, item
///   9): on Windows `DirEntry::metadata` is served from the `FindNextFileW`
///   data with no handle opened, so a not-local entry is known before anything
///   touches it, and a folder that says not local is never listed.
pub fn walk_source(root: &Path, exclude: &[PathBuf]) -> io::Result<WalkResult> {
    walk_with_paths(root, exclude).map(|walk| walk.result)
}

pub(crate) fn walk_with_paths(root: &Path, exclude: &[PathBuf]) -> io::Result<Walk> {
    // The root itself may be a link (an XDG folder on another disk): it is the
    // person's choice, so it is followed. Nothing inside it is.
    if !std::fs::metadata(root)?.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::NotADirectory,
            "the backed-up folder is not a folder",
        ));
    }
    let excludes = Excludes::new(root, exclude, CASE_INSENSITIVE)?;
    let mut walk = Walk {
        result: WalkResult::default(),
        paths: HashMap::new(),
    };
    let mut seen: HashSet<String> = HashSet::new();
    // Each folder carries the excluded paths that still run through it.
    let mut stack: Vec<(PathBuf, String, usize, Vec<usize>)> =
        vec![(root.to_path_buf(), String::new(), 0, excludes.everywhere())];
    while let Some((dir, prefix, depth, through)) = stack.pop() {
        let listing = match list(&dir) {
            Ok(listing) => listing,
            // The backed-up folder itself, whole or partly unreadable: the
            // pass stops, so no record is ever judged against half a listing.
            Err(e) if depth == 0 => return Err(e),
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(_) => {
                walk.result.skipped.push((prefix.clone(), SkipReason::Unreadable));
                continue;
            }
        };
        for (name, item) in listing {
            let Some(key) = unique_key(&prefix, &name, &mut seen) else {
                walk.result
                    .skipped
                    .push((format!("{}\0", join(&prefix, &name)), SkipReason::Unreadable));
                continue;
            };
            let path = item.path();
            let Some(through_child) = excludes.step(&through, depth, &item.file_name()) else {
                walk.result.skipped.push((key, SkipReason::Excluded));
                continue;
            };
            if depth + 1 > MAX_DEPTH {
                walk.result.skipped.push((key, SkipReason::TooDeep));
                continue;
            }
            // From the listing, never from the path: on Windows this is the
            // FindNextFileW data, so no handle is opened before the not-local
            // check below (plan Amendment 1, item 9).
            let meta = match item.metadata() {
                Ok(meta) => meta,
                Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                Err(_) => {
                    walk.result.skipped.push((key, SkipReason::Unreadable));
                    continue;
                }
            };
            let attrs = attrs_of(&meta);
            // A skipped folder, a not-local one above all, is never listed.
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
                stack.push((path, key, depth + 1, through_child));
            } else {
                walk.paths.insert(key, path);
            }
        }
    }
    walk.result.entries.sort_by(|a, b| a.key.cmp(&b.key));
    walk.result.skipped.sort();
    walk.result.skipped.dedup();
    Ok(walk)
}

/// The whole listing of `dir`, or an error. A folder is listed completely or
/// not at all: a listing that fails partway must not leave some of its files
/// planned while the folder is reported unreadable and its records are set
/// aside (they would be uploaded again). Sorted by name, so every pass lists
/// a folder in the same order.
fn list(dir: &Path) -> io::Result<Vec<(String, DirEntry)>> {
    collect_listing(
        std::fs::read_dir(dir)?.map(|item| item.map(|item| (item.file_name().to_string_lossy().into_owned(), item))),
    )
}

/// [`list`] over any listing, so a failure partway is testable.
pub(crate) fn collect_listing<T>(
    listing: impl Iterator<Item = io::Result<(String, T)>>,
) -> io::Result<Vec<(String, T)>> {
    let mut items = listing.collect::<io::Result<Vec<_>>>()?;
    items.sort_by(|(a, _), (b, _)| a.cmp(b));
    Ok(items)
}

fn join(prefix: &str, segment: &str) -> String {
    if prefix.is_empty() {
        segment.to_string()
    } else {
        format!("{prefix}/{segment}")
    }
}

/// Keys are NFC on macOS: names can arrive NFD there, and APFS and HFS+
/// cannot hold two names in one folder that differ only in normalisation, so
/// a key never moves from one file to another. Linux and NTFS can hold such
/// twins, so there the key is the name itself: each twin keeps its own key on
/// every pass, whichever appeared first (spec Amendment 5, lead 17:34; review
/// #4). Records under the other form still pair through `normalize_key`.
const NFC_KEYS: bool = cfg!(target_os = "macos");

/// The key of `name` under `prefix` (see [`NFC_KEYS`]). `None` only for two
/// names that read the same after a lossy (non-UTF-8) conversion.
fn unique_key(prefix: &str, name: &str, seen: &mut HashSet<String>) -> Option<String> {
    let key = if NFC_KEYS {
        join(prefix, &name.nfc().collect::<String>())
    } else {
        join(prefix, name)
    };
    seen.insert(key.clone()).then_some(key)
}

/// Windows and macOS (by default) do not tell names apart by case.
const CASE_INSENSITIVE: bool = cfg!(any(windows, target_os = "macos"));

/// A name as the exclusion compares it: with `case_insensitive`, core's
/// `fold_name` (NFC + lowercase, the one fold every backup rule uses);
/// otherwise its exact bytes.
fn name_key(name: &OsStr, case_insensitive: bool) -> Vec<u8> {
    if case_insensitive {
        fold_name(&name.to_string_lossy()).into_bytes()
    } else {
        name.as_encoded_bytes().to_vec()
    }
}

/// One path component as the exclusion compares it. A verbatim prefix
/// (`\\?\C:\`) equals its plain form (`C:\`).
fn component_key(c: Component<'_>, case_insensitive: bool) -> Vec<u8> {
    match c {
        Component::Prefix(p) => match p.kind() {
            Prefix::Disk(d) | Prefix::VerbatimDisk(d) => vec![d.to_ascii_uppercase(), b':'],
            Prefix::UNC(server, share) | Prefix::VerbatimUNC(server, share) => {
                let mut key = b"\\\\".to_vec();
                key.extend(name_key(server, true));
                key.push(b'\\');
                key.extend(name_key(share, case_insensitive));
                key
            }
            _ => p.as_os_str().as_encoded_bytes().to_vec(),
        },
        other => name_key(other.as_os_str(), case_insensitive),
    }
}

fn path_keys(path: &Path, case_insensitive: bool) -> Vec<Vec<u8>> {
    path.components().map(|c| component_key(c, case_insensitive)).collect()
}

/// True when `path` is `base` or lies under it, component by component (the
/// rule [`Excludes`] applies, one path at a time).
#[cfg(test)]
pub(crate) fn is_within(path: &Path, base: &Path, case_insensitive: bool) -> bool {
    let (path, base) = (path_keys(path, case_insensitive), path_keys(base, case_insensitive));
    !base.is_empty() && path.starts_with(&base)
}

/// An empty, relative or `..` excluded path is refused: compared as
/// components, an empty path would cover everything and a relative or `..`
/// one nothing (review finding 3).
pub(crate) fn check_excludes(exclude: &[PathBuf]) -> io::Result<()> {
    for path in exclude {
        if path.as_os_str().is_empty() || !path.is_absolute() || path.components().any(|c| c == Component::ParentDir) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "an excluded path is empty, relative or holds `..`",
            ));
        }
    }
    Ok(())
}

/// The excluded paths, each folded once before the walk into the components
/// left below the root, so an entry's name is folded only while an excluded
/// path still runs through its folder (review finding 10).
pub(crate) struct Excludes {
    /// The root is an excluded path or lies inside one: every entry is.
    root_inside: bool,
    /// Per excluded path under the root, its components below the root.
    below_root: Vec<Vec<Vec<u8>>>,
    case_insensitive: bool,
}

impl Excludes {
    pub(crate) fn new(root: &Path, exclude: &[PathBuf], case_insensitive: bool) -> io::Result<Excludes> {
        check_excludes(exclude)?;
        let root_keys = path_keys(&std::path::absolute(root)?, case_insensitive);
        let mut excludes = Excludes {
            root_inside: false,
            below_root: Vec::new(),
            case_insensitive,
        };
        for path in exclude {
            let keys = path_keys(path, case_insensitive);
            if root_keys.starts_with(&keys) {
                excludes.root_inside = true;
            } else if keys.starts_with(&root_keys) {
                excludes.below_root.push(keys[root_keys.len()..].to_vec());
            }
        }
        Ok(excludes)
    }

    /// Every excluded path below the root: what runs through the root.
    pub(crate) fn everywhere(&self) -> Vec<usize> {
        (0..self.below_root.len()).collect()
    }

    /// For the entry `name` in a folder `depth` below the root that the
    /// excluded paths `through` run through: `None` when the entry is
    /// excluded, else the excluded paths that run on through it.
    pub(crate) fn step(&self, through: &[usize], depth: usize, name: &OsStr) -> Option<Vec<usize>> {
        if self.root_inside {
            return None;
        }
        if through.is_empty() {
            return Some(Vec::new());
        }
        let key = name_key(name, self.case_insensitive);
        let mut on = Vec::new();
        for &i in through {
            let rest = &self.below_root[i];
            if rest[depth] == key {
                if rest.len() == depth + 1 {
                    return None;
                }
                on.push(i);
            }
        }
        Some(on)
    }
}
