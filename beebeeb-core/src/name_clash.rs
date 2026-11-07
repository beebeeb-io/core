//! The names a clash gives the second item, the same in every client.
//!
//! - [`numbered_name`]: "Keep both" in a prompt gives `report (2).pdf`, then `(3)`,
//!   and so on, until the name is free.
//! - [`drive_conflict_name`]: the drive (Explorer, Finder, the iOS Files app) asks
//!   nothing. A name race and a sync conflict (one file changed in two places)
//!   both keep both, and the device whose write lost names its copy
//!   `report (conflict, <device>).pdf`. Version history keeps every version.
//!
//! A name is free when its normalised form ([`crate::name_tag::normalize_for_tag`])
//! is not in [`TakenNames`], the sibling names the client decrypted. The names
//! come from the incoming name only, never from the existing item's.

use std::collections::HashSet;

use crate::name_tag::normalize_for_tag;
use crate::sync::conflict::{KEEP_BOTH_DEVICE_MAX_BYTES, MAX_NAME_BYTES, prefix_within, safe_device, with_suffix};

/// Whether the item is a file or a folder. A folder's whole name is its stem; a
/// file's extension is the text from its last dot (a name whose only dot leads,
/// `.env`, has none).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ItemKind {
    File,
    Folder,
}

/// The names already in a folder, compared by their normalised form. A name core
/// refuses to normalise (empty, or over 1024 bytes) is kept lowercased, so it
/// still blocks its own spelling.
#[derive(Debug, Clone, Default)]
pub struct TakenNames {
    keys: HashSet<String>,
}

impl TakenNames {
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a sibling's decrypted name.
    pub fn insert(&mut self, name: &str) {
        self.keys.insert(clash_key(name));
    }

    /// Whether `name` clashes with a name already added.
    pub fn contains(&self, name: &str) -> bool {
        self.keys.contains(&clash_key(name))
    }
}

impl<'a> FromIterator<&'a str> for TakenNames {
    fn from_iter<I: IntoIterator<Item = &'a str>>(names: I) -> Self {
        let mut taken = Self::new();
        for name in names {
            taken.insert(name);
        }
        taken
    }
}

fn clash_key(name: &str) -> String {
    normalize_for_tag(name).unwrap_or_else(|_| name.to_lowercase())
}

/// `<name><suffix>` for a folder, or `<stem><suffix><.ext>` for a file, cut to
/// [`MAX_NAME_BYTES`] at a character boundary of the stem.
fn with_kind_suffix(original: &str, kind: ItemKind, suffix: &str) -> String {
    match kind {
        ItemKind::File => with_suffix(original, suffix),
        ItemKind::Folder => fit_whole_with_suffix(original, suffix),
    }
}

/// `<name><suffix>`, the whole name being the stem: the same 255-byte cut as
/// [`with_suffix`], with no extension.
pub(crate) fn fit_whole_with_suffix(name: &str, suffix: &str) -> String {
    let room = MAX_NAME_BYTES.saturating_sub(suffix.len());
    format!("{}{suffix}", prefix_within(name, room))
}

/// The first of `candidates` that is not taken. The candidates differ in their
/// counter, so at most `taken`'s size plus one are tried.
fn first_free(taken: &TakenNames, mut candidates: impl Iterator<Item = String>) -> String {
    candidates
        .find(|candidate| !taken.contains(candidate))
        .expect("the counter runs past every taken name")
}

/// "Keep both": `original` with ` (2)`, ` (3)`, ... until the name is free. The
/// counter goes onto the name as given: `report (2).pdf` gives `report (2) (2).pdf`.
pub fn numbered_name(original: &str, kind: ItemKind, taken: &TakenNames) -> String {
    first_free(
        taken,
        (2u64..).map(|counter| with_kind_suffix(original, kind, &format!(" ({counter})"))),
    )
}

/// The first `count` numbered names, ` (2)` to ` (count + 1)`, for a client that
/// has no decrypted sibling names and probes them instead.
pub fn numbered_candidates(original: &str, kind: ItemKind, count: usize) -> Vec<String> {
    (2u64..)
        .take(count)
        .map(|counter| with_kind_suffix(original, kind, &format!(" ({counter})")))
        .collect()
}

/// The device as it appears in a conflict name: a path separator becomes `_`,
/// the rest goes through the portable path rule, and the result is cut to
/// [`KEEP_BOTH_DEVICE_MAX_BYTES`].
fn drive_device(device: &str) -> String {
    let device = safe_device(&device.replace(['/', '\\'], "_"));
    prefix_within(&device, KEEP_BOTH_DEVICE_MAX_BYTES).to_owned()
}

/// The drive's copy: `original` with ` (conflict, <device>)`, then
/// ` (conflict, <device>) (2)`, ` (3)`, ... until the name is free. `device` is
/// the name of the device whose write lost. It is the one name for both drive
/// cases: a name race and a sync conflict.
pub fn drive_conflict_name(original: &str, kind: ItemKind, device: &str, taken: &TakenNames) -> String {
    let base = format!(" (conflict, {})", drive_device(device));
    let first = std::iter::once(with_kind_suffix(original, kind, &base));
    let numbered = (2u64..).map(|counter| with_kind_suffix(original, kind, &format!("{base} ({counter})")));
    first_free(taken, first.chain(numbered))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_name_core_will_not_normalise_still_blocks_its_own_spelling() {
        let long = format!("{}.txt", "X".repeat(1100));
        let taken: TakenNames = [long.as_str()].into_iter().collect();
        assert!(taken.contains(&long));
        assert!(taken.contains(&long.to_lowercase()));
        assert!(!taken.contains("other.txt"));
    }

    #[test]
    fn the_counter_runs_past_a_long_run_of_taken_names() {
        let names: Vec<String> = (2..=500).map(|n| format!("report ({n}).pdf")).collect();
        let taken: TakenNames = names.iter().map(String::as_str).collect();
        assert_eq!(numbered_name("report.pdf", ItemKind::File, &taken), "report (501).pdf");
    }

    #[test]
    fn a_device_the_path_rule_refuses_is_named_device() {
        assert_eq!(
            drive_conflict_name("a.txt", ItemKind::File, "..", &TakenNames::new()),
            "a (conflict, device).txt"
        );
    }
}
