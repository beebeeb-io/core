//! The backup tree: `Backups/<device folder>/<category display name>/<path>`
//! (spec §4.2 rule 1).

use beebeeb_types::backup::Category;

use super::device::{NAME_MAX_BYTES, clean_name};
use super::fold_name;

/// The root folder's name. It identifies nothing: the root is the folder with
/// the `backups_root` role.
pub const ROOT_NAME: &str = "Backups";

/// The encrypted device manifest in each device folder.
pub const MANIFEST_NAME: &str = ".device.json";

/// The folder name when a custom folder's name has nothing usable in it.
const CUSTOM_FALLBACK_NAME: &str = "Folder";

/// The server folder of a category under `Backups/<device>/`: a fixed
/// category's display name, or a custom name made safe for one path component
/// by the device-folder rule (a name from [`custom_category_name`] is
/// unchanged). Clients name the category folder
/// with this, never with the raw `Category::display_name`.
pub fn category_folder_name(category: &Category) -> String {
    match category {
        Category::Custom(name) => clean_name(name, CUSTOM_FALLBACK_NAME),
        fixed => fixed.display_name().to_string(),
    }
}

/// The name of a custom backup folder the person adds (review #5): `raw`, the
/// folder's own name, made safe by the device-folder rule, and never equal
/// (compared with `fold_name`) to a fixed category's folder or to one of
/// `taken`, the device's other custom folder names: it gets ` (2)`, ` (3)`,
/// ... The whole name, suffix included, is at most 200 UTF-8 bytes: the base
/// is cut to make room, never the suffix, so [`category_folder_name`] gives
/// the name back unchanged. The client stores the result as
/// `Category::Custom(name)` when the folder is added, so the name never
/// changes afterwards.
pub fn custom_category_name(raw: &str, taken: &[&str]) -> String {
    let used: Vec<String> = Category::FIXED
        .iter()
        .map(|c| fold_name(c.display_name()))
        .chain(taken.iter().map(|t| fold_name(t)))
        .collect();
    let base = clean_name(raw, CUSTOM_FALLBACK_NAME);
    let mut candidate = base.clone();
    let mut n = 2;
    while used.contains(&fold_name(&candidate)) {
        let suffix = format!(" ({n})");
        candidate = format!("{}{suffix}", cut_to(&base, NAME_MAX_BYTES - suffix.len()));
        n += 1;
    }
    candidate
}

/// The longest prefix of `name` of at most `max` bytes, cut at a character
/// boundary.
fn cut_to(name: &str, max: usize) -> &str {
    let mut end = max.min(name.len());
    while !name.is_char_boundary(end) {
        end -= 1;
    }
    &name[..end]
}

/// `Backups/<device_folder>/<category folder>/<rel>`, with `/` between
/// segments. An empty `rel` is the category folder itself. `rel` is a backup
/// key (`/`-separated, no leading `/`). The category folder is
/// [`category_folder_name`].
pub fn backup_rel_path(device_folder: &str, category: &Category, rel: &str) -> String {
    let mut path = format!("{ROOT_NAME}/{device_folder}/{}", category_folder_name(category));
    if !rel.is_empty() {
        path.push('/');
        path.push_str(rel);
    }
    path
}
