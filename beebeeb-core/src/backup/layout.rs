//! The backup tree: `Backups/<device folder>/<category display name>/<path>`
//! (spec §4.2 rule 1).

use beebeeb_types::backup::Category;

/// The root folder's name. It identifies nothing: the root is the folder with
/// the `backups_root` role.
pub const ROOT_NAME: &str = "Backups";

/// The encrypted device manifest in each device folder.
pub const MANIFEST_NAME: &str = ".device.json";

/// `Backups/<device_folder>/<category display name>/<rel>`, with `/` between
/// segments. An empty `rel` is the category folder itself. `rel` is a backup
/// key (already normalised, `/`-separated, no leading `/`).
pub fn backup_rel_path(device_folder: &str, category: &Category, rel: &str) -> String {
    let mut path = format!("{ROOT_NAME}/{device_folder}/{}", category.display_name());
    if !rel.is_empty() {
        path.push('/');
        path.push_str(rel);
    }
    path
}
