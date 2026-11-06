//! The backup vocabulary every client and the server share (LD-0113, spec
//! `2026-11-06-backup-from-source-design.md` §4.1).
//!
//! The server learns one thing about backups: which folder is the Backups
//! root, through [`SystemRole::BackupsRoot`]. It never learns a device name, a
//! folder name or a file name. The rules that use these words live in
//! `beebeeb_core::backup`.

use serde::{Deserialize, Serialize};

/// The role a server row can carry. A row without the field (an older server)
/// has no role.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SystemRole {
    /// The account's one Backups root (wire: `"backups_root"`).
    BackupsRoot,
}

impl SystemRole {
    /// The wire string, as the server stores and sends it.
    pub const fn as_str(self) -> &'static str {
        match self {
            SystemRole::BackupsRoot => "backups_root",
        }
    }

    /// Parse a wire string. Only the exact wire string is a role: a folder
    /// NAME (`"Backups"`) never is.
    pub fn parse(s: &str) -> Option<SystemRole> {
        match s {
            "backups_root" => Some(SystemRole::BackupsRoot),
            _ => None,
        }
    }
}

/// The server's error code for a refused mutation of a protected folder.
pub const PROTECTED_FOLDER_ERROR: &str = "protected_folder";

/// The server's error code when `PUT /backups/root` can neither use, claim nor
/// create a root.
pub const BACKUPS_ROOT_UNCLAIMABLE_ERROR: &str = "backups_root_unclaimable";

/// The header every request of a backup pass carries, with [`ORIGIN_BACKUP`]
/// (spec Amendment 8, Guus 2026-11-06 19:33): a backup is written by its
/// device's own backup and by nothing else. The server ignores it until
/// phase 2, when it refuses a write in the backup tree that is not tagged.
pub const ORIGIN_HEADER: &str = "X-Beebeeb-Origin";

/// The [`ORIGIN_HEADER`] value of a backup pass's requests.
pub const ORIGIN_BACKUP: &str = "backup";

/// What a backup folder holds. The display name is the folder's name under
/// `Backups/<device>/`, kept byte-for-byte from the names the clients already
/// write.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Category {
    Desktop,
    Documents,
    Pictures,
    Music,
    /// Windows `Videos`, macOS `~/Movies` and the XDG `VIDEOS` folder.
    Videos,
    Downloads,
    CameraRoll,
    Contacts,
    Calendar,
    /// A folder the person picked. The name is its display name.
    Custom(String),
}

const CUSTOM_PREFIX: &str = "custom:";

impl Category {
    /// Every category except [`Category::Custom`], in display order.
    pub const FIXED: [Category; 9] = [
        Category::Desktop,
        Category::Documents,
        Category::Pictures,
        Category::Music,
        Category::Videos,
        Category::Downloads,
        Category::CameraRoll,
        Category::Contacts,
        Category::Calendar,
    ];

    /// The stable key used in records and manifests: `"desktop"` …
    /// `"downloads"`, `"camera_roll"`, `"contacts"`, `"calendar"`, and
    /// `"custom:<name>"` for a custom folder.
    pub fn key(&self) -> String {
        match self {
            Category::Desktop => "desktop".to_string(),
            Category::Documents => "documents".to_string(),
            Category::Pictures => "pictures".to_string(),
            Category::Music => "music".to_string(),
            Category::Videos => "videos".to_string(),
            Category::Downloads => "downloads".to_string(),
            Category::CameraRoll => "camera_roll".to_string(),
            Category::Contacts => "contacts".to_string(),
            Category::Calendar => "calendar".to_string(),
            Category::Custom(name) => format!("{CUSTOM_PREFIX}{name}"),
        }
    }

    /// The inverse of [`Category::key`]. An unknown key, or a custom key with
    /// an empty name, is `None`.
    pub fn from_key(key: &str) -> Option<Category> {
        if let Some(name) = key.strip_prefix(CUSTOM_PREFIX) {
            return (!name.is_empty()).then(|| Category::Custom(name.to_string()));
        }
        Category::FIXED.into_iter().find(|c| c.key() == key)
    }

    /// The person-facing name. For a custom folder this is the stored name as
    /// given; the server folder is `beebeeb_core::backup::category_folder_name`,
    /// and a new custom name comes from `custom_category_name`, which makes it
    /// safe and unique.
    pub fn display_name(&self) -> &str {
        match self {
            Category::Desktop => "Desktop",
            Category::Documents => "Documents",
            Category::Pictures => "Pictures",
            Category::Music => "Music",
            Category::Videos => "Videos",
            Category::Downloads => "Downloads",
            Category::CameraRoll => "Camera Roll",
            Category::Contacts => "Contacts",
            Category::Calendar => "Calendar",
            Category::Custom(name) => name,
        }
    }
}

/// The platform a device runs. Desktop platforms back up folders; iOS and
/// Android back up the camera roll, contacts and calendar.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Platform {
    Windows,
    Macos,
    Linux,
    Ios,
    Android,
    Cli,
}

impl Platform {
    /// Every platform, in declaration order.
    pub const ALL: [Platform; 6] = [
        Platform::Windows,
        Platform::Macos,
        Platform::Linux,
        Platform::Ios,
        Platform::Android,
        Platform::Cli,
    ];

    /// The wire string (the serde form): `"windows"`, `"macos"`, ...
    pub const fn as_str(self) -> &'static str {
        match self {
            Platform::Windows => "windows",
            Platform::Macos => "macos",
            Platform::Linux => "linux",
            Platform::Ios => "ios",
            Platform::Android => "android",
            Platform::Cli => "cli",
        }
    }

    /// Parse the exact wire string; anything else is `None`.
    pub fn parse(s: &str) -> Option<Platform> {
        Platform::ALL.into_iter().find(|p| p.as_str() == s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_role_wire_string_is_backups_root() {
        assert_eq!(
            serde_json::to_string(&SystemRole::BackupsRoot).unwrap(),
            "\"backups_root\""
        );
        assert_eq!(SystemRole::parse("backups_root"), Some(SystemRole::BackupsRoot));
        assert_eq!(SystemRole::parse("Backups"), None);
    }

    #[test]
    fn category_keys_and_names_round_trip() {
        for c in Category::FIXED {
            assert_eq!(Category::from_key(&c.key()), Some(c.clone()), "{c:?}");
        }
        assert_eq!(Category::CameraRoll.display_name(), "Camera Roll");
        assert_eq!(Category::Videos.display_name(), "Videos");
    }

    #[test]
    fn platform_serde_is_lowercase() {
        assert_eq!(serde_json::to_string(&Platform::Macos).unwrap(), "\"macos\"");
        // as_str / parse are the serde form exactly.
        for p in Platform::ALL {
            assert_eq!(serde_json::to_string(&p).unwrap(), format!("\"{}\"", p.as_str()));
            assert_eq!(Platform::parse(p.as_str()), Some(p));
        }
        assert_eq!(Platform::parse("Windows"), None);
    }
}
