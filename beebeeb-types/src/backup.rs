//! The backup vocabulary every client and the server share (LD-0113, spec
//! `2026-11-06-backup-from-source-design.md` §4.1).
//!
//! The server learns one thing about backups: which folder is the Backups
//! root, through [`SystemRole::BackupsRoot`]. It never learns a device name, a
//! folder name or a file name. When it removes the account's files, or a
//! person deletes a backup, it writes a [`BackupNotice`] with ids only (spec
//! Amendment 12). The rules that use these words live in
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

/// Why a backup stopped on a device (spec Amendment 12, Guus 2026-11-06:
/// "Stop, say why, offer Back up again"). A stopped backup never fills the
/// account up again by itself; the person chooses "Back up again".
///
/// The wire strings are the `notifications` row's `data.reason` values
/// (`erase_request`, `account_reset`, `inactive_cleanup`, `account_lapsed`),
/// plus `backup_deleted` (a step-up delete from another device) and `unknown`
/// (a folder gone with no notice).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackupStopReason {
    /// The device or category folder was deleted from another device (a
    /// `backup_deleted` notice, spec Amendment 11).
    BackupDeleted,
    /// The person's own "Erase all files" (spec §5.3 row 8).
    EraseRequest,
    /// The billing wipe, or the grace clock's oldest-first deletion (row 10).
    AccountLapsed,
    /// The 120-day inactive cleanup (row 9).
    InactiveCleanup,
    /// The admin onboarding reset (row 7).
    AccountReset,
    /// The folder is gone or trashed and no notice says why.
    Unknown,
}

impl BackupStopReason {
    /// Every reason, in declaration order.
    pub const ALL: [BackupStopReason; 6] = [
        BackupStopReason::BackupDeleted,
        BackupStopReason::EraseRequest,
        BackupStopReason::AccountLapsed,
        BackupStopReason::InactiveCleanup,
        BackupStopReason::AccountReset,
        BackupStopReason::Unknown,
    ];

    /// The wire string (the serde form).
    pub const fn as_str(self) -> &'static str {
        match self {
            BackupStopReason::BackupDeleted => "backup_deleted",
            BackupStopReason::EraseRequest => "erase_request",
            BackupStopReason::AccountLapsed => "account_lapsed",
            BackupStopReason::InactiveCleanup => "inactive_cleanup",
            BackupStopReason::AccountReset => "account_reset",
            BackupStopReason::Unknown => "unknown",
        }
    }

    /// Parse the exact wire string; anything else is `None`.
    pub fn parse(s: &str) -> Option<BackupStopReason> {
        BackupStopReason::ALL.into_iter().find(|r| r.as_str() == s)
    }

    /// Whether the account's files were removed (a `files_removed` notice's
    /// reason): every backup of every device stops, even where the folders are
    /// still there.
    pub const fn files_removed(self) -> bool {
        matches!(
            self,
            BackupStopReason::EraseRequest
                | BackupStopReason::AccountLapsed
                | BackupStopReason::InactiveCleanup
                | BackupStopReason::AccountReset
        )
    }
}

/// The `notifications.type` of a removal of the account's files (spec §5.3
/// rows 7-10, Amendment 12a: one per job run, in the transaction of its first
/// removal).
pub const NOTICE_FILES_REMOVED: &str = "files_removed";

/// The `notifications.type` of a person's step-up delete of a device or
/// category folder under the Backups root (spec Amendment 11).
pub const NOTICE_BACKUP_DELETED: &str = "backup_deleted";

/// A backup notice as the server writes it: the `notifications` row's `type`
/// and `data` (spec Amendment 12). Serialised, it is
/// `{"type": "files_removed", "data": {"reason": "erase_request"}}` or
/// `{"type": "backup_deleted", "data": {"device_folder_id": "<uuid>",
/// "category_folder_id": "<uuid>"}}`; the server stores the two fields in the
/// row's own columns. Ids only: the server never sees a name, and the device
/// resolves its names from its own records. A client reads rows through
/// `beebeeb_core::backup::parse_backup_notice`, which never fails on a row it
/// does not know.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum BackupNotice {
    /// Wire type [`NOTICE_FILES_REMOVED`]. `reason` is one of the four
    /// reasons for which [`BackupStopReason::files_removed`] holds.
    FilesRemoved { reason: BackupStopReason },
    /// Wire type [`NOTICE_BACKUP_DELETED`]. Without `category_folder_id` the
    /// whole device folder was deleted.
    BackupDeleted {
        device_folder_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        category_folder_id: Option<String>,
    },
}

impl BackupNotice {
    /// The `notifications.type` of this notice.
    pub const fn kind(&self) -> &'static str {
        match self {
            BackupNotice::FilesRemoved { .. } => NOTICE_FILES_REMOVED,
            BackupNotice::BackupDeleted { .. } => NOTICE_BACKUP_DELETED,
        }
    }

    /// Why the backups this notice reaches stop: a `files_removed` notice's
    /// reason (`Unknown` when it is not one of the four removal reasons), or
    /// `BackupDeleted`.
    pub const fn reason(&self) -> BackupStopReason {
        match self {
            BackupNotice::FilesRemoved { reason } if reason.files_removed() => *reason,
            BackupNotice::FilesRemoved { .. } => BackupStopReason::Unknown,
            BackupNotice::BackupDeleted { .. } => BackupStopReason::BackupDeleted,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backup_stop_reason_wire_strings_are_the_notice_reasons() {
        let wire: Vec<String> = BackupStopReason::ALL
            .iter()
            .map(|r| serde_json::to_string(r).unwrap())
            .collect();
        assert_eq!(
            wire,
            [
                "\"backup_deleted\"",
                "\"erase_request\"",
                "\"account_lapsed\"",
                "\"inactive_cleanup\"",
                "\"account_reset\"",
                "\"unknown\""
            ]
        );
        for r in BackupStopReason::ALL {
            assert_eq!(serde_json::to_string(&r).unwrap(), format!("\"{}\"", r.as_str()));
            assert_eq!(BackupStopReason::parse(r.as_str()), Some(r));
        }
        assert_eq!(BackupStopReason::parse("EraseRequest"), None);
        let removed: Vec<&str> = BackupStopReason::ALL
            .into_iter()
            .filter(|r| r.files_removed())
            .map(BackupStopReason::as_str)
            .collect();
        assert_eq!(
            removed,
            ["erase_request", "account_lapsed", "inactive_cleanup", "account_reset"]
        );
    }

    #[test]
    fn backup_notice_is_the_rows_type_and_data() {
        let erased = BackupNotice::FilesRemoved {
            reason: BackupStopReason::EraseRequest,
        };
        assert_eq!(
            serde_json::to_value(&erased).unwrap(),
            serde_json::json!({"type": "files_removed", "data": {"reason": "erase_request"}})
        );
        let category = BackupNotice::BackupDeleted {
            device_folder_id: "d".to_string(),
            category_folder_id: Some("c".to_string()),
        };
        assert_eq!(
            serde_json::to_value(&category).unwrap(),
            serde_json::json!({"type": "backup_deleted", "data": {"device_folder_id": "d", "category_folder_id": "c"}})
        );
        let device: BackupNotice =
            serde_json::from_value(serde_json::json!({"type": "backup_deleted", "data": {"device_folder_id": "d"}}))
                .unwrap();
        assert_eq!(
            device,
            BackupNotice::BackupDeleted {
                device_folder_id: "d".to_string(),
                category_folder_id: None
            }
        );
        assert_eq!(
            serde_json::to_value(&device).unwrap(),
            serde_json::json!({"type": "backup_deleted", "data": {"device_folder_id": "d"}})
        );
        assert_eq!(
            (erased.kind(), device.kind()),
            (NOTICE_FILES_REMOVED, NOTICE_BACKUP_DELETED)
        );
        assert_eq!(erased.reason(), BackupStopReason::EraseRequest);
        assert_eq!(device.reason(), BackupStopReason::BackupDeleted);
        let odd = BackupNotice::FilesRemoved {
            reason: BackupStopReason::BackupDeleted,
        };
        assert_eq!(odd.reason(), BackupStopReason::Unknown);
    }

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
