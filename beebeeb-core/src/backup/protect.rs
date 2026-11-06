//! Who may change what in the backup tree (spec §4.2 rule 7; spec Amendment
//! 8, Guus 2026-11-06 19:33 "Both, staged" and 20:04 "keep it Backups and
//! just add a read-only badge").
//!
//! A backup is written by its device's own backup pass and by nothing else.
//! Every client enforces that through these rules, with the same words:
//!
//! - [`check_app_mutation`]: web, desktop in the app, the iOS app and the CLI;
//! - [`check_drive_mutation`]: the drive surfaces (Windows Explorer, macOS
//!   Finder, the iOS Files app);
//! - [`check_root_mutation`]: the server's phase-1 rule, the root only (the
//!   server enforces the whole rule in phase 2, for requests not tagged
//!   [`beebeeb_types::backup::ORIGIN_BACKUP`]).
//!
//! The backup pass (`beebeeb-backup::run_pass`, iOS's backup) never goes
//! through these rules: it is the one writer they protect the tree for.

use std::borrow::Cow;
use std::fmt;

use beebeeb_types::backup::SystemRole;

use super::layout::MANIFEST_NAME;

/// What a person (or an old client) tries to do to a row.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Mutation {
    /// Move to Trash.
    Trash,
    /// Delete for good (`"delete"` in the bindings).
    DeletePermanently,
    Rename,
    /// Reparent: checked on the row that moves. The destination is checked
    /// with [`Mutation::Create`].
    Move,
    /// A new item in a folder: an upload, a new folder, or a move's
    /// destination. Checked on the folder the item goes into.
    Create,
    /// A change to a file's content, or a new version of it.
    Write,
}

impl Mutation {
    /// Every mutation, in binding order.
    pub const ALL: [Mutation; 6] = [
        Mutation::Trash,
        Mutation::DeletePermanently,
        Mutation::Rename,
        Mutation::Move,
        Mutation::Create,
        Mutation::Write,
    ];

    /// The binding string: `"trash" | "delete" | "rename" | "move" | "create"
    /// | "write"`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Mutation::Trash => "trash",
            Mutation::DeletePermanently => "delete",
            Mutation::Rename => "rename",
            Mutation::Move => "move",
            Mutation::Create => "create",
            Mutation::Write => "write",
        }
    }

    /// Parse a binding string. Anything else is `None`: a caller turns that
    /// into an error, never into a pass.
    pub fn parse(s: &str) -> Option<Mutation> {
        Mutation::ALL.into_iter().find(|m| m.as_str() == s)
    }

    /// Trash, delete, rename or move: the row itself goes or changes place.
    const fn is_structural(self) -> bool {
        matches!(
            self,
            Mutation::Trash | Mutation::DeletePermanently | Mutation::Rename | Mutation::Move
        )
    }
}

/// Where a row is, relative to the flagged root: the root itself, a device
/// folder, a device's manifest, a category folder, anything deeper, or
/// outside the tree.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BackupPosition {
    Root,
    DeviceFolder,
    /// A device folder's [`MANIFEST_NAME`] (lead 2026-11-06 20:01): each
    /// device writes its own, so no rule allows any change to it, and clients
    /// never list it ([`is_hidden_backup_item`]).
    Manifest,
    CategoryFolder,
    Inside,
    Outside,
}

impl BackupPosition {
    /// Every position, in binding order.
    pub const ALL: [BackupPosition; 6] = [
        BackupPosition::Root,
        BackupPosition::DeviceFolder,
        BackupPosition::Manifest,
        BackupPosition::CategoryFolder,
        BackupPosition::Inside,
        BackupPosition::Outside,
    ];

    /// The position of the row `name`, `depth` folders below the flagged
    /// root: `None` (not under it) is `Outside`, 0 the root, 1 a device
    /// folder, 2 the device's manifest when `name` is exactly
    /// [`MANIFEST_NAME`] and else a category folder, 3 or more `Inside`.
    pub fn at_depth(depth: Option<usize>, name: &str) -> BackupPosition {
        match depth {
            None => BackupPosition::Outside,
            Some(0) => BackupPosition::Root,
            Some(1) => BackupPosition::DeviceFolder,
            Some(2) if name == MANIFEST_NAME => BackupPosition::Manifest,
            Some(2) => BackupPosition::CategoryFolder,
            Some(_) => BackupPosition::Inside,
        }
    }

    /// The binding string: `"root" | "device_folder" | "manifest" |
    /// "category_folder" | "inside" | "outside"`.
    pub const fn as_str(self) -> &'static str {
        match self {
            BackupPosition::Root => "root",
            BackupPosition::DeviceFolder => "device_folder",
            BackupPosition::Manifest => "manifest",
            BackupPosition::CategoryFolder => "category_folder",
            BackupPosition::Inside => "inside",
            BackupPosition::Outside => "outside",
        }
    }

    /// Parse a binding string; anything else is `None` (an error, never a
    /// pass).
    pub fn parse(s: &str) -> Option<BackupPosition> {
        BackupPosition::ALL.into_iter().find(|p| p.as_str() == s)
    }
}

/// `true` for a row that no client ever lists: a device folder's
/// [`MANIFEST_NAME`] (its position is [`BackupPosition::Manifest`]). `depth`
/// and `name` as for [`BackupPosition::at_depth`].
pub fn is_hidden_backup_item(depth: Option<usize>, name: &str) -> bool {
    BackupPosition::at_depth(depth, name) == BackupPosition::Manifest
}

/// Shown when the root would be trashed or deleted (iOS's words,
/// byte-for-byte).
pub const MSG_DELETE: &str = "Backups is a system folder and can't be deleted.";
/// Shown when the root would be moved (iOS's words, byte-for-byte).
pub const MSG_MOVE: &str = "Backups is a system folder and can't be moved.";
/// Shown when the root would be renamed.
pub const MSG_RENAME: &str = "Backups is a system folder and can't be renamed.";

/// Shown in a drive surface for a trash, delete, rename or move of anything
/// under the root (Guus, 2026-11-06 17:49: "Protect the whole tree").
pub const MSG_MANAGED_IN_APP: &str = "Backups are managed in the Beebeeb app. Open Beebeeb to delete a backup.";

/// Shown when anything at or under the root would be changed, created,
/// renamed or moved where that is not allowed (spec Amendments 7 and 8): a
/// backup is one-way, each device writes its own, and an edit to its copy
/// would be overwritten by the next change at the source. Word, for one,
/// opens such a file read-only and offers Save As.
pub const MSG_READ_ONLY: &str = "Backups are read-only: each device writes its own. Change the file on that device, or save a copy outside Backups.";

/// The badge every client shows on the Backups root (Guus, 2026-11-06 20:04).
/// The read-only state is never put in the folder's name.
pub const MSG_BADGE: &str = "Read-only";

/// A refused mutation, with the words to show. The words are fixed except for
/// [`own_backup_refusal`], which names the original's path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Protected {
    pub message: Cow<'static, str>,
}

impl fmt::Display for Protected {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Protected {}

fn refused(message: &'static str) -> Result<(), Protected> {
    Err(Protected {
        message: Cow::Borrowed(message),
    })
}

/// The root's own words: its structural mutations name what was tried; a new
/// item or a content change in it is read-only.
fn root_words(m: Mutation) -> &'static str {
    match m {
        Mutation::Trash | Mutation::DeletePermanently => MSG_DELETE,
        Mutation::Rename => MSG_RENAME,
        Mutation::Move => MSG_MOVE,
        Mutation::Create | Mutation::Write => MSG_READ_ONLY,
    }
}

/// The server's phase-1 rule (spec §5.3), on a row with `role`: the Backups
/// root is never trashed, deleted, renamed or moved. Every other row is
/// `Ok`, and so is a new item in the root or a content change (the root is a
/// folder): the whole rule is the server's in phase 2.
pub fn check_root_mutation(role: Option<SystemRole>, m: Mutation) -> Result<(), Protected> {
    // Exhaustive on purpose: a role added later must be decided here, never
    // fall through to `Ok`.
    match role {
        Some(SystemRole::BackupsRoot) if m.is_structural() => refused(root_words(m)),
        Some(SystemRole::BackupsRoot) | None => Ok(()),
    }
}

/// The app rule (web, desktop in the app, the iOS app, the CLI; spec
/// Amendment 8), on a row at `position` (for [`Mutation::Create`], the folder
/// the new item goes into):
///
/// - the root: everything refused, with the root's words;
/// - a device's manifest: everything refused, [`MSG_READ_ONLY`];
/// - a device folder, a category folder or anything inside: trash and delete
///   are allowed (the "Delete <device>'s backup?" dialog, and one file
///   deleted from a backup, rule 11); rename, move, create and write are
///   refused, [`MSG_READ_ONLY`];
/// - outside: `Ok`.
pub fn check_app_mutation(position: BackupPosition, m: Mutation) -> Result<(), Protected> {
    match position {
        BackupPosition::Outside => Ok(()),
        BackupPosition::Root => refused(root_words(m)),
        BackupPosition::Manifest => refused(MSG_READ_ONLY),
        _ if matches!(m, Mutation::Trash | Mutation::DeletePermanently) => Ok(()),
        _ => refused(MSG_READ_ONLY),
    }
}

/// The drive rule (Guus, 2026-11-06 17:49, 19:30 and 19:33): in a drive
/// surface (Windows Explorer, macOS Finder, the iOS Files app) nothing at or
/// under the root can be trashed, deleted, renamed, moved, created or
/// changed; backups are managed in the app. In order:
///
/// 1. the root, for a trash, delete, rename or move: the root's words
///    ([`MSG_DELETE`], [`MSG_RENAME`], [`MSG_MOVE`]);
/// 2. `own_active_source = Some(path)`: the item is this device's own backup
///    of a folder still being backed up, and `path` is its original:
///    [`own_backup_refusal`];
/// 3. anything else at or under the root: [`MSG_READ_ONLY`] for a create, a
///    write, or anything on a device's manifest (the app refuses those too),
///    else [`MSG_MANAGED_IN_APP`];
/// 4. outside: `Ok`.
pub fn check_drive_mutation(
    position: BackupPosition,
    own_active_source: Option<&str>,
    m: Mutation,
) -> Result<(), Protected> {
    if position == BackupPosition::Root && m.is_structural() {
        return refused(root_words(m));
    }
    if let Some(source_path) = own_active_source {
        return Err(Protected {
            message: Cow::Owned(own_backup_refusal(source_path)),
        });
    }
    match position {
        BackupPosition::Outside => Ok(()),
        BackupPosition::Manifest => refused(MSG_READ_ONLY),
        _ if m.is_structural() => refused(MSG_MANAGED_IN_APP),
        _ => refused(MSG_READ_ONLY),
    }
}

/// The words a device shows when someone deletes, renames, moves or changes
/// an item of its OWN backup of a folder that is still being backed up (spec
/// §6.2). `source_path` is the original's path on this device; it is shown,
/// never logged.
pub fn own_backup_refusal(source_path: &str) -> String {
    format!("This is a backup of {source_path}. Change the original instead.")
}
