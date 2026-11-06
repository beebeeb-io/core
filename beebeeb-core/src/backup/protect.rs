//! The protection rule (spec §4.2 rule 7): the Backups root is never trashed,
//! deleted, renamed or moved. Its children, and moving items INTO it, are
//! ordinary. The server enforces the same rule on every path; every client
//! also refuses locally, with these words.

use std::fmt;

use beebeeb_types::backup::SystemRole;

/// What a person (or an old client) tries to do to a row.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Mutation {
    /// Move to Trash.
    Trash,
    /// Delete for good (`"delete"` in the bindings).
    DeletePermanently,
    Rename,
    /// Reparent (the row itself moves; moving something into the row is not
    /// a mutation of the row).
    Move,
}

impl Mutation {
    /// The binding string: `"trash" | "delete" | "rename" | "move"`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Mutation::Trash => "trash",
            Mutation::DeletePermanently => "delete",
            Mutation::Rename => "rename",
            Mutation::Move => "move",
        }
    }

    /// Parse a binding string. Anything else is `None`: a caller turns that
    /// into an error, never into a pass.
    pub fn parse(s: &str) -> Option<Mutation> {
        match s {
            "trash" => Some(Mutation::Trash),
            "delete" => Some(Mutation::DeletePermanently),
            "rename" => Some(Mutation::Rename),
            "move" => Some(Mutation::Move),
            _ => None,
        }
    }
}

/// Shown when the root would be trashed or deleted (iOS's exact string).
pub const MSG_DELETE: &str = "Backups is a system folder and can't be deleted.";
/// Shown when the root would be moved (iOS's exact string).
pub const MSG_MOVE: &str = "Backups is a system folder and can't be moved.";
/// Shown when the root would be renamed.
pub const MSG_RENAME: &str = "Backups is a system folder and can't be renamed.";

/// A refused mutation, with the words to show.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Protected {
    pub message: &'static str,
}

impl fmt::Display for Protected {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message)
    }
}

impl std::error::Error for Protected {}

/// Refuse `m` on a row with `role`. Only the Backups root is refused; every
/// other row, including the root's children, is `Ok`.
pub fn check_mutation(role: Option<SystemRole>, m: Mutation) -> Result<(), Protected> {
    match role {
        Some(SystemRole::BackupsRoot) => Err(Protected {
            message: match m {
                Mutation::Trash | Mutation::DeletePermanently => MSG_DELETE,
                Mutation::Rename => MSG_RENAME,
                Mutation::Move => MSG_MOVE,
            },
        }),
        None => Ok(()),
    }
}

/// The words a device shows when someone deletes, renames or moves an item of
/// its OWN backup of a folder that is still being backed up (spec §6.2).
/// `source_path` is the original's path on this device; it is shown, never
/// logged.
pub fn own_backup_refusal(source_path: &str) -> String {
    format!("This is a backup of {source_path}. Change the original instead.")
}
