//! The Backups tree in the native services (backup spec §4.2 rules 5 and 7,
//! Amendments 6 to 8): a device's backup is written by that device's own
//! backup pass and by nothing else.
//!
//! Every app mutation (rename, move, trash, delete, a new folder, an upload, a
//! version restore) asks core's app rule, and every File Provider mutation asks
//! core's drive rule, before anything is sent. The row's own role is checked
//! first with core's root rule. The root is the row whose server `system_role`
//! is `backups_root`, never a folder found by its name, and a row's position is
//! its depth below that root, read through its parents (`GET /files/{id}`, one
//! per level). The backup pass itself never goes through these checks: it is
//! the one writer they protect the tree for.

use beebeeb_api::{ApiError, routes::files::FileEntry};
use beebeeb_core::{
    backup::{
        BackupPosition, MANIFEST_NAME, Mutation, Protected, check_app_mutation, check_drive_mutation,
        check_root_mutation,
    },
    encrypt::decrypt_name_metadata,
};
use beebeeb_types::backup::SystemRole;
use serde_json::Value;

use crate::{Client, ClientError};

/// The most parents a position check reads. A tree deeper than this, or a
/// parent loop, is corrupt metadata, never "outside the tree".
pub(crate) const MAX_ANCESTORS: usize = 256;

/// Which of core's rules a mutation goes through.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Rule {
    /// The app rule (`check_app_mutation`): the app's own screens.
    App,
    /// The drive rule (`check_drive_mutation`): the iOS Files app and any
    /// other drive surface. Nothing at or under the root changes there.
    Drive,
}

#[derive(Debug)]
pub(crate) enum GuardError {
    /// Core refused the mutation; the words are core's.
    Refused(Protected),
    /// Where the row is cannot be told (a parent loop or a tree deeper than
    /// [`MAX_ANCESTORS`]), so nothing is changed.
    Unknown,
    Client(ClientError),
}

/// The row's role, as the server sends it. Only core's exact wire value
/// counts; a folder named "Backups" is not the root.
pub(crate) fn system_role(entry: &FileEntry) -> Option<SystemRole> {
    entry
        .extra
        .get("system_role")
        .and_then(Value::as_str)
        .and_then(SystemRole::parse)
}

fn decide(rule: Rule, position: BackupPosition, m: Mutation) -> Result<(), Protected> {
    match rule {
        Rule::App => check_app_mutation(position, m),
        // No native service backs up a folder of its own yet, so no item is
        // this device's active backup of a source path.
        Rule::Drive => check_drive_mutation(position, None, m),
    }
}

impl Client {
    /// The depth below the flagged Backups root of the row `row` (`Some(0)`
    /// for the root itself, `None` for a row outside the tree).
    pub(crate) async fn backup_depth_of(&self, row: &FileEntry) -> Result<Option<usize>, GuardError> {
        let mut steps = 0usize;
        let mut current = row.clone();
        loop {
            if system_role(&current) == Some(SystemRole::BackupsRoot) {
                return Ok(Some(steps));
            }
            let Some(parent) = current.parent_id.clone() else {
                return Ok(None);
            };
            steps = steps.checked_add(1).ok_or(GuardError::Unknown)?;
            if steps > MAX_ANCESTORS {
                return Err(GuardError::Unknown);
            }
            current = match self.get_file(&parent).await {
                Ok(parent) => parent,
                // Above a folder shared with this account sits the sharer's
                // own folder, which this account cannot read. A shared tree is
                // not this account's Backups tree: its root has no parent.
                Err(ClientError::Api(ApiError::Server(server))) if matches!(server.status, 403 | 404) => {
                    return Ok(None);
                }
                Err(error) => return Err(GuardError::Client(error)),
            };
        }
    }

    /// The depth below the flagged Backups root of the row `id`, read fresh
    /// from the server.
    pub(crate) async fn backup_depth(&self, id: &str) -> Result<Option<usize>, GuardError> {
        let row = self.get_file(id).await.map_err(GuardError::Client)?;
        self.backup_depth_of(&row).await
    }

    /// Core's rule `rule` for mutation `m` of the row `id`: the row's own role
    /// first (core's root rule), then its position below the root.
    pub(crate) async fn check_backup_mutation(&self, rule: Rule, id: &str, m: Mutation) -> Result<(), GuardError> {
        let row = self.get_file(id).await.map_err(GuardError::Client)?;
        self.check_backup_row(rule, &row, m).await
    }

    /// [`Self::check_backup_mutation`] for a row the caller has just read from
    /// the server (never a cached or locally built one).
    pub(crate) async fn check_backup_row(&self, rule: Rule, row: &FileEntry, m: Mutation) -> Result<(), GuardError> {
        check_root_mutation(system_role(row), m).map_err(GuardError::Refused)?;
        let depth = self.backup_depth_of(row).await?;
        let name = if depth == Some(2) && !row.is_folder {
            self.backup_item_name(row)
        } else {
            String::new()
        };
        decide(rule, BackupPosition::at_depth(depth, &name), m).map_err(GuardError::Refused)
    }

    /// Core's rule for a new item in folder `parent` (`None`: the top of the
    /// drive, outside the tree). The app and drive rules agree on a create.
    pub(crate) async fn check_backup_create_in(&self, parent: Option<&str>) -> Result<(), GuardError> {
        let Some(parent) = parent else {
            return Ok(());
        };
        // A parent is a folder, so at depth 2 it is a category folder, never a
        // manifest: the name is not needed.
        let depth = self.backup_depth(parent).await?;
        check_app_mutation(BackupPosition::at_depth(depth, ""), Mutation::Create).map_err(GuardError::Refused)
    }

    /// The name of a file directly in a device folder. One whose name cannot
    /// be opened counts as the device's manifest, which nothing may change.
    fn backup_item_name(&self, row: &FileEntry) -> String {
        let opened = self.session_key().ok().and_then(|key| {
            let sealed = row.name_encrypted.as_deref()?;
            decrypt_name_metadata(key.master_key(), &row.id, sealed).ok()
        });
        opened.map_or_else(|| MANIFEST_NAME.to_owned(), |metadata| metadata.name)
    }
}
