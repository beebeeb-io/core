//! One backup pass of one folder (spec §4.3): walk, plan with core's rules,
//! and hand the work to the client.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};

use beebeeb_core::backup::{
    BackupRecord, FolderPresence, PassBudget, RecordState, SkipReason, folder_presence, plan_pass,
};
use beebeeb_types::backup::Category;
use uuid::Uuid;

use crate::host::{BackupHost, HostError, UploadRequest};
use crate::walk::walk_with_paths;
use crate::{Fingerprint, fingerprint};

/// What one pass did, in counts (what a client shows and logs).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PassReport {
    /// Handed to the uploader.
    pub queued: usize,
    /// Moved on the server instead of uploaded again.
    pub moved: usize,
    pub unchanged: usize,
    /// Deleted locally; they stay in the backup.
    pub gone_locally: usize,
    /// Left for the next pass (the budget, or a file that vanished between
    /// the walk and its fingerprint).
    pub deferred: usize,
    /// Not backed up, by reason.
    pub skipped: BTreeMap<SkipReason, usize>,
    /// Set when the device or category folder was deleted elsewhere: the pass
    /// turned this backup off and queued nothing.
    pub turned_off: Option<FolderPresence>,
}

/// The parent key of `key` (`""` for a top-level entry) and its last segment.
fn split_key(key: &str) -> (&str, &str) {
    key.rsplit_once('/').unwrap_or(("", key))
}

fn folder_id(folders: &HashMap<String, Uuid>, key: &str) -> Result<Uuid, HostError> {
    folders
        .get(key)
        .copied()
        .ok_or_else(|| HostError("a planned folder has no id: device_tree or ensure_folder missed it".to_string()))
}

/// Run one pass of the backup of `c` from `source_root` (the person's own
/// folder, read in place). In order:
///
/// 1. read this device's records, then the device tree (records first, so a
///    record written meanwhile by a finishing upload is in the tree listed
///    after it, never mistaken for a deletion elsewhere);
/// 2. if the device or category folder was deleted elsewhere, `turn_off` and
///    stop: nothing is queued;
/// 3. walk the source (on a blocking thread) and plan with
///    `beebeeb_core::backup::plan_pass`, then mark what was removed elsewhere;
/// 4. ensure the planned folders, parents first;
/// 5. apply the moves, re-keying each record with `put_record`;
/// 6. fingerprint each planned upload and `enqueue_upload` it.
///
/// A pass never writes a record for an upload, and never touches the source.
pub async fn run_pass<H: BackupHost>(
    host: &H,
    source_root: &Path,
    c: &Category,
    budget: PassBudget,
) -> Result<PassReport, HostError> {
    let records = host.records(c).await?;
    let tree = host.device_tree(c).await?;
    let presence = folder_presence(tree.device_folder_live, tree.category_folder_live);
    if presence != FolderPresence::Present {
        host.turn_off(c, presence).await?;
        return Ok(PassReport {
            turned_off: Some(presence),
            ..PassReport::default()
        });
    }

    let root = source_root.to_path_buf();
    let walk = tokio::task::spawn_blocking(move || walk_with_paths(&root))
        .await
        .map_err(|_| HostError("the folder walk stopped before it finished".to_string()))?
        .map_err(|e| HostError(format!("cannot read the backed-up folder ({:?})", e.kind())))?;

    let live: HashSet<Uuid> = tree.files.iter().map(|f| f.remote_id).collect();
    let plan = plan_pass(&walk.result.entries, &records, &live, &walk.result.unseen(), budget);
    if !plan.mark_removed_elsewhere.is_empty() {
        host.mark_removed_elsewhere(c, &plan.mark_removed_elsewhere).await?;
    }

    let mut report = PassReport {
        unchanged: plan.unchanged,
        gone_locally: plan.gone_locally,
        deferred: plan.deferred,
        ..PassReport::default()
    };
    for (_, reason) in &walk.result.skipped {
        *report.skipped.entry(*reason).or_default() += 1;
    }

    let mut folders = tree.folders;
    folder_id(&folders, "")?;
    for key in &plan.folders {
        if folders.contains_key(key) {
            continue;
        }
        let (parent, name) = split_key(key);
        let id = host.ensure_folder(folder_id(&folders, parent)?, name).await?;
        folders.insert(key.clone(), id);
    }

    let by_remote: HashMap<Uuid, &BackupRecord> = records.iter().map(|r| (r.remote_id, r)).collect();
    for planned in &plan.moves {
        let (parent, name) = split_key(&planned.to_key);
        host.move_file(planned.remote_id, folder_id(&folders, parent)?, name)
            .await?;
        let before = by_remote
            .get(&planned.remote_id)
            .ok_or_else(|| HostError("a planned move has no record".to_string()))?;
        let moved = BackupRecord {
            key: planned.to_key.clone(),
            state: RecordState::BackedUp,
            ..(*before).clone()
        };
        host.put_record(c, moved).await?;
        report.moved += 1;
    }

    let sources: Vec<(String, PathBuf)> = plan
        .uploads
        .iter()
        .filter_map(|u| walk.paths.get(&u.key).map(|p| (u.key.clone(), p.clone())))
        .collect();
    let fingerprints: HashMap<String, Fingerprint> = tokio::task::spawn_blocking(move || {
        sources
            .into_iter()
            .filter_map(|(key, path)| fingerprint(&path).ok().map(|fp| (key, fp)))
            .collect()
    })
    .await
    .map_err(|_| HostError("fingerprinting stopped before it finished".to_string()))?;

    for upload in plan.uploads {
        let (Some(fp), Some(path)) = (fingerprints.get(&upload.key), walk.paths.get(&upload.key)) else {
            // Gone or no longer a file since the walk: the next pass sees it.
            report.deferred += 1;
            continue;
        };
        let (parent, name) = split_key(&upload.key);
        host.enqueue_upload(UploadRequest {
            category: c.clone(),
            key: upload.key.clone(),
            source_path: path.clone(),
            parent_id: folder_id(&folders, parent)?,
            name: name.to_string(),
            fingerprint: *fp,
            reason: upload.reason,
        })
        .await?;
        report.queued += 1;
    }
    Ok(report)
}
