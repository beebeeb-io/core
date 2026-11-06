//! One backup pass of one folder (spec §4.3): walk, plan with core's rules,
//! and hand the work to the client.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};

use beebeeb_core::backup::{
    BackupRecord, EntryAttrs, FolderPresence, PassBudget, RecordState, SkipReason, file_name, folder_presence, parents,
    plan_pass,
};
use beebeeb_types::backup::Category;
use uuid::Uuid;

use crate::Fingerprint;
use crate::fingerprint::fingerprint_with_attrs;
use crate::host::{BackupHost, HostError, UploadRequest};
use crate::walk::{check_excludes, walk_with_paths};

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
    /// Left for the next pass by the budget.
    pub deferred: usize,
    /// Gone between the walk and the handoff (deleted or renamed meanwhile):
    /// the next pass sees where it went.
    pub vanished: usize,
    /// Not backed up, by reason: the walk's skips plus `held_back`.
    pub skipped: BTreeMap<SkipReason, usize>,
    /// Planned uploads not handed to the uploader, by key, with the reason:
    /// `Unreadable` (its fingerprint could not be read: permission denied, a
    /// sharing violation, no longer a regular file) or `NotLocal` (it went
    /// online-only after the walk). For the client's list; logs carry the
    /// counts only.
    pub held_back: Vec<(String, SkipReason)>,
    /// Set when the device or category folder was deleted elsewhere: the pass
    /// turned this backup off and queued nothing.
    pub turned_off: Option<FolderPresence>,
}

/// The parent key of `key` (`""` for a top-level entry) and its last segment,
/// by core's key rules.
fn split_key(key: &str) -> (&str, &str) {
    (parents(key).last().unwrap_or(""), file_name(key))
}

/// What becomes of one planned upload at the handoff, from a fingerprint read
/// just now.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Handoff {
    Queue(Fingerprint),
    Hold(SkipReason),
    Vanished,
}

pub(crate) fn handoff(now: std::io::Result<(Fingerprint, EntryAttrs)>) -> Handoff {
    match now {
        Ok((_, attrs)) if attrs.not_local => Handoff::Hold(SkipReason::NotLocal),
        Ok((fp, _)) => Handoff::Queue(fp),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Handoff::Vanished,
        Err(_) => Handoff::Hold(SkipReason::Unreadable),
    }
}

fn folder_id(folders: &HashMap<String, Uuid>, key: &str) -> Result<Uuid, HostError> {
    folders
        .get(key)
        .copied()
        .ok_or_else(|| HostError("a planned folder has no id: device_tree or ensure_folder missed it".to_string()))
}

/// Run one pass of the backup of `c` from `source_root` (the person's own
/// folder, read in place), never entering `exclude` (the client's own sync
/// root; see [`crate::walk_source`]). In order:
///
/// 1. read this device's records, then the device tree (records first, so a
///    record written meanwhile by a finishing upload is in the tree listed
///    after it, never mistaken for a deletion elsewhere);
/// 2. if the device or category folder was deleted elsewhere, `turn_off` and
///    stop: nothing is queued;
/// 3. walk the source (on a blocking thread) and plan with
///    `beebeeb_core::backup::plan_pass`, then mark what was removed elsewhere
///    (only from a [`DeviceTree::complete`] listing);
/// 4. ensure the planned folders, parents first;
/// 5. apply the moves, re-keying each record with `put_record`;
/// 6. fingerprint each planned upload, re-check that its bytes are still
///    here, read the records again, and `enqueue_upload` each one no record
///    already holds (an upload that completed during the pass wrote its
///    record meanwhile). A fingerprint that cannot be read or a file gone
///    online-only is reported in [`PassReport::held_back`].
///
/// An empty, relative or `..` path in `exclude` is an error before anything
/// is read.
///
/// A pass never writes a record for an upload, and never touches the source.
pub async fn run_pass<H: BackupHost>(
    host: &H,
    source_root: &Path,
    exclude: &[PathBuf],
    c: &Category,
    budget: PassBudget,
) -> Result<PassReport, HostError> {
    check_excludes(exclude).map_err(|_| HostError("an excluded path is empty, relative or holds `..`".to_string()))?;
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

    let (root, exclude) = (source_root.to_path_buf(), exclude.to_vec());
    let walk = tokio::task::spawn_blocking(move || walk_with_paths(&root, &exclude))
        .await
        .map_err(|_| HostError("the folder walk stopped before it finished".to_string()))?
        .map_err(|e| HostError(format!("cannot read the backed-up folder ({:?})", e.kind())))?;

    let live: HashSet<Uuid> = tree.files.iter().map(|f| f.remote_id).collect();
    let plan = plan_pass(
        &walk.result.entries,
        &records,
        &live,
        tree.complete,
        &walk.result.unseen(),
        budget,
    );
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
    let handoffs: HashMap<String, Handoff> = tokio::task::spawn_blocking(move || {
        sources
            .into_iter()
            .map(|(key, path)| (key, handoff(fingerprint_with_attrs(&path))))
            .collect()
    })
    .await
    .map_err(|_| HostError("fingerprinting stopped before it finished".to_string()))?;

    // An upload of an earlier pass that completed while this one ran has
    // written its record since step 1: queueing it again would upload the
    // same bytes twice (and, for a changed file, add a version).
    let held: HashMap<String, (u64, i64)> = host
        .records(c)
        .await?
        .into_iter()
        .filter(|r| r.state == RecordState::BackedUp)
        .map(|r| (r.key, (r.size, r.modified_ms)))
        .collect();
    for upload in plan.uploads {
        let (Some(handoff), Some(path)) = (handoffs.get(&upload.key), walk.paths.get(&upload.key)) else {
            return Err(HostError("a planned upload has no path from the walk".to_string()));
        };
        let fp = match handoff {
            Handoff::Queue(fp) => fp,
            Handoff::Vanished => {
                report.vanished += 1;
                continue;
            }
            Handoff::Hold(reason) => {
                *report.skipped.entry(*reason).or_default() += 1;
                report.held_back.push((upload.key.clone(), *reason));
                continue;
            }
        };
        if held.get(&upload.key) == Some(&(fp.size, fp.modified_ms)) {
            report.unchanged += 1;
            continue;
        }
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
