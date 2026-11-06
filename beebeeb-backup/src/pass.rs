//! One backup pass of one folder (spec §4.3): walk, plan with core's rules,
//! and hand the work to the client.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};

use beebeeb_core::backup::{
    BackupRecord, EntryAttrs, FolderPresence, PassBudget, RecordState, SkipReason, file_name, fold_name,
    folder_presence, normalize_key, parents, plan_pass,
};
use beebeeb_types::backup::Category;
use uuid::Uuid;

use crate::Fingerprint;
use crate::fingerprint::fingerprint_with_attrs;
use crate::host::{BackupHost, HostError, UploadRequest};
use crate::walk::{CASE_INSENSITIVE, Walk, check_excludes, walk_with_paths};

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
    /// Skipped because the client holds the key (see `BackupHost::held_keys`).
    pub held: usize,
    /// Waiting for a complete listing (see `PassPlan::deferred_unknown`).
    pub deferred_unknown: usize,
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

/// On Windows a listing's size and mtime are the directory entry's
/// (`FindNextFileW`), which can be stale: a file another process keeps open,
/// a hard link whose other names' entries NTFS does not update. A record
/// holds the handle's values (`UploadRequest::fingerprint`). So an entry whose
/// listing differs from its record (by exact key, else by normalised key) is
/// read again from the file before planning: a stale entry is then
/// unchanged, never a `Changed` upload that takes the budget (delta 3 #6).
/// Only entries the walk listed as local reach here (a not-local one is a
/// skip, never an entry); one that cannot be read again, or now says not
/// local, keeps its listing, and the handoff decides.
fn refresh_stale(walk: &mut Walk, records: &[BackupRecord]) {
    let mut exact: HashMap<&str, Vec<(u64, i64)>> = HashMap::new();
    for r in records {
        exact.entry(r.key.as_str()).or_default().push((r.size, r.modified_ms));
    }
    // Built on the first entry with no exact record (a new file), if any.
    let mut normalized: Option<HashMap<String, Vec<(u64, i64)>>> = None;
    let mut stale = Vec::new();
    for (i, entry) in walk.result.entries.iter().enumerate().filter(|(_, e)| !e.is_dir) {
        let here = (entry.size, entry.modified_ms);
        let differs = match exact.get(entry.key.as_str()) {
            Some(recorded) => !recorded.contains(&here),
            None => normalized
                .get_or_insert_with(|| {
                    let mut by_key: HashMap<String, Vec<(u64, i64)>> = HashMap::new();
                    for r in records {
                        by_key
                            .entry(normalize_key(&r.key))
                            .or_default()
                            .push((r.size, r.modified_ms));
                    }
                    by_key
                })
                .get(&normalize_key(&entry.key))
                .is_some_and(|recorded| !recorded.contains(&here)),
        };
        if differs {
            stale.push(i);
        }
    }
    for i in stale {
        let entry = &mut walk.result.entries[i];
        if let Some(path) = walk.paths.get(&entry.key)
            && let Ok((now, attrs)) = fingerprint_with_attrs(path)
            && !attrs.not_local
        {
            entry.size = now.size;
            entry.modified_ms = now.modified_ms;
        }
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
/// 3. walk the source (on a blocking thread), read again from the file each
///    entry whose listing differs from its record (a stale directory entry on
///    Windows), and plan with `beebeeb_core::backup::plan_pass`;
/// 4. check what can fail (the category folder's id, every move's record,
///    every upload's path) before anything changes, then mark what was
///    removed elsewhere (only from a [`DeviceTree::complete`] listing);
/// 5. ensure the planned folders, parents first; on Windows and macOS a
///    folder whose key folds equal to an existing one is that folder, so a
///    case-only rename creates no sibling;
/// 6. apply the moves, re-keying each record with `put_record` (a file
///    already where the move puts it is only re-keyed);
/// 7. fingerprint each planned upload, re-check that its bytes are still
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
    let fs = PassFs {
        walk: Box::new(walk_with_paths),
        case_insensitive: CASE_INSENSITIVE,
    };
    run_pass_with(host, source_root, exclude, c, budget, fs).await
}

/// What a pass reads from the disk and how the platform compares names: the
/// real walk and the platform's rule in [`run_pass`]; a test's in the tests
/// (a stale listing, a case-insensitive drive on Linux).
pub(crate) struct PassFs {
    pub(crate) walk: Box<dyn FnOnce(&Path, &[PathBuf]) -> std::io::Result<Walk> + Send>,
    /// Names that differ only in case or normalisation are one name (Windows,
    /// macOS).
    pub(crate) case_insensitive: bool,
}

pub(crate) async fn run_pass_with<H: BackupHost>(
    host: &H,
    source_root: &Path,
    exclude: &[PathBuf],
    c: &Category,
    budget: PassBudget,
    fs: PassFs,
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
    let (walk_fs, listed) = (fs.walk, records.clone());
    let walk = tokio::task::spawn_blocking(move || {
        walk_fs(&root, &exclude).map(|mut walk| {
            refresh_stale(&mut walk, &listed);
            walk
        })
    })
    .await
    .map_err(|_| HostError("the folder walk stopped before it finished".to_string()))?
    .map_err(|e| HostError(format!("cannot read the backed-up folder ({:?})", e.kind())))?;

    let live: HashSet<Uuid> = tree.files.iter().map(|f| f.remote_id).collect();
    let held = host.held_keys(c).await?;
    let plan = plan_pass(
        &walk.result.entries,
        &records,
        &live,
        tree.complete,
        &walk.result.unseen(),
        &held,
        budget,
    );

    // Everything that can fail is checked before the first change to the
    // host's store or the server (delta 3 #8).
    let mut folders = tree.folders;
    folder_id(&folders, "")?;
    let by_remote: HashMap<Uuid, &BackupRecord> = records.iter().map(|r| (r.remote_id, r)).collect();
    let moves = plan
        .moves
        .iter()
        .map(|planned| {
            by_remote
                .get(&planned.remote_id)
                .map(|before| (planned, *before))
                .ok_or_else(|| HostError("a planned move has no record".to_string()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if plan.uploads.iter().any(|u| !walk.paths.contains_key(&u.key)) {
        return Err(HostError("a planned upload has no path from the walk".to_string()));
    }

    if !plan.mark_removed_elsewhere.is_empty() {
        host.mark_removed_elsewhere(c, &plan.mark_removed_elsewhere).await?;
    }

    let mut report = PassReport {
        unchanged: plan.unchanged,
        gone_locally: plan.gone_locally,
        deferred: plan.deferred,
        held: plan.held,
        deferred_unknown: plan.deferred_unknown,
        ..PassReport::default()
    };
    for (_, reason) in &walk.result.skipped {
        *report.skipped.entry(*reason).or_default() += 1;
    }

    // Where the platform does not tell names apart by case or normalisation,
    // a planned folder is the existing one whose key folds equal: a case-only
    // or NFC/NFD-only rename never creates a sibling (delta 3 #2). The
    // smallest such key wins when two fold equal.
    let mut folded: HashMap<String, Uuid> = HashMap::new();
    if fs.case_insensitive {
        let mut existing: Vec<(&String, &Uuid)> = folders.iter().collect();
        existing.sort();
        for (key, id) in existing {
            folded.entry(fold_name(key)).or_insert(*id);
        }
    }
    for key in &plan.folders {
        if folders.contains_key(key) {
            continue;
        }
        if let Some(id) = fs.case_insensitive.then(|| folded.get(&fold_name(key))).flatten() {
            folders.insert(key.clone(), *id);
            continue;
        }
        let (parent, name) = split_key(key);
        let id = host.ensure_folder(folder_id(&folders, parent)?, name).await?;
        folders.insert(key.clone(), id);
        if fs.case_insensitive {
            folded.entry(fold_name(key)).or_insert(id);
        }
    }

    // A file already where the move puts it (its folder resolved to the one
    // it is in, by the rule above) is only re-keyed.
    let remote_keys: HashMap<Uuid, &str> = tree.files.iter().map(|f| (f.remote_id, f.key.as_str())).collect();
    for (planned, before) in moves {
        let (parent, name) = split_key(&planned.to_key);
        let parent_id = folder_id(&folders, parent)?;
        let in_place = remote_keys.get(&planned.remote_id).is_some_and(|now| {
            let (now_parent, now_name) = split_key(now);
            now_name == name && folders.get(now_parent) == Some(&parent_id)
        });
        if !in_place {
            host.move_file(planned.remote_id, parent_id, name).await?;
        }
        let moved = BackupRecord {
            key: planned.to_key.clone(),
            state: RecordState::BackedUp,
            ..before.clone()
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
    let recorded: HashMap<String, (u64, i64)> = host
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
        if recorded.get(&upload.key) == Some(&(fp.size, fp.modified_ms)) {
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
            record_key: upload.record_key.clone(),
            remote_id: upload.remote_id,
        })
        .await?;
        report.queued += 1;
    }
    Ok(report)
}
