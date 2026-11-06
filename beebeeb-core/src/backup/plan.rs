//! The pass planner (spec §4.2 rules 9 and 11).
//!
//! One pass compares what is in the source folder now with what this device
//! backed up before, and says what to do: upload, move, mark as removed
//! elsewhere, or nothing. The plan is idempotent: whatever the budget leaves
//! out comes back on the next pass, from exactly where this one stopped.

use std::collections::{BTreeSet, HashMap, HashSet};

use serde::{Deserialize, Serialize};
use unicode_normalization::UnicodeNormalization;
use uuid::Uuid;

use super::fold_name;

/// A backup key in its one comparable form: NFC (macOS names arrive NFD),
/// `\` as `/`, no leading `/`.
pub fn normalize_key(raw: &str) -> String {
    let key: String = raw.nfc().map(|c| if c == '\\' { '/' } else { c }).collect();
    key.trim_start_matches('/').to_string()
}

/// One entry of the source folder, as the walk reports it. `key` is the
/// `/`-joined path relative to the backed-up folder. Every `/` in a key is a
/// folder boundary (the planner plans parent folders from them), so a key that
/// is not a path encodes its own `/` first: an iOS asset id
/// (`<uuid>/L0/001`) is passed with each `/` replaced by `|`. Entries that
/// are not local never reach the planner.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceEntry {
    pub key: String,
    pub is_dir: bool,
    pub size: u64,
    pub modified_ms: i64,
}

/// Where a record stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordState {
    /// The server holds this device's copy.
    BackedUp,
    /// Someone deleted it from the backup elsewhere (web, another device). It
    /// stays deleted until the file changes on this device (Guus, 2026-11-06).
    RemovedElsewhere,
}

/// What this device backed up for one key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackupRecord {
    pub key: String,
    pub size: u64,
    pub modified_ms: i64,
    pub remote_id: Uuid,
    pub uploaded_at_ms: i64,
    pub state: RecordState,
}

/// The most one pass queues.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PassBudget {
    pub max_uploads: usize,
    pub max_bytes: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UploadReason {
    /// No record for this key, or the record's server copy is not live (it
    /// was removed elsewhere, or is gone now): the file comes back as a new
    /// file and never becomes a version of a trashed or purged `remote_id`
    /// (Guus, 2026-11-06, ruling A). The client writes a fresh record when the
    /// upload completes.
    New,
    /// Its size or `modified_ms` differs from the record, whose server copy is
    /// live: a new version of the record's `remote_id`.
    Changed,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlannedUpload {
    /// The entry's key: where the file is now.
    pub key: String,
    pub size: u64,
    pub reason: UploadReason,
    /// The paired record's key, `Some` whenever a record pairs. It can differ
    /// from `key` (a record stored under an NFD key or with `\`, paired by
    /// [`normalize_key`]): the host re-keys that record to `key` when the
    /// upload completes (`put_record`, which drops the old key), and never
    /// looks the record up by `key` (review #3).
    pub record_key: Option<String>,
    /// For [`UploadReason::Changed`]: the remote file this upload is a new
    /// version of (the paired record's id, live at planning time). `None` for
    /// `New`.
    pub remote_id: Option<Uuid>,
}

/// A file that moved (or was renamed) in the source: a server-side move of
/// `remote_id`, never a second upload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlannedMove {
    pub remote_id: Uuid,
    /// The record's key.
    pub from_key: String,
    /// The entry's key.
    pub to_key: String,
}

/// One pass's work.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PassPlan {
    /// In key order; the budget keeps a prefix.
    pub uploads: Vec<PlannedUpload>,
    pub moves: Vec<PlannedMove>,
    /// Parent folders (keys) of the planned uploads and moves, parents first.
    pub folders: Vec<String>,
    /// Record keys whose server copy is gone: mark them `RemovedElsewhere`.
    pub mark_removed_elsewhere: Vec<String>,
    /// Backed up, on the server and unchanged.
    pub unchanged: usize,
    /// Records with no entry any more. No action: a file deleted locally
    /// stays in the backup.
    pub gone_locally: usize,
    /// Uploads the budget left for the next pass.
    pub deferred: usize,
    /// Uploads skipped because the host holds their key (a lasting failure:
    /// locked, too large, refused; or one already in flight). They are not
    /// charged to the budget (review #1).
    pub held: usize,
    /// Work that waits for a complete listing: a change to a file whose
    /// record's id is missing from an incomplete listing, and a new entry that
    /// may be such a record's file moved. No upload, no move, no mark: the
    /// next pass with a complete listing decides (lead 17:28, review #2).
    pub deferred_unknown: usize,
}

/// Whether this backup still has somewhere to go (spec §4.2 rule 11).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FolderPresence {
    Present,
    /// The category folder (`Backups/<device>/Pictures`) was deleted
    /// elsewhere: that backup turns off on this device.
    CategoryDeleted,
    /// The device folder was deleted elsewhere: every backup of this device
    /// turns off.
    DeviceDeleted,
}

/// `device_folder_live` is false only when this device's folder existed and is
/// now trashed or gone. `category_folder_live` is `None` when this category
/// never had a folder (a first backup), which is `Present`.
pub fn folder_presence(device_folder_live: bool, category_folder_live: Option<bool>) -> FolderPresence {
    if !device_folder_live {
        FolderPresence::DeviceDeleted
    } else if category_folder_live == Some(false) {
        FolderPresence::CategoryDeleted
    } else {
        FolderPresence::Present
    }
}

/// The last `/` segment of a key: `"a/b/c.jpg"` gives `"c.jpg"`.
pub fn file_name(key: &str) -> &str {
    key.rsplit('/').next().unwrap_or(key)
}

/// Every parent of a key, outermost first: `"a/b/c"` gives `"a"` and
/// `"a/b"`. The last one is the key's own folder.
pub fn parents(key: &str) -> impl Iterator<Item = &str> {
    key.match_indices('/').map(move |(i, _)| &key[..i])
}

/// Pair each file (sorted) with its record (sorted): the exact key first; then,
/// among what is left, the normalised key when it is unique on both sides.
/// Returns, per file, the index of its record.
fn pair(files: &[&SourceEntry], records: &[&BackupRecord]) -> Vec<Option<usize>> {
    let mut paired: Vec<Option<usize>> = vec![None; files.len()];
    let mut record_taken = vec![false; records.len()];
    let mut by_key: HashMap<&str, usize> = HashMap::new();
    for (i, r) in records.iter().enumerate() {
        by_key.entry(r.key.as_str()).or_insert(i);
    }
    for (f, file) in files.iter().enumerate() {
        if let Some(&r) = by_key.get(file.key.as_str())
            && !record_taken[r]
        {
            paired[f] = Some(r);
            record_taken[r] = true;
        }
    }
    let mut left_files: HashMap<String, Vec<usize>> = HashMap::new();
    for (f, file) in files.iter().enumerate() {
        if paired[f].is_none() {
            left_files.entry(normalize_key(&file.key)).or_default().push(f);
        }
    }
    let mut left_records: HashMap<String, Vec<usize>> = HashMap::new();
    for (r, record) in records.iter().enumerate() {
        if !record_taken[r] {
            left_records.entry(normalize_key(&record.key)).or_default().push(r);
        }
    }
    for (key, fs) in &left_files {
        if let (&[f], Some(&[r])) = (fs.as_slice(), left_records.get(key).map(Vec::as_slice)) {
            paired[f] = Some(r);
        }
    }
    paired
}

type MoveSignature = (u64, i64, String);

/// A file's side of the pairing: its record, or (unpaired) the signature a
/// move looks up.
enum Pairing {
    Record(usize),
    Unpaired(MoveSignature),
}

/// Size, mtime and the folded name (`fold_name`) of the normalised key's
/// last segment. `plan_pass` computes it once per unpaired record and file.
fn signature(size: u64, modified_ms: i64, key: &str) -> MoveSignature {
    (size, modified_ms, fold_name(file_name(&normalize_key(key))))
}

/// Whether `key` is one of `unseen` or lies under one, comparing the keys as
/// given (`plan_pass` decides when they are normalised first).
fn under_unseen(key: &str, unseen: &HashSet<&str>) -> bool {
    if unseen.is_empty() {
        return false;
    }
    // `""` is the backed-up folder itself: nothing in it was seen.
    unseen.contains("") || unseen.contains(key) || parents(key).any(|parent| unseen.contains(parent))
}

/// Spec §4.2 rules 9 and 11.
///
/// - `live_remote` holds the ids of this category's files on the server now
///   (not trashed), a file whose name is still pending decryption included.
///   A record is held while its id is live, whatever its state: a file
///   restored from Trash is unchanged again and a valid move source.
/// - `live_remote_complete`: the listing read every page and dropped nothing.
///   Only then is a missing id proof of a deletion: a backed-up record whose
///   id is missing from a complete listing is marked removed elsewhere; from
///   an incomplete one nothing is marked. Either way a record whose id is not
///   live is never a move source and never gets a `Changed` upload.
/// - `unseen` holds the keys the walk did not look at or into (a skipped
///   folder or file, `WalkResult::unseen`): a record at or under one is left
///   untouched, never gone, never a move source and never marked removed
///   elsewhere, because the walk cannot know whether it is still there (plan
///   Amendment 1, items 5-6). `""` stands for the whole folder. A record
///   matches by its raw key, or, when no entry has its exact key, by its
///   normalised key (the exact-then-normalised rule of spec Amendment 5), so
///   a legacy NFD record under an unseen NFC folder is covered too. A file
///   entry at or under an unseen raw key is not planned either (it waits for
///   a pass that sees its folder whole); entries match raw only, so an
///   unreadable NFD folder never hides its readable NFC twin. iOS passes an
///   empty list.
/// - `held`: entry keys the host holds (an upload that failed for a lasting
///   reason, or is still in flight). They are skipped this pass and not
///   charged to the budget, so one stuck file never starves the rest; "the
///   first upload always fits" applies to the first key not held (review #1).
///
/// A record whose id is missing from an INCOMPLETE listing is unknown, not
/// dead (lead 17:28): no upload for its file, no move from it, no mark; it
/// counts in `deferred_unknown`. A listed record behaves as normal.
///
/// The result does not depend on the order of `entries` or `records`.
pub fn plan_pass(
    entries: &[SourceEntry],
    records: &[BackupRecord],
    live_remote: &HashSet<Uuid>,
    live_remote_complete: bool,
    unseen: &[String],
    held: &[String],
    budget: PassBudget,
) -> PassPlan {
    let unseen: HashSet<&str> = unseen.iter().map(|key| key.trim_end_matches('/')).collect();
    let held: HashSet<&str> = held.iter().map(String::as_str).collect();
    let live = |r: &BackupRecord| live_remote.contains(&r.remote_id);
    let unknown = |r: &BackupRecord| !live_remote_complete && !live(r);
    let mut files: Vec<&SourceEntry> = entries
        .iter()
        .filter(|e| !e.is_dir && !under_unseen(&e.key, &unseen))
        .collect();
    files.sort_by(|a, b| a.key.cmp(&b.key));
    let unseen_normalized: Vec<String> = unseen.iter().map(|key| normalize_key(key)).collect();
    let unseen_normalized: HashSet<&str> = unseen_normalized.iter().map(String::as_str).collect();
    let file_keys: HashSet<&str> = files.iter().map(|f| f.key.as_str()).collect();
    let record_unseen = |r: &BackupRecord| {
        !unseen.is_empty()
            && (under_unseen(&r.key, &unseen)
                || (!file_keys.contains(r.key.as_str()) && under_unseen(&normalize_key(&r.key), &unseen_normalized)))
    };
    let mut records: Vec<&BackupRecord> = records.iter().filter(|r| !record_unseen(r)).collect();
    records.sort_by(|a, b| (&a.key, a.remote_id).cmp(&(&b.key, b.remote_id)));

    let paired = pair(&files, &records);
    let mut record_paired = vec![false; records.len()];
    for r in paired.iter().flatten() {
        record_paired[*r] = true;
    }

    // A backed-up record whose server copy is missing from a complete listing
    // was deleted from the backup elsewhere, whether or not the file is still
    // here. A partial listing proves nothing, so it marks nothing.
    let mut plan = PassPlan {
        mark_removed_elsewhere: records
            .iter()
            .filter(|r| live_remote_complete && r.state == RecordState::BackedUp && !live(r))
            .map(|r| r.key.clone())
            .collect(),
        ..PassPlan::default()
    };

    // Moves: a gone record whose server copy is live and a new entry with the
    // same size, mtime and case-folded name, unique in both directions.
    // Each signature is computed once: for an unpaired record that is live
    // or unknown, and for an unpaired file.
    let record_sig: Vec<Option<MoveSignature>> = records
        .iter()
        .enumerate()
        .map(|(r, record)| {
            (!record_paired[r] && (live(record) || unknown(record)))
                .then(|| signature(record.size, record.modified_ms, &record.key))
        })
        .collect();
    let pairing: Vec<Pairing> = files
        .iter()
        .zip(&paired)
        .map(|(file, paired)| match paired {
            Some(r) => Pairing::Record(*r),
            None => Pairing::Unpaired(signature(file.size, file.modified_ms, &file.key)),
        })
        .collect();
    let mut source_count: HashMap<&MoveSignature, Vec<usize>> = HashMap::new();
    // A record missing from an incomplete listing may still be live: a new
    // entry that matches it may be its file moved, so it waits too.
    let mut unknown_sources: HashSet<&MoveSignature> = HashSet::new();
    for (r, sig) in record_sig.iter().enumerate() {
        if let Some(sig) = sig {
            if live(records[r]) {
                source_count.entry(sig).or_default().push(r);
            } else {
                unknown_sources.insert(sig);
            }
        }
    }
    let mut target_count: HashMap<&MoveSignature, usize> = HashMap::new();
    for pairing in &pairing {
        if let Pairing::Unpaired(sig) = pairing {
            *target_count.entry(sig).or_default() += 1;
        }
    }
    let mut moved_record = vec![false; records.len()];

    let mut wanted: Vec<PlannedUpload> = Vec::new();
    for (file, pairing) in files.iter().zip(&pairing) {
        match pairing {
            Pairing::Record(r) => {
                let record = records[*r];
                let changed = file.size != record.size || file.modified_ms != record.modified_ms;
                if changed && unknown(record) {
                    plan.deferred_unknown += 1;
                } else if changed {
                    // Ruling A: a file deleted from the backup elsewhere comes
                    // back as a new file, never as a version of the deleted one.
                    let live_copy = live(record);
                    wanted.push(PlannedUpload {
                        key: file.key.clone(),
                        size: file.size,
                        reason: if live_copy {
                            UploadReason::Changed
                        } else {
                            UploadReason::New
                        },
                        record_key: Some(record.key.clone()),
                        remote_id: live_copy.then_some(record.remote_id),
                    });
                } else if live(record) {
                    plan.unchanged += 1;
                }
            }
            Pairing::Unpaired(sig) => {
                let source = match (source_count.get(sig).map(Vec::as_slice), target_count.get(sig)) {
                    (Some(&[r]), Some(1)) => Some(r),
                    _ => None,
                };
                match source {
                    Some(r) => {
                        moved_record[r] = true;
                        plan.moves.push(PlannedMove {
                            remote_id: records[r].remote_id,
                            from_key: records[r].key.clone(),
                            to_key: file.key.clone(),
                        });
                    }
                    None if unknown_sources.contains(sig) => plan.deferred_unknown += 1,
                    None => wanted.push(PlannedUpload {
                        key: file.key.clone(),
                        size: file.size,
                        reason: UploadReason::New,
                        record_key: None,
                        remote_id: None,
                    }),
                }
            }
        }
    }
    plan.gone_locally = (0..records.len())
        .filter(|&r| !record_paired[r] && !moved_record[r])
        .count();

    // The budget keeps a prefix: the first upload always fits, so one big file
    // is never stuck; after the first that does not fit, the rest wait. A held
    // key is skipped and charged nothing.
    let mut bytes: u64 = 0;
    for upload in wanted {
        if held.contains(upload.key.as_str()) {
            plan.held += 1;
            continue;
        }
        let fits = plan.deferred == 0
            && plan.uploads.len() < budget.max_uploads
            && (plan.uploads.is_empty() || bytes.saturating_add(upload.size) <= budget.max_bytes);
        if fits {
            bytes = bytes.saturating_add(upload.size);
            plan.uploads.push(upload);
        } else {
            plan.deferred += 1;
        }
    }

    let folders: BTreeSet<&str> = plan
        .uploads
        .iter()
        .map(|u| u.key.as_str())
        .chain(plan.moves.iter().map(|m| m.to_key.as_str()))
        .flat_map(parents)
        .collect();
    plan.folders = folders.into_iter().map(str::to_string).collect();
    plan
}
