//! Rebuilding records from the server (spec §4.2 rule 10): after a reinstall,
//! and when the old desktop mirror's copies are adopted (G4).

use std::cmp::Reverse;
use std::collections::{HashMap, HashSet};

use uuid::Uuid;

use super::plan::{BackupRecord, RecordState, SourceEntry, normalize_key};

/// One file of this device's backup of a category, as the server lists it.
/// `key` is its path under the category folder.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemoteEntry {
    pub key: String,
    pub remote_id: Uuid,
    pub size: u64,
    pub uploaded_at_ms: i64,
}

/// Records for the source entries the server already holds: the same key,
/// the same size, and uploaded strictly after the entry last changed. Anything
/// else is uploaded again; the rule never marks a newer local file as backed
/// up. When the server holds several qualifying copies at a key, the newest
/// upload wins. Each remote file backs at most one entry.
///
/// Keys match exactly first; then, for the entries left, by
/// [`normalize_key`] when no other entry left has the same normalised key. So
/// a Linux file named `a\b.jpg` and the file `b.jpg` in folder `a` each keep
/// their own copy. The records come sorted by key.
pub fn records_from_remote(remote: &[RemoteEntry], entries: &[SourceEntry]) -> Vec<BackupRecord> {
    let mut exact: HashMap<&str, Vec<&RemoteEntry>> = HashMap::new();
    let mut normalized: HashMap<String, Vec<&RemoteEntry>> = HashMap::new();
    for r in remote {
        exact.entry(r.key.as_str()).or_default().push(r);
        normalized.entry(normalize_key(&r.key)).or_default().push(r);
    }
    let mut files: Vec<&SourceEntry> = entries.iter().filter(|e| !e.is_dir).collect();
    files.sort_by(|a, b| a.key.cmp(&b.key));

    let mut used: HashSet<Uuid> = HashSet::new();
    let mut records = Vec::new();
    let mut left = Vec::new();
    for file in files {
        match newest_copy(exact.get(file.key.as_str()), file, &used) {
            Some(r) => records.push(backed_up(file, r, &mut used)),
            None => left.push(file),
        }
    }
    let mut sharing: HashMap<String, usize> = HashMap::new();
    for file in &left {
        *sharing.entry(normalize_key(&file.key)).or_default() += 1;
    }
    for file in left {
        let key = normalize_key(&file.key);
        if sharing[&key] != 1 {
            continue;
        }
        if let Some(r) = newest_copy(normalized.get(&key), file, &used) {
            records.push(backed_up(file, r, &mut used));
        }
    }
    records.sort_by(|a, b| a.key.cmp(&b.key));
    records
}

/// The newest copy among `candidates` that can back `file` and backs no
/// other entry yet.
fn newest_copy<'a>(
    candidates: Option<&Vec<&'a RemoteEntry>>,
    file: &SourceEntry,
    used: &HashSet<Uuid>,
) -> Option<&'a RemoteEntry> {
    candidates?
        .iter()
        .copied()
        .filter(|r| r.size == file.size && r.uploaded_at_ms > file.modified_ms && !used.contains(&r.remote_id))
        .min_by_key(|r| (Reverse(r.uploaded_at_ms), r.remote_id))
}

fn backed_up(file: &SourceEntry, r: &RemoteEntry, used: &mut HashSet<Uuid>) -> BackupRecord {
    used.insert(r.remote_id);
    BackupRecord {
        key: file.key.clone(),
        size: file.size,
        modified_ms: file.modified_ms,
        remote_id: r.remote_id,
        uploaded_at_ms: r.uploaded_at_ms,
        state: RecordState::BackedUp,
    }
}
