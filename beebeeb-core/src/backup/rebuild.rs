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
pub fn records_from_remote(remote: &[RemoteEntry], entries: &[SourceEntry]) -> Vec<BackupRecord> {
    let mut by_key: HashMap<String, Vec<&RemoteEntry>> = HashMap::new();
    for r in remote {
        by_key.entry(normalize_key(&r.key)).or_default().push(r);
    }
    let mut files: Vec<&SourceEntry> = entries.iter().filter(|e| !e.is_dir).collect();
    files.sort_by(|a, b| a.key.cmp(&b.key));

    let mut used: HashSet<Uuid> = HashSet::new();
    let mut records = Vec::new();
    for file in files {
        let Some(candidates) = by_key.get(&normalize_key(&file.key)) else {
            continue;
        };
        let best = candidates
            .iter()
            .filter(|r| r.size == file.size && r.uploaded_at_ms > file.modified_ms && !used.contains(&r.remote_id))
            .min_by_key(|r| (Reverse(r.uploaded_at_ms), r.remote_id));
        if let Some(r) = best {
            used.insert(r.remote_id);
            records.push(BackupRecord {
                key: file.key.clone(),
                size: file.size,
                modified_ms: file.modified_ms,
                remote_id: r.remote_id,
                uploaded_at_ms: r.uploaded_at_ms,
                state: RecordState::BackedUp,
            });
        }
    }
    records
}
