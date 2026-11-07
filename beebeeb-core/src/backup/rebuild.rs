//! Rebuilding records from the server (spec §4.2 rule 10): after a reinstall,
//! and when the old desktop mirror's copies are adopted (G4).
//!
//! The rule compares two clocks: a copy's `uploaded_at_ms` is the server's, a
//! source entry's `modified_ms` is the device's. A device clock that runs
//! behind makes an edit look older than it is, so a same-size edit made after
//! the upload would look backed up. [`RebuildClock`] carries the measured
//! offset between the two clocks and its margin, and with no offset known a
//! one-sided floor applies (LD-0123). Every error and every unknown leans
//! toward uploading again.

use std::cmp::Reverse;
use std::collections::{HashMap, HashSet};

use uuid::Uuid;

use super::plan::{BackupRecord, RecordState, SourceEntry, normalize_key};

/// With no offset known, a copy counts only when it was uploaded more than
/// this long after the entry last changed (10 minutes, LD-0123). It is
/// one-sided: it covers a device clock up to 10 minutes behind and never
/// lowers the bar for one that runs ahead (such a device uploads a recent
/// edit once more, nothing worse). A clock further behind is covered only by
/// a measured offset, so a client measures one whenever it has a listing
/// response ([`rebuild_clock_from_date`]).
pub const REBUILD_FLOOR_MS: u64 = 10 * 60 * 1000;

/// The fixed part of a measured margin: an HTTP `Date` header has whole
/// seconds, so the server's clock is known to within one second, and one more
/// second is slack. [`rebuild_clock_from_date`] adds the request's round trip.
pub const REBUILD_MARGIN_BASE_MS: u64 = 2_000;

/// How the device's clock relates to the server's, for
/// [`records_from_remote_with_clock`] (LD-0123).
///
/// A copy counts as backed up only when
/// `uploaded_at_ms > modified_ms + offset_ms + margin_ms`, computed exactly
/// (no overflow, no saturation). With `offset_ms` `None` the offset is taken
/// as 0 and the margin is at least [`REBUILD_FLOOR_MS`]. Build one with
/// [`rebuild_clock_from_date`] from a listing response; a hand-built clock
/// carries its own margin (the rule adds nothing to a measured one).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RebuildClock {
    /// `server_now - device_now` in milliseconds, measured from a listing
    /// response's `Date` header. Positive when the device clock is behind.
    /// `None` when it is not known.
    pub offset_ms: Option<i64>,
    /// The measurement's uncertainty in milliseconds:
    /// [`REBUILD_MARGIN_BASE_MS`] plus the request's round trip.
    pub margin_ms: u64,
}

impl RebuildClock {
    /// No offset known: the one-sided [`REBUILD_FLOOR_MS`] applies.
    pub const UNKNOWN: RebuildClock = RebuildClock {
        offset_ms: None,
        margin_ms: 0,
    };

    /// Whether a copy the server stamped `uploaded_at_ms` was made after the
    /// source entry last changed at `modified_ms` (the device's clock), with
    /// this clock's offset and margin. Exact for every `i64` input.
    pub fn copy_is_newer(&self, uploaded_at_ms: i64, modified_ms: i64) -> bool {
        let (offset, margin) = match self.offset_ms {
            Some(offset) => (offset, self.margin_ms),
            None => (0, self.margin_ms.max(REBUILD_FLOOR_MS)),
        };
        i128::from(uploaded_at_ms) > i128::from(modified_ms) + i128::from(offset) + i128::from(margin)
    }
}

/// The clock of one listing request (LD-0123): `date_header` is the response's
/// HTTP `Date` header (`Sun, 06 Nov 1994 08:49:37 GMT`), `sent_at_ms` and
/// `received_at_ms` the device's clock when the request went out and when the
/// response came back.
///
/// The server stamped the header at some device time between the two, and its
/// whole seconds hide up to one more second, so the offset is measured from
/// the midpoint and the margin is [`REBUILD_MARGIN_BASE_MS`] plus the round
/// trip, which covers both. Every failure leans toward uploading again: no
/// header, one that does not parse, or a response "received" before it was
/// sent (the device clock jumped) gives [`RebuildClock::UNKNOWN`], where the
/// floor applies.
pub fn rebuild_clock_from_date(date_header: Option<&str>, sent_at_ms: i64, received_at_ms: i64) -> RebuildClock {
    let Some(server_ms) = date_header
        .and_then(|date| chrono::DateTime::parse_from_rfc2822(date.trim()).ok())
        .map(|date| date.timestamp_millis())
    else {
        return RebuildClock::UNKNOWN;
    };
    let round_trip = i128::from(received_at_ms) - i128::from(sent_at_ms);
    if round_trip < 0 {
        return RebuildClock::UNKNOWN;
    }
    let midpoint = i128::from(sent_at_ms) + round_trip / 2;
    let Ok(offset_ms) = i64::try_from(i128::from(server_ms) - midpoint) else {
        return RebuildClock::UNKNOWN;
    };
    RebuildClock {
        offset_ms: Some(offset_ms),
        margin_ms: REBUILD_MARGIN_BASE_MS.saturating_add(u64::try_from(round_trip).unwrap_or(u64::MAX)),
    }
}

/// One file of this device's backup of a category, as the server lists it.
/// `key` is its path under the category folder.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemoteEntry {
    pub key: String,
    pub remote_id: Uuid,
    pub size: u64,
    pub uploaded_at_ms: i64,
}

/// [`records_from_remote_with_clock`] with [`RebuildClock::UNKNOWN`]: no
/// offset is known, so a copy counts only when it was uploaded more than
/// [`REBUILD_FLOOR_MS`] after the entry last changed (LD-0123). Kept for the
/// v0.2.1 signature; a caller that has a listing response passes its clock
/// to [`records_from_remote_with_clock`] instead.
pub fn records_from_remote(remote: &[RemoteEntry], entries: &[SourceEntry]) -> Vec<BackupRecord> {
    records_from_remote_with_clock(remote, entries, RebuildClock::UNKNOWN)
}

/// Records for the source entries the server already holds: the same key,
/// the same size, and uploaded after the entry last changed by
/// [`RebuildClock::copy_is_newer`] (later than `modified_ms + offset +
/// margin`, or than the floor with no offset known). Anything else is uploaded
/// again; the rule never marks a newer local file as backed up, and a device
/// clock that runs behind never makes a same-size edit look backed up
/// (LD-0123). When the server holds several qualifying copies at a key, the
/// newest upload wins. Each remote file backs at most one entry.
///
/// Keys match exactly first; then, for the entries left, by
/// [`normalize_key`] when no other entry left has the same normalised key. So
/// a Linux file named `a\b.jpg` and the file `b.jpg` in folder `a` each keep
/// their own copy. The records come sorted by key.
pub fn records_from_remote_with_clock(
    remote: &[RemoteEntry],
    entries: &[SourceEntry],
    clock: RebuildClock,
) -> Vec<BackupRecord> {
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
        match newest_copy(exact.get(file.key.as_str()), file, &used, clock) {
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
        if let Some(r) = newest_copy(normalized.get(&key), file, &used, clock) {
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
    clock: RebuildClock,
) -> Option<&'a RemoteEntry> {
    candidates?
        .iter()
        .copied()
        .filter(|r| {
            r.size == file.size
                && clock.copy_is_newer(r.uploaded_at_ms, file.modified_ms)
                && !used.contains(&r.remote_id)
        })
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
