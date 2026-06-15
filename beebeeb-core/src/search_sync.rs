//! Pure manifest-diff helper for syncing the encrypted search index (task 0784).
//!
//! Given the server's shard manifest (from `GET /api/v1/search-index/shards`,
//! task 0783) and the client's local shard set, compute which shards to PUT
//! (upload), GET (download), and DELETE so the two converge. No crypto, no I/O —
//! pure set reconciliation, so every client binding can share it and it is fully
//! unit-tested.
//!
//! This does NOT touch the verified 0778-B index algorithm/crypto — it is a
//! standalone bookkeeping helper over shard coordinates + versions.

use std::collections::BTreeMap;

/// A shard the holder has, with the version it last knows for that coordinate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShardRef {
    pub bucket: u32,
    pub page: u32,
    pub version: i64,
}

/// A shard coordinate (no version) — an action target in a [`SyncPlan`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ShardCoord {
    pub bucket: u32,
    pub page: u32,
}

impl ShardRef {
    fn coord(&self) -> ShardCoord {
        ShardCoord {
            bucket: self.bucket,
            page: self.page,
        }
    }
}

/// The reconciliation plan: which shard coordinates to push to / pull from /
/// delete on the server. All three lists are sorted and de-duplicated.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SyncPlan {
    /// Local shards to PUT — new locally, or the local version is newer.
    pub to_put: Vec<ShardCoord>,
    /// Server shards to GET — present only on the server (non-authoritative
    /// mode), or the server version is newer.
    pub to_get: Vec<ShardCoord>,
    /// Server shards to DELETE — present on the server but not locally, only when
    /// the local set is authoritative (e.g. just after a full rebuild).
    pub to_delete: Vec<ShardCoord>,
}

/// Reconcile the client's `local` shard set against the server `remote` manifest,
/// last-writer-wins by `version`.
///
/// `local_is_authoritative` resolves the one ambiguous case — a coordinate the
/// server has but the client does not:
/// - `true` (the client just rebuilt its whole index, so `local` is the complete
///   truth): such a coordinate is a stale server shard → **DELETE**.
/// - `false` (an incremental pull): it is a shard another device added →
///   **GET**.
///
/// Coordinates present on both sides compare versions: local newer → PUT, remote
/// newer → GET, equal → no action. Coordinates only local → PUT.
pub fn diff_manifest(local: &[ShardRef], remote: &[ShardRef], local_is_authoritative: bool) -> SyncPlan {
    let local_map: BTreeMap<ShardCoord, i64> = local.iter().map(|s| (s.coord(), s.version)).collect();
    let remote_map: BTreeMap<ShardCoord, i64> = remote.iter().map(|s| (s.coord(), s.version)).collect();

    let mut plan = SyncPlan::default();

    for (coord, &lver) in &local_map {
        match remote_map.get(coord) {
            None => plan.to_put.push(*coord),                       // server has never seen it
            Some(&rver) if lver > rver => plan.to_put.push(*coord), // local is newer
            Some(&rver) if rver > lver => plan.to_get.push(*coord), // remote is newer
            Some(_) => {}                                           // in sync
        }
    }

    for coord in remote_map.keys() {
        if local_map.contains_key(coord) {
            continue; // already handled above
        }
        if local_is_authoritative {
            plan.to_delete.push(*coord);
        } else {
            plan.to_get.push(*coord);
        }
    }

    plan.to_put.sort_unstable();
    plan.to_get.sort_unstable();
    plan.to_delete.sort_unstable();
    plan
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(bucket: u32, page: u32, version: i64) -> ShardRef {
        ShardRef { bucket, page, version }
    }
    fn c(bucket: u32, page: u32) -> ShardCoord {
        ShardCoord { bucket, page }
    }

    #[test]
    fn empty_both_sides_is_noop() {
        let p = diff_manifest(&[], &[], true);
        assert_eq!(p, SyncPlan::default());
    }

    #[test]
    fn local_only_is_put() {
        let p = diff_manifest(&[r(1, 0, 1), r(2, 0, 1)], &[], false);
        assert_eq!(p.to_put, vec![c(1, 0), c(2, 0)]);
        assert!(p.to_get.is_empty() && p.to_delete.is_empty());
    }

    #[test]
    fn local_newer_is_put_remote_newer_is_get() {
        let local = [r(1, 0, 5), r(2, 0, 2)];
        let remote = [r(1, 0, 3), r(2, 0, 9)];
        let p = diff_manifest(&local, &remote, false);
        assert_eq!(p.to_put, vec![c(1, 0)]); // local 5 > remote 3
        assert_eq!(p.to_get, vec![c(2, 0)]); // remote 9 > local 2
        assert!(p.to_delete.is_empty());
    }

    #[test]
    fn equal_version_is_noop() {
        let p = diff_manifest(&[r(1, 0, 4)], &[r(1, 0, 4)], true);
        assert_eq!(p, SyncPlan::default());
    }

    #[test]
    fn remote_only_authoritative_is_delete() {
        let p = diff_manifest(&[], &[r(7, 1, 2)], true);
        assert_eq!(p.to_delete, vec![c(7, 1)]);
        assert!(p.to_put.is_empty() && p.to_get.is_empty());
    }

    #[test]
    fn remote_only_non_authoritative_is_get() {
        let p = diff_manifest(&[], &[r(7, 1, 2)], false);
        assert_eq!(p.to_get, vec![c(7, 1)]);
        assert!(p.to_put.is_empty() && p.to_delete.is_empty());
    }

    #[test]
    fn mixed_authoritative_rebuild() {
        // Client rebuilt: has buckets 1,2 (new + changed); server still has an old
        // bucket 3 that the client dropped, and a stale bucket 1.
        let local = [r(1, 0, 2), r(2, 0, 1)];
        let remote = [r(1, 0, 1), r(3, 0, 5)];
        let p = diff_manifest(&local, &remote, true);
        assert_eq!(p.to_put, vec![c(1, 0), c(2, 0)]); // 1 newer, 2 new
        assert_eq!(p.to_delete, vec![c(3, 0)]); // dropped locally
        assert!(p.to_get.is_empty());
    }
}
