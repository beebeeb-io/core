//! Whether this client may start a direct transfer right now (task 2173, clients plan A1, decision D19).
//!
//! A transfer that cannot go on directly (storage refuses every request, a proxy blocks the storage
//! host, the bucket's CORS drifted) must not be tried again for every file: it would cost every file
//! the same failed requests. After a give-up the client remembers it, **per direction**, and starts no
//! new direct transfer of that direction for one trust period (the same ten minutes as the discovery
//! answer, [`DISCOVERY_TTL_MS`](super::DISCOVERY_TTL_MS)); then it tries again. A file that has itself
//! given up direct is also kept off it for its own remaining life, whatever the clock says.
//!
//! Time is injected. A client that keeps the state in memory passes a monotonic clock; one that
//! persists it across launches (iOS) passes wall-clock milliseconds and stores the two timestamps with
//! [`DirectHealth::last_gave_up_ms`] / [`DirectHealth::restore`]. A recorded time later than "now" (a
//! clock that stepped back, a value written by a device with a wrong clock) counts as expired, so a bad
//! timestamp can never hold direct off for ever.

use super::{DISCOVERY_TTL_MS, within_trust};

/// How long a give-up holds new direct transfers off: one discovery trust period.
pub const HEALTH_TRUST_MS: i64 = DISCOVERY_TTL_MS;

/// Which way the bytes go. Health is kept apart: a bucket that refuses reads can still take writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Direction {
    Download,
    Upload,
}

impl Direction {
    /// Stable machine name (bindings and vectors).
    pub fn code(self) -> &'static str {
        match self {
            Direction::Download => "download",
            Direction::Upload => "upload",
        }
    }

    /// The inverse of [`Direction::code`]; anything else is `None`.
    pub fn from_code(code: &str) -> Option<Direction> {
        match code {
            "download" => Some(Direction::Download),
            "upload" => Some(Direction::Upload),
            _ => None,
        }
    }
}

/// The give-up memory of one client (one per API base and account).
#[derive(Debug, Clone, Default)]
pub struct DirectHealth {
    download: Option<i64>,
    upload: Option<i64>,
}

impl DirectHealth {
    pub fn new() -> Self {
        Self::default()
    }

    fn slot(&self, d: Direction) -> &Option<i64> {
        match d {
            Direction::Download => &self.download,
            Direction::Upload => &self.upload,
        }
    }

    fn slot_mut(&mut self, d: Direction) -> &mut Option<i64> {
        match d {
            Direction::Download => &mut self.download,
            Direction::Upload => &mut self.upload,
        }
    }

    /// A transfer of this direction gave up direct (a definite give-up, not a hiccup): no new one
    /// starts for [`HEALTH_TRUST_MS`] from `now_ms`. A later give-up renews the hold.
    pub fn gave_up(&mut self, d: Direction, now_ms: i64) {
        *self.slot_mut(d) = Some(now_ms);
    }

    /// May a new direct transfer of this direction start at `now_ms`?
    pub fn may_start(&self, d: Direction, now_ms: i64) -> bool {
        !self.slot(d).is_some_and(|at| within_trust(at, now_ms))
    }

    /// [`DirectHealth::may_start`] for a file that may already have given up direct itself: that file
    /// stays off direct whatever the clock says (`file_gave_up`), which bounds its re-init to one.
    pub fn may_start_file(&self, d: Direction, now_ms: i64, file_gave_up: bool) -> bool {
        !file_gave_up && self.may_start(d, now_ms)
    }

    /// When the last give-up of this direction was recorded, in the clock the caller uses.
    pub fn last_gave_up_ms(&self, d: Direction) -> Option<i64> {
        *self.slot(d)
    }

    /// Put back a timestamp that [`DirectHealth::last_gave_up_ms`] returned earlier (a relaunch).
    pub fn restore(&mut self, d: Direction, last_gave_up_ms: i64) {
        *self.slot_mut(d) = Some(last_gave_up_ms);
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::direct_transfer::DISCOVERY_TTL_MS;

    #[test]
    fn a_give_up_holds_new_transfers_off_direct_for_one_trust_period() {
        let mut h = DirectHealth::new();
        assert!(
            h.may_start(Direction::Upload, 1_000),
            "nothing recorded: direct may start"
        );
        h.gave_up(Direction::Upload, 1_000);
        assert!(!h.may_start(Direction::Upload, 1_000));
        assert!(!h.may_start(Direction::Upload, 1_000 + DISCOVERY_TTL_MS - 1));
        assert!(
            h.may_start(Direction::Upload, 1_000 + DISCOVERY_TTL_MS),
            "the hold ends after one trust period"
        );
        assert!(
            h.may_start(Direction::Download, 1_001),
            "the other direction is not held"
        );
    }

    #[test]
    fn the_trust_period_is_the_discovery_period() {
        assert_eq!(HEALTH_TRUST_MS, DISCOVERY_TTL_MS);
        assert_eq!(HEALTH_TRUST_MS, 10 * 60 * 1000);
    }

    #[test]
    fn the_files_own_bit_bounds_the_reinit_even_with_no_hold() {
        let h = DirectHealth::new();
        assert!(h.may_start_file(Direction::Upload, 0, false));
        assert!(
            !h.may_start_file(Direction::Upload, 0, true),
            "a file that gave up direct stays on the API, whatever the clock says"
        );
        assert!(!h.may_start_file(Direction::Download, i64::MAX, true));
        let mut held = DirectHealth::new();
        held.gave_up(Direction::Download, 5);
        assert!(
            !held.may_start_file(Direction::Download, 6, false),
            "a hold applies to a file with no bit of its own"
        );
        assert!(held.may_start_file(Direction::Download, 5 + DISCOVERY_TTL_MS, false));
    }

    #[test]
    fn a_restored_timestamp_behaves_like_a_live_one() {
        let mut live = DirectHealth::new();
        live.gave_up(Direction::Download, 7_000);
        let mut restored = DirectHealth::new();
        restored.restore(Direction::Download, live.last_gave_up_ms(Direction::Download).unwrap());
        for now in [
            7_000,
            7_001,
            7_000 + DISCOVERY_TTL_MS - 1,
            7_000 + DISCOVERY_TTL_MS,
            7_000 + 2 * DISCOVERY_TTL_MS,
        ] {
            assert_eq!(
                restored.may_start(Direction::Download, now),
                live.may_start(Direction::Download, now),
                "at {now}"
            );
        }
        assert_eq!(
            restored.last_gave_up_ms(Direction::Upload),
            None,
            "only the restored direction"
        );
    }

    #[test]
    fn a_recorded_time_in_the_future_counts_as_expired() {
        // A clock that stepped back, or a value persisted by a device with a wrong clock, must not hold direct off for ever.
        let mut h = DirectHealth::new();
        h.restore(Direction::Upload, 5_000);
        assert!(h.may_start(Direction::Upload, 1_000));
        let mut g = DirectHealth::new();
        g.gave_up(Direction::Upload, i64::MAX);
        assert!(g.may_start(Direction::Upload, 0));
    }

    #[test]
    fn directions_are_independent() {
        let mut h = DirectHealth::new();
        h.gave_up(Direction::Download, 10);
        assert!(!h.may_start(Direction::Download, 11));
        assert!(h.may_start(Direction::Upload, 11));
        assert_eq!(h.last_gave_up_ms(Direction::Download), Some(10));
        assert_eq!(h.last_gave_up_ms(Direction::Upload), None);
        h.gave_up(Direction::Upload, 20);
        assert_eq!(h.last_gave_up_ms(Direction::Download), Some(10), "unchanged");
        assert_eq!(h.last_gave_up_ms(Direction::Upload), Some(20));
    }

    #[test]
    fn a_new_give_up_renews_the_hold() {
        let mut h = DirectHealth::new();
        h.gave_up(Direction::Upload, 0);
        h.gave_up(Direction::Upload, DISCOVERY_TTL_MS - 1);
        assert!(
            !h.may_start(Direction::Upload, DISCOVERY_TTL_MS + 5),
            "held from the later give-up"
        );
        assert!(h.may_start(Direction::Upload, 2 * DISCOVERY_TTL_MS - 1));
    }

    #[test]
    fn direction_codes_round_trip_and_refuse_anything_else() {
        for d in [Direction::Download, Direction::Upload] {
            assert_eq!(Direction::from_code(d.code()), Some(d));
        }
        assert_eq!(Direction::Download.code(), "download");
        assert_eq!(Direction::Upload.code(), "upload");
        for bad in ["", "Download", "up", "uploads", "both"] {
            assert_eq!(Direction::from_code(bad), None, "{bad:?}");
        }
    }
}
