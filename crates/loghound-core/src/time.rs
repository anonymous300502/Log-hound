//! Time primitives: epoch-millisecond [`Timestamp`] and the temporal
//! [`Validity`] interval carried by every node and edge.
//!
//! All timestamps in LogHound are milliseconds since the Unix epoch (UTC),
//! stored as `i64` (see `PLAN.md` §4). Integer interval math keeps temporal
//! filtering branch-cheap and avoids `TIMESTAMP` coercion surprises across the
//! DuckDB FFI boundary.

use serde::{Deserialize, Serialize};

/// A point in time, in milliseconds since the Unix epoch (UTC).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Timestamp(pub i64);

impl Timestamp {
    /// Smallest representable instant (used as an open lower bound).
    pub const MIN: Timestamp = Timestamp(i64::MIN);
    /// Largest representable instant (used as an open upper bound).
    pub const MAX: Timestamp = Timestamp(i64::MAX);

    /// Construct from epoch milliseconds.
    #[inline]
    pub const fn from_millis(ms: i64) -> Self {
        Timestamp(ms)
    }

    /// Epoch milliseconds.
    #[inline]
    pub const fn millis(self) -> i64 {
        self.0
    }

    /// Epoch seconds (truncating).
    #[inline]
    pub const fn secs(self) -> i64 {
        self.0 / 1000
    }
}

impl From<i64> for Timestamp {
    #[inline]
    fn from(ms: i64) -> Self {
        Timestamp(ms)
    }
}

/// Temporal validity interval carried by every [`crate::Node`] and
/// [`crate::Edge`].
///
/// Repeated observations of the same entity/relationship fold into one record:
/// the interval widens to cover the new observation and `event_count` increments
/// — the `ON CREATE / ON MATCH count += 1` semantics of the original prototype,
/// promoted here to a first-class type (`PLAN.md` §2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Validity {
    pub first_seen: Timestamp,
    pub last_seen: Timestamp,
    pub event_count: u64,
}

impl Validity {
    /// A validity seeded by a single observation at `at`.
    #[inline]
    pub fn at(at: Timestamp) -> Self {
        Validity {
            first_seen: at,
            last_seen: at,
            event_count: 1,
        }
    }

    /// Fold another observation in: widen `[first_seen, last_seen]` to include
    /// `at` and increment `event_count`. Observations may arrive out of order.
    #[inline]
    pub fn observe(&mut self, at: Timestamp) {
        if at < self.first_seen {
            self.first_seen = at;
        }
        if at > self.last_seen {
            self.last_seen = at;
        }
        self.event_count += 1;
    }

    /// Merge another validity interval into this one (used when deduping across
    /// ingest batches). Counts add; the interval widens to the union.
    #[inline]
    pub fn merge(&mut self, other: &Validity) {
        if other.first_seen < self.first_seen {
            self.first_seen = other.first_seen;
        }
        if other.last_seen > self.last_seen {
            self.last_seen = other.last_seen;
        }
        self.event_count += other.event_count;
    }

    /// Present at instant `t` iff `first_seen <= t <= last_seen`.
    #[inline]
    pub fn live_at(&self, t: Timestamp) -> bool {
        self.first_seen <= t && t <= self.last_seen
    }

    /// Present over the closed window `[lo, hi]` iff the intervals overlap.
    ///
    /// This is the predicate that powers time-scoped ("rewind") traversal
    /// (`PLAN.md` §6).
    #[inline]
    pub fn live_in(&self, lo: Timestamp, hi: Timestamp) -> bool {
        self.first_seen <= hi && self.last_seen >= lo
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observe_widens_interval_and_counts() {
        let mut v = Validity::at(Timestamp(100));
        assert_eq!(v.event_count, 1);
        v.observe(Timestamp(200)); // later
        v.observe(Timestamp(50)); // earlier (out of order)
        assert_eq!(v.first_seen, Timestamp(50));
        assert_eq!(v.last_seen, Timestamp(200));
        assert_eq!(v.event_count, 3);
    }

    #[test]
    fn merge_unions_intervals_and_adds_counts() {
        let mut a = Validity::at(Timestamp(100));
        let b = Validity {
            first_seen: Timestamp(40),
            last_seen: Timestamp(300),
            event_count: 5,
        };
        a.merge(&b);
        assert_eq!(a.first_seen, Timestamp(40));
        assert_eq!(a.last_seen, Timestamp(300));
        assert_eq!(a.event_count, 6);
    }

    #[test]
    fn live_at_is_inclusive() {
        let v = Validity {
            first_seen: Timestamp(100),
            last_seen: Timestamp(200),
            event_count: 1,
        };
        assert!(!v.live_at(Timestamp(99)));
        assert!(v.live_at(Timestamp(100))); // inclusive lower
        assert!(v.live_at(Timestamp(150)));
        assert!(v.live_at(Timestamp(200))); // inclusive upper
        assert!(!v.live_at(Timestamp(201)));
    }

    #[test]
    fn live_in_detects_overlap() {
        let v = Validity {
            first_seen: Timestamp(100),
            last_seen: Timestamp(200),
            event_count: 1,
        };
        assert!(v.live_in(Timestamp(0), Timestamp(100))); // touches lower edge
        assert!(v.live_in(Timestamp(150), Timestamp(160))); // inside
        assert!(v.live_in(Timestamp(200), Timestamp(999))); // touches upper edge
        assert!(v.live_in(Timestamp(0), Timestamp(9999))); // superset
        assert!(!v.live_in(Timestamp(0), Timestamp(99))); // fully before
        assert!(!v.live_in(Timestamp(201), Timestamp(999))); // fully after
    }
}
