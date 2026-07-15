//! Content-addressed identifiers.
//!
//! [`NodeId`] and [`EdgeId`] are deterministic 64-bit hashes derived from an
//! entity's identity (kind + canonical key) or a relationship's `(src, dst, etype)`
//! triple. Determinism lets the ingest path compute ids without a database
//! round-trip and lets the same real-world entity dedup across files and runs
//! (`PLAN.md` §2, §6). [`EventId`] is an externally-assigned monotonic id.

use serde::{Deserialize, Serialize};
use xxhash_rust::xxh64::xxh64;

/// Fixed seed for all content-addressed hashing. Do not change once data exists.
const HASH_SEED: u64 = 0x4C6F_6748_6F75_6E64; // "LogHound" as bytes

/// Deterministic identity of a graph node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct NodeId(pub u64);

impl NodeId {
    /// Compute `node_id = xxh64(kind ++ 0x00 ++ identity_key)`.
    ///
    /// The `0x00` separator prevents `(kind, key)` collisions where a kind byte
    /// could otherwise merge with the start of a key.
    pub fn of(kind: crate::node::NodeKind, identity_key: &str) -> NodeId {
        let mut buf = Vec::with_capacity(identity_key.len() + 2);
        buf.push(kind.as_u8());
        buf.push(0x00);
        buf.extend_from_slice(identity_key.as_bytes());
        NodeId(xxh64(&buf, HASH_SEED))
    }

    #[inline]
    pub const fn raw(self) -> u64 {
        self.0
    }
}

/// Deterministic identity of an aggregated edge, unique per `(src, dst, etype)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EdgeId(pub u64);

impl EdgeId {
    /// Compute `edge_id = xxh64(src ++ dst ++ etype)`.
    pub fn of(src: NodeId, dst: NodeId, etype: crate::edge::EdgeType) -> EdgeId {
        let mut buf = [0u8; 17];
        buf[0..8].copy_from_slice(&src.0.to_le_bytes());
        buf[8..16].copy_from_slice(&dst.0.to_le_bytes());
        buf[16] = etype.as_u8();
        EdgeId(xxh64(&buf, HASH_SEED))
    }

    #[inline]
    pub const fn raw(self) -> u64 {
        self.0
    }
}

/// A monotonic event identifier, assigned by the ingest pipeline (`PLAN.md` §4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EventId(pub u64);

impl EventId {
    #[inline]
    pub const fn new(v: u64) -> EventId {
        EventId(v)
    }

    #[inline]
    pub const fn raw(self) -> u64 {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::edge::EdgeType;
    use crate::node::NodeKind;

    #[test]
    fn node_id_is_deterministic() {
        let a = NodeId::of(NodeKind::User, "CORP\\alice");
        let b = NodeId::of(NodeKind::User, "CORP\\alice");
        assert_eq!(a, b);
    }

    #[test]
    fn node_id_separator_prevents_kind_key_collision() {
        // Without the separator byte, a crafted key could merge with the kind
        // byte. Confirm two distinct (kind, key) pairs do not collide.
        let a = NodeId::of(NodeKind::from_u8(1).unwrap(), "x"); // kind=1, "x"
        let b = NodeId::of(NodeKind::from_u8(0).unwrap(), "\u{1}x"); // kind=0, key starts 0x01
        assert_ne!(a, b);
    }

    #[test]
    fn edge_id_is_deterministic_and_directional() {
        let s = NodeId(10);
        let d = NodeId(20);
        assert_eq!(
            EdgeId::of(s, d, EdgeType::Spawned),
            EdgeId::of(s, d, EdgeType::Spawned)
        );
        assert_ne!(
            EdgeId::of(s, d, EdgeType::Spawned),
            EdgeId::of(d, s, EdgeType::Spawned)
        );
    }
}
