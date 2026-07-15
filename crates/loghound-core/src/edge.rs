//! Graph edge types and the [`Edge`] record.
//!
//! Edges are aggregated: there is at most one edge per `(src, dst, etype)`
//! triple, identified by [`crate::EdgeId::of`]. Repeated occurrences fold into
//! that edge's [`Validity`] (widen interval, increment `event_count`) — matching
//! the DuckDB `edges` uniqueness constraint (`PLAN.md` §4). Per-occurrence
//! timing is preserved separately via the `edge_events` provenance table.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::ids::{EdgeId, NodeId};
use crate::time::{Timestamp, Validity};

/// The semantic type of a relationship between two nodes.
///
/// `#[repr(u8)]` to map onto DuckDB `edges.etype UTINYINT` and the CSR snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[repr(u8)]
pub enum EdgeType {
    LoggedInTo = 0,
    Authenticated = 1,
    Started = 2,
    Spawned = 3,
    ParentOf = 4,
    ChildOf = 5,
    Executed = 6,
    Used = 7,
    RanAs = 8,
    ConnectedTo = 9,
    Resolved = 10,
    Accessed = 11,
    Created = 12,
    Modified = 13,
    Deleted = 14,
    Owns = 15,
    BelongsTo = 16,
    Generated = 17,
    RequestedTicket = 18,
    AcquiredPrivilege = 19,
    LateralMovement = 20,
    /// Entity → Alert (the detection overlay).
    Triggered = 21,
}

impl EdgeType {
    #[inline]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    pub const fn from_u8(v: u8) -> Option<EdgeType> {
        use EdgeType::*;
        let e = match v {
            0 => LoggedInTo,
            1 => Authenticated,
            2 => Started,
            3 => Spawned,
            4 => ParentOf,
            5 => ChildOf,
            6 => Executed,
            7 => Used,
            8 => RanAs,
            9 => ConnectedTo,
            10 => Resolved,
            11 => Accessed,
            12 => Created,
            13 => Modified,
            14 => Deleted,
            15 => Owns,
            16 => BelongsTo,
            17 => Generated,
            18 => RequestedTicket,
            19 => AcquiredPrivilege,
            20 => LateralMovement,
            21 => Triggered,
            _ => return None,
        };
        Some(e)
    }

    /// Parse an edge type from its [`EdgeType::name`] (used for API filter params).
    pub fn from_name(s: &str) -> Option<EdgeType> {
        (0u8..=21).map(EdgeType::from_u8).find_map(|e| match e {
            Some(e) if e.name() == s => Some(e),
            _ => None,
        })
    }

    /// Stable UPPER_SNAKE label used in API payloads and Cytoscape edge labels.
    pub const fn name(self) -> &'static str {
        use EdgeType::*;
        match self {
            LoggedInTo => "LOGGED_IN_TO",
            Authenticated => "AUTHENTICATED",
            Started => "STARTED",
            Spawned => "SPAWNED",
            ParentOf => "PARENT_OF",
            ChildOf => "CHILD_OF",
            Executed => "EXECUTED",
            Used => "USED",
            RanAs => "RAN_AS",
            ConnectedTo => "CONNECTED_TO",
            Resolved => "RESOLVED",
            Accessed => "ACCESSED",
            Created => "CREATED",
            Modified => "MODIFIED",
            Deleted => "DELETED",
            Owns => "OWNS",
            BelongsTo => "BELONGS_TO",
            Generated => "GENERATED",
            RequestedTicket => "REQUESTED_TICKET",
            AcquiredPrivilege => "ACQUIRED_PRIVILEGE",
            LateralMovement => "LATERAL_MOVEMENT",
            Triggered => "TRIGGERED",
        }
    }
}

/// A temporal, directed, aggregated relationship between two nodes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Edge {
    pub id: EdgeId,
    pub src: NodeId,
    pub dst: NodeId,
    pub etype: EdgeType,
    pub validity: Validity,
    /// Traversal/risk weight (`PLAN.md` §6); defaults to `1.0`.
    pub weight: f32,
    pub props: BTreeMap<String, String>,
}

impl Edge {
    /// Create an edge, deriving its [`EdgeId`] from `(src, dst, etype)` and
    /// seeding a single-observation [`Validity`] at `first_seen`.
    pub fn new(src: NodeId, dst: NodeId, etype: EdgeType, first_seen: Timestamp) -> Edge {
        Edge {
            id: EdgeId::of(src, dst, etype),
            src,
            dst,
            etype,
            validity: Validity::at(first_seen),
            weight: 1.0,
            props: BTreeMap::new(),
        }
    }

    pub fn with_prop(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.props.insert(key.into(), value.into());
        self
    }

    /// Record another occurrence of this relationship at `at`.
    #[inline]
    pub fn observe(&mut self, at: Timestamp) {
        self.validity.observe(at);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::NodeKind;

    #[test]
    fn discriminant_roundtrips_for_all_types() {
        for v in 0u8..=21 {
            let e = EdgeType::from_u8(v).expect("known type");
            assert_eq!(e.as_u8(), v);
        }
        assert_eq!(EdgeType::from_u8(22), None);
    }

    #[test]
    fn edge_id_stable_per_triple_and_directional() {
        let u = NodeId::of(NodeKind::User, "alice");
        let h = NodeId::of(NodeKind::Host, "dc01");
        let e1 = Edge::new(u, h, EdgeType::LoggedInTo, Timestamp(1));
        let e2 = Edge::new(u, h, EdgeType::LoggedInTo, Timestamp(50));
        assert_eq!(e1.id, e2.id, "same (src,dst,etype) => same edge id");

        // Direction matters, and edge type matters.
        assert_ne!(
            e1.id,
            Edge::new(h, u, EdgeType::LoggedInTo, Timestamp(1)).id
        );
        assert_ne!(
            e1.id,
            Edge::new(u, h, EdgeType::Authenticated, Timestamp(1)).id
        );
    }
}
