//! Graph node kinds and the [`Node`] record.
//!
//! Node identity is content-addressed: `node_id = xxh64(kind ++ 0x00 ++ identity_key)`
//! (see [`crate::NodeId::of`]). The `identity_key` is a canonical string chosen
//! per kind so that repeated observations of the same real-world entity collapse
//! to one node (`PLAN.md` §2). Notably, a [`NodeKind::Process`] is keyed by
//! `host:pid:start_time`, which is what makes PID reuse unambiguous.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::ids::NodeId;
use crate::time::{Timestamp, Validity};

/// The kind of a graph node.
///
/// `#[repr(u8)]` so the discriminant maps directly onto the DuckDB `nodes.kind
/// UTINYINT` column and into the compact in-memory CSR snapshot (`PLAN.md` §4, §6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[repr(u8)]
pub enum NodeKind {
    User = 0,
    Host = 1,
    Domain = 2,
    Process = 3,
    Executable = 4,
    CommandLine = 5,
    LogonSession = 6,
    NetworkConnection = 7,
    IpAddress = 8,
    DnsName = 9,
    File = 10,
    RegistryKey = 11,
    Service = 12,
    Task = 13,
    Sid = 14,
    Privilege = 15,
    Certificate = 16,
    Ioc = 17,
    Alert = 18,
    /// An event promoted to a node (rare — only when an Alert/IOC must point at
    /// a specific event). Events normally live in the `events` table, not the
    /// graph (`PLAN.md` §2).
    Event = 19,
}

impl NodeKind {
    /// The discriminant as stored in DuckDB / the CSR snapshot.
    #[inline]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Reconstruct a kind from its stored discriminant.
    pub const fn from_u8(v: u8) -> Option<NodeKind> {
        use NodeKind::*;
        let k = match v {
            0 => User,
            1 => Host,
            2 => Domain,
            3 => Process,
            4 => Executable,
            5 => CommandLine,
            6 => LogonSession,
            7 => NetworkConnection,
            8 => IpAddress,
            9 => DnsName,
            10 => File,
            11 => RegistryKey,
            12 => Service,
            13 => Task,
            14 => Sid,
            15 => Privilege,
            16 => Certificate,
            17 => Ioc,
            18 => Alert,
            19 => Event,
            _ => return None,
        };
        Some(k)
    }

    /// Parse a kind from its [`NodeKind::name`] (used for API filter params).
    pub fn from_name(s: &str) -> Option<NodeKind> {
        (0u8..=19).map(NodeKind::from_u8).find_map(|k| match k {
            Some(k) if k.name() == s => Some(k),
            _ => None,
        })
    }

    /// Stable lowercase name used in API payloads and Cytoscape node classes.
    pub const fn name(self) -> &'static str {
        use NodeKind::*;
        match self {
            User => "user",
            Host => "host",
            Domain => "domain",
            Process => "process",
            Executable => "executable",
            CommandLine => "command_line",
            LogonSession => "logon_session",
            NetworkConnection => "network_connection",
            IpAddress => "ip_address",
            DnsName => "dns_name",
            File => "file",
            RegistryKey => "registry_key",
            Service => "service",
            Task => "task",
            Sid => "sid",
            Privilege => "privilege",
            Certificate => "certificate",
            Ioc => "ioc",
            Alert => "alert",
            Event => "event",
        }
    }
}

/// A temporal graph node: an entity reconstructed from telemetry.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Node {
    pub id: NodeId,
    pub kind: NodeKind,
    /// Canonical dedup string (`PLAN.md` §2). Distinct from `label`.
    pub identity_key: String,
    /// Human-facing display text (user name, hostname, exe basename, ...).
    pub label: String,
    pub validity: Validity,
    /// Composite risk score from the analytics pass (`PLAN.md` §6); `0.0` until computed.
    pub risk_score: f32,
    /// Kind-specific attributes (sorted for deterministic serialization/tests).
    pub props: BTreeMap<String, String>,
}

impl Node {
    /// Create a node, deriving its content-addressed [`NodeId`] from
    /// `(kind, identity_key)` and seeding a single-observation [`Validity`] at
    /// `first_seen`.
    pub fn new(
        kind: NodeKind,
        identity_key: impl Into<String>,
        label: impl Into<String>,
        first_seen: Timestamp,
    ) -> Node {
        let identity_key = identity_key.into();
        let id = NodeId::of(kind, &identity_key);
        Node {
            id,
            kind,
            identity_key,
            label: label.into(),
            validity: Validity::at(first_seen),
            risk_score: 0.0,
            props: BTreeMap::new(),
        }
    }

    /// Attach a property, returning `self` for builder-style construction.
    pub fn with_prop(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.props.insert(key.into(), value.into());
        self
    }

    /// Record another observation of this entity at `at`.
    #[inline]
    pub fn observe(&mut self, at: Timestamp) {
        self.validity.observe(at);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discriminant_roundtrips_for_all_kinds() {
        for v in 0u8..=19 {
            let k = NodeKind::from_u8(v).expect("known kind");
            assert_eq!(k.as_u8(), v);
        }
        assert_eq!(NodeKind::from_u8(20), None);
    }

    #[test]
    fn same_identity_key_yields_same_id() {
        let a = Node::new(NodeKind::Host, "dc01.corp.local", "DC01", Timestamp(1));
        let b = Node::new(NodeKind::Host, "dc01.corp.local", "DC01", Timestamp(999));
        assert_eq!(a.id, b.id, "dedup key must be stable across observations");
    }

    #[test]
    fn different_kind_same_key_yields_different_id() {
        let host = Node::new(NodeKind::Host, "x", "x", Timestamp(1));
        let user = Node::new(NodeKind::User, "x", "x", Timestamp(1));
        assert_ne!(host.id, user.id);
    }
}
