//! [`GraphBuilder`] — an in-memory accumulator that folds repeated observations
//! of the same node/edge into one record with a widening temporal [`Validity`]
//! (`PLAN.md` §8). This is the correlation-time working set; its contents are
//! drained and persisted to the DuckDB store, from which the CSR snapshot is
//! rebuilt.

use std::collections::HashMap;

use loghound_core::edge::EdgeType;
use loghound_core::node::NodeKind;
use loghound_core::{Edge, EdgeId, Node, NodeId, Timestamp};

/// Accumulates temporal nodes and edges keyed by their content-addressed ids.
#[derive(Debug, Default)]
pub struct GraphBuilder {
    nodes: HashMap<NodeId, Node>,
    edges: HashMap<EdgeId, Edge>,
}

impl GraphBuilder {
    pub fn new() -> Self {
        GraphBuilder::default()
    }

    /// Insert a node, or fold this observation into an existing one. Returns the
    /// content-addressed id so callers can wire edges.
    pub fn node(
        &mut self,
        kind: NodeKind,
        identity_key: &str,
        label: &str,
        ts: Timestamp,
    ) -> NodeId {
        let id = NodeId::of(kind, identity_key);
        self.nodes
            .entry(id)
            .and_modify(|n| n.observe(ts))
            .or_insert_with(|| Node::new(kind, identity_key, label, ts));
        id
    }

    /// Insert or fold an edge between two nodes.
    pub fn edge(&mut self, src: NodeId, dst: NodeId, etype: EdgeType, ts: Timestamp) -> EdgeId {
        let id = EdgeId::of(src, dst, etype);
        self.edges
            .entry(id)
            .and_modify(|e| e.observe(ts))
            .or_insert_with(|| Edge::new(src, dst, etype, ts));
        id
    }

    /// Set a property on an already-created node (no-op if the node is unknown).
    pub fn set_node_prop(&mut self, id: NodeId, key: &str, value: &str) {
        if let Some(n) = self.nodes.get_mut(&id) {
            n.props.insert(key.to_string(), value.to_string());
        }
    }

    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }

    /// Drain into sorted vectors (deterministic order for reproducible snapshots).
    pub fn into_parts(self) -> (Vec<Node>, Vec<Edge>) {
        let mut nodes: Vec<Node> = self.nodes.into_values().collect();
        let mut edges: Vec<Edge> = self.edges.into_values().collect();
        nodes.sort_by_key(|n| n.id.raw());
        edges.sort_by_key(|e| e.id.raw());
        (nodes, edges)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repeated_node_folds_validity() {
        let mut b = GraphBuilder::new();
        let a = b.node(NodeKind::Host, "dc01", "DC01", Timestamp(100));
        let a2 = b.node(NodeKind::Host, "dc01", "DC01", Timestamp(300));
        assert_eq!(a, a2);
        assert_eq!(b.node_count(), 1);
        let (nodes, _) = b.into_parts();
        assert_eq!(nodes[0].validity.first_seen, Timestamp(100));
        assert_eq!(nodes[0].validity.last_seen, Timestamp(300));
        assert_eq!(nodes[0].validity.event_count, 2);
    }

    #[test]
    fn repeated_edge_folds() {
        let mut b = GraphBuilder::new();
        let u = b.node(NodeKind::User, "alice", "alice", Timestamp(1));
        let h = b.node(NodeKind::Host, "dc01", "DC01", Timestamp(1));
        b.edge(u, h, EdgeType::LoggedInTo, Timestamp(10));
        b.edge(u, h, EdgeType::LoggedInTo, Timestamp(20));
        assert_eq!(b.edge_count(), 1);
        let (_, edges) = b.into_parts();
        assert_eq!(edges[0].validity.event_count, 2);
        assert_eq!(edges[0].validity.last_seen, Timestamp(20));
    }
}
