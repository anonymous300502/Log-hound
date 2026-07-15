//! [`Graph`] — the coordinator that owns the single DuckDB [`Store`] (source of
//! truth) and the in-memory [`GraphIndex`], keeping them consistent
//! (`PLAN.md` §5, §6).
//!
//! In `M2` the index is (re)built by cold-loading the full node/edge set from
//! DuckDB via [`Graph::refresh_index`]; the streaming, incremental petgraph path
//! arrives with correlation in `M3`. [`Graph::check_invariants`] enforces the
//! DuckDB↔CSR parity invariant flagged as the highest correctness risk in
//! `PLAN.md` §17.

use std::path::Path;
use std::sync::Arc;

use loghound_core::{Edge, Event, Node};

use crate::index::GraphIndex;
use crate::store::{Store, StoreError, Table};

type Result<T> = std::result::Result<T, StoreError>;

/// Couples the persistent store with the in-memory graph index.
pub struct Graph {
    store: Store,
    index: Arc<GraphIndex>,
}

impl Graph {
    /// Open (creating if needed) a file-backed graph.
    pub fn open(path: impl AsRef<Path>) -> Result<Graph> {
        Ok(Graph {
            store: Store::open(path)?,
            index: Arc::new(GraphIndex::new()),
        })
    }

    /// Open an in-memory graph (tests / ephemeral analysis).
    pub fn open_in_memory() -> Result<Graph> {
        Ok(Graph {
            store: Store::open_in_memory()?,
            index: Arc::new(GraphIndex::new()),
        })
    }

    pub fn store(&self) -> &Store {
        &self.store
    }

    /// The in-memory index. Call [`Graph::refresh_index`] after writes to publish
    /// a fresh snapshot for readers.
    pub fn index(&self) -> &GraphIndex {
        &self.index
    }

    /// A shared handle to the lock-free index, for readers (e.g. the API) that
    /// traverse concurrently with DB access.
    pub fn index_handle(&self) -> Arc<GraphIndex> {
        Arc::clone(&self.index)
    }

    // ---- writes (the single writer funnels through here) ----

    pub fn append_event(&self, ev: &Event, batch: u64) -> Result<()> {
        self.store.append_event(ev, batch)
    }

    pub fn upsert_node(&self, node: &Node) -> Result<()> {
        self.store.upsert_node(node)
    }

    pub fn upsert_edge(&self, edge: &Edge) -> Result<()> {
        self.store.upsert_edge(edge)
    }

    /// Persist a correlated batch of nodes and edges, then republish the CSR
    /// snapshot. This is the bridge from the correlation engine (`M3`) to the
    /// queryable graph.
    pub fn apply(&self, nodes: &[Node], edges: &[Edge]) -> Result<()> {
        for n in nodes {
            self.store.upsert_node(n)?;
        }
        for e in edges {
            self.store.upsert_edge(e)?;
        }
        self.refresh_index()
    }

    /// Recompute composite risk over the current CSR snapshot, persist the scores
    /// to DuckDB, and republish the snapshot so traversal/attack-path search see
    /// the updated risk (`PLAN.md` §6, M7). Returns the number of nodes scored.
    pub fn recompute_risk(&self) -> Result<usize> {
        let scores = self.index.load().compute_risk();
        let pairs: Vec<(loghound_core::NodeId, f32)> =
            scores.iter().map(|s| (s.node_id, s.score)).collect();
        self.store.set_risk_scores(&pairs)?;
        self.refresh_index()?;
        Ok(pairs.len())
    }

    /// Cold-load the entire node/edge set from DuckDB and atomically publish a
    /// fresh CSR snapshot. This is the `M2` (re)build path and the crash-recovery
    /// path (DuckDB is the source of truth).
    pub fn refresh_index(&self) -> Result<()> {
        let nodes = self.store.load_nodes()?;
        let edges = self.store.load_edges()?;
        self.index.rebuild(&nodes, &edges);
        Ok(())
    }

    /// Assert DuckDB↔CSR parity (node and edge counts). Returns an error naming
    /// the mismatch so callers can fail loudly rather than serve a stale graph.
    pub fn check_invariants(&self) -> Result<()> {
        let snap = self.index.load();
        let db_nodes = self.store.count(Table::Nodes)?;
        let db_edges = self.store.count(Table::Edges)?;
        if snap.node_count() as u64 != db_nodes {
            return Err(StoreError::Integrity(format!(
                "node count mismatch: index={} store={}",
                snap.node_count(),
                db_nodes
            )));
        }
        if snap.edge_count() as u64 != db_edges {
            return Err(StoreError::Integrity(format!(
                "edge count mismatch: index={} store={}",
                snap.edge_count(),
                db_edges
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::TraversalOpts;
    use loghound_core::edge::EdgeType;
    use loghound_core::node::NodeKind;
    use loghound_core::Timestamp;

    #[test]
    fn refresh_then_invariants_hold_and_graph_is_queryable() {
        let g = Graph::open_in_memory().expect("open");

        let alice = Node::new(NodeKind::User, "alice", "alice", Timestamp(100));
        let dc01 = Node::new(NodeKind::Host, "dc01", "DC01", Timestamp(100));
        g.upsert_node(&alice).unwrap();
        g.upsert_node(&dc01).unwrap();
        let e = Edge::new(alice.id, dc01.id, EdgeType::LoggedInTo, Timestamp(100));
        g.upsert_edge(&e).unwrap();

        // Before refresh the index is empty; the invariant catches the divergence.
        assert!(g.check_invariants().is_err());

        g.refresh_index().unwrap();
        g.check_invariants().expect("parity after refresh");

        // The graph is now queryable in-memory.
        let snap = g.index().load();
        let sub = snap.neighbors(alice.id, &TraversalOpts::default());
        assert!(sub.nodes.iter().any(|v| v.id == dc01.id));
        assert_eq!(sub.edges.len(), 1);
    }
}
