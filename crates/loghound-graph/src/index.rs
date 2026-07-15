//! The in-memory graph index: an immutable **CSR snapshot** for fast, time-aware
//! traversal, published behind an [`arc_swap::ArcSwap`] for lock-free reads
//! (`PLAN.md` §6).
//!
//! The snapshot stores only topology + validity intervals + risk (structure of
//! arrays, cache-friendly). Labels, props, and raw bodies stay in DuckDB and are
//! hydrated on demand at the API layer — this split is what keeps memory bounded
//! at 10M-event scale.
//!
//! `M2` builds the snapshot by full rebuild from the node/edge set. The mutable
//! `petgraph` build-graph for incremental streaming mutation arrives with the
//! correlation engine in `M3`.

use std::sync::Arc;

use ahash::AHashMap;
use arc_swap::ArcSwap;

use loghound_core::edge::EdgeType;
use loghound_core::node::NodeKind;
use loghound_core::{Edge, EdgeId, Node, NodeId, Timestamp};

/// Traversal direction relative to edge orientation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dir {
    Out,
    In,
    Both,
}

/// A bitmask over [`EdgeType`] discriminants (22 types fit in a `u32`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct EdgeTypeMask(u32);

impl EdgeTypeMask {
    pub fn none() -> Self {
        EdgeTypeMask(0)
    }

    pub fn of(types: &[EdgeType]) -> Self {
        let mut m = 0u32;
        for t in types {
            m |= 1 << t.as_u8();
        }
        EdgeTypeMask(m)
    }

    #[inline]
    pub fn contains(self, t: EdgeType) -> bool {
        self.0 & (1 << t.as_u8()) != 0
    }
}

/// Options controlling a traversal (`PLAN.md` §6).
#[derive(Debug, Clone, Copy)]
pub struct TraversalOpts {
    /// Optional inclusive time window `[lo, hi]`; edges must overlap it ("rewind").
    pub time: Option<(Timestamp, Timestamp)>,
    /// Optional edge-type filter; `None` means all types.
    pub etypes: Option<EdgeTypeMask>,
    pub max_hops: u32,
    pub direction: Dir,
}

impl Default for TraversalOpts {
    fn default() -> Self {
        TraversalOpts {
            time: None,
            etypes: None,
            max_hops: 1,
            direction: Dir::Both,
        }
    }
}

/// A lightweight node projection returned by traversals.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct NodeView {
    pub id: NodeId,
    pub kind: NodeKind,
    pub first_seen: Timestamp,
    pub last_seen: Timestamp,
    pub risk: f32,
}

/// A lightweight edge projection returned by traversals.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct EdgeView {
    pub id: EdgeId,
    pub src: NodeId,
    pub dst: NodeId,
    pub etype: EdgeType,
    pub first_seen: Timestamp,
    pub last_seen: Timestamp,
    pub event_count: u64,
    pub weight: f32,
}

/// The materialized result of a neighborhood/path traversal.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Subgraph {
    pub nodes: Vec<NodeView>,
    pub edges: Vec<EdgeView>,
}

/// Immutable compressed-sparse-row snapshot of the temporal graph.
///
/// Fields are `pub(crate)` so the [`crate::analytics`] module can run algorithms
/// (PageRank, components, weighted paths) directly over the arrays; they are not
/// part of the public API.
#[derive(Debug, Default)]
pub struct CsrSnapshot {
    // dense node arrays (index = dense id in 0..n)
    pub(crate) node_id: Vec<u64>,
    pub(crate) node_kind: Vec<NodeKind>,
    pub(crate) node_first: Vec<i64>,
    pub(crate) node_last: Vec<i64>,
    pub(crate) node_risk: Vec<f32>,

    // forward CSR; edge attribute arrays are aligned to forward "slot" order
    pub(crate) row_offsets: Vec<u32>, // len n+1
    pub(crate) col_dst: Vec<u32>,     // len m, dense dst per slot
    pub(crate) edge_id: Vec<u64>,
    pub(crate) edge_type: Vec<EdgeType>,
    pub(crate) edge_first: Vec<i64>,
    pub(crate) edge_last: Vec<i64>,
    pub(crate) edge_count: Vec<u64>,
    pub(crate) edge_weight: Vec<f32>,

    // reverse CSR: for each dense node, its incoming edges (by forward slot)
    pub(crate) rev_offsets: Vec<u32>,  // len n+1
    pub(crate) rev_src: Vec<u32>,      // dense src per rev entry
    pub(crate) rev_edge_ref: Vec<u32>, // forward slot per rev entry

    pub(crate) dense_of_id: AHashMap<u64, u32>,
}

impl CsrSnapshot {
    pub fn empty() -> Self {
        let mut s = CsrSnapshot::default();
        s.row_offsets.push(0);
        s.rev_offsets.push(0);
        s
    }

    pub fn node_count(&self) -> usize {
        self.node_id.len()
    }

    pub fn edge_count(&self) -> usize {
        self.edge_id.len()
    }

    /// Build a snapshot from the full node and edge sets. Edges referencing an
    /// unknown node are skipped (dangling-edge guard).
    pub fn build(nodes: &[Node], edges: &[Edge]) -> Self {
        let n = nodes.len();
        let mut dense_of_id = AHashMap::with_capacity(n);
        let mut node_id = Vec::with_capacity(n);
        let mut node_kind = Vec::with_capacity(n);
        let mut node_first = Vec::with_capacity(n);
        let mut node_last = Vec::with_capacity(n);
        let mut node_risk = Vec::with_capacity(n);
        for (dense, node) in nodes.iter().enumerate() {
            dense_of_id.insert(node.id.raw(), dense as u32);
            node_id.push(node.id.raw());
            node_kind.push(node.kind);
            node_first.push(node.validity.first_seen.millis());
            node_last.push(node.validity.last_seen.millis());
            node_risk.push(node.risk_score);
        }

        // Keep only edges whose endpoints exist; capture dense endpoints.
        let mut kept: Vec<(u32, u32, &Edge)> = Vec::with_capacity(edges.len());
        for e in edges {
            if let (Some(&s), Some(&d)) =
                (dense_of_id.get(&e.src.raw()), dense_of_id.get(&e.dst.raw()))
            {
                kept.push((s, d, e));
            }
        }
        // Forward CSR: sort by dense src so each node's out-edges are contiguous.
        kept.sort_by_key(|(s, _, _)| *s);

        let m = kept.len();
        let mut row_offsets = vec![0u32; n + 1];
        for (s, _, _) in &kept {
            row_offsets[*s as usize + 1] += 1;
        }
        for i in 0..n {
            row_offsets[i + 1] += row_offsets[i];
        }

        let mut col_dst = Vec::with_capacity(m);
        let mut edge_id = Vec::with_capacity(m);
        let mut edge_type = Vec::with_capacity(m);
        let mut edge_first = Vec::with_capacity(m);
        let mut edge_last = Vec::with_capacity(m);
        let mut edge_count = Vec::with_capacity(m);
        let mut edge_weight = Vec::with_capacity(m);
        for (_, d, e) in &kept {
            col_dst.push(*d);
            edge_id.push(e.id.raw());
            edge_type.push(e.etype);
            edge_first.push(e.validity.first_seen.millis());
            edge_last.push(e.validity.last_seen.millis());
            edge_count.push(e.validity.event_count);
            edge_weight.push(e.weight);
        }

        // Reverse CSR: (dense_dst, forward_slot) sorted by dst.
        let mut rev: Vec<(u32, u32, u32)> = kept
            .iter()
            .enumerate()
            .map(|(slot, (s, d, _))| (*d, *s, slot as u32))
            .collect();
        rev.sort_by_key(|(d, _, _)| *d);
        let mut rev_offsets = vec![0u32; n + 1];
        for (d, _, _) in &rev {
            rev_offsets[*d as usize + 1] += 1;
        }
        for i in 0..n {
            rev_offsets[i + 1] += rev_offsets[i];
        }
        let mut rev_src = Vec::with_capacity(m);
        let mut rev_edge_ref = Vec::with_capacity(m);
        for (_, s, slot) in &rev {
            rev_src.push(*s);
            rev_edge_ref.push(*slot);
        }

        CsrSnapshot {
            node_id,
            node_kind,
            node_first,
            node_last,
            node_risk,
            row_offsets,
            col_dst,
            edge_id,
            edge_type,
            edge_first,
            edge_last,
            edge_count,
            edge_weight,
            rev_offsets,
            rev_src,
            rev_edge_ref,
            dense_of_id,
        }
    }

    #[inline]
    pub(crate) fn dense(&self, id: NodeId) -> Option<u32> {
        self.dense_of_id.get(&id.raw()).copied()
    }

    #[inline]
    pub(crate) fn node_view(&self, dense: u32) -> NodeView {
        let i = dense as usize;
        NodeView {
            id: NodeId(self.node_id[i]),
            kind: self.node_kind[i],
            first_seen: Timestamp(self.node_first[i]),
            last_seen: Timestamp(self.node_last[i]),
            risk: self.node_risk[i],
        }
    }

    #[inline]
    pub(crate) fn edge_view(&self, slot: usize, src_dense: u32, dst_dense: u32) -> EdgeView {
        EdgeView {
            id: EdgeId(self.edge_id[slot]),
            src: NodeId(self.node_id[src_dense as usize]),
            dst: NodeId(self.node_id[dst_dense as usize]),
            etype: self.edge_type[slot],
            first_seen: Timestamp(self.edge_first[slot]),
            last_seen: Timestamp(self.edge_last[slot]),
            event_count: self.edge_count[slot],
            weight: self.edge_weight[slot],
        }
    }

    #[inline]
    pub(crate) fn slot_passes(&self, slot: usize, opts: &TraversalOpts) -> bool {
        if let Some((lo, hi)) = opts.time {
            // interval overlap ("rewind")
            if !(self.edge_first[slot] <= hi.millis() && self.edge_last[slot] >= lo.millis()) {
                return false;
            }
        }
        if let Some(mask) = opts.etypes {
            if !mask.contains(self.edge_type[slot]) {
                return false;
            }
        }
        true
    }

    /// Visit each qualifying neighbor of `u` (dense), calling `f(neighbor_dense, edge_slot, src_dense, dst_dense)`.
    fn for_each_neighbor(
        &self,
        u: u32,
        opts: &TraversalOpts,
        mut f: impl FnMut(u32, usize, u32, u32),
    ) {
        if matches!(opts.direction, Dir::Out | Dir::Both) {
            let (a, b) = (
                self.row_offsets[u as usize],
                self.row_offsets[u as usize + 1],
            );
            for slot in a..b {
                let slot = slot as usize;
                if self.slot_passes(slot, opts) {
                    let dst = self.col_dst[slot];
                    f(dst, slot, u, dst);
                }
            }
        }
        if matches!(opts.direction, Dir::In | Dir::Both) {
            let (a, b) = (
                self.rev_offsets[u as usize],
                self.rev_offsets[u as usize + 1],
            );
            for k in a..b {
                let k = k as usize;
                let slot = self.rev_edge_ref[k] as usize;
                if self.slot_passes(slot, opts) {
                    let src = self.rev_src[k];
                    f(src, slot, src, u);
                }
            }
        }
    }

    /// One-hop neighbors of `seed` as a [`Subgraph`] (the "expand node" action).
    pub fn neighbors(&self, seed: NodeId, opts: &TraversalOpts) -> Subgraph {
        let one = TraversalOpts {
            max_hops: 1,
            ..*opts
        };
        self.k_hop(seed, 1, &one)
    }

    /// Breadth-first expansion up to `max_hops` from `seed`, returning the induced
    /// [`Subgraph`] of visited nodes and traversed edges. This backs both the
    /// UI's progressive "pivot & expand" and time-scoped blast-radius queries.
    pub fn k_hop(&self, seed: NodeId, max_hops: u32, opts: &TraversalOpts) -> Subgraph {
        let mut sub = Subgraph::default();
        let Some(seed_dense) = self.dense(seed) else {
            return sub;
        };

        let n = self.node_count();
        let mut visited = vec![false; n];
        let mut seen_edge = vec![false; self.edge_count()];
        let mut frontier = vec![seed_dense];
        visited[seed_dense as usize] = true;
        sub.nodes.push(self.node_view(seed_dense));

        let mut hops = 0;
        while hops < max_hops && !frontier.is_empty() {
            let mut next = Vec::new();
            for &u in &frontier {
                self.for_each_neighbor(u, opts, |nbr, slot, s, d| {
                    if !seen_edge[slot] {
                        seen_edge[slot] = true;
                        sub.edges.push(self.edge_view(slot, s, d));
                    }
                    if !visited[nbr as usize] {
                        visited[nbr as usize] = true;
                        sub.nodes.push(self.node_view(nbr));
                        next.push(nbr);
                    }
                });
            }
            frontier = next;
            hops += 1;
        }
        sub
    }

    /// Shortest (fewest-hops) path from `src` to `dst` under `opts`, returned as
    /// the induced [`Subgraph`] of the path's nodes and edges, or `None` if
    /// unreachable within the time/type filter. Direction is honored (use
    /// [`Dir::Both`] for an undirected path).
    pub fn shortest_path(
        &self,
        src: NodeId,
        dst: NodeId,
        opts: &TraversalOpts,
    ) -> Option<Subgraph> {
        let s = self.dense(src)?;
        let d = self.dense(dst)?;
        if s == d {
            let mut sub = Subgraph::default();
            sub.nodes.push(self.node_view(s));
            return Some(sub);
        }
        let n = self.node_count();
        let mut visited = vec![false; n];
        // prev[node] = (parent_dense, edge_slot, edge_src_dense, edge_dst_dense)
        let mut prev: Vec<Option<(u32, usize, u32, u32)>> = vec![None; n];
        let mut queue = std::collections::VecDeque::new();
        visited[s as usize] = true;
        queue.push_back(s);

        let mut found = false;
        'bfs: while let Some(u) = queue.pop_front() {
            let mut hit = None;
            self.for_each_neighbor(u, opts, |nbr, slot, es, ed| {
                if !visited[nbr as usize] {
                    visited[nbr as usize] = true;
                    prev[nbr as usize] = Some((u, slot, es, ed));
                    if nbr == d {
                        hit = Some(());
                    }
                    queue.push_back(nbr);
                }
            });
            if hit.is_some() {
                found = true;
                break 'bfs;
            }
        }
        if !found {
            return None;
        }

        // Reconstruct the node/edge sequence from dst back to src.
        let mut node_path = vec![d];
        let mut edge_steps: Vec<(usize, u32, u32)> = Vec::new();
        let mut cur = d;
        while cur != s {
            let (parent, slot, es, ed) = prev[cur as usize].expect("path link");
            edge_steps.push((slot, es, ed));
            node_path.push(parent);
            cur = parent;
        }
        node_path.reverse();
        edge_steps.reverse();

        let mut sub = Subgraph::default();
        for nd in node_path {
            sub.nodes.push(self.node_view(nd));
        }
        for (slot, es, ed) in edge_steps {
            sub.edges.push(self.edge_view(slot, es, ed));
        }
        Some(sub)
    }

    /// The set of node ids reachable from `seed` under `opts` (time-scoped blast
    /// radius). Includes `seed`.
    pub fn reachable(&self, seed: NodeId, opts: &TraversalOpts) -> Vec<NodeId> {
        self.k_hop(seed, opts.max_hops.max(u32::MAX / 2), opts)
            .nodes
            .into_iter()
            .map(|v| v.id)
            .collect()
    }
}

/// Lock-free, atomically-swappable holder of the current [`CsrSnapshot`].
pub struct GraphIndex {
    snapshot: ArcSwap<CsrSnapshot>,
}

impl Default for GraphIndex {
    fn default() -> Self {
        GraphIndex {
            snapshot: ArcSwap::from_pointee(CsrSnapshot::empty()),
        }
    }
}

impl GraphIndex {
    pub fn new() -> Self {
        Self::default()
    }

    /// Atomically publish a fresh snapshot built from the given node/edge sets.
    pub fn rebuild(&self, nodes: &[Node], edges: &[Edge]) {
        self.snapshot
            .store(Arc::new(CsrSnapshot::build(nodes, edges)));
    }

    /// Borrow the current snapshot for a read (holds it stable for the query).
    pub fn load(&self) -> Arc<CsrSnapshot> {
        self.snapshot.load_full()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Build: alice --LOGGED_IN_TO--> dc01 --SPAWNED--> proc, with distinct times.
    fn fixture() -> (Vec<Node>, Vec<Edge>) {
        let alice = Node::new(NodeKind::User, "alice", "alice", Timestamp(100));
        let dc01 = Node::new(NodeKind::Host, "dc01", "DC01", Timestamp(100));
        let proc = Node::new(NodeKind::Process, "dc01:900:200", "cmd.exe", Timestamp(200));

        let mut e1 = Edge::new(alice.id, dc01.id, EdgeType::LoggedInTo, Timestamp(100));
        e1.validity.last_seen = Timestamp(150);
        let mut e2 = Edge::new(dc01.id, proc.id, EdgeType::Spawned, Timestamp(200));
        e2.validity.last_seen = Timestamp(250);

        (vec![alice, dc01, proc], vec![e1, e2])
    }

    #[test]
    fn builds_with_correct_counts() {
        let (nodes, edges) = fixture();
        let snap = CsrSnapshot::build(&nodes, &edges);
        assert_eq!(snap.node_count(), 3);
        assert_eq!(snap.edge_count(), 2);
    }

    #[test]
    fn dangling_edges_are_dropped() {
        let (nodes, _) = fixture();
        let ghost = Edge::new(NodeId(999), nodes[0].id, EdgeType::Spawned, Timestamp(1));
        let snap = CsrSnapshot::build(&nodes, &[ghost]);
        assert_eq!(snap.edge_count(), 0);
    }

    #[test]
    fn one_hop_neighbors_both_directions() {
        let (nodes, edges) = fixture();
        let snap = CsrSnapshot::build(&nodes, &edges);
        let dc01 = nodes[1].id;
        let sub = snap.neighbors(dc01, &TraversalOpts::default());
        // dc01 connects to alice (incoming) and proc (outgoing) => 3 nodes, 2 edges.
        assert_eq!(sub.nodes.len(), 3);
        assert_eq!(sub.edges.len(), 2);
    }

    #[test]
    fn direction_filter_restricts_neighbors() {
        let (nodes, edges) = fixture();
        let snap = CsrSnapshot::build(&nodes, &edges);
        let dc01 = nodes[1].id;
        let out = snap.neighbors(
            dc01,
            &TraversalOpts {
                direction: Dir::Out,
                ..Default::default()
            },
        );
        // Out only: dc01 -> proc.
        assert_eq!(out.edges.len(), 1);
        assert_eq!(out.edges[0].etype, EdgeType::Spawned);
    }

    #[test]
    fn edge_type_filter_applies() {
        let (nodes, edges) = fixture();
        let snap = CsrSnapshot::build(&nodes, &edges);
        let dc01 = nodes[1].id;
        let sub = snap.neighbors(
            dc01,
            &TraversalOpts {
                etypes: Some(EdgeTypeMask::of(&[EdgeType::LoggedInTo])),
                ..Default::default()
            },
        );
        assert_eq!(sub.edges.len(), 1);
        assert_eq!(sub.edges[0].etype, EdgeType::LoggedInTo);
    }

    #[test]
    fn time_window_rewind_filters_edges() {
        let (nodes, edges) = fixture();
        let snap = CsrSnapshot::build(&nodes, &edges);
        let dc01 = nodes[1].id;
        // Window [0,160] overlaps only the LOGGED_IN_TO edge ([100,150]), not SPAWNED ([200,250]).
        let sub = snap.neighbors(
            dc01,
            &TraversalOpts {
                time: Some((Timestamp(0), Timestamp(160))),
                ..Default::default()
            },
        );
        assert_eq!(sub.edges.len(), 1);
        assert_eq!(sub.edges[0].etype, EdgeType::LoggedInTo);
    }

    #[test]
    fn two_hop_reaches_process_from_alice() {
        let (nodes, edges) = fixture();
        let snap = CsrSnapshot::build(&nodes, &edges);
        let alice = nodes[0].id;
        let proc = nodes[2].id;
        let sub = snap.k_hop(alice, 2, &TraversalOpts::default());
        assert!(
            sub.nodes.iter().any(|v| v.id == proc),
            "2-hop reaches process"
        );
        let one = snap.k_hop(alice, 1, &TraversalOpts::default());
        assert!(!one.nodes.iter().any(|v| v.id == proc), "1-hop does not");
    }

    #[test]
    fn shortest_path_reconstructs_route() {
        let (nodes, edges) = fixture();
        let snap = CsrSnapshot::build(&nodes, &edges);
        let alice = nodes[0].id;
        let proc = nodes[2].id;
        let path = snap
            .shortest_path(alice, proc, &TraversalOpts::default())
            .expect("path exists");
        // alice -> dc01 -> proc: 3 nodes, 2 edges, endpoints correct.
        assert_eq!(path.nodes.len(), 3);
        assert_eq!(path.edges.len(), 2);
        assert_eq!(path.nodes.first().unwrap().id, alice);
        assert_eq!(path.nodes.last().unwrap().id, proc);

        // No path once the time filter excludes the second hop.
        let none = snap.shortest_path(
            alice,
            proc,
            &TraversalOpts {
                time: Some((Timestamp(0), Timestamp(160))),
                ..Default::default()
            },
        );
        assert!(none.is_none());
    }

    #[test]
    fn graph_index_rebuild_is_visible() {
        let idx = GraphIndex::new();
        assert_eq!(idx.load().node_count(), 0);
        let (nodes, edges) = fixture();
        idx.rebuild(&nodes, &edges);
        assert_eq!(idx.load().node_count(), 3);
        assert_eq!(idx.load().edge_count(), 2);
    }
}
