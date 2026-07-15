//! Graph analytics over the CSR snapshot (`PLAN.md` §6): centrality (degree,
//! PageRank), time-scoped connected components, a composite risk score, and
//! time-respecting weighted attack-path inference.
//!
//! Everything runs on the immutable [`CsrSnapshot`] arrays, so analytics are
//! lock-free reads over a stable graph and never block ingest.

use std::cmp::Ordering;
use std::collections::{BinaryHeap, VecDeque};

use loghound_core::node::NodeKind;
use loghound_core::NodeId;

use crate::index::{CsrSnapshot, EdgeView, NodeView, TraversalOpts};

/// A centrality/score result for one node.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Score {
    pub node_id: NodeId,
    pub score: f32,
}

/// In/out/total degree of a node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Degree {
    pub out_degree: usize,
    pub in_degree: usize,
}

impl Degree {
    pub fn total(&self) -> usize {
        self.out_degree + self.in_degree
    }
}

/// A ranked, time-respecting attack path.
#[derive(Debug, Clone, PartialEq)]
pub struct AttackPath {
    pub nodes: Vec<NodeView>,
    pub edges: Vec<EdgeView>,
    /// Total path cost (lower = a stronger / more suspicious route).
    pub cost: f32,
}

// Fixed-point key so f32 costs can drive a `BinaryHeap` (f32 isn't `Ord`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct HeapKey(i64);
impl Ord for HeapKey {
    fn cmp(&self, other: &Self) -> Ordering {
        // Reverse so `BinaryHeap` (max-heap) pops the smallest cost first.
        other.0.cmp(&self.0)
    }
}
impl PartialOrd for HeapKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
fn key(cost: f32) -> HeapKey {
    HeapKey((cost * 1_000.0) as i64)
}

impl CsrSnapshot {
    #[inline]
    fn out_range(&self, d: u32) -> std::ops::Range<usize> {
        self.row_offsets[d as usize] as usize..self.row_offsets[d as usize + 1] as usize
    }

    #[inline]
    fn in_range(&self, d: u32) -> std::ops::Range<usize> {
        self.rev_offsets[d as usize] as usize..self.rev_offsets[d as usize + 1] as usize
    }

    /// In/out degree of a node (uses raw CSR offsets — O(1)).
    pub fn degree(&self, id: NodeId) -> Option<Degree> {
        let d = self.dense(id)?;
        Some(Degree {
            out_degree: self.out_range(d).len(),
            in_degree: self.in_range(d).len(),
        })
    }

    /// PageRank over the directed graph (power iteration on CSR). Dangling nodes
    /// (no out-edges) redistribute their mass uniformly. Returns scores for every
    /// node, sorted descending (LogonTracer-style centrality risk).
    pub fn pagerank(&self, damping: f32, iters: usize) -> Vec<Score> {
        let n = self.node_count();
        if n == 0 {
            return Vec::new();
        }
        let nf = n as f32;
        let mut rank = vec![1.0f32 / nf; n];
        let out_deg: Vec<usize> = (0..n).map(|d| self.out_range(d as u32).len()).collect();

        for _ in 0..iters {
            let mut next = vec![(1.0 - damping) / nf; n];
            let mut dangling = 0.0f32;
            for u in 0..n {
                if out_deg[u] == 0 {
                    dangling += rank[u];
                    continue;
                }
                let share = damping * rank[u] / out_deg[u] as f32;
                for slot in self.out_range(u as u32) {
                    next[self.col_dst[slot] as usize] += share;
                }
            }
            // Redistribute dangling mass uniformly.
            let spread = damping * dangling / nf;
            for v in next.iter_mut() {
                *v += spread;
            }
            rank = next;
        }

        let mut scores: Vec<Score> = (0..n)
            .map(|d| Score {
                node_id: NodeId(self.node_id[d]),
                score: rank[d],
            })
            .collect();
        scores.sort_by(|a, b| b.score.total_cmp(&a.score));
        scores
    }

    /// Weakly-connected components under `opts` (edges treated as undirected).
    /// Time/type filters make this a time-scoped blast-radius partition. Groups
    /// are returned largest-first.
    pub fn connected_components(&self, opts: &TraversalOpts) -> Vec<Vec<NodeId>> {
        let n = self.node_count();
        let mut parent: Vec<u32> = (0..n as u32).collect();

        fn find(parent: &mut [u32], mut x: u32) -> u32 {
            while parent[x as usize] != x {
                parent[x as usize] = parent[parent[x as usize] as usize]; // path halving
                x = parent[x as usize];
            }
            x
        }

        for u in 0..n as u32 {
            for slot in self.out_range(u) {
                if !self.slot_passes(slot, opts) {
                    continue;
                }
                let v = self.col_dst[slot];
                let (ru, rv) = (find(&mut parent, u), find(&mut parent, v));
                if ru != rv {
                    parent[ru as usize] = rv;
                }
            }
        }

        let mut groups: std::collections::HashMap<u32, Vec<NodeId>> =
            std::collections::HashMap::new();
        for d in 0..n as u32 {
            let root = find(&mut parent, d);
            groups
                .entry(root)
                .or_default()
                .push(NodeId(self.node_id[d as usize]));
        }
        let mut out: Vec<Vec<NodeId>> = groups.into_values().collect();
        out.sort_by_key(|g| std::cmp::Reverse(g.len()));
        out
    }

    /// Undirected neighbors of a dense node (out + in), for BFS.
    fn undirected_neighbors(&self, d: u32, mut f: impl FnMut(u32)) {
        for slot in self.out_range(d) {
            f(self.col_dst[slot]);
        }
        for k in self.in_range(d) {
            f(self.rev_src[k]);
        }
    }

    /// Composite risk score in `[0, 100]` for every node (`PLAN.md` §6):
    /// PageRank centrality + proximity to alerts (BFS decay) + a per-kind weight.
    /// This is what sizes/colors nodes in the UI and steers attack-path search.
    pub fn compute_risk(&self) -> Vec<Score> {
        let n = self.node_count();
        if n == 0 {
            return Vec::new();
        }

        // 1) PageRank, normalized to [0,1].
        let pr = self.pagerank(0.85, 40);
        let mut pr_norm = vec![0.0f32; n];
        let pr_max = pr.iter().map(|s| s.score).fold(0.0f32, f32::max).max(1e-9);
        for s in &pr {
            if let Some(d) = self.dense(s.node_id) {
                pr_norm[d as usize] = s.score / pr_max;
            }
        }

        // 2) Alert proximity: multi-source BFS from Alert nodes, decay 0.5^depth.
        let alerts: Vec<u32> = (0..n as u32)
            .filter(|&d| self.node_kind[d as usize] == NodeKind::Alert)
            .collect();
        let mut ap = vec![0.0f32; n];
        if !alerts.is_empty() {
            const MAX_DEPTH: u32 = 3;
            let mut depth = vec![u32::MAX; n];
            let mut q = VecDeque::new();
            for &a in &alerts {
                depth[a as usize] = 0;
                q.push_back(a);
            }
            while let Some(u) = q.pop_front() {
                let du = depth[u as usize];
                if du >= MAX_DEPTH {
                    continue;
                }
                self.undirected_neighbors(u, |v| {
                    if depth[v as usize] == u32::MAX {
                        depth[v as usize] = du + 1;
                        q.push_back(v);
                    }
                });
            }
            for d in 0..n {
                if depth[d] != u32::MAX {
                    ap[d] = 0.5f32.powi(depth[d] as i32);
                }
            }
        }

        // 3) Per-kind base weight.
        let kind_weight = |k: NodeKind| -> f32 {
            match k {
                NodeKind::Alert => 1.0,
                NodeKind::Ioc => 0.9,
                NodeKind::Privilege | NodeKind::Certificate => 0.5,
                NodeKind::Process | NodeKind::User | NodeKind::Host => 0.25,
                _ => 0.1,
            }
        };

        (0..n)
            .map(|d| {
                let composite =
                    0.45 * pr_norm[d] + 0.40 * ap[d] + 0.15 * kind_weight(self.node_kind[d]);
                Score {
                    node_id: NodeId(self.node_id[d]),
                    score: (composite.clamp(0.0, 1.0) * 100.0),
                }
            })
            .collect()
    }

    /// Top-`k` time-respecting weighted attack paths from `src` to `dst`
    /// (`PLAN.md` §6, approach A). Edge cost is discounted by the destination's
    /// risk, so the search is pulled toward high-risk routes; a temporal
    /// monotonicity constraint forbids a step earlier than the one before it
    /// (you cannot act on a host before reaching it). Successive paths penalize
    /// already-used edges to surface *diverse* routes (a greedy stand-in for
    /// Yen's k-shortest).
    pub fn attack_paths(
        &self,
        src: NodeId,
        dst: NodeId,
        k: usize,
        opts: &TraversalOpts,
    ) -> Vec<AttackPath> {
        let (Some(s), Some(d)) = (self.dense(src), self.dense(dst)) else {
            return Vec::new();
        };
        let mut penalties = vec![0.0f32; self.edge_count()];
        let mut seen: Vec<Vec<usize>> = Vec::new();
        let mut out = Vec::new();
        for _ in 0..k.max(1) {
            match self.best_temporal_path(s, d, &penalties, opts) {
                Some((slots, cost)) => {
                    // Stop once the search can only re-offer an already-returned
                    // route (no genuinely distinct path remains).
                    if seen.contains(&slots) {
                        break;
                    }
                    for &slot in &slots {
                        penalties[slot] += 2.0; // discourage reuse next round
                    }
                    seen.push(slots.clone());
                    out.push(self.materialize_path(s, &slots, cost));
                }
                None => break,
            }
        }
        out
    }

    /// Dijkstra by cost with a temporal-feasibility guard. Returns the ordered
    /// edge slots of the best path and its total cost.
    fn best_temporal_path(
        &self,
        s: u32,
        d: u32,
        penalties: &[f32],
        opts: &TraversalOpts,
    ) -> Option<(Vec<usize>, f32)> {
        let n = self.node_count();
        let mut dist = vec![f32::INFINITY; n];
        let mut arrival = vec![i64::MIN; n]; // time we reached this node
        let mut prev: Vec<Option<(u32, usize)>> = vec![None; n]; // (from_dense, edge_slot)
        let mut heap = BinaryHeap::new();

        dist[s as usize] = 0.0;
        heap.push((key(0.0), s));

        while let Some((HeapKey(negcost), u)) = heap.pop() {
            let cur = -(negcost as f32) / 1_000.0;
            if cur > dist[u as usize] + 1e-6 {
                continue; // stale
            }
            if u == d {
                break;
            }
            let arr_u = arrival[u as usize];
            for slot in self.out_range(u) {
                if !self.slot_passes(slot, opts) {
                    continue;
                }
                // Temporal monotonicity: the step cannot precede our arrival.
                if arr_u != i64::MIN && self.edge_first[slot] < arr_u {
                    continue;
                }
                let v = self.col_dst[slot];
                let step = self.edge_cost(slot, v, penalties);
                let nd = dist[u as usize] + step;
                if nd + 1e-9 < dist[v as usize] {
                    dist[v as usize] = nd;
                    arrival[v as usize] = self.edge_first[slot].max(arr_u);
                    prev[v as usize] = Some((u, slot));
                    heap.push((key(nd), v));
                }
            }
        }

        if dist[d as usize].is_infinite() {
            return None;
        }
        // Reconstruct slot path from d back to s.
        let mut slots = Vec::new();
        let mut cur = d;
        while cur != s {
            let (from, slot) = prev[cur as usize]?;
            slots.push(slot);
            cur = from;
        }
        slots.reverse();
        Some((slots, dist[d as usize]))
    }

    /// Per-edge cost: a small base, discounted by the destination node's risk so
    /// the path is drawn through high-risk entities, plus any diversity penalty.
    #[inline]
    fn edge_cost(&self, slot: usize, dst_dense: u32, penalties: &[f32]) -> f32 {
        let risk_norm = self.node_risk[dst_dense as usize] / 100.0;
        (1.0 - 0.6 * risk_norm + penalties[slot]).max(0.05)
    }

    fn materialize_path(&self, s: u32, slots: &[usize], cost: f32) -> AttackPath {
        let mut nodes = vec![self.node_view(s)];
        let mut edges = Vec::with_capacity(slots.len());
        let mut cur = s;
        for &slot in slots {
            let dst = self.col_dst[slot];
            edges.push(self.edge_view(slot, cur, dst));
            nodes.push(self.node_view(dst));
            cur = dst;
        }
        AttackPath { nodes, edges, cost }
    }
}

/// Convenience: keep only the top `limit` scores (already sorted descending).
pub fn top(mut scores: Vec<Score>, limit: usize) -> Vec<Score> {
    scores.truncate(limit);
    scores
}

/// An all-time, all-types traversal option set for whole-graph analytics.
pub fn all_time() -> TraversalOpts {
    TraversalOpts {
        time: None,
        etypes: None,
        max_hops: u32::MAX / 2,
        direction: crate::index::Dir::Both,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use loghound_core::edge::EdgeType;
    use loghound_core::{Edge, Node, Timestamp};

    // user alice -LOGGED_IN_TO-> host DC01 -SPAWNED-> proc -CONNECTED_TO-> ip,
    // and an Alert triggered by the host.
    fn fixture() -> (Vec<Node>, Vec<Edge>) {
        let alice = Node::new(NodeKind::User, "alice", "alice", Timestamp(100));
        let dc01 = Node::new(NodeKind::Host, "dc01", "DC01", Timestamp(100));
        let proc = Node::new(NodeKind::Process, "dc01:9:2", "cmd.exe", Timestamp(200));
        let ip = Node::new(NodeKind::IpAddress, "1.2.3.4", "1.2.3.4", Timestamp(300));
        let alert = Node::new(
            NodeKind::Alert,
            "AB:dc01:400",
            "Lateral Movement",
            Timestamp(400),
        );

        let e1 = Edge::new(alice.id, dc01.id, EdgeType::LoggedInTo, Timestamp(100));
        let e2 = Edge::new(dc01.id, proc.id, EdgeType::Spawned, Timestamp(200));
        let e3 = Edge::new(proc.id, ip.id, EdgeType::ConnectedTo, Timestamp(300));
        let e4 = Edge::new(dc01.id, alert.id, EdgeType::Triggered, Timestamp(400));

        (vec![alice, dc01, proc, ip, alert], vec![e1, e2, e3, e4])
    }

    #[test]
    fn degree_counts() {
        let (nodes, edges) = fixture();
        let snap = CsrSnapshot::build(&nodes, &edges);
        let dc = snap.degree(nodes[1].id).unwrap();
        assert_eq!(dc.in_degree, 1); // alice -> dc01
        assert_eq!(dc.out_degree, 2); // dc01 -> proc, dc01 -> alert
    }

    #[test]
    fn pagerank_ranks_all_nodes() {
        let (nodes, edges) = fixture();
        let snap = CsrSnapshot::build(&nodes, &edges);
        let pr = snap.pagerank(0.85, 30);
        assert_eq!(pr.len(), nodes.len());
        // Scores are a probability distribution — sum ≈ 1.
        let sum: f32 = pr.iter().map(|s| s.score).sum();
        assert!((sum - 1.0).abs() < 0.05, "pagerank sums to ~1, got {sum}");
    }

    #[test]
    fn components_group_the_connected_graph() {
        let (nodes, edges) = fixture();
        let snap = CsrSnapshot::build(&nodes, &edges);
        let comps = snap.connected_components(&all_time());
        assert_eq!(comps.len(), 1);
        assert_eq!(comps[0].len(), nodes.len());
    }

    #[test]
    fn risk_is_bounded_and_alert_neighbors_score() {
        let (nodes, edges) = fixture();
        let snap = CsrSnapshot::build(&nodes, &edges);
        let risk = snap.compute_risk();
        for s in &risk {
            assert!((0.0..=100.0).contains(&s.score));
        }
        // The alert node and its neighbor host should outrank the leaf IP.
        let by = |id| risk.iter().find(|s| s.node_id == id).unwrap().score;
        assert!(by(nodes[4].id) > by(nodes[3].id), "alert > leaf ip");
        assert!(by(nodes[1].id) > 0.0, "host near alert has risk");
    }

    #[test]
    fn attack_path_is_time_respecting() {
        let (nodes, edges) = fixture();
        let snap = CsrSnapshot::build(&nodes, &edges);
        // alice -> ip via dc01 -> proc, monotonic in time (100 <= 200 <= 300).
        let paths = snap.attack_paths(nodes[0].id, nodes[3].id, 1, &all_time());
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].nodes.first().unwrap().id, nodes[0].id);
        assert_eq!(paths[0].nodes.last().unwrap().id, nodes[3].id);
        assert_eq!(paths[0].edges.len(), 3);
    }

    #[test]
    fn attack_path_blocks_non_monotonic_time() {
        // Reverse the times so the second hop precedes the first — no valid path.
        let alice = Node::new(NodeKind::User, "alice", "alice", Timestamp(500));
        let host = Node::new(NodeKind::Host, "h", "H", Timestamp(500));
        let proc = Node::new(NodeKind::Process, "h:1:1", "p", Timestamp(100));
        let e1 = Edge::new(alice.id, host.id, EdgeType::LoggedInTo, Timestamp(500));
        let e2 = Edge::new(host.id, proc.id, EdgeType::Spawned, Timestamp(100));
        let snap = CsrSnapshot::build(&[alice.clone(), host, proc.clone()], &[e1, e2]);
        let paths = snap.attack_paths(alice.id, proc.id, 1, &all_time());
        assert!(paths.is_empty(), "second hop precedes first → no path");
    }
}
