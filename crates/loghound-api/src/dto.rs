//! Response DTOs. The graph endpoints emit Cytoscape.js-shaped JSON
//! (`{ nodes: [{data}], edges: [{data}] }`) so the frontend can render directly
//! (`PLAN.md` §10, §11). Node/edge ids are strings — Cytoscape requires string
//! ids and JS cannot hold a `u64` losslessly.

use serde::Serialize;

use loghound_core::Node;
use loghound_graph::EdgeView;

#[derive(Debug, Serialize)]
pub struct CyGraph {
    pub nodes: Vec<CyNode>,
    pub edges: Vec<CyEdge>,
}

#[derive(Debug, Serialize)]
pub struct CyNode {
    pub data: CyNodeData,
}

#[derive(Debug, Serialize)]
pub struct CyNodeData {
    pub id: String,
    pub label: String,
    pub kind: &'static str,
    pub risk: f32,
    pub first_seen: i64,
    pub last_seen: i64,
    pub event_count: u64,
}

#[derive(Debug, Serialize)]
pub struct CyEdge {
    pub data: CyEdgeData,
}

#[derive(Debug, Serialize)]
pub struct CyEdgeData {
    pub id: String,
    pub source: String,
    pub target: String,
    pub etype: &'static str,
    pub first_seen: i64,
    pub last_seen: i64,
    pub event_count: u64,
    pub weight: f32,
}

impl CyNodeData {
    pub fn from_node(n: &Node) -> Self {
        CyNodeData {
            id: n.id.raw().to_string(),
            label: n.label.clone(),
            kind: n.kind.name(),
            risk: n.risk_score,
            first_seen: n.validity.first_seen.millis(),
            last_seen: n.validity.last_seen.millis(),
            event_count: n.validity.event_count,
        }
    }
}

impl CyEdgeData {
    pub fn from_view(e: &EdgeView) -> Self {
        CyEdgeData {
            id: e.id.raw().to_string(),
            source: e.src.raw().to_string(),
            target: e.dst.raw().to_string(),
            etype: e.etype.name(),
            first_seen: e.first_seen.millis(),
            last_seen: e.last_seen.millis(),
            event_count: e.event_count,
            weight: e.weight,
        }
    }
}

/// Build a Cytoscape graph from hydrated nodes and traversal edges.
pub fn cy_graph(nodes: &[Node], edges: &[EdgeView]) -> CyGraph {
    CyGraph {
        nodes: nodes
            .iter()
            .map(|n| CyNode {
                data: CyNodeData::from_node(n),
            })
            .collect(),
        edges: edges
            .iter()
            .map(|e| CyEdge {
                data: CyEdgeData::from_view(e),
            })
            .collect(),
    }
}
