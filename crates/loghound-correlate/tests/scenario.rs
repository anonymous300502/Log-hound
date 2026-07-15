//! End-to-end correlation test over a realistic multi-host attack scenario:
//! process tree on HOST-A → C2 network connection → lateral move to HOST-B →
//! payload dropped. Exercises the full parse → normalize → correlate pipeline
//! against the real OPLC wire format (`PLAN.md` §8, M3 exit criterion).

use std::path::PathBuf;

use loghound_core::edge::EdgeType;
use loghound_core::node::NodeKind;
use loghound_core::{Edge, Event, Node, NodeId};
use loghound_correlate::Correlator;
use loghound_normalize::{MappingConfig, Normalizer};
use loghound_parsers::{parse_reader, OplcParser};

const FIXTURE: &str = include_str!("fixtures/scenario.log");

fn pipeline() -> (Vec<Node>, Vec<Edge>) {
    let mappings = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../config/mappings.yaml");
    let normalizer = Normalizer::new(MappingConfig::from_path(mappings).expect("mappings"));
    let parser = OplcParser::new();

    let events: Vec<Event> = parse_reader(&parser, FIXTURE.as_bytes())
        .filter_map(|r| r.ok())
        .map(|rec| normalizer.normalize(&rec))
        .collect();
    assert_eq!(events.len(), 6, "all six scenario lines parse");

    let mut c = Correlator::new();
    c.correlate_batch(&events);
    c.finish()
}

fn node_by(nodes: &[Node], kind: NodeKind, label: &str) -> NodeId {
    nodes
        .iter()
        .find(|n| n.kind == kind && n.label == label)
        .unwrap_or_else(|| panic!("missing {kind:?} node labelled {label:?}"))
        .id
}

fn has_edge(edges: &[Edge], src: NodeId, dst: NodeId, etype: EdgeType) -> bool {
    edges
        .iter()
        .any(|e| e.src == src && e.dst == dst && e.etype == etype)
}

#[test]
fn reconstructs_full_attack_chain() {
    let (nodes, edges) = pipeline();

    let host_a = node_by(&nodes, NodeKind::Host, "HOST-A");
    let host_b = node_by(&nodes, NodeKind::Host, "HOST-B");
    let explorer = node_by(&nodes, NodeKind::Process, "explorer.exe");
    let powershell = node_by(&nodes, NodeKind::Process, "powershell.exe");
    let c2 = node_by(&nodes, NodeKind::IpAddress, "199.9.9.9");
    let payload = node_by(&nodes, NodeKind::File, "payload.dll");

    // Process tree on HOST-A.
    assert!(has_edge(&edges, explorer, powershell, EdgeType::Spawned));
    // C2: the PowerShell instance reached out to the external IP.
    assert!(has_edge(&edges, powershell, c2, EdgeType::ConnectedTo));
    // Lateral movement A -> B inferred from the network logon's source IP.
    assert!(has_edge(&edges, host_a, host_b, EdgeType::LateralMovement));
    // Payload dropped on HOST-B.
    assert!(has_edge(&edges, host_b, payload, EdgeType::Created));

    // The attacker identity deduped across the process logs and the 4624 event.
    let users: Vec<_> = nodes.iter().filter(|n| n.kind == NodeKind::User).collect();
    assert_eq!(users.len(), 1, "one attacker identity across sources");
    let attacker = users[0].id;
    assert!(has_edge(&edges, attacker, host_b, EdgeType::LoggedInTo));
    assert!(has_edge(&edges, attacker, powershell, EdgeType::RanAs));
}

#[test]
fn temporal_validity_populated_on_nodes_and_edges() {
    let (nodes, edges) = pipeline();
    // Every node/edge carries a real (non-zero) validity interval — the property
    // that powers "rewind" (PLAN.md §2).
    assert!(nodes.iter().all(|n| n.validity.first_seen.millis() > 0));
    assert!(edges.iter().all(|e| e.validity.event_count >= 1));
    // The lateral-movement edge is stamped at the 4624 event time (its XML
    // TimeCreated, which the fixture aligns with the envelope generated_ts).
    let host_a = node_by(&nodes, NodeKind::Host, "HOST-A");
    let host_b = node_by(&nodes, NodeKind::Host, "HOST-B");
    let lm = edges
        .iter()
        .find(|e| e.src == host_a && e.dst == host_b && e.etype == EdgeType::LateralMovement)
        .unwrap();
    assert_eq!(lm.validity.first_seen.millis(), 1_782_858_004_000);
}
