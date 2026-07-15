//! Wiring alerts into the temporal graph (`PLAN.md` §3, §9): each [`Alert`]
//! becomes an [`NodeKind::Alert`] node, and the entities in its contributing
//! events (`Host`, `User`, `IpAddress`) get a `TRIGGERED` edge into it. This is
//! what lets an investigator pivot from an alert to the hosts/users/addresses
//! involved and on into the rest of the graph.
//!
//! Entity identity keys are the *same* ones the correlator uses
//! (`loghound_correlate::identity`), so these edges attach to the already-built
//! entity nodes rather than creating duplicates.

use std::collections::HashMap;

use loghound_core::edge::EdgeType;
use loghound_core::node::NodeKind;
use loghound_core::{Edge, Event, Node, NodeId, Timestamp};
use loghound_correlate::{identity, GraphBuilder};

use crate::engine::Alert;

/// Build the Alert nodes + `TRIGGERED` edges for a batch of alerts.
///
/// `events` maps `event_id → &Event` so each alert's provenance events can be
/// resolved to their entities. Nodes/edges fold by content-addressed id, so
/// re-emitting an entity that correlation already created just widens its
/// validity interval.
pub fn build_alert_graph(
    alerts: &[Alert],
    events: &HashMap<u64, &Event>,
) -> (Vec<Node>, Vec<Edge>) {
    let mut b = GraphBuilder::new();
    for a in alerts {
        let ats = Timestamp(a.ts);
        let alert_id = b.node(NodeKind::Alert, &a.alert_id, &a.rule_name, ats);
        b.set_node_prop(alert_id, "rule_id", &a.rule_id);
        b.set_node_prop(alert_id, "severity", &a.severity);
        b.set_node_prop(alert_id, "rule_type", a.rule_type_name());
        if let Some(m) = &a.mitre {
            b.set_node_prop(alert_id, "mitre", m);
        }
        if let Some(id) = &a.mitre_id {
            b.set_node_prop(alert_id, "mitre_id", id);
        }
        b.set_node_prop(alert_id, "risk", &(a.risk() as i64).to_string());

        // Link each distinct involved entity → alert exactly once.
        let mut linked: Vec<NodeId> = Vec::new();
        let mut link = |b: &mut GraphBuilder, kind: NodeKind, key: &str, label: &str| {
            if key.is_empty() {
                return;
            }
            let id = b.node(kind, key, label, ats);
            if !linked.contains(&id) {
                linked.push(id);
                b.edge(id, alert_id, EdgeType::Triggered, ats);
            }
        };

        for eid in &a.event_ids {
            let Some(ev) = events.get(eid) else { continue };
            if let Some(h) = &ev.host {
                link(&mut b, NodeKind::Host, &identity::host_key(h), h);
            }
            if let Some(u) = &ev.user_name {
                // Match the correlator's user identity (domain/SID aware) so the
                // TRIGGERED edge attaches to the existing user node rather than a
                // duplicate (identity.rs / correlator user_node).
                let key = identity::user_key(
                    u,
                    ev.get("user.domain").as_deref(),
                    ev.get("user.uid").as_deref(),
                );
                link(&mut b, NodeKind::User, &key, u);
            }
            if let Some(ip) = &ev.src_ip {
                link(&mut b, NodeKind::IpAddress, ip, ip);
            }
            if let Some(ip) = &ev.dst_ip {
                link(&mut b, NodeKind::IpAddress, ip, ip);
            }
        }
    }
    b.into_parts()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::RuleType;
    use loghound_core::event::class;
    use loghound_core::EventId;

    fn alert() -> Alert {
        Alert {
            alert_id: "BF:10.0.0.9:3000".into(),
            rule_id: "BF".into(),
            rule_name: "Brute Force".into(),
            severity: "high".into(),
            mitre: Some("T1110 - Brute Force".into()),
            mitre_id: Some("T1110".into()),
            description: "brute force".into(),
            rule_type: RuleType::Threshold,
            ts: 3000,
            group_key: Some("10.0.0.9".into()),
            event_ids: vec![1, 2],
        }
    }

    #[test]
    fn alert_links_host_user_ip() {
        let mut e1 = Event::new(class::AUTHENTICATION, Timestamp(1000));
        e1.event_id = EventId::new(1);
        e1.host = Some("DC01".into());
        e1.user_name = Some("alice".into());
        e1.src_ip = Some("10.0.0.9".into());
        let e2 = {
            let mut e = Event::new(class::AUTHENTICATION, Timestamp(2000));
            e.event_id = EventId::new(2);
            e.host = Some("DC01".into()); // same host → folds, no duplicate edge
            e.src_ip = Some("10.0.0.9".into());
            e
        };
        let map: HashMap<u64, &Event> = [(1u64, &e1), (2u64, &e2)].into_iter().collect();

        let (nodes, edges) = build_alert_graph(&[alert()], &map);
        // 1 alert + host + user + ip = 4 nodes.
        assert_eq!(
            nodes.iter().filter(|n| n.kind == NodeKind::Alert).count(),
            1
        );
        assert!(nodes.iter().any(|n| n.kind == NodeKind::Host));
        assert!(nodes.iter().any(|n| n.kind == NodeKind::User));
        assert!(nodes.iter().any(|n| n.kind == NodeKind::IpAddress));
        // 3 TRIGGERED edges (host, user, ip), each folded to one despite 2 events.
        assert_eq!(edges.len(), 3);
        assert!(edges.iter().all(|e| e.etype == EdgeType::Triggered));
    }
}
