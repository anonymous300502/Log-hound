//! [`Correlator`] — joins normalized events across log types into the temporal
//! graph (`PLAN.md` §8).
//!
//! Correlation is two-pass over a batch: pass 1 ([`Correlator::register`])
//! learns each host's own IP so pass 2 ([`Correlator::correlate`]) can attribute
//! remote logons to a source host (cross-host lateral movement) regardless of
//! event ordering. Process instances are keyed `host:pid:start`, so a reused PID
//! yields a fresh node; a `live[(host,pid)]` map tracks the current instance for
//! attributing later network/child events, and is overwritten on relaunch.

use std::collections::HashMap;

use loghound_core::edge::EdgeType;
use loghound_core::event::class;
use loghound_core::node::NodeKind;
use loghound_core::{Edge, Event, Node, NodeId, Timestamp};

use crate::builder::GraphBuilder;
use crate::identity::{
    basename, executable_key, file_key, host_key, process_key, session_key, user_key,
};

/// Stateful cross-log correlation engine.
#[derive(Default)]
pub struct Correlator {
    builder: GraphBuilder,
    /// (host_key, pid) → currently-live process node (PID-reuse aware).
    live: HashMap<(String, i64), NodeId>,
    /// endpoint IP → host_key (from each event's own `env.source_ip`).
    host_addr: HashMap<String, String>,
}

impl Correlator {
    pub fn new() -> Self {
        Correlator::default()
    }

    /// Correlate a whole batch: learn topology, then build the graph.
    pub fn correlate_batch(&mut self, events: &[Event]) {
        for e in events {
            self.register(e);
        }
        for e in events {
            self.correlate(e);
        }
    }

    /// Pass 1: record the endpoint's own IP → host mapping (used for lateral
    /// movement in pass 2).
    pub fn register(&mut self, ev: &Event) {
        if let (Some(host), Some(ip)) = (ev.host.as_deref(), ev.extra.get("env.source_ip")) {
            if !ip.is_empty() {
                self.host_addr.insert(ip.clone(), host_key(host));
            }
        }
    }

    /// Pass 2: emit nodes/edges for one event.
    pub fn correlate(&mut self, ev: &Event) {
        match ev.class_uid {
            class::PROCESS_ACTIVITY => self.process(ev),
            class::NETWORK_ACTIVITY => self.network(ev),
            class::AUTHENTICATION => self.auth(ev),
            class::FILE_ACTIVITY => self.file(ev),
            class::ACCOUNT_CHANGE => self.account(ev),
            _ => self.generic(ev),
        }
    }

    /// Drain the accumulated graph.
    pub fn finish(self) -> (Vec<Node>, Vec<Edge>) {
        self.builder.into_parts()
    }

    // ---- helpers ----

    fn host_node(&mut self, ev: &Event) -> Option<(NodeId, String)> {
        let host = ev.host.as_deref()?;
        let hk = host_key(host);
        let id = self.builder.node(NodeKind::Host, &hk, host, ev.ts);
        Some((id, hk))
    }

    fn user_node(&mut self, ev: &Event, actor: bool, ts: Timestamp) -> Option<NodeId> {
        let (name, domain, sid) = if actor {
            (
                ev.actor_user.as_deref()?,
                ev.get("actor.user.domain"),
                ev.get("actor.user.uid"),
            )
        } else {
            (
                ev.user_name.as_deref()?,
                ev.get("user.domain"),
                ev.get("user.uid"),
            )
        };
        let key = user_key(name, domain.as_deref(), sid.as_deref());
        Some(self.builder.node(NodeKind::User, &key, name, ts))
    }

    /// Create the executable + `EXECUTED` edge for a process instance.
    fn link_executable(&mut self, proc_id: NodeId, path_or_name: &str, ts: Timestamp) {
        let exe = self.builder.node(
            NodeKind::Executable,
            &executable_key(path_or_name),
            basename(path_or_name),
            ts,
        );
        self.builder.edge(exe, proc_id, EdgeType::Executed, ts);
    }

    // ---- per-class handlers ----

    fn process(&mut self, ev: &Event) {
        let ts = ev.ts;
        let Some((host_id, hk)) = self.host_node(ev) else {
            return;
        };
        let Some(pid) = ev.process_pid else { return };
        let name = ev.process_name.as_deref().unwrap_or("process");

        let pkey = process_key(&hk, pid, ts.millis());
        let proc_id = self.builder.node(NodeKind::Process, &pkey, name, ts);
        self.live.insert((hk.clone(), pid), proc_id);

        // Host started this process instance.
        self.builder.edge(host_id, proc_id, EdgeType::Started, ts);

        // Executable (prefer full image path).
        match ev.get("process.file.path") {
            Some(path) if !path.is_empty() => self.link_executable(proc_id, &path, ts),
            _ => self.link_executable(proc_id, name, ts),
        }

        // Command line.
        if let Some(cmd) = ev.get("process.cmd_line") {
            if !cmd.is_empty() {
                let label: String = cmd.chars().take(120).collect();
                let c = self.builder.node(NodeKind::CommandLine, &cmd, &label, ts);
                self.builder.edge(proc_id, c, EdgeType::Used, ts);
            }
        }

        // Owning user.
        if let Some(u) = self.user_node(ev, false, ts) {
            self.builder.edge(u, proc_id, EdgeType::RanAs, ts);
        }

        // Parent → child (PID-reuse aware; synthesize a placeholder if unseen).
        if let Some(ppid) = ev.parent_pid {
            let parent_id = match self.live.get(&(hk.clone(), ppid)) {
                Some(p) => *p,
                None => {
                    let pname = ev
                        .get("parent_process.name")
                        .unwrap_or_else(|| "unknown".into());
                    let key = format!("{hk}:{ppid}:?"); // synthetic (unknown start)
                    self.builder.node(NodeKind::Process, &key, &pname, ts)
                }
            };
            self.builder.edge(parent_id, proc_id, EdgeType::Spawned, ts);
        }

        // Logon session ownership.
        if let Some(sid) = ev.get("session.uid") {
            if !sid.is_empty() && sid != "0x0" {
                let s = self.builder.node(
                    NodeKind::LogonSession,
                    &session_key(&hk, &sid),
                    &format!("session {sid}"),
                    ts,
                );
                self.builder.edge(s, proc_id, EdgeType::Owns, ts);
                self.builder.edge(s, host_id, EdgeType::BelongsTo, ts);
            }
        }
    }

    fn network(&mut self, ev: &Event) {
        let ts = ev.ts;
        let Some((host_id, hk)) = self.host_node(ev) else {
            return;
        };
        let Some(dst) = ev.dst_ip.as_deref() else {
            return;
        };
        let dst_id = self.builder.node(NodeKind::IpAddress, dst, dst, ts);

        // Attribute the connection to the owning process if we know it; else to a
        // network-derived process node, else to the host.
        let src: NodeId = match ev.process_pid {
            Some(pid) => match self.live.get(&(hk.clone(), pid)) {
                Some(p) => *p,
                None => {
                    let name = ev.process_name.as_deref().unwrap_or("process");
                    let key = format!("{hk}:{pid}:net"); // loose instance (no NEW_PROCESS seen)
                    let p = self.builder.node(NodeKind::Process, &key, name, ts);
                    self.builder.edge(host_id, p, EdgeType::Started, ts);
                    self.live.insert((hk.clone(), pid), p);
                    p
                }
            },
            None => host_id,
        };
        self.builder.edge(src, dst_id, EdgeType::ConnectedTo, ts);
    }

    fn auth(&mut self, ev: &Event) {
        let ts = ev.ts;
        let Some((host_id, hk)) = self.host_node(ev) else {
            return;
        };
        let Some(user_id) = self.user_node(ev, false, ts) else {
            return;
        };

        // Success vs attempt keyed on the Windows event code.
        let success = matches!(ev.event_code, Some(4624 | 4768 | 4769 | 4776));
        let etype = if success {
            EdgeType::LoggedInTo
        } else {
            EdgeType::Authenticated
        };
        self.builder.edge(user_id, host_id, etype, ts);

        // Cross-host lateral movement: does the logon source IP belong to a host
        // we've seen generating telemetry?
        if let Some(src_ip) = ev.src_ip.as_deref() {
            if let Some(src_hk) = self.host_addr.get(src_ip).cloned() {
                if src_hk != hk {
                    let src_host = self.builder.node(NodeKind::Host, &src_hk, &src_hk, ts);
                    self.builder
                        .edge(src_host, host_id, EdgeType::LateralMovement, ts);
                }
            }
        }
    }

    fn file(&mut self, ev: &Event) {
        let ts = ev.ts;
        let Some((host_id, hk)) = self.host_node(ev) else {
            return;
        };
        let Some(path) = ev.get("file.path") else {
            return;
        };
        if path.is_empty() {
            return;
        }
        let file_id = self
            .builder
            .node(NodeKind::File, &file_key(&hk, &path), basename(&path), ts);
        let action = ev.get("activity_name").unwrap_or_default();
        let etype = match action.to_ascii_uppercase().as_str() {
            "CREATED" | "CREATE" => EdgeType::Created,
            "DELETED" | "DELETE" | "REMOVED" => EdgeType::Deleted,
            _ => EdgeType::Modified,
        };
        // No PID in file-integrity logs, so attribute to the host (PLAN.md §8 note).
        self.builder.edge(host_id, file_id, etype, ts);
        if let Some(hash) = ev.get("file.hash_md5") {
            self.builder.set_node_prop(file_id, "hash_md5", &hash);
        }
    }

    fn account(&mut self, ev: &Event) {
        let ts = ev.ts;
        let actor = self.user_node(ev, true, ts);
        let target = self.user_node(ev, false, ts);
        if let (Some(a), Some(t)) = (actor, target) {
            if a != t {
                self.builder.edge(a, t, EdgeType::Modified, ts);
            }
        }
    }

    /// Events without a specific class (e.g. 4673 privilege use) still yield a
    /// useful subgraph from their generic fields.
    fn generic(&mut self, ev: &Event) {
        let ts = ev.ts;
        let host = self.host_node(ev);
        let user = self
            .user_node(ev, true, ts)
            .or_else(|| self.user_node(ev, false, ts));

        // Process, if the event carries one.
        let proc = match (
            ev.host.as_deref(),
            ev.process_pid,
            ev.process_name.as_deref(),
        ) {
            (Some(h), Some(pid), name) => {
                let hk = host_key(h);
                let pkey = process_key(&hk, pid, ts.millis());
                let id = self
                    .builder
                    .node(NodeKind::Process, &pkey, name.unwrap_or("process"), ts);
                if let Some((host_id, _)) = host {
                    self.builder.edge(host_id, id, EdgeType::Started, ts);
                }
                if let Some(name) = name {
                    self.link_executable(id, name, ts);
                }
                if let Some(u) = user {
                    self.builder.edge(u, id, EdgeType::RanAs, ts);
                }
                Some(id)
            }
            _ => None,
        };

        // Privilege use → AcquiredPrivilege (from the actor, else the process).
        if let Some(privs) = ev
            .get("PrivilegeList")
            .or_else(|| ev.extra.get("PrivilegeList").cloned())
        {
            for p in privs.split(['\n', '\t', ' ']).filter(|s| !s.is_empty()) {
                let priv_id = self.builder.node(NodeKind::Privilege, p, p, ts);
                if let Some(u) = user {
                    self.builder
                        .edge(u, priv_id, EdgeType::AcquiredPrivilege, ts);
                } else if let Some(pr) = proc {
                    self.builder
                        .edge(pr, priv_id, EdgeType::AcquiredPrivilege, ts);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use loghound_core::edge::EdgeType;
    use loghound_core::NodeId;

    // ---- event builders ----

    fn proc_ev(host: &str, pid: i64, name: &str, ppid: Option<i64>, ts: i64) -> Event {
        let mut e = Event::new(class::PROCESS_ACTIVITY, Timestamp(ts));
        e.host = Some(host.into());
        e.process_pid = Some(pid);
        e.process_name = Some(name.into());
        e.parent_pid = ppid;
        e.activity_id = Some(1);
        e
    }

    fn net_ev(host: &str, own_ip: &str, pid: i64, dst: &str, ts: i64) -> Event {
        let mut e = Event::new(class::NETWORK_ACTIVITY, Timestamp(ts));
        e.host = Some(host.into());
        e.process_pid = Some(pid);
        e.dst_ip = Some(dst.into());
        e.extra.insert("env.source_ip".into(), own_ip.into());
        e
    }

    fn auth_ev(host: &str, user: &str, code: i32, src_ip: &str, ts: i64) -> Event {
        let mut e = Event::new(class::AUTHENTICATION, Timestamp(ts));
        e.host = Some(host.into());
        e.user_name = Some(user.into());
        e.event_code = Some(code);
        e.src_ip = Some(src_ip.into());
        e
    }

    // ---- assertion helpers ----

    fn node_id(nodes: &[Node], kind: NodeKind, label: &str) -> Option<NodeId> {
        nodes
            .iter()
            .find(|n| n.kind == kind && n.label == label)
            .map(|n| n.id)
    }

    fn has_edge(edges: &[Edge], src: NodeId, dst: NodeId, etype: EdgeType) -> bool {
        edges
            .iter()
            .any(|e| e.src == src && e.dst == dst && e.etype == etype)
    }

    #[test]
    fn reconstructs_process_tree() {
        let mut c = Correlator::new();
        c.correlate_batch(&[
            proc_ev("H", 100, "explorer.exe", None, 10),
            proc_ev("H", 200, "cmd.exe", Some(100), 20),
            proc_ev("H", 300, "powershell.exe", Some(200), 30),
        ]);
        let (nodes, edges) = c.finish();
        let explorer = node_id(&nodes, NodeKind::Process, "explorer.exe").unwrap();
        let cmd = node_id(&nodes, NodeKind::Process, "cmd.exe").unwrap();
        let ps = node_id(&nodes, NodeKind::Process, "powershell.exe").unwrap();
        assert!(has_edge(&edges, explorer, cmd, EdgeType::Spawned));
        assert!(has_edge(&edges, cmd, ps, EdgeType::Spawned));
    }

    #[test]
    fn pid_reuse_yields_distinct_process_nodes() {
        let mut c = Correlator::new();
        c.correlate_batch(&[
            proc_ev("H", 200, "cmd.exe", None, 10),
            proc_ev("H", 200, "evil.exe", None, 1000), // same pid, later => new instance
            proc_ev("H", 400, "child.exe", Some(200), 1001), // links to the live (evil) one
        ]);
        let (nodes, edges) = c.finish();
        // Two distinct process nodes share pid 200.
        let cmd = node_id(&nodes, NodeKind::Process, "cmd.exe").unwrap();
        let evil = node_id(&nodes, NodeKind::Process, "evil.exe").unwrap();
        let child = node_id(&nodes, NodeKind::Process, "child.exe").unwrap();
        assert_ne!(cmd, evil);
        assert!(has_edge(&edges, evil, child, EdgeType::Spawned));
        assert!(!has_edge(&edges, cmd, child, EdgeType::Spawned)); // NOT the retired one
    }

    #[test]
    fn missing_parent_gets_synthetic_placeholder() {
        let mut c = Correlator::new();
        c.correlate_batch(&[proc_ev("H", 500, "orphan.exe", Some(999), 10)]);
        let (nodes, edges) = c.finish();
        let orphan = node_id(&nodes, NodeKind::Process, "orphan.exe").unwrap();
        // A placeholder parent node exists and spawned the orphan.
        let placeholder = nodes
            .iter()
            .find(|n| n.kind == NodeKind::Process && n.identity_key.ends_with(":999:?"))
            .expect("synthetic parent");
        assert!(has_edge(&edges, placeholder.id, orphan, EdgeType::Spawned));
    }

    #[test]
    fn attributes_network_to_owning_process() {
        let mut c = Correlator::new();
        c.correlate_batch(&[
            proc_ev("H", 300, "powershell.exe", None, 10),
            net_ev("H", "10.0.0.1", 300, "8.8.8.8", 20),
        ]);
        let (nodes, edges) = c.finish();
        let ps = node_id(&nodes, NodeKind::Process, "powershell.exe").unwrap();
        let ip = node_id(&nodes, NodeKind::IpAddress, "8.8.8.8").unwrap();
        assert!(has_edge(&edges, ps, ip, EdgeType::ConnectedTo));
    }

    #[test]
    fn network_without_new_process_still_attributes_to_a_process() {
        // The real sample has a NETWORK for svchost pid 3232 with no NEW_PROCESS.
        let mut c = Correlator::new();
        c.correlate_batch(&[net_ev("H", "10.0.0.1", 3232, "1.2.3.4", 5)]);
        let (nodes, edges) = c.finish();
        let svc = nodes
            .iter()
            .find(|n| n.kind == NodeKind::Process)
            .unwrap()
            .id;
        let ip = node_id(&nodes, NodeKind::IpAddress, "1.2.3.4").unwrap();
        assert!(has_edge(&edges, svc, ip, EdgeType::ConnectedTo));
    }

    #[test]
    fn auth_success_and_failure_edges() {
        let mut c = Correlator::new();
        c.correlate_batch(&[
            auth_ev("DC", "alice", 4624, "10.0.0.9", 10),
            auth_ev("DC", "bob", 4625, "10.0.0.9", 20),
        ]);
        let (nodes, edges) = c.finish();
        let dc = node_id(&nodes, NodeKind::Host, "DC").unwrap();
        let alice = node_id(&nodes, NodeKind::User, "alice").unwrap();
        let bob = node_id(&nodes, NodeKind::User, "bob").unwrap();
        assert!(has_edge(&edges, alice, dc, EdgeType::LoggedInTo));
        assert!(has_edge(&edges, bob, dc, EdgeType::Authenticated));
    }

    #[test]
    fn cross_host_lateral_movement() {
        // HOST-A (10.0.0.1) is active; then a network logon lands on HOST-B
        // sourced from 10.0.0.1 => LATERAL_MOVEMENT A -> B.
        let mut c = Correlator::new();
        c.correlate_batch(&[
            net_ev("HOST-A", "10.0.0.1", 900, "10.0.0.2", 5), // teaches host_addr[10.0.0.1]=host-a
            auth_ev("HOST-B", "svc", 4624, "10.0.0.1", 50),
        ]);
        let (nodes, edges) = c.finish();
        let a = node_id(&nodes, NodeKind::Host, "HOST-A")
            .or_else(|| {
                nodes
                    .iter()
                    .find(|n| n.kind == NodeKind::Host && n.identity_key == "host-a")
                    .map(|n| n.id)
            })
            .expect("host-a");
        let b = node_id(&nodes, NodeKind::Host, "HOST-B").unwrap();
        assert!(has_edge(&edges, a, b, EdgeType::LateralMovement));
    }

    #[test]
    fn file_integrity_creates_host_file_edge_with_hash() {
        let mut c = Correlator::new();
        let mut e = Event::new(class::FILE_ACTIVITY, Timestamp(10));
        e.host = Some("FS01".into());
        e.set_field("file.path", "C:\\data\\log.txt");
        e.set_field("activity_name", "MODIFIED");
        e.set_field("file.hash_md5", "abc123");
        c.correlate(&e);
        let (nodes, edges) = c.finish();
        let fs = node_id(&nodes, NodeKind::Host, "FS01").unwrap();
        let file = node_id(&nodes, NodeKind::File, "log.txt").unwrap();
        assert!(has_edge(&edges, fs, file, EdgeType::Modified));
        let file_node = nodes.iter().find(|n| n.id == file).unwrap();
        assert_eq!(
            file_node.props.get("hash_md5").map(String::as_str),
            Some("abc123")
        );
    }

    #[test]
    fn generic_privilege_event_links_acquired_privilege() {
        // Models the real 4673 sample: john.doe uses SeTcbPrivilege via msedge.
        let mut e = Event::new(0, Timestamp(10)); // class 0 => generic
        e.host = Some("DB01".into());
        e.actor_user = Some("john.doe".into());
        e.process_pid = Some(12904);
        e.process_name = Some("msedge.exe".into());
        e.set_field("PrivilegeList", "SeTcbPrivilege");
        let mut c = Correlator::new();
        c.correlate(&e);
        let (nodes, edges) = c.finish();
        let user = node_id(&nodes, NodeKind::User, "john.doe").unwrap();
        let priv_id = node_id(&nodes, NodeKind::Privilege, "SeTcbPrivilege").unwrap();
        assert!(has_edge(&edges, user, priv_id, EdgeType::AcquiredPrivilege));
        // And the process/executable were reconstructed too.
        assert!(node_id(&nodes, NodeKind::Process, "msedge.exe").is_some());
    }
}
