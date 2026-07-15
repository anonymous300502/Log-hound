//! The DuckDB persistent store — source of truth for events, nodes, edges, and
//! provenance (`PLAN.md` §4, §5).
//!
//! Maps (`fields`/`extra`/`props`) are persisted as JSON text in `VARCHAR`
//! columns rather than native DuckDB `MAP`, sidestepping the MAP FFI-maturity
//! risk flagged in `PLAN.md` §17 (risk 1). A single [`Store`] owns the one
//! writer connection (DuckDB is single-writer).

use std::collections::BTreeMap;
use std::path::Path;

use duckdb::{params, Connection, Row};
use loghound_core::edge::EdgeType;
use loghound_core::node::NodeKind;
use loghound_core::{Edge, EdgeId, Event, EventId, Node, NodeId, Timestamp, Validity};
use serde::Serialize;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("duckdb error: {0}")]
    Duck(#[from] duckdb::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("data integrity: {0}")]
    Integrity(String),
}

type Result<T> = std::result::Result<T, StoreError>;

/// Embedded DuckDB store.
pub struct Store {
    conn: Connection,
}

impl Store {
    /// Open (creating if needed) a file-backed store and initialize the schema.
    pub fn open(path: impl AsRef<Path>) -> Result<Store> {
        let conn = Connection::open(path)?;
        let store = Store { conn };
        store.init_schema()?;
        Ok(store)
    }

    /// Open an in-memory store (used in tests and ephemeral analysis).
    pub fn open_in_memory() -> Result<Store> {
        let conn = Connection::open_in_memory()?;
        let store = Store { conn };
        store.init_schema()?;
        Ok(store)
    }

    fn init_schema(&self) -> Result<()> {
        self.conn.execute_batch(SCHEMA)?;
        Ok(())
    }

    /// Borrow the underlying connection (read-only queries in later milestones).
    pub fn conn(&self) -> &Connection {
        &self.conn
    }

    // ---- events (append-only) ----

    /// Append a normalized event (and its raw body) under `ingest_batch`.
    pub fn append_event(&self, ev: &Event, ingest_batch: u64) -> Result<()> {
        self.conn.execute(
            "INSERT INTO events (event_id, ocsf_uid, ts, class_uid, activity_id, event_code, \
             host, src_ip, dst_ip, user_name, actor_user, process_pid, parent_pid, process_name, \
             status_id, severity_id, fields, extra, ingest_batch) \
             VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            params![
                ev.event_id.raw(),
                ev.ocsf_uid,
                ev.ts.millis(),
                ev.class_uid,
                ev.activity_id,
                ev.event_code,
                ev.host.as_deref(),
                ev.src_ip.as_deref(),
                ev.dst_ip.as_deref(),
                ev.user_name.as_deref(),
                ev.actor_user.as_deref(),
                ev.process_pid,
                ev.parent_pid,
                ev.process_name.as_deref(),
                ev.status_id,
                ev.severity_id,
                map_to_json(&ev.fields),
                map_to_json(&ev.extra),
                ingest_batch,
            ],
        )?;
        if let Some(raw) = &ev.raw {
            self.conn.execute(
                "INSERT INTO event_raw (event_id, raw) VALUES (?,?) ON CONFLICT DO NOTHING",
                params![ev.event_id.raw(), raw],
            )?;
        }
        Ok(())
    }

    // ---- nodes / edges (upsert; caller supplies the folded validity) ----

    /// Insert or update a node, persisting the caller's current (folded) state.
    pub fn upsert_node(&self, node: &Node) -> Result<()> {
        self.conn.execute(
            "INSERT INTO nodes (node_id, kind, identity_key, label, first_seen, last_seen, \
             event_count, risk_score, props) VALUES (?,?,?,?,?,?,?,?,?) \
             ON CONFLICT (node_id) DO UPDATE SET \
               label = EXCLUDED.label, \
               first_seen = LEAST(nodes.first_seen, EXCLUDED.first_seen), \
               last_seen = GREATEST(nodes.last_seen, EXCLUDED.last_seen), \
               event_count = EXCLUDED.event_count, \
               risk_score = EXCLUDED.risk_score, \
               props = EXCLUDED.props",
            params![
                node.id.raw(),
                node.kind.as_u8(),
                node.identity_key,
                node.label,
                node.validity.first_seen.millis(),
                node.validity.last_seen.millis(),
                node.validity.event_count,
                node.risk_score,
                map_to_json(&node.props),
            ],
        )?;
        Ok(())
    }

    /// Persist recomputed risk scores (`PLAN.md` §6, M7). Batched in one
    /// transaction; ids not present are ignored.
    pub fn set_risk_scores(&self, scores: &[(NodeId, f32)]) -> Result<()> {
        self.conn.execute_batch("BEGIN")?;
        {
            let mut stmt = self
                .conn
                .prepare("UPDATE nodes SET risk_score = ? WHERE node_id = ?")?;
            for (id, risk) in scores {
                stmt.execute(params![*risk, id.raw()])?;
            }
        }
        self.conn.execute_batch("COMMIT")?;
        Ok(())
    }

    /// Insert or update an edge, folding validity via SQL `LEAST`/`GREATEST`.
    pub fn upsert_edge(&self, edge: &Edge) -> Result<()> {
        self.conn.execute(
            "INSERT INTO edges (edge_id, src_id, dst_id, etype, first_seen, last_seen, \
             event_count, weight, props) VALUES (?,?,?,?,?,?,?,?,?) \
             ON CONFLICT (edge_id) DO UPDATE SET \
               first_seen = LEAST(edges.first_seen, EXCLUDED.first_seen), \
               last_seen = GREATEST(edges.last_seen, EXCLUDED.last_seen), \
               event_count = EXCLUDED.event_count, \
               weight = EXCLUDED.weight, \
               props = EXCLUDED.props",
            params![
                edge.id.raw(),
                edge.src.raw(),
                edge.dst.raw(),
                edge.etype.as_u8(),
                edge.validity.first_seen.millis(),
                edge.validity.last_seen.millis(),
                edge.validity.event_count,
                edge.weight,
                map_to_json(&edge.props),
            ],
        )?;
        Ok(())
    }

    /// Link an edge to a source event (provenance for the before/after query).
    pub fn link_edge_event(
        &self,
        edge: EdgeId,
        event: loghound_core::EventId,
        ts: Timestamp,
    ) -> Result<()> {
        self.conn.execute(
            "INSERT INTO edge_events (edge_id, event_id, ts) VALUES (?,?,?) ON CONFLICT DO NOTHING",
            params![edge.raw(), event.raw(), ts.millis()],
        )?;
        Ok(())
    }

    /// Link a node to a source event (provenance).
    pub fn link_node_event(
        &self,
        node: NodeId,
        event: loghound_core::EventId,
        ts: Timestamp,
    ) -> Result<()> {
        self.conn.execute(
            "INSERT INTO node_events (node_id, event_id, ts) VALUES (?,?,?) ON CONFLICT DO NOTHING",
            params![node.raw(), event.raw(), ts.millis()],
        )?;
        Ok(())
    }

    // ---- reads ----

    pub fn count(&self, table: Table) -> Result<u64> {
        let sql = format!("SELECT count(*) FROM {}", table.name());
        let n: i64 = self.conn.query_row(&sql, [], |r| r.get(0))?;
        Ok(n as u64)
    }

    /// Load all nodes (used to cold-build the in-memory index).
    pub fn load_nodes(&self) -> Result<Vec<Node>> {
        let sql = format!("SELECT {NODE_COLS} FROM nodes");
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map([], map_raw_node)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?.into_node()?);
        }
        Ok(out)
    }

    /// Load all edges (used to cold-build the in-memory index).
    pub fn load_edges(&self) -> Result<Vec<Edge>> {
        let sql = format!("SELECT {EDGE_COLS} FROM edges");
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map([], map_raw_edge)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?.into_edge()?);
        }
        Ok(out)
    }
}

/// A compact event projection for the timeline and event-context API.
#[derive(Debug, Clone, Serialize)]
pub struct EventSummary {
    pub event_id: u64,
    pub ts: i64,
    pub class_uid: u32,
    pub event_code: Option<i32>,
    pub host: Option<String>,
    pub user_name: Option<String>,
    pub process_name: Option<String>,
    pub src_ip: Option<String>,
    pub dst_ip: Option<String>,
}

/// Top-level counts for the stats endpoint.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct Stats {
    pub events: u64,
    pub nodes: u64,
    pub edges: u64,
    pub alerts: u64,
}

/// Read queries backing the REST API (`PLAN.md` §10). These run on reader
/// connections; the API serializes DB access behind a mutex (DuckDB is
/// single-writer), while topology traversal uses the lock-free CSR index.
impl Store {
    /// Fetch a single node by id.
    pub fn get_node(&self, id: NodeId) -> Result<Option<Node>> {
        let sql = format!("SELECT {NODE_COLS} FROM nodes WHERE node_id = ?");
        let mut stmt = self.conn.prepare(&sql)?;
        let mut rows = stmt.query_map([id.raw()], map_raw_node)?;
        match rows.next() {
            Some(r) => Ok(Some(r?.into_node()?)),
            None => Ok(None),
        }
    }

    /// Fetch many nodes by id (used to hydrate labels for a traversal result).
    pub fn get_nodes(&self, ids: &[NodeId]) -> Result<Vec<Node>> {
        let mut out = Vec::with_capacity(ids.len());
        for &id in ids {
            if let Some(n) = self.get_node(id)? {
                out.push(n);
            }
        }
        Ok(out)
    }

    /// Fetch a single edge by id.
    pub fn get_edge(&self, id: EdgeId) -> Result<Option<Edge>> {
        let sql = format!("SELECT {EDGE_COLS} FROM edges WHERE edge_id = ?");
        let mut stmt = self.conn.prepare(&sql)?;
        let mut rows = stmt.query_map([id.raw()], map_raw_edge)?;
        match rows.next() {
            Some(r) => Ok(Some(r?.into_edge()?)),
            None => Ok(None),
        }
    }

    /// Substring search over node label/identity, optionally filtered by kind,
    /// ranked by how often the entity was seen.
    pub fn search_nodes(
        &self,
        query: &str,
        kind: Option<NodeKind>,
        limit: usize,
    ) -> Result<Vec<Node>> {
        let pattern = format!("%{query}%");
        let mut out = Vec::new();
        if let Some(k) = kind {
            let sql = format!(
                "SELECT {NODE_COLS} FROM nodes WHERE (label ILIKE ? OR identity_key ILIKE ?) \
                 AND kind = ? ORDER BY event_count DESC LIMIT ?"
            );
            let mut stmt = self.conn.prepare(&sql)?;
            let rows = stmt.query_map(
                params![pattern, pattern, k.as_u8(), limit as i64],
                map_raw_node,
            )?;
            for r in rows {
                out.push(r?.into_node()?);
            }
        } else {
            let sql = format!(
                "SELECT {NODE_COLS} FROM nodes WHERE (label ILIKE ? OR identity_key ILIKE ?) \
                 ORDER BY event_count DESC LIMIT ?"
            );
            let mut stmt = self.conn.prepare(&sql)?;
            let rows = stmt.query_map(params![pattern, pattern, limit as i64], map_raw_node)?;
            for r in rows {
                out.push(r?.into_node()?);
            }
        }
        Ok(out)
    }

    /// Fetch a single event summary by id.
    pub fn get_event(&self, id: EventId) -> Result<Option<EventSummary>> {
        let sql = format!("SELECT {EVENT_COLS} FROM events WHERE event_id = ?");
        let mut stmt = self.conn.prepare(&sql)?;
        let mut rows = stmt.query_map([id.raw()], map_event_summary)?;
        match rows.next() {
            Some(r) => Ok(Some(r?)),
            None => Ok(None),
        }
    }

    /// Events on a host within `[lo, hi]` (the "what happened before/after" query).
    pub fn events_context(
        &self,
        host: &str,
        lo: i64,
        hi: i64,
        limit: usize,
    ) -> Result<Vec<EventSummary>> {
        // Case-insensitive host match: node identity keys carry a lowercased host
        // (see `identity::host_key`) whereas `events.host` keeps the original
        // casing, so the UI can pass either form and still find the evidence.
        let sql = format!(
            "SELECT {EVENT_COLS} FROM events WHERE lower(host) = lower(?) AND ts BETWEEN ? AND ? \
             ORDER BY ts LIMIT ?"
        );
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map(params![host, lo, hi, limit as i64], map_event_summary)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// Bucketed event counts over `[lo, hi]` for the timeline histogram.
    pub fn timeline(
        &self,
        lo: i64,
        hi: i64,
        bucket_ms: i64,
        host: Option<&str>,
    ) -> Result<Vec<(i64, u64)>> {
        let bucket = bucket_ms.max(1);
        let mut out = Vec::new();
        let map = |row: &Row| -> duckdb::Result<(i64, i64)> { Ok((row.get(0)?, row.get(1)?)) };
        if let Some(h) = host {
            let sql = format!(
                "SELECT (ts // {bucket}) * {bucket} AS b, count(*) FROM events \
                 WHERE host = ? AND ts BETWEEN ? AND ? GROUP BY b ORDER BY b"
            );
            let mut stmt = self.conn.prepare(&sql)?;
            let rows = stmt.query_map(params![h, lo, hi], map)?;
            for r in rows {
                let (b, c) = r?;
                out.push((b, c as u64));
            }
        } else {
            let sql = format!(
                "SELECT (ts // {bucket}) * {bucket} AS b, count(*) FROM events \
                 WHERE ts BETWEEN ? AND ? GROUP BY b ORDER BY b"
            );
            let mut stmt = self.conn.prepare(&sql)?;
            let rows = stmt.query_map(params![lo, hi], map)?;
            for r in rows {
                let (b, c) = r?;
                out.push((b, c as u64));
            }
        }
        Ok(out)
    }

    /// Top-level counts.
    pub fn stats(&self) -> Result<Stats> {
        Ok(Stats {
            events: self.count(Table::Events)?,
            nodes: self.count(Table::Nodes)?,
            edges: self.count(Table::Edges)?,
            alerts: self.count(Table::Alerts)?,
        })
    }

    /// Insert (or replace, keyed by `alert_id`) an alert. Idempotent, so
    /// re-running detection over the same corpus does not duplicate alerts.
    pub fn insert_alert(&self, a: &AlertRecord) -> Result<()> {
        let event_ids = serde_json::to_string(&a.event_ids)?;
        self.conn.execute(
            "INSERT OR REPLACE INTO alerts \
             (alert_id, rule_id, name, severity, rule_type, mitre, ts, event_count, group_key, description, event_ids) \
             VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            params![
                a.alert_id,
                a.rule_id,
                a.name,
                a.severity,
                a.rule_type,
                a.mitre,
                a.ts,
                a.event_count as i64,
                a.group_key,
                a.description,
                event_ids,
            ],
        )?;
        Ok(())
    }

    /// List alerts, most recent first.
    pub fn list_alerts(&self, limit: usize) -> Result<Vec<AlertRecord>> {
        let sql = format!("SELECT {ALERT_COLS} FROM alerts ORDER BY ts DESC LIMIT ?");
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map([limit as i64], map_alert)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// The highest-risk nodes (for the CLI summary / risk overlays).
    pub fn top_risk_nodes(&self, limit: usize) -> Result<Vec<Node>> {
        let sql = format!(
            "SELECT {NODE_COLS} FROM nodes ORDER BY risk_score DESC, event_count DESC LIMIT ?"
        );
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map([limit as i64], map_raw_node)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?.into_node()?);
        }
        Ok(out)
    }

    /// Fetch a single alert by id.
    pub fn get_alert(&self, alert_id: &str) -> Result<Option<AlertRecord>> {
        let sql = format!("SELECT {ALERT_COLS} FROM alerts WHERE alert_id = ?");
        let mut stmt = self.conn.prepare(&sql)?;
        let mut rows = stmt.query_map([alert_id], map_alert)?;
        match rows.next() {
            Some(r) => Ok(Some(r?)),
            None => Ok(None),
        }
    }
}

const NODE_COLS: &str =
    "node_id, kind, identity_key, label, first_seen, last_seen, event_count, risk_score, props";
const ALERT_COLS: &str = "alert_id, rule_id, name, severity, rule_type, mitre, ts, event_count, group_key, description, event_ids";
const EDGE_COLS: &str =
    "edge_id, src_id, dst_id, etype, first_seen, last_seen, event_count, weight, props";
const EVENT_COLS: &str =
    "event_id, ts, class_uid, event_code, host, user_name, process_name, src_ip, dst_ip";

fn map_raw_node(row: &Row) -> duckdb::Result<RawNode> {
    Ok(RawNode {
        id: row.get::<_, u64>(0)?,
        kind: row.get(1)?,
        identity_key: row.get(2)?,
        label: row.get(3)?,
        first_seen: row.get(4)?,
        last_seen: row.get(5)?,
        event_count: row.get(6)?,
        risk_score: row.get(7)?,
        props_json: row.get(8)?,
    })
}

fn map_raw_edge(row: &Row) -> duckdb::Result<RawEdge> {
    Ok(RawEdge {
        id: row.get::<_, u64>(0)?,
        src: row.get::<_, u64>(1)?,
        dst: row.get::<_, u64>(2)?,
        etype: row.get(3)?,
        first_seen: row.get(4)?,
        last_seen: row.get(5)?,
        event_count: row.get(6)?,
        weight: row.get(7)?,
        props_json: row.get(8)?,
    })
}

fn map_alert(row: &Row) -> duckdb::Result<AlertRecord> {
    let event_ids_json: String = row.get(10)?;
    Ok(AlertRecord {
        alert_id: row.get(0)?,
        rule_id: row.get(1)?,
        name: row.get(2)?,
        severity: row.get(3)?,
        rule_type: row.get(4)?,
        mitre: row.get(5)?,
        ts: row.get(6)?,
        event_count: row.get::<_, i64>(7)? as u64,
        group_key: row.get(8)?,
        description: row.get(9)?,
        event_ids: serde_json::from_str(&event_ids_json).unwrap_or_default(),
    })
}

fn map_event_summary(row: &Row) -> duckdb::Result<EventSummary> {
    Ok(EventSummary {
        event_id: row.get::<_, u64>(0)?,
        ts: row.get(1)?,
        class_uid: row.get(2)?,
        event_code: row.get(3)?,
        host: row.get(4)?,
        user_name: row.get(5)?,
        process_name: row.get(6)?,
        src_ip: row.get(7)?,
        dst_ip: row.get(8)?,
    })
}

/// Tables addressable by [`Store::count`].
#[derive(Debug, Clone, Copy)]
pub enum Table {
    Events,
    Nodes,
    Edges,
    EdgeEvents,
    NodeEvents,
    Alerts,
}

impl Table {
    fn name(self) -> &'static str {
        match self {
            Table::Events => "events",
            Table::Nodes => "nodes",
            Table::Edges => "edges",
            Table::EdgeEvents => "edge_events",
            Table::NodeEvents => "node_events",
            Table::Alerts => "alerts",
        }
    }
}

/// A persisted alert (`PLAN.md` §4). `event_ids` links back to the exact events
/// that produced it (provenance / evidence).
#[derive(Debug, Clone, Serialize)]
pub struct AlertRecord {
    pub alert_id: String,
    pub rule_id: String,
    pub name: String,
    pub severity: String,
    pub rule_type: String,
    pub mitre: Option<String>,
    pub ts: i64,
    pub event_count: u64,
    pub group_key: Option<String>,
    pub description: String,
    pub event_ids: Vec<u64>,
}

// ---- row → domain reconstruction ----

struct RawNode {
    id: u64,
    kind: u8,
    identity_key: String,
    label: String,
    first_seen: i64,
    last_seen: i64,
    event_count: u64,
    risk_score: f32,
    props_json: String,
}

impl RawNode {
    fn into_node(self) -> Result<Node> {
        let kind = NodeKind::from_u8(self.kind)
            .ok_or_else(|| StoreError::Integrity(format!("unknown node kind {}", self.kind)))?;
        Ok(Node {
            id: NodeId(self.id),
            kind,
            identity_key: self.identity_key,
            label: self.label,
            validity: Validity {
                first_seen: Timestamp(self.first_seen),
                last_seen: Timestamp(self.last_seen),
                event_count: self.event_count,
            },
            risk_score: self.risk_score,
            props: json_to_map(&self.props_json),
        })
    }
}

struct RawEdge {
    id: u64,
    src: u64,
    dst: u64,
    etype: u8,
    first_seen: i64,
    last_seen: i64,
    event_count: u64,
    weight: f32,
    props_json: String,
}

impl RawEdge {
    fn into_edge(self) -> Result<Edge> {
        let etype = EdgeType::from_u8(self.etype)
            .ok_or_else(|| StoreError::Integrity(format!("unknown edge type {}", self.etype)))?;
        Ok(Edge {
            id: EdgeId(self.id),
            src: NodeId(self.src),
            dst: NodeId(self.dst),
            etype,
            validity: Validity {
                first_seen: Timestamp(self.first_seen),
                last_seen: Timestamp(self.last_seen),
                event_count: self.event_count,
            },
            weight: self.weight,
            props: json_to_map(&self.props_json),
        })
    }
}

fn map_to_json(m: &BTreeMap<String, String>) -> String {
    serde_json::to_string(m).unwrap_or_else(|_| "{}".to_string())
}

fn json_to_map(s: &str) -> BTreeMap<String, String> {
    serde_json::from_str(s).unwrap_or_default()
}

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS events (
    event_id     UBIGINT PRIMARY KEY,
    ocsf_uid     VARCHAR,
    ts           BIGINT   NOT NULL,
    class_uid    UINTEGER NOT NULL,
    activity_id  INTEGER,
    event_code   INTEGER,
    host         VARCHAR,
    src_ip       VARCHAR,
    dst_ip       VARCHAR,
    user_name    VARCHAR,
    actor_user   VARCHAR,
    process_pid  BIGINT,
    parent_pid   BIGINT,
    process_name VARCHAR,
    status_id    INTEGER,
    severity_id  INTEGER,
    fields       VARCHAR,
    extra        VARCHAR,
    ingest_batch UBIGINT  NOT NULL
);
CREATE TABLE IF NOT EXISTS event_raw (
    event_id UBIGINT PRIMARY KEY,
    raw      VARCHAR
);
CREATE TABLE IF NOT EXISTS nodes (
    node_id      UBIGINT PRIMARY KEY,
    kind         UTINYINT NOT NULL,
    identity_key VARCHAR  NOT NULL,
    label        VARCHAR,
    first_seen   BIGINT   NOT NULL,
    last_seen    BIGINT   NOT NULL,
    event_count  UBIGINT  NOT NULL DEFAULT 0,
    risk_score   FLOAT    NOT NULL DEFAULT 0.0,
    props        VARCHAR
);
CREATE TABLE IF NOT EXISTS edges (
    edge_id     UBIGINT PRIMARY KEY,
    src_id      UBIGINT  NOT NULL,
    dst_id      UBIGINT  NOT NULL,
    etype       UTINYINT NOT NULL,
    first_seen  BIGINT   NOT NULL,
    last_seen   BIGINT   NOT NULL,
    event_count UBIGINT  NOT NULL DEFAULT 1,
    weight      FLOAT    NOT NULL DEFAULT 1.0,
    props       VARCHAR
);
CREATE TABLE IF NOT EXISTS edge_events (
    edge_id  UBIGINT NOT NULL,
    event_id UBIGINT NOT NULL,
    ts       BIGINT  NOT NULL,
    PRIMARY KEY (edge_id, event_id)
);
CREATE TABLE IF NOT EXISTS node_events (
    node_id  UBIGINT NOT NULL,
    event_id UBIGINT NOT NULL,
    ts       BIGINT  NOT NULL,
    PRIMARY KEY (node_id, event_id)
);
CREATE TABLE IF NOT EXISTS alerts (
    alert_id    VARCHAR PRIMARY KEY,
    rule_id     VARCHAR NOT NULL,
    name        VARCHAR,
    severity    VARCHAR,
    rule_type   VARCHAR,
    mitre       VARCHAR,
    ts          BIGINT  NOT NULL,
    event_count INTEGER NOT NULL DEFAULT 0,
    group_key   VARCHAR,
    description VARCHAR,
    event_ids   VARCHAR
);
CREATE INDEX IF NOT EXISTS idx_events_host_ts ON events(host, ts);
CREATE INDEX IF NOT EXISTS idx_edge_events ON edge_events(edge_id, ts);
CREATE INDEX IF NOT EXISTS idx_node_events ON node_events(node_id, ts);
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts);
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use loghound_core::event::class;

    fn sample_event(id: u64) -> Event {
        let mut ev = Event::new(class::AUTHENTICATION, Timestamp(1_782_858_369_000));
        ev.event_id = loghound_core::EventId::new(id);
        ev.event_code = Some(4624);
        ev.user_name = Some("alice".into());
        ev.host = Some("DC01".into());
        ev.src_ip = Some("10.0.0.9".into());
        ev.set_field("auth_protocol", "Network");
        ev.extra.insert("env.tenant".into(), "acme".into());
        ev.raw = Some("OPLC-...raw...".into());
        ev
    }

    #[test]
    fn schema_initializes_and_counts_zero() {
        let s = Store::open_in_memory().expect("open");
        assert_eq!(s.count(Table::Events).unwrap(), 0);
        assert_eq!(s.count(Table::Nodes).unwrap(), 0);
        assert_eq!(s.count(Table::Edges).unwrap(), 0);
        assert_eq!(s.count(Table::Alerts).unwrap(), 0);
    }

    #[test]
    fn risk_scores_persist_and_rank() {
        let s = Store::open_in_memory().expect("open");
        let low = Node::new(NodeKind::Host, "h1", "H1", Timestamp(1));
        let high = Node::new(NodeKind::Host, "h2", "H2", Timestamp(1));
        s.upsert_node(&low).unwrap();
        s.upsert_node(&high).unwrap();

        s.set_risk_scores(&[(low.id, 10.0), (high.id, 90.0)])
            .unwrap();
        let top = s.top_risk_nodes(10).unwrap();
        assert_eq!(top.first().unwrap().id, high.id);
        assert!((top.first().unwrap().risk_score - 90.0).abs() < 1e-3);
    }

    #[test]
    fn alerts_round_trip_and_dedup() {
        let s = Store::open_in_memory().expect("open");
        let rec = AlertRecord {
            alert_id: "BF_01:10.0.0.9:3000".into(),
            rule_id: "BF_01".into(),
            name: "Brute Force".into(),
            severity: "high".into(),
            rule_type: "threshold".into(),
            mitre: Some("T1110 - Brute Force".into()),
            ts: 3000,
            event_count: 3,
            group_key: Some("10.0.0.9".into()),
            description: "brute force".into(),
            event_ids: vec![1, 2, 3],
        };
        s.insert_alert(&rec).unwrap();
        // Re-inserting the same id is idempotent (INSERT OR REPLACE).
        s.insert_alert(&rec).unwrap();
        assert_eq!(s.count(Table::Alerts).unwrap(), 1);
        assert_eq!(s.stats().unwrap().alerts, 1);

        let got = s
            .get_alert("BF_01:10.0.0.9:3000")
            .unwrap()
            .expect("present");
        assert_eq!(got.rule_id, "BF_01");
        assert_eq!(got.event_ids, vec![1, 2, 3]);
        assert_eq!(got.group_key.as_deref(), Some("10.0.0.9"));
        assert!(s.get_alert("missing").unwrap().is_none());

        let list = s.list_alerts(10).unwrap();
        assert_eq!(list.len(), 1);
    }

    #[test]
    fn event_round_trips() {
        let s = Store::open_in_memory().expect("open");
        s.append_event(&sample_event(1), 1).expect("append");
        assert_eq!(s.count(Table::Events).unwrap(), 1);

        // Verify a typed column and a JSON map field survived.
        let (user, fields): (String, String) = s
            .conn
            .query_row(
                "SELECT user_name, fields FROM events WHERE event_id = 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(user, "alice");
        assert!(fields.contains("auth_protocol"));
    }

    #[test]
    fn node_upsert_folds_validity() {
        let s = Store::open_in_memory().expect("open");
        let mut n = Node::new(NodeKind::Host, "dc01", "DC01", Timestamp(500));
        s.upsert_node(&n).unwrap();
        // Observe earlier + later, then re-upsert: interval should widen, count grow.
        n.observe(Timestamp(100));
        n.observe(Timestamp(900));
        s.upsert_node(&n).unwrap();

        let (fs, ls, cnt): (i64, i64, u64) = s
            .conn
            .query_row(
                "SELECT first_seen, last_seen, event_count FROM nodes WHERE node_id = ?",
                params![n.id.raw()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(fs, 100);
        assert_eq!(ls, 900);
        assert_eq!(cnt, 3);
        assert_eq!(s.count(Table::Nodes).unwrap(), 1); // still one node
    }

    #[test]
    fn nodes_and_edges_load_back_identically() {
        let s = Store::open_in_memory().expect("open");
        let u =
            Node::new(NodeKind::User, "alice", "alice", Timestamp(10)).with_prop("domain", "corp");
        let h = Node::new(NodeKind::Host, "dc01", "DC01", Timestamp(10));
        s.upsert_node(&u).unwrap();
        s.upsert_node(&h).unwrap();
        let e = Edge::new(u.id, h.id, EdgeType::LoggedInTo, Timestamp(10));
        s.upsert_edge(&e).unwrap();

        let nodes = s.load_nodes().unwrap();
        let edges = s.load_edges().unwrap();
        assert_eq!(nodes.len(), 2);
        assert_eq!(edges.len(), 1);
        let loaded_u = nodes.iter().find(|n| n.id == u.id).unwrap();
        assert_eq!(loaded_u.kind, NodeKind::User);
        assert_eq!(
            loaded_u.props.get("domain").map(String::as_str),
            Some("corp")
        );
        assert_eq!(edges[0].etype, EdgeType::LoggedInTo);
        assert_eq!(edges[0].src, u.id);
        assert_eq!(edges[0].dst, h.id);
    }

    #[test]
    fn provenance_links_dedup() {
        let s = Store::open_in_memory().expect("open");
        let n = Node::new(NodeKind::Host, "dc01", "DC01", Timestamp(10));
        s.upsert_node(&n).unwrap();
        let ev = loghound_core::EventId::new(7);
        s.link_node_event(n.id, ev, Timestamp(10)).unwrap();
        s.link_node_event(n.id, ev, Timestamp(10)).unwrap(); // idempotent
        assert_eq!(s.count(Table::NodeEvents).unwrap(), 1);
    }

    #[test]
    fn get_node_and_search() {
        let s = Store::open_in_memory().expect("open");
        let alice = Node::new(NodeKind::User, "corp\\alice", "alice", Timestamp(10));
        let dc = Node::new(NodeKind::Host, "dc01.corp", "DC01", Timestamp(10));
        s.upsert_node(&alice).unwrap();
        s.upsert_node(&dc).unwrap();

        assert_eq!(s.get_node(alice.id).unwrap().unwrap().label, "alice");
        assert!(s.get_node(NodeId(123)).unwrap().is_none());

        // Substring search, and kind filter.
        let hits = s.search_nodes("alic", None, 10).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].id, alice.id);
        let only_hosts = s.search_nodes("dc", Some(NodeKind::Host), 10).unwrap();
        assert_eq!(only_hosts.len(), 1);
        assert!(s
            .search_nodes("dc", Some(NodeKind::User), 10)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn events_context_and_timeline() {
        let s = Store::open_in_memory().expect("open");
        for (i, ts) in [1000i64, 1500, 5000].into_iter().enumerate() {
            let mut ev = Event::new(class::AUTHENTICATION, Timestamp(ts));
            ev.event_id = EventId::new(i as u64 + 1);
            ev.host = Some("DC01".into());
            ev.event_code = Some(4624);
            s.append_event(&ev, 1).unwrap();
        }
        // Context window [0,2000] returns the first two events in ts order.
        let ctx = s.events_context("DC01", 0, 2000, 100).unwrap();
        assert_eq!(ctx.len(), 2);
        assert!(ctx[0].ts <= ctx[1].ts);

        // 1000ms buckets: two events in bucket 1000, one in bucket 5000.
        let tl = s.timeline(0, 10_000, 1000, Some("DC01")).unwrap();
        assert_eq!(tl, vec![(1000, 2), (5000, 1)]);

        let st = s.stats().unwrap();
        assert_eq!(st.events, 3);

        let e = s.get_event(EventId::new(1)).unwrap().unwrap();
        assert_eq!(e.event_code, Some(4624));
    }
}
