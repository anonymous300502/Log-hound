//! # loghound-api
//!
//! The thin HTTP layer (`PLAN.md` §10): Axum handlers returning Cytoscape-shaped
//! graph JSON. Topology traversal uses the lock-free CSR [`GraphIndex`]; DuckDB
//! reads are serialized behind a mutex (DuckDB is single-writer). Handler bodies
//! never hold the mutex across an `.await`.

pub mod dto;
pub mod error;

use std::net::SocketAddr;
use std::path::Path as FsPath;
use std::sync::{Arc, Mutex};

use axum::extract::{Path, Query, State};
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use tower_http::cors::CorsLayer;
use tower_http::services::{ServeDir, ServeFile};

use loghound_core::edge::EdgeType;
use loghound_core::node::NodeKind;
use loghound_core::{EventId, Node, NodeId, Timestamp};
use loghound_graph::{
    all_time, AlertRecord, Dir, EdgeTypeMask, EventSummary, Graph, GraphIndex, Stats, TraversalOpts,
};

use crate::dto::{cy_graph, CyGraph, CyNodeData};
use crate::error::{ApiError, ApiResult};

/// Shared application state.
#[derive(Clone)]
pub struct AppState {
    /// Lock-free traversal index.
    pub index: Arc<GraphIndex>,
    /// Serialized DuckDB access (single-writer engine).
    pub graph: Arc<Mutex<Graph>>,
}

impl AppState {
    /// Build state from an opened graph, capturing a shared index handle.
    pub fn new(graph: Graph) -> Self {
        let index = graph.index_handle();
        AppState {
            index,
            graph: Arc::new(Mutex::new(graph)),
        }
    }
}

/// Construct the API router.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/api/health", get(health))
        .route("/api/stats", get(stats))
        .route("/api/search", get(search))
        .route("/api/nodes/:id", get(node_detail))
        .route("/api/nodes/:id/neighbors", get(neighbors))
        .route("/api/graph/path", get(path))
        .route("/api/timeline", get(timeline))
        .route("/api/events", get(events_context))
        .route("/api/events/:id", get(event_detail))
        .route("/api/alerts", get(alerts))
        .route("/api/alerts/:id", get(alert_detail))
        .route("/api/analytics/pagerank", get(analytics_pagerank))
        .route("/api/analytics/risk", get(analytics_risk))
        .route("/api/analytics/components", get(analytics_components))
        .route("/api/graph/attack-paths", get(attack_paths))
        .layer(CorsLayer::permissive())
        .with_state(state)
}

/// Wrap the API router so that any non-`/api` path is served from a built
/// frontend directory (`frontend/dist`), falling back to `index.html` for
/// client-side routing (PLAN.md §11). This makes `loghound serve` a single
/// command that hosts both the API and the UI.
pub fn with_static(router: Router, dir: &FsPath) -> Router {
    let index = dir.join("index.html");
    let serve_dir = ServeDir::new(dir).not_found_service(ServeFile::new(index));
    router.fallback_service(serve_dir)
}

/// Bind and serve a prebuilt router until shutdown.
pub async fn serve(addr: SocketAddr, app: Router) -> std::io::Result<()> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await
}

// ---- query params ----

#[derive(Deserialize)]
struct SearchQ {
    q: String,
    kind: Option<String>,
    limit: Option<usize>,
}

#[derive(Deserialize)]
struct NeighborsQ {
    hops: Option<u32>,
    etypes: Option<String>,
    dir: Option<String>,
    from: Option<i64>,
    to: Option<i64>,
}

#[derive(Deserialize)]
struct PathQ {
    src: u64,
    dst: u64,
    dir: Option<String>,
    from: Option<i64>,
    to: Option<i64>,
}

#[derive(Deserialize)]
struct TimelineQ {
    host: Option<String>,
    from: Option<i64>,
    to: Option<i64>,
    bucket: Option<i64>,
}

#[derive(Deserialize)]
struct EventsQ {
    host: String,
    ts: i64,
    window: Option<i64>,
}

#[derive(Serialize)]
struct TimelineBucket {
    bucket: i64,
    count: u64,
}

#[derive(Deserialize)]
struct AlertsQ {
    limit: Option<usize>,
}

/// An alert plus its hydrated contributing events (the evidence view).
#[derive(Serialize)]
struct AlertDetail {
    alert: AlertRecord,
    events: Vec<EventSummary>,
}

#[derive(Deserialize)]
struct AnalyticsQ {
    limit: Option<usize>,
}

/// A ranked node score (PageRank / risk overlays).
#[derive(Serialize)]
struct ScoreDto {
    id: String,
    label: String,
    kind: &'static str,
    score: f32,
    risk: f32,
}

/// A weakly-connected component (time-scoped blast radius).
#[derive(Serialize)]
struct ComponentDto {
    size: usize,
    nodes: Vec<String>,
}

#[derive(Deserialize)]
struct AttackPathQ {
    src: u64,
    dst: u64,
    k: Option<usize>,
    from: Option<i64>,
    to: Option<i64>,
}

/// One ranked, time-respecting attack path as a Cytoscape graph plus metadata.
#[derive(Serialize)]
struct AttackPathDto {
    rank: usize,
    cost: f32,
    length: usize,
    /// Ordered edge types along the path (the technique chain).
    etypes: Vec<&'static str>,
    /// MITRE tags gathered from any alert nodes on the path.
    mitre: Vec<String>,
    graph: CyGraph,
}

// ---- param helpers ----

fn parse_dir(s: Option<&str>) -> Dir {
    match s {
        Some("out") => Dir::Out,
        Some("in") => Dir::In,
        _ => Dir::Both,
    }
}

fn parse_etypes(s: Option<&str>) -> Option<EdgeTypeMask> {
    let s = s?;
    let types: Vec<EdgeType> = s
        .split(',')
        .filter_map(|t| EdgeType::from_name(t.trim()))
        .collect();
    if types.is_empty() {
        None
    } else {
        Some(EdgeTypeMask::of(&types))
    }
}

fn time_window(from: Option<i64>, to: Option<i64>) -> Option<(Timestamp, Timestamp)> {
    match (from, to) {
        (None, None) => None,
        (lo, hi) => Some((
            Timestamp(lo.unwrap_or(i64::MIN / 2)),
            Timestamp(hi.unwrap_or(i64::MAX / 2)),
        )),
    }
}

// ---- handlers ----

async fn health() -> &'static str {
    "ok"
}

async fn stats(State(st): State<AppState>) -> ApiResult<Json<Stats>> {
    let out = { st.graph.lock().unwrap().store().stats()? };
    Ok(Json(out))
}

async fn search(
    State(st): State<AppState>,
    Query(q): Query<SearchQ>,
) -> ApiResult<Json<Vec<CyNodeData>>> {
    let kind = q.kind.as_deref().and_then(NodeKind::from_name);
    let limit = q.limit.unwrap_or(50).min(500);
    let hits: Vec<Node> = {
        st.graph
            .lock()
            .unwrap()
            .store()
            .search_nodes(&q.q, kind, limit)?
    };
    Ok(Json(hits.iter().map(CyNodeData::from_node).collect()))
}

async fn node_detail(State(st): State<AppState>, Path(id): Path<u64>) -> ApiResult<Json<Node>> {
    let node = { st.graph.lock().unwrap().store().get_node(NodeId(id))? };
    node.map(Json)
        .ok_or_else(|| ApiError::NotFound(format!("node {id} not found")))
}

async fn neighbors(
    State(st): State<AppState>,
    Path(id): Path<u64>,
    Query(q): Query<NeighborsQ>,
) -> ApiResult<Json<CyGraph>> {
    let opts = TraversalOpts {
        time: time_window(q.from, q.to),
        etypes: parse_etypes(q.etypes.as_deref()),
        max_hops: q.hops.unwrap_or(1).clamp(1, 5),
        direction: parse_dir(q.dir.as_deref()),
    };
    let sub = st.index.load().k_hop(NodeId(id), opts.max_hops, &opts);
    let ids: Vec<NodeId> = sub.nodes.iter().map(|v| v.id).collect();
    let nodes = { st.graph.lock().unwrap().store().get_nodes(&ids)? };
    Ok(Json(cy_graph(&nodes, &sub.edges)))
}

async fn path(State(st): State<AppState>, Query(q): Query<PathQ>) -> ApiResult<Json<CyGraph>> {
    let opts = TraversalOpts {
        time: time_window(q.from, q.to),
        etypes: None,
        max_hops: 0,
        direction: parse_dir(q.dir.as_deref()),
    };
    let sub = st
        .index
        .load()
        .shortest_path(NodeId(q.src), NodeId(q.dst), &opts)
        .ok_or_else(|| ApiError::NotFound("no path between the given nodes".into()))?;
    let ids: Vec<NodeId> = sub.nodes.iter().map(|v| v.id).collect();
    let nodes = { st.graph.lock().unwrap().store().get_nodes(&ids)? };
    Ok(Json(cy_graph(&nodes, &sub.edges)))
}

async fn timeline(
    State(st): State<AppState>,
    Query(q): Query<TimelineQ>,
) -> ApiResult<Json<Vec<TimelineBucket>>> {
    let lo = q.from.unwrap_or(i64::MIN / 2);
    let hi = q.to.unwrap_or(i64::MAX / 2);
    let bucket = q.bucket.unwrap_or(3_600_000).max(1); // default 1h buckets
    let rows = {
        st.graph
            .lock()
            .unwrap()
            .store()
            .timeline(lo, hi, bucket, q.host.as_deref())?
    };
    Ok(Json(
        rows.into_iter()
            .map(|(bucket, count)| TimelineBucket { bucket, count })
            .collect(),
    ))
}

async fn events_context(
    State(st): State<AppState>,
    Query(q): Query<EventsQ>,
) -> ApiResult<Json<Vec<EventSummary>>> {
    let window = q.window.unwrap_or(300_000); // ±5 min default
    let evs = {
        st.graph.lock().unwrap().store().events_context(
            &q.host,
            q.ts - window,
            q.ts + window,
            1000,
        )?
    };
    Ok(Json(evs))
}

async fn event_detail(
    State(st): State<AppState>,
    Path(id): Path<u64>,
) -> ApiResult<Json<EventSummary>> {
    let ev = {
        st.graph
            .lock()
            .unwrap()
            .store()
            .get_event(EventId::new(id))?
    };
    ev.map(Json)
        .ok_or_else(|| ApiError::NotFound(format!("event {id} not found")))
}

async fn alerts(
    State(st): State<AppState>,
    Query(q): Query<AlertsQ>,
) -> ApiResult<Json<Vec<AlertRecord>>> {
    let limit = q.limit.unwrap_or(200).min(2000);
    let out = { st.graph.lock().unwrap().store().list_alerts(limit)? };
    Ok(Json(out))
}

async fn alert_detail(
    State(st): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<Json<AlertDetail>> {
    // Fetch the alert, then hydrate its contributing events for the evidence
    // view. The lock is dropped before serialization; never held across await.
    let (alert, events) = {
        let g = st.graph.lock().unwrap();
        let store = g.store();
        let alert = store
            .get_alert(&id)?
            .ok_or_else(|| ApiError::NotFound(format!("alert {id} not found")))?;
        let mut events = Vec::new();
        for eid in &alert.event_ids {
            if let Some(ev) = store.get_event(EventId::new(*eid))? {
                events.push(ev);
            }
        }
        (alert, events)
    };
    Ok(Json(AlertDetail { alert, events }))
}

async fn analytics_pagerank(
    State(st): State<AppState>,
    Query(q): Query<AnalyticsQ>,
) -> ApiResult<Json<Vec<ScoreDto>>> {
    let limit = q.limit.unwrap_or(50).min(500);
    // Compute on the lock-free snapshot, then hydrate labels from the store.
    let top: Vec<(NodeId, f32)> = {
        let snap = st.index.load();
        snap.pagerank(0.85, 40)
            .into_iter()
            .take(limit)
            .map(|s| (s.node_id, s.score))
            .collect()
    };
    let ids: Vec<NodeId> = top.iter().map(|(id, _)| *id).collect();
    let nodes = { st.graph.lock().unwrap().store().get_nodes(&ids)? };
    let by_id: std::collections::HashMap<u64, &Node> =
        nodes.iter().map(|n| (n.id.raw(), n)).collect();
    let out = top
        .iter()
        .filter_map(|(id, score)| {
            by_id.get(&id.raw()).map(|n| ScoreDto {
                id: id.raw().to_string(),
                label: n.label.clone(),
                kind: n.kind.name(),
                score: *score,
                risk: n.risk_score,
            })
        })
        .collect();
    Ok(Json(out))
}

async fn analytics_risk(
    State(st): State<AppState>,
    Query(q): Query<AnalyticsQ>,
) -> ApiResult<Json<Vec<ScoreDto>>> {
    let limit = q.limit.unwrap_or(10).min(200);
    let nodes = { st.graph.lock().unwrap().store().top_risk_nodes(limit)? };
    let out = nodes
        .iter()
        .map(|n| ScoreDto {
            id: n.id.raw().to_string(),
            label: n.label.clone(),
            kind: n.kind.name(),
            score: n.risk_score,
            risk: n.risk_score,
        })
        .collect();
    Ok(Json(out))
}

async fn analytics_components(
    State(st): State<AppState>,
    Query(q): Query<AnalyticsQ>,
) -> ApiResult<Json<Vec<ComponentDto>>> {
    let limit = q.limit.unwrap_or(50).min(500);
    let snap = st.index.load();
    let comps = snap.connected_components(&all_time());
    let out = comps
        .into_iter()
        .take(limit)
        .map(|group| ComponentDto {
            size: group.len(),
            nodes: group.iter().map(|id| id.raw().to_string()).collect(),
        })
        .collect();
    Ok(Json(out))
}

async fn attack_paths(
    State(st): State<AppState>,
    Query(q): Query<AttackPathQ>,
) -> ApiResult<Json<Vec<AttackPathDto>>> {
    let k = q.k.unwrap_or(3).clamp(1, 10);
    let opts = TraversalOpts {
        time: time_window(q.from, q.to),
        etypes: None,
        max_hops: 0,
        direction: Dir::Out,
    };
    let paths = {
        let snap = st.index.load();
        snap.attack_paths(NodeId(q.src), NodeId(q.dst), k, &opts)
    };
    if paths.is_empty() {
        return Err(ApiError::NotFound(
            "no time-respecting path between the given nodes".into(),
        ));
    }
    let mut out = Vec::with_capacity(paths.len());
    for (i, p) in paths.iter().enumerate() {
        let ids: Vec<NodeId> = p.nodes.iter().map(|v| v.id).collect();
        let nodes = { st.graph.lock().unwrap().store().get_nodes(&ids)? };
        let mitre: Vec<String> = nodes
            .iter()
            .filter(|n| n.kind == NodeKind::Alert)
            .filter_map(|n| n.props.get("mitre").cloned())
            .collect();
        let etypes: Vec<&'static str> = p.edges.iter().map(|e| e.etype.name()).collect();
        out.push(AttackPathDto {
            rank: i + 1,
            cost: p.cost,
            length: p.edges.len(),
            etypes,
            mitre,
            graph: cy_graph(&nodes, &p.edges),
        });
    }
    Ok(Json(out))
}
