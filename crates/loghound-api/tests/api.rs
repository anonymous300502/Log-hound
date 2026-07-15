//! HTTP-level tests: drive the router with `oneshot` requests against an
//! in-memory graph and assert the JSON responses (`PLAN.md` §10, M4).

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use serde_json::Value;
use tower::ServiceExt; // for `oneshot`

use loghound_api::{router, AppState};
use loghound_core::event::class;
use loghound_core::{Event, EventId, NodeId, NodeKind, Timestamp};
use loghound_correlate::{identity, Correlator};
use loghound_graph::{AlertRecord, Graph};

fn events() -> Vec<Event> {
    let mut a = Event::new(class::PROCESS_ACTIVITY, Timestamp(10));
    a.host = Some("WKS01".into());
    a.process_pid = Some(100);
    a.process_name = Some("explorer.exe".into());
    let mut b = Event::new(class::PROCESS_ACTIVITY, Timestamp(20));
    b.host = Some("WKS01".into());
    b.process_pid = Some(200);
    b.process_name = Some("cmd.exe".into());
    b.parent_pid = Some(100);
    vec![a, b]
}

fn state() -> AppState {
    let g = Graph::open_in_memory().expect("open");
    let mut evs = events();
    for (i, ev) in evs.iter_mut().enumerate() {
        ev.event_id = EventId::new(i as u64 + 1);
        g.append_event(ev, 1).unwrap();
    }
    let mut c = Correlator::new();
    c.correlate_batch(&evs);
    let (nodes, edges) = c.finish();
    g.apply(&nodes, &edges).unwrap();
    AppState::new(g)
}

fn host_id() -> NodeId {
    NodeId::of(NodeKind::Host, "wks01")
}
fn proc_id(pid: i64, start: i64) -> NodeId {
    NodeId::of(
        NodeKind::Process,
        &identity::process_key("WKS01", pid, start),
    )
}

async fn get_json(app: &axum::Router, uri: &str) -> (StatusCode, Value) {
    let resp = app
        .clone()
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let json = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, json)
}

#[tokio::test]
async fn health_ok() {
    let app = router(state());
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    assert_eq!(&body[..], b"ok");
}

#[tokio::test]
async fn stats_reports_counts() {
    let app = router(state());
    let (status, json) = get_json(&app, "/api/stats").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["events"], 2);
    assert!(json["nodes"].as_u64().unwrap() >= 3); // host + 2 processes + exes
    assert!(json["edges"].as_u64().unwrap() >= 1);
}

#[tokio::test]
async fn search_finds_process() {
    let app = router(state());
    let (status, json) = get_json(&app, "/api/search?q=explorer").await;
    assert_eq!(status, StatusCode::OK);
    let arr = json.as_array().unwrap();
    assert!(arr
        .iter()
        .any(|n| n["label"] == "explorer.exe" && n["kind"] == "process"));
}

#[tokio::test]
async fn node_detail_and_404() {
    let app = router(state());
    let (status, json) = get_json(&app, &format!("/api/nodes/{}", host_id().raw())).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["label"], "WKS01");

    let (status, _) = get_json(&app, "/api/nodes/123456789").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn neighbors_returns_cytoscape_graph() {
    let app = router(state());
    let (status, json) = get_json(
        &app,
        &format!("/api/nodes/{}/neighbors?hops=1", host_id().raw()),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    // Cytoscape shape.
    assert!(json["nodes"].is_array() && json["edges"].is_array());
    let etypes: Vec<&str> = json["edges"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["data"]["etype"].as_str().unwrap())
        .collect();
    assert!(etypes.contains(&"STARTED"), "host STARTED its processes");
}

#[tokio::test]
async fn shortest_path_between_processes() {
    let app = router(state());
    let uri = format!(
        "/api/graph/path?src={}&dst={}",
        proc_id(100, 10).raw(),
        proc_id(200, 20).raw()
    );
    let (status, json) = get_json(&app, &uri).await;
    assert_eq!(status, StatusCode::OK);
    // explorer -> cmd via a single SPAWNED edge.
    assert_eq!(json["nodes"].as_array().unwrap().len(), 2);
    assert_eq!(json["edges"].as_array().unwrap().len(), 1);
    assert_eq!(json["edges"][0]["data"]["etype"], "SPAWNED");
}

#[tokio::test]
async fn timeline_buckets_events() {
    let app = router(state());
    let (status, json) = get_json(&app, "/api/timeline?from=0&to=1000&bucket=100").await;
    assert_eq!(status, StatusCode::OK);
    let total: u64 = json
        .as_array()
        .unwrap()
        .iter()
        .map(|b| b["count"].as_u64().unwrap())
        .sum();
    assert_eq!(total, 2, "both events fall in the window");
}

/// State with one persisted alert whose evidence points at the ingested events.
fn state_with_alert() -> AppState {
    let g = Graph::open_in_memory().expect("open");
    let mut evs = events();
    for (i, ev) in evs.iter_mut().enumerate() {
        ev.event_id = EventId::new(i as u64 + 1);
        g.append_event(ev, 1).unwrap();
    }
    let mut c = Correlator::new();
    c.correlate_batch(&evs);
    let (nodes, edges) = c.finish();
    g.apply(&nodes, &edges).unwrap();
    g.store()
        .insert_alert(&AlertRecord {
            alert_id: "A_PS:-:20".into(),
            rule_id: "A_PS".into(),
            name: "Suspicious PowerShell".into(),
            severity: "high".into(),
            rule_type: "atomic".into(),
            mitre: Some("T1059.001 - PowerShell".into()),
            ts: 20,
            event_count: 2,
            group_key: None,
            description: "encoded powershell".into(),
            event_ids: vec![1, 2],
        })
        .unwrap();
    AppState::new(g)
}

#[tokio::test]
async fn alerts_list_and_detail_with_evidence() {
    let app = router(state_with_alert());

    let (status, json) = get_json(&app, "/api/alerts").await;
    assert_eq!(status, StatusCode::OK);
    let arr = json.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["rule_id"], "A_PS");
    assert_eq!(arr[0]["event_count"], 2);

    // Detail hydrates the contributing events (the evidence view).
    let (status, json) = get_json(&app, "/api/alerts/A_PS:-:20").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["alert"]["rule_id"], "A_PS");
    assert_eq!(json["events"].as_array().unwrap().len(), 2);

    // Unknown alert → 404.
    let (status, _) = get_json(&app, "/api/alerts/nope").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn stats_includes_alert_count() {
    let app = router(state_with_alert());
    let (status, json) = get_json(&app, "/api/stats").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["alerts"], 1);
}

#[tokio::test]
async fn pagerank_ranks_nodes() {
    let app = router(state());
    let (status, json) = get_json(&app, "/api/analytics/pagerank?limit=10").await;
    assert_eq!(status, StatusCode::OK);
    let arr = json.as_array().unwrap();
    assert!(!arr.is_empty());
    // Scores are present and descending.
    let scores: Vec<f64> = arr.iter().map(|s| s["score"].as_f64().unwrap()).collect();
    assert!(scores.windows(2).all(|w| w[0] >= w[1]), "sorted desc");
}

#[tokio::test]
async fn attack_paths_between_processes() {
    let app = router(state());
    // explorer(100) -> cmd(200) via a single SPAWNED edge, time-respecting.
    let uri = format!(
        "/api/graph/attack-paths?src={}&dst={}&k=3",
        proc_id(100, 10).raw(),
        proc_id(200, 20).raw()
    );
    let (status, json) = get_json(&app, &uri).await;
    assert_eq!(status, StatusCode::OK);
    let arr = json.as_array().unwrap();
    assert!(!arr.is_empty());
    assert_eq!(arr[0]["rank"], 1);
    assert_eq!(arr[0]["etypes"][0], "SPAWNED");
    assert!(arr[0]["graph"]["nodes"].is_array());
}
