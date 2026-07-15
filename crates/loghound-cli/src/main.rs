//! LogHound CLI entry point.
//!
//! `M0` provides two subcommands to prove the workspace wires together and that
//! the backwards-compatible configuration loads:
//!
//! ```text
//! loghound version
//! loghound check-config [<mappings.yaml> <rules.yaml>]
//! loghound parse <logfile> [<mappings.yaml>]
//! ```
//!
//! A full `clap`-based CLI (ingest/serve/export) grows here as later milestones
//! land (`PLAN.md` §16).

use std::collections::{BTreeMap, HashMap};
use std::fs::File;
use std::io::BufReader;
use std::net::SocketAddr;
use std::process::ExitCode;

use anyhow::{Context, Result};
use loghound_api::{router, serve, with_static, AppState};
use loghound_core::{Event, EventId};
use loghound_correlate::Correlator;
use loghound_detect::{build_alert_graph, dedup_alerts, Engine, RuleSet};
use loghound_graph::{AlertRecord, Graph, Table};
use loghound_normalize::{MappingConfig, Normalizer};
use loghound_parsers::{parse_reader, OplcParser};

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = args.first().map(String::as_str).unwrap_or("help");

    let result = match cmd {
        "version" | "--version" | "-V" => {
            println!("loghound {VERSION}");
            Ok(())
        }
        "check-config" => check_config(args.get(1), args.get(2)),
        "parse" => parse_logs(args.get(1), args.get(2)),
        "ingest" => ingest_logs(args.get(1), args.get(2), args.get(3)),
        "serve" => serve_cmd(args.get(1), args.get(2)),
        "help" | "--help" | "-h" => {
            print_help();
            Ok(())
        }
        other => {
            eprintln!("unknown command: {other}\n");
            print_help();
            return ExitCode::from(2);
        }
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn print_help() {
    println!(
        "LogHound {VERSION} — temporal knowledge-graph investigation platform\n\n\
         USAGE:\n  \
           loghound version\n  \
           loghound check-config [<mappings.yaml> <rules.yaml>]\n  \
           loghound parse <logfile> [<mappings.yaml>]\n  \
           loghound ingest <logfile> [<db.duckdb> <mappings.yaml>]\n  \
           loghound serve [<db.duckdb> <addr>]\n\n\
         More commands (export) arrive in later milestones."
    );
}

/// Serve the REST API over an existing graph store (`PLAN.md` §10, M4). Cold-loads
/// the CSR index from DuckDB, then runs the Axum server.
fn serve_cmd(db: Option<&String>, addr: Option<&String>) -> Result<()> {
    let db_path = db.map(String::as_str).unwrap_or("loghound.duckdb");
    let addr: SocketAddr = addr
        .map(String::as_str)
        .unwrap_or("127.0.0.1:8080")
        .parse()
        .context("parsing listen address")?;

    let graph = Graph::open(db_path).with_context(|| format!("opening store {db_path}"))?;
    graph.refresh_index()?; // cold-load the CSR snapshot from DuckDB
    let stats = graph.store().stats()?;
    println!("LogHound serving {db_path} on http://{addr}");
    println!(
        "  graph: {} nodes, {} edges, {} events",
        stats.nodes, stats.edges, stats.events
    );

    // Serve the built UI too, if it exists next to the working directory.
    let state = AppState::new(graph);
    let mut app = router(state);
    let dist = std::path::Path::new("frontend/dist");
    if dist.join("index.html").exists() {
        app = with_static(app, dist);
        println!("  UI:  http://{addr}/  (serving {})", dist.display());
    } else {
        println!("  API only — build the UI with `npm --prefix frontend run build` to enable http://{addr}/");
    }
    println!("  try: curl http://{addr}/api/stats");

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("building tokio runtime")?;
    rt.block_on(serve(addr, app)).context("server error")?;
    Ok(())
}

/// Ingest an OPLC log file into a DuckDB-backed graph: parse → normalize →
/// persist events → correlate into temporal nodes/edges → publish the graph
/// (`PLAN.md` §7, §8; M2–M3).
fn ingest_logs(
    logfile: Option<&String>,
    db: Option<&String>,
    mappings: Option<&String>,
) -> Result<()> {
    let logfile = logfile.ok_or_else(|| {
        anyhow::anyhow!("usage: loghound ingest <logfile> [<db.duckdb> <mappings.yaml>]")
    })?;
    let db_path = db.map(String::as_str).unwrap_or("loghound.duckdb");
    let mappings_path = mappings
        .map(String::as_str)
        .unwrap_or("config/mappings.yaml");

    let normalizer = Normalizer::new(
        MappingConfig::from_path(mappings_path)
            .with_context(|| format!("loading mappings from {mappings_path}"))?,
    );
    let graph = Graph::open(db_path).with_context(|| format!("opening store {db_path}"))?;
    let file = File::open(logfile).with_context(|| format!("opening {logfile}"))?;
    let parser = OplcParser::new();

    let batch = 1u64;
    let mut next_id = graph.store().count(Table::Events)? + 1; // continue after existing rows
    let (mut ok, mut errors) = (0usize, 0usize);
    let mut by_class: BTreeMap<u32, usize> = BTreeMap::new();
    // NOTE: M3 buffers events for two-pass correlation. Streaming correlation for
    // 10M-scale corpora is an M9 optimization (PLAN.md §12).
    let mut events: Vec<Event> = Vec::new();

    for result in parse_reader(&parser, BufReader::new(file)) {
        match result {
            Ok(rec) => {
                let mut ev = normalizer.normalize(&rec);
                ev.event_id = EventId::new(next_id);
                next_id += 1;
                graph.append_event(&ev, batch)?;
                *by_class.entry(ev.class_uid).or_default() += 1;
                events.push(ev);
                ok += 1;
            }
            Err(_) => errors += 1,
        }
    }

    // Correlate the batch into temporal nodes/edges and publish the graph.
    let mut correlator = Correlator::new();
    correlator.correlate_batch(&events);
    let (nodes, edges) = correlator.finish();
    let mut by_kind: BTreeMap<&'static str, usize> = BTreeMap::new();
    for n in &nodes {
        *by_kind.entry(n.kind.name()).or_default() += 1;
    }
    let mut by_etype: BTreeMap<&'static str, usize> = BTreeMap::new();
    for e in &edges {
        *by_etype.entry(e.etype.name()).or_default() += 1;
    }
    graph.apply(&nodes, &edges)?;

    // Run the detection engine over the batch (M6, PLAN.md §9): compile the
    // rules, emit alerts, wire them into the graph (Alert nodes + TRIGGERED
    // edges) and persist the alert records.
    let rules_path = "config/rules.yaml";
    let alerts_persisted = run_detection(&graph, &events, rules_path)?;

    // Compute analytics + composite risk over the full graph (M7, PLAN.md §6),
    // persist the scores, and republish the CSR snapshot.
    graph.recompute_risk()?;

    graph.check_invariants()?;

    println!("Ingested {logfile} -> {db_path}");
    println!("  {ok} events persisted, {errors} lines skipped");
    println!(
        "  graph: {} nodes, {} edges, {} alerts (events table: {} rows)",
        graph.store().count(Table::Nodes)?,
        graph.store().count(Table::Edges)?,
        alerts_persisted,
        graph.store().count(Table::Events)?
    );
    println!("  events by OCSF class:");
    for (class, n) in &by_class {
        println!("    {class:<5} {:<20} {n}", ocsf_class_name(*class));
    }
    println!("  nodes by kind:");
    for (kind, n) in &by_kind {
        println!("    {kind:<16} {n}");
    }
    println!("  edges by type:");
    for (etype, n) in &by_etype {
        println!("    {etype:<18} {n}");
    }
    let top = graph.store().top_risk_nodes(8)?;
    if top.iter().any(|n| n.risk_score > 0.0) {
        println!("  highest-risk entities:");
        for n in top.iter().filter(|n| n.risk_score > 0.0) {
            println!(
                "    {:>5.1}  {:<16} {}",
                n.risk_score,
                n.kind.name(),
                n.label
            );
        }
    }
    Ok(())
}

/// Compile `rules.yaml`, run the detection engine over the ingested events, wire
/// the resulting alerts into the graph, and persist them. Returns the number of
/// alerts persisted. Missing/invalid rules degrade gracefully (0 alerts) so
/// ingest never fails on a detection problem.
fn run_detection(graph: &Graph, events: &[Event], rules_path: &str) -> Result<usize> {
    let set = match RuleSet::from_path(rules_path) {
        Ok(set) => set,
        Err(e) => {
            println!("  detection skipped: could not load {rules_path}: {e}");
            return Ok(0);
        }
    };
    let mut engine = match Engine::from_rules(&set) {
        Ok(e) => e,
        Err(e) => {
            println!("  detection skipped: rule compile error: {e}");
            return Ok(0);
        }
    };

    let alerts = dedup_alerts(engine.run(events));

    // Wire alerts into the temporal graph.
    let ev_map: HashMap<u64, &Event> = events.iter().map(|e| (e.event_id.raw(), e)).collect();
    let (anodes, aedges) = build_alert_graph(&alerts, &ev_map);
    graph.apply(&anodes, &aedges)?;

    // Persist alert records and summarize by severity + rule.
    let mut by_severity: BTreeMap<String, usize> = BTreeMap::new();
    let mut by_rule: BTreeMap<String, usize> = BTreeMap::new();
    for a in &alerts {
        graph.store().insert_alert(&AlertRecord {
            alert_id: a.alert_id.clone(),
            rule_id: a.rule_id.clone(),
            name: a.rule_name.clone(),
            severity: a.severity.clone(),
            rule_type: a.rule_type_name().to_string(),
            mitre: a.mitre.clone(),
            ts: a.ts,
            event_count: a.event_ids.len() as u64,
            group_key: a.group_key.clone(),
            description: a.description.clone(),
            event_ids: a.event_ids.clone(),
        })?;
        *by_severity.entry(a.severity.clone()).or_default() += 1;
        *by_rule.entry(a.rule_id.clone()).or_default() += 1;
    }

    println!(
        "  detection: {} rules evaluated, {} alerts",
        set.len(),
        alerts.len()
    );
    if !alerts.is_empty() {
        for (sev, n) in &by_severity {
            println!("    severity {sev:<9} {n}");
        }
        for (rule, n) in &by_rule {
            println!("    rule {rule:<8} x{n}");
        }
    }
    Ok(alerts.len())
}

/// Parse and normalize an OPLC log file end-to-end, printing a summary. This is
/// the M1 demonstration of the ingest→normalize pipeline (`PLAN.md` §7).
fn parse_logs(logfile: Option<&String>, mappings: Option<&String>) -> Result<()> {
    let logfile = logfile
        .ok_or_else(|| anyhow::anyhow!("usage: loghound parse <logfile> [<mappings.yaml>]"))?;
    let mappings_path = mappings
        .map(String::as_str)
        .unwrap_or("config/mappings.yaml");

    let normalizer = Normalizer::new(
        MappingConfig::from_path(mappings_path)
            .with_context(|| format!("loading mappings from {mappings_path}"))?,
    );
    let file = File::open(logfile).with_context(|| format!("opening {logfile}"))?;
    let parser = OplcParser::new();

    let mut by_kind: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut by_class: BTreeMap<u32, usize> = BTreeMap::new();
    let (mut ok, mut errors) = (0usize, 0usize);
    let mut first_errors: Vec<String> = Vec::new();

    for result in parse_reader(&parser, BufReader::new(file)) {
        match result {
            Ok(rec) => {
                *by_kind.entry(rec.kind.as_str()).or_default() += 1;
                let ev = normalizer.normalize(&rec);
                *by_class.entry(ev.class_uid).or_default() += 1;
                ok += 1;
            }
            Err(e) => {
                errors += 1;
                if first_errors.len() < 5 {
                    first_errors.push(e.to_string());
                }
            }
        }
    }

    println!("Parsed {logfile}: {ok} records, {errors} errors");
    println!("  by log type:");
    for (kind, n) in &by_kind {
        println!("    {kind:<10} {n}");
    }
    println!("  by OCSF class:");
    for (class, n) in &by_class {
        let name = ocsf_class_name(*class);
        println!("    {class:<5} {name:<20} {n}");
    }
    if !first_errors.is_empty() {
        println!("  first errors:");
        for e in &first_errors {
            println!("    {e}");
        }
    }
    Ok(())
}

fn ocsf_class_name(class: u32) -> &'static str {
    use loghound_core::event::class as c;
    match class {
        c::AUTHENTICATION => "Authentication",
        c::PROCESS_ACTIVITY => "Process Activity",
        c::ACCOUNT_CHANGE => "Account Change",
        c::NETWORK_ACTIVITY => "Network Activity",
        c::FILE_ACTIVITY => "File Activity",
        0 => "(generic/unmapped)",
        _ => "(other)",
    }
}

/// Load and summarize the mapping + rule configs, proving the backwards-compat
/// contract from a binary. Defaults to the workspace `config/` files.
fn check_config(mappings: Option<&String>, rules: Option<&String>) -> Result<()> {
    let mappings_path = mappings
        .map(String::as_str)
        .unwrap_or("config/mappings.yaml");
    let rules_path = rules.map(String::as_str).unwrap_or("config/rules.yaml");

    let mappings = MappingConfig::from_path(mappings_path)
        .with_context(|| format!("loading mappings from {mappings_path}"))?;
    let rules = RuleSet::from_path(rules_path)
        .with_context(|| format!("loading rules from {rules_path}"))?;

    println!("OK  {mappings_path}: {} event mappings", mappings.len());
    println!("OK  {rules_path}: {} detection rules", rules.len());
    Ok(())
}
