# LogHound

An investigator-centric **temporal knowledge-graph** platform for Windows
security telemetry — BloodHound's pivot-and-expand investigation experience,
but the graph is real runtime activity reconstructed from logs rather than
Active Directory enumeration.

## What it does

LogHound ingests Windows security telemetry (Windows Event XML plus
network, process, and file-integrity logs in the OPLC format), normalizes it
to [OCSF](https://schema.ocsf.io/), and reconstructs a time-aware graph of
hosts, users, processes, logon sessions, network connections, and files.

Every node and edge carries a `first_seen` / `last_seen` / `event_count`
**validity interval**, so the graph can be *rewound* to any instant or time
window during an investigation.

On top of the graph, LogHound provides:

- **Detection engine** — atomic, threshold, and sequence rules (36 MITRE
  ATT&CK-tagged rules included) plus Sigma rule support.
- **Risk scoring** — composite scores from PageRank centrality and alert
  proximity.
- **Attack-path inference** — ranked, time-respecting attack chains between
  any two entities, annotated with MITRE techniques.
- **Interactive web UI** — search, pivot-and-expand graph exploration,
  process trees, attack-path views, and a time-rewind scrubber.

**Pipeline:** parse → normalize → correlate → persist (DuckDB) → detect → analyze → serve.

No external graph database is required: storage is an embedded DuckDB file
plus a lock-free in-memory CSR index.

## Quick start

Prerequisites: Rust (stable), Node.js 18+, Python 3.8+ (sample-data generator only).

```bash
# 1. Build the backend
cargo build --release

# 2. Generate a 50k-event sample corpus with embedded attack scenarios
python3 scripts/gen_sample_logs.py 50000 sample_logs_50k.log

# 3. Ingest it into a DuckDB database
./target/release/loghound ingest sample_logs_50k.log loghound.duckdb config/mappings.yaml

# 4. Build the web UI
( cd frontend && npm install && npm run build )

# 5. Serve the API + UI
./target/release/loghound serve loghound.duckdb 127.0.0.1:8080
# open http://127.0.0.1:8080/
```

See **[USAGE.md](USAGE.md)** for complete build, run, and test instructions,
an API reference, a UI walkthrough, and troubleshooting.

## Architecture

- **Rust workspace** (`crates/`):
  - `loghound-core` — domain types (events, node/edge kinds, ids, time)
  - `loghound-parsers` — OPLC log parser (event / network / process / integrity)
  - `loghound-normalize` — OCSF normalization and enrichment
  - `loghound-correlate` — temporal graph builder (process trees, logon sessions, lateral movement)
  - `loghound-graph` — DuckDB store, CSR index, analytics (PageRank, risk, attack paths)
  - `loghound-detect` — filter DSL, rule engine, Sigma support
  - `loghound-api` — Axum REST API and static UI hosting
  - `loghound-cli` — the `loghound` binary
- **`frontend/`** — React + TypeScript + Vite, with Cytoscape.js (investigation
  graph) and React Flow (process tree / attack-path views)
- **`config/`** — `mappings.yaml` (OCSF field mappings), `rules.yaml` (detection rules)
- **`scripts/`** — `gen_sample_logs.py`, a realistic sample-corpus generator
