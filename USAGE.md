# LogHound — Build, Run & Test Guide

LogHound is a temporal knowledge-graph investigation platform: it ingests
Windows security telemetry (the OPLC log format), reconstructs a time-aware
graph of hosts, users, processes, logon sessions, connections, and files, runs
detection rules, scores risk, infers attack paths, and serves an interactive
investigation UI.

Pipeline: **parse → normalize → correlate → persist (DuckDB) → detect → analyze → serve**

---

## 1. Prerequisites

| Component | Requirement | Needed for |
|---|---|---|
| Rust | Stable toolchain (pinned via `rust-toolchain.toml`; [install with rustup](https://rustup.rs)) | Backend (required) |
| Node.js | 18 or newer, with `npm` | Web UI (optional) |
| Python | 3.8+ (standard library only) | Sample-log generator (optional) |

> **Note:** the first build compiles a bundled DuckDB (C++), which takes
> around 5 minutes and a few GB of RAM. This happens once; subsequent builds
> are fast.

---

## 2. Build the backend

From the repository root:

```bash
cargo build                  # debug build  -> target/debug/loghound
cargo build --release        # release build -> target/release/loghound
```

The **release** build is strongly recommended for real workloads — ingest is
orders of magnitude faster.

The default release profile enables LTO, which is memory-hungry and can be
OOM-killed on smaller machines. If that happens, disable LTO for the build:

```bash
CARGO_PROFILE_RELEASE_LTO=off CARGO_PROFILE_RELEASE_CODEGEN_UNITS=16 \
  cargo build --release
```

Everywhere below, `loghound` refers to `./target/release/loghound` (or
`./target/debug/loghound` for a debug build).

---

## 3. CLI reference

```bash
loghound version
loghound check-config [config/mappings.yaml config/rules.yaml]   # verify configs load
loghound parse   <logfile> [config/mappings.yaml]                # parse + normalize summary
loghound ingest  <logfile> [<db.duckdb> config/mappings.yaml]    # full pipeline -> DuckDB
loghound serve   [<db.duckdb> <addr>]                            # REST API + web UI
```

---

## 4. Generate a sample corpus

If you don't have OPLC logs at hand, generate a realistic corpus:

```bash
python3 scripts/gen_sample_logs.py 50000 sample_logs_50k.log
```

This writes a mix of all four log types (event, network, process, integrity)
across ~35 hosts and ~15 users, with embedded attack scenarios so the
detection engine has something to find:

| Scenario | Rule(s) triggered |
|---|---|
| 22 failed logons from one IP in ~60 s | `BF_01` / `BF_02` (brute force) |
| One account logging in from 7 IPs in 5 min | `AB_04` (account anomaly) |
| Recon burst (`systeminfo`, `whoami`, `ipconfig`, `netstat`) | `DS_03` (discovery) |
| `mimikatz.exe` executed | `CA_01` (credential dumping) |
| `powershell -enc …` | `EX_01` (encoded execution) |
| `psexec …` | `LM_03` (lateral movement) |
| Member added to Domain Admins | `PE_01` (privilege escalation) |

Any event count works, e.g. `python3 scripts/gen_sample_logs.py 200000 big.log`.

---

## 5. Ingest and serve

`ingest` is **additive** — it appends to an existing database. Start from a
clean database for a fresh run:

```bash
rm -f loghound.duckdb
./target/release/loghound ingest sample_logs_50k.log loghound.duckdb config/mappings.yaml
```

The ingest summary reports events persisted, node/edge/alert counts, events by
OCSF class, detection results by severity and rule, and the highest-risk
entities.

Then start the server:

```bash
./target/release/loghound serve loghound.duckdb 127.0.0.1:8080
# API:  http://127.0.0.1:8080/api/stats
# UI:   http://127.0.0.1:8080/   (requires a built frontend — see section 6)
```

---

## 6. Web UI

### Production: build once, served by the Rust binary

```bash
cd frontend
npm install
npm run build            # -> frontend/dist
cd ..
./target/release/loghound serve loghound.duckdb 127.0.0.1:8080
# open http://127.0.0.1:8080/
```

`loghound serve` auto-detects `frontend/dist` (relative to the working
directory) and serves it; everything under `/api` is the REST API.

### Development: hot reload

Run the API and the Vite dev server in two terminals:

```bash
# terminal 1
./target/release/loghound serve loghound.duckdb 127.0.0.1:8080

# terminal 2
cd frontend && npm run dev          # http://localhost:5173 (proxies /api -> :8080)
```

Point the proxy at a different API with `LOGHOUND_API=http://host:port npm run dev`.

### UI walkthrough

1. **Search** a host, user, or process in the left rail and click a result to
   seed the graph.
2. **Pivot & expand** — click a node to select it; double-click or right-click
   to expand its neighborhood.
3. **Detail panel** (right rail) — risk score, validity interval, properties,
   the **evidence** events behind the node, and **related entities** (click
   any to pivot).
4. **Views** (center tabs) — **Graph**, **Process Tree**, **Attack Path**.
5. **Attack paths** — on a node, click *Mark path start*, select another node,
   then **⚔ Attack path** to get ranked, time-respecting chains with MITRE
   technique tags.
6. **Time rewind** — drag the bottom scrubber handles to re-render the graph
   as it existed in that window. All views share the window and selection.
7. Node size reflects risk; alerts render as red stars. Search for e.g.
   `Brute` or `Credential` to jump to an alert and pivot to the entities it
   triggered on.

---

## 7. Run the tests

### Backend

```bash
cargo test --workspace                                   # all unit + integration tests
cargo test -p loghound-detect                            # a single crate
cargo fmt --all -- --check                               # formatting
cargo clippy --workspace --all-targets -- -D warnings    # lints
```

### Frontend

```bash
cd frontend
npm run typecheck        # tsc --noEmit
npm run build            # typecheck + production build
```

---

## 8. API reference

With the server running on `127.0.0.1:8080`:

```bash
BASE=http://127.0.0.1:8080

curl -s $BASE/api/stats                               # {events,nodes,edges,alerts}
curl -s "$BASE/api/search?q=DC01&kind=host"           # search nodes (kind optional)
curl -s "$BASE/api/nodes/<id>"                        # node detail
curl -s "$BASE/api/nodes/<id>/neighbors?hops=2&dir=out&etypes=SPAWNED,STARTED&from=<ms>&to=<ms>"
curl -s "$BASE/api/graph/path?src=<id>&dst=<id>"      # shortest path
curl -s "$BASE/api/graph/attack-paths?src=<id>&dst=<id>&k=3"   # ranked attack paths
curl -s "$BASE/api/timeline?bucket=3600000"           # event histogram
curl -s "$BASE/api/events?host=DC01.corp.local&ts=<ms>&window=300000"
curl -s $BASE/api/alerts                              # all alerts
curl -s "$BASE/api/alerts/<alert_id>"                 # alert + evidence events
curl -s "$BASE/api/analytics/pagerank?limit=10"       # centrality
curl -s $BASE/api/analytics/components                # connected components
```

Node ids are strings returned by `/api/search`. All time parameters
(`from`, `to`, `ts`) are epoch **milliseconds**.

---

## 9. Troubleshooting

| Symptom | Fix |
|---|---|
| `cargo build --release` killed (OOM) | Disable LTO: `CARGO_PROFILE_RELEASE_LTO=off CARGO_PROFILE_RELEASE_CODEGEN_UNITS=16 cargo build --release` |
| First `cargo build` seems stuck | It is compiling the bundled DuckDB (~5 min, one-time). |
| Ingest of a large corpus is slow | Use the **release** binary, or test with a smaller corpus first. |
| UI shows nothing at `/` | Build the frontend (`npm run build`) and run `serve` from the repo root so `frontend/dist` is found. |
| `serve` fails to bind | Port in use — pick another, e.g. `serve loghound.duckdb 127.0.0.1:8899`. |
| Re-ingest keeps growing the graph | `ingest` is additive — delete the `.duckdb` file first. |
| `npm` errors like `Cannot find module 'semver'` | Some distros ship a broken system npm; use the npm bundled with your Node install: `node "$(dirname "$(command -v node)")/../lib/node_modules/npm/bin/npm-cli.js" install` |

---

## 10. Repository layout

```
crates/
  loghound-core        domain types (Event, NodeKind, EdgeType, ids, time)
  loghound-parsers     OPLC parser (event / network / process / integrity log shapes)
  loghound-normalize   OCSF normalization + enrichment
  loghound-correlate   temporal graph builder (process trees, sessions, lateral movement)
  loghound-graph       DuckDB store + CSR index + analytics (PageRank / risk / attack paths)
  loghound-detect      filter DSL + rule engine (atomic/threshold/sequence) + Sigma
  loghound-api         Axum REST API (Cytoscape-shaped JSON) + static UI hosting
  loghound-cli         the `loghound` binary
config/                mappings.yaml (OCSF field maps) · rules.yaml (detection rules)
frontend/              React + TypeScript + Vite + Cytoscape.js + React Flow
scripts/               gen_sample_logs.py (sample corpus generator)
```
