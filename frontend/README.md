# LogHound Frontend

The investigation UI for LogHound — a temporal knowledge-graph explorer built on
**React + TypeScript + Vite** with **Cytoscape.js** for the graph canvas.

## What it does

- **Search → pivot**: find a user / host / IP / process / file and click it to
  seed the graph.
- **Pivot & expand**: click a node to select it (drives the detail panel),
  double-click or right-click to expand its neighborhood — BloodHound-style
  progressive exploration.
- **Detail + evidence + entity view**: the right rail shows a node's kind, risk,
  validity interval, properties, the source **events** around its lifetime, and
  its **related entities** grouped by kind (a host's users/processes/connections,
  a user's hosts/sessions, …) — every one click-to-pivot.
- **Views** (center tabs): **Graph** (Cytoscape investigation graph),
  **Process Tree** (React Flow lineage rooted at the selected host/process via
  STARTED/SPAWNED), and **Attack Path** (React Flow ordered chain of the ranked
  time-respecting route with MITRE tags).
- **Risk overlay**: node size scales with the composite risk score
  (PageRank + alert-proximity); alerts render as red stars.
- **Attack paths**: mark a start node, select a target, run **⚔ Attack path** to
  get ranked, time-respecting chains (cost + technique + MITRE); click a rank to
  highlight it on the graph and open it in the Attack Path view.
- **Time rewind**: the bottom scrubber spans the loaded graph's temporal extent
  with an event histogram; dragging its two handles re-queries the graph
  *within that window* and re-renders it as it existed then. All views share the
  window and the current selection.
- **Filters**: toggle node kinds and relationship types; choose the layout
  (force / tree / concentric) and hop depth.

## Layout

```
src/
  api/         types.ts (DTO mirrors) · client.ts (typed fetch wrapper)
  store/       useAppStore.ts (Zustand: graph, seeds, window, filters)
  components/  Toolbar · SearchPanel · GraphView · DetailPanel · TimeScrubber
  lib/         cytoStyle.ts · kinds.ts · format.ts · useDebounce.ts
```

The graph is always the union of each *seed* node's k-hop neighborhood **within
the current time window**, so re-running the query on a window change
reconstructs the graph for that instant.

## Develop

```sh
npm install
npm run dev            # Vite dev server on :5173, proxies /api → :8080
```

Point the proxy at a different API with `LOGHOUND_API=http://host:port npm run dev`.
Run the Rust API separately (from the repo root):

```sh
loghound ingest <logfile> loghound.duckdb
loghound serve loghound.duckdb 127.0.0.1:8080
```

## Build & serve from the Rust binary

```sh
npm run build          # → frontend/dist
loghound serve loghound.duckdb 127.0.0.1:8080
# open http://127.0.0.1:8080/  (the API auto-serves frontend/dist)
```

`loghound serve` detects `frontend/dist/index.html` relative to the working
directory and serves the built assets, falling back to `index.html` for
client-side routing. All requests under `/api` go to the REST API.

> Note: if your system `npm` is broken (some distros ship an npm missing its own
> deps), invoke the one bundled with your Node install directly, e.g.
> `node "$(dirname "$(command -v node)")/../lib/node_modules/npm/bin/npm-cli.js" install`.
