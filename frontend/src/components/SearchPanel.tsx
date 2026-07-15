// Left rail: global entity search, plus filters (kind legend + edge-type
// toggles) and a legend. Clicking a search result pivots the graph to that
// entity (PLAN.md §11).

import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../api/client";
import { useAppStore } from "../store/useAppStore";
import { useDebounce } from "../lib/useDebounce";
import { KIND_STYLES, kindStyle } from "../lib/kinds";
import type { EdgeType, NodeKind } from "../api/types";

export default function SearchPanel() {
  const [q, setQ] = useState("");
  const debounced = useDebounce(q, 250);
  const pivotTo = useAppStore((s) => s.pivotTo);
  const selectedId = useAppStore((s) => s.selectedId);

  const search = useQuery({
    queryKey: ["search", debounced],
    queryFn: () => api.search(debounced, undefined, 50),
    enabled: debounced.trim().length >= 2,
  });

  return (
    <aside className="panel left-panel">
      <div className="panel-section">
        <label className="field-label">Search entities</label>
        <input
          className="text-input"
          placeholder="user, host, ip, process…"
          value={q}
          onChange={(e) => setQ(e.target.value)}
          autoFocus
        />
        {debounced.trim().length >= 2 && (
          <div className="search-results">
            {search.isFetching && <div className="muted small">searching…</div>}
            {search.isError && <div className="error small">search failed</div>}
            {search.data && search.data.length === 0 && (
              <div className="muted small">no matches</div>
            )}
            {search.data?.map((n) => {
              const ks = kindStyle(n.kind);
              return (
                <button
                  key={n.id}
                  className={`result-row ${selectedId === n.id ? "active" : ""}`}
                  onClick={() => void pivotTo(n.id)}
                  title={`${ks.label} · ${n.event_count} events`}
                >
                  <span className="kind-dot" style={{ background: ks.color }} />
                  <span className="result-label">{n.label}</span>
                  <span className="result-kind">{ks.label}</span>
                </button>
              );
            })}
          </div>
        )}
      </div>

      <EdgeFilters />
      <Legend />
    </aside>
  );
}

function EdgeFilters() {
  const edges = useAppStore((s) => s.edges);
  const hiddenEtypes = useAppStore((s) => s.hiddenEtypes);
  const toggleEtype = useAppStore((s) => s.toggleEtype);

  // Only show edge types actually present in the current graph.
  const present = useMemo(() => {
    const set = new Set<EdgeType>();
    for (const e of Object.values(edges)) set.add(e.etype);
    return [...set].sort();
  }, [edges]);

  if (present.length === 0) return null;

  return (
    <div className="panel-section">
      <div className="field-label">Relationships</div>
      <div className="chip-list">
        {present.map((et) => (
          <button
            key={et}
            className={`chip ${hiddenEtypes.has(et) ? "off" : "on"}`}
            onClick={() => toggleEtype(et)}
          >
            {et}
          </button>
        ))}
      </div>
    </div>
  );
}

function Legend() {
  const hiddenKinds = useAppStore((s) => s.hiddenKinds);
  const toggleKind = useAppStore((s) => s.toggleKind);
  const nodes = useAppStore((s) => s.nodes);

  // Only show kinds present, so the legend stays relevant to the investigation.
  const present = useMemo(() => {
    const set = new Set<NodeKind>();
    for (const n of Object.values(nodes)) set.add(n.kind);
    return (Object.keys(KIND_STYLES) as NodeKind[]).filter((k) => set.has(k));
  }, [nodes]);

  if (present.length === 0) {
    return (
      <div className="panel-section muted small">
        Search an entity and click a result to start.
      </div>
    );
  }

  return (
    <div className="panel-section">
      <div className="field-label">Node types</div>
      <div className="legend">
        {present.map((k) => (
          <button
            key={k}
            className={`legend-row ${hiddenKinds.has(k) ? "off" : ""}`}
            onClick={() => toggleKind(k)}
            title={hiddenKinds.has(k) ? "hidden — click to show" : "visible — click to hide"}
          >
            <span className="kind-dot" style={{ background: KIND_STYLES[k].color }} />
            {KIND_STYLES[k].label}
          </button>
        ))}
      </div>
    </div>
  );
}
