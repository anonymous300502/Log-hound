// Left rail: global entity search, plus filters (kind legend + edge-type
// toggles) and a legend. Clicking a search result pivots the graph to that
// entity (PLAN.md §11).

import { useEffect, useMemo, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../api/client";
import { useAppStore } from "../store/useAppStore";
import { useDebounce } from "../lib/useDebounce";
import { KIND_STYLES, kindStyle } from "../lib/kinds";
import type { EdgeType, NodeKind } from "../api/types";
import { CloseIcon, SearchIcon } from "./Icons";

const KIND_FILTERS: { id: string; label: string }[] = [
  { id: "all", label: "All" },
  { id: "host", label: "Hosts" },
  { id: "user", label: "Users" },
  { id: "process", label: "Processes" },
  { id: "ip_address", label: "IPs" },
];

export default function SearchPanel() {
  const [q, setQ] = useState("");
  const [kindFilter, setKindFilter] = useState("all");
  const inputRef = useRef<HTMLInputElement>(null);
  const debounced = useDebounce(q, 200);
  const pivotTo = useAppStore((s) => s.pivotTo);
  const selectedId = useAppStore((s) => s.selectedId);

  // Global '/' keyboard shortcut to focus search
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "/" && document.activeElement !== inputRef.current) {
        e.preventDefault();
        inputRef.current?.focus();
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, []);

  const search = useQuery({
    queryKey: ["search", debounced, kindFilter],
    queryFn: () => api.search(debounced, kindFilter === "all" ? undefined : kindFilter, 50),
    enabled: debounced.trim().length >= 2,
  });

  return (
    <aside className="panel left-panel">
      <div className="panel-section">
        <div className="search-header-row">
          <label className="field-label">Search entities</label>
          <span className="kbd-hint">/</span>
        </div>

        <div className="search-input-wrap">
          <SearchIcon className="search-input-icon" />
          <input
            ref={inputRef}
            className="text-input search-input"
            placeholder="Search host, user, process, IP..."
            value={q}
            onChange={(e) => setQ(e.target.value)}
            autoFocus
          />
          {q.length > 0 && (
            <button
              className="search-clear-btn"
              onClick={() => {
                setQ("");
                inputRef.current?.focus();
              }}
              title="Clear search"
            >
              <CloseIcon className="icon-xs" />
            </button>
          )}
        </div>

        <div className="kind-filter-tabs">
          {KIND_FILTERS.map((f) => (
            <button
              key={f.id}
              className={`kind-tab ${kindFilter === f.id ? "active" : ""}`}
              onClick={() => setKindFilter(f.id)}
            >
              {f.label}
            </button>
          ))}
        </div>

        {debounced.trim().length >= 2 && (
          <div className="search-results">
            <div className="search-results-header">
              {search.isFetching ? (
                <span className="muted small">Searching...</span>
              ) : search.isError ? (
                <span className="error small">Search failed</span>
              ) : search.data ? (
                <span className="muted small">{search.data.length} match{search.data.length === 1 ? "" : "es"}</span>
              ) : null}
            </div>

            {search.data && search.data.length === 0 && (
              <div className="muted small text-center py-2">No matching entities found</div>
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
