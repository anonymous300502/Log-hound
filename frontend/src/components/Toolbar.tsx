// Top bar: brand, corpus stats, graph controls (hops, layout, fit, clear) and a
// live status/error indicator.

import { useQuery } from "@tanstack/react-query";
import { api } from "../api/client";
import { useAppStore } from "../store/useAppStore";
import { AlertTriangleIcon, LogHoundLogo } from "./Icons";

interface Props {
  layoutName: string;
  onLayout: (name: string) => void;
  onFit: () => void;
}

export default function Toolbar({ layoutName, onLayout, onFit }: Props) {
  const stats = useQuery({ queryKey: ["stats"], queryFn: api.stats });
  const hops = useAppStore((s) => s.hops);
  const setHops = useAppStore((s) => s.setHops);
  const clear = useAppStore((s) => s.clear);
  const loadOverview = useAppStore((s) => s.loadOverview);
  const loading = useAppStore((s) => s.loading);
  const error = useAppStore((s) => s.error);
  const nodeCount = useAppStore((s) => Object.keys(s.nodes).length);
  const edgeCount = useAppStore((s) => Object.keys(s.edges).length);

  return (
    <header className="toolbar">
      <div className="brand">
        <span className="brand-badge">
          <LogHoundLogo className="brand-icon" />
        </span>
        <div className="brand-text">
          <span className="brand-name">LogHound</span>
          <span className="brand-sub">Temporal Knowledge Graph</span>
        </div>
      </div>

      <div className="toolbar-stats muted small">
        <span className="status-indicator" title="Connected to DuckDB store">
          <span className="status-dot live" />
          <span className="status-text">ONLINE</span>
        </span>
        <span className="sep">|</span>
        {stats.data && (
          <>
            <span className="stat-pill">{stats.data.events.toLocaleString()} events</span>
            <span className="stat-pill">{stats.data.nodes.toLocaleString()} nodes</span>
            <span className="stat-pill">{stats.data.edges.toLocaleString()} edges</span>
            {stats.data.alerts > 0 && (
              <span className="alert-count-pill">{stats.data.alerts.toLocaleString()} alerts</span>
            )}
          </>
        )}
        <span className="sep">|</span>
        <span className="canvas-count">
          visible: {nodeCount} nodes / {edgeCount} edges
        </span>
      </div>

      <div className="toolbar-controls">
        <label className="ctl">
          hops
          <select value={hops} onChange={(e) => void setHops(Number(e.target.value))}>
            {[1, 2, 3].map((h) => (
              <option key={h} value={h}>
                {h}
              </option>
            ))}
          </select>
        </label>
        <label className="ctl">
          layout
          <select value={layoutName} onChange={(e) => onLayout(e.target.value)}>
            <option value="cose">force</option>
            <option value="concentric">concentric</option>
            <option value="breadthfirst">tree</option>
          </select>
        </label>
        <button className="btn" onClick={() => void loadOverview()} title="Load highest-risk or initial pivot entity">
          Overview
        </button>
        <button className="btn" onClick={onFit} title="Center and fit graph in viewport">
          Fit
        </button>
        <button className="btn" onClick={clear} title="Clear graph canvas">
          Clear
        </button>
        {loading && <span className="spinner" title="loading graph telemetry" />}
        {error && (
          <span className="error-pill small" title={error}>
            <AlertTriangleIcon className="icon-inline" /> error
          </span>
        )}
      </div>
    </header>
  );
}
