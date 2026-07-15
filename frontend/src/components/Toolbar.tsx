// Top bar: brand, corpus stats, graph controls (hops, layout, fit, clear) and a
// live status/error indicator.

import { useQuery } from "@tanstack/react-query";
import { api } from "../api/client";
import { useAppStore } from "../store/useAppStore";

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
        <span className="brand-mark">🐾</span>
        <span className="brand-name">LogHound</span>
        <span className="brand-sub">temporal investigation graph</span>
      </div>

      <div className="toolbar-stats muted small">
        {stats.data && (
          <>
            <span>{stats.data.events.toLocaleString()} events</span>
            <span>{stats.data.nodes.toLocaleString()} nodes</span>
            <span>{stats.data.edges.toLocaleString()} edges</span>
            {stats.data.alerts > 0 && (
              <span className="alert-count">{stats.data.alerts.toLocaleString()} alerts</span>
            )}
          </>
        )}
        <span className="sep">|</span>
        <span>
          showing {nodeCount} / {edgeCount}
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
            <option value="breadthfirst">tree</option>
            <option value="concentric">concentric</option>
          </select>
        </label>
        <button className="btn" onClick={() => void loadOverview()} title="Load the highest-risk entities">
          Overview
        </button>
        <button className="btn" onClick={onFit}>
          Fit
        </button>
        <button className="btn" onClick={clear}>
          Clear
        </button>
        {loading && <span className="spinner" title="loading" />}
        {error && (
          <span className="error small" title={error}>
            ⚠ error
          </span>
        )}
      </div>
    </header>
  );
}
