// Right rail: full detail for the selected node — kind, risk, validity, props —
// plus the "evidence" list of source events around its lifetime, and pivot
// actions (expand, set as root, find path). (PLAN.md §11.)

import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../api/client";
import { useAppStore } from "../store/useAppStore";
import { kindStyle, ocsfClassName } from "../lib/kinds";
import { fmtDuration, fmtTime } from "../lib/format";
import type { NodeDetail } from "../api/types";

/** Best-effort host string for the host-scoped events query. */
function hostFor(d: NodeDetail): string | null {
  if (d.kind === "host") return d.label;
  if (d.kind === "process" || d.kind === "file" || d.kind === "logon_session") {
    // identity keys are `host:...` (see identity.rs).
    const seg = d.identity_key.split(":")[0];
    return seg || null;
  }
  return null;
}

export default function DetailPanel() {
  const selectedId = useAppStore((s) => s.selectedId);
  const expand = useAppStore((s) => s.expand);
  const pivotTo = useAppStore((s) => s.pivotTo);
  const loadPath = useAppStore((s) => s.loadPath);
  const runAttackPaths = useAppStore((s) => s.runAttackPaths);
  const [pathSrc, setPathSrc] = useState<{ id: string; label: string } | null>(null);

  const detail = useQuery({
    queryKey: ["node", selectedId],
    queryFn: () => api.node(selectedId as string),
    enabled: !!selectedId,
  });

  if (!selectedId) {
    return (
      <aside className="panel right-panel">
        <div className="panel-section muted small">
          Select a node to see its detail and evidence.
        </div>
      </aside>
    );
  }

  const d = detail.data;

  return (
    <aside className="panel right-panel">
      {detail.isLoading && <div className="panel-section muted small">loading…</div>}
      {detail.isError && <div className="panel-section error small">failed to load node</div>}
      {d && (
        <>
          <div className="panel-section">
            <div className="detail-head">
              <span className="kind-dot lg" style={{ background: kindStyle(d.kind).color }} />
              <div>
                <div className="detail-title">{d.label}</div>
                <div className="muted small">{kindStyle(d.kind).label}</div>
              </div>
            </div>

            <div className="stat-grid">
              <div className="stat">
                <div className="stat-num">{d.risk_score.toFixed(0)}</div>
                <div className="stat-lbl">risk</div>
              </div>
              <div className="stat">
                <div className="stat-num">{d.validity.event_count}</div>
                <div className="stat-lbl">events</div>
              </div>
              <div className="stat">
                <div className="stat-num">
                  {fmtDuration(d.validity.last_seen - d.validity.first_seen)}
                </div>
                <div className="stat-lbl">lifetime</div>
              </div>
            </div>

            <dl className="kv">
              <dt>first seen</dt>
              <dd>{fmtTime(d.validity.first_seen)}</dd>
              <dt>last seen</dt>
              <dd>{fmtTime(d.validity.last_seen)}</dd>
              <dt>identity</dt>
              <dd className="mono ellip" title={d.identity_key}>
                {d.identity_key}
              </dd>
            </dl>

            <div className="btn-row">
              <button className="btn" onClick={() => void expand(selectedId)}>
                Expand
              </button>
              <button className="btn" onClick={() => void pivotTo(selectedId)}>
                Focus
              </button>
              {pathSrc && pathSrc.id !== selectedId ? (
                <>
                  <button
                    className="btn"
                    onClick={() => void loadPath(pathSrc.id, selectedId)}
                    title={`Shortest path from ${pathSrc.label}`}
                  >
                    Path from {pathSrc.label}
                  </button>
                  <button
                    className="btn accent"
                    onClick={() => void runAttackPaths(pathSrc.id, selectedId)}
                    title={`Ranked attack paths from ${pathSrc.label}`}
                  >
                    ⚔ Attack path
                  </button>
                </>
              ) : (
                <button
                  className="btn"
                  onClick={() => setPathSrc({ id: selectedId, label: d.label })}
                >
                  Mark path start
                </button>
              )}
            </div>
          </div>

          <AttackPaths />

          {Object.keys(d.props).length > 0 && (
            <div className="panel-section">
              <div className="field-label">Properties</div>
              <dl className="kv">
                {Object.entries(d.props).map(([k, v]) => (
                  <div key={k} style={{ display: "contents" }}>
                    <dt>{k}</dt>
                    <dd className="mono ellip" title={v}>
                      {v}
                    </dd>
                  </div>
                ))}
              </dl>
            </div>
          )}

          <Related nodeId={selectedId} />
          <Evidence detail={d} />
        </>
      )}
    </aside>
  );
}

/**
 * The entity view (PLAN.md §11, M8): the selected node's one-hop relationships
 * grouped by kind — a host's users/processes/connections/files/alerts, a user's
 * hosts/sessions, etc. Every related entity is a click-to-pivot.
 */
function Related({ nodeId }: { nodeId: string }) {
  const window = useAppStore((s) => s.window);
  const pivotTo = useAppStore((s) => s.pivotTo);

  const rel = useQuery({
    queryKey: ["related", nodeId, window?.from, window?.to],
    queryFn: () => api.neighbors(nodeId, { hops: 1, window }),
    enabled: !!nodeId,
  });

  const groups = new Map<string, { id: string; label: string }[]>();
  for (const n of rel.data?.nodes ?? []) {
    if (n.data.id === nodeId) continue;
    const ks = kindStyle(n.data.kind);
    if (!groups.has(ks.label)) groups.set(ks.label, []);
    groups.get(ks.label)!.push({ id: n.data.id, label: n.data.label });
  }

  if (rel.isFetching) {
    return <div className="panel-section muted small">loading relationships…</div>;
  }
  if (groups.size === 0) return null;

  return (
    <div className="panel-section">
      <div className="field-label">Related entities</div>
      {[...groups.entries()].map(([kind, members]) => (
        <div key={kind} className="rel-group">
          <div className="rel-kind">
            {kind} <span className="muted">· {members.length}</span>
          </div>
          <div className="rel-members">
            {members.slice(0, 12).map((m) => (
              <button
                key={m.id}
                className="rel-chip"
                onClick={() => void pivotTo(m.id)}
                title={m.label}
              >
                {m.label}
              </button>
            ))}
            {members.length > 12 && (
              <span className="muted small">+{members.length - 12} more</span>
            )}
          </div>
        </div>
      ))}
    </div>
  );
}

/** Ranked, time-respecting attack paths (PLAN.md §6, M7). */
function AttackPaths() {
  const attackPaths = useAppStore((s) => s.attackPaths);
  const highlightPath = useAppStore((s) => s.highlightPath);
  const highlightEdges = useAppStore((s) => s.highlightEdges);
  const clearAttackPaths = useAppStore((s) => s.clearAttackPaths);

  if (!attackPaths) return null;

  return (
    <div className="panel-section">
      <div className="field-label">
        Attack paths <span className="muted">· ranked</span>
        <button className="btn tiny" style={{ float: "right" }} onClick={clearAttackPaths}>
          clear
        </button>
      </div>
      {attackPaths.length === 0 && <div className="muted small">no path found</div>}
      <div className="path-list">
        {attackPaths.map((p) => {
          const active = p.graph.edges.some((e) => highlightEdges.has(e.data.id));
          return (
            <button
              key={p.rank}
              className={`path-row ${active ? "active" : ""}`}
              onClick={() => highlightPath(p.rank)}
            >
              <div className="path-top">
                <span className="path-rank">#{p.rank}</span>
                <span className="muted small">
                  {p.length} hop{p.length === 1 ? "" : "s"} · cost {p.cost.toFixed(2)}
                </span>
              </div>
              <div className="path-chain small">{p.etypes.join(" → ")}</div>
              {p.mitre.length > 0 && (
                <div className="mitre-tags">
                  {p.mitre.map((m) => (
                    <span key={m} className="mitre-tag">
                      {m}
                    </span>
                  ))}
                </div>
              )}
            </button>
          );
        })}
      </div>
    </div>
  );
}

function Evidence({ detail }: { detail: NodeDetail }) {
  const host = hostFor(detail);
  const mid = Math.round((detail.validity.first_seen + detail.validity.last_seen) / 2);
  const span = detail.validity.last_seen - detail.validity.first_seen;
  const window = Math.max(300_000, Math.ceil(span / 2) + 60_000);

  const events = useQuery({
    queryKey: ["evidence", host, mid, window],
    queryFn: () => api.events(host as string, mid, window),
    enabled: !!host,
  });

  if (!host) {
    return (
      <div className="panel-section muted small">
        No host-scoped evidence available for this entity kind.
      </div>
    );
  }

  return (
    <div className="panel-section evidence">
      <div className="field-label">
        Evidence <span className="muted">· {host}</span>
      </div>
      {events.isFetching && <div className="muted small">loading events…</div>}
      {events.data && events.data.length === 0 && (
        <div className="muted small">no events in window</div>
      )}
      <ul className="event-list">
        {events.data?.map((e) => (
          <li key={e.event_id} className="event-row">
            <div className="event-top">
              <span className="event-class">{ocsfClassName(e.class_uid)}</span>
              {e.event_code != null && <span className="event-code">#{e.event_code}</span>}
              <span className="event-ts">{fmtTime(e.ts)}</span>
            </div>
            <div className="event-sub muted small">
              {[e.user_name, e.process_name, e.src_ip, e.dst_ip].filter(Boolean).join(" · ") ||
                "—"}
            </div>
          </li>
        ))}
      </ul>
    </div>
  );
}
