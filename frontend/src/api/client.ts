// Typed fetch wrapper over the LogHound REST API (PLAN.md §10). All calls are
// relative to /api so the same code works behind the Vite dev proxy and when the
// Rust server hosts the built assets directly.

import type {
  AlertRecord,
  AttackPathDto,
  CyGraph,
  CyNodeData,
  Direction,
  EventSummary,
  NodeDetail,
  ScoreDto,
  Stats,
  TimelineBucket,
} from "./types";

/** An alert plus its hydrated contributing events (/api/alerts/:id). */
export interface AlertDetail {
  alert: AlertRecord;
  events: EventSummary[];
}

/** A time window applied to graph/timeline queries — the "rewind" filter. */
export interface TimeWindow {
  from: number;
  to: number;
}

async function getJson<T>(path: string): Promise<T> {
  const res = await fetch(path, { headers: { Accept: "application/json" } });
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new ApiError(res.status, body || res.statusText, path);
  }
  return (await res.json()) as T;
}

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
    public path: string,
  ) {
    super(`${status} ${message} (${path})`);
    this.name = "ApiError";
  }
}

function windowParams(win?: TimeWindow | null): string {
  if (!win) return "";
  return `&from=${win.from}&to=${win.to}`;
}

export const api = {
  stats: () => getJson<Stats>("/api/stats"),

  search: (q: string, kind?: string, limit = 50) => {
    const params = new URLSearchParams({ q, limit: String(limit) });
    if (kind) params.set("kind", kind);
    return getJson<CyNodeData[]>(`/api/search?${params.toString()}`);
  },

  node: (id: string) => getJson<NodeDetail>(`/api/nodes/${encodeURIComponent(id)}`),

  neighbors: (
    id: string,
    opts: {
      hops?: number;
      etypes?: string[];
      dir?: Direction;
      window?: TimeWindow | null;
    } = {},
  ) => {
    const params = new URLSearchParams({ hops: String(opts.hops ?? 1) });
    if (opts.etypes && opts.etypes.length) params.set("etypes", opts.etypes.join(","));
    if (opts.dir) params.set("dir", opts.dir);
    return getJson<CyGraph>(
      `/api/nodes/${encodeURIComponent(id)}/neighbors?${params.toString()}${windowParams(
        opts.window,
      )}`,
    );
  },

  path: (src: string, dst: string, window?: TimeWindow | null) => {
    const params = new URLSearchParams({ src, dst });
    return getJson<CyGraph>(`/api/graph/path?${params.toString()}${windowParams(window)}`);
  },

  timeline: (opts: { host?: string; window?: TimeWindow | null; bucket?: number } = {}) => {
    const params = new URLSearchParams();
    if (opts.host) params.set("host", opts.host);
    if (opts.window) {
      params.set("from", String(opts.window.from));
      params.set("to", String(opts.window.to));
    }
    if (opts.bucket) params.set("bucket", String(opts.bucket));
    const qs = params.toString();
    return getJson<TimelineBucket[]>(`/api/timeline${qs ? `?${qs}` : ""}`);
  },

  events: (host: string, ts: number, window = 300_000) => {
    const params = new URLSearchParams({
      host,
      ts: String(ts),
      window: String(window),
    });
    return getJson<EventSummary[]>(`/api/events?${params.toString()}`);
  },

  event: (id: number) => getJson<EventSummary>(`/api/events/${id}`),

  alerts: (limit = 200) => getJson<AlertRecord[]>(`/api/alerts?limit=${limit}`),

  alert: (id: string) => getJson<AlertDetail>(`/api/alerts/${encodeURIComponent(id)}`),

  pagerank: (limit = 50) => getJson<ScoreDto[]>(`/api/analytics/pagerank?limit=${limit}`),

  topRisk: (limit = 10) => getJson<ScoreDto[]>(`/api/analytics/risk?limit=${limit}`),

  attackPaths: (src: string, dst: string, k = 3) =>
    getJson<AttackPathDto[]>(
      `/api/graph/attack-paths?src=${encodeURIComponent(src)}&dst=${encodeURIComponent(
        dst,
      )}&k=${k}`,
    ),
};
