// Central investigation state (Zustand). Holds the merged graph, the set of
// "seed" nodes the investigator has pivoted to, the active time-rewind window,
// and view filters. The graph is always the union of each seed's k-hop
// neighborhood *within the current window* — so dragging the scrubber and
// re-running `refresh()` reconstructs the graph as it existed then (PLAN.md §11).

import { create } from "zustand";
import { api, ApiError, type TimeWindow } from "../api/client";
import type {
  AttackPathDto,
  CyEdgeData,
  CyGraph,
  CyNodeData,
  Direction,
  EdgeType,
  NodeKind,
} from "../api/types";

type NodeMap = Record<string, CyNodeData>;
type EdgeMap = Record<string, CyEdgeData>;

/** Which investigation view fills the center pane. */
export type ViewMode = "graph" | "tree" | "attack";

interface AppState {
  // ---- graph data ----
  nodes: NodeMap;
  edges: EdgeMap;
  seeds: string[]; // explicitly pivoted/expanded node ids
  selectedId: string | null;

  // ---- controls ----
  hops: number;
  direction: Direction;
  window: TimeWindow | null; // active rewind window; null = all time
  dataRange: TimeWindow | null; // full temporal extent of the corpus
  hiddenKinds: Set<NodeKind>;
  hiddenEtypes: Set<EdgeType>;

  // ---- views ----
  viewMode: ViewMode;

  // ---- attack paths ----
  attackPaths: AttackPathDto[] | null;
  highlightEdges: Set<string>; // edge ids highlighted as the selected path

  // ---- status ----
  loading: boolean;
  error: string | null;

  // ---- actions ----
  setViewMode: (m: ViewMode) => void;
  setDataRange: (r: TimeWindow) => void;
  pivotTo: (id: string) => Promise<void>;
  expand: (id: string) => Promise<void>;
  select: (id: string | null) => void;
  setWindow: (win: TimeWindow | null) => Promise<void>;
  setHops: (n: number) => Promise<void>;
  setDirection: (d: Direction) => Promise<void>;
  toggleKind: (k: NodeKind) => void;
  toggleEtype: (e: EdgeType) => void;
  loadPath: (src: string, dst: string) => Promise<void>;
  loadOverview: () => Promise<void>;
  runAttackPaths: (src: string, dst: string) => Promise<void>;
  highlightPath: (rank: number) => void;
  clearAttackPaths: () => void;
  clear: () => void;
  refresh: () => Promise<void>;
}

function mergeGraphs(chunks: CyGraph[]): { nodes: NodeMap; edges: EdgeMap } {
  const nodes: NodeMap = {};
  const edges: EdgeMap = {};
  for (const g of chunks) {
    for (const n of g.nodes) nodes[n.data.id] = n.data;
    for (const e of g.edges) edges[e.data.id] = e.data;
  }
  return { nodes, edges };
}

export const useAppStore = create<AppState>((set, get) => ({
  nodes: {},
  edges: {},
  seeds: [],
  selectedId: null,

  hops: 1,
  direction: "both",
  window: null,
  dataRange: null,
  hiddenKinds: new Set(),
  hiddenEtypes: new Set(),

  viewMode: "graph",

  attackPaths: null,
  highlightEdges: new Set(),

  loading: false,
  error: null,

  setViewMode: (m) => set({ viewMode: m }),
  setDataRange: (r) => set({ dataRange: r }),

  pivotTo: async (id) => {
    set({ seeds: [id], selectedId: id });
    await get().refresh();
  },

  expand: async (id) => {
    const { seeds } = get();
    if (!seeds.includes(id)) set({ seeds: [...seeds, id] });
    set({ selectedId: id });
    await get().refresh();
  },

  select: (id) => set({ selectedId: id }),

  setWindow: async (win) => {
    set({ window: win });
    await get().refresh();
  },

  setHops: async (n) => {
    set({ hops: Math.max(1, Math.min(5, n)) });
    await get().refresh();
  },

  setDirection: async (d) => {
    set({ direction: d });
    await get().refresh();
  },

  toggleKind: (k) =>
    set((s) => {
      const next = new Set(s.hiddenKinds);
      next.has(k) ? next.delete(k) : next.add(k);
      return { hiddenKinds: next };
    }),

  toggleEtype: (e) =>
    set((s) => {
      const next = new Set(s.hiddenEtypes);
      next.has(e) ? next.delete(e) : next.add(e);
      return { hiddenEtypes: next };
    }),

  loadPath: async (src, dst) => {
    set({ loading: true, error: null });
    try {
      const g = await api.path(src, dst, get().window);
      const merged = mergeGraphs([{ nodes: g.nodes, edges: g.edges }]);
      // Keep both endpoints as seeds so rewind/expand stay coherent.
      const seeds = Array.from(new Set([...get().seeds, src, dst]));
      set({
        nodes: { ...get().nodes, ...merged.nodes },
        edges: { ...get().edges, ...merged.edges },
        seeds,
        loading: false,
      });
    } catch (err) {
      set({ loading: false, error: describe(err) });
    }
  },

  loadOverview: async () => {
    // Seed the graph with the highest-risk entities (alerts and whom they hit)
    // so first-run isn't a blank canvas.
    set({ loading: true, error: null });
    try {
      const top = await api.topRisk(8);
      if (top.length === 0) {
        set({ loading: false });
        return;
      }
      set({ seeds: top.map((t) => t.id), selectedId: top[0].id });
      await get().refresh();
    } catch (err) {
      set({ loading: false, error: describe(err) });
    }
  },

  runAttackPaths: async (src, dst) => {
    set({ loading: true, error: null });
    try {
      const paths = await api.attackPaths(src, dst, 5);
      // Merge every ranked path into the view so all chains are visible, then
      // highlight the top (lowest-cost) one.
      const merged = mergeGraphs(paths.map((p) => p.graph));
      const seeds = Array.from(new Set([...get().seeds, src, dst]));
      const topEdges = new Set(paths[0]?.graph.edges.map((e) => e.data.id) ?? []);
      set({
        nodes: { ...get().nodes, ...merged.nodes },
        edges: { ...get().edges, ...merged.edges },
        seeds,
        attackPaths: paths,
        highlightEdges: topEdges,
        viewMode: "attack",
        loading: false,
      });
    } catch (err) {
      set({ loading: false, error: describe(err), attackPaths: [] });
    }
  },

  highlightPath: (rank) => {
    const p = get().attackPaths?.find((x) => x.rank === rank);
    if (p) set({ highlightEdges: new Set(p.graph.edges.map((e) => e.data.id)) });
  },

  clearAttackPaths: () => set({ attackPaths: null, highlightEdges: new Set() }),

  clear: () =>
    set({
      nodes: {},
      edges: {},
      seeds: [],
      selectedId: null,
      window: null,
      error: null,
      attackPaths: null,
      highlightEdges: new Set(),
    }),

  refresh: async () => {
    const { seeds, hops, direction, window } = get();
    if (seeds.length === 0) {
      set({ nodes: {}, edges: {} });
      return;
    }
    set({ loading: true, error: null });
    try {
      const chunks = await Promise.all(
        seeds.map((id) => api.neighbors(id, { hops, dir: direction, window })),
      );
      const { nodes, edges } = mergeGraphs(chunks);
      set({ nodes, edges, loading: false });
    } catch (err) {
      set({ loading: false, error: describe(err) });
    }
  },
}));

function describe(err: unknown): string {
  if (err instanceof ApiError) return err.message;
  if (err instanceof Error) return err.message;
  return String(err);
}
