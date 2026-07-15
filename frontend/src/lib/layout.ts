// Deterministic layouts for the React Flow views (process tree, attack path).
// We compute explicit node positions rather than relying on an auto-layout
// plugin, so rendering is stable and dependency-free.

import type { Edge as RFEdge, Node as RFNode } from "reactflow";
import { MarkerType } from "reactflow";
import type { CyEdgeData, CyNodeData } from "../api/types";
import { kindStyle } from "./kinds";

const NODE_W = 150;
const X_GAP = 190;
const Y_GAP = 110;

function rfNode(n: CyNodeData, x: number, y: number, selectedId: string | null): RFNode {
  const ks = kindStyle(n.kind);
  return {
    id: n.id,
    position: { x, y },
    data: { label: `${n.label}\n(${ks.label})` },
    style: {
      background: ks.color,
      color: "#0b0e14",
      border: n.id === selectedId ? "3px solid #fff" : "1px solid #0b0e14",
      borderRadius: 8,
      width: NODE_W,
      fontSize: 11,
      fontWeight: 600,
      whiteSpace: "pre-line",
      textAlign: "center",
      padding: 6,
    },
  };
}

function rfEdge(e: CyEdgeData, highlight: boolean): RFEdge {
  return {
    id: e.id,
    source: e.source,
    target: e.target,
    label: e.etype,
    animated: highlight,
    markerEnd: { type: MarkerType.ArrowClosed, color: highlight ? "#ff2d55" : "#8b93a7" },
    style: { stroke: highlight ? "#ff2d55" : "#3a4256", strokeWidth: highlight ? 2.5 : 1.2 },
    labelStyle: { fill: "#8b93a7", fontSize: 9 },
    labelBgStyle: { fill: "#0b0e14", fillOpacity: 0.7 },
  };
}

/**
 * Tidy hierarchical tree layout rooted at `rootId`, following out-edges as
 * parent→child. Non-tree edges among placed nodes are still drawn. Leaves are
 * assigned successive x-slots; each parent centers over its children.
 */
export function treeLayout(
  nodes: Record<string, CyNodeData>,
  edges: CyEdgeData[],
  rootId: string,
  selectedId: string | null,
): { nodes: RFNode[]; edges: RFEdge[] } {
  const children = new Map<string, string[]>();
  const indeg = new Map<string, number>();
  for (const id of Object.keys(nodes)) {
    children.set(id, []);
    indeg.set(id, 0);
  }
  for (const e of edges) {
    if (children.has(e.source) && nodes[e.target]) {
      children.get(e.source)!.push(e.target);
      indeg.set(e.target, (indeg.get(e.target) ?? 0) + 1);
    }
  }

  // Walk tree edges (first visit wins) to assign depth + x.
  const depth = new Map<string, number>();
  const xpos = new Map<string, number>();
  let leafX = 0;
  const visited = new Set<string>();

  const place = (id: string, d: number): number => {
    visited.add(id);
    depth.set(id, d);
    const kids = (children.get(id) ?? []).filter((c) => !visited.has(c));
    if (kids.length === 0) {
      const x = leafX;
      leafX += 1;
      xpos.set(id, x);
      return x;
    }
    const xs = kids.map((c) => place(c, d + 1));
    const x = (Math.min(...xs) + Math.max(...xs)) / 2;
    xpos.set(id, x);
    return x;
  };

  const root = nodes[rootId] ? rootId : Object.keys(nodes)[0];
  if (root) place(root, 0);
  // Place any nodes not reached from the root (disconnected) below the tree.
  for (const id of Object.keys(nodes)) {
    if (!visited.has(id)) {
      depth.set(id, (Math.max(0, ...Array.from(depth.values())) || 0) + 2);
      xpos.set(id, leafX);
      leafX += 1;
    }
  }

  const rfNodes = Object.values(nodes).map((n) =>
    rfNode(n, (xpos.get(n.id) ?? 0) * X_GAP, (depth.get(n.id) ?? 0) * Y_GAP, selectedId),
  );
  const rfEdges = edges
    .filter((e) => nodes[e.source] && nodes[e.target])
    .map((e) => rfEdge(e, false));
  return { nodes: rfNodes, edges: rfEdges };
}

/**
 * Linear left-to-right layout for an ordered path. Node order is recovered by
 * walking the ordered edge list source→target (the API returns edges in path
 * order).
 */
export function linearLayout(
  nodes: Record<string, CyNodeData>,
  edges: CyEdgeData[],
  selectedId: string | null,
): { nodes: RFNode[]; edges: RFEdge[] } {
  // Recover node order from the edge chain.
  const order: string[] = [];
  if (edges.length > 0) {
    order.push(edges[0].source);
    for (const e of edges) order.push(e.target);
  } else {
    order.push(...Object.keys(nodes));
  }
  const rfNodes = order
    .filter((id) => nodes[id])
    .map((id, i) => rfNode(nodes[id], i * X_GAP, (i % 2) * 40, selectedId));
  const rfEdges = edges.map((e) => rfEdge(e, true));
  return { nodes: rfNodes, edges: rfEdges };
}
