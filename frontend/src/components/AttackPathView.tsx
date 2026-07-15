// Attack-path view (PLAN.md §11, M8): the currently-selected ranked attack path
// rendered as a left-to-right React Flow chain, with the technique (edge types)
// and MITRE tags called out. Ranking/selection lives in the detail panel; this
// view visualizes the chosen chain.

import { useMemo } from "react";
import ReactFlow, { Background, Controls, type Node as RFNode } from "reactflow";
import "reactflow/dist/style.css";
import { useAppStore } from "../store/useAppStore";
import { linearLayout } from "../lib/layout";
import type { CyNodeData } from "../api/types";

export default function AttackPathView() {
  const attackPaths = useAppStore((s) => s.attackPaths);
  const highlightEdges = useAppStore((s) => s.highlightEdges);
  const select = useAppStore((s) => s.select);

  const active = useMemo(() => {
    if (!attackPaths || attackPaths.length === 0) return null;
    return (
      attackPaths.find(
        (p) => p.graph.edges.length > 0 && p.graph.edges.every((e) => highlightEdges.has(e.data.id)),
      ) ?? attackPaths[0]
    );
  }, [attackPaths, highlightEdges]);

  const { nodes, edges } = useMemo(() => {
    if (!active) return { nodes: [], edges: [] };
    const nodeMap: Record<string, CyNodeData> = {};
    for (const n of active.graph.nodes) nodeMap[n.data.id] = n.data;
    return linearLayout(
      nodeMap,
      active.graph.edges.map((e) => e.data),
      null,
    );
  }, [active]);

  if (!attackPaths) {
    return (
      <div className="view-empty muted">
        Mark a start node in the detail panel, select a target, then run <b>⚔ Attack path</b>.
      </div>
    );
  }
  if (!active) {
    return <div className="view-empty muted">No time-respecting attack path found.</div>;
  }

  return (
    <div className="rf-canvas">
      <div className="attack-banner">
        <span className="path-rank">Rank #{active.rank}</span>
        <span className="muted small">
          {active.length} hop{active.length === 1 ? "" : "s"} · cost {active.cost.toFixed(2)}
        </span>
        <span className="attack-chain small">{active.etypes.join(" → ")}</span>
        {active.mitre.map((m) => (
          <span key={m} className="mitre-tag">
            {m}
          </span>
        ))}
      </div>
      <ReactFlow
        nodes={nodes}
        edges={edges}
        fitView
        minZoom={0.1}
        maxZoom={2}
        proOptions={{ hideAttribution: true }}
        onNodeClick={(_e, n: RFNode) => select(n.id)}
        nodesDraggable={false}
        nodesConnectable={false}
      >
        <Background color="#1b2233" gap={20} />
        <Controls showInteractive={false} />
      </ReactFlow>
    </div>
  );
}
