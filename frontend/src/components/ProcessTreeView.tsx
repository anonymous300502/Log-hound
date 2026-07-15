// Process-tree view (PLAN.md §11, M8): a React Flow DAG of process lineage
// rooted at the selected host/process, following STARTED/SPAWNED out-edges. It
// is time-scoped by the shared scrubber and shares selection with every view.

import { useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import ReactFlow, { Background, Controls, type Node as RFNode } from "reactflow";
import "reactflow/dist/style.css";
import { api } from "../api/client";
import { useAppStore } from "../store/useAppStore";
import { treeLayout } from "../lib/layout";
import type { CyNodeData } from "../api/types";

export default function ProcessTreeView() {
  const selectedId = useAppStore((s) => s.selectedId);
  const window = useAppStore((s) => s.window);
  const select = useAppStore((s) => s.select);

  const tree = useQuery({
    queryKey: ["tree", selectedId, window?.from, window?.to],
    queryFn: () =>
      api.neighbors(selectedId as string, {
        etypes: ["STARTED", "SPAWNED", "RAN_AS"],
        dir: "out",
        hops: 6,
        window,
      }),
    enabled: !!selectedId,
  });

  const { nodes, edges } = useMemo(() => {
    if (!selectedId || !tree.data) return { nodes: [], edges: [] };
    const nodeMap: Record<string, CyNodeData> = {};
    for (const n of tree.data.nodes) nodeMap[n.data.id] = n.data;
    return treeLayout(
      nodeMap,
      tree.data.edges.map((e) => e.data),
      selectedId,
      selectedId,
    );
  }, [tree.data, selectedId]);

  if (!selectedId) {
    return (
      <div className="view-empty muted">
        Select a host or process, then open the Process Tree to see its lineage.
      </div>
    );
  }
  if (tree.isFetching) {
    return <div className="view-empty muted">building process tree…</div>;
  }
  if (nodes.length <= 1) {
    return <div className="view-empty muted">No child processes for this entity.</div>;
  }

  return (
    <div className="rf-canvas">
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
        elementsSelectable
      >
        <Background color="#1b2233" gap={20} />
        <Controls showInteractive={false} />
      </ReactFlow>
    </div>
  );
}
