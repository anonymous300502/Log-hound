// The main investigation canvas (PLAN.md §11). Renders the merged temporal
// graph with Cytoscape: click a node to select it (drives the detail panel),
// double-click to expand its neighbors (pivot), right-click for the same. The
// element set is reconciled incrementally so selection and rewind don't reset
// node positions unnecessarily.

import { useEffect, useMemo, useRef } from "react";
import cytoscape from "cytoscape";
import { useAppStore } from "../store/useAppStore";
import { buildStylesheet, layoutFor } from "../lib/cytoStyle";
import type { NodeKind } from "../api/types";

type Core = cytoscape.Core;
type ElementDefinition = cytoscape.ElementDefinition;

interface Props {
  layoutName: string;
  fitSignal: number; // bump to trigger a fit-to-viewport
}

export default function GraphView({ layoutName, fitSignal }: Props) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const cyRef = useRef<Core | null>(null);

  const nodes = useAppStore((s) => s.nodes);
  const edges = useAppStore((s) => s.edges);
  const seeds = useAppStore((s) => s.seeds);
  const selectedId = useAppStore((s) => s.selectedId);
  const hiddenKinds = useAppStore((s) => s.hiddenKinds);
  const hiddenEtypes = useAppStore((s) => s.hiddenEtypes);
  const select = useAppStore((s) => s.select);
  const expand = useAppStore((s) => s.expand);
  const highlightEdges = useAppStore((s) => s.highlightEdges);

  // Compute the visible element set (respecting kind/etype filters).
  const elements = useMemo<ElementDefinition[]>(() => {
    const visibleNode = (kind: NodeKind) => !hiddenKinds.has(kind);
    const nodeEls: ElementDefinition[] = [];
    const present = new Set<string>();
    for (const n of Object.values(nodes)) {
      if (!visibleNode(n.kind)) continue;
      present.add(n.id);
      nodeEls.push({ group: "nodes", data: { ...n } });
    }
    const edgeEls: ElementDefinition[] = [];
    for (const e of Object.values(edges)) {
      if (hiddenEtypes.has(e.etype)) continue;
      if (!present.has(e.source) || !present.has(e.target)) continue;
      edgeEls.push({ group: "edges", data: { ...e } });
    }
    return [...nodeEls, ...edgeEls];
  }, [nodes, edges, hiddenKinds, hiddenEtypes]);

  // One-time init.
  useEffect(() => {
    if (!containerRef.current || cyRef.current) return;
    const cy = cytoscape({
      container: containerRef.current,
      style: buildStylesheet(),
      wheelSensitivity: 0.2,
      minZoom: 0.1,
      maxZoom: 3,
    });
    cyRef.current = cy;

    // Cytoscape has no native double-click event, so detect it from tap timing.
    // Single tap selects (drives the detail panel); double-tap / right-click
    // expands the node's neighborhood (the "pivot" action).
    let lastTapId = "";
    let lastTapAt = 0;
    cy.on("tap", "node", (evt) => {
      const id = evt.target.id();
      const now = Date.now();
      if (id === lastTapId && now - lastTapAt < 300) {
        void expand(id);
        lastTapId = "";
        lastTapAt = 0;
      } else {
        select(id);
        lastTapId = id;
        lastTapAt = now;
      }
    });
    cy.on("tap", (evt) => {
      if (evt.target === cy) select(null); // background tap clears selection
    });
    cy.on("cxttap", "node", (evt) => void expand(evt.target.id()));

    return () => {
      cy.destroy();
      cyRef.current = null;
    };
  }, [select, expand]);

  // Reconcile elements: add new, remove gone; relayout only on structural change.
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    const desired = new Map(elements.map((el) => [String(el.data.id), el]));
    let structuralChange = false;

    cy.batch(() => {
      // Remove elements no longer desired.
      cy.elements().forEach((el) => {
        if (!desired.has(el.id())) {
          el.remove();
          structuralChange = true;
        }
      });
      // Add / update.
      for (const [id, el] of desired) {
        const existing = cy.getElementById(id);
        if (existing.empty()) {
          cy.add(el);
          structuralChange = true;
        } else {
          existing.data(el.data as Record<string, unknown>);
        }
      }
    });

    if (structuralChange && cy.elements().length > 0) {
      cy.layout(layoutFor(layoutName)).run();
    }
  }, [elements, layoutName]);

  // Mark seed nodes.
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    cy.batch(() => {
      cy.nodes().removeClass("seed");
      for (const id of seeds) cy.getElementById(id).addClass("seed");
    });
  }, [seeds, elements]);

  // Reflect the store's selection in the canvas (e.g. when it changes from the
  // search panel). We don't listen to cytoscape's own select/unselect events, so
  // this can't feed back into a loop.
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    cy.batch(() => {
      cy.$(":selected").unselect();
      if (selectedId) {
        const el = cy.getElementById(selectedId);
        if (!el.empty()) el.select();
      }
    });
  }, [selectedId, elements]);

  // Highlight the edges of the selected attack path (`.path-hi`).
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    cy.batch(() => {
      cy.edges().removeClass("path-hi");
      highlightEdges.forEach((id) => cy.getElementById(id).addClass("path-hi"));
    });
  }, [highlightEdges, elements]);

  // Fit-to-viewport on demand.
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy || cy.elements().length === 0) return;
    cy.animate({ fit: { eles: cy.elements(), padding: 40 }, duration: 300 });
  }, [fitSignal]);

  const isEmpty = Object.keys(nodes).length === 0;
  const loadOverview = useAppStore((s) => s.loadOverview);

  return (
    <div className="graph-wrap">
      <div ref={containerRef} className="graph-canvas" />
      {isEmpty && (
        <div className="canvas-hint">
          <div className="canvas-hint-title">Nothing on the canvas yet</div>
          <div className="muted small">
            Search an entity on the left and click a result, or load the
            highest-risk entities to start.
          </div>
          <button className="btn accent" onClick={() => void loadOverview()}>
            Load overview
          </button>
        </div>
      )}
    </div>
  );
}
