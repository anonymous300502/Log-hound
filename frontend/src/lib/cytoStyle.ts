// Cytoscape stylesheet + layout config. Node color/shape come from the kind
// (see kinds.ts), node size scales with risk, and edge width scales with
// event_count so heavily-observed relationships read as thicker.
//
// Cytoscape's style typings are strict and incomplete, so we build the sheet
// with loose literals and assert the (interface, not the `Stylesheet` type
// alias, which the default-import binding doesn't expose) return type.

import type cytoscape from "cytoscape";
import { KIND_STYLES } from "./kinds";
import type { NodeKind } from "../api/types";

type Sheet = cytoscape.StylesheetStyle;

export function buildStylesheet(): Sheet[] {
  const base = [
    {
      selector: "node",
      style: {
        label: "data(label)",
        color: "#e6e6e6",
        "font-size": 9,
        "text-wrap": "ellipsis",
        "text-max-width": "120px",
        "text-valign": "bottom",
        "text-halign": "center",
        "text-margin-y": 3,
        "border-width": 1,
        "border-color": "#0b0e14",
        width: "mapData(risk, 0, 100, 22, 58)",
        height: "mapData(risk, 0, 100, 22, 58)",
        "min-zoomed-font-size": 6,
      },
    },
    {
      selector: "edge",
      style: {
        label: "data(etype)",
        "font-size": 7,
        color: "#8b93a7",
        "text-rotation": "autorotate",
        "text-background-color": "#0b0e14",
        "text-background-opacity": 0.7,
        "text-background-padding": "1px",
        "curve-style": "bezier",
        "line-color": "#3a4256",
        "target-arrow-color": "#3a4256",
        "target-arrow-shape": "triangle",
        "arrow-scale": 0.8,
        width: "mapData(event_count, 1, 50, 1, 6)",
        "min-zoomed-font-size": 7,
      },
    },
    {
      selector: "node:selected",
      style: {
        "border-width": 3,
        "border-color": "#ffffff",
        "overlay-color": "#ffffff",
        "overlay-opacity": 0.12,
        "overlay-padding": 6,
      },
    },
    {
      selector: "node.seed",
      style: { "border-width": 3, "border-color": "#f5f5f5" },
    },
    {
      selector: "node.alerted",
      style: {
        "overlay-color": "#ff2d55",
        "overlay-opacity": 0.25,
        "overlay-padding": 8,
      },
    },
    {
      selector: "edge:selected",
      style: {
        "line-color": "#ffffff",
        "target-arrow-color": "#ffffff",
        width: 3,
        color: "#ffffff",
      },
    },
    {
      selector: ".path-hi",
      style: {
        "line-color": "#ff2d55",
        "target-arrow-color": "#ff2d55",
        "border-color": "#ff2d55",
        "border-width": 3,
      },
    },
    { selector: ".dimmed", style: { opacity: 0.18 } },
  ];

  const perKind = (Object.keys(KIND_STYLES) as NodeKind[]).map((kind) => ({
    selector: `node[kind = "${kind}"]`,
    style: {
      "background-color": KIND_STYLES[kind].color,
      shape: KIND_STYLES[kind].shape,
    },
  }));

  return [...base, ...perKind] as unknown as Sheet[];
}

export function layoutFor(name: string): cytoscape.LayoutOptions {
  if (name === "breadthfirst") {
    return {
      name: "breadthfirst",
      directed: true,
      spacingFactor: 1.1,
      animate: true,
      animationDuration: 300,
      padding: 30,
    } as cytoscape.LayoutOptions;
  }
  if (name === "concentric") {
    return {
      name: "concentric",
      animate: true,
      animationDuration: 300,
      minNodeSpacing: 30,
      padding: 30,
    } as cytoscape.LayoutOptions;
  }
  return {
    name: "cose",
    animate: true,
    animationDuration: 400,
    nodeRepulsion: () => 12000,
    idealEdgeLength: () => 90,
    nodeDimensionsIncludeLabels: true,
    padding: 30,
    randomize: false,
  } as cytoscape.LayoutOptions;
}
