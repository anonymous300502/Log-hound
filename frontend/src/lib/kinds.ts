// Visual + label metadata for node kinds and OCSF classes, shared by the graph
// stylesheet, the legend, and the detail panel so colors stay consistent.

import type { NodeKind } from "../api/types";

export interface KindStyle {
  color: string;
  shape: string; // Cytoscape node-shape
  label: string; // human label
}

export const KIND_STYLES: Record<NodeKind, KindStyle> = {
  user: { color: "#4f9dff", shape: "ellipse", label: "User" },
  host: { color: "#f2b134", shape: "round-rectangle", label: "Host" },
  domain: { color: "#ffce54", shape: "round-rectangle", label: "Domain" },
  process: { color: "#7ee081", shape: "diamond", label: "Process" },
  executable: { color: "#35c9c9", shape: "hexagon", label: "Executable" },
  command_line: { color: "#9aa0a6", shape: "round-tag", label: "Command Line" },
  logon_session: { color: "#c58af9", shape: "octagon", label: "Logon Session" },
  network_connection: { color: "#ff8a5c", shape: "rhomboid", label: "Connection" },
  ip_address: { color: "#ff6b6b", shape: "triangle", label: "IP Address" },
  dns_name: { color: "#ffd166", shape: "triangle", label: "DNS Name" },
  file: { color: "#a0e7a0", shape: "round-rectangle", label: "File" },
  registry_key: { color: "#b0a0ff", shape: "round-rectangle", label: "Registry Key" },
  service: { color: "#f7a1c4", shape: "pentagon", label: "Service" },
  task: { color: "#c4a1f7", shape: "pentagon", label: "Task" },
  sid: { color: "#8a8a8a", shape: "ellipse", label: "SID" },
  privilege: { color: "#ff5d5d", shape: "vee", label: "Privilege" },
  certificate: { color: "#6ad0ff", shape: "barrel", label: "Certificate" },
  ioc: { color: "#ff3b3b", shape: "star", label: "IOC" },
  alert: { color: "#ff2d55", shape: "star", label: "Alert" },
  event: { color: "#777777", shape: "ellipse", label: "Event" },
};

export function kindStyle(kind: NodeKind): KindStyle {
  return KIND_STYLES[kind] ?? { color: "#888", shape: "ellipse", label: kind };
}

export const OCSF_CLASSES: Record<number, string> = {
  3002: "Authentication",
  1007: "Process Activity",
  3006: "Account Change",
  4001: "Network Activity",
  1001: "File Activity",
  0: "Generic",
};

export function ocsfClassName(uid: number): string {
  return OCSF_CLASSES[uid] ?? `Class ${uid}`;
}
