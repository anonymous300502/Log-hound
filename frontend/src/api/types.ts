// TypeScript mirrors of the Rust API DTOs (crates/loghound-api/src/dto.rs,
// crates/loghound-graph/src/store.rs). Graph ids are strings — Cytoscape
// requires string ids and JS cannot hold a u64 losslessly (PLAN.md §10).

/** Node kind names — must match `NodeKind::name` in loghound-core. */
export type NodeKind =
  | "user"
  | "host"
  | "domain"
  | "process"
  | "executable"
  | "command_line"
  | "logon_session"
  | "network_connection"
  | "ip_address"
  | "dns_name"
  | "file"
  | "registry_key"
  | "service"
  | "task"
  | "sid"
  | "privilege"
  | "certificate"
  | "ioc"
  | "alert"
  | "event";

/** Edge type names — must match `EdgeType::name` in loghound-core. */
export type EdgeType =
  | "LOGGED_IN_TO"
  | "AUTHENTICATED"
  | "STARTED"
  | "SPAWNED"
  | "PARENT_OF"
  | "CHILD_OF"
  | "EXECUTED"
  | "USED"
  | "RAN_AS"
  | "CONNECTED_TO"
  | "RESOLVED"
  | "ACCESSED"
  | "CREATED"
  | "MODIFIED"
  | "DELETED"
  | "OWNS"
  | "BELONGS_TO"
  | "GENERATED"
  | "REQUESTED_TICKET"
  | "ACQUIRED_PRIVILEGE"
  | "LATERAL_MOVEMENT"
  | "TRIGGERED";

/** Cytoscape node `data` payload (CyNodeData). Also used by /search. */
export interface CyNodeData {
  id: string;
  label: string;
  kind: NodeKind;
  risk: number;
  first_seen: number;
  last_seen: number;
  event_count: number;
}

/** Cytoscape edge `data` payload (CyEdgeData). */
export interface CyEdgeData {
  id: string;
  source: string;
  target: string;
  etype: EdgeType;
  first_seen: number;
  last_seen: number;
  event_count: number;
  weight: number;
}

/** Cytoscape-shaped graph returned by /neighbors and /graph/path. */
export interface CyGraph {
  nodes: { data: CyNodeData }[];
  edges: { data: CyEdgeData }[];
}

/** /api/stats */
export interface Stats {
  events: number;
  nodes: number;
  edges: number;
  alerts: number;
}

/** /api/alerts (AlertRecord). */
export interface AlertRecord {
  alert_id: string;
  rule_id: string;
  name: string;
  severity: string;
  rule_type: string;
  mitre: string | null;
  ts: number;
  event_count: number;
  group_key: string | null;
  description: string;
  event_ids: number[];
}

/**
 * Full node detail (/api/nodes/:id). Mirrors the serialized `Node`. Note the
 * numeric `id` here can lose precision in JS for large hashes — the UI keeps the
 * string id it navigated with and never trusts this field for identity.
 */
export interface NodeDetail {
  id: number;
  kind: NodeKind;
  identity_key: string;
  label: string;
  validity: {
    first_seen: number;
    last_seen: number;
    event_count: number;
  };
  risk_score: number;
  props: Record<string, string>;
}

/** /api/events and /api/events/:id (EventSummary). */
export interface EventSummary {
  event_id: number;
  ts: number;
  class_uid: number;
  event_code: number | null;
  host: string | null;
  user_name: string | null;
  process_name: string | null;
  src_ip: string | null;
  dst_ip: string | null;
}

/** /api/timeline (TimelineBucket). */
export interface TimelineBucket {
  bucket: number;
  count: number;
}

export type Direction = "out" | "in" | "both";

/** /api/analytics/pagerank (ScoreDto). */
export interface ScoreDto {
  id: string;
  label: string;
  kind: NodeKind;
  score: number;
  risk: number;
}

/** One ranked attack path (/api/graph/attack-paths). */
export interface AttackPathDto {
  rank: number;
  cost: number;
  length: number;
  etypes: EdgeType[];
  mitre: string[];
  graph: CyGraph;
}
