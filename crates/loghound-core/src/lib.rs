//! # loghound-core
//!
//! Foundational domain types for the LogHound temporal knowledge graph.
//!
//! Everything reconstructed from logs becomes a graph of [`Node`]s connected by
//! [`Edge`]s, both carrying a temporal [`Validity`] interval
//! (`first_seen` / `last_seen` / `event_count`) so investigators can "rewind"
//! the graph to any instant or window (see `PLAN.md` §2, §6).
//!
//! Normalized telemetry is represented by [`Event`], an OCSF-like record shared
//! by every parser (see `PLAN.md` §7).
//!
//! This crate has no I/O and no heavy dependencies — it is the shared vocabulary
//! that the parser, normalization, correlation, graph, detection, and API crates
//! all speak.

pub mod edge;
pub mod event;
pub mod ids;
pub mod node;
pub mod time;

pub use edge::{Edge, EdgeType};
pub use event::{class, Event};
pub use ids::{EdgeId, EventId, NodeId};
pub use node::{Node, NodeKind};
pub use time::{Timestamp, Validity};
