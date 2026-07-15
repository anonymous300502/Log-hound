//! # loghound-graph
//!
//! The temporal graph engine (`PLAN.md` §4–§6): a DuckDB columnar store as the
//! source of truth ([`store::Store`]) plus (from later in `M2`) an in-memory
//! `petgraph` build graph and lock-free CSR snapshot for fast time-aware
//! traversal and analytics.

pub mod analytics;
pub mod graph;
pub mod index;
pub mod store;

pub use analytics::{all_time, AttackPath, Degree, Score};
pub use graph::Graph;
pub use index::{
    CsrSnapshot, Dir, EdgeTypeMask, EdgeView, GraphIndex, NodeView, Subgraph, TraversalOpts,
};
pub use store::{AlertRecord, EventSummary, Stats, Store, StoreError, Table};
