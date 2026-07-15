//! # loghound-correlate
//!
//! Joins normalized [`loghound_core::Event`]s across log types into the temporal
//! graph (`PLAN.md` §8): process-tree reconstruction (with PID-reuse handling),
//! logon-session ownership, network/file attribution, cross-host lateral-movement
//! linking, and generic privilege/account handling.
//!
//! The [`Correlator`] accumulates into a [`GraphBuilder`]; the resulting
//! nodes/edges are persisted to the DuckDB store and the CSR snapshot rebuilt.

pub mod builder;
pub mod correlator;
pub mod identity;

pub use builder::GraphBuilder;
pub use correlator::Correlator;
