//! # loghound-normalize
//!
//! Maps heterogeneous source records into the shared [`loghound_core::Event`]
//! model using the declarative OCSF mappings in `mappings.yaml`.
//!
//! `M0` scope: load and validate the mapping configuration (backwards-compatible
//! with the original prototype's `mappings.yaml`). The record-to-event mapping
//! engine and the schema-aware Windows extractor land in `M1` (`PLAN.md` §7).

pub mod config;
pub mod normalizer;

pub use config::{ConfigError, EventMapping, MappingConfig};
pub use normalizer::Normalizer;
