//! # loghound-detect
//!
//! The detection engine (`PLAN.md` §9).
//!
//! - [`rules`] loads `rules.yaml` into a typed [`rules::RuleSet`]
//!   (atomic/threshold/chain), backwards-compatible with the prototype's 36
//!   MITRE-tagged rules.
//! - [`dsl`] is the filter language: a proper boolean-expression parser + AST +
//!   evaluator (precedence, parentheses, `==`/`!=`/`<`/`>`/`>=`/`<=`/`IN`/
//!   `CONTAINS`/`=~`), replacing the prototype's `str.split(' AND ')`.
//! - [`engine`] compiles rules into an executable IR and evaluates an event
//!   stream, emitting [`engine::Alert`]s (atomic + sliding-window threshold +
//!   N-step correlated sequence).
//! - [`alerts`] wires alerts into the temporal graph (Alert nodes + `TRIGGERED`
//!   edges to the involved host/user/address).
//! - [`sigma`] compiles a common Sigma subset into the same rule IR.

pub mod alerts;
pub mod dsl;
pub mod engine;
pub mod rules;
pub mod sigma;

pub use alerts::build_alert_graph;
pub use dsl::{Expr, ParseError};
pub use engine::{dedup_alerts, Alert, CompiledRuleSet, Engine};
pub use rules::{Rule, RuleSet, RuleStep, RuleType, RulesError};
pub use sigma::{compile_sigma, SigmaError};
