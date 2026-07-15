//! # loghound-parsers
//!
//! Pluggable, streaming log parsers (`PLAN.md` §7). All four log types arrive
//! wrapped in a shared **OPLC envelope**; [`OplcParser`] decodes the envelope and
//! dispatches to a per-logset decoder (Event XML, Network, Process, Integrity),
//! emitting a common [`RawRecord`] stream that normalization turns into
//! [`loghound_core::Event`]s.

pub mod oplc;
pub mod parser;
pub mod record;
pub mod timestamp;

pub use oplc::OplcParser;
pub use parser::{parse_reader, parse_str, Confidence, Parser};
pub use record::{ParseError, RawRecord, RecordKind};
