//! The common [`RawRecord`] every parser emits, plus [`ParseError`].
//!
//! A `RawRecord` is deliberately schema-agnostic: it carries the decoded source
//! fields as strings plus the best-known event time and host. Only the
//! normalization layer (`loghound-normalize`) turns it into an OCSF
//! [`loghound_core::Event`] (`PLAN.md` §7).

use std::collections::BTreeMap;

use loghound_core::Timestamp;

/// Which OPLC logset a record came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordKind {
    /// `logset E` — a Windows Event Log XML record.
    Event,
    /// `logset N` — a network connection record.
    Network,
    /// `logset P` — a process-creation record.
    Process,
    /// `logset I` — a file-integrity record.
    Integrity,
}

impl RecordKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            RecordKind::Event => "event",
            RecordKind::Network => "network",
            RecordKind::Process => "process",
            RecordKind::Integrity => "integrity",
        }
    }
}

/// A decoded-but-not-yet-normalized log record.
#[derive(Debug, Clone, PartialEq)]
pub struct RawRecord {
    pub kind: RecordKind,
    /// Best event time: XML `TimeCreated` for events, else `generated_ts`×1000.
    pub ts: Timestamp,
    /// Best host: XML `Computer` (FQDN) for events, else the envelope hostname.
    pub host: Option<String>,
    /// Source IP from the envelope.
    pub source_ip: Option<String>,
    /// Decoded fields as strings.
    ///
    /// - Events use the raw Windows names (`EventID`, `Computer`, `TargetUserName`,
    ///   `ProcessName`, …) so `mappings.yaml` resolves unchanged, plus `Tag_Attr`
    ///   keys for attribute-bearing System elements (`TimeCreated_SystemTime`).
    /// - N/P/I use descriptive keys (`protocol`, `src_ip`, `pid`, `process`, …).
    /// - Envelope metadata is under `env.*` (`env.tenant`, `env.collector_ts_ms`,
    ///   `env.agent_version`, …) so normalization can route it to `Event::extra`.
    pub fields: BTreeMap<String, String>,
    /// The original source line (kept for provenance / `Event::raw`).
    pub raw: String,
}

impl RawRecord {
    pub fn new(kind: RecordKind, ts: Timestamp, raw: impl Into<String>) -> RawRecord {
        RawRecord {
            kind,
            ts,
            host: None,
            source_ip: None,
            fields: BTreeMap::new(),
            raw: raw.into(),
        }
    }

    /// Insert a field, ignoring empty values (keeps the map tidy).
    pub fn put(&mut self, key: impl Into<String>, value: impl Into<String>) {
        let value = value.into();
        if !value.is_empty() {
            self.fields.insert(key.into(), value);
        }
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.fields.get(key).map(String::as_str)
    }
}

/// A per-record parse failure. Parsing yields `Result<RawRecord, ParseError>` so
/// one bad line never kills the stream (`PLAN.md` §7).
#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("line {line}: not an OPLC record")]
    NotOplc { line: usize },
    #[error("line {line}: malformed envelope: {reason}")]
    Envelope { line: usize, reason: String },
    #[error("line {line}: unknown logset {logset:?}")]
    UnknownLogset { line: usize, logset: String },
    #[error("line {line}: malformed {kind} payload: {reason}")]
    Payload {
        line: usize,
        kind: &'static str,
        reason: String,
    },
    #[error("line {line}: XML error: {reason}")]
    Xml { line: usize, reason: String },
}

impl ParseError {
    /// The 1-based source line this error refers to.
    pub fn line(&self) -> usize {
        match self {
            ParseError::NotOplc { line }
            | ParseError::Envelope { line, .. }
            | ParseError::UnknownLogset { line, .. }
            | ParseError::Payload { line, .. }
            | ParseError::Xml { line, .. } => *line,
        }
    }
}
