//! The [`Parser`] trait and streaming helpers (`PLAN.md` §7).
//!
//! Parsers are line-oriented: the OPLC SIEM emits one record per line. Each
//! parser sniffs a sample to report [`Confidence`], then decodes lines into
//! [`RawRecord`]s, yielding a `Result` per line so a single malformed record
//! never aborts the stream.

use std::io::BufRead;

use crate::record::{ParseError, RawRecord};

/// How confident a parser is that it can handle an input sample.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confidence {
    /// Definitely not this format.
    No,
    /// Possibly this format; higher scores win ties during auto-detection.
    Maybe(u8),
    /// Definitely this format.
    Yes,
}

/// A pluggable log parser.
pub trait Parser: Send + Sync {
    /// Stable identifier (used in logs and the plugin registry).
    fn id(&self) -> &'static str;

    /// Sniff a leading sample of the input to decide if this parser applies.
    fn can_parse(&self, sample: &str) -> Confidence;

    /// Decode a single (non-empty) line into a record.
    fn parse_line(&self, line: &str, line_no: usize) -> Result<RawRecord, ParseError>;
}

/// Stream a reader through a parser, skipping blank lines and yielding one
/// `Result` per record. `line_no` is 1-based over all lines (blank included) so
/// error positions match the source file.
pub fn parse_reader<'a, P, R>(
    parser: &'a P,
    reader: R,
) -> impl Iterator<Item = Result<RawRecord, ParseError>> + 'a
where
    P: Parser,
    R: BufRead + 'a,
{
    reader.lines().enumerate().filter_map(move |(idx, line)| {
        let line_no = idx + 1;
        let line = match line {
            Ok(l) => l,
            // An I/O error mid-stream surfaces as a per-record envelope error.
            Err(e) => {
                return Some(Err(ParseError::Envelope {
                    line: line_no,
                    reason: format!("read error: {e}"),
                }))
            }
        };
        if line.trim().is_empty() {
            return None;
        }
        Some(parser.parse_line(&line, line_no))
    })
}

/// Convenience: parse all records from an in-memory string.
pub fn parse_str<P: Parser>(parser: &P, text: &str) -> Vec<Result<RawRecord, ParseError>> {
    parse_reader(parser, text.as_bytes()).collect()
}
