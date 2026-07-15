//! Timestamp parsing for the three shapes LogHound sees on the wire (`PLAN.md` §7):
//!
//! - 10-digit epoch **seconds** (`generated_ts` in N/P/I payloads),
//! - 13-digit epoch **milliseconds** (OPLC `collector_ts`),
//! - ISO-8601 / RFC 3339 with fractional seconds (Windows XML `TimeCreated`,
//!   e.g. `2026-06-30T22:26:08.7149364Z`).

use chrono::DateTime;
use loghound_core::Timestamp;

/// Parse a bare epoch integer, inferring the unit from its magnitude:
/// values ≥ 10^12 are treated as milliseconds, otherwise as seconds.
///
/// (10^12 ms ≈ year 2001; 10^12 s ≈ year 33658 — so the boundary cleanly
/// separates modern second- and millisecond-epoch values.)
pub fn parse_epoch(s: &str) -> Option<Timestamp> {
    let n: i64 = s.trim().parse().ok()?;
    if n >= 1_000_000_000_000 {
        Some(Timestamp::from_millis(n)) // already milliseconds
    } else {
        Some(Timestamp::from_millis(n.checked_mul(1000)?)) // seconds -> ms
    }
}

/// Parse epoch **seconds** explicitly (used for the payload `generated_ts`,
/// which is always seconds regardless of magnitude).
pub fn parse_epoch_seconds(s: &str) -> Option<Timestamp> {
    let n: i64 = s.trim().parse().ok()?;
    Some(Timestamp::from_millis(n.checked_mul(1000)?))
}

/// Parse epoch **milliseconds** explicitly (used for the OPLC `collector_ts`).
pub fn parse_epoch_millis(s: &str) -> Option<Timestamp> {
    let n: i64 = s.trim().parse().ok()?;
    Some(Timestamp::from_millis(n))
}

/// Parse an ISO-8601 / RFC 3339 timestamp (with optional fractional seconds and
/// a `Z` or numeric offset) to epoch milliseconds. Windows emits 100 ns (7-digit)
/// fractions, which `chrono` accepts.
pub fn parse_iso8601(s: &str) -> Option<Timestamp> {
    let dt = DateTime::parse_from_rfc3339(s.trim()).ok()?;
    Some(Timestamp::from_millis(dt.timestamp_millis()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_seconds_scaled_to_millis() {
        // 1782858197 s -> 1782858197000 ms
        assert_eq!(
            parse_epoch_seconds("1782858197"),
            Some(Timestamp(1_782_858_197_000))
        );
    }

    #[test]
    fn epoch_millis_passthrough() {
        assert_eq!(
            parse_epoch_millis("1782858062494"),
            Some(Timestamp(1_782_858_062_494))
        );
    }

    #[test]
    fn parse_epoch_infers_unit_by_magnitude() {
        assert_eq!(
            parse_epoch("1782858197"),
            Some(Timestamp(1_782_858_197_000))
        ); // s
        assert_eq!(
            parse_epoch("1782858062494"),
            Some(Timestamp(1_782_858_062_494))
        ); // ms
    }

    #[test]
    fn iso8601_with_100ns_fraction_and_z() {
        // 2026-06-30T22:26:08.7149364Z — the XML TimeCreated from the sample.
        let ts = parse_iso8601("2026-06-30T22:26:08.7149364Z").expect("parses");
        // Sanity: matches the sample's generated_ts (1782858369 s) to the second.
        assert_eq!(ts.secs(), 1_782_858_368);
        // Millisecond precision retained (.714 -> 714 ms).
        assert_eq!(ts.millis(), 1_782_858_368_714);
    }

    #[test]
    fn rejects_garbage() {
        assert_eq!(parse_epoch("not-a-number"), None);
        assert_eq!(parse_iso8601("2026-13-40T99:99:99Z"), None);
    }
}
