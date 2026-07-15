//! Integration test: stream the real sample fixture end-to-end.
//!
//! `tests/fixtures/oplc_sample.log` is derived verbatim from the user-provided
//! `sample logs` (one line per log type). This guards the parser against
//! regressions on the actual wire format.

use std::collections::BTreeMap;

use loghound_parsers::{parse_str, OplcParser, RecordKind};

const FIXTURE: &str = include_str!("fixtures/oplc_sample.log");

#[test]
fn parses_all_four_record_types_from_fixture() {
    let results = parse_str(&OplcParser::new(), FIXTURE);
    assert_eq!(results.len(), 4, "fixture has one line per log type");

    let mut by_kind: BTreeMap<&str, usize> = BTreeMap::new();
    for r in &results {
        let rec = r.as_ref().expect("every fixture line parses cleanly");
        *by_kind.entry(rec.kind.as_str()).or_default() += 1;
        // Every record must carry a host and a non-zero event time.
        assert!(rec.host.is_some(), "{:?} missing host", rec.kind);
        assert!(rec.ts.millis() > 0, "{:?} missing timestamp", rec.kind);
        assert_eq!(rec.get("env.tenant"), Some("acme"));
    }

    assert_eq!(by_kind.get("event"), Some(&1));
    assert_eq!(by_kind.get("network"), Some(&1));
    assert_eq!(by_kind.get("process"), Some(&1));
    assert_eq!(by_kind.get("integrity"), Some(&1));
}

#[test]
fn event_record_carries_full_windows_context() {
    let results = parse_str(&OplcParser::new(), FIXTURE);
    let event = results
        .iter()
        .find_map(|r| r.as_ref().ok().filter(|rec| rec.kind == RecordKind::Event))
        .expect("an event record");

    assert_eq!(event.get("EventID"), Some("4673"));
    assert_eq!(event.get("SubjectUserName"), Some("john.doe"));
    assert_eq!(event.get("SubjectDomainName"), Some("acme"));
    assert_eq!(event.get("PrivilegeList"), Some("SeTcbPrivilege"));
    // Full msedge path preserved from the real sample.
    assert!(event
        .get("ProcessName")
        .unwrap()
        .contains("Microsoft\\Edge\\Application\\msedge.exe"));
}
