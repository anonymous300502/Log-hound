//! The OPLC SIEM parser: one envelope decoder + four logset decoders
//! (`PLAN.md` §7).
//!
//! Wire format (confirmed against real samples):
//! ```text
//! OPLC-<tenant>,<collector_ts_ms>,<src_ip> #<generated_ts_s>,<hostname>,<src_ip>,<logset>,<payload…>
//! ```
//! The line is split on `" #"`; the `<logset>` letter (`E`/`N`/`P`/`I`) selects
//! the decoder. Parsing is *positional from the logset marker*, which survives
//! the Process type's extra leading `agent_version` field.

use std::collections::BTreeMap;

use quick_xml::events::{BytesStart, Event as XmlEvent};
use quick_xml::name::QName;
use quick_xml::reader::Reader;

use loghound_core::Timestamp;

use crate::parser::{Confidence, Parser};
use crate::record::{ParseError, RawRecord, RecordKind};
use crate::timestamp::{parse_epoch_millis, parse_epoch_seconds, parse_iso8601};

const NETWORK: &str = "NETWORK";
const NEW_PROCESS: &str = "NEW_PROCESS";
const FILE_INTEGRITY: &str = "FILE_INTEGRITY";

/// Parser for the OPLC SIEM envelope carrying all four log types.
#[derive(Debug, Default, Clone, Copy)]
pub struct OplcParser;

impl OplcParser {
    pub fn new() -> Self {
        OplcParser
    }
}

impl Parser for OplcParser {
    fn id(&self) -> &'static str {
        "oplc"
    }

    fn can_parse(&self, sample: &str) -> Confidence {
        let has_tag = sample.contains("OPLC-");
        if has_tag && sample.contains(" #") {
            Confidence::Yes
        } else if has_tag {
            Confidence::Maybe(50)
        } else {
            Confidence::No
        }
    }

    fn parse_line(&self, line: &str, line_no: usize) -> Result<RawRecord, ParseError> {
        // Tolerate any leading label (e.g. "Event - ") by anchoring on "OPLC-".
        let start = line
            .find("OPLC-")
            .ok_or(ParseError::NotOplc { line: line_no })?;
        let rest = &line[start..];

        // Split header from payload on " #" (fall back to a bare '#').
        let (header, payload) = rest
            .split_once(" #")
            .or_else(|| rest.split_once('#'))
            .ok_or_else(|| ParseError::Envelope {
                line: line_no,
                reason: "missing '#' separator".into(),
            })?;

        let (tenant, collector_ts) = parse_header(header, line_no)?;
        let payload = payload.trim();

        // Events carry raw XML after the CSV meta prefix; N/P/I are pure CSV.
        if let Some(lt) = payload.find('<') {
            decode_event(
                line,
                line_no,
                tenant,
                collector_ts,
                &payload[..lt],
                &payload[lt..],
            )
        } else {
            decode_csv(line, line_no, tenant, collector_ts, payload)
        }
    }
}

/// Parse `OPLC-<tenant>,<collector_ts_ms>,<src_ip>` → (tenant, collector_ts).
fn parse_header(header: &str, line_no: usize) -> Result<(String, Option<Timestamp>), ParseError> {
    let mut it = header.trim().splitn(3, ',');
    let tag = it.next().unwrap_or("");
    let tenant = tag.strip_prefix("OPLC-").unwrap_or(tag).to_string();
    let collector_ts = it.next().and_then(parse_epoch_millis);
    // it.next() (the header src_ip) is redundant with the payload src_ip; ignore.
    if tenant.is_empty() {
        return Err(ParseError::Envelope {
            line: line_no,
            reason: "empty tenant".into(),
        });
    }
    Ok((tenant, collector_ts))
}

/// Common envelope metadata extracted positionally relative to the logset marker.
struct Meta<'a> {
    generated_ts: Option<&'a str>,
    hostname: Option<&'a str>,
    source_ip: Option<&'a str>,
    agent_version: Option<&'a str>,
}

/// Extract the meta prefix given the token slice and the index of the logset letter.
fn meta_from<'a>(tokens: &[&'a str], logset_idx: usize) -> Meta<'a> {
    let at = |back: usize| logset_idx.checked_sub(back).map(|i| tokens[i]);
    Meta {
        source_ip: at(1),
        hostname: at(2),
        generated_ts: at(3),
        agent_version: at(4),
    }
}

/// Attach envelope metadata to a record under `env.*` keys and set ts/host/ip.
fn apply_meta(rec: &mut RawRecord, tenant: &str, collector_ts: Option<Timestamp>, meta: &Meta) {
    rec.put("env.tenant", tenant);
    if let Some(ts) = collector_ts {
        rec.put("env.collector_ts_ms", ts.millis().to_string());
    }
    if let Some(g) = meta.generated_ts {
        rec.put("env.generated_ts_s", g);
    }
    if let Some(h) = meta.hostname {
        rec.put("env.hostname", h);
        if rec.host.is_none() {
            rec.host = Some(h.to_string());
        }
    }
    if let Some(ip) = meta.source_ip {
        rec.put("env.source_ip", ip);
        rec.source_ip = Some(ip.to_string());
    }
    if let Some(av) = meta.agent_version {
        rec.put("env.agent_version", av);
    }
}

// ---------------------------------------------------------------------------
// Event (logset E) — schema-aware Windows XML
// ---------------------------------------------------------------------------

fn decode_event(
    raw: &str,
    line_no: usize,
    tenant: String,
    collector_ts: Option<Timestamp>,
    meta_csv: &str,
    xml: &str,
) -> Result<RawRecord, ParseError> {
    // meta_csv looks like "generated_ts,hostname,src_ip,E," — drop the trailing comma.
    let meta_csv = meta_csv.trim_end_matches(',');
    let tokens: Vec<&str> = meta_csv.split(',').map(str::trim).collect();
    let logset_idx = tokens.len().saturating_sub(1); // the 'E'
    let meta = meta_from(&tokens, logset_idx);

    let fields = extract_xml_fields(xml).map_err(|reason| ParseError::Xml {
        line: line_no,
        reason,
    })?;

    // Event time: prefer the XML's own TimeCreated; fall back to generated_ts.
    let ts = fields
        .get("TimeCreated_SystemTime")
        .and_then(|s| parse_iso8601(s))
        .or_else(|| meta.generated_ts.and_then(parse_epoch_seconds))
        .or(collector_ts)
        .unwrap_or(Timestamp(0));

    let mut rec = RawRecord::new(RecordKind::Event, ts, raw);
    // Prefer the XML Computer (FQDN) as the host for events.
    rec.host = fields.get("Computer").cloned();
    for (k, v) in fields {
        rec.put(k, v);
    }
    apply_meta(&mut rec, &tenant, collector_ts, &meta);
    Ok(rec)
}

/// Flatten a Windows Event XML string into the prototype's key convention:
/// `<System>` children become `Tag` (text) or `Tag_Attr` (attributes), and each
/// `<Data Name="X">v</Data>` becomes `X: v`. Any Windows event is captured
/// generically — nothing is hardcoded per Event ID.
fn extract_xml_fields(xml: &str) -> Result<BTreeMap<String, String>, String> {
    #[derive(PartialEq)]
    enum Section {
        None,
        System,
        EventData,
    }

    let mut reader = Reader::from_str(xml);
    let mut fields: BTreeMap<String, String> = BTreeMap::new();
    let mut section = Section::None;
    let mut cur_key: Option<String> = None; // element/Data currently accumulating text
    let mut text = String::new();

    loop {
        match reader.read_event() {
            Ok(XmlEvent::Start(e)) => {
                let name = qname_local(e.name());
                match name.as_str() {
                    "System" => section = Section::System,
                    "EventData" => section = Section::EventData,
                    _ => match section {
                        Section::System => {
                            record_attrs(&e, &name, &mut fields)?;
                            cur_key = Some(name);
                            text.clear();
                        }
                        Section::EventData if name == "Data" => {
                            cur_key = attr_value(&e, b"Name")?;
                            text.clear();
                        }
                        _ => {}
                    },
                }
            }
            Ok(XmlEvent::Empty(e)) => {
                let name = qname_local(e.name());
                match section {
                    Section::System if name != "System" => {
                        record_attrs(&e, &name, &mut fields)?;
                    }
                    Section::EventData if name == "Data" => {
                        if let Some(k) = attr_value(&e, b"Name")? {
                            fields.entry(k).or_default();
                        }
                    }
                    _ => {}
                }
            }
            Ok(XmlEvent::Text(e)) => {
                let t = e.unescape().map_err(|x| x.to_string())?;
                text.push_str(&t);
            }
            Ok(XmlEvent::End(e)) => {
                let name = qname_local(e.name());
                if name == "System" || name == "EventData" {
                    section = Section::None;
                    cur_key = None;
                    text.clear();
                } else if let Some(key) = cur_key.take() {
                    let val = text.trim();
                    if !val.is_empty() {
                        fields.entry(key).or_insert_with(|| val.to_string());
                    }
                    text.clear();
                }
            }
            Ok(XmlEvent::Eof) => break,
            Err(e) => return Err(e.to_string()),
            _ => {}
        }
    }
    if fields.is_empty() {
        return Err("no fields extracted from XML".into());
    }
    Ok(fields)
}

fn qname_local(name: QName) -> String {
    String::from_utf8_lossy(name.local_name().as_ref()).into_owned()
}

fn record_attrs(
    e: &BytesStart,
    tag: &str,
    fields: &mut BTreeMap<String, String>,
) -> Result<(), String> {
    for a in e.attributes() {
        let a = a.map_err(|x| x.to_string())?;
        let key = qname_local(a.key);
        let val = a.unescape_value().map_err(|x| x.to_string())?.into_owned();
        fields.insert(format!("{tag}_{key}"), val);
    }
    Ok(())
}

fn attr_value(e: &BytesStart, want: &[u8]) -> Result<Option<String>, String> {
    for a in e.attributes() {
        let a = a.map_err(|x| x.to_string())?;
        if a.key.as_ref() == want {
            return Ok(Some(
                a.unescape_value().map_err(|x| x.to_string())?.into_owned(),
            ));
        }
    }
    Ok(None)
}

// ---------------------------------------------------------------------------
// CSV logsets (N / P / I)
// ---------------------------------------------------------------------------

fn decode_csv(
    raw: &str,
    line_no: usize,
    tenant: String,
    collector_ts: Option<Timestamp>,
    payload: &str,
) -> Result<RawRecord, ParseError> {
    let tokens: Vec<&str> = payload.split(',').map(str::trim).collect();
    let logtype_idx = tokens
        .iter()
        .position(|t| *t == NETWORK || *t == NEW_PROCESS || *t == FILE_INTEGRITY)
        .ok_or_else(|| ParseError::UnknownLogset {
            line: line_no,
            logset: payload.chars().take(40).collect(),
        })?;
    let logtype = tokens[logtype_idx];
    let logset_idx = logtype_idx
        .checked_sub(1)
        .ok_or_else(|| ParseError::Envelope {
            line: line_no,
            reason: "no logset before logtype".into(),
        })?;
    let meta = meta_from(&tokens, logset_idx);
    let rest = &tokens[logtype_idx + 1..];

    let mut rec = match logtype {
        NETWORK => decode_network(raw, line_no, rest)?,
        NEW_PROCESS => decode_process(raw, rest, &meta),
        FILE_INTEGRITY => decode_integrity(raw, line_no, rest)?,
        _ => unreachable!("logtype was matched above"),
    };

    // Set best event time from generated_ts (seconds) for N/P/I.
    if let Some(ts) = meta.generated_ts.and_then(parse_epoch_seconds) {
        rec.ts = ts;
    } else if let Some(ts) = collector_ts {
        rec.ts = ts;
    }
    apply_meta(&mut rec, &tenant, collector_ts, &meta);
    Ok(rec)
}

/// `protocol, srcip, srcport, destip, destport, pid, process`
fn decode_network(raw: &str, line_no: usize, rest: &[&str]) -> Result<RawRecord, ParseError> {
    if rest.len() < 7 {
        return Err(ParseError::Payload {
            line: line_no,
            kind: "network",
            reason: format!("expected 7 fields after NETWORK, got {}", rest.len()),
        });
    }
    let mut rec = RawRecord::new(RecordKind::Network, Timestamp(0), raw);
    rec.put("protocol", rest[0]);
    rec.put("src_ip", rest[1]);
    rec.put("src_port", rest[2]);
    rec.put("dst_ip", rest[3]);
    rec.put("dst_port", rest[4]);
    rec.put("pid", rest[5]);
    rec.put("process", rest[6]);
    Ok(rec)
}

/// `pid, processname [, fullpath, parentfolder, user, parentpid, parentprocess]`
/// — variable arity; some agents stop after `processname`.
fn decode_process(raw: &str, rest: &[&str], _meta: &Meta) -> RawRecord {
    let mut rec = RawRecord::new(RecordKind::Process, Timestamp(0), raw);
    let get = |i: usize| rest.get(i).copied().unwrap_or("");
    rec.put("pid", get(0));
    rec.put("process", get(1));
    rec.put("full_path", get(2));
    rec.put("parent_folder", get(3));
    rec.put("user", get(4));
    rec.put("parent_pid", get(5));
    rec.put("parent_process", get(6));
    rec
}

/// `<reserved/empty>, action, filepath…, hash` — rejoin middle tokens for the
/// path (it may contain commas); the hash is always last.
fn decode_integrity(raw: &str, line_no: usize, rest: &[&str]) -> Result<RawRecord, ParseError> {
    if rest.len() < 4 {
        return Err(ParseError::Payload {
            line: line_no,
            kind: "integrity",
            reason: format!(
                "expected >=4 fields after FILE_INTEGRITY, got {}",
                rest.len()
            ),
        });
    }
    let mut rec = RawRecord::new(RecordKind::Integrity, Timestamp(0), raw);
    rec.put("reserved", rest[0]);
    rec.put("action", rest[1]);
    let last = rest.len() - 1;
    rec.put("file_path", rest[2..last].join(","));
    rec.put("hash", rest[last]);
    Ok(rec)
}

#[cfg(test)]
mod tests {
    use super::*;

    const EVENT: &str = "OPLC-acme,1782858033704,192.168.140.13 #1782858369,ACMEHQDB01,192.168.140.13,E,<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/><EventID>4673</EventID><TimeCreated SystemTime='2026-06-30T22:26:08.7149364Z'/><Execution ProcessID='4' ThreadID='14040'/><Channel>Security</Channel><Computer>ACMEDCDB01.acme.local</Computer><Security/></System><EventData><Data Name='SubjectUserName'>john.doe</Data><Data Name='SubjectDomainName'>acme</Data><Data Name='PrivilegeList'>SeTcbPrivilege</Data><Data Name='ProcessId'>0x3268</Data><Data Name='ProcessName'>C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe</Data></EventData></Event>";
    const NET: &str = "OPLC-acme,1782858062494,10.0.9.85 #1782858197,ACMEWEB01,10.0.9.85,N,NETWORK,TCP,10.0.9.85,59145,203.0.113.10,80,3232,svchost.exe";
    const PROC: &str = "OPLC-acme,1782857847190,192.168.140.67 #3.4.8,1782858183,ACMEAPP01,192.168.140.67,P,NEW_PROCESS,8856,WmiPrvSE.exe,C:\\Windows\\System32\\wbem\\WmiPrvSE.exe,C:\\Windows\\System32\\wbem,NT AUTHORITY\\NETWORK SERVICE,968,svchost.exe";
    const INTEG: &str = "OPLC-acme,1782858058738,192.168.140.28 #1782858394,ACMEPDB01,192.168.140.28,I,FILE_INTEGRITY,,MODIFIED,C:\\Program Files\\ExampleApp\\log\\log.txt,fdc0d5ddfb1e5b70e0d8008c559e3f55";

    fn parse(line: &str) -> RawRecord {
        OplcParser::new().parse_line(line, 1).expect("parses")
    }

    #[test]
    fn detects_format() {
        assert_eq!(OplcParser.can_parse(EVENT), Confidence::Yes);
        assert_eq!(OplcParser.can_parse("random text"), Confidence::No);
    }

    #[test]
    fn event_xml_is_schema_aware() {
        let r = parse(EVENT);
        assert_eq!(r.kind, RecordKind::Event);
        assert_eq!(r.get("EventID"), Some("4673"));
        assert_eq!(r.get("SubjectUserName"), Some("john.doe"));
        assert_eq!(r.get("PrivilegeList"), Some("SeTcbPrivilege"));
        assert_eq!(r.get("ProcessId"), Some("0x3268")); // hex PID preserved verbatim
        assert!(r.get("ProcessName").unwrap().ends_with("msedge.exe"));
        assert_eq!(
            r.get("Provider_Name"),
            Some("Microsoft-Windows-Security-Auditing")
        );
        assert_eq!(r.get("Execution_ProcessID"), Some("4"));
        // Host prefers the XML Computer (FQDN), not the envelope hostname.
        assert_eq!(r.host.as_deref(), Some("ACMEDCDB01.acme.local"));
        // Time comes from the XML TimeCreated (.714 ms), not generated_ts.
        assert_eq!(r.ts.millis(), 1_782_858_368_714);
        assert_eq!(r.get("env.tenant"), Some("acme"));
        assert_eq!(r.get("env.hostname"), Some("ACMEHQDB01"));
    }

    #[test]
    fn network_fields() {
        let r = parse(NET);
        assert_eq!(r.kind, RecordKind::Network);
        assert_eq!(r.get("protocol"), Some("TCP"));
        assert_eq!(r.get("src_ip"), Some("10.0.9.85"));
        assert_eq!(r.get("src_port"), Some("59145"));
        assert_eq!(r.get("dst_ip"), Some("203.0.113.10"));
        assert_eq!(r.get("dst_port"), Some("80"));
        assert_eq!(r.get("pid"), Some("3232"));
        assert_eq!(r.get("process"), Some("svchost.exe"));
        assert_eq!(r.host.as_deref(), Some("ACMEWEB01"));
        assert_eq!(r.ts, Timestamp(1_782_858_197_000)); // generated_ts * 1000
    }

    #[test]
    fn process_fields_full() {
        let r = parse(PROC);
        assert_eq!(r.kind, RecordKind::Process);
        assert_eq!(r.get("pid"), Some("8856"));
        assert_eq!(r.get("process"), Some("WmiPrvSE.exe"));
        assert_eq!(
            r.get("full_path"),
            Some("C:\\Windows\\System32\\wbem\\WmiPrvSE.exe")
        );
        assert_eq!(r.get("parent_folder"), Some("C:\\Windows\\System32\\wbem"));
        assert_eq!(r.get("user"), Some("NT AUTHORITY\\NETWORK SERVICE"));
        assert_eq!(r.get("parent_pid"), Some("968"));
        assert_eq!(r.get("parent_process"), Some("svchost.exe"));
        assert_eq!(r.get("env.agent_version"), Some("3.4.8"));
        assert_eq!(r.host.as_deref(), Some("ACMEAPP01"));
    }

    #[test]
    fn process_truncated_arity() {
        let line =
            "OPLC-acme,1,10.0.0.1 #3.4.8,1782858183,HOST01,10.0.0.1,P,NEW_PROCESS,4242,calc.exe";
        let r = parse(line);
        assert_eq!(r.get("pid"), Some("4242"));
        assert_eq!(r.get("process"), Some("calc.exe"));
        assert_eq!(r.get("full_path"), None); // absent fields dropped, not errored
    }

    #[test]
    fn integrity_fields_with_hash() {
        let r = parse(INTEG);
        assert_eq!(r.kind, RecordKind::Integrity);
        assert_eq!(r.get("action"), Some("MODIFIED"));
        assert_eq!(
            r.get("file_path"),
            Some("C:\\Program Files\\ExampleApp\\log\\log.txt")
        );
        assert_eq!(r.get("hash"), Some("fdc0d5ddfb1e5b70e0d8008c559e3f55"));
        assert_eq!(r.host.as_deref(), Some("ACMEPDB01"));
    }

    #[test]
    fn tolerates_leading_label() {
        let r = parse(&format!("Network - {NET}"));
        assert_eq!(r.kind, RecordKind::Network);
    }

    #[test]
    fn non_oplc_line_errors() {
        let err = OplcParser::new()
            .parse_line("just some text", 7)
            .unwrap_err();
        assert!(matches!(err, ParseError::NotOplc { line: 7 }));
    }
}
