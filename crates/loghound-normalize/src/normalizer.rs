//! [`Normalizer`] — turns a [`RawRecord`] into an OCSF-like
//! [`loghound_core::Event`] (`PLAN.md` §7).
//!
//! Events are mapped with `mappings.yaml` on top of a small set of generic
//! Windows→OCSF field conventions, so *any* event (even ones without a specific
//! mapping, e.g. 4673) still yields typed user/host/process fields. The three
//! non-Windows logsets (Network/Process/Integrity) use built-in mappings.
//! Anything not mapped is preserved in [`Event::extra`] — never dropped.

use std::collections::HashSet;

use loghound_core::event::class;
use loghound_core::Event;
use loghound_parsers::{RawRecord, RecordKind};

use crate::config::MappingConfig;

/// Generic Windows-field → OCSF-path conventions applied to every event before
/// its specific `mappings.yaml` entry (which may refine these).
const GENERIC_WINDOWS_FIELDS: &[(&str, &str)] = &[
    ("Computer", "host.hostname"),
    ("TargetUserName", "user.name"),
    ("TargetDomainName", "user.domain"),
    ("TargetUserSid", "user.uid"),
    ("SubjectUserName", "actor.user.name"),
    ("SubjectDomainName", "actor.user.domain"),
    ("SubjectUserSid", "actor.user.uid"),
    ("SubjectLogonId", "session.uid"),
    ("IpAddress", "src_endpoint.ip"),
    ("IpPort", "src_endpoint.port"),
    ("WorkstationName", "src_endpoint.hostname"),
    ("ProcessName", "process.name"),
    ("ProcessId", "process.pid"),
    ("NewProcessName", "process.name"),
    ("NewProcessId", "process.pid"),
    ("CommandLine", "process.cmd_line"),
    ("ParentProcessName", "parent_process.name"),
    ("CreatorProcessId", "parent_process.pid"),
];

/// Windows LogonType → OCSF auth protocol (ported from the prototype's
/// `LOGON_TYPE_MAPPING`).
fn logon_type_to_auth_protocol(lt: &str) -> Option<&'static str> {
    Some(match lt {
        "2" => "Interactive",
        "3" => "Network",
        "4" => "Batch",
        "5" => "Service",
        "7" => "Unlock",
        "8" => "NetworkCleartext",
        "9" => "NewCredentials",
        "10" => "RemoteInteractive",
        "11" => "CachedInteractive",
        _ => return None,
    })
}

/// Parse a Windows PID that may be hex (`0x3268`, common in Security events) or
/// decimal (`8856`, from process logs) into a canonical decimal value. This
/// reconciliation is what lets M3 correlate XML events with process telemetry.
fn parse_pid(s: &str) -> Option<i64> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        i64::from_str_radix(hex, 16).ok()
    } else {
        s.parse().ok()
    }
}

/// Route an OCSF dotted path to a typed hot column when one exists, else stash it
/// in `Event::fields`. Mirrors the typed columns [`Event::get`] reads.
fn set_ocsf(ev: &mut Event, path: &str, value: String) {
    match path {
        "user.name" => ev.user_name = Some(value),
        "actor.user.name" => ev.actor_user = Some(value),
        "src_endpoint.ip" => ev.src_ip = Some(value),
        "dst_endpoint.ip" => ev.dst_ip = Some(value),
        "process.name" => ev.process_name = Some(value),
        "process.pid" => {
            if let Some(pid) = parse_pid(&value) {
                ev.process_pid = Some(pid);
            } else {
                ev.set_field(path, value);
            }
        }
        "parent_process.pid" => {
            if let Some(pid) = parse_pid(&value) {
                ev.parent_pid = Some(pid);
            } else {
                ev.set_field(path, value);
            }
        }
        "host.hostname" => {
            if ev.host.is_none() {
                ev.host = Some(value);
            } else {
                ev.set_field(path, value);
            }
        }
        _ => ev.set_field(path, value),
    }
}

/// Normalizes [`RawRecord`]s into [`Event`]s using the loaded mappings.
pub struct Normalizer {
    mappings: MappingConfig,
}

impl Normalizer {
    pub fn new(mappings: MappingConfig) -> Self {
        Normalizer { mappings }
    }

    /// Normalize one record. Never fails: unmapped fields are preserved in `extra`.
    pub fn normalize(&self, rec: &RawRecord) -> Event {
        match rec.kind {
            RecordKind::Event => self.normalize_event(rec),
            RecordKind::Network => normalize_network(rec),
            RecordKind::Process => normalize_process(rec),
            RecordKind::Integrity => normalize_integrity(rec),
        }
    }

    fn normalize_event(&self, rec: &RawRecord) -> Event {
        let mut ev = Event::new(0, rec.ts);
        ev.host = rec.host.clone();
        ev.raw = Some(rec.raw.clone());
        ev.event_code = rec.get("EventID").and_then(|s| s.parse().ok());

        let mut consumed: HashSet<&str> = HashSet::new();
        consumed.insert("EventID"); // represented by event_code

        // 1) generic Windows conventions (apply to any event)
        for (src, path) in GENERIC_WINDOWS_FIELDS {
            if let Some(v) = rec.get(src) {
                set_ocsf(&mut ev, path, v.to_string());
                consumed.insert(src);
            }
        }

        // 2) specific mapping for this Event ID (refines/overrides generic)
        if let Some(id) = rec.get("EventID") {
            if let Some(m) = self.mappings.get(id) {
                ev.class_uid = m.ocsf_class;
                for (src, path) in &m.mapping {
                    if let Some(v) = rec.get(src) {
                        set_ocsf(&mut ev, path, v.to_string());
                        consumed.insert(src.as_str());
                    }
                }
            }
        }

        // 3) enrichment: auth protocol from logon type, plus the event-code-driven
        //    activity/status/outcome fields the detection rules read (ported from
        //    the prototype's `mapper.py` `_enrich_*`, `PLAN.md` §7, §9).
        if let Some(lt) = rec.get("LogonType") {
            if let Some(ap) = logon_type_to_auth_protocol(lt) {
                ev.set_field("auth_protocol", ap);
            }
        }
        enrich_by_event_code(&mut ev, rec);

        // 4) preserve everything else (unmapped source fields + envelope meta)
        for (k, v) in &rec.fields {
            if k.starts_with("env.") || !consumed.contains(k.as_str()) {
                ev.extra.insert(k.clone(), v.clone());
            }
        }
        ev
    }
}

/// Event-code-driven enrichment for Windows XML events, ported verbatim from the
/// prototype's `mapper.py` `_enrich_authentication` / `_enrich_account_change` /
/// `_enrich_network`. These set the `status`, `activity_id`, and `activity_name`
/// fields the detection rules (`rules.yaml`) compare against.
fn enrich_by_event_code(ev: &mut Event, rec: &RawRecord) {
    match ev.event_code {
        // ---- authentication (class 3002) ----
        Some(4624) => {
            ev.activity_id = Some(1); // Logon
            ev.set_field("activity_name", "Logon");
            ev.set_field("status", "Success");
            ev.status_id = Some(1);
        }
        Some(4625) => {
            ev.activity_id = Some(1); // Logon
            ev.set_field("activity_name", "Logon");
            ev.set_field("status", "Failure");
            ev.status_id = Some(2);
            ev.severity_id = Some(2);
            ev.set_field("severity", "Low");
        }
        Some(4768) => {
            ev.activity_id = Some(3); // Authentication Ticket
            ev.set_field("activity_name", "Authentication Ticket");
            ev.set_field("status", "Success");
            ev.status_id = Some(1);
        }
        // ---- account change (class 3006) ----
        Some(4720) => {
            ev.activity_id = Some(1); // Create
            ev.set_field("activity_name", "Create");
        }
        Some(4732) => {
            ev.activity_id = Some(2); // Add to Group
            ev.set_field("activity_name", "Add to Group");
        }
        _ => {}
    }
    // Share access (class 4001) events carry a ShareName; the prototype tagged
    // them activity_id 6. Only applies to Windows XML network events.
    // (`group.name` for 4732 is already handled by `mappings.yaml`, which maps
    // that event's `TargetUserName` — the group — directly to `group.name`.)
    if ev.class_uid == class::NETWORK_ACTIVITY {
        if let Some(share) = rec.get("ShareName") {
            ev.activity_id = Some(6);
            ev.set_field("activity_name", "Share Access");
            ev.set_field("share_name", share);
        }
    }
}

fn base_event(rec: &RawRecord, class_uid: u32) -> Event {
    let mut ev = Event::new(class_uid, rec.ts);
    ev.host = rec.host.clone();
    ev.raw = Some(rec.raw.clone());
    ev
}

/// Copy all `env.*` envelope metadata into `extra`.
fn carry_envelope(ev: &mut Event, rec: &RawRecord) {
    for (k, v) in &rec.fields {
        if k.starts_with("env.") {
            ev.extra.insert(k.clone(), v.clone());
        }
    }
}

fn normalize_network(rec: &RawRecord) -> Event {
    let mut ev = base_event(rec, class::NETWORK_ACTIVITY);
    if let Some(v) = rec.get("protocol") {
        ev.set_field("connection.protocol", v);
    }
    if let Some(v) = rec.get("src_ip") {
        ev.src_ip = Some(v.to_string());
    }
    if let Some(v) = rec.get("src_port") {
        ev.set_field("src_endpoint.port", v);
    }
    if let Some(v) = rec.get("dst_ip") {
        ev.dst_ip = Some(v.to_string());
    }
    if let Some(v) = rec.get("dst_port") {
        ev.set_field("dst_endpoint.port", v);
    }
    if let Some(v) = rec.get("pid") {
        ev.process_pid = parse_pid(v);
    }
    if let Some(v) = rec.get("process") {
        ev.process_name = Some(v.to_string());
    }
    carry_envelope(&mut ev, rec);
    ev
}

fn normalize_process(rec: &RawRecord) -> Event {
    let mut ev = base_event(rec, class::PROCESS_ACTIVITY);
    ev.activity_id = Some(1); // Launch
    if let Some(v) = rec.get("pid") {
        ev.process_pid = parse_pid(v);
    }
    if let Some(v) = rec.get("process") {
        ev.process_name = Some(v.to_string());
    }
    if let Some(v) = rec.get("full_path") {
        ev.set_field("process.file.path", v);
    }
    if let Some(v) = rec.get("parent_folder") {
        ev.set_field("process.parent_folder", v);
    }
    if let Some(v) = rec.get("user") {
        ev.user_name = Some(v.to_string());
    }
    if let Some(v) = rec.get("parent_pid") {
        ev.parent_pid = parse_pid(v);
    }
    if let Some(v) = rec.get("parent_process") {
        ev.set_field("parent_process.name", v);
    }
    carry_envelope(&mut ev, rec);
    ev
}

fn normalize_integrity(rec: &RawRecord) -> Event {
    let mut ev = base_event(rec, class::FILE_ACTIVITY);
    if let Some(v) = rec.get("action") {
        ev.set_field("activity_name", v);
    }
    if let Some(v) = rec.get("file_path") {
        ev.set_field("file.path", v);
    }
    if let Some(v) = rec.get("hash") {
        ev.set_field("file.hash_md5", v);
    }
    if let Some(v) = rec.get("reserved") {
        ev.set_field("integrity.reserved", v);
    }
    carry_envelope(&mut ev, rec);
    ev
}

#[cfg(test)]
mod tests {
    use super::*;
    use loghound_parsers::{OplcParser, Parser};
    use std::path::PathBuf;

    fn normalizer() -> Normalizer {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../config/mappings.yaml");
        Normalizer::new(MappingConfig::from_path(path).expect("mappings load"))
    }

    fn parse_one(line: &str) -> RawRecord {
        OplcParser::new().parse_line(line, 1).expect("parses")
    }

    const EVENT_4624: &str = "OPLC-acme,1782858033704,10.0.0.5 #1782858369,DC01,10.0.0.5,E,<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><EventID>4624</EventID><TimeCreated SystemTime='2026-06-30T22:26:08.000Z'/><Computer>DC01.corp.local</Computer></System><EventData><Data Name='TargetUserName'>alice</Data><Data Name='TargetDomainName'>CORP</Data><Data Name='IpAddress'>10.0.0.9</Data><Data Name='LogonType'>3</Data></EventData></Event>";
    const EVENT_4673: &str = "OPLC-acme,1782858033704,192.168.140.13 #1782858369,ACMEHQDB01,192.168.140.13,E,<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><EventID>4673</EventID><Computer>ACMEDCDB01.acme.local</Computer></System><EventData><Data Name='SubjectUserName'>john.doe</Data><Data Name='ProcessId'>0x3268</Data><Data Name='ProcessName'>C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe</Data></EventData></Event>";
    const NET: &str = "OPLC-acme,1782858062494,10.0.9.85 #1782858197,ACMEWEB01,10.0.9.85,N,NETWORK,TCP,10.0.9.85,59145,203.0.113.10,80,3232,svchost.exe";
    const PROC: &str = "OPLC-acme,1782857847190,192.168.140.67 #3.4.8,1782858183,ACMEAPP01,192.168.140.67,P,NEW_PROCESS,8856,WmiPrvSE.exe,C:\\Windows\\System32\\wbem\\WmiPrvSE.exe,C:\\Windows\\System32\\wbem,NT AUTHORITY\\NETWORK SERVICE,968,svchost.exe";
    const INTEG: &str = "OPLC-acme,1782858058738,192.168.140.28 #1782858394,ACMEPDB01,192.168.140.28,I,FILE_INTEGRITY,,MODIFIED,C:\\Program Files\\ExampleApp\\log\\log.txt,fdc0d5ddfb1e5b70e0d8008c559e3f55";

    #[test]
    fn mapped_event_populates_typed_fields_and_enrichment() {
        let ev = normalizer().normalize(&parse_one(EVENT_4624));
        assert_eq!(ev.class_uid, class::AUTHENTICATION);
        assert_eq!(ev.event_code, Some(4624));
        assert_eq!(ev.user_name.as_deref(), Some("alice"));
        assert_eq!(ev.src_ip.as_deref(), Some("10.0.0.9"));
        assert_eq!(ev.host.as_deref(), Some("DC01.corp.local"));
        assert_eq!(ev.get("auth_protocol").as_deref(), Some("Network")); // LogonType 3
        assert_eq!(
            ev.get("dst_endpoint.hostname").as_deref(),
            Some("DC01.corp.local")
        );
        // Envelope metadata preserved.
        assert_eq!(ev.extra.get("env.tenant").map(String::as_str), Some("acme"));
    }

    #[test]
    fn auth_enrichment_sets_status_and_activity() {
        // 4624 → successful logon (the fields the detection rules read).
        let ev = normalizer().normalize(&parse_one(EVENT_4624));
        assert_eq!(ev.get("status").as_deref(), Some("Success"));
        assert_eq!(ev.get("activity_id").as_deref(), Some("1"));
        assert_eq!(ev.get("activity_name").as_deref(), Some("Logon"));
        assert_eq!(ev.status_id, Some(1));
    }

    #[test]
    fn unmapped_event_still_extracted_generically_with_hex_pid() {
        let ev = normalizer().normalize(&parse_one(EVENT_4673));
        assert_eq!(ev.class_uid, 0); // no specific mapping for 4673
        assert_eq!(ev.event_code, Some(4673));
        assert_eq!(ev.actor_user.as_deref(), Some("john.doe")); // generic SubjectUserName
        assert!(ev.process_name.as_deref().unwrap().ends_with("msedge.exe"));
        assert_eq!(ev.process_pid, Some(0x3268)); // hex 0x3268 -> 12904 decimal
                                                  // Unmapped privilege detail preserved.
    }

    #[test]
    fn network_maps_to_ocsf() {
        let ev = normalizer().normalize(&parse_one(NET));
        assert_eq!(ev.class_uid, class::NETWORK_ACTIVITY);
        assert_eq!(ev.src_ip.as_deref(), Some("10.0.9.85"));
        assert_eq!(ev.dst_ip.as_deref(), Some("203.0.113.10"));
        assert_eq!(ev.process_pid, Some(3232));
        assert_eq!(ev.process_name.as_deref(), Some("svchost.exe"));
        assert_eq!(ev.get("dst_endpoint.port").as_deref(), Some("80"));
    }

    #[test]
    fn process_maps_to_ocsf_with_lineage() {
        let ev = normalizer().normalize(&parse_one(PROC));
        assert_eq!(ev.class_uid, class::PROCESS_ACTIVITY);
        assert_eq!(ev.process_pid, Some(8856));
        assert_eq!(ev.process_name.as_deref(), Some("WmiPrvSE.exe"));
        assert_eq!(ev.parent_pid, Some(968));
        assert_eq!(
            ev.user_name.as_deref(),
            Some("NT AUTHORITY\\NETWORK SERVICE")
        );
        assert_eq!(
            ev.get("parent_process.name").as_deref(),
            Some("svchost.exe")
        );
    }

    #[test]
    fn integrity_maps_to_file_activity() {
        let ev = normalizer().normalize(&parse_one(INTEG));
        assert_eq!(ev.class_uid, class::FILE_ACTIVITY);
        assert_eq!(ev.get("activity_name").as_deref(), Some("MODIFIED"));
        assert_eq!(
            ev.get("file.path").as_deref(),
            Some("C:\\Program Files\\ExampleApp\\log\\log.txt")
        );
        assert_eq!(
            ev.get("file.hash_md5").as_deref(),
            Some("fdc0d5ddfb1e5b70e0d8008c559e3f55")
        );
    }
}
