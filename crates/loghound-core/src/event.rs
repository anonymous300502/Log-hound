//! The normalized [`Event`] — the OCSF-like record every parser emits.
//!
//! Hot fields the detection engine and graph builder read most often are typed
//! columns; the long tail of normalized OCSF leaf fields lives in `fields`
//! (dotted keys, e.g. `"process.cmd_line"`). Anything a mapping did not claim is
//! preserved in `extra` — telemetry is never silently dropped, which fixes the
//! prototype's never-populated `unmapped` (`PLAN.md` §7). The layout mirrors the
//! DuckDB `events` table (`PLAN.md` §4).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::ids::EventId;
use crate::time::Timestamp;

/// OCSF class UIDs used by LogHound. The first four match the original prototype
/// (`mappings.yaml`); `FILE_ACTIVITY` is added for File Integrity telemetry.
pub mod class {
    /// Authentication (logon/kerberos/ntlm).
    pub const AUTHENTICATION: u32 = 3002;
    /// Process Activity (creation/termination, incl. NEW_PROCESS logs).
    pub const PROCESS_ACTIVITY: u32 = 1007;
    /// Account Change (create/enable/disable/group membership).
    pub const ACCOUNT_CHANGE: u32 = 3006;
    /// Network Activity (share access, connections, NETWORK logs).
    pub const NETWORK_ACTIVITY: u32 = 4001;
    /// File System Activity (File Integrity logs). Added additively (`PLAN.md` §7).
    pub const FILE_ACTIVITY: u32 = 1001;
}

/// A single normalized telemetry record.
///
/// `event_id` is assigned by the ingest pipeline (0 until then). Optional typed
/// fields are `None` when the source event does not carry them.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Event {
    pub event_id: EventId,
    /// OCSF metadata UID (e.g. a UUID string); stable per source event.
    pub ocsf_uid: String,
    pub ts: Timestamp,
    pub class_uid: u32,
    pub activity_id: Option<i32>,
    /// Raw source event code (e.g. Windows EventID 4624), when applicable.
    pub event_code: Option<i32>,

    // ---- typed hot columns (mirror the DuckDB `events` table) ----
    pub host: Option<String>,
    pub src_ip: Option<String>,
    pub dst_ip: Option<String>,
    pub user_name: Option<String>,
    pub actor_user: Option<String>,
    pub process_pid: Option<i64>,
    pub parent_pid: Option<i64>,
    pub process_name: Option<String>,
    pub status_id: Option<i32>,
    pub severity_id: Option<i32>,

    // ---- long tail ----
    /// Normalized OCSF leaf fields keyed by dotted path (e.g. `"process.cmd_line"`).
    pub fields: BTreeMap<String, String>,
    /// Source fields no mapping claimed (never dropped).
    pub extra: BTreeMap<String, String>,
    /// Original source text (kept cold; stored separately in DuckDB).
    pub raw: Option<String>,
}

impl Event {
    /// A minimal event of `class_uid` at `ts`. Builder-style setters/`fields`
    /// fill in the rest during normalization.
    pub fn new(class_uid: u32, ts: Timestamp) -> Event {
        Event {
            event_id: EventId::new(0),
            ocsf_uid: String::new(),
            ts,
            class_uid,
            activity_id: None,
            event_code: None,
            host: None,
            src_ip: None,
            dst_ip: None,
            user_name: None,
            actor_user: None,
            process_pid: None,
            parent_pid: None,
            process_name: None,
            status_id: None,
            severity_id: None,
            fields: BTreeMap::new(),
            extra: BTreeMap::new(),
            raw: None,
        }
    }

    /// Resolve a dotted field path the way the detection DSL will (`PLAN.md` §9):
    /// typed hot columns first, then `fields`, then `extra`.
    ///
    /// Returns an owned `String` because typed columns are not all `String`.
    pub fn get(&self, path: &str) -> Option<String> {
        // Typed hot columns, addressed by their canonical dotted path.
        let typed = match path {
            "time" => Some(self.ts.millis().to_string()),
            "class_uid" => Some(self.class_uid.to_string()),
            "activity_id" => self.activity_id.map(|v| v.to_string()),
            "event_code" => self.event_code.map(|v| v.to_string()),
            "host.hostname" => self.host.clone(),
            "src_endpoint.ip" => self.src_ip.clone(),
            "dst_endpoint.ip" => self.dst_ip.clone(),
            "user.name" => self.user_name.clone(),
            "actor.user.name" => self.actor_user.clone(),
            "process.pid" => self.process_pid.map(|v| v.to_string()),
            "parent_process.pid" => self.parent_pid.map(|v| v.to_string()),
            "process.name" => self.process_name.clone(),
            "status_id" => self.status_id.map(|v| v.to_string()),
            "severity_id" => self.severity_id.map(|v| v.to_string()),
            _ => None,
        };
        if typed.is_some() {
            return typed;
        }
        self.fields
            .get(path)
            .or_else(|| self.extra.get(path))
            .cloned()
    }

    /// Set a normalized leaf field by dotted path (used by the mapper).
    pub fn set_field(&mut self, path: impl Into<String>, value: impl Into<String>) {
        self.fields.insert(path.into(), value.into());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_prefers_typed_then_fields_then_extra() {
        let mut e = Event::new(class::PROCESS_ACTIVITY, Timestamp(1000));
        e.process_name = Some("powershell.exe".into());
        e.set_field("process.cmd_line", "powershell -enc AAA");
        e.extra.insert("Provider_Name".into(), "Sysmon".into());

        assert_eq!(e.get("process.name").as_deref(), Some("powershell.exe")); // typed
        assert_eq!(
            e.get("process.cmd_line").as_deref(),
            Some("powershell -enc AAA")
        ); // fields
        assert_eq!(e.get("Provider_Name").as_deref(), Some("Sysmon")); // extra
        assert_eq!(e.get("time").as_deref(), Some("1000"));
        assert_eq!(e.get("nonexistent"), None);
    }
}
