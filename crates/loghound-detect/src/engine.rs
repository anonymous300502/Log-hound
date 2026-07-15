//! The detection engine (`PLAN.md` §9): compiles [`RuleSet`] rules into an
//! executable IR and evaluates a stream of [`Event`]s, emitting [`Alert`]s.
//!
//! Three detector shapes, faithful to the prototype's semantics:
//!
//! - **atomic** — fires on every event matching an (optional) class gate and a
//!   filter expression.
//! - **threshold** — counts filter-matching events sharing a `group_by` value in
//!   a sliding `window`; fires when the count reaches `threshold`, then resets
//!   that group's window (the prototype's `deque.clear()` on fire).
//! - **sequence** — the generalized `chain`: `step_1 … step_N` correlated on a
//!   `match_on` field, each within `window` of the first step. `rules.yaml` only
//!   ships 2-step chains; the engine handles N steps. Reduces exactly to the
//!   prototype's step-2-first, no-clear (re-fireable) behavior for N = 2.
//!
//! Unlike the prototype (which trusted CSV order), [`Engine::run`] sorts events
//! by timestamp first, so window math is correct across interleaved multi-host
//! sources.

use std::collections::{HashMap, HashSet, VecDeque};

use loghound_core::Event;

use crate::dsl::Expr;
use crate::rules::{Rule, RuleSet, RuleType, RulesError};

/// A detection result. `alert_id` is deterministic (`rule_id:group:ts`) — unlike
/// the prototype's wall-clock id — so re-running ingest is idempotent.
#[derive(Debug, Clone)]
pub struct Alert {
    pub alert_id: String,
    pub rule_id: String,
    pub rule_name: String,
    pub severity: String,
    /// Full MITRE tag as written in the rule (`"T1110 - Brute Force"`).
    pub mitre: Option<String>,
    /// Just the technique/tactic id (`"T1110"`).
    pub mitre_id: Option<String>,
    pub description: String,
    pub rule_type: RuleType,
    /// Fire time in epoch-ms (the triggering event's timestamp).
    pub ts: i64,
    /// The group / correlation value that anchored the alert, if any.
    pub group_key: Option<String>,
    /// Contributing event ids (provenance → the graph/evidence view).
    pub event_ids: Vec<u64>,
}

impl Alert {
    /// Stable lowercase name of the rule type that produced this alert.
    pub fn rule_type_name(&self) -> &'static str {
        match self.rule_type {
            RuleType::Atomic => "atomic",
            RuleType::Threshold => "threshold",
            RuleType::Chain => "chain",
        }
    }

    /// Composite severity → a 0–100 risk score for graph rendering.
    pub fn risk(&self) -> f32 {
        match self.severity.to_ascii_lowercase().as_str() {
            "critical" => 100.0,
            "high" => 75.0,
            "medium" => 50.0,
            "low" => 25.0,
            _ => 40.0,
        }
    }
}

/// Shared rule metadata carried onto every alert.
#[derive(Debug, Clone)]
struct Meta {
    id: String,
    name: String,
    severity: String,
    description: String,
    mitre: Option<String>,
    rule_type: RuleType,
}

/// One step of a sequence detector.
#[derive(Debug)]
struct Step {
    class: Option<u32>,
    filter: Expr,
}

/// The executable form of a rule.
#[derive(Debug)]
enum Detector {
    Atomic {
        class: Option<u32>,
        filter: Expr,
    },
    Threshold {
        class: Option<u32>,
        filter: Expr,
        threshold: u64,
        window_ms: i64,
        group_by: Option<String>,
    },
    Sequence {
        steps: Vec<Step>,
        window_ms: i64,
        match_on: String,
    },
}

#[derive(Debug)]
struct CompiledRule {
    meta: Meta,
    detector: Detector,
}

/// A compiled, ready-to-run rule set.
#[derive(Debug)]
pub struct CompiledRuleSet {
    rules: Vec<CompiledRule>,
}

impl CompiledRuleSet {
    /// Compile a loaded [`RuleSet`] — parsing every filter into a DSL AST.
    pub fn compile(set: &RuleSet) -> Result<CompiledRuleSet, RulesError> {
        let mut rules = Vec::with_capacity(set.detection_rules.len());
        for r in &set.detection_rules {
            rules.push(compile_rule(r)?);
        }
        Ok(CompiledRuleSet { rules })
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
}

fn compile_err(id: &str, reason: impl Into<String>) -> RulesError {
    RulesError::Invalid {
        id: id.to_string(),
        reason: reason.into(),
    }
}

fn parse_filter(id: &str, filter: &str) -> Result<Expr, RulesError> {
    Expr::parse(filter).map_err(|e| compile_err(id, format!("bad filter `{filter}`: {e}")))
}

fn compile_rule(r: &Rule) -> Result<CompiledRule, RulesError> {
    let meta = Meta {
        id: r.id.clone(),
        name: r.name.clone(),
        severity: r.severity.clone(),
        description: r.description.clone(),
        mitre: r.mitre_attack.clone(),
        rule_type: r.rule_type,
    };
    let detector = match r.rule_type {
        RuleType::Atomic => {
            let f = r
                .filter
                .as_deref()
                .ok_or_else(|| compile_err(&r.id, "atomic rule requires `filter`"))?;
            Detector::Atomic {
                class: r.class,
                filter: parse_filter(&r.id, f)?,
            }
        }
        RuleType::Threshold => {
            let f = r
                .filter
                .as_deref()
                .ok_or_else(|| compile_err(&r.id, "threshold rule requires `filter`"))?;
            let threshold = r
                .threshold
                .ok_or_else(|| compile_err(&r.id, "threshold rule requires `threshold`"))?;
            let window = r
                .window
                .ok_or_else(|| compile_err(&r.id, "threshold rule requires `window`"))?;
            Detector::Threshold {
                class: r.class,
                filter: parse_filter(&r.id, f)?,
                threshold,
                window_ms: window as i64 * 1000,
                group_by: r.group_by.clone(),
            }
        }
        RuleType::Chain => {
            let s1 = r
                .step_1
                .as_ref()
                .ok_or_else(|| compile_err(&r.id, "chain rule requires `step_1`"))?;
            let s2 = r
                .step_2
                .as_ref()
                .ok_or_else(|| compile_err(&r.id, "chain rule requires `step_2`"))?;
            let window = r
                .window
                .ok_or_else(|| compile_err(&r.id, "chain rule requires `window`"))?;
            let match_on = r
                .match_on
                .clone()
                .ok_or_else(|| compile_err(&r.id, "chain rule requires `match_on`"))?;
            let steps = vec![
                Step {
                    class: s1.class,
                    filter: parse_filter(&r.id, &s1.filter)?,
                },
                Step {
                    class: s2.class,
                    filter: parse_filter(&r.id, &s2.filter)?,
                },
            ];
            Detector::Sequence {
                steps,
                window_ms: window as i64 * 1000,
                match_on,
            }
        }
    };
    Ok(CompiledRule { meta, detector })
}

/// A live partial sequence match: steps `0..=last_step` satisfied.
#[derive(Debug, Clone)]
struct Partial {
    first_ts: i64,
    event_ids: Vec<u64>,
}

/// The stateful detection engine.
pub struct Engine {
    rules: CompiledRuleSet,
    /// Threshold sliding windows: (rule_idx, group_key) → (ts, event_id) ring.
    thresh: HashMap<(usize, String), VecDeque<(i64, u64)>>,
    /// Sequence partials: (rule_idx, last_completed_step, corr_value) → partials.
    seq: HashMap<(usize, usize, String), Vec<Partial>>,
}

impl Engine {
    pub fn new(rules: CompiledRuleSet) -> Self {
        Engine {
            rules,
            thresh: HashMap::new(),
            seq: HashMap::new(),
        }
    }

    /// Compile a rule set and build an engine in one step.
    pub fn from_rules(set: &RuleSet) -> Result<Self, RulesError> {
        Ok(Engine::new(CompiledRuleSet::compile(set)?))
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Run detection over a batch, sorting by timestamp first (a correctness
    /// improvement over the prototype's reliance on input order).
    pub fn run(&mut self, events: &[Event]) -> Vec<Alert> {
        let mut order: Vec<&Event> = events.iter().collect();
        order.sort_by_key(|e| (e.ts.millis(), e.event_id.raw()));
        let mut alerts = Vec::new();
        for e in order {
            self.process_into(e, &mut alerts);
        }
        alerts
    }

    /// Process a single event, returning any alerts it fires.
    pub fn process(&mut self, e: &Event) -> Vec<Alert> {
        let mut alerts = Vec::new();
        self.process_into(e, &mut alerts);
        alerts
    }

    fn process_into(&mut self, e: &Event, out: &mut Vec<Alert>) {
        for ri in 0..self.rules.rules.len() {
            // Peek the detector kind with a short borrow, then dispatch (the
            // threshold/sequence paths need `&mut self`, so we can't hold a
            // reference to `self.rules` across them).
            let kind = match &self.rules.rules[ri].detector {
                Detector::Atomic { .. } => 0u8,
                Detector::Threshold { .. } => 1,
                Detector::Sequence { .. } => 2,
            };
            match kind {
                0 => {
                    let rule = &self.rules.rules[ri];
                    if let Detector::Atomic { class, filter } = &rule.detector {
                        if class_matches(*class, e) && filter.eval(e) {
                            out.push(make_alert(
                                &rule.meta,
                                e.ts.millis(),
                                None,
                                vec![e.event_id.raw()],
                            ));
                        }
                    }
                }
                1 => {
                    if let Some(a) = self.eval_threshold(ri, e) {
                        out.push(a);
                    }
                }
                _ => self.eval_sequence(ri, e, out),
            }
        }
    }

    fn eval_threshold(&mut self, ri: usize, e: &Event) -> Option<Alert> {
        let (threshold, window_ms, group_key) = {
            let Detector::Threshold {
                class,
                filter,
                threshold,
                window_ms,
                group_by,
            } = &self.rules.rules[ri].detector
            else {
                return None;
            };
            if !class_matches(*class, e) || !filter.eval(e) {
                return None;
            }
            let group_key = match group_by {
                Some(f) => e
                    .get(f)
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| "unknown".into()),
                None => "default".into(),
            };
            (*threshold, *window_ms, group_key)
        };

        let now = e.ts.millis();
        let buf = self.thresh.entry((ri, group_key.clone())).or_default();
        buf.push_back((now, e.event_id.raw()));
        let cutoff = now - window_ms;
        while let Some(&(ts, _)) = buf.front() {
            if ts < cutoff {
                buf.pop_front();
            } else {
                break;
            }
        }
        if buf.len() as u64 >= threshold {
            let ids: Vec<u64> = buf.iter().map(|&(_, id)| id).collect();
            buf.clear();
            return Some(make_alert(
                &self.rules.rules[ri].meta,
                now,
                Some(group_key),
                ids,
            ));
        }
        None
    }

    fn eval_sequence(&mut self, ri: usize, e: &Event, out: &mut Vec<Alert>) {
        // Find the highest step index this event satisfies (step-2-before-step-1
        // exclusivity, mirroring the prototype's if/elif).
        let (n_steps, window_ms, match_on, matched_step) = {
            let rule = &self.rules.rules[ri];
            let Detector::Sequence {
                steps,
                window_ms,
                match_on,
            } = &rule.detector
            else {
                return;
            };
            let mut matched = None;
            for s in (0..steps.len()).rev() {
                if class_matches(steps[s].class, e) && steps[s].filter.eval(e) {
                    matched = Some(s);
                    break;
                }
            }
            (steps.len(), *window_ms, match_on.clone(), matched)
        };
        let Some(s) = matched_step else { return };
        let now = e.ts.millis();
        let corr = e.get(&match_on).unwrap_or_default();

        if s == 0 {
            // Seed a new partial (keyed by correlation value).
            self.seq.entry((ri, 0, corr)).or_default().push(Partial {
                first_ts: now,
                event_ids: vec![e.event_id.raw()],
            });
            return;
        }

        // Advancing step: needs a truthy correlation value and a live predecessor
        // partial within the window (prototype returns None on empty corr).
        if corr.is_empty() {
            return;
        }
        let prev_key = (ri, s - 1, corr.clone());
        let cutoff = now - window_ms;
        let advanced: Vec<Partial> = {
            let Some(partials) = self.seq.get_mut(&prev_key) else {
                return;
            };
            // Drop stale predecessors; keep those within the window.
            partials.retain(|p| p.first_ts >= cutoff);
            partials
                .iter()
                .map(|p| {
                    let mut ids = p.event_ids.clone();
                    ids.push(e.event_id.raw());
                    Partial {
                        first_ts: p.first_ts,
                        event_ids: ids,
                    }
                })
                .collect()
        };
        if advanced.is_empty() {
            return;
        }
        if s == n_steps - 1 {
            // Fire — do NOT clear predecessors (prototype re-fires per step-2).
            let meta = &self.rules.rules[ri].meta;
            for p in advanced {
                out.push(make_alert(meta, now, Some(corr.clone()), p.event_ids));
            }
        } else {
            self.seq.entry((ri, s, corr)).or_default().extend(advanced);
        }
    }
}

/// Optional class gate: `true` if the rule has no class, or the event matches it.
fn class_matches(class: Option<u32>, e: &Event) -> bool {
    match class {
        Some(c) => e.class_uid == c,
        None => true,
    }
}

fn make_alert(meta: &Meta, ts: i64, group_key: Option<String>, event_ids: Vec<u64>) -> Alert {
    let group_part = group_key.as_deref().unwrap_or("-");
    let alert_id = format!("{}:{}:{}", meta.id, group_part, ts);
    let mitre_id = meta
        .mitre
        .as_ref()
        .map(|m| m.split(" - ").next().unwrap_or(m).trim().to_string());
    Alert {
        alert_id,
        rule_id: meta.id.clone(),
        rule_name: meta.name.clone(),
        severity: meta.severity.clone(),
        mitre: meta.mitre.clone(),
        mitre_id,
        description: meta.description.clone(),
        rule_type: meta.rule_type,
        ts,
        group_key,
        event_ids,
    }
}

/// Deduplicate alerts by `alert_id`, keeping the first occurrence and preserving
/// order (sequence rules can re-fire an identical alert).
pub fn dedup_alerts(alerts: Vec<Alert>) -> Vec<Alert> {
    let mut seen = HashSet::new();
    alerts
        .into_iter()
        .filter(|a| seen.insert(a.alert_id.clone()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use loghound_core::event::class;
    use loghound_core::{EventId, Timestamp};

    fn rules() -> RuleSet {
        let yaml = r#"
detection_rules:
  - id: A_PS
    name: "Suspicious PowerShell"
    type: atomic
    severity: high
    class: 1007
    filter: "process.name == 'powershell.exe' AND process.cmd_line CONTAINS '-enc'"
    description: "encoded powershell"
    mitre_attack: "T1059.001 - PowerShell"
  - id: BF
    name: "Brute Force"
    type: threshold
    severity: high
    class: 3002
    filter: "status == 'Failure'"
    threshold: 3
    window: 60
    group_by: "src_endpoint.ip"
    mitre_attack: "T1110 - Brute Force"
  - id: LM
    name: "Lateral Movement"
    type: chain
    severity: critical
    step_1: { class: 3002, filter: "auth_protocol == 'Network' AND status == 'Success'" }
    step_2: { class: 1007, filter: "process.name IN ['cmd.exe', 'powershell.exe']" }
    window: 30
    match_on: "dst_endpoint.hostname"
    mitre_attack: "T1021 - Remote Services"
"#;
        RuleSet::from_yaml_str(yaml).expect("valid rules")
    }

    fn engine() -> Engine {
        Engine::from_rules(&rules()).expect("compiles")
    }

    fn auth(id: u64, ts: i64, ip: &str, status: &str, ap: &str, host: &str) -> Event {
        let mut e = Event::new(class::AUTHENTICATION, Timestamp(ts));
        e.event_id = EventId::new(id);
        e.src_ip = Some(ip.into());
        e.set_field("status", status);
        e.set_field("auth_protocol", ap);
        e.set_field("dst_endpoint.hostname", host);
        e
    }

    fn proc(id: u64, ts: i64, name: &str, cmd: &str, host: &str) -> Event {
        let mut e = Event::new(class::PROCESS_ACTIVITY, Timestamp(ts));
        e.event_id = EventId::new(id);
        e.process_name = Some(name.into());
        e.set_field("process.cmd_line", cmd);
        e.set_field("dst_endpoint.hostname", host);
        e
    }

    #[test]
    fn atomic_fires_on_match_only() {
        let mut eng = engine();
        let hit = proc(1, 10, "powershell.exe", "powershell -enc AAAA", "H1");
        let miss = proc(2, 11, "powershell.exe", "powershell Get-Process", "H1");
        assert_eq!(eng.process(&hit).len(), 1);
        assert_eq!(eng.process(&miss).len(), 0);
    }

    #[test]
    fn threshold_fires_at_count_then_resets() {
        let mut eng = engine();
        // Two failures: no alert yet.
        assert!(eng
            .process(&auth(1, 1000, "10.0.0.1", "Failure", "Network", "H"))
            .is_empty());
        assert!(eng
            .process(&auth(2, 2000, "10.0.0.1", "Failure", "Network", "H"))
            .is_empty());
        // Third within window: fires with all 3 events.
        let fired = eng.process(&auth(3, 3000, "10.0.0.1", "Failure", "Network", "H"));
        assert_eq!(fired.len(), 1);
        assert_eq!(fired[0].rule_id, "BF");
        assert_eq!(fired[0].event_ids.len(), 3);
        assert_eq!(fired[0].group_key.as_deref(), Some("10.0.0.1"));
        // Buffer cleared → next failure alone does not re-fire.
        assert!(eng
            .process(&auth(4, 4000, "10.0.0.1", "Failure", "Network", "H"))
            .is_empty());
    }

    #[test]
    fn threshold_groups_are_independent() {
        let mut eng = engine();
        for i in 0..2 {
            assert!(eng
                .process(&auth(
                    i,
                    1000 + i as i64,
                    "10.0.0.1",
                    "Failure",
                    "Network",
                    "H"
                ))
                .is_empty());
        }
        // A different IP has its own count.
        assert!(eng
            .process(&auth(9, 1500, "10.0.0.2", "Failure", "Network", "H"))
            .is_empty());
    }

    #[test]
    fn threshold_window_expiry() {
        let mut eng = engine();
        // Two failures far apart, then two close → only the close ones count.
        assert!(eng
            .process(&auth(1, 0, "10.0.0.1", "Failure", "Network", "H"))
            .is_empty());
        assert!(eng
            .process(&auth(2, 100_000, "10.0.0.1", "Failure", "Network", "H"))
            .is_empty()); // >60s later, prunes #1
        assert!(eng
            .process(&auth(3, 100_500, "10.0.0.1", "Failure", "Network", "H"))
            .is_empty());
        // 3rd in-window failure fires.
        assert_eq!(
            eng.process(&auth(4, 101_000, "10.0.0.1", "Failure", "Network", "H"))
                .len(),
            1
        );
    }

    #[test]
    fn chain_fires_on_correlated_sequence() {
        let mut eng = engine();
        // Network logon success on host H, then cmd.exe on H within 30s.
        assert!(eng
            .process(&auth(1, 1000, "10.0.0.9", "Success", "Network", "H"))
            .is_empty());
        let fired = eng.process(&proc(2, 5000, "cmd.exe", "cmd /c whoami", "H"));
        assert_eq!(fired.len(), 1);
        assert_eq!(fired[0].rule_id, "LM");
        assert_eq!(fired[0].event_ids, vec![1, 2]);
        assert_eq!(fired[0].group_key.as_deref(), Some("H"));
    }

    #[test]
    fn chain_requires_matching_correlation() {
        let mut eng = engine();
        // Logon on H, process on a DIFFERENT host → no chain.
        assert!(eng
            .process(&auth(1, 1000, "10.0.0.9", "Success", "Network", "H"))
            .is_empty());
        assert!(eng
            .process(&proc(2, 5000, "cmd.exe", "cmd", "OTHER"))
            .is_empty());
    }

    #[test]
    fn chain_respects_window() {
        let mut eng = engine();
        assert!(eng
            .process(&auth(1, 1000, "10.0.0.9", "Success", "Network", "H"))
            .is_empty());
        // Process arrives 40s later (> 30s window) → no chain.
        assert!(eng
            .process(&proc(2, 41_000, "cmd.exe", "cmd", "H"))
            .is_empty());
    }

    #[test]
    fn run_sorts_by_timestamp() {
        // Supply events out of order; run() should still correlate the chain.
        let mut eng = engine();
        let events = vec![
            proc(2, 5000, "cmd.exe", "cmd", "H"),
            auth(1, 1000, "10.0.0.9", "Success", "Network", "H"),
        ];
        let alerts = dedup_alerts(eng.run(&events));
        assert!(alerts.iter().any(|a| a.rule_id == "LM"));
    }

    #[test]
    fn compiles_the_shipped_ruleset() {
        use std::path::PathBuf;
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../config/rules.yaml");
        let set = RuleSet::from_path(path).expect("load");
        let compiled = CompiledRuleSet::compile(&set).expect("all 36 filters compile");
        assert_eq!(compiled.len(), 36);
    }
}
