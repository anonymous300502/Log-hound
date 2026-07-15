//! Minimal Sigma → LogHound rule compiler (`PLAN.md` §9).
//!
//! Sigma is a large spec; this compiler supports the common subset that maps
//! cleanly onto our atomic-rule + filter-DSL IR, so Sigma packs can run through
//! the same evaluator (one engine, not two):
//!
//! - `detection:` with one or more **selection maps** (`field: value`,
//!   `field: [v1, v2]` → `IN`, and the `field|contains` modifier → `CONTAINS`).
//! - `condition:` supporting `sel`, `sel1 and sel2`, `sel1 or sel2`, `not sel`,
//!   `1 of them`, `all of them`, and parentheses.
//! - `logsource:` is recorded but not used for gating (LogHound has no product
//!   channel model yet).
//!
//! Field names are passed through verbatim, so a Sigma pack should use LogHound's
//! OCSF field paths (or be accompanied by a field-mapping — a later enhancement).
//! Unsupported constructs return a [`SigmaError`] rather than silently misfiring.

use serde::Deserialize;
use serde_yaml::Value;

use crate::rules::{Rule, RuleType};

#[derive(Debug, thiserror::Error)]
pub enum SigmaError {
    #[error("failed to parse Sigma YAML: {0}")]
    Yaml(#[from] serde_yaml::Error),
    #[error("Sigma rule missing `detection`")]
    NoDetection,
    #[error("Sigma rule missing `condition`")]
    NoCondition,
    #[error("unknown selection `{0}` referenced in condition")]
    UnknownSelection(String),
    #[error("unsupported condition construct: {0}")]
    UnsupportedCondition(String),
    #[error("unsupported detection value for `{0}`")]
    UnsupportedValue(String),
}

#[derive(Debug, Deserialize)]
struct SigmaDoc {
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    level: Option<String>,
    #[serde(default)]
    tags: Option<Vec<String>>,
    detection: Value,
    #[serde(default)]
    description: Option<String>,
}

/// Compile a single Sigma YAML document into a LogHound [`Rule`] (atomic; its
/// `filter` is our DSL string, ready for [`crate::engine`] to parse).
pub fn compile_sigma(yaml: &str) -> Result<Rule, SigmaError> {
    let doc: SigmaDoc = serde_yaml::from_str(yaml)?;
    let map = doc.detection.as_mapping().ok_or(SigmaError::NoDetection)?;

    // Gather selection definitions and the condition string.
    let mut selections: Vec<(String, String)> = Vec::new(); // (name, DSL fragment)
    let mut condition: Option<String> = None;
    for (k, v) in map {
        let name = k.as_str().unwrap_or_default().to_string();
        if name == "condition" {
            condition = v.as_str().map(str::to_string);
            continue;
        }
        selections.push((name.clone(), selection_to_dsl(&name, v)?));
    }
    let condition = condition.ok_or(SigmaError::NoCondition)?;
    let filter = compile_condition(&condition, &selections)?;

    let severity = doc
        .level
        .map(|l| match l.as_str() {
            "critical" => "critical",
            "high" => "high",
            "low" | "informational" => "low",
            _ => "medium",
        })
        .unwrap_or("medium")
        .to_string();

    let mitre = doc.tags.as_ref().and_then(|tags| {
        tags.iter()
            .find(|t| t.starts_with("attack."))
            .map(|t| t.trim_start_matches("attack.").to_uppercase())
    });

    Ok(Rule {
        id: doc
            .id
            .unwrap_or_else(|| format!("sigma-{}", doc.title.as_deref().unwrap_or("rule"))),
        name: doc.title.unwrap_or_else(|| "Sigma rule".into()),
        rule_type: RuleType::Atomic,
        severity,
        class: None,
        description: doc.description.unwrap_or_default(),
        mitre_attack: mitre,
        filter: Some(filter),
        threshold: None,
        window: None,
        group_by: None,
        step_1: None,
        step_2: None,
        match_on: None,
    })
}

/// Convert one Sigma selection map into a parenthesized DSL fragment (AND of its
/// field predicates).
fn selection_to_dsl(name: &str, v: &Value) -> Result<String, SigmaError> {
    let map = v
        .as_mapping()
        .ok_or_else(|| SigmaError::UnsupportedValue(name.to_string()))?;
    let mut preds = Vec::new();
    for (field, val) in map {
        let raw = field.as_str().unwrap_or_default();
        let (field_name, modifier) = match raw.split_once('|') {
            Some((f, m)) => (f, Some(m)),
            None => (raw, None),
        };
        preds.push(field_pred(field_name, modifier, val)?);
    }
    Ok(format!("({})", preds.join(" AND ")))
}

/// A single `field[|modifier]: value` predicate → DSL.
fn field_pred(field: &str, modifier: Option<&str>, val: &Value) -> Result<String, SigmaError> {
    match val {
        Value::Sequence(items) => {
            let vals: Vec<String> = items
                .iter()
                .map(scalar)
                .collect::<Option<_>>()
                .ok_or_else(|| SigmaError::UnsupportedValue(field.to_string()))?;
            match modifier {
                Some("contains") => {
                    // any-of contains → OR of CONTAINS
                    let ors: Vec<String> = vals
                        .iter()
                        .map(|v| format!("{field} CONTAINS '{}'", esc(v)))
                        .collect();
                    Ok(format!("({})", ors.join(" OR ")))
                }
                None => {
                    let list = vals
                        .iter()
                        .map(|v| format!("'{}'", esc(v)))
                        .collect::<Vec<_>>()
                        .join(", ");
                    Ok(format!("{field} IN [{list}]"))
                }
                Some(m) => Err(SigmaError::UnsupportedValue(format!("{field}|{m}"))),
            }
        }
        other => {
            let v = scalar(other).ok_or_else(|| SigmaError::UnsupportedValue(field.to_string()))?;
            match modifier {
                None => Ok(format!("{field} == '{}'", esc(&v))),
                Some("contains") => Ok(format!("{field} CONTAINS '{}'", esc(&v))),
                Some("re") => Ok(format!("{field} =~ '{}'", esc(&v))),
                Some(m) => Err(SigmaError::UnsupportedValue(format!("{field}|{m}"))),
            }
        }
    }
}

fn scalar(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

/// Escape single quotes so the value is a valid DSL string literal.
fn esc(s: &str) -> String {
    s.replace('\'', "")
}

/// Compile a Sigma `condition` into a DSL boolean expression referencing the
/// named selections. Supports and/or/not, parentheses, `1 of them`,
/// `all of them`.
fn compile_condition(cond: &str, selections: &[(String, String)]) -> Result<String, SigmaError> {
    let lower = cond.trim();
    let all = || {
        selections
            .iter()
            .map(|(_, f)| f.clone())
            .collect::<Vec<_>>()
    };
    match lower {
        "all of them" => return Ok(all().join(" AND ")),
        "1 of them" | "any of them" => return Ok(format!("({})", all().join(" OR "))),
        _ => {}
    }

    // Token substitution: replace selection names with their DSL fragments and
    // keep and/or/not/parentheses. Reject aggregation / near / pipes we can't map.
    if lower.contains('|') || lower.contains(" count(") || lower.contains(" near ") {
        return Err(SigmaError::UnsupportedCondition(cond.to_string()));
    }
    let mut out = String::new();
    for tok in tokenize_condition(lower) {
        match tok.as_str() {
            "and" => out.push_str(" AND "),
            "or" => out.push_str(" OR "),
            "not" => out.push_str(" NOT "),
            "(" => out.push('('),
            ")" => out.push(')'),
            name => {
                let sel = selections
                    .iter()
                    .find(|(n, _)| n == name)
                    .ok_or_else(|| SigmaError::UnknownSelection(name.to_string()))?;
                out.push_str(&sel.1);
            }
        }
    }
    Ok(out.trim().to_string())
}

/// Split a condition into words and parentheses.
fn tokenize_condition(s: &str) -> Vec<String> {
    let mut toks = Vec::new();
    let mut cur = String::new();
    for c in s.chars() {
        match c {
            '(' | ')' => {
                if !cur.is_empty() {
                    toks.push(std::mem::take(&mut cur));
                }
                toks.push(c.to_string());
            }
            c if c.is_whitespace() => {
                if !cur.is_empty() {
                    toks.push(std::mem::take(&mut cur));
                }
            }
            c => cur.push(c),
        }
    }
    if !cur.is_empty() {
        toks.push(cur);
    }
    toks
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::Engine;
    use crate::rules::RuleSet;
    use loghound_core::event::class;
    use loghound_core::{Event, EventId, Timestamp};

    const SIGMA: &str = r#"
title: Encoded PowerShell
id: sig-ps-enc
level: high
tags:
  - attack.t1059.001
detection:
  selection_img:
    process.name: 'powershell.exe'
  selection_flag:
    process.cmd_line|contains:
      - '-enc'
      - '-encodedcommand'
  condition: selection_img and selection_flag
description: Encoded PowerShell command line
"#;

    #[test]
    fn compiles_to_atomic_rule_and_fires() {
        let rule = compile_sigma(SIGMA).expect("compiles");
        assert_eq!(rule.rule_type, RuleType::Atomic);
        assert_eq!(rule.mitre_attack.as_deref(), Some("T1059.001"));
        assert_eq!(rule.severity, "high");

        // Feed it through the real engine.
        let set = RuleSet {
            detection_rules: vec![rule],
        };
        let mut eng = Engine::from_rules(&set).expect("engine");
        let mut hit = Event::new(class::PROCESS_ACTIVITY, Timestamp(1));
        hit.event_id = EventId::new(1);
        hit.process_name = Some("powershell.exe".into());
        hit.set_field("process.cmd_line", "powershell -enc AAAA");
        assert_eq!(eng.process(&hit).len(), 1);

        let mut miss = Event::new(class::PROCESS_ACTIVITY, Timestamp(2));
        miss.event_id = EventId::new(2);
        miss.process_name = Some("powershell.exe".into());
        miss.set_field("process.cmd_line", "powershell Get-Process");
        assert_eq!(eng.process(&miss).len(), 0);
    }

    #[test]
    fn one_of_them_condition() {
        let sigma = r#"
title: Recon Tools
detection:
  a:
    process.name: 'whoami.exe'
  b:
    process.name: 'systeminfo.exe'
  condition: 1 of them
"#;
        let rule = compile_sigma(sigma).expect("compiles");
        let filter = rule.filter.unwrap();
        assert!(filter.contains(" OR "));
    }

    #[test]
    fn rejects_aggregation_condition() {
        let sigma = r#"
title: Agg
detection:
  sel:
    process.name: 'x.exe'
  condition: sel | count() > 5
"#;
        assert!(compile_sigma(sigma).is_err());
    }
}
