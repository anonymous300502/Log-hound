//! Loading and validation of `rules.yaml`.
//!
//! Schema-compatible with the original prototype so all 36 rules load unchanged
//! (`PLAN.md` §9). Three rule shapes are supported:
//!
//! - `atomic`   — a single-event `filter`.
//! - `threshold`— count matches within `window` seconds grouped by `group_by`.
//! - `chain`    — `step_1` then `step_2` within `window`, correlated on `match_on`.
//!
//! ```yaml
//! detection_rules:
//!   - id: BF_01
//!     type: threshold
//!     class: 3002
//!     filter: "status == 'Failure'"
//!     threshold: 15
//!     window: 60
//!     group_by: "src_endpoint.ip"
//!     mitre_attack: "T1110 - Brute Force"
//! ```

use std::path::Path;

use serde::{Deserialize, Serialize};

#[derive(Debug, thiserror::Error)]
pub enum RulesError {
    #[error("failed to read rules file {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse YAML: {0}")]
    Yaml(#[from] serde_yaml::Error),
    #[error("rule '{id}' is invalid: {reason}")]
    Invalid { id: String, reason: String },
}

/// The kind of a detection rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleType {
    Atomic,
    Threshold,
    Chain,
}

/// One step of a `chain` rule.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuleStep {
    #[serde(default)]
    pub class: Option<u32>,
    pub filter: String,
}

/// A single detection rule (union of atomic/threshold/chain fields).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    pub name: String,
    #[serde(rename = "type")]
    pub rule_type: RuleType,
    pub severity: String,
    #[serde(default)]
    pub class: Option<u32>,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub mitre_attack: Option<String>,

    // atomic / threshold
    #[serde(default)]
    pub filter: Option<String>,
    // threshold
    #[serde(default)]
    pub threshold: Option<u64>,
    #[serde(default)]
    pub window: Option<u64>,
    #[serde(default)]
    pub group_by: Option<String>,
    // chain
    #[serde(default)]
    pub step_1: Option<RuleStep>,
    #[serde(default)]
    pub step_2: Option<RuleStep>,
    #[serde(default)]
    pub match_on: Option<String>,
}

impl Rule {
    /// Validate that the fields required by this rule's `type` are present.
    fn validate(&self) -> Result<(), RulesError> {
        let bad = |reason: &str| RulesError::Invalid {
            id: self.id.clone(),
            reason: reason.to_string(),
        };
        match self.rule_type {
            RuleType::Atomic => {
                if self.filter.is_none() {
                    return Err(bad("atomic rule requires `filter`"));
                }
            }
            RuleType::Threshold => {
                if self.filter.is_none() {
                    return Err(bad("threshold rule requires `filter`"));
                }
                if self.threshold.is_none() || self.window.is_none() {
                    return Err(bad("threshold rule requires `threshold` and `window`"));
                }
            }
            RuleType::Chain => {
                if self.step_1.is_none() || self.step_2.is_none() {
                    return Err(bad("chain rule requires `step_1` and `step_2`"));
                }
                if self.match_on.is_none() || self.window.is_none() {
                    return Err(bad("chain rule requires `match_on` and `window`"));
                }
            }
        }
        Ok(())
    }
}

/// The full contents of a `rules.yaml` file.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuleSet {
    pub detection_rules: Vec<Rule>,
}

impl RuleSet {
    pub fn from_yaml_str(s: &str) -> Result<Self, RulesError> {
        let set: RuleSet = serde_yaml::from_str(s)?;
        set.validate()?;
        Ok(set)
    }

    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, RulesError> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path).map_err(|source| RulesError::Io {
            path: path.display().to_string(),
            source,
        })?;
        Self::from_yaml_str(&text)
    }

    pub fn len(&self) -> usize {
        self.detection_rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.detection_rules.is_empty()
    }

    pub fn get(&self, id: &str) -> Option<&Rule> {
        self.detection_rules.iter().find(|r| r.id == id)
    }

    fn validate(&self) -> Result<(), RulesError> {
        for r in &self.detection_rules {
            r.validate()?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn workspace_rules() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../config/rules.yaml")
    }

    #[test]
    fn parses_each_rule_type() {
        let yaml = r#"
detection_rules:
  - id: A1
    name: atomic
    type: atomic
    severity: high
    filter: "process.name == 'mimikatz.exe'"
  - id: T1
    name: thresh
    type: threshold
    severity: high
    filter: "status == 'Failure'"
    threshold: 15
    window: 60
    group_by: "src_endpoint.ip"
  - id: C1
    name: chain
    type: chain
    severity: critical
    step_1: { class: 3002, filter: "status == 'Success'" }
    step_2: { class: 1007, filter: "process.name == 'cmd.exe'" }
    window: 30
    match_on: "dst_endpoint.hostname"
"#;
        let set = RuleSet::from_yaml_str(yaml).expect("valid");
        assert_eq!(set.len(), 3);
        assert_eq!(set.get("T1").unwrap().threshold, Some(15));
        assert_eq!(set.get("C1").unwrap().rule_type, RuleType::Chain);
    }

    #[test]
    fn rejects_threshold_missing_window() {
        let yaml = r#"
detection_rules:
  - id: BAD
    name: bad
    type: threshold
    severity: high
    filter: "x == 'y'"
    threshold: 5
"#;
        let err = RuleSet::from_yaml_str(yaml).unwrap_err();
        assert!(matches!(err, RulesError::Invalid { .. }));
    }

    #[test]
    fn loads_backwards_compatible_prototype_file() {
        let set =
            RuleSet::from_path(workspace_rules()).expect("prototype rules.yaml must still load");
        // The prototype's rules.yaml contains 36 rules (the ~"32" figure in
        // PLAN.md §9 was an estimate; counting the file gives 36).
        assert_eq!(set.len(), 36, "prototype rules.yaml ships 36 rules");
        let bf01 = set.get("BF_01").expect("BF_01 present");
        assert_eq!(bf01.rule_type, RuleType::Threshold);
        assert_eq!(bf01.threshold, Some(15));
        assert_eq!(bf01.window, Some(60));
        assert_eq!(bf01.group_by.as_deref(), Some("src_endpoint.ip"));
        // Every rule should carry a MITRE mapping.
        let missing: Vec<_> = set
            .detection_rules
            .iter()
            .filter(|r| r.mitre_attack.is_none())
            .map(|r| r.id.clone())
            .collect();
        assert!(
            missing.is_empty(),
            "rules missing mitre_attack: {missing:?}"
        );
    }
}
