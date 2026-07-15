//! Loading and validation of `mappings.yaml`.
//!
//! The schema is intentionally identical to the original prototype so existing
//! mapping files load unchanged (`PLAN.md` "backwards compatibility"):
//!
//! ```yaml
//! event_mapping:
//!   "4624":
//!     ocsf_class: 3002
//!     description: "Account logon - successful"
//!     mapping:
//!       TargetUserName: user.name
//!       IpAddress: src_endpoint.ip
//! ```

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

/// Errors that can occur while loading a mapping configuration.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("failed to read config file {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse YAML: {0}")]
    Yaml(#[from] serde_yaml::Error),
    #[error("mapping validation failed: {0}")]
    Invalid(String),
}

/// The full contents of a `mappings.yaml` file.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MappingConfig {
    /// Windows Event ID (as a string key, e.g. `"4624"`) → its OCSF mapping.
    pub event_mapping: BTreeMap<String, EventMapping>,
}

/// The mapping for a single source event type.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EventMapping {
    /// Target OCSF class UID (e.g. `3002` for Authentication).
    pub ocsf_class: u32,
    #[serde(default)]
    pub description: String,
    /// Source field name → dotted OCSF path (e.g. `TargetUserName: user.name`).
    #[serde(default)]
    pub mapping: BTreeMap<String, String>,
}

impl MappingConfig {
    /// Parse a mapping config from a YAML string.
    pub fn from_yaml_str(s: &str) -> Result<Self, ConfigError> {
        let cfg: MappingConfig = serde_yaml::from_str(s)?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Load and validate a mapping config from a file path.
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Io {
            path: path.display().to_string(),
            source,
        })?;
        Self::from_yaml_str(&text)
    }

    /// Number of configured event mappings.
    pub fn len(&self) -> usize {
        self.event_mapping.len()
    }

    pub fn is_empty(&self) -> bool {
        self.event_mapping.is_empty()
    }

    /// Look up the mapping for a source event id (e.g. `"4624"`).
    pub fn get(&self, event_id: &str) -> Option<&EventMapping> {
        self.event_mapping.get(event_id)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.event_mapping.is_empty() {
            return Err(ConfigError::Invalid("event_mapping is empty".into()));
        }
        for (id, m) in &self.event_mapping {
            if m.ocsf_class == 0 {
                return Err(ConfigError::Invalid(format!(
                    "event {id}: ocsf_class must be non-zero"
                )));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// Path to the workspace `config/mappings.yaml` (the backwards-compat file).
    fn workspace_mappings() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../config/mappings.yaml")
    }

    #[test]
    fn parses_inline_yaml() {
        let yaml = r#"
event_mapping:
  "4624":
    ocsf_class: 3002
    description: "Account logon - successful"
    mapping:
      TargetUserName: user.name
      IpAddress: src_endpoint.ip
"#;
        let cfg = MappingConfig::from_yaml_str(yaml).expect("valid");
        let m = cfg.get("4624").expect("4624 present");
        assert_eq!(m.ocsf_class, 3002);
        assert_eq!(m.mapping.get("TargetUserName").unwrap(), "user.name");
    }

    #[test]
    fn rejects_empty_mapping() {
        let err = MappingConfig::from_yaml_str("event_mapping: {}").unwrap_err();
        assert!(matches!(err, ConfigError::Invalid(_)));
    }

    #[test]
    fn loads_backwards_compatible_prototype_file() {
        let cfg = MappingConfig::from_path(workspace_mappings())
            .expect("prototype mappings.yaml must still load");
        // The prototype documents 21 event IDs across 4 OCSF classes (PLAN.md §7).
        assert!(cfg.len() >= 21, "expected >=21 mappings, got {}", cfg.len());
        // Spot-check a representative auth mapping.
        let m = cfg.get("4624").expect("4624 present");
        assert_eq!(m.ocsf_class, 3002);
        assert_eq!(
            m.mapping.get("TargetUserName").map(String::as_str),
            Some("user.name")
        );
    }
}
