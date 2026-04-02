use std::path::Path;

use anyhow::{Context, Result};
use tracing::{debug, info, warn};
use watchpost_types::Rule;

/// Load rules from all `.yaml` files in a directory.
///
/// Each YAML file should contain a list of [`Rule`] definitions.
/// The returned rules are sorted by severity (Critical first).
pub fn load_rules_from_dir(dir: &Path) -> Result<Vec<Rule>> {
    if !dir.is_dir() {
        anyhow::bail!("Rules directory does not exist: {}", dir.display());
    }

    let mut all_rules = Vec::new();

    let entries = std::fs::read_dir(dir)
        .with_context(|| format!("Failed to read rules directory: {}", dir.display()))?;

    for entry in entries {
        let entry = entry?;
        let path = entry.path();

        if path.extension().and_then(|e| e.to_str()) != Some("yaml") {
            continue;
        }

        debug!("Loading rules from {}", path.display());

        let contents = std::fs::read_to_string(&path)
            .with_context(|| format!("Failed to read rule file: {}", path.display()))?;

        match load_rules_from_str(&contents) {
            Ok(rules) => {
                info!("Loaded {} rules from {}", rules.len(), path.display());
                all_rules.extend(rules);
            }
            Err(e) => {
                warn!("Failed to parse rule file {}: {}", path.display(), e);
                return Err(e)
                    .with_context(|| format!("Failed to parse rule file: {}", path.display()));
            }
        }
    }

    // Sort by severity descending (Critical first)
    all_rules.sort_by(|a, b| b.severity.cmp(&a.severity));

    info!("Loaded {} total rules", all_rules.len());
    Ok(all_rules)
}

/// Parse a YAML string as a list of rules.
pub fn load_rules_from_str(yaml: &str) -> Result<Vec<Rule>> {
    let rules: Vec<Rule> =
        serde_yml::from_str(yaml).context("Failed to deserialize rules from YAML")?;
    Ok(rules)
}

#[cfg(test)]
mod tests {
    use super::*;
    use watchpost_types::Severity;

    const SAMPLE_RULES_YAML: &str = r#"
- name: npm-reverse-shell
  description: "npm postinstall script connecting to a reverse shell port"
  severity: critical
  conditions:
    and:
      - ancestor_binary_matches:
          - npm
          - npx
      - dest_port_is:
          - 4444
          - 5555
  action: block

- name: any-temp-dir-exec
  description: "Process executed from a temporary directory"
  severity: medium
  conditions:
    exec_from_temp_dir: null
  action: notify
"#;

    #[test]
    fn parse_yaml_rules() {
        let rules = load_rules_from_str(SAMPLE_RULES_YAML).expect("parse rules");
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].name, "npm-reverse-shell");
        assert_eq!(rules[0].severity, Severity::Critical);
        assert_eq!(rules[1].name, "any-temp-dir-exec");
        assert_eq!(rules[1].severity, Severity::Medium);
    }

    #[test]
    fn rules_sorted_after_dir_load() {
        // Load from string and manually sort to simulate dir loading
        let yaml = r#"
- name: low-rule
  description: "Low severity rule"
  severity: low
  conditions:
    exec_from_temp_dir: null
  action: log

- name: critical-rule
  description: "Critical severity rule"
  severity: critical
  conditions:
    privilege_change: null
  action: block

- name: medium-rule
  description: "Medium severity rule"
  severity: medium
  conditions:
    exec_from_temp_dir: null
  action: notify
"#;
        let mut rules = load_rules_from_str(yaml).expect("parse rules");
        rules.sort_by(|a, b| b.severity.cmp(&a.severity));

        assert_eq!(rules[0].name, "critical-rule");
        assert_eq!(rules[0].severity, Severity::Critical);
        assert_eq!(rules[1].name, "medium-rule");
        assert_eq!(rules[1].severity, Severity::Medium);
        assert_eq!(rules[2].name, "low-rule");
        assert_eq!(rules[2].severity, Severity::Low);
    }
}
