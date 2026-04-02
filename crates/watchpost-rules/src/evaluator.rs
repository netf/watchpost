use chrono::Utc;
use uuid::Uuid;
use watchpost_types::{
    ActionContext, Classification, ConditionTree, Confidence, CorrelatedTrace, EventKind,
    Predicate, RecommendedAction, Rule, RuleAction, Severity, Verdict,
};

/// The deterministic rule engine. Evaluates correlated traces against a sorted
/// list of rules (critical first) and produces verdicts for matching rules.
pub struct RuleEngine {
    rules: Vec<Rule>,
}

impl RuleEngine {
    /// Create a new rule engine from a list of rules.
    /// Rules are sorted by severity descending (Critical first).
    pub fn new(mut rules: Vec<Rule>) -> Self {
        rules.sort_by(|a, b| b.severity.cmp(&a.severity));
        Self { rules }
    }

    /// Evaluate a correlated trace against all rules.
    ///
    /// Returns the verdict from the first (highest severity) matching rule,
    /// or `None` if no rule matches.
    pub fn evaluate(&self, trace: &CorrelatedTrace) -> Option<Verdict> {
        for rule in &self.rules {
            if evaluate_condition(&rule.conditions, trace) {
                tracing::info!(
                    rule = %rule.name,
                    severity = ?rule.severity,
                    trace_id = %trace.id,
                    "Rule matched"
                );
                return Some(rule_to_verdict(rule, trace));
            }
        }
        None
    }
}

/// Evaluate a condition tree against a correlated trace.
fn evaluate_condition(tree: &ConditionTree, trace: &CorrelatedTrace) -> bool {
    match tree {
        ConditionTree::And(children) => children.iter().all(|c| evaluate_condition(c, trace)),
        ConditionTree::Or(children) => children.iter().any(|c| evaluate_condition(c, trace)),
        ConditionTree::Leaf(predicate) => evaluate_predicate(predicate, trace),
    }
}

/// Evaluate a single predicate against all events in a correlated trace.
fn evaluate_predicate(predicate: &Predicate, trace: &CorrelatedTrace) -> bool {
    match predicate {
        Predicate::BinaryMatches(bins) => trace.events.iter().any(|e| {
            let binary = match &e.event.kind {
                EventKind::ProcessExec { binary, .. } => Some(binary.as_str()),
                EventKind::ScriptExec { script_path, .. } => Some(script_path.as_str()),
                _ => None,
            };
            if let Some(path) = binary {
                let basename = basename(path);
                bins.iter().any(|b| b == basename)
            } else {
                false
            }
        }),

        Predicate::AncestorBinaryMatches(bins) => trace.events.iter().any(|e| {
            e.ancestry.iter().any(|ancestor| {
                let basename = basename(&ancestor.binary_path);
                bins.iter().any(|b| b == basename)
            })
        }),

        Predicate::FilePathStartsWith(prefixes) => trace.events.iter().any(|e| {
            if let EventKind::FileAccess { path, .. } = &e.event.kind {
                prefixes.iter().any(|prefix| {
                    // Match absolute paths directly
                    if path.starts_with(prefix) {
                        return true;
                    }
                    // Also match home-relative paths like ".ssh/" against full paths
                    // containing the relative component
                    if prefix.starts_with('.') || !prefix.starts_with('/') {
                        // Check if the path contains the relative prefix as a suffix
                        // e.g., "/home/user/.ssh/id_rsa" contains ".ssh/"
                        if let Some(idx) = path.find(prefix) {
                            // Ensure it appears after a separator
                            return idx == 0 || path.as_bytes()[idx - 1] == b'/';
                        }
                    }
                    false
                })
            } else {
                false
            }
        }),

        Predicate::DestPortIs(ports) => trace.events.iter().any(|e| {
            if let EventKind::NetworkConnect { dest_port, .. } = &e.event.kind {
                ports.contains(dest_port)
            } else {
                false
            }
        }),

        Predicate::DestIpOutsideAllowlist => {
            // Phase 2: always false for now
            false
        }

        Predicate::ExecFromTempDir => trace.events.iter().any(|e| {
            if let EventKind::ProcessExec { binary, .. } = &e.event.kind {
                binary.starts_with("/tmp/")
                    || binary.starts_with("/dev/shm/")
                    || binary.starts_with("/var/tmp/")
            } else {
                false
            }
        }),

        Predicate::PrivilegeChange => trace
            .events
            .iter()
            .any(|e| matches!(&e.event.kind, EventKind::PrivilegeChange { .. })),

        Predicate::InFlatpakSandbox => matches!(&trace.context, ActionContext::FlatpakApp { .. }),

        Predicate::DnsQueryHighEntropy { threshold } => trace.events.iter().any(|e| {
            if let EventKind::DnsQuery { query_name, .. } = &e.event.kind {
                shannon_entropy(query_name) > *threshold
            } else {
                false
            }
        }),

        Predicate::IpReputationMalicious => {
            // Phase 2: always false for now
            false
        }
    }
}

/// Extract the basename (last path component) from a file path.
fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// Compute Shannon entropy of a string.
fn shannon_entropy(s: &str) -> f64 {
    let len = s.len() as f64;
    if len == 0.0 {
        return 0.0;
    }
    let mut freq = [0u32; 256];
    for b in s.bytes() {
        freq[b as usize] += 1;
    }
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// Convert a matched rule + trace into a verdict.
fn rule_to_verdict(rule: &Rule, trace: &CorrelatedTrace) -> Verdict {
    let classification = match rule.severity {
        Severity::Critical | Severity::High => Classification::Malicious,
        Severity::Medium => Classification::Suspicious,
        Severity::Low | Severity::Info => Classification::Benign,
    };

    let recommended_action = match rule.action {
        RuleAction::Block => RecommendedAction::Block,
        RuleAction::Notify => RecommendedAction::Notify,
        RuleAction::Log => RecommendedAction::Allow,
        RuleAction::DeferToLlm => RecommendedAction::Notify,
    };

    Verdict {
        id: Uuid::new_v4(),
        trace_id: trace.id,
        classification,
        confidence: Confidence::new(1.0),
        recommended_action,
        explanation: format!("Rule '{}' matched: {}", rule.name, rule.description),
        profile_violations: Vec::new(),
        timestamp: Utc::now(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use uuid::Uuid;
    use watchpost_types::{
        AncestryEntry, EnrichedEvent, Ecosystem, TetragonEvent,
    };

    /// Helper: create an enriched event with npm ancestry and a network connect.
    fn npm_network_event(dest_port: u16) -> EnrichedEvent {
        EnrichedEvent {
            event: TetragonEvent {
                id: Uuid::new_v4(),
                timestamp: Utc::now(),
                kind: EventKind::NetworkConnect {
                    dest_ip: "10.0.0.1".to_owned(),
                    dest_port,
                    protocol: "tcp".to_owned(),
                },
                process_id: 1234,
                parent_id: Some(1233),
                policy_name: Some("npm-network".to_owned()),
            },
            ancestry: vec![
                AncestryEntry {
                    pid: 1233,
                    binary_path: "/usr/bin/node".to_owned(),
                    cmdline: "node install.js".to_owned(),
                },
                AncestryEntry {
                    pid: 1200,
                    binary_path: "/usr/bin/npm".to_owned(),
                    cmdline: "npm install evil-pkg".to_owned(),
                },
            ],
            context: ActionContext::PackageInstall {
                ecosystem: Ecosystem::Npm,
                package_name: Some("evil-pkg".to_owned()),
                package_version: Some("1.0.0".to_owned()),
                working_dir: "/home/user/project".to_owned(),
            },
        }
    }

    /// Helper: create an enriched event for a process exec from a given binary path.
    fn exec_event(binary: &str, ancestry: Vec<AncestryEntry>, context: ActionContext) -> EnrichedEvent {
        EnrichedEvent {
            event: TetragonEvent {
                id: Uuid::new_v4(),
                timestamp: Utc::now(),
                kind: EventKind::ProcessExec {
                    binary: binary.to_owned(),
                    args: vec![],
                    cwd: "/tmp".to_owned(),
                    uid: 1000,
                },
                process_id: 2000,
                parent_id: Some(1999),
                policy_name: None,
            },
            ancestry,
            context,
        }
    }

    /// Helper: create an enriched event for a file access.
    fn file_access_event(
        path: &str,
        ancestry: Vec<AncestryEntry>,
        context: ActionContext,
    ) -> EnrichedEvent {
        EnrichedEvent {
            event: TetragonEvent {
                id: Uuid::new_v4(),
                timestamp: Utc::now(),
                kind: EventKind::FileAccess {
                    path: path.to_owned(),
                    access_type: watchpost_types::FileAccessType::Read,
                },
                process_id: 3000,
                parent_id: Some(2999),
                policy_name: None,
            },
            ancestry,
            context,
        }
    }

    fn npm_ancestry() -> Vec<AncestryEntry> {
        vec![
            AncestryEntry {
                pid: 1233,
                binary_path: "/usr/bin/node".to_owned(),
                cmdline: "node install.js".to_owned(),
            },
            AncestryEntry {
                pid: 1200,
                binary_path: "/usr/bin/npm".to_owned(),
                cmdline: "npm install evil-pkg".to_owned(),
            },
        ]
    }

    fn npm_context() -> ActionContext {
        ActionContext::PackageInstall {
            ecosystem: Ecosystem::Npm,
            package_name: Some("evil-pkg".to_owned()),
            package_version: Some("1.0.0".to_owned()),
            working_dir: "/home/user/project".to_owned(),
        }
    }

    fn cargo_context() -> ActionContext {
        ActionContext::Build {
            toolchain: "stable".to_owned(),
            working_dir: "/home/user/project".to_owned(),
        }
    }

    fn make_trace(events: Vec<EnrichedEvent>, context: ActionContext) -> CorrelatedTrace {
        CorrelatedTrace {
            id: Uuid::new_v4(),
            trigger: None,
            events,
            signals: vec![],
            score: None,
            context,
        }
    }

    fn sample_rules_yaml() -> &'static str {
        r#"
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

- name: npm-temp-dir-exec
  description: "npm lifecycle script executing a binary from a temp directory"
  severity: critical
  conditions:
    and:
      - ancestor_binary_matches:
          - npm
          - npx
      - exec_from_temp_dir: null
  action: block

- name: npm-ssh-key-access
  description: "npm lifecycle script reading SSH keys"
  severity: critical
  conditions:
    and:
      - ancestor_binary_matches:
          - npm
          - npx
      - file_path_starts_with:
          - ".ssh/"
  action: block

- name: any-temp-dir-exec
  description: "Process executed from a temporary directory"
  severity: medium
  conditions:
    exec_from_temp_dir: null
  action: notify
"#
    }

    fn load_engine() -> RuleEngine {
        let rules = crate::loader::load_rules_from_str(sample_rules_yaml()).expect("parse rules");
        RuleEngine::new(rules)
    }

    #[test]
    fn npm_reverse_shell_matches() {
        let engine = load_engine();
        let trace = make_trace(vec![npm_network_event(4444)], npm_context());

        let verdict = engine.evaluate(&trace);
        assert!(verdict.is_some(), "Expected a verdict for npm reverse shell");

        let v = verdict.unwrap();
        assert_eq!(v.classification, Classification::Malicious);
        assert_eq!(v.recommended_action, RecommendedAction::Block);
        assert!(v.explanation.contains("npm-reverse-shell"));
    }

    #[test]
    fn npm_temp_dir_exec_matches() {
        let engine = load_engine();
        let trace = make_trace(
            vec![exec_event("/tmp/payload", npm_ancestry(), npm_context())],
            npm_context(),
        );

        let verdict = engine.evaluate(&trace);
        assert!(verdict.is_some(), "Expected a verdict for npm temp dir exec");

        let v = verdict.unwrap();
        assert_eq!(v.classification, Classification::Malicious);
        assert_eq!(v.recommended_action, RecommendedAction::Block);
        assert!(v.explanation.contains("npm-temp-dir-exec"));
    }

    #[test]
    fn npm_ssh_key_access_matches() {
        let engine = load_engine();
        let trace = make_trace(
            vec![file_access_event(
                "/home/user/.ssh/id_rsa",
                npm_ancestry(),
                npm_context(),
            )],
            npm_context(),
        );

        let verdict = engine.evaluate(&trace);
        assert!(verdict.is_some(), "Expected a verdict for npm SSH key access");

        let v = verdict.unwrap();
        assert_eq!(v.classification, Classification::Malicious);
        assert_eq!(v.recommended_action, RecommendedAction::Block);
        assert!(v.explanation.contains("npm-ssh-key-access"));
    }

    #[test]
    fn any_temp_dir_exec_matches() {
        let engine = load_engine();

        // A generic temp exec without npm ancestry (use cargo context)
        let trace = make_trace(
            vec![exec_event(
                "/tmp/test",
                vec![AncestryEntry {
                    pid: 100,
                    binary_path: "/usr/bin/bash".to_owned(),
                    cmdline: "bash".to_owned(),
                }],
                cargo_context(),
            )],
            cargo_context(),
        );

        let verdict = engine.evaluate(&trace);
        assert!(verdict.is_some(), "Expected a verdict for temp dir exec");

        let v = verdict.unwrap();
        assert_eq!(v.classification, Classification::Suspicious);
        assert_eq!(v.recommended_action, RecommendedAction::Notify);
        assert!(v.explanation.contains("any-temp-dir-exec"));
    }

    #[test]
    fn no_match_for_normal_cargo_build() {
        let engine = load_engine();

        let event = EnrichedEvent {
            event: TetragonEvent {
                id: Uuid::new_v4(),
                timestamp: Utc::now(),
                kind: EventKind::ProcessExec {
                    binary: "/usr/bin/rustc".to_owned(),
                    args: vec!["rustc".to_owned(), "main.rs".to_owned()],
                    cwd: "/home/user/project".to_owned(),
                    uid: 1000,
                },
                process_id: 5000,
                parent_id: Some(4999),
                policy_name: None,
            },
            ancestry: vec![AncestryEntry {
                pid: 4999,
                binary_path: "/usr/bin/cargo".to_owned(),
                cmdline: "cargo build".to_owned(),
            }],
            context: cargo_context(),
        };

        let trace = make_trace(vec![event], cargo_context());

        let verdict = engine.evaluate(&trace);
        assert!(verdict.is_none(), "Expected no verdict for normal cargo build");
    }

    #[test]
    fn critical_rule_matches_before_medium() {
        let engine = load_engine();

        // This trace has npm ancestry AND temp dir exec, so both the critical
        // npm-temp-dir-exec and the medium any-temp-dir-exec could match.
        // The critical rule should win.
        let trace = make_trace(
            vec![exec_event("/tmp/payload", npm_ancestry(), npm_context())],
            npm_context(),
        );

        let verdict = engine.evaluate(&trace).expect("expected a verdict");
        assert_eq!(verdict.classification, Classification::Malicious);
        // Should match the critical rule, not the medium one
        assert!(
            verdict.explanation.contains("npm-temp-dir-exec"),
            "Expected critical npm-temp-dir-exec to match first, got: {}",
            verdict.explanation
        );
    }

    #[test]
    fn shannon_entropy_empty_string() {
        assert_eq!(shannon_entropy(""), 0.0);
    }

    #[test]
    fn shannon_entropy_single_char() {
        // "aaaa" has entropy 0.0 (all same character)
        assert_eq!(shannon_entropy("aaaa"), 0.0);
    }

    #[test]
    fn shannon_entropy_high_entropy() {
        // A random-looking string should have entropy > 3.0
        let high = "a8f3k2m9x1p4w7";
        assert!(shannon_entropy(high) > 3.0, "Expected high entropy for random-looking string");
    }

    #[test]
    fn dns_high_entropy_predicate() {
        let engine = {
            let yaml = r#"
- name: dns-exfil
  description: "High entropy DNS query detected"
  severity: high
  conditions:
    dns_query_high_entropy:
      threshold: 4.0
  action: block
"#;
            let rules = crate::loader::load_rules_from_str(yaml).expect("parse");
            RuleEngine::new(rules)
        };

        let high_entropy_event = EnrichedEvent {
            event: TetragonEvent {
                id: Uuid::new_v4(),
                timestamp: Utc::now(),
                kind: EventKind::DnsQuery {
                    query_name: "a8f3k2m9x1p4w7q6r5t0u8v3y2z1.evil.com".to_owned(),
                    query_type: "A".to_owned(),
                },
                process_id: 6000,
                parent_id: Some(5999),
                policy_name: None,
            },
            ancestry: vec![],
            context: ActionContext::Unknown,
        };

        let trace = make_trace(vec![high_entropy_event], ActionContext::Unknown);
        let verdict = engine.evaluate(&trace);
        assert!(verdict.is_some(), "Expected verdict for high entropy DNS");

        // Normal DNS query should NOT match
        let normal_event = EnrichedEvent {
            event: TetragonEvent {
                id: Uuid::new_v4(),
                timestamp: Utc::now(),
                kind: EventKind::DnsQuery {
                    query_name: "google.com".to_owned(),
                    query_type: "A".to_owned(),
                },
                process_id: 6001,
                parent_id: Some(5999),
                policy_name: None,
            },
            ancestry: vec![],
            context: ActionContext::Unknown,
        };

        let trace2 = make_trace(vec![normal_event], ActionContext::Unknown);
        let verdict2 = engine.evaluate(&trace2);
        assert!(verdict2.is_none(), "Expected no verdict for normal DNS query");
    }
}
