use serde::{Deserialize, Serialize};

/// The severity level of a rule match.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// The action to take when a rule matches.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuleAction {
    Log,
    Notify,
    Block,
    DeferToLlm,
}

/// A leaf-level predicate that can be evaluated against an enriched event.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Predicate {
    BinaryMatches(Vec<String>),
    AncestorBinaryMatches(Vec<String>),
    FilePathStartsWith(Vec<String>),
    DestPortIs(Vec<u16>),
    DestIpOutsideAllowlist,
    ExecFromTempDir,
    PrivilegeChange,
    InFlatpakSandbox,
    DnsQueryHighEntropy {
        threshold: f64,
    },
    IpReputationMalicious,
}

/// A tree of conditions combined with AND/OR logic.
///
/// Supports nested YAML like:
/// ```yaml
/// conditions:
///   and:
///     - ancestor_binary_matches: [npm, npx]
///     - or:
///         - dest_port_is: [4444, 5555]
///         - binary_matches: [nc, ncat]
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConditionTree {
    And(Vec<ConditionTree>),
    Or(Vec<ConditionTree>),
    #[serde(untagged)]
    Leaf(Predicate),
}

/// A deterministic rule for the fast-path engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub name: String,
    pub description: String,
    pub severity: Severity,
    pub conditions: ConditionTree,
    pub action: RuleAction,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_ordering() {
        assert!(Severity::Info < Severity::Low);
        assert!(Severity::Low < Severity::Medium);
        assert!(Severity::Medium < Severity::High);
        assert!(Severity::High < Severity::Critical);
    }

    #[test]
    fn severity_sort() {
        let mut severities = vec![
            Severity::Critical,
            Severity::Info,
            Severity::High,
            Severity::Low,
            Severity::Medium,
        ];
        severities.sort();
        assert_eq!(
            severities,
            vec![
                Severity::Info,
                Severity::Low,
                Severity::Medium,
                Severity::High,
                Severity::Critical,
            ]
        );
    }

    #[test]
    fn condition_tree_serde_round_trip() {
        let tree = ConditionTree::And(vec![
            ConditionTree::Leaf(Predicate::AncestorBinaryMatches(vec![
                "npm".to_owned(),
                "npx".to_owned(),
            ])),
            ConditionTree::Or(vec![
                ConditionTree::Leaf(Predicate::DestPortIs(vec![4444, 5555])),
                ConditionTree::Leaf(Predicate::BinaryMatches(vec![
                    "nc".to_owned(),
                    "ncat".to_owned(),
                ])),
            ]),
        ]);

        let json = serde_json::to_string(&tree).expect("serialize");
        let deserialized: ConditionTree =
            serde_json::from_str(&json).expect("deserialize");

        // Verify it round-trips by re-serializing
        let json2 = serde_json::to_string(&deserialized).expect("re-serialize");
        assert_eq!(json, json2);
    }
}
