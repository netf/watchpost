use serde::{Deserialize, Serialize};

/// Where a tracing policy originated from.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PolicySource {
    Base,
    Reactive,
    User,
}

/// Metadata attached to a tracing policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyMetadata {
    pub name: String,
    pub description: String,
    pub source: PolicySource,
}

/// A Tetragon tracing policy specification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TracingPolicySpec {
    pub metadata: PolicyMetadata,
    /// The raw YAML content of the Tetragon tracing policy.
    pub yaml_content: String,
}

/// A policy template that bundles a set of TracingPolicies for a specific use case.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyTemplate {
    pub name: String,
    pub description: String,
    pub policies: Vec<String>,
}
