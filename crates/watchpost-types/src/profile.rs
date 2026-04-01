use serde::{Deserialize, Serialize};

/// An expected or forbidden network connection pattern.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkExpectation {
    pub host: Option<String>,
    pub port: Option<u16>,
    pub description: String,
}

/// A behavior profile describing what a particular context is expected to do.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorProfile {
    pub context_type: String,
    pub ecosystem: Option<String>,
    pub expected_network: Vec<NetworkExpectation>,
    pub expected_children: Vec<String>,
    pub expected_file_writes: Vec<String>,
    pub forbidden_file_access: Vec<String>,
    pub forbidden_children: Vec<String>,
    pub forbidden_network: Vec<NetworkExpectation>,
}

/// How an observed behavior relates to a profile.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BehaviorClassification {
    Expected,
    Unspecified,
    Forbidden,
}
