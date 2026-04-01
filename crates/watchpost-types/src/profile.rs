use serde::{Deserialize, Serialize};

use crate::context::Ecosystem;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NetworkExpectation {
    pub host: Option<String>,
    pub port: Option<u16>,
    pub description: String,
}

/// A behavior profile describing what a particular context is expected to do.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorProfile {
    pub context_type: String,
    pub ecosystem: Option<Ecosystem>,
    pub expected_network: Vec<NetworkExpectation>,
    pub expected_children: Vec<String>,
    pub expected_file_writes: Vec<String>,
    pub forbidden_file_access: Vec<String>,
    pub forbidden_children: Vec<String>,
    pub forbidden_network: Vec<NetworkExpectation>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BehaviorClassification {
    Expected,
    Unspecified,
    Forbidden,
}
