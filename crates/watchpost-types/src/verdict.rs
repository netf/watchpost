use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::scoring::Confidence;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Classification {
    Benign,
    Suspicious,
    Malicious,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RecommendedAction {
    Allow,
    Block,
    Notify,
}

/// A complete verdict produced by the engine for a correlated trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Verdict {
    pub id: Uuid,
    pub trace_id: Uuid,
    pub classification: Classification,
    pub confidence: Confidence,
    pub recommended_action: RecommendedAction,
    pub explanation: String,
    pub profile_violations: Vec<String>,
    pub timestamp: DateTime<Utc>,
}
