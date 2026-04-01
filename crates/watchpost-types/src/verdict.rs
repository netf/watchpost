use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// How the system classified a trace.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Classification {
    Benign,
    Suspicious,
    Malicious,
}

/// The recommended enforcement action for a verdict.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RecommendedAction {
    Allow,
    Block,
    Notify,
}

/// A confidence value clamped to [0.0, 1.0].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Confidence(f64);

impl Confidence {
    pub fn new(val: f64) -> Self {
        Self(val.clamp(0.0, 1.0))
    }

    pub fn value(&self) -> f64 {
        self.0
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn confidence_clamps_high() {
        let c = Confidence::new(1.5);
        assert!((c.value() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn confidence_clamps_low() {
        let c = Confidence::new(-0.1);
        assert!((c.value() - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn confidence_preserves_valid() {
        let c = Confidence::new(0.75);
        assert!((c.value() - 0.75).abs() < f64::EPSILON);
    }
}
