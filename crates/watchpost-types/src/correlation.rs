use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::context::ActionContext;
use crate::events::EnrichedEvent;
use crate::scoring::SuspicionScore;

/// Whether correlated events share matching arguments.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArgumentMatch {
    Positive,
    Negative,
    None,
}

/// A signal produced during event correlation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationSignal {
    pub lineage_match: bool,
    pub temporal_weight: f64,
    pub argument_match: ArgumentMatch,
}

/// A group of correlated events forming a single trace for analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelatedTrace {
    pub id: Uuid,
    pub trigger: Option<EnrichedEvent>,
    pub events: Vec<EnrichedEvent>,
    pub signals: Vec<CorrelationSignal>,
    pub score: Option<SuspicionScore>,
    pub context: ActionContext,
}
