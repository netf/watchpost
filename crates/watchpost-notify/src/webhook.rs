use std::time::Duration;

use anyhow::Result;
use reqwest::Client;
use serde::Serialize;
use tracing::{debug, warn};
use watchpost_types::Verdict;

/// Forwards verdicts to an external HTTP endpoint as JSON.
pub struct WebhookForwarder {
    client: Client,
    url: String,
    auth_header: Option<String>,
}

/// The JSON payload sent to the webhook.
#[derive(Debug, Serialize)]
pub(crate) struct WebhookPayload {
    pub event_type: &'static str,
    pub verdict: VerdictPayload,
}

#[derive(Debug, Serialize)]
pub(crate) struct VerdictPayload {
    pub id: String,
    pub trace_id: String,
    pub classification: String,
    pub confidence: f64,
    pub recommended_action: String,
    pub explanation: String,
    pub profile_violations: Vec<String>,
    pub timestamp: String,
}

impl WebhookForwarder {
    /// Create a new webhook forwarder.
    ///
    /// The reqwest `Client` is created once and reused for all requests,
    /// with a 10-second timeout and a custom user-agent.
    pub fn new(url: String, auth_header: Option<String>) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .user_agent("watchpost/0.1.0")
            .build()
            .expect("failed to build reqwest client");

        Self {
            client,
            url,
            auth_header,
        }
    }

    /// POST the verdict as JSON to the configured webhook URL.
    ///
    /// This is best-effort: failures are logged as warnings but never
    /// propagated, so they cannot affect core functionality.
    pub async fn forward(&self, verdict: &Verdict) -> Result<()> {
        let payload = Self::from_verdict(verdict);

        debug!(
            trace_id = %verdict.trace_id,
            url = %self.url,
            "Forwarding verdict to webhook"
        );

        let mut request = self.client.post(&self.url).json(&payload);

        if let Some(ref auth) = self.auth_header {
            request = request.header("Authorization", auth);
        }

        match request.send().await {
            Ok(response) => {
                let status = response.status();
                if !status.is_success() {
                    warn!(
                        trace_id = %verdict.trace_id,
                        status = %status,
                        url = %self.url,
                        "Webhook returned non-success status"
                    );
                } else {
                    debug!(
                        trace_id = %verdict.trace_id,
                        status = %status,
                        "Webhook forwarded successfully"
                    );
                }
            }
            Err(e) => {
                warn!(
                    trace_id = %verdict.trace_id,
                    error = %e,
                    url = %self.url,
                    "Failed to forward verdict to webhook"
                );
            }
        }

        Ok(())
    }

    /// Convert a `Verdict` into the webhook wire format.
    pub(crate) fn from_verdict(verdict: &Verdict) -> WebhookPayload {
        WebhookPayload {
            event_type: "verdict",
            verdict: VerdictPayload {
                id: verdict.id.to_string(),
                trace_id: verdict.trace_id.to_string(),
                classification: format!("{:?}", verdict.classification).to_lowercase(),
                confidence: verdict.confidence.value(),
                recommended_action: format!("{:?}", verdict.recommended_action).to_lowercase(),
                explanation: verdict.explanation.clone(),
                profile_violations: verdict.profile_violations.clone(),
                timestamp: verdict.timestamp.to_rfc3339(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use uuid::Uuid;
    use watchpost_types::{Classification, Confidence, RecommendedAction};

    fn make_test_verdict() -> Verdict {
        Verdict {
            id: Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap(),
            trace_id: Uuid::parse_str("6ba7b810-9dad-11d1-80b4-00c04fd430c8").unwrap(),
            classification: Classification::Malicious,
            confidence: Confidence::new(0.95),
            recommended_action: RecommendedAction::Block,
            explanation: "Suspicious outbound connection to known C2 server".to_owned(),
            profile_violations: vec!["network_egress".to_owned(), "unexpected_dns".to_owned()],
            timestamp: Utc::now(),
        }
    }

    #[test]
    fn webhook_payload_serialization_has_expected_fields() {
        let verdict = make_test_verdict();
        let payload = WebhookForwarder::from_verdict(&verdict);
        let json = serde_json::to_value(&payload).unwrap();

        assert_eq!(json["event_type"], "verdict");
        assert!(json["verdict"].is_object());
        assert!(json["verdict"]["id"].is_string());
        assert!(json["verdict"]["trace_id"].is_string());
        assert!(json["verdict"]["classification"].is_string());
        assert!(json["verdict"]["confidence"].is_number());
        assert!(json["verdict"]["recommended_action"].is_string());
        assert!(json["verdict"]["explanation"].is_string());
        assert!(json["verdict"]["profile_violations"].is_array());
        assert!(json["verdict"]["timestamp"].is_string());
    }

    #[test]
    fn from_verdict_maps_all_fields_correctly() {
        let verdict = make_test_verdict();
        let payload = WebhookForwarder::from_verdict(&verdict);

        assert_eq!(payload.event_type, "verdict");
        assert_eq!(payload.verdict.id, "550e8400-e29b-41d4-a716-446655440000");
        assert_eq!(
            payload.verdict.trace_id,
            "6ba7b810-9dad-11d1-80b4-00c04fd430c8"
        );
        assert_eq!(payload.verdict.classification, "malicious");
        assert!((payload.verdict.confidence - 0.95).abs() < f64::EPSILON);
        assert_eq!(payload.verdict.recommended_action, "block");
        assert_eq!(
            payload.verdict.explanation,
            "Suspicious outbound connection to known C2 server"
        );
        assert_eq!(
            payload.verdict.profile_violations,
            vec!["network_egress", "unexpected_dns"]
        );
        // timestamp should be a valid RFC3339 string
        assert!(payload.verdict.timestamp.contains('T'));
    }

    #[test]
    fn from_verdict_handles_empty_violations() {
        let mut verdict = make_test_verdict();
        verdict.profile_violations = vec![];
        let payload = WebhookForwarder::from_verdict(&verdict);
        assert!(payload.verdict.profile_violations.is_empty());
    }

    #[test]
    fn from_verdict_benign_classification() {
        let mut verdict = make_test_verdict();
        verdict.classification = Classification::Benign;
        verdict.recommended_action = RecommendedAction::Allow;
        let payload = WebhookForwarder::from_verdict(&verdict);
        assert_eq!(payload.verdict.classification, "benign");
        assert_eq!(payload.verdict.recommended_action, "allow");
    }

    #[test]
    fn from_verdict_suspicious_classification() {
        let mut verdict = make_test_verdict();
        verdict.classification = Classification::Suspicious;
        verdict.recommended_action = RecommendedAction::Notify;
        let payload = WebhookForwarder::from_verdict(&verdict);
        assert_eq!(payload.verdict.classification, "suspicious");
        assert_eq!(payload.verdict.recommended_action, "notify");
    }
}
