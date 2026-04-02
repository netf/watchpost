use anyhow::{Context, Result, bail};
use chrono::Utc;
use serde::Deserialize;
use tracing::{debug, warn};
use uuid::Uuid;

use watchpost_types::{
    BehaviorProfile, Classification, Confidence, CorrelatedTrace, RecommendedAction,
    ScoreBreakdown, Verdict,
};

use crate::client::{AnthropicClient, ApiResponse, ContentBlock, Message};
use crate::context_builder::ContextBuilder;
use crate::skill::SkillSpec;
use crate::tools::ToolExecutor;

// ---------------------------------------------------------------------------
// Agent loop
// ---------------------------------------------------------------------------

/// A bounded agent loop that drives the LLM through tool calls until it
/// produces a final verdict.
pub struct AgentLoop {
    client: AnthropicClient,
    tool_executor: ToolExecutor,
    skill: SkillSpec,
    max_tool_calls: u32,
}

impl AgentLoop {
    pub fn new(client: AnthropicClient, skill: SkillSpec, max_tool_calls: u32) -> Self {
        Self {
            client,
            tool_executor: ToolExecutor::new(),
            skill,
            max_tool_calls,
        }
    }

    /// Run the agent loop for a single trace and return a verdict.
    pub async fn analyze(
        &self,
        trace: &CorrelatedTrace,
        profile: Option<&BehaviorProfile>,
        score_breakdown: Option<&ScoreBreakdown>,
    ) -> Result<Verdict> {
        let trace_id = trace.id;
        let system_prompt = &self.skill.system_prompt;
        let tools = self.skill.to_tool_definitions();
        let output_schema = &self.skill.output_schema;

        // 1. Build initial user message.
        let user_message = ContextBuilder::build_user_message(trace, profile, score_breakdown);
        let mut messages: Vec<Message> = vec![user_message];

        let mut tool_call_count: u32 = 0;

        loop {
            // Send message to LLM (always include output_schema for simplicity).
            let response = self
                .client
                .send_message(system_prompt, &messages, &tools, Some(output_schema))
                .await
                .context("LLM API call failed")?;

            match response {
                ApiResponse::ToolUse { id, name, input } => {
                    debug!(tool = %name, call = tool_call_count + 1, "LLM requested tool use");

                    // Execute the tool.
                    let result = self.tool_executor.execute(&name, &input);

                    // Append assistant message with ToolUse content block.
                    messages.push(Message {
                        role: "assistant".to_string(),
                        content: vec![ContentBlock::ToolUse {
                            id: id.clone(),
                            name,
                            input,
                        }],
                    });

                    // Append user message with ToolResult content block.
                    messages.push(Message {
                        role: "user".to_string(),
                        content: vec![ContentBlock::ToolResult {
                            tool_use_id: id,
                            content: result,
                        }],
                    });

                    tool_call_count += 1;

                    // Check budget.
                    if tool_call_count >= self.max_tool_calls {
                        warn!(
                            trace_id = %trace_id,
                            calls = tool_call_count,
                            "tool call budget exceeded, returning best-effort verdict"
                        );
                        return Ok(best_effort_verdict(trace_id));
                    }
                }
                ApiResponse::EndTurn { content } => {
                    debug!(
                        trace_id = %trace_id,
                        tool_calls = tool_call_count,
                        "LLM produced final verdict"
                    );
                    return parse_verdict(&content, trace_id);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Verdict parsing
// ---------------------------------------------------------------------------

/// Intermediate structure for deserializing the LLM's JSON output.
#[derive(Debug, Deserialize)]
struct RawVerdict {
    classification: String,
    confidence: f64,
    recommended_action: String,
    explanation: String,
    #[serde(default)]
    profile_violations: Vec<String>,
}

/// Parse the LLM's JSON output into a [`Verdict`].
pub fn parse_verdict(content: &str, trace_id: Uuid) -> Result<Verdict> {
    let raw: RawVerdict =
        serde_json::from_str(content).context("failed to parse LLM verdict JSON")?;

    let classification = match raw.classification.as_str() {
        "benign" => Classification::Benign,
        "suspicious" => Classification::Suspicious,
        "malicious" => Classification::Malicious,
        other => bail!("unknown classification: {other}"),
    };

    let recommended_action = match raw.recommended_action.as_str() {
        "allow" => RecommendedAction::Allow,
        "block" => RecommendedAction::Block,
        "notify" => RecommendedAction::Notify,
        other => bail!("unknown recommended_action: {other}"),
    };

    Ok(Verdict {
        id: Uuid::new_v4(),
        trace_id,
        classification,
        confidence: Confidence::new(raw.confidence),
        recommended_action,
        explanation: raw.explanation,
        profile_violations: raw.profile_violations,
        timestamp: Utc::now(),
    })
}

/// Produce a best-effort verdict when the tool-call budget is exceeded.
fn best_effort_verdict(trace_id: Uuid) -> Verdict {
    Verdict {
        id: Uuid::new_v4(),
        trace_id,
        classification: Classification::Suspicious,
        confidence: Confidence::new(0.5),
        recommended_action: RecommendedAction::Notify,
        explanation: "Analysis incomplete \u{2014} tool call budget exceeded".to_string(),
        profile_violations: vec![],
        timestamp: Utc::now(),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_verdict_valid_benign() {
        let content = json!({
            "classification": "benign",
            "confidence": 0.95,
            "recommended_action": "allow",
            "explanation": "Normal npm install behavior",
            "profile_violations": []
        })
        .to_string();

        let trace_id = Uuid::new_v4();
        let verdict = parse_verdict(&content, trace_id).expect("should parse");

        assert_eq!(verdict.trace_id, trace_id);
        assert_eq!(verdict.classification, Classification::Benign);
        assert!((verdict.confidence.value() - 0.95).abs() < f64::EPSILON);
        assert_eq!(verdict.recommended_action, RecommendedAction::Allow);
        assert_eq!(verdict.explanation, "Normal npm install behavior");
        assert!(verdict.profile_violations.is_empty());
    }

    #[test]
    fn parse_verdict_valid_malicious() {
        let content = json!({
            "classification": "malicious",
            "confidence": 0.88,
            "recommended_action": "block",
            "explanation": "Package attempted to read /etc/shadow",
            "profile_violations": ["sensitive file read", "reverse shell pattern"]
        })
        .to_string();

        let trace_id = Uuid::new_v4();
        let verdict = parse_verdict(&content, trace_id).expect("should parse");

        assert_eq!(verdict.classification, Classification::Malicious);
        assert_eq!(verdict.recommended_action, RecommendedAction::Block);
        assert_eq!(verdict.profile_violations.len(), 2);
    }

    #[test]
    fn parse_verdict_valid_suspicious() {
        let content = json!({
            "classification": "suspicious",
            "confidence": 0.6,
            "recommended_action": "notify",
            "explanation": "Unusual network connection during build",
            "profile_violations": ["unexpected outbound connection"]
        })
        .to_string();

        let trace_id = Uuid::new_v4();
        let verdict = parse_verdict(&content, trace_id).expect("should parse");

        assert_eq!(verdict.classification, Classification::Suspicious);
        assert_eq!(verdict.recommended_action, RecommendedAction::Notify);
    }

    #[test]
    fn parse_verdict_invalid_json() {
        let result = parse_verdict("not json", Uuid::new_v4());
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("parse"),
            "error should mention parsing — got: {err}"
        );
    }

    #[test]
    fn parse_verdict_unknown_classification() {
        let content = json!({
            "classification": "unknown_thing",
            "confidence": 0.5,
            "recommended_action": "allow",
            "explanation": "test",
            "profile_violations": []
        })
        .to_string();

        let result = parse_verdict(&content, Uuid::new_v4());
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("unknown classification"),
            "error should mention unknown classification — got: {err}"
        );
    }

    #[test]
    fn parse_verdict_unknown_action() {
        let content = json!({
            "classification": "benign",
            "confidence": 0.5,
            "recommended_action": "quarantine",
            "explanation": "test",
            "profile_violations": []
        })
        .to_string();

        let result = parse_verdict(&content, Uuid::new_v4());
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("unknown recommended_action"),
            "error should mention unknown action — got: {err}"
        );
    }

    #[test]
    fn parse_verdict_confidence_is_clamped() {
        let content = json!({
            "classification": "benign",
            "confidence": 1.5,
            "recommended_action": "allow",
            "explanation": "over-confident",
            "profile_violations": []
        })
        .to_string();

        let verdict = parse_verdict(&content, Uuid::new_v4()).expect("should parse");
        assert!((verdict.confidence.value() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn best_effort_verdict_fields() {
        let trace_id = Uuid::new_v4();
        let v = best_effort_verdict(trace_id);
        assert_eq!(v.trace_id, trace_id);
        assert_eq!(v.classification, Classification::Suspicious);
        assert!((v.confidence.value() - 0.5).abs() < f64::EPSILON);
        assert_eq!(v.recommended_action, RecommendedAction::Notify);
        assert!(v.explanation.contains("budget exceeded"));
    }
}
