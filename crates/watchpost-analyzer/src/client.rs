use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use tracing::debug;

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

/// A message in the conversation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub role: String,
    pub content: Vec<ContentBlock>,
}

/// A content block within a message.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ContentBlock {
    #[serde(rename = "text")]
    Text { text: String },
    #[serde(rename = "tool_use")]
    ToolUse {
        id: String,
        name: String,
        input: serde_json::Value,
    },
    #[serde(rename = "tool_result")]
    ToolResult {
        tool_use_id: String,
        content: String,
    },
}

/// A tool definition for the API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDefinition {
    pub name: String,
    pub description: String,
    pub input_schema: serde_json::Value,
}

/// The structured output format configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputConfig {
    pub format: OutputFormat,
}

/// Output format variant.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum OutputFormat {
    #[serde(rename = "json_schema")]
    JsonSchema {
        name: String,
        schema: serde_json::Value,
    },
}

/// Response from the Messages API.
#[derive(Debug, Clone)]
pub enum ApiResponse {
    /// LLM wants to use a tool.
    ToolUse {
        id: String,
        name: String,
        input: serde_json::Value,
    },
    /// LLM produced final text output.
    EndTurn { content: String },
}

// ---------------------------------------------------------------------------
// Internal serde helpers for response parsing
// ---------------------------------------------------------------------------

/// Raw response body returned by the Anthropic Messages API.
#[derive(Debug, Deserialize)]
struct RawApiResponse {
    content: Vec<serde_json::Value>,
    stop_reason: String,
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

/// HTTP client for the Anthropic Messages API.
pub struct AnthropicClient {
    http: reqwest::Client,
    api_key: String,
    model: String,
    base_url: String,
}

impl AnthropicClient {
    /// Create a new client targeting the Anthropic Messages API.
    ///
    /// * `api_key` – Anthropic API key (never logged).
    /// * `model`   – Model identifier, e.g. `"claude-haiku-4-5-20241022"`.
    pub fn new(api_key: String, model: String) -> Self {
        Self {
            http: reqwest::Client::new(),
            api_key,
            model,
            base_url: "https://api.anthropic.com".to_string(),
        }
    }

    /// Override the base URL (useful for testing against a local mock server).
    #[allow(dead_code)]
    pub fn with_base_url(mut self, url: String) -> Self {
        self.base_url = url;
        self
    }

    /// Build the JSON request body without sending it.
    ///
    /// Exposed for testing so we can assert on the structure without hitting
    /// the network.
    pub fn build_request_body(
        &self,
        system_prompt: &str,
        messages: &[Message],
        tools: &[ToolDefinition],
        output_schema: Option<&serde_json::Value>,
    ) -> serde_json::Value {
        let mut body = serde_json::json!({
            "model": self.model,
            "max_tokens": 4096,
            "system": system_prompt,
            "messages": messages,
        });

        if !tools.is_empty() {
            body["tools"] = serde_json::json!(tools);
        }

        if let Some(schema) = output_schema {
            body["output_config"] = serde_json::json!({
                "format": {
                    "type": "json_schema",
                    "name": "verdict",
                    "schema": schema
                }
            });
        }

        body
    }

    /// Send a message to the Anthropic Messages API and return the parsed
    /// response.
    pub async fn send_message(
        &self,
        system_prompt: &str,
        messages: &[Message],
        tools: &[ToolDefinition],
        output_schema: Option<&serde_json::Value>,
    ) -> Result<ApiResponse> {
        let body = self.build_request_body(system_prompt, messages, tools, output_schema);

        debug!(model = %self.model, "sending request to Anthropic Messages API");

        let url = format!("{}/v1/messages", self.base_url);

        let resp = self
            .http
            .post(&url)
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", "2023-06-01")
            .header("content-type", "application/json")
            .json(&body)
            .send()
            .await
            .context("failed to send request to Anthropic API")?;

        let status = resp.status();
        if !status.is_success() {
            let error_body = resp
                .text()
                .await
                .unwrap_or_else(|_| "<failed to read body>".to_string());
            bail!(
                "Anthropic API returned HTTP {}: {}",
                status.as_u16(),
                error_body
            );
        }

        let raw_text = resp
            .text()
            .await
            .context("failed to read Anthropic API response body")?;

        Self::parse_response(&raw_text)
    }

    /// Parse the raw JSON response body into an [`ApiResponse`].
    ///
    /// Separated from `send_message` so it can be tested without network
    /// access.
    pub fn parse_response(raw: &str) -> Result<ApiResponse> {
        let raw_resp: RawApiResponse =
            serde_json::from_str(raw).context("failed to parse Anthropic API response JSON")?;

        match raw_resp.stop_reason.as_str() {
            "tool_use" => {
                // Find the first tool_use content block.
                for block in &raw_resp.content {
                    if block.get("type").and_then(|v| v.as_str()) == Some("tool_use") {
                        let id = block
                            .get("id")
                            .and_then(|v| v.as_str())
                            .unwrap_or_default()
                            .to_string();
                        let name = block
                            .get("name")
                            .and_then(|v| v.as_str())
                            .unwrap_or_default()
                            .to_string();
                        let input = block
                            .get("input")
                            .cloned()
                            .unwrap_or(serde_json::Value::Null);

                        return Ok(ApiResponse::ToolUse { id, name, input });
                    }
                }
                bail!(
                    "Anthropic API returned stop_reason=tool_use but no tool_use block was found in the response"
                );
            }
            "end_turn" => {
                // Concatenate all text blocks.
                let mut text = String::new();
                for block in &raw_resp.content {
                    if block.get("type").and_then(|v| v.as_str()) == Some("text") {
                        if let Some(t) = block.get("text").and_then(|v| v.as_str()) {
                            if !text.is_empty() {
                                text.push('\n');
                            }
                            text.push_str(t);
                        }
                    }
                }
                Ok(ApiResponse::EndTurn { content: text })
            }
            other => {
                bail!(
                    "unexpected stop_reason from Anthropic API: {:?}",
                    other
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // -- Request body construction ------------------------------------------

    #[test]
    fn test_request_body_basic() {
        let client = AnthropicClient::new("test-key".into(), "claude-haiku-4-5-20241022".into());

        let messages = vec![Message {
            role: "user".into(),
            content: vec![ContentBlock::Text {
                text: "Hello".into(),
            }],
        }];

        let body = client.build_request_body("You are a security analyst.", &messages, &[], None);

        assert_eq!(body["model"], "claude-haiku-4-5-20241022");
        assert_eq!(body["max_tokens"], 4096);
        assert_eq!(body["system"], "You are a security analyst.");
        assert!(body["messages"].is_array());
        assert_eq!(body["messages"][0]["role"], "user");
        assert_eq!(body["messages"][0]["content"][0]["type"], "text");
        assert_eq!(body["messages"][0]["content"][0]["text"], "Hello");
        // No tools or output_config when not provided
        assert!(body.get("tools").is_none());
        assert!(body.get("output_config").is_none());
    }

    #[test]
    fn test_request_body_with_tools() {
        let client = AnthropicClient::new("key".into(), "model".into());

        let tools = vec![ToolDefinition {
            name: "lookup_process".into(),
            description: "Look up process info".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "pid": { "type": "integer" }
                },
                "required": ["pid"]
            }),
        }];

        let body = client.build_request_body("sys", &[], &tools, None);

        assert!(body["tools"].is_array());
        assert_eq!(body["tools"][0]["name"], "lookup_process");
        assert!(body.get("output_config").is_none());
    }

    #[test]
    fn test_request_body_with_output_schema() {
        let client = AnthropicClient::new("key".into(), "model".into());

        let schema = json!({
            "type": "object",
            "properties": {
                "verdict": { "type": "string" },
                "confidence": { "type": "number" }
            },
            "required": ["verdict", "confidence"]
        });

        let body = client.build_request_body("sys", &[], &[], Some(&schema));

        let oc = &body["output_config"];
        assert_eq!(oc["format"]["type"], "json_schema");
        assert_eq!(oc["format"]["name"], "verdict");
        assert_eq!(
            oc["format"]["schema"]["properties"]["verdict"]["type"],
            "string"
        );
    }

    // -- Response parsing ---------------------------------------------------

    #[test]
    fn test_parse_tool_use_response() {
        let raw = json!({
            "content": [
                {
                    "type": "text",
                    "text": "Let me look that up."
                },
                {
                    "type": "tool_use",
                    "id": "toolu_abc123",
                    "name": "lookup_process",
                    "input": { "pid": 1234 }
                }
            ],
            "stop_reason": "tool_use"
        })
        .to_string();

        let resp = AnthropicClient::parse_response(&raw).unwrap();
        match resp {
            ApiResponse::ToolUse { id, name, input } => {
                assert_eq!(id, "toolu_abc123");
                assert_eq!(name, "lookup_process");
                assert_eq!(input["pid"], 1234);
            }
            other => panic!("expected ToolUse, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_end_turn_response() {
        let raw = json!({
            "content": [
                {
                    "type": "text",
                    "text": "This process is benign."
                }
            ],
            "stop_reason": "end_turn"
        })
        .to_string();

        let resp = AnthropicClient::parse_response(&raw).unwrap();
        match resp {
            ApiResponse::EndTurn { content } => {
                assert_eq!(content, "This process is benign.");
            }
            other => panic!("expected EndTurn, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_end_turn_multiple_text_blocks() {
        let raw = json!({
            "content": [
                { "type": "text", "text": "First." },
                { "type": "text", "text": "Second." }
            ],
            "stop_reason": "end_turn"
        })
        .to_string();

        let resp = AnthropicClient::parse_response(&raw).unwrap();
        match resp {
            ApiResponse::EndTurn { content } => {
                assert_eq!(content, "First.\nSecond.");
            }
            other => panic!("expected EndTurn, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_tool_use_no_block_errors() {
        // stop_reason says tool_use but there is no tool_use block
        let raw = json!({
            "content": [
                { "type": "text", "text": "oops" }
            ],
            "stop_reason": "tool_use"
        })
        .to_string();

        let result = AnthropicClient::parse_response(&raw);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("no tool_use block"),
            "error should mention missing tool_use block, got: {err_msg}"
        );
    }

    #[test]
    fn test_parse_unexpected_stop_reason() {
        let raw = json!({
            "content": [],
            "stop_reason": "max_tokens"
        })
        .to_string();

        let result = AnthropicClient::parse_response(&raw);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("max_tokens"),
            "error should mention the unexpected stop_reason, got: {err_msg}"
        );
    }

    #[test]
    fn test_parse_malformed_json() {
        let result = AnthropicClient::parse_response("not json at all");
        assert!(result.is_err());
    }

    // -- ContentBlock serde round-trip --------------------------------------

    #[test]
    fn test_content_block_text_roundtrip() {
        let block = ContentBlock::Text {
            text: "hello world".into(),
        };
        let json_str = serde_json::to_string(&block).unwrap();
        let deserialized: ContentBlock = serde_json::from_str(&json_str).unwrap();
        match deserialized {
            ContentBlock::Text { text } => assert_eq!(text, "hello world"),
            other => panic!("expected Text, got {:?}", other),
        }
    }

    #[test]
    fn test_content_block_tool_use_roundtrip() {
        let block = ContentBlock::ToolUse {
            id: "toolu_123".into(),
            name: "get_file".into(),
            input: json!({"path": "/etc/passwd"}),
        };
        let json_str = serde_json::to_string(&block).unwrap();
        let deserialized: ContentBlock = serde_json::from_str(&json_str).unwrap();
        match deserialized {
            ContentBlock::ToolUse { id, name, input } => {
                assert_eq!(id, "toolu_123");
                assert_eq!(name, "get_file");
                assert_eq!(input["path"], "/etc/passwd");
            }
            other => panic!("expected ToolUse, got {:?}", other),
        }
    }

    #[test]
    fn test_content_block_tool_result_roundtrip() {
        let block = ContentBlock::ToolResult {
            tool_use_id: "toolu_123".into(),
            content: "file contents here".into(),
        };
        let json_str = serde_json::to_string(&block).unwrap();
        let deserialized: ContentBlock = serde_json::from_str(&json_str).unwrap();
        match deserialized {
            ContentBlock::ToolResult {
                tool_use_id,
                content,
            } => {
                assert_eq!(tool_use_id, "toolu_123");
                assert_eq!(content, "file contents here");
            }
            other => panic!("expected ToolResult, got {:?}", other),
        }
    }

    #[test]
    fn test_tool_definition_serialization() {
        let tool = ToolDefinition {
            name: "analyze".into(),
            description: "Analyze a trace".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "trace_id": { "type": "string" }
                }
            }),
        };
        let json_str = serde_json::to_string(&tool).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert_eq!(parsed["name"], "analyze");
        assert_eq!(parsed["description"], "Analyze a trace");
        assert!(parsed["input_schema"]["properties"]["trace_id"].is_object());
    }

    #[test]
    fn test_message_serialization() {
        let msg = Message {
            role: "user".into(),
            content: vec![
                ContentBlock::Text {
                    text: "Check this".into(),
                },
                ContentBlock::ToolResult {
                    tool_use_id: "t1".into(),
                    content: "result data".into(),
                },
            ],
        };
        let json_str = serde_json::to_string(&msg).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert_eq!(parsed["role"], "user");
        assert_eq!(parsed["content"].as_array().unwrap().len(), 2);
        assert_eq!(parsed["content"][0]["type"], "text");
        assert_eq!(parsed["content"][1]["type"], "tool_result");
    }
}
