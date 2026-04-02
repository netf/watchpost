use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::client::{ApiResponse, ContentBlock, Message, ToolDefinition};

// ---------------------------------------------------------------------------
// Ollama message types (wire format)
// ---------------------------------------------------------------------------

/// A message in the Ollama chat format (simpler than Anthropic).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OllamaMessage {
    pub role: String,
    pub content: String,
}

/// Request body for Ollama's `/api/chat` endpoint.
#[derive(Debug, Serialize)]
pub struct OllamaChatRequest {
    model: String,
    messages: Vec<OllamaMessage>,
    stream: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    format: Option<String>,
}

/// Response body from Ollama's `/api/chat` endpoint.
#[derive(Debug, Deserialize)]
struct OllamaChatResponse {
    message: OllamaResponseMessage,
    #[allow(dead_code)]
    done: bool,
}

#[derive(Debug, Deserialize)]
struct OllamaResponseMessage {
    #[allow(dead_code)]
    role: String,
    content: String,
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

/// HTTP client for the Ollama local LLM API.
pub struct OllamaClient {
    http: reqwest::Client,
    endpoint: String,
    model: String,
}

impl OllamaClient {
    /// Create a new client targeting a local Ollama instance.
    ///
    /// * `endpoint` – Base URL, e.g. `"http://127.0.0.1:11434"`.
    /// * `model`    – Model identifier, e.g. `"llama3.1:8b"`.
    pub fn new(endpoint: String, model: String) -> Self {
        Self {
            http: reqwest::Client::new(),
            endpoint,
            model,
        }
    }

    /// Send a message to the Ollama `/api/chat` endpoint and return the parsed
    /// response.
    ///
    /// Ollama does not support tool use in our flow, so this always returns
    /// `ApiResponse::EndTurn`.
    ///
    /// The `_tools` parameter is accepted for interface compatibility but
    /// ignored (Ollama tool support is limited).
    pub async fn send_message(
        &self,
        system_prompt: &str,
        messages: &[Message],
        _tools: &[ToolDefinition],
        output_schema: Option<&serde_json::Value>,
    ) -> Result<ApiResponse> {
        let json_mode = output_schema.is_some();
        let body = self.build_request_body(system_prompt, messages, json_mode);

        debug!(model = %self.model, json_mode, "sending request to Ollama API");

        let url = format!("{}/api/chat", self.endpoint);

        let resp = self
            .http
            .post(&url)
            .header("content-type", "application/json")
            .json(&body)
            .send()
            .await
            .context("failed to send request to Ollama API")?;

        let status = resp.status();
        if !status.is_success() {
            let error_body = resp
                .text()
                .await
                .unwrap_or_else(|_| "<failed to read body>".to_string());
            bail!(
                "Ollama API returned HTTP {}: {}",
                status.as_u16(),
                error_body
            );
        }

        let raw_text = resp
            .text()
            .await
            .context("failed to read Ollama API response body")?;

        Self::parse_response(&raw_text, json_mode)
    }

    /// Build the JSON request body without sending it.
    ///
    /// Exposed for testing so we can assert on the structure without hitting
    /// the network.
    pub fn build_request_body(
        &self,
        system_prompt: &str,
        messages: &[Message],
        json_mode: bool,
    ) -> OllamaChatRequest {
        let mut ollama_messages = Vec::with_capacity(messages.len() + 1);

        // System message first.
        ollama_messages.push(OllamaMessage {
            role: "system".to_string(),
            content: system_prompt.to_string(),
        });

        // Convert our Message type to Ollama's simpler format.
        for msg in messages {
            let text = convert_message_to_text(msg);
            if !text.is_empty() {
                ollama_messages.push(OllamaMessage {
                    role: msg.role.clone(),
                    content: text,
                });
            }
        }

        OllamaChatRequest {
            model: self.model.clone(),
            messages: ollama_messages,
            stream: false,
            format: if json_mode {
                Some("json".to_string())
            } else {
                None
            },
        }
    }

    /// Parse the raw JSON response body into an [`ApiResponse`].
    ///
    /// Separated from `send_message` so it can be tested without network
    /// access.
    pub fn parse_response(raw: &str, json_mode: bool) -> Result<ApiResponse> {
        let resp: OllamaChatResponse =
            serde_json::from_str(raw).context("failed to parse Ollama API response JSON")?;

        let content = resp.message.content;

        // If JSON mode was requested, validate the response is valid JSON.
        if json_mode {
            serde_json::from_str::<serde_json::Value>(&content)
                .context("Ollama returned non-JSON response despite format: json")?;
        }

        Ok(ApiResponse::EndTurn { content })
    }
}

// ---------------------------------------------------------------------------
// Message conversion helpers
// ---------------------------------------------------------------------------

/// Convert our internal `Message` type to a plain text string for Ollama.
///
/// - `ContentBlock::Text` blocks are concatenated.
/// - `ContentBlock::ToolResult` blocks are formatted as text.
/// - `ContentBlock::ToolUse` blocks are skipped (assistant tool requests).
pub fn convert_message_to_text(msg: &Message) -> String {
    let mut parts = Vec::new();

    for block in &msg.content {
        match block {
            ContentBlock::Text { text } => {
                if !text.is_empty() {
                    parts.push(text.clone());
                }
            }
            ContentBlock::ToolResult {
                tool_use_id,
                content,
            } => {
                parts.push(format!("[Tool Result for {tool_use_id}]: {content}"));
            }
            ContentBlock::ToolUse { .. } => {
                // Skip — these are assistant tool requests, not relevant for
                // Ollama's simpler message format.
            }
        }
    }

    parts.join("\n")
}

// ---------------------------------------------------------------------------
// LlmBackend implementation
// ---------------------------------------------------------------------------

#[async_trait::async_trait]
impl crate::backend::LlmBackend for OllamaClient {
    async fn send_message(
        &self,
        system_prompt: &str,
        messages: &[Message],
        tools: &[ToolDefinition],
        output_schema: Option<&serde_json::Value>,
    ) -> Result<ApiResponse> {
        self.send_message(system_prompt, messages, tools, output_schema)
            .await
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // -- Message conversion ---------------------------------------------------

    #[test]
    fn convert_text_message() {
        let msg = Message {
            role: "user".to_string(),
            content: vec![ContentBlock::Text {
                text: "Hello world".to_string(),
            }],
        };
        let text = convert_message_to_text(&msg);
        assert_eq!(text, "Hello world");
    }

    #[test]
    fn convert_multiple_text_blocks() {
        let msg = Message {
            role: "user".to_string(),
            content: vec![
                ContentBlock::Text {
                    text: "First".to_string(),
                },
                ContentBlock::Text {
                    text: "Second".to_string(),
                },
            ],
        };
        let text = convert_message_to_text(&msg);
        assert_eq!(text, "First\nSecond");
    }

    #[test]
    fn convert_tool_result_block() {
        let msg = Message {
            role: "user".to_string(),
            content: vec![ContentBlock::ToolResult {
                tool_use_id: "toolu_123".to_string(),
                content: "file contents here".to_string(),
            }],
        };
        let text = convert_message_to_text(&msg);
        assert_eq!(text, "[Tool Result for toolu_123]: file contents here");
    }

    #[test]
    fn convert_skips_tool_use_blocks() {
        let msg = Message {
            role: "assistant".to_string(),
            content: vec![ContentBlock::ToolUse {
                id: "toolu_456".to_string(),
                name: "read_file".to_string(),
                input: json!({"path": "/tmp/test"}),
            }],
        };
        let text = convert_message_to_text(&msg);
        assert!(text.is_empty());
    }

    #[test]
    fn convert_mixed_blocks() {
        let msg = Message {
            role: "user".to_string(),
            content: vec![
                ContentBlock::Text {
                    text: "Here is the context".to_string(),
                },
                ContentBlock::ToolResult {
                    tool_use_id: "t1".to_string(),
                    content: "result data".to_string(),
                },
                ContentBlock::ToolUse {
                    id: "t2".to_string(),
                    name: "get_file".to_string(),
                    input: json!({}),
                },
                ContentBlock::Text {
                    text: "And more text".to_string(),
                },
            ],
        };
        let text = convert_message_to_text(&msg);
        assert_eq!(
            text,
            "Here is the context\n[Tool Result for t1]: result data\nAnd more text"
        );
    }

    // -- Response parsing -----------------------------------------------------

    #[test]
    fn parse_valid_text_response() {
        let raw = json!({
            "message": {
                "role": "assistant",
                "content": "This process looks benign."
            },
            "done": true
        })
        .to_string();

        let resp = OllamaClient::parse_response(&raw, false).unwrap();
        match resp {
            ApiResponse::EndTurn { content } => {
                assert_eq!(content, "This process looks benign.");
            }
            other => panic!("expected EndTurn, got {:?}", other),
        }
    }

    #[test]
    fn parse_valid_json_response() {
        let inner_json = json!({
            "classification": "benign",
            "confidence": 0.9,
            "recommended_action": "allow",
            "explanation": "Normal behavior"
        });
        let raw = json!({
            "message": {
                "role": "assistant",
                "content": inner_json.to_string()
            },
            "done": true
        })
        .to_string();

        let resp = OllamaClient::parse_response(&raw, true).unwrap();
        match resp {
            ApiResponse::EndTurn { content } => {
                // Verify the content is valid JSON
                let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
                assert_eq!(parsed["classification"], "benign");
            }
            other => panic!("expected EndTurn, got {:?}", other),
        }
    }

    #[test]
    fn parse_json_mode_rejects_non_json() {
        let raw = json!({
            "message": {
                "role": "assistant",
                "content": "This is not JSON"
            },
            "done": true
        })
        .to_string();

        let result = OllamaClient::parse_response(&raw, true);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("non-JSON"),
            "error should mention non-JSON, got: {err}"
        );
    }

    #[test]
    fn parse_malformed_response() {
        let result = OllamaClient::parse_response("not json at all", false);
        assert!(result.is_err());
    }

    // -- Request body construction --------------------------------------------

    #[test]
    fn build_request_body_basic() {
        let client = OllamaClient::new(
            "http://127.0.0.1:11434".to_string(),
            "llama3.1:8b".to_string(),
        );

        let messages = vec![Message {
            role: "user".to_string(),
            content: vec![ContentBlock::Text {
                text: "Hello".to_string(),
            }],
        }];

        let body = client.build_request_body("You are a security analyst.", &messages, false);

        assert_eq!(body.model, "llama3.1:8b");
        assert!(!body.stream);
        assert!(body.format.is_none());
        assert_eq!(body.messages.len(), 2); // system + user
        assert_eq!(body.messages[0].role, "system");
        assert_eq!(body.messages[0].content, "You are a security analyst.");
        assert_eq!(body.messages[1].role, "user");
        assert_eq!(body.messages[1].content, "Hello");
    }

    #[test]
    fn build_request_body_json_mode() {
        let client = OllamaClient::new(
            "http://127.0.0.1:11434".to_string(),
            "llama3.1:8b".to_string(),
        );

        let body = client.build_request_body("sys", &[], true);

        assert_eq!(body.format, Some("json".to_string()));
        // Only system message when no user messages
        assert_eq!(body.messages.len(), 1);
    }

    #[test]
    fn build_request_body_converts_tool_results() {
        let client = OllamaClient::new(
            "http://127.0.0.1:11434".to_string(),
            "llama3.1:8b".to_string(),
        );

        let messages = vec![
            Message {
                role: "user".to_string(),
                content: vec![ContentBlock::Text {
                    text: "Analyze this".to_string(),
                }],
            },
            Message {
                role: "assistant".to_string(),
                content: vec![ContentBlock::ToolUse {
                    id: "t1".to_string(),
                    name: "read_file".to_string(),
                    input: json!({"path": "/tmp/test"}),
                }],
            },
            Message {
                role: "user".to_string(),
                content: vec![ContentBlock::ToolResult {
                    tool_use_id: "t1".to_string(),
                    content: "file contents".to_string(),
                }],
            },
        ];

        let body = client.build_request_body("sys", &messages, false);

        // system + user("Analyze this") + user("[Tool Result for t1]: file contents")
        // The assistant ToolUse-only message is skipped (empty text).
        assert_eq!(body.messages.len(), 3);
        assert_eq!(body.messages[1].content, "Analyze this");
        assert_eq!(
            body.messages[2].content,
            "[Tool Result for t1]: file contents"
        );
    }
}
