use anyhow::Result;
use async_trait::async_trait;

use crate::client::{ApiResponse, Message, ToolDefinition};

// ---------------------------------------------------------------------------
// LLM Backend trait
// ---------------------------------------------------------------------------

/// Trait abstracting over different LLM backends (Anthropic, Ollama, etc.).
///
/// This allows the agent loop and gate analyzer to work with any LLM provider
/// without knowing the concrete implementation.
#[async_trait]
pub trait LlmBackend: Send + Sync {
    async fn send_message(
        &self,
        system_prompt: &str,
        messages: &[Message],
        tools: &[ToolDefinition],
        output_schema: Option<&serde_json::Value>,
    ) -> Result<ApiResponse>;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::AnthropicClient;
    use crate::ollama::OllamaClient;

    /// Compile-time check: AnthropicClient implements LlmBackend.
    #[test]
    fn anthropic_client_implements_llm_backend() {
        let client = AnthropicClient::new("test-key".into(), "model".into());
        let _boxed: Box<dyn LlmBackend> = Box::new(client);
    }

    /// Compile-time check: OllamaClient implements LlmBackend.
    #[test]
    fn ollama_client_implements_llm_backend() {
        let client = OllamaClient::new(
            "http://127.0.0.1:11434".into(),
            "llama3.1:8b".into(),
        );
        let _boxed: Box<dyn LlmBackend> = Box::new(client);
    }
}
