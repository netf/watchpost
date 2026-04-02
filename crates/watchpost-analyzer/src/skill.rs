use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::client::ToolDefinition;

// ---------------------------------------------------------------------------
// Skill specification types
// ---------------------------------------------------------------------------

/// A skill specification loaded from a YAML file.
///
/// Skills define the system prompt, available tools, and expected output schema
/// for a particular LLM interaction pattern.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillSpec {
    pub name: String,
    pub version: String,
    pub system_prompt: String,
    pub tools: Vec<SkillToolDef>,
    pub output_schema: serde_json::Value,
}

/// A tool definition within a skill specification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillToolDef {
    pub name: String,
    pub description: String,
    pub parameters: serde_json::Value,
}

impl SkillSpec {
    /// Load a skill specification from a YAML file.
    pub fn load(path: &Path) -> Result<Self> {
        let contents =
            std::fs::read_to_string(path).with_context(|| format!("reading skill file: {}", path.display()))?;
        let spec: SkillSpec = serde_yml::from_str(&contents)
            .with_context(|| format!("parsing skill YAML: {}", path.display()))?;
        Ok(spec)
    }

    /// Convert the skill's tool definitions to the client API format.
    pub fn to_tool_definitions(&self) -> Vec<ToolDefinition> {
        self.tools
            .iter()
            .map(|t| ToolDefinition {
                name: t.name.clone(),
                description: t.description.clone(),
                input_schema: t.parameters.clone(),
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn skills_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../skills")
    }

    #[test]
    fn load_analyzer_skill() {
        let path = skills_dir().join("analyzer.yaml");
        let spec = SkillSpec::load(&path).expect("should load analyzer.yaml");

        assert_eq!(spec.name, "runtime-trace-analyzer");
        assert_eq!(spec.version, "1.0");
        assert_eq!(spec.tools.len(), 3);

        // Verify output_schema has the required fields
        let required = spec.output_schema["required"]
            .as_array()
            .expect("output_schema should have required array");
        let required_strs: Vec<&str> = required.iter().filter_map(|v| v.as_str()).collect();
        assert!(required_strs.contains(&"classification"));
        assert!(required_strs.contains(&"confidence"));
        assert!(required_strs.contains(&"recommended_action"));
        assert!(required_strs.contains(&"explanation"));
        assert!(required_strs.contains(&"profile_violations"));
    }

    #[test]
    fn to_tool_definitions_converts_correctly() {
        let path = skills_dir().join("analyzer.yaml");
        let spec = SkillSpec::load(&path).expect("should load analyzer.yaml");
        let tools = spec.to_tool_definitions();

        assert_eq!(tools.len(), 3);

        let names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
        assert!(names.contains(&"read_project_file"));
        assert!(names.contains(&"get_process_tree"));
        assert!(names.contains(&"get_recent_events"));

        // Verify parameters were mapped to input_schema
        for tool in &tools {
            assert_eq!(tool.input_schema["type"], "object");
            assert!(tool.input_schema["properties"].is_object());
        }
    }
}
