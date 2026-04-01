use serde::{Deserialize, Serialize};

/// Top-level daemon configuration, deserializable from TOML.
///
/// All fields use `#[serde(default)]` so that an empty TOML file
/// produces a fully valid configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct WatchpostConfig {
    pub daemon: DaemonConfig,
    pub enforcement: EnforcementConfig,
    pub notify: NotifyConfig,
    pub advanced: AdvancedConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DaemonConfig {
    pub api_key: String,
    pub log_level: LogLevel,
    pub data_dir: String,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            api_key: String::new(),
            log_level: LogLevel::default(),
            data_dir: "/var/lib/watchpost".to_owned(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

impl Default for LogLevel {
    fn default() -> Self {
        Self::Warn
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementMode {
    Autonomous,
    Advisory,
}

impl Default for EnforcementMode {
    fn default() -> Self {
        Self::Autonomous
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct EnforcementConfig {
    pub mode: EnforcementMode,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct NotifyConfig {
    pub desktop: bool,
    pub webhook_url: Option<String>,
}

impl Default for NotifyConfig {
    fn default() -> Self {
        Self {
            desktop: true,
            webhook_url: None,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct AdvancedConfig {
    pub tetragon: TetragonConfig,
    pub collector: CollectorConfig,
    pub engine: EngineConfig,
    pub analyzer: AnalyzerConfig,
    pub gate: GateConfig,
    pub profiles: ProfilesConfig,
    pub rules: RulesConfig,
    pub policy: PolicyConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TetragonConfig {
    pub endpoint: String,
    pub policy_dir: String,
}

impl Default for TetragonConfig {
    fn default() -> Self {
        Self {
            endpoint: "unix:///var/run/tetragon/tetragon.sock".to_owned(),
            policy_dir: "/etc/tetragon/tetragon.tp.d/".to_owned(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CollectorConfig {
    pub max_ancestry_depth: usize,
    pub manifest_cache_size: usize,
    pub event_channel_buffer: usize,
}

impl Default for CollectorConfig {
    fn default() -> Self {
        Self {
            max_ancestry_depth: 16,
            manifest_cache_size: 256,
            event_channel_buffer: 4096,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct EngineConfig {
    pub immediate_window_ms: u64,
    pub persistent_window_hours: u64,
    pub fast_path_threshold: f64,
    pub llm_threshold: f64,
    pub weight_overrides_path: String,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            immediate_window_ms: 5000,
            persistent_window_hours: 24,
            fast_path_threshold: 0.7,
            llm_threshold: 0.3,
            weight_overrides_path: "/var/lib/watchpost/weight_overrides.toml".to_owned(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AnalyzerBackend {
    Anthropic,
    Ollama,
}

impl Default for AnalyzerBackend {
    fn default() -> Self {
        Self::Anthropic
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AnalyzerConfig {
    pub backend: AnalyzerBackend,
    pub model: String,
    pub ollama_endpoint: Option<String>,
    pub ollama_model: Option<String>,
    pub max_analyses_per_minute: u32,
    pub analysis_queue_size: usize,
    pub max_tool_calls: u32,
}

impl Default for AnalyzerConfig {
    fn default() -> Self {
        Self {
            backend: AnalyzerBackend::default(),
            model: "claude-haiku-4-5-20251001".to_owned(),
            ollama_endpoint: None,
            ollama_model: None,
            max_analyses_per_minute: 10,
            analysis_queue_size: 50,
            max_tool_calls: 8,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GateMode {
    Enforce,
    Advisory,
}

impl Default for GateMode {
    fn default() -> Self {
        Self::Enforce
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GateConfig {
    pub enabled: bool,
    pub mode: GateMode,
    pub timeout_ms: u64,
    pub allowlist_path: String,
}

impl Default for GateConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            mode: GateMode::default(),
            timeout_ms: 5000,
            allowlist_path: "/var/lib/watchpost/gate_allowlist.db".to_owned(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ProfilesConfig {
    pub path: String,
}

impl Default for ProfilesConfig {
    fn default() -> Self {
        Self {
            path: "/etc/watchpost/profiles.d/".to_owned(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RulesConfig {
    pub path: String,
}

impl Default for RulesConfig {
    fn default() -> Self {
        Self {
            path: "/etc/watchpost/rules.d/".to_owned(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PolicyConfig {
    pub learning_threshold: u32,
    pub auto_activate_reactive: bool,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            learning_threshold: 5,
            auto_activate_reactive: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_from_empty_toml() {
        let config: WatchpostConfig = toml::from_str("").unwrap();
        assert_eq!(config.enforcement.mode, EnforcementMode::Autonomous);
        assert_eq!(config.daemon.data_dir, "/var/lib/watchpost");
        assert_eq!(config.daemon.log_level, LogLevel::Warn);
        assert!(config.daemon.api_key.is_empty());
        assert!(config.notify.desktop);
        assert!(config.notify.webhook_url.is_none());
        assert_eq!(
            config.advanced.tetragon.endpoint,
            "unix:///var/run/tetragon/tetragon.sock"
        );
        assert_eq!(config.advanced.collector.max_ancestry_depth, 16);
        assert_eq!(config.advanced.engine.immediate_window_ms, 5000);
        assert_eq!(config.advanced.engine.fast_path_threshold, 0.7);
        assert_eq!(config.advanced.analyzer.model, "claude-haiku-4-5-20251001");
        assert_eq!(config.advanced.analyzer.max_analyses_per_minute, 10);
        assert_eq!(config.advanced.analyzer.backend, AnalyzerBackend::Anthropic);
        assert!(config.advanced.gate.enabled);
        assert_eq!(config.advanced.gate.mode, GateMode::Enforce);
        assert_eq!(config.advanced.policy.learning_threshold, 5);
        assert!(config.advanced.policy.auto_activate_reactive);
    }

    #[test]
    fn config_partial_override() {
        let toml_str = r#"
[daemon]
log_level = "debug"
api_key = "sk-test"

[enforcement]
mode = "advisory"
"#;
        let config: WatchpostConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.daemon.log_level, LogLevel::Debug);
        assert_eq!(config.daemon.api_key, "sk-test");
        assert_eq!(config.enforcement.mode, EnforcementMode::Advisory);
        // Unchanged defaults
        assert_eq!(config.daemon.data_dir, "/var/lib/watchpost");
        assert!(config.notify.desktop);
    }
}
