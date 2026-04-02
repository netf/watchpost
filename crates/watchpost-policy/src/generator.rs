use serde::Serialize;
use watchpost_types::{PolicyMetadata, PolicySource, TracingPolicySpec};

/// Builds valid Tetragon TracingPolicy YAML from structured data.
pub struct PolicyBuilder {
    name: String,
    description: String,
    kprobes: Vec<KprobeSpec>,
    lsmhooks: Vec<LsmHookSpec>,
}

#[derive(Serialize, Clone)]
struct KprobeSpec {
    call: String,
    syscall: bool,
    args: Vec<ArgSpec>,
    selectors: Vec<SelectorSpec>,
}

#[derive(Serialize, Clone)]
struct LsmHookSpec {
    hook: String,
    args: Vec<ArgSpec>,
    selectors: Vec<SelectorSpec>,
}

#[derive(Serialize, Clone)]
struct ArgSpec {
    index: u32,
    #[serde(rename = "type")]
    arg_type: String,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct SelectorSpec {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    match_args: Vec<MatchArgSpec>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    match_binaries: Vec<MatchBinarySpec>,
    match_actions: Vec<MatchActionSpec>,
}

#[derive(Serialize, Clone)]
struct MatchArgSpec {
    index: u32,
    operator: String,
    values: Vec<String>,
}

#[derive(Serialize, Clone)]
struct MatchBinarySpec {
    operator: String,
    values: Vec<String>,
}

#[derive(Serialize, Clone)]
struct MatchActionSpec {
    action: String,
}

/// Top-level Tetragon TracingPolicy structure used for YAML serialization.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TracingPolicyYaml {
    api_version: String,
    kind: String,
    metadata: TracingPolicyMetadataYaml,
    spec: TracingPolicySpecYaml,
}

#[derive(Serialize)]
struct TracingPolicyMetadataYaml {
    name: String,
}

#[derive(Serialize)]
struct TracingPolicySpecYaml {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    kprobes: Vec<KprobeSpec>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    lsmhooks: Vec<LsmHookSpec>,
}

impl PolicyBuilder {
    /// Create a new policy builder with the given name and description.
    pub fn new(name: &str, description: &str) -> Self {
        Self {
            name: name.to_string(),
            description: description.to_string(),
            kprobes: Vec::new(),
            lsmhooks: Vec::new(),
        }
    }

    /// Add a network block rule using a kprobe on `tcp_connect`.
    ///
    /// The generated selector matches binaries in `binary_patterns` and filters
    /// on destination ports in `blocked_ports`, applying a `Sigkill` action.
    pub fn add_network_block(
        &mut self,
        binary_patterns: &[&str],
        blocked_ports: &[u16],
    ) -> &mut Self {
        let port_values: Vec<String> = blocked_ports.iter().map(|p| p.to_string()).collect();

        let selector = SelectorSpec {
            match_args: vec![MatchArgSpec {
                index: 0,
                operator: "InMap".to_string(),
                values: port_values,
            }],
            match_binaries: vec![MatchBinarySpec {
                operator: "In".to_string(),
                values: binary_patterns.iter().map(|s| s.to_string()).collect(),
            }],
            match_actions: vec![MatchActionSpec {
                action: "Sigkill".to_string(),
            }],
        };

        self.kprobes.push(KprobeSpec {
            call: "tcp_connect".to_string(),
            syscall: false,
            args: vec![ArgSpec {
                index: 0,
                arg_type: "sock".to_string(),
            }],
            selectors: vec![selector],
        });

        self
    }

    /// Add a file block rule using an LSM `security_file_permission` hook.
    ///
    /// The generated selector matches binaries in `binary_patterns` accessing
    /// files under `path_prefixes`, applying a `Sigkill` action.
    pub fn add_file_block(
        &mut self,
        binary_patterns: &[&str],
        path_prefixes: &[&str],
    ) -> &mut Self {
        let selector = SelectorSpec {
            match_args: vec![MatchArgSpec {
                index: 0,
                operator: "Prefix".to_string(),
                values: path_prefixes.iter().map(|s| s.to_string()).collect(),
            }],
            match_binaries: vec![MatchBinarySpec {
                operator: "In".to_string(),
                values: binary_patterns.iter().map(|s| s.to_string()).collect(),
            }],
            match_actions: vec![MatchActionSpec {
                action: "Sigkill".to_string(),
            }],
        };

        self.lsmhooks.push(LsmHookSpec {
            hook: "security_file_permission".to_string(),
            args: vec![
                ArgSpec {
                    index: 0,
                    arg_type: "file".to_string(),
                },
                ArgSpec {
                    index: 1,
                    arg_type: "int".to_string(),
                },
            ],
            selectors: vec![selector],
        });

        self
    }

    /// Build the final `TracingPolicySpec` containing the generated YAML.
    pub fn build(&self) -> TracingPolicySpec {
        let policy = TracingPolicyYaml {
            api_version: "cilium.io/v1alpha1".to_string(),
            kind: "TracingPolicy".to_string(),
            metadata: TracingPolicyMetadataYaml {
                name: self.name.clone(),
            },
            spec: TracingPolicySpecYaml {
                kprobes: self.kprobes.clone(),
                lsmhooks: self.lsmhooks.clone(),
            },
        };

        let yaml_content = serde_yml::to_string(&policy).expect("failed to serialize policy YAML");

        TracingPolicySpec {
            metadata: PolicyMetadata {
                name: self.name.clone(),
                description: self.description.clone(),
                source: PolicySource::Reactive,
            },
            yaml_content,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_block_policy() {
        let mut builder = PolicyBuilder::new("block-exfil", "Block data exfiltration");
        builder.add_network_block(&["/usr/bin/curl", "/usr/bin/wget"], &[443, 80]);
        let spec = builder.build();

        assert!(spec.yaml_content.contains("tcp_connect"));
        assert!(spec.yaml_content.contains("443"));
        assert!(spec.yaml_content.contains("80"));
        assert!(spec.yaml_content.contains("Sigkill"));
        assert!(spec.yaml_content.contains("block-exfil"));
        assert!(spec.yaml_content.contains("cilium.io/v1alpha1"));
        assert!(spec.yaml_content.contains("TracingPolicy"));
    }

    #[test]
    fn test_file_block_policy() {
        let mut builder = PolicyBuilder::new("block-sensitive", "Block sensitive file access");
        builder.add_file_block(&["/tmp/malware"], &["/etc/shadow", "/etc/passwd"]);
        let spec = builder.build();

        assert!(spec.yaml_content.contains("security_file_permission"));
        assert!(spec.yaml_content.contains("/etc/shadow"));
        assert!(spec.yaml_content.contains("/etc/passwd"));
        assert!(spec.yaml_content.contains("Sigkill"));
        assert!(spec.yaml_content.contains("block-sensitive"));
    }
}
