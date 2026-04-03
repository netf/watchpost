use std::collections::HashMap;
use std::path::Path;

use anyhow::{Context, Result};
use watchpost_types::{
    util::binary_basename, ActionContext, BehaviorClassification, BehaviorProfile, Ecosystem,
    EventKind, FileAccessType,
};

/// Store of behavior profiles keyed by ecosystem or context type name.
///
/// Profiles describe what a given action context (e.g. "npm install") is
/// expected and forbidden to do, enabling the scorer to suppress indicators
/// for benign activity and amplify indicators for forbidden activity.
pub struct BehaviorProfileStore {
    profiles: HashMap<String, BehaviorProfile>,
}

impl BehaviorProfileStore {
    /// Create an empty store (no profiles loaded).
    pub fn new() -> Self {
        Self {
            profiles: HashMap::new(),
        }
    }

    /// Load all `.yaml` files from the given directory, deserializing each as a
    /// [`BehaviorProfile`] and keying it by the profile's ecosystem (lowercased)
    /// or `context_type` field.
    pub fn load_dir(dir: &Path) -> Result<Self> {
        let mut profiles = HashMap::new();

        let entries = std::fs::read_dir(dir)
            .with_context(|| format!("reading profile directory: {}", dir.display()))?;

        for entry in entries {
            let entry = entry?;
            let path = entry.path();

            let ext = path.extension().and_then(|e| e.to_str());
            if ext != Some("yaml") && ext != Some("yml") {
                continue;
            }

            let contents = std::fs::read_to_string(&path)
                .with_context(|| format!("reading profile file: {}", path.display()))?;

            let profile: BehaviorProfile = serde_yml::from_str(&contents)
                .with_context(|| format!("parsing profile file: {}", path.display()))?;

            let key = profile_key(&profile);
            profiles.insert(key, profile);
        }

        Ok(Self { profiles })
    }

    /// Insert a profile programmatically (useful for testing).
    pub fn insert(&mut self, key: impl Into<String>, profile: BehaviorProfile) {
        self.profiles.insert(key.into(), profile);
    }

    /// Look up the profile for the given action context.
    ///
    /// Mapping:
    /// - `PackageInstall(Npm)` -> "npm"
    /// - `PackageInstall(Pip)` -> "pip"
    /// - `PackageInstall(Cargo)` or `Build("cargo")` -> "cargo"
    /// - Everything else -> "system"
    pub fn get_profile(&self, context: &ActionContext) -> Option<&BehaviorProfile> {
        let key = context_to_key(context);
        self.profiles.get(key)
    }

    /// Classify a single event against the relevant behavior profile.
    ///
    /// Returns [`BehaviorClassification::Expected`] if the event matches an
    /// expected pattern, [`BehaviorClassification::Forbidden`] if it matches a
    /// forbidden pattern, or [`BehaviorClassification::Unspecified`] otherwise.
    pub fn classify_event(
        &self,
        event_kind: &EventKind,
        context: &ActionContext,
    ) -> BehaviorClassification {
        let Some(profile) = self.get_profile(context) else {
            return BehaviorClassification::Unspecified;
        };

        match event_kind {
            EventKind::ProcessExec { binary, .. } => {
                let basename = binary_basename(binary);

                if profile.forbidden_children.iter().any(|f| f == basename) {
                    return BehaviorClassification::Forbidden;
                }
                if profile.expected_children.iter().any(|e| e == basename) {
                    return BehaviorClassification::Expected;
                }
            }
            EventKind::FileAccess { path, access_type } => {
                // Check forbidden first (forbidden_file_access applies to any access type).
                if profile
                    .forbidden_file_access
                    .iter()
                    .any(|prefix| path.contains(prefix))
                {
                    return BehaviorClassification::Forbidden;
                }

                // Expected file writes.
                if *access_type == FileAccessType::Write
                    && profile
                        .expected_file_writes
                        .iter()
                        .any(|prefix| path.starts_with(prefix))
                {
                    return BehaviorClassification::Expected;
                }
            }
            EventKind::NetworkConnect {
                dest_ip, dest_port, ..
            } => {
                // Check forbidden network first.
                if matches_network(&profile.forbidden_network, dest_ip, *dest_port) {
                    return BehaviorClassification::Forbidden;
                }
                if matches_network(&profile.expected_network, dest_ip, *dest_port) {
                    return BehaviorClassification::Expected;
                }
            }
            _ => {}
        }

        BehaviorClassification::Unspecified
    }
}

impl Default for BehaviorProfileStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Derive the store key from a profile: use ecosystem name if present, else
/// context_type.
fn profile_key(profile: &BehaviorProfile) -> String {
    match &profile.ecosystem {
        Some(eco) => match eco {
            Ecosystem::Npm => "npm".into(),
            Ecosystem::Pip => "pip".into(),
            Ecosystem::Cargo => "cargo".into(),
        },
        None => profile.context_type.to_lowercase(),
    }
}

/// Map an `ActionContext` to a profile store key.
fn context_to_key(context: &ActionContext) -> &str {
    match context {
        ActionContext::PackageInstall {
            ecosystem: Ecosystem::Npm,
            ..
        } => "npm",
        ActionContext::PackageInstall {
            ecosystem: Ecosystem::Pip,
            ..
        } => "pip",
        ActionContext::PackageInstall {
            ecosystem: Ecosystem::Cargo,
            ..
        } => "cargo",
        ActionContext::Build { toolchain, .. } if toolchain == "cargo" => "cargo",
        ActionContext::FlatpakApp { .. } => "flatpak",
        _ => "system",
    }
}

// binary_basename is imported from watchpost_types::util

/// Check whether a destination matches any entry in a list of network
/// expectations. An expectation matches if its host is a substring of the
/// destination IP/hostname, and its port (if specified) matches.
fn matches_network(
    expectations: &[watchpost_types::NetworkExpectation],
    dest_ip: &str,
    dest_port: u16,
) -> bool {
    expectations.iter().any(|exp| {
        let host_matches = match &exp.host {
            Some(h) => dest_ip.contains(h.as_str()),
            None => true,
        };
        let port_matches = match exp.port {
            Some(p) => p == dest_port,
            None => true,
        };
        host_matches && port_matches
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use watchpost_types::{BehaviorProfile, Ecosystem, NetworkExpectation};

    /// Build a minimal npm profile for testing.
    fn npm_profile() -> BehaviorProfile {
        BehaviorProfile {
            context_type: "package_install".into(),
            ecosystem: Some(Ecosystem::Npm),
            expected_network: vec![NetworkExpectation {
                host: Some("registry.npmjs.org".into()),
                port: Some(443),
                description: "npm registry".into(),
            }],
            expected_children: vec![
                "node".into(),
                "node-gyp".into(),
                "sh".into(),
            ],
            expected_file_writes: vec![
                "node_modules/".into(),
                "/tmp/npm-".into(),
            ],
            forbidden_file_access: vec![
                ".ssh/".into(),
                ".gnupg/".into(),
                ".aws/".into(),
            ],
            forbidden_children: vec![
                "nc".into(),
                "ncat".into(),
                "nmap".into(),
            ],
            forbidden_network: vec![],
        }
    }

    #[test]
    fn classify_expected_child() {
        let mut store = BehaviorProfileStore::new();
        store.insert("npm", npm_profile());

        let context = ActionContext::PackageInstall {
            ecosystem: Ecosystem::Npm,
            package_name: Some("lodash".into()),
            package_version: None,
            working_dir: "/home/user/project".into(),
        };

        let event = EventKind::ProcessExec {
            binary: "/usr/bin/node-gyp".into(),
            args: vec![],
            cwd: "/tmp".into(),
            uid: 1000,
        };

        assert_eq!(
            store.classify_event(&event, &context),
            BehaviorClassification::Expected
        );
    }

    #[test]
    fn classify_forbidden_file_read() {
        let mut store = BehaviorProfileStore::new();
        store.insert("npm", npm_profile());

        let context = ActionContext::PackageInstall {
            ecosystem: Ecosystem::Npm,
            package_name: Some("evil".into()),
            package_version: None,
            working_dir: "/home/user/project".into(),
        };

        let event = EventKind::FileAccess {
            path: "/home/user/.ssh/id_rsa".into(),
            access_type: FileAccessType::Read,
        };

        assert_eq!(
            store.classify_event(&event, &context),
            BehaviorClassification::Forbidden
        );
    }

    #[test]
    fn classify_unspecified_binary() {
        let mut store = BehaviorProfileStore::new();
        store.insert("npm", npm_profile());

        let context = ActionContext::PackageInstall {
            ecosystem: Ecosystem::Npm,
            package_name: Some("pkg".into()),
            package_version: None,
            working_dir: "/home/user/project".into(),
        };

        let event = EventKind::ProcessExec {
            binary: "/usr/bin/python3".into(),
            args: vec![],
            cwd: "/tmp".into(),
            uid: 1000,
        };

        assert_eq!(
            store.classify_event(&event, &context),
            BehaviorClassification::Unspecified
        );
    }

    #[test]
    fn classify_expected_network() {
        let mut store = BehaviorProfileStore::new();
        store.insert("npm", npm_profile());

        let context = ActionContext::PackageInstall {
            ecosystem: Ecosystem::Npm,
            package_name: Some("lodash".into()),
            package_version: None,
            working_dir: "/home/user/project".into(),
        };

        let event = EventKind::NetworkConnect {
            dest_ip: "registry.npmjs.org".into(),
            dest_port: 443,
            protocol: "tcp".into(),
        };

        assert_eq!(
            store.classify_event(&event, &context),
            BehaviorClassification::Expected
        );
    }

    #[test]
    fn classify_no_profile_returns_unspecified() {
        let store = BehaviorProfileStore::new();

        let context = ActionContext::PackageInstall {
            ecosystem: Ecosystem::Npm,
            package_name: None,
            package_version: None,
            working_dir: "/tmp".into(),
        };

        let event = EventKind::ProcessExec {
            binary: "/bin/sh".into(),
            args: vec![],
            cwd: "/tmp".into(),
            uid: 1000,
        };

        assert_eq!(
            store.classify_event(&event, &context),
            BehaviorClassification::Unspecified,
            "no profiles loaded should return Unspecified"
        );
    }

    #[test]
    fn context_to_key_mapping() {
        assert_eq!(
            context_to_key(&ActionContext::PackageInstall {
                ecosystem: Ecosystem::Npm,
                package_name: None,
                package_version: None,
                working_dir: "/tmp".into(),
            }),
            "npm"
        );
        assert_eq!(
            context_to_key(&ActionContext::PackageInstall {
                ecosystem: Ecosystem::Pip,
                package_name: None,
                package_version: None,
                working_dir: "/tmp".into(),
            }),
            "pip"
        );
        assert_eq!(
            context_to_key(&ActionContext::Build {
                toolchain: "cargo".into(),
                working_dir: "/tmp".into(),
            }),
            "cargo"
        );
        assert_eq!(
            context_to_key(&ActionContext::ShellCommand { tty: None }),
            "system"
        );
    }

    #[test]
    fn classify_forbidden_child() {
        let mut store = BehaviorProfileStore::new();
        store.insert("npm", npm_profile());

        let context = ActionContext::PackageInstall {
            ecosystem: Ecosystem::Npm,
            package_name: Some("evil".into()),
            package_version: None,
            working_dir: "/tmp".into(),
        };

        let event = EventKind::ProcessExec {
            binary: "/usr/bin/nc".into(),
            args: vec!["nc".into(), "-e".into(), "/bin/sh".into()],
            cwd: "/tmp".into(),
            uid: 1000,
        };

        assert_eq!(
            store.classify_event(&event, &context),
            BehaviorClassification::Forbidden
        );
    }

    #[test]
    fn classify_expected_file_write() {
        let mut store = BehaviorProfileStore::new();
        store.insert("npm", npm_profile());

        let context = ActionContext::PackageInstall {
            ecosystem: Ecosystem::Npm,
            package_name: Some("lodash".into()),
            package_version: None,
            working_dir: "/home/user/project".into(),
        };

        let event = EventKind::FileAccess {
            path: "node_modules/lodash/index.js".into(),
            access_type: FileAccessType::Write,
        };

        assert_eq!(
            store.classify_event(&event, &context),
            BehaviorClassification::Expected
        );
    }

    // ------------------------------------------------------------------
    // Tests for shipped profile YAML files
    // ------------------------------------------------------------------

    #[test]
    fn load_shipped_profiles() {
        let profiles_dir =
            std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../../profiles"));
        let store = BehaviorProfileStore::load_dir(profiles_dir)
            .expect("should load shipped profiles from profiles/ directory");

        // At least 4 profiles: npm, cargo, pip, system
        assert!(
            store.profiles.len() >= 4,
            "expected at least 4 profiles, got {}",
            store.profiles.len()
        );

        // npm profile checks
        let npm = store
            .profiles
            .get("npm")
            .expect("npm profile should be loaded");
        assert!(
            npm.expected_children.contains(&"node-gyp".to_string()),
            "npm profile should have node-gyp in expected_children"
        );
        assert!(
            npm.forbidden_file_access.contains(&".ssh/".to_string()),
            "npm profile should have .ssh/ in forbidden_file_access"
        );

        // cargo profile checks
        let cargo = store
            .profiles
            .get("cargo")
            .expect("cargo profile should be loaded");
        assert!(
            cargo.expected_children.contains(&"rustc".to_string()),
            "cargo profile should have rustc in expected_children"
        );

        // pip profile exists
        assert!(
            store.profiles.contains_key("pip"),
            "pip profile should be loaded"
        );

        // system profile exists
        assert!(
            store.profiles.contains_key("system"),
            "system profile should be loaded"
        );
    }

    #[test]
    fn tracing_policy_yaml_files_are_valid() {
        let policies_dir =
            std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../../policies"));
        let entries = std::fs::read_dir(policies_dir)
            .expect("should be able to read policies/ directory");

        let mut count = 0;
        for entry in entries {
            let entry = entry.expect("directory entry should be readable");
            let path = entry.path();

            let ext = path.extension().and_then(|e| e.to_str());
            if ext != Some("yaml") && ext != Some("yml") {
                continue;
            }

            let contents = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("should read {}: {e}", path.display()));

            // Parse as generic YAML value to verify it is valid YAML.
            let _value: serde_yml::Value = serde_yml::from_str(&contents)
                .unwrap_or_else(|e| panic!("{} should be valid YAML: {e}", path.display()));

            count += 1;
        }

        assert!(
            count >= 4,
            "expected at least 4 TracingPolicy YAML files, found {count}"
        );
    }

    #[test]
    fn toolchain_monitoring_policies_are_valid_and_well_structured() {
        let policies_dir =
            std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../../policies"));

        let toolchain_policies = [
            ("npm-monitoring.yaml", "watchpost-npm-monitoring"),
            ("cargo-monitoring.yaml", "watchpost-cargo-monitoring"),
            ("pip-monitoring.yaml", "watchpost-pip-monitoring"),
        ];

        for (filename, expected_name) in &toolchain_policies {
            let path = policies_dir.join(filename);
            assert!(
                path.exists(),
                "toolchain policy file should exist: {}",
                path.display()
            );

            let contents = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("should read {}: {e}", path.display()));

            let value: serde_yml::Value = serde_yml::from_str(&contents)
                .unwrap_or_else(|e| panic!("{} should be valid YAML: {e}", path.display()));

            // Check apiVersion
            assert_eq!(
                value["apiVersion"].as_str(),
                Some("cilium.io/v1alpha1"),
                "{filename}: apiVersion should be cilium.io/v1alpha1"
            );

            // Check kind
            assert_eq!(
                value["kind"].as_str(),
                Some("TracingPolicy"),
                "{filename}: kind should be TracingPolicy"
            );

            // Check metadata.name matches the expected naming convention
            assert_eq!(
                value["metadata"]["name"].as_str(),
                Some(*expected_name),
                "{filename}: metadata.name should be {expected_name}"
            );

            // Check spec.kprobes exists with tcp_connect
            let kprobes = &value["spec"]["kprobes"];
            assert!(
                kprobes.is_sequence(),
                "{filename}: spec.kprobes should be a list"
            );
            let kprobe_call = kprobes[0]["call"].as_str();
            assert_eq!(
                kprobe_call,
                Some("tcp_connect"),
                "{filename}: first kprobe should be tcp_connect"
            );

            // Check spec.lsmhooks exists with security_file_permission
            let lsmhooks = &value["spec"]["lsmhooks"];
            assert!(
                lsmhooks.is_sequence(),
                "{filename}: spec.lsmhooks should be a list"
            );
            let lsm_hook = lsmhooks[0]["hook"].as_str();
            assert_eq!(
                lsm_hook,
                Some("security_file_permission"),
                "{filename}: first lsmhook should be security_file_permission"
            );

            // Check that matchBinaries uses Post action (observe only)
            let kprobe_action = kprobes[0]["selectors"][0]["matchActions"][0]["action"].as_str();
            assert_eq!(
                kprobe_action,
                Some("Post"),
                "{filename}: kprobe matchActions should use Post action"
            );

            let lsm_action = lsmhooks[0]["selectors"][0]["matchActions"][0]["action"].as_str();
            assert_eq!(
                lsm_action,
                Some("Post"),
                "{filename}: lsmhook matchActions should use Post action"
            );
        }
    }

    #[test]
    fn toolchain_policy_names_follow_convention() {
        let policies_dir =
            std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../../policies"));

        // All monitoring policies must follow the naming convention:
        // watchpost-{ecosystem}-monitoring
        let monitoring_files: Vec<_> = std::fs::read_dir(policies_dir)
            .expect("should read policies dir")
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.path()
                    .file_name()
                    .and_then(|n| n.to_str())
                    .map(|n| n.ends_with("-monitoring.yaml"))
                    .unwrap_or(false)
            })
            .collect();

        assert!(
            monitoring_files.len() >= 3,
            "expected at least 3 monitoring policy files, found {}",
            monitoring_files.len()
        );

        for entry in &monitoring_files {
            let path = entry.path();
            let contents = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("should read {}: {e}", path.display()));

            let value: serde_yml::Value = serde_yml::from_str(&contents)
                .unwrap_or_else(|e| panic!("{} should be valid YAML: {e}", path.display()));

            let name = value["metadata"]["name"]
                .as_str()
                .unwrap_or_else(|| panic!("{}: metadata.name should be a string", path.display()));

            assert!(
                name.starts_with("watchpost-") && name.ends_with("-monitoring"),
                "{}: policy name '{}' should match watchpost-{{ecosystem}}-monitoring pattern",
                path.display(),
                name
            );
        }
    }

    #[test]
    fn total_tracing_policy_count_includes_toolchain() {
        let policies_dir =
            std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../../policies"));
        let entries = std::fs::read_dir(policies_dir)
            .expect("should be able to read policies/ directory");

        let mut count = 0;
        for entry in entries {
            let entry = entry.expect("directory entry should be readable");
            let path = entry.path();
            let ext = path.extension().and_then(|e| e.to_str());
            if ext != Some("yaml") && ext != Some("yml") {
                continue;
            }
            count += 1;
        }

        // 5 base + 3 toolchain = 8 total
        assert!(
            count >= 8,
            "expected at least 8 TracingPolicy YAML files (5 base + 3 toolchain), found {count}"
        );
    }
}
