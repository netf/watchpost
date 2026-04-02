use std::collections::HashMap;
use std::path::Path;

use anyhow::{Context, Result};
use watchpost_types::{
    ActionContext, BehaviorClassification, BehaviorProfile, Ecosystem, EventKind, FileAccessType,
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
        _ => "system",
    }
}

/// Extract the basename from a binary path (e.g. "/usr/bin/node" -> "node").
fn binary_basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

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
}
