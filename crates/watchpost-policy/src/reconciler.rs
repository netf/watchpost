use anyhow::{Context, Result};
use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;
use watchpost_types::TracingPolicySpec;

/// Result of a reconciliation pass.
#[derive(Debug, Clone, Default)]
pub struct ReconcileResult {
    /// Policies that were written (new or updated).
    pub added: Vec<String>,
    /// Policies that were removed from Tetragon's directory.
    pub removed: Vec<String>,
    /// Policies that were already present and unchanged.
    pub unchanged: Vec<String>,
}

/// File-based policy reconciler.
///
/// Compares desired state (base policies + active reactive policies) against
/// the actual files in Tetragon's policy directory and applies diffs by
/// writing/removing YAML files.
pub struct PolicyReconciler {
    base_policies_dir: PathBuf,
    tetragon_policy_dir: PathBuf,
}

impl PolicyReconciler {
    /// Create a new reconciler.
    ///
    /// - `base_dir`: directory containing shipped base TracingPolicy YAML files
    /// - `tetragon_dir`: Tetragon's policy directory (e.g. `/etc/tetragon/tetragon.tp.d/`)
    pub fn new(base_dir: PathBuf, tetragon_dir: PathBuf) -> Self {
        Self {
            base_policies_dir: base_dir,
            tetragon_policy_dir: tetragon_dir,
        }
    }

    /// Reconcile desired state against actual state.
    ///
    /// Reads base policy YAML files from the base directory and combines them
    /// with the provided active reactive policies. Writes all desired policies
    /// to the Tetragon policy directory and removes any files that are no longer
    /// desired.
    pub fn reconcile(&self, active_reactive: &[TracingPolicySpec]) -> Result<ReconcileResult> {
        fs::create_dir_all(&self.tetragon_policy_dir).with_context(|| {
            format!(
                "creating tetragon policy dir: {}",
                self.tetragon_policy_dir.display()
            )
        })?;

        // Collect desired policies: base + reactive
        let mut desired: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();

        // Load base policies from disk
        if self.base_policies_dir.exists() {
            for entry in fs::read_dir(&self.base_policies_dir).with_context(|| {
                format!(
                    "reading base policies dir: {}",
                    self.base_policies_dir.display()
                )
            })? {
                let entry = entry?;
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) == Some("yaml") {
                    let filename = path
                        .file_name()
                        .unwrap()
                        .to_string_lossy()
                        .into_owned();
                    let content = fs::read_to_string(&path)
                        .with_context(|| format!("reading base policy {}", path.display()))?;
                    desired.insert(filename, content);
                }
            }
        }

        // Add reactive policies
        for policy in active_reactive {
            let filename = format!("{}.yaml", policy.metadata.name);
            desired.insert(filename, policy.yaml_content.clone());
        }

        // Discover existing files in the Tetragon policy directory
        let mut existing_files: HashSet<String> = HashSet::new();
        if self.tetragon_policy_dir.exists() {
            for entry in fs::read_dir(&self.tetragon_policy_dir)? {
                let entry = entry?;
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) == Some("yaml") {
                    let filename = path
                        .file_name()
                        .unwrap()
                        .to_string_lossy()
                        .into_owned();
                    existing_files.insert(filename);
                }
            }
        }

        let mut result = ReconcileResult::default();

        // Write desired policies
        for (filename, content) in &desired {
            let target_path = self.tetragon_policy_dir.join(filename);

            // Check if content is identical to skip unnecessary writes
            if target_path.exists() {
                let existing_content = fs::read_to_string(&target_path).unwrap_or_default();
                if existing_content == *content {
                    result.unchanged.push(filename.clone());
                    continue;
                }
            }

            fs::write(&target_path, content)
                .with_context(|| format!("writing policy {}", target_path.display()))?;
            tracing::info!(filename = %filename, "reconciler wrote policy");
            result.added.push(filename.clone());
        }

        // Remove policies that are no longer desired
        for filename in &existing_files {
            if !desired.contains_key(filename) {
                let target_path = self.tetragon_policy_dir.join(filename);
                fs::remove_file(&target_path)
                    .with_context(|| format!("removing policy {}", target_path.display()))?;
                tracing::info!(filename = %filename, "reconciler removed policy");
                result.removed.push(filename.clone());
            }
        }

        // Sort for deterministic output
        result.added.sort();
        result.removed.sort();
        result.unchanged.sort();

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use watchpost_types::{PolicyMetadata, PolicySource};

    #[test]
    fn test_reconcile_base_policies_only() {
        let dir = tempdir().unwrap();
        let base_dir = dir.path().join("base");
        let tetragon_dir = dir.path().join("tetragon");
        fs::create_dir_all(&base_dir).unwrap();

        // Write a base policy
        fs::write(
            base_dir.join("watchpost-test.yaml"),
            "apiVersion: cilium.io/v1alpha1\nkind: TracingPolicy\nmetadata:\n  name: watchpost-test\nspec: {}\n",
        )
        .unwrap();

        let reconciler = PolicyReconciler::new(base_dir, tetragon_dir.clone());
        let result = reconciler.reconcile(&[]).unwrap();

        assert_eq!(result.added, vec!["watchpost-test.yaml"]);
        assert!(result.removed.is_empty());
        assert!(result.unchanged.is_empty());

        // Verify the file was written
        assert!(tetragon_dir.join("watchpost-test.yaml").exists());
    }

    #[test]
    fn test_reconcile_adds_reactive_policy() {
        let dir = tempdir().unwrap();
        let base_dir = dir.path().join("base");
        let tetragon_dir = dir.path().join("tetragon");
        fs::create_dir_all(&base_dir).unwrap();

        // Write a base policy
        let base_content = "apiVersion: cilium.io/v1alpha1\nkind: TracingPolicy\nmetadata:\n  name: watchpost-base\nspec: {}\n";
        fs::write(base_dir.join("watchpost-base.yaml"), base_content).unwrap();

        let reconciler = PolicyReconciler::new(base_dir, tetragon_dir.clone());

        // First reconcile with base only
        reconciler.reconcile(&[]).unwrap();

        // Now add a reactive policy
        let reactive = TracingPolicySpec {
            metadata: PolicyMetadata {
                name: "watchpost-reactive-block".to_string(),
                description: "Reactive block policy".to_string(),
                source: PolicySource::Reactive,
            },
            yaml_content: "apiVersion: cilium.io/v1alpha1\nkind: TracingPolicy\nmetadata:\n  name: watchpost-reactive-block\nspec: {}\n".to_string(),
        };

        let result = reconciler.reconcile(&[reactive]).unwrap();

        // The base policy should be unchanged (same content), reactive should be added
        assert!(result.added.contains(&"watchpost-reactive-block.yaml".to_string()));
        assert!(result.unchanged.contains(&"watchpost-base.yaml".to_string()));

        // Verify both files exist
        assert!(tetragon_dir.join("watchpost-base.yaml").exists());
        assert!(tetragon_dir.join("watchpost-reactive-block.yaml").exists());
    }
}
