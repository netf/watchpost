use anyhow::{Context, Result, bail};
use std::fs;
use std::path::PathBuf;
use watchpost_types::TracingPolicySpec;

/// Manages reactive policies that need approval before activation.
///
/// Staged policies live in `staging_dir` until approved, at which point
/// they are moved to `active_dir`.
pub struct StagedPolicyManager {
    staging_dir: PathBuf,
    active_dir: PathBuf,
}

impl StagedPolicyManager {
    /// Create a new staged policy manager, creating directories if needed.
    pub fn new(staging_dir: PathBuf, active_dir: PathBuf) -> Result<Self> {
        fs::create_dir_all(&staging_dir)
            .with_context(|| format!("creating staging dir: {}", staging_dir.display()))?;
        fs::create_dir_all(&active_dir)
            .with_context(|| format!("creating active dir: {}", active_dir.display()))?;
        Ok(Self {
            staging_dir,
            active_dir,
        })
    }

    /// Stage a policy by writing its YAML to the staging directory.
    pub fn stage(&self, policy: &TracingPolicySpec) -> Result<()> {
        let filename = format!("{}.yaml", policy.metadata.name);
        let path = self.staging_dir.join(&filename);
        fs::write(&path, &policy.yaml_content)
            .with_context(|| format!("writing staged policy to {}", path.display()))?;
        tracing::info!(name = %policy.metadata.name, "policy staged");
        Ok(())
    }

    /// Approve a staged policy by moving it from staging to active.
    pub fn approve(&self, name: &str) -> Result<()> {
        let filename = format!("{}.yaml", name);
        let staged_path = self.staging_dir.join(&filename);
        let active_path = self.active_dir.join(&filename);

        if !staged_path.exists() {
            bail!("staged policy '{}' not found at {}", name, staged_path.display());
        }

        fs::rename(&staged_path, &active_path).with_context(|| {
            format!(
                "moving policy from {} to {}",
                staged_path.display(),
                active_path.display()
            )
        })?;
        tracing::info!(name = %name, "policy approved and activated");
        Ok(())
    }

    /// Revoke an active policy by removing it from the active directory.
    pub fn revoke(&self, name: &str) -> Result<()> {
        let filename = format!("{}.yaml", name);
        let active_path = self.active_dir.join(&filename);

        if !active_path.exists() {
            bail!("active policy '{}' not found at {}", name, active_path.display());
        }

        fs::remove_file(&active_path)
            .with_context(|| format!("removing active policy {}", active_path.display()))?;
        tracing::info!(name = %name, "policy revoked");
        Ok(())
    }

    /// List names of all staged policies.
    pub fn list_staged(&self) -> Result<Vec<String>> {
        Self::list_yaml_files(&self.staging_dir)
    }

    /// List names of all active reactive policies.
    pub fn list_active(&self) -> Result<Vec<String>> {
        Self::list_yaml_files(&self.active_dir)
    }

    fn list_yaml_files(dir: &PathBuf) -> Result<Vec<String>> {
        let mut names = Vec::new();
        for entry in fs::read_dir(dir)
            .with_context(|| format!("reading directory {}", dir.display()))?
        {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("yaml") {
                if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                    names.push(stem.to_string());
                }
            }
        }
        names.sort();
        Ok(names)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use watchpost_types::{PolicyMetadata, PolicySource};

    fn make_policy(name: &str) -> TracingPolicySpec {
        TracingPolicySpec {
            metadata: PolicyMetadata {
                name: name.to_string(),
                description: format!("test policy {}", name),
                source: PolicySource::Reactive,
            },
            yaml_content: format!(
                "apiVersion: cilium.io/v1alpha1\nkind: TracingPolicy\nmetadata:\n  name: {}\nspec: {{}}\n",
                name
            ),
        }
    }

    #[test]
    fn test_stage_and_list() {
        let dir = tempdir().unwrap();
        let staging = dir.path().join("staging");
        let active = dir.path().join("active");
        let mgr = StagedPolicyManager::new(staging, active).unwrap();

        let policy = make_policy("test-block-network");
        mgr.stage(&policy).unwrap();

        let staged = mgr.list_staged().unwrap();
        assert_eq!(staged, vec!["test-block-network"]);

        let active = mgr.list_active().unwrap();
        assert!(active.is_empty());
    }

    #[test]
    fn test_approve_moves_to_active() {
        let dir = tempdir().unwrap();
        let staging = dir.path().join("staging");
        let active = dir.path().join("active");
        let mgr = StagedPolicyManager::new(staging, active).unwrap();

        let policy = make_policy("test-block-network");
        mgr.stage(&policy).unwrap();
        mgr.approve("test-block-network").unwrap();

        let staged = mgr.list_staged().unwrap();
        assert!(staged.is_empty());

        let active = mgr.list_active().unwrap();
        assert_eq!(active, vec!["test-block-network"]);
    }

    #[test]
    fn test_revoke_removes_active() {
        let dir = tempdir().unwrap();
        let staging = dir.path().join("staging");
        let active = dir.path().join("active");
        let mgr = StagedPolicyManager::new(staging, active).unwrap();

        let policy = make_policy("test-block-network");
        mgr.stage(&policy).unwrap();
        mgr.approve("test-block-network").unwrap();
        mgr.revoke("test-block-network").unwrap();

        let active = mgr.list_active().unwrap();
        assert!(active.is_empty());
    }
}
