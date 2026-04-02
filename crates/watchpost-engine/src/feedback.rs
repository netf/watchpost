use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use watchpost_types::ScoreIndicator;

/// Per-indicator override record tracking how often it was overridden.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndicatorOverride {
    pub override_count: u32,
    pub total_fires: u32,
    /// Multiplier applied to the indicator weight: 1.0 = default, 0.3 = minimum.
    pub weight_factor: f64,
}

/// Persistent weight overrides loaded from/saved to a TOML file.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WeightOverrides {
    /// Per-indicator overrides keyed by the serde snake_case name of the indicator.
    pub overrides: HashMap<String, IndicatorOverride>,
    /// Additive adjustment to the base suspicion threshold.
    pub autonomous_threshold_adjustment: f64,
}

impl WeightOverrides {
    /// Load overrides from a TOML file. Returns `Default` if the file does not
    /// exist or cannot be parsed.
    pub fn load(path: &Path) -> Self {
        match std::fs::read_to_string(path) {
            Ok(contents) => toml::from_str(&contents).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    /// Persist the overrides to a TOML file, creating parent directories as
    /// needed.
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let serialized = toml::to_string_pretty(self)?;
        std::fs::write(path, serialized)?;
        Ok(())
    }

    /// Record that the user overrode (clicked "Undo" for) a particular
    /// indicator. Increments the override count and recomputes the weight
    /// factor.
    pub fn record_override(&mut self, indicator: &ScoreIndicator) {
        let key = indicator_key(indicator).to_owned();
        let entry = self.overrides.entry(key).or_insert(IndicatorOverride {
            override_count: 0,
            total_fires: 0,
            weight_factor: 1.0,
        });
        entry.override_count += 1;
        // Ensure total_fires is at least as large as override_count.
        if entry.total_fires < entry.override_count {
            entry.total_fires = entry.override_count;
        }
        recompute_factor(entry);
    }

    /// Record that an indicator fired (regardless of whether the user
    /// overrode it). Used to compute the override ratio.
    pub fn record_fire(&mut self, indicator: &ScoreIndicator) {
        let key = indicator_key(indicator).to_owned();
        let entry = self.overrides.entry(key).or_insert(IndicatorOverride {
            override_count: 0,
            total_fires: 0,
            weight_factor: 1.0,
        });
        entry.total_fires += 1;
        recompute_factor(entry);
    }

    /// Return the current weight multiplier for an indicator. Returns `1.0`
    /// (no adjustment) if the indicator has never been overridden.
    pub fn get_weight_factor(&self, indicator: &ScoreIndicator) -> f64 {
        let key = indicator_key(indicator);
        self.overrides
            .get(key)
            .map(|o| o.weight_factor)
            .unwrap_or(1.0)
    }

    /// Recompute weight factors for all tracked indicators.
    pub fn recompute_weights(&mut self) {
        for entry in self.overrides.values_mut() {
            recompute_factor(entry);
        }
    }
}

/// Map a `ScoreIndicator` to a stable string key for persistence.
fn indicator_key(indicator: &ScoreIndicator) -> &'static str {
    match indicator {
        ScoreIndicator::NonRegistryNetwork => "non_registry_network",
        ScoreIndicator::MaliciousIp => "malicious_ip",
        ScoreIndicator::SensitiveFileRead => "sensitive_file_read",
        ScoreIndicator::SensitiveFileWrite => "sensitive_file_write",
        ScoreIndicator::TempDirExec => "temp_dir_exec",
        ScoreIndicator::ShellFromPackageManager => "shell_from_package_manager",
        ScoreIndicator::LdPreload => "ld_preload",
        ScoreIndicator::PrivilegeChange => "privilege_change",
        ScoreIndicator::HighEntropyDns => "high_entropy_dns",
        ScoreIndicator::ReverseShellPattern => "reverse_shell_pattern",
        ScoreIndicator::ObfuscatedContent => "obfuscated_content",
        ScoreIndicator::AntiForensics => "anti_forensics",
        ScoreIndicator::NewPackageLowDownloads => "new_package_low_downloads",
        ScoreIndicator::KnownVulnerability => "known_vulnerability",
        ScoreIndicator::Typosquatting => "typosquatting",
        ScoreIndicator::ProvenanceAttested => "provenance_attested",
        ScoreIndicator::EstablishedPackage => "established_package",
        ScoreIndicator::NoGithubRelease => "no_github_release",
    }
}

/// Recompute the weight factor for a single indicator record.
///
/// Formula: `weight_factor = 1.0 - (override_count / max(total_fires, 1))`,
/// clamped so that the ratio never exceeds 0.7, meaning the minimum factor is
/// 0.3.
fn recompute_factor(entry: &mut IndicatorOverride) {
    let ratio = entry.override_count as f64 / entry.total_fires.max(1) as f64;
    entry.weight_factor = 1.0 - ratio.min(0.7);
    // Clamp to [0.3, 1.0] for safety.
    entry.weight_factor = entry.weight_factor.clamp(0.3, 1.0);
}

// ---------------------------------------------------------------------------
// FeedbackCollector
// ---------------------------------------------------------------------------

/// Collects user feedback (undo actions) and manages persistent weight
/// overrides. Thread-safe via an internal `Mutex`.
pub struct FeedbackCollector {
    overrides: Mutex<WeightOverrides>,
    overrides_path: String,
    /// Number of override recordings since the last save to disk.
    override_count_since_save: Mutex<u32>,
    /// Save to disk every N override recordings.
    save_threshold: u32,
}

impl FeedbackCollector {
    /// Create a new collector, loading any existing overrides from disk.
    pub fn new(overrides_path: &str) -> Self {
        let overrides = WeightOverrides::load(Path::new(overrides_path));
        Self {
            overrides: Mutex::new(overrides),
            overrides_path: overrides_path.to_owned(),
            override_count_since_save: Mutex::new(0),
            save_threshold: 50,
        }
    }

    /// Record that the user overrode these indicators (e.g. clicked "Undo").
    /// Increments counts, recomputes weight factors, and persists if the save
    /// threshold is reached.
    pub fn record_override(&self, indicators: &[ScoreIndicator]) {
        {
            let mut overrides = self.overrides.lock().unwrap();
            for indicator in indicators {
                overrides.record_override(indicator);
            }
        }

        let mut count = self.override_count_since_save.lock().unwrap();
        *count += indicators.len() as u32;
        if *count >= self.save_threshold {
            *count = 0;
            let overrides = self.overrides.lock().unwrap();
            if let Err(e) = overrides.save(Path::new(&self.overrides_path)) {
                tracing::warn!("failed to save weight overrides: {e:#}");
            }
        }
    }

    /// Record that these indicators fired (even if the user did not override
    /// them). Keeps the total-fires denominator accurate for the override
    /// ratio.
    pub fn record_fire(&self, indicators: &[ScoreIndicator]) {
        let mut overrides = self.overrides.lock().unwrap();
        for indicator in indicators {
            overrides.record_fire(indicator);
        }
    }

    /// Return the current weight multiplier for an indicator.
    pub fn get_weight_factor(&self, indicator: &ScoreIndicator) -> f64 {
        let overrides = self.overrides.lock().unwrap();
        overrides.get_weight_factor(indicator)
    }

    /// Return a threshold adjustment value based on recent override
    /// frequency.
    ///
    /// * If > 3 overrides recorded: `+0.05` (more conservative, fewer blocks)
    /// * If 0 overrides recorded: `-0.05` (less conservative)
    /// * Otherwise: `0.0`
    ///
    /// Note: this simplified version counts total overrides rather than
    /// filtering by time window, since individual override timestamps are not
    /// stored. A future iteration could add per-override timestamps.
    pub fn adjust_threshold(&self) -> f64 {
        let overrides = self.overrides.lock().unwrap();
        let total_overrides: u32 = overrides
            .overrides
            .values()
            .map(|o| o.override_count)
            .sum();

        if total_overrides > 3 {
            0.05
        } else if total_overrides == 0 {
            -0.05
        } else {
            0.0
        }
    }

    /// Force a save of the current overrides to disk.
    pub fn save(&self) -> Result<()> {
        let overrides = self.overrides.lock().unwrap();
        overrides.save(Path::new(&self.overrides_path))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_weight_factor_default() {
        let overrides = WeightOverrides::default();
        // No overrides recorded -- every indicator should return 1.0.
        let factor = overrides.get_weight_factor(&ScoreIndicator::MaliciousIp);
        assert!(
            (factor - 1.0).abs() < f64::EPSILON,
            "expected 1.0, got {factor}"
        );
    }

    #[test]
    fn test_weight_factor_after_overrides() {
        let mut overrides = WeightOverrides::default();

        // Simulate 10 fires and 3 overrides for NonRegistryNetwork.
        for _ in 0..10 {
            overrides.record_fire(&ScoreIndicator::NonRegistryNetwork);
        }
        for _ in 0..3 {
            overrides.record_override(&ScoreIndicator::NonRegistryNetwork);
        }

        let factor = overrides.get_weight_factor(&ScoreIndicator::NonRegistryNetwork);
        // ratio = 3/13 ≈ 0.2308 (total_fires = 10 fires + 3 from overrides that
        // ensure total_fires >= override_count). Actually, record_override only
        // bumps total_fires if it's less than override_count.
        // So total_fires = 10, override_count = 3, ratio = 3/10 = 0.3
        // weight_factor = 1.0 - 0.3 = 0.7
        assert!(
            factor < 1.0,
            "expected factor < 1.0 after overrides, got {factor}"
        );
        assert!(
            factor >= 0.3,
            "factor should not go below 0.3, got {factor}"
        );
    }

    #[test]
    fn test_weight_factor_heavily_overridden() {
        let mut overrides = WeightOverrides::default();

        // 10 fires, then 8 overrides.
        for _ in 0..10 {
            overrides.record_fire(&ScoreIndicator::TempDirExec);
        }
        for _ in 0..8 {
            overrides.record_override(&ScoreIndicator::TempDirExec);
        }

        let factor = overrides.get_weight_factor(&ScoreIndicator::TempDirExec);
        // total_fires = 10, override_count = 8, ratio = 8/10 = 0.8 -> capped at 0.7
        // weight_factor = 1.0 - 0.7 = 0.3
        assert!(
            (factor - 0.3).abs() < f64::EPSILON,
            "expected 0.3 for heavily overridden indicator, got {factor}"
        );
    }

    #[test]
    fn test_save_and_load() {
        let mut overrides = WeightOverrides::default();
        for _ in 0..5 {
            overrides.record_fire(&ScoreIndicator::HighEntropyDns);
        }
        for _ in 0..2 {
            overrides.record_override(&ScoreIndicator::HighEntropyDns);
        }

        let tmpfile = NamedTempFile::new().expect("failed to create tempfile");
        overrides
            .save(tmpfile.path())
            .expect("failed to save overrides");

        let loaded = WeightOverrides::load(tmpfile.path());
        let original_factor = overrides.get_weight_factor(&ScoreIndicator::HighEntropyDns);
        let loaded_factor = loaded.get_weight_factor(&ScoreIndicator::HighEntropyDns);

        assert!(
            (original_factor - loaded_factor).abs() < f64::EPSILON,
            "round-trip failed: original={original_factor}, loaded={loaded_factor}"
        );
    }

    #[test]
    fn test_threshold_adjustment_no_overrides() {
        let collector = FeedbackCollector {
            overrides: Mutex::new(WeightOverrides::default()),
            overrides_path: "/dev/null".to_owned(),
            override_count_since_save: Mutex::new(0),
            save_threshold: 50,
        };

        let adjustment = collector.adjust_threshold();
        assert!(
            (adjustment - (-0.05)).abs() < f64::EPSILON,
            "expected -0.05 with no overrides, got {adjustment}"
        );
    }
}
