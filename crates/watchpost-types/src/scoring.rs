use serde::{Deserialize, Serialize};
use std::fmt;

/// A suspicion score clamped to [0.0, 1.0].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuspicionScore(f64);

impl SuspicionScore {
    pub fn new(val: f64) -> Self {
        Self(val.clamp(0.0, 1.0))
    }

    pub fn value(&self) -> f64 {
        self.0
    }
}

impl fmt::Display for SuspicionScore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:.2}", self.0)
    }
}

/// Named indicators that contribute to a suspicion score.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ScoreIndicator {
    NonRegistryNetwork,
    MaliciousIp,
    SensitiveFileRead,
    SensitiveFileWrite,
    TempDirExec,
    ShellFromPackageManager,
    LdPreload,
    PrivilegeChange,
    HighEntropyDns,
    ReverseShellPattern,
    ObfuscatedContent,
    AntiForensics,
}

/// A detailed breakdown of how a suspicion score was computed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoreBreakdown {
    pub indicators: Vec<(ScoreIndicator, f64)>,
    pub context_modifier: f64,
    pub raw_score: f64,
    pub final_score: SuspicionScore,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suspicion_score_clamps_high() {
        let score = SuspicionScore::new(1.5);
        assert!((score.value() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn suspicion_score_clamps_low() {
        let score = SuspicionScore::new(-0.1);
        assert!((score.value() - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn suspicion_score_preserves_valid() {
        let score = SuspicionScore::new(0.5);
        assert!((score.value() - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn suspicion_score_display() {
        let score = SuspicionScore::new(0.756);
        assert_eq!(format!("{score}"), "0.76");
    }
}
