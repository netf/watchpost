use serde::{Deserialize, Serialize};
use std::fmt;

/// Creates a newtype wrapper around f64 that clamps to [0.0, 1.0].
macro_rules! clamped_unit_f64 {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, PartialOrd)]
        pub struct $name(f64);

        impl $name {
            pub fn new(val: f64) -> Self {
                Self(val.clamp(0.0, 1.0))
            }

            pub fn value(&self) -> f64 {
                self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{:.2}", self.0)
            }
        }
    };
}

clamped_unit_f64!(
    /// A suspicion score clamped to [0.0, 1.0].
    SuspicionScore
);
clamped_unit_f64!(
    /// A confidence value clamped to [0.0, 1.0].
    Confidence
);

/// Named indicators that contribute to a suspicion score.
#[derive(Debug, Clone, Hash, Serialize, Deserialize, PartialEq, Eq)]
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
    // Phase 2: package provenance indicators
    /// Package age < 7 days with < 100 downloads (+0.3)
    NewPackageLowDownloads,
    /// Package has known vulnerability per audit (+0.4)
    KnownVulnerability,
    /// Package name is Levenshtein distance <= 2 from a top package (+0.5)
    Typosquatting,
    /// Package has Sigstore/npm provenance attestation (-0.2, trust bonus)
    ProvenanceAttested,
    /// Package has > 10M weekly downloads and > 5 years history (-0.3, trust bonus)
    EstablishedPackage,
    /// Package version has no corresponding GitHub tag/release (+0.4)
    NoGithubRelease,
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

    #[test]
    fn confidence_clamps_high() {
        let c = Confidence::new(1.5);
        assert!((c.value() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn confidence_clamps_low() {
        let c = Confidence::new(-0.1);
        assert!((c.value() - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn confidence_preserves_valid() {
        let c = Confidence::new(0.75);
        assert!((c.value() - 0.75).abs() < f64::EPSILON);
    }

    #[test]
    fn clamped_types_support_comparison() {
        assert!(SuspicionScore::new(0.7) > SuspicionScore::new(0.3));
        assert!(Confidence::new(0.9) > Confidence::new(0.1));
    }
}
