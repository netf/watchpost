use serde::{Deserialize, Serialize};

use crate::context::Ecosystem;

/// Supply-chain provenance information for a package, obtained via registry
/// API lookups and local heuristics (typosquatting detection).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvenanceInfo {
    /// The package name as it appears in the registry.
    pub package_name: String,
    /// The ecosystem this package belongs to.
    pub ecosystem: Ecosystem,
    /// Age of the package in days since first publish, if known.
    pub age_days: Option<u64>,
    /// Weekly download count, if known.
    pub weekly_downloads: Option<u64>,
    /// Whether the package has known vulnerabilities per audit databases.
    pub has_known_vulnerabilities: bool,
    /// Levenshtein distance to the nearest top package (typosquatting signal).
    pub typosquatting_distance: Option<u32>,
    /// Which top package this name is similar to, if any.
    pub typosquatting_target: Option<String>,
    /// Whether the package has a Sigstore signature or npm provenance attestation.
    pub has_provenance_attestation: bool,
    /// Whether the package version has a corresponding GitHub tag/release.
    pub has_github_release: bool,
}
