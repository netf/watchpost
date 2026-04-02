use std::num::NonZeroUsize;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use lru::LruCache;
use tracing::{debug, warn};
use watchpost_types::context::Ecosystem;
use watchpost_types::provenance::ProvenanceInfo;

// ---------------------------------------------------------------------------
// Top packages lists (hardcoded, representative set per ecosystem)
// ---------------------------------------------------------------------------

/// Hardcoded lists of the top ~50 most commonly typosquatted packages per
/// ecosystem.  These are used for Levenshtein-distance typosquatting checks.
pub struct TopPackages {
    pub npm: Vec<String>,
    pub pip: Vec<String>,
    pub cargo: Vec<String>,
}

impl TopPackages {
    pub fn default_lists() -> Self {
        Self {
            npm: vec![
                "express", "react", "lodash", "axios", "webpack", "typescript",
                "moment", "commander", "chalk", "request", "debug", "fs-extra",
                "uuid", "dotenv", "yargs", "glob", "minimist", "mkdirp",
                "rimraf", "semver", "body-parser", "cors", "cross-env", "jest",
                "mocha", "eslint", "prettier", "next", "vue", "angular",
                "jquery", "underscore", "async", "bluebird", "got",
                "superagent", "inquirer", "ora", "execa", "sharp", "esbuild",
                "node-fetch", "node-sass", "husky", "lerna", "turbo", "nx",
                "prisma", "sequelize", "mongoose",
            ]
            .into_iter()
            .map(String::from)
            .collect(),

            pip: vec![
                "requests", "flask", "django", "numpy", "pandas", "scipy",
                "boto3", "click", "pytest", "setuptools", "pip", "wheel",
                "six", "urllib3", "certifi", "charset-normalizer", "idna",
                "cryptography", "pyyaml", "pillow", "jinja2", "sqlalchemy",
                "aiohttp", "fastapi", "uvicorn", "pydantic", "black", "mypy",
                "ruff", "poetry", "tox", "sphinx", "gunicorn", "celery",
                "redis", "psycopg2", "httpx", "rich", "typer",
                "beautifulsoup4", "lxml", "paramiko", "fabric", "ansible",
                "scrapy", "tensorflow", "torch", "scikit-learn",
                "transformers", "openai",
            ]
            .into_iter()
            .map(String::from)
            .collect(),

            cargo: vec![
                "serde", "tokio", "clap", "reqwest", "anyhow", "thiserror",
                "tracing", "uuid", "chrono", "rand", "regex", "lazy_static",
                "log", "env_logger", "futures", "bytes", "http", "tower",
                "hyper", "axum", "actix-web", "diesel", "sqlx", "rusqlite",
                "dashmap", "crossbeam", "parking_lot", "rayon", "itertools",
                "num", "bitflags", "once_cell", "tempfile", "walkdir", "glob",
                "toml", "serde_json", "serde_yaml", "prost", "tonic",
            ]
            .into_iter()
            .map(String::from)
            .collect(),
        }
    }

    /// Return the top-package list for the given ecosystem.
    pub fn list_for(&self, ecosystem: &Ecosystem) -> &[String] {
        match ecosystem {
            Ecosystem::Npm => &self.npm,
            Ecosystem::Pip => &self.pip,
            Ecosystem::Cargo => &self.cargo,
        }
    }
}

// ---------------------------------------------------------------------------
// Typosquatting detection
// ---------------------------------------------------------------------------

/// Check if `name` is within Levenshtein distance <= `threshold` of any top
/// package in the given list.  Returns `(distance, target)` for the closest
/// match, or `None` if no match is close enough or the name is an exact match
/// (distance == 0 is not flagged).
pub fn typosquatting_check(
    name: &str,
    top_packages: &[String],
    threshold: usize,
) -> Option<(u32, String)> {
    let mut best: Option<(usize, &str)> = None;

    for top in top_packages {
        let dist = strsim::levenshtein(name, top);
        // Exact match (dist == 0) is not flagged as typosquatting.
        if dist == 0 {
            return None;
        }
        if dist <= threshold {
            if best.is_none() || dist < best.unwrap().0 {
                best = Some((dist, top.as_str()));
            }
        }
    }

    best.map(|(d, t)| (d as u32, t.to_string()))
}

// ---------------------------------------------------------------------------
// ProvenanceCache
// ---------------------------------------------------------------------------

struct CacheEntry {
    info: ProvenanceInfo,
    fetched_at: Instant,
}

/// An LRU cache for `ProvenanceInfo` keyed by (ecosystem, package_name).
pub struct ProvenanceCache {
    cache: Mutex<LruCache<(String, String), CacheEntry>>,
    ttl: Duration,
}

impl ProvenanceCache {
    pub fn new(capacity: usize, ttl: Duration) -> Self {
        let cap = NonZeroUsize::new(capacity).unwrap_or(NonZeroUsize::new(1).unwrap());
        Self {
            cache: Mutex::new(LruCache::new(cap)),
            ttl,
        }
    }

    /// Return a cached `ProvenanceInfo` if present and not expired.
    pub fn get(&self, ecosystem: &str, package: &str) -> Option<ProvenanceInfo> {
        let mut cache = self.cache.lock().ok()?;
        let key = (ecosystem.to_string(), package.to_string());
        if let Some(entry) = cache.get(&key) {
            if entry.fetched_at.elapsed() < self.ttl {
                return Some(entry.info.clone());
            }
            // Expired -- remove and return None.
            cache.pop(&key);
        }
        None
    }

    /// Insert a `ProvenanceInfo` into the cache.
    pub fn insert(&self, ecosystem: &str, package: &str, info: ProvenanceInfo) {
        if let Ok(mut cache) = self.cache.lock() {
            let key = (ecosystem.to_string(), package.to_string());
            cache.put(
                key,
                CacheEntry {
                    info,
                    fetched_at: Instant::now(),
                },
            );
        }
    }
}

// ---------------------------------------------------------------------------
// ProvenanceEnricher
// ---------------------------------------------------------------------------

/// Performs async registry lookups to enrich package-install events with
/// supply-chain provenance data: age, downloads, vulnerabilities,
/// typosquatting risk, and provenance attestations.
pub struct ProvenanceEnricher {
    http: reqwest::Client,
    cache: ProvenanceCache,
    top_packages: TopPackages,
}

impl ProvenanceEnricher {
    /// Create an enricher with default settings (1024-entry cache, 1-hour TTL).
    pub fn new() -> Self {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .user_agent("watchpost/0.1")
            .build()
            .unwrap_or_default();

        Self {
            http,
            cache: ProvenanceCache::new(1024, Duration::from_secs(3600)),
            top_packages: TopPackages::default_lists(),
        }
    }

    /// Look up provenance information for `package_name` in `ecosystem`.
    ///
    /// Returns cached data on cache hit.  On cache miss, performs a registry
    /// API call (currently only implemented for npm) and caches the result.
    ///
    /// For PyPI and crates.io, only the typosquatting check is performed
    /// (no HTTP call) as registry API integration is deferred to a later phase.
    pub async fn lookup(
        &self,
        ecosystem: &Ecosystem,
        package_name: &str,
    ) -> Option<ProvenanceInfo> {
        let eco_str = ecosystem_str(ecosystem);

        // Check cache first.
        if let Some(cached) = self.cache.get(eco_str, package_name) {
            debug!(ecosystem = eco_str, package = package_name, "provenance cache hit");
            return Some(cached);
        }

        debug!(ecosystem = eco_str, package = package_name, "provenance cache miss, fetching");

        let info = match ecosystem {
            Ecosystem::Npm => self.lookup_npm(package_name).await,
            Ecosystem::Pip | Ecosystem::Cargo => {
                // For non-npm ecosystems, only perform the typosquatting check.
                Some(self.basic_provenance(ecosystem, package_name))
            }
        };

        if let Some(ref info) = info {
            self.cache.insert(eco_str, package_name, info.clone());
        }

        info
    }

    /// npm registry lookup.  Fetches `https://registry.npmjs.org/{package}`.
    async fn lookup_npm(&self, package_name: &str) -> Option<ProvenanceInfo> {
        let url = format!("https://registry.npmjs.org/{}", package_name);

        let resp = match self.http.get(&url).send().await {
            Ok(r) => r,
            Err(e) => {
                warn!(package = package_name, error = %e, "npm registry request failed");
                // Fall back to typosquatting-only info.
                return Some(self.basic_provenance(&Ecosystem::Npm, package_name));
            }
        };

        if !resp.status().is_success() {
            warn!(
                package = package_name,
                status = %resp.status(),
                "npm registry returned non-success"
            );
            return Some(self.basic_provenance(&Ecosystem::Npm, package_name));
        }

        let json: serde_json::Value = match resp.json().await {
            Ok(v) => v,
            Err(e) => {
                warn!(package = package_name, error = %e, "failed to parse npm registry JSON");
                return Some(self.basic_provenance(&Ecosystem::Npm, package_name));
            }
        };

        // Extract creation time -> age_days.
        let age_days = json["time"]["created"]
            .as_str()
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            .map(|created| {
                let now = chrono::Utc::now();
                let duration = now.signed_duration_since(created);
                duration.num_days().max(0) as u64
            });

        // Weekly downloads: npm packument doesn't include download counts.
        // A separate endpoint (`https://api.npmjs.org/downloads/point/last-week/{pkg}`)
        // would be needed. For now, leave as None.
        let weekly_downloads: Option<u64> = None;

        // Check for provenance attestation.  npm packages with provenance have
        // `attestations` in the latest version metadata.
        let has_provenance_attestation = json["dist-tags"]["latest"]
            .as_str()
            .and_then(|ver| json["versions"][ver]["dist"]["attestations"].as_object())
            .is_some();

        // Typosquatting check.
        let typo = typosquatting_check(
            package_name,
            self.top_packages.list_for(&Ecosystem::Npm),
            2,
        );

        Some(ProvenanceInfo {
            package_name: package_name.to_string(),
            ecosystem: Ecosystem::Npm,
            age_days,
            weekly_downloads,
            has_known_vulnerabilities: false, // would need a vuln DB lookup
            typosquatting_distance: typo.as_ref().map(|(d, _)| *d),
            typosquatting_target: typo.map(|(_, t)| t),
            has_provenance_attestation,
            has_github_release: false, // would need a GitHub API lookup
        })
    }

    /// Build a basic `ProvenanceInfo` with only the typosquatting check (no
    /// HTTP calls).  Used for PyPI/crates.io and as a fallback on npm errors.
    fn basic_provenance(&self, ecosystem: &Ecosystem, package_name: &str) -> ProvenanceInfo {
        let typo = typosquatting_check(
            package_name,
            self.top_packages.list_for(ecosystem),
            2,
        );

        ProvenanceInfo {
            package_name: package_name.to_string(),
            ecosystem: ecosystem.clone(),
            age_days: None,
            weekly_downloads: None,
            has_known_vulnerabilities: false,
            typosquatting_distance: typo.as_ref().map(|(d, _)| *d),
            typosquatting_target: typo.map(|(_, t)| t),
            has_provenance_attestation: false,
            has_github_release: false,
        }
    }
}

impl Default for ProvenanceEnricher {
    fn default() -> Self {
        Self::new()
    }
}

/// Convert an `Ecosystem` to a string key for the cache.
fn ecosystem_str(eco: &Ecosystem) -> &'static str {
    match eco {
        Ecosystem::Npm => "npm",
        Ecosystem::Pip => "pip",
        Ecosystem::Cargo => "cargo",
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Cache tests ----

    #[test]
    fn cache_hit_returns_data() {
        let cache = ProvenanceCache::new(16, Duration::from_secs(3600));
        let info = ProvenanceInfo {
            package_name: "lodash".into(),
            ecosystem: Ecosystem::Npm,
            age_days: Some(3650),
            weekly_downloads: Some(50_000_000),
            has_known_vulnerabilities: false,
            typosquatting_distance: None,
            typosquatting_target: None,
            has_provenance_attestation: true,
            has_github_release: true,
        };

        cache.insert("npm", "lodash", info.clone());
        let result = cache.get("npm", "lodash");
        assert!(result.is_some());
        let cached = result.unwrap();
        assert_eq!(cached.package_name, "lodash");
        assert_eq!(cached.age_days, Some(3650));
        assert_eq!(cached.weekly_downloads, Some(50_000_000));
    }

    #[test]
    fn cache_miss_returns_none() {
        let cache = ProvenanceCache::new(16, Duration::from_secs(3600));
        let result = cache.get("npm", "nonexistent-package");
        assert!(result.is_none());
    }

    #[test]
    fn cache_ttl_expires_old_entries() {
        // Use a very short TTL so the entry expires immediately.
        let cache = ProvenanceCache::new(16, Duration::from_millis(1));
        let info = ProvenanceInfo {
            package_name: "expired-pkg".into(),
            ecosystem: Ecosystem::Npm,
            age_days: None,
            weekly_downloads: None,
            has_known_vulnerabilities: false,
            typosquatting_distance: None,
            typosquatting_target: None,
            has_provenance_attestation: false,
            has_github_release: false,
        };

        cache.insert("npm", "expired-pkg", info);
        // Sleep long enough for the TTL to expire.
        std::thread::sleep(Duration::from_millis(10));
        let result = cache.get("npm", "expired-pkg");
        assert!(result.is_none(), "expected expired entry to return None");
    }

    // ---- Typosquatting tests ----

    #[test]
    fn typosquatting_reacct_vs_react() {
        let top = TopPackages::default_lists();
        let result = typosquatting_check("reacct", &top.npm, 2);
        assert!(result.is_some(), "expected typosquatting match for 'reacct'");
        let (dist, target) = result.unwrap();
        assert_eq!(target, "react");
        assert_eq!(dist, 1);
    }

    #[test]
    fn typosquatting_exact_match_not_flagged() {
        let top = TopPackages::default_lists();
        let result = typosquatting_check("express", &top.npm, 2);
        assert!(
            result.is_none(),
            "exact match should not be flagged as typosquatting"
        );
    }

    #[test]
    fn typosquatting_no_close_match() {
        let top = TopPackages::default_lists();
        let result = typosquatting_check("totally-unique-pkg", &top.npm, 2);
        assert!(
            result.is_none(),
            "expected no close match for 'totally-unique-pkg'"
        );
    }
}
