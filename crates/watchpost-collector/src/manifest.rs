use std::fs;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use lru::LruCache;
use tracing::debug;
use watchpost_types::context::Ecosystem;

/// Parsed metadata from a package manifest file.
#[derive(Debug, Clone, PartialEq)]
pub struct ManifestInfo {
    pub package_name: String,
    pub version: String,
    pub has_install_scripts: bool,
}

/// An LRU cache for parsed package manifests, keyed by directory path.
pub struct PackageManifestCache {
    cache: Mutex<LruCache<PathBuf, ManifestInfo>>,
}

impl PackageManifestCache {
    /// Create a new cache with the given capacity.
    pub fn new(capacity: usize) -> Self {
        let cap = NonZeroUsize::new(capacity).unwrap_or(NonZeroUsize::new(1).unwrap());
        Self {
            cache: Mutex::new(LruCache::new(cap)),
        }
    }

    /// Look up a manifest for the given directory and ecosystem.
    ///
    /// Returns a cached result if available; otherwise reads and parses the
    /// manifest file on disk. Returns `None` if the manifest file doesn't
    /// exist or cannot be parsed.
    pub fn get_or_read(&self, dir: &Path, ecosystem: &Ecosystem) -> Option<ManifestInfo> {
        let key = dir.to_path_buf();

        // Check cache first.
        {
            let mut cache = self.cache.lock().ok()?;
            if let Some(info) = cache.get(&key) {
                return Some(info.clone());
            }
        }

        // Cache miss — read from disk.
        let info = match ecosystem {
            Ecosystem::Npm => read_npm_manifest(dir),
            Ecosystem::Cargo => read_cargo_manifest(dir),
            Ecosystem::Pip => read_pip_manifest(dir),
        };

        if let Some(ref info) = info {
            if let Ok(mut cache) = self.cache.lock() {
                cache.put(key, info.clone());
            }
        }

        info
    }

    /// Remove a cached entry for the given directory.
    pub fn invalidate(&self, dir: &Path) {
        if let Ok(mut cache) = self.cache.lock() {
            cache.pop(&dir.to_path_buf());
        }
    }
}

/// Read and parse `package.json` from the given directory.
fn read_npm_manifest(dir: &Path) -> Option<ManifestInfo> {
    let path = dir.join("package.json");
    let content = fs::read_to_string(&path).ok()?;
    let value: serde_json::Value = serde_json::from_str(&content).ok()?;

    let obj = value.as_object()?;
    let package_name = obj
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let version = obj
        .get("version")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    // Check for install lifecycle scripts.
    let has_install_scripts = if let Some(scripts) = obj.get("scripts").and_then(|v| v.as_object())
    {
        scripts.contains_key("preinstall")
            || scripts.contains_key("install")
            || scripts.contains_key("postinstall")
    } else {
        false
    };

    debug!(path = %path.display(), name = %package_name, "parsed package.json");

    Some(ManifestInfo {
        package_name,
        version,
        has_install_scripts,
    })
}

/// Read and parse `Cargo.toml` from the given directory.
fn read_cargo_manifest(dir: &Path) -> Option<ManifestInfo> {
    let path = dir.join("Cargo.toml");
    let content = fs::read_to_string(&path).ok()?;
    let table: toml::Value = content.parse().ok()?;

    let package = table.get("package")?.as_table()?;
    let package_name = package
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let version = package
        .get("version")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    debug!(path = %path.display(), name = %package_name, "parsed Cargo.toml");

    Some(ManifestInfo {
        package_name,
        version,
        has_install_scripts: false,
    })
}

/// Read and parse `pyproject.toml` or `setup.py` from the given directory.
fn read_pip_manifest(dir: &Path) -> Option<ManifestInfo> {
    // Try pyproject.toml first.
    let pyproject_path = dir.join("pyproject.toml");
    if let Ok(content) = fs::read_to_string(&pyproject_path) {
        if let Ok(table) = content.parse::<toml::Value>() {
            // PEP 621: [project] table
            if let Some(project) = table.get("project").and_then(|v| v.as_table()) {
                let name = project
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let version = project
                    .get("version")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();

                debug!(path = %pyproject_path.display(), name = %name, "parsed pyproject.toml");

                return Some(ManifestInfo {
                    package_name: name,
                    version,
                    has_install_scripts: false,
                });
            }

            // Poetry: [tool.poetry] table
            if let Some(poetry) = table
                .get("tool")
                .and_then(|v| v.get("poetry"))
                .and_then(|v| v.as_table())
            {
                let name = poetry
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let version = poetry
                    .get("version")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();

                debug!(path = %pyproject_path.display(), name = %name, "parsed pyproject.toml (poetry)");

                return Some(ManifestInfo {
                    package_name: name,
                    version,
                    has_install_scripts: false,
                });
            }
        }
    }

    // Fallback: best-effort parsing of setup.py
    let setup_path = dir.join("setup.py");
    if let Ok(content) = fs::read_to_string(&setup_path) {
        let name = extract_setup_py_name(&content).unwrap_or_default();

        debug!(path = %setup_path.display(), name = %name, "parsed setup.py");

        return Some(ManifestInfo {
            package_name: name,
            version: String::new(),
            has_install_scripts: false,
        });
    }

    None
}

/// Best-effort extraction of the package name from a setup.py file.
///
/// Looks for patterns like `name="mypackage"` or `name='mypackage'`.
fn extract_setup_py_name(content: &str) -> Option<String> {
    for line in content.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("name") {
            let rest = rest.trim();
            if let Some(rest) = rest.strip_prefix('=') {
                let rest = rest.trim().trim_matches(',');
                let rest = rest.trim();
                // Remove quotes.
                let name = rest.trim_matches('"').trim_matches('\'');
                if !name.is_empty() {
                    return Some(name.to_string());
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_npm_manifest_parsing() {
        let dir = tempdir().expect("create temp dir");
        let package_json = r#"{
            "name": "test-package",
            "version": "1.2.3",
            "scripts": {
                "postinstall": "node setup.js",
                "build": "tsc"
            }
        }"#;
        fs::write(dir.path().join("package.json"), package_json).unwrap();

        let cache = PackageManifestCache::new(16);
        let info = cache
            .get_or_read(dir.path(), &Ecosystem::Npm)
            .expect("should parse package.json");

        assert_eq!(info.package_name, "test-package");
        assert_eq!(info.version, "1.2.3");
        assert!(info.has_install_scripts);
    }

    #[test]
    fn test_npm_manifest_cache_hit() {
        let dir = tempdir().expect("create temp dir");
        let package_json = r#"{
            "name": "cached-pkg",
            "version": "0.1.0"
        }"#;
        fs::write(dir.path().join("package.json"), package_json).unwrap();

        let cache = PackageManifestCache::new(16);
        let first = cache
            .get_or_read(dir.path(), &Ecosystem::Npm)
            .expect("first read");
        let second = cache
            .get_or_read(dir.path(), &Ecosystem::Npm)
            .expect("second read (cache hit)");

        assert_eq!(first, second);
        assert_eq!(first.package_name, "cached-pkg");
    }

    #[test]
    fn test_nonexistent_dir_returns_none() {
        let cache = PackageManifestCache::new(16);
        let result = cache.get_or_read(Path::new("/nonexistent/path/12345"), &Ecosystem::Npm);
        assert!(result.is_none());
    }

    #[test]
    fn test_cargo_manifest_parsing() {
        let dir = tempdir().expect("create temp dir");
        let cargo_toml = r#"
[package]
name = "my-crate"
version = "0.5.0"
edition = "2021"
"#;
        fs::write(dir.path().join("Cargo.toml"), cargo_toml).unwrap();

        let cache = PackageManifestCache::new(16);
        let info = cache
            .get_or_read(dir.path(), &Ecosystem::Cargo)
            .expect("should parse Cargo.toml");

        assert_eq!(info.package_name, "my-crate");
        assert_eq!(info.version, "0.5.0");
        assert!(!info.has_install_scripts);
    }

    #[test]
    fn test_pip_pyproject_parsing() {
        let dir = tempdir().expect("create temp dir");
        let pyproject = r#"
[project]
name = "my-python-pkg"
version = "2.0.0"
"#;
        fs::write(dir.path().join("pyproject.toml"), pyproject).unwrap();

        let cache = PackageManifestCache::new(16);
        let info = cache
            .get_or_read(dir.path(), &Ecosystem::Pip)
            .expect("should parse pyproject.toml");

        assert_eq!(info.package_name, "my-python-pkg");
        assert_eq!(info.version, "2.0.0");
    }

    #[test]
    fn test_cache_invalidation() {
        let dir = tempdir().expect("create temp dir");
        let package_json = r#"{"name": "will-invalidate", "version": "1.0.0"}"#;
        fs::write(dir.path().join("package.json"), package_json).unwrap();

        let cache = PackageManifestCache::new(16);

        // Populate cache.
        let info = cache.get_or_read(dir.path(), &Ecosystem::Npm).unwrap();
        assert_eq!(info.package_name, "will-invalidate");

        // Invalidate.
        cache.invalidate(dir.path());

        // Update the file on disk.
        let updated = r#"{"name": "after-invalidation", "version": "2.0.0"}"#;
        fs::write(dir.path().join("package.json"), updated).unwrap();

        // Should re-read from disk.
        let info = cache.get_or_read(dir.path(), &Ecosystem::Npm).unwrap();
        assert_eq!(info.package_name, "after-invalidation");
    }

    #[test]
    fn test_npm_no_install_scripts() {
        let dir = tempdir().expect("create temp dir");
        let package_json = r#"{
            "name": "safe-package",
            "version": "1.0.0",
            "scripts": {
                "build": "tsc",
                "test": "jest"
            }
        }"#;
        fs::write(dir.path().join("package.json"), package_json).unwrap();

        let cache = PackageManifestCache::new(16);
        let info = cache
            .get_or_read(dir.path(), &Ecosystem::Npm)
            .unwrap();

        assert!(!info.has_install_scripts);
    }
}
