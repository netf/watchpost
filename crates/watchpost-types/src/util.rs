//! Shared utility functions and constants used across multiple crates.

/// Extract the filename (last path component) from a binary path.
///
/// e.g. "/usr/bin/npm" → "npm", "npm" → "npm"
pub fn binary_basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// Shannon entropy of a byte string, in bits per byte.
///
/// Values above ~4.0 indicate high randomness (potential DNS exfiltration,
/// encoded payloads, etc.)
pub fn shannon_entropy(s: &str) -> f64 {
    let len = s.len() as f64;
    if len == 0.0 {
        return 0.0;
    }
    let mut freq = [0u32; 256];
    for b in s.bytes() {
        freq[b as usize] += 1;
    }
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// Common shell binary basenames.
pub const SHELLS: &[&str] = &["sh", "bash", "dash", "zsh", "fish"];

/// Known package registry hostnames, per ecosystem.
pub const NPM_REGISTRIES: &[&str] = &[
    "registry.npmjs.org",
    "github.com",
    "objects.githubusercontent.com",
];
pub const PIP_REGISTRIES: &[&str] = &["pypi.org", "files.pythonhosted.org"];
pub const CARGO_REGISTRIES: &[&str] = &["crates.io", "static.crates.io", "github.com"];

/// Union of all known registry hostnames.
pub const ALL_KNOWN_REGISTRIES: &[&str] = &[
    "registry.npmjs.org",
    "github.com",
    "objects.githubusercontent.com",
    "pypi.org",
    "files.pythonhosted.org",
    "crates.io",
    "static.crates.io",
];

/// Sensitive file path fragments.
pub const SENSITIVE_PATHS: &[&str] = &[".ssh/", ".gnupg/", ".aws/", ".config/gcloud/", ".config/gh/"];

/// Temporary directories used for staging payloads.
pub const TEMP_DIRS: &[&str] = &["/tmp/", "/dev/shm/", "/var/tmp/"];

/// Ports associated with common C2 frameworks and reverse shells.
pub const C2_PORTS: &[u16] = &[4444, 5555, 1337, 9001];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basename_extracts_filename() {
        assert_eq!(binary_basename("/usr/bin/npm"), "npm");
        assert_eq!(binary_basename("npm"), "npm");
        assert_eq!(binary_basename("/a/b/c/cargo"), "cargo");
    }

    #[test]
    fn entropy_low_for_uniform() {
        assert!(shannon_entropy("aaaaaa") < 1.0);
    }

    #[test]
    fn entropy_high_for_random() {
        assert!(shannon_entropy("x7k9mz3qw2") > 3.0);
    }

    #[test]
    fn entropy_zero_for_empty() {
        assert_eq!(shannon_entropy(""), 0.0);
    }
}
