use std::net::IpAddr;
use std::path::{Path, PathBuf};

use tracing::debug;

/// Well-known registry hostnames used for cross-referencing IP lookups.
const KNOWN_REGISTRY_IPS: &[(&str, &str)] = &[
    ("104.16.0.0/12", "registry.npmjs.org (Cloudflare)"),
    ("151.101.0.0/16", "pypi.org (Fastly)"),
    ("108.138.0.0/15", "crates.io (CloudFront)"),
];

/// Hardcoded known-bad IPs for demonstration (Phase 2 only).
const KNOWN_BAD_IPS: &[&str] = &[
    "185.220.101.1",  // TOR exit node (example)
    "45.33.32.156",   // scanme.nmap.org (example)
    "198.51.100.1",   // documentation range, used as test sentinel
];

/// Executes tools requested by the LLM during analysis.
///
/// In Phase 1, `read_project_file` performs real work while `get_process_tree`
/// and `get_recent_events` return placeholders.
///
/// Phase 2 adds `lookup_package` (async HTTP to registries) and `lookup_ip`
/// (local IP reputation checks).
pub struct ToolExecutor {
    /// Allowed base directories for file reads.
    allowed_prefixes: Vec<PathBuf>,
    /// HTTP client for registry lookups.
    http: reqwest::Client,
}

impl ToolExecutor {
    /// Create a new executor that allows reading files under the given prefixes.
    ///
    /// If no prefixes are supplied the default set is:
    /// `/home`, `/tmp`, `/var/cache`.
    pub fn new() -> Self {
        let http = reqwest::Client::builder()
            .user_agent("watchpost/0.1.0")
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .expect("failed to build HTTP client");

        Self {
            allowed_prefixes: vec![
                PathBuf::from("/home"),
                PathBuf::from("/tmp"),
                PathBuf::from("/var/cache"),
            ],
            http,
        }
    }

    /// Execute a tool by name, returning its output as a string.
    pub async fn execute(&self, tool_name: &str, input: &serde_json::Value) -> String {
        match tool_name {
            "read_project_file" => {
                let path = input
                    .get("path")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                self.read_project_file(path)
            }
            "get_process_tree" => {
                let pid = input
                    .get("pid")
                    .and_then(|v| v.as_i64())
                    .unwrap_or(0);
                self.get_process_tree(pid)
            }
            "get_recent_events" => {
                let pid = input
                    .get("pid")
                    .and_then(|v| v.as_i64())
                    .unwrap_or(0);
                let seconds = input
                    .get("seconds")
                    .and_then(|v| v.as_i64())
                    .unwrap_or(0);
                self.get_recent_events(pid, seconds)
            }
            "lookup_package" => {
                let ecosystem = input
                    .get("ecosystem")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let name = input
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let version = input
                    .get("version")
                    .and_then(|v| v.as_str());
                self.lookup_package(ecosystem, name, version).await
            }
            "lookup_ip" => {
                let ip = input
                    .get("ip")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                self.lookup_ip(ip)
            }
            other => format!("Unknown tool: {other}"),
        }
    }

    // -- Tool implementations -------------------------------------------------

    fn read_project_file(&self, path: &str) -> String {
        // Reject paths containing `..` to prevent directory traversal.
        if path.contains("..") {
            return format!("Error: path contains '..', which is not allowed: {path}");
        }

        let abs = Path::new(path);

        // Path must be absolute.
        if !abs.is_absolute() {
            return format!("Error: path must be absolute: {path}");
        }

        // Check that the path falls under one of the allowed prefixes.
        let allowed = self
            .allowed_prefixes
            .iter()
            .any(|prefix| abs.starts_with(prefix));

        if !allowed {
            return format!(
                "Error: path is outside allowed directories: {path}"
            );
        }

        match std::fs::read_to_string(abs) {
            Ok(contents) => contents,
            Err(e) => format!("Error reading file {path}: {e}"),
        }
    }

    fn get_process_tree(&self, pid: i64) -> String {
        format!(
            "Process tree query for PID {pid} \u{2014} not connected in standalone mode"
        )
    }

    fn get_recent_events(&self, pid: i64, seconds: i64) -> String {
        format!(
            "Recent events query for PID {pid} (last {seconds}s) \u{2014} not connected in standalone mode"
        )
    }

    /// Look up package metadata from the appropriate registry.
    async fn lookup_package(
        &self,
        ecosystem: &str,
        name: &str,
        version: Option<&str>,
    ) -> String {
        if name.is_empty() {
            return "Failed to look up package: missing package name".to_string();
        }

        match ecosystem {
            "npm" => self.lookup_npm(name, version).await,
            "pip" => self.lookup_pypi(name, version).await,
            "cargo" => self.lookup_crates_io(name, version).await,
            other => format!("Failed to look up package: unsupported ecosystem '{other}'"),
        }
    }

    /// Query the npm registry for package metadata.
    async fn lookup_npm(&self, name: &str, _version: Option<&str>) -> String {
        let url = format!("https://registry.npmjs.org/{name}");
        debug!(url = %url, "querying npm registry");

        let resp = match self.http.get(&url).send().await {
            Ok(r) => r,
            Err(e) => return format!("Failed to look up package: HTTP request failed: {e}"),
        };

        if !resp.status().is_success() {
            return format!(
                "Failed to look up package: npm returned HTTP {}",
                resp.status()
            );
        }

        let body: serde_json::Value = match resp.json().await {
            Ok(v) => v,
            Err(e) => return format!("Failed to look up package: failed to parse response: {e}"),
        };

        let description = body
            .get("description")
            .and_then(|v| v.as_str())
            .unwrap_or("(no description)");

        let latest_version = body
            .pointer("/dist-tags/latest")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        let created = body
            .pointer("/time/created")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        let maintainers_count = body
            .get("maintainers")
            .and_then(|v| v.as_array())
            .map(|a| a.len())
            .unwrap_or(0);

        format!(
            "Package: {name} (npm)\n\
             Description: {description}\n\
             Latest version: {latest_version}\n\
             Published: {created}\n\
             Maintainers: {maintainers_count}"
        )
    }

    /// Query PyPI for package metadata.
    async fn lookup_pypi(&self, name: &str, version: Option<&str>) -> String {
        let url = match version {
            Some(v) => format!("https://pypi.org/pypi/{name}/{v}/json"),
            None => format!("https://pypi.org/pypi/{name}/json"),
        };
        debug!(url = %url, "querying PyPI");

        let resp = match self.http.get(&url).send().await {
            Ok(r) => r,
            Err(e) => return format!("Failed to look up package: HTTP request failed: {e}"),
        };

        if !resp.status().is_success() {
            return format!(
                "Failed to look up package: PyPI returned HTTP {}",
                resp.status()
            );
        }

        let body: serde_json::Value = match resp.json().await {
            Ok(v) => v,
            Err(e) => return format!("Failed to look up package: failed to parse response: {e}"),
        };

        let summary = body
            .pointer("/info/summary")
            .and_then(|v| v.as_str())
            .unwrap_or("(no description)");

        let latest_version = body
            .pointer("/info/version")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        let author = body
            .pointer("/info/author")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        format!(
            "Package: {name} (pip)\n\
             Description: {summary}\n\
             Latest version: {latest_version}\n\
             Author: {author}"
        )
    }

    /// Query crates.io for package metadata.
    async fn lookup_crates_io(&self, name: &str, _version: Option<&str>) -> String {
        let url = format!("https://crates.io/api/v1/crates/{name}");
        debug!(url = %url, "querying crates.io");

        let resp = match self.http.get(&url).send().await {
            Ok(r) => r,
            Err(e) => return format!("Failed to look up package: HTTP request failed: {e}"),
        };

        if !resp.status().is_success() {
            return format!(
                "Failed to look up package: crates.io returned HTTP {}",
                resp.status()
            );
        }

        let body: serde_json::Value = match resp.json().await {
            Ok(v) => v,
            Err(e) => return format!("Failed to look up package: failed to parse response: {e}"),
        };

        let description = body
            .pointer("/crate/description")
            .and_then(|v| v.as_str())
            .unwrap_or("(no description)");

        let max_version = body
            .pointer("/crate/max_version")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        let downloads = body
            .pointer("/crate/downloads")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        format!(
            "Package: {name} (cargo)\n\
             Description: {description}\n\
             Latest version: {max_version}\n\
             Downloads: {downloads}"
        )
    }

    /// Perform local IP reputation checks.
    ///
    /// Phase 2: local-only analysis. Full AbuseIPDB/VirusTotal integration is
    /// deferred to Phase 3.
    fn lookup_ip(&self, ip_str: &str) -> String {
        if ip_str.is_empty() {
            return "Failed to look up IP: missing IP address".to_string();
        }

        let ip: IpAddr = match ip_str.parse() {
            Ok(addr) => addr,
            Err(e) => return format!("Failed to look up IP: invalid IP address '{ip_str}': {e}"),
        };

        let is_private = is_private_range(&ip);
        let is_loopback = ip.is_loopback();
        let known_registry = check_known_registry(&ip);
        let known_bad = is_known_bad(ip_str);

        let reputation = if known_bad {
            "bad (known malicious indicator)"
        } else if is_private {
            "suspicious (private IP in external connection context)"
        } else if is_loopback {
            "benign (loopback address)"
        } else {
            "unknown (no threat data available)"
        };

        format!(
            "IP: {ip_str}\n\
             Reputation: {reputation}\n\
             Known registry: {}\n\
             Private range: {}\n\
             Loopback: {}",
            known_registry
                .map(|name| format!("Yes ({name})"))
                .unwrap_or_else(|| "No".to_string()),
            if is_private { "Yes" } else { "No" },
            if is_loopback { "Yes" } else { "No" },
        )
    }
}

impl Default for ToolExecutor {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// IP analysis helpers
// ---------------------------------------------------------------------------

/// Check if an IP address falls within private (RFC 1918 / RFC 4193) ranges.
fn is_private_range(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            // 10.0.0.0/8
            if octets[0] == 10 {
                return true;
            }
            // 172.16.0.0/12
            if octets[0] == 172 && (16..=31).contains(&octets[1]) {
                return true;
            }
            // 192.168.0.0/16
            if octets[0] == 192 && octets[1] == 168 {
                return true;
            }
            false
        }
        IpAddr::V6(v6) => {
            let segments = v6.segments();
            // Check for ULA (fc00::/7)
            if (segments[0] & 0xfe00) == 0xfc00 {
                return true;
            }
            // Check IPv4-mapped IPv6 addresses (::ffff:x.x.x.x)
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_private_range(&IpAddr::V4(v4));
            }
            false
        }
    }
}

/// Check if an IP matches a known registry CIDR (simplified prefix check).
fn check_known_registry(ip: &IpAddr) -> Option<&'static str> {
    if let IpAddr::V4(v4) = ip {
        let octets = v4.octets();
        for (cidr, name) in KNOWN_REGISTRY_IPS {
            if let Some(prefix) = cidr.split('/').next() {
                if let Ok(net_ip) = prefix.parse::<std::net::Ipv4Addr>() {
                    let net_octets = net_ip.octets();
                    // Simple prefix match based on the CIDR notation
                    // /12 -> match first 12 bits (first octet + upper 4 bits of second)
                    // /16 -> match first two octets
                    // /15 -> match first 15 bits
                    let mask_len: u32 = cidr
                        .split('/')
                        .nth(1)
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(32);

                    let ip_bits = u32::from_be_bytes(octets);
                    let net_bits = u32::from_be_bytes(net_octets);
                    let mask = if mask_len == 0 {
                        0
                    } else {
                        !0u32 << (32 - mask_len)
                    };

                    if (ip_bits & mask) == (net_bits & mask) {
                        return Some(name);
                    }
                }
            }
        }
    }
    None
}

/// Check if the IP is in the known-bad list.
fn is_known_bad(ip_str: &str) -> bool {
    KNOWN_BAD_IPS.contains(&ip_str)
}

// ---------------------------------------------------------------------------
// Public helpers for building URLs (exposed for testing)
// ---------------------------------------------------------------------------

/// Build the registry URL for a given ecosystem and package name.
pub fn registry_url(ecosystem: &str, name: &str, version: Option<&str>) -> Option<String> {
    match ecosystem {
        "npm" => Some(format!("https://registry.npmjs.org/{name}")),
        "pip" => match version {
            Some(v) => Some(format!("https://pypi.org/pypi/{name}/{v}/json")),
            None => Some(format!("https://pypi.org/pypi/{name}/json")),
        },
        "cargo" => Some(format!("https://crates.io/api/v1/crates/{name}")),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::io::Write;
    use tempfile::NamedTempFile;

    // -- read_project_file tests (unchanged) ----------------------------------

    #[tokio::test]
    async fn read_project_file_valid() {
        let mut tmp = NamedTempFile::new_in("/tmp").expect("create temp file");
        write!(tmp, "hello world").expect("write temp file");
        let path = tmp.path().to_str().unwrap().to_string();

        let executor = ToolExecutor::new();
        let result = executor
            .execute("read_project_file", &json!({ "path": path }))
            .await;
        assert_eq!(result, "hello world");
    }

    #[tokio::test]
    async fn read_project_file_rejects_dotdot() {
        let executor = ToolExecutor::new();
        let result = executor
            .execute(
                "read_project_file",
                &json!({ "path": "/home/user/../etc/shadow" }),
            )
            .await;
        assert!(
            result.contains("not allowed"),
            "should reject path with '..' -- got: {result}"
        );
    }

    #[tokio::test]
    async fn read_project_file_rejects_outside_prefix() {
        let executor = ToolExecutor::new();
        let result = executor
            .execute(
                "read_project_file",
                &json!({ "path": "/etc/shadow" }),
            )
            .await;
        assert!(
            result.contains("outside allowed"),
            "should reject path outside allowed dirs -- got: {result}"
        );
    }

    #[tokio::test]
    async fn read_project_file_rejects_relative_path() {
        let executor = ToolExecutor::new();
        let result = executor
            .execute(
                "read_project_file",
                &json!({ "path": "relative/path.txt" }),
            )
            .await;
        assert!(
            result.contains("must be absolute"),
            "should reject relative path -- got: {result}"
        );
    }

    #[tokio::test]
    async fn unknown_tool_returns_error() {
        let executor = ToolExecutor::new();
        let result = executor
            .execute("nonexistent_tool", &json!({}))
            .await;
        assert_eq!(result, "Unknown tool: nonexistent_tool");
    }

    #[tokio::test]
    async fn get_process_tree_placeholder() {
        let executor = ToolExecutor::new();
        let result = executor
            .execute("get_process_tree", &json!({ "pid": 1234 }))
            .await;
        assert!(result.contains("1234"));
        assert!(result.contains("not connected"));
    }

    #[tokio::test]
    async fn get_recent_events_placeholder() {
        let executor = ToolExecutor::new();
        let result = executor
            .execute(
                "get_recent_events",
                &json!({ "pid": 5678, "seconds": 30 }),
            )
            .await;
        assert!(result.contains("5678"));
        assert!(result.contains("30s"));
        assert!(result.contains("not connected"));
    }

    // -- lookup_package tests -------------------------------------------------

    #[tokio::test]
    async fn lookup_package_unknown_ecosystem() {
        let executor = ToolExecutor::new();
        let result = executor
            .execute(
                "lookup_package",
                &json!({ "ecosystem": "rubygems", "name": "rails" }),
            )
            .await;
        assert!(
            result.contains("unsupported ecosystem"),
            "should return error for unsupported ecosystem -- got: {result}"
        );
    }

    #[tokio::test]
    async fn lookup_package_missing_name() {
        let executor = ToolExecutor::new();
        let result = executor
            .execute("lookup_package", &json!({ "ecosystem": "npm" }))
            .await;
        assert!(
            result.contains("missing package name"),
            "should return error for missing name -- got: {result}"
        );
    }

    #[test]
    fn registry_url_npm() {
        let url = registry_url("npm", "express", None);
        assert_eq!(url, Some("https://registry.npmjs.org/express".to_string()));
    }

    #[test]
    fn registry_url_pypi() {
        let url = registry_url("pip", "requests", None);
        assert_eq!(
            url,
            Some("https://pypi.org/pypi/requests/json".to_string())
        );
    }

    #[test]
    fn registry_url_pypi_with_version() {
        let url = registry_url("pip", "requests", Some("2.31.0"));
        assert_eq!(
            url,
            Some("https://pypi.org/pypi/requests/2.31.0/json".to_string())
        );
    }

    #[test]
    fn registry_url_cargo() {
        let url = registry_url("cargo", "serde", None);
        assert_eq!(
            url,
            Some("https://crates.io/api/v1/crates/serde".to_string())
        );
    }

    #[test]
    fn registry_url_unsupported() {
        let url = registry_url("rubygems", "rails", None);
        assert_eq!(url, None);
    }

    // -- lookup_ip tests ------------------------------------------------------

    #[tokio::test]
    async fn lookup_ip_private_10() {
        let executor = ToolExecutor::new();
        let result = executor
            .execute("lookup_ip", &json!({ "ip": "10.0.0.1" }))
            .await;
        assert!(
            result.contains("Private range: Yes"),
            "should flag 10.x as private -- got: {result}"
        );
        assert!(
            result.contains("suspicious"),
            "private IP should be suspicious -- got: {result}"
        );
    }

    #[tokio::test]
    async fn lookup_ip_private_172() {
        let executor = ToolExecutor::new();
        let result = executor
            .execute("lookup_ip", &json!({ "ip": "172.16.5.1" }))
            .await;
        assert!(
            result.contains("Private range: Yes"),
            "should flag 172.16.x as private -- got: {result}"
        );
    }

    #[tokio::test]
    async fn lookup_ip_private_192() {
        let executor = ToolExecutor::new();
        let result = executor
            .execute("lookup_ip", &json!({ "ip": "192.168.1.1" }))
            .await;
        assert!(
            result.contains("Private range: Yes"),
            "should flag 192.168.x as private -- got: {result}"
        );
    }

    #[tokio::test]
    async fn lookup_ip_public_unknown() {
        let executor = ToolExecutor::new();
        let result = executor
            .execute("lookup_ip", &json!({ "ip": "8.8.8.8" }))
            .await;
        assert!(
            result.contains("IP: 8.8.8.8"),
            "should show the IP -- got: {result}"
        );
        assert!(
            result.contains("unknown"),
            "public IP with no data should be unknown -- got: {result}"
        );
        assert!(
            result.contains("Private range: No"),
            "8.8.8.8 is not private -- got: {result}"
        );
        assert!(
            result.contains("Known registry: No"),
            "8.8.8.8 is not a known registry -- got: {result}"
        );
    }

    #[tokio::test]
    async fn lookup_ip_known_bad() {
        let executor = ToolExecutor::new();
        let result = executor
            .execute("lookup_ip", &json!({ "ip": "198.51.100.1" }))
            .await;
        assert!(
            result.contains("bad"),
            "known-bad IP should be flagged -- got: {result}"
        );
    }

    #[tokio::test]
    async fn lookup_ip_known_registry() {
        let executor = ToolExecutor::new();
        // 104.16.x.x is in the Cloudflare range used by npm
        let result = executor
            .execute("lookup_ip", &json!({ "ip": "104.16.1.1" }))
            .await;
        assert!(
            result.contains("Known registry: Yes"),
            "should identify registry IP -- got: {result}"
        );
        assert!(
            result.contains("npmjs"),
            "should mention npm registry -- got: {result}"
        );
    }

    #[tokio::test]
    async fn lookup_ip_invalid() {
        let executor = ToolExecutor::new();
        let result = executor
            .execute("lookup_ip", &json!({ "ip": "not-an-ip" }))
            .await;
        assert!(
            result.contains("invalid IP address"),
            "should return error for invalid IP -- got: {result}"
        );
    }

    #[tokio::test]
    async fn lookup_ip_missing() {
        let executor = ToolExecutor::new();
        let result = executor
            .execute("lookup_ip", &json!({}))
            .await;
        assert!(
            result.contains("missing IP address"),
            "should return error for missing IP -- got: {result}"
        );
    }

    #[tokio::test]
    async fn lookup_ip_loopback() {
        let executor = ToolExecutor::new();
        let result = executor
            .execute("lookup_ip", &json!({ "ip": "127.0.0.1" }))
            .await;
        assert!(
            result.contains("Loopback: Yes"),
            "should identify loopback -- got: {result}"
        );
        assert!(
            result.contains("benign"),
            "loopback should be benign -- got: {result}"
        );
    }

    // -- IP helper unit tests -------------------------------------------------

    #[test]
    fn is_private_range_10() {
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(is_private_range(&ip));
    }

    #[test]
    fn is_private_range_172() {
        let ip: IpAddr = "172.16.0.1".parse().unwrap();
        assert!(is_private_range(&ip));
        // 172.15.x should NOT be private
        let ip2: IpAddr = "172.15.0.1".parse().unwrap();
        assert!(!is_private_range(&ip2));
        // 172.32.x should NOT be private
        let ip3: IpAddr = "172.32.0.1".parse().unwrap();
        assert!(!is_private_range(&ip3));
    }

    #[test]
    fn is_private_range_192() {
        let ip: IpAddr = "192.168.0.1".parse().unwrap();
        assert!(is_private_range(&ip));
    }

    #[test]
    fn is_private_range_public() {
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        assert!(!is_private_range(&ip));
    }

    #[test]
    fn check_known_registry_npm_range() {
        let ip: IpAddr = "104.16.5.10".parse().unwrap();
        let result = check_known_registry(&ip);
        assert!(result.is_some());
        assert!(result.unwrap().contains("npmjs"));
    }

    #[test]
    fn check_known_registry_pypi_range() {
        let ip: IpAddr = "151.101.1.1".parse().unwrap();
        let result = check_known_registry(&ip);
        assert!(result.is_some());
        assert!(result.unwrap().contains("pypi"));
    }

    #[test]
    fn check_known_registry_no_match() {
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        let result = check_known_registry(&ip);
        assert!(result.is_none());
    }

    #[test]
    fn is_known_bad_match() {
        assert!(is_known_bad("198.51.100.1"));
    }

    #[test]
    fn is_known_bad_no_match() {
        assert!(!is_known_bad("8.8.8.8"));
    }
}
