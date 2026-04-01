use std::fs;
use std::path::PathBuf;

use dashmap::DashMap;
use tracing::debug;
use watchpost_types::events::AncestryEntry;

/// Builds process ancestry chains by walking `/proc` and caching results.
pub struct ProcessAncestryBuilder {
    cache: DashMap<u32, Vec<AncestryEntry>>,
}

impl ProcessAncestryBuilder {
    /// Create a new builder with an empty cache.
    pub fn new() -> Self {
        Self {
            cache: DashMap::new(),
        }
    }

    /// Build the ancestry chain for `pid`, walking parent PIDs up to `max_depth` entries.
    ///
    /// Returns entries ordered from child (the given pid) toward root (PID 1).
    /// Results are cached; subsequent calls for the same pid return the cached chain.
    ///
    /// This is best-effort: if a process has already exited, the chain stops there.
    pub fn build(&self, pid: u32, max_depth: usize) -> Vec<AncestryEntry> {
        // Check cache first.
        if let Some(cached) = self.cache.get(&pid) {
            return cached.clone();
        }

        let chain = self.walk_proc(pid, max_depth);
        self.cache.insert(pid, chain.clone());
        chain
    }

    /// Evict a PID from the cache (e.g. on ProcessExit).
    pub fn evict(&self, pid: u32) {
        self.cache.remove(&pid);
    }

    /// Walk `/proc` to build the ancestry chain starting from `pid`.
    fn walk_proc(&self, start_pid: u32, max_depth: usize) -> Vec<AncestryEntry> {
        let mut chain = Vec::new();
        let mut current_pid = start_pid;

        for _ in 0..max_depth {
            if current_pid == 0 {
                break;
            }

            let proc_dir = PathBuf::from(format!("/proc/{current_pid}"));

            // Read /proc/{pid}/status to find PPid.
            let status_path = proc_dir.join("status");
            let status_content = match fs::read_to_string(&status_path) {
                Ok(content) => content,
                Err(e) => {
                    debug!(pid = current_pid, error = %e, "failed to read /proc status, stopping ancestry walk");
                    break;
                }
            };

            let ppid = parse_ppid(&status_content);

            // Read /proc/{pid}/exe symlink for binary path.
            let binary_path = match fs::read_link(proc_dir.join("exe")) {
                Ok(path) => path.to_string_lossy().into_owned(),
                Err(_) => "unknown".to_string(),
            };

            // Read /proc/{pid}/cmdline (null-byte separated).
            let cmdline = match fs::read_to_string(proc_dir.join("cmdline")) {
                Ok(raw) => {
                    let trimmed = raw.trim_end_matches('\0');
                    trimmed.replace('\0', " ")
                }
                Err(_) => String::new(),
            };

            chain.push(AncestryEntry {
                pid: current_pid,
                binary_path,
                cmdline,
            });

            // Stop at PID 1 (init) -- don't walk further.
            if current_pid <= 1 {
                break;
            }

            match ppid {
                Some(next_pid) => current_pid = next_pid,
                None => break,
            }
        }

        chain
    }
}

impl Default for ProcessAncestryBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse the `PPid` field from `/proc/{pid}/status` content.
fn parse_ppid(status: &str) -> Option<u32> {
    for line in status.lines() {
        if let Some(value) = line.strip_prefix("PPid:\t") {
            return value.trim().parse().ok();
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_ancestry_self() {
        let builder = ProcessAncestryBuilder::new();
        let my_pid = std::process::id();
        let chain = builder.build(my_pid, 16);

        assert!(!chain.is_empty(), "ancestry should contain at least one entry (self)");
        assert_eq!(chain[0].pid, my_pid, "first entry should be the current process");
        assert!(!chain[0].binary_path.is_empty(), "binary path should not be empty");
    }

    #[test]
    fn test_ancestry_cache_hit() {
        let builder = ProcessAncestryBuilder::new();
        let my_pid = std::process::id();

        let first = builder.build(my_pid, 16);
        let second = builder.build(my_pid, 16);

        assert_eq!(first.len(), second.len(), "cached result should have same length");
        assert_eq!(first, second, "cached result should be identical");
    }

    #[test]
    fn test_ancestry_cache_eviction() {
        let builder = ProcessAncestryBuilder::new();
        let my_pid = std::process::id();

        let first = builder.build(my_pid, 16);
        assert!(!first.is_empty());

        builder.evict(my_pid);

        // After eviction, building again should still work (re-walks /proc).
        let second = builder.build(my_pid, 16);
        assert!(!second.is_empty());
        assert_eq!(first[0].pid, second[0].pid);
    }

    #[test]
    fn test_ancestry_unknown_pid() {
        let builder = ProcessAncestryBuilder::new();
        let chain = builder.build(999_999_999, 16);
        assert!(chain.is_empty(), "ancestry of a non-existent PID should be empty");
    }
}
