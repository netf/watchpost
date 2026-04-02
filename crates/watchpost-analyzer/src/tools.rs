use std::path::{Path, PathBuf};

/// Executes tools requested by the LLM during analysis.
///
/// In Phase 1, only `read_project_file` performs real work.  The process tree
/// and recent event tools return placeholders because they require a connection
/// to the daemon's engine, which is wired in later phases.
pub struct ToolExecutor {
    /// Allowed base directories for file reads.
    allowed_prefixes: Vec<PathBuf>,
}

impl ToolExecutor {
    /// Create a new executor that allows reading files under the given prefixes.
    ///
    /// If no prefixes are supplied the default set is:
    /// `/home`, `/tmp`, `/var/cache`.
    pub fn new() -> Self {
        Self {
            allowed_prefixes: vec![
                PathBuf::from("/home"),
                PathBuf::from("/tmp"),
                PathBuf::from("/var/cache"),
            ],
        }
    }

    /// Execute a tool by name, returning its output as a string.
    pub fn execute(&self, tool_name: &str, input: &serde_json::Value) -> String {
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
}

impl Default for ToolExecutor {
    fn default() -> Self {
        Self::new()
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

    #[test]
    fn read_project_file_valid() {
        // Create a temp file under /tmp so it passes the prefix check.
        let mut tmp = NamedTempFile::new_in("/tmp").expect("create temp file");
        write!(tmp, "hello world").expect("write temp file");
        let path = tmp.path().to_str().unwrap().to_string();

        let executor = ToolExecutor::new();
        let result = executor.execute("read_project_file", &json!({ "path": path }));
        assert_eq!(result, "hello world");
    }

    #[test]
    fn read_project_file_rejects_dotdot() {
        let executor = ToolExecutor::new();
        let result = executor.execute(
            "read_project_file",
            &json!({ "path": "/home/user/../etc/shadow" }),
        );
        assert!(
            result.contains("not allowed"),
            "should reject path with '..' — got: {result}"
        );
    }

    #[test]
    fn read_project_file_rejects_outside_prefix() {
        let executor = ToolExecutor::new();
        let result = executor.execute(
            "read_project_file",
            &json!({ "path": "/etc/shadow" }),
        );
        assert!(
            result.contains("outside allowed"),
            "should reject path outside allowed dirs — got: {result}"
        );
    }

    #[test]
    fn read_project_file_rejects_relative_path() {
        let executor = ToolExecutor::new();
        let result = executor.execute(
            "read_project_file",
            &json!({ "path": "relative/path.txt" }),
        );
        assert!(
            result.contains("must be absolute"),
            "should reject relative path — got: {result}"
        );
    }

    #[test]
    fn unknown_tool_returns_error() {
        let executor = ToolExecutor::new();
        let result = executor.execute("nonexistent_tool", &json!({}));
        assert_eq!(result, "Unknown tool: nonexistent_tool");
    }

    #[test]
    fn get_process_tree_placeholder() {
        let executor = ToolExecutor::new();
        let result = executor.execute("get_process_tree", &json!({ "pid": 1234 }));
        assert!(result.contains("1234"));
        assert!(result.contains("not connected"));
    }

    #[test]
    fn get_recent_events_placeholder() {
        let executor = ToolExecutor::new();
        let result = executor.execute(
            "get_recent_events",
            &json!({ "pid": 5678, "seconds": 30 }),
        );
        assert!(result.contains("5678"));
        assert!(result.contains("30s"));
        assert!(result.contains("not connected"));
    }
}
