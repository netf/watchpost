use std::path::Path;

/// Metadata parsed from a Flatpak application.
#[derive(Debug, Clone)]
pub struct FlatpakMetadata {
    pub app_id: String,
    pub permissions: Vec<String>,
}

impl FlatpakMetadata {
    /// Read Flatpak metadata for an app from the standard location.
    ///
    /// Reads from `/var/lib/flatpak/app/{app_id}/current/active/metadata`
    /// and falls back to the user installation at
    /// `~/.local/share/flatpak/app/{app_id}/current/active/metadata`.
    pub fn read(app_id: &str) -> Option<Self> {
        let system_path = format!(
            "/var/lib/flatpak/app/{app_id}/current/active/metadata"
        );
        if let Ok(content) = std::fs::read_to_string(&system_path) {
            return Some(Self::parse(app_id, &content));
        }

        // Try user installation.
        if let Some(home) = std::env::var_os("HOME") {
            let user_path = Path::new(&home)
                .join(".local/share/flatpak/app")
                .join(app_id)
                .join("current/active/metadata");
            if let Ok(content) = std::fs::read_to_string(user_path) {
                return Some(Self::parse(app_id, &content));
            }
        }

        None
    }

    /// Parse the metadata file content.
    ///
    /// The format is INI-like (GKeyFile):
    /// ```text
    /// [Context]
    /// shared=network;ipc;
    /// sockets=x11;wayland;pulseaudio;
    /// filesystems=home;/tmp;xdg-download;
    /// ```
    pub fn parse(app_id: &str, content: &str) -> Self {
        let mut in_context = false;
        let mut permissions = Vec::new();

        for line in content.lines() {
            let trimmed = line.trim();

            // Section headers
            if trimmed.starts_with('[') && trimmed.ends_with(']') {
                in_context = trimmed == "[Context]";
                continue;
            }

            if !in_context {
                continue;
            }

            // Parse key=value pairs within [Context]
            if let Some(value) = trimmed.strip_prefix("filesystems=") {
                for entry in value.split(';') {
                    let entry = entry.trim();
                    if !entry.is_empty() {
                        permissions.push(entry.to_string());
                    }
                }
            }
        }

        Self {
            app_id: app_id.to_string(),
            permissions,
        }
    }

    /// Check if a file path is within the app's declared permissions.
    ///
    /// Permission entries are interpreted as follows:
    /// - `host` — full host filesystem access, everything is permitted
    /// - `home` — access to `/home/` paths
    /// - `xdg-download` — access to `~/Downloads`
    /// - `xdg-documents` — access to `~/Documents`
    /// - `xdg-music` — access to `~/Music`
    /// - `xdg-pictures` — access to `~/Pictures`
    /// - `xdg-videos` — access to `~/Videos`
    /// - `xdg-desktop` — access to `~/Desktop`
    /// - `~/...` — literal path under the user's home directory
    /// - `/...` — literal absolute path prefix
    pub fn is_path_permitted(&self, path: &str) -> bool {
        let home_dir = std::env::var("HOME").unwrap_or_else(|_| "/home/user".to_string());

        for perm in &self.permissions {
            match perm.as_str() {
                "host" => return true,
                "home" => {
                    if path.starts_with("/home/") {
                        return true;
                    }
                }
                "xdg-download" => {
                    let prefix = format!("{home_dir}/Downloads");
                    if path.starts_with(&prefix) {
                        return true;
                    }
                }
                "xdg-documents" => {
                    let prefix = format!("{home_dir}/Documents");
                    if path.starts_with(&prefix) {
                        return true;
                    }
                }
                "xdg-music" => {
                    let prefix = format!("{home_dir}/Music");
                    if path.starts_with(&prefix) {
                        return true;
                    }
                }
                "xdg-pictures" => {
                    let prefix = format!("{home_dir}/Pictures");
                    if path.starts_with(&prefix) {
                        return true;
                    }
                }
                "xdg-videos" => {
                    let prefix = format!("{home_dir}/Videos");
                    if path.starts_with(&prefix) {
                        return true;
                    }
                }
                "xdg-desktop" => {
                    let prefix = format!("{home_dir}/Desktop");
                    if path.starts_with(&prefix) {
                        return true;
                    }
                }
                other => {
                    // Home-relative path: ~/...
                    if let Some(suffix) = other.strip_prefix("~/") {
                        let expanded = format!("{home_dir}/{suffix}");
                        if path.starts_with(&expanded) {
                            return true;
                        }
                    } else if other.starts_with('/') {
                        // Absolute path prefix
                        if path.starts_with(other) {
                            return true;
                        }
                    }
                }
            }
        }

        false
    }
}

/// Extract Flatpak app ID from a process's cgroup path.
///
/// Reads `/proc/{pid}/cgroup` and looks for `app-flatpak-{id}-\d+.scope`
/// in the cgroup hierarchy. The cgroup line typically looks like:
///
/// ```text
/// 0::/user.slice/user-1000.slice/user@1000.service/app.slice/app-flatpak-org.example.App-12345.scope
/// ```
pub fn extract_app_id_from_cgroup(pid: u32) -> Option<String> {
    let cgroup_path = format!("/proc/{pid}/cgroup");
    let content = std::fs::read_to_string(cgroup_path).ok()?;
    extract_app_id_from_cgroup_content(&content)
}

/// Parse a Flatpak app ID from raw cgroup file content.
///
/// Exposed for testing without requiring `/proc` access.
pub fn extract_app_id_from_cgroup_content(content: &str) -> Option<String> {
    for line in content.lines() {
        // Find the "app-flatpak-" marker in the cgroup path
        if let Some(start) = line.find("app-flatpak-") {
            let after_prefix = &line[start + "app-flatpak-".len()..];
            // The format is: app-flatpak-{app_id}-{digits}.scope
            // We need to find the last `-{digits}.scope` and strip it.
            if let Some(scope_pos) = after_prefix.rfind(".scope") {
                let before_scope = &after_prefix[..scope_pos];
                // Strip the trailing -<digits> segment
                if let Some(last_dash) = before_scope.rfind('-') {
                    let candidate_digits = &before_scope[last_dash + 1..];
                    if !candidate_digits.is_empty()
                        && candidate_digits.chars().all(|c| c.is_ascii_digit())
                    {
                        let app_id = &before_scope[..last_dash];
                        if !app_id.is_empty() {
                            return Some(app_id.to_string());
                        }
                    }
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_metadata_extracts_permissions() {
        let content = "\
[Application]
name=org.mozilla.Firefox
runtime=org.freedesktop.Platform/x86_64/23.08

[Context]
shared=network;ipc;
sockets=x11;wayland;pulseaudio;
filesystems=home;/tmp;xdg-download;

[Session Bus Policy]
org.freedesktop.Notifications=talk
";

        let meta = FlatpakMetadata::parse("org.mozilla.Firefox", content);
        assert_eq!(meta.app_id, "org.mozilla.Firefox");
        assert_eq!(meta.permissions, vec!["home", "/tmp", "xdg-download"]);
    }

    #[test]
    fn is_path_permitted_with_home_permission() {
        let meta = FlatpakMetadata {
            app_id: "org.example.App".into(),
            permissions: vec!["home".into()],
        };

        assert!(
            meta.is_path_permitted("/home/user/Documents/file.txt"),
            "home permission should permit /home/user paths"
        );
        assert!(
            !meta.is_path_permitted("/etc/shadow"),
            "home permission should not permit /etc paths"
        );
    }

    #[test]
    fn is_path_permitted_without_home_permission() {
        let meta = FlatpakMetadata {
            app_id: "org.example.App".into(),
            permissions: vec!["/tmp".into()],
        };

        assert!(
            !meta.is_path_permitted("/home/user/file.txt"),
            "without home permission, /home paths should be denied"
        );
        assert!(
            meta.is_path_permitted("/tmp/scratch"),
            "/tmp prefix should be permitted"
        );
    }

    #[test]
    fn is_path_permitted_with_host_permission() {
        let meta = FlatpakMetadata {
            app_id: "org.example.App".into(),
            permissions: vec!["host".into()],
        };

        assert!(
            meta.is_path_permitted("/etc/shadow"),
            "host permission should permit everything"
        );
        assert!(
            meta.is_path_permitted("/home/user/.ssh/id_rsa"),
            "host permission should permit everything"
        );
        assert!(
            meta.is_path_permitted("/root/.bashrc"),
            "host permission should permit everything"
        );
    }

    #[test]
    fn is_path_permitted_with_xdg_download() {
        let meta = FlatpakMetadata {
            app_id: "org.example.App".into(),
            permissions: vec!["xdg-download".into()],
        };

        let home = std::env::var("HOME").unwrap_or_else(|_| "/home/user".to_string());
        let downloads_path = format!("{home}/Downloads/file.pdf");

        assert!(
            meta.is_path_permitted(&downloads_path),
            "xdg-download should permit ~/Downloads paths"
        );
        assert!(
            !meta.is_path_permitted(&format!("{home}/Documents/secret.doc")),
            "xdg-download should not permit ~/Documents paths"
        );
    }

    #[test]
    fn is_path_permitted_with_home_relative_path() {
        let meta = FlatpakMetadata {
            app_id: "org.example.App".into(),
            permissions: vec!["~/.config/foo".into()],
        };

        let home = std::env::var("HOME").unwrap_or_else(|_| "/home/user".to_string());

        assert!(
            meta.is_path_permitted(&format!("{home}/.config/foo/settings.json")),
            "~/.config/foo should permit paths under it"
        );
        assert!(
            !meta.is_path_permitted(&format!("{home}/.config/bar/settings.json")),
            "~/.config/foo should not permit ~/.config/bar"
        );
    }

    #[test]
    fn extract_app_id_from_cgroup_content_valid() {
        let content = "0::/user.slice/user-1000.slice/user@1000.service/app.slice/app-flatpak-org.mozilla.Firefox-12345.scope\n";

        let app_id = extract_app_id_from_cgroup_content(content);
        assert_eq!(app_id, Some("org.mozilla.Firefox".to_string()));
    }

    #[test]
    fn extract_app_id_from_cgroup_content_complex_id() {
        let content = "0::/user.slice/user-1000.slice/user@1000.service/app.slice/app-flatpak-com.valvesoftware.Steam-99999.scope\n";

        let app_id = extract_app_id_from_cgroup_content(content);
        assert_eq!(app_id, Some("com.valvesoftware.Steam".to_string()));
    }

    #[test]
    fn extract_app_id_from_cgroup_content_no_flatpak() {
        let content = "0::/user.slice/user-1000.slice/session-2.scope\n";

        let app_id = extract_app_id_from_cgroup_content(content);
        assert_eq!(app_id, None);
    }

    #[test]
    fn parse_metadata_no_context_section() {
        let content = "\
[Application]
name=org.example.App

[Session Bus Policy]
org.freedesktop.Notifications=talk
";
        let meta = FlatpakMetadata::parse("org.example.App", content);
        assert_eq!(meta.app_id, "org.example.App");
        assert!(
            meta.permissions.is_empty(),
            "no [Context] section should yield empty permissions"
        );
    }

    #[test]
    fn parse_metadata_no_filesystems_key() {
        let content = "\
[Context]
shared=network;ipc;
sockets=x11;wayland;
";
        let meta = FlatpakMetadata::parse("org.example.App", content);
        assert!(
            meta.permissions.is_empty(),
            "no filesystems key should yield empty permissions"
        );
    }
}
