use watchpost_types::context::{ActionContext, Ecosystem};
use watchpost_types::events::AncestryEntry;
use watchpost_types::util::{binary_basename, SHELLS};

/// Extracts the filename from an ancestry entry's binary path.
fn binary_name(entry: &AncestryEntry) -> &str {
    binary_basename(&entry.binary_path)
}

/// Checks whether a binary name corresponds to a common shell.
fn is_shell(name: &str) -> bool {
    SHELLS.contains(&name)
}

/// Infers the [`ActionContext`] from a process ancestry chain.
///
/// The ancestry is ordered child -> root (index 0 is the immediate process,
/// the last entry is the most distant ancestor). The inferrer walks up the
/// chain and returns the first recognized context.
pub struct ActionContextInferrer;

impl ActionContextInferrer {
    /// Walk the ancestry from child toward root. The first binary that matches
    /// a known pattern determines the context.
    pub fn infer(ancestry: &[AncestryEntry]) -> ActionContext {
        if ancestry.is_empty() {
            return ActionContext::Unknown;
        }

        for entry in ancestry {
            let name = binary_name(entry);

            match name {
                // NPM ecosystem package managers
                "npm" | "npx" | "yarn" | "pnpm" => {
                    return ActionContext::PackageInstall {
                        ecosystem: Ecosystem::Npm,
                        package_name: parse_package_arg(&entry.cmdline),
                        package_version: None,
                        working_dir: String::new(),
                    };
                }

                // Cargo build toolchain
                "cargo" => {
                    return ActionContext::Build {
                        toolchain: "cargo".to_string(),
                        working_dir: String::new(),
                    };
                }

                // Python ecosystem package managers
                "pip" | "pip3" | "pipx" | "uv" => {
                    return ActionContext::PackageInstall {
                        ecosystem: Ecosystem::Pip,
                        package_name: parse_package_arg(&entry.cmdline),
                        package_version: None,
                        working_dir: String::new(),
                    };
                }

                // Flatpak
                "flatpak" => {
                    let app_id = parse_flatpak_app_id(&entry.cmdline)
                        .unwrap_or_default();
                    return ActionContext::FlatpakApp {
                        app_id,
                        permissions: Vec::new(),
                    };
                }

                // Toolbox / Distrobox
                "toolbox" | "distrobox" => {
                    return ActionContext::ToolboxSession {
                        container_name: parse_container_name(&entry.cmdline)
                            .unwrap_or_default(),
                        image: String::new(),
                    };
                }

                // VS Code / Codium
                "code" | "codium" => {
                    return ActionContext::IdeOperation {
                        ide_name: "vscode".to_string(),
                    };
                }

                // JetBrains IDEs
                "idea" | "goland" | "clion" | "pycharm" | "webstorm" => {
                    return ActionContext::IdeOperation {
                        ide_name: "jetbrains".to_string(),
                    };
                }

                _ => {}
            }
        }

        // No known tool found. If any ancestor is a shell, this is a terminal session.
        if ancestry.iter().any(|e| is_shell(binary_name(e))) {
            return ActionContext::ShellCommand { tty: None };
        }

        ActionContext::Unknown
    }
}

/// Best-effort extraction of a package name from a cmdline string.
///
/// Looks for the first positional argument after an "install" or "add" subcommand,
/// skipping flags (tokens starting with `-`).
fn parse_package_arg(cmdline: &str) -> Option<String> {
    let tokens: Vec<&str> = cmdline.split_whitespace().collect();

    // Find the index of "install" or "add" subcommand.
    let sub_idx = tokens.iter().position(|t| *t == "install" || *t == "add")?;

    // Walk tokens after the subcommand, skip flags.
    for token in &tokens[sub_idx + 1..] {
        if !token.starts_with('-') {
            return Some(token.to_string());
        }
    }
    None
}

/// Best-effort extraction of a Flatpak app ID from cmdline.
fn parse_flatpak_app_id(cmdline: &str) -> Option<String> {
    let tokens: Vec<&str> = cmdline.split_whitespace().collect();

    // Look for a token that looks like a reverse-DNS ID (contains at least two dots).
    for token in &tokens[1..] {
        if !token.starts_with('-') && token.matches('.').count() >= 2 {
            return Some(token.to_string());
        }
    }

    // Fallback: return the last non-flag argument.
    tokens
        .iter()
        .skip(1)
        .rev()
        .find(|t| !t.starts_with('-'))
        .map(|t| t.to_string())
}

/// Best-effort extraction of a container name from a toolbox/distrobox cmdline.
fn parse_container_name(cmdline: &str) -> Option<String> {
    let tokens: Vec<&str> = cmdline.split_whitespace().collect();

    // Look for --name <value> or -c <value> pattern.
    for window in tokens.windows(2) {
        if window[0] == "--name" || window[0] == "-c" || window[0] == "--container" {
            return Some(window[1].to_string());
        }
    }

    // Fallback: last non-flag argument.
    tokens
        .iter()
        .skip(1)
        .rev()
        .find(|t| !t.starts_with('-'))
        .map(|t| t.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use watchpost_types::events::AncestryEntry;

    fn entry(pid: u32, binary_path: &str, cmdline: &str) -> AncestryEntry {
        AncestryEntry {
            pid,
            binary_path: binary_path.to_string(),
            cmdline: cmdline.to_string(),
        }
    }

    #[test]
    fn test_npm_package_install() {
        let ancestry = vec![
            entry(100, "/usr/bin/sh", "sh -c node install.js"),
            entry(99, "/usr/bin/node", "node install.js"),
            entry(98, "/usr/bin/npm", "npm install evil-package"),
            entry(97, "/usr/bin/bash", "bash"),
            entry(96, "/usr/bin/gnome-terminal", "gnome-terminal"),
        ];
        let ctx = ActionContextInferrer::infer(&ancestry);
        match ctx {
            ActionContext::PackageInstall {
                ecosystem,
                package_name,
                ..
            } => {
                assert_eq!(ecosystem, Ecosystem::Npm);
                assert_eq!(package_name, Some("evil-package".to_string()));
            }
            other => panic!("expected PackageInstall(Npm), got {other:?}"),
        }
    }

    #[test]
    fn test_cargo_build() {
        let ancestry = vec![
            entry(200, "/usr/bin/cc", "cc -o main main.c"),
            entry(199, "/usr/bin/cargo", "cargo build"),
            entry(198, "/usr/bin/bash", "bash"),
        ];
        let ctx = ActionContextInferrer::infer(&ancestry);
        match ctx {
            ActionContext::Build { toolchain, .. } => {
                assert_eq!(toolchain, "cargo");
            }
            other => panic!("expected Build(cargo), got {other:?}"),
        }
    }

    #[test]
    fn test_pip_package_install() {
        let ancestry = vec![
            entry(300, "/usr/bin/python3", "python3 setup.py install"),
            entry(299, "/usr/bin/pip", "pip install requests"),
            entry(298, "/usr/bin/bash", "bash"),
        ];
        let ctx = ActionContextInferrer::infer(&ancestry);
        match ctx {
            ActionContext::PackageInstall {
                ecosystem,
                package_name,
                ..
            } => {
                assert_eq!(ecosystem, Ecosystem::Pip);
                assert_eq!(package_name, Some("requests".to_string()));
            }
            other => panic!("expected PackageInstall(Pip), got {other:?}"),
        }
    }

    #[test]
    fn test_toolbox_session() {
        let ancestry = vec![
            entry(400, "/usr/bin/ls", "ls -la"),
            entry(399, "/usr/bin/bash", "bash"),
            entry(398, "/usr/bin/toolbox", "toolbox enter --name fedora-38"),
        ];
        let ctx = ActionContextInferrer::infer(&ancestry);
        match ctx {
            ActionContext::ToolboxSession {
                container_name, ..
            } => {
                assert_eq!(container_name, "fedora-38");
            }
            other => panic!("expected ToolboxSession, got {other:?}"),
        }
    }

    #[test]
    fn test_shell_command() {
        let ancestry = vec![
            entry(500, "/usr/bin/vim", "vim file.txt"),
            entry(499, "/usr/bin/bash", "bash"),
            entry(498, "/usr/bin/gnome-terminal", "gnome-terminal"),
        ];
        let ctx = ActionContextInferrer::infer(&ancestry);
        match ctx {
            ActionContext::ShellCommand { .. } => {}
            other => panic!("expected ShellCommand, got {other:?}"),
        }
    }

    #[test]
    fn test_ide_vscode() {
        let ancestry = vec![
            entry(600, "/usr/bin/node", "node extension.js"),
            entry(599, "/usr/bin/code", "code --extensions-dir /home/user/.vscode"),
        ];
        let ctx = ActionContextInferrer::infer(&ancestry);
        match ctx {
            ActionContext::IdeOperation { ide_name } => {
                assert_eq!(ide_name, "vscode");
            }
            other => panic!("expected IdeOperation(vscode), got {other:?}"),
        }
    }

    #[test]
    fn test_unknown_binary() {
        let ancestry = vec![entry(700, "/opt/custom/unknown-binary", "unknown-binary")];
        let ctx = ActionContextInferrer::infer(&ancestry);
        assert_eq!(ctx, ActionContext::Unknown);
    }

    #[test]
    fn test_empty_ancestry() {
        let ctx = ActionContextInferrer::infer(&[]);
        assert_eq!(ctx, ActionContext::Unknown);
    }

    #[test]
    fn test_jetbrains_ide() {
        let ancestry = vec![
            entry(800, "/usr/bin/java", "java -jar something.jar"),
            entry(799, "/opt/jetbrains/idea", "idea /home/user/project"),
        ];
        let ctx = ActionContextInferrer::infer(&ancestry);
        match ctx {
            ActionContext::IdeOperation { ide_name } => {
                assert_eq!(ide_name, "jetbrains");
            }
            other => panic!("expected IdeOperation(jetbrains), got {other:?}"),
        }
    }

    #[test]
    fn test_binary_name_extraction() {
        let e = entry(1, "/usr/local/bin/npm", "npm install");
        assert_eq!(binary_name(&e), "npm");

        let e = entry(1, "npm", "npm install");
        assert_eq!(binary_name(&e), "npm");

        let e = entry(1, "/a/b/c/d/cargo", "cargo build");
        assert_eq!(binary_name(&e), "cargo");
    }
}
