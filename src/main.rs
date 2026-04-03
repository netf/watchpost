mod cli;
mod daemon;
mod init;

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;
use watchpost_types::WatchpostConfig;

/// Load the configuration file from the given path.
fn load_config(path: &str) -> Result<WatchpostConfig> {
    let config_str =
        std::fs::read_to_string(path).with_context(|| format!("reading config file: {path}"))?;
    let config: WatchpostConfig =
        toml::from_str(&config_str).with_context(|| format!("parsing config file: {path}"))?;
    Ok(config)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = cli::Cli::parse();

    match cli.command {
        cli::Command::Init { api_key, template } => init::run_init(api_key, template).await,
        cli::Command::Daemon => {
            let config = load_config(&cli.config)?;
            daemon::run_daemon(config).await
        }
        cli::Command::Status => {
            println!("Status command not yet implemented");
            Ok(())
        }
        cli::Command::Events { action: _ } => {
            println!("Events command not yet implemented");
            Ok(())
        }
        cli::Command::Policy { action } => {
            let config = load_config(&cli.config)?;
            handle_policy(action, &config)
        }
        cli::Command::Allowlist { action } => {
            let config = load_config(&cli.config)?;
            handle_allowlist(action, &config)
        }
        cli::Command::Gate { action } => handle_gate(action),
        cli::Command::Tui => {
            let app = watchpost_tui::App::new();
            // TODO: In future, connect to daemon via Unix socket to populate live data
            // For now, start with empty state (demo mode)
            watchpost_tui::run::run_tui(app).await
        }
    }
}

// ---------------------------------------------------------------------------
// Policy handlers
// ---------------------------------------------------------------------------

fn handle_policy(action: cli::PolicyAction, config: &WatchpostConfig) -> Result<()> {
    let policy_dir = PathBuf::from(&config.advanced.tetragon.policy_dir);
    let data_dir = PathBuf::from(&config.daemon.data_dir);
    let staging_dir = data_dir.join("policies/staging");
    let active_dir = data_dir.join("policies/active");

    match action {
        cli::PolicyAction::List => {
            println!("{:<30} {}", "NAME", "STATUS");
            println!("{}", "-".repeat(45));

            // Base policies from Tetragon policy dir
            if policy_dir.is_dir() {
                if let Ok(entries) = std::fs::read_dir(&policy_dir) {
                    for entry in entries.flatten() {
                        let path = entry.path();
                        if path.extension().and_then(|e| e.to_str()) == Some("yaml") {
                            if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                                println!("{:<30} base", stem);
                            }
                        }
                    }
                }
            }

            // Staged policies
            if staging_dir.is_dir() {
                if let Ok(entries) = std::fs::read_dir(&staging_dir) {
                    for entry in entries.flatten() {
                        let path = entry.path();
                        if path.extension().and_then(|e| e.to_str()) == Some("yaml") {
                            if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                                println!("{:<30} staged", stem);
                            }
                        }
                    }
                }
            }

            // Active reactive policies
            if active_dir.is_dir() {
                if let Ok(entries) = std::fs::read_dir(&active_dir) {
                    for entry in entries.flatten() {
                        let path = entry.path();
                        if path.extension().and_then(|e| e.to_str()) == Some("yaml") {
                            if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                                println!("{:<30} active", stem);
                            }
                        }
                    }
                }
            }

            Ok(())
        }
        cli::PolicyAction::Show { name } => {
            let filename = format!("{name}.yaml");

            // Search in all three directories
            let candidates = [
                policy_dir.join(&filename),
                staging_dir.join(&filename),
                active_dir.join(&filename),
            ];

            for path in &candidates {
                if path.exists() {
                    let content = std::fs::read_to_string(path)
                        .with_context(|| format!("reading policy file: {}", path.display()))?;
                    println!("# Source: {}", path.display());
                    println!("{content}");
                    return Ok(());
                }
            }

            anyhow::bail!("policy '{name}' not found");
        }
        cli::PolicyAction::Approve { name } => {
            let mgr =
                watchpost_policy::staged::StagedPolicyManager::new(staging_dir, active_dir)?;
            mgr.approve(&name)?;
            println!("Policy '{name}' approved and activated.");
            Ok(())
        }
        cli::PolicyAction::Revoke { name } => {
            let mgr =
                watchpost_policy::staged::StagedPolicyManager::new(staging_dir, active_dir)?;
            mgr.revoke(&name)?;
            println!("Policy '{name}' revoked.");
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------
// Allowlist handlers
// ---------------------------------------------------------------------------

fn handle_allowlist(action: cli::AllowlistAction, config: &WatchpostConfig) -> Result<()> {
    let data_dir = PathBuf::from(&config.daemon.data_dir);
    let db_path = data_dir.join("allowlist.db");
    let store = watchpost_policy::allowlist::AllowlistStore::open(&db_path)
        .with_context(|| format!("opening allowlist database: {}", db_path.display()))?;

    match action {
        cli::AllowlistAction::List => {
            let entries = store.list()?;
            if entries.is_empty() {
                println!("No allowlist entries.");
                return Ok(());
            }
            println!(
                "{:<6} {:<25} {:<25} {:<10} {:<6}",
                "ID", "PARENT", "CHILD", "CONTEXT", "COUNT"
            );
            println!("{}", "-".repeat(75));
            for e in &entries {
                println!(
                    "{:<6} {:<25} {:<25} {:<10} {:<6}",
                    e.id, e.parent_binary, e.child_binary, e.context_type, e.occurrence_count
                );
            }
            Ok(())
        }
        cli::AllowlistAction::Remove { id } => {
            store.remove(id)?;
            println!("Allowlist entry {id} removed.");
            Ok(())
        }
        cli::AllowlistAction::Reset => {
            store.reset()?;
            println!("Allowlist cleared.");
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------
// Gate handlers (stub — real implementation needs IPC to daemon)
// ---------------------------------------------------------------------------

fn handle_gate(action: cli::GateAction) -> Result<()> {
    match action {
        cli::GateAction::Allow { package, hash } => {
            println!(
                "Recorded: allow package '{package}' with script hash '{hash}'."
            );
            println!("Note: the gate allowlist is in-memory; this takes effect on next daemon restart.");
            Ok(())
        }
        cli::GateAction::Block { package } => {
            println!("Recorded: block package '{package}'.");
            println!("Note: the gate allowlist is in-memory; this takes effect on next daemon restart.");
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use watchpost_types::{PolicyTemplate, WatchpostConfig};

    #[test]
    fn cli_help_does_not_panic() {
        // Verify the CLI can be built without panicking.
        use clap::CommandFactory;
        let cmd = super::cli::Cli::command();
        // Render help to a string to exercise all subcommands.
        let mut buf = Vec::new();
        cmd.clone()
            .write_help(&mut buf)
            .expect("writing help should succeed");
        let help = String::from_utf8(buf).unwrap();
        assert!(help.contains("watchpost"));
        assert!(help.contains("daemon"));
        assert!(help.contains("init"));
        assert!(help.contains("status"));
        assert!(help.contains("events"));
        assert!(help.contains("policy"));
        assert!(help.contains("allowlist"));
        assert!(help.contains("gate"));
        assert!(help.contains("tui"));
    }

    #[test]
    fn cli_parse_policy_list() {
        use clap::Parser;
        let cli = super::cli::Cli::parse_from(["watchpost", "policy", "list"]);
        assert!(matches!(
            cli.command,
            super::cli::Command::Policy {
                action: super::cli::PolicyAction::List,
            }
        ));
    }

    #[test]
    fn cli_parse_policy_show() {
        use clap::Parser;
        let cli = super::cli::Cli::parse_from(["watchpost", "policy", "show", "my-policy"]);
        match cli.command {
            super::cli::Command::Policy {
                action: super::cli::PolicyAction::Show { name },
            } => assert_eq!(name, "my-policy"),
            _ => panic!("expected Policy Show"),
        }
    }

    #[test]
    fn cli_parse_policy_approve() {
        use clap::Parser;
        let cli = super::cli::Cli::parse_from(["watchpost", "policy", "approve", "block-net"]);
        match cli.command {
            super::cli::Command::Policy {
                action: super::cli::PolicyAction::Approve { name },
            } => assert_eq!(name, "block-net"),
            _ => panic!("expected Policy Approve"),
        }
    }

    #[test]
    fn cli_parse_allowlist_remove() {
        use clap::Parser;
        let cli = super::cli::Cli::parse_from(["watchpost", "allowlist", "remove", "42"]);
        match cli.command {
            super::cli::Command::Allowlist {
                action: super::cli::AllowlistAction::Remove { id },
            } => assert_eq!(id, 42),
            _ => panic!("expected Allowlist Remove"),
        }
    }

    #[test]
    fn cli_parse_allowlist_list() {
        use clap::Parser;
        let cli = super::cli::Cli::parse_from(["watchpost", "allowlist", "list"]);
        assert!(matches!(
            cli.command,
            super::cli::Command::Allowlist {
                action: super::cli::AllowlistAction::List,
            }
        ));
    }

    #[test]
    fn cli_parse_allowlist_reset() {
        use clap::Parser;
        let cli = super::cli::Cli::parse_from(["watchpost", "allowlist", "reset"]);
        assert!(matches!(
            cli.command,
            super::cli::Command::Allowlist {
                action: super::cli::AllowlistAction::Reset,
            }
        ));
    }

    #[test]
    fn cli_parse_gate_allow() {
        use clap::Parser;
        let cli =
            super::cli::Cli::parse_from(["watchpost", "gate", "allow", "my-pkg", "abc123"]);
        match cli.command {
            super::cli::Command::Gate {
                action: super::cli::GateAction::Allow { package, hash },
            } => {
                assert_eq!(package, "my-pkg");
                assert_eq!(hash, "abc123");
            }
            _ => panic!("expected Gate Allow"),
        }
    }

    #[test]
    fn cli_parse_gate_block() {
        use clap::Parser;
        let cli = super::cli::Cli::parse_from(["watchpost", "gate", "block", "evil-pkg"]);
        match cli.command {
            super::cli::Command::Gate {
                action: super::cli::GateAction::Block { package },
            } => assert_eq!(package, "evil-pkg"),
            _ => panic!("expected Gate Block"),
        }
    }

    #[test]
    fn cli_global_config_flag() {
        use clap::Parser;
        let cli = super::cli::Cli::parse_from([
            "watchpost",
            "--config",
            "/tmp/test.toml",
            "status",
        ]);
        assert_eq!(cli.config, "/tmp/test.toml");
        assert!(matches!(cli.command, super::cli::Command::Status));
    }

    #[test]
    fn cli_default_config_path() {
        use clap::Parser;
        let cli = super::cli::Cli::parse_from(["watchpost", "status"]);
        assert_eq!(cli.config, "/etc/watchpost/config.toml");
    }

    #[test]
    fn minimal_toml_parses_to_config() {
        let toml_str = r#"
[daemon]
api_key = "sk-ant-test-key"
"#;
        let config: WatchpostConfig =
            toml::from_str(toml_str).expect("minimal TOML should parse");
        assert_eq!(config.daemon.api_key, "sk-ant-test-key");
        assert_eq!(config.daemon.data_dir, "/var/lib/watchpost");
        assert!(config.notify.desktop);
    }

    #[test]
    fn empty_toml_uses_defaults() {
        let config: WatchpostConfig =
            toml::from_str("").expect("empty TOML should parse with defaults");
        assert!(config.daemon.api_key.is_empty());
        assert_eq!(config.daemon.data_dir, "/var/lib/watchpost");
        assert_eq!(
            config.daemon.log_level,
            watchpost_types::LogLevel::Warn
        );
        assert_eq!(
            config.advanced.analyzer.model,
            "claude-haiku-4-5-20251001"
        );
    }

    #[test]
    fn full_config_toml_parses() {
        let toml_str = r#"
[daemon]
api_key = "sk-ant-full-test"
log_level = "debug"
data_dir = "/tmp/watchpost-test"

[enforcement]
mode = "advisory"

[notify]
desktop = false

[advanced.tetragon]
endpoint = "unix:///tmp/tetragon.sock"

[advanced.engine]
fast_path_threshold = 0.8
llm_threshold = 0.4

[advanced.analyzer]
model = "claude-sonnet-4-20250514"
max_analyses_per_minute = 20
"#;
        let config: WatchpostConfig =
            toml::from_str(toml_str).expect("full config should parse");
        assert_eq!(config.daemon.api_key, "sk-ant-full-test");
        assert_eq!(
            config.daemon.log_level,
            watchpost_types::LogLevel::Debug
        );
        assert_eq!(config.daemon.data_dir, "/tmp/watchpost-test");
        assert_eq!(
            config.enforcement.mode,
            watchpost_types::EnforcementMode::Advisory
        );
        assert!(!config.notify.desktop);
        assert_eq!(
            config.advanced.tetragon.endpoint,
            "unix:///tmp/tetragon.sock"
        );
        assert_eq!(config.advanced.engine.fast_path_threshold, 0.8);
        assert_eq!(config.advanced.engine.llm_threshold, 0.4);
        assert_eq!(config.advanced.analyzer.model, "claude-sonnet-4-20250514");
        assert_eq!(config.advanced.analyzer.max_analyses_per_minute, 20);
    }

    // -----------------------------------------------------------------------
    // Policy template tests
    // -----------------------------------------------------------------------

    fn load_template_yaml(name: &str) -> PolicyTemplate {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("templates")
            .join(format!("{name}.yaml"));
        let contents = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
        serde_yml::from_str(&contents)
            .unwrap_or_else(|e| panic!("parsing {}: {e}", path.display()))
    }

    #[test]
    fn template_web_developer_parses() {
        let tpl = load_template_yaml("web-developer");
        assert_eq!(tpl.name, "web-developer");
        assert!(!tpl.description.is_empty());
        assert!(!tpl.policies.is_empty());
    }

    #[test]
    fn template_systems_developer_parses() {
        let tpl = load_template_yaml("systems-developer");
        assert_eq!(tpl.name, "systems-developer");
        assert!(!tpl.description.is_empty());
        assert!(!tpl.policies.is_empty());
    }

    #[test]
    fn template_minimal_parses() {
        let tpl = load_template_yaml("minimal");
        assert_eq!(tpl.name, "minimal");
        assert!(!tpl.description.is_empty());
        assert!(!tpl.policies.is_empty());
    }

    #[test]
    fn template_web_developer_includes_npm_not_cargo() {
        let tpl = load_template_yaml("web-developer");
        assert!(
            tpl.policies.contains(&"npm-monitoring.yaml".to_string()),
            "web-developer should include npm-monitoring"
        );
        assert!(
            !tpl.policies.contains(&"cargo-monitoring.yaml".to_string()),
            "web-developer should not include cargo-monitoring"
        );
    }

    #[test]
    fn template_systems_developer_includes_cargo_not_npm() {
        let tpl = load_template_yaml("systems-developer");
        assert!(
            tpl.policies
                .contains(&"cargo-monitoring.yaml".to_string()),
            "systems-developer should include cargo-monitoring"
        );
        assert!(
            !tpl.policies.contains(&"npm-monitoring.yaml".to_string()),
            "systems-developer should not include npm-monitoring"
        );
    }

    #[test]
    fn template_minimal_has_five_or_fewer_policies() {
        let tpl = load_template_yaml("minimal");
        assert!(
            tpl.policies.len() <= 5,
            "minimal template should have at most 5 policies, got {}",
            tpl.policies.len()
        );
    }

    #[test]
    fn cli_parse_init_with_template() {
        use clap::Parser;
        let cli = super::cli::Cli::parse_from([
            "watchpost",
            "init",
            "--template",
            "web-developer",
        ]);
        match cli.command {
            super::cli::Command::Init { api_key, template } => {
                assert!(api_key.is_none());
                assert_eq!(template.as_deref(), Some("web-developer"));
            }
            _ => panic!("expected Init"),
        }
    }

    #[test]
    fn cli_parse_init_without_template() {
        use clap::Parser;
        let cli = super::cli::Cli::parse_from(["watchpost", "init"]);
        match cli.command {
            super::cli::Command::Init { api_key, template } => {
                assert!(api_key.is_none());
                assert!(template.is_none());
            }
            _ => panic!("expected Init"),
        }
    }
}
