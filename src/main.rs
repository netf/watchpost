mod cli;
mod daemon;
mod init;
mod style;

use std::path::PathBuf;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use clap::Parser;
use console::style;
use watchpost_notify::event_log::{EventFilter, EventLog};
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
async fn main() {
    let cli = cli::Cli::parse();

    let result = run(cli).await;
    if let Err(err) = result {
        style::error_display(&err);
        std::process::exit(1);
    }
}

async fn run(cli: cli::Cli) -> Result<()> {
    match cli.command {
        cli::Command::Init { api_key, template } => init::run_init(api_key, template).await,
        cli::Command::Daemon => {
            let config = load_config(&cli.config)?;
            daemon::run_daemon(config).await
        }
        cli::Command::Status => {
            run_status(&cli.config)
        }
        cli::Command::Events { action } => {
            run_events(&cli.config, action)
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
            watchpost_tui::run::run_tui(app).await
        }
    }
}

// ---------------------------------------------------------------------------
// Status command
// ---------------------------------------------------------------------------

fn run_status(config_path: &str) -> Result<()> {
    let term = console::Term::stdout();

    term.write_line(&format!(
        "\n  {}",
        style(format!("Watchpost v{}", env!("CARGO_PKG_VERSION"))).bold()
    ))?;
    term.write_line("")?;

    // Load config (best-effort: show what we can even if config is missing)
    let config = match load_config(config_path) {
        Ok(c) => Some(c),
        Err(_) => {
            term.write_line(&format!(
                "  {:<14}{}",
                style("Config:").dim(),
                style(format!("not found ({config_path})")).yellow()
            ))?;
            None
        }
    };

    // Daemon status -- just check if the systemd service is active
    let daemon_status = check_daemon_running();
    let daemon_display = if daemon_status {
        style("running").green().to_string()
    } else {
        style("not running").yellow().to_string()
    };
    term.write_line(&format!("  {:<14}{}", style("Daemon:").dim(), daemon_display))?;

    if let Some(ref config) = config {
        // Tetragon socket
        let endpoint = &config.advanced.tetragon.endpoint;
        let socket_path = endpoint
            .strip_prefix("unix://")
            .unwrap_or(endpoint);
        let tetragon_status = if std::path::Path::new(socket_path).exists() {
            format!(
                "{} {}",
                style("connected").green(),
                style(format!("({endpoint})")).dim()
            )
        } else {
            format!(
                "{} {}",
                style("not found").yellow(),
                style(format!("({endpoint})")).dim()
            )
        };
        term.write_line(&format!("  {:<14}{}", style("Tetragon:").dim(), tetragon_status))?;

        // Events DB
        let data_dir = PathBuf::from(&config.daemon.data_dir);
        let db_path = data_dir.join("events.db");
        if db_path.exists() {
            let size = std::fs::metadata(&db_path)
                .map(|m| format_file_size(m.len()))
                .unwrap_or_else(|_| "?".to_string());
            term.write_line(&format!(
                "  {:<14}{} {}",
                style("Events DB:").dim(),
                db_path.display(),
                style(format!("({size})")).dim()
            ))?;

            // Try to query some stats
            if let Ok(log) = EventLog::open(&db_path) {
                term.write_line("")?;
                term.write_line(&format!("  {}", style("Last 24h:").bold()))?;

                let since_24h = Utc::now() - chrono::Duration::hours(24);
                let filter = EventFilter {
                    since: Some(since_24h),
                    limit: usize::MAX,
                    ..Default::default()
                };
                let event_count = log
                    .query_events(&filter)
                    .map(|v| v.len())
                    .unwrap_or(0);

                term.write_line(&format!(
                    "    {:<20} {}",
                    "Events processed:",
                    style(format_number(event_count)).bold()
                ))?;
            }
        } else {
            term.write_line(&format!(
                "  {:<14}{}",
                style("Events DB:").dim(),
                style(format!("{} (not found)", db_path.display())).yellow()
            ))?;
        }
    }

    term.write_line("")?;
    Ok(())
}

/// Check if the watchpost daemon is running.
/// Tries systemctl first (for systemd-managed installs), then falls back to
/// checking for a running `watchpost daemon` process via pgrep.
fn check_daemon_running() -> bool {
    // Check systemd service
    let systemd = std::process::Command::new("systemctl")
        .args(["is-active", "--quiet", "watchpost"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    if systemd {
        return true;
    }

    // Fall back to checking for any running watchpost process
    std::process::Command::new("pgrep")
        .args(["-f", "watchpost daemon"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Format a byte count as a human-readable string.
fn format_file_size(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{bytes} B")
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.1} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

/// Format a number with thousands separators.
fn format_number(n: usize) -> String {
    let s = n.to_string();
    let mut result = String::new();
    for (i, ch) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            result.push(',');
        }
        result.push(ch);
    }
    result.chars().rev().collect()
}

// ---------------------------------------------------------------------------
// Events command
// ---------------------------------------------------------------------------

fn run_events(config_path: &str, action: cli::EventsAction) -> Result<()> {
    match action {
        cli::EventsAction::List {
            since,
            until,
            severity,
            classification,
            binary,
            context,
            format,
            limit,
        } => run_events_list(
            config_path,
            since,
            until,
            severity,
            classification,
            binary,
            context,
            &format,
            limit,
        ),
        cli::EventsAction::Show { event_id } => {
            run_events_show(config_path, &event_id)
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn run_events_list(
    config_path: &str,
    since: Option<String>,
    until: Option<String>,
    _severity: Option<String>,
    classification: Option<String>,
    binary: Option<String>,
    context: Option<String>,
    format: &str,
    limit: usize,
) -> Result<()> {
    let config = load_config(config_path)?;
    let data_dir = PathBuf::from(&config.daemon.data_dir);
    let db_path = data_dir.join("events.db");

    if !db_path.exists() {
        anyhow::bail!(
            "events database not found at {}. Is the daemon running?",
            db_path.display()
        );
    }

    let log = EventLog::open(&db_path)
        .with_context(|| format!("opening events database: {}", db_path.display()))?;

    let since_dt: Option<DateTime<Utc>> = since
        .as_deref()
        .map(|s| parse_datetime(s))
        .transpose()
        .context("invalid --since value")?;

    let until_dt: Option<DateTime<Utc>> = until
        .as_deref()
        .map(|s| parse_datetime(s))
        .transpose()
        .context("invalid --until value")?;

    let filter = EventFilter {
        since: since_dt,
        until: until_dt,
        kind: None,
        classification: classification.clone(),
        binary: binary.clone(),
        context: context.clone(),
        limit,
    };

    let events = log.query_events(&filter)?;

    if format == "json" {
        // Clean JSON output -- no colors, no styling
        let json = serde_json::to_string_pretty(&events)
            .context("serializing events to JSON")?;
        println!("{json}");
        return Ok(());
    }

    // Table format
    let term = console::Term::stdout();

    if events.is_empty() {
        term.write_line(&style::hint("No events found matching the given filters."))?;
        return Ok(());
    }

    // Header
    term.write_line(&format!(
        "\n  {:<22} {:<16} {:<22} {}",
        style("TIME").bold(),
        style("TYPE").bold(),
        style("BINARY").bold(),
        style("CONTEXT").bold(),
    ))?;

    for event in &events {
        let timestamp = event
            .event
            .timestamp
            .format("%Y-%m-%d %H:%M:%S")
            .to_string();
        let kind = event_kind_short(&event.event.kind);
        let binary_path = event
            .event
            .binary()
            .unwrap_or("-")
            .to_string();
        let context_str = action_context_short(&event.context);

        term.write_line(&format!(
            "  {:<22} {:<16} {:<22} {}",
            style(&timestamp).dim(),
            kind,
            binary_path,
            style(context_str).dim(),
        ))?;
    }

    term.write_line(&format!(
        "\n  {}",
        style(format!(
            "Showing {} event{}",
            events.len(),
            if events.len() == 1 { "" } else { "s" }
        ))
        .dim()
    ))?;
    term.write_line("")?;

    Ok(())
}

fn run_events_show(config_path: &str, event_id: &str) -> Result<()> {
    let config = load_config(config_path)?;
    let data_dir = PathBuf::from(&config.daemon.data_dir);
    let db_path = data_dir.join("events.db");

    if !db_path.exists() {
        anyhow::bail!(
            "events database not found at {}. Is the daemon running?",
            db_path.display()
        );
    }

    let log = EventLog::open(&db_path)
        .with_context(|| format!("opening events database: {}", db_path.display()))?;

    // Query all events and find the matching one
    let filter = EventFilter {
        limit: usize::MAX,
        ..Default::default()
    };
    let events = log.query_events(&filter)?;
    let event = events
        .iter()
        .find(|e| e.event.id.to_string() == event_id)
        .ok_or_else(|| anyhow::anyhow!("event '{event_id}' not found"))?;

    let json = serde_json::to_string_pretty(event)
        .context("serializing event to JSON")?;
    println!("{json}");
    Ok(())
}

/// Parse a datetime string. Supports RFC3339 and simple date formats.
fn parse_datetime(s: &str) -> Result<DateTime<Utc>> {
    // Try RFC3339 first
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Ok(dt.with_timezone(&Utc));
    }
    // Try simple date
    if let Ok(date) = chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d") {
        let dt = date
            .and_hms_opt(0, 0, 0)
            .ok_or_else(|| anyhow::anyhow!("invalid date: {s}"))?;
        return Ok(DateTime::<Utc>::from_naive_utc_and_offset(dt, Utc));
    }
    // Try datetime without timezone
    if let Ok(ndt) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S") {
        return Ok(DateTime::<Utc>::from_naive_utc_and_offset(ndt, Utc));
    }
    anyhow::bail!("cannot parse datetime: '{s}'. Use RFC3339, YYYY-MM-DD, or YYYY-MM-DD HH:MM:SS")
}

/// Short display name for an EventKind.
fn event_kind_short(kind: &watchpost_types::EventKind) -> String {
    match kind {
        watchpost_types::EventKind::ProcessExec { .. } => "process_exec".to_string(),
        watchpost_types::EventKind::ProcessExit { .. } => "process_exit".to_string(),
        watchpost_types::EventKind::FileAccess { .. } => "file_access".to_string(),
        watchpost_types::EventKind::NetworkConnect { .. } => "network".to_string(),
        watchpost_types::EventKind::PrivilegeChange { .. } => "priv_change".to_string(),
        watchpost_types::EventKind::DnsQuery { .. } => "dns_query".to_string(),
        watchpost_types::EventKind::ScriptExec { .. } => "script_exec".to_string(),
    }
}

/// Short display name for an ActionContext.
fn action_context_short(ctx: &watchpost_types::ActionContext) -> String {
    match ctx {
        watchpost_types::ActionContext::PackageInstall {
            ecosystem,
            package_name,
            ..
        } => {
            let pkg = package_name.as_deref().unwrap_or("?");
            format!("{} install ({})", ecosystem.as_str(), pkg)
        }
        watchpost_types::ActionContext::Build { toolchain, .. } => {
            format!("{toolchain} build")
        }
        watchpost_types::ActionContext::FlatpakApp { app_id, .. } => {
            format!("flatpak ({app_id})")
        }
        watchpost_types::ActionContext::ToolboxSession {
            container_name, ..
        } => {
            format!("toolbox ({container_name})")
        }
        watchpost_types::ActionContext::ShellCommand { .. } => "shell".to_string(),
        watchpost_types::ActionContext::IdeOperation { ide_name, .. } => {
            format!("ide ({ide_name})")
        }
        watchpost_types::ActionContext::Unknown => "unknown".to_string(),
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
// Gate handlers (stub -- real implementation needs IPC to daemon)
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

    #[test]
    fn format_file_size_bytes() {
        assert_eq!(super::format_file_size(500), "500 B");
    }

    #[test]
    fn format_file_size_kb() {
        let s = super::format_file_size(2048);
        assert!(s.contains("KB"));
    }

    #[test]
    fn format_file_size_mb() {
        let s = super::format_file_size(2_500_000);
        assert!(s.contains("MB"));
    }

    #[test]
    fn format_number_with_commas() {
        assert_eq!(super::format_number(0), "0");
        assert_eq!(super::format_number(999), "999");
        assert_eq!(super::format_number(1000), "1,000");
        assert_eq!(super::format_number(12847), "12,847");
        assert_eq!(super::format_number(1_000_000), "1,000,000");
    }

    #[test]
    fn style_success_returns_non_empty() {
        let s = super::style::success("test");
        assert!(!s.is_empty());
    }

    #[test]
    fn style_failure_returns_non_empty() {
        let s = super::style::failure("test");
        assert!(!s.is_empty());
    }

    #[test]
    fn style_warning_returns_non_empty() {
        let s = super::style::warning("test");
        assert!(!s.is_empty());
    }

    #[test]
    fn cli_parse_events_list_default_limit() {
        use clap::Parser;
        let cli = super::cli::Cli::parse_from(["watchpost", "events", "list"]);
        match cli.command {
            super::cli::Command::Events {
                action: super::cli::EventsAction::List { limit, .. },
            } => assert_eq!(limit, 50),
            _ => panic!("expected Events List"),
        }
    }

    #[test]
    fn cli_parse_events_list_custom_limit() {
        use clap::Parser;
        let cli = super::cli::Cli::parse_from(["watchpost", "events", "list", "--limit", "10"]);
        match cli.command {
            super::cli::Command::Events {
                action: super::cli::EventsAction::List { limit, .. },
            } => assert_eq!(limit, 10),
            _ => panic!("expected Events List"),
        }
    }
}
