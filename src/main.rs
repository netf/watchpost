mod cli;
mod daemon;
mod init;

use clap::Parser;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = cli::Cli::parse();

    match cli.command {
        cli::Command::Init { api_key } => init::run_init(api_key).await,
        cli::Command::Daemon { config } => {
            let config_str = std::fs::read_to_string(&config)?;
            let config: watchpost_types::WatchpostConfig = toml::from_str(&config_str)?;
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
    }
}

#[cfg(test)]
mod tests {
    use watchpost_types::WatchpostConfig;

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
}
