use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "watchpost", version, about = "eBPF-powered desktop security agent")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// One-command setup
    Init {
        #[arg(long)]
        api_key: Option<String>,
    },
    /// Start the daemon (for systemd)
    Daemon {
        #[arg(long, default_value = "/etc/watchpost/config.toml")]
        config: String,
    },
    /// Show daemon status
    Status,
    /// Query the event log
    Events {
        #[command(subcommand)]
        action: EventsAction,
    },
}

#[derive(Subcommand)]
pub enum EventsAction {
    /// List events with filters
    List {
        #[arg(long)]
        since: Option<String>,
        #[arg(long)]
        until: Option<String>,
        #[arg(long)]
        severity: Option<String>,
        #[arg(long)]
        classification: Option<String>,
        #[arg(long)]
        binary: Option<String>,
        #[arg(long)]
        context: Option<String>,
        #[arg(long, default_value = "table")]
        format: String,
    },
    /// Show details of a single event
    Show {
        event_id: String,
    },
}
