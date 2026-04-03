use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "watchpost", version, about = "eBPF-powered desktop security agent")]
pub struct Cli {
    /// Path to config file
    #[arg(long, global = true, default_value = "/etc/watchpost/config.toml")]
    pub config: String,

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
    Daemon,
    /// Show daemon status
    Status,
    /// Query the event log
    Events {
        #[command(subcommand)]
        action: EventsAction,
    },
    /// Manage TracingPolicies
    Policy {
        #[command(subcommand)]
        action: PolicyAction,
    },
    /// Manage the dynamic allowlist
    Allowlist {
        #[command(subcommand)]
        action: AllowlistAction,
    },
    /// Manage the pre-execution gate
    Gate {
        #[command(subcommand)]
        action: GateAction,
    },
    /// Launch the terminal UI dashboard
    Tui,
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

#[derive(Subcommand)]
pub enum PolicyAction {
    /// List all TracingPolicies
    List,
    /// Show details of a specific policy
    Show { name: String },
    /// Approve a staged reactive policy
    Approve { name: String },
    /// Revoke an active reactive policy
    Revoke { name: String },
}

#[derive(Subcommand)]
pub enum AllowlistAction {
    /// List all allowlist entries
    List,
    /// Remove an allowlist entry by ID
    Remove { id: i64 },
    /// Reset (clear) all allowlist entries
    Reset,
}

#[derive(Subcommand)]
pub enum GateAction {
    /// Allow a specific package + script hash
    Allow {
        package: String,
        hash: String,
    },
    /// Block a specific package
    Block {
        package: String,
    },
}
