use serde::{Deserialize, Serialize};

/// Known package manager ecosystems.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Ecosystem {
    Npm,
    Cargo,
    Pip,
}

impl Ecosystem {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Npm => "npm",
            Self::Cargo => "cargo",
            Self::Pip => "pip",
        }
    }
}

/// The inferred context for why an action is happening on the system.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ActionContext {
    PackageInstall {
        ecosystem: Ecosystem,
        package_name: Option<String>,
        package_version: Option<String>,
        working_dir: String,
    },
    Build {
        toolchain: String,
        working_dir: String,
    },
    FlatpakApp {
        app_id: String,
        permissions: Vec<String>,
    },
    ToolboxSession {
        container_name: String,
        image: String,
    },
    ShellCommand {
        tty: Option<String>,
    },
    IdeOperation {
        ide_name: String,
    },
    Unknown,
}
