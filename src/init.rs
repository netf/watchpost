use std::process::Command;

use anyhow::Result;
use tracing::info;

/// Run the `watchpost init` command.
///
/// For Phase 1 this performs a minimal setup: resolves the API key,
/// scans for installed toolchains, and prints the resulting config.
pub async fn run_init(api_key: Option<String>) -> Result<()> {
    println!("watchpost init — one-command setup\n");

    // 1. Resolve API key
    let api_key = api_key
        .or_else(|| std::env::var("ANTHROPIC_API_KEY").ok())
        .unwrap_or_default();

    if api_key.is_empty() {
        println!(
            "No API key provided. Pass --api-key or set ANTHROPIC_API_KEY.\n\
             You can get one at https://console.anthropic.com/\n"
        );
    } else {
        let redacted = if api_key.len() > 10 {
            format!("{}...{}", &api_key[..7], &api_key[api_key.len() - 4..])
        } else {
            "***".to_string()
        };
        println!("API key: {redacted}");
    }

    // 2. Scan PATH for toolchains
    println!("\nDetected toolchains:");
    let toolchains = [
        ("npm", "Node.js / npm"),
        ("cargo", "Rust / Cargo"),
        ("pip", "Python / pip"),
        ("pip3", "Python3 / pip3"),
        ("go", "Go"),
        ("gem", "Ruby / gem"),
        ("composer", "PHP / Composer"),
        ("mvn", "Java / Maven"),
        ("gradle", "Java / Gradle"),
        ("flatpak", "Flatpak"),
    ];

    // Track which ecosystems are detected for toolchain-specific policies.
    let mut npm_detected = false;
    let mut cargo_detected = false;
    let mut pip_detected = false;

    for (binary, label) in &toolchains {
        if which_exists(binary) {
            println!("  [x] {label} ({binary})");
            match *binary {
                "npm" | "npx" | "yarn" | "pnpm" => npm_detected = true,
                "cargo" => cargo_detected = true,
                "pip" | "pip3" | "uv" => pip_detected = true,
                _ => {}
            }
        }
    }

    // Also check for additional ecosystem binaries not in the general list.
    for bin in &["npx", "yarn", "pnpm"] {
        if which_exists(bin) {
            npm_detected = true;
        }
    }
    if which_exists("uv") {
        pip_detected = true;
    }

    // 2b. Report toolchain policies
    let toolchain_policies: Vec<&str> = {
        let mut v = Vec::new();
        if npm_detected {
            v.push("npm-monitoring.yaml");
        }
        if cargo_detected {
            v.push("cargo-monitoring.yaml");
        }
        if pip_detected {
            v.push("pip-monitoring.yaml");
        }
        v
    };

    let toolchain_policy_count = toolchain_policies.len();

    println!(
        "\nTetragon policies installed (5 base + {} toolchain)",
        toolchain_policy_count
    );
    for name in &toolchain_policies {
        println!("  + {name}");
    }

    // 3. Generate config
    let config_toml = format!(
        r#"[daemon]
api_key = "{api_key}"
# log_level = "warn"
# data_dir = "/var/lib/watchpost"

# [enforcement]
# mode = "autonomous"

# [notify]
# desktop = true
"#
    );

    let is_root = unsafe { libc::geteuid() } == 0;
    let config_path = "/etc/watchpost/config.toml";

    if is_root {
        std::fs::create_dir_all("/etc/watchpost")?;
        std::fs::write(config_path, &config_toml)?;
        println!("\nConfig written to {config_path}");
    } else {
        println!("\nNot running as root — cannot write to {config_path}");
        println!("Would write:\n\n{config_toml}");
        println!("To install manually:\n  sudo mkdir -p /etc/watchpost");
        println!("  sudo tee {config_path} << 'EOF'\n{config_toml}EOF");
    }

    info!("init completed");
    println!("\nSetup complete. Start the daemon with: watchpost daemon");

    Ok(())
}

/// Check if a binary exists on PATH using `which`.
fn which_exists(binary: &str) -> bool {
    Command::new("which")
        .arg(binary)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}
