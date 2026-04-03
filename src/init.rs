use std::process::Command;
use std::time::Duration;

use anyhow::{Context, Result};
use console::{style, Term};
use indicatif::{ProgressBar, ProgressStyle};
use watchpost_types::PolicyTemplate;

use crate::style as st;

/// Run the `watchpost init` command.
pub async fn run_init(api_key: Option<String>, template: Option<String>) -> Result<()> {
    let term = Term::stdout();

    term.write_line(&st::header("Watchpost — eBPF-powered desktop security"))?;
    term.write_line("")?;

    // 1. Resolve API key
    let api_key = resolve_api_key(api_key, &term)?;

    match &api_key {
        Some(key) => {
            let redacted = if key.len() > 10 {
                format!("{}...{}", &key[..7], &key[key.len() - 4..])
            } else {
                "***".to_string()
            };
            term.write_line(&st::success(&format!(
                "API key: {}",
                style(&redacted).dim()
            )))?;
        }
        None => {
            term.write_line(&st::warning(
                "API key: not set (pass --api-key or set ANTHROPIC_API_KEY)",
            ))?;
        }
    }

    // 2. Detect installed toolchains with a spinner
    term.write_line(&st::header("Scanning toolchains..."))?;

    let spinner = ProgressBar::new_spinner();
    spinner.set_style(
        ProgressStyle::default_spinner()
            .tick_chars("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏ ")
            .template("    {spinner} {msg}")
            .expect("valid spinner template"),
    );
    spinner.enable_steady_tick(Duration::from_millis(80));

    let toolchains: &[(&str, &[&str])] = &[
        ("npm", &["npm", "npx", "yarn", "pnpm"]),
        ("cargo", &["cargo"]),
        ("pip", &["pip3", "pip", "uv", "pipx"]),
        ("flatpak", &["flatpak"]),
    ];

    let mut ecosystems: Vec<(&str, &str)> = Vec::new();
    let mut not_found: Vec<&str> = Vec::new();

    for (eco, bins) in toolchains {
        spinner.set_message(format!("checking {eco}..."));
        if let Some(bin) = which_any(bins) {
            ecosystems.push((eco, bin));
        } else {
            not_found.push(eco);
        }
    }

    spinner.finish_and_clear();

    for (eco, bin) in &ecosystems {
        term.write_line(&st::success(&format!(
            "{:<10} {}",
            eco,
            style(format!("(via {bin})")).dim()
        )))?;
    }
    for eco in &not_found {
        term.write_line(&st::failure(&format!(
            "{:<10} {}",
            eco,
            style("(not found)").dim()
        )))?;
    }

    // 3. Determine policies
    let policy_list: Vec<String> = if let Some(ref template_name) = template {
        let tpl = load_template(template_name)?;
        term.write_line(&format!(
            "\n  {} {} {}",
            style(tpl.policies.len()).bold(),
            "policies from template",
            style(&tpl.name).bold()
        ))?;
        tpl.policies
    } else {
        let mut policies: Vec<String> = vec![
            "immutability.yaml".into(),
            "sensitive-files.yaml".into(),
            "priv-escalation.yaml".into(),
            "tmp-execution.yaml".into(),
            "install-script-gate.yaml".into(),
        ];
        for (eco, _) in &ecosystems {
            match *eco {
                "npm" => policies.push("npm-monitoring.yaml".into()),
                "cargo" => policies.push("cargo-monitoring.yaml".into()),
                "pip" => policies.push("pip-monitoring.yaml".into()),
                _ => {}
            }
        }
        let toolchain_count = policies.len() - 5;
        term.write_line(&format!(
            "\n  {} policies selected ({} base + {} toolchain)",
            style(policies.len()).bold(),
            5,
            toolchain_count
        ))?;
        policies
    };

    // 4. Generate config
    let key_str = api_key.as_deref().unwrap_or("");
    let config_toml = format!(
        r#"[daemon]
api_key = "{key_str}"

[enforcement]
mode = "autonomous"

[notify]
desktop = true
"#
    );

    // 5. Install
    let is_root = unsafe { libc::geteuid() } == 0;
    let config_path = "/etc/watchpost/config.toml";
    let policy_dir = "/etc/tetragon/tetragon.tp.d";

    term.write_line("")?;
    if is_root {
        std::fs::create_dir_all("/etc/watchpost")?;
        std::fs::write(config_path, &config_toml)?;
        term.write_line(&st::success(&format!("Config written to {config_path}")))?;

        std::fs::create_dir_all(policy_dir)?;
        let policies_src = find_policies_dir();
        let mut installed = 0;
        for name in &policy_list {
            let src = policies_src.join(name);
            let dst = std::path::Path::new(policy_dir).join(name);
            if src.exists() {
                std::fs::copy(&src, &dst)?;
                installed += 1;
            }
        }
        term.write_line(&st::success(&format!(
            "{installed} policies installed to {policy_dir}"
        )))?;

        if api_key.is_some() {
            term.write_line(&format!(
                "\n  {} Start the daemon with:",
                style("Ready!").green().bold()
            ))?;
            term.write_line(&st::hint("sudo systemctl start watchpost"))?;
        } else {
            term.write_line(&st::warning("Almost ready -- add your API key:"))?;
            term.write_line(&st::hint(&format!("sudo nano {config_path}")))?;
            term.write_line(&format!(
                "    {}",
                style("Then start the daemon:").dim()
            ))?;
            term.write_line(&st::hint("sudo systemctl start watchpost"))?;
        }
    } else {
        term.write_line(&st::warning("Not running as root. Run with sudo to install:"))?;
        term.write_line(&st::hint(&format!(
            "sudo watchpost init{}{}",
            api_key
                .as_ref()
                .map(|_| " --api-key <key>")
                .unwrap_or(""),
            template
                .as_ref()
                .map(|t| format!(" --template {t}"))
                .unwrap_or_default(),
        )))?;
    }

    term.write_line("")?;
    Ok(())
}

/// Resolve the API key: CLI flag > env var > interactive prompt (if TTY).
fn resolve_api_key(api_key: Option<String>, term: &Term) -> Result<Option<String>> {
    if let Some(key) = api_key {
        return Ok(Some(key));
    }

    if let Ok(key) = std::env::var("ANTHROPIC_API_KEY") {
        if !key.is_empty() {
            return Ok(Some(key));
        }
    }

    // Only prompt interactively if we have a real terminal
    if term.is_term() {
        let key: String = dialoguer::Password::new()
            .with_prompt("  Anthropic API key")
            .interact()
            .context("reading API key from terminal")?;
        if key.is_empty() {
            return Ok(None);
        }
        return Ok(Some(key));
    }

    Ok(None)
}

/// Load a policy template by name from the `templates/` directory.
fn load_template(name: &str) -> Result<PolicyTemplate> {
    let filename = format!("{name}.yaml");

    let candidates = [
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("templates")
            .join(&filename),
        std::path::PathBuf::from("templates").join(&filename),
    ];

    for path in &candidates {
        if path.exists() {
            let contents = std::fs::read_to_string(path)
                .with_context(|| format!("reading template: {}", path.display()))?;
            let tpl: PolicyTemplate = serde_yml::from_str(&contents)
                .with_context(|| format!("parsing template: {}", path.display()))?;
            return Ok(tpl);
        }
    }

    // List available templates
    let template_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("templates");
    let mut available = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&template_dir) {
        for entry in entries.flatten() {
            if let Some(name) = entry.path().file_stem().and_then(|s| s.to_str()) {
                available.push(name.to_string());
            }
        }
    }
    available.sort();

    anyhow::bail!(
        "template '{}' not found. Available: {}",
        name,
        if available.is_empty() {
            "(none)".to_string()
        } else {
            available.join(", ")
        }
    );
}

/// Find the `policies/` directory (shipped with the binary).
fn find_policies_dir() -> std::path::PathBuf {
    let candidates = [
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("policies"),
        std::path::PathBuf::from("policies"),
    ];
    for path in &candidates {
        if path.is_dir() {
            return path.clone();
        }
    }
    std::path::PathBuf::from("policies")
}

/// Return the first binary name from the list that exists on PATH.
fn which_any<'a>(binaries: &[&'a str]) -> Option<&'a str> {
    binaries.iter().find(|b| which_exists(b)).copied()
}

/// Check if a binary exists on PATH.
fn which_exists(binary: &str) -> bool {
    Command::new("which")
        .arg(binary)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}
