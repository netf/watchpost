use std::process::Command;

use anyhow::{Context, Result};
use watchpost_types::PolicyTemplate;

/// Run the `watchpost init` command.
pub async fn run_init(api_key: Option<String>, template: Option<String>) -> Result<()> {
    println!("Watchpost — eBPF-powered desktop security\n");

    // 1. Resolve API key
    let api_key = api_key.or_else(|| std::env::var("ANTHROPIC_API_KEY").ok());

    match &api_key {
        Some(key) => {
            let redacted = if key.len() > 10 {
                format!("{}...{}", &key[..7], &key[key.len() - 4..])
            } else {
                "***".to_string()
            };
            println!("  API key: {redacted}");
        }
        None => {
            println!("  API key: not set (pass --api-key or set ANTHROPIC_API_KEY)");
        }
    }

    // 2. Detect installed toolchains
    let mut ecosystems: Vec<(&str, &str)> = Vec::new(); // (ecosystem_id, display_name)

    let npm = which_any(&["npm", "npx", "yarn", "pnpm"]);
    let cargo = which_any(&["cargo"]);
    let pip = which_any(&["pip3", "pip", "uv", "pipx"]);
    let flatpak = which_any(&["flatpak"]);

    if let Some(bin) = npm {
        ecosystems.push(("npm", bin));
    }
    if let Some(bin) = cargo {
        ecosystems.push(("cargo", bin));
    }
    if let Some(bin) = pip {
        ecosystems.push(("pip", bin));
    }
    if let Some(bin) = flatpak {
        ecosystems.push(("flatpak", bin));
    }

    println!("\n  Toolchains:");
    if ecosystems.is_empty() {
        println!("    (none detected)");
    } else {
        for (eco, bin) in &ecosystems {
            println!("    {eco:<10} found ({bin})");
        }
    }

    // 3. Determine policies
    let policy_list: Vec<String> = if let Some(ref template_name) = template {
        let tpl = load_template(template_name)?;
        println!(
            "\n  Template: {} ({} policies)",
            tpl.name,
            tpl.policies.len()
        );
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
        println!(
            "\n  Policies: {} base + {} toolchain = {} total",
            5,
            policies.len() - 5,
            policies.len()
        );
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

    println!();
    if is_root {
        // Actually write config and copy policies
        std::fs::create_dir_all("/etc/watchpost")?;
        std::fs::write(config_path, &config_toml)?;
        println!("  Config written to {config_path}");

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
        println!("  {installed} policies installed to {policy_dir}");

        if api_key.is_some() {
            println!("\n  Ready! Start the daemon with:\n    sudo systemctl start watchpost");
        } else {
            println!("\n  Almost ready — add your API key:");
            println!("    sudo nano {config_path}");
            println!("  Then start the daemon:");
            println!("    sudo systemctl start watchpost");
        }
    } else {
        // Print instructions for manual setup
        println!("  Not running as root. To complete setup:\n");
        println!("    sudo mkdir -p /etc/watchpost");
        println!("    sudo mkdir -p {policy_dir}");
        println!("    sudo watchpost init{}{}",
            api_key.as_ref().map(|k| format!(" --api-key {k}")).unwrap_or_default(),
            template.as_ref().map(|t| format!(" --template {t}")).unwrap_or_default(),
        );
        println!();
        println!("  Or manually write the config:");
        println!("    sudo tee {config_path} << 'EOF'");
        print!("{config_toml}");
        println!("EOF");
    }

    Ok(())
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
    // Fallback — caller will handle missing files
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
