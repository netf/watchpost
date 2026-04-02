use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use tokio::sync::mpsc;
use tracing::{error, info, warn};
use watchpost_types::{CorrelatedTrace, LogLevel, Verdict, WatchpostConfig};

use watchpost_analyzer::client::AnthropicClient;
use watchpost_analyzer::skill::SkillSpec;
use watchpost_analyzer::Analyzer;
use watchpost_collector::Collector;
use watchpost_engine::profiles::BehaviorProfileStore;
use watchpost_engine::Engine;
use watchpost_notify::Notifier;
use watchpost_rules::{load_rules_from_dir, RuleEngine};

/// Run the watchpost daemon, wiring all crates together.
pub async fn run_daemon(config: WatchpostConfig) -> Result<()> {
    // ---------------------------------------------------------------
    // 1. Initialize tracing
    // ---------------------------------------------------------------
    let filter = match config.daemon.log_level {
        LogLevel::Trace => "trace",
        LogLevel::Debug => "debug",
        LogLevel::Info => "info",
        LogLevel::Warn => "warn",
        LogLevel::Error => "error",
    };

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .init();

    info!("watchpost daemon starting");

    // ---------------------------------------------------------------
    // 2. Open SQLite event log
    // ---------------------------------------------------------------
    let data_dir = PathBuf::from(&config.daemon.data_dir);
    std::fs::create_dir_all(&data_dir)
        .with_context(|| format!("creating data dir: {}", data_dir.display()))?;
    let db_path = data_dir.join("events.db");

    // ---------------------------------------------------------------
    // 3. Load behavior profiles
    // ---------------------------------------------------------------
    let profiles_dir = PathBuf::from(&config.advanced.profiles.path);
    let profiles = if profiles_dir.is_dir() {
        match BehaviorProfileStore::load_dir(&profiles_dir) {
            Ok(p) => {
                info!(dir = %profiles_dir.display(), "behavior profiles loaded");
                p
            }
            Err(e) => {
                warn!(error = %e, "failed to load behavior profiles, using empty set");
                BehaviorProfileStore::new()
            }
        }
    } else {
        info!(
            dir = %profiles_dir.display(),
            "profiles directory not found, using empty set"
        );
        BehaviorProfileStore::new()
    };

    // ---------------------------------------------------------------
    // 4. Load rules
    // ---------------------------------------------------------------
    let rules_dir = PathBuf::from(&config.advanced.rules.path);
    let rules = if rules_dir.is_dir() {
        load_rules_from_dir(&rules_dir)
            .with_context(|| format!("loading rules from {}", rules_dir.display()))?
    } else {
        warn!(
            dir = %rules_dir.display(),
            "rules directory not found, using empty ruleset"
        );
        Vec::new()
    };
    info!(count = rules.len(), "rules loaded");

    // ---------------------------------------------------------------
    // 5. Load analyzer skill
    // ---------------------------------------------------------------
    let skill_path = find_skill_path();
    let skill = SkillSpec::load(&skill_path)
        .with_context(|| format!("loading analyzer skill from {}", skill_path.display()))?;
    info!(skill = %skill.name, "analyzer skill loaded");

    // ---------------------------------------------------------------
    // 6. Create channels
    // ---------------------------------------------------------------
    let (collector_tx, collector_rx) =
        mpsc::channel(config.advanced.collector.event_channel_buffer);
    let (rules_tx, rules_rx) = mpsc::channel(256);
    let (analyzer_tx, analyzer_rx) = mpsc::channel(256);
    let (log_tx, log_rx) = mpsc::channel(1024);
    let (rules_verdict_tx, rules_verdict_rx) = mpsc::channel(64);
    let (analyzer_verdict_tx, analyzer_verdict_rx) = mpsc::channel(64);
    let (merged_verdict_tx, merged_verdict_rx) = mpsc::channel(128);

    // ---------------------------------------------------------------
    // 7. Create components
    // ---------------------------------------------------------------
    let collector = Collector::new(
        &config.advanced.tetragon.endpoint,
        &config.advanced.collector,
    )
    .await
    .context("failed to create Collector")?;

    let engine = Engine::new(&config.advanced.engine, profiles);

    let rule_engine = RuleEngine::new(rules);

    let api_key = if config.daemon.api_key.is_empty() {
        std::env::var("ANTHROPIC_API_KEY").unwrap_or_default()
    } else {
        config.daemon.api_key.clone()
    };

    let anthropic_client =
        AnthropicClient::new(api_key, config.advanced.analyzer.model.clone());

    let analyzer = Analyzer::new(
        anthropic_client,
        skill,
        config.advanced.analyzer.max_tool_calls,
        config.advanced.analyzer.max_analyses_per_minute,
        config.advanced.analyzer.analysis_queue_size,
    );

    let notifier = Notifier::new(config.notify.desktop, &db_path)
        .context("failed to create Notifier")?;

    // ---------------------------------------------------------------
    // 8. Spawn tokio tasks
    // ---------------------------------------------------------------
    let collector_handle = tokio::spawn(async move {
        if let Err(e) = collector.run(collector_tx).await {
            error!(error = %e, "collector task failed");
        }
    });

    let engine_handle = tokio::spawn(async move {
        if let Err(e) = engine.run(collector_rx, rules_tx, analyzer_tx, log_tx).await {
            error!(error = %e, "engine task failed");
        }
    });

    let rules_handle = tokio::spawn(async move {
        if let Err(e) = run_rules_loop(rule_engine, rules_rx, rules_verdict_tx).await {
            error!(error = %e, "rules task failed");
        }
    });

    let analyzer_handle = tokio::spawn(async move {
        if let Err(e) = analyzer.run(analyzer_rx, analyzer_verdict_tx).await {
            error!(error = %e, "analyzer task failed");
        }
    });

    let merger_handle = tokio::spawn(async move {
        if let Err(e) =
            merge_verdicts(rules_verdict_rx, analyzer_verdict_rx, merged_verdict_tx).await
        {
            error!(error = %e, "verdict merger task failed");
        }
    });

    // The Notifier contains rusqlite::Connection which is !Sync, so we
    // cannot spawn it on the multi-threaded runtime directly. Instead, run
    // it on a dedicated thread with a single-threaded tokio runtime.
    let notifier_handle = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("failed to build notifier runtime");
        rt.block_on(async move {
            if let Err(e) = notifier.run(merged_verdict_rx, log_rx).await {
                error!(error = %e, "notifier task failed");
            }
        });
    });

    // ---------------------------------------------------------------
    // 9. sd_notify: tell systemd we are ready
    // ---------------------------------------------------------------
    let _ = sd_notify::notify(false, &[sd_notify::NotifyState::Ready]);
    info!("daemon ready");

    // ---------------------------------------------------------------
    // 10. Wait for shutdown (SIGTERM / SIGINT / task failure)
    // ---------------------------------------------------------------
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            info!("received SIGINT, shutting down");
        }
        _ = collector_handle => {
            warn!("collector task exited");
        }
        _ = engine_handle => {
            warn!("engine task exited");
        }
        _ = rules_handle => {
            warn!("rules task exited");
        }
        _ = analyzer_handle => {
            warn!("analyzer task exited");
        }
        _ = merger_handle => {
            warn!("verdict merger task exited");
        }
    }

    // The notifier runs on a dedicated OS thread; it will stop when
    // channels are dropped above.
    let _ = notifier_handle.join();

    info!("watchpost daemon stopped");
    Ok(())
}

/// Run the deterministic rules loop in an async task.
async fn run_rules_loop(
    engine: RuleEngine,
    mut rx: mpsc::Receiver<CorrelatedTrace>,
    tx: mpsc::Sender<Verdict>,
) -> Result<()> {
    while let Some(trace) = rx.recv().await {
        if let Some(verdict) = engine.evaluate(&trace) {
            let _ = tx.try_send(verdict);
        }
    }
    Ok(())
}

/// Merge two verdict channels (rules + analyzer) into a single channel
/// consumed by the Notifier.
async fn merge_verdicts(
    mut rules_rx: mpsc::Receiver<Verdict>,
    mut analyzer_rx: mpsc::Receiver<Verdict>,
    merged_tx: mpsc::Sender<Verdict>,
) -> Result<()> {
    loop {
        tokio::select! {
            verdict = rules_rx.recv() => match verdict {
                Some(v) => { let _ = merged_tx.send(v).await; }
                None => break,
            },
            verdict = analyzer_rx.recv() => match verdict {
                Some(v) => { let _ = merged_tx.send(v).await; }
                None => break,
            },
        }
    }
    Ok(())
}

/// Locate the `skills/analyzer.yaml` file.
///
/// Search order:
/// 1. Relative to the executable (`../skills/analyzer.yaml` — installed layout)
/// 2. Relative to the workspace root (development layout)
/// 3. Fallback to `/etc/watchpost/skills/analyzer.yaml`
fn find_skill_path() -> PathBuf {
    // Development / workspace layout
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"));
    let dev_path = workspace.join("skills/analyzer.yaml");
    if dev_path.exists() {
        return dev_path;
    }

    // Relative to the running executable
    if let Ok(exe) = std::env::current_exe() {
        if let Some(bin_dir) = exe.parent() {
            let installed = bin_dir.join("../share/watchpost/skills/analyzer.yaml");
            if installed.exists() {
                return installed;
            }
        }
    }

    // Fallback
    PathBuf::from("/etc/watchpost/skills/analyzer.yaml")
}
