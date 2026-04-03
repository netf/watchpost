use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use tokio::sync::mpsc;
use tracing::{error, info, warn};
use watchpost_types::{AnalyzerBackend, CorrelatedTrace, LogLevel, Verdict, WatchpostConfig};

use watchpost_analyzer::backend::LlmBackend;
use watchpost_analyzer::client::AnthropicClient;
use watchpost_analyzer::ollama::OllamaClient;
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

    let engine = Engine::with_data_dir(&config.advanced.engine, profiles, &data_dir)
        .context("failed to create engine with persistent store")?;
    info!("engine started with persistent correlation window");

    let rule_engine = RuleEngine::new(rules);

    let llm_backend: Box<dyn LlmBackend> = match config.advanced.analyzer.backend {
        AnalyzerBackend::Anthropic => {
            let api_key = if config.daemon.api_key.is_empty() {
                std::env::var("ANTHROPIC_API_KEY").unwrap_or_default()
            } else {
                config.daemon.api_key.clone()
            };
            Box::new(AnthropicClient::new(
                api_key,
                config.advanced.analyzer.model.clone(),
            ))
        }
        AnalyzerBackend::Ollama => {
            let endpoint = config
                .advanced
                .analyzer
                .ollama_endpoint
                .clone()
                .unwrap_or_else(|| "http://127.0.0.1:11434".to_string());
            let model = config
                .advanced
                .analyzer
                .ollama_model
                .clone()
                .unwrap_or_else(|| "llama3.1:8b".to_string());
            Box::new(OllamaClient::new(endpoint, model))
        }
    };

    let analyzer = Analyzer::new(
        llm_backend,
        skill,
        config.advanced.analyzer.max_tool_calls,
        config.advanced.analyzer.max_analyses_per_minute,
        config.advanced.analyzer.analysis_queue_size,
    );

    let webhook_url = config.notify.webhook_url.clone();
    let webhook_auth_header = config.notify.webhook_auth_header.clone();
    let notifier = Notifier::new(config.notify.desktop, &db_path, webhook_url, webhook_auth_header)
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
    // Wait for SIGINT (Ctrl+C) or SIGTERM
    tokio::signal::ctrl_c().await.ok();
    info!("received shutdown signal, stopping...");

    // Abort all spawned tasks so their channel senders drop,
    // which unblocks downstream receivers and the notifier thread.
    collector_handle.abort();
    engine_handle.abort();
    rules_handle.abort();
    analyzer_handle.abort();
    merger_handle.abort();

    // The notifier runs on a dedicated OS thread; it stops when
    // its input channels close (which happens when the tasks above are aborted).
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
            if let Err(e) = tx.try_send(verdict) {
                tracing::warn!("rules verdict channel full or closed: {e}");
            }
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
                Some(v) => {
                    if merged_tx.send(v).await.is_err() {
                        tracing::debug!("verdict merge channel closed");
                        break;
                    }
                }
                None => break,
            },
            verdict = analyzer_rx.recv() => match verdict {
                Some(v) => {
                    if merged_tx.send(v).await.is_err() {
                        tracing::debug!("verdict merge channel closed");
                        break;
                    }
                }
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
