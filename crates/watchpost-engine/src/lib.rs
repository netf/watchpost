pub mod correlation;
pub mod feedback;
pub mod persistent;
pub mod profiles;
pub mod scoring;
pub mod tree;
pub mod triggers;
pub mod windows;

use std::path::Path;

use tracing::warn;
use watchpost_types::{ActionContext, CorrelatedTrace, EngineConfig, EnrichedEvent, EventKind};

use crate::correlation::ThreeSignalCorrelator;
use crate::profiles::BehaviorProfileStore;
use crate::scoring::HeuristicScorer;
use crate::tree::ProcessTree;
use crate::triggers::ActiveTriggerRegistry;

/// The main engine that receives enriched events, correlates them into traces,
/// scores each trace, and routes it to the appropriate output channel based on
/// the suspicion score.
pub struct Engine {
    correlator: ThreeSignalCorrelator,
    scorer: HeuristicScorer,
    fast_path_threshold: f64,
    llm_threshold: f64,
}

impl Engine {
    /// Create a new engine wired from its component parts.
    ///
    /// The engine takes ownership of the `BehaviorProfileStore` (via the scorer)
    /// and creates fresh `ProcessTree` and `ActiveTriggerRegistry` instances.
    /// No persistent store is created; use `with_data_dir` for persistence.
    pub fn new(config: &EngineConfig, profiles: BehaviorProfileStore) -> Self {
        let tree = ProcessTree::new();
        let triggers = ActiveTriggerRegistry::new();
        let correlator =
            ThreeSignalCorrelator::new(tree, triggers, config.immediate_window_ms);
        let scorer = if config.weight_overrides_path.is_empty() {
            HeuristicScorer::new(profiles)
        } else {
            HeuristicScorer::with_feedback(profiles, &config.weight_overrides_path)
        };

        Self {
            correlator,
            scorer,
            fast_path_threshold: config.fast_path_threshold,
            llm_threshold: config.llm_threshold,
        }
    }

    /// Create a new engine with a SQLite-backed persistent correlation window.
    ///
    /// The persistent store is created at `{data_dir}/persistent_triggers.db`.
    pub fn with_data_dir(
        config: &EngineConfig,
        profiles: BehaviorProfileStore,
        data_dir: &Path,
    ) -> anyhow::Result<Self> {
        let tree = ProcessTree::new();
        let triggers = ActiveTriggerRegistry::new();
        let db_path = data_dir.join("persistent_triggers.db");
        let correlator = ThreeSignalCorrelator::with_persistent_store(
            tree,
            triggers,
            config.immediate_window_ms,
            config.persistent_window_hours,
            &db_path,
        )?;
        let scorer = if config.weight_overrides_path.is_empty() {
            HeuristicScorer::new(profiles)
        } else {
            HeuristicScorer::with_feedback(profiles, &config.weight_overrides_path)
        };

        Ok(Self {
            correlator,
            scorer,
            fast_path_threshold: config.fast_path_threshold,
            llm_threshold: config.llm_threshold,
        })
    }

    /// Run the engine event loop until the input channel closes.
    ///
    /// For each incoming event the engine:
    /// 1. Updates the process tree (insert on exec, remove on exit).
    /// 2. Registers triggers for tracked contexts (PackageInstall/Build/FlatpakApp).
    /// 3. Correlates the event against active triggers.
    /// 4. Scores the resulting trace.
    /// 5. Routes the trace to `rules_tx` (high), `analyzer_tx` (medium), or
    ///    `log_tx` (low) based on the score.
    pub async fn run(
        self,
        mut rx: tokio::sync::mpsc::Receiver<EnrichedEvent>,
        rules_tx: tokio::sync::mpsc::Sender<CorrelatedTrace>,
        analyzer_tx: tokio::sync::mpsc::Sender<CorrelatedTrace>,
        log_tx: tokio::sync::mpsc::Sender<CorrelatedTrace>,
    ) -> anyhow::Result<()> {
        while let Some(event) = rx.recv().await {
            // Step 1: Update process tree.
            match &event.event.kind {
                EventKind::ProcessExec {
                    binary, ..
                } => {
                    self.correlator.tree().insert(
                        event.event.process_id,
                        event.event.parent_id,
                        binary.clone(),
                        event.event.timestamp,
                    );
                }
                EventKind::ProcessExit { .. } => {
                    self.correlator.tree().remove(event.event.process_id);
                    self.correlator.deactivate_trigger(event.event.process_id);
                }
                _ => {}
            }

            // Step 2: Check if event is a trigger (tracked context + ProcessExec).
            if matches!(
                event.context,
                ActionContext::PackageInstall { .. }
                    | ActionContext::Build { .. }
                    | ActionContext::FlatpakApp { .. }
            ) && matches!(event.event.kind, EventKind::ProcessExec { .. })
            {
                self.correlator.register_trigger(&event);
            }

            // Step 3: Correlate.
            let Some(mut trace) = self.correlator.correlate(&event) else {
                continue;
            };

            // Step 4: Score.
            let breakdown = self.scorer.score(&trace);
            trace.score = Some(breakdown.final_score);

            // Step 5: Route based on score.
            let score_val = breakdown.final_score.value();

            if score_val >= self.fast_path_threshold {
                if let Err(e) = rules_tx.try_send(trace) {
                    warn!("rules channel full, dropping trace: {e}");
                }
            } else if score_val >= self.llm_threshold {
                if let Err(e) = analyzer_tx.try_send(trace) {
                    warn!("analyzer channel full, dropping trace: {e}");
                }
            } else if let Err(e) = log_tx.try_send(trace) {
                warn!("log channel full, dropping trace: {e}");
            }
        }

        Ok(())
    }

    /// Access the correlator (needed for tool execution in the analyzer).
    pub fn correlator(&self) -> &ThreeSignalCorrelator {
        &self.correlator
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use uuid::Uuid;
    use watchpost_types::{
        ActionContext, Ecosystem, EnrichedEvent, EventKind, FileAccessType, TetragonEvent,
    };

    /// Helper: build an `EnrichedEvent` with the specified parameters.
    fn make_enriched(
        pid: u32,
        parent_pid: Option<u32>,
        kind: EventKind,
        context: ActionContext,
        timestamp: chrono::DateTime<chrono::Utc>,
    ) -> EnrichedEvent {
        EnrichedEvent {
            event: TetragonEvent {
                id: Uuid::new_v4(),
                timestamp,
                kind,
                process_id: pid,
                parent_id: parent_pid,
                policy_name: None,
            },
            ancestry: vec![],
            context,
            provenance: None,
        }
    }

    fn npm_context() -> ActionContext {
        ActionContext::PackageInstall {
            ecosystem: Ecosystem::Npm,
            package_name: Some("evil-package".into()),
            package_version: Some("1.0.0".into()),
            working_dir: "/home/user/project".into(),
        }
    }

    fn cargo_build_context() -> ActionContext {
        ActionContext::Build {
            toolchain: "cargo".into(),
            working_dir: "/home/user/project".into(),
        }
    }

    fn shell_context() -> ActionContext {
        ActionContext::ShellCommand {
            tty: Some("/dev/pts/0".into()),
        }
    }

    fn default_engine() -> Engine {
        let config = EngineConfig::default();
        let profiles = BehaviorProfileStore::new();
        Engine::new(&config, profiles)
    }

    fn npm_profile() -> watchpost_types::BehaviorProfile {
        watchpost_types::BehaviorProfile {
            context_type: "package_install".into(),
            ecosystem: Some(Ecosystem::Npm),
            expected_network: vec![watchpost_types::NetworkExpectation {
                host: Some("registry.npmjs.org".into()),
                port: Some(443),
                description: "npm registry".into(),
            }],
            expected_children: vec!["node".into(), "sh".into()],
            expected_file_writes: vec!["node_modules/".into()],
            forbidden_file_access: vec![".ssh/".into(), ".gnupg/".into()],
            forbidden_children: vec!["nc".into()],
            forbidden_network: vec![],
        }
    }

    fn engine_with_npm_profile() -> Engine {
        let config = EngineConfig::default();
        let mut profiles = BehaviorProfileStore::new();
        profiles.insert("npm", npm_profile());
        Engine::new(&config, profiles)
    }

    // ------------------------------------------------------------------
    // Test 1: High-score routing
    // ------------------------------------------------------------------
    #[tokio::test]
    async fn high_score_routes_to_rules() {
        let engine = engine_with_npm_profile();

        let (tx, rx) = tokio::sync::mpsc::channel(16);
        let (rules_tx, mut rules_rx) = tokio::sync::mpsc::channel(16);
        let (analyzer_tx, mut analyzer_rx) = tokio::sync::mpsc::channel(16);
        let (log_tx, _log_rx) = tokio::sync::mpsc::channel(16);

        let now = Utc::now();

        // Insert the trigger process into the tree via a ProcessExec event.
        let trigger_event = make_enriched(
            100,
            None,
            EventKind::ProcessExec {
                binary: "/usr/bin/npm".into(),
                args: vec!["npm".into(), "install".into(), "evil-package".into()],
                cwd: "/home/user/project".into(),
                uid: 1000,
            },
            npm_context(),
            now,
        );

        // Network connect to evil.com (non-registry -> NonRegistryNetwork indicator)
        let net_event = make_enriched(
            200,
            Some(100),
            EventKind::NetworkConnect {
                dest_ip: "evil.com".into(),
                dest_port: 4444,
                protocol: "tcp".into(),
            },
            npm_context(),
            now + Duration::seconds(1),
        );

        // File access to .ssh/ (SensitiveFileRead indicator)
        let file_event = make_enriched(
            200,
            Some(100),
            EventKind::FileAccess {
                path: "/home/user/.ssh/id_rsa".into(),
                access_type: FileAccessType::Read,
            },
            npm_context(),
            now + Duration::seconds(2),
        );

        // Send all events
        tx.send(trigger_event).await.unwrap();
        tx.send(net_event).await.unwrap();
        tx.send(file_event).await.unwrap();
        drop(tx); // Close the channel so the engine loop terminates.

        // Run the engine.
        engine
            .run(rx, rules_tx, analyzer_tx, log_tx)
            .await
            .unwrap();

        // At least one trace should land on rules_tx (high score).
        let mut rules_traces = Vec::new();
        while let Ok(trace) = rules_rx.try_recv() {
            rules_traces.push(trace);
        }

        assert!(
            !rules_traces.is_empty(),
            "expected at least one high-score trace on rules channel"
        );

        // Verify the score is above fast_path_threshold (0.7).
        for trace in &rules_traces {
            let score = trace.score.as_ref().expect("trace should have a score");
            assert!(
                score.value() >= 0.7,
                "expected score >= 0.7, got {}",
                score.value()
            );
        }

        // Verify analyzer channel is empty (these events should not be medium).
        assert!(
            analyzer_rx.try_recv().is_err(),
            "analyzer channel should be empty for high-score traces"
        );
    }

    // ------------------------------------------------------------------
    // Test 2: Low-score routing
    // ------------------------------------------------------------------
    #[tokio::test]
    async fn low_score_routes_to_log() {
        let engine = default_engine();

        let (tx, rx) = tokio::sync::mpsc::channel(16);
        let (rules_tx, mut rules_rx) = tokio::sync::mpsc::channel(16);
        let (analyzer_tx, mut analyzer_rx) = tokio::sync::mpsc::channel(16);
        let (log_tx, mut log_rx) = tokio::sync::mpsc::channel(16);

        let now = Utc::now();

        // Register a cargo build trigger.
        let trigger_event = make_enriched(
            500,
            None,
            EventKind::ProcessExec {
                binary: "/usr/bin/cargo".into(),
                args: vec!["cargo".into(), "build".into()],
                cwd: "/home/user/project".into(),
                uid: 1000,
            },
            cargo_build_context(),
            now,
        );

        // A normal child process exec (rustc) -- no suspicious indicators.
        let child_event = make_enriched(
            501,
            Some(500),
            EventKind::ProcessExec {
                binary: "/usr/bin/rustc".into(),
                args: vec!["rustc".into(), "main.rs".into()],
                cwd: "/home/user/project".into(),
                uid: 1000,
            },
            cargo_build_context(),
            now + Duration::seconds(1),
        );

        tx.send(trigger_event).await.unwrap();
        tx.send(child_event).await.unwrap();
        drop(tx);

        engine
            .run(rx, rules_tx, analyzer_tx, log_tx)
            .await
            .unwrap();

        // The child event (rustc in a build context) should have 0 indicators,
        // so score = 0.0 which is < llm_threshold (0.3) -> goes to log.
        let mut log_traces = Vec::new();
        while let Ok(trace) = log_rx.try_recv() {
            log_traces.push(trace);
        }

        // The trigger event itself also gets correlated (against itself) and
        // should also be low-score. We expect at least one trace on log.
        assert!(
            !log_traces.is_empty(),
            "expected at least one low-score trace on log channel"
        );

        for trace in &log_traces {
            let score = trace.score.as_ref().expect("trace should have a score");
            assert!(
                score.value() < 0.3,
                "expected score < 0.3, got {}",
                score.value()
            );
        }

        // rules and analyzer should be empty.
        assert!(
            rules_rx.try_recv().is_err(),
            "rules channel should be empty"
        );
        assert!(
            analyzer_rx.try_recv().is_err(),
            "analyzer channel should be empty"
        );
    }

    // ------------------------------------------------------------------
    // Test 3: Process tree updated on exec/exit
    // ------------------------------------------------------------------
    #[tokio::test]
    async fn process_tree_updated_on_exec_exit() {
        let engine = default_engine();

        // Directly test tree updates through the correlator accessor.
        let now = Utc::now();

        let (tx, rx) = tokio::sync::mpsc::channel(16);
        let (rules_tx, _rules_rx) = tokio::sync::mpsc::channel(16);
        let (analyzer_tx, _analyzer_rx) = tokio::sync::mpsc::channel(16);
        let (log_tx, _log_rx) = tokio::sync::mpsc::channel(16);

        // We need to verify tree state, but run() takes ownership. So instead,
        // use the correlator directly to verify tree behavior.
        // Insert a ProcessExec event manually to simulate what the engine does.
        let tree = engine.correlator().tree();

        // Before: tree is empty.
        assert!(tree.get(1000).is_none(), "tree should be empty initially");

        // Simulate ProcessExec: insert into tree.
        tree.insert(1000, None, "/usr/bin/npm".into(), now);
        assert!(
            tree.get(1000).is_some(),
            "tree should have PID 1000 after insert"
        );

        // Simulate ProcessExit: remove from tree.
        tree.remove(1000);
        assert!(
            tree.get(1000).is_none(),
            "tree should not have PID 1000 after remove"
        );

        // Now verify through the actual run loop: send exec then exit.
        let exec_event = make_enriched(
            2000,
            None,
            EventKind::ProcessExec {
                binary: "/usr/bin/test".into(),
                args: vec![],
                cwd: "/tmp".into(),
                uid: 1000,
            },
            shell_context(),
            now,
        );

        let exit_event = make_enriched(
            2000,
            None,
            EventKind::ProcessExit {
                exit_code: 0,
                signal: None,
            },
            shell_context(),
            now + Duration::seconds(1),
        );

        tx.send(exec_event).await.unwrap();
        tx.send(exit_event).await.unwrap();
        drop(tx);

        // Run the engine (consumes self, so we can't check tree after).
        engine
            .run(rx, rules_tx, analyzer_tx, log_tx)
            .await
            .unwrap();
        // If we got here without panics, the tree operations succeeded.
    }

    // ------------------------------------------------------------------
    // Test 4: Medium-score routing to analyzer
    // ------------------------------------------------------------------
    #[tokio::test]
    async fn medium_score_routes_to_analyzer() {
        // Build an engine with npm profiles so we can get a medium score.
        // A single NonRegistryNetwork indicator in an npm context:
        //   0.4 * 1.5 = 0.6, which is >= 0.3 (llm_threshold) but < 0.7 (fast_path_threshold)
        let engine = engine_with_npm_profile();

        let (tx, rx) = tokio::sync::mpsc::channel(16);
        let (rules_tx, _rules_rx) = tokio::sync::mpsc::channel(16);
        let (analyzer_tx, mut analyzer_rx) = tokio::sync::mpsc::channel(16);
        let (log_tx, _log_rx) = tokio::sync::mpsc::channel(16);

        let now = Utc::now();

        // Trigger: npm install
        let trigger_event = make_enriched(
            300,
            None,
            EventKind::ProcessExec {
                binary: "/usr/bin/npm".into(),
                args: vec!["npm".into(), "install".into()],
                cwd: "/home/user/project".into(),
                uid: 1000,
            },
            npm_context(),
            now,
        );

        // A network connect to a non-registry host on port 443 (no C2 port).
        // This gives NonRegistryNetwork (0.4) * 1.5 (npm context) = 0.6
        let net_event = make_enriched(
            301,
            Some(300),
            EventKind::NetworkConnect {
                dest_ip: "suspicious.example.com".into(),
                dest_port: 443,
                protocol: "tcp".into(),
            },
            npm_context(),
            now + Duration::seconds(1),
        );

        tx.send(trigger_event).await.unwrap();
        tx.send(net_event).await.unwrap();
        drop(tx);

        engine
            .run(rx, rules_tx, analyzer_tx, log_tx)
            .await
            .unwrap();

        // The network event should produce a medium score -> analyzer.
        let mut analyzer_traces = Vec::new();
        while let Ok(trace) = analyzer_rx.try_recv() {
            analyzer_traces.push(trace);
        }

        assert!(
            !analyzer_traces.is_empty(),
            "expected at least one medium-score trace on analyzer channel"
        );

        for trace in &analyzer_traces {
            let score = trace.score.as_ref().expect("trace should have a score");
            assert!(
                score.value() >= 0.3 && score.value() < 0.7,
                "expected 0.3 <= score < 0.7, got {}",
                score.value()
            );
        }
    }

    // ------------------------------------------------------------------
    // Test 5: ProcessExit deactivates trigger
    // ------------------------------------------------------------------
    #[tokio::test]
    async fn process_exit_deactivates_trigger() {
        let engine = default_engine();

        let (tx, rx) = tokio::sync::mpsc::channel(16);
        let (rules_tx, _) = tokio::sync::mpsc::channel(16);
        let (analyzer_tx, _) = tokio::sync::mpsc::channel(16);
        let (log_tx, mut log_rx) = tokio::sync::mpsc::channel(16);

        let now = Utc::now();

        // Register a trigger via ProcessExec.
        let trigger_event = make_enriched(
            400,
            None,
            EventKind::ProcessExec {
                binary: "/usr/bin/npm".into(),
                args: vec!["npm".into(), "install".into()],
                cwd: "/tmp".into(),
                uid: 1000,
            },
            npm_context(),
            now,
        );

        // Exit the trigger process.
        let exit_event = make_enriched(
            400,
            None,
            EventKind::ProcessExit {
                exit_code: 0,
                signal: None,
            },
            npm_context(),
            now + Duration::seconds(1),
        );

        // A late event from another process well outside the immediate window.
        // With the trigger deactivated and no lineage, this should not correlate.
        let late_event = make_enriched(
            999,
            None,
            EventKind::ProcessExec {
                binary: "/usr/bin/curl".into(),
                args: vec!["curl".into(), "evil.com".into()],
                cwd: "/tmp".into(),
                uid: 1000,
            },
            shell_context(),
            now + Duration::seconds(60),
        );

        tx.send(trigger_event).await.unwrap();
        tx.send(exit_event).await.unwrap();
        tx.send(late_event).await.unwrap();
        drop(tx);

        engine
            .run(rx, rules_tx, analyzer_tx, log_tx)
            .await
            .unwrap();

        // The late event should NOT produce a trace (trigger deactivated, no
        // lineage, outside immediate window). Only the trigger's own initial
        // correlation may have landed here.
        let mut count = 0;
        while let Ok(_trace) = log_rx.try_recv() {
            count += 1;
        }

        // At most the trigger event itself might correlate. The late_event
        // should not, verifying deactivation worked.
        assert!(
            count <= 1,
            "expected at most 1 trace (trigger self-correlation), got {count}"
        );
    }

    // ------------------------------------------------------------------
    // Test 6: No correlation when no triggers registered
    // ------------------------------------------------------------------
    #[tokio::test]
    async fn no_correlation_without_triggers() {
        let engine = default_engine();

        let (tx, rx) = tokio::sync::mpsc::channel(16);
        let (rules_tx, mut rules_rx) = tokio::sync::mpsc::channel(16);
        let (analyzer_tx, mut analyzer_rx) = tokio::sync::mpsc::channel(16);
        let (log_tx, mut log_rx) = tokio::sync::mpsc::channel::<CorrelatedTrace>(16);

        let now = Utc::now();

        // Send a shell command event -- no trigger context, so no trigger registered.
        let event = make_enriched(
            600,
            None,
            EventKind::ProcessExec {
                binary: "/usr/bin/ls".into(),
                args: vec!["ls".into()],
                cwd: "/home/user".into(),
                uid: 1000,
            },
            shell_context(),
            now,
        );

        tx.send(event).await.unwrap();
        drop(tx);

        engine
            .run(rx, rules_tx, analyzer_tx, log_tx)
            .await
            .unwrap();

        // No triggers registered, so no traces anywhere.
        assert!(rules_rx.try_recv().is_err());
        assert!(analyzer_rx.try_recv().is_err());
        assert!(log_rx.try_recv().is_err());
    }
}
