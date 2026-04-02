//! End-to-end integration tests for the Watchpost engine + rules pipeline.
//!
//! These tests construct realistic event sequences and feed them through the
//! engine and rule engine, validating that the full scoring -> routing -> rule
//! evaluation pipeline produces correct verdicts.
//!
//! No real Tetragon instance is required.

use std::time::Duration;

use chrono::Utc;
use tokio::sync::mpsc;
use uuid::Uuid;

use watchpost_engine::profiles::BehaviorProfileStore;
use watchpost_engine::Engine;
use watchpost_rules::{load_rules_from_dir, RuleEngine};
use watchpost_types::{
    ActionContext, AncestryEntry, BehaviorProfile, Classification, CorrelatedTrace, Ecosystem,
    EngineConfig, EnrichedEvent, EventKind, FileAccessType, NetworkExpectation,
    RecommendedAction, TetragonEvent,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_enriched(
    pid: u32,
    parent_pid: Option<u32>,
    kind: EventKind,
    context: ActionContext,
    timestamp: chrono::DateTime<chrono::Utc>,
    ancestry: Vec<AncestryEntry>,
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
        ancestry,
        context,
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

fn npm_profile() -> BehaviorProfile {
    BehaviorProfile {
        context_type: "package_install".into(),
        ecosystem: Some(Ecosystem::Npm),
        expected_network: vec![NetworkExpectation {
            host: Some("registry.npmjs.org".into()),
            port: Some(443),
            description: "npm registry".into(),
        }],
        expected_children: vec!["node".into(), "node-gyp".into(), "sh".into()],
        expected_file_writes: vec!["node_modules/".into(), "/tmp/npm-".into()],
        forbidden_file_access: vec![".ssh/".into(), ".gnupg/".into()],
        forbidden_children: vec!["nc".into(), "ncat".into()],
        forbidden_network: vec![],
    }
}

fn cargo_profile() -> BehaviorProfile {
    BehaviorProfile {
        context_type: "build".into(),
        ecosystem: Some(Ecosystem::Cargo),
        expected_network: vec![NetworkExpectation {
            host: Some("crates.io".into()),
            port: Some(443),
            description: "crates.io registry".into(),
        }],
        expected_children: vec!["rustc".into(), "cc".into(), "ld".into(), "ar".into()],
        expected_file_writes: vec!["target/".into()],
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

fn engine_with_cargo_profile() -> Engine {
    let config = EngineConfig::default();
    let mut profiles = BehaviorProfileStore::new();
    profiles.insert("cargo", cargo_profile());
    Engine::new(&config, profiles)
}

fn npm_ancestry() -> Vec<AncestryEntry> {
    vec![
        AncestryEntry {
            pid: 200,
            binary_path: "/usr/bin/node".to_owned(),
            cmdline: "node install.js".to_owned(),
        },
        AncestryEntry {
            pid: 100,
            binary_path: "/usr/bin/npm".to_owned(),
            cmdline: "npm install evil-package".to_owned(),
        },
    ]
}

fn load_shipped_rule_engine() -> RuleEngine {
    let rules_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../rules");
    let rules = load_rules_from_dir(&rules_dir).expect("Failed to load shipped rules");
    RuleEngine::new(rules)
}

/// Collect all traces from a channel until it is closed or a timeout expires.
async fn drain_channel(
    rx: &mut mpsc::Receiver<CorrelatedTrace>,
    timeout: Duration,
) -> Vec<CorrelatedTrace> {
    let mut traces = Vec::new();
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        match tokio::time::timeout_at(deadline, rx.recv()).await {
            Ok(Some(trace)) => traces.push(trace),
            Ok(None) => break,  // channel closed
            Err(_) => break,    // timeout
        }
    }
    traces
}

// ---------------------------------------------------------------------------
// Test 1: npm postinstall reads SSH keys
// ---------------------------------------------------------------------------
//
// Scenario: npm install -> node -> sh -> cat ~/.ssh/id_rsa
// Expected: score >= 0.7, rule "npm-ssh-key-access" matches,
//           verdict=Malicious, action=Block
#[tokio::test]
async fn npm_postinstall_reads_ssh_keys() {
    let engine = engine_with_npm_profile();
    let rule_engine = load_shipped_rule_engine();

    let (tx, rx) = mpsc::channel(64);
    let (rules_tx, mut rules_rx) = mpsc::channel(64);
    let (analyzer_tx, mut analyzer_rx) = mpsc::channel(64);
    let (log_tx, mut log_rx) = mpsc::channel(64);

    let now = Utc::now();

    // Event 1: npm ProcessExec (trigger)
    let npm_exec = make_enriched(
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
        vec![],
    );

    // Event 2: node (child of npm)
    let node_exec = make_enriched(
        200,
        Some(100),
        EventKind::ProcessExec {
            binary: "/usr/bin/node".into(),
            args: vec!["node".into(), "install.js".into()],
            cwd: "/home/user/project".into(),
            uid: 1000,
        },
        npm_context(),
        now + chrono::Duration::milliseconds(500),
        vec![AncestryEntry {
            pid: 100,
            binary_path: "/usr/bin/npm".to_owned(),
            cmdline: "npm install evil-package".to_owned(),
        }],
    );

    // Event 3: sh (child of node)
    let sh_exec = make_enriched(
        300,
        Some(200),
        EventKind::ProcessExec {
            binary: "/bin/sh".into(),
            args: vec!["sh".into(), "-c".into(), "cat ~/.ssh/id_rsa".into()],
            cwd: "/home/user/project".into(),
            uid: 1000,
        },
        npm_context(),
        now + chrono::Duration::seconds(1),
        npm_ancestry(),
    );

    // Event 4: FileAccess(Read) for ~/.ssh/id_rsa (from sh, PID 300)
    let ssh_read = make_enriched(
        300,
        Some(200),
        EventKind::FileAccess {
            path: "/home/user/.ssh/id_rsa".into(),
            access_type: FileAccessType::Read,
        },
        npm_context(),
        now + chrono::Duration::seconds(2),
        npm_ancestry(),
    );

    // Event 5: Non-registry network connection (compounds the score above 0.7)
    let net_event = make_enriched(
        300,
        Some(200),
        EventKind::NetworkConnect {
            dest_ip: "evil-exfil.com".into(),
            dest_port: 443,
            protocol: "tcp".into(),
        },
        npm_context(),
        now + chrono::Duration::seconds(3),
        npm_ancestry(),
    );

    // Send events in chronological order
    tx.send(npm_exec).await.unwrap();
    tx.send(node_exec).await.unwrap();
    tx.send(sh_exec).await.unwrap();
    tx.send(ssh_read).await.unwrap();
    tx.send(net_event).await.unwrap();
    drop(tx); // Signal end of input

    // Run the engine
    engine
        .run(rx, rules_tx, analyzer_tx, log_tx)
        .await
        .unwrap();

    // Collect traces from all channels
    let rules_traces = drain_channel(&mut rules_rx, Duration::from_secs(1)).await;
    let analyzer_traces = drain_channel(&mut analyzer_rx, Duration::from_secs(1)).await;
    let log_traces = drain_channel(&mut log_rx, Duration::from_secs(1)).await;

    // With SensitiveFileRead (0.4) + NonRegistryNetwork (0.4) = 0.8,
    // * 1.5 (npm context) = 1.2, clamped to 1.0 -> rules channel.
    // At least one trace should have landed on the rules channel (high score).
    assert!(
        !rules_traces.is_empty(),
        "Expected at least one high-score trace on rules channel; \
         analyzer had {}, log had {}",
        analyzer_traces.len(),
        log_traces.len(),
    );

    // Verify the score is >= 0.7 for rules-channel traces
    for trace in &rules_traces {
        let score = trace.score.as_ref().expect("trace should have a score");
        assert!(
            score.value() >= 0.7,
            "Expected score >= 0.7, got {}",
            score.value()
        );
    }

    // Now run the rule engine on ALL traces (rules + analyzer + log) to find
    // the npm-ssh-key-access match. The rule evaluates trace content (ancestry
    // + file path), which is independent of the numeric score.
    let mut all_traces = Vec::new();
    all_traces.extend(rules_traces);
    all_traces.extend(analyzer_traces);
    all_traces.extend(log_traces);

    let mut found_ssh_rule = false;
    for trace in &all_traces {
        if let Some(verdict) = rule_engine.evaluate(trace) {
            if verdict.explanation.contains("npm-ssh-key-access") {
                found_ssh_rule = true;
                assert_eq!(
                    verdict.classification,
                    Classification::Malicious,
                    "npm-ssh-key-access should classify as Malicious"
                );
                assert_eq!(
                    verdict.recommended_action,
                    RecommendedAction::Block,
                    "npm-ssh-key-access should recommend Block"
                );
            }
        }
    }

    assert!(
        found_ssh_rule,
        "Expected rule 'npm-ssh-key-access' to match at least one trace"
    );
}

// ---------------------------------------------------------------------------
// Test 2: Normal cargo build produces no alerts
// ---------------------------------------------------------------------------
//
// Scenario: cargo build -> rustc -> cc -> ld
// Expected: score < 0.3, no rule match, logged only
#[tokio::test]
async fn normal_cargo_build_no_alerts() {
    let engine = engine_with_cargo_profile();
    let rule_engine = load_shipped_rule_engine();

    let (tx, rx) = mpsc::channel(64);
    let (rules_tx, mut rules_rx) = mpsc::channel(64);
    let (analyzer_tx, mut analyzer_rx) = mpsc::channel(64);
    let (log_tx, mut log_rx) = mpsc::channel(64);

    let now = Utc::now();

    // Event 1: cargo build (trigger)
    let cargo_exec = make_enriched(
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
        vec![],
    );

    // Event 2: rustc (child of cargo)
    let rustc_exec = make_enriched(
        501,
        Some(500),
        EventKind::ProcessExec {
            binary: "/usr/bin/rustc".into(),
            args: vec!["rustc".into(), "--edition=2021".into(), "src/main.rs".into()],
            cwd: "/home/user/project".into(),
            uid: 1000,
        },
        cargo_build_context(),
        now + chrono::Duration::seconds(1),
        vec![AncestryEntry {
            pid: 500,
            binary_path: "/usr/bin/cargo".to_owned(),
            cmdline: "cargo build".to_owned(),
        }],
    );

    // Event 3: cc (child of cargo, for native deps)
    let cc_exec = make_enriched(
        502,
        Some(500),
        EventKind::ProcessExec {
            binary: "/usr/bin/cc".into(),
            args: vec!["cc".into(), "-c".into(), "native.c".into()],
            cwd: "/home/user/project".into(),
            uid: 1000,
        },
        cargo_build_context(),
        now + chrono::Duration::seconds(2),
        vec![AncestryEntry {
            pid: 500,
            binary_path: "/usr/bin/cargo".to_owned(),
            cmdline: "cargo build".to_owned(),
        }],
    );

    // Event 4: ld (linker)
    let ld_exec = make_enriched(
        503,
        Some(500),
        EventKind::ProcessExec {
            binary: "/usr/bin/ld".into(),
            args: vec!["ld".into(), "-o".into(), "target/debug/myapp".into()],
            cwd: "/home/user/project".into(),
            uid: 1000,
        },
        cargo_build_context(),
        now + chrono::Duration::seconds(3),
        vec![AncestryEntry {
            pid: 500,
            binary_path: "/usr/bin/cargo".to_owned(),
            cmdline: "cargo build".to_owned(),
        }],
    );

    tx.send(cargo_exec).await.unwrap();
    tx.send(rustc_exec).await.unwrap();
    tx.send(cc_exec).await.unwrap();
    tx.send(ld_exec).await.unwrap();
    drop(tx);

    engine
        .run(rx, rules_tx, analyzer_tx, log_tx)
        .await
        .unwrap();

    let rules_traces = drain_channel(&mut rules_rx, Duration::from_secs(1)).await;
    let analyzer_traces = drain_channel(&mut analyzer_rx, Duration::from_secs(1)).await;
    let log_traces = drain_channel(&mut log_rx, Duration::from_secs(1)).await;

    // No traces should land on rules or analyzer channels
    assert!(
        rules_traces.is_empty(),
        "Expected no high-score traces for normal cargo build, got {}",
        rules_traces.len()
    );
    assert!(
        analyzer_traces.is_empty(),
        "Expected no medium-score traces for normal cargo build, got {}",
        analyzer_traces.len()
    );

    // All traces (if any) should be low-score on log channel
    for trace in &log_traces {
        let score = trace.score.as_ref().expect("trace should have a score");
        assert!(
            score.value() < 0.3,
            "Expected score < 0.3 for cargo build event, got {}",
            score.value()
        );

        // No rule should match normal build events
        let verdict = rule_engine.evaluate(trace);
        assert!(
            verdict.is_none(),
            "Expected no rule match for normal cargo build, got: {:?}",
            verdict.map(|v| v.explanation)
        );
    }
}

// ---------------------------------------------------------------------------
// Test 3: Cryptominer connection
// ---------------------------------------------------------------------------
//
// Scenario: unknown binary -> tcp_connect to port 3333
// Expected: rule "any-crypto-mining-port" matches, action=Block
#[tokio::test]
async fn cryptominer_connection_blocked() {
    let config = EngineConfig::default();
    let profiles = BehaviorProfileStore::new();
    let engine = Engine::new(&config, profiles);
    let rule_engine = load_shipped_rule_engine();

    let (tx, rx) = mpsc::channel(64);
    let (rules_tx, mut rules_rx) = mpsc::channel(64);
    let (analyzer_tx, mut analyzer_rx) = mpsc::channel(64);
    let (log_tx, mut log_rx) = mpsc::channel(64);

    let now = Utc::now();

    // We need a trigger first; use an npm context to register a trigger
    // so that subsequent events get correlated. In a real scenario, the
    // cryptominer would be spawned as a child of some tracked process.
    let trigger = make_enriched(
        700,
        None,
        EventKind::ProcessExec {
            binary: "/usr/bin/npm".into(),
            args: vec!["npm".into(), "install".into()],
            cwd: "/tmp".into(),
            uid: 1000,
        },
        ActionContext::PackageInstall {
            ecosystem: Ecosystem::Npm,
            package_name: Some("cryptojack".into()),
            package_version: Some("0.1.0".into()),
            working_dir: "/tmp".into(),
        },
        now,
        vec![],
    );

    // The cryptominer binary connects to port 3333
    let miner_connect = make_enriched(
        701,
        Some(700),
        EventKind::NetworkConnect {
            dest_ip: "pool.mining.com".into(),
            dest_port: 3333,
            protocol: "tcp".into(),
        },
        ActionContext::PackageInstall {
            ecosystem: Ecosystem::Npm,
            package_name: Some("cryptojack".into()),
            package_version: Some("0.1.0".into()),
            working_dir: "/tmp".into(),
        },
        now + chrono::Duration::seconds(1),
        vec![AncestryEntry {
            pid: 700,
            binary_path: "/usr/bin/npm".to_owned(),
            cmdline: "npm install cryptojack".to_owned(),
        }],
    );

    tx.send(trigger).await.unwrap();
    tx.send(miner_connect).await.unwrap();
    drop(tx);

    engine
        .run(rx, rules_tx, analyzer_tx, log_tx)
        .await
        .unwrap();

    // Collect traces from all channels -- the mining event may end up on rules
    // (high score) or analyzer (medium score) depending on profile presence.
    let mut all_traces = Vec::new();
    all_traces.extend(drain_channel(&mut rules_rx, Duration::from_secs(1)).await);
    all_traces.extend(drain_channel(&mut analyzer_rx, Duration::from_secs(1)).await);
    all_traces.extend(drain_channel(&mut log_rx, Duration::from_secs(1)).await);

    assert!(
        !all_traces.is_empty(),
        "Expected at least one correlated trace for the mining connection"
    );

    // The rule engine should match "any-crypto-mining-port" on traces
    // that contain the port-3333 network event.
    let mut found_mining_rule = false;
    for trace in &all_traces {
        if let Some(verdict) = rule_engine.evaluate(trace) {
            if verdict.explanation.contains("any-crypto-mining-port") {
                found_mining_rule = true;
                assert_eq!(
                    verdict.recommended_action,
                    RecommendedAction::Block,
                    "any-crypto-mining-port should recommend Block"
                );
            }
        }
    }

    assert!(
        found_mining_rule,
        "Expected rule 'any-crypto-mining-port' to match the mining connection trace"
    );
}

// ---------------------------------------------------------------------------
// Test 4: Ambiguous npm behavior routes to analyzer
// ---------------------------------------------------------------------------
//
// Scenario: npm install -> node -> python3 (single non-registry network connection)
// Expected: 0.3 <= score < 0.7, routed to analyzer_tx
#[tokio::test]
async fn ambiguous_npm_behavior_routes_to_analyzer() {
    let engine = engine_with_npm_profile();

    let (tx, rx) = mpsc::channel(64);
    let (rules_tx, mut rules_rx) = mpsc::channel(64);
    let (analyzer_tx, mut analyzer_rx) = mpsc::channel(64);
    let (log_tx, mut log_rx) = mpsc::channel(64);

    let now = Utc::now();

    // Event 1: npm install trigger
    let npm_exec = make_enriched(
        400,
        None,
        EventKind::ProcessExec {
            binary: "/usr/bin/npm".into(),
            args: vec!["npm".into(), "install".into()],
            cwd: "/home/user/project".into(),
            uid: 1000,
        },
        npm_context(),
        now,
        vec![],
    );

    // Event 2: A single non-registry network connection from a child.
    // This gives NonRegistryNetwork (0.4) * 1.5 (npm context) = 0.6,
    // which is >= 0.3 (llm_threshold) but < 0.7 (fast_path_threshold).
    let net_event = make_enriched(
        401,
        Some(400),
        EventKind::NetworkConnect {
            dest_ip: "suspicious.example.com".into(),
            dest_port: 443,
            protocol: "tcp".into(),
        },
        npm_context(),
        now + chrono::Duration::seconds(1),
        vec![AncestryEntry {
            pid: 400,
            binary_path: "/usr/bin/npm".to_owned(),
            cmdline: "npm install".to_owned(),
        }],
    );

    tx.send(npm_exec).await.unwrap();
    tx.send(net_event).await.unwrap();
    drop(tx);

    engine
        .run(rx, rules_tx, analyzer_tx, log_tx)
        .await
        .unwrap();

    let rules_traces = drain_channel(&mut rules_rx, Duration::from_secs(1)).await;
    let analyzer_traces = drain_channel(&mut analyzer_rx, Duration::from_secs(1)).await;
    let _log_traces = drain_channel(&mut log_rx, Duration::from_secs(1)).await;

    // The network event should produce a medium score -> analyzer channel
    assert!(
        !analyzer_traces.is_empty(),
        "Expected at least one medium-score trace on analyzer channel; \
         rules had {}, analyzer had {}",
        rules_traces.len(),
        analyzer_traces.len(),
    );

    // Verify all analyzer traces are in the medium band
    for trace in &analyzer_traces {
        let score = trace.score.as_ref().expect("trace should have a score");
        assert!(
            score.value() >= 0.3 && score.value() < 0.7,
            "Expected 0.3 <= score < 0.7, got {}",
            score.value()
        );
    }

    // No traces should be on the rules channel for this scenario
    assert!(
        rules_traces.is_empty(),
        "Expected no high-score traces for ambiguous behavior, got {}",
        rules_traces.len()
    );
}

// ---------------------------------------------------------------------------
// Test 5: Multiple indicators compound to high score
// ---------------------------------------------------------------------------
//
// Scenario: npm install -> non-registry network + .ssh/id_rsa read + shell spawn
// Expected: score >= 0.7, multiple indicators present
#[tokio::test]
async fn multiple_indicators_compound_to_high_score() {
    let engine = engine_with_npm_profile();

    let (tx, rx) = mpsc::channel(64);
    let (rules_tx, mut rules_rx) = mpsc::channel(64);
    let (analyzer_tx, _analyzer_rx) = mpsc::channel(64);
    let (log_tx, _log_rx) = mpsc::channel(64);

    let now = Utc::now();

    // Trigger: npm install
    let npm_exec = make_enriched(
        800,
        None,
        EventKind::ProcessExec {
            binary: "/usr/bin/npm".into(),
            args: vec!["npm".into(), "install".into()],
            cwd: "/home/user/project".into(),
            uid: 1000,
        },
        npm_context(),
        now,
        vec![],
    );

    // Network connect to evil host (NonRegistryNetwork indicator)
    let net_event = make_enriched(
        801,
        Some(800),
        EventKind::NetworkConnect {
            dest_ip: "evil.com".into(),
            dest_port: 4444,
            protocol: "tcp".into(),
        },
        npm_context(),
        now + chrono::Duration::seconds(1),
        npm_ancestry(),
    );

    // SSH key read (SensitiveFileRead indicator)
    let ssh_read = make_enriched(
        801,
        Some(800),
        EventKind::FileAccess {
            path: "/home/user/.ssh/id_rsa".into(),
            access_type: FileAccessType::Read,
        },
        npm_context(),
        now + chrono::Duration::seconds(2),
        npm_ancestry(),
    );

    tx.send(npm_exec).await.unwrap();
    tx.send(net_event).await.unwrap();
    tx.send(ssh_read).await.unwrap();
    drop(tx);

    engine
        .run(rx, rules_tx, analyzer_tx, log_tx)
        .await
        .unwrap();

    let rules_traces = drain_channel(&mut rules_rx, Duration::from_secs(1)).await;

    assert!(
        !rules_traces.is_empty(),
        "Expected at least one high-score trace when multiple indicators fire"
    );

    // The final trace (which accumulates all events) should have the highest score
    let last_trace = rules_traces.last().unwrap();
    let score = last_trace.score.as_ref().expect("trace should have a score");
    assert!(
        score.value() >= 0.7,
        "Expected score >= 0.7 with compounded indicators, got {}",
        score.value()
    );
}

// ---------------------------------------------------------------------------
// Test 6: Engine produces no output without triggers
// ---------------------------------------------------------------------------
//
// Scenario: Shell command events with no PackageInstall/Build/FlatpakApp context
// Expected: No traces on any channel (no triggers registered)
#[tokio::test]
async fn no_output_without_triggers() {
    let config = EngineConfig::default();
    let profiles = BehaviorProfileStore::new();
    let engine = Engine::new(&config, profiles);

    let (tx, rx) = mpsc::channel(64);
    let (rules_tx, mut rules_rx) = mpsc::channel(64);
    let (analyzer_tx, mut analyzer_rx) = mpsc::channel(64);
    let (log_tx, mut log_rx) = mpsc::channel(64);

    let now = Utc::now();

    // Shell command -- no trigger context
    let ls_event = make_enriched(
        900,
        None,
        EventKind::ProcessExec {
            binary: "/usr/bin/ls".into(),
            args: vec!["ls".into(), "/tmp".into()],
            cwd: "/home/user".into(),
            uid: 1000,
        },
        ActionContext::ShellCommand {
            tty: Some("/dev/pts/0".into()),
        },
        now,
        vec![],
    );

    tx.send(ls_event).await.unwrap();
    drop(tx);

    engine
        .run(rx, rules_tx, analyzer_tx, log_tx)
        .await
        .unwrap();

    let rules_traces = drain_channel(&mut rules_rx, Duration::from_secs(1)).await;
    let analyzer_traces = drain_channel(&mut analyzer_rx, Duration::from_secs(1)).await;
    let log_traces = drain_channel(&mut log_rx, Duration::from_secs(1)).await;

    assert!(
        rules_traces.is_empty(),
        "Expected no traces on rules channel, got {}",
        rules_traces.len()
    );
    assert!(
        analyzer_traces.is_empty(),
        "Expected no traces on analyzer channel, got {}",
        analyzer_traces.len()
    );
    assert!(
        log_traces.is_empty(),
        "Expected no traces on log channel, got {}",
        log_traces.len()
    );
}

// ---------------------------------------------------------------------------
// Test 7: Rule engine verdict classification matches severity
// ---------------------------------------------------------------------------
//
// Scenario: Directly construct a CorrelatedTrace and run the rule engine
// Expected: Critical/High -> Malicious, Medium -> Suspicious
#[tokio::test]
async fn rule_engine_verdict_classification() {
    let rule_engine = load_shipped_rule_engine();

    // Construct a trace with npm ancestry and port 4444 -> should match
    // npm-reverse-shell (critical) -> Malicious + Block
    let trace_c2 = CorrelatedTrace {
        id: Uuid::new_v4(),
        trigger: None,
        events: vec![make_enriched(
            1000,
            Some(999),
            EventKind::NetworkConnect {
                dest_ip: "evil.com".into(),
                dest_port: 4444,
                protocol: "tcp".into(),
            },
            npm_context(),
            Utc::now(),
            npm_ancestry(),
        )],
        signals: vec![],
        score: None,
        context: npm_context(),
    };

    let verdict = rule_engine
        .evaluate(&trace_c2)
        .expect("Expected a verdict for C2 port trace");
    assert_eq!(verdict.classification, Classification::Malicious);
    assert_eq!(verdict.recommended_action, RecommendedAction::Block);

    // Construct a trace with /tmp exec but no npm ancestry -> should match
    // any-temp-dir-exec (medium) -> Suspicious + Notify
    let trace_tmp = CorrelatedTrace {
        id: Uuid::new_v4(),
        trigger: None,
        events: vec![make_enriched(
            2000,
            Some(1999),
            EventKind::ProcessExec {
                binary: "/tmp/payload".into(),
                args: vec![],
                cwd: "/tmp".into(),
                uid: 1000,
            },
            ActionContext::Unknown,
            Utc::now(),
            vec![AncestryEntry {
                pid: 1999,
                binary_path: "/usr/bin/bash".to_owned(),
                cmdline: "bash".to_owned(),
            }],
        )],
        signals: vec![],
        score: None,
        context: ActionContext::Unknown,
    };

    let verdict_tmp = rule_engine
        .evaluate(&trace_tmp)
        .expect("Expected a verdict for temp dir exec trace");
    assert_eq!(verdict_tmp.classification, Classification::Suspicious);
    assert_eq!(verdict_tmp.recommended_action, RecommendedAction::Notify);

    // Normal cargo build -- no rule should match
    let trace_benign = CorrelatedTrace {
        id: Uuid::new_v4(),
        trigger: None,
        events: vec![make_enriched(
            3000,
            Some(2999),
            EventKind::ProcessExec {
                binary: "/usr/bin/rustc".into(),
                args: vec!["rustc".into(), "main.rs".into()],
                cwd: "/home/user/project".into(),
                uid: 1000,
            },
            cargo_build_context(),
            Utc::now(),
            vec![AncestryEntry {
                pid: 2999,
                binary_path: "/usr/bin/cargo".to_owned(),
                cmdline: "cargo build".to_owned(),
            }],
        )],
        signals: vec![],
        score: None,
        context: cargo_build_context(),
    };

    let verdict_benign = rule_engine.evaluate(&trace_benign);
    assert!(
        verdict_benign.is_none(),
        "Expected no verdict for normal cargo build"
    );
}

// ---------------------------------------------------------------------------
// Test 8: Full pipeline -- engine scoring + rule evaluation agreement
// ---------------------------------------------------------------------------
//
// Scenario: Verify that when the engine routes a trace to rules_tx (high score),
//           the rule engine also produces a verdict (the two systems agree).
#[tokio::test]
async fn engine_scoring_and_rules_agree() {
    let engine = engine_with_npm_profile();
    let rule_engine = load_shipped_rule_engine();

    let (tx, rx) = mpsc::channel(64);
    let (rules_tx, mut rules_rx) = mpsc::channel(64);
    let (analyzer_tx, _analyzer_rx) = mpsc::channel(64);
    let (log_tx, _log_rx) = mpsc::channel(64);

    let now = Utc::now();

    // npm trigger
    let npm_exec = make_enriched(
        1100,
        None,
        EventKind::ProcessExec {
            binary: "/usr/bin/npm".into(),
            args: vec!["npm".into(), "install".into()],
            cwd: "/home/user/project".into(),
            uid: 1000,
        },
        npm_context(),
        now,
        vec![],
    );

    // C2 connection to port 4444 (both the scorer and the rule engine should flag this)
    let c2_event = make_enriched(
        1101,
        Some(1100),
        EventKind::NetworkConnect {
            dest_ip: "evil.com".into(),
            dest_port: 4444,
            protocol: "tcp".into(),
        },
        npm_context(),
        now + chrono::Duration::seconds(1),
        npm_ancestry(),
    );

    tx.send(npm_exec).await.unwrap();
    tx.send(c2_event).await.unwrap();
    drop(tx);

    engine
        .run(rx, rules_tx, analyzer_tx, log_tx)
        .await
        .unwrap();

    let rules_traces = drain_channel(&mut rules_rx, Duration::from_secs(1)).await;

    assert!(
        !rules_traces.is_empty(),
        "Expected at least one trace on rules channel for C2 connection"
    );

    // Every trace on the rules channel should also produce a rule verdict
    for trace in &rules_traces {
        let score = trace.score.as_ref().expect("trace should have a score");
        assert!(
            score.value() >= 0.7,
            "Rules-channel trace should have score >= 0.7, got {}",
            score.value()
        );

        // The rule engine should also find a match
        let verdict = rule_engine.evaluate(trace);
        assert!(
            verdict.is_some(),
            "Expected rule engine to produce a verdict for high-score trace \
             (score={})",
            score.value()
        );
    }
}
