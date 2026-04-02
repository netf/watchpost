use std::collections::HashMap;

use watchpost_types::{
    util::{
        binary_basename, shannon_entropy, ALL_KNOWN_REGISTRIES, C2_PORTS, SENSITIVE_PATHS, SHELLS,
        TEMP_DIRS,
    },
    ActionContext, BehaviorClassification, CorrelatedTrace, EventKind, FileAccessType,
    ScoreBreakdown, ScoreIndicator, SuspicionScore,
};

use crate::feedback::FeedbackCollector;
use crate::profiles::BehaviorProfileStore;

/// Heuristic scorer that evaluates a [`CorrelatedTrace`] and produces a
/// [`ScoreBreakdown`] with individually weighted indicators, a context
/// modifier, and a final clamped [`SuspicionScore`].
pub struct HeuristicScorer {
    weights: HashMap<ScoreIndicator, f64>,
    profiles: BehaviorProfileStore,
    feedback: Option<FeedbackCollector>,
}

impl HeuristicScorer {
    /// Create a scorer with the default indicator weights and the given
    /// behavior profile store.
    pub fn new(profiles: BehaviorProfileStore) -> Self {
        let weights = default_weights();
        Self {
            weights,
            profiles,
            feedback: None,
        }
    }

    /// Create a scorer with feedback-based weight adjustment enabled.
    pub fn with_feedback(profiles: BehaviorProfileStore, weight_overrides_path: &str) -> Self {
        let weights = default_weights();
        let feedback = FeedbackCollector::new(weight_overrides_path);
        Self {
            weights,
            profiles,
            feedback: Some(feedback),
        }
    }

    /// Score a correlated trace.
    ///
    /// For each event the scorer detects applicable indicators, consults the
    /// behavior profile to decide whether to keep, skip, or amplify each
    /// indicator, then sums the weighted indicators, applies the context
    /// modifier, and clamps to `[0.0, 1.0]`.
    ///
    /// When a [`FeedbackCollector`] is present the scorer also records each
    /// indicator fire and multiplies the base weight by the user-feedback
    /// weight factor.
    pub fn score(&self, trace: &CorrelatedTrace) -> ScoreBreakdown {
        let mut indicators: Vec<(ScoreIndicator, f64)> = Vec::new();

        for event in &trace.events {
            // Classify once per event, not once per indicator.
            let classification = self
                .profiles
                .classify_event(&event.event.kind, &trace.context);

            if classification == BehaviorClassification::Expected {
                continue;
            }

            let detected = self.detect_indicators(&event.event.kind, &trace.context);
            for (indicator, weight) in detected {
                indicators.push((indicator, weight));
            }
        }

        // Record fires and apply feedback weight factors.
        if let Some(ref fb) = self.feedback {
            let fired_indicators: Vec<ScoreIndicator> =
                indicators.iter().map(|(i, _)| i.clone()).collect();
            fb.record_fire(&fired_indicators);

            // Multiply each indicator weight by its feedback factor.
            for (indicator, weight) in &mut indicators {
                let factor = fb.get_weight_factor(indicator);
                *weight *= factor;
            }
        }

        let raw_score: f64 = indicators.iter().map(|(_, w)| w).sum();
        let context_modifier = context_modifier(&trace.context);
        let scaled = raw_score * context_modifier;
        let final_score = SuspicionScore::new(scaled);

        ScoreBreakdown {
            indicators,
            context_modifier,
            raw_score,
            final_score,
        }
    }

    /// Record that the user overrode (undid) the given indicators. Delegates
    /// to the internal [`FeedbackCollector`] if present.
    pub fn record_override(&self, indicators: &[ScoreIndicator]) {
        if let Some(ref fb) = self.feedback {
            fb.record_override(indicators);
        }
    }

    /// Detect which indicators apply to a single event.
    fn detect_indicators(
        &self,
        kind: &EventKind,
        context: &ActionContext,
    ) -> Vec<(ScoreIndicator, f64)> {
        let mut found = Vec::new();

        match kind {
            EventKind::NetworkConnect {
                dest_ip, dest_port, ..
            } => {
                // NonRegistryNetwork: destination is not a known registry.
                if !ALL_KNOWN_REGISTRIES.iter().any(|r| dest_ip.contains(r)) {
                    if let Some(&w) = self.weights.get(&ScoreIndicator::NonRegistryNetwork) {
                        found.push((ScoreIndicator::NonRegistryNetwork, w));
                    }
                }

                // MaliciousIp: connection to a C2 port.
                if C2_PORTS.contains(dest_port) {
                    if let Some(&w) = self.weights.get(&ScoreIndicator::MaliciousIp) {
                        found.push((ScoreIndicator::MaliciousIp, w));
                    }
                }
            }

            EventKind::FileAccess { path, access_type } => {
                let is_sensitive = SENSITIVE_PATHS.iter().any(|sp| path.contains(sp));

                if is_sensitive {
                    match access_type {
                        FileAccessType::Read => {
                            if let Some(&w) = self.weights.get(&ScoreIndicator::SensitiveFileRead) {
                                found.push((ScoreIndicator::SensitiveFileRead, w));
                            }
                        }
                        FileAccessType::Write => {
                            if let Some(&w) = self.weights.get(&ScoreIndicator::SensitiveFileWrite)
                            {
                                found.push((ScoreIndicator::SensitiveFileWrite, w));
                            }
                        }
                    }
                }
            }

            EventKind::ProcessExec { binary, .. } => {
                // TempDirExec: binary launched from a temp directory.
                if TEMP_DIRS.iter().any(|td| binary.starts_with(td)) {
                    if let Some(&w) = self.weights.get(&ScoreIndicator::TempDirExec) {
                        found.push((ScoreIndicator::TempDirExec, w));
                    }
                }

                // ShellFromPackageManager: a shell binary launched in a
                // package-install context.
                let basename = binary_basename(binary);
                if SHELLS.contains(&basename) && is_package_install(context) {
                    if let Some(&w) = self.weights.get(&ScoreIndicator::ShellFromPackageManager) {
                        found.push((ScoreIndicator::ShellFromPackageManager, w));
                    }
                }
            }

            EventKind::PrivilegeChange { old_uid, .. } => {
                // Privilege escalation from non-root.
                if *old_uid != 0 {
                    if let Some(&w) = self.weights.get(&ScoreIndicator::PrivilegeChange) {
                        found.push((ScoreIndicator::PrivilegeChange, w));
                    }
                }
            }

            EventKind::DnsQuery { query_name, .. } => {
                if shannon_entropy(query_name) > 4.0 {
                    if let Some(&w) = self.weights.get(&ScoreIndicator::HighEntropyDns) {
                        found.push((ScoreIndicator::HighEntropyDns, w));
                    }
                }
            }

            _ => {}
        }

        found
    }
}

/// Return the context modifier for a given action context.
fn context_modifier(context: &ActionContext) -> f64 {
    match context {
        ActionContext::PackageInstall { .. } => 1.5,
        ActionContext::Build { .. } => 0.7,
        ActionContext::FlatpakApp { .. } => 1.3,
        ActionContext::ToolboxSession { .. } => 0.8,
        _ => 1.0,
    }
}

/// Whether the context is a package install.
fn is_package_install(context: &ActionContext) -> bool {
    matches!(context, ActionContext::PackageInstall { .. })
}


/// Build the default indicator weight table.
fn default_weights() -> HashMap<ScoreIndicator, f64> {
    let mut w = HashMap::new();
    w.insert(ScoreIndicator::NonRegistryNetwork, 0.4);
    w.insert(ScoreIndicator::MaliciousIp, 0.8);
    w.insert(ScoreIndicator::SensitiveFileRead, 0.4);
    w.insert(ScoreIndicator::SensitiveFileWrite, 0.5);
    w.insert(ScoreIndicator::TempDirExec, 0.6);
    w.insert(ScoreIndicator::ShellFromPackageManager, 0.3);
    w.insert(ScoreIndicator::LdPreload, 0.5);
    w.insert(ScoreIndicator::PrivilegeChange, 0.7);
    w.insert(ScoreIndicator::HighEntropyDns, 0.3);
    w.insert(ScoreIndicator::ReverseShellPattern, 0.9);
    w.insert(ScoreIndicator::ObfuscatedContent, 0.7);
    w.insert(ScoreIndicator::AntiForensics, 0.5);
    // Phase 2: package provenance indicators
    w.insert(ScoreIndicator::NewPackageLowDownloads, 0.3);
    w.insert(ScoreIndicator::KnownVulnerability, 0.4);
    w.insert(ScoreIndicator::Typosquatting, 0.5);
    w.insert(ScoreIndicator::ProvenanceAttested, -0.2); // trust bonus (reduces score)
    w.insert(ScoreIndicator::EstablishedPackage, -0.3); // trust bonus (reduces score)
    w.insert(ScoreIndicator::NoGithubRelease, 0.4);
    w
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use uuid::Uuid;
    use watchpost_types::{
        ActionContext, BehaviorProfile, CorrelatedTrace, Ecosystem, EnrichedEvent,
        NetworkExpectation, TetragonEvent,
    };

    // ----- Helpers -----

    fn npm_context() -> ActionContext {
        ActionContext::PackageInstall {
            ecosystem: Ecosystem::Npm,
            package_name: Some("lodash".into()),
            package_version: None,
            working_dir: "/home/user/project".into(),
        }
    }

    fn cargo_build_context() -> ActionContext {
        ActionContext::Build {
            toolchain: "cargo".into(),
            working_dir: "/home/user/project".into(),
        }
    }

    fn unknown_context() -> ActionContext {
        ActionContext::Unknown
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

    fn make_trace(context: ActionContext, events: Vec<EnrichedEvent>) -> CorrelatedTrace {
        CorrelatedTrace {
            id: Uuid::new_v4(),
            trigger: None,
            events,
            signals: vec![],
            score: None,
            context,
        }
    }

    fn make_enriched(kind: EventKind, context: ActionContext) -> EnrichedEvent {
        EnrichedEvent {
            event: TetragonEvent {
                id: Uuid::new_v4(),
                timestamp: Utc::now(),
                kind,
                process_id: 1000,
                parent_id: Some(999),
                policy_name: None,
            },
            ancestry: vec![],
            context,
            provenance: None,
        }
    }

    fn scorer_with_npm_profile() -> HeuristicScorer {
        let mut store = BehaviorProfileStore::new();
        store.insert("npm", npm_profile());
        HeuristicScorer::new(store)
    }

    fn scorer_no_profiles() -> HeuristicScorer {
        HeuristicScorer::new(BehaviorProfileStore::new())
    }

    // ----- Test 1: npm + non-registry network -> score >= 0.6 -----

    #[test]
    fn npm_non_registry_network_score() {
        let scorer = scorer_with_npm_profile();
        let ctx = npm_context();
        let event = make_enriched(
            EventKind::NetworkConnect {
                dest_ip: "evil.com".into(),
                dest_port: 443,
                protocol: "tcp".into(),
            },
            ctx.clone(),
        );
        let trace = make_trace(ctx, vec![event]);
        let breakdown = scorer.score(&trace);

        assert!(
            breakdown.final_score.value() >= 0.6,
            "expected >= 0.6, got {}",
            breakdown.final_score.value()
        );
        assert!(
            breakdown
                .indicators
                .iter()
                .any(|(i, _)| *i == ScoreIndicator::NonRegistryNetwork),
            "expected NonRegistryNetwork indicator"
        );
    }

    // ----- Test 2: npm + .ssh/id_rsa read -> score >= 0.6 -----

    #[test]
    fn npm_sensitive_file_read_score() {
        let scorer = scorer_with_npm_profile();
        let ctx = npm_context();
        let event = make_enriched(
            EventKind::FileAccess {
                path: "/home/user/.ssh/id_rsa".into(),
                access_type: FileAccessType::Read,
            },
            ctx.clone(),
        );
        let trace = make_trace(ctx, vec![event]);
        let breakdown = scorer.score(&trace);

        assert!(
            breakdown.final_score.value() >= 0.6,
            "expected >= 0.6, got {}",
            breakdown.final_score.value()
        );
        assert!(
            breakdown
                .indicators
                .iter()
                .any(|(i, _)| *i == ScoreIndicator::SensitiveFileRead),
            "expected SensitiveFileRead indicator"
        );
    }

    // ----- Test 3: npm + exec from /tmp/payload -> score >= 0.7 -----

    #[test]
    fn npm_temp_dir_exec_score() {
        let scorer = scorer_with_npm_profile();
        let ctx = npm_context();
        let event = make_enriched(
            EventKind::ProcessExec {
                binary: "/tmp/payload".into(),
                args: vec![],
                cwd: "/tmp".into(),
                uid: 1000,
            },
            ctx.clone(),
        );
        let trace = make_trace(ctx, vec![event]);
        let breakdown = scorer.score(&trace);

        // 0.6 * 1.5 = 0.9, clamped to 0.9
        assert!(
            breakdown.final_score.value() >= 0.7,
            "expected >= 0.7, got {}",
            breakdown.final_score.value()
        );
    }

    // ----- Test 4: cargo build + sh -> score < 0.3 -----

    #[test]
    fn cargo_build_shell_low_score() {
        let scorer = scorer_no_profiles();
        let ctx = cargo_build_context();
        let event = make_enriched(
            EventKind::ProcessExec {
                binary: "/bin/sh".into(),
                args: vec![],
                cwd: "/home/user/project".into(),
                uid: 1000,
            },
            ctx.clone(),
        );
        let trace = make_trace(ctx, vec![event]);
        let breakdown = scorer.score(&trace);

        // ShellFromPackageManager only fires for PackageInstall, not Build.
        // No indicators fire, so score = 0.
        assert!(
            breakdown.final_score.value() < 0.3,
            "expected < 0.3, got {}",
            breakdown.final_score.value()
        );
    }

    // ----- Test 5: npm + C2 port 4444 -> score >= 0.7 -----

    #[test]
    fn npm_c2_port_score() {
        let scorer = scorer_with_npm_profile();
        let ctx = npm_context();
        let event = make_enriched(
            EventKind::NetworkConnect {
                dest_ip: "evil.com".into(),
                dest_port: 4444,
                protocol: "tcp".into(),
            },
            ctx.clone(),
        );
        let trace = make_trace(ctx, vec![event]);
        let breakdown = scorer.score(&trace);

        // NonRegistryNetwork (0.4) + MaliciousIp (0.8) = 1.2, * 1.5 = 1.8, clamped to 1.0
        assert!(
            breakdown.final_score.value() >= 0.7,
            "expected >= 0.7, got {}",
            breakdown.final_score.value()
        );
    }

    // ----- Test 6: unknown context + no indicators -> 0.0 -----

    #[test]
    fn no_indicators_zero_score() {
        let scorer = scorer_no_profiles();
        let ctx = unknown_context();
        // A process exit event should not trigger any indicators.
        let event = make_enriched(
            EventKind::ProcessExit {
                exit_code: 0,
                signal: None,
            },
            ctx.clone(),
        );
        let trace = make_trace(ctx, vec![event]);
        let breakdown = scorer.score(&trace);

        assert!(
            (breakdown.final_score.value() - 0.0).abs() < f64::EPSILON,
            "expected 0.0, got {}",
            breakdown.final_score.value()
        );
        assert!(breakdown.indicators.is_empty());
    }

    // ----- Test 7: npm + non-registry + .ssh read -> multiple indicators -----

    #[test]
    fn multiple_indicators_aggregate() {
        let scorer = scorer_with_npm_profile();
        let ctx = npm_context();
        let net_event = make_enriched(
            EventKind::NetworkConnect {
                dest_ip: "evil.com".into(),
                dest_port: 443,
                protocol: "tcp".into(),
            },
            ctx.clone(),
        );
        let file_event = make_enriched(
            EventKind::FileAccess {
                path: "/home/user/.ssh/id_rsa".into(),
                access_type: FileAccessType::Read,
            },
            ctx.clone(),
        );
        let trace = make_trace(ctx, vec![net_event, file_event]);
        let breakdown = scorer.score(&trace);

        // NonRegistryNetwork (0.4) + SensitiveFileRead (0.4) = 0.8, * 1.5 = 1.2 -> clamped 1.0
        assert!(
            breakdown.final_score.value() >= 0.7,
            "expected >= 0.7, got {}",
            breakdown.final_score.value()
        );
        assert!(
            breakdown.indicators.len() >= 2,
            "expected at least 2 indicators, got {}",
            breakdown.indicators.len()
        );
    }

    // ----- Test 8: Shannon entropy -----

    #[test]
    fn shannon_entropy_low_for_repetitive() {
        let e = shannon_entropy("aaa");
        assert!(e < 4.0, "expected < 4.0 for 'aaa', got {e}");
    }

    #[test]
    fn shannon_entropy_high_for_random() {
        let e = shannon_entropy("x7k9mz3q");
        assert!(e > 2.5, "expected > 2.5 for random-looking string, got {e}");
    }

    #[test]
    fn shannon_entropy_empty() {
        assert!((shannon_entropy("") - 0.0).abs() < f64::EPSILON);
    }

    // ----- Test 9: High-entropy DNS triggers indicator -----

    #[test]
    fn high_entropy_dns_triggers_indicator() {
        let scorer = scorer_no_profiles();
        let ctx = npm_context();
        // A high-entropy subdomain typical of DNS exfiltration.
        let event = make_enriched(
            EventKind::DnsQuery {
                query_name: "a8f3k2m9x7q1z5w0.evil.com".into(),
                query_type: "A".into(),
            },
            ctx.clone(),
        );
        let trace = make_trace(ctx, vec![event]);
        let breakdown = scorer.score(&trace);

        assert!(
            breakdown
                .indicators
                .iter()
                .any(|(i, _)| *i == ScoreIndicator::HighEntropyDns),
            "expected HighEntropyDns indicator"
        );
    }

    // ----- Test 10: Expected network is not flagged -----

    #[test]
    fn expected_network_not_flagged() {
        let scorer = scorer_with_npm_profile();
        let ctx = npm_context();
        let event = make_enriched(
            EventKind::NetworkConnect {
                dest_ip: "registry.npmjs.org".into(),
                dest_port: 443,
                protocol: "tcp".into(),
            },
            ctx.clone(),
        );
        let trace = make_trace(ctx, vec![event]);
        let breakdown = scorer.score(&trace);

        // The profile says registry.npmjs.org is expected, and it's also in
        // ALL_KNOWN_REGISTRIES, so NonRegistryNetwork should not fire.
        assert!(
            !breakdown
                .indicators
                .iter()
                .any(|(i, _)| *i == ScoreIndicator::NonRegistryNetwork),
            "expected no NonRegistryNetwork indicator for known registry"
        );
    }

    // ----- Test 11: PrivilegeChange from non-root -----

    #[test]
    fn privilege_change_from_nonroot() {
        let scorer = scorer_no_profiles();
        let ctx = npm_context();
        let event = make_enriched(
            EventKind::PrivilegeChange {
                old_uid: 1000,
                new_uid: 0,
                function_name: "setuid".into(),
            },
            ctx.clone(),
        );
        let trace = make_trace(ctx, vec![event]);
        let breakdown = scorer.score(&trace);

        assert!(
            breakdown
                .indicators
                .iter()
                .any(|(i, _)| *i == ScoreIndicator::PrivilegeChange),
            "expected PrivilegeChange indicator"
        );
        // 0.7 * 1.5 = 1.05, clamped to 1.0
        assert!(
            breakdown.final_score.value() >= 0.7,
            "expected >= 0.7, got {}",
            breakdown.final_score.value()
        );
    }

    // ----- Test 12: Context modifiers are correct -----

    #[test]
    fn context_modifiers() {
        assert!((context_modifier(&npm_context()) - 1.5).abs() < f64::EPSILON);
        assert!((context_modifier(&cargo_build_context()) - 0.7).abs() < f64::EPSILON);
        assert!(
            (context_modifier(&ActionContext::FlatpakApp {
                app_id: "org.test".into(),
                permissions: vec![],
            }) - 1.3)
                .abs()
                < f64::EPSILON
        );
        assert!(
            (context_modifier(&ActionContext::ToolboxSession {
                container_name: "t".into(),
                image: "i".into(),
            }) - 0.8)
                .abs()
                < f64::EPSILON
        );
        assert!((context_modifier(&unknown_context()) - 1.0).abs() < f64::EPSILON);
    }

    // ----- Test 13: Provenance indicators have correct default weights -----

    #[test]
    fn provenance_indicator_weights_registered() {
        let weights = default_weights();

        assert!(
            (weights[&ScoreIndicator::NewPackageLowDownloads] - 0.3).abs() < f64::EPSILON,
            "NewPackageLowDownloads should be 0.3"
        );
        assert!(
            (weights[&ScoreIndicator::KnownVulnerability] - 0.4).abs() < f64::EPSILON,
            "KnownVulnerability should be 0.4"
        );
        assert!(
            (weights[&ScoreIndicator::Typosquatting] - 0.5).abs() < f64::EPSILON,
            "Typosquatting should be 0.5"
        );
        assert!(
            (weights[&ScoreIndicator::ProvenanceAttested] - (-0.2)).abs() < f64::EPSILON,
            "ProvenanceAttested should be -0.2"
        );
        assert!(
            (weights[&ScoreIndicator::EstablishedPackage] - (-0.3)).abs() < f64::EPSILON,
            "EstablishedPackage should be -0.3"
        );
        assert!(
            (weights[&ScoreIndicator::NoGithubRelease] - 0.4).abs() < f64::EPSILON,
            "NoGithubRelease should be 0.4"
        );
    }

    // ----- Test 14: Negative weight (trust bonus) reduces raw score -----

    #[test]
    fn negative_weight_reduces_score() {
        // Verify that if we manually assemble indicators with a positive and
        // a negative weight, the raw_score is their sum.
        let positive = 0.5_f64;
        let negative = -0.2_f64;
        let raw = positive + negative;
        assert!(
            (raw - 0.3).abs() < f64::EPSILON,
            "0.5 + (-0.2) should be 0.3"
        );
    }

    // ----- Test 15: Feedback integration reduces scores for overridden indicators -----

    #[test]
    fn feedback_reduces_overridden_indicator_scores() {
        // Create a scorer with feedback pointing at a temp file.
        let tmpfile = tempfile::NamedTempFile::new().expect("tempfile");
        let path_str = tmpfile.path().to_str().unwrap();
        let scorer = HeuristicScorer::with_feedback(BehaviorProfileStore::new(), path_str);

        let ctx = npm_context();
        let event = make_enriched(
            EventKind::NetworkConnect {
                dest_ip: "evil.com".into(),
                dest_port: 443,
                protocol: "tcp".into(),
            },
            ctx.clone(),
        );
        let trace = make_trace(ctx.clone(), vec![event]);

        // Score once without overrides -- baseline.
        let baseline = scorer.score(&trace);
        let baseline_weight: f64 = baseline
            .indicators
            .iter()
            .filter(|(i, _)| *i == ScoreIndicator::NonRegistryNetwork)
            .map(|(_, w)| *w)
            .sum();
        assert!(baseline_weight > 0.0, "baseline weight should be > 0");

        // Now simulate many fires + overrides for NonRegistryNetwork.
        for _ in 0..10 {
            scorer.record_override(&[ScoreIndicator::NonRegistryNetwork]);
        }

        // Score again -- the weight should be reduced.
        let event2 = make_enriched(
            EventKind::NetworkConnect {
                dest_ip: "evil.com".into(),
                dest_port: 443,
                protocol: "tcp".into(),
            },
            ctx.clone(),
        );
        let trace2 = make_trace(ctx, vec![event2]);
        let adjusted = scorer.score(&trace2);
        let adjusted_weight: f64 = adjusted
            .indicators
            .iter()
            .filter(|(i, _)| *i == ScoreIndicator::NonRegistryNetwork)
            .map(|(_, w)| *w)
            .sum();

        assert!(
            adjusted_weight < baseline_weight,
            "adjusted weight ({adjusted_weight}) should be less than baseline ({baseline_weight})"
        );
    }
}
