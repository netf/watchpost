use std::path::Path;

use dashmap::DashMap;
use tracing::warn;
use uuid::Uuid;
use watchpost_types::{
    util::{CARGO_REGISTRIES, NPM_REGISTRIES, PIP_REGISTRIES},
    ActionContext, ArgumentMatch, CorrelatedTrace, CorrelationSignal, Ecosystem, EnrichedEvent,
    EventKind,
};

use crate::persistent::{PersistentTrigger, PersistentWindowStore};
use crate::tree::ProcessTree;
use crate::triggers::{ActiveTrigger, ActiveTriggerRegistry};
use crate::windows::{ImmediateWindow, PersistentWindow, SessionWindow};

/// Three-signal correlator that matches incoming events against active triggers
/// using lineage (process tree), temporal (time windows), and argument (content
/// matching) signals.
pub struct ThreeSignalCorrelator {
    tree: ProcessTree,
    triggers: ActiveTriggerRegistry,
    immediate_window: ImmediateWindow,
    persistent_window: PersistentWindow,
    persistent_store: Option<PersistentWindowStore>,
    /// Accumulated events for each trigger, keyed by trigger ID.
    trace_buffers: DashMap<Uuid, Vec<EnrichedEvent>>,
}

impl ThreeSignalCorrelator {
    pub fn new(
        tree: ProcessTree,
        triggers: ActiveTriggerRegistry,
        immediate_window_ms: u64,
    ) -> Self {
        Self {
            tree,
            triggers,
            immediate_window: ImmediateWindow::new(immediate_window_ms),
            persistent_window: PersistentWindow::default(),
            persistent_store: None,
            trace_buffers: DashMap::new(),
        }
    }

    /// Create a correlator with a SQLite-backed persistent window store.
    pub fn with_persistent_store(
        tree: ProcessTree,
        triggers: ActiveTriggerRegistry,
        immediate_window_ms: u64,
        persistent_window_hours: u64,
        db_path: &Path,
    ) -> anyhow::Result<Self> {
        let store = PersistentWindowStore::open(db_path)?;
        Ok(Self {
            tree,
            triggers,
            immediate_window: ImmediateWindow::new(immediate_window_ms),
            persistent_window: PersistentWindow::new(persistent_window_hours),
            persistent_store: Some(store),
            trace_buffers: DashMap::new(),
        })
    }

    /// Access the process tree (needed by engine assembly).
    pub fn tree(&self) -> &ProcessTree {
        &self.tree
    }

    /// Access the trigger registry.
    pub fn triggers(&self) -> &ActiveTriggerRegistry {
        &self.triggers
    }

    /// Register a new trigger (delegates to registry and persists if store is available).
    pub fn register_trigger(&self, event: &EnrichedEvent) -> Option<Uuid> {
        let id = self.triggers.register(event)?;

        // Persist the trigger for the 24-hour window.
        if let Some(ref store) = self.persistent_store {
            let binary = match &event.event.kind {
                EventKind::ProcessExec { binary, .. } => binary.clone(),
                _ => String::new(),
            };
            let (context_type, package_name) = match &event.context {
                ActionContext::PackageInstall {
                    ecosystem,
                    package_name,
                    ..
                } => (format!("package_install_{}", ecosystem.as_str()), package_name.clone()),
                ActionContext::Build { toolchain, .. } => {
                    (format!("build_{toolchain}"), None)
                }
                ActionContext::FlatpakApp { app_id, .. } => {
                    (format!("flatpak_{app_id}"), None)
                }
                _ => ("unknown".to_string(), None),
            };

            let persistent = PersistentTrigger {
                trigger_id: id,
                process_pid: event.event.process_id,
                binary,
                context_type,
                package_name,
                start_time: event.event.timestamp,
            };
            if let Err(e) = store.save_trigger(&persistent) {
                warn!(error = %e, "failed to persist trigger");
            }
        }

        Some(id)
    }

    /// Deactivate a trigger's session and clean up its trace buffer.
    pub fn deactivate_trigger(&self, pid: u32) {
        if let Some(trigger) = self.triggers.get_trigger_for_pid(pid) {
            self.trace_buffers.remove(&trigger.id);
        }
        self.triggers.deactivate_session(pid);
    }

    /// Correlate an incoming event against all active triggers and return a
    /// `CorrelatedTrace` if any trigger matches.
    ///
    /// If no active (in-memory) trigger matches, the persistent store is
    /// consulted for a matching trigger by binary name, providing a weak
    /// (0.1) correlation signal for delayed-execution detection.
    pub fn correlate(&self, event: &EnrichedEvent) -> Option<CorrelatedTrace> {
        let active_triggers = self.triggers.get_active_triggers();

        // Compute signals for each active trigger and find the best match.
        let mut best: Option<(ActiveTrigger, CorrelationSignal)> = None;

        for trigger in &active_triggers {
            let signal = self.compute_signal(trigger, event);

            // A trigger correlates if lineage matches or temporal weight > 0.
            if !signal.lineage_match && signal.temporal_weight <= 0.0 {
                continue;
            }

            let is_better = match &best {
                None => true,
                Some((_, prev)) => signal_strength(&signal) > signal_strength(prev),
            };

            if is_better {
                best = Some((trigger.clone(), signal));
            }
        }

        // If we found an active trigger match, use it.
        if let Some((trigger, signal)) = best {
            // Save event to persistent store.
            self.persist_event(&trigger.id, event);

            return Some(self.build_trace(trigger.id, &trigger.event, &trigger.event.context, signal, event));
        }

        // No active trigger matched — check the persistent store for a
        // delayed-execution correlation.
        self.correlate_persistent(event)
    }

    /// Try to correlate an event via the persistent store (weak 0.1 signal).
    fn correlate_persistent(&self, event: &EnrichedEvent) -> Option<CorrelatedTrace> {
        let store = self.persistent_store.as_ref()?;

        // Extract the binary from the event for lookup.
        let binary = match &event.event.kind {
            EventKind::ProcessExec { binary, .. } => binary.as_str(),
            _ => return None,
        };

        let persistent_trigger = match store.find_trigger_for_binary(binary, self.persistent_window.max_age_hours) {
            Ok(Some(pt)) => pt,
            Ok(None) => return None,
            Err(e) => {
                warn!(error = %e, "persistent store lookup failed");
                return None;
            }
        };

        let weight = self.persistent_window.temporal_weight(
            persistent_trigger.start_time,
            event.event.timestamp,
        );
        if weight <= 0.0 {
            return None;
        }

        let signal = CorrelationSignal {
            lineage_match: false,
            temporal_weight: weight,
            argument_match: ArgumentMatch::None,
        };

        // Save event to persistent store.
        self.persist_event(&persistent_trigger.trigger_id, event);

        // Build a trace for the persistent match. Since the original trigger
        // event is not in memory, we use the current event as the trigger
        // stand-in and set context from what we know.
        let trace_id = persistent_trigger.trigger_id;

        const MAX_TRACE_EVENTS: usize = 500;
        let mut buffer = self.trace_buffers.entry(trace_id).or_default();
        if buffer.len() < MAX_TRACE_EVENTS {
            buffer.push(event.clone());
        }
        let buffered_events = buffer.clone();
        drop(buffer);

        Some(CorrelatedTrace {
            id: trace_id,
            trigger: None,
            events: buffered_events,
            signals: vec![signal],
            score: None,
            context: event.context.clone(),
        })
    }

    /// Persist a correlated event to the SQLite store.
    fn persist_event(&self, trigger_id: &Uuid, event: &EnrichedEvent) {
        if let Some(ref store) = self.persistent_store {
            let event_kind = event_kind_str(&event.event.kind);
            if let Err(e) = store.save_event(
                trigger_id,
                &event.event.id,
                &event_kind,
                event.event.process_id,
                &event.event.timestamp,
            ) {
                warn!(error = %e, "failed to persist event");
            }
        }
    }

    /// Build a `CorrelatedTrace` from an active trigger match.
    fn build_trace(
        &self,
        trigger_id: Uuid,
        trigger_event: &EnrichedEvent,
        context: &ActionContext,
        signal: CorrelationSignal,
        event: &EnrichedEvent,
    ) -> CorrelatedTrace {
        const MAX_TRACE_EVENTS: usize = 500;
        let mut buffer = self.trace_buffers.entry(trigger_id).or_default();
        if buffer.len() < MAX_TRACE_EVENTS {
            buffer.push(event.clone());
        }
        let buffered_events = buffer.clone();
        drop(buffer);

        CorrelatedTrace {
            id: trigger_id,
            trigger: Some(trigger_event.clone()),
            events: buffered_events,
            signals: vec![signal],
            score: None,
            context: context.clone(),
        }
    }

    /// Compute the three correlation signals for a (trigger, event) pair.
    fn compute_signal(&self, trigger: &ActiveTrigger, event: &EnrichedEvent) -> CorrelationSignal {
        let lineage_match = self
            .tree
            .is_descendant(event.event.process_id, trigger.process_pid);

        let immediate = self
            .immediate_window
            .temporal_weight(trigger.start_time, event.event.timestamp);
        let session = SessionWindow::temporal_weight(
            trigger.start_time,
            trigger.session_active,
            event.event.timestamp,
        );
        let temporal_weight = immediate.max(session);

        let argument_match = compute_argument_match(&trigger.event.context, &event.event.kind);

        CorrelationSignal {
            lineage_match,
            temporal_weight,
            argument_match,
        }
    }
}

/// Convert an `EventKind` to a short string label for persistence.
fn event_kind_str(kind: &EventKind) -> &'static str {
    match kind {
        EventKind::ProcessExec { .. } => "ProcessExec",
        EventKind::ProcessExit { .. } => "ProcessExit",
        EventKind::FileAccess { .. } => "FileAccess",
        EventKind::NetworkConnect { .. } => "NetworkConnect",
        EventKind::PrivilegeChange { .. } => "PrivilegeChange",
        EventKind::DnsQuery { .. } => "DnsQuery",
        EventKind::ScriptExec { .. } => "ScriptExec",
    }
}

/// Rank a signal for comparison: lineage > temporal > argument.
///
/// Returns a tuple that sorts signals from weakest to strongest, allowing us
/// to pick the trigger with the strongest combined signal.
fn signal_strength(signal: &CorrelationSignal) -> (u8, u64, u8) {
    let lineage = if signal.lineage_match { 1 } else { 0 };
    // Scale temporal weight to integer for deterministic comparison.
    let temporal = (signal.temporal_weight * 1_000_000.0) as u64;
    let argument = match signal.argument_match {
        ArgumentMatch::Positive => 2,
        ArgumentMatch::None => 1,
        ArgumentMatch::Negative => 0,
    };
    (lineage, temporal, argument)
}

/// Compare event content against trigger context expectations for argument
/// matching.
///
/// For `NetworkConnect` events combined with `PackageInstall` triggers, the
/// destination address is checked against known registry hostnames. For all
/// other combinations the result is `None` (neutral).
fn compute_argument_match(trigger_context: &ActionContext, event_kind: &EventKind) -> ArgumentMatch {
    let EventKind::NetworkConnect { dest_ip, .. } = event_kind else {
        return ArgumentMatch::None;
    };

    let ActionContext::PackageInstall { ecosystem, .. } = trigger_context else {
        return ArgumentMatch::None;
    };

    let registries: &[&str] = match ecosystem {
        Ecosystem::Npm => NPM_REGISTRIES,
        Ecosystem::Pip => PIP_REGISTRIES,
        Ecosystem::Cargo => CARGO_REGISTRIES,
    };

    if registries.iter().any(|r| dest_ip.contains(r)) {
        ArgumentMatch::Positive
    } else {
        ArgumentMatch::Negative
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use watchpost_types::{ActionContext, Ecosystem, EventKind, TetragonEvent};

    /// Helper: create an `EnrichedEvent` with the given PID, context, and kind.
    fn make_event_full(
        pid: u32,
        parent_pid: Option<u32>,
        context: ActionContext,
        kind: EventKind,
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

    /// Helper: create a simple `ProcessExec` event at the given time.
    fn make_exec_event(
        pid: u32,
        parent_pid: Option<u32>,
        context: ActionContext,
        timestamp: chrono::DateTime<chrono::Utc>,
    ) -> EnrichedEvent {
        make_event_full(
            pid,
            parent_pid,
            context,
            EventKind::ProcessExec {
                binary: "/usr/bin/node".into(),
                args: vec!["node".into()],
                cwd: "/tmp".into(),
                uid: 1000,
            },
            timestamp,
        )
    }

    /// Helper: create a `NetworkConnect` event.
    fn make_network_event(
        pid: u32,
        parent_pid: Option<u32>,
        dest_ip: &str,
        dest_port: u16,
        context: ActionContext,
        timestamp: chrono::DateTime<chrono::Utc>,
    ) -> EnrichedEvent {
        make_event_full(
            pid,
            parent_pid,
            context,
            EventKind::NetworkConnect {
                dest_ip: dest_ip.into(),
                dest_port,
                protocol: "tcp".into(),
            },
            timestamp,
        )
    }

    fn npm_install_context() -> ActionContext {
        ActionContext::PackageInstall {
            ecosystem: Ecosystem::Npm,
            package_name: Some("lodash".into()),
            package_version: None,
            working_dir: "/home/user/project".into(),
        }
    }

    fn shell_context() -> ActionContext {
        ActionContext::ShellCommand {
            tty: Some("/dev/pts/0".into()),
        }
    }

    // -----------------------------------------------------------------------
    // Test 1: Lineage match
    // -----------------------------------------------------------------------
    #[test]
    fn lineage_match_returns_trace() {
        let tree = ProcessTree::new();
        let now = Utc::now();
        tree.insert(100, None, "/usr/bin/bash".into(), now);
        tree.insert(200, Some(100), "/usr/bin/node".into(), now);

        let triggers = ActiveTriggerRegistry::new();
        let correlator = ThreeSignalCorrelator::new(tree, triggers, 5000);

        // Register a trigger for PID 100 (PackageInstall).
        let trigger_event = make_exec_event(100, None, npm_install_context(), now);
        correlator.register_trigger(&trigger_event);

        // Event from PID 200, which is a child of 100.
        let child_event = make_exec_event(200, Some(100), shell_context(), now + Duration::seconds(1));
        let trace = correlator.correlate(&child_event);

        assert!(trace.is_some(), "expected a correlation trace");
        let trace = trace.unwrap();
        assert!(!trace.signals.is_empty());
        assert!(trace.signals[0].lineage_match, "lineage_match should be true");
    }

    // -----------------------------------------------------------------------
    // Test 2: Temporal match (no lineage)
    // -----------------------------------------------------------------------
    #[test]
    fn temporal_match_returns_trace() {
        let tree = ProcessTree::new();
        let now = Utc::now();
        // PID 100 and PID 500 are not in a parent-child relationship.
        tree.insert(100, None, "/usr/bin/npm".into(), now);
        tree.insert(500, None, "/usr/bin/curl".into(), now);

        let triggers = ActiveTriggerRegistry::new();
        let correlator = ThreeSignalCorrelator::new(tree, triggers, 5000);

        let trigger_event = make_exec_event(100, None, npm_install_context(), now);
        correlator.register_trigger(&trigger_event);

        // Event from PID 500 at T+2s (within 5s immediate window).
        let other_event = make_exec_event(500, None, shell_context(), now + Duration::seconds(2));
        let trace = correlator.correlate(&other_event);

        assert!(trace.is_some(), "expected temporal correlation");
        let trace = trace.unwrap();
        assert!(!trace.signals[0].lineage_match, "lineage_match should be false");
        assert!(
            trace.signals[0].temporal_weight > 0.0,
            "temporal_weight should be > 0"
        );
    }

    // -----------------------------------------------------------------------
    // Test 3: Argument match (positive) — npm registry
    // -----------------------------------------------------------------------
    #[test]
    fn argument_match_positive_npm() {
        let tree = ProcessTree::new();
        let now = Utc::now();
        tree.insert(100, None, "/usr/bin/npm".into(), now);
        tree.insert(200, Some(100), "/usr/bin/curl".into(), now);

        let triggers = ActiveTriggerRegistry::new();
        let correlator = ThreeSignalCorrelator::new(tree, triggers, 5000);

        let trigger_event = make_exec_event(100, None, npm_install_context(), now);
        correlator.register_trigger(&trigger_event);

        let net_event = make_network_event(
            200,
            Some(100),
            "registry.npmjs.org",
            443,
            shell_context(),
            now + Duration::seconds(1),
        );
        let trace = correlator.correlate(&net_event);

        assert!(trace.is_some());
        let trace = trace.unwrap();
        assert_eq!(
            trace.signals[0].argument_match,
            ArgumentMatch::Positive,
            "expected Positive argument match for npm registry"
        );
    }

    // -----------------------------------------------------------------------
    // Test 4: Argument match (negative) — unknown host
    // -----------------------------------------------------------------------
    #[test]
    fn argument_match_negative_unknown_host() {
        let tree = ProcessTree::new();
        let now = Utc::now();
        tree.insert(100, None, "/usr/bin/npm".into(), now);
        tree.insert(200, Some(100), "/usr/bin/curl".into(), now);

        let triggers = ActiveTriggerRegistry::new();
        let correlator = ThreeSignalCorrelator::new(tree, triggers, 5000);

        let trigger_event = make_exec_event(100, None, npm_install_context(), now);
        correlator.register_trigger(&trigger_event);

        let net_event = make_network_event(
            200,
            Some(100),
            "evil.com",
            443,
            shell_context(),
            now + Duration::seconds(1),
        );
        let trace = correlator.correlate(&net_event);

        assert!(trace.is_some());
        let trace = trace.unwrap();
        assert_eq!(
            trace.signals[0].argument_match,
            ArgumentMatch::Negative,
            "expected Negative argument match for evil.com"
        );
    }

    // -----------------------------------------------------------------------
    // Test 5: No correlation — unrelated PID outside time window
    // -----------------------------------------------------------------------
    #[test]
    fn no_correlation_for_unrelated_event() {
        let tree = ProcessTree::new();
        let now = Utc::now();
        tree.insert(100, None, "/usr/bin/npm".into(), now);
        // PID 999 is completely unrelated (no parent chain to 100).
        tree.insert(999, None, "/usr/bin/firefox".into(), now);

        let triggers = ActiveTriggerRegistry::new();
        let correlator = ThreeSignalCorrelator::new(tree, triggers, 5000);

        let trigger_event = make_exec_event(100, None, npm_install_context(), now);
        correlator.register_trigger(&trigger_event);

        // Deactivate the session so SessionWindow returns 0.
        correlator.deactivate_trigger(100);

        // Event from PID 999, well outside the 5s immediate window.
        let late_event = make_exec_event(
            999,
            None,
            shell_context(),
            now + Duration::seconds(60),
        );
        let trace = correlator.correlate(&late_event);

        assert!(trace.is_none(), "expected no correlation for unrelated event");
    }

    // -----------------------------------------------------------------------
    // Test 6: Trace buffering — multiple events accumulate
    // -----------------------------------------------------------------------
    #[test]
    fn trace_buffering_accumulates_events() {
        let tree = ProcessTree::new();
        let now = Utc::now();
        tree.insert(100, None, "/usr/bin/npm".into(), now);
        tree.insert(200, Some(100), "/usr/bin/node".into(), now);

        let triggers = ActiveTriggerRegistry::new();
        let correlator = ThreeSignalCorrelator::new(tree, triggers, 5000);

        let trigger_event = make_exec_event(100, None, npm_install_context(), now);
        correlator.register_trigger(&trigger_event);

        // Correlate 3 events from the same child process.
        for i in 1..=3 {
            let event = make_exec_event(
                200,
                Some(100),
                shell_context(),
                now + Duration::seconds(i),
            );
            let trace = correlator.correlate(&event);
            assert!(trace.is_some(), "event {i} should correlate");

            let trace = trace.unwrap();
            assert_eq!(
                trace.events.len(),
                i as usize,
                "trace should contain {i} events after {i} correlations"
            );
        }
    }
}
