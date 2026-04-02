use std::fmt::Write;

use watchpost_types::{
    ActionContext, BehaviorProfile, CorrelatedTrace, EnrichedEvent, EventKind, ScoreBreakdown,
};

use crate::client::{ContentBlock, Message};

// ---------------------------------------------------------------------------
// Context builder
// ---------------------------------------------------------------------------

/// Builds LLM user messages from correlated kernel event traces.
///
/// The context builder formats a [`CorrelatedTrace`] into a human-readable
/// text message suitable for the runtime trace analyzer skill.
pub struct ContextBuilder;

impl ContextBuilder {
    /// Build a user message from a correlated trace for the LLM.
    ///
    /// The message includes: trigger context, behavior profile summary (if
    /// available), process ancestry, chronological event timeline, correlation
    /// signals, score breakdown (if available), and the analysis task prompt.
    pub fn build_user_message(
        trace: &CorrelatedTrace,
        profile: Option<&BehaviorProfile>,
        score_breakdown: Option<&ScoreBreakdown>,
    ) -> Message {
        let mut text = String::with_capacity(4096);

        // 1. Trigger context
        Self::write_trigger_context(&mut text, trace);

        // 2. Behavior profile summary
        if let Some(profile) = profile {
            Self::write_behavior_profile(&mut text, profile);
        }

        // 3. Process ancestry
        Self::write_process_ancestry(&mut text, trace);

        // 4. Event timeline
        Self::write_event_timeline(&mut text, trace);

        // 5. Correlation signals
        Self::write_correlation_signals(&mut text, trace);

        // 6. Score breakdown
        if let Some(breakdown) = score_breakdown {
            Self::write_score_breakdown(&mut text, breakdown);
        }

        // 7. Task instruction
        writeln!(text).ok();
        writeln!(text, "## Task").ok();
        writeln!(
            text,
            "Analyze the above trace. Use tools if you need additional context. \
             Then classify as benign, suspicious, or malicious."
        )
        .ok();

        Message {
            role: "user".to_string(),
            content: vec![ContentBlock::Text { text }],
        }
    }

    // -- Section writers ------------------------------------------------------

    fn write_trigger_context(text: &mut String, trace: &CorrelatedTrace) {
        writeln!(text, "## Trigger Context").ok();

        if let Some(trigger) = &trace.trigger {
            let (command, directory) = Self::extract_command_and_dir(&trigger.event.kind);
            writeln!(text, "The user ran `{}` in `{}`.", command, directory).ok();
            writeln!(text).ok();
            Self::write_action_context(text, &trigger.context);
        } else {
            // Fall back to the trace-level context
            writeln!(text, "No explicit trigger event.").ok();
            writeln!(text).ok();
            Self::write_action_context(text, &trace.context);
        }
        writeln!(text).ok();
    }

    fn write_action_context(text: &mut String, ctx: &ActionContext) {
        match ctx {
            ActionContext::PackageInstall {
                ecosystem,
                package_name,
                package_version,
                working_dir,
            } => {
                write!(text, "Action: package install ({ecosystem:?})").ok();
                if let Some(name) = package_name {
                    write!(text, ", package: {name}").ok();
                }
                if let Some(version) = package_version {
                    write!(text, " v{version}").ok();
                }
                writeln!(text, ", working dir: {working_dir}").ok();
            }
            ActionContext::Build {
                toolchain,
                working_dir,
            } => {
                writeln!(text, "Action: build ({toolchain}), working dir: {working_dir}").ok();
            }
            ActionContext::FlatpakApp {
                app_id,
                permissions,
            } => {
                writeln!(
                    text,
                    "Action: Flatpak app launch ({app_id}), permissions: [{}]",
                    permissions.join(", ")
                )
                .ok();
            }
            ActionContext::ToolboxSession {
                container_name,
                image,
            } => {
                writeln!(
                    text,
                    "Action: Toolbox session ({container_name}), image: {image}"
                )
                .ok();
            }
            ActionContext::ShellCommand { tty } => {
                writeln!(
                    text,
                    "Action: shell command, tty: {}",
                    tty.as_deref().unwrap_or("none")
                )
                .ok();
            }
            ActionContext::IdeOperation { ide_name } => {
                writeln!(text, "Action: IDE operation ({ide_name})").ok();
            }
            ActionContext::Unknown => {
                writeln!(text, "Action: unknown").ok();
            }
        }
    }

    fn write_behavior_profile(text: &mut String, profile: &BehaviorProfile) {
        writeln!(text, "## Behavior Profile").ok();
        writeln!(
            text,
            "Context type: {}, ecosystem: {}",
            profile.context_type,
            profile
                .ecosystem
                .as_ref()
                .map(|e| format!("{e:?}"))
                .unwrap_or_else(|| "none".to_string())
        )
        .ok();
        writeln!(text).ok();

        if !profile.expected_children.is_empty() {
            writeln!(text, "Expected child processes:").ok();
            for child in &profile.expected_children {
                writeln!(text, "  - {child}").ok();
            }
        }
        if !profile.expected_file_writes.is_empty() {
            writeln!(text, "Expected file writes:").ok();
            for path in &profile.expected_file_writes {
                writeln!(text, "  - {path}").ok();
            }
        }
        if !profile.expected_network.is_empty() {
            writeln!(text, "Expected network:").ok();
            for net in &profile.expected_network {
                writeln!(
                    text,
                    "  - {} ({})",
                    net.host.as_deref().unwrap_or("*"),
                    net.description
                )
                .ok();
            }
        }
        if !profile.forbidden_children.is_empty() {
            writeln!(text, "Forbidden child processes:").ok();
            for child in &profile.forbidden_children {
                writeln!(text, "  - {child}").ok();
            }
        }
        if !profile.forbidden_file_access.is_empty() {
            writeln!(text, "Forbidden file access:").ok();
            for path in &profile.forbidden_file_access {
                writeln!(text, "  - {path}").ok();
            }
        }
        if !profile.forbidden_network.is_empty() {
            writeln!(text, "Forbidden network:").ok();
            for net in &profile.forbidden_network {
                writeln!(
                    text,
                    "  - {} ({})",
                    net.host.as_deref().unwrap_or("*"),
                    net.description
                )
                .ok();
            }
        }
        writeln!(text).ok();
    }

    fn write_process_ancestry(text: &mut String, trace: &CorrelatedTrace) {
        let Some(trigger) = &trace.trigger else {
            return;
        };
        if trigger.ancestry.is_empty() {
            return;
        }

        writeln!(text, "## Process Ancestry").ok();
        // Ancestry is ordered from immediate parent to root, so we reverse
        // for a top-down tree display.
        for (depth, entry) in trigger.ancestry.iter().rev().enumerate() {
            let indent = "  ".repeat(depth);
            writeln!(text, "{indent}[{}] {}", entry.pid, entry.cmdline).ok();
        }
        // The trigger process itself
        let trigger_indent = "  ".repeat(trigger.ancestry.len());
        writeln!(
            text,
            "{trigger_indent}[{}] (trigger)",
            trigger.event.process_id
        )
        .ok();
        writeln!(text).ok();
    }

    fn write_event_timeline(text: &mut String, trace: &CorrelatedTrace) {
        writeln!(text, "## Event Timeline").ok();
        if trace.events.is_empty() {
            writeln!(text, "(no events)").ok();
            writeln!(text).ok();
            return;
        }

        for event in &trace.events {
            Self::write_event_line(text, event);
        }
        writeln!(text).ok();
    }

    fn write_event_line(text: &mut String, enriched: &EnrichedEvent) {
        let ts = enriched.event.timestamp.to_rfc3339();
        let pid = enriched.event.process_id;

        match &enriched.event.kind {
            EventKind::ProcessExec {
                binary, args, cwd, uid,
            } => {
                let args_str = args.join(" ");
                writeln!(
                    text,
                    "  [{ts}] pid={pid} EXEC binary={binary} args=[{args_str}] cwd={cwd} uid={uid}"
                )
                .ok();
            }
            EventKind::ProcessExit { exit_code, signal } => {
                write!(text, "  [{ts}] pid={pid} EXIT code={exit_code}").ok();
                if let Some(sig) = signal {
                    write!(text, " signal={sig}").ok();
                }
                writeln!(text).ok();
            }
            EventKind::FileAccess { path, access_type } => {
                writeln!(
                    text,
                    "  [{ts}] pid={pid} FILE {access_type:?} path={path}"
                )
                .ok();
            }
            EventKind::NetworkConnect {
                dest_ip,
                dest_port,
                protocol,
            } => {
                writeln!(
                    text,
                    "  [{ts}] pid={pid} NET {protocol} dest={dest_ip}:{dest_port}"
                )
                .ok();
            }
            EventKind::PrivilegeChange {
                old_uid,
                new_uid,
                function_name,
            } => {
                writeln!(
                    text,
                    "  [{ts}] pid={pid} PRIV {function_name} uid={old_uid}->{new_uid}"
                )
                .ok();
            }
            EventKind::DnsQuery {
                query_name,
                query_type,
            } => {
                writeln!(text, "  [{ts}] pid={pid} DNS {query_type} {query_name}").ok();
            }
            EventKind::ScriptExec {
                script_path,
                interpreter,
                paused,
            } => {
                writeln!(
                    text,
                    "  [{ts}] pid={pid} SCRIPT {script_path} interpreter={interpreter} paused={paused}"
                )
                .ok();
            }
        }
    }

    fn write_correlation_signals(text: &mut String, trace: &CorrelatedTrace) {
        if trace.signals.is_empty() {
            return;
        }

        writeln!(text, "## Correlation Signals").ok();
        for (i, signal) in trace.signals.iter().enumerate() {
            writeln!(
                text,
                "  Signal {}: lineage_match={}, temporal_weight={:.2}, argument_match={:?}",
                i + 1,
                signal.lineage_match,
                signal.temporal_weight,
                signal.argument_match,
            )
            .ok();
        }
        writeln!(text).ok();
    }

    fn write_score_breakdown(text: &mut String, breakdown: &ScoreBreakdown) {
        writeln!(text, "## Score Breakdown").ok();
        writeln!(
            text,
            "Raw score: {:.3}, context modifier: {:.2}, final score: {}",
            breakdown.raw_score, breakdown.context_modifier, breakdown.final_score,
        )
        .ok();

        if !breakdown.indicators.is_empty() {
            writeln!(text, "Indicators:").ok();
            for (indicator, weight) in &breakdown.indicators {
                writeln!(text, "  - {indicator:?}: {weight:.3}").ok();
            }
        }
        writeln!(text).ok();
    }

    // -- Helpers --------------------------------------------------------------

    fn extract_command_and_dir(kind: &EventKind) -> (String, String) {
        match kind {
            EventKind::ProcessExec {
                binary, args, cwd, ..
            } => {
                let cmd = if args.is_empty() {
                    binary.clone()
                } else {
                    args.join(" ")
                };
                (cmd, cwd.clone())
            }
            EventKind::ScriptExec {
                script_path,
                interpreter,
                ..
            } => (
                format!("{interpreter} {script_path}"),
                String::from("(unknown)"),
            ),
            _ => ("(non-exec trigger)".to_string(), "(unknown)".to_string()),
        }
    }
}

// ---------------------------------------------------------------------------
// Context truncation for small models
// ---------------------------------------------------------------------------

/// Maximum number of recent events to keep when truncating for small context
/// models.
const MAX_RECENT_EVENTS: usize = 20;

/// Truncate a message for small-context models (e.g. Ollama with 8k context).
///
/// When the message text exceeds `max_chars` characters (rough 4:1
/// char-to-token ratio, so 4000 chars ~= 1000 tokens), the event timeline is
/// truncated to the most recent [`MAX_RECENT_EVENTS`] events while keeping the
/// trigger context, ancestry, and task sections intact.
///
/// If the message is short enough, it is returned unchanged.
pub fn truncate_for_small_context(message: &Message, max_chars: usize) -> Message {
    // Extract the text from the first Text block.
    let original_text = match message.content.first() {
        Some(ContentBlock::Text { text }) => text,
        _ => return message.clone(),
    };

    // If within budget, return as-is.
    if original_text.len() <= max_chars {
        return message.clone();
    }

    // Split into sections by "## " headings and rebuild with a truncated
    // event timeline.
    let mut sections: Vec<(&str, &str)> = Vec::new();
    let mut rest = original_text.as_str();

    while let Some(pos) = rest.find("## ") {
        // Find the end of this section (start of next heading, or end of string).
        let section_start = pos;
        let after_heading = &rest[pos + 3..];
        let section_end = after_heading
            .find("## ")
            .map(|p| pos + 3 + p)
            .unwrap_or(rest.len());

        // Extract heading name (first line after "## ").
        let heading_line_end = after_heading
            .find('\n')
            .unwrap_or(after_heading.len());
        let heading_name = &after_heading[..heading_line_end];
        let section_body = &rest[section_start..section_end];

        sections.push((heading_name, section_body));
        rest = &rest[section_end..];
    }

    // Rebuild the text, truncating the Event Timeline section.
    let mut truncated = String::with_capacity(max_chars);

    for (heading, body) in &sections {
        if heading.starts_with("Event Timeline") {
            // Truncate: keep the heading and only the last MAX_RECENT_EVENTS
            // event lines.
            truncated.push_str("## Event Timeline\n");

            let lines: Vec<&str> = body.lines().collect();
            // Event lines are indented with "  [" or start with "("
            let event_lines: Vec<&str> = lines
                .iter()
                .filter(|l| l.starts_with("  [") || l.starts_with("  "))
                .copied()
                .collect();

            let total = event_lines.len();
            if total > MAX_RECENT_EVENTS {
                writeln!(
                    truncated,
                    "(truncated: showing {MAX_RECENT_EVENTS} of {total} events)"
                )
                .ok();
                for line in &event_lines[total - MAX_RECENT_EVENTS..] {
                    writeln!(truncated, "{line}").ok();
                }
            } else {
                // No truncation needed for the timeline.
                truncated.push_str(body);
            }
            writeln!(truncated).ok();
        } else {
            truncated.push_str(body);
        }
    }

    Message {
        role: message.role.clone(),
        content: vec![ContentBlock::Text { text: truncated }],
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use uuid::Uuid;
    use watchpost_types::{
        AncestryEntry, ArgumentMatch, CorrelationSignal, Ecosystem, SuspicionScore, TetragonEvent,
    };

    fn make_npm_trace() -> CorrelatedTrace {
        let trigger_event = EnrichedEvent {
            event: TetragonEvent {
                id: Uuid::new_v4(),
                timestamp: Utc::now(),
                kind: EventKind::ProcessExec {
                    binary: "/usr/bin/npm".to_string(),
                    args: vec![
                        "npm".to_string(),
                        "install".to_string(),
                        "lodash".to_string(),
                    ],
                    cwd: "/home/dev/myproject".to_string(),
                    uid: 1000,
                },
                process_id: 5000,
                parent_id: Some(4999),
                policy_name: None,
            },
            ancestry: vec![
                AncestryEntry {
                    pid: 4999,
                    binary_path: "/usr/bin/bash".to_string(),
                    cmdline: "bash".to_string(),
                },
                AncestryEntry {
                    pid: 4000,
                    binary_path: "/usr/bin/gnome-terminal".to_string(),
                    cmdline: "gnome-terminal".to_string(),
                },
            ],
            context: ActionContext::PackageInstall {
                ecosystem: Ecosystem::Npm,
                package_name: Some("lodash".to_string()),
                package_version: Some("4.17.21".to_string()),
                working_dir: "/home/dev/myproject".to_string(),
            },
            provenance: None,
        };

        let event1 = EnrichedEvent {
            event: TetragonEvent {
                id: Uuid::new_v4(),
                timestamp: Utc::now(),
                kind: EventKind::NetworkConnect {
                    dest_ip: "104.16.0.35".to_string(),
                    dest_port: 443,
                    protocol: "tcp".to_string(),
                },
                process_id: 5001,
                parent_id: Some(5000),
                policy_name: Some("npm-network".to_string()),
            },
            ancestry: vec![],
            context: ActionContext::PackageInstall {
                ecosystem: Ecosystem::Npm,
                package_name: Some("lodash".to_string()),
                package_version: Some("4.17.21".to_string()),
                working_dir: "/home/dev/myproject".to_string(),
            },
            provenance: None,
        };

        let event2 = EnrichedEvent {
            event: TetragonEvent {
                id: Uuid::new_v4(),
                timestamp: Utc::now(),
                kind: EventKind::FileAccess {
                    path: "/home/dev/myproject/node_modules/lodash/package.json".to_string(),
                    access_type: watchpost_types::FileAccessType::Write,
                },
                process_id: 5001,
                parent_id: Some(5000),
                policy_name: None,
            },
            ancestry: vec![],
            context: ActionContext::PackageInstall {
                ecosystem: Ecosystem::Npm,
                package_name: Some("lodash".to_string()),
                package_version: Some("4.17.21".to_string()),
                working_dir: "/home/dev/myproject".to_string(),
            },
            provenance: None,
        };

        CorrelatedTrace {
            id: Uuid::new_v4(),
            trigger: Some(trigger_event),
            events: vec![event1, event2],
            signals: vec![CorrelationSignal {
                lineage_match: true,
                temporal_weight: 0.95,
                argument_match: ArgumentMatch::Positive,
            }],
            score: Some(SuspicionScore::new(0.2)),
            context: ActionContext::PackageInstall {
                ecosystem: Ecosystem::Npm,
                package_name: Some("lodash".to_string()),
                package_version: Some("4.17.21".to_string()),
                working_dir: "/home/dev/myproject".to_string(),
            },
        }
    }

    #[test]
    fn build_user_message_for_npm_install() {
        let trace = make_npm_trace();
        let msg = ContextBuilder::build_user_message(&trace, None, None);

        assert_eq!(msg.role, "user");
        assert_eq!(msg.content.len(), 1);

        let text = match &msg.content[0] {
            ContentBlock::Text { text } => text,
            other => panic!("expected Text block, got: {:?}", other),
        };

        // Should contain the command
        assert!(
            text.contains("npm install lodash"),
            "message should contain the npm install command"
        );
        // Should contain event details
        assert!(
            text.contains("104.16.0.35"),
            "message should contain network dest IP"
        );
        assert!(
            text.contains("node_modules/lodash/package.json"),
            "message should contain file access path"
        );
        // Should contain the analysis task
        assert!(
            text.contains("Analyze"),
            "message should contain the analysis task instruction"
        );
        // Should contain ancestry
        assert!(
            text.contains("gnome-terminal"),
            "message should contain process ancestry"
        );
    }

    #[test]
    fn build_user_message_without_profile_works() {
        let trace = make_npm_trace();
        let msg = ContextBuilder::build_user_message(&trace, None, None);

        let text = match &msg.content[0] {
            ContentBlock::Text { text } => text,
            other => panic!("expected Text block, got: {:?}", other),
        };

        // Should NOT contain behavior profile section
        assert!(
            !text.contains("## Behavior Profile"),
            "message without profile should omit profile section"
        );
        // But should still contain the essentials
        assert!(text.contains("## Trigger Context"));
        assert!(text.contains("## Event Timeline"));
        assert!(text.contains("## Task"));
    }

    #[test]
    fn build_user_message_with_profile_and_score() {
        let trace = make_npm_trace();
        let profile = BehaviorProfile {
            context_type: "package_install".to_string(),
            ecosystem: Some(Ecosystem::Npm),
            expected_network: vec![watchpost_types::NetworkExpectation {
                host: Some("registry.npmjs.org".to_string()),
                port: Some(443),
                description: "npm registry".to_string(),
            }],
            expected_children: vec!["node".to_string(), "sh".to_string()],
            expected_file_writes: vec!["node_modules/".to_string()],
            forbidden_file_access: vec!["/etc/shadow".to_string()],
            forbidden_children: vec!["nc".to_string(), "ncat".to_string()],
            forbidden_network: vec![],
        };

        let breakdown = ScoreBreakdown {
            indicators: vec![
                (watchpost_types::ScoreIndicator::NonRegistryNetwork, 0.3),
                (watchpost_types::ScoreIndicator::SensitiveFileRead, 0.1),
            ],
            context_modifier: 1.0,
            raw_score: 0.4,
            final_score: SuspicionScore::new(0.4),
        };

        let msg = ContextBuilder::build_user_message(&trace, Some(&profile), Some(&breakdown));

        let text = match &msg.content[0] {
            ContentBlock::Text { text } => text,
            other => panic!("expected Text block, got: {:?}", other),
        };

        // Should contain profile section
        assert!(text.contains("## Behavior Profile"));
        assert!(text.contains("registry.npmjs.org"));
        assert!(text.contains("/etc/shadow"));
        assert!(text.contains("node"));

        // Should contain score breakdown
        assert!(text.contains("## Score Breakdown"));
        assert!(text.contains("NonRegistryNetwork"));
        assert!(text.contains("SensitiveFileRead"));
    }

    // -- Truncation tests -----------------------------------------------------

    #[test]
    fn truncate_short_message_unchanged() {
        let msg = Message {
            role: "user".to_string(),
            content: vec![ContentBlock::Text {
                text: "Short message".to_string(),
            }],
        };

        let result = truncate_for_small_context(&msg, 1000);
        match &result.content[0] {
            ContentBlock::Text { text } => assert_eq!(text, "Short message"),
            other => panic!("expected Text, got {:?}", other),
        }
    }

    #[test]
    fn truncate_long_message_trims_timeline() {
        // Build a message with many events to exceed the threshold.
        let mut text = String::new();
        writeln!(text, "## Trigger Context").ok();
        writeln!(text, "The user ran `npm install` in `/home/dev`.").ok();
        writeln!(text).ok();
        writeln!(text, "## Event Timeline").ok();
        // Add 30 event lines — more than MAX_RECENT_EVENTS (20).
        for i in 0..30 {
            writeln!(
                text,
                "  [2025-01-01T00:00:{:02}Z] pid=500{} EXEC binary=/usr/bin/node args=[node] cwd=/tmp uid=1000",
                i, i
            )
            .ok();
        }
        writeln!(text).ok();
        writeln!(text, "## Task").ok();
        writeln!(text, "Analyze the above trace.").ok();

        let msg = Message {
            role: "user".to_string(),
            content: vec![ContentBlock::Text { text }],
        };

        // Use a very small max_chars to force truncation.
        let result = truncate_for_small_context(&msg, 100);
        let result_text = match &result.content[0] {
            ContentBlock::Text { text } => text,
            other => panic!("expected Text, got {:?}", other),
        };

        // Should still contain the trigger and task sections.
        assert!(
            result_text.contains("## Trigger Context"),
            "truncated message should keep trigger context"
        );
        assert!(
            result_text.contains("## Task"),
            "truncated message should keep task section"
        );
        // Should contain the truncation notice.
        assert!(
            result_text.contains("truncated"),
            "truncated message should mention truncation"
        );
        // Should contain event 29 (last) but not event 0 (first).
        assert!(
            result_text.contains("pid=50029"),
            "truncated message should contain the most recent event"
        );
        assert!(
            !result_text.contains("pid=5000 "),
            "truncated message should not contain the oldest event"
        );
    }

    #[test]
    fn truncate_non_text_message_unchanged() {
        let msg = Message {
            role: "user".to_string(),
            content: vec![ContentBlock::ToolResult {
                tool_use_id: "t1".to_string(),
                content: "some result".to_string(),
            }],
        };

        let result = truncate_for_small_context(&msg, 10);
        // Should return the message unchanged since first block isn't Text.
        assert_eq!(result.content.len(), 1);
        match &result.content[0] {
            ContentBlock::ToolResult {
                tool_use_id,
                content,
            } => {
                assert_eq!(tool_use_id, "t1");
                assert_eq!(content, "some result");
            }
            other => panic!("expected ToolResult, got {:?}", other),
        }
    }
}
