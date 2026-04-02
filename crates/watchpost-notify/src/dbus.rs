use std::collections::HashMap;

use anyhow::Result;
use tracing::{info, warn};
use watchpost_types::{Classification, RecommendedAction, Verdict};

/// Sends desktop notifications via D-Bus org.freedesktop.Notifications.
///
/// When disabled, all notification methods are no-ops.
/// When enabled, D-Bus failures are logged as warnings but never propagated
/// as fatal errors — the event log is the primary output, notifications
/// are best-effort.
pub struct DesktopNotifier {
    enabled: bool,
}

impl DesktopNotifier {
    /// Create a new notifier. If `enabled` is false, all notify calls
    /// silently succeed without contacting D-Bus.
    pub fn new(enabled: bool) -> Self {
        Self { enabled }
    }

    /// Returns true if the verdict warrants a desktop notification:
    /// recommended action is Block OR classification is Malicious.
    pub fn should_notify(verdict: &Verdict) -> bool {
        verdict.recommended_action == RecommendedAction::Block
            || verdict.classification == Classification::Malicious
    }

    /// Send a "Blocked" desktop notification for a blocked process.
    pub async fn notify_blocked(&self, verdict: &Verdict) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }

        let summary = format!("Blocked: {}", truncate(&verdict.explanation, 60));
        let body = &verdict.explanation;
        let actions = &["undo", "Undo", "details", "Details"];

        info!(
            trace_id = %verdict.trace_id,
            "Sending blocked notification: {}",
            summary
        );

        if let Err(e) = send_notification(&summary, body, actions, 2).await {
            warn!(
                trace_id = %verdict.trace_id,
                "Failed to send D-Bus notification: {:#}",
                e
            );
        }

        Ok(())
    }

    /// Send a "Threat" desktop notification for a killed process.
    pub async fn notify_threat(&self, verdict: &Verdict) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }

        let summary = format!("Threat: {}", truncate(&verdict.explanation, 60));
        let body = "Process killed.";
        let actions = &["details", "Details"];

        info!(
            trace_id = %verdict.trace_id,
            "Sending threat notification: {}",
            summary
        );

        if let Err(e) = send_notification(&summary, body, actions, 2).await {
            warn!(
                trace_id = %verdict.trace_id,
                "Failed to send D-Bus notification: {:#}",
                e
            );
        }

        Ok(())
    }
}

/// Truncate a string to at most `max_len` characters, appending "..." if truncated.
fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_owned()
    } else {
        let truncated: String = s.chars().take(max_len.saturating_sub(3)).collect();
        format!("{truncated}...")
    }
}

/// Send a notification via the D-Bus org.freedesktop.Notifications interface.
///
/// Parameters follow the freedesktop Notification spec:
/// - `summary`: short title
/// - `body`: longer description
/// - `actions`: alternating id/label pairs, e.g. `["undo", "Undo"]`
/// - `urgency`: 0=low, 1=normal, 2=critical
async fn send_notification(
    summary: &str,
    body: &str,
    actions: &[&str],
    urgency: u8,
) -> Result<()> {
    let connection = zbus::Connection::session().await?;

    let proxy: zbus::Proxy<'_> = zbus::proxy::Builder::new(&connection)
        .interface("org.freedesktop.Notifications")?
        .path("/org/freedesktop/Notifications")?
        .destination("org.freedesktop.Notifications")?
        .build()
        .await?;

    let mut hints = HashMap::new();
    hints.insert("urgency", zbus::zvariant::Value::from(urgency));

    let _: (u32,) = proxy
        .call(
            "Notify",
            &(
                "watchpost",
                0u32,
                "security-high",
                summary,
                body,
                actions,
                &hints,
                -1i32,
            ),
        )
        .await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use uuid::Uuid;
    use watchpost_types::Confidence;

    fn make_verdict(
        classification: Classification,
        action: RecommendedAction,
        confidence: f64,
    ) -> Verdict {
        Verdict {
            id: Uuid::new_v4(),
            trace_id: Uuid::new_v4(),
            classification,
            confidence: Confidence::new(confidence),
            recommended_action: action,
            explanation: "Test explanation for verdict".to_owned(),
            profile_violations: vec![],
            timestamp: Utc::now(),
        }
    }

    #[test]
    fn should_notify_true_for_block_action() {
        let verdict = make_verdict(
            Classification::Suspicious,
            RecommendedAction::Block,
            0.9,
        );
        assert!(DesktopNotifier::should_notify(&verdict));
    }

    #[test]
    fn should_notify_true_for_malicious_classification() {
        let verdict = make_verdict(
            Classification::Malicious,
            RecommendedAction::Notify,
            0.95,
        );
        assert!(DesktopNotifier::should_notify(&verdict));
    }

    #[test]
    fn should_notify_false_for_benign_allow() {
        let verdict = make_verdict(
            Classification::Benign,
            RecommendedAction::Allow,
            0.99,
        );
        assert!(!DesktopNotifier::should_notify(&verdict));
    }

    #[tokio::test]
    async fn disabled_notifier_is_noop() {
        let notifier = DesktopNotifier::new(false);
        let verdict = make_verdict(
            Classification::Malicious,
            RecommendedAction::Block,
            1.0,
        );

        // These should succeed without attempting D-Bus
        notifier.notify_blocked(&verdict).await.unwrap();
        notifier.notify_threat(&verdict).await.unwrap();
    }

    #[test]
    fn truncate_short_string() {
        assert_eq!(truncate("hello", 60), "hello");
    }

    #[test]
    fn truncate_long_string() {
        let long = "a".repeat(100);
        let result = truncate(&long, 60);
        assert!(result.len() <= 60);
        assert!(result.ends_with("..."));
    }

    #[test]
    fn should_notify_true_for_malicious_block() {
        let verdict = make_verdict(
            Classification::Malicious,
            RecommendedAction::Block,
            1.0,
        );
        assert!(DesktopNotifier::should_notify(&verdict));
    }

    #[test]
    fn should_notify_false_for_suspicious_notify() {
        let verdict = make_verdict(
            Classification::Suspicious,
            RecommendedAction::Notify,
            0.7,
        );
        assert!(!DesktopNotifier::should_notify(&verdict));
    }
}
