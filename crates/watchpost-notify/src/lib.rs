pub mod dbus;
pub mod event_log;
pub mod webhook;

use std::path::Path;

use anyhow::{Context, Result};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};
use watchpost_types::{Classification, CorrelatedTrace, Verdict};

use crate::dbus::DesktopNotifier;
use crate::event_log::EventLog;
use crate::webhook::WebhookForwarder;

/// Central notification hub: persists verdicts and traces to the event log
/// and sends desktop notifications for actionable verdicts.
pub struct Notifier {
    desktop: DesktopNotifier,
    event_log: EventLog,
    webhook: Option<WebhookForwarder>,
}

impl Notifier {
    /// Create a new Notifier.
    ///
    /// - `desktop_enabled`: whether to send D-Bus desktop notifications
    /// - `db_path`: path to the SQLite database for the event log
    /// - `webhook_url`: optional URL for webhook forwarding of verdicts
    /// - `webhook_auth_header`: optional Authorization header value (e.g. "Bearer sk-...")
    pub fn new(
        desktop_enabled: bool,
        db_path: &Path,
        webhook_url: Option<String>,
        webhook_auth_header: Option<String>,
    ) -> Result<Self> {
        let event_log =
            EventLog::open(db_path).context("failed to open event log for Notifier")?;
        let desktop = DesktopNotifier::new(desktop_enabled);

        let webhook = webhook_url.map(|url| {
            info!(url = %url, "Webhook forwarding enabled");
            WebhookForwarder::new(url, webhook_auth_header)
        });

        Ok(Self {
            desktop,
            event_log,
            webhook,
        })
    }

    /// Run the notification loop, consuming verdicts and log traces from
    /// their respective channels.
    ///
    /// - Verdicts are persisted and may trigger desktop notifications.
    /// - Correlated traces (low-score, for logging) are persisted without notification.
    /// - Returns `Ok(())` when both channels are closed.
    pub async fn run(
        self,
        mut verdict_rx: mpsc::Receiver<Verdict>,
        mut log_rx: mpsc::Receiver<CorrelatedTrace>,
    ) -> Result<()> {
        info!("Notifier started");

        loop {
            tokio::select! {
                biased;

                verdict = verdict_rx.recv() => {
                    match verdict {
                        Some(verdict) => {
                            self.handle_verdict(&verdict).await;
                        }
                        None => {
                            debug!("Verdict channel closed");
                            // Drain remaining log traces before exiting
                            while let Ok(trace) = log_rx.try_recv() {
                                self.handle_trace(&trace);
                            }
                            break;
                        }
                    }
                }

                trace = log_rx.recv() => {
                    match trace {
                        Some(trace) => {
                            self.handle_trace(&trace);
                        }
                        None => {
                            debug!("Log trace channel closed");
                            // Drain remaining verdicts before exiting
                            while let Ok(verdict) = verdict_rx.try_recv() {
                                self.handle_verdict(&verdict).await;
                            }
                            break;
                        }
                    }
                }
            }
        }

        info!("Notifier shutting down");
        Ok(())
    }

    async fn handle_verdict(&self, verdict: &Verdict) {
        let source = infer_source(verdict);
        if let Err(e) = self.event_log.insert_verdict(verdict, source) {
            warn!(
                trace_id = %verdict.trace_id,
                "Failed to persist verdict: {:#}", e
            );
        }

        if DesktopNotifier::should_notify(verdict) {
            if verdict.classification == Classification::Malicious {
                let _ = self.desktop.notify_threat(verdict).await;
            } else {
                let _ = self.desktop.notify_blocked(verdict).await;
            }
        }

        // Best-effort webhook forwarding — errors are logged internally
        if let Some(ref wh) = self.webhook {
            let _ = wh.forward(verdict).await;
        }
    }

    fn handle_trace(&self, trace: &CorrelatedTrace) {
        for event in &trace.events {
            if let Err(e) = self.event_log.insert_event(event) {
                warn!(
                    trace_id = %trace.id,
                    "Failed to persist trace event: {:#}", e
                );
            }
        }
    }
}

/// Infer the verdict source based on confidence.
/// Rules always produce confidence=1.0; the analyzer produces variable confidence.
fn infer_source(verdict: &Verdict) -> &'static str {
    if (verdict.confidence.value() - 1.0).abs() < f64::EPSILON {
        "rules"
    } else {
        "analyzer"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use chrono::Utc;
    use uuid::Uuid;
    use watchpost_types::{Confidence, RecommendedAction};

    #[test]
    fn infer_source_rules_for_confidence_1() {
        let verdict = Verdict {
            id: Uuid::new_v4(),
            trace_id: Uuid::new_v4(),
            classification: Classification::Malicious,
            confidence: Confidence::new(1.0),
            recommended_action: RecommendedAction::Block,
            explanation: "test".to_owned(),
            profile_violations: vec![],
            timestamp: Utc::now(),
        };
        assert_eq!(infer_source(&verdict), "rules");
    }

    #[test]
    fn infer_source_analyzer_for_variable_confidence() {
        let verdict = Verdict {
            id: Uuid::new_v4(),
            trace_id: Uuid::new_v4(),
            classification: Classification::Suspicious,
            confidence: Confidence::new(0.85),
            recommended_action: RecommendedAction::Notify,
            explanation: "test".to_owned(),
            profile_violations: vec![],
            timestamp: Utc::now(),
        };
        assert_eq!(infer_source(&verdict), "analyzer");
    }

    #[test]
    fn notifier_works_without_webhook() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let notifier = Notifier::new(false, tmp.path(), None, None).unwrap();
        assert!(notifier.webhook.is_none());
    }
}
