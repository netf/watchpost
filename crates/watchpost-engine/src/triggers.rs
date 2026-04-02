use chrono::{DateTime, Utc};
use dashmap::DashMap;
use uuid::Uuid;
use watchpost_types::{ActionContext, EnrichedEvent};

/// An active trigger representing a tracked user action (package install,
/// build, or Flatpak app launch) whose child processes should be monitored.
#[derive(Debug, Clone)]
pub struct ActiveTrigger {
    pub id: Uuid,
    pub event: EnrichedEvent,
    pub process_pid: u32,
    pub start_time: DateTime<Utc>,
    pub session_active: bool,
}

/// Registry of active triggers, indexed by both trigger ID and root PID for
/// fast lookups from either direction.
pub struct ActiveTriggerRegistry {
    triggers: DashMap<Uuid, ActiveTrigger>,
    pid_to_trigger: DashMap<u32, Uuid>,
}

impl ActiveTriggerRegistry {
    pub fn new() -> Self {
        Self {
            triggers: DashMap::new(),
            pid_to_trigger: DashMap::new(),
        }
    }

    /// Register a trigger for an enriched event if its context is one of the
    /// tracked types (PackageInstall, Build, FlatpakApp). Returns the trigger
    /// ID on success, or `None` if the context is not tracked.
    pub fn register(&self, event: &EnrichedEvent) -> Option<Uuid> {
        match &event.context {
            ActionContext::PackageInstall { .. }
            | ActionContext::Build { .. }
            | ActionContext::FlatpakApp { .. } => {}
            _ => return None,
        }

        let id = Uuid::new_v4();
        let trigger = ActiveTrigger {
            id,
            event: event.clone(),
            process_pid: event.event.process_id,
            start_time: event.event.timestamp,
            session_active: true,
        };

        self.pid_to_trigger.insert(trigger.process_pid, id);
        self.triggers.insert(id, trigger);
        Some(id)
    }

    /// Mark the trigger for the given root PID as inactive (called when the
    /// root process exits).
    pub fn deactivate_session(&self, pid: u32) {
        if let Some(trigger_id) = self.pid_to_trigger.get(&pid) {
            if let Some(mut trigger) = self.triggers.get_mut(&*trigger_id) {
                trigger.session_active = false;
            }
        }
    }

    /// Return clones of all triggers whose sessions are still active.
    pub fn get_active_triggers(&self) -> Vec<ActiveTrigger> {
        self.triggers
            .iter()
            .filter(|entry| entry.session_active)
            .map(|entry| entry.value().clone())
            .collect()
    }

    /// Look up a trigger by root PID and return a clone if found.
    pub fn get_trigger_for_pid(&self, pid: u32) -> Option<ActiveTrigger> {
        let trigger_id = self.pid_to_trigger.get(&pid)?;
        self.triggers.get(&*trigger_id).map(|t| t.value().clone())
    }

    /// Remove triggers that were started more than `max_age` ago.
    pub fn cleanup_expired(&self, max_age: std::time::Duration) {
        let cutoff = Utc::now() - chrono::TimeDelta::from_std(max_age).unwrap_or(chrono::TimeDelta::MAX);
        let expired: Vec<(Uuid, u32)> = self
            .triggers
            .iter()
            .filter(|entry| entry.start_time < cutoff)
            .map(|entry| (entry.id, entry.process_pid))
            .collect();

        for (id, pid) in expired {
            self.triggers.remove(&id);
            self.pid_to_trigger.remove(&pid);
        }
    }
}

impl Default for ActiveTriggerRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use watchpost_types::*;

    fn make_event(context: ActionContext, pid: u32) -> EnrichedEvent {
        EnrichedEvent {
            event: TetragonEvent {
                id: Uuid::new_v4(),
                timestamp: Utc::now(),
                kind: EventKind::ProcessExec {
                    binary: "/usr/bin/npm".into(),
                    args: vec!["npm".into(), "install".into()],
                    cwd: "/home/user".into(),
                    uid: 1000,
                },
                process_id: pid,
                parent_id: Some(1),
                policy_name: None,
            },
            ancestry: vec![],
            context,
        }
    }

    #[test]
    fn register_package_install_returns_id() {
        let registry = ActiveTriggerRegistry::new();
        let event = make_event(
            ActionContext::PackageInstall {
                ecosystem: Ecosystem::Npm,
                package_name: Some("lodash".into()),
                package_version: None,
                working_dir: "/tmp".into(),
            },
            100,
        );
        let id = registry.register(&event);
        assert!(id.is_some());
    }

    #[test]
    fn register_shell_command_returns_none() {
        let registry = ActiveTriggerRegistry::new();
        let event = make_event(
            ActionContext::ShellCommand {
                tty: Some("/dev/pts/0".into()),
            },
            101,
        );
        let id = registry.register(&event);
        assert!(id.is_none());
    }

    #[test]
    fn deactivate_session_removes_from_active() {
        let registry = ActiveTriggerRegistry::new();
        let event = make_event(
            ActionContext::Build {
                toolchain: "cargo".into(),
                working_dir: "/tmp".into(),
            },
            200,
        );
        registry.register(&event);
        assert_eq!(registry.get_active_triggers().len(), 1);

        registry.deactivate_session(200);
        assert_eq!(registry.get_active_triggers().len(), 0);
    }

    #[test]
    fn get_trigger_for_pid_returns_correct_trigger() {
        let registry = ActiveTriggerRegistry::new();
        let event = make_event(
            ActionContext::FlatpakApp {
                app_id: "org.example.App".into(),
                permissions: vec![],
            },
            300,
        );
        let id = registry.register(&event).unwrap();
        let trigger = registry.get_trigger_for_pid(300).unwrap();
        assert_eq!(trigger.id, id);
        assert_eq!(trigger.process_pid, 300);
    }

    #[test]
    fn cleanup_expired_removes_old_triggers() {
        let registry = ActiveTriggerRegistry::new();
        // Create an event with a timestamp in the past.
        let mut event = make_event(
            ActionContext::PackageInstall {
                ecosystem: Ecosystem::Cargo,
                package_name: Some("serde".into()),
                package_version: None,
                working_dir: "/tmp".into(),
            },
            400,
        );
        event.event.timestamp = Utc::now() - chrono::Duration::hours(2);
        registry.register(&event);
        assert_eq!(registry.get_active_triggers().len(), 1);

        // Cleanup with a 1-hour max age should remove the trigger.
        registry.cleanup_expired(std::time::Duration::from_secs(3600));
        assert!(registry.get_trigger_for_pid(400).is_none());
    }
}
