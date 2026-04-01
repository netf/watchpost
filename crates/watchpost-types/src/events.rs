use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::context::ActionContext;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FileAccessType {
    Read,
    Write,
}

/// The kind of kernel event observed via Tetragon.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EventKind {
    ProcessExec {
        binary: String,
        args: Vec<String>,
        cwd: String,
        uid: u32,
    },
    ProcessExit {
        exit_code: i32,
        signal: Option<i32>,
    },
    FileAccess {
        path: String,
        access_type: FileAccessType,
    },
    NetworkConnect {
        dest_ip: String,
        dest_port: u16,
        protocol: String,
    },
    PrivilegeChange {
        old_uid: u32,
        new_uid: u32,
        function_name: String,
    },
    DnsQuery {
        query_name: String,
        query_type: String,
    },
    ScriptExec {
        script_path: String,
        interpreter: String,
        paused: bool,
    },
}

/// A raw event received from the Tetragon gRPC stream.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TetragonEvent {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub kind: EventKind,
    pub process_id: u32,
    pub parent_id: Option<u32>,
    pub policy_name: Option<String>,
}

impl TetragonEvent {
    /// Returns the binary path for this event, extracted from the event kind.
    pub fn binary(&self) -> Option<&str> {
        match &self.kind {
            EventKind::ProcessExec { binary, .. } => Some(binary),
            EventKind::ScriptExec { script_path, .. } => Some(script_path),
            _ => None,
        }
    }
}

/// A single entry in a process ancestry chain.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AncestryEntry {
    pub pid: u32,
    pub binary_path: String,
    pub cmdline: String,
}

/// An event enriched with process ancestry and inferred action context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrichedEvent {
    pub event: TetragonEvent,
    pub ancestry: Vec<AncestryEntry>,
    pub context: ActionContext,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use uuid::Uuid;

    fn sample_enriched_event() -> EnrichedEvent {
        EnrichedEvent {
            event: TetragonEvent {
                id: Uuid::new_v4(),
                timestamp: Utc::now(),
                kind: EventKind::ProcessExec {
                    binary: "/usr/bin/curl".to_owned(),
                    args: vec!["curl".to_owned(), "https://evil.com".to_owned()],
                    cwd: "/tmp".to_owned(),
                    uid: 1000,
                },
                process_id: 12345,
                parent_id: Some(12344),
                policy_name: Some("npm-network".to_owned()),
            },
            ancestry: vec![
                AncestryEntry {
                    pid: 12344,
                    binary_path: "/usr/bin/node".to_owned(),
                    cmdline: "node install.js".to_owned(),
                },
                AncestryEntry {
                    pid: 12300,
                    binary_path: "/usr/bin/npm".to_owned(),
                    cmdline: "npm install evil-package".to_owned(),
                },
            ],
            context: ActionContext::PackageInstall {
                ecosystem: crate::context::Ecosystem::Npm,
                package_name: Some("evil-package".to_owned()),
                package_version: Some("1.0.0".to_owned()),
                working_dir: "/home/user/project".to_owned(),
            },
        }
    }

    #[test]
    fn enriched_event_json_round_trip() {
        let event = sample_enriched_event();
        let json = serde_json::to_string(&event).expect("serialize");
        let deserialized: EnrichedEvent = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(deserialized.event.id, event.event.id);
        assert_eq!(deserialized.event.process_id, event.event.process_id);
        assert_eq!(deserialized.ancestry.len(), 2);
        assert_eq!(deserialized.ancestry[0].pid, 12344);
        assert_eq!(
            deserialized.context,
            ActionContext::PackageInstall {
                ecosystem: crate::context::Ecosystem::Npm,
                package_name: Some("evil-package".to_owned()),
                package_version: Some("1.0.0".to_owned()),
                working_dir: "/home/user/project".to_owned(),
            }
        );
    }

    #[test]
    fn binary_accessor_works() {
        let event = sample_enriched_event();
        assert_eq!(event.event.binary(), Some("/usr/bin/curl"));
    }

    #[test]
    fn enriched_event_json_contains_expected_fields() {
        let event = sample_enriched_event();
        let json = serde_json::to_string_pretty(&event).expect("serialize");
        assert!(json.contains("process_exec"));
        assert!(json.contains("evil.com"));
        assert!(json.contains("npm"));
    }
}
