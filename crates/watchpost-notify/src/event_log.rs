use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use rusqlite::{params, Connection};
use uuid::Uuid;
use watchpost_types::{
    ActionContext, Classification, Confidence, EnrichedEvent, EventKind, RecommendedAction, Verdict,
};

/// Filter criteria for querying stored events.
pub struct EventFilter {
    pub since: Option<DateTime<Utc>>,
    pub until: Option<DateTime<Utc>>,
    pub kind: Option<String>,
    pub classification: Option<String>,
    pub binary: Option<String>,
    pub context: Option<String>,
    pub limit: usize,
}

impl Default for EventFilter {
    fn default() -> Self {
        Self {
            since: None,
            until: None,
            kind: None,
            classification: None,
            binary: None,
            context: None,
            limit: 100,
        }
    }
}

/// SQLite-backed event and verdict store with WAL mode.
pub struct EventLog {
    conn: Connection,
}

impl EventLog {
    /// Open or create a SQLite database at the given path.
    pub fn open(path: &std::path::Path) -> Result<Self> {
        let conn = Connection::open(path)
            .with_context(|| format!("failed to open SQLite database at {}", path.display()))?;
        Self::init(conn)
    }

    /// Open an in-memory SQLite database (for testing).
    pub fn open_in_memory() -> Result<Self> {
        let conn =
            Connection::open_in_memory().context("failed to open in-memory SQLite database")?;
        Self::init(conn)
    }

    fn init(conn: Connection) -> Result<Self> {
        conn.execute_batch("PRAGMA journal_mode = WAL;")
            .context("failed to set WAL journal mode")?;
        conn.execute_batch("PRAGMA synchronous = NORMAL;")
            .context("failed to set synchronous mode")?;

        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS events (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                kind TEXT NOT NULL,
                process_id INTEGER,
                binary_path TEXT,
                context_type TEXT,
                severity TEXT,
                raw_json TEXT NOT NULL,
                created_at TEXT DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS verdicts (
                id TEXT PRIMARY KEY,
                trace_id TEXT NOT NULL,
                classification TEXT NOT NULL,
                confidence REAL NOT NULL,
                recommended_action TEXT NOT NULL,
                explanation TEXT,
                profile_violations TEXT,
                source TEXT NOT NULL,
                created_at TEXT DEFAULT (datetime('now'))
            );

            CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
            CREATE INDEX IF NOT EXISTS idx_events_kind ON events(kind);
            CREATE INDEX IF NOT EXISTS idx_verdicts_trace_id ON verdicts(trace_id);
            CREATE INDEX IF NOT EXISTS idx_verdicts_classification ON verdicts(classification);
            ",
        )
        .context("failed to create tables")?;

        Ok(Self { conn })
    }

    /// Insert an enriched event into the events table.
    pub fn insert_event(&self, event: &EnrichedEvent) -> Result<()> {
        let raw_json =
            serde_json::to_string(event).context("failed to serialize EnrichedEvent")?;

        let kind = event_kind_name(&event.event.kind);
        let binary_path = event.event.binary().map(|s| s.to_owned());
        let context_type = action_context_name(&event.context);
        let timestamp = event.event.timestamp.to_rfc3339();

        self.conn
            .execute(
                "INSERT INTO events (id, timestamp, kind, process_id, binary_path, context_type, severity, raw_json)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    event.event.id.to_string(),
                    timestamp,
                    kind,
                    event.event.process_id,
                    binary_path,
                    context_type,
                    Option::<String>::None,
                    raw_json,
                ],
            )
            .context("failed to insert event")?;

        Ok(())
    }

    /// Insert a verdict into the verdicts table.
    pub fn insert_verdict(&self, verdict: &Verdict, source: &str) -> Result<()> {
        let classification =
            serde_json::to_value(&verdict.classification)
                .context("failed to serialize classification")?;
        let recommended_action =
            serde_json::to_value(&verdict.recommended_action)
                .context("failed to serialize recommended_action")?;
        let profile_violations = serde_json::to_string(&verdict.profile_violations)
            .context("failed to serialize profile_violations")?;

        self.conn
            .execute(
                "INSERT INTO verdicts (id, trace_id, classification, confidence, recommended_action, explanation, profile_violations, source)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    verdict.id.to_string(),
                    verdict.trace_id.to_string(),
                    classification.as_str().unwrap_or("unknown"),
                    verdict.confidence.value(),
                    recommended_action.as_str().unwrap_or("unknown"),
                    verdict.explanation,
                    profile_violations,
                    source,
                ],
            )
            .context("failed to insert verdict")?;

        Ok(())
    }

    /// Query events matching the given filter, ordered by timestamp descending.
    pub fn query_events(&self, filter: &EventFilter) -> Result<Vec<EnrichedEvent>> {
        let mut clauses: Vec<String> = Vec::new();
        let mut param_values: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();

        if let Some(ref since) = filter.since {
            clauses.push(format!("timestamp >= ?{}", param_values.len() + 1));
            param_values.push(Box::new(since.to_rfc3339()));
        }
        if let Some(ref until) = filter.until {
            clauses.push(format!("timestamp <= ?{}", param_values.len() + 1));
            param_values.push(Box::new(until.to_rfc3339()));
        }
        if let Some(ref kind) = filter.kind {
            clauses.push(format!("kind = ?{}", param_values.len() + 1));
            param_values.push(Box::new(kind.clone()));
        }
        if let Some(ref binary) = filter.binary {
            clauses.push(format!("binary_path = ?{}", param_values.len() + 1));
            param_values.push(Box::new(binary.clone()));
        }
        if let Some(ref context) = filter.context {
            clauses.push(format!("context_type = ?{}", param_values.len() + 1));
            param_values.push(Box::new(context.clone()));
        }

        let where_clause = if clauses.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", clauses.join(" AND "))
        };

        let sql = format!(
            "SELECT raw_json FROM events {} ORDER BY timestamp DESC LIMIT ?{}",
            where_clause,
            param_values.len() + 1
        );

        param_values.push(Box::new(filter.limit as i64));

        let params_refs: Vec<&dyn rusqlite::types::ToSql> =
            param_values.iter().map(|b| b.as_ref()).collect();

        let mut stmt = self.conn.prepare(&sql).context("failed to prepare query")?;
        let rows = stmt
            .query_map(params_refs.as_slice(), |row| {
                let raw_json: String = row.get(0)?;
                Ok(raw_json)
            })
            .context("failed to execute query")?;

        let mut results = Vec::new();
        for row in rows {
            let raw_json = row.context("failed to read row")?;
            let event: EnrichedEvent =
                serde_json::from_str(&raw_json).context("failed to deserialize EnrichedEvent")?;
            results.push(event);
        }

        Ok(results)
    }

    /// Query a single verdict by trace_id.
    pub fn query_verdict(&self, trace_id: &Uuid) -> Result<Option<Verdict>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, trace_id, classification, confidence, recommended_action, explanation, profile_violations
                 FROM verdicts WHERE trace_id = ?1 LIMIT 1",
            )
            .context("failed to prepare verdict query")?;

        let mut rows = stmt
            .query_map(params![trace_id.to_string()], |row| {
                let id: String = row.get(0)?;
                let trace_id: String = row.get(1)?;
                let classification: String = row.get(2)?;
                let confidence: f64 = row.get(3)?;
                let recommended_action: String = row.get(4)?;
                let explanation: String = row.get(5)?;
                let profile_violations: String = row.get(6)?;
                Ok((
                    id,
                    trace_id,
                    classification,
                    confidence,
                    recommended_action,
                    explanation,
                    profile_violations,
                ))
            })
            .context("failed to execute verdict query")?;

        match rows.next() {
            Some(row) => {
                let (id, trace_id, classification, confidence, recommended_action, explanation, profile_violations) =
                    row.context("failed to read verdict row")?;

                let id: Uuid = id.parse().context("invalid verdict id")?;
                let trace_id: Uuid = trace_id.parse().context("invalid trace_id")?;
                let classification: Classification =
                    serde_json::from_value(serde_json::Value::String(classification))
                        .context("invalid classification")?;
                let recommended_action: RecommendedAction =
                    serde_json::from_value(serde_json::Value::String(recommended_action))
                        .context("invalid recommended_action")?;
                let profile_violations: Vec<String> =
                    serde_json::from_str(&profile_violations)
                        .context("invalid profile_violations")?;

                Ok(Some(Verdict {
                    id,
                    trace_id,
                    classification,
                    confidence: Confidence::new(confidence),
                    recommended_action,
                    explanation,
                    profile_violations,
                    timestamp: Utc::now(),
                }))
            }
            None => Ok(None),
        }
    }
}

/// Extract a snake_case name from an EventKind variant.
fn event_kind_name(kind: &EventKind) -> &'static str {
    match kind {
        EventKind::ProcessExec { .. } => "process_exec",
        EventKind::ProcessExit { .. } => "process_exit",
        EventKind::FileAccess { .. } => "file_access",
        EventKind::NetworkConnect { .. } => "network_connect",
        EventKind::PrivilegeChange { .. } => "privilege_change",
        EventKind::DnsQuery { .. } => "dns_query",
        EventKind::ScriptExec { .. } => "script_exec",
    }
}

/// Extract a snake_case name from an ActionContext variant.
fn action_context_name(ctx: &ActionContext) -> &'static str {
    match ctx {
        ActionContext::PackageInstall { .. } => "package_install",
        ActionContext::Build { .. } => "build",
        ActionContext::FlatpakApp { .. } => "flatpak_app",
        ActionContext::ToolboxSession { .. } => "toolbox_session",
        ActionContext::ShellCommand { .. } => "shell_command",
        ActionContext::IdeOperation { .. } => "ide_operation",
        ActionContext::Unknown => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use uuid::Uuid;
    use watchpost_types::{AncestryEntry, Ecosystem, FileAccessType, TetragonEvent};

    fn make_event(kind: EventKind, context: ActionContext) -> EnrichedEvent {
        EnrichedEvent {
            event: TetragonEvent {
                id: Uuid::new_v4(),
                timestamp: Utc::now(),
                kind,
                process_id: 1234,
                parent_id: Some(1233),
                policy_name: Some("test-policy".to_owned()),
            },
            ancestry: vec![AncestryEntry {
                pid: 1233,
                binary_path: "/usr/bin/bash".to_owned(),
                cmdline: "bash".to_owned(),
            }],
            context,
        }
    }

    fn make_process_exec_event() -> EnrichedEvent {
        make_event(
            EventKind::ProcessExec {
                binary: "/usr/bin/curl".to_owned(),
                args: vec!["curl".to_owned(), "https://example.com".to_owned()],
                cwd: "/tmp".to_owned(),
                uid: 1000,
            },
            ActionContext::PackageInstall {
                ecosystem: Ecosystem::Npm,
                package_name: Some("test-pkg".to_owned()),
                package_version: Some("1.0.0".to_owned()),
                working_dir: "/home/user/project".to_owned(),
            },
        )
    }

    fn make_file_access_event() -> EnrichedEvent {
        make_event(
            EventKind::FileAccess {
                path: "/etc/passwd".to_owned(),
                access_type: FileAccessType::Read,
            },
            ActionContext::ShellCommand {
                tty: Some("/dev/pts/0".to_owned()),
            },
        )
    }

    fn make_network_connect_event() -> EnrichedEvent {
        make_event(
            EventKind::NetworkConnect {
                dest_ip: "1.2.3.4".to_owned(),
                dest_port: 443,
                protocol: "tcp".to_owned(),
            },
            ActionContext::Build {
                toolchain: "cargo".to_owned(),
                working_dir: "/home/user/project".to_owned(),
            },
        )
    }

    fn make_verdict(trace_id: Uuid) -> Verdict {
        Verdict {
            id: Uuid::new_v4(),
            trace_id,
            classification: Classification::Suspicious,
            confidence: Confidence::new(0.85),
            recommended_action: RecommendedAction::Notify,
            explanation: "Suspicious network activity during package install".to_owned(),
            profile_violations: vec!["network_access".to_owned(), "tmp_exec".to_owned()],
            timestamp: Utc::now(),
        }
    }

    #[test]
    fn insert_and_query_event() {
        let log = EventLog::open_in_memory().unwrap();
        let event = make_process_exec_event();
        let original_id = event.event.id;

        log.insert_event(&event).unwrap();

        let results = log.query_events(&EventFilter::default()).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].event.id, original_id);
        assert_eq!(results[0].event.process_id, 1234);
        assert_eq!(results[0].ancestry.len(), 1);
        assert_eq!(results[0].ancestry[0].pid, 1233);
    }

    #[test]
    fn filter_by_kind() {
        let log = EventLog::open_in_memory().unwrap();

        log.insert_event(&make_process_exec_event()).unwrap();
        log.insert_event(&make_file_access_event()).unwrap();
        log.insert_event(&make_network_connect_event()).unwrap();

        let filter = EventFilter {
            kind: Some("file_access".to_owned()),
            ..Default::default()
        };
        let results = log.query_events(&filter).unwrap();
        assert_eq!(results.len(), 1);
        match &results[0].event.kind {
            EventKind::FileAccess { path, .. } => assert_eq!(path, "/etc/passwd"),
            other => panic!("expected FileAccess, got {:?}", other),
        }
    }

    #[test]
    fn filter_by_since() {
        let log = EventLog::open_in_memory().unwrap();

        // Insert an old event with a timestamp 10 minutes ago.
        let mut old_event = make_process_exec_event();
        old_event.event.timestamp = Utc::now() - Duration::minutes(10);
        log.insert_event(&old_event).unwrap();

        // Insert a recent event.
        let recent_event = make_file_access_event();
        log.insert_event(&recent_event).unwrap();

        let filter = EventFilter {
            since: Some(Utc::now() - Duration::minutes(5)),
            ..Default::default()
        };
        let results = log.query_events(&filter).unwrap();
        assert_eq!(results.len(), 1);
        match &results[0].event.kind {
            EventKind::FileAccess { .. } => {}
            other => panic!("expected FileAccess, got {:?}", other),
        }
    }

    #[test]
    fn insert_and_query_verdict() {
        let log = EventLog::open_in_memory().unwrap();
        let trace_id = Uuid::new_v4();
        let verdict = make_verdict(trace_id);
        let original_id = verdict.id;

        log.insert_verdict(&verdict, "rules").unwrap();

        let result = log.query_verdict(&trace_id).unwrap();
        assert!(result.is_some());
        let v = result.unwrap();
        assert_eq!(v.id, original_id);
        assert_eq!(v.trace_id, trace_id);
        assert_eq!(v.classification, Classification::Suspicious);
        assert!((v.confidence.value() - 0.85).abs() < f64::EPSILON);
        assert_eq!(v.recommended_action, RecommendedAction::Notify);
        assert_eq!(
            v.explanation,
            "Suspicious network activity during package install"
        );
        assert_eq!(v.profile_violations.len(), 2);
        assert_eq!(v.profile_violations[0], "network_access");
        assert_eq!(v.profile_violations[1], "tmp_exec");
    }

    #[test]
    fn empty_database_returns_empty_vec() {
        let log = EventLog::open_in_memory().unwrap();
        let results = log.query_events(&EventFilter::default()).unwrap();
        assert!(results.is_empty());
    }
}
