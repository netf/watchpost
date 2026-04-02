use std::path::Path;

use anyhow::Result;
use chrono::{DateTime, Utc};
use rusqlite::Connection;
use uuid::Uuid;

/// A record of a trigger that persists across daemon restarts.
#[derive(Debug, Clone)]
pub struct PersistentTrigger {
    pub trigger_id: Uuid,
    pub process_pid: u32,
    pub binary: String,
    pub context_type: String,
    pub package_name: Option<String>,
    pub start_time: DateTime<Utc>,
}

/// SQLite-backed persistent window store for long-lived trigger correlation.
///
/// This store allows triggers and their associated events to survive daemon
/// restarts, enabling detection of delayed-execution attacks where a payload
/// fires hours after the initial install trigger.
pub struct PersistentWindowStore {
    conn: Connection,
}

impl PersistentWindowStore {
    /// Open (or create) a persistent window store backed by a SQLite file.
    ///
    /// Enables WAL mode for safe concurrent access and creates the schema if
    /// it does not already exist.
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)?;
        Self::init(conn)
    }

    /// Open an in-memory SQLite store (for testing).
    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        Self::init(conn)
    }

    fn init(conn: Connection) -> Result<Self> {
        conn.execute_batch("PRAGMA journal_mode = WAL;")?;

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS persistent_triggers (
                trigger_id TEXT PRIMARY KEY,
                process_pid INTEGER NOT NULL,
                binary TEXT NOT NULL,
                context_type TEXT NOT NULL,
                package_name TEXT,
                start_time TEXT NOT NULL,
                created_at TEXT DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS persistent_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                trigger_id TEXT NOT NULL,
                event_id TEXT NOT NULL,
                event_kind TEXT NOT NULL,
                process_id INTEGER NOT NULL,
                timestamp TEXT NOT NULL,
                FOREIGN KEY (trigger_id) REFERENCES persistent_triggers(trigger_id)
            );

            CREATE INDEX IF NOT EXISTS idx_persistent_triggers_start
                ON persistent_triggers(start_time);
            CREATE INDEX IF NOT EXISTS idx_persistent_events_trigger
                ON persistent_events(trigger_id);",
        )?;

        Ok(Self { conn })
    }

    /// Persist a trigger record.
    pub fn save_trigger(&self, trigger: &PersistentTrigger) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO persistent_triggers
                (trigger_id, process_pid, binary, context_type, package_name, start_time)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                trigger.trigger_id.to_string(),
                trigger.process_pid,
                trigger.binary,
                trigger.context_type,
                trigger.package_name,
                trigger.start_time.to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    /// Associate an event with a persisted trigger.
    pub fn save_event(
        &self,
        trigger_id: &Uuid,
        event_id: &Uuid,
        event_kind: &str,
        process_id: u32,
        timestamp: &DateTime<Utc>,
    ) -> Result<()> {
        self.conn.execute(
            "INSERT INTO persistent_events
                (trigger_id, event_id, event_kind, process_id, timestamp)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                trigger_id.to_string(),
                event_id.to_string(),
                event_kind,
                process_id,
                timestamp.to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    /// Load triggers whose `start_time` is within the last `max_age_hours`.
    pub fn load_recent_triggers(&self, max_age_hours: u64) -> Result<Vec<PersistentTrigger>> {
        let cutoff = Utc::now() - chrono::Duration::hours(max_age_hours as i64);
        let cutoff_str = cutoff.to_rfc3339();

        let mut stmt = self.conn.prepare(
            "SELECT trigger_id, process_pid, binary, context_type, package_name, start_time
             FROM persistent_triggers
             WHERE start_time >= ?1
             ORDER BY start_time DESC",
        )?;

        let rows = stmt.query_map(rusqlite::params![cutoff_str], |row| {
            let id_str: String = row.get(0)?;
            let pid: u32 = row.get(1)?;
            let binary: String = row.get(2)?;
            let context_type: String = row.get(3)?;
            let package_name: Option<String> = row.get(4)?;
            let start_str: String = row.get(5)?;
            Ok((id_str, pid, binary, context_type, package_name, start_str))
        })?;

        let mut triggers = Vec::new();
        for row in rows {
            let (id_str, pid, binary, context_type, package_name, start_str) = row?;
            let trigger_id = Uuid::parse_str(&id_str)
                .map_err(|e| rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e)))?;
            let start_time = DateTime::parse_from_rfc3339(&start_str)
                .map_err(|e| rusqlite::Error::FromSqlConversionFailure(5, rusqlite::types::Type::Text, Box::new(e)))?
                .with_timezone(&Utc);
            triggers.push(PersistentTrigger {
                trigger_id,
                process_pid: pid,
                binary,
                context_type,
                package_name,
                start_time,
            });
        }

        Ok(triggers)
    }

    /// Check if a binary was installed by a recent trigger within `max_age_hours`.
    ///
    /// This enables detection of delayed-execution attacks: "this binary was
    /// installed 6 hours ago by npm, and now it's phoning home."
    pub fn find_trigger_for_binary(
        &self,
        binary: &str,
        max_age_hours: u64,
    ) -> Result<Option<PersistentTrigger>> {
        let cutoff = Utc::now() - chrono::Duration::hours(max_age_hours as i64);
        let cutoff_str = cutoff.to_rfc3339();

        let mut stmt = self.conn.prepare(
            "SELECT trigger_id, process_pid, binary, context_type, package_name, start_time
             FROM persistent_triggers
             WHERE binary = ?1 AND start_time >= ?2
             ORDER BY start_time DESC
             LIMIT 1",
        )?;

        let mut rows = stmt.query(rusqlite::params![binary, cutoff_str])?;
        if let Some(row) = rows.next()? {
            let id_str: String = row.get(0)?;
            let pid: u32 = row.get(1)?;
            let binary: String = row.get(2)?;
            let context_type: String = row.get(3)?;
            let package_name: Option<String> = row.get(4)?;
            let start_str: String = row.get(5)?;

            let trigger_id = Uuid::parse_str(&id_str)
                .map_err(|e| rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e)))?;
            let start_time = DateTime::parse_from_rfc3339(&start_str)
                .map_err(|e| rusqlite::Error::FromSqlConversionFailure(5, rusqlite::types::Type::Text, Box::new(e)))?
                .with_timezone(&Utc);

            Ok(Some(PersistentTrigger {
                trigger_id,
                process_pid: pid,
                binary,
                context_type,
                package_name,
                start_time,
            }))
        } else {
            Ok(None)
        }
    }

    /// Delete triggers and their associated events older than `max_age_hours`.
    ///
    /// Returns the number of triggers deleted.
    pub fn cleanup(&self, max_age_hours: u64) -> Result<u64> {
        let cutoff = Utc::now() - chrono::Duration::hours(max_age_hours as i64);
        let cutoff_str = cutoff.to_rfc3339();

        // Delete events for expired triggers first (foreign key).
        self.conn.execute(
            "DELETE FROM persistent_events WHERE trigger_id IN
                (SELECT trigger_id FROM persistent_triggers WHERE start_time < ?1)",
            rusqlite::params![cutoff_str],
        )?;

        let deleted = self.conn.execute(
            "DELETE FROM persistent_triggers WHERE start_time < ?1",
            rusqlite::params![cutoff_str],
        )?;

        Ok(deleted as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn make_trigger(binary: &str, package_name: Option<&str>, hours_ago: i64) -> PersistentTrigger {
        PersistentTrigger {
            trigger_id: Uuid::new_v4(),
            process_pid: 1000,
            binary: binary.to_string(),
            context_type: "package_install".to_string(),
            package_name: package_name.map(|s| s.to_string()),
            start_time: Utc::now() - Duration::hours(hours_ago),
        }
    }

    // Test 1: Save trigger, load it back, verify fields match
    #[test]
    fn save_and_load_trigger() {
        let store = PersistentWindowStore::open_in_memory().unwrap();
        let trigger = make_trigger("/usr/bin/npm", Some("evil-package"), 1);
        let original_id = trigger.trigger_id;

        store.save_trigger(&trigger).unwrap();

        let loaded = store.load_recent_triggers(24).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].trigger_id, original_id);
        assert_eq!(loaded[0].process_pid, 1000);
        assert_eq!(loaded[0].binary, "/usr/bin/npm");
        assert_eq!(loaded[0].context_type, "package_install");
        assert_eq!(
            loaded[0].package_name.as_deref(),
            Some("evil-package")
        );
    }

    // Test 2: Save trigger + 3 events, verify events associated correctly
    #[test]
    fn save_trigger_and_events() {
        let store = PersistentWindowStore::open_in_memory().unwrap();
        let trigger = make_trigger("/usr/bin/npm", Some("lodash"), 0);
        store.save_trigger(&trigger).unwrap();

        for i in 0..3 {
            let event_id = Uuid::new_v4();
            let ts = Utc::now() + Duration::seconds(i);
            store
                .save_event(&trigger.trigger_id, &event_id, "NetworkConnect", 2000 + i as u32, &ts)
                .unwrap();
        }

        // Verify events are stored by querying directly.
        let mut stmt = store
            .conn
            .prepare("SELECT COUNT(*) FROM persistent_events WHERE trigger_id = ?1")
            .unwrap();
        let count: i64 = stmt
            .query_row(rusqlite::params![trigger.trigger_id.to_string()], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 3);
    }

    // Test 3: find_trigger_for_binary finds a match
    #[test]
    fn find_trigger_for_binary_match() {
        let store = PersistentWindowStore::open_in_memory().unwrap();
        let trigger = make_trigger("/usr/bin/npm", Some("evil-package"), 6);
        store.save_trigger(&trigger).unwrap();

        let found = store.find_trigger_for_binary("/usr/bin/npm", 24).unwrap();
        assert!(found.is_some());
        let found = found.unwrap();
        assert_eq!(found.trigger_id, trigger.trigger_id);
        assert_eq!(found.package_name.as_deref(), Some("evil-package"));
    }

    // Test 4: cleanup removes old triggers
    #[test]
    fn cleanup_removes_old_triggers() {
        let store = PersistentWindowStore::open_in_memory().unwrap();

        // Old trigger: 48 hours ago
        let old = make_trigger("/usr/bin/pip", Some("old-pkg"), 48);
        store.save_trigger(&old).unwrap();
        store
            .save_event(&old.trigger_id, &Uuid::new_v4(), "ProcessExec", 3000, &old.start_time)
            .unwrap();

        // Recent trigger: 1 hour ago
        let recent = make_trigger("/usr/bin/npm", Some("new-pkg"), 1);
        store.save_trigger(&recent).unwrap();

        let deleted = store.cleanup(24).unwrap();
        assert_eq!(deleted, 1);

        // Only the recent trigger should remain.
        let remaining = store.load_recent_triggers(24).unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].trigger_id, recent.trigger_id);

        // Events for the old trigger should also be gone.
        let mut stmt = store
            .conn
            .prepare("SELECT COUNT(*) FROM persistent_events WHERE trigger_id = ?1")
            .unwrap();
        let count: i64 = stmt
            .query_row(rusqlite::params![old.trigger_id.to_string()], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 0);
    }

    // Test 5: load_recent_triggers respects max_age
    #[test]
    fn load_recent_triggers_respects_max_age() {
        let store = PersistentWindowStore::open_in_memory().unwrap();

        // Trigger 2 hours ago
        let t2 = make_trigger("/usr/bin/npm", Some("pkg-a"), 2);
        store.save_trigger(&t2).unwrap();

        // Trigger 10 hours ago
        let t10 = make_trigger("/usr/bin/pip", Some("pkg-b"), 10);
        store.save_trigger(&t10).unwrap();

        // Trigger 30 hours ago
        let t30 = make_trigger("/usr/bin/cargo", Some("pkg-c"), 30);
        store.save_trigger(&t30).unwrap();

        // max_age 24 should return t2 and t10 but not t30
        let recent_24 = store.load_recent_triggers(24).unwrap();
        assert_eq!(recent_24.len(), 2);

        // max_age 5 should return only t2
        let recent_5 = store.load_recent_triggers(5).unwrap();
        assert_eq!(recent_5.len(), 1);
        assert_eq!(recent_5[0].trigger_id, t2.trigger_id);

        // max_age 48 should return all 3
        let recent_48 = store.load_recent_triggers(48).unwrap();
        assert_eq!(recent_48.len(), 3);
    }
}
