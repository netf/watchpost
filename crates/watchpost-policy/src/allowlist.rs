use anyhow::Result;
use chrono::{DateTime, Utc};
use rusqlite::{params, Connection};
use std::path::Path;

/// A single entry in the dynamic allowlist.
#[derive(Debug, Clone)]
pub struct AllowlistEntry {
    pub id: i64,
    pub parent_binary: String,
    pub child_binary: String,
    pub context_type: String,
    pub file_pattern: Option<String>,
    pub network_dest: Option<String>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub occurrence_count: u32,
}

/// SQLite-backed store for dynamic allowlist patterns.
///
/// Patterns that have been observed enough times are considered benign
/// and can be excluded from future alerts.
pub struct AllowlistStore {
    conn: Connection,
}

impl AllowlistStore {
    /// Open (or create) the allowlist database at the given path.
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)?;
        Self::init(conn)
    }

    /// Open an in-memory allowlist database (useful for testing).
    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        Self::init(conn)
    }

    fn init(conn: Connection) -> Result<Self> {
        conn.execute_batch("PRAGMA journal_mode = WAL;")?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS allowlist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                parent_binary TEXT NOT NULL,
                child_binary TEXT NOT NULL,
                context_type TEXT NOT NULL,
                file_pattern TEXT NOT NULL DEFAULT '',
                network_dest TEXT NOT NULL DEFAULT '',
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                occurrence_count INTEGER NOT NULL DEFAULT 1,
                UNIQUE(parent_binary, child_binary, context_type, file_pattern, network_dest)
            );",
        )?;
        Ok(Self { conn })
    }

    /// Record an observation of a (parent, child, context) tuple.
    ///
    /// If the combination already exists, increments the count and updates `last_seen`.
    /// If new, inserts with count=1.
    pub fn record_observation(
        &self,
        parent: &str,
        child: &str,
        context: &str,
        file_pattern: Option<&str>,
        network_dest: Option<&str>,
    ) -> Result<()> {
        let now = Utc::now().to_rfc3339();
        let file_pat = file_pattern.unwrap_or("");
        let net_dest = network_dest.unwrap_or("");
        self.conn.execute(
            "INSERT INTO allowlist (parent_binary, child_binary, context_type, file_pattern, network_dest, first_seen, last_seen, occurrence_count)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 1)
             ON CONFLICT(parent_binary, child_binary, context_type, file_pattern, network_dest)
             DO UPDATE SET
                occurrence_count = occurrence_count + 1,
                last_seen = ?7",
            params![parent, child, context, file_pat, net_dest, now, now],
        )?;
        Ok(())
    }

    /// Check whether a pattern has been observed at least `threshold` times.
    pub fn is_allowlisted(
        &self,
        parent: &str,
        child: &str,
        context: &str,
        threshold: u32,
    ) -> bool {
        let result: Result<u32, _> = self.conn.query_row(
            "SELECT occurrence_count FROM allowlist
             WHERE parent_binary = ?1 AND child_binary = ?2 AND context_type = ?3",
            params![parent, child, context],
            |row| row.get(0),
        );
        match result {
            Ok(count) => count >= threshold,
            Err(_) => false,
        }
    }

    /// List all allowlist entries.
    pub fn list(&self) -> Result<Vec<AllowlistEntry>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, parent_binary, child_binary, context_type, file_pattern, network_dest,
                    first_seen, last_seen, occurrence_count
             FROM allowlist
             ORDER BY id",
        )?;
        let entries = stmt
            .query_map([], |row| {
                let first_seen_str: String = row.get(6)?;
                let last_seen_str: String = row.get(7)?;
                let file_pat: String = row.get(4)?;
                let net_dest: String = row.get(5)?;
                Ok(AllowlistEntry {
                    id: row.get(0)?,
                    parent_binary: row.get(1)?,
                    child_binary: row.get(2)?,
                    context_type: row.get(3)?,
                    file_pattern: if file_pat.is_empty() {
                        None
                    } else {
                        Some(file_pat)
                    },
                    network_dest: if net_dest.is_empty() {
                        None
                    } else {
                        Some(net_dest)
                    },
                    first_seen: DateTime::parse_from_rfc3339(&first_seen_str)
                        .unwrap_or_default()
                        .with_timezone(&Utc),
                    last_seen: DateTime::parse_from_rfc3339(&last_seen_str)
                        .unwrap_or_default()
                        .with_timezone(&Utc),
                    occurrence_count: row.get(8)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(entries)
    }

    /// Remove an allowlist entry by ID.
    pub fn remove(&self, id: i64) -> Result<()> {
        self.conn
            .execute("DELETE FROM allowlist WHERE id = ?1", params![id])?;
        Ok(())
    }

    /// Clear all entries from the allowlist.
    pub fn reset(&self) -> Result<()> {
        self.conn.execute("DELETE FROM allowlist", [])?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_threshold_reached() {
        let store = AllowlistStore::open_in_memory().unwrap();
        let parent = "/usr/bin/bash";
        let child = "/usr/bin/curl";
        let context = "exec";

        for _ in 0..5 {
            store
                .record_observation(parent, child, context, None, None)
                .unwrap();
        }

        assert!(store.is_allowlisted(parent, child, context, 5));
    }

    #[test]
    fn test_threshold_not_reached() {
        let store = AllowlistStore::open_in_memory().unwrap();
        let parent = "/usr/bin/bash";
        let child = "/usr/bin/curl";
        let context = "exec";

        for _ in 0..3 {
            store
                .record_observation(parent, child, context, None, None)
                .unwrap();
        }

        assert!(!store.is_allowlisted(parent, child, context, 5));
    }

    #[test]
    fn test_remove_entry() {
        let store = AllowlistStore::open_in_memory().unwrap();
        store
            .record_observation("/usr/bin/a", "/usr/bin/b", "exec", None, None)
            .unwrap();

        let entries = store.list().unwrap();
        assert_eq!(entries.len(), 1);
        let id = entries[0].id;

        store.remove(id).unwrap();

        let entries = store.list().unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn test_reset_clears_all() {
        let store = AllowlistStore::open_in_memory().unwrap();
        store
            .record_observation("/usr/bin/a", "/usr/bin/b", "exec", None, None)
            .unwrap();
        store
            .record_observation("/usr/bin/c", "/usr/bin/d", "file", None, None)
            .unwrap();

        let entries = store.list().unwrap();
        assert_eq!(entries.len(), 2);

        store.reset().unwrap();

        let entries = store.list().unwrap();
        assert!(entries.is_empty());
    }
}
