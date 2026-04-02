use chrono::{DateTime, Utc};
use dashmap::DashMap;

/// A node in the in-memory process tree.
#[derive(Debug, Clone)]
pub struct ProcessNode {
    pub pid: u32,
    pub parent_pid: Option<u32>,
    pub binary: String,
    pub start_time: DateTime<Utc>,
}

/// Concurrent process tree backed by `DashMap`.
///
/// Supports O(1) insert/remove/lookup and parent-chain walks for ancestry
/// queries. Designed for concurrent access from async event-ingestion and
/// correlation tasks without a global lock.
pub struct ProcessTree {
    nodes: DashMap<u32, ProcessNode>,
}

impl ProcessTree {
    pub fn new() -> Self {
        Self {
            nodes: DashMap::new(),
        }
    }

    /// Insert a process node into the tree.
    pub fn insert(
        &self,
        pid: u32,
        parent_pid: Option<u32>,
        binary: String,
        start_time: DateTime<Utc>,
    ) {
        self.nodes.insert(
            pid,
            ProcessNode {
                pid,
                parent_pid,
                binary,
                start_time,
            },
        );
    }

    /// Remove a single process node. Does **not** recursively remove children;
    /// each child will be removed by its own `ProcessExit` event from Tetragon.
    pub fn remove(&self, pid: u32) {
        self.nodes.remove(&pid);
    }

    /// Walk the parent chain from `pid` upward and return `true` if
    /// `ancestor_pid` is found. Limited to 32 hops to prevent infinite loops
    /// from stale or cyclic data.
    pub fn is_descendant(&self, pid: u32, ancestor_pid: u32) -> bool {
        let mut current = pid;
        for _ in 0..32 {
            if current == ancestor_pid {
                return true;
            }
            match self.nodes.get(&current) {
                Some(node) => match node.parent_pid {
                    Some(ppid) => current = ppid,
                    None => return false,
                },
                None => return false,
            }
        }
        false
    }

    /// Return the ancestry chain starting at `pid` and walking up to root.
    /// Limited to 32 hops.
    pub fn get_ancestry(&self, pid: u32) -> Vec<u32> {
        let mut chain = Vec::new();
        let mut current = pid;
        for _ in 0..32 {
            chain.push(current);
            match self.nodes.get(&current) {
                Some(node) => match node.parent_pid {
                    Some(ppid) => current = ppid,
                    None => break,
                },
                None => break,
            }
        }
        chain
    }

    /// Return a clone of the node for the given PID, if it exists.
    pub fn get(&self, pid: u32) -> Option<ProcessNode> {
        self.nodes.get(&pid).map(|entry| entry.clone())
    }
}

impl Default for ProcessTree {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn build_tree() -> ProcessTree {
        let tree = ProcessTree::new();
        let now = Utc::now();
        tree.insert(100, None, "/usr/bin/bash".into(), now);
        tree.insert(200, Some(100), "/usr/bin/npm".into(), now);
        tree.insert(300, Some(200), "/usr/bin/node".into(), now);
        tree
    }

    #[test]
    fn grandchild_is_descendant_of_root() {
        let tree = build_tree();
        assert!(tree.is_descendant(300, 100));
    }

    #[test]
    fn parent_is_not_descendant_of_child() {
        let tree = build_tree();
        assert!(!tree.is_descendant(100, 300));
    }

    #[test]
    fn nonexistent_pid_is_not_descendant() {
        let tree = build_tree();
        assert!(!tree.is_descendant(400, 100));
    }

    #[test]
    fn remove_does_not_affect_children() {
        let tree = build_tree();
        tree.remove(200);
        assert!(tree.get(200).is_none());
        assert!(tree.get(300).is_some());
    }

    #[test]
    fn get_ancestry_returns_chain() {
        let tree = build_tree();
        let ancestry = tree.get_ancestry(300);
        assert_eq!(ancestry, vec![300, 200, 100]);
    }

    #[tokio::test]
    async fn concurrent_inserts_do_not_panic() {
        let tree = std::sync::Arc::new(ProcessTree::new());
        let mut handles = Vec::new();
        for i in 0..100 {
            let tree = tree.clone();
            handles.push(tokio::spawn(async move {
                tree.insert(i, None, format!("/bin/proc{}", i), Utc::now());
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
        // Verify all 100 nodes were inserted.
        for i in 0..100 {
            assert!(tree.get(i).is_some(), "missing pid {}", i);
        }
    }
}
