pub mod run;
pub mod ui;

use std::collections::VecDeque;

/// The four panels of the dashboard.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Panel {
    Events,
    ProcessTree,
    PolicyStatus,
    AnalysisQueue,
}

/// Application state for the TUI.
pub struct App {
    pub active_panel: Panel,
    pub events: VecDeque<EventEntry>,
    pub processes: Vec<ProcessEntry>,
    pub policies: Vec<PolicyEntry>,
    pub analyses: Vec<AnalysisEntry>,
    pub scroll_offset: usize,
    pub should_quit: bool,
}

/// A displayable event entry.
#[derive(Debug, Clone)]
pub struct EventEntry {
    pub timestamp: String,
    pub kind: String,
    pub binary: String,
    pub context: String,
    pub severity: String,
}

/// A displayable process entry.
#[derive(Debug, Clone)]
pub struct ProcessEntry {
    pub pid: u32,
    pub binary: String,
    pub context: String,
}

/// A displayable policy entry.
#[derive(Debug, Clone)]
pub struct PolicyEntry {
    pub name: String,
    /// One of "base", "reactive", "user".
    pub source: String,
    /// One of "active", "staged".
    pub status: String,
}

/// A displayable analysis queue entry.
#[derive(Debug, Clone)]
pub struct AnalysisEntry {
    pub trace_id: String,
    pub context: String,
    /// One of "pending", "analyzing", "complete".
    pub status: String,
    pub verdict: Option<String>,
}

const MAX_EVENTS: usize = 1000;

impl App {
    /// Create a new app with empty state.
    pub fn new() -> Self {
        Self {
            active_panel: Panel::Events,
            events: VecDeque::new(),
            processes: Vec::new(),
            policies: Vec::new(),
            analyses: Vec::new(),
            scroll_offset: 0,
            should_quit: false,
        }
    }

    /// Cycle to the next panel (Tab key).
    pub fn next_panel(&mut self) {
        self.scroll_offset = 0;
        self.active_panel = match self.active_panel {
            Panel::Events => Panel::ProcessTree,
            Panel::ProcessTree => Panel::PolicyStatus,
            Panel::PolicyStatus => Panel::AnalysisQueue,
            Panel::AnalysisQueue => Panel::Events,
        };
    }

    /// Scroll down in the active panel.
    pub fn scroll_down(&mut self) {
        let max = self.active_panel_len().saturating_sub(1);
        if self.scroll_offset < max {
            self.scroll_offset += 1;
        }
    }

    /// Scroll up in the active panel.
    pub fn scroll_up(&mut self) {
        self.scroll_offset = self.scroll_offset.saturating_sub(1);
    }

    /// Add an event entry, keeping only the last `MAX_EVENTS`.
    pub fn add_event(&mut self, entry: EventEntry) {
        self.events.push_back(entry);
        if self.events.len() > MAX_EVENTS {
            self.events.pop_front();
        }
    }

    /// Add a process entry.
    pub fn add_process(&mut self, entry: ProcessEntry) {
        self.processes.push(entry);
    }

    /// Remove a process entry by PID.
    pub fn remove_process(&mut self, pid: u32) {
        self.processes.retain(|p| p.pid != pid);
    }

    /// Return the number of items in the currently active panel.
    fn active_panel_len(&self) -> usize {
        match self.active_panel {
            Panel::Events => self.events.len(),
            Panel::ProcessTree => self.processes.len(),
            Panel::PolicyStatus => self.policies.len(),
            Panel::AnalysisQueue => self.analyses.len(),
        }
    }
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_app_has_empty_state_and_events_panel() {
        let app = App::new();
        assert_eq!(app.active_panel, Panel::Events);
        assert!(app.events.is_empty());
        assert!(app.processes.is_empty());
        assert!(app.policies.is_empty());
        assert!(app.analyses.is_empty());
        assert_eq!(app.scroll_offset, 0);
        assert!(!app.should_quit);
    }

    #[test]
    fn next_panel_cycles_through_all_panels() {
        let mut app = App::new();
        assert_eq!(app.active_panel, Panel::Events);

        app.next_panel();
        assert_eq!(app.active_panel, Panel::ProcessTree);

        app.next_panel();
        assert_eq!(app.active_panel, Panel::PolicyStatus);

        app.next_panel();
        assert_eq!(app.active_panel, Panel::AnalysisQueue);

        app.next_panel();
        assert_eq!(app.active_panel, Panel::Events);
    }

    #[test]
    fn add_event_caps_at_1000() {
        let mut app = App::new();
        for i in 0..1050 {
            app.add_event(EventEntry {
                timestamp: format!("2026-04-01T00:00:{i:02}"),
                kind: "exec".to_string(),
                binary: format!("/usr/bin/test{i}"),
                context: "test".to_string(),
                severity: "low".to_string(),
            });
        }
        assert_eq!(app.events.len(), 1000);
        // First event should be event #50 (0-49 were dropped)
        assert!(app.events[0].binary.contains("test50"));
    }

    #[test]
    fn scroll_down_and_up_changes_offset() {
        let mut app = App::new();
        // Add some events so there's something to scroll
        for i in 0..10 {
            app.add_event(EventEntry {
                timestamp: format!("t{i}"),
                kind: "exec".to_string(),
                binary: format!("b{i}"),
                context: "ctx".to_string(),
                severity: "low".to_string(),
            });
        }
        assert_eq!(app.scroll_offset, 0);

        app.scroll_down();
        assert_eq!(app.scroll_offset, 1);

        app.scroll_down();
        assert_eq!(app.scroll_offset, 2);

        app.scroll_up();
        assert_eq!(app.scroll_offset, 1);

        app.scroll_up();
        assert_eq!(app.scroll_offset, 0);

        // Scrolling up past 0 stays at 0
        app.scroll_up();
        assert_eq!(app.scroll_offset, 0);
    }

    #[test]
    fn scroll_down_does_not_exceed_list_length() {
        let mut app = App::new();
        app.add_event(EventEntry {
            timestamp: "t".to_string(),
            kind: "exec".to_string(),
            binary: "b".to_string(),
            context: "ctx".to_string(),
            severity: "low".to_string(),
        });
        // With 1 event, max offset is 0
        app.scroll_down();
        assert_eq!(app.scroll_offset, 0);
    }

    #[test]
    fn add_and_remove_process() {
        let mut app = App::new();
        app.add_process(ProcessEntry {
            pid: 100,
            binary: "/usr/bin/foo".to_string(),
            context: "test".to_string(),
        });
        app.add_process(ProcessEntry {
            pid: 200,
            binary: "/usr/bin/bar".to_string(),
            context: "test".to_string(),
        });
        assert_eq!(app.processes.len(), 2);

        app.remove_process(100);
        assert_eq!(app.processes.len(), 1);
        assert_eq!(app.processes[0].pid, 200);
    }

    #[test]
    fn next_panel_resets_scroll_offset() {
        let mut app = App::new();
        for i in 0..5 {
            app.add_event(EventEntry {
                timestamp: format!("t{i}"),
                kind: "exec".to_string(),
                binary: format!("b{i}"),
                context: "ctx".to_string(),
                severity: "low".to_string(),
            });
        }
        app.scroll_down();
        app.scroll_down();
        assert_eq!(app.scroll_offset, 2);

        app.next_panel();
        assert_eq!(app.scroll_offset, 0);
    }
}
