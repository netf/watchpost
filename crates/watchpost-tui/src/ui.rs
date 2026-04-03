use ratatui::prelude::*;
use ratatui::widgets::*;

use crate::{App, Panel};

/// Draw the full 2x2 dashboard layout.
pub fn draw(frame: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(frame.area());

    let top = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
        .split(chunks[0]);

    let bottom = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(chunks[1]);

    draw_events_panel(frame, app, top[0]);
    draw_process_panel(frame, app, top[1]);
    draw_policy_panel(frame, app, bottom[0]);
    draw_analysis_panel(frame, app, bottom[1]);
}

/// Return a border style based on whether the panel is active.
fn panel_block(title: &str, active: bool) -> Block<'_> {
    let style = if active {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default().fg(Color::DarkGray)
    };
    Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(style)
}

fn draw_events_panel(frame: &mut Frame, app: &App, area: Rect) {
    let active = app.active_panel == Panel::Events;
    let header = Row::new(vec!["Time", "Type", "Binary", "Context"])
        .style(Style::default().add_modifier(Modifier::BOLD))
        .bottom_margin(1);

    let rows: Vec<Row> = app
        .events
        .iter()
        .enumerate()
        .map(|(i, e)| {
            let style = if active && i == app.scroll_offset {
                Style::default().bg(Color::DarkGray)
            } else {
                severity_style(&e.severity)
            };
            Row::new(vec![
                e.timestamp.clone(),
                e.kind.clone(),
                e.binary.clone(),
                e.context.clone(),
            ])
            .style(style)
        })
        .collect();

    let widths = [
        Constraint::Length(20),
        Constraint::Length(12),
        Constraint::Min(20),
        Constraint::Length(15),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(panel_block(" Live Events ", active));

    frame.render_widget(table, area);
}

fn draw_process_panel(frame: &mut Frame, app: &App, area: Rect) {
    let active = app.active_panel == Panel::ProcessTree;

    let items: Vec<ListItem> = app
        .processes
        .iter()
        .enumerate()
        .map(|(i, p)| {
            let content = format!("[{}] {} ({})", p.pid, p.binary, p.context);
            let style = if active && i == app.scroll_offset {
                Style::default().bg(Color::DarkGray)
            } else {
                Style::default()
            };
            ListItem::new(content).style(style)
        })
        .collect();

    let list = List::new(items).block(panel_block(" Process Tree ", active));

    frame.render_widget(list, area);
}

fn draw_policy_panel(frame: &mut Frame, app: &App, area: Rect) {
    let active = app.active_panel == Panel::PolicyStatus;
    let header = Row::new(vec!["Name", "Source", "Status"])
        .style(Style::default().add_modifier(Modifier::BOLD))
        .bottom_margin(1);

    let rows: Vec<Row> = app
        .policies
        .iter()
        .enumerate()
        .map(|(i, p)| {
            let style = if active && i == app.scroll_offset {
                Style::default().bg(Color::DarkGray)
            } else {
                policy_status_style(&p.status)
            };
            Row::new(vec![p.name.clone(), p.source.clone(), p.status.clone()]).style(style)
        })
        .collect();

    let widths = [
        Constraint::Min(20),
        Constraint::Length(12),
        Constraint::Length(10),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(panel_block(" Policy Status ", active));

    frame.render_widget(table, area);
}

fn draw_analysis_panel(frame: &mut Frame, app: &App, area: Rect) {
    let active = app.active_panel == Panel::AnalysisQueue;
    let header = Row::new(vec!["Trace", "Context", "Status", "Verdict"])
        .style(Style::default().add_modifier(Modifier::BOLD))
        .bottom_margin(1);

    let rows: Vec<Row> = app
        .analyses
        .iter()
        .enumerate()
        .map(|(i, a)| {
            let style = if active && i == app.scroll_offset {
                Style::default().bg(Color::DarkGray)
            } else {
                analysis_status_style(&a.status)
            };
            Row::new(vec![
                a.trace_id.clone(),
                a.context.clone(),
                a.status.clone(),
                a.verdict.clone().unwrap_or_default(),
            ])
            .style(style)
        })
        .collect();

    let widths = [
        Constraint::Length(12),
        Constraint::Min(15),
        Constraint::Length(12),
        Constraint::Length(12),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(panel_block(" Analysis Queue ", active));

    frame.render_widget(table, area);
}

/// Return a style based on event severity.
fn severity_style(severity: &str) -> Style {
    match severity {
        "critical" => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        "high" => Style::default().fg(Color::Red),
        "medium" => Style::default().fg(Color::Yellow),
        "low" => Style::default().fg(Color::Green),
        _ => Style::default(),
    }
}

/// Return a style based on policy status.
fn policy_status_style(status: &str) -> Style {
    match status {
        "active" => Style::default().fg(Color::Green),
        "staged" => Style::default().fg(Color::Yellow),
        _ => Style::default(),
    }
}

/// Return a style based on analysis status.
fn analysis_status_style(status: &str) -> Style {
    match status {
        "pending" => Style::default().fg(Color::Yellow),
        "analyzing" => Style::default().fg(Color::Cyan),
        "complete" => Style::default().fg(Color::Green),
        _ => Style::default(),
    }
}

#[cfg(test)]
mod tests {
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    use super::*;
    use crate::{AnalysisEntry, EventEntry, PolicyEntry, ProcessEntry};

    #[test]
    fn draw_does_not_panic_with_empty_state() {
        let app = App::new();
        let backend = TestBackend::new(120, 40);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| draw(frame, &app)).unwrap();
    }

    #[test]
    fn draw_does_not_panic_with_populated_state() {
        let mut app = App::new();

        app.add_event(EventEntry {
            timestamp: "2026-04-01T12:00:00".to_string(),
            kind: "exec".to_string(),
            binary: "/usr/bin/curl".to_string(),
            context: "npm-install".to_string(),
            severity: "medium".to_string(),
        });
        app.add_event(EventEntry {
            timestamp: "2026-04-01T12:00:01".to_string(),
            kind: "connect".to_string(),
            binary: "/usr/bin/wget".to_string(),
            context: "pip-install".to_string(),
            severity: "critical".to_string(),
        });

        app.add_process(ProcessEntry {
            pid: 1234,
            binary: "/usr/bin/node".to_string(),
            context: "npm-install".to_string(),
        });
        app.add_process(ProcessEntry {
            pid: 5678,
            binary: "/usr/bin/python3".to_string(),
            context: "pip-install".to_string(),
        });

        app.policies.push(PolicyEntry {
            name: "base-exec-monitor".to_string(),
            source: "base".to_string(),
            status: "active".to_string(),
        });
        app.policies.push(PolicyEntry {
            name: "react-block-net".to_string(),
            source: "reactive".to_string(),
            status: "staged".to_string(),
        });

        app.analyses.push(AnalysisEntry {
            trace_id: "abc123".to_string(),
            context: "npm-install".to_string(),
            status: "analyzing".to_string(),
            verdict: None,
        });
        app.analyses.push(AnalysisEntry {
            trace_id: "def456".to_string(),
            context: "pip-install".to_string(),
            status: "complete".to_string(),
            verdict: Some("benign".to_string()),
        });

        let backend = TestBackend::new(120, 40);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| draw(frame, &app)).unwrap();
    }
}
