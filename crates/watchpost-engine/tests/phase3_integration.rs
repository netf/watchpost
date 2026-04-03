//! Phase 3 integration tests.
//!
//! These tests validate Phase 3 features: TUI dashboard, Flatpak sandbox
//! escape detection, network detection policies, webhook forwarding, and
//! policy templates.  No real terminal, /proc access, or HTTP calls are made.

use std::fs;
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// Test 1: TUI app lifecycle
// ---------------------------------------------------------------------------

#[test]
fn tui_app_lifecycle() {
    use watchpost_tui::{App, EventEntry, Panel};

    // Create a new app and verify empty state.
    let mut app = App::new();
    assert_eq!(app.active_panel, Panel::Events);
    assert!(app.events.is_empty());
    assert!(app.processes.is_empty());
    assert!(app.policies.is_empty());
    assert!(app.analyses.is_empty());
    assert_eq!(app.scroll_offset, 0);
    assert!(!app.should_quit);

    // Add 5 events.
    for i in 0..5 {
        app.add_event(EventEntry {
            timestamp: format!("2026-04-01T00:00:{i:02}"),
            kind: "exec".to_string(),
            binary: format!("/usr/bin/test{i}"),
            context: "test".to_string(),
            severity: "low".to_string(),
        });
    }
    assert_eq!(app.events.len(), 5);

    // Cycle panels: Events -> ProcessTree -> PolicyStatus -> AnalysisQueue -> Events.
    assert_eq!(app.active_panel, Panel::Events);
    app.next_panel();
    assert_eq!(app.active_panel, Panel::ProcessTree);
    app.next_panel();
    assert_eq!(app.active_panel, Panel::PolicyStatus);
    app.next_panel();
    assert_eq!(app.active_panel, Panel::AnalysisQueue);
    app.next_panel();
    assert_eq!(app.active_panel, Panel::Events);

    // Scroll down/up with events in the Events panel.
    assert_eq!(app.scroll_offset, 0);
    app.scroll_down();
    assert_eq!(app.scroll_offset, 1);
    app.scroll_down();
    assert_eq!(app.scroll_offset, 2);
    app.scroll_up();
    assert_eq!(app.scroll_offset, 1);
    app.scroll_up();
    assert_eq!(app.scroll_offset, 0);
    // Scrolling up past 0 stays at 0.
    app.scroll_up();
    assert_eq!(app.scroll_offset, 0);

    // Add 1001 events total (already have 5, add 996 more to reach 1001).
    for i in 5..1001 {
        app.add_event(EventEntry {
            timestamp: format!("2026-04-01T00:01:{:04}", i),
            kind: "exec".to_string(),
            binary: format!("/usr/bin/test{i}"),
            context: "test".to_string(),
            severity: "low".to_string(),
        });
    }
    assert_eq!(
        app.events.len(),
        1000,
        "events should be capped at 1000"
    );
}

// ---------------------------------------------------------------------------
// Test 2: TUI rendering doesn't panic
// ---------------------------------------------------------------------------

#[test]
fn tui_rendering_does_not_panic() {
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    use watchpost_tui::{
        ui, AnalysisEntry, App, EventEntry, PolicyEntry, ProcessEntry,
    };

    // Render with populated state.
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
    app.policies.push(PolicyEntry {
        name: "base-exec-monitor".to_string(),
        source: "base".to_string(),
        status: "active".to_string(),
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
    terminal
        .draw(|frame| ui::draw(frame, &app))
        .expect("rendering populated app should not panic");

    // Render with empty app.
    let empty_app = App::new();
    let backend2 = TestBackend::new(120, 40);
    let mut terminal2 = Terminal::new(backend2).unwrap();
    terminal2
        .draw(|frame| ui::draw(frame, &empty_app))
        .expect("rendering empty app should not panic");
}

// ---------------------------------------------------------------------------
// Test 3: Flatpak metadata parsing
// ---------------------------------------------------------------------------

#[test]
fn flatpak_metadata_parsing() {
    use watchpost_collector::flatpak::FlatpakMetadata;

    let content = "\
[Application]
name=org.mozilla.Firefox
runtime=org.freedesktop.Platform/x86_64/23.08

[Context]
shared=network;ipc;
sockets=x11;wayland;pulseaudio;
filesystems=home;/tmp;xdg-download;

[Session Bus Policy]
org.freedesktop.Notifications=talk
";

    // Verify permissions extracted correctly.
    let meta = FlatpakMetadata::parse("org.mozilla.Firefox", content);
    assert_eq!(meta.app_id, "org.mozilla.Firefox");
    assert_eq!(meta.permissions, vec!["home", "/tmp", "xdg-download"]);

    // Test is_path_permitted with home permission.
    let meta_home = FlatpakMetadata {
        app_id: "org.example.App".into(),
        permissions: vec!["home".into()],
    };
    assert!(
        meta_home.is_path_permitted("/home/user/Documents/file.txt"),
        "home permission should permit /home paths"
    );
    assert!(
        !meta_home.is_path_permitted("/etc/shadow"),
        "home permission should NOT permit /etc paths"
    );

    // Test is_path_permitted without home permission.
    let meta_tmp = FlatpakMetadata {
        app_id: "org.example.App".into(),
        permissions: vec!["/tmp".into()],
    };
    assert!(
        !meta_tmp.is_path_permitted("/home/user/file.txt"),
        "without home permission, /home paths should be denied"
    );
    assert!(
        meta_tmp.is_path_permitted("/tmp/scratch"),
        "/tmp prefix should be permitted"
    );

    // Test is_path_permitted with host (everything allowed).
    let meta_host = FlatpakMetadata {
        app_id: "org.example.App".into(),
        permissions: vec!["host".into()],
    };
    assert!(
        meta_host.is_path_permitted("/etc/shadow"),
        "host should permit everything"
    );
    assert!(
        meta_host.is_path_permitted("/home/user/.ssh/id_rsa"),
        "host should permit everything"
    );
    assert!(
        meta_host.is_path_permitted("/root/.bashrc"),
        "host should permit everything"
    );
}

// ---------------------------------------------------------------------------
// Test 4: Flatpak cgroup extraction
// ---------------------------------------------------------------------------

#[test]
fn flatpak_cgroup_extraction() {
    use watchpost_collector::flatpak::extract_app_id_from_cgroup_content;

    // Standard Flatpak cgroup line.
    let content = "0::/user.slice/user-1000.slice/user@1000.service/app.slice/app-flatpak-org.mozilla.Firefox-12345.scope\n";
    let app_id = extract_app_id_from_cgroup_content(content);
    assert_eq!(app_id, Some("org.mozilla.Firefox".to_string()));

    // Complex app ID with multiple dots.
    let content2 = "0::/user.slice/user-1000.slice/user@1000.service/app.slice/app-flatpak-com.valvesoftware.Steam-99999.scope\n";
    let app_id2 = extract_app_id_from_cgroup_content(content2);
    assert_eq!(app_id2, Some("com.valvesoftware.Steam".to_string()));

    // No Flatpak marker.
    let content3 = "0::/user.slice/user-1000.slice/session-2.scope\n";
    let app_id3 = extract_app_id_from_cgroup_content(content3);
    assert_eq!(app_id3, None);

    // Multiple cgroup lines, only one with Flatpak.
    let content4 = "\
1:name=systemd:/user.slice/user-1000.slice/session-2.scope
0::/user.slice/user-1000.slice/user@1000.service/app.slice/app-flatpak-org.gnome.Calculator-5555.scope
";
    let app_id4 = extract_app_id_from_cgroup_content(content4);
    assert_eq!(app_id4, Some("org.gnome.Calculator".to_string()));
}

// ---------------------------------------------------------------------------
// Test 5: Network policies are complete
// ---------------------------------------------------------------------------

#[test]
fn network_policies_are_complete() {
    let policies_dir = workspace_root().join("policies");

    // Verify all 3 network detection policies exist and are valid YAML.
    let network_policies = ["reverse-shell.yaml", "dns-exfil.yaml", "crypto-miner.yaml"];
    for name in &network_policies {
        let path = policies_dir.join(name);
        assert!(
            path.exists(),
            "network policy {name} should exist at {}",
            path.display()
        );

        let content = fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("failed to read {name}: {e}"));
        let doc: serde_yml::Value = serde_yml::from_str(&content)
            .unwrap_or_else(|e| panic!("{name} is not valid YAML: {e}"));

        // Verify it's a TracingPolicy.
        assert_eq!(
            doc["kind"].as_str(),
            Some("TracingPolicy"),
            "{name} should have kind: TracingPolicy"
        );
    }

    // Verify crypto-miner uses Sigkill.
    let crypto_content = fs::read_to_string(policies_dir.join("crypto-miner.yaml")).unwrap();
    assert!(
        crypto_content.contains("Sigkill"),
        "crypto-miner policy should use Sigkill action"
    );

    // Verify reverse-shell has 2 kprobes.
    let reverse_content = fs::read_to_string(policies_dir.join("reverse-shell.yaml")).unwrap();
    let reverse_doc: serde_yml::Value = serde_yml::from_str(&reverse_content).unwrap();
    let kprobes = reverse_doc["spec"]["kprobes"]
        .as_sequence()
        .expect("reverse-shell should have kprobes sequence");
    assert_eq!(
        kprobes.len(),
        2,
        "reverse-shell should have exactly 2 kprobes"
    );

    // Verify total policy count >= 12.
    let policy_count = count_yaml_files(&policies_dir);
    assert!(
        policy_count >= 12,
        "expected >= 12 policy files, found {policy_count}"
    );
}

// ---------------------------------------------------------------------------
// Test 6: Webhook payload format
// ---------------------------------------------------------------------------

#[test]
fn webhook_payload_format() {
    use chrono::Utc;
    use uuid::Uuid;
    use watchpost_notify::webhook::WebhookForwarder;
    use watchpost_types::{Classification, Confidence, RecommendedAction, Verdict};

    let verdict = Verdict {
        id: Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap(),
        trace_id: Uuid::parse_str("6ba7b810-9dad-11d1-80b4-00c04fd430c8").unwrap(),
        classification: Classification::Malicious,
        confidence: Confidence::new(0.95),
        recommended_action: RecommendedAction::Block,
        explanation: "Suspicious outbound connection to known C2 server".to_owned(),
        profile_violations: vec!["network_egress".to_owned(), "unexpected_dns".to_owned()],
        timestamp: Utc::now(),
    };

    let payload = WebhookForwarder::from_verdict(&verdict);
    let json = serde_json::to_value(&payload).expect("payload should serialize to JSON");

    // Verify expected fields exist and have correct types.
    assert_eq!(json["event_type"], "verdict");
    assert!(json["verdict"].is_object(), "verdict should be an object");
    assert_eq!(
        json["verdict"]["id"].as_str().unwrap(),
        "550e8400-e29b-41d4-a716-446655440000"
    );
    assert_eq!(
        json["verdict"]["trace_id"].as_str().unwrap(),
        "6ba7b810-9dad-11d1-80b4-00c04fd430c8"
    );
    assert_eq!(
        json["verdict"]["classification"].as_str().unwrap(),
        "malicious"
    );
    assert!(
        (json["verdict"]["confidence"].as_f64().unwrap() - 0.95).abs() < f64::EPSILON,
        "confidence should be 0.95"
    );
    assert_eq!(
        json["verdict"]["recommended_action"].as_str().unwrap(),
        "block"
    );
    assert_eq!(
        json["verdict"]["explanation"].as_str().unwrap(),
        "Suspicious outbound connection to known C2 server"
    );
    let violations = json["verdict"]["profile_violations"]
        .as_array()
        .expect("profile_violations should be an array");
    assert_eq!(violations.len(), 2);
    assert_eq!(violations[0], "network_egress");
    assert_eq!(violations[1], "unexpected_dns");
    assert!(
        json["verdict"]["timestamp"].is_string(),
        "timestamp should be a string"
    );
}

// ---------------------------------------------------------------------------
// Test 7: Policy templates content validation
// ---------------------------------------------------------------------------

#[test]
fn policy_templates_content_validation() {
    let root = workspace_root();
    let templates_dir = root.join("templates");
    let policies_dir = root.join("policies");

    let template_files = ["minimal.yaml", "web-developer.yaml", "systems-developer.yaml"];

    for template_name in &template_files {
        let path = templates_dir.join(template_name);
        assert!(
            path.exists(),
            "template {template_name} should exist at {}",
            path.display()
        );

        let content = fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("failed to read template {template_name}: {e}"));
        let doc: serde_yml::Value = serde_yml::from_str(&content)
            .unwrap_or_else(|e| panic!("template {template_name} is not valid YAML: {e}"));

        // Each template should have a name and policies list.
        assert!(
            doc["name"].as_str().is_some(),
            "template {template_name} should have a 'name' field"
        );

        let policies = doc["policies"]
            .as_sequence()
            .unwrap_or_else(|| panic!("template {template_name} should have a 'policies' list"));

        // Verify each referenced policy actually exists in the policies/ directory.
        for policy_entry in policies {
            let policy_file = policy_entry
                .as_str()
                .unwrap_or_else(|| {
                    panic!(
                        "policy entry in {template_name} should be a string, got: {:?}",
                        policy_entry
                    )
                });

            let policy_path = policies_dir.join(policy_file);
            assert!(
                policy_path.exists(),
                "template {template_name} references '{policy_file}' which does not exist at {}",
                policy_path.display()
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Test 8: Full policy count audit
// ---------------------------------------------------------------------------

#[test]
fn full_policy_count_audit() {
    let root = workspace_root();

    let policy_count = count_yaml_files(&root.join("policies"));
    let template_count = count_yaml_files(&root.join("templates"));
    let profile_count = count_yaml_files(&root.join("profiles"));
    let rule_count = count_yaml_files(&root.join("rules"));

    assert!(
        policy_count >= 12,
        "expected >= 12 policy files, found {policy_count}"
    );
    assert_eq!(
        template_count, 3,
        "expected exactly 3 template files, found {template_count}"
    );
    assert!(
        profile_count >= 5,
        "expected >= 5 profile files, found {profile_count}"
    );
    assert!(
        rule_count >= 4,
        "expected >= 4 rule files, found {rule_count}"
    );

    // Print a summary for visibility in test output.
    eprintln!(
        "Policy count audit: policies={policy_count}, templates={template_count}, \
         profiles={profile_count}, rules={rule_count}"
    );
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Resolve the workspace root from CARGO_MANIFEST_DIR.
///
/// `CARGO_MANIFEST_DIR` for `watchpost-engine` points to `crates/watchpost-engine`,
/// so we go up two levels to reach the workspace root.
fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates/ parent")
        .parent()
        .expect("workspace root")
        .to_path_buf()
}

/// Count YAML files (`.yaml` and `.yml`) in a directory.
fn count_yaml_files(dir: &Path) -> usize {
    fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("failed to read directory {}: {e}", dir.display()))
        .filter_map(|entry| entry.ok())
        .filter(|entry| {
            let path = entry.path();
            path.is_file()
                && matches!(
                    path.extension().and_then(|e| e.to_str()),
                    Some("yaml") | Some("yml")
                )
        })
        .count()
}
