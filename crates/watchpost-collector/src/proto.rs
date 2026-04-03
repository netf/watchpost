//! Conversions from Tetragon protobuf types to Watchpost domain types.

use anyhow::{Context, Result};
use chrono::{DateTime, TimeZone, Utc};
use uuid::Uuid;
use watchpost_types::{EventKind, FileAccessType, TetragonEvent};

use crate::tetragon::{
    get_events_response, kprobe_argument, GetEventsResponse, Process, ProcessExec,
    ProcessExit, ProcessKprobe, ProcessLsm,
};

/// Convert a Tetragon `GetEventsResponse` into an optional domain `TetragonEvent`.
///
/// Returns `Ok(None)` for event types that Watchpost does not handle (e.g.
/// uprobe, usdt, loader, throttle, tracepoint, test, rate_limit_info).
pub fn convert_response(resp: &GetEventsResponse) -> Result<Option<TetragonEvent>> {
    let Some(ref event) = resp.event else {
        return Ok(None);
    };

    match event {
        get_events_response::Event::ProcessExec(exec) => {
            convert_exec(exec).map(Some)
        }
        get_events_response::Event::ProcessExit(exit) => {
            convert_exit(exit).map(Some)
        }
        get_events_response::Event::ProcessKprobe(kp) => convert_kprobe(kp),
        get_events_response::Event::ProcessLsm(lsm) => convert_lsm(lsm),
        get_events_response::Event::ProcessTracepoint(_) => {
            tracing::debug!("ignoring tracepoint event");
            Ok(None)
        }
        get_events_response::Event::ProcessUprobe(_) => {
            tracing::debug!("ignoring uprobe event");
            Ok(None)
        }
        get_events_response::Event::ProcessUsdt(_) => {
            tracing::debug!("ignoring usdt event");
            Ok(None)
        }
        get_events_response::Event::ProcessLoader(_) => {
            tracing::debug!("ignoring loader event");
            Ok(None)
        }
        get_events_response::Event::ProcessThrottle(_) => {
            tracing::debug!("ignoring throttle event");
            Ok(None)
        }
        get_events_response::Event::Test(_) => {
            tracing::debug!("ignoring test event");
            Ok(None)
        }
        get_events_response::Event::RateLimitInfo(_) => {
            tracing::debug!("ignoring rate limit info event");
            Ok(None)
        }
    }
}

/// Convert a `ProcessExec` proto message into a domain `TetragonEvent`.
pub fn convert_exec(exec: &ProcessExec) -> Result<TetragonEvent> {
    let process = exec
        .process
        .as_ref()
        .context("ProcessExec missing process field")?;

    let (process_id, parent_id) = extract_ids(process, exec.parent.as_ref());
    let timestamp = extract_timestamp(process.start_time.as_ref());

    let args = parse_arguments(&process.arguments);

    Ok(TetragonEvent {
        id: Uuid::new_v4(),
        timestamp,
        kind: EventKind::ProcessExec {
            binary: process.binary.clone(),
            args,
            cwd: process.cwd.clone(),
            uid: process.uid.unwrap_or(0),
        },
        process_id,
        parent_id,
        policy_name: None,
    })
}

/// Convert a `ProcessExit` proto message into a domain `TetragonEvent`.
pub fn convert_exit(exit: &ProcessExit) -> Result<TetragonEvent> {
    let process = exit
        .process
        .as_ref()
        .context("ProcessExit missing process field")?;

    let (process_id, parent_id) = extract_ids(process, exit.parent.as_ref());
    let timestamp = extract_timestamp(exit.time.as_ref());

    // Parse signal string into an integer if present (e.g. "SIGKILL" -> Some(9)).
    let signal = if exit.signal.is_empty() {
        None
    } else {
        signal_name_to_number(&exit.signal)
    };

    Ok(TetragonEvent {
        id: Uuid::new_v4(),
        timestamp,
        kind: EventKind::ProcessExit {
            exit_code: exit.status as i32,
            signal,
        },
        process_id,
        parent_id,
        policy_name: None,
    })
}

/// Convert a `ProcessKprobe` proto message into a domain `TetragonEvent`.
///
/// Maps known function names to the appropriate `EventKind`:
/// - `tcp_connect`, `__sys_connect` -> `NetworkConnect`
/// - `commit_creds` -> `PrivilegeChange`
/// - `security_file_open`, `security_file_permission` -> `FileAccess`
/// - `security_bprm_check`, `bprm_check_security` -> `ScriptExec`
/// - others -> returns `Ok(None)`
pub fn convert_kprobe(kp: &ProcessKprobe) -> Result<Option<TetragonEvent>> {
    let process = kp
        .process
        .as_ref()
        .context("ProcessKprobe missing process field")?;

    let (process_id, parent_id) = extract_ids(process, kp.parent.as_ref());
    let timestamp = extract_timestamp(process.start_time.as_ref());

    let kind = match kp.function_name.as_str() {
        "tcp_connect" | "__sys_connect" => {
            let (dest_ip, dest_port, protocol) = extract_network_info(&kp.args);
            EventKind::NetworkConnect {
                dest_ip,
                dest_port,
                protocol,
            }
        }
        "commit_creds" => {
            let (old_uid, new_uid) = extract_cred_change(&kp.args);
            EventKind::PrivilegeChange {
                old_uid,
                new_uid,
                function_name: kp.function_name.clone(),
            }
        }
        "security_file_open" | "security_file_permission" => {
            let (path, access_type) = extract_file_info(&kp.args);
            EventKind::FileAccess { path, access_type }
        }
        "security_bprm_check" | "bprm_check_security" => {
            let script_path = extract_binprm_path(&kp.args);
            let paused =
                kp.action == crate::tetragon::KprobeAction::Override as i32;
            EventKind::ScriptExec {
                script_path: script_path.clone(),
                interpreter: process.binary.clone(),
                paused,
            }
        }
        other => {
            tracing::debug!(function_name = other, "ignoring unhandled kprobe");
            return Ok(None);
        }
    };

    let policy_name = if kp.policy_name.is_empty() {
        None
    } else {
        Some(kp.policy_name.clone())
    };

    Ok(Some(TetragonEvent {
        id: Uuid::new_v4(),
        timestamp,
        kind,
        process_id,
        parent_id,
        policy_name,
    }))
}

/// Convert a `ProcessLsm` proto message into a domain `TetragonEvent`.
///
/// Maps known LSM hook names to the appropriate `EventKind`:
/// - `security_file_permission` -> `FileAccess`
/// - `bprm_check_security` -> `ScriptExec`
/// - others -> returns `Ok(None)`
pub fn convert_lsm(lsm: &ProcessLsm) -> Result<Option<TetragonEvent>> {
    let process = lsm
        .process
        .as_ref()
        .context("ProcessLsm missing process field")?;

    let (process_id, parent_id) = extract_ids(process, lsm.parent.as_ref());
    let timestamp = extract_timestamp(process.start_time.as_ref());

    let kind = match lsm.function_name.as_str() {
        "security_file_permission" => {
            let (path, access_type) = extract_file_info(&lsm.args);
            EventKind::FileAccess { path, access_type }
        }
        "bprm_check_security" => {
            let script_path = extract_binprm_path(&lsm.args);
            let paused =
                lsm.action == crate::tetragon::KprobeAction::Override as i32;
            EventKind::ScriptExec {
                script_path: script_path.clone(),
                interpreter: process.binary.clone(),
                paused,
            }
        }
        other => {
            tracing::debug!(function_name = other, "ignoring unhandled LSM hook");
            return Ok(None);
        }
    };

    let policy_name = if lsm.policy_name.is_empty() {
        None
    } else {
        Some(lsm.policy_name.clone())
    };

    Ok(Some(TetragonEvent {
        id: Uuid::new_v4(),
        timestamp,
        kind,
        process_id,
        parent_id,
        policy_name,
    }))
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Extract process and parent IDs from proto messages.
fn extract_ids(process: &Process, parent: Option<&Process>) -> (u32, Option<u32>) {
    let process_id = process.pid.unwrap_or(0);
    let parent_id = parent.and_then(|p| p.pid);
    (process_id, parent_id)
}

/// Convert a prost Timestamp into a chrono DateTime<Utc>.
fn extract_timestamp(ts: Option<&prost_types::Timestamp>) -> DateTime<Utc> {
    ts.and_then(|t| {
        Utc.timestamp_opt(t.seconds, t.nanos as u32).single()
    })
    .unwrap_or_else(Utc::now)
}

/// Parse the Tetragon `arguments` string into a Vec of individual arguments.
///
/// Tetragon concatenates arguments into a single space-separated string.
fn parse_arguments(arguments: &str) -> Vec<String> {
    if arguments.is_empty() {
        return vec![];
    }
    arguments.split(' ').map(String::from).collect()
}

/// Extract network connection information from kprobe arguments.
///
/// Looks for `SockArg`, `SockaddrArg`, or `SkbArg` in the argument list.
fn extract_network_info(
    args: &[crate::tetragon::KprobeArgument],
) -> (String, u16, String) {
    for arg in args {
        if let Some(ref inner) = arg.arg {
            match inner {
                kprobe_argument::Arg::SockArg(sock) => {
                    return (
                        sock.daddr.clone(),
                        sock.dport as u16,
                        sock.protocol.clone(),
                    );
                }
                kprobe_argument::Arg::SockaddrArg(sa) => {
                    return (sa.addr.clone(), sa.port as u16, String::from("tcp"));
                }
                kprobe_argument::Arg::SkbArg(skb) => {
                    return (
                        skb.daddr.clone(),
                        skb.dport as u16,
                        skb.protocol.clone(),
                    );
                }
                _ => {}
            }
        }
    }

    // No network info found -- return defaults.
    (String::from("unknown"), 0, String::from("unknown"))
}

/// Extract credential change information from kprobe arguments.
///
/// Looks for `ProcessCredentialsArg` in the argument list.
/// Since commit_creds typically modifies the process credentials, we attempt
/// to extract old/new UIDs from available arguments.
fn extract_cred_change(args: &[crate::tetragon::KprobeArgument]) -> (u32, u32) {
    for arg in args {
        if let Some(ref inner) = arg.arg {
            if let kprobe_argument::Arg::ProcessCredentialsArg(cred) = inner {
                let uid = cred.uid.unwrap_or(0);
                let euid = cred.euid.unwrap_or(0);
                return (uid, euid);
            }
        }
    }
    (0, 0)
}

/// Parse mount + path + permission into (full_path, access_type).
fn parse_file_fields(mount: &str, path: &str, permission: &str) -> (String, FileAccessType) {
    let access_type = if permission.contains('w') {
        FileAccessType::Write
    } else {
        FileAccessType::Read
    };
    let full_path = if mount.is_empty() {
        path.to_owned()
    } else {
        format!("{mount}{path}")
    };
    (full_path, access_type)
}

/// Extract file path and access type from LSM hook arguments.
fn extract_file_info(
    args: &[crate::tetragon::KprobeArgument],
) -> (String, FileAccessType) {
    for arg in args {
        if let Some(ref inner) = arg.arg {
            match inner {
                kprobe_argument::Arg::FileArg(f) => {
                    return parse_file_fields(&f.mount, &f.path, &f.permission);
                }
                kprobe_argument::Arg::PathArg(p) => {
                    return parse_file_fields(&p.mount, &p.path, &p.permission);
                }
                _ => {}
            }
        }
    }
    (String::from("unknown"), FileAccessType::Read)
}

/// Extract the binary path from a `bprm_check_security` LSM hook's arguments.
fn extract_binprm_path(args: &[crate::tetragon::KprobeArgument]) -> String {
    for arg in args {
        if let Some(ref inner) = arg.arg {
            if let kprobe_argument::Arg::LinuxBinprmArg(binprm) = inner {
                return binprm.path.clone();
            }
        }
    }
    String::from("unknown")
}

/// Best-effort mapping from signal name strings to numbers.
fn signal_name_to_number(signal: &str) -> Option<i32> {
    // Try parsing as a plain number first.
    if let Ok(n) = signal.parse::<i32>() {
        return Some(n);
    }

    match signal {
        "SIGHUP" => Some(1),
        "SIGINT" => Some(2),
        "SIGQUIT" => Some(3),
        "SIGILL" => Some(4),
        "SIGTRAP" => Some(5),
        "SIGABRT" | "SIGIOT" => Some(6),
        "SIGBUS" => Some(7),
        "SIGFPE" => Some(8),
        "SIGKILL" => Some(9),
        "SIGUSR1" => Some(10),
        "SIGSEGV" => Some(11),
        "SIGUSR2" => Some(12),
        "SIGPIPE" => Some(13),
        "SIGALRM" => Some(14),
        "SIGTERM" => Some(15),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tetragon::{
        get_events_response, kprobe_argument, GetEventsResponse, KprobeArgument,
        KprobeFile, KprobeLinuxBinprm, KprobeSock, Process, ProcessExec, ProcessExit,
        ProcessKprobe, ProcessLsm,
    };

    /// Helper to create a minimal `Process` proto message.
    fn mock_process(pid: u32, binary: &str, arguments: &str) -> Process {
        Process {
            exec_id: format!("test-exec-{pid}"),
            pid: Some(pid),
            uid: Some(1000),
            cwd: "/home/user".to_owned(),
            binary: binary.to_owned(),
            arguments: arguments.to_owned(),
            flags: String::new(),
            start_time: Some(prost_types::Timestamp {
                seconds: 1700000000,
                nanos: 0,
            }),
            auid: None,
            pod: None,
            docker: String::new(),
            parent_exec_id: String::new(),
            refcnt: 0,
            cap: None,
            ns: None,
            tid: None,
            process_credentials: None,
            binary_properties: None,
            user: None,
            in_init_tree: None,
        }
    }

    #[test]
    fn convert_process_exec() {
        let exec = ProcessExec {
            process: Some(mock_process(
                1234,
                "/usr/bin/curl",
                "curl https://example.com",
            )),
            parent: Some(mock_process(1200, "/bin/bash", "bash")),
            ancestors: vec![],
        };

        let resp = GetEventsResponse {
            node_name: String::new(),
            time: None,
            aggregation_info: None,
            cluster_name: String::new(),
            node_labels: Default::default(),
            event: Some(get_events_response::Event::ProcessExec(exec)),
        };

        let result = convert_response(&resp).expect("conversion should succeed");
        let event = result.expect("should produce an event");

        assert_eq!(event.process_id, 1234);
        assert_eq!(event.parent_id, Some(1200));
        match &event.kind {
            EventKind::ProcessExec {
                binary,
                args,
                cwd,
                uid,
            } => {
                assert_eq!(binary, "/usr/bin/curl");
                assert_eq!(args, &["curl", "https://example.com"]);
                assert_eq!(cwd, "/home/user");
                assert_eq!(*uid, 1000);
            }
            other => panic!("expected ProcessExec, got {other:?}"),
        }
    }

    #[test]
    fn convert_process_exit() {
        let exit = ProcessExit {
            process: Some(mock_process(5678, "/usr/bin/ls", "ls -la")),
            parent: None,
            signal: "SIGTERM".to_owned(),
            status: 143,
            time: Some(prost_types::Timestamp {
                seconds: 1700000010,
                nanos: 0,
            }),
            ancestors: vec![],
        };

        let resp = GetEventsResponse {
            node_name: String::new(),
            time: None,
            aggregation_info: None,
            cluster_name: String::new(),
            node_labels: Default::default(),
            event: Some(get_events_response::Event::ProcessExit(exit)),
        };

        let result = convert_response(&resp).expect("conversion should succeed");
        let event = result.expect("should produce an event");

        assert_eq!(event.process_id, 5678);
        match &event.kind {
            EventKind::ProcessExit { exit_code, signal } => {
                assert_eq!(*exit_code, 143);
                assert_eq!(*signal, Some(15));
            }
            other => panic!("expected ProcessExit, got {other:?}"),
        }
    }

    #[test]
    fn convert_kprobe_tcp_connect() {
        let kp = ProcessKprobe {
            process: Some(mock_process(
                2000,
                "/usr/bin/curl",
                "curl https://evil.com",
            )),
            parent: Some(mock_process(1999, "/bin/bash", "bash")),
            function_name: "tcp_connect".to_owned(),
            args: vec![KprobeArgument {
                label: String::new(),
                arg: Some(kprobe_argument::Arg::SockArg(KprobeSock {
                    family: "AF_INET".to_owned(),
                    r#type: "SOCK_STREAM".to_owned(),
                    protocol: "tcp".to_owned(),
                    mark: 0,
                    priority: 0,
                    saddr: "10.0.0.1".to_owned(),
                    daddr: "93.184.216.34".to_owned(),
                    sport: 45000,
                    dport: 443,
                    cookie: 0,
                    state: "TCP_SYN_SENT".to_owned(),
                })),
            }],
            r#return: None,
            action: 0,
            kernel_stack_trace: vec![],
            policy_name: "net-monitor".to_owned(),
            return_action: 0,
            message: String::new(),
            tags: vec![],
            user_stack_trace: vec![],
            ancestors: vec![],
            data: vec![],
        };

        let resp = GetEventsResponse {
            node_name: String::new(),
            time: None,
            aggregation_info: None,
            cluster_name: String::new(),
            node_labels: Default::default(),
            event: Some(get_events_response::Event::ProcessKprobe(kp)),
        };

        let result = convert_response(&resp).expect("conversion should succeed");
        let event = result.expect("should produce an event");

        assert_eq!(event.process_id, 2000);
        assert_eq!(event.policy_name.as_deref(), Some("net-monitor"));
        match &event.kind {
            EventKind::NetworkConnect {
                dest_ip,
                dest_port,
                protocol,
            } => {
                assert_eq!(dest_ip, "93.184.216.34");
                assert_eq!(*dest_port, 443);
                assert_eq!(protocol, "tcp");
            }
            other => panic!("expected NetworkConnect, got {other:?}"),
        }
    }

    #[test]
    fn convert_kprobe_unknown_returns_none() {
        let kp = ProcessKprobe {
            process: Some(mock_process(3000, "/usr/bin/test", "")),
            parent: None,
            function_name: "some_unknown_function".to_owned(),
            args: vec![],
            r#return: None,
            action: 0,
            kernel_stack_trace: vec![],
            policy_name: String::new(),
            return_action: 0,
            message: String::new(),
            tags: vec![],
            user_stack_trace: vec![],
            ancestors: vec![],
            data: vec![],
        };

        let resp = GetEventsResponse {
            node_name: String::new(),
            time: None,
            aggregation_info: None,
            cluster_name: String::new(),
            node_labels: Default::default(),
            event: Some(get_events_response::Event::ProcessKprobe(kp)),
        };

        let result = convert_response(&resp).expect("conversion should succeed");
        assert!(result.is_none(), "unknown kprobe should return None");
    }

    #[test]
    fn convert_lsm_file_permission() {
        let lsm = ProcessLsm {
            process: Some(mock_process(4000, "/usr/bin/cat", "cat /etc/passwd")),
            parent: None,
            function_name: "security_file_permission".to_owned(),
            policy_name: "file-monitor".to_owned(),
            message: String::new(),
            args: vec![KprobeArgument {
                label: String::new(),
                arg: Some(kprobe_argument::Arg::FileArg(KprobeFile {
                    mount: String::new(),
                    path: "/etc/passwd".to_owned(),
                    flags: String::new(),
                    permission: "r".to_owned(),
                })),
            }],
            action: 0,
            tags: vec![],
            ancestors: vec![],
            ima_hash: String::new(),
        };

        let resp = GetEventsResponse {
            node_name: String::new(),
            time: None,
            aggregation_info: None,
            cluster_name: String::new(),
            node_labels: Default::default(),
            event: Some(get_events_response::Event::ProcessLsm(lsm)),
        };

        let result = convert_response(&resp).expect("conversion should succeed");
        let event = result.expect("should produce an event");

        assert_eq!(event.process_id, 4000);
        assert_eq!(event.policy_name.as_deref(), Some("file-monitor"));
        match &event.kind {
            EventKind::FileAccess { path, access_type } => {
                assert_eq!(path, "/etc/passwd");
                assert_eq!(*access_type, FileAccessType::Read);
            }
            other => panic!("expected FileAccess, got {other:?}"),
        }
    }

    #[test]
    fn convert_lsm_bprm_check_security() {
        let lsm = ProcessLsm {
            process: Some(mock_process(5000, "/usr/bin/python3", "")),
            parent: None,
            function_name: "bprm_check_security".to_owned(),
            policy_name: String::new(),
            message: String::new(),
            args: vec![KprobeArgument {
                label: String::new(),
                arg: Some(kprobe_argument::Arg::LinuxBinprmArg(KprobeLinuxBinprm {
                    path: "/tmp/malicious.sh".to_owned(),
                    flags: String::new(),
                    permission: String::new(),
                })),
            }],
            action: 0,
            tags: vec![],
            ancestors: vec![],
            ima_hash: String::new(),
        };

        let resp = GetEventsResponse {
            node_name: String::new(),
            time: None,
            aggregation_info: None,
            cluster_name: String::new(),
            node_labels: Default::default(),
            event: Some(get_events_response::Event::ProcessLsm(lsm)),
        };

        let result = convert_response(&resp).expect("conversion should succeed");
        let event = result.expect("should produce an event");

        match &event.kind {
            EventKind::ScriptExec {
                script_path,
                interpreter,
                paused,
            } => {
                assert_eq!(script_path, "/tmp/malicious.sh");
                assert_eq!(interpreter, "/usr/bin/python3");
                assert!(!paused);
            }
            other => panic!("expected ScriptExec, got {other:?}"),
        }
    }

    #[test]
    fn convert_lsm_unknown_returns_none() {
        let lsm = ProcessLsm {
            process: Some(mock_process(6000, "/usr/bin/test", "")),
            parent: None,
            function_name: "some_unknown_lsm_hook".to_owned(),
            policy_name: String::new(),
            message: String::new(),
            args: vec![],
            action: 0,
            tags: vec![],
            ancestors: vec![],
            ima_hash: String::new(),
        };

        let resp = GetEventsResponse {
            node_name: String::new(),
            time: None,
            aggregation_info: None,
            cluster_name: String::new(),
            node_labels: Default::default(),
            event: Some(get_events_response::Event::ProcessLsm(lsm)),
        };

        let result = convert_response(&resp).expect("conversion should succeed");
        assert!(result.is_none(), "unknown LSM hook should return None");
    }

    #[test]
    fn empty_event_returns_none() {
        let resp = GetEventsResponse {
            node_name: String::new(),
            time: None,
            aggregation_info: None,
            cluster_name: String::new(),
            node_labels: Default::default(),
            event: None,
        };

        let result = convert_response(&resp).expect("conversion should succeed");
        assert!(result.is_none(), "empty event should return None");
    }

    #[test]
    fn signal_name_parsing() {
        assert_eq!(signal_name_to_number("SIGKILL"), Some(9));
        assert_eq!(signal_name_to_number("SIGTERM"), Some(15));
        assert_eq!(signal_name_to_number("9"), Some(9));
        assert_eq!(signal_name_to_number("UNKNOWN_SIGNAL"), None);
        assert_eq!(signal_name_to_number(""), None);
    }

    #[test]
    fn lsm_bprm_override_sets_paused_true() {
        let lsm = ProcessLsm {
            process: Some(mock_process(7000, "/usr/bin/node", "")),
            parent: None,
            function_name: "bprm_check_security".to_owned(),
            policy_name: "watchpost-install-script-gate".to_owned(),
            message: String::new(),
            args: vec![KprobeArgument {
                label: String::new(),
                arg: Some(kprobe_argument::Arg::LinuxBinprmArg(KprobeLinuxBinprm {
                    path: "/tmp/postinstall.sh".to_owned(),
                    flags: String::new(),
                    permission: String::new(),
                })),
            }],
            action: crate::tetragon::KprobeAction::Override as i32, // 5
            tags: vec![],
            ancestors: vec![],
            ima_hash: String::new(),
        };

        let resp = GetEventsResponse {
            node_name: String::new(),
            time: None,
            aggregation_info: None,
            cluster_name: String::new(),
            node_labels: Default::default(),
            event: Some(get_events_response::Event::ProcessLsm(lsm)),
        };

        let result = convert_response(&resp).expect("conversion should succeed");
        let event = result.expect("should produce an event");

        match &event.kind {
            EventKind::ScriptExec {
                script_path,
                interpreter,
                paused,
            } => {
                assert_eq!(script_path, "/tmp/postinstall.sh");
                assert_eq!(interpreter, "/usr/bin/node");
                assert!(
                    *paused,
                    "Override action should set paused to true"
                );
            }
            other => panic!("expected ScriptExec, got {other:?}"),
        }
        assert_eq!(
            event.policy_name.as_deref(),
            Some("watchpost-install-script-gate")
        );
    }

    #[test]
    fn lsm_bprm_post_sets_paused_false() {
        let lsm = ProcessLsm {
            process: Some(mock_process(7001, "/usr/bin/bash", "")),
            parent: None,
            function_name: "bprm_check_security".to_owned(),
            policy_name: "watchpost-tmp-execution".to_owned(),
            message: String::new(),
            args: vec![KprobeArgument {
                label: String::new(),
                arg: Some(kprobe_argument::Arg::LinuxBinprmArg(KprobeLinuxBinprm {
                    path: "/tmp/safe-script.sh".to_owned(),
                    flags: String::new(),
                    permission: String::new(),
                })),
            }],
            action: crate::tetragon::KprobeAction::Post as i32, // 1
            tags: vec![],
            ancestors: vec![],
            ima_hash: String::new(),
        };

        let resp = GetEventsResponse {
            node_name: String::new(),
            time: None,
            aggregation_info: None,
            cluster_name: String::new(),
            node_labels: Default::default(),
            event: Some(get_events_response::Event::ProcessLsm(lsm)),
        };

        let result = convert_response(&resp).expect("conversion should succeed");
        let event = result.expect("should produce an event");

        match &event.kind {
            EventKind::ScriptExec {
                script_path,
                interpreter,
                paused,
            } => {
                assert_eq!(script_path, "/tmp/safe-script.sh");
                assert_eq!(interpreter, "/usr/bin/bash");
                assert!(
                    !*paused,
                    "Post action should set paused to false"
                );
            }
            other => panic!("expected ScriptExec, got {other:?}"),
        }
    }

    #[test]
    fn install_script_gate_policy_is_valid_yaml() {
        let yaml_content =
            std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../policies/install-script-gate.yaml"))
                .expect("policy file should exist");
        let doc: serde_yml::Value =
            serde_yml::from_str(&yaml_content).expect("policy should be valid YAML");

        // Verify basic structure
        assert_eq!(
            doc["apiVersion"].as_str().unwrap(),
            "cilium.io/v1alpha1"
        );
        assert_eq!(doc["kind"].as_str().unwrap(), "TracingPolicy");
        assert_eq!(
            doc["metadata"]["name"].as_str().unwrap(),
            "watchpost-install-script-gate"
        );

        let kprobes = doc["spec"]["kprobes"].as_sequence().unwrap();
        assert_eq!(kprobes.len(), 1);
        assert_eq!(
            kprobes[0]["call"].as_str().unwrap(),
            "security_bprm_check"
        );

        let selectors = kprobes[0]["selectors"].as_sequence().unwrap();
        assert_eq!(selectors.len(), 2, "should have two selectors");

        // Both selectors should use Post action (advisory mode on non-LSM kernels)
        for sel in selectors {
            let action = sel["matchActions"][0]["action"].as_str().unwrap();
            assert_eq!(action, "Post");
        }
    }
}
