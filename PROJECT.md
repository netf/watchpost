# Watchpost: eBPF-Powered Intelligent Desktop Security Agent

## Document Purpose

This document is the authoritative design specification for Watchpost. It describes what we are building, why every decision was made, and how the pieces fit together. It contains no source code. An AI coding agent should be able to read this document and produce a complete implementation guide with concrete file-by-file instructions, dependency lists, and build configurations.

---

## 1. What Watchpost Is

Watchpost is a Rust daemon that provides intelligent runtime security monitoring for Linux desktop workstations. It consumes kernel-level telemetry from Cilium Tetragon (an eBPF-based security observability tool), enriches those raw events with desktop context, applies a two-tier classification system (deterministic rules followed by LLM-powered semantic analysis), and delivers actionable security verdicts through desktop notifications, event logs, and adaptive Tetragon policy management.

The name "Watchpost" evokes a sentry position — a point of elevated observation with clear lines of sight. The daemon observes everything entering and leaving the system boundary, decides what is threatening, and raises the alarm or takes defensive action.

### 1.1 The Problem

A Linux desktop used for software development is one of the most attack-surface-rich environments imaginable. Every `npm install`, `pip install`, `cargo build`, Flatpak app launch, browser extension, and VS Code plugin is a vector for supply chain compromise, data exfiltration, or privilege escalation. Traditional desktop security tools (antivirus, file integrity monitoring, auditd) are either too noisy, too slow, or too blind to catch modern attacks that operate within the boundaries of "legitimate" developer behavior.

The specific gap: no existing tool correlates *what the user intended to do* (install a package, build a project, launch an app) with *what the system actually did* at the kernel level (spawned a reverse shell, wrote to SSH keys, contacted a command-and-control server). This semantic gap is where supply chain attacks live — the attack hides inside a legitimate action.

### 1.2 The Insight from AgentSight

Watchpost is directly inspired by the AgentSight research paper ("AgentSight: System-Level Observability for AI Agents Using eBPF," Zheng et al., PACMI 2025, https://arxiv.org/abs/2508.02736). AgentSight solved a parallel problem: how do you monitor AI coding agents (like Claude Code or Gemini CLI) that autonomously execute shell commands, write files, and make network requests? Their answer was "boundary tracing" — monitoring at the two stable interfaces where any process interacts with the outside world:

1. The **network boundary** (intercepting TLS-encrypted LLM API traffic to understand the agent's *intent*)
2. The **kernel boundary** (monitoring syscalls to observe the agent's *actions*)

They then built a correlation engine using three signals — process lineage, temporal proximity, and argument matching — to causally link intent to action. Finally, they passed the correlated trace to a secondary "observer" LLM that performed semantic analysis to classify behavior as benign, malicious, or anomalous.

Watchpost takes this architecture and reframes it for desktop security:

- AgentSight's "intent stream" (LLM API traffic) becomes Watchpost's "user action context" (what launched the process, which package is being installed, which IDE triggered the action)
- AgentSight's "action stream" (custom eBPF kprobes and tracepoints) becomes Watchpost's Tetragon event stream (the same kernel events, but collected via Tetragon's managed TracingPolicies instead of custom eBPF programs)
- AgentSight's correlation engine maps directly — the same three signals apply
- AgentSight's observer LLM becomes Watchpost's analyzer, classifying desktop threat traces instead of AI agent traces

### 1.3 Target Platform

Watchpost targets immutable Fedora desktops (Kinoite/Silverblue) as its primary platform, but should work on any modern Linux distribution with kernel 5.15+ and BTF support. The immutable base OS provides a strong foundation: `/usr` is read-only by default, the package manager is rpm-ostree, and user applications run in Flatpak sandboxes or toolbox containers. Watchpost's job is to monitor everything that happens *outside* those guarantees — the mutable home directory, npm/pip/cargo packages, Flatpak sandbox escapes, and any process that tries to modify the immutable base.

### 1.4 What Watchpost Is Not

- Not a firewall or network filter. It does not intercept or block network traffic. It observes network connection events reported by Tetragon and makes classification decisions.
- Not an antivirus. It does not scan files for signatures. It monitors runtime behavior.
- Not a replacement for Tetragon. Tetragon handles all eBPF instrumentation. Watchpost is the intelligence layer that consumes Tetragon's output and makes it actionable.
- Not a SIEM. It is a single-host desktop agent, not a centralized log aggregation system. It can forward events to a SIEM, but that is not its primary function.

---

## 2. Architecture Overview

Watchpost is a single Rust binary (with a workspace of library crates) that runs as a systemd service alongside Tetragon. The data flows through a pipeline of seven stages:

```
Tetragon eBPF (kernel) 
    → [gRPC stream] 
    → Collector (context enrichment + toolbox/Flatpak awareness) 
    → Engine (multi-horizon correlation + scoring + package provenance) 
    → Rules (deterministic fast path) / Analyzer (agentic LLM slow path)
    → Pre-execution Gate (script analysis before execution, for package installs)
    → Policy Manager (TracingPolicy lifecycle)
    → Notifier (desktop alerts + event log + user feedback loop)
```

### 2.1 Design Principles

**The best security is the kind you forget is there.** Watchpost is an invisible guardian. A developer working normally sees zero notifications per day. The system silently classifies thousands of kernel events per minute, allows legitimate work, and blocks threats — all without interrupting flow. The only time the developer sees Watchpost is when something genuinely dangerous happened and was stopped. If the system generates more than 2-3 notifications per week during normal development, that is a bug in the profiles or thresholds, not expected behavior.

**Smart from minute one.** No calibration period. No learning phase. Watchpost ships with curated behavior profiles that cover 95% of developer workflows on first install — including known-good patterns for the top 1000 npm packages, common cargo/pip build patterns, and all standard toolchains. The system still learns and refines from the user's specific environment, but it starts smart, not blank.

**One command to protect.** `watchpost init` takes an API key, auto-detects installed toolchains, and starts monitoring. No config files to write, no YAML to edit, no services to enable manually. Power users can customize everything; everyone else never touches a config file.

**Tetragon does the kernel work; Watchpost does the thinking.** We deliberately avoid writing any custom eBPF programs. Tetragon is maintained by the Cilium team, many of whom are kernel developers. Their TracingPolicies are declarative YAML files that specify which kprobes, tracepoints, and LSM hooks to instrument. Watchpost generates, manages, and hot-reloads these YAML files. This means zero eBPF C code to maintain, automatic compatibility with kernel upgrades (Tetragon handles CO-RE/BTF), and the ability to focus entirely on the intelligence layer.

**Two-tier classification: fast deterministic rules, slow semantic analysis.** Every correlated event trace first passes through a heuristic scoring function. High-scoring traces (obvious threats like binary execution from `/tmp` by an npm postinstall script) go to the deterministic rule engine, which matches patterns and returns verdicts in microseconds. Ambiguous traces (score above a minimum threshold but not matching any rule) are queued for LLM analysis. Low-scoring traces are simply logged. This means the common case (benign developer activity) generates zero LLM calls, and obvious attacks are caught instantly without waiting for inference.

**Remote-first LLM inference.** Watchpost defaults to the Anthropic API using Claude Haiku 4.5 (model ID: `claude-haiku-4-5-20251001`) for semantic analysis. At $1/$5 per million input/output tokens and with the rate limiter keeping analyses to ~10/minute, the cost for a typical desktop session is negligible. Anthropic's structured output support (GA via `output_config.format` parameter) guarantees schema-validated JSON responses without retry logic. A local Ollama backend is available as an alternative for offline or air-gapped environments, or for users who prefer not to send security telemetry to external APIs.

**The LLM understands valid kernel behavior and acts on it.** Every action context (package install, build, Flatpak launch, shell command) has an expected behavior profile — a set of kernel operations that are consistent with the stated purpose. `npm install express` *should* make network connections to registry.npmjs.org and write to `node_modules/`. It *should not* read `~/.ssh/`, connect to unknown IPs, or execute binaries from `/tmp`. The LLM evaluates each observed kernel action against the behavior profile and acts autonomously: blocking forbidden behavior immediately (SIGKILL), allowing expected behavior silently, and reasoning about unspecified behavior before deciding.

**Analyze before execution, not just after.** For the highest-risk operation class — package install scripts — Watchpost intercepts script execution using Tetragon's `bprm_check_security` LSM hook with `Override` action to pause execution, reads the script content, sends it to the LLM for pre-execution analysis, and autonomously allows or blocks based on the verdict. This shifts the architecture from reactive ("detect and alert after damage") to proactive ("analyze and gate before execution"). The ~200ms latency for Haiku analysis is invisible in the context of package install operations that take seconds to minutes.

**The LLM is an agent, not an oracle.** Rather than single-shot prompt → verdict, the analyzer operates as a tool-using agent that can request additional context: read files, query the process tree, check package registries, or look up IP reputation. This dramatically improves analysis quality for ambiguous cases — the LLM can follow its reasoning ("this process connected to 185.x.x.x — let me check if the package.json declares that as a registry") instead of being limited to whatever context was pre-assembled in the prompt.

**User overrides refine the model silently.** When Watchpost blocks a process and the user clicks "Undo", the pattern is permanently allowlisted and the scoring weights adjust — all without further notifications. Over time, the system converges on the user's specific development patterns. If the user overrides too often (>3 times per week), the system automatically becomes more conservative about blocking. This learning is entirely invisible — no "threshold adjusted" notifications, no "allowlist proposal" popups.

**Desktop-native, not server-oriented.** The event log is a local SQLite database. The optional TUI dashboard uses ratatui. The daemon is designed for a single user's workstation, not a fleet of servers.

---

## 3. The Threat Model

Watchpost protects against threats that emerge at runtime on a developer's Linux desktop. These are threats that static analysis, signature scanning, and build-time checks cannot catch because the malicious behavior only manifests when the code executes.

### 3.1 Supply Chain Attacks via Package Managers

This is the primary threat Watchpost is designed to detect. Modern supply chain attacks compromise a dependency that the developer trusts (or a dependency of a dependency) and use the installation or build process to execute malicious code. Examples include the event-stream incident (npm), the ua-parser-js compromise, the PyPI typosquatting campaigns, and the xz-utils backdoor.

The attack pattern is consistent: a package's install hook (npm `postinstall`, pip `setup.py`, cargo `build.rs`) spawns child processes that perform actions inconsistent with the stated purpose of the package. These actions include downloading and executing binaries, reading SSH keys or environment variables containing tokens, opening reverse shell connections, or modifying system files.

Watchpost detects this by correlating the trigger (package install command) with the child process behavior (network connections to non-registry IPs, file access to sensitive paths, execution of downloaded binaries from temporary directories). The process ancestry chain is the key signal: if `npm → node → sh → curl → /tmp/payload` fires within 30 seconds of `npm install`, that is a supply chain attack pattern regardless of which specific package triggered it.

### 3.2 Privilege Escalation

Any process that changes its credentials (via `commit_creds`, `setuid`, `setgid`, or capability manipulation) from an unexpected context. On a desktop, legitimate privilege escalation happens through `sudo`, `pkexec`, `polkit`, and `systemd` — all of which have predictable process ancestry. A privilege escalation from a Flatpak app, a browser child process, or an npm script is anomalous and should be flagged immediately.

### 3.3 Data Exfiltration

Processes that read sensitive files (SSH keys, GPG keys, browser profiles, password manager databases, environment variables containing API tokens) and then make network connections. The correlation of file-read followed by network-write within the same process group is the detection signal. Sophisticated exfiltration through DNS tunneling (high-entropy DNS queries) or steganographic channels is harder to detect deterministically and is a candidate for LLM analysis.

### 3.4 Sandbox Escapes

Flatpak applications are confined by a namespace and seccomp sandbox. An application that accesses host filesystem paths outside its declared permissions, communicates with the host D-Bus session bus without going through portals, or spawns processes outside its namespace is attempting a sandbox escape. Watchpost monitors for processes in Flatpak cgroups that access paths they should not be able to reach.

### 3.5 Reverse Shells and Remote Access

A process that binds its standard input/output to a network socket, enabling remote interactive access. This is detectable by correlating `dup2` or `dup3` syscalls (redirecting file descriptors 0, 1, 2) with an active `tcp_connect` in the same process. Processes like `nc`, `ncat`, `socat`, and `bash -i` in combination with network activity are strong signals.

### 3.6 Cryptomining

Processes that connect to known Stratum mining pool ports (3333, 4444, 14444, 45700) or exhibit sustained high CPU usage combined with network activity to mining-related infrastructure. This is the simplest threat to detect deterministically and is included in the base policy set.

### 3.7 Immutability Violations

On Fedora Kinoite/Silverblue, the `/usr` filesystem is read-only and managed by rpm-ostree. Any process that attempts to write to `/usr`, `/boot`, `/etc` (outside of ostree transactions), or load kernel modules from non-standard paths is violating the immutability guarantee and is almost certainly malicious or severely misconfigured.

---

## 4. Data Pipeline in Detail

### 4.1 Stage 1: Tetragon Event Collection

Tetragon runs as a separate systemd service and exposes a gRPC API (Unix domain socket at `/var/run/tetragon/tetragon.sock`, or TCP at `localhost:54321` when configured with `--server-address`). Watchpost connects as a gRPC client and subscribes to the event stream using the `GetEvents` RPC on the `FineGuidanceSensors` service (full method: `/tetragon.FineGuidanceSensors/GetEvents`). The same service exposes `AddTracingPolicy` and `DeleteTracingPolicy` RPCs for runtime policy management. Tetragon delivers events in protobuf format.

The events Watchpost consumes:

- **ProcessExec**: A new process was created via `execve`. Contains the binary path, arguments, working directory, UID/GID, parent PID, and capabilities.
- **ProcessExit**: A process terminated. Contains exit code and signal information.
- **Kprobe events**: Triggered when a traced kernel function is called. The specific functions traced depend on which TracingPolicies are loaded. Our base policies trace: `tcp_connect` (outbound TCP connections), `commit_creds` (credential changes), and kernel module loading functions.
- **LSM events**: Triggered on Linux Security Module hooks. Our base policies use `security_file_permission` (file read/write access monitoring — captures actual I/O operations with MAY_READ/MAY_WRITE discrimination), `bprm_check_security` (binary execution control), and `file_open` (fine-grained file open control).
- **Tracepoint events**: Triggered on kernel tracepoints. Used for `sched_process_exec` (process creation) and network-related tracepoints.
- **Additional event types**: Tetragon also generates ProcessUprobe, ProcessLoader, ProcessUsdt, and ProcessThrottle events. These are not consumed by Watchpost's base policies but may appear in the gRPC stream and should be handled gracefully (logged at debug level and discarded).

The protobuf definitions for these events are published by Cilium at `https://github.com/cilium/tetragon/tree/main/api/v1/tetragon`. Watchpost compiles these protos into Rust types using `tonic-build` in a build script.

Tetragon's event stream is high-volume. On an active developer desktop, you might see thousands of events per second during a build. The key to managing this volume is Tetragon's in-kernel filtering: TracingPolicies specify selectors (match on binary path, file path prefix, port number, etc.) so that only relevant events are delivered to userspace. Watchpost's TracingPolicies are designed to be selective enough that the gRPC stream volume stays manageable (target: under 100 events/second sustained, with spikes to 1000/second during builds).

### 4.2 Stage 2: Context Enrichment (Collector)

Raw Tetragon events contain process metadata (PID, binary, arguments, UID) but lack semantic context about *why* the process exists. The collector enriches each event with:

**Process ancestry chain.** Starting from the event's PID, the collector walks the process tree upward through `/proc/{pid}/status` (reading PPid field) until it reaches PID 1 or the session leader. This produces a chain like: `systemd → gdm → gnome-session → gnome-terminal → bash → npm → node → sh → curl`. The ancestry is cached in a concurrent hashmap (keyed by PID) and evicted when a ProcessExit event is received.

**User action context inference.** The collector examines the ancestry chain for known tool binaries and infers what the user was doing:

- If any ancestor is `npm`, `npx`, `yarn`, or `pnpm`: the context is a Node.js package operation. The collector reads `package.json` from the ancestor's working directory to identify the package name and version.
- If any ancestor is `cargo`: the context is a Rust build. The collector reads `Cargo.toml` from the working directory.
- If any ancestor is `pip`, `pip3`, `pipx`, or `uv`: the context is a Python package operation.
- If any ancestor is `flatpak`: the context is a Flatpak application. The collector reads the app ID from the process's cgroup path (`/sys/fs/cgroup/.../app-flatpak-{app_id}-{instance}.scope`).
- If the process runs inside a toolbox or distrobox container: the context is a container development session. Detected via cgroup patterns (`/sys/fs/cgroup/.../libpod-*.scope`), the `container` environment variable, or the presence of `toolbox`/`distrobox` in the ancestry chain. The collector records the container name and image, and treats the containerized session as a distinct development environment. This is critical for Fedora Kinoite/Silverblue, where most developer activity happens inside toolbox containers — without this awareness, normal development would generate constant false positives from namespace boundary crossings.
- If any ancestor is `code` (VS Code), `jetbrains`, or other IDE processes: the context is an IDE operation.
- If the session leader is a terminal emulator and the direct parent is a shell: the context is a shell command, and the collector records the shell's TTY for future correlation.
- Otherwise: context is unknown.

**Package manifest caching.** Reading `package.json` or `Cargo.toml` from disk on every event would be expensive. The collector maintains an LRU cache (default 256 entries) of recently-read manifests keyed by directory path. Cache entries are invalidated when a write event to the manifest file is observed.

**Flatpak metadata.** For processes inside Flatpak sandboxes, the collector reads the declared permissions from `/var/lib/flatpak/app/{app_id}/current/active/metadata` to understand what the app is *supposed* to be able to access. This is compared against what the process actually does.

**Package provenance enrichment.** When the collector identifies a PackageInstall context, it enriches the trigger event with package-level intelligence before forwarding to the engine. This runs as an async background lookup that attaches results to the trigger:
- Package age and download count from the registry API (new packages with few downloads are higher risk)
- `npm audit` / `pip audit` / `cargo audit` known vulnerability status
- Sigstore signature or npm provenance attestation presence (attested packages get a trust bonus)
- Typosquatting distance from top-1000 packages in the same ecosystem (Levenshtein distance ≤ 2 from a popular name is suspicious)
- Registry-source mismatch: the npm/PyPI publish has no corresponding GitHub tag, release, or CI workflow artifact — indicating the publish may have bypassed the project's normal release pipeline (as seen in the 2026 axios compromise where malicious versions were published directly via a compromised npm token with no GitHub release)
These signals feed directly into the engine's heuristic scoring as additional indicators. The registry lookups are cached (LRU, default 1024 entries, 1-hour TTL) to avoid redundant network calls for repeated installs of the same package.

The output of the collector is an "enriched event" that bundles the raw Tetragon event, the process ancestry chain, and the inferred action context. This enriched event is sent to the engine via a bounded async channel (tokio mpsc, default capacity 4096 events).

### 4.3 Stage 3: Correlation and Scoring (Engine)

The engine is the core of Watchpost's intelligence. It maintains three data structures and performs two operations: correlation and scoring.

**Data structure 1: Process tree.** An in-memory representation of all currently-running tracked processes, organized as a tree by parent-child relationships. Updated on every ProcessExec and ProcessExit event. This is a concurrent tree structure (protected by a read-write lock) that supports fast ancestry lookups and subtree queries ("give me all descendants of PID 12345").

**Data structure 2: Multi-horizon time-window buffers.** Instead of a single fixed correlation window, the engine maintains three overlapping time horizons per process group, because different attack classes operate on different timescales:

- **Immediate window** (5 seconds): High-confidence correlation for fast attacks (postinstall reverse shells, immediate payload execution). Events in this window receive the strongest temporal correlation signal.
- **Session window** (duration of the trigger process): Tracks the full lifetime of a user-initiated action. When `npm install` starts, its session window stays open until the npm process exits — whether that takes 2 seconds or 10 minutes. This prevents the fixed-TTL problem where a large `npm install` that takes 3 minutes would lose correlation for child processes spawned in the final minutes. The session window closes when the trigger's root process (e.g., the npm PID) receives a ProcessExit event.
- **Persistent window** (24 hours, backed by SQLite): Catches delayed-execution attacks where a package is installed today but a payload executes hours later (e.g., a cron job planted during install, or a binary that phones home on next login). Events in this window have weak temporal correlation but can be linked by process lineage or argument matching. The persistent window is stored in the event database and survives daemon restarts.

Each window contributes a different temporal correlation weight: immediate (1.0), session (0.7 decaying linearly to 0.3 at process exit), persistent (0.1 constant — weak but non-zero).

**Data structure 3: Active triggers.** A list of currently-active "trigger" events that represent user-initiated actions we want to track the consequences of. When the collector identifies a PackageInstall, Build, or FlatpakLaunch context, that event is registered as an active trigger. The trigger remains active for the duration of its session window (until the root process exits), not a fixed TTL. For the persistent window, trigger metadata is written to SQLite so that events hours later can still be loosely correlated with the original install action.

**Correlation operation.** When a new enriched event arrives, the engine attempts to correlate it with existing triggers and recent events using the three AgentSight signals:

1. *Process lineage*: Is the new event's process a descendant (child, grandchild, etc.) of an active trigger's process? If `npm install` (PID 1000) is an active trigger and a new `tcp_connect` event comes from PID 1005 whose ancestry includes PID 1000, those are correlated by lineage.

2. *Temporal proximity*: Did the new event occur within the correlation window of an active trigger? A `tcp_connect` 2 seconds after `npm install` is strongly correlated. The same event 55 seconds later is weakly correlated. The correlation strength decays linearly with time.

3. *Argument matching*: Do values from the trigger context appear in the new event's arguments? If the `package.json` lists `"registry": "https://registry.npmjs.org"` but the `tcp_connect` resolves to an IP that is not associated with npmjs.org, that is a *negative* argument match (expected value absent, unexpected value present) — a strong suspicion signal.

When correlation succeeds, the engine groups the trigger and all correlated events into a "correlated trace" — a bundle of causally-linked events with metadata about which correlation signals fired and how strong each signal was.

**Scoring operation.** Every correlated trace receives a heuristic suspicion score between 0.0 and 1.0. The score is computed from a weighted sum of indicators:

Indicators that increase the score:
- Network connection to a non-registry IP from a package install context (+0.4)
- Network connection to a known malicious IP or a known C2 port (+0.8)
- File write to a sensitive path (`.ssh/`, `.gnupg/`, `.config/`) from a package install context (+0.5)
- Binary execution from `/tmp`, `/dev/shm`, or `/var/tmp` (+0.6)
- Shell spawned as a child of a package manager or build tool (+0.3)
- `LD_PRELOAD` or `LD_LIBRARY_PATH` set in a child process environment (+0.5)
- `commit_creds` or `setuid` call from a non-privileged context (+0.7)
- DNS query with high Shannon entropy in the query name from a dev tool (+0.3)
- Process stdin/stdout redirected to a socket (reverse shell pattern) (+0.9)
- Script contains obfuscated or encoded content: Base64-encoded strings, hex-encoded payloads, XOR ciphers, or reversed strings in a postinstall script (+0.7)
- Process deletes its own script or modifies its own package.json after execution — anti-forensics behavior (+0.5)

Package provenance indicators (from collector enrichment):
- Package age < 7 days with < 100 downloads (+0.3)
- Package has known vulnerability per `npm audit`/`pip audit`/`cargo audit` (+0.4)
- Package name is Levenshtein distance ≤ 2 from a top-1000 package (typosquatting) (+0.5)
- Package has Sigstore signature or npm provenance attestation (-0.2, trust bonus)
- Package has > 10M weekly downloads and > 5 years of history (-0.3, established trust)
- Package version has no corresponding GitHub tag/release or CI workflow artifact (+0.4, unauthorized publish signal)

Context modifiers that scale the score:
- Package install context: score × 1.5 (supply chain attacks are the primary threat)
- Build context: score × 0.7 (builds are inherently noisy; compilers, linkers, and test runners do unusual things)
- Flatpak context: score × 1.3 (sandbox escapes are high-severity)
- Toolbox/distrobox context: score × 0.8 (containerized development is expected to cross namespace boundaries)
- Unknown context: score × 1.0 (no modification)

The score determines routing:
- Score ≥ 0.7 (fast_path_threshold): sent to the deterministic rule engine. These are likely-malicious traces that should be classified instantly.
- Score ≥ 0.3 and < 0.7 (llm_threshold): sent to the LLM analyzer. These are ambiguous traces that need semantic reasoning.
- Score < 0.3: logged to the event database but not actively classified. These are almost certainly benign.

The thresholds are configurable but the shipped defaults work well for most environments thanks to the curated behavior profiles.

**Action behavior profiles.** The engine maintains a set of curated behavior profiles — one per action context type — that define which kernel operations are valid for that context. These profiles ship pre-populated with real-world data so Watchpost works correctly from first install, not after a learning period.

**Shipped ecosystem profiles** (in `profiles/` directory):
- `npm.yaml`: Known-good patterns for the top 1000 npm packages. Includes: `registry.npmjs.org` + common CDN IPs (github.com release assets, unpkg, jsdelivr) as expected network destinations. `node`, `sh`, `node-gyp`, `make`, `cc`, `python3` as expected native build children. Pre-allowlisted download hosts for packages that legitimately fetch platform binaries (sharp, esbuild, node-sass). Common legitimate postinstall patterns (husky git hooks).
- `cargo.yaml`: `rustc`, `cc`, `ld`, `ar`, `as` as expected children. `crates.io` + known mirrors as expected network. `target/` as expected write path. `build.rs` execution as expected behavior.
- `pip.yaml`: `pypi.org` + known mirrors. `gcc`, `g++`, `python3`, `cmake` as expected children for C extensions. `site-packages/` as expected write path.
- `flatpak.yaml`: Expected portal D-Bus interfaces, declared permission patterns, standard runtime paths (`/app/`, `/usr/` within sandbox).
- `system.yaml`: Known-good privilege escalation paths (sudo, pkexec, polkit, systemd), known-good `/etc/passwd` readers, standard cron/systemd-timer patterns.

**Three-tier behavior classification.** Each behavior observed at runtime falls into one of three categories within the profile:

1. **Expected** — Matches a known-good pattern. Silently allowed. No scoring, no LLM call. Example: `npm install` → `node-gyp` → `make` → `cc`.
2. **Unspecified** — Not in the profile as expected or forbidden. Scored normally and routed to the LLM if ambiguous. The LLM reasons about it using the full profile as context. Example: a build tool shelling out to `python3` — unusual but not malicious.
3. **Forbidden** — Explicitly banned. Always blocked immediately (SIGKILL), no LLM call needed. Example: `setuid` from any package manager context, reading `~/.ssh/` during `npm install`, executing binaries from `/tmp`.

Profiles are defined in YAML files shipped with Watchpost (`profiles/`) and are extensible by the user (`/etc/watchpost/profiles.d/`). The dynamic allowlist extends profiles at runtime — when a user clicks "Undo" on a blocked pattern, it is added to the corresponding profile's expected set. When the LLM analyzer evaluates a trace, the relevant behavior profile is included in its context, grounding its reasoning in concrete expectations rather than relying on general security knowledge alone.

### 4.4 Stage 4a: Deterministic Rule Engine (Fast Path)

The rule engine is a simple pattern matcher that operates on correlated traces. It is intentionally not a general-purpose rule language — complexity belongs in the LLM analyzer, not here. Rules are defined in YAML files and loaded at startup.

Each rule has:
- A name and human-readable description
- A severity level (info, low, medium, high, critical)
- A condition tree (AND/OR composition of predicates)
- An action: `log` (record only), `notify` (desktop notification), `block` (SIGKILL the offending process), or `defer_to_llm` (pause execution via Tetragon `Override` and send to LLM for verdict before allowing/blocking). In advisory enforcement mode, `block` actions are downgraded to `notify`.

Available predicates (all evaluate to true/false against a correlated trace):
- `binary_matches`: the event's binary path matches one of the listed paths
- `ancestor_binary_matches`: any process in the ancestry chain matches
- `file_path_starts_with`: the accessed file path starts with one of the listed prefixes
- `dest_port_is`: the destination port matches one of the listed values
- `dest_ip_outside_allowlist`: the destination IP is NOT in the registry/CDN allowlist
- `exec_from_temp_dir`: the binary was executed from `/tmp`, `/dev/shm`, or `/var/tmp`
- `privilege_change`: the event is a `setuid`, `setgid`, or `commit_creds` call
- `in_flatpak_sandbox`: the process is running inside a Flatpak namespace
- `dns_query_high_entropy`: the DNS query name has Shannon entropy above a threshold
- `ip_reputation_malicious`: the destination IP has a bad reputation score in the threat intelligence cache

Rules are evaluated in priority order (critical first). The first matching rule produces the verdict. If no rule matches, the trace is passed to the LLM analyzer regardless of its score.

The rule engine also integrates with an optional threat intelligence lookup. When a trace contains a network connection, the rule engine can query a local cache of known-malicious IPs (sourced from AbuseIPDB, VirusTotal, or a self-hosted threat feed). The cache is updated periodically (default: every 6 hours) by a background task. If the destination IP has a bad reputation, the score is boosted and the rule engine can match on `ip_reputation_malicious` as a predicate.

Shipped rules (the base set included with Watchpost). All rule names follow the pattern `{context}-{threat}`:

1. `npm-reverse-shell`: npm child process opens a socket on a known reverse shell port (4444, 5555, 1337, 9001) or executes nc/ncat/socat. Action: block, critical.
2. `npm-temp-dir-exec`: npm child process executes a binary from /tmp. Action: block, critical.
3. `npm-ssh-key-access`: npm child process reads or writes ~/.ssh/. Action: block, high.
4. `pip-sensitive-file-access`: pip child process accesses ~/.ssh/, ~/.gnupg/, or browser profile directories. Action: block, high.
5. `any-temp-dir-exec`: any process executes from /tmp or /dev/shm (not matching a known-good exception list). Action: notify, medium.
6. `any-unexpected-privilege-change`: commit_creds or setuid from a process whose ancestry does not include sudo, pkexec, polkit, or systemd. Action: block, high.
7. `flatpak-host-file-escape`: Flatpak-sandboxed process accesses /home/ or /etc/ paths not declared in its permissions. Action: block, high.
8. `any-crypto-mining-port`: any process connects to port 3333, 4444, 14444, or 45700. Action: block, critical.
9. `any-immutability-violation`: any process attempts to write to /usr/ outside an rpm-ostree transaction. Action: block, critical.
10. `any-dns-exfiltration`: DNS query from a dev tool child process has Shannon entropy > 4.0 in the query name. Action: defer_to_llm, medium.

### 4.5 Stage 4b: LLM Semantic Analysis (Slow Path)

Traces that are ambiguous (scored between the thresholds, or not matched by any deterministic rule) are sent to the LLM analyzer for semantic classification. This is the component that brings genuine intelligence to the system — the ability to reason about whether a sequence of events is consistent with the stated user action context.

**Analyzer skill specification.** The LLM analyzer is not an ad-hoc prompt — it is a carefully designed agent skill that must be version-controlled, testable against real traces, and iterable without recompiling. The skill specification lives in `skills/analyzer.yaml` and defines three components:

1. **System prompt** — The analyzer's identity, role, and behavioral instructions. Defines the security analyst persona, the three-tier classification framework (expected/unspecified/forbidden), the requirement to evaluate each event against the behavior profile, and the structured output format for verdicts. This is the most important artifact in the entire system — the quality of Watchpost's intelligence depends entirely on the quality of this prompt.

2. **Tool definitions** — The set of tools the LLM can call during analysis, with parameter schemas and descriptions. These are registered as Anthropic tool definitions (or Ollama function calls).

3. **Output schema** — The JSON schema for the Verdict struct, enforced via Anthropic's `output_config.format` or Ollama's `format` parameter.

The skill specification is loaded at daemon startup and can be hot-reloaded via SIGHUP. This allows prompt iteration without rebuilding the binary — a critical capability since prompt quality determines detection quality. The skill file should be treated as a first-class security artifact, reviewed with the same rigor as detection rules.

A separate skill specification (`skills/gate-analyzer.yaml`) defines the pre-execution gate's analysis behavior, which differs from runtime analysis: it receives script *content* rather than kernel event traces, and its classification focuses on what the script *intends to do* rather than what it *already did*.

**Agentic design.** The analyzer operates as a tool-using agent. The LLM receives initial context (the correlated trace + behavior profile) and can call tools to gather additional information before rendering a verdict. This dramatically improves analysis quality for ambiguous cases — the LLM can follow its reasoning ("this process connected to an unusual IP; let me check if the package declares that as a registry") instead of being limited to whatever context was pre-assembled.

The tools available to the analyzer LLM:

- `read_project_file(path)` → file contents (package.json, Cargo.toml, install scripts, .npmrc). Sandboxed to the trigger's working directory and standard package manager cache paths.
- `get_process_tree(pid)` → full subtree of descendants with binary paths, arguments, and current state.
- `get_recent_events(pid, seconds)` → enriched events for a process group within the specified time window.
- `lookup_package(ecosystem, name, version)` → package metadata from the registry API (description, maintainers, download count, publish date, dependency list).
- `lookup_ip(ip)` → threat intelligence (AbuseIPDB/VirusTotal score, known associations, geolocation).

The typical analysis uses 2-5 tool calls, costing ~$0.01 total with Haiku and taking 1-3 seconds. The agent loop is bounded to a maximum of 8 tool calls per analysis to prevent runaway costs. If the LLM does not render a verdict within the tool call budget, the trace is logged with an `analysis_incomplete` tag and the last available reasoning is used for a best-effort verdict.

**Initial context.** The analyzer constructs the initial message from the skill's system prompt template, populated with:

1. The trigger context in natural language: "The user ran `npm install express` in the directory `/home/piotr/projects/myapp`."
2. The **action behavior profile** for this context: what is expected (silently allowed), what is unspecified (needs your analysis), what is forbidden (already blocked, included for context). This grounds the LLM's reasoning in concrete expectations.
3. The complete process ancestry chain, formatted as a tree.
4. A chronological list of all events in the correlated trace, each with timestamp, event type, and key arguments (file paths, network destinations, binary paths).
5. The correlation signals that linked these events (which lineage, temporal, and argument matches were found).
6. The heuristic score and which indicators contributed to it.
7. The task: investigate using available tools, evaluate each event against the behavior profile, classify (benign / suspicious / malicious), assign confidence (0.0-1.0), explain in one sentence for a desktop notification, and recommend an action (allow / block / notify).

**Verdict execution.** The final verdict is extracted using Anthropic's structured output (`output_config.format`) on the last message in the agent loop. The Verdict struct contains: `classification` (benign/suspicious/malicious), `confidence` (0.0-1.0), `recommended_action` (allow/block/notify), `explanation` (human-readable string), and `profile_violations` (list of specific behavior profile deviations found).

The verdict is then *executed* based on the `[enforcement]` configuration:
- **Autonomous mode** (default): If the LLM's confidence ≥ `autonomous_threshold` (default: 0.85), the recommended action is executed immediately — `block` kills the process, `allow` adds a temporary allowlist entry. The user is notified *after the fact* with the explanation and an "Undo" button. If confidence < `autonomous_threshold`, the recommended action is downgraded to `notify` and the user decides.
- **Advisory mode**: All actions are downgraded to `notify`. The LLM's verdict is shown in the notification but no enforcement occurs. The user can click "Block" to manually enforce.

If the Ollama backend is used, the prompt asks the LLM to respond in JSON format; malformed responses fall back to logging with an "analysis_failed" tag and a single retry. In this case, enforcement falls back to the heuristic score: score ≥ 0.7 → block (in autonomous mode), score ≥ 0.3 → notify.

**Model selection.** The LLM client supports two backends:

1. Anthropic API (remote, default): connects to `https://api.anthropic.com/v1/messages`. Uses Claude Haiku 4.5 (model ID: `claude-haiku-4-5-20251001`) for optimal cost and speed. Structured output is enforced via the `output_config.format` parameter with a JSON schema defining the Verdict response type — this guarantees schema-compliant responses without prompt-based JSON formatting or retry logic. The user must provide their own API key via the configuration file or `ANTHROPIC_API_KEY` environment variable.

2. Ollama (local, optional): connects to `http://127.0.0.1:11434` and uses the `/api/chat` endpoint. For offline or air-gapped environments. The recommended models for this task are:
   - Llama 3.1 8B (Q4_K_M quantization): good balance of speed and quality, runs on CPU in 2-4 seconds per analysis
   - Mistral 7B (Q4_K_M): slightly faster, sometimes less nuanced reasoning
   - Qwen 2.5 7B: strong at structured JSON output
   - If the user has a GPU: Llama 3.1 70B (Q4_K_M) for significantly better reasoning, ~1 second per analysis on a 24GB GPU
   Ollama supports JSON mode via the `format` parameter (set to `"json"` or a full JSON schema for strict enforcement).

**Rate limiting.** The analyzer is rate-limited to a configurable maximum number of analyses per minute (default: 10). During a large `npm install` or `cargo build`, dozens of ambiguous traces might be generated. Exceeding the rate limit causes traces to be queued (bounded queue, default 50) with oldest traces being dropped if the queue is full. Dropped traces are logged with an "analysis_skipped_rate_limit" tag.

**Context window management.** A single correlated trace might contain 5-50 events. The prompt must fit within the model's context window with room for the response. Claude Haiku 4.5 supports a 200K context window, which is more than sufficient for any single trace. For the Ollama backend with smaller models (8K context), the analyzer truncates the event list to the 20 most suspicious events (ranked by their individual indicator scores) if the full trace would exceed 4K tokens. The trigger context, ancestry, and task description are never truncated.

### 4.6 Stage 4c: Pre-Execution Script Gate

The pre-execution gate is Watchpost's proactive defense layer. Instead of waiting for a malicious install script to execute and then detecting the damage, the gate intercepts script execution *before* it happens and analyzes the script content.

**Mechanism.** A dedicated TracingPolicy (`install-script-gate.yaml`) uses Tetragon's `bprm_check_security` LSM hook with the `Override` action to intercept execution of scripts spawned by package managers — including postinstall hooks from transitive dependencies, not just direct installs. This is critical because real-world supply chain attacks (e.g., the 2026 axios compromise) inject malicious code through transitive deps like `plain-crypto-js` that the developer never explicitly chose. When Tetragon detects that a child process of npm/pip/cargo is about to execute a script (shell script, Python script, or binary from a temporary/cache directory), the `Override` action pauses execution and emits an event to Watchpost.

**Analysis flow.** When the gate receives an intercepted execution event:

1. It checks the gate allowlist: if this package + script hash combination has been seen and approved before, execution is released immediately with no LLM call.
2. It reads the script content from the binary path (for shell/Python scripts) or examines the binary metadata (for compiled executables from cache directories).
3. For readable scripts: it sends the script content to the LLM with the package context and the action behavior profile ("This is the `postinstall` script for npm package `foo@1.2.3`. The expected behavior profile allows: writing to `node_modules/`, running `node-gyp`, invoking `make`/`cc` for native compilation, network access to registry.npmjs.org. Analyze the script: does it stay within the expected profile, or does it perform actions outside it?").
4. For compiled binaries from temporary/cache paths: it flags the binary as outside the expected profile (no legitimate package install should execute pre-compiled binaries from temp directories) and blocks by default.
5. The LLM returns a verdict with confidence. The gate acts autonomously based on the `[enforcement]` mode:
   - **Autonomous** (default): confidence ≥ 0.85 benign → allow and add to gate allowlist. Confidence ≥ 0.85 malicious → block (kill process) and notify user. Below threshold → block and notify (fail-closed for the gate, since pre-execution is the last chance to prevent damage).
   - **Advisory**: analyze but always allow. Notify the user of the verdict. The user can retroactively block the package.

**Latency budget.** The ~200ms for a Haiku API call is imperceptible in the context of `npm install` (which takes seconds to minutes). For the Ollama backend, 2-4 seconds per analysis is still acceptable — the user is waiting for the install to complete anyway. If the LLM call fails or times out (default: 5 seconds), the gate falls back to heuristic analysis: scripts from known-good packages (high download count, provenance attestation) are allowed; scripts from unknown packages with suspicious content patterns (base64, curl|sh, encoded strings) are blocked.

**Scope.** The gate is intentionally narrow: it only intercepts scripts spawned by package manager install hooks, not all script execution on the system. This limits the blast radius of false positives (a mis-classification only delays a package install, not the user's shell commands) and keeps the LLM call volume manageable.

**User override.** If Watchpost blocks a script and the user disagrees, they can unblock it via the desktop notification ("Undo" button) or CLI (`watchpost gate allow <package> <hash>`). The package + script hash is then added to the gate allowlist. Conversely, if a script was auto-allowed and the user later discovers it was malicious, `watchpost gate block <package>` revokes the allowlist entry and adds the package to a permanent block list.

### 4.7 Stage 5: Policy Management

The policy manager handles the lifecycle of Tetragon TracingPolicy YAML files. It is the mechanism by which Watchpost adapts its monitoring over time.

**Base policies** are shipped with Watchpost in a `policies/` directory. These are version-controlled, never modified by the agent, and always present. They cover the fundamental monitoring: process execution, sensitive file access, network connections, privilege escalation, and immutability enforcement. Watchpost copies these to Tetragon's policy directory (`/etc/tetragon/tetragon.tp.d/`) on startup and reconciles them on every restart.

**Dynamic allowlists** are the learning mechanism. When the LLM analyzer (or the rule engine) classifies a trace as benign with high confidence (> 0.9) multiple times (configurable threshold, default 5 occurrences), the policy manager records the pattern as a known-good baseline. For example, after seeing `cargo build` spawn `cc`, `ld`, `ar`, and `as` five times without incident, those child processes are added to the cargo build allowlist. Future instances of the same pattern skip scoring entirely (score = 0.0), reducing noise and LLM calls.

Allowlists are stored in a SQLite table with fields: parent binary, child binary, action context type, file path pattern (if applicable), network destination (if applicable), first seen timestamp, last seen timestamp, and occurrence count. Allowlists can be viewed, edited, and deleted through the CLI (`watchpost allowlist list`, `watchpost allowlist remove <id>`).

**Reactive policies** are new TracingPolicies generated by the analyzer or rule engine in response to a detected threat. For example, if the analyzer detects a pattern of npm postinstall scripts making suspicious network connections, it generates a policy that blocks all network access from npm child processes except to registry.npmjs.org. In autonomous enforcement mode, reactive policies with high-confidence backing (generated from verdicts with confidence ≥ `autonomous_threshold`) are activated immediately via gRPC and the user is notified ("New enforcement policy activated: `block-npm-non-registry-network`. Reason: 3 npm packages attempted connections to non-registry IPs in the last hour. Undo?"). In advisory mode, policies are written to a staging directory and require explicit user approval (`watchpost policy approve <name>`) before activation. All reactive policies — whether auto-activated or staged — can be revoked by the user at any time (`watchpost policy revoke <name>`).

**Policy reconciliation** runs on startup and whenever a policy is approved or revoked. The reconciler compares the desired state (base policies + approved staged policies) against the currently-loaded Tetragon policies (queried via gRPC), and uses Tetragon's `AddTracingPolicy` and `DeleteTracingPolicy` gRPC RPCs to add, remove, or replace policies at runtime without restarting Tetragon. On initial startup, the reconciler also writes policy YAML files to Tetragon's policy directory (`/etc/tetragon/tetragon.tp.d/`) so they persist across Tetragon restarts.

### 4.8 Stage 6: Notification and Logging

**Notification philosophy.** Watchpost notifications are rare and informational — they tell the developer what was stopped, not ask what to do. The target is zero notifications per day during normal development, and at most one when installing a novel package with genuinely unusual behavior.

**Two notification types only:**

**Blocked** — Shown when Watchpost killed a process (runtime enforcement or pre-execution gate):

```
🔒 Blocked: npm postinstall for evil-pkg@0.1.0
   Attempted to read ~/.ssh/id_rsa
   [Undo]  [Details]
```

"Undo" adds the pattern to the permanent allowlist so it won't be blocked next time, and records the override as a false positive for weight adjustment. The killed process is not resurrected — the developer re-runs the command (e.g., `npm install` again). "Details" opens the TUI dashboard or outputs the full correlated trace.

**Threat Detected** — Shown for unambiguously malicious behavior caught by deterministic rules (reverse shell, cryptominer, immutability violation):

```
🚨 Threat: Reverse shell detected
   npm → node → sh → nc 185.x.x.x:4444
   Process killed.  [Details]
```

No "Undo" — these are always-malicious patterns. Only "Details".

**What is NOT a notification:** Benign verdicts (silent, logged only). Low-confidence allows (silent, logged for CLI review). Allowlist updates (automatic, silent). Threshold adjustments (automatic, silent). Profile extensions from user overrides (automatic, silent).

**Silent feedback loop.** Every "Undo" click feeds back into the scoring model invisibly:
- The blocked pattern is added to the permanent allowlist and the relevant behavior profile's expected set.
- Per-indicator weights adjust: indicators that trigger frequently-overridden blocks have their weights reduced over a 30-day rolling window. Indicators that are never overridden have their weights increased.
- If the user clicks "Undo" more than 3 times in a week, the internal autonomous threshold auto-raises (the system becomes more conservative about blocking). If no overrides occur for 30 days, the threshold auto-lowers. This is never surfaced as a notification.
- All decisions and overrides are stored in the event database. Weight adjustments are computed on daemon startup and after every 50 overrides, written to `weight_overrides.toml`.

**Event log** is a SQLite database at `/var/lib/watchpost/events.db`. Every enriched event, correlated trace, and verdict is stored with full detail. The schema supports querying by time range, severity, classification, process binary, and trigger context. The CLI provides query access (`watchpost events list --since 1h --severity high`). The database has automatic rotation (default: keep 30 days, configurable).

**Webhook (optional)** allows forwarding verdicts to an external service (Slack webhook, MQTT broker, or custom HTTP endpoint). The webhook payload is a JSON object containing the verdict, the trigger context, and a summary of the correlated events. This is an optional feature, disabled by default.

---

## 5. Workspace Structure

Watchpost is organized as a Cargo workspace with seven crates. Each crate has a single responsibility and communicates with other crates through well-defined async channel boundaries.

### 5.1 `watchpost-types`

Shared type definitions used by all other crates. Contains: event enums (TetragonEvent, EnrichedEvent), action context types (PackageInstall, Build, FlatpakApp, ToolboxSession, ShellCommand, etc.), behavior profile types (ExpectedBehavior, NetworkExpectation, FileAccessExpectation, ChildProcessExpectation), verdict types (Verdict with Classification, Confidence, RecommendedAction, ProfileViolations), enforcement mode types (Autonomous, Advisory), correlated trace types, correlation signal types, and TracingPolicy data model types. This crate has minimal dependencies (only `serde`, `uuid`, and `chrono`) and no async runtime.

### 5.2 `watchpost-collector`

Tetragon gRPC client and context enrichment. Depends on `tonic` (gRPC), `procfs` (reading /proc), and `dashmap` (concurrent caching). Contains: the gRPC client setup and event stream consumer, the process ancestry builder (walks /proc/PID/status), the action context inferrer (matches known tool binaries in ancestry chains, including toolbox/distrobox container detection via cgroup patterns), the package manifest reader and LRU cache, the package provenance enricher (async registry lookups for age, download count, audit status, Sigstore attestation, and typosquatting distance), the Flatpak metadata reader, and the toolbox/distrobox metadata reader. Sends enriched events to the engine via tokio mpsc channel.

### 5.3 `watchpost-engine`

Correlation engine and heuristic scoring. Contains: the in-memory process tree (concurrent tree with RwLock), the multi-horizon time-window buffers (immediate 5s, session-scoped, persistent 24h backed by SQLite), the active trigger registry, the three-signal correlator (lineage, temporal proximity, argument matching), the heuristic scoring function with package provenance indicators, and the user feedback weight adjustment system (loads weight overrides from `weight_overrides.toml`). Receives enriched events from the collector. Sends correlated traces to either the rule engine (fast path) or the analyzer (slow path) based on score thresholds.

### 5.4 `watchpost-rules`

Deterministic rule engine. Contains: the YAML rule loader, the rule condition evaluator (AND/OR tree matching), the threat intelligence client (HTTP client for AbuseIPDB/VirusTotal with local caching), and the verdict producer. Receives high-score correlated traces from the engine. Produces verdicts and sends them to the policy manager and notifier.

### 5.5 `watchpost-analyzer`

LLM-powered agentic semantic analysis. Contains: the skill loader (reads `skills/analyzer.yaml` and `skills/gate-analyzer.yaml` at startup, supports hot-reload via SIGHUP), the context builder (formats correlated traces into structured messages using the skill's system prompt template), the LLM client abstraction (Anthropic remote backend as default, Ollama local backend as optional alternative), the tool executor (implements the five analysis tools: `read_project_file`, `get_process_tree`, `get_recent_events`, `lookup_package`, `lookup_ip`), the agent loop controller (bounds tool calls to 8 per analysis), the structured output response parser, the rate limiter, and the retry logic. Also contains the pre-execution script gate logic (intercepts paused script executions, reads script content, runs gate-specific LLM analysis, and decides allow/block). Receives ambiguous correlated traces from the engine and intercepted execution events from the gate policy. Produces verdicts and sends them to the policy manager and notifier.

### 5.6 `watchpost-policy`

TracingPolicy lifecycle management. Contains: the base policy loader (reads YAML files from the shipped policies directory), the dynamic allowlist store (SQLite table with CRUD operations), the staged policy manager (staging directory, approval workflow), the TracingPolicy YAML generator (constructs valid Tetragon policy YAML from structured data), and the reconciler (uses Tetragon's gRPC `AddTracingPolicy`/`DeleteTracingPolicy` RPCs to sync desired state at runtime, and writes YAML files to the policy directory for persistence across Tetragon restarts). Receives verdicts from the rule engine and analyzer. Writes to Tetragon's policy directory and the allowlist database.

### 5.7 `watchpost-notify`

Desktop notification and event logging. Contains: the D-Bus notification sender (using zbus), the notification action handler (receives user responses to action buttons), the user feedback collector (records Undo overrides and feeds them back to the engine's weight adjustment system), the SQLite event log writer, and the optional webhook forwarder. Receives verdicts from the rule engine and analyzer. Writes to the SQLite database and sends desktop notifications.

### 5.8 `watchpost` (binary crate)

The CLI and daemon entrypoint. Contains: the clap CLI definition with subcommands (`daemon`, `events`, `policy`, `allowlist`, `tui`), the daemon startup logic (initializes all crates, wires channels together, starts the tokio runtime), the systemd notify integration (sd_notify for Type=notify service), the configuration file loader (TOML format), and the signal handler (SIGHUP for config reload, SIGTERM for graceful shutdown).

---

## 6. Shipped TracingPolicies

Watchpost ships with a set of TracingPolicy YAML files organized into three categories. These are the Tetragon policies that get installed to `/etc/tetragon/tetragon.tp.d/` — they tell Tetragon *what* to monitor at the kernel level.

### 6.1 Base Policies (always active)

**immutability.yaml**: Monitors write attempts to `/usr/`, `/boot/`, and `/lib/modules/` from any process that is not `rpm-ostree`, `ostree`, or `systemd-sysext`. Uses the `security_file_permission` LSM hook with arg0 type `file` for path matching (Prefix selector on `/usr/`, `/boot/`, `/lib/modules/`) and arg1 type `int` filtered for `MAY_WRITE` (value `2`), combined with `matchBinaries` using `NotIn` operator for the exception list. Action: Post (log the event, let Watchpost decide enforcement).

**sensitive-files.yaml**: Monitors read and write access to `/etc/shadow`, `/etc/passwd`, `/etc/sudoers`, `/root/.ssh/`, and `$HOME/.ssh/`, `$HOME/.gnupg/`, `$HOME/.config/` from any process. Uses the `security_file_permission` LSM hook with arg0 type `file` and `Prefix` selectors on the sensitive paths, filtering on both `MAY_READ` (value `4`) and `MAY_WRITE` (value `2`) access types. Since this generates high volume (many legitimate reads of `/etc/passwd`), the Tetragon policy uses `matchBinaries` with `NotIn` to exclude known-good binaries (systemd, sshd, gnome-keyring, passwd, sudo) from generating events.

**priv-escalation.yaml**: Monitors `commit_creds` (credential changes, a kernel function — `syscall: false`) and `sys_setuid` (UID changes, a syscall — `syscall: true`; Tetragon auto-translates the portable name to the architecture-specific symbol, e.g. `__x64_sys_setuid` on x86_64). No binary filtering — all processes are monitored. Uses kprobes with `Post` action.

**tmp-execution.yaml**: Monitors `execve` for binaries with paths starting with `/tmp/`, `/dev/shm/`, or `/var/tmp/`. Uses the `sched_process_exec` tracepoint or LSM `bprm_check_security` hook (depending on Tetragon version and kernel support). For enforcement mode, the action can be changed to `Sigkill`.

**install-script-gate.yaml**: Intercepts execution of scripts and binaries spawned by package manager install hooks. Uses the `bprm_check_security` LSM hook with `Override` action and `matchParentBinaries` filtering for npm/node/pip/cargo parent processes. When a child process of a package manager attempts to execute a script from a package cache, temporary directory, or `node_modules/.hooks/` path, execution is paused and an event is sent to Watchpost's pre-execution gate for analysis. This is the only base policy that uses enforcement by default (`Override` action) because the user explicitly opted into analysis-before-execution via the `[gate]` configuration.

### 6.2 Developer Toolchain Policies

**npm-monitoring.yaml**: Monitors network events (`tcp_connect` kprobe) and file access events (`security_file_permission` LSM hook) for processes whose binary is `/usr/bin/node` or whose ancestor binary matches npm/npx/yarn/pnpm. Uses `matchBinaries` with `In` operator. This is the primary supply chain attack detection policy.

**cargo-monitoring.yaml**: Same structure as npm-monitoring but for cargo and its child processes (rustc, cc, ld, ar). Initially in observation-only mode. The dynamic allowlist will learn the normal cargo build process tree and reduce noise over time.

**pip-monitoring.yaml**: Monitors pip, pip3, pipx, and uv child process network and file activity.

**flatpak-escape.yaml**: Monitors file access from Flatpak-sandboxed processes that access host paths outside `/app/`, `/usr/`, and declared portal paths. Uses a two-layer detection approach: (1) In-kernel filtering via `matchNamespaceChanges` to detect processes that have entered different mount/PID namespaces (as Flatpak apps do), combined with `matchBinaries` for Flatpak runtime binaries (`bwrap`, `/app/bin/*`). (2) Userspace enrichment in Watchpost's collector, which reads the cgroup path from `/proc/PID/cgroup` to extract the Flatpak app ID and compares actual file access against declared permissions from the app's metadata. Tetragon does not support cgroup path-based selectors directly, so the fine-grained Flatpak identification happens in Watchpost's userspace enrichment layer.

### 6.3 Network Policies

**reverse-shell.yaml**: Monitors the combination of `tcp_connect` (or `sys_connect`) followed by `dup2`/`dup3` redirecting file descriptors 0, 1, or 2 to the socket. Uses separate kprobes for `tcp_connect` and `dup2`/`dup3`, each filtered to relevant argument patterns. Cross-kprobe correlation (detecting that both events occurred in the same process within a time window) is performed by Watchpost's correlation engine, not by Tetragon — Tetragon fires each kprobe independently and does not support cross-hook event correlation within a single TracingPolicy.

**dns-exfil.yaml**: Monitors DNS query syscalls (`sys_sendto` on UDP port 53) for high-entropy query names. The entropy calculation happens in Watchpost (not in the Tetragon eBPF program), so this policy simply logs all DNS queries from dev tool child processes.

**crypto-miner.yaml**: Monitors `tcp_connect` to destination ports 3333, 4444, 14444, and 45700. Uses `DPort` operator in the Tetragon kprobe selector. Action: `Sigkill` (enforcement by default — there is no legitimate reason for a desktop process to connect to Stratum mining ports).

---

## 7. Configuration

Watchpost is configured through a single TOML file at `/etc/watchpost/config.toml`, generated by `watchpost init`. The minimum viable configuration is a single line:

```toml
[daemon]
api_key = "sk-ant-..."
```

Everything else has smart defaults. Most users never edit this file.

### Essential Settings

**[daemon]**: Anthropic API key (required; also accepted via `ANTHROPIC_API_KEY` env var), log level (default: warn), data directory (default: /var/lib/watchpost).

**[enforcement]**: Enforcement mode (default: autonomous; option: advisory for notification-only). Most users never change this.

**[notify]**: Desktop notifications enabled (default: true), webhook URL (optional).

### Advanced Settings

These settings exist for power users and edge cases. They are documented here for completeness but the defaults work well for the vast majority of environments.

**[advanced.tetragon]**: gRPC endpoint (default: `unix:///var/run/tetragon/tetragon.sock`; alternatively `tcp://localhost:54321`), policy directory path (default: /etc/tetragon/tetragon.tp.d/).

**[advanced.collector]**: Maximum process ancestry depth (default: 16), package manifest cache size (default: 256), event channel buffer size (default: 4096).

**[advanced.engine]**: Immediate correlation window in milliseconds (default: 5000), persistent correlation window in hours (default: 24), fast path score threshold (default: 0.7), LLM analysis score threshold (default: 0.3), weight overrides file path (default: /var/lib/watchpost/weight_overrides.toml).

**[advanced.analyzer]**: LLM backend (default: anthropic), model name (default: `claude-haiku-4-5-20251001`), Ollama endpoint URL and model (optional, for offline use), max analyses per minute (default: 10), analysis queue size (default: 50), max tool calls per analysis (default: 8).

**[advanced.gate]**: Pre-execution script gate enabled (default: true), gate mode (default: enforce; option: advisory), script analysis timeout (default: 5000ms), gate allowlist path (default: /var/lib/watchpost/gate_allowlist.db).

**[advanced.profiles]**: Path to user-defined behavior profile YAML files (default: /etc/watchpost/profiles.d/). These extend or override the shipped profiles.

**[advanced.rules]**: Path to additional user-defined rule YAML files (default: /etc/watchpost/rules.d/).

**[advanced.policy]**: Baseline learning threshold (default: 5 benign occurrences before allowlisting), reactive policy auto-activation (default: true in autonomous mode).

**[advanced.enforcement]**: Per-toolchain mode overrides (e.g., `[advanced.enforcement.cargo] mode = "advisory"`).

---

## 8. CLI Interface

The `watchpost` binary provides the following subcommands. Most users only ever run `watchpost init`.

### Setup

**`watchpost init`**: One-command setup. Prompts for Anthropic API key (or reads `ANTHROPIC_API_KEY` from environment), scans `$PATH` for installed package managers (npm, yarn, pnpm, cargo, pip, pip3, uv, flatpak), detects toolbox/distrobox container environment, writes minimal config to `/etc/watchpost/config.toml`, copies TracingPolicies to Tetragon's policy directory, enables and starts the systemd service, and runs a health check (Tetragon gRPC connection, policy verification, API key validation). Supports `--api-key` flag to skip the interactive prompt.

```
$ watchpost init
  Anthropic API key: sk-ant-...
  ✓ Detected toolchains: npm, cargo, pip
  ✓ Config written to /etc/watchpost/config.toml
  ✓ Tetragon policies installed (5 base + 3 toolchain)
  ✓ Systemd service enabled and started
  ✓ Watchpost is now protecting your system
```

**`watchpost status`**: Show current daemon status, loaded policies, and recent activity summary (events in last hour, blocks in last 24h, active allowlist size).

### Daemon

**`watchpost daemon`**: Start the daemon in the foreground (for systemd). Reads configuration, initializes all crates, wires channels, and runs the event loop. Supports `--config` flag for non-default config path.

### Event Log

**`watchpost events list`**: Query the event log. Supports `--since`, `--until`, `--severity`, `--classification`, `--binary`, and `--context` filters. Output formats: table (default), JSON, and CSV.

**`watchpost events show <event-id>`**: Display full detail of a single event, including the entire correlated trace, all correlation signals, the heuristic score breakdown, and the verdict (if analyzed).

### Policy Management

**`watchpost policy list`**: List all TracingPolicies (base, reactive, approved). Shows status, source (shipped/generated/user), and last modified time.

**`watchpost policy approve <name>`**: Approve a staged policy, moving it to the active set and triggering a Tetragon reconciliation.

**`watchpost policy revoke <name>`**: Remove a reactive policy from the active set and trigger reconciliation.

**`watchpost policy show <name>`**: Display the full YAML content of a policy.

### Allowlist Management

**`watchpost allowlist list`**: Display the dynamic allowlist with columns: ID, parent binary, child binary, context, first seen, last seen, occurrence count.

**`watchpost allowlist remove <id>`**: Remove an allowlist entry, causing future instances of that pattern to be scored normally.

**`watchpost allowlist reset`**: Clear all dynamic allowlist entries (useful for re-learning after a configuration change).

### Dashboard

**`watchpost tui`** (phase 3): Launch the terminal UI dashboard. Connects to the running daemon via a local Unix socket and displays live event stream, process tree, policy status, and analysis queue.

---

## 9. Systemd Integration

Watchpost runs as a Type=notify systemd service that depends on Tetragon. The service file specifies:

- `After=tetragon.service` and `Requires=tetragon.service`: ensures Tetragon is running before Watchpost starts.
- `Type=notify`: Watchpost calls `sd_notify(READY=1)` after successfully connecting to Tetragon's gRPC socket and loading all policies. This prevents systemd from considering the service started before it is actually operational.
- `ExecReload=/bin/kill -HUP $MAINPID`: SIGHUP triggers a Watchpost configuration reload (re-read config.toml, re-load rule YAML files, re-load analyzer skill specifications from `skills/`) without restarting the daemon. Policy reconciliation with Tetragon is performed via gRPC API calls (`AddTracingPolicy`/`DeleteTracingPolicy`), not by signaling the Tetragon process.
- Security hardening: `ProtectSystem=strict` (read-only filesystem except declared paths), `ReadWritePaths=/var/lib/watchpost /etc/tetragon/tetragon.tp.d` (the event database and policy directory), `ProtectHome=read-only` (can read home directory for package manifests but not write), `NoNewPrivileges=true`, `CapabilityBoundingSet=` (no capabilities needed — Watchpost is entirely userspace, Tetragon handles the privileged eBPF operations).

---

## 10. Development Phases

### Phase 1 (MVP): Core Event Pipeline + Remote LLM Analysis

Deliverables:
- `watchpost-types` crate with all shared types
- `watchpost-collector` crate: Tetragon gRPC client, process ancestry builder, basic action context inference (npm, cargo, pip), toolbox/distrobox container detection
- `watchpost-engine` crate: process tree, multi-horizon correlation (immediate + session windows), heuristic scoring with base indicators
- `watchpost-rules` crate: rule loader, condition evaluator, 10 shipped rules
- `watchpost-analyzer` crate: skill loader, context builder, tool executor (`read_project_file`, `get_process_tree`, `get_recent_events`), Anthropic API client (Claude Haiku 4.5 with structured output), agent loop controller, rate limiter
- Analyzer skill specifications: `skills/analyzer.yaml` (runtime trace analysis) and `skills/gate-analyzer.yaml` (pre-execution script analysis)
- `watchpost-notify` crate: D-Bus desktop notifications, SQLite event log
- `watchpost` binary crate: `init`, `daemon`, `status`, and `events` subcommands
- 4 base TracingPolicies (immutability, sensitive files, priv escalation, tmp execution)
- Curated behavior profiles for npm, cargo, pip ecosystems (`profiles/` directory)
- Systemd service file
- Configuration file with defaults

What is explicitly NOT in phase 1: Ollama local LLM backend, policy generation, dynamic allowlists, pre-execution gate, package provenance enrichment, user feedback loop, TUI dashboard, threat intelligence lookup, webhook forwarding, Flatpak-specific monitoring.

The goal of phase 1 is to prove the full detection pipeline works end-to-end: Tetragon events flow through the collector, get enriched with context (including toolbox awareness), get correlated across multiple time horizons and scored, match deterministic rules (fast path) or get investigated by the agentic Claude Haiku 4.5 analyzer (slow path), and produce desktop notifications. A real supply chain attack (like event-stream) should trigger a critical alert. A normal `cargo build` should produce no alerts.

### Phase 2: Proactive Defense + Policy Management

Deliverables:
- Pre-execution script gate: `install-script-gate.yaml` TracingPolicy, `bprm_check_security` with `Override` action, script content analysis via LLM, D-Bus allow/block UX
- `watchpost-policy` crate: allowlist manager, staged policy manager, TracingPolicy YAML generator, gRPC-based reconciler
- Package provenance enrichment in the collector (registry lookups, audit integration, typosquatting detection, Sigstore attestation checking)
- User feedback loop: notification decisions feed back into scoring weights, accelerated allowlisting
- Persistent correlation window (24h, SQLite-backed) for delayed-execution attack detection
- Ollama local LLM backend (optional alternative to Anthropic for offline/air-gapped use)
- Analyzer tools: `lookup_package`, `lookup_ip`
- `policy` and `allowlist` CLI subcommands
- Developer toolchain TracingPolicies (npm, cargo, pip monitoring)
- Threat intelligence integration (AbuseIPDB cache)
- Dynamic baseline learning

### Phase 3: Advanced Features

Deliverables:
- TUI dashboard (`watchpost tui`) using ratatui
- Flatpak sandbox escape detection (flatpak-escape.yaml + namespace-change-aware context builder with userspace cgroup path resolution)
- Network policies (reverse shell, DNS exfiltration, cryptominer)
- Webhook forwarding
- Policy templates (user-shareable YAML bundles for specific environments)

---

## 11. Key Technical Decisions and Rationale

**Why Tetragon instead of custom eBPF (like AgentSight)?**
AgentSight wrote custom C eBPF programs because they needed TLS interception (uprobes on SSL_read/SSL_write), which Tetragon doesn't support. Watchpost doesn't need TLS interception — we reconstruct intent from process context instead. Using Tetragon means zero eBPF C code to maintain, automatic CO-RE/BTF handling, declarative YAML policy management, and the benefit of Cilium's kernel-developer expertise for correct and safe eBPF programs.

**Why the two-tier classification instead of LLM-only?**
An LLM call takes 1-5 seconds (local) or 200-500ms (remote). During a `cargo build`, hundreds of process events fire per second. Sending all of them to an LLM would saturate the model and create a multi-minute backlog. The heuristic scoring + deterministic rules handle 95%+ of events in microseconds. The LLM handles only the genuinely ambiguous 5%. This also means Watchpost works (with reduced intelligence) even if no LLM is configured at all.

**Why SQLite instead of a time-series database?**
For a single desktop, SQLite is the right choice. It is zero-configuration, file-based, handles concurrent reads with WAL mode, and stores months of events in a few hundred megabytes. A TSDB (InfluxDB, Prometheus) adds operational complexity that is not justified for a single-host agent.

**Why Anthropic API as the default LLM backend?**
The Anthropic API (Claude Haiku 4.5) provides higher analysis quality than local 7B/8B models, guaranteed structured JSON output via the `output_config.format` parameter, and requires zero local infrastructure. At ~10 analyses/minute with small payloads, the daily cost is negligible for a single desktop. The tradeoff is an external dependency and sending security telemetry over the network — acceptable for most users, but an Ollama local backend is available as an alternative for offline, air-gapped, or privacy-sensitive environments. Ollama has wide Linux desktop adoption, supports the relevant model families (Llama, Mistral, Qwen), runs on CPU-only machines, and has a simple HTTP API.

**Why `security_file_permission` LSM hook instead of `fd_install` kprobe for file monitoring?**
The `fd_install` kprobe fires when a file descriptor is installed into the process FD table — it detects file *open* operations, not actual reads and writes. The `FollowFD`/`UnfollowFD`/`CopyFD` actions that correlated FD numbers back to file paths in subsequent syscalls are deprecated as of Tetragon v1.4.0 and scheduled for removal in v1.5. The `security_file_permission` LSM hook fires on actual read/write operations, directly provides the access type (MAY_READ vs MAY_WRITE), operates on kernel-resident state (avoiding TOCTOU race conditions), and is the officially documented Tetragon approach for file access monitoring.

**Why process ancestry instead of TLS interception for "intent"?**
On a desktop, the user's intent is expressed by the commands they run, not by LLM API calls. When a developer runs `npm install express`, the intent is clear from the process tree — npm was launched from a shell in a terminal. TLS interception would let us see *what* npm downloads, but the package name is already available from `package.json` in the working directory. The tradeoff: we lose visibility into encrypted payload content (e.g., we can't see the actual malicious code being downloaded), but we gain simplicity and avoid the complexity of maintaining SSL library uprobes across OpenSSL, BoringSSL, GnuTLS, and NSS versions.

**Why a pre-execution gate instead of detection-only?**
The vast majority of supply chain attacks via npm/pip are plaintext install scripts (postinstall.sh, setup.py) that download and execute a payload. These scripts exist on disk before they run. An LLM can read a 50-line postinstall script in ~200ms and determine if it contains `curl | sh`, base64-encoded payloads, or access to `~/.ssh/`. The latency is invisible during package installs that take seconds to minutes. Detection-only means the damage (exfiltrated keys, planted backdoor) has already happened by the time the alert fires. The gate prevents the damage. The scope is intentionally narrow (package install hooks only) to minimize false positive impact on the user's workflow — a mis-classification delays an install, not a shell command.

**Why an agentic LLM rather than single-shot classification?**
A single-shot prompt forces you to pre-assemble all context before calling the LLM. This means either sending too much context (expensive, noisy) or too little (the LLM can't reason about what it can't see). An agentic approach lets the LLM request exactly the information it needs: "This process connected to 185.x.x.x — let me check if the package.json declares that as a registry." The cost overhead is small (~2-5 tool calls at ~$0.002 each with Haiku) and the analysis quality improvement is substantial for the ambiguous cases that reach the LLM in the first place. The 8-call budget prevents runaway costs.

**Why multi-horizon correlation instead of a single time window?**
A fixed 30-second window is a structural weakness. Fast attacks (postinstall reverse shells) happen in 1-5 seconds and benefit from tight correlation. But a large `npm install` can take 10 minutes, and a staged attack might plant a cron job during install that fires hours later. The session window (tied to the trigger process lifetime) naturally handles variable-duration operations. The persistent window (24h, SQLite-backed) catches delayed payloads. The immediate window provides high-confidence correlation for fast attacks. Three horizons with different weights capture the full spectrum of attack timescales.

**Why silent user feedback instead of explicit tuning?**
Static indicator weights are a compromise between different development environments. Rather than requiring manual weight tuning or showing "threshold adjusted" notifications, Watchpost silently tracks which blocks get overridden ("Undo") and adjusts weights over a 30-day rolling window. The developer never sees this learning — they just notice that false positives stop recurring. The statistical sample from a single desktop is too small for ML, but large enough for simple weight adjustment.

**Why the invisible guardian model?**
Security tools that require developer attention get ignored. Alert fatigue, reflexive "Allow" clicking, and notification blindness render human-in-the-loop security worse than useless — it provides false confidence. Watchpost operates as an invisible guardian: it makes autonomous decisions grounded in curated behavior profiles and LLM reasoning, and only surfaces to the developer when something genuinely dangerous was blocked. The risk of false positives is mitigated by three mechanisms: (1) comprehensive shipped profiles that cover 95% of workflows from day one, (2) "Undo" buttons on every block notification for immediate correction, and (3) a silent self-adjusting feedback loop that makes the system more conservative if the user overrides frequently. The pre-execution gate is fail-closed (block on uncertainty, since the script hasn't run yet and there's no state to corrupt), while runtime enforcement blocks only high-confidence threats (SIGKILL) and silently allows low-confidence ambiguous traces.

**Why ship curated profiles instead of learning from scratch?**
A learning-from-scratch model means the first week of use is either unprotected (advisory mode) or riddled with false positives (aggressive blocking of unknown patterns). Neither is acceptable. By researching and curating known-good patterns for the top package ecosystems, Watchpost works correctly from first install. The dynamic learning system refines these profiles over time, but it starts from a strong baseline, not a blank slate. This is the same approach antivirus vendors use with signature databases — ship comprehensive defaults, update incrementally.

---

## 12. Open Questions for Implementation

These are decisions that should be resolved during implementation, not in this design document:

1. **Tetragon gRPC proto version pinning**: Should we vendor the Tetragon proto files or fetch them from the Tetragon repository at build time? Vendoring provides stability; fetching provides compatibility. Recommendation: vendor a specific Tetragon release version and document which version is supported.

2. **Process tree concurrency model**: The process tree is read by the correlation engine and written by the collector, both running as separate async tasks. Should it use a `RwLock<BTreeMap>` or a lock-free structure like `dashmap`? The read-to-write ratio is high (many correlations per process creation), so RwLock may be appropriate with read-biased fairness.

3. **Analyzer skill development**: The skill specifications (`skills/analyzer.yaml` and `skills/gate-analyzer.yaml`) are the highest-impact artifacts in the entire system — detection quality depends entirely on prompt quality. These must be developed iteratively against real attack traces (event-stream, ua-parser-js, axios 2026) and real benign traces (large cargo builds, native module compilation, toolbox activity). Consider building a test harness that replays recorded traces through the analyzer and compares verdicts against expected classifications. The skill files are hot-reloadable via SIGHUP specifically to support rapid prompt iteration in production.

4. **Event channel backpressure**: If the engine falls behind the collector (e.g., during a build spike), the bounded channel will apply backpressure. Should the collector drop events, or should it buffer to disk? For security, dropping events is dangerous. Recommendation: use a large channel buffer (4096+) and log a warning if backpressure is detected. If sustained backpressure occurs, the Tetragon TracingPolicies may need tighter selectors.

5. **Multi-user support**: The current design assumes a single user. If the system has multiple interactive users, should Watchpost run per-user (as a user service) or system-wide? Recommendation: system-wide for phase 1, with user-specific allowlists as a phase 3 feature.

6. **Tetragon version compatibility**: Tetragon's gRPC API and TracingPolicy schema evolve across versions. Watchpost should document the minimum supported Tetragon version and test against it in CI.

7. **Fedora Kinoite packaging**: Should Watchpost be distributed as an RPM (installed via rpm-ostree overlay) or as a standalone binary in /usr/local/bin? The rpm-ostree overlay approach integrates better with the immutable OS model but requires maintaining an RPM spec. A Copr repository would be the standard Fedora community distribution channel.
