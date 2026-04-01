# Watchpost Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a Rust daemon that consumes Tetragon eBPF events, enriches them with desktop context, classifies threats via deterministic rules and agentic LLM analysis, and delivers security verdicts through desktop notifications.

**Architecture:** A Cargo workspace of 7 crates connected by tokio mpsc channels. The collector ingests Tetragon gRPC events and enriches with process ancestry + action context. The engine correlates events across time horizons and scores them. High-score traces go to deterministic rules (fast path); ambiguous traces go to an agentic Claude Haiku analyzer (slow path). Verdicts route to D-Bus notifications and SQLite event log. Tetragon runs in Docker, socket at `/var/run/tetragon/tetragon.sock`.

**Tech Stack:** Rust 1.93+, tonic (gRPC), tokio (async), rusqlite (SQLite/WAL), zbus (D-Bus), procfs (/proc), dashmap (concurrent maps), clap (CLI), reqwest (HTTP/Anthropic API), serde + serde_yml (YAML), tracing (logging), protoc 3.21+ (proto compilation).

---

## File Structure

```
watchpost/
├── Cargo.toml                          # Workspace root
├── Cargo.lock
├── PROJECT.md                          # Design spec (exists)
├── watchpost.service                   # Systemd unit file
├── config.toml.example                 # Example configuration
├── proto/
│   └── tetragon/                       # Vendored Tetragon v1.6.1 protos
│       ├── capabilities.proto
│       ├── events.proto
│       ├── sensors.proto
│       ├── stack.proto
│       └── tetragon.proto
├── policies/                           # Base TracingPolicy YAML files
│   ├── immutability.yaml
│   ├── sensitive-files.yaml
│   ├── priv-escalation.yaml
│   └── tmp-execution.yaml
├── profiles/                           # Behavior profile YAML files
│   ├── npm.yaml
│   ├── cargo.yaml
│   ├── pip.yaml
│   └── system.yaml
├── rules/                              # Deterministic rule YAML files
│   ├── npm-rules.yaml
│   ├── pip-rules.yaml
│   ├── system-rules.yaml
│   └── network-rules.yaml
├── skills/                             # LLM analyzer skill specs
│   ├── analyzer.yaml
│   └── gate-analyzer.yaml              # Phase 2, stub in Phase 1
├── crates/
│   ├── watchpost-types/
│   │   ├── Cargo.toml                  # serde, uuid, chrono only
│   │   └── src/
│   │       ├── lib.rs                  # Re-exports all submodules
│   │       ├── events.rs               # TetragonEvent, EnrichedEvent, EventKind
│   │       ├── context.rs              # ActionContext, PackageInstall, Build, etc.
│   │       ├── profile.rs              # BehaviorProfile, Expected/Forbidden sets
│   │       ├── verdict.rs              # Verdict, Classification, RecommendedAction
│   │       ├── correlation.rs          # CorrelatedTrace, CorrelationSignal
│   │       ├── scoring.rs              # SuspicionScore, ScoreIndicator
│   │       ├── config.rs               # WatchpostConfig + all sections
│   │       ├── rules.rs                # Rule, Condition, Predicate, RuleAction
│   │       └── policy.rs               # TracingPolicy data model
│   ├── watchpost-collector/
│   │   ├── Cargo.toml                  # tonic, prost, procfs, dashmap, lru
│   │   ├── build.rs                    # tonic-build proto compilation
│   │   └── src/
│   │       ├── lib.rs                  # Collector struct, run() method
│   │       ├── grpc.rs                 # TetragonClient, event stream consumer
│   │       ├── proto.rs                # Proto-to-domain type conversions
│   │       ├── ancestry.rs             # ProcessAncestryBuilder, /proc walker
│   │       ├── context.rs              # ActionContextInferrer, tool binary matching
│   │       └── manifest.rs             # PackageManifestCache (LRU)
│   ├── watchpost-engine/
│   │   ├── Cargo.toml                  # dashmap, tokio, rusqlite
│   │   └── src/
│   │       ├── lib.rs                  # Engine struct, run() method
│   │       ├── tree.rs                 # ProcessTree (concurrent, RwLock-based)
│   │       ├── triggers.rs             # ActiveTriggerRegistry
│   │       ├── windows.rs              # TimeWindow, ImmediateWindow, SessionWindow
│   │       ├── correlation.rs          # ThreeSignalCorrelator
│   │       ├── scoring.rs              # HeuristicScorer, indicator weights
│   │       └── profiles.rs             # BehaviorProfileStore (loads YAML)
│   ├── watchpost-rules/
│   │   ├── Cargo.toml                  # serde_yml
│   │   └── src/
│   │       ├── lib.rs                  # RuleEngine struct, evaluate()
│   │       ├── loader.rs               # YAML rule file parser
│   │       └── evaluator.rs            # ConditionTree evaluator, predicate matchers
│   ├── watchpost-analyzer/
│   │   ├── Cargo.toml                  # reqwest, serde_json, serde_yml, tokio
│   │   └── src/
│   │       ├── lib.rs                  # Analyzer struct, run() method
│   │       ├── skill.rs                # SkillSpec loader (YAML)
│   │       ├── client.rs               # AnthropicClient (Messages API + structured output)
│   │       ├── context_builder.rs      # Trace -> LLM message formatting
│   │       ├── tools.rs                # Tool definitions + executor (read_project_file, etc.)
│   │       ├── agent_loop.rs           # Bounded agent loop (max 8 tool calls)
│   │       └── rate_limiter.rs         # TokenBucket rate limiter
│   ├── watchpost-policy/               # Stub in Phase 1, implemented Phase 2
│   │   ├── Cargo.toml
│   │   └── src/
│   │       └── lib.rs
│   └── watchpost-notify/
│       ├── Cargo.toml                  # zbus, rusqlite
│       └── src/
│           ├── lib.rs                  # Notifier struct, run() method
│           ├── dbus.rs                 # D-Bus notification sender + action handler
│           └── event_log.rs            # SQLite writer + query interface
├── src/
│   ├── main.rs                         # Entrypoint, clap dispatch
│   ├── cli.rs                          # Clap subcommand definitions
│   ├── daemon.rs                       # Channel wiring, tokio runtime, graceful shutdown
│   └── init.rs                         # watchpost init command logic
└── tests/
    └── integration/
        ├── scoring_scenarios.rs        # End-to-end scoring test cases
        └── pipeline_test.rs            # Full pipeline with real Tetragon
```

---

## Phase 1: MVP Core Pipeline

Phase 1 proves the full detection pipeline end-to-end: Tetragon events flow through the collector, get enriched with context, get correlated and scored, match deterministic rules (fast path) or get analyzed by Claude Haiku (slow path), and produce desktop notifications + SQLite logs.

**Phase 1 exit criteria:** Run `npm install` with a known-malicious postinstall pattern and get a desktop notification. Run `cargo build` and get zero notifications.

---

### Task 1: Workspace Scaffold + Types Crate

**Files:**
- Modify: `Cargo.toml` (workspace root)
- Create: `crates/watchpost-types/Cargo.toml`
- Create: `crates/watchpost-types/src/lib.rs`
- Create: `crates/watchpost-types/src/events.rs`
- Create: `crates/watchpost-types/src/context.rs`
- Create: `crates/watchpost-types/src/verdict.rs`
- Create: `crates/watchpost-types/src/correlation.rs`
- Create: `crates/watchpost-types/src/scoring.rs`
- Create: `crates/watchpost-types/src/config.rs`
- Create: `crates/watchpost-types/src/rules.rs`
- Create: `crates/watchpost-types/src/policy.rs`
- Create: `crates/watchpost-types/src/profile.rs`
- Modify: `src/main.rs` (placeholder update)

- [ ] **Step 1: Set up the Cargo workspace**

Replace `Cargo.toml` with workspace definition:

```toml
[workspace]
resolver = "2"
members = [
    "crates/watchpost-types",
    "crates/watchpost-collector",
    "crates/watchpost-engine",
    "crates/watchpost-rules",
    "crates/watchpost-analyzer",
    "crates/watchpost-policy",
    "crates/watchpost-notify",
]

[workspace.package]
version = "0.1.0"
edition = "2024"
license = "MIT"

[workspace.dependencies]
watchpost-types = { path = "crates/watchpost-types" }
watchpost-collector = { path = "crates/watchpost-collector" }
watchpost-engine = { path = "crates/watchpost-engine" }
watchpost-rules = { path = "crates/watchpost-rules" }
watchpost-analyzer = { path = "crates/watchpost-analyzer" }
watchpost-policy = { path = "crates/watchpost-policy" }
watchpost-notify = { path = "crates/watchpost-notify" }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
serde_yml = "0.0.12"
tokio = { version = "1", features = ["full"] }
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
chrono = { version = "0.4", features = ["serde"] }
uuid = { version = "1", features = ["v4", "serde"] }
rusqlite = { version = "0.31", features = ["bundled"] }
reqwest = { version = "0.12", features = ["json", "rustls-tls"], default-features = false }
clap = { version = "4", features = ["derive"] }
toml = "0.8"
dashmap = "6"
anyhow = "1"
thiserror = "2"

[package]
name = "watchpost"
version.workspace = true
edition.workspace = true

[dependencies]
watchpost-types.workspace = true
watchpost-collector.workspace = true
watchpost-engine.workspace = true
watchpost-rules.workspace = true
watchpost-analyzer.workspace = true
watchpost-policy.workspace = true
watchpost-notify.workspace = true
tokio.workspace = true
tracing.workspace = true
tracing-subscriber.workspace = true
clap.workspace = true
toml.workspace = true
anyhow.workspace = true
serde.workspace = true
```

- [ ] **Step 2: Create watchpost-types crate with all type definitions**

Create `crates/watchpost-types/Cargo.toml`:

```toml
[package]
name = "watchpost-types"
version.workspace = true
edition.workspace = true

[dependencies]
serde.workspace = true
serde_json.workspace = true
chrono.workspace = true
uuid.workspace = true
thiserror.workspace = true
```

Create all source files in `crates/watchpost-types/src/`. Key types:

**`events.rs`**: `EventKind` enum (ProcessExec, ProcessExit, FileAccess, NetworkConnect, PrivilegeChange, DnsQuery, ScriptExec), `TetragonEvent` struct (id, timestamp, kind, process_id, binary, args, parent_id, policy_name), `EnrichedEvent` struct (raw event + ancestry chain + action context).

**`context.rs`**: `ActionContext` enum (PackageInstall { ecosystem, package_name, package_version, working_dir }, Build { toolchain, working_dir }, FlatpakApp { app_id, permissions }, ToolboxSession { container_name, image }, ShellCommand { tty }, IdeOperation { ide_name }, Unknown). `Ecosystem` enum (Npm, Cargo, Pip).

**`verdict.rs`**: `Verdict` struct (id, trace_id, classification, confidence, recommended_action, explanation, profile_violations, timestamp). `Classification` enum (Benign, Suspicious, Malicious). `RecommendedAction` enum (Allow, Block, Notify). `Confidence` newtype over f64 (0.0-1.0).

**`correlation.rs`**: `CorrelatedTrace` struct (id, trigger, events, signals, score, context). `CorrelationSignal` struct (lineage_match: bool, temporal_weight: f64, argument_match: ArgumentMatch). `ArgumentMatch` enum (Positive, Negative, None).

**`scoring.rs`**: `SuspicionScore` newtype over f64 (0.0-1.0, clamped). `ScoreIndicator` enum with all indicators from the spec (NonRegistryNetwork, MaliciousIp, SensitiveFileWrite, TempDirExec, ShellFromPackageManager, LdPreload, PrivilegeChange, HighEntropyDns, ReverseShellPattern, ObfuscatedContent, AntiForensics). `ScoreBreakdown` struct (indicators: Vec<(ScoreIndicator, f64)>, context_modifier: f64, raw_score: f64, final_score: SuspicionScore).

**`config.rs`**: `WatchpostConfig` struct with `DaemonConfig`, `EnforcementConfig` (mode: EnforcementMode enum Autonomous/Advisory), `NotifyConfig`, and `AdvancedConfig` (sub-structs for tetragon, collector, engine, analyzer, gate, profiles, rules, policy, enforcement_overrides). All fields have `#[serde(default)]` with sensible defaults matching the spec.

**`rules.rs`**: `Rule` struct (name, description, severity: Severity, conditions: ConditionTree, action: RuleAction). `ConditionTree` enum (And(Vec<ConditionTree>), Or(Vec<ConditionTree>), Leaf(Predicate)). `Predicate` enum (BinaryMatches, AncestorBinaryMatches, FilePathStartsWith, DestPortIs, DestIpOutsideAllowlist, ExecFromTempDir, PrivilegeChange, InFlatpakSandbox, DnsQueryHighEntropy, IpReputationMalicious -- each with relevant data fields). `RuleAction` enum (Log, Notify, Block, DeferToLlm). `Severity` enum (Info, Low, Medium, High, Critical).

**`policy.rs`**: `TracingPolicySpec` struct (metadata: PolicyMetadata, spec: PolicyBody). Minimal representation -- Watchpost reads/writes these as YAML strings mostly, not deeply parsed. Include `PolicyMetadata` (name, description, source: PolicySource enum Base/Reactive/User).

**`profile.rs`**: `BehaviorProfile` struct (context_type: ActionContext discriminant, expected_network: Vec<NetworkExpectation>, expected_children: Vec<String>, expected_file_writes: Vec<String>, forbidden_file_access: Vec<String>, forbidden_children: Vec<String>, forbidden_network: Vec<NetworkExpectation>). `NetworkExpectation` struct (host: Option<String>, port: Option<u16>, description: String).

**`lib.rs`**: Re-export all submodules publicly.

- [ ] **Step 3: Write unit tests for types**

Add `#[cfg(test)]` modules to each file. Key tests:
- `SuspicionScore` clamping: `SuspicionScore::new(1.5)` yields 1.0, `new(-0.1)` yields 0.0
- `Confidence` validation
- `WatchpostConfig` default deserialization: `toml::from_str("")` produces valid config with all defaults
- `ConditionTree` serde round-trip
- `EnrichedEvent` JSON serialization round-trip

Run: `cargo test -p watchpost-types`
Expected: All tests pass.

- [ ] **Step 4: Create stub crates for the rest of the workspace**

Create minimal `Cargo.toml` + `src/lib.rs` (empty or with `// TODO`) for: `watchpost-collector`, `watchpost-engine`, `watchpost-rules`, `watchpost-analyzer`, `watchpost-policy`, `watchpost-notify`. Each `Cargo.toml` should only declare `watchpost-types.workspace = true` as a dependency for now. Other deps will be added per-task.

Update `src/main.rs` to:
```rust
fn main() {
    println!("watchpost v{}", env!("CARGO_PKG_VERSION"));
}
```

Run: `cargo build`
Expected: Clean build with all workspace crates.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat: workspace scaffold with watchpost-types crate and all shared type definitions"
```

---

### Task 2: Tetragon Proto Vendoring + gRPC Client

**Files:**
- Create: `proto/tetragon/capabilities.proto`
- Create: `proto/tetragon/events.proto`
- Create: `proto/tetragon/sensors.proto`
- Create: `proto/tetragon/stack.proto`
- Create: `proto/tetragon/tetragon.proto`
- Create: `crates/watchpost-collector/build.rs`
- Modify: `crates/watchpost-collector/Cargo.toml`
- Create: `crates/watchpost-collector/src/grpc.rs`
- Create: `crates/watchpost-collector/src/proto.rs`
- Modify: `crates/watchpost-collector/src/lib.rs`

- [ ] **Step 1: Vendor Tetragon v1.6.1 proto files**

Download the 5 proto files from `https://github.com/cilium/tetragon/tree/v1.6.1/api/v1/tetragon` into `proto/tetragon/`. These define the `FineGuidanceSensors` service and all event types.

Key protos:
- `sensors.proto`: `FineGuidanceSensors` service (GetEvents, AddTracingPolicy, DeleteTracingPolicy, ListTracingPolicies, GetHealth, GetVersion)
- `tetragon.proto`: `Process`, `ProcessExec`, `ProcessExit`, `ProcessKprobe`, `ProcessTracepoint`, `ProcessLsm` messages
- `events.proto`: `GetEventsRequest`, `GetEventsResponse`, filter types
- `capabilities.proto`: Linux capability enums
- `stack.proto`: Stack trace types

- [ ] **Step 2: Set up tonic-build**

Add to `crates/watchpost-collector/Cargo.toml`:
```toml
[dependencies]
watchpost-types.workspace = true
tonic = "0.12"
prost = "0.13"
prost-types = "0.13"
tokio.workspace = true
tracing.workspace = true
anyhow.workspace = true
thiserror.workspace = true
dashmap.workspace = true
futures = "0.3"

[build-dependencies]
tonic-build = "0.12"
```

Create `crates/watchpost-collector/build.rs`:
```rust
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto_files = &[
        "../../proto/tetragon/sensors.proto",
        "../../proto/tetragon/events.proto",
        "../../proto/tetragon/tetragon.proto",
        "../../proto/tetragon/capabilities.proto",
        "../../proto/tetragon/stack.proto",
    ];

    tonic_build::configure()
        .build_client(true)
        .build_server(false)
        .compile_protos(proto_files, &["../../proto"])?;

    Ok(())
}
```

Run: `cargo build -p watchpost-collector`
Expected: Proto compilation succeeds, generated Rust types in `target/`.

- [ ] **Step 3: Implement gRPC client**

Create `crates/watchpost-collector/src/grpc.rs`:

The `TetragonClient` struct wraps a tonic gRPC client. Key method: `connect(endpoint: &str) -> Result<Self>` supporting both `unix:///var/run/tetragon/tetragon.sock` and `tcp://host:port`. Second key method: `event_stream() -> Result<impl Stream<Item = GetEventsResponse>>` that calls the `GetEvents` RPC.

For Unix socket connection, use `tonic::transport::Endpoint::from_static("http://[::]:50051")` with a custom `connect_with_connector` using `tower::service_fn` that opens a `tokio::net::UnixStream`.

Create `crates/watchpost-collector/src/proto.rs`:

Conversion functions from proto types to domain types:
- `fn convert_exec(exec: &tetragon::ProcessExec) -> Result<TetragonEvent>` -- maps ProcessExec to EventKind::ProcessExec
- `fn convert_exit(exit: &tetragon::ProcessExit) -> Result<TetragonEvent>` -- maps ProcessExit to EventKind::ProcessExit
- `fn convert_kprobe(kp: &tetragon::ProcessKprobe) -> Result<TetragonEvent>` -- maps kprobe function_name to the appropriate EventKind (NetworkConnect for tcp_connect, PrivilegeChange for commit_creds, etc.)
- `fn convert_lsm(lsm: &tetragon::ProcessLsm) -> Result<TetragonEvent>` -- maps LSM hook to EventKind (FileAccess for security_file_permission, ScriptExec for bprm_check_security)
- `fn convert_response(resp: GetEventsResponse) -> Result<Option<TetragonEvent>>` -- dispatches on the event oneof field, returns None for event types we don't handle (uprobe, usdt, loader, throttle)

Each converter extracts: binary path, args, PID, parent PID, UID, working directory, timestamp, and event-specific fields (file path, network destination, etc.) from the proto `Process` message.

- [ ] **Step 4: Write proto conversion tests**

Test each conversion function with hand-constructed proto messages. Verify that:
- A ProcessExec proto converts to EventKind::ProcessExec with correct binary/args/pid
- A kprobe with function_name "tcp_connect" becomes EventKind::NetworkConnect
- An LSM with hook "security_file_permission" becomes EventKind::FileAccess
- Unknown event types return Ok(None)
- Missing required fields return an error

Run: `cargo test -p watchpost-collector`
Expected: All conversion tests pass.

- [ ] **Step 5: Write integration test for gRPC connection**

Create a test (behind `#[ignore]` attribute, run with `--ignored` flag) that:
1. Connects to `unix:///var/run/tetragon/tetragon.sock`
2. Calls `GetHealth` to verify the connection works
3. Calls `GetEvents` and reads at least 1 event (run `ls /tmp` in another terminal to trigger events)

Run: `cargo test -p watchpost-collector -- --ignored`
Expected: Connection succeeds and at least 1 event is received.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "feat: vendor Tetragon protos and implement gRPC client with proto-to-domain conversions"
```

---

### Task 3: Process Ancestry Builder

**Files:**
- Modify: `crates/watchpost-collector/Cargo.toml` (add procfs)
- Create: `crates/watchpost-collector/src/ancestry.rs`

- [ ] **Step 1: Write failing tests for ancestry building**

Test cases:
- `test_build_ancestry_self`: build ancestry for current process, verify it contains at least 2 entries (self + parent) and terminates at PID 1 or session leader
- `test_ancestry_cache_hit`: build ancestry twice for same PID, verify cache is used (second call returns same result without /proc reads)
- `test_ancestry_cache_eviction`: verify ProcessExit evicts the cache entry

- [ ] **Step 2: Implement ProcessAncestryBuilder**

Add `procfs = "0.17"` to collector's Cargo.toml.

`ProcessAncestryBuilder` struct contains a `DashMap<u32, Vec<AncestryEntry>>` cache. `AncestryEntry` has pid, binary_path, and cmdline.

Method `build(&self, pid: u32) -> Result<Vec<AncestryEntry>>`:
1. Check cache, return if hit
2. Walk /proc/{pid}/status reading `PPid:` field, then /proc/{pid}/exe for binary path, /proc/{pid}/cmdline for args
3. Recurse up to parent, stopping at PID 1 or max depth (16)
4. Cache the result
5. Return the chain from child to root

Method `evict(&self, pid: u32)`: remove from cache on ProcessExit.

- [ ] **Step 3: Run tests**

Run: `cargo test -p watchpost-collector ancestry`
Expected: All ancestry tests pass.

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "feat: process ancestry builder with /proc walking and DashMap cache"
```

---

### Task 4: Action Context Inference

**Files:**
- Create: `crates/watchpost-collector/src/context.rs`
- Create: `crates/watchpost-collector/src/manifest.rs`

- [ ] **Step 1: Write failing tests for context inference**

Test cases (unit tests using synthetic ancestry chains, no /proc needed):
- Ancestry `[sh, node, npm, bash, gnome-terminal]` -> `ActionContext::PackageInstall { ecosystem: Npm, .. }`
- Ancestry `[cc, cargo, bash]` -> `ActionContext::Build { toolchain: "cargo", .. }`
- Ancestry `[python3, pip, bash]` -> `ActionContext::PackageInstall { ecosystem: Pip, .. }`
- Ancestry `[app, bwrap, flatpak]` with cgroup containing `app-flatpak-` -> `ActionContext::FlatpakApp { .. }`
- Ancestry `[ls, bash, toolbox]` -> `ActionContext::ToolboxSession { .. }`
- Ancestry `[vim, bash, gnome-terminal]` -> `ActionContext::ShellCommand { .. }`
- Ancestry `[node, code]` -> `ActionContext::IdeOperation { ide_name: "vscode" }`
- Ancestry `[unknown-binary]` -> `ActionContext::Unknown`

- [ ] **Step 2: Implement ActionContextInferrer**

`ActionContextInferrer` struct. Method `infer(&self, ancestry: &[AncestryEntry], pid: u32) -> ActionContext`:

Walk the ancestry chain looking for known tool binaries:
- npm/npx/yarn/pnpm -> PackageInstall(Npm)
- cargo -> Build("cargo")
- pip/pip3/pipx/uv -> PackageInstall(Pip)
- flatpak (+ check cgroup at `/proc/{pid}/cgroup` for `app-flatpak-{id}`) -> FlatpakApp
- toolbox/distrobox (+ check cgroup for `libpod-*.scope` or `container` env) -> ToolboxSession
- code/codium -> IdeOperation("vscode"); idea/goland/clion -> IdeOperation("jetbrains")
- If session leader is a terminal emulator and parent is a shell -> ShellCommand
- Otherwise -> Unknown

- [ ] **Step 3: Implement PackageManifestCache**

`PackageManifestCache` wraps an `lru::LruCache<PathBuf, ManifestInfo>` (capacity 256). Add `lru = "0.12"` to collector deps.

`ManifestInfo` struct: package_name, version, has_install_scripts, registry_url.

Method `get_or_read(&mut self, dir: &Path, ecosystem: Ecosystem) -> Option<ManifestInfo>`:
- Check LRU cache
- Read `package.json` (Npm), `Cargo.toml` (Cargo), or `setup.py`/`pyproject.toml` (Pip)
- Parse minimally for name + version
- Cache and return

- [ ] **Step 4: Run tests**

Run: `cargo test -p watchpost-collector context`
Expected: All context inference tests pass.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat: action context inference from process ancestry with manifest caching"
```

---

### Task 5: Collector Assembly

**Files:**
- Modify: `crates/watchpost-collector/src/lib.rs`

- [ ] **Step 1: Wire Collector struct**

The `Collector` struct owns: `TetragonClient`, `ProcessAncestryBuilder`, `ActionContextInferrer`, `PackageManifestCache` (behind a Mutex since LRU is not concurrent).

Method `run(self, tx: tokio::sync::mpsc::Sender<EnrichedEvent>) -> Result<()>`:
1. Open gRPC event stream
2. For each `GetEventsResponse`:
   a. Convert proto to `TetragonEvent` via `proto.rs` (skip None)
   b. Build ancestry via `ancestry.rs`
   c. Infer context via `context.rs`
   d. Construct `EnrichedEvent { event, ancestry, context }`
   e. Send on `tx` channel (log warning if channel full)
3. On ProcessExit events: evict ancestry cache entry
4. Loop until stream ends or shutdown signal

Constructor `Collector::new(config: &CollectorConfig) -> Result<Self>` takes the Tetragon endpoint from config.

- [ ] **Step 2: Write test for collector with mock gRPC**

Create a test that uses a mock gRPC stream (a `tokio::sync::mpsc::channel` producing fake `GetEventsResponse` messages). Verify that the collector:
- Produces EnrichedEvents on the output channel
- Skips unknown event types
- Enriches with ancestry and context

- [ ] **Step 3: Run tests and verify build**

Run: `cargo test -p watchpost-collector`
Expected: All tests pass.

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "feat: collector assembly - gRPC stream to enriched events pipeline"
```

---

### Task 6: Engine - Process Tree + Trigger Registry

**Files:**
- Modify: `crates/watchpost-engine/Cargo.toml`
- Create: `crates/watchpost-engine/src/tree.rs`
- Create: `crates/watchpost-engine/src/triggers.rs`
- Create: `crates/watchpost-engine/src/windows.rs`
- Modify: `crates/watchpost-engine/src/lib.rs`

- [ ] **Step 1: Write failing tests for process tree**

Test cases:
- Insert 3 processes (parent -> child -> grandchild), query `is_descendant(grandchild, parent)` -> true
- Insert then remove child, query `is_descendant(grandchild, parent)` -> false (grandchild also removed)
- `get_subtree(parent)` returns all descendants
- Concurrent inserts from multiple threads don't panic

- [ ] **Step 2: Implement ProcessTree**

Add dependencies to engine Cargo.toml:
```toml
[dependencies]
watchpost-types.workspace = true
tokio.workspace = true
tracing.workspace = true
dashmap.workspace = true
chrono.workspace = true
anyhow.workspace = true
thiserror.workspace = true
rusqlite.workspace = true
serde_yml.workspace = true
serde.workspace = true
```

`ProcessTree` uses a `DashMap<u32, ProcessNode>` where `ProcessNode` has pid, parent_pid, binary, start_time, children: Vec<u32>.

Methods:
- `insert(&self, pid: u32, parent_pid: u32, binary: String, start_time: DateTime<Utc>)`
- `remove(&self, pid: u32)` -- removes node and all descendants recursively
- `is_descendant(&self, pid: u32, ancestor_pid: u32) -> bool` -- walks up parent chain
- `get_subtree(&self, pid: u32) -> Vec<u32>` -- BFS over children
- `get_ancestry(&self, pid: u32) -> Vec<u32>` -- walks up to root

- [ ] **Step 3: Implement ActiveTriggerRegistry and TimeWindows**

`ActiveTriggerRegistry` stores active triggers in a `DashMap<Uuid, ActiveTrigger>`. `ActiveTrigger` has: id, event (the trigger enriched event), process_pid, start_time, session_active (bool).

Methods:
- `register(&self, event: &EnrichedEvent) -> Uuid` -- creates trigger when context is PackageInstall, Build, or FlatpakApp
- `deactivate_session(&self, pid: u32)` -- called on ProcessExit of trigger root process
- `get_active_triggers(&self) -> Vec<ActiveTrigger>`
- `cleanup_expired(&self, max_age: Duration)` -- remove triggers older than persistent window

`ImmediateWindow`: 5-second buffer. `SessionWindow`: per-trigger, lives until trigger process exits. Both are simple: check if an event's timestamp falls within range. The temporal weight decays linearly:
- Immediate: weight = 1.0 if within 5s
- Session: weight = 0.7 - (0.4 * elapsed_fraction), where elapsed_fraction = time_since_trigger_start / trigger_duration

- [ ] **Step 4: Run tests**

Run: `cargo test -p watchpost-engine`
Expected: All tree and trigger tests pass.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat: engine process tree, trigger registry, and time window buffers"
```

---

### Task 7: Engine - Three-Signal Correlator

**Files:**
- Create: `crates/watchpost-engine/src/correlation.rs`

- [ ] **Step 1: Write failing tests for correlation**

Test scenarios (all using synthetic events):

1. **Lineage match**: trigger PID=100, event PID=105 with ancestry containing PID=100 -> lineage_match=true
2. **Temporal match**: trigger at T=0, event at T=2s -> temporal_weight=1.0 (immediate window). Event at T=30s during active session -> temporal_weight ~0.5.
3. **Argument match (positive)**: trigger context has registry=npmjs.org, event network dest resolves to npmjs.org -> Positive
4. **Argument match (negative)**: trigger context has registry=npmjs.org, event connects to unknown IP -> Negative
5. **Full correlation**: event matches trigger by lineage + temporal + argument -> returns CorrelatedTrace with all three signals
6. **No correlation**: event from unrelated process -> returns None

- [ ] **Step 2: Implement ThreeSignalCorrelator**

`ThreeSignalCorrelator` struct holds references to `ProcessTree` and `ActiveTriggerRegistry`.

Method `correlate(&self, event: &EnrichedEvent) -> Option<CorrelatedTrace>`:

For each active trigger:
1. **Lineage check**: `tree.is_descendant(event.pid, trigger.pid)` -> `lineage_match: bool`
2. **Temporal check**: compute time delta between event and trigger start. Check immediate window (5s), then session window (trigger still active). Return `temporal_weight: f64`.
3. **Argument check**: compare event fields against trigger context expectations. Network dest matches registry -> Positive. Network dest doesn't match any expected -> Negative. No network event -> None.
4. If any signal fired (lineage=true OR temporal_weight > 0), create `CorrelationSignal` and group into trace.

Select the trigger with the strongest combined signal if multiple match.

Return `CorrelatedTrace` containing the trigger, the new event, all previously-correlated events for this trigger (stored in a trace buffer), and the signal strengths.

- [ ] **Step 3: Run tests**

Run: `cargo test -p watchpost-engine correlation`
Expected: All correlation tests pass.

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "feat: three-signal correlator (lineage, temporal, argument matching)"
```

---

### Task 8: Engine - Heuristic Scoring + Profiles

**Files:**
- Create: `crates/watchpost-engine/src/scoring.rs`
- Create: `crates/watchpost-engine/src/profiles.rs`

- [ ] **Step 1: Write failing tests for scoring**

Table-driven test cases (from the spec's indicator weights):

| Scenario | Expected Score Range |
|----------|---------------------|
| npm context + network to non-registry IP | >= 0.6 (0.4 x 1.5 context) |
| npm context + ssh key read | >= 0.7 (0.5 x 1.5) |
| npm context + /tmp exec | >= 0.7 (0.6 x 1.5, capped) |
| cargo build + shell spawn | < 0.3 (0.3 x 0.7 context) |
| npm context + reverse shell pattern | >= 0.9 (0.9 x 1.5, capped) |
| unknown context + no indicators | 0.0 |
| npm + non-registry net + ssh read | >= 0.7 (multiple indicators) |

- [ ] **Step 2: Implement HeuristicScorer**

`HeuristicScorer` struct holds indicator weights (HashMap<ScoreIndicator, f64>) initialized from spec defaults, and a `BehaviorProfileStore`.

Method `score(&self, trace: &CorrelatedTrace) -> ScoreBreakdown`:

1. Collect applicable indicators by examining events in the trace:
   - NetworkConnect to non-registry IP -> NonRegistryNetwork(+0.4)
   - NetworkConnect to known malicious IP or C2 port -> MaliciousIp(+0.8)
   - FileAccess(read) to .ssh/.gnupg/.aws -> SensitiveFileRead(+0.4)
   - FileAccess(write) to .ssh/.gnupg/.config -> SensitiveFileWrite(+0.5)
   - ProcessExec from /tmp, /dev/shm, /var/tmp -> TempDirExec(+0.6)
   - ProcessExec of sh/bash as child of package manager -> ShellFromPackageManager(+0.3)
   - LD_PRELOAD in child env -> LdPreload(+0.5)
   - PrivilegeChange from non-root context -> PrivilegeChange(+0.7)
   - DnsQuery with entropy > 4.0 -> HighEntropyDns(+0.3)
   - stdin/stdout redirected to socket -> ReverseShellPattern(+0.9)

Note: `ObfuscatedContent` (+0.7) and `AntiForensics` (+0.5) indicators are defined in the types enum but their detection requires script content analysis. They are scored only when script content is available (Phase 2 pre-execution gate). In Phase 1, they exist in the enum but do not fire.

2. Check behavior profile: if the event matches an "expected" pattern, skip scoring (return 0.0 for that indicator). If "forbidden", add maximum weight.

3. Sum indicator weights -> raw_score

4. Apply context modifier: PackageInstall x 1.5, Build x 0.7, FlatpakApp x 1.3, ToolboxSession x 0.8, Unknown x 1.0

5. Clamp to [0.0, 1.0] -> final SuspicionScore

- [ ] **Step 3: Implement BehaviorProfileStore**

`BehaviorProfileStore` loads YAML profile files from a directory. Method `load(dir: &Path) -> Result<Self>`. Method `get_profile(&self, context: &ActionContext) -> Option<&BehaviorProfile>`. Method `classify_event(&self, event: &TetragonEvent, context: &ActionContext) -> BehaviorClassification` where `BehaviorClassification` is `Expected | Unspecified | Forbidden`.

Write a test that loads a minimal npm profile YAML and verifies that `node-gyp` as a child of `npm` is classified as Expected, and `/tmp/payload` execution is Forbidden.

- [ ] **Step 4: Run tests**

Run: `cargo test -p watchpost-engine scoring`
Expected: All scoring tests pass.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat: heuristic scoring with behavior profiles and context modifiers"
```

---

### Task 9: Engine Assembly + Routing

**Files:**
- Modify: `crates/watchpost-engine/src/lib.rs`

- [ ] **Step 1: Wire Engine struct**

`Engine` struct owns: `ProcessTree`, `ActiveTriggerRegistry`, `ThreeSignalCorrelator`, `HeuristicScorer`, `BehaviorProfileStore`.

Method `run(self, rx: mpsc::Receiver<EnrichedEvent>, rules_tx: mpsc::Sender<CorrelatedTrace>, analyzer_tx: mpsc::Sender<CorrelatedTrace>, log_tx: mpsc::Sender<CorrelatedTrace>) -> Result<()>`:

For each enriched event:
1. Update process tree (insert on Exec, remove on Exit)
2. Check if event should register as a trigger (PackageInstall, Build, FlatpakApp contexts)
3. Correlate with active triggers
4. If correlated: score the trace
5. Route based on score:
   - score >= fast_path_threshold (0.7) -> send to `rules_tx`
   - score >= llm_threshold (0.3) -> send to `analyzer_tx`
   - score < 0.3 -> send to `log_tx` (logged but not classified)
6. On ProcessExit: deactivate session triggers for that PID

- [ ] **Step 2: Write routing test**

Create a test that sends synthetic enriched events through the engine and verifies:
- High-score trace goes to rules channel
- Medium-score trace goes to analyzer channel
- Low-score trace goes to log channel

- [ ] **Step 3: Run tests**

Run: `cargo test -p watchpost-engine`
Expected: All tests pass.

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "feat: engine assembly with score-based routing to rules/analyzer/log"
```

---

### Task 10: Rule Engine

**Files:**
- Modify: `crates/watchpost-rules/Cargo.toml`
- Create: `crates/watchpost-rules/src/loader.rs`
- Create: `crates/watchpost-rules/src/evaluator.rs`
- Modify: `crates/watchpost-rules/src/lib.rs`

- [ ] **Step 1: Write failing tests for rule loading**

Create a test YAML rule string:
```yaml
- name: npm-reverse-shell
  description: "npm child opens reverse shell"
  severity: critical
  conditions:
    and:
      - ancestor_binary_matches: [npm, npx, yarn, pnpm]
      - or:
          - dest_port_is: [4444, 5555, 1337, 9001]
          - binary_matches: [nc, ncat, socat]
  action: block
```
Verify it deserializes into a `Rule` with correct fields.

- [ ] **Step 2: Implement rule loader**

Add to rules Cargo.toml:
```toml
[dependencies]
watchpost-types.workspace = true
serde.workspace = true
serde_yml.workspace = true
tracing.workspace = true
anyhow.workspace = true
thiserror.workspace = true
```

`load_rules(dir: &Path) -> Result<Vec<Rule>>`: reads all `.yaml` files in the directory, deserializes each as `Vec<Rule>`, flattens, sorts by severity (Critical first).

- [ ] **Step 3: Write failing tests for rule evaluation**

Test cases:
- npm-reverse-shell: trace with npm ancestor + dest_port 4444 -> matches, action=Block
- npm-temp-dir-exec: trace with npm ancestor + exec from /tmp/ -> matches, action=Block
- npm-ssh-key-access: trace with npm ancestor + file read ~/.ssh/ -> matches, action=Block
- any-temp-dir-exec: trace with any process + exec from /tmp -> matches, action=Notify
- No match: trace with cargo build + normal network -> no rule matches

- [ ] **Step 4: Implement rule evaluator**

`RuleEngine` struct holds `Vec<Rule>` sorted by severity.

Method `evaluate(&self, trace: &CorrelatedTrace) -> Option<Verdict>`:
1. For each rule (critical first):
2. Evaluate `ConditionTree` against the trace
3. Predicate evaluation:
   - `BinaryMatches(bins)`: check if any event's binary matches any in `bins`
   - `AncestorBinaryMatches(bins)`: check if any ancestry entry matches
   - `FilePathStartsWith(prefixes)`: check file access events
   - `DestPortIs(ports)`: check network events
   - `ExecFromTempDir`: check if binary path starts with /tmp/, /dev/shm/, /var/tmp/
   - `PrivilegeChange`: check for PrivilegeChange events
   - And/Or: short-circuit evaluate children
4. First matching rule produces a Verdict with classification based on severity (Critical/High -> Malicious, Medium -> Suspicious, Low/Info -> Benign), confidence 1.0, and the rule's action.

- [ ] **Step 5: Run tests**

Run: `cargo test -p watchpost-rules`
Expected: All tests pass.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "feat: deterministic rule engine with YAML loader and condition tree evaluator"
```

---

### Task 11: Shipped Rules

**Files:**
- Create: `rules/npm-rules.yaml`
- Create: `rules/pip-rules.yaml`
- Create: `rules/system-rules.yaml`
- Create: `rules/network-rules.yaml`

- [ ] **Step 1: Write the 10 shipped rules from the spec**

**`rules/npm-rules.yaml`** -- 3 rules:
1. `npm-reverse-shell` (critical, block): npm ancestor + reverse shell ports or nc/ncat/socat
2. `npm-temp-dir-exec` (critical, block): npm ancestor + exec from /tmp
3. `npm-ssh-key-access` (high, block): npm ancestor + file access to ~/.ssh/

**`rules/pip-rules.yaml`** -- 1 rule:
4. `pip-sensitive-file-access` (high, block): pip ancestor + access to ~/.ssh/, ~/.gnupg/, browser profiles

**`rules/system-rules.yaml`** -- 3 rules:
5. `any-temp-dir-exec` (medium, notify): any process exec from /tmp or /dev/shm (not in exception list)
6. `any-unexpected-privilege-change` (high, block): privilege change from non-sudo/pkexec/polkit/systemd ancestor
7. `any-immutability-violation` (critical, block): write to /usr/ from non-rpm-ostree/ostree/systemd-sysext process

**`rules/network-rules.yaml`** -- 3 rules:
8. `any-crypto-mining-port` (critical, block): connect to ports 3333, 4444, 14444, 45700
9. `flatpak-host-file-escape` (high, block): flatpak sandbox + access to /home/ or /etc/ outside permissions
10. `any-dns-exfiltration` (medium, defer_to_llm): dev tool child + DNS query with high entropy

- [ ] **Step 2: Write a test that loads shipped rules and evaluates against test traces**

Load all 4 YAML files. Verify 10 rules loaded. Run 3 synthetic traces through the evaluator and verify correct matches.

Run: `cargo test -p watchpost-rules`
Expected: All tests pass including shipped rule tests.

- [ ] **Step 3: Commit**

```bash
git add -A
git commit -m "feat: ship 10 deterministic security rules for npm, pip, system, and network threats"
```

---

### Task 12: Analyzer - Anthropic API Client

**Files:**
- Modify: `crates/watchpost-analyzer/Cargo.toml`
- Create: `crates/watchpost-analyzer/src/client.rs`

- [ ] **Step 1: Write failing test for Anthropic client**

Test that the client constructs a valid Messages API request with:
- Model: `claude-haiku-4-5-20251001`
- System prompt from skill spec
- Structured output via `output_config.format` with Verdict JSON schema
- Tool definitions for the 5 analyzer tools
- Proper Authorization header

Use a mock HTTP server (or test request construction without sending).

- [ ] **Step 2: Implement AnthropicClient**

Add to analyzer Cargo.toml:
```toml
[dependencies]
watchpost-types.workspace = true
reqwest.workspace = true
serde.workspace = true
serde_json.workspace = true
serde_yml.workspace = true
tokio.workspace = true
tracing.workspace = true
anyhow.workspace = true
thiserror.workspace = true
chrono.workspace = true
uuid.workspace = true
```

`AnthropicClient` struct with `reqwest::Client`, `api_key`, `model_id`, `base_url`.

Method `send_message(&self, messages: Vec<Message>, tools: Vec<Tool>, output_schema: serde_json::Value) -> Result<Response>`:

POST to `{base_url}/v1/messages` with body containing model, max_tokens, system prompt, messages, tools, and output_config with json_schema format for structured output.

Parse response: extract tool_use blocks or text content. Return structured `Response` enum: `ToolUse { id, name, input }` or `Text { content }` or `EndTurn { content }`.

- [ ] **Step 3: Run tests**

Run: `cargo test -p watchpost-analyzer client`
Expected: Request construction tests pass.

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "feat: Anthropic Messages API client with structured output support"
```

---

### Task 13: Analyzer - Skill Loader + Context Builder

**Files:**
- Create: `crates/watchpost-analyzer/src/skill.rs`
- Create: `crates/watchpost-analyzer/src/context_builder.rs`
- Create: `skills/analyzer.yaml`

- [ ] **Step 1: Define skill YAML format and create analyzer skill**

Create `skills/analyzer.yaml` -- the system prompt, tool definitions, and output schema for runtime trace analysis. This is the highest-impact artifact in the system.

Structure:
```yaml
name: runtime-trace-analyzer
version: "1.0"

system_prompt: |
  You are a Linux desktop security analyst. You receive correlated kernel event
  traces from a developer's workstation and classify them as benign, suspicious,
  or malicious.

  ## Your Role
  You analyze sequences of kernel events (process execution, file access, network
  connections, privilege changes) that occurred during a specific user action
  (package install, build, app launch). Your job is to determine if the observed
  behavior is consistent with the stated action or indicates a security threat.

  ## Classification Framework
  For each event in the trace, evaluate against the behavior profile:
  - **Expected**: Matches the profile's known-good patterns. No concern.
  - **Unspecified**: Not in the profile. Use your security expertise to assess.
  - **Forbidden**: Explicitly banned in the profile. Always malicious.

  ## Analysis Process
  1. Read the trigger context and behavior profile carefully
  2. Examine each event in the trace chronologically
  3. Use tools to gather additional context when needed
  4. Classify: benign (normal behavior), suspicious (unusual but not clearly
     malicious), or malicious (security threat requiring action)
  5. Provide confidence (0.0-1.0) and a one-sentence explanation suitable for a
     desktop notification

  ## Important Guidelines
  - Developer workstations are noisy. Builds spawn many child processes.
  - Supply chain attacks hide inside legitimate actions. Look for behaviors
    inconsistent with the stated package purpose.
  - Key attack patterns: sensitive file reads during package install, network
    connections to non-registry IPs, binary execution from /tmp, reverse shells.
  - When uncertain, use tools to check package.json, Cargo.toml, or registry data.
  - Be conservative: false positives are worse than false negatives for
    benign-looking traces.

tools:
  - name: read_project_file
    description: "Read a file from the trigger's working directory"
    parameters:
      type: object
      properties:
        path:
          type: string
          description: "File path (sandboxed to working dir and cache paths)"
      required: [path]

  - name: get_process_tree
    description: "Get the full subtree of descendants for a process"
    parameters:
      type: object
      properties:
        pid:
          type: integer
          description: "Process ID to get subtree for"
      required: [pid]

  - name: get_recent_events
    description: "Get enriched events for a process group within a time window"
    parameters:
      type: object
      properties:
        pid:
          type: integer
          description: "Process ID"
        seconds:
          type: integer
          description: "Look back this many seconds"
      required: [pid, seconds]

output_schema:
  type: object
  properties:
    classification:
      type: string
      enum: [benign, suspicious, malicious]
    confidence:
      type: number
      minimum: 0.0
      maximum: 1.0
    recommended_action:
      type: string
      enum: [allow, block, notify]
    explanation:
      type: string
      description: "One sentence for desktop notification"
    profile_violations:
      type: array
      items:
        type: string
      description: "Specific behavior profile deviations found"
  required:
    - classification
    - confidence
    - recommended_action
    - explanation
    - profile_violations
```

- [ ] **Step 2: Implement SkillSpec loader**

`SkillSpec` struct: name, version, system_prompt, tools (Vec<ToolDef>), output_schema (serde_json::Value).

`SkillSpec::load(path: &Path) -> Result<Self>`: reads and deserializes the YAML file. Support hot-reload by re-reading on SIGHUP (the reload mechanism is wired in the daemon, not here).

Write test: load `skills/analyzer.yaml`, verify system_prompt is non-empty, 3 tools defined, output schema has required fields.

- [ ] **Step 3: Implement ContextBuilder**

`ContextBuilder` formats a `CorrelatedTrace` into LLM messages.

Method `build_messages(&self, trace: &CorrelatedTrace, profile: &BehaviorProfile, skill: &SkillSpec) -> Vec<Message>`:

Produces a single user message containing:
1. Trigger context: "The user ran `{command}` in `{directory}`."
2. Behavior profile summary (expected/forbidden patterns)
3. Process ancestry chain formatted as a tree
4. Chronological event list with timestamps and details
5. Correlation signals and heuristic score breakdown
6. Task instruction from skill spec

Write test: build messages for a synthetic npm install trace, verify output contains expected sections.

- [ ] **Step 4: Run tests**

Run: `cargo test -p watchpost-analyzer`
Expected: All tests pass.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat: analyzer skill loader, context builder, and runtime analyzer skill spec"
```

---

### Task 14: Analyzer - Agent Loop + Tools

**Files:**
- Create: `crates/watchpost-analyzer/src/tools.rs`
- Create: `crates/watchpost-analyzer/src/agent_loop.rs`
- Create: `crates/watchpost-analyzer/src/rate_limiter.rs`
- Modify: `crates/watchpost-analyzer/src/lib.rs`

- [ ] **Step 1: Implement tool executor**

`ToolExecutor` struct holds references to the process tree, event log, and working directory.

Method `execute(&self, tool_name: &str, input: serde_json::Value) -> Result<String>`:
- `read_project_file`: read file content, sandboxed to allowed paths. Return content or error.
- `get_process_tree`: query engine's process tree, format as text tree
- `get_recent_events`: query event log for recent events for a PID

For Phase 1, `lookup_package` and `lookup_ip` are not implemented (Phase 2). Return "Tool not available in this version" if called.

Write test: execute `read_project_file` with a temp file path, verify content returned.

- [ ] **Step 2: Implement agent loop**

`AgentLoop` struct with `AnthropicClient`, `ToolExecutor`, `SkillSpec`, max_tool_calls (default 8).

Method `analyze(&self, trace: &CorrelatedTrace, profile: &BehaviorProfile) -> Result<Verdict>`:

1. Build initial messages via ContextBuilder
2. Send to LLM with tool definitions and output schema
3. If response contains tool_use: execute tool, append result, send again
4. Repeat until LLM returns end_turn with structured verdict
5. If tool call budget exceeded: extract last reasoning, produce best-effort verdict
6. Parse structured output into Verdict

Write test with a mock client that returns a sequence: tool_use("read_project_file") then end_turn(verdict). Verify the loop executes the tool and returns the final verdict.

- [ ] **Step 3: Implement rate limiter**

Simple token bucket: `RateLimiter::new(max_per_minute: u32)`. Method `try_acquire() -> bool`. Tracks timestamps of recent acquisitions in a VecDeque, removes entries older than 60 seconds.

Write test: acquire 10 tokens in quick succession (limit=10), 11th fails.

- [ ] **Step 4: Wire Analyzer struct**

`Analyzer` struct owns `AgentLoop`, `RateLimiter`, queue (bounded VecDeque, default 50).

Method `run(self, rx: mpsc::Receiver<CorrelatedTrace>, verdict_tx: mpsc::Sender<Verdict>) -> Result<()>`:
1. Receive trace from channel
2. Check rate limiter: if exhausted, queue the trace (drop oldest if queue full, log warning)
3. If allowed: run `agent_loop.analyze()`
4. Send verdict on `verdict_tx`

- [ ] **Step 5: Run tests**

Run: `cargo test -p watchpost-analyzer`
Expected: All tests pass.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "feat: agentic LLM analyzer with tool execution, bounded agent loop, and rate limiter"
```

---

### Task 15: Notify - SQLite Event Log

**Files:**
- Modify: `crates/watchpost-notify/Cargo.toml`
- Create: `crates/watchpost-notify/src/event_log.rs`
- Modify: `crates/watchpost-notify/src/lib.rs`

- [ ] **Step 1: Write failing tests for event log**

Test cases (all using in-memory SQLite `:memory:`):
- Insert an enriched event, query by ID -> returns same event
- Insert 3 events with different severities, query `--severity high` -> returns only high
- Insert events with timestamps, query `--since 1h` -> returns only recent
- Insert a verdict, query by trace_id -> returns verdict with full detail

- [ ] **Step 2: Implement EventLog**

Add to notify Cargo.toml:
```toml
[dependencies]
watchpost-types.workspace = true
rusqlite.workspace = true
tokio.workspace = true
tracing.workspace = true
anyhow.workspace = true
thiserror.workspace = true
chrono.workspace = true
serde.workspace = true
serde_json.workspace = true
uuid.workspace = true
```

`EventLog` struct wraps `rusqlite::Connection`.

Constructor `EventLog::open(path: &Path) -> Result<Self>`:
- Open or create SQLite database
- `PRAGMA journal_mode = WAL;`
- `PRAGMA synchronous = NORMAL;`
- Create tables: events (id, timestamp, kind, process_id, binary, args, context_type, severity, raw_json, created_at) and verdicts (id, trace_id, classification, confidence, recommended_action, explanation, profile_violations, source, created_at)
- Create indexes on timestamp, severity, and trace_id

Methods:
- `insert_event(&self, event: &EnrichedEvent) -> Result<()>`
- `insert_verdict(&self, verdict: &Verdict, source: &str) -> Result<()>`
- `query_events(&self, filter: &EventFilter) -> Result<Vec<EnrichedEvent>>` -- EventFilter has since, until, severity, classification, binary, context fields
- `query_verdict(&self, trace_id: &Uuid) -> Result<Option<Verdict>>`

- [ ] **Step 3: Run tests**

Run: `cargo test -p watchpost-notify event_log`
Expected: All tests pass.

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "feat: SQLite event log with WAL mode, event/verdict storage, and filtered queries"
```

---

### Task 16: Notify - D-Bus Desktop Notifications

**Files:**
- Create: `crates/watchpost-notify/src/dbus.rs`
- Modify: `crates/watchpost-notify/src/lib.rs`

- [ ] **Step 1: Implement D-Bus notification sender**

Add `zbus = "5"` to notify Cargo.toml.

`DesktopNotifier` struct. Uses `org.freedesktop.Notifications` D-Bus interface.

Method `notify_blocked(&self, verdict: &Verdict) -> Result<()>`:
Send notification with:
- Summary: "Blocked: {context description}"
- Body: "{explanation}"
- Actions: ["undo", "Undo", "details", "Details"]
- Urgency hint: critical
- Icon: "security-high" (standard freedesktop icon)

Method `notify_threat(&self, verdict: &Verdict) -> Result<()>`:
Send notification with:
- Summary: "Threat: {explanation}"
- Body: "Process killed."
- Actions: ["details", "Details"]  (no Undo for threats)
- Urgency hint: critical

Method `listen_for_actions(&self) -> impl Stream<Item = NotificationAction>`:
Listen on the D-Bus `ActionInvoked` signal. Yield `NotificationAction { notification_id, action_key }`.

- [ ] **Step 2: Wire Notifier struct**

`Notifier` struct owns `DesktopNotifier` and `EventLog`.

Method `run(self, verdict_rx: mpsc::Receiver<Verdict>, log_rx: mpsc::Receiver<CorrelatedTrace>) -> Result<()>`:
1. For verdicts: log to SQLite, send desktop notification if action is Block or if classification is Malicious
2. For log-only traces (score < 0.3): log to SQLite, no notification
3. Listen for notification actions: on "undo" record override (Phase 2 handles feedback loop)

- [ ] **Step 3: Write test for notification construction**

Test that `notify_blocked` constructs the correct D-Bus message body (test the message construction, not the actual D-Bus send -- that requires a session bus).

Run: `cargo test -p watchpost-notify`
Expected: All tests pass.

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "feat: D-Bus desktop notifications for blocked processes and threat alerts"
```

---

### Task 17: CLI + Configuration + Daemon Wiring

**Files:**
- Modify: `src/main.rs`
- Create: `src/cli.rs`
- Create: `src/daemon.rs`
- Create: `src/init.rs`
- Create: `config.toml.example`

- [ ] **Step 1: Implement CLI with clap**

`src/cli.rs`:
```rust
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "watchpost", version, about = "eBPF-powered desktop security agent")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// One-command setup
    Init {
        #[arg(long)]
        api_key: Option<String>,
    },
    /// Start the daemon (for systemd)
    Daemon {
        #[arg(long, default_value = "/etc/watchpost/config.toml")]
        config: String,
    },
    /// Show daemon status
    Status,
    /// Query the event log
    Events {
        #[command(subcommand)]
        action: EventsAction,
    },
}

#[derive(Subcommand)]
pub enum EventsAction {
    List {
        #[arg(long)]
        since: Option<String>,
        #[arg(long)]
        until: Option<String>,
        #[arg(long)]
        severity: Option<String>,
        #[arg(long)]
        classification: Option<String>,
        #[arg(long)]
        binary: Option<String>,
        #[arg(long)]
        context: Option<String>,
        #[arg(long, default_value = "table")]
        format: String,  // table, json, csv
    },
    Show { event_id: String },
}
```

- [ ] **Step 2: Implement config loader**

Parse TOML into `WatchpostConfig` (from watchpost-types). Also check `ANTHROPIC_API_KEY` env var as fallback for api_key.

Create `config.toml.example`:
```toml
[daemon]
api_key = "sk-ant-..."
# log_level = "warn"
# data_dir = "/var/lib/watchpost"

# [enforcement]
# mode = "autonomous"  # or "advisory"

# [notify]
# desktop = true

# See PROJECT.md Section 7 for all advanced settings
```

- [ ] **Step 3: Implement daemon wiring**

`src/daemon.rs` -- `pub async fn run_daemon(config: WatchpostConfig) -> Result<()>`:

1. Initialize tracing subscriber with config log level
2. Open SQLite event log at `{data_dir}/events.db`
3. Load behavior profiles from `profiles/` directory
4. Load rules from `rules/` directory
5. Load analyzer skill from `skills/analyzer.yaml`
6. Create channels:
   - `collector -> engine`: mpsc(4096) for EnrichedEvent
   - `engine -> rules`: mpsc(256) for CorrelatedTrace (high score)
   - `engine -> analyzer`: mpsc(256) for CorrelatedTrace (medium score)
   - `engine -> log`: mpsc(1024) for CorrelatedTrace (low score)
   - `rules -> notifier`: mpsc(64) for Verdict
   - `analyzer -> notifier`: mpsc(64) for Verdict
7. Spawn tokio tasks for each component
8. Handle SIGTERM for graceful shutdown (drop channels, await task completion)
9. Call `sd_notify::notify(false, &[sd_notify::NotifyState::Ready])` after setup

Add `sd-notify = "0.4"` to binary crate deps.

- [ ] **Step 4: Implement watchpost init**

`src/init.rs`:
1. Prompt for API key (or use --api-key flag, or ANTHROPIC_API_KEY env)
2. Scan PATH for npm, yarn, pnpm, cargo, pip, pip3, uv, flatpak
3. Write config to `/etc/watchpost/config.toml`
4. Copy policies from `policies/` to Tetragon policy dir
5. Print summary of detected toolchains and installed policies
6. Validate Tetragon connection (try gRPC health check)
7. Validate API key (make a minimal API call)

- [ ] **Step 5: Implement `watchpost status` and `events` output formatters**

`status` command: Connect to daemon's SQLite DB (read-only), query events in last hour, blocks in last 24h, and show daemon PID from pidfile. Print formatted summary.

`events list` output formatters:
- `table`: pretty-printed columns (timestamp, severity, binary, context, classification)
- `json`: serialize Vec<EnrichedEvent> as JSON array
- `csv`: write CSV header + rows using the same fields

- [ ] **Step 6: Wire main.rs**

```rust
mod cli;
mod daemon;
mod init;

use clap::Parser;
use cli::{Cli, Command};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Init { api_key } => init::run(api_key).await,
        Command::Daemon { config } => {
            let cfg = load_config(&config)?;
            daemon::run_daemon(cfg).await
        }
        Command::Status => status::run().await,
        Command::Events { action } => events::run(action).await,
    }
}
```

- [ ] **Step 6: Run build and basic CLI test**

Run: `cargo build`
Expected: Clean build.

Run: `cargo run -- --help`
Expected: Shows usage with init, daemon, status, events subcommands.

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "feat: CLI with init/daemon/status/events commands, config loader, and daemon wiring"
```

---

### Task 18: TracingPolicies + Behavior Profiles

**Files:**
- Create: `policies/immutability.yaml`
- Create: `policies/sensitive-files.yaml`
- Create: `policies/priv-escalation.yaml`
- Create: `policies/tmp-execution.yaml`
- Create: `profiles/npm.yaml`
- Create: `profiles/cargo.yaml`
- Create: `profiles/pip.yaml`
- Create: `profiles/system.yaml`

- [ ] **Step 1: Write the 4 base TracingPolicies**

These are Tetragon TracingPolicy YAML files. Follow Tetragon's TracingPolicy CRD schema.

**`policies/immutability.yaml`**: LSM `security_file_permission` on `/usr/`, `/boot/`, `/lib/modules/` with MAY_WRITE filter, excluding rpm-ostree/ostree/systemd-sysext.

**`policies/sensitive-files.yaml`**: LSM `security_file_permission` on `~/.ssh/`, `~/.gnupg/`, `~/.config/`, `/etc/shadow`, `/etc/passwd`, `/etc/sudoers` with both MAY_READ and MAY_WRITE, excluding systemd/sshd/gnome-keyring/passwd/sudo.

**`policies/priv-escalation.yaml`**: Kprobes on `commit_creds` (syscall: false) and `sys_setuid` (syscall: true -- Tetragon auto-translates to arch-specific symbol like `__x64_sys_setuid`). Post action, no binary filter.

**`policies/tmp-execution.yaml`**: LSM `bprm_check_security` for binaries with path prefix `/tmp/`, `/dev/shm/`, `/var/tmp/`. Post action.

- [ ] **Step 2: Write behavior profiles**

**`profiles/npm.yaml`**:
```yaml
context_type: PackageInstall
ecosystem: npm
expected_network:
  - { host: "registry.npmjs.org", description: "npm registry" }
  - { host: "github.com", description: "GitHub release assets" }
  - { host: "objects.githubusercontent.com", description: "GitHub downloads" }
expected_children:
  - node
  - sh
  - bash
  - node-gyp
  - make
  - cc
  - c++
  - g++
  - python3
  - node-pre-gyp
expected_file_writes:
  - node_modules/
  - package-lock.json
forbidden_file_access:
  - .ssh/
  - .gnupg/
  - .aws/
  - .config/gcloud/
forbidden_children:
  - nc
  - ncat
  - socat
forbidden_network:
  - { port: 4444, description: "common reverse shell port" }
  - { port: 5555, description: "common reverse shell port" }
  - { port: 1337, description: "common reverse shell port" }
```

**`profiles/cargo.yaml`**: Expected: rustc, cc, ld, ar, as, cc1, collect2. Network: crates.io, static.crates.io, github.com. Writes: target/. Forbidden: same sensitive paths.

**`profiles/pip.yaml`**: Expected: gcc, g++, python3, cmake, pip. Network: pypi.org, files.pythonhosted.org. Writes: site-packages/. Forbidden: same.

**`profiles/system.yaml`**: Expected privilege escalation paths: sudo, pkexec, polkit, systemd.

- [ ] **Step 3: Write a test that loads all policies and profiles**

Verify Tetragon policies are valid YAML. Verify behavior profiles deserialize into `BehaviorProfile` structs correctly. Verify npm profile has expected_children containing "node-gyp" and forbidden_file_access containing ".ssh/".

Run: `cargo test -p watchpost-engine profiles`
Expected: All tests pass.

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "feat: ship 4 base TracingPolicies and behavior profiles for npm/cargo/pip/system"
```

---

### Task 19: Systemd Service File

**Files:**
- Create: `watchpost.service`
- Create: `skills/gate-analyzer.yaml` (stub for Phase 2)

- [ ] **Step 1: Create systemd unit file**

```ini
[Unit]
Description=Watchpost eBPF Security Agent
Documentation=https://github.com/user/watchpost
After=tetragon.service
Requires=tetragon.service

[Service]
Type=notify
ExecStart=/usr/local/bin/watchpost daemon
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5

# Security hardening
ProtectSystem=strict
ReadWritePaths=/var/lib/watchpost /etc/tetragon/tetragon.tp.d
ProtectHome=read-only
NoNewPrivileges=true
CapabilityBoundingSet=
PrivateTmp=true
ProtectKernelTunables=true
ProtectControlGroups=true

[Install]
WantedBy=multi-user.target
```

- [ ] **Step 2: Create stub gate-analyzer skill**

Create `skills/gate-analyzer.yaml` with a placeholder:
```yaml
name: gate-analyzer
version: "1.0"
note: "Phase 2 - pre-execution script gate analysis skill"
system_prompt: "TODO: Phase 2"
tools: []
output_schema: {}
```

- [ ] **Step 3: Commit**

```bash
git add -A
git commit -m "feat: systemd service file with security hardening and gate-analyzer stub"
```

---

### Task 20: End-to-End Integration Test

**Files:**
- Create: `tests/integration/pipeline_test.rs`
- Create: `tests/integration/scoring_scenarios.rs`

- [ ] **Step 1: Write scoring scenario tests**

`tests/integration/scoring_scenarios.rs` -- tests that construct realistic event sequences and verify the full scoring + rules pipeline produces correct verdicts. No real Tetragon needed.

Scenarios:
1. **npm postinstall reads SSH keys**: construct EnrichedEvent sequence (npm exec, node exec, sh exec, cat ~/.ssh/id_rsa file access). Feed through engine + rules. Expect: score >= 0.7, rule `npm-ssh-key-access` matches, verdict=Malicious, action=Block.

2. **Normal cargo build**: construct event sequence (cargo exec, rustc exec, cc exec, ld exec, network to crates.io). Feed through engine. Expect: score < 0.3, no rule match, logged only.

3. **Cryptominer connection**: construct event sequence (unknown binary, tcp_connect to port 3333). Expect: rule `any-crypto-mining-port` matches, action=Block.

4. **Ambiguous npm behavior**: construct event sequence (npm, node, python3, moderate indicators). Expect: 0.3 <= score < 0.7, routed to analyzer.

- [ ] **Step 2: Write full pipeline integration test**

`tests/integration/pipeline_test.rs` -- `#[ignore]` test that requires running Tetragon.

1. Start the collector connected to Tetragon
2. Start the engine with test channels
3. Start the rules engine
4. In a separate thread: run `ls /tmp` to generate a ProcessExec event
5. Verify: an event flows through collector -> engine -> either rules or log
6. Verify: event is written to SQLite

- [ ] **Step 3: Run all tests**

Run: `cargo test`
Expected: All unit tests pass.

Run: `cargo test -- --ignored` (requires Tetragon)
Expected: Integration tests pass.

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "test: end-to-end scoring scenarios and pipeline integration tests"
```

---

**Phase 1 exit verification:**

```bash
cargo build --release
cargo test
cargo run -- --help
# Verify: init, daemon, status, events subcommands listed

# With Tetragon running:
cargo test -- --ignored
# Verify: gRPC connection and event flow works

# Manual test:
# 1. Start daemon: cargo run -- daemon --config config.toml.example
# 2. In another terminal, create a suspicious pattern
# 3. Verify: desktop notification appears or event logged to SQLite
```

---

## Phase 2: Proactive Defense + Policy Management

Phase 2 adds proactive script gating, dynamic policy management, the user feedback loop, and extended analyzer capabilities. Each task builds on the Phase 1 infrastructure.

**Phase 2 exit criteria:** Run `npm install` with a malicious postinstall script and have it blocked *before* execution. Verify that clicking "Undo" on a false positive permanently allowlists the pattern.

---

### Task 21: Pre-Execution Script Gate TracingPolicy

**Files:**
- Create: `policies/install-script-gate.yaml`
- Modify: `crates/watchpost-collector/src/grpc.rs` (handle Override events)

- [ ] **Step 1:** Write `install-script-gate.yaml` using `bprm_check_security` LSM hook with `Override` action, filtering for npm/node/pip/cargo parent processes.

- [ ] **Step 2:** Extend the collector's proto conversion to recognize Override action events from `bprm_check_security` as `EventKind::ScriptExec` with a `paused: true` flag.

- [ ] **Step 3:** Write test: verify Override events are parsed and flagged correctly.

- [ ] **Step 4:** Commit.

---

### Task 22: Gate Analyzer

**Files:**
- Modify: `skills/gate-analyzer.yaml` (full implementation)
- Create: `crates/watchpost-analyzer/src/gate.rs`

- [ ] **Step 1:** Write `gate-analyzer.yaml` skill spec focused on pre-execution script analysis (receives script content, not kernel traces).

- [ ] **Step 2:** Implement `GateAnalyzer` that: reads script content from the binary path, sends to LLM with package context and behavior profile, receives allow/block verdict.

- [ ] **Step 3:** Implement gate allowlist (SQLite table: package + script SHA256 hash -> allow/block). Check allowlist before LLM call.

- [ ] **Step 4:** Implement gate fallback for LLM failure: allow known-good packages, block unknown packages with suspicious patterns (base64, curl|sh).

- [ ] **Step 5:** Write tests: mock script content analysis, allowlist cache hit, fallback on timeout.

- [ ] **Step 6:** Commit.

---

### Task 23: Policy Manager Crate

**Files:**
- Modify: `crates/watchpost-policy/Cargo.toml`
- Create: `crates/watchpost-policy/src/allowlist.rs`
- Create: `crates/watchpost-policy/src/staged.rs`
- Create: `crates/watchpost-policy/src/generator.rs`
- Create: `crates/watchpost-policy/src/reconciler.rs`
- Modify: `crates/watchpost-policy/src/lib.rs`

- [ ] **Step 1:** Implement `AllowlistStore` (SQLite CRUD for dynamic allowlist entries).

- [ ] **Step 2:** Implement `StagedPolicyManager` (staging directory, approve/revoke workflow).

- [ ] **Step 3:** Implement `TracingPolicyGenerator` (construct valid Tetragon YAML from structured data).

- [ ] **Step 4:** Implement `PolicyReconciler` (compare desired vs actual state via Tetragon gRPC `ListTracingPolicies`, apply diffs with `AddTracingPolicy`/`DeleteTracingPolicy`).

- [ ] **Step 5:** Write tests for each component. Integration test: reconcile with real Tetragon.

- [ ] **Step 6:** Commit.

---

### Task 24: Package Provenance Enrichment

**Files:**
- Modify: `crates/watchpost-collector/src/context.rs`
- Create: `crates/watchpost-collector/src/provenance.rs`

- [ ] **Step 1:** Implement async registry lookups: npm registry API for package age, download count, publish date. Cache results (LRU, 1024 entries, 1-hour TTL).

- [ ] **Step 2:** Implement `npm audit` / `cargo audit` known vulnerability check.

- [ ] **Step 3:** Implement typosquatting detection (Levenshtein distance <= 2 from top-1000 package names). Add `strsim` dependency.

- [ ] **Step 4:** Implement Sigstore/npm provenance attestation check.

- [ ] **Step 5:** Add provenance indicators to the scoring function (new weights from spec).

- [ ] **Step 6:** Write tests for each provenance signal.

- [ ] **Step 7:** Commit.

---

### Task 25: User Feedback Loop

**Files:**
- Modify: `crates/watchpost-notify/src/dbus.rs` (handle Undo action)
- Modify: `crates/watchpost-engine/src/scoring.rs` (weight adjustment)

- [ ] **Step 1:** Implement Undo handling: when user clicks "Undo", add pattern to allowlist, record as false positive.

- [ ] **Step 2:** Implement weight adjustment: load `weight_overrides.toml` on startup, recompute after every 50 overrides. Reduce weights of frequently-overridden indicators over 30-day window.

- [ ] **Step 3:** Implement autonomous threshold auto-adjustment: >3 overrides/week raises threshold; 0 overrides for 30 days lowers it.

- [ ] **Step 4:** Write tests for weight adjustment logic.

- [ ] **Step 5:** Commit.

---

### Task 26: Persistent Correlation Window

**Files:**
- Modify: `crates/watchpost-engine/src/windows.rs`
- Modify: `crates/watchpost-engine/src/correlation.rs`

- [ ] **Step 1:** Implement 24-hour persistent window backed by SQLite. Store trigger metadata + correlated event IDs.

- [ ] **Step 2:** On daemon startup: reload persistent windows from SQLite. On new events: check persistent window for delayed-execution correlations.

- [ ] **Step 3:** Write tests: trigger registered, daemon restarts, delayed event correlated with weak signal.

- [ ] **Step 4:** Commit.

---

### Task 27: Ollama Local LLM Backend

**Files:**
- Create: `crates/watchpost-analyzer/src/ollama.rs`
- Modify: `crates/watchpost-analyzer/src/agent_loop.rs` (backend abstraction)

- [ ] **Step 1:** Implement `OllamaClient` using `/api/chat` endpoint at `http://127.0.0.1:11434`. Support `format: "json"` for structured output.

- [ ] **Step 2:** Create `LlmBackend` trait with `send_message()`. Implement for both `AnthropicClient` and `OllamaClient`. Update agent loop to use trait.

- [ ] **Step 3:** Implement context truncation for small-context models (truncate to 20 most suspicious events if exceeding 4K tokens).

- [ ] **Step 4:** Implement fallback for malformed Ollama JSON responses (retry once, then fall back to heuristic score).

- [ ] **Step 5:** Write tests with mock Ollama responses.

- [ ] **Step 6:** Commit.

---

### Task 28: Analyzer Tools - lookup_package + lookup_ip

**Files:**
- Modify: `crates/watchpost-analyzer/src/tools.rs`

- [ ] **Step 1:** Implement `lookup_package`: query npm/PyPI/crates.io registry API, return metadata.

- [ ] **Step 2:** Implement `lookup_ip`: query AbuseIPDB or local threat intelligence cache, return reputation.

- [ ] **Step 3:** Write tests with mock HTTP responses.

- [ ] **Step 4:** Commit.

---

### Task 29: Developer Toolchain TracingPolicies

**Files:**
- Create: `policies/npm-monitoring.yaml`
- Create: `policies/cargo-monitoring.yaml`
- Create: `policies/pip-monitoring.yaml`

- [ ] **Step 1:** Write npm-monitoring.yaml: `tcp_connect` kprobe + `security_file_permission` LSM for node/npm/yarn/pnpm processes.

- [ ] **Step 2:** Write cargo-monitoring.yaml: same structure for cargo/rustc/cc/ld.

- [ ] **Step 3:** Write pip-monitoring.yaml: same structure for pip/python/gcc.

- [ ] **Step 4:** Update `watchpost init` to detect which toolchains are installed and only install relevant policies.

- [ ] **Step 5:** Commit.

---

### Task 30: Policy + Allowlist CLI Subcommands

**Files:**
- Modify: `src/cli.rs`
- Modify: `src/main.rs`

- [ ] **Step 1:** Add `policy list`, `policy approve`, `policy revoke`, `policy show` subcommands.

- [ ] **Step 2:** Add `allowlist list`, `allowlist remove`, `allowlist reset` subcommands.

- [ ] **Step 3:** Add `gate allow`, `gate block` subcommands.

- [ ] **Step 4:** Write CLI parsing tests.

- [ ] **Step 5:** Commit.

---

### Task 31: Phase 2 Integration Test

**Files:**
- Modify: `tests/integration/pipeline_test.rs`

- [ ] **Step 1:** Test: malicious postinstall script blocked before execution via gate.

- [ ] **Step 2:** Test: click "Undo" -> pattern allowlisted -> same pattern allowed next time.

- [ ] **Step 3:** Test: dynamic allowlist grows after repeated benign observations.

- [ ] **Step 4:** Commit.

---

## Phase 3: Advanced Features

Phase 3 adds the TUI dashboard, Flatpak monitoring, advanced network detection, and optional integrations.

**Phase 3 exit criteria:** TUI dashboard shows live events. Flatpak sandbox escape is detected. Reverse shell pattern triggers immediate kill.

---

### Task 32: TUI Dashboard

**Files:**
- Create: `crates/watchpost-tui/` (new crate)
- Modify: `Cargo.toml` (add to workspace)
- Modify: `src/cli.rs` (add `tui` subcommand)

- [ ] **Step 1:** Create `watchpost-tui` crate with `ratatui` and `crossterm` dependencies.

- [ ] **Step 2:** Implement 4-panel layout: live event stream (top-left), process tree (top-right), policy status (bottom-left), analysis queue (bottom-right).

- [ ] **Step 3:** Connect to running daemon via Unix socket (JSON lines IPC protocol).

- [ ] **Step 4:** Implement keyboard navigation: tab between panels, j/k scroll, q quit, / filter.

- [ ] **Step 5:** Write rendering tests with mock data.

- [ ] **Step 6:** Commit.

---

### Task 33: Flatpak Sandbox Escape Detection

**Files:**
- Create: `policies/flatpak-escape.yaml`
- Modify: `crates/watchpost-collector/src/context.rs`
- Create: `crates/watchpost-collector/src/flatpak.rs`

- [ ] **Step 1:** Write `flatpak-escape.yaml` using `matchNamespaceChanges` and `matchBinaries` for bwrap/app binaries.

- [ ] **Step 2:** Implement Flatpak metadata reader: parse app metadata for declared permissions.

- [ ] **Step 3:** Implement cgroup-based Flatpak app ID extraction from `/proc/PID/cgroup`.

- [ ] **Step 4:** Add Flatpak profile and rule: compare actual file access against declared permissions.

- [ ] **Step 5:** Write test: Flatpak app accesses undeclared host path -> detected.

- [ ] **Step 6:** Commit.

---

### Task 34: Network Detection Policies

**Files:**
- Create: `policies/reverse-shell.yaml`
- Create: `policies/dns-exfil.yaml`
- Create: `policies/crypto-miner.yaml`
- Modify: `crates/watchpost-engine/src/scoring.rs` (Shannon entropy)

- [ ] **Step 1:** Write `reverse-shell.yaml`: kprobes on `tcp_connect` + `dup2`/`dup3` for fd 0,1,2 redirection.

- [ ] **Step 2:** Write `dns-exfil.yaml`: monitor `sys_sendto` on UDP port 53 from dev tool children.

- [ ] **Step 3:** Write `crypto-miner.yaml`: `tcp_connect` to Stratum ports with `Sigkill` action.

- [ ] **Step 4:** Implement Shannon entropy calculation for DNS query names (~10 lines, manual implementation).

- [ ] **Step 5:** Write tests: reverse shell pattern detection, high-entropy DNS query detection.

- [ ] **Step 6:** Commit.

---

### Task 35: Webhook Forwarding

**Files:**
- Create: `crates/watchpost-notify/src/webhook.rs`
- Modify: `crates/watchpost-notify/src/lib.rs`

- [ ] **Step 1:** Implement `WebhookForwarder`: POST JSON verdicts to configured URL with optional auth header.

- [ ] **Step 2:** Wire into notifier: forward every verdict if webhook_url is configured.

- [ ] **Step 3:** Write test with mock HTTP server.

- [ ] **Step 4:** Commit.

---

### Task 36: Policy Templates

**Files:**
- Create: `templates/` directory with shareable YAML bundles

- [ ] **Step 1:** Create template bundles: `web-developer.yaml`, `systems-developer.yaml`, `minimal.yaml`.

- [ ] **Step 2:** Add `watchpost init --template` support.

- [ ] **Step 3:** Commit.

---

### Task 37: Phase 3 Integration Test

**Files:**
- Modify: `tests/integration/pipeline_test.rs`

- [ ] **Step 1:** Test: TUI connects to daemon and renders events.

- [ ] **Step 2:** Test: Flatpak escape detected with correct app ID.

- [ ] **Step 3:** Test: reverse shell pattern triggers immediate kill.

- [ ] **Step 4:** Test: webhook receives JSON verdict payload.

- [ ] **Step 5:** Final full-system integration test.

- [ ] **Step 6:** Commit.
