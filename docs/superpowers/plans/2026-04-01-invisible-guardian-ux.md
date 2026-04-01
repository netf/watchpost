# Invisible Guardian UX Refinement — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Apply the Invisible Guardian UX design to PROJECT.md — transforming it from a technically correct architecture doc into one that leads with zero-friction developer experience.

**Architecture:** Surgical edits to 7 sections of the existing PROJECT.md. No new files created except the spec already written. All changes are to a single markdown file.

**Tech Stack:** Markdown editing. Verification via grep.

---

### Task 1: Rewrite Section 2.1 Design Principles

**Files:**
- Modify: `PROJECT.md:65-83`

- [ ] **Step 1: Replace the design principles section**

Replace the current Section 2.1 (lines 65-83) with the invisible guardian principles leading, followed by the existing technical principles restructured underneath.

Old text starts with: `### 2.1 Design Principles`
Old text ends with: the line before `---` (line 83)

New text:

```markdown
### 2.1 Design Principles

**The best security is the kind you forget is there.** Watchpost is an invisible guardian. A developer working normally sees zero notifications per day. The system silently classifies thousands of kernel events per minute, allows legitimate work, and blocks threats — all without interrupting flow. The only time the developer sees Watchpost is when something genuinely dangerous happened and was stopped. If the system generates more than 2-3 notifications per week during normal development, that is a bug in the profiles or thresholds, not expected behavior.

**Smart from minute one.** No calibration period. No advisory-first learning phase. Watchpost ships with curated behavior profiles that cover 95% of developer workflows on first install — including known-good patterns for the top 1000 npm packages, common cargo/pip build patterns, and all standard toolchains. The system still learns and refines from the user's specific environment, but it starts smart, not blank.

**One command to protect.** `watchpost init` takes an API key, auto-detects installed toolchains, and starts monitoring. No config files to write, no YAML to edit, no services to enable manually. Power users can customize everything; everyone else never touches a config file.

**Tetragon does the kernel work; Watchpost does the thinking.** We deliberately avoid writing any custom eBPF programs. Tetragon is maintained by the Cilium team, many of whom are kernel developers. Their TracingPolicies are declarative YAML files that specify which kprobes, tracepoints, and LSM hooks to instrument. Watchpost generates, manages, and hot-reloads these YAML files. This means zero eBPF C code to maintain, automatic compatibility with kernel upgrades (Tetragon handles CO-RE/BTF), and the ability to focus entirely on the intelligence layer.

**Two-tier classification: fast deterministic rules, slow semantic analysis.** Every correlated event trace first passes through a heuristic scoring function. High-scoring traces (obvious threats like binary execution from `/tmp` by an npm postinstall script) go to the deterministic rule engine, which matches patterns and returns verdicts in microseconds. Ambiguous traces (score above a minimum threshold but not matching any rule) are queued for LLM analysis. Low-scoring traces are simply logged. This means the common case (benign developer activity) generates zero LLM calls, and obvious attacks are caught instantly without waiting for inference.

**Remote-first LLM inference.** Watchpost defaults to the Anthropic API using Claude Haiku 4.5 (model ID: `claude-haiku-4-5-20251001`) for semantic analysis. At $1/$5 per million input/output tokens and with the rate limiter keeping analyses to ~10/minute, the cost for a typical desktop session is negligible. Anthropic's structured output support (GA via `output_config.format` parameter) guarantees schema-validated JSON responses without retry logic. A local Ollama backend is available as an alternative for offline or air-gapped environments, or for users who prefer not to send security telemetry to external APIs.

**The LLM understands valid kernel behavior and acts on it.** Every action context (package install, build, Flatpak launch, shell command) has an expected behavior profile — a set of kernel operations that are consistent with the stated purpose. `npm install express` *should* make network connections to registry.npmjs.org and write to `node_modules/`. It *should not* read `~/.ssh/`, connect to unknown IPs, or execute binaries from `/tmp`. The LLM evaluates each observed kernel action against the behavior profile and acts autonomously: blocking forbidden behavior immediately (SIGKILL), allowing expected behavior silently, and reasoning about unspecified behavior before deciding.

**Analyze before execution, not just after.** For the highest-risk operation class — package install scripts — Watchpost intercepts script execution using Tetragon's `bprm_check_security` LSM hook with `Override` action to pause execution, reads the script content, sends it to the LLM for pre-execution analysis, and autonomously allows or blocks based on the verdict. This shifts the architecture from reactive ("detect and alert after damage") to proactive ("analyze and gate before execution"). The ~200ms latency for Haiku analysis is invisible in the context of package install operations that take seconds to minutes.

**The LLM is an agent, not an oracle.** Rather than single-shot prompt → verdict, the analyzer operates as a tool-using agent that can request additional context: read files, query the process tree, check package registries, or look up IP reputation. This dramatically improves analysis quality for ambiguous cases — the LLM can follow its reasoning ("this process connected to 185.x.x.x — let me check if the package.json declares that as a registry") instead of being limited to whatever context was pre-assembled in the prompt.

**User overrides refine the model silently.** When Watchpost blocks a process and the user clicks "Undo", the pattern is permanently allowlisted and the scoring weights adjust — all without further notifications. Over time, the system converges on the user's specific development patterns. If the user overrides too often (>3 times per week), the system automatically becomes more conservative about blocking. This learning is entirely invisible — no "threshold adjusted" notifications, no "allowlist proposal" popups.

**Desktop-native, not server-oriented.** The event log is a local SQLite database. The optional TUI dashboard uses ratatui. The daemon is designed for a single user's workstation, not a fleet of servers.
```

- [ ] **Step 2: Verify the edit**

Run: `grep -n "The best security" PROJECT.md`
Expected: Match on the new first principle line.

Run: `grep -n "Allow / Block / Investigate" PROJECT.md`
Expected: No matches (old notification button text removed from principles).

- [ ] **Step 3: Commit**

```bash
git add PROJECT.md
git commit -m "docs: rewrite design principles with invisible guardian UX lead"
```

---

### Task 2: Update Behavior Profiles to Three-Tier Model with Shipped Ecosystem Data

**Files:**
- Modify: `PROJECT.md:232-242` (behavior profiles in Section 4.3)

- [ ] **Step 1: Replace the behavior profiles section**

Replace the current "Action behavior profiles" block (starting at line 232 "**Action behavior profiles.**" through line 242 ending with "...its general security knowledge alone.") with the three-tier model and shipped ecosystem data.

Old text starts with: `**Action behavior profiles.** The engine maintains`
Old text ends with: `This grounds the LLM's reasoning in concrete expectations rather than relying on its general security knowledge alone.`

New text:

```markdown
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

Profiles are defined in YAML files shipped with Watchpost (`profiles/`) and are extensible by the user (`/etc/watchpost/profiles.d/`). The dynamic allowlist extends profiles at runtime — when a user clicks "Undo" on a blocked pattern, it is added to the corresponding profile's expected behavior. When the LLM analyzer evaluates a trace, the relevant behavior profile is included in its context, grounding its reasoning in concrete expectations rather than relying on general security knowledge alone.
```

- [ ] **Step 2: Remove the calibration period reference**

Find and replace the line (around line 230):
`The thresholds are configurable. In the early learning period, a user might lower the LLM threshold to 0.2 to get more analysis coverage at the cost of more LLM calls.`

Replace with:
`The thresholds are configurable but the shipped defaults work well for most environments thanks to the curated behavior profiles.`

- [ ] **Step 3: Verify**

Run: `grep -n "calibration" PROJECT.md`
Expected: No matches.

Run: `grep -n "three-tier" PROJECT.md`
Expected: Match in the new profiles section.

- [ ] **Step 4: Commit**

```bash
git add PROJECT.md
git commit -m "docs: add three-tier behavior profiles with shipped ecosystem data"
```

---

### Task 3: Rewrite Notification Section (4.8)

**Files:**
- Modify: `PROJECT.md:369-397` (Section 4.8)

- [ ] **Step 1: Replace the entire notification and feedback section**

Replace from `### 4.8 Stage 6: Notification and Logging` through the line before `**Event log**` (keeping Event log, Webhook paragraphs intact).

Old text starts with: `### 4.8 Stage 6: Notification and Logging`
Old text ends with: `This creates a closed learning loop: the system starts with conservative defaults, makes autonomous decisions, and progressively refines its accuracy based on the user's corrections — converging on a state where overrides become rare.`

New text:

```markdown
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
```

- [ ] **Step 2: Verify**

Run: `grep -n "Allowed with warning" PROJECT.md`
Expected: No matches (removed notification type).

Run: `grep -n "Accelerated allowlisting" PROJECT.md`
Expected: No matches (removed visible mechanism).

Run: `grep -n "Two notification types only" PROJECT.md`
Expected: One match in Section 4.8.

- [ ] **Step 3: Commit**

```bash
git add PROJECT.md
git commit -m "docs: simplify notifications to two types only for invisible guardian UX"
```

---

### Task 4: Simplify Configuration (Section 7)

**Files:**
- Modify: `PROJECT.md:475-501` (Section 7)

- [ ] **Step 1: Replace the configuration section**

Replace from `## 7. Configuration` through `**[notify]**:` line (keeping the `---` separator).

Old text starts with: `## 7. Configuration`
Old text ends with: `**[notify]**: Desktop notifications enabled (default: true), webhook URL (optional), webhook authentication header (optional).`

New text:

```markdown
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
```

- [ ] **Step 2: Verify**

Run: `grep -n "\[collector\]" PROJECT.md`
Expected: Only matches under `[advanced.collector]`, not as a top-level section.

Run: `grep -c "strict" PROJECT.md`
Expected: Zero matches for strict mode in config (may still appear in other sections — we'll clean those up in Task 6).

- [ ] **Step 3: Commit**

```bash
git add PROJECT.md
git commit -m "docs: simplify config to one-line setup with advanced section"
```

---

### Task 5: Add `watchpost init` and Reorder CLI (Section 8)

**Files:**
- Modify: `PROJECT.md:505-530` (Section 8)

- [ ] **Step 1: Add `watchpost init` at the top of the CLI section and reorder**

Replace from `## 8. CLI Interface` through `**\`watchpost tui\`**` line.

Old text starts with: `## 8. CLI Interface`
Old text ends with: `**\`watchpost tui\`** (phase 2): Launch the terminal UI dashboard. Connects to the running daemon via a local Unix socket and displays live event stream, process tree, policy status, and analysis queue.`

New text:

```markdown
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
```

- [ ] **Step 2: Verify**

Run: `grep -n "watchpost init" PROJECT.md`
Expected: Matches in Section 8 (CLI) and Section 2.1 (design principles).

- [ ] **Step 3: Commit**

```bash
git add PROJECT.md
git commit -m "docs: add watchpost init command and reorder CLI section"
```

---

### Task 6: Update Rationale and Clean Up Stale References (Section 11 + throughout)

**Files:**
- Modify: `PROJECT.md` — Section 11 rationale + global cleanup

- [ ] **Step 1: Replace the enforcement rationale in Section 11**

Find the block starting with `**Why autonomous enforcement with behavior profiles instead of human-in-the-loop?**` and replace it.

Old text starts with: `**Why autonomous enforcement with behavior profiles instead of human-in-the-loop?**`
Old text ends with: `...while killing a running process mid-build can corrupt state.`

New text:

```markdown
**Why the invisible guardian model?**
Security tools that require developer attention get ignored. Alert fatigue, reflexive "Allow" clicking, and notification blindness render human-in-the-loop security worse than useless — it provides false confidence. Watchpost operates as an invisible guardian: it makes autonomous decisions grounded in curated behavior profiles and LLM reasoning, and only surfaces to the developer when something genuinely dangerous was blocked. The risk of false positives is mitigated by three mechanisms: (1) comprehensive shipped profiles that cover 95% of workflows from day one, (2) "Undo" buttons on every block notification for immediate correction, and (3) a silent self-adjusting feedback loop that makes the system more conservative if the user overrides frequently. The pre-execution gate is fail-closed (block on uncertainty, since the script hasn't run yet and there's no state to corrupt), while runtime enforcement blocks only high-confidence threats (SIGKILL) and silently allows low-confidence ambiguous traces.

**Why ship curated profiles instead of learning from scratch?**
A learning-from-scratch model means the first week of use is either unprotected (advisory mode) or riddled with false positives (aggressive blocking of unknown patterns). Neither is acceptable. By researching and curating known-good patterns for the top package ecosystems, Watchpost works correctly from first install. The dynamic learning system refines these profiles over time, but it starts from a strong baseline, not a blank slate. This is the same approach antivirus vendors use with signature databases — ship comprehensive defaults, update incrementally.
```

- [ ] **Step 2: Remove "Why user feedback as a scoring signal?" rationale**

This rationale still applies but its content is now covered by the invisible guardian rationale. Find and replace:

Old text starts with: `**Why user feedback as a scoring signal?**`
Old text ends with: `...but large enough for simple weight adjustment.`

New text:

```markdown
**Why silent user feedback instead of explicit tuning?**
Static indicator weights are a compromise between different development environments. Rather than requiring manual weight tuning or showing "threshold adjusted" notifications, Watchpost silently tracks which blocks get overridden ("Undo") and adjusts weights over a 30-day rolling window. The developer never sees this learning — they just notice that false positives stop recurring. The statistical sample from a single desktop is too small for ML, but large enough for simple weight adjustment.
```

- [ ] **Step 3: Global cleanup — remove stale references**

Search and fix these stale patterns throughout the document:

1. Find `strict` in enforcement context and remove. Specifically in line ~314 (`- **Strict mode**: All ambiguous traces...`), remove that bullet and the preceding line about advisory mode being for "notification-only":

   Replace the verdict execution block (lines ~311-316):
   Old: The three enforcement modes (Autonomous, Advisory, Strict)
   New: Two enforcement modes only (Autonomous default, Advisory optional)

2. Find any remaining `SIGSTOP` references and replace with `SIGKILL`.

3. Find `threshold notifications` or `allowlist proposal` notification references and remove.

4. In Section 4.8 notification types within the enforcement mode types (around line ~407), update to remove references to `Strict` from the types crate description.

- [ ] **Step 4: Verify cleanup**

Run: `grep -in "strict mode" PROJECT.md`
Expected: No matches.

Run: `grep -in "sigstop" PROJECT.md`
Expected: No matches.

Run: `grep -in "calibration" PROJECT.md`
Expected: No matches.

Run: `grep -in "advisory-first\|advisory as default" PROJECT.md`
Expected: No matches.

Run: `grep -in "Allowed with warning\|allowlist proposal\|threshold.*notif" PROJECT.md`
Expected: No matches.

- [ ] **Step 5: Commit**

```bash
git add PROJECT.md
git commit -m "docs: update rationale for invisible guardian, remove stale strict/SIGSTOP/calibration references"
```

---

### Task 7: Update Types Crate and Phase Descriptions

**Files:**
- Modify: `PROJECT.md` — Section 5.1 (types crate), Section 10 (phases)

- [ ] **Step 1: Update types crate to remove Strict mode**

Find the types crate description (Section 5.1) containing `enforcement mode types (Autonomous, Advisory, Strict)`.

Replace `enforcement mode types (Autonomous, Advisory, Strict)` with `enforcement mode types (Autonomous, Advisory)`.

- [ ] **Step 2: Update Phase 1 to include `watchpost init`**

In Section 10, Phase 1 deliverables, add `watchpost init` to the binary crate line.

Find: `- \`watchpost\` binary crate: \`daemon\` and \`events\` subcommands`
Replace with: `- \`watchpost\` binary crate: \`init\`, \`daemon\`, \`status\`, and \`events\` subcommands`

- [ ] **Step 3: Update Phase 1 to mention shipped profiles**

In the Phase 1 deliverables, after the TracingPolicies line, add:
`- Curated behavior profiles for npm, cargo, pip ecosystems (profiles/ directory)`

- [ ] **Step 4: Move TUI to Phase 3**

Verify the TUI reference in the CLI section says "(phase 3)" not "(phase 2)". If it says phase 2, update to phase 3.

- [ ] **Step 5: Verify**

Run: `grep -n "Strict" PROJECT.md`
Expected: No matches in types or enforcement sections (may appear in unrelated contexts — check manually).

Run: `grep -n "watchpost init" PROJECT.md`
Expected: Matches in Section 2.1, Section 8, and Section 10 Phase 1.

- [ ] **Step 6: Commit**

```bash
git add PROJECT.md
git commit -m "docs: update types, phases, and CLI references for invisible guardian UX"
```

---

### Task 8: Final Verification Pass

**Files:**
- Read: `PROJECT.md` (full document)

- [ ] **Step 1: Read the full document end-to-end**

Read PROJECT.md from top to bottom. Check for:
- Internal contradictions between sections
- Stale references to removed concepts (strict mode, SIGSTOP, calibration period, 5 notification types, advisory-as-default)
- Section numbering consistency
- Principle hierarchy consistency (invisible guardian leads everywhere)

- [ ] **Step 2: Fix any issues found**

Apply surgical fixes for any inconsistencies discovered in Step 1.

- [ ] **Step 3: Final verification greps**

Run all of these:
```bash
grep -in "strict mode\|strict enforcement" PROJECT.md
grep -in "sigstop\|sig_stop\|freeze.*process" PROJECT.md
grep -in "calibration period\|learning period\|advisory-first" PROJECT.md
grep -in "Allowed with warning\|allowlist proposal\|threshold.*notification" PROJECT.md
grep -in "Allow / Block / Investigate" PROJECT.md
grep -c "invisible guardian\|zero notification\|smart from minute" PROJECT.md
```

Expected: First 5 greps return no matches. Last grep returns ≥3 matches (principles appear in multiple sections).

- [ ] **Step 4: Commit final cleanup**

```bash
git add PROJECT.md
git commit -m "docs: final consistency pass for invisible guardian UX refinement"
```
