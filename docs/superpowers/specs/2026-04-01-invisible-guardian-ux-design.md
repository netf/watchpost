# Invisible Guardian UX Design

## Context

Watchpost is an eBPF-powered desktop security agent (see PROJECT.md for full architecture). This spec defines the UX refinement that transforms Watchpost from a technically correct security tool into an invisible guardian — security that developers forget is running.

The core problem: security tools that require developer attention get ignored. Alert fatigue, reflexive "Allow" clicking, and notification blindness render human-in-the-loop security worse than useless — it provides false confidence. Watchpost must protect autonomously and silently, surfacing to the developer only when something genuinely dangerous was stopped.

## Design Principles

These replace the current Section 2.1 principle ordering. The technical principles (Tetragon delegation, two-tier classification, etc.) become implementation details under these UX principles.

### 1. "The best security is the kind you forget is there."

A developer working normally sees zero notifications per day. Watchpost silently classifies thousands of kernel events per minute, allows legitimate work, and blocks threats. The only time the developer sees Watchpost is when something dangerous happened and was stopped.

If the system generates more than 2-3 notifications per week during normal development, that is a bug in the profiles or thresholds, not expected behavior.

### 2. "Smart from minute one."

No calibration period. No advisory-first learning phase. Watchpost ships with curated behavior profiles that cover 95% of developer workflows on day one. The system still learns and refines from the user's specific environment, but it starts smart, not blank.

### 3. "One command to protect."

`watchpost init` takes an API key, auto-detects toolchains, and starts monitoring. No config files to write, no YAML to edit, no services to enable manually.

## Shipped Smart Defaults

### Curated Ecosystem Profiles

Watchpost ships behavior profiles in `profiles/` that define expected, unspecified, and forbidden kernel behavior for each action context:

**npm.yaml**: Known-good patterns for top 1000 npm packages. Includes:
- registry.npmjs.org + common CDN IPs (github.com release assets, unpkg, jsdelivr) as expected network destinations
- `node`, `sh`, `node-gyp`, `make`, `cc`, `python3` as expected native build children
- Common legitimate postinstall patterns: husky git hooks setup, esbuild/sharp/node-sass binary downloads from known CDN hosts
- Pre-allowlisted download hosts for packages that legitimately fetch platform binaries

**cargo.yaml**: `rustc`, `cc`, `ld`, `ar`, `as` as expected children. `crates.io` + known mirrors as expected network. `target/` as expected write path. `build.rs` execution as expected behavior.

**pip.yaml**: `pypi.org` + known mirrors. `gcc`, `g++`, `python3`, `cmake` as expected children for C extensions. `site-packages/` as expected write path.

**flatpak.yaml**: Expected portal D-Bus interfaces, declared permission patterns, standard runtime paths (`/app/`, `/usr/` within sandbox).

**system.yaml**: Known-good privilege escalation paths (sudo, pkexec, polkit, systemd), known-good `/etc/passwd` readers, standard cron/systemd-timer patterns.

### Three-Tier Behavior Classification

Each behavior observed at runtime falls into one of three categories:

1. **Expected** — Matches a pattern in the profile. Silently allowed. No scoring, no LLM call. Example: `npm install` → `node-gyp` → `make` → `cc`.

2. **Unspecified** — Not in the profile as expected or forbidden. Scored normally and routed to the LLM if ambiguous. The LLM reasons about it using the behavior profile as context. Example: a build tool shelling out to `python3` — unusual but not malicious.

3. **Forbidden** — Explicitly banned in the profile. Always blocked immediately, no LLM call needed. Example: `setuid` from any package manager context, reading `~/.ssh/` during `npm install`, executing binaries from `/tmp`.

This replaces the binary expected/unexpected model and eliminates the need for a calibration period.

## One-Command Setup

### `watchpost init`

```
$ watchpost init
  Anthropic API key: sk-ant-...
  ✓ Detected toolchains: npm, cargo, pip
  ✓ Config written to /etc/watchpost/config.toml
  ✓ Tetragon policies installed (5 base + 3 toolchain)
  ✓ Systemd service enabled and started
  ✓ Watchpost is now protecting your system
```

Steps performed by `init`:
1. Prompt for API key (or read `ANTHROPIC_API_KEY` from environment)
2. Scan `$PATH` for package managers (npm, yarn, pnpm, cargo, pip, pip3, uv, flatpak) and enable corresponding toolchain policies
3. Detect toolbox/distrobox container environment and adjust container awareness
4. Write minimal config file (just the API key + detected toolchains)
5. Copy TracingPolicies to Tetragon's policy directory
6. Enable and start the systemd service
7. Run health check: connect to Tetragon gRPC, verify policies loaded, test API key validity

### Simplified Configuration

Generated config for normal users:

```toml
[daemon]
api_key = "sk-ant-..."
```

Everything else has smart defaults. The full config surface exists for power users as `[advanced]`:

- `[daemon]` — API key, log level (default: warn), data directory (default: /var/lib/watchpost)
- `[enforcement]` — mode (default: autonomous). Advisory mode available as override.
- `[notify]` — enabled (default: true), webhook URL (optional)
- `[advanced]` — correlation windows, score thresholds, rate limits, Tetragon socket path, Ollama config, per-toolchain enforcement overrides. All documented with defaults, never needed by normal users.

## Notification Philosophy

### Two Notification Types Only

**1. Blocked** — Shown when Watchpost killed a process.

```
🔒 Blocked: npm postinstall for evil-pkg@0.1.0
   Attempted to read ~/.ssh/id_rsa
   [Undo]  [Details]
```

- "Undo" adds the pattern to the permanent allowlist so it won't be blocked next time, and records it as a false positive for weight adjustment. The killed process is not resurrected — the developer re-runs the command (e.g., `npm install` again). For the pre-execution gate, since the parent process (npm) is usually still alive, the re-run happens naturally.
- "Details" opens TUI dashboard or outputs full correlated trace

**2. Threat Detected** — Shown for unambiguously malicious behavior caught by deterministic rules (reverse shell, cryptominer, immutability violation).

```
🚨 Threat: Reverse shell detected
   npm → node → sh → nc 185.x.x.x:4444
   Process killed.  [Details]
```

No "Undo" — these are always-malicious patterns. Only "Details".

### What Is NOT a Notification

- Benign verdicts (silent, logged only)
- Low-confidence allows (silent, logged for CLI review)
- Allowlist updates (automatic, silent)
- Threshold adjustments (automatic, silent)
- Profile extensions from user feedback (automatic, silent)

### Volume Target

Zero notifications per day during normal development. At most one notification when installing a novel package with genuinely unusual behavior.

## Enforcement Model

### SIGKILL, Not SIGSTOP

When Watchpost blocks, it kills. Simple, decisive. The risk of state corruption on false positives is accepted — the "Undo" + re-run path handles recovery.

### Three Enforcement Contexts

| Context | Mechanism | On block | On allow |
|---|---|---|---|
| Pre-execution gate | Tetragon `Override` pauses before execution, LLM analyzes, then allow or SIGKILL | Process never started, zero state corruption | Execution proceeds normally |
| Runtime (high confidence) | Watchpost sends SIGKILL | Process killed, "Blocked" notification with Undo | Silent, logged only |
| Runtime (low confidence) | Silent allow | N/A | Logged for CLI review |

The pre-execution gate is the primary enforcement surface because it has zero blast radius — the script hasn't started, so killing it corrupts nothing. Runtime SIGKILL is the fallback for behavior that deviates after execution begins.

### Removed Concepts

- **Strict mode** — removed. Contradicts invisible guardian (too many false positives on day one).
- **Advisory mode as default** — still exists as `enforcement.mode = "advisory"` in advanced config for users who want notification-only.
- **`autonomous_threshold` as user-facing config** — still exists internally (default 0.85, self-adjusts), never exposed in normal config.
- **Per-context enforcement overrides** — moved to `[advanced]`.

## Feedback Loop

Simplified from 5 mechanisms to 2 visible behaviors:

1. **Undo → allowlist + silent weight adjustment.** User clicks "Undo" on a blocked notification. The pattern is allowlisted, indicator weights adjust, behavior profile extends. All silent.

2. **Auto-conservative on frequent overrides.** If >3 Undos in a week, the internal autonomous threshold auto-raises (system gets more conservative about blocking). If no Undos for 30 days, threshold auto-lowers. Never surfaced as a notification.

All other learning (profile extension, weight persistence, per-indicator tracking) happens identically to the current design but never surfaces to the user.

## Changes to PROJECT.md

Surgical edits to the existing document:

1. **Section 2.1** — Rewrite design principles with invisible guardian as lead. Move technical principles under new UX principles.
2. **Section 4.2** — Add shipped smart defaults concept. Document three-tier (expected/unspecified/forbidden) profile classification.
3. **Section 4.3** — Replace "calibration period" references. Update behavior profiles to include the three-tier model and shipped ecosystem data.
4. **Section 4.8** — Rewrite notification section: two types only, volume target, simplified feedback loop.
5. **Section 7** — Simplify config: minimal default, `[advanced]` for everything else. Remove strict mode from enforcement options.
6. **Section 8** — Add `watchpost init` command. Reorder CLI to lead with `init`.
7. **Section 11** — Add rationale for invisible guardian philosophy and smart defaults. Remove "loosens only" and calibration rationale.
8. **Throughout** — Remove references to SIGSTOP, advisory-as-default, strict mode, calibration period, threshold notifications, allowlist proposal notifications.
