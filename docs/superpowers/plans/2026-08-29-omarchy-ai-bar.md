# Omarchy AI Bar Implementation Plan

**Design:** `docs/superpowers/specs/2026-08-29-omarchy-ai-bar-design.md`
**Baseline:** CodexBar `1680b4ed5`
**Target:** One Rust runtime executable plus an Omarchy/Quickshell QML frontend
**Release rule:** No completed-release claim until every applicable provider and feature parity record passes

## Goal

Build `omarchy-ai-bar`, an Omarchy-native full port of the applicable CodexBar baseline: 69 first-party providers,
multi-account quota/cost/status/session behavior, complete CLI and local server, a sandboxed user-provider runtime, and a
CodexBar-style QML bar/popup/settings experience.

## Execution Contract

1. Work in the numbered dependency order unless a task explicitly names a safe parallel lane.
2. For every behavior, write the focused test first, run it and observe the expected failure, implement the smallest
   behavior, rerun the focused test, then run the task gate.
3. Commit after each task is green. Within provider batches, commit the shared adapter separately and then commit each
   provider independently.
4. Never run live provider probes by default. Use copied/redacted fixtures, fake binaries, and local fake servers.
5. Never read or migrate CodexBar-owned configuration. The baseline repository is a read-only specification and fixture
   source.
6. Keep secrets out of git, test output, long-lived IPC, snapshots, diagnostics, and QML persistence.
7. Add dependencies centrally and only when a task first needs them. Commit `Cargo.lock`; run all CI/release commands
   with `--locked`.
8. Project crates use Rust 2024, workspace resolver 3, `unsafe_code = "forbid"`, and shared warning/clippy policies.
9. All machine-readable stdout is data only; logs go to stderr.
10. Update the parity ledger in the same commit as each implementation. A provider or feature without a passing ledger
    row is incomplete.

## Planned Workspace

```text
Cargo.toml
Cargo.lock
rust-toolchain.toml
rustfmt.toml
clippy.toml
deny.toml
LICENSE
NOTICE
README.md

crates/
  domain/
  storage/
  auth/
  providers/
  cost/
  sessions/
  plugins/
  ipc/
  runtime/
  cli/
  test-support/
  app/                    # the only binary target: omarchy-ai-bar

qml/omarchy-plugin/
  manifest.json
  Service.qml
  BarWidget.qml
  Panel.qml
  Settings.qml
  Protocol.js
  components/
  charts/
  widgets/
  share/
  i18n/

parity/
  baseline.json
  providers.json
  features.json

fixtures/
  domain/
  ipc/
  providers/
  browser/
  processes/

packaging/
  arch/
  systemd/
  desktop/
  metainfo/
  icons/
  release/

scripts/
tests/
```

## Dependency Policy

Use compatible current releases from these families, initially pinned in the workspace manifest:

- Rust 1.98 developer toolchain; Arch system Rust is allowed for AUR when it satisfies `rust-version`.
- Tokio 1.51 LTS family and `tokio-util` 0.7.
- Serde 1, `serde_json`, `thiserror` 2, Clap 4.5, `time` 0.3, and `url` 2.5.
- Reqwest 0.13 with default features off and Rustls enabled explicitly.
- zbus 5 with Tokio only, ksni 0.3, oo7 0.6, and notify-rust with the matching zbus/Tokio feature family.
- rusqlite 0.40 with system SQLite; never enable `bundled` for the Arch package.
- axum 0.8 for the local server.
- rquickjs 0.12 isolated to the plugins crate.
- portable-pty 0.9 isolated from the async executor.
- tempfile, proptest, insta, assert_cmd, predicates, and wiremock-like test support as dev-only dependencies.

The dependency gate rejects duplicate Tokio minor families, multiple zbus majors, and accidental `async-io` transport.

## Phase A — Reproducible Foundation

### Task 1: Bootstrap toolchain and the one-binary workspace

**Developer prerequisite**

```bash
omarchy pkg add rustup
rustup toolchain install 1.98.0 --profile minimal --component rustfmt --component clippy
```

The checked-in `rust-toolchain.toml` selects this toolchain inside the repository. Do not set or depend on a global
default toolchain.

**Files**

- Create root Cargo/toolchain/lint manifests.
- Create every crate manifest and minimal `lib.rs` listed above.
- Create `crates/app/src/main.rs` and `crates/app/tests/version.rs`.
- Add `LICENSE`, `NOTICE`, `.gitignore`, and a minimal `README.md`.

**Test first**

- `omarchy-ai-bar version --json` exits zero, writes one valid JSON object to stdout, and writes no log text there.
- `cargo metadata` exposes exactly one binary target named `omarchy-ai-bar`.

**Implement**

- Add the smallest Clap entry point with `version` and `--json`.
- Centralize workspace package metadata, dependencies, and lints.
- Record upstream MIT attribution in `NOTICE`; use only Omarchy AI Bar identifiers at runtime.

**Verify**

```bash
cargo fmt --all -- --check
cargo check --workspace --all-targets --locked
cargo test --workspace --all-targets --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
```

**Commit:** `chore: initialize reproducible Rust workspace`

### Task 2: Close the baseline and parity ledgers

**Files**

- Create `parity/baseline.json`, `parity/providers.json`, and `parity/features.json`.
- Create `crates/domain/src/provider_id.rs` and `crates/domain/tests/provider_registry.rs`.
- Create `crates/providers/src/registry.rs` and `crates/providers/tests/ledger.rs`.
- Create `scripts/verify-parity-ledger.sh`.

**Test first**

- Registry contains exactly 69 unique IDs and exactly matches the approved design list.
- Baseline revision is `1680b4ed5`.
- Unknown provider IDs fail deserialization.
- Every provider and cross-cutting feature has source provenance, required parity cells, and an initial status.
- The ledger validator fails for a missing, duplicate, or unrecognized record.

**Implement**

- Add typed provider IDs and metadata placeholders only; do not add networking.
- Populate feature rows for privacy, per-account items, `claude-swap`, currency, cost controls, model pricing, display
  controls, config/CLI details, storage, sharing, diagnostics, fleet sync, and approved Apple omissions.

**Verify**

```bash
cargo test -p oab-domain -p oab-providers --locked
scripts/verify-parity-ledger.sh
```

**Commit:** `test: close provider and feature parity ledgers`

### Task 3: Define normalized domain snapshots

**Files**

- Create `crates/domain/src/{ids,percentage,money,rate_window,snapshot,freshness,error,status,identity,privacy}.rs`.
- Create `crates/domain/tests/{snapshot,error,privacy}.rs`.
- Add `fixtures/domain/snapshot-v1.json` and redacted/unredacted goldens.

**Test first**

- Percentages reject non-finite values and clamp only at explicit input boundaries.
- Used/remaining semantics, reset timestamps, and durations stay internally consistent.
- Identity is scoped by provider, instance, and account and cannot be substituted across any boundary.
- A classified error overlays but does not destroy the last-known-good snapshot.
- Snapshot v1 round-trips through JSON without nondeterministic fields.
- Privacy redaction is a domain transformation applied consistently to identity, hooks, server, export, and sync views.

**Implement**

- Keep the domain crate free of Tokio, HTTP, SQLite, QML, and credential dependencies.
- Model primary, secondary, tertiary, named extra windows, balance, cost, detail rows, chart points, provenance, and
  confidence.

**Verify**

```bash
cargo test -p oab-domain --locked
```

**Commit:** `feat: define normalized usage domain`

### Task 4: Add the bounded private UI protocol

**Files**

- Create `crates/ipc/src/{protocol,codec,socket,permissions,credential}.rs`.
- Create `crates/ipc/tests/{protocol,socket_security,credential}.rs`.
- Add canonical `fixtures/ipc/*.jsonl`.

**Test first**

- v1 handshake negotiates capabilities and rejects unknown major versions.
- Sequence numbers strictly increase; stale snapshots are discarded.
- Lines over 64 KiB, malformed JSON, unknown message types, and arbitrary action strings fail closed.
- Runtime directories and sockets are `0700`/`0600`.
- Stale-socket replacement rejects symlinks and non-sockets; peer UID mismatch is rejected when supported.
- Long-lived message types cannot serialize a credential.
- A one-shot credential socket accepts one bounded value and disappears immediately.

**Implement**

- Use a max-length newline codec and enumerated action IDs.
- Separate display and credential transports at the type level.

**Verify**

```bash
cargo test -p oab-ipc --locked
```

**Commit:** `feat: add bounded private UI protocol`

### Task 5: Prove the Omarchy QML bridge and exact anchoring

**Files**

- Create `qml/omarchy-plugin/{manifest.json,Service.qml,BarWidget.qml,Panel.qml,Protocol.js}`.
- Create `tests/qml/tst_protocol.qml`, `crates/app/tests/ui_socket_smoke.rs`, and `scripts/smoke-omarchy.sh`.

**Test first**

- QML protocol reducer accepts a current snapshot, rejects stale sequence numbers, and exposes compatibility failures.
- Rust smoke test performs hello → snapshot → typed action over a temporary runtime socket.
- Manifest validates as plugin ID `local.omarchy-ai-bar`.

**Implement**

- Load one service, render a synthetic snapshot in the bar, and anchor the panel to the real widget.
- Cooperate with `bar.requestPopout` / `releasePopout` and route ownership across monitor instances.
- Keep the QML process free of provider/file/credential reads.

**Automated verify**

```bash
omarchy plugin validate qml/omarchy-plugin
find qml tests/qml -name '*.qml' -print0 | xargs -0 -n1 /usr/lib/qt6/bin/qmlformat --check
QT_QPA_PLATFORM=offscreen /usr/lib/qt6/bin/qmltestrunner -input tests/qml -import /usr/lib/qt6/qml
cargo test -p oab-ipc -p omarchy-ai-bar --locked
```

**Live evidence gate**

- Top, bottom, left, and right bar anchoring.
- Two monitors, fractional scale, shell reload, reconnect, and another panel taking ownership.

Stop provider work if this proof cannot meet the acceptance gate.

**Commit:** `feat: prove Omarchy QML bridge`

### Task 6: Retain a StatusNotifierItem fallback

**Files**

- Create `crates/ipc/src/{frontend_presence,tray}.rs`.
- Create `crates/ipc/tests/{tray_policy,sni_dbus}.rs`.

**Test first**

- No compatible QML client activates SNI after a grace period.
- A compatible client makes SNI passive; an incompatible client does not.
- Last-client disconnect restores SNI without flicker during rapid shell reload.
- Tray menu actions become enumerated runtime actions.

**Implement**

- Use ksni with the Tokio/zbus family and a fake StatusNotifierWatcher in tests.

**Verify**

```bash
dbus-run-session -- cargo test -p oab-ipc --test sni_dbus --locked
cargo test -p oab-ipc --locked
```

**Commit:** `feat: add system tray fallback`

### Task 7: Add typed XDG config and durable storage

**Files**

- Create `crates/storage/src/{paths,atomic_file,lock,watcher,migrations,history}.rs`.
- Create `crates/storage/src/config/{mod,schema,validation}.rs`.
- Create `crates/storage/tests/{xdg_paths,config_atomicity,config_reload,sqlite_history}.rs`.

**Test first**

- Temporary XDG roots are honored; no CodexBar application path is read.
- Config is schema-versioned, locked, and `0600`; ordinary config rejects secret fields.
- Atomic replacement preserves one recoverable predecessor and survives interruption.
- Invalid live edits retain the last-valid configuration and expose a safe diagnostic.
- Unsafe paths, endpoints, unknown providers, and conflicting account IDs fail validation.
- SQLite starts in WAL mode and is owned by one storage thread/actor.

**Implement**

- Add application paths only under the approved XDG namespace.
- Add schema migration scaffolding with rollback fixtures.

**Verify**

```bash
cargo test -p oab-storage --locked
```

**Commit:** `feat: add typed XDG storage`

### Task 8: Add runtime state actor and scheduler skeleton

**Files**

- Create `crates/runtime/src/{actor,command,event,scheduler,snapshot_store,shutdown}.rs`.
- Create `crates/runtime/tests/{actor,scheduler,shutdown}.rs`.
- Create `crates/test-support/src/{fake_provider,clock,fake_transport}.rs`.

**Test first**

- Published sequence numbers increase.
- Concurrent refreshes coalesce; bounded command channels apply backpressure.
- Optional enrichment failure does not cancel required usage.
- Failed refresh preserves last-good state and adds the classified error.
- Popup-open cadence accelerates, returns to normal on close, and reset-boundary scheduling fires once.
- Shutdown cancels and drains outstanding work within a deadline.

**Implement**

- Use paused Tokio time and fake providers only.
- Keep scheduling policy independent of desktop signal acquisition.

**Verify**

```bash
cargo test -p oab-runtime --locked
```

**Commit:** `feat: add runtime state actor`

### Task 9: Wire daemon, control socket, and CLI modes

**Files**

- Create `crates/cli/src/{args,output,exit_code}.rs` and command placeholders.
- Create `crates/app/src/{daemon,wiring,single_instance}.rs`.
- Create `crates/app/tests/{cli_contract,single_instance,shutdown}.rs`.

**Test first**

- One daemon owns runtime sockets and a second invocation forwards an action.
- Safe commands use daemon state and fall back to isolated one-shot mode when appropriate.
- JSON/TOON stdout contains no logs; diagnostics remain on stderr.
- Unimplemented feature handlers return a stable unavailable code and never silently succeed.
- SIGTERM performs bounded graceful shutdown.

**Implement**

- Register the complete command names now: `usage`, `cards`, `dashboard`, `cost`, `serve`, `config`, `hooks`, `guard`,
  `cookie`, `cache`, `plugins`, `sessions`, `diagnose`, `bridge`, and `completion`.

**Verify**

```bash
cargo test -p oab-cli -p omarchy-ai-bar --locked
cargo run -p omarchy-ai-bar --locked -- version --json | jq -e .
```

**Commit:** `feat: wire daemon and CLI modes`

### Task 10: Prove Secret Service and notifications

**Files**

- Create `crates/auth/src/{secret_store,protected_file,precedence,redaction}.rs`.
- Create `crates/auth/tests/{secret_store_contract,protected_file,precedence}.rs`.
- Create `crates/runtime/src/notifications.rs` and `crates/runtime/tests/notification_contract.rs`.

**Test first**

- Fake implementations pass common secret-store and notification contracts.
- Environment overrides remain ephemeral.
- Protected-file persistence requires explicit acknowledgement and uses a separate `0600` file.
- Notifications contain no hidden account data when privacy mode is enabled.

**Implement**

- Add oo7 Secret Service and freedesktop notification adapters behind traits.
- Add ignored live desktop tests; never run them in default CI.

**Verify**

```bash
cargo test -p oab-auth -p oab-runtime --locked
cargo tree --workspace --locked -i zbus
! cargo tree --workspace --locked -i async-io
```

**Commit:** `feat: add desktop security adapters`

### Task 11: Enforce CI, dependency, license, and secret gates

**Files**

- Create `.github/workflows/ci.yml`, `.github/dependabot.yml`, and `deny.toml`.
- Create `scripts/{verify-dependency-families,scan-secret-canaries}.sh`.

**Test first**

- Dependency verifier fails on a fixture graph with multiple runtime families.
- Secret scanner fails on injected canaries and ignores approved redacted values.
- CI asserts one ELF target and validates both parity ledgers.

**Implement**

- Add fmt/check/test/clippy/docs, QML lint, `cargo deny`, ledger validation, secret-canary scanning, and release-binary jobs.
- Pin CI actions to immutable commit SHAs.

**Verify**

```bash
cargo fmt --all -- --check
cargo test --workspace --all-targets --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo doc --workspace --no-deps --locked
cargo deny check
scripts/verify-dependency-families.sh
scripts/verify-parity-ledger.sh
```

**Commit:** `ci: enforce project quality gates`

### Task 12: Add bridge lifecycle and packaging skeleton

**Files**

- Create `crates/cli/src/commands/bridge.rs` and `crates/app/tests/bridge_lifecycle.rs`.
- Create package files under `packaging/{arch,systemd,desktop,metainfo,release}`.
- Create `scripts/verify-package.sh`.

**Test first**

- Install stages and validates before atomic movement into a temporary HOME.
- Update preserves recognized placement/settings and refuses silent overwrite of modified trees.
- Uninstall disables and removes only application-owned files.
- No symlink enters the plugin directory.
- One previous bridge protocol major remains compatible.
- Package contains one project-owned ELF and never writes into `/usr/share/omarchy` or a real HOME.

**Implement**

- Add source `PKGBUILD`, systemd user unit, desktop file, metainfo, install notices, and archive layout.
- Keep a prebuilt `-bin` package as a later release artifact, not a prerequisite for source-package verification.

**Verify**

```bash
cargo test -p omarchy-ai-bar --test bridge_lifecycle --locked
omarchy plugin validate qml/omarchy-plugin
scripts/verify-package.sh --layout-only
```

**Commit:** `packaging: add Omarchy bridge lifecycle`

## Phase B — Shared Provider Infrastructure

### Task 13: Build the provider contract and bounded HTTP transport

**Files**

- Create `crates/providers/src/{descriptor,capability,context,registry,transport,retry,endpoint,redaction}.rs`.
- Create `crates/providers/tests/{contract,http_transport,endpoint_policy,retry,redaction}.rs`.
- Create reusable fake server support in `crates/test-support`.

**Test first**

- Every descriptor has stable ID, display metadata, capabilities, source labels, and default/disabled behavior.
- HTTP requests enforce endpoint policies, redirect checks, response caps, deadlines, cancellation, and isolated cookies.
- 401, 403, 408, 429, 5xx, malformed body, timeout, and cancellation map to stable errors.
- `Retry-After` and one-retry budget are deterministic under a fake clock.
- Request/response diagnostics redact keys, cookies, tokens, and fixture canaries.

**Implement**

- Add typed auth/header injection after URL validation.
- Add generic fetch/parsing test contracts and last-known-good integration.

**Verify**

```bash
cargo test -p oab-providers --locked
```

**Commit:** `feat: add provider transport contracts`

## Phase C — All 69 Providers

For every provider below, create a focused module under `crates/providers/src/providers/<id>/`, fixtures under
`fixtures/providers/<id>/`, and contract tests under `crates/providers/tests/providers/<id>.rs`. Use native Rust for all
first-party providers; QuickJS is reserved for user-installed providers.

Every provider commit must prove success, missing credential, authentication failure, rate limiting, malformed/truncated
body, reset or balance parsing as applicable, redacted diagnostics, last-good preservation, CLI schema projection, and
provider/account identity isolation.

### Task 14: Batch 1 — fixed API-key HTTP providers (11)

**Shared adapter first:** API-key/header resolution, JSON/date/window helpers, account-scoped clients.

**Provider order:** `elevenlabs`, `openai`, `azureopenai`, `fireworks`, `deepinfra`, `warp`, `deepgram`, `aiand`,
`chutes`, `neuralwatt`, `ibmbob`.

**Special gates**

- OpenAI organization/project scoping and spend/credit histories.
- Azure endpoint/version/deployment validation before auth attachment.
- Native-currency balance and period semantics remain exact.

**Verify after each provider**

Replace `<id>` below with the provider's stable snake/lowercase test-target name.

```bash
cargo test -p oab-providers --test provider_<id> --locked
cargo test -p oab-providers --locked
scripts/verify-parity-ledger.sh
```

### Task 15: Batch 2 — configurable endpoint and former bundled-JS providers (15)

**Shared adapter first:** safe base URLs, loopback/private-network policies, region routing, management keys, generic
balance/spend/history details.

**Provider order:** `litellm`, `clinepass`, `crof`, `moonshot`, `llmproxy`, `sub2api`, `wayfinder`, `zenmux`, `xai`,
`zai`, `openrouter`, `synthetic`, `venice`, `poe`, `clawrouter`.

**Special gates**

- SSRF and redirect tests for every configurable endpoint.
- Authenticated public HTTP is always rejected.
- Authenticated private HTTP requires the approved typed policy.
- Former bundled JavaScript fixtures project to identical normalized snapshots.

### Task 16: Batch 3 — signed cloud and device OAuth providers (4)

**Shared adapter first:** OAuth/device-code state machine, clock injection, AWS SigV4/profile chain, Volcengine signing,
bounded `gcloud` token acquisition.

**Provider order:** `copilot`, `bedrock`, `doubao`, `vertexai`.

**Special gates**

- Device polling handles pending, slow-down, cancellation, expiry, and denial.
- Canonical signed requests have golden fixtures.
- AWS environment/profile/session/SSO precedence is fixture-driven.
- No token reaches cache, logs, CLI JSON, or QML.
- Vertex AI projects its validated Cloud Monitoring quota percentage into the primary 24-hour window. This deliberately
  corrects the pinned descriptor's loss of the already-fetched value; genuine no-data responses remain identity-only.
- Copilot's optional browser-cookie budget enrichment remains assigned to Task 18's shared Linux browser boundary.

### Task 17: Batch 4 — bounded CLI and Linux local readers (5)

**Shared adapter first:** PATH discovery, sanitized environment, stdout/stderr caps, timeout/TERM/KILL escalation, XML
and JSON readers.

**Provider order:** `amp`, `kilo`, `kiro`, `jetbrains`, `codebuff`.

**Special gates**

- Fake CLI transcripts cover success, auth drift, nonzero exit, timeout, and cleanup.
- JetBrains uses Linux config/data roots.
- Codebuff credential-file precedence never copies provider credentials.

### Task 18: Batch 5 — cookie/manual capture and Linux browser profiles (19)

**Shared adapter first:** Cookie/Authorization/cURL normalization, per-provider cookie jars, Chromium and Firefox DB+WAL
snapshots, Secret Service decryption, LevelDB/local-storage readers, global browser/keyring disable.

Complete Copilot's optional budget enrichment in this batch using manual cookie capture and Linux Chromium/Firefox
profile discovery; the macOS-only automatic cookie import is replaced by the shared Linux browser infrastructure.
Complete Amp's deferred manual-cookie and browser-session sources in the same shared boundary; its Task 17 API-key and
CLI sources remain independently usable while browser discovery is disabled.

**Provider order:** `t3chat`, `alibaba`, `opencode`, `qwencloud`, `devin`, `manus`, `mimo`, `sakana`, `mistral`,
`commandcode`, `qoder`, `stepfun`, `longcat`, `zoommate`, `notion`, `alibabatokenplan`, `minimax`, `kimi`, `perplexity`.

**Special gates**

- Manual source works with browser and keyring discovery disabled.
- Amp manual-cookie and Linux Chromium/Firefox sources match its pinned HTML usage parser without Safari or Keychain.
- Encrypted Chromium, Firefox, WAL, and local-storage fixtures remain host-scoped.
- Invalid-session refresh never exposes or cross-forwards a cookie.
- Alibaba regional and multi-cookie routing is tested independently.

### Task 19: Batch 6 — stateful OAuth, JSON-RPC/PTY, and agent telemetry (5)

**Shared adapter first:** refresh-token rotation, provider-owned auth discovery, bounded JSON-RPC, PTY, JSONL/session
scanners, read-only SQLite copies, managed Chromium fallback.

**Provider order:** `codex`, `claude`, `gemini`, `antigravity`, `grok`.

**Special gates**

- Full source-precedence matrix and expired-token behavior per provider.
- Fake `codex`, `claude`, `gemini`, `agy`, and `grok` executables.
- Codex app-server initialization/rate-limit/credits contracts and optional web enrichment isolation.
- Claude admin/OAuth/CLI/browser behavior, local costs, multi-account isolation, and strict `claude-swap` adapter.
- Local logs and sessions never escape the known bounded roots.

### Task 20: Batch 7 — multi-source hybrid providers (5)

**Shared adapter first:** source planner combining API, web, local database, CLI, and optional enrichment with explicit
provenance.

**Provider order:** `opencodego`, `factory`, `ollama`, `deepseek`, `groq`.

**Special gates**

- Each source passes independently and in configured precedence order.
- Optional source failure never erases required usage.
- SQLite/profile/API fixtures preserve account and provenance isolation.

### Task 21: Batch 8 — Linux replacements for macOS-gated providers (5)

**Shared adapter first:** document and test each Linux source matrix before provider code.

**Provider order:** `abacus`, `zed`, `augment`, `cursor`, `windsurf`.

**Special gates**

- Abacus manual/browser cookie path uses the batch-5 security boundary.
- Zed uses Linux provider-owned auth or Secret Service rather than Apple Keychain.
- Augment uses Linux CLI/browser/manual sources rather than app-bundle discovery.
- Cursor and Windsurf use Linux editor/browser state with manual fallback.
- No Apple framework, Safari path, Keychain call, or macOS-only failure remains.

**Batch closure**

```bash
cargo test -p oab-providers --locked
scripts/verify-parity-ledger.sh --providers-complete
```

The arithmetic gate is fixed: 11 + 15 + 4 + 5 + 19 + 5 + 5 + 5 = 69.

## Phase D — Complete Runtime and Operational Features

### Task 22: Complete refresh, pace, status, and power behavior

**Files**

- Add `crates/runtime/src/{adaptive_refresh,reset_boundary,pace,status_polling,low_power,thermal,sleep_wake}.rs`.
- Add corresponding deterministic tests with paused time and fake Linux signals.

**Required tests**

- Fixed 1/2/5/15/30 minute, manual, plain adaptive, and consent-gated agent-aware modes.
- Popup acceleration, reset-boundary once-only scheduling, predictive pace, work-day model, and quota warnings.
- Linux battery/thermal/sleep/wake/network recovery; unknown signals fail conservatively.
- Status incident transitions, recovery, stale feed, and icon/badge projection.

**Commit:** `feat: complete refresh and status runtime`

### Task 23: Port costs, pricing, histories, and currency

**Files**

- Implement `crates/cost/src/{scanner,history,pricing,models_dev,currency,provenance,retention}.rs`.
- Add fixtures/tests for all applicable provider capabilities.

**Required tests**

- Opt-in tracking and scan ranges; 7/30/90/365-day views.
- OpenCodex inclusion, source coverage, list-price disclaimer, native-currency grouping, preferred conversion, and
  subscription/model/project/session breakdown.
- `models.dev` TTL, offline fallback, cache merge, and exact custom-pricing override.
- WAL storage and Codex 25,000-row/256 MiB caps.
- Scanner work never blocks Tokio and never opens provider databases writable.

**Commit:** `feat: port cost and pricing engine`

### Task 24: Port sessions, storage reports, and Hyprland focus

**Files**

- Implement `crates/sessions/src/{local,remote,ssh,tailscale,focus,privacy}.rs`.
- Implement provider-storage catalog/reporting under runtime/storage.

**Required tests**

- `/proc` and process discovery without reading `/proc/<pid>/environ`.
- Privacy-bounded latest activity and optional detailed sessions.
- SSH/Tailscale disabled by default and strictly validated when enabled.
- Hyprland focus actions validate window/workspace identity.
- Storage totals scan only known provider-owned paths, expose copyable breakdowns, and cannot delete.

**Commit:** `feat: port sessions and storage reports`

### Task 25: Embed the sandboxed user-provider runtime

**Files**

- Implement `crates/plugins/src/{engine,manifest,approval,host_api,http,cache,typescript}.rs`.
- Add plugin fixtures, declaration file, and hostile-script tests.

**Required tests**

- 1 MiB source/response limits, 64 MiB heap, 2 MiB stack, and 20-second interrupt watchdog.
- Declared endpoint/capability approval invalidates on authority changes.
- Redirects off, host-owned auth, one retry, deterministic date/format/JWT helpers.
- No Node/browser globals, imports, arbitrary files, subprocesses, or native APIs.
- TypeScript transform cache keys include source and compiler version.
- Browser-cookie plugins fail closed in headless CLI mode.

**Commit:** `feat: add sandboxed provider plugins`

### Task 26: Complete hooks, notifications, guard, and diagnostics

**Files**

- Implement runtime hook transition engine and all related CLI commands.
- Implement provider diagnostics, PATH/login-shell inspection, log levels, fetch-attempt views, and granular cache clear.

**Required tests**

- Hooks are opt-in, use direct argv, bounded JSON stdin, restricted environment, timeout, and rate limits.
- Privacy setting redacts hook and notification data.
- Guard decisions and stable exit codes match window/account selections and never prompt.
- Diagnostics redact fixture canaries and keep machine output separate from logs.

**Commit:** `feat: complete automation and diagnostics`

### Task 27: Complete CLI cards, dashboard, and local HTTP server

**Files**

- Implement all command modules under `crates/cli/src/commands/`.
- Implement `crates/cli/src/server/{routes,auth,host_guard,cache,assets}.rs`.
- Embed dashboard web assets in the executable.

**Required tests**

- Usage/cards human, JSON, and TOON formats; brief/responsive cards; account/all-account selection.
- Config validate/dump/order/toggle/set-key-from-stdin/path override and permission behavior.
- Atomic dashboard file output and last-good local dashboard state.
- `/health`, usage, cost, and dashboard routes; loopback default; Host validation; constant-time token comparison;
  non-loopback acknowledgement; deadlines; cache coalescing; protected no-store responses.

**Commit:** `feat: complete CLI and local dashboard server`

### Task 28: Implement non-secret fleet aggregation

**Files**

- Create `crates/runtime/src/fleet_sync.rs` and QML Fleet Sync settings.
- Add hostile/stale/conflict fixtures under `fixtures/fleet/`.

**Required tests**

- Off by default; user-selected directory only.
- One atomic bounded file per device; stable device ID and filename rules.
- Schema/size/path validation, stale retention, conflict handling, and safe unknown-field behavior.
- Privacy redaction applies before publication.
- No secrets, actions, URLs with tokens, or executable content can serialize.

**Commit:** `feat: add folder-based fleet aggregation`

## Phase E — Full QML Product Surface

### Task 29: Build bar tokens, overview, and provider cards

**Files**

- Build QML components for icon renderer, tokens, countdown, pace, overview, cards, windows, account switcher, status,
  and refresh state.
- Add synthetic snapshot fixtures and QML screenshot tests.

**Required tests**

- Each display token survives missing sibling data.
- Merged and separate-provider modes, highest-usage selection, six-row overview, loading/stale/error/incident states.
- Per-account bar items cap at four, replace provider item, and exclude merged mode.
- Manual refresh keeps card geometry stable.

**Commit:** `feat: build provider bar and panel UI`

### Task 30: Build settings and layout editor

**Files**

- Complete `Settings.qml` and panes for every approved settings section.
- Build layout presets/token editor and provider overrides.

**Required tests**

- General/provider/display/notification/spend/session/hook/plugin/fleet/advanced/about actions use typed IPC only.
- Used/remaining, markers, pace/work days, reset style, credits/extras, contrast, animations, and changelog links.
- One/two-line ordering, add/remove/drag, provider overrides, and reset-to-global behavior.
- Secret entry uses only the one-shot credential socket and clears immediately.

**Commit:** `feat: build settings and layout editor`

### Task 31: Build charts, widgets, sharing, and visual effects

**Files**

- Build cost/history/burndown/heatmap chart components.
- Build compact/wide/usage/history/metric/burndown/switcher widget forms.
- Build share text/image/save PNG and confetti components.

**Required tests**

- Empty, partial, multi-currency, stale, estimated, and high-volume charts.
- Widget designs reproduce useful baseline forms without claiming WidgetKit timeline semantics.
- Shared text/PNG contains no credentials and respects privacy mode.
- Effects are bounded and honor reduced-motion settings.

**Commit:** `feat: add dashboards and share surfaces`

### Task 32: Complete localization, RTL, accessibility, and keyboard behavior

**Files**

- Add the 21-locale QML catalog and locale loader.
- Add accessibility metadata, focus order, shortcuts, and RTL component tests.

**Required tests**

- Every user-visible key exists in every catalog or has an explicit reviewed fallback.
- RTL mirrors structure without reversing data semantics or charts incorrectly.
- Keyboard-only navigation reaches every action; screen-reader names/values expose quota and errors.
- High contrast and fractional-scale screenshots pass.

**Commit:** `feat: complete accessible localized UI`

## Phase F — Platform and Release Closure

### Task 33: Complete Omarchy integration lifecycle

**Files**

- Finalize bridge install/update/status/uninstall, systemd unit, desktop file, metainfo, icons, completions, and optional
  Hyprland binding installer.

**Required tests**

- Plugin staging/validation/update preserves placement and makes recoverable backups of recognized modified copies.
- Protocol compatibility across one prior major and SNI fallback during mismatch.
- Login startup, headless serve/hooks modes, shell reload, notifications, sleep/wake, and removal behavior.
- No modification to `/usr/share/omarchy/`.

**Commit:** `feat: complete Omarchy integration lifecycle`

### Task 34: Security, performance, and full parity closure

**Files**

- Complete `docs/{security,compatibility,unsupported-apple-semantics}.md`.
- Add benchmarks and full-system fixture suites.

**Required tests**

- Every provider and feature ledger cell is passing or one of the two approved Apple semantic omissions.
- Privacy mode propagation across QML, notifications, hooks, CLI/server, exports, diagnostics, and fleet sync.
- Endpoint redirects, browser profiles, QuickJS, IPC, secret storage, package scripts, and synced files pass hostile tests.
- Idle daemon and open panel stay within documented CPU/memory/network budgets.
- No unbounded process, response, database scan, QML message, or history table remains.

**Verify**

```bash
cargo test --workspace --all-targets --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo deny check
omarchy plugin validate qml/omarchy-plugin
scripts/verify-dependency-families.sh
scripts/verify-parity-ledger.sh --all-complete
```

**Commit:** `test: close full product parity`

### Task 35: Build and verify release artifacts

**Files**

- Finalize `packaging/arch/PKGBUILD` and add `PKGBUILD-bin` only when signed release artifacts exist.
- Create `scripts/{build-release,verify-archive,verify-package,upstream-diff}.sh`.
- Complete installation, security, compatibility, and maintenance documentation.

**Required tests**

- Clean Arch source package build and direct archive install.
- Package content contains exactly one project-owned executable plus approved support files.
- Install, upgrade, downgrade-compatible bridge, and remove cycles in a clean VM/container.
- Checksums/signatures, third-party notices, no secret fixtures, and reproducible locked build.
- Upstream-diff tool reports provider, schema, CLI, fixture, UI, and license changes from `1680b4ed5`.

**Verify**

```bash
makepkg --cleanbuild --syncdeps --noconfirm
namcap packaging/arch/PKGBUILD ./*.pkg.tar.zst
scripts/verify-package.sh ./*.pkg.tar.zst
scripts/verify-archive.sh dist/*
```

**Commit:** `release: prepare Omarchy AI Bar`

## Foundation Exit Gate

Provider batch 1 may start only after Tasks 1–12 are green and manual evidence exists for:

- exact QML anchoring on all bar edges;
- multi-monitor ownership and fractional scaling;
- shell reload/reconnect and SNI fallback;
- notification delivery and Secret Service round-trip;
- clean bridge install/update/uninstall in a temporary or disposable user environment.

## Final Definition of Done

- Exactly 69 first-party providers pass their applicable authentication, usage/reset, costs, sessions, browser, status,
  errors, refresh, CLI/server, and UI parity cells.
- Every cross-cutting feature row passes, including the twelve explicit records added during design self-review.
- Folder-based fleet usage aggregation works without secret synchronization.
- The compatibility report lists only encrypted secret synchronization and Apple app-group/WidgetKit host semantics as
  approved unsupported Apple behaviors.
- Direct archive and AUR installation work on supported Omarchy.
- One Rust runtime executable owns all substantive behavior; QML remains presentation-only.
- All verification commands are freshly green and their evidence is recorded before any completion claim.
