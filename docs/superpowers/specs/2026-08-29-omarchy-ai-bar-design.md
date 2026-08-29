# Omarchy AI Bar Design

**Status:** Approved
**Date:** 2026-08-29
**Target:** Omarchy 4.0.1 and later compatible releases
**Parity baseline:** CodexBar `1680b4ed5` (`main` and `origin/main` in the supplied checkout)
**License baseline:** MIT, with upstream attribution retained in repository and distribution notices

## 1. Purpose

`omarchy-ai-bar` is an Omarchy-native application for monitoring AI-provider quotas, resets, credits, costs, status, and local agent activity. It ports the complete applicable CodexBar product surface to a Rust backend and an Omarchy/Quickshell QML frontend.

The project has one runtime executable named `omarchy-ai-bar`. The executable contains all provider, state, security, automation, CLI, and server behavior. Packaged QML, icons, desktop metadata, service definitions, shell completions, and license files are allowed. The application must not depend on CodexBar or invoke its Swift CLI at runtime.

The initial release is complete only when all 69 baseline providers and all applicable feature-parity records pass. Work may be implemented and validated in internal stages, but an incomplete provider subset is not a finished release.

## 2. Product Decisions

The following decisions are fixed for the initial parity release:

- The public project, package, executable, paths, and UI name are `omarchy-ai-bar` / Omarchy AI Bar.
- The runtime is implemented in Rust and builds one application executable.
- The primary UI is a full Omarchy QML plugin, not a GTK application.
- QML owns presentation only. Credentials, provider behavior, persistence, and business rules remain in Rust.
- A standard StatusNotifierItem is retained as a fallback when the Omarchy plugin is unavailable.
- The UI follows CodexBar's visual hierarchy and interaction model as closely as Omarchy permits.
- The application uses its own configuration and data directories and never shares or migrates CodexBar state.
- The same executable supplies the graphical backend and the complete CLI/server surface.
- Updates are delivered through direct release archives and AUR/pacman packages. There is no self-updater.
- Stock Omarchy runtime libraries may be dynamically linked; they need not be bundled into the executable.
- Apple-only features are mapped to real Omarchy/Linux equivalents where one exists. Unsupported features are documented rather than replaced with an unrelated service.
- Fixture-based verification is the default for providers without configured local accounts. Live probes are opt-in and never require committed or shared credentials.

## 3. Scope

### 3.1 Included

- All 69 first-party providers present in the parity baseline.
- Multiple accounts and provider instances.
- Separate-provider and merged bar layouts.
- Overview, provider cards, quota windows, reset countdowns, credits, balances, costs, history, status, and errors.
- Provider configuration, source selection, credentials, browser sessions, OAuth/device flows, and provider actions.
- Adaptive and fixed refresh modes, reset-boundary refresh, incident polling, notifications, and pace warnings.
- Local Codex/Claude and other supported cost scans, session discovery, provider storage reporting, and pricing data.
- User-installed JavaScript/TypeScript provider plugins with a sandboxed QuickJS runtime.
- CLI commands corresponding to usage, cards, dashboard, cost, serve, config, hooks, guard, cookie, cache, plugins, sessions, diagnostics, completion, and version output.
- Loopback HTTP dashboard/API behavior and its security controls.
- External hooks, systemd user operation, Omarchy keyboard integration, and freedesktop notifications.
- Opt-in multi-machine usage aggregation through a user-selected synchronized folder.
- Existing localization breadth, including RTL presentation.
- Direct archive and AUR source/binary packaging.

### 3.2 Platform substitutions

| macOS facility | Omarchy/Linux design |
| --- | --- |
| Menu-bar status items | Omarchy QML bar widget; StatusNotifierItem fallback |
| SwiftUI/AppKit popup and settings | Quickshell QML panels and settings views |
| WidgetKit | Optional QML compact, wide, history, metric, and burndown widget/dashboard views |
| Keychain | Secret Service desktop keyring |
| `SMAppService` | systemd user service and Omarchy plugin activation |
| User notifications | Freedesktop notifications rendered by Omarchy |
| Global shortcut | Installable Omarchy/Hyprland binding |
| `WKWebView` session acquisition | Managed Chromium profile, external browser, or device flow |
| Sparkle | AUR/pacman and direct release archives; no in-app update |
| Status-item placement | Omarchy bar layout and plugin settings |
| Share/copy image facilities | Qt/Quickshell clipboard, file chooser, and offscreen rendering |
| CloudKit fleet snapshots | Per-device snapshot files in a user-selected Syncthing/Dropbox/rsync folder |

### 3.3 Explicitly unsupported Apple semantics

Omarchy has no safe native counterpart for these facilities:

- iCloud/CloudKit encrypted secret synchronization.
- Apple app-group and WidgetKit timeline/container semantics.

Visible widget designs remain in scope as QML components. Omarchy AI Bar can exchange redacted usage snapshots through
a folder the user already synchronizes, following Omarchy's existing Agents-widget pattern. Adding a hosted cloud
service or synchronizing secrets is not in scope.

### 3.4 Explicit cross-cutting parity records

The feature ledger must contain independently testable rows for these baseline behaviors; they cannot be considered
covered merely because a broader screen or command exists:

- A persisted **Hide personal information** setting propagates through the bar, popup, notifications, hooks, CLI,
  server/dashboard, exports, diagnostics, and fleet snapshots. Each surface has redacted and unredacted fixtures.
- Selected **per-account bar indicators** support up to four accounts, replace the provider-level indicator while
  active, preserve stable account identity, and are mutually exclusive with merged-indicator mode.
- The optional `claude-swap` adapter invokes only the documented `cswap --list --json` and
  `cswap --switch-to <slot> --json` forms, validates their schema, never reads its credentials directly, and preserves
  last-good state across adapter errors.
- Preferred currency, native-currency grouping, and exchange-aware display are explicit settings and spend-dashboard
  behaviors; original currency and conversion provenance remain visible.
- Cost controls cover opt-in tracking, scan range, OpenCodex-log inclusion, 7/30/90-day comparisons, source and
  coverage/provenance display, subscription/model/project/session breakdowns, and clear list-price-estimate wording.
- The `models.dev` metadata/pricing cache has tested TTL, offline fallback, merge, and exact custom-pricing overlay
  semantics.
- Advanced display controls cover used-versus-remaining fill, warning markers, pace visibility and work-day model,
  countdown-versus-absolute reset, optional credits/extra usage, high-contrast inactive presentation, loading animation
  selection, and provider changelog links.
- Config commands cover validate/dump, provider order and toggles, API-key input through stdin, isolated config-path
  overrides, redaction, and restrictive permissions.
- CLI cards/dashboard parity covers responsive and brief terminal cards, account selection/all-accounts, clean
  machine-readable diagnostics, atomic dashboard-file output, `/health`, and last-good browser-dashboard state.
- Provider-storage UI covers an opt-in known-path total, path breakdown, copyable paths, and a strict no-delete policy.
- Sharing covers copy text, copy image, and save PNG with a no-credentials guarantee for every generated artifact.
- Debugging covers runtime log-level control, redacted per-provider logs, effective PATH/login-shell diagnostics,
  plugin-engine diagnostics, fetch-attempt inspection, and granular cache cleanup.

## 4. System Architecture

### 4.1 Runtime components

The installation contains one project-owned executable and support files:

1. **Rust backend and CLI (`omarchy-ai-bar`)**
   - Owns authoritative application state.
   - Implements all providers and shared integrations.
   - Persists config, secrets, caches, history, and approvals.
   - Runs refresh scheduling, notifications, hooks, sessions, and HTTP serving.
   - Exposes a private UI protocol to the QML plugin.
   - Registers a fallback StatusNotifierItem when no compatible QML frontend is connected.

2. **Omarchy QML frontend**
   - Renders the bar, popup, settings, dashboards, charts, and optional widgets.
   - Obtains exact bar-widget geometry and participates in Omarchy's panel ownership behavior.
   - Sends typed user actions to Rust and renders immutable display snapshots.
   - Never reads credentials or provider-owned secret files.

3. **External provider tools**
   - Existing provider CLIs such as `codex`, `claude`, `gemini`, `gcloud`, `aws`, or `grok` may be launched as bounded child processes.
   - These are provider dependencies, not project-owned helper executables.

### 4.2 Rust organization

A Cargo workspace may contain internal library crates, but it produces exactly one runtime binary. Boundaries are organized by responsibility:

- `domain`: provider IDs, instance IDs, snapshots, windows, costs, status, identity, freshness, errors, and capability traits.
- `providers`: the 69 native first-party implementations and their fixtures.
- `auth`: Secret Service, environment overrides, OAuth/device flow, browser profiles, manual credentials, and source precedence.
- `runtime`: state actor, refresh scheduler, cancellation, network/process execution, notifications, hooks, and lifecycle.
- `storage`: XDG paths, atomic config, SQLite history, caches, plugin approvals, and migrations.
- `plugins`: QuickJS sandbox and user-provider host API.
- `ipc`: the private QML socket contract and fallback StatusNotifierItem.
- `cli`: command parsing, output models, HTTP server, and exit-code contract.
- `app`: startup, mode selection, dependency wiring, and shutdown.

No UI-specific QML representation enters provider modules. No provider-specific authentication leaks into generic UI code.

### 4.3 Process modes

Running `omarchy-ai-bar` without arguments starts or foregrounds the desktop backend. Explicit subcommands use the same executable:

- `daemon`
- `usage`
- `cards`
- `dashboard`
- `cost`
- `serve`
- `config`
- `hooks`
- `guard`
- `cookie`
- `cache`
- `plugins`
- `sessions`
- `diagnose`
- `bridge`
- `completion`
- `version`

CLI commands that can safely use the running daemon do so through a local control socket. They fall back to an isolated one-shot runtime when no daemon exists. Machine-readable output remains free of log noise.

## 5. QML Frontend

### 5.1 Plugin structure

The packaged plugin uses a non-reserved third-party ID and includes, at minimum:

- `manifest.json`
- `Service.qml`
- `BarWidget.qml`
- `Panel.qml`
- `Settings.qml`
- reusable controls, chart components, localization resources, and visual assets

The stable Omarchy plugin ID is `local.omarchy-ai-bar`. The desktop application ID is
`org.omarchy_ai_bar.App`, and the systemd user unit is `omarchy-ai-bar.service`.

The plugin is shipped under the application's own `/usr/share` directory. The package never writes directly into a user's home directory. The executable provides explicit `bridge install`, `update`, `status`, and `uninstall` commands that stage, validate, and atomically manage the user-owned plugin copy.

The installer:

1. copies the packaged plugin to a staging directory;
2. runs `omarchy plugin validate`;
3. atomically installs it under `~/.config/omarchy/plugins/`;
4. enables or rescans it through supported Omarchy commands;
5. preserves the user's placement and settings during updates;
6. refuses to overwrite an unrecognized or locally modified directory without preserving a backup and obtaining explicit confirmation.

Symlinks are not used because Omarchy rejects them in third-party plugin trees.

### 5.2 Bar and popup behavior

The bar supports:

- merged and multiple-provider display modes;
- provider branding, dynamic usage icons, critters, labels, percentage tokens, pace, reset, balance, cost, and compact bars;
- global and provider-specific layout presets;
- one- and two-line composition;
- loading, stale, error, and incident presentation;
- top, bottom, left, and right bar positions;
- multiple monitors and fractional scaling.

The popup supports:

- overview and provider switching;
- up to six overview rows matching the baseline behavior;
- provider/account identity and source labels;
- primary, secondary, tertiary, and extra rate windows;
- reset countdowns and absolute reset display;
- credits, balances, spend, cost histories, and provider-specific detail sections;
- account switching and stacked account presentation;
- status incidents, stale data, classified errors, and retry actions;
- manual refresh without layout jumps;
- provider actions, settings, and quit.

The clicked QML widget is the real panel anchor, so the popup aligns exactly with the Omarchy bar. Only one popup is open across monitors. It cooperates with Omarchy's popout coordinator so opening another panel closes Omarchy AI Bar and vice versa.

### 5.3 Settings and auxiliary UI

Settings retain these sections:

- General
- Providers
- Display
- Notifications
- Usage & Spend
- Sessions
- Hooks
- Plugins
- Fleet Sync
- Advanced
- About

The QML frontend also implements the layout-token editor, charts, share/export UI, optional widget/dashboard forms, confetti, keyboard navigation, accessibility names, 21-language localization, and RTL layout. Behavior and information hierarchy take priority where AppKit controls have no pixel-identical Qt equivalent.

## 6. UI IPC Contract

### 6.1 Transport

The backend listens on a Unix socket below `$XDG_RUNTIME_DIR/omarchy-ai-bar/`. The directory is mode `0700`; the socket is mode `0600`. Peer UID is verified where the platform API permits it.

Messages are versioned newline-delimited JSON with a strict maximum size of 64 KiB per message. Oversized, malformed, unknown-version, or out-of-state messages are rejected. The frontend cannot supply arbitrary executable commands.

### 6.2 Message responsibilities

Rust sends:

- protocol and capability handshake;
- sequenced, immutable display snapshots;
- provider/account lists and redacted identities;
- settings schemas and current non-secret values;
- refresh, login, export, and action progress;
- panel state, notifications, and compatibility errors.

QML sends:

- frontend handshake and bridge version;
- widget geometry, output name, logical screen geometry, DPR, and bar edge;
- open, close, switch, refresh, and navigation actions;
- validated settings edits;
- provider actions expressed as enumerated action IDs;
- plugin-install and approval decisions without secret values.

Secret entry uses a separate, one-shot credential socket created for one settings action. The socket is user-only,
expires quickly, accepts exactly one bounded value, and is destroyed after Rust confirms storage. QML clears the
secure input immediately after submission. Credentials never enter the long-lived display socket and are never echoed
into display snapshots, logs, or QML-persisted state.

Sequence numbers and request IDs make reconnects and retries idempotent. QML discards older snapshots. Rust treats disconnect as loss of presentation only, not as application shutdown.

## 7. Domain Model and Provider Architecture

### 7.1 Normalized model

Every provider result projects into an immutable model containing applicable fields:

- provider and instance identity;
- account identity, organization, plan, and login method;
- primary, secondary, tertiary, and named extra rate windows;
- used/remaining percentages, reset timestamps, and window durations;
- credits, balances, spend, currency, subscription renewal, and reset-credit inventory;
- daily or periodic chart points and generic detail rows;
- source/provenance and data-confidence classification;
- provider status incidents;
- fetch timestamp, freshness, and last-known-good state;
- classified error with retry and authentication implications.

Presentation rules consume this model but cannot source identity or plan data from another provider/account.

### 7.2 Capability traits

Providers implement small capabilities rather than one monolithic interface:

- metadata and presentation hints;
- authentication discovery and source precedence;
- usage fetch;
- provider status fetch;
- cost/history scan;
- agent-session scan;
- browser cookie or local-storage acquisition;
- storage footprint report;
- login and provider actions.

Shared infrastructure supplies API-key HTTP, manual-cookie HTTP, OAuth/device flow, bounded CLI/RPC, managed browser profile, browser database import, and local JSON/JSONL/SQLite/XML adapters.

### 7.3 Baseline providers

The closed first-party set is:

`codex`, `openai`, `azureopenai`, `claude`, `clinepass`, `cursor`, `opencode`, `opencodego`, `alibaba`, `alibabatokenplan`, `qwencloud`, `factory`, `fireworks`, `gemini`, `antigravity`, `copilot`, `devin`, `zai`, `minimax`, `manus`, `kimi`, `kilo`, `kiro`, `vertexai`, `augment`, `jetbrains`, `moonshot`, `amp`, `t3chat`, `ollama`, `synthetic`, `openrouter`, `elevenlabs`, `warp`, `windsurf`, `zed`, `perplexity`, `mimo`, `doubao`, `sakana`, `abacus`, `mistral`, `deepseek`, `deepinfra`, `codebuff`, `crof`, `venice`, `commandcode`, `qoder`, `stepfun`, `bedrock`, `grok`, `groq`, `llmproxy`, `litellm`, `deepgram`, `poe`, `chutes`, `neuralwatt`, `clawrouter`, `longcat`, `sub2api`, `wayfinder`, `zenmux`, `aiand`, `zoommate`, `xai`, `notion`, and `ibmbob`.

Provider work is grouped by reusable infrastructure:

1. API-key and configurable-endpoint HTTP providers.
2. Manual-cookie and browser-session providers.
3. OAuth, device-flow, and CLI-backed providers.
4. Local JSON, JSONL, SQLite, XML, process, and session readers.
5. Bespoke cloud integrations such as AWS and Google Cloud.

Cursor, Augment, Windsurf, Zed, and Abacus have macOS-only gates in the baseline implementation. They require new Linux-native discovery or manual-auth implementations rather than direct translation. Their parity entries cannot be waived merely because the upstream Swift path is platform-gated.

### 7.4 User-provider plugins

QuickJS is embedded in the Rust executable for user JavaScript/TypeScript providers. The host preserves the baseline security model:

- one local source file with a 1 MiB limit;
- declared HTTPS/private-network origins;
- explicit capability and endpoint approval;
- declared plain and secure settings;
- host-owned authentication headers;
- bounded response size, redirects, retry budget, timeout, heap, stack, and execution duration;
- deterministic date/format/JWT helpers;
- no Node/browser globals, imports, arbitrary files, subprocesses, or native APIs;
- redacted logs and per-plugin caches.

The source-level plugin contract remains compatible where it is not tied to application naming. Paths, declaration files, environment prefixes, approvals, and UI labels use only the Omarchy AI Bar namespace.

## 8. Configuration, Secrets, and Browser Data

### 8.1 XDG layout

- Config: `$XDG_CONFIG_HOME/omarchy-ai-bar/`, defaulting to `~/.config/omarchy-ai-bar/`
- Data: `$XDG_DATA_HOME/omarchy-ai-bar/`, defaulting to `~/.local/share/omarchy-ai-bar/`
- Cache: `$XDG_CACHE_HOME/omarchy-ai-bar/`, defaulting to `~/.cache/omarchy-ai-bar/`
- Runtime: `$XDG_RUNTIME_DIR/omarchy-ai-bar/`

There is no automatic import from or compatibility lookup for CodexBar paths. Provider-owned paths such as `~/.codex/auth.json` remain valid because they belong to the provider, not the upstream application.

### 8.2 Configuration behavior

Configuration is typed, schema-versioned JSON written with atomic replacement and file locking. Files use restrictive permissions. Writes preserve a recoverable previous version. Validation rejects unknown provider IDs where appropriate, invalid endpoints, conflicting account IDs, unsafe paths, and malformed secrets.

The daemon watches configuration and plugin directories with Linux filesystem notifications and applies valid changes without restarting. Invalid edits retain the last valid in-memory state and surface a diagnostic.

All application environment variables use the `OMARCHY_AI_BAR_` prefix. Provider-standard variables such as `OPENAI_API_KEY` remain supported where they are part of provider conventions.

### 8.3 Secret precedence

Authentication sources are resolved explicitly per provider. A typical order is:

1. one-shot CLI override;
2. provider-standard environment variable;
3. selected account secret from Secret Service;
4. provider-owned OAuth/config file;
5. browser/manual session source;
6. provider CLI or device login.

The exact order is recorded per provider and tested. Environment values are never copied into persistent storage automatically.

Secret Service is the default application store. In keyring-disabled/headless mode, persistence remains off unless the
user explicitly selects protected-file storage for a credential after acknowledging a warning. Protected-file secrets
are written to a separate `0600` secret file, never the ordinary settings document. Secret values are excluded from
dumps unless the user supplies an explicit dangerous flag.

### 8.4 Browser integration

Automatic discovery targets installed Linux Chromium-family and Firefox-family profiles. Cookie databases are accessed through read-only snapshots that include WAL state. Decryption uses the appropriate desktop keyring contract. Browser local-storage and LevelDB extraction are separate capabilities and never treated as cookie data.

For flows that require a real browser engine, the backend launches an application-owned Chromium profile and controls it through a bounded browser-debugging connection. External browser/device flows remain preferred when supported. Manual Cookie, Authorization, and cURL capture remain first-class fallbacks.

Users can globally disable browser and keyring discovery. Tokens, cookie values, browser database contents, and authorization headers are never logged.

## 9. Refresh, State, and Failure Semantics

### 9.1 Concurrency

Tokio is the sole asynchronous runtime. One application-state actor publishes immutable snapshots. Provider/account refreshes are coalesced, cancellable, and bounded. Required and optional enrichment operations are separated so an optional failure cannot cancel a required result.

Network clients are isolated by provider/account cookie context. Authorization is attached only after endpoint and redirect validation. Every request has explicit connect/request deadlines and response-size bounds.

Provider CLI and JSON-RPC processes use bounded startup, request, shutdown, and kill deadlines. Interactive PTY work runs on dedicated bounded threads outside the async executor.

### 9.2 Scheduling

The application ports:

- manual refresh;
- fixed 1, 2, 5, 15, and 30 minute intervals;
- adaptive refresh;
- agent-aware adaptive refresh with explicit permission;
- open-popup acceleration;
- reset-boundary refreshes;
- predictive refresh and pace warnings;
- incident/status polling;
- sleep/wake and network recovery behavior;
- low-power and thermal reductions using Linux signals.

Refresh activity is rate-limited and deduplicated. Manual refresh shares an active request rather than spawning duplicates.

### 9.3 Persistence

Application-owned history uses SQLite in WAL mode with bounded retention. Codex session history retains the baseline 25,000-entry and 256 MiB caps unless later fixture evidence requires a compatible adjustment. Provider-owned databases are opened read-only or copied with their WAL before parsing. A shared SQLite connection is not held behind an async mutex; storage work is serialized through a dedicated actor/thread.

### 9.4 Fail-soft behavior

A failed refresh does not erase the last successful snapshot. UI state distinguishes:

- loading;
- fresh;
- refreshing with cached data;
- stale;
- authentication expired;
- missing credential;
- permission denied;
- rate limited;
- provider unavailable;
- network failure;
- parse failure;
- generic API failure.

Errors carry safe display text, retry eligibility, source context, and diagnostics without secret material. Persistent or suspicious reset changes use last-known-good values until confirmed, matching provider-specific baseline behavior.

## 10. Automation, Sessions, and Notifications

- Quota-low, quota-reached, quota-reset, predictive pace, provider outage, and recovery notifications use the freedesktop notification interface.
- Confetti and other purely visual celebrations run in the QML frontend and remain optional.
- External hooks are disabled by default, accept fixed argv rather than shell strings, receive a bounded JSON payload on stdin, use a restricted environment, and have timeout/rate controls.
- Agent-session discovery uses `/proc`, provider-owned metadata, SSH/Tailscale configuration where enabled, and privacy-bounded retention.
- Session focus uses Hyprland IPC with validated window/workspace targets.
- Provider storage reports read only known provider-owned paths and never delete data.
- Fleet sync is off by default. Each machine atomically writes one bounded, schema-versioned, non-secret snapshot to a
  user-selected synchronized folder and reads the other machine files defensively. Device ID, file name, identity
  redaction, and retention are explicit settings. Tokens, cookies, API keys, plugin secrets, and executable actions are
  never included.
- A systemd user unit supports login startup, headless hook watching, and server operation. The QML plugin may also start the backend when a compatible socket is absent.

## 11. CLI and HTTP Server

The CLI preserves human-readable, JSON, and TOON output where present in the baseline. It honors graphical provider settings and accounts. Stable exit codes distinguish usage errors, unavailable providers, authentication failures, guard decisions, and internal failures.

The local server provides usage, cost, and dashboard snapshot endpoints with cached/coalesced refreshes. It binds to loopback by default, validates Host headers, enforces request deadlines, and fails closed on protected routes when no token is configured. Non-loopback binding requires explicit authorization and secure-transport acknowledgement matching the baseline safety intent.

The built-in dashboard assets are compiled into the Rust executable. QML support files remain separate because Omarchy loads them directly.

## 12. Testing Strategy

### 12.1 Traceability

A machine-readable parity ledger maps every provider and feature to:

- baseline source/docs/tests;
- authentication parity;
- usage and reset parsing;
- cost/history behavior;
- CLI/session integration;
- browser behavior;
- status and error behavior;
- refresh/rate-limit behavior;
- Rust tests and current status;
- approved platform adaptation or unsupported reason.

The ledger is generated or validated against the closed 69-provider registry so a missing provider cannot disappear silently.

### 12.2 Test layers

- Domain unit tests for calculations, identity isolation, reset handling, pace, retries, and error mapping.
- Golden parser and request/response fixture tests per provider.
- Contract tests shared by every provider capability.
- Integration tests using fake HTTP servers, fake CLIs, temporary XDG roots, browser-profile fixtures, isolated SQLite databases, and a temporary Secret Service.
- Fleet-sync tests for atomic per-device publication, schema/size rejection, identity redaction, conflict handling, and
  malicious synchronized-folder inputs.
- QuickJS sandbox tests for authority boundaries, time/memory limits, redaction, and deterministic helpers.
- CLI snapshot, schema, exit-code, and server-security tests.
- QML linting, component tests, protocol tests, screenshot comparisons, RTL, keyboard, and accessibility tests.
- Omarchy live smoke tests for every bar edge, multiple monitors, fractional scaling, shell reload, sleep/wake, keyboard integration, notification delivery, and fallback tray operation.
- AUR clean-build, package-content, install, upgrade, downgrade-compatibility, and removal tests.

Live provider tests are opt-in and consume only credentials already configured on the developer machine. Test and diagnostic output must not reveal those credentials.

### 12.3 Completion gate

The first release requires:

- all 69 providers registered;
- every applicable parity-ledger cell passing;
- all approved platform equivalents implemented;
- unsupported Apple-only semantics listed in the compatibility report;
- full automated verification passing;
- a clean AUR build and install/remove cycle;
- no known secret leaks, unsafe redirect behavior, unbounded provider process, or data-isolation violation.

## 13. Packaging and Updates

The project publishes:

1. a direct release archive containing the executable, QML plugin, desktop metadata, systemd unit, icons, completions, metainfo, licenses, checksums, and install instructions;
2. an AUR source package named `omarchy-ai-bar`;
3. optionally, an AUR prebuilt package named `omarchy-ai-bar-bin`.

Direct dependencies are declared even when stock Omarchy already contains them. Rust libraries are normally linked into the executable; Qt, GLib, Wayland, SQLite, Secret Service, and other stock platform libraries remain dynamic.

The application never modifies `/usr/share/omarchy/`. Packaged files live under the application's own `/usr/share` and `/usr/lib/systemd/user` locations. Per-user Omarchy integration is performed explicitly through `omarchy-ai-bar bridge` commands.

AUR/pacman is the update authority. The application may report that a newer package or bridge payload exists, but it does not download, replace, or execute an update itself. Bridge protocol compatibility spans at least one previous protocol major so package and user-plugin updates need not occur atomically.

## 14. Delivery Sequence

Implementation is internally decomposed while preserving the all-or-nothing release gate:

1. Repository, toolchain, licensing, CI, and parity-ledger foundation.
2. Desktop proof: QML widget/panel, private IPC, fallback tray, notifications, Secret Service, multiple monitors, and scaling.
3. Domain model, config, state actor, persistence, CLI framework, and test harness.
4. Shared provider transports and authentication adapters.
5. Provider batches until all 69 parity records pass.
6. Costs, histories, sessions, hooks, plugins, status, browser import, and HTTP server.
7. Full QML UI, settings, charts, localization, widgets, exports, and accessibility.
8. Platform-equivalence closure, security review, performance work, packaging, and release verification.

Each stage must leave its own tests passing. Later work cannot disable or waive earlier parity records to make progress appear complete.

## 15. Upstream Maintenance

The baseline commit is recorded in a checked-in manifest. After initial parity, an upstream-diff workflow compares the tracked CodexBar revision with a selected newer revision and reports:

- provider enum and registry changes;
- config and snapshot schema changes;
- new or removed data sources;
- parser and fixture changes;
- CLI/server contract changes;
- UI and platform-feature changes;
- licensing or bundled-resource changes.

Updates are deliberate ports, not runtime coupling. The application never fetches or executes CodexBar code.

## 16. Risks and Mitigations

| Risk | Mitigation |
| --- | --- |
| Very large baseline: roughly 295k source and 337k test lines | Capability boundaries, parity ledger, provider batching, fixture-first implementation, no partial-release claim |
| Undocumented provider APIs drift | Port exact fixtures/error semantics, isolate providers, keep last-known-good data, maintain upstream-diff report |
| Linux browser encryption/profile variance | Separate importer interface, audited profile support, manual fallback, keyring-disable option, fixture coverage |
| Omarchy plugin API changes | Small shell-facing service boundary, versioned IPC, validator/smoke tests against supported Omarchy releases, SNI fallback |
| QML must not retain secrets | Separate one-shot credential channel, immediate input clearing, no config-file reads, no secrets in display snapshots |
| Third-party JavaScript is hostile or buggy | QuickJS limits, explicit authorities, no arbitrary I/O, watchdog, strict result validation |
| Cross-provider identity leakage | Provider-instance-scoped domain types and tests; no global identity fallback in rendering |
| Rust async/process hangs | Single Tokio runtime, explicit deadlines, cancellation, bounded kill escalation, isolated PTY/storage threads |
| Package/user plugin versions diverge | Version handshake, compatibility window, explicit atomic bridge updater, fallback tray |
| Synchronized folders contain stale or hostile peer files | Non-secret schema, strict size/type validation, per-device files, atomic writes, identity redaction, no executable content |
| Upstream assets or code carry attribution obligations | MIT notice, third-party license bundle, provenance inventory, replacement of assets that cannot be redistributed |

## 17. Definition of Success

On a stock supported Omarchy installation, a user can install Omarchy AI Bar from an AUR package or release archive, enable its QML plugin, configure any baseline provider, and obtain the same applicable quota, reset, credit, cost, status, session, automation, CLI, dashboard, and non-secret fleet-aggregation capabilities represented by the pinned CodexBar baseline. The application presents those capabilities through an Omarchy-native approximation of the CodexBar UI, stores no state under CodexBar paths, runs all substantive behavior through one Rust executable, updates only through packaging, and clearly reports the two approved Apple-only semantic omissions.
