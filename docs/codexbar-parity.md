# CodexBar parity status

The behavioral reference is CodexBar commit
`1680b4ed5bca69f167d388ed17a5b2c36dd05d1f`. Omarchy AI Bar treats that
checkout as a read-only specification; it does not read CodexBar application
state or execute Swift code at runtime.

The provider registry contains the same 69 first-party provider IDs. Registry
coverage alone is not feature parity. The machine-readable records under
[`../parity`](../parity/) remain authoritative, and a complete-release claim is
blocked until `scripts/verify-parity-ledger.sh --all-complete` passes.

## Implemented product slice

- One Rust executable owns the daemon, CLI, provider adapters, local API, and
  Omarchy bridge transport.
- The usage panel shows enabled providers that were detected, have usable
  current or retained data, or were explicitly enabled by the user. An
  explicitly enabled provider keeps a setup/error card before its first
  successful sample. Quota windows, reset times, pace, credits, cost summaries,
  and local history charts are rendered inline when the provider supplies them.
- Refresh scheduling keeps last-known-good data for retryable failures, honors
  provider retry hints and reset boundaries, and uses faster bounded refresh
  while the panel is open. A rate-limited provider can therefore keep showing
  its last usable statistics instead of becoming an empty card.
- App-owned credentials use freedesktop Secret Service. Explicit process
  environment values retain precedence.
- Copilot uses an application-owned GitHub OAuth token and never reads, writes,
  logs out, or rotates Copilot CLI or GitHub CLI credentials. Its local CLI
  history reader uses a private read-only SQLite snapshot.
- Supported Linux browser sessions are lazy authentication fallbacks. They do
  not run during provider detection, do not auto-enable providers, and never
  replace an explicit manual credential.
- GitHub Releases and pacman-installed release packages replace Sparkle; AUR
  publication is deferred. systemd user services replace the login item,
  freedesktop notifications replace Apple notifications, and Quickshell QML
  replaces the native status menu and WidgetKit surface.

## Typed settings foundation and flagship slice

CodexBar's provider implementations define typed toggles, pickers, fields,
actions, dependencies, and account editors. Omarchy AI Bar now projects the
same five flagship inventories through value-free Rust descriptors: 9 Codex
controls, 11 Claude controls, 3 Grok controls, 5 Copilot controls, and 2 z.ai
controls. The CLI exposes them through `config describe`; the QML provider page
renders them by descriptor instead of maintaining a second provider-specific
form.

Only an item with a real runtime path is editable. Upstream controls retained
for layout and gap tracking are labelled unavailable, and `config set-option`
rejects them rather than storing a value the daemon would ignore. Implemented
non-secret values are validated and written to the ordinary configuration;
implemented secret fields target exact, account-scoped Secret Service slots.
Secret values are absent from the descriptor, JSON configuration, and
daemon/display snapshots.

| Provider | Runtime-backed in this slice | Still unavailable from the pinned settings surface |
| --- | --- | --- |
| Codex | Auto/PAT/OAuth/CLI quota source; explicit opt-in to read-only legacy Codex/OpenCode OAuth fallback; isolated managed-account login, switching, removal, and per-account refresh | OpenAI web extras and cookies, battery saver, configurable history/cost/display filters, and promotion of a managed account into the native Codex CLI |
| Claude | Auto/OAuth/CLI source selection; read-only Claude Code OAuth file/environment; bounded shell-free CLI usage fallback | Admin API, claude.ai web-cookie source, `claude-swap`, macOS Keychain policy, display/widget filters, multi-account UI |
| Grok | Auto/CLI/OAuth/Web source and Auto/Manual/Off cookie policy; CLI, read-only OAuth proxy, manual/browser web billing, dashboard, and provider-token-file actions | SuperGrok bearer gRPC enrichment, persistent cookie cache, and multi-account token management |
| Copilot | App-owned GitHub login with pre-storage identity validation, enterprise host, CLI/chat entitlement rows, manual budget extras/cookie slot, and refresh action | Automatic GitHub browser-cookie import, secondary menu-bar budget selection, multiple GitHub accounts |
| z.ai | Global/BigModel CN region, API-key slot, and region-aware credential-page action | Team-scope organization/project editor and multi-account UI |

The generic provider page remains for the other 64 providers. The storage
schema already has bounded non-secret fields for source, cookie policy, extras,
region, workspace, project, organization, team, enterprise host, deployment,
and provider-specific extensions, but those fields are not parity claims until
the provider descriptor, CLI mutation, QML control, and adapter projection are
all connected and tested.

Named slots are also only a foundation. They prevent paired credentials from
being collapsed into one ambiguous secret, but the remaining providers still
need purpose-specific descriptors and runtime hydration. Examples include AWS
Bedrock access/secret keys, Doubao token/secret, OpenRouter inference and
management keys, and StepFun username/password or token modes.

## Copilot credential and budget isolation

The Copilot OAuth device flow writes one application-owned OAuth key only after
an exact-origin, bounded GitHub `/user` identity check succeeds. Status and
logout address only that exact key, while an explicit `COPILOT_API_TOKEN`
continues to win as an environment-owned override. No Copilot or GitHub CLI
credential is imported, refreshed, deleted, or rewritten. This separation is
intentional: running the bar does not alter an authenticated `copilot` CLI
session's local credential. The request matches pinned CodexBar's GitHub device
client `Iv1.b507a08c87ecfe98` and sole `read:user` scope, but its returned token
remains in Omarchy AI Bar's own credential slot. The card also shows GitHub's
separate CLI and Chat entitlement flags when present, explaining why account
quota retrieval can succeed while a CLI model request is policy-disabled.

Optional budget bars use a different credential and authority. The current
end-to-end path requires `copilot-budget-extras=true`, the manual cookie source,
and the named `copilot-budget-cookie` slot. GitHub OAuth login does not provide
that browser cookie. Missing or invalid optional budget input does not replace
otherwise valid base Copilot usage. Automatic browser discovery for budget
cookies remains an explicit gap.

## Source and fallback parity

Codex source selection is runtime-backed: Auto follows the pinned source plan,
while explicit PAT, OAuth, and CLI modes stay within their selected authority.
External legacy Codex and OpenCode OAuth files are off by default, read only
after explicit consent, and are never refreshed or written. Managed Codex
accounts, system-account promotion, and chatgpt.com dashboard extras are not yet
ported.

Claude Auto tries the read-only OAuth usage path and then the provider-owned
Claude CLI. Explicit OAuth and CLI are terminal single-source choices. The CLI
runs bounded `claude auth status --json`, then opens a restricted interactive
PTY, submits `/usage`, captures the rendered quota report, and terminates and
reaps the process group. The path is shell-free, uses an isolated working
directory, strips secret environment overrides, disables updater/nonessential
traffic, removes its probe-owned transcript artifact, and never writes Claude
credentials. As a deliberate safety divergence from CodexBar, OAuth rate-limit
and permission errors do not fan out into a CLI request. Missing/expired
credentials and provider/network/parse/API failures may advance to the CLI. A
successful CLI sample is reused for up to 15 minutes by automatic refreshes,
after OAuth has still been attempted first in Auto mode. CLI failures are never
cached, any reported quota reset invalidates the entry, and an explicit manual
refresh always bypasses it. CLI rate limits carry a cooldown hint, and the
shared runtime retains last-known-good usage.

Grok's pinned Auto order is CLI, SuperGrok OAuth, browser cookies, then bearer
gRPC. The Rust adapter implements explicit Auto/CLI/OAuth/Web plans, the CLI
JSON-RPC lane, the read-only OAuth billing proxy, a named manual cookie slot,
and lazy isolated browser discovery. Manual reads only `grok-web-cookie`; Off
never reads cookies. In Auto, every non-cancelled CLI failure advances to
OAuth. Chrome-family, Firefox, and Zen profiles use the web gRPC
endpoint, require `sso` or `sso-rw`, and rotate past stale sessions. Browser
discovery is attached only for Auto/Web with the Auto cookie policy and is
reached only after the final source reports missing/expired authentication;
rate, network, provider, permission, parse, and API failures do not trigger a
browser scan. Bearer gRPC enrichment, persistent cookie caching, and
multi-account lifecycle remain unavailable.

## Remaining account, settings, and presentation gaps

Codex now has the complete app-owned managed-account lifecycle needed for the
bar: isolated `CODEX_HOME` login, identity-aware duplicate replacement, active
selection, recoverable removal, independent refresh/last-known-good state, one
runtime scope per enabled account, and account controls in both the popup and
settings. The native `~/.codex` account remains an explicit `ambient` choice
and is never overwritten. Promotion of a managed account into the native Codex
CLI is still open, as are Copilot account switching, Claude token
accounts/`claude-swap`, Grok bearer accounts, and z.ai team accounts.

Global settings still need complete daemon-backed refresh policy, provider
ordering, menu-bar layout controls, per-provider and per-window warnings,
depleted and predictive alerts, cost-range/comparison controls, provider
storage reporting, localization/currency, power-aware cadence, hooks/plugins
panes, and a documented Hyprland shortcut.

The QML popup now follows CodexBar's immediate-statistics hierarchy and supports
inline quota/cost/history content, provider settings, a persistent
monitor-bounded drag height, and a dynamic Codex account switcher. It is not
yet exact presentation parity: multi-account menus for the remaining providers,
all provider-specific actions, share/storage surfaces,
complete keyboard/accessibility behavior, localization/RTL, reduced motion,
and multi-monitor/fractional-scale verification remain open ledger items.

## Omarchy adaptations

Implementable equivalents:

- Launch at login: systemd user-unit enablement.
- Global shortcut: a generated or documented Hyprland binding.
- Low-power refresh: power-profiles-daemon or UPower-aware scheduling.
- Credential consent: explicit browser/provider-file access plus Secret
  Service for app-owned values.
- Alerts and celebration: the notification daemon, optional audio, or a
  Quickshell overlay.
- Status-item layout and overview: Quickshell widget layout controls.

Intentionally unsupported Apple semantics are limited to encrypted Apple
Keychain/app-group secret synchronization and WidgetKit timeline/app-group host
semantics. See [`unsupported-apple-semantics.md`](unsupported-apple-semantics.md).
