# Omarchy AI Bar

Omarchy-native AI provider usage, quota, cost, and session monitoring.

The project is under active development against the approved design in
[`docs/superpowers/specs/2026-08-29-omarchy-ai-bar-design.md`](docs/superpowers/specs/2026-08-29-omarchy-ai-bar-design.md).

Omarchy AI Bar is a Rust/Quickshell port inspired by
[CodexBar](https://github.com/steipete/CodexBar), used under the MIT License.

## Current end-to-end provider slice

The daemon, private display socket, Rust-to-QML bridge, refresh actions, and
CodexBar-style multi-provider panel are connected for:

- Codex: native Codex credential files, HTTP usage, and `codex app-server`
  fallback.
- Claude: Claude Code's `~/.claude/.credentials.json` OAuth credential (or
  `CLAUDE_OAUTH_TOKEN`) and Anthropic's OAuth usage endpoint.
- Grok: `grok agent stdio` and its `x.ai/billing` RPC. Run `grok login` first.
- z.ai Coding Plan: `Z_AI_API_KEY`; the adapter also supports its existing
  region, team, endpoint, and BigModel environment options.

Providers without configured credentials remain visible with a safe setup
status instead of disappearing. Credentials are never sent over the QML IPC.

## Install

On Omarchy, install the AUR package and activate the per-user plugin and
service:

```sh
omarchy pkg aur add omarchy-ai-bar
omarchy-ai-bar bridge install
systemctl --user enable --now omarchy-ai-bar.service
```

Package upgrades remain under pacman/AUR control. After an upgrade, refresh
the user-owned QML copy without changing its bar placement or settings:

```sh
omarchy-ai-bar bridge update
```

Direct release archives contain the same single executable and support files.
See [`packaging/release/INSTALL.md`](packaging/release/INSTALL.md) for the
system-wide copy and removal commands.

## Use

Click the `AI` bar widget to open the provider panel. Middle- or right-click
refreshes every provider. Display mode, selected bar provider, used/remaining
direction, reset visibility, setup rows, and warning threshold use Omarchy's
native bar-widget settings.

The same live daemon state is scriptable:

```sh
omarchy-ai-bar usage
omarchy-ai-bar cards --format json
omarchy-ai-bar usage --format toon
omarchy-ai-bar diagnose --format json
omarchy-ai-bar dashboard
```

## Build and visually test on Omarchy

Build the single Rust executable:

```sh
cargo build --release --locked
```

Install the repository's QML bridge into your user Omarchy configuration and
tell a restarted Omarchy shell to use the development executable:

```sh
OMARCHY_AI_BAR_BRIDGE_SOURCE="$PWD/qml/omarchy-plugin" \
  "$PWD/target/release/omarchy-ai-bar" bridge install
hyprctl eval \
  "hl.env(\"OMARCHY_AI_BAR_EXECUTABLE\", \"$PWD/target/release/omarchy-ai-bar\")"
omarchy restart shell
```

Then start the daemon in a terminal from this repository (add provider
environment variables to this command if needed):

```sh
target/release/omarchy-ai-bar daemon
```

The `AI` widget should appear in the Omarchy bar. Left-click opens all four
provider rows; middle/right-click refreshes them. To remove the development
bridge afterward:

```sh
target/release/omarchy-ai-bar bridge uninstall
hyprctl eval 'hl.env("OMARCHY_AI_BAR_EXECUTABLE", "")'
omarchy restart shell
```

The daemon/display integration is also covered without live credentials:

```sh
cargo test -p omarchy-ai-bar --test daemon_display_e2e
```

Security, platform compatibility, and release maintenance are documented in
[`docs/security.md`](docs/security.md),
[`docs/compatibility.md`](docs/compatibility.md), and
[`docs/releasing.md`](docs/releasing.md).
