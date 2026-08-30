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
systemctl --user set-environment \
  OMARCHY_AI_BAR_EXECUTABLE="$PWD/target/release/omarchy-ai-bar"
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
systemctl --user unset-environment OMARCHY_AI_BAR_EXECUTABLE
omarchy restart shell
```

The daemon/display integration is also covered without live credentials:

```sh
cargo test -p omarchy-ai-bar --test daemon_display_e2e
```
