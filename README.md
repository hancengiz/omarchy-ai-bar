# Omarchy AI Bar

Omarchy-native AI provider usage, quota, cost, and session monitoring.

Omarchy AI Bar is a Rust/Quickshell port inspired by
[CodexBar](https://github.com/steipete/CodexBar), used under the MIT License.

## Current end-to-end providers

The daemon, private display socket, Rust-to-QML bridge, refresh actions, and
CodexBar-style multi-provider panel are connected for all 69 native providers:

- Codex: native Codex credential files, HTTP usage, and `codex app-server`
  fallback.
- Claude: Claude Code's `~/.claude/.credentials.json` OAuth credential (or
  `CLAUDE_OAUTH_TOKEN`) and Anthropic's OAuth usage endpoint.
- Grok: `grok agent stdio` and its `x.ai/billing` RPC. Run `grok login` first.
- z.ai Coding Plan: `Z_AI_API_KEY`; the adapter also supports its existing
  region, team, endpoint, and BigModel environment options.
- OpenAI, Azure OpenAI, Fireworks, Moonshot, OpenRouter, Deepgram, Chutes,
  Neuralwatt, IBM Bob, xAI, LiteLLM, LLM Proxy, and sub2api through their
  native API-key or configured-endpoint adapters.
- Synthetic, DeepInfra, Venice, Poe, ZenMux, ai&, Warp, ClinePass, and
  ElevenLabs through native fixed-origin API adapters.
- AWS Bedrock, Vertex AI, JetBrains AI, Wayfinder, ClawRouter, Crof, and
  Codebuff through native cloud, local-data, API, or gateway adapters.
- Amp, Doubao, Kilo, Kiro, and Alibaba Token Plan through source-aware native
  API, cloud-credential, local-session, or shell-free CLI adapters.
- Abacus, Alibaba Coding Plan, Command Code, Devin, LongCat, Manus, MiniMax,
  Mistral, Notion AI, OpenCode, Perplexity, Qoder, Qwen Cloud, Sakana, StepFun,
  T3 Chat, and ZoomMate through native API-key or explicit manual-session
  adapters. Manual-session values use provider-specific
  `OMARCHY_AI_BAR_*_COOKIE` variables and never cross the QML IPC boundary.
- GitHub Copilot, Kimi, and Xiaomi MiMo through OAuth, source-aware
  API/CLI/manual-session selection, and bounded local usage data.
- DeepSeek wallet balance, Groq Prometheus usage rates, and Ollama Cloud
  credential/catalog status through their native APIs.
- OpenCode Go through its public bearer-authenticated rolling, weekly, and
  monthly usage API.
- Zed through its cloud account API, including limited or unlimited edit
  predictions, billing-cycle state, plan identity, and invoice warnings.
- Augment through the shell-free `auggie account status` CLI path, including
  current and legacy credit-report formats.
- Gemini through the Cloud Code quota API using an explicit OAuth access token,
  with Pro, Flash, and Flash Lite tiers grouped like CodexBar.
- Factory (Droid) through `FACTORY_API_KEY`, including authenticated account,
  organization, plan, Standard-token, and Premium-token state.
- Cursor through an explicit `OMARCHY_AI_BAR_CURSOR_COOKIE` session, including
  Total, Auto/Composer, and named-model usage from `/api/usage-summary`.
- Antigravity through its remote Google quota endpoint, grouping Gemini and
  Claude/GPT quota families from an explicit OAuth access token.
- Windsurf through the Omarchy/Linux VS Code-compatible state database,
  including daily/weekly quota percentages and legacy message/flow counters.

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
omarchy-ai-bar guard --max-used 90
```

Configuration validation, Secret Service credentials, cache management,
hooks, local JavaScript providers, and the loopback JSON API are documented in
[`docs/operations.md`](docs/operations.md). Run `omarchy-ai-bar --help` or any
subcommand with `--help` for the complete command reference.

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

The `AI` widget should appear in the Omarchy bar. Left-click opens the provider
rows; middle/right-click refreshes them. To remove the development
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
[`docs/compatibility.md`](docs/compatibility.md),
[`docs/operations.md`](docs/operations.md), and
[`docs/releasing.md`](docs/releasing.md).
