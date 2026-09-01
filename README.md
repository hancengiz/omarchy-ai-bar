# Omarchy AI Bar

Omarchy-native AI provider usage, quota, cost, and session monitoring.

Omarchy AI Bar was ported from
[CodexBar](https://github.com/steipete/CodexBar), used under the MIT License,
and customized for Omarchy by [Cengiz Han](https://cengizhan.bio). Source code:
[github.com/hancengiz/omarchy-ai-bar](https://github.com/hancengiz/omarchy-ai-bar).

## Install on Omarchy

Omarchy AI Bar supports Omarchy 4.0.1 or newer on x86-64. Releases are
published on the [GitHub Releases page](https://github.com/hancengiz/omarchy-ai-bar/releases/latest);
an AUR account is not required.

### One-line install

Run this as your normal desktop user. It downloads the latest Arch package,
verifies its published SHA-256, installs it through pacman, activates or
updates the Omarchy bridge, and starts the user service. Pacman confirmation
is non-interactive because the script itself arrives over standard input; sudo
may still request your password through the terminal:

```sh
curl -fsSL https://github.com/hancengiz/omarchy-ai-bar/releases/latest/download/install.sh | bash
```

The installer and its checksum are published by GitHub Actions alongside each
release. The package is always checksum-verified before installation.

### Manual package install

Download the package and its checksum, verify it, then install it through
pacman so upgrades and removal remain package-managed:

```sh
release=0.3.0
asset="omarchy-ai-bar-$release-1-x86_64.pkg.tar.zst"
base_url="https://github.com/hancengiz/omarchy-ai-bar/releases/download/v$release"
curl --fail --location --remote-name "$base_url/$asset"
curl --fail --location --remote-name "$base_url/$asset.sha256"
sha256sum --check "$asset.sha256"
sudo pacman -U --needed "./$asset"
```

Activate the Omarchy bar plugin and start the user service:

```sh
omarchy-ai-bar bridge install
systemctl --user enable --now omarchy-ai-bar.service
omarchy-ai-bar bridge status
```

The plugin should now appear in the Omarchy bar. Open its gear menu to enable
and configure providers.

### Direct archive fallback

If the Arch package cannot be used, install the verified release archive:

```sh
release=0.3.0
archive="omarchy-ai-bar-$release-linux-x86_64.tar.gz"
base_url="https://github.com/hancengiz/omarchy-ai-bar/releases/download/v$release"
curl --fail --location --remote-name "$base_url/$archive"
curl --fail --location --remote-name "$base_url/$archive.sha256"
sha256sum --check "$archive.sha256"
tar -xzf "$archive"
cd "omarchy-ai-bar-$release"
sudo cp -a --no-preserve=ownership --remove-destination -- bin lib share /usr/
systemctl --user daemon-reload
omarchy-ai-bar bridge install
systemctl --user enable --now omarchy-ai-bar.service
```

`omarchy plugin add` alone is not sufficient: it clones the QML surface but
cannot install the Rust daemon or systemd user unit.

### Upgrade or uninstall

For a package upgrade, download the newer GitHub package, verify it, run
`sudo pacman -U ./omarchy-ai-bar-<version>-1-x86_64.pkg.tar.zst`, then refresh
the user-owned QML copy:

```sh
omarchy-ai-bar bridge update
systemctl --user restart omarchy-ai-bar.service
```

For direct-archive upgrades, stop the service, repeat the verified extraction
and `cp` command above with the newer archive, then run the same bridge update
and service restart.

To uninstall a package-managed installation:

```sh
systemctl --user disable --now omarchy-ai-bar.service
omarchy-ai-bar bridge uninstall
omarchy pkg drop omarchy-ai-bar
```

See the [complete installation guide](packaging/release/INSTALL.md) for direct
archive upgrades and exact manual-removal paths, and
[`docs/operations.md`](docs/operations.md) for provider credentials,
configuration, diagnostics, hooks, and the local API.

## Current provider coverage

The daemon, private display socket, Rust-to-QML bridge, refresh actions, and
CodexBar-style multi-provider panel share one closed registry of all 69 native
providers. The adapters below are implemented, but source, settings, and
presentation parity is still tracked explicitly in [`parity/`](parity/) and is
not claimed complete until that ledger's strict completion gate passes. The
current implementation and gap audit is in
[`docs/codexbar-parity.md`](docs/codexbar-parity.md):

- Codex: native Codex credential files, HTTP usage, and `codex app-server`
  fallback, with runtime-backed Auto/PAT/OAuth/CLI source selection.
- Claude: Claude Code's `~/.claude/.credentials.json` OAuth credential (or
  `CLAUDE_OAUTH_TOKEN`) and Anthropic's OAuth usage endpoint, plus a bounded
  shell-free interactive Claude CLI `/usage` capture and Auto fallback.
- Grok: `grok agent stdio`, then the authenticated Grok CLI billing proxy from
  a valid `~/.grok/auth.json` session, plus explicit source selection, a named
  manual cookie slot, and lazy isolated browser web billing. Run `grok login`
  first.
- z.ai Coding Plan: `Z_AI_API_KEY`; the adapter also supports its existing
  region, team, endpoint, and BigModel environment options. Global/BigModel CN
  region and API-key controls are available in typed settings.
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
  T3 Chat, and ZoomMate through native browser/manual-session adapters. Linux
  browser discovery is currently wired for Abacus, Amp, Command Code, Devin,
  Kimi, MiniMax, Mistral, Notion AI, OpenCode, Perplexity, Qwen Cloud, and
  T3 Chat, with more providers tracked in the parity ledger.
  Manual-session values use provider-specific
  `OMARCHY_AI_BAR_*_COOKIE` variables and are never serialized into the
  daemon/display protocol.
- GitHub Copilot through an app-owned GitHub OAuth device flow plus bounded,
  read-only local Copilot history. Omarchy AI Bar never borrows or changes the
  Copilot CLI or GitHub CLI credential. Optional budget bars use a separate
  manual GitHub Cookie slot and never reuse the OAuth token. Kimi and Xiaomi
  MiMo use their source-aware API/CLI/manual-session adapters.
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

The usage menu shows only configured, enabled providers. Providers are off by
default unless a concrete local client, credential, or account is detected, or
the user explicitly enables one. The normal settings page therefore stays
compact; **Add Provider** opens the searchable 69-provider catalog separately.
Provider pages include account/source details, quota windows, reset times,
credits, errors, secure credential or native login actions, dashboard links,
menu-bar selection, and warning controls. Codex, Claude, Grok, Copilot, and z.ai
use value-free typed descriptors; implemented controls persist into the Rust
runtime and unavailable CodexBar controls remain visibly disabled. Credentials
are never serialized into provider descriptors, JSON configuration, or the
daemon display protocol; secure fields use a bounded one-shot helper input and
retain only configured status.

## Use

Click the `AI` bar widget to open the compact provider cards. The gear opens
provider settings; select a provider to enable it and configure its supported
Linux login or credential flow. Middle- or right-click refreshes every enabled
provider. Drag the small handle along the menu's bottom edge to resize it;
the height is clamped to the current monitor and saved in Omarchy's native
bar-widget settings. Double-click the handle, or use **Display & Menu → Reset**,
to restore the default height. Display mode, selected bar provider,
used/remaining direction, reset visibility, desktop quota notifications, and
warning threshold use the same settings store.

The same live daemon state is scriptable:

```sh
omarchy-ai-bar usage
omarchy-ai-bar cards --format json
omarchy-ai-bar usage --format toon
omarchy-ai-bar diagnose --format json
omarchy-ai-bar dashboard
omarchy-ai-bar guard --max-used 90
omarchy-ai-bar config describe codex --format json
omarchy-ai-bar config set-option claude claude-usage-source auto
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
