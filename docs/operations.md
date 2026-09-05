# Operations

`omarchy-ai-bar daemon` is the single long-running backend used by the Omarchy
widget, CLI projections, local API, and StatusNotifierItem fallback. GitHub
Releases distribute the Arch package and direct archive; the package definition
supplies a user service:

```sh
systemctl --user enable --now omarchy-ai-bar.service
systemctl --user status omarchy-ai-bar.service
journalctl --user -u omarchy-ai-bar.service
```

## Read-only output and automation

`usage`, `cards`, `dashboard`, `cost`, `sessions`, and `diagnose` read the live
daemon. Each accepts `--format human`, `--format json`, or `--format toon`.
Machine-readable output is written only to standard output; failures and
diagnostics use standard error.

The quota guard is suitable for scripts and CI:

```sh
omarchy-ai-bar guard --max-used 90
omarchy-ai-bar guard --provider codex --max-used 80 --quiet
```

It exits successfully when the policy permits work and exits with status 10
when the configured threshold denies work. Missing daemon state is reported as
unavailable instead of being treated as permission.

The optional HTTP projection listens only on a loopback address:

```sh
omarchy-ai-bar serve --listen 127.0.0.1:43129
curl http://127.0.0.1:43129/health
```

Read-only endpoints are `/health`, `/v1/usage`, `/v1/cards`, `/v1/cost`,
`/v1/sessions`, and `/v1/diagnose`. Responses disable caching. The server does
not accept a non-loopback listen address.

## Configuration and cache

The configuration commands operate on the XDG application configuration:

```sh
omarchy-ai-bar config path
omarchy-ai-bar config init
omarchy-ai-bar config show --format json
omarchy-ai-bar config validate ./config.json
omarchy-ai-bar config describe codex --format json
omarchy-ai-bar config enable claude
omarchy-ai-bar config disable claude
omarchy-ai-bar config reorder zai codex claude
omarchy-ai-bar config set-option codex codex-usage-source oauth
omarchy-ai-bar config set-option codex codex-usage-source --clear
omarchy-ai-bar config set-endpoint litellm https://llm.example.net
omarchy-ai-bar config set-endpoint litellm --clear
omarchy-ai-bar cache status
omarchy-ai-bar cache clear
```

Configuration contains non-secret policy only. One base endpoint can be saved
for Azure OpenAI, Kimi, Ollama, Groq, ClawRouter, OpenRouter, Wayfinder,
sub2api, LLM Proxy, LiteLLM, Neuralwatt, Codebuff, Chutes, and Deepgram. Each
adapter applies its own HTTPS/private-network policy, and an explicit service
environment value wins over the saved route. Providers with multiple endpoint
roles, including z.ai, intentionally do not expose an ambiguous single field.
Provider environment variables and supported native credential files remain
active inputs.

`config describe [PROVIDER]` is the public, value-free schema used by the QML
settings renderer. The current typed slice covers Codex, Claude, Grok, Copilot,
and z.ai. It describes pickers, toggles, plain fields, named secret slots,
actions, dependencies, and whether each item is implemented. It contains no
selected values, environment-variable names, credential paths, or secrets.
Only controls marked `implemented` can be changed; a described CodexBar control
that has no Linux runtime path is visible as unavailable instead of being saved
and ignored.

The runtime-backed non-secret settings are:

| Provider | Setting key | Accepted values |
| --- | --- | --- |
| Codex | `codex-usage-source` | `auto`, `pat`, `oauth`, `cli` |
| Codex | `codex-external-oauth-sources` | `true`, `false` |
| Claude | `claude-usage-source` | `auto`, `oauth`, `cli` |
| Grok | `grok-usage-source` | `auto`, `cli`, `oauth`, `web` |
| Grok | `grok-cookie-source` | `auto`, `manual`, `off` |
| Copilot | `copilot-budget-extras` | `true`, `false` |
| Copilot | `copilot-budget-cookie-source` | `manual` |
| Copilot | `copilot-enterprise-host` | a validated GitHub host |
| z.ai | `zai-api-region` | `global`, `bigmodel-cn` |

Claude Auto tries its read-only OAuth endpoint before a bounded interactive
Claude CLI PTY capture. OAuth rate limits and permission failures are terminal
and continue to use the shared last-known-good/backoff behavior; they do not
launch another request through the CLI. A successful CLI sample is reused for
up to 15 minutes by automatic refreshes, after OAuth has still been attempted
first in Auto mode. CLI failures are never cached, any reported quota reset
invalidates the entry, and an explicit manual refresh always bypasses it. Grok
Auto advances from every non-cancelled CLI failure to its read-only OAuth proxy;
only a final missing or expired authentication result can enter an eligible web
session. Browser discovery is lazy and is only attached for Auto/Web with the
Auto cookie policy; it is never performed during provider detection.

Use `--clear` instead of a value to restore any setting to its provider default.
Direct CLI mutations are applied after the user service restarts; the QML
settings page performs that restart automatically.

Enable/disable changes take effect when the daemon restarts; the Omarchy panel
does this automatically when its provider switch is used. Disabled providers
are omitted from daemon polling and from the usage menu. With no explicit route,
a provider is enabled only when its local client, credential, or account can be
detected; the complete registry remains available under **Add Provider**.
`cache clear` is restricted to the application-owned XDG cache directory and
does not follow symlinks.

## Managed provider credentials

Providers with a single API key, access token, or manual browser session can
read an app-owned credential from the desktop Secret Service. Explicit service
environment values keep precedence. `credential` is the preferred command;
`cookie` remains an exact compatibility alias. List the supported canonical
IDs and the adapter environment route with:

```sh
omarchy-ai-bar credential list
```

Credential input is accepted only from a pipe, never from an echoing terminal:

```sh
printf '%s\n' "$SESSION_VALUE" | omarchy-ai-bar credential set cursor
omarchy-ai-bar credential status cursor
omarchy-ai-bar credential delete cursor
```

Add `--account NAME` to isolate more than one stored credential for providers
using the generic credential store.

Codex has a dedicated CodexBar-compatible account lifecycle. Use **Add
account** on the Codex settings page or run `omarchy-ai-bar codex login`; each
login receives a private application-owned `CODEX_HOME`. Use
`omarchy-ai-bar codex list`, `codex activate <ID>`, and `codex remove <ID>` to
manage the same accounts from a terminal. `ambient` selects the native Codex
CLI account. Managed accounts refresh in independent daemon scopes, and none
of these operations overwrite `~/.codex/auth.json`.

Each account's banked resets appear in the account switcher and settings list.
OAuth quota refreshes fetch inventory with the same credential snapshot and
account header; CLI results are enriched only after matching their identity to
the scoped OAuth credential. PAT-only accounts show inventory as unavailable.
An inventory error does not discard quota usage or reuse inventory from an
older successful sample. A zero balance is shown explicitly, retained balances
are marked last known, and known expirations are updated while the UI is open.
This feature never redeems a reset. Normalized reset IDs use an installation-local
private `privacy-key` in the application data directory.

Typed providers may expose more than one purpose-specific credential. Supply
the exact descriptor slot with `--slot`; unsupported provider/slot pairs are
rejected before Secret Service is opened:

```sh
printf '%s\n' "$Z_AI_API_KEY" \
  | omarchy-ai-bar credential set zai --slot zai-api-key
omarchy-ai-bar credential status zai --slot zai-api-key

printf '%s\n' "$GITHUB_COOKIE_HEADER" \
  | omarchy-ai-bar credential set copilot --slot copilot-budget-cookie
omarchy-ai-bar credential delete copilot --slot copilot-budget-cookie

printf '%s\n' "$GROK_COOKIE_HEADER" \
  | omarchy-ai-bar credential set grok --slot grok-web-cookie
```

Secret values are not representable in the JSON configuration or provider
descriptor and are never included in daemon/display snapshots. The QML form
sends one bounded newline-delimited value directly to the credential helper's
standard input, clears its pending copy as soon as the helper starts, and only
retains `configured`/`not configured` status. z.ai's typed API-key control
continues to use the primary 0.2.x Secret Service key so an existing key is not
silently shadowed. Copilot's budget-cookie slot is distinct from its OAuth-token
key.

## GitHub Copilot authentication

Copilot uses a GitHub OAuth device flow owned by Omarchy AI Bar. The resulting
token is stored under an exact application-specific Secret Service key; the
bar does not read, write, log out, or rotate Copilot CLI or GitHub CLI
credentials. The request deliberately matches pinned CodexBar's device flow:
GitHub client `Iv1.b507a08c87ecfe98` with the single `read:user` scope. Sharing
that public request identity does not share the returned token or its local
storage.

Normal background refresh never starts the device flow or mints a token. It
only reads the bar's exact Secret Service item into private in-process provider
state and performs authenticated `GET` requests. Current Copilot CLI releases
instead look for `COPILOT_GITHUB_TOKEN`, `GH_TOKEN`, or `GITHUB_TOKEN`, then the
`copilot-cli` system-keychain item, and finally GitHub CLI; Omarchy AI Bar reads
and writes none of those locations. See GitHub's
[Copilot CLI authentication reference](https://docs.github.com/en/copilot/how-tos/copilot-cli/set-up-copilot-cli/authenticate-copilot-cli).

A user-requested `omarchy-ai-bar copilot login` does create a separate GitHub
OAuth token. GitHub limits a user to ten tokens for the same OAuth app and
scope combination and can revoke an older token after that limit is exceeded,
so repeatedly manufacturing logins should be avoided. That remote OAuth limit
does not make the local credential stores shared, and one or a few ordinary AI
Bar logins do not edit the CLI's saved credential. See GitHub's
[OAuth token-limit documentation](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps#creating-multiple-tokens-for-oauth-apps).

```sh
omarchy-ai-bar copilot login
omarchy-ai-bar copilot status
omarchy-ai-bar copilot logout
```

Successful login enables Copilot and reloads the user service so the new token
is available to the daemon. A newly issued token must pass a bounded GitHub
`/user` identity check before the bar reads or writes its credential item.
Login proves GitHub identity, but active Copilot feature access still depends
on the account's subscription, assigned seat, and organization policy. When
GitHub supplies them, the usage card shows separate **Copilot CLI** and
**Copilot Chat** entitlement rows. Local token history may remain visible when
current cloud access is unavailable; it is historical data, not proof of
current entitlement.

If Copilot CLI completes its authenticated account self-fetch and prints its
welcome message before the service rejects feature/model access with HTTP 403
and `not authorized to use this Copilot feature`, its credential has already
been accepted. GitHub documents that invalid credentials initially produce
HTTP 401, while insufficient authorization can produce HTTP 403; its Copilot
documentation also confirms that seats and organization or enterprise policies
govern CLI access. That evidence points to server-side entitlement or policy,
not Omarchy AI Bar overwriting the CLI credential. It does not identify which
seat or policy needs correction. See GitHub's
[Copilot CLI authentication troubleshooting](https://docs.github.com/en/copilot/how-tos/copilot-cli/set-up-copilot-cli/troubleshoot-copilot-cli-auth)
and [Copilot policy model](https://docs.github.com/en/copilot/concepts/policies).

For GitHub Enterprise, save the host before starting the device flow. The host
is normalized and unsafe, credential-bearing, or loopback inputs are rejected:

```sh
omarchy-ai-bar config set-option \
  copilot copilot-enterprise-host octocorp.ghe.com
omarchy-ai-bar copilot login
```

Copilot budget bars are a separate, optional web enrichment. The OAuth login
does not produce the `github.com` browser cookie they require. Automatic
browser-cookie import is not implemented yet; the current end-to-end path is a
manual Cookie header in its own slot:

```sh
omarchy-ai-bar config set-option copilot copilot-budget-extras true
omarchy-ai-bar config set-option \
  copilot copilot-budget-cookie-source manual
printf '%s\n' "$GITHUB_COOKIE_HEADER" \
  | omarchy-ai-bar credential set copilot --slot copilot-budget-cookie
systemctl --user restart omarchy-ai-bar.service
```

Use **Refresh budgets** in Copilot settings (or refresh Copilot normally) after
the service reloads. A missing or invalid optional budget cookie does not replace
the base Copilot API result. The menu-bar secondary-budget selector and
automatic GitHub browser-cookie discovery remain unavailable and are labelled
that way in the typed settings page.

## Hooks

`omarchy-ai-bar hooks path` prints the private hook directory. Supported exact
filenames are `daemon-started`, `provider-updated`, `refresh-completed`,
`warning`, and `session-detected`.

```sh
install -m 700 ./my-warning-hook "$(omarchy-ai-bar hooks path)/warning"
omarchy-ai-bar hooks list
omarchy-ai-bar hooks run warning
```

Hooks are invoked without a shell, with a cleared environment and discarded
output, and are terminated after 30 seconds. A hook must be a same-owner,
regular executable that is not group- or world-writable. The current release
provides explicit hook execution; automatic event-triggered execution is not
enabled yet.

## Local JavaScript providers

`omarchy-ai-bar plugins path` prints the private plugin directory. A source
file must be a safe same-owner `.js` regular file and assign this contract:

```js
globalThis.omarchyAiBarPlugin = {
  id: "example",
  name: "Example",
  version: 1,
  collect() {
    return {
      provider: "example",
      state: "ready",
      used_percent: 42
    };
  }
};
```

Validate or sample a source without installing it:

```sh
omarchy-ai-bar plugins validate ./example.js
omarchy-ai-bar plugins run ./example.js --format json
```

Plugins run inside embedded QuickJS with source, result, heap, stack, and time
limits. No filesystem, process, browser, or network host API is exposed. The
current release evaluates plugins explicitly; it does not merge plugin samples
into the live 69-provider daemon registry.

## Omarchy bridge lifecycle

The packaged QML payload is copied into the user-owned Omarchy plugin tree so
package operations never overwrite Omarchy files:

```sh
omarchy-ai-bar bridge install
omarchy-ai-bar bridge status
omarchy-ai-bar bridge update
omarchy-ai-bar bridge uninstall
```

Install, update, and uninstall ask Omarchy to reload the plugin registry. A
package upgrade does not silently rewrite the user's bridge; run `bridge
update` after pacman installs a newer version. Do not immediately follow a
successful bridge update with `omarchy restart shell`: the update already
requests a live rescan, and a simultaneous full restart can race Quickshell's
plugin replacement. Restart only when the rescan fails or the widget remains
on the previous payload.
