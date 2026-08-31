# Operations

`omarchy-ai-bar daemon` is the single long-running backend used by the Omarchy
widget, CLI projections, local API, and StatusNotifierItem fallback. The AUR
package supplies a user service:

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
omarchy-ai-bar cache status
omarchy-ai-bar cache clear
```

Configuration contains non-secret policy only. Provider environment variables
and supported native credential files remain the active provider inputs.
`cache clear` is restricted to the application-owned XDG cache directory and
does not follow symlinks.

## Managed manual sessions

Providers that need a manual browser session can read one from the desktop
Secret Service. List the supported canonical IDs with:

```sh
omarchy-ai-bar cookie list
```

Credential input is accepted only from a pipe, never from an echoing terminal:

```sh
printf '%s' "$SESSION_VALUE" | omarchy-ai-bar cookie set cursor
omarchy-ai-bar cookie status cursor
omarchy-ai-bar cookie delete cursor
```

Add `--account NAME` to isolate more than one stored account. A matching
provider environment variable takes precedence over Secret Service.

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
update` after pacman installs a newer version.
