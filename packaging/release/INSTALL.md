# Installing Omarchy AI Bar

The archive and Arch package install system-owned files only. They never copy
anything into a user's home directory during package installation.

After installing the files, run these commands as the desktop user:

```sh
omarchy-ai-bar bridge install
systemctl --user enable --now omarchy-ai-bar.service
```

Most provider modes need no extra executable. Install optional helpers only for
the credential flow you use:

- `aws-cli-v2` enables AWS profiles, SSO, assume-role, and
  `credential_process` authentication for Bedrock. Static AWS credentials do
  not require it.
- `google-cloud-cli` enables Vertex AI service-account token acquisition and
  `gcloud auth application-default login`. User ADC refresh tokens are handled
  natively.
- Doubao supports native API-key and Volcengine AK/SK modes. Ark CLI is also
  supported when installed separately, but no maintained Arch/AUR package was
  available when this release was prepared.
- `ampcode` provides the `amp` executable for Amp's CLI source. Amp API-key
  mode is native and does not require the helper.
- `kiro-cli` provides Kiro login, profile discovery, and usage. Kiro requires
  this executable because its provider interface is CLI-driven.
- `kilo-cli-git` can perform Kilo login and populate the provider's local auth
  file. Omarchy AI Bar reads that file and calls Kilo's API itself; a direct
  `KILO_API_KEY` does not require the CLI package.
- JetBrains AI quota discovery reads Linux XDG configuration/data roots and
  requires no Apple framework or additional executable. AppCode discovery is
  omitted because AppCode is macOS-only and has no Omarchy counterpart; the
  supported JetBrains IDE families use their Linux configuration roots.
- Codebuff API-key mode is native. Local-login mode reads the provider-owned
  `manicode/credentials.json`; no maintained Codebuff Arch/AUR package was
  located when checked on 2026-08-30, so use Codebuff's official installer if
  you need its login command.

`bridge install` copies the packaged QML plugin from the application's own
`/usr/share/omarchy-ai-bar` directory, validates it with Omarchy, atomically
places it under the user's Omarchy plugin directory, rescans, and enables it.

After an AUR/pacman or direct-archive upgrade, refresh only the user bridge:

```sh
omarchy-ai-bar bridge update
```

The update refuses unrecognized or locally modified plugin trees. Omarchy's
placement, enabled state, and settings are stored outside that tree and remain
unchanged. There is no application self-updater; install package updates through
AUR/pacman or replace the direct-release files yourself.

Before uninstalling system-owned files, run:

```sh
systemctl --user disable --now omarchy-ai-bar.service
omarchy-ai-bar bridge uninstall
```
