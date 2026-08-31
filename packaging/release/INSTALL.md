# Installing Omarchy AI Bar

The archive and Arch package install system-owned files only. They never copy
anything into a user's home directory during package installation.

## Direct release archive

Verify the adjacent checksum, extract the archive, then copy its `bin`, `lib`,
and `share` trees into `/usr`:

```sh
sha256sum --check omarchy-ai-bar-0.1.0-linux-x86_64.tar.gz.sha256
tar -xzf omarchy-ai-bar-0.1.0-linux-x86_64.tar.gz
cd omarchy-ai-bar-0.1.0
sudo cp -a bin lib share /usr/
systemctl --user daemon-reload
```

The AUR package performs the same system-owned installation through pacman.

After installing the files, run these commands as the desktop user:

```sh
omarchy-ai-bar bridge install
systemctl --user enable --now omarchy-ai-bar.service
```

Most provider modes need no extra executable. Install optional helpers only for
the credential flow you use:

- Codex supports its native credential files and HTTP flow. The `codex`
  executable enables app-server fallback.
- Claude reads Claude Code's Linux credential file and calls the OAuth usage
  endpoint natively; the CLI does not need to stay running.
- Grok usage uses the `grok agent stdio` billing RPC and therefore requires the
  Grok Build CLI plus `grok login`.
- z.ai Coding Plan is native and uses `Z_AI_API_KEY` (or the supported
  BigModel/GLM credential variables); no helper executable is required.

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

Then remove the package with pacman, or remove the exact direct-archive paths
listed in `SHA256SUMS`. Do not recursively remove shared `/usr` directories.
