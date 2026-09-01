# Installing Omarchy AI Bar

GitHub releases provide an Arch package and a direct archive for Omarchy
4.0.1 or newer on x86-64. Both install one Rust executable plus its QML and
desktop support files. Neither changes a user's home directory during the
system installation.

## One-line installer

Run the hosted installer as the normal desktop user:

```sh
curl -fsSL https://raw.githubusercontent.com/hancengiz/omarchy-ai-bar/main/install.sh | bash
```

It resolves the latest GitHub release and verifies the Arch package against
its adjacent SHA-256 file before invoking pacman. Review `install.sh` first if
you do not want to execute a script from the mutable `main` branch.

## GitHub Arch package (recommended)

Download the package and adjacent checksum from the
[v0.3.0 release](https://github.com/hancengiz/omarchy-ai-bar/releases/tag/v0.3.0),
then verify and install it through pacman:

```sh
sha256sum --check omarchy-ai-bar-0.3.0-1-x86_64.pkg.tar.zst.sha256
sudo pacman -U --needed ./omarchy-ai-bar-0.3.0-1-x86_64.pkg.tar.zst
```

## Direct release archive

Verify the adjacent checksum, extract the archive, then copy its `bin`, `lib`,
and `share` trees into `/usr` without preserving the extracting user's
ownership:

```sh
sha256sum --check omarchy-ai-bar-0.3.0-linux-x86_64.tar.gz.sha256
tar -xzf omarchy-ai-bar-0.3.0-linux-x86_64.tar.gz
cd omarchy-ai-bar-0.3.0
sudo cp -a --no-preserve=ownership --remove-destination -- bin lib share /usr/
systemctl --user daemon-reload
```

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
- Grok first tries the `grok agent stdio` billing RPC, then reads the valid
  owner-managed `~/.grok/auth.json` session for the authenticated billing
  proxy. Install the Grok Build CLI and run `grok login`; it does not need to
  remain running.
- z.ai Coding Plan is native and uses `Z_AI_API_KEY` (or the supported
  BigModel/GLM credential variables); no helper executable is required.

`bridge install` copies the packaged QML plugin from the application's own
`/usr/share/omarchy-ai-bar` directory, validates it with Omarchy, atomically
places it under the user's Omarchy plugin directory, rescans, and enables it.

After a GitHub package upgrade, refresh the user bridge and restart the daemon:

```sh
omarchy-ai-bar bridge update
systemctl --user restart omarchy-ai-bar.service
```

For a direct-archive upgrade, stop the running executable, repeat the verified
extraction with the newer version, and copy the three trees using the same
ownership-safe command above. Then reload, update, and restart:

```sh
systemctl --user stop omarchy-ai-bar.service
sudo cp -a --no-preserve=ownership --remove-destination -- bin lib share /usr/
systemctl --user daemon-reload
omarchy-ai-bar bridge update
systemctl --user start omarchy-ai-bar.service
```

The bridge command already asks Omarchy to rescan the plugin. Do not immediately
chain `omarchy restart shell`; restart only if the rescan fails or the widget
does not update.

The update refuses unrecognized or locally modified plugin trees. Omarchy's
placement, enabled state, and settings are stored outside that tree and remain
unchanged. There is no application self-updater; install newer packages or
direct archives from GitHub Releases.

## Uninstall

Before removing system-owned files, run these commands as the desktop user:

```sh
systemctl --user disable --now omarchy-ai-bar.service
omarchy-ai-bar bridge uninstall
```

For a package-managed installation, finish with:

```sh
omarchy pkg drop omarchy-ai-bar
```

For a direct-archive installation, remove only these application-owned paths:

```sh
sudo rm -f -- \
  /usr/bin/omarchy-ai-bar \
  /usr/lib/systemd/user/omarchy-ai-bar.service \
  /usr/share/applications/org.omarchy_ai_bar.App.desktop \
  /usr/share/bash-completion/completions/omarchy-ai-bar \
  /usr/share/fish/vendor_completions.d/omarchy-ai-bar.fish \
  /usr/share/icons/hicolor/scalable/apps/org.omarchy_ai_bar.App.svg \
  /usr/share/metainfo/org.omarchy_ai_bar.App.metainfo.xml \
  /usr/share/zsh/site-functions/_omarchy-ai-bar \
  /usr/share/doc/omarchy-ai-bar/INSTALL.md \
  /usr/share/licenses/omarchy-ai-bar/LICENSE \
  /usr/share/licenses/omarchy-ai-bar/NOTICE
sudo rm -rf -- /usr/share/omarchy-ai-bar
systemctl --user daemon-reload
```

Do not recursively remove any shared `/usr` directory other than the exact
application-owned `/usr/share/omarchy-ai-bar` path above.
