# Installing Omarchy AI Bar

The archive and Arch package install system-owned files only. They never copy
anything into a user's home directory during package installation.

After installing the files, run these commands as the desktop user:

```sh
omarchy-ai-bar bridge install
systemctl --user enable --now omarchy-ai-bar.service
```

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
