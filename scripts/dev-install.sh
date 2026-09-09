#!/usr/bin/env bash
# Rebuilds this checkout and reinstalls the Omarchy AI Bar plugin from it.
#
# The bar widget keeps using this repository's build: the bridge payload comes
# from qml/omarchy-plugin and OMARCHY_AI_BAR_EXECUTABLE points the shell at
# target/release. Run this after changing Rust code or plugin QML; nothing is
# written to /usr.
#
# OMARCHY_AI_BAR_EXECUTABLE is persisted in ~/.config/environment.d because
# hyprctl hl.env only reaches the currently running Hyprland; without the file
# every reboot would silently fall the shell back to /usr/bin/omarchy-ai-bar.
set -euo pipefail

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)

cargo build --release --locked --manifest-path "$repo_root/Cargo.toml"

OMARCHY_AI_BAR_BRIDGE_SOURCE="$repo_root/qml/omarchy-plugin" \
  "$repo_root/target/release/omarchy-ai-bar" bridge update

executable="$repo_root/target/release/omarchy-ai-bar"

# Durable override for future sessions: the user session environment that
# launches Hyprland (and with it omarchy-launch-shell) reads environment.d.
environment_dir=$HOME/.config/environment.d
mkdir -p "$environment_dir"
environment_file=$environment_dir/60-omarchy-ai-bar-dev.conf
tmp_file=$environment_file.tmp.$$
printf 'OMARCHY_AI_BAR_EXECUTABLE=%s\n' "$executable" >"$tmp_file"
mv -f "$tmp_file" "$environment_file"

# Immediate override for the current session: hl.env reaches processes Hyprland
# spawns from now on, which includes the restarted shell.
hyprctl eval "hl.env(\"OMARCHY_AI_BAR_EXECUTABLE\", \"$executable\")"

if [[ -f $HOME/.config/systemd/user/omarchy-ai-bar.service ]]; then
  systemctl --user restart omarchy-ai-bar.service
fi

omarchy restart shell
printf 'dev-install: plugin reinstalled from %s\n' "$repo_root"
