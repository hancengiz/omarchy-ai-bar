#!/usr/bin/env bash
# Rebuilds this checkout and reinstalls the Omarchy AI Bar plugin from it.
#
# The bar widget keeps using this repository's build: the bridge payload comes
# from qml/omarchy-plugin and OMARCHY_AI_BAR_EXECUTABLE points the shell at
# target/release. Run this after changing Rust code or plugin QML; nothing is
# written to /usr.
set -euo pipefail

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)

cargo build --release --locked --manifest-path "$repo_root/Cargo.toml"

OMARCHY_AI_BAR_BRIDGE_SOURCE="$repo_root/qml/omarchy-plugin" \
  "$repo_root/target/release/omarchy-ai-bar" bridge update

hyprctl eval \
  "hl.env(\"OMARCHY_AI_BAR_EXECUTABLE\", \"$repo_root/target/release/omarchy-ai-bar\")"

if [[ -f $HOME/.config/systemd/user/omarchy-ai-bar.service ]]; then
  systemctl --user restart omarchy-ai-bar.service
fi

omarchy restart shell
printf 'dev-install: plugin reinstalled from %s\n' "$repo_root"
