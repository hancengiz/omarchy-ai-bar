#!/usr/bin/env bash

set -euo pipefail

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
mode=${1:-}

fail() {
  printf 'verify-package: %s\n' "$*" >&2
  exit 1
}

require_file() {
  [[ -f $repo_root/$1 ]] || fail "missing $1"
}

validate_layout() {
  local required=(
    packaging/arch/PKGBUILD
    packaging/arch/.SRCINFO
    packaging/arch/omarchy-ai-bar.install
    packaging/systemd/omarchy-ai-bar.service
    packaging/desktop/org.omarchy_ai_bar.App.desktop
    packaging/metainfo/org.omarchy_ai_bar.App.metainfo.xml
    packaging/release/INSTALL.md
    packaging/release/archive-layout.txt
    packaging/release/org.omarchy_ai_bar.App.svg
    qml/omarchy-plugin/manifest.json
  )
  local path
  for path in "${required[@]}"; do
    require_file "$path"
  done

  bash -n "$repo_root/packaging/arch/PKGBUILD"
  bash -n "$repo_root/packaging/arch/omarchy-ai-bar.install"

  if find "$repo_root/qml/omarchy-plugin" -type l -print -quit | grep -q .; then
    fail 'QML plugin payload contains a symlink'
  fi
  if rg -n '/usr/share/omarchy(/|["[:space:]])' \
    "$repo_root/packaging/arch" "$repo_root/packaging/release"; then
    fail 'packaging targets Omarchy-owned /usr/share files'
  fi
  if rg -n '^[[:space:]]*(cp|install|mkdir|mv|rm)[[:space:]].*(\$HOME|~/)' \
    "$repo_root/packaging/arch"; then
    fail 'package lifecycle writes into a user home directory'
  fi

  local binary_install_count
  binary_install_count=$(rg -c 'target/release/omarchy-ai-bar' \
    "$repo_root/packaging/arch/PKGBUILD")
  [[ $binary_install_count == 1 ]] || fail 'PKGBUILD must install exactly one project executable'
  rg -q "^pkgname=omarchy-ai-bar$" "$repo_root/packaging/arch/PKGBUILD" \
    || fail 'source AUR package name drifted'
  ! rg -q 'pkgname=.*-bin' "$repo_root/packaging/arch/PKGBUILD" \
    || fail 'prebuilt AUR package is not part of the source-package skeleton'

  rg -q '^ExecStart=/usr/bin/omarchy-ai-bar daemon$' \
    "$repo_root/packaging/systemd/omarchy-ai-bar.service" \
    || fail 'systemd unit does not start the single executable'
  rg -q '^Exec=omarchy-ai-bar dashboard$' \
    "$repo_root/packaging/desktop/org.omarchy_ai_bar.App.desktop" \
    || fail 'desktop launcher does not use the single executable'
  rg -q '<id>org.omarchy_ai_bar.App</id>' \
    "$repo_root/packaging/metainfo/org.omarchy_ai_bar.App.metainfo.xml" \
    || fail 'metainfo application id drifted'
  rg -q '"id": "local.omarchy-ai-bar"' "$repo_root/qml/omarchy-plugin/manifest.json" \
    || fail 'Omarchy plugin id drifted'
  rg -q 'CURRENT_BRIDGE_PROTOCOL_MAJOR: u16 = 1' \
    "$repo_root/crates/cli/src/commands/bridge.rs" \
    || fail 'bridge protocol marker drifted'
  rg -q 'MINIMUM_BRIDGE_PROTOCOL_MAJOR: u16 = CURRENT_BRIDGE_PROTOCOL_MAJOR - 1' \
    "$repo_root/crates/cli/src/commands/bridge.rs" \
    || fail 'previous-major compatibility window is missing'

  if command -v desktop-file-validate >/dev/null 2>&1; then
    desktop-file-validate "$repo_root/packaging/desktop/org.omarchy_ai_bar.App.desktop"
  fi
  if command -v appstreamcli >/dev/null 2>&1; then
    appstreamcli validate --no-net \
      "$repo_root/packaging/metainfo/org.omarchy_ai_bar.App.metainfo.xml"
  fi
  if command -v makepkg >/dev/null 2>&1; then
    local generated_srcinfo
    generated_srcinfo=$(
      cd "$repo_root/packaging/arch"
      makepkg --printsrcinfo
    )
    [[ $generated_srcinfo == "$(<"$repo_root/packaging/arch/.SRCINFO")" ]] \
      || fail 'committed .SRCINFO does not match PKGBUILD'
  fi
}

validate_package_root() {
  local package_root=$1
  [[ -d $package_root ]] || fail "package root not found: $package_root"
  [[ ! -e $package_root/usr/share/omarchy ]] \
    || fail 'package root contains Omarchy-owned /usr/share content'
  [[ ! -e $package_root/home ]] || fail 'package root contains a home directory'

  local elf_count=0
  local file
  while IFS= read -r -d '' file; do
    if file --brief "$file" | rg -q '^ELF '; then
      elf_count=$((elf_count + 1))
      [[ $file == "$package_root/usr/bin/omarchy-ai-bar" ]] \
        || fail "unexpected project ELF: $file"
    fi
  done < <(find "$package_root" -type f -print0)
  [[ $elf_count == 1 ]] || fail "expected one project ELF, found $elf_count"
}

case "$mode" in
--layout-only)
  [[ $# == 1 ]] || fail 'usage: verify-package.sh --layout-only'
  validate_layout
  ;;
--package-root)
  [[ $# == 2 ]] || fail 'usage: verify-package.sh --package-root PATH'
  validate_layout
  validate_package_root "$2"
  ;;
*)
  fail 'usage: verify-package.sh --layout-only | --package-root PATH'
  ;;
esac

printf 'Package verification passed.\n'
