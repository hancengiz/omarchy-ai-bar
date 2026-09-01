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

search_files() {
  local pattern=$1
  shift
  if command -v rg >/dev/null 2>&1; then
    rg --no-config -n "$pattern" "$@"
  else
    grep -ERn -- "$pattern" "$@"
  fi
}

search_quiet() {
  local pattern=$1
  shift
  if command -v rg >/dev/null 2>&1; then
    rg --no-config -q "$pattern" "$@"
  else
    grep -Eq -- "$pattern" "$@"
  fi
}

search_count() {
  local pattern=$1
  shift
  if command -v rg >/dev/null 2>&1; then
    rg --no-config -c "$pattern" "$@"
  else
    grep -Ec -- "$pattern" "$@"
  fi
}

validate_layout() {
  local required=(
    install.sh
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
    scripts/build-release.sh
    scripts/verify-archive.sh
    scripts/upstream-diff.sh
    docs/security.md
    docs/compatibility.md
    docs/unsupported-apple-semantics.md
    docs/releasing.md
  )
  local path
  for path in "${required[@]}"; do
    require_file "$path"
  done

  bash -n "$repo_root/packaging/arch/PKGBUILD"
  bash -n "$repo_root/packaging/arch/omarchy-ai-bar.install"
  bash -n "$repo_root/install.sh"
  bash -n "$repo_root/scripts/build-release.sh"
  bash -n "$repo_root/scripts/live-smoke-omarchy.sh"

  local release_builder
  for release_builder in \
    "$repo_root/scripts/build-release.sh" \
    "$repo_root/packaging/arch/PKGBUILD"; do
    search_quiet 'CARGO_ENCODED_RUSTFLAGS=' "$release_builder" \
      || fail "$release_builder does not preserve encoded Rust flags"
    search_quiet 'remap-path-prefix=' "$release_builder" \
      || fail "$release_builder does not remap Rust source paths"
    search_quiet 'ffile-prefix-map=' "$release_builder" \
      || fail "$release_builder does not remap native source paths"
    search_quiet 'CC_SHELL_ESCAPED_FLAGS=1' "$release_builder" \
      || fail "$release_builder does not safely parse native prefix-map flags"
    search_quiet 'grep -aFq --' "$release_builder" \
      || fail "$release_builder does not reject leaked private build paths"
  done
  search_quiet 'CARGO_TARGET_DIR="\$release_target_dir"' \
    "$repo_root/scripts/build-release.sh" \
    || fail 'direct release build does not pin its Cargo target directory'
  search_quiet "^[[:space:]]*'libnotify'$" "$repo_root/packaging/arch/PKGBUILD" \
    || fail 'PKGBUILD is missing the notify-send runtime dependency'
  search_quiet '^[[:space:]]*depends = libnotify$' \
    "$repo_root/packaging/arch/.SRCINFO" \
    || fail '.SRCINFO is missing the notify-send runtime dependency'

  if find "$repo_root/qml/omarchy-plugin" -type l -print -quit | grep -q .; then
    fail 'QML plugin payload contains a symlink'
  fi
  if search_files '/usr/share/omarchy(/|["[:space:]])' \
    "$repo_root/packaging/arch/PKGBUILD" \
    "$repo_root/packaging/arch/omarchy-ai-bar.install" \
    "$repo_root/packaging/release/INSTALL.md" \
    "$repo_root/packaging/release/archive-layout.txt"; then
    fail 'packaging targets Omarchy-owned /usr/share files'
  fi
  if search_files '^[[:space:]]*(cp|install|mkdir|mv|rm)[[:space:]].*(\$HOME|~/)' \
    "$repo_root/packaging/arch/PKGBUILD" \
    "$repo_root/packaging/arch/omarchy-ai-bar.install"; then
    fail 'package lifecycle writes into a user home directory'
  fi

  local binary_install_count
  binary_install_count=$(search_count \
    '^[[:space:]]*install -Dm755 target/release/omarchy-ai-bar' \
    "$repo_root/packaging/arch/PKGBUILD")
  [[ $binary_install_count == 1 ]] || fail 'PKGBUILD must install exactly one project executable'
  search_quiet "^pkgname=omarchy-ai-bar$" "$repo_root/packaging/arch/PKGBUILD" \
    || fail 'source AUR package name drifted'
  ! search_quiet 'pkgname=.*-bin' "$repo_root/packaging/arch/PKGBUILD" \
    || fail 'prebuilt AUR package is not part of the source-package skeleton'
  for shell in bash fish zsh; do
    search_quiet "completion $shell" "$repo_root/packaging/arch/PKGBUILD" \
      || fail "PKGBUILD does not generate $shell completion"
  done

  search_quiet '^ExecStart=/usr/bin/omarchy-ai-bar daemon$' \
    "$repo_root/packaging/systemd/omarchy-ai-bar.service" \
    || fail 'systemd unit does not start the single executable'
  search_quiet '^Exec=omarchy-ai-bar dashboard$' \
    "$repo_root/packaging/desktop/org.omarchy_ai_bar.App.desktop" \
    || fail 'desktop launcher does not use the single executable'
  search_quiet '<id>org.omarchy_ai_bar.App</id>' \
    "$repo_root/packaging/metainfo/org.omarchy_ai_bar.App.metainfo.xml" \
    || fail 'metainfo application id drifted'
  search_quiet '"id": "local.omarchy-ai-bar"' "$repo_root/qml/omarchy-plugin/manifest.json" \
    || fail 'Omarchy plugin id drifted'
  search_quiet 'CURRENT_BRIDGE_PROTOCOL_MAJOR: u16 = 1' \
    "$repo_root/crates/cli/src/commands/bridge.rs" \
    || fail 'bridge protocol marker drifted'
  search_quiet 'MINIMUM_BRIDGE_PROTOCOL_MAJOR: u16 = CURRENT_BRIDGE_PROTOCOL_MAJOR - 1' \
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
    if file --brief "$file" | search_quiet '^ELF '; then
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
