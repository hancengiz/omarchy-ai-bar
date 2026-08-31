#!/usr/bin/env bash
set -euo pipefail

archive=${1:-}
[[ $# == 1 && -f $archive ]] || {
  echo "usage: verify-archive.sh ARCHIVE.tar.gz" >&2
  exit 2
}

fail() {
  printf 'verify-archive: %s\n' "$*" >&2
  exit 1
}

temporary_root=$(mktemp -d)
trap 'rm -rf -- "$temporary_root"' EXIT

while IFS= read -r entry; do
  [[ -n $entry && $entry != /* && $entry != *'/../'* && $entry != '../'* ]] \
    || fail 'archive contains an unsafe path'
done < <(tar -tzf "$archive")

tar --no-same-owner --no-same-permissions -xzf "$archive" -C "$temporary_root"
mapfile -t roots < <(find "$temporary_root" -mindepth 1 -maxdepth 1 -type d -print)
[[ ${#roots[@]} == 1 ]] || fail 'archive must contain exactly one root directory'
root=${roots[0]}

required=(
  bin/omarchy-ai-bar
  lib/systemd/user/omarchy-ai-bar.service
  share/applications/org.omarchy_ai_bar.App.desktop
  share/icons/hicolor/scalable/apps/org.omarchy_ai_bar.App.svg
  share/metainfo/org.omarchy_ai_bar.App.metainfo.xml
  share/omarchy-ai-bar/omarchy-plugin/manifest.json
  share/bash-completion/completions/omarchy-ai-bar
  share/fish/vendor_completions.d/omarchy-ai-bar.fish
  share/zsh/site-functions/_omarchy-ai-bar
  LICENSE
  NOTICE
  INSTALL.md
  SHA256SUMS
)
for path in "${required[@]}"; do
  [[ -f $root/$path && ! -L $root/$path ]] || fail "missing $path"
done
[[ -x $root/bin/omarchy-ai-bar ]] || fail 'binary is not executable'

if find "$root" -type l -print -quit | grep -q .; then
  fail 'archive contains a symbolic link'
fi
(
  cd -- "$root"
  sha256sum --quiet --check SHA256SUMS
)

elf_count=0
while IFS= read -r -d '' file; do
  if file --brief "$file" | grep -q '^ELF '; then
    elf_count=$((elf_count + 1))
    [[ $file == "$root/bin/omarchy-ai-bar" ]] || fail "unexpected ELF: $file"
  fi
done < <(find "$root" -type f -print0)
[[ $elf_count == 1 ]] || fail "expected one ELF executable, found $elf_count"

"$root/bin/omarchy-ai-bar" version --json \
  | jq -e '.name == "omarchy-ai-bar" and (.version | type == "string")' >/dev/null \
  || fail 'binary identity is invalid'

printf 'Archive verification passed.\n'
