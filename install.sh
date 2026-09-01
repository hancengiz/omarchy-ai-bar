#!/usr/bin/env bash
set -euo pipefail

readonly repository='https://github.com/hancengiz/omarchy-ai-bar'
work_dir=''

die() {
  printf 'omarchy-ai-bar installer: %s\n' "$*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "required command is unavailable: $1"
}

main() {
  ((EUID != 0)) || die 'run this installer as your desktop user, not as root'
  [[ $(uname -s) == Linux ]] || die 'only Linux is supported'
  [[ $(uname -m) == x86_64 ]] || die 'this release supports x86_64 only'

  local command_name=''
  for command_name in curl mktemp omarchy pacman sha256sum sudo systemctl; do
    require_command "$command_name"
  done

  local release_url='' tag='' version='' asset='' download_url=''
  release_url=$(curl --fail --location --silent --show-error \
    --output /dev/null --write-out '%{url_effective}' "$repository/releases/latest")
  tag=${release_url##*/}
  [[ $tag =~ ^v([0-9]+\.[0-9]+\.[0-9]+)$ ]] || \
    die 'GitHub returned an invalid latest-release tag'
  version=${BASH_REMATCH[1]}
  asset="omarchy-ai-bar-$version-1-x86_64.pkg.tar.zst"
  download_url="$repository/releases/download/$tag"

  work_dir=$(mktemp -d)
  trap 'rm -rf -- "$work_dir"' EXIT
  cd "$work_dir"

  printf 'Downloading Omarchy AI Bar %s...\n' "$version"
  curl --fail --location --silent --show-error --remote-name \
    "$download_url/$asset"
  curl --fail --location --silent --show-error --remote-name \
    "$download_url/$asset.sha256"
  sha256sum --check --strict "$asset.sha256"

  sudo pacman -U --needed --noconfirm "./$asset"
  systemctl --user daemon-reload

  local bridge_status=''
  bridge_status=$(omarchy-ai-bar bridge status)
  case $bridge_status in
    'Omarchy bridge: not installed')
      omarchy-ai-bar bridge install
      ;;
    *'installed ('*'matches package)'*)
      printf '%s\n' "$bridge_status"
      ;;
    *'installed ('*)
      omarchy-ai-bar bridge update
      ;;
    *)
      die "$bridge_status; refusing to replace the existing bridge"
      ;;
  esac

  systemctl --user enable omarchy-ai-bar.service
  systemctl --user restart omarchy-ai-bar.service
  omarchy-ai-bar bridge status
  printf 'Omarchy AI Bar %s is installed and running.\n' "$version"
}

main "$@"
