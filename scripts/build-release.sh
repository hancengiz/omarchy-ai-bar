#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
version=${1:-$(sed -n 's/^version = "\([^"]*\)"/\1/p' "$repo_root/Cargo.toml" | head -n 1)}
[[ $version =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]] || {
  echo "build-release: invalid version" >&2
  exit 2
}

cargo_bin=${CARGO:-/home/hancengiz/.cargo/bin/cargo}
command -v "$cargo_bin" >/dev/null 2>&1 || cargo_bin=cargo
dist_dir="$repo_root/dist"
archive_name="omarchy-ai-bar-$version-linux-x86_64.tar.gz"
temporary_root=$(mktemp -d)
trap 'rm -rf -- "$temporary_root"' EXIT
stage="$temporary_root/omarchy-ai-bar-$version"

cd -- "$repo_root"
"$cargo_bin" build --release --locked --package omarchy-ai-bar

install -Dm755 target/release/omarchy-ai-bar "$stage/bin/omarchy-ai-bar"
install -Dm644 packaging/systemd/omarchy-ai-bar.service \
  "$stage/lib/systemd/user/omarchy-ai-bar.service"
install -Dm644 packaging/desktop/org.omarchy_ai_bar.App.desktop \
  "$stage/share/applications/org.omarchy_ai_bar.App.desktop"
install -Dm644 packaging/metainfo/org.omarchy_ai_bar.App.metainfo.xml \
  "$stage/share/metainfo/org.omarchy_ai_bar.App.metainfo.xml"
install -Dm644 packaging/release/org.omarchy_ai_bar.App.svg \
  "$stage/share/icons/hicolor/scalable/apps/org.omarchy_ai_bar.App.svg"
install -dm755 "$stage/share/omarchy-ai-bar/omarchy-plugin"
cp -a -- qml/omarchy-plugin/. "$stage/share/omarchy-ai-bar/omarchy-plugin/"
install -Dm644 LICENSE "$stage/LICENSE"
install -Dm644 NOTICE "$stage/NOTICE"
install -Dm644 packaging/release/INSTALL.md "$stage/INSTALL.md"

install -dm755 \
  "$stage/share/bash-completion/completions" \
  "$stage/share/fish/vendor_completions.d" \
  "$stage/share/zsh/site-functions"
target/release/omarchy-ai-bar completion bash \
  >"$stage/share/bash-completion/completions/omarchy-ai-bar"
target/release/omarchy-ai-bar completion fish \
  >"$stage/share/fish/vendor_completions.d/omarchy-ai-bar.fish"
target/release/omarchy-ai-bar completion zsh \
  >"$stage/share/zsh/site-functions/_omarchy-ai-bar"

(
  cd -- "$stage"
  find . -type f ! -name SHA256SUMS -print0 \
    | LC_ALL=C sort -z \
    | xargs -0 sha256sum >SHA256SUMS
)

mkdir -p -- "$dist_dir"
source_date_epoch=${SOURCE_DATE_EPOCH:-$(git -C "$repo_root" log -1 --format=%ct)}
tar --sort=name --format=posix --owner=0 --group=0 --numeric-owner \
  --mtime="@$source_date_epoch" --pax-option=delete=atime,delete=ctime \
  -C "$temporary_root" -cf - "omarchy-ai-bar-$version" \
  | gzip -n -9 >"$dist_dir/$archive_name"
(
  cd -- "$dist_dir"
  sha256sum "$archive_name" >"$archive_name.sha256"
)

"$repo_root/scripts/verify-archive.sh" "$dist_dir/$archive_name"
printf 'Built %s\n' "$dist_dir/$archive_name"
