#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
version=${1:-$(sed -n 's/^version = "\([^"]*\)"/\1/p' "$repo_root/Cargo.toml" | head -n 1)}
[[ $version =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]] || {
  echo "build-release: invalid version" >&2
  exit 2
}

fail() {
  printf 'build-release: %s\n' "$*" >&2
  exit 1
}

resolve_remap_path() {
  local output_name=$1 label=$2 input=$3 resolved=""
  [[ -n $input ]] || fail "$label path is empty"
  case $input in
  *$'\n'* | *$'\r'* | *$'\t'* | *$'\x1f'* | *=*)
    fail "$label path contains a character unsupported by compiler prefix maps"
    ;;
  esac
  resolved=$(realpath -m -- "$input") || fail "could not resolve $label path"
  [[ $resolved == /* && $resolved != / ]] || fail "$label path is unsafe"
  printf -v "$output_name" '%s' "$resolved"
}

resolve_logical_remap_path() {
  local output_name=$1 label=$2 input=$3 resolved=""
  [[ -n $input ]] || fail "$label path is empty"
  case $input in
  *$'\n'* | *$'\r'* | *$'\t'* | *$'\x1f'* | *=*)
    fail "$label path contains a character unsupported by compiler prefix maps"
    ;;
  esac
  resolved=$(realpath -ms -- "$input") || fail "could not normalize $label path"
  [[ $resolved == /* && $resolved != / ]] || fail "$label path is unsafe"
  printf -v "$output_name" '%s' "$resolved"
}

append_encoded_rustflag() {
  local output_name=$1 flag=$2 current=""
  current=${!output_name-}
  [[ -z $current ]] || current+=$'\x1f'
  current+=$flag
  printf -v "$output_name" '%s' "$current"
}

append_native_flag() {
  local output_name=$1 flag=$2 current="" quoted=""
  current=${!output_name-}
  printf -v quoted '%q' "$flag"
  [[ -z $current ]] || current+=' '
  current+=$quoted
  printf -v "$output_name" '%s' "$current"
}

cargo_bin=${CARGO:-cargo}
command -v "$cargo_bin" >/dev/null 2>&1 || {
  echo "build-release: cargo executable not found" >&2
  exit 1
}
dist_dir="$repo_root/dist"
archive_name="omarchy-ai-bar-$version-linux-x86_64.tar.gz"
temporary_root=$(mktemp -d)
trap 'rm -rf -- "$temporary_root"' EXIT
stage="$temporary_root/omarchy-ai-bar-$version"
release_target_dir="$repo_root/target"

cd -- "$repo_root"
release_source_root=""
cargo_home_input=${CARGO_HOME:-}
if [[ -z $cargo_home_input ]]; then
  [[ -n ${HOME:-} ]] || fail 'neither CARGO_HOME nor HOME is set'
  cargo_home_input=$HOME/.cargo
fi
release_cargo_home=""
release_cargo_home_logical=""
resolve_remap_path release_source_root 'source root' "$repo_root"
resolve_remap_path release_cargo_home 'Cargo home' "$cargo_home_input"
resolve_logical_remap_path release_cargo_home_logical 'Cargo home' "$cargo_home_input"

release_rustflags=""
if [[ ${CARGO_ENCODED_RUSTFLAGS+x} ]]; then
  release_rustflags=$CARGO_ENCODED_RUSTFLAGS
else
  caller_rustflags=${RUSTFLAGS:-}
  caller_rustflags=${caller_rustflags//$'\n'/ }
  caller_rustflags=${caller_rustflags//$'\r'/ }
  read -r -a caller_rustflag_words <<<"$caller_rustflags"
  for caller_rustflag in "${caller_rustflag_words[@]}"; do
    append_encoded_rustflag release_rustflags "$caller_rustflag"
  done
fi

release_cflags=${CFLAGS:-}
release_cxxflags=${CXXFLAGS:-}
declare -a private_build_paths=("$release_cargo_home_logical")
if [[ $release_cargo_home != "$release_cargo_home_logical" ]]; then
  private_build_paths+=("$release_cargo_home")
fi
private_build_paths+=("$release_source_root")
for private_build_path in "${private_build_paths[@]}"; do
  if [[ $private_build_path == "$release_source_root" ]]; then
    native_destination="/usr/src/debug/omarchy-ai-bar-$version"
  else
    native_destination='/usr/src/debug/cargo-home'
  fi
  append_encoded_rustflag release_rustflags \
    "--remap-path-prefix=$private_build_path=$native_destination"
  append_native_flag release_cflags \
    "-ffile-prefix-map=$private_build_path=$native_destination"
  append_native_flag release_cxxflags \
    "-ffile-prefix-map=$private_build_path=$native_destination"
done

CARGO_ENCODED_RUSTFLAGS="$release_rustflags" \
  CC_SHELL_ESCAPED_FLAGS=1 \
  CFLAGS="$release_cflags" \
  CXXFLAGS="$release_cxxflags" \
  CARGO_TARGET_DIR="$release_target_dir" \
  "$cargo_bin" build --release --locked --package omarchy-ai-bar

for private_build_path in "${private_build_paths[@]}"; do
  if LC_ALL=C grep -aFq -- \
    "$private_build_path" "$release_target_dir/release/omarchy-ai-bar"; then
    fail 'release executable contains an unremapped private build path'
  fi
done

install -Dm755 "$release_target_dir/release/omarchy-ai-bar" \
  "$stage/bin/omarchy-ai-bar"
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
"$release_target_dir/release/omarchy-ai-bar" completion bash \
  >"$stage/share/bash-completion/completions/omarchy-ai-bar"
"$release_target_dir/release/omarchy-ai-bar" completion fish \
  >"$stage/share/fish/vendor_completions.d/omarchy-ai-bar.fish"
"$release_target_dir/release/omarchy-ai-bar" completion zsh \
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
