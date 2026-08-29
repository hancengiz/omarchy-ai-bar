#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd -- "$script_dir/.." && pwd)
plugin_dir="$repo_root/qml/omarchy-plugin"
tests_dir="$repo_root/tests"
qml_test_dir="$tests_dir/qml"
service_test="$repo_root/service-state-test.qml"
termination_bridge="$tests_dir/quickshell/ignore-term-bridge"
live_harness="$repo_root/scripts/live-smoke-omarchy.sh"
qmlformat_bin=/usr/lib/qt6/bin/qmlformat
qmllint_bin=/usr/lib/qt6/bin/qmllint
qmltestrunner_bin=/usr/lib/qt6/bin/qmltestrunner
quickshell_bin=/usr/bin/quickshell
cargo_bin=${CARGO:-cargo}

if ! command -v "$cargo_bin" >/dev/null 2>&1; then
  cargo_home=${CARGO_HOME:-"$HOME/.cargo"}
  if [[ -x "$cargo_home/bin/cargo" ]]; then
    cargo_bin="$cargo_home/bin/cargo"
  fi
fi

if (( $# != 0 )); then
  echo "usage: $0" >&2
  exit 2
fi

for command in jq omarchy timeout "$qmlformat_bin" "$qmllint_bin" "$qmltestrunner_bin" "$quickshell_bin" "$cargo_bin"; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "required command is unavailable: $command" >&2
    exit 1
  fi
done

cd -- "$repo_root"
omarchy plugin validate "$plugin_dir"
/usr/bin/bash -n "$live_harness"

# Quickshell 0.3.1 exits successfully but emits this exact text sentinel,
# rather than `[]`, when a selected configuration has no running instances.
# The live recovery path normalizes that frozen contract before parsing JSON.
empty_registry=$(timeout 2 "$quickshell_bin" list \
  -p "$service_test" --any-display --json 2>/dev/null)
expected_empty_registry=$(printf \
  'No running instances for "%s"\nUse --all to list all instances.' "$service_test")
if [[ $empty_registry != "$expected_empty_registry" ]]; then
  echo "unexpected Quickshell empty-registry contract" >&2
  exit 1
fi
if [[ $empty_registry == "$expected_empty_registry" ]]; then
  empty_registry='[]'
fi
registry_filter='if length == 1 and (.[0] | type) == "array" then .[0] else error("unexpected registry envelope") end'
empty_registry=$(jq -cse "$registry_filter" <<<"$empty_registry")
jq -e 'length == 0' <<<"$empty_registry" >/dev/null
nonempty_registry='[{"config_path":"/frozen/shell.qml","pid":7}]'
normalized_nonempty_registry=$(jq -cse "$registry_filter" <<<"$nonempty_registry")
[[ $normalized_nonempty_registry == "$nonempty_registry" ]]
if jq -cse "$registry_filter" <<<'true' >/dev/null 2>&1; then
  echo "Quickshell registry envelope validator accepted a non-array" >&2
  exit 1
fi
for multiple_registries in $'[]\n[]' $'[{"pid":7}]\n[]'; do
  if jq -cse "$registry_filter" <<<"$multiple_registries" >/dev/null 2>&1; then
    echo "Quickshell registry envelope validator accepted multiple documents" >&2
    exit 1
  fi
done

if [[ ! -x "$termination_bridge" ]]; then
  echo "service lifecycle fixture is not executable: $termination_bridge" >&2
  exit 1
fi

format_dir=$(mktemp -d)
trap 'rm -rf -- "$format_dir"' EXIT

# The live witness log starts empty and becomes non-empty after the first
# filtered event. GNU stat's textual %F is size-sensitive, while raw %f keeps
# the device/inode/owner/type-mode identity stable across that append.
identity_probe="$format_dir/mutable-event.log"
: >"$identity_probe"
empty_identity=$(stat -c '%d:%i:%u:%f' -- "$identity_probe")
exec {identity_probe_fd}>>"$identity_probe"
fd_empty_identity=$(stat -L -c '%d:%i:%u:%f' -- "/proc/$$/fd/$identity_probe_fd")
[[ $fd_empty_identity == "$empty_identity" ]]
printf 'monitoradded>>fixture\n' >&"$identity_probe_fd"
nonempty_identity=$(stat -c '%d:%i:%u:%f' -- "$identity_probe")
fd_nonempty_identity=$(stat -L -c '%d:%i:%u:%f' -- "/proc/$$/fd/$identity_probe_fd")
[[ $nonempty_identity == "$empty_identity" ]]
[[ $fd_nonempty_identity == "$empty_identity" ]]
mv -- "$identity_probe" "$identity_probe.replaced"
: >"$identity_probe"
replacement_identity=$(stat -c '%d:%i:%u:%f' -- "$identity_probe")
fd_replaced_identity=$(stat -L -c '%d:%i:%u:%f' -- "/proc/$$/fd/$identity_probe_fd")
[[ $replacement_identity != "$empty_identity" ]]
[[ $fd_replaced_identity == "$empty_identity" ]]
exec {identity_probe_fd}>&-

format_failed=0
while IFS= read -r -d '' qml_file; do
  relative_path=${qml_file#"$repo_root/"}
  formatted_file="$format_dir/${relative_path//\//__}"
  "$qmlformat_bin" "$qml_file" >"$formatted_file"
  if ! cmp -s -- "$qml_file" "$formatted_file"; then
    echo "QML formatting differs: $relative_path" >&2
    format_failed=1
  fi
done < <(find "$plugin_dir" "$tests_dir" "$service_test" -type f \( -name '*.qml' -o -name '*.js' \) -print0 | sort -z)

if (( format_failed != 0 )); then
  exit 1
fi

"$qmllint_bin" \
  "$plugin_dir/Protocol.js" \
  "$qml_test_dir/tst_protocol.qml"

QT_QPA_PLATFORM=offscreen "$qmltestrunner_bin" \
  -input "$qml_test_dir" \
  -import /usr/lib/qt6/qml

service_test_output=""
if ! service_test_output=$(OMARCHY_AI_BAR_EXECUTABLE="$termination_bridge" QT_QPA_PLATFORM=offscreen timeout 10 \
  "$quickshell_bin" -n --no-color -p "$service_test" 2>&1); then
  printf '%s\n' "$service_test_output" >&2
  exit 1
fi
if [[ "$service_test_output" == *OAB_SERVICE_STATE_TEST_FAIL* || "$service_test_output" != *OAB_SERVICE_STATE_TEST_PASS* ]]; then
  printf '%s\n' "$service_test_output" >&2
  exit 1
fi

"$cargo_bin" test -p omarchy-ai-bar --test ui_socket_smoke --locked
