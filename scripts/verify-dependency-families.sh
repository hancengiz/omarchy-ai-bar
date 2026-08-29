#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd -- "$script_dir/.." && pwd)
cargo_bin=${CARGO:-cargo}
jq_bin=${JQ:-jq}

if ! command -v "$cargo_bin" >/dev/null 2>&1; then
  cargo_install_root=${CARGO_HOME:-"$HOME/.cargo"}
  if [[ -x $cargo_install_root/bin/cargo ]]; then
    cargo_bin="$cargo_install_root/bin/cargo"
  fi
fi

usage() {
  echo "usage: $0 [--metadata FILE|--self-test]" >&2
  exit 2
}

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "dependency-family gate: required command is unavailable" >&2
    exit 2
  fi
}

package_features() {
  local metadata=$1 package_name=$2
  "$jq_bin" -r --arg package_name "$package_name" '
    . as $metadata
    | $metadata.packages[]
    | select(.name == $package_name)
    | .id as $package_id
    | $metadata.resolve.nodes[]?
    | select(.id == $package_id)
    | .features[]?
  ' "$metadata"
}

verify_metadata() {
  local metadata=$1 failed=0 family_count major_count forbidden
  local -a features=()

  if ! "$jq_bin" -e '
    (.packages | type == "array")
    and (.resolve | type == "object")
    and (.resolve.nodes | type == "array")
  ' "$metadata" >/dev/null 2>&1; then
    echo "dependency-family gate: invalid Cargo metadata document" >&2
    return 1
  fi

  family_count=$("$jq_bin" -r '
    [.packages[]
      | select(.name == "tokio")
      | .version
      | capture("^(?<major>[0-9]+)\\.(?<minor>[0-9]+)\\.")
      | "\(.major).\(.minor)"]
    | unique
    | length
  ' "$metadata")
  if (( family_count != 1 )); then
    echo "dependency-family gate: expected exactly one Tokio minor family" >&2
    failed=1
  fi

  major_count=$("$jq_bin" -r '
    [.packages[]
      | select(.name == "zbus")
      | .version
      | capture("^(?<major>[0-9]+)\\.")
      | .major]
    | unique
    | length
  ' "$metadata")
  if (( major_count != 1 )); then
    echo "dependency-family gate: expected exactly one zbus major family" >&2
    failed=1
  fi

  forbidden=$("$jq_bin" -r '
    [.packages[].name
      | select(. == "async-io" or . == "async-std" or . == "smol" or . == "glommio")]
    | unique
    | length
  ' "$metadata")
  if (( forbidden != 0 )); then
    echo "dependency-family gate: a non-Tokio async runtime was resolved" >&2
    failed=1
  fi

  mapfile -t features < <(package_features "$metadata" zbus)
  if [[ ! " ${features[*]} " =~ " tokio " || " ${features[*]} " =~ " async-io " ]]; then
    echo "dependency-family gate: zbus must use only its Tokio backend" >&2
    failed=1
  fi

  mapfile -t features < <(package_features "$metadata" oo7)
  if [[ ! " ${features[*]} " =~ " tokio " || " ${features[*]} " =~ " async-std " ]]; then
    echo "dependency-family gate: oo7 must use only its Tokio backend" >&2
    failed=1
  fi

  mapfile -t features < <(package_features "$metadata" notify-rust)
  if [[ ! " ${features[*]} " =~ " z-with-tokio " || " ${features[*]} " =~ " async " ]]; then
    echo "dependency-family gate: notify-rust must use zbus with Tokio" >&2
    failed=1
  fi

  mapfile -t features < <(package_features "$metadata" rusqlite)
  if [[ " ${features[*]} " =~ " bundled " ]]; then
    echo "dependency-family gate: rusqlite may not bundle SQLite" >&2
    failed=1
  fi

  (( failed == 0 ))
}

self_test() {
  local test_dir valid_fixture invalid_fixture
  test_dir=$(mktemp -d)
  trap 'rm -rf -- "$test_dir"' RETURN
  valid_fixture="$test_dir/valid.json"
  invalid_fixture="$test_dir/invalid.json"

  "$jq_bin" -n '
    {
      packages: [
        {id: "tokio 1.53.1", name: "tokio", version: "1.53.1"},
        {id: "zbus 5.19.0", name: "zbus", version: "5.19.0"},
        {id: "oo7 0.6.0", name: "oo7", version: "0.6.0"},
        {id: "notify-rust 4.18.0", name: "notify-rust", version: "4.18.0"},
        {id: "rusqlite 0.40.2", name: "rusqlite", version: "0.40.2"}
      ],
      resolve: {nodes: [
        {id: "tokio 1.53.1", features: ["rt"]},
        {id: "zbus 5.19.0", features: ["tokio"]},
        {id: "oo7 0.6.0", features: ["native_crypto", "tokio"]},
        {id: "notify-rust 4.18.0", features: ["serde", "tokio", "z-with-tokio", "zbus"]},
        {id: "rusqlite 0.40.2", features: []}
      ]}
    }
  ' >"$valid_fixture"

  "$jq_bin" '
    .packages += [
      {id: "tokio 1.54.0", name: "tokio", version: "1.54.0"},
      {id: "zbus 4.4.0", name: "zbus", version: "4.4.0"},
      {id: "async-io 2.6.0", name: "async-io", version: "2.6.0"}
    ]
    | .resolve.nodes += [
      {id: "tokio 1.54.0", features: ["rt"]},
      {id: "zbus 4.4.0", features: ["async-io"]},
      {id: "async-io 2.6.0", features: []}
    ]
  ' "$valid_fixture" >"$invalid_fixture"

  verify_metadata "$valid_fixture" >/dev/null 2>&1 || {
    echo "dependency-family gate: valid self-test fixture was rejected" >&2
    return 1
  }
  if verify_metadata "$invalid_fixture" >/dev/null 2>&1; then
    echo "dependency-family gate: invalid self-test fixture was accepted" >&2
    return 1
  fi
  echo "dependency-family gate: self-test passed"
}

require_command "$jq_bin"

case ${1:-} in
  "")
    (( $# == 0 )) || usage
    require_command "$cargo_bin"
    metadata_file=$(mktemp)
    trap 'rm -f -- "$metadata_file"' EXIT
    cd -- "$repo_root"
    "$cargo_bin" metadata --locked --format-version 1 >"$metadata_file"
    verify_metadata "$metadata_file"
    echo "dependency-family gate: workspace passed"
    ;;
  --metadata)
    (( $# == 2 )) || usage
    [[ -f $2 && ! -L $2 ]] || {
      echo "dependency-family gate: metadata fixture must be a regular file" >&2
      exit 2
    }
    verify_metadata "$2"
    ;;
  --self-test)
    (( $# == 1 )) || usage
    self_test
    ;;
  *) usage ;;
esac
