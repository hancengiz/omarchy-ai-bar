#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd -- "$script_dir/.." && pwd)

case "${1:-}" in
  "")
    if (( $# != 0 )); then
      echo "usage: $0 [--providers-complete|--all-complete]" >&2
      exit 2
    fi
    unset OAB_PARITY_GATE
    ;;
  --providers-complete)
    if (( $# != 1 )); then
      echo "usage: $0 [--providers-complete|--all-complete]" >&2
      exit 2
    fi
    export OAB_PARITY_GATE=providers-complete
    ;;
  --all-complete)
    if (( $# != 1 )); then
      echo "usage: $0 [--providers-complete|--all-complete]" >&2
      exit 2
    fi
    export OAB_PARITY_GATE=all-complete
    ;;
  *)
    echo "usage: $0 [--providers-complete|--all-complete]" >&2
    exit 2
    ;;
esac

if [[ -z "${OAB_BASELINE_DIR:-}" && -d "$repo_root/../CodexBar" ]]; then
  export OAB_BASELINE_DIR="$repo_root/../CodexBar"
fi

cd -- "$repo_root"
cargo test -p oab-domain --test provider_registry --locked
cargo test -p oab-providers --test ledger --locked
