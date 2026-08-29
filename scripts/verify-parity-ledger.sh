#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd -- "$script_dir/.." && pwd)
cargo_bin=${CARGO:-cargo}

if ! command -v "$cargo_bin" >/dev/null 2>&1; then
  cargo_install_root=${CARGO_HOME:-"$HOME/.cargo"}
  if [[ -x $cargo_install_root/bin/cargo ]]; then
    cargo_bin="$cargo_install_root/bin/cargo"
  fi
fi

if ! command -v "$cargo_bin" >/dev/null 2>&1; then
  echo "parity gate: Cargo is unavailable" >&2
  exit 2
fi

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
"$cargo_bin" test -p oab-domain --test provider_registry --locked
"$cargo_bin" test -p oab-providers --test ledger --locked
