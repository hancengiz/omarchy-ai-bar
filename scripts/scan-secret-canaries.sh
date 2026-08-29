#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd -- "$script_dir/.." && pwd)
readonly canary_pattern='OAB_SECRET_CANARY_[[:alnum:]_=-]+|sk[-_](live|proj)[-_][[:alnum:]_-]*canary|[[:alnum:]_-]*(secret|token|cookie|credential)[_-]canary'

usage() {
  echo "usage: $0 [--self-test|PATH ...]" >&2
  exit 2
}

scan_file() {
  local file=$1 status
  if [[ ! -f $file || -L $file || ! -r $file ]]; then
    printf 'secret-canary gate: refusing non-regular or unreadable input: %q\n' "$file" >&2
    return 2
  fi
  set +e
  LC_ALL=C grep -aEq -- "$canary_pattern" "$file"
  status=$?
  set -e
  case $status in
    0)
      # Never print matching content: a failure report must not repeat a secret.
      printf 'secret-canary gate: possible secret material in: %q\n' "$file" >&2
      return 1
      ;;
    1) return 0 ;;
    *)
      printf 'secret-canary gate: could not scan: %q\n' "$file" >&2
      return 2
      ;;
  esac
}

scan_targets() {
  local target file failed=0 scanned=0 status
  for target in "$@"; do
    if [[ -d $target && ! -L $target ]]; then
      while IFS= read -r -d '' file; do
        scanned=$((scanned + 1))
        set +e
        scan_file "$file"
        status=$?
        set -e
        (( status > failed )) && failed=$status
      done < <(find "$target" -type f -print0)
    else
      scanned=$((scanned + 1))
      set +e
      scan_file "$target"
      status=$?
      set -e
      (( status > failed )) && failed=$status
    fi
  done
  if (( scanned == 0 )); then
    echo "secret-canary gate: no regular files were selected" >&2
    return 2
  fi
  return "$failed"
}

self_test() {
  local test_dir leaked redacted
  test_dir=$(mktemp -d)
  trap 'rm -rf -- "$test_dir"' RETURN
  leaked="$test_dir/leaked.log"
  redacted="$test_dir/redacted.log"
  printf '%s\n' 'request failed for OAB_SECRET_CANARY_DO_NOT_PRINT_7F3A' >"$leaked"
  printf '%s\n' '[REDACTED]' 'SecretValue([REDACTED])' '<redacted>' >"$redacted"

  if scan_targets "$leaked" >/dev/null 2>&1; then
    echo "secret-canary gate: injected canary was accepted" >&2
    return 1
  fi
  scan_targets "$redacted" >/dev/null 2>&1 || {
    echo "secret-canary gate: approved redacted values were rejected" >&2
    return 1
  }
  echo "secret-canary gate: self-test passed"
}

case ${1:-} in
  --self-test)
    (( $# == 1 )) || usage
    self_test
    ;;
  "")
    (( $# == 0 )) || usage
    cd -- "$repo_root"
    scan_targets target/release/omarchy-ai-bar
    echo "secret-canary gate: release binary passed"
    ;;
  --*) usage ;;
  *)
    scan_targets "$@"
    echo "secret-canary gate: selected files passed"
    ;;
esac
