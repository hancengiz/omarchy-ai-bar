#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
baseline=${OAB_BASELINE_DIR:-"$repo_root/../CodexBar"}
pinned=$(jq -r '.source.commit_full' "$repo_root/parity/baseline.json")
[[ -d $baseline/.git ]] || {
  echo "upstream-diff: CodexBar checkout not found; set OAB_BASELINE_DIR" >&2
  exit 2
}
git -C "$baseline" cat-file -e "$pinned^{commit}" 2>/dev/null || {
  echo "upstream-diff: pinned baseline commit is unavailable" >&2
  exit 2
}

head=${1:-HEAD}
git -C "$baseline" cat-file -e "$head^{commit}" 2>/dev/null || {
  echo "upstream-diff: requested upstream revision is unavailable" >&2
  exit 2
}

printf 'CodexBar baseline: %s\nCodexBar comparison: %s\n\n' "$pinned" \
  "$(git -C "$baseline" rev-parse "$head^{commit}")"
git -C "$baseline" diff --stat "$pinned" "$head" -- \
  Sources Tests docs Package.swift Package.resolved LICENSE
printf '\nProvider/schema/CLI/UI/license paths changed:\n'
git -C "$baseline" diff --name-only "$pinned" "$head" -- \
  'Sources/*Provider*' 'Sources/**/Providers/**' 'Sources/CodexBarCLI/**' \
  'Sources/CodexBar/**' 'Tests/**' 'docs/**' Package.swift Package.resolved LICENSE
