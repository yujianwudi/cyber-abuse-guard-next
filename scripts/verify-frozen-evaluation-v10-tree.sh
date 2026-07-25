#!/usr/bin/env bash
set -euo pipefail

root="$(cd "${BASH_SOURCE[0]%/*}/.." && pwd -P)"

paths=(
  cmd/evaluation-v10-author
  docs/reports/EVALUATION_V10_REPORT.md
  internal/classifier/evaluation_v10_gate_test.go
  testdata/evaluation-v10
)

# Check only Git metadata. The clean-history successor repository must retain
# no consumed evaluation-v10 path in the worktree, index, or reachable history.
# Do not print the status payload, object listing, or read any payload blobs.
for path in "${paths[@]}"; do
  if [[ -e "$root/$path" || -L "$root/$path" ]]; then
    printf 'consumed evaluation-v10 path remains in the worktree: %s\n' "$path" >&2
    exit 1
  fi
done

status="$(git -C "$root" status --porcelain=v1 --untracked-files=all -- "${paths[@]}")"
if [[ -n "$status" ]]; then
  printf 'frozen evaluation-v10 paths have staged, unstaged, or untracked changes\n' >&2
  exit 1
fi

tracked="$(git -C "$root" ls-files -- "${paths[@]}")"
if [[ -n "$tracked" ]]; then
  printf 'consumed evaluation-v10 paths must remain absent from the clean-history repository\n' >&2
  exit 1
fi

# Ask for commits that touched the paths, not object names. With --objects,
# rev-list emits annotated tag objects even when no path matches.
reachable="$(git -C "$root" rev-list --all --full-history -- "${paths[@]}")"
if [[ -n "$reachable" ]]; then
  printf 'consumed evaluation-v10 paths are reachable from repository history\n' >&2
  exit 1
fi

printf 'consumed evaluation-v10 absence verified without reading payload blobs\n'
