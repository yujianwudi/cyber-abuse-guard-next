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

reachable="$(git -C "$root" rev-list --objects --all -- "${paths[@]}")"
if [[ -n "$reachable" ]]; then
  printf 'consumed evaluation-v10 paths are reachable from repository history\n' >&2
  exit 1
fi

printf 'consumed evaluation-v10 absence verified without reading payload blobs\n'
