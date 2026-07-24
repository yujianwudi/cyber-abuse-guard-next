#!/usr/bin/env bash
set -euo pipefail

root="$(cd "${BASH_SOURCE[0]%/*}/.." && pwd -P)"
commit="$(git -C "$root" rev-parse --verify HEAD)"

paths=(
  cmd/evaluation-v10-author
  docs/reports/EVALUATION_V10_REPORT.md
  internal/classifier/evaluation_v10_gate_test.go
  testdata/evaluation-v10
)

# Check only Git metadata. Any staged, unstaged, or untracked path beneath the
# frozen boundary invalidates the gate, even when HEAD still has the expected
# tree OIDs. Do not print the status payload or read any frozen blob contents.
status="$(git -C "$root" status --porcelain=v1 --untracked-files=all -- "${paths[@]}")"
if [[ -n "$status" ]]; then
  printf 'frozen evaluation-v10 paths have staged, unstaged, or untracked changes\n' >&2
  exit 1
fi

expected="$(printf '%s\n' \
  $'040000 tree a5b2976adc4a44fa80783f5b8588db1c8c9a157a\tcmd/evaluation-v10-author' \
  $'100644 blob 7bd493672f9f0a2c659cbaa1787c92265bb34031\tdocs/reports/EVALUATION_V10_REPORT.md' \
  $'100644 blob 36290d08ab4e43a8c763f97e836af846c36a04b7\tinternal/classifier/evaluation_v10_gate_test.go' \
  $'040000 tree 59843ce4d136df92c7e99f38a3cea18d88cf7886\ttestdata/evaluation-v10')"
actual="$(git -C "$root" ls-tree "$commit" -- "${paths[@]}")"

if [[ "$actual" != "$expected" ]]; then
  printf 'frozen evaluation-v10 tree identity changed; the consumed FAIL evidence must not be modified or rerun\n' >&2
  exit 1
fi

printf 'frozen evaluation-v10 tree identity verified without reading payload blobs\n'
