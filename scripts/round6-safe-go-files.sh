#!/usr/bin/env bash
set -euo pipefail

root="$(cd "${BASH_SOURCE[0]%/*}/.." && pwd -P)"
cd "$root"

safe_roots=(
  cmd/cyber-abuse-guard
  cmd/development-adversarial-v11-prep-validator
  cmd/development-public-jailbreak-patterns-v1-validator
  cmd/round9-development-benign-corpus-runner
  cmd/round9-development-corpus-freezer
  cmd/round9-paired-malicious-corpus-freezer
  cmd/round9-paired-malicious-corpus-runner
  cmd/round9-public-corpus-validator
  internal/audit
  internal/buildinfo
  internal/classifier
  internal/config
  internal/extract
  internal/explanation
  internal/fixturepublish
  internal/plugin
  internal/round9corpus
  internal/round8test
  internal/rules
  internal/subject
  integration/round9countedmock
  integration/cpalatestcontract
  integration/pluginstorecontract
  rules
)

while IFS= read -r -d '' file; do
  case "$file" in
    *.go) ;;
    *) continue ;;
  esac
  case "${file,,}" in
    internal/classifier/*evaluation*|internal/classifier/*holdout*|internal/classifier/*consumed*|internal/classifier/*private*|internal/classifier/*retired*|internal/classifier/*blind*)
      continue
      ;;
  esac
  printf '%s\0' "$file"
done < <(git ls-files -co --exclude-standard -z -- "${safe_roots[@]}")
