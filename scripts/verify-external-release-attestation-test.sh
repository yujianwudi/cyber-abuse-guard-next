#!/usr/bin/env bash
set -euo pipefail

root="$(cd "${BASH_SOURCE[0]%/*}/.." && pwd -P)"
verify="$root/scripts/verify-external-release-attestation.sh"
work="$(mktemp -d)"
trap 'rm -rf -- "$work"' EXIT

commit=1111111111111111111111111111111111111111
tree=2222222222222222222222222222222222222222
candidate_run_id=29578024185
so_sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
store_zip_sha256=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
tag=v0.15-dev.round6.2
cpa_version=v7.2.95
cpa_commit=f71ec0eb6776854457892452cf28c47f0d658251

export EXPECTED_TAG="$tag"
export EXPECTED_COMMIT="$commit"
export EXPECTED_TREE="$tree"
export CANDIDATE_RUN_ID="$candidate_run_id"
export EXPECTED_SO_SHA256="$so_sha256"
export EXPECTED_STORE_ZIP_SHA256="$store_zip_sha256"

write_valid_attestation() {
  local directory="$1"
  mkdir -p "$directory"
  jq -n \
    --arg tag "$tag" \
    --arg commit "$commit" \
    --arg tree "$tree" \
    --argjson candidate_run_id "$candidate_run_id" \
    --arg so_sha256 "$so_sha256" \
    --arg store_zip_sha256 "$store_zip_sha256" \
    --arg cpa_version "$cpa_version" \
    --arg cpa_commit "$cpa_commit" '
    {
      schema_version: 2,
      status: "HOST_AUDIT_AND_EVALUATION_PASS / FORMAL_RELEASE_BLOCKED",
      version: "0.15",
      tag: $tag,
      commit: $commit,
      tree: $tree,
      ci_run_id: 29578025961,
      candidate_run_id: $candidate_run_id,
      artifacts: {
        so_sha256: $so_sha256,
        store_zip_sha256: $store_zip_sha256
      },
      evidence: {
        cpa_version: $cpa_version,
        cpa_commit: $cpa_commit,
        cpa_host_sha256: "8383838383838383838383838383838383838383838383838383838383838383",
        independent_audit_sha256: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        independent_evaluation_id: "evaluation-v11",
        independent_evaluation_status: "CONSUMED / PASS",
        independent_evaluation_sha256: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
      },
      workflow: {
        repository: "yujianwudi/cyber-abuse-guard",
        ref: ("yujianwudi/cyber-abuse-guard/.github/workflows/attested-prerelease.yml@refs/tags/" + $tag),
        sha: $commit,
        run_id: 29580000001,
        run_attempt: 1
      }
    }
  ' >"$directory/round6-prerelease-attestation.json"
  write_checksum "$directory"
}

write_checksum() {
  local directory="$1"
  (
    cd "$directory"
    sha256sum round6-prerelease-attestation.json \
      >round6-prerelease-attestation.json.sha256
  )
}

copy_case() {
  local name="$1"
  mkdir -p "$work/$name"
  cp -a "$work/baseline/." "$work/$name/"
}

mutate_case() {
  local name="$1"
  local filter="$2"
  copy_case "$name"
  jq "$filter" "$work/$name/round6-prerelease-attestation.json" \
    >"$work/$name/attestation.tmp"
  mv -f "$work/$name/attestation.tmp" \
    "$work/$name/round6-prerelease-attestation.json"
  write_checksum "$work/$name"
}

verify_case() {
  local directory="$1"
  "$verify" "$directory/round6-prerelease-attestation.json"
}

run_must_pass() {
  local name="$1"
  shift
  if "$@" >"$work/$name.log" 2>&1; then
    printf 'external attestation contract passed: %s\n' "$name"
  else
    printf 'external attestation contract unexpectedly failed: %s\n' "$name" >&2
    cat "$work/$name.log" >&2
    exit 1
  fi
}

run_must_fail() {
  local name="$1"
  shift
  if "$@" >"$work/$name.log" 2>&1; then
    printf 'external attestation contract unexpectedly passed: %s\n' "$name" >&2
    cat "$work/$name.log" >&2
    exit 1
  fi
  printf 'external attestation contract rejected as expected: %s\n' "$name"
}

write_valid_attestation "$work/baseline"
run_must_pass exact-v11-candidate verify_case "$work/baseline"
run_must_pass makefile-release-gate env \
  RELEASE_EXTERNAL_ATTESTATION="$work/baseline/round6-prerelease-attestation.json" \
  ROUND6_CANDIDATE_TAG="$tag" \
  ROUND6_ATTESTED_COMMIT="$commit" \
  ROUND6_ATTESTED_TREE="$tree" \
  ROUND6_CANDIDATE_RUN_ID="$candidate_run_id" \
  ROUND6_CANDIDATE_SO_SHA256="$so_sha256" \
  ROUND6_CANDIDATE_STORE_ZIP_SHA256="$store_zip_sha256" \
  make -C "$root" external-release-attestation

mutate_case evaluation-v12 '.evidence.independent_evaluation_id = "evaluation-v12"'
run_must_pass later-independent-evaluation verify_case "$work/evaluation-v12"

copy_case checksum-mismatch
printf ' ' >>"$work/checksum-mismatch/round6-prerelease-attestation.json"
run_must_fail checksum-mismatch verify_case "$work/checksum-mismatch"

copy_case wrong-checksum-target
sed -i 's/round6-prerelease-attestation\.json$/other.json/' \
  "$work/wrong-checksum-target/round6-prerelease-attestation.json.sha256"
run_must_fail wrong-checksum-target verify_case "$work/wrong-checksum-target"

copy_case invalid-json
printf '{' >"$work/invalid-json/round6-prerelease-attestation.json"
write_checksum "$work/invalid-json"
run_must_fail invalid-json verify_case "$work/invalid-json"

copy_case duplicate-key
sed -i '0,/"schema_version": 2/s//"schema_version": 2, "schema_version": 2/' \
  "$work/duplicate-key/round6-prerelease-attestation.json"
write_checksum "$work/duplicate-key"
run_must_fail duplicate-json-key verify_case "$work/duplicate-key"

mutate_case extra-top-level-field '.historical_evaluation = {id: "evaluation-v10", status: "CONSUMED / FAIL"}'
run_must_fail historical-v10-cannot-authorize verify_case "$work/extra-top-level-field"

mutate_case evaluation-v10-fail '.evidence.independent_evaluation_id = "evaluation-v10"'
run_must_fail consumed-v10-fail-cannot-authorize verify_case "$work/evaluation-v10-fail"

mutate_case evaluation-v10-pass-label '.evidence.independent_evaluation_id = "evaluation-v10-pass"'
run_must_fail disguised-v10-cannot-authorize verify_case "$work/evaluation-v10-pass-label"

mutate_case evaluation-leading-zero '.evidence.independent_evaluation_id = "evaluation-v011"'
run_must_fail leading-zero-evaluation-version verify_case "$work/evaluation-leading-zero"

mutate_case missing-evaluation-hash 'del(.evidence.independent_evaluation_sha256)'
run_must_fail missing-evaluation-hash verify_case "$work/missing-evaluation-hash"

mutate_case malformed-evaluation-hash '.evidence.independent_evaluation_sha256 = "not-a-sha256"'
run_must_fail malformed-evaluation-hash verify_case "$work/malformed-evaluation-hash"

mutate_case non-consumed-evaluation '.evidence.independent_evaluation_status = "PASS"'
run_must_fail evaluation-must-be-consumed-pass verify_case "$work/non-consumed-evaluation"

mutate_case missing-cpa-version 'del(.evidence.cpa_version)'
run_must_fail missing-cpa-version verify_case "$work/missing-cpa-version"

mutate_case wrong-cpa-version '.evidence.cpa_version = "v7.2.87"'
run_must_fail wrong-cpa-version verify_case "$work/wrong-cpa-version"

mutate_case missing-cpa-commit 'del(.evidence.cpa_commit)'
run_must_fail missing-cpa-commit verify_case "$work/missing-cpa-commit"

mutate_case wrong-cpa-commit '.evidence.cpa_commit = "81d70f5d9f3fdb39a6290ed9c917ff0c6f27ca30"'
run_must_fail wrong-cpa-commit verify_case "$work/wrong-cpa-commit"

mutate_case missing-host-hash 'del(.evidence.cpa_host_sha256)'
run_must_fail missing-cpa-host-evidence verify_case "$work/missing-host-hash"

mutate_case legacy-version-encoded-host-field '.evidence.cpa_v7_2_86_sha256 = .evidence.cpa_host_sha256 | del(.evidence.cpa_host_sha256)'
run_must_fail legacy-version-encoded-host-field verify_case "$work/legacy-version-encoded-host-field"

mutate_case malformed-host-hash '.evidence.cpa_host_sha256 = "8383"'
run_must_fail malformed-host-evidence-hash verify_case "$work/malformed-host-hash"

mutate_case missing-audit 'del(.evidence.independent_audit_sha256)'
run_must_fail missing-independent-audit verify_case "$work/missing-audit"

mutate_case malformed-audit-hash '.evidence.independent_audit_sha256 = "blocked"'
run_must_fail malformed-independent-audit-hash verify_case "$work/malformed-audit-hash"

mutate_case wrong-status '.status = "BLOCKED / PENDING"'
run_must_fail non-pass-attestation-status verify_case "$work/wrong-status"

mutate_case pre-evaluation-status '.status = "HOST_AND_INDEPENDENT_AUDIT_PASS / FORMAL_RELEASE_BLOCKED"'
run_must_fail status-must-explicitly-bind-evaluation-pass verify_case "$work/pre-evaluation-status"

mutate_case wrong-version '.version = "0.15.0"'
run_must_fail three-component-version-alias verify_case "$work/wrong-version"

mutate_case wrong-commit '.commit = "3333333333333333333333333333333333333333"'
run_must_fail candidate-commit-mismatch verify_case "$work/wrong-commit"

mutate_case wrong-tree '.tree = "4444444444444444444444444444444444444444"'
run_must_fail candidate-tree-mismatch verify_case "$work/wrong-tree"

mutate_case wrong-candidate-run '.candidate_run_id = 29578024186'
run_must_fail candidate-run-mismatch verify_case "$work/wrong-candidate-run"

mutate_case wrong-so '.artifacts.so_sha256 = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"'
run_must_fail candidate-so-mismatch verify_case "$work/wrong-so"

mutate_case wrong-store-zip '.artifacts.store_zip_sha256 = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"'
run_must_fail candidate-store-zip-mismatch verify_case "$work/wrong-store-zip"

mutate_case wrong-workflow-sha '.workflow.sha = "3333333333333333333333333333333333333333"'
run_must_fail workflow-source-mismatch verify_case "$work/wrong-workflow-sha"

mutate_case wrong-workflow-ref '.workflow.ref = "yujianwudi/cyber-abuse-guard/.github/workflows/attested-prerelease.yml@refs/heads/main"'
run_must_fail non-tag-workflow-ref verify_case "$work/wrong-workflow-ref"

mutate_case wrong-repository '.workflow.repository = "attacker/cyber-abuse-guard"'
run_must_fail non-canonical-repository verify_case "$work/wrong-repository"

mutate_case fractional-run-id '.workflow.run_id = 1.5'
run_must_fail fractional-workflow-run-id verify_case "$work/fractional-run-id"

copy_case symlink-attestation
mv "$work/symlink-attestation/round6-prerelease-attestation.json" \
  "$work/symlink-attestation/real-attestation.json"
ln -s real-attestation.json \
  "$work/symlink-attestation/round6-prerelease-attestation.json"
write_checksum "$work/symlink-attestation"
run_must_fail symlink-attestation verify_case "$work/symlink-attestation"

run_must_fail missing-expected-commit env -u EXPECTED_COMMIT \
  EXPECTED_TAG="$EXPECTED_TAG" EXPECTED_TREE="$EXPECTED_TREE" \
  CANDIDATE_RUN_ID="$CANDIDATE_RUN_ID" EXPECTED_SO_SHA256="$EXPECTED_SO_SHA256" \
  EXPECTED_STORE_ZIP_SHA256="$EXPECTED_STORE_ZIP_SHA256" \
  "$verify" "$work/baseline/round6-prerelease-attestation.json"

printf 'all external release attestation contracts passed\n'
