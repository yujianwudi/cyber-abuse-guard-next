#!/usr/bin/env bash
set -euo pipefail

root="$(cd "${BASH_SOURCE[0]%/*}/.." && pwd -P)"
# shellcheck source=release-common.sh
source "$root/scripts/release-common.sh"
release_require_commands git mktemp rm mkdir sed

# This script owns the complete formal/candidate/RC test matrix. Do not let a
# caller's active release mode or identity leak into the synthetic fixture.
unset \
  ALLOW_DIRTY_BUILD \
  RELEASE_CANDIDATE_BUILD \
  RELEASE_CANDIDATE_EXPECTED_COMMIT \
  RELEASE_CANDIDATE_EXPECTED_TREE \
  RELEASE_RC_BUILD \
  RELEASE_RC_TAG \
  RELEASE_RC_EXPECTED_COMMIT \
  RELEASE_RC_EXPECTED_TREE \
  ROUND6_SAFE_SPARSE_BUILD \
  SOURCE_DATE_EPOCH \
  VERSION

work="$(mktemp -d)"
fixture="$work/repository"
cleanup() {
  rm -rf -- "$work"
}
trap cleanup EXIT

mkdir -p "$fixture/internal/buildinfo" "$fixture/internal/classifier" "$fixture/rules" \
  "$fixture/docs/reports" "$fixture/docs"
printf '%s\n' \
  'package buildinfo' \
  'const StreamingScannerIdentity = "streaming-scanner-v1"' \
  'var (' \
  '  Version = "0.15"' \
  '  RulesetVersion = "1.0.7"' \
  ')' \
  >"$fixture/internal/buildinfo/buildinfo.go"
printf '%s\n' \
  'package classifier' \
  'const ClassifierPolicyVersion = "classifier-policy-v3"' \
  'const ClassifierPolicySHA256 = "7471f3170ac832f8dc839a7da005c5d4d487c1c60f1a01eb7385e93fff49da5f"' \
  >"$fixture/internal/classifier/policy_identity.go"
printf '%s\n' 'version: "1.0.7"' 'rule_files: [rules.yaml]' >"$fixture/rules/manifest.yaml"
printf '%s\n' 'version: "1.0.7"' 'rules: []' >"$fixture/rules/rules.yaml"
printf '%s\n' '# Synthetic consumed evaluation marker' >"$fixture/docs/reports/EVALUATION_V10_REPORT.md"
printf '%s\n' '# Synthetic holdout marker' >"$fixture/docs/reports/HOLDOUT_REPORT.md"
printf '%s\n' '# Synthetic ordinary release document' >"$fixture/docs/ROUND6_RELEASE_GATE.md"

git -C "$fixture" init -q
git -C "$fixture" config user.name 'Round6 Candidate Contract'
git -C "$fixture" config user.email 'candidate-contract@example.invalid'
git -C "$fixture" add .
GIT_AUTHOR_DATE='2026-07-17T00:00:00Z' GIT_COMMITTER_DATE='2026-07-17T00:00:00Z' \
  git -C "$fixture" commit -q -m baseline

commit="$(git -C "$fixture" rev-parse HEAD)"
tree="$(git -C "$fixture" rev-parse 'HEAD^{tree}')"

candidate_case() {
  RELEASE_ROOT="$fixture"
  RELEASE_CANDIDATE_BUILD="${RELEASE_CANDIDATE_BUILD:-1}"
  RELEASE_RC_BUILD="${RELEASE_RC_BUILD:-0}"
  RELEASE_CANDIDATE_EXPECTED_COMMIT="${RELEASE_CANDIDATE_EXPECTED_COMMIT:-$commit}"
  RELEASE_CANDIDATE_EXPECTED_TREE="${RELEASE_CANDIDATE_EXPECTED_TREE:-$tree}"
  ALLOW_DIRTY_BUILD="${ALLOW_DIRTY_BUILD:-0}"
  export RELEASE_ROOT RELEASE_CANDIDATE_BUILD RELEASE_CANDIDATE_EXPECTED_COMMIT
  export RELEASE_CANDIDATE_EXPECTED_TREE RELEASE_RC_BUILD ALLOW_DIRTY_BUILD
  release_init
}

run_must_pass() {
  local name="$1"
  shift
  if ("$@"); then
    printf 'candidate release contract passed: %s\n' "$name"
  else
    printf 'candidate release contract unexpectedly failed: %s\n' "$name" >&2
    exit 1
  fi
}

run_must_fail() {
  local name="$1"
  shift
  if ("$@" >/dev/null 2>&1); then
    printf 'candidate release contract unexpectedly passed: %s\n' "$name" >&2
    exit 1
  fi
  printf 'candidate release contract rejected as expected: %s\n' "$name"
}

run_must_fail_with() {
  local name="$1"
  local expected="$2"
  local output
  shift 2
  if output="$("$@" 2>&1)"; then
    printf 'candidate release contract unexpectedly passed: %s\n' "$name" >&2
    exit 1
  fi
  if [[ "$output" != *"$expected"* ]]; then
    printf 'candidate release contract failed for the wrong reason: %s\n' "$name" >&2
    printf 'expected diagnostic substring: %s\n' "$expected" >&2
    printf 'actual output:\n%s\n' "$output" >&2
    exit 1
  fi
  printf 'candidate release contract rejected with the expected diagnostic: %s\n' "$name"
}

candidate_success() {
  unset SOURCE_DATE_EPOCH
  candidate_case
  release_assert_tag
  release_assert_candidate_build
  [[ "$RELEASE_BUILD_KIND" == candidate ]]
  [[ "$RELEASE_ARTIFACT_VERSION" == 0.15 ]]
  [[ "$RELEASE_DIRTY" == false ]]
}

candidate_wrong_commit() {
  RELEASE_CANDIDATE_EXPECTED_COMMIT=0000000000000000000000000000000000000000 candidate_case
}

candidate_wrong_tree() {
  RELEASE_CANDIDATE_EXPECTED_TREE=0000000000000000000000000000000000000000 candidate_case
}

candidate_dirty_conflict() {
  ALLOW_DIRTY_BUILD=1 candidate_case
}

candidate_wrong_epoch() {
  SOURCE_DATE_EPOCH=315532800
  export SOURCE_DATE_EPOCH
  candidate_case
}

candidate_cannot_run_formal_operation() {
  candidate_case
  release_assert_formal_build
}

candidate_cannot_run_rc_operation() {
  candidate_case
  release_assert_rc_build
}

rc_case() {
  RELEASE_ROOT="$fixture"
  RELEASE_CANDIDATE_BUILD="${RELEASE_CANDIDATE_BUILD:-0}"
  RELEASE_RC_BUILD="${RELEASE_RC_BUILD:-1}"
  RELEASE_RC_TAG="${RELEASE_RC_TAG:-v0.15-rc.3}"
  RELEASE_RC_EXPECTED_COMMIT="${RELEASE_RC_EXPECTED_COMMIT:-$commit}"
  RELEASE_RC_EXPECTED_TREE="${RELEASE_RC_EXPECTED_TREE:-$tree}"
  ALLOW_DIRTY_BUILD="${ALLOW_DIRTY_BUILD:-0}"
  if [[ "${GITHUB_ACTIONS:-false}" == true ]]; then
    GITHUB_REF_TYPE=tag
    GITHUB_REF_NAME="$RELEASE_RC_TAG"
    export GITHUB_REF_TYPE GITHUB_REF_NAME
  fi
  export RELEASE_ROOT RELEASE_CANDIDATE_BUILD RELEASE_RC_BUILD RELEASE_RC_TAG
  export RELEASE_RC_EXPECTED_COMMIT RELEASE_RC_EXPECTED_TREE ALLOW_DIRTY_BUILD
  release_init
}

rc_success() {
  unset SOURCE_DATE_EPOCH
  rc_case
  release_assert_tag
  release_assert_rc_build
  [[ "$RELEASE_BUILD_KIND" == rc ]]
  [[ "$RELEASE_ARTIFACT_VERSION" == 0.15-rc.3 ]]
  [[ "$RELEASE_DIRTY" == false ]]
}

rc_wrong_commit() {
  RELEASE_RC_EXPECTED_COMMIT=0000000000000000000000000000000000000000 rc_case
}

rc_wrong_tree() {
  RELEASE_RC_EXPECTED_TREE=0000000000000000000000000000000000000000 rc_case
}

rc_zero_suffix() {
  RELEASE_RC_TAG=v0.15-rc.0 rc_case
}

rc_leading_zero_suffix() {
  RELEASE_RC_TAG=v0.15-rc.02 rc_case
}

rc_dirty_conflict() {
  ALLOW_DIRTY_BUILD=1 rc_case
}

rc_candidate_conflict() {
  RELEASE_CANDIDATE_BUILD=1 rc_case
}

rc_wrong_epoch() {
  SOURCE_DATE_EPOCH=315532800
  export SOURCE_DATE_EPOCH
  rc_case
}

rc_cannot_run_formal_operation() {
  rc_case
  release_assert_formal_build
}

rc_cannot_run_candidate_operation() {
  rc_case
  release_assert_candidate_build
}

round6_sparse_path_contract() {
  release_round6_safe_sparse_path "docs/reports/EVALUATION_V10_REPORT.md"
  release_round6_safe_sparse_path "docs/reports/HOLDOUT_V3_REPORT.md"
  release_round6_safe_sparse_path "docs/reports/HOLDOUT_REPORT.md"
  release_round6_safe_sparse_path "cmd/private-evaluation/main.go"
  release_round6_safe_sparse_path "internal/classifier/Consumed_Evaluation_test.go"
  release_round6_safe_sparse_path "testdata/Retired-Holdout/manifest.json"
  ! release_round6_safe_sparse_path "docs/reports/TEST_REPORT.md"
  ! release_round6_safe_sparse_path "docs/ROUND6_RELEASE_GATE.md"
  ! release_round6_safe_sparse_path "scripts/release-common.sh"
}

rc_script_mode_contract() {
  local entry mode object stage path
  entry="$(git -C "$root" ls-files --stage -- scripts/round6-rc-artifacts.sh)"
  read -r mode object stage path <<<"$entry"
  [[ "$mode" == 100755 ]]
  [[ "$object" =~ ^[0-9a-f]{40}$ ]]
  [[ "$stage" == 0 ]]
  [[ "$path" == scripts/round6-rc-artifacts.sh ]]
}

candidate_safe_sparse_checkout() {
  cleanup_sparse() {
    git -C "$fixture" sparse-checkout disable >/dev/null 2>&1 || true
  }
  trap cleanup_sparse EXIT
  git -C "$fixture" sparse-checkout init --no-cone
  git -C "$fixture" sparse-checkout set --no-cone \
    '/*' \
    '!/docs/reports/EVALUATION_V10_REPORT.md' \
    '!/docs/reports/HOLDOUT_REPORT.md'
  git -C "$fixture" checkout -q "$commit"
  [[ ! -e "$fixture/docs/reports/EVALUATION_V10_REPORT.md" ]]
  [[ ! -e "$fixture/docs/reports/HOLDOUT_REPORT.md" ]]
  ROUND6_SAFE_SPARSE_BUILD=1 candidate_case
}

candidate_unsafe_sparse_checkout() {
  cleanup_sparse() {
    git -C "$fixture" sparse-checkout disable >/dev/null 2>&1 || true
  }
  trap cleanup_sparse EXIT
  git -C "$fixture" sparse-checkout init --no-cone
  git -C "$fixture" sparse-checkout set --no-cone \
    '/*' \
    '!/docs/ROUND6_RELEASE_GATE.md'
  git -C "$fixture" checkout -q "$commit"
  [[ ! -e "$fixture/docs/ROUND6_RELEASE_GATE.md" ]]
  ROUND6_SAFE_SPARSE_BUILD=1 candidate_case
}

formal_without_tag() {
  RELEASE_ROOT="$fixture"
  ALLOW_DIRTY_BUILD=0
  RELEASE_CANDIDATE_BUILD=0
  RELEASE_RC_BUILD=0
  unset SOURCE_DATE_EPOCH
  export RELEASE_ROOT ALLOW_DIRTY_BUILD RELEASE_CANDIDATE_BUILD RELEASE_RC_BUILD
  release_init
  release_assert_tag
}

formal_with_annotated_tag() {
  RELEASE_ROOT="$fixture"
  ALLOW_DIRTY_BUILD=0
  RELEASE_CANDIDATE_BUILD=0
  RELEASE_RC_BUILD=0
  if [[ "${GITHUB_ACTIONS:-false}" == true ]]; then
    GITHUB_REF_TYPE=tag
    GITHUB_REF_NAME=v0.15
    export GITHUB_REF_TYPE GITHUB_REF_NAME
  fi
  unset SOURCE_DATE_EPOCH
  export RELEASE_ROOT ALLOW_DIRTY_BUILD RELEASE_CANDIDATE_BUILD RELEASE_RC_BUILD
  release_init
  release_assert_tag
  release_assert_formal_build
}

run_must_pass clean-exact-candidate candidate_success
run_must_fail mismatched-candidate-commit candidate_wrong_commit
run_must_fail mismatched-candidate-tree candidate_wrong_tree
run_must_fail dirty-candidate-conflict candidate_dirty_conflict
run_must_fail candidate-source-date-override candidate_wrong_epoch
run_must_fail candidate-cannot-run-formal-operation candidate_cannot_run_formal_operation
run_must_fail candidate-cannot-run-rc-operation candidate_cannot_run_rc_operation
run_must_pass round6-safe-sparse-path-case-folding round6_sparse_path_contract
run_must_pass rc-release-script-executable-mode rc_script_mode_contract
run_must_pass round6-safe-sparse-release-init candidate_safe_sparse_checkout
run_must_fail round6-unsafe-sparse-release-init candidate_unsafe_sparse_checkout
run_must_fail formal-build-without-tag formal_without_tag

run_must_fail rc-build-without-tag rc_success
run_must_fail_with rc-zero-suffix \
  'RC builds require RELEASE_RC_TAG=v0.15-rc.N with N >= 1 and no leading zero' \
  rc_zero_suffix
run_must_fail_with rc-leading-zero-suffix \
  'RC builds require RELEASE_RC_TAG=v0.15-rc.N with N >= 1 and no leading zero' \
  rc_leading_zero_suffix
run_must_fail mismatched-rc-commit rc_wrong_commit
run_must_fail mismatched-rc-tree rc_wrong_tree
run_must_fail dirty-rc-conflict rc_dirty_conflict
run_must_fail candidate-rc-conflict rc_candidate_conflict
run_must_fail rc-source-date-override rc_wrong_epoch

git -C "$fixture" tag v0.15
run_must_fail formal-build-with-lightweight-tag formal_without_tag
run_must_fail candidate-after-lightweight-formal-tag candidate_success
git -C "$fixture" tag -d v0.15 >/dev/null

git -C "$fixture" tag v0.15-rc.3
run_must_fail rc-build-with-lightweight-tag rc_success
git -C "$fixture" tag -d v0.15-rc.3 >/dev/null

git -C "$fixture" tag -a v0.15-rc.3 -m 'sandbox v0.15-rc.3'
run_must_pass rc-build-with-annotated-tag rc_success
run_must_fail rc-cannot-run-formal-operation rc_cannot_run_formal_operation
run_must_fail rc-cannot-run-candidate-operation rc_cannot_run_candidate_operation

git -C "$fixture" tag -a v0.15 -m 'formal v0.15'
run_must_pass formal-build-with-annotated-tag formal_with_annotated_tag
run_must_fail candidate-after-formal-tag candidate_success
run_must_fail rc-after-formal-tag rc_success
git -C "$fixture" tag -d v0.15 >/dev/null
git -C "$fixture" tag -d v0.15-rc.3 >/dev/null

sed -i 's/Version = "0\.15"/Version = "0.15.0"/' "$fixture/internal/buildinfo/buildinfo.go"
run_must_fail_with three-component-project-alias \
  'cannot read the exact two-component source version from internal/buildinfo/buildinfo.go' \
  candidate_success
git -C "$fixture" checkout -q -- internal/buildinfo/buildinfo.go

printf 'all candidate release contracts passed\n'
