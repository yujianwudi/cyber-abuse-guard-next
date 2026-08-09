#!/usr/bin/env bash
set -euo pipefail

root="$(cd "${BASH_SOURCE[0]%/*}/.." && pwd -P)"
# shellcheck source=release-common.sh
source "$root/scripts/release-common.sh"
release_require_commands git mktemp rm mkdir sed jq cmp date

# GIT_NO_LAZY_FETCH is required to prove that the excluded synthetic blob was
# never materialized. Reject older Git clients explicitly instead of turning an
# unsupported environment into a misleading reproducibility failure.
require_git_no_lazy_fetch_contract() {
  local version_text major minor
  version_text="$(git version)"
  if [[ "$version_text" =~ ^git\ version\ ([0-9]+)\.([0-9]+)(\.|$) ]]; then
    major="${BASH_REMATCH[1]}"
    minor="${BASH_REMATCH[2]}"
  else
    release_die "cannot parse Git version for the GIT_NO_LAZY_FETCH contract"
  fi
  if ((major < 2 || (major == 2 && minor < 39))); then
    release_die "candidate contract requires Git 2.39 or newer for GIT_NO_LAZY_FETCH"
  fi
}
require_git_no_lazy_fetch_contract

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
  '  Version = "1.0.0"' \
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
  [[ "$RELEASE_ARTIFACT_VERSION" == 1.0.0 ]]
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
  RELEASE_RC_TAG="${RELEASE_RC_TAG:-v1.0.0-rc.1}"
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
  [[ "$RELEASE_ARTIFACT_VERSION" == 1.0.0-rc.1 ]]
  [[ "$RELEASE_DIRTY" == false ]]
}

rc_wrong_commit() {
  RELEASE_RC_EXPECTED_COMMIT=0000000000000000000000000000000000000000 rc_case
}

rc_wrong_tree() {
  RELEASE_RC_EXPECTED_TREE=0000000000000000000000000000000000000000 rc_case
}

rc_zero_suffix() {
  RELEASE_RC_TAG=v1.0.0-rc.0 rc_case
}

rc_leading_zero_suffix() {
  RELEASE_RC_TAG=v1.0.0-rc.02 rc_case
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

blobless_local_fetch_contract() {
  local origin="$work/blobless-origin"
  local clone="$work/blobless-clone"
  local origin_commit restricted_blob blob_state
  local upload_pack='git -c uploadpack.allowFilter=true -c uploadpack.allowAnySHA1InWant=true upload-pack'
  local -a promisor_markers

  mkdir -p "$origin/testdata/round9-independent-benign-v1"
  git -C "$origin" init -q
  git -C "$origin" config user.name 'Round6 Blobless Contract'
  git -C "$origin" config user.email 'blobless-contract@example.invalid'
  printf 'public fixture\n' >"$origin/public.txt"
  printf 'restricted synthetic fixture\n' \
    >"$origin/testdata/round9-independent-benign-v1/cases.jsonl"
  git -C "$origin" add .
  git -C "$origin" commit -q -m 'blobless fixture'
  origin_commit="$(git -C "$origin" rev-parse HEAD)"
  restricted_blob="$(git -C "$origin" rev-parse \
    'HEAD:testdata/round9-independent-benign-v1/cases.jsonl')"

  mkdir -m 0700 -- "$clone"
  git -C "$clone" init -q
  git -C "$clone" remote add origin "$origin"
  git -C "$clone" config remote.origin.uploadpack "$upload_pack"
  git -C "$clone" fetch -q --filter=blob:none --no-tags origin "$origin_commit"
  [[ "$(git -C "$clone" rev-parse FETCH_HEAD)" == "$origin_commit" ]]
  [[ "$(git -C "$clone" rev-parse --git-common-dir)" == .git ]]
  [[ ! -e "$clone/.git/objects/info/alternates" ]]
  [[ "$(git -C "$clone" config --get remote.origin.promisor)" == true ]]
  [[ "$(git -C "$clone" config --get remote.origin.partialclonefilter)" == blob:none ]]
  [[ "$(git -C "$clone" config --get remote.origin.uploadpack)" == "$upload_pack" ]]
  shopt -s nullglob
  promisor_markers=("$clone"/.git/objects/pack/*.promisor)
  shopt -u nullglob
  ((${#promisor_markers[@]} > 0))
  blob_state="$(printf '%s\n' "$restricted_blob" | GIT_NO_LAZY_FETCH=1 \
    git -C "$clone" cat-file --batch-check='%(objectname) %(objecttype)')"
  [[ "$blob_state" == "$restricted_blob missing" ]]

  git -C "$clone" sparse-checkout set --no-cone \
    '/*' '!/testdata/round9-independent-benign-v1/**'
  git -C "$clone" checkout -q --detach "$origin_commit"
  [[ -f "$clone/public.txt" ]]
  [[ ! -e "$clone/testdata/round9-independent-benign-v1/cases.jsonl" ]]
  blob_state="$(printf '%s\n' "$restricted_blob" | GIT_NO_LAZY_FETCH=1 \
    git -C "$clone" cat-file --batch-check='%(objectname) %(objecttype)')"
  [[ "$blob_state" == "$restricted_blob missing" ]]
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
    GITHUB_REF_NAME=v1.0.0
    export GITHUB_REF_TYPE GITHUB_REF_NAME
  fi
  unset SOURCE_DATE_EPOCH
  export RELEASE_ROOT ALLOW_DIRTY_BUILD RELEASE_CANDIDATE_BUILD RELEASE_RC_BUILD
  release_init
  release_assert_tag
  release_assert_formal_build
}

write_sbom_fixture() {
  local destination="$1"
  local identity_mode="$2"
  local version_override="${3:-}"
  local module="$RELEASE_CYCLONEDX_MAIN_MODULE"
  local version ref purl has_version
  version="$(release_cyclonedx_component_version)"
  [[ -z "$version_override" ]] || version="$version_override"
  case "$identity_mode" in
    versioned)
      ref="pkg:golang/${module}@${version}?type=module"
      has_version=true
      ;;
    unversioned)
      ref="pkg:golang/${module}?type=module"
      has_version=false
      ;;
    *)
      release_die "unknown synthetic SBOM identity mode"
      ;;
  esac
  purl="${ref}&goos=linux&goarch=amd64"
  jq -n -S \
    --arg module "$module" \
    --arg version "$version" \
    --arg ref "$ref" \
    --arg purl "$purl" \
    --argjson has_version "$has_version" \
    '{
      bomFormat: "CycloneDX",
      specVersion: "1.6",
      metadata: {
        timestamp: "2000-01-01T00:00:00Z",
        component: ({
          "bom-ref": $ref,
          type: "application",
          name: $module,
          purl: $purl
        } + (if $has_version then {version: $version} else {} end))
      },
      components: [{
        "bom-ref": "pkg:golang/example.invalid/dependency@v1.0.0?type=module",
        type: "library",
        name: "example.invalid/dependency",
        version: "v1.0.0"
      }],
      dependencies: [
        {ref: $ref, dependsOn: ["pkg:golang/example.invalid/dependency@v1.0.0?type=module"]},
        {ref: "pkg:golang/example.invalid/dependency@v1.0.0?type=module"}
      ]
    }' >"$destination"
}

normalize_sbom_fixture() {
  local input="$1"
  local output="$2"
  local timestamp
  timestamp="$(date -u -d "@$RELEASE_SOURCE_DATE_EPOCH" '+%Y-%m-%dT%H:%M:%SZ')"
  release_normalize_cyclonedx_sbom "$input" "$output" "$timestamp"
}

assert_normalized_sbom_identity() {
  local sbom="$1"
  local expected_version="$2"
  local expected_kind="$3"
  local expected_ref="pkg:golang/${RELEASE_CYCLONEDX_MAIN_MODULE}@${expected_version}?type=module"
  jq -e \
    --arg version "$expected_version" \
    --arg kind "$expected_kind" \
    --arg ref "$expected_ref" \
    --arg commit "$RELEASE_GIT_COMMIT" \
    --arg tree "$RELEASE_GIT_TREE" \
    '.metadata.component.version == $version and
     .metadata.component["bom-ref"] == $ref and
     .metadata.component.purl == ($ref + "&goos=linux&goarch=amd64") and
     ([.metadata.component.properties[] |
       select(.name == "cag:source:git-commit" and .value == $commit)] | length) == 1 and
     ([.metadata.component.properties[] |
       select(.name == "cag:source:git-tree" and .value == $tree)] | length) == 1 and
     ([.metadata.component.properties[] |
       select(.name == "cag:build:kind" and .value == $kind)] | length) == 1 and
     ([.dependencies[] | select(.ref == $ref)] | length) == 1' \
    "$sbom" >/dev/null
}

candidate_sbom_identity_contract() {
  local versioned="$work/candidate-versioned.json"
  local unversioned="$work/candidate-unversioned.json"
  local normalized_versioned="$work/candidate-normalized-versioned.json"
  local normalized_unversioned="$work/candidate-normalized-unversioned.json"
  local referenced_unversioned="$work/candidate-unversioned-with-reference.json"
  local normalized_referenced="$work/candidate-normalized-with-reference.json"
  local ancestor_versioned="$work/candidate-ancestor-versioned.json"
  local normalized_ancestor="$work/candidate-normalized-ancestor.json"
  local old_ref expected_version expected_ref ancestor_version
  candidate_case
  write_sbom_fixture "$versioned" versioned
  write_sbom_fixture "$unversioned" unversioned
  old_ref="$(jq -r '.metadata.component["bom-ref"]' "$unversioned")"
  expected_version="$(release_cyclonedx_component_version)"
  expected_ref="pkg:golang/github.com/yujianwudi/cyber-abuse-guard-next@${expected_version}?type=module"
  ancestor_version="v0.14.1-0.20260716010203-${RELEASE_GIT_COMMIT:0:12}"
  write_sbom_fixture "$ancestor_versioned" versioned "$ancestor_version"
  jq --arg old_ref "$old_ref" \
    '.dependencies[1].dependsOn = [$old_ref]' \
    "$unversioned" >"$referenced_unversioned"
  normalize_sbom_fixture "$versioned" "$normalized_versioned"
  normalize_sbom_fixture "$unversioned" "$normalized_unversioned"
  normalize_sbom_fixture "$ancestor_versioned" "$normalized_ancestor"
  cmp -s "$normalized_versioned" "$normalized_unversioned"
  cmp -s "$normalized_ancestor" "$normalized_unversioned"
  assert_normalized_sbom_identity "$normalized_versioned" "$expected_version" candidate
  normalize_sbom_fixture "$referenced_unversioned" "$normalized_referenced"
  jq -e \
    --arg old_ref "$old_ref" \
    --arg expected_ref "$expected_ref" \
    '([.dependencies[] | .dependsOn[]? | select(. == $old_ref)] | length) == 0 and
     ([.dependencies[] | .dependsOn[]? | select(. == $expected_ref)] | length) == 1' \
    "$normalized_referenced" >/dev/null
}

candidate_sbom_rejects_mutation() {
  local mutation="$1"
  local raw="$work/candidate-invalid-${mutation}.json"
  local mutated="$work/candidate-invalid-${mutation}-mutated.json"
  local output="$work/candidate-invalid-${mutation}-normalized.json"
  candidate_case
  if [[ "$mutation" == pseudo-suffix ]]; then
    write_sbom_fixture "$raw" versioned \
      'v0.14.1-0.20260716010203-000000000000'
  else
    write_sbom_fixture "$raw" versioned
  fi
  case "$mutation" in
    module)
      jq '.metadata.component.name = "example.invalid/wrong"' "$raw" >"$mutated"
      ;;
    duplicate)
      jq '.dependencies += [.dependencies[0]]' "$raw" >"$mutated"
      ;;
    purl)
      jq '.metadata.component.purl += "-wrong"' "$raw" >"$mutated"
      ;;
    version)
      jq '.metadata.component.version = "v9.9.9"' "$raw" >"$mutated"
      ;;
    property)
      jq '.metadata.component.properties = [{name:"cag:source:git-commit",value:"wrong"}]' \
        "$raw" >"$mutated"
      ;;
    depends-on)
      jq '.dependencies[0].dependsOn = "not-an-array"' "$raw" >"$mutated"
      ;;
    pseudo-suffix)
      jq '.' "$raw" >"$mutated"
      ;;
    *)
      release_die "unknown synthetic SBOM mutation"
      ;;
  esac
  normalize_sbom_fixture "$mutated" "$output"
}

rc_sbom_identity_contract() {
  local raw="$work/rc-sbom.json"
  local normalized="$work/rc-sbom-normalized.json"
  local unversioned="$work/rc-sbom-unversioned.json"
  local normalized_unversioned="$work/rc-sbom-normalized-unversioned.json"
  local ancestor_version
  rc_case
  ancestor_version="v0.14.1-0.20260716010203-${RELEASE_GIT_COMMIT:0:12}"
  write_sbom_fixture "$raw" versioned "$ancestor_version"
  write_sbom_fixture "$unversioned" unversioned
  normalize_sbom_fixture "$raw" "$normalized"
  normalize_sbom_fixture "$unversioned" "$normalized_unversioned"
  cmp -s "$normalized" "$normalized_unversioned"
  assert_normalized_sbom_identity "$normalized" v1.0.0-rc.1 rc
}

formal_sbom_identity_contract() {
  local raw="$work/formal-sbom.json"
  local normalized="$work/formal-sbom-normalized.json"
  formal_with_annotated_tag
  write_sbom_fixture "$raw" versioned
  normalize_sbom_fixture "$raw" "$normalized"
  assert_normalized_sbom_identity "$normalized" v1.0.0 formal
}

development_sbom_identity_contract() {
  local raw="$work/development-sbom.json"
  local normalized="$work/development-sbom-normalized.json"
  local expected_version
  RELEASE_ROOT="$fixture"
  ALLOW_DIRTY_BUILD=1
  RELEASE_CANDIDATE_BUILD=0
  RELEASE_RC_BUILD=0
  unset SOURCE_DATE_EPOCH
  export RELEASE_ROOT ALLOW_DIRTY_BUILD RELEASE_CANDIDATE_BUILD RELEASE_RC_BUILD
  release_init
  expected_version="v1.0.0-dirty.${RELEASE_GIT_COMMIT:0:12}"
  write_sbom_fixture "$raw" unversioned
  normalize_sbom_fixture "$raw" "$normalized"
  assert_normalized_sbom_identity "$normalized" "$expected_version" development
  [[ "$expected_version" != v1.0.0 ]]
}

run_must_pass clean-exact-candidate candidate_success
run_must_pass candidate-versioned-and-unversioned-sbom candidate_sbom_identity_contract
for sbom_mutation in module duplicate purl version property depends-on pseudo-suffix; do
  run_must_fail "candidate-sbom-${sbom_mutation}" \
    candidate_sbom_rejects_mutation "$sbom_mutation"
done
run_must_fail mismatched-candidate-commit candidate_wrong_commit
run_must_fail mismatched-candidate-tree candidate_wrong_tree
run_must_fail dirty-candidate-conflict candidate_dirty_conflict
run_must_fail candidate-source-date-override candidate_wrong_epoch
run_must_fail candidate-cannot-run-formal-operation candidate_cannot_run_formal_operation
run_must_fail candidate-cannot-run-rc-operation candidate_cannot_run_rc_operation
run_must_pass round6-safe-sparse-path-case-folding round6_sparse_path_contract
run_must_pass independent-blobless-local-fetch blobless_local_fetch_contract
run_must_pass rc-release-script-executable-mode rc_script_mode_contract
run_must_pass round6-safe-sparse-release-init candidate_safe_sparse_checkout
run_must_fail round6-unsafe-sparse-release-init candidate_unsafe_sparse_checkout
run_must_fail formal-build-without-tag formal_without_tag

run_must_fail rc-build-without-tag rc_success
run_must_fail_with rc-zero-suffix \
  'RC builds require RELEASE_RC_TAG=v1.0.0-rc.N with N >= 1 and no leading zero' \
  rc_zero_suffix
run_must_fail_with rc-leading-zero-suffix \
  'RC builds require RELEASE_RC_TAG=v1.0.0-rc.N with N >= 1 and no leading zero' \
  rc_leading_zero_suffix
run_must_fail mismatched-rc-commit rc_wrong_commit
run_must_fail mismatched-rc-tree rc_wrong_tree
run_must_fail dirty-rc-conflict rc_dirty_conflict
run_must_fail candidate-rc-conflict rc_candidate_conflict
run_must_fail rc-source-date-override rc_wrong_epoch

git -C "$fixture" tag v1.0.0
run_must_fail formal-build-with-lightweight-tag formal_without_tag
run_must_fail candidate-after-lightweight-formal-tag candidate_success
git -C "$fixture" tag -d v1.0.0 >/dev/null

git -C "$fixture" tag v1.0.0-rc.1
run_must_fail rc-build-with-lightweight-tag rc_success
git -C "$fixture" tag -d v1.0.0-rc.1 >/dev/null

git -C "$fixture" tag -a v1.0.0-rc.1 -m 'sandbox v1.0.0-rc.1'
run_must_pass rc-build-with-annotated-tag rc_success
run_must_pass rc-sbom-exact-tag-identity rc_sbom_identity_contract
run_must_fail rc-cannot-run-formal-operation rc_cannot_run_formal_operation
run_must_fail rc-cannot-run-candidate-operation rc_cannot_run_candidate_operation

git -C "$fixture" tag -a v1.0.0 -m 'formal v1.0.0'
run_must_pass formal-build-with-annotated-tag formal_with_annotated_tag
run_must_pass formal-sbom-exact-tag-identity formal_sbom_identity_contract
run_must_fail candidate-after-formal-tag candidate_success
run_must_fail rc-after-formal-tag rc_success
git -C "$fixture" tag -d v1.0.0 >/dev/null
git -C "$fixture" tag -d v1.0.0-rc.1 >/dev/null
run_must_pass development-sbom-cannot-claim-formal development_sbom_identity_contract

sed -i 's/Version = "1\.0\.0"/Version = "1.0"/' "$fixture/internal/buildinfo/buildinfo.go"
run_must_fail_with three-component-project-alias \
  'cannot read the exact three-component semantic source version from internal/buildinfo/buildinfo.go' \
  candidate_success
git -C "$fixture" checkout -q -- internal/buildinfo/buildinfo.go

printf 'all candidate release contracts passed\n'
