#!/usr/bin/env bash
set -euo pipefail

PATH=/usr/bin:/bin
export PATH
readonly PATH

root="$(cd "${BASH_SOURCE[0]%/*}/.." && pwd -P)"
# shellcheck source=release-common.sh
source "$root/scripts/release-common.sh"
release_require_commands awk grep sed sha256sum sort tr wc mktemp rm

doc_root="${RELEASE_DOC_ROOT:-$root}"
fixture_mode="${RELEASE_DOC_FIXTURE_MODE:-0}"

fail() {
  printf 'release document consistency error: %s\n' "$*" >&2
  exit 1
}

python3_bin=/usr/bin/python3
[[ -x "$python3_bin" ]] || fail "reviewed Python interpreter is unavailable: $python3_bin"

[[ -d "$doc_root" ]] || fail "release document root is not a directory: $doc_root"
doc_root="$(cd "$doc_root" && pwd -P)"
[[ "$fixture_mode" == 0 || "$fixture_mode" == 1 ]] || \
  fail "RELEASE_DOC_FIXTURE_MODE must be 0 or 1"
if [[ "$doc_root" == "$root" ]]; then
  if [[ -n "${RELEASE_DOC_ROOT+x}" || -n "${RELEASE_DOC_FIXTURE_MODE+x}" ||
    -n "${CURRENT_RELEASE_VERSION+x}" || -n "${CURRENT_RULESET_SHA256+x}" ||
    -n "${CURRENT_CLASSIFIER_POLICY_VERSION+x}" || -n "${CURRENT_CLASSIFIER_POLICY_SHA256+x}" ]]; then
    fail "source-tree release document verification forbids document-root and CURRENT_* overrides"
  fi
elif [[ "$fixture_mode" != 1 ]]; then
  fail "external release document roots are allowed only with RELEASE_DOC_FIXTURE_MODE=1"
fi

verify_canonical_relative_path() {
  local relative="$1"
  local component traversed="" candidate canonical="$doc_root" canonical_parent
  local -a components=()

  [[ -n "$relative" && "$relative" != /* ]] ||
    fail "release document path must be a non-empty relative path: $relative"
  IFS='/' read -r -a components <<<"$relative"
  for component in "${components[@]}"; do
    [[ -n "$component" && "$component" != "." && "$component" != ".." ]] ||
      fail "release document path contains an unsafe component: $relative"
  done
  for component in "${components[@]}"; do
    if [[ -n "$traversed" ]]; then
      traversed="$traversed/$component"
    else
      traversed="$component"
    fi
    candidate="$canonical/$component"
    [[ ! -L "$candidate" ]] ||
      fail "release document path component must not be a symlink: $traversed"
    [[ -e "$candidate" ]] || return 0
    if [[ -d "$candidate" ]]; then
      canonical="$(cd -- "$candidate" && pwd -P)" ||
        fail "cannot canonicalize release document path: $traversed"
    else
      canonical_parent="$(cd -- "${candidate%/*}" && pwd -P)" ||
        fail "cannot canonicalize release document path parent: $traversed"
      canonical="$canonical_parent/${candidate##*/}"
    fi
    case "$canonical" in
      "$doc_root" | "$doc_root"/*)
        ;;
      *)
        fail "release document path escapes canonical document root: $traversed"
        ;;
    esac
  done
}

current_ruleset_sha256="${CURRENT_RULESET_SHA256:-$(release_ruleset_hash)}"
[[ "$current_ruleset_sha256" =~ ^[0-9a-f]{64}$ ]] || \
  fail "current ruleset SHA-256 is not a lowercase 64-character digest"

current_classifier_policy_version="${CURRENT_CLASSIFIER_POLICY_VERSION:-}"
if [[ -z "$current_classifier_policy_version" ]]; then
  current_classifier_policy_version="$(sed -nE \
    's/^const ClassifierPolicyVersion = "([^"]+)"/\1/p' \
    "$root/internal/classifier/policy_identity.go" | sed -n '1p')"
fi
[[ "$current_classifier_policy_version" =~ ^classifier-policy-v[0-9]+$ ]] || \
  fail "cannot determine the current classifier policy version"

current_classifier_policy_sha256="${CURRENT_CLASSIFIER_POLICY_SHA256:-}"
if [[ -z "$current_classifier_policy_sha256" ]]; then
  current_classifier_policy_sha256="$(sed -nE \
    's/^const ClassifierPolicySHA256 = "([0-9a-f]{64})"/\1/p' \
    "$root/internal/classifier/policy_identity.go" | sed -n '1p')"
fi
[[ "$current_classifier_policy_sha256" =~ ^[0-9a-f]{64}$ ]] || \
  fail "cannot determine the current classifier policy SHA-256"

current_release_version="${CURRENT_RELEASE_VERSION:-}"
if [[ -z "$current_release_version" ]]; then
  current_release_version="$(sed -nE \
    's/^[[:space:]]*Version[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/p' \
    "$root/internal/buildinfo/buildinfo.go" | sed -n '1p')"
fi
if [[ "$fixture_mode" == 1 ]]; then
  [[ "$current_release_version" =~ ^[0-9]+\.[0-9]+(\.[0-9]+)?$ ]] || \
    fail "cannot determine the exact fixture release version"
else
  [[ "$current_release_version" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] || \
    fail "cannot determine the exact three-component semantic release version"
fi

round14_audit_receipt_tool="$root/scripts/current_cpa_audit_unit_receipt.py"
round14_audit_receipt_relative="docs/reports/ROUND14_CPA_AUDIT_UNIT_RECEIPT.json"
round14_audit_receipt="$doc_root/$round14_audit_receipt_relative"
if [[ "$fixture_mode" == 1 && "$current_release_version" != 1.0.0 ]]; then
  # The legacy v0.16 mutation fixture predates the Round 14 document set. It
  # still binds the current reviewed tool closure from the real source tree.
  round14_audit_receipt="$root/$round14_audit_receipt_relative"
fi
round14_cpa_module_sum='h1:30twcgoSCSjBtc4tgZBKPC4sQpsEWwgu4d9r7tIDpQQ='
round14_cpa_go_mod_sum='h1:lTHwMAGajc1wKGQiRtDvYbwV0FWsM7sy+N0ZU5/gxJQ='
round14_cpa_archive_sha256='a7cccc8f94b07660303c1874fb6bedae6d573a0f3c4c0b17ad8cf7885dd7a051'
round14_cpa_binary_sha256='e0df04ae5e632649c36230533d9608058dd09689113947809e4824f598f36a9b'
round14_cpa_version='v7.2.142'
round14_cpa_commit='1f53b2eb03b9e963bac647e5566ca2b304239116'
round14_classifier_policy_sha256='a25cd83ea9a6d409a09a4bdd9aa75357ff989757272a006a4f60a32d77ad76db'
round14_csam_text_policy_sha256='a55c706059a27bd40156ea34ba9c5fb250baecefca19da18745620ed9fb556ee'
if [[ "$round14_audit_receipt" == "$doc_root/$round14_audit_receipt_relative" ]]; then
  verify_canonical_relative_path "$round14_audit_receipt_relative"
fi
[[ -f "$round14_audit_receipt" && ! -L "$round14_audit_receipt" ]] || \
  fail "Round 14 CPA audit unit receipt is missing or unsafe: $round14_audit_receipt_relative"
[[ -f "$round14_audit_receipt_tool" && ! -L "$round14_audit_receipt_tool" ]] || \
  fail "Round 14 CPA audit unit receipt validator is missing or unsafe"

audit_identity_output=""
if ! audit_identity_output="$("$python3_bin" -I -B "$round14_audit_receipt_tool" validate \
  --receipt "$round14_audit_receipt" --output-lines)"; then
  fail "Round 14 CPA audit unit receipt validation failed"
fi
audit_identity_values=()
mapfile -t audit_identity_values <<<"$audit_identity_output"
[[ "${#audit_identity_values[@]}" == 15 ]] || \
  fail "cannot determine the current CPA audit execution receipt closure"
current_audit_runner_bundle_sha256="${audit_identity_values[0]}"
current_audit_contract_sha256="${audit_identity_values[1]}"
current_audit_run_source_sha256="${audit_identity_values[2]}"
current_audit_machine_schema_sha256="${audit_identity_values[3]}"
current_audit_tool_test_count="${audit_identity_values[4]}"
current_audit_tool_skip_count="${audit_identity_values[5]}"
current_audit_tool_status="${audit_identity_values[6]}"
current_audit_tool_started_at="${audit_identity_values[7]}"
current_audit_tool_finished_at="${audit_identity_values[8]}"
current_audit_tool_elapsed_ms="${audit_identity_values[9]}"
current_audit_tool_receipt_sha256="${audit_identity_values[10]}"
current_audit_test_sources_sha256="${audit_identity_values[11]}"
current_audit_test_ids_sha256="${audit_identity_values[12]}"
current_audit_tool_command="${audit_identity_values[13]}"
current_audit_tool_platform="${audit_identity_values[14]}"
for digest in \
  "$current_audit_runner_bundle_sha256" \
  "$current_audit_contract_sha256" \
  "$current_audit_run_source_sha256" \
  "$current_audit_machine_schema_sha256" \
  "$current_audit_tool_receipt_sha256" \
  "$current_audit_test_sources_sha256" \
  "$current_audit_test_ids_sha256"; do
  [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || \
    fail "current CPA audit runner identity is not a lowercase 64-character digest"
done
[[ "$current_audit_tool_test_count" =~ ^[1-9][0-9]*$ ]] || \
  fail "current CPA audit tool test count is invalid"
[[ "$current_audit_tool_test_count" == 315 ]] || \
  fail "current CPA audit harness must retain the reviewed 315-test closure"
[[ "$current_audit_tool_skip_count" == 0 ]] || \
  fail "current CPA audit Linux receipt must not skip tests"
[[ "$current_audit_tool_status" == PASS ]] || \
  fail "current CPA audit Linux receipt must report PASS"
[[ "$current_audit_tool_elapsed_ms" =~ ^[1-9][0-9]*$ ]] || \
  fail "current CPA audit Linux receipt elapsed time is invalid"
[[ "$current_audit_tool_platform" == Linux/x86_64 ]] || \
  fail "current CPA audit receipt platform must be Linux/x86_64"
[[ "$current_audit_tool_command" == \
  /usr/bin/python3.*' -I -B -m unittest discover -s tools/current-cpa-audit/tests -p test_*.py' ]] || \
  fail "current CPA audit receipt command differs from the reviewed Linux command"

if [[ "$doc_root" == "$root" ]]; then
  current_audit_execution_receipt="$(mktemp "${TMPDIR:-/tmp}/cag-current-cpa-audit-unit.XXXXXX.json")"
  current_audit_execution_output=""
  if ! current_audit_execution_output="$(
    GOTOOLCHAIN=go1.26.6 PYTHONDONTWRITEBYTECODE=1 \
      "$python3_bin" -I -B "$round14_audit_receipt_tool" run \
      --output "$current_audit_execution_receipt" --replace
  )"; then
    rm -f -- "$current_audit_execution_receipt"
    fail "current source tree failed the live Linux CPA audit unit execution gate"
  fi
  rm -f -- "$current_audit_execution_receipt"
  current_audit_execution_values=()
  mapfile -t current_audit_execution_values <<<"$current_audit_execution_output"
  [[ "${#current_audit_execution_values[@]}" == 15 ]] || \
    fail "live Linux CPA audit unit execution returned an invalid closure"
  [[ "${current_audit_execution_values[0]}" == "$current_audit_runner_bundle_sha256" && \
    "${current_audit_execution_values[1]}" == "$current_audit_contract_sha256" && \
    "${current_audit_execution_values[2]}" == "$current_audit_run_source_sha256" && \
    "${current_audit_execution_values[3]}" == "$current_audit_machine_schema_sha256" && \
    "${current_audit_execution_values[4]}" == "$current_audit_tool_test_count" && \
    "${current_audit_execution_values[5]}" == 0 && \
    "${current_audit_execution_values[6]}" == PASS && \
    "${current_audit_execution_values[11]}" == "$current_audit_test_sources_sha256" && \
    "${current_audit_execution_values[12]}" == "$current_audit_test_ids_sha256" && \
    "${current_audit_execution_values[14]}" == Linux/x86_64 ]] || \
    fail "live Linux CPA audit unit execution differs from the current reviewed closure"
fi

verify_round14_repository_contracts() {
  local workflow_directory="$doc_root/.github/workflows"
  local workflow_index="$workflow_directory/README.md"
  local relative workflow workflow_name
  local -a active_workflows=(
    .github/workflows/ci.yml
    .github/workflows/codeql.yml
    .github/workflows/policy-gate.yml
    .github/workflows/release-rc.yml
  )
  local -a indexed_validation_workflows=(
    .github/workflows/ci.yml
    .github/workflows/codeql.yml
    .github/workflows/policy-gate.yml
  )
  local -A active_workflow_allowlist=()

  verify_canonical_relative_path .github
  verify_canonical_relative_path .github/workflows
  [[ -d "$workflow_directory" && ! -L "$workflow_directory" ]] ||
    fail "active workflow directory must be a regular non-symlink directory: .github/workflows"
  for relative in "${active_workflows[@]}"; do
    [[ -z "${active_workflow_allowlist[$relative]+x}" ]] ||
      fail "active workflow allowlist contains a duplicate: $relative"
    active_workflow_allowlist["$relative"]=1
    verify_canonical_relative_path "$relative"
    [[ -f "$doc_root/$relative" && ! -L "$doc_root/$relative" ]] ||
      fail "required Round 14 active workflow must be a regular non-symlink file: $relative"
  done
  for workflow in "$workflow_directory"/*.yml "$workflow_directory"/*.yaml; do
    [[ -e "$workflow" || -L "$workflow" ]] || continue
    relative=".github/workflows/${workflow##*/}"
    [[ -n "${active_workflow_allowlist[$relative]+x}" ]] ||
      fail "workflow directory contains an unreviewed Round 14 active workflow: $relative"
  done

  verify_canonical_relative_path .github/workflows/README.md
  [[ -f "$workflow_index" && ! -L "$workflow_index" ]] ||
    fail "workflow index must be a regular non-symlink file: .github/workflows/README.md"
  for relative in "${indexed_validation_workflows[@]}"; do
    workflow_name="${relative##*/}"
    grep -Fq "| \`$workflow_name\` |" "$workflow_index" ||
      fail "workflow index lost the Round 14 active workflow: $relative"
  done
  grep -Fq 'The active workflow directory contains exactly four repository workflows:' "$doc_root/docs/README.md" ||
    fail "documentation index lost the exact four-workflow Round 14 boundary"
  for platform_workflow in \
    dynamic/dependabot/dependabot-updates \
    dynamic/dependabot/update-graph; do
    grep -Fqx -- "- \`$platform_workflow\`" "$workflow_index" ||
      fail "workflow index lost the bounded platform workflow: $platform_workflow"
  done
  grep -Fqx 'round14_platform_dynamic_workflows: ALLOWLIST_ONLY / dynamic/dependabot/dependabot-updates / dynamic/dependabot/update-graph / ZERO_OTHER_ACTIVE_PATHS' \
    "$doc_root/docs/ROUND14_STATUS.md" ||
    fail "ROUND14_STATUS.md lost the exact bounded platform workflow line"
  grep -Fq 'RC publication' "$doc_root/docs/README.md" ||
    fail "documentation index lost the gated RC publication boundary"
  grep -Fqx "  RC_CPA_VERSION: $round14_cpa_version" "$doc_root/.github/workflows/release-rc.yml" ||
    fail "release-rc.yml lost the exact CPA $round14_cpa_version identity"
  grep -Fqx "  RC_CPA_COMMIT: $round14_cpa_commit" "$doc_root/.github/workflows/release-rc.yml" ||
    fail "release-rc.yml lost the exact CPA $round14_cpa_version commit"
  grep -Fqx '  RC_CPA_C_ABI: '\''1'\''' "$doc_root/.github/workflows/release-rc.yml" ||
    fail "release-rc.yml lost C ABI 1"
  grep -Fqx '  RC_CPA_RPC_SCHEMA: '\''3'\''' "$doc_root/.github/workflows/release-rc.yml" ||
    fail "release-rc.yml lost RPC schema 3"
  grep -Fqx '  RC_SECOND_MACHINE_SCHEMA: cyber-abuse-guard.second-machine-release-admission.v3' \
    "$doc_root/.github/workflows/release-rc.yml" ||
    fail "release-rc.yml lost second-machine admission schema v3"

  if [[ "$doc_root" == "$root" ]]; then
    grep -Fq '`docs/ROUND9_HOST_RUNNER.md`' \
      "$root/integration/round9countedmock/README.md" ||
      fail "Round 9 counted-Mock README lost its Host contract link"
    grep -Fq '[Round 9 audit schema v6](ROUND9_AUDIT_SCHEMA_V6.md)' \
      "$root/docs/README.md" ||
      fail "documentation index lost the Round 9 audit-schema link"
    grep -Fq '[Round 11 runtime-assurance task book](ROUND11_RUNTIME_ASSURANCE_TASK_BOOK.md)' \
      "$root/docs/README.md" ||
      fail "documentation index lost the Round 11 task-book link"
    grep -Fq '[Round 9 operator-owned rollout and rollback](ROUND9_OPERATOR_ROLLOUT.md)' \
      "$root/docs/README.md" ||
      fail "documentation index lost the Round 9 operator-runbook link"
    grep -Fq '[Round 9 execution record and traceability matrix](reports/ROUND9_EXECUTION_RECORD.md)' \
      "$root/docs/README.md" ||
      fail "documentation index lost the Round 9 execution-record link"
    grep -Fq 'HTTP `503` and the fixed `audit_unavailable` error' \
      "$root/docs/ROUND9_AUDIT_SCHEMA_V6.md" ||
      fail "Round 9 audit guide lost the enabled-but-unavailable management contract"
  fi
}

if [[
  ("$fixture_mode" == 0 && "$current_release_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$) ||
  ("$fixture_mode" == 1 && "$current_release_version" == "1.0.0")
]]; then
  round14_documents=(
    README.md
    README_CN.md
    CHANGELOG.md
    SECURITY.md
    docs/AUDIT_HANDOFF.md
    docs/DESIGN.md
    docs/INSTALL_DOCKER.md
    docs/LIMITATIONS.md
    docs/RAW_CAPTURE.md
    docs/RC2_PLATFORM_DRIFT_RECOVERY.md
    docs/README.md
    docs/RELEASE_POLICY.md
    docs/ROUND6_DEVELOPMENT_HANDOFF.md
    docs/ROUND6_LIMITATIONS.md
    docs/ROUND6_RELEASE_GATE.md
    docs/ROUND6_CONFIG_MIGRATION.md
    docs/ROUND6_STREAMING_SCANNER_DESIGN.md
    docs/ROUND8_HOST_RUNNER.md
    docs/ROUND9_AUDIT_SCHEMA_V6.md
    docs/ROUND9_HOST_RUNNER.md
    docs/ROUND9_OPERATOR_ROLLOUT.md
    docs/ROUND11_RUNTIME_ASSURANCE_TASK_BOOK.md
    docs/ROUND12_PRODUCTION_HARDENING_TASK_BOOK.md
    docs/ROUND12_STATUS.md
    docs/RULES.md
    docs/ROUND13_CPA_V7_2_125_V1_RC1_TASK_BOOK.md
    docs/ROUND13_STATUS.md
    docs/ROUND14_CPA_V7_2_130_SCHEMA3_TASK_BOOK.md
    docs/ROUND14_EXECUTION_AND_RC1_ACCEPTANCE.md
    docs/ROUND14_STATUS.md
    docs/THREAT_MODEL.md
    docs/reports/CPA_INTEGRATION.md
    docs/reports/PHASE0_CPA_CONTRACT.md
    docs/reports/PROMPT_INJECTION_REVIEW.md
    docs/reports/RELEASE_EVIDENCE.md
    docs/reports/ROUND8_RELEASE_READINESS.md
    docs/reports/PERFORMANCE.md
    docs/reports/PRIVACY.md
    docs/reports/PUBLIC_JAILBREAK_REPOSITORY_REVIEW.md
    docs/reports/ROUND8_CALIBRATION.md
    docs/reports/ROUND9_EXECUTION_RECORD.md
    docs/reports/TEST_REPORT.md
    docs/reports/ROUND14_CPA_AUDIT_UNIT_RECEIPT.json
    integration/cpalatestcontract/README.md
    integration/pluginstorecontract/README.md
    tools/current-cpa-audit/README.md
  )
  for relative in "${round14_documents[@]}"; do
    path="$doc_root/$relative"
    verify_canonical_relative_path "$relative"
    [[ -f "$path" && ! -L "$path" ]] || fail "required Round 14 document is missing or unsafe: $relative"
  done

  current_classifier_prologue_documents=(
    README.md
    README_CN.md
    docs/ROUND6_CONFIG_MIGRATION.md
    docs/ROUND6_STREAMING_SCANNER_DESIGN.md
    docs/ROUND8_HOST_RUNNER.md
    docs/ROUND9_AUDIT_SCHEMA_V6.md
    docs/ROUND9_HOST_RUNNER.md
    docs/ROUND9_OPERATOR_ROLLOUT.md
    docs/ROUND11_RUNTIME_ASSURANCE_TASK_BOOK.md
    docs/ROUND12_PRODUCTION_HARDENING_TASK_BOOK.md
    docs/ROUND12_STATUS.md
    docs/RULES.md
    docs/reports/CPA_INTEGRATION.md
    docs/reports/PERFORMANCE.md
    docs/reports/PRIVACY.md
    docs/reports/PUBLIC_JAILBREAK_REPOSITORY_REVIEW.md
    docs/reports/ROUND8_CALIBRATION.md
    docs/reports/ROUND9_EXECUTION_RECORD.md
  )
  current_policy_version='current_classifier_policy_version: classifier-policy-v20'
  current_policy_sha="current_classifier_policy_sha256: $round14_classifier_policy_sha256"
  for relative in "${current_classifier_prologue_documents[@]}"; do
    document="$doc_root/$relative"
    prologue="$(sed -n '1,20p' "$document")"
    [[ "$(grep -Fxc "$current_policy_version" <<<"$prologue")" == 1 && \
       "$(grep -Fxc "$current_policy_sha" <<<"$prologue")" == 1 ]] || \
      fail "$relative lost the exact current classifier identity in its first 20 lines"
    [[ "$(grep -Fxc "$current_policy_version" "$document")" == 1 && \
       "$(grep -Fxc "$current_policy_sha" "$document")" == 1 ]] || \
      fail "$relative must contain exactly one current classifier identity; historical body identities remain allowed"
  done

  grep -Fqx 'current_source_version: 1.0.0' "$doc_root/README.md" || \
    fail "README.md lost the current 1.0.0 source identity"
  grep -Fqx 'current_rc_tag: v1.0.0-rc.3' "$doc_root/README.md" || \
    fail "README.md lost the current RC tag identity"
  grep -Fqx "current_cpa_target: $round14_cpa_version / $round14_cpa_commit" "$doc_root/README.md" || \
    fail "README.md lost the CPA $round14_cpa_version identity"
  grep -Fqx 'current_source_version: 1.0.0' "$doc_root/README_CN.md" || \
    fail "README_CN.md lost the current 1.0.0 source identity"
  grep -Fqx 'current_rc_tag: v1.0.0-rc.3' "$doc_root/README_CN.md" || \
    fail "README_CN.md lost the current RC tag identity"
  grep -Fqx "current_cpa_target: $round14_cpa_version / $round14_cpa_commit" "$doc_root/README_CN.md" || \
    fail "README_CN.md lost the CPA $round14_cpa_version identity"
  grep -Fqx 'current_source_version: 1.0.0' "$doc_root/docs/RELEASE_POLICY.md" || \
    fail "RELEASE_POLICY.md lost the current source version"
  grep -Fqx 'current_rc_tag: v1.0.0-rc.3' "$doc_root/docs/RELEASE_POLICY.md" || \
    fail "RELEASE_POLICY.md lost the current RC tag"
  grep -Fqx 'current_rc_prerelease: true' "$doc_root/docs/RELEASE_POLICY.md" || \
    fail "RELEASE_POLICY.md lost prerelease=true"
  grep -Fqx 'current_rc_make_latest: false' "$doc_root/docs/RELEASE_POLICY.md" || \
    fail "RELEASE_POLICY.md lost make_latest=false"
  grep -Fq '## Unreleased - v1.0.0-rc.3' "$doc_root/CHANGELOG.md" || \
    fail "CHANGELOG.md lost the active v1.0.0-rc.3 section"
  grep -Fq "round14_cpa_target: $round14_cpa_version / $round14_cpa_commit" "$doc_root/docs/ROUND14_STATUS.md" || \
    fail "ROUND14_STATUS.md lost the exact CPA identity"
  for relative in \
    README.md \
    README_CN.md \
    docs/ROUND14_EXECUTION_AND_RC1_ACCEPTANCE.md \
    docs/ROUND14_STATUS.md; do
    grep -Fq 'csam-text-policy-v1' "$doc_root/$relative" &&
      grep -Fq "$round14_csam_text_policy_sha256" \
        "$doc_root/$relative" ||
      fail "$relative lost the exact CSAM text-policy identity"
    grep -Fq 'cyber-abuse-guard.second-machine-release-admission.v3' "$doc_root/$relative" ||
      fail "$relative lost second-machine release admission schema v3"
  done
  grep -Fq 'round14_audit_sqlite_schema: 7 / ACTIVE_CONTRACT' "$doc_root/docs/ROUND14_STATUS.md" ||
    fail "ROUND14_STATUS.md lost Audit SQLite schema 7"
  grep -Fq 'round14_active_workflows: 4 / ci.yml / codeql.yml / policy-gate.yml / release-rc.yml' \
    "$doc_root/docs/ROUND14_STATUS.md" ||
    fail "ROUND14_STATUS.md lost the exact four-workflow inventory"
  grep -Fq 'ALLOWED_AFTER_REQUIRED_CHECKS_AND_EXPLICIT_MAINTAINER_WAIVER / RELEASE_RC_WORKFLOW_ONLY' \
    "$doc_root/docs/ROUND14_STATUS.md" ||
    fail "ROUND14_STATUS.md lost the gated RC publication contract"
  grep -Fq 'round13_rc_tag: v1.0.0-rc.1' "$doc_root/docs/ROUND13_STATUS.md" || \
    fail "ROUND13_STATUS.md lost the exact RC identity"
  grep -Fq 'round13_cpa_target: v7.2.125 / 2e6b1d83f6c304a102aa33c1faf0a4f94d0d331e' \
    "$doc_root/docs/ROUND13_STATUS.md" || \
    fail "ROUND13_STATUS.md lost the frozen CPA v7.2.125 identity"
  grep -Fq 'round13_classifier_policy: classifier-policy-v20 / 888cfe509f77b1321f4f16a70e5e2558c270cac57d3447a831737261fb1188fd' \
    "$doc_root/docs/ROUND13_STATUS.md" || \
    fail "ROUND13_STATUS.md lost the frozen Round 13 classifier identity"
  grep -Fq 'cpa_version: v7.2.125' \
    "$doc_root/docs/ROUND13_CPA_V7_2_125_V1_RC1_TASK_BOOK.md" || \
    fail "Round 13 task book lost the frozen CPA v7.2.125 identity"

  declare -A round14_audit_identities=(
    [round14_audit_runner_bundle_sha256]="$current_audit_runner_bundle_sha256"
    [round14_audit_contract_sha256]="$current_audit_contract_sha256"
    [round14_audit_run_source_sha256]="$current_audit_run_source_sha256"
    [round14_audit_machine_schema_sha256]="$current_audit_machine_schema_sha256"
    [round14_audit_tool_tests]="PASS / LINUX / ${current_audit_tool_test_count}_OF_${current_audit_tool_test_count}"
    [round14_audit_tool_skips]="$current_audit_tool_skip_count"
    [round14_audit_test_sources_sha256]="$current_audit_test_sources_sha256"
    [round14_audit_test_ids_sha256]="$current_audit_test_ids_sha256"
    [round14_audit_unit_receipt_sha256]="$current_audit_tool_receipt_sha256"
    [round14_audit_unit_started_at]="$current_audit_tool_started_at"
    [round14_audit_unit_finished_at]="$current_audit_tool_finished_at"
    [round14_audit_unit_elapsed_ms]="$current_audit_tool_elapsed_ms"
    [round14_audit_unit_command]="$current_audit_tool_command"
  )
  for relative in \
    docs/ROUND14_STATUS.md \
    docs/reports/TEST_REPORT.md \
    docs/reports/CPA_INTEGRATION.md; do
    for key in "${!round14_audit_identities[@]}"; do
      value="${round14_audit_identities[$key]}"
      [[ "$(grep -Fxc -- "$key: $value" "$doc_root/$relative")" == 1 &&
        "$(grep -Ec "^${key}:" "$doc_root/$relative")" == 1 ]] ||
        fail "$relative must bind the exact current Round 14 audit identity: $key"
    done
  done
  declare -A active_audit_identities=(
    [round14_audit_runner_bundle_sha256]="$current_audit_runner_bundle_sha256"
    [round14_audit_contract_sha256]="$current_audit_contract_sha256"
    [round14_audit_run_source_sha256]="$current_audit_run_source_sha256"
    [round14_audit_machine_schema_sha256]="$current_audit_machine_schema_sha256"
    [round14_audit_tool_tests]="PASS / LINUX / ${current_audit_tool_test_count}_OF_${current_audit_tool_test_count}"
    [round14_audit_tool_skips]="$current_audit_tool_skip_count"
    [round14_audit_test_sources_sha256]="$current_audit_test_sources_sha256"
    [round14_audit_test_ids_sha256]="$current_audit_test_ids_sha256"
    [round14_audit_unit_receipt_sha256]="$current_audit_tool_receipt_sha256"
    [round14_audit_unit_started_at]="$current_audit_tool_started_at"
    [round14_audit_unit_finished_at]="$current_audit_tool_finished_at"
    [round14_audit_unit_elapsed_ms]="$current_audit_tool_elapsed_ms"
    [round14_audit_unit_command]="$current_audit_tool_command"
  )
  for key in "${!active_audit_identities[@]}"; do
    value="${active_audit_identities[$key]}"
    [[ "$(grep -Fxc -- "$key: $value" "$doc_root/docs/reports/RELEASE_EVIDENCE.md")" == 1 &&
      "$(grep -Ec "^${key}:" "$doc_root/docs/reports/RELEASE_EVIDENCE.md")" == 1 ]] ||
      fail "docs/reports/RELEASE_EVIDENCE.md must bind the exact current audit identity: $key"
  done

  # Round 12 remains immutable historical evidence.  Its CPA audit closure is
  # deliberately independent of the current Round 14 receipt above; requiring
  # current hashes here would silently relabel an old execution as a new PASS.
  round12_status="$doc_root/docs/ROUND12_STATUS.md"
  declare -A historical_round12_status_identities=(
    [round12_classifier_policy]="HISTORICAL_ROUND12 / classifier-policy-v12 / 2e9d02371c2ff18d6f5efe7765db45517471603ea9d772c73664bf92c7625a5b"
    [round12_audit_runner_bundle]="6c9bcece412f3164845f831856b39fc23e80b0939ae64e3adae2f41e00c017a4"
    [round12_audit_contract]="0b518e0ca12011dc9fe2064740ed799adf5faaf0da8f474512b0ba6557360680"
    [round12_audit_run_source]="cd42cff19d6f01c60f42e382b329c9682f7cb5a995b6213a3fa7094c7966fe73"
    [round12_audit_machine_schema]="063d70925671b54a0726778df4f8224471c1705d8ac39a9ee8bb44340d824060"
    [round12_local_audit_tool_tests]="CPA_V7.2.124_PASS / LINUX / 148_OF_148"
  )
  for key in "${!historical_round12_status_identities[@]}"; do
    value="${historical_round12_status_identities[$key]}"
    [[ "$(grep -Fxc -- "$key: $value" "$round12_status")" == 1 &&
      "$(grep -Ec "^[[:space:]]*${key}[[:space:]]*:" "$round12_status")" == 1 ]] ||
      fail "docs/ROUND12_STATUS.md must preserve the exact frozen Round 12 identity: $key"
  done

  round12_test_report_section="$(awk '
    $0 == "## Frozen Round 12 working-tree pre-final Linux validation" { inside = 1; next }
    inside && /^## / { exit }
    inside { print }
  ' "$doc_root/docs/reports/TEST_REPORT.md")"
  [[ -n "$round12_test_report_section" ]] ||
    fail "docs/reports/TEST_REPORT.md lost the frozen Round 12 validation section"
  declare -A historical_round12_report_identities=(
    [runner_bundle_sha256]="6c9bcece412f3164845f831856b39fc23e80b0939ae64e3adae2f41e00c017a4"
    [audit_contract_sha256]="0b518e0ca12011dc9fe2064740ed799adf5faaf0da8f474512b0ba6557360680"
    [run_source_sha256]="cd42cff19d6f01c60f42e382b329c9682f7cb5a995b6213a3fa7094c7966fe73"
    [machine_schema_sha256]="063d70925671b54a0726778df4f8224471c1705d8ac39a9ee8bb44340d824060"
  )
  for key in "${!historical_round12_report_identities[@]}"; do
    value="${historical_round12_report_identities[$key]}"
    [[ "$(grep -Fxc -- "$key: $value" <<<"$round12_test_report_section")" == 1 &&
      "$(grep -Ec "^[[:space:]]*${key}[[:space:]]*:" <<<"$round12_test_report_section")" == 1 ]] ||
      fail "docs/reports/TEST_REPORT.md must preserve the exact frozen Round 12 identity: $key"
  done
  [[ "$(grep -Fc -- '| Frozen Round 12 CPA audit tool | **PASS**, Linux 148/148.' \
    <<<"$round12_test_report_section")" == 1 ]] ||
    fail "docs/reports/TEST_REPORT.md must preserve the frozen Round 12 audit test count"

  round14_identity_documents=(
    CHANGELOG.md
    docs/README.md
    docs/ROUND14_STATUS.md
    docs/reports/CPA_INTEGRATION.md
    docs/reports/PHASE0_CPA_CONTRACT.md
    tools/current-cpa-audit/README.md
  )
  for relative in "${round14_identity_documents[@]}"; do
    document="$doc_root/$relative"
    grep -Fq "$round14_cpa_module_sum" "$document" || \
      fail "$relative lost the exact CPA $round14_cpa_version module sum"
    grep -Fq "$round14_cpa_go_mod_sum" "$document" || \
      fail "$relative lost the exact CPA $round14_cpa_version go.mod sum"
    grep -Fq "$round14_cpa_archive_sha256" "$document" || \
      fail "$relative lost the exact CPA $round14_cpa_version archive SHA-256"
    grep -Fq "$round14_cpa_binary_sha256" "$document" || \
      fail "$relative lost the exact CPA $round14_cpa_version binary SHA-256"
  done

  round14_overlay_documents=(
    docs/DESIGN.md
    docs/INSTALL_DOCKER.md
    docs/ROUND6_DEVELOPMENT_HANDOFF.md
    docs/ROUND6_LIMITATIONS.md
    docs/ROUND6_RELEASE_GATE.md
    docs/THREAT_MODEL.md
    docs/reports/PROMPT_INJECTION_REVIEW.md
    docs/reports/ROUND8_RELEASE_READINESS.md
  )
  for relative in "${round14_overlay_documents[@]}"; do
    document="$doc_root/$relative"
    grep -Fq "$round14_cpa_version@$round14_cpa_commit" "$document" || \
      fail "$relative lost its active-tree CPA $round14_cpa_version overlay"
    grep -Fq 'current_classifier_policy_version: classifier-policy-v20' "$document" || \
      fail "$relative lost its active-tree classifier overlay"
  done

  grep -Fq "exact $round14_cpa_version / CAG \`1.0.0\` lane must revalidate it" \
    "$doc_root/docs/RAW_CAPTURE.md" || \
    fail "docs/RAW_CAPTURE.md lost the active $round14_cpa_version transport guidance"
  grep -Fq '## Frozen historical Round 12 evidence boundary' \
    "$doc_root/docs/LIMITATIONS.md" || \
    fail "docs/LIMITATIONS.md must explicitly freeze the retained Round 12 body"
  grep -Fq 'cyber-abuse-guard-v1.0.0.so' \
    "$doc_root/tools/current-cpa-audit/README.md" || \
    fail "current CPA audit README lost the closed CAG 1.0.0 SO name"
  grep -Fq '"source_version": {"const": "1.0.0"}' \
    "$root/tools/current-cpa-audit/machine-evidence.schema.json" || \
    fail "machine evidence schema lost the closed CAG 1.0.0 identity"
  grep -Fq '"version": {"const": "1.0.0"}' \
    "$root/tools/current-cpa-audit/host-performance-evidence.schema.json" || \
    fail "Host performance evidence schema lost the closed CAG 1.0.0 candidate version"

  round14_active_cpa_documents=(
    README.md
    README_CN.md
    CHANGELOG.md
    SECURITY.md
    docs/AUDIT_HANDOFF.md
    docs/DESIGN.md
    docs/INSTALL_DOCKER.md
    docs/LIMITATIONS.md
    docs/RAW_CAPTURE.md
    docs/README.md
    docs/ROUND6_DEVELOPMENT_HANDOFF.md
    docs/ROUND6_LIMITATIONS.md
    docs/ROUND6_RELEASE_GATE.md
    docs/ROUND14_STATUS.md
    docs/THREAT_MODEL.md
    docs/reports/CPA_INTEGRATION.md
    docs/reports/PHASE0_CPA_CONTRACT.md
    docs/reports/PROMPT_INJECTION_REVIEW.md
    docs/reports/RELEASE_EVIDENCE.md
    docs/reports/ROUND8_RELEASE_READINESS.md
    docs/reports/TEST_REPORT.md
    integration/cpalatestcontract/README.md
    tools/current-cpa-audit/README.md
  )
  if ! "$python3_bin" -B - "$doc_root" "${round14_active_cpa_documents[@]}" <<'PY'
import re
import sys
from pathlib import Path


root = Path(sys.argv[1])
relatives = sys.argv[2:]
stale = re.compile(r"v7\.2\.(?:124|125)", re.IGNORECASE)
active = re.compile(r"\b(?:active|current)\b|(?:活动|当前)", re.IGNORECASE)
historical = re.compile(
    r"\b(?:frozen|historical|retained|non-transferable|superseded)\b|(?:冻结|历史|保留|不可转移)",
    re.IGNORECASE,
)
freeze_markers = {
    "README.md": "The Round 12 block retained below is historical v7.2.124 evidence.",
    "README_CN.md": "下方第十二轮状态仅保留为 CPA v7.2.124 历史证据",
    "CHANGELOG.md": "## Historical unreleased - v0.16 main development",
    "docs/AUDIT_HANDOFF.md": "下文为冻结的第十二轮历史交接记录",
    "docs/DESIGN.md": "## Frozen historical Round 12 design body",
    "docs/INSTALL_DOCKER.md": "## Frozen historical Round 12 installation body",
    "docs/LIMITATIONS.md": "## Frozen historical Round 12 evidence boundary",
    "docs/THREAT_MODEL.md": "## Frozen historical Round 12 threat-model body",
    "docs/reports/CPA_INTEGRATION.md": "Everything below this overlay is the frozen Round 12 / CPA v7.2.124 report",
    "docs/reports/RELEASE_EVIDENCE.md": "Everything below is frozen v0.16 / Round 12",
    "docs/reports/TEST_REPORT.md": "All v7.2.124 and earlier results below are historical",
}
problems = []
for relative in relatives:
    text = (root / relative).read_text(encoding="utf-8")
    lines = text.splitlines()
    marker = freeze_markers.get(relative)
    frozen_after = len(lines) + 1
    if marker:
        for index, line in enumerate(lines, 1):
            if marker in line:
                frozen_after = index
                break

    if relative == "docs/README.md":
        for index, line in enumerate(lines, 1):
            if stale.search(line) and re.search(
                r"\[Active\s+v7\.2\.(?:124|125)|active\s+v7\.2\.(?:124|125)\s+boundary",
                line,
                re.IGNORECASE,
            ):
                problems.append(f"{relative}:{index}: stale active CPA navigation")

    if relative in {
        "docs/ROUND6_DEVELOPMENT_HANDOFF.md",
        "docs/ROUND6_LIMITATIONS.md",
        "docs/ROUND6_RELEASE_GATE.md",
        "docs/reports/PROMPT_INJECTION_REVIEW.md",
        "docs/reports/ROUND8_RELEASE_READINESS.md",
    }:
        for index, line in enumerate(lines, 1):
            if stale.search(line) and re.search(
                r"current_(?:formal_)?cpa|current\s+(?:formal\s+)?CPA\s+identity",
                line,
                re.IGNORECASE,
            ):
                problems.append(f"{relative}:{index}: stale active-tree CPA overlay")

    paragraph = []
    paragraph_start = 1
    for index in range(1, len(lines) + 2):
        line = lines[index - 1] if index <= len(lines) else ""
        if line.strip():
            if not paragraph:
                paragraph_start = index
            paragraph.append(line)
            continue
        if not paragraph:
            continue
        value = "\n".join(paragraph)
        if (
            paragraph_start < frozen_after
            and stale.search(value)
            and active.search(value)
            and not historical.search(value)
        ):
            problems.append(
                f"{relative}:{paragraph_start}: unfrozen current/active historical CPA claim"
            )
        paragraph = []

if problems:
    print("\n".join(problems), file=sys.stderr)
    raise SystemExit(1)
PY
  then
    fail "Round 14 active document allowlist contains an unfrozen current/active v7.2.125/v7.2.124 claim"
  fi

  for relative in \
    CHANGELOG.md \
    docs/ROUND14_STATUS.md \
    docs/reports/CPA_INTEGRATION.md \
    docs/reports/RELEASE_EVIDENCE.md \
    docs/reports/TEST_REPORT.md; do
    active_document="$doc_root/$relative"
    case "$relative" in
      CHANGELOG.md)
        active_section="$(awk '
          $0 == "## Unreleased - v1.0.0-rc.3" { inside = 1; next }
          inside && $0 == "### Frozen Round 13 v7.2.125 development history" { exit }
          inside && /^## / { exit }
          inside { print }
        ' "$active_document")"
        ;;
      docs/reports/CPA_INTEGRATION.md)
        active_section="${active_document:+$(awk '
          /^## Round 14 active compatibility overlay$/ { inside = 1; next }
          inside && /^## Frozen Round 13 / { exit }
          inside { print }
        ' "$active_document")}"
        ;;
      docs/reports/RELEASE_EVIDENCE.md)
        active_section="$(awk '
          /^## Round 14 active release boundary$/ { inside = 1; next }
          inside && /^## Frozen Round 13 / { exit }
          inside { print }
        ' "$active_document")"
        ;;
      docs/reports/TEST_REPORT.md)
        active_section="$(awk '
          /^## Round 14 current test boundary$/ { inside = 1; next }
          inside && /^## Frozen Round 13 / { exit }
          inside { print }
        ' "$active_document")"
        ;;
      *)
        active_section="$(sed -n '/<!-- round14-status:start -->/,/<!-- round14-status:end -->/p' "$active_document")"
        ;;
    esac
    [[ -n "$active_section" ]] || fail "$relative lost its active Round 14 section"
    if grep -Eq '(^|[^0-9])248/248([^0-9]|$)|248_OF_248|3a1dd5ac6076b0e576feb0e25163efdf02f4e4f6d0759b36d5294db74a13db8e|e3fb417870fcedf6cc7231bff68e960043760a1185a8af5e34bfbb0055c3e251|81d0f7c514a74a3a013c453b13f81b9bd20f1b3ccc9fb434c1aefa26fc08a628|1e41a1b614c854fab60ad1a3be853c0bb99e38636e7a628b7a8a20814164fa6d' \
      <<<"$active_section"; then
      fail "$relative retains a stale active Round 14 248-test or runner identity claim"
    fi
  done

  if ! "$python3_bin" -B - "$doc_root" <<'PY'
import re
import sys
from pathlib import Path


root = Path(sys.argv[1])


def split_once(relative, marker):
    text = (root / relative).read_text(encoding="utf-8")
    if text.count(marker) != 1:
        raise SystemExit(f"{relative}: expected exactly one active/frozen boundary marker")
    return text.split(marker, 1)


for relative, marker in (
    (
        "docs/reports/CPA_INTEGRATION.md",
        "Everything below this overlay, including every Round 13 v7.2.125 PASS and",
    ),
    (
        "docs/reports/TEST_REPORT.md",
        "All Round 13 v7.2.125 results and all Round 12 or earlier results below are",
    ),
):
    active, _ = split_once(relative, marker)
    if len(re.findall(r"(?<![0-9])315/315 PASS(?![0-9])", active)) != 1:
        raise SystemExit(f"{relative}: active Round 14 overlay must contain exactly one 315/315 PASS result")


relative = "docs/reports/RELEASE_EVIDENCE.md"
marker = "## Frozen Round 13 release boundary"
active, frozen = split_once(relative, marker)
expected_target = (
    "round14_cpa_target: v7.2.142 / "
    "1f53b2eb03b9e963bac647e5566ca2b304239116"
)
active_target = re.compile(r"(?m)^[ \t]*" + re.escape(expected_target) + r"[ \t]*$")
if len(active_target.findall(active)) != 1:
    raise SystemExit(
        f"{relative}: active boundary must contain exactly one exact v7.2.142 round14_cpa_target"
    )
if len(re.findall(r"(?m)^[ \t]*round14_cpa_target[ \t]*:", active)) != 1:
    raise SystemExit(f"{relative}: active boundary contains a duplicate or conflicting round14_cpa_target")

round13_target = re.compile(
    r"(?m)^[ \t]*historical_round13_cpa_target:[ \t]*"
    r"v7\.2\.125 / 2e6b1d83f6c304a102aa33c1faf0a4f94d0d331e[ \t]*$"
)
if len(round13_target.findall(frozen)) != 1:
    raise SystemExit(
        f"{relative}: frozen history must contain exactly one historical_round13_cpa_target"
    )

historical_target = re.compile(
    r"(?m)^[ \t]*historical_round12_cpa_target:[ \t]*"
    r"v7\.2\.124 / 197f520426374e514218ed155933ac546c98d345[ \t]*$"
)
if len(historical_target.findall(frozen)) != 1:
    raise SystemExit(
        f"{relative}: frozen history must contain exactly one historical_round12_cpa_target"
    )

required_store_markers = (
    "historical_round13_cpa_store_rc_asset: cyber-abuse-guard_1.0.0-rc.1_linux_amd64.zip / "
    "ROOT_CYBER_ABUSE_GUARD.SO / PAYLOAD_BYTE_EQUAL",
    "historical_round13_cpa_store_checksum_contract: checksums.txt / "
    "EXACT_STANDALONE_AND_TWO_STORE_ZIPS",
    "payload is byte-for-byte equal to the audited standalone SO",
    "derived-container relationship explicitly",
)
for required in required_store_markers:
    if frozen.count(required) != 1:
        raise SystemExit(
            f"{relative}: frozen Round 13 boundary must retain exactly one RC Store marker: {required}"
        )
PY
  then
    fail "Round 14 active and frozen historical release-report contract is inconsistent"
  fi

  # The Round 13 release report is historical data. Reject active-looking
  # `active_cpa_*` keys anywhere below its frozen boundary so a stale claim
  # cannot be smuggled into either the Round 13 or older history.
  if ! active_cpa_diagnostic="$("$python3_bin" -B - "$doc_root/docs/reports/RELEASE_EVIDENCE.md" 2>&1 <<'PY'
import re
import sys
from pathlib import Path

text = Path(sys.argv[1]).read_text(encoding="utf-8")
marker = "## Frozen Round 13 release boundary"
if text.count(marker) != 1:
    raise SystemExit("RELEASE_EVIDENCE.md must contain exactly one Round 13 frozen boundary")
active, frozen = text.split(marker, 1)
history_marker = "Everything below is frozen v0.16 / Round 12 history"
if frozen.count(history_marker) != 1:
    raise SystemExit("RELEASE_EVIDENCE.md must contain exactly one Round 12 history boundary")
round13, round12_and_earlier = frozen.split(history_marker, 1)
keys = sorted(set(re.findall(r"(?m)^active_cpa_[A-Za-z0-9_]+:", frozen)))
if keys:
    raise SystemExit(
        "docs/reports/RELEASE_EVIDENCE.md: frozen release history contains active_cpa_* keys: "
        + ", ".join(key[:-1] for key in keys)
    )
historical_target = re.compile(
    r"(?m)^[ \t]*historical_round12_cpa_target:[ \t]*"
    r"v7\.2\.124 / 197f520426374e514218ed155933ac546c98d345[ \t]*$"
)
if len(historical_target.findall(round12_and_earlier)) != 1:
    raise SystemExit(
        "docs/reports/RELEASE_EVIDENCE.md: frozen block must contain exactly one historical_round12_cpa_target"
    )
required_store_markers = (
    "historical_round13_cpa_store_rc_asset: cyber-abuse-guard_1.0.0-rc.1_linux_amd64.zip / "
    "ROOT_CYBER_ABUSE_GUARD.SO / PAYLOAD_BYTE_EQUAL",
    "historical_round13_cpa_store_checksum_contract: checksums.txt / "
    "EXACT_STANDALONE_AND_TWO_STORE_ZIPS",
    "payload is byte-for-byte equal to the audited standalone SO",
    "derived-container relationship explicitly",
)
for required in required_store_markers:
    if round13.count(required) != 1:
        raise SystemExit(
            f"docs/reports/RELEASE_EVIDENCE.md: frozen Round 13 boundary must retain exactly one RC Store marker: {required}"
        )
PY
)"; then
    fail "$active_cpa_diagnostic"
  fi

  grep -Fqx 'VERSION ?= 1.0.0' "$root/Makefile" || fail "Makefile source version differs from 1.0.0"
  grep -Fq 'Version        = "1.0.0"' "$root/internal/buildinfo/buildinfo.go" || \
    fail "buildinfo source version differs from 1.0.0"
  for modfile in \
    "$root/go.mod" \
    "$root/integration/cpalatestcontract/go.mod" \
    "$root/integration/pluginstorecontract/go.mod"; do
    grep -Fq "github.com/router-for-me/CLIProxyAPI/v7 $round14_cpa_version" "$modfile" || \
      fail "active CPA module is not pinned to $round14_cpa_version: $modfile"
  done
  for sumfile in \
    "$root/go.sum" \
    "$root/integration/cpalatestcontract/go.sum" \
    "$root/integration/pluginstorecontract/go.sum"; do
    grep -Fqx "github.com/router-for-me/CLIProxyAPI/v7 $round14_cpa_version $round14_cpa_module_sum" "$sumfile" || \
      fail "active CPA module sum is not exact: $sumfile"
    grep -Fqx "github.com/router-for-me/CLIProxyAPI/v7 $round14_cpa_version/go.mod $round14_cpa_go_mod_sum" "$sumfile" || \
      fail "active CPA go.mod sum is not exact: $sumfile"
  done

  verify_round14_repository_contracts
  printf 'release document consistency passed: source=%s rc=v%s-rc.3 cpa=%s audit_tests=%s\n' \
    "$current_release_version" "$current_release_version" "$round14_cpa_version" \
    "$current_audit_tool_test_count"
  exit 0
fi

# The remaining body is the explicit v0.16 fixture-only compatibility gate.
# The real source tree and Round 13 fixtures are fully checked above.
[[ "$fixture_mode" == 1 ]] ||
  fail "legacy release-document contracts may run only in fixture mode"

documents=(
  README.md
  README_CN.md
  CHANGELOG.md
  SECURITY.md
  docs/AUDIT_HANDOFF.md
  docs/DESIGN.md
  docs/LIMITATIONS.md
  docs/INSTALL_DOCKER.md
  docs/README.md
  docs/REPOSITORY_GOVERNANCE.md
  docs/RELEASE_POLICY.md
  docs/ROUND6_CONFIG_MIGRATION.md
  docs/ROUND6_DEVELOPMENT_HANDOFF.md
  docs/ROUND6_LIMITATIONS.md
  docs/ROUND6_RELEASE_GATE.md
  docs/ROUND6_STREAMING_SCANNER_DESIGN.md
  docs/ROUND8_HOST_RUNNER.md
  docs/ROUND9_AUDIT_SCHEMA_V6.md
  docs/ROUND9_INDEPENDENT_AUDIT_CONTRACT.md
  docs/ROUND9_HOST_RUNNER.md
  docs/ROUND9_OPERATOR_ROLLOUT.md
  docs/ROUND11_RUNTIME_ASSURANCE_TASK_BOOK.md
  docs/ROUND12_PRODUCTION_HARDENING_TASK_BOOK.md
  docs/ROUND12_STATUS.md
  docs/RULES.md
  docs/THREAT_MODEL.md
  docs/reports/CPA_INTEGRATION.md
  docs/reports/PERFORMANCE.md
  docs/reports/PHASE0_CPA_CONTRACT.md
  docs/reports/PRIVACY.md
  docs/reports/PUBLIC_JAILBREAK_REPOSITORY_REVIEW.md
  docs/reports/PROMPT_INJECTION_REVIEW.md
  docs/reports/RELEASE_EVIDENCE.md
  docs/reports/ROUND8_CALIBRATION.md
  docs/reports/ROUND8_RELEASE_READINESS.md
  docs/reports/ROUND9_EXECUTION_RECORD.md
  docs/reports/TEST_REPORT.md
)

for relative in "${documents[@]}"; do
  document="$doc_root/$relative"
  verify_canonical_relative_path "$relative"
  [[ -f "$document" && ! -L "$document" ]] || fail "required current release document must be a regular non-symlink file: $relative"
done

active_workflows=(
  .github/workflows/ci.yml
  .github/workflows/codeql.yml
  .github/workflows/policy-gate.yml
  .github/workflows/release-rc.yml
)
declare -A active_workflow_allowlist=()
for relative in "${active_workflows[@]}"; do
  [[ -z "${active_workflow_allowlist[$relative]+x}" ]] ||
    fail "active workflow allowlist contains a duplicate: $relative"
  active_workflow_allowlist["$relative"]=1
done

declare -A retired_workflow_document_titles=(
  [docs/ROUND9_HOST_RUNNER.md]='# Historical Round 9 Linux Host runner and counted-Mock design'
  [docs/ROUND9_INDEPENDENT_AUDIT_CONTRACT.md]='# Historical Round 9 exact-candidate independent-audit design'
)
for relative in "${!retired_workflow_document_titles[@]}"; do
  document="$doc_root/$relative"
  [[ "$(sed -n '1p' "$document")" == "${retired_workflow_document_titles[$relative]}" ]] ||
    fail "$relative must remain explicitly titled as a historical non-executable design"
  grep -Fq '**HISTORICAL / NON-EXECUTABLE DESIGN.**' "$document" ||
    fail "$relative must retain the historical non-executable warning"
  grep -Fq 'were deleted from the executable' "$document" ||
    fail "$relative must state that its retired workflows were deleted"
done

grep -Fq '## Historical, non-executable Round 9 workflow designs' "$doc_root/docs/README.md" ||
  fail "documentation index must separate retired Round 9 workflow designs from current entry points"
historical_index_section="$(awk '
  $0 == "## Historical, non-executable Round 9 workflow designs" { inside = 1; next }
  inside && /^## / { exit }
  inside { print }
' "$doc_root/docs/README.md")"
grep -Fq '[Historical, non-executable Round 9 Host runner design](ROUND9_HOST_RUNNER.md)' \
  <<<"$historical_index_section" ||
  fail "historical workflow section must contain the retired Round 9 Host runner link"
grep -Fq '[Historical, non-executable Round 9 independent-audit design](ROUND9_INDEPENDENT_AUDIT_CONTRACT.md)' \
  <<<"$historical_index_section" ||
  fail "historical workflow section must contain the retired Round 9 independent-audit link"
for retired_link_target in \
  ROUND9_HOST_RUNNER.md \
  ROUND9_INDEPENDENT_AUDIT_CONTRACT.md; do
  retired_link_count="$(
    { LC_ALL=C grep -Fo -- "]($retired_link_target)" \
        "$doc_root/docs/README.md" || true; } |
      wc -l |
      tr -d '[:space:]'
  )"
  [[ "$retired_link_count" == 1 ]] ||
    fail "retired workflow link must appear exactly once and only in the historical workflow section: $retired_link_target"
done

round9_host_guide="$doc_root/docs/ROUND9_HOST_RUNNER.md"
[[ "$(grep -Fxc '## Current retained runner maintenance contract' "$round9_host_guide")" == 1 ]] ||
  fail "docs/ROUND9_HOST_RUNNER.md must contain exactly one current retained runner maintenance contract"
current_runner_maintenance_contract="$(awk '
  $0 == "## Current retained runner maintenance contract" { inside = 1; next }
  inside && /^## / { exit }
  inside { print }
' "$round9_host_guide")"
required_current_runner_network_markers=(
  'Runner version 2 no longer publishes Mock or'
  'CPA ports to the Host.'
  'inspected RFC1918 bridge addresses'
  '`Internal=true`, IPv6/attachable/ingress disabled, one RFC1918 IPAM subnet,'
  'exact execution labels and container identities, distinct private addresses,'
  'and no configured or runtime Host port binding.'
)
for marker in "${required_current_runner_network_markers[@]}"; do
  grep -Fq "$marker" <<<"$current_runner_maintenance_contract" ||
    fail "current retained runner maintenance contract lost the Docker 29 internal-only boundary: $marker"
done
[[ "$(grep -Fxc 'host_ip=internal-only, host_port=0, container_port=8317' \
  <<<"$current_runner_maintenance_contract")" == 1 ]] ||
  fail "current retained runner maintenance contract must contain exactly one internal-only evidence tuple"
if grep -Fq '127.0.0.1:18394 -> 8317/tcp' <<<"$current_runner_maintenance_contract"; then
  fail "current retained runner maintenance contract must not reuse the historical Host listener"
fi

[[ "$(grep -Fxc '## Historical CPA sandbox and listener' "$round9_host_guide")" == 1 ]] ||
  fail "docs/ROUND9_HOST_RUNNER.md must contain exactly one historical CPA listener snapshot"
historical_runner_listener_snapshot="$(awk '
  $0 == "## Historical CPA sandbox and listener" { inside = 1; next }
  inside && /^## / { exit }
  inside { print }
' "$round9_host_guide")"
[[ "$(grep -Fxc '127.0.0.1:18394 -> 8317/tcp' \
  <<<"$historical_runner_listener_snapshot")" == 1 ]] ||
  fail "historical CPA listener snapshot must retain exactly one 127.0.0.1:18394 -> 8317/tcp record"

active_network_tuple='host_ip=internal-only, host_port=0, container_port=8317'
for relative in README.md README_CN.md docs/THREAT_MODEL.md; do
  document="$doc_root/$relative"
  tuple_count="$(
    { LC_ALL=C grep -Fo -- "$active_network_tuple" "$document" || true; } |
      wc -l |
      tr -d '[:space:]'
  )"
  [[ "$tuple_count" == 1 ]] ||
    fail "$relative must contain exactly one active internal-only evidence tuple"
  if grep -Fq '127.0.0.1:18394 -> 8317/tcp' "$document"; then
    fail "$relative must not present the historical Host listener as an active contract"
  fi
done

grep -Fq 'publishes no CPA or counted-Mock ports to the Host' "$doc_root/README.md" &&
  grep -Fq 'exact two Docker-inspect-verified, distinct RFC1918 bridge IPv4 addresses' "$doc_root/README.md" &&
  grep -Fq 'any Host binding, additional container, or non-internal network is inadmissible' "$doc_root/README.md" ||
  fail "README.md lost the active Docker 29 internal-only Host boundary"
grep -Fq '不向 Host 发布 CPA 或 counted-Mock 端口' "$doc_root/README_CN.md" &&
  grep -Fq '经 Docker inspect 验证、彼此不同的两个 RFC1918 bridge IPv4' "$doc_root/README_CN.md" &&
  grep -Fq '任何 Host binding、额外容器或非内部网络均不准入' "$doc_root/README_CN.md" ||
  fail "README_CN.md lost the active Docker 29 internal-only Host boundary"
grep -Fq 'publishes neither CPA nor counted-Mock ports to the' "$doc_root/docs/THREAT_MODEL.md" &&
  grep -Fq 'exact two Docker-inspect-verified, distinct RFC1918 bridge IPv4' "$doc_root/docs/THREAT_MODEL.md" &&
  grep -Fq 'Any Host binding, additional container, or non-internal network is' "$doc_root/docs/THREAT_MODEL.md" ||
  fail "docs/THREAT_MODEL.md lost the active Docker 29 internal-only Host boundary"

workflow_directory="$doc_root/.github/workflows"
verify_canonical_relative_path .github/workflows
[[ -d "$workflow_directory" && ! -L "$workflow_directory" ]] ||
  fail "active workflow directory must be a regular non-symlink directory: .github/workflows"
for relative in "${active_workflows[@]}"; do
  workflow="$doc_root/$relative"
  verify_canonical_relative_path "$relative"
  [[ -f "$workflow" && ! -L "$workflow" ]] ||
    fail "required active workflow must be a regular non-symlink file: $relative"
done
for workflow in "$workflow_directory"/*.yml "$workflow_directory"/*.yaml; do
  [[ -e "$workflow" || -L "$workflow" ]] || continue
  relative=".github/workflows/${workflow##*/}"
  [[ -n "${active_workflow_allowlist[$relative]+x}" ]] ||
    fail "workflow directory contains an unreviewed active workflow: $relative"
done
workflow_index="$workflow_directory/README.md"
verify_canonical_relative_path .github/workflows/README.md
[[ -f "$workflow_index" && ! -L "$workflow_index" ]] ||
  fail "workflow index must be a regular non-symlink file: .github/workflows/README.md"
for relative in "${active_workflows[@]}"; do
  workflow_name="${relative##*/}"
  grep -Fq "| \`$workflow_name\` |" "$workflow_index" ||
    fail "workflow index lost the active workflow: $relative"
done

if [[ "$doc_root" == "$root" ]]; then
  grep -Fq '`docs/ROUND9_HOST_RUNNER.md`' \
    "$root/integration/round9countedmock/README.md" ||
    fail "Round 9 counted-Mock README lost its Host contract link"
  grep -Fq '[Round 9 audit schema v6](ROUND9_AUDIT_SCHEMA_V6.md)' \
    "$root/docs/README.md" ||
    fail "documentation index lost the Round 9 audit-schema link"
  grep -Fq '[Round 11 runtime-assurance task book](ROUND11_RUNTIME_ASSURANCE_TASK_BOOK.md)' \
    "$root/docs/README.md" ||
    fail "documentation index lost the Round 11 task-book link"
  grep -Fq '[Round 9 operator-owned rollout and rollback](ROUND9_OPERATOR_ROLLOUT.md)' \
    "$root/docs/README.md" ||
    fail "documentation index lost the Round 9 operator-runbook link"
  grep -Fq '[Round 9 execution record and traceability matrix](reports/ROUND9_EXECUTION_RECORD.md)' \
    "$root/docs/README.md" ||
    fail "documentation index lost the Round 9 execution-record link"
  grep -Fq 'HTTP `503` and the fixed `audit_unavailable` error' \
    "$root/docs/ROUND9_AUDIT_SCHEMA_V6.md" ||
    fail "Round 9 audit guide lost the enabled-but-unavailable management contract"
fi

# Historical RELEASE_POLICY remains required above but intentionally does not
# use the fixed current-document prologue. ROUND8_CALIBRATION now does use it.
classifier_identity_documents=(
  README.md
  README_CN.md
  CHANGELOG.md
  SECURITY.md
  docs/AUDIT_HANDOFF.md
  docs/DESIGN.md
  docs/INSTALL_DOCKER.md
  docs/LIMITATIONS.md
  docs/README.md
  docs/ROUND6_CONFIG_MIGRATION.md
  docs/ROUND6_DEVELOPMENT_HANDOFF.md
  docs/ROUND6_LIMITATIONS.md
  docs/ROUND6_RELEASE_GATE.md
  docs/ROUND6_STREAMING_SCANNER_DESIGN.md
  docs/ROUND8_HOST_RUNNER.md
  docs/ROUND9_AUDIT_SCHEMA_V6.md
  docs/ROUND9_HOST_RUNNER.md
  docs/ROUND9_OPERATOR_ROLLOUT.md
  docs/ROUND11_RUNTIME_ASSURANCE_TASK_BOOK.md
  docs/ROUND12_PRODUCTION_HARDENING_TASK_BOOK.md
  docs/ROUND12_STATUS.md
  docs/RULES.md
  docs/THREAT_MODEL.md
  docs/reports/CPA_INTEGRATION.md
  docs/reports/PERFORMANCE.md
  docs/reports/PHASE0_CPA_CONTRACT.md
  docs/reports/PRIVACY.md
  docs/reports/PUBLIC_JAILBREAK_REPOSITORY_REVIEW.md
  docs/reports/PROMPT_INJECTION_REVIEW.md
  docs/reports/RELEASE_EVIDENCE.md
  docs/reports/ROUND8_RELEASE_READINESS.md
  docs/reports/ROUND9_EXECUTION_RECORD.md
  docs/reports/TEST_REPORT.md
)
canonical_classifier_version_key="current_classifier_policy_version"
canonical_classifier_sha256_key="current_classifier_policy_sha256"
normalized_policy_keys() {
  LC_ALL=C tr -d "\"'\`" <"$1"
}
count_policy_key() {
  local document="$1" key="$2"
  normalized_policy_keys "$document" |
    { grep -Eo "(^|[^[:alnum:]_])${key}[[:space:]]*:" || true; } |
    wc -l | tr -d '[:space:]'
}
count_policy_key_in_text() {
  local text="$1" key="$2"
  printf '%s\n' "$text" |
    LC_ALL=C tr -d "\"'\`" |
    { grep -Eo "(^|[^[:alnum:]_])${key}[[:space:]]*:" || true; } |
    wc -l | tr -d '[:space:]'
}
count_fixed_in_text() {
  local text="$1" value="$2"
  printf '%s\n' "$text" |
    { grep -Fo -- "$value" || true; } |
    wc -l | tr -d '[:space:]'
}
count_exact_key_value_in_text() {
  local text="$1" key="$2" value="$3"
  printf '%s\n' "$text" |
    { grep -Ec "^[[:space:]]*${key}[[:space:]]*:[[:space:]]*${value}[[:space:]]*$" || true; }
}
for relative in "${classifier_identity_documents[@]}"; do
  document="$doc_root/$relative"
  canonical_version_line="${canonical_classifier_version_key}: ${current_classifier_policy_version}"
  canonical_sha256_line="${canonical_classifier_sha256_key}: ${current_classifier_policy_sha256}"

  first_line="$(sed -n '1p' "$document")"
  first_title="${first_line#\# }"
  [[ "$first_line" == '# '* && -n "$first_title" && "$first_title" != \#* &&
    "$first_line" != *'<'* && "$first_line" != *'>'* ]] || \
    fail "$relative must start with one visible top-level Markdown heading"

  # Historical sections may retain explicitly historical identities, but every
  # current release document starts with one visible, fixed canonical prologue.
  # A stale/hidden declaration plus an appended current value fails closed.
  [[ "$(sed -n '2p' "$document")" == "" &&
    "$(sed -n '3p' "$document")" == '```text' &&
    "$(sed -n '4p' "$document")" == "$canonical_version_line" &&
    "$(sed -n '5p' "$document")" == "$canonical_sha256_line" &&
    "$(sed -n '6p' "$document")" == '```' ]] || \
    fail "$relative must place the exact visible classifier policy prologue on lines 2-6"

  [[ "$(count_policy_key "$document" "$canonical_classifier_version_key")" == 1 ]] || \
    fail "$relative must contain exactly one canonical classifier policy version key: $canonical_classifier_version_key"
  [[ "$(count_policy_key "$document" "$canonical_classifier_sha256_key")" == 1 ]] || \
    fail "$relative must contain exactly one canonical classifier policy SHA-256 key: $canonical_classifier_sha256_key"
  if normalized_policy_keys "$document" |
    grep -Eq '(^|[^[:alnum:]_])classifier_policy(_version|_sha256)?[[:space:]]*:'; then
    fail "$relative must not contain unlabeled legacy classifier policy keys; use current_ or historical_ prefixes"
  fi
done

# Current Round 14 receipt identities are validated above only against the
# active Round 14 overlays.  Frozen Round 12 and legacy v0.16 sections are
# historical evidence with their own immutable identities; never rewrite or
# reinterpret them using the current audit-tool closure.

if ! "$python3_bin" -B - \
  "$doc_root" \
  "$current_classifier_policy_version" \
  "$current_classifier_policy_sha256" \
  "${classifier_identity_documents[@]}" <<'PY'
import re
import sys
from pathlib import Path


root = Path(sys.argv[1])
current_version = sys.argv[2]
current_sha256 = sys.argv[3]
documents = sys.argv[4:]
active_key = re.compile(
    r"(?<![A-Za-z0-9_])"
    r"(?P<key>(?:round8|current_release|working_tree)_classifier_policy_(?:version|sha256))"
    r"\s*:\s*(?P<value>[A-Za-z0-9._-]+)"
)
active_prose = re.compile(
    r"(?<![A-Za-z0-9_-])(?:active\s+(?:development\s+)?target|"
    r"(?:current\s+)?working-tree(?:\s+development)?\s+(?:identity|classifier))\b"
    r".{0,240}?\b(?P<version>classifier-policy-v[0-9]+)\b",
    re.IGNORECASE | re.DOTALL,
)
policy_version = re.compile(r"\bclassifier-policy-v[0-9]+\b", re.IGNORECASE)
sha256 = re.compile(r"(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])")
historical_same_version_claim = re.compile(
    r"(?:\b(?:historical|previous|prior|former|superseded|last\s+CPA)\b|"
    r"历史|上一份|先前|旧版)",
    re.IGNORECASE,
)
policy_digest_value = (
    r"(?<![0-9A-Fa-f])"
    r"(?:[0-9A-Fa-f]{64}|[0-9A-Fa-f]{4,63}(?:\.\.\.|…)[0-9A-Fa-f]{0,63})"
    r"(?![0-9A-Fa-f])"
)
digest_before_identity_claim = re.compile(
    r"(?<![A-Za-z0-9_-])(?:current|active|working-tree)\b"
    r"(?:(?!\n\n|[.!?](?=\s|$)|\bruleset\b).){0,200}?"
    rf"(?P<digest>{policy_digest_value})"
    r"(?:(?!\n\n|[.!?](?=\s|$)|\bruleset\b).){0,80}?"
    r"\b(?:(?:classifier\s+)?policy|classifier)\s+identity\b",
    re.IGNORECASE | re.DOTALL,
)
identity_before_digest_claim = re.compile(
    r"(?<![A-Za-z0-9_-])(?:"
    r"(?:current\s+)?working-tree(?:\s+development)?\s+(?:identity|classifier)|"
    r"(?:current|active)\s+(?:(?:classifier\s+)?policy\s+|classifier\s+)?identity"
    r")\b\s*(?:is|:|=)\s*",
    re.IGNORECASE,
)


def following_lines(text: str, start: int, count: int = 3) -> str:
    end = start
    for _ in range(count):
        newline = text.find("\n", end)
        if newline == -1:
            return text[start:]
        end = newline + 1
    return text[start:end]


def reject_stale_claim(relative: str, digest: str) -> None:
    print(
        f"{relative} contains abbreviated or stale current classifier policy "
        f"SHA-256 {digest}",
        file=sys.stderr,
    )
    raise SystemExit(1)

for relative in documents:
    text = (root / relative).read_text(encoding="utf-8")
    normalized = text.translate(str.maketrans("", "", "\"'`"))
    for match in active_key.finditer(normalized):
        expected = current_sha256 if match.group("key").endswith("_sha256") else current_version
        if match.group("value") != expected:
            print(
                f"{relative} contains stale active classifier identity "
                f"{match.group('key')}: {match.group('value')}",
                file=sys.stderr,
            )
            raise SystemExit(1)
    for match in active_prose.finditer(normalized):
        if match.group("version").lower() != current_version.lower():
            print(
                f"{relative} contains stale current or working-tree classifier prose "
                f"{match.group('version')}",
                file=sys.stderr,
            )
            raise SystemExit(1)
    for match in digest_before_identity_claim.finditer(normalized):
        versions = policy_version.findall(match.group(0))
        if versions and versions[0].lower() != current_version.lower():
            print(
                f"{relative} contains stale current or working-tree classifier prose "
                f"{versions[0]}",
                file=sys.stderr,
            )
            raise SystemExit(1)
        if match.group("digest") != current_sha256:
            reject_stale_claim(relative, match.group("digest"))
    for match in identity_before_digest_claim.finditer(normalized):
        claim = following_lines(normalized, match.end())
        versions = policy_version.findall(claim)
        if versions and versions[0].lower() != current_version.lower():
            print(
                f"{relative} contains stale current or working-tree classifier prose "
                f"{versions[0]}",
                file=sys.stderr,
            )
            raise SystemExit(1)
        digests = re.findall(policy_digest_value, claim)
        if not digests:
            print(
                f"{relative} presents a current or working-tree classifier identity "
                "without a full SHA-256",
                file=sys.stderr,
            )
            raise SystemExit(1)
        if digests[0] != current_sha256:
            reject_stale_claim(relative, digests[0])
    lines = text.splitlines()
    for line_number, line in enumerate(lines, start=1):
        if current_version not in line:
            continue
        claim_context = "\n".join(
            lines[max(0, line_number - 2) : min(len(lines), line_number + 2)]
        )
        if historical_same_version_claim.search(claim_context):
            continue
        hashes = sha256.findall(line)
        if not hashes:
            hashes = sha256.findall("\n".join(lines[line_number : line_number + 2]))
            hashes = hashes[:1]
        # The first digest paired with the policy version is its identity.
        # Later digests on the same Markdown table row may be corpus or log
        # evidence and must not be mistaken for a stale classifier identity.
        if hashes and hashes[0] != current_sha256:
            print(
                f"{relative}:{line_number} places {current_version} next to a stale SHA-256",
                file=sys.stderr,
            )
            raise SystemExit(1)
PY
then
  fail "current release documents must not contain stale active classifier identities"
fi

historical_corpus="$doc_root/docs/reports/CORPUS_REPORT.md"
verify_canonical_relative_path docs/reports/CORPUS_REPORT.md
[[ -f "$historical_corpus" ]] || \
  fail "required historical corpus report is missing: docs/reports/CORPUS_REPORT.md"
grep -Eq '^# Historical .*v0\.1\.2 candidate[[:space:]]*$' "$historical_corpus" || \
  fail "docs/reports/CORPUS_REPORT.md must be explicitly labeled as historical v0.1.2 evidence"

policy="$doc_root/docs/RELEASE_POLICY.md"
grep -Fqx 'current_go_toolchain: go1.26.6' "$policy" || \
  fail "docs/RELEASE_POLICY.md must bind the current Round 14 Go 1.26.6 toolchain"
required_active_workflow_policy_markers=(
  'contains only `ci.yml`, `codeql.yml`, and `policy-gate.yml`; none can create'
  'point-in-time audit record, not an executable or current publication plan.'
  'historical snapshot; they do not describe the active workflow inventory.'
)
for marker in "${required_active_workflow_policy_markers[@]}"; do
  grep -Fq "$marker" "$policy" ||
    fail "docs/RELEASE_POLICY.md is missing the active workflow inventory boundary: $marker"
done
# RELEASE_POLICY.md is an explicitly historical snapshot. Its current_* keys,
# including the old loopback listener below, are intentionally asserted
# verbatim and must not be rewritten as the active maintenance contract.
required_policy_lines=(
  "current_round: 9"
  "current_source_version: $current_release_version"
  "current_formal_tag_reserved: v$current_release_version"
  "current_version_alias_policy: reject-v$current_release_version.0"
  "current_candidate_tag: v$current_release_version-rc.4"
  "current_candidate_status: PENDING_FINAL_SOURCE_FREEZE_HOST_AND_INDEPENDENT_EVIDENCE_NOT_PROVIDED"
  "current_platform: linux-amd64"
  "current_go_contract: 1.26.4"
  "current_cpa_version: v7.2.113"
  "current_cpa_commit: bc71c77f5cc42f3fbe1bf040cf14d4f166894835"
  "historical_round8_host_matrix: v7.2.95"
  "historical_round8_host_matrix_commit: f71ec0eb6776854457892452cf28c47f0d658251"
  "current_host_environment: round9-host-validation"
  "current_host_runner_label: cag-round9-sandbox"
  "current_publication_environment: round9-rc-publication"
  "current_rc_manifest_schema: 6"
  "current_rc_build_metadata_schema: 4"
  "current_audit_schema: 6"
  "current_raw_capture_schema: 4"
  "current_development_evidence_schema: round9-development-evidence/v1"
  "current_external_evaluation_schema: round9-external-evaluation/v3"
  "current_external_evaluator_aggregate_schema: round9-external-evaluator-aggregate/v3"
  "current_external_ledger_event_schema: round9-external-evaluation-ledger-event/v3"
  "current_external_ledger_proof_schema: round9-protected-git-ledger-proof/v1"
  "current_independent_audit_evidence_schema: round9-independent-audit-evidence/v1"
  "current_independent_audit_ledger_event_schema: round9-independent-audit-ledger-event/v1"
  "current_independent_audit_ledger_proof_schema: round9-independent-audit-ledger-proof/v1"
  "current_counted_mock_schema: round9-external-counted-mock/v1"
  "current_public_counted_mock_schema: round9-public-counted-mock/v1"
  "current_public_counted_mock_transport_schema: round9-public-counted-mock-transport/v1"
  "current_public_decision_audit_schema: round9-public-cpa-decision-audit/v1"
  "current_external_decision_audit_schema: round9-external-decision-audit/v3"
  "current_cpa_audit_expectations_schema: round9-cpa-audit-expectations/v3"
  "current_cpa_sandbox_finalize_schema: round9-cpa-sandbox-finalize/v2"
  "current_cpa_sandbox_descriptor_schema: round9-external-cpa-sandbox/v2"
  "current_external_evaluator_identity: cag-round9-external-evaluator-v3"
  "current_cpa_host_listener: 127.0.0.1:18394->8317/tcp"
  "current_external_evaluation_asset: round9-external-evaluation.json"
  "current_external_ledger_proof_asset: round9-external-ledger-proof.json"
  "current_candidate_asset_count: 17"
  "current_private_candidate_artifact: actions-only-17-assets"
  "current_private_candidate_capability: build-attest-upload-actions-only"
  "current_legacy_verifier_asset_count: 19"
  "current_legacy_verifier_reachability: disabled-if-false"
  "current_new_public_prerelease_creation: BLOCKED_FAIL_CLOSED"
  "current_exact_candidate_independent_audit_evidence_status: NOT_PROVIDED"
  "current_exact_candidate_independent_audit_mechanical_gate: IMPLEMENTED_FAIL_CLOSED_EVIDENCE_NOT_PROVIDED"
  "current_host_evaluation_publication_sufficiency: false"
  "current_release_title_publication_sufficiency: false"
  "current_publication_write_permission: absent"
  "current_public_adversarial_corpus: round9-public-adversarial-v13"
  "current_public_adversarial_manifest_schema: round9-public-adversarial-corpus/v13"
  "current_public_adversarial_machine_report_schema: round9-public-adversarial-report/v13"
  "current_public_adversarial_counts: payloads-24_formal-unique-23_historical-8_branch-head-1_prompt-like-14_unmerged-carriers-1_nondefault-branches-5_release-assets-16_release-assets-with-prompt-entries-4_release-asset-metadata-records-199_executed-1_not-provided-0_scenario-payloads-24_serialized-routes-120_direct-blocked-12_direct-allowed-12"
  "current_public_adversarial_manifest_bytes: 481448"
  "current_public_adversarial_manifest_sha256: 91a32766c17924c31365f641b2f8fed791d034524f3d3897119f721eb56fecd6"
  "current_public_counted_mock_matrix: unique-10_routes-120_audit-allow-40_enforcement-block-80_upstream-40_usage-40"
  "current_development_paired_recall_requirement: aggregate-and-each-category-exactly-10000-basis-points"
  "current_independent_malicious_recall_requirement: aggregate-and-each-category-at-least-9500-basis-points"
  "current_release_kind: private-candidate-only-public-prerelease-blocked"
  "current_release_latest: false"
  "current_legacy_verifier_identity_contract: release-object,tag=v$current_release_version-rc.4,annotated-tag-target=exact-commit,target-commitish=exact-commit,title=exact,body=exact,prerelease=true,latest=false,draft=false,immutable=true"
  "current_legacy_verifier_asset_contract: exact-count=19,download-count=19,byte-compare-each=rebuilt-candidate,attestation-check=17-release-workflow-plus-2-host-workflow"
  "current_release_recovery: fail-only-existing-release-rejected-no-automatic-verifier"
  "current_release_new_dispatch_or_rerun_all: admission-existing-release-fail-only-otherwise-private-candidate-only"
  "current_release_draft_recovery: fail-only-manual-review-no-automatic-mutation"
  "current_release_recovery_access_policy: no-recovery-path-no-state-mutation"
  "current_release_forbidden_public_release_mutations: release-create,release-edit,release-upload,release-delete"
  "current_release_permitted_private_candidate_writes: actions-artifact-upload,build-provenance-attestation"
  "current_release_forbidden_cache_mutation: cache-write"
  "current_release_latest_stable: v0.15"
  "current_release_mismatch_policy: fail-only-no-automatic-repair"
  "current_independent_audit_status: NOT_PROVIDED"
  "current_production_approval_status: NOT_GRANTED"
  "historical_round8_rc_artifact_version: 0.16-rc.2"
  "historical_round8_rc_manifest_schema: 4"
  "historical_round8_rc_publish_host_evidence: round8-host-evidence.json"
  "historical_round8_rc_publish_host_evidence_sidecar: round8-host-evidence.json.sha256"
  "historical_round8_immutable_published_rc_identity_verification: release-object,tag=v$current_release_version-rc.2,annotated-tag-target=exact-commit,target-commitish=exact-commit,title=exact,body=exact,prerelease=true,latest=false,draft=false,immutable=true"
  "historical_round8_evaluation_v10_policy: immutable-consumed-fail-not-formal-input"
  "historical_round8_formal_bundle_content_policy: exclude-evaluation-holdout-consumed-private-blind-retired"
)
for line in "${required_policy_lines[@]}"; do
  key="${line%%:*}"
  [[ "$(grep -Ec "^${key}:" "$policy")" == 1 ]] || \
    fail "docs/RELEASE_POLICY.md must contain exactly one policy key: $key"
  [[ "$(grep -Fxc "$line" "$policy")" == 1 ]] || \
    fail "docs/RELEASE_POLICY.md must contain exactly one policy line: $line"
done

required_public_v13_policy_markers=(
  "The current public adversarial corpus is development-only v13 evidence under"
  "The original v8 manifest remains frozen"
  "The rejected attempt to rebind corrected bytes to the same v8 identity"
  "The disabled legacy verifier documents the prospective signer split"
  'Admission rejects any existing `v0.16-rc.4`'
  'either creates a fresh private 17-asset candidate after all admission checks or'
  'The Host result is necessary evaluation evidence, but it is not sufficient'
  'Release title/body text such as `independent audit required` is also not evidence'
  'Before any public writer may be restored, an independent authority must provide'
  'The verifier does not create, sign, repair, or infer any of those external records.'
)
for marker in "${required_public_v13_policy_markers[@]}"; do
  grep -Fq "$marker" "$policy" || \
    fail "docs/RELEASE_POLICY.md is missing the active public-v13/release-attestation contract: $marker"
done
if grep -Eq \
  'The current public adversarial corpus is development-only v[0-9] evidence' \
  "$policy"; then
  fail "docs/RELEASE_POLICY.md retains a stale active public corpus version"
fi

legacy_round9_host_policy_keys=(
  current_host_evidence_schema
  current_host_evidence_schema_version
  current_counted_mock_probe_schema_version
  current_evaluation_contract_schema
  current_host_evidence
  current_host_evidence_sidecar
)
for key in "${legacy_round9_host_policy_keys[@]}"; do
  [[ "$(grep -Ec "^${key}:" "$policy")" == 0 ]] ||
    fail "docs/RELEASE_POLICY.md contains a retired active Round 9 Host-evidence key: $key"
done

legacy_round8_active_policy_keys=(
  release_version
  formal_tag
  version_alias_policy
  platform
  local_rc_artifact_version
  local_rc_artifact_scope
  local_rc_evidence_policy
  rc_workflow
  rc_artifact_version
  rc_artifact_history
  rc_status
  rc_manifest_schema
  rc_candidate_asset_count
  rc_publish_asset_count
  rc_publish_host_evidence
  rc_publish_host_evidence_sidecar
  immutable_published_rc_identity_verification
  immutable_published_rc_asset_verification
  immutable_published_rc_recovery
  immutable_published_rc_new_dispatch_or_rerun_all
  immutable_published_rc_recovery_access_policy
  immutable_published_rc_forbidden_mutations
  immutable_published_rc_latest_release
  immutable_published_rc_mismatch_policy
  host_matrix
  host_matrix_commit
  independent_audit_status
  production_approval_status
  stable_v0.16_status
)
for key in "${legacy_round8_active_policy_keys[@]}"; do
  [[ "$(grep -Ec "^${key}:" "$policy")" == 0 ]] ||
    fail "docs/RELEASE_POLICY.md contains an unlabeled legacy Round 8 active key: $key"
done

for relative in README.md README_CN.md CHANGELOG.md docs/ROUND6_RELEASE_GATE.md; do
  document="$doc_root/$relative"
  [[ -f "$document" ]] || fail "required release-facing document is missing: $relative"
  grep -Fq 'round6-prerelease-attestation.json' "$document" || \
    fail "$relative must point readers to the Host/audit attestation"
  grep -Fq 'formal-release-attestation.json' "$document" || \
    fail "$relative must point readers to the formal gate attestation"
done

changelog="$doc_root/CHANGELOG.md"
em_dash=$'\xe2\x80\x94'
if ! grep -Eq \
  "^##[[:space:]]+v?${current_release_version//./\\.}[[:space:]]+(-|$em_dash)[[:space:]]+[0-9]{4}-[0-9]{2}-[0-9]{2}[[:space:]]*$" \
  "$changelog"; then
  fail "CHANGELOG.md must date the $current_release_version heading as YYYY-MM-DD"
fi

current_reports=(
  docs/reports/RELEASE_EVIDENCE.md
  docs/reports/TEST_REPORT.md
)
for relative in "${current_reports[@]}"; do
  report="$doc_root/$relative"
  mapfile -t declared_hashes < <(sed -nE \
    's/^[[:space:]]*ruleset_sha256:[[:space:]]*`?([0-9a-f]{64})`?[[:space:]]*$/\1/p' \
    "$report")
  ((${#declared_hashes[@]} >= 1)) || \
    fail "$relative must declare a concrete ruleset_sha256"
  latest_declared_hash="${declared_hashes[${#declared_hashes[@]}-1]}"
  [[ "$latest_declared_hash" == "$current_ruleset_sha256" ]] || \
    fail "$relative latest ruleset_sha256 $latest_declared_hash does not match current $current_ruleset_sha256"
done

round8_readiness="$doc_root/docs/reports/ROUND8_RELEASE_READINESS.md"
if ! "$python3_bin" -B - "$round8_readiness" <<'PY'
import json
import re
import sys
from pathlib import Path


def reject_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


text = Path(sys.argv[1]).read_text(encoding="utf-8")
blocks = re.findall(r"(?ms)^```json[ \t]*\n(.*?)^```[ \t]*$", text)
evidence_blocks = []
for raw in blocks:
    try:
        value = json.loads(raw, object_pairs_hook=reject_duplicates)
    except (json.JSONDecodeError, ValueError):
        continue
    if isinstance(value, dict) and value.get("validation_scope") == "CPA_HOST_COUNTED_MOCK_ONLY":
        evidence_blocks.append(value)

if len(evidence_blocks) != 1:
    raise SystemExit(1)

cpa = evidence_blocks[0].get("cpa")
if not isinstance(cpa, dict):
    raise SystemExit(1)
for lane in ("primary",):
    entry = cpa.get(lane)
    if not isinstance(entry, dict):
        raise SystemExit(1)
    host_results = entry.get("host_results")
    if not isinstance(host_results, dict):
        raise SystemExit(1)
    database = host_results.get("database")
    if not isinstance(database, dict):
        raise SystemExit(1)
    schema_version = database.get("schema_version")
    migration_versions = database.get("migration_versions")
    if type(schema_version) is not int or schema_version != 5:
        raise SystemExit(1)
    if (
        not isinstance(migration_versions, list)
        or len(migration_versions) != 5
        or any(type(value) is not int for value in migration_versions)
        or migration_versions != [1, 2, 3, 4, 5]
    ):
        raise SystemExit(1)
PY
then
  fail "docs/reports/ROUND8_RELEASE_READINESS.md must show the exact database schema and migration history in each named CPA lane"
fi
if grep -Fq '"database": {"quick_check": "ok", "wal_checkpoint_passed": true}' \
  "$round8_readiness"; then
  fail "docs/reports/ROUND8_RELEASE_READINESS.md contains the obsolete incomplete database evidence example"
fi

printf 'release document consistency passed: version %s, ruleset %s, classifier %s/%s\n' \
  "$current_release_version" "$current_ruleset_sha256" \
  "$current_classifier_policy_version" "$current_classifier_policy_sha256"
