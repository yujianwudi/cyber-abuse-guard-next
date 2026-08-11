#!/usr/bin/env bash
set -euo pipefail

root="$(cd "${BASH_SOURCE[0]%/*}/.." && pwd -P)"
gate="$root/scripts/release-doc-consistency.sh"
ruleset_sha256="a9bbfb2ed76d55cca02f83390e3fe10532dc7cb3fb389c440b0b130a0b2d1642"
old_ruleset_sha256="5354e9b56c5986ac09b2b231b2750f4a519b8e3a6bfcbd71da7747dd32481cf6"
classifier_policy_version="classifier-policy-v5"
classifier_policy_sha256="0e114d98862282d2492fb62e4300297b4746eeaf8165339603d02c48d11bd60b"
old_classifier_policy_version="classifier-policy-v4"
old_classifier_policy_sha256="2763f10e2565dce2ffcf700f5d6566e9fbac68f3fedd08fcce20bceff450b4c8"
stale_round9_policy_version="classifier-policy-v8"
stale_round9_policy_sha256="b3f1e751bf648d426023e4207b8b562fe3aac91d48fa74c1462c79e08fa49dde"
stale_abbreviated_policy_sha256="dc869ac9...e045"
round13_classifier_policy_version="classifier-policy-v19"
round13_classifier_policy_sha256="b9ee45401a50ae5c6fafa80d219e8f47e726bdfe15b5fc7838a96edd095460a1"
work="$(mktemp -d)"
trap 'rm -rf -- "$work"' EXIT
python3_bin=""
if ! python3_bin="$(command -v python3)" || [[ ! -x "$python3_bin" ]]; then
  printf 'python3 is required for release document consistency fixtures\n' >&2
  exit 127
fi

audit_tool_root="$root/tools/current-cpa-audit"
audit_identity_output=""
if ! audit_identity_output="$(python3 -B - "$audit_tool_root" <<'PY'
import sys
import unittest
from pathlib import Path


tool = Path(sys.argv[1]).resolve(strict=True)
sys.path.insert(0, str(tool))
sys.path.insert(0, str(tool / "tests"))
import run


identities = run.runner_identities()
loader = unittest.TestLoader()
suite = loader.discover(str(tool / "tests"), pattern="test_*.py")
if loader.errors:
    for error in loader.errors:
        print(error, file=sys.stderr)
    raise SystemExit("CPA audit unittest discovery reported loader errors")
for key in (
    "bundle_sha256",
    "audit_contract_sha256",
    "run_source_sha256",
    "machine_schema_sha256",
):
    print(identities[key])
print(suite.countTestCases())
PY
)"; then
  printf 'cannot determine current CPA audit runner fixture identities\n' >&2
  exit 1
fi
audit_identity_values=()
mapfile -t audit_identity_values <<<"$audit_identity_output"
[[ "${#audit_identity_values[@]}" == 5 ]] || {
  printf 'cannot determine current CPA audit runner fixture identities\n' >&2
  exit 1
}
audit_runner_bundle_sha256="${audit_identity_values[0]}"
audit_contract_sha256="${audit_identity_values[1]}"
audit_run_source_sha256="${audit_identity_values[2]}"
audit_machine_schema_sha256="${audit_identity_values[3]}"
audit_tool_test_count="${audit_identity_values[4]}"

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
  docs/reports/CORPUS_REPORT.md
)

round13_documents=(
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
  integration/cpalatestcontract/README.md
  tools/current-cpa-audit/README.md
)

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

make_fixture() {
  local fixture="$1" relative
  mkdir -p "$fixture/docs/reports" "$fixture/.github/workflows"
  for relative in ci.yml codeql.yml policy-gate.yml; do
    printf 'name: fixture\n' >"$fixture/.github/workflows/$relative"
  done
  printf '%s\n' \
    '# GitHub Actions' \
    '' \
    '| File |' \
    '|---|' \
    '| `ci.yml` |' \
    '| `codeql.yml` |' \
    '| `policy-gate.yml` |' \
    >"$fixture/.github/workflows/README.md"
  for relative in "${documents[@]}"; do
    mkdir -p "$(dirname "$fixture/$relative")"
    if [[ "$relative" == docs/RELEASE_POLICY.md ]]; then
      # This fixture is an explicitly historical snapshot. Preserve its
      # current_* field names and old loopback listener verbatim.
      printf '%s\n' \
        '# Release policy' \
        '' \
        'current_round: 9' \
        'current_source_version: 0.16' \
        'current_formal_tag_reserved: v0.16' \
        'current_version_alias_policy: reject-v0.16.0' \
        'current_candidate_tag: v0.16-rc.4' \
        'current_candidate_status: PENDING_FINAL_SOURCE_FREEZE_HOST_AND_INDEPENDENT_EVIDENCE_NOT_PROVIDED' \
        'current_platform: linux-amd64' \
        'current_go_contract: 1.26.4' \
        'current_cpa_version: v7.2.113' \
        'current_cpa_commit: bc71c77f5cc42f3fbe1bf040cf14d4f166894835' \
        'current_gate_workflow: .github/workflows/round9-gate.yml' \
        'current_host_workflow: .github/workflows/round9-host-validation.yml' \
        'current_rc_workflow: .github/workflows/round9-release-rc.yml' \
        'current_host_environment: round9-host-validation' \
        'current_host_runner_label: cag-round9-sandbox' \
        'current_publication_environment: round9-rc-publication' \
        'current_rc_manifest_schema: 6' \
        'current_rc_build_metadata_schema: 4' \
        'current_audit_schema: 6' \
        'current_raw_capture_schema: 4' \
        'current_development_evidence_schema: round9-development-evidence/v1' \
        'current_external_evaluation_schema: round9-external-evaluation/v3' \
        'current_external_evaluator_aggregate_schema: round9-external-evaluator-aggregate/v3' \
        'current_external_ledger_event_schema: round9-external-evaluation-ledger-event/v3' \
        'current_external_ledger_proof_schema: round9-protected-git-ledger-proof/v1' \
        'current_independent_audit_evidence_schema: round9-independent-audit-evidence/v1' \
        'current_independent_audit_ledger_event_schema: round9-independent-audit-ledger-event/v1' \
        'current_independent_audit_ledger_proof_schema: round9-independent-audit-ledger-proof/v1' \
        'current_counted_mock_schema: round9-external-counted-mock/v1' \
        'current_public_counted_mock_schema: round9-public-counted-mock/v1' \
        'current_public_counted_mock_transport_schema: round9-public-counted-mock-transport/v1' \
        'current_public_decision_audit_schema: round9-public-cpa-decision-audit/v1' \
        'current_external_decision_audit_schema: round9-external-decision-audit/v3' \
        'current_cpa_audit_expectations_schema: round9-cpa-audit-expectations/v3' \
        'current_cpa_sandbox_finalize_schema: round9-cpa-sandbox-finalize/v2' \
        'current_cpa_sandbox_descriptor_schema: round9-external-cpa-sandbox/v2' \
        'current_external_evaluator_identity: cag-round9-external-evaluator-v3' \
        'current_cpa_host_listener: 127.0.0.1:18394->8317/tcp' \
        'current_external_evaluation_asset: round9-external-evaluation.json' \
        'current_external_ledger_proof_asset: round9-external-ledger-proof.json' \
        'current_candidate_asset_count: 17' \
        'current_private_candidate_artifact: actions-only-17-assets' \
        'current_private_candidate_capability: build-attest-upload-actions-only' \
        'current_legacy_verifier_asset_count: 19' \
        'current_legacy_verifier_reachability: disabled-if-false' \
        'current_new_public_prerelease_creation: BLOCKED_FAIL_CLOSED' \
        'current_exact_candidate_independent_audit_evidence_status: NOT_PROVIDED' \
        'current_exact_candidate_independent_audit_mechanical_gate: IMPLEMENTED_FAIL_CLOSED_EVIDENCE_NOT_PROVIDED' \
        'current_host_evaluation_publication_sufficiency: false' \
        'current_release_title_publication_sufficiency: false' \
        'current_publication_write_permission: absent' \
        'current_round9_gate_admission: workflow=Round 9 policy gate,path=.github/workflows/round9-gate.yml,event=push,branch=main,exact-commit,completed-success' \
        'current_historical_workflow_disable_requirement: 315644586:release-rc.yml=disabled_manually,318443961:round8-host-validation.yml=disabled_manually' \
        'current_public_adversarial_corpus: round9-public-adversarial-v13' \
        'current_public_adversarial_manifest_schema: round9-public-adversarial-corpus/v13' \
        'current_public_adversarial_machine_report_schema: round9-public-adversarial-report/v13' \
        'current_public_adversarial_counts: payloads-24_formal-unique-23_historical-8_branch-head-1_prompt-like-14_unmerged-carriers-1_nondefault-branches-5_release-assets-16_release-assets-with-prompt-entries-4_release-asset-metadata-records-199_executed-1_not-provided-0_scenario-payloads-24_serialized-routes-120_direct-blocked-12_direct-allowed-12' \
  'current_public_adversarial_manifest_bytes: 481448' \
  'current_public_adversarial_manifest_sha256: 91a32766c17924c31365f641b2f8fed791d034524f3d3897119f721eb56fecd6' \
  'current_public_counted_mock_matrix: unique-10_routes-120_audit-allow-40_enforcement-block-80_upstream-40_usage-40' \
        'current_development_paired_recall_requirement: aggregate-and-each-category-exactly-10000-basis-points' \
        'current_independent_malicious_recall_requirement: aggregate-and-each-category-at-least-9500-basis-points' \
        'current_release_kind: private-candidate-only-public-prerelease-blocked' \
        'current_release_latest: false' \
        'current_legacy_verifier_identity_contract: release-object,tag=v0.16-rc.4,annotated-tag-target=exact-commit,target-commitish=exact-commit,title=exact,body=exact,prerelease=true,latest=false,draft=false,immutable=true' \
        'current_legacy_verifier_asset_contract: exact-count=19,download-count=19,byte-compare-each=rebuilt-candidate,attestation-check=17-release-workflow-plus-2-host-workflow' \
        'current_release_recovery: fail-only-existing-release-rejected-no-automatic-verifier' \
        'current_release_new_dispatch_or_rerun_all: admission-existing-release-fail-only-otherwise-private-candidate-only' \
        'current_release_draft_recovery: fail-only-manual-review-no-automatic-mutation' \
        'current_release_recovery_access_policy: no-recovery-path-no-state-mutation' \
        'current_release_forbidden_public_release_mutations: release-create,release-edit,release-upload,release-delete' \
        'current_release_permitted_private_candidate_writes: actions-artifact-upload,build-provenance-attestation' \
        'current_release_forbidden_cache_mutation: cache-write' \
        'current_release_latest_stable: v0.15' \
        'current_release_mismatch_policy: fail-only-no-automatic-repair' \
        'current_independent_audit_status: NOT_PROVIDED' \
        'current_production_approval_status: NOT_GRANTED' \
        'The current public adversarial corpus is development-only v13 evidence under round9-public-adversarial-corpus/v13.' \
        'The original v8 manifest remains frozen as superseded invalid evidence.' \
        'The rejected attempt to rebind corrected bytes to the same v8 identity is retained separately.' \
        'The disabled legacy verifier documents the prospective signer split.' \
        'The two external assets remain separately attested.' \
        'Admission rejects any existing `v0.16-rc.4` Release.' \
        'A new dispatch either creates a fresh private 17-asset candidate after all admission checks or fails closed.' \
        'The Host result is necessary evaluation evidence, but it is not sufficient publication authorization.' \
        'Release title/body text such as `independent audit required` is also not evidence.' \
        'Before any public writer may be restored, an independent authority must provide the exact-candidate audit bindings.' \
        'The verifier does not create, sign, repair, or infer any of those external records.' \
        'The default branch now contains only `ci.yml`, `codeql.yml`, and `policy-gate.yml`; none can create or modify a GitHub Release.' \
        'The remainder of this document is a point-in-time audit record, not an executable or current publication plan.' \
        'Field names beginning with `current_` are preserved from that historical snapshot; they do not describe the active workflow inventory.' \
        'historical_round8_rc_artifact_version: 0.16-rc.2' \
        'historical_round8_rc_manifest_schema: 4' \
        'historical_round8_rc_publish_host_evidence: round8-host-evidence.json' \
        'historical_round8_rc_publish_host_evidence_sidecar: round8-host-evidence.json.sha256' \
        'historical_round8_host_matrix: v7.2.95' \
        'historical_round8_host_matrix_commit: f71ec0eb6776854457892452cf28c47f0d658251' \
        'historical_round8_immutable_published_rc_identity_verification: release-object,tag=v0.16-rc.2,annotated-tag-target=exact-commit,target-commitish=exact-commit,title=exact,body=exact,prerelease=true,latest=false,draft=false,immutable=true' \
        'historical_round8_evaluation_v10_policy: immutable-consumed-fail-not-formal-input' \
        'historical_round8_formal_bundle_content_policy: exclude-evaluation-holdout-consumed-private-blind-retired' \
        >"$fixture/$relative"
    elif [[ "$relative" == docs/ROUND9_HOST_RUNNER.md ]]; then
      printf '%s\n' \
        '# Historical Round 9 Linux Host runner and counted-Mock design' \
        '' \
        '> [!CAUTION]' \
        '> **HISTORICAL / NON-EXECUTABLE DESIGN.**' \
        '> The retired workflows were deleted from the executable workflow directory.' \
        '' \
        '## Current retained runner maintenance contract' \
        '' \
        'The retained source-level runner is still maintained for authorized, manual' \
        'Linux amd64 sandbox diagnostics. Runner version 2 no longer publishes Mock or' \
        'CPA ports to the Host. Docker 29 reaches both containers through their' \
        'inspected RFC1918 bridge addresses.' \
        '' \
        'host_ip=internal-only, host_port=0, container_port=8317' \
        '' \
        '`Internal=true`, IPv6/attachable/ingress disabled, one RFC1918 IPAM subnet,' \
        'exact execution labels and container identities, distinct private addresses,' \
        'and no configured or runtime Host port binding.' \
        '' \
        '## Historical CPA sandbox and listener' \
        '' \
        '127.0.0.1:18394 -> 8317/tcp' \
        >"$fixture/$relative"
    elif [[ "$relative" == docs/ROUND9_INDEPENDENT_AUDIT_CONTRACT.md ]]; then
      printf '%s\n' \
        '# Historical Round 9 exact-candidate independent-audit design' \
        '' \
        '> [!CAUTION]' \
        '> **HISTORICAL / NON-EXECUTABLE DESIGN.**' \
        '> The retired workflows were deleted from the executable workflow directory.' \
        >"$fixture/$relative"
    elif [[ "$relative" == docs/README.md ]]; then
      printf '%s\n' \
        '# Documentation index' \
        '' \
        '## Current v0.16 documents' \
        '' \
        '- Current source-only documents.' \
        '' \
        '## Historical, non-executable Round 9 workflow designs' \
        '' \
        '- [Historical, non-executable Round 9 Host runner design](ROUND9_HOST_RUNNER.md)' \
        '- [Historical, non-executable Round 9 independent-audit design](ROUND9_INDEPENDENT_AUDIT_CONTRACT.md)' \
        '' \
        '## Architecture and security model' \
        >"$fixture/$relative"
    elif [[ "$relative" == CHANGELOG.md ]]; then
      printf '%s\n' \
        '# Changelog' \
        '' \
        '## Unreleased - v0.16 main development' \
        '' \
        "current_audit_runner_bundle_sha256: $audit_runner_bundle_sha256" \
        "current_audit_contract_sha256: $audit_contract_sha256" \
        "current_audit_run_source_sha256: $audit_run_source_sha256" \
        "current_audit_machine_schema_sha256: $audit_machine_schema_sha256" \
        "current_audit_tool_test_count: $audit_tool_test_count" \
        "Linux audit-tool verification is $audit_tool_test_count/$audit_tool_test_count PASS." \
        '' \
        '## 0.16 - 2026-07-21' \
        '' \
        'round6-prerelease-attestation.json' \
        'formal-release-attestation.json' \
        >"$fixture/$relative"
    elif [[ "$relative" == docs/reports/CORPUS_REPORT.md ]]; then
      printf '# Historical project regression corpus report - v0.1.2 candidate\n' >"$fixture/$relative"
    elif [[ "$relative" == docs/reports/ROUND8_RELEASE_READINESS.md ]]; then
      printf '%s\n' \
        '# Round 8 release readiness' \
        '' \
        '```json' \
        '{' \
        '  "validation_scope": "CPA_HOST_COUNTED_MOCK_ONLY",' \
        '  "cpa": {' \
        '    "primary": {' \
        '      "host_results": {' \
        '        "database": {' \
        '          "schema_version": 5,' \
        '          "migration_versions": [1, 2, 3, 4, 5]' \
        '        }' \
        '      }' \
        '    }' \
        '  }' \
        '}' \
        '```' \
        >"$fixture/$relative"
    else
      printf '# Final release document\n\nRelease evidence is complete.\n' >"$fixture/$relative"
    fi
  done
  for relative in README.md README_CN.md docs/ROUND6_RELEASE_GATE.md; do
    printf '\nround6-prerelease-attestation.json\nformal-release-attestation.json\n' \
      >>"$fixture/$relative"
  done
  printf '%s\n' \
    'The current runner publishes no CPA or counted-Mock ports to the Host, records host_ip=internal-only, host_port=0, container_port=8317, and uses the exact two Docker-inspect-verified, distinct RFC1918 bridge IPv4 addresses; any Host binding, additional container, or non-internal network is inadmissible.' \
    >>"$fixture/README.md"
  printf '%s\n' \
    '当前 runner 不向 Host 发布 CPA 或 counted-Mock 端口，记录 host_ip=internal-only, host_port=0, container_port=8317，且只使用经 Docker inspect 验证、彼此不同的两个 RFC1918 bridge IPv4；任何 Host binding、额外容器或非内部网络均不准入。' \
    >>"$fixture/README_CN.md"
  printf '%s\n' \
    'The runner publishes neither CPA nor counted-Mock ports to the' \
    'Host and records host_ip=internal-only, host_port=0, container_port=8317.' \
    'The Host reaches only the exact two Docker-inspect-verified, distinct RFC1918 bridge IPv4 addresses.' \
    'Any Host binding, additional container, or non-internal network is outside the admitted sandbox.' \
    >>"$fixture/docs/THREAT_MODEL.md"
  for relative in "${classifier_identity_documents[@]}"; do
    staged="$fixture/.classifier-prologue"
    {
      sed -n '1p' "$fixture/$relative"
      printf '\n```text\ncurrent_classifier_policy_version: %s\ncurrent_classifier_policy_sha256: %s\n```\n' \
        "$classifier_policy_version" "$classifier_policy_sha256"
      sed -n '3,$p' "$fixture/$relative"
    } >"$staged"
    mv -f -- "$staged" "$fixture/$relative"
  done
  printf '%s\n' \
    '' \
    "round12_classifier_policy: $classifier_policy_version / $classifier_policy_sha256" \
    "round12_audit_runner_bundle: $audit_runner_bundle_sha256" \
    "round12_audit_contract: $audit_contract_sha256" \
    "round12_audit_run_source: $audit_run_source_sha256" \
    "round12_audit_machine_schema: $audit_machine_schema_sha256" \
    "round12_local_audit_tool_tests: PASS / LINUX / ${audit_tool_test_count}_OF_${audit_tool_test_count}" \
    >>"$fixture/docs/ROUND12_STATUS.md"
  printf '%s\n' \
    '' \
    '## Frozen Round 12 working-tree pre-final Linux validation' \
    '' \
    '```text' \
    "runner_bundle_sha256: $audit_runner_bundle_sha256" \
    "audit_contract_sha256: $audit_contract_sha256" \
    "run_source_sha256: $audit_run_source_sha256" \
    "machine_schema_sha256: $audit_machine_schema_sha256" \
    '```' \
    '' \
    "| Current CPA audit tool | **PASS**, Linux $audit_tool_test_count/$audit_tool_test_count. Fixture evidence. |" \
    >>"$fixture/docs/reports/TEST_REPORT.md"
  for relative in \
    docs/reports/RELEASE_EVIDENCE.md \
    docs/reports/TEST_REPORT.md; do
    printf '\nruleset_sha256: %s\n' "$ruleset_sha256" >>"$fixture/$relative"
  done
}

run_gate() {
  local fixture="$1"
  local environment=(
    "RELEASE_DOC_ROOT=$fixture"
    "RELEASE_DOC_FIXTURE_MODE=1"
    "CURRENT_RELEASE_VERSION=0.16"
    "CURRENT_RULESET_SHA256=$ruleset_sha256"
    "CURRENT_CLASSIFIER_POLICY_VERSION=$classifier_policy_version"
    "CURRENT_CLASSIFIER_POLICY_SHA256=$classifier_policy_sha256"
  )
  env "${environment[@]}" "$gate"
}

make_round13_fixture() {
  local fixture="$1" relative
  mkdir -p "$fixture/.github/workflows"
  for relative in ci.yml codeql.yml policy-gate.yml release-rc.yml; do
    cp -a -- "$root/.github/workflows/$relative" "$fixture/.github/workflows/$relative"
  done
  cp -a -- "$root/.github/workflows/README.md" "$fixture/.github/workflows/README.md"
  for relative in "${round13_documents[@]}"; do
    mkdir -p "$(dirname "$fixture/$relative")"
    cp -a -- "$root/$relative" "$fixture/$relative"
  done
}

run_round13_gate() {
  local fixture="$1"
  local environment=(
    "RELEASE_DOC_ROOT=$fixture"
    "RELEASE_DOC_FIXTURE_MODE=1"
    "CURRENT_RELEASE_VERSION=1.0.0"
    "CURRENT_RULESET_SHA256=$ruleset_sha256"
    "CURRENT_CLASSIFIER_POLICY_VERSION=$round13_classifier_policy_version"
    "CURRENT_CLASSIFIER_POLICY_SHA256=$round13_classifier_policy_sha256"
  )
  env "${environment[@]}" "$gate"
}

round13_must_fail() {
  local name="$1" fixture="$2" expected_diagnostic="$3"
  if run_round13_gate "$fixture" >"$work/$name.log" 2>&1; then
    printf 'Round 13 release document consistency fixture unexpectedly passed: %s\n' "$name" >&2
    exit 1
  fi
  if ! grep -Fq -- "$expected_diagnostic" "$work/$name.log"; then
    printf 'Round 13 release document consistency fixture emitted the wrong diagnostic: %s\n' "$name" >&2
    exit 1
  fi
  printf 'Round 13 release document consistency fixture rejected as expected: %s\n' "$name"
}

must_fail() {
  local name="$1" fixture="$2" expected_diagnostic="$3"
  if run_gate "$fixture" >"$work/$name.log" 2>&1; then
    printf 'release document consistency fixture unexpectedly passed: %s\n' "$name" >&2
    exit 1
  fi
  if ! grep -Fq -- "$expected_diagnostic" "$work/$name.log"; then
    printf 'release document consistency fixture emitted the wrong diagnostic: %s\n' "$name" >&2
    exit 1
  fi
  printf 'release document consistency fixture rejected as expected: %s\n' "$name"
}

make_fixture "$work/pass"
run_gate "$work/pass"

make_round13_fixture "$work/round13-pass"
run_round13_gate "$work/round13-pass"

cp -a "$work/round13-pass" "$work/round13-missing-release-workflow"
rm -- "$work/round13-missing-release-workflow/.github/workflows/release-rc.yml"
round13_must_fail round13-missing-release-workflow \
  "$work/round13-missing-release-workflow" \
  'required Round 13 active workflow must be a regular non-symlink file: .github/workflows/release-rc.yml'

cp -a "$work/round13-pass" "$work/round13-unreviewed-workflow"
printf 'name: unreviewed\n' >"$work/round13-unreviewed-workflow/.github/workflows/unreviewed.yml"
round13_must_fail round13-unreviewed-workflow \
  "$work/round13-unreviewed-workflow" \
  'workflow directory contains an unreviewed Round 13 active workflow: .github/workflows/unreviewed.yml'

cp -a "$work/round13-pass" "$work/round13-stale-publication-boundary"
sed -i 's/`release-rc.yml` is the sole publication entry point/Release publication is disabled/' \
  "$work/round13-stale-publication-boundary/docs/README.md"
round13_must_fail round13-stale-publication-boundary \
  "$work/round13-stale-publication-boundary" \
  'documentation index lost the sole Round 13 RC publication boundary'

for mutation in \
  'README.md:readme-current' \
  'README_CN.md:readme-cn-current' \
  'docs/RULES.md:rules-active' \
  'docs/reports/CPA_INTEGRATION.md:cpa-integration-overlay' \
  'docs/reports/PRIVACY.md:privacy-overlay' \
  'docs/reports/ROUND8_CALIBRATION.md:round8-calibration'; do
  relative="${mutation%%:*}"
  name="${mutation##*:}"
  fixture="$work/round13-classifier-$name"
  cp -a "$work/round13-pass" "$fixture"
  sed -i '0,/current_classifier_policy_version: classifier-policy-v19/s//current_classifier_policy_version: classifier-policy-v12/' \
    "$fixture/$relative"
  round13_must_fail "round13-classifier-$name" "$fixture" \
    "$relative lost the exact current classifier identity in its first 15 lines"
done

cp -a "$work/round13-pass" "$work/round13-stale-active-navigation"
sed -i \
  's/Active v7\.2\.125 CPA integration overlay/Active v7.2.124 CPA integration overlay/' \
  "$work/round13-stale-active-navigation/docs/README.md"
round13_must_fail round13-stale-active-navigation \
  "$work/round13-stale-active-navigation" \
  'Round 13 active document allowlist contains an unfrozen current/active v7.2.124 claim'

cp -a "$work/round13-pass" "$work/round13-stale-active-overlay"
printf '\n> current_formal_cpa: v7.2.124@197f520426374e514218ed155933ac546c98d345\n' \
  >>"$work/round13-stale-active-overlay/docs/ROUND6_LIMITATIONS.md"
round13_must_fail round13-stale-active-overlay \
  "$work/round13-stale-active-overlay" \
  'Round 13 active document allowlist contains an unfrozen current/active v7.2.124 claim'

for mutation in \
  'docs/DESIGN.md|## Frozen historical Round 12 design body|round13-stale-design-before-freeze' \
  'docs/INSTALL_DOCKER.md|## Frozen historical Round 12 installation body|round13-stale-install-before-freeze' \
  'docs/THREAT_MODEL.md|## Frozen historical Round 12 threat-model body|round13-stale-threat-model-before-freeze'; do
  IFS='|' read -r relative marker name <<<"$mutation"
  fixture="$work/$name"
  cp -a "$work/round13-pass" "$fixture"
  sed -i \
    "0,/^${marker}$/s//Current CPA identity: v7.2.124 with an unfrozen active claim\\n\\n&/" \
    "$fixture/$relative"
  round13_must_fail "$name" "$fixture" \
    'Round 13 active document allowlist contains an unfrozen current/active v7.2.124 claim'
done

cp -a "$work/round13-pass" "$work/round13-frozen-history"
printf '\nThe then-current target was v7.2.124 in this explicitly frozen historical section.\n' \
  >>"$work/round13-frozen-history/docs/LIMITATIONS.md"
run_round13_gate "$work/round13-frozen-history"
printf 'Round 13 release document consistency allowed explicit frozen v7.2.124 history\n'

cp -a "$work/round13-pass" "$work/round13-binary-sha"
sed -i \
  's/656cde7bfd966dbcaaa9d9260dd1de75716c0b9dead66d91ceb2d8d55f6d623a/0000000000000000000000000000000000000000000000000000000000000000/g' \
  "$work/round13-binary-sha/docs/reports/PHASE0_CPA_CONTRACT.md"
round13_must_fail round13-binary-sha "$work/round13-binary-sha" \
  'docs/reports/PHASE0_CPA_CONTRACT.md lost the exact CPA v7.2.125 binary SHA-256'

cp -a "$work/round13-pass" "$work/round13-cag-version"
sed -i 's/cyber-abuse-guard-v1\.0\.0\.so/cyber-abuse-guard-v0.16.so/g' \
  "$work/round13-cag-version/tools/current-cpa-audit/README.md"
round13_must_fail round13-cag-version "$work/round13-cag-version" \
  'current CPA audit README lost the closed CAG 1.0.0 SO name'

for mutation in \
  'docs/reports/CPA_INTEGRATION.md:round13-cpa-integration-audit-count' \
  'docs/reports/TEST_REPORT.md:round13-test-report-audit-count'; do
  relative="${mutation%%:*}"
  name="${mutation##*:}"
  fixture="$work/$name"
  cp -a "$work/round13-pass" "$fixture"
  sed -i '0,/244\/244 PASS/s//223\/223 PASS/' "$fixture/$relative"
  round13_must_fail "$name" "$fixture" \
    "$relative: active Round 13 overlay must contain exactly one 244/244 PASS result"
done

for mutation in \
  'docs/ROUND13_STATUS.md|round13_audit_runner_bundle_sha256|round13-status-audit-bundle' \
  'docs/reports/TEST_REPORT.md|round13_audit_contract_sha256|round13-test-report-audit-contract'; do
  IFS='|' read -r relative key name <<<"$mutation"
  fixture="$work/$name"
  cp -a "$work/round13-pass" "$fixture"
  sed -i "s|^${key}: .*$|${key}: $(printf '0%.0s' {1..64})|" "$fixture/$relative"
  round13_must_fail "$name" "$fixture" \
    "$relative must bind the exact current Round 13 audit identity: $key"
done

cp -a "$work/round13-pass" "$work/round13-release-evidence-audit-run-source"
sed -i \
  "s|^active_audit_run_source_sha256: .*$|active_audit_run_source_sha256: $(printf '0%.0s' {1..64})|" \
  "$work/round13-release-evidence-audit-run-source/docs/reports/RELEASE_EVIDENCE.md"
round13_must_fail round13-release-evidence-audit-run-source \
  "$work/round13-release-evidence-audit-run-source" \
  'docs/reports/RELEASE_EVIDENCE.md must bind the exact current audit identity: active_audit_run_source_sha256'

cp -a "$work/round13-pass" "$work/round13-duplicate-active-cpa-target"
sed -i '/^active_cpa_target:/a active_cpa_target: v7.2.125 / 2e6b1d83f6c304a102aa33c1faf0a4f94d0d331e' \
  "$work/round13-duplicate-active-cpa-target/docs/reports/RELEASE_EVIDENCE.md"
round13_must_fail round13-duplicate-active-cpa-target \
  "$work/round13-duplicate-active-cpa-target" \
  'docs/reports/RELEASE_EVIDENCE.md: active boundary must contain exactly one exact v7.2.125 active_cpa_target'

cp -a "$work/round13-pass" "$work/round13-conflicting-active-cpa-target"
sed -i \
  's|^active_cpa_target: v7\.2\.125 / 2e6b1d83f6c304a102aa33c1faf0a4f94d0d331e$|active_cpa_target: v7.2.125 / 197f520426374e514218ed155933ac546c98d345|' \
  "$work/round13-conflicting-active-cpa-target/docs/reports/RELEASE_EVIDENCE.md"
round13_must_fail round13-conflicting-active-cpa-target \
  "$work/round13-conflicting-active-cpa-target" \
  'docs/reports/RELEASE_EVIDENCE.md: active boundary must contain exactly one exact v7.2.125 active_cpa_target'

cp -a "$work/round13-pass" "$work/round13-active-key-in-frozen-block"
printf '\nactive_cpa_remote_latest: PASS\n' \
  >>"$work/round13-active-key-in-frozen-block/docs/reports/RELEASE_EVIDENCE.md"
round13_must_fail round13-active-key-in-frozen-block \
  "$work/round13-active-key-in-frozen-block" \
  'docs/reports/RELEASE_EVIDENCE.md: frozen Round 12 block contains active_cpa_* keys: active_cpa_remote_latest'

cp -a "$work/round13-pass" "$work/round13-missing-historical-cpa-target"
sed -i '/^historical_round12_cpa_target:/d' \
  "$work/round13-missing-historical-cpa-target/docs/reports/RELEASE_EVIDENCE.md"
round13_must_fail round13-missing-historical-cpa-target \
  "$work/round13-missing-historical-cpa-target" \
  'docs/reports/RELEASE_EVIDENCE.md: frozen block must contain exactly one historical_round12_cpa_target'

for mutation in \
  'active_cpa_store_rc_asset:round13-missing-rc-store-asset-marker' \
  'active_cpa_store_checksum_contract:round13-missing-rc-store-checksum-marker' \
  'derived-container relationship explicitly:round13-missing-derived-container-marker'; do
  marker="${mutation%%:*}"
  name="${mutation##*:}"
  fixture="$work/$name"
  cp -a "$work/round13-pass" "$fixture"
  sed -i "0,/${marker//\//\\/}/s//BROKEN_ROUND13_STORE_MARKER/" \
    "$fixture/docs/reports/RELEASE_EVIDENCE.md"
  round13_must_fail "$name" "$fixture" \
    'docs/reports/RELEASE_EVIDENCE.md: active boundary must retain exactly one RC Store marker:'
done

mkdir -p "$work/python-exit-after-output"
printf '%s\n' \
  '#!/usr/bin/env bash' \
  'set -euo pipefail' \
  "\"$python3_bin\" \"\$@\"" \
  'exit 1' \
  >"$work/python-exit-after-output/python3"
chmod 0700 "$work/python-exit-after-output/python3"
if PATH="$work/python-exit-after-output:$PATH" \
  run_gate "$work/pass" >"$work/python-exit-after-output.log" 2>&1; then
  printf 'release document consistency accepted failed CPA identity computation\n' >&2
  exit 1
fi
grep -Fq -- \
  'cannot determine the current CPA audit runner identity closure' \
  "$work/python-exit-after-output.log" || {
  printf 'release document consistency emitted the wrong Python failure diagnostic\n' >&2
  exit 1
}
printf 'release document consistency rejected failed CPA identity computation as expected\n'

mkdir -p \
  "$work/python-loader-error-bin" \
  "$work/python-loader-error-module"
printf '%s\n' \
  'class _Suite:' \
  '    def countTestCases(self):' \
  '        return 144' \
  '' \
  'class TestLoader:' \
  '    def __init__(self):' \
  '        self.errors = []' \
  '' \
  '    def discover(self, *args, **kwargs):' \
  '        self.errors.append("synthetic loader error")' \
  '        return _Suite()' \
  >"$work/python-loader-error-module/unittest.py"
printf '%s\n' \
  '#!/usr/bin/env bash' \
  'set -euo pipefail' \
  "export PYTHONPATH=\"$work/python-loader-error-module\${PYTHONPATH:+:\$PYTHONPATH}\"" \
  "exec \"$python3_bin\" \"\$@\"" \
  >"$work/python-loader-error-bin/python3"
chmod 0700 "$work/python-loader-error-bin/python3"
if PATH="$work/python-loader-error-bin:$PATH" \
  run_gate "$work/pass" >"$work/python-loader-error.log" 2>&1; then
  printf 'release document consistency accepted unittest loader errors\n' >&2
  exit 1
fi
grep -Fq -- \
  'cannot determine the current CPA audit runner identity closure' \
  "$work/python-loader-error.log" || {
  printf 'release document consistency emitted the wrong loader-error diagnostic\n' >&2
  exit 1
}
printf 'release document consistency rejected unittest loader errors as expected\n'

cp -a "$work/pass" "$work/stale-round12-task-book-classifier"
sed -i "s/$classifier_policy_sha256/$old_classifier_policy_sha256/" \
  "$work/stale-round12-task-book-classifier/docs/ROUND12_PRODUCTION_HARDENING_TASK_BOOK.md"
must_fail stale-round12-task-book-classifier \
  "$work/stale-round12-task-book-classifier" \
  'docs/ROUND12_PRODUCTION_HARDENING_TASK_BOOK.md must place the exact visible classifier policy prologue on lines 2-6'

cp -a "$work/pass" "$work/stale-round12-status-classifier"
sed -i \
  "s|^round12_classifier_policy: $classifier_policy_version / $classifier_policy_sha256$|round12_classifier_policy: $classifier_policy_version / $old_classifier_policy_sha256|" \
  "$work/stale-round12-status-classifier/docs/ROUND12_STATUS.md"
must_fail stale-round12-status-classifier \
  "$work/stale-round12-status-classifier" \
  'docs/ROUND12_STATUS.md must contain exactly one exact Round 12 classifier policy identity'

cp -a "$work/pass" "$work/duplicate-round12-status-classifier"
printf '\nround12_classifier_policy: %s / %s\n' \
  "$classifier_policy_version" "$old_classifier_policy_sha256" \
  >>"$work/duplicate-round12-status-classifier/docs/ROUND12_STATUS.md"
must_fail duplicate-round12-status-classifier \
  "$work/duplicate-round12-status-classifier" \
  'docs/ROUND12_STATUS.md must contain exactly one exact Round 12 classifier policy identity'

cp -a "$work/pass" "$work/backtick-round12-status-classifier"
printf '\n`round12_classifier_policy: %s / %s`\n' \
  "$old_classifier_policy_version" "$old_classifier_policy_sha256" \
  >>"$work/backtick-round12-status-classifier/docs/ROUND12_STATUS.md"
must_fail backtick-round12-status-classifier \
  "$work/backtick-round12-status-classifier" \
  'docs/ROUND12_STATUS.md must contain exactly one exact Round 12 classifier policy identity'

cp -a "$work/pass" "$work/json-round12-status-classifier"
printf '\n{"round12_classifier_policy": "%s / %s"}\n' \
  "$old_classifier_policy_version" "$old_classifier_policy_sha256" \
  >>"$work/json-round12-status-classifier/docs/ROUND12_STATUS.md"
must_fail json-round12-status-classifier \
  "$work/json-round12-status-classifier" \
  'docs/ROUND12_STATUS.md must contain exactly one exact Round 12 classifier policy identity'

cp -a "$work/pass" "$work/bulleted-round12-status-classifier"
printf '\n- round12_classifier_policy: %s / %s\n' \
  "$old_classifier_policy_version" "$old_classifier_policy_sha256" \
  >>"$work/bulleted-round12-status-classifier/docs/ROUND12_STATUS.md"
must_fail bulleted-round12-status-classifier \
  "$work/bulleted-round12-status-classifier" \
  'docs/ROUND12_STATUS.md must contain exactly one exact Round 12 classifier policy identity'

cp -a "$work/pass" "$work/stale-round12-audit-runner-bundle"
sed -i "s/$audit_runner_bundle_sha256/$old_classifier_policy_sha256/" \
  "$work/stale-round12-audit-runner-bundle/docs/ROUND12_STATUS.md"
must_fail stale-round12-audit-runner-bundle \
  "$work/stale-round12-audit-runner-bundle" \
  'docs/ROUND12_STATUS.md must contain exactly one exact Round 12 CPA audit identity: round12_audit_runner_bundle'

cp -a "$work/pass" "$work/stale-round12-audit-contract-report"
sed -i "s/$audit_contract_sha256/$old_classifier_policy_sha256/" \
  "$work/stale-round12-audit-contract-report/docs/reports/TEST_REPORT.md"
must_fail stale-round12-audit-contract-report \
  "$work/stale-round12-audit-contract-report" \
  'docs/reports/TEST_REPORT.md Round 12 section must bind the current CPA audit identity: audit_contract_sha256'

cp -a "$work/pass" "$work/stale-round12-audit-run-changelog"
sed -i "s/$audit_run_source_sha256/$old_classifier_policy_sha256/" \
  "$work/stale-round12-audit-run-changelog/CHANGELOG.md"
must_fail stale-round12-audit-run-changelog \
  "$work/stale-round12-audit-run-changelog" \
  'CHANGELOG.md Unreleased section must bind the current CPA audit identity:'

cp -a "$work/pass" "$work/swapped-round12-audit-changelog"
sed -i \
  "s|current_audit_contract_sha256: $audit_contract_sha256|current_audit_contract_sha256: $audit_run_source_sha256|" \
  "$work/swapped-round12-audit-changelog/CHANGELOG.md"
sed -i \
  "s|current_audit_run_source_sha256: $audit_run_source_sha256|current_audit_run_source_sha256: $audit_contract_sha256|" \
  "$work/swapped-round12-audit-changelog/CHANGELOG.md"
must_fail swapped-round12-audit-changelog \
  "$work/swapped-round12-audit-changelog" \
  'CHANGELOG.md Unreleased section must bind the current CPA audit identity:'

cp -a "$work/pass" "$work/stale-round12-audit-test-count"
sed -i \
  "s/PASS \/ LINUX \/ ${audit_tool_test_count}_OF_${audit_tool_test_count}/PASS \/ LINUX \/ 1_OF_1/" \
  "$work/stale-round12-audit-test-count/docs/ROUND12_STATUS.md"
must_fail stale-round12-audit-test-count \
  "$work/stale-round12-audit-test-count" \
  'docs/ROUND12_STATUS.md must contain exactly one exact Round 12 CPA audit identity: round12_local_audit_tool_tests'

cp -a "$work/pass" "$work/symlinked-github-parent"
mv -- "$work/symlinked-github-parent/.github" "$work/escaped-github-parent"
ln -s "$work/escaped-github-parent" "$work/symlinked-github-parent/.github"
must_fail symlinked-github-parent "$work/symlinked-github-parent" \
  'release document path component must not be a symlink: .github'

cp -a "$work/pass" "$work/symlinked-workflow-directory"
mv -- \
  "$work/symlinked-workflow-directory/.github/workflows" \
  "$work/escaped-workflow-directory"
ln -s \
  "$work/escaped-workflow-directory" \
  "$work/symlinked-workflow-directory/.github/workflows"
must_fail symlinked-workflow-directory "$work/symlinked-workflow-directory" \
  'release document path component must not be a symlink: .github/workflows'

cp -a "$work/pass" "$work/symlinked-workflow-file"
mv -- \
  "$work/symlinked-workflow-file/.github/workflows/ci.yml" \
  "$work/escaped-workflow-file.yml"
ln -s \
  "$work/escaped-workflow-file.yml" \
  "$work/symlinked-workflow-file/.github/workflows/ci.yml"
must_fail symlinked-workflow-file "$work/symlinked-workflow-file" \
  'release document path component must not be a symlink: .github/workflows/ci.yml'

for workflow in ci.yml codeql.yml policy-gate.yml; do
  fixture_name="missing-${workflow%.yml}-workflow"
  cp -a "$work/pass" "$work/$fixture_name"
  rm -- "$work/$fixture_name/.github/workflows/$workflow"
  must_fail "$fixture_name" "$work/$fixture_name" \
    "required active workflow must be a regular non-symlink file: .github/workflows/$workflow"
done

cp -a "$work/pass" "$work/unreviewed-release-workflow"
printf 'name: retired release fixture\n' \
  >"$work/unreviewed-release-workflow/.github/workflows/release.yml"
must_fail unreviewed-release-workflow "$work/unreviewed-release-workflow" \
  'workflow directory contains an unreviewed active workflow: .github/workflows/release.yml'

cp -a "$work/pass" "$work/retired-host-design-marked-current"
sed -i \
  's/# Historical Round 9 Linux Host runner and counted-Mock design/# Current Round 9 Linux Host runner and counted-Mock contract/' \
  "$work/retired-host-design-marked-current/docs/ROUND9_HOST_RUNNER.md"
must_fail retired-host-design-marked-current "$work/retired-host-design-marked-current" \
  'docs/ROUND9_HOST_RUNNER.md must remain explicitly titled as a historical non-executable design'

cp -a "$work/pass" "$work/current-runner-internal-tuple-changed"
sed -i \
  's/host_ip=internal-only, host_port=0, container_port=8317/host_ip=127.0.0.1, host_port=18394, container_port=8317/' \
  "$work/current-runner-internal-tuple-changed/docs/ROUND9_HOST_RUNNER.md"
must_fail current-runner-internal-tuple-changed "$work/current-runner-internal-tuple-changed" \
  'current retained runner maintenance contract must contain exactly one internal-only evidence tuple'

cp -a "$work/pass" "$work/current-runner-host-publication-relaxed"
sed -i 's/no longer publishes Mock or/no longer documents Mock or/' \
  "$work/current-runner-host-publication-relaxed/docs/ROUND9_HOST_RUNNER.md"
must_fail current-runner-host-publication-relaxed "$work/current-runner-host-publication-relaxed" \
  'current retained runner maintenance contract lost the Docker 29 internal-only boundary: Runner version 2 no longer publishes Mock or'

cp -a "$work/pass" "$work/historical-runner-listener-removed"
sed -i '/^127\.0\.0\.1:18394 -> 8317\/tcp$/d' \
  "$work/historical-runner-listener-removed/docs/ROUND9_HOST_RUNNER.md"
must_fail historical-runner-listener-removed "$work/historical-runner-listener-removed" \
  'historical CPA listener snapshot must retain exactly one 127.0.0.1:18394 -> 8317/tcp record'

cp -a "$work/pass" "$work/readme-host-admission-relaxed"
sed -i \
  's/any Host binding, additional container, or non-internal network is inadmissible/Host bindings are implementation-defined/' \
  "$work/readme-host-admission-relaxed/README.md"
must_fail readme-host-admission-relaxed "$work/readme-host-admission-relaxed" \
  'README.md lost the active Docker 29 internal-only Host boundary'

cp -a "$work/pass" "$work/readme-cn-host-admission-relaxed"
sed -i \
  's/任何 Host binding、额外容器或非内部网络均不准入/Host binding 由环境决定/' \
  "$work/readme-cn-host-admission-relaxed/README_CN.md"
must_fail readme-cn-host-admission-relaxed "$work/readme-cn-host-admission-relaxed" \
  'README_CN.md lost the active Docker 29 internal-only Host boundary'

cp -a "$work/pass" "$work/threat-model-host-admission-relaxed"
sed -i \
  's/Any Host binding, additional container, or non-internal network is outside the admitted sandbox/Additional containers may be admitted/' \
  "$work/threat-model-host-admission-relaxed/docs/THREAT_MODEL.md"
must_fail threat-model-host-admission-relaxed "$work/threat-model-host-admission-relaxed" \
  'docs/THREAT_MODEL.md lost the active Docker 29 internal-only Host boundary'

cp -a "$work/pass" "$work/readme-historical-listener-reactivated"
printf '%s\n' '127.0.0.1:18394 -> 8317/tcp' \
  >>"$work/readme-historical-listener-reactivated/README.md"
must_fail readme-historical-listener-reactivated "$work/readme-historical-listener-reactivated" \
  'README.md must not present the historical Host listener as an active contract'

cp -a "$work/pass" "$work/retired-independent-warning-removed"
sed -i '/HISTORICAL \/ NON-EXECUTABLE DESIGN/d' \
  "$work/retired-independent-warning-removed/docs/ROUND9_INDEPENDENT_AUDIT_CONTRACT.md"
must_fail retired-independent-warning-removed "$work/retired-independent-warning-removed" \
  'docs/ROUND9_INDEPENDENT_AUDIT_CONTRACT.md must retain the historical non-executable warning'

cp -a "$work/pass" "$work/retired-index-marked-current"
sed -i \
  's/## Historical, non-executable Round 9 workflow designs/## Current Round 9 workflow entry points/' \
  "$work/retired-index-marked-current/docs/README.md"
must_fail retired-index-marked-current "$work/retired-index-marked-current" \
  'documentation index must separate retired Round 9 workflow designs from current entry points'

cp -a "$work/pass" "$work/retired-links-misplaced-current"
sed -i \
  '/Historical, non-executable Round 9 Host runner design/d; /Historical, non-executable Round 9 independent-audit design/d' \
  "$work/retired-links-misplaced-current/docs/README.md"
sed -i \
  '/## Current v0.16 documents/a\- [Historical, non-executable Round 9 Host runner design](ROUND9_HOST_RUNNER.md)\n- [Historical, non-executable Round 9 independent-audit design](ROUND9_INDEPENDENT_AUDIT_CONTRACT.md)' \
  "$work/retired-links-misplaced-current/docs/README.md"
must_fail retired-links-misplaced-current "$work/retired-links-misplaced-current" \
  'historical workflow section must contain the retired Round 9 Host runner link'

cp -a "$work/pass" "$work/retired-links-duplicated-current"
sed -i \
  '/^## Current v0\.16 documents$/a\- [Historical, non-executable Round 9 Host runner design](ROUND9_HOST_RUNNER.md)\n- [Historical, non-executable Round 9 independent-audit design](ROUND9_INDEPENDENT_AUDIT_CONTRACT.md)' \
  "$work/retired-links-duplicated-current/docs/README.md"
must_fail retired-links-duplicated-current "$work/retired-links-duplicated-current" \
  'retired workflow link must appear exactly once and only in the historical workflow section: ROUND9_HOST_RUNNER.md'

cp -a "$work/pass" "$work/retired-workflow-history-omitted"
sed -i -E \
  '/^current_(gate|host|rc)_workflow:/d; /^current_round9_gate_admission:/d; /^current_historical_workflow_disable_requirement:/d' \
  "$work/retired-workflow-history-omitted/docs/RELEASE_POLICY.md"
run_gate "$work/retired-workflow-history-omitted"
printf 'release document consistency did not require retired workflow history\n'

if CURRENT_CLASSIFIER_POLICY_VERSION="$old_classifier_policy_version" "$gate" \
  >"$work/source-classifier-override.log" 2>&1; then
  echo 'release document consistency source-tree classifier override unexpectedly passed' >&2
  exit 1
fi
grep -Fq \
  'source-tree release document verification forbids document-root and CURRENT_* overrides' \
  "$work/source-classifier-override.log" || {
  echo 'release document consistency source-tree classifier override emitted the wrong diagnostic' >&2
  exit 1
}
printf 'release document consistency source-tree classifier override rejected as expected\n'

if RELEASE_DOC_ROOT="$work/pass" \
  CURRENT_RELEASE_VERSION=0.16 \
  CURRENT_RULESET_SHA256="$ruleset_sha256" \
  CURRENT_CLASSIFIER_POLICY_VERSION="$classifier_policy_version" \
  CURRENT_CLASSIFIER_POLICY_SHA256="$classifier_policy_sha256" \
  "$gate" >"$work/external-root-without-fixture-mode.log" 2>&1; then
  echo 'release document consistency external root without fixture mode unexpectedly passed' >&2
  exit 1
fi
grep -Fq \
  'external release document roots are allowed only with RELEASE_DOC_FIXTURE_MODE=1' \
  "$work/external-root-without-fixture-mode.log" || {
  echo 'release document consistency external root without fixture mode emitted the wrong diagnostic' >&2
  exit 1
}
printf 'release document consistency external root without fixture mode rejected as expected\n'

cp -a "$work/pass" "$work/historical-hash"
sed -i "/ruleset_sha256:/i ruleset_sha256: $old_ruleset_sha256" \
  "$work/historical-hash/docs/reports/RELEASE_EVIDENCE.md"
run_gate "$work/historical-hash"

cp -a "$work/pass" "$work/stale-document"
sed -i '/formal-release-attestation.json/d' "$work/stale-document/README.md"
must_fail stale-document "$work/stale-document" \
  'README.md must point readers to the formal gate attestation'

cp -a "$work/pass" "$work/stale-round8-security-identity"
sed -i 's/current_classifier_policy_version: classifier-policy-v5/current_classifier_policy_version: classifier-policy-v4/' \
  "$work/stale-round8-security-identity/SECURITY.md"
must_fail stale-round8-security-identity "$work/stale-round8-security-identity" \
  'SECURITY.md must place the exact visible classifier policy prologue on lines 2-6'

cp -a "$work/pass" "$work/stale-active-classifier-key"
printf '\ncurrent_release_classifier_policy_version: %s\ncurrent_release_classifier_policy_sha256: %s\n' \
  "$classifier_policy_version" "$old_classifier_policy_sha256" \
  >>"$work/stale-active-classifier-key/docs/RULES.md"
must_fail stale-active-classifier-key "$work/stale-active-classifier-key" \
  'current release documents must not contain stale active classifier identities'

cp -a "$work/pass" "$work/stale-working-tree-classifier-key"
printf '\nworking_tree_classifier_policy_version: %s\nworking_tree_classifier_policy_sha256: %s\n' \
  "$stale_round9_policy_version" "$stale_round9_policy_sha256" \
  >>"$work/stale-working-tree-classifier-key/docs/reports/TEST_REPORT.md"
must_fail stale-working-tree-classifier-key "$work/stale-working-tree-classifier-key" \
  'current release documents must not contain stale active classifier identities'

cp -a "$work/pass" "$work/stale-working-tree-classifier-prose"
printf '\nThe current working-tree identity is `%s` / `%s`.\n' \
  "$stale_round9_policy_version" "$stale_round9_policy_sha256" \
  >>"$work/stale-working-tree-classifier-prose/docs/reports/PERFORMANCE.md"
must_fail stale-working-tree-classifier-prose "$work/stale-working-tree-classifier-prose" \
  'current release documents must not contain stale active classifier identities'

cp -a "$work/pass" "$work/stale-abbreviated-current-classifier-prose"
printf '\nThe source checks are evidence for the current `%s` policy identity.\n' \
  "$stale_abbreviated_policy_sha256" \
  >>"$work/stale-abbreviated-current-classifier-prose/docs/reports/PERFORMANCE.md"
must_fail stale-abbreviated-current-classifier-prose \
  "$work/stale-abbreviated-current-classifier-prose" \
  "contains abbreviated or stale current classifier policy SHA-256 $stale_abbreviated_policy_sha256"

cp -a "$work/pass" "$work/stale-abbreviated-working-tree-classifier-prose"
printf '\nThe current working-tree identity is `%s` / `%s`.\n' \
  "$classifier_policy_version" "$stale_abbreviated_policy_sha256" \
  >>"$work/stale-abbreviated-working-tree-classifier-prose/docs/reports/PERFORMANCE.md"
must_fail stale-abbreviated-working-tree-classifier-prose \
  "$work/stale-abbreviated-working-tree-classifier-prose" \
  "contains abbreviated or stale current classifier policy SHA-256 $stale_abbreviated_policy_sha256"

cp -a "$work/pass" "$work/missing-working-tree-classifier-sha"
printf '\nThe current working-tree identity is `%s`.\n' \
  "$classifier_policy_version" \
  >>"$work/missing-working-tree-classifier-sha/docs/reports/PERFORMANCE.md"
must_fail missing-working-tree-classifier-sha \
  "$work/missing-working-tree-classifier-sha" \
  'presents a current or working-tree classifier identity without a full SHA-256'

cp -a "$work/pass" "$work/current-full-classifier-prose"
printf '\nThe current working-tree identity is `%s` / `%s`.\n' \
  "$classifier_policy_version" "$classifier_policy_sha256" \
  >>"$work/current-full-classifier-prose/docs/reports/PERFORMANCE.md"
run_gate "$work/current-full-classifier-prose"
printf 'release document consistency allowed an exact full current classifier policy identity\n'

cp -a "$work/pass" "$work/historical-abbreviated-classifier-prose"
printf '\nHistorical evidence retained a pre-current `%s` policy identity as chronology.\n' \
  "$stale_abbreviated_policy_sha256" \
  >>"$work/historical-abbreviated-classifier-prose/docs/reports/PERFORMANCE.md"
run_gate "$work/historical-abbreviated-classifier-prose"
printf 'release document consistency allowed clearly historical abbreviated identity evidence\n'

cp -a "$work/pass" "$work/historical-same-version-classifier-prose"
printf '\nThe last CPA remediation identity was `%s` / `%s`.\n' \
  "$classifier_policy_version" "$old_classifier_policy_sha256" \
  >>"$work/historical-same-version-classifier-prose/docs/reports/PERFORMANCE.md"
run_gate "$work/historical-same-version-classifier-prose"
printf 'release document consistency allowed clearly historical same-version identity evidence\n'

cp -a "$work/pass" "$work/historical-prior-line-classifier-prose"
printf '\nHistorical evidence from the superseded candidate follows.\n`%s` / `%s`\n' \
  "$classifier_policy_version" "$old_classifier_policy_sha256" \
  >>"$work/historical-prior-line-classifier-prose/docs/reports/PERFORMANCE.md"
run_gate "$work/historical-prior-line-classifier-prose"
printf 'release document consistency recognized a historical annotation on the preceding line\n'

cp -a "$work/pass" "$work/stale-active-target-classifier-prose"
printf '\nThe active development target is Linux amd64, %s.\n' \
  "$stale_round9_policy_version" \
  >>"$work/stale-active-target-classifier-prose/docs/reports/RELEASE_EVIDENCE.md"
must_fail stale-active-target-classifier-prose "$work/stale-active-target-classifier-prose" \
  'current release documents must not contain stale active classifier identities'

cp -a "$work/pass" "$work/stale-json-active-classifier-key"
printf '\n{"current_release_classifier_policy_sha256":"%s"}\n' \
  "$old_classifier_policy_sha256" \
  >>"$work/stale-json-active-classifier-key/docs/RULES.md"
must_fail stale-json-active-classifier-key "$work/stale-json-active-classifier-key" \
  'current release documents must not contain stale active classifier identities'

cp -a "$work/pass" "$work/stale-backtick-active-classifier-key"
printf '\n`round8_classifier_policy_sha256`: `%s`\n' \
  "$old_classifier_policy_sha256" \
  >>"$work/stale-backtick-active-classifier-key/docs/reports/RELEASE_EVIDENCE.md"
must_fail stale-backtick-active-classifier-key "$work/stale-backtick-active-classifier-key" \
  'current release documents must not contain stale active classifier identities'

cp -a "$work/pass" "$work/stale-inline-classifier-identity"
printf '\n| Classifier policy | `%s` / `%s` |\n' \
  "$classifier_policy_version" "$old_classifier_policy_sha256" \
  >>"$work/stale-inline-classifier-identity/docs/reports/TEST_REPORT.md"
must_fail stale-inline-classifier-identity "$work/stale-inline-classifier-identity" \
  'current release documents must not contain stale active classifier identities'

cp -a "$work/pass" "$work/stale-adjacent-classifier-identity"
printf '\nActive classifier: `%s`\nActive classifier policy digest: `%s`\n' \
  "$classifier_policy_version" "$old_classifier_policy_sha256" \
  >>"$work/stale-adjacent-classifier-identity/docs/DESIGN.md"
must_fail stale-adjacent-classifier-identity "$work/stale-adjacent-classifier-identity" \
  'current release documents must not contain stale active classifier identities'

cp -a "$work/pass" "$work/stale-three-line-classifier-identity"
printf '\nActive classifier: `%s`\nSHA-256\n`%s`\n' \
  "$classifier_policy_version" "$old_classifier_policy_sha256" \
  >>"$work/stale-three-line-classifier-identity/docs/DESIGN.md"
must_fail stale-three-line-classifier-identity "$work/stale-three-line-classifier-identity" \
  'current release documents must not contain stale active classifier identities'

cp -a "$work/pass" "$work/ruleset-before-current-classifier"
printf '\n| Ruleset SHA-256 | `%s` |\n| Classifier policy | `%s` / `%s` |\n' \
  "$ruleset_sha256" "$classifier_policy_version" "$classifier_policy_sha256" \
  >>"$work/ruleset-before-current-classifier/docs/reports/TEST_REPORT.md"
run_gate "$work/ruleset-before-current-classifier"
printf 'release document consistency allowed a distinct ruleset hash immediately before the correct classifier identity\n'

cp -a "$work/pass" "$work/classifier-before-ruleset"
printf '\nThe current working-tree identity is `%s` /\n`%s`\nand ruleset `1.0.10` /\n`%s`.\n' \
  "$classifier_policy_version" "$classifier_policy_sha256" "$ruleset_sha256" \
  >>"$work/classifier-before-ruleset/docs/reports/PERFORMANCE.md"
run_gate "$work/classifier-before-ruleset"
printf 'release document consistency allowed the correct classifier identity immediately before a distinct ruleset hash\n'

cp -a "$work/pass" "$work/quoted-current-active-classifier"
printf '\n{"current_release_classifier_policy_sha256":"%s"}\n' \
  "$classifier_policy_sha256" \
  >>"$work/quoted-current-active-classifier/docs/RULES.md"
run_gate "$work/quoted-current-active-classifier"
printf 'release document consistency allowed a quoted JSON active classifier identity when it is current\n'

cp -a "$work/pass" "$work/round8-database-same-lane-duplicate"
awk '
  $0 == "          \"schema_version\": 5," {
    schema_count++
    if (schema_count == 1) {
      print
    }
    next
  }
  $0 == "          \"migration_versions\": [1, 2, 3, 4, 5]" {
    migration_count++
    if (migration_count == 1) {
      print $0 ","
      print "          \"schema_version\": 5,"
      print
    }
    next
  }
  { print }
' "$work/round8-database-same-lane-duplicate/docs/reports/ROUND8_RELEASE_READINESS.md" \
  >"$work/round8-database-same-lane-duplicate/docs/reports/ROUND8_RELEASE_READINESS.md.tmp"
mv -f -- \
  "$work/round8-database-same-lane-duplicate/docs/reports/ROUND8_RELEASE_READINESS.md.tmp" \
  "$work/round8-database-same-lane-duplicate/docs/reports/ROUND8_RELEASE_READINESS.md"
must_fail round8-database-same-lane-duplicate \
  "$work/round8-database-same-lane-duplicate" \
  'docs/reports/ROUND8_RELEASE_READINESS.md must show the exact database schema and migration history in each named CPA lane'

cp -a "$work/pass" "$work/alias-policy"
sed -i 's/current_version_alias_policy: reject-v0.16.0/current_version_alias_policy: allow-v0.16.0/' \
  "$work/alias-policy/docs/RELEASE_POLICY.md"
must_fail alias-policy "$work/alias-policy" \
  'docs/RELEASE_POLICY.md must contain exactly one policy line: current_version_alias_policy: reject-v0.16.0'

policy_keys=(
  current_candidate_tag
  current_platform
  current_go_contract
  current_cpa_commit
  current_host_runner_label
  current_rc_manifest_schema
  current_audit_schema
  current_external_evaluation_schema
  current_independent_audit_evidence_schema
  current_independent_audit_ledger_event_schema
  current_independent_audit_ledger_proof_schema
  current_counted_mock_schema
  current_cpa_host_listener
  current_external_evaluation_asset
  current_external_ledger_proof_asset
  current_public_adversarial_corpus
  current_public_adversarial_manifest_schema
  current_public_adversarial_machine_report_schema
  current_candidate_asset_count
  current_private_candidate_artifact
  current_private_candidate_capability
  current_legacy_verifier_asset_count
  current_legacy_verifier_reachability
  current_new_public_prerelease_creation
  current_exact_candidate_independent_audit_evidence_status
  current_exact_candidate_independent_audit_mechanical_gate
  current_host_evaluation_publication_sufficiency
  current_release_title_publication_sufficiency
  current_publication_write_permission
  current_development_paired_recall_requirement
  current_independent_malicious_recall_requirement
  current_release_kind
  current_legacy_verifier_identity_contract
  current_legacy_verifier_asset_contract
  current_release_latest
  current_release_recovery
  current_release_new_dispatch_or_rerun_all
  current_release_draft_recovery
  current_release_latest_stable
  current_independent_audit_status
  current_production_approval_status
  historical_round8_rc_artifact_version
  historical_round8_rc_publish_host_evidence
  historical_round8_host_matrix
  historical_round8_host_matrix_commit
)
policy_values=(
  v0.16-rc.4
  linux-amd64
  1.26.4
  bc71c77f5cc42f3fbe1bf040cf14d4f166894835
  cag-round9-sandbox
  6
  6
  round9-external-evaluation/v3
  round9-independent-audit-evidence/v1
  round9-independent-audit-ledger-event/v1
  round9-independent-audit-ledger-proof/v1
  round9-external-counted-mock/v1
  '127.0.0.1:18394->8317/tcp'
  round9-external-evaluation.json
  round9-external-ledger-proof.json
  round9-public-adversarial-v13
  round9-public-adversarial-corpus/v13
  round9-public-adversarial-report/v13
  17
  actions-only-17-assets
  build-attest-upload-actions-only
  19
  disabled-if-false
  BLOCKED_FAIL_CLOSED
  NOT_PROVIDED
  IMPLEMENTED_FAIL_CLOSED_EVIDENCE_NOT_PROVIDED
  false
  false
  absent
  aggregate-and-each-category-exactly-10000-basis-points
  aggregate-and-each-category-at-least-9500-basis-points
  private-candidate-only-public-prerelease-blocked
  'release-object,tag=v0.16-rc.4,annotated-tag-target=exact-commit,target-commitish=exact-commit,title=exact,body=exact,prerelease=true,latest=false,draft=false,immutable=true'
  'exact-count=19,download-count=19,byte-compare-each=rebuilt-candidate,attestation-check=17-release-workflow-plus-2-host-workflow'
  false
  fail-only-existing-release-rejected-no-automatic-verifier
  admission-existing-release-fail-only-otherwise-private-candidate-only
  fail-only-manual-review-no-automatic-mutation
  v0.15
  NOT_PROVIDED
  NOT_GRANTED
  0.16-rc.2
  round8-host-evidence.json
  v7.2.95
  f71ec0eb6776854457892452cf28c47f0d658251
)
policy_bad_values=(
  v0.16-rc.2
  windows-amd64
  latest
  0000000000000000000000000000000000000000
  cag-round8-sandbox
  5
  5
  round9-external-evaluation/v1
  round9-independent-audit-evidence/v0
  round9-independent-audit-ledger-event/v0
  round9-independent-audit-ledger-proof/v0
  round9-host-evidence/v1
  '0.0.0.0:18394->8317/tcp'
  round9-host-evidence.json
  round9-host-evidence.json.sha256
  round9-public-adversarial-v5
  round9-public-adversarial-corpus/v8
  round9-public-adversarial-report/v5
  16
  github-release
  publish-release
  18
  enabled
  ALLOWED
  PASS
  NOT_IMPLEMENTED
  true
  true
  write
  aggregate-and-each-category-at-least-9500-basis-points
  aggregate-only-at-least-9500-basis-points
  immutable-prerelease
  'release-object,tag=v0.16-rc.2,annotated-tag-target=branch-head,target-commitish=branch-head,title=unchecked,body=unchecked,prerelease=false,latest=true,draft=true'
  'exact-count=19,download-count=19,byte-compare-each=rebuilt-candidate,attestation-check=19-release-workflow'
  true
  same-run-re-run-failed-or-admission-read-only-verifier
  admission-existing-public-read-only-verify-otherwise-publish
  automatic-delete-and-recreate
  v0.16-rc.4
  PASS
  GRANTED
  0.16-rc.4
  round9-host-evidence.json
  v7.2.102
  8423cce2d1004e80948a9e2c60ee69354c0aabc3
)
for index in "${!policy_keys[@]}"; do
  key="${policy_keys[$index]}"
  value="${policy_values[$index]}"
  bad_value="${policy_bad_values[$index]}"

  cp -a "$work/pass" "$work/${key}-missing"
  sed -i "\|^${key}: ${value}$|d" \
    "$work/${key}-missing/docs/RELEASE_POLICY.md"
  must_fail "${key}-missing" "$work/${key}-missing" \
    "docs/RELEASE_POLICY.md must contain exactly one policy key: $key"

  cp -a "$work/pass" "$work/${key}-changed"
  sed -i "s|^${key}: ${value}$|${key}: ${bad_value}|" \
    "$work/${key}-changed/docs/RELEASE_POLICY.md"
  must_fail "${key}-changed" "$work/${key}-changed" \
    "docs/RELEASE_POLICY.md must contain exactly one policy line: ${key}: ${value}"
done

cp -a "$work/pass" "$work/stale-active-public-corpus-prose"
printf '%s\n' 'The current public adversarial corpus is development-only v7 evidence.' \
  >>"$work/stale-active-public-corpus-prose/docs/RELEASE_POLICY.md"
must_fail stale-active-public-corpus-prose "$work/stale-active-public-corpus-prose" \
  'docs/RELEASE_POLICY.md retains a stale active public corpus version'

cp -a "$work/pass" "$work/missing-split-attestation-prose"
sed -i 's/The disabled legacy verifier documents the prospective signer split/The disabled legacy verifier drops the prospective signer split/' \
  "$work/missing-split-attestation-prose/docs/RELEASE_POLICY.md"
must_fail missing-split-attestation-prose "$work/missing-split-attestation-prose" \
  'docs/RELEASE_POLICY.md is missing the active public-v13/release-attestation contract: The disabled legacy verifier documents the prospective signer split'

cp -a "$work/pass" "$work/host-only-publication-prose"
sed -i 's/The Host result is necessary evaluation evidence, but it is not sufficient/The Host result alone is sufficient/' \
  "$work/host-only-publication-prose/docs/RELEASE_POLICY.md"
must_fail host-only-publication-prose "$work/host-only-publication-prose" \
  'docs/RELEASE_POLICY.md is missing the active public-v13/release-attestation contract: The Host result is necessary evaluation evidence, but it is not sufficient'

cp -a "$work/pass" "$work/title-only-publication-prose"
sed -i 's/Release title\/body text such as `independent audit required` is also not evidence/Release title text authorizes publication/' \
  "$work/title-only-publication-prose/docs/RELEASE_POLICY.md"
must_fail title-only-publication-prose "$work/title-only-publication-prose" \
  'docs/RELEASE_POLICY.md is missing the active public-v13/release-attestation contract: Release title/body text such as `independent audit required` is also not evidence'

retired_round9_host_keys=(
  current_host_evidence_schema
  current_host_evidence_schema_version
  current_counted_mock_probe_schema_version
  current_evaluation_contract_schema
  current_host_evidence
  current_host_evidence_sidecar
)
for key in "${retired_round9_host_keys[@]}"; do
  cp -a "$work/pass" "$work/${key}-retired"
  printf '%s: retired\n' "$key" >>"$work/${key}-retired/docs/RELEASE_POLICY.md"
  must_fail "${key}-retired" "$work/${key}-retired" \
    "docs/RELEASE_POLICY.md contains a retired active Round 9 Host-evidence key: $key"
done

cp -a "$work/pass" "$work/duplicate-policy-key"
printf '%s\n' 'current_version_alias_policy: allow-v0.16.0' \
  >>"$work/duplicate-policy-key/docs/RELEASE_POLICY.md"
must_fail duplicate-policy-key "$work/duplicate-policy-key" \
  'docs/RELEASE_POLICY.md must contain exactly one policy key: current_version_alias_policy'

cp -a "$work/pass" "$work/unlabeled-round8-active-key"
printf '%s\n' 'rc_workflow: .github/workflows/release-rc.yml' \
  >>"$work/unlabeled-round8-active-key/docs/RELEASE_POLICY.md"
must_fail unlabeled-round8-active-key "$work/unlabeled-round8-active-key" \
  'docs/RELEASE_POLICY.md contains an unlabeled legacy Round 8 active key: rc_workflow'

cp -a "$work/pass" "$work/unlabeled-historical-corpus"
sed -i 's/^# Historical /# /' \
  "$work/unlabeled-historical-corpus/docs/reports/CORPUS_REPORT.md"
must_fail unlabeled-historical-corpus "$work/unlabeled-historical-corpus" \
  'docs/reports/CORPUS_REPORT.md must be explicitly labeled as historical v0.1.2 evidence'

cp -a "$work/pass" "$work/old-hash"
sed -i "s/$ruleset_sha256/$old_ruleset_sha256/" \
  "$work/old-hash/docs/reports/TEST_REPORT.md"
must_fail old-hash "$work/old-hash" \
  'docs/reports/TEST_REPORT.md latest ruleset_sha256'

cp -a "$work/pass" "$work/old-classifier-hash"
sed -i "s/$classifier_policy_sha256/$old_classifier_policy_sha256/" \
  "$work/old-classifier-hash/docs/reports/TEST_REPORT.md"
must_fail old-classifier-hash "$work/old-classifier-hash" \
  'docs/reports/TEST_REPORT.md must place the exact visible classifier policy prologue on lines 2-6'

cp -a "$work/pass" "$work/old-classifier-version"
sed -i "s/$classifier_policy_version/$old_classifier_policy_version/" \
  "$work/old-classifier-version/docs/reports/TEST_REPORT.md"
must_fail old-classifier-version "$work/old-classifier-version" \
  'docs/reports/TEST_REPORT.md must place the exact visible classifier policy prologue on lines 2-6'

cp -a "$work/pass" "$work/conflicting-classifier-version"
printf '%s\n' "current_classifier_policy_version: $old_classifier_policy_version" \
  >>"$work/conflicting-classifier-version/docs/reports/TEST_REPORT.md"
must_fail conflicting-classifier-version "$work/conflicting-classifier-version" \
  'docs/reports/TEST_REPORT.md must contain exactly one canonical classifier policy version key: current_classifier_policy_version'

cp -a "$work/pass" "$work/conflicting-classifier-hash"
printf '%s\n' "current_classifier_policy_sha256: $old_classifier_policy_sha256" \
  >>"$work/conflicting-classifier-hash/docs/reports/TEST_REPORT.md"
must_fail conflicting-classifier-hash "$work/conflicting-classifier-hash" \
  'docs/reports/TEST_REPORT.md must contain exactly one canonical classifier policy SHA-256 key: current_classifier_policy_sha256'

cp -a "$work/pass" "$work/quoted-conflicting-classifier-version"
printf '%s\n' "\"current_classifier_policy_version\": \"$old_classifier_policy_version\"" \
  >>"$work/quoted-conflicting-classifier-version/docs/reports/TEST_REPORT.md"
must_fail quoted-conflicting-classifier-version "$work/quoted-conflicting-classifier-version" \
  'docs/reports/TEST_REPORT.md must contain exactly one canonical classifier policy version key: current_classifier_policy_version'

cp -a "$work/pass" "$work/same-line-conflicting-classifier-version"
printf '%s\n' \
  "current_classifier_policy_version: $old_classifier_policy_version current_classifier_policy_version: $classifier_policy_version" \
  >>"$work/same-line-conflicting-classifier-version/docs/reports/TEST_REPORT.md"
must_fail same-line-conflicting-classifier-version "$work/same-line-conflicting-classifier-version" \
  'docs/reports/TEST_REPORT.md must contain exactly one canonical classifier policy version key: current_classifier_policy_version'

cp -a "$work/pass" "$work/duplicate-current-classifier-identity"
printf '%s\n%s\n' \
  "current_classifier_policy_version: $classifier_policy_version" \
  "current_classifier_policy_sha256: $classifier_policy_sha256" \
  >>"$work/duplicate-current-classifier-identity/docs/reports/TEST_REPORT.md"
must_fail duplicate-current-classifier-identity "$work/duplicate-current-classifier-identity" \
  'docs/reports/TEST_REPORT.md must contain exactly one canonical classifier policy version key: current_classifier_policy_version'

cp -a "$work/pass" "$work/legacy-plus-current-classifier-identity"
printf '%s\n%s\n' \
  "classifier_policy: $old_classifier_policy_version" \
  "classifier_policy_sha256: $old_classifier_policy_sha256" \
  >>"$work/legacy-plus-current-classifier-identity/docs/reports/TEST_REPORT.md"
must_fail legacy-plus-current-classifier-identity "$work/legacy-plus-current-classifier-identity" \
  'docs/reports/TEST_REPORT.md must not contain unlabeled legacy classifier policy keys; use current_ or historical_ prefixes'

cp -a "$work/pass" "$work/spaced-legacy-classifier-identity"
printf '%s\n' "classifier_policy : $old_classifier_policy_version" \
  >>"$work/spaced-legacy-classifier-identity/docs/reports/TEST_REPORT.md"
must_fail spaced-legacy-classifier-identity "$work/spaced-legacy-classifier-identity" \
  'docs/reports/TEST_REPORT.md must not contain unlabeled legacy classifier policy keys; use current_ or historical_ prefixes'

quoted_legacy_index=0
for quoted_key in \
  '"classifier_policy"' \
  "'classifier_policy'" \
  '`classifier_policy`'; do
  fixture_name="quoted-legacy-$quoted_legacy_index"
  quoted_legacy_index=$((quoted_legacy_index + 1))
  cp -a "$work/pass" "$work/$fixture_name"
  printf '%s: %s\n' "$quoted_key" "$old_classifier_policy_version" \
    >>"$work/$fixture_name/docs/reports/TEST_REPORT.md"
  must_fail "$fixture_name" "$work/$fixture_name" \
    'docs/reports/TEST_REPORT.md must not contain unlabeled legacy classifier policy keys; use current_ or historical_ prefixes'
done

cp -a "$work/pass" "$work/moved-classifier-prologue"
sed -i '2,6d' "$work/moved-classifier-prologue/docs/reports/TEST_REPORT.md"
printf '\n```text\ncurrent_classifier_policy_version: %s\ncurrent_classifier_policy_sha256: %s\n```\n' \
  "$classifier_policy_version" "$classifier_policy_sha256" \
  >>"$work/moved-classifier-prologue/docs/reports/TEST_REPORT.md"
must_fail moved-classifier-prologue "$work/moved-classifier-prologue" \
  'docs/reports/TEST_REPORT.md must place the exact visible classifier policy prologue on lines 2-6'

cp -a "$work/pass" "$work/hidden-classifier-prologue"
sed -i '3s/^```text$/<!--/; 6s/^```$/-->/' \
  "$work/hidden-classifier-prologue/docs/reports/TEST_REPORT.md"
must_fail hidden-classifier-prologue "$work/hidden-classifier-prologue" \
  'docs/reports/TEST_REPORT.md must place the exact visible classifier policy prologue on lines 2-6'

cp -a "$work/pass" "$work/html-wrapped-classifier-prologue"
sed -i '1c<!--' "$work/html-wrapped-classifier-prologue/docs/reports/TEST_REPORT.md"
sed -i '7i-->' "$work/html-wrapped-classifier-prologue/docs/reports/TEST_REPORT.md"
must_fail html-wrapped-classifier-prologue "$work/html-wrapped-classifier-prologue" \
  'docs/reports/TEST_REPORT.md must start with one visible top-level Markdown heading'

cp -a "$work/pass" "$work/frontmatter-wrapped-classifier-prologue"
sed -i '1c---' "$work/frontmatter-wrapped-classifier-prologue/docs/reports/TEST_REPORT.md"
must_fail frontmatter-wrapped-classifier-prologue "$work/frontmatter-wrapped-classifier-prologue" \
  'docs/reports/TEST_REPORT.md must start with one visible top-level Markdown heading'

cp -a "$work/pass" "$work/reordered-classifier-prologue"
awk 'NR == 4 { first = $0; next } NR == 5 { print; print first; next } { print }' \
  "$work/reordered-classifier-prologue/docs/reports/TEST_REPORT.md" \
  >"$work/reordered-classifier-prologue/docs/reports/TEST_REPORT.md.tmp"
mv -f -- \
  "$work/reordered-classifier-prologue/docs/reports/TEST_REPORT.md.tmp" \
  "$work/reordered-classifier-prologue/docs/reports/TEST_REPORT.md"
must_fail reordered-classifier-prologue "$work/reordered-classifier-prologue" \
  'docs/reports/TEST_REPORT.md must place the exact visible classifier policy prologue on lines 2-6'

cp -a "$work/pass" "$work/labeled-historical-classifier-identity"
printf '%s\n%s\n' \
  "historical_classifier_policy_version: $old_classifier_policy_version" \
  "historical_classifier_policy_sha256: $old_classifier_policy_sha256" \
  >>"$work/labeled-historical-classifier-identity/docs/reports/TEST_REPORT.md"
run_gate "$work/labeled-historical-classifier-identity"

printf 'all release document consistency fixtures passed\n'
