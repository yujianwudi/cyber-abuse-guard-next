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
work="$(mktemp -d)"
trap 'rm -rf -- "$work"' EXIT

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
  docs/RELEASE_POLICY.md
  docs/ROUND6_CONFIG_MIGRATION.md
  docs/ROUND6_DEVELOPMENT_HANDOFF.md
  docs/ROUND6_LIMITATIONS.md
  docs/ROUND6_RELEASE_GATE.md
  docs/ROUND6_STREAMING_SCANNER_DESIGN.md
  docs/ROUND8_HOST_RUNNER.md
  docs/ROUND9_AUDIT_SCHEMA_V6.md
  docs/ROUND9_HOST_RUNNER.md
  docs/ROUND9_OPERATOR_ROLLOUT.md
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

make_fixture() {
  local fixture="$1" relative
  mkdir -p "$fixture/docs/reports"
  for relative in "${documents[@]}"; do
    mkdir -p "$(dirname "$fixture/$relative")"
    if [[ "$relative" == docs/RELEASE_POLICY.md ]]; then
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
        'current_cpa_version: v7.2.103' \
        'current_cpa_commit: cade44b9cdee6b9328ea2648fd119129fdf11e2d' \
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
    elif [[ "$relative" == CHANGELOG.md ]]; then
      printf '# Changelog\n\n## 0.16 - 2026-07-21\n\nround6-prerelease-attestation.json\nformal-release-attestation.json\n' >"$fixture/$relative"
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
  current_gate_workflow
  current_host_workflow
  current_rc_workflow
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
  current_round9_gate_admission
  current_historical_workflow_disable_requirement
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
  cade44b9cdee6b9328ea2648fd119129fdf11e2d
  .github/workflows/round9-gate.yml
  .github/workflows/round9-host-validation.yml
  .github/workflows/round9-release-rc.yml
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
  'workflow=Round 9 policy gate,path=.github/workflows/round9-gate.yml,event=push,branch=main,exact-commit,completed-success'
  '315644586:release-rc.yml=disabled_manually,318443961:round8-host-validation.yml=disabled_manually'
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
  .github/workflows/ci.yml
  .github/workflows/round8-host-validation.yml
  .github/workflows/release-rc.yml
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
  'workflow=Round 8 policy gate,path=.github/workflows/round8-gate.yml,event=workflow_dispatch,branch=feature,any-commit,completed-success'
  '315644586:release-rc.yml=active,318443961:round8-host-validation.yml=active'
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
