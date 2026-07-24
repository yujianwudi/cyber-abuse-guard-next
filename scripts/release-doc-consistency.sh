#!/usr/bin/env bash
set -euo pipefail

root="$(cd "${BASH_SOURCE[0]%/*}/.." && pwd -P)"
# shellcheck source=release-common.sh
source "$root/scripts/release-common.sh"
release_require_commands awk grep sed sha256sum sort tr wc python3

doc_root="${RELEASE_DOC_ROOT:-$root}"
fixture_mode="${RELEASE_DOC_FIXTURE_MODE:-0}"

fail() {
  printf 'release document consistency error: %s\n' "$*" >&2
  exit 1
}

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
[[ "$current_release_version" =~ ^[0-9]+\.[0-9]+$ ]] || \
  fail "cannot determine the exact two-component release version"

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
)

for relative in "${documents[@]}"; do
  document="$doc_root/$relative"
  [[ -f "$document" && ! -L "$document" ]] || fail "required current release document must be a regular non-symlink file: $relative"
done

if [[ "$doc_root" == "$root" ]]; then
  grep -Fq '[Round 9 Linux Host runner and counted-Mock contract](ROUND9_HOST_RUNNER.md)' \
    "$root/docs/README.md" ||
    fail "documentation index lost the Round 9 Host runner link"
  grep -Fq '`docs/ROUND9_HOST_RUNNER.md`' \
    "$root/integration/round9countedmock/README.md" ||
    fail "Round 9 counted-Mock README lost its Host contract link"
  grep -Fq '[Round 9 audit schema v6](ROUND9_AUDIT_SCHEMA_V6.md)' \
    "$root/docs/README.md" ||
    fail "documentation index lost the Round 9 audit-schema link"
  grep -Fq '[Round 9 exact-candidate independent-audit verifier contract](ROUND9_INDEPENDENT_AUDIT_CONTRACT.md)' \
    "$root/docs/README.md" ||
    fail "documentation index lost the Round 9 independent-audit verifier link"
  grep -Fq '[Round 9 operator-owned rollout and rollback](ROUND9_OPERATOR_ROLLOUT.md)' \
    "$root/docs/README.md" ||
    fail "documentation index lost the Round 9 operator-runbook link"
  grep -Fq '[Round 9 execution record and traceability matrix](reports/ROUND9_EXECUTION_RECORD.md)' \
    "$root/docs/README.md" ||
    fail "documentation index lost the Round 9 execution-record link"
  grep -Fq '| `round9-release-rc.yml` |' "$root/.github/workflows/README.md" ||
    fail "workflow index lost the active Round 9 RC lane"
  grep -Fq '127.0.0.1:18394 -> 8317/tcp' "$root/docs/ROUND9_HOST_RUNNER.md" ||
    fail "Round 9 Host guide lost the fixed CPA listener contract"
  round9_rc_workflow="$root/.github/workflows/round9-release-rc.yml"
  [[ -f "$round9_rc_workflow" && ! -L "$round9_rc_workflow" ]] ||
    fail "Round 9 RC workflow must be a regular non-symlink file"
  grep -Fq 'ROUND9_NEW_PUBLIC_PRERELEASE_CREATION: BLOCKED_PENDING_EXACT_CANDIDATE_INDEPENDENT_AUDIT_GATE' \
    "$round9_rc_workflow" ||
    fail "Round 9 RC workflow lost the exact-candidate independent-audit publication block"
  [[ "$(grep -Fxc '      publication_permitted: ${{ steps.admit.outputs.publication_permitted }}' "$round9_rc_workflow")" == 1 ]] &&
    [[ "$(grep -Fxc "            printf 'publication_permitted=false\\n'" "$round9_rc_workflow")" == 1 ]] &&
    [[ "$(grep -Fxc "    if: \${{ needs.admission.outputs.publication_permitted == 'true' }}" "$round9_rc_workflow")" == 3 ]] ||
    fail "Round 9 publish, publication-blocker, and legacy verifier jobs must remain gated by the reviewed false admission output"
  grep -Fq 'round9_gate_run:' "$round9_rc_workflow" ||
    fail "Round 9 RC workflow lost the exact-main Round 9 gate-run input"
  grep -Fq 'actions/workflows/315644586' "$round9_rc_workflow" &&
    grep -Fq 'actions/workflows/318443961' "$round9_rc_workflow" &&
    [[ "$(grep -Fc '.state == "disabled_manually"' "$round9_rc_workflow")" == 2 ]] ||
    fail "Round 9 RC workflow must require both historical workflow IDs to remain disabled_manually"
  grep -Fq '[.[][] | select(.tag_name == $tag)] | length == 0' \
    "$round9_rc_workflow" ||
    fail "Round 9 RC workflow must reject every existing candidate Release"
  if grep -Fq 'already_public' "$round9_rc_workflow" ||
    grep -Fq 'inputs.publish_rc_release' "$round9_rc_workflow"; then
    fail "Round 9 RC workflow must not retain the retired public-recovery state or input"
  fi
  grep -Fq 'publication_blocked:' "$round9_rc_workflow" ||
    fail "Round 9 RC workflow lost the fail-closed publication job"
  grep -Fq 'Fail closed after retaining the private candidate artifact' \
    "$round9_rc_workflow" ||
    fail "Round 9 RC workflow lost the private-candidate fail-closed boundary"
  grep -Fq 'verify_published:' "$round9_rc_workflow" ||
    fail "Round 9 RC workflow lost the disabled legacy verifier contract"
  if grep -Eq '^[[:space:]]*contents:[[:space:]]*write[[:space:]]*$' \
    "$round9_rc_workflow"; then
    fail "Round 9 RC workflow must not hold contents write permission while exact-candidate audit evidence is not provided"
  fi
  if grep -Eq '(^|[[:space:]])gh[[:space:]]+(release[[:space:]]+(create|upload|edit|delete)|api[[:space:]].*--method[[:space:]]+(POST|PATCH|PUT|DELETE))([[:space:]]|$)' \
    "$round9_rc_workflow"; then
    fail "Round 9 RC workflow must not contain a Release mutation path while exact-candidate audit is unimplemented"
  fi
  grep -Fq 'HTTP `503` and the fixed `audit_unavailable` error' \
    "$root/docs/ROUND9_AUDIT_SCHEMA_V6.md" ||
    fail "Round 9 audit guide lost the enabled-but-unavailable management contract"
fi

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

if ! python3 -B - \
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
    r"(?P<key>(?:round8|current_release)_classifier_policy_(?:version|sha256))"
    r"\s*:\s*(?P<value>[A-Za-z0-9._-]+)"
)
sha256 = re.compile(r"(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])")

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
    lines = text.splitlines()
    for line_number, line in enumerate(lines, start=1):
        if current_version not in line:
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
[[ -f "$historical_corpus" ]] || \
  fail "required historical corpus report is missing: docs/reports/CORPUS_REPORT.md"
grep -Eq '^# Historical .*v0\.1\.2 candidate[[:space:]]*$' "$historical_corpus" || \
  fail "docs/reports/CORPUS_REPORT.md must be explicitly labeled as historical v0.1.2 evidence"

policy="$doc_root/docs/RELEASE_POLICY.md"
required_policy_lines=(
  "current_round: 9"
  "current_source_version: $current_release_version"
  "current_formal_tag_reserved: v$current_release_version"
  "current_version_alias_policy: reject-v$current_release_version.0"
  "current_candidate_tag: v$current_release_version-rc.3"
  "current_candidate_status: DEVELOPMENT_IN_PROGRESS_HOST_AND_INDEPENDENT_EVIDENCE_NOT_PROVIDED"
  "current_platform: linux-amd64"
  "current_go_contract: 1.26.4"
  "current_cpa_version: v7.2.95"
  "current_cpa_commit: f71ec0eb6776854457892452cf28c47f0d658251"
  "current_gate_workflow: .github/workflows/round9-gate.yml"
  "current_host_workflow: .github/workflows/round9-host-validation.yml"
  "current_rc_workflow: .github/workflows/round9-release-rc.yml"
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
  "current_round9_gate_admission: workflow=Round 9 policy gate,path=.github/workflows/round9-gate.yml,event=push,branch=main,exact-commit,completed-success"
  "current_historical_workflow_disable_requirement: 315644586:release-rc.yml=disabled_manually,318443961:round8-host-validation.yml=disabled_manually"
  "current_public_adversarial_corpus: round9-public-adversarial-v11"
  "current_public_adversarial_manifest_schema: round9-public-adversarial-corpus/v11"
  "current_public_adversarial_machine_report_schema: round9-public-adversarial-report/v11"
  "current_public_adversarial_counts: payloads-24_formal-unique-23_historical-8_branch-head-1_prompt-like-14_unmerged-carriers-1_nondefault-branches-5_release-assets-16_release-assets-with-prompt-entries-4_release-asset-metadata-records-199_executed-1_not-provided-0_scenario-payloads-24_serialized-routes-120_direct-blocked-12_direct-allowed-12"
  "current_public_adversarial_manifest_bytes: 476165"
  "current_public_adversarial_manifest_sha256: 297c01072eb8bea3c6102b957c741722e621860c1116b65450b68a8704e75038"
  "current_public_counted_mock_matrix: unique-10_routes-120_audit-allow-40_enforcement-block-80_upstream-40_usage-40"
  "current_development_paired_recall_requirement: aggregate-and-each-category-exactly-10000-basis-points"
  "current_independent_malicious_recall_requirement: aggregate-and-each-category-at-least-9500-basis-points"
  "current_release_kind: private-candidate-only-public-prerelease-blocked"
  "current_release_latest: false"
  "current_legacy_verifier_identity_contract: release-object,tag=v$current_release_version-rc.3,annotated-tag-target=exact-commit,target-commitish=exact-commit,title=exact,body=exact,prerelease=true,latest=false,draft=false,immutable=true"
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

required_public_v11_policy_markers=(
  "The current public adversarial corpus is development-only v11 evidence under"
  "The original v8 manifest remains frozen"
  "The rejected attempt to rebind corrected bytes to the same v8 identity"
  "The disabled legacy verifier documents the prospective signer split"
  'Admission rejects any existing `v0.16-rc.3`'
  'either creates a fresh private 17-asset candidate after all admission checks or'
  'The Host result is necessary evaluation evidence, but it is not sufficient'
  'Release title/body text such as `independent audit required` is also not evidence'
  'Before any public writer may be restored, an independent authority must provide'
  'The verifier does not create, sign, repair, or infer any of those external records.'
)
for marker in "${required_public_v11_policy_markers[@]}"; do
  grep -Fq "$marker" "$policy" || \
    fail "docs/RELEASE_POLICY.md is missing the active public-v11/release-attestation contract: $marker"
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
if ! python3 -B - "$round8_readiness" <<'PY'
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
