#!/usr/bin/env bash
set -euo pipefail

root="$(cd "${BASH_SOURCE[0]%/*}/.." && pwd -P)"
# shellcheck source=release-common.sh
source "$root/scripts/release-common.sh"
release_require_commands awk basename dirname jq sha256sum sort uniq wc

attestation="${1:-}"
if (($# != 1)); then
  release_die "usage: verify-external-release-attestation.sh ATTESTATION"
fi
checksum="${attestation}.sha256"
pinned_cpa_version='v7.2.95'
pinned_cpa_commit='f71ec0eb6776854457892452cf28c47f0d658251'

require_identity() {
  local name="$1"
  local pattern="$2"
  local value="${!name:-}"
  [[ "$value" =~ $pattern ]] || \
    release_die "$name is missing or has an invalid release identity"
}

require_identity EXPECTED_TAG '^v0\.15-dev\.round6([.][0-9]+)?$'
require_identity EXPECTED_COMMIT '^[0-9a-f]{40}$'
require_identity EXPECTED_TREE '^[0-9a-f]{40}$'
require_identity CANDIDATE_RUN_ID '^[1-9][0-9]*$'
require_identity EXPECTED_SO_SHA256 '^[0-9a-f]{64}$'
require_identity EXPECTED_STORE_ZIP_SHA256 '^[0-9a-f]{64}$'

[[ -f "$attestation" && ! -L "$attestation" ]] || \
  release_die "external release attestation must be a regular non-symlink file"
[[ -f "$checksum" && ! -L "$checksum" ]] || \
  release_die "external release attestation checksum must be a regular non-symlink file"

attestation_name="$(basename -- "$attestation")"
checksum_name="$(basename -- "$checksum")"
[[ "$attestation_name" == round6-prerelease-attestation.json ]] || \
  release_die "external release attestation has an unexpected filename"
[[ "$checksum_name" == round6-prerelease-attestation.json.sha256 ]] || \
  release_die "external release attestation checksum has an unexpected filename"
[[ "$(cd "$(dirname -- "$attestation")" && pwd -P)" == \
  "$(cd "$(dirname -- "$checksum")" && pwd -P)" ]] || \
  release_die "external release attestation and checksum must share one directory"

attestation_size="$(wc -c <"$attestation")"
checksum_size="$(wc -c <"$checksum")"
[[ "$attestation_size" =~ ^[0-9]+$ ]] && ((attestation_size > 0 && attestation_size <= 131072)) || \
  release_die "external release attestation exceeds the bounded JSON size"
[[ "$checksum_size" =~ ^[0-9]+$ ]] && ((checksum_size > 0 && checksum_size <= 256)) || \
  release_die "external release attestation checksum exceeds the bounded sidecar size"

expected_attestation_sha256="$(awk -v target="$attestation_name" '
  NF != 2 || length($1) != 64 || $1 !~ /^[0-9a-f]+$/ || $2 != target {
    invalid = 1
  }
  { hash = $1 }
  END {
    if (invalid || NR != 1) exit 1
    print hash
  }
' "$checksum")" || release_die "external release attestation checksum sidecar is invalid"

actual_attestation_sha256="$(sha256sum "$attestation" | awk '{print $1}')"
[[ "$actual_attestation_sha256" == "$expected_attestation_sha256" ]] || \
  release_die "external release attestation checksum does not match"

jq -e -s 'length == 1' "$attestation" >/dev/null || \
  release_die "external release attestation must contain exactly one JSON value"

duplicate_paths="$(
  jq --stream -r 'select(length == 2) | .[0] | @json' "$attestation" | \
    sort | uniq -d
)" || release_die "external release attestation duplicate-key scan failed"
[[ -z "$duplicate_paths" ]] || \
  release_die "external release attestation contains duplicate JSON keys"

jq -e \
  --arg tag "$EXPECTED_TAG" \
  --arg commit "$EXPECTED_COMMIT" \
  --arg tree "$EXPECTED_TREE" \
  --arg candidate_run_id "$CANDIDATE_RUN_ID" \
  --arg so_sha256 "$EXPECTED_SO_SHA256" \
  --arg store_zip_sha256 "$EXPECTED_STORE_ZIP_SHA256" \
  --arg cpa_version "$pinned_cpa_version" \
  --arg cpa_commit "$pinned_cpa_commit" '
  def exact_keys($expected):
    type == "object" and keys == ($expected | sort);
  def sha256:
    type == "string" and test("^[0-9a-f]{64}$");
  def safe_positive_integer:
    type == "number" and . >= 1 and . <= 9007199254740991 and floor == .;
  def independent_evaluation_v11_or_later:
    type == "string" and
    test("^evaluation-v(1[1-9]|[2-9][0-9]|[1-9][0-9]{2,})$");

  exact_keys([
    "schema_version", "status", "version", "tag", "commit", "tree",
    "ci_run_id", "candidate_run_id", "artifacts", "evidence", "workflow"
  ]) and
  .schema_version == 2 and
  .status == "HOST_AUDIT_AND_EVALUATION_PASS / FORMAL_RELEASE_BLOCKED" and
  .version == "0.15" and
  .tag == $tag and
  .commit == $commit and
  .tree == $tree and
  (.ci_run_id | safe_positive_integer) and
  (.candidate_run_id | safe_positive_integer and tostring == $candidate_run_id) and
  (.artifacts | exact_keys(["so_sha256", "store_zip_sha256"])) and
  (.artifacts.so_sha256 | sha256 and . == $so_sha256) and
  (.artifacts.store_zip_sha256 | sha256 and . == $store_zip_sha256) and
  (.evidence | exact_keys([
    "cpa_version",
    "cpa_commit",
    "cpa_host_sha256",
    "independent_audit_sha256",
    "independent_evaluation_id",
    "independent_evaluation_status",
    "independent_evaluation_sha256"
  ])) and
  .evidence.cpa_version == $cpa_version and
  .evidence.cpa_commit == $cpa_commit and
  (.evidence.cpa_host_sha256 | sha256) and
  (.evidence.independent_audit_sha256 | sha256) and
  (.evidence.independent_evaluation_id | independent_evaluation_v11_or_later) and
  .evidence.independent_evaluation_status == "CONSUMED / PASS" and
  (.evidence.independent_evaluation_sha256 | sha256) and
  (.workflow | exact_keys([
    "repository", "ref", "sha", "run_id", "run_attempt"
  ])) and
  .workflow.repository == "yujianwudi/cyber-abuse-guard" and
  .workflow.ref == (
    "yujianwudi/cyber-abuse-guard/.github/workflows/attested-prerelease.yml@refs/tags/" + $tag
  ) and
  .workflow.sha == $commit and
  (.workflow.run_id | safe_positive_integer) and
  (.workflow.run_attempt | safe_positive_integer)
' "$attestation" >/dev/null || \
  release_die "external release attestation does not satisfy the Round6 candidate gate"

final_attestation_sha256="$(sha256sum "$attestation" | awk '{print $1}')"
[[ "$final_attestation_sha256" == "$actual_attestation_sha256" ]] || \
  release_die "external release attestation changed during verification"

printf 'external release attestation verified: tag=%s commit=%s cpa=%s@%s evaluation=%s\n' \
  "$EXPECTED_TAG" "$EXPECTED_COMMIT" "$pinned_cpa_version" "$pinned_cpa_commit" \
  "$(jq -r '.evidence.independent_evaluation_id' "$attestation")"
