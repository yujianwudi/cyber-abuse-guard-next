#!/usr/bin/env bash
set -euo pipefail

root="$(cd "${BASH_SOURCE[0]%/*}/.." && pwd -P)"
# shellcheck source=release-common.sh
source "$root/scripts/release-common.sh"
release_require_commands make git jq sha256sum awk cmp mktemp mv rm chmod mkdir \
  install find touch zip unzip tar grep wc stat python3

rc_release_lane="${RC_RELEASE_LANE:-round8}"
case "$rc_release_lane" in
  round8) canonical_repository='yujianwudi/cyber-abuse-guard' ;;
  round9) canonical_repository='yujianwudi/cyber-abuse-guard-next' ;;
  *) release_die "RC release assets require a reviewed lane identity" ;;
esac

[[ "${GITHUB_ACTIONS:-false}" == true ]] || \
  release_die "RC release assets may only be produced by GitHub Actions"
[[ "${GITHUB_EVENT_NAME:-}" == workflow_dispatch ]] || \
  release_die "RC release assets require the dedicated manual workflow"
[[ "${GITHUB_REPOSITORY:-}" == "$canonical_repository" ]] || \
  release_die "RC release assets require the canonical repository"
[[ "${GITHUB_RUN_ID:-}" =~ ^[1-9][0-9]*$ ]] || \
  release_die "RC release assets require a numeric GitHub run ID"
[[ "${GITHUB_RUN_ATTEMPT:-}" =~ ^[1-9][0-9]*$ ]] || \
  release_die "RC release assets require a numeric GitHub run attempt"
[[ "${RC_CI_RUN_ID:-}" =~ ^[1-9][0-9]*$ ]] || \
  release_die "RC release assets require the admitted exact-main CI run ID"
[[ "${RC_CI_RUN_ATTEMPT:-}" =~ ^[1-9][0-9]*$ ]] || \
  release_die "RC release assets require the admitted exact-main CI run attempt"
runner_name_reproducible='UNRECORDED_EPHEMERAL_GITHUB_HOSTED_RUNNER'
workflow_run_reproducible='UNRECORDED_EPHEMERAL_GITHUB_ACTIONS_RUN'
workflow_attempt_reproducible='UNRECORDED_EPHEMERAL_GITHUB_ACTIONS_ATTEMPT'
runner_image_unobservable='UNOBSERVABLE_FROM_PINNED_JOB_CONTAINER'
host_evidence=''
host_evidence_sidecar=''
external_evaluation=''
external_ledger_proof=''
case "$rc_release_lane" in
  round8)
    rc_workflow_path='.github/workflows/release-rc.yml'
    host_evidence='round8-host-evidence.json'
    host_evidence_sidecar='round8-host-evidence.json.sha256'
    rc_manifest_schema=4
    ;;
  round9)
    rc_workflow_path='.github/workflows/round9-release-rc.yml'
    external_evaluation='round9-external-evaluation.json'
    external_ledger_proof='round9-external-ledger-proof.json'
    rc_manifest_schema=6
    ;;
  *)
    release_die "RC_RELEASE_LANE must be exactly round8 or round9"
    ;;
esac
[[ "${RC_RUNNER_LABEL:-}" == ubuntu-24.04 ]] || \
  release_die "RC release assets require the exact ubuntu-24.04 build runner label"
[[ "${RC_RUNNER_OS:-}" == Linux ]] || \
  release_die "RC release assets require build runner OS Linux"
[[ "${RC_RUNNER_ARCH:-}" == X64 ]] || \
  release_die "RC release assets require build runner architecture X64"
[[ "${RC_RUNNER_ENVIRONMENT:-}" == github-hosted ]] || \
  release_die "RC release assets require the GitHub-hosted build runner environment"
runner_name="${RC_RUNNER_NAME:-}"
[[ "$runner_name" == "$runner_name_reproducible" ]] || \
  release_die "RC release assets require the reproducible ephemeral-runner sentinel"
[[ "${RC_RUNNER_IMAGE_OS:-}" == "$runner_image_unobservable" && \
  "${RC_RUNNER_IMAGE_VERSION:-}" == "$runner_image_unobservable" ]] || \
  release_die "RC release assets must disclose that host runner image identity is unobservable from the pinned job container"

release_init
release_assert_tag
release_assert_rc_build
case "$rc_release_lane" in
  round8) [[ "$RELEASE_RC_TAG" == v0.16-rc.2 ]] || release_die "Round 8 RC lane requires v0.16-rc.2" ;;
  round9) [[ "$RELEASE_RC_TAG" == v0.16-rc.3 ]] || release_die "Round 9 RC lane requires v0.16-rc.3" ;;
esac
release_rc_tag_object="$(git -C "$root" rev-parse "$RELEASE_RC_TAG^{tag}")"
[[ "$release_rc_tag_object" =~ ^[0-9a-f]{40}$ ]] || \
  release_die "RC release requires the exact annotated source tag object"
[[ "${GITHUB_REF:-}" == "refs/tags/$RELEASE_RC_TAG" ]] || \
  release_die "RC release assets require the exact annotated tag ref"
[[ "${GITHUB_SHA:-}" == "$RELEASE_GIT_COMMIT" ]] || \
  release_die "GitHub dispatch SHA does not match the RC commit"
[[ "${RELEASE_RC_WORKFLOW_SHA:-}" == "$RELEASE_GIT_COMMIT" ]] || \
  release_die "RC workflow source SHA does not match the RC commit"
[[ "${GITHUB_WORKFLOW_REF:-}" == \
  "${GITHUB_REPOSITORY}/${rc_workflow_path}@refs/tags/$RELEASE_RC_TAG" ]] || \
  release_die "RC assets require the pinned lane-specific workflow ref"

export RELEASE_RC_BUILD RELEASE_RC_TAG RELEASE_RC_EXPECTED_COMMIT RELEASE_RC_EXPECTED_TREE
export ROUND6_SAFE_SPARSE_BUILD=1
export REQUIRE_DIST_ARTIFACTS=1

dist="$root/dist"
so="cyber-abuse-guard-v${RELEASE_ARTIFACT_VERSION}.so"
store_zip="cyber-abuse-guard_${RELEASE_ARTIFACT_VERSION}_linux_amd64.zip"
audit_bundle="cyber-abuse-guard-v${RELEASE_ARTIFACT_VERSION}-audit-bundle.zip"
source_archive="cyber-abuse-guard-v${RELEASE_ARTIFACT_VERSION}-source.tar.gz"
test_summary="rc-release-test-summary.txt"
rc_evidence="rc-release-evidence.md"
publish_rc_release="${RC_PUBLISH_RELEASE:-false}"
host_evidence_input="${RC_HOST_EVIDENCE_INPUT:-}"
host_evidence_sidecar_input="${RC_HOST_EVIDENCE_SIDECAR_INPUT:-}"
round9_development_evidence_input="${RC_ROUND9_DEVELOPMENT_EVIDENCE_INPUT:-}"
external_evaluation_input="${RC_EXTERNAL_EVALUATION_INPUT:-}"
external_ledger_proof_input="${RC_EXTERNAL_LEDGER_PROOF_INPUT:-}"
external_evaluator_public_key="${RC_EXTERNAL_EVALUATOR_PUBLIC_KEY:-}"
external_evaluator_public_key_sha256="${RC_EXTERNAL_EVALUATOR_PUBLIC_KEY_SHA256:-}"
external_evaluator_key_id="${RC_EXTERNAL_EVALUATOR_KEY_ID:-}"
external_evaluator_sha256="${RC_EXTERNAL_EVALUATOR_SHA256:-}"
external_ledger_ruleset_id="${RC_EXTERNAL_LEDGER_RULESET_ID:-}"
external_ledger_ruleset_name="${RC_EXTERNAL_LEDGER_RULESET_NAME:-}"
external_host_run_id="${RC_EXTERNAL_HOST_RUN_ID:-}"
external_host_run_attempt="${RC_EXTERNAL_HOST_RUN_ATTEMPT:-}"
external_challenge="${RC_EXTERNAL_CHALLENGE:-}"
export TZ=UTC
if [[ "$rc_release_lane" == round9 ]]; then
  [[ -s "$round9_development_evidence_input" && ! -L "$round9_development_evidence_input" ]] || \
    release_die "Round 9 packaging requires a regular non-empty development evidence input"
  [[ "$(stat -c %s "$round9_development_evidence_input")" -le 1048576 ]] || \
    release_die "Round 9 development evidence input exceeds the reviewed size bound"
fi
case "$publish_rc_release" in
  true)
    if [[ "$rc_release_lane" == round9 ]]; then
      [[ -z "$host_evidence_input" && -z "$host_evidence_sidecar_input" ]] || \
        release_die "Round 9 publication consumes signed external evaluation, not legacy Host evidence inputs"
      [[ -f "$external_evaluation_input" && ! -L "$external_evaluation_input" ]] || \
        release_die "Round 9 publication requires a regular signed external evaluation envelope"
      [[ -f "$external_ledger_proof_input" && ! -L "$external_ledger_proof_input" ]] || \
        release_die "Round 9 publication requires a regular protected-ledger proof"
      [[ -f "$external_evaluator_public_key" && ! -L "$external_evaluator_public_key" ]] || \
        release_die "Round 9 publication requires the regular evaluator public-key file"
      [[ "$external_evaluator_public_key_sha256" =~ ^[0-9a-f]{64}$ ]] || \
        release_die "Round 9 evaluator public-key SHA-256 is invalid"
      [[ "$external_evaluator_key_id" =~ ^[A-Za-z0-9][A-Za-z0-9_.:-]{2,127}$ ]] || \
        release_die "Round 9 evaluator key ID is invalid"
      [[ "$external_evaluator_sha256" =~ ^[0-9a-f]{64}$ ]] || \
        release_die "Round 9 evaluator SHA-256 is invalid"
      [[ "$external_ledger_ruleset_id" =~ ^[1-9][0-9]*$ ]] || \
        release_die "Round 9 ledger ruleset ID is invalid"
      [[ "$external_ledger_ruleset_name" =~ ^[A-Za-z0-9][A-Za-z0-9_.:-]{2,127}$ ]] || \
        release_die "Round 9 ledger ruleset name is invalid"
      [[ "$external_host_run_id" =~ ^[1-9][0-9]*$ && "$external_host_run_attempt" =~ ^[1-9][0-9]*$ ]] || \
        release_die "Round 9 external Host workflow identity is invalid"
      [[ "$external_challenge" =~ ^[0-9a-f]{64}$ ]] || \
        release_die "Round 9 external evaluation challenge is invalid"
      [[ "$(hash_file "$external_evaluator_public_key")" == "$external_evaluator_public_key_sha256" ]] || \
        release_die "Round 9 evaluator public-key fingerprint differs"
    else
      [[ -f "$host_evidence_input" && ! -L "$host_evidence_input" ]] || \
        release_die "publication-stage RC requires a regular Host evidence JSON"
      [[ -f "$host_evidence_sidecar_input" && ! -L "$host_evidence_sidecar_input" ]] || \
        release_die "publication-stage RC requires a regular Host evidence SHA-256 sidecar"
    fi
    ;;
  false)
    [[ -z "$host_evidence_input" || ! -e "$host_evidence_input" ]] || \
      release_die "private Host-test candidate must not receive Host evidence"
    [[ -z "$host_evidence_sidecar_input" || ! -e "$host_evidence_sidecar_input" ]] || \
      release_die "private Host-test candidate must not receive a Host evidence sidecar"
    [[ -z "$external_evaluation_input" || ! -e "$external_evaluation_input" ]] || \
      release_die "private Host-test candidate must not receive external evaluation evidence"
    [[ -z "$external_ledger_proof_input" || ! -e "$external_ledger_proof_input" ]] || \
      release_die "private Host-test candidate must not receive an external ledger proof"
    ;;
  *)
    release_die "RC_PUBLISH_RELEASE must be exactly true or false"
    ;;
esac

validate_round8_host_evidence() {
  local evidence_path="$1"
  local sidecar_path="$2"
  local candidate_so_path="${3:-}"
  local evidence_sha expected_sidecar
  [[ -f "$evidence_path" && ! -L "$evidence_path" ]] || \
    release_die "Host evidence must be a regular non-symlink file"
  [[ -f "$sidecar_path" && ! -L "$sidecar_path" ]] || \
    release_die "Host evidence sidecar must be a regular non-symlink file"
  evidence_sha="$(sha256sum "$evidence_path" | awk '{print $1}')"
  expected_sidecar="$evidence_sha  $host_evidence"
  [[ "$(<"$sidecar_path")" == "$expected_sidecar" ]] || \
    release_die "Host evidence sidecar does not bind the exact evidence bytes"

  python3 -B - "$evidence_path" "$RELEASE_GIT_COMMIT" "$RELEASE_GIT_TREE" \
    "$candidate_so_path" <<'PY'
import hashlib
import json
import re
import sys
import uuid
from pathlib import Path

path = Path(sys.argv[1])
expected_commit = sys.argv[2]
expected_tree = sys.argv[3]
candidate_so_path = Path(sys.argv[4]) if sys.argv[4] else None

def reject_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result

def strict_json_equal(actual, expected):
    if type(actual) is not type(expected):
        return False
    if isinstance(expected, dict):
        return set(actual) == set(expected) and all(
            strict_json_equal(actual[key], value)
            for key, value in expected.items()
        )
    if isinstance(expected, list):
        return len(actual) == len(expected) and all(
            strict_json_equal(left, right)
            for left, right in zip(actual, expected)
        )
    return actual == expected

raw = path.read_bytes()
if not 2 <= len(raw) <= 12288:
    raise SystemExit("Host evidence JSON must be between 2 and 12288 bytes")
try:
    evidence = json.loads(raw.decode("utf-8"), object_pairs_hook=reject_duplicates)
except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
    raise SystemExit(f"invalid Host evidence JSON: {exc}") from exc
canonical = json.dumps(
    evidence,
    ensure_ascii=False,
    sort_keys=True,
    separators=(",", ":"),
).encode("utf-8")
if raw != canonical:
    raise SystemExit("Host evidence JSON must be canonical UTF-8 without trailing bytes")

expected_host_results = {
    "protocol_requests": {
        "chat_benign_upstream": 1,
        "chat_malicious_upstream": 0,
        "responses_benign_upstream": 1,
        "responses_malicious_upstream": 0,
    },
    "matrix": {
        "benign_total": 42,
        "benign_passed": 42,
        "paired_malicious_total": 42,
        "paired_malicious_blocked": 42,
    },
    "transports": {
        "nonstream_passed": True,
        "stream_passed": True,
    },
    "modes": {
        "audit_passed": True,
        "balanced_passed": True,
        "strict_passed": True,
    },
    "policy_outcomes": {
        "balanced_incomplete_allow": True,
        "strict_incomplete_block": True,
        "usage_queue_allow_delta": 1,
        "usage_queue_blocked_zero": True,
    },
    "database": {
        "quick_check": "ok",
        "schema_version": 5,
        "migration_versions": [1, 2, 3, 4, 5],
        "wal_checkpoint_passed": True,
    },
    "raw_capture": {
        "only_blocked_passed": True,
        "ttl_dedup_passed": True,
        "schema_v3_redaction_metadata_passed": True,
        "purge_wal_passed": True,
    },
    "lifecycle": {
        "restart_cycle_passed": True,
        "unexpected_restart_count": 0,
        "oom": False,
        "panic_count": 0,
        "fatal_count": 0,
        "plugin_error_count": 0,
    },
}
mock = evidence.get("mock") if isinstance(evidence, dict) else None
if (
    not isinstance(mock, dict)
    or set(mock) != {"contract", "source", "revision", "tag", "tree", "image_id"}
    or mock.get("contract") != "round8-counted-mock/v1"
    or mock.get("source") != "https://github.com/yujianwudi/cyber-abuse-guard-next"
    or mock.get("revision") != expected_commit
    or mock.get("tag") != "v0.16-rc.2"
    or mock.get("tree") != expected_tree
    or not isinstance(mock.get("image_id"), str)
    or re.fullmatch(r"sha256:[0-9a-f]{64}", mock["image_id"]) is None
):
    raise SystemExit("Host evidence counted-Mock identity is invalid")

cpa = evidence.get("cpa") if isinstance(evidence, dict) else None
if not isinstance(cpa, dict) or set(cpa) != {"primary"}:
    raise SystemExit("Host evidence CPA identity section is invalid")
rfc3339 = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]+)?(?:Z|[+-][0-9]{2}:[0-9]{2})"
)
cpa_identities = {}
for lane, version, revision in (
    ("primary", "v7.2.95", "f71ec0eb6776854457892452cf28c47f0d658251"),
):
    entry = cpa.get(lane)
    if (
        not isinstance(entry, dict)
        or set(entry)
        != {
            "version",
            "commit",
            "image_id",
            "build_date",
            "counted_mock_validation",
            "host_results",
        }
        or entry.get("version") != version
        or entry.get("commit") != revision
        or not isinstance(entry.get("image_id"), str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", entry["image_id"]) is None
        or not isinstance(entry.get("build_date"), str)
        or rfc3339.fullmatch(entry["build_date"]) is None
    ):
        raise SystemExit(f"Host evidence {lane} CPA image identity is invalid")
    cpa_identities[lane] = {
        "image_id": entry["image_id"],
        "build_date": entry["build_date"],
    }

execution = evidence.get("execution") if isinstance(evidence, dict) else None
if not isinstance(execution, dict) or set(execution) != {
    "trust", "challenge", "execution_id", "started_at", "completed_at",
    "workflow", "phase1", "runner", "sandbox",
}:
    raise SystemExit("Host evidence execution binding schema is invalid")
if (
    execution.get("trust") != "GITHUB_ATTESTED_ROUND8_HOST_WORKFLOW"
    or not isinstance(execution.get("challenge"), str)
    or re.fullmatch(r"[0-9a-f]{64}", execution["challenge"]) is None
    or not isinstance(execution.get("execution_id"), str)
):
    raise SystemExit("Host evidence execution identity is invalid")
try:
    uuid.UUID(execution["execution_id"])
except (ValueError, AttributeError) as exc:
    raise SystemExit("Host evidence execution ID is invalid") from exc
if any(
    not isinstance(execution.get(field), str) or rfc3339.fullmatch(execution[field]) is None
    for field in ("started_at", "completed_at")
) or execution["completed_at"] < execution["started_at"]:
    raise SystemExit("Host evidence execution timestamps are invalid")
workflow = execution.get("workflow")
if (
    not isinstance(workflow, dict)
    or set(workflow) != {
        "repository", "path", "ref", "sha", "run_id", "run_attempt",
    }
    or workflow.get("repository") != "yujianwudi/cyber-abuse-guard"
    or workflow.get("path") != ".github/workflows/round8-host-validation.yml"
    or workflow.get("ref") != "refs/tags/v0.16-rc.2"
    or workflow.get("sha") != expected_commit
    or type(workflow.get("run_id")) is not int or workflow["run_id"] <= 0
    or type(workflow.get("run_attempt")) is not int or workflow["run_attempt"] <= 0
):
    raise SystemExit("Host evidence signer workflow binding is invalid")
phase1 = execution.get("phase1")
if (
    not isinstance(phase1, dict)
    or set(phase1) != {
        "workflow_path", "run_id", "run_attempt", "artifact_id", "artifact_digest",
    }
    or phase1.get("workflow_path") != ".github/workflows/release-rc.yml"
    or any(type(phase1.get(field)) is not int or phase1[field] <= 0 for field in ("run_id", "run_attempt", "artifact_id"))
    or not isinstance(phase1.get("artifact_digest"), str)
    or re.fullmatch(r"sha256:[0-9a-f]{64}", phase1["artifact_digest"]) is None
):
    raise SystemExit("Host evidence Phase 1 binding is invalid")
runner = execution.get("runner")
if (
    not isinstance(runner, dict)
    or set(runner) != {"name", "environment", "os", "arch"}
    or runner.get("environment") != "self-hosted"
    or runner.get("os") != "Linux" or runner.get("arch") != "X64"
    or not isinstance(runner.get("name"), str) or not 1 <= len(runner["name"]) <= 128
):
    raise SystemExit("Host evidence runner binding is invalid")
sandbox = execution.get("sandbox")
sandbox_id = sandbox.get("sandbox_id") if isinstance(sandbox, dict) else None
if (
    not isinstance(sandbox, dict)
    or set(sandbox) != {
        "sandbox_id", "daemon_id", "daemon_label", "production_label",
        "probe_image_id", "locality_challenge",
    }
    or not isinstance(sandbox_id, str)
    or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{7,127}", sandbox_id) is None
    or sandbox.get("daemon_label") != f"io.cyber-abuse-guard.round8-sandbox={sandbox_id}"
    or sandbox.get("production_label") != "io.cyber-abuse-guard.production=false"
    or not isinstance(sandbox.get("daemon_id"), str)
    or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{7,127}", sandbox["daemon_id"]) is None
    or not isinstance(sandbox.get("probe_image_id"), str)
    or re.fullmatch(r"sha256:[0-9a-f]{64}", sandbox["probe_image_id"]) is None
    or sandbox.get("locality_challenge") != "PASS"
):
    raise SystemExit("Host evidence protected sandbox binding is invalid")

expected = {
    "schema_version": 2,
    "validation_scope": "CPA_HOST_COUNTED_MOCK_ONLY",
    "candidate": {
        "tag": "v0.16-rc.2",
        "commit": expected_commit,
        "tree": expected_tree,
        "platform": "linux/amd64",
        "so_name": "cyber-abuse-guard-v0.16-rc.2.so",
    },
    "cpa": {
        "primary": {
            "version": "v7.2.95",
            "commit": "f71ec0eb6776854457892452cf28c47f0d658251",
            "image_id": cpa_identities["primary"]["image_id"],
            "build_date": cpa_identities["primary"]["build_date"],
            "counted_mock_validation": "PASS",
            "host_results": expected_host_results,
        },
    },
    "mock": {
        "contract": "round8-counted-mock/v1",
        "source": "https://github.com/yujianwudi/cyber-abuse-guard-next",
        "revision": expected_commit,
        "tag": "v0.16-rc.2",
        "tree": expected_tree,
        "image_id": mock["image_id"],
    },
    "safety": {
        "real_provider_contacted": False,
        "production_accessed": False,
        "unexpected_restart_count": 0,
        "oom": False,
        "panic_count": 0,
        "fatal_count": 0,
        "plugin_error_count": 0,
    },
    "execution": execution,
}
if not isinstance(evidence, dict) or set(evidence) != set(expected):
    raise SystemExit("Host evidence top-level schema is not exact")
candidate = evidence.get("candidate")
if not isinstance(candidate, dict) or set(candidate) != set(expected["candidate"]) | {"so_sha256"}:
    raise SystemExit("Host evidence candidate schema is not exact")
so_sha = candidate.get("so_sha256")
if not isinstance(so_sha, str) or re.fullmatch(r"[0-9a-f]{64}", so_sha) is None:
    raise SystemExit("Host evidence candidate SO SHA-256 is invalid")
candidate_without_sha = dict(candidate)
candidate_without_sha.pop("so_sha256")
if not strict_json_equal(candidate_without_sha, expected["candidate"]):
    raise SystemExit("Host evidence candidate identity does not match this release")
for section in ("cpa", "mock", "safety", "execution"):
    if not strict_json_equal(evidence.get(section), expected[section]):
        raise SystemExit(f"Host evidence {section} contract does not match")
if not strict_json_equal(evidence.get("schema_version"), 2) or not strict_json_equal(
    evidence.get("validation_scope"), expected["validation_scope"]
):
    raise SystemExit("Host evidence scope/version does not match")
if candidate_so_path is not None:
    actual_so_sha = hashlib.sha256(candidate_so_path.read_bytes()).hexdigest()
    if actual_so_sha != so_sha:
        raise SystemExit("Host evidence SO SHA-256 does not match the reproduced candidate")
PY
}

validate_lane_host_evidence() {
  [[ "$rc_release_lane" == round8 ]] || \
    release_die "legacy Host evidence validation is available only to the immutable Round 8 lane"
  validate_round8_host_evidence "$@"
}

validate_round9_development_evidence() {
  local evidence_path="$1"
  python3 -B "$root/scripts/round9_machine_reports.py" validate-development \
    --root "$root" \
    --input "$evidence_path" \
    --tag "$RELEASE_RC_TAG" \
    --commit "$RELEASE_GIT_COMMIT" \
    --tree "$RELEASE_GIT_TREE"
}

validate_round9_external_evaluation() {
  local evaluation_path="$1"
  local proof_path="$2"
  local candidate_so_path="$3"
  local output_dir="$4"
  local classifier_version classifier_sha256
  local evaluator_version evaluator_core_sha256 evaluator_broker_sha256
  local sandbox_adapter_sha256 sandbox_adapter_config_sha256 docker_sandbox_sha256
  local cpa_image_id counted_mock_image_id model release_manifest_sha256
  local phase1_run_id phase1_run_attempt phase1_artifact_id phase1_artifact_digest

  [[ -s "$evaluation_path" && ! -L "$evaluation_path" && "$(stat -c %s "$evaluation_path")" -le 1048576 ]] || \
    release_die "Round 9 signed external evaluation is empty, oversized, or non-regular"
  [[ -s "$proof_path" && ! -L "$proof_path" && "$(stat -c %s "$proof_path")" -le 1048576 ]] || \
    release_die "Round 9 external ledger proof is empty, oversized, or non-regular"
  [[ -f "$candidate_so_path" && ! -L "$candidate_so_path" ]] || \
    release_die "Round 9 external evaluation requires the reproduced candidate SO"
  [[ -f "$output_dir/ruleset-manifest.json" && ! -L "$output_dir/ruleset-manifest.json" ]] || \
    release_die "Round 9 external evaluation requires the reproduced ruleset manifest"
  [[ -f "$output_dir/build-metadata.json" && ! -L "$output_dir/build-metadata.json" ]] || \
    release_die "Round 9 external evaluation requires the reproduced build metadata"

  read -r classifier_version classifier_sha256 < <(
    python3 -B - "$root/internal/classifier/policy_identity.go" <<'PY'
import re
import sys

text = open(sys.argv[1], encoding="utf-8").read()
version = re.findall(r'^const ClassifierPolicyVersion = "([A-Za-z0-9._-]+)"$', text, re.MULTILINE)
digest = re.findall(r'^const ClassifierPolicySHA256 = "([0-9a-f]{64})"$', text, re.MULTILINE)
if len(version) != 1 or len(digest) != 1:
    raise SystemExit("classifier identity source is not exact")
print(version[0], digest[0])
PY
  )
  evaluator_version="$(jq -er '.payload.evaluator.version' "$evaluation_path")"
  evaluator_core_sha256="$(jq -er '.payload.evaluator.core_sha256' "$evaluation_path")"
  evaluator_broker_sha256="$(jq -er '.payload.evaluator.broker_sha256' "$evaluation_path")"
  sandbox_adapter_sha256="$(jq -er '.payload.execution.sandbox_adapter_sha256' "$evaluation_path")"
  sandbox_adapter_config_sha256="$(jq -er '.payload.execution.sandbox_adapter_config_sha256' "$evaluation_path")"
  docker_sandbox_sha256="$(jq -er '.payload.execution.docker_sandbox_sha256' "$evaluation_path")"
  cpa_image_id="$(jq -er '.payload.execution.cpa_image_id' "$evaluation_path")"
  counted_mock_image_id="$(jq -er '.payload.execution.counted_mock_image_id' "$evaluation_path")"
  model="$(jq -er '.payload.execution.model' "$evaluation_path")"
  release_manifest_sha256="$(jq -er '.payload.candidate.release_manifest_sha256' "$evaluation_path")"
  phase1_run_id="$(jq -er '.payload.candidate.phase1_run_id' "$evaluation_path")"
  phase1_run_attempt="$(jq -er '.payload.candidate.phase1_run_attempt' "$evaluation_path")"
  phase1_artifact_id="$(jq -er '.payload.candidate.phase1_artifact_id' "$evaluation_path")"
  phase1_artifact_digest="$(jq -er '.payload.candidate.phase1_artifact_digest' "$evaluation_path")"

  python3 -B "$root/scripts/round9_external_evaluation_contract.py" validate \
    --envelope "$evaluation_path" --proof "$proof_path" \
    --development-evidence "$round9_development_evidence_input" \
    --public-key "$external_evaluator_public_key" \
    --public-key-sha256 "$external_evaluator_public_key_sha256" \
    --key-id "$external_evaluator_key_id" --evaluator-version "$evaluator_version" \
    --evaluator-sha256 "$external_evaluator_sha256" \
    --core-sha256 "$evaluator_core_sha256" --broker-sha256 "$evaluator_broker_sha256" \
    --sandbox-adapter-sha256 "$sandbox_adapter_sha256" \
    --sandbox-adapter-config-sha256 "$sandbox_adapter_config_sha256" \
    --docker-sandbox-sha256 "$docker_sandbox_sha256" \
    --cpa-image-id "$cpa_image_id" --counted-mock-image-id "$counted_mock_image_id" \
    --model "$model" --repository "$GITHUB_REPOSITORY" --tag "$RELEASE_RC_TAG" \
    --tag-object-sha "$release_rc_tag_object" --commit "$RELEASE_GIT_COMMIT" \
    --tree "$RELEASE_GIT_TREE" --so-sha256 "$(hash_file "$candidate_so_path")" \
    --classifier-policy-version "$classifier_version" \
    --classifier-policy-sha256 "$classifier_sha256" \
    --ruleset-version "$(jq -er '.ruleset_version' "$output_dir/ruleset-manifest.json")" \
    --ruleset-sha256 "$(jq -er '.ruleset_sha256' "$output_dir/ruleset-manifest.json")" \
    --ruleset-manifest-sha256 "$(hash_file "$output_dir/ruleset-manifest.json")" \
    --build-metadata-sha256 "$(hash_file "$output_dir/build-metadata.json")" \
    --release-manifest-sha256 "$release_manifest_sha256" \
    --phase1-run-id "$phase1_run_id" --phase1-run-attempt "$phase1_run_attempt" \
    --phase1-artifact-id "$phase1_artifact_id" \
    --phase1-artifact-digest "$phase1_artifact_digest" \
    --host-run-id "$external_host_run_id" --host-run-attempt "$external_host_run_attempt" \
    --challenge "$external_challenge"
}

if [[ "$rc_release_lane" == round9 ]]; then
  validate_round9_development_evidence "$round9_development_evidence_input"
fi

install_lane_publication_evidence() {
  local output_dir="$1"
  [[ "$publish_rc_release" == true ]] || return 0
  if [[ "$rc_release_lane" == round9 ]]; then
    validate_round9_external_evaluation "$external_evaluation_input" \
      "$external_ledger_proof_input" "$output_dir/$so" "$output_dir"
    install -m 0644 "$external_evaluation_input" "$output_dir/$external_evaluation"
    install -m 0644 "$external_ledger_proof_input" "$output_dir/$external_ledger_proof"
  else
    validate_lane_host_evidence "$host_evidence_input" "$host_evidence_sidecar_input" \
      "$output_dir/$so"
    install -m 0644 "$host_evidence_input" "$output_dir/$host_evidence"
    install -m 0644 "$host_evidence_sidecar_input" "$output_dir/$host_evidence_sidecar"
  fi
}

checksum_artifacts=(
  "$so"
  "$so.sha256"
  "$store_zip"
  "$audit_bundle"
  build-metadata.json
  ruleset-manifest.json
  ruleset.sha256
  sbom.cdx.json
)
core_artifacts=(
  "$so"
  "$so.sha256"
  "$store_zip"
  "$audit_bundle"
  build-metadata.json
  ruleset-manifest.json
  ruleset.sha256
  sbom.cdx.json
  checksums.txt
  "$source_archive"
  "$source_archive.sha256"
)
published_artifacts=(
  "$so"
  "$so.sha256"
  "$store_zip"
  "$audit_bundle"
  build-metadata.json
  checksums.txt
  ruleset-manifest.json
  ruleset.sha256
  sbom.cdx.json
  "$test_summary"
  "$test_summary.sha256"
  "$rc_evidence"
  "$rc_evidence.sha256"
  "$source_archive"
  "$source_archive.sha256"
  rc-release-manifest.json
  rc-release-manifest.json.sha256
)
if [[ "$publish_rc_release" == true ]]; then
  if [[ "$rc_release_lane" == round9 ]]; then
    checksum_artifacts+=("$external_evaluation" "$external_ledger_proof")
    core_artifacts+=("$external_evaluation" "$external_ledger_proof")
    published_artifacts+=("$external_evaluation" "$external_ledger_proof")
  else
    checksum_artifacts+=("$host_evidence" "$host_evidence_sidecar")
    core_artifacts+=("$host_evidence" "$host_evidence_sidecar")
    published_artifacts+=("$host_evidence" "$host_evidence_sidecar")
    validate_lane_host_evidence "$host_evidence_input" "$host_evidence_sidecar_input"
  fi
fi

assert_rc_sbom_identity() {
  local sbom_path="$1"
  local component_version="v$RELEASE_ARTIFACT_VERSION"
  local component_ref="pkg:golang/github.com/yujianwudi/cyber-abuse-guard-next@${component_version}?type=module"
  local component_purl="${component_ref}&goos=linux&goarch=amd64"

  jq -e \
    --arg version "$component_version" \
    --arg ref "$component_ref" \
    --arg purl "$component_purl" \
    '.metadata.component.name == "github.com/yujianwudi/cyber-abuse-guard-next" and
     .metadata.component.version == $version and
     .metadata.component["bom-ref"] == $ref and
     .metadata.component.purl == $purl and
     ([.dependencies[] | select(.ref == $ref)] | length) == 1' \
    "$sbom_path" >/dev/null || \
    release_die "RC SBOM does not bind the exact versioned main module identity: $sbom_path"
}

normalize_rc_sbom_identity() {
  local sbom_path="$1"
  local old_ref temporary
  local component_version="v$RELEASE_ARTIFACT_VERSION"
  local component_ref="pkg:golang/github.com/yujianwudi/cyber-abuse-guard-next@${component_version}?type=module"
  local component_purl="${component_ref}&goos=linux&goarch=amd64"

  old_ref="$(jq -er \
    '.metadata.component["bom-ref"] |
     select(type == "string" and length > 0)' "$sbom_path")" || \
    release_die "RC SBOM is missing its generated main component reference: $sbom_path"
  jq -e \
    --arg old_ref "$old_ref" \
    '.metadata.component.name == "github.com/yujianwudi/cyber-abuse-guard-next" and
     (.metadata.component.version | type == "string") and
     .metadata.component["bom-ref"] == $old_ref and
     ($old_ref | startswith("pkg:golang/github.com/yujianwudi/cyber-abuse-guard-next@")) and
     ($old_ref | endswith("?type=module")) and
     (.metadata.component.purl | type == "string") and
     (.metadata.component.purl |
       startswith("pkg:golang/github.com/yujianwudi/cyber-abuse-guard-next@")) and
     (.metadata.component.purl | contains("?type=module")) and
     ([.dependencies[] | select(.ref == $old_ref)] | length) == 1' \
    "$sbom_path" >/dev/null || \
    release_die "RC SBOM generated main component identity is ambiguous: $sbom_path"

  temporary="$(mktemp "${sbom_path%/*}/.sbom-rc-normalized.XXXXXX")"
  if ! jq \
    --arg version "$component_version" \
    --arg ref "$component_ref" \
    --arg purl "$component_purl" \
    '(.metadata.component["bom-ref"]) as $old_ref |
     .metadata.component.version = $version |
     .metadata.component["bom-ref"] = $ref |
     .metadata.component.purl = $purl |
     .dependencies |= map(
       (if .ref == $old_ref then .ref = $ref else . end) |
       (if has("dependsOn") then
          .dependsOn |= map(if . == $old_ref then $ref else . end)
        else . end)
     )' \
    "$sbom_path" >"$temporary"; then
    rm -f -- "$temporary"
    release_die "failed to normalize the exact RC SBOM identity: $sbom_path"
  fi
  chmod 0644 "$temporary"
  mv -f -- "$temporary" "$sbom_path"
  assert_rc_sbom_identity "$sbom_path"
}

write_rc_checksums() {
  local output_dir="$1"
  local temporary
  temporary="$(mktemp "$output_dir/.checksums.XXXXXX")"
  if ! (
    cd "$output_dir"
    sha256sum "${checksum_artifacts[@]}"
  ) >"$temporary"; then
    rm -f -- "$temporary"
    release_die "failed to regenerate checksums for the normalized RC artifacts"
  fi
  chmod 0644 "$temporary"
  mv -f -- "$temporary" "$output_dir/checksums.txt"
}

create_rc_audit_bundle() {
  local source_root="$1"
  local output_dir="$2"
  local stage expected actual verify_dir packaged_mode
  local bundled_metadata=(
    build-metadata.json
    ruleset-manifest.json
    ruleset.sha256
    sbom.cdx.json
  )
  local required_files=(
    README.md
    README_CN.md
    LICENSE
    SECURITY.md
    CHANGELOG.md
    THIRD_PARTY_NOTICES.md
    config.example.yaml
    docs/AUDIT_HANDOFF.md
    docs/RAW_CAPTURE.md
    docs/DESIGN.md
    docs/THREAT_MODEL.md
    docs/INSTALL_DOCKER.md
    docs/LIMITATIONS.md
    docs/README.md
    docs/archive/v0.1.2/NEXT_VERSION.md
    docs/RELEASE_POLICY.md
    docs/ROUND6_CONFIG_MIGRATION.md
    docs/ROUND6_DEVELOPMENT_HANDOFF.md
    docs/ROUND6_LIMITATIONS.md
    docs/ROUND6_RELEASE_GATE.md
    docs/ROUND6_STREAMING_SCANNER_DESIGN.md
    docs/ROUND8_HOST_RUNNER.md
    docs/RULES.md
    docs/reports/TEST_REPORT.md
    docs/reports/PERFORMANCE.md
    docs/reports/CORPUS_REPORT.md
    docs/reports/CPA_INTEGRATION.md
    docs/reports/PHASE0_CPA_CONTRACT.md
    docs/reports/PROMPT_INJECTION_REVIEW.md
    docs/reports/PRIVACY.md
    docs/reports/PUBLIC_JAILBREAK_REPOSITORY_REVIEW.md
    docs/reports/RELEASE_EVIDENCE.md
    docs/reports/ROUND8_CALIBRATION.md
    docs/reports/ROUND8_RELEASE_READINESS.md
    scripts/check-production-health.sh
    scripts/generate-hmac-key.sh
  )

  if [[ "$rc_release_lane" == round9 ]]; then
    required_files+=(
      docs/ROUND9_HOST_RUNNER.md
      docs/ROUND9_AUDIT_SCHEMA_V6.md
      docs/ROUND9_OPERATOR_ROLLOUT.md
      docs/reports/ROUND9_EXECUTION_RECORD.md
      testdata/round9-development-paired-malicious-v3/cases.jsonl
      testdata/round9-development-paired-malicious-v3/manifest.json
      testdata/round9-development-paired-malicious-v3/README.md
      testdata/round9-development-paired-malicious-v3/LABEL_AUDIT.md
      testdata/round9-development-paired-malicious-v3/LABEL_AUDIT_REJECTED_DRAFT1.md
    )
  fi

  if [[ "$publish_rc_release" == true ]]; then
    if [[ "$rc_release_lane" == round9 ]]; then
      bundled_metadata+=("$external_evaluation" "$external_ledger_proof")
    else
      bundled_metadata+=("$host_evidence" "$host_evidence_sidecar")
    fi
  fi

  for relative in "${required_files[@]}"; do
    [[ -f "$source_root/$relative" && ! -L "$source_root/$relative" ]] || \
      release_die "RC audit bundle input must be a regular non-symlink file: $source_root/$relative"
  done
  for relative in "$so" "$so.sha256" "${bundled_metadata[@]}"; do
    [[ -f "$output_dir/$relative" && ! -L "$output_dir/$relative" ]] || \
      release_die "RC audit bundle artifact must be a regular non-symlink file: $output_dir/$relative"
  done

  stage="$(mktemp -d)"
  mkdir -p "$stage/plugins/linux/amd64" "$stage/docs/archive/v0.1.2" \
    "$stage/docs/reports" "$stage/scripts"
  install -m 0755 "$output_dir/$so" "$stage/plugins/linux/amd64/$so"
  install -m 0644 "$output_dir/$so.sha256" \
    "$stage/plugins/linux/amd64/$so.sha256"

  for relative in "${required_files[@]}"; do
    if [[ "$relative" == */* ]]; then
      mkdir -p "$stage/${relative%/*}"
    fi
    if [[ "$relative" == scripts/* ]]; then
      install -m 0755 "$source_root/$relative" "$stage/$relative"
    else
      install -m 0644 "$source_root/$relative" "$stage/$relative"
    fi
  done
  install -m 0644 "$output_dir/build-metadata.json" \
    "$output_dir/ruleset-manifest.json" "$output_dir/ruleset.sha256" \
    "$output_dir/sbom.cdx.json" "$stage/"
  if [[ "$publish_rc_release" == true ]]; then
    if [[ "$rc_release_lane" == round9 ]]; then
      install -m 0644 "$output_dir/$external_evaluation" \
        "$output_dir/$external_ledger_proof" "$stage/"
    else
      install -m 0644 "$output_dir/$host_evidence" \
        "$output_dir/$host_evidence_sidecar" "$stage/"
    fi
  fi

  while IFS= read -r -d '' staged_path; do
    if [[ -d "$staged_path" ]]; then
      chmod 0755 "$staged_path"
    fi
    touch -h -d "@$RELEASE_SOURCE_DATE_EPOCH" "$staged_path"
  done < <(find "$stage" -print0)
  rm -f -- "$output_dir/$audit_bundle"
  (
    cd "$stage"
    find . -mindepth 1 -printf '%P\n' | LC_ALL=C sort | \
      zip -X -q "$output_dir/$audit_bundle" -@
  )
  expected="$(
    cd "$stage"
    while IFS= read -r -d '' staged_path; do
      relative="${staged_path#./}"
      if [[ -d "$staged_path" ]]; then
        printf '%s/\n' "$relative"
      else
        printf '%s\n' "$relative"
      fi
    done < <(find . -mindepth 1 -print0) | LC_ALL=C sort
  )"
  actual="$(unzip -Z1 "$output_dir/$audit_bundle" | LC_ALL=C sort)"
  [[ "$actual" == "$expected" ]] || \
    release_die "RC audit bundle content differs from its fixed allowlist"
  if unzip -Z -l "$output_dir/$audit_bundle" | awk '$1 ~ /^l/ { found = 1 } END { exit !found }'; then
    release_die "RC audit bundle contains a symbolic-link entry"
  fi
  verify_dir="$(mktemp -d)"
  (umask 000; unzip -q "$output_dir/$audit_bundle" -d "$verify_dir")
  while IFS= read -r -d '' packaged_dir; do
    [[ "$(stat -c '%a' "$packaged_dir")" == 755 ]] || \
      release_die "RC audit bundle directory mode must be 0755: $packaged_dir"
  done < <(find "$verify_dir" -mindepth 1 -type d -print0)
  [[ -f "$verify_dir/plugins/linux/amd64/$so" &&
    ! -L "$verify_dir/plugins/linux/amd64/$so" ]] || \
    release_die "RC audit bundle SO did not extract as a regular file"
  cmp -s "$output_dir/$so" "$verify_dir/plugins/linux/amd64/$so" || \
    release_die "RC audit bundle SO differs from the standalone artifact"
  [[ "$(stat -c '%a' "$verify_dir/plugins/linux/amd64/$so")" == 755 ]] || \
    release_die "RC audit bundle SO mode must be 0755"
  [[ "$(stat -c '%a' "$verify_dir/plugins/linux/amd64/$so.sha256")" == 644 ]] || \
    release_die "RC audit bundle SO checksum mode must be 0644"
  cmp -s "$output_dir/$so.sha256" \
    "$verify_dir/plugins/linux/amd64/$so.sha256" || \
    release_die "RC audit bundle SO checksum differs from the standalone sidecar"
  for relative in "${required_files[@]}"; do
    [[ -f "$verify_dir/$relative" && ! -L "$verify_dir/$relative" ]] || \
      release_die "RC audit bundle entry did not extract as a regular file: $relative"
    cmp -s "$source_root/$relative" "$verify_dir/$relative" || \
      release_die "RC audit bundle source entry differs from exact source: $relative"
    packaged_mode="$(stat -c '%a' "$verify_dir/$relative")"
    if [[ "$relative" == scripts/* ]]; then
      [[ "$packaged_mode" == 755 ]] || \
        release_die "RC audit bundle executable mode must be 0755: $relative"
    else
      [[ "$packaged_mode" == 644 ]] || \
        release_die "RC audit bundle document mode must be 0644: $relative"
    fi
  done
  for relative in "${bundled_metadata[@]}"; do
    [[ -f "$verify_dir/$relative" && ! -L "$verify_dir/$relative" ]] || \
      release_die "RC audit bundle metadata did not extract as a regular file: $relative"
    cmp -s "$output_dir/$relative" "$verify_dir/$relative" || \
      release_die "RC audit bundle metadata differs from standalone artifact: $relative"
    [[ "$(stat -c '%a' "$verify_dir/$relative")" == 644 ]] || \
      release_die "RC audit bundle metadata mode must be 0644: $relative"
  done
  rm -rf -- "$verify_dir"
  rm -rf -- "$stage"
}

create_rc_source_archive() {
  local source_root="$1"
  local output_dir="$2"
  local temporary listing restricted_listing verifier_sha verifier_test_sha
  local archive_prefix="cyber-abuse-guard-v${RELEASE_ARTIFACT_VERSION}/"
  local verifier_path='scripts/round9_external_evaluation_contract.py'
  local verifier_sha256='4c330ece27ce5e000f13ebc06bff6dbcaa2f18b5b62f73f940e78591051fae7e'
  local verifier_test_path='scripts/round9_external_evaluation_contract_test.py'
  local verifier_test_sha256='f42625714cb46b89a4bc32a1ec52c2352d6f9c67f5f782ea117d08e7650c43c9'
  local verifier_entry="${archive_prefix}${verifier_path}"
  local verifier_test_entry="${archive_prefix}${verifier_test_path}"
  local transient_path_pattern='(^|/)(classifier_(candidate|single)_[^/]*|[^/]*\.(cpu|mem|pprof|test\.exe|exe))($|/)'
  local test_binary_path_pattern='(^|/)[^/]*\.test($|/)'
  local safe_test_source_pattern='(^|/)Dockerfile\.test($|/)'
  local backup_binary_archive_path_pattern='(^|/)[^/]*\.(bak|backup|so|dll|zip|tar|tgz|gz)($|/)'
  local secret_key_path_pattern='(^|/)(id_(ed25519|ed25519_servers|rsa|dsa|ecdsa)(\.pub)?|[^/]*\.ppk)($|/)'
  local local_sandbox_path_pattern='(^|/)\.round9-local-sandbox($|/)'
  local archive_pathspecs=(
    .
    ':(exclude,glob).round9-local-sandbox/**'
    ':(exclude,glob,icase)cmd/**/*evaluation*'
    ':(exclude,glob,icase)cmd/**/*holdout*'
    ':(exclude,glob,icase)cmd/**/*consumed*'
    ':(exclude,glob,icase)cmd/**/*private*'
    ':(exclude,glob,icase)cmd/**/*blind*'
    ':(exclude,glob,icase)cmd/**/*retired*'
    ':(exclude,glob,icase)docs/**/*EVALUATION_*'
    ':(exclude,glob,icase)docs/**/*HOLDOUT_*'
    ':(exclude,glob,icase)docs/**/*HOLDOUT_REPORT.md'
    ':(exclude,glob,icase)docs/**/*consumed*'
    ':(exclude,glob,icase)docs/**/*private*'
    ':(exclude,glob,icase)docs/**/*blind*'
    ':(exclude,glob,icase)docs/**/*retired*'
    ':(exclude,glob,icase)internal/classifier/**/*evaluation*'
    ':(exclude,glob,icase)internal/classifier/**/*holdout*'
    ':(exclude,glob,icase)internal/classifier/**/*consumed*'
    ':(exclude,glob,icase)internal/classifier/**/*private*'
    ':(exclude,glob,icase)internal/classifier/**/*blind*'
    ':(exclude,glob,icase)internal/classifier/**/*retired*'
    ':(exclude,glob,icase)testdata/**/*evaluation*'
    ':(exclude,glob,icase)testdata/**/*holdout*'
    ':(exclude,glob)testdata/round9-independent-benign-v1/**'
    ':(exclude,glob)testdata/round9-independent-malicious-v1/**'
    ':(exclude,glob,icase)testdata/**/*consumed*'
    ':(exclude,glob,icase)testdata/**/*private*'
    ':(exclude,glob,icase)testdata/**/*blind*'
    ':(exclude,glob,icase)testdata/**/*retired*'
  )

  temporary="$(mktemp "$output_dir/.rc-source-release.XXXXXX")"
  git -C "$source_root" archive --format=tar.gz \
    --prefix="$archive_prefix" \
    --output="$temporary" "$RELEASE_GIT_COMMIT" -- "${archive_pathspecs[@]}"
  listing="$(tar -tzf "$temporary")"
  [[ -n "$listing" ]] || release_die "RC source archive is empty"
  if grep -Ev "^${archive_prefix}" <<<"$listing" >/dev/null; then
    rm -f -- "$temporary"
    release_die "RC source archive contains an entry outside its fixed prefix"
  fi
  if [[ "$(grep -Fxc "$verifier_entry" <<<"$listing")" != 1 ]] ||
    [[ "$(grep -Fxc "$verifier_test_entry" <<<"$listing")" != 1 ]]; then
    rm -f -- "$temporary"
    release_die "RC source archive lacks the exact reviewed external-evaluation verifier sources"
  fi
  if ! verifier_sha="$(tar -xOzf "$temporary" "$verifier_entry" | sha256sum | awk '{print $1}')" ||
    ! verifier_test_sha="$(tar -xOzf "$temporary" "$verifier_test_entry" | sha256sum | awk '{print $1}')"; then
    rm -f -- "$temporary"
    release_die "RC source archive could not hash the reviewed external-evaluation verifier sources"
  fi
  if [[ "$verifier_sha" != "$verifier_sha256" ]] ||
    [[ "$verifier_test_sha" != "$verifier_test_sha256" ]]; then
    rm -f -- "$temporary"
    release_die "RC source archive external-evaluation verifier source identity differs"
  fi
  if grep -Eiq '(^|/)(\.git($|/)|dist($|/)|build($|/)|[^/]*\.(db|sqlite|sqlite3|key|pem|p12|pfx|jks|keystore|log)($|[-.])|\.env($|[./]))' <<<"$listing" ||
    grep -Eiq "$secret_key_path_pattern" <<<"$listing" ||
    grep -Eiq "$local_sandbox_path_pattern" <<<"$listing"; then
    rm -f -- "$temporary"
    release_die "RC source archive contains a forbidden repository, build, database, secret, local sandbox, or log path"
  fi
  if grep -Eiq "$backup_binary_archive_path_pattern" <<<"$listing" ||
    grep -Eiq "$transient_path_pattern" <<<"$listing" ||
    { grep -Ei "$test_binary_path_pattern" <<<"$listing" |
        grep -Eiv "$safe_test_source_pattern" >/dev/null; }; then
    rm -f -- "$temporary"
    release_die "RC source archive contains a forbidden backup, binary, archive, profile, test executable, or temporary classifier candidate"
  fi
  restricted_listing="$(awk -v verifier="$verifier_entry" -v verifier_test="$verifier_test_entry" \
    '$0 != verifier && $0 != verifier_test { print }' <<<"$listing")"
  if grep -Eiq '(^|/)[^/]*(evaluation|holdout|consumed|private|blind|retired)[^/]*($|/)|(^|/)testdata/round9-independent-(benign|malicious)-v1/' <<<"$restricted_listing"; then
    rm -f -- "$temporary"
    release_die "RC source archive contains restricted evaluation material"
  fi
  if tar -tvzf "$temporary" | grep -Eq '^l'; then
    rm -f -- "$temporary"
    release_die "RC source archive contains a symbolic link"
  fi
  chmod 0644 "$temporary"
  mv -f -- "$temporary" "$output_dir/$source_archive"
  (
    cd "$output_dir"
    sha256sum "$source_archive" >"$source_archive.sha256"
    sha256sum -c "$source_archive.sha256"
  )
}

rm -rf -- "$dist"
make -C "$root" -j1 ARTIFACT_VERSION="$RELEASE_ARTIFACT_VERSION" \
  round6-development-artifacts
normalize_rc_sbom_identity "$dist/sbom.cdx.json"
install_lane_publication_evidence "$dist"
create_rc_audit_bundle "$root" "$dist"
create_rc_source_archive "$root" "$dist"
write_rc_checksums "$dist"
make -C "$root" -j1 ARTIFACT_VERSION="$RELEASE_ARTIFACT_VERSION" \
  round6-cpa-store-contract artifact-hash

for artifact in "${core_artifacts[@]}"; do
  [[ -f "$dist/$artifact" && ! -L "$dist/$artifact" ]] || \
    release_die "RC artifact must be a regular non-symlink file: $dist/$artifact"
done
expected_checksum_files="$(printf '%s\n' "${checksum_artifacts[@]}" | LC_ALL=C sort)"
actual_checksum_files="$(awk '{print $2}' "$dist/checksums.txt" | LC_ALL=C sort)"
[[ "$actual_checksum_files" == "$expected_checksum_files" ]] || \
  release_die "RC checksums.txt does not cover exactly the published core artifacts"
for forbidden in round6-prerelease-attestation.json formal-release-attestation.json; do
  [[ ! -e "$dist/$forbidden" ]] || \
    release_die "RC release must not emit formal evidence asset: $forbidden"
done

jq -e \
  --arg version "$RELEASE_ARTIFACT_VERSION" \
  --arg source_version "$RELEASE_SOURCE_VERSION" \
  --arg commit "$RELEASE_GIT_COMMIT" \
  --arg tree "$RELEASE_GIT_TREE" \
  --arg builder_image "$RC_BUILDER_IMAGE" \
  --arg builder_image_digest "$RC_BUILDER_IMAGE_DIGEST" \
  --arg builder_reference "$RC_BUILDER_REFERENCE" \
  --arg runner_label "$RC_RUNNER_LABEL" \
  --arg runner_os "$RC_RUNNER_OS" \
  --arg runner_arch "$RC_RUNNER_ARCH" \
  --arg runner_environment "$RC_RUNNER_ENVIRONMENT" \
  --arg runner_name "$runner_name" \
  --arg runner_image_unobservable "$runner_image_unobservable" \
  '.schema_version == 4 and
   .version == $version and .source_version == $source_version and
   .commit == $commit and .tree == $tree and .dirty == false and
   .go_version == "go1.26.4" and
   .goos == "linux" and .goarch == "amd64" and .cgo_enabled == true and
   .cc_command == "gcc" and
   (.gcc_version | type == "string" and length > 0) and
   .gcc_target == "x86_64-linux-gnu" and
   (.binutils_ld_version | type == "string" and length > 0) and
   (.glibc_version | type == "string" and length > 0) and
   .builder_image == $builder_image and
   .builder_image_digest == $builder_image_digest and
   .builder_reference == $builder_reference and
   .builder_reference == ($builder_image + "@" + $builder_image_digest) and
   .runner_label == $runner_label and
   .runner_os == $runner_os and
   .runner_arch == $runner_arch and
   .runner_environment == $runner_environment and
   .runner_name == $runner_name and
   .runner_image_os == $runner_image_unobservable and
   .runner_image_version == $runner_image_unobservable and
   ($builder_image_digest | test("^sha256:[0-9a-f]{64}$"))' \
  "$dist/build-metadata.json" >/dev/null || \
  release_die "RC build metadata does not describe the clean exact Linux amd64 source and toolchain"

assert_rc_sbom_identity "$dist/sbom.cdx.json"

work="$(mktemp -d)"
clone_a="$work/source-a"
clone_b="$work/source-b"
cleanup() {
  rm -rf -- "$work"
}
trap cleanup EXIT

round6_sparse_clone() {
  local destination="$1"
  mkdir -m 0700 -- "$destination"
  git -C "$destination" init --quiet
  git -C "$destination" remote add origin "https://github.com/${GITHUB_REPOSITORY}.git"
  git -C "$destination" fetch --quiet --filter=blob:none --no-tags origin \
    "+refs/tags/$RELEASE_RC_TAG:refs/tags/$RELEASE_RC_TAG"
  [[ -d "$destination/.git" && ! -L "$destination/.git" ]] || \
    release_die "RC reproducibility clone must use an independent Git directory"
  [[ ! -e "$destination/.git/objects/info/alternates" ]] || \
    release_die "RC reproducibility clone must not share a local object database"
  [[ "$(git -C "$destination" tag --list)" == "$RELEASE_RC_TAG" ]] || \
    release_die "RC reproducibility clone must contain only the exact RC tag"
  [[ "$(git -C "$destination" cat-file -t "$RELEASE_RC_TAG")" == tag ]] || \
    release_die "RC reproducibility clone requires the annotated RC tag object"
  [[ "$(git -C "$destination" rev-parse "$RELEASE_RC_TAG^{tag}")" == \
    "$release_rc_tag_object" ]] || \
    release_die "RC reproducibility clone tag object differs from the admitted source tag"
  [[ "$(git -C "$destination" rev-parse "$RELEASE_RC_TAG^{commit}")" == \
    "$RELEASE_GIT_COMMIT" ]] || \
    release_die "RC reproducibility clone tag does not resolve to the expected commit"
  git -C "$destination" sparse-checkout set --no-cone \
    '/*' \
    '!/cmd/**/*[Ee][Vv][Aa][Ll][Uu][Aa][Tt][Ii][Oo][Nn]*' '!/cmd/**/*[Hh][Oo][Ll][Dd][Oo][Uu][Tt]*' '!/cmd/**/*[Cc][Oo][Nn][Ss][Uu][Mm][Ee][Dd]*' '!/cmd/**/*[Pp][Rr][Ii][Vv][Aa][Tt][Ee]*' '!/cmd/**/*[Bb][Ll][Ii][Nn][Dd]*' '!/cmd/**/*[Rr][Ee][Tt][Ii][Rr][Ee][Dd]*' \
    '!/docs/**/*[Ee][Vv][Aa][Ll][Uu][Aa][Tt][Ii][Oo][Nn]*' '!/docs/**/*[Hh][Oo][Ll][Dd][Oo][Uu][Tt]*' '!/docs/**/*[Hh][Oo][Ll][Dd][Oo][Uu][Tt]_[Rr][Ee][Pp][Oo][Rr][Tt].[Mm][Dd]' \
    '!/docs/**/*[Cc][Oo][Nn][Ss][Uu][Mm][Ee][Dd]*' '!/docs/**/*[Pp][Rr][Ii][Vv][Aa][Tt][Ee]*' '!/docs/**/*[Bb][Ll][Ii][Nn][Dd]*' '!/docs/**/*[Rr][Ee][Tt][Ii][Rr][Ee][Dd]*' \
    '!/internal/classifier/**/*[Ee][Vv][Aa][Ll][Uu][Aa][Tt][Ii][Oo][Nn]*' '!/internal/classifier/**/*[Hh][Oo][Ll][Dd][Oo][Uu][Tt]*' \
    '!/internal/classifier/**/*[Cc][Oo][Nn][Ss][Uu][Mm][Ee][Dd]*' '!/internal/classifier/**/*[Pp][Rr][Ii][Vv][Aa][Tt][Ee]*' '!/internal/classifier/**/*[Bb][Ll][Ii][Nn][Dd]*' '!/internal/classifier/**/*[Rr][Ee][Tt][Ii][Rr][Ee][Dd]*' \
    '!/testdata/**/*[Ee][Vv][Aa][Ll][Uu][Aa][Tt][Ii][Oo][Nn]*' '!/testdata/**/*[Hh][Oo][Ll][Dd][Oo][Uu][Tt]*' '!/testdata/**/*[Cc][Oo][Nn][Ss][Uu][Mm][Ee][Dd]*' '!/testdata/**/*[Pp][Rr][Ii][Vv][Aa][Tt][Ee]*' '!/testdata/**/*[Bb][Ll][Ii][Nn][Dd]*' '!/testdata/**/*[Rr][Ee][Tt][Ii][Rr][Ee][Dd]*'
  git -C "$destination" checkout --quiet --detach "$RELEASE_GIT_COMMIT"
  [[ "$(git -C "$destination" rev-parse HEAD)" == "$RELEASE_GIT_COMMIT" ]] || \
    release_die "RC reproducibility clone did not check out the expected commit"
  [[ "$(git -C "$destination" rev-parse 'HEAD^{tree}')" == "$RELEASE_GIT_TREE" ]] || \
    release_die "RC reproducibility clone did not check out the expected tree"
  [[ -z "$(git -C "$destination" status --porcelain)" ]] || \
    release_die "RC reproducibility clone is not clean after checkout"
}

round6_sparse_clone "$clone_a"
round6_sparse_clone "$clone_b"
go_path="$(command -v "${GO:-go}")"
cyclonedx_path="$(command -v "${CYCLONEDX_GOMOD:-cyclonedx-gomod}")"

for name in a b; do
  clone="$work/source-$name"
  env \
    GO="$go_path" \
    VERSION="$RELEASE_SOURCE_VERSION" \
    SOURCE_DATE_EPOCH="$RELEASE_SOURCE_DATE_EPOCH" \
    RELEASE_RC_BUILD=1 \
    RELEASE_RC_TAG="$RELEASE_RC_TAG" \
    RELEASE_RC_EXPECTED_COMMIT="$RELEASE_GIT_COMMIT" \
    RELEASE_RC_EXPECTED_TREE="$RELEASE_GIT_TREE" \
    RC_BUILDER_IMAGE="$RC_BUILDER_IMAGE" \
    RC_BUILDER_IMAGE_DIGEST="$RC_BUILDER_IMAGE_DIGEST" \
    RC_BUILDER_REFERENCE="$RC_BUILDER_REFERENCE" \
    RC_RUNNER_LABEL="$RC_RUNNER_LABEL" \
    RC_RUNNER_OS="$RC_RUNNER_OS" \
    RC_RUNNER_ARCH="$RC_RUNNER_ARCH" \
    RC_RUNNER_ENVIRONMENT="$RC_RUNNER_ENVIRONMENT" \
    RC_RUNNER_NAME="$runner_name" \
    RC_RUNNER_IMAGE_OS="$runner_image_unobservable" \
    RC_RUNNER_IMAGE_VERSION="$runner_image_unobservable" \
    ROUND6_SAFE_SPARSE_BUILD=1 \
    REQUIRE_DIST_ARTIFACTS=1 \
    CYCLONEDX_GOMOD="$cyclonedx_path" \
    CYCLONEDX_GOMOD_VERSION="${CYCLONEDX_GOMOD_VERSION:-v1.9.0}" \
    GOCACHE="$work/go-build-cache-$name" \
    make -C "$clone" -j1 ARTIFACT_VERSION="$RELEASE_ARTIFACT_VERSION" \
      round6-development-artifacts
  normalize_rc_sbom_identity "$clone/dist/sbom.cdx.json"
  install_lane_publication_evidence "$clone/dist"
  create_rc_audit_bundle "$clone" "$clone/dist"
  create_rc_source_archive "$clone" "$clone/dist"
  write_rc_checksums "$clone/dist"
  env \
    GO="$go_path" \
    VERSION="$RELEASE_SOURCE_VERSION" \
    SOURCE_DATE_EPOCH="$RELEASE_SOURCE_DATE_EPOCH" \
    RELEASE_RC_BUILD=1 \
    RELEASE_RC_TAG="$RELEASE_RC_TAG" \
    RELEASE_RC_EXPECTED_COMMIT="$RELEASE_GIT_COMMIT" \
    RELEASE_RC_EXPECTED_TREE="$RELEASE_GIT_TREE" \
    RC_BUILDER_IMAGE="$RC_BUILDER_IMAGE" \
    RC_BUILDER_IMAGE_DIGEST="$RC_BUILDER_IMAGE_DIGEST" \
    RC_BUILDER_REFERENCE="$RC_BUILDER_REFERENCE" \
    RC_RUNNER_LABEL="$RC_RUNNER_LABEL" \
    RC_RUNNER_OS="$RC_RUNNER_OS" \
    RC_RUNNER_ARCH="$RC_RUNNER_ARCH" \
    RC_RUNNER_ENVIRONMENT="$RC_RUNNER_ENVIRONMENT" \
    RC_RUNNER_NAME="$runner_name" \
    RC_RUNNER_IMAGE_OS="$runner_image_unobservable" \
    RC_RUNNER_IMAGE_VERSION="$runner_image_unobservable" \
    ROUND6_SAFE_SPARSE_BUILD=1 \
    REQUIRE_DIST_ARTIFACTS=1 \
    CYCLONEDX_GOMOD="$cyclonedx_path" \
    CYCLONEDX_GOMOD_VERSION="${CYCLONEDX_GOMOD_VERSION:-v1.9.0}" \
    GOCACHE="$work/go-build-cache-$name" \
    make -C "$clone" -j1 ARTIFACT_VERSION="$RELEASE_ARTIFACT_VERSION" \
      round6-cpa-store-contract artifact-hash
  [[ -z "$(git -C "$clone" status --porcelain)" ]] || \
    release_die "RC reproducibility source $name became dirty"
  assert_rc_sbom_identity "$clone/dist/sbom.cdx.json"
done

for artifact in "${core_artifacts[@]}"; do
  cmp -s "$clone_a/dist/$artifact" "$clone_b/dist/$artifact" || \
    release_die "RC reproducibility clones differ for $artifact"
  cmp -s "$dist/$artifact" "$clone_a/dist/$artifact" || \
    release_die "root RC artifact differs from clean clone for $artifact"
done

hash_file() {
  sha256sum "$1" | awk '{print $1}'
}

summary_input="${RC_TEST_SUMMARY_INPUT:-}"
[[ -n "$summary_input" ]] || \
  release_die "RC_TEST_SUMMARY_INPUT is required for formal-structure RC packaging"
[[ -f "$summary_input" && ! -L "$summary_input" ]] || \
  release_die "RC test summary input must be a regular non-symlink file"
expected_summary="$work/expected-rc-release-test-summary.txt"
case "$rc_release_lane" in
  round8) rc_summary_heading='CPA Cyber Abuse Guard v0.16-rc.2 canonical internal Linux release gates' ;;
  round9) rc_summary_heading="CPA Cyber Abuse Guard v${RELEASE_ARTIFACT_VERSION} Round 9 canonical Linux release gates" ;;
esac
{
  printf '%s\n' \
    "$rc_summary_heading" \
    'summary_schema=1' \
    "commit=$RELEASE_GIT_COMMIT" \
    "tree=$RELEASE_GIT_TREE" \
    "exact_main_ci_run=$RC_CI_RUN_ID" \
    "exact_main_ci_attempt=$RC_CI_RUN_ATTEMPT" \
    'rc_gate.safe_contract=PASS' \
    'rc_gate.full_linux_quality=PASS' \
    'rc_gate.cpa_v7.2.95_primary_source_compatibility=PASS' \
    'rc_gate.rc_integration=PASS' \
    'rc_gate.clean_tree=PASS' \
    'dynamic_stdout_included=false' \
    'wall_clock_timing_included=false' \
    'benchmark_measurements_included=false'
} >"$expected_summary"
cmp -s "$summary_input" "$expected_summary" || \
  release_die "RC test summary must exactly match the canonical timing-free gate record"
release_assert_no_sensitive_env_values "$summary_input" \
  CPA_MANAGEMENT_KEY \
  CYBER_ABUSE_GUARD_HMAC_KEY \
  CYBER_ABUSE_GUARD_HMAC_KEY_FILE \
  GITHUB_TOKEN \
  GH_TOKEN \
  OPENAI_API_KEY \
  ANTHROPIC_API_KEY \
  GOOGLE_API_KEY \
  AZURE_OPENAI_API_KEY \
  AWS_SECRET_ACCESS_KEY \
  DATABASE_URL

finalize_rc_package() {
  local output_dir="$1"
  local evidence evidence_temporary manifest temporary
  local release_phase status packaging host_validation counted_mock_validation
  local host_evidence_origin host_evidence_claim
  local host_evidence_sha256_value='' host_evidence_sidecar_sha256_value=''
  local primary_host_results='{}'
  local round9_classifier='{}' round9_ruleset='{}' round9_corpus='{}'
  local round9_audit_contract='{}' round9_machine_reports='{}'
  local round9_development_evidence='{}' round9_counted_mock='{}'
  local round9_external_evaluation_manifest='{}'
  local round9_external_ledger_proof_manifest='{}'
  local round9_contract_status='NOT_APPLICABLE'
  local round9_release_title='' round9_release_body='' round9_release_assets='[]'
  local independent_evaluation_status='NOT_PROVIDED'
  local expected_dist_files actual_dist_files expected_count
  local evidence_hash_artifacts=(
    "${checksum_artifacts[@]}"
    checksums.txt
    "$test_summary"
    "$test_summary.sha256"
    "$source_archive"
    "$source_archive.sha256"
  )

  if [[ "$rc_release_lane" == round9 ]]; then
    round9_development_evidence="$(jq -c '.' "$round9_development_evidence_input")"
    round9_classifier="$(jq -c '.candidate.classifier' <<<"$round9_development_evidence")"
    round9_ruleset="$(jq -c '.candidate.ruleset' <<<"$round9_development_evidence")"
    round9_audit_contract="$(jq -c '.audit_contract' <<<"$round9_development_evidence")"
    round9_machine_reports="$(jq -c '.machine_reports' <<<"$round9_development_evidence")"
    round9_contract_status=PASS
  fi

  if [[ "$publish_rc_release" == true ]]; then
    release_phase=publish
    if [[ "$rc_release_lane" == round9 ]]; then
      status='ROUND9_INTERNAL_GATES_PASS / DEVELOPMENT_EVIDENCE_BOUND / SIGNED_EXTERNAL_EVALUATION_VERIFIED / PROTECTED_LEDGER_VERIFIED / COUNTED_MOCK_ONLY / REAL_PROVIDER_NOT_CONTACTED / PRODUCTION_NOT_ACCESSED / INDEPENDENT_AUDIT_REQUIRED / PRODUCTION_NOT_APPROVED / NOT_STABLE_V0.16'
      packaging='ROUND9_SCHEMA6 / RC EVIDENCE ONLY / GITHUB ARTIFACT PROVENANCE / SIGNED EXTERNAL EVALUATION / PROTECTED LEDGER / NO INDEPENDENT AUDIT ATTESTATION'
      jq -e --slurpfile development "$round9_development_evidence_input" \
        '.payload.development_evidence == $development[0]' \
        "$output_dir/$external_evaluation" >/dev/null || \
        release_die "signed external evaluation development evidence differs from Phase 1"
      round9_external_evaluation_manifest="$(jq -c '.payload' "$output_dir/$external_evaluation")"
      jq -e '
        .payload.schema == "round9-external-evaluation/v3" and
        .payload.state == "PASS" and
        .payload.counted_mock.schema == "round9-external-counted-mock/v1" and
        .payload.counted_mock.state == "PASS" and
        .payload.public_counted_mock.schema == "round9-public-counted-mock/v1" and
        .payload.public_counted_mock.state == "PASS" and
        .payload.public_counted_mock.development_only == true and
        .payload.public_counted_mock.independent_holdout == false and
        .payload.public_counted_mock.third_party_code_executed == false and
        .payload.public_counted_mock.manifest.schema ==
          "round9-public-adversarial-corpus/v11" and
        .payload.public_counted_mock.manifest.dataset ==
          "round9-public-adversarial-v11" and
        .payload.public_counted_mock.route_matrix == {
          modes: ["audit", "balanced", "strict"],
          protocols: ["openai_chat", "openai_responses"],
          streams: ["nonstream", "stream"], routes_per_payload: 12
        } and
        .payload.public_counted_mock.families.historical_unique.unique_payloads == 8 and
        .payload.public_counted_mock.families.branch_head.unique_payloads == 1 and
        .payload.public_counted_mock.families.unmerged_candidate_carrier.unique_payloads == 1 and
        .payload.public_counted_mock.total.unique_payloads == 10 and
        .payload.public_counted_mock.total.serialized_executions == 120 and
        .payload.public_counted_mock.total.local_blocked == 80 and
        .payload.public_counted_mock.total.upstream_delta == 40 and
        .payload.public_counted_mock.total.usage_delta == 40 and
        (.payload.public_counted_mock.total.hard_policy_blocked >= 0 and
          .payload.public_counted_mock.total.hard_policy_blocked <= 80) and
        .payload.public_counted_mock.total.decision_kind_counts.audit_eligible_malicious_text == 40 and
        .payload.public_counted_mock.total.decision_kind_counts.block_malicious_text == 80 and
        .payload.metrics.public_counted_mock == .payload.public_counted_mock and
        .payload.execution.network_binding == {
          host_ip: "127.0.0.1", host_port: 18394, container_port: 8317
        } and
        .payload.execution.phase_protocol == {
          single_cpa_container: true,
          initial_mode: "audit",
          phase_order: ["audit", "balanced", "strict"],
          mode_switch_method: "PUT",
          mode_switch_endpoint: "/v0/management/plugins/cyber-abuse-guard/config",
          status_endpoint: "/v0/management/plugins/cyber-abuse-guard/status",
          status_required_after_each_phase_transition: true,
          mode_switch_authenticated: true
        } and
        .payload.metrics.route_order.algorithm ==
          "hmac_sha256_challenge_sequential_phase_order_v3" and
        .payload.metrics.route_order.phase_order == ["audit", "balanced", "strict"] and
        .payload.metrics.route_order.mode_status_verified == {
          audit: true, balanced: true, strict: true
        } and
        .payload.metrics.route_order.mode_switch_authenticated == true and
        .payload.metrics.incomplete.audit == {
          policy_blocked: false, upstream_delta: 1, usage_delta: 1
        } and
        .payload.metrics.incomplete.balanced == {
          policy_blocked: false, upstream_delta: 1, usage_delta: 1
        } and
        .payload.metrics.incomplete.strict == {
          policy_blocked: true, upstream_delta: 0, usage_delta: 0
        } and
        .payload.metrics.runtime_checks ==
          .payload.counted_mock.host_results.runtime_checks and
        .payload.metrics.runtime_checks.schema ==
          "round9-external-cpa-runtime-checks/v1" and
        .payload.metrics.runtime_checks.state == "PASS" and
        .payload.metrics.runtime_checks.audit_database == {
          observed: true, quick_check: "ok", schema_version: 6,
          migration_versions: [1, 2, 3, 4, 5, 6], wal_checkpoint_passed: true
        } and
        .payload.metrics.runtime_checks.restart_recovery == {
          observed: true, controlled_restart_count: 1,
          unexpected_restart_count: 0, post_restart_mode_verified: "audit"
        } and
        .payload.metrics.runtime_checks.panic_recovery == {
          observed: true, probe_passed: true, panic_count: 0,
          fatal_count: 0, plugin_error_count: 0
        } and
        .payload.metrics.runtime_checks.usage_queue == {
          observed: true, allowed_request_delta: 1, blocked_request_delta: 0
        } and
        .payload.metrics.runtime_checks.raw_capture == {
          observed: true, default_disabled: true, normal_request_records: 0,
          normal_request_plaintext_persisted: false
        } and
        .payload.metrics.runtime_checks.lifecycle == {
          observed: true, exit_code: 0, oom_killed: false,
          unexpected_restart_count: 0
        } and
        .payload.counted_mock.not_observed == [] and
        .payload.counted_mock.host_results.phase_order == ["audit", "balanced", "strict"] and
        .payload.counted_mock.host_results.phase_route_executions ==
          .payload.metrics.route_order.phase_route_executions and
        .payload.counted_mock.host_results.mode_status_verified == {
          audit: true, balanced: true, strict: true
        } and
        .payload.counted_mock.host_results.mode_switch_authenticated == true
      ' "$output_dir/$external_evaluation" >/dev/null ||
        release_die "Round 9 external evaluation lost the fixed counted-Mock phase contract"
      round9_external_ledger_proof_manifest="$(jq -nc \
        --arg schema "$(jq -er '.schema' "$output_dir/$external_ledger_proof")" \
        --arg name "$external_ledger_proof" \
        --arg sha256 "$(hash_file "$output_dir/$external_ledger_proof")" \
        '{schema:$schema,name:$name,sha256:$sha256}')"
      round9_counted_mock="$(jq -c '.counted_mock' <<<"$round9_external_evaluation_manifest")"
      round9_corpus="$(jq -nc \
        --argjson development "$round9_development_evidence" \
        --argjson external "$round9_external_evaluation_manifest" \
        '$development.corpus + {
          independent_benign: $external.metrics.benign,
          independent_malicious: $external.metrics.malicious
        }')"
      primary_host_results="$(jq -c '.host_results' <<<"$round9_counted_mock")"
      jq -e '.network_binding == {
        host_ip: "127.0.0.1", host_port: 18394, container_port: 8317
      }' <<<"$primary_host_results" >/dev/null ||
        release_die "Round 9 counted-Mock evidence lost the fixed 127.0.0.1:18394 CPA listener contract"
      host_validation='SIGNED_EXTERNAL_EVALUATION_VERIFIED / GITHUB_ATTESTED_HOST_WORKFLOW / PROTECTED_LEDGER'
      host_evidence_origin='SIGNED_EXTERNAL_EVALUATION_AND_PROTECTED_LEDGER'
      host_evidence_claim='PHASE1_ATTESTATION_TAG_COMMIT_TREE_RUN_ARTIFACT_CHALLENGE_EVALUATOR_AND_LEDGER_VERIFIED'
      independent_evaluation_status='PASS / SIGNED EXTERNAL EVALUATION VERIFIED'
    else
      status='RC_INTERNAL_GATES_PASS / HOST_EVIDENCE_ATTESTED_PROTECTED_WORKFLOW / SANDBOX_IDENTITY_AND_LOCALITY_VERIFIED / REAL_PROVIDER_NOT_CONTACTED / PRODUCTION_NOT_ACCESSED / INDEPENDENT_AUDIT_REQUIRED / PRODUCTION_NOT_APPROVED / NOT_STABLE_V0.16'
      packaging='FORMAL_STRUCTURE / RC EVIDENCE ONLY / GITHUB ARTIFACT PROVENANCE / PROTECTED HOST WORKFLOW ATTESTATION / NO INDEPENDENT FORMAL ATTESTATION'
      host_validation='GITHUB_ATTESTATION_VERIFIED / PROTECTED_HOST_WORKFLOW / COUNTED_MOCK_ONLY'
      host_evidence_origin='ATTESTED_PROTECTED_HOST_WORKFLOW_ARTIFACT'
      host_evidence_claim='SIGNER_WORKFLOW_REF_COMMIT_RUN_ARTIFACT_DIGEST_CHALLENGE_AND_SANDBOX_LOCALITY_VERIFIED'
      host_evidence_sha256_value="$(hash_file "$output_dir/$host_evidence")"
      host_evidence_sidecar_sha256_value="$(hash_file "$output_dir/$host_evidence_sidecar")"
      primary_host_results="$(jq -c '.cpa.primary.host_results' "$output_dir/$host_evidence")"
    fi
    counted_mock_validation=PASS
    expected_count=19
  else
    release_phase=candidate
    if [[ "$rc_release_lane" == round9 ]]; then
      status='ROUND9_INTERNAL_GATES_PASS / DEVELOPMENT_EVIDENCE_BOUND / PRIVATE_EXTERNAL_EVALUATION_CANDIDATE / EXTERNAL_EVALUATION_REQUIRED / INDEPENDENT_AUDIT_REQUIRED / PRODUCTION_NOT_APPROVED / NOT_STABLE_V0.16'
      packaging='ROUND9_SCHEMA6 / PRIVATE EXTERNAL-EVALUATION CANDIDATE / GITHUB ARTIFACT PROVENANCE / DEVELOPMENT EVIDENCE EMBEDDED / NO EXTERNAL EVIDENCE'
      round9_corpus="$(jq -nc --argjson development "$round9_development_evidence" '
        $development.corpus + {
          independent_benign: {state:"NOT_PROVIDED",reason:"EXTERNAL_EVALUATION_REQUIRED"},
          independent_malicious: {state:"NOT_PROVIDED",reason:"EXTERNAL_EVALUATION_REQUIRED"}
        }')"
      round9_counted_mock='{"state":"NOT_PROVIDED","reason":"EXTERNAL_EVALUATION_REQUIRED"}'
      round9_external_evaluation_manifest='{"state":"NOT_PROVIDED","reason":"EXTERNAL_EVALUATION_REQUIRED"}'
      round9_external_ledger_proof_manifest='{"state":"NOT_PROVIDED","reason":"EXTERNAL_EVALUATION_REQUIRED"}'
    else
      status='RC_INTERNAL_GATES_PASS / PRIVATE_HOST_TEST_CANDIDATE / HOST_VALIDATION_REQUIRED / INDEPENDENT_AUDIT_REQUIRED / PRODUCTION_NOT_APPROVED / NOT_STABLE_V0.16'
      packaging='FORMAL_STRUCTURE / PRIVATE HOST-TEST CANDIDATE / GITHUB ARTIFACT PROVENANCE / NO INDEPENDENT FORMAL ATTESTATION'
    fi
    if [[ "$rc_release_lane" == round9 ]]; then
      host_validation='NOT_RUN / EXTERNAL_EVALUATION_REQUIRED'
      host_evidence_origin='NOT_PROVIDED / EXTERNAL_EVALUATION_REQUIRED'
      host_evidence_claim='NOT_RUN / EXTERNAL_EVALUATION_REQUIRED'
      counted_mock_validation='NOT_RUN / EXTERNAL_EVALUATION_REQUIRED'
    else
      host_validation='NOT_RUN / HOST_TEST_REQUIRED'
      host_evidence_origin='NOT_PROVIDED / HOST_TEST_REQUIRED'
      host_evidence_claim='NOT_RUN / HOST_TEST_REQUIRED'
      counted_mock_validation='NOT_RUN / HOST_TEST_REQUIRED'
    fi
    expected_count=17
  fi

  if [[ "$rc_release_lane" == round9 ]]; then
    round9_release_title='v0.16-rc.3 - Round 9 counted-Mock candidate; independent audit required'
    round9_release_assets="$(
      printf '%s\n' "${published_artifacts[@]}" | LC_ALL=C sort | \
        jq -Rsc 'split("\n")[:-1]'
    )"
    if [[ "$publish_rc_release" == true ]]; then
      round9_release_body="$(cat <<EOF
Round 9 Linux amd64 prerelease for CPA v7.2.95.

- Exact commit: $RELEASE_GIT_COMMIT
- Classifier: $(jq -r '.version' <<<"$round9_classifier") / $(jq -r '.sha256' <<<"$round9_classifier")
- Ruleset: $(jq -r '.version' <<<"$round9_ruleset") / $(jq -r '.sha256' <<<"$round9_ruleset")
- Independent benign: $(jq -r '.independent_benign.unique_semantic_samples' <<<"$round9_corpus") unique; 0 blocked; Wilson95 upper $(jq -r '.independent_benign.wilson_upper_bound_ppm' <<<"$round9_corpus") ppm
- Paired malicious recall: $(jq -r '.paired_malicious.recall_basis_points' <<<"$round9_corpus") basis points
- Paired label audit: manifest v$(jq -r '.paired_malicious.corpus_manifest_version' <<<"$round9_corpus"); $(jq -r '.paired_malicious.label_audit.sha256' <<<"$round9_corpus")
- Public adversarial v11: $(jq -r '.public_adversarial.unique_formal_payloads' <<<"$round9_corpus") formal unique ($(jq -r '.public_adversarial.unique_historical_payloads' <<<"$round9_corpus") historical + $(jq -r '.public_adversarial.unique_branch_head_payloads' <<<"$round9_corpus") branch-head + $(jq -r '.public_adversarial.unique_current_prompt_like_payloads' <<<"$round9_corpus") current prompt-like); $(jq -r '.public_adversarial.payload_records' <<<"$round9_corpus") payload records; $(jq -r '.public_adversarial.unmerged_candidate_carriers' <<<"$round9_corpus") unmerged carrier; $(jq -r '.public_adversarial.nondefault_branch_candidate_carriers' <<<"$round9_corpus") active behind branches; $(jq -r '.public_adversarial.release_assets_reviewed' <<<"$round9_corpus") reviewed historical Release assets / $(jq -r '.public_adversarial.release_assets_with_prompt_entries' <<<"$round9_corpus") with prompt entries; $(jq -r '.public_adversarial.release_asset_metadata_records' <<<"$round9_corpus") Release asset metadata/digest records (none downloaded/opened); $(jq -r '.public_adversarial.candidate_carrier_executions' <<<"$round9_corpus") executed; $(jq -r '.public_adversarial.candidate_carriers_not_provided' <<<"$round9_corpus") NOT_PROVIDED; direct $(jq -r '.public_adversarial.direct_active_blocked' <<<"$round9_corpus") blocked / $(jq -r '.public_adversarial.direct_active_allowed' <<<"$round9_corpus") allowed; $(jq -r '.public_adversarial.serialized_route_executions' <<<"$round9_corpus") serialized routes
- Independent malicious recall: $(jq -r '.independent_malicious.recall_basis_points' <<<"$round9_corpus") basis points
- Audit schema v6; Raw Capture schema v4; CPA v7.2.95 counted-Mock PASS

This is a prerelease with latest=false. It is counted-Mock-only, did not contact a real Provider or production, does not authorize deployment, and still requires independent audit.
EOF
)"
    else
      round9_release_body='NOT_PROVIDED / EXTERNAL_EVALUATION_REQUIRED'
    fi
  fi

  install -m 0644 "$summary_input" "$output_dir/$test_summary"
  (
    cd "$output_dir"
    sha256sum "$test_summary" >"$test_summary.sha256"
    sha256sum -c "$test_summary.sha256"
  )

  evidence="$output_dir/$rc_evidence"
  evidence_temporary="$(mktemp "$output_dir/.rc-release-evidence.XXXXXX")"
  {
    printf '# CPA Cyber Abuse Guard v%s release-candidate evidence\n\n' \
      "$RELEASE_ARTIFACT_VERSION"
    printf 'Status: %s\n\n' "$status"
    printf 'This record proves the internal Linux build, test, packaging, and reproducibility gates for this exact RC.\n\n'
    printf -- '- Release phase: %s\n' "$release_phase"
    printf -- '- Tag: %s\n' "$RELEASE_RC_TAG"
    printf -- '- Annotated tag object: %s\n' "$release_rc_tag_object"
    printf -- '- Commit: %s\n' "$RELEASE_GIT_COMMIT"
    printf -- '- Tree: %s\n' "$RELEASE_GIT_TREE"
    printf -- '- Exact-main CI run: https://github.com/%s/actions/runs/%s\n' \
      "$GITHUB_REPOSITORY" "$RC_CI_RUN_ID"
    printf -- '- Exact-main CI run attempt: %s\n' "$RC_CI_RUN_ATTEMPT"
    printf -- '- Release workflow run identity: %s\n' "$workflow_run_reproducible"
    printf -- '- Release workflow attempt identity: %s\n' "$workflow_attempt_reproducible"
    printf -- '- Platform: linux/amd64, CGO enabled\n'
    printf -- '- Build runner: label=%s; os=%s; arch=%s; environment=%s; name=%s\n' \
      "$RC_RUNNER_LABEL" "$RC_RUNNER_OS" "$RC_RUNNER_ARCH" \
      "$RC_RUNNER_ENVIRONMENT" "$runner_name"
    printf -- '- Build runner host image OS/version: %s / %s\n' \
      "$runner_image_unobservable" "$runner_image_unobservable"
    printf -- '- Immutable builder container: %s\n' "$RC_BUILDER_REFERENCE"
    printf -- '- CPA primary source/compile compatibility: PASS, v7.2.95 at f71ec0eb6776854457892452cf28c47f0d658251\n'
    if [[ "$rc_release_lane" == round9 ]]; then
      printf -- '- Signed external evaluation validation: %s\n' "$host_validation"
    else
      printf -- '- Host evidence validation: %s\n' "$host_validation"
    fi
    printf -- '- CPA v7.2.95 primary counted-Mock validation: %s\n' "$counted_mock_validation"
    if [[ "$rc_release_lane" == round9 && "$publish_rc_release" == true ]]; then
      printf -- '- CPA Host listener: 127.0.0.1:18394 -> container 8317/tcp (exact)\n'
    fi
    printf -- '- Real Provider validation: NOT_RUN / PROHIBITED\n'
    printf -- '- Production validation: NOT_RUN / PROHIBITED\n'
    if [[ "$publish_rc_release" == true ]]; then
      printf -- '- Real Provider contacted: false\n'
      printf -- '- Production accessed: false\n'
      printf -- '- Unexpected restart count: 0\n'
      printf -- '- OOM: false\n'
      printf -- '- Panic/fatal/plugin error counts: 0 / 0 / 0\n'
      if [[ "$rc_release_lane" == round9 ]]; then
        printf -- '- Round 9 classifier: %s / %s\n' \
          "$(jq -r '.version' <<<"$round9_classifier")" \
          "$(jq -r '.sha256' <<<"$round9_classifier")"
        printf -- '- Round 9 ruleset: %s / %s\n' \
          "$(jq -r '.version' <<<"$round9_ruleset")" \
          "$(jq -r '.sha256' <<<"$round9_ruleset")"
        printf -- '- Development benign: unique=%s; routes=%s; blocked=0; hard_policy=0\n' \
          "$(jq -r '.development_benign.unique_semantic_samples' <<<"$round9_corpus")" \
          "$(jq -r '.development_benign.serialized_route_executions' <<<"$round9_corpus")"
        printf -- '- Independent benign: unique=%s; routes=%s; blocked=0; hard_policy=0; Wilson95 upper ppm=%s\n' \
          "$(jq -r '.independent_benign.unique_semantic_samples' <<<"$round9_corpus")" \
          "$(jq -r '.independent_benign.serialized_route_executions' <<<"$round9_corpus")" \
          "$(jq -r '.independent_benign.wilson_upper_bound_ppm' <<<"$round9_corpus")"
        printf -- '- Malicious recall: paired=%s bp; independent=%s bp\n' \
          "$(jq -r '.paired_malicious.recall_basis_points' <<<"$round9_corpus")" \
          "$(jq -r '.independent_malicious.recall_basis_points' <<<"$round9_corpus")"
        printf -- '- Paired development identity: %s / %s; samples=%s; routes=%s; Wilson95=%s..%s bp\n' \
          "$(jq -r '.paired_malicious.corpus_name' <<<"$round9_corpus")" \
          "$(jq -r '.paired_malicious.source_report_schema' <<<"$round9_corpus")" \
          "$(jq -r '.paired_malicious.samples' <<<"$round9_corpus")" \
          "$(jq -r '.paired_malicious.serialized_route_executions' <<<"$round9_corpus")" \
          "$(jq -r '.paired_malicious.wilson_lower_bound_basis_points' <<<"$round9_corpus")" \
          "$(jq -r '.paired_malicious.wilson_upper_bound_basis_points' <<<"$round9_corpus")"
        printf -- '- Paired label audit: manifest_version=%s; bytes=%s; sha256=%s\n' \
          "$(jq -r '.paired_malicious.corpus_manifest_version' <<<"$round9_corpus")" \
          "$(jq -r '.paired_malicious.label_audit.bytes' <<<"$round9_corpus")" \
          "$(jq -r '.paired_malicious.label_audit.sha256' <<<"$round9_corpus")"
        printf -- '- Paired machine report: schema=%s; bytes=%s; sha256=%s\n' \
          "$(jq -r '.paired_malicious.schema' <<<"$round9_machine_reports")" \
          "$(jq -r '.paired_malicious.bytes' <<<"$round9_machine_reports")" \
          "$(jq -r '.paired_malicious.sha256' <<<"$round9_machine_reports")"
        printf -- '- Public adversarial v11: payloads=%s; formal_unique=%s; historical=%s; branch_head=%s; current_prompt_like=%s; unmerged_carriers=%s; nondefault_branches=%s; release_assets=%s; release_assets_with_prompts=%s; release_asset_metadata_records=%s; executed=%s; NOT_PROVIDED=%s; scenario_payloads=%s; serialized_routes=%s; direct_blocked=%s; direct_allowed=%s\n' \
          "$(jq -r '.public_adversarial.payload_records' <<<"$round9_corpus")" \
          "$(jq -r '.public_adversarial.unique_formal_payloads' <<<"$round9_corpus")" \
          "$(jq -r '.public_adversarial.unique_historical_payloads' <<<"$round9_corpus")" \
          "$(jq -r '.public_adversarial.unique_branch_head_payloads' <<<"$round9_corpus")" \
          "$(jq -r '.public_adversarial.unique_current_prompt_like_payloads' <<<"$round9_corpus")" \
          "$(jq -r '.public_adversarial.unmerged_candidate_carriers' <<<"$round9_corpus")" \
          "$(jq -r '.public_adversarial.nondefault_branch_candidate_carriers' <<<"$round9_corpus")" \
          "$(jq -r '.public_adversarial.release_assets_reviewed' <<<"$round9_corpus")" \
          "$(jq -r '.public_adversarial.release_assets_with_prompt_entries' <<<"$round9_corpus")" \
          "$(jq -r '.public_adversarial.release_asset_metadata_records' <<<"$round9_corpus")" \
          "$(jq -r '.public_adversarial.candidate_carrier_executions' <<<"$round9_corpus")" \
          "$(jq -r '.public_adversarial.candidate_carriers_not_provided' <<<"$round9_corpus")" \
          "$(jq -r '.public_adversarial.scenario_payload_executions' <<<"$round9_corpus")" \
          "$(jq -r '.public_adversarial.serialized_route_executions' <<<"$round9_corpus")" \
          "$(jq -r '.public_adversarial.direct_active_blocked' <<<"$round9_corpus")" \
          "$(jq -r '.public_adversarial.direct_active_allowed' <<<"$round9_corpus")"
        printf -- '- Public adversarial machine report: schema=%s; bytes=%s; sha256=%s\n' \
          "$(jq -r '.public_adversarial.schema' <<<"$round9_machine_reports")" \
          "$(jq -r '.public_adversarial.bytes' <<<"$round9_machine_reports")" \
          "$(jq -r '.public_adversarial.sha256' <<<"$round9_machine_reports")"
        printf -- '- Audit contract: schema v6; Raw Capture v4; decision kinds closed; quick_check/WAL/restart passed\n'
        printf -- '- Route contract: Chat/Responses; stream/nonstream; Audit/Balanced/Strict; Audit/Balanced incomplete allow and Strict incomplete block; authenticated mode status after each transition\n'
        printf 'The signed external evaluation and protected-ledger proof are produced by the protected Round 9 external-evaluation workflow and bind the exact development evidence, classifier, ruleset, frozen candidate, counted-Mock result, tag, commit, tree, run, artifact digest, challenge, evaluator identity, and sandbox adapter identity.\n'
      else
        printf -- '- Primary protocol deltas: Chat benign/malicious=1/0; Responses benign/malicious=1/0\n'
        printf -- '- Primary corpus matrix: benign=42/42; paired malicious blocked=42/42\n'
        printf -- '- Primary coverage: stream=true; nonstream=true; audit=true; balanced=true; strict=true\n'
        printf -- '- Primary policy outcomes: balanced_incomplete_allow=true; strict_incomplete_block=true; usage_queue_allow_delta=1; usage_queue_blocked_zero=true\n'
        printf -- '- Primary database/lifecycle: quick_check=ok; WAL=true; restart_cycle=true; unexpected_restart=0\n'
        printf -- '- Primary Raw Capture: only_blocked=true; TTL_dedup=true; schema_v3_redaction_metadata=true; purge_WAL=true\n'
        printf 'The Host evidence is produced and signed by the protected Round 8 Host workflow and is bound to its signer workflow, tag, commit, run, artifact digest, challenge, Phase 1 artifact, sandbox daemon identity, and host-locality challenge. This trust still depends on the protected runner and environment configuration.\n'
      fi
      printf 'The claimed counted-Mock result is not real Provider validation or production validation.\n'
    else
      if [[ "$rc_release_lane" == round9 ]]; then
        printf 'This is a private external-evaluation candidate and no GitHub Release may be created by this phase.\n'
      else
        printf 'This is a private Host-test candidate and no GitHub Release may be created by this phase.\n'
      fi
    fi
    printf -- '- Independent audit: NOT_PROVIDED (required)\n'
    printf -- '- Independent evaluation: %s\n' "$independent_evaluation_status"
    printf -- '- Production approval: NOT_GRANTED\n\n'
    printf '## Artifact hashes\n\n'
    for name in "${evidence_hash_artifacts[@]}"; do
      printf -- '- %s: %s\n' "$name" "$(hash_file "$output_dir/$name")"
    done
  } >"$evidence_temporary"
  release_assert_no_sensitive_env_values "$evidence_temporary" \
    CPA_MANAGEMENT_KEY CYBER_ABUSE_GUARD_HMAC_KEY CYBER_ABUSE_GUARD_HMAC_KEY_FILE \
    GITHUB_TOKEN GH_TOKEN OPENAI_API_KEY ANTHROPIC_API_KEY GOOGLE_API_KEY \
    AZURE_OPENAI_API_KEY AWS_SECRET_ACCESS_KEY DATABASE_URL
  chmod 0644 "$evidence_temporary"
  mv -f -- "$evidence_temporary" "$evidence"
  (
    cd "$output_dir"
    sha256sum "$rc_evidence" >"$rc_evidence.sha256"
    sha256sum -c "$rc_evidence.sha256"
  )

  manifest="$output_dir/rc-release-manifest.json"
  temporary="$(mktemp "$output_dir/.rc-release-manifest.XXXXXX")"
  jq -n \
    --arg release_lane "$rc_release_lane" \
    --argjson manifest_schema "$rc_manifest_schema" \
    --argjson is_round9 "$( [[ "$rc_release_lane" == round9 ]] && printf true || printf false )" \
    --argjson publish_rc_release "$publish_rc_release" \
    --arg release_phase "$release_phase" \
    --arg status "$status" \
    --arg packaging_profile "$packaging" \
    --arg source_version "$RELEASE_SOURCE_VERSION" \
    --arg artifact_version "$RELEASE_ARTIFACT_VERSION" \
    --arg tag "$RELEASE_RC_TAG" \
    --arg tag_object "$release_rc_tag_object" \
    --arg commit "$RELEASE_GIT_COMMIT" \
    --arg tree "$RELEASE_GIT_TREE" \
    --argjson source_date_epoch "$RELEASE_SOURCE_DATE_EPOCH" \
    --argjson ci_run_id "$RC_CI_RUN_ID" \
    --argjson ci_run_attempt "$RC_CI_RUN_ATTEMPT" \
    --arg repository "$GITHUB_REPOSITORY" \
    --arg workflow_ref "$GITHUB_WORKFLOW_REF" \
    --arg workflow_sha "$RELEASE_RC_WORKFLOW_SHA" \
    --arg ref "$GITHUB_REF" \
    --arg run_id "$workflow_run_reproducible" \
    --arg run_attempt "$workflow_attempt_reproducible" \
    --argjson artifact_count "$expected_count" \
    --arg host_validation "$host_validation" \
    --arg host_evidence_origin "$host_evidence_origin" \
    --arg host_evidence_claim "$host_evidence_claim" \
    --arg counted_mock_validation "$counted_mock_validation" \
    --argjson primary_host_results "$primary_host_results" \
    --argjson round9_classifier "$round9_classifier" \
    --argjson round9_ruleset "$round9_ruleset" \
    --argjson round9_corpus "$round9_corpus" \
    --argjson round9_audit_contract "$round9_audit_contract" \
    --argjson round9_machine_reports "$round9_machine_reports" \
    --argjson round9_development_evidence "$round9_development_evidence" \
    --argjson round9_counted_mock "$round9_counted_mock" \
    --argjson round9_external_evaluation "$round9_external_evaluation_manifest" \
    --argjson round9_external_ledger_proof "$round9_external_ledger_proof_manifest" \
    --arg round9_contract_status "$round9_contract_status" \
    --arg round9_release_title "$round9_release_title" \
    --arg round9_release_body "$round9_release_body" \
    --argjson round9_release_assets "$round9_release_assets" \
    --arg so "$so" \
    --arg so_sha256 "$(hash_file "$output_dir/$so")" \
    --arg so_sidecar_sha256 "$(hash_file "$output_dir/$so.sha256")" \
    --arg store_zip "$store_zip" \
    --arg store_zip_sha256 "$(hash_file "$output_dir/$store_zip")" \
    --arg audit_bundle "$audit_bundle" \
    --arg audit_bundle_sha256 "$(hash_file "$output_dir/$audit_bundle")" \
    --arg build_metadata_sha256 "$(hash_file "$output_dir/build-metadata.json")" \
    --arg checksums_sha256 "$(hash_file "$output_dir/checksums.txt")" \
    --arg ruleset_manifest_sha256 "$(hash_file "$output_dir/ruleset-manifest.json")" \
    --arg ruleset_sha256 "$(hash_file "$output_dir/ruleset.sha256")" \
    --arg sbom_sha256 "$(hash_file "$output_dir/sbom.cdx.json")" \
    --arg test_summary "$test_summary" \
    --arg test_summary_sha256 "$(hash_file "$output_dir/$test_summary")" \
    --arg test_summary_sidecar_sha256 "$(hash_file "$output_dir/$test_summary.sha256")" \
    --arg rc_evidence "$rc_evidence" \
    --arg rc_evidence_sha256 "$(hash_file "$output_dir/$rc_evidence")" \
    --arg rc_evidence_sidecar_sha256 "$(hash_file "$output_dir/$rc_evidence.sha256")" \
    --arg source_archive "$source_archive" \
    --arg source_archive_sha256 "$(hash_file "$output_dir/$source_archive")" \
    --arg source_archive_sidecar_sha256 "$(hash_file "$output_dir/$source_archive.sha256")" \
    --arg host_evidence "$host_evidence" \
    --arg host_evidence_sha256 "$host_evidence_sha256_value" \
    --arg host_evidence_sidecar_sha256 "$host_evidence_sidecar_sha256_value" \
    --arg external_evaluation "$external_evaluation" \
    --arg external_evaluation_sha256 "$(if [[ "$rc_release_lane" == round9 && "$publish_rc_release" == true ]]; then hash_file "$output_dir/$external_evaluation"; fi)" \
    --arg external_ledger_proof "$external_ledger_proof" \
    --arg external_ledger_proof_sha256 "$(if [[ "$rc_release_lane" == round9 && "$publish_rc_release" == true ]]; then hash_file "$output_dir/$external_ledger_proof"; fi)" \
    --arg independent_evaluation "$independent_evaluation_status" \
    '{
      schema_version: $manifest_schema,
      release_phase: $release_phase,
      publish_rc_release: $publish_rc_release,
      status: $status,
      packaging_profile: $packaging_profile,
      source_version: $source_version,
      artifact_version: $artifact_version,
      tag: $tag,
      tag_object: $tag_object,
      commit: $commit,
      tree: $tree,
      source_date_epoch: $source_date_epoch,
      ci_run_id: $ci_run_id,
      ci_run_attempt: $ci_run_attempt,
      artifact_count: $artifact_count,
      cpa: ({
        primary: ({
          version: "v7.2.95",
          commit: "f71ec0eb6776854457892452cf28c47f0d658251",
          source_compatibility: "PASS",
          counted_mock_validation: $counted_mock_validation
        } + (if $publish_rc_release then {host_results: $primary_host_results} else {} end)),
        real_provider_validation: "NOT_RUN / PROHIBITED"
      } + (if $is_round9 then {
        external_evaluation_validation: $host_validation,
        external_evaluation_origin: $host_evidence_origin,
        external_evaluation_claim: $host_evidence_claim
      } else {
        host_evidence_validation: $host_validation,
        host_evidence_origin: $host_evidence_origin,
        host_evidence_claim: $host_evidence_claim
      } end)),
      production_validation: "NOT_RUN / PROHIBITED",
      independent_audit: "NOT_PROVIDED",
      independent_audit_requirement: "required",
      independent_evaluation: $independent_evaluation,
      independent_evaluation_requirement: (if $independent_evaluation | startswith("PASS") then "satisfied" else "required" end),
      workflow: {
        repository: $repository,
        ref: $workflow_ref,
        sha: $workflow_sha,
        dispatch_ref: $ref,
        run_id: $run_id,
        run_attempt: $run_attempt
      },
      artifacts: ({
        so: {name: $so, sha256: $so_sha256, sidecar_sha256: $so_sidecar_sha256},
        store_zip: {name: $store_zip, sha256: $store_zip_sha256},
        audit_bundle: {name: $audit_bundle, sha256: $audit_bundle_sha256},
        build_metadata_sha256: $build_metadata_sha256,
        checksums_sha256: $checksums_sha256,
        ruleset_manifest_sha256: $ruleset_manifest_sha256,
        ruleset_sha256: $ruleset_sha256,
        sbom_sha256: $sbom_sha256,
        test_summary: {
          name: $test_summary,
          sha256: $test_summary_sha256,
          sidecar_sha256: $test_summary_sidecar_sha256
        },
        rc_evidence: {
          name: $rc_evidence,
          sha256: $rc_evidence_sha256,
          sidecar_sha256: $rc_evidence_sidecar_sha256
        },
        source_archive: {
          name: $source_archive,
          sha256: $source_archive_sha256,
          sidecar_sha256: $source_archive_sidecar_sha256
        }
      } + (if $publish_rc_release and $is_round9 then {
        external_evaluation: {
          name: $external_evaluation,
          sha256: $external_evaluation_sha256
        },
        external_ledger_proof: {
          name: $external_ledger_proof,
          sha256: $external_ledger_proof_sha256
        }
      } elif $publish_rc_release then {
          host_evidence: {
            name: $host_evidence,
            sha256: $host_evidence_sha256,
            sidecar_sha256: $host_evidence_sidecar_sha256
          }
      } else {} end))
    } + (if $publish_rc_release then {
      host_safety: {
        real_provider_contacted: false,
        production_accessed: false,
        unexpected_restart_count: 0,
        oom: false,
        panic_count: 0,
        fatal_count: 0,
        plugin_error_count: 0
      }
    } else {} end) + (if $is_round9 then {
      round9: {
        release_lane: $release_lane,
        classifier: $round9_classifier,
        ruleset: $round9_ruleset,
        corpus_contract_status: $round9_contract_status,
        corpus: $round9_corpus,
        audit_contract: $round9_audit_contract,
        machine_reports: $round9_machine_reports,
        development_evidence: $round9_development_evidence,
        counted_mock: $round9_counted_mock,
        external_evaluation: $round9_external_evaluation,
        external_ledger_proof: $round9_external_ledger_proof,
        release: {
          tag: $tag,
          title: $round9_release_title,
          body: $round9_release_body,
          publication_permitted: $publish_rc_release,
          draft: false,
          prerelease: true,
          latest: false,
          asset_allowlist: $round9_release_assets
        },
        cpa_contract: {
          version: "v7.2.95",
          commit: "f71ec0eb6776854457892452cf28c47f0d658251",
          upstream_version_policy: "fixed-no-automatic-follow"
        }
      }
    } else {} end)' >"$temporary"

  release_assert_no_sensitive_env_values "$temporary" \
    CPA_MANAGEMENT_KEY CYBER_ABUSE_GUARD_HMAC_KEY CYBER_ABUSE_GUARD_HMAC_KEY_FILE \
    GITHUB_TOKEN GH_TOKEN OPENAI_API_KEY ANTHROPIC_API_KEY GOOGLE_API_KEY \
    AZURE_OPENAI_API_KEY AWS_SECRET_ACCESS_KEY DATABASE_URL
  chmod 0644 "$temporary"
  mv -f -- "$temporary" "$manifest"
  (
    cd "$output_dir"
    sha256sum rc-release-manifest.json >rc-release-manifest.json.sha256
    sha256sum -c rc-release-manifest.json.sha256
  )

  expected_dist_files="$(printf '%s\n' "${published_artifacts[@]}" | LC_ALL=C sort)"
  actual_dist_files="$(find "$output_dir" -mindepth 1 -maxdepth 1 -printf '%f\n' | LC_ALL=C sort)"
  [[ "$actual_dist_files" == "$expected_dist_files" ]] || \
    release_die "RC dist directory does not contain exactly the $expected_count reviewed assets"
  [[ "$(wc -l <<<"$actual_dist_files")" == "$expected_count" ]] || \
    release_die "RC dist asset count differs from the reviewed phase contract"
  while IFS= read -r name; do
    [[ -f "$output_dir/$name" && ! -L "$output_dir/$name" ]] || \
      release_die "RC published asset must be a regular non-symlink file: $name"
  done <<<"$expected_dist_files"
  (
    cd "$output_dir"
    sha256sum -c checksums.txt
    sha256sum -c "$so.sha256"
    sha256sum -c ruleset.sha256
    sha256sum -c "$test_summary.sha256"
    sha256sum -c "$rc_evidence.sha256"
    sha256sum -c "$source_archive.sha256"
    sha256sum -c rc-release-manifest.json.sha256
    if [[ "$publish_rc_release" == true && "$rc_release_lane" == round8 ]]; then
      sha256sum -c "$host_evidence_sidecar"
    fi
  )
  for forbidden in round6-prerelease-attestation.json formal-release-attestation.json \
    release-evidence-final.md FORMAL_GATES_PASS; do
    [[ ! -e "$output_dir/$forbidden" ]] || \
      release_die "RC release must not emit formal evidence asset: $forbidden"
  done
}

finalize_rc_package "$dist"
finalize_rc_package "$clone_a/dist"
finalize_rc_package "$clone_b/dist"

for artifact in "${published_artifacts[@]}"; do
  cmp -s "$clone_a/dist/$artifact" "$clone_b/dist/$artifact" || \
    release_die "RC reproducibility clones differ for final asset $artifact"
  cmp -s "$dist/$artifact" "$clone_a/dist/$artifact" || \
    release_die "root RC final asset differs from clean clone for $artifact"
done

release_assert_source_unchanged
printf 'RC phase=%s assets and full reproducibility verified: %s\n' \
  "$([[ "$publish_rc_release" == true ]] && printf publish || printf candidate)" "$dist"
