#!/usr/bin/env bash
set -euo pipefail

root="$(cd "${BASH_SOURCE[0]%/*}/.." && pwd -P)"
cd "$root"
contract_test="$root/scripts/release-rc-contract-test.sh"
release_script="$root/scripts/release-rc.sh"
workflow="$root/.github/workflows/release-rc.yml"
portable="$root/tools/current-cpa-audit/second_machine_release_admission.py"
portable_schema="$root/tools/current-cpa-audit/second-machine-release-admission.schema.json"
github_validator="$root/scripts/release_rc_github_admission.py"
artifact_zip="$root/scripts/release_rc_artifact_zip.py"
artifact_zip_test="$root/scripts/release_rc_artifact_zip_test.py"
cpa_store="$root/scripts/release_rc_cpa_store.py"
cpa_store_test="$root/scripts/release_rc_cpa_store_test.py"
workflow_inventory="$root/scripts/release_rc_workflow_inventory.py"
workflow_inventory_test="$root/scripts/release_rc_workflow_inventory_test.py"
work="$(mktemp -d)"
trap 'rm -rf -- "$work"' EXIT

for path in "$contract_test" "$release_script" "$workflow" "$portable" \
  "$portable_schema" "$github_validator" "$artifact_zip" "$artifact_zip_test" \
  "$cpa_store" "$cpa_store_test" "$workflow_inventory" "$workflow_inventory_test"; do
  [[ -f "$path" && ! -L "$path" ]] || {
    printf 'required RC release contract input is missing: %s\n' "$path" >&2
    exit 1
  }
done

bash -n ./scripts/release-rc-contract-test.sh
bash -n ./scripts/release-common.sh
bash -n ./scripts/release-candidate-contract-test.sh
bash -n ./scripts/release-rc.sh
python3 -B - "$root" <<'PY'
from pathlib import Path
import sys

root = Path(sys.argv[1])
for relative in (
    "tools/current-cpa-audit/second_machine_release_admission.py",
    "scripts/release_rc_github_admission.py",
    "scripts/release_rc_artifact_zip.py",
    "scripts/release_rc_artifact_zip_test.py",
    "scripts/release_rc_cpa_store.py",
    "scripts/release_rc_cpa_store_test.py",
    "scripts/release_rc_workflow_inventory.py",
    "scripts/release_rc_workflow_inventory_test.py",
):
    path = root / relative
    compile(path.read_bytes(), relative, "exec")
PY
python3 -B ./scripts/release_rc_artifact_zip_test.py
python3 -B ./scripts/release_rc_cpa_store_test.py
python3 -B ./scripts/release_rc_github_admission_test.py
python3 -B ./scripts/release_rc_workflow_inventory_test.py
python3 -B ./tools/current-cpa-audit/tests/test_second_machine_release_admission.py
(cd "$root/integration/pluginstorecontract" && \
  go test ./... -run '^TestCPAReleaseCandidatePluginStoreInstallContract$' -count=1)

python3 -B - "$root" <<'PY'
from __future__ import annotations

from collections import Counter
from pathlib import Path
import re
import sys


root = Path(sys.argv[1])
workflow = (root / ".github/workflows/release-rc.yml").read_text("utf-8")
workflow_inventory = (root / "scripts/release_rc_workflow_inventory.py").read_text("utf-8")
script = (root / "scripts/release-rc.sh").read_text("utf-8")
portable = (root / "tools/current-cpa-audit/second_machine_release_admission.py").read_text("utf-8")
portable_schema = (root / "tools/current-cpa-audit/second-machine-release-admission.schema.json").read_text("utf-8")
api_validator = (root / "scripts/release_rc_github_admission.py").read_text("utf-8")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"release RC contract failed: {message}")


for marker in (
    "name: RC Release",
    "name: RC release admission",
    "name: RC Linux amd64 audited-candidate seal and attestation",
    "name: RC prerelease publication",
    "second_machine_release_id:",
    "second_machine_asset_id:",
    "second_machine_asset_sha256:",
    "repos/${GITHUB_REPOSITORY}/releases/${SECOND_MACHINE_RELEASE_ID}",
    "repos/${GITHUB_REPOSITORY}/releases/${SECOND_MACHINE_RELEASE_ID}/assets?per_page=100",
    "repos/${GITHUB_REPOSITORY}/releases/assets/${SECOND_MACHINE_ASSET_ID}",
    "release_rc_github_admission.py",
    "second_machine_release_admission.py validate",
    "actions/runs/${CI_RUN_ID}/artifacts?per_page=100",
    "name: cyber-abuse-guard-linux-amd64-audit-candidate",
    "run-id: ${{ inputs.ci_run_id }}",
    "name: Seal audited candidate bytes as fixed RC assets",
    "bash scripts/release-rc.sh seal-candidate",
    "EXACT_PROTECTED_MAIN_CHECKS_PASS",
    "SECOND_MACHINE_OWNER_RELEASE_ADMISSION_PASS",
    "SECOND_MACHINE_OWNER_RELEASE_ADMISSION_WAIVED",
    "I_ACK_SECOND_MACHINE_NOT_RUN",
    "second_machine_waiver:",
    "second_machine_waiver_acknowledgment:",
    "second_machine_waiver_reason:",
    "SUPPLEMENTAL_ARCHIVE_PASS",
    "NATIVE_HOST_SPECIAL_PATHS_PASS",
    "RC_SECOND_MACHINE_SCHEMA: cyber-abuse-guard.second-machine-release-admission.v3",
    "RC_CPA_VERSION: v7.2.142",
    "RC_CPA_COMMIT: 1f53b2eb03b9e963bac647e5566ca2b304239116",
    "RC_CPA_C_ABI: '1'",
    "RC_CPA_RPC_SCHEMA: '3'",
    "23000a55f3922c9c2daf04e27d4bdf49d5f95109dd76ba25fa0b3f834c67ed1c",
    "supplemental_archive_status=",
    "supplemental_archive_sha256=",
    "native_host_status=",
    "commit: ${{ steps.evidence.outputs.commit }}",
    "tree: ${{ steps.evidence.outputs.tree }}",
    "cpa_tag: ${{ steps.evidence.outputs.cpa_tag }}",
    "cpa_abi: ${{ steps.evidence.outputs.cpa_abi }}",
    "cpa_rpc_schema: ${{ steps.evidence.outputs.cpa_rpc_schema }}",
    "corpus_repository_count: ${{ steps.evidence.outputs.corpus_repository_count }}",
    "false_positives: ${{ steps.evidence.outputs.false_positives }}",
    "malicious_recall_percent: ${{ steps.evidence.outputs.malicious_recall_percent }}",
    "side_effect_violations: ${{ steps.evidence.outputs.side_effect_violations }}",
    "performance_gates_passed: ${{ steps.evidence.outputs.performance_gates_passed }}",
    "cleanup_pass: ${{ steps.evidence.outputs.cleanup_pass }}",
    ".verification.verified == true and .verification.reason == \"valid\"",
    "RC_TAG_SIGNER_POLICY: github-verification-verified-valid-annotated-tag-and-commit",
    "tag_signer_policy=",
    '.name == "main" and .protected == true and .commit.sha == $commit',
    "quality-and-artifacts",
    "fuzz-long",
    "reproducibility",
    "Analyze Go on Linux",
    "round9-policy-and-corpus",
    "--draft",
    "--prerelease",
    "--latest=false",
    "-F draft=false -F prerelease=true -f make_latest=false",
    "verify_tag_unchanged()",
    "verify_release_assets()",
    "verify_draft_release_exact()",
    "actions/workflows?per_page=100",
    'python3 -B scripts/release_rc_workflow_inventory.py --input "$active_workflows"',
    "--minimum-remaining-seconds \"$((RC_PUBLISH_TIMEOUT_SECONDS + RC_CLOCK_MARGIN_SECONDS))\"",
    "ATTESTATION_BUNDLE_PATH:",
    '[[ "$verified" == 18 ]]',
    '((${#assets[@]} == 19))',
):
    require(marker in workflow, f"workflow is missing {marker!r}")

require(workflow.count('python3 -B scripts/release_rc_workflow_inventory.py --input "$active_workflows"') == 2,
        "workflow inventory validator must run at admission and publication")
for marker in (
    '".github/workflows/ci.yml"',
    '".github/workflows/codeql.yml"',
    '".github/workflows/policy-gate.yml"',
    '".github/workflows/release-rc.yml"',
    '"dynamic/dependabot/dependabot-updates"',
    '"dynamic/dependabot/update-graph"',
    "duplicate active workflow path",
    "unknown active workflow paths",
):
    require(marker in workflow_inventory, f"workflow inventory validator is missing {marker!r}")

trigger_block = workflow.split("on:", 1)[1].split("\npermissions:", 1)[0]
top_level_triggers = re.findall(r"(?m)^  ([a-z_]+):\s*$", trigger_block)
require(top_level_triggers == ["workflow_dispatch"],
        f"RC workflow trigger set changed: {top_level_triggers!r}")

dispatch_inputs = re.findall(r"(?m)^      ([a-z0-9_]+):\s*$", trigger_block)
require(
    dispatch_inputs == [
        "ci_run_id",
        "codeql_run_id",
        "policy_run_id",
        "second_machine_release_id",
        "second_machine_asset_id",
        "second_machine_asset_sha256",
        "authorize_prerelease",
        "second_machine_waiver",
        "second_machine_waiver_acknowledgment",
        "second_machine_waiver_reason",
    ],
    f"RC dispatch input trust boundary changed: {dispatch_inputs!r}",
)

latest_function = workflow.split("latest_release_id() {", 1)[1].split(
    "revalidate_second_machine()", 1
)[0]
require(
    'if ! latest="$(jq -er' in latest_function
    and 'printf \'%s\\n\' "$latest"' in latest_function,
    "latest Release identity parser does not preserve jq failure status",
)
require(workflow.count('verify_release_assets "$release_id"') == 2,
        "draft and published asset digest/size closure must both run")
require(workflow.count("verify_tag_unchanged") == 4,
        "tag identity must be checked before staging, publication, and completion")
require(workflow.count('verify_draft_release_exact "$release_id"') == 2,
        "draft identity must be re-fetched before and immediately before PATCH")
draft_exact_function = workflow.split("verify_draft_release_exact() {", 1)[1].split(
    "revalidate_second_machine()", 1
)[0]
require('expected_body="$(<' not in draft_exact_function,
        "draft body comparison must not lose trailing newlines through command substitution")
require(
    "jq -erj '.body | select(type == \"string\")'" in draft_exact_function
    and 'cmp -s -- "$DIST_DIR/release-evidence.md" "$draft_body"' in draft_exact_function,
    "draft body must be decoded to a file and compared byte-for-byte",
)
require('if ! jq -e' in workflow,
        "critical jq predicates must use explicit fail-closed conditionals")
for exact_required_run in (
    'verify_jobs "$CI_RUN_ID" quality-and-artifacts fuzz-long reproducibility',
    'verify_jobs "$CODEQL_RUN_ID" \'Analyze Go on Linux\'',
    'verify_jobs "$POLICY_RUN_ID" round9-policy-and-corpus',
):
    require(exact_required_run in workflow,
            f"exact protected-main required-check binding changed: {exact_required_run}")

input_block = workflow.split("permissions: {}", 1)[0]
inputs = re.findall(r"(?m)^      ([a-z0-9_]+):\s*$", input_block)
require(
    inputs == [
        "ci_run_id",
        "codeql_run_id",
        "policy_run_id",
        "second_machine_release_id",
        "second_machine_asset_id",
        "second_machine_asset_sha256",
        "authorize_prerelease",
        "second_machine_waiver",
        "second_machine_waiver_acknowledgment",
        "second_machine_waiver_reason",
    ],
    f"dispatch input trust boundary changed: {inputs!r}",
)
require(len(re.findall(r"(?m)^        type:\s+(?:string|boolean)\s*$", input_block)) == 10,
        "RC dispatch must expose exactly ten typed inputs")
for forbidden in (
    "second_machine_status:",
    "second_machine_report_sha256:",
    "second_machine_commit:",
    "second_machine_tree:",
    "second_machine_so_sha256:",
):
    require(forbidden not in input_block, f"workflow revives self-reported input {forbidden}")

require('release.get("draft") is not True' in api_validator,
        "API validator does not require a draft staging Release")
require("target_commitish" in api_validator, "API validator does not bind target_commitish")
require("len(matches) != 1" in api_validator, "API validator does not reject duplicate CI artifacts")
require('artifact.get("expired") is not False' in api_validator,
        "API validator does not reject expired CI artifacts")
require("asset != members[0]" in api_validator,
        "API validator does not prove release-asset membership")
require('digest != expected_digest' in api_validator,
        "API validator does not bind the release asset API digest")

for marker in (
    "validate_machine_evidence(",
    "supplemental_manifest_path=args.supplemental_manifest",
    "supplemental_policy_path=args.supplemental_policy",
    "supplemental_results_path=args.supplemental_results",
    "validate_supplemental_evidence_copies(",
    "native.validate_bundle(",
    "validate_evidence_run_config(machine, run_config, run_config_raw)",
    "validate_candidate_manifest_file(run_config)",
    "validate_evidence_bundle(",
    "require_pass=True",
    "derive_semantic_summary",
    "derive_supplemental_summary",
    "local_tool_identities()",
    'SCHEMA = "cyber-abuse-guard.second-machine-release-admission.v3"',
    "EXPECTED_CORE_EXECUTIONS = 684",
    "EXPECTED_SUPPLEMENTAL_EXECUTIONS = 252",
    'pack.add_argument("--supplemental-archive", type=Path, required=True)',
    'pack.add_argument("--supplemental-manifest", type=Path, required=True)',
    'pack.add_argument("--supplemental-policy", type=Path, required=True)',
    'pack.add_argument("--supplemental-results", type=Path, required=True)',
    'pack.add_argument("--native-report", type=Path, required=True)',
    'pack.add_argument("--native-go-test-jsonl", type=Path, required=True)',
    'pack.add_argument("--checkout", type=Path, required=True)',
    'pack.add_argument("--lazy-read-phase-boundary", type=Path, required=True)',
    'pack.add_argument("--lazy-read-runtime-read-trace", type=Path, required=True)',
    'pack.add_argument("--lazy-read-runtime-read-summary", type=Path, required=True)',
    'pack.add_argument("--csam-text-fixture-manifest", type=Path, required=True)',
    'pack.add_argument("--csam-text-results", type=Path, required=True)',
    'pack.add_argument("--csam-text-summary", type=Path, required=True)',
    'pack.add_argument("--csam-text-privacy-cleanup", type=Path, required=True)',
    'report["evidence_refs"]',
    '"cpa_rpc_schema": report["cpa"]["rpc_schema"]',
    '"cpa_abi": report["cpa"]["c_abi"]',
    "REPORT_TTL = timedelta(hours=24)",
    'so["name"] != CAG_SO_NAME',
    'candidate_manifest["event"] == "push"',
):
    require(marker in portable, f"portable admission contract is missing {marker!r}")

for marker in (
    "workload_generator_sha256",
    "test_source_sha256",
    "critical_tests_sha256",
    '"const": "cyber-abuse-guard.second-machine-release-admission.v3"',
    '"rpc_schema": { "const": 3 }',
    '"c_abi": { "const": 1 }',
    '"evidence_refs"',
):
    require(marker in portable_schema, f"portable admission schema is missing {marker!r}")

for marker in (
    "readonly rc_source_version='1.0.0'",
    "readonly rc_binary_version='1.0.0'",
    "readonly rc_artifact_version='1.0.0-rc.2'",
    "readonly rc_tag='v1.0.0-rc.3'",
    "readonly rc_cpa_version='v7.2.142'",
    "readonly rc_cpa_commit='1f53b2eb03b9e963bac647e5566ca2b304239116'",
    "readonly rc_cpa_c_abi='1'",
    "readonly rc_cpa_rpc_schema='3'",
    "readonly rc_second_schema='cyber-abuse-guard.second-machine-release-admission.v3'",
    "release_assert_rc_build",
    "seal_candidate()",
    "validate_portable_and_candidate",
    "validate_dist_candidate() (",
    'trap \'rm -rf -- "$stage"\' EXIT',
    '--candidate-directory "$candidate_directory" >/dev/null || return $?',
    "create_source_archive",
    "write_release_evidence",
    "write_release_provenance",
    "write_release_manifest",
    "write_release_checksums",
    "create_cpa_store_assets",
    "TestPublishedRCStoreArchive",
    'so="cyber-abuse-guard-v${rc_binary_version}.so"',
    'audit_store_zip="cyber-abuse-guard_${rc_binary_version}_linux_amd64.zip"',
    'cpa_store_zip="cyber-abuse-guard_${rc_artifact_version}_linux_amd64.zip"',
    'audit_checksums="audit-candidate-checksums.txt"',
    'archive_entry: "cyber-abuse-guard.so"',
    'relationship: "cpa-plugin-store-container"',
    "standalone_rc_named_so_published: false",
    'source_archive="cyber-abuse-guard-v${rc_artifact_version}-source.tar.gz"',
    '[[ ! -e "$dist/cyber-abuse-guard-v${rc_artifact_version}.so" ]]',
    "original_bytes_reused: true",
    "schema_version: 3",
    "c_abi: $cpa_abi, rpc_schema: $cpa_rpc_schema",
    "schema: $second_schema",
    "recompiled_for_rc: false",
    "renamed_for_rc: false",
    "release-checksums.txt",
    "second-machine-release-admission.json",
    "independent_proof: false",
    "CAG_RELEASE_GOVERNANCE_TOKEN",
    "not an independent audit or independent proof",
    "NOT STABLE PRODUCTION APPROVAL",
    '[[ "$require_attestation" =~ ^[01]$ ]]',
    "REQUIRE_ATTESTATION must be exactly 0 or 1",
):
    require(marker in script, f"release seal script is missing {marker!r}")

require(script.count('[[ "$require_attestation" =~ ^[01]$ ]]') == 1,
        "release verify must validate the attestation requirement exactly once")
require("if ! validate_portable_and_candidate" not in script,
        "candidate validation must not suppress fail-closed function status")

for forbidden in (
    "build_assets()",
    "build-linux-amd64.sh",
    "release-build-metadata.sh",
    "release-sbom.sh",
    "create-store-archive.sh",
    "-ldflags",
    'so="cyber-abuse-guard-v${rc_artifact_version}.so"',
):
    require(forbidden not in script, f"release seal script can rebuild or rename candidate bytes: {forbidden!r}")

for stale_identity in (
    "v7.2.125",
    "2e6b1d83f6c304a102aa33c1faf0a4f94d0d331e",
    "cyber-abuse-guard.second-machine-release-admission.v2",
):
    require(stale_identity not in workflow, f"workflow retains stale release identity: {stale_identity}")
    require(stale_identity not in script, f"release script retains stale release identity: {stale_identity}")

require("cyber-abuse-guard-v1.0.0-rc.3.so" not in workflow,
        "workflow names an RC SO that was never audited")
require("cyber-abuse-guard-v1.0.0-rc.3.so" not in script,
        "release script names an RC SO that was never audited")

uses_pattern = re.compile(r"(?m)^\s*uses:\s+([^\s#]+)(?:\s+#.*)?$")
uses = uses_pattern.findall(workflow)
expected_uses = Counter(
    {
        "actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0": 3,
        "actions/download-artifact@37930b1c2abaa49bbe596cd826c3c89aef350131": 3,
        "actions/attest-build-provenance@0f67c3f4856b2e3261c31976d6725780e5e4c373": 1,
        "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a": 2,
    }
)
require(Counter(uses) == expected_uses, f"GitHub action allowlist changed: {Counter(uses)!r}")
for use in uses:
    require(re.fullmatch(r"actions/[a-z0-9-]+@[0-9a-f]{40}", use) is not None,
            f"action is not GitHub-owned and immutable-SHA pinned: {use}")

require(workflow.count("contents: write") == 1,
        "contents write must exist only in publication")
require(workflow.count("attestations: write") == 1,
        "attestation write must exist only in seal")
require(workflow.count("id-token: write") == 1,
        "OIDC write must exist only in seal")
require(workflow.count("runs-on: ubuntu-24.04") == 3,
        "all RC jobs must use the fixed runner")
for forbidden in ("ubuntu-latest", "make_latest=true", "--latest=true"):
    require(forbidden not in workflow, f"workflow contains forbidden marker {forbidden!r}")
require(re.search(r"(?m)^\s*runs-on:.*self-hosted", workflow) is None,
        "workflow may not run release code on a self-hosted runner")
require(workflow.count("secrets.CAG_RELEASE_GOVERNANCE_TOKEN") == 2,
        "admission and final publication must use the dedicated governance credential")
admission_workflow = workflow[workflow.index("  admission:"):workflow.index("  seal_candidate:")]
require("GH_TOKEN: ${{ github.token }}" in admission_workflow,
        "ordinary admission APIs must use the ephemeral workflow token")
require("GOVERNANCE_TOKEN: ${{ secrets.CAG_RELEASE_GOVERNANCE_TOKEN }}" in admission_workflow,
        "governance admission must use the dedicated governance credential")
require("governance_api()" in admission_workflow,
        "governance API calls must be isolated behind the dedicated token wrapper")
for marker in (
    '"repos/${GITHUB_REPOSITORY}/branches?per_page=100"',
    '([.[][] | .name] | sort) == ["main"]',
    '"repos/${GITHUB_REPOSITORY}/actions/runners?per_page=100"',
    ".total_count == 0 and .runners == []",
):
    require(marker in workflow, f"release admission is missing repository cleanup gate {marker!r}")
for forbidden in (
    "git tag -f",
    "git push --force",
    "gh release delete",
    "gh release edit",
    "--clobber",
):
    require(forbidden not in workflow, f"workflow can overwrite or delete release identity: {forbidden!r}")
require(re.search(r"gh api\s+--method\s+(?:DELETE|PUT).*git/refs/tags", workflow) is None,
        "workflow can delete or overwrite an admitted tag")

print("fixed RC byte-identity and staged-evidence contracts passed")
PY

python3 -B - "$release_script" "$work/validate-dist-candidate.sh" <<'PY'
from pathlib import Path
import re
import sys


source = Path(sys.argv[1]).read_text(encoding="utf-8")
match = re.search(
    r"(?ms)^validate_dist_candidate\(\) \(\n.*?^\)\n",
    source,
)
if match is None:
    raise SystemExit("release RC contract failed: cannot extract validate_dist_candidate")
Path(sys.argv[2]).write_text(match.group(0), encoding="utf-8", newline="\n")
PY

for failure_mode in return exit; do
  case_root="$work/$failure_mode"
  mkdir -p "$case_root/dist" "$case_root/tmp"
  printf 'payload\n' >"$case_root/dist/payload.bin"
  printf 'checksums\n' >"$case_root/dist/audit-checksums.txt"
  printf 'checksums\n' >"$case_root/dist/checksums.txt"
  printf '{}\n' >"$case_root/dist/report.json"
  if [[ "$failure_mode" == return ]]; then
    expected_status=42
  else
    expected_status=43
  fi
  set +e
  TMPDIR="$case_root/tmp" bash -euo pipefail -c '
    source "$1"
    dist="$2/dist"
    candidate_input_assets=(payload.bin checksums.txt)
    audit_checksums=audit-checksums.txt
    rc_second_report=report.json
    if [[ "$3" == return ]]; then
      validate_portable_and_candidate() { return 42; }
    else
      validate_portable_and_candidate() { exit 43; }
    fi
    validate_dist_candidate
  ' _ "$work/validate-dist-candidate.sh" "$case_root" "$failure_mode"
  actual_status=$?
  set -e
  if [[ "$actual_status" -ne "$expected_status" ]]; then
    printf 'release RC candidate validation fault returned %s, expected %s: %s\n' \
      "$actual_status" "$expected_status" "$failure_mode" >&2
    exit 1
  fi
  if find "$case_root/tmp" -mindepth 1 -print -quit | grep -q .; then
    printf 'release RC candidate validation leaked staging data: %s\n' "$failure_mode" >&2
    exit 1
  fi
done
printf 'release RC candidate validation faults fail closed and clean staging\n'

printf 'all v1.0.0-rc.3 release contracts passed\n'
