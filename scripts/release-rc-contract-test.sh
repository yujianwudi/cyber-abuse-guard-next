#!/usr/bin/env bash
set -euo pipefail

root="$(cd "${BASH_SOURCE[0]%/*}/.." && pwd -P)"
release_script="$root/scripts/release-rc.sh"
workflow="$root/.github/workflows/release-rc.yml"
workflow_readme="$root/.github/workflows/README.md"
portable="$root/tools/current-cpa-audit/second_machine_release_admission.py"
portable_schema="$root/tools/current-cpa-audit/second-machine-release-admission.schema.json"
github_validator="$root/scripts/release_rc_github_admission.py"
cpa_store="$root/scripts/release_rc_cpa_store.py"
cpa_store_test="$root/scripts/release_rc_cpa_store_test.py"

for path in "$release_script" "$workflow" "$workflow_readme" "$portable" \
  "$portable_schema" "$github_validator" "$cpa_store" "$cpa_store_test"; do
  [[ -f "$path" && ! -L "$path" ]] || {
    printf 'required RC release contract input is missing: %s\n' "$path" >&2
    exit 1
  }
done

bash -n "$root/scripts/release-common.sh"
bash -n "$root/scripts/release-candidate-contract-test.sh"
bash -n "$release_script"
python3 -B -m py_compile "$portable" "$github_validator" "$cpa_store" "$cpa_store_test"
python3 -B "$cpa_store_test"
python3 -B "$root/scripts/release_rc_github_admission_test.py"
python3 -B "$root/tools/current-cpa-audit/tests/test_second_machine_release_admission.py"
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
script = (root / "scripts/release-rc.sh").read_text("utf-8")
readme = (root / ".github/workflows/README.md").read_text("utf-8")
portable = (root / "tools/current-cpa-audit/second_machine_release_admission.py").read_text("utf-8")
api_validator = (root / "scripts/release_rc_github_admission.py").read_text("utf-8")
normalized_readme = " ".join(readme.split())


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
    "commit: ${{ steps.evidence.outputs.commit }}",
    "tree: ${{ steps.evidence.outputs.tree }}",
    "cpa_tag: ${{ steps.evidence.outputs.cpa_tag }}",
    "corpus_repository_count: ${{ steps.evidence.outputs.corpus_repository_count }}",
    "false_positives: ${{ steps.evidence.outputs.false_positives }}",
    "malicious_recall_percent: ${{ steps.evidence.outputs.malicious_recall_percent }}",
    "side_effect_violations: ${{ steps.evidence.outputs.side_effect_violations }}",
    "performance_gates_passed: ${{ steps.evidence.outputs.performance_gates_passed }}",
    "cleanup_pass: ${{ steps.evidence.outputs.cleanup_pass }}",
    ".verification.verified == true and .verification.reason == \"valid\"",
    "quality-and-artifacts",
    "fuzz-long",
    "reproducibility",
    "Analyze Go on Linux",
    "round9-policy-and-corpus",
    "--draft",
    "--prerelease",
    "--latest=false",
    '[[ "$verified" == 18 ]]',
    '((${#assets[@]} == 19))',
):
    require(marker in workflow, f"workflow is missing {marker!r}")

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
    ],
    f"dispatch input trust boundary changed: {inputs!r}",
)
require(len(re.findall(r"(?m)^        type:\s+(?:string|boolean)\s*$", input_block)) == 7,
        "RC dispatch must expose exactly seven typed inputs")
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
    "validate_machine_evidence(manifest, machine, args.results)",
    "validate_evidence_run_config(machine, run_config, run_config_raw)",
    "validate_candidate_manifest_file(run_config)",
    "validate_evidence_bundle(",
    "require_pass=True",
    "derive_semantic_summary",
    "local_tool_identities()",
    "REPORT_TTL = timedelta(hours=24)",
    'so["name"] != CAG_SO_NAME',
    'candidate_manifest["event"] == "push"',
):
    require(marker in portable, f"portable admission contract is missing {marker!r}")

for marker in (
    "readonly rc_source_version='1.0.0'",
    "readonly rc_binary_version='1.0.0'",
    "readonly rc_artifact_version='1.0.0-rc.1'",
    "readonly rc_tag='v1.0.0-rc.1'",
    "readonly rc_cpa_version='v7.2.125'",
    "release_assert_rc_build",
    "seal_candidate()",
    "validate_portable_and_candidate",
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
    "recompiled_for_rc: false",
    "renamed_for_rc: false",
    "release-checksums.txt",
    "second-machine-release-admission.json",
    "independent_proof: false",
    "not an independent audit or independent proof",
    "NOT STABLE PRODUCTION APPROVAL",
):
    require(marker in script, f"release seal script is missing {marker!r}")

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

require("cyber-abuse-guard-v1.0.0-rc.1.so" not in workflow,
        "workflow names an RC SO that was never audited")
require("cyber-abuse-guard-v1.0.0-rc.1.so" not in script,
        "release script names an RC SO that was never audited")

uses_pattern = re.compile(r"(?m)^\s*uses:\s+([^\s#]+)(?:\s+#.*)?$")
uses = uses_pattern.findall(workflow)
expected_uses = Counter(
    {
        "actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0": 3,
        "actions/download-artifact@37930b1c2abaa49bbe596cd826c3c89aef350131": 2,
        "actions/attest-build-provenance@0f67c3f4856b2e3261c31976d6725780e5e4c373": 1,
        "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a": 1,
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

for marker in (
    "`release-rc.yml`",
    "v1.0.0-rc.1",
    "v7.2.125",
    "Linux amd64",
):
    require(marker in readme, f"workflow README is missing {marker!r}")
require("not an independent audit or independent proof" in normalized_readme,
        "workflow README overstates second-machine evidence")
require("not a stable release or production approval" in normalized_readme,
        "workflow README loses the RC production boundary")

print("fixed RC byte-identity and staged-evidence contracts passed")
PY

printf 'all v1.0.0-rc.1 release contracts passed\n'
