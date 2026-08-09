from __future__ import annotations

import copy
import hashlib
import json
import struct
import sys
import tempfile
import unittest
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


HERE = Path(__file__).resolve().parent
TOOL = HERE.parent
sys.path.insert(0, str(TOOL))

from audit_contract import (  # noqa: E402
    CAG_SO_NAME,
    CAG_SOURCE_VERSION,
    CPA_COMMIT,
    CPA_OFFICIAL_ASSET_NAME,
    CPA_OFFICIAL_ASSET_SHA256,
    CPA_OFFICIAL_BINARY_SHA256,
    CPA_TAG,
    MODES,
    candidate_identity,
    canonical_bytes,
)
from host_performance import EVIDENCE_SCHEMA, THRESHOLDS  # noqa: E402
from second_machine_release_admission import (  # noqa: E402
    AdmissionError,
    BOUNDARY,
    EXPECTED_CANDIDATE_FILES,
    INPUT_HASH_KEYS,
    REPORT_TTL,
    SCHEMA,
    STATUS,
    _performance_gate,
    build_report,
    derive_semantic_summary,
    derive_summary,
    local_tool_identities,
    validate_report,
    validate_candidate_directory,
)
from fixtures import audit_candidate_manifest, evidence_files  # noqa: E402


try:
    from jsonschema import Draft202012Validator
except ImportError:  # pragma: no cover
    Draft202012Validator = None  # type: ignore[assignment]


NOW = datetime(2026, 8, 9, 4, 0, 0, tzinfo=timezone.utc)
COMMIT = "1" * 40
TREE = "2" * 40
SO_SHA = "3" * 64
MANIFEST_SHA = "4" * 64


def passing_metric(metric: str) -> float:
    operator, limit = THRESHOLDS[metric]
    if operator == "<":
        return float(limit) - 0.01
    if operator == "<=":
        return float(limit)
    if operator == ">=":
        return float(limit)
    if operator == "=":
        return float(limit)
    raise AssertionError(operator)


def valid_report() -> dict[str, object]:
    files = []
    for index, name in enumerate(EXPECTED_CANDIDATE_FILES, start=1):
        digest = f"{index:x}" * 64
        if name == CAG_SO_NAME:
            digest = SO_SHA
        if name == "audit-candidate-manifest.json":
            digest = MANIFEST_SHA
        files.append({"bytes": 1000 + index, "name": name, "sha256": digest})
    outcomes = []
    for case_index in range(19):
        malicious = case_index == 0
        for mode in MODES:
            actual = "allow" if not malicious or mode == "audit" else "block_malicious_text"
            outcomes.append(
                {
                    "actual_action": actual,
                    "all_executions_passed": True,
                    "execution_count": 12,
                    "expected_action": actual,
                    "false_positive": False,
                    "label": "malicious_active" if malicious else "normal_control",
                    "malicious": malicious,
                    "malicious_detected": malicious,
                    "mode": mode,
                    "semantic_case_id": f"case-{case_index:02d}",
                    "side_effect_violations": 0,
                }
            )
    metrics = {name: passing_metric(name) for name in sorted(THRESHOLDS)}
    gates = {name: _performance_gate(name, metrics[name]) for name in sorted(THRESHOLDS)}
    report: dict[str, object] = {
        "candidate": {
            "files": files,
            "github_artifact": {
                "digest": "sha256:" + "5" * 64,
                "id": 2002,
                "name": "cyber-abuse-guard-linux-amd64-audit-candidate",
                "run_attempt": 1,
                "run_id": 1001,
                "size": 123456,
                "workflow_name": "CI",
                "workflow_path": ".github/workflows/ci.yml",
            },
            "manifest_sha256": MANIFEST_SHA,
        },
        "claim_boundary": BOUNDARY,
        "cleanup": {
            "all_owned_resources_absent": True,
            "global_prune_used": False,
            "images_removed": False,
            "resource_count": 7,
            "third_party_text_files_removed": 11,
            "third_party_text_retained": False,
        },
        "corpus": {
            "manifest_sha256": "6" * 64,
            "policy_review_status": "approved",
            "repositories": [
                {
                    "commit": f"{index + 3:x}" * 40,
                    "default_branch": "main",
                    "repository": f"owner{index}/repo{index}",
                    "repository_key": f"repo{index}",
                    "tree": f"{index + 8:x}" * 40,
                }
                for index in range(5)
            ],
            "repository_count": 5,
            "source_count": 11,
            "unique_content_hashes": 11,
            "unique_semantic_cases": 19,
            "zip_source": {
                "archive_member": "README.md",
                "path": "fixture.zip",
                "repository": "owner3/repo3",
                "repository_key": "repo3",
                "source_sha256": "d" * 64,
                "text_sha256": "e" * 64,
            },
        },
        "cpa": {
            "binary_path": "/CLIProxyAPI",
            "binary_sha256": CPA_OFFICIAL_BINARY_SHA256,
            "commit": CPA_COMMIT,
            "image_id": "sha256:" + "7" * 64,
            "official_asset_name": CPA_OFFICIAL_ASSET_NAME,
            "official_asset_sha256": CPA_OFFICIAL_ASSET_SHA256,
            "repo_digest": "registry.example/cpa@sha256:" + "8" * 64,
            "tag": CPA_TAG,
        },
        "expires_at": (NOW + REPORT_TTL).isoformat().replace("+00:00", "Z"),
        "generated_at": NOW.isoformat().replace("+00:00", "Z"),
        "inputs": {key: f"{(index % 6) + 9:x}" * 64 for index, key in enumerate(INPUT_HASH_KEYS)},
        "performance": {
            "evidence_schema": EVIDENCE_SCHEMA,
            "gates": gates,
            "metrics": metrics,
            "status": "PASS",
        },
        "safety": {
            "business_snapshots_unchanged": True,
            "corpus_third_party_code_executions": 0,
            "independent_proof": False,
            "infrastructure_error_count": 0,
            "machine_third_party_code_executions": 0,
            "owner_run": True,
        },
        "schema": SCHEMA,
        "semantic": {"outcomes": outcomes, "summary_by_mode": derive_semantic_summary(outcomes)},
        "source": {
            "binary_version": "1.0.0",
            "commit": COMMIT,
            "repository": "yujianwudi/cyber-abuse-guard-next",
            "so": {"bytes": 1001, "name": CAG_SO_NAME, "sha256": SO_SHA},
            "source_version": "1.0.0",
            "tree": TREE,
        },
        "status": STATUS,
        "summary": {},
        "tool_bundles": local_tool_identities(),
    }
    report["inputs"]["candidate_manifest_sha256"] = MANIFEST_SHA  # type: ignore[index]
    report["inputs"]["corpus_manifest_sha256"] = "6" * 64  # type: ignore[index]
    report["summary"] = derive_summary(report)
    return report


def expected() -> dict[str, object]:
    return {
        "repository": "yujianwudi/cyber-abuse-guard-next",
        "commit": COMMIT,
        "tree": TREE,
        "candidate_run_id": 1001,
        "candidate_run_attempt": 1,
        "candidate_artifact_id": 2002,
        "candidate_artifact_digest": "sha256:" + "5" * 64,
        "candidate_artifact_size": 123456,
    }


class PortableAdmissionTests(unittest.TestCase):
    def test_accepts_closed_pass_report(self) -> None:
        self.assertEqual(validate_report(valid_report(), now=NOW, expected=expected())["status"], STATUS)

    def test_packer_builds_portable_report_from_validated_details(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest, machine, results_path = evidence_files(Path(directory))
            cag = machine["identities"]["cag"]
            candidate_manifest = audit_candidate_manifest(
                commit=cag["commit"],
                tree=cag["tree"],
                so_sha256=cag["so_sha256"],
                run_id="1001",
            )
            candidate_manifest["event"] = "push"
            candidate_manifest["head_branch"] = "main"
            candidate_manifest["head_sha"] = cag["commit"]
            candidate_raw = canonical_bytes(candidate_manifest) + b"\n"
            candidate = candidate_identity(
                candidate_manifest,
                candidate_raw,
                artifact_id="2002",
                artifact_name="cyber-abuse-guard-linux-amd64-audit-candidate",
                artifact_digest="sha256:" + "5" * 64,
            )
            machine["identities"]["candidate"] = candidate
            machine_raw = canonical_bytes(machine) + b"\n"
            metrics = {name: passing_metric(name) for name in sorted(THRESHOLDS)}
            performance = {
                "identities": {
                    "cag": copy.deepcopy(machine["identities"]["cag"]),
                    "candidate": copy.deepcopy(candidate),
                    "cpa": copy.deepcopy(machine["identities"]["cpa"]),
                },
                "metrics": metrics,
                "schema": EVIDENCE_SCHEMA,
                "status": "PASS",
            }
            candidate_files = [
                {"bytes": item["bytes"], "name": item["name"], "sha256": item["sha256"]}
                for item in candidate_manifest["artifacts"]
            ]
            candidate_files.append(
                {
                    "bytes": len(candidate_raw),
                    "name": "audit-candidate-manifest.json",
                    "sha256": hashlib.sha256(candidate_raw).hexdigest(),
                }
            )
            candidate_files.sort(key=lambda item: item["name"])
            run_config = {
                "identities": {"candidate": candidate},
                "paths": {"evidence_directory": str(Path(directory).resolve())},
            }
            results_raw = results_path.read_bytes()

            def pack(raw: bytes) -> dict[str, Any]:
                return build_report(
                    manifest=manifest,
                    manifest_raw=canonical_bytes(manifest) + b"\n",
                    machine=machine,
                    machine_raw=machine_raw,
                    results_path=results_path,
                    results_raw=raw,
                    run_config=run_config,
                    run_config_raw=canonical_bytes(run_config) + b"\n",
                    candidate_manifest=candidate_manifest,
                    candidate_raw=candidate_raw,
                    candidate_files=candidate_files,
                    candidate_artifact_size=123456,
                    workload_raw=b"{}\n",
                    performance_config_raw=b"{}\n",
                    measurements_raw=b"{}\n",
                    performance=performance,
                    performance_raw=canonical_bytes(performance) + b"\n",
                    generated_at=NOW,
                )

            report = pack(results_raw)
            self.assertEqual(report["status"], STATUS)
            self.assertEqual(report["source"]["so"]["name"], CAG_SO_NAME)
            self.assertEqual(report["summary"]["performance_gate_count"], len(THRESHOLDS))

            missing_arm = machine["run"]["cold_start_count"]
            incomplete_results_raw = b"".join(
                line + b"\n"
                for line in results_raw.splitlines()
                if json.loads(line)["cold_start"] != missing_arm
            )
            with self.assertRaisesRegex(
                AdmissionError, r"semantic summary cell .* is incomplete"
            ):
                pack(incomplete_results_raw)

    def test_candidate_directory_requires_exact_original_nine_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            so = bytearray(64)
            so[:6] = b"\x7fELF\x02\x01"
            struct.pack_into("<HH", so, 16, 3, 62)
            (root / CAG_SO_NAME).write_bytes(so)
            so_sha = hashlib.sha256(so).hexdigest()
            (root / f"{CAG_SO_NAME}.sha256").write_text(
                f"{so_sha}  {CAG_SO_NAME}\n", encoding="ascii", newline="\n"
            )
            zip_name = f"cyber-abuse-guard_{CAG_SOURCE_VERSION}_linux_amd64.zip"
            with zipfile.ZipFile(root / zip_name, "w", compression=zipfile.ZIP_STORED) as archive:
                archive.writestr(CAG_SO_NAME, so)
            metadata = {
                "cgo_enabled": True,
                "commit": COMMIT,
                "dirty": False,
                "goarch": "amd64",
                "goos": "linux",
                "schema_version": 4,
                "source_version": "1.0.0",
                "tree": TREE,
                "version": "1.0.0",
            }
            (root / "build-metadata.json").write_bytes(canonical_bytes(metadata) + b"\n")
            ruleset = {"plugin_version": "1.0.0", "ruleset_sha256": "7" * 64}
            ruleset_raw = canonical_bytes(ruleset) + b"\n"
            (root / "ruleset-manifest.json").write_bytes(ruleset_raw)
            (root / "ruleset.sha256").write_text(
                f"{hashlib.sha256(ruleset_raw).hexdigest()}  ruleset-manifest.json\n",
                encoding="ascii",
                newline="\n",
            )
            sbom = {
                "metadata": {
                    "component": {
                        "properties": [
                            {"name": "cag:source:git-commit", "value": COMMIT},
                            {"name": "cag:source:git-tree", "value": TREE},
                            {"name": "cag:build:kind", "value": "candidate"},
                        ]
                    }
                }
            }
            (root / "sbom.cdx.json").write_bytes(canonical_bytes(sbom) + b"\n")
            checksummed = (
                CAG_SO_NAME,
                CAG_SO_NAME + ".sha256",
                zip_name,
                "build-metadata.json",
                "ruleset-manifest.json",
                "ruleset.sha256",
                "sbom.cdx.json",
            )
            checksums = b"".join(
                f"{hashlib.sha256((root / name).read_bytes()).hexdigest()}  {name}\n".encode("ascii")
                for name in checksummed
            )
            (root / "checksums.txt").write_bytes(checksums)
            artifacts = [
                {
                    "bytes": (root / name).stat().st_size,
                    "name": name,
                    "sha256": hashlib.sha256((root / name).read_bytes()).hexdigest(),
                }
                for name in checksummed + ("checksums.txt",)
            ]
            manifest = {
                "artifacts": artifacts,
                "commit": COMMIT,
                "dirty": False,
                "event": "push",
                "head_branch": "main",
                "head_sha": COMMIT,
                "repository": "yujianwudi/cyber-abuse-guard-next",
                "run_attempt": "1",
                "run_id": "1001",
                "schema": "cyber-abuse-guard.audit-candidate-manifest.v1",
                "status": "UNRELEASED / SECOND-MACHINE AUDIT CANDIDATE / NOT RELEASE",
                "tree": TREE,
                "version": "1.0.0",
                "workflow_name": "CI",
                "workflow_path": ".github/workflows/ci.yml",
            }
            (root / "audit-candidate-manifest.json").write_bytes(canonical_bytes(manifest) + b"\n")
            self.assertEqual(len(validate_candidate_directory(root, manifest)), 9)
            (root / "cyber-abuse-guard-v1.0.0-rc.1.so").write_bytes(so)
            with self.assertRaises(AdmissionError):
                validate_candidate_directory(root, manifest)

    def assert_rejected(self, mutate, *, when: datetime = NOW) -> None:  # type: ignore[no-untyped-def]
        report = valid_report()
        mutate(report)
        with self.assertRaises(AdmissionError):
            validate_report(report, now=when, expected=expected())

    def test_rejects_unknown_key_and_fabricated_summary(self) -> None:
        self.assert_rejected(lambda report: report.__setitem__("operator_note", "trust me"))
        self.assert_rejected(lambda report: report["summary"].__setitem__("false_positives", 1))  # type: ignore[union-attr]

    def test_rejects_wrong_commit_tree_or_so(self) -> None:
        self.assert_rejected(lambda report: report["source"].__setitem__("commit", "9" * 40))  # type: ignore[union-attr]
        self.assert_rejected(lambda report: report["source"].__setitem__("tree", "9" * 40))  # type: ignore[union-attr]
        self.assert_rejected(lambda report: report["source"]["so"].__setitem__("sha256", "9" * 64))  # type: ignore[index,union-attr]

    def test_rejects_rc_renamed_or_recompiled_so_identity(self) -> None:
        self.assert_rejected(lambda report: report["source"]["so"].__setitem__("name", "cyber-abuse-guard-v1.0.0-rc.1.so"))  # type: ignore[index,union-attr]

    def test_rejects_wrong_nine_file_set(self) -> None:
        self.assert_rejected(lambda report: report["candidate"]["files"].pop())  # type: ignore[index,union-attr]
        self.assert_rejected(lambda report: report["candidate"]["files"][0].__setitem__("name", "extra.so"))  # type: ignore[index,union-attr]

    def test_rejects_wrong_candidate_api_coordinates(self) -> None:
        self.assert_rejected(lambda report: report["candidate"]["github_artifact"].__setitem__("id", 9999))  # type: ignore[index,union-attr]
        self.assert_rejected(lambda report: report["candidate"]["github_artifact"].__setitem__("digest", "sha256:" + "9" * 64))  # type: ignore[index,union-attr]

    def test_rejects_expired_or_nonfixed_lifetime(self) -> None:
        with self.assertRaises(AdmissionError):
            validate_report(valid_report(), now=NOW + REPORT_TTL + timedelta(seconds=1), expected=expected())
        self.assert_rejected(lambda report: report.__setitem__("expires_at", (NOW + timedelta(hours=48)).isoformat().replace("+00:00", "Z")))

    def test_remaining_validity_covers_publish_timeout_and_clock_margin(self) -> None:
        required = timedelta(minutes=25)
        boundary = NOW + REPORT_TTL - required
        self.assertEqual(
            validate_report(
                valid_report(),
                now=boundary,
                minimum_remaining=required,
                expected=expected(),
            )["status"],
            STATUS,
        )
        with self.assertRaisesRegex(AdmissionError, "required remaining validity"):
            validate_report(
                valid_report(),
                now=boundary + timedelta(seconds=1),
                minimum_remaining=required,
                expected=expected(),
            )

    def test_revalidation_mock_clock_crosses_expiry(self) -> None:
        report = valid_report()
        validate_report(
            report,
            now=NOW + REPORT_TTL - timedelta(seconds=1),
            expected=expected(),
        )
        with self.assertRaisesRegex(AdmissionError, "validity window"):
            validate_report(
                report,
                now=NOW + REPORT_TTL + timedelta(seconds=1),
                expected=expected(),
            )

    def test_rejects_false_positive_missed_recall_or_side_effect(self) -> None:
        self.assert_rejected(lambda report: report["semantic"]["outcomes"][3].__setitem__("false_positive", True))  # type: ignore[index,union-attr]
        self.assert_rejected(lambda report: report["semantic"]["outcomes"][0].__setitem__("malicious_detected", False))  # type: ignore[index,union-attr]
        self.assert_rejected(lambda report: report["semantic"]["outcomes"][0].__setitem__("side_effect_violations", 1))  # type: ignore[index,union-attr]

    def test_rejects_failed_or_tampered_performance_gate(self) -> None:
        metric = next(name for name, (operator, _) in THRESHOLDS.items() if operator in ("<=", "<"))
        limit = THRESHOLDS[metric][1]

        def mutate(report) -> None:  # type: ignore[no-untyped-def]
            report["performance"]["metrics"][metric] = limit + 1.0
            report["performance"]["gates"][metric] = _performance_gate(metric, limit + 1.0)

        self.assert_rejected(mutate)
        self.assert_rejected(lambda report: report["performance"]["gates"][metric].__setitem__("status", "PASS" if report["performance"]["gates"][metric]["status"] == "FAIL" else "FAIL"))  # type: ignore[index,union-attr]

    def test_rejects_tool_bundle_drift(self) -> None:
        self.assert_rejected(lambda report: report["tool_bundles"]["admission"].__setitem__("source_sha256", "0" * 64))  # type: ignore[index,union-attr]

    def test_packer_reuses_full_validators_before_emitting(self) -> None:
        source = (TOOL / "second_machine_release_admission.py").read_text("utf-8")
        for marker in (
            "validate_machine_evidence(manifest, machine, args.results)",
            "validate_evidence_run_config(machine, run_config, run_config_raw)",
            "validate_candidate_manifest_file(run_config)",
            "validate_measurements(",
            "validate_evidence_bundle(",
            "require_pass=True",
            "validate_candidate_directory(",
        ):
            self.assertIn(marker, source)

    @unittest.skipIf(Draft202012Validator is None, "jsonschema is not installed")
    def test_report_validates_against_closed_json_schema(self) -> None:
        schema = json.loads((TOOL / "second-machine-release-admission.schema.json").read_text("utf-8"))
        Draft202012Validator.check_schema(schema)
        errors = list(Draft202012Validator(schema).iter_errors(valid_report()))
        self.assertEqual(errors, [], "\n".join(error.message for error in errors))

        def assert_closed(value: object, path: str = "$") -> None:
            if isinstance(value, dict):
                if value.get("type") == "object":
                    self.assertIs(value.get("additionalProperties"), False, path)
                for key, child in value.items():
                    assert_closed(child, f"{path}/{key}")
            elif isinstance(value, list):
                for index, child in enumerate(value):
                    assert_closed(child, f"{path}/{index}")

        assert_closed(schema)


if __name__ == "__main__":
    unittest.main()
