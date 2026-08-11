from __future__ import annotations

import copy
import hashlib
import io
import json
import os
import struct
import sys
import tempfile
import unittest
import zipfile
from unittest import mock
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
    ContractError,
    EXPECTED_SUPPLEMENTAL_ZIP_CASE_COUNT,
    MAX_COLD_STARTS,
    MIN_COLD_STARTS,
    MODES,
    PROTOCOLS,
    STREAM_VALUES,
    SUPPLEMENTAL_ZIP_ARCHIVE_IDENTITY,
    SUPPLEMENTAL_ZIP_POLICY_SHA256,
    candidate_identity,
    canonical_bytes,
)
from host_performance import EVIDENCE_SCHEMA, THRESHOLDS  # noqa: E402
import native_host_special_paths as native  # noqa: E402
from second_machine_release_admission import (  # noqa: E402
    AdmissionError,
    BOUNDARY,
    EXPECTED_CANDIDATE_FILES,
    EXPECTED_CORE_EXECUTIONS,
    EXPECTED_SUPPLEMENTAL_CASE_IDS,
    EXPECTED_SUPPLEMENTAL_EXECUTIONS,
    INPUT_HASH_KEYS,
    REPORT_TTL,
    SCHEMA,
    STATUS,
    SUPPLEMENTAL_STATUS,
    _performance_gate,
    build_report,
    derive_semantic_summary,
    derive_supplemental_summary,
    derive_summary,
    local_tool_identities,
    main,
    validate_supplemental_evidence_copies,
    validate_report,
    validate_candidate_directory,
)
from fixtures import (  # noqa: E402
    audit_candidate_manifest,
    evidence_files,
    supplemental_manifest_fixture,
)


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
    supplemental_outcomes = []
    for case_id in EXPECTED_SUPPLEMENTAL_CASE_IDS:
        suffix = case_id.rsplit(":", 1)[1]
        malicious = suffix == "activated"
        label = {
            "activated": "malicious_active",
            "authorized-ctf": "authorized_security",
            "defensive": "defensive_context",
        }[suffix]
        for mode in MODES:
            actual = (
                "block_malicious_text"
                if malicious and mode in {"balanced", "strict"}
                else "allow"
            )
            supplemental_outcomes.append(
                {
                    "actual_action": actual,
                    "all_executions_passed": True,
                    "execution_count": 12,
                    "expected_action": actual,
                    "false_positive": False,
                    "label": label,
                    "malicious": malicious,
                    "malicious_detected": malicious,
                    "mode": mode,
                    "side_effect_violations": 0,
                    "supplemental_case_id": case_id,
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
        "native_host_special_paths": {
            "candidate": {
                "artifact_digest": "sha256:" + "5" * 64,
                "artifact_id": 2002,
                "artifact_size": 123456,
                "manifest_sha256": MANIFEST_SHA,
                "run_attempt": 1,
                "run_id": 1001,
                "so_sha256": SO_SHA,
                "source_commit": COMMIT,
                "source_tree": TREE,
            },
            "cpa_commit": CPA_COMMIT,
            "cpa_tag": CPA_TAG,
            "critical_test_count": len(native.CRITICAL_SUBTESTS),
            "critical_tests_sha256": hashlib.sha256(
                canonical_bytes(native.expected_critical_tests())
            ).hexdigest(),
            "fail_count": 0,
            "go_test_log_sha256": "f" * 64,
            "go_version": native.GO_VERSION,
            "observed_test_count": len(native.CRITICAL_SUBTESTS) + 1,
            "platform": native.PLATFORM,
            "report_schema": native.SCHEMA,
            "report_sha256": "0" * 64,
            "required_test_count": len(native.CRITICAL_SUBTESTS) + 1,
            "schema_sha256": local_tool_identities()["native_host_special_paths"][
                "schema_sha256"
            ],
            "skip_count": 0,
            "source_sha256": local_tool_identities()["native_host_special_paths"][
                "source_sha256"
            ],
            "status": native.STATUS,
            "test_source_sha256": local_tool_identities()["native_host_special_paths"][
                "test_source_sha256"
            ],
        },
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
        "supplemental_archive": {
            "archive": {
                "bytes": SUPPLEMENTAL_ZIP_ARCHIVE_IDENTITY["bytes"],
                "sha256": SUPPLEMENTAL_ZIP_ARCHIVE_IDENTITY["sha256"],
            },
            "case_count": 7,
            "code_executions": 0,
            "entry_count": 4,
            "input_archive_preserved": True,
            "manifest_sha256": "2" * 64,
            "member_text_files_created": 0,
            "member_text_files_removed": 0,
            "member_text_retained": False,
            "outcomes": supplemental_outcomes,
            "policy_sha256": SUPPLEMENTAL_ZIP_POLICY_SHA256,
            "results_sha256": "3" * 64,
            "side_effect_violations": 0,
            "status": SUPPLEMENTAL_STATUS,
            "summary_by_mode": derive_supplemental_summary(supplemental_outcomes),
            "third_party_code_executions": 0,
            "total_executions": EXPECTED_SUPPLEMENTAL_EXECUTIONS,
        },
        "summary": {},
        "tool_bundles": local_tool_identities(),
    }
    report["inputs"]["candidate_manifest_sha256"] = MANIFEST_SHA  # type: ignore[index]
    report["inputs"]["corpus_manifest_sha256"] = "6" * 64  # type: ignore[index]
    report["inputs"]["supplemental_archive_sha256"] = SUPPLEMENTAL_ZIP_ARCHIVE_IDENTITY["sha256"]  # type: ignore[index]
    report["inputs"]["supplemental_manifest_sha256"] = "2" * 64  # type: ignore[index]
    report["inputs"]["supplemental_policy_sha256"] = SUPPLEMENTAL_ZIP_POLICY_SHA256  # type: ignore[index]
    report["inputs"]["supplemental_results_sha256"] = "3" * 64  # type: ignore[index]
    report["inputs"]["native_host_special_paths_report_sha256"] = "0" * 64  # type: ignore[index]
    report["inputs"]["native_host_go_test_log_sha256"] = "f" * 64  # type: ignore[index]
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
                cag_identity=cag,
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
            supplemental_manifest, _supplemental_policy, supplemental_policy_raw = (
                supplemental_manifest_fixture()
            )
            supplemental_manifest_raw = canonical_bytes(supplemental_manifest) + b"\n"
            supplemental_results_raw = (
                Path(directory) / "supplemental-zip-results.jsonl"
            ).read_bytes()
            native_go_test_raw = b'{"Action":"pass"}\n'
            native_report = {
                "candidate": {
                    "artifact": {
                        "digest": candidate["artifact"]["digest"],
                        "id": int(candidate["artifact"]["id"]),
                        "name": candidate["artifact"]["name"],
                        "run_attempt": int(candidate["run_attempt"]),
                        "run_id": int(candidate["run_id"]),
                        "size": 123456,
                    },
                    "manifest_sha256": hashlib.sha256(candidate_raw).hexdigest(),
                    "so": {"sha256": cag["so_sha256"]},
                    "source": {"commit": cag["commit"], "tree": cag["tree"]},
                },
                "cpa": {"commit": CPA_COMMIT, "tag": CPA_TAG},
                "execution": {
                    "critical_tests": native.expected_critical_tests(),
                    "fail_count": 0,
                    "observed_test_count": len(native.CRITICAL_SUBTESTS) + 1,
                    "required_test_count": len(native.CRITICAL_SUBTESTS) + 1,
                    "skip_count": 0,
                },
                "runtime": {"go_version": native.GO_VERSION, "platform": native.PLATFORM},
                "schema": native.SCHEMA,
                "status": native.STATUS,
                "test_log": {"sha256": hashlib.sha256(native_go_test_raw).hexdigest()},
                "test_source": {
                    "sha256": local_tool_identities()["native_host_special_paths"][
                        "test_source_sha256"
                    ]
                },
                "tool": native.tool_identity(),
            }
            native_report_raw = canonical_bytes(native_report) + b"\n"

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
                    native_go_test_raw=native_go_test_raw,
                    native_report=native_report,
                    native_report_raw=native_report_raw,
                    performance=performance,
                    performance_raw=canonical_bytes(performance) + b"\n",
                    supplemental_archive_binding={
                        "bytes": SUPPLEMENTAL_ZIP_ARCHIVE_IDENTITY["bytes"],
                        "sha256": SUPPLEMENTAL_ZIP_ARCHIVE_IDENTITY["sha256"],
                    },
                    supplemental_manifest=supplemental_manifest,
                    supplemental_manifest_raw=supplemental_manifest_raw,
                    supplemental_policy_raw=supplemental_policy_raw,
                    supplemental_results_raw=supplemental_results_raw,
                    generated_at=NOW,
                )

            report = pack(results_raw)
            self.assertEqual(report["status"], STATUS)
            self.assertEqual(report["source"]["so"]["name"], CAG_SO_NAME)
            self.assertEqual(report["summary"]["performance_gate_count"], len(THRESHOLDS))
            self.assertEqual(
                sum(item["execution_count"] for item in report["semantic"]["outcomes"]),
                EXPECTED_CORE_EXECUTIONS,
            )
            self.assertEqual(
                report["supplemental_archive"]["total_executions"],
                EXPECTED_SUPPLEMENTAL_EXECUTIONS,
            )

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
            original_infolist = zipfile.ZipFile.infolist

            def oversized_member(archive: zipfile.ZipFile) -> list[zipfile.ZipInfo]:
                members = original_infolist(archive)
                members[0].file_size = len(so) + 1
                return members

            with mock.patch.object(
                zipfile.ZipFile, "infolist", new=oversized_member
            ), self.assertRaisesRegex(AdmissionError, "declared size"):
                validate_candidate_directory(root, manifest)

            (root / "cyber-abuse-guard-v1.0.0-rc.1.so").write_bytes(so)
            with self.assertRaises(AdmissionError):
                validate_candidate_directory(root, manifest)

    def test_supplemental_evidence_copies_may_live_outside_original_directories(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original = root / "operator-inputs"
            evidence = root / "machine-evidence"
            original.mkdir()
            evidence.mkdir()
            manifest, policy, policy_raw = supplemental_manifest_fixture()
            manifest_raw = canonical_bytes(manifest) + b"\n"
            original_manifest = original / "supplemental-zip-manifest.json"
            original_policy = original / "supplemental-zip-policy.json"
            evidence_manifest = evidence / "supplemental-zip-manifest.json"
            evidence_policy = evidence / "supplemental-zip-policy.json"
            original_manifest.write_bytes(manifest_raw)
            original_policy.write_bytes(policy_raw)
            evidence_manifest.write_bytes(manifest_raw)
            evidence_policy.write_bytes(policy_raw)
            self.assertNotEqual(original_manifest.parent, evidence_manifest.parent)

            validate_supplemental_evidence_copies(
                original_manifest=json.loads(original_manifest.read_bytes()),
                original_manifest_raw=original_manifest.read_bytes(),
                original_policy=json.loads(original_policy.read_bytes()),
                original_policy_raw=original_policy.read_bytes(),
                evidence_manifest_path=evidence_manifest,
                evidence_policy_path=evidence_policy,
            )

            changed = copy.deepcopy(manifest)
            changed["acquired_at"] = "2026-08-10T00:00:00Z"
            evidence_manifest.write_bytes(canonical_bytes(changed) + b"\n")
            with self.assertRaisesRegex(AdmissionError, "evidence copies differ"):
                validate_supplemental_evidence_copies(
                    original_manifest=manifest,
                    original_manifest_raw=manifest_raw,
                    original_policy=policy,
                    original_policy_raw=policy_raw,
                    evidence_manifest_path=evidence_manifest,
                    evidence_policy_path=evidence_policy,
                )
            evidence_manifest.write_bytes(manifest_raw)
            os.link(evidence_manifest, evidence / "manifest-hardlink.json")
            with self.assertRaises(ContractError):
                validate_supplemental_evidence_copies(
                    original_manifest=manifest,
                    original_manifest_raw=manifest_raw,
                    original_policy=policy,
                    original_policy_raw=policy_raw,
                    evidence_manifest_path=evidence_manifest,
                    evidence_policy_path=evidence_policy,
                )

    def test_archive_reverification_precedes_report_write(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "second-machine-release-admission.json"
            archive = root / "supplemental.zip"
            report = valid_report()
            values: dict[str, Any] = {
                "supplemental_archive_binding": {
                    "bytes": SUPPLEMENTAL_ZIP_ARCHIVE_IDENTITY["bytes"],
                    "sha256": SUPPLEMENTAL_ZIP_ARCHIVE_IDENTITY["sha256"],
                },
                "supplemental_archive_path": archive,
            }

            def fail_before_write(*_args, **_kwargs) -> None:  # type: ignore[no-untyped-def]
                self.assertFalse(output.exists())
                raise AdmissionError("supplemental archive drift")

            arguments = [
                "pack",
                "--manifest", "unused",
                "--evidence", "unused",
                "--results", "unused",
                "--run-config", "unused",
                "--candidate-manifest", "unused",
                "--candidate-artifact-size", "1",
                "--supplemental-archive", "unused",
                "--supplemental-manifest", "unused",
                "--supplemental-policy", "unused",
                "--supplemental-results", "unused",
                "--native-report", "unused",
                "--native-go-test-jsonl", "unused",
                "--checkout", "unused",
                "--workload-manifest", "unused",
                "--performance-config", "unused",
                "--measurements", "unused",
                "--performance-evidence", "unused",
                "--output", str(output),
            ]
            module = main.__module__
            with (
                mock.patch(f"{module}.load_validated_inputs", return_value=dict(values)),
                mock.patch(f"{module}.build_report", return_value=report),
                mock.patch(
                    f"{module}.reverify_supplemental_archive",
                    side_effect=fail_before_write,
                ),
                mock.patch("sys.stderr"),
                mock.patch("sys.stdout", new_callable=io.StringIO) as stdout,
            ):
                self.assertEqual(main(arguments), 2)
            self.assertFalse(output.exists())
            self.assertEqual(stdout.getvalue(), "")

            def pass_before_write(*_args, **_kwargs) -> None:  # type: ignore[no-untyped-def]
                self.assertFalse(output.exists())

            with (
                mock.patch(f"{module}.load_validated_inputs", return_value=dict(values)),
                mock.patch(f"{module}.build_report", return_value=report),
                mock.patch(
                    f"{module}.reverify_supplemental_archive",
                    side_effect=pass_before_write,
                ),
                mock.patch("sys.stdout", new_callable=io.StringIO) as stdout,
            ):
                self.assertEqual(main(arguments), 0)
            expected_raw = canonical_bytes(report) + b"\n"
            self.assertEqual(
                output.read_bytes(), expected_raw
            )
            self.assertEqual(
                stdout.getvalue(),
                json.dumps(
                    {
                        "report_sha256": hashlib.sha256(expected_raw).hexdigest(),
                        "status": report["status"],
                        "valid": True,
                    },
                    sort_keys=True,
                )
                + "\n",
            )

    def assert_rejected(self, mutate, *, when: datetime = NOW) -> None:  # type: ignore[no-untyped-def]
        report = valid_report()
        mutate(report)
        with self.assertRaises(AdmissionError):
            validate_report(report, now=when, expected=expected())

    def test_rejects_unknown_key_and_fabricated_summary(self) -> None:
        self.assert_rejected(lambda report: report.__setitem__("operator_note", "trust me"))
        self.assert_rejected(lambda report: report.__setitem__("schema", "cyber-abuse-guard.second-machine-release-admission.v1"))
        self.assert_rejected(lambda report: report["supplemental_archive"].__setitem__("operator_note", "trust me"))  # type: ignore[union-attr]
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

    def test_rejects_core_and_supplemental_denominator_blending(self) -> None:
        self.assert_rejected(lambda report: report["semantic"]["outcomes"][0].__setitem__("execution_count", 13))  # type: ignore[index,union-attr]
        self.assert_rejected(lambda report: report["supplemental_archive"].__setitem__("total_executions", EXPECTED_CORE_EXECUTIONS + EXPECTED_SUPPLEMENTAL_EXECUTIONS))  # type: ignore[union-attr]
        self.assert_rejected(lambda report: report["supplemental_archive"]["outcomes"][0].__setitem__("execution_count", 11))  # type: ignore[index,union-attr]

    def test_rejects_supplemental_hash_count_status_and_safety_drift(self) -> None:
        self.assert_rejected(lambda report: report["supplemental_archive"]["archive"].__setitem__("sha256", "9" * 64))  # type: ignore[index,union-attr]
        self.assert_rejected(lambda report: report["supplemental_archive"].__setitem__("manifest_sha256", "9" * 64))  # type: ignore[union-attr]
        self.assert_rejected(lambda report: report["supplemental_archive"].__setitem__("entry_count", 5))  # type: ignore[union-attr]
        self.assert_rejected(lambda report: report["supplemental_archive"].__setitem__("case_count", 8))  # type: ignore[union-attr]
        self.assert_rejected(lambda report: report["supplemental_archive"].__setitem__("status", "PASS"))  # type: ignore[union-attr]
        self.assert_rejected(lambda report: report["supplemental_archive"].__setitem__("member_text_retained", True))  # type: ignore[union-attr]
        self.assert_rejected(lambda report: report["supplemental_archive"].__setitem__("third_party_code_executions", 1))  # type: ignore[union-attr]

    def test_rejects_supplemental_false_positive_recall_and_audit_blocking(self) -> None:
        benign = next(
            item
            for item in valid_report()["supplemental_archive"]["outcomes"]  # type: ignore[index,union-attr]
            if not item["malicious"]
        )
        benign_id = benign["supplemental_case_id"]
        malicious_id = next(
            item["supplemental_case_id"]
            for item in valid_report()["supplemental_archive"]["outcomes"]  # type: ignore[index,union-attr]
            if item["malicious"] and item["mode"] == "balanced"
        )
        audit_id = next(
            item["supplemental_case_id"]
            for item in valid_report()["supplemental_archive"]["outcomes"]  # type: ignore[index,union-attr]
            if item["malicious"] and item["mode"] == "audit"
        )

        def mutate_case(report, case_id, mode, key, value) -> None:  # type: ignore[no-untyped-def]
            row = next(
                item
                for item in report["supplemental_archive"]["outcomes"]
                if item["supplemental_case_id"] == case_id and item["mode"] == mode
            )
            row[key] = value

        self.assert_rejected(lambda report: mutate_case(report, benign_id, "audit", "false_positive", True))
        self.assert_rejected(lambda report: mutate_case(report, malicious_id, "balanced", "malicious_detected", False))
        self.assert_rejected(lambda report: mutate_case(report, audit_id, "audit", "actual_action", "block_malicious_text"))

    def test_rejects_native_report_log_tool_candidate_test_and_status_drift(self) -> None:
        self.assert_rejected(lambda report: report["native_host_special_paths"].__setitem__("report_sha256", "9" * 64))  # type: ignore[union-attr]
        self.assert_rejected(lambda report: report["native_host_special_paths"].__setitem__("go_test_log_sha256", "9" * 64))  # type: ignore[union-attr]
        self.assert_rejected(lambda report: report["native_host_special_paths"].__setitem__("source_sha256", "9" * 64))  # type: ignore[union-attr]
        self.assert_rejected(lambda report: report["native_host_special_paths"].__setitem__("test_source_sha256", "9" * 64))  # type: ignore[union-attr]
        self.assert_rejected(lambda report: report["native_host_special_paths"].__setitem__("critical_tests_sha256", "9" * 64))  # type: ignore[union-attr]
        self.assert_rejected(lambda report: report["native_host_special_paths"]["candidate"].__setitem__("source_commit", "9" * 40))  # type: ignore[index,union-attr]
        self.assert_rejected(lambda report: report["native_host_special_paths"].__setitem__("critical_test_count", 34))  # type: ignore[union-attr]
        self.assert_rejected(lambda report: report["native_host_special_paths"].__setitem__("required_test_count", 35))  # type: ignore[union-attr]
        self.assert_rejected(lambda report: report["native_host_special_paths"].__setitem__("fail_count", 1))  # type: ignore[union-attr]
        self.assert_rejected(lambda report: report["native_host_special_paths"].__setitem__("status", "PASS"))  # type: ignore[union-attr]

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
            "validate_machine_evidence(",
            "validate_evidence_run_config(machine, run_config, run_config_raw)",
            "validate_supplemental_run_config_files(run_config)",
            "create_supplemental_manifest(",
            "supplemental_manifest_path=args.supplemental_manifest",
            "supplemental_policy_path=args.supplemental_policy",
            "supplemental_results_path=args.supplemental_results",
            "native.validate_bundle(",
            "checkout=checkout",
            "go_test_jsonl=native_go_test_path",
            'pack.add_argument("--supplemental-archive", type=Path, required=True)',
            'pack.add_argument("--supplemental-manifest", type=Path, required=True)',
            'pack.add_argument("--supplemental-policy", type=Path, required=True)',
            'pack.add_argument("--supplemental-results", type=Path, required=True)',
            'pack.add_argument("--native-report", type=Path, required=True)',
            'pack.add_argument("--native-go-test-jsonl", type=Path, required=True)',
            'pack.add_argument("--checkout", type=Path, required=True)',
            "validate_candidate_manifest_file(run_config)",
            "validate_measurements(",
            "validate_evidence_bundle(",
            "require_pass=True",
            "validate_candidate_directory(",
        ):
            self.assertIn(marker, source)

    @unittest.skipIf(Draft202012Validator is None, "jsonschema is not installed")
    def test_json_schema_execution_bounds_track_cold_start_contract(self) -> None:
        schema = json.loads((TOOL / "second-machine-release-admission.schema.json").read_text("utf-8"))
        transport_multiplier = len(PROTOCOLS) * len(STREAM_VALUES)
        minimum_per_outcome = transport_multiplier * MIN_COLD_STARTS
        maximum_per_outcome = transport_multiplier * MAX_COLD_STARTS
        supplemental_cell_count = EXPECTED_SUPPLEMENTAL_ZIP_CASE_COUNT * len(MODES)
        minimum_supplemental_total = supplemental_cell_count * minimum_per_outcome
        maximum_supplemental_total = supplemental_cell_count * maximum_per_outcome
        contracts = (
            (
                "outcome.execution_count",
                schema["$defs"]["outcome"]["properties"]["execution_count"],
                minimum_per_outcome,
                maximum_per_outcome,
            ),
            (
                "supplemental_outcome.execution_count",
                schema["$defs"]["supplemental_outcome"]["properties"]["execution_count"],
                minimum_per_outcome,
                maximum_per_outcome,
            ),
            (
                "supplemental_archive.total_executions",
                schema["$defs"]["supplemental_archive"]["properties"]["total_executions"],
                minimum_supplemental_total,
                maximum_supplemental_total,
            ),
        )

        for label, contract, minimum, maximum in contracts:
            with self.subTest(label=label):
                self.assertEqual(
                    contract,
                    {"maximum": maximum, "minimum": minimum, "type": "integer"},
                )
                validator = Draft202012Validator(contract)
                self.assertTrue(validator.is_valid(minimum), "minimum must be accepted")
                self.assertTrue(validator.is_valid(maximum), "maximum must be accepted")
                self.assertFalse(
                    validator.is_valid(minimum - 1), "value below minimum must be rejected"
                )
                self.assertFalse(
                    validator.is_valid(maximum + 1), "value above maximum must be rejected"
                )

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
