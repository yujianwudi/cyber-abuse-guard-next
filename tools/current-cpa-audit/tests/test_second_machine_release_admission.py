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
    REALTIME_ROUTE_CONTRACT,
    REALTIME_RPC_COUNTER_KEYS,
    CAG_SO_NAME,
    CAG_SOURCE_VERSION,
    CPA_C_ABI,
    CPA_COMMIT,
    CPA_OFFICIAL_ASSET_NAME,
    CPA_OFFICIAL_ASSET_SHA256,
    CPA_OFFICIAL_BINARY_SHA256,
    CPA_RPC_SCHEMA,
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
import host_admission as host  # noqa: E402
import test_host_admission as host_fixture  # noqa: E402
from second_machine_release_admission import (  # noqa: E402
    AdmissionError,
    BOUNDARY,
    CSAM_BENIGN_FAMILIES,
    CSAM_MALICIOUS_FAMILIES,
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
    derive_supplemental_semantics,
    derive_supplemental_summary,
    derive_summary,
    local_tool_identities,
    main,
    validate_supplemental_evidence_copies,
    validate_report,
    validate_csam_text_evidence,
    validate_lazy_read_evidence,
    validate_lazy_read_bindings,
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
_MISSING = object()


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


def lazy_read_fixture(
    run_id: str = host_fixture.RUN_ID,
) -> tuple[dict[str, Any], bytes, dict[str, Any]]:
    rows = [
        {
            "bytes": 10,
            "case_id_hash": "1" * 64,
            "ordinal": 1,
            "phase": "preflight",
            "request_sha256": None,
            "run_id": run_id,
            "schema": "cag-current-cpa-lazy-read-trace/v1",
            "source_path": "corpus/source-one.txt",
            "source_sha256": "2" * 64,
        },
        {
            "bytes": 10,
            "case_id_hash": "3" * 64,
            "ordinal": 2,
            "phase": "transport",
            "request_sha256": "4" * 64,
            "run_id": run_id,
            "schema": "cag-current-cpa-lazy-read-trace/v1",
            "source_path": "corpus/source-one.txt",
            "source_sha256": "2" * 64,
        },
    ]
    trace = b"".join(canonical_bytes(row) + b"\n" for row in rows)
    phase = {
        "preflight_completed": True,
        "preflight_full_corpus_cache_created": False,
        "run_id": run_id,
        "schema": "cag-current-cpa-lazy-read-phase-boundary/v1",
        "status": "PASS",
        "transport_started_after_preflight": True,
    }
    summary = {
        "finally_cleanup_complete": True,
        "full_corpus_cache_created": False,
        "post_unlink_nlink_zero": True,
        "run_id": run_id,
        "schema": "cag-current-cpa-lazy-read-summary/v1",
        "status": "PASS",
        "supplemental_member_text_retained": False,
        "temporary_secret_or_config_retained": False,
        "third_party_text_retained": False,
        "trace_sha256": hashlib.sha256(trace).hexdigest(),
        "transport_request_count": 1,
        "transport_source_read_count": 1,
    }
    return phase, trace, summary


def csam_text_fixture(
    run_id: str = host_fixture.RUN_ID,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    cases = [
        {
            "case_id": f"csam-malicious-{family}-{variant}",
            "label": "malicious",
            "text_sha256": f"{index:064x}",
        }
        for index, (family, variant) in enumerate(
            (
                (family, variant)
                for family in CSAM_MALICIOUS_FAMILIES
                for variant in range(1, 4)
            ),
            start=1,
        )
    ] + [
        {
            "case_id": f"csam-benign-{family}-{variant}",
            "label": "benign",
            "text_sha256": f"{index + 100:064x}",
        }
        for index, (family, variant) in enumerate(
            (
                (family, variant)
                for family in CSAM_BENIGN_FAMILIES
                for variant in range(1, 4)
            ),
            start=1,
        )
    ]
    rule_by_family = {
        family: f"CSAM-TXT-{family.upper()}-001"
        for family in CSAM_MALICIOUS_FAMILIES
    }
    manifest = {
        "benign_case_count": 21,
        "cases": cases,
        "fixture_text_retained": False,
        "malicious_case_count": 15,
        "real_or_explicit_media_inputs": 0,
        "run_id": run_id,
        "schema": "cag-current-cpa-csam-text-fixture-manifest/v1",
        "status": "PASS",
        "synthetic_text_only": True,
    }
    executions = []
    for case in cases:
        malicious = case["label"] == "malicious"
        for mode in MODES:
            for protocol in PROTOCOLS:
                for stream in STREAM_VALUES:
                    for cold_start in range(1, 4):
                        blocked = malicious and mode in {"balanced", "strict"}
                        executions.append({
                            "actual_action": "block_malicious_text" if blocked else "allow",
                            "case_id": case["case_id"],
                            "category": "csam_malicious" if malicious else None,
                            "cold_start": cold_start,
                            "mode": mode,
                            "protocol": protocol,
                            "request_sha256": hashlib.sha256(f"{case['case_id']}:{mode}:{protocol}:{stream}:{cold_start}".encode()).hexdigest(),
                            "side_effect_deltas": {key: 0 if blocked else 1 for key in ("auth", "mock", "provider", "usage")},
                            "stream": stream,
                            "text_retained": False,
                            "trusted_current_user": True,
                            "winning_rule_id": (
                                rule_by_family[case["case_id"].removeprefix("csam-malicious-").rsplit("-", 1)[0]]
                                if malicious
                                else None
                            ),
                        })
    results = {
        "audit_detected_malicious": 15,
        "audit_http_blocks": 0,
        "balanced_blocked_malicious": 15,
        "benign_allowed": 21,
        "cold_start_count": 3,
        "false_positive_count": 0,
        "malicious_case_count": 15,
        "executions": executions,
        "run_id": run_id,
        "schema": "cag-current-cpa-csam-text-results/v1",
        "side_effect_violations": 0,
        "status": "PASS",
        "strict_blocked_malicious": 15,
        "unexpected_errors": 0,
    }
    summary = {
        "audit_detection_percent": 100,
        "audit_http_block_percent": 0,
        "balanced_block_percent": 100,
        "benign_allow_percent": 100,
        "malicious_case_count": 15,
        "run_id": run_id,
        "schema": "cag-current-cpa-csam-text-summary/v1",
        "status": "PASS",
        "strict_block_percent": 100,
    }
    cleanup = {
        "fixture_text_retained": False,
        "real_or_explicit_media_inputs": 0,
        "reversible_encodings_retained": False,
        "run_id": run_id,
        "schema": "cag-current-cpa-csam-text-privacy-cleanup/v1",
        "status": "PASS",
        "synthetic_text_only": True,
    }
    return manifest, results, summary, cleanup


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
        malicious = suffix in {"activated", "authorized-ctf"}
        label = {
            "activated": "malicious_active",
            "authorized-ctf": "malicious_active",
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
                    "actual_winning_category": (
                        "defense_evasion"
                        if suffix == "authorized-ctf"
                        else "credential_theft"
                        if malicious
                        else None
                    ),
                    "actual_winning_rule_id": (
                        "META-OVERRIDE-001"
                        if suffix == "authorized-ctf"
                        else "CRED-001"
                        if malicious
                        else None
                    ),
                    "all_executions_passed": True,
                    "execution_count": 12,
                    "expected_action": actual,
                    "expected_winning_category": (
                        "defense_evasion" if suffix == "authorized-ctf" else None
                    ),
                    "expected_winning_rule_id": (
                        "META-OVERRIDE-001" if suffix == "authorized-ctf" else None
                    ),
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
            "c_abi": CPA_C_ABI,
            "commit": CPA_COMMIT,
            "image_id": "sha256:" + "7" * 64,
            "official_asset_name": CPA_OFFICIAL_ASSET_NAME,
            "official_asset_sha256": CPA_OFFICIAL_ASSET_SHA256,
            "repo_digest": "registry.example/cpa@sha256:" + "8" * 64,
            "rpc_schema": CPA_RPC_SCHEMA,
            "tag": CPA_TAG,
        },
        "expires_at": (NOW + REPORT_TTL).isoformat().replace("+00:00", "Z"),
        "generated_at": NOW.isoformat().replace("+00:00", "Z"),
        "inputs": {key: f"{(index % 6) + 9:x}" * 64 for index, key in enumerate(INPUT_HASH_KEYS)},
        "host_admission": {
            "candidate_artifact_digest": "sha256:" + "5" * 64,
            "candidate_manifest_sha256": MANIFEST_SHA,
            "claim_boundary": host.CLAIM_BOUNDARY,
            "cpa_commit": CPA_COMMIT,
            "cpa_rpc_schema": CPA_RPC_SCHEMA,
            "cpa_tag": CPA_TAG,
            "host_300s_sample_count": 301,
            "host_300s_samples_sha256": hashlib.sha256(host_fixture.RAW_300).hexdigest(),
            "host_3600s_sample_count": 3601,
            "host_3600s_samples_sha256": hashlib.sha256(host_fixture.RAW_3600).hexdigest(),
            "platform": "linux/amd64",
            "realtime_route_count": 14,
            "realtime_routes_sha256": hashlib.sha256(host_fixture.RAW_REALTIME_ROUTES).hexdigest(),
            "run_id": host_fixture.RUN_ID,
            "schema": host.SCHEMA,
            "so_sha256": SO_SHA,
            "source_commit": COMMIT,
            "source_tree": TREE,
            "status": host.STATUS,
            "store_zip_sha256": "7" * 64,
        },
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
            "cpa_abi": CPA_C_ABI,
            "cpa_commit": CPA_COMMIT,
            "cpa_rpc_schema": CPA_RPC_SCHEMA,
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
        "realtime": {
            "authenticated_dynamic_evidence": "NOT_PERFORMED_PROVIDER_SAFETY_BOUNDARY",
            "cag_visible": False,
            "cold_starts": [
                {
                    "cag_counters_after": {key: 0 for key in REALTIME_RPC_COUNTER_KEYS},
                    "cag_counters_before": {key: 0 for key in REALTIME_RPC_COUNTER_KEYS},
                    "cag_visible": False,
                    "cold_start": index,
                    "evidence_level": "AUTH_BOUNDARY_ONLY",
                    "event_head_after": "",
                    "event_head_before": "",
                    "mock_after": {"auth": 0, "mock": 0, "provider": 0},
                    "mock_before": {"auth": 0, "mock": 0, "provider": 0},
                    "protection": "unprotected",
                    "real_provider_calls": 0,
                    "routes": [
                        {
                            "auth": auth,
                            "cag_counter_delta": {
                                key: 0 for key in REALTIME_RPC_COUNTER_KEYS
                            },
                            "credential_kind": "NONE",
                            "method": method,
                            "probe_mode": "UNAUTHENTICATED",
                            "route": route,
                            "status": 401,
                            "termination": "AUTH_REJECTED",
                            "upgrade": False,
                        }
                        for method, route, auth in REALTIME_ROUTE_CONTRACT
                    ],
                    "target_boundary": {
                        "counted_mock_only": True,
                        "cpa_private_bridge_only": True,
                        "real_provider_forbidden": True,
                    },
                    "usage_records": 0,
                }
                for index in range(1, 4)
            ],
            "evidence_level": "AUTH_BOUNDARY_ONLY",
            "protection": "unprotected",
            "real_provider_calls": 0,
            "route_count": 14,
            "source_topology": "SOURCE_TOPOLOGY_UNPROTECTED",
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
    report["inputs"]["host_admission_300s_samples_sha256"] = report["host_admission"]["host_300s_samples_sha256"]  # type: ignore[index]
    report["inputs"]["host_admission_3600s_samples_sha256"] = report["host_admission"]["host_3600s_samples_sha256"]  # type: ignore[index]
    report["inputs"]["host_admission_realtime_routes_sha256"] = report["host_admission"]["realtime_routes_sha256"]  # type: ignore[index]
    report["host_admission"]["evidence_sha256"] = report["inputs"]["host_admission_evidence_sha256"]  # type: ignore[index]
    report["performance"]["config_sha256"] = report["inputs"]["host_performance_config_sha256"]  # type: ignore[index]
    report["performance"]["evidence_sha256"] = report["inputs"]["host_performance_evidence_sha256"]  # type: ignore[index]
    report["performance"]["measurements_sha256"] = report["inputs"]["host_performance_measurements_sha256"]  # type: ignore[index]
    lazy_phase, lazy_trace, lazy_summary = lazy_read_fixture()
    lazy_projection = validate_lazy_read_evidence(lazy_phase, lazy_trace, lazy_summary)
    csam_manifest, csam_results, csam_summary, csam_cleanup = csam_text_fixture()
    csam_projection = validate_csam_text_evidence(
        csam_manifest, csam_results, csam_summary, csam_cleanup
    )
    lazy_phase_raw = canonical_bytes(lazy_phase) + b"\n"
    lazy_summary_raw = canonical_bytes(lazy_summary) + b"\n"
    csam_manifest_raw = canonical_bytes(csam_manifest) + b"\n"
    csam_results_raw = canonical_bytes(csam_results) + b"\n"
    csam_summary_raw = canonical_bytes(csam_summary) + b"\n"
    csam_cleanup_raw = canonical_bytes(csam_cleanup) + b"\n"
    evidence_raws = {
        "lazy_read_phase_boundary_sha256": lazy_phase_raw,
        "lazy_read_runtime_read_trace_sha256": lazy_trace,
        "lazy_read_runtime_read_summary_sha256": lazy_summary_raw,
        "csam_text_fixture_manifest_sha256": csam_manifest_raw,
        "csam_text_results_sha256": csam_results_raw,
        "csam_text_summary_sha256": csam_summary_raw,
        "csam_text_privacy_cleanup_sha256": csam_cleanup_raw,
    }
    for key, raw in evidence_raws.items():
        report["inputs"][key] = hashlib.sha256(raw).hexdigest()  # type: ignore[index]
    report["evidence_refs"] = {
        "lazy_read": {
            **lazy_projection,
            "phase_boundary_path": "lazy-read/phase-boundary.json",
            "phase_boundary_sha256": report["inputs"]["lazy_read_phase_boundary_sha256"],  # type: ignore[index]
            "runtime_read_summary_path": "lazy-read/runtime-read-summary.json",
            "runtime_read_summary_sha256": report["inputs"]["lazy_read_runtime_read_summary_sha256"],  # type: ignore[index]
            "runtime_read_trace_path": "lazy-read/runtime-read-trace.jsonl",
            "runtime_read_trace_sha256": report["inputs"]["lazy_read_runtime_read_trace_sha256"],  # type: ignore[index]
        },
        "csam_text": {
            **csam_projection,
            "fixture_manifest_path": "csam-text/fixture-manifest.json",
            "fixture_manifest_sha256": report["inputs"]["csam_text_fixture_manifest_sha256"],  # type: ignore[index]
            "privacy_cleanup_path": "csam-text/privacy-cleanup.json",
            "privacy_cleanup_sha256": report["inputs"]["csam_text_privacy_cleanup_sha256"],  # type: ignore[index]
            "results_path": "csam-text/results.json",
            "results_sha256": report["inputs"]["csam_text_results_sha256"],  # type: ignore[index]
            "summary_path": "csam-text/summary.json",
            "summary_sha256": report["inputs"]["csam_text_summary_sha256"],  # type: ignore[index]
        },
    }
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
    def test_lazy_read_allows_duplicate_content_but_not_content_drift(self) -> None:
        phase, trace, summary = lazy_read_fixture()
        rows = [json.loads(raw) for raw in trace.splitlines()]
        duplicate = copy.deepcopy(rows[1])
        duplicate.update(
            {
                "case_id_hash": "5" * 64,
                "ordinal": 3,
                "source_path": "corpus/duplicate-approved-source.txt",
            }
        )
        rows.append(duplicate)
        duplicate_trace = b"".join(canonical_bytes(row) + b"\n" for row in rows)
        duplicate_summary = copy.deepcopy(summary)
        duplicate_summary.update(
            {
                "trace_sha256": hashlib.sha256(duplicate_trace).hexdigest(),
                "transport_request_count": 2,
                "transport_source_read_count": 2,
            }
        )
        self.assertEqual(
            validate_lazy_read_evidence(
                phase, duplicate_trace, duplicate_summary
            )["transport_request_count"],
            2,
        )

        duplicate["source_sha256"] = "6" * 64
        drift_trace = b"".join(
            canonical_bytes(row) + b"\n" for row in (*rows[:-1], duplicate)
        )
        drift_summary = copy.deepcopy(duplicate_summary)
        drift_summary["trace_sha256"] = hashlib.sha256(drift_trace).hexdigest()
        with self.assertRaisesRegex(AdmissionError, "different source content"):
            validate_lazy_read_evidence(phase, drift_trace, drift_summary)

    def test_required_evidence_planes_fail_closed(self) -> None:
        phase, trace, lazy_summary = lazy_read_fixture()
        self.assertEqual(
            validate_lazy_read_evidence(phase, trace, lazy_summary)["status"],
            "PASS",
        )
        duplicate = json.loads(trace.splitlines()[1])
        duplicate["ordinal"] = 3
        duplicate_trace = trace + canonical_bytes(duplicate) + b"\n"
        broken_summary = copy.deepcopy(lazy_summary)
        broken_summary["trace_sha256"] = hashlib.sha256(duplicate_trace).hexdigest()
        broken_summary["transport_source_read_count"] = 2
        with self.assertRaisesRegex(AdmissionError, "more than one source"):
            validate_lazy_read_evidence(phase, duplicate_trace, broken_summary)
        reversed_rows = []
        for ordinal, raw in enumerate(reversed(trace.splitlines()), start=1):
            row = json.loads(raw)
            row["ordinal"] = ordinal
            reversed_rows.append(canonical_bytes(row) + b"\n")
        reversed_trace = b"".join(reversed_rows)
        reversed_summary = copy.deepcopy(lazy_summary)
        reversed_summary["trace_sha256"] = hashlib.sha256(reversed_trace).hexdigest()
        with self.assertRaisesRegex(AdmissionError, "preflight trace occurs after"):
            validate_lazy_read_evidence(phase, reversed_trace, reversed_summary)

        csam_parts = csam_text_fixture()
        self.assertEqual(validate_csam_text_evidence(*csam_parts)["status"], "PASS")
        failed_results = copy.deepcopy(csam_parts[1])
        failed_results["balanced_blocked_malicious"] = 14
        with self.assertRaisesRegex(AdmissionError, "admission denominator"):
            validate_csam_text_evidence(
                csam_parts[0], failed_results, csam_parts[2], csam_parts[3]
            )

    def test_v2_cannot_bypass_required_evidence_refs(self) -> None:
        report = valid_report()
        report["schema"] = "cyber-abuse-guard.second-machine-release-admission.v2"
        report.pop("evidence_refs")
        with self.assertRaises(AdmissionError):
            validate_report(report, now=NOW, expected=expected())

    def test_missing_or_mutated_evidence_ref_is_rejected(self) -> None:
        report = valid_report()
        del report["evidence_refs"]["csam_text"]  # type: ignore[index]
        with self.assertRaises(AdmissionError):
            validate_report(report, now=NOW, expected=expected())
        report = valid_report()
        report["evidence_refs"]["lazy_read"]["status"] = "PENDING"  # type: ignore[index]
        with self.assertRaises(AdmissionError):
            validate_report(report, now=NOW, expected=expected())

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
                "cpa": {
                    "c_abi": CPA_C_ABI,
                    "commit": CPA_COMMIT,
                    "rpc_schema": CPA_RPC_SCHEMA,
                    "tag": CPA_TAG,
                },
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
            host_report = host_fixture.evidence()
            # The synthetic machine bundle uses its own deterministic run ID;
            # rebuild every run-bound Host input just as a real same-run
            # acquisition would. A top-level-only rewrite would create a bundle
            # that the Host validator can never accept.
            host_run_id = machine["run"]["run_id"]
            host_rows_300 = copy.deepcopy(host_fixture.ROWS_300)
            host_rows_3600 = copy.deepcopy(host_fixture.ROWS_3600)
            for row in (*host_rows_300, *host_rows_3600):
                row["run_id"] = host_run_id
            host_300s_raw = host_fixture.jsonl(host_rows_300)
            host_3600s_raw = host_fixture.jsonl(host_rows_3600)
            host_realtime_raw = host_fixture.RAW_REALTIME_ROUTES
            host_report["run_id"] = host_run_id
            host_report["tail_verification"]["run_id"] = host_run_id
            host_report["windows"][0]["samples_sha256"] = hashlib.sha256(host_300s_raw).hexdigest()
            host_report["windows"][1]["samples_sha256"] = hashlib.sha256(host_3600s_raw).hexdigest()
            host_report["tail_verification"]["host_3600s_samples_sha256"] = hashlib.sha256(host_3600s_raw).hexdigest()
            host_report["candidate"]["artifacts"]["candidate_artifact_digest"] = candidate["artifact"]["digest"]
            host_report["candidate"]["artifacts"]["candidate_manifest_sha256"] = hashlib.sha256(candidate_raw).hexdigest()
            host_report["candidate"]["cag"].update(
                {
                    "commit": cag["commit"],
                    "so_sha256": cag["so_sha256"],
                    "store_zip_sha256": next(
                        item["sha256"] for item in candidate_files
                        if item["name"] == f"cyber-abuse-guard_{CAG_SOURCE_VERSION}_linux_amd64.zip"
                    ),
                    "tree": cag["tree"],
                }
            )
            host_report["tail_verification"]["candidate_artifact_digest"] = candidate["artifact"]["digest"]
            host_report_raw = canonical_bytes(host_report) + b"\n"
            self.assertEqual(
                host.validate_host_admission(
                    host_report,
                    host_300s_raw,
                    host_3600s_raw,
                    host_realtime_raw,
                    copy.deepcopy(host_report["candidate"]),
                ),
                host_report,
            )
            lazy_phase, lazy_trace, lazy_summary = lazy_read_fixture("unit-run")
            core_rows = [json.loads(raw) for raw in results_raw.splitlines()]
            supplemental_rows = [json.loads(raw) for raw in supplemental_results_raw.splitlines()]
            core_cases = {case["id"]: case for case in manifest["semantic_cases"]}
            supplemental_cases = {
                case["id"]: case
                for case in supplemental_manifest["reviewed_cases"]
            }
            request_sources: list[tuple[str, str, str, int, str]] = []
            for row in core_rows:
                case_id = row["semantic_case_id"]
                source = core_cases[case_id]["source"]
                request_sources.append(
                    (
                        row["request_sha256"],
                        row["source_text_sha256"],
                        case_id,
                        source["text_bytes"],
                        source["corpus_file"],
                    )
                )
            for row in supplemental_rows:
                case_id = row["supplemental_case_id"]
                source = supplemental_cases[case_id]["source"]
                request_sources.append(
                    (
                        row["request_sha256"],
                        row["source_text_sha256"],
                        case_id,
                        source["text_bytes"],
                        "corpus/supplemental/"
                        + hashlib.sha256(
                            str(source["entry_id"]).encode("utf-8", "strict")
                        ).hexdigest(),
                    )
                )
            lazy_rows = [json.loads(raw) for raw in lazy_trace.splitlines() if json.loads(raw)["phase"] == "preflight"]
            for request_sha, source_sha, case_id, source_bytes, source_path in request_sources:
                lazy_rows.append({
                    "bytes": source_bytes,
                    "case_id_hash": hashlib.sha256(case_id.encode()).hexdigest(),
                    "ordinal": len(lazy_rows) + 1,
                    "phase": "transport",
                    "request_sha256": request_sha,
                    "run_id": "unit-run",
                    "schema": "cag-current-cpa-lazy-read-trace/v1",
                    "source_path": source_path,
                    "source_sha256": source_sha,
                })
            lazy_trace = b"".join(canonical_bytes(row) + b"\n" for row in lazy_rows)
            lazy_summary["trace_sha256"] = hashlib.sha256(lazy_trace).hexdigest()
            lazy_summary["transport_request_count"] = len(request_sources)
            lazy_summary["transport_source_read_count"] = len(request_sources)
            lazy_projection = validate_lazy_read_evidence(
                lazy_phase, lazy_trace, lazy_summary
            )
            validate_lazy_read_bindings(
                lazy_trace, manifest, results_raw,
                supplemental_manifest, supplemental_results_raw,
            )
            wrong_lazy_rows = copy.deepcopy(lazy_rows)
            wrong_lazy_rows[-1]["source_path"] = "corpus/wrong-approved-source.txt"
            wrong_lazy_trace = b"".join(
                canonical_bytes(row) + b"\n" for row in wrong_lazy_rows
            )
            with self.assertRaisesRegex(
                AdmissionError, "source metadata differs"
            ):
                validate_lazy_read_bindings(
                    wrong_lazy_trace,
                    manifest,
                    results_raw,
                    supplemental_manifest,
                    supplemental_results_raw,
                )
            csam_manifest, csam_results, csam_summary, csam_cleanup = csam_text_fixture("unit-run")
            csam_projection = validate_csam_text_evidence(
                csam_manifest, csam_results, csam_summary, csam_cleanup
            )

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
                    host_admission=host_report,
                    host_admission_raw=host_report_raw,
                    host_admission_300s_raw=host_300s_raw,
                    host_admission_3600s_raw=host_3600s_raw,
                    host_admission_realtime_raw=host_realtime_raw,
                    lazy_read=lazy_projection,
                    lazy_read_phase_boundary_raw=canonical_bytes(lazy_phase) + b"\n",
                    lazy_read_runtime_read_trace_raw=lazy_trace,
                    lazy_read_runtime_read_summary_raw=canonical_bytes(lazy_summary) + b"\n",
                    csam_text=csam_projection,
                    csam_text_fixture_manifest_raw=canonical_bytes(csam_manifest) + b"\n",
                    csam_text_results_raw=canonical_bytes(csam_results) + b"\n",
                    csam_text_summary_raw=canonical_bytes(csam_summary) + b"\n",
                    csam_text_privacy_cleanup_raw=canonical_bytes(csam_cleanup) + b"\n",
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
            host_report_raw = b"{}\n"
            with self.assertRaisesRegex(
                AdmissionError, "Host admission raw bytes differ from the validated object"
            ):
                pack(results_raw)
            host_report_raw = canonical_bytes(host_report) + b"\n"
            host_report["run_id"] = "borrowed-host-run"
            host_report_raw = canonical_bytes(host_report) + b"\n"
            with self.assertRaisesRegex(
                AdmissionError, "Host admission run_id differs from machine evidence run_id"
            ):
                pack(results_raw)
            host_report["run_id"] = host_run_id
            host_report_raw = canonical_bytes(host_report) + b"\n"
            self.assertEqual(report["summary"]["performance_gate_count"], len(THRESHOLDS))
            self.assertEqual(
                sum(item["execution_count"] for item in report["semantic"]["outcomes"]),
                EXPECTED_CORE_EXECUTIONS,
            )
            self.assertEqual(
                report["supplemental_archive"]["total_executions"],
                EXPECTED_SUPPLEMENTAL_EXECUTIONS,
            )
            authorized = [
                item
                for item in report["supplemental_archive"]["outcomes"]
                if item["supplemental_case_id"]
                == "supplemental-zip:ctf-sandbox:authorized-ctf"
            ]
            self.assertEqual({item["mode"] for item in authorized}, set(MODES))
            for item in authorized:
                self.assertEqual(
                    (
                        item["expected_winning_category"],
                        item["expected_winning_rule_id"],
                        item["actual_winning_category"],
                        item["actual_winning_rule_id"],
                    ),
                    (
                        "defense_evasion",
                        "META-OVERRIDE-001",
                        "defense_evasion",
                        "META-OVERRIDE-001",
                    ),
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
                "--host-admission", "unused",
                "--host-admission-300s", "unused",
                "--host-admission-3600s", "unused",
                "--host-admission-realtime", "unused",
                "--host-admission-config", "unused",
                "--host-admission-evidence-manifest", "unused",
                "--lazy-read-phase-boundary", "unused",
                "--lazy-read-runtime-read-trace", "unused",
                "--lazy-read-runtime-read-summary", "unused",
                "--csam-text-fixture-manifest", "unused",
                "--csam-text-results", "unused",
                "--csam-text-summary", "unused",
                "--csam-text-privacy-cleanup", "unused",
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

    def test_rejects_unsafe_run_id_in_each_portable_evidence_reference(self) -> None:
        # The JSON schema requires ^[a-z0-9][a-z0-9_.-]{2,62}$; the standalone
        # validator must enforce the same contract when jsonschema is absent.
        for section in (
            ("host_admission",),
            ("evidence_refs", "lazy_read"),
            ("evidence_refs", "csam_text"),
        ):
            with self.subTest(section=section):
                def mutate(report: dict[str, object], path=section) -> None:
                    value: object = report
                    for key in path:
                        assert isinstance(value, dict)
                        value = value[key]
                    assert isinstance(value, dict)
                    value["run_id"] = "A!"

                self.assert_rejected(mutate)

    def test_rejects_wrong_commit_tree_or_so(self) -> None:
        self.assert_rejected(lambda report: report["source"].__setitem__("commit", "9" * 40))  # type: ignore[union-attr]
        self.assert_rejected(lambda report: report["source"].__setitem__("tree", "9" * 40))  # type: ignore[union-attr]
        self.assert_rejected(lambda report: report["source"]["so"].__setitem__("sha256", "9" * 64))  # type: ignore[index,union-attr]

    def test_rejects_wrong_cpa_abi_or_rpc_schema(self) -> None:
        self.assert_rejected(lambda report: report["cpa"].__setitem__("c_abi", 2))  # type: ignore[index,union-attr]
        self.assert_rejected(lambda report: report["cpa"].__setitem__("rpc_schema", 2))  # type: ignore[index,union-attr]

    def test_rejects_non_integer_or_missing_cpa_abi_and_rpc_schema(self) -> None:
        for key, values in (
            ("c_abi", (True, "1", None, _MISSING)),
            ("rpc_schema", (True, "3", None, _MISSING)),
        ):
            for value in values:
                with self.subTest(key=key, value=value):
                    def mutate(report: dict[str, object]) -> None:
                        cpa = report["cpa"]
                        assert isinstance(cpa, dict)
                        if value is _MISSING:
                            cpa.pop(key)
                        else:
                            cpa[key] = value

                    self.assert_rejected(mutate)

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

    def test_rejects_tampered_realtime_projection_fields(self) -> None:
        def cold(report):  # type: ignore[no-untyped-def]
            return report["realtime"]["cold_starts"][0]

        mutations = (
            lambda report: cold(report)["routes"][0].__setitem__("status", 200),
            lambda report: cold(report)["routes"][0].__setitem__("upgrade", True),
            lambda report: cold(report)["routes"][0].__setitem__("auth", "standard"),
            lambda report: cold(report)["routes"].__setitem__(0, cold(report)["routes"][1]),
            lambda report: cold(report)["routes"].pop(),
            lambda report: cold(report)["cag_counters_after"].__setitem__("rpc_model_route_calls", 1),
            lambda report: cold(report)["cag_counters_before"].__setitem__("bad key", 0),
            lambda report: cold(report)["routes"][0]["cag_counter_delta"].__setitem__("rpc_request_before_calls", 1),
            lambda report: cold(report)["routes"][0].__setitem__("credential_kind", "BEARER"),
            lambda report: cold(report)["routes"][0].__setitem__("probe_mode", "AUTHENTICATED"),
            lambda report: cold(report)["routes"][0].__setitem__("termination", "HANDLER_COMPLETED"),
            lambda report: cold(report).__setitem__("event_head_after", "changed"),
            lambda report: cold(report).__setitem__("cold_start", 3),
            lambda report: cold(report).__setitem__("evidence_level", "FULL_ISOLATED_DYNAMIC"),
            lambda report: cold(report)["target_boundary"].__setitem__("real_provider_forbidden", False),
            lambda report: report["realtime"].__setitem__("evidence_level", "FULL_ISOLATED_DYNAMIC"),
            lambda report: report["realtime"].__setitem__("authenticated_dynamic_evidence", "FULL_ISOLATED_DYNAMIC"),
            lambda report: report["realtime"].__setitem__("source_topology", "SOURCE_TOPOLOGY_PROTECTED"),
        )
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                self.assert_rejected(mutate)

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

    def test_rejects_supplemental_winner_omission_or_drift(self) -> None:
        authorized_id = "supplemental-zip:ctf-sandbox:authorized-ctf"
        activated_id = next(
            case_id
            for case_id in EXPECTED_SUPPLEMENTAL_CASE_IDS
            if case_id.endswith(":activated")
        )

        def mutate_case(report, case_id, mode, key, value) -> None:  # type: ignore[no-untyped-def]
            row = next(
                item
                for item in report["supplemental_archive"]["outcomes"]
                if item["supplemental_case_id"] == case_id and item["mode"] == mode
            )
            if value is _MISSING:
                row.pop(key)
            else:
                row[key] = value

        for field in (
            "expected_winning_category",
            "expected_winning_rule_id",
            "actual_winning_category",
            "actual_winning_rule_id",
        ):
            with self.subTest(field=field, mutation="missing"):
                self.assert_rejected(
                    lambda report, field=field: mutate_case(
                        report, authorized_id, "audit", field, _MISSING
                    )
                )
        mutations = (
            (authorized_id, "audit", "expected_winning_category", None),
            (authorized_id, "balanced", "expected_winning_rule_id", "CRED-001"),
            (authorized_id, "strict", "actual_winning_category", "credential_theft"),
            (authorized_id, "audit", "actual_winning_rule_id", None),
            (activated_id, "balanced", "expected_winning_category", "credential_theft"),
            (activated_id, "strict", "actual_winning_rule_id", None),
        )
        for case_id, mode, field, value in mutations:
            with self.subTest(case_id=case_id, mode=mode, field=field):
                self.assert_rejected(
                    lambda report, case_id=case_id, mode=mode, field=field, value=value: mutate_case(
                        report, case_id, mode, field, value
                    )
                )

    def test_supplemental_projection_rejects_inconsistent_cell_winner(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _manifest, machine, _results = evidence_files(root)
            supplemental_manifest, _policy, _policy_raw = supplemental_manifest_fixture()
            results_path = root / machine["supplemental_zip_results"]["results_path"]
            rows = [json.loads(line) for line in results_path.read_bytes().splitlines()]
            target = next(
                row
                for row in rows
                if row["supplemental_case_id"].endswith(":activated")
                and row["mode"] == "balanced"
            )
            target["audit_event"]["category"] = "defense_evasion"
            target["audit_event"]["winning_rule_id"] = "META-OVERRIDE-001"
            raw = b"".join(canonical_bytes(row) + b"\n" for row in rows)
            with self.assertRaisesRegex(AdmissionError, "inconsistent winning rules"):
                derive_supplemental_semantics(
                    supplemental_manifest,
                    raw,
                    tuple(range(1, machine["run"]["cold_start_count"] + 1)),
                )

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

    def test_rejects_unbound_host_and_performance_raw_hashes(self) -> None:
        self.assert_rejected(lambda report: report["host_admission"].__setitem__("evidence_sha256", "0" * 64))  # type: ignore[union-attr]
        self.assert_rejected(lambda report: report["performance"].__setitem__("evidence_sha256", "0" * 64))  # type: ignore[union-attr]
        self.assert_rejected(lambda report: report["performance"].__setitem__("measurements_sha256", "0" * 64))  # type: ignore[union-attr]

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

        half_pair = valid_report()
        half_pair["supplemental_archive"]["outcomes"][0][
            "actual_winning_rule_id"
        ] = None
        self.assertTrue(list(Draft202012Validator(schema).iter_errors(half_pair)))

        empty_winner = valid_report()
        empty_winner["supplemental_archive"]["outcomes"][0][
            "actual_winning_category"
        ] = ""
        self.assertTrue(list(Draft202012Validator(schema).iter_errors(empty_winner)))

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
