#!/usr/bin/env python3
"""Pack and validate the portable owner-run second-machine RC admission.

The packer is intentionally server-side: it first validates the complete,
path-bound machine and Host-performance bundles in their original evidence
directory.  Only then does it emit a canonical, text-free portable summary.
The portable report is owner-run release admission, not independent proof.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import stat
import struct
import sys
import zipfile
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping, NoReturn, Sequence

from audit_contract import (
    CAG_SO_NAME,
    CAG_SOURCE_VERSION,
    CANDIDATE_ARTIFACT_NAME,
    CANDIDATE_MANIFEST_NAME,
    CANDIDATE_REPOSITORY,
    CANDIDATE_WORKFLOW_NAME,
    CANDIDATE_WORKFLOW_PATH,
    CLAIM_BOUNDARY,
    ContractError,
    MODES,
    PROTOCOLS,
    STREAM_VALUES,
    canonical_bytes,
    iter_jsonl_bytes,
    load_json_bytes,
    read_regular_bytes,
    sha256_bytes,
    validate_candidate_manifest_file,
    validate_evidence_run_config,
    validate_machine_evidence,
    validate_result,
    validate_run_config,
)


SCHEMA = "cyber-abuse-guard.second-machine-release-admission.v1"
STATUS = "SECOND_MACHINE_OWNER_RELEASE_ADMISSION_PASS"
BOUNDARY = "OWNER-RUN SECOND-MACHINE RELEASE ADMISSION; NOT INDEPENDENT PROOF"
REPORT_NAME = "second-machine-release-admission.json"
SCHEMA_NAME = "second-machine-release-admission.schema.json"
REPORT_TTL = timedelta(hours=24)
MAX_CLOCK_SKEW = timedelta(minutes=5)
MAX_REPORT_BYTES = 8 * 1024 * 1024
MAX_CANDIDATE_FILE_BYTES = 512 * 1024 * 1024
HEX40 = re.compile(r"[0-9a-f]{40}")
HEX64 = re.compile(r"[0-9a-f]{64}")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
UTC = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z"
)
TOOL_DIR = Path(__file__).resolve().parent
SCRIPT_PATH = Path(__file__).resolve()
SCHEMA_PATH = TOOL_DIR / SCHEMA_NAME
EXPECTED_CANDIDATE_FILES = (
    CAG_SO_NAME,
    CAG_SO_NAME + ".sha256",
    f"cyber-abuse-guard_{CAG_SOURCE_VERSION}_linux_amd64.zip",
    "audit-candidate-manifest.json",
    "build-metadata.json",
    "checksums.txt",
    "ruleset-manifest.json",
    "ruleset.sha256",
    "sbom.cdx.json",
)
INPUT_HASH_KEYS = (
    "candidate_manifest_sha256",
    "corpus_manifest_sha256",
    "host_performance_config_sha256",
    "host_performance_evidence_sha256",
    "host_performance_measurements_sha256",
    "machine_evidence_sha256",
    "performance_workload_manifest_sha256",
    "run_config_sha256",
    "transport_results_sha256",
)


class AdmissionError(ContractError):
    """A portable report or one of its source bundles failed closed."""


def fail(message: str) -> NoReturn:
    raise AdmissionError(message)


def exact_object(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict:
        fail(f"{label} must be a JSON object")
    actual = set(value)
    if actual != keys:
        missing = sorted(keys - actual)
        extra = sorted(actual - keys)
        fail(f"{label} keys are not closed (missing={missing}, extra={extra})")
    return value


def exact_list(value: Any, label: str) -> list[Any]:
    if type(value) is not list:
        fail(f"{label} must be a JSON array")
    return value


def exact_bool(value: Any, label: str) -> bool:
    if type(value) is not bool:
        fail(f"{label} must be a JSON boolean")
    return value


def exact_int(value: Any, label: str, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        fail(f"{label} must be an integer >= {minimum}")
    return value


def exact_number(value: Any, label: str) -> int | float:
    if type(value) not in (int, float) or not math.isfinite(float(value)):
        fail(f"{label} must be a finite JSON number")
    return value


def exact_string(value: Any, label: str, maximum: int = 1024) -> str:
    if type(value) is not str or not value or len(value) > maximum:
        fail(f"{label} must be a non-empty bounded string")
    return value


def require_hex(value: Any, label: str, pattern: re.Pattern[str] = HEX64) -> str:
    value = exact_string(value, label, 80)
    if pattern.fullmatch(value) is None:
        fail(f"{label} is not a lowercase hexadecimal identity")
    return value


def require_digest(value: Any, label: str) -> str:
    value = exact_string(value, label, 80)
    if DIGEST.fullmatch(value) is None:
        fail(f"{label} is not a lowercase sha256: digest")
    return value


def parse_timestamp(value: Any, label: str) -> datetime:
    value = exact_string(value, label, 40)
    if UTC.fullmatch(value) is None:
        fail(f"{label} must use strict UTC Z syntax")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        fail(f"{label} is not a real timestamp")
    return parsed


def timestamp(value: datetime) -> str:
    value = value.astimezone(timezone.utc)
    return value.isoformat(timespec="seconds").replace("+00:00", "Z")


def sha256_file(path: Path, label: str, maximum: int = MAX_CANDIDATE_FILE_BYTES) -> tuple[str, int, bytes]:
    raw = read_regular_bytes(path, label, maximum, require_single_link=True)
    return sha256_bytes(raw), len(raw), raw


def load_canonical(path: Path, label: str, maximum: int) -> tuple[dict[str, Any], bytes]:
    raw = read_regular_bytes(path, label, maximum, require_single_link=True)
    value = load_json_bytes(raw, label, maximum)
    if type(value) is not dict:
        fail(f"{label} must be a JSON object")
    if raw != canonical_bytes(value) + b"\n":
        fail(f"{label} must be canonical JSON with one terminal newline")
    return value, raw


def local_tool_identities() -> dict[str, Any]:
    from host_performance import tool_identities as host_tool_identities
    from run import runner_identities

    source_sha, _, _ = sha256_file(SCRIPT_PATH, "release admission packer", 2 * 1024 * 1024)
    schema_sha, _, _ = sha256_file(SCHEMA_PATH, "release admission schema", 2 * 1024 * 1024)
    return {
        "admission": {
            "schema_sha256": schema_sha,
            "source_sha256": source_sha,
        },
        "host_performance": host_tool_identities(),
        "machine": runner_identities(),
    }


def _parse_sha_file(raw: bytes, expected_name: str, label: str) -> str:
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError:
        fail(f"{label} is not ASCII")
    match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._-]{0,255})\n", text)
    if match is None or match.group(2) != expected_name:
        fail(f"{label} does not bind exactly {expected_name}")
    return match.group(1)


def _verify_elf_linux_amd64(raw: bytes) -> None:
    if len(raw) < 64 or raw[:6] != b"\x7fELF\x02\x01":
        fail("candidate SO is not a little-endian ELF64 object")
    elf_type, machine = struct.unpack_from("<HH", raw, 16)
    if elf_type != 3 or machine != 62:
        fail("candidate SO is not an x86-64 shared object")


def validate_candidate_directory(
    directory: Path,
    manifest: Mapping[str, Any],
) -> list[dict[str, Any]]:
    try:
        resolved = directory.resolve(strict=True)
    except (FileNotFoundError, OSError) as exc:
        fail(f"candidate directory cannot be resolved: {type(exc).__name__}")
    if resolved != directory:
        fail("candidate directory must already be a resolved real path")
    info = directory.stat(follow_symlinks=False)
    if not stat.S_ISDIR(info.st_mode):
        fail("candidate artifact path is not a real directory")
    actual = tuple(sorted(entry.name for entry in directory.iterdir()))
    expected = tuple(sorted(EXPECTED_CANDIDATE_FILES))
    if actual != expected:
        fail(f"candidate artifact is not the exact nine-file set: {actual}")

    declared = {item["name"]: item for item in manifest["artifacts"]}
    files: list[dict[str, Any]] = []
    raw_by_name: dict[str, bytes] = {}
    for name in EXPECTED_CANDIDATE_FILES:
        path = directory / name
        digest, size, raw = sha256_file(path, f"candidate file {name}")
        raw_by_name[name] = raw
        if name == CANDIDATE_MANIFEST_NAME:
            expected_digest = sha256_bytes(canonical_bytes(manifest) + b"\n")
            if digest != expected_digest:
                fail("candidate manifest bytes changed during admission packing")
        else:
            record = declared.get(name)
            if record is None or record["sha256"] != digest or record["bytes"] != size:
                fail(f"candidate manifest does not bind the bytes of {name}")
        files.append({"bytes": size, "name": name, "sha256": digest})

    so_raw = raw_by_name[CAG_SO_NAME]
    so_sha = sha256_bytes(so_raw)
    _verify_elf_linux_amd64(so_raw)
    if _parse_sha_file(
        raw_by_name[CAG_SO_NAME + ".sha256"], CAG_SO_NAME, "candidate SO sidecar"
    ) != so_sha:
        fail("candidate SO sidecar SHA differs from the selected SO")
    if _parse_sha_file(
        raw_by_name["ruleset.sha256"], "ruleset-manifest.json", "candidate ruleset sidecar"
    ) != sha256_bytes(raw_by_name["ruleset-manifest.json"]):
        fail("candidate ruleset sidecar SHA differs from the ruleset manifest")

    checksum_lines: dict[str, str] = {}
    try:
        checksum_text = raw_by_name["checksums.txt"].decode("ascii")
    except UnicodeDecodeError:
        fail("candidate checksums.txt is not ASCII")
    for line in checksum_text.splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._-]{0,255})", line)
        if match is None or match.group(2) in checksum_lines:
            fail("candidate checksums.txt has an invalid or duplicate row")
        checksum_lines[match.group(2)] = match.group(1)
    checksummed = set(EXPECTED_CANDIDATE_FILES) - {"audit-candidate-manifest.json", "checksums.txt"}
    if set(checksum_lines) != checksummed:
        fail("candidate checksums.txt does not cover the exact seven-file base set")
    for name, digest in checksum_lines.items():
        if digest != sha256_bytes(raw_by_name[name]):
            fail(f"candidate checksums.txt does not bind {name}")

    zip_name = f"cyber-abuse-guard_{CAG_SOURCE_VERSION}_linux_amd64.zip"
    try:
        with zipfile.ZipFile(directory / zip_name) as archive:
            members = archive.infolist()
            if len(members) != 1 or members[0].filename != CAG_SO_NAME:
                fail("candidate Store ZIP must contain exactly the root candidate SO")
            if members[0].is_dir() or ((members[0].external_attr >> 16) & 0o170000) == 0o120000:
                fail("candidate Store ZIP member is not a regular file")
            if archive.read(members[0]) != so_raw:
                fail("candidate Store ZIP SO bytes differ from the standalone SO")
    except (OSError, zipfile.BadZipFile) as exc:
        fail(f"candidate Store ZIP is invalid: {type(exc).__name__}")

    metadata = load_json_bytes(raw_by_name["build-metadata.json"], "candidate build metadata")
    if type(metadata) is not dict or not (
        metadata.get("schema_version") == 4
        and metadata.get("version") == CAG_SOURCE_VERSION
        and metadata.get("source_version") == CAG_SOURCE_VERSION
        and metadata.get("commit") == manifest["commit"]
        and metadata.get("tree") == manifest["tree"]
        and metadata.get("dirty") is False
        and metadata.get("goos") == "linux"
        and metadata.get("goarch") == "amd64"
        and metadata.get("cgo_enabled") is True
    ):
        fail("candidate build metadata does not bind the exact audited Linux amd64 bytes")
    ruleset = load_json_bytes(raw_by_name["ruleset-manifest.json"], "candidate ruleset manifest")
    if type(ruleset) is not dict or ruleset.get("plugin_version") != CAG_SOURCE_VERSION:
        fail("candidate ruleset manifest does not retain binary version 1.0.0")
    sbom = load_json_bytes(raw_by_name["sbom.cdx.json"], "candidate SBOM")
    properties = (
        sbom.get("metadata", {}).get("component", {}).get("properties", [])
        if type(sbom) is dict
        else []
    )
    if not (
        type(properties) is list
        and sum(
            item == {"name": "cag:source:git-commit", "value": manifest["commit"]}
            for item in properties
        )
        == 1
        and sum(
            item == {"name": "cag:source:git-tree", "value": manifest["tree"]}
            for item in properties
        )
        == 1
        and sum(
            item == {"name": "cag:build:kind", "value": "candidate"}
            for item in properties
        )
        == 1
    ):
        fail("candidate SBOM does not bind the audited candidate source")
    return sorted(files, key=lambda item: item["name"])


def _performance_gate(metric: str, observed: int | float) -> dict[str, Any]:
    from host_performance import THRESHOLDS

    operator, limit = THRESHOLDS[metric]
    if operator == "<=":
        passed = observed <= limit
    elif operator == "<":
        passed = observed < limit
    elif operator == ">=":
        passed = observed >= limit
    elif operator == "=":
        passed = observed == limit
    else:
        fail(f"unknown Host-performance threshold operator for {metric}")
    return {
        "limit": limit,
        "observed": observed,
        "operator": operator,
        "status": "PASS" if passed else "FAIL",
    }


def derive_semantics(
    manifest: Mapping[str, Any], results_raw: bytes, cold_start_arms: Sequence[int]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    cases = {case["id"]: case for case in manifest["semantic_cases"]}
    rows = [
        validate_result(value, cases, f"portable derivation result[{index}]")
        for index, value in enumerate(iter_jsonl_bytes(results_raw, "transport results"))
    ]
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped[(row["semantic_case_id"], row["mode"])].append(row)
    expected_matrix = {
        (protocol, stream, cold_start)
        for protocol in PROTOCOLS
        for stream in STREAM_VALUES
        for cold_start in cold_start_arms
    }
    outcomes: list[dict[str, Any]] = []
    for case_id in sorted(cases):
        case = cases[case_id]
        malicious = case["label"] == "malicious_active"
        for mode in MODES:
            selected = grouped[(case_id, mode)]
            observed_matrix = {
                (row["protocol"], row["stream"], row["cold_start"]) for row in selected
            }
            if len(selected) != len(expected_matrix) or observed_matrix != expected_matrix:
                fail(f"semantic summary cell {case_id}/{mode} is incomplete")
            expected_actions = {row["expected_action"] for row in selected}
            actual_actions = {row["actual_action"] for row in selected}
            if len(expected_actions) != 1 or len(actual_actions) != 1:
                fail(f"semantic summary cell {case_id}/{mode} is inconsistent")
            expected_action = next(iter(expected_actions))
            actual_action = next(iter(actual_actions))
            side_expected = (
                {"auth": 1, "mock": 1, "provider": 1, "usage": 1}
                if expected_action == "allow"
                else {"auth": 0, "mock": 0, "provider": 0, "usage": 0}
            )
            side_violations = sum(row["side_effect_deltas"] != side_expected for row in selected)
            if mode == "audit":
                detected = malicious and all(
                    row["audit_event"] is not None
                    and row["audit_event"]["decision"] == "audit_malicious_text"
                    for row in selected
                )
            else:
                detected = malicious and all(
                    row["actual_action"] == "block_malicious_text" for row in selected
                )
            outcomes.append(
                {
                    "actual_action": actual_action,
                    "all_executions_passed": all(row["passed"] for row in selected),
                    "execution_count": len(selected),
                    "expected_action": expected_action,
                    "false_positive": (not malicious and actual_action == "block_malicious_text"),
                    "label": case["label"],
                    "malicious": malicious,
                    "malicious_detected": detected,
                    "mode": mode,
                    "semantic_case_id": case_id,
                    "side_effect_violations": side_violations,
                }
            )
    summary = derive_semantic_summary(outcomes)
    return outcomes, summary


def derive_semantic_summary(outcomes: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    summaries: list[dict[str, Any]] = []
    for mode in MODES:
        selected = [row for row in outcomes if row["mode"] == mode]
        malicious = [row for row in selected if row["malicious"]]
        detected = sum(row["malicious_detected"] is True for row in malicious)
        total = len(malicious)
        summaries.append(
            {
                "all_semantic_contracts_passed": bool(selected)
                and all(row["all_executions_passed"] is True for row in selected),
                "false_positives": sum(row["false_positive"] is True for row in selected),
                "malicious_cases": total,
                "malicious_detected": detected,
                "malicious_recall_percent": 100.0 * detected / total if total else 0.0,
                "mode": mode,
                "semantic_cases": len(selected),
                "side_effect_violations": sum(int(row["side_effect_violations"]) for row in selected),
            }
        )
    return summaries


def derive_summary(report: Mapping[str, Any]) -> dict[str, Any]:
    semantic = derive_semantic_summary(report["semantic"]["outcomes"])
    gates = report["performance"]["gates"]
    return {
        "business_side_effects": 0 if report["safety"]["business_snapshots_unchanged"] else 1,
        "cleanup_pass": bool(
            report["cleanup"]["all_owned_resources_absent"]
            and not report["cleanup"]["global_prune_used"]
            and not report["cleanup"]["images_removed"]
            and not report["cleanup"]["third_party_text_retained"]
        ),
        "false_positives": sum(item["false_positives"] for item in semantic),
        "malicious_cases": sum(item["malicious_cases"] for item in semantic),
        "malicious_detected": sum(item["malicious_detected"] for item in semantic),
        "malicious_recall_percent": min(item["malicious_recall_percent"] for item in semantic),
        "mode_count": len(semantic),
        "performance_gate_count": len(gates),
        "performance_gates_passed": sum(item["status"] == "PASS" for item in gates.values()),
        "semantic_case_count": min(item["semantic_cases"] for item in semantic),
        "side_effect_violations": sum(item["side_effect_violations"] for item in semantic),
        "third_party_code_executions": report["safety"]["machine_third_party_code_executions"]
        + report["safety"]["corpus_third_party_code_executions"],
    }


def _corpus_identity(manifest: Mapping[str, Any]) -> dict[str, Any]:
    repositories = []
    for observation in sorted(manifest["head_observations"], key=lambda item: item["repository_key"]):
        repositories.append(
            {
                "commit": observation["pre"]["commit"],
                "default_branch": observation["default_branch"],
                "repository": observation["repository"],
                "repository_key": observation["repository_key"],
                "tree": observation["pre"]["tree"],
            }
        )
    zip_sources: dict[tuple[str, str], dict[str, Any]] = {}
    for case in manifest["semantic_cases"]:
        source = case["source"]
        if source["archive_member"] is not None:
            zip_sources[(source["repository_key"], source["path"])] = {
                "archive_member": source["archive_member"],
                "path": source["path"],
                "repository": source["repository"],
                "repository_key": source["repository_key"],
                "source_sha256": source["source_sha256"],
                "text_sha256": source["text_sha256"],
            }
    if len(zip_sources) != 1:
        fail("validated corpus did not yield the exact one ZIP source identity")
    return {"repositories": repositories, "zip_source": next(iter(zip_sources.values()))}


def build_report(
    *,
    manifest: Mapping[str, Any],
    manifest_raw: bytes,
    machine: Mapping[str, Any],
    machine_raw: bytes,
    results_path: Path,
    results_raw: bytes,
    run_config: Mapping[str, Any],
    run_config_raw: bytes,
    candidate_manifest: Mapping[str, Any],
    candidate_raw: bytes,
    candidate_files: list[dict[str, Any]],
    candidate_artifact_size: int,
    workload_raw: bytes,
    performance_config_raw: bytes,
    measurements_raw: bytes,
    performance: Mapping[str, Any],
    performance_raw: bytes,
    generated_at: datetime,
) -> dict[str, Any]:
    del results_path
    cold_start_arms = tuple(range(1, int(machine["run"]["cold_start_count"]) + 1))
    outcomes, semantic_summary = derive_semantics(manifest, results_raw, cold_start_arms)
    candidate = run_config["identities"]["candidate"]
    if not (
        candidate_manifest["event"] == "push"
        and candidate_manifest["head_branch"] == "main"
        and candidate_manifest["head_sha"] == candidate_manifest["commit"]
        and candidate_manifest["run_id"] == candidate["run_id"]
        and candidate_manifest["run_attempt"] == candidate["run_attempt"]
    ):
        fail("release admission requires a push/main candidate manifest identity")
    if machine["identities"]["cag"] != performance["identities"]["cag"]:
        fail("machine and Host-performance CAG identities differ")
    if machine["identities"]["candidate"] != performance["identities"]["candidate"]:
        fail("machine and Host-performance candidate provenance differs")
    if machine["identities"]["cpa"] != performance["identities"]["cpa"]:
        fail("machine and Host-performance CPA identities differ")

    from host_performance import THRESHOLDS

    metrics = {key: performance["metrics"][key] for key in sorted(THRESHOLDS)}
    gates = {key: _performance_gate(key, metrics[key]) for key in sorted(THRESHOLDS)}
    if performance["status"] != "PASS" or any(item["status"] != "PASS" for item in gates.values()):
        fail("Host-performance evidence does not pass every current closed gate")
    corpus_identity = _corpus_identity(manifest)
    source = machine["identities"]["cag"]
    so_file = next(item for item in candidate_files if item["name"] == CAG_SO_NAME)
    if so_file["sha256"] != source["so_sha256"]:
        fail("candidate SO bytes differ from the validated machine identity")
    input_hashes = {
        "candidate_manifest_sha256": sha256_bytes(candidate_raw),
        "corpus_manifest_sha256": sha256_bytes(manifest_raw),
        "host_performance_config_sha256": sha256_bytes(performance_config_raw),
        "host_performance_evidence_sha256": sha256_bytes(performance_raw),
        "host_performance_measurements_sha256": sha256_bytes(measurements_raw),
        "machine_evidence_sha256": sha256_bytes(machine_raw),
        "performance_workload_manifest_sha256": sha256_bytes(workload_raw),
        "run_config_sha256": sha256_bytes(run_config_raw),
        "transport_results_sha256": sha256_bytes(results_raw),
    }
    generated_at = generated_at.astimezone(timezone.utc).replace(microsecond=0)
    report: dict[str, Any] = {
        "candidate": {
            "files": candidate_files,
            "github_artifact": {
                "digest": candidate["artifact"]["digest"],
                "id": int(candidate["artifact"]["id"]),
                "name": candidate["artifact"]["name"],
                "run_attempt": int(candidate["run_attempt"]),
                "run_id": int(candidate["run_id"]),
                "size": candidate_artifact_size,
                "workflow_name": CANDIDATE_WORKFLOW_NAME,
                "workflow_path": CANDIDATE_WORKFLOW_PATH,
            },
            "manifest_sha256": sha256_bytes(candidate_raw),
        },
        "claim_boundary": BOUNDARY,
        "cleanup": {
            "all_owned_resources_absent": machine["cleanup"]["all_owned_resources_absent"],
            "global_prune_used": machine["cleanup"]["global_prune_used"],
            "images_removed": machine["cleanup"]["images_removed"],
            "resource_count": len(machine["cleanup"]["resources"]),
            "third_party_text_files_removed": machine["cleanup"]["third_party_text_files_removed"],
            "third_party_text_retained": machine["cleanup"]["third_party_text_retained"],
        },
        "corpus": {
            "manifest_sha256": sha256_bytes(manifest_raw),
            "policy_review_status": manifest["policy_review_status"],
            "repositories": corpus_identity["repositories"],
            "repository_count": manifest["repository_count"],
            "source_count": manifest["source_count"],
            "unique_content_hashes": manifest["unique_content_hashes"],
            "unique_semantic_cases": manifest["unique_semantic_cases"],
            "zip_source": corpus_identity["zip_source"],
        },
        "cpa": dict(machine["identities"]["cpa"]),
        "expires_at": timestamp(generated_at + REPORT_TTL),
        "generated_at": timestamp(generated_at),
        "inputs": input_hashes,
        "performance": {
            "evidence_schema": performance["schema"],
            "gates": gates,
            "metrics": metrics,
            "status": performance["status"],
        },
        "safety": {
            "business_snapshots_unchanged": machine["business_snapshots"]["unchanged"],
            "corpus_third_party_code_executions": manifest["third_party_code_executions"],
            "independent_proof": False,
            "infrastructure_error_count": len(machine["infrastructure_errors"]),
            "machine_third_party_code_executions": machine["third_party_code_executions"],
            "owner_run": True,
        },
        "schema": SCHEMA,
        "semantic": {"outcomes": outcomes, "summary_by_mode": semantic_summary},
        "source": {
            "binary_version": CAG_SOURCE_VERSION,
            "commit": source["commit"],
            "repository": CANDIDATE_REPOSITORY,
            "so": {"bytes": so_file["bytes"], "name": source["so_name"], "sha256": source["so_sha256"]},
            "source_version": source["source_version"],
            "tree": source["tree"],
        },
        "status": STATUS,
        "summary": {},
        "tool_bundles": local_tool_identities(),
    }
    report["summary"] = derive_summary(report)
    validate_report(report, now=generated_at)
    return report


def validate_report(
    value: Any,
    *,
    now: datetime | None = None,
    minimum_remaining: timedelta = timedelta(0),
    expected: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    report = exact_object(
        value,
        {
            "candidate", "claim_boundary", "cleanup", "corpus", "cpa", "expires_at",
            "generated_at", "inputs", "performance", "safety", "schema", "semantic",
            "source", "status", "summary", "tool_bundles",
        },
        "release admission report",
    )
    if report["schema"] != SCHEMA or report["status"] != STATUS or report["claim_boundary"] != BOUNDARY:
        fail("release admission report schema/status/claim boundary is invalid")
    generated = parse_timestamp(report["generated_at"], "report.generated_at")
    expires = parse_timestamp(report["expires_at"], "report.expires_at")
    if expires - generated != REPORT_TTL:
        fail("release admission report must use the fixed 24-hour lifetime")
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    if current < generated - MAX_CLOCK_SKEW or current > expires:
        fail("release admission report is not currently within its fixed validity window")
    if minimum_remaining < timedelta(0):
        fail("minimum remaining validity may not be negative")
    if expires - current < minimum_remaining:
        fail("release admission report does not cover the required remaining validity window")

    source = exact_object(report["source"], {"binary_version", "commit", "repository", "so", "source_version", "tree"}, "report.source")
    if source["repository"] != CANDIDATE_REPOSITORY or source["source_version"] != CAG_SOURCE_VERSION or source["binary_version"] != CAG_SOURCE_VERSION:
        fail("report source does not bind the fixed repository and binary/source version 1.0.0")
    require_hex(source["commit"], "report.source.commit", HEX40)
    require_hex(source["tree"], "report.source.tree", HEX40)
    so = exact_object(source["so"], {"bytes", "name", "sha256"}, "report.source.so")
    if so["name"] != CAG_SO_NAME:
        fail("report SO uses a renamed RC binary instead of the audited v1.0.0 name")
    exact_int(so["bytes"], "report.source.so.bytes", 1)
    require_hex(so["sha256"], "report.source.so.sha256")

    candidate = exact_object(report["candidate"], {"files", "github_artifact", "manifest_sha256"}, "report.candidate")
    require_hex(candidate["manifest_sha256"], "report.candidate.manifest_sha256")
    files = exact_list(candidate["files"], "report.candidate.files")
    if len(files) != len(EXPECTED_CANDIDATE_FILES):
        fail("report candidate file set is not exactly nine files")
    names: set[str] = set()
    for index, raw in enumerate(files):
        item = exact_object(raw, {"bytes", "name", "sha256"}, f"report.candidate.files[{index}]")
        name = exact_string(item["name"], f"report.candidate.files[{index}].name", 256)
        if name in names or Path(name).name != name:
            fail("report candidate file names are duplicated or unsafe")
        names.add(name)
        exact_int(item["bytes"], f"report.candidate.files[{index}].bytes", 1)
        require_hex(item["sha256"], f"report.candidate.files[{index}].sha256")
    if names != set(EXPECTED_CANDIDATE_FILES):
        fail("report candidate file allowlist is not exact")
    file_so = next(item for item in files if item["name"] == CAG_SO_NAME)
    file_manifest = next(item for item in files if item["name"] == CANDIDATE_MANIFEST_NAME)
    if file_so["sha256"] != so["sha256"] or file_so["bytes"] != so["bytes"]:
        fail("report source SO differs from the sealed candidate file")
    if file_manifest["sha256"] != candidate["manifest_sha256"]:
        fail("report candidate manifest file SHA is internally inconsistent")
    artifact = exact_object(candidate["github_artifact"], {"digest", "id", "name", "run_attempt", "run_id", "size", "workflow_name", "workflow_path"}, "report.candidate.github_artifact")
    if artifact["name"] != CANDIDATE_ARTIFACT_NAME or artifact["workflow_name"] != CANDIDATE_WORKFLOW_NAME or artifact["workflow_path"] != CANDIDATE_WORKFLOW_PATH:
        fail("report candidate GitHub artifact/workflow identity is invalid")
    for key in ("id", "run_attempt", "run_id", "size"):
        exact_int(artifact[key], f"report.candidate.github_artifact.{key}", 1)
    require_digest(artifact["digest"], "report.candidate.github_artifact.digest")

    inputs = exact_object(report["inputs"], set(INPUT_HASH_KEYS), "report.inputs")
    for key in INPUT_HASH_KEYS:
        require_hex(inputs[key], f"report.inputs.{key}")
    if inputs["candidate_manifest_sha256"] != candidate["manifest_sha256"] or inputs["corpus_manifest_sha256"] != report["corpus"]["manifest_sha256"]:
        fail("report input hashes do not bind the candidate/corpus summaries")

    safety = exact_object(report["safety"], {"business_snapshots_unchanged", "corpus_third_party_code_executions", "independent_proof", "infrastructure_error_count", "machine_third_party_code_executions", "owner_run"}, "report.safety")
    if exact_bool(safety["owner_run"], "report.safety.owner_run") is not True or exact_bool(safety["independent_proof"], "report.safety.independent_proof") is not False:
        fail("report must preserve the owner-run/non-independent claim boundary")
    if exact_bool(safety["business_snapshots_unchanged"], "report.safety.business_snapshots_unchanged") is not True:
        fail("report claims business-container side effects")
    for key in ("corpus_third_party_code_executions", "infrastructure_error_count", "machine_third_party_code_executions"):
        if exact_int(safety[key], f"report.safety.{key}") != 0:
            fail(f"report safety gate {key} is not zero")

    cleanup = exact_object(report["cleanup"], {"all_owned_resources_absent", "global_prune_used", "images_removed", "resource_count", "third_party_text_files_removed", "third_party_text_retained"}, "report.cleanup")
    if not exact_bool(cleanup["all_owned_resources_absent"], "report.cleanup.all_owned_resources_absent") or exact_bool(cleanup["global_prune_used"], "report.cleanup.global_prune_used") or exact_bool(cleanup["images_removed"], "report.cleanup.images_removed") or exact_bool(cleanup["third_party_text_retained"], "report.cleanup.third_party_text_retained"):
        fail("report cleanup is incomplete or used forbidden broad cleanup")
    exact_int(cleanup["resource_count"], "report.cleanup.resource_count", 1)
    exact_int(cleanup["third_party_text_files_removed"], "report.cleanup.third_party_text_files_removed", 1)

    corpus = exact_object(report["corpus"], {"manifest_sha256", "policy_review_status", "repositories", "repository_count", "source_count", "unique_content_hashes", "unique_semantic_cases", "zip_source"}, "report.corpus")
    require_hex(corpus["manifest_sha256"], "report.corpus.manifest_sha256")
    if corpus["policy_review_status"] != "approved" or exact_int(corpus["repository_count"], "report.corpus.repository_count") != 5 or exact_int(corpus["source_count"], "report.corpus.source_count") != 11 or exact_int(corpus["unique_semantic_cases"], "report.corpus.unique_semantic_cases") != 19:
        fail("report corpus does not bind the approved exact five-repository/11-source/19-case set")
    exact_int(corpus["unique_content_hashes"], "report.corpus.unique_content_hashes", 1)
    repositories = exact_list(corpus["repositories"], "report.corpus.repositories")
    if len(repositories) != 5:
        fail("report corpus repository pins are not exactly five")
    repository_keys: set[str] = set()
    for index, raw in enumerate(repositories):
        item = exact_object(raw, {"commit", "default_branch", "repository", "repository_key", "tree"}, f"report.corpus.repositories[{index}]")
        key = exact_string(item["repository_key"], f"report.corpus.repositories[{index}].repository_key", 64)
        if key in repository_keys:
            fail("report corpus repository key is duplicated")
        repository_keys.add(key)
        exact_string(item["repository"], f"report.corpus.repositories[{index}].repository", 256)
        exact_string(item["default_branch"], f"report.corpus.repositories[{index}].default_branch", 256)
        require_hex(item["commit"], f"report.corpus.repositories[{index}].commit", HEX40)
        require_hex(item["tree"], f"report.corpus.repositories[{index}].tree", HEX40)
    zip_source = exact_object(corpus["zip_source"], {"archive_member", "path", "repository", "repository_key", "source_sha256", "text_sha256"}, "report.corpus.zip_source")
    for key in ("archive_member", "path", "repository", "repository_key"):
        exact_string(zip_source[key], f"report.corpus.zip_source.{key}", 512)
    require_hex(zip_source["source_sha256"], "report.corpus.zip_source.source_sha256")
    require_hex(zip_source["text_sha256"], "report.corpus.zip_source.text_sha256")

    semantic = exact_object(report["semantic"], {"outcomes", "summary_by_mode"}, "report.semantic")
    outcomes = exact_list(semantic["outcomes"], "report.semantic.outcomes")
    if len(outcomes) != 19 * len(MODES):
        fail("report semantic outcomes are not the exact 19-case by three-mode matrix")
    seen: set[tuple[str, str]] = set()
    for index, raw in enumerate(outcomes):
        item = exact_object(raw, {"actual_action", "all_executions_passed", "execution_count", "expected_action", "false_positive", "label", "malicious", "malicious_detected", "mode", "semantic_case_id", "side_effect_violations"}, f"report.semantic.outcomes[{index}]")
        identity = (exact_string(item["semantic_case_id"], f"report.semantic.outcomes[{index}].semantic_case_id", 256), exact_string(item["mode"], f"report.semantic.outcomes[{index}].mode", 16))
        if identity in seen or identity[1] not in MODES:
            fail("report semantic outcome identity is duplicate or uses an unknown mode")
        seen.add(identity)
        for key in ("actual_action", "expected_action", "label"):
            exact_string(item[key], f"report.semantic.outcomes[{index}].{key}", 128)
        exact_int(item["execution_count"], f"report.semantic.outcomes[{index}].execution_count", 1)
        if exact_int(item["side_effect_violations"], f"report.semantic.outcomes[{index}].side_effect_violations") != 0:
            fail("report semantic outcome contains a side-effect violation")
        if not exact_bool(item["all_executions_passed"], f"report.semantic.outcomes[{index}].all_executions_passed"):
            fail("report semantic outcome contains a failed execution")
        for key in ("false_positive", "malicious", "malicious_detected"):
            exact_bool(item[key], f"report.semantic.outcomes[{index}].{key}")
        if item["false_positive"]:
            fail("report semantic outcome contains a false positive")
        if item["malicious"] and not item["malicious_detected"]:
            fail("report semantic outcome missed malicious ground truth")
    recomputed_semantic = derive_semantic_summary(outcomes)
    if semantic["summary_by_mode"] != recomputed_semantic:
        fail("report semantic summary differs from the closed outcome matrix")
    for item in recomputed_semantic:
        if not item["all_semantic_contracts_passed"] or item["false_positives"] != 0 or item["malicious_cases"] < 1 or item["malicious_detected"] != item["malicious_cases"] or item["malicious_recall_percent"] != 100.0 or item["semantic_cases"] != 19 or item["side_effect_violations"] != 0:
            fail(f"report mode {item['mode']} does not satisfy the zero-FP/100%-recall contract")

    performance = exact_object(report["performance"], {"evidence_schema", "gates", "metrics", "status"}, "report.performance")
    exact_string(performance["evidence_schema"], "report.performance.evidence_schema", 256)
    if performance["status"] != "PASS":
        fail("report Host-performance status is not PASS")
    from host_performance import THRESHOLDS
    metrics = exact_object(performance["metrics"], set(THRESHOLDS), "report.performance.metrics")
    gates = exact_object(performance["gates"], set(THRESHOLDS), "report.performance.gates")
    for metric in sorted(THRESHOLDS):
        observed = exact_number(metrics[metric], f"report.performance.metrics.{metric}")
        expected_gate = _performance_gate(metric, observed)
        gate = exact_object(gates[metric], {"limit", "observed", "operator", "status"}, f"report.performance.gates.{metric}")
        if gate != expected_gate or gate["status"] != "PASS":
            fail(f"report Host-performance gate {metric} does not pass the checked-out threshold")

    cpa = report["cpa"]
    if type(cpa) is not dict or cpa != {
        key: cpa[key]
        for key in ("binary_path", "binary_sha256", "commit", "image_id", "official_asset_name", "official_asset_sha256", "repo_digest", "tag")
        if key in cpa
    } or set(cpa) != {"binary_path", "binary_sha256", "commit", "image_id", "official_asset_name", "official_asset_sha256", "repo_digest", "tag"}:
        fail("report CPA identity keys are not closed")
    from audit_contract import CPA_COMMIT, CPA_OFFICIAL_ASSET_NAME, CPA_OFFICIAL_ASSET_SHA256, CPA_OFFICIAL_BINARY_SHA256, CPA_TAG
    if cpa["tag"] != CPA_TAG or cpa["commit"] != CPA_COMMIT or cpa["official_asset_name"] != CPA_OFFICIAL_ASSET_NAME or cpa["official_asset_sha256"] != CPA_OFFICIAL_ASSET_SHA256 or cpa["binary_sha256"] != CPA_OFFICIAL_BINARY_SHA256:
        fail("report does not bind the fixed CPA v7.2.125 official bytes")

    tools = exact_object(report["tool_bundles"], {"admission", "host_performance", "machine"}, "report.tool_bundles")
    if tools != local_tool_identities():
        fail("report tool bundle hashes differ from the checked-out tag validator")

    summary = exact_object(report["summary"], {"business_side_effects", "cleanup_pass", "false_positives", "malicious_cases", "malicious_detected", "malicious_recall_percent", "mode_count", "performance_gate_count", "performance_gates_passed", "semantic_case_count", "side_effect_violations", "third_party_code_executions"}, "report.summary")
    recomputed = derive_summary(report)
    if summary != recomputed:
        fail("report top-level summary differs from its closed detail")
    if not (
        summary["business_side_effects"] == 0
        and summary["cleanup_pass"] is True
        and summary["false_positives"] == 0
        and summary["malicious_cases"] > 0
        and summary["malicious_detected"] == summary["malicious_cases"]
        and summary["malicious_recall_percent"] == 100.0
        and summary["mode_count"] == len(MODES)
        and summary["performance_gate_count"] == len(THRESHOLDS)
        and summary["performance_gates_passed"] == len(THRESHOLDS)
        and summary["semantic_case_count"] == 19
        and summary["side_effect_violations"] == 0
        and summary["third_party_code_executions"] == 0
    ):
        fail("report PASS status is not supported by every release gate")

    if expected is not None:
        checks = {
            "repository": source["repository"],
            "commit": source["commit"],
            "tree": source["tree"],
            "candidate_run_id": artifact["run_id"],
            "candidate_run_attempt": artifact["run_attempt"],
            "candidate_artifact_id": artifact["id"],
            "candidate_artifact_digest": artifact["digest"],
            "candidate_artifact_size": artifact["size"],
        }
        for key, observed in checks.items():
            if key in expected and observed != expected[key]:
                fail(f"report {key} differs from the GitHub admission identity")
    return report


def load_validated_inputs(args: argparse.Namespace) -> dict[str, Any]:
    from validate import bind_policy

    manifest, manifest_raw = load_canonical(args.manifest, "corpus manifest", 64 * 1024 * 1024)
    from audit_contract import validate_corpus_manifest
    manifest = validate_corpus_manifest(manifest)
    bind_policy(manifest)
    machine, machine_raw = load_canonical(args.evidence, "machine evidence", 64 * 1024 * 1024)
    from run import runner_identities
    if machine.get("identities", {}).get("runner") != runner_identities():
        fail("machine evidence runner identity differs from this packer bundle")
    machine = validate_machine_evidence(manifest, machine, args.results)
    declared_manifest = args.evidence.parent / machine["corpus"]["manifest_path"]
    declared_results = args.evidence.parent / machine["transport"]["results_path"]
    if declared_manifest.resolve(strict=True) != args.manifest.resolve(strict=True) or declared_results.resolve(strict=True) != args.results.resolve(strict=True):
        fail("machine evidence relative input paths differ from the supplied full bundle")
    results_raw = read_regular_bytes(args.results, "transport results", 512 * 1024 * 1024, require_single_link=True)

    run_config, run_config_raw = load_canonical(args.run_config, "run config", 2 * 1024 * 1024)
    run_config = validate_run_config(run_config)
    candidate_manifest, candidate_raw = validate_candidate_manifest_file(run_config)
    if Path(run_config["paths"]["evidence_directory"]).resolve(strict=True) != args.evidence.parent.resolve(strict=True):
        fail("run config evidence directory differs from the supplied machine evidence")
    validate_evidence_run_config(machine, run_config, run_config_raw)
    candidate_path = Path(run_config["paths"]["candidate_manifest"])
    if candidate_path.resolve(strict=True) != args.candidate_manifest.resolve(strict=True):
        fail("supplied candidate manifest differs from the run config")
    candidate_files = validate_candidate_directory(candidate_path.parent.resolve(strict=True), candidate_manifest)

    workload, workload_raw = load_canonical(args.workload_manifest, "performance workload manifest", 2 * 1024 * 1024)
    performance_config, performance_config_raw = load_canonical(args.performance_config, "Host-performance config", 2 * 1024 * 1024)
    measurements, measurements_raw = load_canonical(args.measurements, "Host-performance measurements", 128 * 1024 * 1024)
    performance, performance_raw = load_canonical(args.performance_evidence, "Host-performance evidence", 8 * 1024 * 1024)
    from host_performance import validate_config as validate_performance_config, validate_evidence_bundle, validate_measurements, validate_workload_manifest
    workload = validate_workload_manifest(workload)
    performance_config = validate_performance_config(performance_config, run_config, run_config_raw, candidate_manifest, candidate_raw, workload_raw)
    validated_measurements, summaries, baseline, extra = validate_measurements(measurements, measurements_raw, performance_config, performance_config_raw, workload)
    performance = validate_evidence_bundle(performance, performance_config, performance_config_raw, validated_measurements, measurements_raw, summaries, baseline, extra, require_pass=True)
    return {
        "candidate_files": candidate_files,
        "candidate_manifest": candidate_manifest,
        "candidate_raw": candidate_raw,
        "machine": machine,
        "machine_raw": machine_raw,
        "manifest": manifest,
        "manifest_raw": manifest_raw,
        "measurements_raw": measurements_raw,
        "performance": performance,
        "performance_config_raw": performance_config_raw,
        "performance_raw": performance_raw,
        "results_path": args.results,
        "results_raw": results_raw,
        "run_config": run_config,
        "run_config_raw": run_config_raw,
        "workload_raw": workload_raw,
    }


def write_exclusive(path: Path, value: Mapping[str, Any]) -> None:
    raw = canonical_bytes(value) + b"\n"
    if len(raw) > MAX_REPORT_BYTES:
        fail("portable release admission report exceeds the 8 MiB bound")
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    commands = root.add_subparsers(dest="command", required=True)
    pack = commands.add_parser("pack", help="validate full evidence and write the portable admission")
    pack.add_argument("--manifest", type=Path, required=True)
    pack.add_argument("--evidence", type=Path, required=True)
    pack.add_argument("--results", type=Path, required=True)
    pack.add_argument("--run-config", type=Path, required=True)
    pack.add_argument("--candidate-manifest", type=Path, required=True)
    pack.add_argument("--candidate-artifact-size", type=int, required=True)
    pack.add_argument("--workload-manifest", type=Path, required=True)
    pack.add_argument("--performance-config", type=Path, required=True)
    pack.add_argument("--measurements", type=Path, required=True)
    pack.add_argument("--performance-evidence", type=Path, required=True)
    pack.add_argument("--output", type=Path, required=True)
    validate = commands.add_parser("validate", help="validate a downloaded portable admission")
    validate.add_argument("--report", type=Path, required=True)
    validate.add_argument("--expected-repository", default=CANDIDATE_REPOSITORY)
    validate.add_argument("--expected-commit", required=True)
    validate.add_argument("--expected-tree", required=True)
    validate.add_argument("--expected-candidate-run-id", type=int, required=True)
    validate.add_argument("--expected-candidate-run-attempt", type=int, required=True)
    validate.add_argument("--expected-candidate-artifact-id", type=int, required=True)
    validate.add_argument("--expected-candidate-artifact-digest", required=True)
    validate.add_argument("--expected-candidate-artifact-size", type=int, required=True)
    validate.add_argument(
        "--minimum-remaining-seconds",
        type=int,
        default=0,
        help="require validity to extend at least this many seconds beyond validation",
    )
    validate.add_argument(
        "--now",
        help="test-only RFC3339 UTC clock override",
    )
    validate.add_argument(
        "--candidate-directory",
        type=Path,
        help="also validate the downloaded exact nine-file candidate against the report",
    )
    validate.add_argument("--github-output", type=Path)
    return root


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "pack":
            if args.candidate_artifact_size < 1:
                fail("candidate GitHub artifact size must be positive")
            values = load_validated_inputs(args)
            report = build_report(
                **values,
                candidate_artifact_size=args.candidate_artifact_size,
                generated_at=datetime.now(timezone.utc),
            )
            write_exclusive(args.output, report)
            print(json.dumps({"report_sha256": sha256_bytes(canonical_bytes(report) + b"\n"), "status": report["status"], "valid": True}, sort_keys=True))
            return 0
        raw = read_regular_bytes(args.report, "portable release admission", MAX_REPORT_BYTES, require_single_link=True)
        value = load_json_bytes(raw, "portable release admission", MAX_REPORT_BYTES)
        if raw != canonical_bytes(value) + b"\n":
            fail("portable release admission must be canonical JSON with one terminal newline")
        expected = {
            "repository": args.expected_repository,
            "commit": args.expected_commit,
            "tree": args.expected_tree,
            "candidate_run_id": args.expected_candidate_run_id,
            "candidate_run_attempt": args.expected_candidate_run_attempt,
            "candidate_artifact_id": args.expected_candidate_artifact_id,
            "candidate_artifact_digest": args.expected_candidate_artifact_digest,
            "candidate_artifact_size": args.expected_candidate_artifact_size,
        }
        if args.minimum_remaining_seconds < 0:
            fail("minimum remaining validity seconds may not be negative")
        clock = parse_timestamp(args.now, "--now") if args.now is not None else None
        report = validate_report(
            value,
            now=clock,
            minimum_remaining=timedelta(seconds=args.minimum_remaining_seconds),
            expected=expected,
        )
        if args.candidate_directory is not None:
            from audit_contract import read_candidate_manifest

            cag_identity = {
                "commit": report["source"]["commit"],
                "so_name": report["source"]["so"]["name"],
                "so_sha256": report["source"]["so"]["sha256"],
                "source_version": report["source"]["source_version"],
                "tree": report["source"]["tree"],
            }
            candidate_manifest, candidate_raw = read_candidate_manifest(
                args.candidate_directory / CANDIDATE_MANIFEST_NAME,
                cag_identity,
            )
            files = validate_candidate_directory(
                args.candidate_directory.resolve(strict=True), candidate_manifest
            )
            if files != report["candidate"]["files"]:
                fail("downloaded candidate file bytes differ from the second-machine report")
            artifact = report["candidate"]["github_artifact"]
            if not (
                sha256_bytes(candidate_raw) == report["candidate"]["manifest_sha256"]
                and candidate_manifest["event"] == "push"
                and candidate_manifest["head_branch"] == "main"
                and candidate_manifest["head_sha"] == candidate_manifest["commit"]
                and int(candidate_manifest["run_id"]) == artifact["run_id"]
                and int(candidate_manifest["run_attempt"]) == artifact["run_attempt"]
            ):
                fail("downloaded candidate manifest provenance differs from the report")
        summary = report["summary"]
        output = {
            "cleanup_pass": str(summary["cleanup_pass"]).lower(),
            "corpus_manifest_sha256": report["corpus"]["manifest_sha256"],
            "corpus_repository_count": report["corpus"]["repository_count"],
            "corpus_source_count": report["corpus"]["source_count"],
            "cpa_binary_sha256": report["cpa"]["binary_sha256"],
            "cpa_commit": report["cpa"]["commit"],
            "cpa_tag": report["cpa"]["tag"],
            "false_positives": summary["false_positives"],
            "independent_proof": str(report["safety"]["independent_proof"]).lower(),
            "malicious_recall_percent": summary["malicious_recall_percent"],
            "owner_run": str(report["safety"]["owner_run"]).lower(),
            "performance_gate_count": summary["performance_gate_count"],
            "performance_gates_passed": summary["performance_gates_passed"],
            "performance_gates_sha256": sha256_bytes(canonical_bytes(report["performance"]["gates"])),
            "performance_status": report["performance"]["status"],
            "report_candidate_artifact_digest": report["candidate"]["github_artifact"]["digest"],
            "report_candidate_artifact_id": report["candidate"]["github_artifact"]["id"],
            "report_candidate_artifact_size": report["candidate"]["github_artifact"]["size"],
            "commit": report["source"]["commit"],
            "expires_at": report["expires_at"],
            "report_sha256": sha256_bytes(raw),
            "so_sha256": report["source"]["so"]["sha256"],
            "status": report["status"],
            "semantic_case_count": summary["semantic_case_count"],
            "semantic_summary_sha256": sha256_bytes(canonical_bytes(report["semantic"]["summary_by_mode"])),
            "side_effect_violations": summary["side_effect_violations"],
            "third_party_code_executions": summary["third_party_code_executions"],
            "tree": report["source"]["tree"],
        }
        if args.github_output is not None:
            with args.github_output.open("a", encoding="utf-8", newline="\n") as handle:
                for key, item in output.items():
                    handle.write(f"{key}={item}\n")
        print(json.dumps({**output, "valid": True}, sort_keys=True))
        return 0
    except (AdmissionError, ContractError, OSError, ValueError, KeyError, zipfile.BadZipFile) as exc:
        print(f"SECOND-MACHINE RELEASE ADMISSION FAILED: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
