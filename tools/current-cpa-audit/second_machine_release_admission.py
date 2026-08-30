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
from collections import Counter, defaultdict
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
    CPA_C_ABI,
    CPA_COMMIT,
    CPA_OFFICIAL_ASSET_NAME,
    CPA_OFFICIAL_ASSET_SHA256,
    CPA_OFFICIAL_ASSET_SIZE,
    CPA_OFFICIAL_BINARY_SHA256,
    CPA_OFFICIAL_BINARY_SIZE,
    CPA_RPC_SCHEMA,
    CPA_TAG,
    ContractError,
    EXPECTED_SUPPLEMENTAL_ZIP_CASE_COUNT,
    EXPECTED_SUPPLEMENTAL_ZIP_ENTRY_COUNT,
    MODES,
    PROTOCOLS,
    SUPPLEMENTAL_ZIP_ARCHIVE_IDENTITY,
    SUPPLEMENTAL_ZIP_CASE_SUFFIXES,
    SUPPLEMENTAL_ZIP_LIMITS,
    SUPPLEMENTAL_ZIP_POLICY_SHA256,
    STREAM_VALUES,
    canonical_bytes,
    iter_jsonl_bytes,
    load_json_bytes,
    read_regular_bytes,
    require_repo_digest,
    require_safe_relative,
    sha256_bytes,
    validate_candidate_manifest_file,
    validate_evidence_run_config,
    validate_machine_evidence,
    validate_realtime_boundary,
    validate_result,
    validate_run_config,
    validate_supplemental_result,
    validate_supplemental_manifest,
    validate_supplemental_policy,
    validate_supplemental_run_config_files,
)


# v3 closes the Round 14 admission boundary by carrying immutable references to
# the lazy-read and CSAM-text evidence planes. Historical v2 reports are not
# accepted by this packer or by the standalone validator.
SCHEMA = "cyber-abuse-guard.second-machine-release-admission.v3"
STATUS = "SECOND_MACHINE_OWNER_RELEASE_ADMISSION_PASS"
SUPPLEMENTAL_STATUS = "SUPPLEMENTAL_ARCHIVE_PASS"
BOUNDARY = "OWNER-RUN SECOND-MACHINE RELEASE ADMISSION; NOT INDEPENDENT PROOF"
REPORT_NAME = "second-machine-release-admission.json"
SCHEMA_NAME = "second-machine-release-admission.schema.json"
REPORT_TTL = timedelta(hours=24)
MAX_CLOCK_SKEW = timedelta(minutes=5)
MAX_REPORT_BYTES = 8 * 1024 * 1024
MAX_CANDIDATE_FILE_BYTES = 512 * 1024 * 1024
HEX40 = re.compile(r"[0-9a-f]{40}")
HEX64 = re.compile(r"(?!0{64})[0-9a-f]{64}")
DIGEST = re.compile(r"sha256:(?!0{64})[0-9a-f]{64}")
SAFE_ID = re.compile(r"[a-z0-9][a-z0-9_.-]{2,62}")
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
    "host_admission_evidence_sha256",
    "host_admission_config_sha256",
    "host_admission_evidence_manifest_sha256",
    "host_admission_sqlite_sha256",
    "host_admission_300s_samples_sha256",
    "host_admission_3600s_samples_sha256",
    "host_admission_realtime_routes_sha256",
    "machine_evidence_sha256",
    "native_host_go_test_log_sha256",
    "native_host_special_paths_report_sha256",
    "performance_workload_manifest_sha256",
    "run_config_sha256",
    "supplemental_archive_sha256",
    "supplemental_manifest_sha256",
    "supplemental_policy_sha256",
    "supplemental_results_sha256",
    "transport_results_sha256",
    "lazy_read_phase_boundary_sha256",
    "lazy_read_runtime_read_trace_sha256",
    "lazy_read_runtime_read_summary_sha256",
    "csam_text_fixture_manifest_sha256",
    "csam_text_results_sha256",
    "csam_text_summary_sha256",
    "csam_text_privacy_cleanup_sha256",
)
EXPECTED_CORE_COLD_STARTS = 3
EXPECTED_CORE_EXECUTIONS = 684
EXPECTED_SUPPLEMENTAL_EXECUTIONS = 252
EXPECTED_SUPPLEMENTAL_CASE_IDS = tuple(
    sorted(
        f"supplemental-zip:{entry_id}:{suffix}"
        for entry_id, suffixes in SUPPLEMENTAL_ZIP_CASE_SUFFIXES.items()
        for suffix in suffixes
    )
)

# These paths are deliberately fixed below the original evidence root.  A
# portable report retains only hashes and summaries; the packer must validate
# the original bytes before it can emit a PASS.
LAZY_READ_PATHS = {
    "phase_boundary": "lazy-read/phase-boundary.json",
    "runtime_read_trace": "lazy-read/runtime-read-trace.jsonl",
    "runtime_read_summary": "lazy-read/runtime-read-summary.json",
}
CSAM_TEXT_PATHS = {
    "fixture_manifest": "csam-text/fixture-manifest.json",
    "results": "csam-text/results.json",
    "summary": "csam-text/summary.json",
    "privacy_cleanup": "csam-text/privacy-cleanup.json",
}
LAZY_PHASE_SCHEMA = "cag-current-cpa-lazy-read-phase-boundary/v1"
LAZY_TRACE_SCHEMA = "cag-current-cpa-lazy-read-trace/v1"
LAZY_SUMMARY_SCHEMA = "cag-current-cpa-lazy-read-summary/v1"
CSAM_MANIFEST_SCHEMA = "cag-current-cpa-csam-text-fixture-manifest/v1"
CSAM_RESULTS_SCHEMA = "cag-current-cpa-csam-text-results/v1"
CSAM_SUMMARY_SCHEMA = "cag-current-cpa-csam-text-summary/v1"
CSAM_CLEANUP_SCHEMA = "cag-current-cpa-csam-text-privacy-cleanup/v1"

# The text-only CSAM plane is intentionally a closed, synthetic catalog.  The
# admission validator must not accept an arbitrary caller-chosen case ID or
# classifier winner and then report it as coverage for the reviewed matrix.
CSAM_MALICIOUS_FAMILIES = (
    "production",
    "solicitation",
    "exchange",
    "dissemination",
    "grooming",
)
CSAM_BENIGN_FAMILIES = (
    "news",
    "legal-compliance",
    "reporting",
    "victim-support",
    "security-research",
    "parental-protection",
    "content-removal",
)
CSAM_MALICIOUS_CASE_IDS = frozenset(
    f"csam-malicious-{family}-{variant}"
    for family in CSAM_MALICIOUS_FAMILIES
    for variant in range(1, 4)
)
CSAM_BENIGN_CASE_IDS = frozenset(
    f"csam-benign-{family}-{variant}"
    for family in CSAM_BENIGN_FAMILIES
    for variant in range(1, 4)
)
CSAM_CASE_LABELS = {
    **{case_id: "malicious" for case_id in CSAM_MALICIOUS_CASE_IDS},
    **{case_id: "benign" for case_id in CSAM_BENIGN_CASE_IDS},
}
CSAM_RULE_IDS = frozenset(
    {
        "CSAM-TXT-PRODUCTION-001",
        "CSAM-TXT-SOLICITATION-001",
        "CSAM-TXT-EXCHANGE-001",
        "CSAM-TXT-DISSEMINATION-001",
        "CSAM-TXT-GROOMING-001",
    }
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


def exact_run_id(value: Any, label: str) -> str:
    """Validate the lower-case run identity required by the JSON schema.

    Run IDs become directory/evidence selectors and are copied across three
    independently produced evidence planes.  Keeping the standalone validator
    on the same safe alphabet and length bounds as the schema prevents a
    malformed portable report from being accepted when JSON Schema is not
    installed.
    """

    run_id = exact_string(value, label, 63)
    if SAFE_ID.fullmatch(run_id) is None:
        fail(f"{label} is not a safe lower-case run identity")
    return run_id


def nullable_exact_string(
    value: Any, label: str, maximum: int = 1024
) -> str | None:
    if value is None:
        return None
    return exact_string(value, label, maximum)


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


def validate_realtime_projection(
    value: Any, *, cold_start_count: int = EXPECTED_CORE_COLD_STARTS
) -> dict[str, Any]:
    """Validate the portable realtime projection as strictly as machine evidence.

    The report intentionally projects only the fixed v7.2.145 negative-coverage
    proof.  Re-validate every projected field so a portable report cannot turn a
    malformed or side-effecting probe into an unprotected/CAG-invisible claim.
    """

    try:
        return validate_realtime_boundary(
            value,
            cold_start_count=cold_start_count,
            label="report.realtime",
        )
    except ContractError as exc:
        fail(str(exc))


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


def load_canonical_bytes(raw: bytes, label: str) -> tuple[dict[str, Any], bytes]:
    if not isinstance(raw, bytes):
        fail(f"{label} must be supplied as bytes")
    value = load_json_bytes(raw, label, len(raw) or 1)
    if type(value) is not dict:
        fail(f"{label} must be a JSON object")
    if raw != canonical_bytes(value) + b"\n":
        fail(f"{label} must be canonical JSON with one terminal newline")
    return value, raw


def _strict_evidence_path(
    path: Path, evidence_directory: Path, expected_relative: str, label: str
) -> Path:
    """Bind one supplied evidence argument to its fixed path below the run root."""

    try:
        require_safe_relative(expected_relative, f"{label} expected path")
        resolved = path.resolve(strict=True)
        expected = (evidence_directory / expected_relative).resolve(strict=True)
    except ContractError as exc:
        fail(str(exc))
    if resolved != expected:
        fail(f"{label} must be the fixed original evidence file {expected_relative}")
    return resolved


def _positive_int(value: Any, label: str) -> int:
    return exact_int(value, label, 1)


def validate_lazy_read_evidence(
    phase_boundary: Any,
    trace_raw: bytes,
    summary: Any,
) -> dict[str, Any]:
    """Validate the text-free Round 14 lazy-read evidence plane.

    This contract proves the phase split structurally: verification reads may
    occur before transport, while transport reads are exactly one bound corpus
    file per request.  It also requires finally-cleanup and zero retained text.
    """

    phase = exact_object(
        phase_boundary,
        {
            "preflight_completed",
            "preflight_full_corpus_cache_created",
            "run_id",
            "schema",
            "status",
            "transport_started_after_preflight",
        },
        "lazy-read phase boundary",
    )
    if (
        phase["schema"] != LAZY_PHASE_SCHEMA
        or phase["status"] != "PASS"
        or exact_bool(phase["preflight_completed"], "lazy-read phase boundary.preflight_completed")
        is not True
        or exact_bool(
            phase["transport_started_after_preflight"],
            "lazy-read phase boundary.transport_started_after_preflight",
        )
        is not True
        or exact_bool(
            phase["preflight_full_corpus_cache_created"],
            "lazy-read phase boundary.preflight_full_corpus_cache_created",
        )
        is not False
    ):
        fail("lazy-read phase boundary is not a complete PASS")
    run_id = exact_run_id(phase["run_id"], "lazy-read phase boundary.run_id")

    if not isinstance(trace_raw, bytes):
        fail("lazy-read runtime trace must be supplied as bytes")
    trace_rows = list(
        iter_jsonl_bytes(trace_raw, "lazy-read runtime trace", 32 * 1024)
    )
    if not trace_rows:
        fail("lazy-read runtime trace is empty")
    phases: set[str] = set()
    # A request digest identifies the request bytes, not an execution.  The
    # same request is expected to recur across cold starts, and independently
    # approved core/ZIP sources may contain identical normalized text.  Retain
    # the execution multiset while rejecting only a digest paired with
    # different source *content* here.  ``validate_lazy_read_bindings`` below
    # separately binds every execution to its exact path, byte count, and case
    # identity so this duplicate-content allowance cannot hide a wrong-file
    # read.
    transport_requests: list[str] = []
    transport_contents: dict[str, tuple[str, int]] = {}
    transport_reads = 0
    transport_started = False
    for index, raw in enumerate(trace_rows):
        label = f"lazy-read runtime trace[{index}]"
        row = exact_object(
            raw,
            {
                "bytes",
                "case_id_hash",
                "ordinal",
                "phase",
                "request_sha256",
                "run_id",
                "schema",
                "source_path",
                "source_sha256",
            },
            label,
        )
        if row["schema"] != LAZY_TRACE_SCHEMA or row["run_id"] != run_id:
            fail(f"{label} schema/run identity drifted")
        if exact_int(row["ordinal"], f"{label}.ordinal", 1) != index + 1:
            fail(f"{label}.ordinal is not consecutive")
        phase_name = exact_string(row["phase"], f"{label}.phase", 16)
        if phase_name not in {"preflight", "transport"}:
            fail(f"{label}.phase is not preflight or transport")
        phases.add(phase_name)
        require_safe_relative(row["source_path"], f"{label}.source_path", "corpus")
        require_hex(row["source_sha256"], f"{label}.source_sha256")
        require_hex(row["case_id_hash"], f"{label}.case_id_hash")
        _positive_int(row["bytes"], f"{label}.bytes")
        request_sha = row["request_sha256"]
        if phase_name == "transport":
            transport_started = True
            require_hex(request_sha, f"{label}.request_sha256")
            content_identity = (
                row["source_sha256"],
                row["bytes"],
            )
            prior_content = transport_contents.setdefault(request_sha, content_identity)
            if prior_content != content_identity:
                fail("lazy-read transport request hash is bound to different source content")
            transport_requests.append(request_sha)
            transport_reads += 1
        elif request_sha is not None:
            fail(f"{label}.request_sha256 must be null during preflight")
        elif transport_started:
            fail("lazy-read preflight trace occurs after transport started")
    if phases != {"preflight", "transport"}:
        fail("lazy-read runtime trace must distinguish preflight and transport")

    detail = exact_object(
        summary,
        {
            "finally_cleanup_complete",
            "full_corpus_cache_created",
            "post_unlink_nlink_zero",
            "run_id",
            "schema",
            "status",
            "supplemental_member_text_retained",
            "temporary_secret_or_config_retained",
            "third_party_text_retained",
            "trace_sha256",
            "transport_request_count",
            "transport_source_read_count",
        },
        "lazy-read runtime summary",
    )
    if detail["schema"] != LAZY_SUMMARY_SCHEMA or detail["run_id"] != run_id:
        fail("lazy-read runtime summary schema/run identity drifted")
    if detail["status"] != "PASS":
        fail("lazy-read runtime summary is not PASS")
    if require_hex(detail["trace_sha256"], "lazy-read runtime summary.trace_sha256") != sha256_bytes(trace_raw):
        fail("lazy-read runtime summary does not bind the trace bytes")
    request_count = _positive_int(
        detail["transport_request_count"],
        "lazy-read runtime summary.transport_request_count",
    )
    read_count = _positive_int(
        detail["transport_source_read_count"],
        "lazy-read runtime summary.transport_source_read_count",
    )
    if request_count != transport_reads or read_count != transport_reads:
        # Keep the legacy diagnostic stable for a stale denominator or an
        # appended duplicate row.  A legitimate repeated request must update
        # both execution counters and is represented as a multiset below.
        fail("lazy-read transport trace reads more than one source for a request")
    expected_booleans = {
        "finally_cleanup_complete": True,
        "full_corpus_cache_created": False,
        "post_unlink_nlink_zero": True,
        "supplemental_member_text_retained": False,
        "temporary_secret_or_config_retained": False,
        "third_party_text_retained": False,
    }
    for key, expected in expected_booleans.items():
        if exact_bool(detail[key], f"lazy-read runtime summary.{key}") is not expected:
            fail(f"lazy-read runtime summary.{key} does not close the privacy boundary")
    return {
        "phase_boundary_status": phase["status"],
        "preflight_trace_count": sum(row["phase"] == "preflight" for row in trace_rows),
        "run_id": run_id,
        "status": detail["status"],
        "transport_request_count": request_count,
        "transport_source_read_count": read_count,
    }


def validate_lazy_read_bindings(
    trace_raw: bytes,
    manifest: Mapping[str, Any],
    results_raw: bytes,
    supplemental_manifest: Mapping[str, Any],
    supplemental_results_raw: bytes,
) -> None:
    """Bind runtime reads to every validated core and supplemental request."""
    core_cases = {case["id"]: case for case in manifest["semantic_cases"]}
    zip_cases = {case["id"]: case for case in supplemental_manifest["reviewed_cases"]}
    core_rows = [validate_result(v, core_cases, f"lazy core result[{i}]") for i, v in enumerate(iter_jsonl_bytes(results_raw, "lazy core results"))]
    zip_rows = [validate_supplemental_result(v, zip_cases, f"lazy ZIP result[{i}]") for i, v in enumerate(iter_jsonl_bytes(supplemental_results_raw, "lazy ZIP results"))]
    if (len(core_rows), len(zip_rows)) != (EXPECTED_CORE_EXECUTIONS, EXPECTED_SUPPLEMENTAL_EXECUTIONS):
        fail("lazy-read binding does not cover the fixed 684/252 denominators")
    expected: Counter[tuple[str, str, str, int, str]] = Counter()
    request_contents: dict[str, tuple[str, int]] = {}

    def add_expected(
        row: Mapping[str, Any],
        case: Mapping[str, Any],
        *,
        supplemental: bool,
    ) -> None:
        request = row["request_sha256"]
        source = row["source_text_sha256"]
        source_detail = case["source"]
        source_bytes = source_detail["text_bytes"]
        if supplemental:
            source_path = "corpus/supplemental/" + sha256_bytes(
                str(source_detail["entry_id"]).encode("utf-8", "strict")
            )
            case_id = row["supplemental_case_id"]
        else:
            source_path = source_detail["corpus_file"]
            case_id = row["semantic_case_id"]
        content_identity = (source, source_bytes)
        prior_content = request_contents.setdefault(request, content_identity)
        if prior_content != content_identity:
            fail("validated results reuse one request hash for different source content")
        expected[
            (
                request,
                source,
                source_path,
                source_bytes,
                hashlib.sha256(case_id.encode("utf-8", "strict")).hexdigest(),
            )
        ] += 1

    for row in core_rows:
        add_expected(row, core_cases[row["semantic_case_id"]], supplemental=False)
    for row in zip_rows:
        add_expected(
            row,
            zip_cases[row["supplemental_case_id"]],
            supplemental=True,
        )

    observed: Counter[tuple[str, str, str, int, str]] = Counter()
    for i, value in enumerate(iter_jsonl_bytes(trace_raw, "bound lazy-read trace", 32 * 1024)):
        if value.get("phase") != "transport":
            continue
        request = value.get("request_sha256")
        source = value.get("source_sha256")
        if request not in request_contents:
            fail(f"bound lazy-read trace[{i}] request is unknown")
        key = (
            request,
            source,
            value.get("source_path"),
            value.get("bytes"),
            value.get("case_id_hash"),
        )
        if key not in expected:
            fail(
                f"bound lazy-read trace[{i}] source metadata differs from its transport result"
            )
        observed[key] += 1
        if observed[key] > expected[key]:
            fail(f"bound lazy-read trace[{i}] request appears more times than its execution multiset")
    if observed != expected:
        fail("lazy-read trace does not cover every core and supplemental transport request")


def validate_csam_text_evidence(
    fixture_manifest: Any,
    results: Any,
    summary: Any,
    privacy_cleanup: Any,
    *,
    expected_run_id: str | None = None,
) -> dict[str, Any]:
    """Validate Round 14's separate synthetic CSAM-text feasibility plane."""

    fixture = exact_object(
        fixture_manifest,
        {
            "benign_case_count",
            "cases",
            "fixture_text_retained",
            "malicious_case_count",
            "real_or_explicit_media_inputs",
            "run_id",
            "schema",
            "status",
            "synthetic_text_only",
        },
        "CSAM text fixture manifest",
    )
    if (
        fixture["schema"] != CSAM_MANIFEST_SCHEMA
        or fixture["status"] != "PASS"
        or exact_int(fixture["malicious_case_count"], "CSAM text fixture manifest.malicious_case_count") != 15
        or exact_int(fixture["benign_case_count"], "CSAM text fixture manifest.benign_case_count") != 21
        or exact_bool(fixture["synthetic_text_only"], "CSAM text fixture manifest.synthetic_text_only") is not True
        or exact_bool(fixture["fixture_text_retained"], "CSAM text fixture manifest.fixture_text_retained") is not False
        or exact_int(fixture["real_or_explicit_media_inputs"], "CSAM text fixture manifest.real_or_explicit_media_inputs") != 0
    ):
        fail("CSAM text fixture manifest is not the fixed synthetic 15/21 PASS plane")
    run_id = exact_run_id(fixture["run_id"], "CSAM text fixture manifest.run_id")
    cases = exact_list(fixture["cases"], "CSAM text fixture manifest.cases")
    if len(cases) != 36:
        fail("CSAM text fixture manifest must bind exactly 36 cases")
    case_map: dict[str, dict[str, Any]] = {}
    case_text_hashes: set[str] = set()
    for index, raw in enumerate(cases):
        case = exact_object(raw, {"case_id", "label", "text_sha256"}, f"CSAM case[{index}]")
        case_id = exact_string(case["case_id"], f"CSAM case[{index}].case_id", 128)
        label = case["label"]
        if type(label) is not str or label != CSAM_CASE_LABELS.get(case_id):
            fail("CSAM text case identity/label is not the fixed 15/21 catalog")
        if case_id in case_map:
            fail("CSAM text case identity/label is duplicated")
        text_sha = require_hex(case["text_sha256"], f"CSAM case[{index}].text_sha256")
        if text_sha in case_text_hashes:
            fail("CSAM text fixture contains duplicate text identities")
        case_text_hashes.add(text_sha)
        case_map[case_id] = case
    if set(case_map) != set(CSAM_CASE_LABELS):
        fail("CSAM text fixture case IDs do not match the fixed catalog")
    if sum(c["label"] == "malicious" for c in cases) != 15:
        fail("CSAM text fixture malicious denominator drifted")

    result = exact_object(
        results,
        {
            "audit_detected_malicious",
            "audit_http_blocks",
            "balanced_blocked_malicious",
            "benign_allowed",
            "cold_start_count",
            "false_positive_count",
            "malicious_case_count",
            "executions",
            "run_id",
            "schema",
            "side_effect_violations",
            "status",
            "strict_blocked_malicious",
            "unexpected_errors",
        },
        "CSAM text results",
    )
    if result["schema"] != CSAM_RESULTS_SCHEMA or result["status"] != "PASS":
        fail("CSAM text results are not PASS")
    if exact_run_id(result["run_id"], "CSAM text results.run_id") != run_id:
        fail("CSAM text results run identity drifted")
    expected_counts = {
        "audit_detected_malicious": 15,
        "audit_http_blocks": 0,
        "balanced_blocked_malicious": 15,
        "benign_allowed": 21,
        "cold_start_count": 3,
        "false_positive_count": 0,
        "malicious_case_count": 15,
        "side_effect_violations": 0,
        "strict_blocked_malicious": 15,
        "unexpected_errors": 0,
    }
    for key, expected in expected_counts.items():
        if exact_int(result[key], f"CSAM text results.{key}") != expected:
            fail(f"CSAM text results.{key} does not meet the fixed admission denominator")
    executions = exact_list(result["executions"], "CSAM text results.executions")
    expected_matrix = {
        (case_id, mode, protocol, stream, cold)
        for case_id in case_map for mode in MODES for protocol in PROTOCOLS
        for stream in STREAM_VALUES for cold in range(1, 4)
    }
    seen: set[tuple[str, str, str, bool, int]] = set()
    for index, raw in enumerate(executions):
        row = exact_object(raw, {
            "actual_action", "case_id", "category", "cold_start", "mode",
            "protocol", "request_sha256", "side_effect_deltas", "stream",
            "text_retained", "trusted_current_user", "winning_rule_id",
        }, f"CSAM execution[{index}]")
        case_id = exact_string(
            row["case_id"], f"CSAM execution[{index}].case_id", 128
        )
        if case_id not in case_map:
            fail("CSAM execution references an unknown case ID")
        mode = exact_string(row["mode"], f"CSAM execution[{index}].mode", 16)
        protocol = exact_string(
            row["protocol"], f"CSAM execution[{index}].protocol", 16
        )
        if mode not in MODES or protocol not in PROTOCOLS:
            fail("CSAM execution mode or protocol is outside the fixed matrix")
        stream = exact_bool(row["stream"], f"CSAM execution[{index}].stream")
        cold_start = exact_int(
            row["cold_start"], f"CSAM execution[{index}].cold_start", 1
        )
        if cold_start > EXPECTED_CORE_COLD_STARTS:
            fail("CSAM execution cold_start is outside the fixed 1..3 range")
        identity = (
            case_id,
            mode,
            protocol,
            stream,
            cold_start,
        )
        if identity in seen or identity not in expected_matrix:
            fail("CSAM execution identity is duplicate or outside the fixed matrix")
        seen.add(identity)
        require_hex(row["request_sha256"], f"CSAM execution[{index}].request_sha256")
        if exact_bool(row["trusted_current_user"], f"CSAM execution[{index}].trusted_current_user") is not True:
            fail("CSAM enforcement evidence is not current trusted user content")
        if exact_bool(row["text_retained"], f"CSAM execution[{index}].text_retained") is not False:
            fail("CSAM execution retained text")
        side = exact_object(row["side_effect_deltas"], {"auth", "mock", "provider", "usage"}, f"CSAM execution[{index}].side_effect_deltas")
        if any(
            type(value) is not int or value < 0
            for value in side.values()
        ):
            fail("CSAM execution side-effect delta is not a non-negative integer")
        malicious = case_map[identity[0]]["label"] == "malicious"
        blocked = malicious and identity[1] in {"balanced", "strict"}
        expected_action = "block_malicious_text" if blocked else "allow"
        expected_category = "csam_malicious" if malicious else None
        actual_action = exact_string(
            row["actual_action"], f"CSAM execution[{index}].actual_action", 64
        )
        category = row["category"]
        if category is not None and type(category) is not str:
            fail("CSAM execution category must be a string or null")
        if actual_action != expected_action or category != expected_category:
            fail("CSAM execution outcome/category violates eligibility")
        winner = row["winning_rule_id"]
        if malicious:
            winner = exact_string(
                winner, f"CSAM execution[{index}].winning_rule_id", 128
            )
            if winner not in CSAM_RULE_IDS:
                fail("CSAM malicious execution winner is not an eligible CSAM rule")
        if not malicious and row["winning_rule_id"] is not None:
            fail("CSAM benign execution fabricated a winner")
        expected_side = {key: 0 for key in side} if blocked else {key: 1 for key in side}
        if side != expected_side:
            fail("CSAM execution violates the allow/block side-effect contract")
    if seen != expected_matrix:
        fail("CSAM results do not cover the exact 36-case execution matrix")

    detail = exact_object(
        summary,
        {
            "audit_detection_percent",
            "audit_http_block_percent",
            "balanced_block_percent",
            "benign_allow_percent",
            "malicious_case_count",
            "run_id",
            "schema",
            "status",
            "strict_block_percent",
        },
        "CSAM text summary",
    )
    if detail["schema"] != CSAM_SUMMARY_SCHEMA or detail["status"] != "PASS":
        fail("CSAM text summary is not PASS")
    if exact_run_id(detail["run_id"], "CSAM text summary.run_id") != run_id:
        fail("CSAM text summary run identity drifted")
    for key, expected in {
        "audit_detection_percent": 100,
        "audit_http_block_percent": 0,
        "balanced_block_percent": 100,
        "benign_allow_percent": 100,
        "strict_block_percent": 100,
    }.items():
        if exact_number(detail[key], f"CSAM text summary.{key}") != expected:
            fail(f"CSAM text summary.{key} does not meet the admission threshold")
    if exact_int(detail["malicious_case_count"], "CSAM text summary.malicious_case_count") != 15:
        fail("CSAM text summary malicious denominator drifted")

    cleanup = exact_object(
        privacy_cleanup,
        {
            "fixture_text_retained",
            "real_or_explicit_media_inputs",
            "reversible_encodings_retained",
            "run_id",
            "schema",
            "status",
            "synthetic_text_only",
        },
        "CSAM text privacy cleanup",
    )
    if (
        cleanup["schema"] != CSAM_CLEANUP_SCHEMA
        or cleanup["status"] != "PASS"
        or exact_bool(cleanup["fixture_text_retained"], "CSAM text privacy cleanup.fixture_text_retained") is not False
        or exact_bool(cleanup["reversible_encodings_retained"], "CSAM text privacy cleanup.reversible_encodings_retained") is not False
        or exact_bool(cleanup["synthetic_text_only"], "CSAM text privacy cleanup.synthetic_text_only") is not True
        or exact_int(cleanup["real_or_explicit_media_inputs"], "CSAM text privacy cleanup.real_or_explicit_media_inputs") != 0
    ):
        fail("CSAM text privacy cleanup is not complete")
    if exact_run_id(cleanup["run_id"], "CSAM text privacy cleanup.run_id") != run_id:
        fail("CSAM text privacy cleanup run identity drifted")
    if expected_run_id is not None and run_id != expected_run_id:
        fail("CSAM text evidence run ID differs from the machine evidence")
    return {
        "benign_case_count": 21,
        "false_positive_count": 0,
        "malicious_case_count": 15,
        "run_id": run_id,
        "status": "PASS",
    }


def bind_supplemental_archive(path: Path) -> dict[str, int | str]:
    """Seal the operator-owned archive without extracting any member to disk."""

    before = path.stat(follow_symlinks=False)
    raw = read_regular_bytes(
        path,
        "supplemental ZIP archive",
        SUPPLEMENTAL_ZIP_LIMITS["max_archive_bytes"],
        require_single_link=True,
    )
    after = path.stat(follow_symlinks=False)
    identity_fields = ("st_dev", "st_ino", "st_nlink", "st_size")
    if any(getattr(before, key) != getattr(after, key) for key in identity_fields):
        fail("supplemental ZIP archive identity changed while hashing")
    binding: dict[str, int | str] = {
        "bytes": len(raw),
        "sha256": sha256_bytes(raw),
        **{key: int(getattr(after, key)) for key in identity_fields},
    }
    if (
        binding["bytes"] != SUPPLEMENTAL_ZIP_ARCHIVE_IDENTITY["bytes"]
        or binding["sha256"] != SUPPLEMENTAL_ZIP_ARCHIVE_IDENTITY["sha256"]
    ):
        fail("supplemental ZIP archive differs from the fixed reviewed bytes")
    return binding


def reverify_supplemental_archive(
    path: Path, expected: Mapping[str, int | str]
) -> None:
    if bind_supplemental_archive(path) != dict(expected):
        fail("supplemental ZIP archive stat/SHA identity changed during admission packing")


def validate_supplemental_evidence_copies(
    *,
    original_manifest: Mapping[str, Any],
    original_manifest_raw: bytes,
    original_policy: Mapping[str, Any],
    original_policy_raw: bytes,
    evidence_manifest_path: Path,
    evidence_policy_path: Path,
) -> None:
    """Require evidence-directory copies to equal the separately bound originals."""

    evidence_policy_raw = read_regular_bytes(
        evidence_policy_path,
        "evidence-copy supplemental ZIP policy",
        2 * 1024 * 1024,
        require_single_link=True,
    )
    evidence_policy = validate_supplemental_policy(
        load_json_bytes(evidence_policy_raw, "evidence-copy supplemental ZIP policy"),
    )
    evidence_manifest, evidence_manifest_raw = load_canonical(
        evidence_manifest_path,
        "evidence-copy supplemental ZIP manifest",
        8 * 1024 * 1024,
    )
    evidence_manifest = validate_supplemental_manifest(
        evidence_manifest,
        evidence_policy,
        policy_sha256=sha256_bytes(evidence_policy_raw),
    )
    if (
        evidence_policy != dict(original_policy)
        or evidence_policy_raw != original_policy_raw
        or evidence_manifest != dict(original_manifest)
        or evidence_manifest_raw != original_manifest_raw
    ):
        fail("supplemental ZIP evidence copies differ from the run-config original bytes")


def local_tool_identities() -> dict[str, Any]:
    from host_performance import tool_identities as host_tool_identities
    from host_admission_collector import tool_identities as host_admission_tool_identities
    import native_host_special_paths
    from run import runner_identities

    source_sha, _, _ = sha256_file(SCRIPT_PATH, "release admission packer", 2 * 1024 * 1024)
    schema_sha, _, _ = sha256_file(SCHEMA_PATH, "release admission schema", 2 * 1024 * 1024)
    native_test_source_sha, _, _ = sha256_file(
        TOOL_DIR.parent.parent / native_host_special_paths.TEST_SOURCE,
        "native Host integration test source",
        8 * 1024 * 1024,
    )
    return {
        "admission": {
            "schema_sha256": schema_sha,
            "source_sha256": source_sha,
        },
        "host_performance": host_tool_identities(),
        "host_admission": host_admission_tool_identities(),
        "machine": runner_identities(),
        "native_host_special_paths": {
            **native_host_special_paths.tool_identity(),
            "test_source_sha256": native_test_source_sha,
        },
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
            member = members[0]
            mode = member.external_attr >> 16
            if (
                member.flag_bits & 0x1
                or member.is_dir()
                or (mode and stat.S_IFMT(mode) not in (0, stat.S_IFREG))
            ):
                fail("candidate Store ZIP member is not a regular file")
            if member.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                fail("candidate Store ZIP uses an unsupported compression method")
            if member.file_size != len(so_raw):
                fail("candidate Store ZIP SO declared size differs from the standalone SO")
            offset = 0
            with archive.open(member, "r") as source:
                while chunk := source.read(1024 * 1024):
                    next_offset = offset + len(chunk)
                    if next_offset > len(so_raw) or chunk != so_raw[offset:next_offset]:
                        fail("candidate Store ZIP SO bytes differ from the standalone SO")
                    offset = next_offset
            if offset != len(so_raw):
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


def derive_supplemental_semantics(
    manifest: Mapping[str, Any], results_raw: bytes, cold_start_arms: Sequence[int]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    cases = {case["id"]: case for case in manifest["reviewed_cases"]}
    if tuple(sorted(cases)) != EXPECTED_SUPPLEMENTAL_CASE_IDS:
        fail("supplemental manifest does not contain the exact seven reviewed cases")
    rows = [
        validate_supplemental_result(value, cases, f"portable supplemental result[{index}]")
        for index, value in enumerate(
            iter_jsonl_bytes(results_raw, "supplemental ZIP results")
        )
    ]
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped[(row["supplemental_case_id"], row["mode"])].append(row)
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
                (row["protocol"], row["stream"], row["cold_start"])
                for row in selected
            }
            if len(selected) != len(expected_matrix) or observed_matrix != expected_matrix:
                fail(f"supplemental summary cell {case_id}/{mode} is incomplete")
            expected_actions = {row["expected_action"] for row in selected}
            actual_actions = {row["actual_action"] for row in selected}
            if len(expected_actions) != 1 or len(actual_actions) != 1:
                fail(f"supplemental summary cell {case_id}/{mode} is inconsistent")
            expected_action = next(iter(expected_actions))
            actual_action = next(iter(actual_actions))
            actual_winners = {
                (
                    row["audit_event"]["category"],
                    row["audit_event"]["winning_rule_id"],
                )
                if row["audit_event"] is not None
                else (None, None)
                for row in selected
            }
            if len(actual_winners) != 1:
                fail(
                    f"supplemental summary cell {case_id}/{mode} has inconsistent winning rules"
                )
            actual_winning_category, actual_winning_rule_id = next(
                iter(actual_winners)
            )
            side_expected = (
                {"auth": 1, "mock": 1, "provider": 1, "usage": 1}
                if expected_action == "allow"
                else {"auth": 0, "mock": 0, "provider": 0, "usage": 0}
            )
            side_violations = sum(
                row["side_effect_deltas"] != side_expected for row in selected
            )
            if mode == "audit":
                detected = malicious and all(
                    row["actual_action"] == "allow"
                    and row["audit_event"] is not None
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
                    "actual_winning_category": actual_winning_category,
                    "actual_winning_rule_id": actual_winning_rule_id,
                    "all_executions_passed": all(row["passed"] for row in selected),
                    "execution_count": len(selected),
                    "expected_action": expected_action,
                    "expected_winning_category": case["expected_winning_category"],
                    "expected_winning_rule_id": case["expected_winning_rule_id"],
                    "false_positive": (not malicious and actual_action != "allow"),
                    "label": case["label"],
                    "malicious": malicious,
                    "malicious_detected": detected,
                    "mode": mode,
                    "side_effect_violations": side_violations,
                    "supplemental_case_id": case_id,
                }
            )
    return outcomes, derive_supplemental_summary(outcomes)


def derive_supplemental_summary(
    outcomes: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    summaries: list[dict[str, Any]] = []
    for mode in MODES:
        selected = [row for row in outcomes if row["mode"] == mode]
        benign = [row for row in selected if not row["malicious"]]
        malicious = [row for row in selected if row["malicious"]]
        detected = sum(row["malicious_detected"] is True for row in malicious)
        denominator = len(malicious)
        summaries.append(
            {
                "all_supplemental_contracts_passed": bool(selected)
                and all(row["all_executions_passed"] is True for row in selected),
                "false_positive_denominator": len(benign),
                "false_positives": sum(row["false_positive"] is True for row in benign),
                "malicious_detected": detected,
                "malicious_recall_denominator": denominator,
                "malicious_recall_percent": (
                    100.0 * detected / denominator if denominator else 0.0
                ),
                "mode": mode,
                "side_effect_violations": sum(
                    int(row["side_effect_violations"]) for row in selected
                ),
                "supplemental_cases": len(selected),
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
        "realtime_protection": report["realtime"]["protection"],
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


def _native_host_projection(
    native_report: Mapping[str, Any],
    native_report_raw: bytes,
    native_go_test_raw: bytes,
    *,
    candidate: Mapping[str, Any],
    source: Mapping[str, Any],
    cpa: Mapping[str, Any],
) -> dict[str, Any]:
    import native_host_special_paths as native

    native_candidate = native_report["candidate"]
    native_artifact = native_candidate["artifact"]
    portable_artifact = candidate["github_artifact"]
    if not (
        native_candidate["source"]["commit"] == source["commit"]
        and native_candidate["source"]["tree"] == source["tree"]
        and native_candidate["so"]["sha256"] == source["so"]["sha256"]
        and native_candidate["manifest_sha256"] == candidate["manifest_sha256"]
        and native_artifact["id"] == portable_artifact["id"]
        and native_artifact["digest"] == portable_artifact["digest"]
        and native_artifact["size"] == portable_artifact["size"]
        and native_artifact["run_id"] == portable_artifact["run_id"]
        and native_artifact["run_attempt"] == portable_artifact["run_attempt"]
    ):
        fail("native Host report candidate identity differs from the portable candidate")
    native_cpa = native_report["cpa"]
    if (
        native_cpa["tag"] != cpa["tag"]
        or native_cpa["commit"] != cpa["commit"]
        or exact_int(native_cpa["c_abi"], "native Host report.cpa.c_abi", 1)
        != exact_int(cpa["c_abi"], "machine evidence.cpa.c_abi", 1)
        or exact_int(
            native_cpa["rpc_schema"], "native Host report.cpa.rpc_schema", 1
        )
        != exact_int(cpa["rpc_schema"], "machine evidence.cpa.rpc_schema", 1)
    ):
        fail("native Host report CPA identity differs from the machine evidence")
    if native_report["tool"] != native.tool_identity():
        fail("native Host report tool identity differs from the checked-out validator")
    if sha256_bytes(native_go_test_raw) != native_report["test_log"]["sha256"]:
        fail("native Host go test log bytes differ from the validated report")
    execution = native_report["execution"]
    return {
        "candidate": {
            "artifact_digest": native_artifact["digest"],
            "artifact_id": native_artifact["id"],
            "artifact_size": native_artifact["size"],
            "manifest_sha256": native_candidate["manifest_sha256"],
            "run_attempt": native_artifact["run_attempt"],
            "run_id": native_artifact["run_id"],
            "so_sha256": native_candidate["so"]["sha256"],
            "source_commit": native_candidate["source"]["commit"],
            "source_tree": native_candidate["source"]["tree"],
        },
        "cpa_abi": native_report["cpa"]["c_abi"],
        "cpa_commit": native_report["cpa"]["commit"],
        "cpa_rpc_schema": native_report["cpa"]["rpc_schema"],
        "cpa_tag": native_report["cpa"]["tag"],
        "critical_test_count": len(execution["critical_tests"]),
        "critical_tests_sha256": sha256_bytes(
            canonical_bytes(execution["critical_tests"])
        ),
        "fail_count": execution["fail_count"],
        "go_test_log_sha256": native_report["test_log"]["sha256"],
        "go_version": native_report["runtime"]["go_version"],
        "observed_test_count": execution["observed_test_count"],
        "platform": native_report["runtime"]["platform"],
        "report_schema": native_report["schema"],
        "report_sha256": sha256_bytes(native_report_raw),
        "required_test_count": execution["required_test_count"],
        "schema_sha256": native_report["tool"]["schema_sha256"],
        "skip_count": execution["skip_count"],
        "source_sha256": native_report["tool"]["source_sha256"],
        "status": native_report["status"],
        "test_source_sha256": native_report["test_source"]["sha256"],
    }


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
    native_go_test_raw: bytes,
    native_report: Mapping[str, Any],
    native_report_raw: bytes,
    performance: Mapping[str, Any],
    performance_raw: bytes,
    host_admission: Mapping[str, Any],
    host_admission_config: Mapping[str, Any],
    host_admission_config_raw: bytes,
    host_admission_manifest_raw: bytes,
    host_admission_sqlite_sha256: str,
    host_admission_approved_runtime: Mapping[str, Any],
    host_admission_raw: bytes,
    host_admission_300s_raw: bytes,
    host_admission_3600s_raw: bytes,
    host_admission_realtime_raw: bytes,
    lazy_read: Mapping[str, Any],
    lazy_read_phase_boundary_raw: bytes,
    lazy_read_runtime_read_trace_raw: bytes,
    lazy_read_runtime_read_summary_raw: bytes,
    csam_text: Mapping[str, Any],
    csam_text_fixture_manifest_raw: bytes,
    csam_text_results_raw: bytes,
    csam_text_summary_raw: bytes,
    csam_text_privacy_cleanup_raw: bytes,
    supplemental_archive_binding: Mapping[str, int | str],
    supplemental_manifest: Mapping[str, Any],
    supplemental_manifest_raw: bytes,
    supplemental_policy_raw: bytes,
    supplemental_results_raw: bytes,
    generated_at: datetime,
) -> dict[str, Any]:
    del results_path
    if supplemental_manifest_raw != canonical_bytes(supplemental_manifest) + b"\n":
        fail("supplemental manifest raw bytes differ from the validated object")
    if native_report_raw != canonical_bytes(native_report) + b"\n":
        fail("native Host report raw bytes differ from the validated object")
    if host_admission_raw != canonical_bytes(host_admission) + b"\n":
        fail("Host admission raw bytes differ from the validated object")
    if host_admission["run_id"] != machine["run"]["run_id"]:
        fail("Host admission run_id differs from machine evidence run_id")
    # Re-run the complete production Host binding inside the only PASS
    # producer.  Callers cannot turn a hand-written config/manifest into a
    # portable PASS merely by invoking build_report() directly and bypassing
    # load_validated_inputs().
    import host_admission as host_validator
    import host_admission_collector as host_collector

    (
        validated_host_config,
        validated_host_manifest,
        validated_host_candidate,
    ) = host_collector.validate_production_bindings(
        host_admission_config_raw,
        host_admission_manifest_raw,
        host_admission_300s_raw,
        host_admission_3600s_raw,
        host_admission_realtime_raw,
    )
    if dict(host_admission_config) != validated_host_config:
        fail("Host admission config differs from its production-validated bytes")
    if (
        dict(host_admission_approved_runtime)
        != validated_host_config["approved_runtime_identities"]
    ):
        fail("Host admission runtime approval differs from the validated config")
    if (
        require_hex(
            host_admission_sqlite_sha256,
            "Host admission preserved SQLite SHA-256",
        )
        != validated_host_manifest["sqlite"]["database_sha256"]
    ):
        fail("Host admission preserved SQLite differs from the validated manifest")
    validated_host_evidence = host_validator.validate_host_admission(
        host_admission,
        host_admission_300s_raw,
        host_admission_3600s_raw,
        host_admission_realtime_raw,
        validated_host_candidate,
    )
    if dict(host_admission) != validated_host_evidence:
        fail("Host admission projection differs from its production-validated evidence")
    lazy_phase_value, _ = load_canonical_bytes(
        lazy_read_phase_boundary_raw, "lazy-read phase boundary"
    )
    lazy_summary_value, _ = load_canonical_bytes(
        lazy_read_runtime_read_summary_raw, "lazy-read runtime read summary"
    )
    validated_lazy_read = validate_lazy_read_evidence(
        lazy_phase_value, lazy_read_runtime_read_trace_raw, lazy_summary_value
    )
    if dict(lazy_read) != validated_lazy_read:
        fail("lazy-read projection differs from its validated original evidence")
    csam_fixture_value, _ = load_canonical_bytes(
        csam_text_fixture_manifest_raw, "CSAM text fixture manifest"
    )
    csam_results_value, _ = load_canonical_bytes(
        csam_text_results_raw, "CSAM text results"
    )
    csam_summary_value, _ = load_canonical_bytes(
        csam_text_summary_raw, "CSAM text summary"
    )
    csam_cleanup_value, _ = load_canonical_bytes(
        csam_text_privacy_cleanup_raw, "CSAM text privacy cleanup"
    )
    validated_csam_text = validate_csam_text_evidence(
        csam_fixture_value,
        csam_results_value,
        csam_summary_value,
        csam_cleanup_value,
        expected_run_id=machine["run"]["run_id"],
    )
    if dict(csam_text) != validated_csam_text:
        fail("CSAM text projection differs from its validated original evidence")
    if int(machine["run"]["cold_start_count"]) != EXPECTED_CORE_COLD_STARTS:
        fail("release admission requires exactly three cold starts")
    cold_start_arms = tuple(range(1, int(machine["run"]["cold_start_count"]) + 1))
    outcomes, semantic_summary = derive_semantics(manifest, results_raw, cold_start_arms)
    supplemental_outcomes, supplemental_summary = derive_supplemental_semantics(
        supplemental_manifest, supplemental_results_raw, cold_start_arms
    )
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
    if (
        supplemental_archive_binding["bytes"]
        != supplemental_manifest["archive"]["bytes"]
        or supplemental_archive_binding["sha256"]
        != supplemental_manifest["archive"]["sha256"]
    ):
        fail("supplemental archive binding differs from its reconstructed manifest")
    input_hashes = {
        "candidate_manifest_sha256": sha256_bytes(candidate_raw),
        "corpus_manifest_sha256": sha256_bytes(manifest_raw),
        "host_performance_config_sha256": sha256_bytes(performance_config_raw),
        "host_performance_evidence_sha256": sha256_bytes(performance_raw),
        "host_performance_measurements_sha256": sha256_bytes(measurements_raw),
        "host_admission_evidence_sha256": sha256_bytes(host_admission_raw),
        "host_admission_config_sha256": sha256_bytes(host_admission_config_raw),
        "host_admission_evidence_manifest_sha256": sha256_bytes(host_admission_manifest_raw),
        "host_admission_sqlite_sha256": host_admission_sqlite_sha256,
        "host_admission_300s_samples_sha256": sha256_bytes(host_admission_300s_raw),
        "host_admission_3600s_samples_sha256": sha256_bytes(host_admission_3600s_raw),
        "host_admission_realtime_routes_sha256": sha256_bytes(host_admission_realtime_raw),
        "machine_evidence_sha256": sha256_bytes(machine_raw),
        "native_host_go_test_log_sha256": sha256_bytes(native_go_test_raw),
        "native_host_special_paths_report_sha256": sha256_bytes(native_report_raw),
        "performance_workload_manifest_sha256": sha256_bytes(workload_raw),
        "run_config_sha256": sha256_bytes(run_config_raw),
        "supplemental_archive_sha256": str(supplemental_archive_binding["sha256"]),
        "supplemental_manifest_sha256": sha256_bytes(supplemental_manifest_raw),
        "supplemental_policy_sha256": sha256_bytes(supplemental_policy_raw),
        "supplemental_results_sha256": sha256_bytes(supplemental_results_raw),
        "transport_results_sha256": sha256_bytes(results_raw),
        "lazy_read_phase_boundary_sha256": sha256_bytes(lazy_read_phase_boundary_raw),
        "lazy_read_runtime_read_trace_sha256": sha256_bytes(lazy_read_runtime_read_trace_raw),
        "lazy_read_runtime_read_summary_sha256": sha256_bytes(lazy_read_runtime_read_summary_raw),
        "csam_text_fixture_manifest_sha256": sha256_bytes(csam_text_fixture_manifest_raw),
        "csam_text_results_sha256": sha256_bytes(csam_text_results_raw),
        "csam_text_summary_sha256": sha256_bytes(csam_text_summary_raw),
        "csam_text_privacy_cleanup_sha256": sha256_bytes(csam_text_privacy_cleanup_raw),
    }
    generated_at = generated_at.astimezone(timezone.utc).replace(microsecond=0)
    portable_candidate = {
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
    }
    portable_source = {
        "binary_version": CAG_SOURCE_VERSION,
        "commit": source["commit"],
        "repository": CANDIDATE_REPOSITORY,
        "so": {
            "bytes": so_file["bytes"],
            "name": source["so_name"],
            "sha256": source["so_sha256"],
        },
        "source_version": source["source_version"],
        "tree": source["tree"],
    }
    host_candidate = host_admission["candidate"]
    host_windows = host_admission["windows"]
    approved_keeper = host_admission_approved_runtime["keeper"]
    projected_keeper = {
        "base_image_ref": host_admission_config["identities"]["keeper"]["base_image_ref"],
        "contract": host_admission_config["identities"]["keeper"]["contract"],
        "image_id": host_admission_config["identities"]["keeper"]["image_id"],
        "image_ref": host_admission_config["identities"]["keeper"]["image_ref"],
        "source_sha256": host_admission_config["identities"]["keeper"]["source_sha256"],
    }
    if approved_keeper != projected_keeper:
        fail("Host admission Keeper projection differs from independently approved runtime identities")
    observed_keeper = host_admission["runtime_identity"]["keeper"]
    if (
        observed_keeper["image_id"] != approved_keeper["image_id"]
        or observed_keeper["image_digest"] != approved_keeper["image_ref"]
    ):
        fail("Host admission observed Keeper runtime differs from its independent approval")
    host_projection = {
        "approved_runtime_identities_sha256": host_admission_config[
            "approved_runtime_identities_sha256"
        ],
        "evidence_sha256": input_hashes["host_admission_evidence_sha256"],
        "candidate_artifact_digest": host_candidate["artifacts"]["candidate_artifact_digest"],
        "candidate_manifest_sha256": host_candidate["artifacts"]["candidate_manifest_sha256"],
        "config_sha256": host_candidate["artifacts"]["config_sha256"],
        "claim_boundary": host_admission["claim_boundary"],
        "cpa_commit": host_candidate["cpa"]["commit"],
        "cpa_rpc_schema": host_candidate["cpa"]["rpc_schema"],
        "cpa_tag": host_candidate["cpa"]["tag"],
        "host_300s_sample_count": host_windows[0]["sample_count"],
        "host_300s_samples_sha256": host_windows[0]["samples_sha256"],
        "host_3600s_sample_count": host_windows[1]["sample_count"],
        "host_3600s_samples_sha256": host_windows[1]["samples_sha256"],
        "evidence_manifest_sha256": host_candidate["artifacts"]["evidence_manifest_sha256"],
        "keeper_base_image_ref": host_admission_config["identities"]["keeper"]["base_image_ref"],
        "keeper_contract": host_admission_config["identities"]["keeper"]["contract"],
        "keeper_image_id": host_admission_config["identities"]["keeper"]["image_id"],
        "keeper_image_ref": host_admission_config["identities"]["keeper"]["image_ref"],
        "keeper_source_sha256": host_admission_config["identities"]["keeper"]["source_sha256"],
        "sqlite_sha256": input_hashes["host_admission_sqlite_sha256"],
        "platform": host_admission["platform"],
        "realtime_route_count": host_admission["tail_verification"]["realtime"]["route_count"],
        "realtime_routes_sha256": host_admission["tail_verification"]["realtime"]["routes_sha256"],
        "run_id": host_admission["run_id"],
        "schema": host_admission["schema"],
        "so_sha256": host_candidate["cag"]["so_sha256"],
        "source_commit": host_candidate["cag"]["commit"],
        "source_tree": host_candidate["cag"]["tree"],
        "status": host_admission["status"],
        "store_zip_sha256": host_candidate["cag"]["store_zip_sha256"],
    }
    native_projection = _native_host_projection(
        native_report,
        native_report_raw,
        native_go_test_raw,
        candidate=portable_candidate,
        source=portable_source,
        cpa=machine["identities"]["cpa"],
    )
    report: dict[str, Any] = {
        "candidate": portable_candidate,
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
        "evidence_refs": {
            "csam_text": {
                **dict(csam_text),
                "fixture_manifest_path": CSAM_TEXT_PATHS["fixture_manifest"],
                "fixture_manifest_sha256": input_hashes["csam_text_fixture_manifest_sha256"],
                "privacy_cleanup_path": CSAM_TEXT_PATHS["privacy_cleanup"],
                "privacy_cleanup_sha256": input_hashes["csam_text_privacy_cleanup_sha256"],
                "results_path": CSAM_TEXT_PATHS["results"],
                "results_sha256": input_hashes["csam_text_results_sha256"],
                "summary_path": CSAM_TEXT_PATHS["summary"],
                "summary_sha256": input_hashes["csam_text_summary_sha256"],
            },
            "lazy_read": {
                **dict(lazy_read),
                "phase_boundary_path": LAZY_READ_PATHS["phase_boundary"],
                "phase_boundary_sha256": input_hashes["lazy_read_phase_boundary_sha256"],
                "runtime_read_summary_path": LAZY_READ_PATHS["runtime_read_summary"],
                "runtime_read_summary_sha256": input_hashes["lazy_read_runtime_read_summary_sha256"],
                "runtime_read_trace_path": LAZY_READ_PATHS["runtime_read_trace"],
                "runtime_read_trace_sha256": input_hashes["lazy_read_runtime_read_trace_sha256"],
            },
        },
        "generated_at": timestamp(generated_at),
        "inputs": input_hashes,
        "host_admission": host_projection,
        "native_host_special_paths": native_projection,
        "performance": {
            "evidence_schema": performance["schema"],
            "config_sha256": input_hashes["host_performance_config_sha256"],
            "evidence_sha256": input_hashes["host_performance_evidence_sha256"],
            "measurements_sha256": input_hashes["host_performance_measurements_sha256"],
            "gates": gates,
            "metrics": metrics,
            "status": performance["status"],
        },
        "realtime": dict(machine["realtime"]),
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
        "source": portable_source,
        "status": STATUS,
        "supplemental_archive": {
            "archive": {
                "bytes": supplemental_manifest["archive"]["bytes"],
                "sha256": supplemental_manifest["archive"]["sha256"],
            },
            "case_count": supplemental_manifest["unique_reviewed_cases"],
            "code_executions": supplemental_manifest["code_executions"],
            "entry_count": supplemental_manifest["selected_entry_count"],
            "input_archive_preserved": machine["cleanup"][
                "supplemental_input_archive_preserved"
            ],
            "manifest_sha256": sha256_bytes(supplemental_manifest_raw),
            "member_text_files_created": machine["cleanup"][
                "supplemental_member_text_files_created"
            ],
            "member_text_files_removed": machine["cleanup"][
                "supplemental_member_text_files_removed"
            ],
            "member_text_retained": machine["cleanup"][
                "supplemental_member_text_retained"
            ],
            "outcomes": supplemental_outcomes,
            "policy_sha256": sha256_bytes(supplemental_policy_raw),
            "results_sha256": sha256_bytes(supplemental_results_raw),
            "side_effect_violations": sum(
                item["side_effect_violations"] for item in supplemental_outcomes
            ),
            "status": SUPPLEMENTAL_STATUS,
            "summary_by_mode": supplemental_summary,
            "third_party_code_executions": supplemental_manifest[
                "third_party_code_executions"
            ],
            "total_executions": sum(
                item["execution_count"] for item in supplemental_outcomes
            ),
        },
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
            "evidence_refs", "generated_at", "host_admission", "inputs", "native_host_special_paths", "performance", "realtime", "safety",
            "schema", "semantic", "source", "status", "summary", "supplemental_archive",
            "tool_bundles",
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

    refs = exact_object(
        report["evidence_refs"], {"csam_text", "lazy_read"}, "report.evidence_refs"
    )
    lazy_ref = exact_object(
        refs["lazy_read"],
        {
            "phase_boundary_path",
            "phase_boundary_sha256",
            "phase_boundary_status",
            "preflight_trace_count",
            "run_id",
            "runtime_read_summary_path",
            "runtime_read_summary_sha256",
            "runtime_read_trace_path",
            "runtime_read_trace_sha256",
            "status",
            "transport_request_count",
            "transport_source_read_count",
        },
        "report.evidence_refs.lazy_read",
    )
    expected_lazy_paths = {
        "phase_boundary_path": LAZY_READ_PATHS["phase_boundary"],
        "runtime_read_summary_path": LAZY_READ_PATHS["runtime_read_summary"],
        "runtime_read_trace_path": LAZY_READ_PATHS["runtime_read_trace"],
    }
    for key, expected_path in expected_lazy_paths.items():
        if require_safe_relative(lazy_ref[key], f"report.evidence_refs.lazy_read.{key}") != expected_path:
            fail(f"report.evidence_refs.lazy_read.{key} is not the fixed evidence path")
    for key in ("phase_boundary_sha256", "runtime_read_summary_sha256", "runtime_read_trace_sha256"):
        require_hex(lazy_ref[key], f"report.evidence_refs.lazy_read.{key}")
    if (
        lazy_ref["status"] != "PASS"
        or lazy_ref["phase_boundary_status"] != "PASS"
        or exact_int(lazy_ref["preflight_trace_count"], "report.evidence_refs.lazy_read.preflight_trace_count", 1) < 1
        or exact_int(lazy_ref["transport_request_count"], "report.evidence_refs.lazy_read.transport_request_count", 1)
        != exact_int(lazy_ref["transport_source_read_count"], "report.evidence_refs.lazy_read.transport_source_read_count", 1)
    ):
        fail("report lazy-read evidence reference is not a complete PASS")
    exact_run_id(lazy_ref["run_id"], "report.evidence_refs.lazy_read.run_id")
    lazy_bindings = {
        "phase_boundary_sha256": "lazy_read_phase_boundary_sha256",
        "runtime_read_summary_sha256": "lazy_read_runtime_read_summary_sha256",
        "runtime_read_trace_sha256": "lazy_read_runtime_read_trace_sha256",
    }
    if any(lazy_ref[key] != inputs[input_key] for key, input_key in lazy_bindings.items()):
        fail("report lazy-read references differ from the bound input hashes")

    csam_ref = exact_object(
        refs["csam_text"],
        {
            "benign_case_count",
            "false_positive_count",
            "fixture_manifest_path",
            "fixture_manifest_sha256",
            "malicious_case_count",
            "privacy_cleanup_path",
            "privacy_cleanup_sha256",
            "results_path",
            "results_sha256",
            "run_id",
            "status",
            "summary_path",
            "summary_sha256",
        },
        "report.evidence_refs.csam_text",
    )
    expected_csam_paths = {
        "fixture_manifest_path": CSAM_TEXT_PATHS["fixture_manifest"],
        "privacy_cleanup_path": CSAM_TEXT_PATHS["privacy_cleanup"],
        "results_path": CSAM_TEXT_PATHS["results"],
        "summary_path": CSAM_TEXT_PATHS["summary"],
    }
    for key, expected_path in expected_csam_paths.items():
        if require_safe_relative(csam_ref[key], f"report.evidence_refs.csam_text.{key}") != expected_path:
            fail(f"report.evidence_refs.csam_text.{key} is not the fixed evidence path")
    for key in ("fixture_manifest_sha256", "privacy_cleanup_sha256", "results_sha256", "summary_sha256"):
        require_hex(csam_ref[key], f"report.evidence_refs.csam_text.{key}")
    if (
        csam_ref["status"] != "PASS"
        or exact_int(csam_ref["malicious_case_count"], "report.evidence_refs.csam_text.malicious_case_count") != 15
        or exact_int(csam_ref["benign_case_count"], "report.evidence_refs.csam_text.benign_case_count") != 21
        or exact_int(csam_ref["false_positive_count"], "report.evidence_refs.csam_text.false_positive_count") != 0
    ):
        fail("report CSAM text evidence reference is not the fixed 15/21 PASS")
    exact_run_id(csam_ref["run_id"], "report.evidence_refs.csam_text.run_id")
    csam_bindings = {
        "fixture_manifest_sha256": "csam_text_fixture_manifest_sha256",
        "privacy_cleanup_sha256": "csam_text_privacy_cleanup_sha256",
        "results_sha256": "csam_text_results_sha256",
        "summary_sha256": "csam_text_summary_sha256",
    }
    if any(csam_ref[key] != inputs[input_key] for key, input_key in csam_bindings.items()):
        fail("report CSAM text references differ from the bound input hashes")

    host_section = exact_object(
        report["host_admission"],
        {
            "approved_runtime_identities_sha256", "candidate_artifact_digest", "candidate_manifest_sha256", "claim_boundary",
            "config_sha256", "evidence_manifest_sha256", "evidence_sha256",
            "cpa_commit", "cpa_rpc_schema", "cpa_tag", "host_300s_sample_count",
            "host_300s_samples_sha256", "host_3600s_sample_count",
            "host_3600s_samples_sha256", "keeper_base_image_ref", "keeper_contract", "keeper_image_id",
            "keeper_image_ref", "keeper_source_sha256", "platform", "realtime_route_count",
            "realtime_routes_sha256", "run_id", "schema", "so_sha256",
            "source_commit", "source_tree", "sqlite_sha256", "status", "store_zip_sha256",
        },
        "report.host_admission",
    )
    if host_section["schema"] != "cag-current-cpa-host-admission-evidence/v1" or host_section["status"] != "PASS":
        fail("Host admission schema/status is invalid")
    expected_host_claim = (
        "SECOND-MACHINE OWNER HOST ADMISSION; EXACT CANDIDATE AND PROTECTED "
        "ROUTES ONLY; NOT INDEPENDENT ATTESTATION"
    )
    if host_section["claim_boundary"] != expected_host_claim:
        fail("Host admission claim boundary is invalid")
    if host_section["evidence_sha256"] != inputs["host_admission_evidence_sha256"]:
        fail("Host admission projection differs from its bound raw evidence")
    if (
        host_section["config_sha256"] != inputs["host_admission_config_sha256"]
        or host_section["evidence_manifest_sha256"]
        != inputs["host_admission_evidence_manifest_sha256"]
        or host_section["sqlite_sha256"] != inputs["host_admission_sqlite_sha256"]
    ):
        fail("Host admission tracked config/manifest/SQLite inputs differ from its projection")
    if host_section["platform"] != "linux/amd64" or host_section["cpa_tag"] != CPA_TAG or host_section["cpa_commit"] != CPA_COMMIT or exact_int(host_section["cpa_rpc_schema"], "report.host_admission.cpa_rpc_schema") != CPA_RPC_SCHEMA:
        fail("Host admission platform/CPA identity is invalid")
    if host_section["source_commit"] != source["commit"]:
        fail("Host admission source commit differs from the portable candidate")
    if host_section["source_tree"] != source["tree"]:
        fail("Host admission source tree differs from the portable candidate")
    if host_section["so_sha256"] != so["sha256"]:
        fail("Host admission SO differs from the portable candidate")
    if host_section["candidate_artifact_digest"] != artifact["digest"]:
        fail("Host admission artifact digest differs from the portable candidate")
    if host_section["candidate_manifest_sha256"] != candidate["manifest_sha256"]:
        fail("Host admission manifest differs from the portable candidate")
    store_name = f"cyber-abuse-guard_{CAG_SOURCE_VERSION}_linux_amd64.zip"
    file_store = next(item for item in files if item["name"] == store_name)
    if host_section["store_zip_sha256"] != file_store["sha256"]:
        fail("Host admission Store ZIP differs from the sealed candidate file")
    if host_section["cpa_commit"] != report["cpa"]["commit"]:
        fail("Host admission CPA differs from the portable CPA")
    for key in ("source_commit", "source_tree"):
        require_hex(host_section[key], f"report.host_admission.{key}", HEX40)
    for key in ("approved_runtime_identities_sha256", "candidate_manifest_sha256", "config_sha256", "evidence_manifest_sha256", "host_300s_samples_sha256", "host_3600s_samples_sha256", "keeper_source_sha256", "realtime_routes_sha256", "so_sha256", "sqlite_sha256", "store_zip_sha256"):
        require_hex(host_section[key], f"report.host_admission.{key}")
    require_digest(host_section["keeper_image_id"], "report.host_admission.keeper_image_id")
    if host_section["keeper_contract"] != "cag-current-cpa-host-keeper/v1":
        fail("report Host Keeper contract is invalid")
    require_repo_digest(host_section["keeper_image_ref"], "report.host_admission.keeper_image_ref")
    require_repo_digest(host_section["keeper_base_image_ref"], "report.host_admission.keeper_base_image_ref")
    portable_runtime_approval = {
        "keeper": {
            "base_image_ref": host_section["keeper_base_image_ref"],
            "contract": host_section["keeper_contract"],
            "image_id": host_section["keeper_image_id"],
            "image_ref": host_section["keeper_image_ref"],
            "source_sha256": host_section["keeper_source_sha256"],
        },
        "schema": "cag-current-cpa-host-admission-approved-runtime-identities/v1",
    }
    from host_admission_collector import load_tracked_approved_runtime_identities

    tracked_runtime_approval, tracked_runtime_approval_raw = (
        load_tracked_approved_runtime_identities()
    )
    if portable_runtime_approval != tracked_runtime_approval:
        fail("report Host Keeper identity differs from the tracked runtime approval")
    if host_section["approved_runtime_identities_sha256"] != sha256_bytes(
        tracked_runtime_approval_raw
    ):
        fail("report Host Keeper fields do not bind the tracked runtime approval SHA")
    require_digest(host_section["candidate_artifact_digest"], "report.host_admission.candidate_artifact_digest")
    exact_run_id(host_section["run_id"], "report.host_admission.run_id")
    if exact_int(host_section["host_300s_sample_count"], "report.host_admission.host_300s_sample_count") != 301 or exact_int(host_section["host_3600s_sample_count"], "report.host_admission.host_3600s_sample_count") != 3601 or exact_int(host_section["realtime_route_count"], "report.host_admission.realtime_route_count") != 14:
        fail("Host admission sample/route denominator is invalid")
    if inputs["host_admission_300s_samples_sha256"] != host_section["host_300s_samples_sha256"] or inputs["host_admission_3600s_samples_sha256"] != host_section["host_3600s_samples_sha256"] or inputs["host_admission_realtime_routes_sha256"] != host_section["realtime_routes_sha256"]:
        fail("Host admission raw input hashes differ from its portable projection")
    if (
        lazy_ref["run_id"] != host_section["run_id"]
        or csam_ref["run_id"] != host_section["run_id"]
    ):
        fail("lazy-read/CSAM evidence references do not share the Host admission run ID")

    realtime = validate_realtime_projection(report["realtime"])

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
        if exact_int(
            item["execution_count"],
            f"report.semantic.outcomes[{index}].execution_count",
            1,
        ) != len(PROTOCOLS) * len(STREAM_VALUES) * EXPECTED_CORE_COLD_STARTS:
            fail("report semantic outcome does not bind exactly three cold starts")
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
        if item["actual_action"] != item["expected_action"]:
            fail("report semantic outcome actual action differs from expected action")
    if sum(item["execution_count"] for item in outcomes) != EXPECTED_CORE_EXECUTIONS:
        fail("report semantic plane is not the exact independent 684-execution denominator")
    recomputed_semantic = derive_semantic_summary(outcomes)
    if semantic["summary_by_mode"] != recomputed_semantic:
        fail("report semantic summary differs from the closed outcome matrix")
    for item in recomputed_semantic:
        if not item["all_semantic_contracts_passed"] or item["false_positives"] != 0 or item["malicious_cases"] < 1 or item["malicious_detected"] != item["malicious_cases"] or item["malicious_recall_percent"] != 100.0 or item["semantic_cases"] != 19 or item["side_effect_violations"] != 0:
            fail(f"report mode {item['mode']} does not satisfy the zero-FP/100%-recall contract")

    supplemental = exact_object(
        report["supplemental_archive"],
        {
            "archive",
            "case_count",
            "code_executions",
            "entry_count",
            "input_archive_preserved",
            "manifest_sha256",
            "member_text_files_created",
            "member_text_files_removed",
            "member_text_retained",
            "outcomes",
            "policy_sha256",
            "results_sha256",
            "side_effect_violations",
            "status",
            "summary_by_mode",
            "third_party_code_executions",
            "total_executions",
        },
        "report.supplemental_archive",
    )
    supplemental_archive = exact_object(
        supplemental["archive"],
        {"bytes", "sha256"},
        "report.supplemental_archive.archive",
    )
    if supplemental_archive != {
        "bytes": SUPPLEMENTAL_ZIP_ARCHIVE_IDENTITY["bytes"],
        "sha256": SUPPLEMENTAL_ZIP_ARCHIVE_IDENTITY["sha256"],
    }:
        fail("report supplemental archive does not bind the fixed reviewed ZIP")
    require_hex(
        supplemental["manifest_sha256"],
        "report.supplemental_archive.manifest_sha256",
    )
    if require_hex(
        supplemental["policy_sha256"],
        "report.supplemental_archive.policy_sha256",
    ) != SUPPLEMENTAL_ZIP_POLICY_SHA256:
        fail("report supplemental policy does not bind the fixed reviewed bytes")
    require_hex(
        supplemental["results_sha256"],
        "report.supplemental_archive.results_sha256",
    )
    if (
        supplemental["status"] != SUPPLEMENTAL_STATUS
        or exact_int(supplemental["entry_count"], "report.supplemental_archive.entry_count")
        != EXPECTED_SUPPLEMENTAL_ZIP_ENTRY_COUNT
        or exact_int(supplemental["case_count"], "report.supplemental_archive.case_count")
        != EXPECTED_SUPPLEMENTAL_ZIP_CASE_COUNT
        or exact_int(
            supplemental["total_executions"],
            "report.supplemental_archive.total_executions",
        )
        != EXPECTED_SUPPLEMENTAL_EXECUTIONS
    ):
        fail("report supplemental archive status or independent matrix counts are invalid")
    for key in (
        "code_executions",
        "member_text_files_created",
        "member_text_files_removed",
        "side_effect_violations",
        "third_party_code_executions",
    ):
        if exact_int(supplemental[key], f"report.supplemental_archive.{key}") != 0:
            fail(f"report supplemental archive {key} must remain zero")
    if (
        exact_bool(
            supplemental["input_archive_preserved"],
            "report.supplemental_archive.input_archive_preserved",
        )
        is not True
        or exact_bool(
            supplemental["member_text_retained"],
            "report.supplemental_archive.member_text_retained",
        )
        is not False
    ):
        fail("report supplemental archive preservation/text-retention contract failed")

    supplemental_outcomes = exact_list(
        supplemental["outcomes"], "report.supplemental_archive.outcomes"
    )
    if len(supplemental_outcomes) != EXPECTED_SUPPLEMENTAL_ZIP_CASE_COUNT * len(MODES):
        fail("report supplemental outcomes are not the exact seven-case by three-mode matrix")
    supplemental_seen: set[tuple[str, str]] = set()
    expected_supplemental_identities = {
        (case_id, mode) for case_id in EXPECTED_SUPPLEMENTAL_CASE_IDS for mode in MODES
    }
    for index, raw in enumerate(supplemental_outcomes):
        label = f"report.supplemental_archive.outcomes[{index}]"
        item = exact_object(
            raw,
            {
                "actual_action",
                "actual_winning_category",
                "actual_winning_rule_id",
                "all_executions_passed",
                "execution_count",
                "expected_action",
                "expected_winning_category",
                "expected_winning_rule_id",
                "false_positive",
                "label",
                "malicious",
                "malicious_detected",
                "mode",
                "side_effect_violations",
                "supplemental_case_id",
            },
            label,
        )
        case_id = exact_string(item["supplemental_case_id"], f"{label}.supplemental_case_id", 256)
        mode = exact_string(item["mode"], f"{label}.mode", 16)
        identity = (case_id, mode)
        if identity in supplemental_seen or identity not in expected_supplemental_identities:
            fail("report supplemental outcome identity is duplicate or outside the fixed matrix")
        supplemental_seen.add(identity)
        suffix = case_id.rsplit(":", 1)[1]
        expected_malicious = suffix in {"activated", "authorized-ctf"}
        expected_label = {
            "activated": "malicious_active",
            "authorized-ctf": "malicious_active",
            "defensive": "defensive_context",
        }[suffix]
        expected_action = (
            "block_malicious_text"
            if expected_malicious and mode in {"balanced", "strict"}
            else "allow"
        )
        expected_category = nullable_exact_string(
            item["expected_winning_category"],
            f"{label}.expected_winning_category",
            128,
        )
        expected_rule = nullable_exact_string(
            item["expected_winning_rule_id"],
            f"{label}.expected_winning_rule_id",
            128,
        )
        actual_category = nullable_exact_string(
            item["actual_winning_category"],
            f"{label}.actual_winning_category",
            128,
        )
        actual_rule = nullable_exact_string(
            item["actual_winning_rule_id"],
            f"{label}.actual_winning_rule_id",
            128,
        )
        if (expected_category is None) != (expected_rule is None):
            fail("report supplemental expected winner must bind category and rule together")
        if (actual_category is None) != (actual_rule is None):
            fail("report supplemental actual winner must bind category and rule together")
        reviewed_winner = (
            ("defense_evasion", "META-OVERRIDE-001")
            if suffix == "authorized-ctf"
            else (None, None)
        )
        if (
            exact_string(item["label"], f"{label}.label", 128) != expected_label
            or exact_bool(item["malicious"], f"{label}.malicious") is not expected_malicious
            or exact_bool(item["malicious_detected"], f"{label}.malicious_detected")
            is not expected_malicious
            or exact_bool(item["all_executions_passed"], f"{label}.all_executions_passed")
            is not True
            or exact_bool(item["false_positive"], f"{label}.false_positive") is not False
            or item["expected_action"] != expected_action
            or item["actual_action"] != expected_action
            or (expected_category, expected_rule) != reviewed_winner
            or (
                suffix == "authorized-ctf"
                and (actual_category, actual_rule) != reviewed_winner
            )
            or (expected_malicious and actual_rule is None)
            or exact_int(item["side_effect_violations"], f"{label}.side_effect_violations")
            != 0
            or exact_int(item["execution_count"], f"{label}.execution_count", 1)
            != len(PROTOCOLS) * len(STREAM_VALUES) * EXPECTED_CORE_COLD_STARTS
        ):
            fail("report supplemental outcome violates its reviewed action/detection contract")
    if supplemental_seen != expected_supplemental_identities:
        fail("report supplemental outcome matrix is incomplete")
    if sum(item["execution_count"] for item in supplemental_outcomes) != EXPECTED_SUPPLEMENTAL_EXECUTIONS:
        fail("report supplemental plane is not the independent 252-execution denominator")
    recomputed_supplemental = derive_supplemental_summary(supplemental_outcomes)
    if supplemental["summary_by_mode"] != recomputed_supplemental:
        fail("report supplemental summary differs from the closed outcome matrix")
    for item in recomputed_supplemental:
        if not (
            item["all_supplemental_contracts_passed"] is True
            and item["false_positive_denominator"] == 3
            and item["false_positives"] == 0
            and item["malicious_recall_denominator"] == 4
            and item["malicious_detected"] == 4
            and item["malicious_recall_percent"] == 100.0
            and item["side_effect_violations"] == 0
            and item["supplemental_cases"] == EXPECTED_SUPPLEMENTAL_ZIP_CASE_COUNT
        ):
            fail(f"report supplemental mode {item['mode']} does not pass the fixed contract")

    if not (
        inputs["supplemental_archive_sha256"] == supplemental_archive["sha256"]
        and inputs["supplemental_manifest_sha256"] == supplemental["manifest_sha256"]
        and inputs["supplemental_policy_sha256"] == supplemental["policy_sha256"]
        and inputs["supplemental_results_sha256"] == supplemental["results_sha256"]
    ):
        fail("report input hashes do not bind the supplemental archive plane")

    performance = exact_object(report["performance"], {"config_sha256", "evidence_schema", "evidence_sha256", "gates", "measurements_sha256", "metrics", "status"}, "report.performance")
    exact_string(performance["evidence_schema"], "report.performance.evidence_schema", 256)
    if performance["status"] != "PASS":
        fail("report Host-performance status is not PASS")
    if (
        performance["config_sha256"] != inputs["host_performance_config_sha256"]
        or performance["evidence_sha256"] != inputs["host_performance_evidence_sha256"]
        or performance["measurements_sha256"] != inputs["host_performance_measurements_sha256"]
    ):
        fail("report Host-performance projection differs from its bound raw evidence")
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
        for key in ("binary_path", "binary_sha256", "c_abi", "commit", "image_id", "official_asset_name", "official_asset_sha256", "repo_digest", "rpc_schema", "tag")
        if key in cpa
    } or set(cpa) != {"binary_path", "binary_sha256", "c_abi", "commit", "image_id", "official_asset_name", "official_asset_sha256", "repo_digest", "rpc_schema", "tag"}:
        fail("report CPA identity keys are not closed")
    if (
        cpa["tag"] != CPA_TAG
        or cpa["commit"] != CPA_COMMIT
        or exact_int(cpa["c_abi"], "report.cpa.c_abi", 1) != CPA_C_ABI
        or exact_int(cpa["rpc_schema"], "report.cpa.rpc_schema", 1)
        != CPA_RPC_SCHEMA
        or cpa["official_asset_name"] != CPA_OFFICIAL_ASSET_NAME
        or cpa["official_asset_sha256"] != CPA_OFFICIAL_ASSET_SHA256
        or cpa["binary_sha256"] != CPA_OFFICIAL_BINARY_SHA256
    ):
        fail("report does not bind the fixed CPA v7.2.145 official bytes")

    import native_host_special_paths as native

    native_section = exact_object(
        report["native_host_special_paths"],
        {
            "candidate",
            "cpa_abi",
            "cpa_commit",
            "cpa_rpc_schema",
            "cpa_tag",
            "critical_test_count",
            "critical_tests_sha256",
            "fail_count",
            "go_test_log_sha256",
            "go_version",
            "observed_test_count",
            "platform",
            "report_schema",
            "report_sha256",
            "required_test_count",
            "schema_sha256",
            "skip_count",
            "source_sha256",
            "status",
            "test_source_sha256",
        },
        "report.native_host_special_paths",
    )
    native_candidate = exact_object(
        native_section["candidate"],
        {
            "artifact_digest",
            "artifact_id",
            "artifact_size",
            "manifest_sha256",
            "run_attempt",
            "run_id",
            "so_sha256",
            "source_commit",
            "source_tree",
        },
        "report.native_host_special_paths.candidate",
    )
    for key in (
        "go_test_log_sha256",
        "critical_tests_sha256",
        "report_sha256",
        "schema_sha256",
        "source_sha256",
        "test_source_sha256",
    ):
        require_hex(native_section[key], f"report.native_host_special_paths.{key}")
    for key in ("manifest_sha256", "so_sha256"):
        require_hex(native_candidate[key], f"report.native_host_special_paths.candidate.{key}")
    require_hex(
        native_candidate["source_commit"],
        "report.native_host_special_paths.candidate.source_commit",
        HEX40,
    )
    require_hex(
        native_candidate["source_tree"],
        "report.native_host_special_paths.candidate.source_tree",
        HEX40,
    )
    require_digest(
        native_candidate["artifact_digest"],
        "report.native_host_special_paths.candidate.artifact_digest",
    )
    for key in ("artifact_id", "artifact_size", "run_attempt", "run_id"):
        exact_int(
            native_candidate[key],
            f"report.native_host_special_paths.candidate.{key}",
            1,
        )
    required_native_tests = len(native.CRITICAL_SUBTESTS) + 1
    expected_critical_tests_sha256 = sha256_bytes(
        canonical_bytes(native.expected_critical_tests())
    )
    if not (
        native_section["status"] == native.STATUS
        and native_section["report_schema"] == native.SCHEMA
        and native_section["go_version"] == native.GO_VERSION
        and native_section["platform"] == native.PLATFORM
        and native_section["critical_tests_sha256"]
        == expected_critical_tests_sha256
        and native_section["cpa_commit"] == cpa["commit"]
        and exact_int(native_section["cpa_abi"], "report.native_host_special_paths.cpa_abi") == cpa["c_abi"]
        and exact_int(native_section["cpa_rpc_schema"], "report.native_host_special_paths.cpa_rpc_schema") == cpa["rpc_schema"]
        and native_section["cpa_tag"] == cpa["tag"]
        and exact_int(
            native_section["critical_test_count"],
            "report.native_host_special_paths.critical_test_count",
        )
        == len(native.CRITICAL_SUBTESTS)
        and exact_int(
            native_section["required_test_count"],
            "report.native_host_special_paths.required_test_count",
        )
        == required_native_tests
        and exact_int(
            native_section["observed_test_count"],
            "report.native_host_special_paths.observed_test_count",
            required_native_tests,
        )
        >= required_native_tests
        and exact_int(
            native_section["fail_count"], "report.native_host_special_paths.fail_count"
        )
        == 0
        and exact_int(
            native_section["skip_count"], "report.native_host_special_paths.skip_count"
        )
        == 0
    ):
        fail("report native Host status/runtime/test denominator is invalid")
    if native_candidate != {
        "artifact_digest": artifact["digest"],
        "artifact_id": artifact["id"],
        "artifact_size": artifact["size"],
        "manifest_sha256": candidate["manifest_sha256"],
        "run_attempt": artifact["run_attempt"],
        "run_id": artifact["run_id"],
        "so_sha256": so["sha256"],
        "source_commit": source["commit"],
        "source_tree": source["tree"],
    }:
        fail("report native Host candidate projection differs from the portable candidate")
    if not (
        inputs["native_host_special_paths_report_sha256"]
        == native_section["report_sha256"]
        and inputs["native_host_go_test_log_sha256"]
        == native_section["go_test_log_sha256"]
    ):
        fail("report input hashes do not bind the native Host evidence/log")

    tools = exact_object(
        report["tool_bundles"],
        {"admission", "host_admission", "host_performance", "machine", "native_host_special_paths"},
        "report.tool_bundles",
    )
    if not (
        native_section["schema_sha256"]
        == tools["native_host_special_paths"]["schema_sha256"]
        and native_section["source_sha256"]
        == tools["native_host_special_paths"]["source_sha256"]
        and native_section["test_source_sha256"]
        == tools["native_host_special_paths"]["test_source_sha256"]
    ):
        fail("report native Host projection differs from its tool bundle identity")
    if host_section["keeper_source_sha256"] != tools["host_admission"]["keeper_source_sha256"]:
        fail("report Host Keeper source differs from the tracked Host-admission tool bundle")
    if tools != local_tool_identities():
        fail("report tool bundle hashes differ from the checked-out tag validator")

    summary = exact_object(report["summary"], {"business_side_effects", "cleanup_pass", "false_positives", "malicious_cases", "malicious_detected", "malicious_recall_percent", "mode_count", "performance_gate_count", "performance_gates_passed", "realtime_protection", "semantic_case_count", "side_effect_violations", "third_party_code_executions"}, "report.summary")
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
        and summary["realtime_protection"] == "unprotected"
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

    run_config, run_config_raw = load_canonical(args.run_config, "run config", 2 * 1024 * 1024)
    run_config = validate_run_config(run_config)
    if int(run_config["run"]["cold_start_count"]) != EXPECTED_CORE_COLD_STARTS:
        fail("release admission requires exactly three cold starts")
    supplemental_manifest, supplemental_manifest_raw, supplemental_policy, supplemental_policy_raw, archive_stat = validate_supplemental_run_config_files(run_config)
    if (
        Path(run_config["paths"]["supplemental_zip"]).resolve(strict=True)
        != args.supplemental_archive.resolve(strict=True)
    ):
        fail("supplied supplemental archive path differs from the immutable run config")
    validate_supplemental_evidence_copies(
        original_manifest=supplemental_manifest,
        original_manifest_raw=supplemental_manifest_raw,
        original_policy=supplemental_policy,
        original_policy_raw=supplemental_policy_raw,
        evidence_manifest_path=args.supplemental_manifest,
        evidence_policy_path=args.supplemental_policy,
    )
    from supplemental_zip import create_supplemental_manifest

    rebuilt_supplemental_manifest = create_supplemental_manifest(
        args.supplemental_archive.resolve(strict=True),
        supplemental_policy,
        sha256_bytes(supplemental_policy_raw),
        supplemental_manifest["acquired_at"],
    )
    if rebuilt_supplemental_manifest != supplemental_manifest:
        fail("supplemental ZIP manifest differs from the archive reconstructed in memory")
    supplemental_archive_binding = bind_supplemental_archive(
        args.supplemental_archive.resolve(strict=True)
    )
    if any(
        supplemental_archive_binding[key] != int(getattr(archive_stat, key))
        for key in ("st_dev", "st_ino", "st_nlink", "st_size")
    ):
        fail("supplemental ZIP archive stat identity drifted after reconstruction")

    machine = validate_machine_evidence(
        manifest,
        machine,
        args.results,
        supplemental_manifest_path=args.supplemental_manifest,
        supplemental_policy_path=args.supplemental_policy,
        supplemental_results_path=args.supplemental_results,
    )
    evidence_directory = args.evidence.parent.resolve(strict=True)
    declared_paths = {
        "corpus manifest": evidence_directory / machine["corpus"]["manifest_path"],
        "transport results": evidence_directory / machine["transport"]["results_path"],
        "supplemental manifest": evidence_directory
        / machine["supplemental_zip_manifest"]["manifest_path"],
        "supplemental policy": evidence_directory
        / machine["supplemental_zip_manifest"]["policy_path"],
        "supplemental results": evidence_directory
        / machine["supplemental_zip_results"]["results_path"],
    }
    supplied_paths = {
        "corpus manifest": args.manifest,
        "transport results": args.results,
        "supplemental manifest": args.supplemental_manifest,
        "supplemental policy": args.supplemental_policy,
        "supplemental results": args.supplemental_results,
    }
    for label, declared in declared_paths.items():
        if declared.resolve(strict=True) != supplied_paths[label].resolve(strict=True):
            fail(f"machine evidence relative {label} path differs from the supplied bundle")
    results_raw = read_regular_bytes(
        args.results,
        "transport results",
        512 * 1024 * 1024,
        require_single_link=True,
    )
    supplemental_results_raw = read_regular_bytes(
        args.supplemental_results,
        "supplemental ZIP results",
        64 * 1024 * 1024,
        require_single_link=True,
    )
    if sha256_bytes(results_raw) != machine["transport"]["results_sha256"]:
        fail("transport results changed after full machine-evidence validation")
    if (
        sha256_bytes(supplemental_results_raw)
        != machine["supplemental_zip_results"]["results_sha256"]
    ):
        fail("supplemental ZIP results changed after full machine-evidence validation")

    candidate_manifest, candidate_raw = validate_candidate_manifest_file(run_config)
    if Path(run_config["paths"]["evidence_directory"]).resolve(strict=True) != evidence_directory:
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

    import native_host_special_paths as native

    native_report_path = args.native_report.resolve(strict=True)
    native_go_test_path = args.native_go_test_jsonl.resolve(strict=True)
    checkout = args.checkout.resolve(strict=True)
    candidate_identity = run_config["identities"]["candidate"]
    native_report = native.validate_bundle(
        report_path=native_report_path,
        candidate_manifest=args.candidate_manifest.resolve(strict=True),
        checkout=checkout,
        go_test_jsonl=native_go_test_path,
        artifact_id=candidate_identity["artifact"]["id"],
        artifact_name=candidate_identity["artifact"]["name"],
        artifact_digest=candidate_identity["artifact"]["digest"],
        artifact_size=args.candidate_artifact_size,
    )
    native_report_again, native_report_raw = native.load_report(native_report_path)
    if native_report_again != native_report:
        fail("native Host report changed after full bundle reconstruction")
    native_go_test_raw = read_regular_bytes(
        native_go_test_path,
        "native Host go test JSONL",
        native.MAX_LOG_BYTES,
        require_single_link=True,
    )
    if sha256_bytes(native_go_test_raw) != native_report["test_log"]["sha256"]:
        fail("native Host go test JSONL changed after full bundle reconstruction")

    import host_admission as host
    import host_admission_collector as host_collector

    for supplied, relative, label in (
        (args.host_admission, "host-admission/evidence.json", "Host admission evidence"),
        (args.host_admission_300s, "host-admission/host-300s-samples.jsonl", "Host admission 300-second samples"),
        (args.host_admission_3600s, "host-admission/host-3600s-samples.jsonl", "Host admission 3600-second samples"),
        (args.host_admission_realtime, "host-admission/realtime-auth-boundary-routes.jsonl", "Host admission Realtime routes"),
        (args.host_admission_config, "host-admission/config.json", "Host admission config"),
        (args.host_admission_evidence_manifest, "host-admission/evidence-manifest.json", "Host admission evidence manifest"),
    ):
        _strict_evidence_path(supplied, evidence_directory, relative, label)

    host_admission_raw = read_regular_bytes(
        args.host_admission, "Host admission evidence", host.MAX_EVIDENCE_BYTES,
        require_single_link=True,
    )
    host_admission_300s_raw = read_regular_bytes(
        args.host_admission_300s, "Host admission 300-second samples",
        301 * host.MAX_SAMPLE_LINE_BYTES, require_single_link=True,
    )
    host_admission_3600s_raw = read_regular_bytes(
        args.host_admission_3600s, "Host admission 3600-second samples",
        3_601 * host.MAX_SAMPLE_LINE_BYTES, require_single_link=True,
    )
    host_admission_realtime_raw = read_regular_bytes(
        args.host_admission_realtime, "Host admission Realtime routes",
        len(host.REALTIME_ROUTE_CONTRACT) * host.MAX_SAMPLE_LINE_BYTES,
        require_single_link=True,
    )
    host_config_raw = read_regular_bytes(
        args.host_admission_config, "Host admission config", 2 * 1024 * 1024,
        require_single_link=True,
    )
    host_evidence_manifest_raw = read_regular_bytes(
        args.host_admission_evidence_manifest, "Host admission evidence manifest",
        8 * 1024 * 1024, require_single_link=True,
    )
    host_config, host_evidence_manifest, rebuilt_host_candidate = (
        host_collector.validate_production_bindings(
            host_config_raw,
            host_evidence_manifest_raw,
            host_admission_300s_raw,
            host_admission_3600s_raw,
            host_admission_realtime_raw,
        )
    )
    host_sqlite_path = _strict_evidence_path(
        Path(host_config["paths"]["host_admission_directory"]) / "audit-events.sqlite3",
        evidence_directory,
        "host-admission/audit-events.sqlite3",
        "Host admission preserved audit SQLite",
    )
    host_sqlite_sha256, _, _host_sqlite_raw = sha256_file(
        host_sqlite_path, "Host admission preserved audit SQLite", 512 * 1024 * 1024
    )
    del _host_sqlite_raw
    if host_sqlite_sha256 != host_evidence_manifest["sqlite"]["database_sha256"]:
        fail("Host admission preserved SQLite differs from its tracked evidence manifest")
    store_zip = next(
        item for item in candidate_files
        if item["name"] == f"cyber-abuse-guard_{CAG_SOURCE_VERSION}_linux_amd64.zip"
    )
    expected_host_candidate = {
        "artifacts": {
            "candidate_artifact_digest": candidate_identity["artifact"]["digest"],
            "candidate_manifest_sha256": sha256_bytes(candidate_raw),
            "config_sha256": sha256_bytes(host_config_raw),
            "evidence_manifest_sha256": sha256_bytes(host_evidence_manifest_raw),
        },
        "cag": {
            "commit": machine["identities"]["cag"]["commit"],
            "so_name": CAG_SO_NAME,
            "so_sha256": machine["identities"]["cag"]["so_sha256"],
            "source_version": CAG_SOURCE_VERSION,
            "store_zip_sha256": store_zip["sha256"],
            "tree": machine["identities"]["cag"]["tree"],
        },
        "cpa": {
            "c_abi": CPA_C_ABI,
            "commit": CPA_COMMIT,
            "official_asset_name": CPA_OFFICIAL_ASSET_NAME,
            "official_asset_sha256": CPA_OFFICIAL_ASSET_SHA256,
            "official_asset_size": CPA_OFFICIAL_ASSET_SIZE,
            "official_binary_sha256": CPA_OFFICIAL_BINARY_SHA256,
            "official_binary_size": CPA_OFFICIAL_BINARY_SIZE,
            "platform": host.PLATFORM,
            "rpc_schema": CPA_RPC_SCHEMA,
            "tag": CPA_TAG,
        },
    }
    if rebuilt_host_candidate != expected_host_candidate:
        fail("Host admission config/manifest reconstruction differs from release inputs")
    validated_host_admission = host.parse_host_admission(
        host_admission_raw,
        host_admission_300s_raw,
        host_admission_3600s_raw,
        host_admission_realtime_raw,
        expected_host_candidate,
    )

    # Round 14 P1 gates are separate from the five-repository semantic plane.
    # Resolve and read every required file from the original evidence root;
    # absence, path substitution, non-canonical JSON, or an incomplete privacy
    # summary must fail before a portable PASS can be built.
    def evidence_file(
        supplied: Path, relative: str, label: str, maximum: int
    ) -> tuple[bytes, Path]:
        path = _strict_evidence_path(
            supplied,
            evidence_directory,
            relative,
            label,
        )
        return read_regular_bytes(path, label, maximum, require_single_link=True), path

    lazy_phase_raw, _ = evidence_file(
        args.lazy_read_phase_boundary,
        LAZY_READ_PATHS["phase_boundary"],
        "lazy-read phase boundary",
        2 * 1024 * 1024,
    )
    lazy_trace_raw, _ = evidence_file(
        args.lazy_read_runtime_read_trace,
        LAZY_READ_PATHS["runtime_read_trace"],
        "lazy-read runtime read trace",
        64 * 1024 * 1024,
    )
    lazy_summary_raw, _ = evidence_file(
        args.lazy_read_runtime_read_summary,
        LAZY_READ_PATHS["runtime_read_summary"],
        "lazy-read runtime read summary",
        2 * 1024 * 1024,
    )
    csam_fixture_raw, _ = evidence_file(
        args.csam_text_fixture_manifest,
        CSAM_TEXT_PATHS["fixture_manifest"],
        "CSAM text fixture manifest",
        2 * 1024 * 1024,
    )
    csam_results_raw, _ = evidence_file(
        args.csam_text_results,
        CSAM_TEXT_PATHS["results"],
        "CSAM text results",
        2 * 1024 * 1024,
    )
    csam_summary_raw, _ = evidence_file(
        args.csam_text_summary,
        CSAM_TEXT_PATHS["summary"],
        "CSAM text summary",
        2 * 1024 * 1024,
    )
    csam_cleanup_raw, _ = evidence_file(
        args.csam_text_privacy_cleanup,
        CSAM_TEXT_PATHS["privacy_cleanup"],
        "CSAM text privacy cleanup",
        2 * 1024 * 1024,
    )
    lazy_phase, _ = load_canonical_bytes(lazy_phase_raw, "lazy-read phase boundary")
    lazy_summary, _ = load_canonical_bytes(lazy_summary_raw, "lazy-read runtime read summary")
    csam_fixture, _ = load_canonical_bytes(csam_fixture_raw, "CSAM text fixture manifest")
    csam_results, _ = load_canonical_bytes(csam_results_raw, "CSAM text results")
    csam_summary, _ = load_canonical_bytes(csam_summary_raw, "CSAM text summary")
    csam_cleanup, _ = load_canonical_bytes(csam_cleanup_raw, "CSAM text privacy cleanup")
    lazy_projection = validate_lazy_read_evidence(
        lazy_phase, lazy_trace_raw, lazy_summary
    )
    validate_lazy_read_bindings(
        lazy_trace_raw, manifest, results_raw,
        supplemental_manifest, supplemental_results_raw,
    )
    if lazy_projection["run_id"] != machine["run"]["run_id"]:
        fail("lazy-read evidence run ID differs from the machine evidence")
    csam_projection = validate_csam_text_evidence(
        csam_fixture,
        csam_results,
        csam_summary,
        csam_cleanup,
        expected_run_id=machine["run"]["run_id"],
    )
    # Keep the packer's output contract honest even if a future caller changes
    # the projection helper: all seven source bytes must already be reflected
    # in the returned input map and can never be omitted silently.
    return {
        "candidate_files": candidate_files,
        "candidate_manifest": candidate_manifest,
        "candidate_raw": candidate_raw,
        "machine": machine,
        "machine_raw": machine_raw,
        "manifest": manifest,
        "manifest_raw": manifest_raw,
        "measurements_raw": measurements_raw,
        "native_go_test_raw": native_go_test_raw,
        "native_report": native_report,
        "native_report_raw": native_report_raw,
        "performance": performance,
        "performance_config_raw": performance_config_raw,
        "performance_raw": performance_raw,
        "host_admission": validated_host_admission,
        "host_admission_config": host_config,
        "host_admission_approved_runtime": host_config["approved_runtime_identities"],
        "host_admission_config_raw": host_config_raw,
        "host_admission_manifest_raw": host_evidence_manifest_raw,
        "host_admission_sqlite_sha256": host_sqlite_sha256,
        "host_admission_raw": host_admission_raw,
        "host_admission_300s_raw": host_admission_300s_raw,
        "host_admission_3600s_raw": host_admission_3600s_raw,
        "host_admission_realtime_raw": host_admission_realtime_raw,
        "lazy_read": lazy_projection,
        "lazy_read_phase_boundary_raw": lazy_phase_raw,
        "lazy_read_runtime_read_trace_raw": lazy_trace_raw,
        "lazy_read_runtime_read_summary_raw": lazy_summary_raw,
        "csam_text": csam_projection,
        "csam_text_fixture_manifest_raw": csam_fixture_raw,
        "csam_text_results_raw": csam_results_raw,
        "csam_text_summary_raw": csam_summary_raw,
        "csam_text_privacy_cleanup_raw": csam_cleanup_raw,
        "results_path": args.results,
        "results_raw": results_raw,
        "run_config": run_config,
        "run_config_raw": run_config_raw,
        "supplemental_archive_binding": supplemental_archive_binding,
        "supplemental_archive_path": args.supplemental_archive.resolve(strict=True),
        "supplemental_manifest": supplemental_manifest,
        "supplemental_manifest_raw": supplemental_manifest_raw,
        "supplemental_policy_raw": supplemental_policy_raw,
        "supplemental_results_raw": supplemental_results_raw,
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
    created_identity: tuple[int, int] | None = None
    try:
        created = path.lstat()
        created_identity = (created.st_dev, created.st_ino)
        initial = os.fstat(descriptor)
        if (
            not stat.S_ISREG(initial.st_mode)
            or initial.st_nlink != 1
            or initial.st_size != 0
            or (initial.st_dev, initial.st_ino) != created_identity
        ):
            fail("new admission output is not a fresh single-link regular file")
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            descriptor = -1
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
            info = os.fstat(handle.fileno())
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or info.st_size != len(raw)
                or (info.st_dev, info.st_ino) != created_identity
            ):
                fail("new admission output is not a complete single-link regular file")
    except BaseException:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass
        try:
            current = path.lstat()
            if created_identity is None or (
                current.st_dev,
                current.st_ino,
            ) == created_identity:
                path.unlink()
        except FileNotFoundError:
            pass
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
    pack.add_argument("--supplemental-archive", type=Path, required=True)
    pack.add_argument("--supplemental-manifest", type=Path, required=True)
    pack.add_argument("--supplemental-policy", type=Path, required=True)
    pack.add_argument("--supplemental-results", type=Path, required=True)
    pack.add_argument("--native-report", type=Path, required=True)
    pack.add_argument("--native-go-test-jsonl", type=Path, required=True)
    pack.add_argument("--checkout", type=Path, required=True)
    pack.add_argument("--workload-manifest", type=Path, required=True)
    pack.add_argument("--performance-config", type=Path, required=True)
    pack.add_argument("--measurements", type=Path, required=True)
    pack.add_argument("--performance-evidence", type=Path, required=True)
    pack.add_argument("--host-admission", type=Path, required=True)
    pack.add_argument("--host-admission-300s", type=Path, required=True)
    pack.add_argument("--host-admission-3600s", type=Path, required=True)
    pack.add_argument("--host-admission-realtime", type=Path, required=True)
    pack.add_argument("--host-admission-config", type=Path, required=True)
    pack.add_argument("--host-admission-evidence-manifest", type=Path, required=True)
    # These are intentionally explicit even though the files live below the
    # machine-evidence directory: operators must point at the original run
    # artifacts, never at a copied/hand-authored summary.
    pack.add_argument("--lazy-read-phase-boundary", type=Path, required=True)
    pack.add_argument("--lazy-read-runtime-read-trace", type=Path, required=True)
    pack.add_argument("--lazy-read-runtime-read-summary", type=Path, required=True)
    pack.add_argument("--csam-text-fixture-manifest", type=Path, required=True)
    pack.add_argument("--csam-text-results", type=Path, required=True)
    pack.add_argument("--csam-text-summary", type=Path, required=True)
    pack.add_argument("--csam-text-privacy-cleanup", type=Path, required=True)
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
            supplemental_archive_path = values.pop("supplemental_archive_path")
            supplemental_archive_binding = values["supplemental_archive_binding"]
            report = build_report(
                **values,
                candidate_artifact_size=args.candidate_artifact_size,
                generated_at=datetime.now(timezone.utc),
            )
            reverify_supplemental_archive(
                supplemental_archive_path, supplemental_archive_binding
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
            "cpa_abi": report["cpa"]["c_abi"],
            "cpa_commit": report["cpa"]["commit"],
            "cpa_rpc_schema": report["cpa"]["rpc_schema"],
            "cpa_tag": report["cpa"]["tag"],
            "false_positives": summary["false_positives"],
            "independent_proof": str(report["safety"]["independent_proof"]).lower(),
            "malicious_recall_percent": summary["malicious_recall_percent"],
            "owner_run": str(report["safety"]["owner_run"]).lower(),
            "performance_gate_count": summary["performance_gate_count"],
            "performance_gates_passed": summary["performance_gates_passed"],
            "performance_gates_sha256": sha256_bytes(canonical_bytes(report["performance"]["gates"])),
            "performance_status": report["performance"]["status"],
            "supplemental_archive_status": report["supplemental_archive"]["status"],
            "supplemental_archive_sha256": report["supplemental_archive"]["archive"]["sha256"],
            "supplemental_manifest_sha256": report["supplemental_archive"]["manifest_sha256"],
            "supplemental_policy_sha256": report["supplemental_archive"]["policy_sha256"],
            "supplemental_results_sha256": report["supplemental_archive"]["results_sha256"],
            "supplemental_summary_sha256": sha256_bytes(canonical_bytes(report["supplemental_archive"]["summary_by_mode"])),
            "native_host_status": report["native_host_special_paths"]["status"],
            "native_host_special_paths_report_sha256": report["native_host_special_paths"]["report_sha256"],
            "native_host_special_paths_source_sha256": report["native_host_special_paths"]["source_sha256"],
            "native_host_special_paths_schema_sha256": report["native_host_special_paths"]["schema_sha256"],
            "native_host_test_source_sha256": report["native_host_special_paths"]["test_source_sha256"],
            "native_host_go_test_log_sha256": report["native_host_special_paths"]["go_test_log_sha256"],
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
