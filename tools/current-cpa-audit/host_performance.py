#!/usr/bin/env python3
"""Build and validate fail-closed RT12-06 CPA Host A/B performance evidence.

This module deliberately does not invent measurements.  Its Linux ``collect``
entry point drives the two inspected Host arms and writes a closed raw capture;
its assembler then recomputes every published percentile and comparison, binds
the result to the current-CPA run config and sealed CI candidate manifest, and
emits PASS only when the sample contract and every task-book threshold hold.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import math
import os
import platform
import random
import re
import stat
import statistics
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Mapping, NoReturn, Sequence

from audit_contract import (
    CLAIM_BOUNDARY,
    ContractError,
    canonical_bytes,
    exact_bool,
    exact_int,
    exact_keys,
    exact_list,
    load_json_bytes,
    nonempty_string,
    one_of,
    read_regular_bytes,
    require_hex,
    require_safe_relative,
    sha256_bytes,
    timestamp_value,
    validate_run_config,
)


CONFIG_SCHEMA = "cag-current-cpa-host-performance-config/v1"
MEASUREMENTS_SCHEMA = "cag-current-cpa-host-performance-measurements/v1"
EVIDENCE_SCHEMA = "cag-current-cpa-host-performance-evidence/v1"
WORKLOAD_SCHEMA = "cag-current-cpa-host-performance-workloads/v1"
CANDIDATE_SCHEMA = "cyber-abuse-guard.audit-candidate-manifest.v1"
CANDIDATE_STATUS = "UNRELEASED / SECOND-MACHINE AUDIT CANDIDATE / NOT RELEASE"

ARMS = ("cpa_only", "cpa_cag")
CONCURRENCIES = (1, 4, 8, 16)
ABSOLUTE_WORKLOADS = ("ordinary", "five_repository_activation", "public")
FIXED_WORKLOAD = "fixed_workload"
ALL_WORKLOADS = (FIXED_WORKLOAD, *ABSOLUTE_WORKLOADS)

MIN_PAIRED_REPETITIONS = 3
MAX_PAIRED_REPETITIONS = 10
MIN_WARMUP_SECONDS = 30
MIN_MEASUREMENT_SECONDS = 120
MIN_SUCCESS_SAMPLES_PER_CELL = 1_000
MIN_SECRET_LENGTH = 32
MAX_CELL_OVERRUN_SECONDS = 5.0
MAX_PAIRED_WINDOW_DELTA_SECONDS = 1.0
MIN_PREFLIGHT_SECONDS = 300
MAX_PREFLIGHT_INTERVAL_SECONDS = 1
BACKGROUND_CPU_LIMIT_PERCENT = 20.0
STEAL_CPU_LIMIT_PERCENT = 1.0
BACKGROUND_CPU_ROLLING_SECONDS = 60
MEASUREMENT_HOST_CPU_LIMIT_PERCENT = 95.0
TIMESTAMP_TOLERANCE_SECONDS = 5.0
MAX_WARM_DRAIN_SECONDS = 125.0
SAMPLER_TIMING_PREFLIGHT_SAMPLES = 3
MOCK_COUNTER_KEYS = ("auth", "mock", "provider")

EXPECTED_STATUS_BY_WORKLOAD: dict[str, dict[str, int]] = {
    "fixed_workload": {"cpa_only": 200, "cpa_cag": 200},
    "ordinary": {"cpa_only": 200, "cpa_cag": 200},
    "five_repository_activation": {"cpa_only": 200, "cpa_cag": 403},
    "public": {"cpa_only": 200, "cpa_cag": 200},
}

THRESHOLDS: dict[str, tuple[str, float]] = {
    "ordinary_p95_ms": ("<=", 10.0),
    "five_repository_activation_p95_ms": ("<=", 250.0),
    "public_p95_ms": ("<=", 150.0),
    "public_p99_ms": ("<=", 300.0),
    "fixed_workload_p99_regression_percent": ("<=", 10.0),
    "host_throughput_vs_cpa_only": (">=", 0.90),
    "audit_queue_peak_ratio": ("<", 0.80),
    "warm_rss_growth_60m_mib": ("<=", 64.0),
    "unexpected_http_or_infra_errors": ("=", 0.0),
    "restart_oom_panic": ("=", 0.0),
}

SAFE_ARTIFACT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,255}")
SAFE_PAIR = re.compile(r"[a-z0-9][a-z0-9_.-]{2,127}")
TOOL_DIR = Path(__file__).resolve().parent
TOOL_IDENTITY_SOURCE_KEYS = (
    "acquire_sha256",
    "audit_contract_sha256",
    "host_performance_schema_sha256",
    "host_performance_source_sha256",
    "run_sha256",
    "validator_sha256",
)
TOOL_IDENTITY_KEYS = (*TOOL_IDENTITY_SOURCE_KEYS, "bundle_sha256")


class PerformanceError(ContractError):
    """A Host performance input or cross-file binding failed closed."""


def fail(message: str) -> NoReturn:
    raise PerformanceError(message)


def finite_number(
    value: Any, label: str, *, minimum: float | None = None
) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        fail(f"{label} must be a finite number")
    result = float(value)
    if not math.isfinite(result) or (minimum is not None and result < minimum):
        fail(f"{label} must be a finite number >= {minimum}")
    return result


def _canonical_file(path: Path, label: str, maximum: int) -> tuple[dict[str, Any], bytes]:
    raw = read_regular_bytes(path, label, maximum)
    value = load_json_bytes(raw, label, maximum)
    if not isinstance(value, dict):
        fail(f"{label} must be a JSON object")
    if raw != canonical_bytes(value) + b"\n":
        fail(f"{label} must be canonical JSON with one terminal newline")
    return value, raw


def _timestamp_order(
    started: Any,
    completed: Any,
    label: str,
    *,
    elapsed_seconds: float | None = None,
) -> None:
    start = timestamp_value(started, f"{label}.started_at")
    end = timestamp_value(completed, f"{label}.completed_at")
    if end < start:
        fail(f"{label} completion precedes its start")
    if elapsed_seconds is not None:
        wall_seconds = (end - start).total_seconds()
        if (
            wall_seconds < elapsed_seconds - TIMESTAMP_TOLERANCE_SECONDS
            or wall_seconds > elapsed_seconds + TIMESTAMP_TOLERANCE_SECONDS
        ):
            fail(f"{label} wall-clock interval does not match elapsed_seconds")


def _redacted_cpa_config(value: Any, *, path: tuple[str, ...] = ()) -> Any:
    """Return a secret-free, plugin-neutral projection of observed CPA config."""

    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for raw_key, item in value.items():
            key = str(raw_key)
            lowered = key.lower()
            if not path and lowered == "plugins":
                continue
            if (
                lowered in {
                    "api-key",
                    "api-keys",
                    "secret-key",
                    "master-key",
                    "access-token",
                    "refresh-token",
                }
                or lowered.endswith(("-api-key", "_api_key", "-secret", "_secret", "-token", "_token"))
            ):
                if isinstance(item, list):
                    result[key] = ["<redacted>"] * len(item)
                elif item is None:
                    result[key] = None
                else:
                    result[key] = "<redacted>"
            else:
                result[key] = _redacted_cpa_config(item, path=(*path, key))
        return result
    if isinstance(value, list):
        return [_redacted_cpa_config(item, path=path) for item in value]
    return value


def _redacted_environment(value: Any) -> list[str]:
    if value in (None, []):
        return []
    if not isinstance(value, list):
        fail("Host performance container Env is not a list")
    result: list[str] = []
    for index, raw in enumerate(value):
        if not isinstance(raw, str) or "=" not in raw:
            fail(f"Host performance container Env[{index}] is invalid")
        name, item = raw.split("=", 1)
        if not name:
            fail(f"Host performance container Env[{index}] has no name")
        upper = name.upper()
        if upper == "HOSTNAME":
            item = "<container-specific>"
        elif any(
            marker in upper
            for marker in ("KEY", "TOKEN", "SECRET", "PASSWORD", "CREDENTIAL")
        ):
            item = "<redacted>"
        result.append(f"{name}={item}")
    return sorted(result)


def _docker_comparable_projection(info: Mapping[str, Any]) -> dict[str, Any]:
    """Project observed Docker state that must be equal across A/B arms."""

    config_raw = info.get("Config") or {}
    host_raw = info.get("HostConfig") or {}
    if not isinstance(config_raw, dict) or not isinstance(host_raw, dict):
        fail("Host performance Docker inspect config is invalid")
    config = {
        key: value
        for key, value in config_raw.items()
        if key not in {"Env", "Hostname", "Labels"}
    }
    config["Env"] = _redacted_environment(config_raw.get("Env"))
    labels = config_raw.get("Labels") or {}
    if not isinstance(labels, dict):
        fail("Host performance Docker inspect labels are invalid")
    config["Labels"] = {
        key: value
        for key, value in labels.items()
        if key
        not in {
            "cag.current-cpa-audit.run",
            "cag.current-cpa-audit.role",
        }
    }
    host = {
        key: value
        for key, value in host_raw.items()
        if key not in {"Binds", "Mounts"}
    }
    mounts: list[dict[str, Any]] = []
    for raw in info.get("Mounts") or []:
        if not isinstance(raw, dict):
            fail("Host performance Docker inspect mount is invalid")
        destination = str(raw.get("Destination", ""))
        if destination == "/cag/plugins":
            continue
        mounts.append(
            {
                "destination": destination,
                "driver": str(raw.get("Driver", "")),
                "mode": str(raw.get("Mode", "")),
                "propagation": str(raw.get("Propagation", "")),
                "read_only": raw.get("RW") is False,
                "type": str(raw.get("Type", "")),
            }
        )
    mounts.sort(
        key=lambda item: (
            item["destination"],
            item["type"],
            item["mode"],
        )
    )
    return {
        "args": info.get("Args") or [],
        "config": config,
        "host_config": host,
        "mounts": mounts,
        "path": str(info.get("Path", "")),
        "platform": str(info.get("Platform", "")),
    }


def _mountinfo_path(value: str) -> str:
    return re.sub(
        r"\\([0-7]{3})",
        lambda match: chr(int(match.group(1), 8)),
        value,
    )


def _mount_backing_identity(path: Path, mountinfo_raw: str) -> dict[str, Any]:
    resolved = path.resolve(strict=True)
    info = resolved.stat()
    matches: list[tuple[int, dict[str, Any]]] = []
    for raw_line in mountinfo_raw.splitlines():
        fields = raw_line.split()
        if "-" not in fields:
            continue
        separator = fields.index("-")
        if separator < 6 or len(fields) <= separator + 3:
            continue
        mountpoint = Path(_mountinfo_path(fields[4]))
        try:
            resolved.relative_to(mountpoint)
        except ValueError:
            continue
        matches.append(
            (
                len(mountpoint.parts),
                {
                    "device": fields[2],
                    "filesystem_type": fields[separator + 1],
                    "kind": (
                        "directory"
                        if stat.S_ISDIR(info.st_mode)
                        else "file"
                        if stat.S_ISREG(info.st_mode)
                        else "other"
                    ),
                    "mount_options": sorted(fields[5].split(",")),
                    "st_dev": int(info.st_dev),
                    "super_options": sorted(fields[separator + 3].split(",")),
                },
            )
        )
    if not matches:
        fail("Host performance bind source has no /proc/self/mountinfo identity")
    return max(matches, key=lambda item: item[0])[1]


def validate_tool_identities(value: Any, label: str) -> dict[str, str]:
    identities = exact_keys(value, set(TOOL_IDENTITY_KEYS), label)
    sources = {
        key: require_hex(identities[key], f"{label}.{key}")
        for key in TOOL_IDENTITY_SOURCE_KEYS
    }
    bundle = require_hex(identities["bundle_sha256"], f"{label}.bundle_sha256")
    if bundle != sha256_bytes(canonical_bytes(sources)):
        fail(f"{label}.bundle_sha256 does not bind the individual tool identities")
    return {**sources, "bundle_sha256": bundle}


def tool_identities() -> dict[str, str]:
    paths = {
        "acquire_sha256": TOOL_DIR / "acquire.py",
        "audit_contract_sha256": TOOL_DIR / "audit_contract.py",
        "host_performance_schema_sha256": TOOL_DIR / "host-performance-evidence.schema.json",
        "host_performance_source_sha256": TOOL_DIR / "host_performance.py",
        "run_sha256": TOOL_DIR / "run.py",
        "validator_sha256": TOOL_DIR / "validate.py",
    }
    identities = {
        key: sha256_bytes(read_regular_bytes(path, key, 4 * 1024 * 1024))
        for key, path in paths.items()
    }
    identities["bundle_sha256"] = sha256_bytes(canonical_bytes(identities))
    return validate_tool_identities(identities, "current Host performance tools")


def require_current_tool_identities(
    expected: Any, label: str
) -> dict[str, str]:
    approved = validate_tool_identities(expected, f"{label}.approved")
    observed = tool_identities()
    if observed != approved:
        fail(f"{label} drifted from the approved Host performance tool identities")
    return observed


def validate_candidate_manifest(
    value: Any, cag_identity: Mapping[str, Any]
) -> dict[str, Any]:
    """Validate the exact eight-file CI candidate seal and selected SO identity."""

    manifest = exact_keys(
        value,
        {
            "artifacts",
            "commit",
            "dirty",
            "event",
            "run_attempt",
            "run_id",
            "schema",
            "status",
            "tree",
            "version",
        },
        "candidate manifest",
    )
    if manifest["schema"] != CANDIDATE_SCHEMA or manifest["status"] != CANDIDATE_STATUS:
        fail("candidate manifest schema or diagnostic status is invalid")
    if exact_bool(manifest["dirty"], "candidate manifest.dirty"):
        fail("candidate manifest is dirty")
    commit = require_hex(manifest["commit"], "candidate manifest.commit", re.compile(r"[0-9a-f]{40}"))
    tree = require_hex(manifest["tree"], "candidate manifest.tree", re.compile(r"[0-9a-f]{40}"))
    if commit != cag_identity["commit"] or tree != cag_identity["tree"]:
        fail("candidate manifest commit/tree drifted from the run config")
    nonempty_string(manifest["event"], "candidate manifest.event", 64)
    candidate_run_id = nonempty_string(manifest["run_id"], "candidate manifest.run_id", 32)
    candidate_attempt = nonempty_string(
        manifest["run_attempt"], "candidate manifest.run_attempt", 20
    )
    if not candidate_run_id.isdigit() or candidate_run_id.startswith("0"):
        fail("candidate manifest.run_id must be a positive decimal GitHub run ID")
    if not candidate_attempt.isdigit() or candidate_attempt.startswith("0"):
        fail("candidate manifest.run_attempt must be a positive decimal value")
    version = nonempty_string(manifest["version"], "candidate manifest.version", 64)
    if re.fullmatch(r"[0-9]+\.[0-9]+(?:\.[0-9]+)?(?:[-+][0-9A-Za-z.-]+)?", version) is None:
        fail("candidate manifest.version is invalid")
    artifacts = exact_list(manifest["artifacts"], "candidate manifest.artifacts", 8)
    if len(artifacts) != 8:
        fail("candidate manifest must seal exactly eight base artifacts")
    names: set[str] = set()
    selected: dict[str, Any] | None = None
    expected_so_name = f"cyber-abuse-guard-v{version}.so"
    for index, raw in enumerate(artifacts):
        label = f"candidate manifest.artifacts[{index}]"
        item = exact_keys(raw, {"bytes", "name", "sha256"}, label)
        name = nonempty_string(item["name"], f"{label}.name", 256)
        if SAFE_ARTIFACT.fullmatch(name) is None or name in names:
            fail(f"{label}.name is unsafe or duplicated")
        names.add(name)
        exact_int(item["bytes"], f"{label}.bytes", 1)
        require_hex(item["sha256"], f"{label}.sha256")
        if name == expected_so_name:
            selected = item
    if selected is None or selected["sha256"] != cag_identity["so_sha256"]:
        fail("candidate manifest does not bind the selected CAG SO")
    expected_names = {
        expected_so_name,
        expected_so_name + ".sha256",
        f"cyber-abuse-guard_{version}_linux_amd64.zip",
        "build-metadata.json",
        "checksums.txt",
        "ruleset-manifest.json",
        "ruleset.sha256",
        "sbom.cdx.json",
    }
    if names != expected_names:
        fail("candidate manifest base-artifact name set is not exact")
    return manifest


def candidate_identity(manifest: Mapping[str, Any], raw: bytes) -> dict[str, Any]:
    version = str(manifest["version"])
    artifact_name = f"cyber-abuse-guard-v{version}.so"
    selected = next(item for item in manifest["artifacts"] if item["name"] == artifact_name)
    return {
        "artifact_name": artifact_name,
        "artifact_sha256": selected["sha256"],
        "commit": manifest["commit"],
        "dirty": manifest["dirty"],
        "manifest_sha256": sha256_bytes(raw),
        "run_attempt": manifest["run_attempt"],
        "run_id": manifest["run_id"],
        "schema": manifest["schema"],
        "status": manifest["status"],
        "tree": manifest["tree"],
        "version": manifest["version"],
    }


def validate_workload_manifest(value: Any) -> dict[str, Any]:
    manifest = exact_keys(value, {"schema", "workloads"}, "performance workload manifest")
    if manifest["schema"] != WORKLOAD_SCHEMA:
        fail("performance workload manifest schema is invalid")
    workloads = exact_list(manifest["workloads"], "performance workload manifest.workloads", 4)
    if len(workloads) != 4:
        fail("performance workload manifest must contain exactly four workloads")
    seen: dict[str, dict[str, Any]] = {}
    for index, raw in enumerate(workloads):
        label = f"performance workload manifest.workloads[{index}]"
        item = exact_keys(raw, {"id", "request_count", "request_set_sha256", "requests"}, label)
        workload = one_of(item["id"], ALL_WORKLOADS, f"{label}.id")
        if workload in seen:
            fail("performance workload manifest contains a duplicate workload")
        request_count = exact_int(item["request_count"], f"{label}.request_count", 1)
        requests = exact_list(item["requests"], f"{label}.requests", 1)
        if len(requests) != request_count:
            fail(f"{label}.request_count does not match requests")
        seen_paths: set[str] = set()
        for request_index, request_raw in enumerate(requests):
            request_label = f"{label}.requests[{request_index}]"
            request = exact_keys(
                request_raw,
                {"body_path", "body_sha256", "endpoint", "expected_status_by_arm"},
                request_label,
            )
            body_path = require_safe_relative(request["body_path"], f"{request_label}.body_path")
            if body_path in seen_paths:
                fail(f"{request_label}.body_path is duplicated")
            seen_paths.add(body_path)
            require_hex(request["body_sha256"], f"{request_label}.body_sha256")
            one_of(
                request["endpoint"],
                ("/v1/chat/completions", "/v1/responses"),
                f"{request_label}.endpoint",
            )
            statuses = exact_keys(
                request["expected_status_by_arm"], ARMS, f"{request_label}.expected_status_by_arm"
            )
            for arm in ARMS:
                status = exact_int(statuses[arm], f"{request_label}.expected_status_by_arm.{arm}", 100)
                if status > 599:
                    fail(f"{request_label}.expected_status_by_arm.{arm} exceeds 599")
                if status != EXPECTED_STATUS_BY_WORKLOAD[workload][arm]:
                    fail(
                        f"{request_label}.expected_status_by_arm.{arm} does not match "
                        "the code-owned workload contract"
                    )
        request_set_sha = require_hex(item["request_set_sha256"], f"{label}.request_set_sha256")
        if request_set_sha != sha256_bytes(canonical_bytes(requests)):
            fail(f"{label}.request_set_sha256 does not bind the request contracts")
        seen[workload] = item
    if set(seen) != set(ALL_WORKLOADS):
        fail("performance workload manifest is incomplete")
    return manifest


def _validate_thresholds(value: Any, label: str) -> dict[str, Any]:
    thresholds = exact_keys(value, THRESHOLDS, label)
    for metric, (_, expected) in THRESHOLDS.items():
        observed = finite_number(thresholds[metric], f"{label}.{metric}")
        if observed != expected:
            fail(f"{label}.{metric} cannot loosen the RT12-06 threshold")
    return thresholds


def build_config(
    run_config: Mapping[str, Any],
    run_config_raw: bytes,
    candidate_manifest: Mapping[str, Any],
    candidate_raw: bytes,
    workload_raw: bytes,
    *,
    approved_tool_identities: Mapping[str, Any],
    seed: int,
    paired_repetitions: int,
    warmup_seconds: int,
    measurement_seconds: int,
    min_success_samples_per_cell: int,
    resource_sample_interval_ms: int,
    queue_sample_interval_ms: int,
    warm_rss_sample_interval_seconds: int,
) -> dict[str, Any]:
    approved_tools = require_current_tool_identities(
        approved_tool_identities, "Host performance make-config"
    )
    config = {
        "approved_tool_identities": approved_tools,
        "candidate_manifest_sha256": sha256_bytes(candidate_raw),
        "identities": {
            "cag": dict(run_config["identities"]["cag"]),
            "candidate": candidate_identity(candidate_manifest, candidate_raw),
            "cpa": dict(run_config["identities"]["cpa"]),
            "mock": dict(run_config["identities"]["mock"]),
        },
        "plan": {
            "arms": list(ARMS),
            "concurrencies": list(CONCURRENCIES),
            "measurement_seconds": measurement_seconds,
            "min_success_samples_per_cell": min_success_samples_per_cell,
            "paired_repetitions": paired_repetitions,
            "queue_sample_interval_ms": queue_sample_interval_ms,
            "resource_sample_interval_ms": resource_sample_interval_ms,
            "seed": seed,
            "warm_rss_concurrency": 16,
            "warm_rss_duration_seconds": 3600,
            "warm_rss_sample_interval_seconds": warm_rss_sample_interval_seconds,
            "warmup_seconds": warmup_seconds,
        },
        "run_config_sha256": sha256_bytes(run_config_raw),
        "schema": CONFIG_SCHEMA,
        "semantic_run_id": run_config["run"]["run_id"],
        "thresholds": {metric: limit for metric, (_, limit) in THRESHOLDS.items()},
        "workload_manifest_sha256": sha256_bytes(workload_raw),
    }
    validate_config(config, run_config, run_config_raw, candidate_manifest, candidate_raw, workload_raw)
    return config


def validate_config(
    value: Any,
    run_config: Mapping[str, Any],
    run_config_raw: bytes,
    candidate_manifest: Mapping[str, Any],
    candidate_raw: bytes,
    workload_raw: bytes,
    *,
    observed_tool_identities: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    config = exact_keys(
        value,
        {
            "approved_tool_identities",
            "candidate_manifest_sha256",
            "identities",
            "plan",
            "run_config_sha256",
            "schema",
            "semantic_run_id",
            "thresholds",
            "workload_manifest_sha256",
        },
        "host performance config",
    )
    if config["schema"] != CONFIG_SCHEMA:
        fail("host performance config schema is invalid")
    approved_tools = validate_tool_identities(
        config["approved_tool_identities"],
        "host performance config.approved_tool_identities",
    )
    observed_tools = (
        tool_identities()
        if observed_tool_identities is None
        else validate_tool_identities(
            observed_tool_identities,
            "observed Host performance tool identities",
        )
    )
    if observed_tools != approved_tools:
        fail("host performance config tool identities drifted from current tool bytes")
    if config["semantic_run_id"] != run_config["run"]["run_id"]:
        fail("host performance config semantic run ID drifted from the run config")
    if require_hex(config["run_config_sha256"], "host performance config.run_config_sha256") != sha256_bytes(run_config_raw):
        fail("host performance config is not bound to the supplied run config")
    if require_hex(config["candidate_manifest_sha256"], "host performance config.candidate_manifest_sha256") != sha256_bytes(candidate_raw):
        fail("host performance config is not bound to the candidate manifest")
    if require_hex(config["workload_manifest_sha256"], "host performance config.workload_manifest_sha256") != sha256_bytes(workload_raw):
        fail("host performance config is not bound to the workload manifest")

    expected_identities = exact_keys(
        config["identities"], {"cag", "candidate", "cpa", "mock"}, "host performance config.identities"
    )
    if expected_identities["cag"] != run_config["identities"]["cag"]:
        fail("host performance config CAG identity drifted from the run config")
    if expected_identities["cpa"] != run_config["identities"]["cpa"]:
        fail("host performance config CPA identity drifted from the run config")
    if expected_identities["mock"] != run_config["identities"]["mock"]:
        fail("host performance config Mock identity drifted from the run config")
    if expected_identities["candidate"] != candidate_identity(candidate_manifest, candidate_raw):
        fail("host performance config candidate identity drifted")

    plan = exact_keys(
        config["plan"],
        {
            "arms",
            "concurrencies",
            "measurement_seconds",
            "min_success_samples_per_cell",
            "paired_repetitions",
            "queue_sample_interval_ms",
            "resource_sample_interval_ms",
            "seed",
            "warm_rss_concurrency",
            "warm_rss_duration_seconds",
            "warm_rss_sample_interval_seconds",
            "warmup_seconds",
        },
        "host performance config.plan",
    )
    if plan["arms"] != list(ARMS) or plan["concurrencies"] != list(CONCURRENCIES):
        fail("host performance config does not require the exact CPA-only/CPA+CAG c=1/4/8/16 matrix")
    exact_int(plan["seed"], "host performance config.plan.seed", 0)
    repetitions = exact_int(plan["paired_repetitions"], "host performance config.plan.paired_repetitions", MIN_PAIRED_REPETITIONS)
    if repetitions > MAX_PAIRED_REPETITIONS:
        fail("host performance paired repetition count exceeds the reviewed bound")
    exact_int(plan["warmup_seconds"], "host performance config.plan.warmup_seconds", MIN_WARMUP_SECONDS)
    exact_int(plan["measurement_seconds"], "host performance config.plan.measurement_seconds", MIN_MEASUREMENT_SECONDS)
    exact_int(plan["min_success_samples_per_cell"], "host performance config.plan.min_success_samples_per_cell", MIN_SUCCESS_SAMPLES_PER_CELL)
    resource_interval = exact_int(plan["resource_sample_interval_ms"], "host performance config.plan.resource_sample_interval_ms", 100)
    if resource_interval != 1000:
        fail("host performance resource sample interval must be exactly 1000 ms")
    queue_interval = exact_int(plan["queue_sample_interval_ms"], "host performance config.plan.queue_sample_interval_ms", 10)
    if queue_interval != 100:
        fail("host performance audit-queue sample interval must be exactly 100 ms")
    if exact_int(plan["warm_rss_duration_seconds"], "host performance config.plan.warm_rss_duration_seconds") != 3600:
        fail("host performance warm RSS duration must be exactly 3600 seconds")
    if exact_int(plan["warm_rss_concurrency"], "host performance config.plan.warm_rss_concurrency") != 16:
        fail("host performance warm RSS concurrency must be 16")
    warm_interval = exact_int(plan["warm_rss_sample_interval_seconds"], "host performance config.plan.warm_rss_sample_interval_seconds", 1)
    if warm_interval != 1:
        fail("host performance warm RSS sample interval must be exactly 1 second")
    _validate_thresholds(config["thresholds"], "host performance config.thresholds")
    return config


def paired_order(seed: int, concurrency: int, repetition: int) -> tuple[str, str]:
    rng = random.Random(f"cag-rt12-host-ab:{seed}:{concurrency}:{repetition}")
    arms = list(ARMS)
    rng.shuffle(arms)
    return arms[0], arms[1]


def nearest_rank(samples: Sequence[float], percentile: int) -> float:
    if not samples:
        fail("percentile sample set is empty")
    if percentile < 1 or percentile > 100:
        fail("percentile is outside 1..100")
    ordered = sorted(samples)
    index = max(0, math.ceil((percentile / 100.0) * len(ordered)) - 1)
    return float(ordered[index])


def _rolling_mean_peak(samples: Sequence[float], width: int) -> float:
    if width < 1 or len(samples) < width:
        fail("preflight sample set cannot cover the rolling CPU window")
    window = sum(samples[:width])
    peak = window / width
    for index in range(width, len(samples)):
        window += samples[index] - samples[index - width]
        peak = max(peak, window / width)
    return peak


def _validate_preflight(value: Any) -> tuple[dict[str, Any], dict[str, float | int | bool]]:
    preflight = exact_keys(
        value,
        {"background_cpu_percent", "sample_interval_seconds", "steal_cpu_percent"},
        "host performance measurements.baseline_eligibility",
    )
    interval = exact_int(preflight["sample_interval_seconds"], "baseline eligibility.sample_interval_seconds", 1)
    if interval > MAX_PREFLIGHT_INTERVAL_SECONDS:
        fail("baseline eligibility samples are too sparse")
    minimum = math.ceil(MIN_PREFLIGHT_SECONDS / interval)
    cpu_raw = exact_list(preflight["background_cpu_percent"], "baseline eligibility.background_cpu_percent", minimum)
    steal_raw = exact_list(preflight["steal_cpu_percent"], "baseline eligibility.steal_cpu_percent", minimum)
    if len(cpu_raw) != len(steal_raw) or len(cpu_raw) < minimum:
        fail("baseline eligibility lacks the complete paired CPU/steal preflight")
    cpu = [finite_number(item, f"baseline eligibility.background_cpu_percent[{index}]", minimum=0.0) for index, item in enumerate(cpu_raw)]
    steal = [finite_number(item, f"baseline eligibility.steal_cpu_percent[{index}]", minimum=0.0) for index, item in enumerate(steal_raw)]
    if any(item > 100 for item in (*cpu, *steal)):
        fail("baseline eligibility CPU percentage exceeds 100")
    rolling_width = math.ceil(BACKGROUND_CPU_ROLLING_SECONDS / interval)
    cpu_p95 = nearest_rank(cpu, 95)
    cpu_rolling = _rolling_mean_peak(cpu, rolling_width)
    steal_p95 = nearest_rank(steal, 95)
    interfered = (
        cpu_p95 > BACKGROUND_CPU_LIMIT_PERCENT
        or cpu_rolling > BACKGROUND_CPU_LIMIT_PERCENT
        or steal_p95 > STEAL_CPU_LIMIT_PERCENT
    )
    reason_codes = ["sustained_high_cpu_interference"] if interfered else []
    return preflight, {
        "background_cpu_p95_percent": cpu_p95,
        "background_cpu_rolling_60s_peak_percent": cpu_rolling,
        "eligible": not interfered,
        "reason_codes": reason_codes,
        "sample_count": len(cpu),
        "status": "DIAGNOSTIC_NOT_BASELINE" if interfered else "BASELINE_ELIGIBLE",
        "steal_cpu_p95_percent": steal_p95,
        "sustained_high_cpu_interference": interfered,
    }


def _validate_container_security(value: Any, label: str) -> dict[str, Any]:
    security = exact_keys(value, {"no_new_privileges", "pids_limit"}, label)
    if not exact_bool(
        security["no_new_privileges"], f"{label}.no_new_privileges"
    ):
        fail(f"{label}.no_new_privileges must be true")
    pids_limit = exact_int(security["pids_limit"], f"{label}.pids_limit", 1)
    return {"no_new_privileges": True, "pids_limit": pids_limit}


def _validate_runtime(
    value: Any,
    label: str,
    arm: str,
    identities: Mapping[str, Any],
) -> dict[str, Any]:
    runtime = exact_keys(
        value,
        {
            "cag_loaded",
            "container_security",
            "cpa_base_config_sha256",
            "cpa_binary_sha256",
            "cpa_container_id",
            "cpa_image_id",
            "cpa_memory_bytes",
            "cpa_oom_killed",
            "cpa_restart_count",
            "cpuset_cpus",
            "docker_comparable_sha256",
            "loaded_cag_so_sha256",
            "mock_container_id",
            "mock_image_id",
            "mock_oom_killed",
            "mock_restart_count",
            "mock_source_sha256",
            "nano_cpus",
            "panic_mentions",
            "plugin_count",
            "runtime_config_sha256",
        },
        label,
    )
    container_security = exact_keys(
        runtime["container_security"], {"cpa", "mock"}, f"{label}.container_security"
    )
    _validate_container_security(
        container_security["cpa"], f"{label}.container_security.cpa"
    )
    _validate_container_security(
        container_security["mock"], f"{label}.container_security.mock"
    )
    require_hex(runtime["cpa_base_config_sha256"], f"{label}.cpa_base_config_sha256")
    require_hex(runtime["docker_comparable_sha256"], f"{label}.docker_comparable_sha256")
    require_hex(runtime["cpa_binary_sha256"], f"{label}.cpa_binary_sha256")
    require_hex(runtime["cpa_image_id"], f"{label}.cpa_image_id", re.compile(r"sha256:[0-9a-f]{64}"))
    require_hex(runtime["mock_image_id"], f"{label}.mock_image_id", re.compile(r"sha256:[0-9a-f]{64}"))
    require_hex(runtime["mock_source_sha256"], f"{label}.mock_source_sha256")
    if runtime["cpa_binary_sha256"] != identities["cpa"]["binary_sha256"] or runtime["cpa_image_id"] != identities["cpa"]["image_id"]:
        fail(f"{label} CPA runtime identity drifted")
    if runtime["mock_image_id"] != identities["mock"]["image_id"]:
        fail(f"{label} Mock runtime identity drifted")
    if runtime["mock_source_sha256"] != identities["mock"]["source_sha256"]:
        fail(f"{label} Mock source identity drifted")
    nonempty_string(runtime["cpa_container_id"], f"{label}.cpa_container_id", 128)
    nonempty_string(runtime["mock_container_id"], f"{label}.mock_container_id", 128)
    nonempty_string(runtime["cpuset_cpus"], f"{label}.cpuset_cpus", 128)
    exact_int(runtime["nano_cpus"], f"{label}.nano_cpus", 1)
    exact_int(runtime["cpa_memory_bytes"], f"{label}.cpa_memory_bytes", 1)
    require_hex(runtime["runtime_config_sha256"], f"{label}.runtime_config_sha256")
    exact_int(runtime["cpa_restart_count"], f"{label}.cpa_restart_count")
    exact_int(runtime["mock_restart_count"], f"{label}.mock_restart_count")
    exact_int(runtime["panic_mentions"], f"{label}.panic_mentions")
    exact_bool(runtime["cpa_oom_killed"], f"{label}.cpa_oom_killed")
    exact_bool(runtime["mock_oom_killed"], f"{label}.mock_oom_killed")
    loaded = exact_bool(runtime["cag_loaded"], f"{label}.cag_loaded")
    plugins = exact_int(runtime["plugin_count"], f"{label}.plugin_count")
    if arm == "cpa_only":
        if loaded or plugins != 0 or runtime["loaded_cag_so_sha256"] is not None:
            fail(f"{label} CPA-only arm loaded a plugin")
    else:
        if not loaded or plugins != 1:
            fail(f"{label} CPA+CAG arm did not load exactly one plugin")
        if require_hex(runtime["loaded_cag_so_sha256"], f"{label}.loaded_cag_so_sha256") != identities["cag"]["so_sha256"]:
            fail(f"{label} loaded CAG SO identity drifted")
    return runtime


def _validate_mock_counters(
    value: Any,
    label: str,
    *,
    expected_status: int,
    successful_samples: int,
) -> tuple[dict[str, Any], dict[str, int]]:
    record = exact_keys(value, {"after", "before", "delta"}, label)
    snapshots: dict[str, dict[str, int]] = {}
    for name in ("before", "after", "delta"):
        raw_snapshot = exact_keys(
            record[name], set(MOCK_COUNTER_KEYS), f"{label}.{name}"
        )
        snapshots[name] = {
            key: exact_int(raw_snapshot[key], f"{label}.{name}.{key}")
            for key in MOCK_COUNTER_KEYS
        }
    if snapshots["before"] != {key: 0 for key in MOCK_COUNTER_KEYS}:
        fail(f"{label}.before is not the post-reset zero snapshot")
    derived = {
        key: snapshots["after"][key] - snapshots["before"][key]
        for key in MOCK_COUNTER_KEYS
    }
    if any(value < 0 for value in derived.values()) or snapshots["delta"] != derived:
        fail(f"{label}.delta does not match the counted-Mock snapshots")
    expected_count = successful_samples if expected_status == 200 else 0
    expected = {key: expected_count for key in MOCK_COUNTER_KEYS}
    if derived != expected:
        fail(f"{label} violates the code-owned counted-Mock side-effect contract")
    return record, derived


def _validate_resource_samples(
    value: Any,
    label: str,
    duration_seconds: float,
    interval_ms: int,
    logical_cpu_count: int,
) -> tuple[
    list[dict[str, Any]],
    list[float],
    list[float],
    list[float],
    list[float],
    list[float],
    list[float],
]:
    minimum = math.floor(duration_seconds * 1000 / interval_ms) + 1
    rows = exact_list(value, label, minimum)
    if len(rows) < minimum:
        fail(f"{label} has insufficient resource samples")
    maximum = math.floor(duration_seconds * 1000 / interval_ms) + 2
    if len(rows) > maximum:
        fail(f"{label} has too many samples for the fixed cadence")
    cpu: list[float] = []
    rss: list[float] = []
    host_cpu: list[float] = []
    steal_cpu: list[float] = []
    residual_cpu: list[float] = []
    inactive_host_cpu: list[float] = []
    previous = -1.0
    for index, raw in enumerate(rows):
        item_label = f"{label}[{index}]"
        item = exact_keys(
            raw,
            {
                "cpu_percent",
                "collector_host_cpu_percent",
                "elapsed_ms",
                "final_sample",
                "host_cpu_percent",
                "inactive_cpa_cpu_percent",
                "mock_cpu_percent",
                "rss_mib",
                "steal_cpu_percent",
            },
            item_label,
        )
        elapsed = finite_number(item["elapsed_ms"], f"{item_label}.elapsed_ms", minimum=0.0)
        final_sample = exact_bool(item["final_sample"], f"{item_label}.final_sample")
        gap = elapsed - previous
        if elapsed > duration_seconds * 1000:
            fail(f"{label} sample timestamp exceeds elapsed_seconds")
        if elapsed <= previous or (previous >= 0 and gap >= interval_ms * 2):
            fail(f"{label} is not monotonic/continuous")
        if previous >= 0 and not final_sample and gap < interval_ms / 2:
            fail(f"{label} violates the minimum fixed-cadence interval")
        if final_sample != (index == len(rows) - 1):
            fail(f"{label} must contain exactly one terminal final sample")
        previous = elapsed
        active_cpu = finite_number(
            item["cpu_percent"], f"{item_label}.cpu_percent", minimum=0.0
        )
        cpu.append(active_cpu)
        rss.append(finite_number(item["rss_mib"], f"{item_label}.rss_mib", minimum=0.0))
        host_value = finite_number(
            item["host_cpu_percent"], f"{item_label}.host_cpu_percent", minimum=0.0
        )
        steal_value = finite_number(
            item["steal_cpu_percent"], f"{item_label}.steal_cpu_percent", minimum=0.0
        )
        if host_value > 100 or steal_value > 100:
            fail(f"{item_label} Host/steal CPU percentage exceeds 100")
        collector_value = finite_number(
            item["collector_host_cpu_percent"],
            f"{item_label}.collector_host_cpu_percent",
            minimum=0.0,
        )
        mock_value = finite_number(
            item["mock_cpu_percent"],
            f"{item_label}.mock_cpu_percent",
            minimum=0.0,
        )
        inactive_value = finite_number(
            item["inactive_cpa_cpu_percent"],
            f"{item_label}.inactive_cpa_cpu_percent",
            minimum=0.0,
        )
        if (
            collector_value > 100
            or active_cpu > logical_cpu_count * 100
            or mock_value > logical_cpu_count * 100
            or inactive_value > logical_cpu_count * 100
        ):
            fail(f"{item_label} target/collector CPU accounting is invalid")
        host_cpu.append(host_value)
        steal_cpu.append(steal_value)
        residual_cpu.append(
            max(
                0.0,
                host_value
                - ((active_cpu + mock_value) / logical_cpu_count)
                - collector_value,
            )
        )
        inactive_host_cpu.append(inactive_value / logical_cpu_count)
    if (
        rows[0]["elapsed_ms"] > interval_ms
        or previous < duration_seconds * 1000 - interval_ms
    ):
        fail(f"{label} does not cover the full measurement interval")
    return rows, cpu, rss, host_cpu, steal_cpu, residual_cpu, inactive_host_cpu


def _validate_queue_samples(
    value: Any,
    label: str,
    arm: str,
    duration_seconds: float,
    interval_ms: int,
) -> tuple[list[dict[str, Any]], int | None, int | None]:
    rows = exact_list(value, label)
    if arm == "cpa_only":
        if rows:
            fail(f"{label} must be empty for CPA-only")
        return rows, None, None
    minimum = math.floor(duration_seconds * 1000 / interval_ms) + 1
    if len(rows) < minimum:
        fail(f"{label} has insufficient audit-queue samples")
    maximum = math.floor(duration_seconds * 1000 / interval_ms) + 2
    if len(rows) > maximum:
        fail(f"{label} has too many samples for the fixed cadence")
    previous = -1.0
    capacities: set[int] = set()
    peak = 0
    for index, raw in enumerate(rows):
        item_label = f"{label}[{index}]"
        item = exact_keys(
            raw, {"capacity", "depth", "elapsed_ms", "final_sample"}, item_label
        )
        elapsed = finite_number(item["elapsed_ms"], f"{item_label}.elapsed_ms", minimum=0.0)
        final_sample = exact_bool(item["final_sample"], f"{item_label}.final_sample")
        gap = elapsed - previous
        if elapsed > duration_seconds * 1000:
            fail(f"{label} sample timestamp exceeds elapsed_seconds")
        if elapsed <= previous or (previous >= 0 and gap >= interval_ms * 2):
            fail(f"{label} is not monotonic/continuous")
        if previous >= 0 and not final_sample and gap < interval_ms / 2:
            fail(f"{label} violates the minimum fixed-cadence interval")
        if final_sample != (index == len(rows) - 1):
            fail(f"{label} must contain exactly one terminal final sample")
        previous = elapsed
        capacity = exact_int(item["capacity"], f"{item_label}.capacity", 1)
        depth = exact_int(item["depth"], f"{item_label}.depth")
        if depth > capacity:
            fail(f"{item_label}.depth exceeds capacity")
        capacities.add(capacity)
        peak = max(peak, depth)
    if (
        len(capacities) != 1
        or rows[0]["elapsed_ms"] > interval_ms
        or previous < duration_seconds * 1000 - interval_ms
    ):
        fail(f"{label} capacity drifted or coverage is incomplete")
    return rows, peak, next(iter(capacities))


def _validate_cell(
    value: Any,
    label: str,
    *,
    phase: str,
    config: Mapping[str, Any],
    workload_map: Mapping[str, Mapping[str, Any]],
    logical_cpu_count: int,
) -> tuple[dict[str, Any], dict[str, Any]]:
    cell = exact_keys(
        value,
        {
            "arm",
            "completed_at",
            "completed_requests",
            "concurrency",
            "elapsed_seconds",
            "infrastructure_errors",
            "latency_samples_ms",
            "mock_counters",
            "order_index",
            "pair_id",
            "phase",
            "planned_requests",
            "queue_samples",
            "repetition",
            "request_set_sha256",
            "resource_samples",
            "runtime",
            "started_at",
            "successful_samples",
            "unexpected_http_errors",
            "warmup_seconds",
            "workload",
        },
        label,
    )
    if cell["phase"] != phase:
        fail(f"{label}.phase is invalid")
    arm = one_of(cell["arm"], ARMS, f"{label}.arm")
    workload = one_of(cell["workload"], ALL_WORKLOADS, f"{label}.workload")
    if phase == "paired_ab" and workload != FIXED_WORKLOAD:
        fail(f"{label} paired A/B cell must use fixed_workload")
    if phase == "absolute" and (arm != "cpa_cag" or workload not in ABSOLUTE_WORKLOADS):
        fail(f"{label} absolute cell arm/workload is invalid")
    concurrency = one_of(cell["concurrency"], CONCURRENCIES, f"{label}.concurrency")
    repetition = exact_int(cell["repetition"], f"{label}.repetition", 1)
    if repetition > config["plan"]["paired_repetitions"]:
        fail(f"{label}.repetition exceeds the plan")
    pair_id = nonempty_string(cell["pair_id"], f"{label}.pair_id", 128)
    if SAFE_PAIR.fullmatch(pair_id) is None:
        fail(f"{label}.pair_id is unsafe")
    order = exact_int(cell["order_index"], f"{label}.order_index")
    if order > 1:
        fail(f"{label}.order_index must be zero or one")
    if exact_int(cell["warmup_seconds"], f"{label}.warmup_seconds") != config["plan"]["warmup_seconds"]:
        fail(f"{label}.warmup_seconds drifted from the plan")
    planned_window = float(config["plan"]["measurement_seconds"])
    elapsed = finite_number(
        cell["elapsed_seconds"],
        f"{label}.elapsed_seconds",
        minimum=planned_window,
    )
    if elapsed > planned_window + MAX_CELL_OVERRUN_SECONDS:
        fail(f"{label}.elapsed_seconds exceeds the planned measurement window")
    _timestamp_order(
        cell["started_at"],
        cell["completed_at"],
        label,
        elapsed_seconds=elapsed,
    )
    planned = exact_int(cell["planned_requests"], f"{label}.planned_requests", config["plan"]["min_success_samples_per_cell"])
    completed = exact_int(cell["completed_requests"], f"{label}.completed_requests")
    success = exact_int(cell["successful_samples"], f"{label}.successful_samples", config["plan"]["min_success_samples_per_cell"])
    if completed > planned or success > completed:
        fail(f"{label} request counts are inconsistent")
    latency_raw = exact_list(cell["latency_samples_ms"], f"{label}.latency_samples_ms", success)
    if len(latency_raw) != success:
        fail(f"{label} successful sample count does not match raw latency samples")
    latencies = [finite_number(item, f"{label}.latency_samples_ms[{index}]", minimum=0.0) for index, item in enumerate(latency_raw)]
    errors = exact_int(cell["unexpected_http_errors"], f"{label}.unexpected_http_errors")
    _, mock_delta = _validate_mock_counters(
        cell["mock_counters"],
        f"{label}.mock_counters",
        expected_status=EXPECTED_STATUS_BY_WORKLOAD[workload][arm],
        successful_samples=success,
    )
    infra = exact_list(cell["infrastructure_errors"], f"{label}.infrastructure_errors")
    for index, item in enumerate(infra):
        nonempty_string(item, f"{label}.infrastructure_errors[{index}]", 256)
    if completed - success > errors:
        fail(f"{label} completed/successful request gap exceeds HTTP errors")
    if planned - completed > len(infra):
        fail(f"{label} planned/completed request gap exceeds infrastructure errors")
    if require_hex(cell["request_set_sha256"], f"{label}.request_set_sha256") != workload_map[workload]["request_set_sha256"]:
        fail(f"{label} workload request-set identity drifted")
    runtime = _validate_runtime(cell["runtime"], f"{label}.runtime", arm, config["identities"])
    (
        _,
        cpu,
        rss,
        host_cpu,
        steal_cpu,
        residual_cpu,
        inactive_host_cpu,
    ) = _validate_resource_samples(
        cell["resource_samples"],
        f"{label}.resource_samples",
        elapsed,
        config["plan"]["resource_sample_interval_ms"],
        logical_cpu_count,
    )
    residual_width = math.ceil(
        BACKGROUND_CPU_ROLLING_SECONDS
        / (config["plan"]["resource_sample_interval_ms"] / 1000.0)
    )
    _, queue_peak, queue_capacity = _validate_queue_samples(
        cell["queue_samples"], f"{label}.queue_samples", arm, elapsed, config["plan"]["queue_sample_interval_ms"]
    )
    summary = {
        "arm": arm,
        "completed_requests": completed,
        "concurrency": concurrency,
        "cpu_peak_percent": max(cpu),
        "cpu_p95_percent": nearest_rank(cpu, 95),
        "elapsed_seconds": elapsed,
        "infrastructure_error_count": len(infra),
        "host_cpu_p95_percent": nearest_rank(host_cpu, 95),
        "host_steal_p95_percent": nearest_rank(steal_cpu, 95),
        "latencies": latencies,
        "inactive_cpa_cpu_p95_percent": nearest_rank(inactive_host_cpu, 95),
        "mock_auth_delta": mock_delta["auth"],
        "mock_mock_delta": mock_delta["mock"],
        "mock_provider_delta": mock_delta["provider"],
        "order_index": order,
        "pair_id": pair_id,
        "phase": phase,
        "queue_capacity": queue_capacity,
        "queue_peak_depth": queue_peak,
        "repetition": repetition,
        "restart_oom_panic": (
            runtime["cpa_restart_count"]
            + runtime["mock_restart_count"]
            + runtime["panic_mentions"]
            + (1 if runtime["cpa_oom_killed"] else 0)
            + (1 if runtime["mock_oom_killed"] else 0)
        ),
        "residual_cpu_p95_percent": nearest_rank(residual_cpu, 95),
        "residual_cpu_rolling_60s_peak_percent": _rolling_mean_peak(
            residual_cpu, residual_width
        ),
        "rss_peak_mib": max(rss),
        "rss_p95_mib": nearest_rank(rss, 95),
        "successful_samples": success,
        "unexpected_http_errors": errors,
        "workload": workload,
    }
    return cell, summary


def _validate_host(value: Any) -> dict[str, Any]:
    host = exact_keys(
        value,
        {"architecture", "boot_id_sha256", "logical_cpu_count", "machine_id_sha256", "platform", "runner_uid"},
        "host performance measurements.host",
    )
    if host["platform"] != "linux" or host["architecture"] not in ("amd64", "x86_64"):
        fail("Host performance measurements require linux/amd64")
    require_hex(host["boot_id_sha256"], "host performance measurements.host.boot_id_sha256")
    require_hex(host["machine_id_sha256"], "host performance measurements.host.machine_id_sha256")
    exact_int(host["logical_cpu_count"], "host performance measurements.host.logical_cpu_count", 1)
    exact_int(host["runner_uid"], "host performance measurements.host.runner_uid", 1)
    return host


def _expected_pair_id(concurrency: int, repetition: int) -> str:
    return f"c{concurrency}-r{repetition}"


def validate_measurements(
    value: Any,
    raw: bytes,
    config: Mapping[str, Any],
    config_raw: bytes,
    workload_manifest: Mapping[str, Any],
) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, Any], dict[str, Any]]:
    measurements = exact_keys(
        value,
        {
            "absolute_cells",
            "baseline_eligibility",
            "candidate_manifest_sha256",
            "collector_tool_identities",
            "completed_at",
            "config_sha256",
            "host",
            "paired_cells",
            "run_config_sha256",
            "schema",
            "started_at",
            "warm_rss",
            "workload_manifest_sha256",
        },
        "host performance measurements",
    )
    del raw
    if measurements["schema"] != MEASUREMENTS_SCHEMA:
        fail("host performance measurements schema is invalid")
    collector_tools = validate_tool_identities(
        measurements["collector_tool_identities"],
        "host performance measurements.collector_tool_identities",
    )
    approved_tools = validate_tool_identities(
        config["approved_tool_identities"],
        "host performance config.approved_tool_identities",
    )
    if collector_tools != approved_tools:
        fail("host performance measurements tool identities drifted from the approved config")
    for key, expected in (
        ("config_sha256", sha256_bytes(config_raw)),
        ("run_config_sha256", config["run_config_sha256"]),
        ("candidate_manifest_sha256", config["candidate_manifest_sha256"]),
        ("workload_manifest_sha256", config["workload_manifest_sha256"]),
    ):
        if require_hex(measurements[key], f"host performance measurements.{key}") != expected:
            fail(f"host performance measurements.{key} drifted")
    _timestamp_order(measurements["started_at"], measurements["completed_at"], "host performance measurements")
    host = _validate_host(measurements["host"])
    _, baseline = _validate_preflight(measurements["baseline_eligibility"])
    workload_map = {item["id"]: item for item in workload_manifest["workloads"]}
    repetitions = config["plan"]["paired_repetitions"]

    paired_raw = exact_list(measurements["paired_cells"], "host performance measurements.paired_cells")
    expected_paired_count = len(ARMS) * len(CONCURRENCIES) * repetitions
    if len(paired_raw) != expected_paired_count:
        fail("host performance measurements paired A/B matrix is incomplete")
    summaries: list[dict[str, Any]] = []
    paired_seen: dict[tuple[int, int, str], dict[str, Any]] = {}
    resource_contracts: set[tuple[int, int, str, str]] = set()
    container_ids: dict[str, set[str]] = {arm: set() for arm in ARMS}
    mock_container_ids: set[str] = set()
    runtime_hashes: dict[str, set[str]] = {arm: set() for arm in ARMS}
    base_config_hashes: set[str] = set()
    docker_comparable_hashes: set[str] = set()
    audit_queue_capacities: set[int] = set()
    security_observations: dict[str, set[tuple[bool, int]]] = {
        "cpa_only": set(),
        "cpa_cag": set(),
        "mock": set(),
    }

    def record_security(arm: str, runtime: Mapping[str, Any]) -> None:
        security = runtime["container_security"]
        cpa = security["cpa"]
        mock = security["mock"]
        security_observations[arm].add(
            (bool(cpa["no_new_privileges"]), int(cpa["pids_limit"]))
        )
        security_observations["mock"].add(
            (bool(mock["no_new_privileges"]), int(mock["pids_limit"]))
        )
    expected_paired_sequence = [
        (concurrency, repetition, arm, order_index)
        for concurrency in CONCURRENCIES
        for repetition in range(1, repetitions + 1)
        for order_index, arm in enumerate(
            paired_order(config["plan"]["seed"], concurrency, repetition)
        )
    ]
    for index, raw_cell in enumerate(paired_raw):
        cell, summary = _validate_cell(
            raw_cell,
            f"host performance measurements.paired_cells[{index}]",
            phase="paired_ab",
            config=config,
            workload_map=workload_map,
            logical_cpu_count=host["logical_cpu_count"],
        )
        key = (summary["concurrency"], summary["repetition"], summary["arm"])
        if key in paired_seen:
            fail("host performance measurements contain a duplicate paired cell")
        expected_id = _expected_pair_id(summary["concurrency"], summary["repetition"])
        expected_order = paired_order(config["plan"]["seed"], summary["concurrency"], summary["repetition"])
        if summary["pair_id"] != expected_id or expected_order[summary["order_index"]] != summary["arm"]:
            fail("host performance paired order/pair identity drifted from the seeded plan")
        if (
            summary["concurrency"],
            summary["repetition"],
            summary["arm"],
            summary["order_index"],
        ) != expected_paired_sequence[index]:
            fail("host performance paired cells are not in the exact seeded execution sequence")
        paired_seen[key] = summary
        runtime = cell["runtime"]
        resource_contracts.add((runtime["nano_cpus"], runtime["cpa_memory_bytes"], runtime["cpuset_cpus"], runtime["mock_image_id"]))
        container_ids[summary["arm"]].add(runtime["cpa_container_id"])
        mock_container_ids.add(runtime["mock_container_id"])
        runtime_hashes[summary["arm"]].add(runtime["runtime_config_sha256"])
        base_config_hashes.add(runtime["cpa_base_config_sha256"])
        docker_comparable_hashes.add(runtime["docker_comparable_sha256"])
        record_security(summary["arm"], runtime)
        if summary["queue_capacity"] is not None:
            audit_queue_capacities.add(int(summary["queue_capacity"]))
        summaries.append(summary)
    expected_paired = {
        (concurrency, repetition, arm)
        for concurrency in CONCURRENCIES
        for repetition in range(1, repetitions + 1)
        for arm in ARMS
    }
    if set(paired_seen) != expected_paired:
        fail("host performance paired A/B matrix has missing or unexpected cells")
    for concurrency in CONCURRENCIES:
        for repetition in range(1, repetitions + 1):
            baseline_elapsed = float(
                paired_seen[(concurrency, repetition, "cpa_only")][
                    "elapsed_seconds"
                ]
            )
            candidate_elapsed = float(
                paired_seen[(concurrency, repetition, "cpa_cag")][
                    "elapsed_seconds"
                ]
            )
            if (
                abs(candidate_elapsed - baseline_elapsed)
                > MAX_PAIRED_WINDOW_DELTA_SECONDS
            ):
                fail(
                    "host performance paired A/B elapsed windows are not comparable"
                )

    absolute_raw = exact_list(measurements["absolute_cells"], "host performance measurements.absolute_cells")
    expected_absolute_count = len(ABSOLUTE_WORKLOADS) * len(CONCURRENCIES) * repetitions
    if len(absolute_raw) != expected_absolute_count:
        fail("host performance measurements absolute workload matrix is incomplete")
    absolute_seen: set[tuple[str, int, int]] = set()
    expected_absolute_sequence = [
        (workload, concurrency, repetition)
        for workload in ABSOLUTE_WORKLOADS
        for concurrency in CONCURRENCIES
        for repetition in range(1, repetitions + 1)
    ]
    for index, raw_cell in enumerate(absolute_raw):
        cell, summary = _validate_cell(
            raw_cell,
            f"host performance measurements.absolute_cells[{index}]",
            phase="absolute",
            config=config,
            workload_map=workload_map,
            logical_cpu_count=host["logical_cpu_count"],
        )
        key = (summary["workload"], summary["concurrency"], summary["repetition"])
        if key in absolute_seen:
            fail("host performance measurements contain a duplicate absolute cell")
        expected_id = f"{summary['workload']}-c{summary['concurrency']}-r{summary['repetition']}"
        if summary["pair_id"] != expected_id or summary["order_index"] != 0:
            fail("host performance absolute cell identity is invalid")
        if key != expected_absolute_sequence[index]:
            fail("host performance absolute cells are not in the exact execution sequence")
        absolute_seen.add(key)
        runtime = cell["runtime"]
        resource_contracts.add((runtime["nano_cpus"], runtime["cpa_memory_bytes"], runtime["cpuset_cpus"], runtime["mock_image_id"]))
        container_ids[summary["arm"]].add(runtime["cpa_container_id"])
        mock_container_ids.add(runtime["mock_container_id"])
        runtime_hashes[summary["arm"]].add(runtime["runtime_config_sha256"])
        base_config_hashes.add(runtime["cpa_base_config_sha256"])
        docker_comparable_hashes.add(runtime["docker_comparable_sha256"])
        record_security(summary["arm"], runtime)
        if summary["queue_capacity"] is not None:
            audit_queue_capacities.add(int(summary["queue_capacity"]))
        summaries.append(summary)
    expected_absolute = {
        (workload, concurrency, repetition)
        for workload in ABSOLUTE_WORKLOADS
        for concurrency in CONCURRENCIES
        for repetition in range(1, repetitions + 1)
    }
    if absolute_seen != expected_absolute:
        fail("host performance absolute workload matrix has missing or unexpected cells")
    if any(len(container_ids[arm]) != 1 for arm in ARMS):
        fail("Host performance cells did not retain one fixed container per A/B arm")
    if container_ids["cpa_only"] == container_ids["cpa_cag"]:
        fail("CPA-only and CPA+CAG measurements used the same container")
    if any(len(runtime_hashes[arm]) != 1 for arm in ARMS):
        fail("Host performance runtime configuration changed within an A/B arm")
    if runtime_hashes["cpa_only"] == runtime_hashes["cpa_cag"]:
        fail("CPA-only and CPA+CAG runtime configuration identities are indistinguishable")
    if len(base_config_hashes) != 1:
        fail("CPA-only and CPA+CAG non-plugin runtime configuration drifted")
    if len(docker_comparable_hashes) != 1:
        fail("CPA-only and CPA+CAG Docker performance configuration drifted")
    if len(mock_container_ids) != 1:
        fail("Host performance cells did not retain one fixed counted-Mock container")
    if len(audit_queue_capacities) != 1:
        fail("CAG audit queue capacity changed across performance cells")
    if len(resource_contracts) != 1:
        fail("Host A/B arms did not use the same CPU/memory/cpuset/Mock contract")

    warm, warm_summary = _validate_warm_rss(
        measurements["warm_rss"],
        config,
        workload_map,
        container_ids,
        host["logical_cpu_count"],
    )
    warm_runtime = warm["runtime"]
    resource_contracts.add(
        (
            warm_runtime["nano_cpus"],
            warm_runtime["cpa_memory_bytes"],
            warm_runtime["cpuset_cpus"],
            warm_runtime["mock_image_id"],
        )
    )
    if len(resource_contracts) != 1:
        fail("warm RSS lane drifted from the Host A/B CPU/memory/cpuset/Mock contract")
    if warm_runtime["runtime_config_sha256"] not in runtime_hashes["cpa_cag"]:
        fail("warm RSS lane runtime configuration drifted from CPA+CAG")
    if warm_runtime["cpa_base_config_sha256"] not in base_config_hashes:
        fail("warm RSS lane non-plugin CPA configuration drifted")
    if warm_runtime["docker_comparable_sha256"] not in docker_comparable_hashes:
        fail("warm RSS lane Docker performance configuration drifted")
    if warm_runtime["mock_container_id"] not in mock_container_ids:
        fail("warm RSS lane did not retain the fixed counted-Mock container")
    record_security("cpa_cag", warm_runtime)
    if any(len(values) != 1 for values in security_observations.values()):
        fail("Host performance container security observations changed during acquisition")
    if security_observations["cpa_only"] != security_observations["cpa_cag"]:
        fail("CPA-only and CPA+CAG container security contracts differ")
    container_security: dict[str, dict[str, Any]] = {}
    for role in ("cpa_only", "cpa_cag", "mock"):
        no_new_privileges, pids_limit = next(iter(security_observations[role]))
        container_security[role] = {
            "no_new_privileges": no_new_privileges,
            "pids_limit": pids_limit,
        }
    measurement_started = timestamp_value(
        measurements["started_at"], "host performance measurements.started_at"
    )
    measurement_completed = timestamp_value(
        measurements["completed_at"], "host performance measurements.completed_at"
    )
    chronological_cells = (
        *(
            (f"paired_cells[{index}]", item)
            for index, item in enumerate(paired_raw)
        ),
        *(
            (f"absolute_cells[{index}]", item)
            for index, item in enumerate(absolute_raw)
        ),
        ("warm_rss", warm),
    )
    previous_completed = None
    for index, (label, raw_cell) in enumerate(chronological_cells):
        started = timestamp_value(raw_cell["started_at"], f"{label}.started_at")
        completed = timestamp_value(raw_cell["completed_at"], f"{label}.completed_at")
        if started < measurement_started or completed > measurement_completed:
            fail(f"{label} timestamps fall outside the Host measurement interval")
        if previous_completed is None:
            required_gap = MIN_PREFLIGHT_SECONDS + config["plan"]["warmup_seconds"]
            gap = (started - measurement_started).total_seconds()
            if gap < required_gap - TIMESTAMP_TOLERANCE_SECONDS:
                fail("Host performance first cell does not follow the full CPU preflight and warmup")
        else:
            if started < previous_completed:
                fail(f"{label} overlaps or precedes the prior Host measurement cell")
            gap = (started - previous_completed).total_seconds()
            if gap < config["plan"]["warmup_seconds"] - TIMESTAMP_TOLERANCE_SECONDS:
                fail(f"{label} does not follow its complete warmup interval")
        previous_completed = completed
    if previous_completed is None or previous_completed > measurement_completed:
        fail("Host performance chronological interval is incomplete")
    summaries.append(warm_summary)
    measurement_host_p95 = max(
        float(item["host_cpu_p95_percent"]) for item in summaries
    )
    measurement_steal_p95 = max(
        float(item["host_steal_p95_percent"]) for item in summaries
    )
    measurement_residual_p95 = max(
        float(item["residual_cpu_p95_percent"]) for item in summaries
    )
    measurement_residual_rolling = max(
        float(item["residual_cpu_rolling_60s_peak_percent"])
        for item in summaries
    )
    measurement_inactive_cpa_p95 = max(
        float(item["inactive_cpa_cpu_p95_percent"]) for item in summaries
    )
    measurement_interference = (
        measurement_host_p95 > MEASUREMENT_HOST_CPU_LIMIT_PERCENT
        or measurement_steal_p95 > STEAL_CPU_LIMIT_PERCENT
        or measurement_residual_p95 > BACKGROUND_CPU_LIMIT_PERCENT
        or measurement_residual_rolling > BACKGROUND_CPU_LIMIT_PERCENT
    )
    baseline["measurement_host_cpu_p95_percent"] = measurement_host_p95
    baseline["measurement_steal_cpu_p95_percent"] = measurement_steal_p95
    baseline["measurement_residual_cpu_p95_percent"] = measurement_residual_p95
    baseline[
        "measurement_residual_cpu_rolling_60s_peak_percent"
    ] = measurement_residual_rolling
    baseline["measurement_inactive_cpa_cpu_p95_percent"] = (
        measurement_inactive_cpa_p95
    )
    baseline["sustained_measurement_cpu_interference"] = measurement_interference
    if measurement_interference:
        baseline["eligible"] = False
        if "sustained_measurement_cpu_interference" not in baseline["reason_codes"]:
            baseline["reason_codes"].append("sustained_measurement_cpu_interference")
        baseline["status"] = "DIAGNOSTIC_NOT_BASELINE"
    return measurements, summaries, baseline, {
        "container_security": container_security,
        "host": host,
        "warm": warm,
    }


def _validate_warm_rss(
    value: Any,
    config: Mapping[str, Any],
    workload_map: Mapping[str, Mapping[str, Any]],
    container_ids: Mapping[str, set[str]],
    logical_cpu_count: int,
) -> tuple[dict[str, Any], dict[str, Any]]:
    label = "host performance measurements.warm_rss"
    warm = exact_keys(
        value,
        {
            "arm",
            "completed_at",
            "concurrency",
            "elapsed_seconds",
            "infrastructure_errors",
            "measurement_window_seconds",
            "mock_counters",
            "request_set_sha256",
            "requests_completed",
            "resource_samples",
            "runtime",
            "started_at",
            "unexpected_http_errors",
            "warmup_seconds",
            "workload",
        },
        label,
    )
    if warm["arm"] != "cpa_cag" or warm["workload"] != FIXED_WORKLOAD or warm["concurrency"] != 16:
        fail("warm RSS lane must be CPA+CAG fixed_workload c=16")
    duration = finite_number(
        warm["elapsed_seconds"], f"{label}.elapsed_seconds", minimum=3600.0
    )
    if duration > 3600.0 + MAX_WARM_DRAIN_SECONDS:
        fail("warm RSS final in-flight batch exceeded the drain bound")
    window = finite_number(
        warm["measurement_window_seconds"],
        f"{label}.measurement_window_seconds",
        minimum=3600.0,
    )
    if window != 3600.0:
        fail("warm RSS measurement_window_seconds must be exactly 3600")
    _timestamp_order(
        warm["started_at"],
        warm["completed_at"],
        label,
        elapsed_seconds=duration,
    )
    if exact_int(warm["warmup_seconds"], f"{label}.warmup_seconds") != config["plan"]["warmup_seconds"]:
        fail("warm RSS warmup_seconds drifted from the plan")
    completed_requests = exact_int(
        warm["requests_completed"],
        f"{label}.requests_completed",
        config["plan"]["min_success_samples_per_cell"],
    )
    _, mock_delta = _validate_mock_counters(
        warm["mock_counters"],
        f"{label}.mock_counters",
        expected_status=EXPECTED_STATUS_BY_WORKLOAD[FIXED_WORKLOAD]["cpa_cag"],
        successful_samples=completed_requests,
    )
    if require_hex(warm["request_set_sha256"], f"{label}.request_set_sha256") != workload_map[FIXED_WORKLOAD]["request_set_sha256"]:
        fail("warm RSS workload identity drifted")
    infra = exact_list(warm["infrastructure_errors"], f"{label}.infrastructure_errors")
    for index, item in enumerate(infra):
        nonempty_string(item, f"{label}.infrastructure_errors[{index}]", 256)
    errors = exact_int(warm["unexpected_http_errors"], f"{label}.unexpected_http_errors")
    runtime = _validate_runtime(warm["runtime"], f"{label}.runtime", "cpa_cag", config["identities"])
    if runtime["cpa_container_id"] not in container_ids["cpa_cag"]:
        fail("warm RSS lane did not use the fixed CPA+CAG container")
    interval = config["plan"]["warm_rss_sample_interval_seconds"]
    minimum_samples = math.floor(3600 / interval) + 1
    samples = exact_list(
        warm["resource_samples"], f"{label}.resource_samples", minimum_samples
    )
    if len(samples) > minimum_samples + 1:
        fail("warm RSS lane has too many samples for the fixed cadence")
    rss: list[tuple[float, float]] = []
    cpu: list[float] = []
    host_cpu: list[float] = []
    steal_cpu: list[float] = []
    residual_cpu: list[float] = []
    inactive_host_cpu: list[float] = []
    previous = -1.0
    for index, raw in enumerate(samples):
        item_label = f"{label}.resource_samples[{index}]"
        item = exact_keys(
            raw,
            {
                "cpu_percent",
                "collector_host_cpu_percent",
                "elapsed_seconds",
                "host_cpu_percent",
                "inactive_cpa_cpu_percent",
                "mock_cpu_percent",
                "rss_mib",
                "steal_cpu_percent",
            },
            item_label,
        )
        elapsed = finite_number(item["elapsed_seconds"], f"{item_label}.elapsed_seconds", minimum=0.0)
        gap = elapsed - previous
        terminal_sample = index == len(samples) - 1
        if elapsed <= previous or (previous >= 0 and gap >= interval * 2):
            fail("warm RSS resource samples are not monotonic/continuous")
        if previous >= 0 and not terminal_sample and gap < interval / 2:
            fail("warm RSS resource samples violate the minimum fixed-cadence interval")
        previous = elapsed
        rss_value = finite_number(item["rss_mib"], f"{item_label}.rss_mib", minimum=0.0)
        active_cpu = finite_number(
            item["cpu_percent"], f"{item_label}.cpu_percent", minimum=0.0
        )
        cpu.append(active_cpu)
        host_value = finite_number(
            item["host_cpu_percent"], f"{item_label}.host_cpu_percent", minimum=0.0
        )
        steal_value = finite_number(
            item["steal_cpu_percent"], f"{item_label}.steal_cpu_percent", minimum=0.0
        )
        if host_value > 100 or steal_value > 100:
            fail(f"{item_label} Host/steal CPU percentage exceeds 100")
        collector_value = finite_number(
            item["collector_host_cpu_percent"],
            f"{item_label}.collector_host_cpu_percent",
            minimum=0.0,
        )
        mock_value = finite_number(
            item["mock_cpu_percent"],
            f"{item_label}.mock_cpu_percent",
            minimum=0.0,
        )
        inactive_value = finite_number(
            item["inactive_cpa_cpu_percent"],
            f"{item_label}.inactive_cpa_cpu_percent",
            minimum=0.0,
        )
        if (
            collector_value > 100
            or active_cpu > logical_cpu_count * 100
            or mock_value > logical_cpu_count * 100
            or inactive_value > logical_cpu_count * 100
        ):
            fail(f"{item_label} target/collector CPU accounting is invalid")
        host_cpu.append(host_value)
        steal_cpu.append(steal_value)
        residual_cpu.append(
            max(
                0.0,
                host_value
                - ((active_cpu + mock_value) / logical_cpu_count)
                - collector_value,
            )
        )
        inactive_host_cpu.append(inactive_value / logical_cpu_count)
        rss.append((elapsed, rss_value))
    if rss[0][0] > interval * 2 or previous < 3600 or previous > 3600 + interval * 2:
        fail("warm RSS samples do not cover 60 minutes")
    first = [value for elapsed, value in rss if elapsed <= 300]
    last = [value for elapsed, value in rss if 3300 <= elapsed <= 3600]
    minimum_window = math.floor(300 / interval)
    if len(first) < minimum_window or len(last) < minimum_window:
        fail("warm RSS first/last five-minute windows are incomplete")
    first_median = float(statistics.median(first))
    last_median = float(statistics.median(last))
    summary = {
        "arm": "cpa_cag",
        "completed_requests": warm["requests_completed"],
        "concurrency": 16,
        "cpu_peak_percent": max(cpu),
        "cpu_p95_percent": nearest_rank(cpu, 95),
        "elapsed_seconds": window,
        "infrastructure_error_count": len(infra),
        "host_cpu_p95_percent": nearest_rank(host_cpu, 95),
        "host_steal_p95_percent": nearest_rank(steal_cpu, 95),
        "latencies": [],
        "inactive_cpa_cpu_p95_percent": nearest_rank(inactive_host_cpu, 95),
        "mock_auth_delta": mock_delta["auth"],
        "mock_mock_delta": mock_delta["mock"],
        "mock_provider_delta": mock_delta["provider"],
        "order_index": 0,
        "pair_id": "warm-rss-60m-c16",
        "phase": "warm_rss",
        "queue_capacity": None,
        "queue_peak_depth": None,
        "repetition": 1,
        "restart_oom_panic": (
            runtime["cpa_restart_count"]
            + runtime["mock_restart_count"]
            + runtime["panic_mentions"]
            + (1 if runtime["cpa_oom_killed"] else 0)
            + (1 if runtime["mock_oom_killed"] else 0)
        ),
        "residual_cpu_p95_percent": nearest_rank(residual_cpu, 95),
        "residual_cpu_rolling_60s_peak_percent": _rolling_mean_peak(
            residual_cpu,
            math.ceil(BACKGROUND_CPU_ROLLING_SECONDS / interval),
        ),
        "rss_first_window_median_mib": first_median,
        "rss_last_window_median_mib": last_median,
        "rss_peak_mib": max(value for _, value in rss),
        "rss_p95_mib": nearest_rank([value for _, value in rss], 95),
        "successful_samples": warm["requests_completed"],
        "unexpected_http_errors": errors,
        "workload": FIXED_WORKLOAD,
    }
    return warm, summary


def _aggregate_cells(summaries: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[tuple[str, str, str, int], list[Mapping[str, Any]]] = {}
    for item in summaries:
        if item["phase"] == "warm_rss":
            continue
        key = (item["phase"], item["arm"], item["workload"], item["concurrency"])
        groups.setdefault(key, []).append(item)
    matrix: list[dict[str, Any]] = []
    for key in sorted(groups):
        phase, arm, workload, concurrency = key
        rows = groups[key]
        latencies = [sample for row in rows for sample in row["latencies"]]
        elapsed = sum(float(row["elapsed_seconds"]) for row in rows)
        successes = sum(int(row["successful_samples"]) for row in rows)
        queue_peaks = [int(row["queue_peak_depth"]) for row in rows if row["queue_peak_depth"] is not None]
        capacities = {int(row["queue_capacity"]) for row in rows if row["queue_capacity"] is not None}
        if arm == "cpa_cag" and len(capacities) != 1:
            fail("aggregated CPA+CAG audit queue capacity is inconsistent")
        capacity = next(iter(capacities)) if capacities else None
        peak = max(queue_peaks) if queue_peaks else None
        matrix.append(
            {
                "arm": arm,
                "concurrency": concurrency,
                "cpu_peak_percent": max(float(row["cpu_peak_percent"]) for row in rows),
                "cpu_p95_percent": max(float(row["cpu_p95_percent"]) for row in rows),
                "latency_p50_ms": nearest_rank(latencies, 50),
                "latency_p95_ms": nearest_rank(latencies, 95),
                "latency_p99_ms": nearest_rank(latencies, 99),
                "mock_auth_delta": sum(int(row["mock_auth_delta"]) for row in rows),
                "mock_mock_delta": sum(int(row["mock_mock_delta"]) for row in rows),
                "mock_provider_delta": sum(int(row["mock_provider_delta"]) for row in rows),
                "phase": phase,
                "audit_queue_capacity": capacity,
                "audit_queue_peak_depth": peak,
                "audit_queue_peak_ratio": (peak / capacity if peak is not None and capacity else None),
                "rss_peak_mib": max(float(row["rss_peak_mib"]) for row in rows),
                "rss_p95_mib": max(float(row["rss_p95_mib"]) for row in rows),
                "sample_count": successes,
                "total_elapsed_seconds": elapsed,
                "throughput_rps": successes / elapsed,
                "workload": workload,
            }
        )
    return matrix


def _metric_gate(metric: str, observed: float) -> dict[str, Any]:
    operator, limit = THRESHOLDS[metric]
    if operator == "<=":
        passed = observed <= limit
    elif operator == "<":
        passed = observed < limit
    elif operator == ">=":
        passed = observed >= limit
    else:
        passed = observed == limit
    return {
        "limit": limit,
        "observed": observed,
        "operator": operator,
        "status": "PASS" if passed else "FAIL",
    }


def build_evidence(
    config: Mapping[str, Any],
    config_raw: bytes,
    measurements: Mapping[str, Any],
    measurements_raw: bytes,
    summaries: Sequence[Mapping[str, Any]],
    baseline: Mapping[str, Any],
    extra: Mapping[str, Any],
) -> dict[str, Any]:
    matrix = _aggregate_cells(summaries)
    lookup = {
        (row["phase"], row["arm"], row["workload"], row["concurrency"]): row
        for row in matrix
    }
    comparisons: list[dict[str, Any]] = []
    for concurrency in CONCURRENCIES:
        baseline_cell = lookup[("paired_ab", "cpa_only", FIXED_WORKLOAD, concurrency)]
        candidate_cell = lookup[("paired_ab", "cpa_cag", FIXED_WORKLOAD, concurrency)]
        if baseline_cell["throughput_rps"] <= 0 or baseline_cell["latency_p99_ms"] <= 0:
            fail("CPA-only baseline throughput and p99 must be positive")
        throughput_ratio = candidate_cell["throughput_rps"] / baseline_cell["throughput_rps"]
        regression = ((candidate_cell["latency_p99_ms"] / baseline_cell["latency_p99_ms"]) - 1.0) * 100.0
        comparisons.append(
            {
                "concurrency": concurrency,
                "cpa_cag_p99_ms": candidate_cell["latency_p99_ms"],
                "cpa_cag_throughput_rps": candidate_cell["throughput_rps"],
                "cpa_only_p99_ms": baseline_cell["latency_p99_ms"],
                "cpa_only_throughput_rps": baseline_cell["throughput_rps"],
                "fixed_workload_p99_regression_percent": regression,
                "host_throughput_vs_cpa_only": throughput_ratio,
            }
        )
    warm_summary = next(item for item in summaries if item["phase"] == "warm_rss")
    candidate_queue_ratios = [row["audit_queue_peak_ratio"] for row in matrix if row["arm"] == "cpa_cag"]
    unexpected = sum(int(item["unexpected_http_errors"]) + int(item["infrastructure_error_count"]) for item in summaries)
    runtime_failures = sum(int(item["restart_oom_panic"]) for item in summaries)
    metrics = {
        "audit_queue_peak_ratio": max(float(value) for value in candidate_queue_ratios if value is not None),
        "five_repository_activation_p95_ms": max(lookup[("absolute", "cpa_cag", "five_repository_activation", c)]["latency_p95_ms"] for c in CONCURRENCIES),
        "fixed_workload_p99_regression_percent": max(item["fixed_workload_p99_regression_percent"] for item in comparisons),
        "host_throughput_vs_cpa_only": min(item["host_throughput_vs_cpa_only"] for item in comparisons),
        "ordinary_p95_ms": max(lookup[("absolute", "cpa_cag", "ordinary", c)]["latency_p95_ms"] for c in CONCURRENCIES),
        "public_p95_ms": max(lookup[("absolute", "cpa_cag", "public", c)]["latency_p95_ms"] for c in CONCURRENCIES),
        "public_p99_ms": max(lookup[("absolute", "cpa_cag", "public", c)]["latency_p99_ms"] for c in CONCURRENCIES),
        "restart_oom_panic": runtime_failures,
        "unexpected_http_or_infra_errors": unexpected,
        "warm_rss_growth_60m_mib": warm_summary["rss_last_window_median_mib"] - warm_summary["rss_first_window_median_mib"],
    }
    gates = {metric: _metric_gate(metric, float(metrics[metric])) for metric in THRESHOLDS}
    thresholds_pass = all(item["status"] == "PASS" for item in gates.values())
    status = "PASS" if thresholds_pass else "FAIL"
    correctness_failed = (
        metrics["unexpected_http_or_infra_errors"] != 0
        or metrics["restart_oom_panic"] != 0
    )
    if not baseline["eligible"] and not correctness_failed and thresholds_pass:
        status = "DIAGNOSTIC_NOT_BASELINE"
    host = extra["host"]
    tools = validate_tool_identities(
        config["approved_tool_identities"],
        "host performance config.approved_tool_identities",
    )
    evidence = {
        "artifacts": {
            "acquire_sha256": tools["acquire_sha256"],
            "audit_contract_sha256": tools["audit_contract_sha256"],
            "bundle_sha256": tools["bundle_sha256"],
            "candidate_manifest_sha256": config["candidate_manifest_sha256"],
            "config_sha256": sha256_bytes(config_raw),
            "host_performance_schema_sha256": tools["host_performance_schema_sha256"],
            "host_performance_source_sha256": tools["host_performance_source_sha256"],
            "measurements_sha256": sha256_bytes(measurements_raw),
            "run_config_sha256": config["run_config_sha256"],
            "run_sha256": tools["run_sha256"],
            "validator_sha256": tools["validator_sha256"],
            "workload_manifest_sha256": config["workload_manifest_sha256"],
        },
        "baseline_eligibility": dict(baseline),
        "claim_boundary": CLAIM_BOUNDARY,
        "comparisons": comparisons,
        "completed_at": measurements["completed_at"],
        "container_security": {
            role: dict(extra["container_security"][role])
            for role in ("cpa_only", "cpa_cag", "mock")
        },
        "gates": gates,
        "identities": {
            "cag": dict(config["identities"]["cag"]),
            "candidate": dict(config["identities"]["candidate"]),
            "cpa": {
                key: config["identities"]["cpa"][key]
                for key in (
                    "binary_path",
                    "binary_sha256",
                    "commit",
                    "image_id",
                    "official_asset_name",
                    "official_asset_sha256",
                    "repo_digest",
                    "tag",
                )
            },
            "host": {
                "architecture": host["architecture"],
                "boot_id_sha256": host["boot_id_sha256"],
                "logical_cpu_count": host["logical_cpu_count"],
                "machine_id_sha256": host["machine_id_sha256"],
                "platform": "linux/amd64",
                "runner_uid": host["runner_uid"],
            },
            "mock": {
                key: config["identities"]["mock"][key]
                for key in ("contract", "image_id", "repo_digest", "source_sha256")
            },
        },
        "matrix": matrix,
        "metrics": metrics,
        "plan": dict(config["plan"]),
        "schema": EVIDENCE_SCHEMA,
        "started_at": measurements["started_at"],
        "status": status,
        "warm_rss_60m": {
            "arm": "cpa_cag",
            "concurrency": 16,
            "duration_seconds": warm_summary["elapsed_seconds"],
            "first_window_median_mib": warm_summary["rss_first_window_median_mib"],
            "last_window_median_mib": warm_summary["rss_last_window_median_mib"],
            "mock_auth_delta": warm_summary["mock_auth_delta"],
            "mock_mock_delta": warm_summary["mock_mock_delta"],
            "mock_provider_delta": warm_summary["mock_provider_delta"],
            "peak_rss_mib": warm_summary["rss_peak_mib"],
            "sample_count": len(extra["warm"]["resource_samples"]),
            "warm_rss_growth_60m_mib": metrics["warm_rss_growth_60m_mib"],
        },
    }
    return evidence


def validate_evidence_bundle(
    evidence: Any,
    config: Mapping[str, Any],
    config_raw: bytes,
    measurements: Mapping[str, Any],
    measurements_raw: bytes,
    summaries: Sequence[Mapping[str, Any]],
    baseline: Mapping[str, Any],
    extra: Mapping[str, Any],
    *,
    require_pass: bool = True,
) -> dict[str, Any]:
    if not isinstance(evidence, dict):
        fail("host performance evidence must be a JSON object")
    require_current_tool_identities(
        config["approved_tool_identities"], "Host performance evidence validation"
    )
    expected = build_evidence(
        config,
        config_raw,
        measurements,
        measurements_raw,
        summaries,
        baseline,
        extra,
    )
    if canonical_bytes(evidence) != canonical_bytes(expected):
        fail("host performance evidence differs from the raw-derived closed result")
    if require_pass and evidence["status"] != "PASS":
        fail(f"host performance evidence status is {evidence['status']}, not PASS")
    require_current_tool_identities(
        config["approved_tool_identities"],
        "Host performance evidence validation completion",
    )
    return evidence


def _parse_size_mib(value: str) -> float:
    match = re.fullmatch(r"\s*([0-9]+(?:\.[0-9]+)?)\s*([KMGT]?i?B)\s*", value)
    if match is None:
        fail("docker stats returned an unknown memory unit")
    number = float(match.group(1))
    unit = match.group(2)
    factors = {
        "B": 1 / (1024 * 1024),
        "KB": 1000 / (1024 * 1024),
        "KiB": 1 / 1024,
        "MB": 1_000_000 / (1024 * 1024),
        "MiB": 1.0,
        "GB": 1_000_000_000 / (1024 * 1024),
        "GiB": 1024.0,
        "TB": 1_000_000_000_000 / (1024 * 1024),
        "TiB": 1024.0 * 1024.0,
    }
    if unit not in factors:
        fail("docker stats returned an unsupported memory unit")
    return number * factors[unit]


def _proc_cpu_values(raw: str) -> tuple[int, int, int]:
    first = raw.splitlines()[0].split() if raw.splitlines() else []
    if len(first) < 9 or first[0] != "cpu":
        fail("/proc/stat does not expose the aggregate CPU counters")
    try:
        values = [int(item) for item in first[1:]]
    except ValueError:
        fail("/proc/stat aggregate CPU counters are invalid")
    # Linux reports guest and guest_nice inside user and nice already.  The
    # aggregate total therefore uses only user..steal (the first eight fields).
    total = sum(values[:8])
    idle = values[3] + (values[4] if len(values) > 4 else 0)
    steal = values[7] if len(values) > 7 else 0
    return total, idle, steal


def _cpu_delta(previous: tuple[int, int, int], current: tuple[int, int, int]) -> tuple[float, float]:
    total = current[0] - previous[0]
    idle = current[1] - previous[1]
    steal = current[2] - previous[2]
    if total <= 0 or idle < 0 or steal < 0 or idle > total or steal > total:
        fail("/proc/stat aggregate CPU counters moved backwards")
    return ((total - idle) * 100.0 / total, steal * 100.0 / total)


def _read_proc_cpu() -> tuple[int, int, int]:
    return _proc_cpu_values(Path("/proc/stat").read_text("ascii"))


def _proc_self_cpu_ticks(raw: str) -> int:
    close = raw.rfind(")")
    fields = raw[close + 1 :].split() if close >= 0 else []
    # fields[0] is state (field 3); utime/stime are fields 14/15.
    if len(fields) < 15:
        fail("/proc/self/stat does not expose process CPU counters")
    try:
        user = int(fields[11])
        system = int(fields[12])
        child_user = int(fields[13])
        child_system = int(fields[14])
    except ValueError:
        fail("/proc/self/stat process CPU counters are invalid")
    if min(user, system, child_user, child_system) < 0:
        fail("/proc/self/stat process CPU counters are negative")
    return user + system + child_user + child_system


def _read_self_cpu_ticks() -> int:
    return _proc_self_cpu_ticks(Path("/proc/self/stat").read_text("ascii"))


def _observed_cpu_delta(
    previous: tuple[int, int, int],
    previous_process_ticks: int,
) -> tuple[float, float, float, tuple[int, int, int], int]:
    current = _read_proc_cpu()
    current_process_ticks = _read_self_cpu_ticks()
    if current[0] == previous[0]:
        # A very fast mocked/real stats read can land inside one kernel tick.
        # Wait for an actual counter delta rather than inventing a zero sample.
        time.sleep(0.01)
        current = _read_proc_cpu()
        current_process_ticks = _read_self_cpu_ticks()
    host_cpu, steal_cpu = _cpu_delta(previous, current)
    process_delta = current_process_ticks - previous_process_ticks
    total_delta = current[0] - previous[0]
    if process_delta < 0 or process_delta > total_delta:
        fail("/proc/self/stat process CPU counters moved backwards or exceed Host time")
    collector_host_cpu = process_delta * 100.0 / total_delta
    return (
        host_cpu,
        steal_cpu,
        collector_host_cpu,
        current,
        current_process_ticks,
    )


def target_names(run_id: str) -> dict[str, str]:
    semantic_run_id = nonempty_string(run_id, "host performance semantic run ID", 128)
    prefix = f"{semantic_run_id}-perf"
    return {
        "cpa_only": f"{prefix}-cpa-only",
        "cpa_cag": f"{prefix}-cpa-cag",
        "mock": f"{prefix}-mock",
        "network": f"{prefix}-net",
    }


def _require_logical_cpu_count() -> int:
    value = os.cpu_count()
    if type(value) is not int or value < 1:
        fail("Linux Host logical CPU count is unavailable or invalid")
    return value


def _require_runtime_secret(value: Any, label: str) -> str:
    if (
        type(value) is not str
        or len(value) < MIN_SECRET_LENGTH
        or any(marker in value for marker in ("\x00", "\r", "\n"))
    ):
        fail(
            f"Host performance {label} must contain at least "
            f"{MIN_SECRET_LENGTH} characters without control-line delimiters"
        )
    return value


class LinuxHostCollector:
    """Acquire raw RT12-06 measurements from three pre-created isolated containers.

    Container creation remains an operator-controlled Host setup step.  This
    collector refuses arbitrary target names: they are derived from run_id and
    must be the only members of the matching internal Docker network.
    """

    def __init__(
        self,
        config: Mapping[str, Any],
        config_raw: bytes,
        workload_manifest: Mapping[str, Any],
        workload_root: Path,
        *,
        collector_tool_identities: Mapping[str, Any],
        client_key: str,
        management_key: str,
        mock_control_token: str,
    ) -> None:
        if platform.system() != "Linux" or platform.machine().lower() not in {"amd64", "x86_64"}:
            fail("Host performance acquisition requires linux/amd64")
        if not hasattr(os, "getuid") or os.getuid() == 0 or os.getgid() == 0:
            fail("Host performance acquisition requires a dedicated non-root UID/GID")
        self.logical_cpu_count = _require_logical_cpu_count()
        client_key = _require_runtime_secret(client_key, "client key")
        management_key = _require_runtime_secret(management_key, "management key")
        mock_control_token = _require_runtime_secret(
            mock_control_token, "Mock control token"
        )
        if len({client_key, management_key, mock_control_token}) != 3:
            fail("Host performance client, management, and Mock control keys must differ")
        approved_tools = validate_tool_identities(
            config["approved_tool_identities"],
            "host performance config.approved_tool_identities",
        )
        collector_tools = validate_tool_identities(
            collector_tool_identities,
            "Host performance collector tool identities",
        )
        if collector_tools != approved_tools:
            fail("Host performance collector tool identities drifted from the approved config")
        require_current_tool_identities(
            approved_tools,
            "Host performance collector run import preflight",
        )
        import run as audit_run

        require_current_tool_identities(
            approved_tools,
            "Host performance collector run import completion",
        )
        self.audit_run = audit_run
        self.docker = audit_run.Docker()
        self.config = config
        self.config_raw = config_raw
        self.collector_tool_identities = approved_tools
        self.workload_manifest = workload_manifest
        self.client_headers = {"Authorization": "Bearer " + client_key}
        self.management_headers = {"Authorization": "Bearer " + management_key}
        self.control_headers = {"Authorization": "Bearer " + mock_control_token}
        # Docker resource names bind to the semantic audit run, not the GitHub run.
        self.semantic_run_id = nonempty_string(
            config["semantic_run_id"], "host performance semantic run ID", 128
        )
        self.prefix = f"{self.semantic_run_id}-perf"
        self.names = target_names(self.semantic_run_id)
        self.urls: dict[str, str] = {}
        self.mock_url = ""
        self.workloads = self._load_workloads(workload_root)
        self.container_infos: dict[str, dict[str, Any]] = {}
        self.container_contracts: dict[str, dict[str, Any]] = {}
        self.mock_info: dict[str, Any] = {}
        self.observed_binary_sha256: dict[str, str] = {}
        self.observed_base_config_sha256: dict[str, str] = {}
        self.observed_docker_comparable_sha256: dict[str, str] = {}
        self.observed_cag_so_sha256 = ""
        self.observed_mock_source_sha256 = ""
        self._verify_environment()

    def _load_workloads(self, root: Path) -> dict[str, list[dict[str, Any]]]:
        if root.is_symlink():
            fail("Host performance workload root must not be a symlink")
        root = root.resolve(strict=True)
        if not root.is_dir():
            fail("Host performance workload root must be a real directory")
        result: dict[str, list[dict[str, Any]]] = {}
        for workload in self.workload_manifest["workloads"]:
            requests: list[dict[str, Any]] = []
            for contract in workload["requests"]:
                cursor = root
                for part in contract["body_path"].split("/"):
                    cursor = cursor / part
                    if cursor.is_symlink():
                        fail("Host performance workload path contains a symlink")
                path = cursor.resolve(strict=True)
                try:
                    path.relative_to(root)
                except ValueError:
                    fail("Host performance workload body escaped its root")
                if path.is_symlink():
                    fail("Host performance workload body is a symlink")
                raw = read_regular_bytes(path, "Host performance workload body", 16 * 1024 * 1024)
                if sha256_bytes(raw) != contract["body_sha256"]:
                    fail("Host performance workload body SHA drifted")
                body = load_json_bytes(raw, "Host performance workload body", 16 * 1024 * 1024)
                if not isinstance(body, dict) or raw != canonical_bytes(body) + b"\n":
                    fail("Host performance workload body must be a canonical JSON object")
                requests.append({"body": raw[:-1], **contract})
            result[workload["id"]] = requests
        return result

    @staticmethod
    def _container_contract(
        info: Mapping[str, Any], expected_image: str, label: str
    ) -> dict[str, Any]:
        config = info.get("Config") or {}
        host = info.get("HostConfig") or {}
        state = info.get("State") or {}
        ports = (info.get("NetworkSettings") or {}).get("Ports") or {}
        container_user = str(config.get("User", ""))
        security_options = host.get("SecurityOpt")
        if not isinstance(security_options, list) or any(
            not isinstance(item, str) for item in security_options
        ):
            fail(f"Host performance {label} container SecurityOpt is invalid")
        no_new_privileges = [
            item
            for item in security_options
            if item.startswith("no-new-privileges")
        ]
        if no_new_privileges != ["no-new-privileges:true"]:
            fail(
                f"Host performance {label} container must enable exactly one "
                "no-new-privileges:true option"
            )
        pids_limit = host.get("PidsLimit")
        if type(pids_limit) is not int or pids_limit <= 0:
            fail(f"Host performance {label} container PidsLimit must be a positive integer")
        if (
            info.get("Image") != expected_image
            or state.get("Running") is not True
            or state.get("Restarting") is True
            or state.get("Dead") is True
            or state.get("OOMKilled") is not False
            or int(info.get("RestartCount") or 0) != 0
            or host.get("ReadonlyRootfs") is not True
            or host.get("Privileged") is not False
            or (host.get("CapDrop") or []) != ["ALL"]
            or (host.get("CapAdd") or []) != []
            or (host.get("RestartPolicy") or {}).get("Name", "") not in ("", "no")
            or host.get("PublishAllPorts") is not False
            or (host.get("PortBindings") or {}) != {}
            or any(item not in (None, []) for item in ports.values())
            or re.fullmatch(r"[1-9][0-9]*:[1-9][0-9]*", container_user) is None
        ):
            fail(f"Host performance {label} container security/runtime contract failed")
        nano_cpus = int(host.get("NanoCpus") or 0)
        memory = int(host.get("Memory") or 0)
        cpuset = str(host.get("CpusetCpus") or "")
        if nano_cpus < 1 or memory < 1 or not cpuset:
            fail(f"Host performance {label} resource contract is incomplete")
        return {
            "cpuset_cpus": cpuset,
            "memory_bytes": memory,
            "nano_cpus": nano_cpus,
            "security": {
                "no_new_privileges": True,
                "pids_limit": pids_limit,
            },
        }

    def _verify_environment(self) -> None:
        self.audit_run.image_identity(self.docker, self.config["identities"]["cpa"], "cpa")
        self.audit_run.image_identity(self.docker, self.config["identities"]["mock"], "mock")
        expected_roles = {
            "cpa_only": "host-perf-cpa-only",
            "cpa_cag": "host-perf-cpa-cag",
            "mock": "host-perf-mock",
        }
        resource_contracts: set[bytes] = set()
        for arm in ARMS:
            info = self.docker.inspect("container", self.names[arm])
            labels = (info.get("Config") or {}).get("Labels") or {}
            if (
                labels.get(self.audit_run.LABEL_KEY) != self.semantic_run_id
                or labels.get(self.audit_run.ROLE_LABEL) != expected_roles[arm]
            ):
                fail(f"Host performance {arm} container labels are not bound")
            contract = self._container_contract(
                info, self.config["identities"]["cpa"]["image_id"], arm
            )
            self.container_contracts[arm] = contract
            resource_contracts.add(canonical_bytes(contract))
            self.observed_docker_comparable_sha256[arm] = sha256_bytes(
                canonical_bytes(_docker_comparable_projection(info))
            )
            self.container_infos[arm] = info
        if len(resource_contracts) != 1:
            fail("CPA-only and CPA+CAG resource limits differ")
        if len(set(self.observed_docker_comparable_sha256.values())) != 1:
            fail("CPA-only and CPA+CAG Docker performance configuration differs")
        mock = self.docker.inspect("container", self.names["mock"])
        mock_labels = (mock.get("Config") or {}).get("Labels") or {}
        if (
            mock_labels.get(self.audit_run.LABEL_KEY) != self.semantic_run_id
            or mock_labels.get(self.audit_run.ROLE_LABEL) != expected_roles["mock"]
        ):
            fail("Host performance Mock container labels are not bound")
        self.container_contracts["mock"] = self._container_contract(
            mock, self.config["identities"]["mock"]["image_id"], "mock"
        )
        mock_config = mock.get("Config") or {}
        if (
            mock_config.get("Entrypoint") != self.audit_run.MOCK_ENTRYPOINT
            or mock_config.get("Cmd") not in (None, [])
        ):
            fail("Host performance Mock container entrypoint drifted")
        self.mock_info = mock
        self._verify_mock_source()

        network = self.docker.inspect("network", self.names["network"])
        members = {
            str(item.get("Name", ""))
            for item in (network.get("Containers") or {}).values()
            if isinstance(item, dict)
        }
        if (
            network.get("Driver") != "bridge"
            or network.get("Internal") is not True
            or network.get("Attachable") is True
            or network.get("Ingress") is True
            or network.get("EnableIPv6") is True
            or (network.get("Labels") or {}).get(self.audit_run.LABEL_KEY) != self.semantic_run_id
            or members != {self.names["cpa_only"], self.names["cpa_cag"], self.names["mock"]}
        ):
            fail("Host performance network is not the exact internal three-member bridge")
        for arm in ARMS:
            info = self.container_infos[arm]
            if (info.get("HostConfig") or {}).get("NetworkMode") != self.names["network"]:
                fail(f"Host performance {arm} escaped the fixed network")
            address = self.audit_run.container_ip(self.docker, self.names[arm], self.names["network"])
            self.urls[arm] = self.audit_run.internal_base(address, self.audit_run.CPA_PORT)
        if (mock.get("HostConfig") or {}).get("NetworkMode") != self.names["network"]:
            fail("Host performance Mock escaped the fixed network")
        mock_address = self.audit_run.container_ip(
            self.docker, self.names["mock"], self.names["network"]
        )
        self.mock_url = self.audit_run.internal_base(
            mock_address, self.audit_run.MOCK_PORT
        )
        health, _, _ = self.audit_run.http_json(self.mock_url, "GET", "/healthz")
        if health != {
            "contract": self.config["identities"]["mock"]["contract"],
            "healthy": True,
            "request_body_retention": False,
        }:
            fail("Host performance counted-Mock health contract failed")

        for arm in ARMS:
            self._verify_binary(arm)
            self.observed_base_config_sha256[arm] = self._verify_cpa_config(arm)
            self._verify_plugin_state(arm)
        if len(set(self.observed_base_config_sha256.values())) != 1:
            fail("CPA-only and CPA+CAG non-plugin runtime configuration differs")
        self._reset_mock()
        self._verify_plugin_bytes()
        self._verify_sampler_timing()

    def _verify_cpa_config(self, arm: str) -> str:
        value, _, _ = self.audit_run.http_json(
            self.urls[arm],
            "GET",
            "/v0/management/config",
            headers=self.management_headers,
        )
        providers = value.get("openai-compatibility") if isinstance(value, dict) else None
        if (
            not isinstance(value, dict)
            or value.get("commercial-mode") is not True
            or value.get("request-log") is not False
            or value.get("logging-to-file") is not False
            or not isinstance(providers, list)
            or len(providers) != 1
            or not isinstance(providers[0], dict)
            or providers[0].get("base-url") != "http://mock:18080/v1"
        ):
            fail(f"Host performance {arm} did not retain the counted-Mock-only CPA config")
        for key in (
            "claude-api-key",
            "codex-api-key",
            "gemini-api-key",
            "interactions-api-key",
            "vertex-api-key",
            "xai-api-key",
        ):
            if value.get(key) not in (None, []):
                fail(f"Host performance {arm} exposes an unexpected Provider config")
        return sha256_bytes(canonical_bytes(_redacted_cpa_config(value)))

    def _verify_mock_source(self) -> None:
        with tempfile.TemporaryDirectory(prefix="cag-host-perf-mock-source-") as directory:
            target = Path(directory) / "counted_mock.py"
            self.docker.run(
                [
                    "cp",
                    f"{self.names['mock']}:{self.audit_run.MOCK_SOURCE_PATH}",
                    str(target),
                ],
                timeout=60,
            )
            observed = sha256_bytes(
                read_regular_bytes(
                    target, "counted-Mock image source", 4 * 1024 * 1024
                )
            )
            if observed != self.config["identities"]["mock"]["source_sha256"]:
                fail("Host performance counted-Mock image source SHA drifted")
            self.observed_mock_source_sha256 = observed

    def _mock_snapshot(self) -> dict[str, int]:
        value, _, _ = self.audit_run.http_json(
            self.mock_url,
            "GET",
            "/__cag/stats",
            headers=self.control_headers,
        )
        if (
            not isinstance(value, dict)
            or set(value) != {"schema", *MOCK_COUNTER_KEYS}
            or value.get("schema") != self.config["identities"]["mock"]["contract"]
        ):
            fail("Host performance counted-Mock stats contract drifted")
        result: dict[str, int] = {}
        for key in MOCK_COUNTER_KEYS:
            counter = value.get(key)
            if type(counter) is not int or counter < 0:
                fail("Host performance counted-Mock counter is invalid")
            result[key] = counter
        return result

    def _reset_mock(self) -> None:
        value, _, _ = self.audit_run.http_json(
            self.mock_url,
            "POST",
            "/__cag/reset",
            headers=self.control_headers,
        )
        expected = {
            "schema": self.config["identities"]["mock"]["contract"],
            **{key: 0 for key in MOCK_COUNTER_KEYS},
        }
        if value != expected or self._mock_snapshot() != {
            key: 0 for key in MOCK_COUNTER_KEYS
        }:
            fail("Host performance counted-Mock reset did not reach zero")

    def _verify_binary(self, arm: str) -> None:
        with tempfile.TemporaryDirectory(prefix="cag-host-perf-binary-") as directory:
            target = Path(directory) / "cpa-binary"
            self.docker.run(
                ["cp", f"{self.names[arm]}:{self.config['identities']['cpa']['binary_path']}", str(target)],
                timeout=60,
            )
            observed = sha256_bytes(
                read_regular_bytes(target, "CPA image binary", 512 * 1024 * 1024)
            )
            if observed != self.config["identities"]["cpa"]["binary_sha256"]:
                fail(f"Host performance {arm} CPA binary SHA drifted")
            self.observed_binary_sha256[arm] = observed

    def _plugins(self, arm: str) -> tuple[dict[str, Any], Mapping[str, str]]:
        value, headers, _ = self.audit_run.http_json(
            self.urls[arm], "GET", "/v0/management/plugins", headers=self.management_headers
        )
        if not isinstance(value, dict) or not isinstance(value.get("plugins"), list):
            fail(f"Host performance {arm} plugin listing is invalid")
        cpa = self.config["identities"]["cpa"]
        version = str(headers.get("x-cpa-version", "")).lstrip("v")
        commit = str(headers.get("x-cpa-commit", "")).lower()
        if version != cpa["tag"].lstrip("v") or not (7 <= len(commit) <= 40 and cpa["commit"].startswith(commit)):
            fail(f"Host performance {arm} CPA response identity drifted")
        return value, headers

    def _verify_plugin_state(self, arm: str) -> tuple[bool, int]:
        plugins, _ = self._plugins(arm)
        matches = [
            item
            for item in plugins["plugins"]
            if isinstance(item, dict) and item.get("id") == "cyber-abuse-guard"
        ]
        if arm == "cpa_only":
            if matches or plugins["plugins"]:
                fail("CPA-only performance arm exposes CAG")
            return False, 0
        if len(matches) != 1 or len(plugins["plugins"]) != 1 or not all(
            matches[0].get(key) is True
            for key in ("registered", "configured", "effective_enabled")
        ):
            fail("CPA+CAG performance arm did not load exactly one effective CAG")
        status, _, _ = self.audit_run.http_json(
            self.urls[arm],
            "GET",
            "/v0/management/plugins/cyber-abuse-guard/status",
            headers=self.management_headers,
        )
        audit = status.get("audit") if isinstance(status, dict) else None
        if (
            not isinstance(status, dict)
            or status.get("commit") != self.config["identities"]["cag"]["commit"]
            or status.get("dirty") is not False
            or status.get("enabled") is not True
            or status.get("enforcement_ready") is not True
            or status.get("operational_ready") is not True
            or not isinstance(audit, dict)
            or audit.get("healthy") is not True
            or audit.get("degraded") is not False
            or audit.get("schema_version") != 6
            or audit.get("persistence_verified") is not True
            or type(audit.get("queue_depth")) is not int
            or type(audit.get("queue_capacity")) is not int
            or audit["queue_capacity"] < 1
        ):
            fail("CPA+CAG performance arm readiness/audit-queue contract failed")
        return True, 1

    def _verify_plugin_bytes(self) -> None:
        artifact_name = self.config["identities"]["candidate"]["artifact_name"]
        with tempfile.TemporaryDirectory(prefix="cag-host-perf-so-") as directory:
            root = Path(directory)
            baseline_root = root / "baseline-plugins"
            baseline = self.docker.run(
                ["cp", f"{self.names['cpa_only']}:/cag/plugins", str(baseline_root)],
                timeout=60,
                check=False,
            )
            if baseline.returncode == 0:
                baseline_entries = list(baseline_root.rglob("*"))
                if any(path.is_file() or path.is_symlink() for path in baseline_entries):
                    fail("CPA-only performance arm contains plugin bytes")
            else:
                diagnostic = (baseline.stdout + baseline.stderr).lower()
                if "no such" not in diagnostic and "could not find" not in diagnostic:
                    fail("CPA-only plugin directory could not be verified")
            candidate_root = root / "candidate-plugins"
            self.docker.run(
                ["cp", f"{self.names['cpa_cag']}:/cag/plugins", str(candidate_root)],
                timeout=60,
            )
            entries = list(candidate_root.rglob("*"))
            if any(path.is_symlink() for path in entries):
                fail("CPA+CAG plugin directory contains a symlink")
            files = [path for path in entries if path.is_file()]
            expected = candidate_root / "linux" / "amd64" / artifact_name
            if files != [expected]:
                fail("CPA+CAG plugin directory is not the exact one-SO set")
            observed = sha256_bytes(
                read_regular_bytes(expected, "loaded CAG SO", 512 * 1024 * 1024)
            )
            if observed != self.config["identities"]["cag"]["so_sha256"]:
                fail("CPA+CAG performance arm loaded the wrong SO bytes")
            self.observed_cag_so_sha256 = observed

    def _queue_snapshot(self) -> tuple[int, int]:
        status, _, _ = self.audit_run.http_json(
            self.urls["cpa_cag"],
            "GET",
            "/v0/management/plugins/cyber-abuse-guard/status",
            headers=self.management_headers,
        )
        audit = status.get("audit") if isinstance(status, dict) else None
        if not isinstance(audit, dict):
            fail("CAG audit status is unavailable during queue sampling")
        depth = audit.get("queue_depth")
        capacity = audit.get("queue_capacity")
        if (
            audit.get("healthy") is not True
            or audit.get("degraded") is not False
            or type(depth) is not int
            or type(capacity) is not int
            or capacity < 1
            or depth < 0
            or depth > capacity
        ):
            fail("CAG audit queue sample is invalid")
        return depth, capacity

    def _verify_sampler_timing(self) -> None:
        resource_limit = self.config["plan"]["resource_sample_interval_ms"] / 1000.0
        queue_limit = self.config["plan"]["queue_sample_interval_ms"] / 1000.0
        for _ in range(SAMPLER_TIMING_PREFLIGHT_SAMPLES):
            started = time.monotonic()
            self._docker_stats("cpa_cag")
            if time.monotonic() - started >= resource_limit:
                fail("Host performance docker stats cannot sustain the fixed sample interval")
            started = time.monotonic()
            self._queue_snapshot()
            if time.monotonic() - started >= queue_limit:
                fail("Host performance queue polling cannot sustain the fixed sample interval")

    def _docker_stats(self, arm: str) -> tuple[float, float, float, float]:
        target_names = [self.names["cpa_only"], self.names["cpa_cag"], self.names["mock"]]
        result = self.docker.run(
            ["stats", "--no-stream", "--format", "{{json .}}", *target_names],
            timeout=30,
        )
        rows: dict[str, tuple[float, float]] = {}
        expected_ids = {
            self.names["cpa_only"]: str(self.container_infos["cpa_only"].get("Id", "")),
            self.names["cpa_cag"]: str(self.container_infos["cpa_cag"].get("Id", "")),
            self.names["mock"]: str(self.mock_info.get("Id", "")),
        }
        for raw_line in result.stdout.splitlines():
            if not raw_line.strip():
                continue
            try:
                value = json.loads(raw_line)
            except json.JSONDecodeError:
                fail("docker stats returned invalid JSON")
            if not isinstance(value, dict):
                fail("docker stats returned an invalid object")
            stats_name = str(value.get("Name", ""))
            stats_id = str(value.get("ID", ""))
            expected_id = expected_ids.get(stats_name, "")
            if (
                stats_name in rows
                or not expected_id
                or not stats_id
                or not expected_id.startswith(stats_id)
            ):
                fail("docker stats returned the wrong container identity")
            cpu_text = str(value.get("CPUPerc", ""))
            memory_text = str(value.get("MemUsage", "")).split("/", 1)[0]
            if not cpu_text.endswith("%"):
                fail("docker stats CPU percentage is invalid")
            try:
                cpu = float(cpu_text[:-1].strip())
            except ValueError:
                fail("docker stats CPU percentage is invalid")
            if not math.isfinite(cpu) or cpu < 0:
                fail("docker stats CPU percentage is invalid")
            rows[stats_name] = (cpu, _parse_size_mib(memory_text))
        if set(rows) != set(target_names):
            fail("docker stats did not return the exact three-container target set")
        active_cpu, active_rss = rows[self.names[arm]]
        inactive_arm = "cpa_cag" if arm == "cpa_only" else "cpa_only"
        mock_cpu = rows[self.names["mock"]][0]
        inactive_cpu = rows[self.names[inactive_arm]][0]
        return active_cpu, active_rss, mock_cpu, inactive_cpu

    def _verify_mock_runtime(self) -> tuple[dict[str, Any], dict[str, Any]]:
        info = self.docker.inspect("container", self.names["mock"])
        if not self.mock_info.get("Id") or info.get("Id") != self.mock_info.get("Id"):
            fail("Host performance counted-Mock container identity changed")
        contract = self._container_contract(
            info, self.config["identities"]["mock"]["image_id"], "mock"
        )
        if contract != self.container_contracts.get("mock"):
            fail("Host performance counted-Mock resource/security contract changed")
        mock_config = info.get("Config") or {}
        if (
            mock_config.get("Entrypoint") != self.audit_run.MOCK_ENTRYPOINT
            or mock_config.get("Cmd") not in (None, [])
        ):
            fail("Host performance counted-Mock entrypoint changed")
        labels = (info.get("Config") or {}).get("Labels") or {}
        if (
            labels.get(self.audit_run.LABEL_KEY) != self.semantic_run_id
            or labels.get(self.audit_run.ROLE_LABEL) != "host-perf-mock"
            or (info.get("HostConfig") or {}).get("NetworkMode")
            != self.names["network"]
        ):
            fail("Host performance counted-Mock runtime binding drifted")
        network = self.docker.inspect("network", self.names["network"])
        members = {
            str(item.get("Name", ""))
            for item in (network.get("Containers") or {}).values()
            if isinstance(item, dict)
        }
        if members != {
            self.names["cpa_only"],
            self.names["cpa_cag"],
            self.names["mock"],
        }:
            fail("Host performance network membership changed during acquisition")
        health, _, _ = self.audit_run.http_json(self.mock_url, "GET", "/healthz")
        if health != {
            "contract": self.config["identities"]["mock"]["contract"],
            "healthy": True,
            "request_body_retention": False,
        }:
            fail("Host performance counted-Mock health drifted during acquisition")
        return info, contract

    def _verify_arm_configuration(
        self, arm: str
    ) -> tuple[dict[str, Any], str, dict[str, Any]]:
        info = self.docker.inspect("container", self.names[arm])
        if info.get("Id") != self.container_infos[arm].get("Id"):
            fail(f"Host performance {arm} container identity changed")
        contract = self._container_contract(
            info, self.config["identities"]["cpa"]["image_id"], arm
        )
        if contract != self.container_contracts.get(arm):
            fail(f"Host performance {arm} resource/security contract changed")
        observed_docker_comparable = sha256_bytes(
            canonical_bytes(_docker_comparable_projection(info))
        )
        if (
            observed_docker_comparable
            != self.observed_docker_comparable_sha256[arm]
        ):
            fail(f"Host performance {arm} Docker performance configuration changed")
        observed_base_config = self._verify_cpa_config(arm)
        if observed_base_config != self.observed_base_config_sha256[arm]:
            fail(f"Host performance {arm} non-plugin CPA configuration changed")
        return info, observed_docker_comparable, contract

    def _runtime(self, arm: str) -> dict[str, Any]:
        info, observed_docker_comparable, cpa_contract = (
            self._verify_arm_configuration(arm)
        )
        host = info.get("HostConfig") or {}
        state = info.get("State") or {}
        mock_info, mock_contract = self._verify_mock_runtime()
        mock_state = mock_info.get("State") or {}
        loaded, count = self._verify_plugin_state(arm)
        logs = self.docker.run(["logs", self.names[arm]], timeout=30, check=False)
        if logs.returncode != 0:
            fail(f"Host performance {arm} logs are unavailable")
        safe_runtime = {
            "arm": arm,
            "cag_loaded": loaded,
            "container_security": {
                "cpa": dict(cpa_contract["security"]),
                "mock": dict(mock_contract["security"]),
            },
            "cpa_base_config_sha256": self.observed_base_config_sha256[arm],
            "command": (info.get("Config") or {}).get("Cmd") or [],
            "cpuset_cpus": str(host.get("CpusetCpus") or ""),
            "docker_comparable_sha256": observed_docker_comparable,
            "image_id": str(info.get("Image") or ""),
            "memory": int(host.get("Memory") or 0),
            "mounts": sorted(
                [
                    {
                        "destination": str(item.get("Destination", "")),
                        "read_only": item.get("RW") is False,
                        "type": str(item.get("Type", "")),
                    }
                    for item in (info.get("Mounts") or [])
                    if isinstance(item, dict)
                ],
                key=lambda item: (item["destination"], item["type"]),
            ),
            "nano_cpus": int(host.get("NanoCpus") or 0),
            "network_mode": str(host.get("NetworkMode") or ""),
            "mock_container_id": str(mock_info.get("Id") or ""),
            "mock_image_id": str(mock_info.get("Image") or ""),
            "mock_source_sha256": self.observed_mock_source_sha256,
            "selected_cag_so_sha256": (
                self.observed_cag_so_sha256 if loaded else None
            ),
        }
        log_text = logs.stdout + logs.stderr
        return {
            "cag_loaded": loaded,
            "container_security": {
                "cpa": dict(cpa_contract["security"]),
                "mock": dict(mock_contract["security"]),
            },
            "cpa_base_config_sha256": self.observed_base_config_sha256[arm],
            "cpa_binary_sha256": self.observed_binary_sha256[arm],
            "cpa_container_id": str(info.get("Id", "")),
            "cpa_image_id": str(info.get("Image", "")),
            "cpa_memory_bytes": int(host.get("Memory") or 0),
            "cpa_oom_killed": state.get("OOMKilled") is True,
            "cpa_restart_count": int(info.get("RestartCount") or 0),
            "cpuset_cpus": str(host.get("CpusetCpus") or ""),
            "docker_comparable_sha256": observed_docker_comparable,
            "loaded_cag_so_sha256": self.observed_cag_so_sha256 if loaded else None,
            "mock_container_id": str(mock_info.get("Id") or ""),
            "mock_image_id": str(mock_info.get("Image") or ""),
            "mock_oom_killed": mock_state.get("OOMKilled") is True,
            "mock_restart_count": int(mock_info.get("RestartCount") or 0),
            "mock_source_sha256": self.observed_mock_source_sha256,
            "nano_cpus": int(host.get("NanoCpus") or 0),
            "panic_mentions": len(re.findall(r"(?i)\bpanic\b", log_text)),
            "plugin_count": count,
            "runtime_config_sha256": sha256_bytes(canonical_bytes(safe_runtime)),
        }

    def _request_once(self, arm: str, request: Mapping[str, Any]) -> tuple[bool, bool, float, str | None]:
        try:
            status, body, _, latency = self.audit_run.http_request(
                self.urls[arm],
                "POST",
                request["endpoint"],
                request["body"],
                self.client_headers,
            )
            body = b""
            expected = request["expected_status_by_arm"][arm]
            return status == expected, status != expected, float(latency), None
        except (self.audit_run.AuditFailure, OSError) as exc:
            return False, False, 0.0, type(exc).__name__

    def _drive_batch(
        self,
        executor: concurrent.futures.ThreadPoolExecutor,
        arm: str,
        requests: Sequence[Mapping[str, Any]],
        concurrency: int,
        offset: int,
    ) -> list[tuple[bool, bool, float, str | None]]:
        barrier = threading.Barrier(concurrency)

        def invoke(request: Mapping[str, Any]) -> tuple[bool, bool, float, str | None]:
            try:
                barrier.wait(timeout=10)
            except threading.BrokenBarrierError:
                return False, False, 0.0, "BrokenBarrierError"
            return self._request_once(arm, request)

        futures = [
            executor.submit(invoke, requests[(offset + index) % len(requests)])
            for index in range(concurrency)
        ]
        results: list[tuple[bool, bool, float, str | None]] = []
        for future in futures:
            try:
                results.append(future.result(timeout=120))
            except concurrent.futures.TimeoutError:
                fail("Host performance HTTP worker exceeded its timeout")
            except Exception as exc:
                results.append((False, False, 0.0, type(exc).__name__))
        return results

    def _sample_loop(
        self,
        arm: str,
        started: float,
        stop: threading.Event,
        resources: list[dict[str, Any]],
        queues: list[dict[str, Any]],
        errors: list[str],
        cpu_state: list[tuple[int, int, int]],
        process_cpu_state: list[int],
        *,
        warm: bool,
    ) -> None:
        resource_interval = (
            self.config["plan"]["warm_rss_sample_interval_seconds"]
            if warm
            else self.config["plan"]["resource_sample_interval_ms"] / 1000.0
        )
        next_resource = started
        del queues
        while not stop.is_set():
            now = time.monotonic()
            if now >= next_resource:
                try:
                    cpu, rss, mock_cpu, inactive_cpu = self._docker_stats(arm)
                    (
                        host_cpu,
                        steal_cpu,
                        collector_cpu,
                        current_cpu,
                        current_process_cpu,
                    ) = _observed_cpu_delta(cpu_state[0], process_cpu_state[0])
                    cpu_state[0] = current_cpu
                    process_cpu_state[0] = current_process_cpu
                    elapsed = max(0.0, time.monotonic() - started)
                    if warm:
                        resources.append(
                            {
                                "cpu_percent": cpu,
                                "collector_host_cpu_percent": collector_cpu,
                                "elapsed_seconds": elapsed,
                                "host_cpu_percent": host_cpu,
                                "inactive_cpa_cpu_percent": inactive_cpu,
                                "mock_cpu_percent": mock_cpu,
                                "rss_mib": rss,
                                "steal_cpu_percent": steal_cpu,
                            }
                        )
                    else:
                        resources.append(
                            {
                                "cpu_percent": cpu,
                                "collector_host_cpu_percent": collector_cpu,
                                "elapsed_ms": elapsed * 1000.0,
                                "final_sample": False,
                                "host_cpu_percent": host_cpu,
                                "inactive_cpa_cpu_percent": inactive_cpu,
                                "mock_cpu_percent": mock_cpu,
                                "rss_mib": rss,
                                "steal_cpu_percent": steal_cpu,
                            }
                        )
                except Exception as exc:
                    errors.append("resource_sample:" + type(exc).__name__)
                    stop.set()
                    return
                next_resource += resource_interval
                if time.monotonic() >= next_resource:
                    errors.append("resource_sample:MissedDeadline")
                    stop.set()
                    return
                if warm and elapsed >= self.config["plan"]["warm_rss_duration_seconds"]:
                    stop.set()
                    return
            stop.wait(max(0.001, min(0.02, next_resource - time.monotonic())))

    def _queue_loop(
        self,
        started: float,
        stop: threading.Event,
        queues: list[dict[str, Any]],
        errors: list[str],
    ) -> None:
        interval = self.config["plan"]["queue_sample_interval_ms"] / 1000.0
        next_sample = started
        while not stop.is_set():
            now = time.monotonic()
            if now >= next_sample:
                try:
                    depth, capacity = self._queue_snapshot()
                    elapsed = max(0.0, time.monotonic() - started) * 1000.0
                    queues.append(
                        {
                            "capacity": capacity,
                            "depth": depth,
                            "elapsed_ms": elapsed,
                            "final_sample": False,
                        }
                    )
                except Exception as exc:
                    errors.append("queue_sample:" + type(exc).__name__)
                    stop.set()
                    return
                next_sample += interval
                if time.monotonic() >= next_sample:
                    errors.append("queue_sample:MissedDeadline")
                    stop.set()
                    return
            stop.wait(max(0.001, min(0.01, next_sample - time.monotonic())))

    def _append_final_samples(
        self,
        arm: str,
        started: float,
        resources: list[dict[str, Any]],
        queues: list[dict[str, Any]],
        cpu_state: list[tuple[int, int, int]],
        process_cpu_state: list[int],
        *,
        warm: bool,
    ) -> float:
        elapsed = time.monotonic() - started
        if (
            warm
            and resources
            and resources[-1]["elapsed_seconds"]
            >= self.config["plan"]["warm_rss_duration_seconds"]
        ):
            return elapsed
        cpu, rss, mock_cpu, inactive_cpu = self._docker_stats(arm)
        (
            host_cpu,
            steal_cpu,
            collector_cpu,
            current_cpu,
            current_process_cpu,
        ) = _observed_cpu_delta(cpu_state[0], process_cpu_state[0])
        cpu_state[0] = current_cpu
        process_cpu_state[0] = current_process_cpu
        if warm:
            marker = time.monotonic() - started
            if resources and marker <= resources[-1]["elapsed_seconds"]:
                marker = resources[-1]["elapsed_seconds"] + 0.000001
            resources.append(
                {
                    "cpu_percent": cpu,
                    "collector_host_cpu_percent": collector_cpu,
                    "elapsed_seconds": marker,
                    "host_cpu_percent": host_cpu,
                    "inactive_cpa_cpu_percent": inactive_cpu,
                    "mock_cpu_percent": mock_cpu,
                    "rss_mib": rss,
                    "steal_cpu_percent": steal_cpu,
                }
            )
        else:
            marker = (time.monotonic() - started) * 1000.0
            if resources and marker <= resources[-1]["elapsed_ms"]:
                marker = resources[-1]["elapsed_ms"] + 0.001
            resources.append(
                {
                    "cpu_percent": cpu,
                    "collector_host_cpu_percent": collector_cpu,
                    "elapsed_ms": marker,
                    "final_sample": True,
                    "host_cpu_percent": host_cpu,
                    "inactive_cpa_cpu_percent": inactive_cpu,
                    "mock_cpu_percent": mock_cpu,
                    "rss_mib": rss,
                    "steal_cpu_percent": steal_cpu,
                }
            )
            if arm == "cpa_cag":
                depth, capacity = self._queue_snapshot()
                queue_marker = (time.monotonic() - started) * 1000.0
                if queues and queue_marker <= queues[-1]["elapsed_ms"]:
                    queue_marker = queues[-1]["elapsed_ms"] + 0.001
                queues.append(
                    {
                        "capacity": capacity,
                        "depth": depth,
                        "elapsed_ms": queue_marker,
                        "final_sample": True,
                    }
                )
        return elapsed

    def _warmup(self, arm: str, requests: Sequence[Mapping[str, Any]], concurrency: int) -> tuple[int, list[str]]:
        deadline = time.monotonic() + self.config["plan"]["warmup_seconds"]
        unexpected = 0
        infra: list[str] = []
        offset = 0
        with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
            while time.monotonic() < deadline:
                for success, wrong, _, error in self._drive_batch(
                    executor, arm, requests, concurrency, offset
                ):
                    del success
                    unexpected += 1 if wrong else 0
                    if error is not None:
                        infra.append("warmup:" + error)
                offset += concurrency
        return unexpected, infra

    def _measure_cell(
        self,
        arm: str,
        workload: str,
        concurrency: int,
        repetition: int,
        phase: str,
        order_index: int,
    ) -> dict[str, Any]:
        requests = self.workloads[workload]
        self._verify_arm_configuration(arm)
        warmup_unexpected, warmup_infra = self._warmup(arm, requests, concurrency)
        self._reset_mock()
        mock_before = self._mock_snapshot()
        started_at = _now_iso()
        started = time.monotonic()
        resources: list[dict[str, Any]] = []
        queues: list[dict[str, Any]] = []
        sampler_errors: list[str] = []
        cpu_state = [_read_proc_cpu()]
        process_cpu_state = [_read_self_cpu_ticks()]
        resource_stop = threading.Event()
        queue_stop = threading.Event()
        sampler = threading.Thread(
            target=self._sample_loop,
            args=(
                arm,
                started,
                resource_stop,
                resources,
                queues,
                sampler_errors,
                cpu_state,
                process_cpu_state,
            ),
            kwargs={"warm": False},
            daemon=True,
        )
        sampler.start()
        queue_sampler: threading.Thread | None = None
        if arm == "cpa_cag":
            queue_sampler = threading.Thread(
                target=self._queue_loop,
                args=(started, queue_stop, queues, sampler_errors),
                daemon=True,
            )
            queue_sampler.start()
        latencies: list[float] = []
        unexpected = warmup_unexpected
        infra = list(warmup_infra)
        attempts = completed = 0
        offset = 0
        target_seconds = self.config["plan"]["measurement_seconds"]
        minimum = self.config["plan"]["min_success_samples_per_cell"]
        elapsed = 0.0
        completed_at = ""
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
                while time.monotonic() - started < target_seconds:
                    if sampler_errors:
                        fail("Host performance cell sampler failed")
                    batch = self._drive_batch(executor, arm, requests, concurrency, offset)
                    attempts += len(batch)
                    offset += len(batch)
                    for success, wrong, latency, error in batch:
                        if error is not None:
                            infra.append(error)
                            continue
                        completed += 1
                        if wrong:
                            unexpected += 1
                        if success:
                            latencies.append(latency)
        finally:
            resource_stop.set()
            sampler.join(timeout=30)
            if queue_sampler is not None:
                queue_stop.set()
                queue_sampler.join(timeout=30)
        if sampler.is_alive() or (queue_sampler is not None and queue_sampler.is_alive()):
            fail("Host performance sampler thread did not stop")
        self._append_final_samples(
            arm,
            started,
            resources,
            queues,
            cpu_state,
            process_cpu_state,
            warm=False,
        )
        elapsed = time.monotonic() - started
        completed_at = _now_iso()
        infra.extend(sampler_errors)
        if elapsed > target_seconds + MAX_CELL_OVERRUN_SECONDS:
            fail("Host performance cell exceeded its fixed measurement window")
        if len(latencies) < minimum:
            fail(
                "Host performance cell did not reach the minimum successful samples "
                "within its fixed measurement window"
            )
        mock_after = self._mock_snapshot()
        workload_contract = next(item for item in self.workload_manifest["workloads"] if item["id"] == workload)
        pair_id = (
            _expected_pair_id(concurrency, repetition)
            if phase == "paired_ab"
            else f"{workload}-c{concurrency}-r{repetition}"
        )
        return {
            "arm": arm,
            "completed_at": completed_at,
            "completed_requests": completed,
            "concurrency": concurrency,
            "elapsed_seconds": elapsed,
            "infrastructure_errors": infra,
            "latency_samples_ms": latencies,
            "mock_counters": {
                "after": mock_after,
                "before": mock_before,
                "delta": {
                    key: mock_after[key] - mock_before[key]
                    for key in MOCK_COUNTER_KEYS
                },
            },
            "order_index": order_index,
            "pair_id": pair_id,
            "phase": phase,
            "planned_requests": attempts,
            "queue_samples": queues,
            "repetition": repetition,
            "request_set_sha256": workload_contract["request_set_sha256"],
            "resource_samples": resources,
            "runtime": self._runtime(arm),
            "started_at": started_at,
            "successful_samples": len(latencies),
            "unexpected_http_errors": unexpected,
            "warmup_seconds": self.config["plan"]["warmup_seconds"],
            "workload": workload,
        }

    def _measure_warm_rss(self) -> dict[str, Any]:
        arm = "cpa_cag"
        concurrency = 16
        requests = self.workloads[FIXED_WORKLOAD]
        self._verify_arm_configuration(arm)
        warmup_unexpected, warmup_infra = self._warmup(
            arm, requests, concurrency
        )
        self._reset_mock()
        mock_before = self._mock_snapshot()
        started_at = _now_iso()
        started = time.monotonic()
        resources: list[dict[str, Any]] = []
        errors: list[str] = []
        cpu_state = [_read_proc_cpu()]
        process_cpu_state = [_read_self_cpu_ticks()]
        stop = threading.Event()
        sampler = threading.Thread(
            target=self._sample_loop,
            args=(
                arm,
                started,
                stop,
                resources,
                [],
                errors,
                cpu_state,
                process_cpu_state,
            ),
            kwargs={"warm": True},
            daemon=True,
        )
        sampler.start()
        unexpected = warmup_unexpected
        completed = attempts = 0
        infra: list[str] = list(warmup_infra)
        offset = 0
        duration = self.config["plan"]["warm_rss_duration_seconds"]
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
                while time.monotonic() - started < duration:
                    if errors:
                        fail("Host performance warm RSS sampler failed")
                    batch = self._drive_batch(executor, arm, requests, concurrency, offset)
                    attempts += len(batch)
                    offset += len(batch)
                    for success, wrong, _, error in batch:
                        if error is not None:
                            infra.append(error)
                            continue
                        if success:
                            completed += 1
                        if wrong:
                            unexpected += 1
        finally:
            stop.set()
            sampler.join(timeout=30)
        if sampler.is_alive():
            fail("Host performance warm RSS sampler thread did not stop")
        infra.extend(errors)
        self._append_final_samples(
            arm,
            started,
            resources,
            [],
            cpu_state,
            process_cpu_state,
            warm=True,
        )
        mock_after = self._mock_snapshot()
        elapsed = time.monotonic() - started
        completed_at = _now_iso()
        # The fixed measurement window ends at 3,600 seconds.  A final in-flight
        # batch is allowed to drain and its bounded duration remains explicit.
        del attempts
        workload_contract = next(
            item for item in self.workload_manifest["workloads"] if item["id"] == FIXED_WORKLOAD
        )
        return {
            "arm": arm,
            "completed_at": completed_at,
            "concurrency": concurrency,
            "elapsed_seconds": elapsed,
            "infrastructure_errors": infra,
            "measurement_window_seconds": 3600.0,
            "mock_counters": {
                "after": mock_after,
                "before": mock_before,
                "delta": {
                    key: mock_after[key] - mock_before[key]
                    for key in MOCK_COUNTER_KEYS
                },
            },
            "request_set_sha256": workload_contract["request_set_sha256"],
            "requests_completed": completed,
            "resource_samples": resources,
            "runtime": self._runtime(arm),
            "started_at": started_at,
            "unexpected_http_errors": unexpected,
            "warmup_seconds": self.config["plan"]["warmup_seconds"],
            "workload": FIXED_WORKLOAD,
        }

    def _preflight(self) -> dict[str, Any]:
        interval = 1
        count = MIN_PREFLIGHT_SECONDS
        cpu: list[float] = []
        steal: list[float] = []
        previous = _read_proc_cpu()
        for _ in range(count):
            time.sleep(interval)
            current = _read_proc_cpu()
            busy_value, steal_value = _cpu_delta(previous, current)
            cpu.append(busy_value)
            steal.append(steal_value)
            previous = current
        return {
            "background_cpu_percent": cpu,
            "sample_interval_seconds": interval,
            "steal_cpu_percent": steal,
        }

    def _host_identity(self) -> dict[str, Any]:
        machine = read_regular_bytes(Path("/etc/machine-id"), "machine id", 4096).strip()
        boot = read_regular_bytes(Path("/proc/sys/kernel/random/boot_id"), "boot id", 4096).strip()
        if not machine or not boot:
            fail("Linux Host machine/boot identity is unavailable")
        return {
            "architecture": platform.machine().lower(),
            "boot_id_sha256": sha256_bytes(boot),
            "logical_cpu_count": self.logical_cpu_count,
            "machine_id_sha256": sha256_bytes(machine),
            "platform": "linux",
            "runner_uid": os.getuid(),
        }

    def collect(self) -> dict[str, Any]:
        require_current_tool_identities(
            self.collector_tool_identities, "Host performance collect start"
        )
        started_at = _now_iso()
        baseline = self._preflight()
        paired_cells: list[dict[str, Any]] = []
        absolute_cells: list[dict[str, Any]] = []
        repetitions = self.config["plan"]["paired_repetitions"]
        for concurrency in CONCURRENCIES:
            for repetition in range(1, repetitions + 1):
                for order_index, arm in enumerate(
                    paired_order(self.config["plan"]["seed"], concurrency, repetition)
                ):
                    paired_cells.append(
                        self._measure_cell(
                            arm,
                            FIXED_WORKLOAD,
                            concurrency,
                            repetition,
                            "paired_ab",
                            order_index,
                        )
                    )
        for workload in ABSOLUTE_WORKLOADS:
            for concurrency in CONCURRENCIES:
                for repetition in range(1, repetitions + 1):
                    absolute_cells.append(
                        self._measure_cell(
                            "cpa_cag",
                            workload,
                            concurrency,
                            repetition,
                            "absolute",
                            0,
                        )
                    )
        warm_rss = self._measure_warm_rss()
        completed_at = _now_iso()
        require_current_tool_identities(
            self.collector_tool_identities, "Host performance collect completion"
        )
        return {
            "absolute_cells": absolute_cells,
            "baseline_eligibility": baseline,
            "candidate_manifest_sha256": self.config["candidate_manifest_sha256"],
            "collector_tool_identities": dict(self.collector_tool_identities),
            "completed_at": completed_at,
            "config_sha256": sha256_bytes(self.config_raw),
            "host": self._host_identity(),
            "paired_cells": paired_cells,
            "run_config_sha256": self.config["run_config_sha256"],
            "schema": MEASUREMENTS_SCHEMA,
            "started_at": started_at,
            "warm_rss": warm_rss,
            "workload_manifest_sha256": self.config["workload_manifest_sha256"],
        }


def _now_iso() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _write_exclusive(path: Path, value: Any) -> None:
    raw = canonical_bytes(value) + b"\n"
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
    make = commands.add_parser("make-config", help="bind a Host A/B measurement plan")
    collect = commands.add_parser(
        "collect", help="drive the isolated CPA-only/CPA+CAG containers and acquire raw samples"
    )
    summarize = commands.add_parser("summarize", help="derive final evidence from raw Host measurements")
    for command in (make, collect, summarize):
        command.add_argument("--run-config", type=Path, required=True)
        command.add_argument("--candidate-manifest", type=Path, required=True)
        command.add_argument("--workload-manifest", type=Path, required=True)
    make.add_argument("--approved-tool-identities", type=Path, required=True)
    make.add_argument("--output", type=Path, required=True)
    make.add_argument("--seed", type=int, default=1206)
    make.add_argument("--paired-repetitions", type=int, default=3)
    make.add_argument("--warmup-seconds", type=int, default=30)
    make.add_argument("--measurement-seconds", type=int, default=120)
    make.add_argument("--min-success-samples-per-cell", type=int, default=1_000)
    make.add_argument("--resource-sample-interval-ms", type=int, default=1000)
    make.add_argument("--queue-sample-interval-ms", type=int, default=100)
    make.add_argument("--warm-rss-sample-interval-seconds", type=int, default=1)
    collect.add_argument("--config", type=Path, required=True)
    collect.add_argument("--workload-root", type=Path, required=True)
    collect.add_argument("--output", type=Path, required=True)
    summarize.add_argument("--config", type=Path, required=True)
    summarize.add_argument("--measurements", type=Path, required=True)
    summarize.add_argument("--output", type=Path, required=True)
    return root


def _load_bindings(args: argparse.Namespace) -> tuple[
    dict[str, Any], bytes, dict[str, Any], bytes, dict[str, Any], bytes
]:
    run_config, run_raw = _canonical_file(args.run_config, "run config", 2 * 1024 * 1024)
    validate_run_config(run_config)
    candidate_raw = read_regular_bytes(args.candidate_manifest, "candidate manifest", 2 * 1024 * 1024)
    candidate_value = load_json_bytes(candidate_raw, "candidate manifest", 2 * 1024 * 1024)
    candidate = validate_candidate_manifest(candidate_value, run_config["identities"]["cag"])
    workload, workload_raw = _canonical_file(args.workload_manifest, "performance workload manifest", 2 * 1024 * 1024)
    validate_workload_manifest(workload)
    return run_config, run_raw, candidate, candidate_raw, workload, workload_raw


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        stage_tool_identities = tool_identities()
        run_config, run_raw, candidate, candidate_raw, workload, workload_raw = _load_bindings(args)
        if args.command == "make-config":
            approved_tools, _ = _canonical_file(
                args.approved_tool_identities,
                "approved Host performance tool identities",
                64 * 1024,
            )
            config = build_config(
                run_config,
                run_raw,
                candidate,
                candidate_raw,
                workload_raw,
                approved_tool_identities=approved_tools,
                seed=args.seed,
                paired_repetitions=args.paired_repetitions,
                warmup_seconds=args.warmup_seconds,
                measurement_seconds=args.measurement_seconds,
                min_success_samples_per_cell=args.min_success_samples_per_cell,
                resource_sample_interval_ms=args.resource_sample_interval_ms,
                queue_sample_interval_ms=args.queue_sample_interval_ms,
                warm_rss_sample_interval_seconds=args.warm_rss_sample_interval_seconds,
            )
            require_current_tool_identities(
                stage_tool_identities, "Host performance make-config completion"
            )
            _write_exclusive(args.output, config)
            print(json.dumps({"config_sha256": sha256_bytes(canonical_bytes(config) + b"\n"), "valid": True}, sort_keys=True))
            return 0
        config, config_raw = _canonical_file(args.config, "host performance config", 2 * 1024 * 1024)
        validate_config(
            config,
            run_config,
            run_raw,
            candidate,
            candidate_raw,
            workload_raw,
            observed_tool_identities=stage_tool_identities,
        )
        if args.command == "collect":
            collector = LinuxHostCollector(
                config,
                config_raw,
                workload,
                args.workload_root,
                collector_tool_identities=stage_tool_identities,
                client_key=os.environ.get("CAG_HOST_PERF_CLIENT_KEY", ""),
                management_key=os.environ.get("CAG_HOST_PERF_MANAGEMENT_KEY", ""),
                mock_control_token=os.environ.get(
                    "CAG_HOST_PERF_MOCK_CONTROL_TOKEN", ""
                ),
            )
            measurements = collector.collect()
            measurements_raw = canonical_bytes(measurements) + b"\n"
            validate_measurements(
                measurements, measurements_raw, config, config_raw, workload
            )
            require_current_tool_identities(
                stage_tool_identities, "Host performance collect output"
            )
            _write_exclusive(args.output, measurements)
            print(
                json.dumps(
                    {
                        "measurements_sha256": sha256_bytes(measurements_raw),
                        "valid": True,
                    },
                    sort_keys=True,
                )
            )
            return 0
        measurements, measurements_raw = _canonical_file(
            args.measurements, "host performance measurements", 128 * 1024 * 1024
        )
        validated, summaries, baseline, extra = validate_measurements(
            measurements, measurements_raw, config, config_raw, workload
        )
        evidence = build_evidence(
            config, config_raw, validated, measurements_raw, summaries, baseline, extra
        )
        require_current_tool_identities(
            stage_tool_identities, "Host performance summarize completion"
        )
        _write_exclusive(args.output, evidence)
        print(json.dumps({"status": evidence["status"], "valid": evidence["status"] == "PASS"}, sort_keys=True))
        return 0 if evidence["status"] == "PASS" else 2
    except (ContractError, OSError) as exc:
        print(f"HOST PERFORMANCE FAILED: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
