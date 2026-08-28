#!/usr/bin/env python3
"""Pure parser and validator for Round 14 Host admission evidence.

The module deliberately accepts bytes and JSON values only.  It does not read
files, spawn commands, contact a network, start containers, or wait for either
the 300-second or 3600-second gate.  Acquisition stays an operator concern;
this module only decides whether already captured canonical JSON/JSONL closes
the R14-08 evidence contract.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta
from typing import Any, Mapping, NoReturn, Sequence

from audit_contract import (
    AUDIT_SCHEMA_VERSION,
    CAG_SO_NAME,
    CAG_SOURCE_VERSION,
    CPA_C_ABI,
    CPA_COMMIT,
    CPA_OFFICIAL_ASSET_NAME,
    CPA_OFFICIAL_ASSET_SHA256,
    CPA_OFFICIAL_ASSET_SIZE,
    CPA_OFFICIAL_BINARY_SHA256,
    CPA_OFFICIAL_BINARY_SIZE,
    CPA_RPC_SCHEMA,
    CPA_TAG,
    REALTIME_ROUTE_CONTRACT,
    REALTIME_RPC_COUNTER_KEYS,
    SUPPLEMENTAL_ZIP_ARCHIVE_IDENTITY,
    ContractError,
    canonical_bytes,
    exact_bool,
    exact_int,
    exact_keys,
    iter_jsonl_bytes,
    load_json_bytes,
    nonempty_string,
    require_repo_digest,
    require_safe_relative,
    sha256_bytes,
)


SCHEMA = "cag-current-cpa-host-admission-evidence/v1"
SAMPLE_SCHEMA = "cag-current-cpa-host-admission-sample/v1"
REALTIME_ROUTE_SCHEMA = "cag-current-cpa-host-admission-realtime-route/v1"
STATUS = "PASS"
CLAIM_BOUNDARY = (
    "SECOND-MACHINE OWNER HOST ADMISSION; EXACT CANDIDATE AND PROTECTED ROUTES ONLY; "
    "NOT INDEPENDENT ATTESTATION"
)
PLATFORM = "linux/amd64"
STABILITY_BASIS = "DEDICATED_HOST_3600S_WINDOW"
SAMPLE_INTERVAL_MS = 1_000
MIN_SAMPLE_INTERVAL_MS = SAMPLE_INTERVAL_MS // 2
MAX_SAMPLE_INTERVAL_MS = SAMPLE_INTERVAL_MS * 2
MAX_WINDOW_DURATION_FACTOR = 2
WINDOW_SPECS: tuple[tuple[str, int, int], ...] = (
    ("host_300s", 300, 301),
    ("host_3600s", 3_600, 3_601),
)
EXPECTED_SAMPLE_PATHS = {
    "host_300s": "host-admission/host-300s-samples.jsonl",
    "host_3600s": "host-admission/host-3600s-samples.jsonl",
}
EXPECTED_REALTIME_ROUTES_PATH = "host-admission/realtime-auth-boundary-routes.jsonl"
FIXED_REPOSITORIES: tuple[str, ...] = (
    "Jia-Ethan/codex-keysmith",
    "yynxxxxx/Codex-5.5-codex-instruct-5.5",
    "yynxxxxx/Codex-X",
    "MDX-Tom/gpt-5.6-instruct",
    "lingbol088-spec/5.6-JAILBREAK-NERV-codex-instruct-5.6",
)
MOCK_COUNTER_KEYS = ("auth", "mock", "provider")
SIDE_EFFECT_KEYS = (
    "auth",
    "executor",
    "mock",
    "provider",
    "router",
    "sse",
    "usage",
)
MAX_EVIDENCE_BYTES = 4 * 1024 * 1024
MAX_SAMPLE_LINE_BYTES = 32 * 1024

HEX40 = re.compile(r"[0-9a-f]{40}")
HEX64 = re.compile(r"[0-9a-f]{64}")
CONTAINER_ID = re.compile(r"[0-9a-f]{64}")
IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}")
SAFE_ID = re.compile(r"[a-z0-9][a-z0-9_.-]{2,62}")
UTC_MILLISECONDS = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z"
)
UTC_DOCKER = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,9})?Z"
)


class HostAdmissionError(ContractError):
    """The supplied Host admission bundle is not a closed R14-08 PASS."""


def fail(message: str) -> NoReturn:
    raise HostAdmissionError(message)


def _exact_string(value: Any, label: str, maximum: int = 1024) -> str:
    text = nonempty_string(value, label, maximum)
    if type(value) is not str:
        fail(f"{label} must be a JSON string")
    return text


def _exact_digest(
    value: Any, label: str, pattern: re.Pattern[str] = HEX64
) -> str:
    text = _exact_string(value, label, 256)
    if pattern.fullmatch(text) is None or not text.rsplit(":", 1)[-1].strip("0"):
        fail(f"{label} must be a non-zero lowercase digest identity")
    return text


def _parse_timestamp(
    value: Any, label: str, pattern: re.Pattern[str] = UTC_MILLISECONDS
) -> datetime:
    text = _exact_string(value, label, 64)
    if pattern.fullmatch(text) is None:
        fail(f"{label} must be a strict UTC timestamp ending in Z")
    # datetime accepts at most microseconds.  Docker StartedAt may carry nine
    # fractional digits, so retain microseconds for ordering after validating
    # all original digits syntactically.
    normalized = text
    if "." in text:
        prefix, fraction_z = text.split(".", 1)
        fraction = fraction_z[:-1]
        normalized = f"{prefix}.{fraction[:6].ljust(6, '0')}Z"
    try:
        return datetime.fromisoformat(normalized[:-1] + "+00:00")
    except ValueError:
        fail(f"{label} is not a real UTC timestamp")


def _validate_run_id(value: Any, label: str) -> str:
    run_id = _exact_string(value, label, 63)
    if SAFE_ID.fullmatch(run_id) is None:
        fail(f"{label} is not a safe lower-case run identity")
    return run_id


def _validate_rpc_counters(value: Any, label: str) -> dict[str, Any]:
    counters = exact_keys(value, REALTIME_RPC_COUNTER_KEYS, label)
    for key in REALTIME_RPC_COUNTER_KEYS:
        exact_int(counters[key], f"{label}.{key}")
    if counters["rpc_request_complete_errors"] != 0:
        fail(f"{label}.rpc_request_complete_errors must remain zero")
    return counters


def _validate_mock_counters(value: Any, label: str) -> dict[str, Any]:
    counters = exact_keys(value, MOCK_COUNTER_KEYS, label)
    for key in MOCK_COUNTER_KEYS:
        exact_int(counters[key], f"{label}.{key}")
    return counters


def _validate_process_identity(value: Any, label: str) -> dict[str, Any]:
    identity = exact_keys(
        value,
        {
            "container_id",
            "docker_started_at",
            "image_digest",
            "image_id",
            "init_pid",
            "proc_starttime_ticks",
        },
        label,
    )
    _exact_digest(identity["container_id"], f"{label}.container_id", CONTAINER_ID)
    _parse_timestamp(
        identity["docker_started_at"],
        f"{label}.docker_started_at",
        UTC_DOCKER,
    )
    _exact_digest(identity["image_id"], f"{label}.image_id", IMAGE_ID)
    try:
        require_repo_digest(identity["image_digest"], f"{label}.image_digest")
    except ContractError as exc:
        fail(str(exc))
    exact_int(identity["init_pid"], f"{label}.init_pid", 1)
    exact_int(
        identity["proc_starttime_ticks"], f"{label}.proc_starttime_ticks", 1
    )
    return identity


def _validate_runtime_identity(value: Any, label: str) -> dict[str, Any]:
    identities = exact_keys(value, {"cpa", "keeper", "mock"}, label)
    for name in ("cpa", "keeper", "mock"):
        _validate_process_identity(identities[name], f"{label}.{name}")
    container_ids = [identities[name]["container_id"] for name in identities]
    pids = [identities[name]["init_pid"] for name in identities]
    if len(set(container_ids)) != 3 or len(set(pids)) != 3:
        fail(f"{label} must identify three distinct containers and init PIDs")
    return identities


def _validate_candidate(value: Any) -> dict[str, Any]:
    candidate = exact_keys(value, {"artifacts", "cag", "cpa"}, "evidence.candidate")
    cpa = exact_keys(
        candidate["cpa"],
        {
            "c_abi",
            "commit",
            "official_asset_name",
            "official_asset_sha256",
            "official_asset_size",
            "official_binary_sha256",
            "official_binary_size",
            "platform",
            "rpc_schema",
            "tag",
        },
        "evidence.candidate.cpa",
    )
    expected_cpa = {
        "c_abi": CPA_C_ABI,
        "commit": CPA_COMMIT,
        "official_asset_name": CPA_OFFICIAL_ASSET_NAME,
        "official_asset_sha256": CPA_OFFICIAL_ASSET_SHA256,
        "official_asset_size": CPA_OFFICIAL_ASSET_SIZE,
        "official_binary_sha256": CPA_OFFICIAL_BINARY_SHA256,
        "official_binary_size": CPA_OFFICIAL_BINARY_SIZE,
        "platform": PLATFORM,
        "rpc_schema": CPA_RPC_SCHEMA,
        "tag": CPA_TAG,
    }
    for key in ("c_abi", "official_asset_size", "official_binary_size", "rpc_schema"):
        exact_int(cpa[key], f"evidence.candidate.cpa.{key}")
    for key in (
        "commit",
        "official_asset_name",
        "official_asset_sha256",
        "official_binary_sha256",
        "platform",
        "tag",
    ):
        _exact_string(cpa[key], f"evidence.candidate.cpa.{key}", 256)
    if cpa != expected_cpa:
        fail("evidence.candidate.cpa is not the frozen v7.2.144 Linux amd64 identity")

    cag = exact_keys(
        candidate["cag"],
        {
            "commit",
            "so_name",
            "so_sha256",
            "source_version",
            "store_zip_sha256",
            "tree",
        },
        "evidence.candidate.cag",
    )
    if cag["source_version"] != CAG_SOURCE_VERSION or cag["so_name"] != CAG_SO_NAME:
        fail("evidence.candidate.cag source/SO identity drifted")
    _exact_digest(cag["commit"], "evidence.candidate.cag.commit", HEX40)
    _exact_digest(cag["tree"], "evidence.candidate.cag.tree", HEX40)
    _exact_digest(cag["so_sha256"], "evidence.candidate.cag.so_sha256")
    _exact_digest(
        cag["store_zip_sha256"], "evidence.candidate.cag.store_zip_sha256"
    )

    artifacts = exact_keys(
        candidate["artifacts"],
        {
            "candidate_artifact_digest",
            "candidate_manifest_sha256",
            "config_sha256",
            "evidence_manifest_sha256",
        },
        "evidence.candidate.artifacts",
    )
    _exact_digest(
        artifacts["candidate_artifact_digest"],
        "evidence.candidate.artifacts.candidate_artifact_digest",
        IMAGE_ID,
    )
    for key in ("candidate_manifest_sha256", "config_sha256", "evidence_manifest_sha256"):
        _exact_digest(artifacts[key], f"evidence.candidate.artifacts.{key}")
    return candidate


def _validate_endpoint_health(value: Any, label: str) -> None:
    endpoints = exact_keys(value, {"keeper", "root", "unauthorized_models"}, label)
    keeper = exact_keys(endpoints["keeper"], {"path", "state", "status"}, f"{label}.keeper")
    if keeper != {"path": "/keeper/healthz", "state": "healthy", "status": 200}:
        fail(f"{label}.keeper is not healthy HTTP 200")
    root = exact_keys(endpoints["root"], {"path", "status"}, f"{label}.root")
    if root != {"path": "/", "status": 200}:
        fail(f"{label}.root is not HTTP 200")
    models = exact_keys(
        endpoints["unauthorized_models"],
        {"authorization", "path", "status"},
        f"{label}.unauthorized_models",
    )
    if models != {"authorization": "none", "path": "/v1/models", "status": 401}:
        fail(f"{label}.unauthorized_models is not the unauthenticated HTTP 401 probe")


def _validate_failures(value: Any, label: str) -> None:
    failures = exact_keys(
        value,
        {
            "oom_events",
            "panic_events",
            "plugin_errors",
            "real_provider_calls",
            "restarts",
            "unexpected_errors",
        },
        label,
    )
    for key in failures:
        if exact_int(failures[key], f"{label}.{key}") != 0:
            fail(f"{label}.{key} must remain zero")


def _validate_audit_queue(value: Any, label: str) -> dict[str, Any]:
    queue = exact_keys(value, {"capacity", "depth", "errors", "healthy"}, label)
    capacity = exact_int(queue["capacity"], f"{label}.capacity", 1)
    depth = exact_int(queue["depth"], f"{label}.depth")
    if depth >= capacity:
        fail(f"{label}.depth must stay below capacity")
    if exact_int(queue["errors"], f"{label}.errors") != 0:
        fail(f"{label}.errors must remain zero")
    if not exact_bool(queue["healthy"], f"{label}.healthy"):
        fail(f"{label}.healthy must remain true")
    return queue


def _validate_sample(
    value: Any,
    *,
    label: str,
    run_id: str,
    window_name: str,
    ordinal: int,
    runtime_identity: Mapping[str, Any],
) -> dict[str, Any]:
    sample = exact_keys(
        value,
        {
            "audit_queue",
            "endpoints",
            "failures",
            "mock_counters",
            "monotonic_ns",
            "ordinal",
            "rpc_counters",
            "rss_bytes",
            "run_id",
            "runtime_identity",
            "sampled_at",
            "schema",
            "usage_records",
            "window",
        },
        label,
    )
    if sample["schema"] != SAMPLE_SCHEMA:
        fail(f"{label}.schema is not {SAMPLE_SCHEMA}")
    if sample["run_id"] != run_id or sample["window"] != window_name:
        fail(f"{label} run/window identity drifted")
    if exact_int(sample["ordinal"], f"{label}.ordinal", 1) != ordinal:
        fail(f"{label}.ordinal is not the consecutive 1-based ordinal")
    _parse_timestamp(sample["sampled_at"], f"{label}.sampled_at")
    exact_int(sample["monotonic_ns"], f"{label}.monotonic_ns", 1)
    exact_int(sample["rss_bytes"], f"{label}.rss_bytes", 1)
    exact_int(sample["usage_records"], f"{label}.usage_records")
    _validate_endpoint_health(sample["endpoints"], f"{label}.endpoints")
    _validate_failures(sample["failures"], f"{label}.failures")
    _validate_audit_queue(sample["audit_queue"], f"{label}.audit_queue")
    _validate_rpc_counters(sample["rpc_counters"], f"{label}.rpc_counters")
    _validate_mock_counters(sample["mock_counters"], f"{label}.mock_counters")
    observed_identity = _validate_runtime_identity(
        sample["runtime_identity"], f"{label}.runtime_identity"
    )
    if observed_identity != runtime_identity:
        fail(f"{label}.runtime_identity drifted from the frozen Host identity")
    return sample


def _counter_delta(
    first: Mapping[str, Any], last: Mapping[str, Any], keys: Sequence[str], label: str
) -> dict[str, int]:
    result: dict[str, int] = {}
    for key in keys:
        delta = last[key] - first[key]
        if delta < 0:
            fail(f"{label}.{key} went backwards")
        result[key] = delta
    return result


def _validate_probe(value: Any, label: str, *, blocked: bool) -> dict[str, Any]:
    probe = exact_keys(
        value,
        {
            "actual_action",
            "executions",
            "expected_action",
            "http_status",
            "passed",
            "side_effect_deltas",
        },
        label,
    )
    executions = exact_int(probe["executions"], f"{label}.executions", 1)
    if exact_int(probe["passed"], f"{label}.passed", 1) != executions:
        fail(f"{label} did not pass every representative execution")
    expected_action = "block_malicious_text" if blocked else "allow"
    expected_status = 403 if blocked else 200
    if (
        probe["expected_action"] != expected_action
        or probe["actual_action"] != expected_action
        or probe["http_status"] != expected_status
    ):
        fail(f"{label} action/status does not match the representative probe")
    side = exact_keys(probe["side_effect_deltas"], SIDE_EFFECT_KEYS, f"{label}.side_effect_deltas")
    for key in SIDE_EFFECT_KEYS:
        exact_int(side[key], f"{label}.side_effect_deltas.{key}")
    expected_side = (
        {key: 0 for key in SIDE_EFFECT_KEYS}
        if blocked
        else {
            "auth": executions,
            "executor": executions,
            "mock": executions,
            "provider": executions,
            "router": executions,
            "sse": 0,
            "usage": executions,
        }
    )
    if side != expected_side:
        fail(f"{label} violates the exact allow/block side-effect contract")
    return probe


def _validate_window_summary(
    value: Any,
    *,
    expected_name: str,
    expected_duration: int,
    expected_count: int,
) -> dict[str, Any]:
    label = f"evidence.windows.{expected_name}"
    window = exact_keys(
        value,
        {
            "duration_seconds",
            "ended_at",
            "ended_monotonic_ns",
            "name",
            "representative_probes",
            "sample_count",
            "sample_interval_ms",
            "samples_path",
            "samples_sha256",
            "started_at",
            "started_monotonic_ns",
        },
        label,
    )
    if window["name"] != expected_name:
        fail(f"{label}.name is not {expected_name}")
    if exact_int(window["duration_seconds"], f"{label}.duration_seconds") != expected_duration:
        fail(f"{label}.duration_seconds is not exact")
    if exact_int(window["sample_count"], f"{label}.sample_count") != expected_count:
        fail(f"{label}.sample_count is not exact")
    if exact_int(window["sample_interval_ms"], f"{label}.sample_interval_ms") != SAMPLE_INTERVAL_MS:
        fail(f"{label}.sample_interval_ms must be 1000")
    start = _parse_timestamp(window["started_at"], f"{label}.started_at")
    end = _parse_timestamp(window["ended_at"], f"{label}.ended_at")
    start_mono = exact_int(window["started_monotonic_ns"], f"{label}.started_monotonic_ns", 1)
    end_mono = exact_int(window["ended_monotonic_ns"], f"{label}.ended_monotonic_ns", 1)
    minimum_duration = timedelta(seconds=expected_duration)
    maximum_duration = minimum_duration * MAX_WINDOW_DURATION_FACTOR
    utc_duration = end - start
    if not minimum_duration <= utc_duration <= maximum_duration:
        fail(f"{label} UTC duration is outside the complete bounded window")
    monotonic_duration = end_mono - start_mono
    minimum_monotonic = expected_duration * 1_000_000_000
    maximum_monotonic = minimum_monotonic * MAX_WINDOW_DURATION_FACTOR
    if not minimum_monotonic <= monotonic_duration <= maximum_monotonic:
        fail(f"{label} monotonic duration is outside the complete bounded window")
    try:
        require_safe_relative(window["samples_path"], f"{label}.samples_path", "host-admission")
    except ContractError as exc:
        fail(str(exc))
    if window["samples_path"] != EXPECTED_SAMPLE_PATHS[expected_name]:
        fail(f"{label}.samples_path is not the fixed raw evidence path")
    _exact_digest(window["samples_sha256"], f"{label}.samples_sha256")
    probes = exact_keys(window["representative_probes"], {"allow", "block"}, f"{label}.representative_probes")
    _validate_probe(probes["allow"], f"{label}.representative_probes.allow", blocked=False)
    _validate_probe(probes["block"], f"{label}.representative_probes.block", blocked=True)
    return window


def _validate_samples(
    raw: bytes,
    *,
    window: Mapping[str, Any],
    run_id: str,
    runtime_identity: Mapping[str, Any],
    expected_name: str,
    expected_count: int,
) -> tuple[dict[str, Any], dict[str, Any]]:
    label = f"{expected_name} samples"
    if not isinstance(raw, bytes):
        fail(f"{label} must be supplied as bytes")
    if len(raw) > expected_count * MAX_SAMPLE_LINE_BYTES:
        fail(f"{label} exceeds the closed byte bound")
    if sha256_bytes(raw) != window["samples_sha256"]:
        fail(f"{label} SHA-256 differs from the window binding")

    first: dict[str, Any] | None = None
    previous: dict[str, Any] | None = None
    queue_capacity: int | None = None
    observed_count = 0
    for ordinal, value in enumerate(
        iter_jsonl_bytes(raw, label, MAX_SAMPLE_LINE_BYTES), start=1
    ):
        if ordinal > expected_count:
            fail(f"{label} contains more than {expected_count} rows")
        observed_count = ordinal
        row = _validate_sample(
            value,
            label=f"{label}[{ordinal - 1}]",
            run_id=run_id,
            window_name=expected_name,
            ordinal=ordinal,
            runtime_identity=runtime_identity,
        )
        if first is None:
            first = row
            queue_capacity = row["audit_queue"]["capacity"]
        if row["audit_queue"]["capacity"] != queue_capacity:
            fail(f"{label} audit queue capacity drifted")
        if previous is not None:
            previous_utc = _parse_timestamp(previous["sampled_at"], f"{label}.previous.sampled_at")
            current_utc = _parse_timestamp(row["sampled_at"], f"{label}.current.sampled_at")
            utc_interval = current_utc - previous_utc
            if not (
                timedelta(milliseconds=MIN_SAMPLE_INTERVAL_MS)
                <= utc_interval
                <= timedelta(milliseconds=MAX_SAMPLE_INTERVAL_MS)
            ):
                fail(f"{label} has a UTC sampling gap or rollback before ordinal {ordinal}")
            monotonic_interval = row["monotonic_ns"] - previous["monotonic_ns"]
            if not (
                MIN_SAMPLE_INTERVAL_MS * 1_000_000
                <= monotonic_interval
                <= MAX_SAMPLE_INTERVAL_MS * 1_000_000
            ):
                fail(f"{label} has a monotonic sampling gap or rollback before ordinal {ordinal}")
            _counter_delta(previous["rpc_counters"], row["rpc_counters"], REALTIME_RPC_COUNTER_KEYS, f"{label}.rpc_counters")
            _counter_delta(previous["mock_counters"], row["mock_counters"], MOCK_COUNTER_KEYS, f"{label}.mock_counters")
            if row["usage_records"] < previous["usage_records"]:
                fail(f"{label}.usage_records went backwards")
        previous = row

    if observed_count != expected_count:
        fail(f"{label} must contain exactly {expected_count} canonical JSONL rows")
    if first is None or previous is None:
        fail(f"{label} did not contain the required samples")
    last = previous
    if (
        first["sampled_at"] != window["started_at"]
        or last["sampled_at"] != window["ended_at"]
        or first["monotonic_ns"] != window["started_monotonic_ns"]
        or last["monotonic_ns"] != window["ended_monotonic_ns"]
    ):
        fail(f"{label} first/last clocks differ from the window summary")

    allow_count = window["representative_probes"]["allow"]["executions"]
    block_count = window["representative_probes"]["block"]["executions"]
    rpc_delta = _counter_delta(first["rpc_counters"], last["rpc_counters"], REALTIME_RPC_COUNTER_KEYS, f"{label}.rpc_delta")
    expected_rpc_delta = {
        "rpc_request_before_calls": allow_count + block_count,
        "rpc_request_after_calls": allow_count,
        "rpc_request_complete_calls": allow_count,
        "rpc_request_complete_errors": 0,
        "rpc_model_route_calls": allow_count,
        "rpc_executor_calls": allow_count,
    }
    if rpc_delta != expected_rpc_delta:
        fail(f"{label} fixed CAG RPC counter deltas do not match the representative probes")
    mock_delta = _counter_delta(first["mock_counters"], last["mock_counters"], MOCK_COUNTER_KEYS, f"{label}.mock_delta")
    if mock_delta != {"auth": allow_count, "mock": allow_count, "provider": allow_count}:
        fail(f"{label} counted-Mock deltas do not match allow-only upstream traffic")
    if last["usage_records"] - first["usage_records"] != allow_count:
        fail(f"{label} usage delta does not match successful allow traffic")
    return first, last


def _validate_realtime(
    value: Any, routes_raw: bytes, label: str
) -> dict[str, Any]:
    realtime = exact_keys(
        value,
        {
            "cag_visible",
            "credential_kind",
            "evidence_level",
            "mock_counters_after",
            "mock_counters_before",
            "probe_mode",
            "protection",
            "real_provider_calls",
            "route_count",
            "routes_path",
            "routes_sha256",
            "rpc_counters_after",
            "rpc_counters_before",
            "target_boundary",
            "termination",
            "usage_records",
        },
        label,
    )
    if (
        realtime["evidence_level"] != "AUTH_BOUNDARY_ONLY"
        or realtime["protection"] != "unprotected"
        or realtime["probe_mode"] != "UNAUTHENTICATED"
        or realtime["credential_kind"] != "NONE"
        or realtime["termination"] != "AUTH_REJECTED"
        or exact_bool(realtime["cag_visible"], f"{label}.cag_visible")
        or exact_int(realtime["real_provider_calls"], f"{label}.real_provider_calls") != 0
        or exact_int(realtime["route_count"], f"{label}.route_count")
        != len(REALTIME_ROUTE_CONTRACT)
        or exact_int(realtime["usage_records"], f"{label}.usage_records") != 0
    ):
        fail(f"{label} must remain AUTH_BOUNDARY_ONLY, unprotected, and CAG-invisible")
    target = exact_keys(
        realtime["target_boundary"],
        {"counted_mock_only", "cpa_private_bridge_only", "real_provider_forbidden"},
        f"{label}.target_boundary",
    )
    if any(
        not exact_bool(target[key], f"{label}.target_boundary.{key}")
        for key in target
    ):
        fail(f"{label}.target_boundary is not the isolated private CPA/count-Mock boundary")
    try:
        require_safe_relative(
            realtime["routes_path"], f"{label}.routes_path", "host-admission"
        )
    except ContractError as exc:
        fail(str(exc))
    if realtime["routes_path"] != EXPECTED_REALTIME_ROUTES_PATH:
        fail(f"{label}.routes_path is not the fixed raw evidence path")
    _exact_digest(realtime["routes_sha256"], f"{label}.routes_sha256")
    if not isinstance(routes_raw, bytes):
        fail(f"{label} routes must be supplied as bytes")
    if len(routes_raw) > len(REALTIME_ROUTE_CONTRACT) * MAX_SAMPLE_LINE_BYTES:
        fail(f"{label} routes exceed the closed byte bound")
    if sha256_bytes(routes_raw) != realtime["routes_sha256"]:
        fail(f"{label} routes SHA-256 differs from the tail binding")
    before_rpc = _validate_rpc_counters(realtime["rpc_counters_before"], f"{label}.rpc_counters_before")
    after_rpc = _validate_rpc_counters(realtime["rpc_counters_after"], f"{label}.rpc_counters_after")
    before_mock = _validate_mock_counters(realtime["mock_counters_before"], f"{label}.mock_counters_before")
    after_mock = _validate_mock_counters(realtime["mock_counters_after"], f"{label}.mock_counters_after")
    if before_rpc != after_rpc or before_mock != after_mock:
        fail(f"{label} auth-boundary probes changed CAG or counted-Mock counters")
    seen: set[tuple[str, str, str]] = set()
    previous_rpc = before_rpc
    previous_mock = before_mock
    observed_count = 0
    for index, raw_route in enumerate(
        iter_jsonl_bytes(routes_raw, f"{label} routes", MAX_SAMPLE_LINE_BYTES),
        start=1,
    ):
        if index > len(REALTIME_ROUTE_CONTRACT):
            fail(f"{label}.routes contains too many route records")
        observed_count = index
        route_label = f"{label}.routes[{index}]"
        route = exact_keys(
            raw_route,
            {
                "auth",
                "credential_kind",
                "method",
                "mock_counters_after",
                "mock_counters_before",
                "ordinal",
                "probe_mode",
                "real_provider_calls",
                "route",
                "rpc_counters_after",
                "rpc_counters_before",
                "schema",
                "status",
                "target_boundary",
                "termination",
                "upgrade",
                "usage_records",
            },
            route_label,
        )
        if route["schema"] != REALTIME_ROUTE_SCHEMA:
            fail(f"{route_label}.schema is not {REALTIME_ROUTE_SCHEMA}")
        if exact_int(route["ordinal"], f"{route_label}.ordinal", 1) != index:
            fail(f"{route_label}.ordinal is not consecutive")
        identity = (
            _exact_string(route["method"], f"{route_label}.method", 8),
            _exact_string(route["route"], f"{route_label}.route", 256),
            _exact_string(route["auth"], f"{route_label}.auth", 16),
        )
        if identity in seen or identity != REALTIME_ROUTE_CONTRACT[index - 1]:
            fail(f"{route_label} is duplicate, reordered, or outside the fixed v7.2.144 route set")
        seen.add(identity)
        route_target = exact_keys(
            route["target_boundary"],
            {"counted_mock_only", "cpa_private_bridge_only", "real_provider_forbidden"},
            f"{route_label}.target_boundary",
        )
        if (
            route["probe_mode"] != "UNAUTHENTICATED"
            or route["credential_kind"] != "NONE"
            or route["termination"] != "AUTH_REJECTED"
            or route_target != {
                "counted_mock_only": True,
                "cpa_private_bridge_only": True,
                "real_provider_forbidden": True,
            }
            or exact_int(route["status"], f"{route_label}.status") not in {401, 403}
            or exact_bool(route["upgrade"], f"{route_label}.upgrade")
            or exact_int(
                route["real_provider_calls"], f"{route_label}.real_provider_calls"
            )
            != 0
            or exact_int(route["usage_records"], f"{route_label}.usage_records") != 0
        ):
            fail(f"{route_label} did not terminate at the isolated authentication boundary")
        route_rpc_before = _validate_rpc_counters(
            route["rpc_counters_before"], f"{route_label}.rpc_counters_before"
        )
        route_rpc_after = _validate_rpc_counters(
            route["rpc_counters_after"], f"{route_label}.rpc_counters_after"
        )
        route_mock_before = _validate_mock_counters(
            route["mock_counters_before"], f"{route_label}.mock_counters_before"
        )
        route_mock_after = _validate_mock_counters(
            route["mock_counters_after"], f"{route_label}.mock_counters_after"
        )
        if (
            route_rpc_before != previous_rpc
            or route_mock_before != previous_mock
            or route_rpc_after != route_rpc_before
            or route_mock_after != route_mock_before
        ):
            fail(f"{route_label} changed or broke continuity of CAG/Mock counters")
        previous_rpc = route_rpc_after
        previous_mock = route_mock_after
    if observed_count != len(REALTIME_ROUTE_CONTRACT):
        fail(f"{label}.routes must cover the exact fixed v7.2.144 route set")
    if seen != set(REALTIME_ROUTE_CONTRACT):
        fail(f"{label}.routes omits a fixed v7.2.144 realtime route")
    if previous_rpc != after_rpc or previous_mock != after_mock:
        fail(f"{label}.routes do not close against the realtime final counters")
    return realtime


def _validate_corpus_summary(value: Any, label: str) -> dict[str, Any]:
    summary = exact_keys(
        value,
        {
            "audit_detected_malicious",
            "balanced_blocked_malicious",
            "expected_malicious_cases",
            "false_positive_count",
            "normal_cases",
            "repositories",
            "repository_count",
            "status",
            "strict_blocked_malicious",
            "third_party_code_executions",
            "unexpected_errors",
        },
        label,
    )
    if summary["status"] != "PASS" or exact_int(summary["repository_count"], f"{label}.repository_count") != 5:
        fail(f"{label} does not report an exact five-repository PASS")
    repositories = summary["repositories"]
    if type(repositories) is not list or repositories != list(FIXED_REPOSITORIES):
        fail(f"{label}.repositories is not the frozen ordered five-repository set")
    normal = exact_int(summary["normal_cases"], f"{label}.normal_cases", 1)
    malicious = exact_int(summary["expected_malicious_cases"], f"{label}.expected_malicious_cases", 1)
    del normal
    if (
        exact_int(summary["false_positive_count"], f"{label}.false_positive_count") != 0
        or exact_int(summary["audit_detected_malicious"], f"{label}.audit_detected_malicious") != malicious
        or exact_int(summary["balanced_blocked_malicious"], f"{label}.balanced_blocked_malicious") != malicious
        or exact_int(summary["strict_blocked_malicious"], f"{label}.strict_blocked_malicious") != malicious
        or exact_int(summary["third_party_code_executions"], f"{label}.third_party_code_executions") != 0
        or exact_int(summary["unexpected_errors"], f"{label}.unexpected_errors") != 0
    ):
        fail(f"{label} semantic, safety, or error summary is not a PASS")
    return summary


def _validate_supplemental_summary(value: Any, label: str) -> dict[str, Any]:
    summary = exact_keys(
        value,
        {
            "archive_sha256",
            "audit_detected_malicious",
            "balanced_blocked_malicious",
            "denominators_separate_from_repositories",
            "expected_malicious_cases",
            "false_positive_count",
            "normal_cases",
            "status",
            "strict_blocked_malicious",
            "third_party_code_executions",
            "unexpected_errors",
        },
        label,
    )
    if summary["status"] != "PASS" or summary["archive_sha256"] != SUPPLEMENTAL_ZIP_ARCHIVE_IDENTITY["sha256"]:
        fail(f"{label} is not the frozen supplemental ZIP PASS")
    if not exact_bool(summary["denominators_separate_from_repositories"], f"{label}.denominators_separate_from_repositories"):
        fail(f"{label} mixed ZIP and five-repository denominators")
    exact_int(summary["normal_cases"], f"{label}.normal_cases", 1)
    malicious = exact_int(summary["expected_malicious_cases"], f"{label}.expected_malicious_cases", 1)
    if (
        exact_int(summary["false_positive_count"], f"{label}.false_positive_count") != 0
        or exact_int(summary["audit_detected_malicious"], f"{label}.audit_detected_malicious") != malicious
        or exact_int(summary["balanced_blocked_malicious"], f"{label}.balanced_blocked_malicious") != malicious
        or exact_int(summary["strict_blocked_malicious"], f"{label}.strict_blocked_malicious") != malicious
        or exact_int(summary["third_party_code_executions"], f"{label}.third_party_code_executions") != 0
        or exact_int(summary["unexpected_errors"], f"{label}.unexpected_errors") != 0
    ):
        fail(f"{label} semantic, safety, or error summary is not a PASS")
    return summary


def _validate_tail(
    value: Any,
    realtime_routes_jsonl: bytes,
    *,
    ended_at: datetime,
    ended_monotonic_ns: int,
    run_id: str,
    candidate_artifact_digest: str,
    samples_sha256: str,
    runtime_identity: Mapping[str, Any],
    final_sample: Mapping[str, Any],
) -> dict[str, Any]:
    label = "evidence.tail_verification"
    tail = exact_keys(
        value,
        {
            "candidate_artifact_digest",
            "cleanup",
            "host_3600s_samples_sha256",
            "repositories",
            "realtime",
            "run_id",
            "runtime_identity_before_cleanup",
            "sqlite",
            "stability_basis",
            "supplemental_zip",
            "verified_at",
            "verified_monotonic_ns",
        },
        label,
    )
    if tail["run_id"] != run_id:
        fail(f"{label}.run_id drifted from the Host admission run")
    if tail["candidate_artifact_digest"] != candidate_artifact_digest:
        fail(f"{label}.candidate_artifact_digest drifted")
    if tail["host_3600s_samples_sha256"] != samples_sha256:
        fail(f"{label} is not bound to the validated 3600-second JSONL")
    tail_identity = _validate_runtime_identity(
        tail["runtime_identity_before_cleanup"],
        f"{label}.runtime_identity_before_cleanup",
    )
    if tail_identity != runtime_identity or final_sample["runtime_identity"] != runtime_identity:
        fail(f"{label} did not reverify the exact runtime identity before cleanup")
    if tail["stability_basis"] != STABILITY_BASIS:
        fail(f"{label}.stability_basis cannot be replaced by warm_rss_60m")
    verified_at = _parse_timestamp(tail["verified_at"], f"{label}.verified_at")
    verified_mono = exact_int(tail["verified_monotonic_ns"], f"{label}.verified_monotonic_ns", 1)
    if verified_at <= ended_at or verified_mono <= ended_monotonic_ns:
        fail(f"{label} must occur after the complete 3600-second window")
    realtime = _validate_realtime(
        tail["realtime"], realtime_routes_jsonl, f"{label}.realtime"
    )
    if (
        realtime["rpc_counters_before"] != final_sample["rpc_counters"]
        or realtime["mock_counters_before"] != final_sample["mock_counters"]
    ):
        fail(f"{label}.realtime is not continuous with the 3600-second tail sample")
    _validate_corpus_summary(tail["repositories"], f"{label}.repositories")
    _validate_supplemental_summary(tail["supplemental_zip"], f"{label}.supplemental_zip")
    sqlite = exact_keys(tail["sqlite"], {"quick_check", "schema_version"}, f"{label}.sqlite")
    if sqlite != {"quick_check": "ok", "schema_version": AUDIT_SCHEMA_VERSION}:
        fail(
            f"{label}.sqlite must report quick_check=ok and "
            f"schema_version={AUDIT_SCHEMA_VERSION}"
        )
    cleanup = exact_keys(
        tail["cleanup"],
        {
            "all_owned_resources_absent",
            "evidence_preserved",
            "global_prune_used",
            "status",
            "unrelated_resources_touched",
        },
        f"{label}.cleanup",
    )
    for key in (
        "all_owned_resources_absent",
        "evidence_preserved",
        "global_prune_used",
        "unrelated_resources_touched",
    ):
        exact_bool(cleanup[key], f"{label}.cleanup.{key}")
    _exact_string(cleanup["status"], f"{label}.cleanup.status", 16)
    if cleanup != {
        "all_owned_resources_absent": True,
        "evidence_preserved": True,
        "global_prune_used": False,
        "status": "PASS",
        "unrelated_resources_touched": False,
    }:
        fail(f"{label}.cleanup is not exact-run, evidence-preserving cleanup")
    return tail


def _validate_host_admission(
    evidence_value: Any,
    host_300s_jsonl: bytes,
    host_3600s_jsonl: bytes,
    realtime_routes_jsonl: bytes,
    expected_candidate: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate a report, three canonical JSONLs, and a trusted candidate."""

    evidence = exact_keys(
        evidence_value,
        {
            "candidate",
            "claim_boundary",
            "platform",
            "run_id",
            "runtime_identity",
            "schema",
            "status",
            "tail_verification",
            "windows",
        },
        "evidence",
    )
    if evidence["schema"] != SCHEMA:
        fail(f"evidence.schema is not {SCHEMA}")
    if evidence["claim_boundary"] != CLAIM_BOUNDARY or evidence["status"] != STATUS:
        fail("evidence claim boundary/status is not the exact owner-run PASS contract")
    if evidence["platform"] != PLATFORM:
        fail("evidence.platform must be linux/amd64")
    run_id = _validate_run_id(evidence["run_id"], "evidence.run_id")
    _validate_candidate(evidence["candidate"])
    if not isinstance(expected_candidate, Mapping):
        fail("expected_candidate must be an independently trusted mapping")
    expected_candidate_copy = dict(expected_candidate)
    _validate_candidate(expected_candidate_copy)
    if evidence["candidate"] != expected_candidate_copy:
        fail("evidence.candidate differs from the independently trusted candidate identity")
    runtime_identity = _validate_runtime_identity(evidence["runtime_identity"], "evidence.runtime_identity")

    windows_raw = evidence["windows"]
    if type(windows_raw) is not list or len(windows_raw) != 2:
        fail("evidence.windows must contain exactly host_300s then host_3600s")
    windows: list[dict[str, Any]] = []
    for raw_window, (name, duration, count) in zip(windows_raw, WINDOW_SPECS):
        windows.append(
            _validate_window_summary(
                raw_window,
                expected_name=name,
                expected_duration=duration,
                expected_count=count,
            )
        )
    if windows[0]["samples_path"] == windows[1]["samples_path"]:
        fail("the 300-second and 3600-second windows must bind independent JSONL paths")

    end_300_summary = _parse_timestamp(windows[0]["ended_at"], "host_300s ended_at")
    start_3600_summary = _parse_timestamp(
        windows[1]["started_at"], "host_3600s started_at"
    )
    if (
        start_3600_summary <= end_300_summary
        or windows[1]["started_monotonic_ns"] <= windows[0]["ended_monotonic_ns"]
    ):
        fail("Host windows must be independent, sequential, and strictly non-overlapping")
    first_300, last_300 = _validate_samples(
        host_300s_jsonl,
        window=windows[0],
        run_id=run_id,
        runtime_identity=runtime_identity,
        expected_name="host_300s",
        expected_count=301,
    )
    first_3600, last_3600 = _validate_samples(
        host_3600s_jsonl,
        window=windows[1],
        run_id=run_id,
        runtime_identity=runtime_identity,
        expected_name="host_3600s",
        expected_count=3_601,
    )
    _counter_delta(last_300["rpc_counters"], first_3600["rpc_counters"], REALTIME_RPC_COUNTER_KEYS, "cross-window rpc_counters")
    _counter_delta(last_300["mock_counters"], first_3600["mock_counters"], MOCK_COUNTER_KEYS, "cross-window mock_counters")
    if first_3600["usage_records"] < last_300["usage_records"]:
        fail("cross-window usage_records went backwards")
    if first_3600["audit_queue"]["capacity"] != first_300["audit_queue"]["capacity"]:
        fail("audit queue capacity drifted between Host windows")

    _validate_tail(
        evidence["tail_verification"],
        realtime_routes_jsonl,
        ended_at=_parse_timestamp(last_3600["sampled_at"], "host_3600s last sampled_at"),
        ended_monotonic_ns=last_3600["monotonic_ns"],
        run_id=run_id,
        candidate_artifact_digest=evidence["candidate"]["artifacts"][
            "candidate_artifact_digest"
        ],
        samples_sha256=windows[1]["samples_sha256"],
        runtime_identity=runtime_identity,
        final_sample=last_3600,
    )

    return evidence


def validate_host_admission(
    evidence_value: Any,
    host_300s_jsonl: bytes,
    host_3600s_jsonl: bytes,
    realtime_routes_jsonl: bytes,
    expected_candidate: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate a parsed report and expose one module-specific error type."""

    try:
        return _validate_host_admission(
            evidence_value,
            host_300s_jsonl,
            host_3600s_jsonl,
            realtime_routes_jsonl,
            expected_candidate,
        )
    except HostAdmissionError:
        raise
    except ContractError as exc:
        raise HostAdmissionError(str(exc)) from exc


def _parse_host_admission(
    evidence_raw: bytes,
    host_300s_jsonl: bytes,
    host_3600s_jsonl: bytes,
    realtime_routes_jsonl: bytes,
    expected_candidate: Mapping[str, Any],
) -> dict[str, Any]:
    if not isinstance(evidence_raw, bytes):
        fail("Host admission evidence must be supplied as bytes")
    value = load_json_bytes(evidence_raw, "Host admission evidence", MAX_EVIDENCE_BYTES)
    if evidence_raw != canonical_bytes(value) + b"\n":
        fail("Host admission evidence must be canonical JSON with one terminal newline")
    return validate_host_admission(
        value,
        host_300s_jsonl,
        host_3600s_jsonl,
        realtime_routes_jsonl,
        expected_candidate,
    )


def parse_host_admission(
    evidence_raw: bytes,
    host_300s_jsonl: bytes,
    host_3600s_jsonl: bytes,
    realtime_routes_jsonl: bytes,
    expected_candidate: Mapping[str, Any],
) -> dict[str, Any]:
    """Parse and validate a report, three JSONLs, and a trusted candidate."""

    try:
        return _parse_host_admission(
            evidence_raw,
            host_300s_jsonl,
            host_3600s_jsonl,
            realtime_routes_jsonl,
            expected_candidate,
        )
    except HostAdmissionError:
        raise
    except ContractError as exc:
        raise HostAdmissionError(str(exc)) from exc


# Descriptive alias for callers that treat the report and raw streams as a bundle.
validate_canonical_bundle = parse_host_admission


__all__ = [
    "CLAIM_BOUNDARY",
    "FIXED_REPOSITORIES",
    "EXPECTED_SAMPLE_PATHS",
    "EXPECTED_REALTIME_ROUTES_PATH",
    "HostAdmissionError",
    "PLATFORM",
    "SAMPLE_INTERVAL_MS",
    "SAMPLE_SCHEMA",
    "REALTIME_ROUTE_SCHEMA",
    "SCHEMA",
    "STABILITY_BASIS",
    "WINDOW_SPECS",
    "parse_host_admission",
    "validate_canonical_bundle",
    "validate_host_admission",
]
