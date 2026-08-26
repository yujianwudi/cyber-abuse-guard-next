from __future__ import annotations

import copy
import json
import subprocess
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable


HERE = Path(__file__).resolve().parent
TOOL_DIR = HERE.parent
sys.path.insert(0, str(TOOL_DIR))

from audit_contract import (  # noqa: E402
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
    canonical_bytes,
    sha256_bytes,
)
import host_admission as host  # noqa: E402


try:
    from jsonschema import Draft202012Validator
except ImportError:  # pragma: no cover
    Draft202012Validator = None  # type: ignore[assignment]


UTC = timezone.utc
RUN_ID = "round14-host-admission-001"
BASE_300 = datetime(2026, 8, 13, 0, 0, 0, tzinfo=UTC)
BASE_3600 = datetime(2026, 8, 13, 0, 6, 0, tzinfo=UTC)
MONO_300 = 10_000_000_000
MONO_3600 = 400_000_000_000
QUEUE_CAPACITY = 100
ALLOW_COUNT = 2
BLOCK_COUNT = 1


def timestamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def process_identity(
    *, container_char: str, image_char: str, repository: str, pid: int, starttime: int
) -> dict[str, Any]:
    return {
        "container_id": container_char * 64,
        "docker_started_at": "2026-08-12T23:59:00.123456789Z",
        "image_digest": f"{repository}@sha256:{image_char * 64}",
        "image_id": f"sha256:{image_char * 64}",
        "init_pid": pid,
        "proc_starttime_ticks": starttime,
    }


RUNTIME_IDENTITY = {
    "cpa": process_identity(
        container_char="1",
        image_char="a",
        repository="audit/cpa",
        pid=101,
        starttime=1001,
    ),
    "keeper": process_identity(
        container_char="2",
        image_char="b",
        repository="audit/keeper",
        pid=202,
        starttime=2002,
    ),
    "mock": process_identity(
        container_char="3",
        image_char="c",
        repository="audit/mock",
        pid=303,
        starttime=3003,
    ),
}


def rpc_counters(*, before: int, after: int, complete: int) -> dict[str, int]:
    return {
        "rpc_request_before_calls": before,
        "rpc_request_after_calls": after,
        "rpc_request_complete_calls": complete,
        "rpc_request_complete_errors": 0,
        "rpc_model_route_calls": after,
        "rpc_executor_calls": after,
    }


def sample(
    *,
    name: str,
    ordinal: int,
    base: datetime,
    monotonic_base: int,
    counter_base: int,
) -> dict[str, Any]:
    final = 301 if name == "host_300s" else 3_601
    is_final = ordinal == final
    before = counter_base + (ALLOW_COUNT + BLOCK_COUNT if is_final else 0)
    allowed = counter_base + (ALLOW_COUNT if is_final else 0)
    return {
        "audit_queue": {
            "capacity": QUEUE_CAPACITY,
            "depth": ordinal % 7,
            "errors": 0,
            "healthy": True,
        },
        "endpoints": {
            "keeper": {
                "path": "/keeper/healthz",
                "state": "healthy",
                "status": 200,
            },
            "root": {"path": "/", "status": 200},
            "unauthorized_models": {
                "authorization": "none",
                "path": "/v1/models",
                "status": 401,
            },
        },
        "failures": {
            "oom_events": 0,
            "panic_events": 0,
            "plugin_errors": 0,
            "real_provider_calls": 0,
            "restarts": 0,
            "unexpected_errors": 0,
        },
        "mock_counters": {
            "auth": allowed,
            "mock": allowed,
            "provider": allowed,
        },
        "monotonic_ns": monotonic_base + (ordinal - 1) * 1_000_000_000,
        "ordinal": ordinal,
        "rpc_counters": rpc_counters(before=before, after=allowed, complete=allowed),
        "rss_bytes": 64 * 1024 * 1024 + ordinal,
        "run_id": RUN_ID,
        "runtime_identity": copy.deepcopy(RUNTIME_IDENTITY),
        "sampled_at": timestamp(base + timedelta(seconds=ordinal - 1)),
        "schema": host.SAMPLE_SCHEMA,
        "usage_records": allowed,
        "window": name,
    }


def build_rows(
    *, name: str, count: int, base: datetime, monotonic_base: int, counter_base: int
) -> list[dict[str, Any]]:
    return [
        sample(
            name=name,
            ordinal=ordinal,
            base=base,
            monotonic_base=monotonic_base,
            counter_base=counter_base,
        )
        for ordinal in range(1, count + 1)
    ]


def jsonl(rows: list[dict[str, Any]]) -> bytes:
    return b"".join(canonical_bytes(row) + b"\n" for row in rows)


def probe(*, blocked: bool) -> dict[str, Any]:
    executions = BLOCK_COUNT if blocked else ALLOW_COUNT
    side = {key: 0 for key in host.SIDE_EFFECT_KEYS}
    if not blocked:
        for key in ("auth", "executor", "mock", "provider", "router", "usage"):
            side[key] = executions
    action = "block_malicious_text" if blocked else "allow"
    return {
        "actual_action": action,
        "executions": executions,
        "expected_action": action,
        "http_status": 403 if blocked else 200,
        "passed": executions,
        "side_effect_deltas": side,
    }


def window(
    *, name: str, rows: list[dict[str, Any]], raw: bytes, duration: int
) -> dict[str, Any]:
    return {
        "duration_seconds": duration,
        "ended_at": rows[-1]["sampled_at"],
        "ended_monotonic_ns": rows[-1]["monotonic_ns"],
        "name": name,
        "representative_probes": {
            "allow": probe(blocked=False),
            "block": probe(blocked=True),
        },
        "sample_count": len(rows),
        "sample_interval_ms": 1_000,
        "samples_path": host.EXPECTED_SAMPLE_PATHS[name],
        "samples_sha256": sha256_bytes(raw),
        "started_at": rows[0]["sampled_at"],
        "started_monotonic_ns": rows[0]["monotonic_ns"],
    }


ROWS_300 = build_rows(
    name="host_300s",
    count=301,
    base=BASE_300,
    monotonic_base=MONO_300,
    counter_base=0,
)
ROWS_3600 = build_rows(
    name="host_3600s",
    count=3_601,
    base=BASE_3600,
    monotonic_base=MONO_3600,
    counter_base=10,
)
RAW_300 = jsonl(ROWS_300)
RAW_3600 = jsonl(ROWS_3600)


def realtime_route_rows() -> list[dict[str, Any]]:
    counters = copy.deepcopy(ROWS_3600[-1]["rpc_counters"])
    mock = copy.deepcopy(ROWS_3600[-1]["mock_counters"])
    boundary = {
        "counted_mock_only": True,
        "cpa_private_bridge_only": True,
        "real_provider_forbidden": True,
    }
    return [
        {
            "auth": auth,
            "credential_kind": "NONE",
            "method": method,
            "mock_counters_after": copy.deepcopy(mock),
            "mock_counters_before": copy.deepcopy(mock),
            "ordinal": ordinal,
            "probe_mode": "UNAUTHENTICATED",
            "real_provider_calls": 0,
            "route": route,
            "rpc_counters_after": copy.deepcopy(counters),
            "rpc_counters_before": copy.deepcopy(counters),
            "schema": host.REALTIME_ROUTE_SCHEMA,
            "status": 401,
            "target_boundary": copy.deepcopy(boundary),
            "termination": "AUTH_REJECTED",
            "upgrade": False,
            "usage_records": 0,
        }
        for ordinal, (method, route, auth) in enumerate(
            REALTIME_ROUTE_CONTRACT, start=1
        )
    ]


REALTIME_ROUTE_ROWS = realtime_route_rows()
RAW_REALTIME_ROUTES = jsonl(REALTIME_ROUTE_ROWS)


def realtime_projection() -> dict[str, Any]:
    counters = copy.deepcopy(ROWS_3600[-1]["rpc_counters"])
    mock = copy.deepcopy(ROWS_3600[-1]["mock_counters"])
    return {
        "cag_visible": False,
        "credential_kind": "NONE",
        "evidence_level": "AUTH_BOUNDARY_ONLY",
        "mock_counters_after": copy.deepcopy(mock),
        "mock_counters_before": copy.deepcopy(mock),
        "probe_mode": "UNAUTHENTICATED",
        "protection": "unprotected",
        "real_provider_calls": 0,
        "route_count": len(REALTIME_ROUTE_CONTRACT),
        "routes_path": host.EXPECTED_REALTIME_ROUTES_PATH,
        "routes_sha256": sha256_bytes(RAW_REALTIME_ROUTES),
        "rpc_counters_after": copy.deepcopy(counters),
        "rpc_counters_before": copy.deepcopy(counters),
        "target_boundary": {
            "counted_mock_only": True,
            "cpa_private_bridge_only": True,
            "real_provider_forbidden": True,
        },
        "termination": "AUTH_REJECTED",
        "usage_records": 0,
    }


def candidate_identity() -> dict[str, Any]:
    return {
        "artifacts": {
            "candidate_artifact_digest": "sha256:" + "d" * 64,
            "candidate_manifest_sha256": "e" * 64,
            "config_sha256": "f" * 64,
            "evidence_manifest_sha256": "9" * 64,
        },
        "cag": {
            "commit": "4" * 40,
            "so_name": CAG_SO_NAME,
            "so_sha256": "5" * 64,
            "source_version": CAG_SOURCE_VERSION,
            "store_zip_sha256": "6" * 64,
            "tree": "7" * 40,
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


def semantic_summary(*, supplemental: bool) -> dict[str, Any]:
    summary: dict[str, Any] = {
        "audit_detected_malicious": 4,
        "balanced_blocked_malicious": 4,
        "expected_malicious_cases": 4,
        "false_positive_count": 0,
        "normal_cases": 6,
        "status": "PASS",
        "strict_blocked_malicious": 4,
        "third_party_code_executions": 0,
        "unexpected_errors": 0,
    }
    if supplemental:
        summary.update(
            {
                "archive_sha256": SUPPLEMENTAL_ZIP_ARCHIVE_IDENTITY["sha256"],
                "denominators_separate_from_repositories": True,
            }
        )
    else:
        summary.update(
            {
                "repositories": list(host.FIXED_REPOSITORIES),
                "repository_count": 5,
            }
        )
    return summary


def evidence() -> dict[str, Any]:
    return {
        "candidate": candidate_identity(),
        "claim_boundary": host.CLAIM_BOUNDARY,
        "platform": host.PLATFORM,
        "run_id": RUN_ID,
        "runtime_identity": copy.deepcopy(RUNTIME_IDENTITY),
        "schema": host.SCHEMA,
        "status": host.STATUS,
        "tail_verification": {
            "candidate_artifact_digest": "sha256:" + "d" * 64,
            "cleanup": {
                "all_owned_resources_absent": True,
                "evidence_preserved": True,
                "global_prune_used": False,
                "status": "PASS",
                "unrelated_resources_touched": False,
            },
            "host_3600s_samples_sha256": sha256_bytes(RAW_3600),
            "repositories": semantic_summary(supplemental=False),
            "realtime": realtime_projection(),
            "run_id": RUN_ID,
            "runtime_identity_before_cleanup": copy.deepcopy(RUNTIME_IDENTITY),
            "sqlite": {"quick_check": "ok", "schema_version": AUDIT_SCHEMA_VERSION},
            "stability_basis": host.STABILITY_BASIS,
            "supplemental_zip": semantic_summary(supplemental=True),
            "verified_at": timestamp(BASE_3600 + timedelta(seconds=3_601)),
            "verified_monotonic_ns": MONO_3600 + 3_601 * 1_000_000_000,
        },
        "windows": [
            window(name="host_300s", rows=ROWS_300, raw=RAW_300, duration=300),
            window(name="host_3600s", rows=ROWS_3600, raw=RAW_3600, duration=3_600),
        ],
    }


def canonical_evidence(value: dict[str, Any]) -> bytes:
    return canonical_bytes(value) + b"\n"


def validate_report(
    report: dict[str, Any],
    raw_300: bytes = RAW_300,
    raw_3600: bytes = RAW_3600,
    realtime_raw: bytes = RAW_REALTIME_ROUTES,
    expected_candidate: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return host.validate_host_admission(
        report,
        raw_300,
        raw_3600,
        realtime_raw,
        candidate_identity() if expected_candidate is None else expected_candidate,
    )


def parse_report(
    report_raw: bytes,
    raw_300: bytes = RAW_300,
    raw_3600: bytes = RAW_3600,
    realtime_raw: bytes = RAW_REALTIME_ROUTES,
    expected_candidate: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return host.parse_host_admission(
        report_raw,
        raw_300,
        raw_3600,
        realtime_raw,
        candidate_identity() if expected_candidate is None else expected_candidate,
    )


class HostAdmissionTests(unittest.TestCase):
    def assert_rejected(
        self,
        mutate: Callable[[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]], None],
        pattern: str,
    ) -> None:
        report = evidence()
        rows_300 = copy.deepcopy(ROWS_300)
        rows_3600 = copy.deepcopy(ROWS_3600)
        mutate(report, rows_300, rows_3600)
        raw_300 = jsonl(rows_300)
        raw_3600 = jsonl(rows_3600)
        # Unless the mutation deliberately targets a digest/sample-count
        # binding, reseal both streams so validation reaches the intended rule.
        report["windows"][0]["samples_sha256"] = sha256_bytes(raw_300)
        report["windows"][1]["samples_sha256"] = sha256_bytes(raw_3600)
        with self.assertRaisesRegex(host.HostAdmissionError, pattern):
            parse_report(canonical_evidence(report), raw_300, raw_3600)

    def test_positive_canonical_bundle(self) -> None:
        report = evidence()
        self.assertEqual(
            parse_report(canonical_evidence(report)),
            report,
        )

    def test_schema_is_closed_and_accepts_report(self) -> None:
        schema = json.loads(
            (TOOL_DIR / "host-admission-evidence.schema.json").read_text(encoding="utf-8")
        )
        self.assertFalse(schema["additionalProperties"])
        for definition in schema["$defs"].values():
            if isinstance(definition, dict) and definition.get("type") == "object":
                self.assertFalse(definition.get("additionalProperties", True))
        if Draft202012Validator is not None:
            Draft202012Validator.check_schema(schema)
            Draft202012Validator(schema).validate(evidence())

    def test_requires_canonical_report_and_jsonl(self) -> None:
        report = evidence()
        pretty = json.dumps(report, indent=2, ensure_ascii=False).encode("utf-8") + b"\n"
        with self.assertRaisesRegex(host.HostAdmissionError, "canonical JSON"):
            parse_report(pretty)
        noncanonical_jsonl = RAW_300.replace(b'"ordinal":1', b'"ordinal": 1', 1)
        report["windows"][0]["samples_sha256"] = sha256_bytes(noncanonical_jsonl)
        with self.assertRaisesRegex(host.HostAdmissionError, "canonical JSONL"):
            parse_report(canonical_evidence(report), noncanonical_jsonl, RAW_3600)

    def test_rejects_missing_or_extra_samples(self) -> None:
        self.assert_rejected(lambda _r, rows, _l: rows.pop(), "exactly 301")
        self.assert_rejected(
            lambda _r, _s, rows: rows.append(copy.deepcopy(rows[-1])),
            "more than 3601",
        )

    def test_rejects_ordinal_disorder(self) -> None:
        self.assert_rejected(
            lambda _r, rows, _l: rows[50].__setitem__("ordinal", 52),
            "consecutive 1-based ordinal",
        )

    def test_rejects_utc_gap_and_rollback(self) -> None:
        self.assert_rejected(
            lambda _r, rows, _l: rows[100].__setitem__(
                "sampled_at", timestamp(BASE_300 + timedelta(seconds=101))
            ),
            "UTC sampling gap or rollback",
        )
        self.assert_rejected(
            lambda _r, _s, rows: rows[1].__setitem__("sampled_at", rows[0]["sampled_at"]),
            "UTC sampling gap or rollback",
        )

    def test_rejects_monotonic_gap_and_rollback(self) -> None:
        self.assert_rejected(
            lambda _r, rows, _l: rows[100].__setitem__(
                "monotonic_ns", rows[99]["monotonic_ns"] + 2_000_000_000
            ),
            "monotonic sampling gap or rollback",
        )
        self.assert_rejected(
            lambda _r, _s, rows: rows[1].__setitem__(
                "monotonic_ns", rows[0]["monotonic_ns"] - 1
            ),
            "monotonic sampling gap or rollback",
        )

    def test_accepts_bounded_scheduler_jitter_without_shortening_the_window(self) -> None:
        report = evidence()
        rows_300 = copy.deepcopy(ROWS_300)
        for row in rows_300[1:]:
            sampled_at = datetime.fromisoformat(row["sampled_at"].replace("Z", "+00:00"))
            row["sampled_at"] = timestamp(sampled_at + timedelta(milliseconds=100))
            row["monotonic_ns"] += 100_000_000
        raw_300 = jsonl(rows_300)
        report["windows"][0]["ended_at"] = rows_300[-1]["sampled_at"]
        report["windows"][0]["ended_monotonic_ns"] = rows_300[-1]["monotonic_ns"]
        report["windows"][0]["samples_sha256"] = sha256_bytes(raw_300)
        self.assertEqual(
            parse_report(canonical_evidence(report), raw_300, RAW_3600),
            report,
        )

    def test_rejects_bounded_intervals_that_do_not_cover_the_nominal_window(self) -> None:
        report = evidence()
        rows_300 = copy.deepcopy(ROWS_300)
        for index, row in enumerate(rows_300):
            row["sampled_at"] = timestamp(
                BASE_300 + timedelta(milliseconds=999 * index)
            )
            row["monotonic_ns"] = MONO_300 + 999_000_000 * index
        raw_300 = jsonl(rows_300)
        report["windows"][0]["ended_at"] = rows_300[-1]["sampled_at"]
        report["windows"][0]["ended_monotonic_ns"] = rows_300[-1]["monotonic_ns"]
        report["windows"][0]["samples_sha256"] = sha256_bytes(raw_300)
        with self.assertRaisesRegex(host.HostAdmissionError, "complete bounded window"):
            parse_report(canonical_evidence(report), raw_300, RAW_3600)

    def test_rejects_overlapping_or_reversed_windows_before_jsonl_walk(self) -> None:
        report = evidence()
        report["windows"][1]["started_at"] = report["windows"][0]["ended_at"]
        report["windows"][1]["ended_at"] = timestamp(
            datetime.fromisoformat(report["windows"][1]["started_at"].replace("Z", "+00:00"))
            + timedelta(seconds=3_600)
        )
        report["windows"][1]["started_monotonic_ns"] = report["windows"][0]["ended_monotonic_ns"]
        report["windows"][1]["ended_monotonic_ns"] = (
            report["windows"][1]["started_monotonic_ns"] + 3_600_000_000_000
        )
        with self.assertRaisesRegex(host.HostAdmissionError, "non-overlapping"):
            validate_report(report, b"not parsed", b"not parsed")

    def test_rejects_runtime_identity_drift(self) -> None:
        self.assert_rejected(
            lambda _r, _s, rows: rows[1]["runtime_identity"]["keeper"].__setitem__(
                "proc_starttime_ticks", 9999
            ),
            "runtime_identity drifted",
        )
        self.assert_rejected(
            lambda _r, rows, _l: rows[1]["runtime_identity"]["cpa"].__setitem__(
                "container_id", "8" * 64
            ),
            "runtime_identity drifted",
        )

    def test_rejects_endpoint_failures(self) -> None:
        cases = (
            ("keeper", "status", 503),
            ("keeper", "state", "starting"),
            ("root", "status", 500),
            ("unauthorized_models", "status", 200),
        )
        for endpoint, key, value in cases:
            with self.subTest(endpoint=endpoint, key=key):
                self.assert_rejected(
                    lambda _r, rows, _l, e=endpoint, k=key, v=value: rows[10][
                        "endpoints"
                    ][e].__setitem__(k, v),
                    "not healthy|not HTTP|not the unauthenticated",
                )

    def test_rejects_restart_oom_panic_plugin_and_provider(self) -> None:
        for field in (
            "restarts",
            "oom_events",
            "panic_events",
            "plugin_errors",
            "real_provider_calls",
        ):
            with self.subTest(field=field):
                self.assert_rejected(
                    lambda _r, _s, rows, f=field: rows[100]["failures"].__setitem__(f, 1),
                    "must remain zero",
                )

    def test_rejects_audit_queue_or_health_failure(self) -> None:
        self.assert_rejected(
            lambda _r, rows, _l: rows[3]["audit_queue"].__setitem__("healthy", False),
            "healthy must remain true",
        )
        self.assert_rejected(
            lambda _r, _s, rows: rows[3]["audit_queue"].__setitem__(
                "depth", QUEUE_CAPACITY
            ),
            "depth must stay below capacity",
        )

    def test_rejects_rpc_mock_and_usage_delta_mismatch(self) -> None:
        self.assert_rejected(
            lambda _r, _s, rows: rows[-1]["rpc_counters"].__setitem__(
                "rpc_executor_calls", rows[-1]["rpc_counters"]["rpc_executor_calls"] + 1
            ),
            "fixed CAG RPC counter deltas",
        )
        self.assert_rejected(
            lambda _r, rows, _l: rows[-1]["mock_counters"].__setitem__(
                "provider", rows[-1]["mock_counters"]["provider"] + 1
            ),
            "counted-Mock deltas",
        )
        self.assert_rejected(
            lambda _r, _s, rows: rows[-1].__setitem__(
                "usage_records", rows[-1]["usage_records"] + 1
            ),
            "usage delta",
        )

    def test_rejects_allow_or_block_side_effect_violation(self) -> None:
        report = evidence()
        report["windows"][0]["representative_probes"]["allow"]["side_effect_deltas"][
            "provider"
        ] = 0
        with self.assertRaisesRegex(host.HostAdmissionError, "side-effect contract"):
            validate_report(report)
        report = evidence()
        report["windows"][1]["representative_probes"]["block"]["side_effect_deltas"][
            "usage"
        ] = 1
        with self.assertRaisesRegex(host.HostAdmissionError, "side-effect contract"):
            validate_report(report)

    def test_rejects_missing_or_malformed_tail_verification(self) -> None:
        report = evidence()
        del report["tail_verification"]
        with self.assertRaisesRegex(host.HostAdmissionError, "exactly"):
            validate_report(report)
        cases = (
            ("realtime", "protection", "protected"),
            ("sqlite", "quick_check", "corrupt"),
            ("sqlite", "schema_version", 5),
            ("cleanup", "global_prune_used", True),
            ("repositories", "false_positive_count", 1),
            ("supplemental_zip", "denominators_separate_from_repositories", False),
        )
        for section, key, value in cases:
            with self.subTest(section=section, key=key):
                report = evidence()
                report["tail_verification"][section][key] = value
                with self.assertRaises(host.HostAdmissionError):
                    validate_report(report)

    def test_rejects_warm_rss_substitution(self) -> None:
        report = evidence()
        report["tail_verification"]["stability_basis"] = "warm_rss_60m"
        with self.assertRaisesRegex(host.HostAdmissionError, "warm_rss_60m"):
            validate_report(report)

    def test_rejects_tail_timestamp_not_after_window(self) -> None:
        report = evidence()
        report["tail_verification"]["verified_at"] = report["windows"][1]["ended_at"]
        with self.assertRaisesRegex(host.HostAdmissionError, "after the complete"):
            validate_report(report)

    def test_rejects_borrowed_tail_bindings_or_counter_discontinuity(self) -> None:
        cases: tuple[tuple[str, Callable[[dict[str, Any]], None]], ...] = (
            (
                "run_id",
                lambda report: report["tail_verification"].__setitem__(
                    "run_id", "round14-host-admission-old"
                ),
            ),
            (
                "candidate_artifact",
                lambda report: report["tail_verification"].__setitem__(
                    "candidate_artifact_digest", "sha256:" + "8" * 64
                ),
            ),
            (
                "3600-second JSONL",
                lambda report: report["tail_verification"].__setitem__(
                    "host_3600s_samples_sha256", "8" * 64
                ),
            ),
            (
                "runtime identity",
                lambda report: report["tail_verification"][
                    "runtime_identity_before_cleanup"
                ]["cpa"].__setitem__("proc_starttime_ticks", 123456),
            ),
            (
                "continuity",
                lambda report: [
                    report["tail_verification"]["realtime"][side].__setitem__(
                        "rpc_request_before_calls",
                        report["tail_verification"]["realtime"][side][
                            "rpc_request_before_calls"
                        ]
                        + 1,
                    )
                    for side in ("rpc_counters_before", "rpc_counters_after")
                ],
            ),
        )
        for expected, mutation in cases:
            with self.subTest(expected=expected):
                report = evidence()
                mutation(report)
                with self.assertRaisesRegex(host.HostAdmissionError, expected):
                    validate_report(report)

    def test_rejects_missing_duplicate_or_malformed_realtime_routes(self) -> None:
        mutations: tuple[
            tuple[str, Callable[[list[dict[str, Any]]], None]], ...
        ] = (
            ("exact fixed", lambda rows: rows.pop()),
            (
                "duplicate, reordered",
                lambda rows: rows[1].update(
                    {
                        "method": rows[0]["method"],
                        "route": rows[0]["route"],
                        "auth": rows[0]["auth"],
                    }
                ),
            ),
            (
                "authentication boundary",
                lambda rows: rows[4].__setitem__("termination", "ROUTED"),
            ),
            (
                "changed or broke continuity",
                lambda rows: rows[6]["rpc_counters_after"].__setitem__(
                    "rpc_executor_calls",
                    rows[6]["rpc_counters_after"]["rpc_executor_calls"] + 1,
                ),
            ),
        )
        for pattern, mutation in mutations:
            with self.subTest(pattern=pattern):
                report = evidence()
                rows = copy.deepcopy(REALTIME_ROUTE_ROWS)
                mutation(rows)
                raw = jsonl(rows)
                report["tail_verification"]["realtime"]["routes_sha256"] = sha256_bytes(raw)
                with self.assertRaisesRegex(host.HostAdmissionError, pattern):
                    validate_report(report, realtime_raw=raw)

    def test_rejects_wholesale_or_single_candidate_self_report_replacement(self) -> None:
        report = evidence()
        replacement = copy.deepcopy(report["candidate"])
        replacement["cag"].update(
            {
                "commit": "8" * 40,
                "tree": "9" * 40,
                "so_sha256": "a" * 64,
                "store_zip_sha256": "b" * 64,
            }
        )
        replacement["artifacts"].update(
            {
                "candidate_artifact_digest": "sha256:" + "c" * 64,
                "candidate_manifest_sha256": "d" * 64,
                "config_sha256": "e" * 64,
                "evidence_manifest_sha256": "f" * 64,
            }
        )
        report["candidate"] = replacement
        report["tail_verification"]["candidate_artifact_digest"] = replacement[
            "artifacts"
        ]["candidate_artifact_digest"]
        with self.assertRaisesRegex(host.HostAdmissionError, "independently trusted"):
            validate_report(report)

        report = evidence()
        report["candidate"]["cag"]["so_sha256"] = "8" * 64
        with self.assertRaisesRegex(host.HostAdmissionError, "independently trusted"):
            validate_report(report)

    def test_optimized_python_keeps_positive_and_fail_closed_paths(self) -> None:
        source = (TOOL_DIR / "host_admission.py").read_text(encoding="utf-8")
        self.assertNotIn("assert ", source)
        script = f"""
import importlib.util
import pathlib
import sys

path = pathlib.Path({str(Path(__file__).resolve())!r})
spec = importlib.util.spec_from_file_location("host_admission_optimized_fixture", path)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
report = module.evidence()
module.parse_report(module.canonical_evidence(report))
report["extra"] = True
try:
    module.validate_report(report)
except module.host.HostAdmissionError:
    pass
else:
    raise SystemExit("optimized validator accepted an extra field")
"""
        result = subprocess.run(
            [sys.executable, "-O", "-c", script],
            cwd=TOOL_DIR.parent.parent,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=120,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_rejects_extra_fields_at_report_sample_and_tail(self) -> None:
        report = evidence()
        report["extra"] = True
        with self.assertRaisesRegex(host.HostAdmissionError, "exactly"):
            validate_report(report)
        self.assert_rejected(
            lambda _r, rows, _l: rows[0].__setitem__("extra", True),
            "must contain exactly",
        )
        report = evidence()
        report["tail_verification"]["cleanup"]["extra"] = True
        with self.assertRaisesRegex(host.HostAdmissionError, "exactly"):
            validate_report(report)

    def test_rejects_candidate_or_report_identity_drift(self) -> None:
        report = evidence()
        report["candidate"]["cpa"]["rpc_schema"] = 2
        with self.assertRaisesRegex(host.HostAdmissionError, "frozen v7.2.142"):
            validate_report(report)
        report = evidence()
        report["runtime_identity"]["mock"]["init_pid"] = 404
        with self.assertRaisesRegex(host.HostAdmissionError, "runtime_identity drifted"):
            validate_report(report)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
