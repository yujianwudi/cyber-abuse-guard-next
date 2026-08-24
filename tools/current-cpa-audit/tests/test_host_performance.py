from __future__ import annotations

import copy
import contextlib
import io
import json
import os
import stat
import sys
import tempfile
import threading
import time
import tarfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

HERE = Path(__file__).resolve().parent
TOOL = HERE.parent
sys.path.insert(0, str(TOOL))
sys.path.insert(0, str(HERE))

from audit_contract import ContractError, canonical_bytes, sha256_bytes
from host_performance import (
    LinuxHostCollector,
    PLUGIN_ARCHIVE_MAX_BYTES,
    PerformanceError,
    QUEUE_STATUS_PATH,
    _QueueStatusPoller,
    _fail_cell_sampler,
    _validate_plugin_archive,
    _require_logical_cpu_count,
    _require_runtime_secret,
    build_evidence,
    _cpu_delta,
    _docker_arm_specific_mount_projection,
    _docker_comparable_projection,
    _docker_engine_cpu_percent,
    _docker_engine_stats_projection,
    _docker_mount_identity_projection,
    _host_timestamp_value,
    _proc_cpu_values,
    _proc_self_cpu_ticks,
    _validate_mount_backing_identity,
    _validate_arm_specific_backing_equivalence,
    _validate_large_payload_cell,
    main as performance_main,
    parser as performance_parser,
    require_current_tool_identities,
    target_names,
    tool_identities,
    validate_candidate_manifest,
    validate_config,
    validate_evidence_bundle,
    validate_measurements,
    validate_tool_identities,
    validate_workload_manifest,
)
from host_performance_fixtures import (
    candidate_manifest,
    docker_container_info,
    evidence_bundle,
    measurements,
    performance_config,
    retime_measurements,
    run_config,
    workload_manifest,
)
import validate as validator_cli

try:
    from jsonschema import Draft202012Validator
except ImportError:  # pragma: no cover - optional local schema verifier
    Draft202012Validator = None  # type: ignore[assignment]


REAL_TIME_RSS_TEST_SKIP_ENV = "CAG_HOST_PERF_ALLOW_REAL_TIME_RSS_TEST_SKIP"
REAL_TIME_RSS_TEST_SKIP_VALUE = "1"


def _plugin_tar(entries: list[tuple[str, str, bytes | str]]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, kind, value in entries:
            member = tarfile.TarInfo(name)
            member.mtime = 0
            if kind == "directory":
                member.type = tarfile.DIRTYPE
                member.mode = 0o700
                member.size = 0
                archive.addfile(member)
            elif kind == "file":
                assert isinstance(value, bytes)
                member.mode = 0o600
                member.size = len(value)
                archive.addfile(member, io.BytesIO(value))
            elif kind == "symlink":
                assert isinstance(value, str)
                member.type = tarfile.SYMTYPE
                member.linkname = value
                archive.addfile(member)
            elif kind == "hardlink":
                assert isinstance(value, str)
                member.type = tarfile.LNKTYPE
                member.linkname = value
                archive.addfile(member)
            elif kind == "fifo":
                member.type = tarfile.FIFOTYPE
                archive.addfile(member)
            else:  # pragma: no cover - test helper contract
                raise AssertionError(kind)
    return buffer.getvalue()


def _fail_or_skip_real_time_rss_deadline(
    test_case: unittest.TestCase,
    exc: ContractError,
    sampler_error_ids: list[str],
) -> None:
    recorded_sampler_error_ids = list(
        getattr(exc, "sampler_error_ids", ()) or sampler_error_ids
    )
    expected_missed_deadline = (
        type(exc) is PerformanceError
        and str(exc) == "Host performance large-payload RSS sampler failed"
        and recorded_sampler_error_ids == ["large_payload_rss:MissedDeadline"]
    )
    if (
        expected_missed_deadline
        and os.environ.get(REAL_TIME_RSS_TEST_SKIP_ENV)
        == REAL_TIME_RSS_TEST_SKIP_VALUE
    ):
        test_case.skipTest(
            "test-host scheduler stalled beyond the production RSS deadline; "
            f"explicitly allowed by {REAL_TIME_RSS_TEST_SKIP_ENV}="
            f"{REAL_TIME_RSS_TEST_SKIP_VALUE}"
        )
    raise exc


def drifted_tool_identities(
    key: str = "host_performance_source_sha256",
) -> dict[str, str]:
    value = tool_identities()
    value[key] = ("e" if value.get(key) != "e" * 64 else "f") * 64
    sources = {key: item for key, item in value.items() if key != "bundle_sha256"}
    value["bundle_sha256"] = sha256_bytes(canonical_bytes(sources))
    return value


class HostPerformanceContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        (
            cls.good_evidence,
            cls.good_measurements,
            cls.good_measurements_raw,
            cls.good_config,
            cls.good_config_raw,
            cls.good_workload,
            derived,
        ) = evidence_bundle()
        cls.good_summaries = derived["summaries"]
        cls.good_baseline = derived["baseline"]
        cls.good_extra = derived["extra"]

    def test_complete_host_ab_evidence_passes(self) -> None:
        validated = validate_evidence_bundle(
            self.good_evidence,
            self.good_config,
            self.good_config_raw,
            self.good_measurements,
            self.good_measurements_raw,
            self.good_summaries,
            self.good_baseline,
            self.good_extra,
        )
        self.assertEqual(validated["status"], "PASS")
        self.assertEqual(
            [item["concurrency"] for item in validated["comparisons"]],
            [1, 4, 8, 16],
        )
        self.assertGreaterEqual(validated["metrics"]["host_throughput_vs_cpa_only"], 0.90)
        self.assertLess(validated["metrics"]["audit_queue_peak_ratio"], 0.80)
        self.assertLessEqual(validated["metrics"]["warm_rss_growth_60m_mib"], 64)
        large_payload = validated["large_payload_resident_memory"]
        self.assertEqual(large_payload["rss_sample_gap_deadline_ms"], 30)
        self.assertEqual(large_payload["rss_sample_gap_hard_limit_ms"], 60)
        self.assertEqual(large_payload["rss_sample_gap_overrun_limit_per_cell"], 1)
        for comparison in large_payload["comparisons"]:
            self.assertEqual(comparison["cpa_only_rss_max_sample_gap_ms"], 20.0)
            self.assertEqual(comparison["cpa_cag_rss_max_sample_gap_ms"], 20.0)
            self.assertEqual(
                comparison["cpa_only_rss_sample_gap_overrun_count"], 0
            )
            self.assertEqual(
                comparison["cpa_cag_rss_sample_gap_overrun_count"], 0
            )

        partial_queue_summaries = copy.deepcopy(self.good_summaries)
        nullable_group = next(
            (
                summary["phase"],
                summary["workload"],
                summary["concurrency"],
            )
            for summary in partial_queue_summaries
            if summary["arm"] == "cpa_cag" and summary["phase"] != "warm_rss"
        )
        for summary in partial_queue_summaries:
            if (
                summary["arm"] == "cpa_cag"
                and (
                    summary["phase"],
                    summary["workload"],
                    summary["concurrency"],
                )
                == nullable_group
            ):
                summary["queue_peak_depth"] = None
        with self.subTest(queue_ratio="partial-none"):
            partial_queue_evidence = build_evidence(
                self.good_config,
                self.good_config_raw,
                self.good_measurements,
                self.good_measurements_raw,
                partial_queue_summaries,
                self.good_baseline,
                self.good_extra,
            )
            candidate_ratios = [
                row["audit_queue_peak_ratio"]
                for row in partial_queue_evidence["matrix"]
                if row["arm"] == "cpa_cag"
            ]
            self.assertIn(None, candidate_ratios)
            observed_ratios = [
                float(value) for value in candidate_ratios if value is not None
            ]
            self.assertTrue(observed_ratios)
            self.assertEqual(
                partial_queue_evidence["metrics"]["audit_queue_peak_ratio"],
                max(observed_ratios),
            )

        empty_queue_summaries = copy.deepcopy(self.good_summaries)
        for summary in empty_queue_summaries:
            if summary["arm"] == "cpa_cag":
                summary["queue_peak_depth"] = None
        with self.subTest(queue_ratio="all-none"), self.assertRaisesRegex(
            ContractError, r"CPA\+CAG audit queue peak ratio is unavailable"
        ):
            build_evidence(
                self.good_config,
                self.good_config_raw,
                self.good_measurements,
                self.good_measurements_raw,
                empty_queue_summaries,
                self.good_baseline,
                self.good_extra,
            )

    def test_mount_backing_kind_closes_content_digest_semantics(self) -> None:
        file_backing = copy.deepcopy(
            self.good_measurements["paired_cells"][0]["runtime"][
                "mount_identity_projection"
            ]["common_mounts"][0]["backing"]
        )
        directory_backing = copy.deepcopy(file_backing)
        directory_backing["kind"] = "directory"
        directory_backing["content_sha256"] = None
        directory_backing["identity_sha256"] = sha256_bytes(
            canonical_bytes(
                {
                    key: item
                    for key, item in directory_backing.items()
                    if key != "identity_sha256"
                }
            )
        )

        self.assertEqual(
            _validate_mount_backing_identity(file_backing, "file backing"),
            file_backing,
        )
        self.assertEqual(
            _validate_mount_backing_identity(
                directory_backing, "directory backing"
            ),
            directory_backing,
        )

        mutations = (
            ("file", None),
            ("directory", sha256_bytes(b"forged-directory-content")),
        )
        for kind, content_sha256 in mutations:
            forged = copy.deepcopy(file_backing)
            forged["kind"] = kind
            forged["content_sha256"] = content_sha256
            forged["identity_sha256"] = sha256_bytes(
                canonical_bytes(
                    {
                        key: item
                        for key, item in forged.items()
                        if key != "identity_sha256"
                    }
                )
            )
            with self.subTest(kind=kind), self.assertRaisesRegex(
                ContractError, "content_sha256"
            ):
                _validate_mount_backing_identity(forged, f"{kind} backing")

    @unittest.skipIf(Draft202012Validator is None, "jsonschema is not installed")
    def test_mount_backing_schema_closes_content_digest_semantics(self) -> None:
        schema = json.loads(
            (TOOL / "host-performance-evidence.schema.json").read_text("utf-8")
        )
        backing_schema = {
            "$schema": schema["$schema"],
            "$defs": schema["$defs"],
            **schema["$defs"]["mount_backing_identity"],
        }
        Draft202012Validator.check_schema(backing_schema)
        validator = Draft202012Validator(backing_schema)
        file_backing = copy.deepcopy(
            self.good_measurements["paired_cells"][0]["runtime"][
                "mount_identity_projection"
            ]["common_mounts"][0]["backing"]
        )
        directory_backing = copy.deepcopy(file_backing)
        directory_backing["kind"] = "directory"
        directory_backing["content_sha256"] = None
        directory_backing["identity_sha256"] = sha256_bytes(
            canonical_bytes(
                {
                    key: item
                    for key, item in directory_backing.items()
                    if key != "identity_sha256"
                }
            )
        )
        self.assertTrue(validator.is_valid(file_backing))
        self.assertTrue(validator.is_valid(directory_backing))

        mutations = (
            ("file", None),
            ("directory", sha256_bytes(b"forged-directory-content")),
        )
        for kind, content_sha256 in mutations:
            forged = copy.deepcopy(file_backing)
            forged["kind"] = kind
            forged["content_sha256"] = content_sha256
            forged["identity_sha256"] = sha256_bytes(
                canonical_bytes(
                    {
                        key: item
                        for key, item in forged.items()
                        if key != "identity_sha256"
                    }
                )
            )
            with self.subTest(kind=kind):
                self.assertFalse(validator.is_valid(forged))

    def test_tool_identity_manifest_is_closed_and_bundle_bound(self) -> None:
        approved = tool_identities()
        source_files = {
            "acquire_sha256": "acquire.py",
            "audit_contract_sha256": "audit_contract.py",
            "host_performance_schema_sha256": "host-performance-evidence.schema.json",
            "host_performance_source_sha256": "host_performance.py",
            "run_sha256": "run.py",
            "validator_sha256": "validate.py",
            "workload_generator_sha256": "host_performance_workloads.py",
        }
        self.assertEqual(set(approved), {*source_files, "bundle_sha256"})
        for key, filename in source_files.items():
            with self.subTest(mapping=key):
                self.assertEqual(
                    approved[key], sha256_bytes((TOOL / filename).read_bytes())
                )
        self.assertEqual(
            validate_tool_identities(approved, "approved tools"), approved
        )
        mutations = {
            "missing": lambda value: value.pop("validator_sha256"),
            "extra": lambda value: value.__setitem__("unexpected_sha256", "f" * 64),
            "zero": lambda value: value.__setitem__(
                "audit_contract_sha256", "0" * 64
            ),
            "source_without_bundle": lambda value: value.__setitem__(
                "host_performance_source_sha256", "e" * 64
            ),
            "bundle": lambda value: value.__setitem__("bundle_sha256", "f" * 64),
        }
        for label, mutate in mutations.items():
            value = copy.deepcopy(approved)
            mutate(value)
            with self.subTest(label=label), self.assertRaises(ContractError):
                validate_tool_identities(value, "approved tools")

        for key in source_files:
            with self.subTest(single_dependency_drift=key), self.assertRaisesRegex(
                ContractError, "drifted"
            ):
                require_current_tool_identities(
                    drifted_tool_identities(key), "single-dependency drift"
                )

    def test_config_measurements_and_evidence_bind_one_approved_tool_identity(self) -> None:
        approved = self.good_config["approved_tool_identities"]
        self.assertEqual(self.good_measurements["collector_tool_identities"], approved)
        for key, expected in approved.items():
            self.assertEqual(self.good_evidence["artifacts"][key], expected)

        measurement = copy.deepcopy(self.good_measurements)
        measurement["collector_tool_identities"] = drifted_tool_identities()
        with self.assertRaisesRegex(ContractError, "tool identities drifted"):
            validate_measurements(
                measurement,
                canonical_bytes(measurement) + b"\n",
                self.good_config,
                self.good_config_raw,
                self.good_workload,
            )

        (
            config,
            _,
            run,
            run_raw,
            candidate,
            candidate_raw,
            _,
            workload_raw,
        ) = performance_config()
        with (
            mock.patch(
                "host_performance.tool_identities",
                return_value=drifted_tool_identities(),
            ),
            self.assertRaisesRegex(ContractError, "current tool bytes"),
        ):
            validate_config(
                config,
                run,
                run_raw,
                candidate,
                candidate_raw,
                workload_raw,
            )

    def test_collector_rejects_approved_identity_mismatch_before_importing_run(
        self,
    ) -> None:
        config = copy.deepcopy(self.good_config)
        config["approved_tool_identities"] = drifted_tool_identities(
            "acquire_sha256"
        )
        docker_factory = mock.Mock(name="Docker")
        fake_run = SimpleNamespace(Docker=docker_factory)

        with (
            mock.patch("host_performance.platform.system", return_value="Linux"),
            mock.patch("host_performance.platform.machine", return_value="x86_64"),
            mock.patch("host_performance.os.getuid", return_value=1000, create=True),
            mock.patch("host_performance.os.getgid", return_value=1000, create=True),
            mock.patch("host_performance.os.cpu_count", return_value=8),
            mock.patch.object(LinuxHostCollector, "_load_workloads", return_value={}),
            mock.patch.dict(sys.modules, {"run": fake_run}),
            mock.patch("builtins.__import__", wraps=__import__) as importer,
            self.assertRaisesRegex(ContractError, "tool identities drifted"),
        ):
            LinuxHostCollector(
                config,
                self.good_config_raw,
                self.good_workload,
                Path("unused"),
                collector_tool_identities=tool_identities(),
                client_key="c" * 32,
                management_key="g" * 32,
                mock_control_token="m" * 32,
            )

        self.assertFalse(
            any(call.args and call.args[0] == "run" for call in importer.mock_calls)
        )
        docker_factory.assert_not_called()

    def test_collector_rechecks_identity_after_run_import_before_docker(
        self,
    ) -> None:
        approved = tool_identities()
        docker_factory = mock.Mock(name="Docker")
        fake_run = SimpleNamespace(Docker=docker_factory)

        with (
            mock.patch("host_performance.platform.system", return_value="Linux"),
            mock.patch("host_performance.platform.machine", return_value="x86_64"),
            mock.patch("host_performance.os.getuid", return_value=1000, create=True),
            mock.patch("host_performance.os.getgid", return_value=1000, create=True),
            mock.patch("host_performance.os.cpu_count", return_value=8),
            mock.patch.object(LinuxHostCollector, "_load_workloads", return_value={}),
            mock.patch.dict(sys.modules, {"run": fake_run}),
            mock.patch(
                "host_performance.tool_identities",
                side_effect=[approved, drifted_tool_identities("run_sha256")],
            ),
            mock.patch("builtins.__import__", wraps=__import__) as importer,
            self.assertRaisesRegex(ContractError, "run import completion"),
        ):
            LinuxHostCollector(
                self.good_config,
                self.good_config_raw,
                self.good_workload,
                Path("unused"),
                collector_tool_identities=approved,
                client_key="c" * 32,
                management_key="g" * 32,
                mock_control_token="m" * 32,
            )

        self.assertTrue(
            any(call.args and call.args[0] == "run" for call in importer.mock_calls)
        )
        docker_factory.assert_not_called()

    def test_collector_preflights_secret_and_logical_cpu_contracts(self) -> None:
        for value in (None, 0, -1, True):
            with (
                self.subTest(logical_cpu_count=value),
                mock.patch("host_performance.os.cpu_count", return_value=value),
                self.assertRaisesRegex(ContractError, "logical CPU count"),
            ):
                _require_logical_cpu_count()
        with mock.patch("host_performance.os.cpu_count", return_value=8):
            self.assertEqual(_require_logical_cpu_count(), 8)

        for label, value in (
            ("missing", ""),
            ("short", "x" * 31),
            ("newline", "x" * 31 + "\n"),
            ("non-string", 32),
        ):
            with self.subTest(secret=label), self.assertRaisesRegex(
                ContractError, "at least 32 characters"
            ):
                _require_runtime_secret(value, "test key")
        self.assertEqual(_require_runtime_secret("x" * 32, "test key"), "x" * 32)

    def test_config_rejects_negative_seed(self) -> None:
        (
            config,
            _,
            run,
            run_raw,
            candidate,
            candidate_raw,
            _,
            workload_raw,
        ) = performance_config()
        config["plan"]["seed"] = -1
        with self.assertRaisesRegex(ContractError, "plan.seed"):
            validate_config(
                config,
                run,
                run_raw,
                candidate,
                candidate_raw,
                workload_raw,
            )

    def test_collector_derives_closed_target_names_and_parses_host_counters(self) -> None:
        self.assertEqual(
            target_names("unit-run"),
            {
                "cpa_only": "unit-run-perf-cpa-only",
                "cpa_cag": "unit-run-perf-cpa-cag",
                "mock": "unit-run-perf-mock",
                "network": "unit-run-perf-net",
            },
        )
        projected = _docker_engine_stats_projection(
            {
                "id": "a" * 64,
                "name": "/unit-container",
                "cpu_stats": {
                    "cpu_usage": {"total_usage": 125},
                    "online_cpus": 4,
                    "system_cpu_usage": 1_200,
                },
                "memory_stats": {
                    "stats": {"inactive_file": 24 * 1024 * 1024},
                    "usage": 128 * 1024 * 1024,
                },
            },
            expected_id="a" * 64,
            expected_name="unit-container",
            logical_cpu_count=4,
        )
        self.assertEqual(projected, (125, 1_200, 4, 104.0))
        self.assertEqual(_docker_engine_cpu_percent((100, 1_000), projected), 50.0)
        first = _proc_cpu_values("cpu  10 0 5 80 5 0 0 0 0 0\n")
        second = _proc_cpu_values("cpu  30 0 5 140 5 0 0 5 0 0\n")
        busy, steal = _cpu_delta(first, second)
        self.assertGreater(busy, 0)
        self.assertGreater(steal, 0)
        # guest/guest_nice are already included in Linux user/nice and must not
        # inflate the aggregate denominator a second time.
        self.assertEqual(
            _proc_cpu_values("cpu  100 20 30 40 5 6 7 8 50 10\n"),
            (216, 45, 8),
        )
        self.assertEqual(
            _proc_self_cpu_ticks(
                "123 (collector with spaces) R 1 2 3 4 5 6 7 8 9 10 11 12 13 14\n"
            ),
            50,
        )
        parsed = performance_parser().parse_args(
            [
                "collect",
                "--run-config",
                "run-config.json",
                "--candidate-manifest",
                "candidate.json",
                "--workload-manifest",
                "workloads.json",
                "--config",
                "performance-config.json",
                "--workload-root",
                "workloads",
                "--output",
                "measurements.json",
            ]
        )
        self.assertEqual(parsed.command, "collect")
        self.assertEqual(parsed.output, Path("measurements.json"))

    def test_collector_schedule_covers_exact_seeded_matrix(self) -> None:
        collector = object.__new__(LinuxHostCollector)
        collector.config = self.good_config
        collector.config_raw = self.good_config_raw
        collector.collector_tool_identities = dict(
            self.good_config["approved_tool_identities"]
        )
        collector._preflight = mock.Mock(
            return_value={
                "background_cpu_percent": [0.0] * 300,
                "sample_interval_seconds": 1,
                "steal_cpu_percent": [0.0] * 300,
            }
        )
        collector._measure_cell = mock.Mock(
            side_effect=lambda arm, workload, concurrency, repetition, phase, order: {
                "arm": arm,
                "workload": workload,
                "concurrency": concurrency,
                "repetition": repetition,
                "phase": phase,
                "order_index": order,
            }
        )
        collector._measure_large_payload_cell = mock.Mock(
            side_effect=lambda arm, repetition, order: {
                "arm": arm,
                "repetition": repetition,
                "order_index": order,
            }
        )
        collector._measure_warm_rss = mock.Mock(return_value={"lane": "warm"})
        collector._host_identity = mock.Mock(return_value={"host": "unit"})
        result = collector.collect()
        self.assertEqual(len(result["paired_cells"]), 24)
        self.assertEqual(len(result["absolute_cells"]), 72)
        self.assertEqual(len(result["large_payload_cells"]), 6)
        self.assertEqual(result["warm_rss"], {"lane": "warm"})
        for index in range(0, len(result["paired_cells"]), 2):
            pair = result["paired_cells"][index : index + 2]
            self.assertEqual({item["arm"] for item in pair}, {"cpa_only", "cpa_cag"})
            self.assertEqual([item["order_index"] for item in pair], [0, 1])

    def test_collector_final_sample_observes_host_and_steal_cpu(self) -> None:
        collector = object.__new__(LinuxHostCollector)
        collector.config = self.good_config
        collector._docker_stats = mock.Mock(
            return_value=(12.5, 101.0, 5.0, 2.5)
        )
        resources: list[dict[str, float]] = []
        cpu_state = [(100, 50, 0)]
        process_cpu_state = [10]
        with (
            mock.patch(
                "host_performance._read_proc_cpu", return_value=(200, 100, 5)
            ),
            mock.patch("host_performance._read_self_cpu_ticks", return_value=10),
        ):
            collector._append_final_samples(
                "cpa_only",
                time.monotonic() - 0.1,
                resources,
                [],
                cpu_state,
                process_cpu_state,
                warm=False,
            )
        self.assertEqual(len(resources), 1)
        self.assertEqual(
            set(resources[0]),
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
        )
        self.assertEqual(resources[0]["host_cpu_percent"], 50.0)
        self.assertEqual(resources[0]["steal_cpu_percent"], 5.0)
        self.assertTrue(resources[0]["final_sample"])

    def test_docker_engine_stats_binds_exact_three_target_identities(self) -> None:
        collector = object.__new__(LinuxHostCollector)
        collector.logical_cpu_count = 4
        collector.names = {
            "cpa_only": "unit-run-perf-cpa-only",
            "cpa_cag": "unit-run-perf-cpa-cag",
            "mock": "unit-run-perf-mock",
        }
        collector.container_infos = {
            "cpa_only": {"Id": "a" * 64},
            "cpa_cag": {"Id": "b" * 64},
        }
        collector.mock_info = {"Id": "c" * 64}
        collector._docker_stats_previous = {
            collector.names["cpa_only"]: (100, 1_000),
            collector.names["cpa_cag"]: (100, 1_000),
            collector.names["mock"]: (100, 1_000),
        }
        collector._docker_engine_stats = mock.Mock(
            side_effect=[
                (110, 1_100, 4, 100.0),
                (120, 1_100, 4, 110.0),
                (105, 1_100, 4, 50.0),
            ]
        )
        self.assertEqual(
            collector._docker_stats("cpa_cag"), (80.0, 110.0, 20.0, 40.0)
        )
        self.assertEqual(
            collector._docker_engine_stats.mock_calls,
            [
                mock.call(collector.names["cpa_only"], "a" * 64),
                mock.call(collector.names["cpa_cag"], "b" * 64),
                mock.call(collector.names["mock"], "c" * 64),
            ],
        )

        collector.mock_info = {"Id": "short"}
        with self.assertRaisesRegex(ContractError, "target identity"):
            collector._docker_stats("cpa_cag")

        self._assert_docker_engine_initializes_all_three_counter_baselines()
        self._assert_docker_engine_projection_rejects_identity_and_counter_drift()
        self._assert_docker_engine_cpu_rejects_nonadvancing_counters()
        self._assert_docker_stats_socket_contract_and_identity_drift()
        self._assert_docker_engine_request_is_bounded_and_fail_closed()

    def _assert_docker_engine_initializes_all_three_counter_baselines(self) -> None:
        collector = object.__new__(LinuxHostCollector)
        collector.logical_cpu_count = 4
        collector.names = {
            "cpa_only": "unit-run-perf-cpa-only",
            "cpa_cag": "unit-run-perf-cpa-cag",
            "mock": "unit-run-perf-mock",
        }
        collector.container_infos = {
            "cpa_only": {"Id": "a" * 64},
            "cpa_cag": {"Id": "b" * 64},
        }
        collector.mock_info = {"Id": "c" * 64}
        collector._docker_stats_previous = {"stale": (1, 2)}
        collector._reset_docker_stats_baseline()
        self.assertEqual(collector._docker_stats_previous, {})
        collector._docker_engine_stats = mock.Mock(
            side_effect=[
                (100, 1_000, 4, 90.0),
                (200, 2_000, 4, 100.0),
                (300, 3_000, 4, 40.0),
                (110, 1_100, 4, 91.0),
                (220, 2_100, 4, 101.0),
                (305, 3_100, 4, 41.0),
            ]
        )
        with mock.patch("host_performance.time.sleep") as sleeper:
            self.assertEqual(
                collector._docker_stats("cpa_cag"), (80.0, 101.0, 20.0, 40.0)
            )
        sleeper.assert_called_once_with(0.02)
        self.assertEqual(collector._docker_engine_stats.call_count, 6)
        self.assertEqual(
            collector._docker_stats_previous,
            {
                collector.names["cpa_only"]: (110, 1_100),
                collector.names["cpa_cag"]: (220, 2_100),
                collector.names["mock"]: (305, 3_100),
            },
        )

    def _assert_docker_engine_projection_rejects_identity_and_counter_drift(self) -> None:
        base = {
            "id": "a" * 64,
            "name": "/unit-container",
            "cpu_stats": {
                "cpu_usage": {"total_usage": 125},
                "online_cpus": 4,
                "system_cpu_usage": 1_200,
            },
            "memory_stats": {
                "stats": {"inactive_file": 24},
                "usage": 128,
            },
        }
        cases: dict[str, tuple[object, str]] = {
            "not_object": ([], "invalid object"),
            "wrong_id": ({**base, "id": "b" * 64}, "wrong container identity"),
            "wrong_name": ({**base, "name": "/other"}, "wrong container identity"),
            "missing_cpu": ({**base, "cpu_stats": None}, "omitted CPU or memory"),
            "missing_cpu_usage": (
                {**base, "cpu_stats": {"system_cpu_usage": 1_200}},
                "omitted container CPU usage",
            ),
            "negative_total": (
                {
                    **base,
                    "cpu_stats": {
                        **base["cpu_stats"],
                        "cpu_usage": {"total_usage": -1},
                    },
                },
                "CPU counters are invalid",
            ),
            "too_many_online_cpus": (
                {
                    **base,
                    "cpu_stats": {**base["cpu_stats"], "online_cpus": 5},
                },
                "CPU counters are invalid",
            ),
            "negative_memory": (
                {**base, "memory_stats": {"stats": {}, "usage": -1}},
                "memory counters are invalid",
            ),
            "inactive_above_usage": (
                {
                    **base,
                    "memory_stats": {"stats": {"inactive_file": 129}, "usage": 128},
                },
                "inactive-file counter is invalid",
            ),
        }
        for label, (value, error) in cases.items():
            with self.subTest(case=label), self.assertRaisesRegex(ContractError, error):
                _docker_engine_stats_projection(
                    value,
                    expected_id="a" * 64,
                    expected_name="unit-container",
                    logical_cpu_count=4,
                )

        percpu_fallback = copy.deepcopy(base)
        percpu_fallback["cpu_stats"].pop("online_cpus")
        percpu_fallback["cpu_stats"]["cpu_usage"]["percpu_usage"] = [1, 2, 3, 4]
        self.assertEqual(
            _docker_engine_stats_projection(
                percpu_fallback,
                expected_id="a" * 64,
                expected_name="unit-container",
                logical_cpu_count=4,
            ),
            (125, 1_200, 4, (128 - 24) / (1024.0 * 1024.0)),
        )

    def _assert_docker_engine_cpu_rejects_nonadvancing_counters(self) -> None:
        for label, previous, current in (
            ("container_regression", (101, 1_000), (100, 1_100, 4, 1.0)),
            ("system_regression", (100, 1_101), (101, 1_100, 4, 1.0)),
            ("system_zero_delta", (100, 1_100), (101, 1_100, 4, 1.0)),
        ):
            with self.subTest(case=label), self.assertRaisesRegex(
                ContractError, "moved backwards or did not advance"
            ):
                _docker_engine_cpu_percent(previous, current)

    def _assert_docker_stats_socket_contract_and_identity_drift(self) -> None:
        valid = SimpleNamespace(
            st_mode=stat.S_IFSOCK | 0o660,
            st_nlink=1,
            st_uid=0,
            st_gid=999,
            st_dev=42,
            st_ino=84,
        )
        with (
            mock.patch("host_performance.os.lstat", return_value=valid),
            mock.patch("host_performance.os.access", return_value=True),
        ):
            self.assertEqual(
                LinuxHostCollector._require_docker_stats_socket(),
                (42, 84, 0, 999, 0o660),
            )

        invalid = {
            "not_socket": SimpleNamespace(**{**vars(valid), "st_mode": stat.S_IFREG | 0o660}),
            "multiple_links": SimpleNamespace(**{**vars(valid), "st_nlink": 2}),
            "non_root_owner": SimpleNamespace(**{**vars(valid), "st_uid": 1000}),
            "world_accessible": SimpleNamespace(**{**vars(valid), "st_mode": stat.S_IFSOCK | 0o666}),
            "group_not_rw": SimpleNamespace(**{**vars(valid), "st_mode": stat.S_IFSOCK | 0o640}),
        }
        for label, info in invalid.items():
            with (
                self.subTest(case=label),
                mock.patch("host_performance.os.lstat", return_value=info),
                mock.patch("host_performance.os.access", return_value=True),
                self.assertRaisesRegex(ContractError, "root-owned, private"),
            ):
                LinuxHostCollector._require_docker_stats_socket()
        with (
            mock.patch("host_performance.os.lstat", side_effect=FileNotFoundError),
            self.assertRaisesRegex(ContractError, "socket is unavailable"),
        ):
            LinuxHostCollector._require_docker_stats_socket()
        with (
            mock.patch("host_performance.os.lstat", return_value=valid),
            mock.patch("host_performance.os.access", return_value=False),
            self.assertRaisesRegex(ContractError, "runner-accessible"),
        ):
            LinuxHostCollector._require_docker_stats_socket()

        collector = object.__new__(LinuxHostCollector)
        collector._docker_stats_socket_identity = (42, 84, 0, 999, 0o660)
        with (
            mock.patch.object(
                LinuxHostCollector,
                "_require_docker_stats_socket",
                return_value=(42, 85, 0, 999, 0o660),
            ),
            self.assertRaisesRegex(ContractError, "identity drifted"),
        ):
            collector._verify_docker_stats_socket()

    def _assert_docker_engine_request_is_bounded_and_fail_closed(self) -> None:
        collector = object.__new__(LinuxHostCollector)
        collector.logical_cpu_count = 4
        collector._verify_docker_stats_socket = mock.Mock()
        valid_body = json.dumps(
            {
                "id": "a" * 64,
                "name": "/unit-container",
                "cpu_stats": {
                    "cpu_usage": {"total_usage": 125},
                    "online_cpus": 4,
                    "system_cpu_usage": 1_200,
                },
                "memory_stats": {"stats": {"inactive_file": 24}, "usage": 128},
            }
        ).encode()

        def connection_for(
            *,
            status: int = 200,
            content_type: str = "application/json; charset=utf-8",
            body: bytes = valid_body,
            request_error: BaseException | None = None,
        ) -> SimpleNamespace:
            response = SimpleNamespace(
                status=status,
                read=mock.Mock(return_value=body),
                getheader=mock.Mock(return_value=content_type),
            )
            connection = SimpleNamespace(
                request=mock.Mock(side_effect=request_error),
                getresponse=mock.Mock(return_value=response),
                close=mock.Mock(),
            )
            return SimpleNamespace(connection=connection, response=response)

        success = connection_for()
        with mock.patch(
            "host_performance._DockerUnixHTTPConnection",
            return_value=success.connection,
        ) as factory:
            self.assertEqual(
                collector._docker_engine_stats("unit-container", "a" * 64),
                (125, 1_200, 4, (128 - 24) / (1024.0 * 1024.0)),
            )
        factory.assert_called_once_with(Path("/var/run/docker.sock"))
        success.connection.request.assert_called_once_with(
            "GET",
            "/v1.44/containers/" + "a" * 64 + "/stats?stream=false&one-shot=true",
            headers={"Accept": "application/json", "Connection": "close"},
        )
        success.response.read.assert_called_once_with(16 * 1024 * 1024 + 1)
        success.connection.close.assert_called_once_with()
        self.assertEqual(collector._verify_docker_stats_socket.call_count, 2)

        cases = {
            "http_status": connection_for(status=500),
            "content_type": connection_for(content_type="text/plain"),
            "oversized": connection_for(body=b"x" * (16 * 1024 * 1024 + 1)),
            "bad_json": connection_for(body=b"{"),
            "bad_utf8": connection_for(body=b"\xff"),
            "request_error": connection_for(request_error=OSError("closed")),
        }
        for label, item in cases.items():
            with (
                self.subTest(case=label),
                mock.patch(
                    "host_performance._DockerUnixHTTPConnection",
                    return_value=item.connection,
                ),
                self.assertRaises(ContractError),
            ):
                collector._docker_engine_stats("unit-container", "a" * 64)
            item.connection.close.assert_called_once_with()

    def test_plugin_archive_accepts_empty_baseline_and_exact_candidate(self) -> None:
        so_name = "cyber-abuse-guard-v1.0.0.so"
        so_bytes = b"exact nested candidate SO bytes"
        baseline = _plugin_tar([])
        candidate = _plugin_tar(
            [
                (".", "directory", b""),
                ("linux", "directory", b""),
                ("linux/amd64", "directory", b""),
                (f"linux/amd64/{so_name}", "file", so_bytes),
            ]
        )
        self.assertIsNone(
            _validate_plugin_archive(
                baseline,
                artifact_name=None,
                expected_sha256=None,
            )
        )
        self.assertEqual(
            _validate_plugin_archive(
                candidate,
                artifact_name=so_name,
                expected_sha256=sha256_bytes(so_bytes),
            ),
            sha256_bytes(so_bytes),
        )

    def test_plugin_archive_rejects_unsafe_members_and_non_exact_sets(self) -> None:
        so_name = "cyber-abuse-guard-v1.0.0.so"
        so_bytes = b"candidate"
        expected = f"linux/amd64/{so_name}"
        cases = {
            "absolute": [(f"/{expected}", "file", so_bytes)],
            "traversal": [(f"linux/../{so_name}", "file", so_bytes)],
            "duplicate": [
                (expected, "file", so_bytes),
                (expected, "file", so_bytes),
            ],
            "symlink": [(expected, "symlink", "elsewhere")],
            "hardlink": [(expected, "hardlink", "elsewhere")],
            "fifo": [(expected, "fifo", b"")],
            "extra_file": [
                (expected, "file", so_bytes),
                ("unexpected.txt", "file", b"extra"),
            ],
            "extra_directory": [
                ("unexpected", "directory", b""),
                (expected, "file", so_bytes),
            ],
        }
        for label, entries in cases.items():
            with self.subTest(label=label), self.assertRaises(ContractError):
                _validate_plugin_archive(
                    _plugin_tar(entries),
                    artifact_name=so_name,
                    expected_sha256=sha256_bytes(so_bytes),
                )

    def test_plugin_archive_rejects_hash_format_size_and_terminator_drift(self) -> None:
        so_name = "cyber-abuse-guard-v1.0.0.so"
        raw = _plugin_tar([(f"linux/amd64/{so_name}", "file", b"candidate")])
        invalid = (
            (raw, sha256_bytes(b"wrong"), PLUGIN_ARCHIVE_MAX_BYTES),
            (b"not-a-tar", sha256_bytes(b"candidate"), PLUGIN_ARCHIVE_MAX_BYTES),
            (raw + (b"X" * 512), sha256_bytes(b"candidate"), PLUGIN_ARCHIVE_MAX_BYTES),
            (raw, sha256_bytes(b"candidate"), len(raw) - 1),
        )
        for archive, expected_sha256, maximum in invalid:
            with self.subTest(maximum=maximum), self.assertRaises(ContractError):
                _validate_plugin_archive(
                    archive,
                    artifact_name=so_name,
                    expected_sha256=expected_sha256,
                    maximum_bytes=maximum,
                )

    def test_collector_hashes_bounded_docker_tar_stream_without_extracting(self) -> None:
        collector = object.__new__(LinuxHostCollector)
        collector.config = copy.deepcopy(self.good_config)
        candidate = collector.config["identities"]["candidate"]
        self.assertNotIn("artifact_name", candidate)
        so_name = candidate["so"]["name"]
        so_bytes = b"exact nested candidate SO bytes"
        collector.config["identities"]["cag"]["so_sha256"] = sha256_bytes(so_bytes)
        collector.names = {
            "cpa_only": "unit-cpa-only",
            "cpa_cag": "unit-cpa-cag",
        }
        baseline = _plugin_tar([])
        candidate_tar = _plugin_tar(
            [(f"linux/amd64/{so_name}", "file", so_bytes)]
        )
        results = iter(
            [
                SimpleNamespace(returncode=0, stdout=baseline, stderr=b""),
                SimpleNamespace(returncode=0, stdout=candidate_tar, stderr=b""),
            ]
        )
        collector.docker = SimpleNamespace(
            run_binary=mock.Mock(side_effect=lambda *_args, **_kwargs: next(results))
        )

        with mock.patch.object(
            tarfile.TarFile,
            "extractall",
            side_effect=AssertionError("plugin tar must never be extracted"),
        ):
            collector._verify_plugin_bytes()

        self.assertEqual(
            collector.observed_cag_so_sha256,
            collector.config["identities"]["cag"]["so_sha256"],
        )
        self.assertEqual(
            [call.args[0] for call in collector.docker.run_binary.call_args_list],
            [
                ["cp", "unit-cpa-only:/cag/plugins/.", "-"],
                ["cp", "unit-cpa-cag:/cag/plugins/.", "-"],
            ],
        )
        self.assertTrue(
            all(
                call.kwargs["max_stdout_bytes"] == PLUGIN_ARCHIVE_MAX_BYTES
                for call in collector.docker.run_binary.call_args_list
            )
        )

    def test_collector_fails_closed_on_docker_archive_errors(self) -> None:
        collector = object.__new__(LinuxHostCollector)
        collector.config = copy.deepcopy(self.good_config)
        collector.names = {"cpa_only": "unit-cpa-only", "cpa_cag": "unit-cpa-cag"}
        collector.docker = SimpleNamespace(
            run_binary=mock.Mock(
                return_value=SimpleNamespace(
                    returncode=2,
                    stdout=b"",
                    stderr=b"permission denied",
                )
            )
        )
        with self.assertRaisesRegex(ContractError, "could not be verified"):
            collector._verify_plugin_bytes()

        collector.docker.run_binary.side_effect = [
            SimpleNamespace(
                returncode=1,
                stdout=b"",
                stderr=b"no such file or directory",
            ),
            SimpleNamespace(returncode=2, stdout=b"", stderr=b"copy failed"),
        ]
        with self.assertRaisesRegex(ContractError, "could not be read"):
            collector._verify_plugin_bytes()

    def test_sampler_threads_record_runtime_audit_failures(self) -> None:
        class RuntimeAuditFailure(RuntimeError):
            pass

        collector = object.__new__(LinuxHostCollector)
        collector.config = self.good_config
        collector.audit_run = SimpleNamespace(AuditFailure=RuntimeAuditFailure)
        collector._docker_stats = mock.Mock(
            side_effect=RuntimeAuditFailure("stats failed")
        )
        resource_stop = threading.Event()
        resource_errors: list[str] = []
        collector._sample_loop(
            "cpa_only",
            time.monotonic(),
            resource_stop,
            [],
            [],
            resource_errors,
            [(100, 50, 0)],
            [0],
            warm=False,
        )
        self.assertTrue(resource_stop.is_set())
        self.assertEqual(resource_errors, ["resource_sample:RuntimeAuditFailure"])

        queue_poller = SimpleNamespace(
            snapshot=mock.Mock(side_effect=RuntimeAuditFailure("queue failed")),
            close=mock.Mock(),
        )
        collector._queue_poller = mock.Mock(return_value=queue_poller)
        queue_stop = threading.Event()
        queue_errors: list[str] = []
        collector._queue_loop(
            time.monotonic(), queue_stop, [], queue_errors
        )
        self.assertTrue(queue_stop.is_set())
        self.assertEqual(queue_errors, ["queue_sample:RuntimeAuditFailure"])
        queue_poller.close.assert_called_once_with()
        self._assert_queue_status_poller_reuses_one_private_connection()
        self._assert_queue_status_poller_rejects_public_or_closing_connections()

    def _assert_queue_status_poller_reuses_one_private_connection(self) -> None:
        status = canonical_bytes(
            {
                "audit": {
                    "degraded": False,
                    "healthy": True,
                    "queue_capacity": 4096,
                    "queue_depth": 7,
                }
            }
        )

        class Response:
            status = 200
            will_close = False

            def read(self, _limit: int) -> bytes:
                return status

        class Connection:
            def __init__(self, host: str, port: int, *, timeout: float) -> None:
                self.host = host
                self.port = port
                self.timeout = timeout
                self.requests: list[tuple[str, str, dict[str, str]]] = []
                self.closed = False

            def request(
                self, method: str, path: str, *, headers: dict[str, str]
            ) -> None:
                self.requests.append((method, path, headers))

            def getresponse(self) -> Response:
                return Response()

            def close(self) -> None:
                self.closed = True

        connections: list[Connection] = []

        def factory(host: str, port: int, *, timeout: float) -> Connection:
            connection = Connection(host, port, timeout=timeout)
            connections.append(connection)
            return connection

        poller = _QueueStatusPoller(
            "http://172.31.250.2:8317",
            {"Authorization": "Bearer unit-management-key"},
            0.1,
            connection_factory=factory,
        )
        self.assertEqual(poller.snapshot(), (7, 4096))
        self.assertEqual(poller.snapshot(), (7, 4096))
        poller.close()

        self.assertEqual(len(connections), 1)
        connection = connections[0]
        self.assertEqual((connection.host, connection.port), ("172.31.250.2", 8317))
        self.assertEqual(connection.timeout, 0.1)
        self.assertEqual(len(connection.requests), 2)
        self.assertTrue(
            all(
                method == "GET"
                and path == QUEUE_STATUS_PATH
                and headers["Connection"] == "keep-alive"
                for method, path, headers in connection.requests
            )
        )
        self.assertTrue(connection.closed)

    def _assert_queue_status_poller_rejects_public_or_closing_connections(self) -> None:
        with self.assertRaisesRegex(ContractError, "outside the private bridge"):
            _QueueStatusPoller("http://203.0.113.5:8317", {}, 0.1)

        response = SimpleNamespace(
            status=200,
            will_close=True,
            read=lambda _limit: canonical_bytes(
                {
                    "audit": {
                        "degraded": False,
                        "healthy": True,
                        "queue_capacity": 4096,
                        "queue_depth": 0,
                    }
                }
            ),
        )
        connection = SimpleNamespace(
            request=mock.Mock(),
            getresponse=mock.Mock(return_value=response),
            close=mock.Mock(),
        )
        poller = _QueueStatusPoller(
            "http://172.31.250.2:8317",
            {},
            0.1,
            connection_factory=lambda *_args, **_kwargs: connection,
        )
        with self.assertRaisesRegex(ContractError, "did not retain"):
            poller.snapshot()
        poller.close()
        connection.close.assert_called_once_with()

        nonfinite_response = SimpleNamespace(
            status=200,
            will_close=False,
            read=lambda _limit: b'{"audit":{"degraded":false,"healthy":true,'
            b'"queue_capacity":4096,"queue_depth":0},"extra":NaN}',
        )
        nonfinite_connection = SimpleNamespace(
            request=mock.Mock(),
            getresponse=mock.Mock(return_value=nonfinite_response),
            close=mock.Mock(),
        )
        nonfinite_poller = _QueueStatusPoller(
            "http://172.31.250.2:8317",
            {},
            0.1,
            connection_factory=lambda *_args, **_kwargs: nonfinite_connection,
        )
        with self.assertRaisesRegex(ContractError, "contains 'NaN'"):
            nonfinite_poller.snapshot()
        nonfinite_poller.close()
        nonfinite_connection.close.assert_called_once_with()

    def test_cell_sampler_failure_retains_safe_error_ids(self) -> None:
        with self.assertRaisesRegex(
            PerformanceError, "Host performance cell sampler failed"
        ) as caught:
            _fail_cell_sampler(["queue_sample:MissedDeadline"])

        self.assertEqual(
            caught.exception.sampler_error_ids,
            ("queue_sample:MissedDeadline",),
        )

    def test_main_reports_safe_sampler_error_ids(self) -> None:
        arguments = [
            "collect",
            "--run-config",
            "run-config.json",
            "--candidate-manifest",
            "candidate-manifest.json",
            "--workload-manifest",
            "workload-manifest.json",
            "--config",
            "host-performance-config.json",
            "--workload-root",
            "workloads",
            "--output",
            "measurements.json",
        ]
        stderr = io.StringIO()
        failure = PerformanceError(
            "Host performance cell sampler failed",
            sampler_error_ids=("resource_sample:MissedDeadline",),
        )
        with (
            mock.patch("host_performance._canonical_file", side_effect=failure),
            contextlib.redirect_stderr(stderr),
        ):
            self.assertEqual(performance_main(arguments), 2)

        self.assertEqual(
            stderr.getvalue(),
            "HOST PERFORMANCE FAILED: Host performance cell sampler failed; "
            "sampler_error_ids=resource_sample:MissedDeadline\n",
        )

        stderr = io.StringIO()
        unsafe_failure = PerformanceError(
            "Host performance cell sampler failed",
            sampler_error_ids=("queue_sample:Bad\nInjected",),
        )
        with (
            mock.patch(
                "host_performance._canonical_file", side_effect=unsafe_failure
            ),
            contextlib.redirect_stderr(stderr),
        ):
            self.assertEqual(performance_main(arguments), 2)

        self.assertEqual(
            stderr.getvalue(),
            "HOST PERFORMANCE FAILED: Host performance cell sampler failed\n",
        )

    def test_large_payload_rss_sampler_has_one_bounded_gap_tolerance(self) -> None:
        class FakeClock:
            def __init__(self) -> None:
                self.current = 0.0

            def monotonic(self) -> float:
                return self.current

            def sleep(self, seconds: float) -> None:
                self.current += seconds

        collector = object.__new__(LinuxHostCollector)
        collector.config = self.good_config

        def run_sampler(
            elapsed_samples: list[float],
            *,
            initial_sample_gap_overruns: int = 0,
            stop_after_last_sample: bool = False,
        ) -> tuple[list[dict[str, object]], list[str], threading.Event]:
            clock = FakeClock()
            stop = threading.Event()
            rows: list[dict[str, object]] = [{"elapsed_ms": 0.0}]
            errors: list[str] = []
            observations = iter(elapsed_samples)

            def observe(*_args, **_kwargs) -> dict[str, object]:
                elapsed_ms = next(observations)
                if stop_after_last_sample and elapsed_ms == elapsed_samples[-1]:
                    stop.set()
                return {"elapsed_ms": elapsed_ms}

            collector._rss_observation = observe
            with (
                mock.patch("host_performance.time.monotonic", clock.monotonic),
                mock.patch("host_performance.time.sleep", clock.sleep),
            ):
                collector._large_payload_rss_loop(
                    "cpa_only",
                    {"pid": 4101, "start_time_ticks": 987654},
                    0.0,
                    0.0,
                    stop,
                    rows,
                    initial_sample_gap_overruns,
                    errors,
                )
            return rows, errors, stop

        rows, errors, stop = run_sampler([40.0], stop_after_last_sample=True)
        self.assertTrue(stop.is_set())
        self.assertEqual(errors, [])
        self.assertEqual([row["elapsed_ms"] for row in rows], [0.0, 40.0])

        for case, elapsed_samples, initial_sample_gap_overruns in (
            ("consecutive_request_overruns", [40.0, 80.0], 0),
            ("baseline_budget_already_consumed", [40.0], 1),
            ("hard_limit", [61.0], 0),
        ):
            with self.subTest(case=case):
                rows, errors, stop = run_sampler(
                    elapsed_samples,
                    initial_sample_gap_overruns=initial_sample_gap_overruns,
                )
                self.assertTrue(stop.is_set())
                self.assertEqual(errors, ["large_payload_rss:MissedDeadline"])
                self.assertEqual(len(rows), len(elapsed_samples))

    def test_large_payload_baseline_tolerance_avoids_dense_catch_up(self) -> None:
        class FakeClock:
            def __init__(self) -> None:
                self.current = 0.0

            def monotonic(self) -> float:
                return self.current

            def sleep(self, seconds: float) -> None:
                self.current += max(0.0, seconds)

        collector = object.__new__(LinuxHostCollector)
        collector.config = self.good_config
        workload_map = {
            item["id"]: item for item in self.good_workload["workloads"]
        }
        collector.workloads = {
            key: value["requests"] for key, value in workload_map.items()
        }
        collector._verify_arm_configuration = mock.Mock()
        collector._warmup = mock.Mock(return_value=(0, []))
        collector._drain_audit_queue = mock.Mock()
        collector._reset_mock = mock.Mock()
        collector._mock_snapshot = mock.Mock(
            return_value={"auth": 0, "mock": 0, "provider": 0}
        )
        collector._process_identity = mock.Mock(
            return_value={"pid": 4101, "start_time_ticks": 987654}
        )
        clock = FakeClock()
        observed_elapsed_ms: list[float] = []

        def observe(*_args, **_kwargs) -> dict[str, float]:
            sample_index = len(observed_elapsed_ms)
            if sample_index == 1:
                clock.current += 0.020
            elif sample_index == 3:
                clock.current += 0.051
            elapsed_ms = clock.current * 1000.0
            observed_elapsed_ms.append(elapsed_ms)
            return {"elapsed_ms": elapsed_ms}

        collector._rss_observation = mock.Mock(side_effect=observe)
        collector._drive_batch = mock.Mock()

        with (
            mock.patch("host_performance.time.monotonic", clock.monotonic),
            mock.patch("host_performance.time.sleep", clock.sleep),
            self.assertRaisesRegex(
                PerformanceError,
                "Host performance large-payload RSS sampler failed",
            ) as caught,
        ):
            collector._measure_large_payload_cell("cpa_only", 1, 0)

        self.assertEqual(collector._rss_observation.call_count, 4)
        self.assertAlmostEqual(observed_elapsed_ms[1] - observed_elapsed_ms[0], 40.0)
        self.assertGreaterEqual(
            observed_elapsed_ms[2] - observed_elapsed_ms[1], 10.0
        )
        self.assertGreater(observed_elapsed_ms[3] - observed_elapsed_ms[2], 60.0)
        self.assertEqual(
            caught.exception.sampler_error_ids,
            ("large_payload_rss:MissedDeadline",),
        )
        collector._drive_batch.assert_not_called()

    def test_real_time_large_payload_collector_output_validates(self) -> None:
        collector = object.__new__(LinuxHostCollector)
        collector.config = self.good_config
        workload_map = {
            item["id"]: item for item in self.good_workload["workloads"]
        }
        collector.workload_manifest = self.good_workload
        collector.workloads = {
            key: value["requests"] for key, value in workload_map.items()
        }
        collector._verify_arm_configuration = mock.Mock()
        collector._warmup = mock.Mock(return_value=(0, []))
        collector._drain_audit_queue = mock.Mock()
        collector._reset_mock = mock.Mock()
        zero = {"auth": 0, "mock": 0, "provider": 0}
        observed = {"auth": 16, "mock": 16, "provider": 16}
        collector._mock_snapshot = mock.Mock(side_effect=[zero, observed])
        process_identity = {"pid": 4101, "start_time_ticks": 987654}
        collector._process_identity = mock.Mock(return_value=process_identity)
        collector._process_rss_mib = mock.Mock(return_value=100.0)
        collector._runtime = mock.Mock(
            return_value=copy.deepcopy(
                next(
                    cell["runtime"]
                    for cell in self.good_measurements["large_payload_cells"]
                    if cell["arm"] == "cpa_only"
                )
            )
        )

        deterministic_cell = copy.deepcopy(
            next(
                cell
                for cell in self.good_measurements["large_payload_cells"]
                if cell["arm"] == "cpa_only"
            )
        )
        deterministic_validated, deterministic_summary = _validate_large_payload_cell(
            deterministic_cell,
            "deterministic large-payload cell",
            config=self.good_config,
            workload_map=workload_map,
        )
        self.assertEqual(deterministic_validated, deterministic_cell)
        self.assertEqual(deterministic_summary["successful_samples"], 16)

        single_scheduler_gap = copy.deepcopy(deterministic_cell)
        single_scheduler_gap["rss_samples"] = [
            sample
            for sample in single_scheduler_gap["rss_samples"]
            if sample["elapsed_ms"] != 120.0
        ]
        validated, summary = _validate_large_payload_cell(
            single_scheduler_gap,
            "single bounded large-payload deadline gap",
            config=self.good_config,
            workload_map=workload_map,
        )
        self.assertEqual(validated, single_scheduler_gap)
        self.assertEqual(summary["rss_max_sample_gap_ms"], 40.0)
        self.assertEqual(summary["rss_sample_gap_overrun_count"], 1)

        consecutive_gaps = copy.deepcopy(deterministic_cell)
        consecutive_gaps["rss_samples"] = [
            sample
            for sample in consecutive_gaps["rss_samples"]
            if sample["elapsed_ms"] not in (120.0, 160.0)
        ]
        with self.assertRaisesRegex(ContractError, "bounded tolerance"):
            _validate_large_payload_cell(
                consecutive_gaps,
                "consecutive large-payload deadline gaps",
                config=self.good_config,
                workload_map=workload_map,
            )

        hard_limit_gap = copy.deepcopy(deterministic_cell)
        hard_limit_gap["rss_samples"] = [
            sample
            for sample in hard_limit_gap["rss_samples"]
            if sample["elapsed_ms"] not in (120.0, 140.0, 160.0)
        ]
        with self.assertRaisesRegex(ContractError, "hard observation gap limit"):
            _validate_large_payload_cell(
                hard_limit_gap,
                "hard-limit large-payload deadline gap",
                config=self.good_config,
                workload_map=workload_map,
            )

        batch_delay_seconds = 0.150

        def drive_batch(*_args, **_kwargs):
            # Keep each batch alive for multiple production 20 ms sampling
            # periods so the unit test does not race sampler shutdown on an
            # ordinary loaded CI host. The production 30 ms maximum gap and
            # all validation assertions remain unchanged.
            time.sleep(batch_delay_seconds)
            return [(True, False, batch_delay_seconds * 1000.0, None)] * 4

        collector._drive_batch = drive_batch
        sampler_error_ids: list[str] = []
        original_rss_loop = collector._large_payload_rss_loop

        def capture_rss_loop_errors(*args, **kwargs):
            errors = args[-1] if args else kwargs["errors"]
            try:
                return original_rss_loop(*args, **kwargs)
            finally:
                sampler_error_ids[:] = errors

        collector._large_payload_rss_loop = capture_rss_loop_errors
        try:
            cell = collector._measure_large_payload_cell("cpa_only", 1, 0)
            validated, summary = _validate_large_payload_cell(
                cell,
                "real-time large-payload cell",
                config=self.good_config,
                workload_map=workload_map,
            )
        except ContractError as exc:
            _fail_or_skip_real_time_rss_deadline(self, exc, sampler_error_ids)
        self.assertEqual(validated, cell)
        self.assertEqual(summary["successful_samples"], 16)
        self.assertEqual(len(cell["rss_baseline_samples"]), 5)
        self.assertGreaterEqual(len(cell["rss_samples"]), 3)

    def test_real_time_large_payload_deadline_skip_requires_explicit_opt_out(
        self,
    ) -> None:
        def missed_deadline() -> PerformanceError:
            return PerformanceError(
                "Host performance large-payload RSS sampler failed"
            )

        sampler_error_ids = ["large_payload_rss:MissedDeadline"]

        failure = missed_deadline()
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(PerformanceError) as caught:
                _fail_or_skip_real_time_rss_deadline(
                    self, failure, sampler_error_ids
                )
        self.assertIs(caught.exception, failure)

        with mock.patch.dict(
            os.environ,
            {REAL_TIME_RSS_TEST_SKIP_ENV: REAL_TIME_RSS_TEST_SKIP_VALUE},
            clear=True,
        ):
            with self.assertRaises(unittest.SkipTest) as caught_skip:
                _fail_or_skip_real_time_rss_deadline(
                    self, missed_deadline(), sampler_error_ids
                )
        self.assertIn(
            f"{REAL_TIME_RSS_TEST_SKIP_ENV}={REAL_TIME_RSS_TEST_SKIP_VALUE}",
            str(caught_skip.exception),
        )

        baseline_failure = PerformanceError(
            "Host performance large-payload RSS sampler failed",
            sampler_error_ids=sampler_error_ids,
        )
        with mock.patch.dict(
            os.environ,
            {REAL_TIME_RSS_TEST_SKIP_ENV: REAL_TIME_RSS_TEST_SKIP_VALUE},
            clear=True,
        ):
            with self.assertRaises(unittest.SkipTest):
                _fail_or_skip_real_time_rss_deadline(self, baseline_failure, [])

        for value in ("", "0", "true", "TRUE", "yes", " 1", "1 "):
            with self.subTest(value=value):
                failure = missed_deadline()
                with mock.patch.dict(
                    os.environ,
                    {REAL_TIME_RSS_TEST_SKIP_ENV: value},
                    clear=True,
                ):
                    with self.assertRaises(PerformanceError) as caught:
                        _fail_or_skip_real_time_rss_deadline(
                            self, failure, sampler_error_ids
                        )
                self.assertIs(caught.exception, failure)

    def test_large_payload_completion_excludes_post_rss_identity_inspection(
        self,
    ) -> None:
        class FakeClock:
            def __init__(self) -> None:
                self.origin = 1_000.0
                self.current = self.origin
                self.wall = datetime(2026, 8, 9, tzinfo=timezone.utc)

            def monotonic(self) -> float:
                return self.current

            def sleep(self, seconds: float) -> None:
                self.current += max(0.0, seconds)

            def now_iso(self) -> str:
                value = self.wall + timedelta(seconds=self.current - self.origin)
                return value.isoformat(timespec="milliseconds").replace("+00:00", "Z")

        workload_map = {
            item["id"]: item for item in self.good_workload["workloads"]
        }
        process_identity = {"pid": 4101, "start_time_ticks": 987654}

        def configured_collector(
            clock: FakeClock,
            *,
            slow_identity_call: int | None = None,
            drift_identity_call: int | None = None,
        ):
            collector = object.__new__(LinuxHostCollector)
            collector.config = self.good_config
            collector.workload_manifest = self.good_workload
            collector.workloads = {
                key: value["requests"] for key, value in workload_map.items()
            }
            collector._verify_arm_configuration = mock.Mock()
            collector._warmup = mock.Mock(return_value=(0, []))
            collector._drain_audit_queue = mock.Mock()
            collector._reset_mock = mock.Mock()
            request_count = collector.config["plan"]["large_payload_request_count"]
            zero = {"auth": 0, "mock": 0, "provider": 0}
            observed = {
                "auth": request_count,
                "mock": request_count,
                "provider": request_count,
            }
            collector._mock_snapshot = mock.Mock(side_effect=[zero, observed])
            calls = 0

            def inspect_identity(_arm: str) -> dict[str, int]:
                nonlocal calls
                calls += 1
                if calls == drift_identity_call:
                    return {"pid": 4102, "start_time_ticks": 987655}
                if calls == slow_identity_call:
                    clock.sleep(0.050)
                return dict(process_identity)

            collector._process_identity = mock.Mock(side_effect=inspect_identity)
            collector._process_rss_mib = mock.Mock(return_value=100.0)
            collector._large_payload_rss_loop = mock.Mock()

            def drive_batch(_executor, _arm, _requests, concurrency, offset):
                clock.sleep(0.002)
                count = min(concurrency, request_count - offset)
                return [(True, False, 0.0, None)] * count

            collector._drive_batch = drive_batch
            collector._runtime = mock.Mock(
                return_value=copy.deepcopy(
                    next(
                        cell["runtime"]
                        for cell in self.good_measurements["large_payload_cells"]
                        if cell["arm"] == "cpa_only"
                    )
                )
            )
            return collector

        def measure(clock: FakeClock, collector: LinuxHostCollector):
            with (
                mock.patch("host_performance.time.monotonic", clock.monotonic),
                mock.patch("host_performance.time.sleep", clock.sleep),
                mock.patch("host_performance._now_iso", clock.now_iso),
            ):
                return collector._measure_large_payload_cell("cpa_only", 1, 0)

        for identity_call, label in (
            (2, "slow identity inspection before final RSS"),
            (3, "slow identity inspection after final RSS"),
        ):
            with self.subTest(label):
                clock = FakeClock()
                collector = configured_collector(
                    clock, slow_identity_call=identity_call
                )
                cell = measure(clock, collector)
                _validate_large_payload_cell(
                    cell,
                    label,
                    config=self.good_config,
                    workload_map=workload_map,
                )
                self.assertGreaterEqual(
                    (clock.current - clock.origin) - cell["elapsed_seconds"], 0.049
                )

        for identity_call, error_pattern in (
            (2, r"process identity changed$"),
            (3, "changed after final RSS"),
        ):
            with self.subTest(identity_drift_call=identity_call):
                clock = FakeClock()
                collector = configured_collector(
                    clock, drift_identity_call=identity_call
                )
                with self.assertRaisesRegex(ContractError, error_pattern):
                    measure(clock, collector)

    def test_collector_rejects_replaced_mock_runtime_identity(self) -> None:
        collector = object.__new__(LinuxHostCollector)
        collector.mock_info = {"Id": "original-mock"}
        collector.names = {"mock": "unit-run-perf-mock"}
        collector.docker = SimpleNamespace(
            inspect=mock.Mock(return_value={"Id": "replacement-mock"})
        )
        with self.assertRaisesRegex(ContractError, "Mock container identity changed"):
            collector._verify_mock_runtime()

    def test_container_contract_requires_true_no_new_privileges_and_positive_pids(self) -> None:
        image_id = "sha256:" + "5" * 64
        good = docker_container_info(image_id=image_id)
        contract = LinuxHostCollector._container_contract(good, image_id, "unit")
        self.assertEqual(
            contract["security"],
            {"no_new_privileges": True, "pids_limit": 256},
        )

        unrelated = docker_container_info(
            image_id=image_id,
            security_options=["seccomp=unit-profile", "no-new-privileges:true"],
        )
        self.assertTrue(
            LinuxHostCollector._container_contract(
                unrelated, image_id, "unit"
            )["security"]["no_new_privileges"]
        )

        security_mutations = (
            [],
            ["no-new-privileges:false"],
            ["no-new-privileges:true", "no-new-privileges:true"],
            ["no-new-privileges:true", "no-new-privileges:false"],
            [123],
        )
        for options in security_mutations:
            with self.subTest(security_options=options), self.assertRaises(
                ContractError
            ):
                LinuxHostCollector._container_contract(
                    docker_container_info(
                        image_id=image_id, security_options=options
                    ),
                    image_id,
                    "unit",
                )

        for pids_limit in (None, False, "256", 0, -1):
            with self.subTest(pids_limit=pids_limit), self.assertRaises(
                ContractError
            ):
                LinuxHostCollector._container_contract(
                    docker_container_info(
                        image_id=image_id, pids_limit=pids_limit
                    ),
                    image_id,
                    "unit",
                )

    def test_docker_comparable_projection_detects_ab_runtime_bias(self) -> None:
        def backing(
            value: dict[str, object], *, device: str = "8:1"
        ) -> dict[str, dict[str, object]]:
            result: dict[str, dict[str, object]] = {}
            for item in value["Mounts"]:  # type: ignore[index]
                source = item["Source"]
                result[source] = {
                    "device": device,
                    "filesystem_type": "ext4",
                    "identity_sha256": sha256_bytes(
                        f"{source}:{device}".encode("utf-8")
                    ),
                    "source_path_sha256": sha256_bytes(source.encode("utf-8")),
                    "st_dev": 2049,
                    "st_ino": 100,
                }
            return result

        baseline = {
            "Args": ["--config", "/cag/config.yaml"],
            "Config": {
                "Cmd": ["--config", "/cag/config.yaml"],
                "Entrypoint": ["/CLIProxyAPI"],
                "Env": ["API_KEY=baseline-secret", "GOMAXPROCS=2"],
                "Hostname": "baseline-id",
                "Image": "image@sha256:unit",
                "Labels": {
                    "cag.current-cpa-audit.role": "host-perf-cpa-only",
                    "cag.current-cpa-audit.run": "unit-run",
                    "stable": "same",
                },
                "User": "1000:1000",
                "WorkingDir": "/cag",
            },
            "HostConfig": {
                "Binds": ["/host/baseline-config:/cag/config.yaml:ro"],
                "CpuShares": 1024,
                "NanoCpus": 1_000_000_000,
                "PidsLimit": 256,
                "Ulimits": [{"Name": "nofile", "Hard": 4096, "Soft": 4096}],
            },
            "Mounts": [
                {
                    "Destination": "/cag/config.yaml",
                    "Mode": "ro",
                    "Propagation": "rprivate",
                    "RW": False,
                    "Source": "/host/baseline-config",
                    "Type": "bind",
                },
                {
                    "Destination": "/cag/workloads",
                    "Mode": "ro",
                    "Propagation": "rprivate",
                    "RW": False,
                    "Source": "/host/shared-workloads",
                    "Type": "bind",
                },
            ],
            "Path": "/CLIProxyAPI",
            "Platform": "linux",
        }
        candidate = copy.deepcopy(baseline)
        candidate["Config"]["Env"][0] = "API_KEY=candidate-secret"
        candidate["Config"]["Hostname"] = "candidate-id"
        candidate["Config"]["Labels"][
            "cag.current-cpa-audit.role"
        ] = "host-perf-cpa-cag"
        candidate["HostConfig"]["Binds"] = [
            "/host/candidate-config:/cag/config.yaml:ro",
            "/host/plugins:/cag/plugins:ro",
        ]
        candidate["Mounts"][0]["Source"] = "/host/candidate-config"
        candidate["Mounts"].append(
            {
                "Destination": "/cag/plugins",
                "Mode": "ro",
                "Propagation": "rprivate",
                "RW": False,
                "Source": "/host/plugins",
                "Type": "bind",
            }
        )
        self.assertEqual(
            _docker_comparable_projection(
                baseline, backing_identities=backing(baseline)
            ),
            _docker_comparable_projection(
                candidate, backing_identities=backing(candidate)
            ),
        )
        self.assertIsNone(
            _docker_arm_specific_mount_projection(
                baseline,
                "cpa_only",
                backing_identities=backing(baseline),
            )["cag_plugin_mount"]
        )
        self.assertIsNotNone(
            _docker_arm_specific_mount_projection(
                candidate,
                "cpa_cag",
                backing_identities=backing(candidate),
            )["cag_plugin_mount"]
        )

        for label, mutate in (
            (
                "env",
                lambda value: value["Config"].__setitem__(
                    "Env", ["API_KEY=candidate-secret", "GOMAXPROCS=4"]
                ),
            ),
            (
                "command",
                lambda value: value["Config"].__setitem__("Cmd", ["--fast"]),
            ),
            (
                "ulimit",
                lambda value: value["HostConfig"].__setitem__(
                    "Ulimits", [{"Name": "nofile", "Hard": 8192, "Soft": 8192}]
                ),
            ),
        ):
            drifted = copy.deepcopy(candidate)
            mutate(drifted)
            with self.subTest(label=label):
                self.assertNotEqual(
                    _docker_comparable_projection(
                        baseline, backing_identities=backing(baseline)
                    ),
                    _docker_comparable_projection(
                        drifted, backing_identities=backing(drifted)
                    ),
                )

        different_source = copy.deepcopy(candidate)
        shared_mount = next(
            item
            for item in different_source["Mounts"]
            if item["Destination"] == "/cag/workloads"
        )
        shared_mount["Source"] = "/host/other-workloads"
        self.assertNotEqual(
            _docker_comparable_projection(
                baseline, backing_identities=backing(baseline)
            ),
            _docker_comparable_projection(
                different_source,
                backing_identities=backing(different_source),
            ),
        )

        different_backing = backing(candidate)
        different_backing["/host/shared-workloads"]["device"] = "0:99"
        with self.assertRaisesRegex(ContractError, "lacks a supplied backing identity"):
            missing = backing(candidate)
            missing.pop("/host/shared-workloads")
            _docker_comparable_projection(candidate, backing_identities=missing)
        self.assertNotEqual(
            _docker_comparable_projection(
                baseline, backing_identities=backing(baseline)
            ),
            _docker_comparable_projection(
                candidate, backing_identities=different_backing
            ),
        )

        if sys.platform == "linux":
            mountinfo_raw = Path("/proc/self/mountinfo").read_text("utf-8")
            with tempfile.TemporaryDirectory() as temporary_directory:
                canonical_source = str(Path(temporary_directory).resolve())
                for suffix in ("", "/", "//", "/./"):
                    source = canonical_source + suffix
                    info = {
                        "Config": {},
                        "HostConfig": {},
                        "Mounts": [
                            {
                                "Destination": "/cag/workloads",
                                "Mode": "ro",
                                "Propagation": "rprivate",
                                "RW": False,
                                "Source": source,
                                "Type": "bind",
                            }
                        ],
                    }
                    with self.subTest(raw_bind_source=source):
                        projection = _docker_comparable_projection(
                            info, mountinfo_raw
                        )
                        record = projection["mounts"][0]
                        expected_source_sha256 = sha256_bytes(
                            source.encode("utf-8")
                        )
                        self.assertEqual(
                            record["source_path_sha256"], expected_source_sha256
                        )
                        self.assertEqual(
                            record["backing"]["source_path_sha256"],
                            expected_source_sha256,
                        )
                        self.assertEqual(
                            record["backing"]["resolved_source_sha256"],
                            sha256_bytes(
                                str(Path(source).resolve()).encode("utf-8")
                            ),
                        )

    def test_arm_specific_mounts_reject_different_filesystem_backing(self) -> None:
        baseline = copy.deepcopy(
            next(
                cell["runtime"]["mount_identity_projection"]
                for cell in self.good_measurements["paired_cells"]
                if cell["arm"] == "cpa_only"
            )
        )
        candidate = copy.deepcopy(
            next(
                cell["runtime"]["mount_identity_projection"]
                for cell in self.good_measurements["paired_cells"]
                if cell["arm"] == "cpa_cag"
            )
        )
        _validate_arm_specific_backing_equivalence(baseline, candidate)
        for filesystem_type in ("nfs", "fuse.sshfs"):
            drifted = copy.deepcopy(candidate)
            drifted["config_runtime_mounts"][0]["backing"][
                "filesystem_type"
            ] = filesystem_type
            with self.subTest(filesystem_type=filesystem_type), self.assertRaisesRegex(
                ContractError, "mount backing differs"
            ):
                _validate_arm_specific_backing_equivalence(baseline, drifted)

    def test_runtime_rereads_management_config_and_rejects_cell_drift(self) -> None:
        info = {
            "Args": [],
            "Config": {"Env": [], "Labels": {}, "User": "1000:1000"},
            "HostConfig": {},
            "Id": "container-cpa-only",
            "Mounts": [],
            "Path": "/CLIProxyAPI",
            "Platform": "linux",
            "State": {},
        }
        collector = object.__new__(LinuxHostCollector)
        collector.names = {"cpa_only": "unit-run-perf-cpa-only"}
        collector.container_infos = {"cpa_only": {"Id": info["Id"]}}
        collector.config = {"identities": {"cpa": {"image_id": "image"}}}
        collector.docker = SimpleNamespace(inspect=mock.Mock(return_value=info))
        contract = {
            "cpuset_cpus": "0",
            "memory_bytes": 1,
            "nano_cpus": 1,
            "security": {"no_new_privileges": True, "pids_limit": 1},
        }
        collector.container_contracts = {"cpa_only": contract}
        collector._container_contract = mock.Mock(return_value=contract)
        collector.observed_docker_comparable_sha256 = {
            "cpa_only": sha256_bytes(
                canonical_bytes(_docker_comparable_projection(info))
            )
        }
        collector.observed_docker_arm_specific_mount_sha256 = {
            "cpa_only": sha256_bytes(
                canonical_bytes(
                    _docker_arm_specific_mount_projection(info, "cpa_only")
                )
            )
        }
        mount_projection = _docker_mount_identity_projection(info, "cpa_only")
        collector.observed_mount_identity_projection = {
            "cpa_only": mount_projection
        }
        collector.observed_docker_common_mount_sha256 = {
            "cpa_only": mount_projection["common_sha256"]
        }
        collector.observed_docker_mount_projection_sha256 = {
            "cpa_only": sha256_bytes(canonical_bytes(mount_projection))
        }
        collector.observed_base_config_sha256 = {"cpa_only": "a" * 64}
        collector._verify_cpa_config = mock.Mock(return_value="b" * 64)
        with self.assertRaisesRegex(ContractError, "non-plugin CPA configuration changed"):
            collector._runtime("cpa_only")
        collector._verify_cpa_config.assert_called_once_with("cpa_only")

    def test_collector_hashes_observed_mock_source_bytes(self) -> None:
        observed = b"reviewed counted mock source\n"

        class CopyingDocker:
            @staticmethod
            def run(arguments, *, timeout):
                del timeout
                Path(arguments[-1]).write_bytes(observed)

        collector = object.__new__(LinuxHostCollector)
        collector.names = {"mock": "unit-run-perf-mock"}
        collector.audit_run = SimpleNamespace(
            MOCK_SOURCE_PATH="/opt/cag-audit/counted_mock.py"
        )
        collector.docker = CopyingDocker()
        collector.config = {
            "identities": {"mock": {"source_sha256": sha256_bytes(observed)}}
        }
        collector.observed_mock_source_sha256 = ""
        collector._verify_mock_source()
        self.assertEqual(
            collector.observed_mock_source_sha256, sha256_bytes(observed)
        )

        collector.config["identities"]["mock"]["source_sha256"] = "e" * 64
        with self.assertRaisesRegex(ContractError, "image source SHA drifted"):
            collector._verify_mock_source()

    def test_collect_validates_before_creating_output(self) -> None:
        run, run_raw = run_config()
        candidate, candidate_raw = candidate_manifest()
        workload, workload_raw = workload_manifest()
        collector = mock.Mock()
        collector.collect.return_value = {"invalid": True}
        arguments = [
            "collect",
            "--run-config",
            "run.json",
            "--candidate-manifest",
            "candidate.json",
            "--workload-manifest",
            "workloads.json",
            "--config",
            "performance.json",
            "--workload-root",
            "workloads",
            "--output",
            "measurements.json",
        ]
        with (
            mock.patch(
                "host_performance._load_bindings",
                return_value=(
                    run,
                    run_raw,
                    candidate,
                    candidate_raw,
                    workload,
                    workload_raw,
                ),
            ),
            mock.patch(
                "host_performance._canonical_file",
                return_value=(self.good_config, self.good_config_raw),
            ),
            mock.patch("host_performance.validate_config"),
            mock.patch("host_performance.LinuxHostCollector", return_value=collector),
            mock.patch(
                "host_performance.validate_measurements",
                side_effect=ContractError("invalid in-memory acquisition"),
            ),
            mock.patch("host_performance._write_exclusive") as write,
            contextlib.redirect_stderr(io.StringIO()),
        ):
            self.assertEqual(performance_main(arguments), 2)
        write.assert_not_called()

    def test_collect_rejects_current_tool_drift_without_writing_output(self) -> None:
        (
            measurement,
            _,
            config,
            config_raw,
            workload,
            workload_raw,
            run,
            run_raw,
            candidate,
            candidate_raw,
        ) = measurements()
        approved = dict(config["approved_tool_identities"])
        collector = mock.Mock()
        collector.collect.return_value = measurement
        arguments = [
            "collect",
            "--run-config",
            "run.json",
            "--candidate-manifest",
            "candidate.json",
            "--workload-manifest",
            "workloads.json",
            "--config",
            "performance.json",
            "--workload-root",
            "workloads",
            "--output",
            "measurements.json",
        ]
        with (
            mock.patch(
                "host_performance.tool_identities",
                side_effect=[approved, drifted_tool_identities()],
            ),
            mock.patch(
                "host_performance._load_bindings",
                return_value=(
                    run,
                    run_raw,
                    candidate,
                    candidate_raw,
                    workload,
                    workload_raw,
                ),
            ),
            mock.patch(
                "host_performance._canonical_file",
                return_value=(config, config_raw),
            ),
            mock.patch("host_performance.LinuxHostCollector", return_value=collector),
            mock.patch("host_performance._write_exclusive") as write,
            contextlib.redirect_stderr(io.StringIO()),
        ):
            self.assertEqual(performance_main(arguments), 2)
        collector.collect.assert_called_once_with()
        write.assert_not_called()

    def test_summarize_rejects_binding_or_tool_drift_without_writing_output(self) -> None:
        (
            measurement,
            _,
            config,
            _,
            workload,
            workload_raw,
            run,
            run_raw,
            candidate,
            candidate_raw,
        ) = measurements()
        approved = dict(config["approved_tool_identities"])
        cases: list[
            tuple[str, dict[str, object], dict[str, object], list[dict[str, str]]]
        ] = []

        config_approval_drift = copy.deepcopy(config)
        config_approval_drift["approved_tool_identities"] = drifted_tool_identities()
        cases.append(
            (
                "config_approval",
                config_approval_drift,
                copy.deepcopy(measurement),
                [approved],
            )
        )

        config_measurement_drift = copy.deepcopy(config)
        config_measurement_drift["plan"]["seed"] += 1
        cases.append(
            (
                "config_measurement_binding",
                config_measurement_drift,
                copy.deepcopy(measurement),
                [approved],
            )
        )

        measurement_tool_drift = copy.deepcopy(measurement)
        measurement_tool_drift["collector_tool_identities"] = (
            drifted_tool_identities()
        )
        cases.append(
            (
                "measurement_tools",
                copy.deepcopy(config),
                measurement_tool_drift,
                [approved],
            )
        )

        cases.append(
            (
                "current_tools_at_output",
                copy.deepcopy(config),
                copy.deepcopy(measurement),
                [approved, drifted_tool_identities()],
            )
        )

        arguments = [
            "summarize",
            "--run-config",
            "run.json",
            "--candidate-manifest",
            "candidate.json",
            "--workload-manifest",
            "workloads.json",
            "--config",
            "performance.json",
            "--measurements",
            "measurements.json",
            "--output",
            "evidence.json",
        ]
        for label, config_value, measurement_value, observed_tools in cases:
            config_value_raw = canonical_bytes(config_value) + b"\n"
            measurement_value_raw = canonical_bytes(measurement_value) + b"\n"

            def canonical_file(
                _path: Path, value_label: str, _maximum_bytes: int
            ) -> tuple[dict[str, object], bytes]:
                if value_label == "host performance config":
                    return config_value, config_value_raw
                if value_label == "host performance measurements":
                    return measurement_value, measurement_value_raw
                self.fail(f"unexpected canonical-file label: {value_label}")

            with (
                self.subTest(label=label),
                mock.patch(
                    "host_performance.tool_identities",
                    side_effect=observed_tools,
                ),
                mock.patch(
                    "host_performance._load_bindings",
                    return_value=(
                        run,
                        run_raw,
                        candidate,
                        candidate_raw,
                        workload,
                        workload_raw,
                    ),
                ),
                mock.patch(
                    "host_performance._canonical_file", side_effect=canonical_file
                ),
                mock.patch("host_performance._write_exclusive") as write,
                contextlib.redirect_stderr(io.StringIO()),
            ):
                self.assertEqual(performance_main(arguments), 2)
            write.assert_not_called()

    def test_missing_arm_or_cell_fails_closed(self) -> None:
        value = copy.deepcopy(self.good_measurements)
        value["paired_cells"].pop()
        raw = canonical_bytes(value) + b"\n"
        with self.assertRaisesRegex(ContractError, "matrix is incomplete"):
            validate_measurements(value, raw, self.good_config, self.good_config_raw, self.good_workload)

    def test_ordinary_overhead_requires_a_paired_baseline_and_conserved_samples(
        self,
    ) -> None:
        missing_baseline = copy.deepcopy(self.good_measurements)
        baseline_index = next(
            index
            for index, cell in enumerate(missing_baseline["absolute_cells"])
            if cell["workload"] == "ordinary" and cell["arm"] == "cpa_only"
        )
        missing_baseline["absolute_cells"].pop(baseline_index)
        with self.assertRaisesRegex(ContractError, "matrix is incomplete"):
            validate_measurements(
                missing_baseline,
                canonical_bytes(missing_baseline) + b"\n",
                self.good_config,
                self.good_config_raw,
                self.good_workload,
            )

        mismatched_samples = copy.deepcopy(self.good_measurements)
        ordinary_baseline = next(
            cell
            for cell in mismatched_samples["absolute_cells"]
            if cell["workload"] == "ordinary" and cell["arm"] == "cpa_only"
        )
        ordinary_baseline["latency_samples_ms"].pop()
        with self.assertRaisesRegex(ContractError, "latency_samples_ms"):
            validate_measurements(
                mismatched_samples,
                canonical_bytes(mismatched_samples) + b"\n",
                self.good_config,
                self.good_config_raw,
                self.good_workload,
            )

    def test_ordinary_overhead_is_conservative_and_raw_derived(self) -> None:
        self.assertEqual(
            self.good_evidence["metrics"]["ordinary_plugin_overhead_p95_ms"],
            1.0,
        )
        for comparison in self.good_evidence["comparisons"]:
            self.assertEqual(comparison["ordinary_cpa_cag_p95_ms"], 2.0)
            self.assertEqual(comparison["ordinary_cpa_only_p50_ms"], 1.0)
            self.assertEqual(comparison["ordinary_plugin_overhead_p95_ms"], 1.0)

        forged = copy.deepcopy(self.good_evidence)
        forged["metrics"]["ordinary_plugin_overhead_p95_ms"] = 0.0
        with self.assertRaisesRegex(ContractError, "raw-derived closed result"):
            validate_evidence_bundle(
                forged,
                self.good_config,
                self.good_config_raw,
                self.good_measurements,
                self.good_measurements_raw,
                self.good_summaries,
                self.good_baseline,
                self.good_extra,
                require_pass=False,
            )

    def test_large_payload_requires_raw_rss_and_rejects_self_reported_boolean(
        self,
    ) -> None:
        missing = copy.deepcopy(self.good_measurements)
        missing["large_payload_cells"].pop()
        with self.assertRaisesRegex(ContractError, "matrix is incomplete"):
            validate_measurements(
                missing,
                canonical_bytes(missing) + b"\n",
                self.good_config,
                self.good_config_raw,
                self.good_workload,
            )

        no_rss = copy.deepcopy(self.good_measurements)
        no_rss["large_payload_cells"][0].pop("rss_samples")
        with self.assertRaisesRegex(ContractError, "must contain exactly"):
            validate_measurements(
                no_rss,
                canonical_bytes(no_rss) + b"\n",
                self.good_config,
                self.good_config_raw,
                self.good_workload,
            )

        self_reported = copy.deepcopy(self.good_measurements)
        self_reported["large_payload_cells"][0]["full_copy_regression"] = False
        with self.assertRaisesRegex(ContractError, "must contain exactly"):
            validate_measurements(
                self_reported,
                canonical_bytes(self_reported) + b"\n",
                self.good_config,
                self.good_config_raw,
                self.good_workload,
            )

    def test_large_payload_full_payload_equivalent_failure_cannot_be_forged(
        self,
    ) -> None:
        value = copy.deepcopy(self.good_measurements)
        candidate = next(
            cell
            for cell in value["large_payload_cells"]
            if cell["repetition"] == 1 and cell["arm"] == "cpa_cag"
        )
        for sample in candidate["rss_samples"]:
            sample["rss_mib"] = 107.0
        raw = canonical_bytes(value) + b"\n"
        validated, summaries, baseline, extra = validate_measurements(
            value,
            raw,
            self.good_config,
            self.good_config_raw,
            self.good_workload,
        )
        evidence = build_evidence(
            self.good_config,
            self.good_config_raw,
            validated,
            raw,
            summaries,
            baseline,
            extra,
        )
        self.assertEqual(evidence["metrics"]["large_payload_full_copy_regression"], 1)
        self.assertEqual(
            evidence["gates"]["large_payload_full_copy_regression"]["status"],
            "FAIL",
        )
        self.assertEqual(evidence["status"], "FAIL")

        forged = copy.deepcopy(evidence)
        forged["metrics"]["large_payload_full_copy_regression"] = 0
        forged["gates"]["large_payload_full_copy_regression"].update(
            {"observed": 0, "status": "PASS"}
        )
        forged["large_payload_resident_memory"][
            "full_payload_equivalent_regression_count"
        ] = 0
        forged["large_payload_resident_memory"]["comparisons"][0][
            "full_payload_equivalent_regression"
        ] = 0
        with self.assertRaisesRegex(ContractError, "raw-derived closed result"):
            validate_evidence_bundle(
                forged,
                self.good_config,
                self.good_config_raw,
                validated,
                raw,
                summaries,
                baseline,
                extra,
                require_pass=False,
            )

    def test_large_payload_rss_identity_cadence_and_work_are_fail_closed(
        self,
    ) -> None:
        cases: list[tuple[str, dict[str, object], str]] = []

        sparse = copy.deepcopy(self.good_measurements)
        sparse_cell = sparse["large_payload_cells"][0]
        sparse_cell["rss_samples"] = sparse_cell["rss_samples"][::5]
        cases.append(("100_ms_sparse_rss", sparse, "at least 31 entries"))

        impossible_work = copy.deepcopy(self.good_measurements)
        impossible_cell = impossible_work["large_payload_cells"][0]
        started = datetime.fromisoformat(
            impossible_cell["started_at"].replace("Z", "+00:00")
        )
        impossible_cell["elapsed_seconds"] = 0.001
        impossible_cell["completed_at"] = (
            (started + timedelta(milliseconds=1))
            .isoformat(timespec="milliseconds")
            .replace("+00:00", "Z")
        )
        impossible_cell["request_started_elapsed_ms"] = 0.0
        cases.append(
            (
                "one_ms_cell_with_sixteen_ten_ms_latencies",
                impossible_work,
                "latency work cannot fit",
            )
        )

        missing_timestamp = copy.deepcopy(self.good_measurements)
        missing_timestamp["large_payload_cells"][0]["rss_baseline_samples"][0].pop(
            "observed_at"
        )
        cases.append(
            ("missing_baseline_timestamp", missing_timestamp, "must contain exactly")
        )

        pid_drift = copy.deepcopy(self.good_measurements)
        pid_drift["large_payload_cells"][0]["rss_samples"][1]["pid"] += 1
        cases.append(("pid_drift", pid_drift, "process identity drifted"))

        starttime_drift = copy.deepcopy(self.good_measurements)
        starttime_drift["large_payload_cells"][0]["rss_samples"][1][
            "process_start_time_ticks"
        ] += 1
        cases.append(
            ("process_starttime_drift", starttime_drift, "process identity drifted")
        )

        for case, value, message in cases:
            with self.subTest(case=case), self.assertRaisesRegex(
                ContractError, message
            ):
                validate_measurements(
                    value,
                    canonical_bytes(value) + b"\n",
                    self.good_config,
                    self.good_config_raw,
                    self.good_workload,
                )

    def test_large_payload_bounded_gap_is_published_from_raw_samples(self) -> None:
        def apply_baseline_jitter(cell: dict[str, object]) -> None:
            started = datetime.fromisoformat(
                str(cell["started_at"]).replace("Z", "+00:00")
            )
            baseline_samples = cell["rss_baseline_samples"]
            for sample, elapsed_ms in zip(
                baseline_samples, (0.0, 20.0, 60.0, 70.0, 80.0), strict=True
            ):
                sample["elapsed_ms"] = elapsed_ms
                sample["observed_at"] = (
                    started + timedelta(milliseconds=elapsed_ms)
                ).isoformat(timespec="milliseconds").replace("+00:00", "Z")

        for gap_series in ("baseline", "request"):
            with self.subTest(gap_series=gap_series):
                jittered = copy.deepcopy(self.good_measurements)
                cell = jittered["large_payload_cells"][0]
                if gap_series == "baseline":
                    apply_baseline_jitter(cell)
                else:
                    cell["rss_samples"] = [
                        sample
                        for sample in cell["rss_samples"]
                        if sample["elapsed_ms"] != 120.0
                    ]
                raw = canonical_bytes(jittered) + b"\n"
                validated, summaries, baseline, extra = validate_measurements(
                    jittered,
                    raw,
                    self.good_config,
                    self.good_config_raw,
                    self.good_workload,
                )
                evidence = build_evidence(
                    self.good_config,
                    self.good_config_raw,
                    validated,
                    raw,
                    summaries,
                    baseline,
                    extra,
                )
                comparison = next(
                    item
                    for item in evidence["large_payload_resident_memory"][
                        "comparisons"
                    ]
                    if item["repetition"] == cell["repetition"]
                )
                prefix = cell["arm"]
                self.assertEqual(
                    comparison[f"{prefix}_rss_max_sample_gap_ms"], 40.0
                )
                self.assertEqual(
                    comparison[f"{prefix}_rss_sample_gap_overrun_count"], 1
                )

        exhausted = copy.deepcopy(self.good_measurements)
        exhausted_cell = exhausted["large_payload_cells"][0]
        apply_baseline_jitter(exhausted_cell)
        exhausted_cell["rss_samples"] = [
            sample
            for sample in exhausted_cell["rss_samples"]
            if sample["elapsed_ms"] != 120.0
        ]
        with self.assertRaisesRegex(ContractError, "bounded tolerance"):
            validate_measurements(
                exhausted,
                canonical_bytes(exhausted) + b"\n",
                self.good_config,
                self.good_config_raw,
                self.good_workload,
            )

    def test_readme_documents_shared_large_payload_gap_budget(self) -> None:
        readme = " ".join((TOOL / "README.md").read_text(encoding="utf-8").split())
        self.assertIn(
            "Across the baseline and request RSS series together, each cell may "
            "retain at most one gap above the 30 ms deadline and no greater than "
            "the hard 60 ms limit",
            readme,
        )
        self.assertIn(
            "total overrun count across the combined baseline and request series",
            readme,
        )
        self.assertNotIn("each request series may retain one gap", readme)

    def test_host_timestamp_requires_exact_three_digit_utc_shape(self) -> None:
        accepted = "2026-08-09T12:34:56.123Z"
        self.assertEqual(
            _host_timestamp_value(accepted, "timestamp").isoformat(),
            "2026-08-09T12:34:56.123000+00:00",
        )
        for rejected in (
            "2026-08-09T12:34:56Z",
            "2026-08-09T12:34:56.1Z",
            "2026-08-09T12:34:56.12Z",
            "2026-08-09T12:34:56.1234Z",
            "2026-08-09T12:34:56.12345Z",
            "2026-08-09T12:34:56.123456Z",
            "2026-08-09T12:34:56.123+00:00",
            "2026-08-09T12:34:56.123-05:00",
        ):
            with self.subTest(timestamp=rejected), self.assertRaisesRegex(
                ContractError, "exactly three fractional UTC digits and Z"
            ):
                _host_timestamp_value(rejected, "timestamp")

    def test_workload_status_is_code_owned_and_rejects_fast_500(self) -> None:
        workload, _ = workload_manifest()
        workload["workloads"][0]["requests"][0]["expected_status_by_arm"][
            "cpa_cag"
        ] = 500
        with self.assertRaisesRegex(ContractError, "code-owned workload contract"):
            validate_workload_manifest(workload)

    def test_counted_mock_snapshots_and_side_effects_fail_closed(self) -> None:
        cases = []
        delta_drift = copy.deepcopy(self.good_measurements)
        delta_drift["paired_cells"][0]["mock_counters"]["delta"]["provider"] += 1
        cases.append(("delta", delta_drift, "does not match"))

        blocked_forward = copy.deepcopy(self.good_measurements)
        blocked_cell = next(
            cell
            for cell in blocked_forward["absolute_cells"]
            if cell["workload"] == "five_repository_activation"
        )
        for snapshot in ("after", "delta"):
            blocked_cell["mock_counters"][snapshot] = {
                "auth": 1,
                "mock": 1,
                "provider": 1,
            }
        cases.append(("blocked", blocked_forward, "side-effect contract"))

        nonzero_before = copy.deepcopy(self.good_measurements)
        nonzero_before["paired_cells"][0]["mock_counters"]["before"]["mock"] = 1
        cases.append(("before", nonzero_before, "post-reset zero"))

        for label, value, message in cases:
            with self.subTest(label=label), self.assertRaisesRegex(
                ContractError, message
            ):
                validate_measurements(
                    value,
                    canonical_bytes(value) + b"\n",
                    self.good_config,
                    self.good_config_raw,
                    self.good_workload,
                )

    def test_measurement_timeline_is_serial_and_elapsed_bound(self) -> None:
        overlap = copy.deepcopy(self.good_measurements)
        first, second = overlap["paired_cells"][:2]
        second["started_at"] = first["started_at"]
        start = datetime.fromisoformat(second["started_at"].replace("Z", "+00:00"))
        second["completed_at"] = (
            start + timedelta(seconds=float(second["elapsed_seconds"]))
        ).astimezone(timezone.utc).isoformat(timespec="milliseconds").replace(
            "+00:00", "Z"
        )
        with self.assertRaisesRegex(ContractError, "overlaps or precedes"):
            validate_measurements(
                overlap,
                canonical_bytes(overlap) + b"\n",
                self.good_config,
                self.good_config_raw,
                self.good_workload,
            )

        elapsed_drift = copy.deepcopy(self.good_measurements)
        cell = elapsed_drift["paired_cells"][0]
        end = datetime.fromisoformat(cell["completed_at"].replace("Z", "+00:00"))
        cell["completed_at"] = (
            end + timedelta(seconds=10)
        ).astimezone(timezone.utc).isoformat(timespec="milliseconds").replace(
            "+00:00", "Z"
        )
        with self.assertRaisesRegex(ContractError, "wall-clock interval"):
            validate_measurements(
                elapsed_drift,
                canonical_bytes(elapsed_drift) + b"\n",
                self.good_config,
                self.good_config_raw,
                self.good_workload,
            )

        shuffled = copy.deepcopy(self.good_measurements)
        shuffled["paired_cells"][0], shuffled["paired_cells"][1] = (
            shuffled["paired_cells"][1],
            shuffled["paired_cells"][0],
        )
        with self.assertRaisesRegex(ContractError, "exact seeded execution sequence"):
            validate_measurements(
                shuffled,
                canonical_bytes(shuffled) + b"\n",
                self.good_config,
                self.good_config_raw,
                self.good_workload,
            )

    def test_large_payload_wall_tolerances_are_closed_by_scope(self) -> None:
        for offset_ms, accepted in ((5000, True), (5001, False)):
            with self.subTest(field="cell", offset_ms=offset_ms):
                value = copy.deepcopy(self.good_measurements)
                cell = value["large_payload_cells"][0]
                completed = datetime.fromisoformat(
                    cell["completed_at"].replace("Z", "+00:00")
                )
                cell["completed_at"] = (
                    completed + timedelta(milliseconds=offset_ms)
                ).astimezone(timezone.utc).isoformat(timespec="milliseconds").replace(
                    "+00:00", "Z"
                )
                if accepted:
                    validate_measurements(
                        value,
                        canonical_bytes(value) + b"\n",
                        self.good_config,
                        self.good_config_raw,
                        self.good_workload,
                    )
                else:
                    with self.assertRaisesRegex(ContractError, "wall-clock interval"):
                        validate_measurements(
                            value,
                            canonical_bytes(value) + b"\n",
                            self.good_config,
                            self.good_config_raw,
                            self.good_workload,
                        )

        for offset_ms, accepted in ((5, True), (6, False)):
            with self.subTest(field="rss_sample", offset_ms=offset_ms):
                value = copy.deepcopy(self.good_measurements)
                sample = value["large_payload_cells"][0]["rss_baseline_samples"][0]
                observed = datetime.fromisoformat(
                    sample["observed_at"].replace("Z", "+00:00")
                )
                sample["observed_at"] = (
                    observed + timedelta(milliseconds=offset_ms)
                ).astimezone(timezone.utc).isoformat(timespec="milliseconds").replace(
                    "+00:00", "Z"
                )
                if accepted:
                    validate_measurements(
                        value,
                        canonical_bytes(value) + b"\n",
                        self.good_config,
                        self.good_config_raw,
                        self.good_workload,
                    )
                else:
                    with self.assertRaisesRegex(ContractError, "wall timestamp"):
                        validate_measurements(
                            value,
                            canonical_bytes(value) + b"\n",
                            self.good_config,
                            self.good_config_raw,
                            self.good_workload,
                        )

    def test_exact_double_interval_resource_gap_fails_closed(self) -> None:
        value = copy.deepcopy(self.good_measurements)
        value["paired_cells"][0]["resource_samples"][2]["elapsed_ms"] = 3000
        with self.assertRaisesRegex(ContractError, "monotonic/continuous"):
            validate_measurements(
                value,
                canonical_bytes(value) + b"\n",
                self.good_config,
                self.good_config_raw,
                self.good_workload,
            )

    def test_post_boundary_normal_samples_fail_closed(self) -> None:
        resource_value = copy.deepcopy(self.good_measurements)
        resource_cell = resource_value["paired_cells"][0]
        resource_row = copy.deepcopy(resource_cell["resource_samples"][-1])
        resource_cell["resource_samples"][-1]["final_sample"] = False
        resource_row["elapsed_ms"] = resource_cell["elapsed_seconds"] * 1000 + 500
        resource_cell["resource_samples"].append(resource_row)
        with self.assertRaisesRegex(ContractError, "exceeds elapsed_seconds"):
            validate_measurements(
                resource_value,
                canonical_bytes(resource_value) + b"\n",
                self.good_config,
                self.good_config_raw,
                self.good_workload,
            )

        queue_value = copy.deepcopy(self.good_measurements)
        queue_cell = next(
            cell for cell in queue_value["paired_cells"] if cell["arm"] == "cpa_cag"
        )
        queue_row = copy.deepcopy(queue_cell["queue_samples"][-1])
        queue_cell["queue_samples"][-1]["final_sample"] = False
        queue_row["elapsed_ms"] = queue_cell["elapsed_seconds"] * 1000 + 50
        queue_cell["queue_samples"].append(queue_row)
        with self.assertRaisesRegex(ContractError, "exceeds elapsed_seconds"):
            validate_measurements(
                queue_value,
                canonical_bytes(queue_value) + b"\n",
                self.good_config,
                self.good_config_raw,
                self.good_workload,
            )

    def test_dense_tail_samples_cannot_dilute_host_or_queue_metrics(self) -> None:
        resource_value = copy.deepcopy(self.good_measurements)
        resource_cell = resource_value["absolute_cells"][0]
        self.assertEqual(resource_cell["elapsed_seconds"], 120.0)
        cadence_rows = resource_cell["resource_samples"][:-1]
        for index, sample in enumerate(cadence_rows):
            sample["collector_host_cpu_percent"] = 0.0
            sample["cpu_percent"] = 0.0
            sample["host_cpu_percent"] = 50.0 if index < 20 else 0.0
            sample["mock_cpu_percent"] = 0.0
        tail_template = copy.deepcopy(resource_cell["resource_samples"][-1])
        for key in (
            "collector_host_cpu_percent",
            "cpu_percent",
            "host_cpu_percent",
            "inactive_cpa_cpu_percent",
            "mock_cpu_percent",
            "steal_cpu_percent",
        ):
            tail_template[key] = 0.0
        dense_tail = []
        for index in range(2500):
            sample = copy.deepcopy(tail_template)
            sample["elapsed_ms"] = 119000.0 + ((index + 1) * 1000.0 / 2500)
            sample["final_sample"] = index == 2499
            dense_tail.append(sample)
        resource_cell["resource_samples"] = [*cadence_rows, *dense_tail]
        with self.assertRaisesRegex(ContractError, "too many samples for the fixed cadence"):
            validate_measurements(
                resource_value,
                canonical_bytes(resource_value) + b"\n",
                self.good_config,
                self.good_config_raw,
                self.good_workload,
            )

        queue_value = copy.deepcopy(self.good_measurements)
        queue_cell = next(
            cell
            for cell in queue_value["absolute_cells"]
            if cell["arm"] == "cpa_cag" and cell["elapsed_seconds"] == 120.0
        )
        queue_cadence_rows = queue_cell["queue_samples"][:-1]
        queue_template = copy.deepcopy(queue_cell["queue_samples"][-1])
        dense_queue_tail = []
        for index in range(2500):
            sample = copy.deepcopy(queue_template)
            sample["elapsed_ms"] = 119900.0 + ((index + 1) * 100.0 / 2500)
            sample["final_sample"] = index == 2499
            dense_queue_tail.append(sample)
        queue_cell["queue_samples"] = [*queue_cadence_rows, *dense_queue_tail]
        with self.assertRaisesRegex(ContractError, "too many samples for the fixed cadence"):
            validate_measurements(
                queue_value,
                canonical_bytes(queue_value) + b"\n",
                self.good_config,
                self.good_config_raw,
                self.good_workload,
            )

    def test_normal_samples_enforce_cadence_minimum_gap(self) -> None:
        resource_value = copy.deepcopy(self.good_measurements)
        resource_value["paired_cells"][0]["resource_samples"][2]["elapsed_ms"] = 1499.0
        with self.assertRaisesRegex(ContractError, "minimum fixed-cadence interval"):
            validate_measurements(
                resource_value,
                canonical_bytes(resource_value) + b"\n",
                self.good_config,
                self.good_config_raw,
                self.good_workload,
            )

        queue_value = copy.deepcopy(self.good_measurements)
        queue_cell = next(
            cell for cell in queue_value["paired_cells"] if cell["arm"] == "cpa_cag"
        )
        queue_cell["queue_samples"][2]["elapsed_ms"] = 149.9
        with self.assertRaisesRegex(ContractError, "minimum fixed-cadence interval"):
            validate_measurements(
                queue_value,
                canonical_bytes(queue_value) + b"\n",
                self.good_config,
                self.good_config_raw,
                self.good_workload,
            )

    def test_insufficient_latency_samples_fail_closed(self) -> None:
        value = copy.deepcopy(self.good_measurements)
        cell = value["paired_cells"][0]
        cell["latency_samples_ms"] = cell["latency_samples_ms"][:-1]
        cell["successful_samples"] -= 1
        cell["completed_requests"] -= 1
        raw = canonical_bytes(value) + b"\n"
        with self.assertRaisesRegex(ContractError, "successful_samples"):
            validate_measurements(value, raw, self.good_config, self.good_config_raw, self.good_workload)

    def test_cell_count_gaps_cannot_hide_cleared_error_fields(self) -> None:
        missing_http_error = copy.deepcopy(self.good_measurements)
        http_cell = missing_http_error["paired_cells"][0]
        http_cell["planned_requests"] += 1
        http_cell["completed_requests"] += 1
        http_cell["unexpected_http_errors"] = 0

        missing_infrastructure_error = copy.deepcopy(self.good_measurements)
        infrastructure_cell = missing_infrastructure_error["paired_cells"][0]
        infrastructure_cell["planned_requests"] += 1
        infrastructure_cell["infrastructure_errors"] = []

        for label, value, message in (
            (
                "completed_without_success_or_http_error",
                missing_http_error,
                "completed/successful request gap exceeds HTTP errors",
            ),
            (
                "planned_without_completion_or_infrastructure_error",
                missing_infrastructure_error,
                "planned/completed request gap exceeds infrastructure errors",
            ),
        ):
            with self.subTest(label=label), self.assertRaisesRegex(
                ContractError, message
            ):
                validate_measurements(
                    value,
                    canonical_bytes(value) + b"\n",
                    self.good_config,
                    self.good_config_raw,
                    self.good_workload,
                )

    def test_warmup_only_errors_allow_strict_counts_but_build_truthful_fail(
        self,
    ) -> None:
        value = copy.deepcopy(self.good_measurements)
        cell = value["paired_cells"][0]
        cell["unexpected_http_errors"] = 1
        cell["infrastructure_errors"] = ["warmup-only connection failure"]
        self.assertLess(
            cell["completed_requests"] - cell["successful_samples"],
            cell["unexpected_http_errors"],
        )
        self.assertLess(
            cell["planned_requests"] - cell["completed_requests"],
            len(cell["infrastructure_errors"]),
        )

        raw = canonical_bytes(value) + b"\n"
        validated, summaries, baseline, extra = validate_measurements(
            value,
            raw,
            self.good_config,
            self.good_config_raw,
            self.good_workload,
        )
        evidence = build_evidence(
            self.good_config,
            self.good_config_raw,
            validated,
            raw,
            summaries,
            baseline,
            extra,
        )
        self.assertEqual(
            evidence["metrics"]["unexpected_http_or_infrastructure_errors"], 2
        )
        self.assertEqual(
            evidence["gates"]["unexpected_http_or_infrastructure_errors"][
                "status"
            ],
            "FAIL",
        )
        self.assertEqual(evidence["status"], "FAIL")
        self.assertEqual(
            validate_evidence_bundle(
                evidence,
                self.good_config,
                self.good_config_raw,
                validated,
                raw,
                summaries,
                baseline,
                extra,
                require_pass=False,
            )["status"],
            "FAIL",
        )

    def test_measurement_candidate_cpa_and_runtime_identity_mismatch_fail(self) -> None:
        mutations = {
            "run_config": lambda value: value.__setitem__("run_config_sha256", "e" * 64),
            "candidate": lambda value: value.__setitem__("candidate_manifest_sha256", "f" * 64),
            "cpa": lambda value: value["paired_cells"][0]["runtime"].__setitem__("cpa_binary_sha256", "e" * 64),
            "cag": lambda value: next(
                cell for cell in value["paired_cells"] if cell["arm"] == "cpa_cag"
            )["runtime"].__setitem__("loaded_cag_so_sha256", "e" * 64),
            "mock_image": lambda value: value["paired_cells"][0]["runtime"].__setitem__(
                "mock_image_id", "sha256:" + "e" * 64
            ),
            "mock_source": lambda value: value["paired_cells"][0]["runtime"].__setitem__(
                "mock_source_sha256", "e" * 64
            ),
        }
        for label, mutate in mutations.items():
            value = copy.deepcopy(self.good_measurements)
            mutate(value)
            raw = canonical_bytes(value) + b"\n"
            with self.subTest(label=label), self.assertRaises(ContractError):
                validate_measurements(value, raw, self.good_config, self.good_config_raw, self.good_workload)

        container_drift = copy.deepcopy(self.good_measurements)
        next(
            cell
            for cell in container_drift["paired_cells"]
            if cell["arm"] == "cpa_only"
        )["runtime"]["cpa_container_id"] = "different-baseline-container"
        with self.assertRaisesRegex(ContractError, "one fixed container"):
            validate_measurements(
                container_drift,
                canonical_bytes(container_drift) + b"\n",
                self.good_config,
                self.good_config_raw,
                self.good_workload,
            )

    def test_raw_runtime_rejects_unsafe_container_security(self) -> None:
        for role, key, unsafe in (
            ("cpa", "no_new_privileges", False),
            ("cpa", "pids_limit", 0),
            ("mock", "no_new_privileges", False),
            ("mock", "pids_limit", 0),
        ):
            value = copy.deepcopy(self.good_measurements)
            value["paired_cells"][0]["runtime"]["container_security"][role][
                key
            ] = unsafe
            with self.subTest(role=role, key=key), self.assertRaises(
                ContractError
            ):
                validate_measurements(
                    value,
                    canonical_bytes(value) + b"\n",
                    self.good_config,
                    self.good_config_raw,
                    self.good_workload,
                )

    def test_container_security_must_remain_stable_across_cells_and_warm_lane(
        self,
    ) -> None:
        validated, _, _, _ = validate_measurements(
            self.good_measurements,
            self.good_measurements_raw,
            self.good_config,
            self.good_config_raw,
            self.good_workload,
        )
        self.assertEqual(
            validated["warm_rss"]["runtime"]["docker_common_mount_sha256"],
            validated["paired_cells"][0]["runtime"][
                "docker_common_mount_sha256"
            ],
        )

        cross_cell = copy.deepcopy(self.good_measurements)
        cross_cell["absolute_cells"][0]["runtime"]["container_security"]["cpa"][
            "pids_limit"
        ] += 1
        with self.assertRaisesRegex(ContractError, "security observations changed"):
            validate_measurements(
                cross_cell,
                canonical_bytes(cross_cell) + b"\n",
                self.good_config,
                self.good_config_raw,
                self.good_workload,
            )

        warm_lane = copy.deepcopy(self.good_measurements)
        warm_lane["warm_rss"]["runtime"]["container_security"]["mock"][
            "pids_limit"
        ] += 1
        with self.assertRaisesRegex(ContractError, "security observations changed"):
            validate_measurements(
                warm_lane,
                canonical_bytes(warm_lane) + b"\n",
                self.good_config,
                self.good_config_raw,
                self.good_workload,
            )

        base_config_drift = copy.deepcopy(self.good_measurements)
        base_config_drift["paired_cells"][0]["runtime"][
            "cpa_base_config_sha256"
        ] = "e" * 64
        with self.assertRaisesRegex(ContractError, "non-plugin runtime configuration"):
            validate_measurements(
                base_config_drift,
                canonical_bytes(base_config_drift) + b"\n",
                self.good_config,
                self.good_config_raw,
                self.good_workload,
            )

        docker_config_drift = copy.deepcopy(self.good_measurements)
        docker_config_drift["paired_cells"][0]["runtime"][
            "docker_comparable_sha256"
        ] = "e" * 64
        with self.assertRaisesRegex(ContractError, "Docker performance configuration"):
            validate_measurements(
                docker_config_drift,
                canonical_bytes(docker_config_drift) + b"\n",
                self.good_config,
                self.good_config_raw,
                self.good_workload,
            )

        arm_mount_drift = copy.deepcopy(self.good_measurements)
        arm_mount_drift["absolute_cells"][0]["runtime"][
            "docker_arm_specific_mount_sha256"
        ] = "e" * 64
        with self.assertRaisesRegex(ContractError, "mount projection hashes"):
            validate_measurements(
                arm_mount_drift,
                canonical_bytes(arm_mount_drift) + b"\n",
                self.good_config,
                self.good_config_raw,
                self.good_workload,
            )

        forged_projection_hash = copy.deepcopy(self.good_measurements)
        forged_projection_hash["paired_cells"][0]["runtime"][
            "docker_mount_projection_sha256"
        ] = "e" * 64
        with self.assertRaisesRegex(ContractError, "mount projection hashes"):
            validate_measurements(
                forged_projection_hash,
                canonical_bytes(forged_projection_hash) + b"\n",
                self.good_config,
                self.good_config_raw,
                self.good_workload,
            )

        warm_common_mount_drift = copy.deepcopy(self.good_measurements)
        warm_runtime = warm_common_mount_drift["warm_rss"]["runtime"]
        warm_projection = warm_runtime["mount_identity_projection"]
        warm_projection["common_mounts"][0]["mode"] = "ro,warm-only-drift"
        warm_projection["common_sha256"] = sha256_bytes(
            canonical_bytes(warm_projection["common_mounts"])
        )
        warm_runtime["docker_common_mount_sha256"] = warm_projection[
            "common_sha256"
        ]
        warm_runtime["docker_mount_projection_sha256"] = sha256_bytes(
            canonical_bytes(warm_projection)
        )
        with self.assertRaisesRegex(
            ContractError, "warm RSS lane common mount projection drifted from Host A/B"
        ):
            validate_measurements(
                warm_common_mount_drift,
                canonical_bytes(warm_common_mount_drift) + b"\n",
                self.good_config,
                self.good_config_raw,
                self.good_workload,
            )

        missing_projection = copy.deepcopy(self.good_measurements)
        missing_projection["paired_cells"][0]["runtime"].pop(
            "mount_identity_projection"
        )
        with self.assertRaisesRegex(ContractError, "must contain exactly"):
            validate_measurements(
                missing_projection,
                canonical_bytes(missing_projection) + b"\n",
                self.good_config,
                self.good_config_raw,
                self.good_workload,
            )

        mock_container_drift = copy.deepcopy(self.good_measurements)
        mock_container_drift["paired_cells"][0]["runtime"][
            "mock_container_id"
        ] = "different-mock-container"
        with self.assertRaisesRegex(ContractError, "one fixed counted-Mock"):
            validate_measurements(
                mock_container_drift,
                canonical_bytes(mock_container_drift) + b"\n",
                self.good_config,
                self.good_config_raw,
                self.good_workload,
            )

    def test_derived_evidence_tampering_fails_recomputation(self) -> None:
        value = copy.deepcopy(self.good_evidence)
        value["metrics"]["host_throughput_vs_cpa_only"] = 0.5
        with self.assertRaisesRegex(ContractError, "raw-derived"):
            validate_evidence_bundle(
                value,
                self.good_config,
                self.good_config_raw,
                self.good_measurements,
                self.good_measurements_raw,
                self.good_summaries,
                self.good_baseline,
                self.good_extra,
            )

        mount_identity = copy.deepcopy(self.good_evidence)
        mount_identity["mount_identity"][
            "common_docker_projection_sha256"
        ] = "e" * 64
        with self.assertRaisesRegex(ContractError, "raw-derived"):
            validate_evidence_bundle(
                mount_identity,
                self.good_config,
                self.good_config_raw,
                self.good_measurements,
                self.good_measurements_raw,
                self.good_summaries,
                self.good_baseline,
                self.good_extra,
            )

        security = copy.deepcopy(self.good_evidence)
        security["container_security"]["cpa_only"]["pids_limit"] += 1
        with self.assertRaisesRegex(ContractError, "raw-derived"):
            validate_evidence_bundle(
                security,
                self.good_config,
                self.good_config_raw,
                self.good_measurements,
                self.good_measurements_raw,
                self.good_summaries,
                self.good_baseline,
                self.good_extra,
            )

    def test_threshold_failure_is_truthful_fail_and_never_passes_gate(self) -> None:
        value = copy.deepcopy(self.good_measurements)
        for cell in value["paired_cells"]:
            if cell["arm"] == "cpa_cag":
                cell["latency_samples_ms"] = [2.0] * len(cell["latency_samples_ms"])
            else:
                cell["planned_requests"] = 1_200
                cell["completed_requests"] = 1_200
                cell["successful_samples"] = 1_200
                cell["latency_samples_ms"] = [1.0] * 1_200
                for snapshot in ("after", "delta"):
                    cell["mock_counters"][snapshot] = {
                        "auth": 1_200,
                        "mock": 1_200,
                        "provider": 1_200,
                    }
        raw = canonical_bytes(value) + b"\n"
        validated, summaries, baseline, extra = validate_measurements(
            value, raw, self.good_config, self.good_config_raw, self.good_workload
        )
        evidence = build_evidence(
            self.good_config,
            self.good_config_raw,
            validated,
            raw,
            summaries,
            baseline,
            extra,
        )
        self.assertEqual(evidence["status"], "FAIL")
        self.assertEqual(evidence["gates"]["host_throughput_vs_cpa_only"]["status"], "FAIL")
        self.assertEqual(evidence["gates"]["fixed_workload_p99_regression_percent"]["status"], "FAIL")
        with self.assertRaisesRegex(ContractError, "not PASS"):
            validate_evidence_bundle(
                evidence,
                self.good_config,
                self.good_config_raw,
                validated,
                raw,
                summaries,
                baseline,
                extra,
            )

    def test_measurement_window_and_pair_elapsed_are_fail_closed(self) -> None:
        extended = copy.deepcopy(self.good_measurements)
        extended["paired_cells"][0]["elapsed_seconds"] = 126.0
        with self.assertRaisesRegex(ContractError, "planned measurement window"):
            validate_measurements(
                extended,
                canonical_bytes(extended) + b"\n",
                self.good_config,
                self.good_config_raw,
                self.good_workload,
            )

        mismatched = copy.deepcopy(self.good_measurements)
        cell = next(
            item
            for item in mismatched["paired_cells"]
            if item["pair_id"] == "c1-r1" and item["arm"] == "cpa_cag"
        )
        cell["elapsed_seconds"] = 121.1
        cell["resource_samples"][-1]["final_sample"] = False
        resource_final = copy.deepcopy(cell["resource_samples"][-1])
        resource_final["elapsed_ms"] = 121_000
        resource_final["final_sample"] = True
        cell["resource_samples"].append(resource_final)
        cell["queue_samples"][-1]["final_sample"] = False
        queue_template = copy.deepcopy(cell["queue_samples"][-1])
        for index in range(1, 12):
            sample = copy.deepcopy(queue_template)
            sample["elapsed_ms"] = 120_000 + index * 100
            sample["final_sample"] = index == 11
            cell["queue_samples"].append(sample)
        retime_measurements(mismatched, self.good_config)

        with self.assertRaisesRegex(ContractError, "elapsed windows are not comparable"):
            validate_measurements(
                mismatched,
                canonical_bytes(mismatched) + b"\n",
                self.good_config,
                self.good_config_raw,
                self.good_workload,
            )

    def test_high_cpu_can_only_be_diagnostic_not_baseline(self) -> None:
        value = copy.deepcopy(self.good_measurements)
        value["baseline_eligibility"]["background_cpu_percent"] = [25.0] * 300
        raw = canonical_bytes(value) + b"\n"
        validated, summaries, baseline, extra = validate_measurements(
            value, raw, self.good_config, self.good_config_raw, self.good_workload
        )
        evidence = build_evidence(
            self.good_config,
            self.good_config_raw,
            validated,
            raw,
            summaries,
            baseline,
            extra,
        )
        self.assertFalse(evidence["baseline_eligibility"]["eligible"])
        self.assertEqual(evidence["status"], "DIAGNOSTIC_NOT_BASELINE")
        with self.assertRaisesRegex(ContractError, "not PASS"):
            validate_evidence_bundle(
                evidence,
                self.good_config,
                self.good_config_raw,
                validated,
                raw,
                summaries,
                baseline,
                extra,
            )

    def test_ineligible_baseline_cannot_mask_threshold_failure(self) -> None:
        value = copy.deepcopy(self.good_measurements)
        value["baseline_eligibility"]["background_cpu_percent"] = [25.0] * 300
        for sample in value["warm_rss"]["resource_samples"]:
            if 3300 <= sample["elapsed_seconds"] <= 3600:
                sample["rss_mib"] = 300.0

        raw = canonical_bytes(value) + b"\n"
        validated, summaries, baseline, extra = validate_measurements(
            value, raw, self.good_config, self.good_config_raw, self.good_workload
        )
        evidence = build_evidence(
            self.good_config,
            self.good_config_raw,
            validated,
            raw,
            summaries,
            baseline,
            extra,
        )

        self.assertFalse(evidence["baseline_eligibility"]["eligible"])
        self.assertEqual(evidence["gates"]["warm_rss_growth_60m_mib"]["status"], "FAIL")
        self.assertEqual(evidence["status"], "FAIL")

    def test_measurement_period_cpu_interference_is_diagnostic(self) -> None:
        value = copy.deepcopy(self.good_measurements)
        for sample in value["paired_cells"][0]["resource_samples"]:
            sample["host_cpu_percent"] = 96.0
        raw = canonical_bytes(value) + b"\n"
        validated, summaries, baseline, extra = validate_measurements(
            value, raw, self.good_config, self.good_config_raw, self.good_workload
        )
        evidence = build_evidence(
            self.good_config,
            self.good_config_raw,
            validated,
            raw,
            summaries,
            baseline,
            extra,
        )
        self.assertEqual(evidence["status"], "DIAGNOSTIC_NOT_BASELINE")
        self.assertFalse(evidence["baseline_eligibility"]["eligible"])
        self.assertEqual(
            evidence["baseline_eligibility"][
                "measurement_host_cpu_p95_percent"
            ],
            96.0,
        )
        self.assertIn(
            "sustained_measurement_cpu_interference",
            evidence["baseline_eligibility"]["reason_codes"],
        )

    def test_residual_background_cpu_detects_sub_saturation_interference(self) -> None:
        value = copy.deepcopy(self.good_measurements)
        for cell in (*value["paired_cells"], *value["absolute_cells"]):
            for sample in cell["resource_samples"]:
                sample["host_cpu_percent"] = 50.0
        for sample in value["warm_rss"]["resource_samples"]:
            sample["host_cpu_percent"] = 50.0
        raw = canonical_bytes(value) + b"\n"
        validated, summaries, baseline, extra = validate_measurements(
            value, raw, self.good_config, self.good_config_raw, self.good_workload
        )
        evidence = build_evidence(
            self.good_config,
            self.good_config_raw,
            validated,
            raw,
            summaries,
            baseline,
            extra,
        )
        eligibility = evidence["baseline_eligibility"]
        self.assertEqual(evidence["status"], "DIAGNOSTIC_NOT_BASELINE")
        self.assertEqual(eligibility["measurement_host_cpu_p95_percent"], 50.0)
        self.assertEqual(eligibility["measurement_residual_cpu_p95_percent"], 40.0)
        self.assertGreater(
            eligibility["measurement_residual_cpu_rolling_60s_peak_percent"],
            20.0,
        )

    def test_inactive_cpa_cpu_is_not_subtracted_from_residual(self) -> None:
        value = copy.deepcopy(self.good_measurements)
        for sample in value["paired_cells"][0]["resource_samples"]:
            sample["host_cpu_percent"] = 60.0
            sample["inactive_cpa_cpu_percent"] = 800.0
        raw = canonical_bytes(value) + b"\n"
        validated, summaries, baseline, extra = validate_measurements(
            value, raw, self.good_config, self.good_config_raw, self.good_workload
        )
        evidence = build_evidence(
            self.good_config,
            self.good_config_raw,
            validated,
            raw,
            summaries,
            baseline,
            extra,
        )
        eligibility = evidence["baseline_eligibility"]
        self.assertEqual(evidence["status"], "DIAGNOSTIC_NOT_BASELINE")
        self.assertEqual(
            eligibility["measurement_inactive_cpa_cpu_p95_percent"], 50.0
        )
        self.assertEqual(
            eligibility["measurement_residual_cpu_p95_percent"], 50.0
        )

    def test_warm_resource_samples_reject_more_than_one_terminal_extra(
        self,
    ) -> None:
        value = copy.deepcopy(self.good_measurements)
        samples = value["warm_rss"]["resource_samples"]
        self.assertEqual(len(samples), 3601)
        for elapsed in (3600.5, 3601.0):
            extra = copy.deepcopy(samples[-1])
            extra["elapsed_seconds"] = elapsed
            samples.append(extra)
        self.assertEqual(len(samples), 3603)

        with self.assertRaisesRegex(
            ContractError, "too many samples for the fixed cadence"
        ):
            validate_measurements(
                value,
                canonical_bytes(value) + b"\n",
                self.good_config,
                self.good_config_raw,
                self.good_workload,
            )

    def test_dense_low_rss_tail_cannot_turn_truthful_warm_failure_into_pass(
        self,
    ) -> None:
        value = copy.deepcopy(self.good_measurements)
        samples = value["warm_rss"]["resource_samples"]
        for sample in samples:
            if 3300 <= sample["elapsed_seconds"] <= 3600:
                sample["rss_mib"] = 300.0

        raw = canonical_bytes(value) + b"\n"
        validated, summaries, baseline, extra = validate_measurements(
            value,
            raw,
            self.good_config,
            self.good_config_raw,
            self.good_workload,
        )
        truthful = build_evidence(
            self.good_config,
            self.good_config_raw,
            validated,
            raw,
            summaries,
            baseline,
            extra,
        )
        self.assertGreater(truthful["metrics"]["warm_rss_growth_60m_mib"], 64)
        self.assertEqual(truthful["gates"]["warm_rss_growth_60m_mib"]["status"], "FAIL")
        self.assertEqual(truthful["status"], "FAIL")

        final_sample = samples[-1]
        dense_tail = []
        for index in range(400):
            sample = copy.deepcopy(final_sample)
            sample["elapsed_seconds"] = 3599.0 + ((index + 1) / 401.0)
            sample["rss_mib"] = 0.0
            dense_tail.append(sample)
        value["warm_rss"]["resource_samples"] = [
            *samples[:-1],
            *dense_tail,
            final_sample,
        ]
        self.assertEqual(len(value["warm_rss"]["resource_samples"]), 4001)

        with self.assertRaisesRegex(
            ContractError, "too many samples for the fixed cadence"
        ):
            validate_measurements(
                value,
                canonical_bytes(value) + b"\n",
                self.good_config,
                self.good_config_raw,
                self.good_workload,
            )

    def test_warm_nonterminal_samples_enforce_half_interval_gap(self) -> None:
        value = copy.deepcopy(self.good_measurements)
        samples = value["warm_rss"]["resource_samples"]
        samples[1000]["elapsed_seconds"] = (
            samples[999]["elapsed_seconds"] + 0.25
        )

        with self.assertRaisesRegex(
            ContractError, "minimum fixed-cadence interval"
        ):
            validate_measurements(
                value,
                canonical_bytes(value) + b"\n",
                self.good_config,
                self.good_config_raw,
                self.good_workload,
            )

    def test_post_3600_sample_cannot_dilute_warm_rss_growth(self) -> None:
        value = copy.deepcopy(self.good_measurements)
        value["warm_rss"]["resource_samples"].append(
            {
                "cpu_percent": 0.0,
                "collector_host_cpu_percent": 0.0,
                "elapsed_seconds": 3600.25,
                "host_cpu_percent": 0.0,
                "inactive_cpa_cpu_percent": 0.0,
                "mock_cpu_percent": 0.0,
                "rss_mib": 0.0,
                "steal_cpu_percent": 0.0,
            }
        )
        samples = value["warm_rss"]["resource_samples"]
        self.assertEqual(len(samples), 3602)
        self.assertLess(
            samples[-1]["elapsed_seconds"] - samples[-2]["elapsed_seconds"], 0.5
        )
        raw = canonical_bytes(value) + b"\n"
        validated, summaries, baseline, extra = validate_measurements(
            value, raw, self.good_config, self.good_config_raw, self.good_workload
        )
        evidence = build_evidence(
            self.good_config,
            self.good_config_raw,
            validated,
            raw,
            summaries,
            baseline,
            extra,
        )
        self.assertEqual(
            evidence["metrics"]["warm_rss_growth_60m_mib"],
            self.good_evidence["metrics"]["warm_rss_growth_60m_mib"],
        )

    def test_warm_lane_records_bounded_final_batch_drain_separately(self) -> None:
        value = copy.deepcopy(self.good_measurements)
        value["warm_rss"]["elapsed_seconds"] = 3606.0
        retime_measurements(value, self.good_config)
        raw = canonical_bytes(value) + b"\n"
        validated, summaries, baseline, extra = validate_measurements(
            value, raw, self.good_config, self.good_config_raw, self.good_workload
        )
        evidence = build_evidence(
            self.good_config,
            self.good_config_raw,
            validated,
            raw,
            summaries,
            baseline,
            extra,
        )
        self.assertEqual(evidence["warm_rss_60m"]["duration_seconds"], 3600.0)
        self.assertEqual(value["warm_rss"]["elapsed_seconds"], 3606.0)

        value["warm_rss"]["elapsed_seconds"] = 3726.0
        retime_measurements(value, self.good_config)
        with self.assertRaisesRegex(ContractError, "drain bound"):
            validate_measurements(
                value,
                canonical_bytes(value) + b"\n",
                self.good_config,
                self.good_config_raw,
                self.good_workload,
            )

    def test_candidate_manifest_tamper_and_dirty_state_fail(self) -> None:
        run, _ = run_config()
        candidate, _ = candidate_manifest()
        for label, mutate in (
            ("dirty", lambda value: value.__setitem__("dirty", True)),
            ("commit", lambda value: value.__setitem__("commit", "e" * 40)),
            ("so", lambda value: value["artifacts"][0].__setitem__("sha256", "e" * 64)),
        ):
            value = copy.deepcopy(candidate)
            mutate(value)
            with self.subTest(label=label), self.assertRaises(ContractError):
                validate_candidate_manifest(value, run["identities"]["cag"])

    def test_candidate_manifest_github_identifier_length_boundaries(self) -> None:
        run, _ = run_config()
        candidate, _ = candidate_manifest()
        candidate["run_id"] = "9" * 32
        candidate["run_attempt"] = "9" * 20
        self.assertEqual(
            validate_candidate_manifest(candidate, run["identities"]["cag"]),
            candidate,
        )

        for field, length in (("run_id", 33), ("run_attempt", 21)):
            value = copy.deepcopy(candidate)
            value[field] = "9" * length
            with self.subTest(field=field), self.assertRaisesRegex(
                ContractError, f"candidate manifest.{field}"
            ):
                validate_candidate_manifest(value, run["identities"]["cag"])

    def test_validator_cli_cross_binds_every_host_performance_file(self) -> None:
        (
            measurement,
            measurement_raw,
            config,
            config_raw,
            workload,
            workload_raw,
            run,
            run_raw,
            candidate,
            candidate_raw,
        ) = measurements()
        evidence = self.good_evidence
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            files = {
                "run-config.json": run_raw,
                "candidate.json": candidate_raw,
                "workloads.json": workload_raw,
                "performance-config.json": config_raw,
                "measurements.json": measurement_raw,
                "evidence.json": canonical_bytes(evidence) + b"\n",
            }
            for name, raw in files.items():
                (root / name).write_bytes(raw)
            arguments = [
                "host-performance",
                "--run-config",
                str(root / "run-config.json"),
                "--candidate-manifest",
                str(root / "candidate.json"),
                "--workload-manifest",
                str(root / "workloads.json"),
                "--config",
                str(root / "performance-config.json"),
                "--measurements",
                str(root / "measurements.json"),
                "--evidence",
                str(root / "evidence.json"),
            ]
            output = io.StringIO()
            original_resolve = Path.resolve
            configured_candidate = Path(run["paths"]["candidate_manifest"])

            def resolve_candidate(path: Path, strict: bool = False) -> Path:
                if path == configured_candidate:
                    return original_resolve(root / "candidate.json", strict=True)
                return original_resolve(path, strict=strict)

            candidate_binding = mock.patch.object(
                validator_cli,
                "validate_candidate_manifest_file",
                return_value=(candidate, candidate_raw),
            )
            path_binding = mock.patch.object(Path, "resolve", new=resolve_candidate)
            with candidate_binding, path_binding, contextlib.redirect_stdout(output):
                self.assertEqual(validator_cli.main(arguments), 0)
            self.assertIn('"status": "PASS"', output.getvalue())

            tampered = copy.deepcopy(evidence)
            tampered["identities"]["cpa"]["binary_sha256"] = "e" * 64
            (root / "evidence.json").write_bytes(canonical_bytes(tampered) + b"\n")
            with (
                mock.patch.object(
                    validator_cli,
                    "validate_candidate_manifest_file",
                    return_value=(candidate, candidate_raw),
                ),
                mock.patch.object(
                    Path,
                    "resolve",
                    new=resolve_candidate,
                ),
                contextlib.redirect_stderr(io.StringIO()),
            ):
                self.assertEqual(validator_cli.main(arguments), 2)


if __name__ == "__main__":
    unittest.main()
