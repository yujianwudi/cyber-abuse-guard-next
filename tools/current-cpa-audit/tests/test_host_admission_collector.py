from __future__ import annotations

import copy
import json
import os
import sqlite3
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


HERE = Path(__file__).resolve().parent
TOOL_DIR = HERE.parent
sys.path.insert(0, str(TOOL_DIR))
sys.path.insert(0, str(HERE))

from audit_contract import (  # noqa: E402
    BLOCK_REFUSAL_MESSAGE,
    candidate_identity,
    canonical_bytes,
    sha256_bytes,
)
import host_admission as host  # noqa: E402
import host_admission_collector as collector  # noqa: E402
from host_performance_fixtures import (  # noqa: E402
    candidate_manifest as performance_candidate_manifest,
    run_config as performance_run_config,
)


try:
    from jsonschema import Draft202012Validator
except ImportError:  # pragma: no cover - optional developer dependency
    Draft202012Validator = None  # type: ignore[assignment]


def fake_tools() -> dict[str, str]:
    sources = {
        key: f"{index:x}" * 64
        for index, key in enumerate(collector.TOOL_IDENTITY_SOURCE_KEYS, start=1)
    }
    tracked_runtime, tracked_runtime_raw = (
        collector.load_tracked_approved_runtime_identities()
    )
    sources["approved_runtime_identities_sha256"] = sha256_bytes(
        tracked_runtime_raw
    )
    sources["keeper_source_sha256"] = tracked_runtime["keeper"]["source_sha256"]
    return {**sources, "bundle_sha256": sha256_bytes(canonical_bytes(sources))}


def approved_runtime(tools: dict[str, str]) -> dict[str, object]:
    tracked, _ = collector.load_tracked_approved_runtime_identities()
    if tools["keeper_source_sha256"] != tracked["keeper"]["source_sha256"]:
        raise AssertionError("synthetic tool identity lost the tracked Keeper source")
    return copy.deepcopy(tracked)


def config_fixture(root: Path) -> tuple[dict[str, object], bytes]:
    run, _ = performance_run_config()
    tools = fake_tools()
    approval = approved_runtime(tools)
    host_dir = root / "evidence" / "host-admission"
    runtime_root = root / "unit-run-host-runtime"
    paths = {
        "approved_runtime_identities": str(root / "approved-runtime.json"),
        "approved_tool_identities": str(root / "approved-tools.json"),
        "audit_sqlite_database": str(runtime_root / "audit" / "events.db"),
        "candidate_manifest": str(root / "candidate" / "audit-candidate-manifest.json"),
        "candidate_store_zip": str(root / "candidate" / "cyber-abuse-guard_1.0.0_linux_amd64.zip"),
        "corpus_manifest": str(root / "evidence" / "corpus-manifest.json"),
        "host_admission_directory": str(host_dir),
        "machine_evidence": str(root / "evidence" / "machine-evidence.json"),
        "run_config": str(root / "run-config.json"),
        "runtime_root": str(runtime_root),
        "supplemental_manifest": str(root / "evidence" / "supplemental-zip-manifest.json"),
        "supplemental_policy": str(root / "evidence" / "supplemental-zip-policy.json"),
        "supplemental_results": str(root / "evidence" / "supplemental-zip-results.jsonl"),
        "transport_results": str(root / "evidence" / "transport-results.jsonl"),
    }
    keeper = approval["keeper"]
    value: dict[str, object] = {
        "approved_runtime_identities": copy.deepcopy(approval),
        "approved_runtime_identities_sha256": sha256_bytes(canonical_bytes(approval) + b"\n"),
        "approved_tool_identities": tools,
        "artifacts": {
            "store_zip_name": "cyber-abuse-guard_1.0.0_linux_amd64.zip",
            "store_zip_sha256": "e" * 64,
        },
        "candidate_manifest_sha256": "f" * 64,
        "identities": {
            "candidate": copy.deepcopy(run["identities"]["candidate"]),
            "cag": copy.deepcopy(run["identities"]["cag"]),
            "cpa": copy.deepcopy(run["identities"]["cpa"]),
            "keeper": {
                "base_image_ref": keeper["base_image_ref"],
                "contract": keeper["contract"],
                "expected_executor": collector.KEEPER_EXPECTED_EXECUTOR,
                "expected_mode": collector.REQUIRED_MODE,
                "expected_model": collector.MODEL,
                "expected_provider": collector.KEEPER_EXPECTED_PROVIDER,
                "image_id": keeper["image_id"],
                "image_ref": keeper["image_ref"],
                "port": collector.KEEPER_PORT,
                "repo_digest": keeper["image_ref"],
                "source_path": collector.KEEPER_CONTAINER_SOURCE,
                "source_sha256": keeper["source_sha256"],
            },
            "mock": copy.deepcopy(run["identities"]["mock"]),
        },
        "input_sha256": {key: f"{index:x}" * 64 for index, key in enumerate((
            "approved_runtime_identities", "approved_tool_identities", "corpus_manifest", "machine_evidence", "supplemental_manifest",
            "supplemental_policy", "supplemental_results", "transport_results",
        ), start=1)},
        "network": {
            "attachable": False,
            "internal": True,
            "member_count": 3,
            "name": "unit-run-host-net",
            "real_provider_forbidden": True,
        },
        "paths": paths,
        "plan": {
            "allow_probe_executions": 2,
            "block_probe_executions": 1,
            "maximum_sample_interval_ms": 2000,
            "minimum_sample_interval_ms": 500,
            "probe_endpoint": "/v1/chat/completions",
            "realtime_route_count": 14,
            "required_mode": "balanced",
            "sample_interval_ms": 1000,
            "stability_basis": host.STABILITY_BASIS,
            "windows": [
                {"duration_seconds": 300, "name": "host_300s", "sample_count": 301},
                {"duration_seconds": 3600, "name": "host_3600s", "sample_count": 3601},
            ],
        },
        "probe_contract": copy.deepcopy(collector.PROBE_CONTRACT),
        "roles": {
            role: {"container_name": f"unit-run-host-{role}", "label": f"host-admission-{role}"}
            for role in ("cpa", "keeper", "mock")
        },
        "run_config_sha256": "a" * 64,
        "run_id": "unit-run",
        "schema": collector.CONFIG_SCHEMA,
        "sqlite": {"checkpoint_mode": "TRUNCATE", "quick_check": "PRAGMA quick_check", "schema_version": 7},
        "usage_source": {"endpoint": "/keeper/stats", "field": "usage_records", "kind": "keeper_sqlite_persisted_records", "monotonic": True},
    }
    return value, canonical_bytes(value) + b"\n"


def manifest_fixture(
    config: dict[str, object], config_raw: bytes, root: Path
) -> tuple[dict[str, object], bytes, bytes, bytes]:
    raw_300 = b"{}\n" * 301
    raw_3600 = b"{}\n" * 3601
    realtime = b"{}\n" * 14
    host_dir = Path(config["paths"]["host_admission_directory"])  # type: ignore[index]
    host_dir.mkdir(parents=True)
    sqlite_raw = b"SQLite format 3\x00tracked-unit-evidence"
    (host_dir / "audit-events.sqlite3").write_bytes(sqlite_raw)
    candidate = config["identities"]["candidate"]  # type: ignore[index]
    cag = config["identities"]["cag"]  # type: ignore[index]
    value: dict[str, object] = {
        "approved_runtime_identities_sha256": config["approved_runtime_identities_sha256"],
        "candidate": {
            "candidate_artifact_digest": candidate["artifact"]["digest"],
            "candidate_manifest_sha256": config["candidate_manifest_sha256"],
            "cag_commit": cag["commit"],
            "cag_so_sha256": cag["so_sha256"],
            "cag_store_zip_sha256": config["artifacts"]["store_zip_sha256"],  # type: ignore[index]
            "cag_tree": cag["tree"],
            "cpa_commit": collector.CPA_COMMIT,
            "cpa_tag": collector.CPA_TAG,
        },
        "cleanup": {
            "all_owned_resources_absent": True,
            "evidence_preserved": True,
            "global_prune_used": False,
            "resources": [
                {"action": "removed", "id": char * 64, "kind": kind, "name": name, "run_label": "unit-run"}
                for char, kind, name in (
                    ("1", "container", "unit-run-host-cpa"),
                    ("2", "container", "unit-run-host-keeper"),
                    ("3", "container", "unit-run-host-mock"),
                    ("4", "network", "unit-run-host-net"),
                )
            ],
            "runtime_root_absent": True,
            "secret_files_absent": True,
            "status": "PASS",
            "unrelated_resources_touched": False,
        },
        "collector_tool_identities": copy.deepcopy(config["approved_tool_identities"]),
        "config_sha256": sha256_bytes(config_raw),
        "inputs": copy.deepcopy(config["input_sha256"]),
        "observation_sources": {
            "cleanup": "EXACT_LABEL_NAME_AND_DOCKER_INSPECT",
            "endpoints": "REAL_HTTP_PRIVATE_BRIDGE",
            "failures": "DOCKER_INSPECT_CAG_STATUS_AND_CPA_LOGS",
            "mock_counters": "COUNTED_MOCK_CONTROL_STATS",
            "rpc_counters": "CAG_MANAGEMENT_STATUS",
            "rss_bytes": "PROC_CONTAINER_INIT_VMRSS",
            "usage_records": "KEEPER_SQLITE_PERSISTED_CPA_POP_OLDEST",
        },
        "outputs": {
            "audit_sqlite": {"bytes": len(sqlite_raw), "path": "host-admission/audit-events.sqlite3", "sha256": sha256_bytes(sqlite_raw)},
            "host_300s": {"bytes": len(raw_300), "path": host.EXPECTED_SAMPLE_PATHS["host_300s"], "row_count": 301, "sha256": sha256_bytes(raw_300)},
            "host_3600s": {"bytes": len(raw_3600), "path": host.EXPECTED_SAMPLE_PATHS["host_3600s"], "row_count": 3601, "sha256": sha256_bytes(raw_3600)},
            "realtime_routes": {"bytes": len(realtime), "path": host.EXPECTED_REALTIME_ROUTES_PATH, "row_count": 14, "sha256": sha256_bytes(realtime)},
        },
        "producer": "tracked_integrated_host_admission_collector",
        "run_id": "unit-run",
        "schema": collector.MANIFEST_SCHEMA,
        "sqlite": {
            "blocked_credential_theft_events": 2,
            "database_sha256": sha256_bytes(sqlite_raw),
            "event_rows": 2,
            "evidence_bytes": len(sqlite_raw),
            "evidence_path": "host-admission/audit-events.sqlite3",
            "quick_check": "ok",
            "raw_capture_rows": 0,
            "schema_version": 7,
            "wal_checkpoint": {"busy": 0, "checkpointed_frames": 0, "log_frames": 0},
        },
    }
    return value, raw_300, raw_3600, realtime


@unittest.skipIf(Draft202012Validator is None, "jsonschema is not installed")
class HostAdmissionCollectorSchemaTests(unittest.TestCase):
    def test_schemas_are_closed_and_accept_complete_fixtures(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config, config_raw = config_fixture(root)
            manifest, _, _, _ = manifest_fixture(config, config_raw, root)
            schema_config = copy.deepcopy(config)
            schema_config["paths"] = {
                key: f"/srv/{key.replace('_', '-')}"
                for key in config["paths"]
            }
            for filename, value in (
                ("host-admission-config.schema.json", schema_config),
                ("host-admission-evidence-manifest.schema.json", manifest),
            ):
                schema = json.loads((TOOL_DIR / filename).read_text("utf-8"))
                Draft202012Validator.check_schema(schema)
                Draft202012Validator(schema).validate(value)
                changed = copy.deepcopy(value)
                changed["unexpected"] = True
                self.assertTrue(list(Draft202012Validator(schema).iter_errors(changed)))


class HostAdmissionCollectorContractTests(unittest.TestCase):
    @staticmethod
    def collector_instance(root: Path) -> collector.LinuxHostAdmissionCollector:
        config, _ = config_fixture(root)
        instance = collector.LinuxHostAdmissionCollector.__new__(
            collector.LinuxHostAdmissionCollector
        )
        instance.config = config
        instance.run_id = "unit-run"
        instance.names = collector._expected_names(instance.run_id)
        instance.runtime_root = root / "unit-run-host-runtime"
        instance.container_contract_sha256 = {}
        instance.secret_values = {
            name: chr(ord("a") + index) * 32
            for index, name in enumerate(collector.TOKEN_NAMES)
        }
        return instance

    @staticmethod
    def valid_cpa_inspect(
        instance: collector.LinuxHostAdmissionCollector,
    ) -> dict[str, object]:
        cpa = instance.config["identities"]["cpa"]
        return {
            "Config": {
                "Cmd": ["-config", "/cag/config/config.yaml", "-local-model"],
                "Entrypoint": ["/CLIProxyAPI"],
                "Env": [
                    "PATH=/usr/bin",
                    "CYBER_ABUSE_GUARD_HMAC_KEY_FILE=/cag/secrets/hmac.key",
                ],
                "Labels": {
                    collector.LABEL_KEY: instance.run_id,
                    collector.ROLE_LABEL: "host-admission-cpa",
                },
                "User": "1000:1000",
                "WorkingDir": "",
            },
            "HostConfig": {
                "AutoRemove": False,
                "CapAdd": [],
                "CapDrop": ["ALL"],
                "CgroupnsMode": "private",
                "CpusetCpus": "0",
                "DeviceRequests": [],
                "Devices": [],
                "Dns": [],
                "DnsOptions": [],
                "DnsSearch": [],
                "ExtraHosts": [],
                "GroupAdd": [],
                "IpcMode": "private",
                "Links": [],
                "Memory": 128 * 1024 * 1024,
                "NanoCpus": 500_000_000,
                "NetworkMode": instance.names["network"],
                "OomKillDisable": False,
                "PidMode": "private",
                "PidsLimit": 64,
                "PortBindings": {},
                "Privileged": False,
                "PublishAllPorts": False,
                "ReadonlyRootfs": True,
                "RestartPolicy": {"Name": "no"},
                "Runtime": "runc",
                "SecurityOpt": ["no-new-privileges:true"],
                "Sysctls": {},
                "UTSMode": "private",
                "VolumesFrom": [],
            },
            "Id": "1" * 64,
            "Image": cpa["image_id"],
            "Mounts": [],
            "Name": "/" + instance.names["cpa"],
            "NetworkSettings": {
                "Networks": {
                    instance.names["network"]: {"Aliases": ["cpa"]}
                },
                "Ports": {},
            },
            "RestartCount": 0,
            "State": {
                "Dead": False,
                "OOMKilled": False,
                "Restarting": False,
                "Running": True,
            },
        }

    @staticmethod
    def create_audit_v7_database(path: Path) -> None:
        connection = sqlite3.connect(path)
        try:
            connection.executescript(
                """
                CREATE TABLE audit_events (
                  id TEXT PRIMARY KEY, timestamp_ns INTEGER NOT NULL,
                  action TEXT NOT NULL, mode TEXT NOT NULL, category TEXT NOT NULL,
                  risk_score INTEGER NOT NULL, rule_ids TEXT NOT NULL,
                  request_hash TEXT NOT NULL, subject_hash TEXT NOT NULL,
                  model TEXT NOT NULL, source_format TEXT NOT NULL,
                  stream INTEGER NOT NULL, text_bytes_scanned INTEGER NOT NULL,
                  classifier TEXT NOT NULL, latency_us INTEGER NOT NULL,
                  decision TEXT NOT NULL, coverage TEXT NOT NULL,
                  incomplete_reason TEXT NOT NULL, scanner TEXT NOT NULL,
                  decision_explanation TEXT NOT NULL, disposition TEXT NOT NULL,
                  explanation_schema TEXT NOT NULL
                );
                CREATE INDEX idx_audit_events_timestamp ON audit_events(timestamp_ns DESC);
                CREATE INDEX idx_audit_events_action_timestamp ON audit_events(action, timestamp_ns DESC);
                CREATE INDEX idx_audit_events_category_timestamp ON audit_events(category, timestamp_ns DESC);
                CREATE INDEX idx_audit_events_subject_timestamp ON audit_events(subject_hash, timestamp_ns DESC);
                CREATE INDEX idx_audit_events_decision_timestamp ON audit_events(decision, timestamp_ns DESC);
                CREATE TABLE schema_version (
                  singleton INTEGER PRIMARY KEY, version INTEGER NOT NULL,
                  updated_at_ns INTEGER NOT NULL
                );
                CREATE TABLE migration_history (
                  version INTEGER PRIMARY KEY, applied_at_ns INTEGER NOT NULL,
                  description TEXT NOT NULL
                );
                CREATE TABLE subject_state_meta (
                  singleton INTEGER PRIMARY KEY, persistence_version INTEGER NOT NULL,
                  hmac_key_id TEXT NOT NULL, saved_at_ns INTEGER NOT NULL,
                  updated_at_ns INTEGER NOT NULL
                );
                CREATE TABLE subject_state (
                  subject_hash TEXT PRIMARY KEY, state_json TEXT NOT NULL,
                  updated_at_ns INTEGER NOT NULL
                );
                CREATE INDEX idx_subject_state_updated_at ON subject_state(updated_at_ns DESC);
                CREATE TABLE raw_request_captures (
                  id TEXT PRIMARY KEY, event_id TEXT NOT NULL,
                  timestamp_ns INTEGER NOT NULL, request_hash TEXT NOT NULL,
                  subject_hash TEXT NOT NULL, action TEXT NOT NULL,
                  decision TEXT NOT NULL, truncated INTEGER NOT NULL,
                  redacted INTEGER NOT NULL, raw_preview TEXT NOT NULL,
                  raw_sha256 TEXT NOT NULL, redaction_pattern_hits INTEGER NOT NULL,
                  redaction_version TEXT NOT NULL, decision_kind TEXT NOT NULL,
                  explanation_schema TEXT NOT NULL
                );
                CREATE UNIQUE INDEX idx_raw_request_captures_event ON raw_request_captures(event_id);
                CREATE INDEX idx_raw_request_captures_timestamp ON raw_request_captures(timestamp_ns DESC);
                CREATE INDEX idx_raw_request_captures_request_timestamp ON raw_request_captures(request_hash, timestamp_ns DESC);
                CREATE UNIQUE INDEX idx_raw_request_captures_raw_sha256_unique ON raw_request_captures(raw_sha256) WHERE raw_sha256 <> '';
                INSERT INTO schema_version(singleton, version, updated_at_ns) VALUES (1, 7, 1);
                """
            )
            connection.executemany(
                "INSERT INTO migration_history(version, applied_at_ns, description) VALUES (?, ?, ?)",
                [(version, version, f"migration {version}") for version in range(1, 8)],
            )
            row = (
                "", 1, "block", "balanced", "credential_theft", 90, "[]",
                "sha256:" + "1" * 64, "", collector.MODEL, "openai", 0,
                100, "rules", 1, "block_malicious_text", "complete", "",
                "streaming-scanner-v1", "{}", "block_malicious_text",
                "decision-explanation-v2",
            )
            connection.executemany(
                "INSERT INTO audit_events VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                [("block-1", *row[1:]), ("block-2", *row[1:])],
            )
            connection.commit()
        finally:
            connection.close()
        os.chmod(path, 0o600)

    @staticmethod
    def blocked_probe_response() -> tuple[int, bytes, dict[str, str], float]:
        return (
            403,
            canonical_bytes(
                {
                    "error": {
                        "category": "credential_theft",
                        "code": "cyber_abuse_guard_blocked",
                        "message": BLOCK_REFUSAL_MESSAGE,
                        "type": "policy_violation",
                    }
                }
            ),
            {
                "cache-control": "no-store",
                "content-type": "application/json",
                "x-content-type-options": "nosniff",
            },
            1.0,
        )

    def blocked_probe_instance(self, snapshots: list[tuple[dict[str, int], dict[str, int], int]]):
        instance = collector.LinuxHostAdmissionCollector.__new__(
            collector.LinuxHostAdmissionCollector
        )
        instance.urls = {"cpa": "http://172.30.250.2:8317"}
        instance.client_headers = {"Authorization": "Bearer " + "a" * 32}
        instance.audit_run = mock.Mock()
        instance.audit_run.http_request.return_value = self.blocked_probe_response()
        calls = iter(snapshots)
        instance._effect_snapshot = mock.Mock(side_effect=lambda: next(calls))
        return instance

    def test_blocked_probe_requires_full_quiet_window_and_rejects_delayed_effect(self) -> None:
        zero_rpc = {key: 0 for key in collector.REALTIME_RPC_COUNTER_KEYS}
        blocked_rpc = copy.deepcopy(zero_rpc)
        blocked_rpc["rpc_request_before_calls"] = 1
        zero_mock = {key: 0 for key in host.MOCK_COUNTER_KEYS}
        clock = [0.0]

        def monotonic() -> float:
            return clock[0]

        def sleep(seconds: float) -> None:
            clock[0] += seconds

        # One baseline plus enough identical real snapshots to cover the full
        # quiet window and its terminal observation must pass.
        passing = self.blocked_probe_instance(
            [(copy.deepcopy(zero_rpc), copy.deepcopy(zero_mock), 0)]
            + [(copy.deepcopy(blocked_rpc), copy.deepcopy(zero_mock), 0)] * 63
        )
        with (
            mock.patch.object(collector.time, "monotonic", side_effect=monotonic),
            mock.patch.object(collector.time, "sleep", side_effect=sleep),
        ):
            result = passing._one_probe(collector.BLOCK_PROBE_BODY, blocked=True)
        self.assertEqual(result["actual_action"], "block_malicious_text")
        self.assertGreater(passing._effect_snapshot.call_count, 3)
        self.assertGreaterEqual(clock[0], 1.0)

        # A delayed Mock/Auth side effect appearing after several zero
        # snapshots must fail rather than being hidden by the first zero.
        clock[0] = 0.0
        delayed_mock = copy.deepcopy(zero_mock)
        delayed_mock["auth"] = 1
        delayed = self.blocked_probe_instance(
            [(copy.deepcopy(zero_rpc), copy.deepcopy(zero_mock), 0)]
            + [(copy.deepcopy(blocked_rpc), copy.deepcopy(zero_mock), 0)] * 7
            + [(copy.deepcopy(blocked_rpc), delayed_mock, 0)]
        )
        with (
            mock.patch.object(collector.time, "monotonic", side_effect=monotonic),
            mock.patch.object(collector.time, "sleep", side_effect=sleep),
            self.assertRaises(collector.HostCollectorError),
        ):
            delayed._one_probe(collector.BLOCK_PROBE_BODY, blocked=True)

    def test_allowed_probe_rejects_an_invalid_upstream_response_contract(self) -> None:
        zero_rpc = {key: 0 for key in collector.REALTIME_RPC_COUNTER_KEYS}
        allowed_rpc = {
            "rpc_request_before_calls": 1,
            "rpc_request_after_calls": 1,
            "rpc_request_complete_calls": 1,
            "rpc_request_complete_errors": 0,
            "rpc_model_route_calls": 1,
            "rpc_executor_calls": 1,
        }
        zero_mock = {key: 0 for key in host.MOCK_COUNTER_KEYS}
        allowed_mock = {key: 1 for key in host.MOCK_COUNTER_KEYS}
        instance = collector.LinuxHostAdmissionCollector.__new__(
            collector.LinuxHostAdmissionCollector
        )
        instance.urls = {"cpa": "http://172.30.250.2:8317"}
        instance.client_headers = {"Authorization": "Bearer " + "a" * 32}
        instance.audit_run = mock.Mock()
        instance.audit_run.http_request.return_value = (
            200,
            b"{}",
            {"content-type": "application/json"},
            1.0,
        )
        instance._effect_snapshot = mock.Mock(
            side_effect=[(zero_rpc, zero_mock, 0), (allowed_rpc, allowed_mock, 1)]
        )
        with self.assertRaises(collector.HostCollectorError):
            instance._one_probe(collector.ALLOW_PROBE_BODIES[0], blocked=False)

    def test_code_owned_probe_contract_is_stable_and_distinct(self) -> None:
        self.assertEqual(collector.MODEL, "current-cpa-audit-model")
        hashes = [*collector.PROBE_CONTRACT["allow_request_sha256s"], collector.PROBE_CONTRACT["block_request_sha256"]]
        self.assertEqual(len(hashes), len(set(hashes)))
        self.assertEqual(len(hashes), 3)

    def test_tool_and_runtime_approvals_reject_half_or_extra_identity(self) -> None:
        tools = fake_tools()
        self.assertEqual(collector.validate_tool_identities(tools, "tools"), tools)
        approval = approved_runtime(tools)
        self.assertEqual(
            collector.validate_approved_runtime_identities(approval, "runtime"), approval
        )
        for mutate in (
            lambda value: value["keeper"].pop("base_image_ref"),
            lambda value: value["keeper"].__setitem__("extra", True),
            lambda value: value["keeper"].__setitem__("image_id", "sha256:" + "0" * 64),
        ):
            changed = copy.deepcopy(approval)
            mutate(changed)
            with self.assertRaises(collector.ContractError):
                collector.validate_approved_runtime_identities(changed, "runtime")

    def test_runtime_secrets_are_bounded_distinct_and_never_returned_in_config(self) -> None:
        values = {
            name: chr(ord("a") + index) * 32
            for index, name in enumerate(collector.TOKEN_NAMES)
        }
        self.assertEqual(collector.validate_runtime_secrets(values), values)
        for changed in (
            {**values, collector.TOKEN_NAMES[0]: "x" * 31},
            {**values, collector.TOKEN_NAMES[0]: values[collector.TOKEN_NAMES[1]]},
            {**values, collector.TOKEN_NAMES[0]: "x" * 31 + "\n"},
        ):
            with self.assertRaises(collector.HostCollectorError):
                collector.validate_runtime_secrets(changed)

    @unittest.skipUnless(os.name == "posix", "Host config producer paths are POSIX-only")
    @unittest.skipIf(Draft202012Validator is None, "jsonschema is not installed")
    def test_build_config_output_passes_imperative_validator_and_closed_schema(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            evidence_directory = root / "evidence"
            host_directory = evidence_directory / "host-admission"
            candidate_directory = root / "candidate"
            runtime_root = root / "unit-run-host-runtime"
            for path in (evidence_directory, host_directory, candidate_directory, runtime_root):
                path.mkdir(mode=0o700, parents=True, exist_ok=True)
                os.chmod(path, 0o700)
            for name in ("audit", "auth", "config", "keeper-secrets", "plugins", "secrets"):
                child = runtime_root / name
                child.mkdir(mode=0o700)
                os.chmod(child, 0o700)

            run, _ = performance_run_config()
            candidate, _ = performance_candidate_manifest()
            candidate = copy.deepcopy(candidate)
            so_raw = b"tracked Host build-config producer fixture"
            so_sha256 = sha256_bytes(so_raw)
            run["identities"]["cag"]["so_sha256"] = so_sha256

            store_path = (
                candidate_directory
                / f"cyber-abuse-guard_{collector.CAG_SOURCE_VERSION}_linux_amd64.zip"
            )
            with zipfile.ZipFile(store_path, "w", compression=zipfile.ZIP_STORED) as archive:
                archive.writestr(collector.CAG_SO_NAME, so_raw)
            store_raw = store_path.read_bytes()
            so_path = candidate_directory / collector.CAG_SO_NAME
            so_path.write_bytes(so_raw)
            for artifact in candidate["artifacts"]:
                if artifact["name"] == collector.CAG_SO_NAME:
                    artifact.update({"bytes": len(so_raw), "sha256": so_sha256})
                elif artifact["name"] == store_path.name:
                    artifact.update(
                        {"bytes": len(store_raw), "sha256": sha256_bytes(store_raw)}
                    )
            candidate_raw = canonical_bytes(candidate) + b"\n"
            old_candidate = run["identities"]["candidate"]
            run["identities"]["candidate"] = candidate_identity(
                candidate,
                candidate_raw,
                cag_identity=run["identities"]["cag"],
                artifact_id=old_candidate["artifact"]["id"],
                artifact_name=old_candidate["artifact"]["name"],
                artifact_digest=old_candidate["artifact"]["digest"],
            )
            candidate_path = candidate_directory / "audit-candidate-manifest.json"
            candidate_path.write_bytes(candidate_raw)
            run["paths"]["candidate_manifest"] = str(candidate_path)
            run["paths"]["cag_so"] = str(so_path)
            run["paths"]["evidence_directory"] = str(evidence_directory)
            run_raw = canonical_bytes(run) + b"\n"
            run_path = root / "run-config.json"
            run_path.write_bytes(run_raw)

            tools = collector.tool_identities()
            approval, approval_raw = collector.load_tracked_approved_runtime_identities()
            approved_tools_path = root / "approved-tools.json"
            approved_runtime_path = root / "approved-runtime.json"
            approved_tools_path.write_bytes(canonical_bytes(tools) + b"\n")
            approved_runtime_path.write_bytes(approval_raw)
            os.chmod(approved_tools_path, 0o600)
            os.chmod(approved_runtime_path, 0o600)

            paths: dict[str, Path] = {
                "approved_runtime_identities": approved_runtime_path,
                "approved_tool_identities": approved_tools_path,
                "audit_sqlite_database": runtime_root / "audit" / "events.db",
                "candidate_manifest": candidate_path,
                "candidate_store_zip": store_path,
                "corpus_manifest": evidence_directory / "corpus-manifest.json",
                "host_admission_directory": host_directory,
                "machine_evidence": evidence_directory / "machine-evidence.json",
                "run_config": run_path,
                "runtime_root": runtime_root,
                "supplemental_manifest": evidence_directory / "supplemental-zip-manifest.json",
                "supplemental_policy": evidence_directory / "supplemental-zip-policy.json",
                "supplemental_results": evidence_directory / "supplemental-zip-results.jsonl",
                "transport_results": evidence_directory / "transport-results.jsonl",
            }
            for key in (
                "corpus_manifest",
                "machine_evidence",
                "supplemental_manifest",
                "supplemental_policy",
                "supplemental_results",
                "transport_results",
            ):
                paths[key].write_bytes(b"{}\n")

            produced = collector.build_config(
                run,
                run_raw,
                candidate,
                candidate_raw,
                approved_tool_identities=tools,
                approved_runtime_identities=approval,
                approved_runtime_raw=approval_raw,
                paths=paths,
            )
            self.assertEqual(
                collector.validate_config(
                    produced,
                    run,
                    run_raw,
                    candidate,
                    candidate_raw,
                    observed_tool_identities=tools,
                    require_live_runtime=True,
                ),
                produced,
            )
            schema = json.loads(
                (TOOL_DIR / "host-admission-config.schema.json").read_text("utf-8")
            )
            Draft202012Validator.check_schema(schema)
            Draft202012Validator(schema).validate(produced)

    def test_environment_allowlist_accepts_documented_keeper_minimum_and_rejects_injection(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            instance = self.collector_instance(Path(directory))
            documented_keeper = {
                "CAG_KEEPER_RUN_ID": "unit-run",
                "CAG_KEEPER_CPA_ORIGIN": "http://cpa:8317",
                "CAG_KEEPER_EXPECTED_MODE": collector.REQUIRED_MODE,
                "CAG_KEEPER_EXPECTED_CAG_COMMIT": instance.config["identities"]["cag"]["commit"],
                "CAG_KEEPER_CONTROL_TOKEN_FILE": "/run/secrets/control-token",
                "CAG_KEEPER_CPA_MANAGEMENT_KEY_FILE": "/run/secrets/cpa-management-key",
            }
            instance._verify_environment("keeper", documented_keeper)

            cpa_environment = {
                "PATH": "/usr/bin",
                "CYBER_ABUSE_GUARD_HMAC_KEY_FILE": "/cag/secrets/hmac.key",
            }
            instance._verify_environment("cpa", cpa_environment)
            for key, value in (
                ("LD_PRELOAD", "/cag/config/injected.so"),
                ("UNREVIEWED_RUNTIME_FLAG", "1"),
            ):
                changed = {**cpa_environment, key: value}
                with self.subTest(key=key), self.assertRaises(
                    collector.HostCollectorError
                ):
                    instance._verify_environment("cpa", changed)

            mock_environment = {
                "CAG_MOCK_CONTROL_TOKEN": instance.secret_values[
                    "CAG_HOST_ADMISSION_MOCK_CONTROL_TOKEN"
                ],
                "CAG_MOCK_UPSTREAM_KEY": instance.secret_values[
                    "CAG_HOST_ADMISSION_UPSTREAM_KEY"
                ],
            }
            instance._verify_environment("mock", mock_environment)
            mock_environment["CAG_MOCK_UPSTREAM_KEY"] = "z" * 32
            with self.assertRaises(collector.HostCollectorError):
                instance._verify_environment("mock", mock_environment)

    def test_container_contract_rejects_namespace_device_network_security_and_command_overrides(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            instance = self.collector_instance(Path(directory))
            instance._verify_mounts = mock.Mock()
            instance.docker = mock.Mock()
            baseline = self.valid_cpa_inspect(instance)
            mutations = (
                ("host pid namespace", "HostConfig", "PidMode", "host"),
                ("host device", "HostConfig", "Devices", [{"PathOnHost": "/dev/null"}]),
                ("extra host", "HostConfig", "ExtraHosts", ["mock:127.0.0.1"]),
                (
                    "unconfined security",
                    "HostConfig",
                    "SecurityOpt",
                    ["no-new-privileges:true", "seccomp=unconfined"],
                ),
                ("entrypoint override", "Config", "Entrypoint", ["/bin/sh"]),
                ("command override", "Config", "Cmd", ["-c", "sleep 3600"]),
            )
            uid = 1000
            with (
                mock.patch.object(collector.os, "geteuid", return_value=uid, create=True),
                mock.patch.object(collector.os, "getegid", return_value=uid, create=True),
            ):
                instance.docker.inspect.return_value = baseline
                self.assertIs(instance._inspect_role("cpa"), baseline)
                for label, section, key, value in mutations:
                    changed = copy.deepcopy(baseline)
                    changed[section][key] = value
                    instance.docker.inspect.return_value = changed
                    with self.subTest(label=label), self.assertRaises(
                        collector.HostCollectorError
                    ):
                        instance._inspect_role("cpa")

    def test_bind_mount_rejects_named_source_inode_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            instance = self.collector_instance(root)
            for name in ("audit", "auth", "config", "plugins", "secrets"):
                (instance.runtime_root / name).mkdir(parents=True, mode=0o700)
            info = self.valid_cpa_inspect(instance)
            info["State"]["Pid"] = os.getpid()
            info["HostConfig"]["Tmpfs"] = {
                "/tmp": "rw,noexec,nosuid,nodev,size=64m"
            }
            writable = {"plugins": False, "config": True, "auth": True, "audit": True, "secrets": False}
            info["Mounts"] = [
                {
                    "Destination": "/tmp",
                    "RW": True,
                    "Type": "tmpfs",
                },
                *[
                    {
                        "Destination": f"/cag/{name}",
                        "Propagation": "rprivate",
                        "RW": is_writable,
                        "Source": str(instance.runtime_root / name),
                        "Type": "bind",
                    }
                    for name, is_writable in writable.items()
                ],
            ]
            concrete_path = type(instance.runtime_root)
            real_stat = concrete_path.stat

            def replaced_mount_stat(path: Path, *args: object, **kwargs: object):
                normalized = str(path).replace("\\", "/")
                if normalized.startswith(f"/proc/{os.getpid()}/root/cag/"):
                    source_info = real_stat(instance.runtime_root / "plugins")
                    return SimpleNamespace(
                        st_dev=source_info.st_dev + 1,
                        st_ino=source_info.st_ino,
                        st_mode=source_info.st_mode,
                    )
                return real_stat(path, *args, **kwargs)

            with mock.patch.object(concrete_path, "stat", new=replaced_mount_stat):
                with self.assertRaisesRegex(
                    collector.HostCollectorError, "not the current Host source inode"
                ):
                    instance._verify_mounts("cpa", info)

    @unittest.skipUnless(os.name == "posix", "auth directory descriptor checks require POSIX")
    def test_oauth_auth_directory_must_remain_empty(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            instance = self.collector_instance(root)
            instance.runtime_root.mkdir(mode=0o700)
            auth = instance.runtime_root / "auth"
            auth.mkdir(mode=0o700)
            flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
            instance.runtime_root_fd = os.open(instance.runtime_root, flags)
            try:
                instance._verify_auth_directory_empty()
                (auth / "oauth.json").write_text("{}", encoding="utf-8")
                with self.assertRaises(collector.HostCollectorError):
                    instance._verify_auth_directory_empty()
            finally:
                os.close(instance.runtime_root_fd)

    def test_audit_database_must_be_fresh_before_code_owned_probes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            instance = self.collector_instance(root)
            database = Path(instance.config["paths"]["audit_sqlite_database"])
            database.parent.mkdir(parents=True)
            self.create_audit_v7_database(database)
            info = database.stat()
            instance.audit_database_identity = (info.st_dev, info.st_ino, info.st_nlink)
            with self.assertRaises(collector.HostCollectorError):
                instance._verify_fresh_audit_database()

            connection = sqlite3.connect(database)
            try:
                connection.execute("DELETE FROM audit_events")
                connection.commit()
            finally:
                connection.close()
            instance._verify_fresh_audit_database()

            connection = sqlite3.connect(database)
            try:
                connection.execute(
                    "INSERT INTO raw_request_captures VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        "capture", "event", 1, "", "", "block",
                        "block_malicious_text", 0, 1, "private text", "sha256:" + "2" * 64,
                        0, "v1", "block_malicious_text", "decision-explanation-v2",
                    ),
                )
                connection.commit()
            finally:
                connection.close()
            with self.assertRaises(collector.HostCollectorError):
                instance._verify_fresh_audit_database()

    def test_canonical_input_rejects_empty_noncanonical_and_extra_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "input.json"
            for raw in (b"", b'{"b":1,"a":2}\n', b'{"a":1}\nextra'):
                path.write_bytes(raw)
                with self.assertRaises(collector.ContractError):
                    collector._canonical_file(path, "unit input")

    @unittest.skipUnless(os.name == "posix", "descriptor-bound runtime cleanup is Linux/POSIX")
    def test_runtime_root_cleanup_is_descriptor_bound_and_rejects_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            root = parent / "unit-run-host-runtime"
            for name in ("audit", "auth", "config", "keeper-secrets", "plugins", "secrets"):
                (root / name).mkdir(parents=True, mode=0o700)
            (root / "config" / "config.yaml").write_bytes(b"fixture")
            os.chmod(root / "config" / "config.yaml", 0o600)
            instance = collector.LinuxHostAdmissionCollector.__new__(collector.LinuxHostAdmissionCollector)
            instance.runtime_root = root
            instance.run_id = "unit-run"
            instance.config = {"paths": {"host_admission_directory": str(parent / "evidence" / "host-admission")}}
            instance.runtime_root_identity = None
            instance.runtime_root_fd = None
            instance.runtime_parent_identity = None
            instance.runtime_parent_fd = None
            instance._bind_runtime_root()
            instance._remove_runtime_root()
            self.assertFalse(root.exists())

            for name in ("audit", "auth", "config", "keeper-secrets", "plugins", "secrets"):
                (root / name).mkdir(parents=True, mode=0o700)
            (root / "auth" / "escape").symlink_to(parent)
            instance.runtime_root = root
            instance.runtime_root_identity = None
            instance.runtime_root_fd = None
            instance.runtime_parent_identity = None
            instance.runtime_parent_fd = None
            instance._bind_runtime_root()
            with self.assertRaises(collector.HostCollectorError):
                instance._remove_runtime_root()
            os.close(instance.runtime_root_fd)
            os.close(instance.runtime_parent_fd)

    def test_manifest_binds_raw_sqlite_cleanup_and_current_tools(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config, config_raw = config_fixture(root)
            manifest, raw_300, raw_3600, realtime = manifest_fixture(config, config_raw, root)
            self.assertEqual(
                collector.validate_evidence_manifest(
                    manifest,
                    config,
                    config_raw,
                    raw_300,
                    raw_3600,
                    realtime,
                    observed_tool_identities=config["approved_tool_identities"],
                ),
                manifest,
            )
            mutations = (
                lambda value: value["outputs"]["host_300s"].__setitem__("sha256", "f" * 64),
                lambda value: value["cleanup"].__setitem__("runtime_root_absent", False),
                lambda value: value["cleanup"]["resources"][0].__setitem__("name", "other-cpa"),
                lambda value: value["cleanup"]["resources"][0].__setitem__("id", "0" * 64),
                lambda value: value["sqlite"].__setitem__("database_sha256", "e" * 64),
                lambda value: value["observation_sources"].__setitem__("usage_records", "HAND_AUTHORED"),
            )
            for mutate in mutations:
                changed = copy.deepcopy(manifest)
                mutate(changed)
                with self.assertRaises(collector.HostCollectorError):
                    collector.validate_evidence_manifest(
                        changed,
                        config,
                        config_raw,
                        raw_300,
                        raw_3600,
                        realtime,
                        observed_tool_identities=config["approved_tool_identities"],
                    )

    @unittest.skipUnless(os.name == "posix", "preserved SQLite uses Linux /proc fd binding")
    def test_preserved_sqlite_is_reopened_and_integrity_checked(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config, config_raw = config_fixture(root)
            manifest, _, _, _ = manifest_fixture(config, config_raw, root)
            database = (
                Path(config["paths"]["host_admission_directory"])
                / "audit-events.sqlite3"
            )
            database.unlink()
            self.create_audit_v7_database(database)

            def reseal() -> None:
                raw = database.read_bytes()
                digest = sha256_bytes(raw)
                manifest["sqlite"].update(  # type: ignore[index,union-attr]
                    {"database_sha256": digest, "evidence_bytes": len(raw)}
                )
                manifest["outputs"]["audit_sqlite"].update(  # type: ignore[index,union-attr]
                    {"bytes": len(raw), "sha256": digest}
                )

            reseal()
            receipt = collector.validate_preserved_sqlite(database, manifest)
            self.assertEqual(receipt["quick_check"], "ok")
            self.assertEqual(receipt["schema_version"], 7)

            connection = sqlite3.connect(database)
            try:
                connection.execute("UPDATE schema_version SET version = 6")
                connection.commit()
            finally:
                connection.close()
            reseal()
            with self.assertRaises(collector.HostCollectorError):
                collector.validate_preserved_sqlite(database, manifest)

            self.create_audit_v7_database(database.with_name("extra.sqlite3"))
            extra = database.with_name("extra.sqlite3")
            connection = sqlite3.connect(extra)
            try:
                connection.execute("CREATE TABLE secret_payload(value TEXT)")
                connection.commit()
            finally:
                connection.close()
            with self.assertRaises(collector.HostCollectorError):
                connection = sqlite3.connect(extra)
                try:
                    collector._validate_audit_sqlite_contract(connection)
                finally:
                    connection.close()

            connection = sqlite3.connect(database)
            try:
                connection.execute("UPDATE schema_version SET version = 7")
                connection.commit()
            finally:
                connection.close()
            reseal()
            Path(str(database) + "-wal").write_bytes(b"unexpected")
            with self.assertRaises(collector.HostCollectorError):
                collector.validate_preserved_sqlite(database, manifest)

            Path(str(database) + "-wal").unlink()
            connection = sqlite3.connect(database)
            try:
                connection.execute("DROP INDEX idx_audit_events_decision_timestamp")
                connection.commit()
            finally:
                connection.close()
            reseal()
            with self.assertRaises(collector.HostCollectorError):
                collector.validate_preserved_sqlite(database, manifest)

    def test_expected_candidate_is_rebuilt_from_config_and_manifest_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config, config_raw = config_fixture(Path(directory))
            manifest_raw = canonical_bytes({"tracked": True}) + b"\n"
            candidate = collector.expected_candidate_from_bindings(config, config_raw, manifest_raw)
            self.assertEqual(candidate["artifacts"]["config_sha256"], sha256_bytes(config_raw))
            self.assertEqual(candidate["artifacts"]["evidence_manifest_sha256"], sha256_bytes(manifest_raw))
            self.assertEqual(candidate["cpa"]["tag"], "v7.2.145")

    def test_source_has_no_synthetic_or_warm_lane_fallback(self) -> None:
        source = (TOOL_DIR / "host_admission_collector.py").read_text("utf-8")
        self.assertNotIn("warm_rss_60m", source)
        self.assertNotIn("test_host_admission", source)
        self.assertNotIn("ROWS_300", source)
        self.assertIn("time.monotonic_ns()", source)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
