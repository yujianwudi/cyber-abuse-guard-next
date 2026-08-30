from __future__ import annotations

import hashlib
import hmac
import http.client
import json
import os
import sqlite3
import sys
import tempfile
import threading
import unittest
from contextlib import contextmanager
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Iterator
from unittest import mock


HERE = Path(__file__).resolve().parent
TOOL_DIR = HERE.parent
FIXTURE_DIR = TOOL_DIR / "host_keeper_fixture"
sys.path.insert(0, str(FIXTURE_DIR))

import keeper_fixture as keeper  # noqa: E402


RUN_ID = "round17-host-keeper-001"
CAG_COMMIT = "1" * 40
CONTROL_TOKEN = "control-" + "c" * 48
MANAGEMENT_KEY = "management-" + "m" * 48
REQUEST_SECRET = "request-body-must-never-be-retained"
USAGE_SECRET = "usage-api-key-must-never-be-retained"


def make_config(database: Path, origin: str) -> keeper.KeeperConfig:
    return keeper.KeeperConfig(
        run_id=RUN_ID,
        database_path=database,
        cpa_origin=origin,
        expected_mode="balanced",
        expected_cag_commit=CAG_COMMIT,
        expected_provider=keeper.EXPECTED_PROVIDER,
        expected_model=keeper.EXPECTED_MODEL,
        expected_executor=keeper.EXPECTED_EXECUTOR,
        control_token=CONTROL_TOKEN,
        management_key=MANAGEMENT_KEY,
        poll_interval=0.1,
    )


def usage_record(request_id: str = "keeper-request-001") -> dict[str, Any]:
    return {
        "accounting_version": 2,
        "alias": keeper.EXPECTED_MODEL,
        "api_key": USAGE_SECRET,
        "auth_index": "0",
        "auth_type": "apikey",
        "client_ip": "192.0.2.10",
        "endpoint": "POST /v1/chat/completions",
        "executor_type": keeper.EXPECTED_EXECUTOR,
        "fail": {"body": "", "status_code": 200},
        "failed": False,
        "generate": True,
        "latency_ms": 10,
        "model": keeper.EXPECTED_MODEL,
        "provider": keeper.EXPECTED_PROVIDER,
        "reasoning_effort": "",
        "request_id": request_id,
        "service_tier": "auto",
        "source": "isolated-test-source@example.invalid",
        "timestamp": "2026-08-30T01:02:03.456Z",
        "token_breakdown": {
            "input": {
                "cache_read_tokens": 0,
                "cache_write_tokens": 0,
                "total_tokens": 5,
                "uncached_tokens": 5,
            },
            "output": {
                "non_reasoning_tokens": 3,
                "reasoning_tokens": 0,
                "total_tokens": 3,
            },
            "quality": "complete",
            "schema_version": 2,
            "total_tokens": 8,
            "unclassified_tokens": 0,
        },
        "tokens": {
            "cache_creation_tokens": 0,
            "cache_read_tokens": 0,
            "cache_read_tokens_present": True,
            "cached_tokens": 0,
            "input_tokens": 5,
            "output_tokens": 3,
            "reasoning_tokens": 0,
            "total_tokens": 8,
        },
        "ttft_ms": 1,
        "user_agent": "isolated-host-admission/1",
        "x_forwarded_for": "",
    }


def cag_status() -> dict[str, Any]:
    return {
        "id": "cyber-abuse-guard",
        "commit": CAG_COMMIT,
        "dirty": False,
        "enabled": True,
        "mode": "balanced",
        "enforcement_ready": True,
        "operational_ready": True,
        "audit_degraded": False,
        "persistence_degraded": False,
        "audit": {
            "healthy": True,
            "degraded": False,
            "schema_version": keeper.CAG_AUDIT_SCHEMA_VERSION,
            "persistence_verified": True,
            "dropped": 0,
            "failed": 0,
            "rejected": 0,
        },
        "raw_capture": {"enabled": False},
    }


class CPAState:
    def __init__(self) -> None:
        self.root_status = HTTPStatus.OK
        self.models_status = HTTPStatus.UNAUTHORIZED
        self.status_value = cag_status()
        self.config_value = {
            "commercial-mode": True,
            "request-log": False,
            "logging-to-file": False,
            "usage-statistics-enabled": True,
            "proxy-url": "",
            "openai-compatibility": [
                {
                    "name": "current-cpa-counted-mock",
                    "base-url": "http://mock:18080/v1",
                    "api-key-entries": [{"api-key": "redacted"}],
                    "models": [
                        {
                            "name": keeper.EXPECTED_MODEL,
                            "alias": keeper.EXPECTED_MODEL,
                        }
                    ],
                }
            ],
            "claude-api-key": [],
            "codex-api-key": [],
            "gemini-api-key": [],
            "interactions-api-key": [],
            "vertex-api-key": [],
            "xai-api-key": [],
        }
        self.usage_batches: list[list[dict[str, Any]]] = []
        self.management_authorizations: list[str] = []


class CPAHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    @property
    def state(self) -> CPAState:
        return self.server.state  # type: ignore[attr-defined,no-any-return]

    def log_message(self, format: str, *args: Any) -> None:
        del format, args

    def _json(
        self,
        status: int,
        value: Any,
        *,
        cpa_headers: bool = False,
    ) -> None:
        raw = keeper.compact_json(value)
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Connection", "close")
        if cpa_headers:
            self.send_header("X-CPA-Version", keeper.CPA_TAG)
            self.send_header("X-CPA-Commit", keeper.CPA_COMMIT)
        self.end_headers()
        self.wfile.write(raw)
        self.close_connection = True

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/":
            self._json(self.state.root_status, {"ok": self.state.root_status == 200})
            return
        if self.path == "/v1/models":
            if self.headers.get("Authorization"):
                self._json(500, {"error": "authorization_must_be_absent"})
                return
            self._json(self.state.models_status, {"error": "unauthorized"})
            return
        if self.path in {
            "/v0/management/config",
            "/v0/management/plugins/cyber-abuse-guard/status",
            "/v0/management/usage-queue?count=100",
        }:
            authorization = self.headers.get("Authorization", "")
            self.state.management_authorizations.append(authorization)
            if authorization != "Bearer " + MANAGEMENT_KEY:
                self._json(HTTPStatus.UNAUTHORIZED, {"error": "unauthorized"})
                return
            if self.path.endswith("/status"):
                self._json(HTTPStatus.OK, self.state.status_value, cpa_headers=True)
                return
            if self.path == "/v0/management/config":
                self._json(HTTPStatus.OK, self.state.config_value)
                return
            batch = self.state.usage_batches.pop(0) if self.state.usage_batches else []
            self._json(HTTPStatus.OK, batch)
            return
        self._json(HTTPStatus.NOT_FOUND, {"error": "not_found"})


@contextmanager
def cpa_server(state: CPAState | None = None) -> Iterator[tuple[CPAState, str]]:
    active = CPAState() if state is None else state
    server = ThreadingHTTPServer(("127.0.0.1", 0), CPAHandler)
    server.state = active  # type: ignore[attr-defined]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield active, f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@contextmanager
def keeper_server(runtime: keeper.KeeperRuntime) -> Iterator[str]:
    server = keeper.KeeperHTTPServer(("127.0.0.1", 0), runtime, CONTROL_TOKEN)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def request(
    origin: str,
    method: str,
    path: str,
    *,
    token: str | None = None,
    value: Any | None = None,
) -> tuple[int, dict[str, Any]]:
    host, raw_port = origin.rsplit(":", 1)
    body = keeper.compact_json(value) if value is not None else None
    headers: dict[str, str] = {}
    if token is not None:
        headers["Authorization"] = "Bearer " + token
    if body is not None:
        headers["Content-Type"] = "application/json"
    connection = http.client.HTTPConnection(host, int(raw_port), timeout=5)
    try:
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        raw = response.read()
        return response.status, json.loads(raw)
    finally:
        connection.close()


class FakeClient:
    def __init__(self, *, healthy: bool = True, batches: list[list[bytes]] | None = None) -> None:
        self.healthy = healthy
        self.batches = [] if batches is None else list(batches)

    def health_checks(self) -> dict[str, bool]:
        return {
            "cag_status": self.healthy,
            "cpa_root": self.healthy,
            "cpa_unauthorized_models": self.healthy,
        }

    def pop_usage_event_keys(self, event_hmac_key: bytes) -> list[bytes]:
        del event_hmac_key
        if not self.healthy:
            raise keeper.ProbeError("simulated")
        return self.batches.pop(0) if self.batches else []


def mark_poller_alive(runtime: keeper.KeeperRuntime) -> None:
    thread = mock.Mock()
    thread.is_alive.return_value = True
    runtime._thread = thread


class HostKeeperFixtureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.database_path = self.root / "keeper.sqlite3"

    def database(self) -> keeper.KeeperDatabase:
        return keeper.KeeperDatabase(self.database_path, RUN_ID)

    def test_config_requires_private_origin_and_distinct_bounded_secrets(self) -> None:
        environment = {
            "CAG_KEEPER_RUN_ID": RUN_ID,
            "CAG_KEEPER_EXPECTED_MODE": "balanced",
            "CAG_KEEPER_EXPECTED_CAG_COMMIT": CAG_COMMIT,
            "CAG_KEEPER_CPA_ORIGIN": "https://example.invalid:8317/path",
            "CAG_KEEPER_CONTROL_TOKEN": CONTROL_TOKEN,
            "CAG_KEEPER_CPA_MANAGEMENT_KEY": MANAGEMENT_KEY,
        }
        with self.assertRaises(keeper.ConfigurationError):
            keeper.KeeperConfig.from_environment(self.database_path, environment)
        environment["CAG_KEEPER_CPA_ORIGIN"] = "http://cpa:8317"
        environment["CAG_KEEPER_CPA_MANAGEMENT_KEY"] = CONTROL_TOKEN
        with self.assertRaises(keeper.ConfigurationError):
            keeper.KeeperConfig.from_environment(self.database_path, environment)
        environment["CAG_KEEPER_CPA_MANAGEMENT_KEY"] = "bad token " + "x" * 32
        with self.assertRaises(keeper.ConfigurationError):
            keeper.KeeperConfig.from_environment(self.database_path, environment)

    @unittest.skipUnless(os.name == "posix", "POSIX secret ownership/mode contract")
    def test_secret_file_rejects_world_readable_and_wrong_owner(self) -> None:
        secret = self.root / "control-token"
        secret.write_text(CONTROL_TOKEN, encoding="utf-8")
        secret.chmod(0o644)
        with self.assertRaises(keeper.ConfigurationError):
            keeper.read_secret(
                {"CAG_KEEPER_CONTROL_TOKEN_FILE": str(secret)},
                "CAG_KEEPER_CONTROL_TOKEN",
            )
        secret.chmod(0o600)
        info = secret.stat()
        with mock.patch.object(keeper.os, "getuid", return_value=info.st_uid + 1):
            with self.assertRaises(keeper.ConfigurationError):
                keeper.read_secret(
                    {"CAG_KEEPER_CONTROL_TOKEN_FILE": str(secret)},
                    "CAG_KEEPER_CONTROL_TOKEN",
                )

    def test_secret_file_requires_absolute_path_without_symlink_parent(self) -> None:
        with self.assertRaises(keeper.ConfigurationError):
            keeper.read_secret(
                {"CAG_KEEPER_CONTROL_TOKEN_FILE": "relative-secret"},
                "CAG_KEEPER_CONTROL_TOKEN",
            )
        real_parent = self.root / "real-secrets"
        real_parent.mkdir()
        secret = real_parent / "control-token"
        secret.write_text(CONTROL_TOKEN, encoding="utf-8")
        secret.chmod(0o600)
        link_parent = self.root / "linked-secrets"
        try:
            link_parent.symlink_to(real_parent, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("directory symlink creation is unavailable")
        with self.assertRaises(keeper.ConfigurationError):
            keeper.read_secret(
                {"CAG_KEEPER_CONTROL_TOKEN_FILE": str(link_parent / secret.name)},
                "CAG_KEEPER_CONTROL_TOKEN",
            )

    def test_health_is_503_for_unhealthy_cpa_and_200_only_after_real_poll(self) -> None:
        config = make_config(self.database_path, "http://cpa:8317")
        database = self.database()
        unhealthy_runtime = keeper.KeeperRuntime(config, database, FakeClient(healthy=False))
        status, payload = unhealthy_runtime.health()
        self.assertEqual(status, HTTPStatus.SERVICE_UNAVAILABLE)
        self.assertEqual(payload["state"], "unhealthy")
        self.assertFalse(payload["checks"]["cpa_root"])
        self.assertFalse(payload["checks"]["poller"])

        healthy_runtime = keeper.KeeperRuntime(config, database, FakeClient())
        self.assertTrue(healthy_runtime.poll_once())
        stopped_status, stopped_payload = healthy_runtime.health()
        self.assertEqual(stopped_status, HTTPStatus.SERVICE_UNAVAILABLE)
        self.assertFalse(stopped_payload["checks"]["poller"])
        mark_poller_alive(healthy_runtime)
        status, payload = healthy_runtime.health()
        self.assertEqual(status, HTTPStatus.OK)
        self.assertEqual(
            payload,
            {
                "schema": keeper.CONTRACT,
                "state": "healthy",
                "checks": {
                    "cag_status": True,
                    "cpa_root": True,
                    "cpa_unauthorized_models": True,
                    "poller": True,
                    "sqlite_quick_check": "ok",
                    "sqlite_writable": True,
                    "usage_records": 0,
                },
            },
        )

    def test_health_is_503_when_sqlite_is_not_writable_or_checkable(self) -> None:
        config = make_config(self.database_path, "http://cpa:8317")
        database = self.database()
        runtime = keeper.KeeperRuntime(config, database, FakeClient())
        self.assertTrue(runtime.poll_once())
        mark_poller_alive(runtime)
        with mock.patch.object(
            database,
            "health_snapshot",
            side_effect=keeper.DatabaseInvariantError("simulated"),
        ):
            status, payload = runtime.health()
        self.assertEqual(status, HTTPStatus.SERVICE_UNAVAILABLE)
        self.assertEqual(payload["state"], "unhealthy")
        self.assertEqual(payload["checks"]["sqlite_quick_check"], "failed")
        self.assertFalse(payload["checks"]["sqlite_writable"])

    def test_health_is_503_when_started_poller_thread_has_died(self) -> None:
        config = make_config(self.database_path, "http://cpa:8317")
        runtime = keeper.KeeperRuntime(config, self.database(), FakeClient())
        self.assertTrue(runtime.poll_once())
        dead_thread = mock.Mock()
        dead_thread.is_alive.return_value = False
        runtime._thread = dead_thread
        status, payload = runtime.health()
        self.assertEqual(status, HTTPStatus.SERVICE_UNAVAILABLE)
        self.assertFalse(payload["checks"]["poller"])

    def test_unexpected_poller_fault_is_contained_and_fails_health(self) -> None:
        class ExplodingClient(FakeClient):
            def pop_usage_event_keys(self, event_hmac_key: bytes) -> list[bytes]:
                del event_hmac_key
                raise RuntimeError("unexpected parser fault")

        config = make_config(self.database_path, "http://cpa:8317")
        runtime = keeper.KeeperRuntime(config, self.database(), ExplodingClient())
        with mock.patch.object(threading, "excepthook") as excepthook:
            runtime.start()
            self.assertIsNotNone(runtime._thread)
            runtime._thread.join(timeout=5)
            self.assertFalse(runtime._thread.is_alive())
            excepthook.assert_not_called()
        status, payload = runtime.health()
        self.assertEqual(status, HTTPStatus.SERVICE_UNAVAILABLE)
        self.assertFalse(payload["checks"]["poller"])
        runtime.stop()

    def test_cpa_health_probes_root_models_and_exact_cag_state(self) -> None:
        with cpa_server() as (state, origin):
            config = make_config(self.database_path, origin)
            client = keeper.CPAClient(config, allow_loopback_for_tests=True)
            self.assertEqual(
                client.health_checks(),
                {
                    "cag_status": True,
                    "cpa_root": True,
                    "cpa_unauthorized_models": True,
                },
            )
            state.root_status = HTTPStatus.INTERNAL_SERVER_ERROR
            state.status_value["operational_ready"] = False
            state.models_status = HTTPStatus.OK
            state.config_value["openai-compatibility"][0]["base-url"] = (
                "https://real-provider.example/v1"
            )
            self.assertEqual(
                client.health_checks(),
                {
                    "cag_status": False,
                    "cpa_root": False,
                    "cpa_unauthorized_models": False,
                },
            )
            self.assertTrue(state.management_authorizations)
            self.assertTrue(
                all(value == "Bearer " + MANAGEMENT_KEY for value in state.management_authorizations)
            )

    def test_stats_and_reset_require_control_token_and_reset_never_rolls_back(self) -> None:
        config = make_config(self.database_path, "http://cpa:8317")
        database = self.database()
        event_key = hashlib.sha256(b"allowed-request").digest()
        runtime = keeper.KeeperRuntime(config, database, FakeClient(batches=[[event_key]]))
        self.assertTrue(runtime.poll_once())
        with keeper_server(runtime) as origin:
            status, value = request(origin, "GET", "/keeper/stats", token="wrong-" + "x" * 40)
            self.assertEqual(status, HTTPStatus.UNAUTHORIZED)
            self.assertEqual(value["error"], "unauthorized")
            status, value = request(origin, "GET", "/keeper/stats", token=CONTROL_TOKEN)
            self.assertEqual(status, HTTPStatus.OK)
            self.assertEqual(value["usage_records"], 1)
            self.assertEqual(value["last_sequence"], 1)
            self.assertFalse(value["request_body_retention"])
            self.assertFalse(value["usage_payload_retention"])
            reset = {
                "schema": keeper.CONTRACT,
                "run_id": RUN_ID,
                "expected_usage_records": 0,
            }
            status, value = request(
                origin,
                "POST",
                "/keeper/reset",
                token="wrong-" + "x" * 40,
                value=reset,
            )
            self.assertEqual(status, HTTPStatus.UNAUTHORIZED)
            status, value = request(
                origin,
                "POST",
                "/keeper/reset",
                token=CONTROL_TOKEN,
                value=reset,
            )
            self.assertEqual(status, HTTPStatus.CONFLICT)
            self.assertEqual(value["error"], "rollback_forbidden")
            status, value = request(origin, "GET", "/keeper/stats", token=CONTROL_TOKEN)
            self.assertEqual((status, value["usage_records"]), (HTTPStatus.OK, 1))

    def test_fresh_reset_is_strict_noop_and_record_endpoint_does_not_exist(self) -> None:
        config = make_config(self.database_path, "http://cpa:8317")
        runtime = keeper.KeeperRuntime(config, self.database(), FakeClient())
        self.assertTrue(runtime.poll_once())
        reset = {
            "schema": keeper.CONTRACT,
            "run_id": RUN_ID,
            "expected_usage_records": 0,
        }
        with keeper_server(runtime) as origin:
            status, value = request(
                origin,
                "POST",
                "/keeper/reset",
                token=CONTROL_TOKEN,
                value=reset,
            )
            self.assertEqual(
                (status, value),
                (
                    HTTPStatus.OK,
                    {
                        "schema": keeper.CONTRACT,
                        "run_id": RUN_ID,
                        "state": "fresh",
                        "usage_records": 0,
                    },
                ),
            )
            status, value = request(
                origin,
                "POST",
                "/keeper/reset",
                token=CONTROL_TOKEN,
                value={**reset, "unexpected": True},
            )
            self.assertEqual(status, HTTPStatus.BAD_REQUEST)
            self.assertEqual(value["error"], "invalid_schema")
            status, value = request(
                origin,
                "POST",
                "/keeper/record",
                token=CONTROL_TOKEN,
                value={"usage_records": 1},
            )
            self.assertEqual(status, HTTPStatus.NOT_FOUND)
            self.assertEqual(value["error"], "not_found")

    def test_duplicate_usage_is_fail_closed_and_does_not_increment(self) -> None:
        config = make_config(self.database_path, "http://cpa:8317")
        database = self.database()
        event_key = hashlib.sha256(b"same-request").digest()
        runtime = keeper.KeeperRuntime(
            config,
            database,
            FakeClient(batches=[[event_key], [event_key]]),
        )
        self.assertTrue(runtime.poll_once())
        self.assertFalse(runtime.poll_once())
        state = database.snapshot()
        self.assertEqual(state["usage_records"], 1)
        self.assertEqual(state["last_sequence"], 1)
        self.assertEqual(state["poll_errors"], 1)
        self.assertEqual(state["invalid_records"], 1)
        self.assertEqual(state["duplicate_records"], 1)
        status, payload = runtime.health()
        self.assertEqual(status, HTTPStatus.SERVICE_UNAVAILABLE)
        self.assertFalse(payload["checks"]["poller"])

    def test_duplicate_usage_inside_one_batch_is_not_partially_counted(self) -> None:
        config = make_config(self.database_path, "http://cpa:8317")
        database = self.database()
        event_key = hashlib.sha256(b"same-batch-request").digest()
        runtime = keeper.KeeperRuntime(
            config,
            database,
            FakeClient(batches=[[event_key, event_key]]),
        )
        self.assertFalse(runtime.poll_once())
        state = database.snapshot()
        self.assertEqual(state["usage_records"], 0)
        self.assertEqual(state["last_sequence"], 0)
        self.assertEqual(state["poll_errors"], 1)
        self.assertEqual(state["invalid_records"], 1)
        self.assertEqual(state["duplicate_records"], 1)

    def test_sqlite_triggers_reject_counter_rollback_and_event_deletion(self) -> None:
        database = self.database()
        event_key = hashlib.sha256(b"monotonic-request").digest()
        state = database.record_poll([event_key])
        self.assertEqual(state["usage_records"], 1)
        connection = sqlite3.connect(str(self.database_path))
        try:
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute(
                    "UPDATE keeper_state SET usage_records = 0, last_sequence = 0 WHERE singleton = 1"
                )
            connection.rollback()
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute("DELETE FROM observed_events")
            connection.rollback()
        finally:
            connection.close()
        self.assertEqual(database.snapshot()["usage_records"], 1)

    def test_sqlite_schema_sql_tamper_is_detected(self) -> None:
        database = self.database()
        connection = sqlite3.connect(str(self.database_path))
        try:
            connection.execute("DROP TRIGGER keeper_state_no_delete")
            connection.execute(
                """
                CREATE TRIGGER keeper_state_no_delete
                BEFORE DELETE ON keeper_state
                BEGIN
                    SELECT 1;
                END
                """
            )
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(keeper.DatabaseInvariantError):
            database.snapshot()

    def test_usage_count_is_persistent_across_keeper_database_reopen(self) -> None:
        database = self.database()
        database.record_poll([hashlib.sha256(b"persistent-request").digest()])
        reopened = keeper.KeeperDatabase(self.database_path, RUN_ID)
        state = reopened.snapshot()
        self.assertEqual(state["usage_records"], 1)
        self.assertEqual(state["last_sequence"], 1)
        with self.assertRaises(keeper.RollbackForbidden):
            reopened.confirm_fresh(RUN_ID, 0)

    def test_real_usage_shape_is_counted_once_without_body_or_credentials_in_sqlite(self) -> None:
        record = usage_record()
        with cpa_server() as (state, origin):
            state.usage_batches.append([record])
            config = make_config(self.database_path, origin)
            database = self.database()
            client = keeper.CPAClient(config, allow_loopback_for_tests=True)
            runtime = keeper.KeeperRuntime(config, database, client)
            self.assertTrue(runtime.poll_once())
            self.assertEqual(database.snapshot()["usage_records"], 1)

        connection = sqlite3.connect(str(self.database_path))
        try:
            event_columns = [
                row[1] for row in connection.execute("PRAGMA table_info(observed_events)")
            ]
            self.assertEqual(event_columns, ["event_key", "sequence"])
            event_key, sequence = connection.execute(
                "SELECT event_key, sequence FROM observed_events"
            ).fetchone()
            self.assertEqual((len(event_key), sequence), (32, 1))
        finally:
            connection.close()
        database.checkpoint()
        retained = b"".join(
            path.read_bytes()
            for path in self.root.iterdir()
            if path.is_file() and path.name.startswith("keeper.sqlite3")
        )
        self.assertNotIn(USAGE_SECRET.encode("utf-8"), retained)
        self.assertNotIn(record["source"].encode("utf-8"), retained)
        self.assertNotIn(record["request_id"].encode("utf-8"), retained)

    def test_invalid_usage_schema_is_not_counted_and_makes_health_unhealthy(self) -> None:
        record = usage_record()
        record["request_body"] = REQUEST_SECRET
        with cpa_server() as (state, origin):
            state.usage_batches.append([record])
            config = make_config(self.database_path, origin)
            database = self.database()
            runtime = keeper.KeeperRuntime(
                config,
                database,
                keeper.CPAClient(config, allow_loopback_for_tests=True),
            )
            self.assertFalse(runtime.poll_once())
            snapshot = database.snapshot()
            self.assertEqual(snapshot["usage_records"], 0)
            self.assertEqual(snapshot["invalid_records"], 1)
            status, payload = runtime.health()
            self.assertEqual(status, HTTPStatus.SERVICE_UNAVAILABLE)
            self.assertFalse(payload["checks"]["poller"])

    def test_usage_model_and_internal_provider_drift_are_rejected(self) -> None:
        config = make_config(self.database_path, "http://cpa:8317")
        for key, value in (
            ("model", "other-model"),
            ("provider", "current-cpa-counted-mock"),
        ):
            with self.subTest(key=key):
                record = usage_record()
                record[key] = value
                with self.assertRaises(keeper.UsageRecordError):
                    keeper.validate_usage_record(record, config, 0)

    def test_control_request_body_is_strict_and_not_persisted(self) -> None:
        config = make_config(self.database_path, "http://cpa:8317")
        database = self.database()
        runtime = keeper.KeeperRuntime(config, database, FakeClient())
        self.assertTrue(runtime.poll_once())
        with keeper_server(runtime) as origin:
            status, value = request(
                origin,
                "POST",
                "/keeper/reset",
                token=CONTROL_TOKEN,
                value={
                    "schema": keeper.CONTRACT,
                    "run_id": RUN_ID,
                    "expected_usage_records": 0,
                    "body": REQUEST_SECRET,
                },
            )
            self.assertEqual(status, HTTPStatus.BAD_REQUEST)
            self.assertEqual(value["error"], "invalid_schema")
        database.checkpoint()
        retained = b"".join(
            path.read_bytes()
            for path in self.root.iterdir()
            if path.is_file() and path.name.startswith("keeper.sqlite3")
        )
        self.assertNotIn(REQUEST_SECRET.encode("utf-8"), retained)

    def test_database_parent_path_cannot_use_lexical_traversal(self) -> None:
        nested = self.root / "nested"
        nested.mkdir()
        traversal = nested / ".." / "keeper.sqlite3"
        with self.assertRaises(keeper.ConfigurationError):
            keeper.KeeperDatabase(traversal, RUN_ID)

    def test_source_hash_sidecar_and_dockerfile_contract(self) -> None:
        source = FIXTURE_DIR / "keeper_fixture.py"
        sidecar = FIXTURE_DIR / "keeper_fixture.py.sha256"
        dockerfile = FIXTURE_DIR / "Dockerfile"
        expected = sidecar.read_text(encoding="ascii").strip().split()[0]
        self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), expected)
        text = dockerfile.read_text(encoding="utf-8")
        self.assertIn("ARG KEEPER_BASE_IMAGE", text)
        self.assertIn("FROM ${KEEPER_BASE_IMAGE}", text)
        self.assertIn("ARG KEEPER_SOURCE_SHA256", text)
        self.assertIn("sys.argv[1]", text)
        self.assertIn("sys.argv[2]", text)
        self.assertIn("import hashlib,os,pathlib,re,sqlite3,sys", text)
        self.assertIn("USER 0:0", text)
        self.assertIn('"$KEEPER_BASE_IMAGE" "$KEEPER_SOURCE_SHA256"', text)
        self.assertNotIn('base="${KEEPER_BASE_IMAGE}"', text)
        self.assertIn("cag.current-cpa-audit.source-sha256", text)
        self.assertIn("USER 65532:65532", text)
        self.assertIn("os.chmod(source,0o555)", text)
        self.assertIn("0o444", text)
        self.assertIn(keeper.SOURCE_PATH, text)
        self.assertIn(
            'ENTRYPOINT ["python3", "-I", "-S", "-B", '
            '"/opt/cag-host-keeper/keeper_fixture.py"]',
            text,
        )
        self.assertIn(
            'CMD ["--host", "0.0.0.0", "--port", "18081", '
            '"--database", "/var/lib/cag-host-keeper/keeper.sqlite3"]',
            text,
        )
        readme = (FIXTURE_DIR / "README.md").read_text(encoding="utf-8")
        self.assertIn('--tag "local/cag-host-keeper:$RUN_ID"', readme)
        self.assertNotIn('local/cag-host-keeper@$RUN_ID', readme)
        self.assertIn('--user "$AUDIT_UID:$AUDIT_GID"', readme)
        self.assertIn("uid=$AUDIT_UID,gid=$AUDIT_GID", readme)


if __name__ == "__main__":
    unittest.main()
