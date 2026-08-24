from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, Mapping
from unittest import mock


HERE = Path(__file__).resolve().parent
TOOL = HERE.parent
sys.path.insert(0, str(TOOL))

import csam_text_evidence as evidence  # noqa: E402
import csam_text_runner as live  # noqa: E402
from audit_contract import MODES, PROTOCOLS, STREAM_VALUES, canonical_bytes  # noqa: E402
from second_machine_release_admission import validate_csam_text_evidence  # noqa: E402


RULE_BY_FAMILY = {
    "production": "CSAM-TXT-PRODUCTION-001",
    "solicitation": "CSAM-TXT-SOLICITATION-001",
    "exchange": "CSAM-TXT-EXCHANGE-001",
    "dissemination": "CSAM-TXT-DISSEMINATION-001",
    "grooming": "CSAM-TXT-GROOMING-001",
}


class FakeExecutor:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, str, bool, int]] = []
        self.body_references: list[bytearray] = []
        self.cold_starts: list[int] = []
        self.closed = False

    def begin_cold_start(self, index: int) -> None:
        self.cold_starts.append(index)

    def execute(self, request: evidence.TransportRequest) -> Mapping[str, Any]:
        self.calls.append(
            (
                request.case_id,
                request.mode,
                request.protocol,
                request.stream,
                request.cold_start,
            )
        )
        self.body_references.append(request.body)
        payload = json.loads(request.body)
        self._assert_request_shape(request, payload)
        malicious = request.label == "malicious"
        blocked = malicious and request.mode in {"balanced", "strict"}
        family = request.case_id.removeprefix("csam-malicious-").rsplit("-", 1)[0]
        return {
            "actual_action": "block_malicious_text" if blocked else "allow",
            "category": "csam_malicious" if malicious else None,
            "side_effect_deltas": {
                key: 0 if blocked else 1
                for key in ("auth", "mock", "provider", "usage")
            },
            "winning_rule_id": RULE_BY_FAMILY[family] if malicious else None,
        }

    @staticmethod
    def _assert_request_shape(
        request: evidence.TransportRequest, payload: Mapping[str, Any]
    ) -> None:
        if payload.get("model") != request.model or payload.get("stream") is not request.stream:
            raise AssertionError("request model/stream drifted")
        if request.protocol == "chat":
            messages = payload.get("messages")
            if (
                type(messages) is not list
                or len(messages) != 1
                or set(messages[0]) != {"content", "role"}
                or messages[0]["role"] != "user"
                or type(messages[0]["content"]) is not str
            ):
                raise AssertionError("chat request is not one current user/content")
            return
        inputs = payload.get("input")
        item = inputs[0] if type(inputs) is list and len(inputs) == 1 else None
        content = item.get("content") if type(item) is dict else None
        part = content[0] if type(content) is list and len(content) == 1 else None
        if (
            type(item) is not dict
            or item.get("role") != "user"
            or item.get("type") != "message"
            or type(part) is not dict
            or set(part) != {"text", "type"}
            or part.get("type") != "input_text"
            or type(part.get("text")) is not str
        ):
            raise AssertionError("Responses request is not one current user/content")

    def close(self) -> None:
        self.closed = True


class MutatingExecutor(FakeExecutor):
    def __init__(self, mutation: str, fail_at: int = 1) -> None:
        super().__init__()
        self.mutation = mutation
        self.fail_at = fail_at

    def execute(self, request: evidence.TransportRequest) -> Mapping[str, Any]:
        if len(self.calls) + 1 == self.fail_at and self.mutation == "exception":
            self.calls.append(
                (
                    request.case_id,
                    request.mode,
                    request.protocol,
                    request.stream,
                    request.cold_start,
                )
            )
            self.body_references.append(request.body)
            raise RuntimeError("synthetic executor failure")
        value = dict(super().execute(request))
        value["side_effect_deltas"] = dict(value["side_effect_deltas"])
        if len(self.calls) == self.fail_at:
            if self.mutation == "decision":
                value["actual_action"] = "block_malicious_text"
            elif self.mutation == "side-effect":
                value["side_effect_deltas"]["provider"] = 7
            elif self.mutation == "bool-side-effect":
                value["side_effect_deltas"]["provider"] = True
            elif self.mutation == "reversible-winner":
                value["winning_rule_id"] = base64.b64encode(request.body).decode("ascii")
            elif self.mutation == "extra-text":
                value["retained_text"] = "forbidden"
            elif self.mutation == "body-mutation":
                request.body[0] = 0
        return value


def load_bundle(paths: Mapping[str, Path]) -> tuple[dict[str, Any], ...]:
    return tuple(
        json.loads(paths[key].read_text(encoding="utf-8"))
        for key in ("fixture_manifest", "results", "summary", "privacy_cleanup")
    )


class CSAMTextEvidenceTests(unittest.TestCase):
    def test_happy_path_is_validator_interoperable_and_text_free(self) -> None:
        executor = FakeExecutor()
        zeroized: list[bytearray] = []
        original_zeroize = evidence._zeroize

        def recording_zeroize(value: bytearray) -> None:
            zeroized.append(value)
            original_zeroize(value)

        with tempfile.TemporaryDirectory() as root, mock.patch.object(
            evidence, "_zeroize", side_effect=recording_zeroize
        ):
            output = Path(root) / "csam-text"
            paths = evidence.produce_evidence("unit-csam-run", output, executor)
            manifest, results, summary, cleanup = load_bundle(paths)
            projection = validate_csam_text_evidence(
                manifest,
                results,
                summary,
                cleanup,
                expected_run_id="unit-csam-run",
            )
            self.assertEqual(projection["status"], "PASS")
            self.assertEqual(len(manifest["cases"]), 36)
            self.assertEqual(
                sum(case["label"] == "malicious" for case in manifest["cases"]), 15
            )
            self.assertEqual(
                sum(case["label"] == "benign" for case in manifest["cases"]), 21
            )
            self.assertEqual(len(results["executions"]), 1296)
            self.assertEqual(results["side_effect_violations"], 0)
            self.assertEqual(results["unexpected_errors"], 0)
            self.assertEqual(summary["audit_detection_percent"], 100)
            self.assertFalse(cleanup["fixture_text_retained"])
            self.assertFalse(cleanup["reversible_encodings_retained"])

            expected_matrix = {
                (case.case_id, mode, protocol, stream, cold_start)
                for case in evidence.CASE_SPECS
                for mode in MODES
                for protocol in PROTOCOLS
                for stream in STREAM_VALUES
                for cold_start in range(1, 4)
            }
            self.assertEqual(set(executor.calls), expected_matrix)
            self.assertEqual(len(executor.calls), len(expected_matrix))
            self.assertEqual(executor.cold_starts, [1, 2, 3])
            self.assertTrue(executor.closed)

            for name, path in paths.items():
                raw = path.read_bytes()
                self.assertEqual(raw, canonical_bytes(json.loads(raw)) + b"\n", name)
                if os.name != "nt":
                    self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            if os.name != "nt":
                self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o700)
            combined = b"\n".join(path.read_bytes() for path in paths.values())
            for case in evidence.CASE_SPECS:
                text = evidence.build_case_text(case)
                try:
                    immutable = bytes(text)
                    self.assertNotIn(immutable, combined)
                    self.assertNotIn(base64.b64encode(immutable), combined)
                    self.assertNotIn(immutable.hex().encode("ascii"), combined)
                finally:
                    original_zeroize(text)

        self.assertTrue(zeroized)
        self.assertTrue(all(not value or set(value) == {0} for value in zeroized))
        self.assertTrue(executor.body_references)
        self.assertTrue(
            all(not body or set(body) == {0} for body in executor.body_references)
        )

    def test_missing_and_duplicate_catalog_cases_fail_closed(self) -> None:
        missing = list(evidence.CASE_SPECS[:-1])
        with self.assertRaisesRegex(evidence.EvidenceError, "exactly 36"):
            evidence._validate_case_catalog(missing)
        duplicate = list(evidence.CASE_SPECS)
        duplicate[-1] = duplicate[0]
        with self.assertRaisesRegex(evidence.EvidenceError, "duplicate"):
            evidence._validate_case_catalog(duplicate)

    def test_observation_failures_publish_nothing(self) -> None:
        for mutation, error in (
            ("decision", "decision"),
            ("side-effect", "side effects"),
            ("bool-side-effect", "non-negative integer"),
            ("reversible-winner", "unsafe CSAM rule"),
            ("extra-text", "keys are not closed"),
            ("body-mutation", "mutated the bound request"),
            ("exception", "synthetic executor failure"),
        ):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as root:
                output = Path(root) / "csam-text"
                executor = MutatingExecutor(mutation)
                with self.assertRaisesRegex((evidence.EvidenceError, RuntimeError), error):
                    evidence.produce_evidence("unit-csam-run", output, executor)
                self.assertFalse(os.path.lexists(output))
                self.assertTrue(executor.closed)
                self.assertTrue(executor.body_references)
                self.assertTrue(
                    all(not body or set(body) == {0} for body in executor.body_references)
                )

    def test_failure_after_multiple_requests_zeroizes_every_owned_body(self) -> None:
        executor = MutatingExecutor("exception", fail_at=19)
        with self.assertRaisesRegex(RuntimeError, "synthetic executor failure"):
            evidence.collect_evidence("unit-csam-run", executor)
        self.assertEqual(len(executor.calls), 19)
        self.assertTrue(executor.closed)
        self.assertTrue(all(set(body) == {0} for body in executor.body_references))

    def test_preexisting_output_is_rejected_before_transport(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            output = Path(root) / "csam-text"
            output.mkdir()
            executor = FakeExecutor()
            with self.assertRaisesRegex(evidence.EvidenceError, "already exists"):
                evidence.produce_evidence("unit-csam-run", output, executor)
            self.assertEqual(executor.calls, [])
            self.assertFalse(executor.closed)

    def test_symlink_output_is_rejected_before_transport(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            target = Path(root) / "target"
            target.mkdir()
            output = Path(root) / "csam-text"
            try:
                output.symlink_to(target, target_is_directory=True)
            except OSError as exc:
                self.skipTest(f"symlink creation unavailable: {exc}")
            executor = FakeExecutor()
            with self.assertRaisesRegex(evidence.EvidenceError, "already exists"):
                evidence.produce_evidence("unit-csam-run", output, executor)
            self.assertEqual(executor.calls, [])
            self.assertFalse(executor.closed)

    def test_invalid_run_id_fails_before_executor_close_or_transport(self) -> None:
        executor = FakeExecutor()
        with self.assertRaisesRegex(evidence.EvidenceError, "run ID"):
            evidence.collect_evidence("../unsafe", executor)
        self.assertEqual(executor.calls, [])
        self.assertFalse(executor.closed)

    def test_admission_validator_rejects_missing_and_duplicate_execution(self) -> None:
        bundle = evidence.collect_evidence("unit-csam-run", FakeExecutor())
        missing = copy.deepcopy(bundle.results)
        missing["executions"].pop()
        with self.assertRaises(Exception):
            validate_csam_text_evidence(
                bundle.fixture_manifest,
                missing,
                bundle.summary,
                bundle.privacy_cleanup,
            )
        duplicate = copy.deepcopy(bundle.results)
        duplicate["executions"][-1] = copy.deepcopy(duplicate["executions"][0])
        with self.assertRaises(Exception):
            validate_csam_text_evidence(
                bundle.fixture_manifest,
                duplicate,
                bundle.summary,
                bundle.privacy_cleanup,
            )

    def test_admission_validator_rejects_untyped_fields_and_catalog_drift(self) -> None:
        bundle = evidence.collect_evidence("unit-csam-run", FakeExecutor())

        def reject(mutator: Any, message: str) -> None:
            mutated = copy.deepcopy(bundle.results)
            mutator(mutated)
            with self.assertRaisesRegex(Exception, message):
                validate_csam_text_evidence(
                    bundle.fixture_manifest,
                    mutated,
                    bundle.summary,
                    bundle.privacy_cleanup,
                )

        reject(
            lambda value: value["executions"][0].__setitem__("stream", 1),
            "JSON boolean",
        )
        reject(
            lambda value: value["executions"][0].__setitem__("cold_start", True),
            "integer",
        )
        reject(
            lambda value: value["executions"][0]["side_effect_deltas"].__setitem__(
                "provider", True
            ),
            "non-negative integer",
        )
        reject(
            lambda value: value["executions"][0].__setitem__(
                "winning_rule_id", "CSAM-TEXT-UNSAFE-001"
            ),
            "eligible CSAM rule",
        )

        manifest = copy.deepcopy(bundle.fixture_manifest)
        manifest["cases"][0]["case_id"] = "csam-malicious-unknown-1"
        with self.assertRaisesRegex(Exception, "fixed 15/21 catalog"):
            validate_csam_text_evidence(
                manifest,
                bundle.results,
                bundle.summary,
                bundle.privacy_cleanup,
            )


class LiveRunnerUnitTests(unittest.TestCase):
    def make_live_executor(
        self, hook: Path, **overrides: Any
    ) -> live.LiveCPAExecutor:
        arguments: dict[str, Any] = {
            "cpa_url": "http://172.20.0.2:8317",
            "mock_url": "http://172.20.0.3:18080",
            "cold_start_hook": hook,
            "runtime_root": hook.parent / "runtime",
            "client_key_env": "TEST_CSAM_CLIENT_KEY",
            "management_key_env": "TEST_CSAM_MANAGEMENT_KEY",
            "mock_control_token_env": "TEST_CSAM_MOCK_TOKEN",
            "upstream_key_env": "TEST_CSAM_UPSTREAM_KEY",
        }
        arguments.update(overrides)
        return live.LiveCPAExecutor(**arguments)

    def test_private_http_base_accepts_only_local_ip_or_single_label_dns(self) -> None:
        accepted = (
            "http://127.0.0.1:8317",
            "http://10.1.2.3:8317",
            "http://172.20.0.2:8317/",
            "http://192.168.1.2:8317",
            "http://169.254.10.20:8317",
            "http://[::1]:8317",
            "http://[fd00::2]:8317",
            "http://[fe80::2]:8317",
            "http://cpa:8317",
            "http://counted-mock-1:18080",
        )
        for value in accepted:
            with self.subTest(accepted=value):
                self.assertEqual(
                    live._validate_private_http_base(value, "test"), value.rstrip("/")
                )

        public_dns_ipv4 = "http://" + ".".join(("8", "8", "8", "8")) + ":8317"
        multicast_ipv4 = "http://" + ".".join(("224", "0", "0", "1")) + ":8317"
        credential_url = "http://" + "user" + ":" + "secret" + "@cpa:8317"
        rejected = (
            public_dns_ipv4,
            "http://[2001:4860:4860::8888]:8317",
            "http://0.0.0.0:8317",
            multicast_ipv4,
            "http://example.com:8317",
            "http://cpa.internal:8317",
            "http://cpa.local.:8317",
            "http://bad_name:8317",
            "http://-cpa:8317",
            "http://cpa-:8317",
            "https://cpa:8317",
            credential_url,
            "http://cpa:8317/path",
            "http://cpa:8317?query=1",
            "http://cpa",
            "http://cpa:0",
            "http://cpa:99999",
        )
        for value in rejected:
            with self.subTest(rejected=value), self.assertRaises(live.LiveRunnerError):
                live._validate_private_http_base(value, "test")

    def test_timeouts_require_finite_native_numbers_within_bounds(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            hook = Path(root) / "hook.exe"
            hook.write_bytes(b"placeholder")
            hook.chmod(0o700)
            for readiness, hook_timeout in ((1, 1.0), (300.0, 900)):
                with self.subTest(valid=(readiness, hook_timeout)):
                    executor = self.make_live_executor(
                        hook,
                        readiness_timeout=readiness,
                        hook_timeout=hook_timeout,
                    )
                    self.assertEqual(executor.readiness_timeout, float(readiness))
                    self.assertEqual(executor.hook_timeout, float(hook_timeout))
            invalid_readiness = (
                True,
                False,
                float("nan"),
                float("inf"),
                float("-inf"),
                0,
                -1,
                300.0001,
                "60",
                None,
            )
            for value in invalid_readiness:
                with self.subTest(readiness=value), self.assertRaises(
                    live.LiveRunnerError
                ):
                    self.make_live_executor(hook, readiness_timeout=value)
            invalid_hook = (
                True,
                False,
                float("nan"),
                float("inf"),
                float("-inf"),
                0,
                -1,
                900.0001,
                "180",
                None,
            )
            for value in invalid_hook:
                with self.subTest(hook_timeout=value), self.assertRaises(
                    live.LiveRunnerError
                ):
                    self.make_live_executor(hook, hook_timeout=value)

    def test_event_head_id_rejects_empty_and_non_string_values(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            hook = Path(root) / "hook.exe"
            hook.write_bytes(b"placeholder")
            hook.chmod(0o700)
            executor = self.make_live_executor(hook)
            with mock.patch.object(executor, "_event_head", return_value=None):
                self.assertEqual(executor._event_head_id(), live.NO_PRIOR_EVENT_ID)
            with mock.patch.object(
                executor, "_event_head", return_value={"id": "event-1"}
            ):
                self.assertEqual(executor._event_head_id(), "event-1")
            for malformed in (None, "", 0, 1, False, [], {}):
                with self.subTest(event_id=malformed), mock.patch.object(
                    executor, "_event_head", return_value={"id": malformed}
                ), self.assertRaisesRegex(live.LiveRunnerError, "empty or malformed"):
                    executor._event_head_id()

    @staticmethod
    def request(mode: str = "audit") -> evidence.TransportRequest:
        return evidence.TransportRequest(
            body=bytearray(
                b'{"messages":[{"content":"synthetic","role":"user"}],'
                b'"model":"current-cpa-audit-model","stream":false}'
            ),
            case_id="csam-malicious-production-1",
            cold_start=1,
            label="malicious",
            mode=mode,
            model="current-cpa-audit-model",
            protocol="chat",
            stream=False,
        )

    def test_cold_start_hook_requires_three_distinct_runtime_identities(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            hook = Path(root) / "hook.exe"
            hook.write_bytes(b"placeholder")
            hook.chmod(0o700)
            executor = self.make_live_executor(hook)
            first = {
                "cold_start": 1,
                "instance_id": "runtime-one",
                "schema": live.COLD_START_HOOK_SCHEMA,
                "status": "PASS",
            }
            second = {**first, "cold_start": 2}
            runs = [
                subprocess_result(first),
                subprocess_result(second),
            ]
            runtime_root = hook.parent / "runtime"

            def create_runtime(*args: Any, **kwargs: Any) -> Any:
                runtime_root.mkdir(mode=0o700, exist_ok=True)
                runtime_root.chmod(0o700)
                return runs.pop(0)

            with mock.patch.dict(
                os.environ, {"TEST_CSAM_UPSTREAM_KEY": "u" * 32}
            ), mock.patch.object(live.subprocess, "run", side_effect=create_runtime), mock.patch.object(
                executor, "_wait_mock"
            ), mock.patch.object(executor, "_configure_mode"), mock.patch.object(
                executor, "reset_mock"
            ), mock.patch.object(executor, "drain_usage_queue"):
                executor.begin_cold_start(1)
                with self.assertRaisesRegex(live.LiveRunnerError, "reused"):
                    executor.begin_cold_start(2)
            receipt = {
                "owned_resources_absent": True,
                "runtime_root_absent": True,
                "schema": live.CLEANUP_HOOK_SCHEMA,
                "status": "PASS",
            }

            with mock.patch.object(
                live.subprocess, "run", return_value=subprocess_result(receipt)
            ), self.assertRaisesRegex(live.LiveRunnerError, "remained"):
                executor._run_cleanup_hook()

            def cleanup(*args: Any, **kwargs: Any) -> Any:
                self.assertEqual(
                    args[0], [str(hook), "cleanup", str(runtime_root)]
                )
                runtime_root.rmdir()
                return subprocess_result(receipt)

            with mock.patch.object(executor, "drain_usage_queue"), mock.patch.object(
                executor, "reset_mock"
            ), mock.patch.object(live.subprocess, "run", side_effect=cleanup):
                executor.close()
            self.assertTrue(executor._closed)
            self.assertFalse(os.path.lexists(runtime_root))

            replacement = self.make_live_executor(hook)
            distinct = {**first, "cold_start": 2, "instance_id": "runtime-two"}
            repeated = [subprocess_result(first), subprocess_result(distinct)]

            def reuse_runtime_root(*args: Any, **kwargs: Any) -> Any:
                runtime_root.mkdir(mode=0o700, exist_ok=True)
                runtime_root.chmod(0o700)
                return repeated.pop(0)

            with mock.patch.dict(
                os.environ, {"TEST_CSAM_UPSTREAM_KEY": "u" * 32}
            ), mock.patch.object(
                live.subprocess, "run", side_effect=reuse_runtime_root
            ), mock.patch.object(replacement, "_wait_mock"), mock.patch.object(
                replacement, "_configure_mode"
            ), mock.patch.object(replacement, "reset_mock"), mock.patch.object(
                replacement, "drain_usage_queue"
            ):
                replacement.begin_cold_start(1)
                with self.assertRaisesRegex(live.LiveRunnerError, "runtime root identity"):
                    replacement.begin_cold_start(2)
            runtime_root.rmdir()

    def test_live_allow_projection_uses_top_level_csam_rule_ids(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            hook = Path(root) / "hook.exe"
            hook.write_bytes(b"placeholder")
            hook.chmod(0o700)
            executor = self.make_live_executor(hook)
            executor._cold_start = 1
            executor._current_mode = "audit"
            request = self.request()
            event = {
                "action": "audit",
                "category": "csam_malicious",
                "classifier": "csam-text-v1",
                "decision_explanation": {"kind": "csam_text"},
                "decision_kind": "audit_csam_text",
                "mode": "audit",
                "rule_ids": ["CSAM-TXT-PRODUCTION-001"],
            }
            snapshots = [
                {"auth": 0, "mock": 0, "provider": 0},
                {"auth": 1, "mock": 1, "provider": 1},
            ]
            with mock.patch.dict(
                os.environ,
                {
                    "TEST_CSAM_CLIENT_KEY": "c" * 32,
                    "TEST_CSAM_MANAGEMENT_KEY": "m" * 32,
                    "TEST_CSAM_MOCK_TOKEN": "t" * 32,
                },
            ), mock.patch.object(executor, "drain_usage_queue"), mock.patch.object(
                executor, "reset_mock"
            ), mock.patch.object(
                executor, "mock_snapshot", side_effect=snapshots
            ), mock.patch.object(
                executor, "_event_head_id", return_value="old"
            ), mock.patch.object(
                executor, "_audit_counter_snapshot", return_value={
                    "dropped": 0,
                    "enqueued": 0,
                    "failed": 0,
                    "queue_depth": 0,
                    "rejected": 0,
                    "written": 0,
                }
            ), mock.patch.object(
                executor, "_event_or_idle_audit", return_value=event
            ), mock.patch.object(
                executor, "_usage_after_request", return_value=1
            ), mock.patch.object(
                live, "http_request", return_value=(200, b"response", {}, 1.0)
            ), mock.patch.object(
                live, "validate_allow_response", return_value=(True, True)
            ):
                observed = executor.execute(request)
            self.assertEqual(observed["actual_action"], "allow")
            self.assertEqual(observed["category"], "csam_malicious")
            self.assertEqual(
                observed["winning_rule_id"], "CSAM-TXT-PRODUCTION-001"
            )
            self.assertEqual(
                observed["side_effect_deltas"],
                {"auth": 1, "mock": 1, "provider": 1, "usage": 1},
            )

    def test_live_block_projection_normalizes_observed_csam_block(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            hook = Path(root) / "hook.exe"
            hook.write_bytes(b"placeholder")
            hook.chmod(0o700)
            executor = self.make_live_executor(hook)
            executor._cold_start = 1
            executor._current_mode = "balanced"
            request = self.request("balanced")
            event = {
                "action": "block",
                "category": "csam_malicious",
                "classifier": "csam-text-v1",
                "decision_explanation": {"kind": "csam_text"},
                "decision_kind": "block_csam_text",
                "mode": "balanced",
                "rule_ids": ["CSAM-TXT-PRODUCTION-001"],
            }
            snapshots = [
                {"auth": 0, "mock": 0, "provider": 0},
                {"auth": 0, "mock": 0, "provider": 0},
            ]
            with mock.patch.dict(
                os.environ,
                {
                    "TEST_CSAM_CLIENT_KEY": "c" * 32,
                    "TEST_CSAM_MANAGEMENT_KEY": "m" * 32,
                    "TEST_CSAM_MOCK_TOKEN": "t" * 32,
                },
            ), mock.patch.object(executor, "drain_usage_queue"), mock.patch.object(
                executor, "reset_mock"
            ), mock.patch.object(
                executor, "mock_snapshot", side_effect=snapshots
            ), mock.patch.object(
                executor, "_event_head_id", return_value="old"
            ), mock.patch.object(
                executor, "_audit_counter_snapshot", return_value={
                    "dropped": 0,
                    "enqueued": 0,
                    "failed": 0,
                    "queue_depth": 0,
                    "rejected": 0,
                    "written": 0,
                }
            ), mock.patch.object(
                executor, "_event_or_idle_audit", return_value=event
            ), mock.patch.object(
                executor, "_usage_after_request", return_value=0
            ), mock.patch.object(
                live, "http_request", return_value=(403, b"blocked", {}, 1.0)
            ), mock.patch.object(live, "validate_block_response"):
                observed = executor.execute(request)
            self.assertEqual(observed["actual_action"], "block_malicious_text")
            self.assertEqual(
                observed["side_effect_deltas"],
                {"auth": 0, "mock": 0, "provider": 0, "usage": 0},
            )


def subprocess_result(value: Mapping[str, Any]) -> Any:
    return live.subprocess.CompletedProcess(
        args=["hook"],
        returncode=0,
        stdout=canonical_bytes(dict(value)) + b"\n",
        stderr=b"",
    )


if __name__ == "__main__":
    unittest.main()
