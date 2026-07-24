#!/usr/bin/env python3

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import threading
import unittest
from unittest import mock

from cag_round9_external_evaluator import (
    AUDIT_EXPECTATIONS_SCHEMA,
    BENIGN_MANIFEST_SCHEMA,
    CORPUS_BUNDLE_SCHEMA,
    MALICIOUS_MANIFEST_SCHEMA,
    CPAClient,
    SANDBOX_SCHEMA,
    evaluate_cases,
    expected_plugin_config,
    load_corpus_bundle,
    main as evaluator_main,
    validate_sandbox_descriptor,
)
from round9_eval_core import (
    FIXED_NETWORK_BINDING,
    FIXED_PHASE_PROTOCOL,
    ContractError,
    canonical_bytes,
    sha256_file,
    signed_envelope,
)
from round9_eval_test_fixtures import runtime_checks


class SyntheticCPAHandler(BaseHTTPRequestHandler):
    requests_seen = 0
    usage_seen = 0
    token = "synthetic-token"
    management_token = "synthetic-management-token"
    bodies_seen: list[str] = []
    request_modes: list[str] = []
    mode = "audit"
    mode_switch_count = 0
    usage_queue_items: list[dict] = []

    def log_message(self, _format: str, *_args) -> None:
        return

    def _json(self, status: int, value: dict) -> None:
        raw = canonical_bytes(value)
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _authorized(self) -> bool:
        return self.headers.get("Authorization") == f"Bearer {self.token}"

    def _management_authorized(self) -> bool:
        return self.headers.get("Authorization") == f"Bearer {self.management_token}"

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/counter")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if self.path == "/v0/management/plugins/cyber-abuse-guard/status":
            if not self._management_authorized():
                self._json(401, {"error": {"type": "unauthorized"}})
                return
            self._json(
                200,
                {
                    "loaded": True,
                    "initialized": True,
                    "enforcement_ready": True,
                    "enabled": True,
                    "mode": type(self).mode,
                    "priority": 300,
                    "opaque_media_policy": "audit",
                    "subjects": 0,
                    "audit_degraded": False,
                    "router_errors": 0,
                    "panics_recovered": 0,
                    "last_reconfigure_error": "",
                    "last_config_error": "",
                    "effective_limits": {
                        "max_text_window_bytes": 16_384,
                        "max_total_text_bytes": 16_384,
                        "legacy_max_scan_bytes_configured": 16_384,
                    },
                    "audit": {"enabled": True, "healthy": True, "degraded": False},
                    "subject_control": {"enabled": False, "subjects": 0},
                    "classifier": {"remote": False},
                    "raw_capture": {
                        "enabled": False,
                        "only_blocked": True,
                        "redact_secrets": True,
                        "max_bytes": 8192,
                        "ttl_hours": 1,
                    },
                },
            )
            return
        if self.path == "/v0/management/usage-queue?count=100":
            if not self._management_authorized():
                self._json(401, {"error": {"type": "unauthorized"}})
                return
            observed = list(type(self).usage_queue_items)
            type(self).usage_queue_items = []
            self._json(200, observed)
            return
        if not self._authorized() or self.path != "/counter":
            self._json(404, {"error": {"type": "not_found"}})
            return
        self._json(
            200,
            {"requests": type(self).requests_seen, "usage": type(self).usage_seen},
        )

    def do_POST(self) -> None:  # noqa: N802
        if not self._authorized():
            self._json(401, {"error": {"type": "unauthorized"}})
            return
        length = int(self.headers.get("Content-Length", "0"))
        body = json.loads(self.rfile.read(length))
        serialized = json.dumps(body, ensure_ascii=False)
        type(self).bodies_seen.append(serialized)
        type(self).request_modes.append(type(self).mode)
        if type(self).mode == "strict" and len(serialized.encode("utf-8")) > 16_384:
            self._json(403, {"error": {"type": "cyber_policy"}})
            return
        if "synthetic malicious" in serialized and type(self).mode in {"balanced", "strict"}:
            self._json(403, {"error": {"type": "cyber_policy"}})
            return
        if "synthetic benign" not in serialized and "synthetic malicious" not in serialized:
            self._json(400, {"error": {"type": "unknown_fixture"}})
            return
        type(self).requests_seen += 1
        type(self).usage_seen += 1
        type(self).usage_queue_items = [{"id": type(self).usage_seen}]
        self._json(200, {"id": "synthetic", "object": "response"})

    def do_PUT(self) -> None:  # noqa: N802
        if (
            not self._management_authorized()
            or self.path != "/v0/management/plugins/cyber-abuse-guard/config"
        ):
            self._json(401, {"error": {"type": "unauthorized"}})
            return
        length = int(self.headers.get("Content-Length", "0"))
        body = json.loads(self.rfile.read(length))
        expected = {"audit": "balanced", "balanced": "strict"}.get(type(self).mode)
        if expected is None or body != expected_plugin_config(expected):
            self._json(400, {"error": {"type": "invalid_transition"}})
            return
        type(self).mode = expected
        type(self).mode_switch_count += 1
        self._json(200, {"status": "ok"})


@unittest.skipUnless(shutil.which("openssl"), "OpenSSL is required for Ed25519 tests")
class ExternalEvaluatorTest(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.private = self.root / "author-private.pem"
        self.public = self.root / "author-public.pem"
        private_key = subprocess.run(
            ["openssl", "genpkey", "-algorithm", "ed25519"],
            check=True,
            capture_output=True,
        ).stdout
        self.private.write_bytes(private_key)
        public_key = subprocess.run(
            ["openssl", "pkey", "-pubout"],
            input=private_key,
            check=True,
            capture_output=True,
        ).stdout
        self.public.write_bytes(public_key)
        SyntheticCPAHandler.requests_seen = 0
        SyntheticCPAHandler.usage_seen = 0
        SyntheticCPAHandler.bodies_seen = []
        SyntheticCPAHandler.request_modes = []
        SyntheticCPAHandler.mode = "audit"
        SyntheticCPAHandler.mode_switch_count = 0
        SyntheticCPAHandler.usage_queue_items = []
        self.server = ThreadingHTTPServer(("127.0.0.1", 18394), SyntheticCPAHandler)
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(self.server.shutdown)
        self.addCleanup(self.server.server_close)

    def write_corpus(self) -> tuple[Path, Path]:
        corpus = self.root / "synthetic-corpus"
        corpus.mkdir()
        benign_manifest = {
            "schema": BENIGN_MANIFEST_SCHEMA,
            "unique_semantic_samples": 2,
            "routes_per_sample": 12,
            "categories": ["coding", "operations"],
            "languages": ["en", "zh"],
            "expected_disposition": "allow",
            "ground_truth_frozen_before_candidate": True,
        }
        malicious_manifest = {
            "schema": MALICIOUS_MANIFEST_SCHEMA,
            "unique_semantic_samples": 2,
            "routes_per_sample": 12,
            "categories": ["credential_theft", "defense_evasion"],
            "languages": ["en", "zh"],
            "expected_disposition": "block_malicious_text",
            "ground_truth_frozen_before_candidate": True,
        }
        files = {
            "benign-manifest.json": canonical_bytes(benign_manifest),
            "benign-cases.jsonl": b"".join(
                canonical_bytes(item)
                for item in (
                    {
                        "id": "benign-case-en",
                        "category": "coding",
                        "language": "en",
                        "prompt": "synthetic benign request",
                    },
                    {
                        "id": "benign-case-zh",
                        "category": "operations",
                        "language": "zh",
                        "prompt": "synthetic benign request zh",
                    },
                )
            ),
            "malicious-manifest.json": canonical_bytes(malicious_manifest),
            "malicious-cases.jsonl": b"".join(
                canonical_bytes(item)
                for item in (
                    {
                        "id": "malicious-case-en",
                        "category": "credential_theft",
                        "language": "en",
                        "prompt": "synthetic malicious request",
                    },
                    {
                        "id": "malicious-case-zh",
                        "category": "defense_evasion",
                        "language": "zh",
                        "prompt": "synthetic malicious request zh",
                    },
                )
            ),
        }
        for name, raw in files.items():
            (corpus / name).write_bytes(raw)
        payload = {
            "schema": CORPUS_BUNDLE_SCHEMA,
            "evaluation_id": "synthetic-independent-v1",
            "author": {
                "key_id": "synthetic-author-v1",
                "independence": "AUTHOR_DID_NOT_PARTICIPATE_IN_RULE_DEVELOPMENT",
                "candidate_outputs_seen": False,
            },
            "files": {
                name: {"bytes": len(raw), "sha256": sha256_file(corpus / name)}
                for name, raw in files.items()
            },
            "benign": benign_manifest,
            "malicious": malicious_manifest,
            "plaintext_in_repository": False,
        }
        signed = corpus / "bundle-manifest.signed.json"
        signed.write_bytes(
            canonical_bytes(signed_envelope(payload, self.private, "synthetic-author-v1"))
        )
        return corpus, signed

    def test_fake_cpa_black_box_routes_and_counted_mock_contract(self) -> None:
        corpus_root, signed = self.write_corpus()
        corpus, benign, malicious = load_corpus_bundle(
            corpus_root,
            signed_manifest_path=signed,
            author_public_key=self.public,
            author_key_id="synthetic-author-v1",
            bundle_sha256="a" * 64,
            minimum_benign=1,
            minimum_malicious=1,
        )
        self.assertEqual(corpus["plaintext_in_repository"], False)
        token_file = self.root / "authorization.token"
        token_file.write_text(SyntheticCPAHandler.token + "\n", encoding="utf-8")
        management_file = self.root / "management.token"
        management_file.write_text(
            SyntheticCPAHandler.management_token + "\n", encoding="utf-8"
        )
        balanced_config = self.root / "balanced-plugin-config.json"
        balanced_config.write_bytes(canonical_bytes(expected_plugin_config("balanced")))
        strict_config = self.root / "strict-plugin-config.json"
        strict_config.write_bytes(canonical_bytes(expected_plugin_config("strict")))
        canary_file = self.root / "runtime-canary.txt"
        canary_file.write_text("CAG_ROUND9_NORMAL_CANARY_SYNTHETIC\n", encoding="ascii")
        port = self.server.server_address[1]
        descriptor = validate_sandbox_descriptor(
            {
                "schema": SANDBOX_SCHEMA,
                "base_url": f"http://127.0.0.1:{port}",
                "counter_url": f"http://127.0.0.1:{port}/counter",
                "authorization_token_file": str(token_file),
                "management_token_file": str(management_file),
                "balanced_plugin_config_file": str(balanced_config),
                "strict_plugin_config_file": str(strict_config),
                "network_binding": dict(FIXED_NETWORK_BINDING),
                "phase_protocol": dict(FIXED_PHASE_PROTOCOL),
                "model": "gpt-5.4",
                "scan_limit_bytes": 16_384,
                "candidate_so_sha256": "b" * 64,
                "cpa_version": "v7.2.95",
                "cpa_commit": "f71ec0eb6776854457892452cf28c47f0d658251",
                "cpa_image_id": "sha256:" + "d" * 64,
                "counted_mock_image_id": "sha256:" + "e" * 64,
                "sandbox_id": "synthetic-sandbox-v1",
                "daemon_id": "synthetic-daemon-v1",
                "probe_image_id": "sha256:" + "c" * 64,
                "production_accessed": False,
                "real_provider_contacted": False,
                "runtime_checks": runtime_checks("preflight"),
                "runtime_baseline": {
                    "audit_event_count": 3,
                    "raw_capture_count": 0,
                    "subject_state_rows": 0,
                    "restart_count": 0,
                },
                "runtime_canary_file": str(canary_file),
            },
            "b" * 64,
            enforce_root_ownership=False,
        )
        audit_expectations: list[dict] = []
        metrics = evaluate_cases(
            descriptor,
            benign,
            malicious,
            challenge="f" * 64,
            timeout=5,
            audit_expectations=audit_expectations,
        )
        self.assertEqual(metrics["benign"]["blocked"], 0)
        self.assertEqual(metrics["benign"]["serialized_route_executions"], 24)
        self.assertEqual(metrics["malicious"]["semantic_blocked"], 2)
        self.assertEqual(metrics["malicious"]["passed_route_executions"], 16)
        self.assertEqual(metrics["malicious"]["audit_allowed_route_executions"], 8)
        self.assertEqual(metrics["malicious"]["audit_policy_blocked"], 0)
        self.assertEqual(AUDIT_EXPECTATIONS_SCHEMA, "round9-cpa-audit-expectations/v2")
        benign_expectations = [
            item for item in audit_expectations if item["kind"] == "benign"
        ]
        required_expectations = [
            item for item in audit_expectations if item["persistence"] == "required"
        ]
        self.assertEqual(len(benign_expectations), 24)
        self.assertEqual(len(required_expectations), 27)
        self.assertTrue(
            all(
                item["persistence"] == "optional"
                and item["expected_persisted_decision_kind"] == "audit_ineligible_risk"
                and "expected_decision_kind" not in item
                for item in benign_expectations
            )
        )
        self.assertTrue(
            all(item["kind"] != "benign" for item in required_expectations)
        )
        self.assertEqual(SyntheticCPAHandler.requests_seen, 34)
        self.assertEqual(SyntheticCPAHandler.usage_seen, 34)
        self.assertEqual(SyntheticCPAHandler.mode_switch_count, 2)
        self.assertEqual(
            metrics["route_order"]["phase_order"], ["audit", "balanced", "strict"]
        )
        self.assertEqual(
            metrics["route_order"]["mode_status_verified"],
            {"audit": True, "balanced": True, "strict": True},
        )
        self.assertTrue(metrics["route_order"]["mode_switch_authenticated"])
        self.assertEqual(metrics["runtime_checks"], runtime_checks("preflight"))
        self.assertEqual(
            metrics["route_order"]["mode_switch_negative_auth_verified"],
            {"balanced": True, "strict": True},
        )
        self.assertEqual(
            set(metrics["route_order"]["effective_config_sha256"]),
            {"audit", "balanced", "strict"},
        )
        self.assertEqual(
            SyntheticCPAHandler.request_modes,
            ["audit"] * 17 + ["balanced"] * 17 + ["strict"] * 17,
        )
        self.assertIn("request_hmac_sha256", metrics["incomplete"])
        self.assertNotIn("request_sha256", metrics["incomplete"])
        public_metrics = json.dumps(metrics, sort_keys=True, separators=(",", ":"))
        self.assertNotIn('"request_hash"', public_metrics)
        for expectation in audit_expectations:
            self.assertNotIn(expectation["request_hash"], public_metrics)
        transmitted = "\n".join(SyntheticCPAHandler.bodies_seen).casefold()
        for forbidden in (
            "benign-case-en",
            "malicious-case-en",
            "credential_theft",
            "defense_evasion",
            "synthetic-independent-v1",
            "round9",
            "holdout",
            "corpus",
        ):
            self.assertNotIn(forbidden, transmitted)

        changed = dict(descriptor)
        changed["base_url"] = "http://127.0.0.1:18395"
        with self.assertRaisesRegex(ContractError, "fixed CPA base URL"):
            validate_sandbox_descriptor(
                changed, "b" * 64, enforce_root_ownership=False
            )

    def test_loopback_client_bypasses_environment_proxy_and_rejects_redirects(self) -> None:
        token_file = self.root / "authorization.token"
        token_file.write_text(SyntheticCPAHandler.token + "\n", encoding="utf-8")
        management_file = self.root / "management.token"
        management_file.write_text(
            SyntheticCPAHandler.management_token + "\n", encoding="utf-8"
        )
        client = CPAClient(
            {
                "authorization_token_file": str(token_file),
                "management_token_file": str(management_file),
            },
            timeout=2,
        )
        port = self.server.server_address[1]
        poisoned_proxy = {
            "HTTP_PROXY": "http://127.0.0.1:9",
            "HTTPS_PROXY": "http://127.0.0.1:9",
            "ALL_PROXY": "http://127.0.0.1:9",
            "NO_PROXY": "",
            "http_proxy": "http://127.0.0.1:9",
            "https_proxy": "http://127.0.0.1:9",
            "all_proxy": "http://127.0.0.1:9",
            "no_proxy": "",
        }
        with mock.patch.dict(os.environ, poisoned_proxy, clear=False):
            status, _raw = client._open(f"http://127.0.0.1:{port}/counter")
            self.assertEqual(status, 200)
            with self.assertRaisesRegex(ContractError, "redirect was rejected"):
                client._open(f"http://127.0.0.1:{port}/redirect")

    def test_failed_aggregate_write_removes_new_audit_expectations(self) -> None:
        output = self.root / "aggregate.json"
        expectations = self.root / "audit-expectations.json"

        def fake_evaluate(args) -> dict:
            args.audit_expectations_output.write_bytes(b"sensitive expectations\n")
            args.output.write_bytes(b"raced aggregate\n")
            return {"schema": "synthetic"}

        argv = [
            "--corpus-root",
            str(self.root),
            "--signed-manifest",
            str(self.root / "signed.json"),
            "--author-public-key",
            str(self.public),
            "--author-key-id",
            "round9-author-key-v1",
            "--bundle-sha256",
            "a" * 64,
            "--sandbox-descriptor",
            str(self.root / "sandbox.json"),
            "--expected-candidate-so-sha256",
            "b" * 64,
            "--expected-core-sha256",
            "c" * 64,
            "--challenge",
            "d" * 64,
            "--output",
            str(output),
            "--audit-expectations-output",
            str(expectations),
        ]
        with (
            mock.patch("cag_round9_external_evaluator.os.geteuid", return_value=0),
            mock.patch("cag_round9_external_evaluator.evaluate", side_effect=fake_evaluate),
        ):
            self.assertEqual(evaluator_main(argv), 1)
        self.assertFalse(expectations.exists())
        self.assertTrue(output.exists())

    def test_existing_aggregate_fails_before_evaluation(self) -> None:
        output = self.root / "aggregate.json"
        expectations = self.root / "audit-expectations.json"
        output.write_bytes(b"existing\n")
        argv = [
            "--corpus-root",
            str(self.root),
            "--signed-manifest",
            str(self.root / "signed.json"),
            "--author-public-key",
            str(self.public),
            "--author-key-id",
            "round9-author-key-v1",
            "--bundle-sha256",
            "a" * 64,
            "--sandbox-descriptor",
            str(self.root / "sandbox.json"),
            "--expected-candidate-so-sha256",
            "b" * 64,
            "--expected-core-sha256",
            "c" * 64,
            "--challenge",
            "d" * 64,
            "--output",
            str(output),
            "--audit-expectations-output",
            str(expectations),
        ]
        with (
            mock.patch("cag_round9_external_evaluator.os.geteuid", return_value=0),
            mock.patch("cag_round9_external_evaluator.evaluate") as evaluate_mock,
        ):
            self.assertEqual(evaluator_main(argv), 1)
        evaluate_mock.assert_not_called()
        self.assertFalse(expectations.exists())


if __name__ == "__main__":
    unittest.main()
