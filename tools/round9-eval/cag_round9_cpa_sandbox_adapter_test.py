#!/usr/bin/env python3

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hashlib
import io
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import threading
import unittest
from unittest import mock

from cag_round9_cpa_sandbox_adapter import (
    AdapterError,
    CONFIG_SCHEMA,
    CPA_COMMIT,
    CPA_SOURCE,
    CPA_VERSION,
    DESCRIPTOR_SCHEMA,
    FINALIZE_REPORT_SCHEMA,
    MOCK_CONTRACT,
    NETWORK_BINDING,
    PHASE_PROTOCOL,
    PUBLIC_DECISION_AUDIT_SCHEMA,
    SCAN_LIMIT_BYTES,
    STATE_SCHEMA,
    canonical_bytes,
    cleanup,
    expected_persisted_decision,
    finalize_evaluation,
    http_request,
    load_audit_expectations,
    load_json,
    main as adapter_main,
    plugin_config,
    published_port,
    read_bounded,
    run_runtime_preflight,
    synthetic_runtime_checks,
    validate_config,
    validate_descriptor,
    validate_persisted_explanation,
    verify_images,
)
from cag_round9_external_evaluator import expected_plugin_config
from round9_eval_core import (
    FIXED_NETWORK_BINDING,
    FIXED_PHASE_PROTOCOL,
    validate_runtime_checks,
)


def completed(command: list[str], code: int = 0, stdout: bytes = b"") -> subprocess.CompletedProcess[bytes]:
    return subprocess.CompletedProcess(command, code, stdout=stdout, stderr=b"")


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class SandboxAdapterContractTest(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.image = "sha256:" + "a" * 64
        self.mock = "sha256:" + "b" * 64
        self.probe = "sha256:" + "c" * 64
        self.config = validate_config(
            {
                "schema": CONFIG_SCHEMA,
                "docker_executable": "/usr/bin/docker",
                "docker_sandbox": "/usr/local/libexec/cag-round9-docker-sandbox",
                "docker_sandbox_sha256": "d" * 64,
                "sandbox_id": "sandbox-identity-v1",
                "daemon_id": "daemon-identity-v1",
                "probe_image_id": self.probe,
                "cpa_image_id": self.image,
                "counted_mock_image_id": self.mock,
                "model": "gpt-5.4",
                "scan_limit_bytes": SCAN_LIMIT_BYTES,
            }
        )
        self.config["_docker"] = Path("/usr/bin/docker")

    def test_duplicate_keys_symlinks_and_oversized_files_fail_closed(self) -> None:
        duplicate = self.root / "duplicate.json"
        duplicate.write_text('{"schema":"a","schema":"b"}\n', encoding="utf-8")
        with self.assertRaisesRegex(AdapterError, "duplicate JSON key"):
            load_json(duplicate, "duplicate")
        symlink = self.root / "link"
        symlink.symlink_to(duplicate)
        with self.assertRaises(AdapterError):
            read_bounded(symlink, "symlink")
        oversized = self.root / "oversized"
        oversized.write_bytes(b"x" * 33)
        with self.assertRaisesRegex(AdapterError, "outside the reviewed bound"):
            read_bounded(oversized, "oversized", maximum=32)

    def test_image_identity_and_labels_are_exact(self) -> None:
        def runner(command, **_kwargs):
            image_id = command[-1]
            labels = (
                {
                    "org.opencontainers.image.source": CPA_SOURCE,
                    "org.opencontainers.image.revision": CPA_COMMIT,
                    "org.opencontainers.image.version": CPA_VERSION,
                }
                if image_id == self.image
                else {"io.cyber-abuse-guard.round9.mock-contract": MOCK_CONTRACT}
            )
            raw = json.dumps(
                [{"Id": image_id, "Os": "linux", "Architecture": "amd64", "Config": {"Labels": labels}}]
            ).encode()
            return completed(command, stdout=raw)

        verify_images(self.config, runner=runner)

        def bad_runner(command, **_kwargs):
            raw = json.dumps(
                [{"Id": command[-1], "Os": "linux", "Architecture": "amd64", "Config": {"Labels": {}}}]
            ).encode()
            return completed(command, stdout=raw)

        with self.assertRaisesRegex(AdapterError, "labels|contract"):
            verify_images(self.config, runner=bad_runner)

    def test_published_port_accepts_only_one_loopback_binding(self) -> None:
        good = lambda command, **_kwargs: completed(command, stdout=b"127.0.0.1:18394\n")
        self.assertEqual(
            published_port(
                self.config, "cpa", 8317, expected_host_port=18394, runner=good
            ),
            18394,
        )
        wrong_port = lambda command, **_kwargs: completed(
            command, stdout=b"127.0.0.1:18395\n"
        )
        with self.assertRaisesRegex(AdapterError, "fixed host binding"):
            published_port(
                self.config,
                "cpa",
                8317,
                expected_host_port=18394,
                runner=wrong_port,
            )
        bad = lambda command, **_kwargs: completed(command, stdout=b"0.0.0.0:18394\n")
        with self.assertRaisesRegex(AdapterError, "loopback"):
            published_port(self.config, "cpa", 8317, runner=bad)

    def descriptor(self, root: Path | None = None) -> dict:
        root = root or self.root
        token = root / "authorization.token"
        management = root / "management.token"
        strict = root / "strict-plugin-config.json"
        balanced = root / "balanced-plugin-config.json"
        canary = root / "runtime-canary.txt"
        for path in (token, management):
            path.write_text("secret\n", encoding="ascii")
            path.chmod(0o600)
        for path, mode in ((balanced, "balanced"), (strict, "strict")):
            path.write_bytes(canonical_bytes(plugin_config(mode)))
            path.chmod(0o600)
        canary.write_text("CAG_ROUND9_NORMAL_CANARY_SYNTHETIC\n", encoding="ascii")
        return {
            "schema": DESCRIPTOR_SCHEMA,
            "base_url": "http://127.0.0.1:18394",
            "counter_url": "http://127.0.0.1:18396/__cag/stats",
            "authorization_token_file": str(token),
            "management_token_file": str(management),
            "balanced_plugin_config_file": str(balanced),
            "strict_plugin_config_file": str(strict),
            "network_binding": dict(NETWORK_BINDING),
            "phase_protocol": dict(PHASE_PROTOCOL),
            "model": "gpt-5.4",
            "scan_limit_bytes": SCAN_LIMIT_BYTES,
            "candidate_so_sha256": "e" * 64,
            "cpa_version": CPA_VERSION,
            "cpa_commit": CPA_COMMIT,
            "cpa_image_id": self.image,
            "counted_mock_image_id": self.mock,
            "sandbox_id": "sandbox-identity-v1",
            "daemon_id": "daemon-identity-v1",
            "probe_image_id": self.probe,
            "production_accessed": False,
            "real_provider_contacted": False,
            "runtime_checks": synthetic_runtime_checks(),
            "runtime_baseline": {
                "audit_event_count": 3,
                "raw_capture_count": 0,
                "subject_state_rows": 0,
                "restart_count": 0,
            },
            "runtime_canary_file": str(canary),
        }

    def test_descriptor_is_closed_and_loopback_only(self) -> None:
        descriptor = self.descriptor()
        validate_descriptor(descriptor, enforce_token_file=False)
        descriptor["unexpected"] = True
        with self.assertRaisesRegex(AdapterError, "keys are not exact"):
            validate_descriptor(descriptor, enforce_token_file=False)
        descriptor = self.descriptor()
        descriptor["base_url"] = "http://0.0.0.0:18394"
        with self.assertRaisesRegex(AdapterError, "loopback"):
            validate_descriptor(descriptor, enforce_token_file=False)
        for key, value in (
            ("host_ip", "0.0.0.0"),
            ("host_port", 18395),
            ("container_port", 8318),
        ):
            descriptor = self.descriptor()
            descriptor["network_binding"][key] = value
            with self.assertRaisesRegex(AdapterError, "network binding"):
                validate_descriptor(descriptor, enforce_token_file=False)
        descriptor = self.descriptor()
        descriptor["phase_protocol"]["phase_order"] = ["strict", "balanced", "audit"]
        with self.assertRaisesRegex(AdapterError, "phase protocol"):
            validate_descriptor(descriptor, enforce_token_file=False)

        descriptor = self.descriptor()
        descriptor["runtime_checks"]["restart_recovery"]["observed"] = False
        with self.assertRaisesRegex(AdapterError, "runtime checks"):
            validate_descriptor(descriptor, enforce_token_file=False)

    def test_audit_initial_mode_and_runtime_fixture_are_closed(self) -> None:
        self.assertEqual(PHASE_PROTOCOL["initial_mode"], "audit")
        self.assertEqual(PHASE_PROTOCOL["phase_order"], ["audit", "balanced", "strict"])
        self.assertEqual(PHASE_PROTOCOL, FIXED_PHASE_PROTOCOL)
        self.assertEqual(NETWORK_BINDING, FIXED_NETWORK_BINDING)
        for mode in ("audit", "balanced", "strict"):
            self.assertEqual(plugin_config(mode), expected_plugin_config(mode))
        validate_runtime_checks(synthetic_runtime_checks())
        validate_descriptor(self.descriptor(), enforce_token_file=False)

    def test_runtime_preflight_mechanically_observes_closed_pass(self) -> None:
        audit = self.root / "audit"
        audit.mkdir()
        database = sqlite3.connect(audit / "events.db")
        try:
            database.execute("PRAGMA journal_mode=WAL")
            database.execute(
                "CREATE TABLE schema_version (singleton INTEGER PRIMARY KEY, version INTEGER)"
            )
            database.execute("INSERT INTO schema_version VALUES (1, 6)")
            database.execute("CREATE TABLE migration_history (version INTEGER)")
            database.executemany(
                "INSERT INTO migration_history VALUES (?)",
                [(1,), (2,), (3,), (4,), (5,), (6,)],
            )
            database.execute("CREATE TABLE raw_request_captures (id INTEGER)")
            database.execute("CREATE TABLE audit_events (id INTEGER)")
            database.executemany("INSERT INTO audit_events VALUES (?)", [(1,), (2,), (3,)])
            database.execute("CREATE TABLE subject_state (subject_hash TEXT)")
            database.commit()
        finally:
            database.close()

        ticks = {"value": 0.0}

        def monotonic() -> float:
            ticks["value"] += 0.2
            return ticks["value"]

        stopped = {
            "State": {"Running": False, "ExitCode": 0, "OOMKilled": False},
            "RestartCount": 0,
        }
        restarted = {
            "State": {"Running": True, "ExitCode": 0, "OOMKilled": False},
            "RestartCount": 0,
        }
        policy = canonical_bytes({"error": {"type": "cyber_policy"}})
        with (
            mock.patch("cag_round9_cpa_sandbox_adapter.wait_cpa"),
            mock.patch("cag_round9_cpa_sandbox_adapter.drain_usage_queue"),
            mock.patch("cag_round9_cpa_sandbox_adapter.reset_mock"),
            mock.patch(
                "cag_round9_cpa_sandbox_adapter.http_request",
                side_effect=[(200, b"{}"), (403, policy), (400, b"{}")],
            ),
            mock.patch(
                "cag_round9_cpa_sandbox_adapter.mock_total",
                side_effect=[1, 0, 0, 0],
            ),
            mock.patch(
                "cag_round9_cpa_sandbox_adapter.usage_queue",
                side_effect=[[{"usage": 1}], [], [], [], []],
            ),
            mock.patch(
                "cag_round9_cpa_sandbox_adapter.raw_capture_count", return_value=0
            ),
            mock.patch("cag_round9_cpa_sandbox_adapter.switch_plugin_mode"),
            mock.patch("cag_round9_cpa_sandbox_adapter.safe_chown"),
            mock.patch(
                "cag_round9_cpa_sandbox_adapter.inspect_container",
                side_effect=[stopped, restarted],
            ),
            mock.patch(
                "cag_round9_cpa_sandbox_adapter.docker",
                return_value=completed([], stdout=b""),
            ),
            mock.patch(
                "cag_round9_cpa_sandbox_adapter.time.monotonic",
                side_effect=monotonic,
            ),
            mock.patch("cag_round9_cpa_sandbox_adapter.time.sleep"),
        ):
            checks, baseline, canary = run_runtime_preflight(
                self.config,
                cpa_base="http://127.0.0.1:18394",
                mock_base="http://127.0.0.1:18396",
                client_key="client-key",
                management_key="management-key",
                model="gpt-5.4",
                audit_dir=audit,
                cpa_container="cpa",
                challenge="f" * 64,
            )
        self.assertEqual(checks, synthetic_runtime_checks())
        self.assertEqual(
            baseline,
            {
                "audit_event_count": 3,
                "raw_capture_count": 0,
                "subject_state_rows": 0,
                "restart_count": 0,
            },
        )
        self.assertEqual(canary, "CAG_ROUND9_NORMAL_CANARY_" + "f" * 24)

    def write_state(
        self,
        *,
        owner: str = "f" * 64,
        challenge_sha256: str = "1" * 64,
        work: Path | None = None,
    ) -> dict:
        work = work or self.root
        prefix = "cag-r9-external-" + owner[:12]
        state = {
            "schema": STATE_SCHEMA,
            "execution_id": owner,
            "challenge_sha256": challenge_sha256,
            "network": prefix + "-net",
            "containers": {
                "mock": prefix + "-mock",
                "cpa": prefix + "-cpa",
            },
        }
        (work / "adapter-state.json").write_bytes(canonical_bytes(state))
        return state

    def finalize_fixture(self, name: str) -> dict:
        root = self.root / name
        root.mkdir()
        work = root / "sandbox"
        work.mkdir()
        state = self.write_state(work=work)
        descriptor = self.descriptor(root)
        descriptor_path = root / "sandbox-descriptor.json"
        descriptor_path.write_bytes(canonical_bytes(descriptor))
        categories = [
            "credential_theft",
            "defense_evasion",
            "exfiltration",
            "exploitation",
            "malware_execution",
            "phishing",
            "ransomware",
            "service_disruption",
            "prompt_injection",
        ]
        public_requests = []
        public_families = {
            "historical_unique": 8,
            "branch_head": 1,
            "unmerged_candidate_carrier": 1,
        }
        for family, unique_payloads in public_families.items():
            for payload_index in range(unique_payloads):
                payload_hmac = sha256_text(f"public-payload:{family}:{payload_index}")
                for mode in ("audit", "balanced", "strict"):
                    for protocol in ("openai_chat", "openai_responses"):
                        for stream in ("nonstream", "stream"):
                            request_digest = sha256_text(
                                f"public-request:{payload_hmac}:{protocol}:{stream}"
                            )
                            audit_mode = mode == "audit"
                            public_requests.append(
                                {
                                    "request_id_hmac_sha256": sha256_text(
                                        f"public-id:{payload_hmac}:{mode}:{protocol}:{stream}"
                                    ),
                                    "request_hash": "sha256:" + request_digest,
                                    "request_hash_hmac_sha256": sha256_text(
                                        "public-request-hmac:" + request_digest
                                    ),
                                    "mode": mode,
                                    "kind": "public_development",
                                    "public_family": family,
                                    "public_payload_hmac_sha256": payload_hmac,
                                    "protocol": protocol,
                                    "stream": stream,
                                    "required": True,
                                    "expected_decision_kind": (
                                        "audit_eligible_malicious_text"
                                        if audit_mode
                                        else "block_malicious_text"
                                    ),
                                    "expected_local_block": not audit_mode,
                                    "expected_upstream_delta": int(audit_mode),
                                    "expected_usage_delta": int(audit_mode),
                                    "expected_hard_policy": False if audit_mode else None,
                                }
                            )
        expectations = {
            "schema": "round9-cpa-audit-expectations/v3",
            "challenge_sha256": "1" * 64,
            "malicious_categories": categories,
            "public_manifest": {
                "schema": "round9-public-adversarial-corpus/v13",
                "dataset": "round9-public-adversarial-v13",
                "bytes": 4096,
                "sha256": "8" * 64,
            },
            "requests": [
                {
                    "request_id_hmac_sha256": "2" * 64,
                    "request_hash": "sha256:" + "3" * 64,
                    "request_hash_hmac_sha256": "4" * 64,
                    "mode": "balanced",
                    "kind": "benign",
                    "persistence": "optional",
                    "expected_persisted_decision_kind": "audit_ineligible_risk",
                    "expected_category": "",
                },
                {
                    "request_id_hmac_sha256": "5" * 64,
                    "request_hash": "sha256:" + "6" * 64,
                    "request_hash_hmac_sha256": "7" * 64,
                    "mode": "balanced",
                    "kind": "malicious",
                    "persistence": "required",
                    "expected_persisted_decision_kind": "block_malicious_text",
                    "expected_category": "credential_theft",
                },
                *public_requests,
            ],
        }
        expectations_path = root / "audit-expectations.json"
        expectations_path.write_bytes(canonical_bytes(expectations))
        database_path = work / "audit" / "audit" / "events.db"
        database_path.parent.mkdir(parents=True)
        database = sqlite3.connect(database_path)
        try:
            database.execute("PRAGMA journal_mode=WAL")
            database.execute(
                "CREATE TABLE schema_version (singleton INTEGER PRIMARY KEY, version INTEGER)"
            )
            database.execute("INSERT INTO schema_version VALUES (1, 6)")
            database.execute("CREATE TABLE migration_history (version INTEGER)")
            database.executemany(
                "INSERT INTO migration_history VALUES (?)",
                [(1,), (2,), (3,), (4,), (5,), (6,)],
            )
            database.execute("CREATE TABLE raw_request_captures (id INTEGER)")
            database.execute("CREATE TABLE subject_state (subject_hash TEXT)")
            database.execute("CREATE TABLE subject_state_meta (subject_hash TEXT)")
            database.execute(
                """CREATE TABLE audit_events (
                       id TEXT,
                       timestamp_ns INTEGER,
                       action TEXT,
                       mode TEXT,
                       category TEXT,
                       rule_ids TEXT,
                       request_hash TEXT,
                       subject_hash TEXT,
                       decision TEXT,
                       coverage TEXT,
                       incomplete_reason TEXT,
                       decision_explanation TEXT,
                       disposition TEXT,
                       explanation_schema TEXT
                   )"""
            )
            baseline = [
                (
                    f"baseline-{index}",
                    index,
                    "audit",
                    "audit",
                    "",
                    "[]",
                    "sha256:" + str(index) * 64,
                    "",
                    "allow_clean",
                    "complete",
                    "",
                    "{}",
                    "allow_clean",
                    "none",
                )
                for index in range(1, 4)
            ]
            malicious_explanation = {
                "kind": "malicious",
                "winning_category": "credential_theft",
                "winning_rule_id": "CRED-001",
                "core_predicate_complete": True,
                "current_turn_evidence": True,
                "evidence_occurrence_count": 2,
                "evidence_segment_count": 1,
                "winning_role": "user",
                "winning_provenance": "content",
                "block_eligible": True,
                "primary_eligibility_reason": "eligible_explicit_malice",
                "eligibility_reason_flags": 1 << 9,
                "inspection_complete": True,
                "evidence_owned_by_current_user": True,
                "current_execution_act_proven": True,
                "harmful_core_complete": True,
                "operationally_actionable": True,
                "authorization_claim_state": "absent",
                "referent_proof_complete": True,
                "defensive_scope_conflict": False,
                "quoted_or_analytical_scope": False,
                "cross_scope_composition": False,
                "evidence_ambiguous": False,
            }
            evaluated = [
                (
                    "evaluated-malicious",
                    4,
                    "block",
                    "balanced",
                    "credential_theft",
                    '["CRED-001"]',
                    expectations["requests"][1]["request_hash"],
                    "",
                    "block_malicious_text",
                    "complete",
                    "",
                    json.dumps(malicious_explanation, sort_keys=True, separators=(",", ":")),
                    "block_malicious_text",
                    "decision-explanation-v2",
                ),
            ]
            explanation_json = json.dumps(
                malicious_explanation, sort_keys=True, separators=(",", ":")
            )
            for event_index, public in enumerate(public_requests, start=5):
                audit_mode = public["mode"] == "audit"
                evaluated.append(
                    (
                        "evaluated-public-" + public["request_id_hmac_sha256"],
                        event_index,
                        "audit" if audit_mode else "block",
                        public["mode"],
                        "credential_theft",
                        '["CRED-001"]',
                        public["request_hash"],
                        "",
                        public["expected_decision_kind"],
                        "complete",
                        "",
                        explanation_json,
                        "audit_malicious_text" if audit_mode else "block_malicious_text",
                        "decision-explanation-v2",
                    )
                )
            database.executemany(
                "INSERT INTO audit_events VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                baseline + evaluated,
            )
            database.commit()
        finally:
            database.close()
        return {
            "root": root,
            "work": work,
            "state": state,
            "descriptor": descriptor,
            "descriptor_path": descriptor_path,
            "expectations_path": expectations_path,
            "public_requests": public_requests,
            "database_path": database_path,
            "output": root / "sandbox-finalize.json",
        }

    def run_finalize_fixture(
        self,
        fixture: dict,
        *,
        inspected: dict | None = None,
        logs: bytes = b"",
    ) -> dict:
        inspected = inspected or {
            "State": {"Running": False, "ExitCode": 0, "OOMKilled": False},
            "RestartCount": 0,
            "Config": {
                "Labels": {
                    "io.cyber-abuse-guard.external-eval": fixture["state"]["execution_id"],
                    "io.cyber-abuse-guard.external-role": "cpa",
                }
            },
        }

        def fake_docker(_config, arguments, *_args, **_kwargs):  # noqa: ANN001
            return completed(arguments, stdout=logs if arguments[0] == "logs" else b"")

        with (
            mock.patch("cag_round9_cpa_sandbox_adapter.validate_descriptor", return_value=fixture["descriptor"]),
            mock.patch("cag_round9_cpa_sandbox_adapter.wait_cpa"),
            mock.patch("cag_round9_cpa_sandbox_adapter.wait_usage_queue_quiet"),
            mock.patch("cag_round9_cpa_sandbox_adapter.inspect_container", return_value=inspected),
            mock.patch("cag_round9_cpa_sandbox_adapter.docker", side_effect=fake_docker),
        ):
            return finalize_evaluation(
                self.config,
                fixture["work"],
                fixture["descriptor_path"],
                fixture["expectations_path"],
                fixture["output"],
            )

    def make_first_event_balanced_incomplete(
        self,
        fixture: dict,
        *,
        category: str = "",
        coverage: str = "incomplete",
        reason: str = "scan_limit",
    ) -> None:
        expectations = load_json(
            fixture["expectations_path"], "mutated expectations", 4_194_304
        )
        expectations["requests"][0].update(
            {
                "kind": "incomplete",
                "persistence": "required",
                "expected_persisted_decision_kind": "audit_ineligible_risk",
                "expected_category": "",
            }
        )
        fixture["expectations_path"].write_bytes(canonical_bytes(expectations))
        database = sqlite3.connect(fixture["database_path"])
        try:
            database.execute("DELETE FROM audit_events WHERE id='evaluated-benign'")
            database.execute(
                """INSERT INTO audit_events VALUES (
                       'evaluated-benign', 5, 'audit', 'balanced', ?, '[]', ?, '',
                       'audit_ineligible_risk', ?, ?, '{}',
                       'allow_due_to_incomplete_inspection', 'none'
                   )""",
                (
                    category,
                    expectations["requests"][0]["request_hash"],
                    coverage,
                    reason,
                ),
            )
            database.commit()
        finally:
            database.close()

    def add_optional_benign_ineligible_event(self, fixture: dict) -> None:
        expectations = load_json(
            fixture["expectations_path"], "optional benign expectations", 4_194_304
        )
        explanation = {
            "kind": "malicious",
            "winning_category": "credential_theft",
            "winning_rule_id": "CRED-002",
            "core_predicate_complete": True,
            "evidence_dimension_mask": 3,
            "evidence_occurrence_count": 1,
            "evidence_segment_count": 1,
            "winning_role": "user",
            "winning_provenance": "content",
            "current_turn_evidence": True,
            "referent_link_used": False,
            "quoted_or_inert_suppressed": True,
            "context_adjustment": 0,
            "hard_floor_applied": False,
            "block_eligible": False,
            "primary_eligibility_reason": "quoted_or_analytical",
            "eligibility_reason_flags": 1 << 3,
            "inspection_complete": True,
            "evidence_owned_by_current_user": True,
            "current_execution_act_proven": False,
            "harmful_core_complete": True,
            "operationally_actionable": False,
            "authorization_claim_state": "absent",
            "explicit_victim_or_nonconsent": False,
            "covert_acquisition": False,
            "exfiltration_or_takeover": False,
            "malicious_persistence": False,
            "destructive_outcome": False,
            "security_control_evasion": False,
            "defensive_scope_conflict": False,
            "quoted_or_analytical_scope": True,
            "cross_scope_composition": False,
            "referent_proof_complete": True,
            "evidence_ambiguous": False,
        }
        database = sqlite3.connect(fixture["database_path"])
        try:
            database.execute(
                """INSERT INTO audit_events VALUES (
                       'evaluated-benign', 5, 'audit', 'balanced',
                       'credential_theft', '["CRED-002"]', ?, '',
                       'audit_ineligible_risk', 'complete', '', ?,
                       'audit_ineligible_risk', 'decision-explanation-v2'
                   )""",
                (
                    expectations["requests"][0]["request_hash"],
                    json.dumps(explanation, sort_keys=True, separators=(",", ":")),
                ),
            )
            database.commit()
        finally:
            database.close()

    def test_audit_expectations_v3_closes_public_manifest_routes_and_outcomes(self) -> None:
        fixture = self.finalize_fixture("expectations-v3")
        value, digest = load_audit_expectations(fixture["expectations_path"])
        self.assertEqual(value["schema"], "round9-cpa-audit-expectations/v3")
        self.assertEqual(value["public_manifest"]["dataset"], "round9-public-adversarial-v13")
        self.assertEqual(len([row for row in value["requests"] if row["kind"] == "public_development"]), 120)
        self.assertEqual(len(digest), 64)

        for name in (
            "manifest-version",
            "optional",
            "audit-decision",
            "audit-hard",
            "enforcement-local-block",
            "enforcement-upstream",
            "blocked-usage",
            "enforcement-hard",
            "family-cardinality",
            "duplicate-route",
            "duplicate-request-id",
            "duplicate-request-hmac",
            "cross-family-payload-hmac",
        ):
            with self.subTest(name=name):
                changed = json.loads(json.dumps(value))
                public = [
                    row for row in changed["requests"] if row["kind"] == "public_development"
                ]
                audit = next(row for row in public if row["mode"] == "audit")
                enforcement = next(row for row in public if row["mode"] == "balanced")
                if name == "manifest-version":
                    changed["public_manifest"]["schema"] = "round9-public-adversarial-corpus/v10"
                elif name == "optional":
                    enforcement["required"] = False
                elif name == "audit-decision":
                    audit["expected_decision_kind"] = "block_malicious_text"
                elif name == "audit-hard":
                    audit["expected_hard_policy"] = True
                elif name == "enforcement-local-block":
                    enforcement["expected_local_block"] = False
                elif name == "enforcement-upstream":
                    enforcement["expected_upstream_delta"] = 1
                elif name == "blocked-usage":
                    enforcement["expected_usage_delta"] = 1
                elif name == "enforcement-hard":
                    enforcement["expected_hard_policy"] = False
                elif name == "family-cardinality":
                    branch = next(row for row in public if row["public_family"] == "branch_head")
                    branch["public_family"] = "historical_unique"
                elif name == "duplicate-route":
                    same_payload = [
                        row
                        for row in public
                        if row["public_payload_hmac_sha256"]
                        == public[0]["public_payload_hmac_sha256"]
                    ]
                    same_payload[1]["mode"] = same_payload[0]["mode"]
                    same_payload[1]["protocol"] = same_payload[0]["protocol"]
                    same_payload[1]["stream"] = same_payload[0]["stream"]
                elif name == "duplicate-request-id":
                    public[1]["request_id_hmac_sha256"] = public[0][
                        "request_id_hmac_sha256"
                    ]
                elif name == "duplicate-request-hmac":
                    public[1]["request_hash_hmac_sha256"] = public[0][
                        "request_hash_hmac_sha256"
                    ]
                elif name == "cross-family-payload-hmac":
                    branch = next(row for row in public if row["public_family"] == "branch_head")
                    branch["public_payload_hmac_sha256"] = public[0][
                        "public_payload_hmac_sha256"
                    ]
                fixture["expectations_path"].write_bytes(canonical_bytes(changed))
                with self.assertRaises(AdapterError):
                    load_audit_expectations(fixture["expectations_path"])

    def test_finalize_rejects_public_db_decision_missing_and_duplicate_rows(self) -> None:
        for name in ("db-decision", "all-allowed", "missing", "duplicate"):
            with self.subTest(name=name):
                fixture = self.finalize_fixture("finalize-public-" + name)
                database = sqlite3.connect(fixture["database_path"])
                try:
                    if name == "db-decision":
                        target = next(
                            row
                            for row in fixture["public_requests"]
                            if row["mode"] == "balanced"
                        )
                        database.execute(
                            "UPDATE audit_events SET decision='audit_eligible_malicious_text' WHERE request_hash=? AND mode='balanced'",
                            (target["request_hash"],),
                        )
                    elif name == "all-allowed":
                        database.execute(
                            """UPDATE audit_events
                                  SET decision='audit_eligible_malicious_text',
                                      action='audit', disposition='audit_malicious_text'
                                WHERE id LIKE 'evaluated-public-%'"""
                        )
                    elif name == "missing":
                        database.execute(
                            "DELETE FROM audit_events WHERE id=(SELECT id FROM audit_events WHERE id LIKE 'evaluated-public-%' LIMIT 1)"
                        )
                    else:
                        database.execute(
                            """INSERT INTO audit_events
                               SELECT id || '-duplicate', timestamp_ns + 1000, action, mode,
                                      category, rule_ids, request_hash, subject_hash, decision,
                                      coverage, incomplete_reason, decision_explanation,
                                      disposition, explanation_schema
                                 FROM audit_events
                                WHERE id LIKE 'evaluated-public-%'
                                LIMIT 1"""
                        )
                    database.commit()
                finally:
                    database.close()
                with self.assertRaises(AdapterError):
                    self.run_finalize_fixture(fixture)

    def test_finalize_binds_decisions_correlations_and_post_run_state(self) -> None:
        fixture = self.finalize_fixture("finalize-success")
        report = self.run_finalize_fixture(fixture)
        self.assertEqual(report["schema"], FINALIZE_REPORT_SCHEMA)
        self.assertEqual(report["runtime_checks"]["audit_database"]["evaluation_event_delta"], 121)
        self.assertEqual(
            report["decision_audit"]["decision_kind_counts"][
                "audit_eligible_malicious_text"
            ],
            40,
        )
        self.assertEqual(
            report["decision_audit"]["decision_kind_counts"]["block_malicious_text"],
            81,
        )
        self.assertEqual(report["decision_audit"]["schema"], "round9-external-decision-audit/v3")
        self.assertEqual(report["decision_audit"]["required_expectation_count"], 121)
        self.assertEqual(report["decision_audit"]["optional_expectation_count"], 1)
        self.assertEqual(report["decision_audit"]["matched_count"], 121)
        self.assertEqual(report["decision_audit"]["optional_persisted_count"], 0)
        self.assertEqual(report["decision_audit"]["optional_missing_count"], 1)
        self.assertEqual(report["decision_audit"]["group_counts"]["public_development"], 120)
        self.assertEqual(report["decision_audit"]["subject_state_rows"], 0)
        public_audit = report["public_decision_audit"]
        self.assertEqual(public_audit["schema"], PUBLIC_DECISION_AUDIT_SCHEMA)
        self.assertEqual(
            set(public_audit), {"schema", "manifest", "route_matrix", "families", "total"}
        )
        self.assertEqual(public_audit["total"]["unique_payloads"], 10)
        self.assertEqual(public_audit["total"]["serialized_executions"], 120)
        self.assertEqual(
            public_audit["total"]["decision_kind_counts"][
                "audit_eligible_malicious_text"
            ],
            40,
        )
        self.assertEqual(
            public_audit["total"]["decision_kind_counts"]["block_malicious_text"],
            80,
        )
        self.assertEqual(
            public_audit["families"]["historical_unique"]["serialized_executions"],
            96,
        )
        self.assertEqual(
            public_audit["families"]["branch_head"]["serialized_executions"], 12
        )
        self.assertEqual(
            public_audit["families"]["unmerged_candidate_carrier"][
                "serialized_executions"
            ],
            12,
        )
        public = json.dumps(report, sort_keys=True, separators=(",", ":"))
        self.assertNotIn('"request_hash"', public)
        self.assertNotIn("public_payload_hmac_sha256", public)
        self.assertNotIn("expected_upstream_delta", public)
        self.assertNotIn("expected_hard_policy", public)
        self.assertNotIn("sha256:" + "3" * 64, public)
        self.assertNotIn("sha256:" + "6" * 64, public)

    def test_finalize_accepts_optional_benign_ineligible_risk_row(self) -> None:
        fixture = self.finalize_fixture("finalize-optional-benign-persisted")
        self.add_optional_benign_ineligible_event(fixture)
        report = self.run_finalize_fixture(fixture)
        self.assertEqual(report["runtime_checks"]["audit_database"]["evaluation_event_delta"], 122)
        self.assertEqual(report["decision_audit"]["matched_count"], 122)
        self.assertEqual(report["decision_audit"]["optional_persisted_count"], 1)
        self.assertEqual(report["decision_audit"]["optional_missing_count"], 0)
        self.assertEqual(
            report["decision_audit"]["decision_kind_counts"]["audit_ineligible_risk"], 1
        )

    def test_finalize_rejects_arbitrary_nonempty_incomplete_category(self) -> None:
        fixture = self.finalize_fixture("finalize-incomplete-category")
        self.make_first_event_balanced_incomplete(
            fixture, category="new_malicious_taxonomy"
        )
        with self.assertRaisesRegex(AdapterError, "winner/category metadata"):
            self.run_finalize_fixture(fixture)

    def test_finalize_accepts_closed_incomplete_reason_as_category(self) -> None:
        fixture = self.finalize_fixture("finalize-incomplete-reason-category")
        self.make_first_event_balanced_incomplete(fixture, category="scan_limit")
        report = self.run_finalize_fixture(fixture)
        self.assertEqual(report["runtime_checks"]["audit_database"]["evaluation_event_delta"], 122)
        self.assertEqual(report["decision_audit"]["matched_count"], 122)
        self.assertEqual(report["decision_audit"]["incomplete_malicious_category_count"], 0)

    def test_finalize_rejects_open_incomplete_reason_and_coverage_values(self) -> None:
        cases = (
            (
                "reason",
                {"reason": "raw_request_fragment_should_not_be_an_enum"},
            ),
            (
                "coverage",
                {"coverage": "raw_request_fragment_should_not_be_coverage"},
            ),
        )
        for name, mutation in cases:
            with self.subTest(name=name):
                fixture = self.finalize_fixture("finalize-incomplete-" + name)
                self.make_first_event_balanced_incomplete(fixture, **mutation)
                with self.assertRaisesRegex(AdapterError, "winner/category metadata"):
                    self.run_finalize_fixture(fixture)

    def test_schema6_persisted_decision_mapping_covers_the_fixed_phase_matrix(self) -> None:
        cases = (
            ({"kind": "benign", "mode": "balanced", "persistence": "optional", "expected_persisted_decision_kind": "audit_ineligible_risk"}, ("audit", "audit_ineligible_risk", "decision-explanation-v2", "ineligible")),
            ({"kind": "malicious", "mode": "audit", "persistence": "required", "expected_persisted_decision_kind": "audit_eligible_malicious_text"}, ("audit", "audit_malicious_text", "decision-explanation-v2", "malicious")),
            ({"kind": "malicious", "mode": "strict", "persistence": "required", "expected_persisted_decision_kind": "block_malicious_text"}, ("block", "block_malicious_text", "decision-explanation-v2", "malicious")),
            ({"kind": "incomplete", "mode": "audit", "persistence": "required", "expected_persisted_decision_kind": "audit_ineligible_risk"}, ("audit", "audit_incomplete_inspection", "none", "")),
            ({"kind": "incomplete", "mode": "balanced", "persistence": "required", "expected_persisted_decision_kind": "audit_ineligible_risk"}, ("audit", "allow_due_to_incomplete_inspection", "none", "")),
            ({"kind": "incomplete", "mode": "strict", "persistence": "required", "expected_persisted_decision_kind": "block_incomplete_inspection"}, ("block", "block_due_to_incomplete_inspection", "decision-explanation-v2", "incomplete")),
            ({"kind": "public_development", "mode": "audit", "required": True, "expected_decision_kind": "audit_eligible_malicious_text"}, ("audit", "audit_malicious_text", "decision-explanation-v2", "malicious")),
            ({"kind": "public_development", "mode": "balanced", "required": True, "expected_decision_kind": "block_malicious_text"}, ("block", "block_malicious_text", "decision-explanation-v2", "malicious")),
        )
        for expected, wanted in cases:
            with self.subTest(expected=expected):
                self.assertEqual(expected_persisted_decision(expected), wanted)
        incomplete = {
            "kind": "incomplete",
            "incomplete_inspection_reason": "scan_limit",
            "block_eligible": False,
        }
        validate_persisted_explanation(
            incomplete,
            "decision-explanation-v2",
            "incomplete",
            "",
            "scan_limit",
            [],
        )
        neutral_full = dict(incomplete)
        neutral_full.update(
            {
                "core_predicate_complete": False,
                "evidence_dimension_mask": 0,
                "evidence_occurrence_count": 0,
                "evidence_segment_count": 0,
                "current_turn_evidence": False,
                "referent_link_used": False,
                "quoted_or_inert_suppressed": False,
                "context_adjustment": 0,
                "hard_floor_applied": False,
                "eligibility_reason_flags": 0,
                "inspection_complete": False,
                "evidence_owned_by_current_user": False,
                "current_execution_act_proven": False,
                "harmful_core_complete": False,
                "operationally_actionable": False,
                "explicit_victim_or_nonconsent": False,
                "covert_acquisition": False,
                "exfiltration_or_takeover": False,
                "malicious_persistence": False,
                "destructive_outcome": False,
                "security_control_evasion": False,
                "defensive_scope_conflict": False,
                "quoted_or_analytical_scope": False,
                "cross_scope_composition": False,
                "referent_proof_complete": False,
                "evidence_ambiguous": False,
            }
        )
        validate_persisted_explanation(
            neutral_full,
            "decision-explanation-v2",
            "incomplete",
            "",
            "scan_limit",
            [],
        )
        arbitrary_reason = dict(incomplete)
        arbitrary_reason["incomplete_inspection_reason"] = (
            "raw_request_fragment_should_not_be_an_enum"
        )
        with self.assertRaisesRegex(AdapterError, "closed schema-v6"):
            validate_persisted_explanation(
                arbitrary_reason,
                "decision-explanation-v2",
                "incomplete",
                "",
                "raw_request_fragment_should_not_be_an_enum",
                [],
            )
        contaminated = {
            "winning_rule_id": "CRED-001",
            "winning_role": "user",
            "winning_provenance": "content",
            "primary_eligibility_reason": "eligible_explicit_malice",
            "eligibility_reason_flags": 1 << 9,
            "inspection_complete": True,
            "evidence_owned_by_current_user": True,
            "current_execution_act_proven": True,
            "harmful_core_complete": True,
            "operationally_actionable": True,
        }
        for key, value in contaminated.items():
            with self.subTest(incomplete_contamination=key):
                changed = dict(incomplete)
                changed[key] = value
                with self.assertRaisesRegex(AdapterError, "retained malicious"):
                    validate_persisted_explanation(
                        changed,
                        "decision-explanation-v2",
                        "incomplete",
                        "",
                        "scan_limit",
                        [],
                    )

    def test_finalize_fails_closed_on_lifecycle_logs_db_and_audit_drift(self) -> None:
        cases = (
            ("oom", "lifecycle", None),
            ("panic-log", "logs contain", None),
            ("subject-state", "DB/WAL", "subject"),
            ("decision-kind", "decision_kind differs", "decision"),
            ("action", "action/disposition", "action"),
            ("disposition", "action/disposition", "disposition"),
            ("explanation-schema", "action/disposition", "schema"),
            ("explanation-eligibility", "eligible winner contract", "explanation"),
            ("request-correlation", "request identity", "correlation"),
            ("plaintext-canary", "DB/WAL", "canary"),
            ("challenge-binding", "challenge differs", "challenge"),
        )
        for name, message, mutation in cases:
            with self.subTest(name=name):
                fixture = self.finalize_fixture("finalize-failure-" + name)
                inspected = None
                logs = b""
                if name == "oom":
                    inspected = {
                        "State": {"Running": False, "ExitCode": 0, "OOMKilled": True},
                        "RestartCount": 0,
                        "Config": {
                            "Labels": {
                                "io.cyber-abuse-guard.external-eval": fixture["state"]["execution_id"],
                                "io.cyber-abuse-guard.external-role": "cpa",
                            }
                        },
                    }
                elif name == "panic-log":
                    logs = b"panic: synthetic post-run failure\n"
                elif mutation in {
                    "subject",
                    "decision",
                    "action",
                    "disposition",
                    "schema",
                    "explanation",
                    "correlation",
                }:
                    database = sqlite3.connect(fixture["database_path"])
                    try:
                        if mutation == "subject":
                            database.execute("INSERT INTO subject_state VALUES ('unexpected')")
                        elif mutation == "decision":
                            database.execute(
                                "UPDATE audit_events SET decision='audit_ineligible_risk' WHERE id='evaluated-malicious'"
                            )
                        elif mutation == "action":
                            database.execute(
                                "UPDATE audit_events SET action='audit' WHERE id='evaluated-malicious'"
                            )
                        elif mutation == "disposition":
                            database.execute(
                                "UPDATE audit_events SET disposition='block' WHERE id='evaluated-malicious'"
                            )
                        elif mutation == "schema":
                            database.execute(
                                "UPDATE audit_events SET explanation_schema='none' WHERE id='evaluated-malicious'"
                            )
                        elif mutation == "explanation":
                            raw = database.execute(
                                "SELECT decision_explanation FROM audit_events WHERE id='evaluated-malicious'"
                            ).fetchone()[0]
                            value = json.loads(raw)
                            value["block_eligible"] = False
                            database.execute(
                                "UPDATE audit_events SET decision_explanation=? WHERE id='evaluated-malicious'",
                                (json.dumps(value, sort_keys=True, separators=(",", ":")),),
                            )
                        else:
                            database.execute(
                                "UPDATE audit_events SET request_hash=? WHERE id='evaluated-malicious'",
                                ("sha256:" + "9" * 64,),
                            )
                        database.commit()
                    finally:
                        database.close()
                elif mutation == "challenge":
                    expectations = load_json(
                        fixture["expectations_path"], "mutated expectations", 4_194_304
                    )
                    expectations["challenge_sha256"] = "9" * 64
                    fixture["expectations_path"].write_bytes(canonical_bytes(expectations))
                elif mutation == "canary":
                    database = sqlite3.connect(fixture["database_path"])
                    try:
                        database.execute(
                            "UPDATE audit_events SET subject_hash=? WHERE id='baseline-1'",
                            (
                                Path(
                                    fixture["descriptor"]["runtime_canary_file"]
                                ).read_text(encoding="ascii").strip(),
                            ),
                        )
                        database.commit()
                    finally:
                        database.close()
                with self.assertRaisesRegex(AdapterError, message):
                    self.run_finalize_fixture(fixture, inspected=inspected, logs=logs)

    def test_adapter_loopback_http_ignores_proxy_and_rejects_redirect(self) -> None:
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, _format: str, *_args: object) -> None:
                return

            def do_GET(self) -> None:  # noqa: N802
                if self.path == "/redirect":
                    self.send_response(302)
                    self.send_header("Location", "/ok")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                self.send_response(200)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"{}")

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.shutdown)
        self.addCleanup(server.server_close)
        base = f"http://127.0.0.1:{server.server_address[1]}"
        proxy = {
            "HTTP_PROXY": "http://127.0.0.1:9",
            "HTTPS_PROXY": "http://127.0.0.1:9",
            "ALL_PROXY": "http://127.0.0.1:9",
            "NO_PROXY": "",
        }
        with mock.patch.dict(os.environ, proxy, clear=False):
            self.assertEqual(http_request(base, "/ok"), (200, b"{}"))
            with self.assertRaisesRegex(AdapterError, "redirect was rejected"):
                http_request(base, "/redirect")

    def test_cleanup_deletes_only_exact_owned_resources(self) -> None:
        state = self.write_state()
        removed: list[str] = []

        def runner(command, **_kwargs):
            if command[1] == "info":
                return completed(command, stdout=b'"28.0.0"\n')
            if command[1] == "inspect":
                if command[-1] in removed:
                    return completed(command, code=1)
                raw = json.dumps(
                    [{"Config": {"Labels": {"io.cyber-abuse-guard.external-eval": state["execution_id"]}}}]
                ).encode()
                return completed(command, stdout=raw)
            if command[1:3] == ["network", "inspect"]:
                if command[-1] in removed:
                    return completed(command, code=1)
                raw = json.dumps(
                    [{"Labels": {"io.cyber-abuse-guard.external-eval": state["execution_id"]}}]
                ).encode()
                return completed(command, stdout=raw)
            if command[1:3] == ["container", "ls"]:
                return completed(command)
            if command[1:3] == ["network", "ls"]:
                return completed(command)
            if command[1] == "rm" or command[1:3] == ["network", "rm"]:
                removed.append(command[-1])
                return completed(command)
            return completed(command, code=1)

        cleanup(self.config, self.root, runner=runner)
        self.assertEqual(len(removed), 3)
        self.assertFalse((self.root / "adapter-state.json").exists())

    def test_cleanup_rejects_ownership_mismatch_and_preserves_state(self) -> None:
        self.write_state()

        def runner(command, **_kwargs):
            if command[1] == "info":
                return completed(command, stdout=b'"28.0.0"\n')
            if command[1] == "inspect":
                return completed(
                    command,
                    stdout=b'[{"Config":{"Labels":{"io.cyber-abuse-guard.external-eval":"wrong"}}}]',
                )
            if command[1:3] == ["network", "inspect"]:
                return completed(command, code=1)
            if command[1:3] == ["network", "ls"]:
                return completed(command)
            return completed(command)

        with self.assertRaisesRegex(AdapterError, "cleanup failed"):
            cleanup(self.config, self.root, runner=runner)
        self.assertTrue((self.root / "adapter-state.json").exists())

    def test_cleanup_accepts_absent_resources_only_after_exact_name_proof(self) -> None:
        self.write_state()
        commands: list[list[str]] = []

        def runner(command, **_kwargs):
            commands.append(list(command))
            if command[1] == "info":
                return completed(command, stdout=b'"28.0.0"\n')
            if command[1] == "inspect" or command[1:3] == ["network", "inspect"]:
                return completed(command, code=1)
            if command[1:3] in (["container", "ls"], ["network", "ls"]):
                return completed(command)
            raise AssertionError(f"unexpected cleanup command: {command}")

        cleanup(self.config, self.root, runner=runner)
        self.assertFalse((self.root / "adapter-state.json").exists())
        self.assertEqual(sum(command[1] == "info" for command in commands), 3)
        self.assertEqual(
            sum(command[1:3] == ["container", "ls"] for command in commands), 2
        )
        self.assertEqual(
            sum(command[1:3] == ["network", "ls"] for command in commands), 1
        )
        self.assertFalse(
            any(
                command[1] == "rm" or command[1:3] == ["network", "rm"]
                for command in commands
            )
        )

    def test_cleanup_daemon_unavailable_preserves_state_and_stop_never_prints_clean(self) -> None:
        self.write_state()
        commands: list[list[str]] = []

        def runner(command, **_kwargs):
            commands.append(list(command))
            if command[1] == "inspect":
                return completed(command, code=1)
            if command[1] == "info":
                return completed(command, code=1)
            raise AssertionError(f"cleanup continued after unavailable daemon: {command}")

        with self.assertRaisesRegex(AdapterError, "daemon health is unavailable"):
            cleanup(self.config, self.root, runner=runner)
        self.assertTrue((self.root / "adapter-state.json").exists())
        self.assertEqual([command[1] for command in commands], ["inspect", "info"])

        output = io.StringIO()
        error = io.StringIO()
        with (
            mock.patch("cag_round9_cpa_sandbox_adapter.os.geteuid", return_value=0),
            mock.patch(
                "cag_round9_cpa_sandbox_adapter.load_config", return_value=self.config
            ),
            mock.patch(
                "cag_round9_cpa_sandbox_adapter.cleanup",
                side_effect=AdapterError("Docker daemon health is unavailable during cleanup"),
            ),
            mock.patch("cag_round9_cpa_sandbox_adapter.sys.stdout", output),
            mock.patch("cag_round9_cpa_sandbox_adapter.sys.stderr", error),
        ):
            self.assertEqual(
                adapter_main(
                    [
                        "stop",
                        "--config",
                        str(self.root / "adapter-config.json"),
                        "--work",
                        str(self.root),
                    ]
                ),
                1,
            )
        self.assertNotIn("CLEAN", output.getvalue())
        self.assertIn("FAIL", error.getvalue())


if __name__ == "__main__":
    unittest.main()
