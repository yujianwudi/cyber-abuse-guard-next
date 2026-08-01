#!/usr/bin/env python3

from __future__ import annotations

import copy
import hashlib
from pathlib import Path
import shutil
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from round9_eval_core import (
    EVALUATION_SCHEMA,
    FIXED_NETWORK_BINDING,
    FIXED_PHASE_PROTOCOL,
    LEDGER_EVENT_SCHEMA,
    LEDGER_PROOF_SCHEMA,
    ContractError,
    canonical_bytes,
    challenge_sha256,
    derive_counted_mock,
    ledger_namespace,
    ledger_ref,
    merge_public_counted_mock,
    openssl_sign,
    openssl_verify,
    sha256_bytes,
    signed_envelope,
    validate_evaluation_payload,
    validate_counted_mock,
    validate_development_evidence,
    validate_ledger_proof,
    validate_metrics,
    validate_public_counted_mock_transport,
    validate_public_decision_audit,
    verify_signed_envelope,
    wilson_interval_95,
)
from round9_eval_test_fixtures import (
    decision_audit,
    development_evidence,
    public_counted_mock,
    public_counted_mock_transport,
    public_decision_audit,
    runtime_checks,
)


@unittest.skipUnless(shutil.which("openssl"), "OpenSSL is required for Ed25519 tests")
class Round9EvalCoreTest(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.private = self.root / "private.pem"
        self.public = self.root / "public.pem"
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

    @staticmethod
    def metrics() -> dict:
        z = 1.959963984540054
        benign_categories = {f"benign_category_{index:02d}": 40 for index in range(15)}
        malicious_categories = {f"malicious_category_{index:02d}": 10 for index in range(9)}
        lower, upper = wilson_interval_95(90, 90)
        return {
            "route_order": {
                "algorithm": "hmac_sha256_challenge_sequential_phase_order_v3",
                "seed_sha256": challenge_sha256("d" * 64),
                "phase_order": ["audit", "balanced", "strict"],
                "phase_permutation_sha256": {
                    "audit": "d" * 64,
                    "balanced": "e" * 64,
                    "strict": "f" * 64,
                },
                "phase_route_executions": {
                    "audit": 2801,
                    "balanced": 2801,
                    "strict": 2801,
                },
                "mode_status_verified": {
                    "audit": True,
                    "balanced": True,
                    "strict": True,
                },
                "mode_switch_authenticated": True,
                "mode_switch_negative_auth_verified": {
                    "balanced": True,
                    "strict": True,
                },
                "effective_config_sha256": {
                    "audit": "a" * 64,
                    "balanced": "b" * 64,
                    "strict": "c" * 64,
                },
                "route_executions": 8403,
            },
            "route_histogram": {
                "benign": {
                    f"{mode}|openai_{protocol}|{stream}": {
                        "executions": 600,
                        "policy_blocked": 0,
                        "upstream_delta": 600,
                        "usage_delta": 600,
                    }
                    for mode in ("audit", "balanced", "strict")
                    for protocol in ("chat", "responses")
                    for stream in ("stream", "nonstream")
                },
                "malicious": {
                    f"{mode}|openai_{protocol}|{stream}": {
                        "executions": 90,
                        "policy_blocked": 0 if mode == "audit" else 90,
                        "upstream_delta": 90 if mode == "audit" else 0,
                        "usage_delta": 90 if mode == "audit" else 0,
                    }
                    for mode in ("audit", "balanced", "strict")
                    for protocol in ("chat", "responses")
                    for stream in ("stream", "nonstream")
                },
                "incomplete": {
                    f"{mode}|openai_chat|nonstream": {
                        "executions": 1,
                        "policy_blocked": 1 if mode == "strict" else 0,
                        "upstream_delta": 0 if mode == "strict" else 1,
                        "usage_delta": 0 if mode == "strict" else 1,
                    }
                    for mode in ("audit", "balanced", "strict")
                },
                "public_development": {
                    f"{mode}|openai_{protocol}|{stream}": {
                        "executions": 10,
                        "policy_blocked": 0 if mode == "audit" else 10,
                        "upstream_delta": 10 if mode == "audit" else 0,
                        "usage_delta": 10 if mode == "audit" else 0,
                    }
                    for mode in ("audit", "balanced", "strict")
                    for protocol in ("chat", "responses")
                    for stream in ("stream", "nonstream")
                },
            },
            "benign": {
                "unique_semantic_samples": 600,
                "serialized_route_executions": 7200,
                "blocked": 0,
                "hard_policy_blocked": 0,
                "wilson_upper_bound_ppm": round(1_000_000 * z * z / (600 + z * z)),
                "category_counts": benign_categories,
                "language_counts": {"en": 300, "zh": 300},
                "protocol_counts": {"openai_chat": 3600, "openai_responses": 3600},
                "stream_counts": {"stream": 3600, "nonstream": 3600},
                "mode_counts": {"audit": 2400, "balanced": 2400, "strict": 2400},
                "carrier_counts": {"current_user_direct": 7200},
                "upstream_delta": 7200,
                "usage_delta": 7200,
                "cag_policy_block_delta": 0,
            },
            "malicious": {
                "unique_semantic_samples": 90,
                "semantic_blocked": 90,
                "serialized_route_executions": 1080,
                "enforcement_route_executions": 720,
                "audit_route_executions": 360,
                "passed_route_executions": 720,
                "audit_allowed_route_executions": 360,
                "audit_policy_blocked": 0,
                "recall_basis_points": 10000,
                "wilson_lower_bound_basis_points": round(lower * 10000),
                "wilson_upper_bound_basis_points": round(upper * 10000),
                "per_category": {
                    category: {
                        "samples": samples,
                        "blocked": samples,
                        "recall_basis_points": 10000,
                        "wilson_lower_bound_basis_points": round(
                            wilson_interval_95(samples, samples)[0] * 10000
                        ),
                        "wilson_upper_bound_basis_points": round(
                            wilson_interval_95(samples, samples)[1] * 10000
                        ),
                    }
                    for category, samples in malicious_categories.items()
                },
                "category_counts": malicious_categories,
                "language_counts": {"en": 45, "zh": 45},
                "protocol_counts": {"openai_chat": 540, "openai_responses": 540},
                "stream_counts": {"stream": 540, "nonstream": 540},
                "mode_counts": {"audit": 360, "balanced": 360, "strict": 360},
                "carrier_counts": {"current_user_direct": 1080},
                "upstream_delta": 360,
                "usage_delta": 360,
                "cag_policy_block_delta": 720,
                "failure_id_hmac_sha256": [],
                "enforcement_blocks_per_semantic_sample": {
                    **{str(index): 0 for index in range(8)},
                    "8": 90,
                },
            },
            "incomplete": {
                "request_hmac_sha256": "f" * 64,
                "request_bytes": 20000,
                "scan_limit_bytes": 16384,
                "valid_json": True,
                "protocol": "openai_chat",
                "stream": False,
                "carrier": "current_user_direct",
                "audit": {"policy_blocked": False, "upstream_delta": 1, "usage_delta": 1},
                "balanced": {"policy_blocked": False, "upstream_delta": 1, "usage_delta": 1},
                "strict": {"policy_blocked": True, "upstream_delta": 0, "usage_delta": 0},
            },
            "runtime_checks": runtime_checks(),
            "decision_audit": decision_audit(),
            "public_counted_mock": public_counted_mock(),
        }

    def fixture(self) -> tuple[dict, dict, dict]:
        candidate = {
            "tag": "v0.16-rc.4",
            "tag_object_sha": "1" * 40,
            "source_version": "0.16",
            "commit": "2" * 40,
            "tree": "3" * 40,
            "so_sha256": "4" * 64,
            "cpa_version": "v7.2.113",
            "cpa_commit": "bc71c77f5cc42f3fbe1bf040cf14d4f166894835",
            "classifier_policy_version": "classifier-policy-v10",
            "classifier_policy_sha256": "5" * 64,
            "ruleset_version": "1.0.10",
            "ruleset_sha256": "6" * 64,
            "ruleset_manifest_sha256": "7" * 64,
            "build_metadata_sha256": "8" * 64,
            "release_manifest_sha256": "9" * 64,
            "phase1_run_id": 101,
            "phase1_run_attempt": 1,
            "phase1_artifact_id": 202,
            "phase1_artifact_digest": "sha256:" + "a" * 64,
        }
        evaluator = {
            "version": "cag-round9-external-evaluator-v3",
            "sha256": "b" * 64,
            "core_sha256": "c" * 64,
            "broker_sha256": "d" * 64,
            "key_id": "round9-evaluator-key-v1",
            "execution_mode": "EXTERNAL_ROOT_OWNED_BLACK_BOX_CPA",
        }
        corpus = {
            "evaluation_id": "round9-independent-v1",
            "bundle_sha256": "1" * 64,
            "bundle_manifest_sha256": "2" * 64,
            "benign_manifest_sha256": "3" * 64,
            "benign_cases_sha256": "4" * 64,
            "malicious_manifest_sha256": "5" * 64,
            "malicious_cases_sha256": "6" * 64,
            "author_key_id": "round9-independent-author-v1",
            "plaintext_in_repository": False,
        }
        execution = {
            "workflow_run_id": 303,
            "workflow_run_attempt": 1,
            "challenge_sha256": challenge_sha256("d" * 64),
            "route_order_seed_sha256": challenge_sha256("d" * 64),
            "sandbox_id": "round9-sandbox-test",
            "daemon_id": "round9-daemon-test",
            "probe_image_id": "sha256:" + "7" * 64,
            "cpa_version": "v7.2.113",
            "cpa_commit": "bc71c77f5cc42f3fbe1bf040cf14d4f166894835",
            "cpa_image_id": "sha256:" + "8" * 64,
            "counted_mock_image_id": "sha256:" + "9" * 64,
            "model": "gpt-5.4",
            "scan_limit_bytes": 16384,
            "sandbox_adapter_sha256": "a" * 64,
            "sandbox_adapter_config_sha256": "b" * 64,
            "docker_sandbox_sha256": "c" * 64,
            "network_binding": dict(FIXED_NETWORK_BINDING),
            "phase_protocol": dict(FIXED_PHASE_PROTOCOL),
            "production_accessed": False,
            "real_provider_contacted": False,
        }
        namespace = ledger_namespace(corpus["bundle_sha256"])
        development = development_evidence(
            tag_object_sha=candidate["tag_object_sha"],
            commit=candidate["commit"],
            tree=candidate["tree"],
            classifier_version=candidate["classifier_policy_version"],
            classifier_sha256=candidate["classifier_policy_sha256"],
            ruleset_version=candidate["ruleset_version"],
            ruleset_sha256=candidate["ruleset_sha256"],
        )
        metrics = self.metrics()
        counted_mock = derive_counted_mock(metrics, execution)
        payload = {
            "schema": EVALUATION_SCHEMA,
            "state": "PASS",
            "candidate": candidate,
            "evaluator": evaluator,
            "corpus": corpus,
            "execution": execution,
            "ledger": {
                "repository": "example/cyber-abuse-guard",
                "namespace": namespace,
                "reserved_ref": ledger_ref(namespace, "reserved"),
                "started_ref": ledger_ref(namespace, "started"),
                "result_ref": ledger_ref(namespace, "result"),
            },
            "development_evidence": development,
            "counted_mock": counted_mock,
            "public_counted_mock": metrics["public_counted_mock"],
            "metrics": metrics,
            "privacy": {
                "raw_prompts_in_result": False,
                "raw_responses_in_result": False,
                "request_bodies_in_logs": False,
                "failure_identifier_policy": "challenge_hmac_sha256_case_id_only",
            },
        }
        envelope = signed_envelope(payload, self.private, evaluator["key_id"])
        evaluation_digest = sha256_bytes(canonical_bytes(envelope))
        refs = {}
        for index, event in enumerate(("reserved", "started", "result"), start=1):
            event_payload = {
                "schema": LEDGER_EVENT_SCHEMA,
                "event": event,
                "repository": payload["ledger"]["repository"],
                "namespace": namespace,
                "candidate": candidate,
                "evaluator": evaluator,
                "corpus": corpus,
                "execution": execution,
                "development_evidence": development,
                "counted_mock": counted_mock if event == "result" else None,
                "public_counted_mock": (
                    metrics["public_counted_mock"] if event == "result" else None
                ),
                "evaluation_envelope_sha256": evaluation_digest if event == "result" else None,
            }
            event_envelope = signed_envelope(event_payload, self.private, evaluator["key_id"])
            refs[event] = {
                "ref": ledger_ref(namespace, event),
                "tag_object_sha": f"{index}" * 40,
                "message_sha256": sha256_bytes(canonical_bytes(event_envelope)),
                "envelope": event_envelope,
            }
        proof = {
            "schema": LEDGER_PROOF_SCHEMA,
            "repository": payload["ledger"]["repository"],
            "namespace": namespace,
            "refs": refs,
            "aborted_ref_absent": True,
        }
        return envelope, payload, proof

    def test_stale_cpa_v72102_candidate_identity_is_rejected(self) -> None:
        _envelope, payload, _proof = self.fixture()
        payload["candidate"]["cpa_version"] = "v7.2.102"
        payload["candidate"]["cpa_commit"] = (
            "8423cce2d1004e80948a9e2c60ee69354c0aabc3"
        )
        with self.assertRaisesRegex(ContractError, "candidate CPA version"):
            validate_evaluation_payload(payload)

    def test_synthetic_stale_cpa_candidate_identity_is_rejected(self) -> None:
        _envelope, payload, _proof = self.fixture()
        payload["candidate"]["cpa_version"] = "v0.0.0-stale-sentinel"
        payload["candidate"]["cpa_commit"] = "0" * 40
        with self.assertRaisesRegex(ContractError, "candidate CPA version"):
            validate_evaluation_payload(payload)

    def test_signed_evaluation_and_result_ledger_binding_pass(self) -> None:
        envelope, payload, proof = self.fixture()
        verified = verify_signed_envelope(
            envelope,
            self.public,
            payload["evaluator"]["key_id"],
            expected_payload_schema=EVALUATION_SCHEMA,
        )
        validate_evaluation_payload(verified)
        remote = {
            entry["ref"]: (
                entry["tag_object_sha"],
                canonical_bytes(entry["envelope"]).decode("utf-8"),
            )
            for entry in proof["refs"].values()
        }
        validate_ledger_proof(
            proof,
            envelope,
            verified,
            self.public,
            payload["evaluator"]["key_id"],
            remote_loader=lambda _repository, ref: remote[ref],
        )

    def test_public_transport_and_cpa_decisions_merge_without_trusting_cross_domain_counts(self) -> None:
        transport = public_counted_mock_transport(hard_policy_blocked=7)
        decisions = public_decision_audit()
        validate_public_counted_mock_transport(transport)
        validate_public_decision_audit(decisions)
        merged = merge_public_counted_mock(transport, decisions)
        self.assertEqual(merged["total"]["serialized_executions"], 120)
        self.assertEqual(merged["total"]["local_blocked"], 80)
        self.assertEqual(merged["total"]["upstream_delta"], 40)
        self.assertEqual(merged["total"]["usage_delta"], 40)
        self.assertEqual(merged["total"]["hard_policy_blocked"], 7)
        self.assertEqual(
            merged["total"]["decision_kind_counts"]["audit_eligible_malicious_text"],
            40,
        )
        self.assertEqual(
            merged["total"]["decision_kind_counts"]["block_malicious_text"],
            80,
        )

        drifted_decisions = copy.deepcopy(decisions)
        drifted_decisions["families"]["branch_head"]["corpus_role"] = (
            "historical_default_payload"
        )
        with self.assertRaisesRegex(ContractError, "corpus role"):
            merge_public_counted_mock(transport, drifted_decisions)

        drifted_transport = copy.deepcopy(transport)
        drifted_transport["families"]["branch_head"]["upstream_delta"] += 1
        with self.assertRaisesRegex(ContractError, "accounting|frozen"):
            merge_public_counted_mock(drifted_transport, decisions)

    def test_pinned_openssl_subprocess_receives_no_ambient_environment(self) -> None:
        environments: list[dict[str, str]] = []

        def fake_run(command: list[str], **kwargs: object) -> SimpleNamespace:
            environments.append(dict(kwargs["env"]))
            if "-sign" in command:
                output = Path(command[command.index("-out") + 1])
                output.write_bytes(b"s" * 64)
            return SimpleNamespace(returncode=0)

        with mock.patch("round9_eval_core.subprocess.run", side_effect=fake_run):
            signature = openssl_sign(b"payload", self.private, "/usr/bin/openssl")
            openssl_verify(
                b"payload", signature, self.public, "/usr/bin/openssl"
            )
        self.assertEqual(len(environments), 2)
        for environment in environments:
            self.assertEqual(
                environment,
                {
                    "PATH": "/usr/bin:/bin",
                    "HOME": "/nonexistent",
                    "LANG": "C.UTF-8",
                    "LC_ALL": "C.UTF-8",
                    "TZ": "UTC",
                },
            )

    def test_result_ledger_must_bind_exact_signed_envelope(self) -> None:
        envelope, payload, proof = self.fixture()
        proof["refs"]["result"]["envelope"]["payload"]["evaluation_envelope_sha256"] = "f" * 64
        replacement = signed_envelope(
            proof["refs"]["result"]["envelope"]["payload"],
            self.private,
            payload["evaluator"]["key_id"],
        )
        proof["refs"]["result"]["envelope"] = replacement
        proof["refs"]["result"]["message_sha256"] = hashlib.sha256(
            canonical_bytes(replacement)
        ).hexdigest()
        with self.assertRaisesRegex(ContractError, "exact evaluation envelope"):
            validate_ledger_proof(
                proof,
                envelope,
                payload,
                self.public,
                payload["evaluator"]["key_id"],
            )

    def test_metric_aggregate_cannot_disagree_with_categories(self) -> None:
        metrics = self.metrics()
        metrics["malicious"]["per_category"]["malicious_category_00"]["blocked"] = 9
        metrics["malicious"]["per_category"]["malicious_category_00"]["recall_basis_points"] = 9000
        with self.assertRaisesRegex(ContractError, "recall floor|totals"):
            validate_metrics(metrics)

    def test_route_semantic_and_decision_histograms_are_mechanically_bound(self) -> None:
        mutations = (
            (
                lambda value: value["route_histogram"]["benign"][
                    "audit|openai_chat|stream"
                ].__setitem__("upstream_delta", 599),
                "route histogram|counted-Mock",
            ),
            (
                lambda value: (
                    value["malicious"]["enforcement_blocks_per_semantic_sample"].__setitem__(
                        "8", 89
                    ),
                    value["malicious"]["enforcement_blocks_per_semantic_sample"].__setitem__(
                        "7", 1
                    ),
                ),
                "semantic recall",
            ),
            (
                lambda value: value["decision_audit"]["decision_kind_counts"].__setitem__(
                    "block_malicious_text", 719
                ),
                "decision audit|decision/runtime evidence",
            ),
            (
                lambda value: value["runtime_checks"]["audit_database"].__setitem__(
                    "evaluation_event_delta", 1082
                ),
                "decision/runtime evidence|runtime counters",
            ),
        )
        for mutate, message in mutations:
            with self.subTest(message=message):
                metrics = self.metrics()
                mutate(metrics)
                with self.assertRaisesRegex(ContractError, message):
                    validate_metrics(metrics)

    def test_optional_benign_persistence_binds_without_requiring_clean_rows(self) -> None:
        metrics = self.metrics()
        audit = metrics["decision_audit"]
        audit["matched_count"] += 1
        audit["optional_persisted_count"] = 1
        audit["optional_missing_count"] -= 1
        audit["decision_kind_counts"]["audit_ineligible_risk"] += 1
        audit["group_counts"]["benign"] = 1
        metrics["runtime_checks"]["audit_database"]["evaluation_event_delta"] += 1
        validate_metrics(metrics)

        audit["optional_missing_count"] -= 1
        with self.assertRaisesRegex(ContractError, "required/optional persistence counts"):
            validate_metrics(metrics)

    def test_public_metrics_require_execution_scoped_incomplete_hmac(self) -> None:
        metrics = self.metrics()
        metrics["incomplete"]["request_sha256"] = metrics["incomplete"].pop(
            "request_hmac_sha256"
        )
        with self.assertRaisesRegex(ContractError, "keys are not exact"):
            validate_metrics(metrics)

    def test_fixed_network_and_sequential_phase_contract_cannot_drift(self) -> None:
        _envelope, payload, _proof = self.fixture()
        for key, value in (
            ("host_port", 18395),
            ("container_port", 8318),
            ("host_ip", "0.0.0.0"),
        ):
            changed = dict(payload["execution"]["network_binding"])
            changed[key] = value
            payload["execution"]["network_binding"] = changed
            with self.assertRaisesRegex(ContractError, "network binding"):
                validate_evaluation_payload(payload)
            payload["execution"]["network_binding"] = dict(FIXED_NETWORK_BINDING)
        for phases in (["balanced", "strict"], ["strict", "balanced", "audit"]):
            payload["metrics"]["route_order"]["phase_order"] = phases
            with self.assertRaisesRegex(ContractError, "Audit, Balanced, then Strict"):
                validate_evaluation_payload(payload)
            payload["metrics"]["route_order"]["phase_order"] = [
                "audit",
                "balanced",
                "strict",
            ]

    def test_runtime_and_authenticated_phase_evidence_fail_closed(self) -> None:
        for path, value, message in (
            (("route_order", "mode_switch_authenticated"), False, "authenticated"),
            (("route_order", "mode_status_verified", "audit"), False, "status verified"),
            (("runtime_checks", "state"), "NOT_PROVIDED", "runtime checks state"),
            (("runtime_checks", "audit_database", "quick_check"), "failed", "quick_check"),
            (("runtime_checks", "audit_database", "wal_checkpoint_passed"), False, "WAL"),
            (("runtime_checks", "restart_recovery", "observed"), False, "restart observed"),
            (("runtime_checks", "restart_recovery", "controlled_restart_count"), 0, "exactly one"),
            (("runtime_checks", "panic_recovery", "probe_passed"), False, "panic recovery probe"),
            (("runtime_checks", "panic_recovery", "panic_count"), 1, "non-zero panic_count"),
            (("runtime_checks", "usage_queue", "allowed_request_delta"), 0, "exactly one usage"),
            (("runtime_checks", "usage_queue", "blocked_request_delta"), 1, "blocked runtime probe"),
            (("runtime_checks", "raw_capture", "default_disabled"), False, "Raw Capture"),
            (("runtime_checks", "raw_capture", "normal_request_records"), 1, "Raw Capture record"),
            (("runtime_checks", "raw_capture", "normal_request_plaintext_persisted"), True, "plaintext"),
            (("runtime_checks", "lifecycle", "oom_killed"), True, "OOM"),
            (("runtime_checks", "lifecycle", "exit_code"), 1, "not clean"),
            (("runtime_checks", "lifecycle", "unexpected_restart_count"), 1, "unexpected restart"),
        ):
            metrics = self.metrics()
            target = metrics
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = value
            with self.subTest(path=path), self.assertRaisesRegex(ContractError, message):
                validate_metrics(metrics)

    def test_development_evidence_and_counted_mock_are_closed_bindings(self) -> None:
        _envelope, payload, _proof = self.fixture()
        validate_development_evidence(
            payload["development_evidence"], expected_candidate=payload["candidate"]
        )
        paired_95 = copy.deepcopy(payload["development_evidence"])
        paired = paired_95["corpus"]["paired_malicious"]
        paired["semantic_blocked"] = 114
        paired["recall_basis_points"] = 9_500
        for category in paired["per_category"].values():
            category["blocked"] = 57
            category["recall_basis_points"] = 9_500
        with self.assertRaisesRegex(ContractError, "frozen recall contract"):
            validate_development_evidence(
                paired_95, expected_candidate=payload["candidate"]
            )
        validate_counted_mock(payload["counted_mock"], payload["metrics"], payload["execution"])
        changed = dict(payload["development_evidence"])
        changed.pop("producer_logs")
        payload["development_evidence"] = changed
        with self.assertRaisesRegex(ContractError, "keys are not exact"):
            validate_evaluation_payload(payload)

        _envelope, payload, _proof = self.fixture()
        payload["counted_mock"] = {
            "schema": "round9-external-counted-mock/v1",
            "state": "PASS",
        }
        with self.assertRaisesRegex(ContractError, "keys are not exact"):
            validate_evaluation_payload(payload)

        _envelope, payload, _proof = self.fixture()
        payload["counted_mock"]["host_results"]["benign"]["upstream_delta"] -= 1
        with self.assertRaisesRegex(ContractError, "mechanical"):
            validate_evaluation_payload(payload)

        _envelope, payload, _proof = self.fixture()
        payload["counted_mock"]["host_results"]["runtime_checks"]["state"] = (
            "NOT_PROVIDED"
        )
        with self.assertRaisesRegex(ContractError, "mechanical"):
            validate_evaluation_payload(payload)


if __name__ == "__main__":
    unittest.main()
