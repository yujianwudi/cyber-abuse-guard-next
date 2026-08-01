#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


SOURCE = Path(__file__).with_name("round9_host_evidence_contract.py")
SPEC = importlib.util.spec_from_file_location("round9_host_evidence_contract", SOURCE)
assert SPEC and SPEC.loader
contract = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(contract)


H40 = "1" * 40
TREE = "2" * 40
H64 = "3" * 64
CHALLENGE = "d" * 64


def canonical(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode()


class Round9HostEvidenceContractTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.so = self.root / "cyber-abuse-guard-v0.16-rc.4.so"
        self.so.write_bytes(b"round9-so")
        self.policy = self.root / "policy_identity.go"
        self.policy.write_text(
            'package classifier\n\nconst ClassifierPolicyVersion = "classifier-policy-v10"\n'
            f'const ClassifierPolicySHA256 = "{H64}"\n',
            encoding="utf-8",
        )
        self.rules = self.root / "ruleset-manifest.json"
        self.rules.write_bytes(
            canonical(
                {
                    "schema_version": 1,
                    "plugin_version": "0.16-rc.4",
                    "ruleset_version": "1.0.10",
                    "ruleset_sha256": "4" * 64,
                    "files": [],
                }
            )
        )
        self.rules_sidecar = self.root / "ruleset.sha256"
        self.write_sidecar(self.rules, self.rules_sidecar)
        self.probe = self.root / "round9-counted-mock-evidence.json"
        self.probe.write_bytes(canonical(self.probe_evidence()))
        self.probe_sidecar = self.root / "round9-counted-mock-evidence.json.sha256"
        self.write_sidecar(self.probe, self.probe_sidecar)

        self.development = self.root / "development-benign.json"
        self.development.write_bytes(canonical(self.benign_report("development")))
        self.independent = self.root / "independent-benign.json"
        self.independent.write_bytes(canonical(self.benign_report("independent")))
        self.malicious = self.root / "independent-malicious.json"
        self.malicious.write_bytes(canonical(self.malicious_report()))
        self.paired_log = self.root / "paired-malicious.log"
        self.paired_log.write_bytes(b'{"paired":"producer-log"}\n')
        self.paired_report_path = self.root / "paired-malicious.json"
        self.paired_report_path.write_bytes(canonical(self.paired_report()))

        self.public_log = self.root / "public.log"
        self.public_log.write_bytes(b"round9 public corpus PASS\n")
        self.public = self.root / "public.json"
        self.public.write_bytes(canonical(self.public_report()))
        self.audit_log = self.root / "audit.log"
        self.audit_log.write_bytes(b"ok audit\nok plugin\n")
        self.audit = self.root / "audit.json"
        self.audit.write_bytes(canonical(self.audit_report()))
        self.host_smoke = self.root / "round8-host-smoke.json"
        self.host_smoke.write_bytes(
            canonical(
                {
                    "schema": "round8-balanced-readmission/v1",
                    "pairs": [{"family": f"f{index:02d}"} for index in range(42)],
                }
            )
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def write_sidecar(target: Path, sidecar: Path) -> None:
        digest = hashlib.sha256(target.read_bytes()).hexdigest()
        sidecar.write_text(f"{digest}  {target.name}\n", encoding="utf-8", newline="\n")

    @staticmethod
    def file_identity(byte: str) -> dict[str, object]:
        return {"bytes": 100, "sha256": byte * 64}

    @staticmethod
    def candidate() -> dict[str, str]:
        return {
            "commit": H40,
            "tree": TREE,
            "policy_version": "classifier-policy-v10",
            "policy_sha256": H64,
            "ruleset": "1.0.10",
        }

    def one_shot(
        self, corpus: str, manifest: dict[str, object], cases: dict[str, object]
    ) -> dict[str, object]:
        return {
            "schema": "round9-independent-one-shot-reservation/v1",
            "corpus": corpus,
            "candidate": self.candidate(),
            "corpus_manifest": manifest,
            "corpus_cases": cases,
            "workflow_run_id": 10,
            "run_attempt": 1,
            "challenge_sha256": hashlib.sha256(bytes.fromhex(CHALLENGE)).hexdigest(),
            "state": "reserved_before_candidate_execution",
        }

    @staticmethod
    def host_results() -> dict[str, object]:
        return {
            "network_binding": {
                "host_ip": contract.CPA_HOST_IP,
                "host_port": contract.CPA_HOST_PORT,
                "container_port": contract.CPA_CONTAINER_PORT,
            },
            "protocol_requests": {
                "chat_benign_upstream": 1,
                "chat_malicious_upstream": 0,
                "responses_benign_upstream": 1,
                "responses_malicious_upstream": 0,
            },
            "matrix": {
                "benign_total": 42,
                "benign_passed": 42,
                "host_smoke_malicious_total": 42,
                "host_smoke_malicious_blocked": 42,
            },
            "transports": {"nonstream_passed": True, "stream_passed": True},
            "modes": {"audit_passed": True, "balanced_passed": True, "strict_passed": True},
            "policy_outcomes": {
                "balanced_incomplete_allow": True,
                "strict_incomplete_block": True,
                "usage_queue_allow_delta": 1,
                "usage_queue_blocked_zero": True,
            },
            "database": {
                "quick_check": "ok",
                "schema_version": 6,
                "migration_versions": [1, 2, 3, 4, 5, 6],
                "wal_checkpoint_passed": True,
            },
            "raw_capture": {
                "only_blocked_passed": True,
                "ttl_dedup_passed": True,
                "schema_v4_redaction_metadata_passed": True,
                "purge_wal_passed": True,
            },
            "lifecycle": {
                "restart_cycle_passed": True,
                "unexpected_restart_count": 0,
                "oom": False,
                "panic_count": 0,
                "fatal_count": 0,
                "plugin_error_count": 0,
            },
        }

    def probe_evidence(self) -> dict[str, object]:
        so_sha = hashlib.sha256(b"round9-so").hexdigest()
        return {
            "schema_version": 2,
            "validation_scope": "CPA_HOST_COUNTED_MOCK_ONLY",
            "candidate": {
                "tag": contract.TAG,
                "commit": H40,
                "tree": TREE,
                "platform": "linux/amd64",
                "so_name": f"cyber-abuse-guard-{contract.TAG}.so",
                "so_sha256": so_sha,
            },
            "cpa": {
                "primary": {
                    "version": "v7.2.109",
                    "commit": contract.CPA_COMMIT,
                    "image_id": "sha256:" + "5" * 64,
                    "build_date": "2026-07-23T00:00:00Z",
                    "counted_mock_validation": "PASS",
                    "host_results": self.host_results(),
                }
            },
            "mock": {
                "contract": "round9-counted-mock/v1",
                "source": f"https://github.com/{contract.REPOSITORY}",
                "revision": H40,
                "tag": contract.TAG,
                "tree": TREE,
                "image_id": "sha256:" + "0" * 64,
            },
            "safety": {
                "real_provider_contacted": False,
                "production_accessed": False,
                "unexpected_restart_count": 0,
                "oom": False,
                "panic_count": 0,
                "fatal_count": 0,
                "plugin_error_count": 0,
            },
            "execution": {
                "trust": "GITHUB_ATTESTED_ROUND9_HOST_WORKFLOW",
                "challenge": CHALLENGE,
                "execution_id": "019f7cb0-1f9e-7ff0-8ed2-111111111111",
                "started_at": "2026-07-23T00:00:00Z",
                "completed_at": "2026-07-23T00:01:00Z",
                "workflow": {
                    "repository": contract.REPOSITORY,
                    "path": contract.HOST_WORKFLOW,
                    "ref": f"refs/tags/{contract.TAG}",
                    "sha": H40,
                    "run_id": 10,
                    "run_attempt": 1,
                },
                "phase1": {
                    "workflow_path": contract.RELEASE_WORKFLOW,
                    "run_id": 11,
                    "run_attempt": 1,
                    "artifact_id": 12,
                    "artifact_digest": "sha256:" + "e" * 64,
                },
                "runner": {
                    "name": "round9-test-runner",
                    "environment": "self-hosted",
                    "os": "Linux",
                    "arch": "X64",
                },
                "sandbox": {
                    "sandbox_id": "round9-sandbox",
                    "daemon_id": "round9-daemon",
                    "daemon_label": "io.cyber-abuse-guard.round9-sandbox=round9-sandbox",
                    "production_label": "io.cyber-abuse-guard.production=false",
                    "probe_image_id": "sha256:" + "7" * 64,
                    "locality_challenge": "PASS",
                },
            },
        }

    def benign_report(self, profile: str) -> dict[str, object]:
        unique = 1200 if profile == "development" else 600
        routes = unique * 6
        categories = {f"category_{index:02d}": unique // 15 for index in range(15)}
        manifest = self.file_identity("8")
        cases = self.file_identity("9")
        candidate = self.candidate()
        if profile == "development":
            candidate = dict(candidate, commit="", tree="")
        report: dict[str, object] = {
            "schema": "round9-benign-corpus-report/v1",
            "profile": profile,
            "corpus": f"round9-{profile}-benign-v1",
            "corpus_manifest_bytes": manifest["bytes"],
            "corpus_manifest_sha256": manifest["sha256"],
            "corpus_cases_bytes": cases["bytes"],
            "corpus_cases_sha256": cases["sha256"],
            "candidate": candidate,
            "runtime": "go1.26.4",
            "platform": "linux/amd64",
            "metrics": {
                "schema": "round9-route-executions/v1",
                "unique_semantic_samples": unique,
                "serialized_route_executions": routes,
                "blocked_executions": 0,
                "audit_executions": routes,
                "allow_executions": 0,
                "category_counts": categories,
                "language_counts": {"zh": unique // 2, "en": unique // 2},
                "protocol_counts": {"openai_chat": routes // 2, "openai_responses": routes // 2},
                "stream_counts": {"false": routes // 2, "true": routes // 2},
                "carrier_counts": {"current_user_direct": routes},
                "mode_counts": {"balanced": routes},
            },
            "observed_benign_blocks": 0,
            "wilson_95_upper_percent": 0.0,
            "claim_boundary": "development evidence",
        }
        if profile == "independent":
            report["one_shot"] = self.one_shot(
                "round9-independent-benign-v1", manifest, cases
            )
        return report

    def malicious_report(self) -> dict[str, object]:
        manifest = self.file_identity("a")
        cases = self.file_identity("b")
        categories = {f"category_{index:02d}": 10 for index in range(9)}
        per_category = {
            name: {
                "semantic_samples": 10,
                "semantic_blocked": 10,
                "route_executions": 80,
                "passed_route_executions": 80,
                "recall_percent": 100.0,
                "wilson_95_lower_percent": 72.2,
                "wilson_95_upper_percent": 100.0,
            }
            for name in categories
        }
        return {
            "schema": "round9-independent-malicious-report/v1",
            "corpus": "round9-independent-malicious-v1",
            "corpus_manifest": manifest,
            "corpus_cases": cases,
            "candidate": self.candidate(),
            "one_shot": self.one_shot(
                "round9-independent-malicious-v1", manifest, cases
            ),
            "runtime": "go1.26.4",
            "platform": "linux/amd64",
            "metrics": {
                "schema": "round9-malicious-route-executions/v1",
                "unique_semantic_samples": 90,
                "semantic_blocked": 90,
                "serialized_route_executions": 720,
                "passed_route_executions": 720,
                "category_counts": categories,
                "language_counts": {"zh": 45, "en": 45},
                "protocol_counts": {"openai_chat": 360, "openai_responses": 360},
                "stream_counts": {"false": 360, "true": 360},
                "mode_counts": {"balanced": 360, "strict": 360},
                "per_category": per_category,
                "failures": [],
            },
            "recall_percent": 100.0,
            "wilson_95_lower_percent": 95.9,
            "wilson_95_upper_percent": 100.0,
            "claim_boundary": "independent development evidence",
        }

    def paired_report(
        self,
        *,
        source_version: int = 3,
        corpus_version: int = 3,
        blocked_by_category: dict[str, int] | None = None,
    ) -> dict[str, object]:
        category_samples = {"credential_theft": 60, "phishing_deployment": 60}
        if blocked_by_category is None:
            blocked_by_category = {name: count for name, count in category_samples.items()}
        per_category: dict[str, dict[str, int]] = {}
        total_blocked = 0
        for name, samples in category_samples.items():
            blocked = blocked_by_category[name]
            lower, upper = contract.wilson_interval(blocked, samples)
            per_category[name] = {
                "samples": samples,
                "blocked": blocked,
                "recall_basis_points": blocked * 10000 // samples,
                "wilson_lower_bound_basis_points": round(lower * 10000),
                "wilson_upper_bound_basis_points": round(upper * 10000),
            }
            total_blocked += blocked
        samples = sum(category_samples.values())
        lower, upper = contract.wilson_interval(total_blocked, samples)
        return {
            "schema": "round9-development-paired-malicious-machine-report/v1",
            "source_report_schema": (
                f"round9-development-paired-malicious-report/v{source_version}"
            ),
            "corpus": f"round9-development-paired-malicious-v{corpus_version}",
            "corpus_manifest_version": 2,
            "corpus_manifest": self.file_identity("c"),
            "corpus_cases": self.file_identity("d"),
            "corpus_label_audit": {"bytes": 600, "sha256": "e" * 64},
            "benign_corpus_manifest": self.file_identity("8"),
            "benign_corpus_cases": self.file_identity("9"),
            "candidate": self.candidate(),
            "runtime": "go1.26.4",
            "platform": "linux/amd64",
            "metrics": {
                "unique_semantic_samples": samples,
                "semantic_blocked": total_blocked,
                "serialized_route_executions": samples * 8,
                "passed_route_executions": samples * 8,
                "recall_basis_points": total_blocked * 10000 // samples,
                "wilson_lower_bound_basis_points": round(lower * 10000),
                "wilson_upper_bound_basis_points": round(upper * 10000),
                "per_category": per_category,
            },
            "producer_log": self.binding(self.paired_log),
            "claim_boundary": "visible paired development evidence",
        }

    @staticmethod
    def binding(path: Path) -> dict[str, object]:
        raw = path.read_bytes()
        return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}

    def public_report(self) -> dict[str, object]:
        return {
            "schema": contract.PUBLIC_DEVELOPMENT_REPORT_SCHEMA,
            "candidate": self.candidate(),
            "manifest": dict(contract.PUBLIC_DEVELOPMENT_MANIFEST),
            "producer_log": self.binding(self.public_log),
            "metrics": dict(contract.PUBLIC_DEVELOPMENT_METRICS),
            "claim_boundary": "public development regression",
        }

    def audit_report(self) -> dict[str, object]:
        return {
            "schema": "round9-audit-contract-report/v1",
            "candidate": self.candidate(),
            "producer_log": self.binding(self.audit_log),
            "contract": {
                "decision_kinds": [
                    "allow_clean",
                    "audit_eligible_malicious_text",
                    "audit_ineligible_risk",
                    "block_incomplete_inspection",
                    "block_malicious_text",
                    "block_opaque_media",
                    "block_subject_risk",
                ],
                "malicious_block_requires_eligible_winner": True,
                "incomplete_has_no_malicious_winner": True,
            },
            "claim_boundary": "machine audit contract",
        }

    def assemble_args(self):
        output = self.root / "round9-host-evidence.json"
        sidecar = self.root / "round9-host-evidence.json.sha256"
        return contract.parser().parse_args(
            [
                "assemble",
                "--probe-evidence", str(self.probe),
                "--probe-sidecar", str(self.probe_sidecar),
                "--development-benign-report", str(self.development),
                "--independent-benign-report", str(self.independent),
                "--paired-malicious-report", str(self.paired_report_path),
                "--paired-malicious-log", str(self.paired_log),
                "--independent-malicious-report", str(self.malicious),
                "--public-adversarial-report", str(self.public),
                "--public-adversarial-log", str(self.public_log),
                "--audit-report", str(self.audit),
                "--audit-log", str(self.audit_log),
                "--host-smoke-corpus", str(self.host_smoke),
                "--candidate-so", str(self.so),
                "--policy-source", str(self.policy),
                "--ruleset-manifest", str(self.rules),
                "--ruleset-sidecar", str(self.rules_sidecar),
                "--output", str(output),
                "--sidecar", str(sidecar),
                "--tag", contract.TAG,
                "--commit", H40,
                "--tree", TREE,
                "--challenge", CHALLENGE,
                "--workflow-path", contract.HOST_WORKFLOW,
                "--workflow-ref", f"refs/tags/{contract.TAG}",
                "--release-workflow-path", contract.RELEASE_WORKFLOW,
                "--phase1-artifact-digest", "sha256:" + "e" * 64,
                "--workflow-run-id", "10",
                "--workflow-run-attempt", "1",
                "--phase1-run-id", "11",
                "--phase1-run-attempt", "1",
                "--phase1-artifact-id", "12",
            ]
        )

    def rewrite(self, path: Path, value: dict[str, object]) -> None:
        path.write_bytes(canonical(value))

    def test_round9_envelope_assembles_and_validates(self):
        args = self.assemble_args()
        contract.assemble(args)
        assembled = json.loads(args.output.read_text(encoding="utf-8"))
        self.assertEqual(assembled["validation_scope"], contract.VALIDATION_SCOPE)
        check = contract.parser().parse_args(
            [
                "validate",
                "--evidence", str(args.output),
                "--sidecar", str(args.sidecar),
                "--candidate-so", str(self.so),
                "--tag", contract.TAG,
                "--commit", H40,
                "--tree", TREE,
            ]
        )
        contract.validate(check)

    def test_stale_cpa_validation_scope_is_rejected(self):
        args = self.assemble_args()
        contract.assemble(args)
        assembled = json.loads(args.output.read_text(encoding="utf-8"))
        assembled["validation_scope"] = (
            "CPA_V7_2_95_COUNTED_MOCK_AND_FROZEN_CORPUS_ADMISSION"
        )
        with self.assertRaisesRegex(contract.ContractError, "scope is invalid"):
            contract.validate_evidence(assembled, args)

    def test_round8_evidence_cannot_masquerade_as_round9(self):
        value = self.probe_evidence()
        value["candidate"]["tag"] = "v0.16-rc.2"
        value["mock"]["contract"] = "round8-counted-mock/v1"
        value["execution"]["trust"] = "GITHUB_ATTESTED_ROUND8_HOST_WORKFLOW"
        self.probe.write_bytes(canonical(value))
        self.write_sidecar(self.probe, self.probe_sidecar)
        with self.assertRaisesRegex(contract.ContractError, "Round 9"):
            contract.assemble(self.assemble_args())

    def test_schema_v5_raw_capture_v3_machine_evidence_is_rejected(self):
        value = self.probe_evidence()
        value["cpa"]["primary"]["host_results"]["database"]["schema_version"] = 5
        value["cpa"]["primary"]["host_results"]["raw_capture"]["schema_v4_redaction_metadata_passed"] = False
        self.probe.write_bytes(canonical(value))
        self.write_sidecar(self.probe, self.probe_sidecar)
        with self.assertRaisesRegex(contract.ContractError, "schema v6"):
            contract.assemble(self.assemble_args())

    def test_non_contract_cpa_host_port_is_rejected(self):
        value = self.probe_evidence()
        value["cpa"]["primary"]["host_results"]["network_binding"][
            "host_port"
        ] = contract.CPA_HOST_PORT + 1
        self.probe.write_bytes(canonical(value))
        self.write_sidecar(self.probe, self.probe_sidecar)
        with self.assertRaisesRegex(contract.ContractError, "127.0.0.1:18394"):
            contract.assemble(self.assemble_args())

    def test_any_benign_block_is_a_whole_gate_failure(self):
        value = self.benign_report("independent")
        value["metrics"]["blocked_executions"] = 1
        value["metrics"]["audit_executions"] -= 1
        value["observed_benign_blocks"] = 1
        self.rewrite(self.independent, value)
        with self.assertRaisesRegex(contract.ContractError, "normal request block"):
            contract.assemble(self.assemble_args())

    def test_benign_stream_counts_use_closed_boolean_keys(self):
        value = self.benign_report("independent")
        value["metrics"]["stream_counts"] = {"false": 1800, "stream": 1800}
        self.rewrite(self.independent, value)
        with self.assertRaisesRegex(contract.ContractError, "distribution accounting"):
            contract.assemble(self.assemble_args())

    def test_independent_malicious_stream_counts_are_route_bound(self):
        value = self.malicious_report()
        value["metrics"]["stream_counts"]["true"] -= 1
        self.rewrite(self.malicious, value)
        with self.assertRaisesRegex(contract.ContractError, "distribution accounting"):
            contract.assemble(self.assemble_args())

    def test_candidate_policy_hash_drift_is_rejected(self):
        value = self.malicious_report()
        value["candidate"]["policy_sha256"] = "f" * 64
        self.rewrite(self.malicious, value)
        with self.assertRaisesRegex(contract.ContractError, "candidate identity"):
            contract.assemble(self.assemble_args())

    def test_candidate_policy_version_lookalike_is_rejected(self):
        self.policy.write_text(
            'package classifier\n\n'
            'const ClassifierPolicyVersion = "classifier-policy-v10-lookalike"\n'
            f'const ClassifierPolicySHA256 = "{H64}"\n',
            encoding="utf-8",
        )
        with self.assertRaisesRegex(contract.ContractError, "exact classifier-policy-v10"):
            contract.assemble(self.assemble_args())

    def test_paired_v2_identity_is_rejected(self):
        self.rewrite(
            self.paired_report_path,
            self.paired_report(source_version=2, corpus_version=2),
        )
        with self.assertRaisesRegex(contract.ContractError, "identity|v3-or-newer"):
            contract.assemble(self.assemble_args())

    def test_paired_schema_and_corpus_versions_must_match(self):
        self.rewrite(
            self.paired_report_path,
            self.paired_report(source_version=3, corpus_version=4),
        )
        with self.assertRaisesRegex(contract.ContractError, "identity|v3-or-newer"):
            contract.assemble(self.assemble_args())

    def test_paired_manifest_v1_is_rejected(self):
        value = self.paired_report()
        value["corpus_manifest_version"] = 1
        self.rewrite(self.paired_report_path, value)
        with self.assertRaisesRegex(contract.ContractError, "manifest version 2"):
            contract.assemble(self.assemble_args())

    def test_paired_label_audit_identity_is_required(self):
        value = self.paired_report()
        value["corpus_label_audit"]["bytes"] = 511
        self.rewrite(self.paired_report_path, value)
        with self.assertRaisesRegex(contract.ContractError, "label-audit"):
            contract.assemble(self.assemble_args())

    def test_paired_log_hash_drift_is_rejected(self):
        self.paired_log.write_bytes(b'{"paired":"drifted"}\n')
        with self.assertRaisesRegex(contract.ContractError, "producer log"):
            contract.assemble(self.assemble_args())

    def test_public_pre_v13_report_and_count_drift_are_rejected(self):
        value = self.public_report()
        value["schema"] = "round9-public-adversarial-report/v9"
        self.rewrite(self.public, value)
        with self.assertRaisesRegex(contract.ContractError, "schema"):
            contract.assemble(self.assemble_args())

        value = self.public_report()
        value["manifest"]["sha256"] = "f" * 64
        self.rewrite(self.public, value)
        with self.assertRaisesRegex(contract.ContractError, "frozen v13 manifest"):
            contract.assemble(self.assemble_args())

        value = self.public_report()
        value["metrics"]["candidate_carriers"] = 2
        value["metrics"]["candidate_executions"] = 2
        value["metrics"]["serialized_route_executions"] = 121
        value["metrics"]["direct_blocked"] = 13
        self.rewrite(self.public, value)
        with self.assertRaisesRegex(contract.ContractError, "frozen v13 contract"):
            contract.assemble(self.assemble_args())

        value = self.public_report()
        value["metrics"]["system_blocked"] = 0
        value["metrics"]["tool_blocked"] = 0
        self.rewrite(self.public, value)
        with self.assertRaisesRegex(contract.ContractError, "frozen v13 contract"):
            contract.assemble(self.assemble_args())

    def test_paired_per_category_wilson_drift_is_rejected(self):
        value = self.paired_report()
        value["metrics"]["per_category"]["credential_theft"][
            "wilson_lower_bound_basis_points"
        ] -= 1
        self.rewrite(self.paired_report_path, value)
        with self.assertRaisesRegex(contract.ContractError, "category evidence"):
            contract.assemble(self.assemble_args())

    def test_paired_benign_baseline_binding_drift_is_rejected(self):
        value = self.paired_report()
        value["benign_corpus_cases"]["sha256"] = "e" * 64
        self.rewrite(self.paired_report_path, value)
        with self.assertRaisesRegex(contract.ContractError, "development benign baseline"):
            contract.assemble(self.assemble_args())

    def test_development_paired_recall_below_100_percent_is_rejected(self):
        self.rewrite(
            self.paired_report_path,
            self.paired_report(
                blocked_by_category={
                    "credential_theft": 57,
                    "phishing_deployment": 57,
                }
            ),
        )
        args = self.assemble_args()
        with self.assertRaisesRegex(contract.ContractError, "paired malicious aggregate"):
            contract.assemble(args)

    def test_independent_malicious_95_percent_threshold_remains_valid(self):
        lower, _ = contract.wilson_interval(19, 20)
        value = {
            "corpus_sha256": "a" * 64,
            "ground_truth_sha256": "b" * 64,
            "samples": 20,
            "eligible_samples": 20,
            "blocked": 19,
            "recall_basis_points": 9500,
            "wilson_lower_bound_basis_points": round(lower * 10000),
        }
        self.assertEqual(
            contract.validate_malicious_section(value, "independent_malicious"),
            value,
        )

    def test_missing_machine_report_is_not_provided(self):
        self.independent.unlink()
        with self.assertRaisesRegex(contract.ContractError, "required JSON"):
            contract.assemble(self.assemble_args())

    def test_operator_contract_json_argument_is_absent(self):
        destinations = {
            action.dest for action in contract.parser()._subparsers._group_actions[0].choices["assemble"]._actions
        }
        self.assertNotIn("contract", destinations)


if __name__ == "__main__":
    unittest.main()
