#!/usr/bin/env python3
from __future__ import annotations

import copy
import importlib.util
import hashlib
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


SOURCE = Path(__file__).with_name("round9_machine_reports.py")
SPEC = importlib.util.spec_from_file_location("round9_machine_reports", SOURCE)
assert SPEC and SPEC.loader
reports = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(reports)
REPOSITORY_ROOT = SOURCE.parent.parent
EVALUATION_CORE_SOURCE = REPOSITORY_ROOT / "tools/round9-eval/round9_eval_core.py"
EVALUATION_CORE_SPEC = importlib.util.spec_from_file_location(
    "round9_eval_core_cross_contract", EVALUATION_CORE_SOURCE
)
assert EVALUATION_CORE_SPEC and EVALUATION_CORE_SPEC.loader
evaluation_core = importlib.util.module_from_spec(EVALUATION_CORE_SPEC)
EVALUATION_CORE_SPEC.loader.exec_module(evaluation_core)


class Round9MachineReportsTest(unittest.TestCase):
    @staticmethod
    def identity(path: Path) -> dict[str, object]:
        raw = path.read_bytes()
        return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}

    @staticmethod
    def git(root: Path, *arguments: str) -> str:
        result = subprocess.run(
            ["git", "-C", str(root), *arguments],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        return result.stdout.strip()

    def development_fixture(
        self, temporary: str, *, annotated: bool = True
    ) -> tuple[Path, Path, SimpleNamespace, dict[str, str]]:
        base = Path(temporary)
        root = base / "repo"
        artifacts = base / "artifacts"
        artifacts.mkdir(parents=True)
        for directory in (
            root / "internal/classifier",
            root / "internal/audit",
            root / "internal/plugin",
            root / "rules",
            root / "testdata/round9-development-benign-v1",
            root / "testdata/round9-development-paired-malicious-v3",
            root / "testdata/round9-public-adversarial-v13",
        ):
            directory.mkdir(parents=True)
        (root / "internal/classifier/policy_identity.go").write_text(
            'package classifier\n\nconst ClassifierPolicyVersion = "classifier-policy-v8"\n'
            f'const ClassifierPolicySHA256 = "{"3" * 64}"\n',
            encoding="utf-8",
        )
        (root / "internal/audit/migrations.go").write_text(
            "package audit\n\nconst currentSchemaVersion = 6\n", encoding="utf-8"
        )
        (root / "internal/plugin/management.go").write_text(
            "package plugin\n\nconst (\n\tmanagementRawCaptureSchema = 4\n)\n",
            encoding="utf-8",
        )
        (root / "rules/manifest.yaml").write_text(
            'version: "1.0.10"\n', encoding="utf-8"
        )
        (root / "rules/semantics.yaml").write_text(
            "rules: []\n", encoding="utf-8"
        )

        benign_root = root / "testdata/round9-development-benign-v1"
        benign_cases = benign_root / "cases.jsonl"
        benign_cases.write_bytes(b'{"id":"benign-001"}\n')
        benign_manifest = {
            "name": "round9-development-benign-v1",
            "version": 1,
            "counts": {"total": 1200},
            "files": {"cases.jsonl": self.identity(benign_cases)},
        }
        (benign_root / "manifest.json").write_text(
            json.dumps(benign_manifest, sort_keys=True, separators=(",", ":")),
            encoding="utf-8",
        )

        paired_root = root / "testdata/round9-development-paired-malicious-v3"
        paired_cases = paired_root / "cases.jsonl"
        paired_cases.write_bytes(b'{"id":"paired-001"}\n')
        label_audit = paired_root / "LABEL_AUDIT.md"
        label_audit.write_text("# frozen label audit\n" + "reviewed before execution\n" * 32, encoding="utf-8")
        paired_manifest = {
            "name": "round9-development-paired-malicious-v3",
            "version": 2,
            "files": {"cases.jsonl": self.identity(paired_cases)},
            "label_audit": self.identity(label_audit),
        }
        (paired_root / "manifest.json").write_text(
            json.dumps(paired_manifest, sort_keys=True, separators=(",", ":")),
            encoding="utf-8",
        )
        shutil.copyfile(
            REPOSITORY_ROOT / "testdata/round9-public-adversarial-v13/manifest.json",
            root / "testdata/round9-public-adversarial-v13/manifest.json",
        )

        self.git(root.parent, "init", "-q", str(root))
        self.git(root, "config", "user.name", "Round 9 Test")
        self.git(root, "config", "user.email", "round9-test@example.invalid")
        self.git(root, "add", ".")
        self.git(root, "commit", "-q", "-m", "fixture")
        commit = self.git(root, "rev-parse", "HEAD")
        tree = self.git(root, "rev-parse", "HEAD^{tree}")
        if annotated:
            self.git(root, "tag", "-a", reports.DEVELOPMENT_TAG, "-m", "fixture tag")
        else:
            self.git(root, "tag", reports.DEVELOPMENT_TAG)
        candidate = {
            "commit": commit,
            "tree": tree,
            "policy_version": "classifier-policy-v8",
            "policy_sha256": "3" * 64,
            "ruleset": "1.0.10",
        }

        development_report = artifacts / "development-benign.json"
        benign_categories = {f"category_{index:02d}": 80 for index in range(15)}
        development_value = {
            "schema": "round9-development-benign-corpus-report/v1",
            "corpus": "round9-development-benign-v1",
            "corpus_manifest_bytes": self.identity(benign_root / "manifest.json")["bytes"],
            "corpus_manifest_sha256": self.identity(benign_root / "manifest.json")["sha256"],
            "corpus_cases_bytes": self.identity(benign_cases)["bytes"],
            "corpus_cases_sha256": self.identity(benign_cases)["sha256"],
            "runtime_identity": {
                "classifier_policy_version": "classifier-policy-v8",
                "classifier_policy_sha256": "3" * 64,
                "ruleset_version": "1.0.10",
            },
            "runtime": reports.DEVELOPMENT_RUNTIME,
            "platform": reports.DEVELOPMENT_PLATFORM,
            "metrics": {
                "schema": "round9-route-executions/v1",
                "unique_semantic_samples": 1200,
                "serialized_route_executions": 7200,
                "blocked_semantic_samples": 0,
                "blocked_executions": 0,
                "audit_executions": 0,
                "allow_executions": 7200,
                "category_counts": benign_categories,
                "language_counts": {"en": 600, "zh": 600},
                "protocol_counts": {"openai_chat": 3600, "openai_responses": 3600},
                "stream_counts": {"false": 3600, "true": 3600},
                "carrier_counts": {"direct": 7200},
                "mode_counts": {"balanced": 3600, "strict": 3600},
                "failures": [],
            },
            "observed_benign_semantic_blocks": 0,
            "observed_benign_route_blocks": 0,
            "wilson_95_upper_percent": 0.319,
            "claim_boundary": "development fixture",
        }
        development_report.write_text(
            json.dumps(development_value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )

        paired_log = artifacts / "paired.log"
        public_log = artifacts / "public.log"
        audit_log = artifacts / "audit.log"
        public_log.write_bytes(
            (
                "round9 public corpus PASS: payload_records=24 formal_unique=23 "
                "candidate_carriers=1 candidate_executions=1 not_provided=0 "
                "scenario_payload_executions=24 serialized_route_executions=120 "
                "direct_block=12 direct_allow=12 quoted_block=0 historical_block=0 "
                "system_block=0 tool_block=0\n"
            ).encode()
        )
        audit_log.write_bytes(b"audit producer log\n")
        paired_categories = {"credential_theft": 60, "phishing_deployment": 60}
        category_lower, category_upper = reports.wilson_interval(60, 60)
        paired_per_category = {
            name: {
                "samples": 60,
                "blocked": 60,
                "recall_basis_points": 10000,
                "wilson_lower_bound_basis_points": round(category_lower * 10000),
                "wilson_upper_bound_basis_points": round(category_upper * 10000),
            }
            for name in paired_categories
        }
        source_per_category = {
            name: {
                "semantic_samples": 60,
                "semantic_blocked": 60,
                "route_executions": 480,
                "passed_route_executions": 480,
                "recall_percent": 100.0,
                "wilson_95_lower_percent": category_lower * 100,
                "wilson_95_upper_percent": category_upper * 100,
            }
            for name in paired_categories
        }
        overall_lower, overall_upper = reports.wilson_interval(120, 120)
        paired_source_value = {
            "schema": "round9-development-paired-malicious-report/v3",
            "corpus": "round9-development-paired-malicious-v3",
            "corpus_manifest": self.identity(paired_root / "manifest.json"),
            "corpus_cases": self.identity(paired_cases),
            "corpus_label_audit": self.identity(label_audit),
            "benign_corpus_manifest": self.identity(benign_root / "manifest.json"),
            "benign_corpus_cases": self.identity(benign_cases),
            "candidate": {
                "policy_version": "classifier-policy-v8",
                "policy_sha256": "3" * 64,
                "ruleset": "1.0.10",
            },
            "runtime": reports.DEVELOPMENT_RUNTIME,
            "platform": reports.DEVELOPMENT_PLATFORM,
            "pair_counts": {
                "total": 120,
                "languages": {"en": 60, "zh": 60},
                "families": {
                    f"family_{index:02d}": {"total": 8, "zh": 4, "en": 4}
                    for index in range(15)
                },
                "categories": paired_categories,
                "difference_axes": {"active_harm": 60, "third_party_victim": 60},
            },
            "metrics": {
                "schema": "round9-malicious-route-executions/v1",
                "unique_semantic_samples": 120,
                "semantic_blocked": 120,
                "serialized_route_executions": 960,
                "passed_route_executions": 960,
                "category_counts": paired_categories,
                "language_counts": {"en": 60, "zh": 60},
                "protocol_counts": {"openai_chat": 480, "openai_responses": 480},
                "stream_counts": {"false": 480, "true": 480},
                "mode_counts": {"balanced": 480, "strict": 480},
                "per_category": source_per_category,
                "failures": [],
            },
            "recall_percent": 100.0,
            "wilson_95_lower_percent": overall_lower * 100,
            "wilson_95_upper_percent": overall_upper * 100,
            "claim_boundary": "paired producer fixture",
        }
        paired_log.write_bytes(reports.canonical_bytes(paired_source_value))
        paired_value = {
            "schema": "round9-development-paired-malicious-machine-report/v1",
            "source_report_schema": "round9-development-paired-malicious-report/v3",
            "corpus": "round9-development-paired-malicious-v3",
            "corpus_manifest_version": 2,
            "corpus_manifest": self.identity(paired_root / "manifest.json"),
            "corpus_cases": self.identity(paired_cases),
            "corpus_label_audit": self.identity(label_audit),
            "benign_corpus_manifest": self.identity(benign_root / "manifest.json"),
            "benign_corpus_cases": self.identity(benign_cases),
            "candidate": candidate,
            "runtime": reports.DEVELOPMENT_RUNTIME,
            "platform": reports.DEVELOPMENT_PLATFORM,
            "metrics": {
                "unique_semantic_samples": 120,
                "semantic_blocked": 120,
                "serialized_route_executions": 960,
                "passed_route_executions": 960,
                "recall_basis_points": 10000,
                "wilson_lower_bound_basis_points": round(overall_lower * 10000),
                "wilson_upper_bound_basis_points": round(overall_upper * 10000),
                "per_category": paired_per_category,
            },
            "producer_log": self.identity(paired_log),
            "claim_boundary": "paired fixture",
        }
        paired_report = artifacts / "paired.json"
        paired_report.write_bytes(reports.canonical_bytes(paired_value))

        public_value = {
            "schema": reports.PUBLIC_REPORT_SCHEMA,
            "candidate": candidate,
            "manifest": self.identity(
                root / "testdata/round9-public-adversarial-v13/manifest.json"
            ),
            "producer_log": self.identity(public_log),
            "metrics": reports.PUBLIC_METRICS,
            "claim_boundary": "public fixture",
        }
        public_report = artifacts / "public.json"
        public_report.write_bytes(reports.canonical_bytes(public_value))
        audit_value = {
            "schema": "round9-audit-contract-report/v1",
            "candidate": candidate,
            "producer_log": self.identity(audit_log),
            "contract": {
                "schema_version": 6,
                "raw_capture_schema_version": 4,
                "decision_kinds": reports.DECISION_KINDS,
                "malicious_block_requires_eligible_winner": True,
                "incomplete_has_no_malicious_winner": True,
            },
            "claim_boundary": "audit fixture",
        }
        audit_report = artifacts / "audit.json"
        audit_report.write_bytes(reports.canonical_bytes(audit_value))
        args = SimpleNamespace(
            root=str(root),
            tag=reports.DEVELOPMENT_TAG,
            commit=commit,
            tree=tree,
            runtime=reports.DEVELOPMENT_RUNTIME,
            platform=reports.DEVELOPMENT_PLATFORM,
            development_benign_report=str(development_report),
            paired_report=str(paired_report),
            paired_log=str(paired_log),
            public_report=str(public_report),
            public_log=str(public_log),
            audit_report=str(audit_report),
            audit_log=str(audit_log),
            output=str(artifacts / "development-evidence.json"),
            input=str(artifacts / "development-evidence.json"),
        )
        return root, artifacts, args, candidate

    @staticmethod
    def paired_source(root: Path, *, version: int = 3) -> bytes:
        paired_root = root / f"testdata/round9-development-paired-malicious-v{version}"
        benign_root = root / "testdata/round9-development-benign-v1"
        paired_root.mkdir(parents=True)
        benign_root.mkdir(parents=True)
        cases_payload = b'{"id":"paired-001"}\n'
        cases_sha256 = hashlib.sha256(cases_payload).hexdigest()
        label_audit_payload = (
            "# Round 9 paired-v3 pre-execution label audit\n\n"
            f"Draft cases SHA-256: `{cases_sha256}`\n\n"
            "Reviewed records: 120\n"
            "Passed records: 120\n"
            "Failed records: 0\n"
            "Candidate output observed: false\n"
            "Classifier or project tests run: false\n"
            "Overall verdict: PASS\n\n"
            + ("bounded independent label-review fixture; " * 16)
            + "\n"
        ).encode()
        label_identity = {
            "bytes": len(label_audit_payload),
            "sha256": hashlib.sha256(label_audit_payload).hexdigest(),
        }
        manifest_payload = json.dumps(
            {
                "name": f"round9-development-paired-malicious-v{version}",
                "version": 2,
                "generated_at": "2026-07-23T00:00:00Z",
                "authoring_context": "visible_round9_paired_development_v3",
                "expected_decision": "block_malicious_text",
                "label_confidence": "unambiguous",
                "generation_boundary": {},
                "schema": {},
                "counts": {},
                "files": {
                    "cases.jsonl": {
                        "bytes": len(cases_payload),
                        "sha256": cases_sha256,
                    }
                },
                "label_audit": label_identity,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        for path, payload in (
            (paired_root / "manifest.json", manifest_payload),
            (paired_root / "cases.jsonl", cases_payload),
            (paired_root / "LABEL_AUDIT.md", label_audit_payload),
            (benign_root / "manifest.json", b'{"benign":true}'),
            (benign_root / "cases.jsonl", b'{"id":"benign-001"}\n'),
        ):
            path.write_bytes(payload)

        def identity(path: Path) -> dict[str, object]:
            raw = path.read_bytes()
            return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}

        categories = {"credential_theft": 60, "phishing_deployment": 60}
        per_category = {}
        for name, samples in categories.items():
            lower, upper = reports.wilson_interval(samples, samples)
            per_category[name] = {
                "semantic_samples": samples,
                "semantic_blocked": samples,
                "route_executions": samples * 8,
                "passed_route_executions": samples * 8,
                "recall_percent": 100.0,
                "wilson_95_lower_percent": lower * 100,
                "wilson_95_upper_percent": upper * 100,
            }
        lower, upper = reports.wilson_interval(120, 120)
        source = {
            "schema": f"round9-development-paired-malicious-report/v{version}",
            "corpus": f"round9-development-paired-malicious-v{version}",
            "corpus_manifest": identity(paired_root / "manifest.json"),
            "corpus_cases": identity(paired_root / "cases.jsonl"),
            "corpus_label_audit": identity(paired_root / "LABEL_AUDIT.md"),
            "benign_corpus_manifest": identity(benign_root / "manifest.json"),
            "benign_corpus_cases": identity(benign_root / "cases.jsonl"),
            "candidate": {
                "policy_version": "classifier-policy-v8",
                "policy_sha256": "3" * 64,
                "ruleset": "1.0.10",
            },
            "runtime": "go1.26.4",
            "platform": "linux/amd64",
            "pair_counts": {
                "total": 120,
                "languages": {"en": 60, "zh": 60},
                "families": {
                    f"family_{index:02d}": {"total": 8, "zh": 4, "en": 4}
                    for index in range(15)
                },
                "categories": categories,
                "difference_axes": {"active_harm": 60, "third_party_victim": 60},
            },
            "metrics": {
                "schema": "round9-malicious-route-executions/v1",
                "unique_semantic_samples": 120,
                "semantic_blocked": 120,
                "serialized_route_executions": 960,
                "passed_route_executions": 960,
                "category_counts": categories,
                "language_counts": {"en": 60, "zh": 60},
                "protocol_counts": {"openai_chat": 480, "openai_responses": 480},
                "stream_counts": {"false": 480, "true": 480},
                "mode_counts": {"balanced": 480, "strict": 480},
                "per_category": per_category,
                "failures": [],
            },
            "recall_percent": 100.0,
            "wilson_95_lower_percent": lower * 100,
            "wilson_95_upper_percent": upper * 100,
            "claim_boundary": "paired development fixture",
        }
        return json.dumps(source, sort_keys=True, separators=(",", ":")).encode()

    def test_public_pass_line_is_closed_and_exact(self) -> None:
        line = (
            "round9 public corpus PASS: payload_records=24 formal_unique=23 "
            "candidate_carriers=1 candidate_executions=1 not_provided=0 "
            "scenario_payload_executions=24 serialized_route_executions=120 "
            "direct_block=12 direct_allow=12 quoted_block=0 "
            "historical_block=0 system_block=0 tool_block=0\n"
        )
        match = reports.PUBLIC_RESULT.fullmatch(line)
        self.assertIsNotNone(match)
        self.assertIsNone(reports.PUBLIC_RESULT.fullmatch(line + "operator_override=PASS\n"))

    def test_public_report_is_v13_and_binds_the_frozen_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repo"
            corpus_root = root / "testdata/round9-public-adversarial-v13"
            corpus_root.mkdir(parents=True)
            manifest_path = corpus_root / "manifest.json"
            shutil.copyfile(
                REPOSITORY_ROOT / "testdata/round9-public-adversarial-v13/manifest.json",
                manifest_path,
            )
            output = Path(temporary) / "public.json"
            log = Path(temporary) / "public.log"
            args = SimpleNamespace(
                root=str(root),
                commit="1" * 40,
                tree="2" * 40,
                go="go",
                output=str(output),
                log=str(log),
            )
            candidate = {
                "commit": "1" * 40,
                "tree": "2" * 40,
                "policy_version": "classifier-policy-v8",
                "policy_sha256": "3" * 64,
                "ruleset": "1.0.10",
            }
            line = (
                "round9 public corpus PASS: payload_records=24 formal_unique=23 "
                "candidate_carriers=1 candidate_executions=1 not_provided=0 "
                "scenario_payload_executions=24 serialized_route_executions=120 "
                "direct_block=12 direct_allow=12 quoted_block=0 historical_block=0 "
                "system_block=0 tool_block=0\n"
            ).encode()
            with mock.patch.object(
                reports, "candidate_identity", return_value=candidate
            ), mock.patch.object(reports, "run_command", return_value=line):
                reports.public_report(args)
            value = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(value["schema"], reports.PUBLIC_REPORT_SCHEMA)
            self.assertEqual(value["manifest"], self.identity(manifest_path))
            self.assertEqual(value["metrics"], reports.PUBLIC_METRICS)
            self.assertEqual(output.read_bytes(), reports.canonical_bytes(value))
            self.assertEqual(log.read_bytes(), line)

    def test_audit_contract_includes_eligible_audit_kind(self) -> None:
        self.assertEqual(
            reports.DECISION_KINDS,
            [
                "allow_clean",
                "audit_eligible_malicious_text",
                "audit_ineligible_risk",
                "block_incomplete_inspection",
                "block_malicious_text",
                "block_opaque_media",
                "block_subject_risk",
            ],
        )

    def test_exclusive_report_write_refuses_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "report.json"
            reports.write_exclusive(path, b"{}")
            with self.assertRaises(FileExistsError):
                reports.write_exclusive(path, b'{"changed":true}')
            self.assertEqual(path.read_bytes(), b"{}")

    def test_development_evidence_is_canonical_and_revalidates(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            _, _, args, _ = self.development_fixture(temporary)
            reports.development_report(args)
            raw = Path(args.output).read_bytes()
            value = json.loads(raw.decode("utf-8"))
            self.assertEqual(raw, reports.canonical_bytes(value))
            self.assertEqual(
                set(value),
                {
                    "schema",
                    "state",
                    "candidate",
                    "runtime",
                    "platform",
                    "corpus",
                    "audit_contract",
                    "machine_reports",
                    "producer_logs",
                    "claim_boundary",
                },
            )
            self.assertEqual(value["schema"], reports.DEVELOPMENT_SCHEMA)
            self.assertEqual(value["state"], "PASS")
            self.assertEqual(
                set(value["candidate"]),
                {"tag", "tag_object_sha", "commit", "tree", "classifier", "ruleset"},
            )
            self.assertEqual(
                set(value["corpus"]),
                {"development_benign", "paired_malicious", "public_adversarial"},
            )
            self.assertEqual(
                set(value["machine_reports"]),
                {"development_benign", "paired_malicious", "public_adversarial", "audit_contract"},
            )
            self.assertEqual(
                set(value["producer_logs"]),
                {"paired_malicious", "public_adversarial", "audit_contract"},
            )
            public = value["corpus"]["public_adversarial"]
            self.assertEqual(set(public), set(reports.PUBLIC_RELEASE_SUMMARY_KEYS))
            self.assertNotIn("metrics", public)
            self.assertEqual(public["name"], reports.PUBLIC_CORPUS)
            self.assertEqual(public["payload_records"], 24)
            self.assertEqual(public["unique_historical_payloads"], 8)
            self.assertEqual(public["unique_branch_head_payloads"], 1)
            self.assertEqual(public["unique_current_prompt_like_payloads"], 14)
            self.assertEqual(public["unique_formal_payloads"], 23)
            self.assertEqual(public["unmerged_candidate_carriers"], 1)
            self.assertEqual(public["nondefault_branch_candidate_carriers"], 5)
            self.assertEqual(public["release_assets_reviewed"], 16)
            self.assertEqual(public["release_assets_with_prompt_entries"], 4)
            self.assertEqual(public["release_asset_metadata_records"], 199)
            self.assertEqual(public["candidate_carrier_executions"], 1)
            self.assertEqual(public["candidate_carriers_not_provided"], 0)
            self.assertEqual(public["scenario_payload_executions"], 24)
            self.assertEqual(public["serialized_route_executions"], 120)
            self.assertEqual(public["direct_active_blocked"], 12)
            self.assertEqual(public["direct_active_allowed"], 12)
            for binding in value["producer_logs"].values():
                self.assertEqual(set(binding), {"bytes", "sha256"})
            validate_args = reports.parser().parse_args(
                [
                    "validate-development",
                    "--root",
                    args.root,
                    "--input",
                    args.input,
                    "--tag",
                    args.tag,
                    "--commit",
                    args.commit,
                    "--tree",
                    args.tree,
                ]
            )
            self.assertFalse(hasattr(validate_args, "runtime"))
            reports.validate_development_report(validate_args)

    def test_real_development_evidence_crosses_active_external_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            _, _, args, _ = self.development_fixture(temporary)
            reports.development_report(args)
            value = json.loads(Path(args.output).read_text(encoding="utf-8"))
            candidate = value["candidate"]
            expected_candidate = {
                "tag": candidate["tag"],
                "tag_object_sha": candidate["tag_object_sha"],
                "source_version": "0.16",
                "commit": candidate["commit"],
                "tree": candidate["tree"],
                "so_sha256": "6" * 64,
                "cpa_version": "v7.2.95",
                "cpa_commit": "f71ec0eb6776854457892452cf28c47f0d658251",
                "classifier_policy_version": candidate["classifier"]["version"],
                "classifier_policy_sha256": candidate["classifier"]["sha256"],
                "ruleset_version": candidate["ruleset"]["version"],
                "ruleset_sha256": candidate["ruleset"]["sha256"],
                "ruleset_manifest_sha256": "7" * 64,
                "build_metadata_sha256": "8" * 64,
                "release_manifest_sha256": "9" * 64,
                "phase1_run_id": 101,
                "phase1_run_attempt": 1,
                "phase1_artifact_id": 202,
                "phase1_artifact_digest": "sha256:" + "a" * 64,
            }
            self.assertEqual(
                evaluation_core.validate_development_evidence(
                    value, expected_candidate=expected_candidate
                ),
                value,
            )

            stale = copy.deepcopy(value)
            stale_public = stale["corpus"]["public_adversarial"]
            stale_public["name"] = "round9-public-adversarial-v5"
            with self.assertRaisesRegex(
                evaluation_core.ContractError, "public corpus name"
            ):
                evaluation_core.validate_development_evidence(stale)

            nested = copy.deepcopy(value)
            nested["corpus"]["public_adversarial"]["metrics"] = {}
            with self.assertRaisesRegex(
                evaluation_core.ContractError, "keys are not exact"
            ):
                evaluation_core.validate_development_evidence(nested)

    def test_development_evidence_rejects_95_percent_paired_recall(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            _, _, args, _ = self.development_fixture(temporary)
            reports.development_report(args)
            path = Path(args.input)
            value = json.loads(path.read_text(encoding="utf-8"))
            paired = value["corpus"]["paired_malicious"]
            paired["semantic_blocked"] = 114
            paired["recall_basis_points"] = 9_500
            for category in paired["per_category"].values():
                category["blocked"] = 57
                category["recall_basis_points"] = 9_500
            path.chmod(0o600)
            path.write_bytes(reports.canonical_bytes(value))
            with self.assertRaisesRegex(
                reports.ReportError, "self-contained evidence recall contract"
            ):
                reports.validate_development_report(args)

    def test_development_benign_report_rejects_null_failures(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            _, _, args, _ = self.development_fixture(temporary)
            path = Path(args.development_benign_report)
            value = json.loads(path.read_text(encoding="utf-8"))
            value["metrics"]["failures"] = None
            path.write_bytes(reports.canonical_bytes(value))
            with self.assertRaisesRegex(
                reports.ReportError, "zero-block route contract failed"
            ):
                reports.build_development_evidence(args)

    def test_development_benign_stream_counts_are_route_bound(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            _, _, args, _ = self.development_fixture(temporary)
            path = Path(args.development_benign_report)
            value = json.loads(path.read_text(encoding="utf-8"))
            value["metrics"]["stream_counts"]["true"] -= 1
            path.write_bytes(reports.canonical_bytes(value))
            with self.assertRaisesRegex(
                reports.ReportError, "distribution accounting is invalid"
            ):
                reports.build_development_evidence(args)

    def test_paired_producer_log_rejects_null_failures_after_rebinding(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            _, _, args, _ = self.development_fixture(temporary)
            log = Path(args.paired_log)
            source = json.loads(log.read_text(encoding="utf-8"))
            source["metrics"]["failures"] = None
            log.write_bytes(reports.canonical_bytes(source))

            machine_path = Path(args.paired_report)
            machine = json.loads(machine_path.read_text(encoding="utf-8"))
            machine["producer_log"] = self.identity(log)
            machine_path.write_bytes(reports.canonical_bytes(machine))
            with self.assertRaisesRegex(
                reports.ReportError,
                "paired malicious producer metrics drifted",
            ):
                reports.build_development_evidence(args)

    def test_paired_producer_stream_counts_use_closed_boolean_keys(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            _, _, args, _ = self.development_fixture(temporary)
            log = Path(args.paired_log)
            source = json.loads(log.read_text(encoding="utf-8"))
            source["metrics"]["stream_counts"] = {"false": 480, "stream": 480}
            log.write_bytes(reports.canonical_bytes(source))

            machine_path = Path(args.paired_report)
            machine = json.loads(machine_path.read_text(encoding="utf-8"))
            machine["producer_log"] = self.identity(log)
            machine_path.write_bytes(reports.canonical_bytes(machine))
            with self.assertRaisesRegex(
                reports.ReportError,
                "paired malicious producer metrics drifted",
            ):
                reports.build_development_evidence(args)

    def test_public_release_summary_matches_exact_rc_consumer_contract(self) -> None:
        release_fields = set(reports.PUBLIC_RELEASE_SUMMARY_METRIC_FIELDS) | set(
            reports.PUBLIC_RELEASE_SUMMARY_MANIFEST_FIELDS
        )
        rc_script = (REPOSITORY_ROOT / "scripts/round6-rc-artifacts.sh").read_text(
            encoding="utf-8"
        )
        rc_workflow = (
            REPOSITORY_ROOT / ".github/workflows/round9-release-rc.yml"
        ).read_text(encoding="utf-8")
        for field in sorted(release_fields):
            with self.subTest(field=field):
                self.assertIn(f".public_adversarial.{field}", rc_script)
                self.assertIn(
                    f".round9.corpus.public_adversarial.{field}", rc_workflow
                )
        self.assertNotIn(".public_adversarial.metrics.", rc_script)
        self.assertNotIn(".round9.corpus.public_adversarial.metrics.", rc_workflow)

    def test_release_latest_and_existing_release_fail_only_contract_rejects_workflow_drift(
        self,
    ) -> None:
        exact_latest = '[[ "$latest" == v0.15 ]]'
        weaker_latest = '[[ "$latest" != "$TAG" ]]'
        publication_block = (
            "ROUND9_NEW_PUBLIC_PRERELEASE_CREATION: "
            "BLOCKED_PENDING_EXACT_CANDIDATE_INDEPENDENT_AUDIT_GATE"
        )
        blocked_job = "  publication_blocked:\n"
        disabled_job = (
            "    if: ${{ needs.admission.outputs.publication_permitted == 'true' }}\n"
        )
        forced_false_output = "            printf 'publication_permitted=false\\n'\n"
        existing_release_gate = (
            '[.[][] | select(.tag_name == $tag)] | length == 0'
        )
        existing_release_failure = (
            "an existing Round 9 Release is fail-only until exact-candidate "
            "independent-audit evidence passes mechanical verification"
        )
        historical_workflow_state = '.state == "disabled_manually"'
        workflow = (
            REPOSITORY_ROOT / ".github/workflows/round9-release-rc.yml"
        ).read_text(encoding="utf-8")
        policy = (REPOSITORY_ROOT / "docs/RELEASE_POLICY.md").read_text(
            encoding="utf-8"
        )
        required_policy_lines = (
            "current_release_recovery: "
            "fail-only-existing-release-rejected-no-automatic-verifier",
            "current_release_draft_recovery: "
            "fail-only-manual-review-no-automatic-mutation",
            "current_release_new_dispatch_or_rerun_all: "
            "admission-existing-release-fail-only-otherwise-private-candidate-only",
            "current_historical_workflow_disable_requirement: "
            "315644586:release-rc.yml=disabled_manually,"
            "318443961:round8-host-validation.yml=disabled_manually",
            "current_development_paired_recall_requirement: "
            "aggregate-and-each-category-exactly-10000-basis-points",
            "current_independent_malicious_recall_requirement: "
            "aggregate-and-each-category-at-least-9500-basis-points",
            "current_release_latest_stable: v0.15",
            "current_new_public_prerelease_creation: BLOCKED_FAIL_CLOSED",
            "current_exact_candidate_independent_audit_mechanical_gate: "
            "IMPLEMENTED_FAIL_CLOSED_EVIDENCE_NOT_PROVIDED",
            "current_publication_write_permission: absent",
        )
        stale_active_recovery = (
            "current_release_recovery: "
            "admission-read-only-verifier-for-existing-non-draft-immutable-release"
        )

        def assert_contract(workflow_text: str, policy_text: str) -> None:
            self.assertEqual(workflow_text.count(exact_latest), 1)
            self.assertNotIn(weaker_latest, workflow_text)
            self.assertEqual(workflow_text.count(publication_block), 1)
            self.assertEqual(workflow_text.count(blocked_job), 1)
            self.assertEqual(workflow_text.count(disabled_job), 3)
            self.assertEqual(workflow_text.count(forced_false_output), 1)
            self.assertEqual(workflow_text.count(existing_release_gate), 1)
            self.assertEqual(workflow_text.count(existing_release_failure), 1)
            self.assertEqual(workflow_text.count(historical_workflow_state), 2)
            self.assertNotIn("already_public", workflow_text)
            self.assertNotIn("inputs.publish_rc_release", workflow_text)
            self.assertNotIn("contents: write", workflow_text)
            self.assertNotIn("gh release create", workflow_text)
            self.assertNotIn("make_latest=", workflow_text)
            for line in required_policy_lines:
                self.assertEqual(policy_text.count(line), 1)
            self.assertNotIn(stale_active_recovery, policy_text)

        assert_contract(workflow, policy)
        latest_weakened = workflow.replace(exact_latest, weaker_latest, 1)
        publication_enabled = workflow.replace(disabled_job, "    if: ${{ true }}\n", 1)
        existing_release_recovered = workflow.replace(
            existing_release_gate,
            '[.[][] | select(.tag_name == $tag)] | length >= 0',
            1,
        )
        historical_workflow_enabled = workflow.replace(
            historical_workflow_state,
            '.state == "active"',
            1,
        )
        writer_injected = workflow.replace(
            "          exit 1\n\n  verify_published:",
            '          gh release create "$TAG" dist/* --latest=false\n'
            "          exit 1\n\n  verify_published:",
            1,
        )
        for name, mutation in (
            ("existing-verifier-latest-check", latest_weakened),
            ("publication-job-enabled", publication_enabled),
            ("existing-release-success-recovery", existing_release_recovered),
            ("historical-workflow-reenabled", historical_workflow_enabled),
            ("release-writer-injected", writer_injected),
        ):
            with self.subTest(name=name):
                self.assertNotEqual(mutation, workflow)
                with self.assertRaises(AssertionError):
                    assert_contract(mutation, policy)

    def test_public_release_summary_field_alias_and_value_drift_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            _, _, args, _ = self.development_fixture(temporary)
            reports.development_report(args)
            evidence_path = Path(args.input)
            original = json.loads(evidence_path.read_text(encoding="utf-8"))

            renamed = copy.deepcopy(original)
            public = renamed["corpus"]["public_adversarial"]
            public["formal_unique_payloads"] = public.pop("unique_formal_payloads")

            nested = copy.deepcopy(original)
            nested["corpus"]["public_adversarial"]["metrics"] = {
                "payload_records": 24
            }

            wrong_value = copy.deepcopy(original)
            wrong_value["corpus"]["public_adversarial"][
                "candidate_carrier_executions"
            ] = 0

            for name, mutation, error in (
                ("renamed", renamed, "must contain exactly"),
                ("nested", nested, "must contain exactly"),
                ("wrong-value", wrong_value, "identity drifted"),
            ):
                with self.subTest(name=name):
                    evidence_path.chmod(0o600)
                    evidence_path.write_bytes(reports.canonical_bytes(mutation))
                    with self.assertRaisesRegex(reports.ReportError, error):
                        reports.validate_development_report(args)

    def test_development_candidate_requires_annotated_tag_and_clean_checkout(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            _, _, args, _ = self.development_fixture(temporary, annotated=False)
            with self.assertRaisesRegex(reports.ReportError, "annotated tag"):
                reports.build_development_evidence(args)
        with tempfile.TemporaryDirectory() as temporary:
            root, _, args, _ = self.development_fixture(temporary)
            (root / "rules/semantics.yaml").write_text("rules: [dirty]\n", encoding="utf-8")
            with self.assertRaisesRegex(reports.ReportError, "clean candidate checkout"):
                reports.build_development_evidence(args)

    def test_candidate_rejects_classifier_version_prefix_lookalike(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "internal/classifier").mkdir(parents=True)
            (root / "internal/classifier/policy_identity.go").write_text(
                'package classifier\n\n'
                'const ClassifierPolicyVersion = "classifier-policy-v8-lookalike"\n'
                f'const ClassifierPolicySHA256 = "{"3" * 64}"\n',
                encoding="utf-8",
            )

            def fake_git_output(_root: Path, *arguments: str) -> str:
                if arguments == ("rev-parse", "HEAD"):
                    return "1" * 40
                if arguments == ("rev-parse", "HEAD^{tree}"):
                    return "2" * 40
                if arguments == ("status", "--porcelain=v1", "--untracked-files=all"):
                    return ""
                raise AssertionError(arguments)

            with mock.patch.object(reports, "git_output", side_effect=fake_git_output):
                with self.assertRaisesRegex(reports.ReportError, "reviewed Round 9 identity"):
                    reports.candidate_identity(root, "1" * 40, "2" * 40)

    def test_development_candidate_report_identity_drift_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            _, _, args, _ = self.development_fixture(temporary)
            path = Path(args.paired_report)
            value = json.loads(path.read_text(encoding="utf-8"))
            value["candidate"]["policy_sha256"] = "4" * 64
            path.write_bytes(reports.canonical_bytes(value))
            with self.assertRaisesRegex(reports.ReportError, "candidate identity drifted"):
                reports.build_development_evidence(args)

    def test_report_schema_extra_key_and_duplicate_key_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            _, _, args, _ = self.development_fixture(temporary)
            path = Path(args.development_benign_report)
            value = json.loads(path.read_text(encoding="utf-8"))
            value["schema"] = "round9-development-benign-corpus-report/v0"
            path.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaisesRegex(reports.ReportError, "identity is invalid"):
                reports.build_development_evidence(args)
        with tempfile.TemporaryDirectory() as temporary:
            _, _, args, _ = self.development_fixture(temporary)
            path = Path(args.public_report)
            value = json.loads(path.read_text(encoding="utf-8"))
            value["operator_override"] = "PASS"
            path.write_bytes(reports.canonical_bytes(value))
            with self.assertRaisesRegex(reports.ReportError, "must contain exactly"):
                reports.build_development_evidence(args)
        with tempfile.TemporaryDirectory() as temporary:
            _, _, args, _ = self.development_fixture(temporary)
            path = Path(args.audit_report)
            raw = path.read_bytes()
            path.write_bytes(raw[:-1] + b',"schema":"round9-audit-contract-report/v1"}')
            with self.assertRaisesRegex(reports.ReportError, "duplicate JSON key"):
                reports.build_development_evidence(args)

    def test_machine_report_hash_and_producer_log_drift_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            _, _, args, _ = self.development_fixture(temporary)
            reports.development_report(args)
            evidence_path = Path(args.input)
            evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
            evidence["machine_reports"]["public_adversarial"]["sha256"] = "0" * 64
            evidence_path.chmod(0o600)
            evidence_path.write_bytes(reports.canonical_bytes(evidence))
            with self.assertRaisesRegex(reports.ReportError, "all-zero sentinel"):
                reports.validate_development_report(args)
        with tempfile.TemporaryDirectory() as temporary:
            _, _, args, _ = self.development_fixture(temporary)
            Path(args.paired_log).write_bytes(b"paired producer log drift\n")
            with self.assertRaisesRegex(reports.ReportError, "producer log bytes drifted"):
                reports.build_development_evidence(args)

    def test_machine_reports_must_be_derived_from_their_producer_logs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            _, _, args, _ = self.development_fixture(temporary)
            path = Path(args.paired_report)
            value = json.loads(path.read_text(encoding="utf-8"))
            value["metrics"]["wilson_lower_bound_basis_points"] += 1
            path.write_bytes(reports.canonical_bytes(value))
            with self.assertRaisesRegex(reports.ReportError, "not derived from its producer log"):
                reports.build_development_evidence(args)
        with tempfile.TemporaryDirectory() as temporary:
            _, _, args, _ = self.development_fixture(temporary)
            log = Path(args.public_log)
            log.write_bytes(log.read_bytes().replace(b"direct_block=12", b"direct_block=11"))
            report_path = Path(args.public_report)
            value = json.loads(report_path.read_text(encoding="utf-8"))
            value["producer_log"] = self.identity(log)
            report_path.write_bytes(reports.canonical_bytes(value))
            with self.assertRaisesRegex(reports.ReportError, "not derived from its producer log"):
                reports.build_development_evidence(args)

    def test_all_checkout_identity_bindings_reject_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, _, args, candidate = self.development_fixture(temporary)
            (root / "testdata/round9-development-benign-v1/cases.jsonl").write_bytes(
                b'{"id":"changed"}\n'
            )
            with self.assertRaisesRegex(reports.ReportError, "frozen corpus files"):
                reports.validate_development_benign_report(
                    root,
                    Path(args.development_benign_report),
                    candidate,
                    args.runtime,
                    args.platform,
                )
        with tempfile.TemporaryDirectory() as temporary:
            root, _, args, candidate = self.development_fixture(temporary)
            (root / "testdata/round9-development-paired-malicious-v3/cases.jsonl").write_bytes(
                b'{"id":"changed"}\n'
            )
            with self.assertRaisesRegex(reports.ReportError, "does not bind"):
                reports.validate_development_paired_report(
                    root,
                    Path(args.paired_report),
                    Path(args.paired_log),
                    candidate,
                    args.runtime,
                    args.platform,
                )
        with tempfile.TemporaryDirectory() as temporary:
            root, _, args, candidate = self.development_fixture(temporary)
            manifest = root / "testdata/round9-public-adversarial-v13/manifest.json"
            manifest.write_bytes(manifest.read_bytes() + b"\n")
            with self.assertRaisesRegex(reports.ReportError, "manifest identity drifted"):
                reports.validate_development_public_report(
                    root,
                    Path(args.public_report),
                    Path(args.public_log),
                    candidate,
                )
        with tempfile.TemporaryDirectory() as temporary:
            root, _, args, candidate = self.development_fixture(temporary)
            (root / "internal/plugin/management.go").write_text(
                "package plugin\n\nconst (\n\tmanagementRawCaptureSchema = 5\n)\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(reports.ReportError, "schema v6 and Raw Capture v4"):
                reports.validate_development_audit_report(
                    root,
                    Path(args.audit_report),
                    Path(args.audit_log),
                    candidate,
                )

    def test_noncanonical_evidence_and_extra_producer_log_fields_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            _, _, args, _ = self.development_fixture(temporary)
            reports.development_report(args)
            path = Path(args.input)
            value = json.loads(path.read_text(encoding="utf-8"))
            path.chmod(0o600)
            path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(reports.ReportError, "canonical UTF-8 JSON"):
                reports.validate_development_report(args)
        with tempfile.TemporaryDirectory() as temporary:
            _, _, args, _ = self.development_fixture(temporary)
            reports.development_report(args)
            path = Path(args.input)
            value = json.loads(path.read_text(encoding="utf-8"))
            value["producer_logs"]["public_adversarial"]["path"] = "public.log"
            path.chmod(0o600)
            path.write_bytes(reports.canonical_bytes(value))
            with self.assertRaisesRegex(reports.ReportError, "must contain exactly"):
                reports.validate_development_report(args)

    def test_paired_v3_runner_output_becomes_hash_bound_machine_report(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            raw = self.paired_source(root)
            output = root / "paired-machine.json"
            log = root / "paired.log"
            args = SimpleNamespace(
                root=str(root),
                commit="1" * 40,
                tree="2" * 40,
                go="go",
                output=str(output),
                log=str(log),
            )
            candidate = {
                "commit": "1" * 40,
                "tree": "2" * 40,
                "policy_version": "classifier-policy-v8",
                "policy_sha256": "3" * 64,
                "ruleset": "1.0.10",
            }
            with mock.patch.object(reports, "candidate_identity", return_value=candidate), mock.patch.object(
                reports, "run_command", return_value=raw
            ):
                reports.paired_report(args)
            machine = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(
                machine["schema"],
                "round9-development-paired-malicious-machine-report/v1",
            )
            self.assertEqual(machine["source_report_schema"], "round9-development-paired-malicious-report/v3")
            self.assertEqual(machine["corpus_manifest_version"], 2)
            self.assertEqual(
                machine["corpus_label_audit"],
                json.loads(raw)["corpus_label_audit"],
            )
            self.assertEqual(machine["metrics"]["unique_semantic_samples"], 120)
            self.assertEqual(machine["metrics"]["serialized_route_executions"], 960)
            self.assertEqual(log.read_bytes(), raw)
            self.assertEqual(output.read_bytes(), reports.canonical_bytes(machine))

    def test_paired_v2_runner_identity_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            raw = self.paired_source(root, version=2)
            args = SimpleNamespace(
                root=str(root),
                commit="1" * 40,
                tree="2" * 40,
                go="go",
                output=str(root / "paired-machine.json"),
                log=str(root / "paired.log"),
            )
            candidate = {
                "commit": "1" * 40,
                "tree": "2" * 40,
                "policy_version": "classifier-policy-v8",
                "policy_sha256": "3" * 64,
                "ruleset": "1.0.10",
            }
            with mock.patch.object(reports, "candidate_identity", return_value=candidate), mock.patch.object(
                reports, "run_command", return_value=raw
            ), self.assertRaisesRegex(reports.ReportError, "v3-or-newer"):
                reports.paired_report(args)


if __name__ == "__main__":
    unittest.main()
