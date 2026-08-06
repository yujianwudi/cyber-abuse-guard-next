from __future__ import annotations

import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
TOOL = HERE.parent
sys.path.insert(0, str(TOOL))
sys.path.insert(0, str(HERE))

import acquire
from audit_contract import (
    CPA_COMMIT,
    CPA_TAG,
    MOCK_CONTRACT,
    RUN_CONFIG_SCHEMA,
    ContractError,
    build_execution_plan,
    load_json_file,
    validate_corpus_manifest,
    validate_machine_evidence,
    validate_result,
    validate_run_config,
)
from fixtures import approved_policy, evidence_files, manifest


class ContractTests(unittest.TestCase):
    def test_repository_policy_is_exact_and_closed(self) -> None:
        policy = load_json_file(TOOL / "repository-policy.json", "policy")
        validated = acquire.validate_policy(policy, require_approved=True)
        self.assertEqual(len(validated["repositories"]), 5)
        self.assertEqual(
            validated["reviewer"],
            {
                "identity": "Codex Round 12 exact-source review",
                "reviewed_at": "2026-08-06T01:19:51.256Z",
                "status": "approved",
            },
        )
        self.assertTrue(
            all(
                all(isinstance(value, str) and value for value in source["reviewed_source"].values())
                for repository in validated["repositories"]
                for source in repository["paths"]
            )
        )
        acquire.validate_policy(approved_policy(), require_approved=True)
        self.assertEqual(
            next(item for item in validated["repositories"] if item["key"] == "nerv")["retention"],
            "hash_identity_count_only",
        )

    def test_manifest_and_fixed_seed_plan_are_deterministic(self) -> None:
        value = validate_corpus_manifest(manifest())
        first = build_execution_plan(value, 1205, 3)
        second = build_execution_plan(value, 1205, 3)
        different = build_execution_plan(value, 1206, 3)
        self.assertEqual(first, second)
        self.assertNotEqual(first, different)
        self.assertEqual(len(first), 19 * 3 * 2 * 2 * 3)

    def test_manifest_missing_ground_truth_fails_closed(self) -> None:
        value = manifest()
        del value["semantic_cases"][0]["authorization"]
        with self.assertRaises(ContractError):
            validate_corpus_manifest(value)

    def test_manifest_missing_post_head_fails_closed(self) -> None:
        value = manifest()
        del value["head_observations"][0]["post"]
        with self.assertRaises(ContractError):
            validate_corpus_manifest(value)

    def test_manifest_extra_field_fails_closed(self) -> None:
        value = manifest()
        value["unreviewed"] = True
        with self.assertRaises(ContractError):
            validate_corpus_manifest(value)

    def test_run_config_is_closed_and_binds_cpa(self) -> None:
        config = {
            "corpus_manifest_sha256": "1" * 64,
            "identities": {
                "cag": {"commit": "1" * 40, "so_sha256": "2" * 64, "tree": "3" * 40},
                "cpa": {
                    "binary_path": "/usr/local/bin/CLIProxyAPI",
                    "binary_sha256": "3" * 64,
                    "commit": CPA_COMMIT,
                    "image_id": "sha256:" + "4" * 64,
                    "image_ref": "registry.example/cpa@sha256:" + "5" * 64,
                    "official_asset_name": "cpa.tar.gz",
                    "official_asset_sha256": "6" * 64,
                    "repo_digest": "registry.example/cpa@sha256:" + "5" * 64,
                    "tag": CPA_TAG,
                },
                "mock": {
                    "contract": MOCK_CONTRACT,
                    "image_id": "sha256:" + "7" * 64,
                    "image_ref": "registry.example/mock@sha256:" + "8" * 64,
                    "repo_digest": "registry.example/mock@sha256:" + "8" * 64,
                    "source_sha256": "9" * 64,
                },
            },
            "paths": {
                "cag_repository": "/srv/cag",
                "cag_so": "/srv/cag.so",
                "corpus_manifest": "/srv/acquisition/corpus-manifest.json",
                "cpa_official_asset": "/srv/cpa.tar.gz",
                "evidence_directory": "/srv/evidence",
                "mock_source": "/srv/counted_mock.py",
            },
            "policy_sha256": "a" * 64,
            "run": {"cold_start_count": 3, "platform": "linux/amd64", "run_id": "unit-run", "seed": 1205},
            "schema": RUN_CONFIG_SCHEMA,
        }
        validate_run_config(config)
        extra = copy.deepcopy(config)
        extra["identities"]["cpa"]["untrusted"] = True
        with self.assertRaises(ContractError):
            validate_run_config(extra)
        wrong = copy.deepcopy(config)
        wrong["identities"]["cpa"]["tag"] = "v7.2.115"
        with self.assertRaises(ContractError):
            validate_run_config(wrong)

    def test_complete_machine_evidence_passes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source_manifest, evidence, results = evidence_files(Path(directory))
            validated = validate_machine_evidence(source_manifest, evidence, results)
            self.assertEqual(validated["third_party_code_executions"], 0)
            self.assertEqual(validated["run"]["cold_start_count"], 3)

    def test_missing_identity_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source_manifest, evidence, results = evidence_files(Path(directory))
            del evidence["identities"]["cpa"]["binary_sha256"]
            with self.assertRaises(ContractError):
                validate_machine_evidence(source_manifest, evidence, results)

    def test_missing_quick_check_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source_manifest, evidence, results = evidence_files(Path(directory))
            del evidence["cold_starts"][0]["sqlite"]["quick_check"]
            with self.assertRaises(ContractError):
                validate_machine_evidence(source_manifest, evidence, results)

    def test_machine_evidence_extra_field_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source_manifest, evidence, results = evidence_files(Path(directory))
            evidence["trust_me"] = True
            with self.assertRaises(ContractError):
                validate_machine_evidence(source_manifest, evidence, results)

    def test_inconsistent_cold_result_digest_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source_manifest, evidence, results = evidence_files(Path(directory))
            evidence["cold_starts"][1]["results_sha256"] = "c" * 64
            with self.assertRaises(ContractError):
                validate_machine_evidence(source_manifest, evidence, results)

    def test_block_error_response_contract_is_mandatory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source_manifest, _, results = evidence_files(Path(directory))
            cases = {case["id"]: case for case in source_manifest["semantic_cases"]}
            rows = [json.loads(line) for line in results.read_text("utf-8").splitlines()]
            blocked = next(row for row in rows if row["expected_action"] == "block_malicious_text")
            blocked["error_contract"]["schema_valid"] = False
            with self.assertRaises(ContractError):
                validate_result(blocked, cases, "mutated block")

    def test_audit_malicious_event_preserves_disposition_kind_split(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source_manifest, _, results = evidence_files(Path(directory))
            cases = {case["id"]: case for case in source_manifest["semantic_cases"]}
            rows = [json.loads(line) for line in results.read_text("utf-8").splitlines()]
            audited = next(
                row
                for row in rows
                if row["mode"] == "audit"
                and row["expected_action"] == "allow"
                and row["audit_event"] is not None
            )
            self.assertEqual(audited["audit_event"]["decision"], "audit_malicious_text")
            self.assertEqual(
                audited["audit_event"]["decision_kind"],
                "audit_eligible_malicious_text",
            )
            validate_result(audited, cases, "audited malicious allow")

            drifted = copy.deepcopy(audited)
            drifted["audit_event"]["decision"] = "audit_eligible_malicious_text"
            with self.assertRaisesRegex(ContractError, "paired Audit semantic event"):
                validate_result(drifted, cases, "drifted audited malicious allow")

    def test_result_extra_field_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source_manifest, _, results = evidence_files(Path(directory))
            cases = {case["id"]: case for case in source_manifest["semantic_cases"]}
            row = json.loads(results.read_text("utf-8").splitlines()[0])
            row["request_text"] = "must never be retained"
            with self.assertRaises(ContractError):
                validate_result(row, cases, "extra field")


if __name__ == "__main__":
    unittest.main()
