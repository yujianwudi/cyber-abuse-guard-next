#!/usr/bin/env python3

from __future__ import annotations

import argparse
import copy
from email.message import Message
import os
from pathlib import Path
import unittest
from unittest import mock

import round9_external_evaluation_contract as contract
from round9_eval_test_fixtures import development_evidence, runtime_checks


class FakeHTTPResponse:
    def __init__(self, status: int, raw: bytes = b"", headers: Message | None = None):
        self.status = status
        self._raw = raw
        self.headers = headers or Message()

    def __enter__(self) -> "FakeHTTPResponse":
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def read(self, _maximum: int = -1) -> bytes:
        return self._raw


class FakeGitHubClient:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.main_sha = args.commit
        self.tag_type = "tag"
        self.tag_sha = args.tag_object_sha
        self.tree_sha = args.tree
        self.phase1_head_sha = args.commit
        self.host_head_sha = args.commit
        self.artifact_digest = args.phase1_artifact_digest
        self.ruleset_name = args.ruleset_name
        self.ruleset_rules: object = [
            {"type": "deletion"},
            {"type": "update"},
        ]
        self.aborted_present = False
        self.refs_requested: list[str] = []
        self.json_requested: list[str] = []

    def ref(
        self,
        _repository: str,
        full_ref: str,
        *,
        absent_ok: bool = False,
    ) -> dict | None:
        del absent_ok
        self.refs_requested.append(full_ref)
        if full_ref == "refs/heads/main":
            return {"object": {"type": "commit", "sha": self.main_sha}}
        if full_ref == f"refs/tags/{self.args.tag}":
            return {"object": {"type": self.tag_type, "sha": self.tag_sha}}
        if full_ref.endswith("/aborted"):
            if self.aborted_present:
                return {"object": {"type": "tag", "sha": "f" * 40}}
            return None
        raise AssertionError(f"unexpected ref: {full_ref}")

    def json(self, endpoint: str) -> dict:
        self.json_requested.append(endpoint)
        prefix = f"repos/{self.args.repository}/"
        if endpoint == prefix + f"git/tags/{self.args.tag_object_sha}":
            return {
                "object": {"type": "commit", "sha": self.args.commit},
            }
        if endpoint == prefix + f"git/commits/{self.args.commit}":
            return {"tree": {"sha": self.tree_sha}}
        if endpoint == prefix + f"actions/runs/{self.args.phase1_run_id}":
            return {
                "id": self.args.phase1_run_id,
                "run_attempt": self.args.phase1_run_attempt,
                "name": contract.PHASE1_WORKFLOW_NAME,
                "path": contract.RELEASE_WORKFLOW,
                "head_sha": self.phase1_head_sha,
                "status": "completed",
                "conclusion": "success",
            }
        if endpoint == prefix + f"actions/artifacts/{self.args.phase1_artifact_id}":
            return {
                "id": self.args.phase1_artifact_id,
                "digest": self.artifact_digest,
                "expired": False,
                "workflow_run": {"id": self.args.phase1_run_id},
            }
        if endpoint == prefix + f"actions/runs/{self.args.host_run_id}":
            return {
                "id": self.args.host_run_id,
                "run_attempt": self.args.host_run_attempt,
                "name": contract.HOST_WORKFLOW_NAME,
                "path": contract.HOST_WORKFLOW,
                "head_sha": self.host_head_sha,
                "event": "workflow_dispatch",
                "status": "completed",
                "conclusion": "success",
            }
        if endpoint == prefix + f"rulesets/{self.args.ruleset_id}":
            return {
                "id": self.args.ruleset_id,
                "name": self.ruleset_name,
                "target": "tag",
                "enforcement": "active",
                "bypass_actors": [],
                "conditions": {
                    "ref_name": {
                        "include": ["refs/tags/round9-eval-ledger/**"],
                        "exclude": [],
                    }
                },
                "rules": copy.deepcopy(self.ruleset_rules),
            }
        raise AssertionError(f"unexpected endpoint: {endpoint}")


class ExternalEvaluationContractTest(unittest.TestCase):
    def args(self, command: str = "validate") -> argparse.Namespace:
        return argparse.Namespace(
            command=command,
            envelope=Path("external.json"),
            proof=Path("proof.json"),
            development_evidence=Path("development-evidence.json"),
            public_key=Path("evaluator.pub"),
            public_key_sha256="a" * 64,
            key_id="round9-evaluator-key-v1",
            evaluator_version="cag-round9-external-evaluator-v2",
            evaluator_sha256="b" * 64,
            core_sha256="c" * 64,
            broker_sha256="d" * 64,
            sandbox_adapter_sha256="e" * 64,
            sandbox_adapter_config_sha256="f" * 64,
            docker_sandbox_sha256="1" * 64,
            cpa_image_id="sha256:" + "2" * 64,
            counted_mock_image_id="sha256:" + "3" * 64,
            model="gpt-5.4",
            repository="example/cyber-abuse-guard",
            tag="v0.16-rc.3",
            tag_object_sha="4" * 40,
            commit="5" * 40,
            tree="6" * 40,
            so_sha256="7" * 64,
            classifier_policy_version="classifier-policy-v8",
            classifier_policy_sha256="8" * 64,
            ruleset_version="1.0.10",
            ruleset_sha256="9" * 64,
            ruleset_manifest_sha256="a" * 64,
            build_metadata_sha256="b" * 64,
            release_manifest_sha256="c" * 64,
            phase1_run_id=101,
            phase1_run_attempt=1,
            phase1_artifact_id=202,
            phase1_artifact_digest="sha256:" + "d" * 64,
            host_run_id=303,
            host_run_attempt=2,
            challenge="e" * 64,
            openssl="openssl",
            ruleset_id=19602252,
            ruleset_name="round9-eval-ledger-immutable",
        )

    @staticmethod
    def payload(args: argparse.Namespace) -> dict:
        development = development_evidence(
            tag_object_sha=args.tag_object_sha,
            commit=args.commit,
            tree=args.tree,
            classifier_version=args.classifier_policy_version,
            classifier_sha256=args.classifier_policy_sha256,
            ruleset_version=args.ruleset_version,
            ruleset_sha256=args.ruleset_sha256,
        )
        return {
            "evaluator": {
                "version": args.evaluator_version,
                "sha256": args.evaluator_sha256,
                "core_sha256": args.core_sha256,
                "broker_sha256": args.broker_sha256,
            },
            "execution": {
                "workflow_run_id": args.host_run_id,
                "workflow_run_attempt": args.host_run_attempt,
                "cpa_image_id": args.cpa_image_id,
                "counted_mock_image_id": args.counted_mock_image_id,
                "model": args.model,
                "scan_limit_bytes": 16_384,
                "sandbox_adapter_sha256": args.sandbox_adapter_sha256,
                "sandbox_adapter_config_sha256": args.sandbox_adapter_config_sha256,
                "docker_sandbox_sha256": args.docker_sandbox_sha256,
            },
            "ledger": {"repository": args.repository},
            "development_evidence": development,
            "counted_mock": {"schema": "round9-external-counted-mock/v1", "state": "PASS"},
            "metrics": {
                "identity": "synthetic-metrics",
                "runtime_checks": runtime_checks(),
            },
        }

    def load_contract(
        self, args: argparse.Namespace, payload: dict
    ) -> tuple[dict, dict, dict]:
        envelope = {"schema": "signed-envelope"}
        proof = {"schema": "ledger-proof"}
        development = development_evidence(
            tag_object_sha=args.tag_object_sha,
            commit=args.commit,
            tree=args.tree,
            classifier_version=args.classifier_policy_version,
            classifier_sha256=args.classifier_policy_sha256,
            ruleset_version=args.ruleset_version,
            ruleset_sha256=args.ruleset_sha256,
        )

        def fake_load(path: Path, _label: str, **_kwargs: object) -> dict:
            if path == args.envelope:
                return envelope
            if path == args.proof:
                return proof
            if path == args.development_evidence:
                return development
            raise AssertionError(f"unexpected path: {path}")

        with (
            mock.patch.object(
                contract, "load_canonical_json", side_effect=fake_load
            ),
            mock.patch.object(
                contract, "sha256_file", return_value=args.public_key_sha256
            ),
            mock.patch.object(
                contract, "verify_signed_envelope", return_value=payload
            ),
            mock.patch.object(contract, "validate_evaluation_payload"),
            mock.patch.object(contract, "validate_development_evidence"),
            mock.patch.object(contract, "validate_counted_mock"),
        ):
            return contract.load_contract(args)

    def test_local_contract_binds_all_evaluator_and_execution_identities(self) -> None:
        args = self.args()
        payload = self.payload(args)
        _envelope, loaded, _proof = self.load_contract(args, payload)
        self.assertIs(loaded, payload)

        mutations = {
            "evaluator.version": ("evaluator", "version", "other-evaluator"),
            "evaluator.sha256": ("evaluator", "sha256", "0" * 64),
            "evaluator.core_sha256": ("evaluator", "core_sha256", "0" * 64),
            "evaluator.broker_sha256": ("evaluator", "broker_sha256", "0" * 64),
            "execution.workflow_run_id": (
                "execution",
                "workflow_run_id",
                999,
            ),
            "execution.workflow_run_attempt": (
                "execution",
                "workflow_run_attempt",
                999,
            ),
            "execution.cpa_image_id": (
                "execution",
                "cpa_image_id",
                "sha256:" + "0" * 64,
            ),
            "execution.counted_mock_image_id": (
                "execution",
                "counted_mock_image_id",
                "sha256:" + "0" * 64,
            ),
            "execution.model": ("execution", "model", "gpt-5.3"),
            "execution.scan_limit_bytes": ("execution", "scan_limit_bytes", 8192),
            "execution.sandbox_adapter_sha256": (
                "execution",
                "sandbox_adapter_sha256",
                "0" * 64,
            ),
            "execution.sandbox_adapter_config_sha256": (
                "execution",
                "sandbox_adapter_config_sha256",
                "0" * 64,
            ),
            "execution.docker_sandbox_sha256": (
                "execution",
                "docker_sandbox_sha256",
                "0" * 64,
            ),
            "ledger.repository": ("ledger", "repository", "other/repository"),
        }
        for label, (section, key, value) in mutations.items():
            with self.subTest(label=label):
                changed = copy.deepcopy(payload)
                changed[section][key] = value
                with self.assertRaises(contract.ContractError):
                    self.load_contract(args, changed)

        changed = copy.deepcopy(payload)
        changed["development_evidence"]["candidate"]["commit"] = "0" * 40
        with self.assertRaisesRegex(contract.ContractError, "development evidence differs"):
            self.load_contract(args, changed)

        changed = copy.deepcopy(payload)
        changed["metrics"]["runtime_checks"]["state"] = "NOT_PROVIDED"
        with self.assertRaisesRegex(contract.ContractError, "runtime checks state"):
            self.load_contract(args, changed)

    def test_argument_contract_rejects_evaluation_markers_and_identity_drift(self) -> None:
        args = self.args()
        contract.validate_args(args)

        for field, value in (
            ("model", "round9-test-model"),
            ("cpa_image_id", "2" * 64),
            ("counted_mock_image_id", "sha256:short"),
            ("ruleset_version", "1.0.11"),
            ("tag", "v0.16-rc.4"),
        ):
            with self.subTest(field=field):
                changed = copy.copy(args)
                setattr(changed, field, value)
                with self.assertRaises(contract.ContractError):
                    contract.validate_args(changed)

    def test_remote_contract_binds_main_tag_tree_phase1_artifact_and_ruleset(self) -> None:
        args = self.args(command="verify-remote")
        client = FakeGitHubClient(args)
        envelope: dict = {}
        proof: dict = {}
        payload = {
            "ledger": {"namespace": "round9-eval-ledger/" + "a" * 64}
        }
        loader_calls: list[tuple[str, str]] = []

        def fake_remote_tag_message(
            _client: object,
            repository: str,
            full_ref: str,
            expected_commit: str,
        ) -> tuple[str, str]:
            self.assertEqual(expected_commit, args.commit)
            loader_calls.append((repository, full_ref))
            return "f" * 40, "{}"

        def fake_validate_proof(
            _proof: dict,
            _envelope: dict,
            _payload: dict,
            _public_key: Path,
            _key_id: str,
            *,
            remote_loader: object,
        ) -> None:
            self.assertTrue(callable(remote_loader))
            remote_loader(args.repository, "refs/tags/round9-eval-ledger/a/reserved")

        with (
            mock.patch.dict(os.environ, {"GH_TOKEN": "token"}),
            mock.patch.object(contract, "GitHubClient", return_value=client),
            mock.patch.object(
                contract,
                "remote_tag_message",
                side_effect=fake_remote_tag_message,
            ),
            mock.patch.object(
                contract, "validate_ledger_proof", side_effect=fake_validate_proof
            ),
        ):
            contract.verify_remote(args, envelope, payload, proof)

        self.assertIn("refs/heads/main", client.refs_requested)
        self.assertIn(f"refs/tags/{args.tag}", client.refs_requested)
        self.assertTrue(any(ref.endswith("/aborted") for ref in client.refs_requested))
        self.assertIn(
            f"repos/{args.repository}/git/commits/{args.commit}",
            client.json_requested,
        )
        self.assertIn(
            f"repos/{args.repository}/actions/runs/{args.phase1_run_id}",
            client.json_requested,
        )
        self.assertIn(
            f"repos/{args.repository}/actions/artifacts/{args.phase1_artifact_id}",
            client.json_requested,
        )
        self.assertIn(
            f"repos/{args.repository}/actions/runs/{args.host_run_id}",
            client.json_requested,
        )
        self.assertIn(
            f"repos/{args.repository}/rulesets/{args.ruleset_id}",
            client.json_requested,
        )
        self.assertEqual(len(loader_calls), 1)

    def test_remote_contract_rejects_each_protected_identity_drift(self) -> None:
        args = self.args(command="verify-remote")
        payload = {
            "ledger": {"namespace": "round9-eval-ledger/" + "a" * 64}
        }
        cases = (
            ("main", "main_sha", "0" * 40, "remote main"),
            ("tag", "tag_sha", "0" * 40, "tag reference"),
            ("tree", "tree_sha", "0" * 40, "candidate tree"),
            ("phase1", "phase1_head_sha", "0" * 40, "Phase 1 workflow"),
            (
                "artifact",
                "artifact_digest",
                "sha256:" + "0" * 64,
                "Phase 1 artifact",
            ),
            (
                "host",
                "host_head_sha",
                "0" * 40,
                "external Host workflow",
            ),
            ("ruleset", "ruleset_name", "wrong-ruleset", "ruleset"),
            ("aborted", "aborted_present", True, "aborted event"),
        )
        for label, field, value, message in cases:
            with self.subTest(label=label):
                client = FakeGitHubClient(args)
                setattr(client, field, value)
                with (
                    mock.patch.dict(os.environ, {"GH_TOKEN": "token"}),
                    mock.patch.object(contract, "GitHubClient", return_value=client),
                    mock.patch.object(contract, "validate_ledger_proof"),
                ):
                    with self.assertRaisesRegex(contract.ContractError, message):
                        contract.verify_remote(args, {}, payload, {})

    def test_remote_contract_rejects_malformed_or_incomplete_ruleset_rules(self) -> None:
        args = self.args(command="verify-remote")
        payload = {
            "ledger": {"namespace": "round9-eval-ledger/" + "a" * 64}
        }
        cases = (
            ("missing", None),
            ("not-list", {}),
            ("non-object-entry", ["deletion", {"type": "update"}]),
            ("missing-type", [{}, {"type": "update"}]),
            ("non-string-type", [{"type": "deletion"}, {"type": None}]),
            (
                "non-fast-forward-is-not-update",
                [{"type": "deletion"}, {"type": "non_fast_forward"}],
            ),
            (
                "update-without-deletion",
                [{"type": "update"}, {"type": "non_fast_forward"}],
            ),
            ("deletion-only", [{"type": "deletion"}]),
            ("update-only", [{"type": "update"}]),
        )
        for label, rules in cases:
            with self.subTest(label=label):
                client = FakeGitHubClient(args)
                client.ruleset_rules = rules
                with (
                    mock.patch.dict(os.environ, {"GH_TOKEN": "token"}),
                    mock.patch.object(contract, "GitHubClient", return_value=client),
                    mock.patch.object(contract, "validate_ledger_proof"),
                ):
                    with self.assertRaisesRegex(contract.ContractError, "ruleset"):
                        contract.verify_remote(args, {}, payload, {})

    def test_public_remote_verifier_rejects_redirect_without_forwarding_pat(self) -> None:
        client = contract.GitHubClient("public-verifier-secret")
        seen: list[object] = []
        headers = Message()
        headers["Location"] = "https://redirect.example.invalid/target"

        class Opener:
            def open(self, operation, **_kwargs):  # noqa: ANN001
                seen.append(operation)
                return FakeHTTPResponse(302, headers=headers)

        client._opener = Opener()  # type: ignore[assignment]
        with self.assertRaisesRegex(contract.ContractError, "redirect was rejected"):
            client.json("repos/example/project")
        self.assertEqual(len(seen), 1)
        self.assertEqual(
            seen[0].get_header("Authorization"), "Bearer public-verifier-secret"
        )


if __name__ == "__main__":
    unittest.main()
