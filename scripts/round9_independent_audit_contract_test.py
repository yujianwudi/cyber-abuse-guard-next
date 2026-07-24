#!/usr/bin/env python3

from __future__ import annotations

import argparse
import copy
from contextlib import redirect_stderr
import hashlib
import io
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import round9_independent_audit_contract as contract


class Fixture:
    repository = "example/cyber-abuse-guard"
    tag_object_sha = "1" * 40
    commit = "2" * 40
    tree = "3" * 40
    challenge = "4" * 64
    key_id = "round9-independent-auditor-key-v1"
    auditor_repository = "independent/audit-authority"
    auditor_workflow_name = "Round 9 independent candidate audit"
    auditor_workflow = ".github/workflows/round9-independent-audit.yml"
    auditor_ref = "refs/tags/round9-auditor-v1"
    auditor_workflow_sha = "5" * 40
    auditor_run_id = 101
    auditor_run_attempt = 2
    ledger_ruleset_id = 303
    ledger_ruleset_name = "round9-independent-audit-ledger-immutable"
    audit_artifact_id = 404
    audit_artifact_name = "round9-independent-audit-v0.16-rc.3"
    audit_artifact_digest = "sha256:" + "6" * 64

    def __init__(self, root: Path) -> None:
        self.root = root
        self.assets = root / "assets"
        self.assets.mkdir()
        self.public_key = root / "auditor-public-key.pem"
        self.public_key.write_bytes(b"synthetic-test-public-key\n")
        self.public_key_sha256 = hashlib.sha256(self.public_key.read_bytes()).hexdigest()
        self.host_public_key_sha256 = "7" * 64
        for index, name in enumerate(contract.ASSET_NAMES, start=1):
            if name in {"rc-release-manifest.json", "rc-release-manifest.json.sha256"}:
                continue
            (self.assets / name).write_bytes(
                f"synthetic-test-asset:{index}:{name}\n".encode("utf-8")
            )
        pre_manifest = self.asset_identities()
        manifest = self.manifest(pre_manifest)
        (self.assets / "rc-release-manifest.json").write_bytes(
            contract.canonical_bytes(manifest)
        )
        manifest_sha = hashlib.sha256(
            (self.assets / "rc-release-manifest.json").read_bytes()
        ).hexdigest()
        (self.assets / "rc-release-manifest.json.sha256").write_text(
            f"{manifest_sha}  rc-release-manifest.json\n", encoding="utf-8"
        )
        self.asset_identity = self.asset_identities()
        self.payload = self.evidence_payload()
        self.envelope = self.signed(self.payload)
        self.proof = self.ledger_proof()
        self.evidence_path = root / "round9-independent-audit.json"
        self.proof_path = root / "round9-independent-audit-ledger-proof.json"
        self.write_evidence()
        self.write_proof()

    def asset_identities(self) -> dict[str, dict[str, object]]:
        result: dict[str, dict[str, object]] = {}
        for name in contract.ASSET_NAMES:
            path = self.assets / name
            if not path.exists():
                continue
            raw = path.read_bytes()
            result[name] = {
                "bytes": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(),
            }
        return result

    def manifest(self, assets: dict[str, dict[str, object]]) -> dict:
        return {
            "schema_version": 6,
            "release_phase": "publish",
            "publish_rc_release": True,
            "source_version": contract.SOURCE_VERSION,
            "artifact_version": contract.ARTIFACT_VERSION,
            "tag": contract.TAG,
            "tag_object": self.tag_object_sha,
            "commit": self.commit,
            "tree": self.tree,
            "artifact_count": len(contract.ASSET_NAMES),
            "independent_audit": "NOT_PROVIDED",
            "independent_audit_requirement": "required",
            "workflow": {
                "repository": self.repository,
                "ref": f"{self.repository}/{contract.RELEASE_WORKFLOW}@refs/tags/{contract.TAG}",
                "sha": self.commit,
                "dispatch_ref": f"refs/tags/{contract.TAG}",
            },
            "artifacts": {
                "so": {
                    "name": "cyber-abuse-guard-v0.16-rc.3.so",
                    "sha256": assets["cyber-abuse-guard-v0.16-rc.3.so"]["sha256"],
                },
                "build_metadata_sha256": assets["build-metadata.json"]["sha256"],
                "ruleset_manifest_sha256": assets["ruleset-manifest.json"]["sha256"],
                "external_evaluation": {
                    "name": "round9-external-evaluation.json",
                    "sha256": assets["round9-external-evaluation.json"]["sha256"],
                },
                "external_ledger_proof": {
                    "name": "round9-external-ledger-proof.json",
                    "sha256": assets["round9-external-ledger-proof.json"]["sha256"],
                },
            },
            "round9": {
                "release_lane": "round9",
                "classifier": {
                    "version": "classifier-policy-v8",
                    "sha256": "8" * 64,
                },
                "ruleset": {"version": "1.0.10", "sha256": "9" * 64},
                "release": {
                    "tag": contract.TAG,
                    "title": contract.RELEASE_TITLE,
                    "body": "Public adversarial v11; latest=false; independent audit required",
                    "publication_permitted": True,
                    "draft": False,
                    "prerelease": True,
                    "latest": False,
                    "asset_allowlist": list(contract.ASSET_NAMES),
                },
            },
        }

    @staticmethod
    def signed(payload: dict) -> dict:
        return {
            "schema": contract.SIGNED_ENVELOPE_SCHEMA,
            "payload": payload,
            "signature": {
                "algorithm": "ed25519",
                "key_id": Fixture.key_id,
                "value_base64": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==",
            },
        }

    def candidate(self) -> dict:
        manifest = self.asset_identity["rc-release-manifest.json"]
        return {
            "repository": self.repository,
            "tag": contract.TAG,
            "tag_object_sha": self.tag_object_sha,
            "source_version": contract.SOURCE_VERSION,
            "artifact_version": contract.ARTIFACT_VERSION,
            "commit": self.commit,
            "tree": self.tree,
            "release_manifest_bytes": manifest["bytes"],
            "release_manifest_sha256": manifest["sha256"],
            "so_sha256": self.asset_identity["cyber-abuse-guard-v0.16-rc.3.so"][
                "sha256"
            ],
            "build_metadata_sha256": self.asset_identity["build-metadata.json"][
                "sha256"
            ],
            "ruleset_manifest_sha256": self.asset_identity["ruleset-manifest.json"][
                "sha256"
            ],
            "classifier_policy_version": "classifier-policy-v8",
            "classifier_policy_sha256": "8" * 64,
            "ruleset_version": "1.0.10",
            "ruleset_sha256": "9" * 64,
            "external_evaluation_sha256": self.asset_identity[
                "round9-external-evaluation.json"
            ]["sha256"],
            "external_ledger_proof_sha256": self.asset_identity[
                "round9-external-ledger-proof.json"
            ]["sha256"],
        }

    def audit(self) -> dict:
        return {
            "auditor_id": "independent-auditor-v1",
            "auditor_repository": self.auditor_repository,
            "workflow_name": self.auditor_workflow_name,
            "workflow_path": self.auditor_workflow,
            "workflow_ref": self.auditor_ref,
            "workflow_sha": self.auditor_workflow_sha,
            "run_id": self.auditor_run_id,
            "run_attempt": self.auditor_run_attempt,
            "key_id": self.key_id,
            "public_key_sha256": self.public_key_sha256,
            "challenge_sha256": contract.challenge_sha256(self.challenge),
            "independent_from_candidate_builder": True,
            "independent_from_host_evaluator": True,
            "restricted_material_zero_access_claim": False,
            "production_accessed": False,
            "real_provider_contacted": False,
        }

    def provenance(self, name: str) -> dict:
        workflow = (
            contract.HOST_WORKFLOW
            if name in contract.HOST_ASSET_NAMES
            else contract.RELEASE_WORKFLOW
        )
        return {
            "state": "VERIFIED",
            "predicate_type": contract.PROVENANCE_PREDICATE,
            "signer_repository": self.repository,
            "signer_workflow": workflow,
            "signer_digest": self.commit,
            "source_ref": f"refs/tags/{contract.TAG}",
            "source_digest": self.commit,
        }

    def evidence_payload(self) -> dict:
        candidate = self.candidate()
        namespace = contract.ledger_namespace(
            self.commit, contract.challenge_sha256(self.challenge)
        )
        return {
            "schema": contract.EVIDENCE_SCHEMA,
            "state": "PASS",
            "candidate": candidate,
            "audit": self.audit(),
            "assets": [
                {
                    "name": name,
                    "bytes": self.asset_identity[name]["bytes"],
                    "sha256": self.asset_identity[name]["sha256"],
                    "provenance": self.provenance(name),
                }
                for name in contract.ASSET_NAMES
            ],
            "findings": {
                "decision": "PASS",
                "scope": [
                    "source",
                    "artifacts",
                    "supply_chain",
                    "external_evaluation",
                    "release_contract",
                ],
                "source_review": {
                    "state": "PASS",
                    "open_critical": 0,
                    "open_high": 0,
                },
                "artifact_review": {
                    "state": "PASS",
                    "assets_verified": 19,
                    "attestations_verified": 19,
                },
                "external_evaluation_review": {
                    "state": "PASS",
                    "evaluation_sha256": candidate["external_evaluation_sha256"],
                    "ledger_proof_sha256": candidate[
                        "external_ledger_proof_sha256"
                    ],
                },
                "release_contract_review": {
                    "state": "PASS",
                    "manifest_sha256": candidate["release_manifest_sha256"],
                    "asset_allowlist_sha256": contract.sha256_bytes(
                        contract.canonical_bytes(list(contract.ASSET_NAMES))
                    ),
                },
            },
            "privacy": {
                "raw_prompts_in_result": False,
                "raw_responses_in_result": False,
                "request_bodies_in_result": False,
                "restricted_material_in_result": False,
                "production_data_in_result": False,
            },
            "ledger": {
                "repository": self.repository,
                "namespace": namespace,
                "ruleset_id": self.ledger_ruleset_id,
                "ruleset_name": self.ledger_ruleset_name,
                "reserved_ref": contract.ledger_ref(namespace, "reserved"),
                "started_ref": contract.ledger_ref(namespace, "started"),
                "result_ref": contract.ledger_ref(namespace, "result"),
            },
        }

    def event_payload(
        self,
        event: str,
        sequence: int,
        created_at: str,
        previous: str | None,
        evidence_digest: str,
    ) -> dict:
        return {
            "schema": contract.LEDGER_EVENT_SCHEMA,
            "event": event,
            "sequence": sequence,
            "created_at": created_at,
            "repository": self.repository,
            "namespace": self.payload["ledger"]["namespace"],
            "candidate": {
                "repository": self.repository,
                "tag": contract.TAG,
                "tag_object_sha": self.tag_object_sha,
                "commit": self.commit,
                "tree": self.tree,
            },
            "audit": {
                "auditor_repository": self.auditor_repository,
                "workflow_path": self.auditor_workflow,
                "workflow_sha": self.auditor_workflow_sha,
                "run_id": self.auditor_run_id,
                "run_attempt": self.auditor_run_attempt,
                "key_id": self.key_id,
            },
            "challenge_sha256": self.payload["audit"]["challenge_sha256"],
            "previous_event_envelope_sha256": previous,
            "evidence_envelope_sha256": evidence_digest if event == "result" else None,
        }

    def ledger_proof(self) -> dict:
        evidence_digest = contract.sha256_bytes(contract.canonical_bytes(self.envelope))
        events: dict[str, dict] = {}
        previous: str | None = None
        for sequence, (event, created_at) in enumerate(
            (
                ("reserved", "2026-07-24T01:00:00Z"),
                ("started", "2026-07-24T01:00:01Z"),
                ("result", "2026-07-24T01:00:02Z"),
            ),
            start=1,
        ):
            envelope = self.signed(
                self.event_payload(
                    event, sequence, created_at, previous, evidence_digest
                )
            )
            message = contract.canonical_bytes(envelope)
            events[event] = {
                "ref": self.payload["ledger"][f"{event}_ref"],
                "tag_object_sha": str(sequence + 6) * 40,
                "message_sha256": contract.sha256_bytes(message),
                "envelope": envelope,
            }
            previous = contract.sha256_bytes(message)
        return {
            "schema": contract.LEDGER_PROOF_SCHEMA,
            "repository": self.repository,
            "namespace": self.payload["ledger"]["namespace"],
            "ruleset_id": self.ledger_ruleset_id,
            "ruleset_name": self.ledger_ruleset_name,
            "refs": events,
        }

    def write_evidence(self) -> None:
        self.evidence_path.write_bytes(contract.canonical_bytes(self.envelope))

    def write_proof(self) -> None:
        self.proof_path.write_bytes(contract.canonical_bytes(self.proof))

    def args(self, command: str = "validate") -> argparse.Namespace:
        values = dict(
            command=command,
            evidence=str(self.evidence_path),
            proof=str(self.proof_path),
            asset_dir=str(self.assets),
            public_key=str(self.public_key),
            public_key_sha256=self.public_key_sha256,
            host_evaluator_public_key_sha256=self.host_public_key_sha256,
            key_id=self.key_id,
            repository=self.repository,
            tag=contract.TAG,
            tag_object_sha=self.tag_object_sha,
            commit=self.commit,
            tree=self.tree,
            challenge=self.challenge,
            auditor_repository=self.auditor_repository,
            auditor_workflow_name=self.auditor_workflow_name,
            auditor_workflow=self.auditor_workflow,
            auditor_ref=self.auditor_ref,
            auditor_workflow_sha=self.auditor_workflow_sha,
            auditor_run_id=self.auditor_run_id,
            auditor_run_attempt=self.auditor_run_attempt,
            ledger_ruleset_id=self.ledger_ruleset_id,
            ledger_ruleset_name=self.ledger_ruleset_name,
            openssl="openssl",
        )
        if command == "verify-remote":
            values.update(
                audit_artifact_id=self.audit_artifact_id,
                audit_artifact_name=self.audit_artifact_name,
                audit_artifact_digest=self.audit_artifact_digest,
            )
        return argparse.Namespace(**values)


class FakeGitHubClient:
    def __init__(self, fixture: Fixture) -> None:
        self.fixture = fixture
        self.main_sha = fixture.commit
        self.tag_sha = fixture.tag_object_sha
        self.tree_sha = fixture.tree
        self.audit_head_sha = fixture.auditor_workflow_sha
        self.artifact_digest = fixture.audit_artifact_digest
        self.ruleset_rules: object = [{"type": "deletion"}, {"type": "update"}]
        self.aborted_present = False
        self.refs_requested: list[str] = []
        self.json_requested: list[str] = []
        self.ledger_by_ref = {
            item["ref"]: item for item in fixture.proof["refs"].values()
        }

    def ref(
        self, repository: str, full_ref: str, *, absent_ok: bool = False
    ) -> dict | None:
        del absent_ok
        self.refs_requested.append(full_ref)
        if repository != self.fixture.repository:
            raise AssertionError(repository)
        if full_ref == "refs/heads/main":
            return {"object": {"type": "commit", "sha": self.main_sha}}
        if full_ref == f"refs/tags/{contract.TAG}":
            return {"object": {"type": "tag", "sha": self.tag_sha}}
        if full_ref.endswith("/aborted"):
            return (
                {"object": {"type": "tag", "sha": "f" * 40}}
                if self.aborted_present
                else None
            )
        item = self.ledger_by_ref.get(full_ref)
        if item is not None:
            return {
                "object": {"type": "tag", "sha": item["tag_object_sha"]}
            }
        raise AssertionError(full_ref)

    def json(self, endpoint: str) -> dict:
        self.json_requested.append(endpoint)
        candidate_prefix = f"repos/{self.fixture.repository}/"
        auditor_prefix = f"repos/{self.fixture.auditor_repository}/"
        if endpoint == candidate_prefix + f"git/tags/{self.fixture.tag_object_sha}":
            return {"object": {"type": "commit", "sha": self.fixture.commit}}
        if endpoint == candidate_prefix + f"git/commits/{self.fixture.commit}":
            return {"tree": {"sha": self.tree_sha}}
        if endpoint == auditor_prefix + f"actions/runs/{self.fixture.auditor_run_id}":
            return {
                "id": self.fixture.auditor_run_id,
                "run_attempt": self.fixture.auditor_run_attempt,
                "name": self.fixture.auditor_workflow_name,
                "path": self.fixture.auditor_workflow,
                "head_sha": self.audit_head_sha,
                "event": "workflow_dispatch",
                "status": "completed",
                "conclusion": "success",
                "repository": {"full_name": self.fixture.auditor_repository},
            }
        if endpoint == auditor_prefix + f"actions/artifacts/{self.fixture.audit_artifact_id}":
            return {
                "id": self.fixture.audit_artifact_id,
                "name": self.fixture.audit_artifact_name,
                "digest": self.artifact_digest,
                "expired": False,
                "workflow_run": {"id": self.fixture.auditor_run_id},
            }
        if endpoint == candidate_prefix + f"rulesets/{self.fixture.ledger_ruleset_id}":
            return {
                "id": self.fixture.ledger_ruleset_id,
                "name": self.fixture.ledger_ruleset_name,
                "target": "tag",
                "enforcement": "active",
                "bypass_actors": [],
                "conditions": {
                    "ref_name": {
                        "include": [
                            "refs/tags/round9-independent-audit-ledger/**"
                        ],
                        "exclude": [],
                    }
                },
                "rules": copy.deepcopy(self.ruleset_rules),
            }
        for item in self.fixture.proof["refs"].values():
            if endpoint == candidate_prefix + f"git/tags/{item['tag_object_sha']}":
                return {
                    "object": {"type": "commit", "sha": self.fixture.commit},
                    "message": contract.canonical_bytes(item["envelope"]).decode(
                        "utf-8"
                    ),
                }
        raise AssertionError(endpoint)


class IndependentAuditContractTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="cag-r9-audit-test-")
        self.fixture = Fixture(Path(self.temporary.name))

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def load(self, args: argparse.Namespace | None = None):
        with mock.patch.object(contract, "openssl_verify") as verify:
            result = contract.load_contract(args or self.fixture.args())
        self.assertEqual(verify.call_count, 4)
        return result

    def test_valid_offline_contract_binds_schema_identity_assets_and_ledger(self) -> None:
        evidence, payload, proof = self.load()
        self.assertEqual(payload["schema"], contract.EVIDENCE_SCHEMA)
        self.assertEqual(len(payload["assets"]), 19)
        self.assertEqual(proof["schema"], contract.LEDGER_PROOF_SCHEMA)
        self.assertEqual(evidence, self.fixture.envelope)

    def test_missing_evidence_is_not_provided_not_pass(self) -> None:
        args = self.fixture.args()
        args.evidence = ""
        with self.assertRaisesRegex(contract.EvidenceNotProvided, "NOT_PROVIDED"):
            contract.load_contract(args)
        stream = io.StringIO()
        parser = mock.Mock()
        parser.parse_args.return_value = args
        with mock.patch.object(contract, "parser", return_value=parser), redirect_stderr(stream):
            self.assertEqual(contract.main([]), 3)
        self.assertIn("NOT_PROVIDED", stream.getvalue())
        self.assertNotIn("PASS", stream.getvalue())

    def test_title_host_or_boolean_pass_cannot_replace_signed_exact_evidence(self) -> None:
        cases = {
            "title-only": {
                "schema": contract.EVIDENCE_SCHEMA,
                "state": "PASS",
                "title": contract.RELEASE_TITLE,
            },
            "host-only": {
                "schema": "round9-external-evaluation/v3",
                "state": "PASS",
            },
            "boolean-pass": {"schema": contract.EVIDENCE_SCHEMA, "state": "PASS"},
        }
        for label, payload in cases.items():
            with self.subTest(label=label):
                self.fixture.envelope["payload"] = payload
                self.fixture.write_evidence()
                with mock.patch.object(contract, "openssl_verify"):
                    with self.assertRaises(contract.ContractError):
                        contract.load_contract(self.fixture.args())

    def test_unknown_fields_identity_drift_and_zero_access_claim_fail_closed(self) -> None:
        mutations = (
            ("unknown", lambda value: value.update({"approval": True})),
            (
                "candidate-commit",
                lambda value: value["candidate"].update({"commit": "0" * 40}),
            ),
            (
                "workflow",
                lambda value: value["audit"].update(
                    {"workflow_path": contract.HOST_WORKFLOW}
                ),
            ),
            (
                "restricted-zero-access",
                lambda value: value["audit"].update(
                    {"restricted_material_zero_access_claim": True}
                ),
            ),
            (
                "privacy",
                lambda value: value["privacy"].update(
                    {"raw_prompts_in_result": True}
                ),
            ),
        )
        for label, mutate in mutations:
            with self.subTest(label=label):
                payload = copy.deepcopy(self.fixture.payload)
                mutate(payload)
                self.fixture.envelope["payload"] = payload
                self.fixture.write_evidence()
                with mock.patch.object(contract, "openssl_verify"):
                    with self.assertRaises(contract.ContractError):
                        contract.load_contract(self.fixture.args())

    def test_asset_substitution_extra_asset_and_attestation_signer_drift_fail(self) -> None:
        target = self.fixture.assets / "sbom.cdx.json"
        target.write_bytes(b"substituted\n")
        with mock.patch.object(contract, "openssl_verify"):
            with self.assertRaisesRegex(contract.ContractError, "bytes or SHA-256"):
                contract.load_contract(self.fixture.args())

        target.write_bytes(b"synthetic-test-asset:19:sbom.cdx.json\n")
        extra = self.fixture.assets / "approval.txt"
        extra.write_text("PASS\n", encoding="utf-8")
        with mock.patch.object(contract, "openssl_verify"):
            with self.assertRaisesRegex(contract.ContractError, "exact 19 assets"):
                contract.load_contract(self.fixture.args())
        extra.unlink()

        payload = copy.deepcopy(self.fixture.payload)
        payload["assets"][0]["provenance"]["signer_workflow"] = contract.HOST_WORKFLOW
        self.fixture.envelope["payload"] = payload
        self.fixture.write_evidence()
        with mock.patch.object(contract, "openssl_verify"):
            with self.assertRaisesRegex(contract.ContractError, "attestation identity"):
                contract.load_contract(self.fixture.args())

    @unittest.skipIf(os.name == "nt", "symlink creation requires elevated Windows privileges")
    def test_asset_symlink_is_rejected(self) -> None:
        target = self.fixture.assets / "sbom.cdx.json"
        raw = target.read_bytes()
        target.unlink()
        backing = self.fixture.root / "sbom-real.json"
        backing.write_bytes(raw)
        target.symlink_to(backing)
        with mock.patch.object(contract, "openssl_verify"):
            with self.assertRaisesRegex(contract.ContractError, "non-symlink"):
                contract.load_contract(self.fixture.args())

    def test_manifest_self_approval_and_release_title_drift_are_rejected(self) -> None:
        manifest_path = self.fixture.assets / "rc-release-manifest.json"
        manifest = contract.load_canonical_json(manifest_path, "manifest")
        for label, mutate in (
            (
                "self-approval",
                lambda value: value.update({"independent_audit": "PASS"}),
            ),
            (
                "title",
                lambda value: value["round9"]["release"].update(
                    {"title": "independent audit approved"}
                ),
            ),
        ):
            with self.subTest(label=label):
                changed = copy.deepcopy(manifest)
                mutate(changed)
                manifest_path.write_bytes(contract.canonical_bytes(changed))
                with mock.patch.object(contract, "openssl_verify"):
                    with self.assertRaises(contract.ContractError):
                        contract.load_contract(self.fixture.args())
        manifest_path.write_bytes(contract.canonical_bytes(manifest))

    def test_key_independence_and_signature_contract_are_enforced(self) -> None:
        args = self.fixture.args()
        args.host_evaluator_public_key_sha256 = args.public_key_sha256
        with mock.patch.object(contract, "openssl_verify"):
            with self.assertRaisesRegex(contract.ContractError, "must differ"):
                contract.load_contract(args)

        envelope = copy.deepcopy(self.fixture.envelope)
        envelope["signature"]["value_base64"] = "not-base64"
        with self.assertRaisesRegex(contract.ContractError, "base64"):
            contract.verify_signed_envelope(
                envelope,
                self.fixture.public_key,
                self.fixture.key_id,
                expected_payload_schema=contract.EVIDENCE_SCHEMA,
            )

        with mock.patch.object(
            contract,
            "openssl_verify",
            side_effect=contract.ContractError("invalid signature"),
        ):
            with self.assertRaisesRegex(contract.ContractError, "invalid signature"):
                contract.load_contract(self.fixture.args())

    def test_ledger_chain_digest_order_and_unknown_fields_are_rejected(self) -> None:
        mutations = (
            (
                "chain",
                lambda proof: proof["refs"]["started"]["envelope"]["payload"].update(
                    {"previous_event_envelope_sha256": "0" * 64}
                ),
            ),
            (
                "result-digest",
                lambda proof: proof["refs"]["result"]["envelope"]["payload"].update(
                    {"evidence_envelope_sha256": "0" * 64}
                ),
            ),
            (
                "time-order",
                lambda proof: proof["refs"]["result"]["envelope"]["payload"].update(
                    {"created_at": "2026-07-24T01:00:00Z"}
                ),
            ),
            (
                "unknown",
                lambda proof: proof.update({"approval": "PASS"}),
            ),
        )
        for label, mutate in mutations:
            with self.subTest(label=label):
                self.fixture.proof = self.fixture.ledger_proof()
                mutate(self.fixture.proof)
                # Rebind the message digest so each case reaches its intended invariant.
                for item in self.fixture.proof["refs"].values():
                    item["message_sha256"] = contract.sha256_bytes(
                        contract.canonical_bytes(item["envelope"])
                    )
                self.fixture.write_proof()
                with mock.patch.object(contract, "openssl_verify"):
                    with self.assertRaises(contract.ContractError):
                        contract.load_contract(self.fixture.args())

    def test_remote_contract_binds_candidate_auditor_artifact_ruleset_and_ledger(self) -> None:
        args = self.fixture.args("verify-remote")
        client = FakeGitHubClient(self.fixture)
        with (
            mock.patch.dict(os.environ, {"GH_TOKEN": "token"}),
            mock.patch.object(contract, "GitHubClient", return_value=client),
            mock.patch.object(contract, "openssl_verify"),
        ):
            evidence, payload, proof = contract.load_contract(args)
            contract.verify_remote(args, evidence, payload, proof)
        self.assertIn("refs/heads/main", client.refs_requested)
        self.assertIn(f"refs/tags/{contract.TAG}", client.refs_requested)
        self.assertTrue(any(item.endswith("/aborted") for item in client.refs_requested))
        self.assertTrue(all(item["ref"] in client.refs_requested for item in self.fixture.proof["refs"].values()))

    def test_remote_contract_rejects_identity_drift_and_aborted_ledger(self) -> None:
        args = self.fixture.args("verify-remote")
        cases = (
            ("main", "main_sha", "0" * 40, "remote main"),
            ("tag", "tag_sha", "0" * 40, "candidate tag"),
            ("tree", "tree_sha", "0" * 40, "candidate tree"),
            (
                "audit-run",
                "audit_head_sha",
                "0" * 40,
                "workflow run",
            ),
            (
                "artifact",
                "artifact_digest",
                "sha256:" + "0" * 64,
                "artifact identity",
            ),
            ("aborted", "aborted_present", True, "aborted event"),
        )
        for label, field, value, message in cases:
            with self.subTest(label=label):
                client = FakeGitHubClient(self.fixture)
                setattr(client, field, value)
                with (
                    mock.patch.dict(os.environ, {"GH_TOKEN": "token"}),
                    mock.patch.object(contract, "GitHubClient", return_value=client),
                    mock.patch.object(contract, "openssl_verify"),
                ):
                    evidence, payload, proof = contract.load_contract(args)
                    with self.assertRaisesRegex(contract.ContractError, message):
                        contract.verify_remote(args, evidence, payload, proof)

    def test_remote_ruleset_requires_well_formed_deletion_and_update_rules(self) -> None:
        args = self.fixture.args("verify-remote")
        cases = (
            None,
            {},
            ["deletion", {"type": "update"}],
            [{}, {"type": "update"}],
            [{"type": "deletion"}, {"type": None}],
            [{"type": "deletion"}, {"type": "non_fast_forward"}],
            [{"type": "update"}, {"type": "non_fast_forward"}],
            [{"type": "deletion"}],
            [{"type": "update"}],
        )
        for rules in cases:
            with self.subTest(rules=rules):
                client = FakeGitHubClient(self.fixture)
                client.ruleset_rules = rules
                with (
                    mock.patch.dict(os.environ, {"GH_TOKEN": "token"}),
                    mock.patch.object(contract, "GitHubClient", return_value=client),
                    mock.patch.object(contract, "openssl_verify"),
                ):
                    evidence, payload, proof = contract.load_contract(args)
                    with self.assertRaisesRegex(contract.ContractError, "ruleset"):
                        contract.verify_remote(args, evidence, payload, proof)


if __name__ == "__main__":
    unittest.main()
