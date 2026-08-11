from __future__ import annotations

import copy
import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
TOOL = HERE.parent
sys.path.insert(0, str(TOOL))

import make_run_config
from audit_contract import (
    CAG_SO_NAME,
    CAG_SOURCE_VERSION,
    CANDIDATE_ARTIFACT_NAME,
    CANDIDATE_MANIFEST_SCHEMA,
    CANDIDATE_MANIFEST_STATUS,
    CANDIDATE_REPOSITORY,
    CANDIDATE_WORKFLOW_NAME,
    CANDIDATE_WORKFLOW_PATH,
    ContractError,
    candidate_identity,
    canonical_bytes,
    sha256_bytes,
)


COMMIT = "1" * 40
TREE = "2" * 40
VERSION = CAG_SOURCE_VERSION
SO_NAME = CAG_SO_NAME


def candidate_manifest(so_sha256: str) -> dict[str, object]:
    names = (
        SO_NAME,
        SO_NAME + ".sha256",
        f"cyber-abuse-guard_{VERSION}_linux_amd64.zip",
        "build-metadata.json",
        "checksums.txt",
        "ruleset-manifest.json",
        "ruleset.sha256",
        "sbom.cdx.json",
    )
    artifacts = [
        {
            "bytes": 100 + index,
            "name": name,
            "sha256": so_sha256 if name == SO_NAME else f"{index:x}" * 64,
        }
        for index, name in enumerate(names, start=1)
    ]
    return {
        "artifacts": artifacts,
        "commit": COMMIT,
        "dirty": False,
        "event": "pull_request",
        "head_branch": "feature/candidate-provenance",
        "head_sha": "3" * 40,
        "repository": CANDIDATE_REPOSITORY,
        "run_attempt": "1",
        "run_id": "123456789",
        "schema": CANDIDATE_MANIFEST_SCHEMA,
        "status": CANDIDATE_MANIFEST_STATUS,
        "tree": TREE,
        "version": VERSION,
        "workflow_name": CANDIDATE_WORKFLOW_NAME,
        "workflow_path": CANDIDATE_WORKFLOW_PATH,
    }


class MakeRunConfigTests(unittest.TestCase):
    def test_supplemental_zip_policy_and_manifest_cli_inputs_are_required(self) -> None:
        argv = [
            "--output", "run-config.json",
            "--run-id", "unit-run",
            "--manifest", "corpus-manifest.json",
            "--supplemental-archive", "operator.zip",
            "--supplemental-zip-policy", "supplemental-zip-policy.json",
            "--supplemental-zip-manifest", "supplemental-zip-manifest.json",
            "--evidence-directory", "evidence",
            "--cag-repository", "cag",
            "--cag-so", CAG_SO_NAME,
            "--candidate-manifest", "audit-candidate-manifest.json",
            "--candidate-artifact-id", "1",
            "--candidate-artifact-name", CANDIDATE_ARTIFACT_NAME,
            "--candidate-artifact-digest", "sha256:" + "1" * 64,
            "--cpa-official-asset", "cpa.tar.gz",
            "--cpa-official-asset-sha256", "2" * 64,
            "--cpa-binary-path", "/CLIProxyAPI",
            "--cpa-binary-sha256", "3" * 64,
            "--cpa-image-ref", "registry/cpa@sha256:" + "4" * 64,
            "--cpa-image-id", "sha256:" + "5" * 64,
            "--mock-image-ref", "registry/mock@sha256:" + "6" * 64,
            "--mock-image-id", "sha256:" + "7" * 64,
        ]
        parsed = make_run_config.parse_args(argv)
        self.assertEqual(parsed.supplemental_zip, Path("operator.zip"))
        self.assertEqual(
            parsed.supplemental_zip_policy, Path("supplemental-zip-policy.json")
        )
        self.assertEqual(
            parsed.supplemental_zip_manifest,
            Path("supplemental-zip-manifest.json"),
        )
        for option in (
            "--supplemental-archive",
            "--supplemental-zip-policy",
            "--supplemental-zip-manifest",
        ):
            index = argv.index(option)
            missing = argv[:index] + argv[index + 2 :]
            with (
                self.subTest(option=option),
                contextlib.redirect_stderr(io.StringIO()),
                self.assertRaises(SystemExit),
            ):
                make_run_config.parse_args(missing)

    def test_ci_manifest_uses_context_and_post_upload_external_admission(self) -> None:
        workflow = (
            TOOL.parents[1] / ".github" / "workflows" / "ci.yml"
        ).read_text("utf-8")
        seal_start = workflow.index("- name: Seal exact-merge audit candidate manifest")
        upload_start = workflow.index("- name: Upload exact-merge clean audit candidate")
        admission_start = workflow.index(
            "- name: Report post-upload candidate artifact admission coordinates"
        )
        self.assertLess(seal_start, upload_start)
        self.assertLess(upload_start, admission_start)
        seal = workflow[seal_start:upload_start]
        admission = workflow[admission_start:]
        self.assertIn("jq -cS -n", seal)
        for token in (
            'case "$GITHUB_EVENT_NAME" in',
            'candidate_head_branch="$GITHUB_HEAD_REF"',
            "'.pull_request.head.sha'",
            'candidate_head_sha="$GITHUB_SHA"',
            'candidate_repository="$GITHUB_REPOSITORY"',
            'candidate_workflow_name="$GITHUB_WORKFLOW"',
            'candidate_workflow_ref="$GITHUB_WORKFLOW_REF"',
            "--arg head_branch",
            "--arg head_sha",
            "--arg repository",
            "--arg workflow_name",
            "--arg workflow_path",
        ):
            with self.subTest(token=token):
                self.assertIn(token, seal)
        self.assertNotIn("artifact-digest", seal)
        self.assertNotIn("artifact-id", seal)
        self.assertIn(
            "steps.upload_audit_candidate.outputs.artifact-digest", admission
        )
        self.assertIn("steps.upload_audit_candidate.outputs.artifact-id", admission)

    def test_require_git_clean_includes_and_rejects_untracked_files(self) -> None:
        completed = subprocess.CompletedProcess([], 0, stdout="?? local.txt\n", stderr="")
        with mock.patch.object(make_run_config.subprocess, "run", return_value=completed) as run:
            with self.assertRaisesRegex(RuntimeError, "untracked"):
                make_run_config.require_git_clean(Path("/tmp/repository"))
        self.assertIn("--untracked-files=all", run.call_args.args[0])

    def test_validated_candidate_returns_bound_identity_and_canonical_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = root / "repository"
            repository.mkdir()
            cag_so = root / SO_NAME
            cag_so.write_bytes(b"exact candidate SO")
            so_sha256 = sha256_bytes(cag_so.read_bytes())
            manifest_path = root / "audit-candidate-manifest.json"
            manifest_path.write_bytes(
                canonical_bytes(candidate_manifest(so_sha256)) + b"\n"
            )

            with mock.patch.object(make_run_config, "require_git_clean") as clean, mock.patch.object(
                make_run_config,
                "git_id",
                side_effect=lambda _repository, expression: (
                    COMMIT if expression == "HEAD^{commit}" else TREE
                ),
            ):
                identity, validated_manifest, manifest_raw = make_run_config.validated_cag_candidate(
                    repository, cag_so, manifest_path
                )

        clean.assert_called_once_with(repository)
        self.assertEqual(
            identity,
            {
                "commit": COMMIT,
                "so_name": SO_NAME,
                "so_sha256": so_sha256,
                "source_version": VERSION,
                "tree": TREE,
            },
        )
        self.assertEqual(validated_manifest, candidate_manifest(so_sha256))
        self.assertEqual(manifest_raw, canonical_bytes(validated_manifest) + b"\n")
        provenance = candidate_identity(
            validated_manifest,
            manifest_raw,
            cag_identity=identity,
            artifact_id="456789",
            artifact_name=CANDIDATE_ARTIFACT_NAME,
            artifact_digest="sha256:" + "a" * 64,
        )
        self.assertEqual(provenance["manifest_sha256"], sha256_bytes(manifest_raw))
        self.assertEqual(provenance["artifact"]["id"], "456789")
        self.assertEqual(
            provenance["so"], {"name": SO_NAME, "sha256": so_sha256}
        )
        for field, drifted_value in (
            ("commit", "3" * 40),
            ("tree", "4" * 40),
            ("source_version", "9.9.9"),
            ("so_name", "lookalike.so"),
            ("so_sha256", "5" * 64),
        ):
            drifted_cag_identity = copy.deepcopy(identity)
            drifted_cag_identity[field] = drifted_value
            with self.subTest(cag_identity_drift=field), self.assertRaisesRegex(
                ContractError, "candidate identity"
            ):
                candidate_identity(
                    validated_manifest,
                    manifest_raw,
                    cag_identity=drifted_cag_identity,
                    artifact_id="456789",
                    artifact_name=CANDIDATE_ARTIFACT_NAME,
                    artifact_digest="sha256:" + "a" * 64,
                )
        for label, artifact in {
            "id": {"artifact_id": "0"},
            "name": {"artifact_name": "lookalike-candidate"},
            "digest": {"artifact_digest": "a" * 64},
        }.items():
            arguments = {
                "cag_identity": identity,
                "artifact_id": "456789",
                "artifact_name": CANDIDATE_ARTIFACT_NAME,
                "artifact_digest": "sha256:" + "a" * 64,
                **artifact,
            }
            with self.subTest(label=label), self.assertRaises(ContractError):
                candidate_identity(validated_manifest, manifest_raw, **arguments)

        missing_so = copy.deepcopy(validated_manifest)
        missing_so["artifacts"] = [
            item
            for item in missing_so["artifacts"]
            if item["name"] != CAG_SO_NAME
        ]
        with self.subTest(label="missing selected CAG SO"), self.assertRaisesRegex(
            ContractError, "^candidate manifest does not bind the selected CAG SO$"
        ):
            candidate_identity(
                missing_so,
                canonical_bytes(missing_so) + b"\n",
                cag_identity=identity,
                artifact_id="456789",
                artifact_name=CANDIDATE_ARTIFACT_NAME,
                artifact_digest="sha256:" + "a" * 64,
            )

    def test_candidate_manifest_must_bind_clean_exact_candidate_and_so_name(self) -> None:
        mutations = {
            "schema": lambda value: value.__setitem__("schema", "wrong"),
            "status": lambda value: value.__setitem__("status", "RELEASED"),
            "dirty": lambda value: value.__setitem__("dirty", True),
            "commit": lambda value: value.__setitem__("commit", "3" * 40),
            "tree": lambda value: value.__setitem__("tree", "4" * 40),
            "version": lambda value: value.__setitem__("version", "0.16"),
            "repository": lambda value: value.__setitem__("repository", "other/repo"),
            "workflow_name": lambda value: value.__setitem__("workflow_name", "Other"),
            "workflow_path": lambda value: value.__setitem__("workflow_path", ".github/workflows/other.yml"),
            "run_id": lambda value: value.__setitem__("run_id", "0"),
            "run_attempt": lambda value: value.__setitem__("run_attempt", "unknown"),
            "head_sha": lambda value: value.__setitem__("head_sha", "not-a-sha"),
            "head_branch": lambda value: value.__setitem__(
                "head_branch", "feature/../unreviewed"
            ),
            "so_sha256": lambda value: value["artifacts"][0].__setitem__(
                "sha256", "5" * 64
            ),
            "eight_file_closure": lambda value: value["artifacts"].pop(),
            "unknown_field": lambda value: value.__setitem__("artifact_digest", "fake"),
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = root / "repository"
            repository.mkdir()
            cag_so = root / SO_NAME
            cag_so.write_bytes(b"exact candidate SO")
            so_sha256 = sha256_bytes(cag_so.read_bytes())
            with mock.patch.object(make_run_config, "require_git_clean"), mock.patch.object(
                make_run_config,
                "git_id",
                side_effect=lambda _repository, expression: (
                    COMMIT if expression == "HEAD^{commit}" else TREE
                ),
            ):
                for label, mutate in mutations.items():
                    value = copy.deepcopy(candidate_manifest(so_sha256))
                    mutate(value)
                    path = root / f"{label}.json"
                    path.write_bytes(canonical_bytes(value) + b"\n")
                    with self.subTest(label=label), self.assertRaises(ContractError):
                        make_run_config.validated_cag_candidate(repository, cag_so, path)

                wrong_name = root / "cyber-abuse-guard.so"
                wrong_name.write_bytes(cag_so.read_bytes())
                valid_path = root / "valid.json"
                valid_path.write_bytes(
                    canonical_bytes(candidate_manifest(so_sha256)) + b"\n"
                )
                with self.assertRaisesRegex(RuntimeError, "filename"):
                    make_run_config.validated_cag_candidate(
                        repository, wrong_name, valid_path
                    )

                noncanonical = root / "noncanonical.json"
                noncanonical.write_text(
                    json.dumps(candidate_manifest(so_sha256), indent=2) + "\n",
                    encoding="utf-8",
                )
                with self.assertRaisesRegex(ContractError, "canonical"):
                    make_run_config.validated_cag_candidate(
                        repository, cag_so, noncanonical
                    )

                linked = root / "linked.json"
                os.link(valid_path, linked)
                with self.assertRaisesRegex(ContractError, "one hard link"):
                    make_run_config.validated_cag_candidate(
                        repository, cag_so, valid_path
                    )

if __name__ == "__main__":
    unittest.main()
