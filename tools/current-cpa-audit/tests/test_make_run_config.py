from __future__ import annotations

import copy
import json
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
from audit_contract import ContractError, canonical_bytes, sha256_bytes
from host_performance import CANDIDATE_SCHEMA, CANDIDATE_STATUS


COMMIT = "1" * 40
TREE = "2" * 40
VERSION = "0.16"
SO_NAME = f"cyber-abuse-guard-v{VERSION}.so"


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
        "run_attempt": "1",
        "run_id": "123456789",
        "schema": CANDIDATE_SCHEMA,
        "status": CANDIDATE_STATUS,
        "tree": TREE,
        "version": VERSION,
    }


class MakeRunConfigTests(unittest.TestCase):
    def test_require_git_clean_includes_and_rejects_untracked_files(self) -> None:
        completed = subprocess.CompletedProcess([], 0, stdout="?? local.txt\n", stderr="")
        with mock.patch.object(make_run_config.subprocess, "run", return_value=completed) as run:
            with self.assertRaisesRegex(RuntimeError, "untracked"):
                make_run_config.require_git_clean(Path("/tmp/repository"))
        self.assertIn("--untracked-files=all", run.call_args.args[0])

    def test_validated_candidate_returns_only_the_bound_cag_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = root / "repository"
            repository.mkdir()
            cag_so = root / SO_NAME
            cag_so.write_bytes(b"exact candidate SO")
            so_sha256 = sha256_bytes(cag_so.read_bytes())
            manifest_path = root / "audit-candidate-manifest.json"
            manifest_path.write_text(
                json.dumps(candidate_manifest(so_sha256), indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )

            with mock.patch.object(make_run_config, "require_git_clean") as clean, mock.patch.object(
                make_run_config,
                "git_id",
                side_effect=lambda _repository, expression: (
                    COMMIT if expression == "HEAD^{commit}" else TREE
                ),
            ):
                identity = make_run_config.validated_cag_candidate(
                    repository, cag_so, manifest_path
                )

        clean.assert_called_once_with(repository)
        self.assertEqual(
            identity,
            {"commit": COMMIT, "so_sha256": so_sha256, "tree": TREE},
        )

    def test_candidate_manifest_must_bind_clean_exact_candidate_and_so_name(self) -> None:
        mutations = {
            "schema": lambda value: value.__setitem__("schema", "wrong"),
            "status": lambda value: value.__setitem__("status", "RELEASED"),
            "dirty": lambda value: value.__setitem__("dirty", True),
            "commit": lambda value: value.__setitem__("commit", "3" * 40),
            "tree": lambda value: value.__setitem__("tree", "4" * 40),
            "so_sha256": lambda value: value["artifacts"][0].__setitem__(
                "sha256", "5" * 64
            ),
            "eight_file_closure": lambda value: value["artifacts"].pop(),
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

if __name__ == "__main__":
    unittest.main()
