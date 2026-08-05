from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
TOOL = HERE.parent
sys.path.insert(0, str(TOOL))
sys.path.insert(0, str(HERE))

import run
from audit_contract import canonical_bytes, sha256_bytes
from fixtures import manifest


class RunnerPureTests(unittest.TestCase):
    def test_runtime_config_has_only_counted_mock(self) -> None:
        raw = run.cpa_yaml("balanced", "client", "management", "upstream").decode("utf-8")
        self.assertIn('base-url: "http://mock:18080/v1"', raw)
        self.assertIn("request-log: false", raw)
        self.assertIn("logging-to-file: false", raw)
        self.assertIn('data_dir": "/cag/audit"', raw)
        for marker in ("api.openai.com", "oauth", "provider.example"):
            self.assertNotIn(marker, raw.lower())
        dockerfile = (TOOL / "Dockerfile.mock").read_text("utf-8")
        self.assertIn(
            'ENTRYPOINT ["python3", "-I", "-S", "-B", '
            '"/opt/cag-audit/counted_mock.py"]',
            dockerfile,
        )

    def test_internal_target_rejects_loopback_and_non_rfc1918(self) -> None:
        self.assertEqual(run.internal_base("172.20.0.2", 8317), "http://172.20.0.2:8317")
        for address in ("127.0.0.1", "192.0.2.1", "not-an-ip"):
            with self.subTest(address=address), self.assertRaises(run.AuditFailure):
                run.internal_base(address, 8317)

    def test_runner_bundle_identity_is_complete(self) -> None:
        identity = run.runner_identities()
        self.assertEqual(
            set(identity),
            {
                "audit_contract_sha256",
                "bundle_sha256",
                "machine_schema_sha256",
                "mock_source_sha256",
                "policy_sha256",
                "run_source_sha256",
            },
        )
        self.assertTrue(all(len(value) == 64 and value.strip("0") for value in identity.values()))

    def test_owned_tree_cleanup_does_not_remove_parent(self) -> None:
        with tempfile.TemporaryDirectory() as parent:
            owned = Path(parent) / "runtime"
            (owned / "nested").mkdir(parents=True)
            (owned / "nested" / "state").write_text("first-party", encoding="utf-8")
            self.assertEqual(run.remove_owned_tree(owned), 1)
            self.assertFalse(owned.exists())
            self.assertTrue(Path(parent).exists())

    def test_evidence_directory_binding_rejects_path_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent)
            evidence = root / "evidence"
            moved = root / "moved"
            binding = run.BoundEvidenceDirectory.create(evidence)
            try:
                evidence.rename(moved)
                evidence.mkdir(mode=0o700)
                with self.assertRaises(run.AuditFailure):
                    binding.verify_path()
                run.write_exclusive(binding.bound_path / "bound-canary", b"bound")
                self.assertTrue((moved / "bound-canary").is_file())
                self.assertFalse((evidence / "bound-canary").exists())
            finally:
                binding.close()

        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent)
            evidence = root / "evidence"
            moved = root / "moved-before-bind"
            original_open = run.os.open

            def replace_before_child_open(
                path: object, flags: int, *args: object, **kwargs: object
            ) -> int:
                if path == "evidence" and kwargs.get("dir_fd") is not None:
                    evidence.rename(moved)
                    evidence.mkdir(mode=0o700)
                return original_open(path, flags, *args, **kwargs)

            with mock.patch.object(run.os, "open", side_effect=replace_before_child_open):
                with self.assertRaises(run.AuditFailure):
                    run.BoundEvidenceDirectory.create(evidence)

    @unittest.skipUnless(os.name == "posix", "Linux permission contract")
    def test_evidence_directory_binding_rejects_nonprivate_parent(self) -> None:
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent)
            evidence = root / "evidence"
            root.chmod(0o770)
            try:
                with self.assertRaisesRegex(
                    run.AuditFailure, "parent must be a private real directory"
                ):
                    run.BoundEvidenceDirectory.create(evidence)
                self.assertFalse(evidence.exists())
            finally:
                root.chmod(0o700)

    @unittest.skipUnless(os.name == "posix", "Linux proc-fd contract")
    def test_evidence_bound_path_is_visible_to_an_independent_process(self) -> None:
        with tempfile.TemporaryDirectory() as parent:
            evidence = Path(parent) / "evidence"
            binding = run.BoundEvidenceDirectory.create(evidence)
            try:
                result = run.run_process(
                    [
                        sys.executable,
                        "-I",
                        "-c",
                        (
                            "from pathlib import Path; import sys; "
                            "Path(sys.argv[1], 'external-canary').write_text("
                            "'external', encoding='utf-8')"
                        ),
                        str(binding.bound_path),
                    ]
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(
                    (evidence / "external-canary").read_text("utf-8"), "external"
                )
                binding.verify_path()
            finally:
                binding.close()

    def test_validated_corpus_cleanup_removes_nerv_text_and_retains_no_body(self) -> None:
        value = manifest()
        canary = b"NERV_COMPLETE_TEXT_CANARY_MUST_NOT_REMAIN"
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent)
            corpus = root / "corpus"
            corpus.mkdir()
            payloads: dict[str, bytes] = {}
            for case in value["semantic_cases"]:
                source = case["source"]
                relative = source["corpus_file"]
                payload = payloads.setdefault(
                    relative, canary + relative.encode("utf-8")
                )
                source["text_bytes"] = len(payload)
                source["text_sha256"] = sha256_bytes(payload)
                if source["archive_member"] is None:
                    source["source_sha256"] = source["text_sha256"]
                (root / relative).write_bytes(payload)
            root_info = root.stat()
            corpus_info = corpus.stat()
            value["filesystem_identity"] = {
                "acquisition_root": {
                    "device": root_info.st_dev,
                    "inode": root_info.st_ino,
                },
                "corpus_directory": {
                    "device": corpus_info.st_dev,
                    "inode": corpus_info.st_ino,
                },
            }
            removed, retained = run.remove_manifest_corpus(value, root)
            self.assertEqual(removed, value["source_count"])
            self.assertFalse(retained)
            self.assertFalse(corpus.exists())
            self.assertTrue(root.exists())
            self.assertNotIn(canary, canonical_bytes(value))


if __name__ == "__main__":
    unittest.main()
