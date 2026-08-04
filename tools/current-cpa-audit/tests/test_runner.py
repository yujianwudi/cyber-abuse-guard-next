from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

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
            self.assertNotIn(canary, canonical_bytes(value))


if __name__ == "__main__":
    unittest.main()
