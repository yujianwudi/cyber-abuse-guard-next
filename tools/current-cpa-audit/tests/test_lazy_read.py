from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
TOOL = HERE.parent
sys.path.insert(0, str(TOOL))
sys.path.insert(0, str(HERE))

from audit_contract import BoundCorpus, sha256_bytes
from lazy_read import LazyReadError, LazyReadRecorder
from second_machine_release_admission import validate_lazy_read_evidence


class LazyReadProducerTests(unittest.TestCase):
    def test_produces_text_free_evidence_and_allows_repeated_request_hashes(self) -> None:
        secret = b"synthetic-sensitive-source-sentinel"
        source_sha = sha256_bytes(secret)
        request_sha = hashlib.sha256(b"same-request-across-cold-starts").hexdigest()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            recorder = LazyReadRecorder(root, "unit-run")
            recorder.record_preflight(
                source_path="corpus/source.txt",
                source_bytes=len(secret),
                source_sha256=source_sha,
                case_identity="case-one",
            )
            recorder.start_transport()
            for _ in range(2):
                recorder.record_transport(
                    source_path="corpus/source.txt",
                    source_bytes=len(secret),
                    source_sha256=source_sha,
                    case_identity="case-one",
                    request_sha256=request_sha,
                )
            summary = recorder.finalize(
                expected_transport_reads=2,
                finally_cleanup_complete=True,
                post_unlink_nlink_zero=True,
                supplemental_member_text_retained=False,
                temporary_secret_or_config_retained=False,
                third_party_text_retained=False,
            )

            evidence = root / "lazy-read"
            phase_raw = (evidence / "phase-boundary.json").read_bytes()
            trace_raw = (evidence / "runtime-read-trace.jsonl").read_bytes()
            summary_raw = (evidence / "runtime-read-summary.json").read_bytes()
            self.assertNotIn(secret, phase_raw + trace_raw + summary_raw)
            self.assertEqual(summary["transport_source_read_count"], 2)
            self.assertEqual(
                json.loads(summary_raw),
                summary,
            )
            projection = validate_lazy_read_evidence(
                json.loads(phase_raw), trace_raw, json.loads(summary_raw)
            )
            self.assertEqual(projection["transport_request_count"], 2)
            rows = [json.loads(row) for row in trace_raw.splitlines()]
            self.assertEqual([row["ordinal"] for row in rows], [1, 2, 3])
            self.assertEqual(rows[1]["request_sha256"], rows[2]["request_sha256"])

    def test_fails_closed_on_missing_read_or_privacy_cleanup(self) -> None:
        digest = "a" * 64
        with tempfile.TemporaryDirectory() as directory:
            recorder = LazyReadRecorder(Path(directory), "unit-run")
            with self.assertRaisesRegex(LazyReadError, "observed no real source reads"):
                recorder.start_transport()
            recorder.abort()

        with tempfile.TemporaryDirectory() as directory:
            recorder = LazyReadRecorder(Path(directory), "unit-run")
            recorder.record_preflight(
                source_path="corpus/source.txt",
                source_bytes=1,
                source_sha256=digest,
                case_identity="case-one",
            )
            recorder.start_transport()
            recorder.record_transport(
                source_path="corpus/source.txt",
                source_bytes=1,
                source_sha256=digest,
                case_identity="case-one",
                request_sha256="b" * 64,
            )
            with self.assertRaisesRegex(LazyReadError, "retained sensitive"):
                recorder.finalize(
                    expected_transport_reads=1,
                    finally_cleanup_complete=True,
                    post_unlink_nlink_zero=True,
                    supplemental_member_text_retained=True,
                    temporary_secret_or_config_retained=False,
                    third_party_text_retained=False,
                )
            recorder.abort()
            self.assertFalse(
                (Path(directory) / "lazy-read" / "runtime-read-summary.json").exists()
            )

    def test_bound_corpus_observer_receives_metadata_not_source_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            corpus = root / "corpus"
            corpus.mkdir()
            raw = b"observer-sensitive-sentinel"
            source = corpus / "source.txt"
            source.write_bytes(raw)
            root_info = root.lstat()
            corpus_info = corpus.lstat()
            observed: list[tuple[str, int, str]] = []
            bound = BoundCorpus(
                root,
                {
                    "acquisition_root": {
                        "device": root_info.st_dev,
                        "inode": root_info.st_ino,
                    },
                    "corpus_directory": {
                        "device": corpus_info.st_dev,
                        "inode": corpus_info.st_ino,
                    },
                },
                "unit corpus",
                lambda relative, size, digest: observed.append(
                    (relative, size, digest)
                ),
            )
            try:
                self.assertEqual(
                    bound.read("corpus/source.txt", "unit source", len(raw)), raw
                )
            finally:
                bound.close()
            self.assertEqual(
                observed,
                [("corpus/source.txt", len(raw), sha256_bytes(raw))],
            )
            self.assertNotIn(raw, repr(observed).encode("utf-8"))


if __name__ == "__main__":
    unittest.main()
