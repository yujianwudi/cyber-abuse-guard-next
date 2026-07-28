#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from repository_secret_scan import (
    Finding,
    git_visible_paths,
    normalize_relative_path,
    scan_paths,
)


class RepositorySecretScanTests(unittest.TestCase):
    OLD_SO_RAW_CAPTURE = (
        "testdata/round9-old-so-v0.16-rc.2-source/internal/audit/raw_capture.go"
    )

    def test_rejects_parent_path_escape(self) -> None:
        for value in ("../outside", "nested/../../outside", r"nested\..\..\outside"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                normalize_relative_path(value)

    @mock.patch("repository_secret_scan.subprocess.run")
    def test_git_inventory_is_static_bounded_and_non_shell(
        self, run_mock: mock.Mock
    ) -> None:
        run_mock.return_value = mock.Mock(returncode=0, stdout=b"README.md\0")
        root = Path("/synthetic/repository")
        self.assertEqual(["README.md"], git_visible_paths(root))
        run_mock.assert_called_once_with(
            [
                "git",
                "-C",
                str(root),
                "ls-files",
                "-co",
                "--exclude-standard",
                "-z",
            ],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=False,
            timeout=30,
        )

    @mock.patch("repository_secret_scan.subprocess.run")
    def test_git_inventory_failure_is_bounded(self, run_mock: mock.Mock) -> None:
        run_mock.side_effect = subprocess.TimeoutExpired(["git"], 30)
        with self.assertRaisesRegex(RuntimeError, "Git-visible path inventory failed"):
            git_visible_paths(Path("/synthetic/repository"))

    def test_rejects_sensitive_filenames_without_printing_values(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = [
                "id_ed25519",
                "nested/id_ed25519_servers",
                "id_rsa",
                "keys/operator.ppk",
                ".round9-local-sandbox/cache.txt",
            ]
            for relative in paths:
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("synthetic\n", encoding="utf-8")
            rules = {finding.rule for finding in scan_paths(root, paths)}
            self.assertIn("ssh-key-filename", rules)
            self.assertIn("secret-container-filename", rules)
            self.assertIn("local-sandbox-path", rules)

    def test_detects_content_and_public_host_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            token = "sk-" + "A" * 24
            private_key = "-" * 5 + "BEGIN PRIVATE KEY" + "-" * 5
            url = "https://" + "operator:password" + "@host.example.invalid/path"
            public_ip = ".".join(("8", "8", "8", "8"))
            text = "\n".join((token, private_key, url, public_ip))
            (root / "fixture.txt").write_text(text, encoding="utf-8")
            findings = scan_paths(root, ["fixture.txt"])
            self.assertEqual(
                {
                    Finding("fixture.txt", 1, "openai-api-key"),
                    Finding("fixture.txt", 2, "private-key-material"),
                    Finding("fixture.txt", 3, "credential-bearing-url"),
                    Finding("fixture.txt", 4, "public-ipv4-metadata"),
                },
                set(findings),
            )

    def test_explicit_review_marker_is_line_local(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = "sk-" + "B" * 24 + "  # repo-secret-scan: allow synthetic-fixture"
            second = "sk-" + "C" * 24
            (root / "fixture.txt").write_text(first + "\n" + second + "\n", encoding="utf-8")
            self.assertEqual(
                [Finding("fixture.txt", 2, "openai-api-key")],
                scan_paths(root, ["fixture.txt"]),
            )

    def test_reserved_addresses_and_safe_neighbor_names_are_allowed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = ["docs/id_ed25519.md", "internal/id_rsa_policy.go"]
            for relative in paths:
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("127.0.0.1 192.0.2.10 198.51.100.4 203.0.113.8\n", encoding="utf-8")
            self.assertEqual([], scan_paths(root, paths))

    def test_restricted_paths_are_refused_before_content_scan(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            relative = "testdata/holdout/synthetic.txt"
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("sk-" + "D" * 24, encoding="utf-8")
            self.assertEqual([], scan_paths(root, [relative]))

    def test_allows_only_the_fixed_old_so_raw_capture_false_positive(self) -> None:
        root = Path(__file__).resolve().parent.parent
        self.assertEqual([], scan_paths(root, [self.OLD_SO_RAW_CAPTURE]))

    def test_old_so_exception_fails_closed_on_content_drift_or_other_path(self) -> None:
        repository_root = Path(__file__).resolve().parent.parent
        original = (repository_root / self.OLD_SO_RAW_CAPTURE).read_bytes()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            drifted = root / self.OLD_SO_RAW_CAPTURE
            drifted.parent.mkdir(parents=True, exist_ok=True)
            drifted.write_bytes(original + b"\n")
            copied_relative = "fixtures/raw_capture.go"
            copied = root / copied_relative
            copied.parent.mkdir(parents=True, exist_ok=True)
            copied.write_bytes(original)

            self.assertEqual(
                [Finding(self.OLD_SO_RAW_CAPTURE, 148, "private-key-material")],
                scan_paths(root, [self.OLD_SO_RAW_CAPTURE]),
            )
            self.assertEqual(
                [Finding(copied_relative, 148, "private-key-material")],
                scan_paths(root, [copied_relative]),
            )


if __name__ == "__main__":
    unittest.main()
