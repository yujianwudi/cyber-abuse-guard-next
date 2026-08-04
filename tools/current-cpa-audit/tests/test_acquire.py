from __future__ import annotations

import io
import stat
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
TOOL = HERE.parent
sys.path.insert(0, str(TOOL))

import acquire
from audit_contract import ContractError, validate_inert_text


def archive_bytes(
    names: list[str], *, compression: int = zipfile.ZIP_DEFLATED, symlink: bool = False
) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=compression) as archive:
        for name in names:
            if symlink:
                info = zipfile.ZipInfo(name)
                info.create_system = 3
                info.external_attr = (stat.S_IFLNK | 0o777) << 16
                archive.writestr(info, "target.md")
            else:
                archive.writestr(name, "reviewed inert markdown\n")
    return output.getvalue()


class AcquisitionSecurityTests(unittest.TestCase):
    def test_only_fixed_https_github_hosts_are_accepted(self) -> None:
        for url in (
            "https://api.github.com/repos/owner/name",
            "https://raw.githubusercontent.com/owner/name/commit/file.md",
        ):
            acquire.validate_github_url(url)
        for url in (
            "http://api.github.com/repos/owner/name",
            "https://evil.example/repos/owner/name",
            "https://api.github.com.evil.example/repos/owner/name",
            "https://user@api.github.com/repos/owner/name",
            "https://api.github.com:444/repos/owner/name",
            "https://api.github.com/repos\\owner",
            "https://api.github.com/repos/owner/name#fragment",
        ):
            with self.subTest(url=url), self.assertRaises(ContractError):
                acquire.validate_github_url(url)

    def test_inert_text_rejects_lfs_nul_non_utf8_and_limit(self) -> None:
        self.assertEqual(validate_inert_text(b"\xef\xbb\xbfhello", "text", 32), b"hello")
        rejected = (
            b"version https://git-lfs.github.com/spec/v1\n",
            b"hello\x00world",
            b"\xff",
            b"x" * 33,
        )
        for raw in rejected:
            with self.subTest(raw=raw[:16]), self.assertRaises(ContractError):
                validate_inert_text(raw, "text", 32)

    def test_single_markdown_zip_positive(self) -> None:
        raw = archive_bytes(["only.md"])
        self.assertEqual(
            acquire.extract_single_markdown_zip(raw, "only.md", 1024),
            b"reviewed inert markdown\n",
        )

    def test_zip_rejects_multiple_entries(self) -> None:
        with self.assertRaises(ContractError):
            acquire.extract_single_markdown_zip(
                archive_bytes(["one.md", "two.md"]), "one.md", 1024
            )

    def test_zip_rejects_symlink_and_unknown_compression(self) -> None:
        with self.assertRaises(ContractError):
            acquire.extract_single_markdown_zip(
                archive_bytes(["only.md"], symlink=True), "only.md", 1024
            )
        with self.assertRaises(ContractError):
            acquire.extract_single_markdown_zip(
                archive_bytes(["only.md"], compression=zipfile.ZIP_BZIP2),
                "only.md",
                1024,
            )

    def test_zip_rejects_traversal_prefix_and_trailer(self) -> None:
        with self.assertRaises(ContractError):
            acquire.extract_single_markdown_zip(
                archive_bytes(["../escape.md"]), "../escape.md", 1024
            )
        valid = archive_bytes(["only.md"])
        for raw in (b"prefix" + valid, valid + b"trailer"):
            with self.assertRaises(ContractError):
                acquire.extract_single_markdown_zip(raw, "only.md", 1024)

    def test_zip_rejects_concatenated_archive_prefix(self) -> None:
        hidden_archive = archive_bytes(["hidden.md"])
        reviewed_archive = archive_bytes(["only.md"])
        with self.assertRaises(ContractError):
            acquire.extract_single_markdown_zip(
                hidden_archive + reviewed_archive, "only.md", 1024
            )

    def test_tree_entry_rejects_executable_symlink_and_oversize(self) -> None:
        base = {"path": "safe.md", "type": "blob", "mode": "100644", "sha": "a" * 40, "size": 10}
        self.assertEqual(acquire._tree_entry(base, "safe.md", 10), base)
        for change in (
            {"mode": "100755"},
            {"mode": "120000"},
            {"type": "tree"},
            {"size": 11},
        ):
            value = {**base, **change}
            with self.subTest(change=change), self.assertRaises(ContractError):
                acquire._tree_entry(value, "safe.md", 10)

    def test_failed_output_cleanup_is_exact(self) -> None:
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent) / "owned"
            (root / "corpus").mkdir(parents=True)
            (root / "corpus" / "nerv.txt").write_text("inert", encoding="utf-8")
            removed = acquire.remove_private_tree(root)
            self.assertEqual(removed, 1)
            self.assertFalse(root.exists())
            self.assertTrue(Path(parent).exists())


if __name__ == "__main__":
    unittest.main()
