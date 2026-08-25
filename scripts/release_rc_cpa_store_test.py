from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

from release_rc_cpa_store import (
    AUDIT_CHECKSUM_NAMES,
    AUDIT_CHECKSUMS,
    AUDIT_ZIP,
    CPA_CHECKSUMS,
    ENTRY_NAME,
    RC_ZIP,
    SO_NAME,
    create,
    verify_release,
)


class CPAStoreReleaseTests(unittest.TestCase):
    def write_zip(self, path: Path, entries: dict[str, bytes]) -> None:
        with zipfile.ZipFile(path, "w", zipfile.ZIP_STORED) as archive:
            for name, payload in entries.items():
                archive.writestr(name, payload)

    def fixture(self, root: Path) -> tuple[Path, bytes]:
        payload = b"audited-elf-payload\x00"
        (root / SO_NAME).write_bytes(payload)
        self.write_zip(root / AUDIT_ZIP, {SO_NAME: payload})
        create(root / SO_NAME, root / RC_ZIP)
        supporting_assets = {
            f"{SO_NAME}.sha256": hashlib.sha256(payload).hexdigest()
            + f"  {SO_NAME}\n",
            "build-metadata.json": "{}\n",
            "ruleset-manifest.json": "{}\n",
            "ruleset.sha256": "0" * 64 + "  rules/manifest.yaml\n",
            "sbom.cdx.json": "{}\n",
        }
        for name, content in supporting_assets.items():
            (root / name).write_text(content, encoding="ascii")
        (root / AUDIT_CHECKSUMS).write_text(
            "".join(
                hashlib.sha256((root / name).read_bytes()).hexdigest()
                + f"  {name}\n"
                for name in sorted(AUDIT_CHECKSUM_NAMES)
            ),
            encoding="ascii",
        )
        names = (SO_NAME, AUDIT_ZIP, RC_ZIP)
        (root / CPA_CHECKSUMS).write_text(
            "".join(
                hashlib.sha256((root / name).read_bytes()).hexdigest() + f"  {name}\n"
                for name in names
            ),
            encoding="ascii",
        )
        digest = hashlib.sha256(payload).hexdigest()
        provenance = {
            "derived_artifacts": [{
                "name": RC_ZIP,
                "relationship": "cpa-plugin-store-container",
                "derived_from": {"name": SO_NAME, "sha256": digest},
                "archive_entry": ENTRY_NAME,
                "payload_sha256": digest,
                "recompiled": False,
                "standalone_renamed": False,
            }]
        }
        (root / "release-provenance.json").write_text(
            json.dumps(provenance, sort_keys=True) + "\n", encoding="utf-8"
        )
        return root, payload

    def assert_published_rc_store_archive(self, root: Path) -> None:
        go = shutil.which("go")
        if go is None:
            self.skipTest("Go toolchain is not available")
        repository = Path(__file__).resolve().parent.parent
        result = subprocess.run(
            [
                go,
                "test",
                "./...",
                "-run",
                "^TestPublishedRCStoreArchive$",
                "-count=1",
                "-v",
            ],
            cwd=repository / "integration/pluginstorecontract",
            env={**os.environ, "DIST_DIR": str(root)},
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertRegex(
            result.stdout,
            r"(?m)^--- PASS: TestPublishedRCStoreArchive \([0-9.]+s\)$",
        )

    def test_deterministic_rc_zip_and_valid_release(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, _ = self.fixture(Path(temporary))
            verify_release(root)
            other = root / "other.zip"
            with mock.patch.object(os, "fchmod", wraps=os.fchmod) as fchmod:
                create(root / SO_NAME, other)
            fchmod.assert_called_once()
            self.assertEqual(fchmod.call_args.args[1], 0o644)
            self.assertEqual((root / RC_ZIP).read_bytes(), other.read_bytes())

    def test_exclusive_create_race_preserves_competing_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / SO_NAME
            output = root / RC_ZIP
            source.write_bytes(b"audited-elf-payload\x00")
            sentinel = b"competing-writer-owned-output"
            original_open = os.open

            def race_open(path: object, flags: int, mode: int = 0o777) -> int:
                if Path(path) == output and flags & os.O_EXCL:
                    with output.open("wb") as competitor:
                        competitor.write(sentinel)
                    raise FileExistsError("simulated exclusive-create race")
                return original_open(path, flags, mode)

            with (
                mock.patch.object(os, "open", new=race_open),
                self.assertRaises(FileExistsError),
            ):
                create(source, output)
            self.assertEqual(output.read_bytes(), sentinel)

    def test_generated_package_is_accepted_by_pinned_cpa_install_archive(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, _ = self.fixture(Path(temporary))
            self.assert_published_rc_store_archive(root)

    def test_pinned_cpa_archive_skips_without_go(self) -> None:
        with mock.patch.object(shutil, "which", return_value=None):
            with self.assertRaisesRegex(unittest.SkipTest, "Go toolchain"):
                self.assert_published_rc_store_archive(Path("."))

    def test_pinned_cpa_archive_rejects_zero_match_success(self) -> None:
        zero_match = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout="testing: warning: no tests to run\nPASS\nok  \tpackage\t0.001s [no tests to run]\n",
            stderr="",
        )
        with (
            mock.patch.object(shutil, "which", return_value="/usr/bin/go"),
            mock.patch.object(subprocess, "run", return_value=zero_match),
        ):
            with self.assertRaisesRegex(AssertionError, "TestPublishedRCStoreArchive"):
                self.assert_published_rc_store_archive(Path("."))

    def test_cli_rejects_non_object_provenance_with_controlled_error(self) -> None:
        script = Path(__file__).with_name("release_rc_cpa_store.py")
        for name, provenance in (("list", []), ("scalar", "not-an-object")):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root, _ = self.fixture(Path(temporary))
                (root / "release-provenance.json").write_text(
                    json.dumps(provenance) + "\n", encoding="utf-8"
                )
                result = subprocess.run(
                    [
                        sys.executable,
                        str(script),
                        "verify-release",
                        "--directory",
                        str(root),
                    ],
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertIn(
                    "error: release provenance must be a JSON object", result.stderr
                )
                self.assertNotIn("Traceback", result.stderr)

    def test_rejects_packaging_and_release_mutations(self) -> None:
        mutations = {
            "stable-only": lambda root, payload: (root / RC_ZIP).unlink(),
            "base-version-entry": lambda root, payload: self.write_zip(root / RC_ZIP, {SO_NAME: payload}),
            "rc-standalone": lambda root, payload: (root / "cyber-abuse-guard-v1.0.0-rc.2.so").write_bytes(payload),
            "subdirectory": lambda root, payload: self.write_zip(root / RC_ZIP, {"nested/" + ENTRY_NAME: payload}),
            "second-so": lambda root, payload: self.write_zip(root / RC_ZIP, {ENTRY_NAME: payload, "other.so": payload}),
            "payload-drift": lambda root, payload: self.write_zip(root / RC_ZIP, {ENTRY_NAME: payload + b"drift"}),
            "symlink-entry": lambda root, payload: self.rewrite_rc(root, payload, mode=stat.S_IFLNK | 0o777),
            "device-entry": lambda root, payload: self.rewrite_rc(root, payload, mode=stat.S_IFCHR | 0o600),
            "encrypted-entry": self.encrypt_rc_entry,
            "compressed-method": lambda root, payload: self.rewrite_rc(root, payload, method=zipfile.ZIP_DEFLATED),
            "timestamp-drift": lambda root, payload: self.rewrite_rc(root, payload, date_time=(2026, 8, 9, 0, 0, 0)),
            "mode-drift": lambda root, payload: self.rewrite_rc(root, payload, mode=stat.S_IFREG | 0o644),
            "extra-field": lambda root, payload: self.rewrite_rc(root, payload, extra=b"\x01\x00\x00\x00"),
            "entry-comment": lambda root, payload: self.rewrite_rc(root, payload, comment=b"drift"),
            "archive-comment": lambda root, payload: self.rewrite_rc(root, payload, archive_comment=b"drift"),
            "checksums-missing-rc": self.remove_rc_checksum,
            "checksums-wrong-hash": self.wrong_rc_checksum,
            "candidate-checksums-masquerade": self.copy_candidate_checksums,
            "candidate-checksums-missing-asset": self.remove_audit_checksum,
            "candidate-checksums-extra-asset": self.add_audit_checksum,
            "candidate-checksums-wrong-hash": self.wrong_audit_checksum,
            "provenance-missing-derived": self.remove_derived,
            "provenance-symlink": self.symlink_provenance,
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root, payload = self.fixture(Path(temporary))
                mutate(root, payload)
                with self.assertRaises((ValueError, FileNotFoundError, zipfile.BadZipFile)):
                    verify_release(root)

    @staticmethod
    def remove_rc_checksum(root: Path, _payload: bytes) -> None:
        rows = (root / CPA_CHECKSUMS).read_text("ascii").splitlines()
        (root / CPA_CHECKSUMS).write_text(
            "\n".join(row for row in rows if not row.endswith("  " + RC_ZIP)) + "\n",
            encoding="ascii",
        )

    @staticmethod
    def wrong_rc_checksum(root: Path, _payload: bytes) -> None:
        text = (root / CPA_CHECKSUMS).read_text("ascii")
        rows = ["0" * 64 + f"  {RC_ZIP}" if row.endswith("  " + RC_ZIP) else row for row in text.splitlines()]
        (root / CPA_CHECKSUMS).write_text("\n".join(rows) + "\n", encoding="ascii")

    @staticmethod
    def copy_candidate_checksums(root: Path, _payload: bytes) -> None:
        (root / CPA_CHECKSUMS).write_bytes((root / AUDIT_CHECKSUMS).read_bytes())

    @staticmethod
    def remove_audit_checksum(root: Path, _payload: bytes) -> None:
        rows = (root / AUDIT_CHECKSUMS).read_text("ascii").splitlines()
        (root / AUDIT_CHECKSUMS).write_text(
            "\n".join(row for row in rows if not row.endswith("  sbom.cdx.json"))
            + "\n",
            encoding="ascii",
        )

    @staticmethod
    def add_audit_checksum(root: Path, _payload: bytes) -> None:
        with (root / AUDIT_CHECKSUMS).open("a", encoding="ascii") as output:
            output.write("0" * 64 + "  unreviewed.bin\n")

    @staticmethod
    def wrong_audit_checksum(root: Path, _payload: bytes) -> None:
        text = (root / AUDIT_CHECKSUMS).read_text("ascii")
        rows = [
            "0" * 64 + f"  {AUDIT_ZIP}"
            if row.endswith("  " + AUDIT_ZIP)
            else row
            for row in text.splitlines()
        ]
        (root / AUDIT_CHECKSUMS).write_text(
            "\n".join(rows) + "\n", encoding="ascii"
        )

    @staticmethod
    def remove_derived(root: Path, _payload: bytes) -> None:
        (root / "release-provenance.json").write_text(
            json.dumps({"derived_artifacts": []}) + "\n", encoding="utf-8"
        )

    @staticmethod
    def symlink_provenance(root: Path, _payload: bytes) -> None:
        provenance = root / "release-provenance.json"
        target = root / "release-provenance-target.json"
        target.write_bytes(provenance.read_bytes())
        provenance.unlink()
        provenance.symlink_to(target.name)

    @staticmethod
    def rewrite_rc(
        root: Path,
        payload: bytes,
        *,
        mode: int = stat.S_IFREG | 0o755,
        method: int = zipfile.ZIP_STORED,
        date_time: tuple[int, int, int, int, int, int] = (1980, 1, 1, 0, 0, 0),
        extra: bytes = b"",
        comment: bytes = b"",
        archive_comment: bytes = b"",
    ) -> None:
        info = zipfile.ZipInfo(ENTRY_NAME, date_time=date_time)
        info.create_system = 3
        info.compress_type = method
        info.external_attr = mode << 16
        info.extra = extra
        info.comment = comment
        with zipfile.ZipFile(root / RC_ZIP, "w") as archive:
            archive.comment = archive_comment
            archive.writestr(info, payload)

    @staticmethod
    def encrypt_rc_entry(root: Path, _payload: bytes) -> None:
        path = root / RC_ZIP
        raw = bytearray(path.read_bytes())
        local = raw.index(b"PK\x03\x04")
        central = raw.index(b"PK\x01\x02")
        raw[local + 6 : local + 8] = (
            int.from_bytes(raw[local + 6 : local + 8], "little") | 1
        ).to_bytes(2, "little")
        raw[central + 8 : central + 10] = (
            int.from_bytes(raw[central + 8 : central + 10], "little") | 1
        ).to_bytes(2, "little")
        path.write_bytes(raw)


if __name__ == "__main__":
    unittest.main()
