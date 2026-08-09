from __future__ import annotations

import hashlib
import stat
import tempfile
import unittest
import warnings
import zipfile
from pathlib import Path
from unittest import mock

import release_rc_artifact_zip as verifier
from release_rc_artifact_zip import ArtifactZipError, EXPECTED_FILES, verify_artifact_zip


class ArtifactZipTests(unittest.TestCase):
    def action_output(self, root: Path) -> Path:
        output = root / "action"
        output.mkdir()
        for index, name in enumerate(sorted(EXPECTED_FILES)):
            (output / name).write_bytes(f"file-{index}\n".encode())
        return output

    def write_archive(
        self,
        archive: Path,
        output: Path,
        names: list[str] | None = None,
        modes: dict[str, int] | None = None,
        compression: int = zipfile.ZIP_DEFLATED,
    ) -> tuple[str, int]:
        modes = modes or {}
        with warnings.catch_warnings(), zipfile.ZipFile(
            archive, "w", compression
        ) as zipped:
            warnings.simplefilter("ignore", UserWarning)
            for name in names or sorted(EXPECTED_FILES):
                info = zipfile.ZipInfo(name)
                info.create_system = 3
                info.compress_type = compression
                info.external_attr = modes.get(name, stat.S_IFREG | 0o644) << 16
                payload = (output / name).read_bytes() if name in EXPECTED_FILES else b"bad"
                zipped.writestr(info, payload)
        return self.metadata(archive)

    @staticmethod
    def metadata(archive: Path) -> tuple[str, int]:
        raw = archive.read_bytes()
        return "sha256:" + hashlib.sha256(raw).hexdigest(), len(raw)

    def fixture(self, root: Path) -> tuple[Path, Path, str, int]:
        output = self.action_output(root)
        archive = root / "artifact.zip"
        digest, size = self.write_archive(archive, output)
        return archive, output, digest, size

    def rejected(self, archive: Path, output: Path, pattern: str) -> None:
        digest, size = self.metadata(archive)
        with self.assertRaisesRegex(ArtifactZipError, pattern):
            verify_artifact_zip(archive, output, digest, size)

    def test_accepts_exact_raw_zip_and_action_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            archive, output, digest, size = self.fixture(Path(temporary))
            verify_artifact_zip(archive, output, digest, size)
            with mock.patch.object(
                Path,
                "read_bytes",
                side_effect=AssertionError("verifier must not buffer whole files"),
            ):
                verify_artifact_zip(archive, output, digest, size)

    def test_rejects_api_metadata_and_archive_type_mutations(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            archive, output, digest, size = self.fixture(Path(temporary))
            cases = (
                (digest, size + 1, "byte count"),
                ("sha256:" + "0" * 64, size, "SHA-256"),
                ("sha512:" + "0" * 64, size, "sha256 digest"),
                ("sha256:" + "A" * 64, size, "metadata is invalid"),
                (digest, 0, "metadata is invalid"),
                (digest, verifier.MAX_ARCHIVE_BYTES + 1, "metadata is invalid"),
            )
            for expected_digest, expected_size, pattern in cases:
                with self.subTest(pattern=pattern), self.assertRaisesRegex(
                    ArtifactZipError, pattern
                ):
                    verify_artifact_zip(
                        archive, output, expected_digest, expected_size
                    )
            with self.assertRaisesRegex(ArtifactZipError, "not a regular file"):
                verify_artifact_zip(output, output, digest, size)

    def test_rejects_duplicate_expected_name(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = self.action_output(root)
            names = sorted(EXPECTED_FILES)
            archive = root / "duplicate.zip"
            self.write_archive(archive, output, names + [names[0]])
            self.rejected(archive, output, "duplicate entry")

    def test_rejects_unsafe_modes_and_noncanonical_compression(self) -> None:
        unsafe_modes = (
            stat.S_IFLNK | 0o777,
            stat.S_IFCHR | 0o600,
            stat.S_IFBLK | 0o600,
            stat.S_IFIFO | 0o600,
            stat.S_IFSOCK | 0o600,
        )
        for mode in unsafe_modes:
            with self.subTest(mode=oct(mode)), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                output = self.action_output(root)
                name = sorted(EXPECTED_FILES)[0]
                archive = root / "mode.zip"
                self.write_archive(archive, output, modes={name: mode})
                self.rejected(archive, output, "unsafe entry")

        for compression in (zipfile.ZIP_BZIP2, zipfile.ZIP_LZMA):
            with self.subTest(compression=compression), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                output = self.action_output(root)
                archive = root / "compression.zip"
                self.write_archive(archive, output, compression=compression)
                self.rejected(archive, output, "unsupported compression")

    def test_rejects_absolute_parent_and_backslash_paths(self) -> None:
        unsafe_names = ("/absolute", "../escape", "folder/escape", r"folder\escape")
        for unsafe in unsafe_names:
            with self.subTest(name=unsafe), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                output = self.action_output(root)
                names = sorted(EXPECTED_FILES)
                names[0] = unsafe
                archive = root / "path.zip"
                self.write_archive(archive, output, names)
                self.rejected(archive, output, "unsafe entry")

    def test_rejects_encrypted_flag(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive, output, _digest, _size = self.fixture(root)
            raw = bytearray(archive.read_bytes())
            local = raw.index(b"PK\x03\x04")
            central = raw.index(b"PK\x01\x02")
            raw[local + 6 : local + 8] = (
                int.from_bytes(raw[local + 6 : local + 8], "little") | 1
            ).to_bytes(2, "little")
            raw[central + 8 : central + 10] = (
                int.from_bytes(raw[central + 8 : central + 10], "little") | 1
            ).to_bytes(2, "little")
            archive.write_bytes(raw)
            self.rejected(archive, output, "unsafe entry")

    def test_rejects_directory_and_extra_entries(self) -> None:
        cases = (("extra/", "unsafe entry"), ("extra.txt", "nine-file"))
        for extra, pattern in cases:
            with self.subTest(extra=extra), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                output = self.action_output(root)
                archive = root / "extra.zip"
                self.write_archive(archive, output, sorted(EXPECTED_FILES) + [extra])
                self.rejected(archive, output, pattern)

    def test_rejects_declared_uncompressed_total_over_limit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            archive, output, _digest, _size = self.fixture(Path(temporary))
            with mock.patch.object(verifier, "MAX_UNCOMPRESSED_BYTES", 1):
                self.rejected(archive, output, "extraction limit")

    def test_rejects_stream_bytes_beyond_declared_entry_size(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            archive, output, digest, size = self.fixture(Path(temporary))
            original_open = zipfile.ZipFile.open

            class OverreadStream:
                def __init__(self, source: object) -> None:
                    self.source = source
                    self.emitted_extra = False

                def __enter__(self) -> "OverreadStream":
                    return self

                def __exit__(self, *_args: object) -> None:
                    self.source.close()  # type: ignore[attr-defined]

                def read(self, count: int) -> bytes:
                    chunk = self.source.read(count)  # type: ignore[attr-defined]
                    if chunk:
                        return chunk
                    if not self.emitted_extra:
                        self.emitted_extra = True
                        return b"x"
                    return b""

            def overread(
                zipped: zipfile.ZipFile,
                member: object,
                mode: str = "r",
                pwd: bytes | None = None,
                *,
                force_zip64: bool = False,
            ) -> OverreadStream:
                return OverreadStream(
                    original_open(
                        zipped,
                        member,
                        mode,
                        pwd,
                        force_zip64=force_zip64,
                    )
                )

            with mock.patch.object(zipfile.ZipFile, "open", new=overread), self.assertRaisesRegex(
                ArtifactZipError, "declared uncompressed size"
            ):
                verify_artifact_zip(archive, output, digest, size)

    def test_rejects_malformed_archive(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = self.action_output(root)
            archive = root / "malformed.zip"
            archive.write_bytes(b"PK\x03\x04not-a-zip")
            self.rejected(archive, output, "cannot be safely unpacked")

    def test_rejects_action_output_nonregular_or_wrong_set(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive, output, digest, size = self.fixture(root)
            name = sorted(EXPECTED_FILES)[0]
            (output / name).unlink()
            (output / name).mkdir()
            with self.assertRaisesRegex(ArtifactZipError, "non-regular entry"):
                verify_artifact_zip(archive, output, digest, size)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive, output, digest, size = self.fixture(root)
            (output / sorted(EXPECTED_FILES)[0]).unlink()
            with self.assertRaisesRegex(ArtifactZipError, "nine-file candidate"):
                verify_artifact_zip(archive, output, digest, size)

    def test_rejects_action_extraction_content_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            archive, output, digest, size = self.fixture(Path(temporary))
            first = next(iter(EXPECTED_FILES))
            (output / first).write_bytes(b"mutated action extraction")
            with self.assertRaisesRegex(ArtifactZipError, "differs from action output"):
                verify_artifact_zip(archive, output, digest, size)


if __name__ == "__main__":
    unittest.main()
