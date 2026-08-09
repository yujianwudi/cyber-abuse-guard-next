#!/usr/bin/env python3
"""Verify GitHub's canonical artifact ZIP against API metadata and action output."""

from __future__ import annotations

import argparse
import hashlib
import os
import stat
import zipfile
from pathlib import Path


EXPECTED_FILES = frozenset(
    {
        "cyber-abuse-guard.so",
        "cyber-abuse-guard.so.sha256",
        "cyber-abuse-guard_1.0.0_linux_amd64.zip",
        "audit-candidate-manifest.json",
        "build-metadata.json",
        "checksums.txt",
        "ruleset-manifest.json",
        "ruleset.sha256",
        "sbom.cdx.json",
    }
)
MAX_UNCOMPRESSED_BYTES = 1024 * 1024 * 1024
MAX_ARCHIVE_BYTES = 1024 * 1024 * 1024
READ_CHUNK_BYTES = 1024 * 1024
ALLOWED_COMPRESSIONS = frozenset({zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED})


class ArtifactZipError(ValueError):
    pass


def _regular_directory_files(directory: Path) -> dict[str, Path]:
    if directory.is_symlink() or not directory.is_dir():
        raise ArtifactZipError("action output is not a regular directory")
    files: dict[str, Path] = {}
    for entry in directory.iterdir():
        if entry.is_symlink() or not entry.is_file():
            raise ArtifactZipError("action output contains a non-regular entry")
        files[entry.name] = entry
    if set(files) != EXPECTED_FILES:
        raise ArtifactZipError("action output is not the exact nine-file candidate")
    return files


def verify_artifact_zip(
    archive: Path,
    action_directory: Path,
    expected_digest: str,
    expected_size: int,
) -> None:
    if not expected_digest.startswith("sha256:") or len(expected_digest) != 71:
        raise ArtifactZipError("API artifact digest is not a sha256 digest")
    try:
        int(expected_digest[7:], 16)
    except ValueError as exc:
        raise ArtifactZipError("API artifact digest is not lowercase hexadecimal") from exc
    if (
        expected_digest[7:] != expected_digest[7:].lower()
        or expected_size < 1
        or expected_size > MAX_ARCHIVE_BYTES
    ):
        raise ArtifactZipError("API artifact metadata is invalid")
    flags = os.O_RDONLY
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(archive, flags)
    except OSError as exc:
        raise ArtifactZipError("canonical artifact ZIP is not a regular file") from exc
    try:
        archive_handle = os.fdopen(descriptor, "rb", closefd=True)
    except BaseException:
        os.close(descriptor)
        raise
    try:
        archive_info = os.fstat(archive_handle.fileno())
        if not stat.S_ISREG(archive_info.st_mode) or archive_info.st_nlink != 1:
            raise ArtifactZipError("canonical artifact ZIP is not a regular file")
        if archive_info.st_size != expected_size:
            raise ArtifactZipError(
                "canonical artifact ZIP byte count differs from the API size"
            )
        archive_digest = hashlib.sha256()
        observed_archive_bytes = 0
        while chunk := archive_handle.read(READ_CHUNK_BYTES):
            observed_archive_bytes += len(chunk)
            if observed_archive_bytes > expected_size:
                raise ArtifactZipError(
                    "canonical artifact ZIP byte count differs from the API size"
                )
            archive_digest.update(chunk)
        if observed_archive_bytes != expected_size:
            raise ArtifactZipError(
                "canonical artifact ZIP byte count differs from the API size"
            )
        if archive_digest.hexdigest() != expected_digest[7:]:
            raise ArtifactZipError(
                "canonical artifact ZIP SHA-256 differs from the API digest"
            )
        archive_handle.seek(0)

        action_files = _regular_directory_files(action_directory)
        with zipfile.ZipFile(archive_handle) as zipped:
            infos = zipped.infolist()
            names = [item.filename for item in infos]
            if len(names) != len(set(names)):
                raise ArtifactZipError("canonical artifact ZIP contains a duplicate entry")
            for item in infos:
                mode = item.external_attr >> 16
                if (
                    item.flag_bits & 0x1
                    or item.is_dir()
                    or "\\" in item.filename
                    or Path(item.filename).name != item.filename
                    or (mode and stat.S_IFMT(mode) not in (0, stat.S_IFREG))
                ):
                    raise ArtifactZipError("canonical artifact ZIP contains an unsafe entry")
                if item.compress_type not in ALLOWED_COMPRESSIONS:
                    raise ArtifactZipError(
                        "canonical artifact ZIP uses an unsupported compression method"
                    )
            if set(names) != EXPECTED_FILES:
                raise ArtifactZipError(
                    "canonical artifact ZIP is not the exact nine-file set"
                )
            if sum(item.file_size for item in infos) > MAX_UNCOMPRESSED_BYTES:
                raise ArtifactZipError(
                    "canonical artifact ZIP exceeds the extraction limit"
                )
            extracted_bytes = 0
            for item in infos:
                action_path = action_files[item.filename]
                action_info = action_path.stat(follow_symlinks=False)
                if (
                    not stat.S_ISREG(action_info.st_mode)
                    or action_info.st_size != item.file_size
                ):
                    raise ArtifactZipError(
                        f"canonical artifact ZIP differs from action output: {item.filename}"
                    )
                entry_bytes = 0
                with zipped.open(item, "r") as source, action_path.open("rb") as action:
                    while chunk := source.read(READ_CHUNK_BYTES):
                        next_entry_bytes = entry_bytes + len(chunk)
                        if next_entry_bytes > item.file_size:
                            raise ArtifactZipError(
                                "canonical artifact ZIP entry exceeds its declared uncompressed size"
                            )
                        next_extracted_bytes = extracted_bytes + len(chunk)
                        if next_extracted_bytes > MAX_UNCOMPRESSED_BYTES:
                            raise ArtifactZipError(
                                "canonical artifact ZIP exceeds the extraction limit"
                            )
                        if action.read(len(chunk)) != chunk:
                            raise ArtifactZipError(
                                f"canonical artifact ZIP differs from action output: {item.filename}"
                            )
                        entry_bytes = next_entry_bytes
                        extracted_bytes = next_extracted_bytes
                    if action.read(1):
                        raise ArtifactZipError(
                            f"canonical artifact ZIP differs from action output: {item.filename}"
                        )
                if entry_bytes != item.file_size:
                    raise ArtifactZipError(
                        "canonical artifact ZIP entry byte count differs from its declared uncompressed size"
                    )
    except ArtifactZipError:
        raise
    except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
        raise ArtifactZipError(
            f"canonical artifact ZIP cannot be safely unpacked: {exc}"
        ) from exc
    finally:
        archive_handle.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--action-directory", type=Path, required=True)
    parser.add_argument("--expected-digest", required=True)
    parser.add_argument("--expected-size", type=int, required=True)
    args = parser.parse_args()
    try:
        verify_artifact_zip(
            args.archive,
            args.action_directory,
            args.expected_digest,
            args.expected_size,
        )
    except ArtifactZipError as exc:
        parser.error(str(exc))
    print("canonical artifact ZIP matches API metadata and exact action output")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
