#!/usr/bin/env python3
"""Verify GitHub's canonical artifact ZIP against API metadata and action output."""

from __future__ import annotations

import argparse
import hashlib
import stat
import tempfile
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
    if expected_digest[7:] != expected_digest[7:].lower() or expected_size < 1:
        raise ArtifactZipError("API artifact metadata is invalid")
    if archive.is_symlink() or not archive.is_file():
        raise ArtifactZipError("canonical artifact ZIP is not a regular file")
    raw = archive.read_bytes()
    if len(raw) != expected_size:
        raise ArtifactZipError("canonical artifact ZIP byte count differs from the API size")
    if hashlib.sha256(raw).hexdigest() != expected_digest[7:]:
        raise ArtifactZipError("canonical artifact ZIP SHA-256 differs from the API digest")

    action_files = _regular_directory_files(action_directory)
    try:
        with zipfile.ZipFile(archive) as zipped, tempfile.TemporaryDirectory() as temporary:
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
            if set(names) != EXPECTED_FILES:
                raise ArtifactZipError("canonical artifact ZIP is not the exact nine-file set")
            if sum(item.file_size for item in infos) > MAX_UNCOMPRESSED_BYTES:
                raise ArtifactZipError("canonical artifact ZIP exceeds the extraction limit")
            destination = Path(temporary)
            for item in infos:
                output = destination / item.filename
                with zipped.open(item, "r") as source, output.open("xb") as target:
                    while chunk := source.read(1024 * 1024):
                        target.write(chunk)
                if output.read_bytes() != action_files[item.filename].read_bytes():
                    raise ArtifactZipError(
                        f"canonical artifact ZIP differs from action output: {item.filename}"
                    )
    except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
        raise ArtifactZipError(f"canonical artifact ZIP cannot be safely unpacked: {exc}") from exc


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
