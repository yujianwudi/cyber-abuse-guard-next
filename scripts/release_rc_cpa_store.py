#!/usr/bin/env python3
"""Create the deterministic CPA Plugin Store RC container from audited SO bytes."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import zipfile
from pathlib import Path


ENTRY_NAME = "cyber-abuse-guard.so"
SO_NAME = "cyber-abuse-guard-v1.0.0.so"
AUDIT_ZIP = "cyber-abuse-guard_1.0.0_linux_amd64.zip"
RC_ZIP = "cyber-abuse-guard_1.0.0-rc.1_linux_amd64.zip"
AUDIT_CHECKSUMS = "audit-candidate-checksums.txt"
CPA_CHECKSUMS = "checksums.txt"
AUDIT_CHECKSUM_NAMES = frozenset(
    {
        SO_NAME,
        f"{SO_NAME}.sha256",
        AUDIT_ZIP,
        "build-metadata.json",
        "ruleset-manifest.json",
        "ruleset.sha256",
        "sbom.cdx.json",
    }
)


def create(source: Path, output: Path) -> None:
    if source.is_symlink() or not source.is_file():
        raise ValueError("audited SO must be a regular non-symlink file")
    if output.exists() or output.is_symlink():
        raise ValueError("CPA Store ZIP output must not already exist")
    payload = source.read_bytes()
    info = zipfile.ZipInfo(ENTRY_NAME, date_time=(1980, 1, 1, 0, 0, 0))
    info.create_system = 3
    info.compress_type = zipfile.ZIP_STORED
    info.external_attr = (stat.S_IFREG | 0o755) << 16
    info.flag_bits = 0
    info.extra = b""
    info.comment = b""
    try:
        with output.open("xb") as raw, zipfile.ZipFile(raw, "w") as archive:
            archive.comment = b""
            archive.writestr(info, payload)
        os.chmod(output, 0o644)
    except BaseException:
        output.unlink(missing_ok=True)
        raise


def _zip_payload(path: Path, expected_entry: str, *, deterministic: bool = False) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"required Store ZIP is missing: {path.name}")
    with zipfile.ZipFile(path) as archive:
        infos = archive.infolist()
        if len(infos) != 1 or infos[0].filename != expected_entry or infos[0].is_dir():
            raise ValueError(f"{path.name} does not contain exactly {expected_entry} at root")
        info = infos[0]
        mode = info.external_attr >> 16
        if (
            info.flag_bits & 0x1
            or (mode and stat.S_IFMT(mode) not in (0, stat.S_IFREG))
        ):
            raise ValueError(f"{path.name} contains an unsafe non-regular or encrypted entry")
        if deterministic and not (
            archive.comment == b""
            and info.create_system == 3
            and info.compress_type == zipfile.ZIP_STORED
            and info.date_time == (1980, 1, 1, 0, 0, 0)
            and mode == (stat.S_IFREG | 0o755)
            and info.flag_bits == 0
            and info.extra == b""
            and info.comment == b""
        ):
            raise ValueError(f"{path.name} deterministic ZIP metadata drifted")
        return archive.read(info)


def _checksums(path: Path) -> dict[str, str]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"checksum file is missing: {path.name}")
    result: dict[str, str] = {}
    for line in path.read_text(encoding="ascii").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._-]*)", line)
        if match is None or match.group(2) in result:
            raise ValueError(f"{path.name} contains an invalid or duplicate checksum row")
        result[match.group(2)] = match.group(1)
    return result


def verify_release(directory: Path) -> None:
    directory = directory.resolve(strict=True)
    so = directory / SO_NAME
    if so.is_symlink() or not so.is_file():
        raise ValueError("audited standalone SO is missing or unsafe")
    if (directory / "cyber-abuse-guard-v1.0.0-rc.1.so").exists():
        raise ValueError("RC-named standalone SO must not be published")
    payload = so.read_bytes()
    digest = hashlib.sha256(payload).hexdigest()
    if _zip_payload(directory / AUDIT_ZIP, SO_NAME) != payload:
        raise ValueError("audited candidate Store ZIP payload drifted")
    if _zip_payload(directory / RC_ZIP, ENTRY_NAME, deterministic=True) != payload:
        raise ValueError("CPA RC Store ZIP payload differs from audited SO")
    audit = _checksums(directory / AUDIT_CHECKSUMS)
    if CPA_CHECKSUMS in audit:
        raise ValueError("candidate checksums may not masquerade as CPA release checksums")
    if set(audit) != AUDIT_CHECKSUM_NAMES:
        raise ValueError(
            "audit-candidate-checksums.txt does not cover the exact audited asset set"
        )
    for name in AUDIT_CHECKSUM_NAMES:
        path = directory / name
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"audited candidate asset is missing or unsafe: {name}")
        if audit[name] != hashlib.sha256(path.read_bytes()).hexdigest():
            raise ValueError(f"audit-candidate-checksums.txt hash differs for {name}")
    cpa = _checksums(directory / CPA_CHECKSUMS)
    expected_names = {SO_NAME, AUDIT_ZIP, RC_ZIP}
    if set(cpa) != expected_names:
        raise ValueError("checksums.txt does not cover the exact CPA release asset set")
    for name in expected_names:
        if cpa[name] != hashlib.sha256((directory / name).read_bytes()).hexdigest():
            raise ValueError(f"checksums.txt hash differs for {name}")
    provenance_path = directory / "release-provenance.json"
    if provenance_path.is_symlink() or not provenance_path.is_file():
        raise ValueError("release provenance file is missing or unsafe")
    provenance = json.loads(provenance_path.read_bytes())
    if not isinstance(provenance, dict):
        raise ValueError("release provenance must be a JSON object")
    expected_derived = [{
        "name": RC_ZIP,
        "relationship": "cpa-plugin-store-container",
        "derived_from": {"name": SO_NAME, "sha256": digest},
        "archive_entry": ENTRY_NAME,
        "payload_sha256": digest,
        "recompiled": False,
        "standalone_renamed": False,
    }]
    if provenance.get("derived_artifacts") != expected_derived:
        raise ValueError("release provenance does not bind the exact derived CPA container")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    create_parser = commands.add_parser("create")
    create_parser.add_argument("--source", required=True, type=Path)
    create_parser.add_argument("--output", required=True, type=Path)
    verify_parser = commands.add_parser("verify-release")
    verify_parser.add_argument("--directory", required=True, type=Path)
    args = parser.parse_args()
    try:
        if args.command == "create":
            create(args.source, args.output)
        else:
            verify_release(args.directory)
    except (OSError, ValueError, zipfile.BadZipFile) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
