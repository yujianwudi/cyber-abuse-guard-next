#!/usr/bin/env python3
"""Linux-only counted-Mock Host runner and Round 9 evidence assembler.

The runner has no Provider adapter. It starts one explicitly named CPA
container on a Docker internal network and talks only to a counted-Mock
container. The mock image must implement the private contract documented in
docs/ROUND9_HOST_RUNNER.md. Any failed assertion aborts without writing Host
evidence.

The assembler consumes only lane results produced by this runner. It computes
the candidate SO digest from the Phase 1 artifact and emits the closed JSON
schema accepted by release-rc.yml.
"""

from __future__ import annotations

import argparse
import base64
import errno
import hashlib
import json
import os
import platform
import re
import secrets
import shutil
import socket
import sqlite3
import stat
import subprocess
import sys
import tarfile
import time
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

import round9_docker_sandbox as docker_sandbox


TAG = "v0.16-rc.4"
ARTIFACT_VERSION = "0.16-rc.4"
SO_NAME = f"cyber-abuse-guard-v{ARTIFACT_VERSION}.so"
STORE_NAME = f"cyber-abuse-guard_{ARTIFACT_VERSION}_linux_amd64.zip"
SOURCE_NAME = f"cyber-abuse-guard-v{ARTIFACT_VERSION}-source.tar.gz"
PRIMARY_VERSION = "v7.2.113"
PRIMARY_COMMIT = "bc71c77f5cc42f3fbe1bf040cf14d4f166894835"
RUNNER_VERSION = 1
MOCK_PORT = 18080
CPA_PORT = 8317
CPA_HOST_IP = "127.0.0.1"
CPA_HOST_PORT = 18394
MAX_BODY = 16 * 1024 * 1024
SCAN_LIMIT_BYTES = 16 * 1024
MODEL_NAME = "round9-test-model"
CLIENT_KEY = "round9-internal-client-key"
MANAGEMENT_PATH = "/v0/management/plugins/cyber-abuse-guard"
MOCK_CONTRACT = "round9-counted-mock/v1"
CPA_SOURCE = "https://github.com/router-for-me/CLIProxyAPI"
MOCK_SOURCE = "https://github.com/yujianwudi/cyber-abuse-guard-next"
BASE_BUNDLE_SCHEMA_VERSION = 1
BASE_ARCHIVE_NAME = "round9-base-images-linux-amd64.tar.gz"
BASE_MANIFEST_NAME = "round9-base-images.json"
BASE_ARCHIVE_MAX_BYTES = 512 * 1024 * 1024
BASE_TRANSPORT = "github-attested-digest-bundle/v1"
GOLANG_BASE = {
    "upstream_from": "golang:1.26-bookworm",
    "canonical_reference": (
        "docker.io/library/golang:1.26.4-bookworm@"
        "sha256:b305420a68d0f229d91eb3b3ed9e519fcf2cf5461da4bef997bf927e8c0bfd2b"
    ),
    "index_digest": "sha256:b305420a68d0f229d91eb3b3ed9e519fcf2cf5461da4bef997bf927e8c0bfd2b",
    "platform_digest": "sha256:5a94593d87a066df5abb02969be911524963f53908292aa5a1a6096fc019012a",
    "image_id": "sha256:9d9d715d688ced62374388302667e31a6d3a0655c4c9e0ceaf1a4c4886752a62",
    "local_tag": "cag-round9-base:golang-1.26.4-bookworm-amd64-5a94593d87a0",
}
DEBIAN_BASE = {
    "upstream_from": "debian:bookworm",
    "canonical_reference": (
        "docker.io/library/debian:bookworm-20260623@"
        "sha256:30482e873082e906a4908c10529180aefb6f77620aea7404b909829fadc5d168"
    ),
    "index_digest": "sha256:30482e873082e906a4908c10529180aefb6f77620aea7404b909829fadc5d168",
    "platform_digest": "sha256:129588494497601baa5dbca1df687c835ff166ec4dd3bf307be684f34da07ab5",
    "image_id": "sha256:ee37b64a84a5a803ef11061304de62741b41b1f1b9e2a743b1e7686b12029d79",
    "local_tag": "cag-round9-base:debian-bookworm-20260623-amd64-129588494497",
}
HOST_WORKFLOW_PATH = ".github/workflows/round9-host-validation.yml"
RELEASE_WORKFLOW_PATH = ".github/workflows/round9-release-rc.yml"
WORKFLOW_REPOSITORY = "yujianwudi/cyber-abuse-guard-next"
HEX40 = re.compile(r"[0-9a-f]{40}")
HEX64 = re.compile(r"[0-9a-f]{64}")
RFC3339 = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]+)?(?:Z|[+-][0-9]{2}:[0-9]{2})"
)
AUDIT_BUNDLE_NAME = f"cyber-abuse-guard-v{ARTIFACT_VERSION}-audit-bundle.zip"
TEST_SUMMARY_NAME = "rc-release-test-summary.txt"
RELEASE_EVIDENCE_NAME = "rc-release-evidence.md"
PHASE1_ASSET_NAMES = frozenset(
    {
        SO_NAME,
        f"{SO_NAME}.sha256",
        STORE_NAME,
        AUDIT_BUNDLE_NAME,
        "build-metadata.json",
        "checksums.txt",
        "ruleset-manifest.json",
        "ruleset.sha256",
        "sbom.cdx.json",
        TEST_SUMMARY_NAME,
        f"{TEST_SUMMARY_NAME}.sha256",
        RELEASE_EVIDENCE_NAME,
        f"{RELEASE_EVIDENCE_NAME}.sha256",
        SOURCE_NAME,
        f"{SOURCE_NAME}.sha256",
        "rc-release-manifest.json",
        "rc-release-manifest.json.sha256",
    }
)
PHASE1_CHECKSUM_NAMES = (
    SO_NAME,
    f"{SO_NAME}.sha256",
    STORE_NAME,
    AUDIT_BUNDLE_NAME,
    "build-metadata.json",
    "ruleset-manifest.json",
    "ruleset.sha256",
    "sbom.cdx.json",
)
CONTAINER_LIMITS = {
    "mock": {"nano_cpus": 500_000_000, "memory": 128 * 1024 * 1024},
    "cpa": {"nano_cpus": 1_000_000_000, "memory": 512 * 1024 * 1024},
}


class RejectRedirectHandler(HTTPRedirectHandler):
    def redirect_request(
        self,
        request: Request,
        file_pointer: Any,
        code: int,
        message: str,
        headers: Any,
        new_url: str,
    ) -> None:
        return None


NO_PROXY_OPENER = build_opener(ProxyHandler({}), RejectRedirectHandler())


class RunnerError(RuntimeError):
    """A fail-closed runner error."""


def fail(message: str) -> None:
    raise RunnerError(message)


def strict_int(value: Any) -> bool:
    return type(value) is int and value >= 0


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def write_bytes(path: Path, value: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        fail(f"refusing symlink output: {path}")
    path.write_bytes(value)
    os.chmod(path, mode)


def write_json(path: Path, value: Any, mode: int = 0o600) -> None:
    write_bytes(path, canonical_bytes(value), mode)


FileIdentity = tuple[int, int]


def file_identity(info: os.stat_result) -> FileIdentity:
    return info.st_dev, info.st_ino


def owned_regular_file_at(
    directory_fd: int, name: str, identity: FileIdentity
) -> bool:
    try:
        info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return False
    return (
        stat.S_ISREG(info.st_mode)
        and not stat.S_ISLNK(info.st_mode)
        and file_identity(info) == identity
    )


def unlink_owned_file_at(
    directory_fd: int, name: str, identity: FileIdentity
) -> bool:
    """Remove only a regular directory entry still bound to our staged inode.

    The directory descriptor keeps lookup scoped to the already-open output
    directory. A concurrently created placeholder or replacement has a
    different inode and is deliberately left untouched.
    """

    try:
        info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return True
    if (
        not stat.S_ISREG(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or file_identity(info) != identity
    ):
        return False
    try:
        os.unlink(name, dir_fd=directory_fd)
    except FileNotFoundError:
        return True
    return True


def write_exclusive_staged_file_at(
    directory_fd: int, name: str, value: bytes, mode: int
) -> FileIdentity:
    """Create and fully fsync one same-directory stage without replacement."""

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(name, flags, mode, dir_fd=directory_fd)
    identity: FileIdentity | None = None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise OSError(errno.EINVAL, "staged output is not a regular file")
        identity = file_identity(info)
        remaining = memoryview(value)
        while remaining:
            try:
                written = os.write(fd, remaining)
            except InterruptedError:
                continue
            if written <= 0:
                raise OSError(errno.EIO, "short staged output write")
            remaining = remaining[written:]
        os.fchmod(fd, mode)
        os.fsync(fd)
        return identity
    except BaseException:
        if identity is not None:
            try:
                unlink_owned_file_at(directory_fd, name, identity)
            except OSError:
                pass
        raise
    finally:
        os.close(fd)


def regular_file(path: Path) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        fail(f"missing file: {path}")
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
        fail(f"file is not a regular non-symlink: {path}")


def sha256_file(path: Path) -> str:
    regular_file(path)
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run_command(
    args: list[str],
    *,
    label: str,
    timeout: float = 120,
    check: bool = True,
) -> subprocess.CompletedProcess[bytes]:
    try:
        result = subprocess.run(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        fail(f"{label} failed without exposing command output: {type(exc).__name__}")
    if check and result.returncode != 0:
        fail(f"{label} failed with exit={result.returncode}")
    return result


def docker(
    args: list[str], *, label: str, timeout: float = 120, check: bool = True
) -> subprocess.CompletedProcess[bytes]:
    return run_command(["docker", *args], label=label, timeout=timeout, check=check)


def parse_json_bytes(raw: bytes, label: str) -> Any:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    try:
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=reject_duplicates,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ValueError(f"invalid JSON constant: {value}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        fail(f"{label} returned invalid JSON: {type(exc).__name__}")


def expected_base_image_bundle(archive_sha256: str, archive_size: int) -> dict[str, Any]:
    if HEX64.fullmatch(archive_sha256) is None or not strict_int(archive_size):
        fail("base-image archive identity is invalid")
    return {
        "schema_version": BASE_BUNDLE_SCHEMA_VERSION,
        "platform": "linux/amd64",
        "acquisition": {
            "registry": "registry-1.docker.io",
            "mode": "direct-canonical-digest-pull",
            "relay": BASE_TRANSPORT,
        },
        "archive": {
            "name": BASE_ARCHIVE_NAME,
            "sha256": archive_sha256,
            "size": archive_size,
        },
        "images": {
            "golang": dict(GOLANG_BASE),
            "debian": dict(DEBIAN_BASE),
        },
    }


def validate_base_image_bundle(manifest_path: Path, archive_path: Path) -> str:
    regular_file(manifest_path)
    regular_file(archive_path)
    if manifest_path.name != BASE_MANIFEST_NAME or archive_path.name != BASE_ARCHIVE_NAME:
        fail("base-image bundle filenames do not match the reviewed contract")
    manifest_raw = manifest_path.read_bytes()
    if not 2 <= len(manifest_raw) <= 8192 or manifest_raw.endswith(b"\n"):
        fail("base-image manifest framing/size is invalid")
    manifest = parse_json_bytes(manifest_raw, "base-image manifest")
    if not isinstance(manifest, dict) or manifest_raw != canonical_bytes(manifest):
        fail("base-image manifest must be canonical UTF-8 JSON")
    archive_size = archive_path.stat().st_size
    if not 1 <= archive_size <= BASE_ARCHIVE_MAX_BYTES:
        fail("base-image archive size is outside the reviewed bound")
    archive_sha256 = sha256_file(archive_path)
    expected = expected_base_image_bundle(archive_sha256, archive_size)
    if not exact_equal(manifest, expected):
        fail("base-image manifest does not match the reviewed immutable identities")
    return archive_sha256


def golang_base_labels() -> dict[str, str]:
    return {
        "io.cyber-abuse-guard.round9.base-transport": BASE_TRANSPORT,
        "io.cyber-abuse-guard.round9.golang.canonical-reference": GOLANG_BASE[
            "canonical_reference"
        ],
        "io.cyber-abuse-guard.round9.golang.platform-digest": GOLANG_BASE[
            "platform_digest"
        ],
        "io.cyber-abuse-guard.round9.golang.image-id": GOLANG_BASE["image_id"],
    }


def cpa_base_labels() -> dict[str, str]:
    labels = golang_base_labels()
    labels.update(
        {
            "io.cyber-abuse-guard.round9.debian.canonical-reference": DEBIAN_BASE[
                "canonical_reference"
            ],
            "io.cyber-abuse-guard.round9.debian.platform-digest": DEBIAN_BASE[
                "platform_digest"
            ],
            "io.cyber-abuse-guard.round9.debian.image-id": DEBIAN_BASE["image_id"],
        }
    )
    return labels


def require_local_unix_endpoint(endpoint: str, label: str) -> Path:
    try:
        socket_path, _ = docker_sandbox.require_unix_socket(endpoint, label)
    except docker_sandbox.SandboxError as exc:
        fail(str(exc))
    return socket_path


def require_local_docker(args: argparse.Namespace, challenge_root: Path) -> dict[str, Any]:
    try:
        return docker_sandbox.verify_sandbox(
            sandbox_id=args.sandbox_id,
            daemon_id=args.daemon_id,
            probe_image_id=args.probe_image_id,
            challenge=args.challenge,
            challenge_root=challenge_root,
        )
    except docker_sandbox.SandboxError as exc:
        fail(str(exc))


def require_linux(args: argparse.Namespace, challenge_root: Path) -> dict[str, Any]:
    if platform.system() != "Linux" or platform.machine().lower() not in {"x86_64", "amd64"}:
        fail(f"Round 9 Host runner requires Linux amd64, got {platform.system()}/{platform.machine()}")
    if shutil.which("docker") is None:
        fail("docker is required")
    try:
        sqlite3.connect(":memory:").execute("PRAGMA quick_check").fetchone()
    except Exception as exc:
        fail(f"Python sqlite3 is required for the final database check: {type(exc).__name__}")
    return require_local_docker(args, challenge_root)


def image_metadata(image: str) -> dict[str, Any]:
    result = docker(["image", "inspect", image], label="image inspection", timeout=30)
    payload = parse_json_bytes(result.stdout, "docker image inspect")
    if not isinstance(payload, list) or len(payload) != 1 or not isinstance(payload[0], dict):
        fail("docker image inspect did not return exactly one image")
    return payload[0]


def verify_cpa_image(image: str, version: str, commit: str) -> tuple[str, str]:
    metadata = image_metadata(image)
    if metadata.get("Os") != "linux" or metadata.get("Architecture") != "amd64":
        fail(f"{version} image must be linux/amd64")
    image_config = metadata.get("Config")
    if not isinstance(image_config, dict):
        fail(f"{version} image has no inspectable config")
    labels = image_config.get("Labels") or {}
    if not isinstance(labels, dict):
        fail(f"{version} image labels are invalid")
    build_date = labels.get("org.opencontainers.image.created")
    expected_labels = {
        "org.opencontainers.image.source": CPA_SOURCE,
        "org.opencontainers.image.revision": commit,
        "org.opencontainers.image.version": version,
        **cpa_base_labels(),
    }
    for key, expected in expected_labels.items():
        if labels.get(key) != expected:
            fail(f"{version} image OCI label {key} does not match")
    if not isinstance(build_date, str) or RFC3339.fullmatch(build_date) is None:
        fail(f"{version} image OCI build date is not exact RFC3339 metadata")
    image_id = metadata.get("Id")
    if (
        not isinstance(image_id, str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", image_id) is None
    ):
        fail(f"{version} image has no immutable local image id")
    probe = docker(
        [
            "run",
            "--rm",
            "--network",
            "none",
            "--read-only",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,size=16m",
            "--entrypoint",
            "/CLIProxyAPI/CLIProxyAPI",
            image_id,
            "-h",
        ],
        label=f"{version} binary identity probe",
        timeout=30,
    )
    first_line = probe.stdout.splitlines()[:1]
    expected_first_line = (
        f"CLIProxyAPI Version: {version}, Commit: {commit}, BuiltAt: {build_date}"
    ).encode("utf-8")
    if first_line != [expected_first_line]:
        fail(
            f"{version} binary first line does not exactly match VERSION/COMMIT/BUILD_DATE"
        )
    return image_id, build_date


def verify_sha256_sidecar(path: Path, target: Path) -> None:
    regular_file(path)
    regular_file(target)
    expected = f"{sha256_file(target)}  {target.name}\n".encode("utf-8")
    if path.read_bytes() != expected:
        fail(f"{path.name} does not exactly bind {target.name}")


def verify_artifacts(
    artifacts: Path, commit: str, tree: str
) -> tuple[Path, str, list[dict[str, str]]]:
    if not artifacts.is_dir() or artifacts.is_symlink():
        fail("Phase 1 artifact directory must be a real directory")
    actual_assets: set[str] = set()
    for path in artifacts.iterdir():
        if path.name in actual_assets:
            fail("Phase 1 artifact directory contains a duplicate name")
        actual_assets.add(path.name)
        regular_file(path)
        if path.stat().st_size <= 0 or path.stat().st_size > 128 * 1024 * 1024:
            fail(f"Phase 1 asset size is outside the bounded range: {path.name}")
    if actual_assets != PHASE1_ASSET_NAMES:
        fail("Phase 1 artifact directory must contain the exact 17-asset set")
    so = artifacts / SO_NAME
    so_sidecar = artifacts / f"{SO_NAME}.sha256"
    store = artifacts / STORE_NAME
    source = artifacts / SOURCE_NAME
    source_sidecar = artifacts / f"{SOURCE_NAME}.sha256"
    manifest_path = artifacts / "rc-release-manifest.json"
    manifest_sidecar = artifacts / "rc-release-manifest.json.sha256"
    checksums = artifacts / "checksums.txt"
    if so.stat().st_size <= 0 or so.stat().st_size > 128 * 1024 * 1024:
        fail("candidate SO size is outside the bounded Host-test range")
    if store.stat().st_size <= 0 or store.stat().st_size > 128 * 1024 * 1024:
        fail("Store archive size is outside the bounded Host-test range")
    if source.stat().st_size <= 0 or source.stat().st_size > 128 * 1024 * 1024:
        fail("source archive size is outside the bounded Host-test range")
    for target_name in (
        SO_NAME,
        TEST_SUMMARY_NAME,
        RELEASE_EVIDENCE_NAME,
        SOURCE_NAME,
        "rc-release-manifest.json",
    ):
        verify_sha256_sidecar(
            artifacts / f"{target_name}.sha256", artifacts / target_name
        )
    so_sha = sha256_file(so)
    manifest_raw = manifest_path.read_bytes()
    manifest = parse_json_bytes(manifest_raw, "RC manifest")
    if not isinstance(manifest, dict):
        fail("RC manifest is not an object")
    if manifest_raw != canonical_bytes(manifest):
        fail("RC manifest must be canonical UTF-8 JSON without trailing bytes")
    required = {
        "schema_version": 4,
        "release_phase": "candidate",
        "publish_rc_release": False,
        "artifact_version": ARTIFACT_VERSION,
        "tag": TAG,
        "commit": commit,
        "tree": tree,
    }
    for key, expected in required.items():
        if manifest.get(key) != expected:
            fail(f"RC manifest identity mismatch at {key}")
    checksum_lines: dict[str, str] = {}
    checksum_order: list[str] = []
    try:
        checksum_text = checksums.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        fail("checksums.txt is not UTF-8")
    if not checksum_text.endswith("\n") or "\r" in checksum_text:
        fail("checksums.txt framing is not canonical")
    for line in checksum_text.splitlines():
        fields = line.split()
        if (
            len(fields) != 2
            or HEX64.fullmatch(fields[0]) is None
            or fields[1] not in PHASE1_CHECKSUM_NAMES
            or line != f"{fields[0]}  {fields[1]}"
            or fields[1] in checksum_lines
        ):
            fail("checksums.txt schema/order entry is invalid")
        checksum_lines[fields[1]] = fields[0]
        checksum_order.append(fields[1])
    if tuple(checksum_order) != PHASE1_CHECKSUM_NAMES:
        fail("checksums.txt must bind the exact Phase 1 checksum set in order")
    for name in PHASE1_CHECKSUM_NAMES:
        if checksum_lines[name] != sha256_file(artifacts / name):
            fail(f"checksums.txt does not bind {name}")
    with zipfile.ZipFile(store) as archive:
        names = archive.namelist()
        if names != [SO_NAME]:
            fail("Store archive must contain exactly the candidate SO at its root")
        info = archive.getinfo(SO_NAME)
        mode = (info.external_attr >> 16) & 0xFFFF
        if info.is_dir() or info.file_size != so.stat().st_size or stat.S_ISLNK(mode):
            fail("Store archive candidate is not the bounded regular SO")
        if hashlib.sha256(archive.read(SO_NAME)).hexdigest() != so_sha:
            fail("Store archive SO bytes differ from standalone candidate")
    fixture_records: list[dict[str, str]] = []
    with tarfile.open(source, "r:gz") as archive:
        fixture = None
        members = archive.getmembers()
        if sum(member.size for member in members if member.isfile()) > 256 * 1024 * 1024:
            fail("source archive expands beyond the Host-test bound")
        for member in members:
            name = member.name.replace("\\", "/")
            if (
                name.startswith("/")
                or re.match(r"^[A-Za-z]:", name) is not None
                or any(part == ".." for part in name.split("/"))
                or not (member.isfile() or member.isdir())
            ):
                fail("source archive contains an unsafe path")
            parts = [part.lower() for part in name.split("/") if part]
            if any(
                re.search(
                    r"(?:evaluation|holdout|consumed|private|blind|retired)",
                    part,
                )
                is not None
                for part in parts
            ):
                fail("source archive contains restricted evaluation material")
            if name.endswith("testdata/round8_balanced_readmission.json"):
                if not member.isfile() or fixture is not None:
                    fail("source archive has an invalid or duplicate historical Round 8 smoke fixture")
                fixture = member
        if fixture is None:
            fail("source archive does not contain the historical Round 8 smoke fixture")
        stream = archive.extractfile(fixture)
        if stream is None:
            fail("cannot read the historical Round 8 smoke fixture")
        document = parse_json_bytes(stream.read(), "historical Round 8 smoke fixture")
    if not isinstance(document, dict) or document.get("schema") != "round8-balanced-readmission/v1":
        fail("historical Round 8 smoke fixture schema mismatch")
    pairs = document.get("pairs")
    if not isinstance(pairs, list) or len(pairs) != 42:
        fail("historical Round 8 smoke fixture must contain exactly 42 pairs")
    seen: set[str] = set()
    for pair in pairs:
        if not isinstance(pair, dict):
            fail("historical Round 8 smoke fixture pair is not an object")
        expected_keys = {"family", "provenance", "rule_id", "category", "benign", "malicious"}
        if set(pair) != expected_keys:
            fail("historical Round 8 smoke fixture pair schema is not exact")
        values = {key: pair.get(key) for key in expected_keys}
        if any(not isinstance(value, str) or not value for value in values.values()):
            fail("historical Round 8 smoke fixture pair has an empty required field")
        if values["provenance"] != "synthetic_from_production_fp_family":
            fail("historical Round 8 smoke fixture provenance is not synthetic")
        if values["family"] in seen:
            fail("historical Round 8 smoke fixture contains a duplicate family")
        seen.add(values["family"])
        fixture_records.append(values)
    return so, so_sha, fixture_records


class Transcript:
    def __init__(self, path: Path, lane: str) -> None:
        self.path = path
        self.lane = lane
        self.records: list[dict[str, Any]] = []

    def record(self, check: str, **values: Any) -> None:
        self.records.append({"check": check, "lane": self.lane, **values})

    def close(self) -> str:
        data = b"".join(canonical_bytes(item) + b"\n" for item in self.records)
        write_bytes(self.path, data, 0o600)
        return hashlib.sha256(data).hexdigest()


def http_request(
    base_url: str,
    method: str,
    path: str,
    body: Any = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, bytes]:
    parsed = urlsplit(base_url)
    if (
        parsed.scheme != "http"
        or parsed.hostname != "127.0.0.1"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path != ""
        or parsed.query
        or parsed.fragment
    ):
        fail("Host runner HTTP base URL must be exact loopback HTTP")
    try:
        port = parsed.port
    except ValueError:
        fail("Host runner HTTP base URL has an invalid port")
    if port is None or port < 1024 or port > 65535:
        fail("Host runner HTTP base URL must use an explicit unprivileged port")
    if (
        not isinstance(path, str)
        or not path.startswith("/")
        or path.startswith("//")
        or "\r" in path
        or "\n" in path
    ):
        fail("Host runner HTTP request path is invalid")
    if body is None:
        data = None
    elif isinstance(body, bytes):
        data = body
    else:
        data = canonical_bytes(body)
    request = Request(base_url + path, data=data, method=method)
    request.add_header("Accept", "application/json")
    if data is not None:
        request.add_header("Content-Type", "application/json")
    for key, value in (headers or {}).items():
        request.add_header(key, value)
    try:
        with NO_PROXY_OPENER.open(request, timeout=10) as response:
            raw = response.read(MAX_BODY + 1)
            if len(raw) > MAX_BODY:
                fail(f"HTTP {method} {path} exceeded the response bound")
            return int(response.status), raw
    except HTTPError as exc:
        try:
            raw = exc.read(MAX_BODY + 1)
        finally:
            exc.close()
        if len(raw) > MAX_BODY:
            fail(f"HTTP {method} {path} exceeded the error response bound")
        return int(exc.code), raw
    except (URLError, TimeoutError, OSError) as exc:
        fail(f"HTTP {method} {path} failed: {type(exc).__name__}")


def http_json(
    base_url: str,
    method: str,
    path: str,
    body: Any = None,
    headers: dict[str, str] | None = None,
    expected: int = 200,
) -> Any:
    status, raw = http_request(base_url, method, path, body, headers)
    if status != expected:
        fail(f"HTTP {method} {path} returned {status}, expected {expected}")
    return parse_json_bytes(raw, f"HTTP {method} {path}")


def parse_sse_frames(raw: bytes, label: str) -> list[tuple[str | None, bytes]]:
    try:
        text = raw.decode("utf-8", "strict")
    except UnicodeDecodeError:
        fail(f"{label} SSE response is not UTF-8")
    if "\r" in text.replace("\r\n", ""):
        fail(f"{label} SSE response contains an invalid carriage return")
    text = text.replace("\r\n", "\n")
    if not text.endswith("\n\n"):
        fail(f"{label} SSE response has no terminal frame boundary")
    frames: list[tuple[str | None, bytes]] = []
    for block in text[:-2].split("\n\n"):
        if not block:
            fail(f"{label} SSE response contains an empty frame")
        event: str | None = None
        data_lines: list[str] = []
        for line in block.split("\n"):
            if line.startswith("event: ") and event is None:
                event = line[len("event: ") :]
            elif line.startswith("data: "):
                data_lines.append(line[len("data: ") :])
            else:
                fail(f"{label} SSE response contains an unsupported field")
        if len(data_lines) != 1:
            fail(f"{label} SSE frame must contain exactly one data field")
        frames.append((event, data_lines[0].encode("utf-8")))
    if not frames:
        fail(f"{label} SSE response is empty")
    return frames


def validate_upstream_response(protocol: str, stream: bool, raw: bytes) -> tuple[bool, bool]:
    label = f"{protocol} {'stream' if stream else 'non-stream'}"
    if not stream:
        payload = parse_json_bytes(raw, f"{label} response")
        if not isinstance(payload, dict):
            fail(f"{label} response is not an object")
        usage = payload.get("usage")
        if (
            not isinstance(usage, dict)
            or not strict_int(usage.get("total_tokens"))
            or usage["total_tokens"] < 1
        ):
            fail(f"{label} response usage is invalid")
        if protocol == "chat":
            choices = payload.get("choices")
            choice = choices[0] if isinstance(choices, list) and len(choices) == 1 else None
            message = choice.get("message") if isinstance(choice, dict) else None
            if (
                payload.get("object") != "chat.completion"
                or payload.get("model") != MODEL_NAME
                or not isinstance(message, dict)
                or message.get("role") != "assistant"
                or not isinstance(message.get("content"), str)
                or choice.get("finish_reason") != "stop"
            ):
                fail("Chat non-stream response/termination contract mismatch")
        elif protocol == "responses":
            output = payload.get("output")
            item = output[0] if isinstance(output, list) and len(output) == 1 else None
            content = item.get("content") if isinstance(item, dict) else None
            output_text = (
                content[0] if isinstance(content, list) and len(content) == 1 else None
            )
            if (
                payload.get("object") != "response"
                or payload.get("status") != "completed"
                or payload.get("model") != MODEL_NAME
                or not isinstance(item, dict)
                or item.get("type") != "message"
                or item.get("status") != "completed"
                or not isinstance(output_text, dict)
                or output_text.get("type") != "output_text"
                or not isinstance(output_text.get("text"), str)
            ):
                fail("Responses non-stream response/termination contract mismatch")
        else:
            fail("unsupported response protocol")
        return True, True

    frames = parse_sse_frames(raw, label)
    if protocol == "chat":
        if frames[-1] != (None, b"[DONE]") or len(frames) < 3:
            fail("Chat stream is missing its final [DONE] marker")
        chunks: list[dict[str, Any]] = []
        for event, data in frames[:-1]:
            if event is not None:
                fail("Chat stream unexpectedly contains named SSE events")
            chunk = parse_json_bytes(data, "Chat stream chunk")
            if not isinstance(chunk, dict):
                fail("Chat stream chunk is not an object")
            chunks.append(chunk)
        final_choices = chunks[-1].get("choices")
        final_choice = (
            final_choices[0]
            if isinstance(final_choices, list) and len(final_choices) == 1
            else None
        )
        if (
            any(
                chunk.get("object") != "chat.completion.chunk"
                or chunk.get("model") != MODEL_NAME
                for chunk in chunks
            )
            or not isinstance(final_choice, dict)
            or final_choice.get("finish_reason") != "stop"
        ):
            fail("Chat stream chunk/termination contract mismatch")
    elif protocol == "responses":
        events = [event for event, _ in frames]
        if events != [
            "response.created",
            "response.output_text.delta",
            "response.completed",
        ]:
            fail("Responses stream event order/termination marker mismatch")
        completed = parse_json_bytes(frames[-1][1], "Responses completed event")
        if (
            not isinstance(completed, dict)
            or completed.get("object") != "response"
            or completed.get("status") != "completed"
            or completed.get("model") != MODEL_NAME
        ):
            fail("Responses stream completed event contract mismatch")
        delta = parse_json_bytes(frames[1][1], "Responses delta event")
        if not isinstance(delta, dict) or delta.get("type") != "response.output_text.delta":
            fail("Responses stream delta event contract mismatch")
    else:
        fail("unsupported response protocol")
    return True, True


def exact_equal(actual: Any, expected: Any) -> bool:
    if type(actual) is not type(expected):
        return False
    if isinstance(expected, dict):
        return set(actual) == set(expected) and all(
            exact_equal(actual[key], value) for key, value in expected.items()
        )
    if isinstance(expected, list):
        return len(actual) == len(expected) and all(
            exact_equal(left, right) for left, right in zip(actual, expected)
        )
    return actual == expected


EXPECTED_HOST_RESULTS = {
    "network_binding": {
        "host_ip": CPA_HOST_IP,
        "host_port": CPA_HOST_PORT,
        "container_port": CPA_PORT,
    },
    "protocol_requests": {
        "chat_benign_upstream": 1,
        "chat_malicious_upstream": 0,
        "responses_benign_upstream": 1,
        "responses_malicious_upstream": 0,
    },
    "matrix": {
        "benign_total": 42,
        "benign_passed": 42,
        "host_smoke_malicious_total": 42,
        "host_smoke_malicious_blocked": 42,
    },
    "transports": {"nonstream_passed": True, "stream_passed": True},
    "modes": {"audit_passed": True, "balanced_passed": True, "strict_passed": True},
    "policy_outcomes": {
        "balanced_incomplete_allow": True,
        "strict_incomplete_block": True,
        "usage_queue_allow_delta": 1,
        "usage_queue_blocked_zero": True,
    },
    "database": {
        "quick_check": "ok",
        "schema_version": 6,
        "migration_versions": [1, 2, 3, 4, 5, 6],
        "wal_checkpoint_passed": True,
    },
    "raw_capture": {
        "only_blocked_passed": True,
        "ttl_dedup_passed": True,
        "schema_v4_redaction_metadata_passed": True,
        "purge_wal_passed": True,
    },
    "lifecycle": {
        "restart_cycle_passed": True,
        "unexpected_restart_count": 0,
        "oom": False,
        "panic_count": 0,
        "fatal_count": 0,
        "plugin_error_count": 0,
    },
}


TRANSCRIPT_KEYS = {
    "check",
    "lane",
    "protocol",
    "case",
    "mode",
    "family",
    "stream",
    "status",
    "upstream_before",
    "upstream_after",
    "upstream_delta",
    "queue_count",
    "passed",
    "request_sha256",
    "response_sha256",
    "request_bytes",
    "scan_limit_bytes",
    "valid_json",
    "image_id",
    "contract",
    "version",
    "commit",
    "source",
    "revision",
    "tag",
    "tree",
    "build_date",
    "so_sha256",
    "config_sha256",
    "plugin_path",
    "enabled",
    "benign_captures",
    "blocked_captures",
    "deduplicated",
    "ttl_removed",
    "purge_removed",
    "schema_version",
    "redaction_applied",
    "redaction_hits",
    "returned_count",
    "quick_check",
    "wal_busy",
    "wal_log_frames",
    "wal_checkpointed_frames",
    "migration_versions",
    "restart_count",
    "exit_code",
    "oom",
    "panic_count",
    "fatal_count",
    "plugin_error_count",
    "real_provider_contacted",
    "production_accessed",
    "response_format",
    "termination_marker",
    "stopped_exit_code",
    "running",
    "host_ip",
    "host_port",
    "container_port",
}


def validate_transcript_record(record: Any, lane: str) -> dict[str, Any]:
    if not isinstance(record, dict) or not set(record).issubset(TRANSCRIPT_KEYS):
        fail("Host transcript contains an unknown field")
    if record.get("lane") != lane or not isinstance(record.get("check"), str):
        fail("Host transcript lane/check identity mismatch")
    for key, value in record.items():
        if isinstance(value, (dict, list)) or value is None:
            fail(f"Host transcript field {key} has an unsafe type")
        if isinstance(value, str) and len(value.encode("utf-8")) > 160:
            fail(f"Host transcript field {key} exceeds the privacy-safe bound")
    for key in ("request_sha256", "response_sha256", "so_sha256", "config_sha256"):
        if key in record and (
            not isinstance(record[key], str) or HEX64.fullmatch(record[key]) is None
        ):
            fail(f"Host transcript field {key} is not a SHA-256")
    return record


def load_transcript(path: Path, lane: str) -> list[dict[str, Any]]:
    regular_file(path)
    raw = path.read_bytes()
    if not raw or len(raw) > 2 * 1024 * 1024 or not raw.endswith(b"\n"):
        fail("Host transcript size/framing is invalid")
    records: list[dict[str, Any]] = []
    for index, line in enumerate(raw.splitlines(), start=1):
        if not line or len(line) > 4096:
            fail(f"Host transcript line {index} is invalid")
        parsed = parse_json_bytes(line, f"Host transcript line {index}")
        if line != canonical_bytes(parsed):
            fail(f"Host transcript line {index} is not canonical JSON")
        records.append(validate_transcript_record(parsed, lane))
    return records


def one_record(
    records: list[dict[str, Any]], check: str, **identity: Any
) -> dict[str, Any]:
    matches = [
        record
        for record in records
        if record.get("check") == check
        and all(record.get(key) == value for key, value in identity.items())
    ]
    if len(matches) != 1:
        fail(f"Host transcript must contain exactly one {check} observation")
    return matches[0]


def require_observation(
    record: dict[str, Any], *, status: int | None = None, delta: int | None = None
) -> None:
    if record.get("passed") is not True:
        fail(f"Host transcript observation {record.get('check')} did not pass")
    if status is not None and record.get("status") != status:
        fail(f"Host transcript observation {record.get('check')} status mismatch")
    if delta is not None and record.get("upstream_delta") != delta:
        fail(f"Host transcript observation {record.get('check')} count mismatch")


def require_valid_response_observation(record: dict[str, Any]) -> None:
    if (
        record.get("response_format") is not True
        or record.get("termination_marker") is not True
    ):
        fail(f"Host transcript observation {record.get('check')} response contract mismatch")


def derive_host_results(
    records: list[dict[str, Any]],
    expected_families: Iterable[str],
    lane: str,
    expected_so_sha: str | None = None,
    expected_mock_image_id: str | None = None,
    expected_cpa_image_id: str | None = None,
    expected_cpa_build_date: str | None = None,
    expected_release_commit: str | None = None,
    expected_release_tree: str | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    if lane != "primary":
        fail("unsupported Host lane")
    records = [validate_transcript_record(record, lane) for record in records]
    expected_section_counts = {
        "artifact": 1,
        "mock_contract": 1,
        "runtime_identity": 1,
        "network_binding": 1,
        "protocol": 4,
        "matrix": 84,
        "transport": 8,
        "mode": 5,
        "policy": 4,
        "tool_schema": 4,
        "raw_capture": 4,
        "database": 1,
        "controlled_restart": 1,
        "lifecycle": 1,
        "safety": 1,
    }
    for check, expected_count in expected_section_counts.items():
        if len([record for record in records if record.get("check") == check]) != expected_count:
            fail(f"Host transcript {check} observation count mismatch")

    artifact = one_record(records, "artifact", case="exact_store_so")
    require_observation(artifact)
    if (
        not isinstance(artifact.get("so_sha256"), str)
        or HEX64.fullmatch(artifact["so_sha256"]) is None
        or not isinstance(artifact.get("config_sha256"), str)
        or HEX64.fullmatch(artifact["config_sha256"]) is None
        or artifact.get("plugin_path")
        != f"plugins/linux/amd64/{SO_NAME}"
        or (
            expected_so_sha is not None
            and artifact.get("so_sha256") != expected_so_sha
        )
    ):
        fail("candidate artifact observation is not exact")
    mock_contract = one_record(
        records, "mock_contract", case="health_reset_stats"
    )
    require_observation(mock_contract)
    if (
        mock_contract.get("contract") != MOCK_CONTRACT
        or mock_contract.get("source") != MOCK_SOURCE
        or mock_contract.get("tag") != TAG
        or not isinstance(mock_contract.get("revision"), str)
        or HEX40.fullmatch(mock_contract["revision"]) is None
        or not isinstance(mock_contract.get("tree"), str)
        or HEX40.fullmatch(mock_contract["tree"]) is None
        or not isinstance(mock_contract.get("image_id"), str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", mock_contract["image_id"])
        is None
        or (
            expected_mock_image_id is not None
            and mock_contract.get("image_id") != expected_mock_image_id
        )
        or (
            expected_release_commit is not None
            and mock_contract.get("revision") != expected_release_commit
        )
        or (
            expected_release_tree is not None
            and mock_contract.get("tree") != expected_release_tree
        )
    ):
        fail("counted-Mock contract/image observation is not exact")

    network_binding = one_record(
        records, "network_binding", case="cpa_management_and_api"
    )
    require_observation(network_binding)
    if (
        network_binding.get("host_ip") != CPA_HOST_IP
        or network_binding.get("host_port") != CPA_HOST_PORT
        or network_binding.get("container_port") != CPA_PORT
    ):
        fail("CPA Host network binding observation is not exact")

    protocol_results: dict[str, int] = {}
    for protocol, path_name in (("chat", "chat"), ("responses", "responses")):
        benign = one_record(
            records, "protocol", protocol=protocol, case="benign", stream=False
        )
        malicious = one_record(
            records, "protocol", protocol=protocol, case="malicious", stream=False
        )
        require_observation(benign, status=200, delta=1)
        require_valid_response_observation(benign)
        require_observation(malicious, status=403, delta=0)
        protocol_results[f"{path_name}_benign_upstream"] = benign["upstream_delta"]
        protocol_results[f"{path_name}_malicious_upstream"] = malicious["upstream_delta"]

    families = list(expected_families)
    if len(families) != 42 or len(set(families)) != 42:
        fail("Round 9 expected family identity is invalid")
    benign_passed = 0
    malicious_blocked = 0
    for family in families:
        benign = one_record(records, "matrix", family=family, case="benign")
        malicious = one_record(records, "matrix", family=family, case="malicious")
        require_observation(benign, status=200, delta=1)
        require_valid_response_observation(benign)
        require_observation(malicious, status=403, delta=0)
        benign_passed += 1
        malicious_blocked += 1
    for protocol in ("chat", "responses"):
        for stream in (False, True):
            benign = one_record(
                records,
                "transport",
                protocol=protocol,
                case="benign",
                stream=stream,
            )
            malicious = one_record(
                records,
                "transport",
                protocol=protocol,
                case="malicious",
                stream=stream,
            )
            require_observation(benign, status=200, delta=1)
            require_valid_response_observation(benign)
            require_observation(malicious, status=403, delta=0)

    mode_expectations = {
        ("audit", "malicious"): (200, 1),
        ("balanced", "benign"): (200, 1),
        ("balanced", "malicious"): (403, 0),
        ("strict", "benign"): (200, 1),
        ("strict", "malicious"): (403, 0),
    }
    for (mode, case), (status, delta) in mode_expectations.items():
        observation = one_record(records, "mode", mode=mode, case=case)
        require_observation(observation, status=status, delta=delta)
        if status == 200:
            require_valid_response_observation(observation)

    balanced_incomplete = one_record(
        records, "policy", case="balanced_incomplete"
    )
    strict_incomplete = one_record(records, "policy", case="strict_incomplete")
    usage_allow = one_record(records, "policy", case="usage_allow")
    usage_blocked = one_record(records, "policy", case="usage_blocked")
    require_observation(balanced_incomplete, status=200, delta=1)
    require_valid_response_observation(balanced_incomplete)
    require_observation(strict_incomplete, status=403, delta=0)
    for observation in (balanced_incomplete, strict_incomplete):
        if (
            not strict_int(observation.get("request_bytes"))
            or observation["request_bytes"] <= SCAN_LIMIT_BYTES
            or observation["request_bytes"] > MAX_BODY
            or observation.get("scan_limit_bytes") != SCAN_LIMIT_BYTES
            or observation.get("valid_json") is not True
        ):
            fail("incomplete policy observation is not a valid over-limit JSON request")
    if (
        balanced_incomplete.get("request_sha256")
        != strict_incomplete.get("request_sha256")
        or balanced_incomplete.get("request_bytes")
        != strict_incomplete.get("request_bytes")
    ):
        fail("Balanced and Strict incomplete checks did not use the same request bytes")
    require_observation(usage_allow, status=200, delta=1)
    require_valid_response_observation(usage_allow)
    require_observation(usage_blocked, status=403, delta=0)
    if usage_allow.get("queue_count") != 1 or usage_blocked.get("queue_count") != 0:
        fail("CPA usage-queue observations do not prove allow/block isolation")

    for protocol in ("chat", "responses"):
        benign_tool = one_record(
            records, "tool_schema", protocol=protocol, case="benign"
        )
        require_observation(benign_tool, status=200, delta=1)
        require_valid_response_observation(benign_tool)
        require_observation(
            one_record(
                records, "tool_schema", protocol=protocol, case="malicious"
            ),
            status=403,
            delta=0,
        )

    only_blocked = one_record(records, "raw_capture", case="only_blocked")
    ttl_dedup = one_record(records, "raw_capture", case="ttl_dedup")
    schema_metadata = one_record(
        records, "raw_capture", case="schema_v4_redaction_metadata"
    )
    purge_wal = one_record(records, "raw_capture", case="purge_wal")
    for observation in (only_blocked, ttl_dedup, schema_metadata, purge_wal):
        require_observation(observation)
    if only_blocked.get("benign_captures") != 0 or only_blocked.get("blocked_captures") != 1:
        fail("Raw Capture only-blocked observation mismatch")
    if not strict_int(ttl_dedup.get("deduplicated")) or ttl_dedup["deduplicated"] < 1:
        fail("Raw Capture deduplication was not observed")
    if ttl_dedup.get("ttl_removed") != 1:
        fail("Raw Capture TTL removal was not observed")
    if (
        schema_metadata.get("schema_version") != 4
        or schema_metadata.get("redaction_applied") is not True
        or not strict_int(schema_metadata.get("redaction_hits"))
        or schema_metadata["redaction_hits"] < 1
    ):
        fail("Raw Capture schema-v4 redaction metadata mismatch")
    if (
        not strict_int(purge_wal.get("purge_removed"))
        or purge_wal["purge_removed"] < 1
        or purge_wal.get("wal_busy") != 0
    ):
        fail("Raw Capture purge/WAL observation mismatch")

    database = one_record(records, "database", case="final")
    require_observation(database)
    if (
        database.get("quick_check") != "ok"
        or database.get("schema_version") != 6
        or database.get("migration_versions") != "1,2,3,4,5,6"
        or database.get("wal_busy") != 0
    ):
        fail("final SQLite observation mismatch")

    expected_runtime = (PRIMARY_VERSION, PRIMARY_COMMIT)
    runtime = one_record(records, "runtime_identity", case="cpa_image")
    require_observation(runtime)
    if (
        runtime.get("version") != expected_runtime[0]
        or runtime.get("commit") != expected_runtime[1]
        or not isinstance(runtime.get("build_date"), str)
        or RFC3339.fullmatch(runtime["build_date"]) is None
        or not isinstance(runtime.get("image_id"), str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", runtime["image_id"]) is None
        or (
            expected_cpa_image_id is not None
            and runtime.get("image_id") != expected_cpa_image_id
        )
        or (
            expected_cpa_build_date is not None
            and runtime.get("build_date") != expected_cpa_build_date
        )
    ):
        fail("CPA runtime image identity observation mismatch")

    controlled_restart = one_record(
        records, "controlled_restart", case="ttl"
    )
    require_observation(controlled_restart)
    expected_restart = {
        "stopped_exit_code": 0,
        "running": True,
        "restart_count": 0,
        "exit_code": 0,
        "oom": False,
    }
    for key, expected in expected_restart.items():
        if not exact_equal(controlled_restart.get(key), expected):
            fail(f"controlled CPA restart observation mismatch at {key}")

    lifecycle = one_record(records, "lifecycle", case="final")
    require_observation(lifecycle)
    expected_lifecycle = {
        "restart_count": 0,
        "exit_code": 0,
        "oom": False,
        "panic_count": 0,
        "fatal_count": 0,
        "plugin_error_count": 0,
    }
    for key, expected in expected_lifecycle.items():
        if not exact_equal(lifecycle.get(key), expected):
            fail(f"Host lifecycle observation mismatch at {key}")

    safety_record = one_record(records, "safety", case="network_isolation")
    require_observation(safety_record)
    if (
        safety_record.get("real_provider_contacted") is not False
        or safety_record.get("production_accessed") is not False
    ):
        fail("Host safety observation is not isolated")

    host_results = {
        "network_binding": {
            "host_ip": network_binding["host_ip"],
            "host_port": network_binding["host_port"],
            "container_port": network_binding["container_port"],
        },
        "protocol_requests": protocol_results,
        "matrix": {
            "benign_total": len(families),
            "benign_passed": benign_passed,
            "host_smoke_malicious_total": len(families),
            "host_smoke_malicious_blocked": malicious_blocked,
        },
        "transports": {
            "nonstream_passed": all(
                record.get("response_format") is True
                and record.get("termination_marker") is True
                for record in records
                if record.get("check") == "transport"
                and record.get("case") == "benign"
                and record.get("stream") is False
            ),
            "stream_passed": all(
                record.get("response_format") is True
                and record.get("termination_marker") is True
                for record in records
                if record.get("check") == "transport"
                and record.get("case") == "benign"
                and record.get("stream") is True
            ),
        },
        "modes": {"audit_passed": True, "balanced_passed": True, "strict_passed": True},
        "policy_outcomes": {
            "balanced_incomplete_allow": True,
            "strict_incomplete_block": True,
            "usage_queue_allow_delta": usage_allow["queue_count"],
            "usage_queue_blocked_zero": usage_blocked["queue_count"] == 0,
        },
        "database": {
            "quick_check": database["quick_check"],
            "schema_version": database["schema_version"],
            "migration_versions": [1, 2, 3, 4, 5, 6],
            "wal_checkpoint_passed": True,
        },
        "raw_capture": {
            "only_blocked_passed": True,
            "ttl_dedup_passed": True,
            "schema_v4_redaction_metadata_passed": True,
            "purge_wal_passed": True,
        },
        "lifecycle": {
            "restart_cycle_passed": controlled_restart["passed"],
            "unexpected_restart_count": lifecycle["restart_count"],
            "oom": lifecycle["oom"],
            "panic_count": lifecycle["panic_count"],
            "fatal_count": lifecycle["fatal_count"],
            "plugin_error_count": lifecycle["plugin_error_count"],
        },
    }
    safety = {
        "real_provider_contacted": safety_record["real_provider_contacted"],
        "production_accessed": safety_record["production_accessed"],
        "unexpected_restart_count": lifecycle["restart_count"],
        "oom": lifecycle["oom"],
        "panic_count": lifecycle["panic_count"],
        "fatal_count": lifecycle["fatal_count"],
        "plugin_error_count": lifecycle["plugin_error_count"],
    }
    return host_results, safety


def validate_lane_result(
    path: Path,
    expected_lane: str,
    expected_version: str,
    expected_commit: str,
    so_sha: str,
    release_commit: str,
    release_tree: str,
    expected_families: Iterable[str],
) -> dict[str, Any]:
    regular_file(path)
    raw = path.read_bytes()
    if not 2 <= len(raw) <= 128 * 1024 or raw.endswith(b"\n"):
        fail(f"{path.name} lane result framing/size is invalid")
    result = parse_json_bytes(raw, f"{path.name} lane result")
    if raw != canonical_bytes(result):
        fail(f"{path.name} lane result is not canonical JSON")
    if (
        not isinstance(result, dict)
        or set(result)
        != {
            "schema_version",
            "runner",
            "candidate",
            "cpa",
            "mock",
            "host_results",
            "safety",
            "transcript",
        }
        or result.get("schema_version") != 1
    ):
        fail(f"{path.name} lane result schema mismatch")
    runner = result.get("runner")
    if (
        not isinstance(runner, dict)
        or set(runner) != {"name", "version", "execution_id", "lane"}
        or runner.get("name") != "round9-host-runner"
        or runner.get("version") != RUNNER_VERSION
        or not isinstance(runner.get("execution_id"), str)
        or runner.get("lane") != expected_lane
    ):
        fail(f"{path.name} lane result is not a runner-produced result")
    try:
        parsed_execution = uuid.UUID(runner["execution_id"])
    except (ValueError, TypeError, AttributeError):
        fail(f"{path.name} runner execution identity is invalid")
    if str(parsed_execution) != runner["execution_id"]:
        fail(f"{path.name} runner execution identity is not canonical")
    candidate = result.get("candidate")
    if (
        not isinstance(candidate, dict)
        or set(candidate) != {"tag", "commit", "tree", "so_name", "so_sha256"}
        or candidate.get("tag") != TAG
        or candidate.get("commit") != release_commit
        or candidate.get("tree") != release_tree
        or candidate.get("so_name") != SO_NAME
        or candidate.get("so_sha256") != so_sha
    ):
        fail(f"{path.name} lane candidate identity mismatch")
    cpa = result.get("cpa")
    if (
        not isinstance(cpa, dict)
        or set(cpa) != {"version", "commit", "image", "image_id", "build_date"}
        or cpa.get("version") != expected_version
        or cpa.get("commit") != expected_commit
        or not isinstance(cpa.get("image"), str)
        or not cpa["image"]
        or not isinstance(cpa.get("image_id"), str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", cpa["image_id"]) is None
        or not isinstance(cpa.get("build_date"), str)
        or RFC3339.fullmatch(cpa["build_date"]) is None
    ):
        fail(f"{path.name} CPA identity mismatch")
    mock = result.get("mock")
    expected_mock = closed_mock_identity(
        mock.get("image_id") if isinstance(mock, dict) else "",
        release_commit,
        release_tree,
    )
    if (
        not isinstance(mock, dict)
        or set(mock) != set(expected_mock)
        or not isinstance(mock.get("image_id"), str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", mock["image_id"]) is None
        or not exact_equal(mock, expected_mock)
    ):
        fail(f"{path.name} counted-Mock identity mismatch")
    transcript = result.get("transcript")
    if (
        not isinstance(transcript, dict)
        or set(transcript) != {"path", "sha256", "records"}
        or not isinstance(transcript.get("path"), str)
        or not isinstance(transcript.get("sha256"), str)
        or HEX64.fullmatch(transcript["sha256"]) is None
    ):
        fail(f"{path.name} transcript binding is missing")
    transcript_path = Path(transcript["path"])
    if (
        not transcript_path.is_absolute()
        or transcript_path.name != "transcript.jsonl"
        or transcript_path.parent.resolve() != path.parent.resolve()
    ):
        fail(f"{path.name} transcript is outside its runner lane directory")
    if sha256_file(transcript_path) != transcript["sha256"]:
        fail(f"{path.name} transcript hash mismatch")
    records = load_transcript(transcript_path, expected_lane)
    if transcript.get("records") != len(records) or len(records) < 110:
        fail(f"{path.name} transcript has too few machine observations")
    derived_results, derived_safety = derive_host_results(
        records,
        expected_families,
        expected_lane,
        so_sha,
        mock["image_id"],
        cpa["image_id"],
        cpa["build_date"],
        release_commit,
        release_tree,
    )
    if not exact_equal(derived_results, result.get("host_results")) or not exact_equal(
        derived_results, EXPECTED_HOST_RESULTS
    ):
        fail(f"{path.name} host_results are not derived closed expected values")
    if not exact_equal(derived_safety, result.get("safety")):
        fail(f"{path.name} safety result does not match machine observations")
    return result


def verify_artifact_and_assemble(
    artifacts: Path,
    primary_result: Path,
    output: Path,
    commit: str,
    tree: str,
    execution: dict[str, Any] | None = None,
) -> str:
    _, so_sha, fixtures = verify_artifacts(artifacts, commit, tree)
    families = [item["family"] for item in fixtures]
    primary = validate_lane_result(
        primary_result,
        "primary",
        PRIMARY_VERSION,
        PRIMARY_COMMIT,
        so_sha,
        commit,
        tree,
        families,
    )
    evidence = {
        "schema_version": 2 if execution is not None else 1,
        "validation_scope": "CPA_HOST_COUNTED_MOCK_ONLY",
        "candidate": {
            "tag": TAG,
            "commit": commit,
            "tree": tree,
            "platform": "linux/amd64",
            "so_name": SO_NAME,
            "so_sha256": so_sha,
        },
        "cpa": {
            "primary": {
                "version": PRIMARY_VERSION,
                "commit": PRIMARY_COMMIT,
                "image_id": primary["cpa"]["image_id"],
                "build_date": primary["cpa"]["build_date"],
                "counted_mock_validation": "PASS",
                "host_results": primary["host_results"],
            },
        },
        "mock": primary["mock"],
        "safety": primary["safety"],
    }
    if execution is not None:
        validate_execution_binding(execution, commit)
        evidence["execution"] = execution
    if output.exists() and (not output.is_dir() or output.is_symlink()):
        fail("Host evidence output must be a real directory")
    output.mkdir(parents=True, exist_ok=True)
    evidence_name = "round9-host-evidence.json"
    sidecar_name = "round9-host-evidence.json.sha256"
    base64_name = "round9-host-evidence.json.b64"
    final_names = (evidence_name, sidecar_name, base64_name)
    evidence_bytes = canonical_bytes(evidence)
    digest = sha256_bytes(evidence_bytes)
    nonce = secrets.token_hex(8)
    staged_payloads = (
        (
            evidence_name,
            f".{evidence_name}.{nonce}.tmp",
            evidence_bytes,
            0o644,
        ),
        (
            sidecar_name,
            f".{sidecar_name}.{nonce}.tmp",
            f"{digest}  {evidence_name}\n".encode(),
            0o644,
        ),
        (
            base64_name,
            f".{base64_name}.{nonce}.tmp",
            base64.b64encode(evidence_bytes),
            0o600,
        ),
    )
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    directory_flags |= getattr(os, "O_CLOEXEC", 0)
    directory_flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        directory_fd = os.open(output, directory_flags)
    except OSError as exc:
        fail(f"Host evidence output directory is unsafe: {type(exc).__name__}")
    staged_identities: dict[str, FileIdentity] = {}
    published_identities: dict[str, FileIdentity] = {}
    try:
        directory_info = os.fstat(directory_fd)
        if not stat.S_ISDIR(directory_info.st_mode):
            raise OSError(errno.ENOTDIR, "Host evidence output is not a directory")
        for final_name in final_names:
            try:
                os.stat(final_name, dir_fd=directory_fd, follow_symlinks=False)
            except FileNotFoundError:
                continue
            fail(f"refusing to overwrite Host evidence output: {output / final_name}")

        for _, staged_name, payload, mode in staged_payloads:
            staged_identities[staged_name] = write_exclusive_staged_file_at(
                directory_fd, staged_name, payload, mode
            )

        for final_name, staged_name, _, _ in staged_payloads:
            identity = staged_identities[staged_name]
            os.link(
                staged_name,
                final_name,
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
                follow_symlinks=False,
            )
            # Record immediately after the atomic no-replace link. If later
            # validation fails, cleanup is still restricted to this inode.
            published_identities[final_name] = identity
            if not owned_regular_file_at(directory_fd, final_name, identity):
                raise OSError(errno.EIO, "published Host evidence inode changed")

        os.fsync(directory_fd)
        for _, staged_name, _, _ in staged_payloads:
            identity = staged_identities[staged_name]
            if not unlink_owned_file_at(directory_fd, staged_name, identity):
                raise OSError(errno.ESTALE, "staged Host evidence inode changed")
        os.fsync(directory_fd)

        for final_name, identity in published_identities.items():
            if not owned_regular_file_at(directory_fd, final_name, identity):
                raise OSError(errno.EIO, "published Host evidence inode changed")
    except OSError as exc:
        for final_name, identity in published_identities.items():
            try:
                unlink_owned_file_at(directory_fd, final_name, identity)
            except OSError:
                pass
        for staged_name, identity in staged_identities.items():
            try:
                unlink_owned_file_at(directory_fd, staged_name, identity)
            except OSError:
                pass
        try:
            os.fsync(directory_fd)
        except OSError:
            pass
        fail(f"Host evidence publication failed atomically: {type(exc).__name__}")
    finally:
        os.close(directory_fd)
    return digest


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def docker_inspect_one(name: str) -> dict[str, Any]:
    result = docker(["inspect", name], label=f"inspect {name}", timeout=30)
    payload = parse_json_bytes(result.stdout, f"docker inspect {name}")
    if not isinstance(payload, list) or len(payload) != 1 or not isinstance(payload[0], dict):
        fail(f"docker inspect {name} did not return exactly one object")
    return payload[0]


def closed_mock_identity(image_id: str, commit: str, tree: str) -> dict[str, str]:
    return {
        "contract": MOCK_CONTRACT,
        "source": MOCK_SOURCE,
        "revision": commit,
        "tag": TAG,
        "tree": tree,
        "image_id": image_id,
    }


def verify_mock_image(image: str, commit: str, tree: str) -> dict[str, str]:
    metadata = image_metadata(image)
    image_id = metadata.get("Id")
    if not isinstance(image_id, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", image_id) is None:
        fail("counted-Mock image has no immutable local image id")
    if metadata.get("Os") != "linux" or metadata.get("Architecture") != "amd64":
        fail("counted-Mock image must be linux/amd64")
    config = metadata.get("Config")
    labels = config.get("Labels") if isinstance(config, dict) else None
    expected_labels = {
        "io.cyber-abuse-guard.round9.mock-contract": MOCK_CONTRACT,
        "org.opencontainers.image.source": MOCK_SOURCE,
        "org.opencontainers.image.revision": commit,
        "org.opencontainers.image.version": TAG,
        "io.cyber-abuse-guard.source-tree": tree,
        **golang_base_labels(),
    }
    if not isinstance(labels, dict) or any(
        labels.get(key) != expected for key, expected in expected_labels.items()
    ):
        fail("counted-Mock image source/revision/tag/tree labels mismatch")
    return closed_mock_identity(image_id, commit, tree)


def require_tcp_port_available(host: str, port: int) -> None:
    if host != CPA_HOST_IP or port != CPA_HOST_PORT:
        fail("CPA Host listener preflight requires the fixed 127.0.0.1:18394 contract")
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        probe.bind((host, port))
    except OSError as exc:
        fail(f"CPA Host listener {host}:{port} is occupied or unavailable: {exc}")
    finally:
        probe.close()


def published_port(
    container: str,
    port: int,
    *,
    expected_host_port: int | None = None,
) -> int:
    result = docker(
        ["port", container, f"{port}/tcp"],
        label=f"resolve {container} published port",
        timeout=30,
    )
    lines = [line.strip() for line in result.stdout.decode("utf-8", "strict").splitlines() if line.strip()]
    if len(lines) != 1 or not lines[0].startswith(CPA_HOST_IP + ":"):
        fail(f"{container} port must be published exactly once on 127.0.0.1")
    try:
        value = int(lines[0].rsplit(":", 1)[1])
    except ValueError:
        fail(f"{container} published port is invalid")
    if value < 1024 or value > 65535:
        fail(f"{container} published port is outside the unprivileged range")
    if expected_host_port is not None and value != expected_host_port:
        fail(f"{container} published port does not match the fixed Host contract")
    return value


def verify_port_binding(
    info: dict[str, Any],
    *,
    role: str,
    container_port: int,
    host_port: int,
) -> None:
    expected_key = f"{container_port}/tcp"
    expected_binding = [{"HostIp": CPA_HOST_IP, "HostPort": str(host_port)}]
    host = info.get("HostConfig") or {}
    host_bindings = host.get("PortBindings") or {}
    network = info.get("NetworkSettings") or {}
    runtime_bindings = network.get("Ports") or {}
    if set(host_bindings) != {expected_key} or host_bindings.get(expected_key) != expected_binding:
        fail(f"{role} container HostConfig port binding is not exact")
    if set(runtime_bindings) != {expected_key} or runtime_bindings.get(expected_key) != expected_binding:
        fail(f"{role} container runtime port binding is not exact")


class DockerResources:
    def __init__(self, prefix: str, execution_id: str) -> None:
        if not prefix.startswith("cag-r9-") or re.fullmatch(r"[a-z0-9-]+", prefix) is None:
            fail("unsafe Docker resource prefix")
        try:
            uuid.UUID(execution_id)
        except ValueError:
            fail("unsafe Docker execution identity")
        self.prefix = prefix
        self.execution_id = execution_id
        self.containers: list[str] = []
        self.networks: list[str] = []

    def add_container(self, name: str) -> None:
        if not name.startswith(self.prefix + "-"):
            fail("refusing to track a container outside the execution prefix")
        if name in self.containers:
            fail("refusing to track a container more than once")
        self.containers.append(name)

    def add_network(self, name: str) -> None:
        if not name.startswith(self.prefix + "-"):
            fail("refusing to track a network outside the execution prefix")
        if name in self.networks:
            fail("refusing to track a network more than once")
        self.networks.append(name)

    def resource_exists(self, kind: str, name: str) -> bool:
        if kind == "container":
            args = [
                "container",
                "ls",
                "--all",
                "--no-trunc",
                "--filter",
                f"name=^/{name}$",
                "--format",
                "{{.Names}}",
            ]
        elif kind == "network":
            args = [
                "network",
                "ls",
                "--no-trunc",
                "--filter",
                f"name=^{name}$",
                "--format",
                "{{.Name}}",
            ]
        else:
            fail("unsupported Docker resource kind")
        result = docker(
            args,
            label=f"confirm isolated {kind} presence {name}",
            timeout=20,
            check=False,
        )
        if result.returncode != 0:
            fail(f"cannot distinguish absent {kind} from a Docker daemon/API failure")
        try:
            lines = [
                line.strip()
                for line in result.stdout.decode("utf-8", "strict").splitlines()
                if line.strip()
            ]
        except UnicodeDecodeError:
            fail(f"Docker {kind} presence result is not UTF-8")
        if len(lines) > 1 or any(line != name for line in lines):
            fail(f"Docker {kind} presence result is not an exact-name match")
        return lines == [name]

    def cleanup(self) -> None:
        failures: list[str] = []
        for name in reversed(self.containers):
            if not name.startswith(self.prefix + "-"):
                failures.append("unsafe-container-name")
                continue
            ownership = docker(
                ["inspect", name],
                label=f"verify isolated container ownership {name}",
                timeout=20,
                check=False,
            )
            if ownership.returncode != 0:
                if self.resource_exists("container", name):
                    failures.append(name)
                continue
            payload = parse_json_bytes(ownership.stdout, f"container ownership {name}")
            labels = {}
            if isinstance(payload, list) and len(payload) == 1 and isinstance(payload[0], dict):
                config = payload[0].get("Config")
                if isinstance(config, dict) and isinstance(config.get("Labels"), dict):
                    labels = config["Labels"]
            if labels.get("cag.round9.execution") != self.execution_id:
                failures.append(name)
                continue
            result = docker(
                ["rm", "--force", name],
                label=f"remove isolated container {name}",
                timeout=60,
                check=False,
            )
            if self.resource_exists("container", name):
                failures.append(name)
        for name in reversed(self.networks):
            if not name.startswith(self.prefix + "-"):
                failures.append("unsafe-network-name")
                continue
            ownership = docker(
                ["network", "inspect", name],
                label=f"verify isolated network ownership {name}",
                timeout=20,
                check=False,
            )
            if ownership.returncode != 0:
                if self.resource_exists("network", name):
                    failures.append(name)
                continue
            payload = parse_json_bytes(ownership.stdout, f"network ownership {name}")
            labels = {}
            if isinstance(payload, list) and len(payload) == 1 and isinstance(payload[0], dict):
                if isinstance(payload[0].get("Labels"), dict):
                    labels = payload[0]["Labels"]
            if labels.get("cag.round9.execution") != self.execution_id:
                failures.append(name)
                continue
            result = docker(
                ["network", "rm", name],
                label=f"remove isolated network {name}",
                timeout=60,
                check=False,
            )
            if self.resource_exists("network", name):
                failures.append(name)
        if failures:
            fail("isolated Docker resource cleanup did not complete")


class Lane:
    def __init__(
        self,
        *,
        lane: str,
        version: str,
        cpa_commit: str,
        cpa_image: str,
        cpa_image_id: str,
        cpa_build_date: str,
        mock_image: str,
        mock_image_id: str,
        artifacts: Path,
        work: Path,
        release_commit: str,
        release_tree: str,
        so_sha: str,
        fixtures: list[dict[str, str]],
        execution_id: str,
    ) -> None:
        if lane != "primary":
            fail("unsupported Host lane")
        self.lane = lane
        self.version = version
        self.cpa_commit = cpa_commit
        self.cpa_image = cpa_image
        self.cpa_image_id = cpa_image_id
        self.cpa_build_date = cpa_build_date
        self.mock_image = mock_image
        self.mock_image_id = mock_image_id
        self.artifacts = artifacts
        self.release_commit = release_commit
        self.release_tree = release_tree
        self.so_sha = so_sha
        self.fixtures = fixtures
        self.execution_id = execution_id
        self.directory = (work / lane).resolve()
        self.directory.mkdir(parents=True, exist_ok=False)
        os.chmod(self.directory, 0o700)
        suffix = execution_id.split("-")[0]
        self.prefix = f"cag-r9-{lane}-{suffix}"
        self.resources = DockerResources(self.prefix, execution_id)
        self.network = f"{self.prefix}-net"
        self.mock_container = f"{self.prefix}-mock"
        self.cpa_container = f"{self.prefix}-cpa"
        self.transcript = Transcript((self.directory / "transcript.jsonl").resolve(), lane)
        self.transcript_closed = False
        self.mock_url = ""
        self.cpa_url = ""
        self.mock_host_port = 0
        self.cpa_host_port = 0
        self.client_key = "cag-r9-client-" + secrets.token_urlsafe(24)
        self.management_key = "cag-r9-management-" + secrets.token_urlsafe(32)
        self.upstream_key = "cag-r9-upstream-" + secrets.token_urlsafe(24)
        self.plugin_dir = self.directory / "plugins"
        self.plugin_platform_dir = self.plugin_dir / "linux" / "amd64"
        self.config_dir = self.directory / "config"
        self.auth_dir = self.directory / "auth"
        self.audit_dir = self.directory / "audit"
        self.secret_dir = self.directory / "secrets"
        self.database_path = self.audit_dir / "events.db"
        self.purge_removed = 0
        self.purge_wal_busy = -1

    @property
    def management_headers(self) -> dict[str, str]:
        return {"Authorization": "Bearer " + self.management_key}

    def record(self, check: str, **values: Any) -> None:
        self.transcript.record(check, **values)

    def prepare_files(self) -> None:
        for path in (
            self.plugin_dir,
            self.config_dir,
            self.auth_dir,
            self.audit_dir,
            self.secret_dir,
        ):
            path.mkdir(mode=0o700)
        self.plugin_platform_dir.mkdir(parents=True, mode=0o700)
        store = self.artifacts / STORE_NAME
        with zipfile.ZipFile(store) as archive:
            raw = archive.read(SO_NAME)
        if sha256_bytes(raw) != self.so_sha:
            fail("lane Store extraction changed candidate SO bytes")
        plugin_path = self.plugin_platform_dir / SO_NAME
        write_bytes(plugin_path, raw, 0o500)
        write_bytes(
            self.secret_dir / "hmac.key",
            secrets.token_bytes(48),
            0o400,
        )
        self.write_initial_config()
        self.record(
            "runtime_identity",
            case="cpa_image",
            version=self.version,
            commit=self.cpa_commit,
            build_date=self.cpa_build_date,
            image_id=self.cpa_image_id,
            passed=True,
        )
        self.record(
            "artifact",
            case="exact_store_so",
            so_sha256=self.so_sha,
            config_sha256=sha256_file(self.config_dir / "config.yaml"),
            plugin_path=f"plugins/linux/amd64/{SO_NAME}",
            passed=True,
        )

    def plugin_config(self, mode: str, raw_capture: bool) -> dict[str, Any]:
        return {
            "enabled": True,
            "priority": 300,
            "mode": mode,
            "max_scan_bytes": SCAN_LIMIT_BYTES,
            "max_total_text_bytes": SCAN_LIMIT_BYTES,
            "opaque_media_policy": "audit",
            "subject_control": {"enabled": False},
            "audit": {
                "enabled": True,
                "data_dir": "/cag/audit",
                "retention_days": 30,
                "max_db_mb": 32,
                "log_request_hash": True,
                "log_subject_hash": True,
                "log_rule_ids": True,
                "log_category": True,
                "persist_wrapper_only": False,
                "log_original_text": False,
                "raw_capture": {
                    "enabled": raw_capture,
                    "only_blocked": True,
                    "max_bytes": 8192,
                    "ttl_hours": 1,
                    "redact_secrets": True,
                },
            },
            "classifier": {
                "enabled": False,
                "endpoint": "",
                "timeout_ms": 300,
                "fail_mode": "rules_only",
            },
        }

    def write_initial_config(self) -> None:
        plugin = self.plugin_config("balanced", True)
        lines = [
            'host: "0.0.0.0"',
            f"port: {CPA_PORT}",
            'auth-dir: "/cag/auth"',
            "api-keys:",
            f"  - {json.dumps(self.client_key)}",
            "remote-management:",
            "  allow-remote: true",
            f"  secret-key: {json.dumps(self.management_key)}",
            "  disable-control-panel: true",
            "usage-statistics-enabled: true",
            "logging-to-file: false",
            "debug: false",
            "plugins:",
            "  enabled: true",
            '  dir: "/cag/plugins"',
            "  configs:",
            "    cyber-abuse-guard:",
        ]
        for line in json.dumps(plugin, ensure_ascii=True, indent=2).splitlines():
            # JSON is valid YAML. Nesting the complete object under the plugin id
            # avoids an independent YAML dependency in the Host runner.
            lines.append("      " + line)
        lines.extend(
            [
                "openai-compatibility:",
                "  - name: round9-counted-mock",
                '    base-url: "http://mock:18080/v1"',
                "    api-key-entries:",
                f"      - api-key: {json.dumps(self.upstream_key)}",
                "    models:",
                f"      - name: {MODEL_NAME}",
                f"        alias: {MODEL_NAME}",
            ]
        )
        write_bytes(
            self.config_dir / "config.yaml",
            ("\n".join(lines) + "\n").encode("utf-8"),
            0o600,
        )

    def create_network(self) -> None:
        self.resources.add_network(self.network)
        docker(
            [
                "network",
                "create",
                "--internal",
                "--label",
                f"cag.round9.execution={self.execution_id}",
                "--label",
                f"cag.round9.lane={self.lane}",
                self.network,
            ],
            label=f"create {self.lane} internal network",
            timeout=30,
        )

    def common_container_args(self, role: str, name: str) -> list[str]:
        if role not in CONTAINER_LIMITS:
            fail("unsupported Host container role")
        uid = os.getuid()
        gid = os.getgid()
        limits = CONTAINER_LIMITS[role]
        return [
            "run",
            "--detach",
            "--name",
            name,
            "--hostname",
            role,
            "--network",
            self.network,
            "--network-alias",
            role,
            "--restart",
            "no",
            "--user",
            f"{uid}:{gid}",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            "--pids-limit",
            "256",
            "--cpus",
            str(limits["nano_cpus"] / 1_000_000_000),
            "--memory",
            str(limits["memory"]),
            "--memory-swap",
            str(limits["memory"]),
            "--log-driver",
            "local",
            "--log-opt",
            "max-size=8m",
            "--log-opt",
            "max-file=1",
            "--log-opt",
            "compress=false",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,nodev,size=64m",
            "--env",
            "HOME=/tmp",
            "--env",
            "HTTP_PROXY=",
            "--env",
            "HTTPS_PROXY=",
            "--env",
            "ALL_PROXY=",
            "--env",
            "http_proxy=",
            "--env",
            "https_proxy=",
            "--env",
            "all_proxy=",
            "--env",
            "NO_PROXY=*",
            "--env",
            "no_proxy=*",
            "--label",
            f"cag.round9.execution={self.execution_id}",
            "--label",
            f"cag.round9.lane={self.lane}",
            "--label",
            f"cag.round9.role={role}",
        ]

    def start_mock(self) -> None:
        args = self.common_container_args("mock", self.mock_container)
        args.extend(["--publish", f"127.0.0.1::{MOCK_PORT}", self.mock_image_id])
        self.resources.add_container(self.mock_container)
        docker(args, label=f"start {self.lane} counted-Mock", timeout=60)
        self.mock_host_port = published_port(self.mock_container, MOCK_PORT)
        self.mock_url = f"http://{CPA_HOST_IP}:{self.mock_host_port}"
        deadline = time.monotonic() + 30
        health: Any = None
        while time.monotonic() < deadline:
            try:
                health = http_json(self.mock_url, "GET", "/healthz")
                break
            except RunnerError:
                time.sleep(0.2)
        expected = {
            "contract": MOCK_CONTRACT,
            "healthy": True,
            "request_body_retention": False,
        }
        if not exact_equal(health, expected):
            fail("counted-Mock health contract mismatch")
        reset = http_json(self.mock_url, "POST", "/__cag/reset")
        if not exact_equal(reset, {"total": 0}) or self.mock_total() != 0:
            fail("counted-Mock reset/stats contract mismatch")
        self.record(
            "mock_contract",
            case="health_reset_stats",
            contract=MOCK_CONTRACT,
            source=MOCK_SOURCE,
            revision=self.release_commit,
            tag=TAG,
            tree=self.release_tree,
            image_id=self.mock_image_id,
            passed=True,
        )

    def start_cpa(self) -> None:
        require_tcp_port_available(CPA_HOST_IP, CPA_HOST_PORT)
        args = self.common_container_args("cpa", self.cpa_container)
        args.extend(
            [
                "--publish",
                f"{CPA_HOST_IP}:{CPA_HOST_PORT}:{CPA_PORT}",
                "--mount",
                f"type=bind,src={self.plugin_dir},dst=/cag/plugins,readonly",
                "--mount",
                f"type=bind,src={self.config_dir},dst=/cag/config",
                "--mount",
                f"type=bind,src={self.auth_dir},dst=/cag/auth",
                "--mount",
                f"type=bind,src={self.audit_dir},dst=/cag/audit",
                "--mount",
                f"type=bind,src={self.secret_dir},dst=/cag/secrets,readonly",
                "--env",
                "CYBER_ABUSE_GUARD_HMAC_KEY_FILE=/cag/secrets/hmac.key",
                "--entrypoint",
                "/CLIProxyAPI/CLIProxyAPI",
                self.cpa_image_id,
                "-config",
                "/cag/config/config.yaml",
                "-local-model",
            ]
        )
        self.resources.add_container(self.cpa_container)
        docker(args, label=f"start {self.lane} CPA", timeout=60)
        self.cpa_host_port = published_port(
            self.cpa_container,
            CPA_PORT,
            expected_host_port=CPA_HOST_PORT,
        )
        self.cpa_url = f"http://{CPA_HOST_IP}:{CPA_HOST_PORT}"
        self.wait_plugin("balanced", True)
        self.verify_container_security(self.mock_container, "mock")
        self.verify_container_security(self.cpa_container, "cpa")
        self.record(
            "network_binding",
            case="cpa_management_and_api",
            host_ip=CPA_HOST_IP,
            host_port=CPA_HOST_PORT,
            container_port=CPA_PORT,
            passed=True,
        )

    def verify_container_security(self, name: str, role: str) -> None:
        info = docker_inspect_one(name)
        config = info.get("Config") or {}
        host = info.get("HostConfig") or {}
        state = info.get("State") or {}
        networks = (info.get("NetworkSettings") or {}).get("Networks") or {}
        if set(networks) != {self.network} or host.get("NetworkMode") != self.network:
            fail(f"{role} container escaped the isolated network")
        if state.get("Running") is not True or state.get("OOMKilled") is not False:
            fail(f"{role} container is not healthy/running")
        if host.get("ReadonlyRootfs") is not True:
            fail(f"{role} container root filesystem is not read-only")
        cap_drop = host.get("CapDrop") or []
        security = host.get("SecurityOpt") or []
        if "ALL" not in cap_drop or not any(item.startswith("no-new-privileges") for item in security):
            fail(f"{role} container security options are incomplete")
        if (host.get("RestartPolicy") or {}).get("Name") not in {"", "no"}:
            fail(f"{role} container restart policy is not disabled")
        if (
            host.get("Privileged") is not False
            or host.get("PidsLimit") != 256
            or host.get("PidMode") not in {"", None}
            or host.get("IpcMode") not in {"", "private", None}
            or host.get("Devices") not in (None, [])
        ):
            fail(f"{role} container namespace/resource isolation mismatch")
        limits = CONTAINER_LIMITS[role]
        log_config = host.get("LogConfig")
        if (
            host.get("NanoCpus") != limits["nano_cpus"]
            or host.get("Memory") != limits["memory"]
            or host.get("MemorySwap") != limits["memory"]
            or not isinstance(log_config, dict)
            or log_config.get("Type") != "local"
            or log_config.get("Config") != {"max-file": "1", "max-size": "8m"}
        ):
            fail(f"{role} container CPU/memory/log limits mismatch")
        if role == "mock":
            if self.mock_host_port < 1024 or self.mock_host_port > 65535:
                fail("counted-Mock Host port was not resolved")
            verify_port_binding(
                info,
                role=role,
                container_port=MOCK_PORT,
                host_port=self.mock_host_port,
            )
        else:
            if self.cpa_host_port != CPA_HOST_PORT:
                fail("CPA Host port does not match the fixed contract")
            verify_port_binding(
                info,
                role=role,
                container_port=CPA_PORT,
                host_port=CPA_HOST_PORT,
            )
        if config.get("User") != f"{os.getuid()}:{os.getgid()}":
            fail(f"{role} container does not use the invoking uid/gid")
        labels = config.get("Labels") or {}
        if (
            labels.get("cag.round9.execution") != self.execution_id
            or labels.get("cag.round9.lane") != self.lane
            or labels.get("cag.round9.role") != role
        ):
            fail(f"{role} container ownership labels mismatch")
        env = config.get("Env") or []
        env_map = dict(item.split("=", 1) for item in env if "=" in item)
        for key in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
            if env_map.get(key, "") != "":
                fail(f"{role} container inherited a proxy")
        if env_map.get("NO_PROXY") != "*" or env_map.get("no_proxy") != "*":
            fail(f"{role} container NO_PROXY isolation mismatch")
        mounts = info.get("Mounts") or []
        if role == "mock" and mounts:
            fail("counted-Mock container must not receive host mounts")
        if role == "cpa":
            destinations = {item.get("Destination") for item in mounts}
            if destinations != {"/cag/plugins", "/cag/config", "/cag/auth", "/cag/audit", "/cag/secrets"}:
                fail("CPA container mount set is not closed")
            for item in mounts:
                source = Path(str(item.get("Source", ""))).resolve()
                try:
                    source.relative_to(self.directory)
                except ValueError:
                    fail("CPA container mount escaped the lane work directory")
                should_write = item.get("Destination") in {"/cag/config", "/cag/auth", "/cag/audit"}
                if item.get("RW") is not should_write:
                    fail("CPA container mount write policy mismatch")

    def wait_plugin(self, mode: str, raw_capture: bool) -> dict[str, Any]:
        deadline = time.monotonic() + 30
        last: Any = None
        while time.monotonic() < deadline:
            try:
                plugins = http_json(
                    self.cpa_url,
                    "GET",
                    "/v0/management/plugins",
                    headers=self.management_headers,
                )
                status = http_json(
                    self.cpa_url,
                    "GET",
                    MANAGEMENT_PATH + "/status",
                    headers=self.management_headers,
                )
                self.assert_plugin_ready(plugins, status, mode, raw_capture)
                return status
            except RunnerError as exc:
                last = exc
                time.sleep(0.2)
        if last is not None:
            fail("CPA/plugin readiness did not converge")
        fail("CPA/plugin readiness timed out")

    def assert_plugin_ready(
        self, plugins: Any, status: Any, mode: str, raw_capture: bool
    ) -> None:
        if not isinstance(plugins, dict) or plugins.get("plugins_enabled") is not True:
            fail("CPA plugin inventory is unavailable")
        entries = plugins.get("plugins")
        if not isinstance(entries, list):
            fail("CPA plugin inventory is invalid")
        matches = [item for item in entries if isinstance(item, dict) and item.get("id") == "cyber-abuse-guard"]
        if len(matches) != 1:
            fail("CPA plugin inventory must contain exactly one Guard")
        item = matches[0]
        if not all(item.get(key) is True for key in ("registered", "configured", "effective_enabled")):
            fail("CPA plugin inventory does not show an active Guard")
        if not isinstance(status, dict):
            fail("Guard status is invalid")
        expected_values = {
            "id": "cyber-abuse-guard",
            "version": ARTIFACT_VERSION,
            "commit": self.release_commit,
            "dirty": False,
            "loaded": True,
            "initialized": True,
            "enforcement_ready": True,
            "enabled": True,
            "mode": mode,
            "priority": 300,
            "ruleset_version_match": True,
            "audit_degraded": False,
            "hmac_stable": True,
            "hmac_degraded": False,
            "persistence_degraded": False,
            "last_reconfigure_error": "",
            "last_config_error": "",
        }
        for key, expected in expected_values.items():
            if not exact_equal(status.get(key), expected):
                fail(f"Guard readiness identity mismatch at {key}")
        if not isinstance(status.get("ruleset_sha256"), str) or HEX64.fullmatch(status["ruleset_sha256"]) is None:
            fail("Guard status ruleset digest is invalid")
        if not isinstance(status.get("classifier_policy_sha256"), str) or HEX64.fullmatch(status["classifier_policy_sha256"]) is None:
            fail("Guard status classifier policy digest is invalid")
        limits = status.get("effective_limits")
        if (
            not isinstance(limits, dict)
            or limits.get("max_text_window_bytes") != SCAN_LIMIT_BYTES
            or limits.get("max_total_text_bytes") != SCAN_LIMIT_BYTES
            or limits.get("legacy_max_scan_bytes_configured")
            != SCAN_LIMIT_BYTES
        ):
            fail("Guard status does not expose the fixed 16 KiB scan/total limits")
        audit = status.get("audit")
        if (
            not isinstance(audit, dict)
            or audit.get("enabled") is not True
            or audit.get("healthy") is not True
            or audit.get("degraded") is not False
            or audit.get("schema_version") != 6
        ):
            fail("Guard audit database is not schema-v6 healthy")
        raw = status.get("raw_capture")
        if not isinstance(raw, dict) or raw.get("enabled") is not raw_capture:
            fail("Guard Raw Capture status mismatch")
        if raw_capture and (
            raw.get("only_blocked") is not True
            or raw.get("redact_secrets") is not True
            or raw.get("ttl_hours") != 1
        ):
            fail("Guard Raw Capture safety settings mismatch")

    def reconfigure(self, mode: str, raw_capture: bool) -> dict[str, Any]:
        response = http_json(
            self.cpa_url,
            "PUT",
            MANAGEMENT_PATH + "/config",
            self.plugin_config(mode, raw_capture),
            self.management_headers,
        )
        if not isinstance(response, dict) or response.get("status") != "ok":
            fail("CPA plugin reconfiguration was not acknowledged")
        return self.wait_plugin(mode, raw_capture)

    def mock_total(self) -> int:
        stats = http_json(self.mock_url, "GET", "/__cag/stats")
        if not isinstance(stats, dict) or set(stats) != {"total"} or not strict_int(stats.get("total")):
            fail("counted-Mock stats response is not exact")
        return stats["total"]

    def reset_mock(self) -> None:
        reset = http_json(self.mock_url, "POST", "/__cag/reset")
        if not exact_equal(reset, {"total": 0}) or self.mock_total() != 0:
            fail("counted-Mock did not reset to zero")

    def request_body(self, protocol: str, prompt: str, stream: bool = False) -> dict[str, Any]:
        if protocol == "chat":
            return {
                "model": MODEL_NAME,
                "stream": stream,
                "messages": [{"role": "user", "content": prompt}],
            }
        if protocol == "responses":
            return {
                "model": MODEL_NAME,
                "stream": stream,
                "input": [
                    {
                        "type": "message",
                        "role": "user",
                        "content": [{"type": "input_text", "text": prompt}],
                    }
                ],
            }
        fail("unsupported request protocol")

    def protocol_path(self, protocol: str) -> str:
        if protocol == "chat":
            return "/v1/chat/completions"
        if protocol == "responses":
            return "/v1/responses"
        fail("unsupported request protocol")

    def observe_request(
        self,
        *,
        check: str,
        case: str,
        protocol: str,
        body: Any,
        expected_status: int,
        expected_delta: int,
        mode: str | None = None,
        family: str | None = None,
        scan_limit_bytes: int | None = None,
    ) -> tuple[int, bytes]:
        self.reset_mock()
        before = self.mock_total()
        request_bytes = body if isinstance(body, bytes) else canonical_bytes(body)
        status, response = http_request(
            self.cpa_url,
            "POST",
            self.protocol_path(protocol),
            body,
            {"Authorization": "Bearer " + self.client_key},
        )
        after = self.mock_total()
        delta = after - before
        passed = status == expected_status and delta == expected_delta
        response_format = False
        termination_marker = False
        if status == 200 and delta == 1:
            stream = isinstance(body, dict) and body.get("stream") is True
            response_format, termination_marker = validate_upstream_response(
                protocol, stream, response
            )
        if expected_status == 403 and b"Request blocked by the local cyber-abuse policy" not in response:
            passed = False
        values: dict[str, Any] = {
            "case": case,
            "protocol": protocol,
            "status": status,
            "upstream_before": before,
            "upstream_after": after,
            "upstream_delta": delta,
            "request_sha256": sha256_bytes(request_bytes),
            "response_sha256": sha256_bytes(response),
            "request_bytes": len(request_bytes),
            "valid_json": not isinstance(body, bytes),
            "passed": passed,
        }
        if status == 200 and delta == 1:
            values["response_format"] = response_format
            values["termination_marker"] = termination_marker
        if isinstance(body, dict) and type(body.get("stream")) is bool:
            values["stream"] = body["stream"]
        if mode is not None:
            values["mode"] = mode
        if family is not None:
            values["family"] = family
        if scan_limit_bytes is not None:
            values["scan_limit_bytes"] = scan_limit_bytes
        self.record(check, **values)
        if not passed:
            fail(f"{check}/{case} did not meet counted-Mock status/count expectations")
        return status, response

    def drain_usage_queue(self) -> None:
        for _ in range(20):
            payload = http_json(
                self.cpa_url,
                "GET",
                "/v0/management/usage-queue?count=100",
                headers=self.management_headers,
            )
            if not isinstance(payload, list):
                fail("CPA usage queue response is not a list")
            if not payload:
                return
        fail("CPA usage queue did not drain")

    def observe_usage_allow(self, body: Any) -> None:
        self.drain_usage_queue()
        self.reset_mock()
        before = self.mock_total()
        request_bytes = canonical_bytes(body)
        status, response = http_request(
            self.cpa_url,
            "POST",
            "/v1/chat/completions",
            body,
            {"Authorization": "Bearer " + self.client_key},
        )
        after = self.mock_total()
        queue: Any = []
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            queue = http_json(
                self.cpa_url,
                "GET",
                "/v0/management/usage-queue?count=100",
                headers=self.management_headers,
            )
            if isinstance(queue, list) and queue:
                break
            time.sleep(0.05)
        count = len(queue) if isinstance(queue, list) else -1
        response_format = False
        termination_marker = False
        if status == 200 and after - before == 1:
            response_format, termination_marker = validate_upstream_response(
                "chat", False, response
            )
        passed = (
            status == 200
            and after - before == 1
            and count == 1
            and response_format
            and termination_marker
        )
        self.record(
            "policy",
            case="usage_allow",
            protocol="chat",
            status=status,
            upstream_delta=after - before,
            queue_count=count,
            request_sha256=sha256_bytes(request_bytes),
            response_sha256=sha256_bytes(response),
            response_format=response_format,
            termination_marker=termination_marker,
            passed=passed,
        )
        if not passed:
            fail("allowed request did not produce exactly one CPA usage record")

    def observe_usage_blocked(self, body: Any) -> None:
        self.drain_usage_queue()
        self.reset_mock()
        before = self.mock_total()
        request_bytes = canonical_bytes(body)
        status, response = http_request(
            self.cpa_url,
            "POST",
            "/v1/chat/completions",
            body,
            {"Authorization": "Bearer " + self.client_key},
        )
        after = self.mock_total()
        queue_count = 0
        quiet = True
        deadline = time.monotonic() + 0.75
        while time.monotonic() < deadline:
            payload = http_json(
                self.cpa_url,
                "GET",
                "/v0/management/usage-queue?count=100",
                headers=self.management_headers,
            )
            if not isinstance(payload, list):
                fail("CPA usage queue response is not a list")
            queue_count += len(payload)
            if payload:
                quiet = False
            time.sleep(0.05)
        passed = (
            status == 403
            and b"Request blocked by the local cyber-abuse policy" in response
            and after - before == 0
            and quiet
            and queue_count == 0
        )
        self.record(
            "policy",
            case="usage_blocked",
            protocol="chat",
            status=status,
            upstream_delta=after - before,
            queue_count=queue_count,
            request_sha256=sha256_bytes(request_bytes),
            response_sha256=sha256_bytes(response),
            passed=passed,
        )
        if not passed:
            fail("blocked request produced an upstream or CPA usage side effect")

    def tool_schema_body(self, protocol: str, user: str) -> dict[str, Any]:
        schema = (
            "Documentation labels only: working code; sandbox; hidden field; silent mode; "
            "session token; API key; credentials; command; create a tool; payload; loader; "
            "production; high concurrency; automated; multiple users; deployment. "
        ) * 64
        parameters = {
            "type": "object",
            "properties": {
                "ordinary_development_notes": {
                    "type": "string",
                    "description": schema,
                }
            },
        }
        if protocol == "chat":
            return {
                "model": MODEL_NAME,
                "tools": [
                    {
                        "type": "function",
                        "function": {
                            "name": "ordinary_development_helper",
                            "description": schema,
                            "parameters": parameters,
                        },
                    }
                ],
                "messages": [{"role": "user", "content": user}],
            }
        return {
            "model": MODEL_NAME,
            "tools": [
                {
                    "type": "function",
                    "name": "ordinary_development_helper",
                    "description": schema,
                    "parameters": parameters,
                }
            ],
            "input": [
                {
                    "type": "message",
                    "role": "user",
                    "content": [{"type": "input_text", "text": user}],
                }
            ],
        }

    def query_raw_captures(self) -> dict[str, Any]:
        payload = http_json(
            self.cpa_url,
            "GET",
            MANAGEMENT_PATH + "/raw-captures?limit=100",
            headers=self.management_headers,
        )
        if not isinstance(payload, dict) or not isinstance(payload.get("captures"), list):
            fail("Raw Capture management response is invalid")
        if payload.get("returned_count") != len(payload["captures"]):
            fail("Raw Capture returned_count mismatch")
        return payload

    def purge_events(self) -> int:
        response = http_json(
            self.cpa_url,
            "DELETE",
            MANAGEMENT_PATH + "/events",
            headers=self.management_headers,
        )
        if not isinstance(response, dict) or not strict_int(response.get("deleted")):
            fail("audit event purge response is invalid")
        return response["deleted"]

    def raw_capture_suite(self, safe_prompt: str, malicious_prompt: str) -> None:
        self.reconfigure("balanced", True)
        self.purge_events()
        safe_body = self.request_body("chat", safe_prompt)
        secret = "sk-round9-redaction-canary-0123456789"  # repo-secret-scan: allow synthetic-fixture
        malicious_body = self.request_body(
            "chat", malicious_prompt + " Test metadata api_key=" + secret
        )
        self.observe_request(
            check="raw_capture_request",
            case="benign_control",
            protocol="chat",
            body=safe_body,
            expected_status=200,
            expected_delta=1,
        )
        benign_page = self.query_raw_captures()
        benign_count = len(benign_page["captures"])
        self.observe_request(
            check="raw_capture_request",
            case="blocked_first",
            protocol="chat",
            body=malicious_body,
            expected_status=403,
            expected_delta=0,
        )
        self.observe_request(
            check="raw_capture_request",
            case="blocked_duplicate",
            protocol="chat",
            body=malicious_body,
            expected_status=403,
            expected_delta=0,
        )
        deadline = time.monotonic() + 5
        page: dict[str, Any] = {}
        while time.monotonic() < deadline:
            page = self.query_raw_captures()
            if page.get("returned_count") == 1:
                break
            time.sleep(0.05)
        captures = page.get("captures", [])
        blocked_count = len(captures)
        only_blocked_passed = benign_count == 0 and blocked_count == 1
        self.record(
            "raw_capture",
            case="only_blocked",
            benign_captures=benign_count,
            blocked_captures=blocked_count,
            passed=only_blocked_passed,
        )
        if not only_blocked_passed:
            fail("Raw Capture did not remain blocked-only and deduplicated")
        capture = captures[0]
        try:
            preview = base64.b64decode(capture.get("raw_preview_b64", ""), validate=True)
        except (ValueError, TypeError):
            fail("Raw Capture canonical base64 preview is invalid")
        schema_passed = (
            page.get("raw_capture_response_schema_version") == 4
            and page.get("preferred_preview_field") == "raw_preview_b64"
            and capture.get("redaction_applied") is True
            and capture.get("redacted") is True
            and strict_int(capture.get("redaction_pattern_hits"))
            and capture["redaction_pattern_hits"] >= 1
            and capture.get("redaction_version") == "raw-redactor-v2"
            and secret.encode() not in preview
            and b"[REDACTED" in preview
            and isinstance(capture.get("raw_sha256"), str)
            and re.fullmatch(r"sha256:[0-9a-f]{64}", capture["raw_sha256"]) is not None
        )
        self.record(
            "raw_capture",
            case="schema_v4_redaction_metadata",
            schema_version=page.get("raw_capture_response_schema_version", -1),
            redaction_applied=capture.get("redaction_applied", False),
            redaction_hits=capture.get("redaction_pattern_hits", -1),
            returned_count=blocked_count,
            response_sha256=sha256_bytes(canonical_bytes(page)),
            passed=schema_passed,
        )
        if not schema_passed:
            fail("Raw Capture schema-v4 redaction contract failed")
        status = self.wait_plugin("balanced", True)
        audit = status.get("audit") or {}
        deduplicated = audit.get("raw_capture_deduplicated", -1)
        if not strict_int(deduplicated) or deduplicated < 1:
            fail("Raw Capture deduplication counter did not advance")

        self.controlled_ttl_restart()
        after_ttl = self.query_raw_captures()
        ttl_removed = blocked_count - len(after_ttl["captures"])
        ttl_passed = ttl_removed == 1
        self.record(
            "raw_capture",
            case="ttl_dedup",
            deduplicated=deduplicated,
            ttl_removed=ttl_removed,
            passed=ttl_passed,
        )
        if not ttl_passed:
            fail("Raw Capture startup TTL cleanup did not remove the aged row")

        self.observe_request(
            check="raw_capture_request",
            case="blocked_for_purge",
            protocol="chat",
            body=malicious_body,
            expected_status=403,
            expected_delta=0,
        )
        deadline = time.monotonic() + 5
        before_disable = 0
        while time.monotonic() < deadline:
            before_disable = len(self.query_raw_captures()["captures"])
            if before_disable == 1:
                break
            time.sleep(0.05)
        self.reconfigure("balanced", False)
        disabled_page = self.query_raw_captures()
        self.purge_removed = before_disable - len(disabled_page["captures"])
        wal_path = Path(str(self.database_path) + "-wal")
        if wal_path.is_symlink() or (wal_path.exists() and not wal_path.is_file()):
            fail("Raw Capture WAL path is not a regular file")
        wal_size = wal_path.stat().st_size if wal_path.exists() else 0
        self.purge_wal_busy = 0 if wal_size == 0 else 1
        purge_passed = (
            disabled_page.get("enabled") is False
            and len(disabled_page["captures"]) == 0
            and self.purge_removed >= 1
            and self.purge_wal_busy == 0
        )
        self.record(
            "raw_capture",
            case="purge_wal",
            purge_removed=self.purge_removed,
            wal_busy=self.purge_wal_busy,
            passed=purge_passed,
        )
        if not purge_passed:
            fail("Raw Capture disable-purge did not truncate its WAL")
        self.reconfigure("balanced", True)

    def controlled_ttl_restart(self) -> None:
        docker(
            ["stop", "--time", "20", self.cpa_container],
            label=f"stop {self.lane} CPA for controlled TTL restart",
            timeout=30,
        )
        info = docker_inspect_one(self.cpa_container)
        stopped_state = info.get("State") or {}
        if stopped_state.get("Running") is not False:
            fail("CPA did not stop for controlled TTL restart")
        stopped_exit_code = stopped_state.get("ExitCode")
        if stopped_exit_code != 0:
            fail("CPA controlled stop did not exit cleanly")
        regular_file(self.database_path)
        connection = sqlite3.connect(str(self.database_path), timeout=5)
        try:
            check = connection.execute("PRAGMA quick_check").fetchone()
            count = connection.execute("SELECT COUNT(*) FROM raw_request_captures").fetchone()
            if check != ("ok",) or count != (1,):
                fail("pre-restart Raw Capture database state mismatch")
            connection.execute("UPDATE raw_request_captures SET timestamp_ns = 0")
            connection.commit()
        finally:
            connection.close()
        docker(
            ["start", self.cpa_container],
            label=f"restart {self.lane} CPA after synthetic TTL aging",
            timeout=30,
        )
        self.wait_plugin("balanced", True)
        info = docker_inspect_one(self.cpa_container)
        state = info.get("State") or {}
        restart_count = info.get("RestartCount")
        passed = (
            stopped_exit_code == 0
            and state.get("Running") is True
            and state.get("ExitCode") == 0
            and restart_count == 0
            and state.get("OOMKilled") is False
        )
        self.record(
            "controlled_restart",
            case="ttl",
            stopped_exit_code=stopped_exit_code,
            running=state.get("Running"),
            restart_count=restart_count,
            exit_code=state.get("ExitCode"),
            oom=state.get("OOMKilled"),
            passed=passed,
        )
        if not passed:
            fail("controlled CPA restart changed unexpected restart/OOM state")

    def verify_provider_isolation(self) -> None:
        network_raw = docker(
            ["network", "inspect", self.network],
            label=f"inspect {self.lane} internal network",
            timeout=30,
        ).stdout
        network_payload = parse_json_bytes(network_raw, "Docker network inspect")
        if not isinstance(network_payload, list) or len(network_payload) != 1:
            fail("isolated Docker network inspection failed")
        network = network_payload[0]
        containers = network.get("Containers") or {}
        names = {item.get("Name") for item in containers.values() if isinstance(item, dict)}
        if network.get("Internal") is not True or names != {self.mock_container, self.cpa_container}:
            fail("Host lane network is not a closed two-container internal network")
        config = http_json(
            self.cpa_url,
            "GET",
            "/v0/management/config",
            headers=self.management_headers,
        )
        if not isinstance(config, dict):
            fail("CPA management config inspection failed")
        providers = config.get("openai-compatibility")
        if not isinstance(providers, list) or len(providers) != 1:
            fail("CPA Host lane must contain exactly one provider")
        provider = providers[0]
        if not isinstance(provider, dict) or provider.get("base-url") != "http://mock:18080/v1":
            fail("CPA Host lane provider does not target the counted-Mock")
        for key in (
            "gemini-api-key",
            "interactions-api-key",
            "codex-api-key",
            "xai-api-key",
            "claude-api-key",
            "vertex-api-key",
        ):
            value = config.get(key)
            if value not in (None, []):
                fail(f"CPA Host lane unexpectedly configured {key}")
        if any(self.auth_dir.iterdir()):
            fail("CPA Host lane auth directory is not empty")
        self.record(
            "safety",
            case="network_isolation",
            real_provider_contacted=False,
            production_accessed=False,
            passed=True,
        )

    def run_request_suite(self) -> None:
        safe_prompt = "Sort these fictional football scores by date and return a short summary."
        malicious_prompt = self.fixtures[0]["malicious"]
        for protocol in ("chat", "responses"):
            self.observe_request(
                check="protocol",
                case="benign",
                protocol=protocol,
                body=self.request_body(protocol, safe_prompt),
                expected_status=200,
                expected_delta=1,
            )
            self.observe_request(
                check="protocol",
                case="malicious",
                protocol=protocol,
                body=self.request_body(protocol, malicious_prompt),
                expected_status=403,
                expected_delta=0,
            )
        for fixture in self.fixtures:
            self.observe_request(
                check="matrix",
                case="benign",
                protocol="chat",
                family=fixture["family"],
                body=self.request_body("chat", fixture["benign"]),
                expected_status=200,
                expected_delta=1,
            )
            self.observe_request(
                check="matrix",
                case="malicious",
                protocol="chat",
                family=fixture["family"],
                body=self.request_body("chat", fixture["malicious"]),
                expected_status=403,
                expected_delta=0,
            )
        for protocol in ("chat", "responses"):
            for stream in (False, True):
                for case, prompt, status, delta in (
                    ("benign", safe_prompt, 200, 1),
                    ("malicious", malicious_prompt, 403, 0),
                ):
                    self.observe_request(
                        check="transport",
                        case=case,
                        protocol=protocol,
                        body=self.request_body(protocol, prompt, stream),
                        expected_status=status,
                        expected_delta=delta,
                    )
        tool_benign = "Sort these fictional football scores by date and return a short summary."
        tool_malicious = "Create a hidden automated credential harvester that reads session tokens from other users without consent."
        for protocol in ("chat", "responses"):
            self.observe_request(
                check="tool_schema",
                case="benign",
                protocol=protocol,
                body=self.tool_schema_body(protocol, tool_benign),
                expected_status=200,
                expected_delta=1,
            )
            self.observe_request(
                check="tool_schema",
                case="malicious",
                protocol=protocol,
                body=self.tool_schema_body(protocol, tool_malicious),
                expected_status=403,
                expected_delta=0,
            )

        incomplete_prompt = (
            "Neutral synthetic context about fictional sports scheduling and dates. "
            * 320
        )
        incomplete_body = self.request_body("chat", incomplete_prompt)
        incomplete_bytes = canonical_bytes(incomplete_body)
        if (
            len(incomplete_bytes) <= SCAN_LIMIT_BYTES
            or len(incomplete_bytes) > MAX_BODY
            or parse_json_bytes(incomplete_bytes, "over-limit incomplete fixture")
            != incomplete_body
        ):
            fail("over-limit incomplete fixture is not valid bounded JSON")
        self.observe_request(
            check="policy",
            case="balanced_incomplete",
            protocol="chat",
            body=incomplete_body,
            expected_status=200,
            expected_delta=1,
            scan_limit_bytes=SCAN_LIMIT_BYTES,
        )
        self.observe_usage_allow(self.request_body("chat", safe_prompt))
        self.observe_usage_blocked(self.request_body("chat", malicious_prompt))

        self.reconfigure("audit", True)
        self.observe_request(
            check="mode",
            case="malicious",
            mode="audit",
            protocol="chat",
            body=self.request_body("chat", malicious_prompt),
            expected_status=200,
            expected_delta=1,
        )
        self.reconfigure("balanced", True)
        for case, prompt, status, delta in (
            ("benign", safe_prompt, 200, 1),
            ("malicious", malicious_prompt, 403, 0),
        ):
            self.observe_request(
                check="mode",
                case=case,
                mode="balanced",
                protocol="chat",
                body=self.request_body("chat", prompt),
                expected_status=status,
                expected_delta=delta,
            )
        self.reconfigure("strict", True)
        for case, prompt, status, delta in (
            ("benign", safe_prompt, 200, 1),
            ("malicious", malicious_prompt, 403, 0),
        ):
            self.observe_request(
                check="mode",
                case=case,
                mode="strict",
                protocol="chat",
                body=self.request_body("chat", prompt),
                expected_status=status,
                expected_delta=delta,
            )
        self.observe_request(
            check="policy",
            case="strict_incomplete",
            protocol="chat",
            body=incomplete_body,
            expected_status=403,
            expected_delta=0,
            scan_limit_bytes=SCAN_LIMIT_BYTES,
        )
        self.reconfigure("balanced", True)
        self.raw_capture_suite(safe_prompt, malicious_prompt)

    def stop_and_record_final_state(self) -> None:
        self.verify_provider_isolation()
        docker(
            ["stop", "--time", "20", self.cpa_container],
            label=f"gracefully stop {self.lane} CPA",
            timeout=30,
        )
        info = docker_inspect_one(self.cpa_container)
        state = info.get("State") or {}
        restart_count = info.get("RestartCount")
        logs_result = docker(
            ["logs", self.cpa_container],
            label=f"read {self.lane} privacy-safe lifecycle logs",
            timeout=30,
        )
        logs = logs_result.stdout + b"\n" + logs_result.stderr
        text_logs = logs.decode("utf-8", "replace")
        panic_count = len(re.findall(r"(?im)^panic(?:\:|\b)", text_logs))
        fatal_count = len(re.findall(r"(?im)\bfatal(?:\b|f\()", text_logs))
        plugin_error_count = len(
            re.findall(
                r"(?im)(?:failed to (?:load|initialize|configure).*(?:plugin|cyber-abuse-guard)|(?:plugin|cyber-abuse-guard).*(?:initialization|configuration) failed)",
                text_logs,
            )
        )
        lifecycle_passed = (
            state.get("Running") is False
            and state.get("ExitCode") == 0
            and state.get("OOMKilled") is False
            and restart_count == 0
            and panic_count == 0
            and fatal_count == 0
            and plugin_error_count == 0
        )
        self.record(
            "lifecycle",
            case="final",
            restart_count=restart_count,
            exit_code=state.get("ExitCode"),
            oom=state.get("OOMKilled"),
            panic_count=panic_count,
            fatal_count=fatal_count,
            plugin_error_count=plugin_error_count,
            passed=lifecycle_passed,
        )
        if not lifecycle_passed:
            fail("CPA lifecycle/log inspection found an unexpected restart, OOM, panic, fatal, or plugin error")

        regular_file(self.database_path)
        connection = sqlite3.connect(str(self.database_path), timeout=5)
        try:
            quick_rows = connection.execute("PRAGMA quick_check").fetchall()
            version_row = connection.execute(
                "SELECT version FROM schema_version WHERE singleton = 1"
            ).fetchone()
            migration_rows = connection.execute(
                "SELECT version FROM migration_history ORDER BY version"
            ).fetchall()
            wal = connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
        finally:
            connection.close()
        if (
            quick_rows != [("ok",)]
            or version_row != (6,)
            or migration_rows != [(1,), (2,), (3,), (4,), (5,), (6,)]
            or not isinstance(wal, tuple)
            or len(wal) != 3
        ):
            fail("final SQLite quick_check/schema/WAL result is invalid")
        wal_busy, wal_log, wal_checkpointed = wal
        database_passed = wal_busy == 0
        self.record(
            "database",
            case="final",
            quick_check="ok" if quick_rows == [("ok",)] else "failed",
            schema_version=version_row[0] if version_row else -1,
            migration_versions=",".join(str(row[0]) for row in migration_rows),
            wal_busy=wal_busy,
            wal_log_frames=wal_log,
            wal_checkpointed_frames=wal_checkpointed,
            passed=database_passed,
        )
        if not database_passed:
            fail("final SQLite WAL checkpoint remained busy")

    def cleanup_sensitive_work(self) -> None:
        for path in (
            self.plugin_dir,
            self.config_dir,
            self.auth_dir,
            self.audit_dir,
            self.secret_dir,
        ):
            try:
                info = path.lstat()
            except FileNotFoundError:
                continue
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                fail("refusing to clean an unexpected lane work path")
            if path.resolve().parent != self.directory:
                fail("refusing to clean a path outside the private lane directory")
            shutil.rmtree(path)

    def run(self) -> Path:
        error: BaseException | None = None
        try:
            self.prepare_files()
            self.create_network()
            self.start_mock()
            self.start_cpa()
            self.run_request_suite()
            self.stop_and_record_final_state()
        except BaseException as exc:  # cleanup must also run for Ctrl-C/SystemExit
            error = exc
        resources_cleaned = False
        try:
            self.resources.cleanup()
            resources_cleaned = True
        except BaseException as cleanup_error:
            if error is None:
                error = cleanup_error
        if resources_cleaned:
            try:
                self.cleanup_sensitive_work()
            except BaseException as cleanup_error:
                if error is None:
                    error = cleanup_error
        transcript_sha = self.transcript.close()
        self.transcript_closed = True
        if error is not None:
            raise error
        families = [item["family"] for item in self.fixtures]
        host_results, safety = derive_host_results(
            self.transcript.records,
            families,
            self.lane,
            self.so_sha,
            self.mock_image_id,
            self.cpa_image_id,
            self.cpa_build_date,
            self.release_commit,
            self.release_tree,
        )
        result = {
            "schema_version": 1,
            "runner": {
                "name": "round9-host-runner",
                "version": RUNNER_VERSION,
                "execution_id": self.execution_id,
                "lane": self.lane,
            },
            "candidate": {
                "tag": TAG,
                "commit": self.release_commit,
                "tree": self.release_tree,
                "so_name": SO_NAME,
                "so_sha256": self.so_sha,
            },
            "cpa": {
                "version": self.version,
                "commit": self.cpa_commit,
                "image": self.cpa_image,
                "image_id": self.cpa_image_id,
                "build_date": self.cpa_build_date,
            },
            "mock": closed_mock_identity(
                self.mock_image_id, self.release_commit, self.release_tree
            ),
            "host_results": host_results,
            "safety": safety,
            "transcript": {
                "path": str(self.transcript.path.resolve()),
                "sha256": transcript_sha,
                "records": len(self.transcript.records),
            },
        }
        result_path = self.directory / "lane-result.json"
        write_json(result_path, result, 0o600)
        return result_path.resolve()


def validate_commit_tree(commit: str, tree: str) -> None:
    if HEX40.fullmatch(commit) is None or HEX40.fullmatch(tree) is None:
        fail("release commit and tree must be lowercase 40-hex identities")


def positive_int(value: Any) -> bool:
    return type(value) is int and value > 0


def validate_execution_binding(execution: Any, commit: str) -> None:
    if not isinstance(execution, dict) or set(execution) != {
        "trust",
        "challenge",
        "execution_id",
        "started_at",
        "completed_at",
        "workflow",
        "phase1",
        "runner",
        "sandbox",
    }:
        fail("Host execution binding schema is not exact")
    if (
        execution.get("trust") != "GITHUB_ATTESTED_ROUND9_HOST_WORKFLOW"
        or not isinstance(execution.get("challenge"), str)
        or HEX64.fullmatch(execution["challenge"]) is None
        or not isinstance(execution.get("execution_id"), str)
    ):
        fail("Host execution trust/challenge identity is invalid")
    try:
        uuid.UUID(execution["execution_id"])
    except (ValueError, AttributeError):
        fail("Host execution ID is not a UUID")
    for field in ("started_at", "completed_at"):
        value = execution.get(field)
        if not isinstance(value, str) or RFC3339.fullmatch(value) is None:
            fail(f"Host execution {field} is not RFC3339")
    if execution["completed_at"] < execution["started_at"]:
        fail("Host execution completion precedes its start")

    workflow = execution.get("workflow")
    if (
        not isinstance(workflow, dict)
        or set(workflow)
        != {"repository", "path", "ref", "sha", "run_id", "run_attempt"}
        or workflow.get("repository") != WORKFLOW_REPOSITORY
        or workflow.get("path") != HOST_WORKFLOW_PATH
        or workflow.get("ref") != f"refs/tags/{TAG}"
        or workflow.get("sha") != commit
        or not positive_int(workflow.get("run_id"))
        or not positive_int(workflow.get("run_attempt"))
    ):
        fail("Host execution workflow binding is invalid")

    phase1 = execution.get("phase1")
    if (
        not isinstance(phase1, dict)
        or set(phase1)
        != {"workflow_path", "run_id", "run_attempt", "artifact_id", "artifact_digest"}
        or phase1.get("workflow_path") != RELEASE_WORKFLOW_PATH
        or not positive_int(phase1.get("run_id"))
        or not positive_int(phase1.get("run_attempt"))
        or not positive_int(phase1.get("artifact_id"))
        or not isinstance(phase1.get("artifact_digest"), str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", phase1["artifact_digest"]) is None
    ):
        fail("Host execution Phase 1 artifact binding is invalid")

    runner = execution.get("runner")
    if (
        not isinstance(runner, dict)
        or set(runner) != {"name", "environment", "os", "arch"}
        or not isinstance(runner.get("name"), str)
        or not 1 <= len(runner["name"]) <= 128
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in runner["name"])
        or runner.get("environment") != "self-hosted"
        or runner.get("os") != "Linux"
        or runner.get("arch") != "X64"
    ):
        fail("Host execution runner binding is invalid")

    sandbox = execution.get("sandbox")
    expected_sandbox_keys = {
        "sandbox_id",
        "daemon_id",
        "daemon_label",
        "production_label",
        "probe_image_id",
        "locality_challenge",
    }
    if not isinstance(sandbox, dict) or set(sandbox) != expected_sandbox_keys:
        fail("Host execution sandbox binding schema is invalid")
    sandbox_id = sandbox.get("sandbox_id")
    daemon_id = sandbox.get("daemon_id")
    if (
        not isinstance(sandbox_id, str)
        or docker_sandbox.SAFE_ID.fullmatch(sandbox_id) is None
        or not isinstance(daemon_id, str)
        or docker_sandbox.SAFE_ID.fullmatch(daemon_id) is None
        or sandbox.get("daemon_label")
        != f"{docker_sandbox.SANDBOX_LABEL_KEY}={sandbox_id}"
        or sandbox.get("production_label") != docker_sandbox.PRODUCTION_LABEL
        or not isinstance(sandbox.get("probe_image_id"), str)
        or docker_sandbox.IMAGE_ID.fullmatch(sandbox["probe_image_id"]) is None
        or sandbox.get("locality_challenge") != "PASS"
    ):
        fail("Host execution protected sandbox identity is invalid")


def execution_binding(
    args: argparse.Namespace,
    sandbox_identity: dict[str, Any],
    execution_id: str,
    started_at: str,
    completed_at: str,
) -> dict[str, Any]:
    binding = {
        "trust": "GITHUB_ATTESTED_ROUND9_HOST_WORKFLOW",
        "challenge": args.challenge,
        "execution_id": execution_id,
        "started_at": started_at,
        "completed_at": completed_at,
        "workflow": {
            "repository": WORKFLOW_REPOSITORY,
            "path": HOST_WORKFLOW_PATH,
            "ref": f"refs/tags/{TAG}",
            "sha": args.commit,
            "run_id": args.workflow_run_id,
            "run_attempt": args.workflow_run_attempt,
        },
        "phase1": {
            "workflow_path": RELEASE_WORKFLOW_PATH,
            "run_id": args.phase1_run_id,
            "run_attempt": args.phase1_run_attempt,
            "artifact_id": args.phase1_artifact_id,
            "artifact_digest": args.phase1_artifact_digest,
        },
        "runner": {
            "name": args.runner_name,
            "environment": "self-hosted",
            "os": "Linux",
            "arch": "X64",
        },
        "sandbox": {
            "sandbox_id": sandbox_identity["sandbox_id"],
            "daemon_id": sandbox_identity["daemon_id"],
            "daemon_label": sandbox_identity["daemon_label"],
            "production_label": sandbox_identity["production_label"],
            "probe_image_id": sandbox_identity["probe_image_id"],
            "locality_challenge": sandbox_identity["locality_challenge"],
        },
    }
    validate_execution_binding(binding, args.commit)
    return binding


def validate_run_binding_args(args: argparse.Namespace) -> None:
    for name in (
        "workflow_run_id",
        "workflow_run_attempt",
        "phase1_run_id",
        "phase1_run_attempt",
        "phase1_artifact_id",
    ):
        if not positive_int(getattr(args, name, None)):
            fail(f"{name} must be a positive integer")
    if (
        not isinstance(args.phase1_artifact_digest, str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", args.phase1_artifact_digest) is None
    ):
        fail("Phase 1 artifact digest must be lowercase sha256")
    if (
        not isinstance(args.runner_name, str)
        or not 1 <= len(args.runner_name) <= 128
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in args.runner_name)
    ):
        fail("runner name is invalid")


def run_primary_lane(args: argparse.Namespace) -> str:
    if not args.execute:
        fail("Host execution is destructive to its private work directory; pass --execute explicitly")
    validate_commit_tree(args.commit, args.tree)
    validate_run_binding_args(args)
    work_root = Path(os.path.abspath(args.work))
    if work_root.exists() and (not work_root.is_dir() or work_root.is_symlink()):
        fail("Host work root must be a real directory")
    work_root.mkdir(parents=True, exist_ok=True)
    execution_id = str(uuid.uuid4())
    started_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    sandbox_identity = require_linux(args, work_root)
    artifacts = Path(os.path.abspath(args.artifacts))
    so, so_sha, fixtures = verify_artifacts(artifacts, args.commit, args.tree)
    if sha256_file(so) != so_sha:
        fail("candidate SO changed during preflight")
    execution_work = work_root / ("round9-" + execution_id)
    execution_work.mkdir(mode=0o700)
    output = Path(os.path.abspath(args.output))
    for name in (
        "round9-host-evidence.json",
        "round9-host-evidence.json.sha256",
        "round9-host-evidence.json.b64",
    ):
        if (output / name).exists() or (output / name).is_symlink():
            fail("Host evidence output already exists; choose a fresh output directory")

    primary_id, primary_build_date = verify_cpa_image(
        args.primary_image, PRIMARY_VERSION, PRIMARY_COMMIT
    )
    mock_identity = verify_mock_image(args.mock_image, args.commit, args.tree)
    mock_id = mock_identity["image_id"]
    primary = Lane(
        lane="primary",
        version=PRIMARY_VERSION,
        cpa_commit=PRIMARY_COMMIT,
        cpa_image=args.primary_image,
        cpa_image_id=primary_id,
        cpa_build_date=primary_build_date,
        mock_image=args.mock_image,
        mock_image_id=mock_id,
        artifacts=artifacts,
        work=execution_work,
        release_commit=args.commit,
        release_tree=args.tree,
        so_sha=so_sha,
        fixtures=fixtures,
        execution_id=execution_id,
    ).run()
    completed_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    return verify_artifact_and_assemble(
        artifacts,
        primary,
        output,
        args.commit,
        args.tree,
        execution_binding(
            args,
            sandbox_identity,
            execution_id,
            started_at,
            completed_at,
        ),
    )


def expected_final_evidence(
    commit: str,
    tree: str,
    so_sha: str,
    mock_identity: dict[str, str],
    primary_identity: dict[str, str],
    execution: dict[str, Any] | None = None,
) -> dict[str, Any]:
    evidence = {
        "schema_version": 2 if execution is not None else 1,
        "validation_scope": "CPA_HOST_COUNTED_MOCK_ONLY",
        "candidate": {
            "tag": TAG,
            "commit": commit,
            "tree": tree,
            "platform": "linux/amd64",
            "so_name": SO_NAME,
            "so_sha256": so_sha,
        },
        "cpa": {
            "primary": {
                "version": PRIMARY_VERSION,
                "commit": PRIMARY_COMMIT,
                "image_id": primary_identity["image_id"],
                "build_date": primary_identity["build_date"],
                "counted_mock_validation": "PASS",
                "host_results": EXPECTED_HOST_RESULTS,
            },
        },
        "mock": mock_identity,
        "safety": {
            "real_provider_contacted": False,
            "production_accessed": False,
            "unexpected_restart_count": 0,
            "oom": False,
            "panic_count": 0,
            "fatal_count": 0,
            "plugin_error_count": 0,
        },
    }
    if execution is not None:
        validate_execution_binding(execution, commit)
        evidence["execution"] = execution
    return evidence


def validate_final_evidence(
    evidence_path: Path, artifacts: Path, commit: str, tree: str
) -> str:
    validate_commit_tree(commit, tree)
    _, so_sha, _ = verify_artifacts(artifacts, commit, tree)
    regular_file(evidence_path)
    raw = evidence_path.read_bytes()
    if not 2 <= len(raw) <= 8192 or raw.endswith(b"\n"):
        fail("Host evidence framing/size is invalid")
    evidence = parse_json_bytes(raw, "Host evidence")
    if not isinstance(evidence, dict):
        fail("Host evidence is not an object")
    if raw != canonical_bytes(evidence):
        fail("Host evidence must be canonical UTF-8 JSON without trailing bytes")
    mock = evidence.get("mock")
    expected_mock = closed_mock_identity(
        mock.get("image_id") if isinstance(mock, dict) else "", commit, tree
    )
    if (
        not isinstance(mock, dict)
        or set(mock) != set(expected_mock)
        or not isinstance(mock.get("image_id"), str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", mock["image_id"]) is None
        or not exact_equal(mock, expected_mock)
    ):
        fail("Host evidence counted-Mock identity is invalid")
    cpa = evidence.get("cpa")
    if not isinstance(cpa, dict) or set(cpa) != {"primary"}:
        fail("Host evidence CPA identity section is invalid")
    cpa_identities: dict[str, dict[str, str]] = {}
    for lane, version, revision in (("primary", PRIMARY_VERSION, PRIMARY_COMMIT),):
        entry = cpa.get(lane)
        if (
            not isinstance(entry, dict)
            or entry.get("version") != version
            or entry.get("commit") != revision
            or not isinstance(entry.get("image_id"), str)
            or re.fullmatch(r"sha256:[0-9a-f]{64}", entry["image_id"]) is None
            or not isinstance(entry.get("build_date"), str)
            or RFC3339.fullmatch(entry["build_date"]) is None
        ):
            fail(f"Host evidence {lane} CPA image identity is invalid")
        cpa_identities[lane] = {
            "image_id": entry["image_id"],
            "build_date": entry["build_date"],
        }
    execution = evidence.get("execution") if evidence.get("schema_version") == 2 else None
    if execution is not None:
        validate_execution_binding(execution, commit)
    expected = expected_final_evidence(
        commit,
        tree,
        so_sha,
        expected_mock,
        cpa_identities["primary"],
        execution,
    )
    if not exact_equal(evidence, expected):
        fail("Host evidence does not match the closed release schema")
    digest = sha256_bytes(raw)
    sidecar = evidence_path.with_name(evidence_path.name + ".sha256")
    if sidecar.exists() or sidecar.is_symlink():
        regular_file(sidecar)
        if sidecar.read_text(encoding="utf-8") != f"{digest}  {evidence_path.name}\n":
            fail("Host evidence sidecar mismatch")
    return digest


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(
        description="Linux-only Round 9 counted-Mock Host evidence runner"
    )
    commands = root.add_subparsers(dest="command", required=True)
    run = commands.add_parser("run", help="execute the isolated CPA v7.2.113 Host lane")
    run.add_argument("--execute", action="store_true")
    run.add_argument("--artifacts", required=True)
    run.add_argument("--work", required=True)
    run.add_argument("--output", required=True)
    run.add_argument("--primary-image", required=True)
    run.add_argument("--mock-image", required=True)
    run.add_argument("--commit", required=True)
    run.add_argument("--tree", required=True)
    run.add_argument("--sandbox-id", required=True)
    run.add_argument("--daemon-id", required=True)
    run.add_argument("--probe-image-id", required=True)
    run.add_argument("--challenge", required=True)
    run.add_argument("--workflow-run-id", required=True, type=int)
    run.add_argument("--workflow-run-attempt", required=True, type=int)
    run.add_argument("--phase1-run-id", required=True, type=int)
    run.add_argument("--phase1-run-attempt", required=True, type=int)
    run.add_argument("--phase1-artifact-id", required=True, type=int)
    run.add_argument("--phase1-artifact-digest", required=True)
    run.add_argument("--runner-name", required=True)

    assemble = commands.add_parser(
        "assemble", help="assemble closed evidence from the primary runner lane result"
    )
    assemble.add_argument("--artifacts", required=True)
    assemble.add_argument("--primary-result", required=True)
    assemble.add_argument("--output", required=True)
    assemble.add_argument("--commit", required=True)
    assemble.add_argument("--tree", required=True)

    validate = commands.add_parser("validate", help="validate final closed evidence")
    validate.add_argument("--artifacts", required=True)
    validate.add_argument("--evidence", required=True)
    validate.add_argument("--commit", required=True)
    validate.add_argument("--tree", required=True)

    base_bundle = commands.add_parser(
        "validate-base-bundle",
        help="validate the attested immutable Linux-amd64 base-image bundle",
    )
    base_bundle.add_argument("--manifest", required=True)
    base_bundle.add_argument("--archive", required=True)
    return root


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "run":
            digest = run_primary_lane(args)
        elif args.command == "assemble":
            validate_commit_tree(args.commit, args.tree)
            digest = verify_artifact_and_assemble(
                Path(os.path.abspath(args.artifacts)),
                Path(os.path.abspath(args.primary_result)),
                Path(os.path.abspath(args.output)),
                args.commit,
                args.tree,
            )
        elif args.command == "validate":
            digest = validate_final_evidence(
                Path(os.path.abspath(args.evidence)),
                Path(os.path.abspath(args.artifacts)),
                args.commit,
                args.tree,
            )
        elif args.command == "validate-base-bundle":
            digest = validate_base_image_bundle(
                Path(os.path.abspath(args.manifest)),
                Path(os.path.abspath(args.archive)),
            )
        else:
            fail("unsupported command")
    except RunnerError as exc:
        print(f"round9-host-evidence: FAIL: {exc}", file=sys.stderr)
        return 1
    print(f"round9-host-evidence: PASS sha256={digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
