#!/usr/bin/env python3
"""Fail-closed Docker sandbox identity and host-locality preflight.

The Unix-socket shape is not a locality proof: SSH and socat can expose a
remote daemon through a local AF_UNIX socket.  This helper therefore binds the
daemon to protected identity metadata and performs an unpredictable host bind
mount challenge before any Round 8 build, workload container, or network is
created.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import secrets
import shutil
import stat
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Sequence


SANDBOX_LABEL_KEY = "io.cyber-abuse-guard.round8-sandbox"
PRODUCTION_LABEL = "io.cyber-abuse-guard.production=false"
HEX64 = re.compile(r"[0-9a-f]{64}")
IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}")
SAFE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{7,127}")
CONTEXT_NAME = re.compile(r"[A-Za-z0-9_.-]{1,128}")


class SandboxError(RuntimeError):
    """A fail-closed sandbox preflight error."""


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: bytes
    stderr: bytes


DockerRunner = Callable[[Sequence[str], str, float, bool], CommandResult]


def _fail(message: str) -> None:
    raise SandboxError(message)


def _docker(
    args: Sequence[str], label: str, timeout: float = 30, check: bool = True
) -> CommandResult:
    try:
        completed = subprocess.run(
            ["docker", *args],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        _fail(f"{label} failed without exposing command output: {type(exc).__name__}")
    result = CommandResult(completed.returncode, completed.stdout, completed.stderr)
    if check and result.returncode != 0:
        _fail(f"{label} failed with exit={result.returncode}")
    return result


def _decode(raw: bytes, label: str) -> str:
    try:
        return raw.decode("utf-8", "strict").strip()
    except UnicodeDecodeError:
        _fail(f"{label} is not UTF-8")


def _json(raw: bytes, label: str) -> Any:
    try:
        return json.loads(raw.decode("utf-8", "strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        _fail(f"{label} is not valid JSON: {type(exc).__name__}")


def require_unix_socket(endpoint: str, label: str) -> tuple[Path, os.stat_result]:
    if not isinstance(endpoint, str) or not endpoint.startswith("unix://"):
        _fail(f"{label} must use a Unix Docker socket")
    raw = endpoint[len("unix://") :]
    if (
        not raw.startswith("/")
        or any(marker in raw for marker in ("%", "?", "#"))
        or any(part == ".." for part in Path(raw).parts)
    ):
        _fail(f"{label} Unix Docker socket path is invalid")
    path = Path(raw)
    try:
        info = path.lstat()
    except FileNotFoundError:
        _fail(f"{label} Unix Docker socket is missing")
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISSOCK(info.st_mode):
        _fail(f"{label} endpoint is not a real Unix socket")
    return path, info


def _validate_inputs(
    sandbox_id: str,
    daemon_id: str,
    probe_image_id: str,
    challenge: str,
    challenge_root: Path,
) -> None:
    if SAFE_ID.fullmatch(sandbox_id) is None:
        _fail("sandbox ID must be 8-128 safe identity characters")
    if SAFE_ID.fullmatch(daemon_id) is None:
        _fail("expected Docker daemon ID must be 8-128 safe identity characters")
    if IMAGE_ID.fullmatch(probe_image_id) is None:
        _fail("probe image must be an immutable sha256 image ID")
    if HEX64.fullmatch(challenge) is None:
        _fail("sandbox challenge must be lowercase 64-hex")
    try:
        root_info = challenge_root.lstat()
    except FileNotFoundError:
        _fail("sandbox challenge root is missing")
    if stat.S_ISLNK(root_info.st_mode) or not stat.S_ISDIR(root_info.st_mode):
        _fail("sandbox challenge root must be a real directory")


def verify_sandbox(
    *,
    sandbox_id: str,
    daemon_id: str,
    probe_image_id: str,
    challenge: str,
    challenge_root: Path,
    docker_runner: DockerRunner = _docker,
) -> dict[str, Any]:
    """Verify protected daemon identity and prove host bind-mount locality."""

    _validate_inputs(sandbox_id, daemon_id, probe_image_id, challenge, challenge_root)
    if platform.system() != "Linux" or platform.machine().lower() not in {
        "x86_64",
        "amd64",
    }:
        _fail("Round 8 Docker sandbox preflight requires Linux amd64")
    if shutil.which("docker") is None and docker_runner is _docker:
        _fail("docker is required for sandbox preflight")
    for name in ("DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH"):
        if os.environ.get(name):
            _fail(f"{name} is forbidden for the Round 8 sandbox daemon")

    context_name = _decode(
        docker_runner(["context", "show"], "Docker context identity", 30, True).stdout,
        "Docker context identity",
    )
    if CONTEXT_NAME.fullmatch(context_name) is None:
        _fail("Docker context identity is invalid")
    configured_context = os.environ.get("DOCKER_CONTEXT")
    if configured_context and configured_context != context_name:
        _fail("DOCKER_CONTEXT does not match the active Docker context")
    context_payload = _json(
        docker_runner(
            ["context", "inspect", context_name],
            "Docker context inspection",
            30,
            True,
        ).stdout,
        "Docker context inspection",
    )
    if (
        not isinstance(context_payload, list)
        or len(context_payload) != 1
        or not isinstance(context_payload[0], dict)
    ):
        _fail("Docker context inspection did not return one context")
    endpoints = context_payload[0].get("Endpoints")
    docker_endpoint = endpoints.get("docker") if isinstance(endpoints, dict) else None
    endpoint = docker_endpoint.get("Host") if isinstance(docker_endpoint, dict) else None
    if not isinstance(endpoint, str):
        _fail("Docker context has no exact daemon endpoint")
    socket_path, socket_info = require_unix_socket(endpoint, "Docker context")
    configured_host = os.environ.get("DOCKER_HOST")
    if configured_host:
        require_unix_socket(configured_host, "DOCKER_HOST")
        if configured_host != endpoint:
            _fail("DOCKER_HOST does not match the active Docker context")

    info_template = (
        '{"id":{{json .ID}},"os":{{json .OSType}},'
        '"arch":{{json .Architecture}},"labels":{{json .Labels}}}'
    )
    daemon = _json(
        docker_runner(
            ["info", "--format", info_template],
            "Docker protected identity",
            30,
            True,
        ).stdout,
        "Docker protected identity",
    )
    if not isinstance(daemon, dict):
        _fail("Docker protected identity is not an object")
    labels = daemon.get("labels")
    if labels is None:
        labels = []
    if not isinstance(labels, list) or not all(isinstance(item, str) for item in labels):
        _fail("Docker daemon labels are invalid")
    expected_sandbox_label = f"{SANDBOX_LABEL_KEY}={sandbox_id}"
    if daemon.get("id") != daemon_id:
        _fail("Docker daemon ID does not match the protected sandbox identity")
    if daemon.get("os") != "linux" or daemon.get("arch") not in {
        "x86_64",
        "amd64",
    }:
        _fail("Docker daemon must be Linux amd64")
    if labels.count(expected_sandbox_label) != 1 or labels.count(PRODUCTION_LABEL) != 1:
        _fail("Docker daemon is missing the exact protected non-production sandbox labels")

    image = _json(
        docker_runner(
            ["image", "inspect", probe_image_id],
            "sandbox probe image inspection",
            30,
            True,
        ).stdout,
        "sandbox probe image inspection",
    )
    if (
        not isinstance(image, list)
        or len(image) != 1
        or not isinstance(image[0], dict)
        or image[0].get("Id") != probe_image_id
        or image[0].get("Os") != "linux"
        or image[0].get("Architecture") != "amd64"
    ):
        _fail("sandbox probe image identity/platform is invalid")

    directory = Path(
        tempfile.mkdtemp(prefix="cag-round8-locality-", dir=str(challenge_root.resolve()))
    )
    container_name = "cag-round8-locality-" + secrets.token_hex(8)
    container_created = False
    try:
        directory.chmod(0o700)
        nonce = hashlib.sha256(
            (challenge + ":" + secrets.token_hex(32)).encode("ascii")
        ).hexdigest()
        nonce_path = directory / "nonce"
        nonce_path.write_text(nonce + "\n", encoding="ascii")
        nonce_path.chmod(0o400)
        create = docker_runner(
            [
                "create",
                "--name",
                container_name,
                "--network",
                "none",
                "--read-only",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges",
                "--pids-limit",
                "32",
                "--memory",
                "32m",
                "--memory-swap",
                "32m",
                "--cpus",
                "0.25",
                "--ulimit",
                "nofile=64:64",
                "--mount",
                f"type=bind,src={directory.resolve()},dst=/challenge,readonly",
                "--entrypoint",
                "/bin/cat",
                probe_image_id,
                "/challenge/nonce",
            ],
            "sandbox host-locality container creation",
            30,
            False,
        )
        if create.returncode != 0:
            _fail("sandbox host-locality bind mount could not be created")
        container_created = True
        container_id = _decode(create.stdout, "sandbox locality container ID")
        if re.fullmatch(r"[0-9a-f]{12,64}", container_id) is None:
            _fail("sandbox locality container ID is invalid")
        started = docker_runner(
            ["start", "--attach", container_name],
            "sandbox host-locality challenge",
            30,
            False,
        )
        if started.returncode != 0 or _decode(started.stdout, "locality response") != nonce:
            _fail("Docker daemon failed the host bind-mount locality challenge")
    finally:
        if container_created:
            docker_runner(
                ["rm", "--force", container_name],
                "sandbox locality cleanup",
                30,
                False,
            )
        try:
            nonce_path = directory / "nonce"
            if nonce_path.exists() and not nonce_path.is_symlink():
                nonce_path.chmod(0o600)
            shutil.rmtree(directory)
        except OSError:
            pass

    return {
        "sandbox_id": sandbox_id,
        "daemon_id": daemon_id,
        "daemon_label": expected_sandbox_label,
        "production_label": PRODUCTION_LABEL,
        "probe_image_id": probe_image_id,
        "docker_context": context_name,
        "socket_path": str(socket_path),
        "socket_device": socket_info.st_dev,
        "socket_inode": socket_info.st_ino,
        "socket_uid": socket_info.st_uid,
        "socket_gid": socket_info.st_gid,
        "locality_challenge": "PASS",
    }


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description="Round 8 protected Docker sandbox preflight")
    result.add_argument("--sandbox-id", required=True)
    result.add_argument("--daemon-id", required=True)
    result.add_argument("--probe-image-id", required=True)
    result.add_argument("--challenge", required=True)
    result.add_argument("--challenge-root", required=True)
    return result


def main() -> int:
    args = parser().parse_args()
    try:
        identity = verify_sandbox(
            sandbox_id=args.sandbox_id,
            daemon_id=args.daemon_id,
            probe_image_id=args.probe_image_id,
            challenge=args.challenge,
            challenge_root=Path(args.challenge_root),
        )
    except SandboxError as exc:
        print(f"round8-docker-sandbox: FAIL: {exc}", file=os.sys.stderr)
        return 1
    print(json.dumps(identity, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
