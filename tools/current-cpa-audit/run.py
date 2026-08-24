#!/usr/bin/env python3
"""Run the fixed five-repository corpus against CPA v7.2.137 in isolation.

The harness never executes corpus bytes.  It gives CPA exactly one internal
counted-Mock upstream, publishes no host port, records no request text, and
removes every complete corpus text in ``finally`` (including all NERV bytes).
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import platform
import re
import secrets
import signal
import shutil
import socket
import sqlite3
import stat
import subprocess
import sys
import tempfile
import threading
import time
import traceback
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator, Mapping, NoReturn, Sequence
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from acquire import validate_policy
from audit_contract import (
    AUDIT_SCHEMA_VERSION,
    CLAIM_BOUNDARY,
    CPA_OFFICIAL_ASSET_SIZE,
    CPA_TAG,
    EVIDENCE_SCHEMA,
    FIXED_REPOSITORIES,
    MOCK_CONTRACT,
    MODES,
    PROTOCOLS,
    REALTIME_ROUTE_CONTRACT,
    REALTIME_RPC_COUNTER_KEYS,
    RESULT_SCHEMA,
    STREAM_VALUES,
    SUPPLEMENTAL_ZIP_RESULT_SCHEMA,
    BoundCorpus,
    ContractError,
    add_exception_note,
    apply_template,
    build_execution_plan,
    build_supplemental_execution_plan,
    canonical_bytes,
    expected_request_hash,
    load_json_bytes,
    load_json_file,
    read_regular_bytes,
    regular_file_info,
    sha256_bytes,
    sha256_file,
    validate_allow_response,
    validate_block_response,
    validate_candidate_manifest_file,
    validate_corpus_manifest,
    validate_machine_evidence,
    validate_manifest_policy,
    validate_result,
    validate_run_config,
    validate_supplemental_result,
    validate_supplemental_run_config_files,
)
from supplemental_zip import load_selected_supplemental_texts
from lazy_read import LazyReadError, LazyReadRecorder
from second_machine_release_admission import (
    validate_csam_text_evidence,
    validate_lazy_read_bindings,
    validate_lazy_read_evidence,
)


TOOL_DIR = Path(__file__).resolve().parent
POLICY_PATH = TOOL_DIR / "repository-policy.json"
MACHINE_SCHEMA_PATH = TOOL_DIR / "machine-evidence.schema.json"
MODEL = "current-cpa-audit-model"
LABEL_KEY = "cag.current-cpa-audit.run"
ROLE_LABEL = "cag.current-cpa-audit.role"
CPA_PORT = 8317
MOCK_PORT = 18080
MOCK_SOURCE_PATH = "/opt/cag-audit/counted_mock.py"
MOCK_ENTRYPOINT = ["python3", "-I", "-S", "-B", MOCK_SOURCE_PATH]
REALTIME_ROUTES = REALTIME_ROUTE_CONTRACT
MAX_REQUEST_BYTES = 16 * 1024 * 1024
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
MAX_CONFIG_BYTES = 2 * 1024 * 1024
# Backward-compatible local name used throughout the runner and its fixtures.
SCHEMA_VERSION = AUDIT_SCHEMA_VERSION
RUNNER_BUNDLE_FILES = (
    "Dockerfile.mock",
    "README.md",
    "acquire.py",
    "audit_contract.py",
    "counted_mock.py",
    "csam_text_evidence.py",
    "csam_text_runner.py",
    "lazy_read.py",
    "make_run_config.py",
    "machine-evidence.schema.json",
    "repository-policy.json",
    "run.py",
    "second_machine_release_admission.py",
    "supplemental-zip-policy.json",
    "supplemental_zip.py",
    "validate.py",
)


class AuditFailure(RuntimeError):
    """A runtime or identity gate failed."""


class CleanupFailure(AuditFailure):
    """Cleanup was attempted but exact absence could not be proven."""

    def __init__(self, errors: Sequence[str]) -> None:
        self.cleanup_error_id = sha256_bytes(canonical_bytes(list(errors)))[:16]
        super().__init__(f"cleanup failed closed; cleanup_error_id={self.cleanup_error_id}")


def _zeroize_supplemental_texts(values: dict[str, bytearray]) -> bool:
    """Zero caller-owned buffers and report whether the cleanup was proven."""

    buffers = tuple(values.values())
    for raw in buffers:
        raw[:] = b"\x00" * len(raw)
    values.clear()
    return not values and all(not any(raw) for raw in buffers)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def fail(message: str) -> NoReturn:
    raise AuditFailure(message)


def write_exclusive(path: Path, raw: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, mode)
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise
    os.chmod(path, mode)


def write_json(path: Path, value: Any) -> None:
    write_exclusive(path, canonical_bytes(value) + b"\n")


@contextmanager
def ephemeral_mock_environment(
    directory: Path, control_token: str, upstream_key: str
) -> Iterator[Path]:
    """Expose Mock credentials to the Docker CLI without placing values in argv.

    The file lives below the descriptor-bound runtime tree, is created with one
    link and mode 0600, and is removed immediately after ``docker run`` returns.
    Docker expands ``--env-file`` into the container configuration, so the
    local rootful daemon remains in the trusted computing base.
    """

    values = {
        "CAG_MOCK_CONTROL_TOKEN": control_token,
        "CAG_MOCK_UPSTREAM_KEY": upstream_key,
    }
    for key, value in values.items():
        if not value or any(marker in value for marker in ("\x00", "\r", "\n")):
            fail(f"{key} cannot be represented in a Docker environment file")
    raw = b"".join(
        f"{key}={value}\n".encode("utf-8") for key, value in values.items()
    )
    path = directory / ".mock-environment"
    write_exclusive(path, raw, mode=0o600)
    expected = path.lstat()
    expected_identity = (
        expected.st_dev,
        expected.st_ino,
        expected.st_uid,
        expected.st_gid,
        stat.S_IMODE(expected.st_mode),
        expected.st_nlink,
        expected.st_size,
    )
    expected_sha256 = sha256_bytes(raw)
    primary_error: BaseException | None = None
    try:
        try:
            if (
                not stat.S_ISREG(expected.st_mode)
                or stat.S_ISLNK(expected.st_mode)
                or expected.st_nlink != 1
                or stat.S_IMODE(expected.st_mode) != 0o600
                or expected.st_size != len(raw)
                or (
                    os.name == "posix"
                    and (expected.st_uid != os.getuid() or expected.st_gid != os.getgid())
                )
                or sha256_file(path) != expected_sha256
            ):
                fail("ephemeral Mock environment file identity is invalid")
            yield path
        except BaseException as error:
            primary_error = error
            raise
    finally:
        try:
            try:
                current = path.lstat()
            except FileNotFoundError:
                fail("ephemeral Mock environment file disappeared before cleanup")
            current_identity = (
                current.st_dev,
                current.st_ino,
                current.st_uid,
                current.st_gid,
                stat.S_IMODE(current.st_mode),
                current.st_nlink,
                current.st_size,
            )
            if (
                not stat.S_ISREG(current.st_mode)
                or stat.S_ISLNK(current.st_mode)
                or current_identity != expected_identity
                or sha256_file(path) != expected_sha256
            ):
                fail("ephemeral Mock environment file changed before cleanup")
            path.unlink()
            try:
                path.lstat()
            except FileNotFoundError:
                pass
            else:
                fail("ephemeral Mock environment file remained after cleanup")
        except Exception as cleanup_error:
            if primary_error is None:
                raise
            add_exception_note(
                primary_error,
                "ephemeral Mock environment cleanup also failed: "
                f"{type(cleanup_error).__name__}: {cleanup_error}"
            )


def load_canonical(path: Path, label: str, maximum: int) -> tuple[dict[str, Any], bytes]:
    raw = read_regular_bytes(path, label, maximum)
    value = load_json_bytes(raw, label, maximum)
    if not isinstance(value, dict):
        fail(f"{label} must be an object")
    if raw != canonical_bytes(value) + b"\n":
        fail(f"{label} must be canonical JSON with one terminal newline")
    return value, raw


def require_private_directory(path: Path, label: str) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        fail(f"{label} is missing")
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        fail(f"{label} must be a real directory")
    if os.name == "posix" and info.st_mode & 0o077:
        fail(f"{label} must be mode-0700 or stricter")


class BoundEvidenceDirectory:
    """Keep evidence writes pinned to one inode after the directory is bound."""

    @staticmethod
    def _flags() -> int:
        if not hasattr(os, "O_DIRECTORY") or not hasattr(os, "O_NOFOLLOW"):
            fail("the evidence directory binding requires Linux openat semantics")
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        return flags

    def __init__(self, path: Path) -> None:
        try:
            descriptor = os.open(path, self._flags())
        except OSError as exc:
            fail(f"evidence directory cannot be bound: {type(exc).__name__}")
        self._initialize(path, descriptor)

    @staticmethod
    def _absolute_components(path: Path) -> tuple[Path, ...]:
        if not path.is_absolute() or not path.anchor:
            fail("evidence directory must be an absolute path")
        cursor = Path(path.anchor)
        components = [cursor]
        for part in path.parts[1:]:
            if part in {"", ".", ".."}:
                fail("evidence directory path has an unsafe component")
            cursor /= part
            components.append(cursor)
        return tuple(components)

    @classmethod
    def _snapshot_path(cls, path: Path) -> tuple[tuple[int, int], ...]:
        """Capture every real directory inode in one lexical absolute path."""

        identity: list[tuple[int, int]] = []
        for component in cls._absolute_components(path):
            try:
                info = component.lstat()
            except OSError as exc:
                fail(
                    "evidence directory ancestor cannot be verified: "
                    f"{type(exc).__name__}"
                )
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                fail("evidence directory ancestors must be real directories")
            identity.append((info.st_dev, info.st_ino))
        return tuple(identity)

    @classmethod
    def create(cls, path: Path) -> "BoundEvidenceDirectory":
        """Create and bind below a private parent for a dedicated-UID run.

        Linux has no syscall that atomically creates a directory and returns an
        fd for that new inode.  The operator contract therefore excludes an
        untrusted process sharing the runner UID during bootstrap and execution.
        The descriptor binding detects path replacement after the child is open.
        """

        flags = cls._flags()
        if path.name in {"", ".", ".."}:
            fail("evidence directory path has an unsafe final component")
        parent_identity = cls._snapshot_path(path.parent)
        try:
            parent_descriptor = os.open(path.parent, flags)
        except OSError as exc:
            fail(f"evidence directory parent cannot be bound: {type(exc).__name__}")
        descriptor = -1
        try:
            parent_info = os.fstat(parent_descriptor)
            if (
                not stat.S_ISDIR(parent_info.st_mode)
                or (parent_info.st_dev, parent_info.st_ino) != parent_identity[-1]
                or (
                    os.name == "posix" and parent_info.st_mode & 0o077
                )
            ):
                fail("evidence directory parent must be a private real directory")
            try:
                os.mkdir(path.name, mode=0o700, dir_fd=parent_descriptor)
            except FileExistsError:
                fail("evidence directory must be a new path")
            except OSError as exc:
                fail(f"evidence directory cannot be created: {type(exc).__name__}")
            created = os.stat(
                path.name, dir_fd=parent_descriptor, follow_symlinks=False
            )
            descriptor = os.open(path.name, flags, dir_fd=parent_descriptor)
            opened = os.fstat(descriptor)
            if (
                not stat.S_ISDIR(created.st_mode)
                or (created.st_dev, created.st_ino) != (opened.st_dev, opened.st_ino)
            ):
                fail("evidence directory changed between creation and binding")
            os.fchmod(descriptor, 0o700)
            instance = cls.__new__(cls)
            owned_descriptor = descriptor
            descriptor = -1
            instance._initialize(
                path,
                owned_descriptor,
                expected=created,
                expected_path_identity=parent_identity
                + ((created.st_dev, created.st_ino),),
            )
            return instance
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            os.close(parent_descriptor)

    def _initialize(
        self,
        path: Path,
        descriptor: int,
        *,
        expected: os.stat_result | None = None,
        expected_path_identity: tuple[tuple[int, int], ...] | None = None,
    ) -> None:
        self.descriptor = descriptor
        self.path = path
        self.info = os.fstat(self.descriptor)
        # Use the runner's numeric PID rather than /proc/self: paths below this
        # directory are also passed to the separate sudo/docker client and the
        # local rootful daemon, whose /proc/self refers to a different process.
        self.bound_path = Path(f"/proc/{os.getpid()}/fd/{self.descriptor}")
        if (
            not stat.S_ISDIR(self.info.st_mode)
            or self.info.st_mode & 0o077
            or (
                expected is not None
                and (expected.st_dev, expected.st_ino)
                != (self.info.st_dev, self.info.st_ino)
            )
        ):
            self.close()
            fail("evidence directory binding is not a private directory")
        try:
            self.path_identity = self._snapshot_path(self.path)
            if (
                expected_path_identity is not None
                and self.path_identity != expected_path_identity
            ):
                fail("evidence directory ancestors changed during creation")
            parent = self.path.parent.lstat()
            current = self.path.lstat()
            self.parent_security = (
                parent.st_uid,
                parent.st_gid,
                stat.S_IMODE(parent.st_mode),
            )
            self.path_security = (
                current.st_uid,
                current.st_gid,
                stat.S_IMODE(current.st_mode),
            )
            if self.parent_security[2] & 0o077:
                fail("evidence directory parent must remain private")
            self.verify_path()
        except BaseException:
            self.close()
            raise

    def verify_path(self) -> None:
        try:
            bound = os.fstat(self.descriptor)
        except OSError as exc:
            fail(f"evidence directory identity cannot be revalidated: {type(exc).__name__}")
        try:
            current_identity = self._snapshot_path(self.path)
        except AuditFailure:
            fail("evidence directory identity changed during the audit")
        if (
            current_identity != self.path_identity
            or current_identity[-1] != (self.info.st_dev, self.info.st_ino)
            or (bound.st_dev, bound.st_ino) != (self.info.st_dev, self.info.st_ino)
        ):
            fail("evidence directory identity changed during the audit")
        try:
            parent = self.path.parent.lstat()
            current = self.path.lstat()
        except OSError:
            fail("evidence directory identity changed during the audit")
        if (
            (
                parent.st_uid,
                parent.st_gid,
                stat.S_IMODE(parent.st_mode),
            )
            != self.parent_security
            or (
                current.st_uid,
                current.st_gid,
                stat.S_IMODE(current.st_mode),
            )
            != self.path_security
            or current.st_mode & 0o077
        ):
            fail("evidence directory identity changed during the audit")

    def close(self) -> None:
        descriptor = getattr(self, "descriptor", -1)
        if descriptor >= 0:
            os.close(descriptor)
            self.descriptor = -1


def remove_owned_tree(path: Path) -> int:
    """Delete a run-created tree without following a replaced symlink."""

    try:
        info = path.lstat()
    except FileNotFoundError:
        return 0
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        fail(f"owned cleanup root identity changed: {path}")
    removed = 0
    with os.scandir(path) as entries:
        children = [Path(entry.path) for entry in entries]
    for child in children:
        child_info = child.lstat()
        if stat.S_ISDIR(child_info.st_mode) and not stat.S_ISLNK(child_info.st_mode):
            removed += remove_owned_tree(child)
        else:
            child.unlink()
            removed += 1
    path.rmdir()
    return removed


def remove_manifest_corpus(
    manifest: Mapping[str, Any],
    corpus_root: Path,
    bound_corpus: BoundCorpus | None = None,
) -> tuple[int, bool]:
    """Remove the validated flat acquisition files and retain only metadata."""

    owns_binding = bound_corpus is None
    try:
        if bound_corpus is None:
            require_private_directory(corpus_root, "acquisition root during cleanup")
            try:
                bound_corpus = BoundCorpus(
                    corpus_root,
                    manifest["filesystem_identity"],
                    "corpus cleanup",
                )
            except (ContractError, KeyError) as exc:
                raise CleanupFailure(
                    [f"directory_identity:{type(exc).__name__}"]
                ) from exc
        problems = bound_corpus.identity_problems()
        sources: dict[str, Mapping[str, Any]] = {}
        for case in manifest["semantic_cases"]:
            source = case["source"]
            sources.setdefault(source["corpus_file"], source)
        removed = 0
        for relative, source in sorted(sources.items()):
            was_removed, file_problems = bound_corpus.unlink_source(
                relative,
                source["text_bytes"],
                source["text_sha256"],
            )
            removed += int(was_removed)
            problems.extend(file_problems)
        problems.extend(bound_corpus.finish_cleanup())
        if problems:
            raise CleanupFailure(sorted(set(problems)))
        return removed, False
    finally:
        if owns_binding and bound_corpus is not None:
            bound_corpus.close()


def _process_environment() -> dict[str, str]:
    environment = os.environ.copy()
    environment.update(
        {
            "ALL_PROXY": "",
            "GIT_OPTIONAL_LOCKS": "0",
            "HTTPS_PROXY": "",
            "HTTP_PROXY": "",
            "all_proxy": "",
            "https_proxy": "",
            "http_proxy": "",
        }
    )
    return environment


def run_process(argv: Sequence[str], *, timeout: int = 60) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            list(argv),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
            env=_process_environment(),
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        fail(f"command failed without shell execution: {argv[0]}: {type(exc).__name__}")


def run_process_bytes(
    argv: Sequence[str],
    *,
    timeout: int,
    max_stdout_bytes: int,
    max_stderr_bytes: int,
) -> subprocess.CompletedProcess[bytes]:
    """Run a binary command without a shell and cap both captured streams."""

    if (
        not argv
        or timeout < 1
        or max_stdout_bytes < 1
        or max_stderr_bytes < 1
    ):
        fail("binary command limits are invalid")
    try:
        process = subprocess.Popen(
            list(argv),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=_process_environment(),
            start_new_session=os.name == "posix",
        )
    except OSError as exc:
        fail(f"binary command failed without shell execution: {argv[0]}: {type(exc).__name__}")
    if process.stdout is None or process.stderr is None:  # pragma: no cover - Popen contract
        fail("binary command pipes are unavailable")

    stdout_chunks: list[bytes] = []
    stderr_chunks: list[bytes] = []
    overflow = threading.Event()
    stream_errors: list[str] = []
    overflow_streams: list[str] = []

    def drain(
        stream: Any,
        limit: int,
        destination: list[bytes],
        label: str,
    ) -> None:
        total = 0
        try:
            while True:
                chunk = stream.read(min(64 * 1024, max(1, limit + 1 - total)))
                if not chunk:
                    return
                total += len(chunk)
                if total > limit:
                    overflow_streams.append(label)
                    overflow.set()
                    return
                destination.append(chunk)
        except OSError:
            stream_errors.append(label)
            overflow.set()
        finally:
            stream.close()

    readers = (
        threading.Thread(
            target=drain,
            args=(process.stdout, max_stdout_bytes, stdout_chunks, "stdout"),
            daemon=True,
        ),
        threading.Thread(
            target=drain,
            args=(process.stderr, max_stderr_bytes, stderr_chunks, "stderr"),
            daemon=True,
        ),
    )
    for reader in readers:
        reader.start()

    deadline = time.monotonic() + timeout
    timed_out = False
    while process.poll() is None:
        if overflow.wait(0.05):
            break
        if time.monotonic() >= deadline:
            timed_out = True
            break

    if process.poll() is None:
        try:
            if os.name == "posix":
                os.killpg(process.pid, signal.SIGTERM)
            else:  # pragma: no cover - the audit runner is Linux-only
                process.terminate()
            process.wait(timeout=2)
        except (OSError, ProcessLookupError, subprocess.TimeoutExpired):
            try:
                if os.name == "posix":
                    os.killpg(process.pid, signal.SIGKILL)
                else:  # pragma: no cover - the audit runner is Linux-only
                    process.kill()
            except (OSError, ProcessLookupError):
                pass
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                fail("binary command could not be terminated")

    for reader in readers:
        reader.join(timeout=2)
    if any(reader.is_alive() for reader in readers):
        fail("binary command pipe reader did not terminate")
    if timed_out:
        fail(f"binary command timed out without shell execution: {argv[0]}")
    if stream_errors:
        fail("binary command output could not be read")
    if overflow_streams:
        fail(f"binary command {sorted(set(overflow_streams))[0]} exceeded its byte limit")
    return subprocess.CompletedProcess(
        list(argv),
        int(process.returncode),
        b"".join(stdout_chunks),
        b"".join(stderr_chunks),
    )


class Docker:
    def __init__(self) -> None:
        if not hasattr(os, "geteuid"):
            fail("the isolated runner requires Linux")
        self.prefix = ["docker"] if os.geteuid() == 0 else ["sudo", "-n", "docker"]

    def run(
        self, args: Sequence[str], *, timeout: int = 60, check: bool = True
    ) -> subprocess.CompletedProcess[str]:
        result = run_process([*self.prefix, *args], timeout=timeout)
        if check and result.returncode != 0:
            operation = " ".join(args[:3])
            fail(
                f"docker {operation} failed rc={result.returncode}; "
                f"stderr_sha256={sha256_bytes(result.stderr.encode('utf-8'))}"
            )
        return result

    def run_binary(
        self,
        args: Sequence[str],
        *,
        timeout: int = 60,
        check: bool = True,
        max_stdout_bytes: int,
        max_stderr_bytes: int = 1024 * 1024,
    ) -> subprocess.CompletedProcess[bytes]:
        result = run_process_bytes(
            [*self.prefix, *args],
            timeout=timeout,
            max_stdout_bytes=max_stdout_bytes,
            max_stderr_bytes=max_stderr_bytes,
        )
        if check and result.returncode != 0:
            operation = " ".join(args[:3])
            fail(
                f"docker {operation} failed rc={result.returncode}; "
                f"stderr_sha256={sha256_bytes(result.stderr)}"
            )
        return result

    def inspect(self, kind: str, identity: str) -> dict[str, Any]:
        result = self.run([kind, "inspect", identity], timeout=30)
        try:
            value = json.loads(result.stdout)
        except json.JSONDecodeError:
            fail(f"docker {kind} inspect returned invalid JSON")
        if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
            fail(f"docker {kind} inspect returned an unexpected shape")
        return value[0]

    def absent(self, kind: str, name: str) -> bool:
        result = self.run([kind, "inspect", name], timeout=30, check=False)
        if result.returncode == 0:
            return False
        diagnostic = (result.stdout + result.stderr).lower()
        if "no such" in diagnostic or "not found" in diagnostic:
            return True
        fail(
            f"docker {kind} absence check failed rc={result.returncode}; "
            f"diagnostic_sha256={sha256_bytes(diagnostic.encode('utf-8'))}"
        )


def git_identity(repository: Path) -> tuple[str, str]:
    try:
        info = repository.lstat()
    except FileNotFoundError:
        fail("CAG source repository is missing")
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        fail("CAG source repository must be a real directory")
    git = ["git", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null"]
    head = run_process([*git, "-C", str(repository), "rev-parse", "HEAD^{commit}"], timeout=30)
    tree = run_process([*git, "-C", str(repository), "rev-parse", "HEAD^{tree}"], timeout=30)
    if head.returncode or tree.returncode:
        fail("CAG Git source identity could not be read")
    commit = head.stdout.strip().lower()
    tree_id = tree.stdout.strip().lower()
    if re.fullmatch(r"[0-9a-f]{40}", commit) is None or re.fullmatch(r"[0-9a-f]{40}", tree_id) is None:
        fail("CAG Git source identity is invalid")
    return commit, tree_id


def require_git_tracked_clean(repository: Path) -> None:
    status = run_process(
        [
            "git",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.hooksPath=/dev/null",
            "-C",
            str(repository),
            "status",
            "--porcelain=v1",
            "--untracked-files=no",
        ],
        timeout=30,
    )
    if status.returncode != 0 or status.stdout:
        fail("CAG source repository has tracked working-tree drift")


class RejectRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        del args, kwargs
        fail("isolated HTTP endpoint attempted a redirect")


HTTP_OPENER = build_opener(ProxyHandler({}), RejectRedirect())


def internal_base(host: str, port: int) -> str:
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        fail("container address is not an IP literal")
    private_networks = (
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
    )
    if address.version != 4 or not any(address in network for network in private_networks):
        fail("container address is outside the private Docker bridge")
    return f"http://{address.compressed}:{port}"


def http_request(
    base: str,
    method: str,
    path: str,
    body: bytes | None = None,
    headers: Mapping[str, str] | None = None,
    timeout: float = 45.0,
) -> tuple[int, bytes, dict[str, str], float]:
    parts = urlsplit(base)
    if (
        parts.scheme != "http"
        or parts.hostname is None
        or parts.username
        or parts.password
        or parts.query
        or parts.fragment
        or not path.startswith("/")
        or "\\" in path
    ):
        fail("isolated HTTP target is invalid")
    try:
        resolved = socket.gethostbyname(parts.hostname)
    except OSError:
        fail("isolated HTTP target did not resolve")
    internal_base(resolved, parts.port or 80)
    if body is not None and len(body) > MAX_REQUEST_BYTES:
        fail("isolated request exceeds the byte limit")
    request_headers = {
        "Accept": "application/json",
        "User-Agent": "cag-current-cpa-audit-runner/1",
    }
    if headers:
        request_headers.update(headers)
    if body is not None:
        request_headers.setdefault("Content-Type", "application/json")
    request = Request(base + path, data=body, method=method, headers=request_headers)
    started = time.perf_counter_ns()
    try:
        with HTTP_OPENER.open(request, timeout=timeout) as response:
            raw = response.read(MAX_RESPONSE_BYTES + 1)
            status = int(response.status)
            response_headers = {key.lower(): value for key, value in response.headers.items()}
    except HTTPError as exc:
        raw = exc.read(MAX_RESPONSE_BYTES + 1)
        status = int(exc.code)
        response_headers = {key.lower(): value for key, value in exc.headers.items()}
    except (URLError, TimeoutError, OSError) as exc:
        fail(f"isolated HTTP request failed: {method} {path}: {type(exc).__name__}")
    latency_ms = (time.perf_counter_ns() - started) / 1_000_000
    if len(raw) > MAX_RESPONSE_BYTES:
        fail("isolated HTTP response exceeds the byte limit")
    return status, raw, response_headers, latency_ms


def http_json(
    base: str,
    method: str,
    path: str,
    body: Any = None,
    headers: Mapping[str, str] | None = None,
    expected: int = 200,
) -> tuple[Any, dict[str, str], float]:
    raw_body = None if body is None else canonical_bytes(body)
    status, raw, response_headers, latency = http_request(
        base, method, path, raw_body, headers
    )
    if status != expected:
        fail(
            f"{method} {path} returned {status}, expected {expected}; "
            f"body_sha256={sha256_bytes(raw)}"
        )
    try:
        value = json.loads(raw.decode("utf-8", "strict"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        fail(f"{method} {path} returned invalid JSON")
    return value, response_headers, latency


def image_identity(docker: Docker, expected: Mapping[str, Any], role: str) -> dict[str, Any]:
    info = docker.inspect("image", str(expected["image_ref"]))
    digests = info.get("RepoDigests") or []
    if (
        info.get("Id") != expected["image_id"]
        or info.get("Architecture") != "amd64"
        or info.get("Os") != "linux"
        or expected["repo_digest"] not in digests
    ):
        fail(f"{role} image ID, platform, or RepoDigest is invalid")
    labels = (info.get("Config") or {}).get("Labels") or {}
    if role == "cpa":
        version = str(labels.get("org.opencontainers.image.version", ""))
        revision = str(labels.get("org.opencontainers.image.revision", "")).lower()
        if version.lstrip("v") != str(expected["tag"]).lstrip("v") or revision != expected["commit"]:
            fail(f"CPA image labels do not bind {CPA_TAG}")
    else:
        if (
            labels.get("io.cyber-abuse-guard.mock-contract") != MOCK_CONTRACT
            or labels.get("io.cyber-abuse-guard.mock-source-sha256")
            != expected["source_sha256"]
        ):
            fail("counted-Mock image labels do not bind its source contract")
        image_config = info.get("Config") or {}
        if (
            image_config.get("Entrypoint") != MOCK_ENTRYPOINT
            or image_config.get("Cmd") not in (None, [])
        ):
            fail("counted-Mock image entrypoint does not execute the reviewed source")
    return info


def container_ip(docker: Docker, name: str, network_name: str) -> str:
    info = docker.inspect("container", name)
    networks = ((info.get("NetworkSettings") or {}).get("Networks") or {})
    if set(networks) != {network_name}:
        fail(f"container {name} escaped the single audit network")
    address = (networks[network_name] or {}).get("IPAddress")
    if not isinstance(address, str):
        fail(f"container {name} has no network address")
    internal_base(address, 1)
    return address


def business_snapshot(docker: Docker, run_id: str) -> list[dict[str, Any]]:
    result = docker.run(["ps", "-aq", "--no-trunc"], timeout=30)
    snapshot: list[dict[str, Any]] = []
    for container_id in sorted(result.stdout.split()):
        info = docker.inspect("container", container_id)
        labels = (info.get("Config") or {}).get("Labels") or {}
        if labels.get(LABEL_KEY) == run_id:
            continue
        state = info.get("State") or {}
        snapshot.append(
            {
                "id": str(info.get("Id", "")),
                "image_id": str(info.get("Image", "")),
                "name": str(info.get("Name", "")).lstrip("/"),
                "oom_killed": state.get("OOMKilled") is True,
                "restart_count": int(info.get("RestartCount") or 0),
                "running": state.get("Running") is True,
                "status": str(state.get("Status", "unknown")),
            }
        )
    return snapshot


def plugin_config(mode: str) -> dict[str, Any]:
    if mode not in MODES:
        fail(f"unsupported CAG mode: {mode}")
    return {
        "audit": {
            "data_dir": "/cag/audit",
            "enabled": True,
            "log_category": True,
            "log_original_text": False,
            "log_request_hash": True,
            "log_rule_ids": True,
            "log_subject_hash": True,
            "max_db_mb": 64,
            "persist_wrapper_only": False,
            "raw_capture": {
                "enabled": False,
                "max_bytes": 8192,
                "only_blocked": True,
                "redact_secrets": True,
                "ttl_hours": 72,
            },
            "require_persistent_storage": True,
            "retention_days": 30,
        },
        "classifier": {
            "enabled": False,
            "endpoint": "",
            "fail_mode": "rules_only",
            "timeout_ms": 300,
        },
        "enabled": True,
        "max_json_depth": 32,
        "max_scan_bytes": 262144,
        "max_text_parts": 512,
        "max_total_text_bytes": 8388608,
        "mode": mode,
        "opaque_media_policy": "audit",
        "priority": 300,
        "subject_control": {"enabled": False},
    }


def cpa_yaml(
    mode: str, client_key: str, management_key: str, upstream_key: str
) -> bytes:
    lines = [
        'host: "0.0.0.0"',
        f"port: {CPA_PORT}",
        'auth-dir: "/cag/auth"',
        "api-keys:",
        f"  - {json.dumps(client_key)}",
        "remote-management:",
        "  allow-remote: true",
        f"  secret-key: {json.dumps(management_key)}",
        "  disable-control-panel: true",
        "usage-statistics-enabled: true",
        "commercial-mode: true",
        "request-log: false",
        "logging-to-file: false",
        "debug: false",
        "plugins:",
        "  enabled: true",
        '  dir: "/cag/plugins"',
        "  configs:",
        "    cyber-abuse-guard:",
    ]
    lines.extend(
        "      " + line
        for line in json.dumps(plugin_config(mode), ensure_ascii=True, indent=2).splitlines()
    )
    lines.extend(
        [
            "openai-compatibility:",
            "  - name: current-cpa-counted-mock",
            '    base-url: "http://mock:18080/v1"',
            "    api-key-entries:",
            f"      - api-key: {json.dumps(upstream_key)}",
            "    models:",
            f"      - name: {MODEL}",
            f"        alias: {MODEL}",
        ]
    )
    return ("\n".join(lines) + "\n").encode("utf-8")


def runner_identities() -> dict[str, str]:
    file_hashes: dict[str, str] = {}
    for name in RUNNER_BUNDLE_FILES:
        path = TOOL_DIR / name
        regular_file_info(path, f"runner bundle file {name}")
        file_hashes[name] = sha256_file(path, 16 * 1024 * 1024)
    return {
        "audit_contract_sha256": file_hashes["audit_contract.py"],
        "bundle_sha256": sha256_bytes(canonical_bytes(file_hashes)),
        "machine_schema_sha256": file_hashes["machine-evidence.schema.json"],
        "mock_source_sha256": file_hashes["counted_mock.py"],
        "policy_sha256": file_hashes["repository-policy.json"],
        "run_source_sha256": file_hashes["run.py"],
    }


class CleanupTracker:
    def __init__(self, docker: Docker, run_id: str, cpa_name: str, mock_name: str, network: str) -> None:
        self.docker = docker
        self.run_id = run_id
        self.cpa_name = cpa_name
        self.mock_name = mock_name
        self.network = network
        self.resources: list[dict[str, Any]] = []
        self.graceful_stop_attempts = 0
        self.checkpoint_attempts = 0
        self.text_files_removed = 0
        self.text_retained = True

    def _label(self, kind: str, name: str) -> str:
        info = self.docker.inspect(kind, name)
        if kind == "container":
            labels = (info.get("Config") or {}).get("Labels") or {}
        else:
            labels = info.get("Labels") or {}
        observed = str(labels.get(LABEL_KEY, ""))
        if observed != self.run_id:
            fail(f"refusing cleanup of {kind} {name}: run label mismatch")
        return observed

    def stop(self, name: str) -> bool:
        if self.docker.absent("container", name):
            return False
        self._label("container", name)
        self.graceful_stop_attempts += 1
        result = self.docker.run(["stop", "--time", "20", name], timeout=30, check=False)
        return result.returncode == 0

    def remove_container(self, name: str) -> None:
        observed = self._label("container", name)
        info = self.docker.inspect("container", name)
        if (info.get("State") or {}).get("Running") is True:
            fail(f"refusing to remove running container {name}")
        self.docker.run(["rm", name], timeout=30)
        self.resources.append(
            {
                "action": "removed",
                "expected_label": self.run_id,
                "kind": "container",
                "name": name,
                "observed_label": observed,
            }
        )

    def remove_network(self) -> None:
        observed = self._label("network", self.network)
        info = self.docker.inspect("network", self.network)
        if info.get("Containers") not in ({}, None):
            fail("refusing to remove a non-empty audit network")
        self.docker.run(["network", "rm", self.network], timeout=30)
        self.resources.append(
            {
                "action": "removed",
                "expected_label": self.run_id,
                "kind": "network",
                "name": self.network,
                "observed_label": observed,
            }
        )

    def emergency(self) -> None:
        errors: list[str] = []
        for name in (self.cpa_name, self.mock_name):
            try:
                absent = self.docker.absent("container", name)
            except BaseException as exc:
                errors.append(f"inspect:{name}:{type(exc).__name__}")
                continue
            if absent:
                continue
            try:
                if not self.stop(name):
                    errors.append(f"stop:{name}:failed")
            except BaseException as exc:
                errors.append(f"stop:{name}:{type(exc).__name__}")
            try:
                if not self.docker.absent("container", name):
                    self.remove_container(name)
            except BaseException as exc:
                errors.append(f"remove:{name}:{type(exc).__name__}")
        try:
            network_present = not self.docker.absent("network", self.network)
        except BaseException as exc:
            errors.append(f"inspect:{self.network}:{type(exc).__name__}")
            network_present = False
        if network_present:
            try:
                self.remove_network()
            except BaseException as exc:
                errors.append(f"remove:{self.network}:{type(exc).__name__}")
        for kind, name in (
            ("container", self.cpa_name),
            ("container", self.mock_name),
            ("network", self.network),
        ):
            try:
                if not self.docker.absent(kind, name):
                    errors.append(f"residual:{kind}:{name}")
            except BaseException as exc:
                errors.append(f"verify:{kind}:{name}:{type(exc).__name__}")
        if errors:
            raise CleanupFailure(errors)


class Harness:
    def __init__(
        self,
        config: dict[str, Any],
        config_raw: bytes,
        manifest: dict[str, Any],
        manifest_raw: bytes,
        evidence_binding: BoundEvidenceDirectory,
        docker: Docker,
    ) -> None:
        self.config = config
        self.config_raw = config_raw
        self.manifest = manifest
        self.manifest_raw = manifest_raw
        self.evidence_binding = evidence_binding
        self.evidence_dir = evidence_binding.bound_path
        self.host_evidence_dir = evidence_binding.path
        self.docker = docker
        self.run_id = config["run"]["run_id"]
        self.cold_count = config["run"]["cold_start_count"]
        self.seed = config["run"]["seed"]
        self.cpa_name = f"{self.run_id}-cpa"
        self.mock_name = f"{self.run_id}-mock"
        self.network_name = f"{self.run_id}-net"
        self.results_path = self.evidence_dir / "transport-results.jsonl"
        self.supplemental_results_path = (
            self.evidence_dir / "supplemental-zip-results.jsonl"
        )
        self.runtime_root = self.evidence_dir / ".runtime"
        self.corpus_root = Path(config["paths"]["corpus_manifest"]).parent
        self.cases = {case["id"]: case for case in manifest["semantic_cases"]}
        self.plan = build_execution_plan(manifest, self.seed, self.cold_count)
        self.supplemental_manifest: dict[str, Any] | None = None
        self.supplemental_manifest_raw = b""
        self.supplemental_policy: dict[str, Any] | None = None
        self.supplemental_policy_raw = b""
        self.supplemental_cases: dict[str, dict[str, Any]] = {}
        self.supplemental_plan: list[Any] = []
        self.supplemental_texts: dict[str, bytearray] = {}
        self.supplemental_texts_zeroized = False
        self.supplemental_archive_identity: tuple[int, int, int, int] | None = None
        self.supplemental_archive_preserved = False
        self.cleanup = CleanupTracker(
            docker, self.run_id, self.cpa_name, self.mock_name, self.network_name
        )
        self.results_handle: Any = None
        self.supplemental_results_handle: Any = None
        self.results_count = 0
        self.supplemental_results_count = 0
        self.supplemental_action_counts = {
            "allow": 0,
            "block_incomplete_inspection": 0,
            "block_malicious_text": 0,
            "transport_error": 0,
        }
        self.cold_evidence: list[dict[str, Any]] = []
        self.realtime_evidence: list[dict[str, Any]] = []
        self.runtime_hashes: list[str] = []
        self.runner_identity: dict[str, str] = {}
        self.cag_pre: tuple[str, str] = ("", "")
        self.mock_url = ""
        self.cpa_url = ""
        self.client_key = ""
        self.management_key = ""
        self.upstream_key = ""
        self.control_token = ""
        self.last_event_id = ""
        self.binary_verified = False
        self.bound_corpus: BoundCorpus | None = None
        self.corpus_cleanup_completed = False
        self.corpus_validated = False
        self.active_auth_dir: Path | None = None
        self.failure_stage = "initialization"
        self.readiness_state_sha256: str | None = None
        self.active_cpa_mounts: dict[
            str, tuple[Path, Path, bool, tuple[tuple[int, int], ...]]
        ] = {}
        # The lazy-read recorder is created before static verification so the
        # BoundCorpus observer can prove the preflight/transport phase edge.
        # It receives only path/size/digest metadata; source bytes remain
        # caller-owned and are never passed to the evidence producer.
        self.lazy_read: LazyReadRecorder | None = None
        self._lazy_observe_mode: str | None = "preflight"
        self._pending_bound_read: tuple[str, int, str] | None = None
        self._source_case_identity: dict[str, str] = {}
        for semantic_case in self.manifest["semantic_cases"]:
            source_path = semantic_case["source"]["corpus_file"]
            self._source_case_identity.setdefault(source_path, semantic_case["id"])
        self.lazy_read_finalized = False
        self.csam_text_validated = False

    @property
    def management_headers(self) -> dict[str, str]:
        return {"Authorization": "Bearer " + self.management_key}

    @property
    def client_headers(self) -> dict[str, str]:
        return {"Authorization": "Bearer " + self.client_key}

    @property
    def control_headers(self) -> dict[str, str]:
        return {"Authorization": "Bearer " + self.control_token}

    @property
    def supplemental_member_text_retained(self) -> bool:
        return not self.supplemental_texts_zeroized

    @staticmethod
    def supplemental_archive_stat_identity(info: os.stat_result) -> tuple[int, int, int, int]:
        return (info.st_dev, info.st_ino, info.st_nlink, info.st_size)

    def verify_supplemental_archive_identity(self) -> None:
        if self.supplemental_archive_identity is None:
            fail("supplemental ZIP archive was not bound before verification")
        archive_path = Path(self.config["paths"]["supplemental_zip"])
        info = regular_file_info(
            archive_path, "supplemental ZIP archive", require_single_link=True
        )
        if self.supplemental_archive_stat_identity(info) != self.supplemental_archive_identity:
            fail("supplemental ZIP archive inode, link count, size, or device drifted")
        if sha256_file(
            archive_path,
            self.config["supplemental_zip"]["archive_bytes"],
            require_single_link=True,
        ) != self.config["supplemental_zip"]["archive_sha256"]:
            fail("supplemental ZIP archive SHA-256 drifted")

    def bind_supplemental_inputs(self) -> None:
        (
            supplemental_manifest,
            supplemental_manifest_raw,
            supplemental_policy,
            supplemental_policy_raw,
            archive_info,
        ) = validate_supplemental_run_config_files(self.config)
        self.supplemental_manifest = supplemental_manifest
        self.supplemental_manifest_raw = supplemental_manifest_raw
        self.supplemental_policy = supplemental_policy
        self.supplemental_policy_raw = supplemental_policy_raw
        self.supplemental_cases = {
            case["id"]: case for case in supplemental_manifest["reviewed_cases"]
        }
        self.supplemental_plan = build_supplemental_execution_plan(
            supplemental_manifest, self.seed, self.cold_count
        )
        self.supplemental_archive_identity = self.supplemental_archive_stat_identity(
            archive_info
        )
        self.supplemental_texts = load_selected_supplemental_texts(
            Path(self.config["paths"]["supplemental_zip"]),
            supplemental_policy,
            supplemental_manifest,
            policy_sha256=sha256_bytes(supplemental_policy_raw),
        )
        for case_id, case in self.supplemental_cases.items():
            source = case["source"]
            raw = self.supplemental_texts.get(source["entry_id"])
            if (
                raw is None
                or len(raw) != source["text_bytes"]
                or sha256_bytes(raw) != source["normalized_text_sha256"]
            ):
                fail(f"supplemental ZIP selected text identity changed: {case_id}")
        self.verify_supplemental_archive_identity()

    def verify_static_inputs(self) -> None:
        validate_candidate_manifest_file(self.config)
        require_private_directory(self.corpus_root, "acquisition root")
        require_private_directory(self.corpus_root / "corpus", "private corpus directory")
        manifest_path = Path(self.config["paths"]["corpus_manifest"])
        if manifest_path.parent != self.corpus_root:
            fail("corpus manifest path resolution drifted")
        validate_corpus_manifest(self.manifest)
        if getattr(self, "lazy_read", None) is None:
            fail("lazy-read recorder is unavailable during static verification")
        self.bound_corpus = BoundCorpus(
            self.corpus_root,
            self.manifest["filesystem_identity"],
            "runner corpus",
            read_observer=self._bound_read_observer,
        )
        self.bound_corpus.verify_manifest_files(self.manifest)
        self.corpus_validated = True
        if sha256_bytes(self.manifest_raw) != self.config["corpus_manifest_sha256"]:
            fail("corpus manifest does not match the run-config digest")
        machine = platform.machine().lower()
        if platform.system() != "Linux" or machine not in {"amd64", "x86_64"}:
            fail("the isolated runner requires linux/amd64")
        if os.getuid() == 0 or os.getgid() == 0:
            fail("run the audit as a dedicated non-root user with passwordless sudo for Docker")
        if self.config["run"]["platform"] != "linux/amd64":
            fail("run configuration platform drifted")

        self.runner_identity = runner_identities()
        if (
            self.runner_identity["policy_sha256"] != self.config["policy_sha256"]
            or self.manifest["policy_sha256"] != self.config["policy_sha256"]
        ):
            fail("source policy identity is not closed across config, tool, and corpus")
        policy_raw = read_regular_bytes(POLICY_PATH, "fixed source policy", 2 * 1024 * 1024)
        policy = validate_policy(
            load_json_bytes(policy_raw, "fixed source policy"), require_approved=True
        )
        validate_manifest_policy(self.manifest, policy, require_approved=True)
        self.bind_supplemental_inputs()
        mock_source = Path(self.config["paths"]["mock_source"])
        if mock_source.resolve(strict=True) != (TOOL_DIR / "counted_mock.py").resolve(strict=True):
            fail("run config selected a different counted-Mock source")
        if self.runner_identity["mock_source_sha256"] != self.config["identities"]["mock"]["source_sha256"]:
            fail("counted-Mock source SHA drifted")

        seen_files: set[str] = set()
        for case in self.manifest["semantic_cases"]:
            relative = case["source"]["corpus_file"]
            if relative in seen_files:
                continue
            seen_files.add(relative)
            path = self.corpus_root / relative
            info = regular_file_info(
                path, f"corpus text {relative}", require_single_link=True
            )
            if os.name == "posix" and info.st_mode & 0o077:
                fail(f"corpus text is not mode-0600 or stricter: {relative}")

        cag = self.config["identities"]["cag"]
        cag_repository = Path(self.config["paths"]["cag_repository"])
        self.cag_pre = git_identity(cag_repository)
        require_git_tracked_clean(cag_repository)
        if self.cag_pre != (cag["commit"], cag["tree"]):
            fail("CAG source commit/tree does not match run config")
        cag_so = Path(self.config["paths"]["cag_so"])
        if sha256_file(cag_so, require_single_link=True) != cag["so_sha256"]:
            fail("CAG shared object SHA drifted")

        cpa = self.config["identities"]["cpa"]
        asset = Path(self.config["paths"]["cpa_official_asset"])
        asset_info = regular_file_info(asset, "CPA official release asset")
        if (
            asset.name != cpa["official_asset_name"]
            or asset_info.st_size != CPA_OFFICIAL_ASSET_SIZE
            or sha256_file(asset) != cpa["official_asset_sha256"]
        ):
            fail("CPA official release asset identity drifted")
        image_identity(self.docker, cpa, "cpa")
        image_identity(self.docker, self.config["identities"]["mock"], "mock")

        for kind, name in (
            ("container", self.cpa_name),
            ("container", self.mock_name),
            ("network", self.network_name),
        ):
            if not self.docker.absent(kind, name):
                fail(f"pre-existing audit resource name refused: {kind} {name}")
        self.verify_mock_image_source()
        # Static verification is the only phase allowed to inspect every
        # source.  Start transport only after every identity/image gate has
        # passed, so a partial preflight can never publish a PASS boundary.
        try:
            self.lazy_read.start_transport()
        except LazyReadError as exc:
            fail(str(exc))
        self._lazy_observe_mode = "transport"

    def verify_mock_image_source(self) -> None:
        """Copy and hash the stopped image payload before any Mock code runs."""

        mock = self.config["identities"]["mock"]
        extraction = Path(
            tempfile.mkdtemp(prefix="mock-source-verify-", dir=self.evidence_dir)
        )
        os.chmod(extraction, 0o700)
        target = extraction / "counted_mock.py"
        created = False
        try:
            self.docker.run(
                [
                    "create",
                    "--pull",
                    "never",
                    "--name",
                    self.mock_name,
                    "--network",
                    "none",
                    "--label",
                    f"{LABEL_KEY}={self.run_id}",
                    "--label",
                    f"{ROLE_LABEL}=mock-source-verifier",
                    "--entrypoint",
                    "/bin/false",
                    mock["image_ref"],
                ],
                timeout=60,
            )
            created = True
            container = self.docker.inspect("container", self.mock_name)
            labels = (container.get("Config") or {}).get("Labels") or {}
            if (
                container.get("Image") != mock["image_id"]
                or (container.get("State") or {}).get("Running") is not False
                or (container.get("HostConfig") or {}).get("NetworkMode") != "none"
                or labels.get(LABEL_KEY) != self.run_id
                or labels.get(ROLE_LABEL) != "mock-source-verifier"
            ):
                fail("counted-Mock source verifier container identity is invalid")
            self.docker.run(
                ["cp", f"{self.mock_name}:{MOCK_SOURCE_PATH}", str(target)],
                timeout=60,
            )
            regular_file_info(
                target, "counted-Mock image source", require_single_link=True
            )
            if sha256_file(target) != mock["source_sha256"]:
                fail("counted-Mock source inside the selected image has the wrong SHA")
        finally:
            try:
                if created and not self.docker.absent("container", self.mock_name):
                    container = self.docker.inspect("container", self.mock_name)
                    labels = (container.get("Config") or {}).get("Labels") or {}
                    if (
                        labels.get(LABEL_KEY) != self.run_id
                        or labels.get(ROLE_LABEL) != "mock-source-verifier"
                        or (container.get("State") or {}).get("Running") is not False
                    ):
                        fail("refusing cleanup of an unbound Mock source verifier")
                    self.docker.run(["rm", self.mock_name], timeout=30)
                    if not self.docker.absent("container", self.mock_name):
                        fail("counted-Mock source verifier removal was not confirmed")
            finally:
                remove_owned_tree(extraction)

    def create_network(self) -> None:
        self.docker.run(
            [
                "network",
                "create",
                "--driver",
                "bridge",
                "--internal",
                "--label",
                f"{LABEL_KEY}={self.run_id}",
                self.network_name,
            ],
            timeout=30,
        )
        info = self.docker.inspect("network", self.network_name)
        if (
            info.get("Driver") != "bridge"
            or info.get("Internal") is not True
            or info.get("Attachable") is True
            or info.get("Ingress") is True
            or (info.get("Labels") or {}).get(LABEL_KEY) != self.run_id
        ):
            fail("audit network isolation contract failed")

    def common_container_args(self, role: str, name: str) -> list[str]:
        memory = "128m" if role == "mock" else "768m"
        cpus = "0.5" if role == "mock" else "1.0"
        return [
            "run",
            "--detach",
            "--pull",
            "never",
            "--name",
            name,
            "--hostname",
            role,
            "--network",
            self.network_name,
            "--network-alias",
            role,
            "--restart",
            "no",
            "--user",
            f"{os.getuid()}:{os.getgid()}",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            "--pids-limit",
            "256",
            "--cpus",
            cpus,
            "--memory",
            memory,
            "--memory-swap",
            memory,
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
            f"{LABEL_KEY}={self.run_id}",
            "--label",
            f"{ROLE_LABEL}={role}",
        ]

    def prepare_cold_runtime(self, cold_start: int, initial_mode: str) -> tuple[Path, str]:
        cold_root = self.runtime_root / f"cold-{cold_start}"
        plugin_dir = cold_root / "plugins" / "linux" / "amd64"
        config_dir = cold_root / "config"
        auth_dir = cold_root / "auth"
        audit_dir = cold_root / "audit"
        secret_dir = cold_root / "secrets"
        for directory in (
            cold_root,
            cold_root / "plugins",
            cold_root / "plugins" / "linux",
            plugin_dir,
            config_dir,
            auth_dir,
            audit_dir,
            secret_dir,
        ):
            directory.mkdir(parents=True, mode=0o700)
            os.chmod(directory, 0o700)
        cag_so = Path(self.config["paths"]["cag_so"])
        target_so = plugin_dir / cag_so.name
        shutil.copyfile(cag_so, target_so)
        os.chmod(target_so, 0o500)
        if sha256_file(target_so) != self.config["identities"]["cag"]["so_sha256"]:
            fail("runtime CAG copy SHA drifted")

        self.client_key = secrets.token_urlsafe(48)
        self.management_key = secrets.token_urlsafe(48)
        self.upstream_key = secrets.token_urlsafe(48)
        self.control_token = secrets.token_urlsafe(48)
        if len({self.client_key, self.management_key, self.upstream_key, self.control_token}) != 4:
            fail("run-random token generation collided")
        hmac_key = secrets.token_bytes(48)
        hmac_path = secret_dir / "hmac.key"
        write_exclusive(hmac_path, hmac_key)
        yaml_bytes = cpa_yaml(
            initial_mode, self.client_key, self.management_key, self.upstream_key
        )
        write_exclusive(config_dir / "config.yaml", yaml_bytes)
        identity = {
            "hmac_sha256": sha256_bytes(hmac_key),
            "mode_config_sha256s": {
                mode: sha256_bytes(canonical_bytes(plugin_config(mode))) for mode in MODES
            },
            "token_sha256s": sorted(
                sha256_bytes(token.encode("utf-8"))
                for token in (
                    self.client_key,
                    self.management_key,
                    self.upstream_key,
                    self.control_token,
                )
            ),
            "yaml_sha256": sha256_bytes(yaml_bytes),
        }
        runtime_hash = sha256_bytes(canonical_bytes(identity))
        self.active_auth_dir = auth_dir
        return cold_root, runtime_hash

    def docker_bind_source(
        self,
        bound_source: Path,
        *,
        expected_identity: tuple[tuple[int, int], ...] | None = None,
    ) -> tuple[Path, tuple[tuple[int, int], ...]]:
        """Map one descriptor-bound directory to its verified normal host path.

        Docker/runc cannot use proc-fd magic links as bind-mount sources.  Local
        writes stay below ``self.evidence_dir`` while the daemon receives the
        corresponding normal path only after every component has been checked
        to name the same real directory inode.  The dedicated-UID operator
        contract excludes a hostile same-UID process during this handoff.
        """

        if (
            self.evidence_dir != self.evidence_binding.bound_path
            or self.host_evidence_dir != self.evidence_binding.path
        ):
            fail("Docker bind source binding contract is inconsistent")
        self.evidence_binding.verify_path()
        try:
            relative = bound_source.relative_to(self.evidence_dir)
        except ValueError:
            fail("Docker bind source is outside the bound evidence directory")
        if not relative.parts or any(part in {"", ".", ".."} for part in relative.parts):
            fail("Docker bind source has an unsafe relative path")

        bound_cursor = self.evidence_dir
        host_cursor = self.host_evidence_dir
        identity: list[tuple[int, int]] = []
        for part in (None, *relative.parts):
            if part is not None:
                bound_cursor /= part
                host_cursor /= part
            try:
                bound_info = bound_cursor.stat()
                host_info = host_cursor.lstat()
            except OSError as exc:
                fail(f"Docker bind source cannot be verified: {type(exc).__name__}")
            if (
                stat.S_ISLNK(host_info.st_mode)
                or not stat.S_ISDIR(host_info.st_mode)
                or not stat.S_ISDIR(bound_info.st_mode)
                or (bound_info.st_dev, bound_info.st_ino)
                != (host_info.st_dev, host_info.st_ino)
                or (os.name == "posix" and host_info.st_mode & 0o077)
            ):
                fail("Docker bind source is not the descriptor-bound private directory")
            identity.append((host_info.st_dev, host_info.st_ino))
        captured = tuple(identity)
        if expected_identity is not None and captured != expected_identity:
            fail("Docker bind source identity changed after daemon handoff")
        return host_cursor, captured

    def cpa_bind_mount_args(self, cold_root: Path) -> list[str]:
        specifications = (
            (cold_root / "plugins", "/cag/plugins", True),
            # CPA persists the replacement plugin object before applying its
            # asynchronous hot reload. This bind is an isolated, per-cold-
            # start directory below the descriptor-bound evidence root; a
            # read-only bind makes every mode transition fail with HTTP 500.
            (cold_root / "config", "/cag/config", False),
            (cold_root / "auth", "/cag/auth", False),
            (cold_root / "audit", "/cag/audit", False),
            (cold_root / "secrets", "/cag/secrets", True),
        )
        arguments: list[str] = []
        self.active_cpa_mounts = {}
        for bound_source, destination, read_only in specifications:
            host_source, identity = self.docker_bind_source(bound_source)
            self.active_cpa_mounts[destination] = (
                bound_source,
                host_source,
                read_only,
                identity,
            )
            value = f"type=bind,src={host_source},dst={destination}"
            if read_only:
                value += ",readonly"
            arguments.extend(["--mount", value])
        return arguments

    @staticmethod
    def verify_tmpfs_contract(host_config: Mapping[str, Any]) -> None:
        tmpfs = host_config.get("Tmpfs")
        if not isinstance(tmpfs, dict) or set(tmpfs) != {"/tmp"}:
            fail("container tmpfs destination set is not closed")
        options = [value for value in str(tmpfs["/tmp"]).split(",") if value]
        expected = {"rw", "noexec", "nosuid", "nodev", "size=64m"}
        if len(options) != len(expected) or set(options) != expected:
            fail("container tmpfs access or size contract drifted")

    def verify_cpa_bind_mounts(self) -> None:
        if set(self.active_cpa_mounts) != {
            "/cag/plugins",
            "/cag/config",
            "/cag/auth",
            "/cag/audit",
            "/cag/secrets",
        }:
            fail("CPA bind-mount contract is incomplete")
        info = self.docker.inspect("container", self.cpa_name)
        host_config = info.get("HostConfig") or {}
        if not isinstance(host_config, dict):
            fail("CPA bind-mount inspection is invalid")
        self.verify_tmpfs_contract(host_config)
        mounts = info.get("Mounts")
        if not isinstance(mounts, list):
            fail("CPA bind-mount inspection is invalid")
        observed: dict[str, Mapping[str, Any]] = {}
        # HostConfig.Tmpfs is the authoritative closed tmpfs contract. Docker
        # versions differ on whether that tmpfs is repeated in Mounts, so allow
        # it to be absent there or present once with the same destination/RW.
        observed_tmpfs = 0
        for item in mounts:
            if not isinstance(item, dict):
                fail("CPA bind-mount inspection is invalid")
            if item.get("Type") != "bind":
                if not (
                    item.get("Type") == "tmpfs"
                    and item.get("Destination") == "/tmp"
                    and item.get("RW") is True
                    and observed_tmpfs == 0
                ):
                    fail("CPA container has an unexpected non-bind mount")
                observed_tmpfs += 1
                continue
            destination = str(item.get("Destination", ""))
            if destination in observed:
                fail("CPA bind-mount destinations are not unique")
            observed[destination] = item
        if set(observed) != set(self.active_cpa_mounts):
            fail("CPA bind-mount destination set is not closed")
        for destination, (bound_source, expected_host, read_only, identity) in (
            self.active_cpa_mounts.items()
        ):
            current_host, _ = self.docker_bind_source(
                bound_source, expected_identity=identity
            )
            item = observed[destination]
            if (
                current_host != expected_host
                or item.get("Type") != "bind"
                or item.get("Source") != str(current_host)
                or item.get("RW") is not (not read_only)
                or item.get("Propagation") != "rprivate"
            ):
                fail("CPA bind-mount source, identity, or access mode drifted")

    def verify_runtime_config_storage(self) -> None:
        record = self.active_cpa_mounts.get("/cag/config")
        if record is None or record[2] is not False:
            fail("isolated CPA config bind must be present and writable")
        config_directory = record[0]
        require_private_directory(config_directory, "isolated CPA config directory")
        directory_info = config_directory.lstat()
        if os.name == "posix" and (
            directory_info.st_uid != os.getuid()
            or directory_info.st_gid != os.getgid()
        ):
            fail("isolated CPA config directory owner drifted")
        try:
            entries = list(config_directory.iterdir())
        except OSError as exc:
            fail(
                "isolated CPA config directory cannot be listed: "
                f"{type(exc).__name__}"
            )
        if len(entries) != 1 or entries[0].name != "config.yaml":
            fail("isolated CPA config directory file set is not closed")
        config_info = regular_file_info(
            entries[0], "isolated CPA runtime config", require_single_link=True
        )
        if (
            config_info.st_size < 1
            or config_info.st_size > MAX_CONFIG_BYTES
            or (
                os.name == "posix"
                and (
                    config_info.st_uid != os.getuid()
                    or config_info.st_gid != os.getgid()
                    or config_info.st_mode & 0o022
                )
            )
        ):
            fail("isolated CPA runtime config ownership, mode, or size drifted")

    def start_cold(self, cold_root: Path, initial_mode: str) -> None:
        mock = self.config["identities"]["mock"]
        mock_args = self.common_container_args("mock", self.mock_name)
        self.failure_stage = "mock_start"
        with ephemeral_mock_environment(
            cold_root, self.control_token, self.upstream_key
        ) as environment_file:
            mock_args.extend(
                [
                    "--env-file",
                    str(environment_file),
                    mock["image_ref"],
                    "--host",
                    "0.0.0.0",
                    "--port",
                    str(MOCK_PORT),
                ]
            )
            self.docker.run(mock_args, timeout=60)
        self.mock_url = internal_base(
            container_ip(self.docker, self.mock_name, self.network_name), MOCK_PORT
        )
        self.failure_stage = "mock_readiness"
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            try:
                health, _, _ = http_json(self.mock_url, "GET", "/healthz")
                if health == {
                    "contract": MOCK_CONTRACT,
                    "healthy": True,
                    "request_body_retention": False,
                }:
                    break
            except AuditFailure:
                pass
            time.sleep(0.25)
        else:
            fail("counted-Mock did not become ready")
        self.reset_mock()

        cpa = self.config["identities"]["cpa"]
        cpa_args = self.common_container_args("cpa", self.cpa_name)
        cpa_args.extend(self.cpa_bind_mount_args(cold_root))
        cpa_args.extend(
            [
                "--env",
                "CYBER_ABUSE_GUARD_HMAC_KEY_FILE=/cag/secrets/hmac.key",
                cpa["image_ref"],
                "-config",
                "/cag/config/config.yaml",
                "-local-model",
            ]
        )
        self.failure_stage = "cpa_start"
        self.docker.run(cpa_args, timeout=60)
        self.failure_stage = "cpa_mount_contract"
        self.verify_cpa_bind_mounts()
        self.cpa_url = internal_base(
            container_ip(self.docker, self.cpa_name, self.network_name), CPA_PORT
        )
        self.failure_stage = "cpa_readiness"
        self.wait_ready(initial_mode)
        self.failure_stage = "sandbox_contract"
        self.verify_sandbox()
        self.last_event_id = self.event_head_id()
        if not self.binary_verified:
            self.failure_stage = "cpa_binary_identity"
            self.verify_image_binary()

    def verify_image_binary(self) -> None:
        cpa = self.config["identities"]["cpa"]
        extraction = Path(tempfile.mkdtemp(prefix="binary-verify-", dir=self.runtime_root))
        os.chmod(extraction, 0o700)
        target = extraction / "cpa-binary"
        try:
            self.docker.run(
                ["cp", f"{self.cpa_name}:{cpa['binary_path']}", str(target)], timeout=60
            )
            regular_file_info(target, "CPA image binary")
            if sha256_file(target) != cpa["binary_sha256"]:
                fail("CPA binary inside the selected image has the wrong SHA")
            self.binary_verified = True
        finally:
            remove_owned_tree(extraction)

    def wait_ready(self, mode: str) -> dict[str, Any]:
        deadline = time.monotonic() + 45
        last_digest = ""
        while time.monotonic() < deadline:
            try:
                plugins, headers, _ = http_json(
                    self.cpa_url,
                    "GET",
                    "/v0/management/plugins",
                    headers=self.management_headers,
                )
                status, status_headers, _ = http_json(
                    self.cpa_url,
                    "GET",
                    "/v0/management/plugins/cyber-abuse-guard/status",
                    headers=self.management_headers,
                )
                entries = plugins.get("plugins") if isinstance(plugins, dict) else None
                matches = [
                    item
                    for item in entries or []
                    if isinstance(item, dict) and item.get("id") == "cyber-abuse-guard"
                ]
                audit = status.get("audit") if isinstance(status, dict) else None
                raw_capture = status.get("raw_capture") if isinstance(status, dict) else None
                cpa = self.config["identities"]["cpa"]
                version_headers = (
                    str(headers.get("x-cpa-version", "")).lstrip("v"),
                    str(status_headers.get("x-cpa-version", "")).lstrip("v"),
                )
                commit_headers = (
                    str(headers.get("x-cpa-commit", "")).lower(),
                    str(status_headers.get("x-cpa-commit", "")).lower(),
                )
                commit_ok = all(
                    7 <= len(value) <= 40 and cpa["commit"].startswith(value)
                    for value in commit_headers
                )
                ready = (
                    isinstance(plugins, dict)
                    and plugins.get("plugins_enabled") is True
                    and len(matches) == 1
                    and all(
                        matches[0].get(key) is True
                        for key in ("registered", "configured", "effective_enabled")
                    )
                    and isinstance(status, dict)
                    and status.get("id") == "cyber-abuse-guard"
                    and status.get("commit") == self.config["identities"]["cag"]["commit"]
                    and status.get("dirty") is False
                    and status.get("enabled") is True
                    and status.get("mode") == mode
                    and status.get("enforcement_ready") is True
                    and status.get("operational_ready") is True
                    and status.get("audit_degraded") is False
                    and status.get("persistence_degraded") is False
                    and isinstance(audit, dict)
                    and audit.get("healthy") is True
                    and audit.get("degraded") is False
                    and audit.get("schema_version") == SCHEMA_VERSION
                    and audit.get("persistence_verified") is True
                    and isinstance(raw_capture, dict)
                    and raw_capture.get("enabled") is False
                    and version_headers == (cpa["tag"].lstrip("v"),) * 2
                    and commit_ok
                )
                if ready:
                    self.readiness_state_sha256 = None
                    return status
                last_digest = sha256_bytes(canonical_bytes({"plugins": plugins, "status": status}))
            except (AuditFailure, ContractError) as exc:
                last_digest = sha256_bytes(str(exc).encode("utf-8"))
            time.sleep(0.25)
        self.readiness_state_sha256 = last_digest or None
        fail(f"CPA/CAG readiness did not converge for {mode}; state_sha256={last_digest}")

    def reconfigure(self, mode: str) -> None:
        value, _, _ = http_json(
            self.cpa_url,
            "PUT",
            "/v0/management/plugins/cyber-abuse-guard/config",
            plugin_config(mode),
            self.management_headers,
        )
        if not isinstance(value, dict) or value.get("status") != "ok":
            fail(f"CAG did not acknowledge {mode} reconfiguration")
        self.wait_ready(mode)
        self.last_event_id = self.event_head_id()

    def container_contract(self, name: str, image_id: str, role: str) -> dict[str, Any]:
        info = self.docker.inspect("container", name)
        config = info.get("Config") or {}
        host = info.get("HostConfig") or {}
        state = info.get("State") or {}
        labels = config.get("Labels") or {}
        ports = (info.get("NetworkSettings") or {}).get("Ports") or {}
        cap_drop = host.get("CapDrop") or []
        cap_add = host.get("CapAdd") or []
        security_opt = host.get("SecurityOpt") or []
        restart = (host.get("RestartPolicy") or {}).get("Name", "")
        container_user = str(config.get("User", ""))
        expected_user = f"{os.getuid()}:{os.getgid()}"
        self.verify_tmpfs_contract(host)
        if (
            info.get("Image") != image_id
            or labels.get(LABEL_KEY) != self.run_id
            or labels.get(ROLE_LABEL) != role
            or state.get("Running") is not True
            or state.get("OOMKilled") is not False
            or host.get("ReadonlyRootfs") is not True
            or cap_drop != ["ALL"]
            or cap_add != []
            or not any(str(value).startswith("no-new-privileges") for value in security_opt)
            or host.get("Privileged") is not False
            or restart not in ("", "no")
            or container_user != expected_user
            or host.get("PublishAllPorts") is not False
            or (host.get("PortBindings") or {}) != {}
            or host.get("NetworkMode") != self.network_name
            or any(value not in (None, []) for value in ports.values())
            or int(host.get("PidsLimit") or 0) < 1
            or int(host.get("Memory") or 0) < 1
        ):
            fail(f"container security or identity contract failed: {role}")
        if role == "cpa":
            self.verify_cpa_bind_mounts()
        return {
            "cap_add": [str(value) for value in cap_add],
            "cap_drop": [str(value) for value in cap_drop],
            "host_port_bindings": sum(
                len(value or []) for value in ports.values() if isinstance(value, list)
            ),
            "id": str(info.get("Id", "")),
            "image_id": str(info.get("Image", "")),
            "memory_bytes": int(host.get("Memory")),
            "pids_limit": int(host.get("PidsLimit")),
            "privileged": host.get("Privileged") is True,
            "read_only_rootfs": host.get("ReadonlyRootfs") is True,
            "restart_policy": str(restart),
            "role": role,
            "running_before_stop": state.get("Running") is True,
            "security_opt": [str(value) for value in security_opt],
            "user": container_user,
        }

    def network_contract(self) -> dict[str, Any]:
        info = self.docker.inspect("network", self.network_name)
        members = info.get("Containers") or {}
        names = {
            str(item.get("Name", "")): str(item.get("Name", ""))
            for item in members.values()
            if isinstance(item, dict)
        }
        if set(names) != {self.cpa_name, self.mock_name}:
            fail("audit network member set is not closed")
        return {
            "attachable": info.get("Attachable") is True,
            "driver": str(info.get("Driver", "")),
            "host_ports": 0,
            "ingress": info.get("Ingress") is True,
            "internal": info.get("Internal") is True,
            "ipv6": info.get("EnableIPv6") is True,
            "members": ["cpa", "mock"],
            "name": self.network_name,
        }

    def verify_sandbox(self) -> None:
        self.container_contract(
            self.cpa_name, self.config["identities"]["cpa"]["image_id"], "cpa"
        )
        self.verify_runtime_config_storage()
        self.container_contract(
            self.mock_name, self.config["identities"]["mock"]["image_id"], "mock"
        )
        network = self.network_contract()
        if (
            network["driver"] != "bridge"
            or network["internal"] is not True
            or network["attachable"] is True
            or network["ingress"] is True
            or network["ipv6"] is True
            or network["host_ports"] != 0
        ):
            fail("audit network is not a closed IPv4 internal bridge")
        config, _, _ = http_json(
            self.cpa_url,
            "GET",
            "/v0/management/config",
            headers=self.management_headers,
        )
        providers = config.get("openai-compatibility") if isinstance(config, dict) else None
        if (
            not isinstance(config, dict)
            or config.get("commercial-mode") is not True
            or config.get("request-log") is not False
            or config.get("logging-to-file") is not False
            or not isinstance(providers, list)
            or len(providers) != 1
            or not isinstance(providers[0], dict)
            or providers[0].get("base-url") != "http://mock:18080/v1"
        ):
            fail("CPA runtime configuration escaped the counted-Mock contract")
        for key in (
            "claude-api-key",
            "codex-api-key",
            "gemini-api-key",
            "interactions-api-key",
            "vertex-api-key",
            "xai-api-key",
        ):
            if config.get(key) not in (None, []):
                fail(f"unexpected real Provider configuration: {key}")
        if self.active_auth_dir is None:
            fail("isolated CPA auth directory is unavailable")
        require_private_directory(self.active_auth_dir, "isolated CPA auth directory")
        if any(self.active_auth_dir.iterdir()):
            fail("isolated CPA auth directory is missing or not empty")

    def mock_snapshot(self) -> dict[str, int]:
        value, _, _ = http_json(
            self.mock_url, "GET", "/__cag/stats", headers=self.control_headers
        )
        if not isinstance(value, dict) or set(value) != {"schema", "auth", "mock", "provider"}:
            fail("counted-Mock stats schema is invalid")
        if value["schema"] != MOCK_CONTRACT:
            fail("counted-Mock stats contract drifted")
        result: dict[str, int] = {}
        for key in ("auth", "mock", "provider"):
            if type(value[key]) is not int or value[key] < 0:
                fail("counted-Mock counter is invalid")
            result[key] = value[key]
        return result

    def reset_mock(self) -> None:
        value, _, _ = http_json(
            self.mock_url, "POST", "/__cag/reset", headers=self.control_headers
        )
        if value != {"schema": MOCK_CONTRACT, "auth": 0, "mock": 0, "provider": 0}:
            fail("counted-Mock reset response is invalid")
        if self.mock_snapshot() != {"auth": 0, "mock": 0, "provider": 0}:
            fail("counted-Mock reset did not reach zero")

    def usage_queue(self) -> list[Any]:
        value, _, _ = http_json(
            self.cpa_url,
            "GET",
            "/v0/management/usage-queue?count=100",
            headers=self.management_headers,
        )
        if not isinstance(value, list):
            fail("CPA usage queue response is not a list")
        return value

    def drain_usage_queue(self) -> None:
        for _ in range(40):
            if not self.usage_queue():
                return
            time.sleep(0.025)
        fail("CPA usage queue did not drain")

    def usage_after_request(self, expected_allow: bool) -> int:
        deadline = time.monotonic() + (5.0 if expected_allow else 0.75)
        observed: list[Any] = []
        while time.monotonic() < deadline:
            observed = self.usage_queue()
            if observed:
                break
            time.sleep(0.05)
        return len(observed)

    def event_head(self) -> dict[str, Any] | None:
        value, _, _ = http_json(
            self.cpa_url,
            "GET",
            "/v0/management/plugins/cyber-abuse-guard/events?limit=1",
            headers=self.management_headers,
        )
        if (
            not isinstance(value, dict)
            or value.get("audit_schema_version") != SCHEMA_VERSION
            or value.get("event_response_schema_version") != 2
            or not isinstance(value.get("events"), list)
            or len(value["events"]) > 1
        ):
            fail("CAG audit event response schema is invalid")
        if not value["events"]:
            return None
        event = value["events"][0]
        if not isinstance(event, dict):
            fail("CAG audit event is not an object")
        return event

    def event_head_id(self) -> str:
        event = self.event_head()
        return str(event.get("id", "")) if event is not None else ""

    def cag_counter_snapshot(self) -> dict[str, int]:
        value, _, _ = http_json(
            self.cpa_url,
            "GET",
            "/v0/management/plugins/cyber-abuse-guard/status",
            headers=self.management_headers,
        )
        counters = value.get("counters") if isinstance(value, dict) else None
        if not isinstance(counters, dict) or not counters:
            fail("CAG status counters are missing during realtime boundary probe")
        result: dict[str, int] = {}
        for key in REALTIME_RPC_COUNTER_KEYS:
            raw = counters.get(key)
            if type(raw) is not int or raw < 0:
                fail(f"CAG status is missing fixed RPC callback counter {key}")
            result[key] = raw
        return result

    def probe_realtime_boundary(self, cold_start: int) -> dict[str, Any]:
        """Prove the fixed v7.2.137 realtime registrations bypass CAG.

        Every request is deliberately unauthenticated, so the isolated Host must
        terminate in its realtime authentication middleware.  Supplying model or
        Provider credentials here would turn a negative-coverage probe into a
        real-upstream risk and is therefore forbidden.
        """
        before_counters = self.cag_counter_snapshot()
        before_event = self.event_head_id()
        self.drain_usage_queue()
        before_mock = self.mock_snapshot()
        observations: list[dict[str, Any]] = []
        for method, route, auth in REALTIME_ROUTES:
            route_counters_before = self.cag_counter_snapshot()
            status, raw, headers, _ = http_request(
                self.cpa_url,
                method,
                route,
                body=(b"{}" if method == "POST" else None),
                headers={"Accept": "application/json"},
                timeout=5.0,
            )
            route_counters_after = self.cag_counter_snapshot()
            if status not in {401, 403}:
                fail(
                    f"realtime negative-coverage probe did not stop at authentication: "
                    f"{method} {route} status={status} body_sha256={sha256_bytes(raw)}"
                )
            observations.append(
                {
                    "auth": auth,
                    "cag_counter_delta": {
                        key: route_counters_after[key] - route_counters_before[key]
                        for key in REALTIME_RPC_COUNTER_KEYS
                    },
                    "credential_kind": "NONE",
                    "method": method,
                    "probe_mode": "UNAUTHENTICATED",
                    "route": route,
                    "status": status,
                    "termination": "AUTH_REJECTED",
                    "upgrade": headers.get("upgrade", "").lower() == "websocket",
                }
            )
        after_counters = self.cag_counter_snapshot()
        after_event = self.event_head_id()
        usage_records = len(self.usage_queue())
        after_mock = self.mock_snapshot()
        if (
            before_counters != after_counters
            or before_event != after_event
            or before_mock != {"auth": 0, "mock": 0, "provider": 0}
            or after_mock != before_mock
            or usage_records != 0
            or any(item["upgrade"] for item in observations)
            or any(
                any(delta != 0 for delta in item["cag_counter_delta"].values())
                for item in observations
            )
        ):
            fail("realtime negative-coverage probe reached CAG, usage, Mock, or websocket upgrade")
        return {
            "cag_counters_after": after_counters,
            "cag_counters_before": before_counters,
            "cag_visible": False,
            "cold_start": cold_start,
            "evidence_level": "AUTH_BOUNDARY_ONLY",
            "event_head_after": after_event,
            "event_head_before": before_event,
            "mock_after": after_mock,
            "mock_before": before_mock,
            "protection": "unprotected",
            "real_provider_calls": 0,
            "routes": observations,
            "target_boundary": {
                "counted_mock_only": True,
                "cpa_private_bridge_only": True,
                "real_provider_forbidden": True,
            },
            "usage_records": usage_records,
        }

    def new_event(self, previous_id: str) -> dict[str, Any] | None:
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline:
            event = self.event_head()
            event_id = str(event.get("id", "")) if event is not None else ""
            if event_id and event_id != previous_id:
                self.last_event_id = event_id
                return event
            time.sleep(0.025)
        return None

    @staticmethod
    def event_summary(event: Mapping[str, Any] | None) -> dict[str, Any] | None:
        if event is None:
            return None
        explanation = event.get("decision_explanation")
        winning_rule_id = (
            explanation.get("winning_rule_id")
            if isinstance(explanation, dict)
            else None
        )
        return {
            "action": event.get("action"),
            "category": event.get("category") or None,
            "coverage": event.get("coverage"),
            "decision": event.get("decision"),
            "decision_kind": event.get("decision_kind"),
            "explanation_schema": event.get("explanation_schema"),
            "id": event.get("id"),
            "incomplete_reason": event.get("incomplete_reason") or None,
            "mode": event.get("mode"),
            "request_hash": event.get("request_hash"),
            "winning_rule_id": winning_rule_id or None,
        }

    def open_results(self) -> None:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(self.results_path, flags, 0o600)
        self.results_handle = os.fdopen(descriptor, "wb", closefd=True)
        os.chmod(self.results_path, 0o600)
        supplemental_descriptor: int | None = None
        try:
            supplemental_descriptor = os.open(
                self.supplemental_results_path, flags, 0o600
            )
            self.supplemental_results_handle = os.fdopen(
                supplemental_descriptor, "wb", closefd=True
            )
            supplemental_descriptor = None
            os.chmod(self.supplemental_results_path, 0o600)
        except BaseException:
            if (
                self.supplemental_results_handle is not None
                and not self.supplemental_results_handle.closed
            ):
                self.supplemental_results_handle.close()
            elif supplemental_descriptor is not None:
                os.close(supplemental_descriptor)
            self.results_handle.close()
            raise

    def append_result(self, result: Mapping[str, Any]) -> bytes:
        if self.results_handle is None or self.results_handle.closed:
            fail("transport result handle is not open")
        raw = canonical_bytes(result) + b"\n"
        self.results_handle.write(raw)
        self.results_handle.flush()
        os.fsync(self.results_handle.fileno())
        self.results_count += 1
        return raw

    def append_supplemental_result(self, result: Mapping[str, Any]) -> bytes:
        if (
            self.supplemental_results_handle is None
            or self.supplemental_results_handle.closed
        ):
            fail("supplemental ZIP result handle is not open")
        raw = canonical_bytes(result) + b"\n"
        self.supplemental_results_handle.write(raw)
        self.supplemental_results_handle.flush()
        os.fsync(self.supplemental_results_handle.fileno())
        self.supplemental_results_count += 1
        action = result.get("actual_action")
        if action in self.supplemental_action_counts:
            self.supplemental_action_counts[action] += 1
        return raw

    def execute_entry(self, entry: Any, ordinal: int) -> bytes:
        case = self.cases[entry.semantic_case_id]
        source = case["source"]
        if self.bound_corpus is None:
            fail("bound corpus is unavailable during execution")
        self._pending_bound_read = None
        raw_text = self.bound_corpus.read(
            source["corpus_file"],
            f"corpus text {case['id']}",
            source["text_bytes"],
        )
        if (
            len(raw_text) != source["text_bytes"]
            or sha256_bytes(raw_text) != source["text_sha256"]
        ):
            fail(f"corpus text identity changed: {case['id']}")
        pending_read = self._pending_bound_read
        self._pending_bound_read = None
        if pending_read is None:
            fail(f"lazy-read observer missed transport source: {case['id']}")
        try:
            text = raw_text.decode("utf-8", "strict")
        except UnicodeDecodeError:
            fail(f"corpus text is no longer UTF-8: {case['id']}")
        return self.execute_transport_case(
            entry, ordinal, case, raw_text, text, False, pending_read
        )

    def execute_supplemental_entry(self, entry: Any, ordinal: int) -> bytes:
        case = self.supplemental_cases[entry.semantic_case_id]
        source = case["source"]
        raw_text = self.supplemental_texts.get(source["entry_id"])
        if (
            raw_text is None
            or len(raw_text) != source["text_bytes"]
            or sha256_bytes(raw_text) != source["normalized_text_sha256"]
        ):
            fail(f"supplemental ZIP selected text identity changed: {case['id']}")
        try:
            text = raw_text.decode("utf-8", "strict")
        except UnicodeDecodeError:
            fail(f"supplemental ZIP selected text is no longer UTF-8: {case['id']}")
        source_path = "corpus/supplemental/" + sha256_bytes(
            str(source["entry_id"]).encode("utf-8", "strict")
        )
        pending_read = (
            source_path,
            source["text_bytes"],
            source["normalized_text_sha256"],
        )
        return self.execute_transport_case(
            entry, ordinal, case, raw_text, text, True, pending_read
        )

    def execute_transport_case(
        self,
        entry: Any,
        ordinal: int,
        case: Mapping[str, Any],
        raw_text: bytes | bytearray,
        text: str,
        supplemental: bool,
        lazy_source: tuple[str, int, str],
    ) -> bytes:
        source = case["source"]
        body = apply_template(case["template"]["id"], text, entry.protocol, entry.stream, MODEL)
        request_bytes = canonical_bytes(body)
        request_digest = sha256_bytes(request_bytes)
        audit_request_hash = expected_request_hash(request_bytes)
        expected = case["expected_action_by_mode"][entry.mode]

        source_path, source_bytes, source_sha256 = lazy_source
        if source_bytes != len(raw_text) or source_sha256 != sha256_bytes(raw_text):
            fail(f"lazy-read source identity changed: {case['id']}")
        try:
            self.lazy_read.record_transport(
                source_path=source_path,
                source_bytes=source_bytes,
                source_sha256=source_sha256,
                case_identity=case["id"],
                request_sha256=request_digest,
            )
        except LazyReadError as exc:
            fail(str(exc))

        self.drain_usage_queue()
        self.reset_mock()
        before = self.mock_snapshot()
        previous_event = self.event_head_id()
        endpoint = "/v1/chat/completions" if entry.protocol == "chat" else "/v1/responses"
        status, response, response_headers, latency_ms = http_request(
            self.cpa_url,
            "POST",
            endpoint,
            request_bytes,
            self.client_headers,
        )
        after = self.mock_snapshot()
        usage_count = self.usage_after_request(expected == "allow")
        event = self.new_event(previous_event)
        event_summary = self.event_summary(event)
        side_effects = {
            "auth": after["auth"] - before["auth"],
            "mock": after["mock"] - before["mock"],
            "provider": after["provider"] - before["provider"],
            "usage": usage_count,
        }

        if status == 200:
            actual = "allow"
        elif status == 403 and event_summary is not None and event_summary["decision_kind"] in (
            "block_incomplete_inspection",
            "block_malicious_text",
        ):
            actual = event_summary["decision_kind"]
        else:
            actual = "transport_error"

        if status == 403:
            error_contract = validate_block_response(response, response_headers)
            stream_terminated = False
        else:
            error_contract = {
                "checked": False,
                "content_type": None,
                "no_store": None,
                "nosniff": None,
                "schema_valid": None,
            }
            response_valid, stream_terminated = validate_allow_response(
                entry.protocol, entry.stream, response, response_headers, MODEL
            )
            if not response_valid:
                stream_terminated = False

        result: dict[str, Any] = {
            "actual_action": actual,
            "audit_event": event_summary,
            "cold_start": entry.cold_start,
            "error_contract": error_contract,
            "execution_id": (
                f"{self.run_id}:supplemental:{ordinal:08d}"
                if supplemental
                else f"{self.run_id}:{ordinal:08d}"
            ),
            "expected_action": expected,
            "expected_action_by_mode": dict(case["expected_action_by_mode"]),
            "expected_audit_request_hash": audit_request_hash,
            "http_status": status,
            "infrastructure_error": None,
            "latency_ms": round(latency_ms, 6),
            "mode": entry.mode,
            "ordinal": ordinal,
            "passed": True,
            "protocol": entry.protocol,
            "request_sha256": request_digest,
            "response_bytes": len(response),
            "response_sha256": sha256_bytes(response),
            "schema": (
                SUPPLEMENTAL_ZIP_RESULT_SCHEMA if supplemental else RESULT_SCHEMA
            ),
            "side_effect_deltas": side_effects,
            "source_text_sha256": (
                source["normalized_text_sha256"]
                if supplemental
                else source["text_sha256"]
            ),
            "stream": entry.stream,
            "stream_terminated": stream_terminated,
            "template_sha256": case["template"]["sha256"],
            "usage_recorded": usage_count == 1,
        }
        result[
            "supplemental_case_id" if supplemental else "semantic_case_id"
        ] = case["id"]
        result_label = (
            f"supplemental ZIP execution {ordinal}"
            if supplemental
            else f"transport execution {ordinal}"
        )
        append = self.append_supplemental_result if supplemental else self.append_result
        try:
            if supplemental:
                validate_supplemental_result(
                    result, self.supplemental_cases, result_label
                )
            else:
                validate_result(result, self.cases, result_label)
        except ContractError as exc:
            error_id = sha256_bytes(str(exc).encode("utf-8"))[:16]
            result["passed"] = False
            result["infrastructure_error"] = f"closed_contract_failure:{error_id}"
            raw_result = append(result)
            del raw_result
            fail(
                f"{result_label} failed closed; contract_error_id={error_id}"
            )
        finally:
            raw_text = b""
            text = ""
            body = {}
            request_bytes = b""
            response = b""
        return append(result)

    def sqlite_checkpoint(self, database: Path) -> dict[str, Any]:
        self.cleanup.checkpoint_attempts += 1
        regular_file_info(database, "CAG audit SQLite database")
        connection = sqlite3.connect(str(database), timeout=5.0, isolation_level=None)
        try:
            checkpoint = connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
            quick_rows = connection.execute("PRAGMA quick_check").fetchall()
            version_row = connection.execute(
                "SELECT version FROM schema_version WHERE singleton = 1"
            ).fetchone()
        except sqlite3.Error as exc:
            fail(f"SQLite post-stop verification failed: {type(exc).__name__}")
        finally:
            connection.close()
        if (
            not isinstance(checkpoint, tuple)
            or len(checkpoint) != 3
            or len(quick_rows) != 1
            or quick_rows[0] != ("ok",)
            or version_row != (SCHEMA_VERSION,)
        ):
            fail("SQLite quick_check, schema, or checkpoint contract failed")
        busy, logged, checkpointed = (int(value) for value in checkpoint)
        if busy != 0 or logged != checkpointed:
            fail("SQLite WAL checkpoint did not fully close")
        return {
            "database_sha256": sha256_file(database),
            "quick_check": "ok",
            "schema_version": SCHEMA_VERSION,
            "wal_checkpoint": {
                "busy": busy,
                "checkpointed_frames": checkpointed,
                "log_frames": logged,
            },
        }

    def stopped_runtime(self) -> dict[str, Any]:
        cpa = self.docker.inspect("container", self.cpa_name)
        mock = self.docker.inspect("container", self.mock_name)
        cpa_state = cpa.get("State") or {}
        mock_state = mock.get("State") or {}
        logs = self.docker.run(["logs", self.cpa_name], timeout=30, check=False)
        if logs.returncode != 0:
            fail(
                "CPA logs could not be inspected; diagnostic_sha256="
                + sha256_bytes((logs.stdout + logs.stderr).encode("utf-8"))
            )
        log_text = logs.stdout + logs.stderr
        return {
            "cpa_exit_code": int(cpa_state.get("ExitCode") or 0),
            "cpa_oom_killed": cpa_state.get("OOMKilled") is True,
            "cpa_restart_count": int(cpa.get("RestartCount") or 0),
            "fatal_mentions": len(re.findall(r"(?i)\bfatal\b", log_text)),
            "mock_exit_code": int(mock_state.get("ExitCode") or 0),
            "mock_oom_killed": mock_state.get("OOMKilled") is True,
            "mock_restart_count": int(mock.get("RestartCount") or 0),
            "panic_mentions": len(re.findall(r"(?i)\bpanic\b", log_text)),
            "plugin_error_mentions": len(
                re.findall(r"(?i)\b(?:plugin|router)\b.{0,80}\b(?:error|failed)\b", log_text)
            ),
        }

    def finish_cold(
        self,
        cold_root: Path,
        started_at: str,
        execution_count: int,
        order_sha256: str,
        result_bytes: bytes,
        supplemental_execution_count: int,
        supplemental_order_sha256: str,
        supplemental_result_bytes: bytes,
        runtime_hash: str,
    ) -> dict[str, Any]:
        self.verify_sandbox()
        containers = {
            "cpa": self.container_contract(
                self.cpa_name, self.config["identities"]["cpa"]["image_id"], "cpa"
            ),
            "mock": self.container_contract(
                self.mock_name, self.config["identities"]["mock"]["image_id"], "mock"
            ),
        }
        network = self.network_contract()
        cpa_stopped = self.cleanup.stop(self.cpa_name)
        mock_stopped = self.cleanup.stop(self.mock_name)
        runtime = self.stopped_runtime()
        sqlite = self.sqlite_checkpoint(cold_root / "audit" / "events.db")
        stop = {
            "checkpoint_after_stop": True,
            "cpa_graceful": cpa_stopped and runtime["cpa_exit_code"] == 0,
            "forced_kill_used": False,
            "mock_graceful": mock_stopped and runtime["mock_exit_code"] == 0,
        }
        if not all(value == 0 for key, value in runtime.items() if key not in {"cpa_oom_killed", "mock_oom_killed"}):
            fail("runtime exit/restart/panic/fatal/plugin-error contract failed")
        if runtime["cpa_oom_killed"] or runtime["mock_oom_killed"]:
            fail("runtime reported OOM")
        if not stop["cpa_graceful"] or not stop["mock_graceful"]:
            fail("container graceful stop contract failed")
        self.cleanup.remove_container(self.cpa_name)
        self.cleanup.remove_container(self.mock_name)
        remove_owned_tree(cold_root)
        self.active_auth_dir = None
        return {
            "completed_at": now_iso(),
            "containers": containers,
            "execution_count": execution_count,
            "index": len(self.cold_evidence) + 1,
            "network": network,
            "order_sha256": order_sha256,
            "results_sha256": sha256_bytes(result_bytes),
            "runtime": runtime,
            "runtime_config_sha256": runtime_hash,
            "sqlite": sqlite,
            "started_at": started_at,
            "stop": stop,
            "supplemental_execution_count": supplemental_execution_count,
            "supplemental_order_sha256": supplemental_order_sha256,
            "supplemental_results_sha256": sha256_bytes(
                supplemental_result_bytes
            ),
        }

    def run_cold_start(
        self,
        cold_start: int,
        ordinal_offset: int,
        supplemental_ordinal_offset: int,
    ) -> tuple[int, int]:
        entries = [entry for entry in self.plan if entry.cold_start == cold_start]
        supplemental_entries = [
            entry
            for entry in self.supplemental_plan
            if entry.cold_start == cold_start
        ]
        if not entries:
            fail(f"cold start {cold_start} has no planned executions")
        if not supplemental_entries:
            fail(f"cold start {cold_start} has no supplemental ZIP executions")
        initial_mode = entries[0].mode
        self.failure_stage = "cold_runtime_prepare"
        cold_root, runtime_hash = self.prepare_cold_runtime(cold_start, initial_mode)
        self.runtime_hashes.append(runtime_hash)
        started_at = now_iso()
        self.start_cold(cold_root, initial_mode)
        self.failure_stage = "realtime_negative_coverage"
        if getattr(self, "cpa_url", ""):
            self.realtime_evidence.append(self.probe_realtime_boundary(cold_start))
        current_mode = initial_mode
        self.failure_stage = "transport_matrix"
        cold_raw = bytearray()
        order: list[tuple[str, str, str, bool]] = []
        for index, entry in enumerate(entries, start=1):
            if entry.mode != current_mode:
                self.reconfigure(entry.mode)
                current_mode = entry.mode
                self.verify_sandbox()
            ordinal = ordinal_offset + index
            cold_raw.extend(self.execute_entry(entry, ordinal))
            order.append(
                (entry.mode, entry.semantic_case_id, entry.protocol, entry.stream)
            )
            if index % 25 == 0 or index == len(entries):
                print(
                    json.dumps(
                        {
                            "cold_start": cold_start,
                            "completed": index,
                            "total": len(entries),
                        },
                        sort_keys=True,
                    ),
                    flush=True,
                )
        self.failure_stage = "supplemental_zip_matrix"
        supplemental_cold_raw = bytearray()
        supplemental_order: list[tuple[str, str, str, bool]] = []
        for index, entry in enumerate(supplemental_entries, start=1):
            if entry.mode != current_mode:
                self.reconfigure(entry.mode)
                current_mode = entry.mode
                self.verify_sandbox()
            ordinal = supplemental_ordinal_offset + index
            supplemental_cold_raw.extend(
                self.execute_supplemental_entry(entry, ordinal)
            )
            supplemental_order.append(
                (entry.mode, entry.semantic_case_id, entry.protocol, entry.stream)
            )
            if index % 25 == 0 or index == len(supplemental_entries):
                print(
                    json.dumps(
                        {
                            "cold_start": cold_start,
                            "completed": index,
                            "plane": "supplemental_zip",
                            "total": len(supplemental_entries),
                        },
                        sort_keys=True,
                    ),
                    flush=True,
                )
        self.failure_stage = "cold_finish"
        cold = self.finish_cold(
            cold_root,
            started_at,
            len(entries),
            sha256_bytes(canonical_bytes(order)),
            bytes(cold_raw),
            len(supplemental_entries),
            sha256_bytes(canonical_bytes(supplemental_order)),
            bytes(supplemental_cold_raw),
            runtime_hash,
        )
        self.cold_evidence.append(cold)
        return len(entries), len(supplemental_entries)

    def close_results(self) -> None:
        errors: list[str] = []
        for label, handle in (
            ("transport", self.results_handle),
            ("supplemental_zip", self.supplemental_results_handle),
        ):
            if handle is None or handle.closed:
                continue
            try:
                handle.flush()
                os.fsync(handle.fileno())
            except BaseException as exc:
                errors.append(f"{label}:{type(exc).__name__}")
            finally:
                try:
                    handle.close()
                except BaseException as exc:
                    errors.append(f"{label}_close:{type(exc).__name__}")
        if errors:
            fail("result close failed: " + ",".join(errors))

    def remove_corpus_texts(self) -> None:
        self._lazy_observe_mode = None
        removed, retained = remove_manifest_corpus(
            self.manifest, self.corpus_root, self.bound_corpus
        )
        self.cleanup.text_files_removed = removed
        self.cleanup.text_retained = retained
        self.corpus_cleanup_completed = True

    def _bound_read_observer(self, source_path: str, source_bytes: int, source_sha256: str) -> None:
        """Receive metadata only from BoundCorpus after a verified read."""

        lazy_read = getattr(self, "lazy_read", None)
        if lazy_read is None:
            fail("lazy-read observer received a read before recorder initialization")
        mode = self._lazy_observe_mode
        case_identity = self._source_case_identity.get(source_path, source_path)
        if mode == "preflight":
            try:
                lazy_read.record_preflight(
                    source_path=source_path,
                    source_bytes=source_bytes,
                    source_sha256=source_sha256,
                    case_identity=case_identity,
                )
            except LazyReadError as exc:
                fail(str(exc))
        elif mode == "transport":
            if self._pending_bound_read is not None:
                fail("lazy-read transport opened more than one source for a request")
            self._pending_bound_read = (source_path, source_bytes, source_sha256)

    def _abort_lazy_read(self) -> None:
        lazy_read = getattr(self, "lazy_read", None)
        if lazy_read is None or self.lazy_read_finalized:
            return
        try:
            lazy_read.abort()
        except BaseException:
            pass

    def finalize_lazy_read(self) -> None:
        if self.lazy_read_finalized:
            fail("lazy-read evidence was finalized twice")
        lazy_read = getattr(self, "lazy_read", None)
        if lazy_read is None:
            fail("lazy-read recorder is unavailable during finalization")
        try:
            lazy_read.finalize(
                expected_transport_reads=self.results_count
                + self.supplemental_results_count,
                finally_cleanup_complete=(
                    self.corpus_cleanup_completed
                    and self.supplemental_texts_zeroized
                    and not self.runtime_root.exists()
                    and self.owned_resources_absent()
                ),
                post_unlink_nlink_zero=not self.cleanup.text_retained,
                supplemental_member_text_retained=self.supplemental_member_text_retained,
                temporary_secret_or_config_retained=(
                    self.active_auth_dir is not None or self.runtime_root.exists()
                ),
                third_party_text_retained=self.cleanup.text_retained,
            )
            phase = load_json_file(lazy_read.phase_path, "lazy-read phase boundary")
            summary = load_json_file(lazy_read.summary_path, "lazy-read runtime summary")
            trace_raw = read_regular_bytes(
                lazy_read.trace_path,
                "lazy-read runtime trace",
                64 * 1024 * 1024,
                require_single_link=True,
            )
            lazy_projection = validate_lazy_read_evidence(
                phase, trace_raw, summary
            )
            if self.supplemental_manifest is None:
                fail("supplemental ZIP manifest is unavailable for lazy-read validation")
            validate_lazy_read_bindings(
                trace_raw,
                self.manifest,
                read_regular_bytes(
                    self.results_path,
                    "lazy-read transport results",
                    128 * 1024 * 1024,
                    require_single_link=True,
                ),
                self.supplemental_manifest,
                read_regular_bytes(
                    self.supplemental_results_path,
                    "lazy-read supplemental results",
                    128 * 1024 * 1024,
                    require_single_link=True,
                ),
            )
            if lazy_projection["transport_request_count"] != (
                self.results_count + self.supplemental_results_count
            ):
                fail("lazy-read validated denominator differs from result counters")
        except (LazyReadError, ContractError, OSError) as exc:
            fail(str(exc))
        self.lazy_read_finalized = True

    def verify_bound_host_directory_alias(
        self, bound_directory: Path, host_directory: Path, label: str
    ) -> None:
        """Prove a child-created real directory is below the held evidence inode."""

        if (
            self.evidence_dir != self.evidence_binding.bound_path
            or self.host_evidence_dir != self.evidence_binding.path
        ):
            fail(f"{label} binding contract is inconsistent")
        try:
            bound_relative = bound_directory.relative_to(self.evidence_dir)
            host_relative = host_directory.relative_to(self.host_evidence_dir)
        except ValueError:
            fail(f"{label} is outside the evidence directory")
        if (
            bound_relative != host_relative
            or not bound_relative.parts
            or any(part in {"", ".", ".."} for part in bound_relative.parts)
        ):
            fail(f"{label} aliases do not identify the same safe relative path")

        self.evidence_binding.verify_path()
        try:
            bound_info = bound_directory.lstat()
            host_info = host_directory.lstat()
        except OSError as exc:
            fail(f"{label} cannot be verified: {type(exc).__name__}")
        bound_security = (
            bound_info.st_uid,
            bound_info.st_gid,
            stat.S_IMODE(bound_info.st_mode),
        )
        host_security = (
            host_info.st_uid,
            host_info.st_gid,
            stat.S_IMODE(host_info.st_mode),
        )
        if (
            stat.S_ISLNK(bound_info.st_mode)
            or stat.S_ISLNK(host_info.st_mode)
            or not stat.S_ISDIR(bound_info.st_mode)
            or not stat.S_ISDIR(host_info.st_mode)
            or (bound_info.st_dev, bound_info.st_ino)
            != (host_info.st_dev, host_info.st_ino)
            or bound_security != host_security
            or host_security[:2] != self.evidence_binding.path_security[:2]
            or (os.name == "posix" and host_security[2] & 0o077)
        ):
            fail(f"{label} is not the descriptor-bound private directory")
        self.evidence_binding.verify_path()

    @staticmethod
    def _required_csam_setting(name: str) -> str:
        value = os.environ.get(name, "")
        if not value or len(value) > 4096 or any(ord(char) < 0x20 for char in value):
            fail(f"CSAM live runner setting is missing or malformed: {name}")
        return value

    def run_csam_text_evidence(self) -> None:
        """Run and validate the independent synthetic CSAM live plane.

        The hook and private endpoints are deliberately operator-owned inputs;
        this runner never discovers or executes anything from the reviewed
        repositories or supplemental archive.  A missing hook/configuration is
        a hard failure, rather than a silent downgrade to a synthetic PASS.
        """

        if self.csam_text_validated:
            fail("CSAM text evidence was executed twice")
        cpa_url = self._required_csam_setting("CAG_CSAM_TEXT_CPA_URL")
        mock_url = self._required_csam_setting("CAG_CSAM_TEXT_MOCK_URL")
        hook = self._required_csam_setting("CAG_CSAM_TEXT_COLD_START_HOOK")
        hook_path = Path(hook)
        if not hook_path.is_absolute():
            fail("CAG_CSAM_TEXT_COLD_START_HOOK must be an absolute path")
        # The producer intentionally rejects proc-fd magic-link parents. Give
        # it the verified normal Host alias, while this parent runner keeps all
        # reads below the descriptor-bound alias after proving both names refer
        # to the same private inode.
        output = self.evidence_dir / "csam-text"
        host_output = self.host_evidence_dir / "csam-text"
        runtime_root = self.host_evidence_dir / ".csam-runtime"
        self.evidence_binding.verify_path()
        if os.path.lexists(output) or os.path.lexists(host_output):
            fail("CSAM evidence output must be absent before execution")
        if os.path.lexists(runtime_root):
            fail("CSAM runtime root must be absent before execution")
        self.evidence_binding.verify_path()
        command = [
            sys.executable,
            "-I",
            "-B",
            str(TOOL_DIR / "csam_text_runner.py"),
            "--run-id",
            self.run_id,
            "--output-dir",
            str(host_output),
            "--cpa-url",
            cpa_url,
            "--mock-url",
            mock_url,
            "--cold-start-hook",
            str(hook_path),
            "--runtime-root",
            str(runtime_root),
        ]
        allowed_env = {
            "PATH": "/usr/bin:/bin",
            "LANG": "C",
            "LC_ALL": "C",
            "PYTHONNOUSERSITE": "1",
        }
        for name in (
            "CAG_CSAM_CLIENT_KEY",
            "CAG_CSAM_MANAGEMENT_KEY",
            "CAG_CSAM_MOCK_CONTROL_TOKEN",
            "CAG_CSAM_UPSTREAM_KEY",
        ):
            allowed_env[name] = self._required_csam_setting(name)
        completed: subprocess.CompletedProcess[bytes] | None = None
        invocation_error: BaseException | None = None
        try:
            completed = subprocess.run(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=allowed_env,
                timeout=3_600,
                check=False,
                shell=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            invocation_error = exc
        binding_error: AuditFailure | None = None
        try:
            self.evidence_binding.verify_path()
        except AuditFailure as exc:
            binding_error = exc
        cleanup_errors: list[str] = []
        if os.path.lexists(runtime_root):
            try:
                remove_owned_tree(runtime_root)
            except BaseException as exc:
                cleanup_errors.append(f"runtime:{type(exc).__name__}")
        try:
            if not self.owned_resources_absent():
                self.cleanup.emergency()
            if not self.owned_resources_absent():
                cleanup_errors.append("docker:resources_remain")
        except BaseException as exc:
            cleanup_errors.append(f"docker:{type(exc).__name__}")
        if cleanup_errors:
            raise CleanupFailure(sorted(set(cleanup_errors)))
        if binding_error is not None:
            raise binding_error
        if invocation_error is not None:
            fail(
                "CSAM live runner invocation failed: "
                f"{type(invocation_error).__name__}"
            )
        if completed is None:  # pragma: no cover - defensive exhaustiveness
            fail("CSAM live runner invocation produced no result")
        if completed.returncode != 0:
            diagnostic = sha256_bytes(
                completed.stdout[:4096] + b"\x00" + completed.stderr[:4096]
            )
            fail(
                "CSAM live runner did not produce PASS; "
                f"diagnostic_sha256={diagnostic}"
            )
        self.verify_bound_host_directory_alias(
            output, host_output, "CSAM evidence output"
        )
        expected_names = {
            "fixture-manifest.json",
            "results.json",
            "summary.json",
            "privacy-cleanup.json",
        }
        try:
            children = {child.name for child in output.iterdir()}
        except OSError as exc:
            fail(f"CSAM evidence directory is unavailable: {type(exc).__name__}")
        if children != expected_names:
            fail("CSAM evidence directory contains unexpected or missing files")
        try:
            fixture = load_json_bytes(
                read_regular_bytes(
                    output / "fixture-manifest.json",
                    "CSAM fixture manifest",
                    2 * 1024 * 1024,
                    require_single_link=True,
                ),
                "CSAM fixture manifest",
            )
            results = load_json_bytes(
                read_regular_bytes(
                    output / "results.json",
                    "CSAM results",
                    64 * 1024 * 1024,
                    require_single_link=True,
                ),
                "CSAM results",
            )
            summary = load_json_bytes(
                read_regular_bytes(
                    output / "summary.json",
                    "CSAM summary",
                    2 * 1024 * 1024,
                    require_single_link=True,
                ),
                "CSAM summary",
            )
            cleanup = load_json_bytes(
                read_regular_bytes(
                    output / "privacy-cleanup.json",
                    "CSAM privacy cleanup",
                    2 * 1024 * 1024,
                    require_single_link=True,
                ),
                "CSAM privacy cleanup",
            )
            validate_csam_text_evidence(
                fixture,
                results,
                summary,
                cleanup,
                expected_run_id=self.run_id,
            )
        except (ContractError, OSError, ValueError) as exc:
            fail(f"CSAM live evidence failed closed: {type(exc).__name__}")
        self.csam_text_validated = True

    def owned_resources_absent(self) -> bool:
        return all(
            self.docker.absent(kind, name)
            for kind, name in (
                ("container", self.cpa_name),
                ("container", self.mock_name),
                ("network", self.network_name),
            )
        )

    def machine_evidence(
        self,
        started_at: str,
        business_before: list[dict[str, Any]],
        business_after: list[dict[str, Any]],
    ) -> dict[str, Any]:
        if self.supplemental_manifest is None:
            fail("supplemental ZIP manifest is unavailable for machine evidence")
        cpa_config = self.config["identities"]["cpa"]
        mock_config = self.config["identities"]["mock"]
        cleanup = {
            "all_owned_resources_absent": self.owned_resources_absent(),
            "checkpoint_attempts": self.cleanup.checkpoint_attempts,
            "global_prune_used": False,
            "graceful_stop_attempts": self.cleanup.graceful_stop_attempts,
            "images_removed": False,
            "resources": self.cleanup.resources,
            "supplemental_input_archive_preserved": self.supplemental_archive_preserved,
            "supplemental_member_text_files_created": 0,
            "supplemental_member_text_files_removed": 0,
            "supplemental_member_text_retained": self.supplemental_member_text_retained,
            "third_party_text_files_removed": self.cleanup.text_files_removed,
            "third_party_text_retained": self.cleanup.text_retained,
        }
        evidence = {
            "business_snapshots": {
                "after": business_after,
                "after_sha256": sha256_bytes(canonical_bytes(business_after)),
                "before": business_before,
                "before_sha256": sha256_bytes(canonical_bytes(business_before)),
                "unchanged": business_before == business_after,
            },
            "claim_boundary": CLAIM_BOUNDARY,
            "cleanup": cleanup,
            "cold_starts": self.cold_evidence,
            "completed_at": now_iso(),
            "corpus": {
                "artifact_status": self.manifest["artifact_status"],
                "manifest_path": "corpus-manifest.json",
                "manifest_sha256": sha256_bytes(self.manifest_raw),
                "policy_review_status": self.manifest["policy_review_status"],
                "repository_count": self.manifest["repository_count"],
                "source_count": self.manifest["source_count"],
                "unique_content_hashes": self.manifest["unique_content_hashes"],
                "unique_semantic_cases": self.manifest["unique_semantic_cases"],
            },
            "identities": {
                "candidate": self.config["identities"]["candidate"],
                "cag": {
                    "commit": self.config["identities"]["cag"]["commit"],
                    "so_name": self.config["identities"]["cag"]["so_name"],
                    "so_sha256": self.config["identities"]["cag"]["so_sha256"],
                    "source_version": self.config["identities"]["cag"]["source_version"],
                    "tree": self.config["identities"]["cag"]["tree"],
                },
                "configuration": {
                    "input_sha256": sha256_bytes(self.config_raw),
                    "runtime_sha256s": self.runtime_hashes,
                },
                "cpa": {
                    "binary_path": cpa_config["binary_path"],
                    "binary_sha256": cpa_config["binary_sha256"],
                    "c_abi": cpa_config["c_abi"],
                    "commit": cpa_config["commit"],
                    "image_id": cpa_config["image_id"],
                    "official_asset_name": cpa_config["official_asset_name"],
                    "official_asset_sha256": cpa_config["official_asset_sha256"],
                    "repo_digest": cpa_config["repo_digest"],
                    "rpc_schema": cpa_config["rpc_schema"],
                    "tag": cpa_config["tag"],
                },
                "mock": {
                    "contract": mock_config["contract"],
                    "image_id": mock_config["image_id"],
                    "repo_digest": mock_config["repo_digest"],
                    "source_sha256": mock_config["source_sha256"],
                },
                "runner": self.runner_identity,
            },
            "infrastructure_errors": [],
            "run": {
                "cold_start_count": self.cold_count,
                "platform": "linux/amd64",
                "run_id": self.run_id,
                "seed": self.seed,
            },
            "realtime": {
                "authenticated_dynamic_evidence": "NOT_PERFORMED_PROVIDER_SAFETY_BOUNDARY",
                "cag_visible": False,
                "cold_starts": self.realtime_evidence,
                "evidence_level": "AUTH_BOUNDARY_ONLY",
                "protection": "unprotected",
                "real_provider_calls": 0,
                "route_count": len(REALTIME_ROUTES),
                "source_topology": "SOURCE_TOPOLOGY_UNPROTECTED",
            },
            "schema": EVIDENCE_SCHEMA,
            "started_at": started_at,
            "supplemental_zip_manifest": {
                "archive_bytes": self.supplemental_manifest["archive"]["bytes"],
                "archive_sha256": self.supplemental_manifest["archive"]["sha256"],
                "code_executions": 0,
                "manifest_path": "supplemental-zip-manifest.json",
                "manifest_sha256": sha256_bytes(self.supplemental_manifest_raw),
                "member_text_files_created": 0,
                "policy_path": "supplemental-zip-policy.json",
                "policy_sha256": sha256_bytes(self.supplemental_policy_raw),
                "selected_entry_count": self.supplemental_manifest[
                    "selected_entry_count"
                ],
                "third_party_code_executions": 0,
                "unique_reviewed_cases": self.supplemental_manifest[
                    "unique_reviewed_cases"
                ],
            },
            "supplemental_zip_results": {
                "modes": list(MODES),
                "protocols": list(PROTOCOLS),
                "results_path": "supplemental-zip-results.jsonl",
                "results_sha256": sha256_file(self.supplemental_results_path),
                "streams": list(STREAM_VALUES),
                "supplemental_executions": self.supplemental_results_count,
            },
            "supplemental_zip_summary": {
                "allow_executions": self.supplemental_action_counts["allow"],
                "block_incomplete_inspection_executions": self.supplemental_action_counts[
                    "block_incomplete_inspection"
                ],
                "block_malicious_text_executions": self.supplemental_action_counts[
                    "block_malicious_text"
                ],
                "code_executions": 0,
                "malicious_case_count": sum(
                    case["label"] == "malicious_active"
                    for case in self.supplemental_cases.values()
                ),
                "passed_executions": self.supplemental_results_count,
                "third_party_code_executions": 0,
                "total_executions": self.supplemental_results_count,
                "transport_error_executions": self.supplemental_action_counts[
                    "transport_error"
                ],
            },
            "third_party_code_executions": 0,
            "transport": {
                "modes": list(MODES),
                "protocols": list(PROTOCOLS),
                "results_path": "transport-results.jsonl",
                "results_sha256": sha256_file(self.results_path),
                "streams": list(STREAM_VALUES),
                "transport_executions": self.results_count,
            },
        }
        return evidence

    def execute(self, started_at: str) -> dict[str, Any]:
        succeeded = False
        business_before: list[dict[str, Any]] = []
        business_after: list[dict[str, Any]] = []
        try:
            try:
                self.lazy_read = LazyReadRecorder(self.evidence_dir, self.run_id)
            except LazyReadError as exc:
                fail(str(exc))
            self.failure_stage = "static_inputs"
            self.verify_static_inputs()
            write_exclusive(self.evidence_dir / "corpus-manifest.json", self.manifest_raw)
            write_exclusive(self.evidence_dir / "run-config.json", self.config_raw)
            write_exclusive(
                self.evidence_dir / "supplemental-zip-policy.json",
                self.supplemental_policy_raw,
            )
            write_exclusive(
                self.evidence_dir / "supplemental-zip-manifest.json",
                self.supplemental_manifest_raw,
            )
            business_before = business_snapshot(self.docker, self.run_id)
            self.runtime_root.mkdir(mode=0o700)
            os.chmod(self.runtime_root, 0o700)
            self.open_results()
            self.failure_stage = "network_create"
            self.create_network()
            ordinal_offset = 0
            supplemental_ordinal_offset = 0
            for cold_start in range(1, self.cold_count + 1):
                core_count, supplemental_count = self.run_cold_start(
                    cold_start, ordinal_offset, supplemental_ordinal_offset
                )
                ordinal_offset += core_count
                supplemental_ordinal_offset += supplemental_count
            self.close_results()
            self.failure_stage = "network_cleanup"
            self.cleanup.remove_network()
            cag_post = git_identity(Path(self.config["paths"]["cag_repository"]))
            require_git_tracked_clean(Path(self.config["paths"]["cag_repository"]))
            if cag_post != self.cag_pre:
                fail("CAG source HEAD/tree moved during the audit")
            business_after = business_snapshot(self.docker, self.run_id)
            self.verify_supplemental_archive_identity()
            self.supplemental_archive_preserved = True
            self.failure_stage = "evidence_finalize"
            succeeded = True
        finally:
            cleanup_errors: list[str] = []
            try:
                self.close_results()
            except BaseException as cleanup_exc:
                cleanup_errors.append(f"close_results:{type(cleanup_exc).__name__}")
            if not succeeded:
                try:
                    self.cleanup.emergency()
                except BaseException as cleanup_exc:
                    cleanup_errors.append(f"emergency:{type(cleanup_exc).__name__}")
            if self.corpus_validated:
                try:
                    self.remove_corpus_texts()
                except BaseException as cleanup_exc:
                    cleanup_errors.append(f"corpus:{type(cleanup_exc).__name__}")
            if self.runtime_root.is_symlink():
                cleanup_errors.append("runtime:replaced_symlink")
            elif self.runtime_root.exists():
                try:
                    remove_owned_tree(self.runtime_root)
                except BaseException as cleanup_exc:
                    cleanup_errors.append(f"runtime:{type(cleanup_exc).__name__}")
            if self.bound_corpus is not None:
                try:
                    self.bound_corpus.close()
                except BaseException as cleanup_exc:
                    cleanup_errors.append(f"corpus_fds:{type(cleanup_exc).__name__}")
                finally:
                    self.bound_corpus = None
            self.supplemental_texts_zeroized = _zeroize_supplemental_texts(
                self.supplemental_texts
            )
            if succeeded and not cleanup_errors:
                try:
                    self.run_csam_text_evidence()
                except BaseException as csam_exc:
                    cleanup_errors.append(f"csam_text:{type(csam_exc).__name__}")
            if succeeded and not cleanup_errors:
                try:
                    self.finalize_lazy_read()
                except BaseException as lazy_exc:
                    cleanup_errors.append(f"lazy_read:{type(lazy_exc).__name__}")
            elif not self.lazy_read_finalized:
                self._abort_lazy_read()
            if cleanup_errors:
                raise CleanupFailure(cleanup_errors)
        evidence = self.machine_evidence(started_at, business_before, business_after)
        validate_machine_evidence(
            self.manifest,
            evidence,
            self.results_path,
            corpus_root=None,
            supplemental_results_path=self.supplemental_results_path,
        )
        write_json(self.evidence_dir / "machine-evidence.json", evidence)
        return evidence


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True, help="canonical run-config JSON")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    started_at = now_iso()
    evidence_dir: Path | None = None
    evidence_dir_created = False
    evidence_binding: BoundEvidenceDirectory | None = None
    cleanup_manifest: tuple[dict[str, Any], Path] | None = None
    harness: Harness | None = None
    try:
        config_value, config_raw = load_canonical(args.config, "run config", MAX_CONFIG_BYTES)
        config = validate_run_config(config_value)
        manifest_path = Path(config["paths"]["corpus_manifest"])
        manifest, manifest_raw = load_canonical(
            manifest_path, "corpus manifest", 64 * 1024 * 1024
        )
        require_private_directory(manifest_path.parent, "acquisition root")
        require_private_directory(
            manifest_path.parent / "corpus", "private corpus directory"
        )
        validate_corpus_manifest(manifest, manifest_path.parent)
        cleanup_manifest = (manifest, manifest_path.parent)
        validate_candidate_manifest_file(config)
        policy_raw = read_regular_bytes(POLICY_PATH, "fixed source policy", 2 * 1024 * 1024)
        policy_sha256 = sha256_bytes(policy_raw)
        if (
            config["policy_sha256"] != policy_sha256
            or manifest["policy_sha256"] != policy_sha256
        ):
            fail("source policy identity is not closed across config, tool, and corpus")
        policy = validate_policy(
            load_json_bytes(policy_raw, "fixed source policy"), require_approved=True
        )
        validate_manifest_policy(manifest, policy, require_approved=True)
        evidence_dir = Path(config["paths"]["evidence_directory"])
        evidence_binding = BoundEvidenceDirectory.create(evidence_dir)
        evidence_dir_created = True
        harness = Harness(
            config,
            config_raw,
            manifest,
            manifest_raw,
            evidence_binding,
            Docker(),
        )
        evidence = harness.execute(started_at)
        evidence_binding.verify_path()
        print(
            json.dumps(
                {
                    "completed": True,
                    "evidence": str(evidence_dir / "machine-evidence.json"),
                    "supplemental_code_executions": evidence[
                        "supplemental_zip_summary"
                    ]["code_executions"],
                    "supplemental_executions": evidence[
                        "supplemental_zip_results"
                    ]["supplemental_executions"],
                    "third_party_code_executions": evidence["third_party_code_executions"],
                    "transport_executions": evidence["transport"]["transport_executions"],
                },
                sort_keys=True,
            ),
            flush=True,
        )
        return 0
    except BaseException as exc:
        error_id = sha256_bytes(str(exc).encode("utf-8"))[:16]
        cleanup_error_ids: list[str] = []
        if isinstance(exc, CleanupFailure):
            cleanup_error_ids.append(exc.cleanup_error_id)
        if cleanup_manifest is not None and not (
            harness is not None and harness.corpus_cleanup_completed
        ):
            try:
                remove_manifest_corpus(*cleanup_manifest)
            except BaseException as cleanup_exc:
                cleanup_error_ids.append(
                    cleanup_exc.cleanup_error_id
                    if isinstance(cleanup_exc, CleanupFailure)
                    else sha256_bytes(str(cleanup_exc).encode("utf-8"))[:16]
                )
        unique_cleanup_error_ids = sorted(set(cleanup_error_ids))
        cleanup_error_id: str | None = None
        if len(unique_cleanup_error_ids) == 1:
            cleanup_error_id = unique_cleanup_error_ids[0]
        elif unique_cleanup_error_ids:
            cleanup_error_id = sha256_bytes(
                canonical_bytes(unique_cleanup_error_ids)
            )[:16]
        if evidence_binding is not None:
            try:
                evidence_binding.verify_path()
            except BaseException as cleanup_exc:
                cleanup_error_ids.append(
                    sha256_bytes(str(cleanup_exc).encode("utf-8"))[:16]
                )
                unique_cleanup_error_ids = sorted(set(cleanup_error_ids))
                cleanup_error_id = (
                    unique_cleanup_error_ids[0]
                    if len(unique_cleanup_error_ids) == 1
                    else sha256_bytes(canonical_bytes(unique_cleanup_error_ids))[:16]
                )
        if evidence_dir_created and evidence_binding is not None:
            failure_path = evidence_binding.bound_path / "failure.json"
            if not failure_path.exists():
                failure_stage = getattr(harness, "failure_stage", None)
                if (
                    not isinstance(failure_stage, str)
                    or re.fullmatch(r"[a-z][a-z0-9_]{2,63}", failure_stage) is None
                ):
                    failure_stage = "bootstrap"
                state_sha256 = getattr(harness, "readiness_state_sha256", None)
                if not isinstance(state_sha256, str) or re.fullmatch(
                    r"[0-9a-f]{64}", state_sha256
                ) is None:
                    state_sha256 = None
                write_json(
                    failure_path,
                    {
                        "error_id": error_id,
                        "error_type": type(exc).__name__,
                        "failed_at": now_iso(),
                        "machine_evidence_emitted": False,
                        "cleanup_error_id": cleanup_error_id,
                        "failure_stage": failure_stage,
                        "state_sha256": state_sha256,
                        "third_party_code_executions": 0,
                        "traceback_sha256": sha256_bytes(
                            traceback.format_exc(limit=20).encode("utf-8")
                        ),
                    },
                )
        print(f"AUDIT FAILED CLOSED: error_id={error_id}", file=sys.stderr)
        return 2
    finally:
        if evidence_binding is not None:
            evidence_binding.close()


if __name__ == "__main__":
    raise SystemExit(main())
