#!/usr/bin/env python3
"""Generate and validate the Round 14 current-CPA audit unit-test receipt.

The release-document gate must never infer PASS from unittest discovery.  This
tool records one local Linux development execution and detects drift in the
tested implementation, test source bytes, and discovered test IDs.  Validation
is intentionally non-executing so document mutation tests can reuse the
reviewed receipt.  The receipt is unsigned repository-owned self-report; it is
not independent evidence and cannot replace exact-commit CI.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import platform
import re
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator, NoReturn, Sequence


SCHEMA = "cag-current-cpa-audit-unit-receipt/v1"
REVIEWED_TEST_COUNT = 315
REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
TOOL_ROOT = REPOSITORY_ROOT / "tools" / "current-cpa-audit"
TEST_ROOT = TOOL_ROOT / "tests"
RECEIPT_TOOL = Path(__file__).resolve()
TEST_PATTERN = "test_*.py"
TESTED_TOOL_FILES = (
    "Dockerfile.mock",
    "README.md",
    "acquire.py",
    "audit_contract.py",
    "counted_mock.py",
    "csam_text_evidence.py",
    "csam_text_runner.py",
    "host-performance-evidence.schema.json",
    "host-admission-evidence.schema.json",
    "host_admission.py",
    "host_performance.py",
    "host_performance_workloads.py",
    "lazy_read.py",
    "machine-evidence.schema.json",
    "make_run_config.py",
    "native-host-special-paths.schema.json",
    "native_host_special_paths.py",
    "repository-policy.json",
    "run.py",
    "second-machine-release-admission.schema.json",
    "second_machine_release_admission.py",
    "supplemental-zip-policy.json",
    "supplemental_zip.py",
    "validate.py",
)
TESTED_REPOSITORY_FILES = (
    ".github/workflows/ci.yml",
    "integration/host_integration_test.go",
    "scripts/current_cpa_audit_unit_receipt.py",
    "testdata/development-public-jailbreak-patterns-v1/cases.jsonl",
)
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
# Every file hashed into the runner identity must also be read into the signed
# source closure.  Keep this fail-closed assertion next to the two lists so a
# new runtime import cannot silently escape receipt coverage.
if not set(RUNNER_BUNDLE_FILES).issubset(TESTED_TOOL_FILES):
    raise RuntimeError("runner bundle contains a file outside the tested source closure")
TRUSTED_TEST_PATH = "/usr/bin:/bin"
COMMAND_SUFFIX = (
    "-I",
    "-B",
    "-m",
    "unittest",
    "discover",
    "-s",
    "tools/current-cpa-audit/tests",
    "-p",
    TEST_PATTERN,
)
RUNNER_IDENTITY_KEYS = (
    "bundle_sha256",
    "audit_contract_sha256",
    "run_source_sha256",
    "machine_schema_sha256",
)
PASS_SUMMARY = re.compile(
    r"(?:^|\n)Ran ([1-9][0-9]*) tests? in ([0-9]+(?:\.[0-9]+)?)s\n\n"
    r"OK(?: \(skipped=([1-9][0-9]*)\))?\s*\Z"
)
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
MAX_TIMESTAMP_ELAPSED_DELTA_MS = 5_000
UTC_TIMESTAMP = re.compile(
    r"(20[0-9]{2})-(0[1-9]|1[0-2])-([0-2][0-9]|3[01])T"
    r"([01][0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9])\.([0-9]{3})Z\Z"
)
DISCOVERY_SCRIPT = """\
import json
import sys
import unittest
from pathlib import Path

root = Path.cwd()
tool = root / "tools" / "current-cpa-audit"
tests = tool / "tests"
sys.path[:0] = [str(tests), str(tool)]
loader = unittest.TestLoader()
suite = loader.discover(str(tests), pattern="test_*.py")
if loader.errors:
    raise SystemExit(" | ".join(loader.errors))

def flatten(value):
    for item in value:
        if isinstance(item, unittest.TestSuite):
            yield from flatten(item)
        else:
            yield item

identities = sorted(test.id() for test in flatten(suite))
print(json.dumps(identities, ensure_ascii=False, separators=(",", ":")))
"""


class ReceiptError(RuntimeError):
    """The unit-test receipt is absent, stale, malformed, or not a PASS."""


def fail(message: str) -> NoReturn:
    raise ReceiptError(message)


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def read_regular_bytes(path: Path, label: str, limit: int) -> bytes:
    try:
        info = path.lstat()
    except FileNotFoundError:
        fail(f"{label} is missing: {path}")
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
        fail(f"{label} must be a regular non-symlink file: {path}")
    if info.st_nlink != 1:
        fail(f"{label} must have exactly one hard link: {path}")
    if info.st_size > limit:
        fail(f"{label} exceeds its byte limit: {path}")
    flags = os.O_RDONLY
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            fail(f"{label} descriptor is not a regular file: {path}")
        if (
            opened.st_dev,
            opened.st_ino,
            opened.st_mode,
            opened.st_nlink,
            opened.st_size,
            opened.st_mtime_ns,
            opened.st_ctime_ns,
        ) != (
            info.st_dev,
            info.st_ino,
            info.st_mode,
            info.st_nlink,
            info.st_size,
            info.st_mtime_ns,
            info.st_ctime_ns,
        ):
            fail(f"{label} changed while opening: {path}")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, limit + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            if total > limit:
                fail(f"{label} exceeds its byte limit: {path}")
            chunks.append(chunk)
        after = os.fstat(descriptor)
        if (
            opened.st_dev,
            opened.st_ino,
            opened.st_mode,
            opened.st_nlink,
            opened.st_size,
            opened.st_mtime_ns,
            opened.st_ctime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_nlink,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            fail(f"{label} changed while reading: {path}")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            fail(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def reject_constant(value: str) -> NoReturn:
    fail(f"non-finite JSON number is forbidden: {value}")


def load_json(path: Path) -> tuple[dict[str, Any], bytes]:
    raw = read_regular_bytes(path, "Round 14 audit unit receipt", 2 * 1024 * 1024)
    try:
        value = json.loads(
            raw,
            object_pairs_hook=reject_duplicate_pairs,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        fail(f"Round 14 audit unit receipt is not strict UTF-8 JSON: {exc}")
    if type(value) is not dict:
        fail("Round 14 audit unit receipt must be a JSON object")
    if raw != canonical_bytes(value) + b"\n":
        fail("Round 14 audit unit receipt must use canonical JSON plus one LF")
    return value, raw


def exact_keys(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict:
        fail(f"{label} must be an object")
    actual = set(value)
    if actual != keys:
        missing = sorted(keys - actual)
        unknown = sorted(actual - keys)
        fail(f"{label} keys differ; missing={missing}, unknown={unknown}")
    return value


def exact_int(value: Any, label: str, *, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        fail(f"{label} must be an integer >= {minimum}")
    return value


def exact_string(value: Any, label: str, *, maximum: int = 1_000_000) -> str:
    if type(value) is not str or not value or len(value.encode("utf-8")) > maximum:
        fail(f"{label} must be a non-empty bounded string")
    return value


def exact_digest(value: Any, label: str) -> str:
    digest = exact_string(value, label, maximum=64)
    if HEX64.fullmatch(digest) is None:
        fail(f"{label} must be a lowercase SHA-256")
    return digest


def parse_timestamp(value: Any, label: str) -> datetime:
    raw = exact_string(value, label, maximum=24)
    if UTC_TIMESTAMP.fullmatch(raw) is None:
        fail(f"{label} must be millisecond UTC")
    try:
        parsed = datetime.strptime(raw, "%Y-%m-%dT%H:%M:%S.%fZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as exc:
        fail(f"{label} is not a real UTC timestamp: {exc}")
    return parsed


def format_utc_milliseconds(value: datetime) -> str:
    """Render UTC milliseconds by truncating, never rounding, smaller units."""

    return value.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def now_utc() -> str:
    return format_utc_milliseconds(datetime.now(timezone.utc))


def validate_elapsed_timing(
    started: datetime, finished: datetime, elapsed_ms: int
) -> None:
    """Bound monotonic elapsed time against truncated UTC endpoints.

    UTC and monotonic samples are adjacent rather than atomic.  Millisecond
    truncation normally accounts for at most one millisecond, while scheduler
    preemption between either sample pair can add a larger boundary delay.
    Keep that delay bounded so overloaded runners do not fail spuriously while
    materially inconsistent receipts are still rejected.
    """

    wall_ms = (finished - started) // timedelta(milliseconds=1)
    if wall_ms <= 0 or abs(wall_ms - elapsed_ms) > MAX_TIMESTAMP_ELAPSED_DELTA_MS:
        fail(
            "receipt execution wall and monotonic durations are inconsistent; "
            f"the maximum permitted difference is {MAX_TIMESTAMP_ELAPSED_DELTA_MS} ms"
        )


def iter_tests(suite: unittest.TestSuite) -> Iterable[unittest.TestCase]:
    for value in suite:
        if isinstance(value, unittest.TestSuite):
            yield from iter_tests(value)
        else:
            yield value


def runner_identities_from_sources(source_bytes: dict[str, bytes]) -> dict[str, str]:
    file_hashes = {
        name: sha256_bytes(source_bytes[f"tools/current-cpa-audit/{name}"])
        for name in RUNNER_BUNDLE_FILES
    }
    return {
        "audit_contract_sha256": file_hashes["audit_contract.py"],
        "bundle_sha256": sha256_bytes(canonical_bytes(file_hashes)),
        "machine_schema_sha256": file_hashes["machine-evidence.schema.json"],
        "run_source_sha256": file_hashes["run.py"],
    }


def source_closure_bytes() -> dict[str, bytes]:
    source_bytes: dict[str, bytes] = {}
    for name in TESTED_TOOL_FILES:
        path = TOOL_ROOT / name
        relative = path.relative_to(REPOSITORY_ROOT).as_posix()
        source_bytes[relative] = read_regular_bytes(
            path, f"tested audit implementation {relative}", 16 * 1024 * 1024
        )
    for relative in TESTED_REPOSITORY_FILES:
        path = REPOSITORY_ROOT / relative
        source_bytes[relative] = read_regular_bytes(
            path, f"tested repository input {relative}", 16 * 1024 * 1024
        )
    for path in sorted(TEST_ROOT.rglob("*.py")):
        relative = path.relative_to(REPOSITORY_ROOT).as_posix()
        source_bytes[relative] = read_regular_bytes(
            path, f"audit unit-test source {relative}", 16 * 1024 * 1024
        )
    if not source_bytes:
        fail("CPA audit unittest source closure is empty")
    return source_bytes


def trusted_environment() -> dict[str, str]:
    environment = os.environ.copy()
    environment.pop("PYTHONHOME", None)
    environment.pop("PYTHONPATH", None)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["GOTOOLCHAIN"] = "go1.26.6"
    environment["PATH"] = TRUSTED_TEST_PATH
    return environment


def discover_test_ids(python_executable: str, root: Path) -> list[str]:
    completed = subprocess.run(
        [python_executable, "-I", "-B", "-c", DISCOVERY_SCRIPT],
        cwd=root,
        env=trusted_environment(),
        check=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=60,
    )
    if completed.returncode != 0:
        diagnostic = completed.stderr.decode("utf-8", errors="replace")[:4096]
        fail(f"CPA audit unittest discovery failed in isolated snapshot: {diagnostic}")
    try:
        value = json.loads(completed.stdout.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        fail(f"CPA audit unittest discovery returned invalid JSON: {exc}")
    if type(value) is not list or any(type(item) is not str or not item for item in value):
        fail("CPA audit unittest discovery returned invalid test IDs")
    test_ids = sorted(value)
    if len(test_ids) != len(set(test_ids)):
        fail("CPA audit unittest discovery produced duplicate test IDs")
    if len(test_ids) != REVIEWED_TEST_COUNT:
        fail(
            "CPA audit unittest closure differs from the reviewed Round 14 "
            f"count: expected {REVIEWED_TEST_COUNT}, found {len(test_ids)}"
        )
    return test_ids


@contextlib.contextmanager
def materialized_snapshot(source_bytes: dict[str, bytes]) -> Iterator[Path]:
    with tempfile.TemporaryDirectory(prefix="cag-current-cpa-audit-unit-") as temporary:
        snapshot = Path(temporary).resolve(strict=True)
        os.chmod(snapshot, 0o700)
        for relative, raw in source_bytes.items():
            target = snapshot / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
            os.chmod(target, 0o400)
        yield snapshot


def closure_from_sources(
    source_bytes: dict[str, bytes], test_ids: Sequence[str]
) -> dict[str, Any]:
    source_hashes = {
        relative: sha256_bytes(raw) for relative, raw in sorted(source_bytes.items())
    }
    return {
        "runner": runner_identities_from_sources(source_bytes),
        "test_count": len(test_ids),
        "test_file_count": len(source_hashes),
        "test_ids_sha256": sha256_bytes(canonical_bytes(sorted(test_ids))),
        "test_sources_sha256": sha256_bytes(canonical_bytes(source_hashes)),
        "receipt_tool_sha256": sha256_bytes(
            read_regular_bytes(RECEIPT_TOOL, "audit unit receipt tool", 2 * 1024 * 1024)
        ),
    }


def current_closure() -> dict[str, Any]:
    sys.dont_write_bytecode = True
    tool = TOOL_ROOT.resolve(strict=True)
    tests = TEST_ROOT.resolve(strict=True)
    for candidate in (tool, tests):
        if candidate.is_symlink() or not candidate.is_dir():
            fail(f"audit unit-test directory is unsafe: {candidate}")

    source_bytes = source_closure_bytes()
    python_executable = str(Path(sys.executable).resolve(strict=True))
    with materialized_snapshot(source_bytes) as snapshot:
        test_ids = discover_test_ids(python_executable, snapshot)
    return closure_from_sources(source_bytes, test_ids)


def remove_and_reject_bytecode(*, remove: bool) -> None:
    for bytecode in TOOL_ROOT.rglob("*.pyc"):
        if not remove:
            fail(f"audit tool bytecode cache is forbidden: {bytecode}")
        bytecode.unlink(missing_ok=True)
    for cache in sorted(
        (path for path in TOOL_ROOT.rglob("__pycache__") if path.is_dir()),
        key=lambda path: len(path.parts),
        reverse=True,
    ):
        if not remove:
            fail(f"audit tool bytecode cache is forbidden: {cache}")
        try:
            cache.rmdir()
        except OSError:
            fail(f"audit tool bytecode cache could not be removed: {cache}")
    if any(TOOL_ROOT.rglob("*.pyc")) or any(TOOL_ROOT.rglob("__pycache__")):
        fail("audit tool bytecode cache remains present")


def parse_pass_summary(stderr: str) -> tuple[int, int, int]:
    match = PASS_SUMMARY.search(stderr.replace("\r\n", "\n"))
    if match is None:
        fail("unittest stderr does not contain one terminal PASS summary")
    tests_run = int(match.group(1))
    skipped = int(match.group(3) or 0)
    duration_ms = round(float(match.group(2)) * 1000)
    return tests_run, skipped, duration_ms


def validate_receipt(path: Path) -> tuple[dict[str, Any], bytes]:
    remove_and_reject_bytecode(remove=False)
    receipt, raw = load_json(path)
    receipt = exact_keys(
        receipt,
        {"closure", "environment", "execution", "result", "schema"},
        "receipt",
    )
    if receipt["schema"] != SCHEMA:
        fail("receipt.schema differs from the Round 14 contract")

    closure = exact_keys(
        receipt["closure"],
        {
            "audit_contract_sha256",
            "machine_schema_sha256",
            "receipt_tool_sha256",
            "run_source_sha256",
            "runner_bundle_sha256",
            "test_count",
            "test_file_count",
            "test_ids_sha256",
            "test_sources_sha256",
        },
        "receipt.closure",
    )
    environment = exact_keys(
        receipt["environment"],
        {
            "go_toolchain",
            "kernel_release",
            "machine",
            "python_executable",
            "python_implementation",
            "python_version",
            "system",
        },
        "receipt.environment",
    )
    execution = exact_keys(
        receipt["execution"],
        {
            "command",
            "cwd",
            "elapsed_ms",
            "finished_at",
            "return_code",
            "started_at",
            "stderr",
            "stderr_bytes",
            "stderr_sha256",
            "stdout",
            "stdout_bytes",
            "stdout_sha256",
        },
        "receipt.execution",
    )
    result = exact_keys(
        receipt["result"],
        {"errors", "failures", "skipped", "status", "tests_run", "unexpected_successes"},
        "receipt.result",
    )

    current = current_closure()
    closure_mapping = {
        "runner_bundle_sha256": current["runner"]["bundle_sha256"],
        "audit_contract_sha256": current["runner"]["audit_contract_sha256"],
        "run_source_sha256": current["runner"]["run_source_sha256"],
        "machine_schema_sha256": current["runner"]["machine_schema_sha256"],
        "receipt_tool_sha256": current["receipt_tool_sha256"],
        "test_ids_sha256": current["test_ids_sha256"],
        "test_sources_sha256": current["test_sources_sha256"],
    }
    for key, expected in closure_mapping.items():
        if exact_digest(closure[key], f"receipt.closure.{key}") != expected:
            fail(f"receipt.closure.{key} differs from the current source closure")
    for key in ("test_count", "test_file_count"):
        if exact_int(closure[key], f"receipt.closure.{key}", minimum=1) != current[key]:
            fail(f"receipt.closure.{key} differs from the current source closure")

    if environment["system"] != "Linux" or environment["machine"] != "x86_64":
        fail("receipt environment must be Linux x86_64")
    for key in (
        "kernel_release",
        "python_executable",
        "python_implementation",
        "python_version",
    ):
        exact_string(environment[key], f"receipt.environment.{key}", maximum=512)
    if environment["python_implementation"] != "CPython":
        fail("receipt environment must use CPython")
    if environment["go_toolchain"] != "go1.26.6":
        fail("receipt environment must retain GOTOOLCHAIN=go1.26.6")

    command = execution["command"]
    if type(command) is not list or any(type(item) is not str for item in command):
        fail("receipt.execution.command must be an array of strings")
    python_executable = exact_string(
        environment["python_executable"], "receipt.environment.python_executable", maximum=512
    )
    if tuple(command) != (python_executable, *COMMAND_SUFFIX):
        fail("receipt.execution.command differs from the reviewed unittest command")
    if execution["cwd"] != ".":
        fail("receipt.execution.cwd must be repository-relative dot")
    if exact_int(execution["return_code"], "receipt.execution.return_code") != 0:
        fail("receipt execution did not return zero")
    elapsed_ms = exact_int(execution["elapsed_ms"], "receipt.execution.elapsed_ms", minimum=1)
    started = parse_timestamp(execution["started_at"], "receipt.execution.started_at")
    finished = parse_timestamp(execution["finished_at"], "receipt.execution.finished_at")
    validate_elapsed_timing(started, finished, elapsed_ms)

    for stream in ("stdout", "stderr"):
        text = execution[stream]
        if type(text) is not str or len(text.encode("utf-8")) > 1024 * 1024:
            fail(f"receipt.execution.{stream} must be a bounded string")
        raw_stream = text.encode("utf-8")
        if exact_int(
            execution[f"{stream}_bytes"], f"receipt.execution.{stream}_bytes"
        ) != len(raw_stream):
            fail(f"receipt.execution.{stream}_bytes differs from embedded bytes")
        if exact_digest(
            execution[f"{stream}_sha256"], f"receipt.execution.{stream}_sha256"
        ) != sha256_bytes(raw_stream):
            fail(f"receipt.execution.{stream}_sha256 differs from embedded bytes")

    tests_run, skipped, reported_duration_ms = parse_pass_summary(execution["stderr"])
    if tests_run != current["test_count"] or tests_run != REVIEWED_TEST_COUNT:
        fail("receipt unittest PASS count differs from the reviewed current closure")
    if abs(reported_duration_ms - elapsed_ms) > 10_000:
        fail("receipt unittest duration is inconsistent with the execution duration")
    if execution["stdout"]:
        fail("receipt unittest command must not emit stdout")

    if result["status"] != "PASS":
        fail("receipt.result.status must be PASS")
    zero_fields = ("errors", "failures", "unexpected_successes")
    for key in zero_fields:
        if exact_int(result[key], f"receipt.result.{key}") != 0:
            fail(f"receipt.result.{key} must be zero")
    if exact_int(result["tests_run"], "receipt.result.tests_run", minimum=1) != tests_run:
        fail("receipt.result.tests_run differs from unittest stderr")
    if exact_int(result["skipped"], "receipt.result.skipped") != skipped:
        fail("receipt.result.skipped differs from unittest stderr")
    if skipped != 0:
        fail("Round 14 Linux audit unit receipt must not skip tests")
    return receipt, raw


def validate_receipt_bytes(path: Path) -> tuple[dict[str, Any], bytes]:
    """Validate from the already-read bytes and prove the path stayed stable."""

    receipt, raw = validate_receipt(path)
    if read_regular_bytes(path, "Round 14 audit unit receipt", 2 * 1024 * 1024) != raw:
        fail("Round 14 audit unit receipt changed after validation")
    return receipt, raw


def write_exclusive(path: Path, raw: bytes, replace: bool) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        fail(f"receipt output must not be a symlink: {path}")
    temporary: Path | None = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{path.name}.", dir=path.parent
        )
        temporary = Path(temporary_name)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o644)
        if not replace and path.exists():
            fail(f"receipt output already exists: {path}")
        os.replace(temporary, path)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def generate_receipt(output: Path, replace: bool) -> dict[str, Any]:
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        fail("Round 14 audit unit receipt generation requires Linux x86_64")
    remove_and_reject_bytecode(remove=True)
    source_bytes = source_closure_bytes()
    python_executable = str(Path(sys.executable).resolve(strict=True))
    command = [python_executable, *COMMAND_SUFFIX]
    environment = trusted_environment()
    with materialized_snapshot(source_bytes) as snapshot:
        test_ids = discover_test_ids(python_executable, snapshot)
        closure = closure_from_sources(source_bytes, test_ids)
        started_at = now_utc()
        started_monotonic = time.monotonic_ns()
        completed = subprocess.run(
            command,
            cwd=snapshot,
            env=environment,
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=15 * 60,
        )
    elapsed_ms = max(1, round((time.monotonic_ns() - started_monotonic) / 1_000_000))
    finished_at = now_utc()
    try:
        stdout = completed.stdout.decode("utf-8", errors="strict")
        stderr = completed.stderr.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        fail(f"unittest output is not UTF-8: {exc}")
    tests_run, skipped, _ = parse_pass_summary(stderr)
    if completed.returncode != 0:
        fail(f"unittest command failed with return code {completed.returncode}")
    if tests_run != closure["test_count"] or tests_run != REVIEWED_TEST_COUNT:
        fail("executed unittest count differs from the reviewed current closure")
    if skipped != 0:
        fail("executed Linux unittest suite skipped tests")
    if stdout:
        fail("executed unittest suite unexpectedly emitted stdout")
    remove_and_reject_bytecode(remove=False)
    post_closure = current_closure()
    if post_closure != closure:
        fail("audit unit source closure changed during execution")

    receipt = {
        "closure": {
            "audit_contract_sha256": closure["runner"]["audit_contract_sha256"],
            "machine_schema_sha256": closure["runner"]["machine_schema_sha256"],
            "receipt_tool_sha256": closure["receipt_tool_sha256"],
            "run_source_sha256": closure["runner"]["run_source_sha256"],
            "runner_bundle_sha256": closure["runner"]["bundle_sha256"],
            "test_count": closure["test_count"],
            "test_file_count": closure["test_file_count"],
            "test_ids_sha256": closure["test_ids_sha256"],
            "test_sources_sha256": closure["test_sources_sha256"],
        },
        "environment": {
            "go_toolchain": "go1.26.6",
            "kernel_release": platform.release(),
            "machine": platform.machine(),
            "python_executable": python_executable,
            "python_implementation": platform.python_implementation(),
            "python_version": platform.python_version(),
            "system": platform.system(),
        },
        "execution": {
            "command": command,
            "cwd": ".",
            "elapsed_ms": elapsed_ms,
            "finished_at": finished_at,
            "return_code": completed.returncode,
            "started_at": started_at,
            "stderr": stderr,
            "stderr_bytes": len(completed.stderr),
            "stderr_sha256": sha256_bytes(completed.stderr),
            "stdout": stdout,
            "stdout_bytes": len(completed.stdout),
            "stdout_sha256": sha256_bytes(completed.stdout),
        },
        "result": {
            "errors": 0,
            "failures": 0,
            "skipped": skipped,
            "status": "PASS",
            "tests_run": tests_run,
            "unexpected_successes": 0,
        },
        "schema": SCHEMA,
    }
    raw = canonical_bytes(receipt) + b"\n"
    write_exclusive(output, raw, replace)
    validate_receipt_bytes(output)
    return receipt


def output_lines(receipt: dict[str, Any], raw: bytes) -> None:
    closure = receipt["closure"]
    execution = receipt["execution"]
    result = receipt["result"]
    environment = receipt["environment"]
    values = (
        closure["runner_bundle_sha256"],
        closure["audit_contract_sha256"],
        closure["run_source_sha256"],
        closure["machine_schema_sha256"],
        str(result["tests_run"]),
        str(result["skipped"]),
        result["status"],
        execution["started_at"],
        execution["finished_at"],
        str(execution["elapsed_ms"]),
        sha256_bytes(raw),
        closure["test_sources_sha256"],
        closure["test_ids_sha256"],
        " ".join(execution["command"]),
        f"{environment['system']}/{environment['machine']}",
    )
    for value in values:
        print(value)


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    run_command = commands.add_parser("run", help="run tests and create a receipt")
    run_command.add_argument("--output", type=Path, required=True)
    run_command.add_argument("--replace", action="store_true")
    validate_command = commands.add_parser("validate", help="validate a receipt")
    validate_command.add_argument("--receipt", type=Path, required=True)
    validate_command.add_argument("--output-lines", action="store_true")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        if args.command == "run":
            generate_receipt(args.output, args.replace)
            receipt, raw = validate_receipt_bytes(args.output)
            output_lines(receipt, raw)
        else:
            receipt, raw = validate_receipt_bytes(args.receipt)
            if args.output_lines:
                output_lines(receipt, raw)
            else:
                print(
                    json.dumps(
                        {
                            "receipt_sha256": sha256_bytes(raw),
                            "status": receipt["result"]["status"],
                            "tests_run": receipt["result"]["tests_run"],
                            "valid": True,
                        },
                        sort_keys=True,
                    )
                )
        return 0
    except (OSError, ReceiptError, subprocess.SubprocessError) as exc:
        print(f"current CPA audit unit receipt error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
