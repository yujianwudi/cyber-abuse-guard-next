#!/usr/bin/env python3
"""Pack and validate owner-run native CPA Host special-path evidence.

The input log is produced by one exact ``go test -json`` invocation.  This
tool never copies test output into the portable summary: it retains only the
log hash, event counts, first-party test identities, and immutable candidate
and checkout identities.  The result is owner-run corroboration, not
independent proof and not a release admission by itself.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import platform
import re
import stat
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, NoReturn, Sequence

from audit_contract import (
    CAG_SO_NAME,
    CAG_SOURCE_VERSION,
    CANDIDATE_ARTIFACT_NAME,
    CANDIDATE_MANIFEST_NAME,
    CANDIDATE_MAX_BYTES,
    CANDIDATE_REPOSITORY,
    CANDIDATE_WORKFLOW_NAME,
    CANDIDATE_WORKFLOW_PATH,
    CPA_COMMIT,
    CPA_TAG,
    ContractError,
    canonical_bytes,
    load_json_bytes,
    read_candidate_manifest,
    read_regular_bytes,
    regular_file_info,
    sha256_bytes,
)


SCHEMA = "cyber-abuse-guard.native-host-special-paths.v1"
STATUS = "NATIVE_HOST_SPECIAL_PATHS_PASS"
BOUNDARY = "OWNER-RUN NATIVE HOST SPECIAL-PATH EVIDENCE; NOT INDEPENDENT PROOF"
SCHEMA_NAME = "native-host-special-paths.schema.json"
REPORT_NAME = "native-host-special-paths.json"
PLATFORM = "linux/amd64"
GO_VERSION = "go1.26.4"
PACKAGE = "github.com/yujianwudi/cyber-abuse-guard-next/integration"
TOP_LEVEL_TEST = "TestCPAPluginHostBlocksBeforeUpstream"
TEST_SOURCE = "integration/host_integration_test.go"
MAX_REPORT_BYTES = 4 * 1024 * 1024
MAX_LOG_BYTES = 64 * 1024 * 1024
MAX_CANDIDATE_FILE_BYTES = 512 * 1024 * 1024
MAX_ARTIFACT_BYTES = 1024 * 1024 * 1024
SCRIPT_PATH = Path(__file__).resolve()
SCHEMA_PATH = SCRIPT_PATH.parent / SCHEMA_NAME
HEX40 = re.compile(r"[0-9a-f]{40}")
HEX64 = re.compile(r"[0-9a-f]{64}")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
UTC = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z"
)
SAFE_BRANCH = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,254}")

COMMAND = (
    "go",
    "test",
    "-json",
    "-count=1",
    "-run=^TestCPAPluginHostBlocksBeforeUpstream$",
    "-tags=integration,sqlite_omit_load_extension",
    "./integration",
)

EXPECTED_CANDIDATE_FILES = (
    CAG_SO_NAME,
    CAG_SO_NAME + ".sha256",
    f"cyber-abuse-guard_{CAG_SOURCE_VERSION}_linux_amd64.zip",
    CANDIDATE_MANIFEST_NAME,
    "build-metadata.json",
    "checksums.txt",
    "ruleset-manifest.json",
    "ruleset.sha256",
    "sbom.cdx.json",
)


def _multi_agent_tests() -> list[tuple[str, str]]:
    result: list[tuple[str, str]] = []
    for client in ("desktop", "tui", "cli-rs"):
        for transport in ("http", "sse"):
            result.append(("multi_agent_v2", f"allow-codex-multi-agent-v2-{client}-{transport}"))
            result.append(("multi_agent_v2", f"block-codex-multi-agent-v2-{client}-{transport}"))
    for transport in ("http", "sse"):
        result.append(
            (
                "multi_agent_v2",
                f"allow-codex-multi-agent-v2-inert-tool-description-{transport}",
            )
        )
    return result


def _ordered_tool_tests() -> list[tuple[str, str]]:
    result: list[tuple[str, str]] = []
    for protocol in ("chat", "responses"):
        for order in ("model-tools-current", "current-model-tools"):
            result.append(("ordered_tool", f"allow-ordered-tool-schema-{protocol}-{order}"))
            result.append(("ordered_tool", f"block-ordered-tool-schema-{protocol}-{order}"))
    return result


CRITICAL_SUBTESTS: tuple[tuple[str, str], ...] = tuple(
    [
        ("no_copy", "allow-json-guard-enabled-control-fingerprint"),
        ("no_copy", "allow-openai-image-edits-multipart-large-file-keywords-ignored"),
        ("no_copy", "balanced-incomplete-allows-and-audits-rpc-body-limit"),
        ("no_copy", "strict-incomplete-blocks-rpc-body-limit"),
        ("no_copy", "allow-json-disabled-control-matches-guard-enabled-upstream"),
        ("no_copy", "allow-multipart-disabled-control-matches-guard-enabled-semantics"),
        *_multi_agent_tests(),
        (
            "response_failed",
            "allow-stream-upstream-failure-official-codex-response-failed",
        ),
        (
            "response_failed",
            "allow-stream-upstream-failure-non-codex-legacy-error",
        ),
        (
            "originator",
            "allow-stream-upstream-failure-official-codex-originator-response-failed",
        ),
        (
            "originator",
            "allow-stream-upstream-failure-official-codex-bare-originator-response-failed",
        ),
        ("claude_replay", "allow-claude-compatible-thinking-replay-http"),
        ("claude_replay", "allow-claude-compatible-thinking-replay-sse"),
        (
            "claude_replay",
            "allow-claude-compatible-thinking-replay-clears-after-upstream-bad-request",
        ),
        *_ordered_tool_tests(),
    ]
)

ALLOWED_GO_ACTIONS = frozenset({"start", "run", "pause", "cont", "output", "pass", "fail", "skip"})
ALLOWED_GO_EVENT_KEYS = frozenset(
    {"Time", "Action", "Package", "Test", "Elapsed", "Output", "FailedBuild"}
)


class SpecialPathsError(ContractError):
    """The native Host evidence failed its closed contract."""


def fail(message: str) -> NoReturn:
    raise SpecialPathsError(message)


def exact_object(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict:
        fail(f"{label} must be a JSON object")
    actual = set(value)
    if actual != keys:
        fail(
            f"{label} keys are not closed "
            f"(missing={sorted(keys - actual)}, extra={sorted(actual - keys)})"
        )
    return value


def exact_list(value: Any, label: str) -> list[Any]:
    if type(value) is not list:
        fail(f"{label} must be a JSON array")
    return value


def exact_string(value: Any, label: str, maximum: int = 1024) -> str:
    if type(value) is not str or not value or len(value) > maximum:
        fail(f"{label} must be a non-empty bounded string")
    return value


def exact_int(value: Any, label: str, minimum: int = 0, maximum: int | None = None) -> int:
    if type(value) is not int or value < minimum or (maximum is not None and value > maximum):
        fail(f"{label} must be an integer in the reviewed range")
    return value


def exact_number(value: Any, label: str) -> int | float:
    if type(value) not in (int, float) or not math.isfinite(float(value)) or value < 0:
        fail(f"{label} must be a finite non-negative number")
    return value


def require_hex(value: Any, label: str, pattern: re.Pattern[str] = HEX64) -> str:
    text = exact_string(value, label, 128)
    if pattern.fullmatch(text) is None or not text.strip("0"):
        fail(f"{label} is not a non-zero lowercase digest")
    return text


def timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_timestamp(value: Any, label: str) -> datetime:
    text = exact_string(value, label, 64)
    if UTC.fullmatch(text) is None:
        fail(f"{label} must be canonical second-precision UTC")
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        fail(f"{label} is not a valid timestamp")


def sha256_file(path: Path, label: str, maximum: int) -> tuple[str, int, bytes]:
    raw = read_regular_bytes(path, label, maximum, require_single_link=True)
    return sha256_bytes(raw), len(raw), raw


def _git(repository: Path, arguments: Sequence[str], label: str) -> str:
    environment = os.environ.copy()
    environment.update(
        {
            "GIT_OPTIONAL_LOCKS": "0",
            "HTTP_PROXY": "",
            "HTTPS_PROXY": "",
            "ALL_PROXY": "",
        }
    )
    result = subprocess.run(
        [
            "git",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.hooksPath=/dev/null",
            "-C",
            str(repository),
            *arguments,
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
        check=False,
        env=environment,
    )
    if result.returncode != 0:
        fail(f"cannot read checkout {label}")
    return result.stdout


def checkout_identity(repository: Path) -> dict[str, Any]:
    try:
        resolved = repository.resolve(strict=True)
    except (FileNotFoundError, OSError) as exc:
        fail(f"checkout cannot be resolved: {type(exc).__name__}")
    if resolved != repository or not repository.is_dir() or repository.is_symlink():
        fail("checkout must be a resolved real directory")
    top = Path(_git(repository, ("rev-parse", "--show-toplevel"), "root").strip()).resolve()
    if top != repository:
        fail("checkout path is not the Git top-level directory")
    status = _git(
        repository,
        ("status", "--porcelain=v1", "--untracked-files=all"),
        "clean status",
    )
    if status:
        fail("checkout has tracked or untracked drift")
    commit = _git(repository, ("rev-parse", "HEAD^{commit}"), "commit").strip().lower()
    tree = _git(repository, ("rev-parse", "HEAD^{tree}"), "tree").strip().lower()
    require_hex(commit, "checkout commit", HEX40)
    require_hex(tree, "checkout tree", HEX40)
    tracked = _git(
        repository,
        ("ls-files", "--error-unmatch", "--", TEST_SOURCE),
        "test source tracking",
    ).strip()
    if tracked.replace("\\", "/") != TEST_SOURCE:
        fail("native Host test source is not the exact tracked path")
    source_path = repository / Path(TEST_SOURCE)
    source_sha, source_bytes, _ = sha256_file(
        source_path, "native Host test source", 8 * 1024 * 1024
    )
    return {
        "commit": commit,
        "test_source": {
            "bytes": source_bytes,
            "path": TEST_SOURCE,
            "sha256": source_sha,
        },
        "tree": tree,
    }


def live_runtime_identity() -> dict[str, str]:
    machine = platform.machine().lower()
    if sys.platform != "linux" or machine not in {"amd64", "x86_64"}:
        fail("native Host evidence must be packed on Linux amd64")
    environment = os.environ.copy()
    environment.update({"HTTP_PROXY": "", "HTTPS_PROXY": "", "ALL_PROXY": ""})
    result = subprocess.run(
        ["go", "env", "GOVERSION", "GOOS", "GOARCH"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
        check=False,
        env=environment,
    )
    values = result.stdout.splitlines()
    if result.returncode != 0 or values != [GO_VERSION, "linux", "amd64"]:
        fail(f"native Host evidence requires {GO_VERSION} targeting linux/amd64")
    return {"go_version": GO_VERSION, "platform": PLATFORM}


def tool_identity() -> dict[str, str]:
    source_sha, _, _ = sha256_file(SCRIPT_PATH, "native Host evidence source", 2 * 1024 * 1024)
    schema_sha, _, _ = sha256_file(SCHEMA_PATH, "native Host evidence schema", 2 * 1024 * 1024)
    return {"schema_sha256": schema_sha, "source_sha256": source_sha}


def validate_candidate_inputs(
    candidate_manifest: Path,
    checkout: Path,
    *,
    artifact_id: Any,
    artifact_name: Any,
    artifact_digest: Any,
    artifact_size: Any,
) -> dict[str, Any]:
    source = checkout_identity(checkout)
    try:
        manifest_path = candidate_manifest.resolve(strict=True)
    except (FileNotFoundError, OSError) as exc:
        fail(f"candidate manifest cannot be resolved: {type(exc).__name__}")
    if manifest_path != candidate_manifest or manifest_path.name != CANDIDATE_MANIFEST_NAME:
        fail("candidate manifest must be the resolved fixed-name file")
    directory = manifest_path.parent
    if directory.is_symlink() or not directory.is_dir() or directory.resolve() != directory:
        fail("candidate artifact directory must be a resolved real directory")
    actual = tuple(sorted(item.name for item in directory.iterdir()))
    expected = tuple(sorted(EXPECTED_CANDIDATE_FILES))
    if actual != expected:
        fail(f"candidate artifact is not the exact nine-file set: {actual}")

    so_path = directory / CAG_SO_NAME
    so_sha, _, _ = sha256_file(so_path, "candidate SO", MAX_CANDIDATE_FILE_BYTES)
    cag_identity = {"commit": source["commit"], "so_sha256": so_sha, "tree": source["tree"]}
    manifest, manifest_raw = read_candidate_manifest(manifest_path, cag_identity)

    declared = {item["name"]: item for item in manifest["artifacts"]}
    files: list[dict[str, Any]] = []
    metadata: dict[str, Any] | None = None
    for name in EXPECTED_CANDIDATE_FILES:
        digest, size, raw = sha256_file(
            directory / name,
            f"candidate file {name}",
            CANDIDATE_MAX_BYTES if name == CANDIDATE_MANIFEST_NAME else MAX_CANDIDATE_FILE_BYTES,
        )
        if name == CANDIDATE_MANIFEST_NAME:
            if raw != manifest_raw:
                fail("candidate manifest changed while binding candidate files")
        else:
            record = declared.get(name)
            if record is None or record["sha256"] != digest or record["bytes"] != size:
                fail(f"candidate manifest does not bind {name}")
        if name == "build-metadata.json":
            value = load_json_bytes(raw, "candidate build metadata", MAX_CANDIDATE_FILE_BYTES)
            if type(value) is dict:
                metadata = value
        files.append({"bytes": size, "name": name, "sha256": digest})
    if metadata is None or not (
        metadata.get("commit") == source["commit"]
        and metadata.get("tree") == source["tree"]
        and metadata.get("version") == CAG_SOURCE_VERSION
        and metadata.get("source_version") == CAG_SOURCE_VERSION
        and metadata.get("dirty") is False
        and metadata.get("goos") == "linux"
        and metadata.get("goarch") == "amd64"
        and metadata.get("cgo_enabled") is True
    ):
        fail("candidate build metadata does not bind Linux amd64 candidate identity")

    candidate_artifact_id = exact_int(artifact_id, "candidate artifact id", 1)
    candidate_artifact_name = exact_string(artifact_name, "candidate artifact name", 256)
    if candidate_artifact_name != CANDIDATE_ARTIFACT_NAME:
        fail("candidate artifact name is not the fixed CI name")
    candidate_artifact_digest = exact_string(artifact_digest, "candidate artifact digest", 128)
    if (
        DIGEST.fullmatch(candidate_artifact_digest) is None
        or not candidate_artifact_digest.removeprefix("sha256:").strip("0")
    ):
        fail("candidate artifact digest must be sha256:<lowercase hex>")
    candidate_artifact_size = exact_int(
        artifact_size, "candidate artifact size", 1, MAX_ARTIFACT_BYTES
    )

    return {
        "artifact": {
            "digest": candidate_artifact_digest,
            "id": candidate_artifact_id,
            "name": candidate_artifact_name,
            "run_attempt": int(manifest["run_attempt"]),
            "run_id": int(manifest["run_id"]),
            "size": candidate_artifact_size,
        },
        "files": sorted(files, key=lambda item: item["name"]),
        "manifest_sha256": sha256_bytes(manifest_raw),
        "repository": CANDIDATE_REPOSITORY,
        "source": {
            "commit": source["commit"],
            "dirty": False,
            "event": manifest["event"],
            "head_branch": manifest["head_branch"],
            "head_sha": manifest["head_sha"],
            "tree": source["tree"],
            "version": CAG_SOURCE_VERSION,
        },
        "so": {"name": CAG_SO_NAME, "sha256": so_sha},
        "test_source": source["test_source"],
        "workflow": {"name": CANDIDATE_WORKFLOW_NAME, "path": CANDIDATE_WORKFLOW_PATH},
    }


def _go_event(value: Any, label: str) -> dict[str, Any]:
    if type(value) is not dict:
        fail(f"{label} must be a JSON object")
    keys = set(value)
    if not {"Time", "Action", "Package"}.issubset(keys) or not keys.issubset(
        ALLOWED_GO_EVENT_KEYS
    ):
        fail(f"{label} fields are not the closed go test event shape")
    exact_string(value["Time"], f"{label}.Time", 128)
    action = exact_string(value["Action"], f"{label}.Action", 32)
    if action not in ALLOWED_GO_ACTIONS:
        fail(f"{label}.Action is unknown: {action}")
    package = exact_string(value["Package"], f"{label}.Package", 512)
    if package != PACKAGE:
        fail("go test log contains an unexpected package")
    if "Test" in value:
        test = exact_string(value["Test"], f"{label}.Test", 1024)
        if "\n" in test or "\r" in test:
            fail(f"{label}.Test contains a line break")
    if "Elapsed" in value:
        exact_number(value["Elapsed"], f"{label}.Elapsed")
    if "Output" in value and type(value["Output"]) is not str:
        fail(f"{label}.Output must be a string")
    if "FailedBuild" in value:
        exact_string(value["FailedBuild"], f"{label}.FailedBuild", 512)
        fail("go test log reports a failed build")
    return value


def parse_go_test_log(path: Path) -> dict[str, Any]:
    raw = read_regular_bytes(
        path, "native Host go test JSONL", MAX_LOG_BYTES, require_single_link=True
    )
    if not raw.endswith(b"\n") or b"\r" in raw:
        fail("go test JSONL must use LF and one terminal newline")
    encoded_lines = raw[:-1].split(b"\n")
    if not encoded_lines or any(not line for line in encoded_lines):
        fail("go test JSONL contains an empty or missing event")

    run_counts: dict[str, int] = {}
    pass_counts: dict[str, int] = {}
    observed_tests: set[str] = set()
    package_starts = 0
    package_passes = 0
    fail_count = 0
    skip_count = 0
    for index, encoded in enumerate(encoded_lines):
        value = load_json_bytes(encoded, f"go test event[{index}]", MAX_LOG_BYTES)
        event = _go_event(value, f"go test event[{index}]")
        action = event["Action"]
        test = event.get("Test")
        if action == "start":
            if test is not None:
                fail("go test package start unexpectedly names a test")
            package_starts += 1
        if action in {"fail", "skip"}:
            if action == "fail":
                fail_count += 1
            else:
                skip_count += 1
        if test is None:
            if action == "pass":
                package_passes += 1
            continue
        if test != TOP_LEVEL_TEST and not test.startswith(TOP_LEVEL_TEST + "/"):
            fail("go test log contains a test outside the exact top-level selection")
        observed_tests.add(test)
        if action == "run":
            run_counts[test] = run_counts.get(test, 0) + 1
        elif action == "pass":
            pass_counts[test] = pass_counts.get(test, 0) + 1

    if fail_count or skip_count:
        fail("go test log contains FAIL or SKIP")
    if package_starts != 1 or package_passes != 1:
        fail("go test log does not contain one successful package execution")
    required = {TOP_LEVEL_TEST}
    required.update(f"{TOP_LEVEL_TEST}/{suffix}" for _, suffix in CRITICAL_SUBTESTS)
    missing = sorted(required - observed_tests)
    if missing:
        fail(f"go test log is missing required PASS events: {missing}")
    for test in observed_tests:
        if run_counts.get(test) != 1 or pass_counts.get(test) != 1:
            fail(f"go test test identity is not one-run/one-pass: {test}")

    critical = [
        {
            "category": category,
            "name": f"{TOP_LEVEL_TEST}/{suffix}",
            "status": "PASS",
        }
        for category, suffix in CRITICAL_SUBTESTS
    ]
    return {
        "critical_tests": critical,
        "event_count": len(encoded_lines),
        "fail_count": fail_count,
        "log": {"bytes": len(raw), "sha256": sha256_bytes(raw)},
        "observed_test_count": len(observed_tests),
        "package_status": "PASS",
        "required_test_count": len(required),
        "skip_count": skip_count,
        "top_level_status": "PASS",
    }


def expected_critical_tests() -> list[dict[str, str]]:
    return [
        {
            "category": category,
            "name": f"{TOP_LEVEL_TEST}/{suffix}",
            "status": "PASS",
        }
        for category, suffix in CRITICAL_SUBTESTS
    ]


def build_report(
    *,
    candidate_manifest: Path,
    checkout: Path,
    go_test_jsonl: Path,
    artifact_id: Any,
    artifact_name: Any,
    artifact_digest: Any,
    artifact_size: Any,
    generated_at: datetime | None = None,
    runtime: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    candidate = validate_candidate_inputs(
        candidate_manifest,
        checkout,
        artifact_id=artifact_id,
        artifact_name=artifact_name,
        artifact_digest=artifact_digest,
        artifact_size=artifact_size,
    )
    tests = parse_go_test_log(go_test_jsonl)
    observed_runtime = dict(runtime) if runtime is not None else live_runtime_identity()
    if observed_runtime != {"go_version": GO_VERSION, "platform": PLATFORM}:
        fail("runtime identity is not the fixed Linux amd64 Go toolchain")
    created = generated_at or datetime.now(timezone.utc)
    report = {
        "candidate": {key: value for key, value in candidate.items() if key != "test_source"},
        "claim_boundary": BOUNDARY,
        "cpa": {"commit": CPA_COMMIT, "tag": CPA_TAG},
        "execution": {
            "command": list(COMMAND),
            "critical_tests": tests["critical_tests"],
            "fail_count": tests["fail_count"],
            "observed_test_count": tests["observed_test_count"],
            "package": PACKAGE,
            "package_status": tests["package_status"],
            "required_test_count": tests["required_test_count"],
            "skip_count": tests["skip_count"],
            "top_level_status": tests["top_level_status"],
            "top_level_test": TOP_LEVEL_TEST,
        },
        "generated_at": timestamp(created),
        "runtime": observed_runtime,
        "schema": SCHEMA,
        "status": STATUS,
        "test_log": {
            "bytes": tests["log"]["bytes"],
            "event_count": tests["event_count"],
            "sha256": tests["log"]["sha256"],
        },
        "test_source": candidate["test_source"],
        "tool": tool_identity(),
    }
    return validate_report(report, check_local_tool=True)


def validate_report(value: Any, *, check_local_tool: bool = True) -> dict[str, Any]:
    report = exact_object(
        value,
        {
            "candidate",
            "claim_boundary",
            "cpa",
            "execution",
            "generated_at",
            "runtime",
            "schema",
            "status",
            "test_log",
            "test_source",
            "tool",
        },
        "native Host special-path report",
    )
    if (
        report["schema"] != SCHEMA
        or report["status"] != STATUS
        or report["claim_boundary"] != BOUNDARY
    ):
        fail("native Host report identity or claim boundary is invalid")
    parse_timestamp(report["generated_at"], "report.generated_at")

    cpa = exact_object(report["cpa"], {"commit", "tag"}, "report.cpa")
    if cpa != {"commit": CPA_COMMIT, "tag": CPA_TAG}:
        fail("report CPA identity is not v7.2.125")
    runtime = exact_object(
        report["runtime"], {"go_version", "platform"}, "report.runtime"
    )
    if runtime != {"go_version": GO_VERSION, "platform": PLATFORM}:
        fail("report runtime identity is not fixed")
    tool = exact_object(
        report["tool"], {"schema_sha256", "source_sha256"}, "report.tool"
    )
    require_hex(tool["schema_sha256"], "report.tool.schema_sha256")
    require_hex(tool["source_sha256"], "report.tool.source_sha256")
    if check_local_tool and tool != tool_identity():
        fail("report tool identity differs from the current validator")

    candidate = exact_object(
        report["candidate"],
        {
            "artifact",
            "files",
            "manifest_sha256",
            "repository",
            "source",
            "so",
            "workflow",
        },
        "report.candidate",
    )
    if candidate["repository"] != CANDIDATE_REPOSITORY:
        fail("report candidate repository is invalid")
    artifact = exact_object(
        candidate["artifact"],
        {"digest", "id", "name", "run_attempt", "run_id", "size"},
        "report.candidate.artifact",
    )
    if (
        artifact["name"] != CANDIDATE_ARTIFACT_NAME
        or DIGEST.fullmatch(
            exact_string(artifact["digest"], "report.candidate.artifact.digest", 128)
        )
        is None
        or not artifact["digest"].removeprefix("sha256:").strip("0")
    ):
        fail("report candidate artifact coordinates are invalid")
    for key in ("id", "run_attempt", "run_id"):
        exact_int(artifact[key], f"report.candidate.artifact.{key}", 1)
    exact_int(
        artifact["size"],
        "report.candidate.artifact.size",
        1,
        MAX_ARTIFACT_BYTES,
    )
    require_hex(candidate["manifest_sha256"], "report.candidate.manifest_sha256")
    source = exact_object(
        candidate["source"],
        {"commit", "dirty", "event", "head_branch", "head_sha", "tree", "version"},
        "report.candidate.source",
    )
    require_hex(source["commit"], "report.candidate.source.commit", HEX40)
    require_hex(source["tree"], "report.candidate.source.tree", HEX40)
    require_hex(source["head_sha"], "report.candidate.source.head_sha", HEX40)
    event = exact_string(source["event"], "report.candidate.source.event", 32)
    if (
        source["dirty"] is not False
        or event not in {"pull_request", "push"}
        or source["version"] != CAG_SOURCE_VERSION
    ):
        fail("report candidate source identity is invalid")
    branch = exact_string(
        source["head_branch"], "report.candidate.source.head_branch", 255
    )
    if (
        SAFE_BRANCH.fullmatch(branch) is None
        or branch.endswith(("/", "."))
        or ".." in branch
        or "//" in branch
        or "@{" in branch
    ):
        fail("report candidate branch is unsafe")
    if event == "push" and source["head_sha"] != source["commit"]:
        fail("report push candidate head SHA differs from commit")
    so = exact_object(candidate["so"], {"name", "sha256"}, "report.candidate.so")
    if so["name"] != CAG_SO_NAME:
        fail("report candidate SO name is invalid")
    require_hex(so["sha256"], "report.candidate.so.sha256")
    workflow = exact_object(candidate["workflow"], {"name", "path"}, "report.candidate.workflow")
    if workflow != {"name": CANDIDATE_WORKFLOW_NAME, "path": CANDIDATE_WORKFLOW_PATH}:
        fail("report candidate workflow identity is invalid")

    files = exact_list(candidate["files"], "report.candidate.files")
    if len(files) != len(EXPECTED_CANDIDATE_FILES):
        fail("report candidate file count is not nine")
    normalized_files: list[dict[str, Any]] = []
    for index, raw in enumerate(files):
        item = exact_object(raw, {"bytes", "name", "sha256"}, f"report.candidate.files[{index}]")
        name = exact_string(item["name"], f"report.candidate.files[{index}].name", 256)
        normalized_files.append(
            {
                "bytes": exact_int(item["bytes"], f"report.candidate.files[{index}].bytes", 1),
                "name": name,
                "sha256": require_hex(item["sha256"], f"report.candidate.files[{index}].sha256"),
            }
        )
    if normalized_files != sorted(normalized_files, key=lambda item: item["name"]) or tuple(
        item["name"] for item in normalized_files
    ) != tuple(sorted(EXPECTED_CANDIDATE_FILES)):
        fail("report candidate file set/order is not exact")
    selected_so = next(item for item in normalized_files if item["name"] == CAG_SO_NAME)
    selected_manifest = next(
        item for item in normalized_files if item["name"] == CANDIDATE_MANIFEST_NAME
    )
    if selected_so["sha256"] != so["sha256"]:
        fail("report candidate file list does not bind the selected SO")
    if selected_manifest["sha256"] != candidate["manifest_sha256"]:
        fail("report candidate manifest file SHA is internally inconsistent")

    execution = exact_object(
        report["execution"],
        {
            "command",
            "critical_tests",
            "fail_count",
            "observed_test_count",
            "package",
            "package_status",
            "required_test_count",
            "skip_count",
            "top_level_status",
            "top_level_test",
        },
        "report.execution",
    )
    if (
        execution["command"] != list(COMMAND)
        or execution["package"] != PACKAGE
        or execution["top_level_test"] != TOP_LEVEL_TEST
    ):
        fail("report go test command/package/top-level identity is invalid")
    if (
        execution["package_status"] != "PASS"
        or execution["top_level_status"] != "PASS"
    ):
        fail("report top-level or package status is not PASS")
    if exact_int(execution["fail_count"], "report.execution.fail_count") != 0 or exact_int(
        execution["skip_count"], "report.execution.skip_count"
    ) != 0:
        fail("report contains FAIL or SKIP")
    required_count = len(CRITICAL_SUBTESTS) + 1
    if (
        exact_int(
            execution["required_test_count"],
            "report.execution.required_test_count",
            1,
        )
        != required_count
    ):
        fail("report required test count is invalid")
    if (
        exact_int(
            execution["observed_test_count"],
            "report.execution.observed_test_count",
            required_count,
        )
        < required_count
    ):
        fail("report observed test count is incomplete")
    critical = exact_list(execution["critical_tests"], "report.execution.critical_tests")
    normalized_critical = []
    for index, raw in enumerate(critical):
        label = f"report.execution.critical_tests[{index}]"
        item = exact_object(raw, {"category", "name", "status"}, label)
        normalized_critical.append(
            {
                "category": exact_string(item["category"], f"{label}.category", 64),
                "name": exact_string(item["name"], f"{label}.name", 1024),
                "status": exact_string(item["status"], f"{label}.status", 16),
            }
        )
    if normalized_critical != expected_critical_tests():
        fail("report critical test inventory is missing, reordered, or not PASS")

    log = exact_object(
        report["test_log"], {"bytes", "event_count", "sha256"}, "report.test_log"
    )
    exact_int(log["bytes"], "report.test_log.bytes", 1, MAX_LOG_BYTES)
    exact_int(
        log["event_count"],
        "report.test_log.event_count",
        (required_count * 2) + 2,
    )
    require_hex(log["sha256"], "report.test_log.sha256")
    test_source = exact_object(
        report["test_source"],
        {"bytes", "path", "sha256"},
        "report.test_source",
    )
    if test_source["path"] != TEST_SOURCE:
        fail("report native Host test source path is invalid")
    exact_int(
        test_source["bytes"], "report.test_source.bytes", 1, 8 * 1024 * 1024
    )
    require_hex(test_source["sha256"], "report.test_source.sha256")
    return report


def load_report(path: Path) -> tuple[dict[str, Any], bytes]:
    info = regular_file_info(path, "native Host special-path report", require_single_link=True)
    if os.name == "posix" and stat.S_IMODE(info.st_mode) != 0o600:
        fail("native Host special-path report must be mode-0600")
    raw = read_regular_bytes(
        path, "native Host special-path report", MAX_REPORT_BYTES, require_single_link=True
    )
    value = load_json_bytes(raw, "native Host special-path report", MAX_REPORT_BYTES)
    if raw != canonical_bytes(value) + b"\n":
        fail("native Host special-path report must be canonical JSON with one terminal newline")
    return validate_report(value, check_local_tool=True), raw


def _created_file_identity(info: os.stat_result) -> dict[str, int]:
    return {
        "st_dev": int(info.st_dev),
        "st_ino": int(info.st_ino),
        "st_nlink": int(info.st_nlink),
        "st_size": int(info.st_size),
    }


def _verify_created_output(
    path: Path, expected: Mapping[str, int], raw: bytes
) -> None:
    flags = os.O_RDONLY
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        fail(f"native Host output cannot be reopened safely: {type(exc).__name__}")
    try:
        info = os.fstat(descriptor)
        observed = _created_file_identity(info)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or observed != dict(expected)
        ):
            fail("native Host output identity changed after creation")
        if os.name == "posix" and stat.S_IMODE(info.st_mode) != 0o600:
            fail("native Host special-path output mode is not 0600")
        with os.fdopen(descriptor, "rb", closefd=True) as handle:
            descriptor = -1
            observed_raw = handle.read(len(raw) + 1)
            if observed_raw != raw:
                fail("native Host output bytes changed after creation")
            final_info = os.fstat(handle.fileno())
            if _created_file_identity(final_info) != dict(expected):
                fail("native Host output identity changed while being verified")
            try:
                path_info = path.stat(follow_symlinks=False)
            except OSError as exc:
                fail(f"native Host output path cannot be rebound safely: {type(exc).__name__}")
            if _created_file_identity(path_info) != dict(expected):
                fail("native Host output path was replaced after creation")
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def write_exclusive(path: Path, report: Mapping[str, Any]) -> None:
    if path.exists() or path.is_symlink():
        fail("native Host special-path output must be a new path")
    try:
        parent = path.parent.resolve(strict=True)
    except (FileNotFoundError, OSError) as exc:
        fail(f"native Host output parent cannot be resolved: {type(exc).__name__}")
    if parent != path.parent or not parent.is_dir() or parent.is_symlink():
        fail("native Host output parent must be a resolved real directory")
    raw = canonical_bytes(report) + b"\n"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor: int | None = None
    identity: dict[str, int] | None = None
    handle = None
    try:
        descriptor = os.open(path, flags, 0o600)
        if hasattr(os, "fchmod"):
            os.fchmod(descriptor, 0o600)
        handle = os.fdopen(descriptor, "wb", closefd=True)
        descriptor = None
        try:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
            info = os.fstat(handle.fileno())
            identity = _created_file_identity(info)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or info.st_size != len(raw)
            ):
                fail("new native Host output is not a complete single-link regular file")
            if os.name == "posix" and stat.S_IMODE(info.st_mode) != 0o600:
                fail("native Host special-path output mode is not 0600")
        finally:
            if identity is None:
                try:
                    identity = _created_file_identity(os.fstat(handle.fileno()))
                except OSError:
                    identity = None
            handle.close()
            handle = None
        if os.name != "posix":
            os.chmod(path, 0o600)
        if identity is None:
            fail("native Host output identity is unavailable after creation")
        _verify_created_output(path, identity, raw)
    except BaseException:
        if descriptor is not None:
            if identity is None:
                try:
                    identity = _created_file_identity(os.fstat(descriptor))
                except OSError:
                    identity = None
            os.close(descriptor)
        if handle is not None and not handle.closed:
            handle.close()
        # Never unlink a failed output by pathname. A same-UID actor could swap
        # the entry between any identity check and unlink; the mode-0700,
        # task-scoped evidence directory is cleaned explicitly after the run.
        raise


def validate_bundle(
    *,
    report_path: Path,
    candidate_manifest: Path,
    checkout: Path,
    go_test_jsonl: Path,
    artifact_id: Any,
    artifact_name: Any,
    artifact_digest: Any,
    artifact_size: Any,
    runtime: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    report, _ = load_report(report_path)
    generated_at = parse_timestamp(report["generated_at"], "report.generated_at")
    rebuilt = build_report(
        candidate_manifest=candidate_manifest,
        checkout=checkout,
        go_test_jsonl=go_test_jsonl,
        artifact_id=artifact_id,
        artifact_name=artifact_name,
        artifact_digest=artifact_digest,
        artifact_size=artifact_size,
        generated_at=generated_at,
        runtime=runtime,
    )
    if rebuilt != report:
        fail("native Host report differs from the supplied candidate/log/checkout inputs")
    return report


def add_common_arguments(command: argparse.ArgumentParser) -> None:
    command.add_argument("--candidate-manifest", type=Path, required=True)
    command.add_argument("--candidate-artifact-id", type=int, required=True)
    command.add_argument("--candidate-artifact-name", required=True)
    command.add_argument("--candidate-artifact-digest", required=True)
    command.add_argument("--candidate-artifact-size", type=int, required=True)
    command.add_argument("--go-test-jsonl", type=Path, required=True)
    command.add_argument("--checkout", type=Path, required=True)


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    commands = root.add_subparsers(dest="command", required=True)
    pack = commands.add_parser("pack", help="validate inputs and write canonical evidence")
    add_common_arguments(pack)
    pack.add_argument("--output", type=Path, required=True)
    validate = commands.add_parser("validate", help="revalidate evidence against original inputs")
    add_common_arguments(validate)
    validate.add_argument("--report", type=Path, required=True)
    return root


def _resolved(path: Path, *, must_exist: bool) -> Path:
    return path.resolve(strict=must_exist)


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        common = {
            "candidate_manifest": _resolved(args.candidate_manifest, must_exist=True),
            "checkout": _resolved(args.checkout, must_exist=True),
            "go_test_jsonl": _resolved(args.go_test_jsonl, must_exist=True),
            "artifact_id": args.candidate_artifact_id,
            "artifact_name": args.candidate_artifact_name,
            "artifact_digest": args.candidate_artifact_digest,
            "artifact_size": args.candidate_artifact_size,
        }
        if args.command == "pack":
            report = build_report(**common)
            output = _resolved(args.output, must_exist=False)
            write_exclusive(output, report)
            raw = canonical_bytes(report) + b"\n"
        else:
            report = validate_bundle(
                report_path=_resolved(args.report, must_exist=True), **common
            )
            raw = canonical_bytes(report) + b"\n"
        print(
            json.dumps(
                {
                    "commit": report["candidate"]["source"]["commit"],
                    "report_sha256": sha256_bytes(raw),
                    "status": report["status"],
                    "valid": True,
                },
                sort_keys=True,
            )
        )
        return 0
    except (
        ContractError,
        OSError,
        RuntimeError,
        ValueError,
        subprocess.SubprocessError,
    ) as exc:
        print(
            f"native Host special-path evidence failed: {type(exc).__name__}",
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
