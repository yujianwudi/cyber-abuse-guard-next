#!/usr/bin/env python3
"""Build deterministic, identity-bound CPA Host performance workloads.

The generator consumes the validated five-repository core corpus and the
checked-in sanitized public corpus.  It never reads supplemental ZIP inputs,
executes third-party content, or writes outside the two explicit outputs.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Sequence

from audit_contract import (
    FIXED_REPOSITORIES,
    ContractError,
    apply_template,
    canonical_bytes,
    fail,
    load_json_bytes,
    read_regular_bytes,
    sha256_bytes,
    validate_corpus_manifest,
)
from host_performance import (
    ALL_WORKLOADS,
    EXPECTED_STATUS_BY_WORKLOAD,
    LARGE_PAYLOAD_BYTES,
    WORKLOAD_SCHEMA,
    validate_workload_manifest,
)


MODEL = "current-cpa-audit-model"
PUBLIC_RELATIVE_PATH = PurePosixPath(
    "testdata/development-public-jailbreak-patterns-v1/cases.jsonl"
)
PUBLIC_SHA256 = "743f60087a70798a63b4bdb3ba735bdd9a9e75a4489280fecc1dbc2f162ba80d"
PUBLIC_GIT_BLOB = "8b70b69b76a117e3b55150d6cc86bc7183a84c89"
PUBLIC_ROW_COUNT = 36
PUBLIC_SELECTED_COUNT = 10
PUBLIC_PROTOCOL_COUNTS = {"openai_chat": 7, "openai_responses": 3}

MAX_CORE_MANIFEST_BYTES = 8 * 1024 * 1024
MAX_PUBLIC_BYTES = 2 * 1024 * 1024
MAX_SOURCE_BYTES = 32 * 1024 * 1024
MAX_OUTPUT_FILE_BYTES = 16 * 1024 * 1024
MAX_MANIFEST_BYTES = 2 * 1024 * 1024
FILE_IDENTITY_BIND_ATTEMPTS = 3

ENDPOINT_BY_PROTOCOL = {
    "chat": "/v1/chat/completions",
    "responses": "/v1/responses",
}
PUBLIC_PROTOCOL_MAP = {
    "openai_chat": "chat",
    "openai_responses": "responses",
}

FIXED_TEXT = "Summarize the fictional football score Blue 2, Gold 1 in one short sentence."
ORDINARY_TEXTS = (
    (
        "chat",
        "Sort these fictional football scores by date and summarize the highest score: "
        "2026-06-11 2-1, 2026-06-12 0-0, 2026-06-13 3-2.",
    ),
    (
        "responses",
        "Summarize this harmless deployment note in one sentence: the staging service "
        "started, its health check returned 200, and no production state changed.",
    ),
)


@dataclass(frozen=True)
class BodySpec:
    relative_path: str
    endpoint: str
    body: dict[str, Any]


@dataclass(frozen=True)
class BoundInputs:
    core_manifest: dict[str, Any]
    core_manifest_raw: bytes
    core_manifest_path: Path
    corpus_root: Path
    public_raw: bytes
    public_rows: tuple[dict[str, Any], ...]
    repository_root: Path


@dataclass(frozen=True)
class _CreatedPath:
    path: Path
    device: int | None
    inode: int | None
    directory: bool


def _absolute(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


def _is_link_or_reparse(info: os.stat_result) -> bool:
    if stat.S_ISLNK(info.st_mode):
        return True
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    attributes = getattr(info, "st_file_attributes", 0)
    return bool(reparse and attributes & reparse)


def _require_real_directory(path: Path, label: str) -> Path:
    """Reject links/reparse points in every component of an existing directory."""

    absolute = _absolute(path)
    parts = absolute.parts
    if not parts or not absolute.anchor:
        fail(f"{label} must be an absolute directory")
    current = Path(absolute.anchor)
    for part in parts[1:]:
        current /= part
        try:
            info = current.lstat()
        except FileNotFoundError:
            fail(f"{label} is missing: {absolute}")
        if _is_link_or_reparse(info) or not stat.S_ISDIR(info.st_mode):
            fail(f"{label} and its ancestors must be real directories: {absolute}")
    return absolute


def _require_absent(path: Path, label: str) -> Path:
    absolute = _absolute(path)
    try:
        absolute.lstat()
    except FileNotFoundError:
        return absolute
    fail(f"{label} must be wholly new: {absolute}")


def _same_identity(left: os.stat_result, right: os.stat_result) -> bool:
    return left.st_dev == right.st_dev and left.st_ino == right.st_ino


def _read_bound_file(path: Path, label: str, maximum: int) -> bytes:
    try:
        before = path.lstat()
    except FileNotFoundError:
        fail(f"{label} is missing: {path}")
    if (
        _is_link_or_reparse(before)
        or not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
    ):
        fail(f"{label} must be a regular non-link file with exactly one hard link")
    raw = read_regular_bytes(
        path,
        label,
        maximum,
        require_single_link=True,
    )
    try:
        after = path.lstat()
    except FileNotFoundError:
        fail(f"{label} disappeared during its bound read")
    if (
        not _same_identity(before, after)
        or _is_link_or_reparse(after)
        or not stat.S_ISREG(after.st_mode)
        or after.st_nlink != 1
        or after.st_size != len(raw)
    ):
        fail(f"{label} identity changed during its bound read")
    return raw


def _canonical_object(raw: bytes, label: str, maximum: int) -> dict[str, Any]:
    value = load_json_bytes(raw, label, maximum)
    if not isinstance(value, dict) or raw != canonical_bytes(value) + b"\n":
        fail(f"{label} must be a canonical JSON object with one terminal newline")
    return value


def _git(repository_root: Path, arguments: Sequence[str], label: str) -> bytes:
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.upper().startswith("GIT_")
    }
    environment.update(
        {
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_OPTIONAL_LOCKS": "0",
        }
    )
    try:
        completed = subprocess.run(
            [
                "git",
                "--no-optional-locks",
                "--no-replace-objects",
                "--literal-pathspecs",
                "-c",
                "core.fsmonitor=false",
                "-c",
                "core.hooksPath=",
                "-C",
                str(repository_root),
                *arguments,
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            check=False,
            timeout=15,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        fail(f"{label} could not run the local Git identity check: {type(exc).__name__}")
    if completed.returncode != 0:
        fail(f"{label} failed the local Git identity check")
    return completed.stdout


def _git_blob_sha1(raw: bytes) -> str:
    framed = b"blob " + str(len(raw)).encode("ascii") + b"\x00" + raw
    try:
        return hashlib.sha1(framed, usedforsecurity=False).hexdigest()
    except TypeError:  # pragma: no cover - compatibility with older Python
        return hashlib.sha1(framed).hexdigest()


def _bind_repository_root(repository_root: Path) -> Path:
    root = _require_real_directory(repository_root, "repository root")
    top_raw = _git(root, ("rev-parse", "--show-toplevel"), "repository root")
    try:
        top_text = top_raw.decode("utf-8", "strict").strip()
    except UnicodeDecodeError:
        fail("repository root Git identity is not UTF-8")
    if not top_text:
        fail("repository root Git identity is empty")
    top = Path(top_text)
    try:
        same = os.path.samefile(root, top)
    except OSError:
        same = False
    if not same:
        fail("repository root must be the exact Git worktree top level")
    return root


def _bind_public_corpus(repository_root: Path) -> tuple[bytes, tuple[dict[str, Any], ...]]:
    relative = PUBLIC_RELATIVE_PATH.as_posix()
    stage_raw = _git(
        repository_root,
        ("ls-files", "--stage", "-z", "--error-unmatch", "--", relative),
        "public corpus",
    )
    records = stage_raw.split(b"\x00")
    if len(records) != 2 or records[1] != b"" or b"\t" not in records[0]:
        fail("public corpus must have exactly one tracked stage-zero index entry")
    metadata, tracked_path = records[0].split(b"\t", 1)
    fields = metadata.split(b" ")
    if (
        len(fields) != 3
        or fields[0] != b"100644"
        or fields[1].decode("ascii", "ignore") != PUBLIC_GIT_BLOB
        or fields[2] != b"0"
        or tracked_path != relative.encode("ascii")
    ):
        fail("public corpus index identity drifted from the fixed tracked blob")

    public_path = repository_root.joinpath(*PUBLIC_RELATIVE_PATH.parts)
    _require_real_directory(public_path.parent, "public corpus parent")
    raw = _read_bound_file(public_path, "public corpus", MAX_PUBLIC_BYTES)
    if sha256_bytes(raw) != PUBLIC_SHA256 or _git_blob_sha1(raw) != PUBLIC_GIT_BLOB:
        fail("public corpus worktree bytes drifted from the fixed identities")

    rows: list[dict[str, Any]] = []
    lines = raw.splitlines()
    if len(lines) != PUBLIC_ROW_COUNT or not raw.endswith(b"\n"):
        fail("public corpus row framing drifted")
    for index, line in enumerate(lines, start=1):
        value = load_json_bytes(line, f"public corpus row {index}", MAX_PUBLIC_BYTES)
        if not isinstance(value, dict):
            fail(f"public corpus row {index} must be a JSON object")
        rows.append(value)
    return raw, tuple(rows)


def _load_core_manifest(
    core_manifest_path: Path, corpus_root: Path
) -> tuple[dict[str, Any], bytes, Path, Path]:
    manifest_path = _absolute(core_manifest_path)
    _require_real_directory(manifest_path.parent, "core manifest parent")
    raw = _read_bound_file(
        manifest_path,
        "core corpus manifest",
        MAX_CORE_MANIFEST_BYTES,
    )
    value = _canonical_object(raw, "core corpus manifest", MAX_CORE_MANIFEST_BYTES)
    root = _require_real_directory(corpus_root, "core corpus root")
    validated = validate_corpus_manifest(value, root)
    return validated, raw, manifest_path, root


def bind_inputs(
    *,
    core_manifest_path: Path,
    corpus_root: Path,
    repository_root: Path,
) -> BoundInputs:
    core, core_raw, manifest_path, root = _load_core_manifest(
        core_manifest_path, corpus_root
    )
    repository = _bind_repository_root(repository_root)
    public_raw, public_rows = _bind_public_corpus(repository)
    return BoundInputs(
        core_manifest=core,
        core_manifest_raw=core_raw,
        core_manifest_path=manifest_path,
        corpus_root=root,
        public_raw=public_raw,
        public_rows=public_rows,
        repository_root=repository,
    )


def _spec(
    workload: str,
    ordinal: int,
    protocol: str,
    body: dict[str, Any],
) -> BodySpec:
    endpoint = ENDPOINT_BY_PROTOCOL.get(protocol)
    if endpoint is None:
        fail(f"unsupported workload protocol: {protocol}")
    return BodySpec(
        relative_path=f"{workload}/{ordinal:04d}-{protocol}.json",
        endpoint=endpoint,
        body=body,
    )


def _fixed_specs() -> list[BodySpec]:
    body = apply_template("raw-user-v1", FIXED_TEXT, "chat", False, MODEL)
    return [_spec("fixed_workload", 1, "chat", body)]


def _ordinary_specs() -> list[BodySpec]:
    result: list[BodySpec] = []
    for ordinal, (protocol, text) in enumerate(ORDINARY_TEXTS, start=1):
        body = apply_template("raw-user-v1", text, protocol, False, MODEL)
        result.append(_spec("ordinary", ordinal, protocol, body))
    return result


def _source_text(case: Mapping[str, Any], corpus_root: Path, ordinal: int) -> str:
    source = case["source"]
    path = corpus_root / source["corpus_file"]
    raw = _read_bound_file(
        path,
        f"activation core source {ordinal}",
        MAX_SOURCE_BYTES,
    )
    if len(raw) != source["text_bytes"] or sha256_bytes(raw) != source["text_sha256"]:
        fail(f"activation core source {ordinal} drifted from the validated manifest")
    try:
        return raw.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        fail(f"activation core source {ordinal} is not UTF-8 at byte {exc.start}")


def _activation_specs(core_manifest: Mapping[str, Any], corpus_root: Path) -> list[BodySpec]:
    selected = [
        case
        for case in core_manifest["semantic_cases"]
        if case["label"] == "malicious_active"
    ]
    if not selected:
        fail("five_repository_activation has no malicious_active core cases")
    represented = {case["source"]["repository_key"] for case in selected}
    if represented != set(FIXED_REPOSITORIES):
        fail("five_repository_activation does not cover the exact five core repositories")

    result: list[BodySpec] = []
    request_ordinal = 0
    for case_ordinal, case in enumerate(selected, start=1):
        template_id = case["template"]["id"]
        if template_id != "activated-user-v1":
            fail("malicious_active core case does not use its activated template")
        text = _source_text(case, corpus_root, case_ordinal)
        for protocol in ("chat", "responses"):
            request_ordinal += 1
            body = apply_template(template_id, text, protocol, False, MODEL)
            result.append(
                _spec(
                    "five_repository_activation",
                    request_ordinal,
                    protocol,
                    body,
                )
            )
    return result


def _public_specs(rows: Sequence[Mapping[str, Any]]) -> list[BodySpec]:
    selected: list[tuple[str, Mapping[str, Any]]] = []
    seen_ids: set[str] = set()
    counts = {key: 0 for key in PUBLIC_PROTOCOL_COUNTS}
    for row in rows:
        protocol_name = row.get("protocol")
        if not (
            row.get("harmless_canary") is True
            and row.get("label") == "allow"
            and protocol_name in PUBLIC_PROTOCOL_MAP
        ):
            continue
        identifier = row.get("id")
        if not isinstance(identifier, str) or not identifier or identifier in seen_ids:
            fail("selected public corpus rows must have unique non-empty IDs")
        seen_ids.add(identifier)
        counts[protocol_name] += 1
        selected.append((protocol_name, row))
    if len(selected) != PUBLIC_SELECTED_COUNT or counts != PUBLIC_PROTOCOL_COUNTS:
        fail("public corpus does not contain the exact fixed 10-row allow subset")

    result: list[BodySpec] = []
    for ordinal, (protocol_name, row) in enumerate(selected, start=1):
        protocol = PUBLIC_PROTOCOL_MAP[protocol_name]
        input_value = row.get("input")
        expected_key = "messages" if protocol == "chat" else "input"
        if not isinstance(input_value, dict) or set(input_value) != {expected_key}:
            fail("selected public corpus input escaped its fixed OpenAI wire shape")
        body = {
            expected_key: input_value[expected_key],
            "model": MODEL,
            "stream": False,
        }
        result.append(_spec("public", ordinal, protocol, body))
    return result


def _large_payload_specs() -> list[BodySpec]:
    prefix = "Harmless large-payload Host performance canary. "
    body: dict[str, Any] = {
        "messages": [{"content": prefix, "role": "user"}],
        "model": MODEL,
        "stream": False,
    }
    base_size = len(canonical_bytes(body))
    filler_size = LARGE_PAYLOAD_BYTES - base_size
    if filler_size < 0:
        fail("large-payload fixed envelope exceeds its code-owned byte budget")
    body["messages"][0]["content"] = prefix + ("A" * filler_size)
    if len(canonical_bytes(body)) != LARGE_PAYLOAD_BYTES:
        fail("large-payload body construction did not reach exactly 4 MiB")
    return [_spec("large_payload", 1, "chat", body)]


def build_workloads(inputs: BoundInputs) -> tuple[dict[str, Any], dict[str, bytes]]:
    specs_by_workload = {
        "fixed_workload": _fixed_specs(),
        "ordinary": _ordinary_specs(),
        "five_repository_activation": _activation_specs(
            inputs.core_manifest, inputs.corpus_root
        ),
        "public": _public_specs(inputs.public_rows),
        "large_payload": _large_payload_specs(),
    }
    if tuple(specs_by_workload) != ALL_WORKLOADS:
        fail("workload builders drifted from the code-owned workload order")

    bodies: dict[str, bytes] = {}
    workloads: list[dict[str, Any]] = []
    for workload in ALL_WORKLOADS:
        requests: list[dict[str, Any]] = []
        for spec in specs_by_workload[workload]:
            if spec.relative_path in bodies:
                fail("workload builder produced a duplicate body path")
            body_raw = canonical_bytes(spec.body) + b"\n"
            body_bytes = len(body_raw) - 1
            if workload != "large_payload" and body_bytes >= LARGE_PAYLOAD_BYTES:
                fail("non-large workload body reached the reserved 4 MiB size")
            bodies[spec.relative_path] = body_raw
            requests.append(
                {
                    "body_bytes": body_bytes,
                    "body_path": spec.relative_path,
                    "body_sha256": sha256_bytes(body_raw),
                    "endpoint": spec.endpoint,
                    "expected_status_by_arm": dict(
                        EXPECTED_STATUS_BY_WORKLOAD[workload]
                    ),
                }
            )
        workloads.append(
            {
                "id": workload,
                "request_count": len(requests),
                "request_set_sha256": sha256_bytes(canonical_bytes(requests)),
                "requests": requests,
            }
        )
    manifest = {"schema": WORKLOAD_SCHEMA, "workloads": workloads}
    validate_workload_manifest(manifest)
    return manifest, bodies


class _OutputTransaction:
    def __init__(self) -> None:
        self.created: list[_CreatedPath] = []

    def create_directory(self, path: Path, mode: int = 0o700) -> None:
        try:
            os.mkdir(path, mode)
        except FileExistsError:
            fail(f"refusing to replace an existing workload directory: {path}")
        record_index = len(self.created)
        self.created.append(_CreatedPath(path, None, None, True))
        # Unlike a file descriptor, a path retry cannot prove that a directory
        # still names the object created by mkdir.  A failed first bind remains
        # unbound so cleanup preserves any same-path replacement and reports it.
        info = path.lstat()
        self.created[record_index] = _CreatedPath(
            path, info.st_dev, info.st_ino, True
        )
        if _is_link_or_reparse(info) or not stat.S_ISDIR(info.st_mode):
            fail(f"new workload directory identity is invalid: {path}")
        os.chmod(path, mode)
        post = path.lstat()
        if not _same_identity(info, post) or _is_link_or_reparse(post):
            fail(f"new workload directory identity changed: {path}")
        if os.name == "posix" and stat.S_IMODE(post.st_mode) != mode:
            fail(f"new workload directory mode is not {mode:04o}: {path}")

    def write_file(self, path: Path, raw: bytes, mode: int = 0o600) -> None:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        flags |= getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(path, flags, mode)
        except FileExistsError:
            fail(f"refusing to replace an existing workload output: {path}")
        try:
            record_index = len(self.created)
            self.created.append(_CreatedPath(path, None, None, False))
            last_error = None
            for _ in range(FILE_IDENTITY_BIND_ATTEMPTS):
                try:
                    info = os.fstat(descriptor)
                    break
                except OSError as exc:
                    last_error = exc
            else:
                assert last_error is not None
                raise last_error
            self.created[record_index] = _CreatedPath(
                path, info.st_dev, info.st_ino, False
            )
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                fail(f"new workload output is not a single-link regular file: {path}")
            with os.fdopen(descriptor, "wb", closefd=True) as handle:
                descriptor = -1
                written = handle.write(raw)
                if written != len(raw):
                    fail(f"short write while creating workload output: {path}")
                handle.flush()
                os.fsync(handle.fileno())
                current = os.fstat(handle.fileno())
                if not _same_identity(info, current) or current.st_nlink != 1:
                    fail(f"new workload output acquired an external hard link: {path}")
        finally:
            if descriptor >= 0:
                os.close(descriptor)
        os.chmod(path, mode)
        post = path.lstat()
        if (
            not _same_identity(info, post)
            or _is_link_or_reparse(post)
            or not stat.S_ISREG(post.st_mode)
            or post.st_nlink != 1
        ):
            fail(f"new workload output identity changed: {path}")
        if os.name == "posix" and stat.S_IMODE(post.st_mode) != mode:
            fail(f"new workload output mode is not {mode:04o}: {path}")

    def cleanup(self) -> list[str]:
        problems: list[str] = []
        for created in reversed(self.created):
            try:
                info = created.path.lstat()
            except FileNotFoundError:
                continue
            except OSError as exc:
                problems.append(f"inspect_{type(exc).__name__}:{created.path}")
                continue
            if created.device is None or created.inode is None:
                problems.append(f"unbound_identity:{created.path}")
                continue
            if info.st_dev != created.device or info.st_ino != created.inode:
                problems.append(f"identity:{created.path}")
                continue
            try:
                if created.directory:
                    if _is_link_or_reparse(info) or not stat.S_ISDIR(info.st_mode):
                        problems.append(f"type:{created.path}")
                        continue
                    created.path.rmdir()
                else:
                    if _is_link_or_reparse(info) or not stat.S_ISREG(info.st_mode):
                        problems.append(f"type:{created.path}")
                        continue
                    created.path.unlink()
            except OSError as exc:
                problems.append(f"{type(exc).__name__}:{created.path}")
        return problems


def _disk_path(output_root: Path, relative: str) -> Path:
    parts = PurePosixPath(relative).parts
    if len(parts) != 2 or parts[0] not in ALL_WORKLOADS:
        fail("workload body path escaped the fixed one-directory layout")
    return output_root.joinpath(*parts)


def _verify_outputs(
    manifest: Mapping[str, Any],
    output_root: Path,
    manifest_path: Path,
) -> None:
    root_info = output_root.lstat()
    if _is_link_or_reparse(root_info) or not stat.S_ISDIR(root_info.st_mode):
        fail("workload output root identity changed before verification")
    if os.name == "posix" and stat.S_IMODE(root_info.st_mode) != 0o700:
        fail("workload output root mode is not 0700")
    with os.scandir(output_root) as entries:
        root_names = {entry.name for entry in entries}
    if root_names != set(ALL_WORKLOADS):
        fail("workload output root does not contain the exact five workload groups")

    for workload in manifest["workloads"]:
        group = output_root / workload["id"]
        group_info = group.lstat()
        if _is_link_or_reparse(group_info) or not stat.S_ISDIR(group_info.st_mode):
            fail("workload group identity changed before verification")
        if os.name == "posix" and stat.S_IMODE(group_info.st_mode) != 0o700:
            fail("workload group mode is not 0700")
        expected_names = {
            PurePosixPath(request["body_path"]).name for request in workload["requests"]
        }
        with os.scandir(group) as entries:
            observed_names = {entry.name for entry in entries}
        if observed_names != expected_names:
            fail("workload group file set drifted before verification")
        for request in workload["requests"]:
            path = _disk_path(output_root, request["body_path"])
            raw = _read_bound_file(
                path,
                "generated workload body",
                MAX_OUTPUT_FILE_BYTES,
            )
            body = _canonical_object(raw, "generated workload body", MAX_OUTPUT_FILE_BYTES)
            if (
                len(raw) - 1 != request["body_bytes"]
                or sha256_bytes(raw) != request["body_sha256"]
                or raw != canonical_bytes(body) + b"\n"
            ):
                fail("generated workload body drifted from its request contract")
            if os.name == "posix" and stat.S_IMODE(path.stat().st_mode) != 0o600:
                fail("generated workload body mode is not 0600")

    manifest_raw = _read_bound_file(
        manifest_path,
        "generated workload manifest",
        MAX_MANIFEST_BYTES,
    )
    observed = _canonical_object(
        manifest_raw,
        "generated workload manifest",
        MAX_MANIFEST_BYTES,
    )
    validate_workload_manifest(observed)
    if observed != manifest or manifest_raw != canonical_bytes(manifest) + b"\n":
        fail("generated workload manifest drifted before verification")
    if os.name == "posix" and stat.S_IMODE(manifest_path.stat().st_mode) != 0o600:
        fail("generated workload manifest mode is not 0600")


def _path_is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def generate_workloads(
    *,
    core_manifest_path: Path,
    corpus_root: Path,
    repository_root: Path,
    output_root: Path,
    manifest_path: Path,
) -> dict[str, str]:
    inputs = bind_inputs(
        core_manifest_path=core_manifest_path,
        corpus_root=corpus_root,
        repository_root=repository_root,
    )
    manifest, bodies = build_workloads(inputs)

    output = _require_absent(output_root, "workload output root")
    _require_real_directory(output.parent, "workload output parent")
    manifest_output = _require_absent(manifest_path, "workload manifest")
    _require_real_directory(manifest_output.parent, "workload manifest parent")
    if _path_is_within(manifest_output, output):
        fail("workload manifest must remain outside the private workload body root")

    transaction = _OutputTransaction()
    try:
        transaction.create_directory(output)
        for workload in ALL_WORKLOADS:
            transaction.create_directory(output / workload)
        for workload in manifest["workloads"]:
            for request in workload["requests"]:
                path = _disk_path(output, request["body_path"])
                transaction.write_file(path, bodies[request["body_path"]])
        transaction.write_file(manifest_output, canonical_bytes(manifest) + b"\n")

        _verify_outputs(manifest, output, manifest_output)

        # Rebind both sources after all writes so input drift cannot be hidden by
        # a valid-looking output assembled from a stale first read.
        core_again, core_raw_again, _, root_again = _load_core_manifest(
            inputs.core_manifest_path, inputs.corpus_root
        )
        public_raw_again, public_rows_again = _bind_public_corpus(
            inputs.repository_root
        )
        if (
            core_raw_again != inputs.core_manifest_raw
            or core_again != inputs.core_manifest
            or root_again != inputs.corpus_root
            or public_raw_again != inputs.public_raw
            or public_rows_again != inputs.public_rows
        ):
            fail("workload source identity drifted during generation")
    except BaseException as exc:
        cleanup_problems = transaction.cleanup()
        if cleanup_problems:
            raise ContractError(
                "workload generation cleanup failed closed: "
                + ",".join(sorted(cleanup_problems))
            ) from exc
        raise

    return {
        "core_manifest_sha256": sha256_bytes(inputs.core_manifest_raw),
        "public_corpus_sha256": sha256_bytes(inputs.public_raw),
    }


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    commands = root.add_subparsers(dest="command", required=True)
    generate = commands.add_parser(
        "generate",
        help="validate fixed inputs and create canonical workload bodies and manifest",
    )
    generate.add_argument("--core-manifest", type=Path, required=True)
    generate.add_argument("--corpus-root", type=Path, required=True)
    generate.add_argument("--repository-root", type=Path, required=True)
    generate.add_argument("--output-root", type=Path, required=True)
    generate.add_argument("--manifest", type=Path, required=True)
    return root


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        identities = generate_workloads(
            core_manifest_path=args.core_manifest,
            corpus_root=args.corpus_root,
            repository_root=args.repository_root,
            output_root=args.output_root,
            manifest_path=args.manifest,
        )
        print(json.dumps(identities, sort_keys=True))
        return 0
    except (ContractError, OSError, ValueError) as exc:
        print(f"HOST PERFORMANCE WORKLOAD GENERATION FAILED: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
