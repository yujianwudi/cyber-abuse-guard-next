#!/usr/bin/env python3
"""Synthetic Linux-only helpers for the Round 9 historical-SO rollback gate.

The module never accepts a production path from the workflow.  Its caller
creates a private temporary sandbox, builds the historical SO from a frozen
production-source capsule derived from v0.16-rc.2, and uses only
``plugin.register`` against synthetic SQLite databases in that sandbox.
"""

from __future__ import annotations

import argparse
import base64
import ctypes
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import sqlite3
import stat
import sys
from typing import Any
import urllib.parse


MANIFEST_SCHEMA = "cyber-abuse-guard-audit-backup-v1"
MANIFEST_KEYS = frozenset(
    {
        "schema",
        "database_file",
        "source_schema_version",
        "target_schema_version",
        "created_at",
        "bytes",
        "sha256",
        "sqlite_quick_check",
        "exact_snapshot",
        "rollback_instruction",
    }
)
ROLLBACK_INSTRUCTION = (
    "stop CPA; verify this manifest; restore this exact database before loading an older SO"
)
HISTORICAL_REPOSITORY = "https://github.com/yujianwudi/cyber-abuse-guard.git"
HISTORICAL_SOURCE_CAPSULE = "testdata/round9-old-so-v0.16-rc.2-source"
HISTORICAL_SOURCE_CAPSULE_SHA256 = (
    "0934503d90f08a7df0403f6325d7f30b6c9bfb0a6ec713d1b160469ee3857f4b"
)
HISTORICAL_SOURCE_FILE_COUNT = 76
HISTORICAL_SOURCE_DATE_EPOCH = 1_784_752_111
SENTINEL_EVENT_ID = "round9-old-so-rollback-event"
SENTINEL_CAPTURE_ID = "round9-old-so-rollback-capture"
SENTINEL_PREVIEW = "synthetic rollback preview; no provider or customer content"
SENTINEL_PREVIEW_SHA256 = hashlib.sha256(SENTINEL_PREVIEW.encode("utf-8")).hexdigest()
FIXED_TIMESTAMP_NS = 1_774_483_200_000_000_000
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


class GateError(RuntimeError):
    """A fail-closed rollback-contract violation."""


class NativeBuffer(ctypes.Structure):
    _fields_ = [("ptr", ctypes.c_void_p), ("length", ctypes.c_size_t)]


PluginCall = ctypes.CFUNCTYPE(
    ctypes.c_int,
    ctypes.c_char_p,
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
    ctypes.POINTER(NativeBuffer),
)
PluginFree = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.c_size_t)
PluginShutdown = ctypes.CFUNCTYPE(None)


class PluginAPI(ctypes.Structure):
    _fields_ = [
        ("abi_version", ctypes.c_uint32),
        ("call", PluginCall),
        ("free_buffer", PluginFree),
        ("shutdown", PluginShutdown),
    ]


def require_linux_amd64() -> None:
    if sys.platform != "linux" or platform.machine() != "x86_64":
        raise GateError("the historical-SO rollback helper requires Linux x86_64")


def require_regular_file(path: Path, label: str) -> os.stat_result:
    try:
        info = path.lstat()
    except FileNotFoundError as exc:
        raise GateError(f"{label} is missing") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise GateError(f"{label} must be a regular non-symlink file")
    return info


def require_private_directory(path: Path, label: str) -> os.stat_result:
    try:
        info = path.lstat()
    except FileNotFoundError as exc:
        raise GateError(f"{label} is missing") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise GateError(f"{label} must be a real directory")
    if stat.S_IMODE(info.st_mode) & 0o077:
        raise GateError(f"{label} must not be accessible by group or other users")
    return info


def file_sha256(path: Path) -> str:
    require_regular_file(path, "hash input")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_json_object(path: Path, label: str) -> dict[str, Any]:
    require_regular_file(path, label)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise GateError(f"{label} is not valid UTF-8 JSON") from exc
    if type(value) is not dict:
        raise GateError(f"{label} must be a JSON object")
    return value


def sqlite_read_only(path: Path) -> sqlite3.Connection:
    require_regular_file(path, "SQLite database")
    quoted = urllib.parse.quote(str(path.resolve()), safe="/")
    connection = sqlite3.connect(
        f"file:{quoted}?mode=ro&immutable=1", uri=True, timeout=2.5
    )
    connection.execute("PRAGMA query_only=ON")
    return connection


def sqlite_quick_check(connection: sqlite3.Connection) -> str:
    rows = [str(row[0]) for row in connection.execute("PRAGMA quick_check")]
    if rows != ["ok"]:
        raise GateError("SQLite quick_check did not return exactly one ok row")
    return rows[0]


def sqlite_schema_version(connection: sqlite3.Connection) -> int:
    row = connection.execute(
        "SELECT version FROM schema_version WHERE singleton=1"
    ).fetchone()
    if row is None or type(row[0]) is not int:
        raise GateError("SQLite schema_version singleton is missing or malformed")
    return int(row[0])


def inspect_database(path: Path, expected_version: int) -> dict[str, Any]:
    with sqlite_read_only(path) as connection:
        quick_check = sqlite_quick_check(connection)
        version = sqlite_schema_version(connection)
        if version != expected_version:
            raise GateError(
                f"SQLite schema version is {version}, expected {expected_version}"
            )
        event_count = int(
            connection.execute(
                "SELECT COUNT(*) FROM audit_events WHERE id=?", (SENTINEL_EVENT_ID,)
            ).fetchone()[0]
        )
        capture_row = connection.execute(
            "SELECT raw_preview, raw_sha256 FROM raw_request_captures WHERE id=?",
            (SENTINEL_CAPTURE_ID,),
        ).fetchone()
        capture_count = 0 if capture_row is None else 1
        if event_count != 1 or capture_count != 1:
            raise GateError("synthetic rollback sentinel event/capture is missing")
        preview = str(capture_row[0])
        raw_sha256 = str(capture_row[1])
        if hashlib.sha256(preview.encode("utf-8")).hexdigest() != SENTINEL_PREVIEW_SHA256:
            raise GateError("synthetic rollback preview digest changed")
        if raw_sha256 != f"sha256:{SENTINEL_PREVIEW_SHA256}":
            raise GateError("synthetic rollback raw_sha256 changed")
        columns = {
            str(row[1]) for row in connection.execute("PRAGMA table_info(audit_events)")
        }
        has_v6_columns = {"disposition", "explanation_schema"}.issubset(columns)
        if has_v6_columns != (expected_version == 6):
            raise GateError("SQLite audit_events columns do not match the schema identity")
    return {
        "schema_version": version,
        "quick_check": quick_check,
        "sentinel_event_count": event_count,
        "sentinel_capture_count": capture_count,
        "sentinel_preview_sha256": SENTINEL_PREVIEW_SHA256,
    }


def domain_digest(prefix: str, domain: bytes, value: bytes) -> str:
    return prefix + hashlib.sha256(domain + value).hexdigest()


def seed_v5_database(path: Path) -> dict[str, Any]:
    info = require_regular_file(path, "v5 seed database")
    if stat.S_IMODE(info.st_mode) & 0o077:
        raise GateError("v5 seed database permissions are not private")
    with sqlite3.connect(path, timeout=2.5) as connection:
        if sqlite_quick_check(connection) != "ok" or sqlite_schema_version(connection) != 5:
            raise GateError("historical SO did not create a valid schema-v5 database")
        request_hash = domain_digest(
            "sha256:",
            b"cyber-abuse-guard/audit/request/v1\x00",
            b"round9-old-so-rollback-request",
        )
        model_hash = domain_digest(
            "sha256-model-v1:",
            b"cyber-abuse-guard/audit/model/v1\x00",
            b"round9-old-so-rollback-model",
        )
        subject_hash = "hmac-sha256:" + hashlib.sha256(
            b"round9-old-so-rollback-subject"
        ).hexdigest()
        connection.execute(
            """
            INSERT INTO audit_events (
                id, timestamp_ns, action, mode, category, risk_score, rule_ids,
                request_hash, subject_hash, model, source_format, stream,
                text_bytes_scanned, classifier, latency_us, decision, coverage,
                incomplete_reason, scanner, decision_explanation
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                SENTINEL_EVENT_ID,
                FIXED_TIMESTAMP_NS,
                "block",
                "balanced",
                "defense_evasion",
                90,
                '["EVADE-002"]',
                request_hash,
                subject_hash,
                model_hash,
                "openai",
                0,
                128,
                "classifier-policy-v7",
                25,
                "block_malicious_text",
                "complete",
                "",
                "streaming-scanner-v1",
                "{}",
            ),
        )
        connection.execute(
            """
            INSERT INTO raw_request_captures (
                id, event_id, timestamp_ns, request_hash, subject_hash, action,
                decision, truncated, redacted, raw_preview, raw_sha256,
                redaction_pattern_hits, redaction_version
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                SENTINEL_CAPTURE_ID,
                SENTINEL_EVENT_ID,
                FIXED_TIMESTAMP_NS,
                request_hash,
                subject_hash,
                "block",
                "block_malicious_text",
                0,
                0,
                SENTINEL_PREVIEW,
                f"sha256:{SENTINEL_PREVIEW_SHA256}",
                0,
                "raw-redactor-v1",
            ),
        )
        connection.commit()
        connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    # sqlite3.Connection's context manager commits or rolls back but does not
    # close the handle.  The final live handle keeps WAL/SHM sidecars present,
    # so close it before asserting the exact single-file rollback snapshot.
    connection.close()
    for suffix in ("-wal", "-shm"):
        sidecar = Path(str(path) + suffix)
        if sidecar.exists() or sidecar.is_symlink():
            raise GateError("v5 fixture retained a SQLite sidecar after checkpoint")
    return inspect_database(path, 5)


def lifecycle_config(data_dir: Path, raw_capture_enabled: bool) -> bytes:
    require_private_directory(data_dir, "historical SO data directory")
    path_text = str(data_dir.resolve())
    if any(character in path_text for character in "\x00\r\n"):
        raise GateError("historical SO data directory contains control characters")
    enabled = "true" if raw_capture_enabled else "false"
    yaml = (
        "enabled: true\n"
        "mode: audit\n"
        "audit:\n"
        "  enabled: true\n"
        f"  data_dir: {json.dumps(path_text)}\n"
        "  retention_days: 3650\n"
        "  backup_before_migration: false\n"
        "  max_migration_backups: 1\n"
        "  raw_capture:\n"
        f"    enabled: {enabled}\n"
        "    only_blocked: true\n"
        "    redact_secrets: true\n"
        "    max_bytes: 8192\n"
        "    ttl_hours: 87600\n"
        "subject_control:\n"
        "  enabled: false\n"
    )
    return yaml.encode("utf-8")


def invoke_old_so(
    so_path: Path,
    data_dir: Path,
    expectation: str,
    expected_version: str,
) -> dict[str, Any]:
    require_linux_amd64()
    require_regular_file(so_path, "historical SO")
    require_private_directory(data_dir, "historical SO data directory")
    database = data_dir / "events.db"
    before_hash = file_sha256(database) if database.exists() else None
    before_sidecars = {
        suffix: (Path(str(database) + suffix).exists()) for suffix in ("-wal", "-shm")
    }

    library = ctypes.CDLL(str(so_path.resolve()), mode=os.RTLD_LOCAL | os.RTLD_NOW)
    init = library.cliproxy_plugin_init
    init.argtypes = [ctypes.c_void_p, ctypes.POINTER(PluginAPI)]
    init.restype = ctypes.c_int
    api = PluginAPI()
    if init(None, ctypes.byref(api)) != 0 or api.abi_version != 1:
        raise GateError("historical SO ABI initialization failed")

    raw_capture_enabled = expectation != "reject-v6"
    request = json.dumps(
        {
            "schema_version": 1,
            "config_yaml": base64.b64encode(
                lifecycle_config(data_dir, raw_capture_enabled)
            ).decode("ascii"),
        },
        separators=(",", ":"),
    ).encode("utf-8")
    request_buffer = (ctypes.c_uint8 * len(request)).from_buffer_copy(request)
    response = NativeBuffer()
    try:
        return_code = api.call(
            b"plugin.register",
            request_buffer,
            len(request),
            ctypes.byref(response),
        )
        if response.ptr is None or response.length == 0:
            raise GateError("historical SO returned an empty registration response")
        response_bytes = ctypes.string_at(response.ptr, response.length)
        try:
            envelope = json.loads(response_bytes.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise GateError("historical SO returned an invalid registration envelope") from exc
    finally:
        if response.ptr:
            api.free_buffer(response.ptr, response.length)
        api.shutdown()

    if return_code != 0 or type(envelope) is not dict:
        raise GateError("historical SO registration returned an ABI failure")
    if expectation in {"create-v5", "accept-v5"}:
        result = envelope.get("result")
        metadata = result.get("metadata") if type(result) is dict else None
        if (
            envelope.get("ok") is not True
            or type(result) is not dict
            or result.get("schema_version") != 1
            or type(metadata) is not dict
            or metadata.get("Version") != expected_version
        ):
            raise GateError("historical SO did not accept the schema-v5 fixture")
        database_state = inspect_database(database, 5) if expectation == "accept-v5" else {}
        return {
            "expectation": expectation,
            "accepted": True,
            "abi_version": api.abi_version,
            "plugin_version": metadata.get("Version"),
            "rpc_methods": ["plugin.register"],
            "database": database_state,
        }

    error = envelope.get("error")
    expected_message = "database schema version 6 is newer than supported version 5"
    if (
        expectation != "reject-v6"
        or envelope.get("ok") is not False
        or type(error) is not dict
        or error.get("code") != "invalid_config"
        or expected_message not in str(error.get("message", ""))
    ):
        raise GateError("historical SO did not fail closed on schema v6")
    after_hash = file_sha256(database)
    after_sidecars = {
        suffix: (Path(str(database) + suffix).exists()) for suffix in ("-wal", "-shm")
    }
    if before_hash != after_hash or before_sidecars != after_sidecars:
        raise GateError("historical SO changed the isolated schema-v6 probe database")
    return {
        "expectation": expectation,
        "accepted": False,
        "error_code": "invalid_config",
        "schema_gate": expected_message,
        "database_sha256_unchanged": True,
        "sqlite_sidecars_unchanged": True,
        "rpc_methods": ["plugin.register"],
    }


def validate_manifest(backup: Path, manifest_path: Path) -> dict[str, Any]:
    backup_info = require_regular_file(backup, "pre-v6 backup")
    manifest_info = require_regular_file(manifest_path, "pre-v6 manifest")
    if stat.S_IMODE(backup_info.st_mode) != 0o400:
        raise GateError("pre-v6 backup mode must be exactly 0400")
    if stat.S_IMODE(manifest_info.st_mode) != 0o400:
        raise GateError("pre-v6 manifest mode must be exactly 0400")
    if manifest_path != Path(str(backup) + ".manifest.json"):
        raise GateError("pre-v6 manifest path is not paired with its backup")
    manifest = read_json_object(manifest_path, "pre-v6 manifest")
    if set(manifest) != MANIFEST_KEYS:
        raise GateError("pre-v6 manifest fields differ from the closed contract")
    if manifest.get("schema") != MANIFEST_SCHEMA:
        raise GateError("pre-v6 manifest schema identity changed")
    database_file = manifest.get("database_file")
    if type(database_file) is not str or Path(database_file).name != database_file:
        raise GateError("pre-v6 manifest database_file is not a basename")
    if database_file != backup.name:
        raise GateError("pre-v6 manifest database_file does not name the backup")
    if type(manifest.get("source_schema_version")) is not int or manifest.get(
        "source_schema_version"
    ) != 5:
        raise GateError("pre-v6 manifest source schema must be exactly 5")
    if type(manifest.get("target_schema_version")) is not int or manifest.get(
        "target_schema_version"
    ) != 6:
        raise GateError("pre-v6 manifest target schema must be exactly 6")
    if type(manifest.get("bytes")) is not int or manifest.get("bytes") != backup_info.st_size:
        raise GateError("pre-v6 manifest byte count does not match the backup")
    digest = file_sha256(backup)
    if manifest.get("sha256") != f"sha256:{digest}" or not SHA256_RE.fullmatch(
        str(manifest.get("sha256", ""))
    ):
        raise GateError("pre-v6 manifest SHA-256 does not match the backup")
    if manifest.get("sqlite_quick_check") != "ok":
        raise GateError("pre-v6 manifest quick_check claim is not ok")
    if type(manifest.get("exact_snapshot")) is not bool or manifest.get(
        "exact_snapshot"
    ) is not True:
        raise GateError("pre-v6 manifest exact_snapshot must be true")
    if manifest.get("rollback_instruction") != ROLLBACK_INSTRUCTION:
        raise GateError("pre-v6 manifest rollback instruction changed")
    created_at = manifest.get("created_at")
    if type(created_at) is not str or not created_at.endswith("Z"):
        raise GateError("pre-v6 manifest creation time must be UTC")
    try:
        dt.datetime.fromisoformat(created_at.removesuffix("Z") + "+00:00")
    except ValueError as exc:
        raise GateError("pre-v6 manifest creation time is invalid") from exc
    database = inspect_database(backup, 5)
    return {
        "manifest_schema": MANIFEST_SCHEMA,
        "source_schema_version": 5,
        "target_schema_version": 6,
        "bytes": backup_info.st_size,
        "sha256": f"sha256:{digest}",
        "sqlite_quick_check": database["quick_check"],
        "exact_snapshot": True,
        "sentinel_event_count": database["sentinel_event_count"],
        "sentinel_capture_count": database["sentinel_capture_count"],
        "sentinel_preview_sha256": database["sentinel_preview_sha256"],
    }


def restore_backup(backup: Path, manifest: Path, destination: Path) -> dict[str, Any]:
    verified = validate_manifest(backup, manifest)
    require_private_directory(destination.parent, "restore destination directory")
    if destination.exists() or destination.is_symlink():
        raise GateError("restore destination already exists")
    source_fd = os.open(backup, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    destination_fd = -1
    try:
        destination_fd = os.open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
        )
        while True:
            chunk = os.read(source_fd, 1024 * 1024)
            if not chunk:
                break
            view = memoryview(chunk)
            while view:
                written = os.write(destination_fd, view)
                if written <= 0:
                    raise GateError("restore write did not make progress")
                view = view[written:]
        os.fchmod(destination_fd, 0o600)
        os.fsync(destination_fd)
    except Exception:
        if destination_fd >= 0:
            os.close(destination_fd)
            destination_fd = -1
        destination.unlink(missing_ok=True)
        raise
    finally:
        os.close(source_fd)
        if destination_fd >= 0:
            os.close(destination_fd)
    directory_fd = os.open(destination.parent, os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    destination_info = require_regular_file(destination, "restored v5 database")
    if stat.S_IMODE(destination_info.st_mode) != 0o600:
        raise GateError("restored v5 database mode must be exactly 0600")
    restored_digest = f"sha256:{file_sha256(destination)}"
    if restored_digest != verified["sha256"]:
        raise GateError("restored v5 database does not match the manifest SHA-256")
    inspected = inspect_database(destination, 5)
    return {
        "restored_sha256": restored_digest,
        "manifest_sha256_match": True,
        "mode": "0600",
        **inspected,
    }


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    parent_info = path.parent.lstat()
    if stat.S_ISLNK(parent_info.st_mode) or not stat.S_ISDIR(parent_info.st_mode):
        raise GateError("JSON output directory must be a real directory")
    if path.parent.resolve() != path.parent.absolute():
        raise GateError("JSON output directory may not resolve through a symlink")
    temporary = path.with_name(path.name + f".tmp-{os.getpid()}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW
    descriptor = os.open(temporary, flags, 0o600)
    try:
        payload = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise GateError("JSON output write did not make progress")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)
    os.chmod(path, 0o600)


def assemble_report(args: argparse.Namespace) -> dict[str, Any]:
    create = read_json_object(args.create_result, "historical create result")
    migration = read_json_object(args.migration_result, "v6 migration result")
    manifest = read_json_object(args.manifest_result, "manifest result")
    rejection = read_json_object(args.rejection_result, "historical rejection result")
    restore = read_json_object(args.restore_result, "restore result")
    acceptance = read_json_object(args.acceptance_result, "historical acceptance result")
    if create.get("accepted") is not True or acceptance.get("accepted") is not True:
        raise GateError("historical SO v5 compatibility result is not passing")
    if rejection.get("accepted") is not False or rejection.get(
        "database_sha256_unchanged"
    ) is not True:
        raise GateError("historical SO v6 rejection result is not passing")
    if migration.get("source_schema_version") != 5 or migration.get(
        "target_schema_version"
    ) != 6:
        raise GateError("current-source migration result is not v5 to v6")
    if manifest.get("sha256") != restore.get("restored_sha256"):
        raise GateError("restored database identity differs from the migration manifest")
    if args.repository != HISTORICAL_REPOSITORY:
        raise GateError("historical source repository differs from the frozen predecessor")
    if args.source_capsule != HISTORICAL_SOURCE_CAPSULE:
        raise GateError("historical source capsule path differs from the reviewed fixture")
    if args.source_capsule_sha256 != HISTORICAL_SOURCE_CAPSULE_SHA256:
        raise GateError("historical source capsule SHA-256 differs from the reviewed fixture")
    if args.source_file_count != HISTORICAL_SOURCE_FILE_COUNT:
        raise GateError("historical source capsule file count differs from the reviewed fixture")
    if args.source_date_epoch != HISTORICAL_SOURCE_DATE_EPOCH:
        raise GateError("historical source timestamp differs from the reviewed fixture")
    report = {
        "schema": "round9-old-so-rollback-gate/v2",
        "platform": "linux/amd64",
        "go_runtime": args.go_runtime,
        "historical_source": {
            "repository": args.repository,
            "tag": args.tag,
            "tag_object": args.tag_object,
            "commit": args.commit,
            "tree": args.tree,
            "classifier": args.classifier,
            "classifier_sha256": args.classifier_sha256,
            "ruleset": args.ruleset,
            "ruleset_sha256": args.ruleset_sha256,
            "source_mode": "repository_local_reviewed_production_capsule",
            "capsule_path": args.source_capsule,
            "capsule_sha256": f"sha256:{args.source_capsule_sha256}",
            "capsule_file_count": args.source_file_count,
            "source_date_epoch": args.source_date_epoch,
            "remote_ref_verified": False,
            "remote_dependency_required": False,
        },
        "historical_so": {
            "provenance": "rebuilt_from_frozen_reviewed_production_source_capsule",
            "bytes": args.so_bytes,
            "sha256": f"sha256:{args.so_sha256}",
            "archived_release_so_byte_identity": "NOT_PROVIDED",
        },
        "migration_backup": manifest,
        "restoration": restore,
        "compatibility": {
            "old_so_created_schema_v5": True,
            "old_so_rejected_schema_v6": True,
            "old_so_v6_probe_database_unchanged": True,
            "old_so_accepted_exact_restored_v5": True,
            "schema_gate": rejection.get("schema_gate"),
            "rpc_methods": ["plugin.register"],
            "provider_contacted": False,
            "production_contacted": False,
        },
        "restricted_material_zero_access_claim": False,
        "external_conditions": {
            "archived_release_so_byte_identity": "NOT_PROVIDED",
            "independent_audit": "REQUIRES INDEPENDENT AUDIT",
            "production_admission": "BLOCKED",
        },
        "conclusion": "BLOCKED / NOT PROVIDED / REQUIRES INDEPENDENT AUDIT",
    }
    write_json(args.output, report)
    return report


def emit_result(args: argparse.Namespace, value: dict[str, Any]) -> None:
    if args.output is not None:
        write_json(args.output, value)
    else:
        print(json.dumps(value, sort_keys=True))


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    old_so = subparsers.add_parser("old-so")
    old_so.add_argument("--so", type=Path, required=True)
    old_so.add_argument("--data-dir", type=Path, required=True)
    old_so.add_argument(
        "--expect", choices=("create-v5", "accept-v5", "reject-v6"), required=True
    )
    old_so.add_argument("--expected-version", required=True)
    old_so.add_argument("--output", type=Path)

    seed = subparsers.add_parser("seed-v5")
    seed.add_argument("--database", type=Path, required=True)
    seed.add_argument("--output", type=Path)

    inspect = subparsers.add_parser("inspect")
    inspect.add_argument("--database", type=Path, required=True)
    inspect.add_argument("--expected-version", type=int, choices=(5, 6), required=True)
    inspect.add_argument("--output", type=Path)

    verify = subparsers.add_parser("verify-backup")
    verify.add_argument("--backup", type=Path, required=True)
    verify.add_argument("--manifest", type=Path, required=True)
    verify.add_argument("--output", type=Path)

    restore = subparsers.add_parser("restore")
    restore.add_argument("--backup", type=Path, required=True)
    restore.add_argument("--manifest", type=Path, required=True)
    restore.add_argument("--destination", type=Path, required=True)
    restore.add_argument("--output", type=Path)

    report = subparsers.add_parser("report")
    for name in (
        "create_result",
        "migration_result",
        "manifest_result",
        "rejection_result",
        "restore_result",
        "acceptance_result",
    ):
        report.add_argument(f"--{name.replace('_', '-')}", type=Path, required=True)
    for name in (
        "repository",
        "tag",
        "tag_object",
        "commit",
        "tree",
        "classifier",
        "classifier_sha256",
        "ruleset",
        "ruleset_sha256",
        "go_runtime",
        "source_capsule",
        "source_capsule_sha256",
        "so_sha256",
    ):
        report.add_argument(f"--{name.replace('_', '-')}", required=True)
    report.add_argument("--source-file-count", type=int, required=True)
    report.add_argument("--source-date-epoch", type=int, required=True)
    report.add_argument("--so-bytes", type=int, required=True)
    report.add_argument("--output", type=Path, required=True)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        if args.command == "old-so":
            emit_result(
                args,
                invoke_old_so(
                    args.so, args.data_dir, args.expect, args.expected_version
                ),
            )
        elif args.command == "seed-v5":
            emit_result(args, seed_v5_database(args.database))
        elif args.command == "inspect":
            emit_result(args, inspect_database(args.database, args.expected_version))
        elif args.command == "verify-backup":
            emit_result(args, validate_manifest(args.backup, args.manifest))
        elif args.command == "restore":
            emit_result(
                args, restore_backup(args.backup, args.manifest, args.destination)
            )
        elif args.command == "report":
            assemble_report(args)
        else:
            raise GateError("unsupported rollback helper command")
    except (GateError, OSError, sqlite3.Error, ValueError) as exc:
        print(f"Round 9 old-SO rollback helper: FAIL: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
