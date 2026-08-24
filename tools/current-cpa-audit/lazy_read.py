#!/usr/bin/env python3
"""Text-free evidence producer for the Round 14 lazy-read boundary.

The producer records only source metadata and irreversible digests.  Corpus
bytes stay caller-owned and are never retained by this module.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
from pathlib import Path
from typing import Any, Mapping

from audit_contract import (
    canonical_bytes,
    read_regular_bytes,
    require_safe_relative,
    sha256_bytes,
)


PHASE_SCHEMA = "cag-current-cpa-lazy-read-phase-boundary/v1"
TRACE_SCHEMA = "cag-current-cpa-lazy-read-trace/v1"
SUMMARY_SCHEMA = "cag-current-cpa-lazy-read-summary/v1"
SAFE_RUN_ID = re.compile(r"[a-z0-9][a-z0-9_.-]{2,62}")
HEX64 = re.compile(r"[0-9a-f]{64}")


class LazyReadError(RuntimeError):
    """The lazy-read producer could not prove its closed evidence contract."""


def _fail(message: str) -> None:
    raise LazyReadError(message)


def _exclusive_file(path: Path) -> Any:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        handle = os.fdopen(descriptor, "wb", closefd=True)
    except BaseException:
        os.close(descriptor)
        raise
    os.chmod(path, 0o600)
    return handle


def _write_canonical_exclusive(path: Path, value: Mapping[str, Any]) -> None:
    raw = canonical_bytes(dict(value)) + b"\n"
    handle = _exclusive_file(path)
    try:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())
    finally:
        handle.close()


def case_id_hash(case_id: str) -> str:
    if not isinstance(case_id, str) or not case_id or "\x00" in case_id:
        _fail("lazy-read case identity is invalid")
    return hashlib.sha256(case_id.encode("utf-8", "strict")).hexdigest()


class LazyReadRecorder:
    """Append-only producer for phase, trace, and cleanup evidence.

    ``record_preflight`` and ``record_transport`` accept metadata only.  In
    particular, they deliberately have no argument capable of retaining source
    text.
    """

    def __init__(self, evidence_root: Path, run_id: str) -> None:
        if SAFE_RUN_ID.fullmatch(run_id) is None:
            _fail("lazy-read run identity is unsafe")
        self.run_id = run_id
        self.directory = evidence_root / "lazy-read"
        self.phase_path = self.directory / "phase-boundary.json"
        self.trace_path = self.directory / "runtime-read-trace.jsonl"
        self.summary_path = self.directory / "runtime-read-summary.json"
        self.phase = "preflight"
        self.ordinal = 0
        self.preflight_read_count = 0
        self.transport_read_count = 0
        self._closed = False
        self._finalized = False
        created_directory = False
        try:
            self.directory.mkdir(mode=0o700)
            created_directory = True
            os.chmod(self.directory, 0o700)
            info = self.directory.lstat()
            if not self.directory.is_dir() or self.directory.is_symlink():
                _fail("lazy-read evidence path is not a real directory")
            if os.name == "posix" and info.st_mode & 0o077:
                _fail("lazy-read evidence directory is not private")
            self._trace = _exclusive_file(self.trace_path)
            trace_info = os.fstat(self._trace.fileno())
            self._trace_identity = (trace_info.st_dev, trace_info.st_ino)
        except BaseException:
            trace = getattr(self, "_trace", None)
            if trace is not None and not trace.closed:
                trace.close()
            if created_directory:
                try:
                    self.trace_path.unlink(missing_ok=True)
                    self.directory.rmdir()
                except OSError:
                    pass
            raise

    @staticmethod
    def _digest(value: str, label: str) -> str:
        if not isinstance(value, str) or HEX64.fullmatch(value) is None:
            _fail(f"{label} is not a lowercase SHA-256")
        return value

    @staticmethod
    def _size(value: int) -> int:
        if type(value) is not int or value <= 0:
            _fail("lazy-read source byte length must be positive")
        return value

    def _append(
        self,
        *,
        phase: str,
        source_path: str,
        source_bytes: int,
        source_sha256: str,
        case_identity: str,
        request_sha256: str | None,
    ) -> None:
        if self._closed or self._finalized:
            _fail("lazy-read trace is already closed")
        if phase != self.phase:
            _fail("lazy-read producer phase drifted")
        require_safe_relative(source_path, "lazy-read source path", "corpus")
        self._size(source_bytes)
        self._digest(source_sha256, "lazy-read source digest")
        if phase == "preflight":
            if request_sha256 is not None:
                _fail("preflight lazy-read rows cannot bind a request")
        elif phase == "transport":
            if request_sha256 is None:
                _fail("transport lazy-read rows require a request digest")
            self._digest(request_sha256, "lazy-read request digest")
        else:
            _fail("lazy-read phase is unsupported")
        self.ordinal += 1
        row = {
            "bytes": source_bytes,
            "case_id_hash": case_id_hash(case_identity),
            "ordinal": self.ordinal,
            "phase": phase,
            "request_sha256": request_sha256,
            "run_id": self.run_id,
            "schema": TRACE_SCHEMA,
            "source_path": source_path,
            "source_sha256": source_sha256,
        }
        self._trace.write(canonical_bytes(row) + b"\n")
        if phase == "preflight":
            self.preflight_read_count += 1
        else:
            self.transport_read_count += 1

    def record_preflight(
        self,
        *,
        source_path: str,
        source_bytes: int,
        source_sha256: str,
        case_identity: str,
    ) -> None:
        self._append(
            phase="preflight",
            source_path=source_path,
            source_bytes=source_bytes,
            source_sha256=source_sha256,
            case_identity=case_identity,
            request_sha256=None,
        )

    def start_transport(self) -> None:
        if self.phase != "preflight" or self._closed or self._finalized:
            _fail("lazy-read transport phase cannot start twice")
        if self.preflight_read_count <= 0:
            _fail("lazy-read preflight observed no real source reads")
        self._trace.flush()
        os.fsync(self._trace.fileno())
        _write_canonical_exclusive(
            self.phase_path,
            {
                "preflight_completed": True,
                "preflight_full_corpus_cache_created": False,
                "run_id": self.run_id,
                "schema": PHASE_SCHEMA,
                "status": "PASS",
                "transport_started_after_preflight": True,
            },
        )
        self.phase = "transport"

    def record_transport(
        self,
        *,
        source_path: str,
        source_bytes: int,
        source_sha256: str,
        case_identity: str,
        request_sha256: str,
    ) -> None:
        self._append(
            phase="transport",
            source_path=source_path,
            source_bytes=source_bytes,
            source_sha256=source_sha256,
            case_identity=case_identity,
            request_sha256=request_sha256,
        )

    def _close_trace(self) -> None:
        if self._closed:
            return
        self._trace.flush()
        os.fsync(self._trace.fileno())
        self._trace.close()
        self._closed = True

    def abort(self) -> None:
        """Close a partial trace without ever labelling it PASS."""

        self._close_trace()

    def finalize(
        self,
        *,
        expected_transport_reads: int,
        finally_cleanup_complete: bool,
        post_unlink_nlink_zero: bool,
        supplemental_member_text_retained: bool,
        temporary_secret_or_config_retained: bool,
        third_party_text_retained: bool,
    ) -> dict[str, Any]:
        if self._finalized:
            _fail("lazy-read evidence was finalized twice")
        if self.phase != "transport":
            _fail("lazy-read transport phase never started")
        if type(expected_transport_reads) is not int or expected_transport_reads <= 0:
            _fail("lazy-read expected transport denominator is invalid")
        if self.transport_read_count != expected_transport_reads:
            _fail("lazy-read trace does not cover every transport execution")
        privacy = {
            "finally_cleanup_complete": finally_cleanup_complete,
            "post_unlink_nlink_zero": post_unlink_nlink_zero,
            "supplemental_member_text_retained": supplemental_member_text_retained,
            "temporary_secret_or_config_retained": temporary_secret_or_config_retained,
            "third_party_text_retained": third_party_text_retained,
        }
        if any(type(value) is not bool for value in privacy.values()):
            _fail("lazy-read cleanup claims must be booleans")
        if not finally_cleanup_complete or not post_unlink_nlink_zero:
            _fail("lazy-read cleanup proof is incomplete")
        if any(
            privacy[key]
            for key in (
                "supplemental_member_text_retained",
                "temporary_secret_or_config_retained",
                "third_party_text_retained",
            )
        ):
            _fail("lazy-read cleanup retained sensitive runtime state")
        self._close_trace()
        trace_info = self.trace_path.lstat()
        if (
            stat.S_ISLNK(trace_info.st_mode)
            or not stat.S_ISREG(trace_info.st_mode)
            or trace_info.st_nlink != 1
            or (trace_info.st_dev, trace_info.st_ino) != self._trace_identity
        ):
            _fail("lazy-read trace identity changed before finalization")
        trace_raw = read_regular_bytes(
            self.trace_path,
            "lazy-read runtime trace",
            64 * 1024 * 1024,
            require_single_link=True,
        )
        if not trace_raw or not trace_raw.endswith(b"\n"):
            _fail("lazy-read trace bytes are incomplete")
        summary = {
            **privacy,
            "full_corpus_cache_created": False,
            "run_id": self.run_id,
            "schema": SUMMARY_SCHEMA,
            "status": "PASS",
            "trace_sha256": sha256_bytes(trace_raw),
            "transport_request_count": self.transport_read_count,
            "transport_source_read_count": self.transport_read_count,
        }
        _write_canonical_exclusive(self.summary_path, summary)
        self._finalized = True
        return summary


__all__ = [
    "LazyReadError",
    "LazyReadRecorder",
    "PHASE_SCHEMA",
    "SUMMARY_SCHEMA",
    "TRACE_SCHEMA",
    "case_id_hash",
]
