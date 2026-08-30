#!/usr/bin/env python3
"""Isolated counted-Mock-only Keeper fixture for Host admission.

The fixture consumes the authenticated CPA v7.2.145 usage PopOldest queue,
validates the exact successful counted-Mock usage shape, and persists only a
monotonic observation count plus keyed, non-reversible event identities.  It
never accepts operator-authored usage records and never stores CPA response
bodies, request bodies, API keys, management credentials, or control tokens.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import hmac
import http.client
import ipaddress
import json
import os
import re
import signal
import socket
import sqlite3
import stat
import sys
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Mapping, NoReturn, Sequence
from urllib.parse import urlsplit


CONTRACT = "cag-current-cpa-host-keeper/v1"
OBSERVATION_SOURCE = "CPA_AUTHENTICATED_POP_OLDEST"
DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 18081
DEFAULT_DATABASE = "/var/lib/cag-host-keeper/keeper.sqlite3"
SOURCE_PATH = "/opt/cag-host-keeper/keeper_fixture.py"
SOURCE_HASH_PATH = SOURCE_PATH + ".sha256"

CPA_TAG = "v7.2.145"
CPA_COMMIT = "d9cea8904b14fbbebb77ef26e98ef08f6b48a724"
CAG_AUDIT_SCHEMA_VERSION = 7
EXPECTED_MODEL = "current-cpa-audit-model"
# CPA v7.2.145 turns the configured OpenAI-compatibility name
# ``current-cpa-counted-mock`` into this internal executor/provider identity.
# The usage reporter publishes executor.Identifier(), not the display name.
EXPECTED_PROVIDER = "openai-compatible-current-cpa-counted-mock"
EXPECTED_EXECUTOR = "OpenAICompatExecutor"
EXPECTED_ENDPOINTS = (
    "POST /v1/chat/completions",
    "POST /v1/responses",
)
EXPECTED_TOKEN_TOTALS = (5, 3, 8)

DATABASE_SCHEMA_VERSION = 1
MAX_HTTP_BODY = 1024 * 1024
MAX_USAGE_RESPONSE = 4 * 1024 * 1024
MAX_USAGE_BATCH = 100
MAX_USAGE_RECORDS = 100_000
MAX_DATABASE_BYTES = 64 * 1024 * 1024
MAX_SECRET_BYTES = 4096
MAX_CONTROL_BODY = 1024
MAX_COUNTER = (1 << 63) - 1
POLL_COUNT = 100
MIN_POLL_INTERVAL = 0.05
MAX_POLL_INTERVAL = 1.0
DEFAULT_POLL_INTERVAL = 0.10
CPA_TIMEOUT_SECONDS = 2.0
HEALTH_TIMEOUT_SECONDS = 0.5

SAFE_RUN_ID = re.compile(r"[a-z0-9][a-z0-9_.-]{2,62}")
HEX40 = re.compile(r"[0-9a-f]{40}")
SAFE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}")
SAFE_HOST = re.compile(r"[a-z0-9][a-z0-9.-]{0,252}")
BEARER_TOKEN = re.compile(r"[A-Za-z0-9._~+/=-]{32,4096}")
RFC1918_NETWORKS = tuple(
    ipaddress.ip_network(value)
    for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)
ALLOWED_MODES = ("audit", "balanced", "strict")


class KeeperError(RuntimeError):
    """A bounded fixture contract failed."""


class ConfigurationError(KeeperError):
    """The operator configuration is not closed or safe."""


class ProbeError(KeeperError):
    """A CPA readiness or queue probe failed without retaining its body."""


class UsageRecordError(KeeperError):
    """A destructively popped usage record is not the frozen Mock contract."""


class DatabaseInvariantError(KeeperError):
    """The monotonic SQLite state is unavailable or inconsistent."""


class DuplicateObservation(DatabaseInvariantError):
    """A previously counted request identity was observed again."""


class RollbackForbidden(DatabaseInvariantError):
    """A reset would make the persistent usage observation go backwards."""


def fail(message: str) -> NoReturn:
    raise KeeperError(message)


def compact_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("ascii")


def reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


def reject_constant(value: str) -> NoReturn:
    raise ValueError(f"non-finite JSON number {value}")


def strict_json(raw: bytes | bytearray, label: str) -> Any:
    try:
        text = bytes(raw).decode("utf-8", "strict")
        return json.loads(
            text,
            object_pairs_hook=reject_duplicate_pairs,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise KeeperError(f"{label} is not strict JSON") from exc


def exact_object(
    value: Any,
    required: set[str],
    label: str,
    optional: set[str] | None = None,
) -> dict[str, Any]:
    if type(value) is not dict:
        raise KeeperError(f"{label} must be an object")
    allowed = required | (optional or set())
    keys = set(value)
    if not required.issubset(keys) or not keys.issubset(allowed):
        raise KeeperError(f"{label} keys do not match the frozen contract")
    return value


def exact_int(value: Any, label: str, minimum: int = 0, maximum: int = MAX_COUNTER) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise KeeperError(f"{label} must be a bounded integer")
    return value


def exact_bool(value: Any, label: str) -> bool:
    if type(value) is not bool:
        raise KeeperError(f"{label} must be a boolean")
    return value


def bounded_string(value: Any, label: str, maximum: int = 1024) -> str:
    if type(value) is not str or not value or len(value.encode("utf-8")) > maximum:
        raise KeeperError(f"{label} must be a bounded non-empty string")
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in value):
        raise KeeperError(f"{label} contains a control character")
    return value


def optional_string(value: Any, label: str, maximum: int = 1024) -> str:
    if type(value) is not str or len(value.encode("utf-8")) > maximum:
        raise KeeperError(f"{label} must be a bounded string")
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in value):
        raise KeeperError(f"{label} contains a control character")
    return value


def strict_timestamp(value: Any, label: str) -> str:
    text = bounded_string(value, label, 64)
    normalized = text[:-1] + "+00:00" if text.endswith("Z") else text
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise KeeperError(f"{label} must be an RFC3339 timestamp") from exc
    if parsed.tzinfo is None:
        raise KeeperError(f"{label} must include a timezone")
    return text


def read_secret(environment: Mapping[str, str], name: str) -> str:
    direct = environment.get(name, "")
    file_name = environment.get(name + "_FILE", "")
    if bool(direct) == bool(file_name):
        raise ConfigurationError(f"exactly one of {name} or {name}_FILE is required")
    if file_name:
        path = Path(file_name)
        if not path.is_absolute():
            raise ConfigurationError(f"{name}_FILE must be an absolute path")
        try:
            parent_info = path.parent.lstat()
            if not stat.S_ISDIR(parent_info.st_mode):
                raise ConfigurationError(f"{name}_FILE parent is not a directory")
            if path.parent.resolve(strict=True) != path.parent:
                raise ConfigurationError(f"{name}_FILE parent must not traverse a symlink")
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ConfigurationError(f"{name}_FILE must be a single-link regular file")
            if os.name == "posix" and (
                info.st_uid != os.getuid()
                or info.st_gid != os.getgid()
                or stat.S_IMODE(info.st_mode) & 0o077
                or stat.S_IMODE(parent_info.st_mode) & 0o022
            ):
                raise ConfigurationError(
                    f"{name}_FILE must be owned by the process and private"
                )
            if info.st_size < 32 or info.st_size > MAX_SECRET_BYTES:
                raise ConfigurationError(f"{name}_FILE has an invalid size")
            raw = bytearray(path.read_bytes())
        except OSError as exc:
            raise ConfigurationError(f"{name}_FILE is unavailable") from exc
        try:
            if len(raw) > MAX_SECRET_BYTES:
                raise ConfigurationError(f"{name}_FILE exceeds the size limit")
            value = bytes(raw).decode("utf-8", "strict").strip()
        except UnicodeDecodeError as exc:
            raise ConfigurationError(f"{name}_FILE is not UTF-8") from exc
        finally:
            for index in range(len(raw)):
                raw[index] = 0
    else:
        value = direct
    if BEARER_TOKEN.fullmatch(value) is None:
        raise ConfigurationError(f"{name} must be a bounded ASCII bearer token")
    return value


@dataclass(frozen=True)
class KeeperConfig:
    run_id: str
    database_path: Path
    cpa_origin: str
    expected_mode: str
    expected_cag_commit: str
    expected_provider: str
    expected_model: str
    expected_executor: str
    control_token: str
    management_key: str
    poll_interval: float = DEFAULT_POLL_INTERVAL

    @classmethod
    def from_environment(
        cls,
        database_path: Path,
        environment: Mapping[str, str] | None = None,
    ) -> "KeeperConfig":
        env = os.environ if environment is None else environment
        run_id = env.get("CAG_KEEPER_RUN_ID", "")
        if SAFE_RUN_ID.fullmatch(run_id) is None:
            raise ConfigurationError("CAG_KEEPER_RUN_ID is not a safe run identity")
        mode = env.get("CAG_KEEPER_EXPECTED_MODE", "")
        if mode not in ALLOWED_MODES:
            raise ConfigurationError("CAG_KEEPER_EXPECTED_MODE is not frozen")
        cag_commit = env.get("CAG_KEEPER_EXPECTED_CAG_COMMIT", "")
        if HEX40.fullmatch(cag_commit) is None or not cag_commit.strip("0"):
            raise ConfigurationError("CAG_KEEPER_EXPECTED_CAG_COMMIT is invalid")
        origin = env.get("CAG_KEEPER_CPA_ORIGIN", "")
        StrictPrivateOrigin.parse(origin)
        provider = env.get("CAG_KEEPER_EXPECTED_PROVIDER", EXPECTED_PROVIDER)
        model = env.get("CAG_KEEPER_EXPECTED_MODEL", EXPECTED_MODEL)
        executor = env.get("CAG_KEEPER_EXPECTED_EXECUTOR", EXPECTED_EXECUTOR)
        for value, label in (
            (provider, "CAG_KEEPER_EXPECTED_PROVIDER"),
            (model, "CAG_KEEPER_EXPECTED_MODEL"),
            (executor, "CAG_KEEPER_EXPECTED_EXECUTOR"),
        ):
            if SAFE_NAME.fullmatch(value) is None:
                raise ConfigurationError(f"{label} is invalid")
        raw_interval = env.get("CAG_KEEPER_POLL_INTERVAL_SECONDS", str(DEFAULT_POLL_INTERVAL))
        try:
            interval = float(raw_interval)
        except ValueError as exc:
            raise ConfigurationError("CAG_KEEPER_POLL_INTERVAL_SECONDS is invalid") from exc
        if not MIN_POLL_INTERVAL <= interval <= MAX_POLL_INTERVAL:
            raise ConfigurationError("CAG_KEEPER_POLL_INTERVAL_SECONDS is out of range")
        control = read_secret(env, "CAG_KEEPER_CONTROL_TOKEN")
        management = read_secret(env, "CAG_KEEPER_CPA_MANAGEMENT_KEY")
        if hmac.compare_digest(control.encode("utf-8"), management.encode("utf-8")):
            raise ConfigurationError("control and management secrets must be distinct")
        return cls(
            run_id=run_id,
            database_path=database_path,
            cpa_origin=origin,
            expected_mode=mode,
            expected_cag_commit=cag_commit,
            expected_provider=provider,
            expected_model=model,
            expected_executor=executor,
            control_token=control,
            management_key=management,
            poll_interval=interval,
        )


@dataclass(frozen=True)
class StrictPrivateOrigin:
    host: str
    port: int

    @classmethod
    def parse(cls, origin: str) -> "StrictPrivateOrigin":
        try:
            parsed = urlsplit(origin)
            port = parsed.port
        except ValueError as exc:
            raise ConfigurationError("CPA origin is malformed") from exc
        if (
            parsed.scheme != "http"
            or not parsed.hostname
            or port is None
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in ("", "/")
            or parsed.query
            or parsed.fragment
            or not 1 <= port <= 65535
        ):
            raise ConfigurationError("CPA origin must be an exact private HTTP origin")
        host = parsed.hostname.lower()
        if SAFE_HOST.fullmatch(host) is None:
            raise ConfigurationError("CPA origin hostname is invalid")
        return cls(host=host, port=port)

    def resolve(self, *, allow_loopback: bool = False) -> str:
        try:
            results = socket.getaddrinfo(
                self.host,
                self.port,
                family=socket.AF_INET,
                type=socket.SOCK_STREAM,
            )
        except OSError as exc:
            raise ProbeError("cpa_private_dns_failed") from exc
        addresses = {entry[4][0] for entry in results}
        if len(addresses) != 1:
            raise ProbeError("cpa_private_dns_not_single_address")
        address = ipaddress.ip_address(next(iter(addresses)))
        private = any(address in network for network in RFC1918_NETWORKS)
        if not private and not (allow_loopback and address.is_loopback):
            raise ProbeError("cpa_address_not_isolated_rfc1918")
        return str(address)

    @property
    def host_header(self) -> str:
        return f"{self.host}:{self.port}"


class CPAClient:
    """Bounded, proxy-independent CPA client for the private bridge only."""

    def __init__(
        self,
        config: KeeperConfig,
        *,
        allow_loopback_for_tests: bool = False,
    ) -> None:
        self.config = config
        self.origin = StrictPrivateOrigin.parse(config.cpa_origin)
        self.allow_loopback_for_tests = allow_loopback_for_tests

    def _request(
        self,
        path: str,
        *,
        management: bool,
        maximum: int,
        timeout: float = CPA_TIMEOUT_SECONDS,
    ) -> tuple[int, dict[str, str], bytearray]:
        if path not in {
            "/",
            "/v1/models",
            "/v0/management/config",
            "/v0/management/plugins/cyber-abuse-guard/status",
            f"/v0/management/usage-queue?count={POLL_COUNT}",
        }:
            raise ProbeError("cpa_path_not_allowlisted")
        address = self.origin.resolve(allow_loopback=self.allow_loopback_for_tests)
        headers = {
            "Accept": "application/json",
            "Connection": "close",
            "Host": self.origin.host_header,
            "User-Agent": "cag-host-keeper/1",
        }
        if management:
            headers["Authorization"] = "Bearer " + self.config.management_key
        connection = http.client.HTTPConnection(
            address,
            self.origin.port,
            timeout=timeout,
        )
        try:
            connection.request("GET", path, headers=headers)
            response = connection.getresponse()
            raw_bytes = response.read(maximum + 1)
            if len(raw_bytes) > maximum:
                raise ProbeError("cpa_response_body_limit")
            result_headers: dict[str, str] = {}
            for key, value in response.getheaders():
                lower = key.lower()
                if lower in result_headers:
                    result_headers[lower] += "," + value
                else:
                    result_headers[lower] = value
            return response.status, result_headers, bytearray(raw_bytes)
        except (OSError, http.client.HTTPException) as exc:
            raise ProbeError("cpa_private_http_failed") from exc
        finally:
            connection.close()

    @staticmethod
    def _wipe(raw: bytearray) -> None:
        for index in range(len(raw)):
            raw[index] = 0

    def _probe_root(self) -> bool:
        raw = bytearray()
        try:
            status, _, raw = self._request(
                "/",
                management=False,
                maximum=MAX_HTTP_BODY,
                timeout=HEALTH_TIMEOUT_SECONDS,
            )
            return status == HTTPStatus.OK
        except ProbeError:
            return False
        finally:
            self._wipe(raw)

    def _probe_models(self) -> bool:
        raw = bytearray()
        try:
            status, _, raw = self._request(
                "/v1/models",
                management=False,
                maximum=MAX_HTTP_BODY,
                timeout=HEALTH_TIMEOUT_SECONDS,
            )
            return status == HTTPStatus.UNAUTHORIZED
        except ProbeError:
            return False
        finally:
            self._wipe(raw)

    def _probe_cag(self) -> bool:
        raw = bytearray()
        value: Any = None
        try:
            status, headers, raw = self._request(
                "/v0/management/plugins/cyber-abuse-guard/status",
                management=True,
                maximum=MAX_HTTP_BODY,
                timeout=HEALTH_TIMEOUT_SECONDS,
            )
            if status != HTTPStatus.OK:
                return False
            try:
                value = strict_json(raw, "CAG status")
            except KeeperError:
                return False
            if type(value) is not dict:
                return False
            audit = value.get("audit")
            raw_capture = value.get("raw_capture")
            version = headers.get("x-cpa-version", "")
            commit = headers.get("x-cpa-commit", "").lower()
            commit_ok = 7 <= len(commit) <= 40 and CPA_COMMIT.startswith(commit)
            audit_counters_ok = all(
                type(audit.get(key)) is int and audit.get(key) == 0
                for key in ("dropped", "failed", "rejected")
            )
            return (
                value.get("id") == "cyber-abuse-guard"
                and value.get("commit") == self.config.expected_cag_commit
                and value.get("dirty") is False
                and value.get("enabled") is True
                and value.get("mode") == self.config.expected_mode
                and value.get("enforcement_ready") is True
                and value.get("operational_ready") is True
                and value.get("audit_degraded") is False
                and value.get("persistence_degraded") is False
                and type(audit) is dict
                and audit.get("healthy") is True
                and audit.get("degraded") is False
                and audit.get("schema_version") == CAG_AUDIT_SCHEMA_VERSION
                and audit.get("persistence_verified") is True
                and audit_counters_ok
                and type(raw_capture) is dict
                and raw_capture.get("enabled") is False
                and version.lstrip("v") == CPA_TAG.lstrip("v")
                and commit_ok
            )
        except ProbeError:
            return False
        finally:
            value = None
            self._wipe(raw)

    def _probe_runtime_config(self) -> bool:
        raw = bytearray()
        value: Any = None
        try:
            status, _, raw = self._request(
                "/v0/management/config",
                management=True,
                maximum=MAX_HTTP_BODY,
                timeout=HEALTH_TIMEOUT_SECONDS,
            )
            if status != HTTPStatus.OK:
                return False
            try:
                value = strict_json(raw, "CPA runtime config")
            except KeeperError:
                return False
            if type(value) is not dict:
                return False
            providers = value.get("openai-compatibility")
            if (
                value.get("commercial-mode") is not True
                or value.get("request-log") is not False
                or value.get("logging-to-file") is not False
                or value.get("usage-statistics-enabled") is not True
                or value.get("proxy-url") not in (None, "")
                or type(providers) is not list
                or len(providers) != 1
                or type(providers[0]) is not dict
            ):
                return False
            provider = providers[0]
            if (
                provider.get("name") != "current-cpa-counted-mock"
                or provider.get("base-url") != "http://mock:18080/v1"
                or provider.get("proxy-url") not in (None, "")
            ):
                return False
            models = provider.get("models")
            if (
                type(models) is not list
                or models
                != [
                    {
                        "alias": self.config.expected_model,
                        "name": self.config.expected_model,
                    }
                ]
            ):
                return False
            entries = provider.get("api-key-entries")
            if type(entries) is not list or len(entries) != 1 or type(entries[0]) is not dict:
                return False
            if entries[0].get("proxy-url") not in (None, ""):
                return False
            for key in (
                "claude-api-key",
                "codex-api-key",
                "gemini-api-key",
                "interactions-api-key",
                "vertex-api-key",
                "xai-api-key",
            ):
                if value.get(key) not in (None, []):
                    return False
            return True
        except ProbeError:
            return False
        finally:
            if type(value) is dict:
                value.clear()
            value = None
            self._wipe(raw)

    def health_checks(self) -> dict[str, bool]:
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            root = executor.submit(self._probe_root)
            models = executor.submit(self._probe_models)
            cag = executor.submit(self._probe_cag)
            runtime_config = executor.submit(self._probe_runtime_config)
            return {
                "cpa_root": root.result(),
                "cpa_unauthorized_models": models.result(),
                # Preserve the fixed public health shape: CAG readiness is only
                # true when the same CPA also retains its closed Mock-only
                # configuration and no proxy/real-provider keys.
                "cag_status": cag.result() and runtime_config.result(),
            }

    def pop_usage_event_keys(self, event_hmac_key: bytes) -> list[bytes]:
        raw = bytearray()
        payload: Any = None
        try:
            status, _, raw = self._request(
                f"/v0/management/usage-queue?count={POLL_COUNT}",
                management=True,
                maximum=MAX_USAGE_RESPONSE,
            )
            if status != HTTPStatus.OK:
                raise ProbeError("usage_queue_http_status")
            try:
                payload = strict_json(raw, "CPA usage queue")
            except KeeperError as exc:
                raise UsageRecordError("usage_queue_invalid_json") from exc
            if type(payload) is not list or len(payload) > MAX_USAGE_BATCH:
                raise UsageRecordError("usage_queue_batch_contract")
            event_keys: list[bytes] = []
            for index, record in enumerate(payload):
                try:
                    request_id = validate_usage_record(record, self.config, index)
                except UsageRecordError:
                    raise
                except KeeperError as exc:
                    raise UsageRecordError("usage_record_schema") from exc
                request_id_bytes = bytearray(request_id.encode("utf-8"))
                event_message = bytearray(
                    b"cag-host-keeper-usage-request-id-v1\x00"
                )
                event_message.extend(request_id_bytes)
                try:
                    event_keys.append(
                        hmac.new(
                            event_hmac_key,
                            event_message,
                            hashlib.sha256,
                        ).digest()
                    )
                finally:
                    for byte_index in range(len(request_id_bytes)):
                        request_id_bytes[byte_index] = 0
                    for byte_index in range(len(event_message)):
                        event_message[byte_index] = 0
                    request_id = ""
                    # Drop the parsed API key, source, headers, and all other
                    # usage fields immediately after deriving the irreversible
                    # identity.  Only the digest leaves this loop.
                    record.clear()
            # KeeperDatabase owns duplicate detection so an in-batch replay and
            # a cross-poll replay take the same atomic fail-closed path and the
            # same persistent duplicate/error counters.
            return event_keys
        finally:
            payload = None
            self._wipe(raw)


def _validate_token_object(value: Any) -> None:
    tokens = exact_object(
        value,
        {
            "cache_creation_tokens",
            "cache_read_tokens",
            "cache_read_tokens_present",
            "cached_tokens",
            "input_tokens",
            "output_tokens",
            "reasoning_tokens",
            "total_tokens",
        },
        "usage.tokens",
    )
    for key in tokens:
        if key == "cache_read_tokens_present":
            if exact_bool(tokens[key], f"usage.tokens.{key}") is not True:
                raise UsageRecordError("usage token presence flag is false")
        else:
            exact_int(tokens[key], f"usage.tokens.{key}")
    expected_input, expected_output, expected_total = EXPECTED_TOKEN_TOTALS
    if (
        tokens["input_tokens"] != expected_input
        or tokens["output_tokens"] != expected_output
        or tokens["total_tokens"] != expected_total
        or tokens["reasoning_tokens"] != 0
        or tokens["cached_tokens"] != 0
        or tokens["cache_read_tokens"] != 0
        or tokens["cache_creation_tokens"] != 0
    ):
        raise UsageRecordError("usage tokens are not the counted-Mock response")


def _validate_token_breakdown(value: Any) -> None:
    breakdown = exact_object(
        value,
        {
            "input",
            "output",
            "quality",
            "schema_version",
            "total_tokens",
            "unclassified_tokens",
        },
        "usage.token_breakdown",
    )
    input_tokens = exact_object(
        breakdown["input"],
        {"cache_read_tokens", "cache_write_tokens", "total_tokens", "uncached_tokens"},
        "usage.token_breakdown.input",
    )
    output_tokens = exact_object(
        breakdown["output"],
        {"non_reasoning_tokens", "reasoning_tokens", "total_tokens"},
        "usage.token_breakdown.output",
    )
    for key, value_item in input_tokens.items():
        exact_int(value_item, f"usage.token_breakdown.input.{key}")
    for key, value_item in output_tokens.items():
        exact_int(value_item, f"usage.token_breakdown.output.{key}")
    expected_input, expected_output, expected_total = EXPECTED_TOKEN_TOTALS
    expected = {
        "schema_version": 2,
        "quality": "complete",
        "total_tokens": expected_total,
        "unclassified_tokens": 0,
        "input": {
            "total_tokens": expected_input,
            "uncached_tokens": expected_input,
            "cache_read_tokens": 0,
            "cache_write_tokens": 0,
        },
        "output": {
            "total_tokens": expected_output,
            "non_reasoning_tokens": expected_output,
            "reasoning_tokens": 0,
        },
    }
    if breakdown != expected:
        raise UsageRecordError("usage token breakdown is not the counted-Mock response")


def _validate_response_headers(value: Any) -> None:
    if type(value) is not dict or len(value) > 32:
        raise UsageRecordError("usage response_headers is not bounded")
    sensitive = {"authorization", "cookie", "proxy-authorization", "set-cookie"}
    total = 0
    for key, items in value.items():
        name = bounded_string(key, "usage.response_headers key", 128)
        if name.lower() in sensitive or type(items) is not list or len(items) > 16:
            raise UsageRecordError("usage response_headers contains forbidden metadata")
        for item in items:
            total += len(optional_string(item, "usage.response_headers value", 1024).encode("utf-8"))
    if total > 8192:
        raise UsageRecordError("usage response_headers exceeds the bounded contract")


def validate_usage_record(value: Any, config: KeeperConfig, ordinal: int) -> str:
    label = f"usage[{ordinal}]"
    record = exact_object(
        value,
        {
            "accounting_version",
            "alias",
            "api_key",
            "auth_index",
            "auth_type",
            "client_ip",
            "endpoint",
            "executor_type",
            "fail",
            "failed",
            "generate",
            "latency_ms",
            "model",
            "provider",
            "reasoning_effort",
            "request_id",
            "service_tier",
            "source",
            "timestamp",
            "token_breakdown",
            "tokens",
            "ttft_ms",
            "user_agent",
            "x_forwarded_for",
        },
        label,
        optional={
            "access_token_sha256",
            "response_headers",
            "response_service_tier",
        },
    )
    exact_int(record["accounting_version"], f"{label}.accounting_version", 2, 2)
    if bounded_string(record["provider"], f"{label}.provider", 256) != config.expected_provider:
        raise UsageRecordError("usage provider escaped counted-Mock")
    if bounded_string(record["executor_type"], f"{label}.executor_type", 256) != config.expected_executor:
        raise UsageRecordError("usage executor escaped counted-Mock")
    if bounded_string(record["model"], f"{label}.model", 256) != config.expected_model:
        raise UsageRecordError("usage model escaped counted-Mock")
    if bounded_string(record["alias"], f"{label}.alias", 256) != config.expected_model:
        raise UsageRecordError("usage alias escaped counted-Mock")
    if bounded_string(record["endpoint"], f"{label}.endpoint", 128) not in EXPECTED_ENDPOINTS:
        raise UsageRecordError("usage endpoint escaped allowed non-stream routes")
    if bounded_string(record["auth_type"], f"{label}.auth_type", 64) != "apikey":
        raise UsageRecordError("usage auth_type is not the isolated API-key fixture")
    if exact_bool(record["failed"], f"{label}.failed") is not False:
        raise UsageRecordError("failed usage cannot prove an allowed request")
    if exact_bool(record["generate"], f"{label}.generate") is not True:
        raise UsageRecordError("non-generation usage cannot prove an allowed request")
    fail_value = exact_object(record["fail"], {"body", "status_code"}, f"{label}.fail")
    if exact_int(fail_value["status_code"], f"{label}.fail.status_code") != 200:
        raise UsageRecordError("usage fail status is not successful")
    if optional_string(fail_value["body"], f"{label}.fail.body", 1) != "":
        raise UsageRecordError("usage success unexpectedly retained a failure body")
    exact_int(record["latency_ms"], f"{label}.latency_ms")
    exact_int(record["ttft_ms"], f"{label}.ttft_ms")
    strict_timestamp(record["timestamp"], f"{label}.timestamp")
    request_id = bounded_string(record["request_id"], f"{label}.request_id", 256)
    if SAFE_NAME.fullmatch(request_id) is None:
        raise UsageRecordError("usage request_id is not a safe bounded identity")
    for key, maximum in (
        ("api_key", MAX_SECRET_BYTES),
        ("auth_index", 256),
        ("client_ip", 256),
        ("reasoning_effort", 64),
        ("service_tier", 64),
        ("source", 1024),
        ("user_agent", 1024),
        ("x_forwarded_for", 1024),
    ):
        optional_string(record[key], f"{label}.{key}", maximum)
    if "access_token_sha256" in record:
        optional_string(record["access_token_sha256"], f"{label}.access_token_sha256", 128)
    if "response_service_tier" in record:
        optional_string(record["response_service_tier"], f"{label}.response_service_tier", 64)
    if "response_headers" in record:
        _validate_response_headers(record["response_headers"])
    _validate_token_object(record["tokens"])
    _validate_token_breakdown(record["token_breakdown"])
    return request_id


class KeeperDatabase:
    """SQLite-backed monotonic counter with deletion and rollback guards."""

    def __init__(self, path: Path, run_id: str) -> None:
        self.path = path
        self.run_id = run_id
        self._lock = threading.RLock()
        self._prepare_path()
        self._initialize()

    def _prepare_path(self) -> None:
        if not self.path.is_absolute():
            raise ConfigurationError("Keeper database path must be absolute")
        try:
            parent = self.path.parent.resolve(strict=True)
            info = parent.stat()
        except OSError as exc:
            raise ConfigurationError("Keeper database parent is unavailable") from exc
        if not stat.S_ISDIR(info.st_mode):
            raise ConfigurationError("Keeper database parent is not a directory")
        if self.path.parent != parent:
            raise ConfigurationError("Keeper database parent resolution drifted")
        if os.name == "posix" and (
            info.st_uid != os.getuid()
            or info.st_gid != os.getgid()
            or stat.S_IMODE(info.st_mode) & 0o077
        ):
            raise ConfigurationError(
                "Keeper database parent must be process-owned and private"
            )
        if self.path.exists():
            self._verify_file()

    def _verify_file(self) -> None:
        try:
            info = self.path.lstat()
        except OSError as exc:
            raise DatabaseInvariantError("Keeper database file is unavailable") from exc
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_size > MAX_DATABASE_BYTES
            or (
                os.name == "posix"
                and (
                    info.st_uid != os.getuid()
                    or info.st_gid != os.getgid()
                    or stat.S_IMODE(info.st_mode) & 0o077
                )
            )
        ):
            raise DatabaseInvariantError("Keeper database file identity is invalid")

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            str(self.path),
            timeout=2.0,
            isolation_level=None,
        )
        connection.execute("PRAGMA busy_timeout = 2000")
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA trusted_schema = OFF")
        connection.execute("PRAGMA synchronous = FULL")
        connection.execute("PRAGMA secure_delete = ON")
        return connection

    def _initialize(self) -> None:
        with self._lock:
            connection = self._connect()
            try:
                journal = connection.execute("PRAGMA journal_mode = WAL").fetchone()
                if journal is None or str(journal[0]).lower() != "wal":
                    raise DatabaseInvariantError("Keeper SQLite WAL mode is unavailable")
                connection.execute("PRAGMA synchronous = FULL")
                connection.execute("PRAGMA secure_delete = ON")
                connection.execute("PRAGMA wal_autocheckpoint = 64")
                connection.executescript(
                    """
                    BEGIN IMMEDIATE;
                    CREATE TABLE IF NOT EXISTS keeper_state (
                        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                        schema_version INTEGER NOT NULL CHECK (schema_version = 1),
                        run_id TEXT NOT NULL,
                        usage_records INTEGER NOT NULL CHECK (usage_records BETWEEN 0 AND 100000),
                        last_sequence INTEGER NOT NULL CHECK (last_sequence BETWEEN 0 AND 100000),
                        poll_cycles INTEGER NOT NULL CHECK (poll_cycles >= 0),
                        poll_errors INTEGER NOT NULL CHECK (poll_errors >= 0),
                        invalid_records INTEGER NOT NULL CHECK (invalid_records >= 0),
                        duplicate_records INTEGER NOT NULL CHECK (duplicate_records >= 0)
                    );
                    CREATE TABLE IF NOT EXISTS observed_events (
                        event_key BLOB PRIMARY KEY CHECK (length(event_key) = 32),
                        sequence INTEGER NOT NULL UNIQUE CHECK (sequence BETWEEN 1 AND 100000)
                    );
                    CREATE TABLE IF NOT EXISTS health_probe (
                        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                        nonce INTEGER NOT NULL CHECK (nonce >= 0)
                    );
                    CREATE TRIGGER IF NOT EXISTS keeper_state_no_delete
                    BEFORE DELETE ON keeper_state
                    BEGIN
                        SELECT RAISE(ABORT, 'keeper state deletion forbidden');
                    END;
                    CREATE TRIGGER IF NOT EXISTS keeper_state_no_rollback
                    BEFORE UPDATE ON keeper_state
                    WHEN NEW.usage_records < OLD.usage_records
                      OR NEW.last_sequence < OLD.last_sequence
                      OR NEW.poll_cycles < OLD.poll_cycles
                      OR NEW.poll_errors < OLD.poll_errors
                      OR NEW.invalid_records < OLD.invalid_records
                      OR NEW.duplicate_records < OLD.duplicate_records
                    BEGIN
                        SELECT RAISE(ABORT, 'keeper counter rollback forbidden');
                    END;
                    CREATE TRIGGER IF NOT EXISTS observed_events_no_delete
                    BEFORE DELETE ON observed_events
                    BEGIN
                        SELECT RAISE(ABORT, 'keeper event deletion forbidden');
                    END;
                    CREATE TRIGGER IF NOT EXISTS observed_events_no_update
                    BEFORE UPDATE ON observed_events
                    BEGIN
                        SELECT RAISE(ABORT, 'keeper event mutation forbidden');
                    END;
                    """
                )
                row = connection.execute(
                    "SELECT run_id FROM keeper_state WHERE singleton = 1"
                ).fetchone()
                if row is None:
                    connection.execute(
                        """
                        INSERT INTO keeper_state (
                            singleton, schema_version, run_id, usage_records,
                            last_sequence, poll_cycles, poll_errors,
                            invalid_records, duplicate_records
                        ) VALUES (1, ?, ?, 0, 0, 0, 0, 0, 0)
                        """,
                        (DATABASE_SCHEMA_VERSION, self.run_id),
                    )
                elif row != (self.run_id,):
                    raise DatabaseInvariantError("Keeper database run identity drifted")
                connection.execute(
                    "INSERT OR IGNORE INTO health_probe (singleton, nonce) VALUES (1, 0)"
                )
                connection.execute(f"PRAGMA user_version = {DATABASE_SCHEMA_VERSION}")
                connection.commit()
                os.chmod(self.path, 0o600)
                self._verify_schema(connection)
                self._snapshot_locked(connection)
            except Exception:
                if connection.in_transaction:
                    connection.rollback()
                raise
            finally:
                connection.close()
            self._verify_file()

    @staticmethod
    def _verify_schema(connection: sqlite3.Connection) -> None:
        pragmas = {
            "foreign_keys": 1,
            "journal_mode": "wal",
            "secure_delete": 1,
            "synchronous": 2,
            "trusted_schema": 0,
            "user_version": DATABASE_SCHEMA_VERSION,
        }
        for name, expected in pragmas.items():
            row = connection.execute(f"PRAGMA {name}").fetchone()
            if row is None or len(row) != 1 or row[0] != expected:
                raise DatabaseInvariantError(
                    f"Keeper database PRAGMA {name} drifted"
                )
        objects = connection.execute(
            """
            SELECT type, name FROM sqlite_master
            WHERE name NOT LIKE 'sqlite_%'
            ORDER BY type, name
            """
        ).fetchall()
        expected = sorted(
            [
                ("table", "health_probe"),
                ("table", "keeper_state"),
                ("table", "observed_events"),
                ("trigger", "keeper_state_no_delete"),
                ("trigger", "keeper_state_no_rollback"),
                ("trigger", "observed_events_no_delete"),
                ("trigger", "observed_events_no_update"),
            ]
        )
        if objects != expected:
            raise DatabaseInvariantError("Keeper database object set drifted")
        expected_columns = {
            "keeper_state": (
                "singleton",
                "schema_version",
                "run_id",
                "usage_records",
                "last_sequence",
                "poll_cycles",
                "poll_errors",
                "invalid_records",
                "duplicate_records",
            ),
            "observed_events": ("event_key", "sequence"),
            "health_probe": ("singleton", "nonce"),
        }
        for table, columns in expected_columns.items():
            observed = tuple(
                row[1] for row in connection.execute(f"PRAGMA table_info({table})")
            )
            if observed != columns:
                raise DatabaseInvariantError(f"Keeper database {table} columns drifted")
        required_sql_fragments = {
            "keeper_state": (
                "check (singleton = 1)",
                "schema_version integer not null check (schema_version = 1)",
                "usage_records integer not null check (usage_records between 0 and 100000)",
                "last_sequence integer not null check (last_sequence between 0 and 100000)",
                "poll_cycles integer not null check (poll_cycles >= 0)",
                "poll_errors integer not null check (poll_errors >= 0)",
                "invalid_records integer not null check (invalid_records >= 0)",
                "duplicate_records integer not null check (duplicate_records >= 0)",
            ),
            "observed_events": (
                "event_key blob primary key check (length(event_key) = 32)",
                "sequence integer not null unique check (sequence between 1 and 100000)",
            ),
            "health_probe": (
                "check (singleton = 1)",
                "nonce integer not null check (nonce >= 0)",
            ),
            "keeper_state_no_delete": (
                "before delete on keeper_state",
                "raise(abort, 'keeper state deletion forbidden')",
            ),
            "keeper_state_no_rollback": (
                "before update on keeper_state",
                "new.usage_records < old.usage_records",
                "new.last_sequence < old.last_sequence",
                "new.poll_cycles < old.poll_cycles",
                "new.poll_errors < old.poll_errors",
                "new.invalid_records < old.invalid_records",
                "new.duplicate_records < old.duplicate_records",
                "raise(abort, 'keeper counter rollback forbidden')",
            ),
            "observed_events_no_delete": (
                "before delete on observed_events",
                "raise(abort, 'keeper event deletion forbidden')",
            ),
            "observed_events_no_update": (
                "before update on observed_events",
                "raise(abort, 'keeper event mutation forbidden')",
            ),
        }
        rows = connection.execute(
            """
            SELECT name, sql FROM sqlite_master
            WHERE name NOT LIKE 'sqlite_%'
            """
        ).fetchall()
        sql_by_name = {
            name: " ".join(str(sql).lower().split())
            for name, sql in rows
            if sql is not None
        }
        if set(sql_by_name) != set(required_sql_fragments):
            raise DatabaseInvariantError("Keeper database schema SQL set drifted")
        for name, fragments in required_sql_fragments.items():
            observed_sql = sql_by_name[name]
            if any(fragment not in observed_sql for fragment in fragments):
                raise DatabaseInvariantError(
                    f"Keeper database schema SQL drifted for {name}"
                )

    def _snapshot_locked(self, connection: sqlite3.Connection) -> dict[str, Any]:
        row = connection.execute(
            """
            SELECT schema_version, run_id, usage_records, last_sequence,
                   poll_cycles, poll_errors, invalid_records, duplicate_records
            FROM keeper_state WHERE singleton = 1
            """
        ).fetchone()
        if row is None or len(row) != 8:
            raise DatabaseInvariantError("Keeper state row is missing")
        (
            schema_version,
            run_id,
            usage_records,
            last_sequence,
            poll_cycles,
            poll_errors,
            invalid_records,
            duplicate_records,
        ) = row
        for value, label in (
            (usage_records, "usage_records"),
            (last_sequence, "last_sequence"),
            (poll_cycles, "poll_cycles"),
            (poll_errors, "poll_errors"),
            (invalid_records, "invalid_records"),
            (duplicate_records, "duplicate_records"),
        ):
            exact_int(value, f"database.{label}")
        if schema_version != DATABASE_SCHEMA_VERSION or run_id != self.run_id:
            raise DatabaseInvariantError("Keeper database identity drifted")
        event_row = connection.execute(
            "SELECT COUNT(*), COALESCE(MIN(sequence), 0), COALESCE(MAX(sequence), 0) "
            "FROM observed_events"
        ).fetchone()
        if event_row is None:
            raise DatabaseInvariantError("Keeper event state is unavailable")
        event_count, minimum_sequence, maximum_sequence = event_row
        if (
            usage_records != event_count
            or last_sequence != usage_records
            or (usage_records == 0 and (minimum_sequence != 0 or maximum_sequence != 0))
            or (usage_records > 0 and (minimum_sequence != 1 or maximum_sequence != usage_records))
        ):
            raise DatabaseInvariantError("Keeper usage sequence is inconsistent")
        return {
            "schema": CONTRACT,
            "run_id": run_id,
            "usage_records": usage_records,
            "last_sequence": last_sequence,
            "poll_cycles": poll_cycles,
            "poll_errors": poll_errors,
            "invalid_records": invalid_records,
            "duplicate_records": duplicate_records,
            "observation_source": OBSERVATION_SOURCE,
            "request_body_retention": False,
            "usage_payload_retention": False,
        }

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            self._verify_file()
            connection = self._connect()
            try:
                self._verify_schema(connection)
                return self._snapshot_locked(connection)
            finally:
                connection.close()

    def record_poll(self, event_keys: Sequence[bytes]) -> dict[str, Any]:
        if len(event_keys) > MAX_USAGE_BATCH or any(
            type(key) is not bytes or len(key) != 32 for key in event_keys
        ):
            raise DatabaseInvariantError("Keeper event key batch is invalid")
        if len(set(event_keys)) != len(event_keys):
            self.mark_poll_failure(invalid=True, duplicate=True)
            raise DuplicateObservation("duplicate event identity in one poll")
        with self._lock:
            self._verify_file()
            connection = self._connect()
            try:
                connection.execute("BEGIN IMMEDIATE")
                self._verify_schema(connection)
                current = self._snapshot_locked(connection)
                new_total = current["usage_records"] + len(event_keys)
                if new_total > MAX_USAGE_RECORDS:
                    raise DatabaseInvariantError("Keeper usage observation limit exceeded")
                for offset, event_key in enumerate(event_keys, start=1):
                    try:
                        connection.execute(
                            "INSERT INTO observed_events (event_key, sequence) VALUES (?, ?)",
                            (event_key, current["last_sequence"] + offset),
                        )
                    except sqlite3.IntegrityError as exc:
                        raise DuplicateObservation("duplicate persistent usage observation") from exc
                connection.execute(
                    """
                    UPDATE keeper_state
                    SET usage_records = ?, last_sequence = ?, poll_cycles = poll_cycles + 1
                    WHERE singleton = 1
                    """,
                    (new_total, new_total),
                )
                result = self._snapshot_locked(connection)
                connection.commit()
                return result
            except DuplicateObservation:
                if connection.in_transaction:
                    connection.rollback()
                connection.close()
                self.mark_poll_failure(invalid=True, duplicate=True)
                raise
            except Exception:
                if connection.in_transaction:
                    connection.rollback()
                raise
            finally:
                try:
                    connection.close()
                except sqlite3.Error:
                    pass

    def mark_poll_failure(self, *, invalid: bool, duplicate: bool = False) -> None:
        with self._lock:
            self._verify_file()
            connection = self._connect()
            try:
                connection.execute("BEGIN IMMEDIATE")
                self._verify_schema(connection)
                self._snapshot_locked(connection)
                connection.execute(
                    """
                    UPDATE keeper_state
                    SET poll_errors = poll_errors + 1,
                        invalid_records = invalid_records + ?,
                        duplicate_records = duplicate_records + ?
                    WHERE singleton = 1
                    """,
                    (1 if invalid else 0, 1 if duplicate else 0),
                )
                connection.commit()
            except Exception:
                if connection.in_transaction:
                    connection.rollback()
                raise
            finally:
                connection.close()

    def confirm_fresh(self, run_id: str, expected_usage_records: int) -> dict[str, Any]:
        if run_id != self.run_id or expected_usage_records != 0:
            raise RollbackForbidden("Keeper fresh-state confirmation identity drifted")
        state = self.snapshot()
        if (
            state["usage_records"] != 0
            or state["last_sequence"] != 0
            or state["poll_cycles"] < 1
            or state["poll_errors"] != 0
            or state["invalid_records"] != 0
            or state["duplicate_records"] != 0
        ):
            raise RollbackForbidden("Keeper usage rollback is forbidden")
        return {
            "schema": CONTRACT,
            "run_id": self.run_id,
            "state": "fresh",
            "usage_records": 0,
        }

    def health_snapshot(self) -> tuple[dict[str, Any], str, bool]:
        with self._lock:
            self._verify_file()
            connection = self._connect()
            try:
                self._verify_schema(connection)
                rows = connection.execute("PRAGMA quick_check").fetchall()
                quick_check = "ok" if rows == [("ok",)] else "failed"
                if quick_check != "ok":
                    raise DatabaseInvariantError("Keeper SQLite quick_check failed")
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(
                    "UPDATE health_probe SET nonce = nonce + 1 WHERE singleton = 1"
                )
                state = self._snapshot_locked(connection)
                connection.commit()
                return state, quick_check, True
            except Exception:
                if connection.in_transaction:
                    connection.rollback()
                raise
            finally:
                connection.close()

    def checkpoint(self) -> None:
        with self._lock:
            self._verify_file()
            connection = self._connect()
            try:
                self._verify_schema(connection)
                row = connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
                if row is None or len(row) != 3 or row[0] != 0:
                    raise DatabaseInvariantError("Keeper SQLite checkpoint failed")
            finally:
                connection.close()


class KeeperRuntime:
    """Owns the CPA poller and presents fail-closed health/stats projections."""

    def __init__(
        self,
        config: KeeperConfig,
        database: KeeperDatabase,
        client: Any,
        *,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self.config = config
        self.database = database
        self.client = client
        self.monotonic = monotonic
        self._event_hmac_key = hashlib.sha256(
            b"cag-host-keeper-event-hmac-v1\x00" + config.control_token.encode("utf-8")
        ).digest()
        self._stop = threading.Event()
        self._poll_lock = threading.Lock()
        self._state_lock = threading.RLock()
        self._thread: threading.Thread | None = None
        self._fatal = False
        self._last_success = 0.0
        self._last_usage_records = 0

    def start(self) -> None:
        with self._state_lock:
            if self._thread is not None:
                raise KeeperError("Keeper poller already started")
            self._thread = threading.Thread(
                target=self._poll_loop,
                name="cag-host-keeper-poller",
                daemon=True,
            )
            self._thread.start()

    def _set_fatal(self, *, invalid: bool, duplicate: bool = False) -> None:
        with self._state_lock:
            self._fatal = True
        try:
            self.database.mark_poll_failure(invalid=invalid, duplicate=duplicate)
        except Exception:
            pass

    def poll_once(self) -> bool:
        with self._poll_lock:
            with self._state_lock:
                if self._fatal:
                    return False
            try:
                event_keys = self.client.pop_usage_event_keys(self._event_hmac_key)
                state = self.database.record_poll(event_keys)
            except DuplicateObservation:
                with self._state_lock:
                    self._fatal = True
                return False
            except UsageRecordError:
                self._set_fatal(invalid=True)
                return False
            except (ProbeError, DatabaseInvariantError, sqlite3.Error):
                self._set_fatal(invalid=False)
                return False
            with self._state_lock:
                self._last_success = self.monotonic()
                self._last_usage_records = state["usage_records"]
            return True

    def _poll_loop(self) -> None:
        try:
            while not self._stop.is_set():
                if not self.poll_once():
                    return
                self._stop.wait(self.config.poll_interval)
        except Exception:
            # threading.excepthook normally prints a traceback.  Suppress it so
            # an unexpected parser/runtime fault cannot write any transient
            # usage or credential object to container logs; health still fails.
            self._set_fatal(invalid=False)

    def stop(self) -> None:
        self._stop.set()
        thread = self._thread
        if thread is not None:
            thread.join(timeout=max(2.0, self.config.poll_interval * 4))
            if thread.is_alive():
                raise KeeperError("Keeper poller did not stop")
        self.database.checkpoint()

    def stats(self) -> dict[str, Any]:
        state = self.database.snapshot()
        with self._state_lock:
            self._last_usage_records = state["usage_records"]
        return state

    def confirm_fresh(self, value: Any) -> dict[str, Any]:
        payload = exact_object(
            value,
            {"expected_usage_records", "run_id", "schema"},
            "reset request",
        )
        if payload["schema"] != CONTRACT:
            raise RollbackForbidden("Keeper reset schema drifted")
        expected = exact_int(
            payload["expected_usage_records"],
            "reset request.expected_usage_records",
        )
        run_id = bounded_string(payload["run_id"], "reset request.run_id", 63)
        with self._poll_lock:
            return self.database.confirm_fresh(run_id, expected)

    def health(self) -> tuple[int, dict[str, Any]]:
        try:
            cpa_checks = self.client.health_checks()
        except Exception:
            cpa_checks = {
                "cag_status": False,
                "cpa_root": False,
                "cpa_unauthorized_models": False,
            }
        sqlite_quick_check = "failed"
        sqlite_writable = False
        usage_records: int
        with self._state_lock:
            usage_records = self._last_usage_records
            fatal = self._fatal
            last_success = self._last_success
        poll_errors = 1
        invalid_records = 1
        duplicate_records = 1
        try:
            state, sqlite_quick_check, sqlite_writable = self.database.health_snapshot()
            usage_records = state["usage_records"]
            poll_errors = state["poll_errors"]
            invalid_records = state["invalid_records"]
            duplicate_records = state["duplicate_records"]
            with self._state_lock:
                self._last_usage_records = usage_records
        except Exception:
            pass
        maximum_age = max(1.0, self.config.poll_interval * 10)
        thread = self._thread
        thread_alive = thread is not None and thread.is_alive()
        poller = (
            not fatal
            and thread_alive
            and last_success > 0
            and self.monotonic() - last_success <= maximum_age
            and poll_errors == 0
            and invalid_records == 0
            and duplicate_records == 0
        )
        checks: dict[str, Any] = {
            "cag_status": cpa_checks.get("cag_status") is True,
            "cpa_root": cpa_checks.get("cpa_root") is True,
            "cpa_unauthorized_models": cpa_checks.get("cpa_unauthorized_models") is True,
            "poller": poller,
            "sqlite_quick_check": sqlite_quick_check,
            "sqlite_writable": sqlite_writable,
            "usage_records": usage_records,
        }
        healthy = (
            checks["cag_status"] is True
            and checks["cpa_root"] is True
            and checks["cpa_unauthorized_models"] is True
            and checks["poller"] is True
            and checks["sqlite_quick_check"] == "ok"
            and checks["sqlite_writable"] is True
        )
        payload = {
            "schema": CONTRACT,
            "state": "healthy" if healthy else "unhealthy",
            "checks": checks,
        }
        return (HTTPStatus.OK if healthy else HTTPStatus.SERVICE_UNAVAILABLE), payload


class KeeperHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    block_on_close = True

    def __init__(
        self,
        address: tuple[str, int],
        runtime: KeeperRuntime,
        control_token: str,
    ) -> None:
        super().__init__(address, KeeperHandler)
        self.runtime = runtime
        self.control_token = control_token

    def handle_error(self, request: Any, client_address: Any) -> None:
        del request, client_address
        # Never log a request, header, body, exception, or credential.


class KeeperHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "cag-host-keeper/1"
    sys_version = ""
    timeout = 5.0

    @property
    def keeper_server(self) -> KeeperHTTPServer:
        return self.server  # type: ignore[return-value]

    def log_message(self, format: str, *args: Any) -> None:
        del format, args

    def _send(self, status: int, value: Any) -> None:
        raw = compact_json(value)
        self.send_response(status)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Connection", "close")
        self.end_headers()
        try:
            self.wfile.write(raw)
            self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass
        self.close_connection = True

    def _route(self) -> str | None:
        parsed = urlsplit(self.path)
        if parsed.scheme or parsed.netloc or parsed.query or parsed.fragment:
            self._send(HTTPStatus.BAD_REQUEST, {"schema": CONTRACT, "error": "invalid_target"})
            return None
        return parsed.path

    def _no_body(self) -> bool:
        if self.headers.get("Transfer-Encoding") is not None:
            return False
        lengths = self.headers.get_all("Content-Length", failobj=[])
        return len(lengths) == 0 or lengths == ["0"]

    def _authorized(self) -> bool:
        values = self.headers.get_all("Authorization", failobj=[])
        if len(values) != 1:
            return False
        expected = "Bearer " + self.keeper_server.control_token
        return hmac.compare_digest(values[0].encode("utf-8"), expected.encode("utf-8"))

    def _require_control(self) -> bool:
        if self._authorized():
            return True
        self._send(HTTPStatus.UNAUTHORIZED, {"schema": CONTRACT, "error": "unauthorized"})
        return False

    def _read_control_json(self) -> Any | None:
        if self.headers.get("Transfer-Encoding") is not None:
            self._send(HTTPStatus.BAD_REQUEST, {"schema": CONTRACT, "error": "invalid_framing"})
            return None
        content_types = self.headers.get_all("Content-Type", failobj=[])
        lengths = self.headers.get_all("Content-Length", failobj=[])
        if (
            len(content_types) != 1
            or content_types[0].split(";", 1)[0].strip().lower() != "application/json"
            or len(lengths) != 1
        ):
            self._send(HTTPStatus.BAD_REQUEST, {"schema": CONTRACT, "error": "invalid_framing"})
            return None
        try:
            length = int(lengths[0])
        except ValueError:
            length = -1
        if not 1 <= length <= MAX_CONTROL_BODY:
            self._send(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"schema": CONTRACT, "error": "body_limit"})
            return None
        raw = bytearray(self.rfile.read(length))
        try:
            if len(raw) != length:
                self._send(HTTPStatus.BAD_REQUEST, {"schema": CONTRACT, "error": "short_body"})
                return None
            try:
                return strict_json(raw, "control request")
            except KeeperError:
                self._send(HTTPStatus.BAD_REQUEST, {"schema": CONTRACT, "error": "invalid_json"})
                return None
        finally:
            for index in range(len(raw)):
                raw[index] = 0

    def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
        route = self._route()
        if route is None:
            return
        if not self._no_body():
            self._send(HTTPStatus.BAD_REQUEST, {"schema": CONTRACT, "error": "body_forbidden"})
            return
        if route == "/keeper/healthz":
            status, value = self.keeper_server.runtime.health()
            self._send(status, value)
            return
        if route == "/keeper/stats":
            if not self._require_control():
                return
            try:
                value = self.keeper_server.runtime.stats()
            except (KeeperError, sqlite3.Error, OSError):
                self._send(HTTPStatus.SERVICE_UNAVAILABLE, {"schema": CONTRACT, "error": "unavailable"})
                return
            self._send(HTTPStatus.OK, value)
            return
        self._send(HTTPStatus.NOT_FOUND, {"schema": CONTRACT, "error": "not_found"})

    def do_POST(self) -> None:  # noqa: N802 - stdlib handler API
        route = self._route()
        if route is None:
            return
        if route != "/keeper/reset":
            self._send(HTTPStatus.NOT_FOUND, {"schema": CONTRACT, "error": "not_found"})
            return
        if not self._require_control():
            return
        value = self._read_control_json()
        if value is None:
            return
        try:
            result = self.keeper_server.runtime.confirm_fresh(value)
        except RollbackForbidden:
            self._send(HTTPStatus.CONFLICT, {"schema": CONTRACT, "error": "rollback_forbidden"})
            return
        except KeeperError:
            self._send(HTTPStatus.BAD_REQUEST, {"schema": CONTRACT, "error": "invalid_schema"})
            return
        self._send(HTTPStatus.OK, result)

    def _method_not_allowed(self) -> None:
        self._send(HTTPStatus.METHOD_NOT_ALLOWED, {"schema": CONTRACT, "error": "method_not_allowed"})

    do_DELETE = _method_not_allowed  # type: ignore[assignment]
    do_HEAD = _method_not_allowed  # type: ignore[assignment]
    do_OPTIONS = _method_not_allowed  # type: ignore[assignment]
    do_PATCH = _method_not_allowed  # type: ignore[assignment]
    do_PUT = _method_not_allowed  # type: ignore[assignment]
    do_TRACE = _method_not_allowed  # type: ignore[assignment]


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--database", type=Path, default=Path(DEFAULT_DATABASE))
    args = parser.parse_args(argv)
    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")
    try:
        address = ipaddress.ip_address(args.host)
    except ValueError:
        parser.error("--host must be an IPv4 literal")
    if not isinstance(address, ipaddress.IPv4Address):
        parser.error("--host must be an IPv4 literal")
    return args


def main(argv: Sequence[str] | None = None) -> int:
    os.umask(0o077)
    args = parse_args(argv)
    config = KeeperConfig.from_environment(args.database)
    database = KeeperDatabase(config.database_path, config.run_id)
    client = CPAClient(config)
    runtime = KeeperRuntime(config, database, client)
    server = KeeperHTTPServer((args.host, args.port), runtime, config.control_token)

    def graceful_stop(signum: int, frame: Any) -> None:
        del signum, frame
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, graceful_stop)
    signal.signal(signal.SIGINT, graceful_stop)
    runtime.start()
    try:
        server.serve_forever(poll_interval=0.25)
    finally:
        server.server_close()
        runtime.stop()
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (KeyboardInterrupt, SystemExit):
        raise
    except BaseException as exc:
        # Keep startup/teardown failures observable without rendering an
        # exception object that could retain a secret or transient usage item.
        sys.stderr.write(f"HOST KEEPER FAILED: {type(exc).__name__}\n")
        raise SystemExit(2) from None
