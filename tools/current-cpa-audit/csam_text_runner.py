#!/usr/bin/env python3
"""Run the Round 14 CSAM-text producer against an isolated live CPA/CAG.

This CLI never supplies expected decisions to the transport.  It derives the
observation from the HTTP result, the newly persisted CAG audit event, the
counted-Mock counters, and the CPA usage queue.  The producer in
``csam_text_evidence`` performs the separate fail-closed comparison.

Every cold start requires an operator-owned executable hook.  The hook is
invoked without a shell as ``HOOK <index> <runtime-root>`` and must
synchronously replace the CPA/CAG + counted-Mock runtime, then print exactly
one JSON object:

    {"cold_start":1,"instance_id":"new-runtime-id",
     "schema":"cag-current-cpa-csam-text-cold-start-hook/v1","status":"PASS"}

The three ``instance_id`` values must be distinct.  Fixed private-network DNS
names (for example ``http://cpa:8317`` and ``http://mock:18080``) let the hook
replace containers while keeping the runner endpoints stable.

After collection, the same hook is invoked as ``HOOK cleanup <runtime-root>``.
It must remove every runtime resource and the private runtime root, then print
exactly one cleanup receipt.  The runner independently proves that the runtime
root is absent; the parent audit runner separately proves that its labelled
Docker resource names are absent before it can emit machine evidence.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import math
import os
import re
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Mapping, Sequence
from urllib.parse import urlsplit

# ``run.py`` launches this producer with ``python -I`` so ambient site and
# working-directory imports cannot affect the audit.  Isolated mode also omits
# the script directory from ``sys.path``; bind imports to this verified bundle
# explicitly before loading sibling modules.
_TOOL_DIR = Path(__file__).resolve().parent
if str(_TOOL_DIR) not in sys.path:
    sys.path.insert(0, str(_TOOL_DIR))

from audit_contract import (
    AUDIT_SCHEMA_VERSION,
    MOCK_CONTRACT,
    MODES,
    REQUEST_HASH_DOMAIN,
    ContractError,
    add_exception_note,
    sha256_bytes,
    validate_allow_response,
    validate_block_response,
)
from csam_text_evidence import (
    CSAM_RULE_IDS,
    EvidenceError,
    TransportRequest,
    produce_evidence,
)
from run import AuditFailure, http_json, http_request, plugin_config


COLD_START_HOOK_SCHEMA = "cag-current-cpa-csam-text-cold-start-hook/v1"
CLEANUP_HOOK_SCHEMA = "cag-current-cpa-csam-text-cleanup-hook/v1"
SAFE_INSTANCE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{2,127}")
SAFE_ENV_NAME = re.compile(r"[A-Z_][A-Z0-9_]{1,127}")
SAFE_CONTAINER_DNS = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
MAX_HOOK_OUTPUT = 4096
NO_PRIOR_EVENT_ID = "<no-prior-event>"
# CPA can acknowledge the first request before its freshly started audit
# writer has made the event visible through the management endpoint.  Keep a
# bounded cold-start grace period without adding latency to steady-state
# requests.
FIRST_EVENT_PERSISTENCE_TIMEOUT = 15.0
EVENT_PERSISTENCE_TIMEOUT = 5.0
# A normal allow request is deliberately not retained as a CAG audit event.
# Once the persistent audit queue is observed idle and its counters are
# unchanged, a short additional window is enough to reject a delayed event
# without making each of the 756 benign matrix rows wait for the full event
# persistence timeout.
NO_EVENT_SETTLE_TIMEOUT = 0.25
AUDIT_COUNTER_KEYS = (
    "dropped",
    "enqueued",
    "failed",
    "queue_depth",
    "rejected",
    "written",
)
PRIVATE_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("::1/128"),
)


class LiveRunnerError(EvidenceError):
    """The live CPA/CAG observation boundary failed closed."""


def _bounded_secret(name: str) -> str:
    value = os.environ.get(name, "")
    if len(value) < 32 or len(value) > 4096 or any(ord(char) < 0x21 for char in value):
        raise LiveRunnerError(f"required credential environment variable is invalid: {name}")
    return value


def _validate_env_name(value: str) -> str:
    if SAFE_ENV_NAME.fullmatch(value) is None:
        raise LiveRunnerError("credential environment variable name is invalid")
    return value


def _validate_private_http_base(value: str, label: str) -> str:
    if type(value) is not str or not value:
        raise LiveRunnerError(f"{label} must be an explicit private HTTP base URL")
    try:
        parts = urlsplit(value)
        port = parts.port
    except ValueError as exc:
        raise LiveRunnerError(
            f"{label} must be an explicit private HTTP base URL"
        ) from exc
    if (
        parts.scheme != "http"
        or parts.hostname is None
        or parts.username is not None
        or parts.password is not None
        or parts.query
        or parts.fragment
        or parts.path not in {"", "/"}
        or port is None
        or port < 1
    ):
        raise LiveRunnerError(f"{label} must be an explicit private HTTP base URL")
    host = parts.hostname
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        # Container service discovery is intentionally limited to one bounded
        # DNS label.  Dotted/search-domain names and public FQDNs never enter
        # the runner's HTTP boundary.
        if (
            SAFE_CONTAINER_DNS.fullmatch(host) is None
            or not any(character.isalpha() for character in host)
        ):
            raise LiveRunnerError(
                f"{label} host is not a private IP or single-label container DNS name"
            )
    else:
        if not any(
            address.version == network.version and address in network
            for network in PRIVATE_NETWORKS
        ):
            raise LiveRunnerError(
                f"{label} IP is not loopback, private, or link-local"
            )
    return value.rstrip("/")


def _bounded_timeout(value: Any, label: str, maximum: float) -> float:
    if type(value) not in (int, float):
        raise LiveRunnerError(f"{label} must be a finite native number")
    try:
        finite = math.isfinite(value)
    except (OverflowError, TypeError, ValueError):
        finite = False
    if not finite or value <= 0 or value > maximum:
        raise LiveRunnerError(
            f"{label} must be finite and within the 0..{maximum:g} second bound"
        )
    return float(value)


def _json_no_duplicates(raw: bytes, label: str) -> Any:
    def pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in values:
            if key in result:
                raise LiveRunnerError(f"{label} contains a duplicate JSON key")
            result[key] = value
        return result

    try:
        return json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LiveRunnerError(f"{label} is not strict UTF-8 JSON") from exc


class LiveCPAExecutor:
    """Observe a pre-provisioned, isolated CPA/CAG + counted-Mock runtime."""

    def __init__(
        self,
        *,
        cpa_url: str,
        mock_url: str,
        cold_start_hook: Path,
        runtime_root: Path,
        client_key_env: str,
        management_key_env: str,
        mock_control_token_env: str,
        upstream_key_env: str,
        readiness_timeout: float = 60.0,
        hook_timeout: float = 180.0,
    ) -> None:
        self.cpa_url = _validate_private_http_base(cpa_url, "CPA URL")
        self.mock_url = _validate_private_http_base(mock_url, "counted-Mock URL")
        self.cold_start_hook = Path(cold_start_hook)
        self.runtime_root = Path(runtime_root)
        self.client_key_env = _validate_env_name(client_key_env)
        self.management_key_env = _validate_env_name(management_key_env)
        self.mock_control_token_env = _validate_env_name(mock_control_token_env)
        self.upstream_key_env = _validate_env_name(upstream_key_env)
        self.readiness_timeout = _bounded_timeout(
            readiness_timeout, "readiness timeout", 300
        )
        self.hook_timeout = _bounded_timeout(hook_timeout, "hook timeout", 900)
        self._instances: set[str] = set()
        self._runtime_root_identities: set[tuple[int, int]] = set()
        self._cold_start = 0
        self._requests_since_cold_start = 0
        self._current_mode: str | None = None
        self._closed = False
        self._hook_started = False
        self._validate_hook()
        self._validate_runtime_root_preflight()

    def _validate_hook(self) -> None:
        if not self.cold_start_hook.is_absolute():
            raise LiveRunnerError("cold-start hook must be an absolute path")
        try:
            info = self.cold_start_hook.lstat()
        except OSError as exc:
            raise LiveRunnerError("cold-start hook is unavailable") from exc
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            raise LiveRunnerError("cold-start hook must be a regular non-symlink file")
        if os.name != "nt" and not os.access(self.cold_start_hook, os.X_OK):
            raise LiveRunnerError("cold-start hook is not executable")

    def _validate_runtime_root_preflight(self) -> None:
        if (
            not self.runtime_root.is_absolute()
            or self.runtime_root.name in {"", ".", ".."}
        ):
            raise LiveRunnerError("CSAM runtime root must be an absolute child path")
        if os.path.lexists(self.runtime_root):
            raise LiveRunnerError("CSAM runtime root must not exist before execution")
        try:
            parent = self.runtime_root.parent.lstat()
        except OSError as exc:
            raise LiveRunnerError("CSAM runtime root parent is unavailable") from exc
        if stat.S_ISLNK(parent.st_mode) or not stat.S_ISDIR(parent.st_mode):
            raise LiveRunnerError("CSAM runtime root parent must be a real directory")
        if os.name != "nt" and parent.st_mode & 0o077:
            raise LiveRunnerError("CSAM runtime root parent must be private")

    def _validate_active_runtime_root(self) -> tuple[int, int]:
        try:
            info = self.runtime_root.lstat()
        except OSError as exc:
            raise LiveRunnerError("cold-start hook did not create its runtime root") from exc
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise LiveRunnerError("CSAM runtime root is not a real directory")
        if os.name != "nt" and (
            info.st_mode & 0o077
            or info.st_uid != os.getuid()
            or info.st_gid != os.getgid()
        ):
            raise LiveRunnerError("CSAM runtime root owner or mode is unsafe")
        return info.st_dev, info.st_ino

    @property
    def management_headers(self) -> dict[str, str]:
        return {"Authorization": "Bearer " + _bounded_secret(self.management_key_env)}

    @property
    def client_headers(self) -> dict[str, str]:
        return {"Authorization": "Bearer " + _bounded_secret(self.client_key_env)}

    @property
    def control_headers(self) -> dict[str, str]:
        return {
            "Authorization": "Bearer " + _bounded_secret(self.mock_control_token_env)
        }

    def _run_cold_start_hook(self, index: int) -> str:
        # Validate the fourth credential before invoking operator code.  The
        # live observer itself never sends this key; the hook uses it only to
        # bind CPA's isolated upstream entry to the counted Mock.
        _bounded_secret(self.upstream_key_env)
        try:
            completed = subprocess.run(
                [str(self.cold_start_hook), str(index), str(self.runtime_root)],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=self.hook_timeout,
                check=False,
                shell=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise LiveRunnerError(
                f"cold-start hook invocation failed: {type(exc).__name__}"
            ) from exc
        stdout = completed.stdout
        stderr = completed.stderr
        if (
            completed.returncode != 0
            or len(stdout) > MAX_HOOK_OUTPUT
            or len(stderr) > MAX_HOOK_OUTPUT
        ):
            diagnostic = sha256_bytes(stdout[:MAX_HOOK_OUTPUT] + b"\x00" + stderr[:MAX_HOOK_OUTPUT])
            raise LiveRunnerError(
                "cold-start hook failed or exceeded its output bound; "
                f"diagnostic_sha256={diagnostic}"
            )
        value = _json_no_duplicates(stdout, "cold-start hook output")
        if type(value) is not dict or set(value) != {
            "cold_start",
            "instance_id",
            "schema",
            "status",
        }:
            raise LiveRunnerError("cold-start hook output keys are not closed")
        if (
            type(value["cold_start"]) is not int
            or value["cold_start"] != index
            or value["schema"] != COLD_START_HOOK_SCHEMA
            or value["status"] != "PASS"
            or type(value["instance_id"]) is not str
            or SAFE_INSTANCE_ID.fullmatch(value["instance_id"]) is None
        ):
            raise LiveRunnerError("cold-start hook did not attest the requested runtime")
        instance_id = value["instance_id"]
        if instance_id in self._instances:
            raise LiveRunnerError("cold-start hook reused a runtime instance identity")
        runtime_identity = self._validate_active_runtime_root()
        if runtime_identity in self._runtime_root_identities:
            raise LiveRunnerError("cold-start hook reused its runtime root identity")
        self._runtime_root_identities.add(runtime_identity)
        self._hook_started = True
        return instance_id

    def _run_cleanup_hook(self) -> None:
        try:
            completed = subprocess.run(
                [str(self.cold_start_hook), "cleanup", str(self.runtime_root)],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=self.hook_timeout,
                check=False,
                shell=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise LiveRunnerError(
                f"cleanup hook invocation failed: {type(exc).__name__}"
            ) from exc
        stdout = completed.stdout
        stderr = completed.stderr
        if (
            completed.returncode != 0
            or len(stdout) > MAX_HOOK_OUTPUT
            or len(stderr) > MAX_HOOK_OUTPUT
        ):
            diagnostic = sha256_bytes(
                stdout[:MAX_HOOK_OUTPUT] + b"\x00" + stderr[:MAX_HOOK_OUTPUT]
            )
            raise LiveRunnerError(
                "cleanup hook failed or exceeded its output bound; "
                f"diagnostic_sha256={diagnostic}"
            )
        value = _json_no_duplicates(stdout, "cleanup hook output")
        if type(value) is not dict or set(value) != {
            "owned_resources_absent",
            "runtime_root_absent",
            "schema",
            "status",
        }:
            raise LiveRunnerError("cleanup hook output keys are not closed")
        if value != {
            "owned_resources_absent": True,
            "runtime_root_absent": True,
            "schema": CLEANUP_HOOK_SCHEMA,
            "status": "PASS",
        }:
            raise LiveRunnerError("cleanup hook did not attest exact absence")
        if os.path.lexists(self.runtime_root):
            raise LiveRunnerError("CSAM runtime root remained after cleanup")

    def _mock_health_ready(self) -> bool:
        value, _, _ = http_json(self.mock_url, "GET", "/healthz")
        return value == {
            "contract": MOCK_CONTRACT,
            "healthy": True,
            "request_body_retention": False,
        }

    def _wait_mock(self) -> None:
        deadline = time.monotonic() + self.readiness_timeout
        while time.monotonic() < deadline:
            try:
                if self._mock_health_ready():
                    return
            except (AuditFailure, ContractError):
                pass
            time.sleep(0.25)
        raise LiveRunnerError("counted-Mock readiness did not converge")

    @staticmethod
    def _status_ready(status: Any, mode: str) -> bool:
        if type(status) is not dict:
            return False
        audit = status.get("audit")
        raw_capture = status.get("raw_capture")
        return (
            status.get("id") == "cyber-abuse-guard"
            and status.get("enabled") is True
            and status.get("mode") == mode
            and status.get("enforcement_ready") is True
            and status.get("operational_ready") is True
            and status.get("audit_degraded") is False
            and status.get("persistence_degraded") is False
            and type(audit) is dict
            and audit.get("healthy") is True
            and audit.get("degraded") is False
            and audit.get("schema_version") == AUDIT_SCHEMA_VERSION
            and audit.get("persistence_verified") is True
            and type(raw_capture) is dict
            and raw_capture.get("enabled") is False
        )

    def _wait_mode(self, mode: str) -> None:
        deadline = time.monotonic() + self.readiness_timeout
        while time.monotonic() < deadline:
            try:
                status, _, _ = http_json(
                    self.cpa_url,
                    "GET",
                    "/v0/management/plugins/cyber-abuse-guard/status",
                    headers=self.management_headers,
                )
                if self._status_ready(status, mode):
                    return
            except (AuditFailure, ContractError):
                pass
            time.sleep(0.25)
        raise LiveRunnerError(f"CPA/CAG readiness did not converge for mode={mode}")

    def _configure_mode(self, mode: str) -> None:
        if mode not in MODES:
            raise LiveRunnerError("producer requested an unsupported CAG mode")
        deadline = time.monotonic() + self.readiness_timeout
        while time.monotonic() < deadline:
            try:
                value, _, _ = http_json(
                    self.cpa_url,
                    "PUT",
                    "/v0/management/plugins/cyber-abuse-guard/config",
                    plugin_config(mode),
                    self.management_headers,
                )
                if type(value) is dict and value.get("status") == "ok":
                    break
            except (AuditFailure, ContractError):
                pass
            time.sleep(0.25)
        else:
            raise LiveRunnerError("CAG did not acknowledge its mode configuration")
        self._wait_mode(mode)
        self._current_mode = mode

    def begin_cold_start(self, index: int) -> None:
        if self._closed:
            raise LiveRunnerError("executor is already closed")
        if type(index) is not int or index != self._cold_start + 1 or index not in {1, 2, 3}:
            raise LiveRunnerError("cold starts must be requested exactly once in order")
        instance_id = self._run_cold_start_hook(index)
        self._current_mode = None
        self._wait_mock()
        self._configure_mode("audit")
        self.reset_mock()
        self.drain_usage_queue()
        self._requests_since_cold_start = 0
        self._instances.add(instance_id)
        self._cold_start = index

    def mock_snapshot(self) -> dict[str, int]:
        value, _, _ = http_json(
            self.mock_url, "GET", "/__cag/stats", headers=self.control_headers
        )
        if type(value) is not dict or set(value) != {
            "schema",
            "auth",
            "mock",
            "provider",
        }:
            raise LiveRunnerError("counted-Mock stats schema is invalid")
        if value["schema"] != MOCK_CONTRACT:
            raise LiveRunnerError("counted-Mock stats contract drifted")
        result: dict[str, int] = {}
        for key in ("auth", "mock", "provider"):
            if type(value[key]) is not int or value[key] < 0:
                raise LiveRunnerError("counted-Mock counter is invalid")
            result[key] = value[key]
        return result

    def reset_mock(self) -> None:
        value, _, _ = http_json(
            self.mock_url, "POST", "/__cag/reset", headers=self.control_headers
        )
        expected = {"schema": MOCK_CONTRACT, "auth": 0, "mock": 0, "provider": 0}
        if value != expected or self.mock_snapshot() != {
            "auth": 0,
            "mock": 0,
            "provider": 0,
        }:
            raise LiveRunnerError("counted-Mock reset did not reach exact zero")

    def usage_queue(self) -> list[Any]:
        value, _, _ = http_json(
            self.cpa_url,
            "GET",
            "/v0/management/usage-queue?count=100",
            headers=self.management_headers,
        )
        if type(value) is not list:
            raise LiveRunnerError("CPA usage queue response is not a list")
        return value

    def drain_usage_queue(self) -> None:
        for _ in range(80):
            if not self.usage_queue():
                return
            time.sleep(0.025)
        raise LiveRunnerError("CPA usage queue did not drain")

    def _usage_after_request(self, allowed: bool) -> int:
        deadline = time.monotonic() + (5.0 if allowed else 0.75)
        observed: list[Any] = []
        while time.monotonic() < deadline:
            observed = self.usage_queue()
            if observed:
                break
            time.sleep(0.05)
        return len(observed)

    def _event_head(self) -> dict[str, Any] | None:
        value, _, _ = http_json(
            self.cpa_url,
            "GET",
            "/v0/management/plugins/cyber-abuse-guard/events?limit=1",
            headers=self.management_headers,
        )
        if (
            type(value) is not dict
            or value.get("audit_schema_version") != AUDIT_SCHEMA_VERSION
            or value.get("event_response_schema_version") != 2
            or type(value.get("events")) is not list
            or len(value["events"]) > 1
        ):
            raise LiveRunnerError("CAG audit event response schema is invalid")
        if not value["events"]:
            return None
        event = value["events"][0]
        if type(event) is not dict:
            raise LiveRunnerError("CAG audit event is not an object")
        return event

    def _event_head_id(self) -> str:
        event = self._event_head()
        if event is None:
            return NO_PRIOR_EVENT_ID
        event_id = event.get("id")
        if type(event_id) is not str or not event_id:
            raise LiveRunnerError("CAG audit event ID is empty or malformed")
        return event_id

    def _audit_counter_snapshot(self) -> dict[str, int]:
        value, _, _ = http_json(
            self.cpa_url,
            "GET",
            "/v0/management/plugins/cyber-abuse-guard/status",
            headers=self.management_headers,
        )
        audit = value.get("audit") if type(value) is dict else None
        if type(audit) is not dict:
            raise LiveRunnerError("CAG audit status is unavailable")
        snapshot: dict[str, int] = {}
        for key in AUDIT_COUNTER_KEYS:
            current = audit.get(key)
            if type(current) is not int or current < 0:
                raise LiveRunnerError("CAG audit status counter is invalid")
            snapshot[key] = current
        return snapshot

    def _new_event(self, previous_id: str, request_hash: str) -> dict[str, Any]:
        timeout = (
            FIRST_EVENT_PERSISTENCE_TIMEOUT
            if self._requests_since_cold_start == 0
            else EVENT_PERSISTENCE_TIMEOUT
        )
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            event = self._event_head()
            if event is not None:
                event_id = event.get("id")
                if type(event_id) is not str or not event_id:
                    raise LiveRunnerError("CAG audit event ID is empty or malformed")
                if event_id != previous_id:
                    if event.get("request_hash") != request_hash:
                        raise LiveRunnerError("new CAG audit event is not bound to this request")
                    return event
            time.sleep(0.025)
        raise LiveRunnerError("CAG did not persist a request-bound audit event")

    def _event_or_idle_audit(
        self,
        previous_id: str,
        request_hash: str,
        before_audit: Mapping[str, int],
    ) -> dict[str, Any] | None:
        """Return the new event, or prove the request produced no audit work.

        CAG intentionally persists enforced/audited findings, not every normal
        allow.  Treating absent events as a universal failure made the CSAM
        evidence plane reject benign requests.  Conversely, accepting an absent
        event while the bounded writer has changed counters would hide a failed
        persistence path.  The two observations together keep the distinction
        explicit and fail closed on ambiguous writer activity.
        """

        if set(before_audit) != set(AUDIT_COUNTER_KEYS):
            raise LiveRunnerError("CAG pre-request audit snapshot is invalid")
        event_deadline = time.monotonic() + (
            FIRST_EVENT_PERSISTENCE_TIMEOUT
            if self._requests_since_cold_start == 0
            else EVENT_PERSISTENCE_TIMEOUT
        )
        idle_deadline = time.monotonic() + NO_EVENT_SETTLE_TIMEOUT
        while time.monotonic() < event_deadline:
            event = self._event_head()
            if event is not None:
                event_id = event.get("id")
                if type(event_id) is not str or not event_id:
                    raise LiveRunnerError("CAG audit event ID is empty or malformed")
                if event_id != previous_id:
                    if event.get("request_hash") != request_hash:
                        raise LiveRunnerError("new CAG audit event is not bound to this request")
                    return event
            current_audit = self._audit_counter_snapshot()
            counters_unchanged = all(
                current_audit[key] == before_audit[key] for key in AUDIT_COUNTER_KEYS
            )
            if counters_unchanged and current_audit["queue_depth"] == 0:
                if time.monotonic() >= idle_deadline:
                    return None
            elif current_audit["enqueued"] < before_audit["enqueued"]:
                raise LiveRunnerError("CAG audit enqueue counter regressed")
            time.sleep(0.025)
        raise LiveRunnerError("CAG audit activity did not yield a request-bound event")

    @staticmethod
    def _request_audit_hash(body: bytearray) -> str:
        digest = hashlib.sha256()
        digest.update(REQUEST_HASH_DOMAIN)
        digest.update(body)
        return "sha256:" + digest.hexdigest()

    @staticmethod
    def _event_projection(event: Mapping[str, Any], mode: str) -> tuple[str | None, str | None]:
        if event.get("mode") != mode:
            raise LiveRunnerError("CAG audit event mode differs from the request")
        category = event.get("category") or None
        if category is not None and type(category) is not str:
            raise LiveRunnerError("CAG audit event category is malformed")
        raw_rules = event.get("rule_ids")
        if raw_rules is None:
            rules: list[Any] = []
        elif type(raw_rules) is list:
            rules = raw_rules
        else:
            raise LiveRunnerError("CAG audit event rule_ids is malformed")
        if category == "csam_malicious":
            explanation = event.get("decision_explanation")
            if (
                event.get("classifier") != "csam-text-v1"
                or len(rules) != 1
                or rules[0] not in CSAM_RULE_IDS
                or type(explanation) is not dict
                or explanation.get("kind") != "csam_text"
            ):
                raise LiveRunnerError("CAG CSAM event lacks its fixed taxonomy proof")
            return category, rules[0]
        if rules:
            # A non-CSAM observation must not smuggle an arbitrary winner into
            # the separate CSAM evidence plane.
            return category, None
        return category, None

    def execute(self, request: TransportRequest) -> Mapping[str, Any]:
        if self._closed or request.cold_start != self._cold_start:
            raise LiveRunnerError("transport request is outside the active cold start")
        if request.mode != self._current_mode:
            self._configure_mode(request.mode)

        self.drain_usage_queue()
        self.reset_mock()
        before = self.mock_snapshot()
        before_audit = self._audit_counter_snapshot()
        previous_event = self._event_head_id()
        request_hash = self._request_audit_hash(request.body)
        endpoint = "/v1/chat/completions" if request.protocol == "chat" else "/v1/responses"
        status, response, response_headers, _ = http_request(
            self.cpa_url,
            "POST",
            endpoint,
            request.body,
            self.client_headers,
        )
        after = self.mock_snapshot()
        allowed = status == 200
        usage_count = self._usage_after_request(allowed)
        event = self._event_or_idle_audit(previous_event, request_hash, before_audit)
        self._requests_since_cold_start += 1
        if event is None:
            category, winner = None, None
            decision_kind = None
        else:
            category, winner = self._event_projection(event, request.mode)
            decision_kind = event.get("decision_kind")

        if status == 200:
            response_valid, stream_terminated = validate_allow_response(
                request.protocol,
                request.stream,
                response,
                response_headers,
                request.model,
            )
            if not response_valid or not stream_terminated:
                raise LiveRunnerError("allowed transport response failed its protocol contract")
            if category == "csam_malicious" and (
                decision_kind != "audit_csam_text" or event.get("action") != "audit"
            ):
                raise LiveRunnerError("allowed CSAM transport lacks its audit disposition")
            if category != "csam_malicious" and decision_kind in {
                "audit_csam_text",
                "block_csam_text",
            }:
                raise LiveRunnerError("allowed non-CSAM transport carries a CSAM disposition")
            actual_action = "allow"
        elif status == 403:
            validate_block_response(response, response_headers)
            if (
                event is None
                or decision_kind != "block_csam_text"
                or event.get("action") != "block"
            ):
                raise LiveRunnerError("HTTP block is not an observed CSAM-text block")
            actual_action = "block_malicious_text"
        else:
            diagnostic = sha256_bytes(response)
            raise LiveRunnerError(
                f"unexpected CPA transport status={status}; response_sha256={diagnostic}"
            )

        return {
            "actual_action": actual_action,
            "category": category,
            "side_effect_deltas": {
                "auth": after["auth"] - before["auth"],
                "mock": after["mock"] - before["mock"],
                "provider": after["provider"] - before["provider"],
                "usage": usage_count,
            },
            "winning_rule_id": winner,
        }

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        primary: BaseException | None = None
        if self._cold_start:
            try:
                self.drain_usage_queue()
                self.reset_mock()
            except BaseException as exc:
                primary = exc
        if self._hook_started:
            try:
                self._run_cleanup_hook()
            except BaseException as cleanup_exc:
                if primary is None:
                    primary = cleanup_exc
                else:
                    add_exception_note(
                        primary,
                        "CSAM cleanup hook also failed: "
                        f"{type(cleanup_exc).__name__}: {cleanup_exc}"
                    )
        self._current_mode = None
        if primary is not None:
            raise primary


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Produce text-free Round 14 CSAM evidence from a live isolated CPA/CAG"
    )
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--cpa-url", required=True)
    parser.add_argument("--mock-url", required=True)
    parser.add_argument("--cold-start-hook", required=True, type=Path)
    parser.add_argument("--runtime-root", required=True, type=Path)
    parser.add_argument("--model", default="current-cpa-audit-model")
    parser.add_argument("--client-key-env", default="CAG_CSAM_CLIENT_KEY")
    parser.add_argument("--management-key-env", default="CAG_CSAM_MANAGEMENT_KEY")
    parser.add_argument(
        "--mock-control-token-env", default="CAG_CSAM_MOCK_CONTROL_TOKEN"
    )
    parser.add_argument("--upstream-key-env", default="CAG_CSAM_UPSTREAM_KEY")
    parser.add_argument("--readiness-timeout", type=float, default=60.0)
    parser.add_argument("--hook-timeout", type=float, default=180.0)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        executor = LiveCPAExecutor(
            cpa_url=args.cpa_url,
            mock_url=args.mock_url,
            cold_start_hook=args.cold_start_hook,
            runtime_root=args.runtime_root,
            client_key_env=args.client_key_env,
            management_key_env=args.management_key_env,
            mock_control_token_env=args.mock_control_token_env,
            upstream_key_env=args.upstream_key_env,
            readiness_timeout=args.readiness_timeout,
            hook_timeout=args.hook_timeout,
        )
        paths = produce_evidence(
            args.run_id, args.output_dir, executor, model=args.model
        )
        digests = {
            key + "_sha256": hashlib.sha256(path.read_bytes()).hexdigest()
            for key, path in paths.items()
        }
        print(
            json.dumps(
                {
                    **digests,
                    "execution_count": 1296,
                    "run_id": args.run_id,
                    "status": "PASS",
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 0
    except (AuditFailure, ContractError, EvidenceError, OSError, ValueError) as exc:
        print(f"CSAM text evidence failed closed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
