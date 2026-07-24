#!/usr/bin/env python3
"""Root-installed black-box evaluator for the Round 9 independent corpus.

The evaluator never imports the Guard Go module and never emits prompt or
response text.  It accepts only a private, already-decrypted corpus directory,
talks to loopback CPA/counting endpoints, and returns bounded aggregate/hash
evidence for the broker to sign.
"""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import stat
import sys
import time
from typing import Any, Iterable
from urllib import error, parse, request

sys.path.insert(0, str(Path(__file__).resolve().parent))
import round9_eval_core as core_module  # noqa: E402

from round9_eval_core import (  # noqa: E402
    CORPUS_BUNDLE_SCHEMA,
    EVALUATOR_AGGREGATE_SCHEMA,
    FIXED_NETWORK_BINDING,
    FIXED_PHASE_PROTOCOL,
    ContractError,
    HEX64,
    IDENTIFIER,
    canonical_bytes,
    challenge_sha256,
    exact_bool,
    exact_int,
    exact_object,
    load_canonical_json,
    load_json_bytes,
    require_literal,
    require_pattern,
    require_root_owned_regular,
    sha256_bytes,
    sha256_file,
    validate_runtime_checks,
    validate_metrics,
    verify_signed_envelope,
    wilson_interval_95,
)


BENIGN_MANIFEST_SCHEMA = "round9-independent-benign-manifest/v1"
MALICIOUS_MANIFEST_SCHEMA = "round9-independent-malicious-manifest/v1"
SANDBOX_SCHEMA = "round9-external-cpa-sandbox/v2"
AUDIT_EXPECTATIONS_SCHEMA = "round9-cpa-audit-expectations/v2"
CPA_VERSION = "v7.2.95"
CPA_COMMIT = "f71ec0eb6776854457892452cf28c47f0d658251"
MAX_PROMPT_BYTES = 131_072
MAX_RESPONSE_BYTES = 1_048_576
USAGE_QUIET_WINDOW_SECONDS = 0.02
USAGE_OBSERVE_TIMEOUT_SECONDS = 2.0
REQUEST_HASH_DOMAIN = b"cyber-abuse-guard/audit/request/v1\x00"
MODEL_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")

BENIGN_ROUTES = tuple(
    (mode, protocol, stream)
    for mode in FIXED_PHASE_PROTOCOL["phase_order"]
    for protocol in ("chat", "responses")
    for stream in (False, True)
)
MALICIOUS_ROUTES = tuple(
    (mode, protocol, stream)
    for mode in FIXED_PHASE_PROTOCOL["phase_order"]
    for protocol in ("chat", "responses")
    for stream in (False, True)
)
ENFORCEMENT_MODES = ("balanced", "strict")
MALICIOUS_ENFORCEMENT_ROUTES = tuple(
    route for route in MALICIOUS_ROUTES if route[0] in ENFORCEMENT_MODES
)


class _NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        del req, fp, code, msg, headers, newurl
        return None


LOOPBACK_OPENER = request.build_opener(request.ProxyHandler({}), _NoRedirect())


def fail(message: str) -> None:
    raise ContractError(message)


def safe_text(value: Any, label: str, *, maximum: int = MAX_PROMPT_BYTES) -> str:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > maximum:
        fail(f"{label} is empty or exceeds the reviewed UTF-8 bound")
    if "\x00" in value:
        fail(f"{label} contains a NUL byte")
    return value


def audit_request_hash(body: bytes) -> str:
    return "sha256:" + hashlib.sha256(REQUEST_HASH_DOMAIN + body).hexdigest()


def read_jsonl(path: Path, label: str, *, maximum: int = 268_435_456) -> list[dict[str, Any]]:
    if path.is_symlink() or not path.is_file():
        fail(f"{label} must be a regular non-symlink file")
    size = path.stat().st_size
    if size <= 0 or size > maximum:
        fail(f"{label} size is outside the reviewed bound")
    cases: list[dict[str, Any]] = []
    with path.open("rb") as source:
        for line_number, raw in enumerate(source, start=1):
            if len(raw) > MAX_PROMPT_BYTES + 4096:
                fail(f"{label} line {line_number} exceeds the reviewed bound")
            if not raw.endswith(b"\n") or raw in {b"\n", b"\r\n"}:
                fail(f"{label} line {line_number} is not canonical JSONL")
            value = load_json_bytes(raw, f"{label} line {line_number}")
            if not isinstance(value, dict) or canonical_bytes(value) != raw:
                fail(f"{label} line {line_number} is not canonical JSONL")
            cases.append(value)
    if not cases:
        fail(f"{label} is empty")
    return cases


def validate_case(value: Any, label: str) -> dict[str, str]:
    case = exact_object(value, {"id", "category", "language", "prompt"}, label)
    require_pattern(case["id"], IDENTIFIER, f"{label}.id")
    require_pattern(case["category"], IDENTIFIER, f"{label}.category")
    if case["language"] not in {"en", "zh"}:
        fail(f"{label}.language must be en or zh")
    prompt = safe_text(case["prompt"], f"{label}.prompt")
    folded = prompt.casefold()
    if case["id"].casefold() in folded or any(
        marker in folded
        for marker in (
            "round9",
            "round 9",
            "independent benign",
            "independent malicious",
            "holdout case",
            "corpus case",
        )
    ):
        fail(f"{label}.prompt exposes evaluator-only identity text")
    return case


def validate_file_identity(path: Path, value: Any, label: str) -> None:
    identity = exact_object(value, {"bytes", "sha256"}, label)
    if path.is_symlink() or not path.is_file():
        fail(f"{label} target must be a regular non-symlink file")
    if exact_int(identity["bytes"], f"{label}.bytes", minimum=1) != path.stat().st_size:
        fail(f"{label} byte identity differs")
    if require_pattern(identity["sha256"], HEX64, f"{label}.sha256") != sha256_file(path):
        fail(f"{label} SHA-256 identity differs")


def validate_corpus_section(
    value: Any,
    label: str,
    *,
    schema: str,
    routes_per_sample: int,
    expected_disposition: str,
    minimum_samples: int,
) -> dict[str, Any]:
    section = exact_object(
        value,
        {
            "schema",
            "unique_semantic_samples",
            "routes_per_sample",
            "categories",
            "languages",
            "expected_disposition",
            "ground_truth_frozen_before_candidate",
        },
        label,
    )
    require_literal(section["schema"], schema, f"{label}.schema")
    exact_int(section["unique_semantic_samples"], f"{label}.samples", minimum=minimum_samples)
    if exact_int(section["routes_per_sample"], f"{label}.routes_per_sample") != routes_per_sample:
        fail(f"{label}.routes_per_sample differs from the frozen matrix")
    categories = section["categories"]
    if (
        not isinstance(categories, list)
        or not categories
        or len(categories) != len(set(categories))
        or any(not isinstance(item, str) or IDENTIFIER.fullmatch(item) is None for item in categories)
    ):
        fail(f"{label}.categories is invalid")
    if section["languages"] != ["en", "zh"]:
        fail(f"{label}.languages must be the canonical en/zh list")
    require_literal(section["expected_disposition"], expected_disposition, f"{label}.expected_disposition")
    exact_bool(
        section["ground_truth_frozen_before_candidate"],
        True,
        f"{label}.ground_truth_frozen_before_candidate",
    )
    return section


def load_corpus_bundle(
    corpus_root: Path,
    *,
    signed_manifest_path: Path,
    author_public_key: Path,
    author_key_id: str,
    bundle_sha256: str,
    minimum_benign: int = 600,
    minimum_malicious: int = 90,
) -> tuple[dict[str, Any], list[dict[str, str]], list[dict[str, str]]]:
    if corpus_root.is_symlink() or not corpus_root.is_dir():
        fail("decrypted corpus root must be a regular directory")
    require_pattern(bundle_sha256, HEX64, "encrypted corpus bundle sha256")
    envelope = load_canonical_json(
        signed_manifest_path, "signed corpus manifest", maximum=1_048_576
    )
    payload = verify_signed_envelope(
        envelope,
        author_public_key,
        author_key_id,
        expected_payload_schema=CORPUS_BUNDLE_SCHEMA,
    )
    manifest = exact_object(
        payload,
        {
            "schema",
            "evaluation_id",
            "author",
            "files",
            "benign",
            "malicious",
            "plaintext_in_repository",
        },
        "corpus bundle manifest",
    )
    require_pattern(manifest["evaluation_id"], IDENTIFIER, "corpus evaluation id")
    author = exact_object(
        manifest["author"],
        {"key_id", "independence", "candidate_outputs_seen"},
        "corpus author",
    )
    require_literal(author["key_id"], author_key_id, "corpus author key id")
    require_literal(
        author["independence"],
        "AUTHOR_DID_NOT_PARTICIPATE_IN_RULE_DEVELOPMENT",
        "corpus author independence",
    )
    exact_bool(author["candidate_outputs_seen"], False, "candidate_outputs_seen")
    exact_bool(manifest["plaintext_in_repository"], False, "plaintext_in_repository")

    names = {
        "benign-manifest.json",
        "benign-cases.jsonl",
        "malicious-manifest.json",
        "malicious-cases.jsonl",
    }
    files = exact_object(manifest["files"], names, "corpus bundle files")
    paths = {name: corpus_root / name for name in names}
    for name in sorted(names):
        validate_file_identity(paths[name], files[name], f"corpus file {name}")

    benign_section = validate_corpus_section(
        manifest["benign"],
        "benign corpus",
        schema=BENIGN_MANIFEST_SCHEMA,
        routes_per_sample=len(BENIGN_ROUTES),
        expected_disposition="allow",
        minimum_samples=minimum_benign,
    )
    malicious_section = validate_corpus_section(
        manifest["malicious"],
        "malicious corpus",
        schema=MALICIOUS_MANIFEST_SCHEMA,
        routes_per_sample=len(MALICIOUS_ROUTES),
        expected_disposition="block_malicious_text",
        minimum_samples=minimum_malicious,
    )

    # The standalone manifests are duplicated, signed identities. They make
    # ground-truth hashes independently reviewable without exposing case text.
    if load_canonical_json(paths["benign-manifest.json"], "benign manifest") != benign_section:
        fail("benign standalone manifest differs from the signed bundle")
    if load_canonical_json(paths["malicious-manifest.json"], "malicious manifest") != malicious_section:
        fail("malicious standalone manifest differs from the signed bundle")

    benign_cases = [
        validate_case(item, f"benign case {index}")
        for index, item in enumerate(read_jsonl(paths["benign-cases.jsonl"], "benign cases"))
    ]
    malicious_cases = [
        validate_case(item, f"malicious case {index}")
        for index, item in enumerate(read_jsonl(paths["malicious-cases.jsonl"], "malicious cases"))
    ]
    for label, cases, section in (
        ("benign", benign_cases, benign_section),
        ("malicious", malicious_cases, malicious_section),
    ):
        ids = [item["id"] for item in cases]
        if len(ids) != len(set(ids)):
            fail(f"{label} case identifiers are not unique")
        if len(cases) != section["unique_semantic_samples"]:
            fail(f"{label} case count differs from the signed manifest")
        if set(item["category"] for item in cases) != set(section["categories"]):
            fail(f"{label} case categories differ from the signed manifest")
        if set(item["language"] for item in cases) != {"en", "zh"}:
            fail(f"{label} cases must contain both en and zh")
        evaluation_marker = manifest["evaluation_id"].casefold()
        if any(evaluation_marker in item["prompt"].casefold() for item in cases):
            fail(f"{label} prompt exposes the corpus evaluation identity")

    corpus = {
        "evaluation_id": manifest["evaluation_id"],
        "bundle_sha256": bundle_sha256,
        "bundle_manifest_sha256": sha256_file(signed_manifest_path),
        "benign_manifest_sha256": sha256_file(paths["benign-manifest.json"]),
        "benign_cases_sha256": sha256_file(paths["benign-cases.jsonl"]),
        "malicious_manifest_sha256": sha256_file(paths["malicious-manifest.json"]),
        "malicious_cases_sha256": sha256_file(paths["malicious-cases.jsonl"]),
        "author_key_id": author_key_id,
        "plaintext_in_repository": False,
    }
    return corpus, benign_cases, malicious_cases


def require_loopback_url(value: Any, label: str) -> str:
    if not isinstance(value, str):
        fail(f"{label} must be text")
    parsed = parse.urlsplit(value)
    if (
        parsed.scheme != "http"
        or parsed.hostname not in {"127.0.0.1", "::1"}
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        fail(f"{label} must be an uncredentialed loopback HTTP URL")
    return value.rstrip("/")


def expected_plugin_config(mode: str) -> dict[str, Any]:
    if mode not in {"audit", "balanced", "strict"}:
        fail("sandbox plugin mode is invalid")
    return {
        "enabled": True,
        "priority": 300,
        "mode": mode,
        "max_scan_bytes": 16_384,
        "max_total_text_bytes": 16_384,
        "opaque_media_policy": "audit",
        "subject_control": {"enabled": False},
        "audit": {
            "enabled": True,
            "data_dir": "/cag/audit",
            "retention_days": 1,
            "max_db_mb": 32,
            "log_request_hash": True,
            "log_subject_hash": True,
            "log_rule_ids": True,
            "log_category": True,
            "persist_wrapper_only": False,
            "log_original_text": False,
            "raw_capture": {
                "enabled": False,
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


def validate_sandbox_descriptor(
    value: Any,
    expected_candidate_so_sha256: str,
    *,
    enforce_root_ownership: bool = True,
) -> dict[str, Any]:
    descriptor = exact_object(
        value,
        {
            "schema",
            "base_url",
            "counter_url",
            "authorization_token_file",
            "management_token_file",
            "balanced_plugin_config_file",
            "strict_plugin_config_file",
            "network_binding",
            "phase_protocol",
            "model",
            "scan_limit_bytes",
            "candidate_so_sha256",
            "cpa_version",
            "cpa_commit",
            "cpa_image_id",
            "counted_mock_image_id",
            "sandbox_id",
            "daemon_id",
            "probe_image_id",
            "production_accessed",
            "real_provider_contacted",
            "runtime_checks",
            "runtime_baseline",
            "runtime_canary_file",
        },
        "sandbox descriptor",
    )
    require_literal(descriptor["schema"], SANDBOX_SCHEMA, "sandbox schema")
    for key in ("base_url", "counter_url"):
        require_loopback_url(descriptor[key], f"sandbox {key}")
    require_literal(
        descriptor["base_url"],
        "http://127.0.0.1:18394",
        "sandbox fixed CPA base URL",
    )
    if descriptor["network_binding"] != FIXED_NETWORK_BINDING:
        fail("sandbox network binding differs from 127.0.0.1:18394 -> 8317/tcp")
    if descriptor["phase_protocol"] != FIXED_PHASE_PROTOCOL:
        fail(
            "sandbox phase protocol is not one authenticated CPA in Audit, Balanced, then Strict order"
        )
    model = descriptor["model"]
    if (
        not isinstance(model, str)
        or MODEL_ID.fullmatch(model) is None
        or any(marker in model.casefold() for marker in ("round9", "eval", "mock", "corpus", "holdout", "test"))
    ):
        fail("sandbox model must be an ordinary non-evaluation model identity")
    if exact_int(descriptor["scan_limit_bytes"], "sandbox scan limit", minimum=4096) != 16_384:
        fail("sandbox scan limit must remain exactly 16 KiB")
    for key, label in (
        ("authorization_token_file", "sandbox authorization token"),
        ("management_token_file", "sandbox management token"),
        ("balanced_plugin_config_file", "sandbox Balanced plugin configuration"),
        ("strict_plugin_config_file", "sandbox strict plugin configuration"),
        ("runtime_canary_file", "sandbox synthetic runtime canary"),
    ):
        target = Path(descriptor[key])
        if enforce_root_ownership:
            require_root_owned_regular(target, label, mode_mask=0o077)
        elif target.is_symlink() or not target.is_file():
            fail(f"{label} must be a regular file")
    balanced_config = load_canonical_json(
        Path(descriptor["balanced_plugin_config_file"]),
        "sandbox Balanced plugin configuration",
        maximum=262_144,
    )
    if balanced_config != expected_plugin_config("balanced"):
        fail("sandbox Balanced plugin configuration differs from the frozen contract")
    strict_config = load_canonical_json(
        Path(descriptor["strict_plugin_config_file"]),
        "sandbox strict plugin configuration",
        maximum=262_144,
    )
    if strict_config != expected_plugin_config("strict"):
        fail("sandbox strict plugin configuration differs from the frozen contract")
    require_literal(
        descriptor["candidate_so_sha256"],
        expected_candidate_so_sha256,
        "sandbox candidate SO sha256",
    )
    require_literal(descriptor["cpa_version"], CPA_VERSION, "sandbox CPA version")
    require_literal(descriptor["cpa_commit"], CPA_COMMIT, "sandbox CPA commit")
    for key, label in (
        ("cpa_image_id", "sandbox CPA image id"),
        ("counted_mock_image_id", "sandbox counted Mock image id"),
    ):
        value = descriptor[key]
        if not isinstance(value, str) or not value.startswith("sha256:"):
            fail(f"{label} is invalid")
        require_pattern(value[7:], HEX64, label)
    require_pattern(descriptor["sandbox_id"], IDENTIFIER, "sandbox id")
    require_pattern(descriptor["daemon_id"], IDENTIFIER, "sandbox daemon id")
    if not isinstance(descriptor["probe_image_id"], str) or not descriptor["probe_image_id"].startswith("sha256:"):
        fail("sandbox probe image id is invalid")
    require_pattern(descriptor["probe_image_id"][7:], HEX64, "sandbox probe image sha256")
    exact_bool(descriptor["production_accessed"], False, "sandbox production_accessed")
    exact_bool(descriptor["real_provider_contacted"], False, "sandbox real_provider_contacted")
    validate_runtime_checks(descriptor["runtime_checks"])
    baseline = exact_object(
        descriptor["runtime_baseline"],
        {"audit_event_count", "raw_capture_count", "subject_state_rows", "restart_count"},
        "sandbox runtime baseline",
    )
    if (
        exact_int(baseline["audit_event_count"], "sandbox baseline audit events", minimum=3) < 3
        or exact_int(baseline["raw_capture_count"], "sandbox baseline Raw Capture") != 0
        or exact_int(baseline["subject_state_rows"], "sandbox baseline subjects") != 0
        or exact_int(baseline["restart_count"], "sandbox baseline restarts") != 0
    ):
        fail("sandbox runtime baseline differs from the closed preflight")
    return descriptor


class CPAClient:
    def __init__(self, descriptor: dict[str, Any], *, timeout: float = 20.0):
        self.descriptor = descriptor
        self.timeout = timeout
        token_path = Path(descriptor["authorization_token_file"])
        token = token_path.read_text(encoding="utf-8").strip()
        if not token or len(token) > 4096 or "\n" in token or "\r" in token:
            fail("sandbox authorization token is invalid")
        self.authorization = f"Bearer {token}"
        management_path = Path(descriptor["management_token_file"])
        management_token = management_path.read_text(encoding="utf-8").strip()
        if (
            not management_token
            or len(management_token) > 4096
            or "\n" in management_token
            or "\r" in management_token
        ):
            fail("sandbox management token is invalid")
        self.management_authorization = f"Bearer {management_token}"
        self.current_mode = "audit"
        self.mode_status_verified = {
            mode: False for mode in FIXED_PHASE_PROTOCOL["phase_order"]
        }
        self.authenticated_mode_switches: list[str] = []
        self.mode_switch_negative_auth_verified = {
            mode: False for mode in ("balanced", "strict")
        }
        self.effective_config_sha256: dict[str, str] = {}

    def _open(
        self,
        target: str,
        *,
        method: str = "GET",
        body: bytes | None = None,
        authorization: str | None = None,
    ) -> tuple[int, bytes]:
        parsed = parse.urlsplit(target)
        if (
            parsed.scheme != "http"
            or parsed.hostname not in {"127.0.0.1", "::1"}
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
        ):
            fail("CPA sandbox request target must remain loopback-only")
        headers = {"Accept": "application/json"}
        selected_authorization = self.authorization if authorization is None else authorization
        if selected_authorization:
            headers["Authorization"] = selected_authorization
        if body is not None:
            headers["Content-Type"] = "application/json"
        operation = request.Request(target, data=body, headers=headers, method=method)
        try:
            with LOOPBACK_OPENER.open(operation, timeout=self.timeout) as response:
                raw = response.read(MAX_RESPONSE_BYTES + 1)
                status = response.status
        except error.HTTPError as exc:
            try:
                raw = exc.read(MAX_RESPONSE_BYTES + 1)
                status = exc.code
            finally:
                exc.close()
        except (error.URLError, TimeoutError, OSError) as exc:
            raise ContractError("CPA sandbox HTTP request failed") from exc
        if len(raw) > MAX_RESPONSE_BYTES:
            fail("CPA sandbox response exceeds the reviewed bound")
        if 300 <= status < 400:
            fail("CPA sandbox redirect was rejected")
        return status, raw

    def counter(self) -> int:
        status, raw = self._open(self.descriptor["counter_url"])
        if status != 200:
            fail("counted Mock counter endpoint failed")
        value = load_json_bytes(raw, "counted Mock counter response")
        if isinstance(value, dict) and set(value) == {"total"}:
            return exact_int(value["total"], "counted Mock total")
        counter = exact_object(value, {"requests", "usage"}, "counted Mock counter")
        # The counted upstream proves only upstream transport. Its historical
        # `usage` field is deliberately ignored: usage evidence comes from the
        # independent CPA management usage queue below.
        exact_int(counter["usage"], "counted Mock legacy usage")
        return exact_int(counter["requests"], "counted Mock requests")

    def usage_queue(self) -> list[Any]:
        status, raw = self._open(
            self.descriptor["base_url"] + "/v0/management/usage-queue?count=100",
            authorization=self.management_authorization,
        )
        if status != 200:
            fail("CPA usage queue endpoint failed")
        value = load_json_bytes(raw, "CPA usage queue response")
        if not isinstance(value, list) or len(value) > 100:
            fail("CPA usage queue response is not a bounded list")
        return value

    def wait_usage_quiet(self, *, reject_records: bool) -> None:
        deadline = time.monotonic() + USAGE_OBSERVE_TIMEOUT_SECONDS
        quiet_since: float | None = None
        observed_records = False
        while time.monotonic() < deadline:
            records = self.usage_queue()
            if records:
                observed_records = True
                quiet_since = None
            else:
                if quiet_since is None:
                    quiet_since = time.monotonic()
                elif time.monotonic() - quiet_since >= USAGE_QUIET_WINDOW_SECONDS:
                    if reject_records and observed_records:
                        fail("locally blocked request created a CPA usage record")
                    return
            time.sleep(0.005)
        fail("CPA usage queue did not reach the required quiet window")

    def observe_allowed_usage(self) -> int:
        deadline = time.monotonic() + USAGE_OBSERVE_TIMEOUT_SECONDS
        observed_max = 0
        quiet_since: float | None = None
        while time.monotonic() < deadline:
            records = self.usage_queue()
            observed_max = max(observed_max, len(records))
            if len(records) > 1:
                fail("allowed request created more than one CPA usage record")
            if observed_max == 1 and not records:
                if quiet_since is None:
                    quiet_since = time.monotonic()
                elif time.monotonic() - quiet_since >= USAGE_QUIET_WINDOW_SECONDS:
                    return 1
            else:
                quiet_since = None
            time.sleep(0.005)
        fail("allowed request did not produce exactly one independently observed usage record")

    @staticmethod
    def _effective_status(value: Any, expected: str) -> dict[str, Any]:
        if not isinstance(value, dict):
            fail("CPA plugin status is not an object")
        limits = value.get("effective_limits")
        audit = value.get("audit")
        raw_capture = value.get("raw_capture")
        subject = value.get("subject_control")
        classifier = value.get("classifier")
        if (
            value.get("mode") != expected
            or any(value.get(key) is not True for key in ("loaded", "initialized", "enforcement_ready", "enabled"))
            or value.get("priority") != 300
            or value.get("opaque_media_policy") != "audit"
            or value.get("subjects") != 0
            or value.get("audit_degraded") is not False
            or value.get("router_errors") != 0
            or value.get("panics_recovered") != 0
            or value.get("last_reconfigure_error") not in ("", None)
            or value.get("last_config_error") not in ("", None)
            or not isinstance(limits, dict)
            or limits.get("max_text_window_bytes") != 16_384
            or limits.get("max_total_text_bytes") != 16_384
            or limits.get("legacy_max_scan_bytes_configured") != 16_384
            or not isinstance(audit, dict)
            or audit.get("enabled") is not True
            or audit.get("healthy") is not True
            or audit.get("degraded") is not False
            or not isinstance(subject, dict)
            or subject.get("enabled") is not False
            or subject.get("subjects", 0) != 0
            or not isinstance(classifier, dict)
            or classifier.get("remote") is not False
            or not isinstance(raw_capture, dict)
            or raw_capture.get("enabled") is not False
            or raw_capture.get("only_blocked") is not True
            or raw_capture.get("redact_secrets") is not True
            or raw_capture.get("max_bytes") != 8192
            or raw_capture.get("ttl_hours") != 1
        ):
            fail(f"CPA plugin effective status differs in {expected}")
        return {
            "enabled": value["enabled"],
            "priority": value["priority"],
            "mode": value["mode"],
            "max_scan_bytes": limits["legacy_max_scan_bytes_configured"],
            "max_total_text_bytes": limits["max_total_text_bytes"],
            "opaque_media_policy": value["opaque_media_policy"],
            "subject_control": {"enabled": subject["enabled"]},
            "audit": {
                "enabled": audit["enabled"],
                "raw_capture": {
                    "enabled": raw_capture["enabled"],
                    "only_blocked": raw_capture["only_blocked"],
                    "max_bytes": raw_capture["max_bytes"],
                    "ttl_hours": raw_capture["ttl_hours"],
                    "redact_secrets": raw_capture["redact_secrets"],
                },
            },
            "classifier": {"remote": classifier["remote"]},
        }

    def status_snapshot(self, expected: str) -> tuple[dict[str, Any], str]:
        status, raw = self._open(
            self.descriptor["base_url"] + FIXED_PHASE_PROTOCOL["status_endpoint"],
            authorization=self.management_authorization,
        )
        if status != 200:
            fail("CPA plugin status endpoint failed")
        value = load_json_bytes(raw, "CPA plugin status")
        effective = self._effective_status(value, expected)
        return effective, sha256_bytes(canonical_bytes(effective))

    def verify_mode(self, expected: str) -> None:
        deadline = time.monotonic() + min(30.0, max(2.0, self.timeout * 2))
        while time.monotonic() < deadline:
            try:
                status, raw = self._open(
                    self.descriptor["base_url"]
                    + FIXED_PHASE_PROTOCOL["status_endpoint"],
                    authorization=self.management_authorization,
                )
                value = load_json_bytes(raw, "CPA plugin status") if status == 200 else None
                effective = self._effective_status(value, expected)
                if effective:
                    self.mode_status_verified[expected] = True
                    self.effective_config_sha256[expected] = sha256_bytes(
                        canonical_bytes(effective)
                    )
                    return
            except ContractError:
                pass
            time.sleep(0.1)
        fail(f"CPA plugin mode did not converge to {expected}")

    def switch_mode(self, target: str) -> None:
        expected_target = {"audit": "balanced", "balanced": "strict"}.get(
            self.current_mode
        )
        if target != expected_target:
            fail("CPA mode transition does not follow Audit, Balanced, Strict order")
        configuration = load_canonical_json(
            Path(self.descriptor[f"{target}_plugin_config_file"]),
            f"sandbox {target} plugin configuration",
            maximum=262_144,
        )
        if configuration != expected_plugin_config(target):
            fail(f"sandbox {target} configuration changed after descriptor validation")
        _before, before_sha = self.status_snapshot(self.current_mode)
        endpoint = self.descriptor["base_url"] + FIXED_PHASE_PROTOCOL["mode_switch_endpoint"]
        for authorization in ("", "Bearer cag-round9-intentionally-wrong-management-token"):
            denied, _raw = self._open(
                endpoint,
                method=FIXED_PHASE_PROTOCOL["mode_switch_method"],
                body=canonical_bytes(configuration),
                authorization=authorization,
            )
            if denied not in {401, 403}:
                fail("CPA plugin mode switch accepted missing or incorrect management credentials")
            _unchanged, unchanged_sha = self.status_snapshot(self.current_mode)
            if unchanged_sha != before_sha:
                fail("failed CPA mode switch changed the effective configuration")
        self.mode_switch_negative_auth_verified[target] = True
        status, _raw = self._open(
            endpoint,
            method=FIXED_PHASE_PROTOCOL["mode_switch_method"],
            body=canonical_bytes(configuration),
            authorization=self.management_authorization,
        )
        if status != 200:
            fail("CPA authenticated plugin mode switch failed")
        self.verify_mode(target)
        self.current_mode = target
        self.authenticated_mode_switches.append(target)

    def mode_switch_authenticated(self) -> bool:
        return self.authenticated_mode_switches == ["balanced", "strict"]

    @staticmethod
    def _policy_kind(status: int, raw: bytes) -> str:
        if status != 403:
            return ""
        try:
            value = load_json_bytes(raw, "CPA policy response")
        except ContractError:
            return ""
        if not isinstance(value, dict):
            return ""
        candidates: list[Any] = [value.get("code"), value.get("type")]
        nested = value.get("error")
        if isinstance(nested, dict):
            candidates.extend((nested.get("code"), nested.get("type")))
        for item in candidates:
            if item in {
                "cyber_policy",
                "cyber_abuse_guard_policy",
                "cyber_abuse_guard_hard_policy",
            }:
                return item
        return ""

    def _body(self, protocol: str, prompt: str, stream: bool) -> dict[str, Any]:
        if protocol == "chat":
            return {
                "model": self.descriptor["model"],
                "messages": [{"role": "user", "content": prompt}],
                "stream": stream,
            }
        if protocol == "responses":
            return {
                "model": self.descriptor["model"],
                "input": [
                    {
                        "role": "user",
                        "content": [{"type": "input_text", "text": prompt}],
                    }
                ],
                "stream": stream,
            }
        fail("unsupported CPA protocol")

    def execute_body(self, body: bytes, mode: str, protocol: str) -> dict[str, Any]:
        if mode != self.current_mode:
            fail("CPA request phase differs from the verified current plugin mode")
        self.wait_usage_quiet(reject_records=False)
        before = self.counter()
        base = self.descriptor["base_url"]
        suffix = "/v1/chat/completions" if protocol == "chat" else "/v1/responses"
        status, raw = self._open(base + suffix, method="POST", body=body)
        after = self.counter()
        policy_kind = self._policy_kind(status, raw)
        policy_block = bool(policy_kind)
        if policy_block:
            if after != before:
                fail("locally blocked request reached counted Mock upstream")
            self.wait_usage_quiet(reject_records=True)
            usage_delta = 0
        else:
            if not 200 <= status < 300:
                fail("CPA returned a non-policy error during external evaluation")
            if after != before + 1:
                fail("allowed request did not increment counted Mock upstream exactly once")
            usage_delta = self.observe_allowed_usage()
        return {
            "policy_blocked": policy_block,
            "hard_policy_blocked": policy_kind == "cyber_abuse_guard_hard_policy",
            "upstream_delta": after - before,
            "usage_delta": usage_delta,
        }

    def execute(self, prompt: str, mode: str, protocol: str, stream: bool) -> dict[str, Any]:
        return self.execute_body(
            canonical_bytes(self._body(protocol, prompt, stream)), mode, protocol
        )


def evaluate_cases(
    descriptor: dict[str, Any],
    benign_cases: Iterable[dict[str, str]],
    malicious_cases: Iterable[dict[str, str]],
    *,
    challenge: str,
    timeout: float = 20.0,
    audit_expectations: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    require_pattern(challenge, HEX64, "route shuffle challenge")
    seed = bytes.fromhex(challenge)
    seed_sha256 = challenge_sha256(challenge)
    benign = list(benign_cases)
    malicious = list(malicious_cases)
    client = CPAClient(descriptor, timeout=timeout)
    benign_categories = Counter(item["category"] for item in benign)
    benign_languages = Counter(item["language"] for item in benign)
    benign_protocols: Counter[str] = Counter()
    benign_streams: Counter[str] = Counter()
    benign_modes: Counter[str] = Counter()
    malicious_protocols: Counter[str] = Counter()
    malicious_streams: Counter[str] = Counter()
    malicious_modes: Counter[str] = Counter()
    phase_tasks: dict[str, list[dict[str, Any]]] = {
        mode: [] for mode in FIXED_PHASE_PROTOCOL["phase_order"]
    }
    for kind, cases, routes in (
        ("benign", benign, BENIGN_ROUTES),
        ("malicious", malicious, MALICIOUS_ROUTES),
    ):
        for case in cases:
            for mode, protocol, stream in routes:
                phase_tasks[mode].append(
                    {
                        "kind": kind,
                        "case": case,
                        "mode": mode,
                        "protocol": protocol,
                        "stream": stream,
                        "opaque": "\0".join(
                            (kind, case["id"], mode, protocol, str(stream).lower())
                        ),
                    }
                )
                protocol_counter = benign_protocols if kind == "benign" else malicious_protocols
                stream_counter = benign_streams if kind == "benign" else malicious_streams
                mode_counter = benign_modes if kind == "benign" else malicious_modes
                protocol_counter[f"openai_{protocol}"] += 1
                stream_counter["stream" if stream else "nonstream"] += 1
                mode_counter[mode] += 1

    scan_limit = exact_int(descriptor["scan_limit_bytes"], "sandbox scan limit", minimum=4096)
    if scan_limit + 4096 > MAX_PROMPT_BYTES:
        fail("sandbox scan limit leaves no bounded incomplete-probe budget")
    harmless_words = ("documentation", "configuration", "maintenance", "review")
    selector = int.from_bytes(hashlib.sha256(seed + b"incomplete-words-v1").digest(), "big")
    words = [harmless_words[(selector >> (index * 2)) & 3] for index in range(4)]
    incomplete_prompt = benign[0]["prompt"] + " "
    while True:
        incomplete_prompt += " ".join(words) + ". "
        incomplete_body = canonical_bytes(client._body("chat", incomplete_prompt, False))
        if len(incomplete_body) > scan_limit + 1024:
            break
        if len(incomplete_body) > MAX_PROMPT_BYTES:
            fail("cannot construct a bounded valid over-limit incomplete request")
    incomplete_digest = sha256_bytes(incomplete_body)
    for mode in FIXED_PHASE_PROTOCOL["phase_order"]:
        phase_tasks[mode].append(
            {
                "kind": "incomplete",
                "case": None,
                "mode": mode,
                "protocol": "chat",
                "stream": False,
                "body": incomplete_body,
                "opaque": f"incomplete\0{mode}\0{incomplete_digest}",
            }
        )

    phase_permutations: dict[str, str] = {}
    phase_route_executions: dict[str, int] = {}
    for mode in FIXED_PHASE_PROTOCOL["phase_order"]:
        tasks = phase_tasks[mode]
        for task in tasks:
            task["order_key"] = hmac.new(
                seed,
                b"route-order-v3\0" + mode.encode("ascii") + b"\0" + task["opaque"].encode("utf-8"),
                hashlib.sha256,
            ).digest()
        tasks.sort(key=lambda item: (item["order_key"], item["opaque"]))
        phase_permutations[mode] = hashlib.sha256(
            b"".join(item["order_key"] for item in tasks)
        ).hexdigest()
        phase_route_executions[mode] = len(tasks)

    benign_blocked = 0
    benign_hard_blocked = 0
    malicious_categories = Counter(item["category"] for item in malicious)
    malicious_languages = Counter(item["language"] for item in malicious)
    category_blocked: dict[str, int] = defaultdict(int)
    passed_routes = 0
    malicious_audit_allowed = 0
    malicious_audit_blocked = 0
    benign_upstream = 0
    benign_usage = 0
    malicious_upstream = 0
    malicious_usage = 0
    passed_per_malicious: Counter[str] = Counter()
    incomplete_observations: dict[str, dict[str, Any]] = {}
    route_histogram: dict[str, dict[str, dict[str, int]]] = {
        "benign": {},
        "malicious": {},
        "incomplete": {},
    }
    expectation_keys: set[tuple[str, str]] = set()

    def record_route(kind: str, task: dict[str, Any], outcome: dict[str, Any]) -> None:
        key = "|".join(
            (
                task["mode"],
                "openai_" + task["protocol"],
                "stream" if task["stream"] else "nonstream",
            )
        )
        row = route_histogram[kind].setdefault(
            key,
            {"executions": 0, "policy_blocked": 0, "upstream_delta": 0, "usage_delta": 0},
        )
        row["executions"] += 1
        row["policy_blocked"] += int(outcome["policy_blocked"])
        row["upstream_delta"] += outcome["upstream_delta"]
        row["usage_delta"] += outcome["usage_delta"]

    def record_expectation(task: dict[str, Any], body: bytes, outcome: dict[str, Any]) -> None:
        if audit_expectations is None:
            return
        kind = task["kind"]
        mode = task["mode"]
        request_hash = audit_request_hash(body)
        key = (request_hash, mode)
        if key in expectation_keys:
            fail("external corpus produced a duplicate request-hash/mode audit identity")
        expectation_keys.add(key)
        if kind == "benign":
            # A clean allow does not enter the per-request audit queue.  A
            # benign request can still produce a bounded, non-blocking
            # ineligible-risk audit row, so the Host contract treats benign
            # persistence as optional and constrains the only row that may be
            # present.
            persistence = "optional"
            expected_persisted_decision_kind = "audit_ineligible_risk"
            category = ""
        elif kind == "malicious":
            persistence = "required"
            expected_persisted_decision_kind = (
                "block_malicious_text"
                if outcome["policy_blocked"]
                else "audit_eligible_malicious_text"
            )
            category = task["case"]["category"]
        elif mode == "strict":
            persistence = "required"
            expected_persisted_decision_kind = "block_incomplete_inspection"
            category = ""
        else:
            persistence = "required"
            expected_persisted_decision_kind = "audit_ineligible_risk"
            category = ""
        audit_expectations.append(
            {
                "request_id_hmac_sha256": hmac.new(
                    seed,
                    b"audit-request-id-v1\0" + task["opaque"].encode("utf-8"),
                    hashlib.sha256,
                ).hexdigest(),
                "request_hash": request_hash,
                "request_hash_hmac_sha256": hmac.new(
                    seed,
                    b"audit-request-hash-v1\0" + request_hash.encode("ascii"),
                    hashlib.sha256,
                ).hexdigest(),
                "mode": mode,
                "kind": kind,
                "persistence": persistence,
                "expected_persisted_decision_kind": expected_persisted_decision_kind,
                "expected_category": category,
            }
        )

    client.verify_mode("audit")
    for mode in FIXED_PHASE_PROTOCOL["phase_order"]:
        if mode != "audit":
            client.switch_mode(mode)
        for task in phase_tasks[mode]:
            if task["mode"] != mode:
                fail("route-order phase contains a mixed-mode task")
            if task["kind"] == "incomplete":
                body = task["body"]
                outcome = client.execute_body(body, task["mode"], task["protocol"])
                record_route("incomplete", task, outcome)
                record_expectation(task, body, outcome)
                incomplete_observations[task["mode"]] = {
                    "policy_blocked": outcome["policy_blocked"],
                    "upstream_delta": outcome["upstream_delta"],
                    "usage_delta": outcome["usage_delta"],
                }
                continue
            case = task["case"]
            body = canonical_bytes(
                client._body(task["protocol"], case["prompt"], task["stream"])
            )
            outcome = client.execute_body(body, task["mode"], task["protocol"])
            record_route(task["kind"], task, outcome)
            record_expectation(task, body, outcome)
            if task["kind"] == "benign":
                benign_blocked += int(outcome["policy_blocked"])
                benign_hard_blocked += int(outcome["hard_policy_blocked"])
                benign_upstream += outcome["upstream_delta"]
                benign_usage += outcome["usage_delta"]
            else:
                malicious_upstream += outcome["upstream_delta"]
                malicious_usage += outcome["usage_delta"]
                if mode == "audit":
                    malicious_audit_blocked += int(outcome["policy_blocked"])
                    malicious_audit_allowed += int(not outcome["policy_blocked"])
                else:
                    passed_routes += int(outcome["policy_blocked"])
                    if outcome["policy_blocked"]:
                        passed_per_malicious[case["id"]] += 1

    semantic_blocked = 0
    failures: list[str] = []
    for case in malicious:
        if passed_per_malicious[case["id"]] == len(MALICIOUS_ENFORCEMENT_ROUTES):
            semantic_blocked += 1
            category_blocked[case["category"]] += 1
        else:
            failures.append(
                hmac.new(
                    seed,
                    b"failure-id-v1\0" + case["id"].encode("utf-8"),
                    hashlib.sha256,
                ).hexdigest()
            )
    semantic_route_histogram = {
        str(blocks): sum(
            1 for case in malicious if passed_per_malicious[case["id"]] == blocks
        )
        for blocks in range(len(MALICIOUS_ENFORCEMENT_ROUTES) + 1)
    }

    benign_samples = len(benign)
    malicious_samples = len(malicious)
    per_category: dict[str, dict[str, int]] = {}
    for category, samples in sorted(malicious_categories.items()):
        blocked = category_blocked[category]
        lower, upper = wilson_interval_95(blocked, samples)
        per_category[category] = {
            "samples": samples,
            "blocked": blocked,
            "recall_basis_points": blocked * 10_000 // samples,
            "wilson_lower_bound_basis_points": round(lower * 10_000),
            "wilson_upper_bound_basis_points": round(upper * 10_000),
        }
    z = 1.959963984540054
    malicious_lower, malicious_upper = wilson_interval_95(
        semantic_blocked, malicious_samples
    )
    return {
        "route_order": {
            "algorithm": "hmac_sha256_challenge_sequential_phase_order_v3",
            "seed_sha256": seed_sha256,
            "phase_order": list(FIXED_PHASE_PROTOCOL["phase_order"]),
            "phase_permutation_sha256": phase_permutations,
            "phase_route_executions": phase_route_executions,
            "mode_status_verified": dict(client.mode_status_verified),
            "mode_switch_authenticated": client.mode_switch_authenticated(),
            "mode_switch_negative_auth_verified": dict(
                client.mode_switch_negative_auth_verified
            ),
            "effective_config_sha256": dict(client.effective_config_sha256),
            "route_executions": sum(phase_route_executions.values()),
        },
        "route_histogram": {
            kind: {key: value for key, value in sorted(rows.items())}
            for kind, rows in route_histogram.items()
        },
        "benign": {
            "unique_semantic_samples": benign_samples,
            "serialized_route_executions": benign_samples * len(BENIGN_ROUTES),
            "blocked": benign_blocked,
            "hard_policy_blocked": benign_hard_blocked,
            "wilson_upper_bound_ppm": round(1_000_000 * z * z / (benign_samples + z * z)),
            "category_counts": dict(sorted(benign_categories.items())),
            "language_counts": dict(sorted(benign_languages.items())),
            "protocol_counts": dict(sorted(benign_protocols.items())),
            "stream_counts": dict(sorted(benign_streams.items())),
            "mode_counts": dict(sorted(benign_modes.items())),
            "carrier_counts": {"current_user_direct": benign_samples * len(BENIGN_ROUTES)},
            "upstream_delta": benign_upstream,
            "usage_delta": benign_usage,
            "cag_policy_block_delta": benign_blocked,
        },
        "malicious": {
            "unique_semantic_samples": malicious_samples,
            "semantic_blocked": semantic_blocked,
            "serialized_route_executions": malicious_samples * len(MALICIOUS_ROUTES),
            "enforcement_route_executions": malicious_samples
            * len(MALICIOUS_ENFORCEMENT_ROUTES),
            "audit_route_executions": malicious_samples
            * (len(MALICIOUS_ROUTES) - len(MALICIOUS_ENFORCEMENT_ROUTES)),
            "passed_route_executions": passed_routes,
            "audit_allowed_route_executions": malicious_audit_allowed,
            "audit_policy_blocked": malicious_audit_blocked,
            "recall_basis_points": semantic_blocked * 10_000 // malicious_samples,
            "wilson_lower_bound_basis_points": round(malicious_lower * 10_000),
            "wilson_upper_bound_basis_points": round(malicious_upper * 10_000),
            "per_category": per_category,
            "category_counts": dict(sorted(malicious_categories.items())),
            "language_counts": dict(sorted(malicious_languages.items())),
            "protocol_counts": dict(sorted(malicious_protocols.items())),
            "stream_counts": dict(sorted(malicious_streams.items())),
            "mode_counts": dict(sorted(malicious_modes.items())),
            "carrier_counts": {
                "current_user_direct": malicious_samples * len(MALICIOUS_ROUTES)
            },
            "upstream_delta": malicious_upstream,
            "usage_delta": malicious_usage,
            "cag_policy_block_delta": passed_routes,
            "failure_id_hmac_sha256": failures,
            "enforcement_blocks_per_semantic_sample": semantic_route_histogram,
        },
        "incomplete": {
            "request_hmac_sha256": hmac.new(
                seed,
                b"incomplete-request-v1\0" + incomplete_body,
                hashlib.sha256,
            ).hexdigest(),
            "request_bytes": len(incomplete_body),
            "scan_limit_bytes": scan_limit,
            "valid_json": True,
            "protocol": "openai_chat",
            "stream": False,
            "carrier": "current_user_direct",
            "audit": incomplete_observations["audit"],
            "balanced": incomplete_observations["balanced"],
            "strict": incomplete_observations["strict"],
        },
        "runtime_checks": descriptor["runtime_checks"],
    }


def evaluate(args: argparse.Namespace) -> dict[str, Any]:
    require_pattern(args.expected_candidate_so_sha256, HEX64, "expected candidate SO sha256")
    require_pattern(args.expected_core_sha256, HEX64, "expected evaluator core sha256")
    if sha256_file(Path(core_module.__file__).resolve()) != args.expected_core_sha256:
        fail("installed evaluator core differs from the root-pinned SHA-256")
    descriptor = validate_sandbox_descriptor(
        load_canonical_json(args.sandbox_descriptor, "sandbox descriptor"),
        args.expected_candidate_so_sha256,
    )
    corpus, benign, malicious = load_corpus_bundle(
        args.corpus_root,
        signed_manifest_path=args.signed_manifest,
        author_public_key=args.author_public_key,
        author_key_id=args.author_key_id,
        bundle_sha256=args.bundle_sha256,
    )
    audit_expectations: list[dict[str, Any]] = []
    metrics = evaluate_cases(
        descriptor,
        benign,
        malicious,
        challenge=args.challenge,
        timeout=args.timeout,
        audit_expectations=audit_expectations,
    )
    expectations_payload = {
        "schema": AUDIT_EXPECTATIONS_SCHEMA,
        "challenge_sha256": challenge_sha256(args.challenge),
        "malicious_categories": sorted({item["category"] for item in malicious}),
        "requests": audit_expectations,
    }
    raw_expectations = canonical_bytes(expectations_payload)
    if len(raw_expectations) > 4_194_304:
        fail("CPA audit expectations exceed the reviewed bound")
    descriptor_out = os.open(
        args.audit_expectations_output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
    )
    try:
        os.write(descriptor_out, raw_expectations)
        os.fsync(descriptor_out)
    finally:
        os.close(descriptor_out)
    return {
        "schema": EVALUATOR_AGGREGATE_SCHEMA,
        "evaluator": {
            "version": "cag-round9-external-evaluator-v2",
            "sha256": sha256_file(Path(__file__).resolve()),
            "core_sha256": args.expected_core_sha256,
            "execution_mode": "EXTERNAL_ROOT_OWNED_BLACK_BOX_CPA",
        },
        "corpus": corpus,
        "sandbox": {
            key: descriptor[key]
            for key in (
                "candidate_so_sha256",
                "cpa_version",
                "cpa_commit",
                "cpa_image_id",
                "counted_mock_image_id",
                "sandbox_id",
                "daemon_id",
                "probe_image_id",
                "network_binding",
                "phase_protocol",
                "production_accessed",
                "real_provider_contacted",
                "runtime_checks",
            )
        },
        "metrics": metrics,
        "privacy": {
            "raw_prompts_in_result": False,
            "raw_responses_in_result": False,
            "request_bodies_in_logs": False,
            "failure_identifier_policy": "challenge_hmac_sha256_case_id_only",
        },
    }


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--corpus-root", required=True, type=Path)
    result.add_argument("--signed-manifest", required=True, type=Path)
    result.add_argument("--author-public-key", required=True, type=Path)
    result.add_argument("--author-key-id", required=True)
    result.add_argument("--bundle-sha256", required=True)
    result.add_argument("--sandbox-descriptor", required=True, type=Path)
    result.add_argument("--expected-candidate-so-sha256", required=True)
    result.add_argument("--expected-core-sha256", required=True)
    result.add_argument("--challenge", required=True)
    result.add_argument("--output", required=True, type=Path)
    result.add_argument("--audit-expectations-output", required=True, type=Path)
    result.add_argument("--timeout", type=float, default=20.0)
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    expectations_was_absent = False
    try:
        if os.geteuid() != 0:
            fail("the installed external evaluator must run as root")
        output = args.output.resolve(strict=False)
        expectations_output = args.audit_expectations_output.resolve(strict=False)
        if output == expectations_output:
            fail("aggregate and audit expectations outputs must be distinct")
        for label, path in (
            ("aggregate output", args.output),
            ("audit expectations output", args.audit_expectations_output),
        ):
            if not path.is_absolute():
                fail(f"{label} must use an absolute path")
            if path.exists() or path.is_symlink():
                fail(f"{label} must not already exist")
            if not path.parent.is_dir() or path.parent.is_symlink():
                fail(f"{label} parent must be an existing non-symlink directory")
        expectations_was_absent = True
        payload = evaluate(args)
        raw = canonical_bytes(payload)
        descriptor = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(descriptor, raw)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except (ContractError, OSError, ValueError) as exc:
        if expectations_was_absent:
            try:
                metadata = args.audit_expectations_output.lstat()
                if stat.S_ISREG(metadata.st_mode):
                    args.audit_expectations_output.unlink()
            except FileNotFoundError:
                pass
            except OSError as cleanup_exc:
                print(
                    "cag-round9-external-evaluator: FAIL: "
                    f"could not remove failed-run audit expectations: {cleanup_exc}",
                    file=sys.stderr,
                )
        print(f"cag-round9-external-evaluator: FAIL: {exc}", file=sys.stderr)
        return 1
    print(
        "cag-round9-external-evaluator: PASS "
        f"aggregate_sha256={hashlib.sha256(raw).hexdigest()}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
